package main

import (
	"context"
	"database/sql"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"
	"github.com/onbehalfofhim/secrets-keeper/internal/crypto"
	grpcserver "github.com/onbehalfofhim/secrets-keeper/internal/grpc"
	"github.com/onbehalfofhim/secrets-keeper/internal/logger"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository/postgres"
	"github.com/onbehalfofhim/secrets-keeper/internal/serializer"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const defaultGRPCAddr = ":50051"

func main() {
	logger := logger.NewLogger()

	// Получаем конфигурацию.
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("DATABASE_URL is not set")
		os.Exit(1)
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		logger.Error("JWT_SECRET is not set")
		os.Exit(1)
	}

	encryptionKey := []byte(os.Getenv("ENCRYPTION_KEY"))

	// Подключаемся к PostgreSQL.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	logger.Info("connected to PostgreSQL")

	// ============================================================
	// Auth
	// ============================================================

	userRepository := postgres.NewUsersRepository(db)

	jwtManager := auth.NewJWT(
		jwtSecret,
		24*time.Hour,
	)

	authService := service.NewAuthService(
		userRepository,
		jwtManager,
	)

	authServer := grpcserver.NewAuthServer(
		authService,
		logger,
	)

	// ============================================================
	// Encryption
	// ============================================================

	encryptor, err := crypto.NewAESGCM(encryptionKey)
	if err != nil {
		logger.Error("failed to initialize encryption", "error", err)
		os.Exit(1)
	}

	serializer := serializer.NewJSONSerializer()

	// ============================================================
	// Secret
	// ============================================================

	secretRepository := postgres.NewSecretRepository(db)

	secretService := service.NewSecretService(
		secretRepository,
		encryptor,
		serializer,
	)

	secretServer := grpcserver.NewSecretServer(
		secretService,
		logger,
	)

	// ============================================================
	// Binary
	// ============================================================

	binaryService := service.NewBinaryService(
		secretRepository,
		encryptor,
	)

	binaryServer := grpcserver.NewBinaryServer(
		binaryService,
		logger,
	)

	// ============================================================
	// gRPC Server
	// ============================================================

	server := grpcserver.NewServer(
		defaultGRPCAddr,
		authServer,
		secretServer,
		binaryServer,
		jwtManager,
		logger,
	)

	// ============================================================
	// Graceful shutdown
	// ============================================================

	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		os.Interrupt,
		syscall.SIGTERM,
	)

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- server.Start()
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			logger.Error("gRPC server stopped with error", "error", err)
			os.Exit(1)
		}

	case <-stop:
		logger.Info("shutdown signal received")

		server.Stop()
	}
}
