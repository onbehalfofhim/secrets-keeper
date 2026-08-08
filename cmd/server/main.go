package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"
	"github.com/onbehalfofhim/secrets-keeper/internal/crypto"
	grpcserver "github.com/onbehalfofhim/secrets-keeper/internal/grpc"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository/postgres"
	"github.com/onbehalfofhim/secrets-keeper/internal/serializer"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	defaultGRPCAddr = ":50051"
)

func main() {
	logger := slog.New(
		slog.NewTextHandler(
			os.Stdout,
			&slog.HandlerOptions{
				Level: slog.LevelDebug,
			},
		),
	)

	// Временно задаем конфигурацию напрямую.
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
		logger.Error(
			"failed to connect to database",
			"error",
			err,
		)
		os.Exit(1)
	}

	logger.Info("connected to PostgreSQL")

	// Auth Server
	userRepository := postgres.NewUsersRepository(db)

	jwtManager := auth.NewJWT(jwtSecret, 24*time.Hour)

	authService := service.NewAuthService(
		userRepository,
		jwtManager,
	)

	authServer := grpcserver.NewAuthServer(
		authService,
	)

	// Secret Server
	secretRepository := postgres.NewSecretRepository(db)

	key := []byte(os.Getenv("ENCRYPTION_KEY"))

	encryptor, err := crypto.NewAESGCM(key)
	if err != nil {
		logger.Error("failed to initialize encryption", "error", err)
		os.Exit(1)
	}

	serializer := serializer.NewJSONSerializer()

	secretService := service.NewSecretService(
		secretRepository,
		encryptor,
		serializer,
	)

	secretServer := grpcserver.NewSecretServer(
		secretService,
	)

	// binary server
	binaryService := service.NewBinaryService(
		secretRepository,
		encryptor,
	)

	binaryServer := grpcserver.NewBinaryServer(
		binaryService,
	)

	// gRPC Server
	server := grpcserver.NewServer(
		defaultGRPCAddr,
		authServer,
		secretServer,
		binaryServer,
		jwtManager,
	)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		os.Interrupt,
		syscall.SIGTERM,
	)

	go func() {
		logger.Info(
			"gRPC server started",
			"address",
			defaultGRPCAddr,
		)

		if err := server.Start(); err != nil {
			logger.Error(
				"gRPC server stopped with error",
				"error",
				err,
			)

			os.Exit(1)
		}
	}()

	<-stop

	logger.Info("shutting down gRPC server")

	server.Stop()

	logger.Info("gRPC server stopped")
}
