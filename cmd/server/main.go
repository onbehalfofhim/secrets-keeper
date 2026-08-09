package main

import (
	"context"
	"database/sql"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"
	"github.com/onbehalfofhim/secrets-keeper/internal/config"
	"github.com/onbehalfofhim/secrets-keeper/internal/crypto"
	grpcserver "github.com/onbehalfofhim/secrets-keeper/internal/grpc"
	"github.com/onbehalfofhim/secrets-keeper/internal/logger"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository/postgres"
	"github.com/onbehalfofhim/secrets-keeper/internal/serializer"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	databasePingTimeout = 5 * time.Second
	jwtExpiration       = 24 * time.Hour
)

func main() {
	log := logger.NewLogger()

	// ============================================================
	// Configuration
	// ============================================================

	cfg, err := config.ParseFlags()
	if err != nil {
		log.Error("failed to load configuration", "error", err)

		os.Exit(1)
	}

	// ============================================================
	// PostgreSQL
	// ============================================================

	db, err := sql.Open("pgx", cfg.DatabaseURI)
	if err != nil {
		log.Error("failed to open database", "error", err)

		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), databasePingTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Error("failed to connect to database", "error", err)

		db.Close()

		os.Exit(1)
	}

	log.Info("connected to PostgreSQL")

	// ============================================================
	// Auth
	// ============================================================

	userRepository := postgres.NewUsersRepository(db)

	jwtManager := auth.NewJWT(
		cfg.JWTSecret,
		jwtExpiration,
	)

	authService := service.NewAuthService(
		userRepository,
		jwtManager,
	)

	authServer := grpcserver.NewAuthServer(
		authService,
		log,
	)

	// ============================================================
	// Encryption
	// ============================================================

	encryptor, err := crypto.NewAESGCM(
		[]byte(cfg.EncryptionKey),
		log,
	)
	if err != nil {
		log.Error("failed to initialize encryption", "error", err)

		db.Close()

		os.Exit(1)
	}

	jsonSerializer := serializer.NewJSONSerializer()

	// ============================================================
	// Secret
	// ============================================================

	secretRepository := postgres.NewSecretRepository(db)

	secretService := service.NewSecretService(
		secretRepository,
		encryptor,
		jsonSerializer,
	)

	secretServer := grpcserver.NewSecretServer(
		secretService,
		log,
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
		log,
	)

	// ============================================================
	// gRPC Server
	// ============================================================

	server := grpcserver.NewServer(
		cfg.RunAddr,
		authServer,
		secretServer,
		binaryServer,
		jwtManager,
		log,
	)

	// ============================================================
	// Signals
	// ============================================================

	stop := make(chan os.Signal, 1)

	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	defer signal.Stop(stop)

	// ============================================================
	// Start gRPC server
	// ============================================================

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- server.Start()
	}()

	// ============================================================
	// Wait
	// ============================================================

	select {
	case err := <-serverErr:
		if err != nil {
			log.Error("gRPC server stopped with error", "error", err)

			db.Close()

			os.Exit(1)
		}

	case signal := <-stop:
		log.Info("shutdown signal received", "signal", signal.String())
	}

	// ============================================================
	// Graceful shutdown
	// ============================================================

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	server.Stop(shutdownCtx)

	// ============================================================
	// PostgreSQL shutdown
	// ============================================================

	log.Info("closing PostgreSQL connection")

	if err := db.Close(); err != nil {
		log.Error("failed to close PostgreSQL connection", "error", err)

		os.Exit(1)
	}

	log.Info("PostgreSQL connection closed")
	log.Info("application stopped")
}
