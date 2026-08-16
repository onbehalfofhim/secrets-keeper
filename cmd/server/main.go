package main

import (
	"context"
	"crypto/tls"
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

	"github.com/jackc/pgx/v5/pgxpool"

	"google.golang.org/grpc/credentials"
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

	ctx, cancel := context.WithTimeout(
		context.Background(),
		databasePingTimeout,
	)
	defer cancel()

	db, err := pgxpool.New(ctx, cfg.DatabaseURI)
	if err != nil {
		log.Error("failed to create database pool", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Ping(ctx); err != nil {
		log.Error("failed to connect to database", "error", err)
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
		log.With("component", "auth-server"),
	)

	// ============================================================
	// Encryption
	// ============================================================

	encryptor, err := crypto.NewAESGCM(
		[]byte(cfg.EncryptionKey),
		log.With("component", "crypto"),
	)
	if err != nil {
		log.Error("failed to initialize encryption", "error", err)
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
		log.With("component", "secret-server"),
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
		log.With("component", "binary-server"),
	)

	// ============================================================
	// TLS
	// ============================================================

	cert, err := tls.LoadX509KeyPair(
		cfg.TLSCertFile,
		cfg.TLSKeyFile,
	)
	if err != nil {
		log.Error(
			"failed to load TLS certificate",
			"error",
			err,
		)

		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	transportCredentials := credentials.NewTLS(tlsConfig)

	// ============================================================
	// gRPC Server
	// ============================================================

	server := grpcserver.NewServer(
		cfg.RunAddr,
		authServer,
		secretServer,
		binaryServer,
		jwtManager,
		log.With("component", "grpc-server"),
		transportCredentials,
	)

	// ============================================================
	// Signals
	// ============================================================

	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		os.Interrupt,
		syscall.SIGTERM,
	)

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
			log.Error(
				"gRPC server stopped with error",
				"error",
				err,
			)

			os.Exit(1)
		}

	case signal := <-stop:
		log.Info(
			"shutdown signal received",
			"signal",
			signal.String(),
		)
	}

	// ============================================================
	// Graceful shutdown
	// ============================================================

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		cfg.ShutdownTimeout,
	)
	defer shutdownCancel()

	server.Stop(shutdownCtx)

	// PostgreSQL закрывается через defer db.Close().
	log.Info("application stopped")
}
