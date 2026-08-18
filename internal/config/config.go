package config

import (
	"flag"
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config содержит конфигурацию Secrets Keeper.
type Config struct {
	RunAddr         string        `env:"RUN_ADDRESS" envDefault:":50051"`
	DatabaseURI     string        `env:"DATABASE_URL"`
	JWTSecret       string        `env:"JWT_SECRET"`
	EncryptionKey   string        `env:"ENCRYPTION_KEY"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"10s"`

	TLSCertFile string `env:"TLS_CERT_FILE"`
	TLSKeyFile  string `env:"TLS_KEY_FILE"`
}

// ParseFlags загружает конфигурацию из .env,
// переменных окружения и аргументов командной строки.
func ParseFlags() (Config, error) {
	var cfg Config

	// 1. .env → environment
	_ = godotenv.Load()

	// 2. environment → Config
	if err := env.Parse(&cfg); err != nil {
		return cfg, fmt.Errorf("can't parse env: %w", err)
	}

	// 3. flags → поверх environment
	flag.StringVar(&cfg.RunAddr, "a", cfg.RunAddr, "gRPC server address")
	flag.StringVar(&cfg.DatabaseURI, "d", cfg.DatabaseURI, "database URI")
	flag.StringVar(&cfg.JWTSecret, "k", cfg.JWTSecret, "JWT secret")
	flag.StringVar(&cfg.EncryptionKey, "e", cfg.EncryptionKey, "encryption key")
	flag.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "graceful shutdown timeout")

	flag.StringVar(&cfg.TLSCertFile, "tls-cert", cfg.TLSCertFile, "TLS cert")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", cfg.TLSKeyFile, "TLS key")
	flag.Parse()

	// 4. Валидация
	if cfg.DatabaseURI == "" {
		return cfg, fmt.Errorf("DATABASE_URL is required")
	}

	if cfg.JWTSecret == "" {
		return cfg, fmt.Errorf("JWT_SECRET is required")
	}

	if cfg.EncryptionKey == "" {
		return cfg, fmt.Errorf("ENCRYPTION_KEY is required")
	}

	if cfg.ShutdownTimeout <= 0 {
		return cfg, fmt.Errorf("shutdown timeout must be greater than zero")
	}

	return cfg, nil
}
