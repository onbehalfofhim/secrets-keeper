package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/caarlos0/env/v11"
)

// Config содержит настройки CLI.
type Config struct {
	ServerAddr string `env:"SECRETS_KEEPER_ADDR" envDefault:"localhost:50051"`
	TokenFile  string `env:"SECRETS_KEEPER_TOKEN"`
	CertFile   string `env:"GRPC_CERT_FILE" envDefault:"certs/server.crt"`
}

// LoadConfig загружает конфигурацию из .env и environment.
func LoadConfig() (Config, error) {
	var cfg Config

	// environment → Config.
	if err := env.Parse(&cfg); err != nil {
		return cfg, fmt.Errorf(
			"can't parse environment: %w",
			err,
		)
	}

	// Default token path.
	if cfg.TokenFile == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return cfg, fmt.Errorf(
				"get user home directory: %w",
				err,
			)
		}

		cfg.TokenFile = filepath.Join(homeDir, "secrets-keeper", "token")
	}

	return cfg, nil
}
