package main

import (
	"fmt"

	clitool "github.com/onbehalfofhim/secrets-keeper/internal/cli"
)

// App содержит состояние CLI-приложения.
type App struct {
	config clitool.Config
	client *clitool.Client
}

// NewApp создаёт CLI-приложение.
func NewApp(config clitool.Config) *App {
	return &App{
		config: config,
	}
}

// Run запускает CLI.
func (a *App) Run() error {
	rootCmd := NewRootCommand(a)

	return rootCmd.Execute()
}

// connect создаёт gRPC client.
func (a *App) connect() error {
	if a.client != nil {
		return nil
	}

	client, err := clitool.NewClient(a.config)
	if err != nil {
		return fmt.Errorf(
			"create gRPC client: %w",
			err,
		)
	}

	a.client = client

	return nil
}

// close закрывает gRPC connection.
func (a *App) close() {
	if a.client == nil {
		return
	}

	_ = a.client.Close()
	a.client = nil
}
