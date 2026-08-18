package main

import (
	"fmt"
	"os"

	"github.com/onbehalfofhim/secrets-keeper/internal/buildinfo"
	clitool "github.com/onbehalfofhim/secrets-keeper/internal/cli"
)

func main() {
	cfg, err := clitool.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		// "failed to set environment variables"
		os.Exit(1)
	}

	app := NewApp(cfg, buildinfo.Get())

	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, clitool.FormatGRPCError(err))
		os.Exit(1)
	}
}
