package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewRootCommand создаёт root Cobra command.
func NewRootCommand(app *App) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "secrets-cli",
		Short: "Secrets Keeper CLI",
		Long:  "CLI client for Secrets Keeper",

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "version" {
				return nil
			}
			serverAddr, err := cmd.Flags().GetString("server")
			if err != nil {
				return err
			}
			if serverAddr != "" {
				app.config.ServerAddr = serverAddr
			}
			return app.connect()
		},

		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			app.close()
		},
	}

	rootCmd.PersistentFlags().String(
		"server",
		"",
		"gRPC server address",
	)

	rootCmd.AddCommand(
		newVersionCommand(app),
		newRegisterCommand(app),
		newLoginCommand(app),
		newLogoutCommand(app),
		newSecretCommand(app),
		newFileCommand(app),
	)

	return rootCmd
}

func newVersionCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show CLI version and build date",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(
				cmd.OutOrStdout(),
				"secrets-cli\n",
			)
			fmt.Fprintf(
				cmd.OutOrStdout(),
				"version: %s\n",
				app.buildInfo.Version,
			)
			fmt.Fprintf(
				cmd.OutOrStdout(),
				"build date: %s\n",
				app.buildInfo.BuildDate,
			)
		},
	}
}
