package main

import (
	"fmt"
	"os"
	"strings"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	clitool "github.com/onbehalfofhim/secrets-keeper/internal/cli"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newRegisterCommand создаёт команду:
//
//	secrets-cli register
func newRegisterCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "register",
		Short: "Register a new user",

		RunE: func(cmd *cobra.Command, args []string) error {
			return registerUser(app)
		},
	}
}

// newLoginCommand создаёт команду:
//
//	secrets-cli login
func newLoginCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Login to Secrets Keeper",

		RunE: func(cmd *cobra.Command, args []string) error {
			return loginUser(app)
		},
	}
}

// newLogoutCommand создаёт команду:
//
//	secrets-cli logout
func newLogoutCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Logout from Secrets Keeper",

		RunE: func(cmd *cobra.Command, args []string) error {
			return logoutUser(app)
		},
	}
}

// registerUser ргеистрируется пользователя.
func registerUser(app *App) error {
	login, password, err := readCredentials()
	if err != nil {
		return err
	}

	ctx, cancel := app.client.Context()
	defer cancel()

	response, err := app.client.Auth.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    login,
			Password: password,
		}.Build(),
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	fmt.Println("User registered successfully.")
	fmt.Println("User ID:", response.GetUserId())

	return nil
}

// loginUser авторизирует пользователя.
// Сохраняет JWT-токен в файл.
func loginUser(app *App) error {
	login, password, err := readCredentials()
	if err != nil {
		return err
	}

	ctx, cancel := app.client.Context()
	defer cancel()

	response, err := app.client.Auth.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    login,
			Password: password,
		}.Build(),
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	if err := app.client.SaveToken(
		response.GetAccessToken(),
	); err != nil {
		return err
	}

	fmt.Println("Login successful.")
	fmt.Printf(
		"Token expires in: %d seconds\n",
		response.GetExpiresIn(),
	)

	return nil
}

// logoutUser завершает сессию пользователя.
// Удаляет сохранённый JWT.
func logoutUser(app *App) error {
	if err := app.client.DeleteToken(); err != nil {
		return err
	}

	fmt.Println("Logged out successfully.")

	return nil
}

// readCredentials сбор входных данных пользователя.
func readCredentials() (string, string, error) {
	fmt.Print("Login: ")

	var login string

	if _, err := fmt.Scanln(&login); err != nil {
		return "", "", fmt.Errorf(
			"read login: %w",
			err,
		)
	}

	login = strings.TrimSpace(login)

	if login == "" {
		return "", "", fmt.Errorf(
			"login cannot be empty",
		)
	}

	fmt.Print("Password: ")

	passwordBytes, err := term.ReadPassword(
		int(os.Stdin.Fd()),
	)
	if err != nil {
		return "", "", fmt.Errorf(
			"read password: %w",
			err,
		)
	}

	fmt.Println()

	password := string(passwordBytes)

	if password == "" {
		return "", "", fmt.Errorf(
			"password cannot be empty",
		)
	}

	return login, password, nil
}
