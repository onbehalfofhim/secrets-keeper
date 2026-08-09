package main

import (
	"fmt"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	clitool "github.com/onbehalfofhim/secrets-keeper/internal/cli"

	"github.com/spf13/cobra"
)

// secretFlags содержит параметры создания/обновления секрета.
type secretFlags struct {
	secretType string

	textValue string

	loginValue    string
	passwordValue string

	cardNumber string
	cardHolder string
	cardExpire string
	cardCVV    string

	filename string
	mimeType string
}

// newSecretCommand создаёт группу команд secret.
func newSecretCommand(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets",
	}

	// Отдельные flags для create и update.
	// Они не используют общее состояние.
	createFlags := &secretFlags{}
	updateFlags := &secretFlags{}

	cmd.AddCommand(
		newSecretCreateCommand(app, createFlags),
		newSecretGetCommand(app),
		newSecretListCommand(app),
		newSecretUpdateCommand(app, updateFlags),
		newSecretDeleteCommand(app),
	)

	return cmd
}

// newSecretCreateCommand создаёт команду:
//	secrets-cli secret create
func newSecretCreateCommand(app *App, flags *secretFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a secret",

		RunE: func(cmd *cobra.Command, args []string) error {
			return createSecret(app, flags)
		},
	}

	addSecretFlags(cmd, flags)

	return cmd
}

// newSecretGetCommand создаёт команду:
//	secrets-cli secret get <id>
func newSecretGetCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get a secret",

		Args: cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return getSecret(app, args[0])
		},
	}
}

// newSecretListCommand создаёт команду:
//	secrets-cli secret list
func newSecretListCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List secrets",

		Args: cobra.NoArgs,

		RunE: func(cmd *cobra.Command, args []string) error {
			return listSecrets(app)
		},
	}
}

// newSecretUpdateCommand создаёт команду:
//	secrets-cli secret update <id>
func newSecretUpdateCommand(app *App, flags *secretFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a secret",

		Args: cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return updateSecret(app, args[0], flags)
		},
	}

	addSecretFlags(cmd, flags)

	return cmd
}

// newSecretDeleteCommand создаёт команду:
//	secrets-cli secret delete <id>
func newSecretDeleteCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a secret",

		Args: cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteSecret(app, args[0])
		},
	}
}

// addSecretFlags добавляет flags для create/update.
func addSecretFlags(cmd *cobra.Command, flags *secretFlags) {
	cmd.Flags().StringVar(&flags.secretType, "type", "", "secret type: text, login, card, binary")

	cmd.Flags().StringVar(&flags.textValue, "text", "", "text secret value")

	cmd.Flags().StringVar(&flags.loginValue, "login", "", "login value")

	cmd.Flags().StringVar(&flags.passwordValue, "password", "", "password value")

	cmd.Flags().StringVar(&flags.cardNumber, "number", "", "bank card number")

	cmd.Flags().StringVar(&flags.cardHolder, "holder", "", "bank card holder")

	cmd.Flags().StringVar(&flags.cardExpire, "expire", "", "bank card expiration")

	cmd.Flags().StringVar(&flags.cardCVV, "cvv", "", "bank card CVV")

	cmd.Flags().StringVar(&flags.filename, "filename", "", "binary filename")

	cmd.Flags().StringVar(&flags.mimeType, "mime-type", "", "binary MIME type")
}

// createSecret вызывает CreateSecret RPC.
func createSecret(app *App, flags *secretFlags) error {
	ctx, cancel, err := app.client.AuthenticatedContext()
	if err != nil {
		return err
	}
	defer cancel()

	secret, err := buildSecret(flags)
	if err != nil {
		return err
	}

	response, err := app.client.Secret.CreateSecret(
		ctx,
		&pb.CreateSecretRequest{
			Secret: secret,
		},
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	fmt.Println("Secret created successfully.")
	fmt.Println("ID:", response.GetId())

	// Для binary сначала создаётся metadata,
	// затем файл загружается отдельным RPC.
	if secret.GetBinary() != nil {
		fmt.Println()
		fmt.Println("Binary secret created.")
		fmt.Println("Upload the file with:")
		fmt.Printf(
			"  secrets-cli file upload %s <path>\n",
			response.GetId(),
		)
	}

	return nil
}

// buildSecret преобразует CLI flags в protobuf Secret.
func buildSecret(flags *secretFlags) (*pb.Secret, error) {
	switch flags.secretType {
	case "text":
		if flags.textValue == "" {
			return nil, fmt.Errorf("text value is required")
		}

		return &pb.Secret{
			Payload: &pb.Secret_Text{
				Text: &pb.TextSecret{
					Text: flags.textValue,
				},
			},
		}, nil

	case "login":
		if flags.loginValue == "" {
			return nil, fmt.Errorf("login value is required")
		}

		if flags.passwordValue == "" {
			return nil, fmt.Errorf("password value is required")
		}

		return &pb.Secret{
			Payload: &pb.Secret_LoginPassword{
				LoginPassword: &pb.LoginPasswordSecret{
					Login:    flags.loginValue,
					Password: flags.passwordValue,
				},
			},
		}, nil

	case "card":
		if flags.cardNumber == "" {
			return nil, fmt.Errorf("card number is required")
		}

		if flags.cardHolder == "" {
			return nil, fmt.Errorf("card holder is required")
		}

		if flags.cardExpire == "" {
			return nil, fmt.Errorf("card expiration is required")
		}

		if flags.cardCVV == "" {
			return nil, fmt.Errorf("card CVV is required")
		}

		return &pb.Secret{
			Payload: &pb.Secret_BankCard{
				BankCard: &pb.BankCardSecret{
					Number: flags.cardNumber,
					Holder: flags.cardHolder,
					Expire: flags.cardExpire,
					Cvv:    flags.cardCVV,
				},
			},
		}, nil

	case "binary":
		if flags.filename == "" {
			return nil, fmt.Errorf("filename is required")
		}

		if flags.mimeType == "" {
			return nil, fmt.Errorf("mime-type is required")
		}

		return &pb.Secret{
			Payload: &pb.Secret_Binary{
				Binary: &pb.BinarySecret{
					Filename: flags.filename,
					MimeType: flags.mimeType,
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf(
			"unsupported secret type %q; "+
				"use text, login, card or binary",
			flags.secretType,
		)
	}
}

// getSecret вызывает GetSecret RPC.
func getSecret(app *App, id string) error {
	ctx, cancel, err := app.client.AuthenticatedContext()
	if err != nil {
		return err
	}
	defer cancel()

	response, err := app.client.Secret.GetSecret(
		ctx,
		&pb.GetSecretRequest{
			Id: id,
		},
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	printSecret(response.GetSecret())

	return nil
}

// listSecrets вызывает ListSecrets RPC.
func listSecrets(app *App) error {
	ctx, cancel, err := app.client.AuthenticatedContext()
	if err != nil {
		return err
	}
	defer cancel()

	response, err := app.client.Secret.ListSecrets(
		ctx,
		&pb.ListSecretsRequest{},
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	secrets := response.GetSecrets()

	if len(secrets) == 0 {
		fmt.Println("No secrets found.")
		return nil
	}

	fmt.Printf(
		"Found %d secret(s):\n\n",
		len(secrets),
	)

	for _, secret := range secrets {
		fmt.Printf(
			"ID:   %s\n",
			secret.GetId(),
		)

		fmt.Printf(
			"Type: %s\n",
			secret.GetType(),
		)

		fmt.Println("---")
	}

	return nil
}

// updateSecret вызывает UpdateSecret RPC.
func updateSecret(app *App, id string, flags *secretFlags) error {
	ctx, cancel, err := app.client.AuthenticatedContext()
	if err != nil {
		return err
	}
	defer cancel()

	secret, err := buildSecret(flags)
	if err != nil {
		return err
	}

	// UpdateSecret использует ID из metadata.
	secret.Metadata = &pb.SecretMetadata{
		Id: id,
	}

	_, err = app.client.Secret.UpdateSecret(
		ctx,
		&pb.UpdateSecretRequest{
			Secret: secret,
		},
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	fmt.Println("Secret updated successfully.")

	return nil
}

// deleteSecret вызывает DeleteSecret RPC.
func deleteSecret(app *App, id string) error {
	ctx, cancel, err := app.client.AuthenticatedContext()
	if err != nil {
		return err
	}
	defer cancel()

	_, err = app.client.Secret.DeleteSecret(
		ctx,
		&pb.DeleteSecretRequest{
			Id: id,
		},
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	fmt.Println("Secret deleted successfully.")

	return nil
}

// printSecret выводит содержимое секрета.
func printSecret(secret *pb.Secret) {
	if secret == nil {
		fmt.Println("Secret is empty.")
		return
	}

	metadata := secret.GetMetadata()

	if metadata != nil {
		fmt.Println("ID:", metadata.GetId())
		fmt.Println("Type:", metadata.GetType())
		fmt.Println("Title:", metadata.GetTitle())
		fmt.Println("Description:", metadata.GetDescription())

		if metadata.GetCreatedAt() != nil {
			fmt.Println(
				"Created:",
				metadata.GetCreatedAt().AsTime(),
			)
		}

		if metadata.GetUpdatedAt() != nil {
			fmt.Println(
				"Updated:",
				metadata.GetUpdatedAt().AsTime(),
			)
		}
	}

	fmt.Println()

	switch payload := secret.GetPayload().(type) {
	case *pb.Secret_Text:
		fmt.Println(
			"Text:",
			payload.Text.GetText(),
		)

	case *pb.Secret_LoginPassword:
		fmt.Println(
			"Login:",
			payload.LoginPassword.GetLogin(),
		)
		fmt.Println(
			"Password:",
			payload.LoginPassword.GetPassword(),
		)

	case *pb.Secret_BankCard:
		fmt.Println(
			"Number:",
			payload.BankCard.GetNumber(),
		)
		fmt.Println(
			"Holder:",
			payload.BankCard.GetHolder(),
		)
		fmt.Println(
			"Expire:",
			payload.BankCard.GetExpire(),
		)
		fmt.Println(
			"CVV:",
			payload.BankCard.GetCvv(),
		)

	case *pb.Secret_Binary:
		fmt.Println(
			"Filename:",
			payload.Binary.GetFilename(),
		)
		fmt.Println(
			"MIME type:",
			payload.Binary.GetMimeType(),
		)

	default:
		fmt.Println("Payload: <unknown>")
	}
}
