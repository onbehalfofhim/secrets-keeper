package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	clitool "github.com/onbehalfofhim/secrets-keeper/internal/cli"

	"github.com/spf13/cobra"
)

const binaryChunkSize = 64 * 1024 // 64 KB

// newFileCommand создаёт группу команд file.
func newFileCommand(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "file",
		Short: "Manage binary files",
	}

	cmd.AddCommand(
		newFileUploadCommand(app),
		newFileDownloadCommand(app),
	)

	return cmd
}

// newFileUploadCommand создаёт:
//
//	secrets-cli file upload <secret-id> <file-path>
func newFileUploadCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "upload <secret-id> <file-path>",
		Short: "Upload a file to a binary secret",

		Args: cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			return uploadFile(
				app,
				args[0],
				args[1],
			)
		},
	}
}

// newFileDownloadCommand создаёт:
//
//	secrets-cli file download <secret-id> <file-path>
func newFileDownloadCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "download <secret-id> <file-path>",
		Short: "Download a binary secret to a file",

		Args: cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			return downloadFile(
				app,
				args[0],
				args[1],
			)
		},
	}
}

// uploadFile загружает файл через client-streaming RPC.
func uploadFile(app *App, secretID string, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf(
			"open file: %w",
			err,
		)
	}
	defer file.Close()

	ctx, cancel, err := app.client.AuthenticatedContext()
	if err != nil {
		return err
	}
	defer cancel()

	stream, err := app.client.Binary.UploadBinary(ctx)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	buffer := make([]byte, binaryChunkSize)

	var totalBytes int64

	for {
		n, readErr := file.Read(buffer)

		if n > 0 {
			// Делаем копию данных.
			// buffer будет переиспользован на следующей итерации.
			chunkData := append(
				[]byte(nil),
				buffer[:n]...,
			)

			err := stream.Send(
				&pb.UploadBinaryChunk{
					SecretId: secretID,
					Chunk:    chunkData,
				},
			)
			if err != nil {
				return clitool.FormatGRPCError(err)
			}

			totalBytes += int64(n)
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return fmt.Errorf(
				"read file: %w",
				readErr,
			)
		}
	}

	// Закрываем client stream и ждём response от сервера.
	if _, err := stream.CloseAndRecv(); err != nil {
		return clitool.FormatGRPCError(err)
	}

	fmt.Println("File uploaded successfully.")
	fmt.Println("Path:", filePath)
	fmt.Println("Size:", totalBytes, "bytes")

	return nil
}

// downloadFile скачивает файл через server-streaming RPC.
func downloadFile(app *App, secretID string, filePath string) error {
	ctx, cancel, err := app.client.AuthenticatedContext()
	if err != nil {
		return err
	}
	defer cancel()

	stream, err := app.client.Binary.DownloadBinary(
		ctx,
		&pb.DownloadBinaryRequest{
			SecretId: secretID,
		},
	)
	if err != nil {
		return clitool.FormatGRPCError(err)
	}

	// Создаём временный файл в той же директории,
	// чтобы после успешного download можно было сделать rename.
	outputDir := filepath.Dir(filePath)

	tempFile, err := os.CreateTemp(
		outputDir,
		".secrets-keeper-download-*",
	)
	if err != nil {
		return fmt.Errorf(
			"create temporary file: %w",
			err,
		)
	}

	tempPath := tempFile.Name()

	// Если download завершится с ошибкой,
	// временный файл нужно удалить.
	success := false

	defer func() {
		_ = tempFile.Close()

		if !success {
			_ = os.Remove(tempPath)
		}
	}()

	var totalBytes int64

	for {
		chunk, err := stream.Recv()

		if err == io.EOF {
			break
		}

		if err != nil {
			return clitool.FormatGRPCError(err)
		}

		data := chunk.GetChunk()

		if len(data) == 0 {
			continue
		}

		n, err := tempFile.Write(data)
		if err != nil {
			return fmt.Errorf(
				"write downloaded file: %w",
				err,
			)
		}

		totalBytes += int64(n)
	}

	// Закрываем файл перед rename.
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf(
			"close downloaded file: %w",
			err,
		)
	}

	if err := os.Rename(
		tempPath,
		filePath,
	); err != nil {
		return fmt.Errorf(
			"save downloaded file: %w",
			err,
		)
	}

	success = true

	fmt.Println("File downloaded successfully.")
	fmt.Println("Path:", filePath)
	fmt.Println("Size:", totalBytes, "bytes")

	return nil
}
