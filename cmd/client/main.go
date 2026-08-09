package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"time"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const grpcAddr = "localhost:50051"

func main() {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		grpcAddr,
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
	)
	if err != nil {
		log.Fatalf("failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	authClient := pb.NewAuthServiceClient(conn)
	secretClient := pb.NewSecretServiceClient(conn)
	binaryClient := pb.NewBinaryServiceClient(conn)

	// ============================================================
	// 1. REGISTER
	// ============================================================

	fmt.Println("========================================")
	fmt.Println("1. REGISTER")
	fmt.Println("========================================")

	login := fmt.Sprintf(
		"test_user_%d",
		time.Now().UnixNano(),
	)
	password := "test-password"

	registerResponse, err := authClient.Register(
		ctx,
		&pb.RegisterRequest{
			Login:    login,
			Password: password,
		},
	)
	if err != nil {
		log.Fatalf("register failed: %v", err)
	}

	fmt.Println("✓ user registered")
	fmt.Println("  user id:", registerResponse.GetUserId())
	fmt.Println("  login:", login)

	// ============================================================
	// 2. LOGIN
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("2. LOGIN")
	fmt.Println("========================================")

	loginResponse, err := authClient.Login(
		ctx,
		&pb.LoginRequest{
			Login:    login,
			Password: password,
		},
	)
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	token := loginResponse.GetAccessToken()

	fmt.Println("✓ login successful")
	fmt.Println("  expires in:", loginResponse.GetExpiresIn(), "seconds")
	fmt.Println("  token:", token)

	authCtx := authenticatedContext(
		context.Background(),
		token,
	)

	// ============================================================
	// 3. CREATE TEXT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("3. CREATE TEXT SECRET")
	fmt.Println("========================================")

	createResponse, err := secretClient.CreateSecret(
		authCtx,
		&pb.CreateSecretRequest{
			Secret: &pb.Secret{
				Payload: &pb.Secret_Text{
					Text: &pb.TextSecret{
						Text: "my first secret",
					},
				},
			},
		},
	)
	if err != nil {
		log.Fatalf("create secret failed: %v", err)
	}

	secretID := createResponse.GetId()

	fmt.Println("✓ secret created")
	fmt.Println("  secret id:", secretID)

	// ============================================================
	// 4. GET SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("4. GET SECRET")
	fmt.Println("========================================")

	getResponse, err := secretClient.GetSecret(
		authCtx,
		&pb.GetSecretRequest{
			Id: secretID,
		},
	)
	if err != nil {
		log.Fatalf("get secret failed: %v", err)
	}

	printSecret(getResponse.GetSecret())

	// ============================================================
	// 5. UPDATE SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("5. UPDATE SECRET")
	fmt.Println("========================================")

	_, err = secretClient.UpdateSecret(
		authCtx,
		&pb.UpdateSecretRequest{
			Secret: &pb.Secret{
				Metadata: &pb.SecretMetadata{
					Id: secretID,
				},
				Payload: &pb.Secret_Text{
					Text: &pb.TextSecret{
						Text: "updated secret value",
					},
				},
			},
		},
	)
	if err != nil {
		log.Fatalf("update secret failed: %v", err)
	}

	fmt.Println("✓ secret updated")

	// ============================================================
	// 6. GET SECRET AFTER UPDATE
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("6. GET UPDATED SECRET")
	fmt.Println("========================================")

	getResponse, err = secretClient.GetSecret(
		authCtx,
		&pb.GetSecretRequest{
			Id: secretID,
		},
	)
	if err != nil {
		log.Fatalf("get updated secret failed: %v", err)
	}

	printSecret(getResponse.GetSecret())

	// ============================================================
	// 7. LIST SECRETS
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("7. LIST SECRETS")
	fmt.Println("========================================")

	listResponse, err := secretClient.ListSecrets(
		authCtx,
		&pb.ListSecretsRequest{},
	)
	if err != nil {
		log.Fatalf("list secrets failed: %v", err)
	}

	fmt.Println("✓ secrets received")
	fmt.Println("  count:", len(listResponse.GetSecrets()))

	for _, secret := range listResponse.GetSecrets() {
		fmt.Printf(
			"  - id=%s type=%s\n",
			secret.GetId(),
			secret.GetType(),
		)
	}

	// ============================================================
	// 8. DELETE TEXT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("8. DELETE TEXT SECRET")
	fmt.Println("========================================")

	_, err = secretClient.DeleteSecret(
		authCtx,
		&pb.DeleteSecretRequest{
			Id: secretID,
		},
	)
	if err != nil {
		log.Fatalf("delete secret failed: %v", err)
	}

	fmt.Println("✓ secret deleted")

	// ============================================================
	// 9. CHECK THAT TEXT SECRET NO LONGER EXISTS
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("9. GET DELETED TEXT SECRET")
	fmt.Println("========================================")

	_, err = secretClient.GetSecret(
		authCtx,
		&pb.GetSecretRequest{
			Id: secretID,
		},
	)

	if err == nil {
		log.Fatal("expected GetSecret to return NotFound")
	}

	if status.Code(err) != codes.NotFound {
		log.Fatalf(
			"expected NotFound, got %v: %v",
			status.Code(err),
			err,
		)
	}

	fmt.Println("✓ deleted secret is not accessible")
	fmt.Println("  error:", err)

	// ============================================================
	// 10. CREATE BINARY SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("10. CREATE BINARY SECRET")
	fmt.Println("========================================")

	filename := "test.txt"
	mimeType := "text/plain"

	binaryCreateResponse, err := secretClient.CreateSecret(
		authCtx,
		&pb.CreateSecretRequest{
			Secret: &pb.Secret{
				Payload: &pb.Secret_Binary{
					Binary: &pb.BinarySecret{
						Filename: filename,
						MimeType: mimeType,
					},
				},
			},
		},
	)
	if err != nil {
		log.Fatalf(
			"create binary secret failed: %v",
			err,
		)
	}

	binarySecretID := binaryCreateResponse.GetId()

	fmt.Println("✓ binary secret created")
	fmt.Println("  secret id:", binarySecretID)
	fmt.Println("  filename:", filename)
	fmt.Println("  mime type:", mimeType)

	// ============================================================
	// 11. UPLOAD FILE
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("11. UPLOAD FILE")
	fmt.Println("========================================")

	originalData := []byte(
		"This is a test file.\n" +
			"It is uploaded using gRPC streaming.\n" +
			"Secret Keeper test.",
	)

	err = uploadFile(
		authCtx,
		binaryClient,
		binarySecretID,
		originalData,
	)
	if err != nil {
		log.Fatalf("upload file failed: %v", err)
	}

	fmt.Println("✓ file uploaded")
	fmt.Println("  size:", len(originalData), "bytes")

	// ============================================================
	// 12. DOWNLOAD FILE
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("12. DOWNLOAD FILE")
	fmt.Println("========================================")

	downloadedData, err := downloadFile(
		authCtx,
		binaryClient,
		binarySecretID,
	)
	if err != nil {
		log.Fatalf("download file failed: %v", err)
	}

	fmt.Println("✓ file downloaded")
	fmt.Println("  size:", len(downloadedData), "bytes")

	// ============================================================
	// 13. COMPARE FILES
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("13. COMPARE FILES")
	fmt.Println("========================================")

	if !bytes.Equal(originalData, downloadedData) {
		fmt.Println("✗ downloaded file differs from original")

		fmt.Println()
		fmt.Println("Original:")
		fmt.Printf("%q\n", originalData)

		fmt.Println()
		fmt.Println("Downloaded:")
		fmt.Printf("%q\n", downloadedData)

		log.Fatal("binary data mismatch")
	}

	fmt.Println("✓ original and downloaded files are identical")

	// ============================================================
	// 14. GET BINARY SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("14. GET BINARY SECRET")
	fmt.Println("========================================")

	binaryGetResponse, err := secretClient.GetSecret(
		authCtx,
		&pb.GetSecretRequest{
			Id: binarySecretID,
		},
	)
	if err != nil {
		log.Fatalf(
			"get binary secret failed: %v",
			err,
		)
	}

	printSecret(binaryGetResponse.GetSecret())

	// ============================================================
	// 15. DELETE BINARY SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("15. DELETE BINARY SECRET")
	fmt.Println("========================================")

	_, err = secretClient.DeleteSecret(
		authCtx,
		&pb.DeleteSecretRequest{
			Id: binarySecretID,
		},
	)
	if err != nil {
		log.Fatalf(
			"delete binary secret failed: %v",
			err,
		)
	}

	fmt.Println("✓ binary secret deleted")

	// ============================================================
	// 16. CHECK THAT BINARY SECRET NO LONGER EXISTS
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("16. GET DELETED BINARY SECRET")
	fmt.Println("========================================")

	_, err = secretClient.GetSecret(
		authCtx,
		&pb.GetSecretRequest{
			Id: binarySecretID,
		},
	)

	if err == nil {
		log.Fatal(
			"expected GetSecret to return NotFound",
		)
	}

	if status.Code(err) != codes.NotFound {
		log.Fatalf(
			"expected NotFound, got %v: %v",
			status.Code(err),
			err,
		)
	}

	fmt.Println("✓ deleted binary secret is not accessible")

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("ALL SCENARIOS PASSED")
	fmt.Println("========================================")

	runSecurityTests(
		ctx,
		authClient,
		secretClient,
		binaryClient,
	)

	runNegativeGRPCTests(
		authClient,
		secretClient,
		binaryClient,
	)
}

// ============================================================
// Upload file using client-side streaming
// ============================================================

func uploadFile(
	ctx context.Context,
	client pb.BinaryServiceClient,
	secretID string,
	data []byte,
) error {
	stream, err := client.UploadBinary(ctx)
	if err != nil {
		return fmt.Errorf("create upload stream: %w", err)
	}

	const chunkSize = 8

	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize

		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]

		err := stream.Send(
			&pb.UploadBinaryChunk{
				SecretId: secretID,
				Chunk:    chunk,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"send upload chunk: %w",
				err,
			)
		}

		fmt.Printf(
			"  uploaded chunk: %d-%d (%d bytes)\n",
			offset,
			end,
			len(chunk),
		)
	}

	_, err = stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf(
			"close upload stream: %w",
			err,
		)
	}

	return nil
}

// ============================================================
// Download file using server-side streaming
// ============================================================

func downloadFile(
	ctx context.Context,
	client pb.BinaryServiceClient,
	secretID string,
) ([]byte, error) {
	stream, err := client.DownloadBinary(
		ctx,
		&pb.DownloadBinaryRequest{
			SecretId: secretID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create download stream: %w",
			err,
		)
	}

	var data []byte

	for {
		response, err := stream.Recv()

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf(
				"receive download chunk: %w",
				err,
			)
		}

		chunk := response.GetChunk()

		data = append(data, chunk...)

		fmt.Printf(
			"  downloaded chunk: %d bytes\n",
			len(chunk),
		)
	}

	return data, nil
}

// ============================================================
// Authentication
// ============================================================

func authenticatedContext(
	ctx context.Context,
	token string,
) context.Context {
	md := metadata.Pairs(
		"authorization",
		"Bearer "+token,
	)

	return metadata.NewOutgoingContext(
		ctx,
		md,
	)
}

// ============================================================
// Print secret
// ============================================================

func printSecret(secret *pb.Secret) {
	if secret == nil {
		fmt.Println("  secret is nil")
		return
	}

	fmt.Println("✓ secret received")

	if secret.GetMetadata() != nil {
		fmt.Println(
			"  id:",
			secret.GetMetadata().GetId(),
		)
		fmt.Println(
			"  type:",
			secret.GetMetadata().GetType(),
		)
	}

	switch payload := secret.GetPayload().(type) {
	case *pb.Secret_Text:
		fmt.Println(
			"  text:",
			payload.Text.GetText(),
		)

	case *pb.Secret_LoginPassword:
		fmt.Println(
			"  login:",
			payload.LoginPassword.GetLogin(),
		)
		fmt.Println(
			"  password:",
			payload.LoginPassword.GetPassword(),
		)

	case *pb.Secret_BankCard:
		fmt.Println(
			"  card number:",
			payload.BankCard.GetNumber(),
		)
		fmt.Println(
			"  card holder:",
			payload.BankCard.GetHolder(),
		)
		fmt.Println(
			"  card expire:",
			payload.BankCard.GetExpire(),
		)
		fmt.Println(
			"  card CVV:",
			payload.BankCard.GetCvv(),
		)

	case *pb.Secret_Binary:
		fmt.Println(
			"  filename:",
			payload.Binary.GetFilename(),
		)
		fmt.Println(
			"  mime type:",
			payload.Binary.GetMimeType(),
		)

	default:
		fmt.Println("  payload: <unknown>")
	}
}
