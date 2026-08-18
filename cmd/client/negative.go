package main

import (
	"context"
	"fmt"
	"io"
	"log"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func runNegativeGRPCTests(
	authClient pb.AuthServiceClient,
	secretClient pb.SecretServiceClient,
	binaryClient pb.BinaryServiceClient,
) {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("NEGATIVE gRPC TESTS")
	fmt.Println("========================================")

	// ------------------------------------------------------------
	// Подготавливаем отдельного пользователя для тестов.
	// ------------------------------------------------------------

	ctx := context.Background()

	login := uniqueLogin("negative")
	password := "negative-password"

	_, err := authClient.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    login,
			Password: password,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("failed to create negative-test user: %v", err)
	}

	loginResponse, err := authClient.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    login,
			Password: password,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("failed to login negative-test user: %v", err)
	}

	authCtx := authenticatedContext(
		context.Background(),
		loginResponse.GetAccessToken(),
	)

	fmt.Println("✓ test user authenticated")

	// ============================================================
	// AUTH
	// ============================================================

	runNegativeAuthTests(authClient)

	// ============================================================
	// SECRET
	// ============================================================

	runNegativeSecretTests(
		secretClient,
		authCtx,
	)

	// ============================================================
	// BINARY
	// ============================================================

	runNegativeBinaryTests(
		secretClient,
		binaryClient,
		authCtx,
	)

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("ALL NEGATIVE gRPC TESTS PASSED")
	fmt.Println("========================================")
}

func runNegativeAuthTests(
	authClient pb.AuthServiceClient,
) {
	fmt.Println()
	fmt.Println("----------------------------------------")
	fmt.Println("AUTH NEGATIVE TESTS")
	fmt.Println("----------------------------------------")

	ctx := context.Background()

	// ============================================================
	// 1. REGISTER WITH EMPTY LOGIN
	// ============================================================

	fmt.Println()
	fmt.Println("1. REGISTER WITH EMPTY LOGIN")

	_, err := authClient.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    "",
			Password: "password",
		}.Build(),
	)

	assertCode(
		"Register with empty login",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ empty login rejected")

	// ============================================================
	// 2. REGISTER WITH EMPTY PASSWORD
	// ============================================================

	fmt.Println()
	fmt.Println("2. REGISTER WITH EMPTY PASSWORD")

	_, err = authClient.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    uniqueLogin("empty-password"),
			Password: "",
		}.Build(),
	)

	assertCode(
		"Register with empty password",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ empty password rejected")

	// ============================================================
	// 3. REGISTER WITH EXISTING LOGIN
	// ============================================================

	fmt.Println()
	fmt.Println("3. REGISTER WITH EXISTING LOGIN")

	login := uniqueLogin("duplicate")

	_, err = authClient.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    login,
			Password: "password",
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to create user for duplicate-login test: %v",
			err,
		)
	}

	_, err = authClient.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    login,
			Password: "password",
		}.Build(),
	)

	assertCode(
		"Register with existing login",
		err,
		codes.AlreadyExists,
	)

	fmt.Println("✓ duplicate login rejected")

	// ============================================================
	// 4. LOGIN WITH WRONG PASSWORD
	// ============================================================

	fmt.Println()
	fmt.Println("4. LOGIN WITH WRONG PASSWORD")

	_, err = authClient.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    login,
			Password: "wrong-password",
		}.Build(),
	)

	assertCode(
		"Login with wrong password",
		err,
		codes.Unauthenticated,
	)

	fmt.Println("✓ wrong password rejected")

	// ============================================================
	// 5. LOGIN WITH NON-EXISTENT USER
	// ============================================================

	fmt.Println()
	fmt.Println("5. LOGIN WITH NON-EXISTENT USER")

	_, err = authClient.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    uniqueLogin("does-not-exist"),
			Password: "password",
		}.Build(),
	)

	assertCode(
		"Login with non-existent user",
		err,
		codes.Unauthenticated,
	)

	fmt.Println("✓ non-existent user rejected")

	// ============================================================
	// 6. LOGIN WITH EMPTY LOGIN
	// ============================================================

	fmt.Println()
	fmt.Println("6. LOGIN WITH EMPTY LOGIN")

	_, err = authClient.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    "",
			Password: "password",
		}.Build(),
	)

	assertCode(
		"Login with empty login",
		err,
		codes.Unauthenticated,
	)

	fmt.Println("✓ empty login rejected")

	// ============================================================
	// 7. LOGIN WITH EMPTY PASSWORD
	// ============================================================

	fmt.Println()
	fmt.Println("7. LOGIN WITH EMPTY PASSWORD")

	_, err = authClient.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    uniqueLogin("empty-login-password"),
			Password: "",
		}.Build(),
	)

	assertCode(
		"Login with empty password",
		err,
		codes.Unauthenticated,
	)

	fmt.Println("✓ empty password rejected")
}

func runNegativeSecretTests(
	secretClient pb.SecretServiceClient,
	authCtx context.Context,
) {
	fmt.Println()
	fmt.Println("----------------------------------------")
	fmt.Println("SECRET NEGATIVE TESTS")
	fmt.Println("----------------------------------------")

	// ============================================================
	// 1. CREATE WITH NIL SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("1. CREATE WITH NIL SECRET")

	_, err := secretClient.CreateSecret(
		authCtx,
		pb.CreateSecretRequest_builder{
			Secret: nil,
		}.Build(),
	)

	assertCode(
		"Create with nil secret",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ nil secret rejected")

	// ============================================================
	// 2. CREATE WITH EMPTY PAYLOAD
	// ============================================================

	fmt.Println()
	fmt.Println("2. CREATE WITH EMPTY PAYLOAD")

	_, err = secretClient.CreateSecret(
		authCtx,
		pb.CreateSecretRequest_builder{
			Secret: pb.Secret_builder{}.Build(),
		}.Build(),
	)

	assertCode(
		"Create with empty payload",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ empty payload rejected")

	// ============================================================
	// 3. GET WITH INVALID UUID
	// ============================================================

	fmt.Println()
	fmt.Println("3. GET WITH INVALID UUID")

	_, err = secretClient.GetSecret(
		authCtx,
		pb.GetSecretRequest_builder{
			Id: "not-a-uuid",
		}.Build(),
	)

	assertCode(
		"Get with invalid UUID",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ invalid UUID rejected")

	// ============================================================
	// 4. GET NON-EXISTENT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("4. GET NON-EXISTENT SECRET")

	_, err = secretClient.GetSecret(
		authCtx,
		pb.GetSecretRequest_builder{
			Id: "00000000-0000-0000-0000-000000000001",
		}.Build(),
	)

	assertCode(
		"Get non-existent secret",
		err,
		codes.NotFound,
	)

	fmt.Println("✓ non-existent secret rejected")

	// ============================================================
	// 5. UPDATE WITH NIL SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("5. UPDATE WITH NIL SECRET")

	_, err = secretClient.UpdateSecret(
		authCtx,
		pb.UpdateSecretRequest_builder{
			Secret: nil,
		}.Build(),
	)

	assertCode(
		"Update with nil secret",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ nil secret rejected")

	// ============================================================
	// 6. UPDATE WITHOUT ID
	// ============================================================

	fmt.Println()
	fmt.Println("6. UPDATE WITHOUT ID")

	_, err = secretClient.UpdateSecret(
		authCtx,
		pb.UpdateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Text: pb.TextSecret_builder{
					Text: "updated",
				}.Build(),
			}.Build(),
		}.Build(),
	)

	assertCode(
		"Update without ID",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ update without ID rejected")

	// ============================================================
	// 7. UPDATE NON-EXISTENT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("7. UPDATE NON-EXISTENT SECRET")

	_, err = secretClient.UpdateSecret(
		authCtx,
		pb.UpdateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Metadata: pb.SecretMetadata_builder{
					Id: "00000000-0000-0000-0000-000000000002",
				}.Build(),
				Text: pb.TextSecret_builder{
					Text: "updated",
				}.Build(),
			}.Build(),
		}.Build(),
	)

	assertCode(
		"Update non-existent secret",
		err,
		codes.NotFound,
	)

	fmt.Println("✓ update of non-existent secret rejected")

	// ============================================================
	// 8. DELETE WITH INVALID UUID
	// ============================================================

	fmt.Println()
	fmt.Println("8. DELETE WITH INVALID UUID")

	_, err = secretClient.DeleteSecret(
		authCtx,
		pb.DeleteSecretRequest_builder{
			Id: "not-a-uuid",
		}.Build(),
	)

	assertCode(
		"Delete with invalid UUID",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ invalid UUID rejected")

	// ============================================================
	// 9. DELETE NON-EXISTENT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("9. DELETE NON-EXISTENT SECRET")

	_, err = secretClient.DeleteSecret(
		authCtx,
		pb.DeleteSecretRequest_builder{
			Id: "00000000-0000-0000-0000-000000000003",
		}.Build(),
	)

	assertCode(
		"Delete non-existent secret",
		err,
		codes.NotFound,
	)

	fmt.Println("✓ delete of non-existent secret rejected")
}

func runNegativeBinaryTests(
	secretClient pb.SecretServiceClient,
	binaryClient pb.BinaryServiceClient,
	authCtx context.Context,
) {
	fmt.Println()
	fmt.Println("----------------------------------------")
	fmt.Println("BINARY NEGATIVE TESTS")
	fmt.Println("----------------------------------------")

	// ============================================================
	// 1. UPLOAD WITHOUT CHUNKS
	// ============================================================

	fmt.Println()
	fmt.Println("1. UPLOAD WITHOUT CHUNKS")

	stream, err := binaryClient.UploadBinary(authCtx)
	if err != nil {
		log.Fatalf(
			"failed to create upload stream: %v",
			err,
		)
	}

	_, err = stream.CloseAndRecv()

	assertCode(
		"Upload without chunks",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ empty upload rejected")

	// ============================================================
	// 2. UPLOAD WITH EMPTY SECRET ID
	// ============================================================

	fmt.Println()
	fmt.Println("2. UPLOAD WITH EMPTY SECRET ID")

	stream, err = binaryClient.UploadBinary(authCtx)
	if err != nil {
		log.Fatalf(
			"failed to create upload stream: %v",
			err,
		)
	}

	err = stream.Send(
		pb.UploadBinaryChunk_builder{
			SecretId: "",
			Chunk:    []byte("test"),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to send empty-secret-id chunk: %v",
			err,
		)
	}

	_, err = stream.CloseAndRecv()

	assertCode(
		"Upload with empty secret ID",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ empty secret ID rejected")

	// ============================================================
	// 3. UPLOAD WITH INVALID UUID
	// ============================================================

	fmt.Println()
	fmt.Println("3. UPLOAD WITH INVALID UUID")

	stream, err = binaryClient.UploadBinary(authCtx)
	if err != nil {
		log.Fatalf(
			"failed to create upload stream: %v",
			err,
		)
	}

	err = stream.Send(
		pb.UploadBinaryChunk_builder{
			SecretId: "not-a-uuid",
			Chunk:    []byte("test"),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to send invalid-uuid chunk: %v",
			err,
		)
	}

	_, err = stream.CloseAndRecv()

	assertCode(
		"Upload with invalid UUID",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ invalid UUID rejected")

	// ============================================================
	// 4. UPLOAD TO NON-EXISTENT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("4. UPLOAD TO NON-EXISTENT SECRET")

	stream, err = binaryClient.UploadBinary(authCtx)
	if err != nil {
		log.Fatalf(
			"failed to create upload stream: %v",
			err,
		)
	}

	err = stream.Send(
		pb.UploadBinaryChunk_builder{
			SecretId: "00000000-0000-0000-0000-000000000010",
			Chunk:    []byte("test"),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to send chunk: %v",
			err,
		)
	}

	_, err = stream.CloseAndRecv()

	assertCode(
		"Upload to non-existent secret",
		err,
		codes.NotFound,
	)

	fmt.Println("✓ upload to non-existent secret rejected")

	// ============================================================
	// 5. CREATE TEXT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("5. CREATE TEXT SECRET FOR BINARY TEST")

	response, err := secretClient.CreateSecret(
		authCtx,
		pb.CreateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Text: pb.TextSecret_builder{
					Text: "not a binary secret",
				}.Build(),
			}.Build(),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to create text secret: %v",
			err,
		)
	}

	textSecretID := response.GetId()

	fmt.Println("✓ text secret created")

	// ============================================================
	// 6. UPLOAD TO TEXT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("6. UPLOAD TO TEXT SECRET")

	stream, err = binaryClient.UploadBinary(authCtx)
	if err != nil {
		log.Fatalf(
			"failed to create upload stream: %v",
			err,
		)
	}

	err = stream.Send(
		pb.UploadBinaryChunk_builder{
			SecretId: textSecretID,
			Chunk:    []byte("this must fail"),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to send chunk: %v",
			err,
		)
	}

	_, err = stream.CloseAndRecv()

	assertCode(
		"Upload to TEXT secret",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ upload to TEXT secret rejected")

	// ============================================================
	// 7. DOWNLOAD INVALID UUID
	// ============================================================

	fmt.Println()
	fmt.Println("7. DOWNLOAD WITH INVALID UUID")

	downloadStream, err := binaryClient.DownloadBinary(
		authCtx,
		pb.DownloadBinaryRequest_builder{
			SecretId: "not-a-uuid",
		}.Build(),
	)
	if err == nil {
		// В server-streaming RPC ошибка может возникнуть не на самом
		// вызове, а при Recv().
		err = receiveExpectedStreamError(downloadStream)
	}

	assertCode(
		"Download with invalid UUID",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ invalid UUID rejected")

	// ============================================================
	// 8. DOWNLOAD NON-EXISTENT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("8. DOWNLOAD NON-EXISTENT SECRET")

	downloadStream, err = binaryClient.DownloadBinary(
		authCtx,
		pb.DownloadBinaryRequest_builder{
			SecretId: "00000000-0000-0000-0000-000000000011",
		}.Build(),
	)
	if err == nil {
		err = receiveExpectedStreamError(downloadStream)
	}

	assertCode(
		"Download non-existent secret",
		err,
		codes.NotFound,
	)

	fmt.Println("✓ download of non-existent secret rejected")

	// ============================================================
	// 9. DOWNLOAD TEXT SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("9. DOWNLOAD TEXT SECRET")

	downloadStream, err = binaryClient.DownloadBinary(
		authCtx,
		pb.DownloadBinaryRequest_builder{
			SecretId: textSecretID,
		}.Build(),
	)
	if err == nil {
		err = receiveExpectedStreamError(downloadStream)
	}

	assertCode(
		"Download TEXT secret",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ download of TEXT secret rejected")

	// ============================================================
	// 10. CREATE EMPTY BINARY SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("10. CREATE BINARY SECRET WITHOUT FILE")

	response, err = secretClient.CreateSecret(
		authCtx,
		pb.CreateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Binary: pb.BinarySecret_builder{
					Filename: "not-uploaded.txt",
					MimeType: "text/plain",
				}.Build(),
			}.Build(),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to create binary secret: %v",
			err,
		)
	}

	binarySecretID := response.GetId()

	fmt.Println("✓ empty binary secret created")

	// ============================================================
	// 11. DOWNLOAD BINARY BEFORE UPLOAD
	// ============================================================

	fmt.Println()
	fmt.Println("11. DOWNLOAD BINARY BEFORE UPLOAD")

	downloadStream, err = binaryClient.DownloadBinary(
		authCtx,
		pb.DownloadBinaryRequest_builder{
			SecretId: binarySecretID,
		}.Build(),
	)
	if err == nil {
		err = receiveExpectedStreamError(downloadStream)
	}

	assertCode(
		"Download binary before upload",
		err,
		codes.NotFound,
	)

	fmt.Println("✓ download before upload rejected")

	// ============================================================
	// 12. INVALID STREAM
	// ============================================================

	fmt.Println()
	fmt.Println("12. INVALID STREAM")

	stream, err = binaryClient.UploadBinary(authCtx)
	if err != nil {
		log.Fatalf(
			"failed to create upload stream: %v",
			err,
		)
	}

	// Первый chunk содержит один secret_id.
	err = stream.Send(
		pb.UploadBinaryChunk_builder{
			SecretId: binarySecretID,
			Chunk:    []byte("first chunk"),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to send first chunk: %v",
			err,
		)
	}

	// Второй chunk содержит другой secret_id.
	err = stream.Send(
		pb.UploadBinaryChunk_builder{
			SecretId: textSecretID,
			Chunk:    []byte("second chunk"),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"failed to send second chunk: %v",
			err,
		)
	}

	_, err = stream.CloseAndRecv()

	assertCode(
		"Upload stream with different secret IDs",
		err,
		codes.InvalidArgument,
	)

	fmt.Println("✓ invalid stream rejected")
}

func receiveExpectedStreamError(
	stream pb.BinaryService_DownloadBinaryClient,
) error {
	if stream == nil {
		return nil
	}

	for {
		_, err := stream.Recv()

		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}
	}
}

func assertCode(
	description string,
	err error,
	expected codes.Code,
) {
	if err == nil {
		log.Fatalf(
			"negative test failed: %s: expected %s, got nil",
			description,
			expected,
		)
	}

	actual := status.Code(err)

	if actual != expected {
		log.Fatalf(
			"negative test failed: %s: expected %s, got %s: %v",
			description,
			expected,
			actual,
			err,
		)
	}
}
