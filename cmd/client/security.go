package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func runSecurityTests(
	ctx context.Context,
	authClient pb.AuthServiceClient,
	secretClient pb.SecretServiceClient,
	binaryClient pb.BinaryServiceClient,
) {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("SECURITY TESTS: USER A vs USER B")
	fmt.Println("========================================")

	// ============================================================
	// 1. CREATE USER A
	// ============================================================

	fmt.Println()
	fmt.Println("1. CREATE USER A")

	loginA := uniqueLogin("security_a")
	passwordA := "password-a"

	_, err := authClient.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    loginA,
			Password: passwordA,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("register user A failed: %v", err)
	}

	loginResponseA, err := authClient.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    loginA,
			Password: passwordA,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("login user A failed: %v", err)
	}

	ctxA := authenticatedContext(
		context.Background(),
		loginResponseA.GetAccessToken(),
	)

	fmt.Println("✓ User A authenticated")

	// ============================================================
	// 2. CREATE USER B
	// ============================================================

	fmt.Println()
	fmt.Println("2. CREATE USER B")

	loginB := uniqueLogin("security_b")
	passwordB := "password-b"

	_, err = authClient.Register(
		ctx,
		pb.RegisterRequest_builder{
			Login:    loginB,
			Password: passwordB,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("register user B failed: %v", err)
	}

	loginResponseB, err := authClient.Login(
		ctx,
		pb.LoginRequest_builder{
			Login:    loginB,
			Password: passwordB,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("login user B failed: %v", err)
	}

	ctxB := authenticatedContext(
		context.Background(),
		loginResponseB.GetAccessToken(),
	)

	fmt.Println("✓ User B authenticated")

	// ============================================================
	// 3. USER A CREATES SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("3. USER A CREATES SECRET")

	const secretAText = "User A private secret"

	createAResponse, err := secretClient.CreateSecret(
		ctxA,
		pb.CreateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Text: pb.TextSecret_builder{
					Text: secretAText,
				}.Build(),
			}.Build(),
		}.Build(),
	)
	if err != nil {
		log.Fatalf("User A create secret failed: %v", err)
	}

	secretAID := createAResponse.GetId()

	fmt.Println("✓ User A created secret")
	fmt.Println("  secret id:", secretAID)

	// ============================================================
	// 4. USER B CREATES SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("4. USER B CREATES SECRET")

	const secretBText = "User B private secret"

	createBResponse, err := secretClient.CreateSecret(
		ctxB,
		pb.CreateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Text: pb.TextSecret_builder{
					Text: secretBText,
				}.Build(),
			}.Build(),
		}.Build(),
	)
	if err != nil {
		log.Fatalf("User B create secret failed: %v", err)
	}

	secretBID := createBResponse.GetId()

	fmt.Println("✓ User B created secret")
	fmt.Println("  secret id:", secretBID)

	// ============================================================
	// 5. USER A CAN ACCESS OWN SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("5. USER A → OWN SECRET")

	response, err := secretClient.GetSecret(
		ctxA,
		pb.GetSecretRequest_builder{
			Id: secretAID,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("User A cannot access own secret: %v", err)
	}

	if response.GetSecret() == nil {
		log.Fatal("User A received nil secret")
	}

	if response.GetSecret().GetText().GetText() != secretAText {
		log.Fatalf(
			"User A received unexpected secret value: %q",
			response.GetSecret().GetText().GetText(),
		)
	}

	fmt.Println("✓ User A can access own secret")

	// ============================================================
	// 6. USER B CAN ACCESS OWN SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("6. USER B → OWN SECRET")

	response, err = secretClient.GetSecret(
		ctxB,
		pb.GetSecretRequest_builder{
			Id: secretBID,
		}.Build(),
	)
	if err != nil {
		log.Fatalf("User B cannot access own secret: %v", err)
	}

	if response.GetSecret() == nil {
		log.Fatal("User B received nil secret")
	}

	if response.GetSecret().GetText().GetText() != secretBText {
		log.Fatalf(
			"User B received unexpected secret value: %q",
			response.GetSecret().GetText().GetText(),
		)
	}

	fmt.Println("✓ User B can access own secret")

	// ============================================================
	// 7. USER B CANNOT GET USER A SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("7. USER B → USER A SECRET")

	_, err = secretClient.GetSecret(
		ctxB,
		pb.GetSecretRequest_builder{
			Id: secretAID,
		}.Build(),
	)

	assertNotFound(
		"User B must not be able to get User A secret",
		err,
	)

	fmt.Println("✓ User B cannot access User A secret")

	// ============================================================
	// 8. USER A CANNOT GET USER B SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("8. USER A → USER B SECRET")

	_, err = secretClient.GetSecret(
		ctxA,
		pb.GetSecretRequest_builder{
			Id: secretBID,
		}.Build(),
	)

	assertNotFound(
		"User A must not be able to get User B secret",
		err,
	)

	fmt.Println("✓ User A cannot access User B secret")

	// ============================================================
	// 9. USER B CANNOT UPDATE USER A SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("9. USER B → UPDATE USER A SECRET")

	_, err = secretClient.UpdateSecret(
		ctxB,
		pb.UpdateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Metadata: pb.SecretMetadata_builder{
					Id: secretAID,
				}.Build(),
				Text: pb.TextSecret_builder{
					Text: "HACKED BY USER B",
				}.Build(),
			}.Build(),
		}.Build(),
	)

	assertNotFound(
		"User B must not be able to update User A secret",
		err,
	)

	fmt.Println("✓ User B cannot update User A secret")

	// ============================================================
	// 10. CHECK THAT USER A SECRET WAS NOT MODIFIED
	// ============================================================

	fmt.Println()
	fmt.Println("10. CHECK USER A SECRET AFTER FAILED UPDATE")

	response, err = secretClient.GetSecret(
		ctxA,
		pb.GetSecretRequest_builder{
			Id: secretAID,
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"cannot get User A secret after failed update: %v",
			err,
		)
	}

	actualText := response.GetSecret().GetText().GetText()

	if actualText != secretAText {
		log.Fatalf(
			"security violation: User A secret was modified: %q",
			actualText,
		)
	}

	fmt.Println("✓ User A secret was not modified")

	// ============================================================
	// 11. USER A CANNOT UPDATE USER B SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("11. USER A → UPDATE USER B SECRET")

	_, err = secretClient.UpdateSecret(
		ctxA,
		pb.UpdateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Metadata: pb.SecretMetadata_builder{
					Id: secretBID,
				}.Build(),
				Text: pb.TextSecret_builder{
					Text: "HACKED BY USER A",
				}.Build(),
			}.Build(),
		}.Build(),
	)

	assertNotFound(
		"User A must not be able to update User B secret",
		err,
	)

	fmt.Println("✓ User A cannot update User B secret")

	// ============================================================
	// 12. USER B CANNOT DELETE USER A SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("12. USER B → DELETE USER A SECRET")

	_, err = secretClient.DeleteSecret(
		ctxB,
		pb.DeleteSecretRequest_builder{
			Id: secretAID,
		}.Build(),
	)

	assertNotFound(
		"User B must not be able to delete User A secret",
		err,
	)

	fmt.Println("✓ User B cannot delete User A secret")

	// ============================================================
	// 13. CHECK THAT USER A SECRET STILL EXISTS
	// ============================================================

	fmt.Println()
	fmt.Println("13. CHECK USER A SECRET AFTER FAILED DELETE")

	_, err = secretClient.GetSecret(
		ctxA,
		pb.GetSecretRequest_builder{
			Id: secretAID,
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"User A secret was deleted by User B: %v",
			err,
		)
	}

	fmt.Println("✓ User A secret still exists")

	// ============================================================
	// 14. USER A CANNOT DELETE USER B SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("14. USER A → DELETE USER B SECRET")

	_, err = secretClient.DeleteSecret(
		ctxA,
		pb.DeleteSecretRequest_builder{
			Id: secretBID,
		}.Build(),
	)

	assertNotFound(
		"User A must not be able to delete User B secret",
		err,
	)

	fmt.Println("✓ User A cannot delete User B secret")

	// ============================================================
	// 15. USER A LIST
	// ============================================================

	fmt.Println()
	fmt.Println("15. USER A → LIST SECRETS")

	listA, err := secretClient.ListSecrets(
		ctxA,
		&pb.ListSecretsRequest{},
	)
	if err != nil {
		log.Fatalf("User A list secrets failed: %v", err)
	}

	if !containsSecret(listA.GetSecrets(), secretAID) {
		log.Fatal(
			"User A cannot see own secret in ListSecrets",
		)
	}

	if containsSecret(listA.GetSecrets(), secretBID) {
		log.Fatal(
			"security violation: User A can see User B secret in ListSecrets",
		)
	}

	fmt.Println("✓ User A sees only own secret")

	// ============================================================
	// 16. USER B LIST
	// ============================================================

	fmt.Println()
	fmt.Println("16. USER B → LIST SECRETS")

	listB, err := secretClient.ListSecrets(
		ctxB,
		&pb.ListSecretsRequest{},
	)
	if err != nil {
		log.Fatalf("User B list secrets failed: %v", err)
	}

	if !containsSecret(listB.GetSecrets(), secretBID) {
		log.Fatal(
			"User B cannot see own secret in ListSecrets",
		)
	}

	if containsSecret(listB.GetSecrets(), secretAID) {
		log.Fatal(
			"security violation: User B can see User A secret in ListSecrets",
		)
	}

	fmt.Println("✓ User B sees only own secret")

	// ============================================================
	// 17. CREATE USER A BINARY SECRET
	// ============================================================

	fmt.Println()
	fmt.Println("17. USER A → CREATE BINARY SECRET")

	binaryCreateResponse, err := secretClient.CreateSecret(
		ctxA,
		pb.CreateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Binary: pb.BinarySecret_builder{
					Filename: "user-a-secret.txt",
					MimeType: "text/plain",
				}.Build(),
			}.Build(),
		}.Build(),
	)
	if err != nil {
		log.Fatalf(
			"User A create binary secret failed: %v",
			err,
		)
	}

	binaryAID := binaryCreateResponse.GetId()

	fmt.Println("✓ User A created binary secret")
	fmt.Println("  secret id:", binaryAID)

	// ============================================================
	// 18. USER A UPLOADS FILE
	// ============================================================

	fmt.Println()
	fmt.Println("18. USER A → UPLOAD FILE")

	originalData := []byte(
		"User A private binary data",
	)

	err = uploadFile(
		ctxA,
		binaryClient,
		binaryAID,
		originalData,
	)
	if err != nil {
		log.Fatalf(
			"User A upload failed: %v",
			err,
		)
	}

	fmt.Println("✓ User A uploaded file")

	// ============================================================
	// 19. USER A DOWNLOADS OWN FILE
	// ============================================================

	fmt.Println()
	fmt.Println("19. USER A → DOWNLOAD OWN FILE")

	downloadedData, err := downloadFile(
		ctxA,
		binaryClient,
		binaryAID,
	)
	if err != nil {
		log.Fatalf(
			"User A download failed: %v",
			err,
		)
	}

	if !bytes.Equal(originalData, downloadedData) {
		log.Fatal(
			"User A downloaded data differs from uploaded data",
		)
	}

	fmt.Println("✓ User A can download own file")

	// ============================================================
	// 20. USER B CANNOT DOWNLOAD USER A FILE
	// ============================================================

	fmt.Println()
	fmt.Println("20. USER B → DOWNLOAD USER A FILE")

	_, err = downloadFile(
		ctxB,
		binaryClient,
		binaryAID,
	)

	assertNotFound(
		"User B must not be able to download User A file",
		err,
	)

	fmt.Println("✓ User B cannot download User A file")

	// ============================================================
	// 21. USER B CANNOT UPLOAD TO USER A FILE
	// ============================================================

	fmt.Println()
	fmt.Println("21. USER B → UPLOAD TO USER A FILE")

	err = uploadFile(
		ctxB,
		binaryClient,
		binaryAID,
		[]byte("HACKED BY USER B"),
	)

	assertNotFound(
		"User B must not be able to upload to User A file",
		err,
	)

	fmt.Println("✓ User B cannot modify User A file")

	// ============================================================
	// 22. CHECK THAT USER A FILE WAS NOT MODIFIED
	// ============================================================

	fmt.Println()
	fmt.Println("22. CHECK USER A FILE AFTER FAILED UPLOAD")

	downloadedData, err = downloadFile(
		ctxA,
		binaryClient,
		binaryAID,
	)
	if err != nil {
		log.Fatalf(
			"User A cannot download own file after failed attack: %v",
			err,
		)
	}

	if !bytes.Equal(originalData, downloadedData) {
		log.Fatal(
			"security violation: User A file was modified by User B",
		)
	}

	fmt.Println("✓ User A file was not modified")

	// ============================================================
	// RESULT
	// ============================================================

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("ALL SECURITY TESTS PASSED")
	fmt.Println("========================================")
}

func assertNotFound(description string, err error) {
	if err == nil {
		log.Fatalf(
			"security violation: %s: expected error, got nil",
			description,
		)
	}

	if status.Code(err) != codes.NotFound {
		log.Fatalf(
			"security violation: %s: expected NotFound, got %v: %v",
			description,
			status.Code(err),
			err,
		)
	}
}

func containsSecret(
	secrets []*pb.SecretMetadata,
	id string,
) bool {
	for _, secret := range secrets {
		if secret.GetId() == id {
			return true
		}
	}

	return false
}

func uniqueLogin(prefix string) string {
	return fmt.Sprintf(
		"%s_%d",
		prefix,
		time.Now().UnixNano(),
	)
}
