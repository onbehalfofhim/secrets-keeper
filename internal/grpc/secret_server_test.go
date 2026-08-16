package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/logger"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/serializer"
	"github.com/onbehalfofhim/secrets-keeper/internal/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockSecretRepo struct {
	createFunc func(
		ctx context.Context,
		secret *models.Secret,
	) (*models.Secret, error)

	getByIDFunc func(
		ctx context.Context,
		ownerID, secretID uuid.UUID,
	) (*models.Secret, error)

	listFunc func(
		ctx context.Context,
		ownerID uuid.UUID,
	) ([]*models.Secret, error)

	updateFunc func(
		ctx context.Context,
		secret *models.Secret,
	) (*models.Secret, error)

	deleteFunc func(
		ctx context.Context,
		ownerID, secretID uuid.UUID,
	) error

	updateEncryptedDataFunc func(
		ctx context.Context,
		ownerID, secretID uuid.UUID,
		data []byte,
	) error
}

func (m *mockSecretRepo) Create(
	ctx context.Context,
	secret *models.Secret,
) (*models.Secret, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, secret)
	}

	return secret, nil
}

func (m *mockSecretRepo) GetByID(
	ctx context.Context,
	ownerID, secretID uuid.UUID,
) (*models.Secret, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, ownerID, secretID)
	}

	return nil, nil
}

func (m *mockSecretRepo) List(
	ctx context.Context,
	ownerID uuid.UUID,
) ([]*models.Secret, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, ownerID)
	}

	return nil, nil
}

func (m *mockSecretRepo) Update(
	ctx context.Context,
	secret *models.Secret,
) (*models.Secret, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, secret)
	}

	return secret, nil
}

func (m *mockSecretRepo) UpdateEncryptedData(
	ctx context.Context,
	ownerID, secretID uuid.UUID,
	data []byte,
) error {
	if m.updateEncryptedDataFunc != nil {
		return m.updateEncryptedDataFunc(
			ctx,
			ownerID,
			secretID,
			data,
		)
	}

	return nil
}

func (m *mockSecretRepo) Delete(
	ctx context.Context,
	ownerID, secretID uuid.UUID,
) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, ownerID, secretID)
	}

	return nil
}

type mockEncryptor struct {
	encryptFunc func([]byte) ([]byte, error)
	decryptFunc func([]byte) ([]byte, error)
}

func (m *mockEncryptor) Encrypt(data []byte) ([]byte, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(data)
	}

	return data, nil
}

func (m *mockEncryptor) Decrypt(data []byte) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(data)
	}

	return data, nil
}

func newTestSecretServer(repo repository.SecretRepo) *SecretServer {
	secretService := service.NewSecretService(
		repo,
		&mockEncryptor{},
		serializer.NewJSONSerializer(),
	)
	logger := logger.NewLogger()

	return NewSecretServer(secretService, logger)
}

func contextWithUserID(userID uuid.UUID) context.Context {
	return context.WithValue(
		context.Background(),
		userIDKey,
		userID.String(),
	)
}

func TestNewSecretServer(t *testing.T) {
	repo := &mockSecretRepo{}

	server := newTestSecretServer(repo)

	if server == nil {
		t.Fatal("expected server, got nil")
	}

	if server.service == nil {
		t.Fatal("expected service, got nil")
	}
}

func TestGetUserID(t *testing.T) {
	validID := uuid.New()

	tests := []struct {
		name     string
		ctx      context.Context
		wantID   uuid.UUID
		wantCode codes.Code
	}{
		{
			name:     "success",
			ctx:      contextWithUserID(validID),
			wantID:   validID,
			wantCode: codes.OK,
		},
		{
			name:     "user ID is missing",
			ctx:      context.Background(),
			wantID:   uuid.Nil,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "invalid user ID",
			ctx: context.WithValue(
				context.Background(),
				userIDKey,
				"not-a-uuid",
			),
			wantID:   uuid.Nil,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getUserID(tt.ctx)

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got != tt.wantID {
					t.Errorf(
						"ID = %v, want %v",
						got,
						tt.wantID,
					)
				}

				return
			}

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if status.Code(err) != tt.wantCode {
				t.Errorf(
					"code = %v, want %v",
					status.Code(err),
					tt.wantCode,
				)
			}

			if got != tt.wantID {
				t.Errorf(
					"ID = %v, want %v",
					got,
					tt.wantID,
				)
			}
		})
	}
}

func TestProtoMetadataToJSON(t *testing.T) {
	tests := []struct {
		name     string
		metadata *pb.SecretMetadata
		want     string
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			want:     `{}`,
		},
		{
			name: "full metadata",
			metadata: pb.SecretMetadata_builder{
				Title:       "My secret",
				Description: "Description",
			}.Build(),
			want: `{"title":"My secret","description":"Description"}`,
		},
		{
			name:     "empty metadata",
			metadata: &pb.SecretMetadata{},
			want:     `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protoMetadataToJSON(tt.metadata)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf(
					"got %s, want %s",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestProtoToCreateSecretInput(t *testing.T) {
	tests := []struct {
		name string

		secret *pb.Secret

		wantType models.SecretType
		check    func(t *testing.T, input service.CreateSecretInput)
		wantErr  bool
	}{
		{
			name: "text",
			secret: pb.Secret_builder{
				Text: pb.TextSecret_builder{
					Text: "hello",
				}.Build(),
			}.Build(),
			wantType: models.SecretText,
			check: func(
				t *testing.T,
				input service.CreateSecretInput,
			) {
				value, ok := input.Data.(*models.TextSecret)
				if !ok {
					t.Fatalf(
						"expected *models.TextSecret, got %T",
						input.Data,
					)
				}

				if value.Text != "hello" {
					t.Errorf(
						"Text = %q, want %q",
						value.Text,
						"hello",
					)
				}
			},
		},
		{
			name: "login password",
			secret: pb.Secret_builder{
				LoginPassword: pb.LoginPasswordSecret_builder{
					Login:    "user",
					Password: "password",
				}.Build(),
			}.Build(),
			wantType: models.SecretLogin,
			check: func(
				t *testing.T,
				input service.CreateSecretInput,
			) {
				value, ok := input.Data.(*models.LoginPasswordSecret)
				if !ok {
					t.Fatalf(
						"expected *models.LoginPasswordSecret, got %T",
						input.Data,
					)
				}

				if value.Login != "user" {
					t.Errorf(
						"Login = %q, want %q",
						value.Login,
						"user",
					)
				}

				if value.Password != "password" {
					t.Errorf(
						"Password = %q, want %q",
						value.Password,
						"password",
					)
				}
			},
		},
		{
			name: "bank card",
			secret: pb.Secret_builder{
				BankCard: pb.BankCardSecret_builder{
					Number: "1234",
					Holder: "John Doe",
					Expire: "12/30",
					Cvv:    "123",
				}.Build(),
			}.Build(),
			wantType: models.SecretCard,
			check: func(
				t *testing.T,
				input service.CreateSecretInput,
			) {
				value, ok := input.Data.(*models.CardSecret)
				if !ok {
					t.Fatalf(
						"expected *models.CardSecret, got %T",
						input.Data,
					)
				}

				if value.Number != "1234" {
					t.Errorf(
						"Number = %q, want %q",
						value.Number,
						"1234",
					)
				}

				if value.Holder != "John Doe" {
					t.Errorf(
						"Holder = %q, want %q",
						value.Holder,
						"John Doe",
					)
				}

				if value.Expire != "12/30" {
					t.Errorf(
						"Expire = %q, want %q",
						value.Expire,
						"12/30",
					)
				}

				if value.CVV != "123" {
					t.Errorf(
						"CVV = %q, want %q",
						value.CVV,
						"123",
					)
				}
			},
		},
		{
			name: "binary",
			secret: pb.Secret_builder{
				Binary: pb.BinarySecret_builder{
					Filename: "file.pdf",
					MimeType: "application/pdf",
				}.Build(),
			}.Build(),
			wantType: models.SecretBinary,
			check: func(
				t *testing.T,
				input service.CreateSecretInput,
			) {
				value, ok := input.Data.(*models.BinarySecret)
				if !ok {
					t.Fatalf(
						"expected *models.BinarySecret, got %T",
						input.Data,
					)
				}

				if value.Filename != "file.pdf" {
					t.Errorf(
						"Filename = %q, want %q",
						value.Filename,
						"file.pdf",
					)
				}

				if value.MIMEType != "application/pdf" {
					t.Errorf(
						"MIMEType = %q, want %q",
						value.MIMEType,
						"application/pdf",
					)
				}

				var metadata models.BinarySecret

				if err := json.Unmarshal(
					input.Metadata,
					&metadata,
				); err != nil {
					t.Fatalf(
						"invalid binary metadata: %v",
						err,
					)
				}

				if metadata.Filename != "file.pdf" {
					t.Errorf(
						"metadata filename = %q, want %q",
						metadata.Filename,
						"file.pdf",
					)
				}
			},
		},
		{
			name:    "payload missing",
			secret:  &pb.Secret{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := protoToCreateSecretInput(tt.secret)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if status.Code(err) != codes.InvalidArgument {
					t.Errorf(
						"code = %v, want %v",
						status.Code(err),
						codes.InvalidArgument,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if input.Type != tt.wantType {
				t.Errorf(
					"Type = %v, want %v",
					input.Type,
					tt.wantType,
				)
			}

			if tt.check != nil {
				tt.check(t, input)
			}
		})
	}
}

func TestProtoToUpdateSecretInput(t *testing.T) {
	secretID := uuid.New()

	tests := []struct {
		name string

		secret *pb.Secret

		wantType models.SecretType
		check    func(t *testing.T, input service.UpdateSecretInput)
		wantErr  bool
	}{
		{
			name: "text",
			secret: pb.Secret_builder{
				Text: pb.TextSecret_builder{
					Text: "updated",
				}.Build(),
			}.Build(),
			wantType: models.SecretText,
			check: func(
				t *testing.T,
				input service.UpdateSecretInput,
			) {
				value := input.Data.(*models.TextSecret)

				if value.Text != "updated" {
					t.Errorf(
						"Text = %q, want %q",
						value.Text,
						"updated",
					)
				}
			},
		},
		{
			name: "login password",
			secret: pb.Secret_builder{
				LoginPassword: pb.LoginPasswordSecret_builder{
					Login:    "new-user",
					Password: "new-password",
				}.Build(),
			}.Build(),
			wantType: models.SecretLogin,
			check: func(
				t *testing.T,
				input service.UpdateSecretInput,
			) {
				value := input.Data.(*models.LoginPasswordSecret)

				if value.Login != "new-user" {
					t.Errorf(
						"Login = %q, want %q",
						value.Login,
						"new-user",
					)
				}
			},
		},
		{
			name: "bank card",
			secret: pb.Secret_builder{
				BankCard: pb.BankCardSecret_builder{
					Number: "1111",
					Holder: "Jane Doe",
					Expire: "01/31",
					Cvv:    "999",
				}.Build(),
			}.Build(),
			wantType: models.SecretCard,
		},
		{
			name: "binary",
			secret: pb.Secret_builder{
				Binary: pb.BinarySecret_builder{
					Filename: "new.pdf",
					MimeType: "application/pdf",
				}.Build(),
			}.Build(),
			wantType: models.SecretBinary,
			check: func(
				t *testing.T,
				input service.UpdateSecretInput,
			) {
				value := input.Data.(*models.BinarySecret)

				if value.Filename != "new.pdf" {
					t.Errorf(
						"Filename = %q, want %q",
						value.Filename,
						"new.pdf",
					)
				}
			},
		},
		{
			name:    "payload missing",
			secret:  &pb.Secret{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := protoToUpdateSecretInput(
				secretID,
				tt.secret,
			)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if status.Code(err) != codes.InvalidArgument {
					t.Errorf(
						"code = %v, want %v",
						status.Code(err),
						codes.InvalidArgument,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if input.ID != secretID {
				t.Errorf(
					"ID = %v, want %v",
					input.ID,
					secretID,
				)
			}

			if input.Type != tt.wantType {
				t.Errorf(
					"Type = %v, want %v",
					input.Type,
					tt.wantType,
				)
			}

			if tt.check != nil {
				tt.check(t, input)
			}
		})
	}
}

func TestDomainToProtoSecret(t *testing.T) {
	secretID := uuid.New()

	secret := &models.Secret{
		ID:        secretID,
		Type:      models.SecretText,
		CreatedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
	}

	tests := []struct {
		name string
		data any

		check   func(t *testing.T, result *pb.Secret)
		wantErr bool
	}{
		{
			name: "text",
			data: &models.TextSecret{
				Text: "hello",
			},
			check: func(t *testing.T, result *pb.Secret) {
				value := result.GetText()

				if value.GetText() != "hello" {
					t.Errorf(
						"Text = %q, want %q",
						value.GetText(),
						"hello",
					)
				}
			},
		},
		{
			name: "login",
			data: &models.LoginPasswordSecret{
				Login:    "user",
				Password: "password",
			},
			check: func(t *testing.T, result *pb.Secret) {
				value := result.GetLoginPassword()

				if value.GetLogin() != "user" {
					t.Errorf(
						"Login = %q, want %q",
						value.GetLogin(),
						"user",
					)
				}

				if value.GetPassword() != "password" {
					t.Errorf(
						"Password = %q, want %q",
						value.GetPassword(),
						"password",
					)
				}
			},
		},
		{
			name: "card",
			data: &models.CardSecret{
				Number: "1234",
				Holder: "John Doe",
				Expire: "12/30",
				CVV:    "123",
			},
			check: func(t *testing.T, result *pb.Secret) {
				value := result.GetBankCard()

				if value.GetNumber() != "1234" {
					t.Errorf(
						"Number = %q, want %q",
						value.GetNumber(),
						"1234",
					)
				}

				if value.GetHolder() != "John Doe" {
					t.Errorf(
						"Holder = %q, want %q",
						value.GetHolder(),
						"John Doe",
					)
				}

				if value.GetExpire() != "12/30" {
					t.Errorf(
						"Expire = %q, want %q",
						value.GetExpire(),
						"12/30",
					)
				}

				if value.GetCvv() != "123" {
					t.Errorf(
						"CVV = %q, want %q",
						value.GetCvv(),
						"123",
					)
				}
			},
		},
		{
			name: "binary metadata",
			data: &models.BinarySecret{
				Filename: "file.pdf",
				MIMEType: "application/pdf",
			},
			check: func(t *testing.T, result *pb.Secret) {
				value := result.GetBinary()

				if value.GetFilename() != "file.pdf" {
					t.Errorf(
						"Filename = %q, want %q",
						value.GetFilename(),
						"file.pdf",
					)
				}

				if value.GetMimeType() != "application/pdf" {
					t.Errorf(
						"MimeType = %q, want %q",
						value.GetMimeType(),
						"application/pdf",
					)
				}
			},
		},
		{
			name:    "binary data",
			data:    []byte("binary data"),
			wantErr: true,
		},
		{
			name:    "unsupported data",
			data:    "unsupported",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := domainToProtoSecret(
				secret,
				tt.data,
			)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if status.Code(err) != codes.Internal {
					t.Errorf(
						"code = %v, want %v",
						status.Code(err),
						codes.Internal,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.GetMetadata().GetId() != secretID.String() {
				t.Errorf(
					"metadata ID = %q, want %q",
					result.GetMetadata().GetId(),
					secretID.String(),
				)
			}

			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestDomainMetadataToProto(t *testing.T) {
	id := uuid.New()

	createdAt := time.Now().UTC().Truncate(time.Second)
	updatedAt := createdAt.Add(time.Hour)

	secret := &models.Secret{
		ID:        id,
		Type:      models.SecretCard,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}

	result := domainMetadataToProto(secret)

	if result.GetId() != id.String() {
		t.Errorf(
			"Id = %q, want %q",
			result.GetId(),
			id.String(),
		)
	}

	if result.GetType() != pb.SecretType_SECRET_TYPE_BANK_CARD {
		t.Errorf(
			"Type = %v, want %v",
			result.GetType(),
			pb.SecretType_SECRET_TYPE_BANK_CARD,
		)
	}

	if !result.GetCreatedAt().AsTime().Equal(createdAt) {
		t.Errorf(
			"CreatedAt = %v, want %v",
			result.GetCreatedAt().AsTime(),
			createdAt,
		)
	}

	if !result.GetUpdatedAt().AsTime().Equal(updatedAt) {
		t.Errorf(
			"UpdatedAt = %v, want %v",
			result.GetUpdatedAt().AsTime(),
			updatedAt,
		)
	}
}

func TestSecretTypeToProto(t *testing.T) {
	tests := []struct {
		name string
		in   models.SecretType
		want pb.SecretType
	}{
		{
			name: "text",
			in:   models.SecretText,
			want: pb.SecretType_SECRET_TYPE_TEXT,
		},
		{
			name: "login",
			in:   models.SecretLogin,
			want: pb.SecretType_SECRET_TYPE_LOGIN_PASSWORD,
		},
		{
			name: "card",
			in:   models.SecretCard,
			want: pb.SecretType_SECRET_TYPE_BANK_CARD,
		},
		{
			name: "binary",
			in:   models.SecretBinary,
			want: pb.SecretType_SECRET_TYPE_BINARY_FILE,
		},
		{
			name: "unknown",
			in:   models.SecretType("unknown"),
			want: pb.SecretType_SECRET_TYPE_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secretTypeToProto(tt.in)

			if got != tt.want {
				t.Errorf(
					"got %v, want %v",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestMapSecretError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantCode    codes.Code
		wantMessage string
	}{
		{
			name:        "secret not found",
			err:         repository.ErrSecretNotFound,
			wantCode:    codes.NotFound,
			wantMessage: "secret not found",
		},
		{
			name:        "invalid secret",
			err:         service.ErrInvalidSecret,
			wantCode:    codes.InvalidArgument,
			wantMessage: "invalid secret",
		},
		{
			name:        "invalid secret type",
			err:         service.ErrInvalidSecretType,
			wantCode:    codes.InvalidArgument,
			wantMessage: "invalid secret",
		},
		{
			name:        "unknown error",
			err:         errors.New("database error"),
			wantCode:    codes.Internal,
			wantMessage: "internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapSecretError(tt.err)

			if status.Code(err) != tt.wantCode {
				t.Errorf(
					"code = %v, want %v",
					status.Code(err),
					tt.wantCode,
				)
			}

			if status.Convert(err).Message() != tt.wantMessage {
				t.Errorf(
					"message = %q, want %q",
					status.Convert(err).Message(),
					tt.wantMessage,
				)
			}
		})
	}
}

func TestSecretServer_CreateSecret(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	repo := &mockSecretRepo{
		createFunc: func(
			ctx context.Context,
			secret *models.Secret,
		) (*models.Secret, error) {
			secret.ID = secretID

			return secret, nil
		},
	}

	server := newTestSecretServer(repo)

	req := pb.CreateSecretRequest_builder{
		Secret: pb.Secret_builder{
			Text: pb.TextSecret_builder{
				Text: "hello",
			}.Build(),
		}.Build(),
	}.Build()

	result, err := server.CreateSecret(
		contextWithUserID(ownerID),
		req,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected response, got nil")
	}

	if result.GetId() != secretID.String() {
		t.Errorf(
			"ID = %q, want %q",
			result.GetId(),
			secretID.String(),
		)
	}
}

func TestSecretServer_CreateSecret_NilSecret(t *testing.T) {
	server := newTestSecretServer(&mockSecretRepo{})

	result, err := server.CreateSecret(
		contextWithUserID(uuid.New()),
		&pb.CreateSecretRequest{},
	)

	if result != nil {
		t.Errorf(
			"expected nil response, got %+v",
			result,
		)
	}

	if status.Code(err) != codes.InvalidArgument {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.InvalidArgument,
		)
	}
}

func TestSecretServer_CreateSecret_Unauthenticated(t *testing.T) {
	server := newTestSecretServer(&mockSecretRepo{})

	result, err := server.CreateSecret(
		context.Background(),
		&pb.CreateSecretRequest{},
	)

	if result != nil {
		t.Errorf(
			"expected nil response, got %+v",
			result,
		)
	}

	if status.Code(err) != codes.Unauthenticated {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.Unauthenticated,
		)
	}
}

func TestSecretServer_CreateSecret_ServiceError(t *testing.T) {
	repo := &mockSecretRepo{
		createFunc: func(
			ctx context.Context,
			secret *models.Secret,
		) (*models.Secret, error) {
			return nil, repository.ErrSecretNotFound
		},
	}

	server := newTestSecretServer(repo)

	req := pb.CreateSecretRequest_builder{
		Secret: pb.Secret_builder{
			Text: pb.TextSecret_builder{
				Text: "hello",
			}.Build(),
		}.Build(),
	}.Build()

	_, err := server.CreateSecret(
		contextWithUserID(uuid.New()),
		req,
	)

	if status.Code(err) != codes.NotFound {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.NotFound,
		)
	}
}

func TestSecretServer_GetSecret(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	repo := &mockSecretRepo{
		getByIDFunc: func(
			ctx context.Context,
			gotOwnerID, gotSecretID uuid.UUID,
		) (*models.Secret, error) {
			return &models.Secret{
				ID:            gotSecretID,
				OwnerID:       gotOwnerID,
				Type:          models.SecretText,
				EncryptedData: []byte(`{"text":"hello"}`),
			}, nil
		},
	}

	server := newTestSecretServer(repo)

	result, err := server.GetSecret(
		contextWithUserID(ownerID),
		pb.GetSecretRequest_builder{
			Id: secretID.String(),
		}.Build(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil || !result.HasSecret() {
		t.Fatal("expected secret in response")
	}

	text := result.GetSecret().GetText()

	if text.GetText() != "hello" {
		t.Errorf(
			"Text = %q, want %q",
			text.GetText(),
			"hello",
		)
	}
}

func TestSecretServer_GetSecret_InvalidID(t *testing.T) {
	server := newTestSecretServer(&mockSecretRepo{})

	result, err := server.GetSecret(
		contextWithUserID(uuid.New()),
		pb.GetSecretRequest_builder{
			Id: "invalid",
		}.Build(),
	)

	if result != nil {
		t.Errorf(
			"expected nil response, got %+v",
			result,
		)
	}

	if status.Code(err) != codes.InvalidArgument {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.InvalidArgument,
		)
	}
}

func TestSecretServer_ListSecrets(t *testing.T) {
	ownerID := uuid.New()

	secret1 := &models.Secret{
		ID:        uuid.New(),
		OwnerID:   ownerID,
		Type:      models.SecretText,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	secret2 := &models.Secret{
		ID:        uuid.New(),
		OwnerID:   ownerID,
		Type:      models.SecretBinary,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	repo := &mockSecretRepo{
		listFunc: func(
			ctx context.Context,
			gotOwnerID uuid.UUID,
		) ([]*models.Secret, error) {
			return []*models.Secret{
				secret1,
				secret2,
			}, nil
		},
	}

	server := newTestSecretServer(repo)

	result, err := server.ListSecrets(
		contextWithUserID(ownerID),
		&pb.ListSecretsRequest{},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.GetSecrets()) != 2 {
		t.Fatalf(
			"got %d secrets, want 2",
			len(result.GetSecrets()),
		)
	}

	if result.GetSecrets()[0].GetId() != secret1.ID.String() {
		t.Errorf(
			"first ID = %q, want %q",
			result.GetSecrets()[0].GetId(),
			secret1.ID.String(),
		)
	}

	if result.GetSecrets()[1].GetType() !=
		pb.SecretType_SECRET_TYPE_BINARY_FILE {
		t.Errorf(
			"second type = %v, want binary",
			result.GetSecrets()[1].GetType(),
		)
	}
}

func TestSecretServer_ListSecrets_Error(t *testing.T) {
	repo := &mockSecretRepo{
		listFunc: func(
			ctx context.Context,
			ownerID uuid.UUID,
		) ([]*models.Secret, error) {
			return nil, errors.New("database error")
		},
	}

	server := newTestSecretServer(repo)

	result, err := server.ListSecrets(
		contextWithUserID(uuid.New()),
		&pb.ListSecretsRequest{},
	)

	if result != nil {
		t.Errorf(
			"expected nil response, got %+v",
			result,
		)
	}

	if status.Code(err) != codes.Internal {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.Internal,
		)
	}
}

func TestSecretServer_DeleteSecret(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	var deletedOwnerID uuid.UUID
	var deletedSecretID uuid.UUID

	repo := &mockSecretRepo{
		deleteFunc: func(
			ctx context.Context,
			gotOwnerID, gotSecretID uuid.UUID,
		) error {
			deletedOwnerID = gotOwnerID
			deletedSecretID = gotSecretID
			return nil
		},
	}

	server := newTestSecretServer(repo)

	result, err := server.DeleteSecret(
		contextWithUserID(ownerID),
		pb.DeleteSecretRequest_builder{
			Id: secretID.String(),
		}.Build(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected response, got nil")
	}

	if deletedOwnerID != ownerID {
		t.Errorf(
			"ownerID = %v, want %v",
			deletedOwnerID,
			ownerID,
		)
	}

	if deletedSecretID != secretID {
		t.Errorf(
			"secretID = %v, want %v",
			deletedSecretID,
			secretID,
		)
	}
}

func TestSecretServer_DeleteSecret_InvalidID(t *testing.T) {
	server := newTestSecretServer(&mockSecretRepo{})

	result, err := server.DeleteSecret(
		contextWithUserID(uuid.New()),
		pb.DeleteSecretRequest_builder{
			Id: "invalid",
		}.Build(),
	)

	if result != nil {
		t.Errorf(
			"expected nil response, got %+v",
			result,
		)
	}

	if status.Code(err) != codes.InvalidArgument {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.InvalidArgument,
		)
	}
}

func TestSecretServer_DeleteSecret_Error(t *testing.T) {
	repo := &mockSecretRepo{
		deleteFunc: func(
			ctx context.Context,
			ownerID, secretID uuid.UUID,
		) error {
			return repository.ErrSecretNotFound
		},
	}

	server := newTestSecretServer(repo)

	_, err := server.DeleteSecret(
		contextWithUserID(uuid.New()),
		pb.DeleteSecretRequest_builder{
			Id: uuid.New().String(),
		}.Build(),
	)

	if status.Code(err) != codes.NotFound {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.NotFound,
		)
	}
}

func TestSecretServer_UpdateSecret(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	repo := &mockSecretRepo{
		updateFunc: func(
			ctx context.Context,
			secret *models.Secret,
		) (*models.Secret, error) {
			return secret, nil
		},
	}

	server := newTestSecretServer(repo)

	req := pb.UpdateSecretRequest_builder{
		Secret: pb.Secret_builder{
			Metadata: pb.SecretMetadata_builder{
				Id: secretID.String(),
			}.Build(),
			Text: pb.TextSecret_builder{
				Text: "updated text",
			}.Build(),
		}.Build(),
	}.Build()

	result, err := server.UpdateSecret(
		contextWithUserID(ownerID),
		req,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected response, got nil")
	}
}

func TestSecretServer_UpdateSecret_NilSecret(t *testing.T) {
	server := newTestSecretServer(&mockSecretRepo{})

	_, err := server.UpdateSecret(
		contextWithUserID(uuid.New()),
		&pb.UpdateSecretRequest{},
	)

	if status.Code(err) != codes.InvalidArgument {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.InvalidArgument,
		)
	}
}

func TestSecretServer_UpdateSecret_MissingMetadata(t *testing.T) {
	server := newTestSecretServer(&mockSecretRepo{})

	_, err := server.UpdateSecret(
		contextWithUserID(uuid.New()),
		pb.UpdateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Text: pb.TextSecret_builder{
					Text: "text",
				}.Build(),
			}.Build(),
		}.Build(),
	)

	if status.Code(err) != codes.InvalidArgument {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.InvalidArgument,
		)
	}

	if status.Convert(err).Message() !=
		"secret metadata is required" {
		t.Errorf(
			"message = %q, want %q",
			status.Convert(err).Message(),
			"secret metadata is required",
		)
	}
}

func TestSecretServer_UpdateSecret_InvalidID(t *testing.T) {
	server := newTestSecretServer(&mockSecretRepo{})

	_, err := server.UpdateSecret(
		contextWithUserID(uuid.New()),
		pb.UpdateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Metadata: pb.SecretMetadata_builder{
					Id: "invalid",
				}.Build(),
				Text: pb.TextSecret_builder{
					Text: "text",
				}.Build(),
			}.Build(),
		}.Build(),
	)

	if status.Code(err) != codes.InvalidArgument {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.InvalidArgument,
		)
	}
}

func TestSecretServer_UpdateSecret_ServiceError(t *testing.T) {
	repo := &mockSecretRepo{
		updateFunc: func(
			ctx context.Context,
			secret *models.Secret,
		) (*models.Secret, error) {
			return nil, repository.ErrSecretNotFound
		},
	}

	server := newTestSecretServer(repo)

	_, err := server.UpdateSecret(
		contextWithUserID(uuid.New()),
		pb.UpdateSecretRequest_builder{
			Secret: pb.Secret_builder{
				Metadata: pb.SecretMetadata_builder{
					Id: uuid.New().String(),
				}.Build(),
				Text: pb.TextSecret_builder{
					Text: "text",
				}.Build(),
			}.Build(),
		}.Build(),
	)

	if status.Code(err) != codes.NotFound {
		t.Errorf(
			"code = %v, want %v",
			status.Code(err),
			codes.NotFound,
		)
	}
}
