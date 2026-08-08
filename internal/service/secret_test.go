package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/onbehalfofhim/secrets-keeper/internal/crypto"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/serializer"
)

func newTestSecretService(
	repo repository.SecretRepo,
	encryptor crypto.Encryptor,
	serializer serializer.Serializer,
) *SecretService {
	return NewSecretService(repo, encryptor, serializer)
}

func TestNewSecretService(t *testing.T) {
	repo := &mockSecretRepository{}
	encryptor := &mockEncryptor{}
	serializer := &mockSerializer{}

	service := NewSecretService(repo, encryptor, serializer)

	if service == nil {
		t.Fatal("expected service, got nil")
	}

	if service.repository != repo {
		t.Error("service contains unexpected repository")
	}

	if service.encryptor != encryptor {
		t.Error("service contains unexpected encryptor")
	}

	if service.serializer != serializer {
		t.Error("service contains unexpected serializer")
	}
}

func TestSecretService_Create(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	encryptedData := []byte("encrypted-data")
	serializedData := []byte(`{"text":"secret"}`)
	metadata := json.RawMessage(`{"name":"test"}`)

	serializeErr := errors.New("serialize failed")
	encryptErr := errors.New("encrypt failed")
	repositoryErr := errors.New("repository failed")

	tests := []struct {
		name string

		ownerID uuid.UUID
		input   CreateSecretInput

		serializeFunc func(any) ([]byte, error)
		encryptFunc   func([]byte) ([]byte, error)
		createFunc    func(context.Context, *models.Secret) (*models.Secret, error)

		wantErr error
	}{
		{
			name:    "empty owner ID",
			ownerID: uuid.Nil,
			input: CreateSecretInput{
				Type: models.SecretText,
				Data: "secret",
			},
			wantErr: ErrInvalidSecret,
		},
		{
			name:    "empty secret type",
			ownerID: ownerID,
			input: CreateSecretInput{
				Type: "",
				Data: "secret",
			},
			wantErr: ErrInvalidSecretType,
		},
		{
			name:    "unsupported secret type",
			ownerID: ownerID,
			input: CreateSecretInput{
				Type: models.SecretType("unsupported"),
				Data: "secret",
			},
			wantErr: ErrInvalidSecretType,
		},
		{
			name:    "serialize error",
			ownerID: ownerID,
			input: CreateSecretInput{
				Type: models.SecretText,
				Data: "secret",
			},
			serializeFunc: func(data any) ([]byte, error) {
				return nil, serializeErr
			},
			wantErr: serializeErr,
		},
		{
			name:    "encrypt error",
			ownerID: ownerID,
			input: CreateSecretInput{
				Type: models.SecretText,
				Data: "secret",
			},
			serializeFunc: func(data any) ([]byte, error) {
				return serializedData, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return nil, encryptErr
			},
			wantErr: encryptErr,
		},
		{
			name:    "repository error",
			ownerID: ownerID,
			input: CreateSecretInput{
				Type:     models.SecretText,
				Data:     "secret",
				Metadata: metadata,
			},
			serializeFunc: func(data any) ([]byte, error) {
				return serializedData, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return encryptedData, nil
			},
			createFunc: func(
				ctx context.Context,
				secret *models.Secret,
			) (*models.Secret, error) {
				return nil, repositoryErr
			},
			wantErr: repositoryErr,
		},
		{
			name:    "binary secret",
			ownerID: ownerID,
			input: CreateSecretInput{
				Type:     models.SecretBinary,
				Metadata: metadata,
			},
			createFunc: func(
				ctx context.Context,
				secret *models.Secret,
			) (*models.Secret, error) {
				return secret, nil
			},
		},
		{
			name:    "success text secret",
			ownerID: ownerID,
			input: CreateSecretInput{
				Type:     models.SecretText,
				Data:     "secret",
				Metadata: metadata,
			},
			serializeFunc: func(data any) ([]byte, error) {
				return serializedData, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return encryptedData, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockSecretRepository{
				createFunc: tt.createFunc,
			}

			encryptor := &mockEncryptor{
				encryptFunc: tt.encryptFunc,
			}

			serializer := &mockSerializer{
				serializeFunc: tt.serializeFunc,
			}

			service := newTestSecretService(
				repo,
				encryptor,
				serializer,
			)

			got, err := service.Create(
				ctx,
				tt.ownerID,
				tt.input,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error %v, got %v",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf(
						"expected nil secret, got %+v",
						got,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got == nil {
				t.Fatal("expected secret, got nil")
			}

			if !repo.createCalled {
				t.Fatal("expected repository Create to be called")
			}

			created := repo.createdSecret

			if created == nil {
				t.Fatal("expected created secret, got nil")
			}

			if created.ID == uuid.Nil {
				t.Error("expected generated secret ID")
			}

			if created.OwnerID != tt.ownerID {
				t.Errorf(
					"OwnerID = %v, want %v",
					created.OwnerID,
					tt.ownerID,
				)
			}

			if created.Type != tt.input.Type {
				t.Errorf(
					"Type = %q, want %q",
					created.Type,
					tt.input.Type,
				)
			}

			if tt.input.Metadata == nil {
				if string(created.Metadata) != `{}` {
					t.Errorf(
						"Metadata = %q, want %q",
						created.Metadata,
						`{}`,
					)
				}
			} else if string(created.Metadata) != string(tt.input.Metadata) {
				t.Errorf(
					"Metadata = %q, want %q",
					created.Metadata,
					tt.input.Metadata,
				)
			}

			if tt.input.Type == models.SecretBinary {
				if serializer.serializeCalled {
					t.Error(
						"Serialize should not be called for binary secret",
					)
				}

				if encryptor.encryptCalled {
					t.Error(
						"Encrypt should not be called for binary secret",
					)
				}

				if created.EncryptedData != nil {
					t.Errorf(
						"EncryptedData = %v, want nil",
						created.EncryptedData,
					)
				}

				return
			}

			if !serializer.serializeCalled {
				t.Fatal("expected Serialize to be called")
			}

			if serializer.serializeInput != tt.input.Data {
				t.Errorf(
					"Serialize input = %v, want %v",
					serializer.serializeInput,
					tt.input.Data,
				)
			}

			if !encryptor.encryptCalled {
				t.Fatal("expected Encrypt to be called")
			}

			if string(encryptor.encryptInput) != string(serializedData) {
				t.Errorf(
					"Encrypt input = %q, want %q",
					encryptor.encryptInput,
					serializedData,
				)
			}

			if string(created.EncryptedData) != string(encryptedData) {
				t.Errorf(
					"EncryptedData = %q, want %q",
					created.EncryptedData,
					encryptedData,
				)
			}
		})
	}
}

func TestSecretService_Get(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()

	secret := &models.Secret{
		ID:            secretID,
		OwnerID:       ownerID,
		Type:          models.SecretText,
		EncryptedData: []byte("encrypted"),
	}

	decryptedData := []byte(`{"text":"secret"}`)
	deserializedData := &models.TextSecret{}

	decryptErr := errors.New("decrypt failed")
	deserializeErr := errors.New("deserialize failed")

	tests := []struct {
		name string

		secret *models.Secret

		getByIDFunc     func(context.Context, uuid.UUID, uuid.UUID) (*models.Secret, error)
		decryptFunc     func([]byte) ([]byte, error)
		deserializeFunc func(models.SecretType, []byte) (any, error)

		want    any
		wantErr error
	}{
		{
			name: "repository error",
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return nil, repository.ErrSecretNotFound
			},
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:   "decrypt error",
			secret: secret,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return secret, nil
			},
			decryptFunc: func(data []byte) ([]byte, error) {
				return nil, decryptErr
			},
			wantErr: decryptErr,
		},
		{
			name:   "deserialize error",
			secret: secret,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return secret, nil
			},
			decryptFunc: func(data []byte) ([]byte, error) {
				return decryptedData, nil
			},
			deserializeFunc: func(
				secretType models.SecretType,
				data []byte,
			) (any, error) {
				return nil, deserializeErr
			},
			wantErr: deserializeErr,
		},
		{
			name:   "success structured secret",
			secret: secret,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return secret, nil
			},
			decryptFunc: func(data []byte) ([]byte, error) {
				return decryptedData, nil
			},
			deserializeFunc: func(
				secretType models.SecretType,
				data []byte,
			) (any, error) {
				return deserializedData, nil
			},
			want: deserializedData,
		},
		{
			name: "binary secret",
			secret: &models.Secret{
				ID:      secretID,
				OwnerID: ownerID,
				Type:    models.SecretBinary,
				Metadata: json.RawMessage(`{
					"filename": "document.pdf",
					"mime_type": "application/pdf"
				}`),
			},
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:      secretID,
					OwnerID: ownerID,
					Type:    models.SecretBinary,
					Metadata: json.RawMessage(`{
						"filename": "document.pdf",
						"mime_type": "application/pdf"
					}`),
				}, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockSecretRepository{
				getByIDFunc: tt.getByIDFunc,
			}

			encryptor := &mockEncryptor{
				decryptFunc: tt.decryptFunc,
			}

			serializer := &mockSerializer{
				deserializeFunc: tt.deserializeFunc,
			}

			service := newTestSecretService(
				repo,
				encryptor,
				serializer,
			)

			gotSecret, gotData, err := service.Get(
				ctx,
				ownerID,
				secretID,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error %v, got %v",
						tt.wantErr,
						err,
					)
				}

				if gotSecret != nil || gotData != nil {
					t.Error(
						"expected nil secret and data on error",
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotSecret == nil {
				t.Fatal("expected secret, got nil")
			}

			if tt.secret != nil && gotSecret.ID != tt.secret.ID {
				t.Errorf(
					"ID = %v, want %v",
					gotSecret.ID,
					tt.secret.ID,
				)
			}

			if tt.want != nil {
				if gotData != tt.want {
					t.Errorf(
						"data = %v, want %v",
						gotData,
						tt.want,
					)
				}
			}

			if tt.secret != nil &&
				tt.secret.Type == models.SecretBinary {

				if encryptor.decryptCalled {
					t.Error(
						"Decrypt should not be called for binary secret",
					)
				}

				if serializer.deserializeCalled {
					t.Error(
						"Deserialize should not be called for binary secret",
					)
				}

				if gotData == nil {
					t.Fatal("expected binary metadata, got nil")
				}

				if _, ok := gotData.(*models.BinarySecret); !ok {
					t.Fatalf(
						"expected *models.BinarySecret, got %T",
						gotData,
					)
				}

				return
			}

			if !encryptor.decryptCalled {
				t.Error("expected Decrypt to be called")
			}

			if string(encryptor.decryptInput) != string(secret.EncryptedData) {
				t.Errorf(
					"Decrypt input = %q, want %q",
					encryptor.decryptInput,
					secret.EncryptedData,
				)
			}

			if !serializer.deserializeCalled {
				t.Error("expected Deserialize to be called")
			}

			if serializer.deserializeType != secret.Type {
				t.Errorf(
					"Deserialize type = %q, want %q",
					serializer.deserializeType,
					secret.Type,
				)
			}

			if string(serializer.deserializeInput) != string(decryptedData) {
				t.Errorf(
					"Deserialize input = %q, want %q",
					serializer.deserializeInput,
					decryptedData,
				)
			}
		})
	}
}

func TestSecretService_Get_BinaryInvalidMetadata(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	repo := &mockSecretRepository{
		getByIDFunc: func(
			ctx context.Context,
			ownerID, secretID uuid.UUID,
		) (*models.Secret, error) {
			return &models.Secret{
				ID:       secretID,
				OwnerID:  ownerID,
				Type:     models.SecretBinary,
				Metadata: []byte(`invalid json`),
			}, nil
		},
	}

	encryptor := &mockEncryptor{}
	serializer := &mockSerializer{}

	service := newTestSecretService(
		repo,
		encryptor,
		serializer,
	)

	secret, data, err := service.Get(
		context.Background(),
		ownerID,
		secretID,
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if secret != nil || data != nil {
		t.Error("expected nil secret and data")
	}

	if encryptor.decryptCalled {
		t.Error("Decrypt should not be called")
	}

	if serializer.deserializeCalled {
		t.Error("Deserialize should not be called")
	}
}

func TestSecretService_List(t *testing.T) {
	ownerID := uuid.New()

	expected := []*models.Secret{
		{
			ID:      uuid.New(),
			OwnerID: ownerID,
			Type:    models.SecretText,
		},
		{
			ID:      uuid.New(),
			OwnerID: ownerID,
			Type:    models.SecretCard,
		},
	}

	listErr := errors.New("list failed")

	tests := []struct {
		name     string
		listFunc func(context.Context, uuid.UUID) ([]*models.Secret, error)
		wantErr  error
	}{
		{
			name: "success",
			listFunc: func(
				ctx context.Context,
				ownerID uuid.UUID,
			) ([]*models.Secret, error) {
				return expected, nil
			},
		},
		{
			name: "repository error",
			listFunc: func(
				ctx context.Context,
				ownerID uuid.UUID,
			) ([]*models.Secret, error) {
				return nil, listErr
			},
			wantErr: listErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockSecretRepository{
				listFunc: tt.listFunc,
			}

			service := newTestSecretService(
				repo,
				&mockEncryptor{},
				&mockSerializer{},
			)

			got, err := service.List(
				context.Background(),
				ownerID,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error %v, got %v",
						tt.wantErr,
						err,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != len(expected) {
				t.Fatalf(
					"got %d secrets, want %d",
					len(got),
					len(expected),
				)
			}

			for i := range expected {
				if got[i] != expected[i] {
					t.Errorf(
						"secret %d = %v, want %v",
						i,
						got[i],
						expected[i],
					)
				}
			}

			if !repo.listCalled {
				t.Fatal("expected List to be called")
			}

			if repo.listOwnerID != ownerID {
				t.Errorf(
					"List ownerID = %v, want %v",
					repo.listOwnerID,
					ownerID,
				)
			}
		})
	}
}

func TestSecretService_Update(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()

	serializedData := []byte(`{"text":"secret"}`)
	encryptedData := []byte("encrypted")

	serializeErr := errors.New("serialize failed")
	encryptErr := errors.New("encrypt failed")
	repositoryErr := errors.New("repository update failed")

	tests := []struct {
		name string

		ownerID uuid.UUID
		input   UpdateSecretInput

		serializeFunc func(any) ([]byte, error)
		encryptFunc   func([]byte) ([]byte, error)
		updateFunc    func(context.Context, *models.Secret) (*models.Secret, error)

		wantErr error
	}{
		{
			name:    "empty owner ID",
			ownerID: uuid.Nil,
			input: UpdateSecretInput{
				ID:   secretID,
				Type: models.SecretText,
				Data: "secret",
			},
			wantErr: ErrInvalidSecret,
		},
		{
			name:    "empty secret ID",
			ownerID: ownerID,
			input: UpdateSecretInput{
				ID:   uuid.Nil,
				Type: models.SecretText,
				Data: "secret",
			},
			wantErr: ErrInvalidSecret,
		},
		{
			name:    "binary with invalid data type",
			ownerID: ownerID,
			input: UpdateSecretInput{
				ID:   secretID,
				Type: models.SecretBinary,
				Data: "not bytes",
			},
			wantErr: ErrInvalidSecret,
		},
		{
			name:    "serialize error",
			ownerID: ownerID,
			input: UpdateSecretInput{
				ID:   secretID,
				Type: models.SecretText,
				Data: "secret",
			},
			serializeFunc: func(data any) ([]byte, error) {
				return nil, serializeErr
			},
			wantErr: serializeErr,
		},
		{
			name:    "encrypt error",
			ownerID: ownerID,
			input: UpdateSecretInput{
				ID:   secretID,
				Type: models.SecretText,
				Data: "secret",
			},
			serializeFunc: func(data any) ([]byte, error) {
				return serializedData, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return nil, encryptErr
			},
			wantErr: encryptErr,
		},
		{
			name:    "repository error",
			ownerID: ownerID,
			input: UpdateSecretInput{
				ID:       secretID,
				Type:     models.SecretText,
				Data:     "secret",
				Metadata: json.RawMessage(`{}`),
			},
			serializeFunc: func(data any) ([]byte, error) {
				return serializedData, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return encryptedData, nil
			},
			updateFunc: func(
				ctx context.Context,
				secret *models.Secret,
			) (*models.Secret, error) {
				return nil, repositoryErr
			},
			wantErr: repositoryErr,
		},
		{
			name:    "success structured secret",
			ownerID: ownerID,
			input: UpdateSecretInput{
				ID:       secretID,
				Type:     models.SecretText,
				Data:     "secret",
				Metadata: json.RawMessage(`{"name":"test"}`),
			},
			serializeFunc: func(data any) ([]byte, error) {
				return serializedData, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return encryptedData, nil
			},
		},
		{
			name:    "success binary secret",
			ownerID: ownerID,
			input: UpdateSecretInput{
				ID:       secretID,
				Type:     models.SecretBinary,
				Data:     []byte("binary data"),
				Metadata: json.RawMessage(`{}`),
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return encryptedData, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockSecretRepository{
				updateFunc: tt.updateFunc,
			}

			encryptor := &mockEncryptor{
				encryptFunc: tt.encryptFunc,
			}

			serializer := &mockSerializer{
				serializeFunc: tt.serializeFunc,
			}

			service := newTestSecretService(
				repo,
				encryptor,
				serializer,
			)

			got, err := service.Update(
				ctx,
				tt.ownerID,
				tt.input,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error %v, got %v",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf(
						"expected nil secret, got %+v",
						got,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !repo.updateCalled {
				t.Fatal("expected repository Update to be called")
			}

			updated := repo.updatedSecret

			if updated == nil {
				t.Fatal("expected updated secret, got nil")
			}

			if updated.ID != tt.input.ID {
				t.Errorf(
					"ID = %v, want %v",
					updated.ID,
					tt.input.ID,
				)
			}

			if updated.OwnerID != tt.ownerID {
				t.Errorf(
					"OwnerID = %v, want %v",
					updated.OwnerID,
					tt.ownerID,
				)
			}

			if updated.Type != tt.input.Type {
				t.Errorf(
					"Type = %q, want %q",
					updated.Type,
					tt.input.Type,
				)
			}

			if string(updated.EncryptedData) != string(encryptedData) {
				t.Errorf(
					"EncryptedData = %q, want %q",
					updated.EncryptedData,
					encryptedData,
				)
			}

			if tt.input.Type == models.SecretBinary {
				if serializer.serializeCalled {
					t.Error(
						"Serialize should not be called for binary secret",
					)
				}

				if !encryptor.encryptCalled {
					t.Fatal("expected Encrypt to be called")
				}

				if string(encryptor.encryptInput) !=
					string(tt.input.Data.([]byte)) {
					t.Errorf(
						"Encrypt input = %q, want %q",
						encryptor.encryptInput,
						tt.input.Data,
					)
				}
			} else {
				if !serializer.serializeCalled {
					t.Fatal("expected Serialize to be called")
				}

				if serializer.serializeInput != tt.input.Data {
					t.Errorf(
						"Serialize input = %v, want %v",
						serializer.serializeInput,
						tt.input.Data,
					)
				}

				if !encryptor.encryptCalled {
					t.Fatal("expected Encrypt to be called")
				}

				if string(encryptor.encryptInput) !=
					string(serializedData) {
					t.Errorf(
						"Encrypt input = %q, want %q",
						encryptor.encryptInput,
						serializedData,
					)
				}
			}
		})
	}
}

func TestSecretService_Delete(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	deleteErr := errors.New("delete failed")

	tests := []struct {
		name       string
		deleteFunc func(context.Context, uuid.UUID, uuid.UUID) error
		wantErr    error
	}{
		{
			name: "success",
		},
		{
			name: "repository error",
			deleteFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) error {
				return deleteErr
			},
			wantErr: deleteErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockSecretRepository{
				deleteFunc: tt.deleteFunc,
			}

			service := newTestSecretService(
				repo,
				&mockEncryptor{},
				&mockSerializer{},
			)

			err := service.Delete(
				context.Background(),
				ownerID,
				secretID,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error %v, got %v",
						tt.wantErr,
						err,
					)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !repo.deleteCalled {
				t.Fatal("expected Delete to be called")
			}

			if repo.deleteOwnerID != ownerID {
				t.Errorf(
					"ownerID = %v, want %v",
					repo.deleteOwnerID,
					ownerID,
				)
			}

			if repo.deleteSecretID != secretID {
				t.Errorf(
					"secretID = %v, want %v",
					repo.deleteSecretID,
					secretID,
				)
			}
		})
	}
}
