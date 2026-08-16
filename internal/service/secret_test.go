package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service/mocks"
)

func TestNewSecretService(t *testing.T) {
	repo := mocks.NewMockSecretRepo(t)
	encryptor := mocks.NewMockEncryptor(t)
	serializer := mocks.NewMockSerializer(t)

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
		name    string
		ownerID uuid.UUID
		input   CreateSecretInput

		setupMock func(
			*mocks.MockSecretRepo,
			*mocks.MockEncryptor,
			*mocks.MockSerializer,
		)

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
				Type: models.SecretType(""),
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
			setupMock: func(
				_ *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(nil, serializeErr)
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
			setupMock: func(
				_ *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(serializedData, nil)

				e.EXPECT().
					Encrypt(serializedData).
					Return(nil, encryptErr)
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
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(serializedData, nil)

				e.EXPECT().
					Encrypt(serializedData).
					Return(encryptedData, nil)

				r.EXPECT().
					Create(
						mock.Anything,
						mock.AnythingOfType("*models.Secret"),
					).
					Return(nil, repositoryErr)
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
			setupMock: func(
				r *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
				_ *mocks.MockSerializer,
			) {
				r.EXPECT().
					Create(
						mock.Anything,
						mock.MatchedBy(func(secret *models.Secret) bool {
							return secret.OwnerID == ownerID &&
								secret.Type == models.SecretBinary &&
								secret.ID != uuid.Nil &&
								string(secret.Metadata) == string(metadata) &&
								secret.EncryptedData == nil
						}),
					).
					Return(&models.Secret{
						ID:       uuid.New(),
						OwnerID:  ownerID,
						Type:     models.SecretBinary,
						Metadata: metadata,
					}, nil)
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
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(serializedData, nil)

				e.EXPECT().
					Encrypt(serializedData).
					Return(encryptedData, nil)

				r.EXPECT().
					Create(
						mock.Anything,
						mock.MatchedBy(func(secret *models.Secret) bool {
							return secret.OwnerID == ownerID &&
								secret.Type == models.SecretText &&
								string(secret.EncryptedData) == string(encryptedData) &&
								string(secret.Metadata) == string(metadata)
						}),
					).
					Return(&models.Secret{
						ID:            uuid.New(),
						OwnerID:       ownerID,
						Type:          models.SecretText,
						EncryptedData: encryptedData,
						Metadata:      metadata,
					}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)
			serializer := mocks.NewMockSerializer(t)

			if tt.setupMock != nil {
				tt.setupMock(repo, encryptor, serializer)
			}

			service := NewSecretService(
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

			if got.OwnerID != tt.ownerID {
				t.Errorf(
					"OwnerID = %v, want %v",
					got.OwnerID,
					tt.ownerID,
				)
			}

			if got.Type != tt.input.Type {
				t.Errorf(
					"Type = %q, want %q",
					got.Type,
					tt.input.Type,
				)
			}

			if tt.input.Metadata == nil {
				if string(got.Metadata) != `{}` {
					t.Errorf(
						"Metadata = %q, want %q",
						got.Metadata,
						`{}`,
					)
				}
			} else if string(got.Metadata) != string(tt.input.Metadata) {
				t.Errorf(
					"Metadata = %q, want %q",
					got.Metadata,
					tt.input.Metadata,
				)
			}

			if tt.input.Type == models.SecretBinary {
				if got.EncryptedData != nil {
					t.Errorf(
						"EncryptedData = %v, want nil",
						got.EncryptedData,
					)
				}

				return
			}

			if string(got.EncryptedData) != string(encryptedData) {
				t.Errorf(
					"EncryptedData = %q, want %q",
					got.EncryptedData,
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
		name   string
		secret *models.Secret

		setupMock func(
			*mocks.MockSecretRepo,
			*mocks.MockEncryptor,
			*mocks.MockSerializer,
		)

		want    any
		wantErr error
	}{
		{
			name: "repository error",
			setupMock: func(
				r *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
				_ *mocks.MockSerializer,
			) {
				r.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(nil, repository.ErrSecretNotFound)
			},
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:   "decrypt error",
			secret: secret,
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				_ *mocks.MockSerializer,
			) {
				r.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(secret, nil)

				e.EXPECT().
					Decrypt(secret.EncryptedData).
					Return(nil, decryptErr)
			},
			wantErr: decryptErr,
		},
		{
			name:   "deserialize error",
			secret: secret,
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				r.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(secret, nil)

				e.EXPECT().
					Decrypt(secret.EncryptedData).
					Return(decryptedData, nil)

				s.EXPECT().
					Deserialize(
						secret.Type,
						decryptedData,
					).
					Return(nil, deserializeErr)
			},
			wantErr: deserializeErr,
		},
		{
			name:   "success structured secret",
			secret: secret,
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				r.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(secret, nil)

				e.EXPECT().
					Decrypt(secret.EncryptedData).
					Return(decryptedData, nil)

				s.EXPECT().
					Deserialize(
						secret.Type,
						decryptedData,
					).
					Return(deserializedData, nil)
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
			setupMock: func(
				r *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
				_ *mocks.MockSerializer,
			) {
				r.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:      secretID,
						OwnerID: ownerID,
						Type:    models.SecretBinary,
						Metadata: json.RawMessage(`{
							"filename": "document.pdf",
							"mime_type": "application/pdf"
						}`),
					}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)
			serializer := mocks.NewMockSerializer(t)

			if tt.setupMock != nil {
				tt.setupMock(repo, encryptor, serializer)
			}

			service := NewSecretService(
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

			if gotSecret.ID != tt.secret.ID {
				t.Errorf(
					"ID = %v, want %v",
					gotSecret.ID,
					tt.secret.ID,
				)
			}

			if tt.want != nil && gotData != tt.want {
				t.Errorf(
					"data = %v, want %v",
					gotData,
					tt.want,
				)
			}

			if tt.secret.Type == models.SecretBinary {
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
		})
	}
}

func TestSecretService_Get_BinaryInvalidMetadata(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	repo := mocks.NewMockSecretRepo(t)
	encryptor := mocks.NewMockEncryptor(t)
	serializer := mocks.NewMockSerializer(t)

	repo.EXPECT().
		GetByID(
			mock.Anything,
			ownerID,
			secretID,
		).
		Return(&models.Secret{
			ID:       secretID,
			OwnerID:  ownerID,
			Type:     models.SecretBinary,
			Metadata: []byte(`invalid json`),
		}, nil)

	service := NewSecretService(
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
		name    string
		setup   func(*mocks.MockSecretRepo)
		wantErr error
	}{
		{
			name: "success",
			setup: func(repo *mocks.MockSecretRepo) {
				repo.EXPECT().
					List(
						mock.Anything,
						ownerID,
					).
					Return(expected, nil)
			},
		},
		{
			name: "repository error",
			setup: func(repo *mocks.MockSecretRepo) {
				repo.EXPECT().
					List(
						mock.Anything,
						ownerID,
					).
					Return(nil, listErr)
			},
			wantErr: listErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)
			serializer := mocks.NewMockSerializer(t)

			tt.setup(repo)

			service := NewSecretService(
				repo,
				encryptor,
				serializer,
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
		name    string
		ownerID uuid.UUID
		input   UpdateSecretInput

		setupMock func(
			*mocks.MockSecretRepo,
			*mocks.MockEncryptor,
			*mocks.MockSerializer,
		)

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
			setupMock: func(
				_ *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(nil, serializeErr)
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
			setupMock: func(
				_ *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(serializedData, nil)

				e.EXPECT().
					Encrypt(serializedData).
					Return(nil, encryptErr)
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
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(serializedData, nil)

				e.EXPECT().
					Encrypt(serializedData).
					Return(encryptedData, nil)

				r.EXPECT().
					Update(
						mock.Anything,
						mock.MatchedBy(func(secret *models.Secret) bool {
							return secret.ID == secretID &&
								secret.OwnerID == ownerID &&
								secret.Type == models.SecretText
						}),
					).
					Return(nil, repositoryErr)
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
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				s *mocks.MockSerializer,
			) {
				s.EXPECT().
					Serialize("secret").
					Return(serializedData, nil)

				e.EXPECT().
					Encrypt(serializedData).
					Return(encryptedData, nil)

				r.EXPECT().
					Update(
						mock.Anything,
						mock.MatchedBy(func(secret *models.Secret) bool {
							return secret.ID == secretID &&
								secret.OwnerID == ownerID &&
								secret.Type == models.SecretText &&
								string(secret.EncryptedData) == string(encryptedData)
						}),
					).
					Return(&models.Secret{
						ID:            secretID,
						OwnerID:       ownerID,
						Type:          models.SecretText,
						EncryptedData: encryptedData,
						Metadata:      json.RawMessage(`{"name":"test"}`),
					}, nil)
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
			setupMock: func(
				r *mocks.MockSecretRepo,
				e *mocks.MockEncryptor,
				_ *mocks.MockSerializer,
			) {
				e.EXPECT().
					Encrypt([]byte("binary data")).
					Return(encryptedData, nil)

				r.EXPECT().
					Update(
						mock.Anything,
						mock.MatchedBy(func(secret *models.Secret) bool {
							return secret.ID == secretID &&
								secret.OwnerID == ownerID &&
								secret.Type == models.SecretBinary &&
								string(secret.EncryptedData) == string(encryptedData)
						}),
					).
					Return(&models.Secret{
						ID:            secretID,
						OwnerID:       ownerID,
						Type:          models.SecretBinary,
						EncryptedData: encryptedData,
						Metadata:      json.RawMessage(`{}`),
					}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)
			serializer := mocks.NewMockSerializer(t)

			if tt.setupMock != nil {
				tt.setupMock(repo, encryptor, serializer)
			}

			service := NewSecretService(
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

			if got == nil {
				t.Fatal("expected secret, got nil")
			}

			if got.ID != secretID {
				t.Errorf(
					"ID = %v, want %v",
					got.ID,
					secretID,
				)
			}

			if got.OwnerID != ownerID {
				t.Errorf(
					"OwnerID = %v, want %v",
					got.OwnerID,
					ownerID,
				)
			}

			if got.Type != tt.input.Type {
				t.Errorf(
					"Type = %q, want %q",
					got.Type,
					tt.input.Type,
				)
			}

			if string(got.EncryptedData) != string(encryptedData) {
				t.Errorf(
					"EncryptedData = %q, want %q",
					got.EncryptedData,
					encryptedData,
				)
			}
		})
	}
}

func TestSecretService_Delete(t *testing.T) {
	ownerID := uuid.New()
	secretID := uuid.New()

	deleteErr := errors.New("delete failed")

	tests := []struct {
		name    string
		setup   func(*mocks.MockSecretRepo)
		wantErr error
	}{
		{
			name: "success",
			setup: func(repo *mocks.MockSecretRepo) {
				repo.EXPECT().
					Delete(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(nil)
			},
		},
		{
			name: "repository error",
			setup: func(repo *mocks.MockSecretRepo) {
				repo.EXPECT().
					Delete(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(deleteErr)
			},
			wantErr: deleteErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)
			serializer := mocks.NewMockSerializer(t)

			tt.setup(repo)

			service := NewSecretService(
				repo,
				encryptor,
				serializer,
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

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
