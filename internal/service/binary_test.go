package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/service/mocks"
)

func TestNewBinaryService(t *testing.T) {
	repo := mocks.NewMockSecretRepo(t)
	encryptor := mocks.NewMockEncryptor(t)

	service := NewBinaryService(repo, encryptor)

	if service == nil {
		t.Fatal("expected service, got nil")
	}

	if service.repository != repo {
		t.Error("service contains unexpected repository")
	}

	if service.encryptor != encryptor {
		t.Error("service contains unexpected encryptor")
	}
}

func TestBinaryService_Upload(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()

	plainData := []byte("binary data")
	encryptedData := []byte("encrypted binary data")

	encryptionErr := errors.New("encryption failed")
	updateErr := errors.New("update failed")

	tests := []struct {
		name     string
		ownerID  uuid.UUID
		secretID uuid.UUID
		data     []byte

		setupMock func(
			*mock.Mock,
			*mocks.MockSecretRepo,
			*mocks.MockEncryptor,
		)

		wantErr error
	}{
		{
			name:     "empty owner ID",
			ownerID:  uuid.Nil,
			secretID: secretID,
			data:     plainData,
			wantErr:  ErrInvalidSecret,
		},
		{
			name:     "empty secret ID",
			ownerID:  ownerID,
			secretID: uuid.Nil,
			data:     plainData,
			wantErr:  ErrInvalidSecret,
		},
		{
			name:     "repository error",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			setupMock: func(
				_ *mock.Mock,
				repo *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
			) {
				repo.EXPECT().
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
			name:     "secret is not binary",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			setupMock: func(
				_ *mock.Mock,
				repo *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
			) {
				repo.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:      secretID,
						OwnerID: ownerID,
						Type:    models.SecretText,
					}, nil)
			},
			wantErr: ErrInvalidSecretType,
		},
		{
			name:     "encryption error",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			setupMock: func(
				_ *mock.Mock,
				repo *mocks.MockSecretRepo,
				encryptor *mocks.MockEncryptor,
			) {
				repo.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:      secretID,
						OwnerID: ownerID,
						Type:    models.SecretBinary,
					}, nil)

				encryptor.EXPECT().
					Encrypt(plainData).
					Return(nil, encryptionErr)
			},
			wantErr: encryptionErr,
		},
		{
			name:     "repository update error",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			setupMock: func(
				_ *mock.Mock,
				repo *mocks.MockSecretRepo,
				encryptor *mocks.MockEncryptor,
			) {
				repo.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:      secretID,
						OwnerID: ownerID,
						Type:    models.SecretBinary,
					}, nil)

				encryptor.EXPECT().
					Encrypt(plainData).
					Return(encryptedData, nil)

				repo.EXPECT().
					UpdateEncryptedData(
						mock.Anything,
						ownerID,
						secretID,
						encryptedData,
					).
					Return(updateErr)
			},
			wantErr: updateErr,
		},
		{
			name:     "success",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			setupMock: func(
				_ *mock.Mock,
				repo *mocks.MockSecretRepo,
				encryptor *mocks.MockEncryptor,
			) {
				repo.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:      secretID,
						OwnerID: ownerID,
						Type:    models.SecretBinary,
					}, nil)

				encryptor.EXPECT().
					Encrypt(plainData).
					Return(encryptedData, nil)

				repo.EXPECT().
					UpdateEncryptedData(
						mock.Anything,
						ownerID,
						secretID,
						encryptedData,
					).
					Return(nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)

			if tt.setupMock != nil {
				tt.setupMock(
					&mock.Mock{},
					repo,
					encryptor,
				)
			}

			service := NewBinaryService(repo, encryptor)

			err := service.Upload(
				ctx,
				tt.ownerID,
				tt.secretID,
				tt.data,
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

func TestBinaryService_Upload_DoesNotCallDependenciesForInvalidIDs(
	t *testing.T,
) {
	tests := []struct {
		name     string
		ownerID  uuid.UUID
		secretID uuid.UUID
	}{
		{
			name:     "empty owner ID",
			ownerID:  uuid.Nil,
			secretID: uuid.New(),
		},
		{
			name:     "empty secret ID",
			ownerID:  uuid.New(),
			secretID: uuid.Nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)

			service := NewBinaryService(repo, encryptor)

			err := service.Upload(
				context.Background(),
				tt.ownerID,
				tt.secretID,
				[]byte("data"),
			)

			if !errors.Is(err, ErrInvalidSecret) {
				t.Fatalf(
					"expected ErrInvalidSecret, got %v",
					err,
				)
			}

			// Если сервис неожиданно вызовет эти методы,
			// mockery автоматически сообщит об unexpected call.
		})
	}
}

func TestBinaryService_Upload_DoesNotEncryptNonBinarySecret(
	t *testing.T,
) {
	ownerID := uuid.New()
	secretID := uuid.New()

	repo := mocks.NewMockSecretRepo(t)
	encryptor := mocks.NewMockEncryptor(t)

	repo.EXPECT().
		GetByID(
			mock.Anything,
			ownerID,
			secretID,
		).
		Return(&models.Secret{
			ID:      secretID,
			OwnerID: ownerID,
			Type:    models.SecretText,
		}, nil)

	service := NewBinaryService(repo, encryptor)

	err := service.Upload(
		context.Background(),
		ownerID,
		secretID,
		[]byte("data"),
	)

	if !errors.Is(err, ErrInvalidSecretType) {
		t.Fatalf(
			"expected ErrInvalidSecretType, got %v",
			err,
		)
	}

	// Encrypt и UpdateEncryptedData не имеют EXPECT().
	// Поэтому их вызов автоматически будет считаться ошибкой.
}

func TestBinaryService_Download(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()

	encryptedData := []byte("encrypted binary data")
	plainData := []byte("binary data")

	decryptionErr := errors.New("decryption failed")

	tests := []struct {
		name     string
		ownerID  uuid.UUID
		secretID uuid.UUID

		setupMock func(
			*mocks.MockSecretRepo,
			*mocks.MockEncryptor,
		)

		want    []byte
		wantErr error
	}{
		{
			name:     "empty owner ID",
			ownerID:  uuid.Nil,
			secretID: secretID,
			wantErr:  ErrInvalidSecret,
		},
		{
			name:     "empty secret ID",
			ownerID:  ownerID,
			secretID: uuid.Nil,
			wantErr:  ErrInvalidSecret,
		},
		{
			name:     "repository error",
			ownerID:  ownerID,
			secretID: secretID,
			setupMock: func(
				repo *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
			) {
				repo.EXPECT().
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
			name:     "secret is not binary",
			ownerID:  ownerID,
			secretID: secretID,
			setupMock: func(
				repo *mocks.MockSecretRepo,
				_ *mocks.MockEncryptor,
			) {
				repo.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:      secretID,
						OwnerID: ownerID,
						Type:    models.SecretText,
					}, nil)
			},
			wantErr: ErrInvalidSecretType,
		},
		{
			name:     "decryption error",
			ownerID:  ownerID,
			secretID: secretID,
			setupMock: func(
				repo *mocks.MockSecretRepo,
				encryptor *mocks.MockEncryptor,
			) {
				repo.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:            secretID,
						OwnerID:       ownerID,
						Type:          models.SecretBinary,
						EncryptedData: encryptedData,
					}, nil)

				encryptor.EXPECT().
					Decrypt(encryptedData).
					Return(nil, decryptionErr)
			},
			wantErr: decryptionErr,
		},
		{
			name:     "success",
			ownerID:  ownerID,
			secretID: secretID,
			setupMock: func(
				repo *mocks.MockSecretRepo,
				encryptor *mocks.MockEncryptor,
			) {
				repo.EXPECT().
					GetByID(
						mock.Anything,
						ownerID,
						secretID,
					).
					Return(&models.Secret{
						ID:            secretID,
						OwnerID:       ownerID,
						Type:          models.SecretBinary,
						EncryptedData: encryptedData,
					}, nil)

				encryptor.EXPECT().
					Decrypt(encryptedData).
					Return(plainData, nil)
			},
			want: plainData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)

			if tt.setupMock != nil {
				tt.setupMock(repo, encryptor)
			}

			service := NewBinaryService(repo, encryptor)

			got, err := service.Download(
				ctx,
				tt.ownerID,
				tt.secretID,
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
						"expected nil data, got %v",
						got,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(got) != string(tt.want) {
				t.Errorf(
					"Download() = %q, want %q",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestBinaryService_Download_DoesNotCallDependenciesForInvalidIDs(
	t *testing.T,
) {
	tests := []struct {
		name     string
		ownerID  uuid.UUID
		secretID uuid.UUID
	}{
		{
			name:     "empty owner ID",
			ownerID:  uuid.Nil,
			secretID: uuid.New(),
		},
		{
			name:     "empty secret ID",
			ownerID:  uuid.New(),
			secretID: uuid.Nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := mocks.NewMockSecretRepo(t)
			encryptor := mocks.NewMockEncryptor(t)

			service := NewBinaryService(repo, encryptor)

			_, err := service.Download(
				context.Background(),
				tt.ownerID,
				tt.secretID,
			)

			if !errors.Is(err, ErrInvalidSecret) {
				t.Fatalf(
					"expected ErrInvalidSecret, got %v",
					err,
				)
			}
		})
	}
}

func TestBinaryService_Download_DoesNotDecryptNonBinarySecret(
	t *testing.T,
) {
	ownerID := uuid.New()
	secretID := uuid.New()

	repo := mocks.NewMockSecretRepo(t)
	encryptor := mocks.NewMockEncryptor(t)

	repo.EXPECT().
		GetByID(
			mock.Anything,
			ownerID,
			secretID,
		).
		Return(&models.Secret{
			ID:      secretID,
			OwnerID: ownerID,
			Type:    models.SecretText,
		}, nil)

	service := NewBinaryService(repo, encryptor)

	_, err := service.Download(
		context.Background(),
		ownerID,
		secretID,
	)

	if !errors.Is(err, ErrInvalidSecretType) {
		t.Fatalf(
			"expected ErrInvalidSecretType, got %v",
			err,
		)
	}
}
