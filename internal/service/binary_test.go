package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

func TestNewBinaryService(t *testing.T) {
	repo := &mockSecretRepository{}
	encryptor := &mockEncryptor{}

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
		name string

		ownerID  uuid.UUID
		secretID uuid.UUID
		data     []byte

		getByIDFunc func(
			ctx context.Context,
			ownerID, secretID uuid.UUID,
		) (*models.Secret, error)

		encryptFunc func([]byte) ([]byte, error)

		updateEncryptedDataFunc func(
			ctx context.Context,
			ownerID, secretID uuid.UUID,
			encryptedData []byte,
		) error

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
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return nil, repository.ErrSecretNotFound
			},
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:     "secret is not binary",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:      secretID,
					OwnerID: ownerID,
					Type:    models.SecretText,
				}, nil
			},
			wantErr: ErrInvalidSecretType,
		},
		{
			name:     "encryption error",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:      secretID,
					OwnerID: ownerID,
					Type:    models.SecretBinary,
				}, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return nil, encryptionErr
			},
			wantErr: encryptionErr,
		},
		{
			name:     "repository update error",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:      secretID,
					OwnerID: ownerID,
					Type:    models.SecretBinary,
				}, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return encryptedData, nil
			},
			updateEncryptedDataFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
				encryptedData []byte,
			) error {
				return updateErr
			},
			wantErr: updateErr,
		},
		{
			name:     "success",
			ownerID:  ownerID,
			secretID: secretID,
			data:     plainData,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:      secretID,
					OwnerID: ownerID,
					Type:    models.SecretBinary,
				}, nil
			},
			encryptFunc: func(data []byte) ([]byte, error) {
				return encryptedData, nil
			},
			updateEncryptedDataFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
				encryptedData []byte,
			) error {
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockSecretRepository{
				getByIDFunc:             tt.getByIDFunc,
				updateEncryptedDataFunc: tt.updateEncryptedDataFunc,
			}

			encryptor := &mockEncryptor{
				encryptFunc: tt.encryptFunc,
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

			if !repo.getByIDCalled {
				t.Fatal("expected GetByID to be called")
			}

			if repo.getByIDOwnerID != ownerID {
				t.Errorf(
					"GetByID ownerID = %v, want %v",
					repo.getByIDOwnerID,
					ownerID,
				)
			}

			if repo.getByIDSecretID != secretID {
				t.Errorf(
					"GetByID secretID = %v, want %v",
					repo.getByIDSecretID,
					secretID,
				)
			}

			if !encryptor.encryptCalled {
				t.Fatal("expected Encrypt to be called")
			}

			if string(encryptor.encryptInput) != string(plainData) {
				t.Errorf(
					"Encrypt input = %q, want %q",
					encryptor.encryptInput,
					plainData,
				)
			}

			if !repo.updateEncryptedDataCalled {
				t.Fatal("expected UpdateEncryptedData to be called")
			}

			if repo.updateEncryptedDataOwnerID != ownerID {
				t.Errorf(
					"UpdateEncryptedData ownerID = %v, want %v",
					repo.updateEncryptedDataOwnerID,
					ownerID,
				)
			}

			if repo.updateEncryptedDataSecretID != secretID {
				t.Errorf(
					"UpdateEncryptedData secretID = %v, want %v",
					repo.updateEncryptedDataSecretID,
					secretID,
				)
			}

			if string(repo.updateEncryptedData) != string(encryptedData) {
				t.Errorf(
					"encrypted data = %q, want %q",
					repo.updateEncryptedData,
					encryptedData,
				)
			}
		})
	}
}

func TestBinaryService_Upload_DoesNotCallDependenciesForInvalidIDs(t *testing.T) {
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
			repo := &mockSecretRepository{}
			encryptor := &mockEncryptor{}

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

			if repo.getByIDCalled {
				t.Error("GetByID should not be called")
			}

			if encryptor.encryptCalled {
				t.Error("Encrypt should not be called")
			}

			if repo.updateEncryptedDataCalled {
				t.Error(
					"UpdateEncryptedData should not be called",
				)
			}
		})
	}
}

func TestBinaryService_Upload_DoesNotEncryptNonBinarySecret(t *testing.T) {
	repo := &mockSecretRepository{
		getByIDFunc: func(
			ctx context.Context,
			ownerID, secretID uuid.UUID,
		) (*models.Secret, error) {
			return &models.Secret{
				ID:      secretID,
				OwnerID: ownerID,
				Type:    models.SecretText,
			}, nil
		},
	}

	encryptor := &mockEncryptor{}

	service := NewBinaryService(repo, encryptor)

	err := service.Upload(
		context.Background(),
		uuid.New(),
		uuid.New(),
		[]byte("data"),
	)

	if !errors.Is(err, ErrInvalidSecretType) {
		t.Fatalf(
			"expected ErrInvalidSecretType, got %v",
			err,
		)
	}

	if encryptor.encryptCalled {
		t.Fatal(
			"Encrypt should not be called for non-binary secret",
		)
	}

	if repo.updateEncryptedDataCalled {
		t.Fatal(
			"UpdateEncryptedData should not be called for non-binary secret",
		)
	}
}

func TestBinaryService_Download(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()

	encryptedData := []byte("encrypted binary data")
	plainData := []byte("binary data")

	decryptionErr := errors.New("decryption failed")

	tests := []struct {
		name string

		ownerID  uuid.UUID
		secretID uuid.UUID

		getByIDFunc func(
			ctx context.Context,
			ownerID, secretID uuid.UUID,
		) (*models.Secret, error)

		decryptFunc func([]byte) ([]byte, error)

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
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return nil, repository.ErrSecretNotFound
			},
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:     "secret is not binary",
			ownerID:  ownerID,
			secretID: secretID,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:      secretID,
					OwnerID: ownerID,
					Type:    models.SecretText,
				}, nil
			},
			wantErr: ErrInvalidSecretType,
		},
		{
			name:     "decryption error",
			ownerID:  ownerID,
			secretID: secretID,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:            secretID,
					OwnerID:       ownerID,
					Type:          models.SecretBinary,
					EncryptedData: encryptedData,
				}, nil
			},
			decryptFunc: func(data []byte) ([]byte, error) {
				return nil, decryptionErr
			},
			wantErr: decryptionErr,
		},
		{
			name:     "success",
			ownerID:  ownerID,
			secretID: secretID,
			getByIDFunc: func(
				ctx context.Context,
				ownerID, secretID uuid.UUID,
			) (*models.Secret, error) {
				return &models.Secret{
					ID:            secretID,
					OwnerID:       ownerID,
					Type:          models.SecretBinary,
					EncryptedData: encryptedData,
				}, nil
			},
			decryptFunc: func(data []byte) ([]byte, error) {
				return plainData, nil
			},
			want: plainData,
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

			if !repo.getByIDCalled {
				t.Fatal("expected GetByID to be called")
			}

			if !encryptor.decryptCalled {
				t.Fatal("expected Decrypt to be called")
			}

			if string(encryptor.decryptInput) != string(encryptedData) {
				t.Errorf(
					"Decrypt input = %q, want %q",
					encryptor.decryptInput,
					encryptedData,
				)
			}
		})
	}
}

func TestBinaryService_Download_DoesNotCallDependenciesForInvalidIDs(t *testing.T) {
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
			repo := &mockSecretRepository{}
			encryptor := &mockEncryptor{}

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

			if repo.getByIDCalled {
				t.Error("GetByID should not be called")
			}

			if encryptor.decryptCalled {
				t.Error("Decrypt should not be called")
			}
		})
	}
}

func TestBinaryService_Download_DoesNotDecryptNonBinarySecret(t *testing.T) {
	repo := &mockSecretRepository{
		getByIDFunc: func(
			ctx context.Context,
			ownerID, secretID uuid.UUID,
		) (*models.Secret, error) {
			return &models.Secret{
				ID:      secretID,
				OwnerID: ownerID,
				Type:    models.SecretText,
			}, nil
		},
	}

	encryptor := &mockEncryptor{}

	service := NewBinaryService(repo, encryptor)

	_, err := service.Download(
		context.Background(),
		uuid.New(),
		uuid.New(),
	)

	if !errors.Is(err, ErrInvalidSecretType) {
		t.Fatalf(
			"expected ErrInvalidSecretType, got %v",
			err,
		)
	}

	if encryptor.decryptCalled {
		t.Fatal(
			"Decrypt should not be called for non-binary secret",
		)
	}
}
