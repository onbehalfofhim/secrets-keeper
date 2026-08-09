package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/onbehalfofhim/secrets-keeper/internal/crypto"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

type BinaryService struct {
	repository repository.SecretRepo
	encryptor  crypto.Encryptor
}

var (
	ErrBinaryNotUploaded = errors.New("binary file not uploaded")
)

func NewBinaryService(repository repository.SecretRepo, encryptor crypto.Encryptor) *BinaryService {
	return &BinaryService{
		repository: repository,
		encryptor:  encryptor,
	}
}

func (s *BinaryService) Upload(ctx context.Context, ownerID uuid.UUID, secretID uuid.UUID, data []byte) error {
	if ownerID == uuid.Nil {
		return fmt.Errorf(
			"%w: owner id is empty",
			ErrInvalidSecret,
		)
	}

	if secretID == uuid.Nil {
		return fmt.Errorf(
			"%w: secret id is empty",
			ErrInvalidSecret,
		)
	}

	secret, err := s.repository.GetByID(
		ctx,
		ownerID,
		secretID,
	)
	if err != nil {
		return err
	}

	if secret.Type != models.SecretBinary {
		return fmt.Errorf(
			"%w: secret is not binary",
			ErrInvalidSecretType,
		)
	}

	encrypted, err := s.encryptor.Encrypt(data)
	if err != nil {
		return fmt.Errorf(
			"encrypt binary data: %w",
			err,
		)
	}

	return s.repository.UpdateEncryptedData(
		ctx,
		ownerID,
		secretID,
		encrypted,
	)
}

func (s *BinaryService) Download(ctx context.Context, ownerID uuid.UUID, secretID uuid.UUID) ([]byte, error) {
	if ownerID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: owner id is empty",
			ErrInvalidSecret,
		)
	}

	if secretID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: secret id is empty",
			ErrInvalidSecret,
		)
	}

	secret, err := s.repository.GetByID(
		ctx,
		ownerID,
		secretID,
	)
	if err != nil {
		return nil, err
	}

	if secret.Type != models.SecretBinary {
		return nil, fmt.Errorf(
			"%w: secret is not binary",
			ErrInvalidSecretType,
		)
	}

	if len(secret.EncryptedData) == 0 {
		return nil, ErrBinaryNotUploaded
	}

	data, err := s.encryptor.Decrypt(
		secret.EncryptedData,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"decrypt binary data: %w",
			err,
		)
	}

	return data, nil
}
