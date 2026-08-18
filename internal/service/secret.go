package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/onbehalfofhim/secrets-keeper/internal/crypto"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
	"github.com/onbehalfofhim/secrets-keeper/internal/serializer"
)

var (
	ErrInvalidSecret     = errors.New("invalid secret")
	ErrInvalidSecretType = errors.New("invalid secret type")
)

// SecretService реализует бизнес-логику работы с секретами.
//
// Сервис отвечает за валидацию данных, сериализацию и шифрование
// секретов перед сохранением, а также расшифровку и десериализацию
// данных при получении.
type SecretService struct {
	repository repository.SecretRepo
	encryptor  crypto.Encryptor
	serializer serializer.Serializer
}

// NewSecretService создаёт новый сервис для работы с секретами.
func NewSecretService(repository repository.SecretRepo, encryptor crypto.Encryptor, serializer serializer.Serializer) *SecretService {
	return &SecretService{
		repository: repository,
		encryptor:  encryptor,
		serializer: serializer,
	}
}

// CreateSecretInput содержит данные для создания секрета.
type CreateSecretInput struct {
	Type     models.SecretType
	Data     any
	Metadata json.RawMessage
}

// Create создаёт новый секрет.
//
// Для текстовых, login/password и банковских секретов данные
// сериализуются в JSON и шифруются перед сохранением.
//
// Для бинарного секрета на этом этапе сохраняется только метаинформация.
// Сам файл загружается отдельным потоковым RPC.
func (s *SecretService) Create(ctx context.Context, ownerID uuid.UUID, input CreateSecretInput) (*models.Secret, error) {
	if ownerID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: owner id is empty",
			ErrInvalidSecret,
		)
	}

	if input.Type == "" {
		return nil, fmt.Errorf(
			"%w: secret type is empty",
			ErrInvalidSecretType,
		)
	}

	if input.Metadata == nil {
		input.Metadata = json.RawMessage(`{}`)
	}

	var encryptedData []byte

	switch input.Type {
	case models.SecretText,
		models.SecretLogin,
		models.SecretCard:

		serialized, err := s.serializer.Serialize(input.Data)
		if err != nil {
			return nil, fmt.Errorf(
				"serialize secret: %w",
				err,
			)
		}

		encryptedData, err = s.encryptor.Encrypt(serialized)
		if err != nil {
			return nil, fmt.Errorf(
				"encrypt secret: %w",
				err,
			)
		}

	case models.SecretBinary:
		// Binary-файл загружается отдельным UploadBinary RPC.
		// Поэтому при создании секрета содержимое файла
		// еще отсутствует.
		encryptedData = nil

	default:
		return nil, fmt.Errorf(
			"%w: %s",
			ErrInvalidSecretType,
			input.Type,
		)
	}

	secret := &models.Secret{
		ID:            uuid.New(),
		OwnerID:       ownerID,
		Type:          input.Type,
		EncryptedData: encryptedData,
		Metadata:      input.Metadata,
	}

	return s.repository.Create(ctx, secret)
}

// Get получает секрет пользователя.
//
// Для бинарного секрета возвращается только метаинформация о файле.
// Содержимое файла не расшифровывается и получается через
// BinaryService.Download.
//
// Для остальных типов секретов зашифрованные данные расшифровываются
// и десериализуются в соответствующую структуру.
func (s *SecretService) Get(ctx context.Context, ownerID uuid.UUID, secretID uuid.UUID) (*models.Secret, any, error) {
	secret, err := s.repository.GetByID(ctx, ownerID, secretID)
	if err != nil {
		return nil, nil, err
	}

	// Бинарный секрет содержит в metadata только информацию
	// о файле: имя и MIME-тип. Само содержимое хранится
	// в encrypted_data.
	if secret.Type == models.SecretBinary {
		var binarySecret models.BinarySecret

		if err := json.Unmarshal(
			secret.Metadata,
			&binarySecret,
		); err != nil {
			return nil, nil, fmt.Errorf(
				"unmarshal binary metadata: %w",
				err,
			)
		}

		return secret, &binarySecret, nil
	}

	// Для обычных секретов:
	// encrypted_data → decrypt → deserialize.
	decrypted, err := s.encryptor.Decrypt(
		secret.EncryptedData,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"decrypt secret: %w",
			err,
		)
	}

	data, err := s.serializer.Deserialize(
		secret.Type,
		decrypted,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"deserialize secret: %w",
			err,
		)
	}

	return secret, data, nil
}

// List возвращает список секретов указанного пользователя.
//
// Данные секретов не расшифровываются — возвращается только
// информация, необходимая для формирования списка.
func (s *SecretService) List(ctx context.Context, ownerID uuid.UUID) ([]*models.Secret, error) {
	return s.repository.List(ctx, ownerID)
}

// UpdateSecretInput содержит данные для обновления секрета.
type UpdateSecretInput struct {
	ID       uuid.UUID
	Type     models.SecretType
	Data     any
	Metadata json.RawMessage
}

// Update обновляет существующий секрет.
//
// Данные сериализуются при необходимости, затем шифруются
// и сохраняются в репозитории. Операция выполняется только
// для указанного владельца секрета.
func (s *SecretService) Update(ctx context.Context, ownerID uuid.UUID, input UpdateSecretInput) (*models.Secret, error) {
	if ownerID == uuid.Nil {
		return nil, fmt.Errorf("%w: owner id is empty", ErrInvalidSecret)
	}

	if input.ID == uuid.Nil {
		return nil, fmt.Errorf("%w: secret id is empty", ErrInvalidSecret)
	}

	var plaintext []byte

	if input.Type == models.SecretBinary {
		binaryData, ok := input.Data.([]byte)
		if !ok {
			return nil, fmt.Errorf(
				"%w: binary secret expects []byte",
				ErrInvalidSecret,
			)
		}

		plaintext = binaryData
	} else {
		serialized, err := s.serializer.Serialize(input.Data)
		if err != nil {
			return nil, fmt.Errorf("serialize secret: %w", err)
		}

		plaintext = serialized
	}

	encrypted, err := s.encryptor.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt secret: %w", err)
	}

	secret := &models.Secret{
		ID:            input.ID,
		OwnerID:       ownerID,
		Type:          input.Type,
		EncryptedData: encrypted,
		Metadata:      input.Metadata,
	}

	return s.repository.Update(ctx, secret)
}

// Delete удаляет секрет указанного пользователя.
func (s *SecretService) Delete(ctx context.Context, ownerID uuid.UUID, secretID uuid.UUID) error {
	return s.repository.Delete(
		ctx,
		ownerID,
		secretID,
	)
}
