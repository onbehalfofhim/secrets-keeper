package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
)

type mockEncryptor struct {
	encryptFunc func([]byte) ([]byte, error)
	decryptFunc func([]byte) ([]byte, error)

	encryptCalled bool
	decryptCalled bool

	encryptInput []byte
	decryptInput []byte
}

func (m *mockEncryptor) Encrypt(data []byte) ([]byte, error) {
	m.encryptCalled = true
	m.encryptInput = data

	if m.encryptFunc != nil {
		return m.encryptFunc(data)
	}

	return nil, nil
}

func (m *mockEncryptor) Decrypt(data []byte) ([]byte, error) {
	m.decryptCalled = true
	m.decryptInput = data

	if m.decryptFunc != nil {
		return m.decryptFunc(data)
	}

	return nil, nil
}

type mockSecretRepository struct {
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

	updateEncryptedDataFunc func(
		ctx context.Context,
		ownerID, secretID uuid.UUID,
		encryptedData []byte,
	) error

	deleteFunc func(
		ctx context.Context,
		ownerID, secretID uuid.UUID,
	) error

	createCalled              bool
	getByIDCalled             bool
	listCalled                bool
	updateCalled              bool
	updateEncryptedDataCalled bool
	deleteCalled              bool

	createdSecret *models.Secret
	updatedSecret *models.Secret

	getByIDOwnerID  uuid.UUID
	getByIDSecretID uuid.UUID

	listOwnerID uuid.UUID

	updateEncryptedDataOwnerID  uuid.UUID
	updateEncryptedDataSecretID uuid.UUID
	updateEncryptedData         []byte

	deleteOwnerID  uuid.UUID
	deleteSecretID uuid.UUID
}

func (m *mockSecretRepository) Create(
	ctx context.Context,
	secret *models.Secret,
) (*models.Secret, error) {
	m.createCalled = true
	m.createdSecret = secret

	if m.createFunc != nil {
		return m.createFunc(ctx, secret)
	}

	return secret, nil
}

func (m *mockSecretRepository) GetByID(
	ctx context.Context,
	ownerID, secretID uuid.UUID,
) (*models.Secret, error) {
	m.getByIDCalled = true
	m.getByIDOwnerID = ownerID
	m.getByIDSecretID = secretID

	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, ownerID, secretID)
	}

	return nil, nil
}

func (m *mockSecretRepository) List(
	ctx context.Context,
	ownerID uuid.UUID,
) ([]*models.Secret, error) {
	m.listCalled = true
	m.listOwnerID = ownerID

	if m.listFunc != nil {
		return m.listFunc(ctx, ownerID)
	}

	return nil, nil
}

func (m *mockSecretRepository) Update(
	ctx context.Context,
	secret *models.Secret,
) (*models.Secret, error) {
	m.updateCalled = true
	m.updatedSecret = secret

	if m.updateFunc != nil {
		return m.updateFunc(ctx, secret)
	}

	return secret, nil
}

func (m *mockSecretRepository) UpdateEncryptedData(
	ctx context.Context,
	ownerID, secretID uuid.UUID,
	encryptedData []byte,
) error {
	m.updateEncryptedDataCalled = true
	m.updateEncryptedDataOwnerID = ownerID
	m.updateEncryptedDataSecretID = secretID
	m.updateEncryptedData = encryptedData

	if m.updateEncryptedDataFunc != nil {
		return m.updateEncryptedDataFunc(
			ctx,
			ownerID,
			secretID,
			encryptedData,
		)
	}

	return nil
}

func (m *mockSecretRepository) Delete(
	ctx context.Context,
	ownerID, secretID uuid.UUID,
) error {
	m.deleteCalled = true
	m.deleteOwnerID = ownerID
	m.deleteSecretID = secretID

	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, ownerID, secretID)
	}

	return nil
}

type mockSerializer struct {
	serializeFunc func(any) ([]byte, error)

	deserializeFunc func(
		models.SecretType,
		[]byte,
	) (any, error)

	serializeCalled   bool
	deserializeCalled bool

	serializeInput   any
	deserializeType  models.SecretType
	deserializeInput []byte
}

func (m *mockSerializer) Serialize(data any) ([]byte, error) {
	m.serializeCalled = true
	m.serializeInput = data

	if m.serializeFunc != nil {
		return m.serializeFunc(data)
	}

	return nil, nil
}

func (m *mockSerializer) Deserialize(
	secretType models.SecretType,
	data []byte,
) (any, error) {
	m.deserializeCalled = true
	m.deserializeType = secretType
	m.deserializeInput = data

	if m.deserializeFunc != nil {
		return m.deserializeFunc(secretType, data)
	}

	return nil, nil
}

type mockUserRepository struct {
	createFunc func(
		ctx context.Context,
		login, passwordHash string,
	) (*models.User, error)

	getByLoginFunc func(
		ctx context.Context,
		login string,
	) (*models.User, error)

	getByIDFunc func(
		ctx context.Context,
		id uuid.UUID,
	) (*models.User, error)

	createCalled     bool
	getByLoginCalled bool
	getByIDCalled    bool

	createLogin        string
	createPasswordHash string
	getByLogin         string
}

func (m *mockUserRepository) Create(
	ctx context.Context,
	login, passwordHash string,
) (*models.User, error) {
	m.createCalled = true
	m.createLogin = login
	m.createPasswordHash = passwordHash

	if m.createFunc != nil {
		return m.createFunc(ctx, login, passwordHash)
	}

	return nil, nil
}

func (m *mockUserRepository) GetByLogin(
	ctx context.Context,
	login string,
) (*models.User, error) {
	m.getByLoginCalled = true
	m.getByLogin = login

	if m.getByLoginFunc != nil {
		return m.getByLoginFunc(ctx, login)
	}

	return nil, nil
}

func (m *mockUserRepository) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*models.User, error) {
	m.getByIDCalled = true

	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}

	return nil, nil
}
