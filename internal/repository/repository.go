package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
)

//go:generate mockery --name UserRepo
//go:generate mockery --name SecretRepo

// UserRepo интерфейс хранилища пользователей приложения.
type UserRepo interface {
	Create(ctx context.Context, login, passwordHash string) (*models.User, error)
	GetByLogin(ctx context.Context, login string) (*models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// SecretRepo интерфейс хранилища секретов пользователя.
type SecretRepo interface {
	Create(ctx context.Context, secret *models.Secret) (*models.Secret, error)
	GetByID(ctx context.Context, ownerID, secretID uuid.UUID) (*models.Secret, error)
	List(ctx context.Context, ownerID uuid.UUID) ([]*models.Secret, error)
	Update(ctx context.Context, secret *models.Secret) (*models.Secret, error)
	UpdateEncryptedData(ctx context.Context, ownerID uuid.UUID, secretID uuid.UUID, encryptedData []byte) error
	Delete(ctx context.Context, ownerID, secretID uuid.UUID) error
}

var (
	// ошибки репозитория с пользоватлями
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")

	// ошибки репозитория с секретами
	ErrSecretNotFound = errors.New("secret not found")
)
