package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/onbehalfofhim/secrets-keeper/internal/auth"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidLogin       = errors.New("invalid login")
	ErrInvalidPassword    = errors.New("invalid password")
)

type AuthService struct {
	users repository.UserRepo
	jwt   *auth.JWT
}

type LoginResult struct {
	AccessToken string
	ExpiresIn   int64
}

func NewAuthService(users repository.UserRepo, jwt *auth.JWT) *AuthService {
	return &AuthService{
		users: users,
		jwt:   jwt,
	}
}

func (s *AuthService) Register(ctx context.Context, login, password string) (*models.User, error) {
	if login == "" {
		return nil, ErrInvalidLogin
	}

	if password == "" {
		return nil, ErrInvalidPassword
	}

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.users.Create(
		ctx,
		login,
		passwordHash,
	)
	if err != nil {
		if errors.Is(err, repository.ErrUserExists) {
			return nil, repository.ErrUserExists
		}

		return nil, fmt.Errorf("create user: %w", err)
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, login, password string) (*LoginResult, error) {
	if login == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.users.GetByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("get user: %w", err)
	}

	if err := auth.CheckPassword(
		user.PasswordHash,
		password,
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	token, expiresIn, err := s.jwt.GenerateToken(
		user.ID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	return &LoginResult{
		AccessToken: token,
		ExpiresIn:   expiresIn,
	}, nil
}
