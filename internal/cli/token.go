package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrTokenNotFound = errors.New("authentication required")

// TokenStore отвечает за локальное хранение JWT.
type TokenStore struct {
	path string
}

// NewTokenStore создаёт TokenStore.
func NewTokenStore(path string) *TokenStore {
	return &TokenStore{
		path: path,
	}
}

// Save сохраняет JWT.
// Файл создаётся с правами 0600, чтобы только владелец
// мог читать токен.
func (s *TokenStore) Save(token string) error {
	token = strings.TrimSpace(token)

	if token == "" {
		return errors.New("token is empty")
	}

	dir := filepath.Dir(s.path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf(
			"create token directory: %w",
			err,
		)
	}

	if err := os.WriteFile(s.path, []byte(token), 0600); err != nil {
		return fmt.Errorf(
			"save token: %w",
			err,
		)
	}

	return nil
}

// Load загружает JWT.
func (s *TokenStore) Load() (string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrTokenNotFound
		}

		return "", fmt.Errorf(
			"read token: %w",
			err,
		)
	}

	token := strings.TrimSpace(string(data))

	if token == "" {
		return "", ErrTokenNotFound
	}

	return token, nil
}

// Delete удаляет сохранённый JWT.
func (s *TokenStore) Delete() error {
	err := os.Remove(s.path)

	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf(
			"delete token: %w",
			err,
		)
	}

	return nil
}
