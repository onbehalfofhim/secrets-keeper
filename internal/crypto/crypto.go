package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/onbehalfofhim/secrets-keeper/internal/logger"
)

var (
	ErrInvalidKey        = errors.New("invalid encryption key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// Encryptor определяет операции шифрования и расшифрования данных.
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// AESGCM реализует шифрование и расшифрование данных
// с использованием AES-GCM.
type AESGCM struct {
	aead   cipher.AEAD
	logger *logger.Logger
}

// NewAESGCM создаёт новый AES-GCM шифратор.
//
// Для AES-256 ключ должен иметь длину ровно 32 байта.
func NewAESGCM(key []byte, logger *logger.Logger) (*AESGCM, error) {
	if len(key) != 32 {
		if logger != nil {
			logger.Error("invalid encryption key", "key_length", len(key))
		}
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("failed to create AES cipher", "error", err)

		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error("failed to create GCM", "error", err)

		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if logger != nil {
		logger.Info("AES-GCM encryptor initialized")
	}

	return &AESGCM{
		aead:   aead,
		logger: logger,
	}, nil
}

// Encrypt шифрует данные с использованием AES-256-GCM.
//
// В результирующем массиве сначала хранится nonce,
// затем зашифрованные данные:
//
// [nonce][ciphertext]
func (a *AESGCM) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		a.logger.Error("failed to generate encryption nonce", "error", err)

		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := a.aead.Seal(
		nonce,
		nonce,
		data,
		nil,
	)

	a.logger.Info("data encrypted", "data_size", len(data), "encrypted_size", len(ciphertext))

	return ciphertext, nil
}

// Decrypt расшифровывает данные, ранее зашифрованные методом Encrypt.
//
// Ожидается, что входные данные имеют следующий формат:
//
// [nonce][ciphertext]
func (a *AESGCM) Decrypt(data []byte) ([]byte, error) {
	nonceSize := a.aead.NonceSize()

	if len(data) < nonceSize {
		a.logger.Error("invalid ciphertext", "ciphertext_size", len(data))

		return nil, ErrInvalidCiphertext
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := a.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		a.logger.Error("failed to decrypt data", "ciphertext_size", len(data), "error", err)

		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	a.logger.Info("data decrypted", "encrypted_size", len(data), "data_size", len(plaintext))

	return plaintext, nil
}
