package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKey        = errors.New("invalid encryption key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// Encryptor defines encryption and decryption operations.
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// AESGCM implements Encryptor using AES-GCM.
type AESGCM struct {
	aead cipher.AEAD
}

// NewAESGCM creates a new AES-GCM encryptor.
//
// key must be exactly 32 bytes long for AES-256.
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &AESGCM{aead: aead}, nil
}

// Encrypt encrypts data using AES-256-GCM.
//
// The returned byte slice contains:
// [nonce][ciphertext]
func (a *AESGCM) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := a.aead.Seal(
		nonce,
		nonce,
		data,
		nil,
	)

	return ciphertext, nil
}

// Decrypt decrypts data encrypted by Encrypt.
//
// The input must contain:
// [nonce][ciphertext]
func (a *AESGCM) Decrypt(data []byte) ([]byte, error) {
	nonceSize := a.aead.NonceSize()

	if len(data) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := a.aead.Open(
		nil,
		nonce,
		ciphertext,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	return plaintext, nil
}
