package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewAESGCM(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
		errIs   error
	}{
		{
			name:    "valid key",
			key:     make([]byte, 32),
			wantErr: false,
		},
		{
			name:    "empty key",
			key:     []byte{},
			wantErr: true,
			errIs:   ErrInvalidKey,
		},
		{
			name:    "key too short",
			key:     make([]byte, 16),
			wantErr: true,
			errIs:   ErrInvalidKey,
		},
		{
			name:    "key too long",
			key:     make([]byte, 64),
			wantErr: true,
			errIs:   ErrInvalidKey,
		},
		{
			name:    "key 31 bytes",
			key:     make([]byte, 31),
			wantErr: true,
			errIs:   ErrInvalidKey,
		},
		{
			name:    "key 33 bytes",
			key:     make([]byte, 33),
			wantErr: true,
			errIs:   ErrInvalidKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAESGCM(tt.key)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.errIs != nil && !errors.Is(err, tt.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tt.errIs, err)
				}

				if got != nil {
					t.Errorf("expected nil AESGCM, got %v", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got == nil {
				t.Fatal("expected AESGCM, got nil")
			}

			if got.aead == nil {
				t.Fatal("expected initialized AEAD")
			}
		})
	}
}

func TestAESGCM_EncryptDecrypt(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	encryptor, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "plain text",
			data: []byte("hello world"),
		},
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "binary data",
			data: []byte{0, 1, 2, 3, 255, 254, 253},
		},
		{
			name: "large data",
			data: bytes.Repeat([]byte("test"), 10_000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := encryptor.Encrypt(tt.data)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			if len(ciphertext) <= encryptor.aead.NonceSize() {
				t.Fatalf(
					"ciphertext is too short: got %d bytes",
					len(ciphertext),
				)
			}

			plaintext, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if !bytes.Equal(plaintext, tt.data) {
				t.Errorf(
					"decrypted data does not match original: got %q, want %q",
					plaintext,
					tt.data,
				)
			}
		})
	}
}

func TestAESGCM_Decrypt_InvalidCiphertext(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	encryptor, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty ciphertext",
			data: []byte{},
		},
		{
			name: "ciphertext shorter than nonce",
			data: make([]byte, encryptor.aead.NonceSize()-1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := encryptor.Decrypt(tt.data)

			if !errors.Is(err, ErrInvalidCiphertext) {
				t.Errorf(
					"expected ErrInvalidCiphertext, got %v",
					err,
				)
			}

			if plaintext != nil {
				t.Errorf(
					"expected nil plaintext, got %v",
					plaintext,
				)
			}
		})
	}
}

func TestAESGCM_Decrypt_CorruptedCiphertext(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	encryptor, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	original := []byte("secret message")

	ciphertext, err := encryptor.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Modify the ciphertext without changing its length.
	ciphertext[len(ciphertext)-1] ^= 0xff

	plaintext, err := encryptor.Decrypt(ciphertext)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if plaintext != nil {
		t.Errorf("expected nil plaintext, got %v", plaintext)
	}

	// AES-GCM authentication must fail.
	if !bytes.Contains([]byte(err.Error()), []byte("decrypt data")) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAESGCM_Decrypt_ModifiedNonce(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	encryptor, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	original := []byte("secret message")

	ciphertext, err := encryptor.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Change the first byte of the nonce.
	ciphertext[0] ^= 0xff

	plaintext, err := encryptor.Decrypt(ciphertext)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if plaintext != nil {
		t.Errorf("expected nil plaintext, got %v", plaintext)
	}
}

func TestAESGCM_Encrypt_RandomNonce(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	encryptor, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	data := []byte("same message")

	ciphertext1, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}

	ciphertext2, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Fatal("encrypting the same data twice produced identical ciphertext")
	}
}

func TestAESGCM_Encrypt_DoesNotContainPlaintext(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	encryptor, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	data := []byte("this is a secret message")

	ciphertext, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if bytes.Contains(ciphertext, data) {
		t.Fatal("ciphertext contains plaintext")
	}
}

func TestAESGCM_Decrypt_WrongKey(t *testing.T) {
	key1 := []byte("01234567890123456789012345678901")
	key2 := []byte("12345678901234567890123456789012")

	encryptor1, err := NewAESGCM(key1)
	if err != nil {
		t.Fatalf("failed to create first encryptor: %v", err)
	}

	encryptor2, err := NewAESGCM(key2)
	if err != nil {
		t.Fatalf("failed to create second encryptor: %v", err)
	}

	data := []byte("secret message")

	ciphertext, err := encryptor1.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	plaintext, err := encryptor2.Decrypt(ciphertext)

	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}

	if plaintext != nil {
		t.Errorf("expected nil plaintext, got %v", plaintext)
	}
}
