package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "valid password",
			password: "qwerty123",
		},
		{
			name:     "empty password",
			password: "",
		},
		{
			name:     "long password",
			password: "very-long-password-1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			hash, err := HashPassword(tt.password)

			assert.NoError(t, err)

			assert.NotEmpty(t, hash)

			// hash не должен совпадать
			// с оригинальным паролем
			assert.NotEqual(t, tt.password, hash)
		})
	}
}

func TestCheckPassword(t *testing.T) {
	password := "qwerty123"

	hash, err := HashPassword(password)
	assert.NoError(t, err)

	tests := []struct {
		name        string
		hash        string
		password    string
		expectedErr bool
	}{
		{
			name:        "valid password",
			hash:        hash,
			password:    password,
			expectedErr: false,
		},
		{
			name:        "invalid password",
			hash:        hash,
			password:    "wrong-password",
			expectedErr: true,
		},
		{
			name:        "empty password",
			hash:        hash,
			password:    "",
			expectedErr: true,
		},
		{
			name:        "invalid hash",
			hash:        "invalid-hash",
			password:    password,
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := CheckPassword(
				tt.hash,
				tt.password,
			)

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
