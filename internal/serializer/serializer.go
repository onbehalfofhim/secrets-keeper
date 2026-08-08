package serializer

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
)

var (
	ErrUnsupportedSecretType = errors.New("unsupported secret type")
	ErrInvalidSecretData     = errors.New("invalid secret data")
)

// Serializer is responsible for serialization and deserialization
// of structured secret data.
//
// Binary secrets are intentionally not handled by Serializer.
// Their data is kept as raw bytes and encrypted directly.
type Serializer interface {
	Serialize(data any) ([]byte, error)
	Deserialize(secretType models.SecretType, data []byte) (any, error)
}

// JSONSerializer implements Serializer using encoding/json.
type JSONSerializer struct{}

// NewJSONSerializer creates a new JSONSerializer.
func NewJSONSerializer() *JSONSerializer {
	return &JSONSerializer{}
}

// Serialize serializes a structured secret into JSON.
//
// BinarySecret is not supported here. Binary data should be encrypted
// directly without JSON/Base64 encoding.
func (s *JSONSerializer) Serialize(data any) ([]byte, error) {
	if !isSupportedData(data) {
		return nil, fmt.Errorf(
			"%w: %T",
			ErrInvalidSecretData,
			data,
		)
	}

	result, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("serialize secret: %w", err)
	}

	return result, nil
}

// Deserialize deserializes JSON into a concrete secret type.
//
// BinarySecret is not supported here. Binary data should be decrypted
// directly into []byte and handled separately.
func (s *JSONSerializer) Deserialize(secretType models.SecretType, data []byte) (any, error) {
	var result any

	switch secretType {
	case models.SecretText:
		result = &models.TextSecret{}

	case models.SecretLogin:
		result = &models.LoginPasswordSecret{}

	case models.SecretCard:
		result = &models.CardSecret{}

	case models.SecretBinary:
		return nil, fmt.Errorf(
			"%w: binary secrets are not serialized as JSON",
			ErrUnsupportedSecretType,
		)

	default:
		return nil, fmt.Errorf(
			"%w: %q",
			ErrUnsupportedSecretType,
			secretType,
		)
	}

	if err := json.Unmarshal(data, result); err != nil {
		return nil, fmt.Errorf("deserialize secret: %w", err)
	}

	return result, nil
}

// isSupportedData checks whether the provided value is a supported
// structured secret type.
func isSupportedData(data any) bool {
	switch data.(type) {
	case *models.TextSecret,
		*models.LoginPasswordSecret,
		*models.CardSecret:
		return true

	default:
		return false
	}
}
