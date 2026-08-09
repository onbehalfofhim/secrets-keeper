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

// Serializer определяет операции сериализации и десериализации
// структурированных данных секрета.
//
// Бинарные секреты не обрабатываются Serializer.
// Их содержимое хранится в виде []byte и шифруется напрямую.
type Serializer interface {
	Serialize(data any) ([]byte, error)
	Deserialize(secretType models.SecretType, data []byte) (any, error)
}

// JSONSerializer реализует Serializer с использованием encoding/json.
type JSONSerializer struct{}

// NewJSONSerializer создаёт новый JSON-сериализатор.
func NewJSONSerializer() *JSONSerializer {
	return &JSONSerializer{}
}

// Serialize сериализует структурированные данные секрета
// в формат JSON.
//
// Поддерживаются текстовые секреты, пары логин/пароль
// и данные банковской карты.
// BinarySecret не поддерживается: бинарные данные шифруются
// напрямую без преобразования в JSON или Base64.
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

// Deserialize десериализует JSON и преобразует его
// в структуру соответствующего типа секрета.
//
// Поддерживаются текстовые секреты, пары логин/пароль
// и данные банковской карты.
// BinarySecret не поддерживается, поскольку бинарные данные
// хранятся и обрабатываются отдельно как []byte.
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

// isSupportedData проверяет, относится ли переданное значение
// к одному из поддерживаемых структурированных типов секрета.
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
