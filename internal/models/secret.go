package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SecretType определяет тип хранимого секрета.
type SecretType string

const (
	SecretText   SecretType = "TEXT"
	SecretLogin  SecretType = "LOGIN_PASSWORD"
	SecretCard   SecretType = "BANK_CARD"
	SecretBinary SecretType = "BINARY_FILE"
)

// Secret содержит основные данные секрета,
// хранимого в системе.
//
// EncryptedData содержит зашифрованные данные секрета.
// Metadata содержит дополнительные метаданные в формате JSON.
type Secret struct {
	ID            uuid.UUID
	OwnerID       uuid.UUID
	Type          SecretType
	EncryptedData []byte
	Metadata      json.RawMessage
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// TextSecret содержит текстовое содержимое секрета.
type TextSecret struct {
	Text string `json:"text"`
}

// LoginPasswordSecret содержит логин и пароль.
type LoginPasswordSecret struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// CardSecret содержит данные банковской карты.
type CardSecret struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expire string `json:"expire"`
	CVV    string `json:"cvv"`
}

// BinarySecret содержит метаданные бинарного файла.
//
// Поле Data не сериализуется в JSON, поскольку содержимое файла
// хранится и передаётся отдельно через BinaryService.
type BinarySecret struct {
	Filename string `json:"filename"`
	MIMEType string `json:"mime_type"`
	Data     []byte `json:"-"`
}
