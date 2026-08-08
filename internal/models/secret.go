package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type SecretType string

const (
	SecretText   SecretType = "TEXT"
	SecretLogin  SecretType = "LOGIN_PASSWORD"
	SecretCard   SecretType = "BANK_CARD"
	SecretBinary SecretType = "BINARY_FILE"
)

type Secret struct {
	ID            uuid.UUID
	OwnerID       uuid.UUID
	Type          SecretType
	EncryptedData []byte
	Metadata      json.RawMessage
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type TextSecret struct {
	Text string `json:"text"`
}

type LoginPasswordSecret struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type CardSecret struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expire string `json:"expire"`
	CVV    string `json:"cvv"`
}

type BinarySecret struct {
	Filename string `json:"filename"`
	MIMEType string `json:"mime_type"`
	Data     []byte `json:"-"`
}
