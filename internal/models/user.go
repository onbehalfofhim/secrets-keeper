package models

import (
	"time"

	"github.com/google/uuid"
)

// User содержит данные пользователя.
type User struct {
	ID           uuid.UUID
	Login        string
	PasswordHash string
	CreatedAt    time.Time
}
