package models

import (
	"time"

	"github.com/google/uuid"
)

// Модель пользователя приложения
type User struct {
	ID           uuid.UUID
	Login        string
	PasswordHash string
	CreatedAt    time.Time
}
