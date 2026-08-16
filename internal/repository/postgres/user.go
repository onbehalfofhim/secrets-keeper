package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

// UserRepository представляет репозиторий для работы с пользователями.
type UserRepository struct {
	db DB
}

// NewUsersRepository создает новый репозиторий пользователей.
func NewUsersRepository(db DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

// Create создание пользователя в БД.
func (r *UserRepository) Create(ctx context.Context, login, passwordHash string) (*models.User, error) {
	query := `INSERT INTO users (id, login, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, login, password_hash, created_at
	`

	row := r.db.QueryRow(ctx, query, uuid.New(), login, passwordHash)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.Login,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError

		// проверка, что полученная ошибка - ошибка уникальности логина
		// (=пользователь с таким логикном уже есть)
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return nil, repository.ErrUserExists
			}
		}
		return nil, err
	}

	return &user, nil
}

// GetByLogin поиск пользователя по логину.
func (r *UserRepository) GetByLogin(ctx context.Context, login string) (*models.User, error) {
	query := `SELECT 
			id, 
			login, 
			password_hash, 
			created_at
		FROM users
		WHERE login = $1
	`

	row := r.db.QueryRow(ctx, query, login)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.Login,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// GetByID поиск пользователя по id.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `SELECT 
			id, 
			login, 
			password_hash, 
			created_at
		FROM users
		WHERE id = $1
	`

	row := r.db.QueryRow(ctx, query, id)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.Login,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}
