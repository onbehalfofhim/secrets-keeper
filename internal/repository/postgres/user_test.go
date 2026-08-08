package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

func setupUserRepository(t *testing.T) (*UserRepository, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	repo := NewUsersRepository(db)

	cleanup := func() {
		db.Close()
	}

	return repo, mock, cleanup
}

func TestNewUsersRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUsersRepository(db)

	if repo == nil {
		t.Fatal("expected repository, got nil")
	}

	if repo.db != db {
		t.Error("repository contains unexpected database")
	}
}

func TestUserRepository_Create(t *testing.T) {
	ctx := context.Background()
	createdAt := time.Now()
	userID := uuid.New()

	tests := []struct {
		name         string
		login        string
		passwordHash string
		mock         func(sqlmock.Sqlmock)
		want         *models.User
		wantErr      error
	}{
		{
			name:         "success",
			login:        "test-user",
			passwordHash: "hashed-password",
			mock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows(
					[]string{"id", "login", "password_hash", "created_at"},
				).AddRow(
					userID,
					"test-user",
					"hashed-password",
					createdAt,
				)

				mock.ExpectQuery(regexp.QuoteMeta(`
					INSERT INTO users (id, login, password_hash)
					VALUES ($1, $2, $3)
					RETURNING id, login, password_hash, created_at
				`)).
					WithArgs(sqlmock.AnyArg(), "test-user", "hashed-password").
					WillReturnRows(rows)
			},
			want: &models.User{
				ID:           userID,
				Login:        "test-user",
				PasswordHash: "hashed-password",
				CreatedAt:    createdAt,
			},
		},
		{
			name:         "user already exists",
			login:        "existing-user",
			passwordHash: "hashed-password",
			mock: func(mock sqlmock.Sqlmock) {
				pgErr := &pgconn.PgError{
					Code: "23505",
				}

				mock.ExpectQuery(regexp.QuoteMeta(`
					INSERT INTO users (id, login, password_hash)
					VALUES ($1, $2, $3)
					RETURNING id, login, password_hash, created_at
				`)).
					WithArgs(sqlmock.AnyArg(), "existing-user", "hashed-password").
					WillReturnError(pgErr)
			},
			wantErr: repository.ErrUserExists,
		},
		{
			name:         "database error",
			login:        "test-user",
			passwordHash: "hashed-password",
			mock: func(mock sqlmock.Sqlmock) {
				dbErr := errors.New("database connection failed")

				mock.ExpectQuery(regexp.QuoteMeta(`
					INSERT INTO users (id, login, password_hash)
					VALUES ($1, $2, $3)
					RETURNING id, login, password_hash, created_at
				`)).
					WithArgs(sqlmock.AnyArg(), "test-user", "hashed-password").
					WillReturnError(dbErr)
			},
			wantErr: errors.New("database connection failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupUserRepository(t)
			defer cleanup()

			tt.mock(mock)

			got, err := repo.Create(ctx, tt.login, tt.passwordHash)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErr == repository.ErrUserExists {
					if !errors.Is(err, repository.ErrUserExists) {
						t.Errorf(
							"expected ErrUserExists, got %v",
							err,
						)
					}
				} else if err.Error() != tt.wantErr.Error() {
					t.Errorf(
						"expected error %q, got %q",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf("expected nil user, got %+v", got)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got == nil {
					t.Fatal("expected user, got nil")
				}

				if got.ID != tt.want.ID {
					t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
				}

				if got.Login != tt.want.Login {
					t.Errorf("Login = %q, want %q", got.Login, tt.want.Login)
				}

				if got.PasswordHash != tt.want.PasswordHash {
					t.Errorf(
						"PasswordHash = %q, want %q",
						got.PasswordHash,
						tt.want.PasswordHash,
					)
				}

				if !got.CreatedAt.Equal(tt.want.CreatedAt) {
					t.Errorf(
						"CreatedAt = %v, want %v",
						got.CreatedAt,
						tt.want.CreatedAt,
					)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestUserRepository_Create_OtherPostgresError(t *testing.T) {
	repo, mock, cleanup := setupUserRepository(t)
	defer cleanup()

	pgErr := &pgconn.PgError{
		Code: "23503",
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
		INSERT INTO users (id, login, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, login, password_hash, created_at
	`)).
		WithArgs(sqlmock.AnyArg(), "test-user", "hashed-password").
		WillReturnError(pgErr)

	got, err := repo.Create(
		context.Background(),
		"test-user",
		"hashed-password",
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, pgErr) {
		t.Errorf("expected original postgres error, got %v", err)
	}

	if got != nil {
		t.Errorf("expected nil user, got %+v", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestUserRepository_GetByLogin(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	createdAt := time.Now()

	tests := []struct {
		name    string
		login   string
		mock    func(sqlmock.Sqlmock)
		want    *models.User
		wantErr error
	}{
		{
			name:  "success",
			login: "test-user",
			mock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows(
					[]string{"id", "login", "password_hash", "created_at"},
				).AddRow(
					userID,
					"test-user",
					"hashed-password",
					createdAt,
				)

				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT 
						id, 
						login, 
						password_hash, 
						created_at
					FROM users
					WHERE login = $1
				`)).
					WithArgs("test-user").
					WillReturnRows(rows)
			},
			want: &models.User{
				ID:           userID,
				Login:        "test-user",
				PasswordHash: "hashed-password",
				CreatedAt:    createdAt,
			},
		},
		{
			name:  "user not found",
			login: "unknown-user",
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT 
						id, 
						login, 
						password_hash, 
						created_at
					FROM users
					WHERE login = $1
				`)).
					WithArgs("unknown-user").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: repository.ErrUserNotFound,
		},
		{
			name:  "database error",
			login: "test-user",
			mock: func(mock sqlmock.Sqlmock) {
				dbErr := errors.New("database error")

				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT 
						id, 
						login, 
						password_hash, 
						created_at
					FROM users
					WHERE login = $1
				`)).
					WithArgs("test-user").
					WillReturnError(dbErr)
			},
			wantErr: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupUserRepository(t)
			defer cleanup()

			tt.mock(mock)

			got, err := repo.GetByLogin(ctx, tt.login)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErr == repository.ErrUserNotFound {
					if !errors.Is(err, repository.ErrUserNotFound) {
						t.Errorf(
							"expected %v, got %v",
							tt.wantErr,
							err,
						)
					}
				} else if err.Error() != tt.wantErr.Error() {
					t.Errorf(
						"expected error %q, got %q",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf("expected nil user, got %+v", got)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if got == nil {
					t.Fatal("expected user, got nil")
				}

				if got.ID != tt.want.ID {
					t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
				}

				if got.Login != tt.want.Login {
					t.Errorf("Login = %q, want %q", got.Login, tt.want.Login)
				}

				if got.PasswordHash != tt.want.PasswordHash {
					t.Errorf(
						"PasswordHash = %q, want %q",
						got.PasswordHash,
						tt.want.PasswordHash,
					)
				}

				if !got.CreatedAt.Equal(tt.want.CreatedAt) {
					t.Errorf(
						"CreatedAt = %v, want %v",
						got.CreatedAt,
						tt.want.CreatedAt,
					)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestUserRepository_GetByID(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	createdAt := time.Now()

	tests := []struct {
		name string
		id   uuid.UUID
		mock func(sqlmock.Sqlmock)
		want *models.User
		err  error
	}{
		{
			name: "success",
			id:   userID,
			mock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows(
					[]string{"id", "login", "password_hash", "created_at"},
				).AddRow(
					userID,
					"test-user",
					"hashed-password",
					createdAt,
				)

				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT 
						id, 
						login, 
						password_hash, 
						created_at
					FROM users
					WHERE id = $1
				`)).
					WithArgs(userID).
					WillReturnRows(rows)
			},
			want: &models.User{
				ID:           userID,
				Login:        "test-user",
				PasswordHash: "hashed-password",
				CreatedAt:    createdAt,
			},
		},
		{
			name: "user not found",
			id:   userID,
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT 
						id, 
						login, 
						password_hash, 
						created_at
					FROM users
					WHERE id = $1
				`)).
					WithArgs(userID).
					WillReturnError(sql.ErrNoRows)
			},
			err: repository.ErrUserNotFound,
		},
		{
			name: "database error",
			id:   userID,
			mock: func(mock sqlmock.Sqlmock) {
				dbErr := errors.New("database error")

				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT 
						id, 
						login, 
						password_hash, 
						created_at
					FROM users
					WHERE id = $1
				`)).
					WithArgs(userID).
					WillReturnError(dbErr)
			},
			err: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupUserRepository(t)
			defer cleanup()

			tt.mock(mock)

			got, err := repo.GetByID(ctx, tt.id)

			if tt.err != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.err == repository.ErrUserNotFound {
					if !errors.Is(err, repository.ErrUserNotFound) {
						t.Errorf(
							"expected ErrUserNotFound, got %v",
							err,
						)
					}
				} else if err.Error() != tt.err.Error() {
					t.Errorf(
						"expected error %q, got %q",
						tt.err,
						err,
					)
				}

				if got != nil {
					t.Errorf("expected nil user, got %+v", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got == nil {
				t.Fatal("expected user, got nil")
			}

			if got.ID != tt.want.ID {
				t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
			}

			if got.Login != tt.want.Login {
				t.Errorf("Login = %q, want %q", got.Login, tt.want.Login)
			}

			if got.PasswordHash != tt.want.PasswordHash {
				t.Errorf(
					"PasswordHash = %q, want %q",
					got.PasswordHash,
					tt.want.PasswordHash,
				)
			}

			if !got.CreatedAt.Equal(tt.want.CreatedAt) {
				t.Errorf(
					"CreatedAt = %v, want %v",
					got.CreatedAt,
					tt.want.CreatedAt,
				)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}
