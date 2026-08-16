package postgres

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v5"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

func setupUserRepository(t *testing.T) (*UserRepository, pgxmock.PgxPoolIface, func()) {
	t.Helper()

	db, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}

	repo := NewUsersRepository(db)

	cleanup := func() {
		db.Close()
	}

	return repo, db, cleanup
}

func TestNewUsersRepository(t *testing.T) {
	db, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
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

	dbErr := errors.New("database connection failed")

	tests := []struct {
		name         string
		login        string
		passwordHash string
		mock         func(pgxmock.PgxPoolIface)
		want         *models.User
		wantErr      error
	}{
		{
			name:         "success",
			login:        "test-user",
			passwordHash: "hashed-password",
			mock: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{
					"id",
					"login",
					"password_hash",
					"created_at",
				}).AddRow(
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
					WithArgs(
						pgxmock.AnyArg(),
						"test-user",
						"hashed-password",
					).
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
			mock: func(mock pgxmock.PgxPoolIface) {
				pgErr := &pgconn.PgError{
					Code: "23505",
				}

				mock.ExpectQuery(regexp.QuoteMeta(`
					INSERT INTO users (id, login, password_hash)
					VALUES ($1, $2, $3)
					RETURNING id, login, password_hash, created_at
				`)).
					WithArgs(
						pgxmock.AnyArg(),
						"existing-user",
						"hashed-password",
					).
					WillReturnError(pgErr)
			},
			wantErr: repository.ErrUserExists,
		},
		{
			name:         "database error",
			login:        "test-user",
			passwordHash: "hashed-password",
			mock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(regexp.QuoteMeta(`
					INSERT INTO users (id, login, password_hash)
					VALUES ($1, $2, $3)
					RETURNING id, login, password_hash, created_at
				`)).
					WithArgs(
						pgxmock.AnyArg(),
						"test-user",
						"hashed-password",
					).
					WillReturnError(dbErr)
			},
			wantErr: dbErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupUserRepository(t)
			defer cleanup()

			tt.mock(mock)

			got, err := repo.Create(
				ctx,
				tt.login,
				tt.passwordHash,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error wrapping %v, got %v",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf(
						"expected nil user, got %+v",
						got,
					)
				}
			} else {
				if err != nil {
					t.Fatalf(
						"unexpected error: %v",
						err,
					)
				}

				assertUserEqual(t, got, tt.want)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet SQL expectations: %v",
					err,
				)
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
		WithArgs(
			pgxmock.AnyArg(),
			"test-user",
			"hashed-password",
		).
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
		t.Errorf(
			"expected original postgres error, got %v",
			err,
		)
	}

	if got != nil {
		t.Errorf(
			"expected nil user, got %+v",
			got,
		)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf(
			"unmet SQL expectations: %v",
			err,
		)
	}
}

func TestUserRepository_GetByLogin(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	createdAt := time.Now()

	dbErr := errors.New("database error")

	tests := []struct {
		name    string
		login   string
		mock    func(pgxmock.PgxPoolIface)
		want    *models.User
		wantErr error
	}{
		{
			name:  "success",
			login: "test-user",
			mock: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{
					"id",
					"login",
					"password_hash",
					"created_at",
				}).AddRow(
					userID,
					"test-user",
					"hashed-password",
					createdAt,
				)

				mock.ExpectQuery(
					`SELECT
						id,
						login,
						password_hash,
						created_at
					 FROM users
					 WHERE login = \$1`,
				).
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
			mock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(
					`SELECT
						id,
						login,
						password_hash,
						created_at
					 FROM users
					 WHERE login = \$1`,
				).
					WithArgs("unknown-user").
					WillReturnError(pgx.ErrNoRows)
			},
			wantErr: repository.ErrUserNotFound,
		},
		{
			name:  "database error",
			login: "test-user",
			mock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(
					`SELECT
						id,
						login,
						password_hash,
						created_at
					 FROM users
					 WHERE login = \$1`,
				).
					WithArgs("test-user").
					WillReturnError(dbErr)
			},
			wantErr: dbErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupUserRepository(t)
			defer cleanup()

			tt.mock(mock)

			got, err := repo.GetByLogin(
				ctx,
				tt.login,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error wrapping %v, got %v",
						tt.wantErr,
						err,
					)
				}

				if got != nil {
					t.Errorf(
						"expected nil user, got %+v",
						got,
					)
				}
			} else {
				if err != nil {
					t.Fatalf(
						"unexpected error: %v",
						err,
					)
				}

				assertUserEqual(t, got, tt.want)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet SQL expectations: %v",
					err,
				)
			}
		})
	}
}

func TestUserRepository_GetByID(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	createdAt := time.Now()

	dbErr := errors.New("database error")

	tests := []struct {
		name string
		id   uuid.UUID
		mock func(pgxmock.PgxPoolIface)
		want *models.User
		err  error
	}{
		{
			name: "success",
			id:   userID,
			mock: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{
					"id",
					"login",
					"password_hash",
					"created_at",
				}).AddRow(
					userID,
					"test-user",
					"hashed-password",
					createdAt,
				)

				mock.ExpectQuery(
					`SELECT
						id,
						login,
						password_hash,
						created_at
					 FROM users
					 WHERE id = \$1`,
				).
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
			mock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(
					`SELECT
						id,
						login,
						password_hash,
						created_at
					 FROM users
					 WHERE id = \$1`,
				).
					WithArgs(userID).
					WillReturnError(pgx.ErrNoRows)
			},
			err: repository.ErrUserNotFound,
		},
		{
			name: "database error",
			id:   userID,
			mock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(
					`SELECT
						id,
						login,
						password_hash,
						created_at
					 FROM users
					 WHERE id = \$1`,
				).
					WithArgs(userID).
					WillReturnError(dbErr)
			},
			err: dbErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupUserRepository(t)
			defer cleanup()

			tt.mock(mock)

			got, err := repo.GetByID(
				ctx,
				tt.id,
			)

			if tt.err != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tt.err) {
					t.Errorf(
						"expected error wrapping %v, got %v",
						tt.err,
						err,
					)
				}

				if got != nil {
					t.Errorf(
						"expected nil user, got %+v",
						got,
					)
				}

				if err := mock.ExpectationsWereMet(); err != nil {
					t.Errorf(
						"unmet SQL expectations: %v",
						err,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf(
					"unexpected error: %v",
					err,
				)
			}

			assertUserEqual(t, got, tt.want)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet SQL expectations: %v",
					err,
				)
			}
		})
	}
}

func assertUserEqual(t *testing.T, got, want *models.User) {
	t.Helper()

	if got == nil {
		t.Fatal("expected user, got nil")
	}

	if want == nil {
		t.Fatal("expected expected user, got nil")
	}

	if got.ID != want.ID {
		t.Errorf(
			"ID = %v, want %v",
			got.ID,
			want.ID,
		)
	}

	if got.Login != want.Login {
		t.Errorf(
			"Login = %q, want %q",
			got.Login,
			want.Login,
		)
	}

	if got.PasswordHash != want.PasswordHash {
		t.Errorf(
			"PasswordHash = %q, want %q",
			got.PasswordHash,
			want.PasswordHash,
		)
	}

	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf(
			"CreatedAt = %v, want %v",
			got.CreatedAt,
			want.CreatedAt,
		)
	}
}