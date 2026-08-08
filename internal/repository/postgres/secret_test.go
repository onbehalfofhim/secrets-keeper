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

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

func setupSecretRepository(t *testing.T) (*SecretRepository, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	repo := NewSecretRepository(db)

	cleanup := func() {
		db.Close()
	}

	return repo, mock, cleanup
}

func TestNewSecretRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewSecretRepository(db)

	if repo == nil {
		t.Fatal("expected repository, got nil")
	}

	if repo.db != db {
		t.Error("repository contains unexpected database")
	}
}

func TestSecretRepository_Create(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New(): %v", err)
	}
	defer db.Close()

	repo := NewSecretRepository(db)

	ownerID := uuid.New()

	secret := &models.Secret{
		OwnerID:       ownerID,
		Type:          models.SecretText,
		EncryptedData: []byte("encrypted"),
		Metadata:      nil,
	}

	createdID := uuid.New()
	createdAt := time.Now()
	updatedAt := createdAt

	rows := sqlmock.NewRows([]string{
		"id",
		"owner_id",
		"type",
		"encrypted_data",
		"metadata",
		"created_at",
		"updated_at",
	}).AddRow(
		createdID,
		ownerID,
		models.SecretText,
		[]byte("encrypted"),
		[]byte(`{}`),
		createdAt,
		updatedAt,
	)

	mock.ExpectQuery(regexp.QuoteMeta(`
		INSERT INTO secrets (
			id,
			owner_id,
			type,
			encrypted_data,
			metadata
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING
			id,
			owner_id,
			type,
			encrypted_data,
			metadata,
			created_at,
			updated_at
	`)).
		WithArgs(
			sqlmock.AnyArg(),
			ownerID,
			models.SecretText,
			[]byte("encrypted"),
			[]byte(`{}`),
		).
		WillReturnRows(rows)

	result, err := repo.Create(
		context.Background(),
		secret,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID == uuid.Nil {
		t.Fatal("expected generated ID, got nil UUID")
	}

	if result.ID != createdID {
		t.Errorf(
			"ID = %v, want %v",
			result.ID,
			createdID,
		)
	}

	if string(secret.Metadata) != `{}` {
		t.Errorf(
			"metadata = %s, want {}",
			secret.Metadata,
		)
	}

	if string(result.Metadata) != `{}` {
		t.Errorf(
			"result metadata = %s, want {}",
			result.Metadata,
		)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSecretRepository_Create_Error(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	secret := &models.Secret{
		ID:            uuid.New(),
		OwnerID:       uuid.New(),
		Type:          "password",
		EncryptedData: []byte("encrypted"),
		Metadata:      []byte(`{}`),
	}

	dbErr := errors.New("database error")

	mock.ExpectQuery(regexp.QuoteMeta(`
		INSERT INTO secrets (
			id,
			owner_id,
			type,
			encrypted_data,
			metadata
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING
			id,
			owner_id,
			type,
			encrypted_data,
			metadata,
			created_at,
			updated_at
	`)).
		WithArgs(
			secret.ID,
			secret.OwnerID,
			secret.Type,
			secret.EncryptedData,
			secret.Metadata,
		).
		WillReturnError(dbErr)

	got, err := repo.Create(context.Background(), secret)

	if !errors.Is(err, dbErr) {
		t.Errorf("expected %v, got %v", dbErr, err)
	}

	if got != nil {
		t.Errorf("expected nil secret, got %+v", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestSecretRepository_GetByID(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()
	createdAt := time.Now()
	updatedAt := createdAt.Add(time.Hour)

	tests := []struct {
		name    string
		mock    func(sqlmock.Sqlmock)
		want    *models.Secret
		wantErr error
	}{
		{
			name: "success",
			mock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id",
					"owner_id",
					"type",
					"encrypted_data",
					"metadata",
					"created_at",
					"updated_at",
				}).AddRow(
					secretID,
					ownerID,
					"password",
					[]byte("encrypted"),
					[]byte(`{"name":"test"}`),
					createdAt,
					updatedAt,
				)

				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT
						id,
						owner_id,
						type,
						encrypted_data,
						metadata,
						created_at,
						updated_at
					FROM secrets
					WHERE id = $1
					  AND owner_id = $2
				`)).
					WithArgs(secretID, ownerID).
					WillReturnRows(rows)
			},
			want: &models.Secret{
				ID:            secretID,
				OwnerID:       ownerID,
				Type:          "password",
				EncryptedData: []byte("encrypted"),
				Metadata:      []byte(`{"name":"test"}`),
				CreatedAt:     createdAt,
				UpdatedAt:     updatedAt,
			},
		},
		{
			name: "not found",
			mock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT
						id,
						owner_id,
						type,
						encrypted_data,
						metadata,
						created_at,
						updated_at
					FROM secrets
					WHERE id = $1
					  AND owner_id = $2
				`)).
					WithArgs(secretID, ownerID).
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name: "database error",
			mock: func(mock sqlmock.Sqlmock) {
				dbErr := errors.New("database error")

				mock.ExpectQuery(regexp.QuoteMeta(`
					SELECT
						id,
						owner_id,
						type,
						encrypted_data,
						metadata,
						created_at,
						updated_at
					FROM secrets
					WHERE id = $1
					  AND owner_id = $2
				`)).
					WithArgs(secretID, ownerID).
					WillReturnError(dbErr)
			},
			wantErr: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupSecretRepository(t)
			defer cleanup()

			tt.mock(mock)

			got, err := repo.GetByID(ctx, ownerID, secretID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErr == repository.ErrSecretNotFound {
					if !errors.Is(err, repository.ErrSecretNotFound) {
						t.Errorf(
							"expected ErrSecretNotFound, got %v",
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
					t.Errorf("expected nil secret, got %+v", got)
				}
			} else {
				assertSecretEqual(t, got, tt.want)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestSecretRepository_List(t *testing.T) {
	ctx := context.Background()
	ownerID := uuid.New()

	secret1 := models.Secret{
		ID:            uuid.New(),
		OwnerID:       ownerID,
		Type:          "password",
		EncryptedData: []byte("encrypted-1"),
		Metadata:      []byte(`{"name":"first"}`),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	secret2 := models.Secret{
		ID:            uuid.New(),
		OwnerID:       ownerID,
		Type:          "login",
		EncryptedData: []byte("encrypted-2"),
		Metadata:      []byte(`{"name":"second"}`),
		CreatedAt:     secret1.CreatedAt.Add(-time.Hour),
		UpdatedAt:     time.Now(),
	}

	tests := []struct {
		name    string
		rows    *sqlmock.Rows
		want    []*models.Secret
		wantErr bool
	}{
		{
			name: "multiple secrets",
			rows: sqlmock.NewRows([]string{
				"id",
				"owner_id",
				"type",
				"encrypted_data",
				"metadata",
				"created_at",
				"updated_at",
			}).
				AddRow(
					secret1.ID,
					secret1.OwnerID,
					secret1.Type,
					secret1.EncryptedData,
					secret1.Metadata,
					secret1.CreatedAt,
					secret1.UpdatedAt,
				).
				AddRow(
					secret2.ID,
					secret2.OwnerID,
					secret2.Type,
					secret2.EncryptedData,
					secret2.Metadata,
					secret2.CreatedAt,
					secret2.UpdatedAt,
				),
			want: []*models.Secret{
				&secret1,
				&secret2,
			},
		},
		{
			name: "empty result",
			rows: sqlmock.NewRows([]string{
				"id",
				"owner_id",
				"type",
				"encrypted_data",
				"metadata",
				"created_at",
				"updated_at",
			}),
			want: []*models.Secret{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupSecretRepository(t)
			defer cleanup()

			mock.ExpectQuery(regexp.QuoteMeta(`
				SELECT
					id,
					owner_id,
					type,
					encrypted_data,
					metadata,
					created_at,
					updated_at
				FROM secrets
				WHERE owner_id = $1
				ORDER BY created_at DESC
			`)).
				WithArgs(ownerID).
				WillReturnRows(tt.rows)

			got, err := repo.List(ctx, ownerID)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("List() error = %v", err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf(
					"got %d secrets, want %d",
					len(got),
					len(tt.want),
				)
			}

			for i := range tt.want {
				assertSecretEqual(t, got[i], tt.want[i])
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestSecretRepository_List_QueryError(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()
	dbErr := errors.New("database error")

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT
			id,
			owner_id,
			type,
			encrypted_data,
			metadata,
			created_at,
			updated_at
		FROM secrets
		WHERE owner_id = $1
		ORDER BY created_at DESC
	`)).
		WithArgs(ownerID).
		WillReturnError(dbErr)

	got, err := repo.List(context.Background(), ownerID)

	if !errors.Is(err, dbErr) {
		t.Errorf("expected %v, got %v", dbErr, err)
	}

	if got != nil {
		t.Errorf("expected nil result, got %+v", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestSecretRepository_List_ScanError(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()

	rows := sqlmock.NewRows([]string{
		"id",
		"owner_id",
		"type",
		"encrypted_data",
		"metadata",
		"created_at",
		"updated_at",
	}).AddRow(
		"not-a-uuid",
		ownerID,
		"password",
		[]byte("encrypted"),
		[]byte(`{}`),
		time.Now(),
		time.Now(),
	)

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT
			id,
			owner_id,
			type,
			encrypted_data,
			metadata,
			created_at,
			updated_at
		FROM secrets
		WHERE owner_id = $1
		ORDER BY created_at DESC
	`)).
		WithArgs(ownerID).
		WillReturnRows(rows)

	got, err := repo.List(context.Background(), ownerID)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got != nil {
		t.Errorf("expected nil result, got %+v", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestSecretRepository_List_RowsError(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()
	rowsErr := errors.New("rows error")

	rows := sqlmock.NewRows([]string{
		"id",
		"owner_id",
		"type",
		"encrypted_data",
		"metadata",
		"created_at",
		"updated_at",
	}).
		AddRow(
			uuid.New(),
			ownerID,
			"password",
			[]byte("encrypted"),
			[]byte(`{}`),
			time.Now(),
			time.Now(),
		).
		RowError(0, rowsErr)

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT
			id,
			owner_id,
			type,
			encrypted_data,
			metadata,
			created_at,
			updated_at
		FROM secrets
		WHERE owner_id = $1
		ORDER BY created_at DESC
	`)).
		WithArgs(ownerID).
		WillReturnRows(rows)

	got, err := repo.List(context.Background(), ownerID)

	if !errors.Is(err, rowsErr) {
		t.Errorf("expected %v, got %v", rowsErr, err)
	}

	if got != nil {
		t.Errorf("expected nil result, got %+v", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestSecretRepository_Update(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()
	createdAt := time.Now()
	updatedAt := createdAt.Add(time.Hour)

	tests := []struct {
		name     string
		secret   *models.Secret
		mockRows func(sqlmock.Sqlmock, *models.Secret)
		want     *models.Secret
		wantErr  error
	}{
		{
			name: "success",
			secret: &models.Secret{
				ID:            secretID,
				OwnerID:       ownerID,
				Type:          "password",
				EncryptedData: []byte("encrypted"),
				Metadata:      []byte(`{"name":"test"}`),
			},
			mockRows: func(mock sqlmock.Sqlmock, secret *models.Secret) {
				rows := sqlmock.NewRows([]string{
					"id",
					"owner_id",
					"type",
					"encrypted_data",
					"metadata",
					"created_at",
					"updated_at",
				}).AddRow(
					secret.ID,
					secret.OwnerID,
					secret.Type,
					secret.EncryptedData,
					secret.Metadata,
					createdAt,
					updatedAt,
				)

				mock.ExpectQuery(regexp.QuoteMeta(`
					UPDATE secrets
					SET
						type = $1,
						encrypted_data = $2,
						metadata = $3,
						updated_at = NOW()
					WHERE id = $4
					  AND owner_id = $5
					RETURNING
						id,
						owner_id,
						type,
						encrypted_data,
						metadata,
						created_at,
						updated_at
				`)).
					WithArgs(
						secret.Type,
						secret.EncryptedData,
						secret.Metadata,
						secret.ID,
						secret.OwnerID,
					).
					WillReturnRows(rows)
			},
			want: &models.Secret{
				ID:            secretID,
				OwnerID:       ownerID,
				Type:          "password",
				EncryptedData: []byte("encrypted"),
				Metadata:      []byte(`{"name":"test"}`),
				CreatedAt:     createdAt,
				UpdatedAt:     updatedAt,
			},
		},
		{
			name: "nil metadata is replaced with empty JSON object",
			secret: &models.Secret{
				ID:            secretID,
				OwnerID:       ownerID,
				Type:          "login",
				EncryptedData: []byte("encrypted"),
				Metadata:      nil,
			},
			mockRows: func(mock sqlmock.Sqlmock, secret *models.Secret) {
				rows := sqlmock.NewRows([]string{
					"id",
					"owner_id",
					"type",
					"encrypted_data",
					"metadata",
					"created_at",
					"updated_at",
				}).AddRow(
					secret.ID,
					secret.OwnerID,
					secret.Type,
					secret.EncryptedData,
					[]byte(`{}`),
					createdAt,
					updatedAt,
				)

				mock.ExpectQuery(regexp.QuoteMeta(`
					UPDATE secrets
					SET
						type = $1,
						encrypted_data = $2,
						metadata = $3,
						updated_at = NOW()
					WHERE id = $4
					  AND owner_id = $5
					RETURNING
						id,
						owner_id,
						type,
						encrypted_data,
						metadata,
						created_at,
						updated_at
				`)).
					WithArgs(
						secret.Type,
						secret.EncryptedData,
						[]byte(`{}`),
						secret.ID,
						secret.OwnerID,
					).
					WillReturnRows(rows)
			},
			want: &models.Secret{
				ID:            secretID,
				OwnerID:       ownerID,
				Type:          "login",
				EncryptedData: []byte("encrypted"),
				Metadata:      []byte(`{}`),
				CreatedAt:     createdAt,
				UpdatedAt:     updatedAt,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupSecretRepository(t)
			defer cleanup()

			tt.mockRows(mock, tt.secret)

			got, err := repo.Update(ctx, tt.secret)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Update() error = %v", err)
			}

			assertSecretEqual(t, got, tt.want)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestSecretRepository_Update_NotFound(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	secret := &models.Secret{
		ID:            uuid.New(),
		OwnerID:       uuid.New(),
		Type:          "password",
		EncryptedData: []byte("encrypted"),
		Metadata:      []byte(`{}`),
	}

	mock.ExpectQuery(regexp.QuoteMeta(`
		UPDATE secrets
		SET
			type = $1,
			encrypted_data = $2,
			metadata = $3,
			updated_at = NOW()
		WHERE id = $4
		  AND owner_id = $5
		RETURNING
			id,
			owner_id,
			type,
			encrypted_data,
			metadata,
			created_at,
			updated_at
	`)).
		WithArgs(
			secret.Type,
			secret.EncryptedData,
			secret.Metadata,
			secret.ID,
			secret.OwnerID,
		).
		WillReturnError(sql.ErrNoRows)

	got, err := repo.Update(context.Background(), secret)

	if !errors.Is(err, repository.ErrSecretNotFound) {
		t.Errorf(
			"expected ErrSecretNotFound, got %v",
			err,
		)
	}

	if got != nil {
		t.Errorf("expected nil secret, got %+v", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestSecretRepository_Update_DatabaseError(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	secret := &models.Secret{
		ID:            uuid.New(),
		OwnerID:       uuid.New(),
		Type:          "password",
		EncryptedData: []byte("encrypted"),
		Metadata:      []byte(`{}`),
	}

	dbErr := errors.New("database error")

	mock.ExpectQuery(regexp.QuoteMeta(`
		UPDATE secrets
		SET
			type = $1,
			encrypted_data = $2,
			metadata = $3,
			updated_at = NOW()
		WHERE id = $4
		  AND owner_id = $5
		RETURNING
			id,
			owner_id,
			type,
			encrypted_data,
			metadata,
			created_at,
			updated_at
	`)).
		WithArgs(
			secret.Type,
			secret.EncryptedData,
			secret.Metadata,
			secret.ID,
			secret.OwnerID,
		).
		WillReturnError(dbErr)

	got, err := repo.Update(context.Background(), secret)

	if !errors.Is(err, dbErr) {
		t.Errorf("expected %v, got %v", dbErr, err)
	}

	if got != nil {
		t.Errorf("expected nil secret, got %+v", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestSecretRepository_Delete(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()

	tests := []struct {
		name       string
		result     sql.Result
		queryError error
		wantErr    error
	}{
		{
			name:   "success",
			result: sqlmock.NewResult(0, 1),
		},
		{
			name:    "secret not found",
			result:  sqlmock.NewResult(0, 0),
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:       "database error",
			queryError: errors.New("database error"),
			wantErr:    errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupSecretRepository(t)
			defer cleanup()

			mock.ExpectExec(regexp.QuoteMeta(`
				DELETE FROM secrets
				WHERE id = $1
				  AND owner_id = $2
			`)).
				WithArgs(secretID, ownerID)

			expect := mock.ExpectationsWereMet

			// Reconfigure expectation with result/error.
			// sqlmock does not allow modifying an existing expectation,
			// so recreate the repository/mock for this case.
			_ = expect

			// The expectation above is replaced by using a fresh mock.
			cleanup()

			repo, mock, cleanup = setupSecretRepository(t)
			defer cleanup()

			expectation := mock.ExpectExec(regexp.QuoteMeta(`
				DELETE FROM secrets
				WHERE id = $1
				  AND owner_id = $2
			`)).
				WithArgs(secretID, ownerID)

			if tt.queryError != nil {
				expectation.WillReturnError(tt.queryError)
			} else {
				expectation.WillReturnResult(tt.result)
			}

			err := repo.Delete(ctx, ownerID, secretID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErr == repository.ErrSecretNotFound {
					if !errors.Is(err, repository.ErrSecretNotFound) {
						t.Errorf(
							"expected ErrSecretNotFound, got %v",
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
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestSecretRepository_Delete_RowsAffectedError(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()
	secretID := uuid.New()

	result := sqlmock.NewErrorResult(errors.New("rows affected error"))

	mock.ExpectExec(regexp.QuoteMeta(`
		DELETE FROM secrets
		WHERE id = $1
		  AND owner_id = $2
	`)).
		WithArgs(secretID, ownerID).
		WillReturnResult(result)

	err := repo.Delete(context.Background(), ownerID, secretID)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "rows affected error" {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func TestSecretRepository_UpdateEncryptedData(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()
	encryptedData := []byte("new encrypted data")

	tests := []struct {
		name       string
		result     sql.Result
		queryError error
		wantErr    error
	}{
		{
			name:   "success",
			result: sqlmock.NewResult(0, 1),
		},
		{
			name:    "secret not found",
			result:  sqlmock.NewResult(0, 0),
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:       "database error",
			queryError: errors.New("database error"),
			wantErr:    errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupSecretRepository(t)
			defer cleanup()

			expectation := mock.ExpectExec(regexp.QuoteMeta(`
				UPDATE secrets
				SET encrypted_data = $1,
				    updated_at = NOW()
				WHERE id = $2
				  AND owner_id = $3
			`)).
				WithArgs(encryptedData, secretID, ownerID)

			if tt.queryError != nil {
				expectation.WillReturnError(tt.queryError)
			} else {
				expectation.WillReturnResult(tt.result)
			}

			err := repo.UpdateEncryptedData(
				ctx,
				ownerID,
				secretID,
				encryptedData,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErr == repository.ErrSecretNotFound {
					if !errors.Is(err, repository.ErrSecretNotFound) {
						t.Errorf(
							"expected ErrSecretNotFound, got %v",
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
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet SQL expectations: %v", err)
			}
		})
	}
}

func TestSecretRepository_UpdateEncryptedData_RowsAffectedError(t *testing.T) {
	repo, mock, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()
	secretID := uuid.New()
	encryptedData := []byte("encrypted")

	result := sqlmock.NewErrorResult(errors.New("rows affected error"))

	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE secrets
		SET encrypted_data = $1,
		    updated_at = NOW()
		WHERE id = $2
		  AND owner_id = $3
	`)).
		WithArgs(encryptedData, secretID, ownerID).
		WillReturnResult(result)

	err := repo.UpdateEncryptedData(
		context.Background(),
		ownerID,
		secretID,
		encryptedData,
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if err.Error() != "rows affected error" {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet SQL expectations: %v", err)
	}
}

func assertSecretEqual(t *testing.T, got, want *models.Secret) {
	t.Helper()

	if got == nil {
		t.Fatal("expected secret, got nil")
	}

	if want == nil {
		t.Fatal("expected secret is nil")
	}

	if got.ID != want.ID {
		t.Errorf("ID = %v, want %v", got.ID, want.ID)
	}

	if got.OwnerID != want.OwnerID {
		t.Errorf("OwnerID = %v, want %v", got.OwnerID, want.OwnerID)
	}

	if got.Type != want.Type {
		t.Errorf("Type = %q, want %q", got.Type, want.Type)
	}

	if string(got.EncryptedData) != string(want.EncryptedData) {
		t.Errorf(
			"EncryptedData = %q, want %q",
			got.EncryptedData,
			want.EncryptedData,
		)
	}

	if string(got.Metadata) != string(want.Metadata) {
		t.Errorf(
			"Metadata = %q, want %q",
			got.Metadata,
			want.Metadata,
		)
	}

	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf(
			"CreatedAt = %v, want %v",
			got.CreatedAt,
			want.CreatedAt,
		)
	}

	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf(
			"UpdatedAt = %v, want %v",
			got.UpdatedAt,
			want.UpdatedAt,
		)
	}
}
