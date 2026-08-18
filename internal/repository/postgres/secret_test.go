package postgres

import (
	"context"
	"encoding/json"
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

func setupSecretRepository(t *testing.T) (*SecretRepository, pgxmock.PgxPoolIface, func()) {
	t.Helper()

	db, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}

	repo := NewSecretRepository(db)

	cleanup := func() {
		db.Close()
	}

	return repo, db, cleanup
}

func TestNewSecretRepository(t *testing.T) {
	db, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("failed to create pgxmock pool: %v", err)
	}
	defer db.Close()

	repo := NewSecretRepository(db)

	if repo == nil {
		t.Fatal("expected repository, got nil")
	}
}

func TestSecretRepository_Create(t *testing.T) {
	db, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool(): %v", err)
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

	rows := pgxmock.NewRows([]string{
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

	db.ExpectQuery(regexp.QuoteMeta(`
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
			pgxmock.AnyArg(),
			ownerID,
			models.SecretText,
			[]byte("encrypted"),
			json.RawMessage(`{}`),
		).
		WillReturnRows(rows)

	result, err := repo.Create(
		context.Background(),
		secret,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
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

	if err := db.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSecretRepository_Create_Error(t *testing.T) {
	repo, db, cleanup := setupSecretRepository(t)
	defer cleanup()

	secret := &models.Secret{
		ID:            uuid.New(),
		OwnerID:       uuid.New(),
		Type:          "password",
		EncryptedData: []byte("encrypted"),
		Metadata:      []byte(`{}`),
	}

	dbErr := errors.New("database error")

	db.ExpectQuery(regexp.QuoteMeta(`
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

	got, err := repo.Create(
		context.Background(),
		secret,
	)

	if !errors.Is(err, dbErr) {
		t.Errorf("expected error wrapping %v, got %v", dbErr, err)
	}

	if got != nil {
		t.Errorf("expected nil secret, got %+v", got)
	}

	if err := db.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestSecretRepository_GetByID(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()
	createdAt := time.Now()
	updatedAt := createdAt.Add(time.Hour)

	dbErr := errors.New("database error")

	tests := []struct {
		name    string
		mock    func(pgxmock.PgxPoolIface)
		want    *models.Secret
		wantErr error
	}{
		{
			name: "success",
			mock: func(db pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{
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

				db.ExpectQuery(regexp.QuoteMeta(`
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
			mock: func(db pgxmock.PgxPoolIface) {
				db.ExpectQuery(regexp.QuoteMeta(`
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
					WillReturnError(pgx.ErrNoRows)
			},
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name: "database error",
			mock: func(db pgxmock.PgxPoolIface) {
				db.ExpectQuery(regexp.QuoteMeta(`
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
			wantErr: dbErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, db, cleanup := setupSecretRepository(t)
			defer cleanup()

			tt.mock(db)

			got, err := repo.GetByID(
				ctx,
				ownerID,
				secretID,
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
						"expected nil secret, got %+v",
						got,
					)
				}
			} else {
				assertSecretEqual(t, got, tt.want)
			}

			if err := db.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet expectations: %v",
					err,
				)
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
		name string
		rows *pgxmock.Rows
		want []*models.Secret
	}{
		{
			name: "multiple secrets",
			rows: pgxmock.NewRows([]string{
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
			rows: pgxmock.NewRows([]string{
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
			repo, db, cleanup := setupSecretRepository(t)
			defer cleanup()

			db.ExpectQuery(regexp.QuoteMeta(`
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

			if err != nil {
				t.Fatalf(
					"List() error = %v",
					err,
				)
			}

			if len(got) != len(tt.want) {
				t.Fatalf(
					"got %d secrets, want %d",
					len(got),
					len(tt.want),
				)
			}

			for i := range tt.want {
				assertSecretEqual(
					t,
					got[i],
					tt.want[i],
				)
			}

			if err := db.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet expectations: %v",
					err,
				)
			}
		})
	}
}

func TestSecretRepository_List_QueryError(t *testing.T) {
	repo, db, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()
	dbErr := errors.New("database error")

	db.ExpectQuery(regexp.QuoteMeta(`
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

	got, err := repo.List(
		context.Background(),
		ownerID,
	)

	if !errors.Is(err, dbErr) {
		t.Errorf(
			"expected error wrapping %v, got %v",
			dbErr,
			err,
		)
	}

	if got != nil {
		t.Errorf(
			"expected nil result, got %+v",
			got,
		)
	}

	if err := db.ExpectationsWereMet(); err != nil {
		t.Errorf(
			"unmet expectations: %v",
			err,
		)
	}
}

func TestSecretRepository_List_ScanError(t *testing.T) {
	repo, db, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()

	rows := pgxmock.NewRows([]string{
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

	db.ExpectQuery(regexp.QuoteMeta(`
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

	got, err := repo.List(
		context.Background(),
		ownerID,
	)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got != nil {
		t.Errorf(
			"expected nil result, got %+v",
			got,
		)
	}

	if err := db.ExpectationsWereMet(); err != nil {
		t.Errorf(
			"unmet expectations: %v",
			err,
		)
	}
}

func TestSecretRepository_List_RowsError(t *testing.T) {
	repo, db, cleanup := setupSecretRepository(t)
	defer cleanup()

	ownerID := uuid.New()
	rowsErr := errors.New("rows error")

	rows := pgxmock.NewRows([]string{
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

	db.ExpectQuery(regexp.QuoteMeta(`
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

	got, err := repo.List(
		context.Background(),
		ownerID,
	)

	if !errors.Is(err, rowsErr) {
		t.Errorf(
			"expected error wrapping %v, got %v",
			rowsErr,
			err,
		)
	}

	if got != nil {
		t.Errorf(
			"expected nil result, got %+v",
			got,
		)
	}

	if err := db.ExpectationsWereMet(); err != nil {
		t.Errorf(
			"unmet expectations: %v",
			err,
		)
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
		mockRows func(pgxmock.PgxPoolIface, *models.Secret)
		want     *models.Secret
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
			mockRows: func(
				db pgxmock.PgxPoolIface,
				secret *models.Secret,
			) {
				rows := pgxmock.NewRows([]string{
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

				db.ExpectQuery(regexp.QuoteMeta(`
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
			mockRows: func(
				db pgxmock.PgxPoolIface,
				secret *models.Secret,
			) {
				rows := pgxmock.NewRows([]string{
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

				db.ExpectQuery(regexp.QuoteMeta(`
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
						json.RawMessage(`{}`),
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
			repo, db, cleanup := setupSecretRepository(t)
			defer cleanup()

			tt.mockRows(db, tt.secret)

			got, err := repo.Update(
				ctx,
				tt.secret,
			)

			if err != nil {
				t.Fatalf(
					"Update() error = %v",
					err,
				)
			}

			assertSecretEqual(
				t,
				got,
				tt.want,
			)

			if err := db.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet expectations: %v",
					err,
				)
			}
		})
	}
}

func TestSecretRepository_Update_NotFound(t *testing.T) {
	repo, db, cleanup := setupSecretRepository(t)
	defer cleanup()

	secret := &models.Secret{
		ID:            uuid.New(),
		OwnerID:       uuid.New(),
		Type:          "password",
		EncryptedData: []byte("encrypted"),
		Metadata:      []byte(`{}`),
	}

	db.ExpectQuery(regexp.QuoteMeta(`
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
		WillReturnError(pgx.ErrNoRows)

	got, err := repo.Update(
		context.Background(),
		secret,
	)

	if !errors.Is(err, repository.ErrSecretNotFound) {
		t.Errorf(
			"expected ErrSecretNotFound, got %v",
			err,
		)
	}

	if got != nil {
		t.Errorf(
			"expected nil secret, got %+v",
			got,
		)
	}

	if err := db.ExpectationsWereMet(); err != nil {
		t.Errorf(
			"unmet expectations: %v",
			err,
		)
	}
}

func TestSecretRepository_Update_DatabaseError(t *testing.T) {
	repo, db, cleanup := setupSecretRepository(t)
	defer cleanup()

	secret := &models.Secret{
		ID:            uuid.New(),
		OwnerID:       uuid.New(),
		Type:          "password",
		EncryptedData: []byte("encrypted"),
		Metadata:      []byte(`{}`),
	}

	dbErr := errors.New("database error")

	db.ExpectQuery(regexp.QuoteMeta(`
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

	got, err := repo.Update(
		context.Background(),
		secret,
	)

	if !errors.Is(err, dbErr) {
		t.Errorf(
			"expected error wrapping %v, got %v",
			dbErr,
			err,
		)
	}

	if got != nil {
		t.Errorf(
			"expected nil secret, got %+v",
			got,
		)
	}

	if err := db.ExpectationsWereMet(); err != nil {
		t.Errorf(
			"unmet expectations: %v",
			err,
		)
	}
}

func TestSecretRepository_Delete(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()

	dbErr := errors.New("database error")

	tests := []struct {
		name       string
		result     pgconn.CommandTag
		queryError error
		wantErr    error
	}{
		{
			name:   "success",
			result: pgxmock.NewResult("DELETE", 1),
		},
		{
			name:    "secret not found",
			result:  pgxmock.NewResult("DELETE", 0),
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:       "database error",
			queryError: dbErr,
			wantErr:    dbErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, db, cleanup := setupSecretRepository(t)
			defer cleanup()

			expectation := db.ExpectExec(regexp.QuoteMeta(`
				DELETE FROM secrets
				WHERE id = $1
				  AND owner_id = $2
			`)).
				WithArgs(
					secretID,
					ownerID,
				)

			if tt.queryError != nil {
				expectation.WillReturnError(tt.queryError)
			} else {
				expectation.WillReturnResult(tt.result)
			}

			err := repo.Delete(
				ctx,
				ownerID,
				secretID,
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
			} else if err != nil {
				t.Fatalf(
					"unexpected error: %v",
					err,
				)
			}

			if err := db.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet expectations: %v",
					err,
				)
			}
		})
	}
}

func TestSecretRepository_UpdateEncryptedData(t *testing.T) {
	ctx := context.Background()

	ownerID := uuid.New()
	secretID := uuid.New()
	encryptedData := []byte("new encrypted data")

	dbErr := errors.New("database error")

	tests := []struct {
		name       string
		result     pgconn.CommandTag
		queryError error
		wantErr    error
	}{
		{
			name:   "success",
			result: pgxmock.NewResult("UPDATE", 1),
		},
		{
			name:    "secret not found",
			result:  pgxmock.NewResult("UPDATE", 0),
			wantErr: repository.ErrSecretNotFound,
		},
		{
			name:       "database error",
			queryError: dbErr,
			wantErr:    dbErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, db, cleanup := setupSecretRepository(t)
			defer cleanup()

			expectation := db.ExpectExec(regexp.QuoteMeta(`
				UPDATE secrets
				SET encrypted_data = $1,
				    updated_at = NOW()
				WHERE id = $2
				  AND owner_id = $3
			`)).
				WithArgs(
					encryptedData,
					secretID,
					ownerID,
				)

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

				if !errors.Is(err, tt.wantErr) {
					t.Errorf(
						"expected error wrapping %v, got %v",
						tt.wantErr,
						err,
					)
				}
			} else if err != nil {
				t.Fatalf(
					"unexpected error: %v",
					err,
				)
			}

			if err := db.ExpectationsWereMet(); err != nil {
				t.Errorf(
					"unmet expectations: %v",
					err,
				)
			}
		})
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
		t.Errorf(
			"ID = %v, want %v",
			got.ID,
			want.ID,
		)
	}

	if got.OwnerID != want.OwnerID {
		t.Errorf(
			"OwnerID = %v, want %v",
			got.OwnerID,
			want.OwnerID,
		)
	}

	if got.Type != want.Type {
		t.Errorf(
			"Type = %q, want %q",
			got.Type,
			want.Type,
		)
	}

	if string(got.EncryptedData) !=
		string(want.EncryptedData) {
		t.Errorf(
			"EncryptedData = %q, want %q",
			got.EncryptedData,
			want.EncryptedData,
		)
	}

	if string(got.Metadata) !=
		string(want.Metadata) {
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
