package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

// представляет репозиторий для работы с секретами
type SecretRepository struct {
	db *sql.DB
}

// создает новый репозиторий секретов
func NewSecretRepository(db *sql.DB) *SecretRepository {
	return &SecretRepository{db: db}
}

func (r *SecretRepository) Create(ctx context.Context, secret *models.Secret) (*models.Secret, error) {
	query := `
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
	`

	if secret.ID == uuid.Nil {
		secret.ID = uuid.New()
	}

	if secret.Metadata == nil {
		secret.Metadata = []byte(`{}`)
	}

	row := r.db.QueryRowContext(
		ctx,
		query,
		secret.ID,
		secret.OwnerID,
		secret.Type,
		secret.EncryptedData,
		secret.Metadata,
	)

	var result models.Secret

	err := row.Scan(
		&result.ID,
		&result.OwnerID,
		&result.Type,
		&result.EncryptedData,
		&result.Metadata,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (r *SecretRepository) GetByID(ctx context.Context, ownerID, secretID uuid.UUID) (*models.Secret, error) {
	query := `
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
	`

	row := r.db.QueryRowContext(
		ctx,
		query,
		secretID,
		ownerID,
	)

	var secret models.Secret

	err := row.Scan(
		&secret.ID,
		&secret.OwnerID,
		&secret.Type,
		&secret.EncryptedData,
		&secret.Metadata,
		&secret.CreatedAt,
		&secret.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrSecretNotFound
		}

		return nil, err
	}

	return &secret, nil
}

func (r *SecretRepository) List(ctx context.Context, ownerID uuid.UUID) ([]*models.Secret, error) {
	query := `
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
	`

	rows, err := r.db.QueryContext(ctx, query, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	secrets := make([]*models.Secret, 0)

	for rows.Next() {
		var secret models.Secret

		err := rows.Scan(
			&secret.ID,
			&secret.OwnerID,
			&secret.Type,
			&secret.EncryptedData,
			&secret.Metadata,
			&secret.CreatedAt,
			&secret.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		secrets = append(secrets, &secret)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}

func (r *SecretRepository) Update(ctx context.Context, secret *models.Secret) (*models.Secret, error) {
	query := `
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
	`

	if secret.Metadata == nil {
		secret.Metadata = []byte(`{}`)
	}

	row := r.db.QueryRowContext(
		ctx,
		query,
		secret.Type,
		secret.EncryptedData,
		secret.Metadata,
		secret.ID,
		secret.OwnerID,
	)

	var result models.Secret

	err := row.Scan(
		&result.ID,
		&result.OwnerID,
		&result.Type,
		&result.EncryptedData,
		&result.Metadata,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrSecretNotFound
		}

		return nil, err
	}

	return &result, nil
}

func (r *SecretRepository) Delete(ctx context.Context, ownerID, secretID uuid.UUID) error {
	const query = `
		DELETE FROM secrets
		WHERE id = $1
		  AND owner_id = $2
	`

	result, err := r.db.ExecContext(
		ctx,
		query,
		secretID,
		ownerID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return repository.ErrSecretNotFound
	}

	return nil
}

func (r *SecretRepository) UpdateEncryptedData(ctx context.Context, ownerID uuid.UUID, secretID uuid.UUID, encryptedData []byte) error {
	query := `
		UPDATE secrets
		SET encrypted_data = $1,
		    updated_at = NOW()
		WHERE id = $2
		  AND owner_id = $3
	`

	result, err := r.db.ExecContext(
		ctx,
		query,
		encryptedData,
		secretID,
		ownerID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return repository.ErrSecretNotFound
	}

	return nil
}
