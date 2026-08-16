package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/onbehalfofhim/secrets-keeper/internal/models"
	"github.com/onbehalfofhim/secrets-keeper/internal/repository"
)

// SecretRepository представляет репозиторий для работы с секретами.
type SecretRepository struct {
	db DB
}

// NewSecretRepository создаёт новый репозиторий секретов
// с указанным подключением к PostgreSQL.
func NewSecretRepository(db DB) *SecretRepository {
	return &SecretRepository{db: db}
}

// Create сохраняет новый секрет в PostgreSQL.
//
// Если идентификатор секрета не задан, генерируется новый UUID.
// Если метаданные не заданы, сохраняется пустой JSON-объект.
// Метод возвращает сохранённый секрет с заполненными временными метками.
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

	row := r.db.QueryRow(
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
		return nil, fmt.Errorf("create secret: %w", err)
	}

	return &result, nil
}

// GetByID возвращает секрет по его идентификатору,
// принадлежащий указанному пользователю.
//
// Проверка ownerID непосредственно в SQL-запросе обеспечивает,
// что пользователь не может получить секрет другого пользователя.
// Если секрет не найден, возвращается repository.ErrSecretNotFound.
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

	row := r.db.QueryRow(
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrSecretNotFound
		}

		return nil, fmt.Errorf("get secret by id: %w", err)
	}

	return &secret, nil
}

// List возвращает список всех секретов указанного пользователя.
//
// Секреты сортируются по дате создания в порядке убывания.
// Секреты других пользователей в результат не попадают.
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

	rows, err := r.db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
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
			return nil, fmt.Errorf("scan secret in list: %w", err)
		}

		secrets = append(secrets, &secret)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secrets: %w", err)
	}

	return secrets, nil
}

// Update обновляет секрет указанного пользователя.
//
// Обновляются тип секрета, зашифрованные данные и метаданные.
// Время изменения updated_at устанавливается на стороне PostgreSQL.
// Если секрет не найден или не принадлежит пользователю,
// возвращается repository.ErrSecretNotFound.
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

	row := r.db.QueryRow(
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrSecretNotFound
		}

		return nil, fmt.Errorf("update secret: %w", err)
	}

	return &result, nil
}

// Delete удаляет секрет пользователя.
//
// Удаление выполняется только при совпадении secretID и ownerID.
// Если секрет не найден или не принадлежит пользователю,
// возвращается repository.ErrSecretNotFound.
func (r *SecretRepository) Delete(ctx context.Context, ownerID, secretID uuid.UUID) error {
	const query = `
		DELETE FROM secrets
		WHERE id = $1
		  AND owner_id = $2
	`

	result, err := r.db.Exec(
		ctx,
		query,
		secretID,
		ownerID,
	)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return repository.ErrSecretNotFound
	}

	return nil
}

// UpdateEncryptedData обновляет только зашифрованные данные секрета.
//
// Метод используется для операций с бинарными данными, когда
// остальные свойства секрета изменять не требуется.
// Проверка ownerID не позволяет изменить файл другого пользователя.
func (r *SecretRepository) UpdateEncryptedData(ctx context.Context, ownerID uuid.UUID, secretID uuid.UUID, encryptedData []byte) error {
	query := `
		UPDATE secrets
		SET encrypted_data = $1,
		    updated_at = NOW()
		WHERE id = $2
		  AND owner_id = $3
	`

	result, err := r.db.Exec(
		ctx,
		query,
		encryptedData,
		secretID,
		ownerID,
	)
	if err != nil {
		return fmt.Errorf("update encrypted data: %w", err)
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return repository.ErrSecretNotFound
	}

	return nil
}
