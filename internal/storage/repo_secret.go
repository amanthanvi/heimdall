package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type secretRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *secretRepository) Create(ctx context.Context, secret *Secret) error {
	if secret == nil {
		return fmt.Errorf("create secret: secret is nil")
	}
	if secret.Name == "" {
		return fmt.Errorf("create secret: name is required")
	}
	if len(secret.Value) == 0 {
		return fmt.Errorf("create secret: value is required")
	}

	secret.ID = ensureID(secret.ID)
	now := nowUTC()
	secret.CreatedAt = now
	secret.UpdatedAt = now

	blob, err := r.vc.EncryptField("secret", secret.ID, "value", secret.Value)
	if err != nil {
		return fmt.Errorf("create secret: encrypt value: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO secrets(id, name, value_ciphertext, value_nonce, created_at, updated_at, deleted_at)
		VALUES(?, ?, ?, ?, ?, ?, NULL)
	`, secret.ID, secret.Name, blob.Ciphertext, blob.Nonce, fmtTime(secret.CreatedAt), fmtTime(secret.UpdatedAt))
	if err != nil {
		return fmt.Errorf("create secret: %w", err)
	}
	return nil
}

func (r *secretRepository) Get(ctx context.Context, name string) (*Secret, error) {
	var (
		secret     Secret
		ciphertext []byte
		nonce      []byte
		createdAt  string
		updatedAt  string
		deletedAt  sql.NullString
	)

	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, value_ciphertext, value_nonce, created_at, updated_at, deleted_at
		FROM secrets
		WHERE name = ? AND deleted_at IS NULL
	`, name).Scan(&secret.ID, &secret.Name, &ciphertext, &nonce, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}

	secret.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	secret.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return nil, err
	}
	secret.DeletedAt, err = parseNullableTime(deletedAt)
	if err != nil {
		return nil, err
	}

	secret.Value, err = r.vc.DecryptField("secret", secret.ID, "value", crypto.EncryptedBlob{Ciphertext: ciphertext, Nonce: nonce})
	if err != nil {
		return nil, fmt.Errorf("get secret: decrypt value: %w", err)
	}

	return &secret, nil
}

func (r *secretRepository) Update(ctx context.Context, secret *Secret) error {
	if secret == nil {
		return fmt.Errorf("update secret: secret is nil")
	}
	if secret.ID == "" {
		return fmt.Errorf("update secret: id is required")
	}
	if len(secret.Value) == 0 {
		return fmt.Errorf("update secret: value is required")
	}

	secret.UpdatedAt = nowUTC()
	blob, err := r.vc.EncryptField("secret", secret.ID, "value", secret.Value)
	if err != nil {
		return fmt.Errorf("update secret: encrypt value: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE secrets
		SET name = ?, value_ciphertext = ?, value_nonce = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, secret.Name, blob.Ciphertext, blob.Nonce, fmtTime(secret.UpdatedAt), secret.ID)
	if err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update secret: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *secretRepository) Delete(ctx context.Context, name string) error {
	now := fmtTime(nowUTC())
	result, err := r.db.ExecContext(ctx, `
		UPDATE secrets
		SET deleted_at = ?, updated_at = ?
		WHERE name = ? AND deleted_at IS NULL
	`, now, now, name)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete secret: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
