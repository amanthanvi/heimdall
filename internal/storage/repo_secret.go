package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

const defaultSecretRevealPolicy = "once-per-unlock"

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
	if secret.RevealPolicy == "" {
		secret.RevealPolicy = defaultSecretRevealPolicy
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
		INSERT INTO secrets(id, name, value_ciphertext, value_nonce, reveal_policy, created_at, updated_at, deleted_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, NULL)
	`, secret.ID, secret.Name, blob.Ciphertext, blob.Nonce, secret.RevealPolicy, fmtTime(secret.CreatedAt), fmtTime(secret.UpdatedAt))
	if err != nil {
		restored, restoreErr := r.restoreSoftDeleted(ctx, secret)
		if restoreErr != nil {
			return fmt.Errorf("create secret: restore soft-deleted: %w", restoreErr)
		}
		if restored {
			return nil
		}
		return fmt.Errorf("create secret: %w", err)
	}
	return nil
}

func (r *secretRepository) restoreSoftDeleted(ctx context.Context, secret *Secret) (bool, error) {
	var (
		existingID string
		createdRaw string
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT id, created_at
		FROM secrets
		WHERE name = ? AND deleted_at IS NOT NULL
	`, secret.Name).Scan(&existingID, &createdRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query deleted secret: %w", err)
	}

	blob, err := r.vc.EncryptField("secret", existingID, "value", secret.Value)
	if err != nil {
		return false, fmt.Errorf("encrypt value: %w", err)
	}
	now := nowUTC()
	result, err := r.db.ExecContext(ctx, `
		UPDATE secrets
		SET value_ciphertext = ?, value_nonce = ?, reveal_policy = ?, updated_at = ?, deleted_at = NULL
		WHERE id = ? AND deleted_at IS NOT NULL
	`, blob.Ciphertext, blob.Nonce, secret.RevealPolicy, fmtTime(now), existingID)
	if err != nil {
		return false, fmt.Errorf("restore deleted secret: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("restore deleted secret rows affected: %w", err)
	}
	if affected == 0 {
		return false, nil
	}

	createdAt, err := parseTime(createdRaw)
	if err != nil {
		return false, fmt.Errorf("parse created_at: %w", err)
	}
	secret.ID = existingID
	secret.CreatedAt = createdAt
	secret.UpdatedAt = now
	return true, nil
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
		SELECT id, name, value_ciphertext, value_nonce, reveal_policy, created_at, updated_at, deleted_at
		FROM secrets
		WHERE name = ? AND deleted_at IS NULL
	`, name).Scan(&secret.ID, &secret.Name, &ciphertext, &nonce, &secret.RevealPolicy, &createdAt, &updatedAt, &deletedAt)
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

func (r *secretRepository) GetMeta(ctx context.Context, name string) (*Secret, error) {
	var (
		secret    Secret
		createdAt string
		updatedAt string
		deletedAt sql.NullString
	)

	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, reveal_policy, created_at, updated_at, deleted_at
		FROM secrets
		WHERE name = ? AND deleted_at IS NULL
	`, name).Scan(&secret.ID, &secret.Name, &secret.RevealPolicy, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get secret meta: %w", err)
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
	if secret.RevealPolicy == "" {
		secret.RevealPolicy = defaultSecretRevealPolicy
	}

	secret.UpdatedAt = nowUTC()
	blob, err := r.vc.EncryptField("secret", secret.ID, "value", secret.Value)
	if err != nil {
		return fmt.Errorf("update secret: encrypt value: %w", err)
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE secrets
		SET name = ?, value_ciphertext = ?, value_nonce = ?, reveal_policy = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, secret.Name, blob.Ciphertext, blob.Nonce, secret.RevealPolicy, fmtTime(secret.UpdatedAt), secret.ID)
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
