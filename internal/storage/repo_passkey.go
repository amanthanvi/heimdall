package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type passkeyRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *passkeyRepository) Create(ctx context.Context, enrollment *PasskeyEnrollment) error {
	if enrollment == nil {
		return fmt.Errorf("create passkey enrollment: enrollment is nil")
	}
	if enrollment.Label == "" {
		return fmt.Errorf("create passkey enrollment: label is required")
	}
	if len(enrollment.CredentialID) == 0 {
		return fmt.Errorf("create passkey enrollment: credential id is required")
	}
	if len(enrollment.PublicKeyCOSE) == 0 {
		return fmt.Errorf("create passkey enrollment: public key cose is required")
	}

	enrollment.ID = ensureID(enrollment.ID)
	now := nowUTC()
	enrollment.CreatedAt = now
	enrollment.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO passkey_enrollments(id, label, credential_id, public_key_cose, aaguid, supports_hmac_secret, created_at, updated_at, deleted_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL)
	`, enrollment.ID, enrollment.Label, enrollment.CredentialID, enrollment.PublicKeyCOSE, nullableBytes(enrollment.AAGUID), boolToInt(enrollment.SupportsHMACSecret), fmtTime(enrollment.CreatedAt), fmtTime(enrollment.UpdatedAt))
	if err != nil {
		return fmt.Errorf("create passkey enrollment: %w", err)
	}
	return nil
}

func (r *passkeyRepository) GetByLabel(ctx context.Context, label string) (*PasskeyEnrollment, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, label, credential_id, public_key_cose, aaguid, supports_hmac_secret, created_at, updated_at, deleted_at
		FROM passkey_enrollments
		WHERE label = ? AND deleted_at IS NULL
	`, label)
	entry, err := scanPasskeyEnrollment(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get passkey by label: %w", err)
	}
	return entry, nil
}

func (r *passkeyRepository) GetByCredentialID(ctx context.Context, credentialID []byte) (*PasskeyEnrollment, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, label, credential_id, public_key_cose, aaguid, supports_hmac_secret, created_at, updated_at, deleted_at
		FROM passkey_enrollments
		WHERE deleted_at IS NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("get passkey by credential id: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		entry, err := scanPasskeyEnrollment(rows)
		if err != nil {
			return nil, fmt.Errorf("get passkey by credential id: %w", err)
		}
		if bytes.Equal(entry.CredentialID, credentialID) {
			return entry, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get passkey by credential id: iterate: %w", err)
	}
	return nil, ErrNotFound
}

func (r *passkeyRepository) Update(ctx context.Context, enrollment *PasskeyEnrollment) error {
	if enrollment == nil {
		return fmt.Errorf("update passkey enrollment: enrollment is nil")
	}
	if enrollment.ID == "" {
		return fmt.Errorf("update passkey enrollment: id is required")
	}
	enrollment.UpdatedAt = nowUTC()

	result, err := r.db.ExecContext(ctx, `
		UPDATE passkey_enrollments
		SET label = ?, credential_id = ?, public_key_cose = ?, aaguid = ?, supports_hmac_secret = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, enrollment.Label, enrollment.CredentialID, enrollment.PublicKeyCOSE, nullableBytes(enrollment.AAGUID), boolToInt(enrollment.SupportsHMACSecret), fmtTime(enrollment.UpdatedAt), enrollment.ID)
	if err != nil {
		return fmt.Errorf("update passkey enrollment: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update passkey enrollment: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *passkeyRepository) Delete(ctx context.Context, label string) error {
	now := fmtTime(nowUTC())
	result, err := r.db.ExecContext(ctx, `
		UPDATE passkey_enrollments
		SET deleted_at = ?, updated_at = ?
		WHERE label = ? AND deleted_at IS NULL
	`, now, now, label)
	if err != nil {
		return fmt.Errorf("delete passkey enrollment: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete passkey enrollment: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func scanPasskeyEnrollment(scanner interface{ Scan(dest ...any) error }) (*PasskeyEnrollment, error) {
	var (
		entry    PasskeyEnrollment
		supports int
		created  string
		updated  string
		deleted  sql.NullString
	)
	if err := scanner.Scan(&entry.ID, &entry.Label, &entry.CredentialID, &entry.PublicKeyCOSE, &entry.AAGUID, &supports, &created, &updated, &deleted); err != nil {
		return nil, err
	}
	var err error
	entry.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	entry.UpdatedAt, err = parseTime(updated)
	if err != nil {
		return nil, err
	}
	entry.DeletedAt, err = parseNullableTime(deleted)
	if err != nil {
		return nil, err
	}
	entry.SupportsHMACSecret = supports == 1
	return &entry, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
