package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type identityRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *identityRepository) Create(ctx context.Context, identity *Identity) error {
	if identity == nil {
		return fmt.Errorf("create identity: identity is nil")
	}
	if identity.Name == "" {
		return fmt.Errorf("create identity: name is required")
	}
	if identity.Kind == "" {
		return fmt.Errorf("create identity: kind is required")
	}
	if identity.Status == "" {
		identity.Status = IdentityStatusActive
	}

	identity.ID = ensureID(identity.ID)
	now := nowUTC()
	identity.CreatedAt = now
	identity.UpdatedAt = now

	var blob crypto.EncryptedBlob
	var err error
	if len(identity.PrivateKey) > 0 {
		blob, err = r.vc.EncryptField("identity", identity.ID, "private_key", identity.PrivateKey)
		if err != nil {
			return fmt.Errorf("create identity: encrypt private key: %w", err)
		}
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO identities(id, name, kind, public_key, private_key_ciphertext, private_key_nonce, status, created_at, updated_at, deleted_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
	`, identity.ID, identity.Name, identity.Kind, identity.PublicKey, nullableBytes(blob.Ciphertext), nullableBytes(blob.Nonce), string(identity.Status), fmtTime(identity.CreatedAt), fmtTime(identity.UpdatedAt))
	if err != nil {
		return fmt.Errorf("create identity: %w", err)
	}
	return nil
}

func (r *identityRepository) Get(ctx context.Context, name string) (*Identity, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, kind, public_key, private_key_ciphertext, private_key_nonce, status, created_at, updated_at, deleted_at
		FROM identities
		WHERE name = ? AND deleted_at IS NULL
	`, name)

	identity, err := scanIdentity(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get identity: %w", err)
	}

	if len(identity.PrivateKey) > 0 {
		plaintext, err := r.vc.DecryptField("identity", identity.ID, "private_key", crypto.EncryptedBlob{
			Ciphertext: identity.PrivateKey,
			Nonce:      identity.rawPrivateKeyNonce,
		})
		if err != nil {
			return nil, fmt.Errorf("get identity: decrypt private key: %w", err)
		}
		identity.PrivateKey = plaintext
	}
	identity.rawPrivateKeyNonce = nil

	out := identity.Identity
	return &out, nil
}

func (r *identityRepository) Update(ctx context.Context, identity *Identity) error {
	if identity == nil {
		return fmt.Errorf("update identity: identity is nil")
	}
	if identity.ID == "" {
		return fmt.Errorf("update identity: id is required")
	}
	identity.UpdatedAt = nowUTC()

	var ciphertext any
	var nonce any
	if len(identity.PrivateKey) > 0 {
		blob, err := r.vc.EncryptField("identity", identity.ID, "private_key", identity.PrivateKey)
		if err != nil {
			return fmt.Errorf("update identity: encrypt private key: %w", err)
		}
		ciphertext = blob.Ciphertext
		nonce = blob.Nonce
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE identities
		SET name = ?, kind = ?, public_key = ?, private_key_ciphertext = ?, private_key_nonce = ?, status = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, identity.Name, identity.Kind, identity.PublicKey, ciphertext, nonce, string(identity.Status), fmtTime(identity.UpdatedAt), identity.ID)
	if err != nil {
		return fmt.Errorf("update identity: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update identity: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *identityRepository) Delete(ctx context.Context, name string) error {
	now := fmtTime(nowUTC())
	result, err := r.db.ExecContext(ctx, `
		UPDATE identities
		SET deleted_at = ?, updated_at = ?
		WHERE name = ? AND deleted_at IS NULL
	`, now, now, name)
	if err != nil {
		return fmt.Errorf("delete identity: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete identity: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

type scannedIdentity struct {
	Identity
	rawPrivateKeyNonce []byte
}

func scanIdentity(scanner interface{ Scan(dest ...any) error }) (*scannedIdentity, error) {
	var (
		identity  scannedIdentity
		status    string
		createdAt string
		updatedAt string
		deletedAt sql.NullString
	)
	if err := scanner.Scan(
		&identity.ID,
		&identity.Name,
		&identity.Kind,
		&identity.PublicKey,
		&identity.PrivateKey,
		&identity.rawPrivateKeyNonce,
		&status,
		&createdAt,
		&updatedAt,
		&deletedAt,
	); err != nil {
		return nil, err
	}

	identity.Status = IdentityStatus(status)
	parsedCreatedAt, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	parsedUpdatedAt, err := parseTime(updatedAt)
	if err != nil {
		return nil, err
	}
	identity.CreatedAt = parsedCreatedAt
	identity.UpdatedAt = parsedUpdatedAt
	identity.DeletedAt, err = parseNullableTime(deletedAt)
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

func nullableBytes(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}
