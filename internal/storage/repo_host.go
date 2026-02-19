package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type hostRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *hostRepository) Create(ctx context.Context, host *Host) error {
	if host == nil {
		return fmt.Errorf("create host: host is nil")
	}
	if host.Name == "" {
		return fmt.Errorf("create host: name is required")
	}
	if host.Address == "" {
		return fmt.Errorf("create host: address is required")
	}
	if host.Port == 0 {
		host.Port = 22
	}

	host.ID = ensureID(host.ID)
	now := nowUTC()
	host.CreatedAt = now
	host.UpdatedAt = now

	envRefs, err := encodeEnvRefs(host.EnvRefs)
	if err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create host: begin tx: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO hosts(id, name, address, port, user, env_refs, created_at, updated_at, deleted_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL)
	`, host.ID, host.Name, host.Address, host.Port, host.User, envRefs, fmtTime(host.CreatedAt), fmtTime(host.UpdatedAt))
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("create host: insert host: %w", err)
	}

	for _, tag := range host.Tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO host_tags(host_id, tag) VALUES(?, ?)`, host.ID, tag); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("create host: add tag: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create host: commit: %w", err)
	}

	return nil
}

func (r *hostRepository) Get(ctx context.Context, name string) (*Host, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, address, port, user, env_refs, created_at, updated_at, deleted_at
		FROM hosts
		WHERE name = ? AND deleted_at IS NULL
	`, name)

	host, err := scanHost(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get host: %w", err)
	}

	tags, err := r.tagsByHostID(ctx, host.ID)
	if err != nil {
		return nil, err
	}
	host.Tags = tags
	return host, nil
}

func (r *hostRepository) List(ctx context.Context, filter HostFilter) ([]Host, error) {
	query := `
		SELECT DISTINCT h.id, h.name, h.address, h.port, h.user, h.env_refs, h.created_at, h.updated_at, h.deleted_at
		FROM hosts h
	`
	args := []any{}

	if filter.Tag != "" {
		query += ` INNER JOIN host_tags ht ON ht.host_id = h.id `
	}

	query += ` WHERE 1=1 `
	if !filter.IncludeDeleted {
		query += ` AND h.deleted_at IS NULL `
	}
	if filter.Tag != "" {
		query += ` AND ht.tag = ? `
		args = append(args, filter.Tag)
	}
	query += ` ORDER BY h.name ASC `

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var out []Host
	for rows.Next() {
		host, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("list hosts: %w", err)
		}
		tags, err := r.tagsByHostID(ctx, host.ID)
		if err != nil {
			return nil, err
		}
		host.Tags = tags
		out = append(out, *host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list hosts: iterate: %w", err)
	}
	return out, nil
}

func (r *hostRepository) Update(ctx context.Context, host *Host) error {
	if host == nil {
		return fmt.Errorf("update host: host is nil")
	}
	if host.ID == "" {
		return fmt.Errorf("update host: id is required")
	}
	if host.Port == 0 {
		host.Port = 22
	}

	host.UpdatedAt = nowUTC()
	envRefs, err := encodeEnvRefs(host.EnvRefs)
	if err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("update host: begin tx: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE hosts
		SET name = ?, address = ?, port = ?, user = ?, env_refs = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, host.Name, host.Address, host.Port, host.User, envRefs, fmtTime(host.UpdatedAt), host.ID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("update host: update row: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("update host: rows affected: %w", err)
	}
	if count == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM host_tags WHERE host_id = ?`, host.ID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("update host: clear tags: %w", err)
	}
	for _, tag := range host.Tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO host_tags(host_id, tag) VALUES(?, ?)`, host.ID, tag); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("update host: add tag: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("update host: commit: %w", err)
	}
	return nil
}

func (r *hostRepository) Delete(ctx context.Context, name string) error {
	now := fmtTime(nowUTC())
	result, err := r.db.ExecContext(ctx, `
		UPDATE hosts
		SET deleted_at = ?, updated_at = ?
		WHERE name = ? AND deleted_at IS NULL
	`, now, now, name)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete host: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *hostRepository) AddTag(ctx context.Context, hostID, tag string) error {
	if hostID == "" || tag == "" {
		return fmt.Errorf("add host tag: hostID and tag are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT OR IGNORE INTO host_tags(host_id, tag) VALUES(?, ?)`, hostID, tag)
	if err != nil {
		return fmt.Errorf("add host tag: %w", err)
	}
	return nil
}

func (r *hostRepository) RemoveTag(ctx context.Context, hostID, tag string) error {
	if hostID == "" || tag == "" {
		return fmt.Errorf("remove host tag: hostID and tag are required")
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM host_tags WHERE host_id = ? AND tag = ?`, hostID, tag)
	if err != nil {
		return fmt.Errorf("remove host tag: %w", err)
	}
	return nil
}

func (r *hostRepository) tagsByHostID(ctx context.Context, hostID string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT tag FROM host_tags WHERE host_id = ? ORDER BY tag ASC`, hostID)
	if err != nil {
		return nil, fmt.Errorf("query host tags: %w", err)
	}
	defer rows.Close()

	tags := []string{}
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, fmt.Errorf("scan host tag: %w", err)
		}
		tags = append(tags, tag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host tags: %w", err)
	}
	return tags, nil
}

type hostScanner interface {
	Scan(dest ...any) error
}

func scanHost(scanner hostScanner) (*Host, error) {
	var (
		host      Host
		envRefs   sql.NullString
		createdAt string
		updatedAt string
		deletedAt sql.NullString
	)

	if err := scanner.Scan(&host.ID, &host.Name, &host.Address, &host.Port, &host.User, &envRefs, &createdAt, &updatedAt, &deletedAt); err != nil {
		return nil, err
	}

	parsedCreatedAt, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	parsedUpdatedAt, err := parseTime(updatedAt)
	if err != nil {
		return nil, err
	}
	host.CreatedAt = parsedCreatedAt
	host.UpdatedAt = parsedUpdatedAt

	host.DeletedAt, err = parseNullableTime(deletedAt)
	if err != nil {
		return nil, err
	}
	host.EnvRefs, err = decodeEnvRefs(envRefs)
	if err != nil {
		return nil, err
	}
	return &host, nil
}
