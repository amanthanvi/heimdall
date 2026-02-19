package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type sessionRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *sessionRepository) RecordStart(ctx context.Context, entry *SessionHistory) error {
	if entry == nil {
		return fmt.Errorf("record session start: entry is nil")
	}
	if entry.HostID == "" {
		return fmt.Errorf("record session start: host id is required")
	}

	entry.ID = ensureID(entry.ID)
	if entry.StartedAt.IsZero() {
		entry.StartedAt = nowUTC()
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO session_history(id, host_id, started_at, ended_at, exit_code)
		VALUES(?, ?, ?, NULL, NULL)
	`, entry.ID, entry.HostID, fmtTime(entry.StartedAt))
	if err != nil {
		return fmt.Errorf("record session start: %w", err)
	}
	return nil
}

func (r *sessionRepository) RecordEnd(ctx context.Context, sessionID string, exitCode int) error {
	endedAt := nowUTC()
	result, err := r.db.ExecContext(ctx, `
		UPDATE session_history
		SET ended_at = ?, exit_code = ?
		WHERE id = ?
	`, fmtTime(endedAt), exitCode, sessionID)
	if err != nil {
		return fmt.Errorf("record session end: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("record session end: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *sessionRepository) ListByHostID(ctx context.Context, hostID string) ([]SessionHistory, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, host_id, started_at, ended_at, exit_code
		FROM session_history
		WHERE host_id = ?
		ORDER BY started_at ASC
	`, hostID)
	if err != nil {
		return nil, fmt.Errorf("list session history by host id: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries := []SessionHistory{}
	for rows.Next() {
		var (
			entry     SessionHistory
			startedAt string
			endedAt   sql.NullString
			exitCode  sql.NullInt64
		)
		if err := rows.Scan(&entry.ID, &entry.HostID, &startedAt, &endedAt, &exitCode); err != nil {
			return nil, fmt.Errorf("list session history by host id: scan row: %w", err)
		}
		entry.StartedAt, err = parseTime(startedAt)
		if err != nil {
			return nil, err
		}
		entry.EndedAt, err = parseNullableTime(endedAt)
		if err != nil {
			return nil, err
		}
		if exitCode.Valid {
			val := int(exitCode.Int64)
			entry.ExitCode = &val
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list session history by host id: iterate: %w", err)
	}
	return entries, nil
}
