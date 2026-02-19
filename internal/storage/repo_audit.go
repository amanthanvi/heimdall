package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type auditRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *auditRepository) Append(ctx context.Context, event *AuditEvent) error {
	if event == nil {
		return fmt.Errorf("append audit event: event is nil")
	}
	if event.EventType == "" {
		return fmt.Errorf("append audit event: event type is required")
	}
	if event.ID == "" {
		event.ID = ensureID("")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = nowUTC()
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_events(id, event_type, actor, metadata, created_at)
		VALUES(?, ?, ?, ?, ?)
	`, event.ID, event.EventType, event.Actor, event.Metadata, fmtTime(event.CreatedAt))
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

func (r *auditRepository) List(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, event_type, actor, metadata, created_at
		FROM audit_events
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	events := []AuditEvent{}
	for rows.Next() {
		var (
			event   AuditEvent
			created string
		)
		if err := rows.Scan(&event.ID, &event.EventType, &event.Actor, &event.Metadata, &created); err != nil {
			return nil, fmt.Errorf("list audit events: scan row: %w", err)
		}
		event.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit events: iterate: %w", err)
	}
	return events, nil
}
