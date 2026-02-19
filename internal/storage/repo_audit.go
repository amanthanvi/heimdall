package storage

import (
	"context"
	"database/sql"
	"errors"
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
	if event.Action == "" {
		event.Action = event.EventType
	}
	if event.Action == "" {
		return fmt.Errorf("append audit event: action is required")
	}
	if event.EventType == "" {
		event.EventType = event.Action
	}
	if event.ID == "" {
		event.ID = ensureID("")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = nowUTC()
	}
	if event.DetailsJSON == "" {
		if event.Metadata != "" {
			event.DetailsJSON = event.Metadata
		} else {
			event.DetailsJSON = "{}"
		}
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_events(
			id, event_type, actor, metadata, action, target_type, target_id, result, details_json, prev_hash, event_hash, created_at
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.EventType, event.Actor, event.Metadata, event.Action, event.TargetType, event.TargetID, event.Result, event.DetailsJSON, event.PrevHash, event.EventHash, fmtTime(event.CreatedAt))
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

func (r *auditRepository) List(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 1000
	}

	query := `
		SELECT
			id,
			COALESCE(event_type, ''),
			COALESCE(actor, ''),
			COALESCE(metadata, ''),
			created_at,
			COALESCE(action, ''),
			COALESCE(target_type, ''),
			COALESCE(target_id, ''),
			COALESCE(result, ''),
			COALESCE(details_json, '{}'),
			COALESCE(prev_hash, ''),
			COALESCE(event_hash, '')
		FROM audit_events
		WHERE 1=1
	`
	args := make([]any, 0, 6)
	if filter.Action != "" {
		query += ` AND action = ? `
		args = append(args, filter.Action)
	}
	if filter.TargetID != "" {
		query += ` AND target_id = ? `
		args = append(args, filter.TargetID)
	}
	if filter.Since != nil {
		query += ` AND created_at >= ? `
		args = append(args, fmtTime(*filter.Since))
	}
	if filter.Until != nil {
		query += ` AND created_at <= ? `
		args = append(args, fmtTime(*filter.Until))
	}
	query += ` ORDER BY rowid ASC LIMIT ? `
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
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
		if err := rows.Scan(
			&event.ID,
			&event.EventType,
			&event.Actor,
			&event.Metadata,
			&created,
			&event.Action,
			&event.TargetType,
			&event.TargetID,
			&event.Result,
			&event.DetailsJSON,
			&event.PrevHash,
			&event.EventHash,
		); err != nil {
			return nil, fmt.Errorf("list audit events: scan row: %w", err)
		}
		event.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		if event.Action == "" {
			event.Action = event.EventType
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit events: iterate: %w", err)
	}
	return events, nil
}

func (r *auditRepository) ChainTip(ctx context.Context) (string, error) {
	var tip string
	err := r.db.QueryRowContext(ctx, `SELECT value FROM vault_meta WHERE key = ?`, auditChainTipMetaKey).Scan(&tip)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("read audit chain tip: %w", err)
	}
	return tip, nil
}

func (r *auditRepository) SetChainTip(ctx context.Context, tip string) error {
	if _, err := r.db.ExecContext(ctx, `INSERT OR REPLACE INTO vault_meta(key, value) VALUES(?, ?)`, auditChainTipMetaKey, tip); err != nil {
		return fmt.Errorf("write audit chain tip: %w", err)
	}
	return nil
}
