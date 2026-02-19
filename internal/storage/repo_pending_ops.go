package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type pendingOpRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *pendingOpRepository) Create(ctx context.Context, op *PendingOp) error {
	if op == nil {
		return fmt.Errorf("create pending op: op is nil")
	}
	if op.OperationType == "" {
		return fmt.Errorf("create pending op: operation type is required")
	}

	op.ID = ensureID(op.ID)
	if op.State == "" {
		op.State = "pending"
	}
	now := nowUTC()
	op.CreatedAt = now
	op.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO pending_ops(id, operation_type, target_id, state, payload, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
	`, op.ID, op.OperationType, op.TargetID, op.State, op.Payload, fmtTime(op.CreatedAt), fmtTime(op.UpdatedAt))
	if err != nil {
		return fmt.Errorf("create pending op: %w", err)
	}
	return nil
}

func (r *pendingOpRepository) MarkCompleted(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE pending_ops
		SET state = 'completed', updated_at = ?
		WHERE id = ?
	`, fmtTime(nowUTC()), id)
	if err != nil {
		return fmt.Errorf("mark pending op completed: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark pending op completed: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *pendingOpRepository) ListIncomplete(ctx context.Context) ([]PendingOp, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, operation_type, target_id, state, payload, created_at, updated_at
		FROM pending_ops
		WHERE state != 'completed'
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list incomplete pending ops: %w", err)
	}
	defer rows.Close()

	out := []PendingOp{}
	for rows.Next() {
		var (
			op      PendingOp
			created string
			updated string
		)
		if err := rows.Scan(&op.ID, &op.OperationType, &op.TargetID, &op.State, &op.Payload, &created, &updated); err != nil {
			return nil, fmt.Errorf("list incomplete pending ops: scan row: %w", err)
		}
		op.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		op.UpdatedAt, err = parseTime(updated)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list incomplete pending ops: iterate: %w", err)
	}
	return out, nil
}
