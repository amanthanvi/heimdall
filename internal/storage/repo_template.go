package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/amanthanvi/heimdall/internal/crypto"
)

type templateRepository struct {
	db *sql.DB
	vc *crypto.VaultCrypto
}

func (r *templateRepository) Create(ctx context.Context, template *Template) error {
	if template == nil {
		return fmt.Errorf("create template: template is nil")
	}
	if template.Name == "" {
		return fmt.Errorf("create template: name is required")
	}

	template.ID = ensureID(template.ID)
	now := nowUTC()
	template.CreatedAt = now
	template.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO templates(id, name, content, created_at, updated_at, deleted_at)
		VALUES(?, ?, ?, ?, ?, NULL)
	`, template.ID, template.Name, template.Content, fmtTime(template.CreatedAt), fmtTime(template.UpdatedAt))
	if err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	return nil
}

func (r *templateRepository) Get(ctx context.Context, name string) (*Template, error) {
	var (
		t       Template
		created string
		updated string
		deleted sql.NullString
	)
	if err := r.db.QueryRowContext(ctx, `
		SELECT id, name, content, created_at, updated_at, deleted_at
		FROM templates
		WHERE name = ? AND deleted_at IS NULL
	`, name).Scan(&t.ID, &t.Name, &t.Content, &created, &updated, &deleted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get template: %w", err)
	}

	var err error
	t.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	t.UpdatedAt, err = parseTime(updated)
	if err != nil {
		return nil, err
	}
	t.DeletedAt, err = parseNullableTime(deleted)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *templateRepository) List(ctx context.Context) ([]Template, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, content, created_at, updated_at, deleted_at
		FROM templates
		WHERE deleted_at IS NULL
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	items := []Template{}
	for rows.Next() {
		var (
			t       Template
			created string
			updated string
			deleted sql.NullString
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.Content, &created, &updated, &deleted); err != nil {
			return nil, fmt.Errorf("list templates: scan row: %w", err)
		}
		t.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		t.UpdatedAt, err = parseTime(updated)
		if err != nil {
			return nil, err
		}
		t.DeletedAt, err = parseNullableTime(deleted)
		if err != nil {
			return nil, err
		}
		items = append(items, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list templates: iterate: %w", err)
	}
	return items, nil
}

func (r *templateRepository) Update(ctx context.Context, template *Template) error {
	if template == nil {
		return fmt.Errorf("update template: template is nil")
	}
	if template.ID == "" {
		return fmt.Errorf("update template: id is required")
	}
	template.UpdatedAt = nowUTC()

	result, err := r.db.ExecContext(ctx, `
		UPDATE templates
		SET name = ?, content = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, template.Name, template.Content, fmtTime(template.UpdatedAt), template.ID)
	if err != nil {
		return fmt.Errorf("update template: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update template: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *templateRepository) Delete(ctx context.Context, name string) error {
	now := fmtTime(nowUTC())
	result, err := r.db.ExecContext(ctx, `
		UPDATE templates
		SET deleted_at = ?, updated_at = ?
		WHERE name = ? AND deleted_at IS NULL
	`, now, now, name)
	if err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete template: rows affected: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
