package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func ensureID(id string) string {
	if id != "" {
		return id
	}
	return uuid.NewString()
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

func fmtTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", raw, err)
	}
	return t, nil
}

func parseNullableTime(raw sql.NullString) (*time.Time, error) {
	if !raw.Valid || raw.String == "" {
		return nil, nil
	}
	t, err := parseTime(raw.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
