package storage

import (
	"database/sql"
	"encoding/json"
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

func encodeEnvRefs(envRefs map[string]string) (sql.NullString, error) {
	if len(envRefs) == 0 {
		return sql.NullString{}, nil
	}
	payload, err := json.Marshal(envRefs)
	if err != nil {
		return sql.NullString{}, fmt.Errorf("encode env refs: %w", err)
	}
	return sql.NullString{String: string(payload), Valid: true}, nil
}

func decodeEnvRefs(raw sql.NullString) (map[string]string, error) {
	if !raw.Valid || raw.String == "" {
		return nil, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
		return nil, fmt.Errorf("decode env refs: %w", err)
	}
	return out, nil
}
