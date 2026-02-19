package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/amanthanvi/heimdall/internal/storage"
)

const defaultRecordResult = "success"

type Service struct {
	repo     storage.AuditRepository
	mu       sync.Mutex
	chainTip string
}

func NewService(repo storage.AuditRepository) (*Service, error) {
	if repo == nil {
		return nil, fmt.Errorf("new audit service: repository is nil")
	}

	ctx := context.Background()
	tip, err := repo.ChainTip(ctx)
	if err != nil {
		return nil, fmt.Errorf("new audit service: read chain tip: %w", err)
	}

	return &Service{
		repo:     repo,
		chainTip: tip,
	}, nil
}

func (s *Service) Record(ctx context.Context, event Event) error {
	if strings.TrimSpace(event.Action) == "" {
		return fmt.Errorf("record audit event: action is required")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	if event.Result == "" {
		event.Result = defaultRecordResult
	}

	detailsJSON, err := canonicalizeDetails(event.Details)
	if err != nil {
		return fmt.Errorf("record audit event: canonicalize details: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	payload := chainEvent{
		Timestamp:  event.Timestamp.Format(time.RFC3339Nano),
		Action:     event.Action,
		TargetType: event.TargetType,
		TargetID:   event.TargetID,
		Result:     event.Result,
		Details:    detailsJSON,
	}

	canonicalPayload, err := canonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("record audit event: canonical payload: %w", err)
	}

	hash := chainHashHex(s.chainTip, canonicalPayload)
	entry := &storage.AuditEvent{
		Action:      event.Action,
		EventType:   event.Action,
		Actor:       event.Actor,
		Metadata:    string(detailsJSON),
		TargetType:  event.TargetType,
		TargetID:    event.TargetID,
		Result:      event.Result,
		DetailsJSON: string(detailsJSON),
		PrevHash:    s.chainTip,
		EventHash:   hash,
		CreatedAt:   event.Timestamp,
	}

	if err := s.repo.AppendWithTip(ctx, entry, hash); err != nil {
		return fmt.Errorf("record audit event: append: %w", err)
	}
	s.chainTip = hash
	return nil
}

func (s *Service) Verify(ctx context.Context) (*VerifyResult, error) {
	events, err := s.repo.List(ctx, storage.AuditFilter{Limit: 1_000_000})
	if err != nil {
		return nil, fmt.Errorf("verify audit chain: list events: %w", err)
	}

	prev := ""
	for _, event := range events {
		payload, err := payloadForStoredEvent(event)
		if err != nil {
			return nil, fmt.Errorf("verify audit chain: event %s payload: %w", event.ID, err)
		}
		expected := chainHashHex(prev, payload)
		if subtle.ConstantTimeCompare([]byte(event.PrevHash), []byte(prev)) != 1 ||
			subtle.ConstantTimeCompare([]byte(event.EventHash), []byte(expected)) != 1 {
			return &VerifyResult{
				Valid:      false,
				EventCount: len(events),
				ChainTip:   prev,
				Error:      fmt.Sprintf("hash mismatch at event %s", event.ID),
			}, nil
		}
		prev = event.EventHash
	}

	storedTip, err := s.repo.ChainTip(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify audit chain: read chain tip: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(storedTip), []byte(prev)) != 1 {
		return &VerifyResult{
			Valid:      false,
			EventCount: len(events),
			ChainTip:   prev,
			Error:      "hash mismatch at chain tip",
		}, nil
	}

	return &VerifyResult{
		Valid:      true,
		EventCount: len(events),
		ChainTip:   prev,
	}, nil
}

func (s *Service) List(ctx context.Context, filter Filter) ([]RecordedEvent, error) {
	events, err := s.repo.List(ctx, storage.AuditFilter{
		Action:   filter.Action,
		TargetID: filter.TargetID,
		Since:    filter.Since,
		Until:    filter.Until,
		Limit:    filter.Limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}

	out := make([]RecordedEvent, 0, len(events))
	for _, event := range events {
		out = append(out, RecordedEvent{
			ID:          event.ID,
			Timestamp:   event.CreatedAt,
			Action:      firstNonEmpty(event.Action, event.EventType),
			TargetType:  event.TargetType,
			TargetID:    event.TargetID,
			Result:      event.Result,
			DetailsJSON: event.DetailsJSON,
			PrevHash:    event.PrevHash,
			EventHash:   event.EventHash,
		})
	}
	return out, nil
}

type chainEvent struct {
	Timestamp  string          `json:"timestamp"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type,omitempty"`
	TargetID   string          `json:"target_id,omitempty"`
	Result     string          `json:"result"`
	Details    json.RawMessage `json:"details"`
}

func payloadForStoredEvent(event storage.AuditEvent) ([]byte, error) {
	details := strings.TrimSpace(event.DetailsJSON)
	if details == "" {
		details = "{}"
	}

	var detailsRaw json.RawMessage
	if !json.Valid([]byte(details)) {
		return nil, fmt.Errorf("invalid details json")
	}
	detailsRaw = json.RawMessage(details)

	payload := chainEvent{
		Timestamp:  event.CreatedAt.UTC().Format(time.RFC3339Nano),
		Action:     firstNonEmpty(event.Action, event.EventType),
		TargetType: event.TargetType,
		TargetID:   event.TargetID,
		Result:     firstNonEmpty(event.Result, defaultRecordResult),
		Details:    detailsRaw,
	}
	return canonicalJSON(payload)
}

func chainHashHex(prevHash string, canonicalPayload []byte) string {
	input := append([]byte(prevHash), canonicalPayload...)
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

func canonicalizeDetails(details any) (json.RawMessage, error) {
	if details == nil {
		return json.RawMessage(`{}`), nil
	}

	raw, err := canonicalJSON(details)
	if err != nil {
		return nil, err
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode details json: %w", err)
	}

	sanitized := sanitizeValue(decoded)
	out, err := canonicalJSONFromDecoded(sanitized)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return json.RawMessage(out), nil
}

func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		clean := make(map[string]any, len(typed))
		for key, nested := range typed {
			if isSensitiveDetailKey(key) {
				continue
			}
			clean[key] = sanitizeValue(nested)
		}
		return clean
	case []any:
		out := make([]any, 0, len(typed))
		for _, nested := range typed {
			out = append(out, sanitizeValue(nested))
		}
		return out
	default:
		return value
	}
}

func isSensitiveDetailKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, pattern := range sensitiveDetailPatterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}
	return false
}

var sensitiveDetailPatterns = []string{
	"secret", "passphrase", "private_key", "token",
	"password", "credential", "api_key", "access_token",
	"refresh_token", "secret_key", "ssh_key", "hmac",
	"kek", "dek", "vmk", "master_key",
}

func canonicalJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("canonical json: value is nil")
	}

	root := reflect.ValueOf(v)
	for root.Kind() == reflect.Pointer {
		if root.IsNil() {
			return nil, fmt.Errorf("canonical json: nil pointer")
		}
		root = root.Elem()
	}
	if root.Kind() == reflect.Map {
		return nil, fmt.Errorf("canonical json: map input is not allowed")
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical json: marshal: %w", err)
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("canonical json: unmarshal: %w", err)
	}

	return canonicalJSONFromDecoded(decoded)
}

func canonicalJSONFromDecoded(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonicalJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeCanonicalJSON(buf *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyBytes, err := json.Marshal(key)
			if err != nil {
				return fmt.Errorf("canonical json: marshal key: %w", err)
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')
			if err := encodeCanonicalJSON(buf, typed[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, elem := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonicalJSON(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return fmt.Errorf("canonical json: marshal scalar: %w", err)
		}
		buf.Write(raw)
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
