package log

import (
	"context"
	"log/slog"
	"strings"
)

var sensitiveFields = map[string]struct{}{
	"secret":      {},
	"token":       {},
	"password":    {},
	"private_key": {},
	"value":       {},
	"passphrase":  {},
	"vmk":         {},
	"kek":         {},
	"dek":         {},
}

type RedactingHandler struct {
	inner slog.Handler
}

func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *RedactingHandler) Handle(ctx context.Context, record slog.Record) (err error) {
	defer func() {
		if r := recover(); r != nil {
			fallback := slog.NewRecord(record.Time, slog.LevelError, "redaction handler panic recovered", record.PC)
			fallback.AddAttrs(slog.String("panic", "[REDACTED]"))
			err = h.inner.Handle(ctx, fallback)
		}
	}()

	redacted := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		redacted.AddAttrs(redactAttr(attr))
		return true
	})
	return h.inner.Handle(ctx, redacted)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		redacted = append(redacted, redactAttr(attr))
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redacted)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(attr slog.Attr) slog.Attr {
	key := strings.ToLower(attr.Key)
	if _, ok := sensitiveFields[key]; ok {
		return slog.String(attr.Key, "[REDACTED]")
	}

	if attr.Value.Kind() == slog.KindGroup {
		group := attr.Value.Group()
		redacted := make([]slog.Attr, 0, len(group))
		for _, nested := range group {
			redacted = append(redacted, redactAttr(nested))
		}
		return slog.Attr{
			Key:   attr.Key,
			Value: slog.GroupValue(redacted...),
		}
	}

	return attr
}
