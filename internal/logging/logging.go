package logging

import (
	"log/slog"
	"os"

	"github.com/athanvi/heimdall/internal/redact"
)

func New(verbose bool, level redact.Level) *slog.Logger {
	handlerLevel := slog.LevelInfo
	if verbose {
		handlerLevel = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: handlerLevel, ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
		if attr.Value.Kind() == slog.KindString {
			attr.Value = slog.StringValue(redact.String(attr.Value.String(), level))
		}
		return attr
	}})
	return slog.New(handler)
}
