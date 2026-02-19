package log

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

type RotationConfig struct {
	File      string
	MaxSizeMB int
	MaxFiles  int
}

func NewRotatingWriter(cfg RotationConfig) (*lumberjack.Logger, error) {
	if cfg.File == "" {
		return nil, fmt.Errorf("rotation file path must not be empty")
	}

	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 10
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 5
	}

	if err := os.MkdirAll(filepath.Dir(cfg.File), 0o700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	writer := &lumberjack.Logger{
		Filename:   cfg.File,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxFiles,
		Compress:   false,
	}
	return writer, nil
}
