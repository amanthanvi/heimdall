package debug

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type Bundle struct {
	GeneratedAt string         `json:"generated_at"`
	GOOS        string         `json:"goos"`
	GOARCH      string         `json:"goarch"`
	Version     map[string]any `json:"version,omitempty"`
	Daemon      map[string]any `json:"daemon,omitempty"`
	Checks      []Check        `json:"checks,omitempty"`
	Notes       []string       `json:"notes,omitempty"`
}

func NewBundle() Bundle {
	return Bundle{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
	}
}

func WriteBundle(outputPath string, bundle Bundle) error {
	if outputPath == "" {
		return fmt.Errorf("write debug bundle: output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return fmt.Errorf("write debug bundle: create output directory: %w", err)
	}

	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("write debug bundle: marshal json: %w", err)
	}
	if err := os.WriteFile(outputPath, payload, 0o600); err != nil {
		return fmt.Errorf("write debug bundle: %w", err)
	}
	return nil
}
