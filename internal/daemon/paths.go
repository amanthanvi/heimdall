package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/amanthanvi/heimdall/internal/config"
)

const daemonInfoFile = "daemon.info"

func resolveHomeDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if env := os.Getenv("HEIMDALL_HOME"); env != "" {
		return env, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}

	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Heimdall"), nil
	}
	dataHome := filepath.Join(home, ".local", "share")
	if xdgDataHome := os.Getenv("XDG_DATA_HOME"); xdgDataHome != "" {
		dataHome = xdgDataHome
	}
	return filepath.Join(dataHome, "heimdall"), nil
}

func resolveRuntimeDir(cfg config.Config, override string) string {
	if override != "" {
		return override
	}
	if cfg.Daemon.SocketDir != "" {
		return cfg.Daemon.SocketDir
	}
	if runtime.GOOS == "darwin" {
		tmp := os.Getenv("TMPDIR")
		if tmp == "" {
			tmp = os.TempDir()
		}
		return filepath.Join(tmp, "heimdall")
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	return filepath.Join(runtimeDir, "heimdall")
}

func validateUNIXSocketPath(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if len(path) >= 104 {
		return fmt.Errorf("socket path too long for macOS: %d bytes", len(path))
	}
	return nil
}

func readInfo(path string) (Info, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Info{}, err
	}
	var info Info
	if err := json.Unmarshal(data, &info); err != nil {
		return Info{}, fmt.Errorf("decode daemon info: %w", err)
	}
	return info, nil
}

func writeInfo(homeDir string, info Info) error {
	if homeDir == "" {
		return fmt.Errorf("write daemon info: empty home dir")
	}
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return fmt.Errorf("write daemon info: create home dir: %w", err)
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = time.Now().UTC()
	}
	info.StartedAt = info.StartedAt.UTC()

	payload, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("write daemon info: encode: %w", err)
	}
	infoPath := filepath.Join(homeDir, daemonInfoFile)
	if err := os.WriteFile(infoPath, payload, 0o600); err != nil {
		return fmt.Errorf("write daemon info: %w", err)
	}
	return nil
}

func removeIfExists(path string) error {
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("remove path %q: %w", path, err)
}

func trimPSOutput(raw string) string {
	return strings.TrimSpace(raw)
}
