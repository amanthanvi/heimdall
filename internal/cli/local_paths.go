package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/amanthanvi/heimdall/internal/daemon"
)

const daemonInfoFilename = "daemon.info"

func resolveVaultPath(globals *GlobalOptions) (string, error) {
	if globals != nil && globals.VaultPath != "" {
		return filepath.Clean(globals.VaultPath), nil
	}
	if value := os.Getenv("HEIMDALL_VAULT_PATH"); value != "" {
		return filepath.Clean(value), nil
	}
	home, err := resolveHeimdallHomePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "vault.db"), nil
}

func resolveConfigPath(globals *GlobalOptions) (string, error) {
	if globals != nil && globals.ConfigPath != "" {
		return filepath.Clean(globals.ConfigPath), nil
	}
	if value := os.Getenv("HEIMDALL_CONFIG_PATH"); value != "" {
		return filepath.Clean(value), nil
	}

	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(userHome, "Library", "Application Support", "Heimdall", "config.toml"), nil
	}

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(userHome, ".config")
	}
	return filepath.Join(configHome, "heimdall", "config.toml"), nil
}

func resolveHeimdallHomePath() (string, error) {
	if value := os.Getenv("HEIMDALL_HOME"); value != "" {
		return filepath.Clean(value), nil
	}

	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve heimdall home: %w", err)
	}

	if runtime.GOOS == "darwin" {
		return filepath.Join(userHome, "Library", "Application Support", "Heimdall"), nil
	}

	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		dataHome = filepath.Join(userHome, ".local", "share")
	}
	return filepath.Join(dataHome, "heimdall"), nil
}

func resolveDaemonInfoPath() (string, error) {
	home, err := resolveHeimdallHomePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, daemonInfoFilename), nil
}

func readDaemonInfoFile() (daemon.Info, error) {
	infoPath, err := resolveDaemonInfoPath()
	if err != nil {
		return daemon.Info{}, err
	}

	data, err := os.ReadFile(infoPath)
	if err != nil {
		return daemon.Info{}, err
	}

	var info daemon.Info
	if err := json.Unmarshal(data, &info); err != nil {
		return daemon.Info{}, fmt.Errorf("read daemon info: decode %q: %w", infoPath, err)
	}
	return info, nil
}

func removeDaemonInfoFile() error {
	infoPath, err := resolveDaemonInfoPath()
	if err != nil {
		return err
	}
	if err := os.Remove(infoPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove daemon info %q: %w", infoPath, err)
	}
	return nil
}

func processIsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
