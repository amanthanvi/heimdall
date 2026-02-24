package sshconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/amanthanvi/heimdall/internal/storage"
)

type SyncService struct {
	hosts  storage.HostRepository
	config config.SSHConfigManagedConfig
}

func NewSyncService(hosts storage.HostRepository, cfg config.SSHConfigManagedConfig) *SyncService {
	return &SyncService{
		hosts:  hosts,
		config: cfg,
	}
}

func (s *SyncService) Sync(ctx context.Context) (string, error) {
	if s == nil || s.hosts == nil {
		return "", fmt.Errorf("ssh config sync: host repository is required")
	}
	fragmentPath, includePath, err := resolvePaths(s.config.Path)
	if err != nil {
		return "", err
	}
	hosts, err := s.hosts.List(ctx, storage.HostFilter{})
	if err != nil {
		return "", fmt.Errorf("ssh config sync: list hosts: %w", err)
	}
	payload := Generate(hosts)
	if err := os.MkdirAll(filepath.Dir(fragmentPath), 0o700); err != nil {
		return "", fmt.Errorf("ssh config sync: create fragment directory: %w", err)
	}
	if err := os.WriteFile(fragmentPath, []byte(payload), 0o600); err != nil {
		return "", fmt.Errorf("ssh config sync: write fragment: %w", err)
	}

	userConfigPath, err := defaultUserSSHConfigPath()
	if err != nil {
		return "", err
	}
	if err := EnsureInclude(userConfigPath, includePath); err != nil {
		return "", err
	}
	return fragmentPath, nil
}

func (s *SyncService) Disable() error {
	_, includePath, err := resolvePaths(s.config.Path)
	if err != nil {
		return err
	}
	userConfigPath, err := defaultUserSSHConfigPath()
	if err != nil {
		return err
	}
	if err := RemoveInclude(userConfigPath, includePath); err != nil {
		return err
	}
	return nil
}

func resolvePaths(configPath string) (string, string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = "~/.ssh/config.d/heimdall.conf"
	}
	expandedPath, err := expandUserPath(configPath)
	if err != nil {
		return "", "", err
	}
	return expandedPath, configPath, nil
}

func expandUserPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("ssh config path is required")
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home: %w", err)
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func defaultUserSSHConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".ssh", "config"), nil
}
