package ssh

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type KnownHostsManager struct {
	filePath string
}

func NewKnownHostsManager(homeDir string) *KnownHostsManager {
	path := filepath.Join(homeDir, "ssh", "known_hosts")
	return &KnownHostsManager{filePath: path}
}

func (m *KnownHostsManager) FilePath() string {
	if m == nil {
		return ""
	}
	return m.filePath
}

func (m *KnownHostsManager) TrustHost(host, keyType, fingerprint string) error {
	if m == nil {
		return fmt.Errorf("known_hosts manager is nil")
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(keyType) == "" || strings.TrimSpace(fingerprint) == "" {
		return fmt.Errorf("host, key type, and fingerprint are required")
	}

	if err := os.MkdirAll(filepath.Dir(m.filePath), 0o700); err != nil {
		return fmt.Errorf("trust host: create known_hosts dir: %w", err)
	}
	line := fmt.Sprintf("%s %s %s\n", host, keyType, fingerprint)
	f, err := os.OpenFile(m.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("trust host: open known_hosts file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("trust host: write entry: %w", err)
	}
	return nil
}

func (m *KnownHostsManager) CheckHost(host, keyType, fingerprint string) (KnownHostsResult, error) {
	if m == nil {
		return KnownHostsUnknown, fmt.Errorf("known_hosts manager is nil")
	}
	file, err := os.Open(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return KnownHostsUnknown, nil
		}
		return KnownHostsUnknown, fmt.Errorf("check host: open known_hosts file: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	seenHost := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		if parts[0] != host || parts[1] != keyType {
			continue
		}
		seenHost = true
		if parts[2] == fingerprint {
			return KnownHostsMatch, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return KnownHostsUnknown, fmt.Errorf("check host: read known_hosts file: %w", err)
	}
	if seenHost {
		return KnownHostsMismatch, nil
	}
	return KnownHostsUnknown, nil
}
