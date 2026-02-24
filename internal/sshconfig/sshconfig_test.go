package sshconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/stretchr/testify/require"
)

func TestGenerateDeterministicSortedOutput(t *testing.T) {
	t.Parallel()

	hosts := []storage.Host{
		{
			Name:    "zeta",
			Address: "10.0.0.20",
			Port:    22,
			User:    "ubuntu",
		},
		{
			Name:         "alpha",
			Address:      "10.0.0.10",
			Port:         2222,
			User:         "root",
			IdentityFile: "~/.ssh/id_ed25519",
			ProxyJump:    "bastion",
		},
	}

	first := Generate(hosts)
	second := Generate(hosts)
	require.Equal(t, first, second)
	require.Contains(t, first, "Host alpha\n")
	require.Contains(t, first, "  Port 2222\n")
	require.Contains(t, first, "  ProxyJump bastion\n")
	require.Contains(t, first, "  IdentityFile ~/.ssh/id_ed25519\n")
	require.Contains(t, first, "  IdentitiesOnly yes\n")
	require.Contains(t, first, "Host zeta\n")
	require.Less(t, indexOf(t, first, "Host alpha"), indexOf(t, first, "Host zeta"))
}

func TestEnsureIncludeIdempotentAndRemovable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	includePath := "~/.ssh/config.d/heimdall.conf"

	require.NoError(t, EnsureInclude(configPath, includePath))
	require.NoError(t, EnsureInclude(configPath, includePath))

	raw, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, "Include ~/.ssh/config.d/heimdall.conf\n", string(raw))

	require.NoError(t, RemoveInclude(configPath, includePath))
	raw, err = os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, "", string(raw))
}

func TestSyncWritesFragmentAndInclude(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo := &stubHostRepo{
		items: []storage.Host{
			{Name: "prod", Address: "10.0.0.10", Port: 22, User: "ubuntu"},
		},
	}

	service := NewSyncService(repo, config.SSHConfigManagedConfig{
		Enabled:  true,
		Path:     "~/.ssh/config.d/heimdall.conf",
		AutoSync: true,
	})
	path, err := service.Sync(context.Background())
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".ssh", "config.d", "heimdall.conf"), path)

	fragment, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(fragment), "Host prod")

	sshConfigPath := filepath.Join(home, ".ssh", "config")
	sshConfig, err := os.ReadFile(sshConfigPath)
	require.NoError(t, err)
	require.Contains(t, string(sshConfig), "Include ~/.ssh/config.d/heimdall.conf")

	require.NoError(t, service.Disable())
	sshConfig, err = os.ReadFile(sshConfigPath)
	require.NoError(t, err)
	require.NotContains(t, string(sshConfig), "Include ~/.ssh/config.d/heimdall.conf")
}

func indexOf(t *testing.T, content, target string) int {
	t.Helper()
	idx := -1
	for i := 0; i+len(target) <= len(content); i++ {
		if content[i:i+len(target)] == target {
			idx = i
			break
		}
	}
	require.NotEqual(t, -1, idx)
	return idx
}

type stubHostRepo struct {
	items []storage.Host
}

func (s *stubHostRepo) Create(context.Context, *storage.Host) error { return nil }

func (s *stubHostRepo) Get(context.Context, string) (*storage.Host, error) {
	return nil, storage.ErrNotFound
}

func (s *stubHostRepo) List(context.Context, storage.HostFilter) ([]storage.Host, error) {
	return append([]storage.Host(nil), s.items...), nil
}

func (s *stubHostRepo) Update(context.Context, *storage.Host) error { return nil }

func (s *stubHostRepo) Delete(context.Context, string) error { return nil }

func (s *stubHostRepo) AddTag(context.Context, string, string) error { return nil }

func (s *stubHostRepo) RemoveTag(context.Context, string, string) error { return nil }
