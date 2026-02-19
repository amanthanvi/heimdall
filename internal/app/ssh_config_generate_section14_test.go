package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSHConfigGenerateRendersValidOpenSSHBlocksFromVaultHosts(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	hostSvc := NewHostService(store.Hosts, store.Sessions)
	_, err := hostSvc.Create(context.Background(), CreateHostRequest{
		Name:    "prod",
		Address: "10.0.0.10",
		Port:    2222,
		User:    "ubuntu",
		EnvRefs: map[string]string{"proxy_jump": "bastion.internal", "identity_ref": "~/.ssh/id_prod"},
	})
	require.NoError(t, err)
	_, err = hostSvc.Create(context.Background(), CreateHostRequest{
		Name:    "cache",
		Address: "10.0.0.11",
		Port:    22,
		User:    "redis",
	})
	require.NoError(t, err)

	outPath := filepath.Join(t.TempDir(), "generated_config")
	transfer := NewTransferService(store)
	require.NoError(t, transfer.GenerateSSHConfig(context.Background(), outPath))

	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	text := string(raw)

	require.Contains(t, text, "Host cache")
	require.Contains(t, text, "  HostName 10.0.0.11")
	require.Contains(t, text, "  User redis")
	require.Contains(t, text, "  Port 22")

	require.Contains(t, text, "Host prod")
	require.Contains(t, text, "  HostName 10.0.0.10")
	require.Contains(t, text, "  User ubuntu")
	require.Contains(t, text, "  Port 2222")
	require.Contains(t, text, "  ProxyJump bastion.internal")
	require.Contains(t, text, "  IdentityFile ~/.ssh/id_prod")
}
