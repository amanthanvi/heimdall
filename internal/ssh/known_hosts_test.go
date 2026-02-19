package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKnownHostsManagerTrustHostWritesManagedFile(t *testing.T) {
	t.Parallel()

	mgr := NewKnownHostsManager(t.TempDir())
	err := mgr.TrustHost("prod.example", "ssh-ed25519", "SHA256:abc")
	require.NoError(t, err)
	require.FileExists(t, mgr.FilePath())
}

func TestKnownHostsManagerCheckHostReturnsMatchMismatchUnknown(t *testing.T) {
	t.Parallel()

	mgr := NewKnownHostsManager(t.TempDir())
	err := mgr.TrustHost("prod.example", "ssh-ed25519", "SHA256:abc")
	require.NoError(t, err)

	result, err := mgr.CheckHost("prod.example", "ssh-ed25519", "SHA256:abc")
	require.NoError(t, err)
	require.Equal(t, KnownHostsMatch, result)

	result, err = mgr.CheckHost("prod.example", "ssh-ed25519", "SHA256:def")
	require.NoError(t, err)
	require.Equal(t, KnownHostsMismatch, result)

	result, err = mgr.CheckHost("new.example", "ssh-ed25519", "SHA256:xyz")
	require.NoError(t, err)
	require.Equal(t, KnownHostsUnknown, result)
}

func TestKnownHostsManagerChangedHostKeyDetectedAndRejected(t *testing.T) {
	t.Parallel()

	mgr := NewKnownHostsManager(t.TempDir())
	err := mgr.TrustHost("prod.example", "ssh-rsa", "SHA256:old")
	require.NoError(t, err)

	result, err := mgr.CheckHost("prod.example", "ssh-rsa", "SHA256:new")
	require.NoError(t, err)
	require.Equal(t, KnownHostsMismatch, result)
}
