package ssh

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSHBinaryCheckReturnsPathAndVersionWhenAvailable(t *testing.T) {
	t.Parallel()

	info, err := CheckBinary(BinaryCheckDeps{
		LookPath: func(string) (string, error) { return "/usr/bin/ssh", nil },
		GetVersion: func(string) (string, error) {
			return "OpenSSH_9.6p1, LibreSSL 3.3.6", nil
		},
	})
	require.NoError(t, err)
	require.Equal(t, "/usr/bin/ssh", info.Path)
	require.Equal(t, "OpenSSH_9.6p1, LibreSSL 3.3.6", info.Version)
}

func TestSSHBinaryCheckReturnsExitCode6WhenMissing(t *testing.T) {
	t.Parallel()

	_, err := CheckBinary(BinaryCheckDeps{
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
	})
	require.Error(t, err)
	require.True(t, IsExitCode(err, ExitCodeDependencyUnavailable))
	require.Contains(t, err.Error(), "OpenSSH client not found")
}

func TestSSHBinaryCheckDetectsProxyJumpSupport(t *testing.T) {
	t.Parallel()

	info, err := CheckBinary(BinaryCheckDeps{
		LookPath: func(string) (string, error) { return "/usr/bin/ssh", nil },
		GetVersion: func(string) (string, error) {
			return "OpenSSH_7.3p1", nil
		},
	})
	require.NoError(t, err)
	require.True(t, info.SupportsProxyJump)

	info, err = CheckBinary(BinaryCheckDeps{
		LookPath: func(string) (string, error) { return "/usr/bin/ssh", nil },
		GetVersion: func(string) (string, error) {
			return "OpenSSH_7.2p2", nil
		},
	})
	require.NoError(t, err)
	require.False(t, info.SupportsProxyJump)
}
