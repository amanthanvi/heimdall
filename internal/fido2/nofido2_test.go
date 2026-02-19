//go:build nofido2 || !fido2

package fido2

import (
	"bytes"
	"testing"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/stretchr/testify/require"
)

func TestNoFIDO2PasskeyCommandsReturnExitCode6WithGuidance(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"enroll", "ls", "rm", "test"} {
		err := PasskeyCommandUnavailable(command)
		require.Error(t, err)
		require.Truef(t, IsExitCode(err, ExitCodeDependencyUnavailable), "command=%s", command)
		require.Contains(t, err.Error(), "install libfido2")
	}

	err := VaultUnlockPasskeyUnavailable()
	require.True(t, IsExitCode(err, ExitCodeDependencyUnavailable))
	require.Contains(t, err.Error(), "passphrase unlock")
}

func TestNoFIDO2PassphraseUnlockStillWorks(t *testing.T) {
	t.Parallel()

	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)
	defer vmk.Destroy()

	vc := crypto.NewVaultCrypto(vmk, "vault-passphrase")
	salt := []byte("0123456789abcdef0123456789abcdef")
	kek, err := crypto.DeriveKEKFromPassphrase([]byte("correct horse battery staple"), salt, crypto.DefaultArgon2Params())
	require.NoError(t, err)

	wrapped, err := vc.WrapVMK(kek, "vault-passphrase", "passphrase")
	require.NoError(t, err)

	commitment := crypto.ComputeCommitmentTag(vmk.Bytes())
	unwrapped, err := crypto.UnwrapVMK(kek, wrapped, commitment)
	require.NoError(t, err)
	defer unwrapped.Destroy()

	require.True(t, bytes.Equal(vmk.Bytes(), unwrapped.Bytes()))
}
