package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyBackupRestorePendingReturnsFalseWhenNoPendingRestoreExists(t *testing.T) {
	t.Parallel()

	vaultPath := filepath.Join(t.TempDir(), "vault.db")
	applied, err := ApplyBackupRestorePending(vaultPath)
	require.NoError(t, err)
	require.False(t, applied)
}

func TestApplyBackupRestorePendingReplacesExistingVaultAndRemovesSidecars(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.db")
	pendingPath := BackupRestorePendingPath(vaultPath)

	require.NoError(t, os.WriteFile(vaultPath, []byte("old-vault"), 0o600))
	require.NoError(t, os.WriteFile(vaultPath+"-wal", []byte("old-wal"), 0o600))
	require.NoError(t, os.WriteFile(vaultPath+"-shm", []byte("old-shm"), 0o600))
	require.NoError(t, os.WriteFile(pendingPath, []byte("new-vault"), 0o600))

	applied, err := ApplyBackupRestorePending(vaultPath)
	require.NoError(t, err)
	require.True(t, applied)

	raw, err := os.ReadFile(vaultPath)
	require.NoError(t, err)
	require.Equal(t, "new-vault", string(raw))
	_, err = os.Stat(pendingPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(vaultPath + "-wal")
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(vaultPath + "-shm")
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(vaultPath + ".restore-old")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRemoveBackupRestorePendingRemovesPendingFilesAndSidecars(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.db")
	pendingPath := BackupRestorePendingPath(vaultPath)

	require.NoError(t, os.WriteFile(pendingPath, []byte("new-vault"), 0o600))
	require.NoError(t, os.WriteFile(pendingPath+"-wal", []byte("pending-wal"), 0o600))
	require.NoError(t, os.WriteFile(pendingPath+"-shm", []byte("pending-shm"), 0o600))

	require.NoError(t, RemoveBackupRestorePending(vaultPath))

	_, err := os.Stat(pendingPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(pendingPath + "-wal")
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(pendingPath + "-shm")
	require.ErrorIs(t, err, os.ErrNotExist)
}
