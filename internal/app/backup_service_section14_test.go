package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestBackupCreateWALCheckpointedBeforeCopy(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	secretSvc := NewSecretService(store.Secrets)
	_, err := secretSvc.Create(ctx, CreateSecretRequest{
		Name:  "late-write",
		Value: []byte("value-present-after-checkpoint"),
	})
	require.NoError(t, err)

	backupPath := filepath.Join(t.TempDir(), "vault.hbk")
	svc := NewBackupService(store)
	_, err = svc.Create(ctx, BackupCreateRequest{
		OutputPath:  backupPath,
		Passphrase:  []byte("backup-pass"),
		KnownHosts:  createKnownHostsFixture(t),
		ConfigPath:  createConfigFixture(t),
		Unencrypted: false,
	})
	require.NoError(t, err)

	payload, err := readBackupPayload(backupPath, []byte("backup-pass"))
	require.NoError(t, err)

	entries, err := extractTarGzEntries(payload)
	require.NoError(t, err)
	require.Contains(t, entries, backupVaultDBFileName)

	dbPath := filepath.Join(t.TempDir(), "restored-vault.db")
	require.NoError(t, os.WriteFile(dbPath, entries[backupVaultDBFileName], 0o600))

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE name = ?`, "late-write").Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestBackupCreateEncryptedArchiveContainsVaultKnownHostsAndConfig(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	backupPath := filepath.Join(t.TempDir(), "vault.hbk")
	svc := NewBackupService(store)
	_, err := svc.Create(context.Background(), BackupCreateRequest{
		OutputPath: backupPath,
		Passphrase: []byte("backup-pass"),
		KnownHosts: createKnownHostsFixture(t),
		ConfigPath: createConfigFixture(t),
	})
	require.NoError(t, err)

	payload, err := readBackupPayload(backupPath, []byte("backup-pass"))
	require.NoError(t, err)
	entries, err := extractTarGzEntries(payload)
	require.NoError(t, err)
	require.Contains(t, entries, backupVaultDBFileName)
	require.Contains(t, entries, backupKnownHostsFileName)
	require.Contains(t, entries, backupConfigFileName)
}

func TestBackupCreateManifestIncludesVersionChecksumsAndTimestamp(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	backupPath := filepath.Join(t.TempDir(), "vault.hbk")
	svc := NewBackupService(store)
	manifest, err := svc.Create(context.Background(), BackupCreateRequest{
		OutputPath: backupPath,
		Passphrase: []byte("backup-pass"),
		KnownHosts: createKnownHostsFixture(t),
		ConfigPath: createConfigFixture(t),
	})
	require.NoError(t, err)
	require.Equal(t, 1, manifest.Version)
	require.NotEmpty(t, manifest.CreatedAt)
	require.NotEmpty(t, manifest.Files[backupVaultDBFileName].SHA256)
	require.NotEmpty(t, manifest.Files[backupKnownHostsFileName].SHA256)
	require.NotEmpty(t, manifest.Files[backupConfigFileName].SHA256)

	payload, err := readBackupPayload(backupPath, []byte("backup-pass"))
	require.NoError(t, err)
	entries, err := extractTarGzEntries(payload)
	require.NoError(t, err)

	var stored BackupManifest
	require.NoError(t, json.Unmarshal(entries[backupManifestFileName], &stored))
	require.Equal(t, manifest.Version, stored.Version)
	require.Equal(t, manifest.Files, stored.Files)
}

func TestBackupRestoreCorrectPassphraseRestoresData(t *testing.T) {
	t.Parallel()

	sourceStore, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	secretSvc := NewSecretService(sourceStore.Secrets)
	_, err := secretSvc.Create(context.Background(), CreateSecretRequest{
		Name:  "restore-me",
		Value: []byte("backed-up-value"),
	})
	require.NoError(t, err)

	backupPath := filepath.Join(t.TempDir(), "vault.hbk")
	svc := NewBackupService(sourceStore)
	_, err = svc.Create(context.Background(), BackupCreateRequest{
		OutputPath: backupPath,
		Passphrase: []byte("backup-pass"),
		KnownHosts: createKnownHostsFixture(t),
		ConfigPath: createConfigFixture(t),
	})
	require.NoError(t, err)

	targetVaultPath := filepath.Join(t.TempDir(), "restored.db")
	_, err = svc.Restore(context.Background(), BackupRestoreRequest{
		InputPath:       backupPath,
		Passphrase:      []byte("backup-pass"),
		TargetVaultPath: targetVaultPath,
		Confirm:         true,
		Overwrite:       true,
	})
	require.NoError(t, err)

	restoredStore := openStoreWithExistingVMK(t, targetVaultPath, vmk)
	restoredSecret, err := restoredStore.Secrets.Get(context.Background(), "restore-me")
	require.NoError(t, err)
	require.Equal(t, []byte("backed-up-value"), restoredSecret.Value)
	require.NoError(t, restoredStore.Close())
}

func TestBackupRestoreWrongPassphraseFails(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	backupPath := filepath.Join(t.TempDir(), "vault.hbk")
	svc := NewBackupService(store)
	_, err := svc.Create(context.Background(), BackupCreateRequest{
		OutputPath: backupPath,
		Passphrase: []byte("correct-pass"),
		KnownHosts: createKnownHostsFixture(t),
		ConfigPath: createConfigFixture(t),
	})
	require.NoError(t, err)

	_, err = svc.Restore(context.Background(), BackupRestoreRequest{
		InputPath:       backupPath,
		Passphrase:      []byte("wrong-pass"),
		TargetVaultPath: filepath.Join(t.TempDir(), "restore.db"),
		Confirm:         true,
		Overwrite:       true,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "passphrase")
}

func TestBackupRestoreTamperedArchiveDetected(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	backupPath := filepath.Join(t.TempDir(), "vault.hbk")
	svc := NewBackupService(store)
	_, err := svc.Create(context.Background(), BackupCreateRequest{
		OutputPath: backupPath,
		Passphrase: []byte("correct-pass"),
		KnownHosts: createKnownHostsFixture(t),
		ConfigPath: createConfigFixture(t),
	})
	require.NoError(t, err)

	raw, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	var envelope backupEnvelope
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.NotEmpty(t, envelope.Ciphertext)
	envelope.Ciphertext[0] ^= 0xFF
	tampered, err := json.Marshal(envelope)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(backupPath, tampered, 0o600))

	_, err = svc.Restore(context.Background(), BackupRestoreRequest{
		InputPath:       backupPath,
		Passphrase:      []byte("correct-pass"),
		TargetVaultPath: filepath.Join(t.TempDir(), "restore.db"),
		Confirm:         true,
		Overwrite:       true,
	})
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "authentication")
}

func TestBackupRestoreOverwriteRequiresConfirmationAndReauth(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	backupPath := filepath.Join(t.TempDir(), "vault.hbk")
	svc := NewBackupService(store)
	_, err := svc.Create(context.Background(), BackupCreateRequest{
		OutputPath: backupPath,
		Passphrase: []byte("correct-pass"),
		KnownHosts: createKnownHostsFixture(t),
		ConfigPath: createConfigFixture(t),
	})
	require.NoError(t, err)

	targetPath := filepath.Join(t.TempDir(), "existing.db")
	require.NoError(t, os.WriteFile(targetPath, []byte("existing"), 0o600))

	_, err = svc.Restore(context.Background(), BackupRestoreRequest{
		InputPath:       backupPath,
		Passphrase:      []byte("correct-pass"),
		TargetVaultPath: targetPath,
		Overwrite:       true,
		Confirm:         false,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "confirmation")

	_, err = svc.Restore(context.Background(), BackupRestoreRequest{
		InputPath:       backupPath,
		Passphrase:      []byte("correct-pass"),
		TargetVaultPath: targetPath,
		Overwrite:       true,
		Confirm:         true,
	})
	require.ErrorIs(t, err, ErrReauthRequired)

	_, err = svc.Restore(WithReauth(context.Background()), BackupRestoreRequest{
		InputPath:       backupPath,
		Passphrase:      []byte("correct-pass"),
		TargetVaultPath: targetPath,
		Overwrite:       true,
		Confirm:         true,
	})
	require.NoError(t, err)
}

func TestBackupCreateUnencryptedRequiresYesAndReauth(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	backupPath := filepath.Join(t.TempDir(), "vault-unencrypted.tar.gz")
	svc := NewBackupService(store)
	_, err := svc.Create(context.Background(), BackupCreateRequest{
		OutputPath:   backupPath,
		KnownHosts:   createKnownHostsFixture(t),
		ConfigPath:   createConfigFixture(t),
		Unencrypted:  true,
		ConfirmNoEnc: false,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "--yes")

	_, err = svc.Create(context.Background(), BackupCreateRequest{
		OutputPath:   backupPath,
		KnownHosts:   createKnownHostsFixture(t),
		ConfigPath:   createConfigFixture(t),
		Unencrypted:  true,
		ConfirmNoEnc: true,
	})
	require.ErrorIs(t, err, ErrReauthRequired)

	_, err = svc.Create(WithReauth(context.Background()), BackupCreateRequest{
		OutputPath:   backupPath,
		KnownHosts:   createKnownHostsFixture(t),
		ConfigPath:   createConfigFixture(t),
		Unencrypted:  true,
		ConfirmNoEnc: true,
	})
	require.NoError(t, err)

	raw, err := os.ReadFile(backupPath)
	require.NoError(t, err)
	require.Greater(t, len(raw), 2)
	require.Equal(t, byte(0x1f), raw[0])
	require.Equal(t, byte(0x8b), raw[1])
}

func TestLargeFileBackupIncludesAndRestoresFiftyMiBSecret(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	large := bytes.Repeat([]byte("a"), 50*1024*1024)
	secretSvc := NewSecretService(store.Secrets)
	_, err := secretSvc.Create(context.Background(), CreateSecretRequest{
		Name:  "large-secret",
		Value: large,
	})
	require.NoError(t, err)

	backupPath := filepath.Join(t.TempDir(), "large.hbk")
	svc := NewBackupService(store)
	_, err = svc.Create(context.Background(), BackupCreateRequest{
		OutputPath: backupPath,
		Passphrase: []byte("backup-pass"),
		KnownHosts: createKnownHostsFixture(t),
		ConfigPath: createConfigFixture(t),
	})
	require.NoError(t, err)

	restoredPath := filepath.Join(t.TempDir(), "restored-large.db")
	_, err = svc.Restore(context.Background(), BackupRestoreRequest{
		InputPath:       backupPath,
		Passphrase:      []byte("backup-pass"),
		TargetVaultPath: restoredPath,
		Confirm:         true,
		Overwrite:       true,
	})
	require.NoError(t, err)

	restoredStore := openStoreWithExistingVMK(t, restoredPath, vmk)
	secret, err := restoredStore.Secrets.Get(context.Background(), "large-secret")
	require.NoError(t, err)
	require.Equal(t, len(large), len(secret.Value))
	require.Equal(t, large[:1024], secret.Value[:1024])
	require.Equal(t, large[len(large)-1024:], secret.Value[len(secret.Value)-1024:])
	require.NoError(t, restoredStore.Close())
}

func openStoreWithExistingVMK(t *testing.T, path string, vmk *memguard.LockedBuffer) *storage.Store {
	t.Helper()

	vc := crypto.NewVaultCrypto(vmk, "app-test-vault")
	store, err := storage.Open(path, "app-test-vault", vc)
	require.NoError(t, err)
	return store
}

func createKnownHostsFixture(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte("example.com ssh-ed25519 AAAABase"), 0o600))
	return path
}

func createConfigFixture(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("[vault]\nauto_lock_timeout = \"5m\"\n"), 0o600))
	return path
}
