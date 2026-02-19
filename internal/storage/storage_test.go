package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestRunMigrationsAppliesAllSequentially(t *testing.T) {
	t.Parallel()

	db := openRawTestDB(t)
	defer closeNoErr(t, db)

	err := RunMigrations(db, DefaultMigrations())
	require.NoError(t, err)

	require.Equal(t, CurrentSchemaVersion(), mustSchemaVersion(t, db))

	expected := []string{
		"vault_meta",
		"hosts",
		"host_tags",
		"identities",
		"secrets",
		"passkey_enrollments",
		"audit_events",
		"session_history",
		"templates",
		"pending_ops",
		"schema_migrations",
	}
	for _, table := range expected {
		require.Truef(t, tableExists(t, db, table), "expected table %s to exist", table)
	}
}

func TestRunMigrationsIsAtomic(t *testing.T) {
	t.Parallel()

	db := openRawTestDB(t)
	defer closeNoErr(t, db)

	migrations := []Migration{
		{
			Version:     1,
			Description: "create a",
			Up: func(tx *sql.Tx) error {
				_, err := tx.Exec(`CREATE TABLE test_a (id TEXT PRIMARY KEY)`)
				return err
			},
		},
		{
			Version:     2,
			Description: "create b then fail",
			Up: func(tx *sql.Tx) error {
				if _, err := tx.Exec(`CREATE TABLE test_b (id TEXT PRIMARY KEY)`); err != nil {
					return err
				}
				return errors.New("boom")
			},
		},
	}

	err := RunMigrations(db, migrations)
	require.Error(t, err)
	require.Equal(t, 1, mustSchemaVersion(t, db))
	require.True(t, tableExists(t, db, "test_a"))
	require.False(t, tableExists(t, db, "test_b"))
}

func TestOpenRefusesNewerSchemaVersion(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	require.NoError(t, RunMigrations(db, DefaultMigrations()))
	_, err = db.Exec(`UPDATE vault_meta SET value = ? WHERE key = 'schema_version'`, CurrentSchemaVersion()+1)
	require.NoError(t, err)
	closeNoErr(t, db)

	vc, _ := newTestVaultCrypto(t)
	store, err := Open(path, "vault-test", vc)
	if store != nil {
		t.Cleanup(func() { _ = store.Close() })
	}
	require.ErrorIs(t, err, ErrSchemaTooNew)
}

func TestRollbackProtectionPreUnlockRejectsDowngrade(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	home := t.TempDir()
	writeVersionFile(t, home, 2)
	require.NoError(t, store.setVersionCounter(context.Background(), 1))

	err := store.VerifyRollbackPreUnlock(home)
	require.ErrorIs(t, err, ErrRollbackDetected)
}

func TestRollbackProtectionPostUnlockDetectsTamperedVersionCounter(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	err := store.SealVersionCounter(context.Background(), vmk.Bytes())
	require.NoError(t, err)

	_, err = store.DB().Exec(`UPDATE vault_meta SET value = '999' WHERE key = 'version_counter'`)
	require.NoError(t, err)

	err = store.VerifyRollbackPostUnlock(context.Background(), vmk.Bytes())
	require.ErrorIs(t, err, ErrRollbackDetected)
}

func TestHostCRUD(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	host := &Host{Name: "prod", Address: "10.0.0.10", Port: 22, User: "root"}
	require.NoError(t, store.Hosts.Create(ctx, host))
	require.NotEmpty(t, host.ID)

	loaded, err := store.Hosts.Get(ctx, host.Name)
	require.NoError(t, err)
	require.Equal(t, host.Address, loaded.Address)

	host.Address = "10.0.0.11"
	require.NoError(t, store.Hosts.Update(ctx, host))

	updated, err := store.Hosts.Get(ctx, host.Name)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.11", updated.Address)

	require.NoError(t, store.Hosts.Delete(ctx, host.Name))
	_, err = store.Hosts.Get(ctx, host.Name)
	require.ErrorIs(t, err, ErrNotFound)

	deletedAt := ""
	err = store.DB().QueryRow(`SELECT deleted_at FROM hosts WHERE id = ?`, host.ID).Scan(&deletedAt)
	require.NoError(t, err)
	require.NotEmpty(t, deletedAt)
}

func TestHostCRUDDeletedExcludedFromList(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	h1 := &Host{Name: "a", Address: "10.0.0.1", Port: 22}
	h2 := &Host{Name: "b", Address: "10.0.0.2", Port: 22}
	require.NoError(t, store.Hosts.Create(ctx, h1))
	require.NoError(t, store.Hosts.Create(ctx, h2))
	require.NoError(t, store.Hosts.Delete(ctx, "a"))

	list, err := store.Hosts.List(ctx, HostFilter{})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "b", list[0].Name)
}

func TestHostTagsAddFilterRemove(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	host := &Host{Name: "tagged", Address: "10.0.0.3", Port: 22}
	require.NoError(t, store.Hosts.Create(ctx, host))

	require.NoError(t, store.Hosts.AddTag(ctx, host.ID, "prod"))
	require.NoError(t, store.Hosts.AddTag(ctx, host.ID, "db"))

	filtered, err := store.Hosts.List(ctx, HostFilter{Tag: "prod"})
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	require.Equal(t, host.Name, filtered[0].Name)

	require.NoError(t, store.Hosts.RemoveTag(ctx, host.ID, "prod"))
	filtered, err = store.Hosts.List(ctx, HostFilter{Tag: "prod"})
	require.NoError(t, err)
	require.Len(t, filtered, 0)
}

func TestIdentityCRUDAndRetire(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	identity := &Identity{Name: "ops", Kind: "ed25519", PublicKey: "ssh-ed25519 AAA...", Status: IdentityStatusActive}
	require.NoError(t, store.Identities.Create(ctx, identity))

	loaded, err := store.Identities.Get(ctx, identity.Name)
	require.NoError(t, err)
	require.Equal(t, IdentityStatusActive, loaded.Status)

	identity.Status = IdentityStatusRetired
	require.NoError(t, store.Identities.Update(ctx, identity))

	retired, err := store.Identities.Get(ctx, identity.Name)
	require.NoError(t, err)
	require.Equal(t, IdentityStatusRetired, retired.Status)
}

func TestSecretCRUDEncryptedRoundTrip(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	secret := &Secret{Name: "db-password", Value: []byte("super-secret")}
	require.NoError(t, store.Secrets.Create(ctx, secret))

	loaded, err := store.Secrets.Get(ctx, secret.Name)
	require.NoError(t, err)
	require.Equal(t, []byte("super-secret"), loaded.Value)

	var ciphertext []byte
	err = store.DB().QueryRow(`SELECT value_ciphertext FROM secrets WHERE id = ?`, secret.ID).Scan(&ciphertext)
	require.NoError(t, err)
	require.NotContains(t, string(ciphertext), "super-secret")
}

func TestPasskeyEnrollmentCRUDStoreAndRetrieveByLabel(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	enrollment := &PasskeyEnrollment{
		Label:              "yubikey",
		CredentialID:       []byte{0x01, 0x02, 0x03},
		PublicKeyCOSE:      []byte{0xa5, 0x01, 0x02},
		AAGUID:             []byte{0xaa, 0xbb},
		SupportsHMACSecret: true,
	}
	require.NoError(t, store.Passkeys.Create(ctx, enrollment))

	loaded, err := store.Passkeys.GetByLabel(ctx, "yubikey")
	require.NoError(t, err)
	require.Equal(t, enrollment.CredentialID, loaded.CredentialID)
	require.Equal(t, enrollment.PublicKeyCOSE, loaded.PublicKeyCOSE)
	require.True(t, loaded.SupportsHMACSecret)
}

func TestSessionHistoryRecordAndQueryByHostID(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	host := &Host{Name: "session-host", Address: "10.0.0.40", Port: 22}
	require.NoError(t, store.Hosts.Create(ctx, host))

	session := &SessionHistory{HostID: host.ID}
	require.NoError(t, store.Sessions.RecordStart(ctx, session))
	require.NoError(t, store.Sessions.RecordEnd(ctx, session.ID, 17))

	records, err := store.Sessions.ListByHostID(ctx, host.ID)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.NotNil(t, records[0].EndedAt)
	require.NotNil(t, records[0].ExitCode)
	require.Equal(t, 17, *records[0].ExitCode)
}

func TestPendingOpsCreateCompleteAndQueryIncomplete(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	op := &PendingOp{OperationType: "backup", TargetID: "vault", Payload: `{"kind":"full"}`}
	require.NoError(t, store.PendingOps.Create(ctx, op))

	incomplete, err := store.PendingOps.ListIncomplete(ctx)
	require.NoError(t, err)
	require.Len(t, incomplete, 1)

	require.NoError(t, store.PendingOps.MarkCompleted(ctx, op.ID))
	incomplete, err = store.PendingOps.ListIncomplete(ctx)
	require.NoError(t, err)
	require.Empty(t, incomplete)
}

func TestConcurrentReadsWhileWriteWithWAL(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	host := &Host{Name: "race-host", Address: "10.0.0.50", Port: 22}
	require.NoError(t, store.Hosts.Create(ctx, host))

	const readers = 8
	errCh := make(chan error, readers+1)
	var wg sync.WaitGroup

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := store.Hosts.List(ctx, HostFilter{}); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			host.Address = fmt.Sprintf("10.0.0.%d", 60+i)
			if err := store.Hosts.Update(ctx, host); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

func TestWALFilePermissions0600OnUnix(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("permissions assertion is unix-specific")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	vc, vmk := newTestVaultCrypto(t)
	defer vmk.Destroy()

	store, err := Open(path, "vault-test", vc)
	require.NoError(t, err)
	defer closeStoreNoErr(t, store)

	ctx := context.Background()
	require.NoError(t, store.Hosts.Create(ctx, &Host{Name: "perm-host", Address: "10.0.0.99", Port: 22}))

	walPath := path + "-wal"
	require.Eventually(t, func() bool {
		_, err := os.Stat(walPath)
		return err == nil
	}, 2*time.Second, 20*time.Millisecond)

	info, err := os.Stat(walPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestUUIDUniquenessForEntityCreation(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	ids := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		s := &Secret{Name: fmt.Sprintf("secret-%d", i), Value: []byte("v")}
		require.NoError(t, store.Secrets.Create(ctx, s))
		_, exists := ids[s.ID]
		require.False(t, exists)
		ids[s.ID] = struct{}{}
	}
}

func TestTimestampsAutoPopulatedAndUpdatedAtChanges(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	host := &Host{Name: "stamp-host", Address: "10.0.0.20", Port: 22}
	require.NoError(t, store.Hosts.Create(ctx, host))
	require.False(t, host.CreatedAt.IsZero())
	require.False(t, host.UpdatedAt.IsZero())
	before := host.UpdatedAt

	time.Sleep(10 * time.Millisecond)
	host.Address = "10.0.0.21"
	require.NoError(t, store.Hosts.Update(ctx, host))
	require.True(t, host.UpdatedAt.After(before))
}

func TestHostEnvRefsJSONRoundTrip(t *testing.T) {
	t.Parallel()

	store, vmk := newTestStore(t)
	defer vmk.Destroy()

	ctx := context.Background()
	host := &Host{
		Name:    "env-host",
		Address: "10.0.0.77",
		Port:    22,
		EnvRefs: map[string]string{
			"DB_PASSWORD": "secret:db-password",
			"API_TOKEN":   "secret:api-token",
		},
	}
	require.NoError(t, store.Hosts.Create(ctx, host))

	loaded, err := store.Hosts.Get(ctx, host.Name)
	require.NoError(t, err)
	require.Equal(t, host.EnvRefs, loaded.EnvRefs)
}

func openRawTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := rawDBPath(t)
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	return db
}

func rawDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vault.db")
}

func mustSchemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var version int
	err := db.QueryRow(`SELECT value FROM vault_meta WHERE key = 'schema_version'`).Scan(&version)
	require.NoError(t, err)
	return version
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var count int
	err := db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count)
	require.NoError(t, err)
	return count == 1
}

func newTestVaultCrypto(t *testing.T) (*crypto.VaultCrypto, *memguard.LockedBuffer) {
	t.Helper()
	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)
	vc := crypto.NewVaultCrypto(vmk, "vault-test")
	return vc, vmk
}

func newTestStore(t *testing.T) (*Store, *memguard.LockedBuffer) {
	t.Helper()
	path := rawDBPath(t)
	vc, vmk := newTestVaultCrypto(t)
	store, err := Open(path, "vault-test", vc)
	require.NoError(t, err)
	t.Cleanup(func() { closeStoreNoErr(t, store) })
	return store, vmk
}

func closeStoreNoErr(t *testing.T, store *Store) {
	t.Helper()
	require.NoError(t, store.Close())
}

func closeNoErr(t *testing.T, db *sql.DB) {
	t.Helper()
	require.NoError(t, db.Close())
}

func writeVersionFile(t *testing.T, home string, version uint64) {
	t.Helper()
	path := filepath.Join(home, "vault.version")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("%d", version)), 0o600))
}
