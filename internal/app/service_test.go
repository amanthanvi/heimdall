package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestHostServiceCreateValidatesRequiredFields(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewHostService(store.Hosts, store.Sessions)
	_, err := svc.Create(context.Background(), CreateHostRequest{
		Address: "10.0.0.1",
	})
	require.Error(t, err)

	_, err = svc.Create(context.Background(), CreateHostRequest{
		Name: "prod",
	})
	require.Error(t, err)
}

func TestHostServiceCreateRejectsDuplicateName(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewHostService(store.Hosts, store.Sessions)
	ctx := context.Background()
	_, err := svc.Create(ctx, CreateHostRequest{
		Name:    "prod",
		Address: "10.0.0.1",
	})
	require.NoError(t, err)

	_, err = svc.Create(ctx, CreateHostRequest{
		Name:    "prod",
		Address: "10.0.0.2",
	})
	require.ErrorIs(t, err, ErrDuplicateName)
}

func TestHostServiceListFiltersByTagGroupSearch(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewHostService(store.Hosts, store.Sessions)
	ctx := context.Background()

	_, err := svc.Create(ctx, CreateHostRequest{
		Name:    "prod-bastion",
		Address: "10.0.0.1",
		Tags:    []string{"prod", "ssh"},
		Group:   "ops",
	})
	require.NoError(t, err)
	_, err = svc.Create(ctx, CreateHostRequest{
		Name:    "dev-api",
		Address: "10.0.0.2",
		Tags:    []string{"dev"},
		Group:   "eng",
	})
	require.NoError(t, err)

	byTag, err := svc.List(ctx, ListHostsRequest{Tag: "prod"})
	require.NoError(t, err)
	require.Len(t, byTag, 1)
	require.Equal(t, "prod-bastion", byTag[0].Name)

	byGroup, err := svc.List(ctx, ListHostsRequest{Group: "ops"})
	require.NoError(t, err)
	require.Len(t, byGroup, 1)
	require.Equal(t, "prod-bastion", byGroup[0].Name)

	bySearch, err := svc.List(ctx, ListHostsRequest{Search: "api"})
	require.NoError(t, err)
	require.Len(t, bySearch, 1)
	require.Equal(t, "dev-api", bySearch[0].Name)
}

func TestHostServiceListSortsByNameAndLastConnected(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewHostService(store.Hosts, store.Sessions)
	ctx := context.Background()

	hostA, err := svc.Create(ctx, CreateHostRequest{
		Name:    "alpha",
		Address: "10.0.0.10",
	})
	require.NoError(t, err)
	hostB, err := svc.Create(ctx, CreateHostRequest{
		Name:    "zulu",
		Address: "10.0.0.11",
	})
	require.NoError(t, err)

	sessionA := &storage.SessionHistory{HostID: hostA.ID, StartedAt: time.Now().UTC().Add(-10 * time.Minute)}
	sessionB := &storage.SessionHistory{HostID: hostB.ID, StartedAt: time.Now().UTC().Add(-time.Minute)}
	require.NoError(t, store.Sessions.RecordStart(ctx, sessionA))
	require.NoError(t, store.Sessions.RecordStart(ctx, sessionB))

	byName, err := svc.List(ctx, ListHostsRequest{SortBy: SortByName})
	require.NoError(t, err)
	require.Len(t, byName, 2)
	require.Equal(t, "alpha", byName[0].Name)
	require.Equal(t, "zulu", byName[1].Name)

	byLast, err := svc.List(ctx, ListHostsRequest{SortBy: SortByLastConnected})
	require.NoError(t, err)
	require.Len(t, byLast, 2)
	require.Equal(t, "zulu", byLast[0].Name)
	require.Equal(t, "alpha", byLast[1].Name)
}

func TestSecretServiceCreateEncryptsValueOnStore(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewSecretService(store.Secrets)
	_, err := svc.Create(context.Background(), CreateSecretRequest{
		Name:  "db-password",
		Value: []byte("super-secret"),
	})
	require.NoError(t, err)

	var ciphertext []byte
	err = store.DB().QueryRow(`SELECT value_ciphertext FROM secrets WHERE name = ?`, "db-password").Scan(&ciphertext)
	require.NoError(t, err)
	require.NotContains(t, string(ciphertext), "super-secret")
}

func TestSecretServiceGetValueDecryptsAndEnforcesRevealPolicy(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewSecretService(store.Secrets)
	ctx := context.Background()

	_, err := svc.Create(ctx, CreateSecretRequest{
		Name:         "always",
		Value:        []byte("always-secret"),
		RevealPolicy: RevealPolicyAlwaysReauth,
	})
	require.NoError(t, err)

	_, err = svc.GetValue(ctx, "always")
	require.ErrorIs(t, err, ErrReauthRequired)

	value, err := svc.GetValue(WithReauth(ctx), "always")
	require.NoError(t, err)
	require.Equal(t, []byte("always-secret"), value)

	_, err = svc.GetValue(ctx, "always")
	require.ErrorIs(t, err, ErrReauthRequired)

	_, err = svc.Create(ctx, CreateSecretRequest{
		Name:         "once",
		Value:        []byte("once-secret"),
		RevealPolicy: RevealPolicyOncePerUnlock,
	})
	require.NoError(t, err)

	_, err = svc.GetValue(ctx, "once")
	require.ErrorIs(t, err, ErrReauthRequired)

	value, err = svc.GetValue(WithReauth(ctx), "once")
	require.NoError(t, err)
	require.Equal(t, []byte("once-secret"), value)

	value, err = svc.GetValue(ctx, "once")
	require.NoError(t, err)
	require.Equal(t, []byte("once-secret"), value)

	svc.ResetRevealCache()
	_, err = svc.GetValue(ctx, "once")
	require.ErrorIs(t, err, ErrReauthRequired)
}

func TestKeyServiceGenerateCreatesEd25519ByDefaultAndRSA3072(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewKeyService(store.Identities)
	ctx := context.Background()

	ed, err := svc.Generate(ctx, GenerateKeyRequest{Name: "default-ed"})
	require.NoError(t, err)
	require.Equal(t, KeyTypeEd25519, ed.Type)

	rsaKey, err := svc.Generate(ctx, GenerateKeyRequest{Name: "rsa-key", Type: KeyTypeRSA})
	require.NoError(t, err)
	require.Equal(t, KeyTypeRSA, rsaKey.Type)
}

func TestKeyServiceImportImportsOpenSSHPrivateKey(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewKeyService(store.Identities)
	ctx := context.Background()

	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "imported")
	require.NoError(t, err)
	privatePEM := pem.EncodeToMemory(block)

	meta, err := svc.Import(ctx, ImportKeyRequest{
		Name:       "imported",
		PrivateKey: privatePEM,
	})
	require.NoError(t, err)
	require.Equal(t, KeyTypeEd25519, meta.Type)
}

func TestKeyServiceExportRequiresReauthAndWrites0600(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("permission assertion is unix-specific")
	}

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewKeyService(store.Identities)
	ctx := context.Background()
	_, err := svc.Generate(ctx, GenerateKeyRequest{Name: "export-me"})
	require.NoError(t, err)

	out := filepath.Join(t.TempDir(), "id_export")
	err = svc.Export(ctx, ExportKeyRequest{
		Name:   "export-me",
		Output: out,
	})
	require.ErrorIs(t, err, ErrReauthRequired)

	err = svc.Export(WithReauth(ctx), ExportKeyRequest{
		Name:   "export-me",
		Output: out,
	})
	require.NoError(t, err)

	info, err := os.Stat(out)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestKeyServiceRotateGeneratesNewKeyAndMarksOldRetired(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	svc := NewKeyService(store.Identities)
	ctx := context.Background()
	original, err := svc.Generate(ctx, GenerateKeyRequest{Name: "rotate-me"})
	require.NoError(t, err)

	rotated, err := svc.Rotate(ctx, "rotate-me")
	require.NoError(t, err)
	require.NotEqual(t, original.ID, rotated.ID)

	var status string
	err = store.DB().QueryRow(`SELECT status FROM identities WHERE id = ?`, original.ID).Scan(&status)
	require.NoError(t, err)
	require.Equal(t, string(storage.IdentityStatusRetired), status)

	current, err := store.Identities.Get(ctx, "rotate-me")
	require.NoError(t, err)
	require.Equal(t, storage.IdentityStatusActive, current.Status)
}

func TestConnectServicePlanBuildsJumpAndForwardArgs(t *testing.T) {
	t.Parallel()

	store, vmk := newAppTestStore(t)
	defer vmk.Destroy()

	hostSvc := NewHostService(store.Hosts, store.Sessions)
	_, err := hostSvc.Create(context.Background(), CreateHostRequest{
		Name:    "prod",
		Address: "10.0.0.8",
		User:    "ubuntu",
		Port:    22,
	})
	require.NoError(t, err)

	svc := NewConnectService(store.Hosts)
	plan, err := svc.Plan(context.Background(), "prod", ConnectOpts{
		JumpHosts:    []string{"jump1", "jump2"},
		Forwards:     []string{"L:8080:localhost:80", "R:2222:localhost:22", "D:1080"},
		IdentityPath: "/tmp/id_prod",
	})
	require.NoError(t, err)

	cmd := strings.Join(plan.Args, " ")
	require.Contains(t, cmd, "-J jump1,jump2")
	require.Contains(t, cmd, "-L 8080:localhost:80")
	require.Contains(t, cmd, "-R 2222:localhost:22")
	require.Contains(t, cmd, "-D 1080")
	require.Contains(t, cmd, "-i /tmp/id_prod")
	require.Contains(t, cmd, "-o IdentitiesOnly=yes")
}

func TestSecretEnvCLIFlowSetsEnvAndKeepsSecretOutOfOutput(t *testing.T) {
	t.Parallel()

	getter := &fakeSecretGetter{
		value: []byte("very-secret"),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode, err := InjectSecretIntoProcessEnv(
		context.Background(),
		getter,
		"db-password",
		"DB_PASSWORD",
		[]string{"sh", "-c", "echo ready"},
		nil,
		&stdout,
		&stderr,
	)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.Contains(t, stdout.String(), "ready")
	require.NotContains(t, stdout.String(), "very-secret")
	require.NotContains(t, stderr.String(), "very-secret")
}

func TestSecretEnvLinuxProcRiskDocumented(t *testing.T) {
	t.Parallel()

	require.Contains(t, LinuxProcEnvironRisk, "/proc")
	require.Contains(t, strings.ToLower(LinuxProcEnvironRisk), "environ")
}

type fakeSecretGetter struct {
	value []byte
}

func (f *fakeSecretGetter) GetValue(ctx context.Context, name string) ([]byte, error) {
	return append([]byte(nil), f.value...), nil
}

func newAppTestStore(t *testing.T) (*storage.Store, *memguard.LockedBuffer) {
	t.Helper()
	path := t.TempDir() + "/vault.db"
	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)

	vc := crypto.NewVaultCrypto(vmk, "app-test-vault")
	store, err := storage.Open(path, "app-test-vault", vc)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store, vmk
}

