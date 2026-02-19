package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/app"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestTier0StatusAccessibleWithoutUnlock(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	h.daemon.setLocked(true)

	resp, err := h.vault.Status(callerCtx(101, "proc-a"), &v1.StatusRequest{})
	require.NoError(t, err)
	require.True(t, resp.GetLocked())
}

func TestTier0VersionAccessibleWithoutUnlock(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	h.daemon.setLocked(true)

	resp, err := h.version.GetVersion(callerCtx(101, "proc-a"), &v1.GetVersionRequest{})
	require.NoError(t, err)
	require.Equal(t, "test-version", resp.GetVersion())
}

func TestTier1HostListRequiresUnlockedVault(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	h.daemon.setLocked(true)
	_, err := h.host.ListHosts(callerCtx(101, "proc-a"), &v1.ListHostsRequest{})
	requirePermissionDenied(t, err)
}

func TestTier1SecretListRequiresUnlockedVault(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	h.daemon.setLocked(true)
	_, err := h.secret.ListSecrets(callerCtx(101, "proc-a"), &v1.ListSecretsRequest{})
	requirePermissionDenied(t, err)
}

func TestTier2SecretGetValueRequiresReauth(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "api-token", []byte("super-secret"))

	_, err := h.secret.GetSecretValue(callerCtx(101, "proc-a"), &v1.GetSecretValueRequest{Name: "api-token"})
	requirePermissionDenied(t, err)
}

func TestTier2KeyExportRequiresReauth(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createIdentity(t, h.store, "deploy-key")

	_, err := h.key.ExportKey(callerCtx(101, "proc-a"), &v1.ExportKeyRequest{Name: "deploy-key"})
	requirePermissionDenied(t, err)
}

func TestTier2SecretDeleteRequiresReauth(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "db-pass", []byte("very-secret"))

	_, err := h.secret.DeleteSecret(callerCtx(101, "proc-a"), &v1.DeleteSecretRequest{Name: "db-pass"})
	requirePermissionDenied(t, err)
}

func TestReauthCacheAllowsTier2CallWithinTTL(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "api-token", []byte("super-secret"))
	ctx := callerCtx(101, "proc-a")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	resp, err := h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "api-token"})
	require.NoError(t, err)
	require.Equal(t, []byte("super-secret"), resp.GetValue())
}

func TestReauthCacheExpiresAfterTTL(t *testing.T) {
	t.Parallel()

	clk := newFakeClock(time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC))
	h := newGRPCHarness(t, withClock(clk))
	createSecret(t, h.store, "api-token", []byte("super-secret"))
	ctx := callerCtx(101, "proc-a")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	clk.Advance(61 * time.Second)
	_, err = h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "api-token"})
	requirePermissionDenied(t, err)
}

func TestReauthCacheScopedToPIDAndStartTime(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createSecret(t, h.store, "api-token", []byte("super-secret"))

	ctxA := callerCtx(101, "proc-a")
	_, err := h.reauth.VerifyPassphrase(ctxA, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	_, err = h.secret.GetSecretValue(callerCtx(102, "proc-a"), &v1.GetSecretValueRequest{Name: "api-token"})
	requirePermissionDenied(t, err)

	_, err = h.secret.GetSecretValue(callerCtx(101, "proc-b"), &v1.GetSecretValueRequest{Name: "api-token"})
	requirePermissionDenied(t, err)
}

func TestRateLimitingTier0Allows1000ThenRejects(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	ctx := callerCtx(303, "proc-rate")
	for i := 0; i < 1000; i++ {
		_, err := h.vault.Status(ctx, &v1.StatusRequest{})
		require.NoError(t, err)
	}
	_, err := h.vault.Status(ctx, &v1.StatusRequest{})
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.ResourceExhausted, st.Code())
}

func TestRateLimitingTier2RejectsAfterTenPerMinute(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	ctx := callerCtx(404, "proc-rate")
	createSecret(t, h.store, "db-pass", []byte("value"))

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "ok"})
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		_, err := h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "db-pass"})
		require.NoError(t, err)
	}
	_, err = h.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: "db-pass"})
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.ResourceExhausted, st.Code())
}

func TestErrorModelContainsRequiredErrorInfoFields(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	h.daemon.setLocked(true)
	_, err := h.host.ListHosts(callerCtx(505, "proc-lock"), &v1.ListHostsRequest{})
	require.Error(t, err)

	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.PermissionDenied, st.Code())

	info := findErrorInfo(t, st)
	require.Equal(t, "VAULT_LOCKED", info.Reason)
	require.Equal(t, "true", info.Metadata["vault_locked"])
	require.Equal(t, "false", info.Metadata["reauth_required"])
	require.NotEmpty(t, info.Metadata["guidance"])
	require.Equal(t, "VAULT_LOCKED", info.Metadata["error_code"])
}

func TestConnectServicePlanHasOnlyPlanRPCAndReturnsSSHCommand(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	createHost(t, h.store, "prod", "10.0.0.1", "ubuntu")

	resp, err := h.connect.Plan(callerCtx(606, "proc-plan"), &v1.PlanConnectRequest{
		HostName:     "prod",
		JumpHosts:    []string{"bastion"},
		Forwards:     []string{"L:8080:localhost:80"},
		IdentityPath: "/tmp/id_prod",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetCommand())
	require.Equal(t, "ssh", resp.GetCommand().GetBinary())
	require.Contains(t, strings.Join(resp.GetCommand().GetArgs(), " "), "-J bastion")
	require.Len(t, v1.ConnectService_ServiceDesc.Methods, 1)
	require.Equal(t, "Plan", v1.ConnectService_ServiceDesc.Methods[0].MethodName)
}

func TestReauthVerifyAssertionValidatesSignature(t *testing.T) {
	t.Parallel()

	h := newGRPCHarness(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = h.store.Passkeys.Create(context.Background(), &storage.PasskeyEnrollment{
		Label:         "work-key",
		CredentialID:  []byte("cred-1"),
		PublicKeyCOSE: append([]byte(nil), pub...),
	})
	require.NoError(t, err)

	authData := []byte("reauth-payload")
	sig := ed25519.Sign(priv, authData)
	ctx := callerCtx(707, "proc-assert")

	resp, err := h.reauth.VerifyAssertion(ctx, &v1.VerifyAssertionRequest{
		Label:     "work-key",
		AuthData:  authData,
		Signature: sig,
	})
	require.NoError(t, err)
	require.True(t, resp.GetOk())
}

func TestLockoutProgressionThreeFiveTenFailures(t *testing.T) {
	t.Parallel()

	clk := newFakeClock(time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC))
	h := newGRPCHarness(t,
		withClock(clk),
		withPassphraseVerifier(func(context.Context, string) bool { return false }),
	)

	ctx := callerCtx(808, "proc-lockout")

	_, err := h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
	require.Error(t, err)
	_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
	require.Error(t, err)

	_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "5s")

	_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "retry")

	clk.Advance(5 * time.Second)
	_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "5s")
	clk.Advance(5 * time.Second)

	_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "30s")

	clk.Advance(30 * time.Second)
	for i := 0; i < 4; i++ {
		_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
		require.Error(t, err)
		clk.Advance(30 * time.Second)
	}
	_, err = h.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: "bad"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "5m")
}

func requirePermissionDenied(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.PermissionDenied, st.Code())
}

func findErrorInfo(t *testing.T, st *grpcstatus.Status) *errdetails.ErrorInfo {
	t.Helper()
	for _, detail := range st.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if ok {
			return info
		}
	}
	t.Fatalf("error info detail not found")
	return nil
}

type grpcHarness struct {
	store    *storage.Store
	vmk      *memguard.LockedBuffer
	daemon   *testDaemon
	clock    *fakeClock
	audit    *auditpkg.Service
	server   *Server
	conn     *grpcpkg.ClientConn
	listener *bufconn.Listener

	vault   v1.VaultServiceClient
	version v1.VersionServiceClient
	host    v1.HostServiceClient
	secret  v1.SecretServiceClient
	key     v1.KeyServiceClient
	connect v1.ConnectServiceClient
	session v1.SessionServiceClient
	reauth  v1.ReauthServiceClient
}

type harnessOption func(*harnessConfig)

type harnessConfig struct {
	clock              *fakeClock
	passphraseVerifier func(context.Context, string) bool
}

func withClock(c *fakeClock) harnessOption {
	return func(cfg *harnessConfig) { cfg.clock = c }
}

func withPassphraseVerifier(verifier func(context.Context, string) bool) harnessOption {
	return func(cfg *harnessConfig) { cfg.passphraseVerifier = verifier }
}

func newGRPCHarness(t *testing.T, opts ...harnessOption) *grpcHarness {
	t.Helper()

	cfg := harnessConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.clock == nil {
		cfg.clock = newFakeClock(time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC))
	}
	if cfg.passphraseVerifier == nil {
		cfg.passphraseVerifier = func(context.Context, string) bool { return true }
	}

	path := t.TempDir() + "/vault.db"
	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)
	vc := crypto.NewVaultCrypto(vmk, "grpc-test-vault")
	store, err := storage.Open(path, "grpc-test-vault", vc)
	require.NoError(t, err)

	auditSvc, err := auditpkg.NewService(store.Audit)
	require.NoError(t, err)

	daemon := &testDaemon{locked: false}
	server, err := NewServer(ServerConfig{
		Daemon:             daemon,
		Store:              store,
		AuditService:       auditSvc,
		Version:            VersionInfo{Version: "test-version", Commit: "test-commit", BuildTime: "test-build"},
		Clock:              cfg.clock,
		PassphraseVerifier: cfg.passphraseVerifier,
	})
	require.NoError(t, err)

	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.Dial()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := grpcpkg.DialContext(
		ctx,
		"bufnet",
		grpcpkg.WithContextDialer(dialer),
		grpcpkg.WithTransportCredentials(insecure.NewCredentials()),
		grpcpkg.WithBlock(),
	)
	require.NoError(t, err)

	h := &grpcHarness{
		store:    store,
		vmk:      vmk,
		daemon:   daemon,
		clock:    cfg.clock,
		audit:    auditSvc,
		server:   server,
		conn:     conn,
		listener: listener,
		vault:    v1.NewVaultServiceClient(conn),
		version:  v1.NewVersionServiceClient(conn),
		host:     v1.NewHostServiceClient(conn),
		secret:   v1.NewSecretServiceClient(conn),
		key:      v1.NewKeyServiceClient(conn),
		connect:  v1.NewConnectServiceClient(conn),
		session:  v1.NewSessionServiceClient(conn),
		reauth:   v1.NewReauthServiceClient(conn),
	}
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		server.Stop()
		_ = listener.Close()
		require.NoError(t, store.Close())
		vmk.Destroy()
	})
	return h
}

func callerCtx(pid int, processStart string) context.Context {
	return metadata.AppendToOutgoingContext(
		context.Background(),
		callerPIDMetadataKey,
		strconv.Itoa(pid),
		callerStartTimeMetadataKey,
		processStart,
	)
}

func createHost(t *testing.T, store *storage.Store, name, address, user string) {
	t.Helper()
	hostSvc := app.NewHostService(store.Hosts, store.Sessions)
	_, err := hostSvc.Create(context.Background(), app.CreateHostRequest{Name: name, Address: address, User: user})
	require.NoError(t, err)
}

func createSecret(t *testing.T, store *storage.Store, name string, value []byte) {
	t.Helper()
	err := store.Secrets.Create(context.Background(), &storage.Secret{Name: name, Value: value})
	require.NoError(t, err)
}

func createIdentity(t *testing.T, store *storage.Store, name string) {
	t.Helper()
	keySvc := app.NewKeyService(store.Identities)
	_, err := keySvc.Generate(context.Background(), app.GenerateKeyRequest{Name: name})
	require.NoError(t, err)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start.UTC()}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

type testDaemon struct {
	mu       sync.RWMutex
	locked   bool
	peerPID  int
	sessions map[string]struct{}
}

func (d *testDaemon) IsLocked() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.locked
}

func (d *testDaemon) HasLiveVMK() bool {
	return !d.IsLocked()
}

func (d *testDaemon) Lock() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.locked = true
	return nil
}

func (d *testDaemon) LastPeerPID() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.peerPID == 0 {
		return 1
	}
	return d.peerPID
}

func (d *testDaemon) RegisterSigningSession(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = map[string]struct{}{}
	}
	d.sessions[id] = struct{}{}
}

func (d *testDaemon) setLocked(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.locked = v
}
