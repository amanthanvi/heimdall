package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	agentpkg "github.com/amanthanvi/heimdall/internal/agent"
	"github.com/amanthanvi/heimdall/internal/app"
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/amanthanvi/heimdall/internal/config"
	cryptopkg "github.com/amanthanvi/heimdall/internal/crypto"
	daemonpkg "github.com/amanthanvi/heimdall/internal/daemon"
	"github.com/amanthanvi/heimdall/internal/fido2"
	grpcpkg "github.com/amanthanvi/heimdall/internal/grpc"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/awnumar/memguard"
	"github.com/spf13/cobra"
)

const (
	serveVaultID          = "heimdall-bootstrap-vault"
	serveMaxSessionWindow = 8 * time.Hour
)

func newDaemonServeCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:     "serve",
		Hidden:  true,
		Short:   "Run daemon server process",
		Example: "  heimdall daemon serve",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("daemon serve does not accept positional arguments")
			}
			return runDaemonServe(cmd.Context(), deps)
		},
	}
}

func runDaemonServe(ctx context.Context, deps commandDeps) (err error) {
	cfg, _, err := loadConfigFn(config.LoadOptions{})
	if err != nil {
		return fmt.Errorf("daemon serve: load config: %w", err)
	}
	configPath, err := resolveConfigPath(deps.globals)
	if err != nil {
		return fmt.Errorf("daemon serve: resolve config path: %w", err)
	}

	vaultPath, err := resolveVaultPath(deps.globals)
	if err != nil {
		return fmt.Errorf("daemon serve: resolve vault path: %w", err)
	}
	if _, err := app.ApplyBackupRestorePending(vaultPath); err != nil {
		return fmt.Errorf("daemon serve: apply pending restore: %w", err)
	}
	if _, statErr := os.Stat(vaultPath); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("daemon serve: vault not initialized: %s", vaultPath)
		}
		return fmt.Errorf("daemon serve: stat vault: %w", statErr)
	}

	homeDir, err := resolveHeimdallHomePath()
	if err != nil {
		return fmt.Errorf("daemon serve: resolve home path: %w", err)
	}
	runtimeDir := resolveServeRuntimeDir(cfg)
	daemonSocketPath := filepath.Join(runtimeDir, "daemon.sock")
	agentSocketPath := filepath.Join(runtimeDir, "agent.sock")
	infoPath := filepath.Join(homeDir, daemonInfoFilename)

	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("daemon serve: create runtime dir: %w", err)
	}
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("daemon serve: set runtime dir permissions: %w", err)
	}
	_ = os.Remove(daemonSocketPath)
	_ = os.Remove(agentSocketPath)

	vc := cryptopkg.NewVaultCrypto(nil, serveVaultID)
	store, err := storage.Open(vaultPath, serveVaultID, vc)
	if err != nil {
		return fmt.Errorf("daemon serve: open storage: %w", err)
	}
	defer func() {
		if closeErr := store.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("daemon serve: close storage: %w", closeErr)
		}
	}()

	auditService, err := auditpkg.NewService(store.Audit)
	if err != nil {
		return fmt.Errorf("daemon serve: initialize audit service: %w", err)
	}

	authenticator, err := fido2.NewAuthenticator("")
	if err != nil {
		return fmt.Errorf("daemon serve: initialize passkey authenticator: %w", err)
	}
	defer func() {
		if closeErr := authenticator.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("daemon serve: close passkey authenticator: %w", closeErr)
		}
	}()
	passkeySvc := fido2.NewService(authenticator, store.Passkeys, nil)

	daemonState := newServeDaemonState(homeDir, cfg.Daemon.MaxSessionDuration, store, vc, passkeySvc)
	agentServer := agentpkg.NewServer(daemonState)
	if err := agentServer.Start(agentSocketPath); err != nil {
		return fmt.Errorf("daemon serve: start agent server: %w", err)
	}
	defer func() {
		if stopErr := agentServer.Stop(); err == nil && stopErr != nil {
			err = fmt.Errorf("daemon serve: stop agent server: %w", stopErr)
		}
	}()

	server, err := grpcpkg.NewServer(grpcpkg.ServerConfig{
		Daemon:             daemonState,
		Store:              store,
		AuditService:       auditService,
		RuntimeConfig:      cfg,
		KeyAgent:           agentServer,
		PasskeyManager:     daemonState,
		PassphraseVerifier: daemonState.VerifyPassphrase,
		Version: grpcpkg.VersionInfo{
			Version:   deps.build.Version,
			Commit:    deps.build.Commit,
			BuildTime: deps.build.BuildTime,
		},
	})
	if err != nil {
		return fmt.Errorf("daemon serve: create grpc server: %w", err)
	}
	defer server.Stop()

	listener, err := net.Listen("unix", daemonSocketPath)
	if err != nil {
		return fmt.Errorf("daemon serve: listen daemon socket: %w", err)
	}
	defer func() {
		if closeErr := listener.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("daemon serve: close listener: %w", closeErr)
		}
	}()
	if err := os.Chmod(daemonSocketPath, 0o600); err != nil {
		return fmt.Errorf("daemon serve: chmod daemon socket: %w", err)
	}

	if err := writeDaemonInfo(infoPath, daemonpkg.Info{
		PID:        os.Getpid(),
		SocketPath: daemonSocketPath,
		AgentPath:  agentSocketPath,
		ConfigPath: configPath,
		VaultPath:  vaultPath,
		StartedAt:  time.Now().UTC(),
	}); err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(infoPath)
		_ = os.Remove(daemonSocketPath)
		_ = os.Remove(agentSocketPath)
	}()

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(listener)
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	select {
	case serveErr := <-serveErrCh:
		if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			if !strings.Contains(strings.ToLower(serveErr.Error()), "closed network") {
				return fmt.Errorf("daemon serve: grpc serve: %w", serveErr)
			}
		}
		return nil
	case <-sigCh:
		return nil
	case <-ctx.Done():
		return nil
	}
}

func resolveServeRuntimeDir(cfg config.Config) string {
	if socketDir := strings.TrimSpace(cfg.Daemon.SocketDir); socketDir != "" {
		return filepath.Clean(socketDir)
	}
	if runtime.GOOS == "darwin" {
		tmp := os.Getenv("TMPDIR")
		if tmp == "" {
			tmp = os.TempDir()
		}
		return filepath.Join(tmp, "heimdall")
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	return filepath.Join(runtimeDir, "heimdall")
}

func writeDaemonInfo(path string, info daemonpkg.Info) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("daemon serve: create daemon info dir: %w", err)
	}
	payload, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("daemon serve: encode daemon info: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("daemon serve: write daemon info: %w", err)
	}
	return nil
}

type serveDaemonState struct {
	mu                 sync.RWMutex
	locked             bool
	sessions           map[string]time.Time
	maxSessionDuration time.Duration
	homeDir            string
	store              *storage.Store
	vc                 *cryptopkg.VaultCrypto
	passkeySvc         *fido2.Service
}

func newServeDaemonState(homeDir string, maxSessionDuration time.Duration, store *storage.Store, vc *cryptopkg.VaultCrypto, passkeySvc *fido2.Service) *serveDaemonState {
	if maxSessionDuration <= 0 {
		maxSessionDuration = serveMaxSessionWindow
	}
	return &serveDaemonState{
		locked:             true,
		sessions:           map[string]time.Time{},
		maxSessionDuration: maxSessionDuration,
		homeDir:            homeDir,
		store:              store,
		vc:                 vc,
		passkeySvc:         passkeySvc,
	}
}

func (d *serveDaemonState) IsLocked() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.locked
}

func (d *serveDaemonState) HasLiveVMK() bool {
	return !d.IsLocked()
}

func (d *serveDaemonState) Unlock(passphrase []byte) error {
	ctx := context.Background()
	vmk, err := d.unwrapPassphraseVMK(ctx, passphrase)
	if err != nil {
		return err
	}
	return d.activateVMK(ctx, vmk)
}

func (d *serveDaemonState) UnlockWithPasskey(label string) error {
	if d.passkeySvc == nil {
		return fido2.VaultUnlockPasskeyUnavailable()
	}

	ctx := context.Background()
	if err := d.store.VerifyRollbackPreUnlock(d.homeDir); err != nil {
		return fmt.Errorf("unlock passkey: verify rollback pre-unlock: %w", err)
	}

	material, err := d.store.LoadVaultAuthMaterial(ctx)
	if err != nil {
		return fmt.Errorf("unlock passkey: load vault auth material: %w", err)
	}
	wrappedMaterial, ok := material.Passkeys[strings.TrimSpace(label)]
	if !ok {
		return fmt.Errorf("unlock passkey: passkey unlock unavailable for %q; re-enroll a passkey with hmac-secret support", label)
	}

	wrapped, err := decodeWrappedKeyMaterial(wrappedMaterial)
	if err != nil {
		return fmt.Errorf("unlock passkey: decode wrapped vmk: %w", err)
	}
	commitmentTag, err := decodeHexMaterialField(material.CommitmentTag, "commitment tag")
	if err != nil {
		return fmt.Errorf("unlock passkey: %w", err)
	}
	vaultSalt, err := decodeHexMaterialField(material.PasskeyUnlock.VaultSalt, "vault salt")
	if err != nil {
		return fmt.Errorf("unlock passkey: %w", err)
	}
	hmacSecretSalt, err := decodeHexMaterialField(material.PasskeyUnlock.HMACSecretSalt, "hmac-secret salt")
	if err != nil {
		return fmt.Errorf("unlock passkey: %w", err)
	}

	vmk, err := d.passkeySvc.UnlockWithPasskey(ctx, strings.TrimSpace(label), wrapped, commitmentTag, vaultSalt, hmacSecretSalt)
	if err != nil {
		return err
	}
	return d.activateVMK(ctx, vmk)
}

func (d *serveDaemonState) VerifyPassphrase(ctx context.Context, passphrase string) bool {
	vmk, err := d.unwrapPassphraseVMK(ctx, []byte(passphrase))
	if err != nil {
		return false
	}
	if err := d.store.VerifyRollbackPostUnlock(ctx, vmk); err != nil {
		vmk.Destroy()
		return false
	}
	vmk.Destroy()
	return true
}

func (d *serveDaemonState) Enroll(ctx context.Context, label, userName string) (*storage.PasskeyEnrollment, error) {
	if d.passkeySvc == nil {
		return nil, fido2.PasskeyCommandUnavailable("enroll")
	}
	if d.IsLocked() {
		return nil, fmt.Errorf("passkey enroll: vault is locked")
	}

	enrollment, err := d.passkeySvc.Enroll(ctx, strings.TrimSpace(label), strings.TrimSpace(userName))
	if err != nil {
		return nil, err
	}

	if !enrollment.SupportsHMACSecret {
		return enrollment, nil
	}

	material, err := d.loadOrInitializeAuthMaterial(ctx)
	if err != nil {
		_ = d.store.Passkeys.Delete(ctx, enrollment.Label)
		return nil, fmt.Errorf("passkey enroll: load vault auth material: %w", err)
	}

	vaultSalt, err := decodeHexMaterialField(material.PasskeyUnlock.VaultSalt, "vault salt")
	if err != nil {
		_ = d.store.Passkeys.Delete(ctx, enrollment.Label)
		return nil, fmt.Errorf("passkey enroll: %w", err)
	}
	hmacSecretSalt, err := decodeHexMaterialField(material.PasskeyUnlock.HMACSecretSalt, "hmac-secret salt")
	if err != nil {
		_ = d.store.Passkeys.Delete(ctx, enrollment.Label)
		return nil, fmt.Errorf("passkey enroll: %w", err)
	}

	kek, err := d.passkeySvc.DeriveKEK(ctx, enrollment.Label, vaultSalt, hmacSecretSalt)
	if err != nil {
		_ = d.store.Passkeys.Delete(ctx, enrollment.Label)
		return nil, err
	}
	defer memguard.WipeBytes(kek)

	wrapped, err := d.vc.WrapVMK(kek, serveVaultID, "passkey:"+enrollment.Label)
	if err != nil {
		_ = d.store.Passkeys.Delete(ctx, enrollment.Label)
		return nil, fmt.Errorf("passkey enroll: wrap vmk: %w", err)
	}
	material.Passkeys[enrollment.Label] = encodeWrappedKeyMaterial(wrapped)
	if err := d.store.StoreVaultAuthMaterial(ctx, material); err != nil {
		delete(material.Passkeys, enrollment.Label)
		_ = d.store.Passkeys.Delete(ctx, enrollment.Label)
		return nil, fmt.Errorf("passkey enroll: store vault auth material: %w", err)
	}

	return enrollment, nil
}

func (d *serveDaemonState) RemovePasskey(ctx context.Context, label string) error {
	if err := d.store.Passkeys.Delete(ctx, strings.TrimSpace(label)); err != nil {
		return err
	}

	material, err := d.loadOrInitializeAuthMaterial(ctx)
	if err != nil {
		return fmt.Errorf("remove passkey: load vault auth material: %w", err)
	}
	delete(material.Passkeys, strings.TrimSpace(label))
	if err := d.store.StoreVaultAuthMaterial(ctx, material); err != nil {
		return fmt.Errorf("remove passkey: store vault auth material: %w", err)
	}
	return nil
}

func (d *serveDaemonState) TestPasskey(ctx context.Context, label string) error {
	if d.passkeySvc == nil {
		return fido2.PasskeyCommandUnavailable("test")
	}
	return d.passkeySvc.Test(ctx, strings.TrimSpace(label))
}

func (d *serveDaemonState) Reauthenticate(ctx context.Context, label string, pid int) error {
	if d.passkeySvc == nil {
		return fido2.PasskeyCommandUnavailable("reauth")
	}
	return d.passkeySvc.Reauthenticate(ctx, strings.TrimSpace(label), pid)
}

func (d *serveDaemonState) Lock() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.vc.SetVMK(nil)
	d.locked = true
	return nil
}

func (d *serveDaemonState) LastPeerPID() int {
	return os.Getpid()
}

func (d *serveDaemonState) RegisterSigningSession(id string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions[id] = time.Now().UTC()
}

func (d *serveDaemonState) CanSign(id string) bool {
	if strings.TrimSpace(id) == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.locked {
		return false
	}
	start, ok := d.sessions[id]
	if !ok {
		return false
	}
	if d.maxSessionDuration <= 0 {
		return true
	}
	return time.Since(start) <= d.maxSessionDuration
}

func (d *serveDaemonState) unwrapPassphraseVMK(ctx context.Context, passphrase []byte) (*memguard.LockedBuffer, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("unlock: passphrase is required")
	}
	if err := d.store.VerifyRollbackPreUnlock(d.homeDir); err != nil {
		return nil, fmt.Errorf("unlock: verify rollback pre-unlock: %w", err)
	}

	material, err := d.store.LoadVaultAuthMaterial(ctx)
	if err != nil {
		return nil, fmt.Errorf("unlock: load vault auth material: %w", err)
	}

	argon2Salt, err := decodeHexMaterialField(material.Passphrase.Argon2Salt, "argon2 salt")
	if err != nil {
		return nil, fmt.Errorf("unlock: %w", err)
	}
	params := cryptopkg.Argon2Params{
		Memory:      material.Passphrase.Memory,
		Iterations:  material.Passphrase.Iterations,
		Parallelism: material.Passphrase.Parallelism,
		SaltLen:     len(argon2Salt),
		KeyLen:      material.Passphrase.KeyLen,
	}
	kek, err := cryptopkg.DeriveKEKFromPassphrase(passphrase, argon2Salt, params)
	if err != nil {
		return nil, fmt.Errorf("unlock: derive kek: %w", err)
	}
	defer memguard.WipeBytes(kek)

	wrapped, err := decodeWrappedKeyMaterial(material.Passphrase.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("unlock: decode wrapped vmk: %w", err)
	}
	commitmentTag, err := decodeHexMaterialField(material.CommitmentTag, "commitment tag")
	if err != nil {
		return nil, fmt.Errorf("unlock: %w", err)
	}
	vmk, err := cryptopkg.UnwrapVMK(kek, wrapped, commitmentTag)
	if err != nil {
		return nil, fmt.Errorf("unlock: unwrap vmk: %w", err)
	}
	return vmk, nil
}

func (d *serveDaemonState) activateVMK(ctx context.Context, vmk *memguard.LockedBuffer) error {
	if vmk == nil || !vmk.IsAlive() {
		return fmt.Errorf("unlock: vmk is nil or destroyed")
	}
	if err := d.store.VerifyRollbackPostUnlock(ctx, vmk); err != nil {
		vmk.Destroy()
		return fmt.Errorf("unlock: verify rollback post-unlock: %w", err)
	}

	d.vc.SetVMK(vmk)
	d.mu.Lock()
	d.locked = false
	d.mu.Unlock()
	return nil
}

func (d *serveDaemonState) loadOrInitializeAuthMaterial(ctx context.Context) (storage.VaultAuthMaterial, error) {
	material, err := d.store.LoadVaultAuthMaterial(ctx)
	if err != nil {
		return storage.VaultAuthMaterial{}, err
	}
	if material.Version == 0 {
		material.Version = storage.VaultAuthMaterialVersion2
	}
	if material.Passkeys == nil {
		material.Passkeys = map[string]storage.WrappedKeyMaterial{}
	}
	if strings.TrimSpace(material.PasskeyUnlock.VaultSalt) == "" {
		salt, err := cryptopkg.GenerateSalt(int(cryptopkg.DefaultArgon2KeyLen))
		if err != nil {
			return storage.VaultAuthMaterial{}, fmt.Errorf("generate vault salt: %w", err)
		}
		material.PasskeyUnlock.VaultSalt = hex.EncodeToString(salt)
	}
	if strings.TrimSpace(material.PasskeyUnlock.HMACSecretSalt) == "" {
		salt, err := cryptopkg.GenerateSalt(int(cryptopkg.DefaultArgon2KeyLen))
		if err != nil {
			return storage.VaultAuthMaterial{}, fmt.Errorf("generate hmac-secret salt: %w", err)
		}
		material.PasskeyUnlock.HMACSecretSalt = hex.EncodeToString(salt)
	}
	if err := d.store.StoreVaultAuthMaterial(ctx, material); err != nil {
		return storage.VaultAuthMaterial{}, err
	}
	return material, nil
}

func encodeWrappedKeyMaterial(wrapped cryptopkg.WrappedKey) storage.WrappedKeyMaterial {
	return storage.WrappedKeyMaterial{
		Ciphertext: hex.EncodeToString(wrapped.Ciphertext),
		Nonce:      hex.EncodeToString(wrapped.Nonce),
		AAD:        hex.EncodeToString(wrapped.Salt),
	}
}

func decodeWrappedKeyMaterial(material storage.WrappedKeyMaterial) (cryptopkg.WrappedKey, error) {
	ciphertext, err := decodeHexMaterialField(material.Ciphertext, "ciphertext")
	if err != nil {
		return cryptopkg.WrappedKey{}, err
	}
	nonce, err := decodeHexMaterialField(material.Nonce, "nonce")
	if err != nil {
		return cryptopkg.WrappedKey{}, err
	}
	aad, err := decodeHexMaterialField(material.AAD, "aad")
	if err != nil {
		return cryptopkg.WrappedKey{}, err
	}
	return cryptopkg.WrappedKey{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       aad,
	}, nil
}

func decodeHexMaterialField(raw string, field string) ([]byte, error) {
	value, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", field, err)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("decode %s: value is empty", field)
	}
	return value, nil
}
