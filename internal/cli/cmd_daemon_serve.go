package cli

import (
	"context"
	"crypto/sha256"
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
	auditpkg "github.com/amanthanvi/heimdall/internal/audit"
	"github.com/amanthanvi/heimdall/internal/config"
	cryptopkg "github.com/amanthanvi/heimdall/internal/crypto"
	daemonpkg "github.com/amanthanvi/heimdall/internal/daemon"
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
		Use:    "serve",
		Hidden: true,
		Short:  "Run daemon server process",
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

	vaultPath, err := resolveVaultPath(deps.globals)
	if err != nil {
		return fmt.Errorf("daemon serve: resolve vault path: %w", err)
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

	vmk := deterministicServeVMK()
	defer vmk.Destroy()

	vc := cryptopkg.NewVaultCrypto(vmk, serveVaultID)
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

	daemonState := newServeDaemonState(cfg.Daemon.MaxSessionDuration)
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
		Daemon:       daemonState,
		Store:        store,
		AuditService: auditService,
		KeyAgent:     agentServer,
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

// deterministicServeVMK returns a fixed VMK for the bootstrap daemon.
// SECURITY: This is NOT cryptographically secure — the seed is public.
// It exists only to allow the daemon to open the vault database during
// development before the full vault-init → passphrase → KEK → VMK unwrap
// flow is wired. Replace with crypto.GenerateVMK() + proper unwrap once
// vault initialization stores a wrapped VMK in vault_meta.
func deterministicServeVMK() *memguard.LockedBuffer {
	seed := sha256.Sum256([]byte("heimdall.daemon.vmk.v1"))
	return memguard.NewBufferFromBytes(seed[:])
}

type serveDaemonState struct {
	mu                 sync.RWMutex
	locked             bool
	sessions           map[string]time.Time
	maxSessionDuration time.Duration
}

func newServeDaemonState(maxSessionDuration time.Duration) *serveDaemonState {
	if maxSessionDuration <= 0 {
		maxSessionDuration = serveMaxSessionWindow
	}
	return &serveDaemonState{
		locked:             true,
		sessions:           map[string]time.Time{},
		maxSessionDuration: maxSessionDuration,
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

func (d *serveDaemonState) Unlock([]byte) error {
	// TODO: implement real credential verification:
	// 1. Load vault metadata (salt, wrapped VMK, commitment tag)
	// 2. Derive KEK from passphrase via Argon2id
	// 3. Unwrap VMK (XChaCha20-Poly1305)
	// 4. Verify commitment tag (HMAC-SHA256)
	// 5. Set VMK into VaultCrypto and flip d.locked = false
	return fmt.Errorf("unlock: vault credential verification not yet wired in daemon serve")
}

func (d *serveDaemonState) Lock() error {
	d.mu.Lock()
	defer d.mu.Unlock()
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
