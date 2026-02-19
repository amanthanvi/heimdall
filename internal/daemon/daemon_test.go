package daemon

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDaemonStartCreatesSocketDirAndSocketsWithPermissions(t *testing.T) {
	t.Parallel()

	d := newTestDaemon(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	info, err := os.Stat(d.RuntimeDir())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	socketInfo, err := os.Stat(d.DaemonSocketPath())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), socketInfo.Mode().Perm())

	agentInfo, err := os.Stat(d.AgentSocketPath())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), agentInfo.Mode().Perm())
}

func TestDaemonStartWritesDaemonInfoJSON(t *testing.T) {
	t.Parallel()

	d := newTestDaemon(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	data, err := os.ReadFile(d.InfoPath())
	require.NoError(t, err)

	var info Info
	require.NoError(t, json.Unmarshal(data, &info))
	require.Equal(t, os.Getpid(), info.PID)
	require.Equal(t, d.DaemonSocketPath(), info.SocketPath)
	require.Equal(t, d.AgentSocketPath(), info.AgentPath)
	require.False(t, info.StartedAt.IsZero())
}

func TestDaemonSecondInstanceRefusesWhenExistingDaemonAlive(t *testing.T) {
	t.Parallel()

	pid := os.Getpid()
	startedAt := time.Now().UTC()
	inspector := &fakeProcessInspector{
		running: map[int]bool{pid: true},
		start:   map[int]time.Time{pid: startedAt},
	}

	base := testPaths(t)
	first := newTestDaemonAtPaths(t, base.home, base.runtime, inspector)
	require.NoError(t, first.writeInfoFile(Info{
		PID:        pid,
		SocketPath: first.DaemonSocketPath(),
		AgentPath:  first.AgentSocketPath(),
		StartedAt:  startedAt,
	}))

	second := newTestDaemonAtPaths(t, base.home, base.runtime, inspector)
	err := second.Start(context.Background())
	require.ErrorIs(t, err, ErrDaemonAlreadyRunning)
}

func TestStaleDaemonInfoCleanedAndNewDaemonStarts(t *testing.T) {
	t.Parallel()

	base := testPaths(t)
	inspector := &fakeProcessInspector{
		running: map[int]bool{424242: false},
		start:   map[int]time.Time{},
	}

	d := newTestDaemonAtPaths(t, base.home, base.runtime, inspector)
	stale := Info{
		PID:        424242,
		SocketPath: filepath.Join(base.runtime, "daemon.sock"),
		AgentPath:  filepath.Join(base.runtime, "agent.sock"),
		StartedAt:  time.Now().UTC().Add(-time.Hour),
	}
	require.NoError(t, os.MkdirAll(base.runtime, 0o700))
	require.NoError(t, os.WriteFile(stale.SocketPath, []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(stale.AgentPath, []byte("x"), 0o600))
	require.NoError(t, d.writeInfoFile(stale))

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, d.Stop(context.Background())) })

	_, err := os.Stat(stale.SocketPath)
	require.NoError(t, err)
	_, err = os.Stat(stale.AgentPath)
	require.NoError(t, err)
}

func TestStaleDaemonInfoPIDReuseDetectedByStartTimeComparison(t *testing.T) {
	t.Parallel()

	base := testPaths(t)
	pid := 5151
	staleStarted := time.Now().UTC().Add(-2 * time.Hour)
	liveStarted := time.Now().UTC()
	inspector := &fakeProcessInspector{
		running: map[int]bool{pid: true},
		start:   map[int]time.Time{pid: liveStarted},
	}

	d := newTestDaemonAtPaths(t, base.home, base.runtime, inspector)
	require.NoError(t, d.writeInfoFile(Info{
		PID:        pid,
		SocketPath: d.DaemonSocketPath(),
		AgentPath:  d.AgentSocketPath(),
		StartedAt:  staleStarted,
	}))

	require.NoError(t, d.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, d.Stop(context.Background())) })
}

func TestSIGTERMGracefulShutdownWipesVMKAndCleansArtifacts(t *testing.T) {
	t.Parallel()

	d := newTestDaemon(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	unlockWithTestVMK(t, d)
	require.False(t, d.IsLocked())
	require.True(t, d.HasLiveVMK())

	d.HandleSignal(syscall.SIGTERM)
	require.Eventually(t, func() bool {
		_, err := os.Stat(d.InfoPath())
		return os.IsNotExist(err)
	}, time.Second, 20*time.Millisecond)

	require.True(t, d.IsLocked())
	require.False(t, d.HasLiveVMK())
}

func TestSIGHUPReloadsConfigWithoutRestart(t *testing.T) {
	t.Parallel()

	var reloaded bool
	d := newTestDaemon(t, &fakeProcessInspector{})
	d.SetReloadHook(func(context.Context) error {
		reloaded = true
		return nil
	})

	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	d.HandleSignal(syscall.SIGHUP)
	require.True(t, reloaded)
	require.FileExists(t, d.DaemonSocketPath())
}

func TestSIGINTTriggersImmediateShutdown(t *testing.T) {
	t.Parallel()

	d := newTestDaemon(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	d.HandleSignal(syscall.SIGINT)
	require.Eventually(t, func() bool {
		_, err := os.Stat(d.InfoPath())
		return os.IsNotExist(err)
	}, time.Second, 20*time.Millisecond)
}

func TestAutoLockVaultAfterTimeout(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Vault.AutoLockTimeout = 60 * time.Millisecond
	d := newTestDaemonWithConfig(t, cfg, nil)

	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	unlockWithTestVMK(t, d)
	require.False(t, d.IsLocked())

	require.Eventually(t, d.IsLocked, time.Second, 20*time.Millisecond)
}

func TestAutoLockTimerResetsOnOperation(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Vault.AutoLockTimeout = 120 * time.Millisecond
	d := newTestDaemonWithConfig(t, cfg, nil)

	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	unlockWithTestVMK(t, d)
	time.Sleep(70 * time.Millisecond)
	d.TouchVaultOperation()
	time.Sleep(70 * time.Millisecond)
	require.False(t, d.IsLocked(), "timer should have been reset by operation")

	require.Eventually(t, d.IsLocked, time.Second, 20*time.Millisecond)
}

func TestMaxSessionDurationStopsSigningAfterExpiry(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Daemon.MaxSessionDuration = 80 * time.Millisecond
	d := newTestDaemonWithConfig(t, cfg, nil)

	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	unlockWithTestVMK(t, d)
	d.RegisterSigningSession("session-1")
	require.True(t, d.CanSign("session-1"))

	time.Sleep(120 * time.Millisecond)
	require.False(t, d.CanSign("session-1"))
}

func TestPeerPIDExtractionAvailableToAuthLayer(t *testing.T) {
	t.Parallel()

	d := newTestDaemon(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	conn, err := net.Dial("unix", d.DaemonSocketPath())
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	_ = conn.Close()

	require.Eventually(t, func() bool {
		return d.LastPeerPID() > 0
	}, time.Second, 20*time.Millisecond)
}

func TestConcurrentClientsTenConnectionsHandled(t *testing.T) {
	t.Parallel()

	d := newTestDaemon(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Start(ctx))
	t.Cleanup(func() { require.NoError(t, d.Stop(ctx)) })

	var wg sync.WaitGroup
	errCh := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := grpc.NewClient(
				"unix:"+d.DaemonSocketPath(),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				errCh <- err
				return
			}
			dialCtx, dialCancel := context.WithTimeout(ctx, 500*time.Millisecond)
			conn.Connect()
			for {
				s := conn.GetState()
				if s == connectivity.Ready {
					break
				}
				if !conn.WaitForStateChange(dialCtx, s) {
					dialCancel()
					_ = conn.Close()
					errCh <- dialCtx.Err()
					return
				}
			}
			dialCancel()
			_ = conn.Close()
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

func TestEnsureDaemonAutoStartsWhenNotRunning(t *testing.T) {
	t.Parallel()

	base := testPaths(t)
	cfg := config.DefaultConfig()
	cfg.Daemon.SocketDir = base.runtime

	started := false
	opts := EnsureOptions{
		HomeDir: base.home,
		Starter: func(context.Context) error {
			started = true
			info := Info{
				PID:        os.Getpid(),
				SocketPath: filepath.Join(base.runtime, "daemon.sock"),
				AgentPath:  filepath.Join(base.runtime, "agent.sock"),
				StartedAt:  time.Now().UTC(),
			}
			return writeInfo(base.home, info)
		},
		DialTimeout: 20 * time.Millisecond,
	}

	_, err := EnsureDaemonWithOptions(context.Background(), &cfg, opts)
	require.Error(t, err)
	require.True(t, started)
}

type fakeProcessInspector struct {
	running map[int]bool
	start   map[int]time.Time
}

func (f *fakeProcessInspector) IsRunning(pid int) bool {
	if f == nil || f.running == nil {
		return false
	}
	return f.running[pid]
}

func (f *fakeProcessInspector) StartTime(pid int) (time.Time, error) {
	if f == nil || f.start == nil {
		return time.Time{}, nil
	}
	return f.start[pid], nil
}

type testPathSet struct {
	home    string
	runtime string
}

func testPaths(t *testing.T) testPathSet {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "hd-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return testPathSet{
		home:    filepath.Join(base, "h"),
		runtime: filepath.Join(base, "r"),
	}
}

func newTestDaemon(t *testing.T, inspector ProcessInspector) *Daemon {
	t.Helper()
	return newTestDaemonWithConfig(t, config.DefaultConfig(), inspector)
}

func newTestDaemonWithConfig(t *testing.T, cfg config.Config, inspector ProcessInspector) *Daemon {
	t.Helper()
	base := testPaths(t)
	return newTestDaemonAtPathsAndConfig(t, base.home, base.runtime, cfg, inspector)
}

func newTestDaemonAtPaths(t *testing.T, home, runtime string, inspector ProcessInspector) *Daemon {
	t.Helper()
	return newTestDaemonAtPathsAndConfig(t, home, runtime, config.DefaultConfig(), inspector)
}

func unlockWithTestVMK(t *testing.T, d *Daemon) {
	t.Helper()
	vmk, err := crypto.GenerateVMK()
	require.NoError(t, err)
	d.SetVMK(vmk)
}

func newTestDaemonAtPathsAndConfig(t *testing.T, home, runtime string, cfg config.Config, inspector ProcessInspector) *Daemon {
	t.Helper()
	cfg.Daemon.SocketDir = runtime
	d, err := New(cfg, Options{
		HomeDir:    home,
		RuntimeDir: runtime,
		Inspector:  inspector,
	})
	require.NoError(t, err)
	return d
}
