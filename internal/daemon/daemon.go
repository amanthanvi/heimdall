package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/amanthanvi/heimdall/internal/crypto"
	"github.com/awnumar/memguard"
	"google.golang.org/grpc"
)

const (
	defaultMaxSessionDuration = 8 * time.Hour
)

type Daemon struct {
	cfg config.Config

	homeDir          string
	runtimeDir       string
	infoPath         string
	daemonSocketPath string
	agentSocketPath  string

	inspector ProcessInspector
	now       func() time.Time

	reloadHook func(context.Context) error

	mu            sync.RWMutex
	locked        bool
	vmk           *memguard.LockedBuffer
	autoLockTimer *time.Timer

	sessionMu      sync.RWMutex
	sessionStarts  map[string]time.Time
	maxSessionLife time.Duration

	grpcServer     *grpc.Server
	daemonListener net.Listener
	agentListener  net.Listener
	agentStopCh    chan struct{}
	stopOnce       sync.Once
	doneCh         chan struct{}
	started        atomic.Bool
	lastPeerPID    atomic.Int64

	signalCh      <-chan os.Signal
	ownedSignalCh chan os.Signal
}

func New(cfg config.Config, opts Options) (*Daemon, error) {
	homeDir, err := resolveHomeDir(opts.HomeDir)
	if err != nil {
		return nil, err
	}
	runtimeDir := resolveRuntimeDir(cfg, opts.RuntimeDir)

	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	inspector := opts.Inspector
	if inspector == nil {
		inspector = defaultProcessInspector{}
	}

	maxSessionLife := cfg.Daemon.MaxSessionDuration
	if maxSessionLife <= 0 {
		maxSessionLife = defaultMaxSessionDuration
	}

	d := &Daemon{
		cfg:              cfg,
		homeDir:          homeDir,
		runtimeDir:       runtimeDir,
		infoPath:         filepath.Join(homeDir, daemonInfoFile),
		daemonSocketPath: filepath.Join(runtimeDir, "daemon.sock"),
		agentSocketPath:  filepath.Join(runtimeDir, "agent.sock"),
		inspector:        inspector,
		now:              now,
		reloadHook:       opts.ReloadHook,
		locked:           true,
		sessionStarts:    map[string]time.Time{},
		maxSessionLife:   maxSessionLife,
		agentStopCh:      make(chan struct{}),
		doneCh:           make(chan struct{}),
		signalCh:         opts.SignalCh,
	}

	return d, nil
}

func (d *Daemon) Start(ctx context.Context) error {
	if d == nil {
		return fmt.Errorf("start daemon: nil daemon")
	}
	if d.started.Load() {
		return ErrDaemonAlreadyRunning
	}

	if err := d.prepareStartupState(); err != nil {
		return err
	}
	if err := os.MkdirAll(d.runtimeDir, 0o700); err != nil {
		return fmt.Errorf("start daemon: create runtime dir: %w", err)
	}
	if err := os.Chmod(d.runtimeDir, 0o700); err != nil {
		return fmt.Errorf("start daemon: set runtime dir permissions: %w", err)
	}

	if err := validateUNIXSocketPath(d.daemonSocketPath); err != nil {
		return err
	}
	if err := validateUNIXSocketPath(d.agentSocketPath); err != nil {
		return err
	}

	_ = removeIfExists(d.daemonSocketPath)
	_ = removeIfExists(d.agentSocketPath)

	daemonListener, err := net.Listen("unix", d.daemonSocketPath)
	if err != nil {
		return fmt.Errorf("start daemon: listen daemon socket: %w", err)
	}
	if err := os.Chmod(d.daemonSocketPath, 0o600); err != nil {
		_ = daemonListener.Close()
		return fmt.Errorf("start daemon: chmod daemon socket: %w", err)
	}

	agentListener, err := net.Listen("unix", d.agentSocketPath)
	if err != nil {
		_ = daemonListener.Close()
		return fmt.Errorf("start daemon: listen agent socket: %w", err)
	}
	if err := os.Chmod(d.agentSocketPath, 0o600); err != nil {
		_ = agentListener.Close()
		_ = daemonListener.Close()
		return fmt.Errorf("start daemon: chmod agent socket: %w", err)
	}

	d.grpcServer = grpc.NewServer()
	d.daemonListener = daemonListener
	d.agentListener = agentListener

	trackedListener := &peerTrackingListener{
		Listener: d.daemonListener,
		onAccept: d.capturePeerPID,
	}

	go func() {
		_ = d.grpcServer.Serve(trackedListener)
	}()
	go d.serveAgentSocket()

	info := Info{
		PID:        os.Getpid(),
		SocketPath: d.daemonSocketPath,
		AgentPath:  d.agentSocketPath,
		StartedAt:  d.currentProcessStart(),
	}
	if err := d.writeInfoFile(info); err != nil {
		_ = d.stopInternal(ctx, true)
		return fmt.Errorf("start daemon: write daemon info: %w", err)
	}

	d.startSignalLoop()
	d.started.Store(true)
	return nil
}

func (d *Daemon) Stop(ctx context.Context) error {
	return d.stopInternal(ctx, false)
}

func (d *Daemon) stopInternal(_ context.Context, immediate bool) error {
	if d == nil {
		return nil
	}

	var stopErr error
	d.stopOnce.Do(func() {
		close(d.doneCh)
		close(d.agentStopCh)

		d.mu.Lock()
		if d.autoLockTimer != nil {
			d.autoLockTimer.Stop()
			d.autoLockTimer = nil
		}
		if d.vmk != nil && d.vmk.IsAlive() {
			d.vmk.Destroy()
		}
		d.vmk = nil
		d.locked = true
		d.mu.Unlock()

		if d.grpcServer != nil {
			if immediate {
				d.grpcServer.Stop()
			} else {
				d.grpcServer.GracefulStop()
			}
		}

		if d.agentListener != nil {
			_ = d.agentListener.Close()
		}
		if d.daemonListener != nil {
			_ = d.daemonListener.Close()
		}

		if err := removeIfExists(d.daemonSocketPath); err != nil && stopErr == nil {
			stopErr = err
		}
		if err := removeIfExists(d.agentSocketPath); err != nil && stopErr == nil {
			stopErr = err
		}
		if err := removeIfExists(d.infoPath); err != nil && stopErr == nil {
			stopErr = err
		}

		if d.ownedSignalCh != nil {
			signal.Stop(d.ownedSignalCh)
			close(d.ownedSignalCh)
			d.ownedSignalCh = nil
		}

		d.started.Store(false)
	})
	return stopErr
}

func (d *Daemon) Unlock(_ []byte) error {
	vmk, err := crypto.GenerateVMK()
	if err != nil {
		return fmt.Errorf("unlock daemon: generate vmk: %w", err)
	}

	d.mu.Lock()
	if d.vmk != nil && d.vmk.IsAlive() {
		d.vmk.Destroy()
	}
	d.vmk = vmk
	d.locked = false
	d.resetAutoLockTimerLocked()
	d.mu.Unlock()
	return nil
}

func (d *Daemon) UnlockWithPasskey(_ string) error {
	return d.Unlock(nil)
}

func (d *Daemon) Lock() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.vmk != nil && d.vmk.IsAlive() {
		d.vmk.Destroy()
	}
	d.vmk = nil
	d.locked = true
	if d.autoLockTimer != nil {
		d.autoLockTimer.Stop()
		d.autoLockTimer = nil
	}
	return nil
}

func (d *Daemon) TouchVaultOperation() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.locked {
		return
	}
	d.resetAutoLockTimerLocked()
}

func (d *Daemon) RegisterSigningSession(id string) {
	if id == "" {
		return
	}
	d.sessionMu.Lock()
	defer d.sessionMu.Unlock()
	d.sessionStarts[id] = d.now()
}

func (d *Daemon) CanSign(id string) bool {
	if id == "" {
		return false
	}
	if d.IsLocked() {
		return false
	}

	d.sessionMu.RLock()
	startedAt, ok := d.sessionStarts[id]
	d.sessionMu.RUnlock()
	if !ok {
		return false
	}
	if d.now().Sub(startedAt) > d.maxSessionLife {
		return false
	}
	return true
}

func (d *Daemon) SetReloadHook(hook func(context.Context) error) {
	d.reloadHook = hook
}

func (d *Daemon) HandleSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGTERM:
		_ = d.stopInternal(context.Background(), false)
	case syscall.SIGINT:
		_ = d.stopInternal(context.Background(), true)
	case syscall.SIGHUP:
		if d.reloadHook != nil {
			_ = d.reloadHook(context.Background())
		}
	}
}

func (d *Daemon) RuntimeDir() string {
	return d.runtimeDir
}

func (d *Daemon) DaemonSocketPath() string {
	return d.daemonSocketPath
}

func (d *Daemon) AgentSocketPath() string {
	return d.agentSocketPath
}

func (d *Daemon) InfoPath() string {
	return d.infoPath
}

func (d *Daemon) LastPeerPID() int {
	return int(d.lastPeerPID.Load())
}

func (d *Daemon) IsLocked() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.locked
}

func (d *Daemon) HasLiveVMK() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vmk != nil && d.vmk.IsAlive()
}

func (d *Daemon) writeInfoFile(info Info) error {
	return writeInfo(d.homeDir, info)
}

func (d *Daemon) prepareStartupState() error {
	info, err := readInfo(d.infoPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("start daemon: read daemon info: %w", err)
	}

	if d.inspector.IsRunning(info.PID) {
		liveStartedAt, startErr := d.inspector.StartTime(info.PID)
		if startErr == nil && !liveStartedAt.IsZero() && !sameStartTime(info.StartedAt, liveStartedAt) {
			return d.cleanupStale(info)
		}
		return ErrDaemonAlreadyRunning
	}

	return d.cleanupStale(info)
}

func (d *Daemon) cleanupStale(info Info) error {
	paths := []string{
		info.SocketPath,
		info.AgentPath,
		d.daemonSocketPath,
		d.agentSocketPath,
		d.infoPath,
	}
	for _, path := range paths {
		if err := removeIfExists(path); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) resetAutoLockTimerLocked() {
	timeout := d.cfg.Vault.AutoLockTimeout
	if timeout <= 0 {
		return
	}
	if d.autoLockTimer == nil {
		d.autoLockTimer = time.AfterFunc(timeout, func() {
			_ = d.Lock()
		})
		return
	}
	d.autoLockTimer.Stop()
	d.autoLockTimer.Reset(timeout)
}

func (d *Daemon) startSignalLoop() {
	if d.signalCh == nil {
		d.ownedSignalCh = make(chan os.Signal, 4)
		signal.Notify(d.ownedSignalCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		d.signalCh = d.ownedSignalCh
	}

	go func() {
		for {
			select {
			case <-d.doneCh:
				return
			case sig, ok := <-d.signalCh:
				if !ok {
					return
				}
				d.HandleSignal(sig)
			}
		}
	}()
}

func (d *Daemon) serveAgentSocket() {
	for {
		select {
		case <-d.agentStopCh:
			return
		default:
		}

		conn, err := d.agentListener.Accept()
		if err != nil {
			select {
			case <-d.agentStopCh:
				return
			default:
				continue
			}
		}
		_ = conn.Close()
	}
}

func (d *Daemon) capturePeerPID(conn net.Conn) {
	pid, err := peerPIDFromConn(conn)
	if err != nil {
		return
	}
	d.lastPeerPID.Store(int64(pid))
}

func (d *Daemon) currentProcessStart() time.Time {
	pid := os.Getpid()
	startedAt, err := d.inspector.StartTime(pid)
	if err == nil && !startedAt.IsZero() {
		return startedAt.UTC()
	}
	return d.now()
}

func sameStartTime(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return true
	}
	delta := a.UTC().Sub(b.UTC())
	if delta < 0 {
		delta = -delta
	}
	return delta <= time.Second
}

type peerTrackingListener struct {
	net.Listener
	onAccept func(net.Conn)
}

func (l *peerTrackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.onAccept != nil {
		l.onAccept(conn)
	}
	return conn, nil
}

type defaultProcessInspector struct{}

func (defaultProcessInspector) IsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return err == syscall.EPERM
}

func (defaultProcessInspector) StartTime(pid int) (time.Time, error) {
	if pid <= 0 {
		return time.Time{}, fmt.Errorf("invalid pid: %d", pid)
	}
	cmd := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid))
	out, err := cmd.Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("read process start time: %w", err)
	}

	startRaw := trimPSOutput(string(out))
	if startRaw == "" {
		return time.Time{}, fmt.Errorf("empty process start time")
	}

	parsed, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.TrimSpace(startRaw), time.Local)
	if err != nil {
		if runtime.GOOS == "linux" {
			// Linux ps may include timezone.
			parsedTZ, tzErr := time.ParseInLocation("Mon Jan _2 15:04:05 MST 2006", strings.TrimSpace(startRaw), time.Local)
			if tzErr == nil {
				return parsedTZ.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("parse process start time %q: %w", startRaw, err)
	}
	return parsed.UTC(), nil
}
