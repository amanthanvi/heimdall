package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/athanvi/heimdall/internal/config"
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type StartRequest struct {
	Name            string
	RuntimeDir      string
	UpstreamSocket  string
	UpstreamCommand []string
	TTL             time.Duration
}

type State struct {
	SocketPath string    `json:"socket_path"`
	ExpiresAt  time.Time `json:"expires_at"`
	RuntimeDir string    `json:"runtime_dir"`
	Mode       string    `json:"mode"`
}

type Server struct {
	listener net.Listener
	cancel   context.CancelFunc
	done     chan struct{}
	socket   string
	marker   string
	once     sync.Once
}

func Start(ctx context.Context, req StartRequest) (*Server, State, error) {
	if req.Name == "" {
		req.Name = "session"
	}
	if !safeName.MatchString(req.Name) {
		return nil, State{}, fmt.Errorf("bridge name must contain only letters, numbers, dot, underscore, or dash")
	}
	if req.TTL <= 0 {
		req.TTL = 30 * time.Minute
	}
	if req.RuntimeDir == "" {
		req.RuntimeDir = DefaultRuntimeDir()
	}
	if err := PrepareRuntimeDir(req.RuntimeDir); err != nil {
		return nil, State{}, err
	}
	if req.UpstreamSocket == "" && len(req.UpstreamCommand) == 0 {
		return nil, State{}, fmt.Errorf("bridge requires an upstream Unix socket or explicit argv command")
	}
	if req.UpstreamSocket != "" && len(req.UpstreamCommand) > 0 {
		return nil, State{}, fmt.Errorf("bridge accepts only one upstream mode")
	}
	if req.UpstreamSocket != "" {
		if err := validateSocketRef(req.UpstreamSocket); err != nil {
			return nil, State{}, err
		}
	}
	if len(req.UpstreamCommand) > 0 {
		if err := validateCommand(req.UpstreamCommand); err != nil {
			return nil, State{}, err
		}
	}
	socketPath := filepath.Join(req.RuntimeDir, "heimdall-"+req.Name+".sock")
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, State{}, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, State{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	markerPath := filepath.Join(req.RuntimeDir, "heimdall-bridge.cleanup")
	srv := &Server{listener: listener, cancel: cancel, done: make(chan struct{}), socket: socketPath, marker: markerPath}
	expires := time.Now().UTC().Add(req.TTL)
	mode := "socket"
	if len(req.UpstreamCommand) > 0 {
		mode = "command"
	}
	if err := WriteCleanupMarker(req.RuntimeDir, socketPath, expires); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		cancel()
		return nil, State{}, err
	}
	go srv.serve(ctx, req, expires)
	return srv, State{SocketPath: socketPath, ExpiresAt: expires, RuntimeDir: req.RuntimeDir, Mode: mode}, nil
}

func (s *Server) Stop() error {
	var err error
	s.once.Do(func() {
		s.cancel()
		err = s.listener.Close()
		<-s.done
		removeErr := os.Remove(s.socket)
		if err == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = removeErr
		}
		markerErr := os.Remove(s.marker)
		if err == nil && markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
			err = markerErr
		}
	})
	return err
}

func (s *Server) serve(ctx context.Context, req StartRequest, expires time.Time) {
	defer close(s.done)
	timer := time.NewTimer(time.Until(expires))
	defer timer.Stop()
	go func() {
		select {
		case <-ctx.Done():
		case <-timer.C:
			s.cancel()
			_ = s.listener.Close()
		}
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go handleConn(ctx, conn, req)
	}
}

func handleConn(ctx context.Context, client net.Conn, req StartRequest) {
	defer client.Close()
	if req.UpstreamSocket != "" {
		upstream, err := net.DialTimeout("unix", req.UpstreamSocket, 3*time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()
		proxy(client, upstream)
		return
	}
	cmd := exec.CommandContext(ctx, req.UpstreamCommand[0], req.UpstreamCommand[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stdin, client)
		_ = stdin.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, stdout)
	}()
	wg.Wait()
	_ = cmd.Wait()
}

func proxy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = a.SetDeadline(time.Now())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = b.SetDeadline(time.Now())
	}()
	wg.Wait()
}

func DefaultRuntimeDir() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("heimdall-%d", os.Getuid()))
	} else {
		base = filepath.Join(base, "heimdall")
	}
	return base
}

func PrepareRuntimeDir(path string) error {
	if path == "" {
		return fmt.Errorf("runtime dir is required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime dir must not be a symlink")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	} else {
		return err
	}
	return DoctorRuntimeDir(path)
}

func DoctorRuntimeDir(path string) error {
	if path == "" {
		return fmt.Errorf("runtime dir is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime path is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("runtime dir permissions too broad: %s", info.Mode().Perm())
	}
	return nil
}

func WriteCleanupMarker(runtimeDir, socketPath string, expiresAt time.Time) error {
	if err := DoctorRuntimeDir(runtimeDir); err != nil {
		return err
	}
	body := []byte(socketPath + "\n" + expiresAt.UTC().Format(time.RFC3339) + "\n")
	return config.AtomicWrite(filepath.Join(runtimeDir, "heimdall-bridge.cleanup"), body, 0o600)
}

func CleanupExpired(runtimeDir string, now time.Time) error {
	marker := filepath.Join(runtimeDir, "heimdall-bridge.cleanup")
	data, err := os.ReadFile(marker)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return fmt.Errorf("invalid cleanup marker")
	}
	expires, err := time.Parse(time.RFC3339, strings.TrimSpace(lines[1]))
	if err != nil {
		return err
	}
	if now.Before(expires) {
		return nil
	}
	socketPath := strings.TrimSpace(lines[0])
	if filepath.Dir(socketPath) != runtimeDir {
		return fmt.Errorf("cleanup marker points outside runtime dir")
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateSocketRef(path string) error {
	if strings.ContainsRune(path, '\x00') || strings.ContainsAny(path, "\n\r") {
		return fmt.Errorf("upstream socket path contains invalid control characters")
	}
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("upstream socket path must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("upstream path is not a Unix socket")
	}
	return nil
}

func validateCommand(argv []string) error {
	if len(argv) == 0 || argv[0] == "" {
		return fmt.Errorf("upstream command is required")
	}
	for _, arg := range argv {
		if strings.ContainsRune(arg, '\x00') || strings.ContainsAny(arg, "\n\r") {
			return fmt.Errorf("upstream command contains invalid control characters")
		}
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return fmt.Errorf("upstream command binary not found: %w", err)
	}
	return nil
}
