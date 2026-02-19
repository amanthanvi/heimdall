package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/amanthanvi/heimdall/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultEnsureDialTimeout = 2 * time.Second

func EnsureDaemon(cfg *config.Config) (*grpc.ClientConn, error) {
	return EnsureDaemonWithOptions(context.Background(), cfg, EnsureOptions{})
}

func EnsureDaemonWithOptions(ctx context.Context, cfg *config.Config, opts EnsureOptions) (*grpc.ClientConn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ensure daemon: config is nil")
	}

	homeDir, err := resolveHomeDir(opts.HomeDir)
	if err != nil {
		return nil, err
	}
	runtimeDir := resolveRuntimeDir(*cfg, opts.RuntimeDir)
	infoPath := filepath.Join(homeDir, daemonInfoFile)

	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultEnsureDialTimeout
	}

	info, err := readInfo(infoPath)
	if err == nil {
		conn, dialErr := dialDaemon(ctx, info.SocketPath, dialTimeout)
		if dialErr == nil {
			return conn, nil
		}
		cleanupStaleRuntimeArtifacts(infoPath, info)
	}

	starter := opts.Starter
	if starter == nil {
		return nil, ErrDaemonStartUnsupported
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return nil, fmt.Errorf("ensure daemon: create runtime dir: %w", err)
	}
	if err := starter(ctx); err != nil {
		return nil, fmt.Errorf("ensure daemon: start daemon: %w", err)
	}

	deadline := time.Now().Add(dialTimeout)
	for time.Now().Before(deadline) {
		info, readErr := readInfo(infoPath)
		if readErr == nil {
			conn, dialErr := dialDaemon(ctx, info.SocketPath, dialTimeout)
			if dialErr == nil {
				return conn, nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	return nil, fmt.Errorf("ensure daemon: daemon did not become ready")
}

func dialDaemon(ctx context.Context, socketPath string, timeout time.Duration) (*grpc.ClientConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		var netDialer net.Dialer
		return netDialer.DialContext(ctx, "unix", socketPath)
	}
	conn, err := grpc.DialContext(
		dialCtx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func cleanupStaleRuntimeArtifacts(infoPath string, info Info) {
	_ = removeIfExists(info.SocketPath)
	_ = removeIfExists(info.AgentPath)
	_ = removeIfExists(infoPath)
}
