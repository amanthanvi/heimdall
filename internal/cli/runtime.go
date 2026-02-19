package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/amanthanvi/heimdall/internal/daemon"
	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type daemonClients struct {
	conn    *grpcpkg.ClientConn
	vault   v1.VaultServiceClient
	host    v1.HostServiceClient
	secret  v1.SecretServiceClient
	key     v1.KeyServiceClient
	passkey v1.PasskeyServiceClient
	connect v1.ConnectServiceClient
	audit   v1.AuditServiceClient
	backup  v1.BackupServiceClient
	version v1.VersionServiceClient
}

func withDaemonClients(cmdCtx context.Context, deps commandDeps, fn func(context.Context, daemonClients) error) error {
	timeout := deps.globals.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(cmdCtx, timeout)
	defer cancel()

	cfg, _, err := config.Load(config.LoadOptions{})
	if err != nil {
		return mapCommandError(fmt.Errorf("load config: %w", err))
	}

	conn, err := daemon.EnsureDaemonWithOptions(ctx, &cfg, daemon.EnsureOptions{})
	if err != nil {
		return mapCommandError(fmt.Errorf("ensure daemon: %w", err))
	}
	defer conn.Close()

	ctx = attachCallerMetadata(ctx)
	clients := daemonClients{
		conn:    conn,
		vault:   v1.NewVaultServiceClient(conn),
		host:    v1.NewHostServiceClient(conn),
		secret:  v1.NewSecretServiceClient(conn),
		key:     v1.NewKeyServiceClient(conn),
		passkey: v1.NewPasskeyServiceClient(conn),
		connect: v1.NewConnectServiceClient(conn),
		audit:   v1.NewAuditServiceClient(conn),
		backup:  v1.NewBackupServiceClient(conn),
		version: v1.NewVersionServiceClient(conn),
	}
	return mapCommandError(fn(ctx, clients))
}

func outputValue(w io.Writer, asJSON bool, value any) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	}
	_, err := fmt.Fprintln(w, value)
	return err
}

func printJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func boolToState(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

type grpcSecretGetter struct {
	client v1.SecretServiceClient
}

func (g grpcSecretGetter) GetValue(ctx context.Context, name string) ([]byte, error) {
	if g.client == nil {
		return nil, fmt.Errorf("secret env: secret service client is nil")
	}
	resp, err := g.client.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: name})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), resp.GetValue()...), nil
}

func runSecretEnv(
	ctx context.Context,
	client v1.SecretServiceClient,
	secretName string,
	envVar string,
	command []string,
	baseEnv []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	if strings.TrimSpace(secretName) == "" {
		return -1, fmt.Errorf("secret env: secret name is required")
	}
	if strings.TrimSpace(envVar) == "" {
		return -1, fmt.Errorf("secret env: env var name is required")
	}
	if len(command) == 0 {
		return -1, fmt.Errorf("secret env: command is required")
	}

	value, err := grpcSecretGetter{client: client}.GetValue(ctx, secretName)
	if err != nil {
		return -1, fmt.Errorf("secret env: get value: %w", err)
	}
	defer wipeBytes(value)

	execCmd := exec.CommandContext(ctx, command[0], command[1:]...)
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	execCmd.Stdout = stdout
	execCmd.Stderr = stderr

	if len(baseEnv) > 0 {
		execCmd.Env = append([]string(nil), baseEnv...)
	} else {
		execCmd.Env = append([]string(nil), os.Environ()...)
	}
	execCmd.Env = append(execCmd.Env, envVar+"="+string(value))

	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return -1, fmt.Errorf("secret env: run command: %w", err)
	}
	return 0, nil
}

func attachCallerMetadata(ctx context.Context) context.Context {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return metadata.AppendToOutgoingContext(
		ctx,
		"x-heimdall-pid",
		fmt.Sprintf("%d", os.Getpid()),
		"x-heimdall-process-start",
		now,
	)
}

func normalizeLines(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func wipeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
