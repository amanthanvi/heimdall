//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	daemonpkg "github.com/amanthanvi/heimdall/internal/daemon"
	"github.com/stretchr/testify/require"
)

var (
	repoRoot         string
	integrationBin   string
	integrationCache string
)

func TestMain(m *testing.M) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "integration: resolve current file")
		os.Exit(1)
	}
	repoRoot = filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))

	tmpDir, err := os.MkdirTemp(repoRoot, ".integration-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	integrationCache = filepath.Join(tmpDir, "gocache")
	if err := os.MkdirAll(integrationCache, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "integration: create gocache: %v\n", err)
		os.Exit(1)
	}

	integrationBin = filepath.Join(tmpDir, "heimdall")
	buildCmd := exec.Command("go", "build", "-o", integrationBin, "./cmd/heimdall")
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "GOCACHE="+integrationCache)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "integration: build cli: %v\n%s\n", err, string(output))
		os.Exit(1)
	}

	os.Exit(m.Run())
}

type cliHarness struct {
	home      string
	runtime   string
	vaultPath string
	config    string
}

type cliResult struct {
	output   string
	exitCode int
	err      error
}

func newHarness(t *testing.T) *cliHarness {
	t.Helper()

	base, err := os.MkdirTemp(repoRoot, ".integration-run-")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(base)
	})

	h := &cliHarness{
		home:      filepath.Join(base, "home"),
		runtime:   filepath.Join(base, "run"),
		vaultPath: filepath.Join(base, "home", "vault.db"),
		config:    filepath.Join(base, "home", "config.toml"),
	}
	t.Cleanup(func() {
		_ = h.run(5*time.Second, "daemon", "stop")
	})
	return h
}

func (h *cliHarness) env() []string {
	return []string{
		"HEIMDALL_HOME=" + h.home,
		"HEIMDALL_VAULT_PATH=" + h.vaultPath,
		"HEIMDALL_CONFIG_PATH=" + h.config,
		"HEIMDALL_DAEMON_SOCKET_DIR=" + h.runtime,
		"HEIMDALL_CLIENT_ID=" + h.home,
		"GOCACHE=" + integrationCache,
	}
}

func (h *cliHarness) run(timeout time.Duration, args ...string) cliResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, integrationBin, args...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), h.env()...)
	output, err := cmd.CombinedOutput()

	res := cliResult{
		output: strings.TrimSpace(string(output)),
		err:    err,
	}
	if err == nil {
		res.exitCode = 0
		return res
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.exitCode = exitErr.ExitCode()
		return res
	}
	res.exitCode = -1
	if ctx.Err() != nil {
		res.output = strings.TrimSpace(string(output) + "\n" + ctx.Err().Error())
	}
	return res
}

func requireSuccess(t *testing.T, res cliResult, command ...string) string {
	t.Helper()
	require.NoError(t, res.err, "command failed: %s\noutput:\n%s", strings.Join(command, " "), res.output)
	require.Equal(t, 0, res.exitCode)
	return res.output
}

func requireFailure(t *testing.T, res cliResult, command ...string) string {
	t.Helper()
	require.Error(t, res.err, "command unexpectedly succeeded: %s\noutput:\n%s", strings.Join(command, " "), res.output)
	require.NotEqual(t, 0, res.exitCode)
	return res.output
}

func (h *cliHarness) daemonInfoPath() string {
	return filepath.Join(h.home, "daemon.info")
}

func (h *cliHarness) daemonInfo(t *testing.T) daemonpkg.Info {
	t.Helper()
	raw, err := os.ReadFile(h.daemonInfoPath())
	require.NoError(t, err)
	var info daemonpkg.Info
	require.NoError(t, json.Unmarshal(raw, &info))
	return info
}

func TestIntegrationLifecycleHostConnectAndLock(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "host", "add", "--name", "prod", "--addr", "127.0.0.1", "--user", "root"), "host add --name prod --addr 127.0.0.1 --user root")
	connectOut := requireSuccess(t, h.run(10*time.Second, "connect", "prod", "--dry-run"), "connect prod --dry-run")
	require.Contains(t, connectOut, "ssh")
	requireSuccess(t, h.run(10*time.Second, "vault", "lock"), "vault lock")

	lockedOut := requireFailure(t, h.run(10*time.Second, "host", "ls"), "host ls")
	require.Contains(t, strings.ToLower(lockedOut), "vault is locked")
}

func TestIntegrationLifecycleSecretShowEnvDelete(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "secret", "add", "--name", "api_token", "--value", "super-secret"), "secret add --name api_token --value super-secret")
	showOut := requireSuccess(t, h.run(10*time.Second, "secret", "show", "api_token", "--reauth"), "secret show api_token --reauth")
	require.Contains(t, showOut, "super-secret")
	envOut := requireSuccess(
		t,
		h.run(10*time.Second, "secret", "env", "api_token", "--env-var", "API_TOKEN", "--", "sh", "-c", `test -n "$API_TOKEN" && printf ok`),
		"secret env api_token --env-var API_TOKEN -- sh -c test -n \"$API_TOKEN\" && printf ok",
	)
	require.Contains(t, envOut, "ok")
	require.NotContains(t, envOut, "super-secret")
	requireSuccess(t, h.run(10*time.Second, "secret", "rm", "api_token"), "secret rm api_token")
}

func TestIntegrationLifecycleKeyGenerateExportDelete(t *testing.T) {
	h := newHarness(t)
	exportPath := filepath.Join(h.home, "deploy.key")

	requireSuccess(t, h.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "key", "gen", "--name", "deploy"), "key gen --name deploy")
	requireSuccess(t, h.run(10*time.Second, "key", "export", "deploy", "--private", "--reauth", "--output", exportPath), "key export deploy --private --reauth --output <path>")
	keyBytes, err := os.ReadFile(exportPath)
	require.NoError(t, err)
	require.NotEmpty(t, keyBytes)
	require.Contains(t, string(keyBytes), "PRIVATE KEY")
	requireSuccess(t, h.run(10*time.Second, "key", "rm", "deploy"), "key rm deploy")
}

func TestIntegrationLifecycleBackupRestoreVerify(t *testing.T) {
	source := newHarness(t)
	backupPath := filepath.Join(source.home, "vault.backup")

	requireSuccess(t, source.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, source.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "host", "add", "--name", "restore-me", "--addr", "10.10.10.10", "--user", "ubuntu"), "host add --name restore-me --addr 10.10.10.10 --user ubuntu")
	requireSuccess(t, source.run(10*time.Second, "backup", "create", "--output", backupPath, "--passphrase", "backup-pass"), "backup create --output <path> --passphrase backup-pass")

	target := newHarness(t)
	requireSuccess(t, target.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, target.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	require.NoError(t, os.Remove(target.vaultPath))
	requireSuccess(t, target.run(10*time.Second, "backup", "restore", "--from", backupPath, "--passphrase", "backup-pass"), "backup restore --from <path> --passphrase backup-pass")
	listOut := requireSuccess(t, target.run(10*time.Second, "host", "ls", "--names-only"), "host ls --names-only")
	require.Contains(t, listOut, "restore-me")
}

func TestIntegrationDaemonRestartRequiresUnlockAgain(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "host", "add", "--name", "restart-host", "--addr", "127.0.0.1"), "host add --name restart-host --addr 127.0.0.1")
	requireSuccess(t, h.run(10*time.Second, "daemon", "restart"), "daemon restart")

	lockedOut := requireFailure(t, h.run(10*time.Second, "host", "ls"), "host ls")
	require.Contains(t, strings.ToLower(lockedOut), "vault is locked")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	listOut := requireSuccess(t, h.run(10*time.Second, "host", "ls", "--names-only"), "host ls --names-only")
	require.Contains(t, listOut, "restart-host")
}

func TestIntegrationDaemonCrashCleansStaleInfoOnNextCommand(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	before := h.daemonInfo(t)

	process, err := os.FindProcess(before.PID)
	require.NoError(t, err)
	require.NoError(t, process.Signal(syscall.SIGKILL))
	time.Sleep(150 * time.Millisecond)

	requireSuccess(t, h.run(10*time.Second, "status"), "status")
	after := h.daemonInfo(t)
	require.NotEqual(t, before.PID, after.PID)
}

func TestIntegrationConcurrentCLIHostList(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes"), "init --yes")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "host", "add", "--name", "parallel-host", "--addr", "127.0.0.1"), "host add --name parallel-host --addr 127.0.0.1")

	var wg sync.WaitGroup
	errCh := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := h.run(10*time.Second, "host", "ls", "--names-only")
			if res.err != nil {
				errCh <- fmt.Errorf("exit=%d output=%s", res.exitCode, res.output)
				return
			}
			if !strings.Contains(res.output, "parallel-host") {
				errCh <- fmt.Errorf("missing host in output: %s", res.output)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}
