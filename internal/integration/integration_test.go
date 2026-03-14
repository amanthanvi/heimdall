//go:build integration

package integration

import (
	"context"
	"database/sql"
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
	_ "modernc.org/sqlite"
)

var (
	repoRoot         string
	integrationBin   string
	integrationCache string
)

const backupCommandTimeout = 45 * time.Second

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
		"HOME=" + h.home,
		"HEIMDALL_HOME=" + h.home,
		"HEIMDALL_VAULT_PATH=" + h.vaultPath,
		"HEIMDALL_CONFIG_PATH=" + h.config,
		"HEIMDALL_DAEMON_SOCKET_DIR=" + h.runtime,
		"HEIMDALL_CLIENT_ID=" + h.home,
		"GOCACHE=" + integrationCache,
	}
}

func TestIntegrationHostDefaultsRoundTripAndConnectPlan(t *testing.T) {
	h := newHarness(t)
	identityPath := filepath.Join(h.home, ".ssh", "id_prod")

	requireSuccess(t, h.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "key", "generate", "--name", "deploy"), "key generate --name deploy")
	requireSuccess(
		t,
		h.run(
			10*time.Second,
			"host", "add",
			"--name", "prod",
			"--address", "192.168.1.186",
			"--user", "kali",
			"--tag", "critical",
			"--notes", "primary prod access",
			"--key", "deploy",
			"--proxy-jump", "bastion",
			"--known-hosts-policy", "accept-new",
			"--forward-agent",
		),
		"host add --name prod --address 192.168.1.186 --user kali --tag critical --notes 'primary prod access' --key deploy --proxy-jump bastion --known-hosts-policy accept-new --forward-agent",
	)

	showOut := requireSuccess(t, h.run(10*time.Second, "--json", "host", "show", "prod"), "--json host show prod")
	var created map[string]any
	require.NoError(t, json.Unmarshal([]byte(showOut), &created))
	require.Equal(t, "primary prod access", created["notes"])
	require.Equal(t, "deploy", created["key_name"])
	require.Equal(t, "bastion", created["proxy_jump"])
	require.Equal(t, "accept-new", created["known_hosts_policy"])
	require.Equal(t, true, created["forward_agent"])

	planOut := requireSuccess(t, h.run(10*time.Second, "--json", "connect", "prod", "--dry-run"), "--json connect prod --dry-run")
	var initialPlan map[string]any
	require.NoError(t, json.Unmarshal([]byte(planOut), &initialPlan))
	initialArgs := strings.Join(stringSliceFromAny(t, initialPlan["args"]), " ")
	require.Contains(t, initialArgs, "-J bastion")
	require.Contains(t, initialArgs, "-A")
	require.Contains(t, initialArgs, "StrictHostKeyChecking=accept-new")
	require.Equal(t, map[string]any{"mode": "managed-agent", "key": "deploy", "ttl": "30m0s"}, initialPlan["auth"])

	requireSuccess(
		t,
		h.run(
			10*time.Second,
			"host", "edit", "prod",
			"--identity-file", identityPath,
			"--clear-key",
			"--clear-proxy-jump",
			"--known-hosts-policy", "strict",
			"--no-forward-agent",
			"--notes", "break glass",
		),
		"host edit prod --identity-file <path> --clear-key --clear-proxy-jump --known-hosts-policy strict --no-forward-agent --notes 'break glass'",
	)

	editedOut := requireSuccess(t, h.run(10*time.Second, "--json", "host", "show", "prod"), "--json host show prod")
	var edited map[string]any
	require.NoError(t, json.Unmarshal([]byte(editedOut), &edited))
	require.Equal(t, "break glass", edited["notes"])
	require.Equal(t, identityPath, edited["identity_path"])
	require.Equal(t, "", optionalStringFromMap(edited, "key_name"))
	require.Equal(t, "", optionalStringFromMap(edited, "proxy_jump"))
	require.Equal(t, "strict", edited["known_hosts_policy"])
	require.False(t, optionalBoolFromMap(edited, "forward_agent"))

	updatedPlanOut := requireSuccess(t, h.run(10*time.Second, "--json", "connect", "prod", "--dry-run"), "--json connect prod --dry-run")
	var updatedPlan map[string]any
	require.NoError(t, json.Unmarshal([]byte(updatedPlanOut), &updatedPlan))
	updatedArgs := strings.Join(stringSliceFromAny(t, updatedPlan["args"]), " ")
	require.Contains(t, updatedArgs, "-i "+identityPath)
	require.Contains(t, updatedArgs, "StrictHostKeyChecking=yes")
	require.NotContains(t, updatedArgs, "-J bastion")
	require.NotContains(t, updatedArgs, "-A")
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

	requireSuccess(t, h.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "host", "add", "--name", "prod", "--address", "127.0.0.1", "--user", "root"), "host add --name prod --address 127.0.0.1 --user root")
	connectOut := requireSuccess(t, h.run(10*time.Second, "connect", "prod", "--dry-run"), "connect prod --dry-run")
	require.Contains(t, connectOut, "ssh")
	requireSuccess(t, h.run(10*time.Second, "vault", "lock"), "vault lock")

	lockedOut := requireFailure(t, h.run(10*time.Second, "host", "list"), "host list")
	require.Contains(t, strings.ToLower(lockedOut), "vault is locked")
}

func TestIntegrationLifecycleSecretShowEnvDelete(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "secret", "add", "--name", "api_token", "--value", "super-secret"), "secret add --name api_token --value super-secret")
	showOut := requireSuccess(t, h.run(10*time.Second, "secret", "show", "api_token"), "secret show api_token")
	require.Contains(t, showOut, "super-secret")
	envOut := requireSuccess(
		t,
		h.run(10*time.Second, "secret", "env", "api_token", "--env-var", "API_TOKEN", "--", "sh", "-c", `test -n "$API_TOKEN" && printf ok`),
		"secret env api_token --env-var API_TOKEN -- sh -c test -n \"$API_TOKEN\" && printf ok",
	)
	require.Contains(t, envOut, "ok")
	require.NotContains(t, envOut, "super-secret")
	requireSuccess(t, h.run(10*time.Second, "vault", "reauth", "--passphrase", "integration-pass"), "vault reauth --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "secret", "remove", "api_token"), "secret remove api_token")
}

func TestIntegrationLifecycleKeyGenerateExportDelete(t *testing.T) {
	h := newHarness(t)
	exportPath := filepath.Join(h.home, "deploy.key")

	requireSuccess(t, h.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "key", "generate", "--name", "deploy"), "key generate --name deploy")
	requireSuccess(t, h.run(10*time.Second, "vault", "reauth", "--passphrase", "integration-pass"), "vault reauth --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "key", "export", "deploy", "--private", "--output", exportPath), "key export deploy --private --output <path>")
	keyBytes, err := os.ReadFile(exportPath)
	require.NoError(t, err)
	require.NotEmpty(t, keyBytes)
	require.Contains(t, string(keyBytes), "PRIVATE KEY")
	requireSuccess(t, h.run(10*time.Second, "key", "remove", "deploy"), "key remove deploy")
}

func TestIntegrationLifecycleBackupRestoreVerify(t *testing.T) {
	source := newHarness(t)
	backupPath := filepath.Join(source.home, "vault.backup")

	requireSuccess(t, source.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "host", "add", "--name", "restore-me", "--address", "10.10.10.10", "--user", "ubuntu"), "host add --name restore-me --address 10.10.10.10 --user ubuntu")
	requireSuccess(t, source.run(backupCommandTimeout, "backup", "create", "--output", backupPath, "--passphrase", "backup-pass"), "backup create --output <path> --passphrase backup-pass")

	target := newHarness(t)
	requireSuccess(t, target.run(10*time.Second, "init", "--yes", "--passphrase", "target-pass"), "init --yes --passphrase target-pass")
	requireSuccess(t, target.run(10*time.Second, "vault", "unlock", "--passphrase", "target-pass"), "vault unlock --passphrase target-pass")
	restoreOut := requireFailure(t, target.run(backupCommandTimeout, "backup", "restore", "--from", backupPath, "--passphrase", "backup-pass", "--overwrite"), "backup restore --from <path> --passphrase backup-pass --overwrite")
	require.Contains(t, strings.ToLower(restoreOut), "re-auth")
	requireSuccess(t, target.run(10*time.Second, "vault", "reauth", "--passphrase", "target-pass"), "vault reauth --passphrase target-pass")
	requireSuccess(t, target.run(backupCommandTimeout, "backup", "restore", "--from", backupPath, "--passphrase", "backup-pass", "--overwrite"), "backup restore --from <path> --passphrase backup-pass --overwrite")
	requireSuccess(t, target.run(10*time.Second, "daemon", "restart"), "daemon restart")
	wrongPassOut := requireFailure(t, target.run(10*time.Second, "vault", "unlock", "--passphrase", "target-pass"), "vault unlock --passphrase target-pass")
	require.Contains(t, strings.ToLower(wrongPassOut), "invalid")
	requireSuccess(t, target.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	listOut := requireSuccess(t, target.run(10*time.Second, "host", "list", "--names-only"), "host list --names-only")
	require.Contains(t, listOut, "restore-me")
}

func TestIntegrationLifecycleBackupRestoreWithoutOverwriteToMissingTarget(t *testing.T) {
	source := newHarness(t)
	backupPath := filepath.Join(source.home, "vault.backup")

	requireSuccess(t, source.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "host", "add", "--name", "restore-me", "--address", "10.10.10.10", "--user", "ubuntu"), "host add --name restore-me --address 10.10.10.10 --user ubuntu")
	requireSuccess(t, source.run(backupCommandTimeout, "backup", "create", "--output", backupPath, "--passphrase", "backup-pass"), "backup create --output <path> --passphrase backup-pass")

	target := newHarness(t)
	requireSuccess(t, target.run(backupCommandTimeout, "backup", "restore", "--from", backupPath, "--passphrase", "backup-pass"), "backup restore --from <path> --passphrase backup-pass")
	requireSuccess(t, target.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	listOut := requireSuccess(t, target.run(10*time.Second, "host", "list", "--names-only"), "host list --names-only")
	require.Contains(t, listOut, "restore-me")
}

func TestIntegrationBackupCreateAfterAuditVerificationRestoresValidSQLite(t *testing.T) {
	source := newHarness(t)
	backupPath := filepath.Join(source.home, "vault.backup")
	privateKeyPath := filepath.Join(source.home, "deploy.key")
	secretPath := filepath.Join(source.home, "secret.txt")

	requireSuccess(t, source.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "host", "add", "--name", "prod", "--address", "10.0.0.10", "--user", "ubuntu"), "host add --name prod --address 10.0.0.10 --user ubuntu")
	requireSuccess(t, source.run(10*time.Second, "host", "add", "--name", "staging", "--address", "10.0.0.11", "--user", "root"), "host add --name staging --address 10.0.0.11 --user root")
	requireSuccess(t, source.run(10*time.Second, "secret", "add", "--name", "api_token", "--value", "super-secret"), "secret add --name api_token --value super-secret")
	requireSuccess(t, source.run(10*time.Second, "secret", "export", "api_token", "--output", secretPath), "secret export api_token --output <path>")
	requireSuccess(t, source.run(10*time.Second, "key", "generate", "--name", "deploy"), "key generate --name deploy")
	requireSuccess(t, source.run(10*time.Second, "vault", "reauth", "--passphrase", "integration-pass"), "vault reauth --passphrase integration-pass")
	requireSuccess(t, source.run(10*time.Second, "key", "export", "deploy", "--private", "--output", privateKeyPath), "key export deploy --private --output <path>")
	auditListOut := requireSuccess(t, source.run(10*time.Second, "audit", "list", "--limit", "20"), "audit list --limit 20")
	require.Contains(t, auditListOut, "action=secret.export")
	require.Contains(t, auditListOut, "action=key.export")
	auditVerifyOut := requireSuccess(t, source.run(10*time.Second, "audit", "verify"), "audit verify")
	require.Contains(t, auditVerifyOut, "valid=true")
	requireSuccess(t, source.run(10*time.Second, "host", "list", "--json"), "host list --json")
	requireSuccess(t, source.run(10*time.Second, "host", "show", "prod", "--json"), "host show prod --json")
	requireSuccess(t, source.run(backupCommandTimeout, "backup", "create", "--output", backupPath, "--passphrase", "backup-pass"), "backup create --output <path> --passphrase backup-pass")

	target := newHarness(t)
	requireSuccess(t, target.run(10*time.Second, "init", "--yes", "--passphrase", "target-pass"), "init --yes --passphrase target-pass")
	requireSuccess(t, target.run(10*time.Second, "vault", "unlock", "--passphrase", "target-pass"), "vault unlock --passphrase target-pass")
	requireSuccess(t, target.run(10*time.Second, "vault", "reauth", "--passphrase", "target-pass"), "vault reauth --passphrase target-pass")
	requireSuccess(t, target.run(backupCommandTimeout, "backup", "restore", "--from", backupPath, "--passphrase", "backup-pass", "--overwrite"), "backup restore --from <path> --passphrase backup-pass --overwrite")
	requireSuccess(t, target.run(10*time.Second, "daemon", "restart"), "daemon restart")
	requireSQLiteIntegrityOK(t, target.vaultPath)
	requireSuccess(t, target.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	listOut := requireSuccess(t, target.run(10*time.Second, "host", "list", "--names-only"), "host list --names-only")
	require.Contains(t, listOut, "prod")
	require.Contains(t, listOut, "staging")
}

func TestIntegrationDaemonRestartRequiresUnlockAgain(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "host", "add", "--name", "restart-host", "--address", "127.0.0.1"), "host add --name restart-host --address 127.0.0.1")
	requireSuccess(t, h.run(10*time.Second, "daemon", "restart"), "daemon restart")

	lockedOut := requireFailure(t, h.run(10*time.Second, "host", "list"), "host list")
	require.Contains(t, strings.ToLower(lockedOut), "vault is locked")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	listOut := requireSuccess(t, h.run(10*time.Second, "host", "list", "--names-only"), "host list --names-only")
	require.Contains(t, listOut, "restart-host")
}

func TestIntegrationDaemonCrashCleansStaleInfoOnNextCommand(t *testing.T) {
	h := newHarness(t)

	requireSuccess(t, h.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
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

	requireSuccess(t, h.run(10*time.Second, "init", "--yes", "--passphrase", "integration-pass"), "init --yes --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "vault", "unlock", "--passphrase", "integration-pass"), "vault unlock --passphrase integration-pass")
	requireSuccess(t, h.run(10*time.Second, "host", "add", "--name", "parallel-host", "--address", "127.0.0.1"), "host add --name parallel-host --address 127.0.0.1")

	var wg sync.WaitGroup
	errCh := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := h.run(10*time.Second, "host", "list", "--names-only")
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

func requireSQLiteIntegrityOK(t *testing.T, dbPath string) {
	t.Helper()

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	var result string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&result)
	require.NoError(t, err)
	require.Equal(t, "ok", result)
}

func stringSliceFromAny(t *testing.T, value any) []string {
	t.Helper()

	items, ok := value.([]any)
	require.True(t, ok, "expected []any, got %T", value)
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		require.True(t, ok, "expected string item, got %T", item)
		out = append(out, text)
	}
	return out
}

func optionalStringFromMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	text, _ := value.(string)
	return text
}

func optionalBoolFromMap(values map[string]any, key string) bool {
	value, ok := values[key]
	if !ok || value == nil {
		return false
	}
	flag, _ := value.(bool)
	return flag
}
