package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/config"
	daemonpkg "github.com/amanthanvi/heimdall/internal/daemon"
	sshpkg "github.com/amanthanvi/heimdall/internal/ssh"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestVersionCommandOutputsBuildInfo(t *testing.T) {

	out, err := runCLI(t, "", "version")
	require.NoError(t, err)
	require.Contains(t, out, "version=1.2.3")
	require.Contains(t, out, "commit=abc123")
	require.Contains(t, out, "build_time=2026-02-19T00:00:00Z")
}

func TestVersionCommandOutputsJSON(t *testing.T) {

	out, err := runCLI(t, "", "--json", "version")
	require.NoError(t, err)

	var payload BuildInfo
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	require.Equal(t, "1.2.3", payload.Version)
	require.Equal(t, "abc123", payload.Commit)
}

func TestRootHasRequiredGlobalFlags(t *testing.T) {

	var out bytes.Buffer
	cmd := NewRootCommand(&out, testBuildInfo())

	required := []string{"json", "quiet", "no-color", "timeout", "vault", "config", "yes", "interactive"}
	for _, name := range required {
		require.NotNilf(t, cmd.PersistentFlags().Lookup(name), "missing flag %q", name)
	}
}

func TestRootHasBatchFiveTopLevelCommands(t *testing.T) {

	var out bytes.Buffer
	cmd := NewRootCommand(&out, testBuildInfo())

	for _, name := range []string{"init", "daemon", "ssh-config", "host", "secret", "key", "backup"} {
		_, _, err := cmd.Find([]string{name})
		require.NoErrorf(t, err, "expected command %q", name)
	}
}

func TestAllCommandsHaveExamples(t *testing.T) {

	var out bytes.Buffer
	root := NewRootCommand(&out, testBuildInfo())

	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		path := cmd.CommandPath()
		if path == "heimdall help" || strings.HasPrefix(path, "heimdall help ") {
			return
		}
		if path == "heimdall completion" || strings.HasPrefix(path, "heimdall completion ") {
			return
		}
		if cmd.Name() != "heimdall" {
			require.NotEmptyf(
				t,
				strings.TrimSpace(cmd.Example),
				"command %q is missing Example text",
				path,
			)
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}

	walk(root)
}

func TestBackupRestoreHelpMentionsWorkflowAndReauth(t *testing.T) {
	out, err := runCLI(t, "", "backup", "restore", "--help")
	require.NoError(t, err)
	require.Contains(t, out, "Recommended workflow")
	require.Contains(t, out, "--overwrite requires a recent re-authentication window")
	require.Contains(t, out, "Restart daemon, then unlock the restored vault")
	require.Contains(t, out, "Restored vault unlock credentials come from the backup source vault")
	require.Contains(t, out, "source-vault-pass")
}

func TestRemovedPlaceholderCommandsDoNotAppearInHelp(t *testing.T) {
	out, err := runCLI(t, "", "host", "--help")
	require.NoError(t, err)
	require.NotContains(t, out, "test")
	require.NotContains(t, out, "trust")
	require.NotContains(t, out, "template")
}

func TestLegacySubcommandGuidanceReturnsUsageError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "host ls",
			args: []string{"host", "ls"},
			want: `use "heimdall host list"`,
		},
		{
			name: "key gen",
			args: []string{"key", "gen"},
			want: `use "heimdall key generate"`,
		},
		{
			name: "secret rm",
			args: []string{"secret", "rm"},
			want: `use "heimdall secret remove"`,
		},
		{
			name: "passkey ls",
			args: []string{"passkey", "ls"},
			want: `use "heimdall passkey list"`,
		},
		{
			name: "key agent rm",
			args: []string{"key", "agent", "rm"},
			want: `use "heimdall key agent remove"`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := runCLI(t, "", tc.args...)
			require.Error(t, err)
			require.Equal(t, ExitCodeUsage, exitCode(err))
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestUnknownFlagReturnsUsageError(t *testing.T) {

	_, err := runCLI(t, "", "--no-daemon")
	require.Error(t, err)
	require.Equal(t, ExitCodeUsage, exitCode(err))
}

func TestInitCreatesVaultAndConfig(t *testing.T) {

	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.db")
	configPath := filepath.Join(tmp, "config.toml")

	out, err := runCLI(t, "", "--vault", vaultPath, "--config", configPath, "--yes", "init", "--passphrase", "test-pass")
	require.NoError(t, err)
	require.Contains(t, out, "initialized vault")

	_, err = os.Stat(vaultPath)
	require.NoError(t, err)
	_, err = os.Stat(configPath)
	require.NoError(t, err)
}

func TestInitPassphraseStdinNonInteractive(t *testing.T) {

	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.db")
	configPath := filepath.Join(tmp, "config.toml")

	_, err := runCLI(t, "super-secret\n", "--vault", vaultPath, "--config", configPath, "--yes", "init", "--passphrase-stdin")
	require.NoError(t, err)
}

func TestInitPassphraseStdinRequiresValue(t *testing.T) {

	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.db")
	configPath := filepath.Join(tmp, "config.toml")

	_, err := runCLI(t, "\n", "--vault", vaultPath, "--config", configPath, "--yes", "init", "--passphrase-stdin")
	require.Error(t, err)
	require.Equal(t, ExitCodeUsage, exitCode(err))
}

func TestSecretShowRequiresReauth(t *testing.T) {

	_, err := runCLI(t, "", "secret", "show", "api-token")
	require.Error(t, err)
	require.Equal(t, ExitCodePermission, exitCode(err))
}

func TestKeyExportPrivateRequiresReauth(t *testing.T) {

	_, err := runCLI(t, "", "key", "export", "deploy", "--private", "--output", "/tmp/ignored")
	require.Error(t, err)
	require.Equal(t, ExitCodePermission, exitCode(err))
}

func TestCompletionGenerationBashZshFish(t *testing.T) {

	out, err := runCLI(t, "", "completion", "bash")
	require.NoError(t, err)
	require.Contains(t, out, "-F __start_heimdall")

	out, err = runCLI(t, "", "completion", "zsh")
	require.NoError(t, err)
	require.Contains(t, out, "#compdef heimdall")

	out, err = runCLI(t, "", "completion", "fish")
	require.NoError(t, err)
	require.Contains(t, out, "complete -c heimdall")
}

func TestCompletionInstallWritesScript(t *testing.T) {
	path := filepath.Join(t.TempDir(), "_heimdall")
	out, err := runCLI(t, "", "completion", "install", "--shell", "zsh", "--path", path, "--verify")
	require.NoError(t, err)
	require.Contains(t, out, "completion installed")

	raw, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Contains(t, string(raw), "#compdef heimdall")
}

func TestCompletionInstallDryRun(t *testing.T) {
	out, err := runCLI(t, "", "completion", "install", "--shell", "zsh", "--dry-run")
	require.NoError(t, err)
	require.Contains(t, out, "completion install dry-run")
}

func TestCompletionHostAddKeyFlagUsesDynamicKeyNames(t *testing.T) {
	server := &cliTestDaemon{
		keys: []*v1.KeyMeta{{Name: "deploy"}, {Name: "ops"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "__complete", "host", "add", "--key", "")
	require.NoError(t, err)
	require.Contains(t, out, "deploy")
	require.Contains(t, out, "ops")
}

func TestCompletionVaultUnlockPasskeyFlagUsesDynamicLabels(t *testing.T) {
	server := &cliTestDaemon{
		passkeys: []*v1.PasskeyMeta{{Label: "macbook-touchid"}, {Label: "yubikey"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "__complete", "vault", "unlock", "--passkey-label", "")
	require.NoError(t, err)
	require.Contains(t, out, "macbook-touchid")
	require.Contains(t, out, "yubikey")
}

func TestCompletionDirectiveSummaryGoesToStderr(t *testing.T) {
	server := &cliTestDaemon{
		keys: []*v1.KeyMeta{{Name: "deploy"}},
	}
	withStubDaemon(t, server)

	stdout, stderr, err := runCLIWithWriters(t, "", "__complete", "host", "add", "--key", "")
	require.NoError(t, err)
	require.Contains(t, stdout, "deploy")
	require.Contains(t, stdout, ":4")
	require.NotContains(t, stdout, "Completion ended with directive")
	require.Contains(t, stderr, "Completion ended with directive: ShellCompDirectiveNoFileComp")
}

func TestGenerateManPagesCreatesFiles(t *testing.T) {

	dir := t.TempDir()
	require.NoError(t, GenerateManPages(dir, testBuildInfo()))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
}

func TestHostListJSONProducesValidArray(t *testing.T) {

	server := &cliTestDaemon{
		hosts: []*v1.Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu", Tags: []string{"critical"}}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "host", "list", "--json")
	require.NoError(t, err)

	var payload []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	require.Len(t, payload, 1)
	require.Equal(t, "prod", payload[0]["name"])
}

func TestConnectDryRunPrintsSSHCommand(t *testing.T) {

	server := &cliTestDaemon{
		hosts: []*v1.Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "connect", "prod", "--dry-run")
	require.NoError(t, err)
	require.Contains(t, out, "ssh")
	require.Contains(t, out, "10.0.0.1")
}

func TestConnectDryRunWithKeyPrintsManagedAgentAuth(t *testing.T) {
	server := &cliTestDaemon{
		hosts: []*v1.Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
		keys:  []*v1.KeyMeta{{Name: "deploy"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "connect", "prod", "--dry-run", "--key", "deploy")
	require.NoError(t, err)
	require.Contains(t, out, "auth: managed-agent key=deploy")
}

func TestConnectRejectsConflictingAuthFlags(t *testing.T) {
	server := &cliTestDaemon{
		hosts: []*v1.Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
	}
	withStubDaemon(t, server)

	_, err := runCLI(t, "", "connect", "prod", "--key", "deploy", "--identity-file", "~/.ssh/id")
	require.Error(t, err)
	require.Equal(t, ExitCodeUsage, exitCode(err))
}

func TestConnectDryRunWithMissingKeyReturnsNotFound(t *testing.T) {
	server := &cliTestDaemon{
		hosts: []*v1.Host{{
			Name:    "prod",
			Address: "10.0.0.1",
			Port:    22,
			User:    "ubuntu",
			EnvRefs: map[string]string{"key_name": "deploy"},
		}},
		keys: []*v1.KeyMeta{},
	}
	withStubDaemon(t, server)

	_, err := runCLI(t, "", "connect", "prod", "--dry-run")
	require.Error(t, err)
	require.Equal(t, ExitCodeNotFound, exitCode(err))
	require.Contains(t, err.Error(), `connect: key "deploy" not found in vault`)
}

func TestConnectWithKeyRegistersSessionLifecycle(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.toml")
	vaultPath := filepath.Join(home, "vault.db")
	t.Setenv("HEIMDALL_HOME", home)
	t.Setenv("HEIMDALL_CONFIG_PATH", configPath)
	t.Setenv("HEIMDALL_VAULT_PATH", vaultPath)

	infoPath, err := resolveDaemonInfoPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(infoPath), 0o700))
	rawInfo, err := json.Marshal(daemonpkg.Info{
		PID:        0,
		AgentPath:  "/tmp/test-agent.sock",
		ConfigPath: configPath,
		VaultPath:  vaultPath,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(infoPath, rawInfo, 0o600))

	server := &cliTestDaemon{
		hosts: []*v1.Host{{
			Id:      "host-1",
			Name:    "prod",
			Address: "10.0.0.1",
			Port:    22,
			User:    "ubuntu",
		}},
		keys: []*v1.KeyMeta{{Name: "deploy"}},
	}
	withStubDaemon(t, server)

	rec := &recordingSSHExecutor{}
	orig := newSSHCommandExecutor
	newSSHCommandExecutor = func() sshCommandExecutor { return rec }
	t.Cleanup(func() {
		newSSHCommandExecutor = orig
	})

	_, err = runCLI(t, "", "connect", "prod", "--key", "deploy")
	require.NoError(t, err)
	require.True(t, rec.called)
	require.Contains(t, rec.command.Env, "SSH_AUTH_SOCK=/tmp/test-agent.sock")
	require.Len(t, server.sessionStarts, 1)
	require.Len(t, server.agentAddSessions, 1)
	require.Equal(t, server.sessionStarts[0], server.agentAddSessions[0])
	require.Len(t, server.sessionEnds, 1)
	require.Equal(t, server.sessionStarts[0], server.sessionEnds[0])
	require.Equal(t, int32(0), server.recordedExitCodes[0])
}

func TestConnectExecutionUsesCommandContextWithoutTimeout(t *testing.T) {

	server := &cliTestDaemon{
		hosts: []*v1.Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
	}
	withStubDaemon(t, server)

	rec := &recordingSSHExecutor{}
	orig := newSSHCommandExecutor
	newSSHCommandExecutor = func() sshCommandExecutor { return rec }
	t.Cleanup(func() {
		newSSHCommandExecutor = orig
	})

	_, err := runCLI(t, "", "--timeout", "2s", "connect", "prod")
	require.NoError(t, err)
	require.True(t, rec.called)
	require.NotNil(t, rec.ctx)
	_, hasDeadline := rec.ctx.Deadline()
	require.False(t, hasDeadline, "connect execution should not use RPC timeout context")
	require.Equal(t, "ssh", rec.command.Binary)
}

func TestDaemonRestartAppliesPathOverridesForSubprocess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("HEIMDALL_CONFIG_PATH", "")
	t.Setenv("HEIMDALL_VAULT_PATH", "")

	configPath := filepath.Join(t.TempDir(), "config.toml")
	vaultPath := filepath.Join(t.TempDir(), "vault.db")

	origLoad := loadConfigFn
	origEnsure := ensureDaemonFn
	t.Cleanup(func() {
		loadConfigFn = origLoad
		ensureDaemonFn = origEnsure
	})

	loadConfigFn = func(opts config.LoadOptions) (config.Config, config.LoadReport, error) {
		require.Equal(t, configPath, opts.ConfigPath)
		require.Equal(t, vaultPath, opts.Env["HEIMDALL_VAULT_PATH"])
		return config.DefaultConfig(), config.LoadReport{}, nil
	}

	var seenConfigEnv string
	var seenVaultEnv string
	ensureDaemonFn = func(_ context.Context, _ *config.Config) (*grpc.ClientConn, error) {
		seenConfigEnv = os.Getenv("HEIMDALL_CONFIG_PATH")
		seenVaultEnv = os.Getenv("HEIMDALL_VAULT_PATH")
		return grpc.NewClient(
			"passthrough:///unused",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}

	_, err := runCLI(t, "", "--config", configPath, "--vault", vaultPath, "daemon", "restart")
	require.NoError(t, err)
	require.Equal(t, configPath, seenConfigEnv)
	require.Equal(t, vaultPath, seenVaultEnv)
	require.Equal(t, "", os.Getenv("HEIMDALL_CONFIG_PATH"))
	require.Equal(t, "", os.Getenv("HEIMDALL_VAULT_PATH"))
}

func TestEnsureDaemonPathOverridesRestartsWhenInfoPathsMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("HEIMDALL_HOME", t.TempDir())

	infoPath, err := resolveDaemonInfoPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(infoPath), 0o700))

	infoBytes, err := json.Marshal(daemonpkg.Info{PID: 12345})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(infoPath, infoBytes, 0o600))

	origStopFn := stopDaemonForPathMismatchFn
	t.Cleanup(func() {
		stopDaemonForPathMismatchFn = origStopFn
	})

	stopCalled := false
	stopDaemonForPathMismatchFn = func() (bool, error) {
		stopCalled = true
		return true, nil
	}

	err = ensureDaemonPathOverrides(&GlobalOptions{
		ConfigPath: "/tmp/expected-config.toml",
		VaultPath:  "/tmp/expected-vault.db",
	})
	require.NoError(t, err)
	require.True(t, stopCalled)
}

func TestEnsureDaemonPathOverridesKeepsMatchingDaemon(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("HEIMDALL_HOME", t.TempDir())

	expectedConfigPath := filepath.Join(t.TempDir(), "config.toml")
	expectedVaultPath := filepath.Join(t.TempDir(), "vault.db")

	infoPath, err := resolveDaemonInfoPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(infoPath), 0o700))

	infoBytes, err := json.Marshal(daemonpkg.Info{
		PID:        12345,
		ConfigPath: expectedConfigPath,
		VaultPath:  expectedVaultPath,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(infoPath, infoBytes, 0o600))

	origStopFn := stopDaemonForPathMismatchFn
	t.Cleanup(func() {
		stopDaemonForPathMismatchFn = origStopFn
	})

	stopCalled := false
	stopDaemonForPathMismatchFn = func() (bool, error) {
		stopCalled = true
		return true, nil
	}

	err = ensureDaemonPathOverrides(&GlobalOptions{
		ConfigPath: expectedConfigPath,
		VaultPath:  expectedVaultPath,
	})
	require.NoError(t, err)
	require.False(t, stopCalled)
}

func TestQuietSuppressesListOutput(t *testing.T) {

	server := &cliTestDaemon{
		hosts: []*v1.Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "--quiet", "host", "list")
	require.NoError(t, err)
	require.Empty(t, strings.TrimSpace(out))
}

func TestSSHConfigGenerateWritesOutputFile(t *testing.T) {

	server := &cliTestDaemon{
		hosts: []*v1.Host{{
			Name:    "prod",
			Address: "10.0.0.1",
			Port:    22,
			User:    "ubuntu",
			EnvRefs: map[string]string{"proxy_jump": "bastion", "identity_ref": "~/.ssh/id_ed25519"},
		}},
	}
	withStubDaemon(t, server)

	outputPath := filepath.Join(t.TempDir(), "generated_config")
	_, err := runCLI(t, "", "ssh-config", "generate", "--output", outputPath)
	require.NoError(t, err)

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "Host prod")
	require.Contains(t, string(content), "ProxyJump bastion")
	require.Contains(t, string(content), "IdentityFile ~/.ssh/id_ed25519")
}

func runCLI(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	cmd := NewRootCommand(&out, testBuildInfo())
	if stdin != "" {
		cmd.SetIn(strings.NewReader(stdin))
	}
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func runCLIWithWriters(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := NewRootCommandWithWriters(&out, &errOut, testBuildInfo())
	if stdin != "" {
		cmd.SetIn(strings.NewReader(stdin))
	}
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func testBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   "1.2.3",
		Commit:    "abc123",
		BuildTime: "2026-02-19T00:00:00Z",
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var withExit interface{ ExitCode() int }
	if errors.As(err, &withExit) {
		return withExit.ExitCode()
	}
	return -1
}

type cliTestDaemon struct {
	v1.UnimplementedVaultServiceServer
	v1.UnimplementedHostServiceServer
	v1.UnimplementedKeyServiceServer
	v1.UnimplementedPasskeyServiceServer
	v1.UnimplementedSessionServiceServer
	v1.UnimplementedConnectServiceServer

	hosts             []*v1.Host
	keys              []*v1.KeyMeta
	passkeys          []*v1.PasskeyMeta
	agentAddSessions  []string
	sessionStarts     []string
	sessionEnds       []string
	recordedExitCodes []int32
}

type recordingSSHExecutor struct {
	called  bool
	ctx     context.Context
	command *sshpkg.SSHCommand
}

func (r *recordingSSHExecutor) Run(ctx context.Context, command *sshpkg.SSHCommand) (int, error) {
	r.called = true
	r.ctx = ctx
	r.command = command
	return 0, nil
}

func (d *cliTestDaemon) Status(context.Context, *v1.StatusRequest) (*v1.StatusResponse, error) {
	return &v1.StatusResponse{Locked: false, HasLiveVmk: true}, nil
}

func (d *cliTestDaemon) ListHosts(_ context.Context, req *v1.ListHostsRequest) (*v1.ListHostsResponse, error) {
	if req.GetNamesOnly() {
		namesOnly := make([]*v1.Host, 0, len(d.hosts))
		for _, host := range d.hosts {
			namesOnly = append(namesOnly, &v1.Host{Name: host.GetName()})
		}
		return &v1.ListHostsResponse{Hosts: namesOnly}, nil
	}
	return &v1.ListHostsResponse{Hosts: d.hosts}, nil
}

func (d *cliTestDaemon) GetHost(_ context.Context, req *v1.GetHostRequest) (*v1.GetHostResponse, error) {
	for _, host := range d.hosts {
		if host.GetName() == req.GetName() {
			return &v1.GetHostResponse{Host: host}, nil
		}
	}
	return nil, errors.New("host not found")
}

func (d *cliTestDaemon) AgentAdd(_ context.Context, req *v1.AgentAddRequest) (*v1.AgentAddResponse, error) {
	d.agentAddSessions = append(d.agentAddSessions, req.GetSessionId())
	return &v1.AgentAddResponse{Fingerprint: "SHA256:test"}, nil
}

func (d *cliTestDaemon) ListKeys(_ context.Context, _ *v1.ListKeysRequest) (*v1.ListKeysResponse, error) {
	return &v1.ListKeysResponse{Keys: d.keys}, nil
}

func (d *cliTestDaemon) ListPasskeys(_ context.Context, _ *v1.ListPasskeysRequest) (*v1.ListPasskeysResponse, error) {
	return &v1.ListPasskeysResponse{Passkeys: d.passkeys}, nil
}

func (d *cliTestDaemon) RecordSessionStart(_ context.Context, req *v1.RecordSessionStartRequest) (*v1.RecordSessionStartResponse, error) {
	sessionID := req.GetSessionId()
	if strings.TrimSpace(sessionID) == "" {
		sessionID = "session-generated"
	}
	d.sessionStarts = append(d.sessionStarts, sessionID)
	return &v1.RecordSessionStartResponse{SessionId: sessionID}, nil
}

func (d *cliTestDaemon) RecordSessionEnd(_ context.Context, req *v1.RecordSessionEndRequest) (*v1.RecordSessionEndResponse, error) {
	d.sessionEnds = append(d.sessionEnds, req.GetSessionId())
	d.recordedExitCodes = append(d.recordedExitCodes, req.GetExitCode())
	return &v1.RecordSessionEndResponse{}, nil
}

func (d *cliTestDaemon) Plan(_ context.Context, req *v1.PlanConnectRequest) (*v1.PlanConnectResponse, error) {
	host := "example.com"
	for _, entry := range d.hosts {
		if entry.GetName() == req.GetHostName() {
			host = entry.GetAddress()
			break
		}
	}
	return &v1.PlanConnectResponse{Command: &v1.SSHCommand{Binary: "ssh", Args: []string{"-p", "22", host}}}, nil
}

func withStubDaemon(t *testing.T, server *cliTestDaemon) {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	v1.RegisterVaultServiceServer(grpcServer, server)
	v1.RegisterHostServiceServer(grpcServer, server)
	v1.RegisterKeyServiceServer(grpcServer, server)
	v1.RegisterPasskeyServiceServer(grpcServer, server)
	v1.RegisterSessionServiceServer(grpcServer, server)
	v1.RegisterConnectServiceServer(grpcServer, server)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	origLoad := loadConfigFn
	origEnsure := ensureDaemonFn
	loadConfigFn = func(config.LoadOptions) (config.Config, config.LoadReport, error) {
		return config.DefaultConfig(), config.LoadReport{}, nil
	}
	ensureDaemonFn = func(_ context.Context, _ *config.Config) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
		)
	}

	t.Cleanup(func() {
		loadConfigFn = origLoad
		ensureDaemonFn = origEnsure
		grpcServer.Stop()
		_ = listener.Close()
	})
}
