package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
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

	for _, name := range []string{"init", "status", "doctor", "vault", "daemon", "host", "connect", "secret", "key", "backup", "audit", "version"} {
		_, _, err := cmd.Find([]string{name})
		require.NoErrorf(t, err, "expected command %q", name)
	}
}

func TestRootOmitsDeferredCommands(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(&out, testBuildInfo())

	for _, name := range []string{"passkey", "ssh-config", "tui", "ui", "import", "export", "debug"} {
		_, _, err := cmd.Find([]string{name})
		require.Error(t, err)
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
	require.Contains(t, out, "target vault path that does not already contain a Heimdall vault")
	require.Contains(t, out, "Plain restore runs locally")
	require.Contains(t, out, "freshly initialized target vault still counts as an existing vault")
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

func TestRemovedLegacySubcommandsReturnPlainUsageError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "host ls",
			args: []string{"host", "ls"},
		},
		{
			name: "key gen",
			args: []string{"key", "gen"},
		},
		{
			name: "secret rm",
			args: []string{"secret", "rm"},
		},
		{
			name: "key agent rm",
			args: []string{"key", "agent", "rm"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := runCLI(t, "", tc.args...)
			require.Error(t, err)
			require.Equal(t, ExitCodeUsage, exitCode(err))
			require.Contains(t, err.Error(), "unknown command")
			require.NotContains(t, err.Error(), "use \"heimdall")
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

func TestVaultUnlockPassphraseStdin(t *testing.T) {
	server := &cliTestDaemon{}
	withStubDaemon(t, server)

	out, err := runCLI(t, "super-secret\n", "vault", "unlock", "--passphrase-stdin")
	require.NoError(t, err)
	require.Contains(t, out, "vault unlocked")
	require.Len(t, server.unlockRequests, 1)
	require.Equal(t, "super-secret", server.unlockRequests[0].GetPassphrase())
	require.Empty(t, server.unlockRequests[0].GetPasskeyLabel())
}

func TestVaultUnlockPassphraseStdinRequiresValue(t *testing.T) {
	_, err := runCLI(t, "\n", "vault", "unlock", "--passphrase-stdin")
	require.Error(t, err)
	require.Equal(t, ExitCodeUsage, exitCode(err))
	require.Contains(t, err.Error(), "vault unlock --passphrase-stdin requires a non-empty value on stdin")
}

func TestVaultUnlockRejectsMultipleAuthMethods(t *testing.T) {
	_, err := runCLI(t, "stdin-secret\n", "vault", "unlock", "--passphrase", "flag-secret", "--passphrase-stdin")
	require.Error(t, err)
	require.Equal(t, ExitCodeUsage, exitCode(err))
	require.Contains(t, err.Error(), "vault unlock accepts only one auth method")
}

func TestVaultReauthPassphraseStdin(t *testing.T) {
	server := &cliTestDaemon{}
	withStubDaemon(t, server)

	out, err := runCLI(t, "super-secret\n", "vault", "reauth", "--passphrase-stdin")
	require.NoError(t, err)
	require.Contains(t, out, "reauthenticated")
	require.Len(t, server.reauthRequests, 1)
	require.Equal(t, "super-secret", server.reauthRequests[0].GetPassphrase())
}

func TestSecretShowUsesDaemonInsteadOfFakeReauthFlag(t *testing.T) {
	server := &cliTestDaemon{
		secrets: map[string][]byte{"api-token": []byte("secret-value")},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "secret", "show", "api-token")
	require.NoError(t, err)
	require.Contains(t, out, "secret-value")
}

func TestKeyExportPrivateUsesDaemonInsteadOfFakeReauthFlag(t *testing.T) {
	server := &cliTestDaemon{
		keys: []*v1.KeyMeta{{
			Name:      "deploy",
			KeyType:   "ed25519",
			PublicKey: "ssh-ed25519 AAAA",
		}},
		exportedKeys: map[string]*v1.ExportKeyResponse{
			"deploy": {
				Name:       "deploy",
				KeyType:    "ed25519",
				PublicKey:  "ssh-ed25519 AAAA",
				PrivateKey: []byte("PRIVATE"),
			},
		},
	}
	withStubDaemon(t, server)

	outputPath := filepath.Join(t.TempDir(), "deploy.key")
	out, err := runCLI(t, "", "key", "export", "deploy", "--private", "--output", outputPath)
	require.NoError(t, err)
	require.Contains(t, out, "key exported to")
	raw, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	require.Equal(t, "PRIVATE", string(raw))
}

func TestKeyExportPublicDoesNotRequireReauth(t *testing.T) {
	server := &cliTestDaemon{
		keys: []*v1.KeyMeta{{
			Name:      "deploy",
			KeyType:   "ed25519",
			PublicKey: "ssh-ed25519 AAAA",
		}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "key", "export", "deploy")
	require.NoError(t, err)
	require.Contains(t, out, "ssh-ed25519 AAAA")
}

func TestCompletionGenerationBashZshFish(t *testing.T) {

	out, err := runCLI(t, "", "completion", "bash")
	require.NoError(t, err)
	require.Contains(t, out, "-F __start_heimdall")
	require.Contains(t, out, "if ! declare -F _get_comp_words_by_ref >/dev/null 2>&1; then")

	out, err = runCLI(t, "", "completion", "zsh")
	require.NoError(t, err)
	require.Contains(t, out, "#compdef heimdall")
	require.Contains(t, out, "Skipping leaked directive token")
	require.Contains(t, out, "Skipping leaked completion summary")

	out, err = runCLI(t, "", "completion", "fish")
	require.NoError(t, err)
	require.Contains(t, out, "complete -c heimdall")
}

func TestCompletionBashScriptWorksWithoutBashCompletionHelpers(t *testing.T) {
	out, err := runCLI(t, "", "completion", "bash")
	require.NoError(t, err)

	scriptPath := filepath.Join(t.TempDir(), "heimdall.bash")
	require.NoError(t, os.WriteFile(scriptPath, []byte(out), 0o600))

	cmd := exec.Command(
		"bash",
		"-lc",
		`set -e
source "$1"
heimdall() { printf 'restore-me\n:4\n'; }
COMP_WORDS=(heimdall host show r)
COMP_CWORD=3
COMP_LINE="heimdall host show r"
COMP_POINT=${#COMP_LINE}
__start_heimdall
printf '%s\n' "${COMPREPLY[@]}"`,
		"bash",
		scriptPath,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "restore-me")
	require.NotContains(t, string(output), "_get_comp_words_by_ref")
}

func TestCompletionBashScriptWorksWithNounset(t *testing.T) {
	out, err := runCLI(t, "", "completion", "bash")
	require.NoError(t, err)

	scriptPath := filepath.Join(t.TempDir(), "heimdall.bash")
	require.NoError(t, os.WriteFile(scriptPath, []byte(out), 0o600))

	cmd := exec.Command(
		"bash",
		"-lc",
		`set -euo pipefail
source "$1"
heimdall() { printf 'accept-new\n:4\n'; }
COMP_WORDS=(heimdall connect prod --known-hosts-policy a)
COMP_CWORD=4
COMP_LINE="heimdall connect prod --known-hosts-policy a"
COMP_POINT=${#COMP_LINE}
__start_heimdall
printf '%s\n' "${COMPREPLY[@]}"`,
		"bash",
		scriptPath,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "accept-new")
	require.NotContains(t, string(output), "unbound variable")
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

func TestCompletionConnectKnownHostsPolicyFlagUsesStaticPolicies(t *testing.T) {
	out, err := runCLI(t, "", "__complete", "connect", "prod", "--known-hosts-policy", "a")
	require.NoError(t, err)
	require.Contains(t, out, "accept-new")
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

func TestAuditVerifyReturnsNonZeroWhenChainIsInvalid(t *testing.T) {
	server := &cliTestDaemon{
		verifyChainResp: &v1.VerifyChainResponse{
			Valid:      false,
			EventCount: 3,
			ChainTip:   "bad-tip",
			Error:      "hash mismatch",
		},
	}
	withStubDaemon(t, server)

	stdout, stderr, err := runCLIWithWriters(t, "", "audit", "verify")
	require.Error(t, err)
	require.Contains(t, stdout, "valid=false")
	require.Equal(t, "", stderr)

	var exitErr *ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, ExitCodeGeneric, exitErr.ExitCode())
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

func TestHostShowJSONOmitsLegacyEnvRefs(t *testing.T) {
	server := &cliTestDaemon{
		hosts: []*v1.Host{{
			Name:             "prod",
			Address:          "10.0.0.1",
			Port:             22,
			User:             "ubuntu",
			Tags:             []string{"critical"},
			Notes:            "primary",
			KeyName:          "deploy",
			IdentityPath:     "/tmp/id_prod",
			ProxyJump:        "bastion",
			KnownHostsPolicy: "accept-new",
			ForwardAgent:     true,
		}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "--json", "host", "show", "prod")
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	require.Equal(t, "prod", payload["name"])
	require.Equal(t, "deploy", payload["key_name"])
	require.Equal(t, "bastion", payload["proxy_jump"])
	require.NotContains(t, payload, "env_refs")
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
			KeyName: "deploy",
		}},
		keys: []*v1.KeyMeta{},
	}
	withStubDaemon(t, server)

	_, err := runCLI(t, "", "connect", "prod", "--dry-run")
	require.Error(t, err)
	require.Equal(t, ExitCodeNotFound, exitCode(err))
	require.Contains(t, err.Error(), `connect: key "deploy" not found in vault`)
}

func TestConnectDryRunIdentityFileOverridesHostDefaultKey(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(identityPath, []byte("dummy"), 0o600))

	server := &cliTestDaemon{
		hosts: []*v1.Host{{
			Name:    "prod",
			Address: "10.0.0.1",
			Port:    22,
			User:    "ubuntu",
			KeyName: "deploy",
		}},
		keys: []*v1.KeyMeta{{Name: "deploy"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "connect", "prod", "--dry-run", "--identity-file", identityPath)
	require.NoError(t, err)
	require.Contains(t, out, identityPath)
	require.NotContains(t, out, "auth: managed-agent")
	require.Len(t, server.planRequests, 1)
	require.Equal(t, identityPath, server.planRequests[0].GetIdentityPath())
}

func TestConnectDryRunKeyOverridesHostDefaultIdentityFile(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(identityPath, []byte("dummy"), 0o600))

	server := &cliTestDaemon{
		hosts: []*v1.Host{{
			Name:         "prod",
			Address:      "10.0.0.1",
			Port:         22,
			User:         "ubuntu",
			IdentityPath: identityPath,
		}},
		keys: []*v1.KeyMeta{{Name: "deploy"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "connect", "prod", "--dry-run", "--key", "deploy")
	require.NoError(t, err)
	require.Contains(t, out, "auth: managed-agent key=deploy")
	require.Len(t, server.planRequests, 1)
	require.Equal(t, connectDisableIdentityPathSentinel, server.planRequests[0].GetIdentityPath())
	require.NotContains(t, out, identityPath)
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

func TestConnectWithoutKeyRecordsSessionLifecycle(t *testing.T) {
	server := &cliTestDaemon{
		hosts: []*v1.Host{{
			Id:      "host-1",
			Name:    "prod",
			Address: "10.0.0.1",
			Port:    22,
			User:    "ubuntu",
		}},
	}
	withStubDaemon(t, server)

	rec := &recordingSSHExecutor{}
	orig := newSSHCommandExecutor
	newSSHCommandExecutor = func() sshCommandExecutor { return rec }
	t.Cleanup(func() {
		newSSHCommandExecutor = orig
	})

	_, err := runCLI(t, "", "connect", "prod")
	require.NoError(t, err)
	require.True(t, rec.called)
	require.Empty(t, server.agentAddSessions)
	require.Len(t, server.sessionStarts, 1)
	require.Len(t, server.sessionEnds, 1)
	require.Equal(t, server.sessionStarts[0], server.sessionEnds[0])
	require.Equal(t, int32(0), server.recordedExitCodes[0])
	require.NotContains(t, rec.command.Env, "SSH_AUTH_SOCK=/tmp/test-agent.sock")
}

func TestConnectExecutionUsesCommandContextWithoutTimeout(t *testing.T) {

	server := &cliTestDaemon{
		hosts: []*v1.Host{{Id: "host-1", Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
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

func TestStatusShowsAuditHintWhenConnectionLoggingDisabled(t *testing.T) {
	server := &cliTestDaemon{}
	withStubDaemon(t, server)

	origLoad := loadConfigFn
	loadConfigFn = func(config.LoadOptions) (config.Config, config.LoadReport, error) {
		cfg := config.DefaultConfig()
		cfg.Audit.ConnectionLogging = false
		return cfg, config.LoadReport{}, nil
	}
	t.Cleanup(func() {
		loadConfigFn = origLoad
	})

	out, err := runCLI(t, "", "status")
	require.NoError(t, err)
	require.Contains(t, out, "audit: connection_logging=disabled")
	require.Contains(t, out, "hint: enable with [audit].connection_logging=true")
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

func TestEnsureDaemonPathOverridesKeepsDaemonWhenNoExplicitPaths(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("HEIMDALL_HOME", t.TempDir())
	t.Setenv("HEIMDALL_CONFIG_PATH", "")
	t.Setenv("HEIMDALL_VAULT_PATH", "")

	infoPath, err := resolveDaemonInfoPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(infoPath), 0o700))

	infoBytes, err := json.Marshal(daemonpkg.Info{
		PID:        12345,
		ConfigPath: "/tmp/custom-config.toml",
		VaultPath:  "/tmp/custom-vault.db",
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

	err = ensureDaemonPathOverrides(&GlobalOptions{})
	require.NoError(t, err)
	require.False(t, stopCalled)
}

func TestEnsureDaemonPathOverridesRestartsWhenExplicitEnvDiffers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("HEIMDALL_HOME", t.TempDir())
	t.Setenv("HEIMDALL_CONFIG_PATH", "/tmp/expected-config.toml")
	t.Setenv("HEIMDALL_VAULT_PATH", "/tmp/expected-vault.db")

	infoPath, err := resolveDaemonInfoPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(infoPath), 0o700))

	infoBytes, err := json.Marshal(daemonpkg.Info{
		PID:        12345,
		ConfigPath: "/tmp/other-config.toml",
		VaultPath:  "/tmp/other-vault.db",
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

	err = ensureDaemonPathOverrides(&GlobalOptions{})
	require.NoError(t, err)
	require.True(t, stopCalled)
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

func TestSSHConfigCommandIsRemoved(t *testing.T) {
	_, err := runCLI(t, "", "ssh-config", "generate")
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown command "ssh-config"`)
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
	v1.UnimplementedSecretServiceServer
	v1.UnimplementedKeyServiceServer
	v1.UnimplementedPasskeyServiceServer
	v1.UnimplementedSessionServiceServer
	v1.UnimplementedConnectServiceServer
	v1.UnimplementedReauthServiceServer
	v1.UnimplementedAuditServiceServer

	hosts             []*v1.Host
	keys              []*v1.KeyMeta
	passkeys          []*v1.PasskeyMeta
	secrets           map[string][]byte
	secretPolicies    map[string]string
	exportedKeys      map[string]*v1.ExportKeyResponse
	unlockRequests    []*v1.UnlockRequest
	reauthRequests    []*v1.VerifyPassphraseRequest
	planRequests      []*v1.PlanConnectRequest
	agentAddSessions  []string
	sessionStarts     []string
	sessionEnds       []string
	recordedExitCodes []int32
	verifyChainResp   *v1.VerifyChainResponse
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

func (d *cliTestDaemon) Unlock(_ context.Context, req *v1.UnlockRequest) (*v1.UnlockResponse, error) {
	if req == nil {
		return nil, errors.New("unlock request is required")
	}
	clone := &v1.UnlockRequest{
		Passphrase:   req.GetPassphrase(),
		PasskeyLabel: req.GetPasskeyLabel(),
	}
	d.unlockRequests = append(d.unlockRequests, clone)
	return &v1.UnlockResponse{Unlocked: true}, nil
}

func (d *cliTestDaemon) VerifyPassphrase(_ context.Context, req *v1.VerifyPassphraseRequest) (*v1.VerifyPassphraseResponse, error) {
	if req == nil {
		return nil, errors.New("reauth request is required")
	}
	clone := &v1.VerifyPassphraseRequest{Passphrase: req.GetPassphrase()}
	d.reauthRequests = append(d.reauthRequests, clone)
	return &v1.VerifyPassphraseResponse{Ok: true}, nil
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

func (d *cliTestDaemon) ListSecrets(_ context.Context, _ *v1.ListSecretsRequest) (*v1.ListSecretsResponse, error) {
	items := make([]*v1.SecretMeta, 0, len(d.secrets))
	for name, value := range d.secrets {
		policy := "once-per-unlock"
		if d.secretPolicies != nil && d.secretPolicies[name] != "" {
			policy = d.secretPolicies[name]
		}
		items = append(items, &v1.SecretMeta{
			Name:         name,
			RevealPolicy: policy,
			SizeBytes:    int64(len(value)),
		})
	}
	return &v1.ListSecretsResponse{Secrets: items}, nil
}

func (d *cliTestDaemon) GetSecretValue(_ context.Context, req *v1.GetSecretValueRequest) (*v1.GetSecretValueResponse, error) {
	if req == nil {
		return nil, errors.New("secret request is required")
	}
	value, ok := d.secrets[req.GetName()]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &v1.GetSecretValueResponse{Value: append([]byte(nil), value...)}, nil
}

func (d *cliTestDaemon) ListKeys(_ context.Context, _ *v1.ListKeysRequest) (*v1.ListKeysResponse, error) {
	return &v1.ListKeysResponse{Keys: d.keys}, nil
}

func (d *cliTestDaemon) ShowKey(_ context.Context, req *v1.ShowKeyRequest) (*v1.ShowKeyResponse, error) {
	if req == nil {
		return nil, errors.New("show key request is required")
	}
	for _, key := range d.keys {
		if key.GetName() == req.GetName() {
			return &v1.ShowKeyResponse{Key: key}, nil
		}
	}
	return nil, errors.New("key not found")
}

func (d *cliTestDaemon) ExportKey(_ context.Context, req *v1.ExportKeyRequest) (*v1.ExportKeyResponse, error) {
	if req == nil {
		return nil, errors.New("export request is required")
	}
	if resp, ok := d.exportedKeys[req.GetName()]; ok {
		return resp, nil
	}
	return nil, errors.New("key not found")
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
	if req != nil {
		d.planRequests = append(d.planRequests, clonePlanConnectRequest(req))
	}
	host := "example.com"
	for _, entry := range d.hosts {
		if entry.GetName() == req.GetHostName() {
			host = entry.GetAddress()
			break
		}
	}
	args := []string{"-p", "22"}
	identityPath := req.GetIdentityPath()
	if identityPath == connectDisableIdentityPathSentinel {
		identityPath = ""
	}
	if identityPath != "" {
		args = append(args, "-i", identityPath)
	}
	if len(req.GetJumpHosts()) > 0 {
		args = append(args, "-J", strings.Join(req.GetJumpHosts(), ","))
	}
	args = append(args, host)
	return &v1.PlanConnectResponse{Command: &v1.SSHCommand{Binary: "ssh", Args: args}}, nil
}

func (d *cliTestDaemon) VerifyChain(_ context.Context, _ *v1.VerifyChainRequest) (*v1.VerifyChainResponse, error) {
	if d.verifyChainResp != nil {
		return d.verifyChainResp, nil
	}
	return &v1.VerifyChainResponse{Valid: true, EventCount: 1, ChainTip: "chain-tip"}, nil
}

func clonePlanConnectRequest(req *v1.PlanConnectRequest) *v1.PlanConnectRequest {
	if req == nil {
		return nil
	}
	return &v1.PlanConnectRequest{
		HostName:     req.GetHostName(),
		User:         req.GetUser(),
		Port:         req.GetPort(),
		JumpHosts:    append([]string(nil), req.GetJumpHosts()...),
		Forwards:     append([]string(nil), req.GetForwards()...),
		IdentityPath: req.GetIdentityPath(),
		KnownHosts:   req.GetKnownHosts(),
		PrintCmd:     req.GetPrintCmd(),
		DryRun:       req.GetDryRun(),
	}
}

func withStubDaemon(t *testing.T, server *cliTestDaemon) {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	v1.RegisterVaultServiceServer(grpcServer, server)
	v1.RegisterHostServiceServer(grpcServer, server)
	v1.RegisterSecretServiceServer(grpcServer, server)
	v1.RegisterKeyServiceServer(grpcServer, server)
	v1.RegisterPasskeyServiceServer(grpcServer, server)
	v1.RegisterSessionServiceServer(grpcServer, server)
	v1.RegisterConnectServiceServer(grpcServer, server)
	v1.RegisterReauthServiceServer(grpcServer, server)
	v1.RegisterAuditServiceServer(grpcServer, server)

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
