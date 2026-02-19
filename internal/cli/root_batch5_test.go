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

	out, err := runCLI(t, "", "host", "ls", "--json")
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

func TestQuietSuppressesListOutput(t *testing.T) {

	server := &cliTestDaemon{
		hosts: []*v1.Host{{Name: "prod", Address: "10.0.0.1", Port: 22, User: "ubuntu"}},
	}
	withStubDaemon(t, server)

	out, err := runCLI(t, "", "--quiet", "host", "ls")
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
	v1.UnimplementedConnectServiceServer

	hosts []*v1.Host
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
