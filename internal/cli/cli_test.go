package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/athanvi/heimdall/internal/config"
	"github.com/athanvi/heimdall/internal/openssh"
)

func TestConfigRenderCommandSmoke(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
agents:
  selectors:
    personal:
      kind: openssh
      socket: /tmp/agent.sock
identities:
  github:
    public_key_path: /tmp/id.pub
    private_key_path_ref: /tmp/id
    agent_selector: personal
contexts:
  github:
    identity: github
    agent: personal
    forwarding:
      agent: deny
host_routes:
  github.com:
    hostname: github.com
    user: git
    context: github
`)
	out, err := execute("config", cfg, "render")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Host github.com") || !strings.Contains(out, "IdentityAgent /tmp/agent.sock") {
		t.Fatalf("unexpected render output:\n%s", out)
	}
}

func TestCertRefreshPreviewCommandSmoke(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
certificates:
  github:
    path: /tmp/id-cert.pub
    refresh_hook: ["refresh-cert", "github"]
`)
	out, err := execute("certs", cfg, "refresh", "github", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"executed": false`) || !strings.Contains(out, "refresh-cert") {
		t.Fatalf("unexpected refresh preview:\n%s", out)
	}
}

func TestWSLConfigureGitPreviewCommandSmoke(t *testing.T) {
	cfg := writeTempConfig(t, "version: 1\n")
	out, err := execute("wsl", cfg, "mode-a", "configure-git", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"executed": false`) || !strings.Contains(out, "core.sshCommand") {
		t.Fatalf("unexpected WSL configure preview:\n%s", out)
	}
}

func TestDoctorFocusedSubcommandFiltersFindings(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
identities:
  id:
    public_key_path: /tmp/id.pub
    certificate_path: /tmp/missing-cert.pub
contexts:
  ctx:
    identity: id
host_routes:
  example:
    hostname: example.com
    context: ctx
    forward_agent: yes
`)
	dir := t.TempDir()
	fragment := filepath.Join(dir, "heimdall.conf")
	userConfig := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(fragment, []byte("# managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfig, []byte("Include "+fragment+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := execute("doctor", cfg, "--format", "json", "--ssh-config", userConfig, "--fragment", fragment, "forwarding")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "HD-FWD-001") {
		t.Fatalf("focused forwarding doctor missed forwarding finding:\n%s", out)
	}
	for _, unwanted := range []string{"HD-CERT-001", "HD-CERT-004", "HD-CONFIG-001", "HD-AGENT-001"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("focused forwarding doctor emitted unrelated %s finding:\n%s", unwanted, out)
		}
	}
}

func TestContextAddWritesSpecStyleRoute(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
agents:
  selectors:
    default:
      kind: openssh
      socket: /tmp/agent.sock
identities:
  github-personal:
    public_key_path: /tmp/id.pub
    private_key_path_ref: /tmp/id
    agent_selector: default
`)
	out, err := execute("context", cfg, "add", "github-personal", "--host", "github.com", "--user", "git", "--identity", "github-personal", "--agent", "default", "--identities-only", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"updated ",
		"contexts:",
		"github-personal:",
		"host: github.com",
		"user: git",
		"identities_only: true",
		"enabled: false",
		"next: heimdall --config ",
		" config render --write",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	matches, err := filepath.Glob(cfg + ".heimdall-backup-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one backup, matches=%v err=%v", matches, err)
	}
	loaded, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := loaded.Contexts["github-personal"]
	if ctx.Identity != "github-personal" || ctx.Agent != "default" || ctx.Forwarding.Enabled == nil || *ctx.Forwarding.Enabled {
		t.Fatalf("unexpected context: %#v", ctx)
	}
	if len(ctx.Routes) != 1 {
		t.Fatalf("expected one route, got %#v", ctx.Routes)
	}
	route := ctx.Routes[0]
	if route.Host != "github.com" || route.User != "git" || route.IdentitiesOnly == nil || !*route.IdentitiesOnly {
		t.Fatalf("unexpected route: %#v", route)
	}
	if len(loaded.HostRoutes) != 0 {
		t.Fatalf("context add should use spec-style nested routes, got %#v", loaded.HostRoutes)
	}
	rendered, err := openssh.Render(config.Normalize(loaded), openssh.RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if text := string(rendered); !strings.Contains(text, "Host github.com") || !strings.Contains(text, "  User git") {
		t.Fatalf("nested route did not render:\n%s", text)
	}
}

func TestContextAddSupportsProxyCommandRouteFlags(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
agents:
  selectors:
    default:
      kind: openssh
      socket: /tmp/agent.sock
identities:
  homelab-admin:
    public_key_path: /tmp/homelab.pub
    private_key_path_ref: /tmp/homelab
    agent_selector: default
`)
	out, err := execute("context", cfg, "add", "homelab-iroh", "--host", "homelab-nas-iroh", "--hostname", "endpoint-id", "--user", "aman", "--identity", "homelab-admin", "--agent", "default", "--proxy-command", "iroh-ssh proxy %h", "--identities-only", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "hostname: endpoint-id") || !strings.Contains(out, "proxy_command: iroh-ssh proxy %h") {
		t.Fatalf("missing proxy route fields in output:\n%s", out)
	}
	loaded, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	route := loaded.Contexts["homelab-iroh"].Routes[0]
	if route.Hostname != "endpoint-id" || route.ProxyCommand != "iroh-ssh proxy %h" {
		t.Fatalf("unexpected route: %#v", route)
	}
	rendered, err := openssh.Render(config.Normalize(loaded), openssh.RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if text := string(rendered); !strings.Contains(text, "Host homelab-nas-iroh") || !strings.Contains(text, "  ProxyCommand iroh-ssh proxy %h") {
		t.Fatalf("proxy route did not render:\n%s", text)
	}
}

func TestContextAddWithoutYesPreviewsAndRefuses(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
agents:
  selectors:
    default:
      kind: openssh
      socket: /tmp/agent.sock
identities:
  github-personal:
    public_key_path: /tmp/id.pub
    private_key_path_ref: /tmp/id
    agent_selector: default
`)
	before, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := execute("context", cfg, "add", "github-personal", "--host", "github.com", "--user", "git", "--identity", "github-personal", "--agent", "default", "--identities-only")
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("preview without --yes mutated config:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !strings.Contains(out, "dry run; no config changes written") || !strings.Contains(out, "refusing config mutation without --yes") {
		t.Fatalf("unexpected refusal output:\n%s", out)
	}
}

func TestContextAddDryRunDoesNotWriteConfig(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
agents:
  selectors:
    default:
      kind: openssh
      socket: /tmp/agent.sock
identities:
  github-personal:
    public_key_path: /tmp/id.pub
    private_key_path_ref: /tmp/id
    agent_selector: default
`)
	before, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := execute("context", cfg, "add", "github-personal", "--host", "github.com", "--user", "git", "--identity", "github-personal", "--agent", "default", "--identities-only", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("dry-run mutated config:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !strings.Contains(out, "dry run; no config changes written") || !strings.Contains(out, "host: github.com") {
		t.Fatalf("unexpected dry-run output:\n%s", out)
	}
}

func TestConfigRollbackInfersConfigBackupTarget(t *testing.T) {
	cfg := writeTempConfig(t, `
version: 1
agents:
  selectors:
    default:
      kind: openssh
      socket: /tmp/agent.sock
identities:
  github-personal:
    public_key_path: /tmp/id.pub
    private_key_path_ref: /tmp/id
    agent_selector: default
`)
	before, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := execute("context", cfg, "add", "github-personal", "--host", "github.com", "--identity", "github-personal", "--agent", "default", "--yes"); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(cfg + ".heimdall-backup-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one backup, matches=%v err=%v", matches, err)
	}
	if _, err := execute("config", cfg, "rollback", matches[0], "--yes"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("rollback did not restore original config:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestTransportAddWritesWithYesAndBackup(t *testing.T) {
	cfg := writeTempConfig(t, "version: 1\n")
	out, err := execute("transport", cfg, "add", "iroh-ssh", "--type", "proxy_command", "--binary", "iroh-ssh", "--arg", "proxy", "--arg", "%h", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"updated ",
		"backup: ",
		"transports:",
		"iroh-ssh:",
		"type: proxy_command",
		"binary: iroh-ssh",
		"- proxy",
		"- '%h'",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	matches, err := filepath.Glob(cfg + ".heimdall-backup-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one backup, matches=%v err=%v", matches, err)
	}
	loaded, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tr := loaded.Transports["iroh-ssh"]
	if tr.Type != "proxy_command" || tr.Binary != "iroh-ssh" || len(tr.Args) != 2 || tr.Args[0] != "proxy" || tr.Args[1] != "%h" {
		t.Fatalf("unexpected transport: %#v", tr)
	}
}

func TestTransportAddWithoutYesPreviewsAndRefuses(t *testing.T) {
	cfg := writeTempConfig(t, "version: 1\n")
	before, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := execute("transport", cfg, "add", "iroh-ssh", "--binary", "iroh-ssh", "--arg", "proxy", "--arg", "%h")
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("preview without --yes mutated config:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !strings.Contains(out, "dry run; no config changes written") || !strings.Contains(out, "refusing config mutation without --yes") || !strings.Contains(out, "binary: iroh-ssh") {
		t.Fatalf("unexpected transport preview:\n%s", out)
	}
}

func TestTransportAddRejectsInvalidArgs(t *testing.T) {
	cfg := writeTempConfig(t, "version: 1\n")
	_, err := execute("transport", cfg, "add", "iroh-ssh", "--type", "proxy_jump", "--binary", "jump-host", "--yes")
	if err == nil {
		t.Fatal("expected unsupported transport type rejection")
	}
	loaded, loadErr := config.Load(cfg)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(loaded.Transports) != 0 {
		t.Fatalf("invalid add mutated transports: %#v", loaded.Transports)
	}
}

func execute(group, cfg string, args ...string) (string, error) {
	root := NewRootCommand()
	read, write, err := os.Pipe()
	if err != nil {
		return "", err
	}
	oldStdout := os.Stdout
	os.Stdout = write
	defer func() {
		os.Stdout = oldStdout
	}()
	root.SetOut(write)
	root.SetErr(write)
	all := []string{"--config", cfg}
	all = append(all, group)
	all = append(all, args...)
	root.SetArgs(all)
	execErr := root.Execute()
	_ = write.Close()
	data, readErr := io.ReadAll(read)
	_ = read.Close()
	if execErr != nil {
		return string(data), execErr
	}
	return string(data), readErr
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
