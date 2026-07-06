package launcher

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/athanvi/heimdall/internal/model"
)

func TestPreviewScopesSelectedAgentAndNoAmbientFallback(t *testing.T) {
	cfg := model.Config{
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "/tmp/selected.sock"}}},
		Identities: map[string]model.Identity{"id": {AgentSelector: "personal"}},
		Contexts:   map[string]model.Context{"ctx": {Identity: "id", Agent: "personal"}},
	}
	preview, err := (Launcher{}).Preview(cfg, "ctx", []string{"git", "fetch"})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Env["SSH_AUTH_SOCK"] != "/tmp/selected.sock" {
		t.Fatalf("unexpected env: %#v", preview.Env)
	}
	delete(cfg.Agents.Selectors, "personal")
	if _, err := (Launcher{}).Preview(cfg, "ctx", []string{"git"}); err != ErrNoAgentSocket {
		t.Fatalf("expected no ambient fallback refusal, got %v", err)
	}
}

func TestPreviewUsesArgvNoShellInjection(t *testing.T) {
	cfg := model.Config{
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "/tmp/selected.sock"}}},
		Identities: map[string]model.Identity{"id": {AgentSelector: "personal"}},
		Contexts:   map[string]model.Context{"ctx": {Identity: "id", Agent: "personal"}},
	}
	preview, err := (Launcher{}).Preview(cfg, "ctx", []string{"ssh", "host; rm -rf /"})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Command[1] != "host; rm -rf /" {
		t.Fatalf("command argument was rewritten: %#v", preview.Command)
	}
}

func TestPreviewAddsScopedOpenSSHRouting(t *testing.T) {
	cfg := model.Config{
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "/tmp/selected.sock"}}},
		Identities: map[string]model.Identity{"id": {AgentSelector: "personal"}},
		Contexts:   map[string]model.Context{"ctx": {Identity: "id", Agent: "personal", Routes: []model.HostRoute{{Host: "github.com"}}}},
	}
	fragment := filepath.Join(t.TempDir(), "heimdall managed ssh_config")
	gitPreview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", []string{"git", "ls-remote", "git@example.com:repo.git"}, Options{SSHConfigPath: fragment})
	if err != nil {
		t.Fatal(err)
	}
	if gitPreview.SSHConfigPath != fragment {
		t.Fatalf("preview did not expose managed fragment path: %#v", gitPreview)
	}
	if got := gitPreview.Env["GIT_SSH_COMMAND"]; got != "ssh -F "+shellQuote(fragment) {
		t.Fatalf("unexpected GIT_SSH_COMMAND %q", got)
	}
	if strings.Join(gitPreview.Command, "\x00") != "git\x00ls-remote\x00git@example.com:repo.git" {
		t.Fatalf("git command should not be rewritten: %#v", gitPreview.Command)
	}

	sshPreview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", []string{"ssh", "github.com", "-T"}, Options{SSHConfigPath: fragment})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh", "-F", fragment, "github.com", "-T"}
	if strings.Join(sshPreview.Command, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("ssh command was not scoped through -F: %#v", sshPreview.Command)
	}

	tests := []struct {
		name    string
		command []string
		want    []string
	}{
		{
			name:    "ssh exe is rewritten",
			command: []string{"C:\\Windows\\System32\\OpenSSH\\ssh.exe", "github.com"},
			want:    []string{"C:\\Windows\\System32\\OpenSSH\\ssh.exe", "-F", fragment, "github.com"},
		},
		{
			name:    "existing config flag is preserved",
			command: []string{"ssh", "-F", "/tmp/custom.conf", "github.com"},
			want:    []string{"ssh", "-F", "/tmp/custom.conf", "github.com"},
		},
		{
			name:    "existing joined config flag is preserved",
			command: []string{"ssh", "-F/tmp/custom.conf", "github.com"},
			want:    []string{"ssh", "-F/tmp/custom.conf", "github.com"},
		},
		{
			name:    "remote command after host does not suppress scoped config",
			command: []string{"ssh", "github.com", "-F", "remote-file"},
			want:    []string{"ssh", "-F", fragment, "github.com", "-F", "remote-file"},
		},
		{
			name:    "option arguments before config flag are skipped",
			command: []string{"ssh", "-p", "2222", "-F", "/tmp/custom.conf", "github.com"},
			want:    []string{"ssh", "-p", "2222", "-F", "/tmp/custom.conf", "github.com"},
		},
		{
			name:    "known route host bounds unknown option scan",
			command: []string{"ssh", "-Z", "future-option-value", "-F", "/tmp/custom.conf", "github.com"},
			want:    []string{"ssh", "-Z", "future-option-value", "-F", "/tmp/custom.conf", "github.com"},
		},
		{
			name:    "unknown option without config flag still gets scoped config",
			command: []string{"ssh", "-Z", "future-option-value", "github.com"},
			want:    []string{"ssh", "-F", fragment, "-Z", "future-option-value", "github.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", tt.command, Options{SSHConfigPath: fragment})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(preview.Command, "\x00") != strings.Join(tt.want, "\x00") {
				t.Fatalf("unexpected rewritten command:\n got %#v\nwant %#v", preview.Command, tt.want)
			}
		})
	}
}

func TestPreviewUsesRouteSpecificAgentWhenLaunchHostIsKnown(t *testing.T) {
	cfg := model.Config{
		Agents: model.AgentConfig{Selectors: map[string]model.AgentSelector{
			"default": {Kind: "openssh", Socket: "/tmp/default.sock"},
			"work":    {Kind: "openssh", Socket: "/tmp/work.sock"},
		}},
		Identities: map[string]model.Identity{
			"default": {AgentSelector: "default"},
			"work":    {AgentSelector: "work"},
		},
		Contexts: map[string]model.Context{"ctx": {
			Identity: "default",
			Agent:    "default",
			Routes: []model.HostRoute{{
				Host:     "github.com",
				Identity: "work",
				Agent:    "work",
			}},
		}},
	}
	for _, tt := range []struct {
		name    string
		command []string
	}{
		{name: "direct ssh", command: []string{"ssh", "git@github.com"}},
		{name: "git scp remote", command: []string{"git", "ls-remote", "git@github.com:owner/repo.git"}},
		{name: "git ssh url", command: []string{"git", "ls-remote", "ssh://git@github.com/owner/repo.git"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			preview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", tt.command, Options{SSHConfigPath: filepath.Join(t.TempDir(), "ssh_config")})
			if err != nil {
				t.Fatal(err)
			}
			if got := preview.Env["SSH_AUTH_SOCK"]; got != "/tmp/work.sock" {
				t.Fatalf("expected route-specific socket, got %q in %#v", got, preview)
			}
		})
	}
	preview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", []string{"ssh", "-Z", "future-option-value", "github.com"}, Options{SSHConfigPath: filepath.Join(t.TempDir(), "ssh_config")})
	if err != nil {
		t.Fatal(err)
	}
	if got := preview.Env["SSH_AUTH_SOCK"]; got != "/tmp/work.sock" {
		t.Fatalf("expected route-specific socket after unknown option, got %q in %#v", got, preview)
	}
}

func TestPreviewDoesNotUseRouteAgentForRemoteCommandWords(t *testing.T) {
	cfg := model.Config{
		Agents: model.AgentConfig{Selectors: map[string]model.AgentSelector{
			"default": {Kind: "openssh", Socket: "/tmp/default.sock"},
			"work":    {Kind: "openssh", Socket: "/tmp/work.sock"},
		}},
		Identities: map[string]model.Identity{
			"default": {AgentSelector: "default"},
			"work":    {AgentSelector: "work"},
		},
		Contexts: map[string]model.Context{"ctx": {
			Identity: "default",
			Agent:    "default",
			Routes: []model.HostRoute{{
				Host:     "github.com",
				Identity: "work",
				Agent:    "work",
			}},
		}},
	}
	preview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", []string{"ssh", "internal.example", "echo", "github.com"}, Options{SSHConfigPath: filepath.Join(t.TempDir(), "ssh_config")})
	if err != nil {
		t.Fatal(err)
	}
	if got := preview.Env["SSH_AUTH_SOCK"]; got != "/tmp/default.sock" {
		t.Fatalf("remote command word should not select route-specific socket, got %q in %#v", got, preview)
	}
}

func TestPreviewAllowsRouteSpecificAgentWithoutContextDefault(t *testing.T) {
	cfg := model.Config{
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"work": {Kind: "openssh", Socket: "/tmp/work.sock"}}},
		Identities: map[string]model.Identity{"work": {AgentSelector: "work"}},
		Contexts: map[string]model.Context{"ctx": {Routes: []model.HostRoute{{
			Host:     "github.com",
			Identity: "work",
			Agent:    "work",
		}}}},
	}
	preview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", []string{"ssh", "github.com"}, Options{SSHConfigPath: filepath.Join(t.TempDir(), "ssh_config")})
	if err != nil {
		t.Fatal(err)
	}
	if got := preview.Env["SSH_AUTH_SOCK"]; got != "/tmp/work.sock" {
		t.Fatalf("expected route-specific socket, got %q", got)
	}
}

func TestGitSSHCommandQuotesWindowsStylePathsWithDoubleQuotes(t *testing.T) {
	path := `C:\Users\Aman Thanvi\AppData\Roaming\Heimdall\ssh_config`
	if got, want := gitSSHCommand(path), `ssh -F "C:\Users\Aman Thanvi\AppData\Roaming\Heimdall\ssh_config"`; got != want {
		t.Fatalf("unexpected Windows-friendly GIT_SSH_COMMAND:\n got %q\nwant %q", got, want)
	}
	quoted := `/tmp/managed $ ssh_config`
	if got, want := gitSSHCommand(quoted), `ssh -F '/tmp/managed $ ssh_config'`; got != want {
		t.Fatalf("unexpected POSIX fallback quoting:\n got %q\nwant %q", got, want)
	}
}

func TestRunWritesManagedFragmentAndScopesRoutingEnv(t *testing.T) {
	dir := t.TempDir()
	fragment := filepath.Join(dir, "ssh_config")
	envPath := filepath.Join(dir, "child-env.txt")
	t.Setenv("HEIMDALL_LAUNCHER_HELPER", "1")
	t.Setenv("GIT_SSH_COMMAND", "ssh -F /ambient/config")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ambient.sock")
	cfg := model.Config{
		Version:    model.ConfigVersion,
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "/tmp/selected.sock"}}},
		Identities: map[string]model.Identity{"id": {PublicKeyPath: "/tmp/id.pub", AgentSelector: "personal"}},
		Contexts: map[string]model.Context{"ctx": {
			Identity: "id",
			Agent:    "personal",
			Routes:   []model.HostRoute{{Host: "github.com", User: "git"}},
		}},
	}
	command := []string{os.Args[0], "-test.run=TestLauncherHelperProcess", "--", envPath}
	if err := (Launcher{}).RunWithOptions(context.Background(), cfg, "ctx", command, Options{SSHConfigPath: fragment}); err != nil {
		t.Fatal(err)
	}
	rendered, err := os.ReadFile(fragment)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), "Host github.com") {
		t.Fatalf("managed fragment was not rendered for launch:\n%s", rendered)
	}
	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	envText := string(envData)
	for _, want := range []string{
		"SSH_AUTH_SOCK=/tmp/selected.sock",
		"GIT_SSH_COMMAND=ssh -F " + shellQuote(fragment),
	} {
		if !strings.Contains(envText, want) {
			t.Fatalf("child env missing %q:\n%s", want, envText)
		}
	}
}

func TestRunDoesNotWriteFragmentWhenPreviewFails(t *testing.T) {
	dir := t.TempDir()
	fragment := filepath.Join(dir, "ssh_config")
	cfg := model.Config{
		Version:    model.ConfigVersion,
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "/tmp/selected.sock"}}},
		Identities: map[string]model.Identity{"id": {PublicKeyPath: "/tmp/id.pub", AgentSelector: "personal"}},
		Contexts:   map[string]model.Context{"ctx": {Identity: "id", Agent: "personal"}},
	}
	err := (Launcher{}).RunWithOptions(context.Background(), cfg, "missing", []string{os.Args[0]}, Options{SSHConfigPath: fragment})
	if err == nil {
		t.Fatal("expected missing context error")
	}
	if _, statErr := os.Stat(fragment); !os.IsNotExist(statErr) {
		t.Fatalf("fragment should not be written after preview failure: %v", statErr)
	}
}

func TestLauncherHelperProcess(t *testing.T) {
	if os.Getenv("HEIMDALL_LAUNCHER_HELPER") != "1" {
		return
	}
	args := os.Args
	envPath := ""
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			envPath = args[i+1]
			break
		}
	}
	if envPath == "" {
		os.Exit(2)
	}
	data := "SSH_AUTH_SOCK=" + os.Getenv("SSH_AUTH_SOCK") + "\n" +
		"GIT_SSH_COMMAND=" + os.Getenv("GIT_SSH_COMMAND") + "\n"
	if err := os.WriteFile(envPath, []byte(data), 0o600); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestRunWithBridgeScopesSocketAndCleansUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket bridge relay is not available on Windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	upstreamPath := filepath.Join(dir, "upstream.sock")
	listener, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := model.Config{
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: upstreamPath}}},
		Identities: map[string]model.Identity{"id": {AgentSelector: "personal"}},
		Contexts:   map[string]model.Context{"ctx": {Identity: "id", Agent: "personal"}},
		Bridges:    map[string]model.Bridge{"wsl": {Type: "wsl", Scope: "session", Socket: upstreamPath, TTL: "1m"}},
	}
	preview, err := (Launcher{}).PreviewWithOptions(cfg, "ctx", []string{"/bin/true"}, Options{BridgeName: "wsl", RuntimeDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Bridge != "wsl" || preview.Env["SSH_AUTH_SOCK"] == upstreamPath {
		t.Fatalf("bridge preview did not scope socket: %#v", preview)
	}
	if err := (Launcher{}).RunWithOptions(context.Background(), cfg, "ctx", []string{"/bin/true"}, Options{BridgeName: "wsl", RuntimeDir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "heimdall-wsl.sock")); !os.IsNotExist(err) {
		t.Fatalf("bridge socket not cleaned up: %v", err)
	}
}
