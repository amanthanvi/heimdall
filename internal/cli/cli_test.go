package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
