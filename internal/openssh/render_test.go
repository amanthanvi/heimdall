package openssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/athanvi/heimdall/internal/model"
)

func TestRenderManagedFragment(t *testing.T) {
	yes := true
	cfg := model.Config{
		Version:    model.ConfigVersion,
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "/tmp/agent.sock"}}},
		Identities: map[string]model.Identity{"github": {PrivateKeyPathRef: "/home/me/.ssh/id_ed25519", CertificatePath: "/home/me/.ssh/id_ed25519-cert.pub", AgentSelector: "personal"}},
		Contexts:   map[string]model.Context{"github": {Identity: "github", Agent: "personal", Forwarding: model.ForwardingPolicy{Agent: "deny"}}},
		Transports: map[string]model.ExternalTransport{"iroh-ssh": {Type: "proxy_command", Binary: "iroh-ssh", Args: []string{"proxy", "%h"}}},
		HostRoutes: map[string]model.HostRoute{"github.com": {Hostname: "github.com", User: "git", Context: "github", IdentitiesOnly: &yes, Transport: "iroh-ssh"}},
	}
	rendered, err := Render(cfg, RenderOptions{GeneratedAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	text := string(rendered)
	for _, want := range []string{
		ManagedHeader,
		"Host github.com",
		"  IdentityAgent /tmp/agent.sock",
		"  IdentityFile /home/me/.ssh/id_ed25519",
		"  CertificateFile /home/me/.ssh/id_ed25519-cert.pub",
		"  IdentitiesOnly yes",
		"  ForwardAgent no",
		"  ProxyCommand iroh-ssh proxy %h",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestInstallIncludeDryRunAndRollback(t *testing.T) {
	dir := t.TempDir()
	userConfig := filepath.Join(dir, "config")
	fragment := filepath.Join(dir, "heimdall_config")
	if err := os.WriteFile(userConfig, []byte("Host old\n  User me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dry, err := InstallInclude(userConfig, fragment, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dry, "Include "+fragment) {
		t.Fatalf("dry-run missing include: %s", dry)
	}
	if data, _ := os.ReadFile(userConfig); strings.Contains(string(data), fragment) {
		t.Fatal("dry run mutated config")
	}
	if _, err := InstallInclude(userConfig, fragment, false); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(userConfig + ".heimdall-backup-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one backup, matches=%v err=%v", matches, err)
	}
	if err := Rollback(userConfig, matches[0]); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(userConfig)
	if strings.Contains(string(data), fragment) {
		t.Fatal("rollback did not restore original config")
	}
}
