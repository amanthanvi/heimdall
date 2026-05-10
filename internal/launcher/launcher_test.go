package launcher

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
