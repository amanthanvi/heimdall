package transport

import (
	"testing"

	"github.com/athanvi/heimdall/internal/model"
)

func TestProxyCommandRenderingAndShellRisk(t *testing.T) {
	tr := model.ExternalTransport{Type: "proxy_command", Binary: "iroh-ssh", Args: []string{"proxy", "%h"}}
	if got := RenderProxyCommand(tr); got != "iroh-ssh proxy %h" {
		t.Fatalf("unexpected command: %q", got)
	}
	if SuspiciousProxyCommand("iroh-ssh proxy %h") {
		t.Fatal("plain argv-like command flagged suspicious")
	}
	if !SuspiciousProxyCommand("sh -c 'evil | cmd'") {
		t.Fatal("shell command not flagged")
	}
}
