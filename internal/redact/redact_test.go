package redact

import (
	"os"
	"strings"
	"testing"
)

func TestRedactsTokensAndHomePaths(t *testing.T) {
	home, _ := os.UserHomeDir()
	got := String("token=abc123 path="+home+"/.ssh/id_ed25519", Default)
	if strings.Contains(got, "abc123") {
		t.Fatalf("token leaked: %s", got)
	}
	if home != "" && strings.Contains(got, home) {
		t.Fatalf("home path leaked: %s", got)
	}
}

func TestRedactsPrivateKeyBlock(t *testing.T) {
	got := String("x -----BEGIN OPENSSH PRIVATE KEY----- secret -----END OPENSSH PRIVATE KEY----- y", Default)
	if strings.Contains(got, "secret") {
		t.Fatalf("private key material leaked: %s", got)
	}
}
