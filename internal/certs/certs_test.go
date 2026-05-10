package certs

import (
	"context"
	"testing"
	"time"

	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
)

func TestInspectExpiredCertFromFixtureOutput(t *testing.T) {
	path := "/tmp/id-cert.pub"
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("ssh-keygen", []string{"-L", "-f", path}): {Stdout: `id-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:abc
        Signing CA: ED25519 SHA256:ca (using ssh-ed25519)
        Key ID: "test"
        Serial: 1
        Valid: from 2025-01-01T00:00:00 to 2025-01-02T00:00:00
        Principals:
                git
`},
	}}
	cert := Inspect(context.Background(), runner, path, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if !cert.Expired || cert.KeyID != "test" || len(cert.Principals) != 1 {
		t.Fatalf("unexpected cert: %#v", cert)
	}
}

func TestRefreshDryRunDoesNotExecute(t *testing.T) {
	runner := &openssh.FakeRunner{}
	ref := model.CertificateRef{RefreshHook: []string{"step", "ssh", "renew"}}
	got, err := Refresh(context.Background(), runner, "cert", ref, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Executed || len(runner.Calls) != 0 {
		t.Fatalf("dry run executed hook: result=%#v calls=%#v", got, runner.Calls)
	}
}

func TestRefreshExecuteUsesArgv(t *testing.T) {
	ref := model.CertificateRef{RefreshHook: []string{"refresh-cert", "arg;not-shell"}}
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("refresh-cert", []string{"arg;not-shell"}): {Stdout: "ok\n"},
	}}
	got, err := Refresh(context.Background(), runner, "cert", ref, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Executed || got.Stdout != "ok\n" {
		t.Fatalf("unexpected refresh result: %#v", got)
	}
	if len(runner.Calls) != 1 || runner.Calls[0] != openssh.CommandKey("refresh-cert", []string{"arg;not-shell"}) {
		t.Fatalf("unexpected calls: %#v", runner.Calls)
	}
}

func TestRefreshRejectsControlCharacters(t *testing.T) {
	ref := model.CertificateRef{RefreshHook: []string{"refresh", "bad\narg"}}
	if _, err := Refresh(context.Background(), nil, "cert", ref, true); err == nil {
		t.Fatal("expected invalid hook refusal")
	}
}
