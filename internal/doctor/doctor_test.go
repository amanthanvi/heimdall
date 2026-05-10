package doctor

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/athanvi/heimdall/internal/inventory"
	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
)

func TestDoctorPassiveHostAddsActiveProbeDisclosure(t *testing.T) {
	cfg := model.Config{
		Version:    model.ConfigVersion,
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "env:SSH_AUTH_SOCK"}}},
		Identities: map[string]model.Identity{"id": {PublicKeyPath: "/tmp/id.pub", AgentSelector: "personal"}},
		Contexts:   map[string]model.Context{"ctx": {Identity: "id", Agent: "personal"}},
		HostRoutes: map[string]model.HostRoute{"example": {Hostname: "example.com", Context: "ctx"}},
	}
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("ssh-add", []string{"-l"}): {Stdout: "The agent has no identities.\n"},
	}}
	report, err := (Engine{
		Runner:  runner,
		Scanner: inventory.Scanner{FS: missingFS{}, Runner: runner, Now: func() time.Time { return time.Unix(0, 0) }},
	}).Run(context.Background(), cfg, Options{Host: "example"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "HD-ACTIVE-001") {
		t.Fatalf("missing active probe disclosure: %#v", report.Findings)
	}
	for _, call := range runner.Calls {
		if call == openssh.CommandKey("ssh", []string{"-G", "example"}) {
			t.Fatalf("passive doctor ran active ssh probe: %#v", runner.Calls)
		}
	}
}

func TestDoctorReportsMissingRouteCertificate(t *testing.T) {
	cfg := model.Config{
		Version: model.ConfigVersion,
		Identities: map[string]model.Identity{
			"id": {PublicKeyPath: "/tmp/id.pub", CertificatePath: "/tmp/missing-cert.pub"},
		},
		Contexts:   map[string]model.Context{"ctx": {Identity: "id"}},
		HostRoutes: map[string]model.HostRoute{"example": {Hostname: "example.com", Context: "ctx"}},
	}
	report, err := (Engine{Runner: &openssh.FakeRunner{}, Scanner: inventory.Scanner{FS: missingFS{}, Runner: &openssh.FakeRunner{}}}).Run(context.Background(), cfg, Options{Host: "example"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "HD-CERT-004") {
		t.Fatalf("missing cert finding: %#v", report.Findings)
	}
}

func hasFinding(findings []model.DiagnosticFinding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

type missingFS struct{}

func (missingFS) ReadPublicFile(path string) ([]byte, error) { return nil, errMissing{} }
func (missingFS) Stat(path string) (fs.FileInfo, error)      { return nil, errMissing{} }
func (missingFS) Glob(pattern string) ([]string, error)      { return nil, nil }

type errMissing struct{}

func (errMissing) Error() string { return "missing" }
