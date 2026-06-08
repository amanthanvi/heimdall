package doctor

import (
	"context"
	"io/fs"
	"reflect"
	"sort"
	"strings"
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

func TestDoctorAreaFiltersFindings(t *testing.T) {
	cfg := model.Config{
		Version: model.ConfigVersion,
		Identities: map[string]model.Identity{
			"id": {PublicKeyPath: "/tmp/id.pub", CertificatePath: "/tmp/missing-cert.pub"},
		},
		Contexts: map[string]model.Context{"ctx": {Identity: "id"}},
		HostRoutes: map[string]model.HostRoute{
			"example": {
				Hostname:     "example.com",
				Context:      "ctx",
				ForwardAgent: "yes",
			},
		},
	}
	runner := &openssh.FakeRunner{}
	report, err := (Engine{
		Runner:  runner,
		Scanner: inventory.Scanner{FS: missingFS{}, Runner: runner},
	}).Run(context.Background(), cfg, Options{Area: AreaForwarding})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "HD-FWD-001") {
		t.Fatalf("missing forwarding finding: %#v", report.Findings)
	}
	for _, finding := range report.Findings {
		if finding.ID != "HD-FWD-001" {
			t.Fatalf("focused forwarding doctor emitted unrelated finding %#v in %#v", finding, report.Findings)
		}
	}
}

func TestFindingAreaMappings(t *testing.T) {
	tests := []struct {
		area string
		in   string
		out  string
	}{
		{AreaWindows, "HD-WIN-001", "HD-WSL-001"},
		{AreaWSL, "HD-WSL-001", "HD-CONTAINER-001"},
		{AreaWSL, "HD-WIN-001", "HD-CONTAINER-001"},
		{AreaContainer, "HD-CONTAINER-001", "HD-AGENT-001"},
		{AreaForwarding, "HD-FWD-001", "HD-CERT-001"},
		{AreaCerts, "HD-CERT-004", "HD-FWD-001"},
	}
	for _, tt := range tests {
		t.Run(tt.area+" includes "+tt.in, func(t *testing.T) {
			if !findingMatchesArea(tt.in, tt.area) {
				t.Fatalf("%s should include %s", tt.area, tt.in)
			}
			if findingMatchesArea(tt.out, tt.area) {
				t.Fatalf("%s should exclude %s", tt.area, tt.out)
			}
		})
	}
}

func TestDoctorActiveProbeReportsEffectiveConfigMismatches(t *testing.T) {
	cfg := activeProbeConfig(true)
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("ssh-add", []string{"-l"}): {Stdout: "The agent has no identities.\n"},
		openssh.CommandKey("ssh", []string{"-G", "example"}): {Stdout: strings.Join([]string{
			"host example",
			"identityagent /tmp/other-agent.sock",
			"identityfile /tmp/other-id",
			"certificatefile /tmp/other-cert.pub",
			"identitiesonly no",
			"forwardagent yes",
			"proxyjump wrong-bastion",
			"proxycommand nc wrong.example 22",
		}, "\n")},
	}}
	report, err := (Engine{
		Runner:  runner,
		Scanner: inventory.Scanner{FS: missingFS{}, Runner: runner, Now: func() time.Time { return time.Unix(0, 0) }},
	}).Run(context.Background(), cfg, Options{Host: "example", ActiveProbe: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"HD-ACTIVE-003",
		"HD-ACTIVE-101",
		"HD-ACTIVE-102",
		"HD-ACTIVE-103",
		"HD-ACTIVE-104",
		"HD-ACTIVE-105",
		"HD-ACTIVE-106",
		"HD-ACTIVE-107",
	} {
		if !hasFinding(report.Findings, id) {
			t.Fatalf("missing finding %s: %#v", id, report.Findings)
		}
	}
	if got := activeProbeCommands(runner.Calls); !reflect.DeepEqual(got, []string{openssh.CommandKey("ssh", []string{"-G", "example"})}) {
		t.Fatalf("active probe ran unexpected ssh commands: %#v", runner.Calls)
	}
}

func TestDoctorActiveProbeAcceptsMatchingEffectiveConfig(t *testing.T) {
	cfg := activeProbeConfig(false)
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("ssh-add", []string{"-l"}): {Stdout: "The agent has no identities.\n"},
		openssh.CommandKey("ssh", []string{"-G", "target.example"}): {Stdout: strings.Join([]string{
			"host target.example",
			"identityagent /tmp/agent.sock",
			"identityfile /tmp/id",
			"certificatefile /tmp/id-cert.pub",
			"identitiesonly yes",
			"forwardagent no",
			"proxyjump none",
			"proxycommand iroh-ssh proxy %h",
		}, "\n")},
	}}
	report, err := (Engine{
		Runner:  runner,
		Scanner: inventory.Scanner{FS: missingFS{}, Runner: runner, Now: func() time.Time { return time.Unix(0, 0) }},
	}).Run(context.Background(), cfg, Options{Host: "target.example", ActiveProbe: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(report.Findings, "HD-ACTIVE-003") {
		t.Fatalf("missing completed active probe finding: %#v", report.Findings)
	}
	for _, finding := range report.Findings {
		if strings.HasPrefix(finding.ID, "HD-ACTIVE-10") {
			t.Fatalf("unexpected active mismatch finding: %#v", finding)
		}
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

func activeProbeConfig(withProxyJump bool) model.Config {
	yes := true
	forwardingDisabled := false
	route := model.HostRoute{
		Host:           "example",
		Hostname:       "target.example",
		Context:        "ctx",
		IdentitiesOnly: &yes,
		ProxyCommand:   "iroh-ssh proxy %h",
	}
	if withProxyJump {
		route.ProxyJump = "bastion"
	}
	return model.Config{
		Version:    model.ConfigVersion,
		Agents:     model.AgentConfig{Selectors: map[string]model.AgentSelector{"personal": {Kind: "openssh", Socket: "/tmp/agent.sock"}}},
		Identities: map[string]model.Identity{"id": {PublicKeyPath: "/tmp/id.pub", PrivateKeyPathRef: "/tmp/id", CertificatePath: "/tmp/id-cert.pub", AgentSelector: "personal"}},
		Contexts: map[string]model.Context{"ctx": {
			Identity:   "id",
			Agent:      "personal",
			Forwarding: model.ForwardingPolicy{Enabled: &forwardingDisabled},
		}},
		HostRoutes: map[string]model.HostRoute{"example": route},
	}
}

func activeProbeCommands(calls []string) []string {
	var out []string
	for _, call := range calls {
		if strings.HasPrefix(call, "ssh\x00") {
			out = append(out, call)
		}
	}
	sort.Strings(out)
	return out
}

type missingFS struct{}

func (missingFS) ReadPublicFile(path string) ([]byte, error) { return nil, errMissing{} }
func (missingFS) Stat(path string) (fs.FileInfo, error)      { return nil, errMissing{} }
func (missingFS) Glob(pattern string) ([]string, error)      { return nil, nil }

type errMissing struct{}

func (errMissing) Error() string { return "missing" }
