package platform

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/athanvi/heimdall/internal/openssh"
)

type fixtureFS struct {
	files map[string][]byte
	stats map[string]fs.FileInfo
}

func (f fixtureFS) ReadFile(path string) ([]byte, error) {
	data, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (f fixtureFS) Stat(path string) (fs.FileInfo, error) {
	info, ok := f.stats[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return info, nil
}

func TestDetectWSLAndWindowsSSHFromFixtures(t *testing.T) {
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("ssh.exe", []string{"-V"}): {Stderr: "OpenSSH_for_Windows_9.5"},
		openssh.CommandKey("powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", "(Get-Service ssh-agent).Status"}): {Stdout: "Running\n"},
		openssh.CommandKey("git", []string{"config", "--global", "--get", "core.sshCommand"}):                                         {Stdout: "ssh.exe\n"},
	}}
	s := Detector{
		GOOS: "linux",
		FS: fixtureFS{files: map[string][]byte{
			"/proc/version": []byte("Linux version Microsoft"),
		}},
		Env:    map[string]string{"SSH_AUTH_SOCK": "/tmp/agent.sock"},
		Runner: runner,
	}.Detect(context.Background())
	if !s.IsWSL || !s.WindowsSSH || s.WindowsAgentService != "Running" || s.GitSSHCommand != "ssh.exe" {
		t.Fatalf("unexpected snapshot: %#v", s)
	}
}

func TestWindowsAgentStoppedFinding(t *testing.T) {
	s := Snapshot{GOOS: "windows", WindowsSSH: true, WindowsAgentService: "Stopped"}
	findings := Findings(s)
	found := false
	for _, finding := range findings {
		if finding.ID == "HD-WIN-002" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing stopped service finding: %#v", findings)
	}
}

func TestConfigureGitModeADryRunAndExecute(t *testing.T) {
	runner := &openssh.FakeRunner{Results: map[string]openssh.Result{
		openssh.CommandKey("git", []string{"config", "--global", "core.sshCommand", "ssh.exe"}): {Stdout: "ok\n"},
	}}
	preview, err := ConfigureGitModeA(context.Background(), runner, false)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Executed || len(runner.Calls) != 0 {
		t.Fatalf("dry run executed: %#v calls=%#v", preview, runner.Calls)
	}
	executed, err := ConfigureGitModeA(context.Background(), runner, true)
	if err != nil {
		t.Fatal(err)
	}
	if !executed.Executed || executed.Stdout != "ok\n" {
		t.Fatalf("unexpected execute result: %#v", executed)
	}
}

func TestContainerFindingFromFixture(t *testing.T) {
	s := Detector{
		GOOS: "linux",
		FS: fixtureFS{files: map[string][]byte{
			"/proc/1/cgroup": []byte("0::/docker/test"),
		}},
		Env: map[string]string{},
		Runner: &openssh.FakeRunner{Results: map[string]openssh.Result{
			openssh.CommandKey("git", []string{"config", "--global", "--get", "core.sshCommand"}): {ExitCode: 1},
		}},
	}.Detect(context.Background())
	if !s.InContainer {
		t.Fatalf("expected container snapshot: %#v", s)
	}
	findings := Findings(s)
	found := false
	for _, finding := range findings {
		if finding.ID == "HD-CONTAINER-001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing container finding: %#v", findings)
	}
}
