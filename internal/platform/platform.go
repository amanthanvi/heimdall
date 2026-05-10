package platform

import (
	"context"
	"io/fs"
	"os"
	"runtime"
	"strings"

	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
)

type Snapshot struct {
	GOOS                string `json:"goos"`
	IsWSL               bool   `json:"is_wsl"`
	InContainer         bool   `json:"in_container"`
	SSHAuthSock         string `json:"ssh_auth_sock,omitempty"`
	WindowsSSH          bool   `json:"windows_ssh"`
	WindowsAgent        string `json:"windows_agent,omitempty"`
	WindowsAgentService string `json:"windows_agent_service,omitempty"`
	GitSSHCommand       string `json:"git_ssh_command,omitempty"`
}

type FileSystem interface {
	ReadFile(path string) ([]byte, error)
	Stat(path string) (fs.FileInfo, error)
}

type OSFileSystem struct{}

func (OSFileSystem) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func (OSFileSystem) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }

type Detector struct {
	GOOS   string
	FS     FileSystem
	Env    map[string]string
	Runner openssh.Runner
}

func Detect(ctx context.Context, runner openssh.Runner) Snapshot {
	return Detector{GOOS: runtime.GOOS, FS: OSFileSystem{}, Runner: runner}.Detect(ctx)
}

func (d Detector) Detect(ctx context.Context) Snapshot {
	goos := d.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	fsys := d.FS
	if fsys == nil {
		fsys = OSFileSystem{}
	}
	runner := d.Runner
	if runner == nil {
		runner = openssh.ExecRunner{}
	}
	s := Snapshot{GOOS: goos, SSHAuthSock: d.getenv("SSH_AUTH_SOCK")}
	if data, err := fsys.ReadFile("/proc/version"); err == nil && strings.Contains(strings.ToLower(string(data)), "microsoft") {
		s.IsWSL = true
	}
	if _, err := fsys.Stat("/.dockerenv"); err == nil {
		s.InContainer = true
	}
	if data, err := fsys.ReadFile("/proc/1/cgroup"); err == nil && (strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd")) {
		s.InContainer = true
	}
	if goos == "windows" || s.IsWSL {
		if res, err := runner.Run(ctx, "ssh.exe", []string{"-V"}); err == nil || strings.Contains(res.Stderr+res.Stdout, "OpenSSH") {
			s.WindowsSSH = true
		}
		if res, err := runner.Run(ctx, "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", "(Get-Service ssh-agent).Status"}); err == nil {
			s.WindowsAgentService = strings.TrimSpace(res.Stdout)
		}
	}
	if res, err := runner.Run(ctx, "git", []string{"config", "--global", "--get", "core.sshCommand"}); err == nil {
		s.GitSSHCommand = strings.TrimSpace(res.Stdout)
	}
	return s
}

func (d Detector) getenv(key string) string {
	if d.Env != nil {
		return d.Env[key]
	}
	return os.Getenv(key)
}

func Findings(s Snapshot) []model.DiagnosticFinding {
	var out []model.DiagnosticFinding
	if s.SSHAuthSock == "" {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-AGENT-001", Severity: "warning", Confidence: "high",
			Title:        "SSH_AUTH_SOCK is not set",
			Evidence:     []string{"current environment has no SSH_AUTH_SOCK"},
			Risk:         "OpenSSH may not reach an agent unless routes set IdentityAgent explicitly.",
			SuggestedFix: "Start an OpenSSH-compatible agent or configure a Heimdall agent selector with an explicit socket.",
			Autofix:      "manual",
		})
	}
	if s.IsWSL && !s.WindowsSSH {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-WSL-001", Severity: "warning", Confidence: "medium",
			Title:        "WSL detected without Windows OpenSSH visibility",
			Evidence:     []string{"environment appears to be WSL; ssh.exe -V was not available"},
			Risk:         "Windows identities may work outside WSL while Linux-native WSL tools use a different agent.",
			SuggestedFix: "Use WSL Mode A with Windows ssh.exe where practical, or explicitly start a scoped bridge for supported child processes.",
			Autofix:      "dry-run-only",
		})
	}
	if (s.GOOS == "windows" || s.IsWSL) && !s.WindowsSSH {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-WIN-001", Severity: "warning", Confidence: "medium",
			Title:        "Windows OpenSSH is not visible",
			Evidence:     []string{"ssh.exe -V did not return OpenSSH evidence"},
			Risk:         "Windows-native routes and WSL Mode A may not work.",
			SuggestedFix: "Install or enable Microsoft OpenSSH Client and verify ssh.exe is on PATH.",
			Autofix:      "manual",
		})
	}
	if (s.GOOS == "windows" || s.IsWSL) && s.WindowsAgentService != "" && !strings.EqualFold(s.WindowsAgentService, "Running") {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-WIN-002", Severity: "warning", Confidence: "high",
			Title:        "Windows ssh-agent service is not running",
			Evidence:     []string{"ssh-agent service status=" + s.WindowsAgentService},
			Risk:         "Windows OpenSSH agent-backed identities may be unavailable.",
			SuggestedFix: "Start the Windows ssh-agent service if that is the intended provider.",
			Autofix:      "manual",
		})
	}
	if s.IsWSL && s.GitSSHCommand != "" && !strings.Contains(strings.ToLower(s.GitSSHCommand), "ssh.exe") {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-WSL-002", Severity: "warning", Confidence: "medium",
			Title:        "WSL Git is not configured for Windows ssh.exe",
			Evidence:     []string{"git core.sshCommand=" + s.GitSSHCommand},
			Risk:         "Git in WSL may authenticate with a different Linux agent than expected.",
			SuggestedFix: "Review `heimdall wsl mode-a configure-git --dry-run` output before applying changes yourself.",
			Autofix:      "dry-run-only",
		})
	}
	if s.InContainer && s.SSHAuthSock == "" {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-CONTAINER-001", Severity: "warning", Confidence: "medium",
			Title:        "Container has no SSH agent socket",
			Evidence:     []string{"container-like environment detected; SSH_AUTH_SOCK is empty"},
			Risk:         "Git or SSH commands inside the container may fail or prompt users to copy private keys.",
			SuggestedFix: "Mount a scoped agent socket only for trusted workflows; do not copy private keys into the image.",
			Autofix:      "manual",
		})
	}
	return out
}

func ContainerSnippet(socketPath string) string {
	if socketPath == "" {
		socketPath = "$SSH_AUTH_SOCK"
	}
	return "docker run --rm -e SSH_AUTH_SOCK=/ssh-agent -v " + socketPath + ":/ssh-agent:ro <image> <cmd>\n"
}

func WSLModeAConfigureGitDryRun() string {
	return "git config --global core.sshCommand 'ssh.exe'\n"
}

type ConfigureGitResult struct {
	Command  []string `json:"command"`
	Executed bool     `json:"executed"`
	Stdout   string   `json:"stdout,omitempty"`
	Stderr   string   `json:"stderr,omitempty"`
	ExitCode int      `json:"exit_code,omitempty"`
}

func ConfigureGitModeA(ctx context.Context, runner openssh.Runner, execute bool) (ConfigureGitResult, error) {
	command := []string{"git", "config", "--global", "core.sshCommand", "ssh.exe"}
	result := ConfigureGitResult{Command: command, Executed: execute}
	if !execute {
		return result, nil
	}
	if runner == nil {
		runner = openssh.ExecRunner{}
	}
	res, err := runner.Run(ctx, command[0], command[1:])
	result.Stdout = res.Stdout
	result.Stderr = res.Stderr
	result.ExitCode = res.ExitCode
	return result, err
}
