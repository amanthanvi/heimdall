package doctor

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/athanvi/heimdall/internal/config"
	"github.com/athanvi/heimdall/internal/inventory"
	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
	"github.com/athanvi/heimdall/internal/platform"
	"github.com/athanvi/heimdall/internal/transport"
)

type Options struct {
	ConfigPath    string
	FragmentPath  string
	UserSSHConfig string
	Host          string
	ActiveProbe   bool
	FailOnWarning bool
}

type Report struct {
	Findings  []model.DiagnosticFinding `json:"findings"`
	Inventory model.Inventory           `json:"inventory"`
	Platform  platform.Snapshot         `json:"platform"`
}

type Engine struct {
	Runner  openssh.Runner
	Scanner inventory.Scanner
}

func (e Engine) Run(ctx context.Context, cfg model.Config, opts Options) (Report, error) {
	runner := e.Runner
	if runner == nil {
		runner = openssh.ExecRunner{}
	}
	scanner := e.Scanner
	if scanner.Runner == nil {
		scanner.Runner = runner
	}
	inv, _ := scanner.Scan(ctx, cfg)
	snapshot := platform.Detect(ctx, runner)
	findings := []model.DiagnosticFinding{}
	findings = append(findings, platform.Findings(snapshot)...)
	findings = append(findings, configFindings(cfg, opts)...)
	findings = append(findings, inventoryFindings(cfg, inv)...)
	findings = append(findings, routeFindings(cfg, opts.Host)...)
	findings = append(findings, certFindings(inv)...)
	findings = append(findings, transportFindings(ctx, cfg)...)
	if opts.Host != "" && !opts.ActiveProbe {
		findings = append(findings, model.DiagnosticFinding{
			ID: "HD-ACTIVE-001", Severity: "info", Confidence: "high",
			Title:        "Active host probe not run",
			Evidence:     []string{"doctor host is passive; no network contact, ProxyCommand execution, or authentication attempt was made"},
			SuggestedFix: "Re-run with --active-probe only if you consent to network contact and local transport execution.",
			Autofix:      "none",
		})
	}
	if opts.Host != "" && opts.ActiveProbe {
		findings = append(findings, activeProbe(ctx, runner, opts.Host))
	}
	return Report{Findings: findings, Inventory: inv, Platform: snapshot}, nil
}

func configFindings(cfg model.Config, opts Options) []model.DiagnosticFinding {
	var out []model.DiagnosticFinding
	userConfig := firstNonEmpty(opts.UserSSHConfig, config.DefaultUserSSHConfigPath())
	fragment := firstNonEmpty(opts.FragmentPath, config.DefaultSSHFragmentPath())
	data, err := os.ReadFile(userConfig)
	if err != nil {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-CONFIG-001", Severity: "warning", Confidence: "high",
			Title:        "User SSH config is missing or unreadable",
			Evidence:     []string{err.Error()},
			Risk:         "OpenSSH will not include Heimdall routes until the managed Include is installed.",
			SuggestedFix: "Run `heimdall config install-include --dry-run` and review the Include line.",
			Autofix:      "dry-run-available",
		})
		return out
	}
	if !strings.Contains(string(data), fragment) {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-CONFIG-002", Severity: "warning", Confidence: "high",
			Title:        "Managed Heimdall Include is missing",
			Evidence:     []string{"expected Include for " + fragment + " was not found in " + userConfig},
			Risk:         "Rendered routes will not affect OpenSSH.",
			SuggestedFix: "Run `heimdall config install-include --dry-run`, review, then rerun without --dry-run.",
			Autofix:      "explicit",
		})
	}
	if _, err := os.Stat(fragment); err != nil {
		out = append(out, model.DiagnosticFinding{
			ID: "HD-CONFIG-003", Severity: "warning", Confidence: "high",
			Title:        "Managed Heimdall fragment is missing",
			Evidence:     []string{err.Error()},
			Risk:         "The Include target may point to a missing file.",
			SuggestedFix: "Run `heimdall config render --write`.",
			Autofix:      "explicit",
		})
	}
	for name, route := range cfg.HostRoutes {
		ctx := cfg.Contexts[route.Context]
		if route.IdentitiesOnly == nil && len(cfg.Identities) > 0 {
			_ = ctx
			out = append(out, model.DiagnosticFinding{
				ID: "HD-ROUTE-001", Severity: "info", Confidence: "medium",
				Title:        "Route will default to IdentitiesOnly yes",
				Evidence:     []string{"host route " + name + " omits identities_only; renderer emits IdentitiesOnly yes"},
				SuggestedFix: "Set identities_only explicitly if you want config intent to be visible in YAML.",
				Autofix:      "manual",
			})
		}
	}
	return out
}

func inventoryFindings(cfg model.Config, inv model.Inventory) []model.DiagnosticFinding {
	var out []model.DiagnosticFinding
	for _, agent := range inv.Agents {
		if agent.Error != "" {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-AGENT-002", Severity: "warning", Confidence: "medium",
				Title:        "Agent could not be inventoried",
				Evidence:     []string{agent.Name + ": " + agent.Error},
				Risk:         "Routes using this agent may fail closed.",
				SuggestedFix: "Verify the selector endpoint and that ssh-add can list identities.",
				Autofix:      "manual",
			})
		}
		if agent.Live && len(agent.Identities) == 0 {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-AGENT-003", Severity: "warning", Confidence: "high",
				Title:        "Agent has zero identities",
				Evidence:     []string{agent.Name + " returned no identities"},
				Risk:         "Authentication will fail unless IdentityFile points to a usable key outside the agent.",
				SuggestedFix: "Load the intended key into the selected agent.",
				Autofix:      "manual",
			})
		}
		if len(agent.Identities) > 6 {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-AGENT-004", Severity: "warning", Confidence: "high",
				Title:        "Agent exposes many identities",
				Evidence:     []string{fmt.Sprintf("%s exposes %d identities", agent.Name, len(agent.Identities))},
				Risk:         "OpenSSH may offer too many keys or a coding agent may inherit broader access than intended.",
				SuggestedFix: "Use route-specific IdentityAgent and IdentitiesOnly yes.",
				Autofix:      "rendered",
			})
		}
	}
	for name, identity := range cfg.Identities {
		if identity.PrivateKeyPathRef != "" {
			if err := inventory.CheckPrivateKeyReference(inventory.OSFileSystem{}, identity.PrivateKeyPathRef); err != nil && !os.IsNotExist(err) {
				out = append(out, model.DiagnosticFinding{
					ID: "HD-KEY-001", Severity: "warning", Confidence: "medium",
					Title:        "Private key path reference has unsafe permissions",
					Evidence:     []string{name + ": " + err.Error()},
					Risk:         "OpenSSH may reject the key or local processes may read it.",
					SuggestedFix: "Restrict permissions, usually chmod 600 on Unix-like systems.",
					Autofix:      "manual",
				})
			}
		}
	}
	return out
}

func routeFindings(cfg model.Config, host string) []model.DiagnosticFinding {
	var out []model.DiagnosticFinding
	for name, route := range cfg.HostRoutes {
		if host != "" && name != host && route.Hostname != host {
			continue
		}
		ctx := cfg.Contexts[route.Context]
		identity := cfg.Identities[firstNonEmpty(route.Identity, ctx.Identity)]
		certPath := firstNonEmpty(route.CertificateFile, identity.CertificatePath)
		if certPath != "" {
			if _, err := os.Stat(inventory.ExpandPath(certPath)); err != nil {
				out = append(out, model.DiagnosticFinding{
					ID: "HD-CERT-004", Severity: "warning", Confidence: "high",
					Title:        "Route certificate file is missing",
					Evidence:     []string{"route " + name + " CertificateFile=" + certPath + ": " + err.Error()},
					Risk:         "Certificate-backed authentication for this route may fail before key selection succeeds.",
					SuggestedFix: "Refresh or correct the public certificate path; Heimdall will not store refresh tokens.",
					Autofix:      "explicit-refresh-hook",
				})
			}
		}
		if route.ForwardAgent == "yes" {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-FWD-001", Severity: "warning", Confidence: "high",
				Title:        "Host route enables agent forwarding",
				Evidence:     []string{"route " + name + " sets ForwardAgent yes"},
				Risk:         "Agent forwarding delegates signing capability to the remote environment.",
				SuggestedFix: "Use ForwardAgent no unless the remote host is explicitly trusted.",
				Autofix:      "manual",
			})
		}
		if route.ProxyCommand != "" && transport.SuspiciousProxyCommand(route.ProxyCommand) {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-TRANSPORT-002", Severity: "warning", Confidence: "high",
				Title:        "ProxyCommand contains shell metacharacters",
				Evidence:     []string{"route " + name + " ProxyCommand=" + route.ProxyCommand},
				Risk:         "ProxyCommand executes locally; shell syntax can expand risk and obscure transport failures.",
				SuggestedFix: "Prefer structured transport binary and args in Heimdall config.",
				Autofix:      "manual",
			})
		}
	}
	return out
}

func certFindings(inv model.Inventory) []model.DiagnosticFinding {
	var out []model.DiagnosticFinding
	for _, cert := range inv.Certificates {
		if cert.Error != "" {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-CERT-001", Severity: "warning", Confidence: "medium",
				Title:        "Certificate could not be inspected",
				Evidence:     []string{cert.Path + ": " + cert.Error},
				SuggestedFix: "Verify the certificate path and run ssh-keygen -L manually if needed.",
				Autofix:      "manual",
			})
		}
		if cert.Expired {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-CERT-002", Severity: "error", Confidence: "high",
				Title:        "SSH certificate is expired",
				Evidence:     []string{cert.Path + " expired before now"},
				Risk:         "Certificate-backed authentication will fail.",
				SuggestedFix: "Refresh the certificate using your external provider; Heimdall will not store refresh tokens.",
				Autofix:      "explicit-refresh-hook",
			})
		} else if cert.NearExpiry {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-CERT-003", Severity: "warning", Confidence: "high",
				Title:        "SSH certificate expires soon",
				Evidence:     []string{cert.Path + " expires soon"},
				SuggestedFix: "Refresh before expiry with your external certificate workflow.",
				Autofix:      "explicit-refresh-hook",
			})
		}
	}
	return out
}

func transportFindings(ctx context.Context, cfg model.Config) []model.DiagnosticFinding {
	var out []model.DiagnosticFinding
	for name, tr := range cfg.Transports {
		if tr.Type == "proxy_command" && transport.MissingBinary(ctx, tr) {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-TRANSPORT-001", Severity: "warning", Confidence: "high",
				Title:        "ProxyCommand binary is missing",
				Evidence:     []string{name + ": " + tr.Binary + " not found on PATH"},
				Risk:         "OpenSSH route will fail before authentication; this is a transport startup failure, not an identity failure.",
				SuggestedFix: "Install the transport binary or adjust the Heimdall transport definition.",
				Autofix:      "manual",
			})
		}
		if transport.SuspiciousProxyCommand(transport.RenderProxyCommand(tr)) {
			out = append(out, model.DiagnosticFinding{
				ID: "HD-TRANSPORT-002", Severity: "warning", Confidence: "high",
				Title:        "Transport ProxyCommand contains shell metacharacters",
				Evidence:     []string{name + ": " + transport.RenderProxyCommand(tr)},
				Risk:         "ProxyCommand executes locally.",
				SuggestedFix: "Use a binary and argv-style args without shell syntax.",
				Autofix:      "manual",
			})
		}
	}
	return out
}

func activeProbe(ctx context.Context, runner openssh.Runner, host string) model.DiagnosticFinding {
	res, err := runner.Run(ctx, "ssh", []string{"-G", host})
	if err != nil {
		return model.DiagnosticFinding{
			ID: "HD-ACTIVE-002", Severity: "warning", Confidence: "medium",
			Title:        "Active OpenSSH config probe failed",
			Evidence:     []string{strings.TrimSpace(res.Stderr)},
			Risk:         "Effective OpenSSH config could not be evaluated.",
			SuggestedFix: "Run ssh -G manually and inspect local OpenSSH errors.",
			Autofix:      "none",
		}
	}
	return model.DiagnosticFinding{
		ID: "HD-ACTIVE-003", Severity: "info", Confidence: "high",
		Title:    "Active OpenSSH config probe completed",
		Evidence: []string{"ssh -G returned " + fmt.Sprintf("%d", len(strings.Split(res.Stdout, "\n"))) + " lines"},
		Autofix:  "none",
	}
}

func SeverityExitCode(findings []model.DiagnosticFinding, failOnWarning bool) int {
	code := 0
	for _, f := range findings {
		if f.Severity == "error" {
			return 1
		}
		if failOnWarning && f.Severity == "warning" {
			code = 5
		}
	}
	return code
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
