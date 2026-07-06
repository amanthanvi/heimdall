package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	"github.com/athanvi/heimdall/internal/bridge"
	"github.com/athanvi/heimdall/internal/certs"
	"github.com/athanvi/heimdall/internal/config"
	"github.com/athanvi/heimdall/internal/doctor"
	"github.com/athanvi/heimdall/internal/inventory"
	"github.com/athanvi/heimdall/internal/launcher"
	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
	"github.com/athanvi/heimdall/internal/platform"
	"github.com/athanvi/heimdall/internal/redact"
	"github.com/athanvi/heimdall/internal/tui"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	exitCommandFailed     = 1
	exitConfigInvalid     = 2
	exitDependencyMissing = 3
	exitSecurityRefusal   = 4
)

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

type options struct {
	configPath       string
	format           string
	json             bool
	dryRun           bool
	verbose          bool
	noColor          bool
	redaction        string
	redact           bool
	unsafeFullOutput bool
	yes              bool
	fragmentPath     string
	userSSHConfig    string
	activeProbe      bool
	failOn           string
	strict           bool
	write            bool
	contextName      string
	bridgeName       string
	bridgeRuntimeDir string
	execute          bool
}

type codedError struct {
	code int
	err  error
}

func (e codedError) Error() string { return e.err.Error() }
func (e codedError) Unwrap() error { return e.err }

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var coded codedError
	if errors.As(err, &coded) {
		return coded.code
	}
	var validation config.ValidationError
	if errors.As(err, &validation) {
		return exitConfigInvalid
	}
	if errors.Is(err, launcher.ErrNoAgentSocket) {
		return exitSecurityRefusal
	}
	return exitCommandFailed
}

func NewRootCommand() *cobra.Command {
	opts := &options{format: "human", redaction: string(redact.Default)}
	version := versionString(currentVersionInfo())
	root := &cobra.Command{
		Use:     "heimdall",
		Short:   "Local-first SSH identity control plane",
		Long:    "Heimdall inventories SSH identities and agents, renders managed OpenSSH config, diagnoses routing failures, and launches scoped SSH-aware commands without private-key custody.",
		Version: version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return validateOutputFlags(cmd, opts)
		},
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.PersistentFlags().StringVar(&opts.configPath, "config", "", "Heimdall config path")
	root.PersistentFlags().StringVar(&opts.format, "format", "human", "output format: human, json, yaml")
	root.PersistentFlags().BoolVar(&opts.json, "json", false, "alias for --format json; cannot be combined with --format other than json")
	root.PersistentFlags().BoolVar(&opts.dryRun, "dry-run", false, "show intended changes without mutating")
	root.PersistentFlags().BoolVar(&opts.verbose, "verbose", false, "verbose diagnostics")
	root.PersistentFlags().BoolVar(&opts.noColor, "no-color", false, "disable color output")
	root.PersistentFlags().StringVar(&opts.redaction, "redaction", string(redact.Default), "redaction level: low, default, high")
	root.PersistentFlags().BoolVar(&opts.unsafeFullOutput, "unsafe-full-output", false, "disable default redaction for local troubleshooting")
	root.PersistentFlags().BoolVar(&opts.yes, "yes", false, "confirm explicit mutation after reviewing dry-run output")
	root.AddCommand(
		doctorCommand(opts),
		identitiesCommand(opts),
		agentsCommand(opts),
		contextsCommand(opts),
		contextCommand(opts),
		runCommand(opts),
		sshCommand(opts),
		configCommand(opts),
		wslCommand(opts),
		bridgeCommand(opts),
		transportCommand(opts),
		certsCommand(opts),
		tuiCommand(opts),
		versionCommand(opts),
		completionCommand(root),
	)
	return root
}

func loadConfig(opts *options) (model.Config, error) {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return model.Config{}, codedError{code: exitConfigInvalid, err: err}
	}
	return config.Normalize(cfg), nil
}

func output(opts *options, value any) error {
	level := redactionLevel(opts)
	switch outputFormat(opts) {
	case "json":
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(redact.String(string(data), level))
	case "yaml":
		data, err := yaml.Marshal(value)
		if err != nil {
			return err
		}
		fmt.Print(redact.String(string(data), level))
	default:
		fmt.Print(redact.String(formatHuman(value), level))
	}
	return nil
}

func doctorCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "doctor",
		Short:   "Diagnose SSH identity, agent, config, platform, certificate, and transport routing",
		Version: versionString(currentVersionInfo()),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			report, err := doctor.Engine{}.Run(cmd.Context(), cfg, doctor.Options{
				ConfigPath: opts.configPath, FragmentPath: opts.fragmentPath, UserSSHConfig: opts.userSSHConfig,
				ActiveProbe: opts.activeProbe, FailOnWarning: doctorFailOnWarning(opts),
			})
			if err != nil {
				return err
			}
			if err := output(opts, report); err != nil {
				return err
			}
			if code := doctor.SeverityExitCode(report.Findings, doctorFailOnWarning(opts)); code != 0 {
				return codedError{code: code, err: fmt.Errorf("doctor reported findings")}
			}
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&opts.fragmentPath, "fragment", config.DefaultSSHFragmentPath(), "managed SSH fragment path")
	cmd.PersistentFlags().StringVar(&opts.userSSHConfig, "ssh-config", config.DefaultUserSSHConfigPath(), "user OpenSSH config path")
	cmd.PersistentFlags().BoolVar(&opts.activeProbe, "active-probe", false, "consent to local active probes such as ssh -G; no auth attempt is made")
	cmd.PersistentFlags().StringVar(&opts.failOn, "fail-on", "", "exit nonzero on severity: warning")
	cmd.PersistentFlags().BoolVar(&opts.redact, "redact", false, "alias for --redaction high")
	cmd.PersistentFlags().BoolVar(&opts.strict, "strict", false, "alias for --fail-on warning")
	cmd.AddCommand(&cobra.Command{
		Use:   "host <host>",
		Short: "Diagnose one host route; passive unless --active-probe is set",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			report, err := doctor.Engine{}.Run(cmd.Context(), cfg, doctor.Options{
				Host: args[0], FragmentPath: opts.fragmentPath, UserSSHConfig: opts.userSSHConfig, ActiveProbe: opts.activeProbe,
			})
			if err != nil {
				return err
			}
			return output(opts, report)
		},
	})
	for _, area := range []string{doctor.AreaWindows, doctor.AreaWSL, doctor.AreaContainer, doctor.AreaForwarding, doctor.AreaCerts} {
		localArea := area
		cmd.AddCommand(&cobra.Command{
			Use:   localArea,
			Short: "Run passive " + localArea + " diagnostics",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadConfig(opts)
				if err != nil {
					return err
				}
				report, err := doctor.Engine{}.Run(cmd.Context(), cfg, doctor.Options{Area: localArea, FragmentPath: opts.fragmentPath, UserSSHConfig: opts.userSSHConfig})
				if err != nil {
					return err
				}
				return output(opts, report)
			},
		})
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "transport <host>",
		Short: "Diagnose transport route for a host without invoking transports by default",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			report, err := doctor.Engine{}.Run(cmd.Context(), cfg, doctor.Options{Host: args[0], FragmentPath: opts.fragmentPath, UserSSHConfig: opts.userSSHConfig, ActiveProbe: opts.activeProbe})
			if err != nil {
				return err
			}
			return output(opts, report)
		},
	})
	return cmd
}

func identitiesCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "identities",
		Short: "Inventory configured public identities without reading private keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			inv, err := inventory.Scanner{}.Scan(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			return output(opts, inv.Identities)
		},
	}
}

func agentsCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "agents",
		Short: "Inventory configured OpenSSH-compatible agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			inv, err := inventory.Scanner{}.Scan(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			return output(opts, inv.Agents)
		},
	}
}

func contextsCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "contexts",
		Short: "List Heimdall contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			return output(opts, cfg.Contexts)
		},
	}
}

func contextCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "context", Short: "Manage Heimdall contexts"}
	addOpts := &contextAddOptions{}
	add := &cobra.Command{
		Use:   "add <context>",
		Short: "Add a context and host route to Heimdall config",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			addOpts.identitiesOnlySet = cmd.Flags().Changed("identities-only")
			result, err := addContextRoute(cfg, config.ResolvePath(opts.configPath), args[0], *addOpts, shouldApplyMutation(opts))
			if err != nil {
				return err
			}
			result.Refused = mutationRefused(opts)
			return outputContextAdd(opts, result)
		},
	}
	add.Flags().StringVar(&addOpts.host, "host", "", "OpenSSH Host alias for this route")
	add.Flags().StringVar(&addOpts.hostname, "hostname", "", "OpenSSH HostName for this route")
	add.Flags().StringVar(&addOpts.user, "user", "", "OpenSSH User for this route")
	add.Flags().IntVar(&addOpts.port, "port", 0, "OpenSSH Port for this route")
	add.Flags().StringVar(&addOpts.identity, "identity", "", "context identity selector")
	add.Flags().StringVar(&addOpts.agent, "agent", "", "context agent selector")
	add.Flags().BoolVar(&addOpts.identitiesOnly, "identities-only", false, "set IdentitiesOnly for this route")
	add.Flags().StringVar(&addOpts.certificateFile, "certificate-file", "", "route-specific CertificateFile")
	add.Flags().StringVar(&addOpts.forwardAgent, "forward-agent", "", "route-specific ForwardAgent value: yes, no, or ask")
	add.Flags().StringVar(&addOpts.proxyJump, "proxy-jump", "", "route-specific ProxyJump")
	add.Flags().StringVar(&addOpts.proxyCommand, "proxy-command", "", "route-specific ProxyCommand")
	add.Flags().StringVar(&addOpts.transport, "transport", "", "configured transport template name")
	_ = add.MarkFlagRequired("host")
	cmd.AddCommand(add)
	return cmd
}

type contextAddOptions struct {
	host              string
	hostname          string
	user              string
	port              int
	identity          string
	agent             string
	identitiesOnly    bool
	identitiesOnlySet bool
	certificateFile   string
	forwardAgent      string
	proxyJump         string
	proxyCommand      string
	transport         string
}

type contextAddResult struct {
	ConfigPath   string   `json:"config_path" yaml:"config_path"`
	Context      string   `json:"context" yaml:"context"`
	Host         string   `json:"host" yaml:"host"`
	DryRun       bool     `json:"dry_run" yaml:"dry_run"`
	BackupPath   string   `json:"backup_path,omitempty" yaml:"backup_path,omitempty"`
	Refused      bool     `json:"refused,omitempty" yaml:"refused,omitempty"`
	Snippet      string   `json:"snippet" yaml:"snippet"`
	NextCommands []string `json:"next_commands" yaml:"next_commands"`
}

func addContextRoute(cfg model.Config, configPath, contextName string, opts contextAddOptions, apply bool) (contextAddResult, error) {
	if strings.TrimSpace(contextName) == "" {
		return contextAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("context name cannot be empty")}
	}
	if strings.TrimSpace(opts.host) == "" {
		return contextAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--host is required")}
	}
	if opts.port < 0 || opts.port > 65535 {
		return contextAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--port must be between 0 and 65535")}
	}
	if opts.forwardAgent != "" && opts.forwardAgent != "yes" && opts.forwardAgent != "no" && opts.forwardAgent != "ask" {
		return contextAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--forward-agent must be yes, no, or ask")}
	}

	cfg = config.Normalize(cfg)
	if routeExists(cfg, opts.host) {
		return contextAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("host route %q already exists", opts.host)}
	}

	ctx, exists := cfg.Contexts[contextName]
	if exists {
		if opts.identity != "" && ctx.Identity != "" && ctx.Identity != opts.identity {
			return contextAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("context %q already uses identity %q", contextName, ctx.Identity)}
		}
		if opts.agent != "" && ctx.Agent != "" && ctx.Agent != opts.agent {
			return contextAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("context %q already uses agent %q", contextName, ctx.Agent)}
		}
	}
	if opts.identity != "" {
		ctx.Identity = opts.identity
	}
	if opts.agent != "" {
		ctx.Agent = opts.agent
	}
	if ctx.Forwarding.Enabled == nil && ctx.Forwarding.Agent == "" {
		disabled := false
		ctx.Forwarding.Enabled = &disabled
	}

	route := model.HostRoute{
		Host:            opts.host,
		Hostname:        opts.hostname,
		User:            opts.user,
		Port:            opts.port,
		CertificateFile: opts.certificateFile,
		ForwardAgent:    opts.forwardAgent,
		ProxyJump:       opts.proxyJump,
		ProxyCommand:    opts.proxyCommand,
		Transport:       opts.transport,
	}
	if opts.identitiesOnlySet {
		route.IdentitiesOnly = &opts.identitiesOnly
	}
	ctx.Routes = append(ctx.Routes, route)
	cfg.Contexts[contextName] = ctx

	if err := config.Validate(cfg); err != nil {
		return contextAddResult{}, err
	}
	backupPath := ""
	if apply {
		var err error
		backupPath, err = config.SaveWithBackup(configPath, cfg)
		if err != nil {
			return contextAddResult{}, err
		}
	}
	snippet, err := contextRouteSnippet(contextName, ctx, route)
	if err != nil {
		return contextAddResult{}, err
	}
	return contextAddResult{
		ConfigPath:   configPath,
		Context:      contextName,
		Host:         opts.host,
		DryRun:       !apply,
		BackupPath:   backupPath,
		Snippet:      snippet,
		NextCommands: renderSuggestion(configPath),
	}, nil
}

func routeExists(cfg model.Config, host string) bool {
	for _, named := range model.NamedHostRoutes(cfg) {
		if named.Host == host {
			return true
		}
	}
	return false
}

type contextRouteSnippetConfig struct {
	Contexts map[string]contextRouteSnippetContext `yaml:"contexts"`
}

type contextRouteSnippetContext struct {
	Identity   string                         `yaml:"identity,omitempty"`
	Agent      string                         `yaml:"agent,omitempty"`
	Routes     []contextRouteSnippetRoute     `yaml:"routes"`
	Forwarding *contextRouteSnippetForwarding `yaml:"forwarding,omitempty"`
}

type contextRouteSnippetRoute struct {
	Host            string `yaml:"host"`
	Hostname        string `yaml:"hostname,omitempty"`
	User            string `yaml:"user,omitempty"`
	Port            int    `yaml:"port,omitempty"`
	IdentitiesOnly  *bool  `yaml:"identities_only,omitempty"`
	CertificateFile string `yaml:"certificate_file,omitempty"`
	ForwardAgent    string `yaml:"forward_agent,omitempty"`
	ProxyJump       string `yaml:"proxy_jump,omitempty"`
	ProxyCommand    string `yaml:"proxy_command,omitempty"`
	Transport       string `yaml:"transport,omitempty"`
}

type contextRouteSnippetForwarding struct {
	Enabled bool `yaml:"enabled"`
}

func contextRouteSnippet(contextName string, ctx model.Context, route model.HostRoute) (string, error) {
	snippetCtx := contextRouteSnippetContext{
		Identity: ctx.Identity,
		Agent:    ctx.Agent,
		Routes: []contextRouteSnippetRoute{{
			Host:            route.Host,
			Hostname:        route.Hostname,
			User:            route.User,
			Port:            route.Port,
			IdentitiesOnly:  route.IdentitiesOnly,
			CertificateFile: route.CertificateFile,
			ForwardAgent:    route.ForwardAgent,
			ProxyJump:       route.ProxyJump,
			ProxyCommand:    route.ProxyCommand,
			Transport:       route.Transport,
		}},
	}
	if ctx.Forwarding.Enabled != nil {
		snippetCtx.Forwarding = &contextRouteSnippetForwarding{Enabled: *ctx.Forwarding.Enabled}
	} else if ctx.Forwarding.Agent == "allow" {
		snippetCtx.Forwarding = &contextRouteSnippetForwarding{Enabled: true}
	} else if ctx.Forwarding.Agent == "deny" {
		snippetCtx.Forwarding = &contextRouteSnippetForwarding{Enabled: false}
	}
	data, err := yaml.Marshal(contextRouteSnippetConfig{Contexts: map[string]contextRouteSnippetContext{contextName: snippetCtx}})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func outputContextAdd(opts *options, result contextAddResult) error {
	if outputFormat(opts) == "json" || outputFormat(opts) == "yaml" {
		return output(opts, result)
	}
	var b strings.Builder
	if result.DryRun {
		b.WriteString("dry run; no config changes written\n")
	} else {
		b.WriteString("updated " + result.ConfigPath + "\n")
		if result.BackupPath != "" {
			b.WriteString("backup: " + result.BackupPath + "\n")
		}
	}
	b.WriteString(result.Snippet)
	for _, command := range result.NextCommands {
		b.WriteString("next: " + command + "\n")
	}
	if result.Refused {
		b.WriteString("refusing config mutation without --yes; rerun with --dry-run first, then --yes\n")
	}
	level := redactionLevel(opts)
	fmt.Print(redact.String(b.String(), level))
	return nil
}

func renderSuggestion(configPath string) []string {
	if configPath == config.DefaultPath() {
		return []string{"heimdall config render --write"}
	}
	return []string{"heimdall --config " + configPath + " config render --write"}
}

func runCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run --context <ctx> -- <cmd> [args...]",
		Short: "Launch a command with only the selected SSH_AUTH_SOCK",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			l := launcher.Launcher{}
			launchOpts := launcher.Options{BridgeName: opts.bridgeName, RuntimeDir: opts.bridgeRuntimeDir}
			preview, err := l.PreviewWithOptions(cfg, opts.contextName, args, launchOpts)
			if err != nil {
				return err
			}
			if opts.dryRun {
				return output(opts, preview)
			}
			return l.RunWithOptions(cmd.Context(), cfg, opts.contextName, args, launchOpts)
		},
	}
	cmd.Flags().StringVar(&opts.contextName, "context", "", "Heimdall context name")
	cmd.Flags().StringVar(&opts.bridgeName, "bridge", "", "session bridge name to expose only to the child process")
	cmd.Flags().StringVar(&opts.bridgeRuntimeDir, "bridge-runtime-dir", "", "bridge runtime directory; must be private")
	_ = cmd.MarkFlagRequired("context")
	return cmd
}

func sshCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh --context <ctx> <host> [ssh args...]",
		Short: "Run OpenSSH with a scoped context",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sshArgs := append([]string{"ssh"}, args...)
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			l := launcher.Launcher{}
			launchOpts := launcher.Options{BridgeName: opts.bridgeName, RuntimeDir: opts.bridgeRuntimeDir}
			preview, err := l.PreviewWithOptions(cfg, opts.contextName, sshArgs, launchOpts)
			if err != nil {
				return err
			}
			if opts.dryRun {
				return output(opts, preview)
			}
			return l.RunWithOptions(cmd.Context(), cfg, opts.contextName, sshArgs, launchOpts)
		},
	}
	cmd.Flags().StringVar(&opts.contextName, "context", "", "Heimdall context name")
	cmd.Flags().StringVar(&opts.bridgeName, "bridge", "", "session bridge name to expose only to the child process")
	cmd.Flags().StringVar(&opts.bridgeRuntimeDir, "bridge-runtime-dir", "", "bridge runtime directory; must be private")
	_ = cmd.MarkFlagRequired("context")
	return cmd
}

func configCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Validate and manage Heimdall/OpenSSH config"}
	cmd.PersistentFlags().StringVar(&opts.fragmentPath, "fragment", config.DefaultSSHFragmentPath(), "managed SSH fragment path")
	cmd.PersistentFlags().StringVar(&opts.userSSHConfig, "ssh-config", config.DefaultUserSSHConfigPath(), "user OpenSSH config path")
	render := &cobra.Command{
		Use:   "render",
		Short: "Render Heimdall-owned OpenSSH config fragment",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			rendered, err := openssh.Render(cfg, openssh.RenderOptions{GeneratedAt: time.Now().UTC()})
			if err != nil {
				return err
			}
			if opts.write {
				if err := openssh.WriteFragment(opts.fragmentPath, rendered); err != nil {
					return err
				}
			}
			fmt.Print(redact.String(string(rendered), redact.Level(opts.redaction)))
			return nil
		},
	}
	render.Flags().BoolVar(&opts.write, "write", false, "write fragment atomically with 0600 permissions")
	cmd.AddCommand(render)
	cmd.AddCommand(&cobra.Command{
		Use:   "install-include",
		Short: "Install one reversible Include line for the Heimdall fragment",
		RunE: func(cmd *cobra.Command, args []string) error {
			dry := opts.dryRun || !opts.yes
			msg, err := openssh.InstallInclude(opts.userSSHConfig, opts.fragmentPath, dry)
			if err != nil {
				return err
			}
			if dry && !opts.dryRun {
				msg += "\nrefusing mutation without --yes; rerun with --dry-run first, then --yes"
			}
			fmt.Print(redact.String(msg, redact.Level(opts.redaction)))
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "doctor",
		Aliases: []string{"validate"},
		Short:   "Validate Heimdall config only",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			return output(opts, map[string]any{"valid": true, "routes": len(model.NamedHostRoutes(cfg))})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "diff",
		Short: "Show diff between current managed fragment and render output",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			rendered, err := openssh.Render(cfg, openssh.RenderOptions{GeneratedAt: time.Time{}})
			if err != nil {
				return err
			}
			diff, err := openssh.Diff(opts.fragmentPath, rendered)
			if err != nil {
				return err
			}
			fmt.Print(redact.String(diff, redact.Level(opts.redaction)))
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "rollback <backup-path>",
		Short: "Restore user SSH config from a Heimdall backup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.yes {
				return codedError{code: exitSecurityRefusal, err: fmt.Errorf("rollback requires --yes after reviewing backup path")}
			}
			targetPath := opts.userSSHConfig
			if inferred, ok := config.OriginalPathFromBackup(args[0]); ok {
				targetPath = inferred
			}
			return config.RestoreBackup(targetPath, args[0])
		},
	})
	return cmd
}

func wslCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "wsl", Short: "WSL diagnostics and scoped bridge controls"}
	modeA := &cobra.Command{Use: "mode-a", Short: "WSL Mode A using Windows ssh.exe"}
	modeA.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Run passive WSL Mode A diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			return output(opts, platform.Detect(cmd.Context(), nil))
		},
	})
	modeA.AddCommand(&cobra.Command{
		Use:   "configure-git",
		Short: "Configure WSL Git to use Windows ssh.exe after explicit confirmation",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := platform.ConfigureGitModeA(cmd.Context(), openssh.ExecRunner{}, opts.yes && !opts.dryRun)
			if err != nil {
				return err
			}
			if !result.Executed {
				if err := output(opts, result); err != nil {
					return err
				}
				if !opts.dryRun {
					fmt.Print("refusing global git config mutation without --yes; rerun with --dry-run first, then --yes\n")
				}
				return nil
			}
			return output(opts, result)
		},
	})
	bridgeCmd := &cobra.Command{Use: "bridge", Short: "WSL Mode B bridge controls"}
	bridgeCmd.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Start a configured WSL bridge in the foreground",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			name := opts.bridgeName
			if name == "" && len(cfg.Bridges) == 1 {
				for key := range cfg.Bridges {
					name = key
				}
			}
			if name == "" {
				return codedError{code: exitSecurityRefusal, err: fmt.Errorf("bridge name required via --bridge")}
			}
			req, err := launcher.BridgeRequest(cfg, name, opts.bridgeRuntimeDir)
			if err != nil {
				return codedError{code: exitSecurityRefusal, err: err}
			}
			signalCtx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			server, state, err := bridge.Start(signalCtx, req)
			if err != nil {
				return codedError{code: exitSecurityRefusal, err: err}
			}
			defer func() {
				_ = server.Stop()
			}()
			if err := output(opts, state); err != nil {
				return err
			}
			<-signalCtx.Done()
			return nil
		},
	})
	bridgeCmd.PersistentFlags().StringVar(&opts.bridgeName, "bridge", "", "bridge name")
	bridgeCmd.PersistentFlags().StringVar(&opts.bridgeRuntimeDir, "bridge-runtime-dir", "", "bridge runtime directory; must be private")
	bridgeCmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check WSL bridge runtime directory permissions",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := os.Getenv("XDG_RUNTIME_DIR")
			if dir == "" {
				dir = os.TempDir()
			}
			err := bridge.DoctorRuntimeDir(dir)
			return output(opts, map[string]any{"runtime_dir": dir, "valid": err == nil, "error": errString(err)})
		},
	})
	cmd.AddCommand(modeA, bridgeCmd)
	return cmd
}

func bridgeCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "bridge", Short: "Container bridge snippets and safety checks"}
	cmd.AddCommand(&cobra.Command{
		Use:   "container",
		Short: "Print explicit container SSH_AUTH_SOCK mount snippet",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(platform.ContainerSnippet(os.Getenv("SSH_AUTH_SOCK")))
			fmt.Print("# Agent sockets are credential delegation; mount only for trusted containers.\n")
			return nil
		},
	})
	return cmd
}

func transportCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "transport", Short: "External transport helpers"}
	addOpts := &transportAddOptions{transportType: "proxy_command"}
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add an external transport template to Heimdall config",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			result, err := addTransport(cfg, config.ResolvePath(opts.configPath), args[0], *addOpts, shouldApplyMutation(opts))
			if err != nil {
				return err
			}
			result.Refused = mutationRefused(opts)
			return outputTransportAdd(opts, result)
		},
	}
	add.Flags().StringVar(&addOpts.transportType, "type", "proxy_command", "transport type: proxy_command")
	add.Flags().StringVar(&addOpts.binary, "binary", "", "transport binary for proxy_command")
	add.Flags().StringArrayVar(&addOpts.args, "arg", nil, "transport argument; repeat for each argv entry")
	cmd.AddCommand(add)
	cmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Run transport diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			report, err := doctor.Engine{}.Run(context.Background(), cfg, doctor.Options{})
			if err != nil {
				return err
			}
			return output(opts, report)
		},
	})
	return cmd
}

type transportAddOptions struct {
	transportType string
	binary        string
	args          []string
}

type transportAddResult struct {
	ConfigPath string `json:"config_path" yaml:"config_path"`
	Transport  string `json:"transport" yaml:"transport"`
	DryRun     bool   `json:"dry_run" yaml:"dry_run"`
	BackupPath string `json:"backup_path,omitempty" yaml:"backup_path,omitempty"`
	Refused    bool   `json:"refused,omitempty" yaml:"refused,omitempty"`
	Snippet    string `json:"snippet" yaml:"snippet"`
}

func addTransport(cfg model.Config, configPath, name string, opts transportAddOptions, apply bool) (transportAddResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return transportAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("transport name cannot be empty")}
	}
	transportType := strings.TrimSpace(opts.transportType)
	if transportType == "" {
		transportType = "proxy_command"
	}
	if transportType != "proxy_command" {
		return transportAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--type must be proxy_command")}
	}
	binary := strings.TrimSpace(opts.binary)
	if binary == "" {
		return transportAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--binary is required for proxy_command transports")}
	}
	if hasInvalidConfigValue(binary) {
		return transportAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--binary contains invalid control characters")}
	}
	args := make([]string, 0, len(opts.args))
	for i, arg := range opts.args {
		if arg == "" {
			return transportAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--arg #%d cannot be empty", i+1)}
		}
		if hasInvalidConfigValue(arg) {
			return transportAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("--arg #%d contains invalid control characters", i+1)}
		}
		args = append(args, arg)
	}

	cfg = config.Normalize(cfg)
	if _, exists := cfg.Transports[name]; exists {
		return transportAddResult{}, codedError{code: exitConfigInvalid, err: fmt.Errorf("transport %q already exists", name)}
	}
	tr := model.ExternalTransport{Type: transportType, Binary: binary, Args: args}
	cfg.Transports[name] = tr
	if err := config.Validate(cfg); err != nil {
		return transportAddResult{}, err
	}
	backupPath := ""
	if apply {
		var err error
		backupPath, err = config.SaveWithBackup(configPath, cfg)
		if err != nil {
			return transportAddResult{}, err
		}
	}
	snippet, err := transportSnippet(name, tr)
	if err != nil {
		return transportAddResult{}, err
	}
	return transportAddResult{
		ConfigPath: configPath,
		Transport:  name,
		DryRun:     !apply,
		BackupPath: backupPath,
		Snippet:    snippet,
	}, nil
}

type transportSnippetConfig struct {
	Transports map[string]model.ExternalTransport `yaml:"transports"`
}

func transportSnippet(name string, tr model.ExternalTransport) (string, error) {
	data, err := yaml.Marshal(transportSnippetConfig{Transports: map[string]model.ExternalTransport{name: tr}})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func outputTransportAdd(opts *options, result transportAddResult) error {
	if outputFormat(opts) == "json" || outputFormat(opts) == "yaml" {
		return output(opts, result)
	}
	var b strings.Builder
	if result.DryRun {
		b.WriteString("dry run; no config changes written\n")
	} else {
		b.WriteString("updated " + result.ConfigPath + "\n")
		if result.BackupPath != "" {
			b.WriteString("backup: " + result.BackupPath + "\n")
		}
	}
	b.WriteString(result.Snippet)
	if result.Refused {
		b.WriteString("refusing config mutation without --yes; rerun with --dry-run first, then --yes\n")
	}
	level := redactionLevel(opts)
	fmt.Print(redact.String(b.String(), level))
	return nil
}

func certsCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certs",
		Short: "Inspect configured SSH certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			inv, err := inventory.Scanner{}.Scan(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			return output(opts, inv.Certificates)
		},
	}
	refresh := &cobra.Command{
		Use:   "refresh <name>",
		Short: "Preview or explicitly execute a configured certificate refresh hook",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			ref, ok := cfg.Certificates[args[0]]
			if !ok {
				return codedError{code: exitConfigInvalid, err: fmt.Errorf("unknown certificate %q", args[0])}
			}
			result, err := certs.Refresh(cmd.Context(), openssh.ExecRunner{}, args[0], ref, opts.execute)
			if err != nil {
				return err
			}
			return output(opts, result)
		},
	}
	refresh.Flags().BoolVar(&opts.execute, "execute", false, "execute the refresh hook; default previews only")
	cmd.AddCommand(refresh)
	return cmd
}

type versionInfo struct {
	Version string `json:"version" yaml:"version"`
	Commit  string `json:"commit,omitempty" yaml:"commit,omitempty"`
	Date    string `json:"date,omitempty" yaml:"date,omitempty"`
	Dirty   bool   `json:"dirty,omitempty" yaml:"dirty,omitempty"`
}

func versionCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Heimdall version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := currentVersionInfo()
			if outputFormat(opts) == "human" {
				fmt.Println(versionString(info))
				return nil
			}
			return output(opts, info)
		},
	}
}

func tuiCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the Heimdall TUI dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			return tui.Run(cmd.Context(), cfg)
		},
	}
}

func completionCommand(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Generate shell completions",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "bash",
		Short: "Generate bash completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenBashCompletion(os.Stdout)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "zsh",
		Short: "Generate zsh completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenZshCompletion(os.Stdout)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "fish",
		Short: "Generate fish completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenFishCompletion(os.Stdout, true)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "powershell",
		Short: "Generate PowerShell completion",
		RunE: func(cmd *cobra.Command, args []string) error {
			return root.GenPowerShellCompletion(os.Stdout)
		},
	})
	return cmd
}

func formatHuman(value any) string {
	switch v := value.(type) {
	case doctor.Report:
		var b strings.Builder
		b.WriteString("Heimdall doctor\n")
		for _, f := range v.Findings {
			b.WriteString(fmt.Sprintf("[%s] %s %s\n", f.Severity, f.ID, f.Title))
			for _, e := range f.Evidence {
				b.WriteString("  evidence: " + e + "\n")
			}
			if f.Risk != "" {
				b.WriteString("  risk: " + f.Risk + "\n")
			}
			if f.SuggestedFix != "" {
				b.WriteString("  fix: " + f.SuggestedFix + "\n")
			}
		}
		if len(v.Findings) == 0 {
			b.WriteString("no findings\n")
		}
		return b.String()
	default:
		data, _ := json.MarshalIndent(value, "", "  ")
		return string(data) + "\n"
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func outputFormat(opts *options) string {
	if opts.json {
		return "json"
	}
	return opts.format
}

func validateOutputFlags(cmd *cobra.Command, opts *options) error {
	if opts.json && cmd.Root().PersistentFlags().Changed("format") && opts.format != "json" {
		return fmt.Errorf("conflicting output format flags: --json and --format=%s", opts.format)
	}
	return nil
}

func redactionLevel(opts *options) redact.Level {
	if opts.unsafeFullOutput {
		return redact.Low
	}
	if opts.redact {
		return redact.High
	}
	return redact.Level(opts.redaction)
}

func doctorFailOnWarning(opts *options) bool {
	return opts.strict || opts.failOn == "warning"
}

func currentVersionInfo() versionInfo {
	info := versionInfo{Version: Version, Commit: Commit, Date: Date}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "" || info.Version == "dev" {
			if buildInfo.Main.Version != "" && buildInfo.Main.Version != "(devel)" {
				info.Version = buildInfo.Main.Version
			}
		}
		for _, setting := range buildInfo.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = setting.Value
				}
			case "vcs.modified":
				info.Dirty = setting.Value == "true"
			}
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
}

func versionString(info versionInfo) string {
	var b strings.Builder
	b.WriteString("heimdall ")
	b.WriteString(info.Version)
	if info.Commit != "" {
		commit := info.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		b.WriteString(" ")
		b.WriteString(commit)
	}
	if info.Date != "" {
		b.WriteString(" ")
		b.WriteString(info.Date)
	}
	if info.Dirty {
		b.WriteString(" dirty")
	}
	return b.String()
}

func shouldApplyMutation(opts *options) bool {
	return opts.yes && !opts.dryRun
}

func mutationRefused(opts *options) bool {
	return !opts.yes && !opts.dryRun
}

func hasInvalidConfigValue(value string) bool {
	return strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\n\r")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
