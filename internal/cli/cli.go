package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
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

type options struct {
	configPath       string
	format           string
	dryRun           bool
	verbose          bool
	noColor          bool
	redaction        string
	unsafeFullOutput bool
	yes              bool
	fragmentPath     string
	userSSHConfig    string
	activeProbe      bool
	failOn           string
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
	root := &cobra.Command{
		Use:   "heimdall",
		Short: "Local-first SSH identity control plane",
		Long:  "Heimdall inventories SSH identities and agents, renders managed OpenSSH config, diagnoses routing failures, and launches scoped SSH-aware commands without private-key custody.",
	}
	root.PersistentFlags().StringVar(&opts.configPath, "config", "", "Heimdall config path")
	root.PersistentFlags().StringVar(&opts.format, "format", "human", "output format: human, json, yaml")
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
	level := redact.Level(opts.redaction)
	if opts.unsafeFullOutput {
		level = redact.Low
	}
	switch opts.format {
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
		Use:   "doctor",
		Short: "Diagnose SSH identity, agent, config, platform, certificate, and transport routing",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			report, err := doctor.Engine{}.Run(cmd.Context(), cfg, doctor.Options{
				ConfigPath: opts.configPath, FragmentPath: opts.fragmentPath, UserSSHConfig: opts.userSSHConfig,
				ActiveProbe: opts.activeProbe, FailOnWarning: opts.failOn == "warning",
			})
			if err != nil {
				return err
			}
			if err := output(opts, report); err != nil {
				return err
			}
			if code := doctor.SeverityExitCode(report.Findings, opts.failOn == "warning"); code != 0 {
				return codedError{code: code, err: fmt.Errorf("doctor reported findings")}
			}
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&opts.fragmentPath, "fragment", config.DefaultSSHFragmentPath(), "managed SSH fragment path")
	cmd.PersistentFlags().StringVar(&opts.userSSHConfig, "ssh-config", config.DefaultUserSSHConfigPath(), "user OpenSSH config path")
	cmd.PersistentFlags().BoolVar(&opts.activeProbe, "active-probe", false, "consent to local active probes such as ssh -G; no auth attempt is made")
	cmd.PersistentFlags().StringVar(&opts.failOn, "fail-on", "", "exit nonzero on severity: warning")
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
	for _, name := range []string{"windows", "wsl", "container", "forwarding", "certs"} {
		localName := name
		cmd.AddCommand(&cobra.Command{
			Use:   localName,
			Short: "Run passive " + localName + " diagnostics",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := loadConfig(opts)
				if err != nil {
					return err
				}
				report, err := doctor.Engine{}.Run(cmd.Context(), cfg, doctor.Options{FragmentPath: opts.fragmentPath, UserSSHConfig: opts.userSSHConfig})
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
	cmd.AddCommand(&cobra.Command{
		Use:   "add",
		Short: "Print a minimal context YAML snippet",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print("contexts:\n  example:\n    identity: example\n    agent: personal\n    forwarding:\n      agent: deny\n")
			return nil
		},
	})
	return cmd
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
		Use:   "doctor",
		Short: "Validate Heimdall config only",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(opts)
			if err != nil {
				return err
			}
			return output(opts, map[string]any{"valid": true, "routes": len(cfg.HostRoutes)})
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
			return openssh.Rollback(opts.userSSHConfig, args[0])
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
	cmd.AddCommand(&cobra.Command{
		Use:   "add",
		Short: "Print a ProxyCommand transport YAML snippet",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print("transports:\n  iroh-ssh:\n    type: proxy_command\n    binary: iroh-ssh\n    args: [\"proxy\", \"%h\"]\n")
			return nil
		},
	})
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
