package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/amanthanvi/heimdall/internal/sshconfig"
	"github.com/amanthanvi/heimdall/internal/storage"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

const defaultManagedSSHConfigPath = "~/.ssh/config.d/heimdall.conf"

func newSSHConfigCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh-config",
		Short: "OpenSSH config utilities",
		Example: "  heimdall ssh-config enable\n" +
			"  heimdall ssh-config sync\n" +
			"  heimdall ssh-config show",
	}
	cmd.AddCommand(
		newSSHConfigEnableCommand(deps),
		newSSHConfigDisableCommand(deps),
		newSSHConfigSyncCommand(deps),
		newSSHConfigDiffCommand(deps),
		newSSHConfigShowCommand(deps),
		newSSHConfigGenerateCommand(deps),
	)
	return cmd
}

func newSSHConfigEnableCommand(deps commandDeps) *cobra.Command {
	var pathOverride string
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable managed ssh-config fragment and sync immediately",
		Example: "  heimdall ssh-config enable\n" +
			"  heimdall ssh-config enable --path ~/.ssh/config.d/heimdall.conf",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("ssh-config enable does not accept positional arguments")
			}
			cfg, configPath, err := loadCLIConfigWithPath(deps.globals)
			if err != nil {
				return mapCommandError(fmt.Errorf("ssh-config enable: %w", err))
			}
			if value := strings.TrimSpace(pathOverride); value != "" {
				cfg.SSHConfig.Path = value
			}
			if strings.TrimSpace(cfg.SSHConfig.Path) == "" {
				cfg.SSHConfig.Path = defaultManagedSSHConfigPath
			}
			cfg.SSHConfig.Enabled = true
			if err := writeConfigFile(configPath, cfg); err != nil {
				return mapCommandError(fmt.Errorf("ssh-config enable: %w", err))
			}

			hostCount, fragmentPath, err := syncManagedSSHConfig(cmd.Context(), deps, cfg)
			if err != nil {
				return err
			}
			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"enabled":       true,
					"path":          fragmentPath,
					"hosts_synced":  hostCount,
					"config_path":   configPath,
					"connectionLog": cfg.Audit.ConnectionLogging,
				})
			}
			if deps.globals.Quiet {
				return nil
			}
			_, err = fmt.Fprintf(deps.out, "ssh-config enabled: %s (hosts=%d)\n", fragmentPath, hostCount)
			return mapCommandError(err)
		},
	}
	cmd.Flags().StringVar(&pathOverride, "path", "", "Managed fragment path")
	return cmd
}

func newSSHConfigDisableCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable managed ssh-config include",
		Example: "  heimdall ssh-config disable\n" +
			"  heimdall --json ssh-config disable",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("ssh-config disable does not accept positional arguments")
			}
			cfg, configPath, err := loadCLIConfigWithPath(deps.globals)
			if err != nil {
				return mapCommandError(fmt.Errorf("ssh-config disable: %w", err))
			}
			_, includePath, err := resolveManagedSSHPaths(cfg.SSHConfig.Path)
			if err != nil {
				return mapCommandError(fmt.Errorf("ssh-config disable: %w", err))
			}
			userConfigPath, err := defaultUserSSHConfigPath()
			if err != nil {
				return mapCommandError(fmt.Errorf("ssh-config disable: %w", err))
			}
			if err := sshconfig.RemoveInclude(userConfigPath, includePath); err != nil {
				return mapCommandError(fmt.Errorf("ssh-config disable: %w", err))
			}
			cfg.SSHConfig.Enabled = false
			if err := writeConfigFile(configPath, cfg); err != nil {
				return mapCommandError(fmt.Errorf("ssh-config disable: %w", err))
			}

			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"enabled":     false,
					"config_path": configPath,
				})
			}
			if deps.globals.Quiet {
				return nil
			}
			_, err = fmt.Fprintln(deps.out, "ssh-config disabled")
			return mapCommandError(err)
		},
	}
	return cmd
}

func newSSHConfigSyncCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync managed ssh-config fragment to disk",
		Example: "  heimdall ssh-config sync\n" +
			"  heimdall --json ssh-config sync",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("ssh-config sync does not accept positional arguments")
			}
			cfg, _, err := loadCLIConfigWithPath(deps.globals)
			if err != nil {
				return mapCommandError(fmt.Errorf("ssh-config sync: %w", err))
			}
			if !cfg.SSHConfig.Enabled {
				return usageErrorf("ssh-config sync requires ssh-config to be enabled; run `heimdall ssh-config enable`")
			}
			hostCount, fragmentPath, err := syncManagedSSHConfig(cmd.Context(), deps, cfg)
			if err != nil {
				return err
			}
			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"path":         fragmentPath,
					"hosts_synced": hostCount,
				})
			}
			if deps.globals.Quiet {
				return nil
			}
			_, err = fmt.Fprintf(deps.out, "ssh-config synced: %s (hosts=%d)\n", fragmentPath, hostCount)
			return mapCommandError(err)
		},
	}
	return cmd
}

func newSSHConfigDiffCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show drift between managed fragment and desired state",
		Example: "  heimdall ssh-config diff\n" +
			"  heimdall --json ssh-config diff",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("ssh-config diff does not accept positional arguments")
			}
			cfg, _, err := loadCLIConfigWithPath(deps.globals)
			if err != nil {
				return mapCommandError(fmt.Errorf("ssh-config diff: %w", err))
			}
			desired, hostCount, err := desiredSSHConfigFragment(cmd.Context(), deps)
			if err != nil {
				return err
			}
			fragmentPath, _, err := resolveManagedSSHPaths(cfg.SSHConfig.Path)
			if err != nil {
				return mapCommandError(fmt.Errorf("ssh-config diff: %w", err))
			}

			current, readErr := os.ReadFile(fragmentPath)
			currentExists := readErr == nil
			if readErr != nil && !os.IsNotExist(readErr) {
				return mapCommandError(fmt.Errorf("ssh-config diff: read fragment: %w", readErr))
			}
			changed := string(current) != desired
			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"changed":        changed,
					"path":           fragmentPath,
					"hosts":          hostCount,
					"current_exists": currentExists,
				})
			}
			if deps.globals.Quiet {
				return nil
			}
			if !changed {
				_, err := fmt.Fprintf(deps.out, "ssh-config up-to-date: %s\n", fragmentPath)
				return mapCommandError(err)
			}
			if _, err := fmt.Fprintf(deps.out, "ssh-config differs: %s\n", fragmentPath); err != nil {
				return mapCommandError(err)
			}
			diff := renderSimpleDiff(string(current), desired)
			_, err = fmt.Fprint(deps.out, diff)
			return mapCommandError(err)
		},
	}
	return cmd
}

func newSSHConfigShowCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show managed ssh-config fragment content",
		Example: "  heimdall ssh-config show\n" +
			"  heimdall --json ssh-config show",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("ssh-config show does not accept positional arguments")
			}
			rendered, hostCount, err := desiredSSHConfigFragment(cmd.Context(), deps)
			if err != nil {
				return err
			}
			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"hosts":    hostCount,
					"fragment": rendered,
				})
			}
			if deps.globals.Quiet {
				return nil
			}
			if _, err := fmt.Fprint(deps.out, rendered); err != nil {
				return mapCommandError(err)
			}
			if rendered == "" {
				_, err := fmt.Fprintln(deps.out)
				return mapCommandError(err)
			}
			return nil
		},
	}
	return cmd
}

func newSSHConfigGenerateCommand(deps commandDeps) *cobra.Command {
	var outputPath string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate OpenSSH config blocks from vault hosts",
		Example: "  heimdall ssh-config generate --output ~/.ssh/heimdall_hosts\n" +
			"  heimdall --json ssh-config generate --output ./ssh_config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("ssh-config generate does not accept positional arguments")
			}
			if strings.TrimSpace(outputPath) == "" {
				return usageErrorf("ssh-config generate requires --output")
			}
			rendered, hostCount, err := desiredSSHConfigFragment(cmd.Context(), deps)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
				return mapCommandError(err)
			}
			if err := os.WriteFile(outputPath, []byte(rendered), 0o600); err != nil {
				return mapCommandError(err)
			}
			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"output": outputPath,
					"hosts":  hostCount,
				})
			}
			if deps.globals.Quiet {
				return nil
			}
			_, err = fmt.Fprintf(deps.out, "ssh-config written: %s (hosts=%d)\n", outputPath, hostCount)
			return mapCommandError(err)
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "Output path for generated OpenSSH config")
	return cmd
}

func desiredSSHConfigFragment(ctx context.Context, deps commandDeps) (string, int, error) {
	hosts, err := collectSSHConfigHosts(ctx, deps)
	if err != nil {
		return "", 0, err
	}
	return sshconfig.Generate(hosts), len(hosts), nil
}

func collectSSHConfigHosts(ctx context.Context, deps commandDeps) ([]storage.Host, error) {
	var hosts []storage.Host
	err := withDaemonClients(ctx, deps, func(ctx context.Context, clients daemonClients) error {
		resp, err := clients.host.ListHosts(ctx, &v1.ListHostsRequest{})
		if err != nil {
			return err
		}
		hosts = protoHostsToStorage(resp.GetHosts())
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

func protoHostsToStorage(hosts []*v1.Host) []storage.Host {
	items := make([]storage.Host, 0, len(hosts))
	for _, host := range hosts {
		items = append(items, storage.Host{
			ID:           host.GetId(),
			Name:         host.GetName(),
			Address:      host.GetAddress(),
			Port:         int(host.GetPort()),
			User:         host.GetUser(),
			ProxyJump:    host.GetEnvRefs()["proxy_jump"],
			IdentityFile: host.GetEnvRefs()["identity_ref"],
			EnvRefs:      cloneMap(host.GetEnvRefs()),
			Tags:         append([]string(nil), host.GetTags()...),
		})
	}
	return items
}

func syncManagedSSHConfig(ctx context.Context, deps commandDeps, cfg config.Config) (int, string, error) {
	rendered, hostCount, err := desiredSSHConfigFragment(ctx, deps)
	if err != nil {
		return 0, "", err
	}
	fragmentPath, includePath, err := resolveManagedSSHPaths(cfg.SSHConfig.Path)
	if err != nil {
		return 0, "", mapCommandError(err)
	}
	if err := os.MkdirAll(filepath.Dir(fragmentPath), 0o700); err != nil {
		return 0, "", mapCommandError(fmt.Errorf("ssh-config sync: create fragment directory: %w", err))
	}
	if err := os.WriteFile(fragmentPath, []byte(rendered), 0o600); err != nil {
		return 0, "", mapCommandError(fmt.Errorf("ssh-config sync: write fragment: %w", err))
	}
	userConfigPath, err := defaultUserSSHConfigPath()
	if err != nil {
		return 0, "", mapCommandError(err)
	}
	if err := sshconfig.EnsureInclude(userConfigPath, includePath); err != nil {
		return 0, "", mapCommandError(err)
	}
	return hostCount, fragmentPath, nil
}

func loadCLIConfigWithPath(globals *GlobalOptions) (config.Config, string, error) {
	loadOpts := config.LoadOptions{}
	if globals != nil {
		if configPath := strings.TrimSpace(globals.ConfigPath); configPath != "" {
			loadOpts.ConfigPath = configPath
		}
		if vaultPath := strings.TrimSpace(globals.VaultPath); vaultPath != "" {
			loadOpts.Env = map[string]string{
				"HEIMDALL_VAULT_PATH": vaultPath,
			}
		}
	}
	cfg, _, err := loadConfigFn(loadOpts)
	if err != nil {
		return config.Config{}, "", fmt.Errorf("load config: %w", err)
	}
	configPath, err := resolveConfigPath(globals)
	if err != nil {
		return config.Config{}, "", err
	}
	return cfg, configPath, nil
}

func writeConfigFile(path string, cfg config.Config) error {
	payload, err := marshalConfig(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("write config: create directory: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func marshalConfig(cfg config.Config) ([]byte, error) {
	type vault struct {
		AutoLockTimeout string `toml:"auto_lock_timeout"`
	}
	type ssh struct {
		KnownHostsPolicyDefault string `toml:"known_hosts_policy_default"`
		ForwardAgentDefault     bool   `toml:"forward_agent_default"`
		ConnectTimeout          string `toml:"connect_timeout"`
	}
	type sshManaged struct {
		Enabled  bool   `toml:"enabled"`
		Path     string `toml:"path"`
		AutoSync bool   `toml:"auto_sync"`
	}
	type audit struct {
		ConnectionLogging bool `toml:"connection_logging"`
	}
	type passkey struct {
		UVDefault string `toml:"uv_default"`
	}
	type daemonCfg struct {
		MaxSessionDuration string `toml:"max_session_duration"`
		SocketDir          string `toml:"socket_dir"`
	}
	type logging struct {
		Level     string `toml:"level"`
		File      string `toml:"file"`
		MaxSizeMB int    `toml:"max_size_mb"`
		MaxFiles  int    `toml:"max_files"`
	}
	type telemetry struct {
		Enabled bool `toml:"enabled"`
	}
	type fileConfig struct {
		Vault     vault      `toml:"vault"`
		SSH       ssh        `toml:"ssh"`
		SSHConfig sshManaged `toml:"ssh_config"`
		Audit     audit      `toml:"audit"`
		Passkey   passkey    `toml:"passkey"`
		Daemon    daemonCfg  `toml:"daemon"`
		Logging   logging    `toml:"logging"`
		Telemetry telemetry  `toml:"telemetry"`
	}

	if strings.TrimSpace(cfg.SSHConfig.Path) == "" {
		cfg.SSHConfig.Path = defaultManagedSSHConfigPath
	}
	doc := fileConfig{
		Vault: vault{
			AutoLockTimeout: cfg.Vault.AutoLockTimeout.String(),
		},
		SSH: ssh{
			KnownHostsPolicyDefault: cfg.SSH.KnownHostsPolicyDefault,
			ForwardAgentDefault:     cfg.SSH.ForwardAgentDefault,
			ConnectTimeout:          cfg.SSH.ConnectTimeout.String(),
		},
		SSHConfig: sshManaged{
			Enabled:  cfg.SSHConfig.Enabled,
			Path:     cfg.SSHConfig.Path,
			AutoSync: cfg.SSHConfig.AutoSync,
		},
		Audit: audit{
			ConnectionLogging: cfg.Audit.ConnectionLogging,
		},
		Passkey: passkey{
			UVDefault: cfg.Passkey.UVDefault,
		},
		Daemon: daemonCfg{
			MaxSessionDuration: cfg.Daemon.MaxSessionDuration.String(),
			SocketDir:          cfg.Daemon.SocketDir,
		},
		Logging: logging{
			Level:     cfg.Logging.Level,
			File:      cfg.Logging.File,
			MaxSizeMB: cfg.Logging.MaxSizeMB,
			MaxFiles:  cfg.Logging.MaxFiles,
		},
		Telemetry: telemetry{
			Enabled: cfg.Telemetry.Enabled,
		},
	}
	return toml.Marshal(doc)
}

func resolveManagedSSHPaths(configPath string) (string, string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = defaultManagedSSHConfigPath
	}
	fragmentPath, err := expandHomePath(configPath)
	if err != nil {
		return "", "", err
	}
	includePath, err := compactHomePath(fragmentPath)
	if err != nil {
		return "", "", err
	}
	return fragmentPath, includePath, nil
}

func expandHomePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("expand path: path is required")
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand path: resolve user home: %w", err)
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func compactHomePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("compact path: path is required")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("compact path: resolve user home: %w", err)
	}
	home = filepath.Clean(home)
	path = filepath.Clean(path)
	if path == home {
		return "~", nil
	}
	prefix := home + string(os.PathSeparator)
	if strings.HasPrefix(path, prefix) {
		return "~/" + strings.TrimPrefix(path, prefix), nil
	}
	return path, nil
}

func defaultUserSSHConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

func renderSimpleDiff(current, desired string) string {
	currentLines := splitDiffLines(current)
	desiredLines := splitDiffLines(desired)
	maxLen := len(currentLines)
	if len(desiredLines) > maxLen {
		maxLen = len(desiredLines)
	}
	var builder strings.Builder
	builder.WriteString("--- current\n")
	builder.WriteString("+++ desired\n")
	for idx := 0; idx < maxLen; idx++ {
		var left, right string
		if idx < len(currentLines) {
			left = currentLines[idx]
		}
		if idx < len(desiredLines) {
			right = desiredLines[idx]
		}
		if left == right {
			continue
		}
		if left != "" {
			builder.WriteString("- ")
			builder.WriteString(left)
			builder.WriteByte('\n')
		}
		if right != "" {
			builder.WriteString("+ ")
			builder.WriteString(right)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func splitDiffLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimSuffix(content, "\n")
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

func parseCreatedAt(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, trimmed)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
