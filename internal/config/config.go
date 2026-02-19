package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

const (
	defaultAutoLockTimeout  = 30 * time.Minute
	defaultConnectTimeout   = 10 * time.Second
	defaultSessionDuration  = 8 * time.Hour
	defaultLogLevel         = "info"
	defaultLogMaxSizeMB     = 10
	defaultLogMaxFiles      = 5
	defaultKnownHostsPolicy = "tofu"
	defaultPasskeyUV        = "preferred"
)

var ErrInvalidConfig = errors.New("invalid config")

type Config struct {
	Vault     VaultConfig     `toml:"vault"`
	SSH       SSHConfig       `toml:"ssh"`
	Passkey   PasskeyConfig   `toml:"passkey"`
	Daemon    DaemonConfig    `toml:"daemon"`
	Logging   LoggingConfig   `toml:"logging"`
	Telemetry TelemetryConfig `toml:"telemetry"`
}

type VaultConfig struct {
	AutoLockTimeout time.Duration `toml:"auto_lock_timeout"`
}

type SSHConfig struct {
	KnownHostsPolicyDefault string        `toml:"known_hosts_policy_default"`
	ForwardAgentDefault     bool          `toml:"forward_agent_default"`
	ConnectTimeout          time.Duration `toml:"connect_timeout"`
}

type PasskeyConfig struct {
	UVDefault string `toml:"uv_default"`
}

type DaemonConfig struct {
	MaxSessionDuration time.Duration `toml:"max_session_duration"`
	SocketDir          string        `toml:"socket_dir"`
}

type LoggingConfig struct {
	Level     string `toml:"level"`
	File      string `toml:"file"`
	MaxSizeMB int    `toml:"max_size_mb"`
	MaxFiles  int    `toml:"max_files"`
}

type TelemetryConfig struct {
	Enabled bool `toml:"enabled"`
}

type LoadOptions struct {
	ConfigPath string
	PolicyPath string
	Env        map[string]string
	Flags      FlagOverrides
}

type FlagOverrides struct {
	VaultAutoLockTimeout *time.Duration
}

type LoadReport struct {
	PolicyOverrides []string
}

func DefaultConfig() Config {
	return Config{
		Vault: VaultConfig{
			AutoLockTimeout: defaultAutoLockTimeout,
		},
		SSH: SSHConfig{
			KnownHostsPolicyDefault: defaultKnownHostsPolicy,
			ForwardAgentDefault:     false,
			ConnectTimeout:          defaultConnectTimeout,
		},
		Passkey: PasskeyConfig{
			UVDefault: defaultPasskeyUV,
		},
		Daemon: DaemonConfig{
			MaxSessionDuration: defaultSessionDuration,
			SocketDir:          "",
		},
		Logging: LoggingConfig{
			Level:     defaultLogLevel,
			File:      "",
			MaxSizeMB: defaultLogMaxSizeMB,
			MaxFiles:  defaultLogMaxFiles,
		},
		Telemetry: TelemetryConfig{
			Enabled: false,
		},
	}
}

func Load(opts LoadOptions) (Config, LoadReport, error) {
	cfg := DefaultConfig()
	report := LoadReport{PolicyOverrides: []string{}}

	configPath, err := resolveConfigPath(opts)
	if err != nil {
		return Config{}, report, fmt.Errorf("resolve config path: %w", err)
	}
	if err := loadAndApplyFile(configPath, &cfg, nil); err != nil {
		return Config{}, report, err
	}

	if err := applyEnvOverrides(&cfg, opts); err != nil {
		return Config{}, report, err
	}
	if err := applyFlagOverrides(&cfg, opts.Flags); err != nil {
		return Config{}, report, err
	}

	policyPath, err := resolvePolicyPath(opts)
	if err != nil {
		return Config{}, report, fmt.Errorf("resolve policy path: %w", err)
	}
	if err := loadAndApplyFile(policyPath, &cfg, &report.PolicyOverrides); err != nil {
		return Config{}, report, err
	}

	if err := validate(cfg); err != nil {
		return Config{}, report, err
	}

	return cfg, report, nil
}

type rawConfig struct {
	Vault     *rawVault     `toml:"vault"`
	SSH       *rawSSH       `toml:"ssh"`
	Passkey   *rawPasskey   `toml:"passkey"`
	Daemon    *rawDaemon    `toml:"daemon"`
	Logging   *rawLogging   `toml:"logging"`
	Telemetry *rawTelemetry `toml:"telemetry"`
}

type rawVault struct {
	AutoLockTimeout *string `toml:"auto_lock_timeout"`
}

type rawSSH struct {
	KnownHostsPolicyDefault *string `toml:"known_hosts_policy_default"`
	ForwardAgentDefault     *bool   `toml:"forward_agent_default"`
	ConnectTimeout          *string `toml:"connect_timeout"`
}

type rawPasskey struct {
	UVDefault *string `toml:"uv_default"`
}

type rawDaemon struct {
	MaxSessionDuration *string `toml:"max_session_duration"`
	SocketDir          *string `toml:"socket_dir"`
}

type rawLogging struct {
	Level     *string `toml:"level"`
	File      *string `toml:"file"`
	MaxSizeMB *int    `toml:"max_size_mb"`
	MaxFiles  *int    `toml:"max_files"`
}

type rawTelemetry struct {
	Enabled *bool `toml:"enabled"`
}

func loadAndApplyFile(path string, cfg *Config, policyOverrides *[]string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config file %q: %w", path, err)
	}

	var raw rawConfig
	if err := toml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: parse TOML file %q: %v", ErrInvalidConfig, path, err)
	}

	if err := applyRawConfig(cfg, raw, policyOverrides); err != nil {
		return err
	}
	return nil
}

func applyRawConfig(cfg *Config, raw rawConfig, policyOverrides *[]string) error {
	if raw.Vault != nil {
		if err := setDuration("vault.auto_lock_timeout", raw.Vault.AutoLockTimeout, &cfg.Vault.AutoLockTimeout, policyOverrides); err != nil {
			return err
		}
	}

	if raw.SSH != nil {
		setString("ssh.known_hosts_policy_default", raw.SSH.KnownHostsPolicyDefault, &cfg.SSH.KnownHostsPolicyDefault, policyOverrides)
		setBool("ssh.forward_agent_default", raw.SSH.ForwardAgentDefault, &cfg.SSH.ForwardAgentDefault, policyOverrides)
		if err := setDuration("ssh.connect_timeout", raw.SSH.ConnectTimeout, &cfg.SSH.ConnectTimeout, policyOverrides); err != nil {
			return err
		}
	}

	if raw.Passkey != nil {
		setString("passkey.uv_default", raw.Passkey.UVDefault, &cfg.Passkey.UVDefault, policyOverrides)
	}

	if raw.Daemon != nil {
		if err := setDuration("daemon.max_session_duration", raw.Daemon.MaxSessionDuration, &cfg.Daemon.MaxSessionDuration, policyOverrides); err != nil {
			return err
		}
		setString("daemon.socket_dir", raw.Daemon.SocketDir, &cfg.Daemon.SocketDir, policyOverrides)
	}

	if raw.Logging != nil {
		setString("logging.level", raw.Logging.Level, &cfg.Logging.Level, policyOverrides)
		setString("logging.file", raw.Logging.File, &cfg.Logging.File, policyOverrides)
		setInt("logging.max_size_mb", raw.Logging.MaxSizeMB, &cfg.Logging.MaxSizeMB, policyOverrides)
		setInt("logging.max_files", raw.Logging.MaxFiles, &cfg.Logging.MaxFiles, policyOverrides)
	}

	if raw.Telemetry != nil {
		setBool("telemetry.enabled", raw.Telemetry.Enabled, &cfg.Telemetry.Enabled, policyOverrides)
	}

	return nil
}

func applyEnvOverrides(cfg *Config, opts LoadOptions) error {
	if value, ok := lookupEnv(opts, "HEIMDALL_VAULT_AUTO_LOCK_TIMEOUT"); ok {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%w: parse HEIMDALL_VAULT_AUTO_LOCK_TIMEOUT: %v", ErrInvalidConfig, err)
		}
		cfg.Vault.AutoLockTimeout = d
	}

	if value, ok := lookupEnv(opts, "HEIMDALL_SSH_KNOWN_HOSTS_POLICY_DEFAULT"); ok {
		cfg.SSH.KnownHostsPolicyDefault = value
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_SSH_FORWARD_AGENT_DEFAULT"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%w: parse HEIMDALL_SSH_FORWARD_AGENT_DEFAULT: %v", ErrInvalidConfig, err)
		}
		cfg.SSH.ForwardAgentDefault = parsed
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_SSH_CONNECT_TIMEOUT"); ok {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%w: parse HEIMDALL_SSH_CONNECT_TIMEOUT: %v", ErrInvalidConfig, err)
		}
		cfg.SSH.ConnectTimeout = d
	}

	if value, ok := lookupEnv(opts, "HEIMDALL_PASSKEY_UV_DEFAULT"); ok {
		cfg.Passkey.UVDefault = value
	}

	if value, ok := lookupEnv(opts, "HEIMDALL_DAEMON_MAX_SESSION_DURATION"); ok {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%w: parse HEIMDALL_DAEMON_MAX_SESSION_DURATION: %v", ErrInvalidConfig, err)
		}
		cfg.Daemon.MaxSessionDuration = d
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_DAEMON_SOCKET_DIR"); ok {
		cfg.Daemon.SocketDir = value
	}

	if value, ok := lookupEnv(opts, "HEIMDALL_LOG_LEVEL"); ok {
		cfg.Logging.Level = value
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_LOG_FILE"); ok {
		cfg.Logging.File = value
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_LOG_MAX_SIZE_MB"); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: parse HEIMDALL_LOG_MAX_SIZE_MB: %v", ErrInvalidConfig, err)
		}
		cfg.Logging.MaxSizeMB = parsed
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_LOG_MAX_FILES"); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: parse HEIMDALL_LOG_MAX_FILES: %v", ErrInvalidConfig, err)
		}
		cfg.Logging.MaxFiles = parsed
	}

	if value, ok := lookupEnv(opts, "HEIMDALL_TELEMETRY_ENABLED"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%w: parse HEIMDALL_TELEMETRY_ENABLED: %v", ErrInvalidConfig, err)
		}
		cfg.Telemetry.Enabled = parsed
	}

	return nil
}

func applyFlagOverrides(cfg *Config, flags FlagOverrides) error {
	if flags.VaultAutoLockTimeout != nil {
		cfg.Vault.AutoLockTimeout = *flags.VaultAutoLockTimeout
	}
	return nil
}

func validate(cfg Config) error {
	if cfg.Vault.AutoLockTimeout <= 0 || cfg.Vault.AutoLockTimeout > 24*time.Hour {
		return fmt.Errorf("%w: vault.auto_lock_timeout must be > 0 and <= 24h", ErrInvalidConfig)
	}
	return nil
}

func setDuration(field string, raw *string, target *time.Duration, policyOverrides *[]string) error {
	if raw == nil {
		return nil
	}
	d, err := time.ParseDuration(*raw)
	if err != nil {
		return fmt.Errorf("%w: parse %s: %v", ErrInvalidConfig, field, err)
	}
	if policyOverrides != nil && *target != d {
		*policyOverrides = append(*policyOverrides, field)
	}
	*target = d
	return nil
}

func setString(field string, raw *string, target *string, policyOverrides *[]string) {
	if raw == nil {
		return
	}
	if policyOverrides != nil && *target != *raw {
		*policyOverrides = append(*policyOverrides, field)
	}
	*target = *raw
}

func setBool(field string, raw *bool, target *bool, policyOverrides *[]string) {
	if raw == nil {
		return
	}
	if policyOverrides != nil && *target != *raw {
		*policyOverrides = append(*policyOverrides, field)
	}
	*target = *raw
}

func setInt(field string, raw *int, target *int, policyOverrides *[]string) {
	if raw == nil {
		return
	}
	if policyOverrides != nil && *target != *raw {
		*policyOverrides = append(*policyOverrides, field)
	}
	*target = *raw
}

func resolveConfigPath(opts LoadOptions) (string, error) {
	if opts.ConfigPath != "" {
		return opts.ConfigPath, nil
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_CONFIG_PATH"); ok {
		return value, nil
	}
	return defaultConfigPath()
}

func resolvePolicyPath(opts LoadOptions) (string, error) {
	if opts.PolicyPath != "" {
		return opts.PolicyPath, nil
	}
	if value, ok := lookupEnv(opts, "HEIMDALL_POLICY_FILE"); ok {
		return value, nil
	}
	home, err := heimdallHome(opts)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "policy.toml"), nil
}

func lookupEnv(opts LoadOptions, key string) (string, bool) {
	if opts.Env != nil {
		if value, ok := opts.Env[key]; ok {
			return value, true
		}
	}
	return os.LookupEnv(key)
}

func heimdallHome(opts LoadOptions) (string, error) {
	if value, ok := lookupEnv(opts, "HEIMDALL_HOME"); ok {
		return value, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}

	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Heimdall"), nil
	}

	dataHome := filepath.Join(home, ".local", "share")
	if xdgDataHome, ok := lookupEnv(opts, "XDG_DATA_HOME"); ok && xdgDataHome != "" {
		dataHome = xdgDataHome
	}
	return filepath.Join(dataHome, "heimdall"), nil
}

func defaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}

	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Heimdall", "config.toml"), nil
	}

	configHome := filepath.Join(home, ".config")
	if xdgConfigHome, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok && xdgConfigHome != "" {
		configHome = xdgConfigHome
	}
	return filepath.Join(configHome, "heimdall", "config.toml"), nil
}
