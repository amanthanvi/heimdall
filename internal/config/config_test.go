package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigPrecedenceFlagOverEnv(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "10m"
`)

	flagTimeout := 5 * time.Minute
	cfg, _, err := Load(LoadOptions{
		ConfigPath: cfgPath,
		Env: map[string]string{
			"HEIMDALL_VAULT_AUTO_LOCK_TIMEOUT": "20m",
		},
		Flags: FlagOverrides{
			VaultAutoLockTimeout: &flagTimeout,
		},
	})
	require.NoError(t, err)
	require.Equal(t, 5*time.Minute, cfg.Vault.AutoLockTimeout)
}

func TestLoadConfigPrecedenceEnvOverFile(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "10m"
`)

	cfg, _, err := Load(LoadOptions{
		ConfigPath: cfgPath,
		Env: map[string]string{
			"HEIMDALL_VAULT_AUTO_LOCK_TIMEOUT": "20m",
		},
	})
	require.NoError(t, err)
	require.Equal(t, 20*time.Minute, cfg.Vault.AutoLockTimeout)
}

func TestLoadConfigPrecedenceFileOverDefault(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "10m"
`)

	cfg, _, err := Load(LoadOptions{
		ConfigPath: cfgPath,
	})
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, cfg.Vault.AutoLockTimeout)
}

func TestLoadConfigFromTOMLParsesAllSupportedFields(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "15m"

[ssh]
known_hosts_policy_default = "strict"
forward_agent_default = true
connect_timeout = "20s"

[passkey]
uv_default = "required"

[daemon]
max_session_duration = "6h"
socket_dir = "/tmp/heimdall.sockdir"

[logging]
level = "debug"
file = "/tmp/heimdall.log"
max_size_mb = 42
max_files = 9

[telemetry]
enabled = true
`)

	cfg, _, err := Load(LoadOptions{
		ConfigPath: cfgPath,
	})
	require.NoError(t, err)
	require.Equal(t, 15*time.Minute, cfg.Vault.AutoLockTimeout)
	require.Equal(t, "strict", cfg.SSH.KnownHostsPolicyDefault)
	require.True(t, cfg.SSH.ForwardAgentDefault)
	require.Equal(t, 20*time.Second, cfg.SSH.ConnectTimeout)
	require.Equal(t, "required", cfg.Passkey.UVDefault)
	require.Equal(t, 6*time.Hour, cfg.Daemon.MaxSessionDuration)
	require.Equal(t, "/tmp/heimdall.sockdir", cfg.Daemon.SocketDir)
	require.Equal(t, "debug", cfg.Logging.Level)
	require.Equal(t, "/tmp/heimdall.log", cfg.Logging.File)
	require.Equal(t, 42, cfg.Logging.MaxSizeMB)
	require.Equal(t, 9, cfg.Logging.MaxFiles)
	require.True(t, cfg.Telemetry.Enabled)
}

func TestLoadConfigValidationRejectsInvalidAutoLockTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		durationVal string
	}{
		{name: "negative", durationVal: "-1m"},
		{name: "greater-than-24h", durationVal: "25h"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "`+tt.durationVal+`"
`)
			_, _, err := Load(LoadOptions{
				ConfigPath: cfgPath,
			})
			require.ErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestPolicyOverrideWinsAndIsReported(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "15m"
`)
	policyPath := writePolicyFile(t, `
[vault]
auto_lock_timeout = "3m"
`)

	cfg, report, err := Load(LoadOptions{
		ConfigPath: cfgPath,
		PolicyPath: policyPath,
	})
	require.NoError(t, err)
	require.Equal(t, 3*time.Minute, cfg.Vault.AutoLockTimeout)
	require.Contains(t, report.PolicyOverrides, "vault.auto_lock_timeout")
}

func TestMissingPolicyFileIsNotAnError(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "15m"
`)
	missingPolicy := filepath.Join(t.TempDir(), "missing-policy.toml")

	cfg, report, err := Load(LoadOptions{
		ConfigPath: cfgPath,
		PolicyPath: missingPolicy,
	})
	require.NoError(t, err)
	require.NotNil(t, report.PolicyOverrides)
	require.Equal(t, 15*time.Minute, cfg.Vault.AutoLockTimeout)
}

func TestLoadPolicyPathFromEnv(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfigFile(t, `
[vault]
auto_lock_timeout = "15m"
`)
	policyPath := writePolicyFile(t, `
[vault]
auto_lock_timeout = "1m"
`)

	cfg, _, err := Load(LoadOptions{
		ConfigPath: cfgPath,
		Env: map[string]string{
			"HEIMDALL_POLICY_FILE": policyPath,
		},
	})
	require.NoError(t, err)
	require.Equal(t, time.Minute, cfg.Vault.AutoLockTimeout)
}

func writeConfigFile(t *testing.T, contents string) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(p, []byte(contents), 0o600))
	return p
}

func writePolicyFile(t *testing.T, contents string) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "policy.toml")
	require.NoError(t, os.WriteFile(p, []byte(contents), 0o600))
	return p
}
