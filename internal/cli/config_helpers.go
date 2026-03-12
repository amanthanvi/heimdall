package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/amanthanvi/heimdall/internal/config"
)

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
