package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/amanthanvi/heimdall/internal/app"
	"github.com/spf13/cobra"
)

const defaultInitConfig = `[vault]
auto_lock_timeout = "30m"

[ssh]
known_hosts_policy_default = "tofu"
forward_agent_default = false
connect_timeout = "10s"

[passkey]
uv_default = "preferred"

[daemon]
max_session_duration = "8h"
socket_dir = ""

[logging]
level = "info"
file = ""
max_size_mb = 10
max_files = 5

[telemetry]
enabled = false
`

func newInitCommand(deps commandDeps) *cobra.Command {
	var (
		passphraseStdin bool
		importSSHConfig string
		enrollPasskey   bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a local vault and config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("init does not accept positional arguments")
			}

			if passphraseStdin {
				if err := readPassphraseFromStdin(cmd.InOrStdin()); err != nil {
					return err
				}
			}

			if importSSHConfig != "" {
				if _, err := os.Stat(importSSHConfig); err != nil {
					return mapCommandError(fmt.Errorf("init: validate --import-ssh-config: %w", err))
				}
			}

			vaultPath, err := resolveVaultPath(deps.globals)
			if err != nil {
				return mapCommandError(err)
			}
			configPath, err := resolveConfigPath(deps.globals)
			if err != nil {
				return mapCommandError(err)
			}
			yes := deps.globals != nil && deps.globals.Yes

			if !yes {
				if _, err := os.Stat(vaultPath); err == nil {
					return usageErrorf("init target vault already exists: %s (use --yes to overwrite)", vaultPath)
				} else if !errors.Is(err, os.ErrNotExist) {
					return mapCommandError(err)
				}
			}

			if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
				return mapCommandError(fmt.Errorf("init: create vault directory: %w", err))
			}
			if err := app.BootstrapVault(vaultPath); err != nil {
				return mapCommandError(err)
			}

			if err := writeDefaultConfig(configPath, yes); err != nil {
				return mapCommandError(err)
			}

			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{
					"initialized":         true,
					"vault_path":          vaultPath,
					"config_path":         configPath,
					"import_ssh_config":   importSSHConfig != "",
					"enroll_passkey":      enrollPasskey,
					"passphrase_provided": passphraseStdin,
				})
			}
			if deps.globals.Quiet {
				return nil
			}

			if _, err := fmt.Fprintf(deps.out, "initialized vault: %s\n", vaultPath); err != nil {
				return mapCommandError(err)
			}
			if _, err := fmt.Fprintf(deps.out, "wrote config: %s\n", configPath); err != nil {
				return mapCommandError(err)
			}
			if importSSHConfig != "" {
				if _, err := fmt.Fprintf(deps.out, "queued ssh config import from: %s\n", importSSHConfig); err != nil {
					return mapCommandError(err)
				}
			}
			if enrollPasskey {
				if _, err := fmt.Fprintln(deps.out, "passkey enrollment requested (run `heimdall passkey enroll --label <label>` after daemon starts)"); err != nil {
					return mapCommandError(err)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "Read passphrase from stdin")
	cmd.Flags().StringVar(&importSSHConfig, "import-ssh-config", "", "Import hosts from an OpenSSH config file after init")
	cmd.Flags().BoolVar(&enrollPasskey, "enroll-passkey", false, "Run passkey enrollment after initialization")
	return cmd
}

func readPassphraseFromStdin(r io.Reader) error {
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return mapCommandError(fmt.Errorf("init: read passphrase from stdin: %w", err))
	}
	if strings.TrimSpace(line) == "" {
		return usageErrorf("init --passphrase-stdin requires a non-empty value on stdin")
	}
	return nil
}

func writeDefaultConfig(path string, overwrite bool) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: config path is required", app.ErrValidation)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("init: create config directory: %w", err)
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("init: stat config path: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(defaultInitConfig), 0o600); err != nil {
		return fmt.Errorf("init: write config: %w", err)
	}
	return nil
}
