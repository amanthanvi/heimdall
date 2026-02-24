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
	"github.com/amanthanvi/heimdall/internal/ssh"
	"github.com/amanthanvi/heimdall/internal/sshconfig"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func newStatusCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault and daemon status",
		Example: "  heimdall status\n" +
			"  heimdall --json status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("status does not accept positional arguments")
			}
			cfg, _, err := loadCLIConfigWithPath(deps.globals)
			if err != nil {
				return mapCommandError(fmt.Errorf("status: %w", err))
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				status, err := clients.vault.Status(ctx, &v1.StatusRequest{})
				if err != nil {
					return err
				}

				vaultLocked := status.GetLocked()
				keysResp, err := clients.key.ListKeys(ctx, &v1.ListKeysRequest{})
				keysAvailable := true
				if err != nil {
					if isVaultLockedRPC(err) {
						keysAvailable = false
						vaultLocked = true
					} else {
						return err
					}
				}
				now := time.Now().UTC()
				staleKeys := make([]map[string]any, 0)
				keyCount := 0
				if keysAvailable {
					keyCount = len(keysResp.GetKeys())
					for _, key := range keysResp.GetKeys() {
						createdAt, ok := parseCreatedAt(key.GetCreatedAt())
						if !ok {
							continue
						}
						ageDays := int(now.Sub(createdAt).Hours() / 24)
						if ageDays <= 365 {
							continue
						}
						staleKeys = append(staleKeys, map[string]any{
							"name":      key.GetName(),
							"age_days":  ageDays,
							"algorithm": key.GetKeyType(),
						})
					}
				}

				sshConfigState := map[string]any{
					"enabled":   cfg.SSHConfig.Enabled,
					"path":      cfg.SSHConfig.Path,
					"auto_sync": cfg.SSHConfig.AutoSync,
					"in_sync":   false,
				}
				if cfg.SSHConfig.Enabled {
					fragmentPath, _, err := resolveManagedSSHPaths(cfg.SSHConfig.Path)
					if err != nil {
						return err
					}
					sshConfigState["path"] = fragmentPath
					if vaultLocked {
						if _, statErr := os.Stat(fragmentPath); statErr == nil {
							sshConfigState["exists"] = true
						} else if os.IsNotExist(statErr) {
							sshConfigState["exists"] = false
						} else {
							return fmt.Errorf("status: stat managed ssh config %s: %w", filepath.Clean(fragmentPath), statErr)
						}
					} else {
						hostResp, hostErr := clients.host.ListHosts(ctx, &v1.ListHostsRequest{})
						if hostErr != nil {
							if isVaultLockedRPC(hostErr) {
								vaultLocked = true
								if _, statErr := os.Stat(fragmentPath); statErr == nil {
									sshConfigState["exists"] = true
								} else if os.IsNotExist(statErr) {
									sshConfigState["exists"] = false
								} else {
									return fmt.Errorf("status: stat managed ssh config %s: %w", filepath.Clean(fragmentPath), statErr)
								}
							} else {
								return hostErr
							}
						} else {
							desired := sshconfig.Generate(protoHostsToStorage(hostResp.GetHosts()))
							current, readErr := os.ReadFile(fragmentPath)
							if readErr == nil {
								sshConfigState["in_sync"] = string(current) == desired
								sshConfigState["exists"] = true
							} else if os.IsNotExist(readErr) {
								sshConfigState["exists"] = false
								sshConfigState["in_sync"] = false
							} else {
								return fmt.Errorf("status: read managed ssh config %s: %w", filepath.Clean(fragmentPath), readErr)
							}
							sshConfigState["host_count"] = len(hostResp.GetHosts())
						}
					}
				}

				if !keysAvailable && !vaultLocked {
					keysAvailable = true
				}
				if !keysAvailable {
					sshConfigState["partial"] = true
				}

				payload := map[string]any{
					"daemon_running":      true,
					"vault_locked":        vaultLocked,
					"has_live_vmk":        status.GetHasLiveVmk(),
					"key_count":           keyCount,
					"key_count_available": keysAvailable,
					"stale_keys":          staleKeys,
					"ssh_config":          sshConfigState,
					"audit": map[string]any{
						"connection_logging": cfg.Audit.ConnectionLogging,
					},
				}
				if deps.globals.JSON {
					return printJSON(deps.out, payload)
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(
					deps.out,
					"daemon=%s vault=%s live_vmk=%s\n",
					boolToState(true, "running", "stopped"),
					boolToState(vaultLocked, "locked", "unlocked"),
					boolToState(status.GetHasLiveVmk(), "yes", "no"),
				)
				if err != nil {
					return err
				}
				if keysAvailable {
					if _, err := fmt.Fprintf(deps.out, "keys: %d total, %d stale (>365d)\n", keyCount, len(staleKeys)); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintln(deps.out, "keys: unavailable (vault locked)"); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprintf(
					deps.out,
					"ssh_config: enabled=%t auto_sync=%t in_sync=%t path=%s\n",
					cfg.SSHConfig.Enabled,
					cfg.SSHConfig.AutoSync,
					sshConfigState["in_sync"],
					sshConfigState["path"],
				); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(
					deps.out,
					"audit: connection_logging=%s\n",
					boolToState(cfg.Audit.ConnectionLogging, "enabled", "disabled"),
				); err != nil {
					return err
				}
				return nil
			})
		},
	}
}

func isVaultLockedRPC(err error) bool {
	if err == nil {
		return false
	}
	st, ok := grpcstatus.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.PermissionDenied, codes.FailedPrecondition:
		return strings.Contains(strings.ToLower(st.Message()), "vault is locked")
	default:
		return false
	}
}

func newDoctorCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run local dependency and daemon health checks",
		Example: "  heimdall doctor\n" +
			"  heimdall --json doctor",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("doctor does not accept positional arguments")
			}

			type doctorCheck struct {
				Name    string `json:"name"`
				OK      bool   `json:"ok"`
				Message string `json:"message"`
			}
			checks := []doctorCheck{}

			sshInfo, sshErr := ssh.CheckBinary(ssh.BinaryCheckDeps{})
			if sshErr != nil {
				checks = append(checks, doctorCheck{
					Name:    "ssh",
					OK:      false,
					Message: sshErr.Error(),
				})
			} else {
				checks = append(checks, doctorCheck{
					Name:    "ssh",
					OK:      true,
					Message: fmt.Sprintf("%s (%s)", sshInfo.Path, sshInfo.Version),
				})
			}

			loadOpts := config.LoadOptions{}
			if deps.globals != nil {
				if configPath := strings.TrimSpace(deps.globals.ConfigPath); configPath != "" {
					loadOpts.ConfigPath = configPath
				}
				if vaultPath := strings.TrimSpace(deps.globals.VaultPath); vaultPath != "" {
					loadOpts.Env = map[string]string{
						"HEIMDALL_VAULT_PATH": vaultPath,
					}
				}
			}
			cfg, _, cfgErr := loadConfigFn(loadOpts)
			if cfgErr != nil {
				checks = append(checks, doctorCheck{
					Name:    "config",
					OK:      false,
					Message: cfgErr.Error(),
				})
			} else {
				conn, daemonErr := ensureDaemonFn(cmd.Context(), &cfg)
				if daemonErr != nil {
					checks = append(checks, doctorCheck{
						Name:    "daemon",
						OK:      false,
						Message: daemonErr.Error(),
					})
				} else {
					_ = conn.Close()
					checks = append(checks, doctorCheck{
						Name:    "daemon",
						OK:      true,
						Message: "reachable",
					})
				}
			}

			if deps.globals.JSON {
				if err := printJSON(deps.out, map[string]any{"checks": checks}); err != nil {
					return mapCommandError(err)
				}
			} else if !deps.globals.Quiet {
				for _, check := range checks {
					state := "ok"
					if !check.OK {
						state = "fail"
					}
					if _, err := fmt.Fprintf(deps.out, "%s: %s (%s)\n", check.Name, state, check.Message); err != nil {
						return mapCommandError(err)
					}
				}
			}

			if sshErr != nil {
				return asExitError(ExitCodeDependencyMissing, sshErr)
			}
			for _, check := range checks {
				if !check.OK {
					return asExitError(ExitCodeGeneric, fmt.Errorf("doctor: one or more checks failed"))
				}
			}
			return nil
		},
	}
}
