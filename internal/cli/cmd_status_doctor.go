package cli

import (
	"context"
	"fmt"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/amanthanvi/heimdall/internal/daemon"
	"github.com/amanthanvi/heimdall/internal/ssh"
	"github.com/spf13/cobra"
)

func newStatusCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault and daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("status does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				status, err := clients.vault.Status(ctx, &v1.StatusRequest{})
				if err != nil {
					return err
				}

				payload := map[string]any{
					"daemon_running": true,
					"vault_locked":   status.GetLocked(),
					"has_live_vmk":   status.GetHasLiveVmk(),
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
					boolToState(status.GetLocked(), "locked", "unlocked"),
					boolToState(status.GetHasLiveVmk(), "yes", "no"),
				)
				return err
			})
		},
	}
}

func newDoctorCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run local dependency and daemon health checks",
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

			cfg, _, cfgErr := config.Load(config.LoadOptions{})
			if cfgErr != nil {
				checks = append(checks, doctorCheck{
					Name:    "config",
					OK:      false,
					Message: cfgErr.Error(),
				})
			} else {
				conn, daemonErr := daemon.EnsureDaemon(&cfg)
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
