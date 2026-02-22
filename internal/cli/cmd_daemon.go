package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/amanthanvi/heimdall/internal/config"
	"github.com/spf13/cobra"
)

func newDaemonCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Daemon lifecycle commands",
		Example: "  heimdall daemon status\n" +
			"  heimdall daemon restart\n" +
			"  heimdall daemon stop",
	}
	cmd.AddCommand(
		newDaemonStatusCommand(deps),
		newDaemonStopCommand(deps),
		newDaemonRestartCommand(deps),
		newDaemonServeCommand(deps),
	)
	return cmd
}

// newDaemonServeCommand is defined in cmd_daemon_serve.go

func newDaemonStatusCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		Example: "  heimdall daemon status\n" +
			"  heimdall --json daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("daemon status does not accept positional arguments")
			}

			info, err := readDaemonInfoFile()
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					if deps.globals.JSON {
						return printJSON(deps.out, map[string]any{"running": false})
					}
					if deps.globals.Quiet {
						return nil
					}
					_, writeErr := fmt.Fprintln(deps.out, "daemon=stopped")
					return mapCommandError(writeErr)
				}
				return mapCommandError(err)
			}

			running := processIsRunning(info.PID)
			payload := map[string]any{
				"running":     running,
				"pid":         info.PID,
				"socket_path": info.SocketPath,
				"agent_path":  info.AgentPath,
				"started_at":  info.StartedAt.Format(time.RFC3339Nano),
			}
			if deps.globals.JSON {
				return printJSON(deps.out, payload)
			}
			if deps.globals.Quiet {
				return nil
			}
			_, writeErr := fmt.Fprintf(
				deps.out,
				"daemon=%s pid=%d socket=%s agent=%s\n",
				boolToState(running, "running", "stopped"),
				info.PID,
				info.SocketPath,
				info.AgentPath,
			)
			return mapCommandError(writeErr)
		},
	}
}

func newDaemonStopCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the running daemon",
		Example: "  heimdall daemon stop\n" +
			"  heimdall --json daemon stop",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("daemon stop does not accept positional arguments")
			}
			stopped, err := stopDaemonProcess()
			if err != nil {
				return mapCommandError(err)
			}
			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{"stopped": stopped})
			}
			if deps.globals.Quiet {
				return nil
			}
			if stopped {
				_, err = fmt.Fprintln(deps.out, "daemon stopped")
				return mapCommandError(err)
			}
			_, err = fmt.Fprintln(deps.out, "daemon already stopped")
			return mapCommandError(err)
		},
	}
}

func newDaemonRestartCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart daemon",
		Example: "  heimdall daemon restart\n" +
			"  heimdall --json daemon restart",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("daemon restart does not accept positional arguments")
			}

			if _, err := stopDaemonProcess(); err != nil {
				return mapCommandError(err)
			}

			restoreEnv := applyPathEnvOverrides(deps.globals)
			defer restoreEnv()

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
			cfg, _, err := loadConfigFn(loadOpts)
			if err != nil {
				return mapCommandError(fmt.Errorf("daemon restart: load config: %w", err))
			}

			conn, err := ensureDaemonFn(context.Background(), &cfg)
			if err != nil {
				return mapCommandError(fmt.Errorf("daemon restart: %w", err))
			}
			_ = conn.Close()

			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{"restarted": true})
			}
			if deps.globals.Quiet {
				return nil
			}
			_, err = fmt.Fprintln(deps.out, "daemon restarted")
			return mapCommandError(err)
		},
	}
}

func stopDaemonProcess() (bool, error) {
	info, err := readDaemonInfoFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	if processIsRunning(info.PID) {
		process, err := os.FindProcess(info.PID)
		if err != nil {
			return false, fmt.Errorf("daemon stop: find process %d: %w", info.PID, err)
		}
		if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return false, fmt.Errorf("daemon stop: signal process %d: %w", info.PID, err)
		}

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if !processIsRunning(info.PID) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if processIsRunning(info.PID) {
			return false, fmt.Errorf("daemon stop: process %d still running after timeout", info.PID)
		}
	}

	if err := removeDaemonInfoFile(); err != nil {
		return false, err
	}
	return true, nil
}
