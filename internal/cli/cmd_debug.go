package cli

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	debugpkg "github.com/amanthanvi/heimdall/internal/debug"
	"github.com/amanthanvi/heimdall/internal/ssh"
	"github.com/spf13/cobra"
)

func newDebugCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "debug",
		Short:   "Diagnostics helpers",
		Example: "  heimdall debug bundle --output ./heimdall-debug.json",
	}
	cmd.AddCommand(newDebugBundleCommand(deps))
	return cmd
}

func newDebugBundleCommand(deps commandDeps) *cobra.Command {
	var outputPath string
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Collect sanitized diagnostics into a JSON bundle",
		Example: "  heimdall debug bundle --output ./heimdall-debug.json\n" +
			"  heimdall --json debug bundle --output ./heimdall-debug.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("debug bundle does not accept positional arguments")
			}
			if strings.TrimSpace(outputPath) == "" {
				return usageErrorf("debug bundle requires --output")
			}

			bundle := debugpkg.NewBundle()
			bundle.Version = map[string]any{
				"version":    deps.build.Version,
				"commit":     deps.build.Commit,
				"build_time": deps.build.BuildTime,
			}

			sshInfo, err := ssh.CheckBinary(ssh.BinaryCheckDeps{})
			if err != nil {
				bundle.Checks = append(bundle.Checks, debugpkg.Check{Name: "ssh", OK: false, Message: err.Error()})
			} else {
				bundle.Checks = append(bundle.Checks, debugpkg.Check{
					Name:    "ssh",
					OK:      true,
					Message: fmt.Sprintf("%s (%s)", sshInfo.Path, sshInfo.Version),
				})
			}

			_ = withDaemonClients(context.Background(), deps, func(ctx context.Context, clients daemonClients) error {
				status, err := clients.vault.Status(ctx, &v1.StatusRequest{})
				if err != nil {
					bundle.Checks = append(bundle.Checks, debugpkg.Check{Name: "daemon", OK: false, Message: err.Error()})
					return nil
				}
				bundle.Daemon = map[string]any{
					"running":      true,
					"vault_locked": status.GetLocked(),
					"has_live_vmk": status.GetHasLiveVmk(),
				}
				bundle.Checks = append(bundle.Checks, debugpkg.Check{Name: "daemon", OK: true, Message: "reachable"})
				return nil
			})

			if err := debugpkg.WriteBundle(outputPath, bundle); err != nil {
				return mapCommandError(err)
			}
			if deps.globals.JSON {
				return printJSON(deps.out, map[string]any{"output": outputPath})
			}
			if deps.globals.Quiet {
				return nil
			}
			_, err = fmt.Fprintf(deps.out, "debug bundle written: %s\n", outputPath)
			return mapCommandError(err)
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "Output JSON bundle path")
	return cmd
}
