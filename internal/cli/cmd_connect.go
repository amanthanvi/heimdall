package cli

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	sshpkg "github.com/amanthanvi/heimdall/internal/ssh"
	"github.com/spf13/cobra"
)

func newConnectCommand(deps commandDeps) *cobra.Command {
	var (
		dryRun       bool
		printCmd     bool
		jumpHosts    []string
		forwards     []string
		user         string
		port         int32
		identityPath string
		knownHosts   string
	)

	cmd := &cobra.Command{
		Use:   "connect <host>",
		Short: "Connect to a host via SSH",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("connect requires exactly one host name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.connect.Plan(ctx, &v1.PlanConnectRequest{
					HostName:     hostName,
					User:         user,
					Port:         port,
					JumpHosts:    append([]string(nil), jumpHosts...),
					Forwards:     append([]string(nil), forwards...),
					IdentityPath: identityPath,
					KnownHosts:   knownHosts,
					PrintCmd:     printCmd,
					DryRun:       dryRun,
				})
				if err != nil {
					return err
				}

				command := resp.GetCommand()
				if command == nil {
					return fmt.Errorf("connect: daemon returned empty command plan")
				}
				if dryRun || printCmd {
					args := command.GetArgs()
					if printCmd && len(command.GetRedactedArgs()) > 0 {
						args = command.GetRedactedArgs()
					}
					line := strings.Join(append([]string{command.GetBinary()}, args...), " ")
					if deps.globals.JSON {
						return printJSON(deps.out, map[string]any{
							"binary": command.GetBinary(),
							"args":   args,
							"line":   line,
						})
					}
					if deps.globals.Quiet {
						return nil
					}
					_, err := fmt.Fprintln(deps.out, line)
					return err
				}

				executor := sshpkg.NewExecutor()
				exitCode, err := executor.Run(ctx, &sshpkg.SSHCommand{
					Binary:    command.GetBinary(),
					Args:      append([]string(nil), command.GetArgs()...),
					Env:       append([]string(nil), command.GetEnv()...),
					TempFiles: append([]string(nil), command.GetTempFiles()...),
				})
				if err != nil {
					return err
				}
				if exitCode != 0 {
					return &ExitError{
						Code: exitCode,
						Err:  fmt.Errorf("connect: ssh exited with code %d", exitCode),
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the SSH command without executing")
	cmd.Flags().BoolVar(&printCmd, "print-cmd", false, "Print redacted SSH command")
	cmd.Flags().StringSliceVar(&jumpHosts, "jump", nil, "Jump host (repeatable)")
	cmd.Flags().StringSliceVar(&forwards, "forward", nil, "Port forward spec, e.g. L:8080:localhost:80")
	cmd.Flags().StringVar(&user, "user", "", "SSH user override")
	cmd.Flags().Int32Var(&port, "port", 0, "SSH port override")
	cmd.Flags().StringVar(&identityPath, "identity", "", "Identity file path")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "Known hosts file path")
	return cmd
}
