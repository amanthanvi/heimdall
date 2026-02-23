package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	sshpkg "github.com/amanthanvi/heimdall/internal/ssh"
	"github.com/spf13/cobra"
)

type sshCommandExecutor interface {
	Run(ctx context.Context, command *sshpkg.SSHCommand) (int, error)
}

var newSSHCommandExecutor = func() sshCommandExecutor {
	return sshpkg.NewExecutor()
}

const defaultConnectKeyTTL = 30 * time.Minute

func newConnectCommand(deps commandDeps) *cobra.Command {
	var (
		dryRun       bool
		printCmd     bool
		jumpHosts    []string
		forwards     []string
		user         string
		port         int32
		keyName      string
		identityFile string
		knownHosts   string
	)

	cmd := &cobra.Command{
		Use:   "connect <host>",
		Short: "Connect to a host via SSH",
		Example: "  heimdall connect prod\n" +
			"  heimdall connect prod --dry-run\n" +
			"  heimdall connect prod --key deploy\n" +
			"  heimdall connect prod --jump bastion --forward L:8080:localhost:80",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("connect requires exactly one host name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				hostResp, err := clients.host.GetHost(ctx, &v1.GetHostRequest{Name: hostName})
				if err != nil {
					return err
				}
				host := hostResp.GetHost()
				if host == nil {
					return fmt.Errorf("connect: host %q not found", hostName)
				}

				effectiveKeyName := strings.TrimSpace(keyName)
				if effectiveKeyName == "" {
					effectiveKeyName = strings.TrimSpace(host.GetEnvRefs()["key_name"])
				}
				effectiveIdentityFile := strings.TrimSpace(identityFile)
				if effectiveIdentityFile == "" {
					effectiveIdentityFile = strings.TrimSpace(host.GetEnvRefs()["identity_ref"])
				}
				effectiveJumpHosts := append([]string(nil), jumpHosts...)
				if len(effectiveJumpHosts) == 0 {
					if defaultJump := strings.TrimSpace(host.GetEnvRefs()["proxy_jump"]); defaultJump != "" {
						effectiveJumpHosts = []string{defaultJump}
					}
				}
				if effectiveKeyName != "" && effectiveIdentityFile != "" {
					return usageErrorf("connect cannot use --key and --identity-file together")
				}

				resp, err := clients.connect.Plan(ctx, &v1.PlanConnectRequest{
					HostName:     hostName,
					User:         user,
					Port:         port,
					JumpHosts:    effectiveJumpHosts,
					Forwards:     append([]string(nil), forwards...),
					IdentityPath: effectiveIdentityFile,
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
					resolvedArgs := command.GetArgs()
					if printCmd && len(command.GetRedactedArgs()) > 0 {
						resolvedArgs = command.GetRedactedArgs()
					}
					line := strings.Join(append([]string{command.GetBinary()}, resolvedArgs...), " ")
					if deps.globals.JSON {
						payload := map[string]any{
							"binary": command.GetBinary(),
							"args":   resolvedArgs,
							"line":   line,
						}
						if effectiveKeyName != "" {
							payload["auth"] = map[string]any{
								"mode": "managed-agent",
								"key":  effectiveKeyName,
								"ttl":  defaultConnectKeyTTL.String(),
							}
						}
						return printJSON(deps.out, payload)
					}
					if deps.globals.Quiet {
						return nil
					}
					if _, err := fmt.Fprintln(deps.out, line); err != nil {
						return err
					}
					if effectiveKeyName != "" {
						_, err := fmt.Fprintf(deps.out, "auth: managed-agent key=%s ttl=%s\n", effectiveKeyName, defaultConnectKeyTTL)
						return err
					}
					return nil
				}

				commandEnv := append([]string(nil), command.GetEnv()...)
				sessionID := ""
				if effectiveKeyName != "" {
					hostID := strings.TrimSpace(host.GetId())
					if hostID == "" {
						return fmt.Errorf("connect: host %q is missing an id", hostName)
					}
					sessionID = fmt.Sprintf("connect-%s-%d", hostName, os.Getpid())
					sessionResp, err := clients.session.RecordSessionStart(ctx, &v1.RecordSessionStartRequest{
						HostId:    hostID,
						SessionId: sessionID,
					})
					if err != nil {
						return err
					}
					if resolved := strings.TrimSpace(sessionResp.GetSessionId()); resolved != "" {
						sessionID = resolved
					}
					if _, err := clients.key.AgentAdd(ctx, &v1.AgentAddRequest{
						Name:       effectiveKeyName,
						SessionId:  sessionID,
						TtlSeconds: int64(defaultConnectKeyTTL / time.Second),
					}); err != nil {
						return err
					}
					info, err := readDaemonInfoFile()
					if err != nil {
						return fmt.Errorf("connect: read daemon info: %w", err)
					}
					agentPath := strings.TrimSpace(info.AgentPath)
					if agentPath == "" {
						return fmt.Errorf("connect: daemon agent socket path is empty")
					}
					commandEnv = append(commandEnv, "SSH_AUTH_SOCK="+agentPath)
				}

				executor := newSSHCommandExecutor()
				exitCode, err := executor.Run(cmd.Context(), &sshpkg.SSHCommand{
					Binary:    command.GetBinary(),
					Args:      append([]string(nil), command.GetArgs()...),
					Env:       commandEnv,
					TempFiles: append([]string(nil), command.GetTempFiles()...),
				})
				if sessionID != "" {
					timeout := 10 * time.Second
					if deps.globals != nil && deps.globals.Timeout > 0 {
						timeout = deps.globals.Timeout
					}
					sessionCtx, cancel := context.WithTimeout(attachCallerMetadata(context.Background()), timeout)
					_, _ = clients.session.RecordSessionEnd(sessionCtx, &v1.RecordSessionEndRequest{
						SessionId: sessionID,
						ExitCode:  int32(exitCode),
					})
					cancel()
				}
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
	cmd.Flags().StringVar(&keyName, "key", "", "Vault key name for managed SSH agent auth")
	cmd.Flags().StringVar(&identityFile, "identity-file", "", "Identity file path")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "Known hosts file path")
	return cmd
}
