package cli

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newBackupCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup operations",
		Example: "  heimdall backup create --output ./vault.backup.hdl --passphrase \"backup-pass\"\n" +
			"  heimdall backup restore --from ./vault.backup.hdl --passphrase \"backup-pass\"",
	}
	cmd.AddCommand(
		newBackupCreateCommand(deps),
		newBackupRestoreCommand(deps),
	)
	return cmd
}

func newBackupCreateCommand(deps commandDeps) *cobra.Command {
	var (
		outputPath string
		passphrase string
		overwrite  bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an encrypted backup",
		Example: "  heimdall backup create --output ./vault.backup.hdl --passphrase \"backup-pass\"\n" +
			"  heimdall backup create --output ./vault.backup.hdl --passphrase \"backup-pass\" --overwrite",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("backup create does not accept positional arguments")
			}
			if strings.TrimSpace(outputPath) == "" {
				return usageErrorf("backup create requires --output")
			}
			if strings.TrimSpace(passphrase) == "" {
				return usageErrorf("backup create requires --passphrase")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.backup.CreateBackup(ctx, &v1.CreateBackupRequest{
					OutputPath: outputPath,
					Passphrase: passphrase,
					Overwrite:  overwrite,
				})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"accepted":    resp.GetAccepted(),
						"output_path": resp.GetOutputPath(),
					})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "backup created: %s\n", resp.GetOutputPath())
				return err
			})
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "Backup output path")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Backup encryption passphrase (required)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite output path if it exists")
	return cmd
}

func newBackupRestoreCommand(deps commandDeps) *cobra.Command {
	var (
		inputPath  string
		passphrase string
		overwrite  bool
	)
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore from backup",
		Example: "  heimdall backup restore --from ./vault.backup.hdl --passphrase \"backup-pass\"\n" +
			"  heimdall backup restore --from ./vault.backup.hdl --passphrase \"backup-pass\" --overwrite",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("backup restore does not accept positional arguments")
			}
			if strings.TrimSpace(inputPath) == "" {
				return usageErrorf("backup restore requires --from")
			}
			if strings.TrimSpace(passphrase) == "" {
				return usageErrorf("backup restore requires --passphrase")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.backup.RestoreBackup(ctx, &v1.RestoreBackupRequest{
					InputPath:  inputPath,
					Passphrase: passphrase,
					Overwrite:  overwrite,
				})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"restored": resp.GetRestored()})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "backup restored: %t\n", resp.GetRestored())
				return err
			})
		},
	}
	cmd.Flags().StringVar(&inputPath, "from", "", "Backup input path")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Backup passphrase (required)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Allow overwriting existing vault")
	return cmd
}

func newAuditCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log operations",
		Example: "  heimdall audit list --limit 50\n" +
			"  heimdall audit verify",
	}
	cmd.AddCommand(
		newAuditListCommand(deps),
		newAuditVerifyCommand(deps),
	)
	return cmd
}

func newAuditListCommand(deps commandDeps) *cobra.Command {
	var limit int32
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit events",
		Example: "  heimdall audit list\n" +
			"  heimdall audit list --limit 20",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("audit list does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.audit.ListEvents(ctx, &v1.ListEventsRequest{Limit: limit})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, resp.GetEvents())
				}
				if deps.globals.Quiet {
					return nil
				}
				for _, event := range resp.GetEvents() {
					if _, err := fmt.Fprintf(
						deps.out,
						"%s action=%s target=%s/%s result=%s\n",
						event.GetId(),
						event.GetAction(),
						event.GetTargetType(),
						event.GetTargetId(),
						event.GetResult(),
					); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().Int32Var(&limit, "limit", 100, "Maximum number of events")
	return cmd
}

func newAuditVerifyCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify audit hash chain integrity",
		Example: "  heimdall audit verify\n" +
			"  heimdall --json audit verify",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("audit verify does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.audit.VerifyChain(ctx, &v1.VerifyChainRequest{})
				if err != nil {
					return err
				}
				payload := map[string]any{
					"valid":       resp.GetValid(),
					"event_count": resp.GetEventCount(),
					"chain_tip":   resp.GetChainTip(),
					"error":       resp.GetError(),
				}
				if deps.globals.JSON {
					return printJSON(deps.out, payload)
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(
					deps.out,
					"valid=%t events=%d chain_tip=%s error=%s\n",
					resp.GetValid(),
					resp.GetEventCount(),
					resp.GetChainTip(),
					resp.GetError(),
				)
				return err
			})
		},
	}
}
