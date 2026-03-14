package cli

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/amanthanvi/heimdall/internal/app"
	"github.com/spf13/cobra"
)

func newBackupCommand(deps commandDeps) *cobra.Command {
	cmd := newGroupCommand(
		"backup",
		"Backup operations",
		"  heimdall backup create --output ./vault.backup.hdl --passphrase \"backup-pass\"\n"+
			"  heimdall --config ./target-config.toml --vault ./target-vault.db backup restore --from ./vault.backup.hdl --passphrase \"backup-pass\"\n"+
			"  heimdall daemon restart\n"+
			"  heimdall vault unlock --passphrase \"source-vault-pass\"",
		map[string]string{},
	)
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
		Long: strings.Join([]string{
			"Restore from backup.",
			"",
			"Recommended workflow:",
			"  1) Point Heimdall at the target config/vault paths you want to restore into.",
			"  2) For a plain restore, use a target vault path that does not already contain a Heimdall vault.",
			"  3) If the target vault already exists, unlock it, re-authenticate, and pass --overwrite.",
			"  4) Restart daemon, then unlock the restored vault with the source vault passphrase.",
			"",
			"Notes:",
			"  - Plain restore runs locally and does not require daemon access to the target vault first.",
			"  - A freshly initialized target vault still counts as an existing vault and requires --overwrite.",
			"  - --overwrite requires a recent re-authentication window.",
			"  - Overwrite restores are staged and applied on the next daemon start/restart.",
			"  - Restored vault unlock credentials come from the backup source vault.",
		}, "\n"),
		Example: "  heimdall --config ./target-config.toml --vault ./target-vault.db backup restore --from ./vault.backup.hdl --passphrase \"backup-pass\"\n" +
			"  heimdall --config ./target-config.toml --vault ./target-vault.db vault unlock --passphrase \"target-pass\"\n" +
			"  heimdall --config ./target-config.toml --vault ./target-vault.db vault reauth --passphrase \"target-pass\"\n" +
			"  heimdall --config ./target-config.toml --vault ./target-vault.db backup restore --from ./vault.backup.hdl --passphrase \"backup-pass\" --overwrite\n" +
			"  heimdall daemon restart\n" +
			"  heimdall vault unlock --passphrase \"source-vault-pass\"",
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
			if !overwrite {
				targetVaultPath, err := resolveVaultPath(deps.globals)
				if err != nil {
					return mapCommandError(err)
				}
				backupSvc := app.NewBackupService(nil)
				_, err = backupSvc.Restore(cmd.Context(), app.BackupRestoreRequest{
					InputPath:       inputPath,
					Passphrase:      []byte(passphrase),
					TargetVaultPath: targetVaultPath,
				})
				if err != nil {
					return mapCommandError(err)
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"restored": true})
				}
				if deps.globals.Quiet {
					return nil
				}
				if _, err := fmt.Fprintf(deps.out, "backup restored: %t\n", true); err != nil {
					return err
				}
				_, err = fmt.Fprintln(
					deps.out,
					"next: run `heimdall daemon restart` if the target daemon was already running, then unlock using the source vault passphrase from the backup",
				)
				return err
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
				if _, err := fmt.Fprintf(deps.out, "backup restored: %t\n", resp.GetRestored()); err != nil {
					return err
				}
				if resp.GetRestored() {
					_, err = fmt.Fprintln(
						deps.out,
						"next: run `heimdall daemon restart` then unlock using the source vault passphrase from the backup",
					)
					return err
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&inputPath, "from", "", "Backup input path")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Backup passphrase (required)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Allow overwriting existing vault (requires recent re-authentication)")
	return cmd
}

func newAuditCommand(deps commandDeps) *cobra.Command {
	cmd := newGroupCommand(
		"audit",
		"Audit log operations",
		"  heimdall audit list --limit 50\n"+
			"  heimdall audit verify",
		map[string]string{},
	)
	cmd.AddCommand(
		newAuditListCommand(deps),
		newAuditVerifyCommand(deps),
	)
	return cmd
}

func newAuditListCommand(deps commandDeps) *cobra.Command {
	var (
		limit  int32
		action string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit events",
		Example: "  heimdall audit list\n" +
			"  heimdall audit list --limit 20\n" +
			"  heimdall audit list --action connect.start --limit 20",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("audit list does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.audit.ListEvents(ctx, &v1.ListEventsRequest{
					Limit:  limit,
					Action: strings.TrimSpace(action),
				})
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
	cmd.Flags().StringVar(&action, "action", "", "Filter by action type")
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
				var invalidChainErr error
				if !resp.GetValid() {
					invalidChainErr = &ExitError{Code: ExitCodeGeneric}
				}
				payload := map[string]any{
					"valid":       resp.GetValid(),
					"event_count": resp.GetEventCount(),
					"chain_tip":   resp.GetChainTip(),
					"error":       resp.GetError(),
				}
				if deps.globals.JSON {
					if err := printJSON(deps.out, payload); err != nil {
						return err
					}
					return invalidChainErr
				}
				if deps.globals.Quiet {
					return invalidChainErr
				}
				_, err = fmt.Fprintf(
					deps.out,
					"valid=%t events=%d chain_tip=%s error=%s\n",
					resp.GetValid(),
					resp.GetEventCount(),
					resp.GetChainTip(),
					resp.GetError(),
				)
				if err != nil {
					return err
				}
				return invalidChainErr
			})
		},
	}
}
