package cli

import (
	"context"
	"fmt"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newVaultCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Vault operations",
		Example: "  heimdall vault status\n" +
			"  heimdall vault unlock --passphrase \"dev-pass\"\n" +
			"  heimdall vault lock",
	}
	cmd.AddCommand(
		newVaultStatusCommand(deps),
		newVaultLockCommand(deps),
		newVaultUnlockCommand(deps),
		newVaultTimeoutCommand(),
		newVaultUnsupportedCommand("change-passphrase"),
	)
	return cmd
}

func newVaultTimeoutCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "timeout",
		Short: "Vault auto-lock timeout operations",
		Example: "  heimdall vault timeout show\n" +
			"  heimdall vault timeout set",
	}
	cmd.AddCommand(
		newVaultUnsupportedCommand("set"),
		newVaultUnsupportedCommand("show"),
	)
	return cmd
}

func newVaultUnsupportedCommand(name string) *cobra.Command {
	return &cobra.Command{
		Use:     name,
		Short:   "Reserved vault command (future release)",
		Example: fmt.Sprintf("  heimdall vault %s", name),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mapCommandError(fmt.Errorf("%s is reserved for a future release", cmd.CommandPath()))
		},
	}
}

func newVaultStatusCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault lock status",
		Example: "  heimdall vault status\n" +
			"  heimdall --json vault status",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("vault status does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.vault.Status(ctx, &v1.StatusRequest{})
				if err != nil {
					return err
				}
				payload := map[string]any{
					"locked":       resp.GetLocked(),
					"has_live_vmk": resp.GetHasLiveVmk(),
				}
				if deps.globals.JSON {
					return printJSON(deps.out, payload)
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(
					deps.out,
					"vault=%s live_vmk=%s\n",
					boolToState(resp.GetLocked(), "locked", "unlocked"),
					boolToState(resp.GetHasLiveVmk(), "yes", "no"),
				)
				return err
			})
		},
	}
}

func newVaultLockCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the vault",
		Example: "  heimdall vault lock\n" +
			"  heimdall --json vault lock",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("vault lock does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.vault.Lock(ctx, &v1.LockRequest{})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"locked": true})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintln(deps.out, "vault locked")
				return err
			})
		},
	}
}

func newVaultUnlockCommand(deps commandDeps) *cobra.Command {
	var passphrase string
	var passkeyLabel string

	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault",
		Example: "  heimdall vault unlock --passphrase \"dev-pass\"\n" +
			"  heimdall vault unlock --passkey-label \"macbook-touchid\"",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("vault unlock does not accept positional arguments")
			}
			if passphrase == "" && passkeyLabel == "" {
				return usageErrorf("vault unlock requires --passphrase or --passkey-label")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.vault.Unlock(ctx, &v1.UnlockRequest{
					Passphrase:   passphrase,
					PasskeyLabel: passkeyLabel,
				})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"unlocked": true})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintln(deps.out, "vault unlocked")
				return err
			})
		},
	}

	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Vault passphrase")
	cmd.Flags().StringVar(&passkeyLabel, "passkey-label", "", "Passkey label for unlock")
	return cmd
}
