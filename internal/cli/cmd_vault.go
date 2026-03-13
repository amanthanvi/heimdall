package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newVaultCommand(deps commandDeps) *cobra.Command {
	cmd := newGroupCommand(
		"vault",
		"Vault operations",
		"  heimdall vault status\n"+
			"  heimdall vault unlock --passphrase \"dev-pass\"\n"+
			"  heimdall vault reauth --passphrase \"dev-pass\"\n"+
			"  heimdall vault lock",
		map[string]string{},
	)
	cmd.AddCommand(
		newVaultStatusCommand(deps),
		newVaultLockCommand(deps),
		newVaultUnlockCommand(deps),
		newVaultReauthCommand(deps),
	)
	return cmd
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
	var passphraseStdin bool

	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault",
		Example: "  heimdall vault unlock --passphrase \"dev-pass\"\n" +
			"  printf \"dev-pass\\n\" | heimdall vault unlock --passphrase-stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("vault unlock does not accept positional arguments")
			}
			authMethods := 0
			if strings.TrimSpace(passphrase) != "" {
				authMethods++
			}
			if passphraseStdin {
				authMethods++
			}
			if authMethods == 0 {
				return usageErrorf("vault unlock requires exactly one of --passphrase or --passphrase-stdin")
			}
			if authMethods > 1 {
				return usageErrorf("vault unlock accepts only one auth method: --passphrase or --passphrase-stdin")
			}

			resolvedPassphrase := passphrase
			if passphraseStdin {
				stdinPassphrase, err := readUnlockPassphraseFromStdin(cmd.InOrStdin())
				if err != nil {
					return err
				}
				resolvedPassphrase = stdinPassphrase
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.vault.Unlock(ctx, &v1.UnlockRequest{
					Passphrase: resolvedPassphrase,
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
	cmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "Read passphrase from stdin")
	return cmd
}

func newVaultReauthCommand(deps commandDeps) *cobra.Command {
	var passphrase string
	var passphraseStdin bool

	cmd := &cobra.Command{
		Use:   "reauth",
		Short: "Open a recent re-authentication window for sensitive operations",
		Example: "  heimdall vault reauth --passphrase \"dev-pass\"\n" +
			"  printf \"dev-pass\\n\" | heimdall vault reauth --passphrase-stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("vault reauth does not accept positional arguments")
			}
			authMethods := 0
			if strings.TrimSpace(passphrase) != "" {
				authMethods++
			}
			if passphraseStdin {
				authMethods++
			}
			if authMethods == 0 {
				return usageErrorf("vault reauth requires exactly one of --passphrase or --passphrase-stdin")
			}
			if authMethods > 1 {
				return usageErrorf("vault reauth accepts only one auth method: --passphrase or --passphrase-stdin")
			}

			resolvedPassphrase := passphrase
			if passphraseStdin {
				stdinPassphrase, err := readUnlockPassphraseFromStdin(cmd.InOrStdin())
				if err != nil {
					return err
				}
				resolvedPassphrase = stdinPassphrase
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.reauth.VerifyPassphrase(ctx, &v1.VerifyPassphraseRequest{Passphrase: resolvedPassphrase})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"reauthenticated": true})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintln(deps.out, "vault reauthenticated")
				return err
			})
		},
	}

	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Vault passphrase for re-authentication")
	cmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "Read re-authentication passphrase from stdin")
	return cmd
}

func readUnlockPassphraseFromStdin(reader io.Reader) (string, error) {
	lineReader := bufio.NewReader(reader)
	line, err := lineReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", mapCommandError(fmt.Errorf("vault unlock: read passphrase from stdin: %w", err))
	}
	passphrase := strings.TrimSpace(line)
	if passphrase == "" {
		return "", usageErrorf("vault unlock --passphrase-stdin requires a non-empty value on stdin")
	}
	return passphrase, nil
}
