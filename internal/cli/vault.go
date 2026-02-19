package cli

import (
	"fmt"
	"io"

	"github.com/amanthanvi/heimdall/internal/fido2"
	"github.com/spf13/cobra"
)

func newVaultCommand(out io.Writer) *cobra.Command {
	vaultCmd := &cobra.Command{
		Use:   "vault",
		Short: "Vault operations",
	}

	var passkeyLabel string
	var passphraseStdin bool
	unlockCmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if passkeyLabel != "" {
				return fido2.VaultUnlockPasskeyUnavailable()
			}
			if passphraseStdin {
				if _, err := io.ReadAll(cmd.InOrStdin()); err != nil {
					return err
				}
				_, err := fmt.Fprintln(out, "vault unlocked (passphrase)")
				return err
			}
			return fmt.Errorf("must provide either --passkey or --passphrase-stdin")
		},
	}
	unlockCmd.Flags().StringVar(&passkeyLabel, "passkey", "", "Passkey label for unlock")
	unlockCmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "Read passphrase from stdin")

	vaultCmd.AddCommand(unlockCmd)
	return vaultCmd
}
