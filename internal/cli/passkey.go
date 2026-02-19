package cli

import (
	"github.com/amanthanvi/heimdall/internal/fido2"
	"github.com/spf13/cobra"
)

func newPasskeyCommand() *cobra.Command {
	passkeyCmd := &cobra.Command{
		Use:   "passkey",
		Short: "Manage passkey enrollments",
	}

	for _, sub := range []string{"enroll", "ls", "rm", "test"} {
		command := sub
		passkeyCmd.AddCommand(&cobra.Command{
			Use:   command,
			Short: "Passkey operation",
			RunE: func(_ *cobra.Command, _ []string) error {
				return fido2.PasskeyCommandUnavailable(command)
			},
		})
	}

	return passkeyCmd
}
