package cli

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newPasskeyCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passkey",
		Short: "Passkey management",
		Example: "  heimdall passkey enroll --label macbook-touchid\n" +
			"  heimdall passkey ls\n" +
			"  heimdall passkey test macbook-touchid",
	}
	cmd.AddCommand(
		newPasskeyEnrollCommand(deps),
		newPasskeyListCommand(deps),
		newPasskeyRemoveCommand(deps),
		newPasskeyTestCommand(deps),
	)
	return cmd
}

func newPasskeyEnrollCommand(deps commandDeps) *cobra.Command {
	var (
		label    string
		userName string
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a passkey",
		Example: "  heimdall passkey enroll --label macbook-touchid\n" +
			"  heimdall passkey enroll --label yubikey --user aman",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("passkey enroll does not accept positional arguments")
			}
			if strings.TrimSpace(label) == "" {
				return usageErrorf("passkey enroll requires --label")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.passkey.Enroll(ctx, &v1.EnrollPasskeyRequest{
					Label:    label,
					UserName: userName,
				})
				if err != nil {
					return err
				}
				return printPasskeyOutput(deps, resp.GetPasskey())
			})
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "Passkey label")
	cmd.Flags().StringVar(&userName, "user", "", "Passkey user name")
	return cmd
}

func newPasskeyListCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List passkeys",
		Example: "  heimdall passkey ls\n" +
			"  heimdall --json passkey ls",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("passkey ls does not accept positional arguments")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.passkey.ListPasskeys(ctx, &v1.ListPasskeysRequest{})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, resp.GetPasskeys())
				}
				if deps.globals.Quiet {
					return nil
				}
				for _, passkey := range resp.GetPasskeys() {
					if _, err := fmt.Fprintf(deps.out, "%s hmac_secret=%t\n", passkey.GetLabel(), passkey.GetSupportsHmacSecret()); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
}

func newPasskeyRemoveCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:     "rm <label>",
		Short:   "Remove a passkey",
		Example: "  heimdall passkey rm macbook-touchid",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("passkey rm requires exactly one passkey label")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.passkey.RemovePasskey(ctx, &v1.RemovePasskeyRequest{Label: args[0]})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"removed": args[0]})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "passkey removed: %s\n", args[0])
				return err
			})
		},
	}
}

func newPasskeyTestCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:     "test <label>",
		Short:   "Test passkey availability",
		Example: "  heimdall passkey test macbook-touchid",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("passkey test requires exactly one passkey label")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.passkey.TestPasskey(ctx, &v1.TestPasskeyRequest{Label: args[0]})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"label": args[0],
						"ok":    resp.GetOk(),
					})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "passkey %s ok=%t\n", args[0], resp.GetOk())
				return err
			})
		},
	}
}

func printPasskeyOutput(deps commandDeps, passkey *v1.PasskeyMeta) error {
	if deps.globals.JSON {
		return printJSON(deps.out, passkey)
	}
	if deps.globals.Quiet {
		return nil
	}
	_, err := fmt.Fprintf(deps.out, "%s hmac_secret=%t\n", passkey.GetLabel(), passkey.GetSupportsHmacSecret())
	return err
}
