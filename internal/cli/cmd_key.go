package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newKeyCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "SSH key management",
	}
	cmd.AddCommand(
		newKeyGenerateCommand(deps),
		newKeyImportCommand(deps),
		newKeyExportCommand(deps),
		newKeyListCommand(deps),
		newKeyShowCommand(deps),
		newKeyRemoveCommand(deps),
		newKeyRotateCommand(deps),
		newKeyAgentCommand(),
	)
	return cmd
}

func newKeyAgentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "SSH agent key operations",
	}
	cmd.AddCommand(
		newKeyUnsupportedCommand("add"),
		newKeyUnsupportedCommand("rm"),
	)
	return cmd
}

func newKeyUnsupportedCommand(name string) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: fmt.Sprintf("%s key settings (not yet implemented)", name),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mapCommandError(fmt.Errorf("%s is not implemented", cmd.CommandPath()))
		},
	}
}

func newKeyGenerateCommand(deps commandDeps) *cobra.Command {
	var (
		name    string
		keyType string
	)
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a new key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("key gen does not accept positional arguments")
			}
			if strings.TrimSpace(name) == "" {
				return usageErrorf("key gen requires --name")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.key.GenerateKey(ctx, &v1.GenerateKeyRequest{
					Name:    name,
					KeyType: keyType,
				})
				if err != nil {
					return err
				}
				return printKeyMetaOutput(deps, resp.GetKey())
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Key name")
	cmd.Flags().StringVar(&keyType, "type", "ed25519", "Key type (ed25519|rsa)")
	return cmd
}

func newKeyImportCommand(deps commandDeps) *cobra.Command {
	var (
		name       string
		inputPath  string
		passphrase string
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an existing private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("key import does not accept positional arguments")
			}
			if strings.TrimSpace(name) == "" {
				return usageErrorf("key import requires --name")
			}
			if strings.TrimSpace(inputPath) == "" {
				return usageErrorf("key import requires --from")
			}

			raw, err := os.ReadFile(inputPath)
			if err != nil {
				return mapCommandError(err)
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.key.ImportKey(ctx, &v1.ImportKeyRequest{
					Name:       name,
					PrivateKey: raw,
					Passphrase: []byte(passphrase),
				})
				if err != nil {
					return err
				}
				return printKeyMetaOutput(deps, resp.GetKey())
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Key name")
	cmd.Flags().StringVar(&inputPath, "from", "", "Input private key file")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Import passphrase for encrypted key")
	return cmd
}

func newKeyExportCommand(deps commandDeps) *cobra.Command {
	var (
		outputPath string
		private    bool
		reauth     bool
	)
	cmd := &cobra.Command{
		Use:   "export <name>",
		Short: "Export key material",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("key export requires a key name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if private && !reauth {
				return asExitError(ExitCodePermission, fmt.Errorf("key export --private requires re-authentication"))
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.key.ExportKey(ctx, &v1.ExportKeyRequest{Name: args[0]})
				if err != nil {
					return err
				}

				if !private {
					if deps.globals.JSON {
						return printJSON(deps.out, map[string]any{
							"name":       resp.GetName(),
							"key_type":   resp.GetKeyType(),
							"public_key": resp.GetPublicKey(),
						})
					}
					if deps.globals.Quiet {
						return nil
					}
					_, err = fmt.Fprintln(deps.out, resp.GetPublicKey())
					return err
				}

				if strings.TrimSpace(outputPath) == "" {
					return usageErrorf("key export --private requires --output")
				}
				if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(outputPath, resp.GetPrivateKey(), 0o600); err != nil {
					return err
				}

				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"name":   args[0],
						"output": outputPath,
					})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "key exported to %s\n", outputPath)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "Output path for private key")
	cmd.Flags().BoolVar(&private, "private", false, "Export private key material")
	cmd.Flags().BoolVar(&reauth, "reauth", false, "Confirm re-authentication completed")
	return cmd
}

func newKeyListCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List key metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("key ls does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.key.ListKeys(ctx, &v1.ListKeysRequest{})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, resp.GetKeys())
				}
				if deps.globals.Quiet {
					return nil
				}
				for _, key := range resp.GetKeys() {
					if _, err := fmt.Fprintf(deps.out, "%s type=%s status=%s\n", key.GetName(), key.GetKeyType(), key.GetStatus()); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
}

func newKeyShowCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show key metadata",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("key show requires exactly one key name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.key.ShowKey(ctx, &v1.ShowKeyRequest{Name: args[0]})
				if err != nil {
					return err
				}
				return printKeyMetaOutput(deps, resp.GetKey())
			})
		},
	}
}

func newKeyRemoveCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a key",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("key rm requires exactly one key name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.key.DeleteKey(ctx, &v1.DeleteKeyRequest{Name: args[0]})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"deleted": args[0]})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "key removed: %s\n", args[0])
				return err
			})
		},
	}
}

func newKeyRotateCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <name>",
		Short: "Rotate a key",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("key rotate requires exactly one key name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.key.RotateKey(ctx, &v1.RotateKeyRequest{Name: args[0]})
				if err != nil {
					return err
				}
				return printKeyMetaOutput(deps, resp.GetKey())
			})
		},
	}
}

func printKeyMetaOutput(deps commandDeps, key *v1.KeyMeta) error {
	if deps.globals.JSON {
		return printJSON(deps.out, key)
	}
	if deps.globals.Quiet {
		return nil
	}
	_, err := fmt.Fprintf(
		deps.out,
		"%s type=%s status=%s\n",
		key.GetName(),
		key.GetKeyType(),
		key.GetStatus(),
	)
	return err
}
