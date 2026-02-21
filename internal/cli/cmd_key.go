package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newKeyCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "SSH key management",
		Example: "  heimdall key gen --name deploy\n" +
			"  heimdall key ls\n" +
			"  heimdall key export deploy --private --reauth --output ./deploy.key",
	}
	cmd.AddCommand(
		newKeyGenerateCommand(deps),
		newKeyImportCommand(deps),
		newKeyExportCommand(deps),
		newKeyListCommand(deps),
		newKeyShowCommand(deps),
		newKeyRemoveCommand(deps),
		newKeyRotateCommand(deps),
		newKeyAgentCommand(deps),
	)
	return cmd
}

func newKeyAgentCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "SSH agent key operations",
		Example: "  heimdall key agent add deploy --ttl 30m\n" +
			"  heimdall key agent rm SHA256:abc123",
	}
	cmd.AddCommand(
		newKeyAgentAddCommand(deps),
		newKeyAgentRemoveCommand(deps),
	)
	return cmd
}

func newKeyGenerateCommand(deps commandDeps) *cobra.Command {
	var (
		name    string
		keyType string
	)
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a new key",
		Example: "  heimdall key gen --name deploy\n" +
			"  heimdall key gen --name ci-rsa --type rsa",
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

func newKeyAgentAddCommand(deps commandDeps) *cobra.Command {
	var (
		sessionID string
		ttl       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a private key to the managed SSH agent",
		Example: "  heimdall key agent add deploy\n" +
			"  heimdall key agent add deploy --ttl 1h --session-id build-123",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("key agent add requires exactly one key name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if ttl < 0 {
				return usageErrorf("key agent add --ttl must be >= 0")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.key.AgentAdd(ctx, &v1.AgentAddRequest{
					Name:       args[0],
					SessionId:  sessionID,
					TtlSeconds: int64(ttl / time.Second),
				})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"name":        args[0],
						"fingerprint": resp.GetFingerprint(),
					})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "key added to agent: %s (%s)\n", args[0], resp.GetFingerprint())
				return err
			})
		},
	}
	cmd.Flags().StringVar(&sessionID, "session-id", "", "Optional session ID for signing scope")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "Optional key TTL")
	return cmd
}

func newKeyAgentRemoveCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:     "rm <fingerprint>",
		Short:   "Remove a key from the managed SSH agent by fingerprint",
		Example: "  heimdall key agent rm SHA256:abc123",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("key agent rm requires exactly one fingerprint")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.key.AgentRemove(ctx, &v1.AgentRemoveRequest{Fingerprint: args[0]})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"removed": args[0]})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "key removed from agent: %s\n", args[0])
				return err
			})
		},
	}
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
		Example: "  heimdall key import --name deploy --from ./deploy.key\n" +
			"  heimdall key import --name deploy --from ./deploy.enc --passphrase \"key-pass\"",
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
		Example: "  heimdall key export deploy\n" +
			"  heimdall key export deploy --private --reauth --output ./deploy.key",
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
		Example: "  heimdall key ls\n" +
			"  heimdall --json key ls",
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
		Example: "  heimdall key show deploy\n" +
			"  heimdall --json key show deploy",
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
		Use:     "rm <name>",
		Short:   "Delete a key",
		Example: "  heimdall key rm deploy",
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
		Use:     "rotate <name>",
		Short:   "Rotate a key",
		Example: "  heimdall key rotate deploy",
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
