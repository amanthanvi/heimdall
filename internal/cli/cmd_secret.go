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

func newSecretCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Secret management",
	}
	cmd.AddCommand(
		newSecretAddCommand(deps),
		newSecretListCommand(deps),
		newSecretShowCommand(deps),
		newSecretRemoveCommand(deps),
		newSecretExportCommand(deps),
		newSecretEnvCommand(deps),
		newSecretUnsupportedCommand("set-policy"),
	)
	return cmd
}

func newSecretUnsupportedCommand(name string) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: fmt.Sprintf("%s secret settings (not yet implemented)", name),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mapCommandError(fmt.Errorf("%s is not implemented", cmd.CommandPath()))
		},
	}
}

func newSecretAddCommand(deps commandDeps) *cobra.Command {
	var (
		name         string
		value        string
		revealPolicy string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("secret add does not accept positional arguments")
			}
			if strings.TrimSpace(name) == "" {
				return usageErrorf("secret add requires --name")
			}
			if value == "" {
				return usageErrorf("secret add requires --value")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.secret.CreateSecret(ctx, &v1.CreateSecretRequest{
					Name:         name,
					Value:        []byte(value),
					RevealPolicy: revealPolicy,
				})
				if err != nil {
					return err
				}
				return printSecretMetaOutput(deps, resp.GetSecret())
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Secret name")
	cmd.Flags().StringVar(&value, "value", "", "Secret value")
	cmd.Flags().StringVar(&revealPolicy, "reveal-policy", "", "Reveal policy (once-per-unlock|always-reauth)")
	return cmd
}

func newSecretListCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List secret metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("secret ls does not accept positional arguments")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.secret.ListSecrets(ctx, &v1.ListSecretsRequest{})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, resp.GetSecrets())
				}
				if deps.globals.Quiet {
					return nil
				}
				for _, secret := range resp.GetSecrets() {
					if _, err := fmt.Fprintf(deps.out, "%s (%d bytes)\n", secret.GetName(), secret.GetSizeBytes()); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
}

func newSecretShowCommand(deps commandDeps) *cobra.Command {
	var reauth bool
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Reveal a secret value",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("secret show requires exactly one secret name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if !reauth {
				return asExitError(ExitCodePermission, fmt.Errorf("secret show requires re-authentication"))
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: args[0]})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"name":  args[0],
						"value": string(resp.GetValue()),
					})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintln(deps.out, string(resp.GetValue()))
				return err
			})
		},
	}
	cmd.Flags().BoolVar(&reauth, "reauth", false, "Confirm re-authentication completed")
	return cmd
}

func newSecretRemoveCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a secret",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("secret rm requires exactly one secret name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.secret.DeleteSecret(ctx, &v1.DeleteSecretRequest{Name: args[0]})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"deleted": args[0]})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "secret removed: %s\n", args[0])
				return err
			})
		},
	}
}

func newSecretExportCommand(deps commandDeps) *cobra.Command {
	var (
		outputPath string
		reauth     bool
	)
	cmd := &cobra.Command{
		Use:   "export <name>",
		Short: "Export secret value to a file",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("secret export requires exactly one secret name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if !reauth {
				return asExitError(ExitCodePermission, fmt.Errorf("secret export requires re-authentication"))
			}
			if strings.TrimSpace(outputPath) == "" {
				return usageErrorf("secret export requires --output")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.secret.GetSecretValue(ctx, &v1.GetSecretValueRequest{Name: args[0]})
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(outputPath, resp.GetValue(), 0o600); err != nil {
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
				_, err = fmt.Fprintf(deps.out, "secret exported: %s\n", outputPath)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "Output path")
	cmd.Flags().BoolVar(&reauth, "reauth", false, "Confirm re-authentication completed")
	return cmd
}

func newSecretEnvCommand(deps commandDeps) *cobra.Command {
	var envVar string
	cmd := &cobra.Command{
		Use:   "env <name> -- <command...>",
		Short: "Inject a secret into a subprocess environment variable",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return usageErrorf("secret env requires a secret name and a command after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			index := cmd.ArgsLenAtDash()
			if index < 1 || index >= len(args) {
				return usageErrorf("secret env usage: secret env <name> -- <command...>")
			}
			if index != 1 {
				return usageErrorf("secret env accepts exactly one secret name before --")
			}
			secretName := args[0]
			command := args[index:]
			if envVar == "" {
				envVar = secretToEnvVar(secretName)
			}

			err := withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				exitCode, err := runSecretEnv(ctx, clients.secret, secretName, envVar, command, nil, deps.out, deps.errOut)
				if err != nil {
					return err
				}
				if exitCode != 0 {
					return &ExitError{
						Code: exitCode,
						Err:  fmt.Errorf("secret env command exited with code %d", exitCode),
					}
				}
				return nil
			})
			return err
		},
	}
	cmd.Flags().StringVar(&envVar, "env-var", "", "Environment variable name (default derived from secret)")
	cmd.Flags().StringVar(&envVar, "var", "", "Environment variable name (deprecated alias for --env-var)")
	return cmd
}

func printSecretMetaOutput(deps commandDeps, secret *v1.SecretMeta) error {
	if deps.globals.JSON {
		return printJSON(deps.out, secret)
	}
	if deps.globals.Quiet {
		return nil
	}
	_, err := fmt.Fprintf(deps.out, "%s (%d bytes)\n", secret.GetName(), secret.GetSizeBytes())
	return err
}

func secretToEnvVar(name string) string {
	upper := strings.ToUpper(name)
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_")
	return replacer.Replace(upper)
}
