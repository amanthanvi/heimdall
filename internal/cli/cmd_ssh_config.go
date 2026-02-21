package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newSSHConfigCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ssh-config",
		Short:   "OpenSSH config utilities",
		Example: "  heimdall ssh-config generate --output ~/.ssh/heimdall_hosts",
	}
	cmd.AddCommand(newSSHConfigGenerateCommand(deps))
	return cmd
}

func newSSHConfigGenerateCommand(deps commandDeps) *cobra.Command {
	var outputPath string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate OpenSSH config blocks from vault hosts",
		Example: "  heimdall ssh-config generate --output ~/.ssh/heimdall_hosts\n" +
			"  heimdall --json ssh-config generate --output ./ssh_config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("ssh-config generate does not accept positional arguments")
			}
			if strings.TrimSpace(outputPath) == "" {
				return usageErrorf("ssh-config generate requires --output")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.host.ListHosts(ctx, &v1.ListHostsRequest{})
				if err != nil {
					return err
				}

				rendered := renderSSHConfig(resp.GetHosts())
				if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(outputPath, []byte(rendered), 0o600); err != nil {
					return err
				}

				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{
						"output": outputPath,
						"hosts":  len(resp.GetHosts()),
					})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "ssh-config written: %s (hosts=%d)\n", outputPath, len(resp.GetHosts()))
				return err
			})
		},
	}
	cmd.Flags().StringVar(&outputPath, "output", "", "Output path for generated OpenSSH config")
	return cmd
}

func renderSSHConfig(hosts []*v1.Host) string {
	items := make([]*v1.Host, 0, len(hosts))
	for _, host := range hosts {
		if host == nil || strings.TrimSpace(host.GetName()) == "" {
			continue
		}
		items = append(items, host)
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].GetName() < items[j].GetName()
	})

	var builder strings.Builder
	for idx, host := range items {
		if idx > 0 {
			builder.WriteByte('\n')
		}

		builder.WriteString("Host ")
		builder.WriteString(host.GetName())
		builder.WriteByte('\n')
		builder.WriteString("  HostName ")
		builder.WriteString(host.GetAddress())
		builder.WriteByte('\n')

		if user := strings.TrimSpace(host.GetUser()); user != "" {
			builder.WriteString("  User ")
			builder.WriteString(user)
			builder.WriteByte('\n')
		}

		port := host.GetPort()
		if port == 0 {
			port = 22
		}
		fmt.Fprintf(&builder, "  Port %d\n", port)

		envRefs := host.GetEnvRefs()
		if jump := strings.TrimSpace(envRefs["proxy_jump"]); jump != "" {
			builder.WriteString("  ProxyJump ")
			builder.WriteString(jump)
			builder.WriteByte('\n')
		}
		if identity := strings.TrimSpace(envRefs["identity_ref"]); identity != "" {
			builder.WriteString("  IdentityFile ")
			builder.WriteString(identity)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}
