package cli

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newHostCommand(deps commandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Host management",
	}
	cmd.AddCommand(
		newHostAddCommand(deps),
		newHostListCommand(deps),
		newHostShowCommand(deps),
		newHostRemoveCommand(deps),
		newHostEditCommand(deps),
		newHostUnsupportedCommand("test"),
		newHostUnsupportedCommand("trust"),
		newHostTemplateCommand(),
	)
	return cmd
}

func newHostUnsupportedCommand(name string) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: fmt.Sprintf("%s host settings (not yet implemented)", name),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mapCommandError(fmt.Errorf("%s is not implemented", cmd.CommandPath()))
		},
	}
}

func newHostTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Host template operations",
	}
	cmd.AddCommand(
		newHostUnsupportedCommand("add"),
		newHostUnsupportedCommand("edit"),
		newHostUnsupportedCommand("rm"),
		newHostUnsupportedCommand("ls"),
		newHostUnsupportedCommand("show"),
	)
	return cmd
}

func newHostAddCommand(deps commandDeps) *cobra.Command {
	var (
		name    string
		address string
		port    int32
		user    string
		tags    []string
		group   string
		envRefs []string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a host",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("host add does not accept positional arguments")
			}
			if strings.TrimSpace(name) == "" {
				return usageErrorf("host add requires --name")
			}
			if strings.TrimSpace(address) == "" {
				return usageErrorf("host add requires --addr")
			}
			if port < 1 || port > 65535 {
				return usageErrorf("host add --port must be between 1 and 65535")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.host.CreateHost(ctx, &v1.CreateHostRequest{
					Name:    name,
					Address: address,
					Port:    port,
					User:    user,
					Tags:    append([]string(nil), tags...),
					Group:   group,
					EnvRefs: parseKeyValuePairs(envRefs),
				})
				if err != nil {
					return err
				}
				return printHostOutput(deps, resp.GetHost())
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Host name")
	cmd.Flags().StringVar(&address, "addr", "", "Host address")
	cmd.Flags().Int32Var(&port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&user, "user", "", "SSH user")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Host tag (repeatable)")
	cmd.Flags().StringVar(&group, "group", "", "Host group")
	cmd.Flags().StringSliceVar(&envRefs, "env-ref", nil, "Host environment reference key=value (repeatable)")
	return cmd
}

func newHostListCommand(deps commandDeps) *cobra.Command {
	var (
		namesOnly bool
		tag       string
		group     string
		search    string
	)

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("host ls does not accept positional arguments")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.host.ListHosts(ctx, &v1.ListHostsRequest{NamesOnly: namesOnly})
				if err != nil {
					return err
				}
				hosts := filterHosts(resp.GetHosts(), tag, group, search)
				if deps.globals.JSON {
					return printJSON(deps.out, hosts)
				}
				if deps.globals.Quiet {
					return nil
				}
				for _, host := range hosts {
					if namesOnly {
						if _, err := fmt.Fprintln(deps.out, host.GetName()); err != nil {
							return err
						}
						continue
					}
					if _, err := fmt.Fprintf(
						deps.out,
						"%s %s:%d user=%s\n",
						host.GetName(),
						host.GetAddress(),
						host.GetPort(),
						host.GetUser(),
					); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&namesOnly, "names-only", false, "Only print host names")
	cmd.Flags().StringVar(&tag, "tag", "", "Filter by tag")
	cmd.Flags().StringVar(&group, "group", "", "Filter by group tag")
	cmd.Flags().StringVar(&search, "search", "", "Case-insensitive search on name/address/user/tags")
	return cmd
}

func newHostShowCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show host details",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("host show requires exactly one host name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				resp, err := clients.host.GetHost(ctx, &v1.GetHostRequest{Name: args[0]})
				if err != nil {
					return err
				}
				return printHostOutput(deps, resp.GetHost())
			})
		},
	}
}

func newHostRemoveCommand(deps commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a host",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("host rm requires exactly one host name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				_, err := clients.host.DeleteHost(ctx, &v1.DeleteHostRequest{Name: args[0]})
				if err != nil {
					return err
				}
				if deps.globals.JSON {
					return printJSON(deps.out, map[string]any{"deleted": args[0]})
				}
				if deps.globals.Quiet {
					return nil
				}
				_, err = fmt.Fprintf(deps.out, "host removed: %s\n", args[0])
				return err
			})
		},
	}
}

func newHostEditCommand(deps commandDeps) *cobra.Command {
	var (
		newName   string
		address   string
		port      int32
		user      string
		tags      []string
		clearTags bool
		envRefs   []string
	)

	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit an existing host",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("host edit requires exactly one host name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if port < 0 || port > 65535 {
				return usageErrorf("host edit --port must be between 1 and 65535 when provided")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				req := &v1.UpdateHostRequest{
					Name:      args[0],
					NewName:   newName,
					Address:   address,
					Port:      port,
					ClearTags: clearTags,
					EnvRefs:   parseKeyValuePairs(envRefs),
				}
				if user != "" {
					req.User = user
				}
				if len(tags) > 0 {
					req.Tags = append([]string(nil), tags...)
				}
				resp, err := clients.host.UpdateHost(ctx, req)
				if err != nil {
					return err
				}
				return printHostOutput(deps, resp.GetHost())
			})
		},
	}

	cmd.Flags().StringVar(&newName, "name", "", "Updated host name")
	cmd.Flags().StringVar(&address, "addr", "", "Updated host address")
	cmd.Flags().Int32Var(&port, "port", 0, "Updated SSH port")
	cmd.Flags().StringVar(&user, "user", "", "Updated SSH user")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Updated host tags")
	cmd.Flags().BoolVar(&clearTags, "clear-tags", false, "Remove all host tags")
	cmd.Flags().StringSliceVar(&envRefs, "env-ref", nil, "Updated environment reference key=value")
	return cmd
}

func filterHosts(hosts []*v1.Host, tag, group, search string) []*v1.Host {
	if len(hosts) == 0 {
		return nil
	}

	wantTag := strings.ToLower(strings.TrimSpace(tag))
	wantGroup := strings.ToLower(strings.TrimSpace(group))
	needle := strings.ToLower(strings.TrimSpace(search))

	out := make([]*v1.Host, 0, len(hosts))
	for _, host := range hosts {
		if host == nil {
			continue
		}
		if wantTag != "" && !containsTag(host.GetTags(), wantTag) {
			continue
		}
		if wantGroup != "" && !containsTag(host.GetTags(), "group:"+wantGroup) && !containsTag(host.GetTags(), wantGroup) {
			continue
		}
		if needle != "" {
			haystack := []string{host.GetName(), host.GetAddress(), host.GetUser(), strings.Join(host.GetTags(), " ")}
			matched := false
			for _, value := range haystack {
				if strings.Contains(strings.ToLower(value), needle) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		out = append(out, host)
	}
	return out
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if strings.ToLower(strings.TrimSpace(tag)) == want {
			return true
		}
	}
	return false
}

func printHostOutput(deps commandDeps, host *v1.Host) error {
	if deps.globals.JSON {
		return printJSON(deps.out, host)
	}
	if deps.globals.Quiet {
		return nil
	}
	_, err := fmt.Fprintf(
		deps.out,
		"%s %s:%d user=%s tags=%s\n",
		host.GetName(),
		host.GetAddress(),
		host.GetPort(),
		host.GetUser(),
		strings.Join(host.GetTags(), ","),
	)
	return err
}

func parseKeyValuePairs(values []string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, raw := range values {
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
