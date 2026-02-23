package cli

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/amanthanvi/heimdall/api/v1"
	"github.com/spf13/cobra"
)

func newHostCommand(deps commandDeps) *cobra.Command {
	cmd := newGroupCommand(
		"host",
		"Host management",
		"  heimdall host add --name prod --address 10.0.0.10 --user ubuntu\n"+
			"  heimdall host list\n"+
			"  heimdall host show prod",
		map[string]string{
			"ls": "list",
			"rm": "remove",
		},
	)
	cmd.AddCommand(
		newHostAddCommand(deps),
		newHostListCommand(deps),
		newHostShowCommand(deps),
		newHostRemoveCommand(deps),
		newHostEditCommand(deps),
	)
	return cmd
}

func newHostAddCommand(deps commandDeps) *cobra.Command {
	var (
		name         string
		address      string
		port         int32
		user         string
		tags         []string
		group        string
		keyName      string
		identityFile string
		proxyJump    string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a host",
		Example: "  heimdall host add --name prod --address 10.0.0.10 --user ubuntu\n" +
			"  heimdall host add --name db --address 10.0.0.20 --user postgres --key deploy --proxy-jump bastion",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("host add does not accept positional arguments")
			}
			if strings.TrimSpace(name) == "" {
				return usageErrorf("host add requires --name")
			}
			if strings.TrimSpace(address) == "" {
				return usageErrorf("host add requires --address")
			}
			if port < 1 || port > 65535 {
				return usageErrorf("host add --port must be between 1 and 65535")
			}
			if strings.TrimSpace(keyName) != "" && strings.TrimSpace(identityFile) != "" {
				return usageErrorf("host add cannot set both --key and --identity-file")
			}

			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				envRefs := map[string]string{}
				if value := strings.TrimSpace(keyName); value != "" {
					envRefs["key_name"] = value
				}
				if value := strings.TrimSpace(identityFile); value != "" {
					envRefs["identity_ref"] = value
				}
				if value := strings.TrimSpace(proxyJump); value != "" {
					envRefs["proxy_jump"] = value
				}
				if len(envRefs) == 0 {
					envRefs = nil
				}
				resp, err := clients.host.CreateHost(ctx, &v1.CreateHostRequest{
					Name:    name,
					Address: address,
					Port:    port,
					User:    user,
					Tags:    append([]string(nil), tags...),
					Group:   group,
					EnvRefs: envRefs,
				})
				if err != nil {
					return err
				}
				return printHostOutput(deps, resp.GetHost())
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Host name")
	cmd.Flags().StringVar(&address, "address", "", "Host address")
	cmd.Flags().Int32Var(&port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&user, "user", "", "SSH user")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Host tag (repeatable)")
	cmd.Flags().StringVar(&group, "group", "", "Host group")
	cmd.Flags().StringVar(&keyName, "key", "", "Default vault key name used by connect")
	cmd.Flags().StringVar(&identityFile, "identity-file", "", "Default identity file used by connect")
	cmd.Flags().StringVar(&proxyJump, "proxy-jump", "", "Default SSH ProxyJump used by connect")
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
		Use:   "list",
		Short: "List hosts",
		Example: "  heimdall host list\n" +
			"  heimdall host list --names-only\n" +
			"  heimdall host list --tag critical --search prod",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return usageErrorf("host list does not accept positional arguments")
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
		Example: "  heimdall host show prod\n" +
			"  heimdall --json host show prod",
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
		Use:     "remove <name>",
		Short:   "Remove a host",
		Example: "  heimdall host remove prod",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErrorf("host remove requires exactly one host name")
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
		newName           string
		address           string
		port              int32
		user              string
		tags              []string
		clearTags         bool
		keyName           string
		identityFile      string
		proxyJump         string
		clearKey          bool
		clearIdentityFile bool
		clearProxyJump    bool
	)

	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit an existing host",
		Example: "  heimdall host edit prod --address 10.0.0.11 --user root\n" +
			"  heimdall host edit prod --key deploy --proxy-jump bastion",
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
			if strings.TrimSpace(keyName) != "" && strings.TrimSpace(identityFile) != "" {
				return usageErrorf("host edit cannot set both --key and --identity-file")
			}
			if clearKey && strings.TrimSpace(keyName) != "" {
				return usageErrorf("host edit cannot combine --key and --clear-key")
			}
			if clearIdentityFile && strings.TrimSpace(identityFile) != "" {
				return usageErrorf("host edit cannot combine --identity-file and --clear-identity-file")
			}
			if clearProxyJump && strings.TrimSpace(proxyJump) != "" {
				return usageErrorf("host edit cannot combine --proxy-jump and --clear-proxy-jump")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				envRefs := map[string]string{}
				if value := strings.TrimSpace(keyName); value != "" {
					envRefs["key_name"] = value
				} else if clearKey {
					envRefs["key_name"] = ""
				}
				if value := strings.TrimSpace(identityFile); value != "" {
					envRefs["identity_ref"] = value
				} else if clearIdentityFile {
					envRefs["identity_ref"] = ""
				}
				if value := strings.TrimSpace(proxyJump); value != "" {
					envRefs["proxy_jump"] = value
				} else if clearProxyJump {
					envRefs["proxy_jump"] = ""
				}
				if len(envRefs) == 0 {
					envRefs = nil
				}

				req := &v1.UpdateHostRequest{
					Name:      args[0],
					NewName:   newName,
					Address:   address,
					Port:      port,
					ClearTags: clearTags,
					EnvRefs:   envRefs,
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

	cmd.Flags().StringVar(&newName, "new-name", "", "Updated host name")
	cmd.Flags().StringVar(&address, "address", "", "Updated host address")
	cmd.Flags().Int32Var(&port, "port", 0, "Updated SSH port")
	cmd.Flags().StringVar(&user, "user", "", "Updated SSH user")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Updated host tags")
	cmd.Flags().BoolVar(&clearTags, "clear-tags", false, "Remove all host tags")
	cmd.Flags().StringVar(&keyName, "key", "", "Updated default vault key name used by connect")
	cmd.Flags().StringVar(&identityFile, "identity-file", "", "Updated default identity file used by connect")
	cmd.Flags().StringVar(&proxyJump, "proxy-jump", "", "Updated default SSH ProxyJump used by connect")
	cmd.Flags().BoolVar(&clearKey, "clear-key", false, "Clear default connect key")
	cmd.Flags().BoolVar(&clearIdentityFile, "clear-identity-file", false, "Clear default identity file")
	cmd.Flags().BoolVar(&clearProxyJump, "clear-proxy-jump", false, "Clear default ProxyJump")
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
	connectDefaults := []string{}
	if value := strings.TrimSpace(host.GetEnvRefs()["key_name"]); value != "" {
		connectDefaults = append(connectDefaults, "key="+value)
	}
	if value := strings.TrimSpace(host.GetEnvRefs()["identity_ref"]); value != "" {
		connectDefaults = append(connectDefaults, "identity_file="+value)
	}
	if value := strings.TrimSpace(host.GetEnvRefs()["proxy_jump"]); value != "" {
		connectDefaults = append(connectDefaults, "proxy_jump="+value)
	}
	connectSuffix := ""
	if len(connectDefaults) > 0 {
		connectSuffix = " connect=" + strings.Join(connectDefaults, ",")
	}
	_, err := fmt.Fprintf(
		deps.out,
		"%s %s:%d user=%s tags=%s%s\n",
		host.GetName(),
		host.GetAddress(),
		host.GetPort(),
		host.GetUser(),
		strings.Join(host.GetTags(), ","),
		connectSuffix,
	)
	return err
}
