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
		map[string]string{},
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
		name             string
		address          string
		port             int32
		user             string
		tags             []string
		notes            string
		keyName          string
		identityFile     string
		proxyJump        string
		knownHostsPolicy string
		forwardAgent     bool
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
				resp, err := clients.host.CreateHost(ctx, &v1.CreateHostRequest{
					Name:             name,
					Address:          address,
					Port:             port,
					User:             user,
					Tags:             append([]string(nil), tags...),
					Notes:            notes,
					KeyName:          keyName,
					IdentityPath:     identityFile,
					ProxyJump:        proxyJump,
					KnownHostsPolicy: knownHostsPolicy,
					ForwardAgent:     forwardAgent,
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
	cmd.Flags().StringVar(&notes, "notes", "", "Encrypted operator notes")
	cmd.Flags().StringVar(&keyName, "key", "", "Default vault key name used by connect")
	cmd.Flags().StringVar(&identityFile, "identity-file", "", "Default identity file used by connect")
	cmd.Flags().StringVar(&proxyJump, "proxy-jump", "", "Default SSH ProxyJump used by connect")
	cmd.Flags().StringVar(&knownHostsPolicy, "known-hosts-policy", "", "Default known_hosts policy (tofu|accept-new|strict|off)")
	cmd.Flags().BoolVar(&forwardAgent, "forward-agent", false, "Default to agent forwarding for this host")
	return cmd
}

func newHostListCommand(deps commandDeps) *cobra.Command {
	var (
		namesOnly bool
		tag       string
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
				hosts := filterHosts(resp.GetHosts(), tag, search)
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
		newName               string
		address               string
		port                  int32
		user                  string
		tags                  []string
		clearTags             bool
		notes                 string
		clearNotes            bool
		keyName               string
		identityFile          string
		proxyJump             string
		knownHostsPolicy      string
		clearKnownHostsPolicy bool
		clearKey              bool
		clearIdentityFile     bool
		clearProxyJump        bool
		forwardAgent          bool
		noForwardAgent        bool
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
			if clearNotes && strings.TrimSpace(notes) != "" {
				return usageErrorf("host edit cannot combine --notes and --clear-notes")
			}
			if clearKnownHostsPolicy && strings.TrimSpace(knownHostsPolicy) != "" {
				return usageErrorf("host edit cannot combine --known-hosts-policy and --clear-known-hosts-policy")
			}
			if forwardAgent && noForwardAgent {
				return usageErrorf("host edit cannot combine --forward-agent and --no-forward-agent")
			}
			return withDaemonClients(cmd.Context(), deps, func(ctx context.Context, clients daemonClients) error {
				req := &v1.UpdateHostRequest{
					Name:                   args[0],
					NewName:                newName,
					Address:                address,
					Port:                   port,
					ClearTags:              clearTags,
					ClearNotes:             clearNotes,
					ClearKeyName:           clearKey,
					ClearIdentityPath:      clearIdentityFile,
					ClearProxyJump:         clearProxyJump,
					ClearKnownHostsPolicy:  clearKnownHostsPolicy,
					ForwardAgent:           forwardAgent,
					ForwardAgentSet:        forwardAgent || noForwardAgent,
				}
				if user != "" {
					req.User = user
				}
				if len(tags) > 0 {
					req.Tags = append([]string(nil), tags...)
				}
				if notes != "" {
					req.Notes = notes
				}
				if keyName != "" {
					req.KeyName = keyName
				}
				if identityFile != "" {
					req.IdentityPath = identityFile
				}
				if proxyJump != "" {
					req.ProxyJump = proxyJump
				}
				if knownHostsPolicy != "" {
					req.KnownHostsPolicy = knownHostsPolicy
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
	cmd.Flags().StringVar(&notes, "notes", "", "Updated encrypted operator notes")
	cmd.Flags().BoolVar(&clearNotes, "clear-notes", false, "Clear operator notes")
	cmd.Flags().StringVar(&keyName, "key", "", "Updated default vault key name used by connect")
	cmd.Flags().StringVar(&identityFile, "identity-file", "", "Updated default identity file used by connect")
	cmd.Flags().StringVar(&proxyJump, "proxy-jump", "", "Updated default SSH ProxyJump used by connect")
	cmd.Flags().StringVar(&knownHostsPolicy, "known-hosts-policy", "", "Updated default known_hosts policy")
	cmd.Flags().BoolVar(&clearKnownHostsPolicy, "clear-known-hosts-policy", false, "Clear known_hosts policy override")
	cmd.Flags().BoolVar(&clearKey, "clear-key", false, "Clear default connect key")
	cmd.Flags().BoolVar(&clearIdentityFile, "clear-identity-file", false, "Clear default identity file")
	cmd.Flags().BoolVar(&clearProxyJump, "clear-proxy-jump", false, "Clear default ProxyJump")
	cmd.Flags().BoolVar(&forwardAgent, "forward-agent", false, "Enable agent forwarding by default for this host")
	cmd.Flags().BoolVar(&noForwardAgent, "no-forward-agent", false, "Disable agent forwarding by default for this host")
	return cmd
}

func filterHosts(hosts []*v1.Host, tag, search string) []*v1.Host {
	if len(hosts) == 0 {
		return nil
	}

	wantTag := strings.ToLower(strings.TrimSpace(tag))
	needle := strings.ToLower(strings.TrimSpace(search))

	out := make([]*v1.Host, 0, len(hosts))
	for _, host := range hosts {
		if host == nil {
			continue
		}
		if wantTag != "" && !containsTag(host.GetTags(), wantTag) {
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
	if value := strings.TrimSpace(host.GetKeyName()); value != "" {
		connectDefaults = append(connectDefaults, "key="+value)
	}
	if value := strings.TrimSpace(host.GetIdentityPath()); value != "" {
		connectDefaults = append(connectDefaults, "identity_path="+value)
	}
	if value := strings.TrimSpace(host.GetProxyJump()); value != "" {
		connectDefaults = append(connectDefaults, "proxy_jump="+value)
	}
	if value := strings.TrimSpace(host.GetKnownHostsPolicy()); value != "" {
		connectDefaults = append(connectDefaults, "known_hosts_policy="+value)
	}
	if host.GetForwardAgent() {
		connectDefaults = append(connectDefaults, "forward_agent=true")
	}
	connectSuffix := ""
	if len(connectDefaults) > 0 {
		connectSuffix = " connect=" + strings.Join(connectDefaults, ",")
	}
	noteSuffix := ""
	if strings.TrimSpace(host.GetNotes()) != "" {
		noteSuffix = " notes=set"
	}
	_, err := fmt.Fprintf(
		deps.out,
		"%s %s:%d user=%s tags=%s%s%s\n",
		host.GetName(),
		host.GetAddress(),
		host.GetPort(),
		host.GetUser(),
		strings.Join(host.GetTags(), ","),
		noteSuffix,
		connectSuffix,
	)
	return err
}
