package openssh

import (
	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/transport"
)

func ExpectedRouteOptions(cfg model.Config, named model.NamedHostRoute) map[string][]string {
	route := named.Route
	ctx := cfg.Contexts[named.Context]
	identityName := firstNonEmpty(route.Identity, ctx.Identity)
	identity := cfg.Identities[identityName]
	agentName := firstNonEmpty(route.Agent, ctx.Agent, identity.AgentSelector)
	agent := cfg.Agents.Selectors[agentName]

	options := map[string][]string{
		"identityagent":   nil,
		"identityfile":    nil,
		"certificatefile": nil,
		"identitiesonly":  {"yes"},
		"forwardagent":    {"no"},
		"proxyjump":       nil,
		"proxycommand":    nil,
	}
	if endpoint := resolveEndpoint(agent); endpoint != "" {
		options["identityagent"] = []string{endpoint}
	}
	if identity.PrivateKeyPathRef != "" {
		options["identityfile"] = []string{expandPath(identity.PrivateKeyPathRef)}
	}
	if certFile := firstNonEmpty(route.CertificateFile, identity.CertificatePath); certFile != "" {
		options["certificatefile"] = []string{expandPath(certFile)}
	}
	if route.IdentitiesOnly != nil {
		options["identitiesonly"] = []string{yesNo(*route.IdentitiesOnly)}
	}
	if route.ForwardAgent != "" {
		options["forwardagent"] = []string{route.ForwardAgent}
	} else if forwardingEnabled(ctx.Forwarding) {
		options["forwardagent"] = []string{"yes"}
	}
	if route.ProxyJump != "" {
		options["proxyjump"] = []string{route.ProxyJump}
	}
	if route.ProxyCommand != "" {
		options["proxycommand"] = []string{route.ProxyCommand}
	} else if route.Transport != "" {
		if command := transport.RenderProxyCommand(cfg.Transports[route.Transport]); command != "" {
			options["proxycommand"] = []string{command}
		}
	}
	return options
}
