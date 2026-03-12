package app

import (
	"context"
	"fmt"
	"strings"

	sshpkg "github.com/amanthanvi/heimdall/internal/ssh"
	"github.com/amanthanvi/heimdall/internal/storage"
)

type ConnectService struct {
	hosts storage.HostRepository
}

const disableIdentityPathSentinel = "__heimdall_disable_identity__"

func NewConnectService(hosts storage.HostRepository) *ConnectService {
	return &ConnectService{hosts: hosts}
}

func (s *ConnectService) Plan(ctx context.Context, hostName string, opts ConnectOpts) (*ConnectPlan, error) {
	if strings.TrimSpace(hostName) == "" {
		return nil, fmt.Errorf("%w: host name is required", ErrValidation)
	}

	host, err := s.hosts.Get(ctx, hostName)
	if err != nil {
		return nil, fmt.Errorf("build connect plan: load host: %w", err)
	}

	user := strings.TrimSpace(opts.User)
	if user == "" {
		user = host.User
	}
	if user != "" && (strings.HasPrefix(user, "-") || !sshUserPattern.MatchString(user)) {
		return nil, fmt.Errorf("%w: user %q contains invalid characters", ErrValidation, user)
	}
	port := opts.Port
	if port == 0 {
		port = host.Port
	}
	if port == 0 {
		port = 22
	}

	effectiveJumpHosts := append([]string(nil), opts.JumpHosts...)
	if len(effectiveJumpHosts) == 0 {
		defaultJump := strings.TrimSpace(host.ProxyJump)
		if defaultJump != "" {
			effectiveJumpHosts = []string{defaultJump}
		}
	}

	effectiveIdentityPath := strings.TrimSpace(opts.IdentityPath)
	disableIdentityDefaults := effectiveIdentityPath == disableIdentityPathSentinel
	if disableIdentityDefaults {
		effectiveIdentityPath = ""
	}
	if effectiveIdentityPath == "" && !disableIdentityDefaults {
		effectiveIdentityPath = strings.TrimSpace(host.IdentityFile)
	}
	sshHost := &sshpkg.Host{
		Name:             host.Name,
		Address:          host.Address,
		Port:             port,
		User:             user,
		JumpHosts:        effectiveJumpHosts,
		IdentityPath:     effectiveIdentityPath,
		ForwardAgent:     host.ForwardAgent,
		KnownHostsPolicy: host.KnownHostsPolicy,
	}
	knownHostsPolicy := host.KnownHostsPolicy
	if strings.TrimSpace(opts.KnownHostsPolicy) != "" {
		knownHostsPolicy = strings.TrimSpace(opts.KnownHostsPolicy)
	}
	forwardAgent := host.ForwardAgent
	if opts.ForwardAgentSet {
		forwardAgent = opts.ForwardAgent
	}
	builder := &sshpkg.CommandBuilder{}
	command, err := builder.Build(sshHost, sshpkg.ConnectOpts{
		User:             user,
		Port:             port,
		JumpHosts:        effectiveJumpHosts,
		ProxyJumpNone:    opts.ProxyJumpNone,
		Forwards:         append([]string(nil), opts.Forwards...),
		IdentityPath:     effectiveIdentityPath,
		ForwardAgent:     forwardAgent,
		KnownHostsFile:   opts.KnownHosts,
		KnownHostsPolicy: knownHostsPolicy,
		InsecureHostKey:  opts.InsecureHostKey,
		IgnoreSSHConfig:  opts.IgnoreSSHConfig,
		Env:              nil,
	})
	if err != nil {
		return nil, fmt.Errorf("build connect plan: %w", err)
	}

	return &ConnectPlan{
		Binary:       command.Binary,
		Args:         append([]string(nil), command.Args...),
		RedactedArgs: redactConnectArgs(append([]string{command.Binary}, command.Args...))[1:],
		Env:          append([]string(nil), command.Env...),
	}, nil
}

func redactConnectArgs(args []string) []string {
	redacted := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-i" && i+1 < len(args) {
			redacted = append(redacted, "-i", "[REDACTED]")
			i++
			continue
		}
		redacted = append(redacted, args[i])
	}
	return redacted
}
