package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/amanthanvi/heimdall/internal/storage"
)

type ConnectService struct {
	hosts storage.HostRepository
}

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

	user := opts.User
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

	target := host.Address
	if user != "" {
		target = user + "@" + host.Address
	}

	args := []string{"ssh", "-p", strconv.Itoa(port)}
	for _, jh := range opts.JumpHosts {
		if strings.HasPrefix(jh, "-") {
			return nil, fmt.Errorf("%w: jump host %q contains invalid characters", ErrValidation, jh)
		}
	}
	if len(opts.JumpHosts) > 0 {
		args = append(args, "-J", strings.Join(opts.JumpHosts, ","))
	}

	for _, forward := range opts.Forwards {
		prefix, spec, ok := parseForward(forward)
		if !ok {
			return nil, fmt.Errorf("%w: invalid forward %q", ErrValidation, forward)
		}
		args = append(args, prefix, spec)
	}

	if opts.IdentityPath != "" {
		args = append(args, "-i", opts.IdentityPath, "-o", "IdentitiesOnly=yes")
	}
	if opts.KnownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+opts.KnownHosts)
	}
	// End-of-options separator prevents target from being parsed as SSH flags.
	args = append(args, "--", target)

	return &ConnectPlan{
		Args:         args,
		RedactedArgs: redactConnectArgs(args),
	}, nil
}

func parseForward(raw string) (flag string, spec string, ok bool) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	mode := strings.ToUpper(strings.TrimSpace(parts[0]))
	spec = strings.TrimSpace(parts[1])
	if spec == "" {
		return "", "", false
	}

	switch mode {
	case "L":
		return "-L", spec, true
	case "R":
		return "-R", spec, true
	case "D":
		return "-D", spec, true
	default:
		return "", "", false
	}
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
