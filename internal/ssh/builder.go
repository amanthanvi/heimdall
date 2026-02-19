package ssh

import (
	"fmt"
	"strconv"
	"strings"
)

func (b *CommandBuilder) Build(host *Host, opts ConnectOpts) (*SSHCommand, error) {
	if host == nil {
		return nil, fmt.Errorf("build ssh command: host is nil")
	}
	if strings.TrimSpace(host.Address) == "" {
		return nil, fmt.Errorf("build ssh command: host address is required")
	}

	binary := b.Binary
	if binary == "" {
		binary = "ssh"
	}

	user := firstNonEmpty(opts.User, host.User)
	port := opts.Port
	if port <= 0 {
		port = host.Port
	}
	if port <= 0 {
		port = 22
	}

	jumpHosts := opts.JumpHosts
	if len(jumpHosts) == 0 {
		jumpHosts = host.JumpHosts
	}
	identityPath := firstNonEmpty(opts.IdentityPath, host.IdentityPath)
	knownHostsPolicy := firstNonEmpty(opts.KnownHostsPolicy, host.KnownHostsPolicy)
	if knownHostsPolicy == "" {
		knownHostsPolicy = "tofu"
	}
	forwardAgent := opts.ForwardAgent || host.ForwardAgent

	args := []string{"-p", strconv.Itoa(port)}
	if opts.IgnoreSSHConfig {
		args = append(args, "-F", "/dev/null")
	}
	if opts.ProxyJumpNone {
		args = append(args, "-o", "ProxyJump=none")
	} else if len(jumpHosts) > 0 {
		args = append(args, "-J", strings.Join(jumpHosts, ","))
	}

	for _, forward := range opts.Forwards {
		flag, spec, err := parseForward(forward)
		if err != nil {
			return nil, err
		}
		args = append(args, flag, spec)
	}

	if identityPath != "" {
		args = append(args, "-i", identityPath, "-o", "IdentitiesOnly=yes")
	}
	if forwardAgent {
		args = append(args, "-A")
	}

	policyArgs, err := knownHostsArgs(knownHostsPolicy, opts.KnownHostsFile, opts.InsecureHostKey)
	if err != nil {
		return nil, err
	}
	args = append(args, policyArgs...)

	target := host.Address
	if user != "" {
		target = user + "@" + host.Address
	}
	args = append(args, target)

	return &SSHCommand{
		Binary: binary,
		Args:   args,
		Env:    append([]string(nil), opts.Env...),
	}, nil
}

func knownHostsArgs(policy, filePath string, insecure bool) ([]string, error) {
	normalized := strings.ToLower(strings.TrimSpace(policy))
	switch normalized {
	case "strict":
		out := []string{"-o", "StrictHostKeyChecking=yes"}
		if filePath != "" {
			out = append(out, "-o", "UserKnownHostsFile="+filePath)
		}
		return out, nil
	case "tofu", "accept-new", "":
		out := []string{"-o", "StrictHostKeyChecking=accept-new"}
		if filePath != "" {
			out = append(out, "-o", "UserKnownHostsFile="+filePath)
		}
		return out, nil
	case "off":
		if !insecure {
			return nil, fmt.Errorf("known_hosts policy=off requires --insecure-hostkey")
		}
		return []string{"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"}, nil
	default:
		return nil, fmt.Errorf("unsupported known_hosts policy %q", policy)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
