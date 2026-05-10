package openssh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/athanvi/heimdall/internal/config"
	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/transport"
)

const ManagedHeader = "# Managed by Heimdall. Do not edit this generated fragment directly."

type RenderOptions struct {
	GeneratedAt time.Time
}

func Render(cfg model.Config, opts RenderOptions) ([]byte, error) {
	var buf bytes.Buffer
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	fmt.Fprintln(&buf, ManagedHeader)
	fmt.Fprintf(&buf, "# Generated at %s\n\n", opts.GeneratedAt.Format(time.RFC3339))
	hosts := make([]string, 0, len(cfg.HostRoutes))
	for host := range cfg.HostRoutes {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		route := cfg.HostRoutes[host]
		ctx := cfg.Contexts[route.Context]
		identityName := firstNonEmpty(route.Identity, ctx.Identity)
		identity := cfg.Identities[identityName]
		agentName := firstNonEmpty(route.Agent, ctx.Agent, identity.AgentSelector)
		agent := cfg.Agents.Selectors[agentName]
		fmt.Fprintf(&buf, "Host %s\n", quoteValue(host))
		if route.Hostname != "" {
			fmt.Fprintf(&buf, "  HostName %s\n", quoteValue(route.Hostname))
		}
		if route.User != "" {
			fmt.Fprintf(&buf, "  User %s\n", quoteValue(route.User))
		}
		if endpoint := resolveEndpoint(agent); endpoint != "" {
			fmt.Fprintf(&buf, "  IdentityAgent %s\n", quoteValue(endpoint))
		}
		if identity.PrivateKeyPathRef != "" {
			fmt.Fprintf(&buf, "  IdentityFile %s\n", quoteValue(expandPath(identity.PrivateKeyPathRef)))
		}
		certFile := firstNonEmpty(route.CertificateFile, identity.CertificatePath)
		if certFile != "" {
			fmt.Fprintf(&buf, "  CertificateFile %s\n", quoteValue(expandPath(certFile)))
		}
		if route.IdentitiesOnly != nil {
			fmt.Fprintf(&buf, "  IdentitiesOnly %s\n", yesNo(*route.IdentitiesOnly))
		} else {
			fmt.Fprintln(&buf, "  IdentitiesOnly yes")
		}
		if route.ForwardAgent != "" {
			fmt.Fprintf(&buf, "  ForwardAgent %s\n", quoteValue(route.ForwardAgent))
		} else if ctx.Forwarding.Agent == "allow" {
			fmt.Fprintln(&buf, "  ForwardAgent yes")
		} else if ctx.Forwarding.Agent == "deny" {
			fmt.Fprintln(&buf, "  ForwardAgent no")
		}
		if route.ProxyJump != "" {
			fmt.Fprintf(&buf, "  ProxyJump %s\n", quoteValue(route.ProxyJump))
		}
		if route.ProxyCommand != "" {
			fmt.Fprintf(&buf, "  ProxyCommand %s\n", route.ProxyCommand)
		} else if route.Transport != "" {
			tr := cfg.Transports[route.Transport]
			if command := transport.RenderProxyCommand(tr); command != "" {
				fmt.Fprintf(&buf, "  ProxyCommand %s\n", command)
			}
		}
		fmt.Fprintln(&buf)
	}
	return buf.Bytes(), nil
}

func WriteFragment(path string, rendered []byte) error {
	return config.AtomicWrite(path, rendered, 0o600)
}

func Diff(path string, rendered []byte) (string, error) {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if bytes.Equal(existing, rendered) {
		return "no changes\n", nil
	}
	return fmt.Sprintf("--- current %s\n+++ rendered\n%s", path, lineDiff(string(existing), string(rendered))), nil
}

func InstallInclude(userConfigPath, fragmentPath string, dryRun bool) (string, error) {
	includeLine := "Include " + quoteValue(fragmentPath)
	current, err := os.ReadFile(userConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if hasInclude(string(current), fragmentPath) {
		return "managed Include already present\n", nil
	}
	next := string(current)
	if next != "" && !strings.HasSuffix(next, "\n") {
		next += "\n"
	}
	next += includeLine + "\n"
	if dryRun {
		return next, nil
	}
	if err := os.MkdirAll(filepath.Dir(userConfigPath), 0o700); err != nil {
		return "", err
	}
	if len(current) > 0 {
		backup := BackupPath(userConfigPath, time.Now().UTC())
		if err := config.AtomicWrite(backup, current, 0o600); err != nil {
			return "", err
		}
	}
	if err := config.AtomicWrite(userConfigPath, []byte(next), 0o600); err != nil {
		return "", err
	}
	return "installed managed Include\n", nil
}

func Rollback(userConfigPath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return config.AtomicWrite(userConfigPath, data, 0o600)
}

func BackupPath(path string, ts time.Time) string {
	return fmt.Sprintf("%s.heimdall-backup-%s", path, ts.Format("20060102T150405Z"))
}

func hasInclude(configText, fragmentPath string) bool {
	for _, line := range strings.Split(configText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Include ") && strings.Contains(line, fragmentPath) {
			return true
		}
	}
	return false
}

func lineDiff(oldText, newText string) string {
	var b strings.Builder
	if oldText != "" {
		for _, line := range strings.Split(strings.TrimSuffix(oldText, "\n"), "\n") {
			b.WriteString("- ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(newText, "\n"), "\n") {
		b.WriteString("+ ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func quoteValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t\"'") {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return value
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func resolveEndpoint(selector model.AgentSelector) string {
	switch {
	case strings.HasPrefix(selector.Socket, "env:"):
		return os.Getenv(strings.TrimPrefix(selector.Socket, "env:"))
	case selector.Socket != "":
		return expandPath(selector.Socket)
	case selector.Pipe != "":
		return selector.Pipe
	default:
		return ""
	}
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return os.ExpandEnv(path)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
