package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/athanvi/heimdall/internal/bridge"
	"github.com/athanvi/heimdall/internal/inventory"
	"github.com/athanvi/heimdall/internal/model"
)

var ErrNoAgentSocket = errors.New("selected context has no agent socket; refusing ambient SSH_AUTH_SOCK fallback")

type Launcher struct{}

type Options struct {
	BridgeName string
	RuntimeDir string
}

func (Launcher) Preview(cfg model.Config, contextName string, command []string) (model.SessionPreview, error) {
	return (Launcher{}).PreviewWithOptions(cfg, contextName, command, Options{})
}

func (Launcher) PreviewWithOptions(cfg model.Config, contextName string, command []string, opts Options) (model.SessionPreview, error) {
	if len(command) == 0 {
		return model.SessionPreview{}, fmt.Errorf("command is required")
	}
	ctx, ok := cfg.Contexts[contextName]
	if !ok {
		return model.SessionPreview{}, fmt.Errorf("unknown context %q", contextName)
	}
	identity := cfg.Identities[ctx.Identity]
	selectorName := firstNonEmpty(ctx.Agent, identity.AgentSelector)
	selector, ok := cfg.Agents.Selectors[selectorName]
	if !ok {
		return model.SessionPreview{}, ErrNoAgentSocket
	}
	endpoint := inventory.ResolveEndpoint(selector)
	if opts.BridgeName != "" {
		br, ok := cfg.Bridges[opts.BridgeName]
		if !ok {
			return model.SessionPreview{}, fmt.Errorf("unknown bridge %q", opts.BridgeName)
		}
		socketPath, err := plannedBridgeSocket(opts.BridgeName, opts.RuntimeDir, br)
		if err != nil {
			return model.SessionPreview{}, err
		}
		endpoint = socketPath
	}
	if endpoint == "" {
		return model.SessionPreview{}, ErrNoAgentSocket
	}
	preview := model.SessionPreview{
		Context: contextName,
		Command: append([]string(nil), command...),
		Env:     map[string]string{"SSH_AUTH_SOCK": endpoint},
	}
	if opts.BridgeName != "" {
		preview.Bridge = opts.BridgeName
		preview.Warnings = append(preview.Warnings, "bridge socket exposure is credential delegation; socket is scoped to this session and cleaned up after child exit")
	}
	if ctx.Forwarding.Agent == "allow" {
		preview.Warnings = append(preview.Warnings, "agent forwarding is credential delegation; use only for trusted remotes")
	}
	if looksLikeCodingAgent(command[0]) {
		preview.Warnings = append(preview.Warnings, "coding-agent command receives only this selected SSH_AUTH_SOCK; review context breadth before running")
	}
	return preview, nil
}

func (l Launcher) Run(ctx context.Context, cfg model.Config, contextName string, command []string) error {
	return l.RunWithOptions(ctx, cfg, contextName, command, Options{})
}

func (l Launcher) RunWithOptions(ctx context.Context, cfg model.Config, contextName string, command []string, opts Options) error {
	var server *bridge.Server
	if opts.BridgeName != "" {
		req, err := BridgeRequest(cfg, opts.BridgeName, opts.RuntimeDir)
		if err != nil {
			return err
		}
		var state bridge.State
		server, state, err = bridge.Start(ctx, req)
		if err != nil {
			return err
		}
		defer func() {
			_ = server.Stop()
		}()
		opts.RuntimeDir = state.RuntimeDir
	}
	preview, err := l.PreviewWithOptions(cfg, contextName, command, opts)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	env := filteredEnv(os.Environ(), "SSH_AUTH_SOCK")
	env = append(env, "SSH_AUTH_SOCK="+preview.Env["SSH_AUTH_SOCK"])
	cmd.Env = env
	return cmd.Run()
}

func BridgeRequest(cfg model.Config, name, runtimeDir string) (bridge.StartRequest, error) {
	br, ok := cfg.Bridges[name]
	if !ok {
		return bridge.StartRequest{}, fmt.Errorf("unknown bridge %q", name)
	}
	ttl := 30 * time.Minute
	if br.TTL != "" {
		parsed, err := time.ParseDuration(br.TTL)
		if err != nil {
			return bridge.StartRequest{}, fmt.Errorf("bridge %q ttl is invalid: %w", name, err)
		}
		ttl = parsed
	}
	if runtimeDir == "" {
		runtimeDir = br.RuntimeDir
	}
	req := bridge.StartRequest{Name: name, RuntimeDir: runtimeDir, TTL: ttl}
	if br.Socket != "" {
		req.UpstreamSocket = inventory.ExpandPath(br.Socket)
	}
	if len(br.Command) > 0 {
		req.UpstreamCommand = append([]string(nil), br.Command...)
	}
	if req.UpstreamSocket == "" && len(req.UpstreamCommand) == 0 && br.UpstreamAgent != "" {
		selector, ok := cfg.Agents.Selectors[br.UpstreamAgent]
		if !ok {
			return bridge.StartRequest{}, fmt.Errorf("bridge %q references missing upstream agent %q", name, br.UpstreamAgent)
		}
		req.UpstreamSocket = inventory.ResolveEndpoint(selector)
	}
	return req, nil
}

func plannedBridgeSocket(name, runtimeDir string, br model.Bridge) (string, error) {
	if runtimeDir == "" {
		runtimeDir = br.RuntimeDir
	}
	if runtimeDir == "" {
		runtimeDir = bridge.DefaultRuntimeDir()
	}
	if name == "" || strings.ContainsAny(name, `/\`+"\x00\n\r") {
		return "", fmt.Errorf("invalid bridge name")
	}
	return filepath.Join(runtimeDir, "heimdall-"+name+".sock"), nil
}

func filteredEnv(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, value := range env {
		if !strings.HasPrefix(value, prefix) {
			out = append(out, value)
		}
	}
	return out
}

func looksLikeCodingAgent(name string) bool {
	base := strings.ToLower(name)
	return strings.Contains(base, "codex") || strings.Contains(base, "claude") || strings.Contains(base, "cursor") || strings.Contains(base, "agent")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
