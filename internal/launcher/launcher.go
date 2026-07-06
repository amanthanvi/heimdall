package launcher

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/athanvi/heimdall/internal/bridge"
	"github.com/athanvi/heimdall/internal/inventory"
	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
)

var ErrNoAgentSocket = errors.New("selected context has no agent socket; refusing ambient SSH_AUTH_SOCK fallback")

type Launcher struct{}

type Options struct {
	BridgeName    string
	RuntimeDir    string
	SSHConfigPath string
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
	route, hasRoute := matchedLaunchRoute(cfg, contextName, command)
	endpoint := ""
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
	} else if hasRoute {
		routeEndpoint, ok := routeAgentEndpoint(cfg, contextName, route)
		if !ok || routeEndpoint == "" {
			return model.SessionPreview{}, ErrNoAgentSocket
		}
		endpoint = routeEndpoint
	} else {
		contextEndpoint, ok := contextAgentEndpoint(cfg, ctx)
		if !ok || contextEndpoint == "" {
			return model.SessionPreview{}, ErrNoAgentSocket
		}
		endpoint = contextEndpoint
	}
	if endpoint == "" {
		return model.SessionPreview{}, ErrNoAgentSocket
	}
	previewCommand := append([]string(nil), command...)
	env := map[string]string{"SSH_AUTH_SOCK": endpoint}
	if opts.SSHConfigPath != "" {
		if err := validateSSHConfigPath(opts.SSHConfigPath); err != nil {
			return model.SessionPreview{}, err
		}
		env["GIT_SSH_COMMAND"] = gitSSHCommand(opts.SSHConfigPath)
		previewCommand = withOpenSSHConfig(previewCommand, opts.SSHConfigPath, routeHostsForContext(cfg, contextName))
	}
	preview := model.SessionPreview{
		Context: contextName,
		Command: previewCommand,
		Env:     env,
	}
	if opts.SSHConfigPath != "" {
		preview.SSHConfigPath = opts.SSHConfigPath
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
	if opts.SSHConfigPath != "" {
		if err := validateSSHConfigPath(opts.SSHConfigPath); err != nil {
			return err
		}
		rendered, err := openssh.Render(cfg, openssh.RenderOptions{})
		if err != nil {
			return err
		}
		if err := openssh.WriteFragment(opts.SSHConfigPath, rendered); err != nil {
			return err
		}
	}
	// preview.Command is the explicit local launch argv; no shell is invoked.
	cmd := exec.CommandContext(ctx, preview.Command[0], preview.Command[1:]...) // #nosec G204
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	keys := envKeys(preview.Env)
	env := filteredEnv(os.Environ(), keys...)
	for _, key := range keys {
		env = append(env, key+"="+preview.Env[key])
	}
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

func filteredEnv(env []string, keys ...string) []string {
	prefixes := make([]string, 0, len(keys))
	for _, key := range keys {
		prefixes = append(prefixes, key+"=")
	}
	out := make([]string, 0, len(env))
	for _, value := range env {
		remove := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(value, prefix) {
				remove = true
				break
			}
		}
		if !remove {
			out = append(out, value)
		}
	}
	return out
}

func envKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func withOpenSSHConfig(command []string, path string, routeHosts []string) []string {
	if len(command) == 0 || !isOpenSSHCommand(command[0]) || hasOpenSSHConfigFlag(command[1:], routeHosts) {
		return command
	}
	out := make([]string, 0, len(command)+2)
	out = append(out, command[0], "-F", path)
	out = append(out, command[1:]...)
	return out
}

func isOpenSSHCommand(name string) bool {
	normalized := strings.ReplaceAll(name, `\`, `/`)
	if idx := strings.LastIndex(normalized, "/"); idx >= 0 {
		normalized = normalized[idx+1:]
	}
	normalized = strings.ToLower(normalized)
	return normalized == "ssh" || normalized == "ssh.exe"
}

func hasOpenSSHConfigFlag(args []string, routeHosts []string) bool {
	optionEnd := sshOptionRegionEnd(args, routeHosts)
	args = args[:optionEnd]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-F" {
			return true
		}
		if strings.HasPrefix(arg, "-F") && arg != "-F" {
			return true
		}
		if sshOptionConsumesNext(arg) {
			i++
		}
	}
	return false
}

func sshOptionRegionEnd(args []string, routeHosts []string) int {
	unknownOptionValue := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return i
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if sshOptionConsumesNext(arg) {
				i++
				unknownOptionValue = false
				continue
			}
			unknownOptionValue = len(arg) == 2
			continue
		}
		if routeHostExactlyMatchesAny(routeHosts, sshLikeHost(arg)) {
			return i
		}
		if unknownOptionValue {
			unknownOptionValue = false
			continue
		}
		return i
	}
	return len(args)
}

const sshOptionsConsumingNext = "BbcDEeFIiJLlmOoPpQRSWw"

// sshOptionConsumesNext is derived from the OpenSSH ssh(1) OPTIONS list.
func sshOptionConsumesNext(arg string) bool {
	if len(arg) != 2 {
		return false
	}
	return strings.ContainsRune(sshOptionsConsumingNext, rune(arg[1]))
}

func validateSSHConfigPath(path string) error {
	if strings.ContainsRune(path, '\x00') || strings.ContainsAny(path, "\n\r") {
		return fmt.Errorf("ssh config path contains invalid control characters")
	}
	return nil
}

func gitSSHCommand(path string) string {
	return "ssh -F " + shellQuote(path)
}

func shellQuote(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\n\r'\"\\$`!#&;()<>|*?[]{}") {
		return value
	}
	if value != "" && !strings.ContainsAny(value, "\"$`!\n\r") {
		return `"` + value + `"`
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func matchedLaunchRoute(cfg model.Config, contextName string, command []string) (model.NamedHostRoute, bool) {
	if len(command) == 0 {
		return model.NamedHostRoute{}, false
	}
	var candidates []string
	routeHosts := routeHostsForContext(cfg, contextName)
	if isOpenSSHCommand(command[0]) {
		if host := sshLaunchHost(command[1:], routeHosts); host != "" {
			candidates = append(candidates, host)
		}
	} else if isGitCommand(command[0]) {
		for _, arg := range command[1:] {
			if host := gitSSHHost(arg); host != "" {
				candidates = append(candidates, host)
			}
		}
	}
	for _, host := range candidates {
		if route, ok := findContextRoute(cfg, contextName, host); ok {
			return route, true
		}
	}
	return model.NamedHostRoute{}, false
}

func routeAgentEndpoint(cfg model.Config, contextName string, named model.NamedHostRoute) (string, bool) {
	ctx := cfg.Contexts[firstNonEmpty(named.Context, contextName)]
	identityName := firstNonEmpty(named.Route.Identity, ctx.Identity)
	identity := cfg.Identities[identityName]
	selectorName := firstNonEmpty(named.Route.Agent, ctx.Agent, identity.AgentSelector)
	if selectorName == "" {
		return "", false
	}
	selector, ok := cfg.Agents.Selectors[selectorName]
	if !ok {
		return "", false
	}
	return inventory.ResolveEndpoint(selector), true
}

func contextAgentEndpoint(cfg model.Config, ctx model.Context) (string, bool) {
	identity := cfg.Identities[ctx.Identity]
	selectorName := firstNonEmpty(ctx.Agent, identity.AgentSelector)
	if selectorName == "" {
		return "", false
	}
	selector, ok := cfg.Agents.Selectors[selectorName]
	if !ok {
		return "", false
	}
	return inventory.ResolveEndpoint(selector), true
}

func findContextRoute(cfg model.Config, contextName, host string) (model.NamedHostRoute, bool) {
	for _, named := range model.NamedHostRoutes(cfg) {
		if named.Context != contextName {
			continue
		}
		if routeHostMatches(named.Host, host) {
			return named, true
		}
	}
	return model.NamedHostRoute{}, false
}

func routeHostsForContext(cfg model.Config, contextName string) []string {
	hosts := []string{}
	for _, named := range model.NamedHostRoutes(cfg) {
		if named.Context == contextName && named.Host != "" {
			hosts = append(hosts, named.Host)
		}
	}
	return hosts
}

func isGitCommand(name string) bool {
	normalized := strings.ReplaceAll(name, `\`, `/`)
	if idx := strings.LastIndex(normalized, "/"); idx >= 0 {
		normalized = normalized[idx+1:]
	}
	normalized = strings.ToLower(normalized)
	return normalized == "git" || normalized == "git.exe"
}

func sshLaunchHost(args []string, routeHosts []string) string {
	end := sshOptionRegionEnd(args, routeHosts)
	if end >= len(args) {
		return ""
	}
	if args[end] == "--" {
		if end+1 >= len(args) {
			return ""
		}
		return sshLikeHost(args[end+1])
	}
	return sshLikeHost(args[end])
}

func gitSSHHost(value string) string {
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme == "ssh" {
		return parsed.Hostname()
	}
	colon := strings.Index(value, ":")
	if colon <= 0 {
		return ""
	}
	prefix := value[:colon]
	if len(prefix) == 1 || strings.ContainsAny(prefix, `/\`) {
		return ""
	}
	return sshLikeHost(prefix)
}

func sshLikeHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme == "ssh" {
		return parsed.Hostname()
	}
	if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	}
	value = strings.TrimPrefix(value, "[")
	if end := strings.Index(value, "]"); end >= 0 {
		return value[:end]
	}
	if colon := strings.Index(value, ":"); colon > 0 {
		return value[:colon]
	}
	return value
}

func routeHostMatchesAny(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if routeHostMatches(pattern, host) {
			return true
		}
	}
	return false
}

func routeHostExactlyMatchesAny(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if routeHostExactlyMatches(pattern, host) {
			return true
		}
	}
	return false
}

func routeHostExactlyMatches(patternList, host string) bool {
	if host == "" {
		return false
	}
	for _, pattern := range strings.Split(patternList, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.HasPrefix(pattern, "!") || strings.ContainsAny(pattern, "*?") {
			continue
		}
		if pattern == host {
			return true
		}
	}
	return false
}

func routeHostMatches(patternList, host string) bool {
	if host == "" {
		return false
	}
	matched := false
	for _, pattern := range strings.Split(patternList, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = strings.TrimPrefix(pattern, "!")
		}
		if pattern == host || wildcardMatch(pattern, host) {
			if negated {
				return false
			}
			matched = true
		}
	}
	return matched
}

func wildcardMatch(pattern, host string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return false
	}
	ok, err := filepath.Match(pattern, host)
	return err == nil && ok
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
