package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/athanvi/heimdall/internal/model"
	"gopkg.in/yaml.v3"
)

var privateKeyBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

type ValidationError struct {
	Problems []string
}

func (e ValidationError) Error() string {
	return strings.Join(e.Problems, "; ")
}

func DefaultPath() string {
	if runtimeConfig := os.Getenv("HEIMDALL_CONFIG"); runtimeConfig != "" {
		return runtimeConfig
	}
	if appdata := os.Getenv("APPDATA"); appdata != "" && filepath.VolumeName(appdata) != "" {
		return filepath.Join(appdata, "Heimdall", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(home, ".config", "heimdall", "config.yaml")
}

func DefaultSSHFragmentPath() string {
	if appdata := os.Getenv("APPDATA"); appdata != "" && filepath.VolumeName(appdata) != "" {
		return filepath.Join(appdata, "Heimdall", "ssh_config")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "ssh_config"
	}
	return filepath.Join(home, ".config", "heimdall", "ssh_config")
}

func DefaultUserSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".ssh", "config")
	}
	return filepath.Join(home, ".ssh", "config")
}

func Load(path string) (model.Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg := Empty()
			cfg.Version = model.ConfigVersion
			return cfg, nil
		}
		return model.Config{}, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return model.Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return model.Config{}, err
	}
	return cfg, nil
}

func Parse(data []byte) (model.Config, error) {
	if privateKeyBlock.Match(data) {
		return model.Config{}, ValidationError{Problems: []string{"config contains embedded private key material; Heimdall only accepts path references"}}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg model.Config
	if err := dec.Decode(&cfg); err != nil {
		return model.Config{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return model.Config{}, fmt.Errorf("config must contain one YAML document")
	}
	return cfg, nil
}

func Empty() model.Config {
	return model.Config{
		Version:      model.ConfigVersion,
		Settings:     model.Settings{DefaultOutput: "human", RedactPaths: true},
		Agents:       model.AgentConfig{Selectors: map[string]model.AgentSelector{}},
		Identities:   map[string]model.Identity{},
		Contexts:     map[string]model.Context{},
		HostRoutes:   map[string]model.HostRoute{},
		Transports:   map[string]model.ExternalTransport{},
		Bridges:      map[string]model.Bridge{},
		Certificates: map[string]model.CertificateRef{},
	}
}

func Normalize(cfg model.Config) model.Config {
	if cfg.Settings.DefaultOutput == "" {
		cfg.Settings.DefaultOutput = "human"
	}
	if cfg.Agents.Selectors == nil {
		cfg.Agents.Selectors = map[string]model.AgentSelector{}
	}
	if cfg.Identities == nil {
		cfg.Identities = map[string]model.Identity{}
	}
	if cfg.Contexts == nil {
		cfg.Contexts = map[string]model.Context{}
	}
	if cfg.HostRoutes == nil {
		cfg.HostRoutes = map[string]model.HostRoute{}
	}
	if cfg.Transports == nil {
		cfg.Transports = map[string]model.ExternalTransport{}
	}
	if cfg.Bridges == nil {
		cfg.Bridges = map[string]model.Bridge{}
	}
	if cfg.Certificates == nil {
		cfg.Certificates = map[string]model.CertificateRef{}
	}
	return cfg
}

func Validate(cfg model.Config) error {
	cfg = Normalize(cfg)
	var problems []string
	if cfg.Version != model.ConfigVersion {
		problems = append(problems, fmt.Sprintf("unsupported config version %d", cfg.Version))
	}
	for name, agent := range cfg.Agents.Selectors {
		if name == "" {
			problems = append(problems, "agent selector name cannot be empty")
		}
		switch agent.Kind {
		case "openssh", "windows_openssh", "bridge":
		default:
			problems = append(problems, fmt.Sprintf("agent %q has unsupported kind %q", name, agent.Kind))
		}
		if agent.Kind == "openssh" && agent.Socket == "" {
			problems = append(problems, fmt.Sprintf("agent %q requires socket", name))
		}
		if agent.Kind == "windows_openssh" && agent.Pipe == "" {
			problems = append(problems, fmt.Sprintf("agent %q requires pipe", name))
		}
		if hasPrivateMaterial(agent.Socket) || hasPrivateMaterial(agent.Pipe) {
			problems = append(problems, fmt.Sprintf("agent %q contains private key material", name))
		}
	}
	for name, identity := range cfg.Identities {
		if identity.PublicKeyPath == "" {
			problems = append(problems, fmt.Sprintf("identity %q requires public_key_path", name))
		}
		if identity.PrivateKeyPathRef != "" && hasPrivateMaterial(identity.PrivateKeyPathRef) {
			problems = append(problems, fmt.Sprintf("identity %q private_key_path_ref contains private key material", name))
		}
		if identity.AgentSelector != "" {
			if _, ok := cfg.Agents.Selectors[identity.AgentSelector]; !ok {
				problems = append(problems, fmt.Sprintf("identity %q references missing agent selector %q", name, identity.AgentSelector))
			}
		}
	}
	for name, ctx := range cfg.Contexts {
		if ctx.Identity != "" {
			if _, ok := cfg.Identities[ctx.Identity]; !ok {
				problems = append(problems, fmt.Sprintf("context %q references missing identity %q", name, ctx.Identity))
			}
		}
		if ctx.Agent != "" {
			if _, ok := cfg.Agents.Selectors[ctx.Agent]; !ok {
				problems = append(problems, fmt.Sprintf("context %q references missing agent %q", name, ctx.Agent))
			}
		}
		if ctx.Forwarding.Agent != "" && ctx.Forwarding.Agent != "deny" && ctx.Forwarding.Agent != "allow" && ctx.Forwarding.Agent != "ask" {
			problems = append(problems, fmt.Sprintf("context %q forwarding.agent must be deny, allow, or ask", name))
		}
	}
	for host, route := range cfg.HostRoutes {
		if host == "" {
			problems = append(problems, "host route name cannot be empty")
		}
		if route.Context != "" {
			if _, ok := cfg.Contexts[route.Context]; !ok {
				problems = append(problems, fmt.Sprintf("host route %q references missing context %q", host, route.Context))
			}
		}
		if route.Identity != "" {
			if _, ok := cfg.Identities[route.Identity]; !ok {
				problems = append(problems, fmt.Sprintf("host route %q references missing identity %q", host, route.Identity))
			}
		}
		if route.Transport != "" {
			if _, ok := cfg.Transports[route.Transport]; !ok {
				problems = append(problems, fmt.Sprintf("host route %q references missing transport %q", host, route.Transport))
			}
		}
	}
	for name, tr := range cfg.Transports {
		if tr.Type != "proxy_command" && tr.Type != "proxy_jump" {
			problems = append(problems, fmt.Sprintf("transport %q has unsupported type %q", name, tr.Type))
		}
		if tr.Type == "proxy_command" && tr.Binary == "" {
			problems = append(problems, fmt.Sprintf("transport %q requires binary", name))
		}
		for _, arg := range append([]string{tr.Binary}, tr.Args...) {
			if hasPrivateMaterial(arg) {
				problems = append(problems, fmt.Sprintf("transport %q contains private key material", name))
			}
		}
	}
	for name, br := range cfg.Bridges {
		if br.Type != "wsl" && br.Type != "container" {
			problems = append(problems, fmt.Sprintf("bridge %q has unsupported type %q", name, br.Type))
		}
		if br.Scope != "" && br.Scope != "session" {
			problems = append(problems, fmt.Sprintf("bridge %q only supports session scope in V1", name))
		}
		if br.Socket != "" && hasPrivateMaterial(br.Socket) {
			problems = append(problems, fmt.Sprintf("bridge %q socket contains private key material", name))
		}
		for _, arg := range br.Command {
			if hasPrivateMaterial(arg) {
				problems = append(problems, fmt.Sprintf("bridge %q command contains private key material", name))
			}
			if strings.ContainsRune(arg, '\x00') || strings.ContainsAny(arg, "\n\r") {
				problems = append(problems, fmt.Sprintf("bridge %q command contains invalid control characters", name))
			}
		}
		if br.Socket == "" && len(br.Command) == 0 && br.UpstreamAgent == "" {
			problems = append(problems, fmt.Sprintf("bridge %q requires socket, command, or upstream_agent", name))
		}
	}
	if len(problems) > 0 {
		return ValidationError{Problems: problems}
	}
	return nil
}

func hasPrivateMaterial(value string) bool {
	return privateKeyBlock.MatchString(value)
}

func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".heimdall-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
