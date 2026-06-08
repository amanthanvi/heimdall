package model

import "time"

const ConfigVersion = 1

type Config struct {
	Version      int                          `yaml:"version" json:"version"`
	Settings     Settings                     `yaml:"settings,omitempty" json:"settings"`
	Agents       AgentConfig                  `yaml:"agents,omitempty" json:"agents"`
	Identities   map[string]Identity          `yaml:"identities,omitempty" json:"identities"`
	Contexts     map[string]Context           `yaml:"contexts,omitempty" json:"contexts"`
	HostRoutes   map[string]HostRoute         `yaml:"host_routes,omitempty" json:"host_routes"`
	Transports   map[string]ExternalTransport `yaml:"transports,omitempty" json:"transports"`
	Bridges      map[string]Bridge            `yaml:"bridges,omitempty" json:"bridges"`
	Certificates map[string]CertificateRef    `yaml:"certificates,omitempty" json:"certificates"`
}

type Settings struct {
	DefaultOutput string `yaml:"default_output" json:"default_output"`
	RedactPaths   bool   `yaml:"redact_paths" json:"redact_paths"`
}

type AgentConfig struct {
	Selectors map[string]AgentSelector `yaml:"selectors,omitempty" json:"selectors"`
}

type AgentSelector struct {
	Kind   string `yaml:"kind,omitempty" json:"kind"`
	Socket string `yaml:"socket,omitempty" json:"socket"`
	Pipe   string `yaml:"pipe,omitempty" json:"pipe"`
}

type Identity struct {
	PublicKeyPath     string `yaml:"public_key_path,omitempty" json:"public_key_path"`
	PrivateKeyPathRef string `yaml:"private_key_path_ref,omitempty" json:"private_key_path_ref"`
	CertificatePath   string `yaml:"certificate_path,omitempty" json:"certificate_path"`
	AgentSelector     string `yaml:"agent_selector,omitempty" json:"agent_selector"`
	Comment           string `yaml:"comment,omitempty" json:"comment"`
}

type Context struct {
	Identity   string           `yaml:"identity,omitempty" json:"identity"`
	Agent      string           `yaml:"agent,omitempty" json:"agent"`
	Routes     []HostRoute      `yaml:"routes,omitempty" json:"routes"`
	Forwarding ForwardingPolicy `yaml:"forwarding,omitempty" json:"forwarding"`
}

type ForwardingPolicy struct {
	Enabled      *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Agent        string   `yaml:"agent,omitempty" json:"agent"`
	TrustedHosts []string `yaml:"trusted_hosts,omitempty" json:"trusted_hosts"`
}

type HostRoute struct {
	Host            string `yaml:"host,omitempty" json:"host"`
	Hostname        string `yaml:"hostname,omitempty" json:"hostname"`
	User            string `yaml:"user,omitempty" json:"user"`
	Port            int    `yaml:"port,omitempty" json:"port"`
	Context         string `yaml:"context,omitempty" json:"context"`
	Identity        string `yaml:"identity,omitempty" json:"identity"`
	Agent           string `yaml:"agent,omitempty" json:"agent"`
	IdentitiesOnly  *bool  `yaml:"identities_only,omitempty" json:"identities_only,omitempty"`
	CertificateFile string `yaml:"certificate_file,omitempty" json:"certificate_file"`
	ForwardAgent    string `yaml:"forward_agent,omitempty" json:"forward_agent"`
	ProxyJump       string `yaml:"proxy_jump,omitempty" json:"proxy_jump"`
	ProxyCommand    string `yaml:"proxy_command,omitempty" json:"proxy_command"`
	Transport       string `yaml:"transport,omitempty" json:"transport"`
}

type NamedHostRoute struct {
	Host    string
	Context string
	Route   HostRoute
}

func NamedHostRoutes(cfg Config) []NamedHostRoute {
	routes := make([]NamedHostRoute, 0, len(cfg.HostRoutes))
	for host, route := range cfg.HostRoutes {
		contextName := route.Context
		route.Host = firstNonEmpty(route.Host, host)
		routes = append(routes, NamedHostRoute{Host: host, Context: contextName, Route: route})
	}
	for contextName, ctx := range cfg.Contexts {
		for _, route := range ctx.Routes {
			host := route.Host
			contextRef := firstNonEmpty(route.Context, contextName)
			routes = append(routes, NamedHostRoute{Host: host, Context: contextRef, Route: route})
		}
	}
	return routes
}

type ExternalTransport struct {
	Type   string   `yaml:"type" json:"type"`
	Binary string   `yaml:"binary" json:"binary"`
	Args   []string `yaml:"args" json:"args"`
}

type Bridge struct {
	Type          string   `yaml:"type" json:"type"`
	UpstreamAgent string   `yaml:"upstream_agent" json:"upstream_agent"`
	Scope         string   `yaml:"scope" json:"scope"`
	TTL           string   `yaml:"ttl" json:"ttl"`
	RuntimeDir    string   `yaml:"runtime_dir" json:"runtime_dir"`
	Socket        string   `yaml:"socket" json:"socket"`
	Command       []string `yaml:"command" json:"command"`
}

type CertificateRef struct {
	Path        string   `yaml:"path" json:"path"`
	Identity    string   `yaml:"identity" json:"identity"`
	RefreshHook []string `yaml:"refresh_hook" json:"refresh_hook"`
}

type Agent struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Endpoint   string          `json:"endpoint"`
	Live       bool            `json:"live"`
	Identities []AgentIdentity `json:"identities"`
	Error      string          `json:"error,omitempty"`
	ObservedAt time.Time       `json:"observed_at"`
}

type AgentIdentity struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Comment     string `json:"comment"`
	PublicKey   string `json:"public_key,omitempty"`
}

type IdentitySource struct {
	Name          string `json:"name"`
	PublicKeyPath string `json:"public_key_path"`
	Fingerprint   string `json:"fingerprint"`
	KeyType       string `json:"key_type"`
	Comment       string `json:"comment"`
	Error         string `json:"error,omitempty"`
}

type Certificate struct {
	Path        string    `json:"path"`
	KeyID       string    `json:"key_id,omitempty"`
	Serial      string    `json:"serial,omitempty"`
	Principals  []string  `json:"principals,omitempty"`
	ValidAfter  time.Time `json:"valid_after,omitempty"`
	ValidBefore time.Time `json:"valid_before,omitempty"`
	Expired     bool      `json:"expired"`
	NearExpiry  bool      `json:"near_expiry"`
	RawSummary  string    `json:"raw_summary,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type DiagnosticFinding struct {
	ID           string   `json:"id"`
	Severity     string   `json:"severity"`
	Confidence   string   `json:"confidence"`
	Title        string   `json:"title"`
	Evidence     []string `json:"evidence"`
	Risk         string   `json:"risk,omitempty"`
	SuggestedFix string   `json:"suggested_fix,omitempty"`
	Autofix      string   `json:"autofix,omitempty"`
}

type Inventory struct {
	Agents       []Agent          `json:"agents"`
	Identities   []IdentitySource `json:"identities"`
	Certificates []Certificate    `json:"certificates"`
	SSHAuthSock  string           `json:"ssh_auth_sock,omitempty"`
}

type SessionPreview struct {
	Context  string            `json:"context"`
	Command  []string          `json:"command"`
	Env      map[string]string `json:"env"`
	Warnings []string          `json:"warnings"`
	Bridge   string            `json:"bridge,omitempty"`
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
