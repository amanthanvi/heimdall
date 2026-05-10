package model

import "time"

const ConfigVersion = 1

type Config struct {
	Version      int                          `yaml:"version" json:"version"`
	Settings     Settings                     `yaml:"settings" json:"settings"`
	Agents       AgentConfig                  `yaml:"agents" json:"agents"`
	Identities   map[string]Identity          `yaml:"identities" json:"identities"`
	Contexts     map[string]Context           `yaml:"contexts" json:"contexts"`
	HostRoutes   map[string]HostRoute         `yaml:"host_routes" json:"host_routes"`
	Transports   map[string]ExternalTransport `yaml:"transports" json:"transports"`
	Bridges      map[string]Bridge            `yaml:"bridges" json:"bridges"`
	Certificates map[string]CertificateRef    `yaml:"certificates" json:"certificates"`
}

type Settings struct {
	DefaultOutput string `yaml:"default_output" json:"default_output"`
	RedactPaths   bool   `yaml:"redact_paths" json:"redact_paths"`
}

type AgentConfig struct {
	Selectors map[string]AgentSelector `yaml:"selectors" json:"selectors"`
}

type AgentSelector struct {
	Kind   string `yaml:"kind" json:"kind"`
	Socket string `yaml:"socket" json:"socket"`
	Pipe   string `yaml:"pipe" json:"pipe"`
}

type Identity struct {
	PublicKeyPath     string `yaml:"public_key_path" json:"public_key_path"`
	PrivateKeyPathRef string `yaml:"private_key_path_ref" json:"private_key_path_ref"`
	CertificatePath   string `yaml:"certificate_path" json:"certificate_path"`
	AgentSelector     string `yaml:"agent_selector" json:"agent_selector"`
	Comment           string `yaml:"comment" json:"comment"`
}

type Context struct {
	Identity   string           `yaml:"identity" json:"identity"`
	Agent      string           `yaml:"agent" json:"agent"`
	Forwarding ForwardingPolicy `yaml:"forwarding" json:"forwarding"`
}

type ForwardingPolicy struct {
	Agent        string   `yaml:"agent" json:"agent"`
	TrustedHosts []string `yaml:"trusted_hosts" json:"trusted_hosts"`
}

type HostRoute struct {
	Hostname        string `yaml:"hostname" json:"hostname"`
	User            string `yaml:"user" json:"user"`
	Context         string `yaml:"context" json:"context"`
	Identity        string `yaml:"identity" json:"identity"`
	Agent           string `yaml:"agent" json:"agent"`
	IdentitiesOnly  *bool  `yaml:"identities_only" json:"identities_only"`
	CertificateFile string `yaml:"certificate_file" json:"certificate_file"`
	ForwardAgent    string `yaml:"forward_agent" json:"forward_agent"`
	ProxyJump       string `yaml:"proxy_jump" json:"proxy_jump"`
	ProxyCommand    string `yaml:"proxy_command" json:"proxy_command"`
	Transport       string `yaml:"transport" json:"transport"`
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
