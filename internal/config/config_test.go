package config

import "testing"

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("version: 1\nunknown: true\n"))
	if err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestParseRejectsEmbeddedPrivateKey(t *testing.T) {
	_, err := Parse([]byte("version: 1\nnotes: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n  sentinel\n  -----END OPENSSH PRIVATE KEY-----\n"))
	if err == nil {
		t.Fatal("expected embedded private key rejection")
	}
}

func TestValidateReferences(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
agents:
  selectors:
    personal:
      kind: openssh
      socket: env:SSH_AUTH_SOCK
identities:
  github:
    public_key_path: ~/.ssh/id_ed25519.pub
    private_key_path_ref: ~/.ssh/id_ed25519
    agent_selector: personal
contexts:
  github:
    identity: github
    agent: personal
    forwarding:
      agent: deny
host_routes:
  github.com:
    hostname: github.com
    user: git
    context: github
    identities_only: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSpecStyleContextRoutes(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
agents:
  selectors:
    personal:
      kind: openssh
      socket: env:SSH_AUTH_SOCK
identities:
  github:
    public_key_path: ~/.ssh/id_ed25519.pub
    private_key_path_ref: ~/.ssh/id_ed25519
    agent_selector: personal
contexts:
  github:
    identity: github
    agent: personal
    routes:
      - host: github.com
        user: git
        identities_only: true
    forwarding:
      enabled: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Contexts["github"].Routes) != 1 {
		t.Fatalf("expected nested route, got %#v", cfg.Contexts["github"].Routes)
	}
}

func TestValidateRejectsTransportControlCharacters(t *testing.T) {
	cfg, err := Parse([]byte("version: 1\ntransports:\n  bad:\n    type: proxy_command\n    binary: \"iroh-ssh\\nbad\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected transport control character rejection")
	}
}
