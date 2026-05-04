Heimdall Product and Technical Specification

Version: 0.2

Status: Revised V1 implementation specification

Audience: implementers, maintainers, security reviewers
Updated: 2026-05-03

Note: this version number is the specification document revision, not the Heimdall product version.

## 0. Executive product decision

Heimdall should exist only if it stays narrow.

The useful product is not another SSH host manager, not another terminal, not a vault, and not a transport layer. The useful product is a local-first SSH identity control plane: a tool that answers, with evidence, "which SSH identity, agent, certificate, forwarding policy, and subprocess environment will be used for this operation?" and then lets the user render transparent OpenSSH configuration or launch a scoped command using that answer.

The product sentence is binding:

Heimdall is a local-first SSH identity control plane. It inventories agents and identities, renders safe OpenSSH config fragments, diagnoses identity-routing failures, and launches scoped SSH-aware sessions for terminals, coding agents, WSL, containers, and external transport tools without storing private keys or implementing its own network transport.

Heimdall does not solve "how do I reach the box?" Heimdall solves "what SSH identity, agent, certificate, forwarding policy, and session environment am I using once I reach it?"

V1 must make `heimdall doctor` the flagship experience. If diagnostics are weak, the rest of the product is decorative.

## 0.1 Revision decisions

1. WSL Mode B is a real V1 target, not decorative spike work. The implementation plan still uses spikes to retire security and feasibility risk, but the product target is a fully operational, opt-in, scoped WSL bridge for validated paths.
2. Agent detection remains standards-first and vendor-neutral. Heimdall supports OpenSSH-compatible standards, documented OS facilities, and user-configured selectors. Popular tools may be recognized only through documented or observable interfaces.
3. Diagnostics remain passive by default. `heimdall doctor` may evaluate local config, environment, sockets, binaries, and generated files without network contact. Host contact, ProxyCommand execution, transport invocation, or auth attempts require explicit active-probe consent.

## 1. Product

### 1.1 Product thesis

Modern power users no longer have one terminal, one SSH key, one agent, and one `~/.ssh/config`. They have local OpenSSH agents, password-manager-backed agents, Windows OpenSSH agents and named pipes, WSL Linux tools expecting `SSH_AUTH_SOCK`, macOS or Linux Unix-domain sockets, containers needing mounted sockets, Git and coding agents inheriting ambient SSH access, SSH certificates, bastions, `ProxyJump`, `ProxyCommand`, and external transports such as `iroh-ssh`.

OpenSSH already provides the primitives. Heimdall's job is to compose them visibly and safely for a single technical user.

### 1.2 Problem statement

Power users often cannot reliably answer:

1. Which SSH agent is active in this shell?
2. Which identities are available through that agent?
3. Which key will OpenSSH offer to a specific host?
4. Is OpenSSH using the intended `IdentityAgent`, `IdentityFile`, `CertificateFile`, `IdentitiesOnly`, `ProxyJump`, or `ProxyCommand`?
5. Why does Git work in Windows but fail in WSL?
6. Why does a coding agent or devcontainer have broader SSH access than intended?
7. Why does a certificate-backed SSH workflow fail even though the key exists?
8. Is the failure identity selection, agent plumbing, certificate expiry, forwarding policy, config conflict, or external reachability?

Heimdall consolidates these into a local, inspectable, non-custodial control plane.

### 1.3 Target users

V1 targets one technical power user: developer, homelabber, security-conscious CLI user, user of coding agents, dotfiles user, and user working across shells, WSL, containers, devcontainers, and remote hosts.

### 1.4 Anti-users

V1 is not for nontechnical GUI bookmark users, teams needing RBAC or audit, users wanting cloud sync of hosts/keys/secrets, users wanting a new SSH client, or users wanting Heimdall to store, encrypt, sync, or back up private keys.

### 1.5 Goals

1. Inventory local SSH identities, public keys, certificates, agents, agent sockets, and Windows agent pipes without storing secrets.
2. Render a Heimdall-owned OpenSSH config fragment.
3. Diagnose identity-routing and agent-plumbing failures with evidence and suggested remediations.
4. Launch scoped SSH-aware sessions and subprocesses.
5. Support Linux, macOS, Windows OpenSSH, WSL Mode A, and an operationally targeted WSL Mode B scoped bridge workflow gated by security acceptance criteria.
6. Support container/devcontainer detection and scoped socket exposure workflows without silently mounting a global agent.
7. Expose SSH certificate metadata and optionally run external refresh hooks.
8. Integrate with external transports through OpenSSH configuration, especially `ProxyCommand` and `ProxyJump`.
9. Provide a TUI that makes inventory and diagnostics visible while preserving a fully capable CLI.

### 1.6 Non-goals

- private-key custody;
- passphrase storage;
- encrypted Heimdall vault;
- cloud sync;
- team sharing;
- enterprise RBAC;
- enterprise audit logs;
- certificate authority operation;
- arbitrary existing SSH config rewrite;
- full SSH client implementation;
- replacement SSH agent implementation;
- required always-on daemon;
- NAT traversal;
- peer discovery;
- relay selection;
- SSH-over-QUIC implementation;
- VPN behavior;
- replacement for Tailscale, WireGuard, ZeroTier, Iroh, or `iroh-ssh`;
- MCP server;
- remote server inventory scanning.

### 1.7 V1 scope

V1 includes:

- `heimdall doctor` as the flagship command;
- `heimdall doctor host <host>`;
- identity and agent inventory;
- certificate inspection;
- managed OpenSSH config rendering;
- safe Include installer with dry-run, backup, validation, rollback;
- context definition and command launching;
- forwarding policy warnings and scoped opt-in;
- Windows OpenSSH support;
- WSL Mode A support;
- WSL Mode B session-scoped bridge for child processes if gates pass;
- container/devcontainer detection, snippets, and scoped bridge integration where safe;
- `ProxyJump` and generic `ProxyCommand` support;
- explicit `iroh-ssh` integration by rendered `ProxyCommand`;
- TUI MVP for inventory, diagnostics, contexts, and launch flows.

### 1.8 Post-V1 scope

Post-V1 candidates include advanced bridge broker features, optional documented provider adapters, richer hardware-key metadata, deeper certificate refresh integrations, host-route templates, profile export/import excluding secrets, richer log/event viewer, optional local policy engine, optional transport diagnostics plugins, and MCP server only after the core security model is mature.

### 1.9 Differentiation

Heimdall differentiates on identity and agent routing, diagnostics, scoped session launching, managed OpenSSH config fragments, Windows/WSL clarity, container/devcontainer SSH socket workflows, forwarding policy, certificate visibility, external transport integration through OpenSSH config, and no private-key custody.

### 1.10 Product-category decisions

| Category | Decision | Rationale |
| --- | --- | --- |
| Host manager | No | Host metadata exists only as part of identity routes and contexts. |
| Vault | No | Private-key custody would destroy the clean security boundary. |
| SSH client | No | OpenSSH remains the client. |
| Agent | No | OpenSSH agents and provider agents remain authoritative. |
| Agent broker | Limited but real | V1 may attempt a stable explicit ephemeral broker for WSL Mode B and selected container sessions. |
| Transport layer | No | External tools own reachability. |
| Config renderer | Yes | Heimdall-owned generated fragments are a core feature. |
| Diagnostics tool | Yes | This is the flagship value. |
| Session launcher | Yes | Scoped subprocesses are core. |
| Certificate workflow assistant | Yes | Inspect certs and invoke external refresh hooks; do not run a CA. |

## 2. Security

### 2.1 Security philosophy

1. Never store private keys.
2. Never store passphrases.
3. Prefer transparent OpenSSH config over hidden runtime behavior.
4. Prefer scoped, temporary access over ambient access.
5. Prefer explicit user consent for forwarding and bridge behavior.
6. Diagnose before changing.
7. Show exact changes before applying them.
8. Fail closed when a chosen identity, agent, bridge, certificate, or transport cannot be verified.
9. Do not weaken SSH security for convenience.

### 2.2 Trust boundaries

| Boundary | Trusted? | Notes |
| --- | --- | --- |
| Heimdall binary | Yes, within normal local-tool assumptions | Must be signed/reproducible where possible. |
| User-owned config files | Mostly | May contain stale, unsafe, or conflicting directives. |
| Existing private key files | Not read | Paths may be referenced; contents must not be read. |
| Public key files | Readable | Safe to fingerprint and display. |
| Agent sockets/pipes | Sensitive | Agent use can authenticate as the user. |
| Same-user processes | Not fully trusted | Heimdall reduces accidental exposure, not malicious same-user compromise. |
| Root/Admin | Not trusted against | Root/admin can observe or modify almost everything. |
| Containers/devcontainers | Untrusted by default | Mounting agent sockets is credential delegation. |
| Remote hosts | Untrusted unless user marks trusted | Forwarding exposes signing capability to the remote environment. |
| External transports | Out of scope | Heimdall verifies local command/config shape. |

### 2.3 Threat model

Heimdall mitigates accidental use of the wrong key, overbroad agent exposure, unsafe global `ForwardAgent yes`, stale certificates, missing `IdentitiesOnly yes`, broken `SSH_AUTH_SOCK`, Windows/WSL mismatch, ambiguous transport-vs-identity failures, copying private keys as a workaround, and coding agents inheriting all SSH access by default.

Heimdall does not mitigate malicious root/admin, compromised OpenSSH, malicious password-manager agents, compromised remote hosts after agent forwarding, malicious containers with mounted sockets, malware running as the same user, compromised external transport binaries, or incorrect user trust decisions.

### 2.4 Privacy posture

Heimdall is local-first: no telemetry, no cloud account, no cloud sync, no remote inventory upload, and local diagnostics by default. Persisted data must not include private key material, passphrases, decrypted secrets, raw unredacted SSH debug logs, refresh-hook tokens, or full environment dumps.

### 2.5 Key custody policy

Heimdall may discover private key paths without reading contents, read public key files, fingerprint public keys, inspect public certificate files, call `ssh-add -l/-L`, call `ssh-keygen -l/-L` on public keys/certs, reference `IdentityFile`, `CertificateFile`, and `IdentityAgent` paths, and launch commands with a chosen `SSH_AUTH_SOCK`.

Heimdall must not import, copy, encrypt, decrypt, store, or read private keys; store passphrases; store agent authentication tokens; read private key contents to detect type; or hide private-key operations behind convenience commands.

Implementation rule: if a file path appears to be a private key, Heimdall may stat it and inspect permissions, but must not read bytes in V1.

### 2.6 Same-user, root, forwarding, bridge, and container risks

Same-user processes are not a security boundary. Root/admin is out of scope. Agent forwarding delegates signing capability to the remote environment. WSL Mode B exposes a Unix socket inside WSL and must be opt-in, scoped, permission-checked, visible, and reversible. Mounting an agent socket into a container grants signing capability and must never happen silently.

### 2.7 External transport and ProxyCommand risk

`ProxyCommand` executes a local command. Heimdall must never auto-generate it from untrusted remote input, must display the exact command, must validate binary existence, must warn about shell metacharacters, and must classify transport failures separately from identity failures.

### 2.8 Logging and redaction

Never log private key contents, passphrases, OAuth/OIDC tokens, full environments, raw agent protocol payloads, or unredacted exported debug logs. Public fingerprints, certificate metadata, redacted paths, command names, and diagnostic IDs may be logged.

### 2.9 Failure and recovery

Heimdall should fail closed. If the selected agent is missing, do not fall back to ambient `SSH_AUTH_SOCK`. If generated config validation fails, do not install it. If include backup fails, do not mutate config. If bridge permissions are broad, refuse by default. Every include install creates a timestamped backup and rollback path.

## 3. Architecture decisions

- Private key custody: never store, import, sync, encrypt, decrypt, or back up private keys.
- Local data model: store only declarative config and user intent; compute inventory at runtime.
- Config format: strict YAML for user config, generated OpenSSH config for SSH, JSON for machine output.
- Command surface: Go CLI with explicit nouns and reversible verbs.
- TUI navigation: Bubble Tea dashboard/inventory/diagnostics model; no terminal emulator.
- Agent/socket routing: explicit OpenSSH-compatible interfaces, `IdentityAgent`, `SSH_AUTH_SOCK`, Windows OpenSSH pipe descriptors, documented sockets, and Heimdall bridge sockets.
- Standards-first provider policy: support SSH/OpenSSH-facing interfaces first; treat vendors as external providers.
- Windows OpenSSH: Windows-native OpenSSH is authority in Windows contexts.
- WSL Mode A: default Windows/WSL V1 path when tools can call Windows `ssh.exe`.
- WSL Mode B: opt-in, security-gated operational V1 bridge target.
- Containers: detection, diagnostics, snippets first; bridge only if the same exposure bar passes.
- Remote hops: support `ProxyJump`, bastions, and forwarding policy without managing remote state.
- External transports: structured OpenSSH route adapters only.
- Certificates: inspect and invoke external hooks; do not sign.
- Subprocess/session model: on-demand subprocess-driven behavior, no daemon required.
- Optional ephemeral broker/helper: allowed only for bridges and scoped sessions.
- Diagnostics: finding schema with severity, confidence, evidence, remediation, and autofix posture.
- Packaging: Go single binary, Cobra, Bubble Tea, GoReleaser, shell completions, signed/checksummed artifacts.

## 4. High-level architecture

```text
+-------------------------------+
|            CLI/TUI            |
|  cobra commands / Bubble Tea   |
+---------------+---------------+
                |
                v
+-------------------------------+
|      Application Services      |
| contexts | inventory | doctor  |
| launcher | renderer  | certs   |
+---+-------+-------+-------+----+
    |       |       |       |
    v       v       v       v
+--------+ +------+ +------+ +-----------------+
| Config | | SSH  | | OS   | | External Tools  |
| Store  | | Model| | Probe| | ssh/ssh-add/... |
+--------+ +------+ +------+ +-----------------+
    |                |             |
    v                v             v
+-------------+  +--------+  +-------------------+
| Generated   |  | Agents |  | OpenSSH / Git /   |
| SSH Config  |  | Pipes  |  | Docker / iroh-ssh |
+-------------+  +--------+  +-------------------+
                    |
                    v
             +----------------+
             | Optional       |
             | Ephemeral      |
             | Broker/Bridge  |
             +----------------+
```

CLI parses commands and flags, invokes services, renders output, and enforces dry-run defaults. TUI visualizes inventory, diagnostics, contexts, launches, and diffs through the same services. Config manager owns strict parsing, validation, atomic writes, permissions, and backups. Renderer owns Heimdall-generated fragments and include installation. Inventory, agent detection, launcher, doctor, certificate, Windows/WSL/container, bridge, and transport modules remain isolated and testable.

## 5. Platform strategy

- Linux: inventory keys/certs, inspect `SSH_AUTH_SOCK`, run OpenSSH tools, render config, install include, launch with selected socket, diagnose common route and forwarding issues.
- macOS: same as Linux with launch-agent and password-manager socket nuances, relying only on OpenSSH-compatible behavior or explicit config.
- Windows: detect `ssh.exe`, `ssh-add.exe`, `ssh-keygen.exe`, service state, config include, Windows named pipe descriptors, and OpenSSH-compatible external agents.
- WSL Mode A: call Windows `ssh.exe` from WSL where tools allow it; diagnose Git `core.sshCommand` and Windows-vs-WSL mismatch.
- WSL Mode B: provide scoped Unix socket bridge for Linux-native WSL tools requiring `SSH_AUTH_SOCK`, if security gates pass.
- Containers/devcontainers: detect container state, inspect sockets, generate explicit Docker/devcontainer snippets, and optionally mount scoped bridge sockets only under the reviewed bridge model.

## 6. External transport strategy

Heimdall owns the SSH identity workflow, not reachability. It may render `ProxyCommand iroh-ssh proxy %h`, validate the local binary, show endpoint IDs, classify startup failure, and distinguish transport unavailability from SSH authentication failure. It must not implement Iroh, pick relays, discover peers, implement SSH-over-QUIC, or diagnose deep network path failures beyond local command/config evidence.

Example:

```yaml
transports:
  iroh-ssh:
    type: proxy_command
    binary: iroh-ssh
    args: ["proxy", "%h"]
```

```sshconfig
Host homelab-nas-iroh
  HostName <iroh-endpoint-id>
  User alice
  ProxyCommand iroh-ssh proxy %h
  IdentityAgent <selected-agent-socket>
  IdentitiesOnly yes
```

Passive diagnostics are default. Active probing must classify config evaluation, proxy startup, transport reachability, SSH handshake, authentication, and session phases.

## 7. Data model

Persisted:

- user config;
- contexts;
- host routes;
- external transport templates;
- forwarding policy;
- bridge policy;
- certificate references;
- backup metadata;
- optional diagnostic suppressions.

Runtime-only:

- live agents;
- socket liveness;
- loaded agent identities;
- expanded OpenSSH config;
- active sessions;
- bridge process state except cleanup metadata;
- diagnostic probe results;
- command outputs.

Entities:

- `Identity`;
- `IdentitySource`;
- `Agent`;
- `AgentSocket`;
- `WindowsAgentPipe`;
- `Context`;
- `HostRoute`;
- `Session`;
- `ForwardingPolicy`;
- `Bridge`;
- `Certificate`;
- `ExternalTransport`;
- `ProxyCommandRoute`;
- `DiagnosticFinding`.

No private key material or passphrases may be persisted.

## 8. Configuration model

| Platform | Heimdall config | Generated SSH fragment | User SSH config |
| --- | --- | --- | --- |
| Linux | `~/.config/heimdall/config.yaml` | `~/.config/heimdall/ssh_config` | `~/.ssh/config` |
| macOS | `~/.config/heimdall/config.yaml` | `~/.config/heimdall/ssh_config` | `~/.ssh/config` |
| Windows | `%APPDATA%\Heimdall\config.yaml` | `%APPDATA%\Heimdall\ssh_config` | `%USERPROFILE%\.ssh\config` |
| WSL | Linux path inside distro | Linux path inside distro | WSL config; Windows config relevant in Mode A |

Example:

```yaml
version: 1
settings:
  default_output: human
  redact_paths: true

agents:
  selectors:
    personal:
      kind: openssh
      socket: env:SSH_AUTH_SOCK
    windows-openssh:
      kind: windows_openssh
      pipe: "\\\\.\\pipe\\openssh-ssh-agent"

identities:
  github-personal:
    public_key_path: ~/.ssh/id_ed25519_github.pub
    private_key_path_ref: ~/.ssh/id_ed25519_github
    agent_selector: personal

contexts:
  github-personal:
    identity: github-personal
    agent: personal
    forwarding:
      agent: deny

transports:
  iroh-ssh:
    type: proxy_command
    binary: iroh-ssh
    args: ["proxy", "%h"]

host_routes:
  github.com:
    hostname: github.com
    user: git
    context: github-personal
    identities_only: true

bridges:
  wsl-personal:
    type: wsl
    upstream_agent: windows-openssh
    scope: session
    ttl: 30m
```

Heimdall owns only its generated fragment. `heimdall config install-include` may add one Include line only after dry-run, backup, validation, and rollback support.

## 9. CLI command surface

Common flags:

- `--config <path>`;
- `--format human|json|yaml`;
- `--dry-run`;
- `--verbose`;
- `--no-color`;
- `--redaction low|default|high`;
- `--unsafe-full-output`;
- `--yes`.

Primary commands:

- `heimdall doctor`;
- `heimdall doctor host <host>`;
- `heimdall doctor windows`;
- `heimdall doctor wsl`;
- `heimdall doctor container`;
- `heimdall doctor forwarding`;
- `heimdall doctor certs`;
- `heimdall doctor transport <host>`;
- `heimdall identities`;
- `heimdall agents`;
- `heimdall contexts`;
- `heimdall context add`;
- `heimdall run`;
- `heimdall ssh`;
- `heimdall config render`;
- `heimdall config install-include`;
- `heimdall config doctor`;
- `heimdall config diff`;
- `heimdall config rollback`;
- `heimdall wsl mode-a doctor`;
- `heimdall wsl mode-a configure-git`;
- `heimdall wsl bridge start`;
- `heimdall wsl bridge doctor`;
- `heimdall bridge container`;
- `heimdall transport add`;
- `heimdall transport doctor`;
- `heimdall certs`;
- `heimdall tui`.

Exit codes:

- 0: success;
- 1: command failed or error findings;
- 2: configuration invalid;
- 3: external dependency missing;
- 4: security refusal;
- 5: diagnostic warnings when `--fail-on warning` is used.

## 10. TUI design

Primary navigation:

1. Dashboard
2. Diagnostics
3. Identities
4. Agents/Sockets
5. Contexts
6. Host Routes
7. Sessions
8. Certificates
9. Windows/WSL
10. Containers
11. External Transports
12. Logs/Events
13. Settings

Keyboard model:

- tab / shift-tab: primary panels;
- arrows: list navigation;
- enter: open detail/action;
- esc: back;
- `/`: search/filter;
- `r`: refresh probes;
- `d`: run doctor;
- `p`: preview rendered config/diff;
- `l`: launch selected context;
- `?`: help;
- `q`: quit.

Mutation flows must show exact changes and require confirmation.

## 11. User journeys

Core journeys include first launch on Linux, macOS, Windows, and WSL; choosing WSL Mode A vs Mode B; configuring WSL Git to use Windows `ssh.exe`; detecting current SSH setup; creating GitHub and homelab contexts; creating an `iroh-ssh` route; launching scoped commands and coding agents; diagnosing wrong-key, too-many-keys, and Windows/WSL failures; launching Linux-native WSL tools through the bridge; forwarding to trusted hosts; exposing scoped sockets to devcontainers; inspecting and refreshing SSH certificates; diagnosing transport routes; and rolling back managed SSH config includes.

## 12. Interoperability

Heimdall uses OpenSSH config directives: `Include`, `Host`, `Match` only when justified, `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`, `CertificateFile`, `ForwardAgent`, `ProxyJump`, and `ProxyCommand`.

Heimdall observes existing agents and calls `ssh-add` and `ssh-keygen` for public identity and certificate inspection. It supports Windows OpenSSH, WSL Mode A/B, standards-first agent compatibility, password-manager-backed agents through documented OpenSSH-compatible behavior, hardware key hints, external certificate flows, `iroh-ssh`, Docker Desktop SSH-agent forwarding, and VS Code Dev Containers without reading private data or mutating configs silently.

## 13. Diagnostics design

Inputs include Heimdall config, generated fragment, user SSH config include status, public keys, certificates, `SSH_AUTH_SOCK`, agent endpoints, `ssh-add`, `ssh-keygen`, `ssh -G`, optional active `ssh -vvv`, Windows tool/service state, WSL and Git config, container environment, and transport binary paths.

Safe probes:

- `ssh -V`;
- `ssh -G <host>`;
- `ssh-add -l`;
- `ssh-add -L`;
- `ssh-keygen -l -f <public-key-or-cert>`;
- `ssh-keygen -L -f <cert>`;
- `git config --global --get core.sshCommand`.

Active probes require explicit consent.

Required diagnostic rules:

1. Missing managed include.
2. Generated config stale.
3. User config conflicts with managed route.
4. Broken `SSH_AUTH_SOCK`.
5. Agent has zero identities.
6. Agent has many identities and route lacks `IdentitiesOnly yes`.
7. Unexpected `IdentityAgent`.
8. Configured identity public key not loaded.
9. Private key path reference exists but public key missing.
10. Private key permissions unsafe, without reading content.
11. Global `ForwardAgent yes`.
12. Host-specific forwarding to untrusted host.
13. Certificate expired.
14. Certificate missing for route requiring one.
15. Certificate near expiry.
16. Windows OpenSSH missing.
17. Windows ssh-agent service stopped.
18. Windows agent identities differ from WSL Linux agent identities.
19. WSL Git using Linux ssh while expected Windows ssh.
20. WSL Mode B bridge socket permissions too broad.
21. Container socket missing/dead.
22. Container sees broader identities than selected context.
23. `ProxyCommand` binary missing.
24. Suspicious `ProxyCommand` shell metacharacters.
25. `ProxyJump` route identity for bastion missing.
26. Coding agent context exposes broad ambient agent.

## 14. Testing and acceptance

V1 is acceptable when:

- `heimdall doctor` produces actionable findings on Linux, macOS, Windows, and WSL;
- identity and agent inventory works without private-key reads;
- config renderer produces valid OpenSSH fragments;
- include installer is dry-run/backed-up/rollback-capable;
- context launcher scopes `SSH_AUTH_SOCK`;
- Windows OpenSSH and WSL Mode A diagnostics work;
- WSL Mode B bridge is stable and reviewed for at least one path, or explicitly withheld;
- container/devcontainer detection and snippet generation work;
- certificate inspection detects expiry;
- `ProxyCommand`/`ProxyJump` routes render and diagnose local config;
- TUI can run doctor, show inventory, show contexts, and preview config.

Security tests must cover private-key read refusal, redaction, broad bridge permission refusal, global forwarding warnings, key-copy refusal, debug log redaction, ProxyCommand shell-risk detection, and no fallback to ambient socket when a selected agent is missing.

## 15. Explicit V1 exclusions

Heimdall will not do private-key custody, passphrase storage, encrypted vaults, cloud sync, team sharing, enterprise RBAC/audit, CA operation, arbitrary SSH config rewriting, full SSH client implementation, replacement agent implementation, required always-on daemon, NAT traversal, peer discovery, relay selection, SSH-over-QUIC, VPN behavior, transport replacement, MCP server, or remote inventory scanning.

## 16. Implementation stack

- Language: Go.
- CLI: Cobra or equivalent.
- TUI: Bubble Tea with Bubbles.
- Config: strict YAML parser and explicit validation.
- Logging: structured logging with redaction before emission.
- Filesystem: atomic writes with restrictive permissions.
- Testing: standard Go testing plus golden helpers; low dependency count.

## 17. References

OpenSSH:

- OpenBSD `ssh-agent(1)`: https://man.openbsd.org/ssh-agent
- OpenBSD `ssh-add(1)`: https://man.openbsd.org/ssh-add
- OpenBSD `ssh_config(5)`: https://man.openbsd.org/ssh_config
- OpenBSD `ssh-keygen(1)`: https://man.openbsd.org/ssh-keygen

Platform behavior:

- Microsoft OpenSSH for Windows key management: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement
- Microsoft OpenSSH for Windows get started: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
- Microsoft WSL Git documentation: https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-git
- Microsoft WSL SSH keys blog: https://devblogs.microsoft.com/commandline/sharing-ssh-keys-between-windows-and-wsl-2/
- VS Code Dev Containers sharing Git credentials: https://code.visualstudio.com/remote/advancedcontainers/sharing-git-credentials
- Docker Desktop SSH agent forwarding: https://docs.docker.com/desktop/features/networking/#ssh-agent-forwarding

Identity systems:

- 1Password SSH Agent: https://developer.1password.com/docs/ssh/agent/
- 1Password SSH Agent security: https://developer.1password.com/docs/ssh/agent/security/
- 1Password SSH Agent compatibility: https://developer.1password.com/docs/ssh/agent/compatibility/
- KeePassXC SSH Agent integration: https://keepassxc.org/docs/KeePassXC_UserGuide#_ssh_agent
- KeePassXC development SSH Agent notes: https://keepassxc.org/docs/KeePassXC_DevGuide#_ssh_agent

Certificates:

- Smallstep SSH certificates: https://smallstep.com/docs/ssh/
- HashiCorp Vault SSH secrets engine signed certificates: https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates
- GitHub SSH certificate authorities: https://docs.github.com/en/organizations/managing-git-access-to-your-organizations-repositories/about-ssh-certificate-authorities

External transport/reachability:

- Iroh docs: https://www.iroh.computer/docs
- Iroh GitHub: https://github.com/n0-computer/iroh
- `iroh-ssh` GitHub: https://github.com/n0-computer/iroh-ssh
- Tailscale SSH docs: https://tailscale.com/kb/1193/tailscale-ssh
- WireGuard: https://www.wireguard.com/

Market landscape:

- Termius: https://termius.com/
- SecureCRT: https://www.vandyke.com/products/securecrt/
- MobaXterm: https://mobaxterm.mobatek.net/features.html
- Royal TS: https://www.royalapps.com/ts/mac/features
- Tabby: https://tabby.sh/
- SSHM: https://github.com/Gu1llaum-3/ssh-manager
- LazySSH: https://github.com/Adembc/lazyssh
- Purple: https://github.com/hverlin/purple
- Teleport OpenSSH integration: https://goteleport.com/docs/enroll-resources/server-access/openssh/openssh-agentless/
- HashiCorp Boundary SSH targets: https://developer.hashicorp.com/boundary/docs/concepts/domain-model/targets
- StrongDM docs: https://www.strongdm.com/docs/

Implementation stack:

- Bubble Tea: https://github.com/charmbracelet/bubbletea
- Bubbles: https://github.com/charmbracelet/bubbles
- Cobra: https://github.com/spf13/cobra
- GoReleaser: https://goreleaser.com/
