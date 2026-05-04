Heimdall Implementation Plan

Version: 0.2

Status: Revised execution-ready V1 plan

Audience: maintainers, implementers, security reviewers
Updated: 2026-05-03

Note: this version number is the plan document revision, not the Heimdall product version.

## 0. Plan summary

Heimdall V1 should be built CLI-first, diagnostics-first, and daemonless by default. The TUI ships as a control surface over the same services, not as a separate product. The core implementation sequence is:

1. Prove the data model, config schema, and no-private-key-custody boundary.
2. Build inventory and managed config rendering.
3. Build `heimdall doctor` around evidence-based findings.
4. Build scoped command launching.
5. Add Windows and WSL Mode A support.
6. Drive WSL Mode B through risk-retirement spikes toward a fully operational, security-reviewed V1 bridge for validated paths; keep container bridge narrower unless it passes the same bar.
7. Add certificates and external transport routing through OpenSSH config.
8. Add a modest Bubble Tea TUI after CLI value is real.
9. Harden security, packaging, docs, and bridge-specific warnings before public launch.

The product must not drift into a generic host manager, vault, SSH client, enterprise PAM product, or transport layer.

## 0.1 Revision decisions

- WSL Mode B is an intended V1 capability, not a mere spike. Spike work remains necessary, but it is risk-retirement in service of a production-quality, opt-in, scoped bridge for validated Windows-to-WSL agent paths. If a bridge variant cannot be made small, auditable, reversible, and session-scoped, that variant is cut.
- Agent detection remains vendor-neutral and standards-first. Heimdall uses OpenSSH-compatible behavior, documented OS mechanisms, and user-configured selectors. Popular tools are observed only through those interfaces.
- `heimdall doctor` remains passive by default. Network contact, ProxyCommand execution, transport invocation, or authentication attempts require explicit `--active-probe` style consent.

## 1. Assumptions

### 1.1 Product assumptions

- V1 is for a single technical power user.
- V1 is local-first and does not require a cloud service.
- V1 does not store private keys, passphrases, OAuth tokens, or agent protocol secrets.
- OpenSSH remains the SSH client and configuration authority.
- Existing OpenSSH-compatible agents remain the signing providers; Heimdall treats password managers and hardware-backed agents as external providers.
- External transports remain external tools invoked through OpenSSH configuration.
- `heimdall doctor` is the flagship experience.
- The TUI must not block the first useful CLI release.
- WSL Mode B should be pursued as far as safely possible in V1, but not by adding persistent-daemon bloat, broad global exposure, or vendor-specific lock-in.

### 1.2 Technical assumptions

- Implementation language: Go.
- CLI framework: Cobra or comparable Go CLI framework.
- TUI framework: Bubble Tea with Bubbles components.
- Config format: strict YAML for Heimdall config; generated OpenSSH config for SSH.
- Default execution model: on-demand subprocesses; no required daemon.
- Optional bridge process: ephemeral, session-scoped, explicitly started.
- Primary OS targets: Linux, macOS, Windows, WSL.
- Container/devcontainer support starts with diagnostics and snippet generation, then reuses the Mode B bridge only if scoped exposure remains auditable.

### 1.3 Security assumptions

- Same-user processes are not a strong security boundary.
- Root/admin is out of scope as an adversary.
- Agent socket exposure is credential delegation.
- Agent forwarding is credential delegation to the remote environment.
- Generated config must be transparent and reversible.
- Active network probes, ProxyCommand execution, transport invocation, and authentication attempts require explicit consent.

## 2. Non-negotiables

Do not cut:

- no-private-key-custody boundary;
- no passphrase storage;
- managed config strategy;
- core diagnostics;
- core identity and agent inventory;
- core config rendering;
- core context launcher;
- security review;
- WSL Mode B threat-model/spike, stable-path implementation attempt, and safety gate if the bridge ships.

Do not add in V1:

- vault behavior;
- cloud sync;
- enterprise RBAC/audit;
- SSH client implementation;
- replacement agent implementation;
- NAT traversal;
- peer discovery;
- relay selection;
- SSH-over-QUIC;
- VPN behavior;
- MCP server;
- remote server inventory scanning.

## 3. Milestones

### M0 - Repository and guardrails

Outcome: repository exists with architecture guardrails, test harness, and contribution rules.

Exit criteria:

- repo structure created;
- CI runs unit tests;
- architecture decision records started;
- security boundary document committed;
- private-key read prevention test exists, even if minimal.

### M1 - Config and data model MVP

Outcome: strict config parser, typed model, validation, and atomic writes.

Exit criteria:

- config schema supports identities, agents, contexts, host routes, forwarding policy, transports, bridges;
- unknown fields rejected;
- no private key material accepted as config values beyond path references;
- config validation errors are clear.

### M2 - Inventory MVP

Outcome: identities, public keys, certificates, agents, and sockets can be inventoried.

Exit criteria:

- public key scanning works;
- agent liveness and identity listing work;
- cert metadata extraction works at basic level;
- no private key contents are read;
- JSON and human output implemented.

### M3 - Managed SSH config renderer

Outcome: Heimdall renders and validates a managed OpenSSH config fragment.

Exit criteria:

- render command works;
- include installer supports dry-run, backup, rollback;
- renderer supports `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`, `CertificateFile`, `ForwardAgent`, `ProxyJump`, `ProxyCommand`;
- rendering tests cover quoting and stale config detection.

### M4 - Diagnostics MVP

Outcome: `heimdall doctor` and `heimdall doctor host <host>` produce evidence-based findings.

Exit criteria:

- core findings implemented;
- severity/confidence/remediation format stable;
- JSON output stable enough for tests;
- active probes require explicit flag and clear network-contact disclosure;
- false-confidence review completed.

### M5 - Context launcher MVP

Outcome: `heimdall run` and `heimdall ssh` can launch scoped commands.

Exit criteria:

- selected `SSH_AUTH_SOCK` passed only to child process;
- no silent fallback to ambient socket;
- command preview and security warning implemented;
- coding-agent broad-access warning implemented.

### M6 - Windows + WSL Mode A

Outcome: Windows OpenSSH and WSL Mode A are first-class diagnostic paths.

Exit criteria:

- Windows tool/service detection works;
- Windows config include install works or is safely disabled with clear docs;
- WSL Mode A doctor works;
- WSL Git configure dry-run works;
- Windows vs WSL mismatch finding implemented.

### M7 - WSL Mode B bridge and container risk retirement

Outcome: WSL Mode B has a reviewed path to stable V1 operation, and container bridge risk is retired enough to decide whether to ship only detection/snippets or a scoped bridge.

Exit criteria:

- threat model completed;
- WSL Mode B proof-of-concept bridge can be started/stopped and is converted into a stable path if security gates pass;
- child-scoped `heimdall run --wsl-bridge -- <cmd>` works in the validated path;
- socket permission, TTL cleanup, interrupted cleanup, and no-ambient-fallback tests exist;
- container/devcontainer doctor and snippets implemented;
- stable WSL Mode B release decision recorded, with unsupported bridge variants explicitly cut rather than left ambiguous.

### M8 - Certificates and external transports

Outcome: certificate inspection and external transport route rendering/diagnosis are implemented.

Exit criteria:

- cert expiry/principal/options visible;
- refresh hook dry-run and explicit execution exist;
- `iroh-ssh` template renders;
- generic `ProxyCommand` and `ProxyJump` diagnostics work;
- transport-vs-identity classification implemented.

### M9 - TUI MVP

Outcome: Bubble Tea TUI provides dashboard, inventory, diagnostics, contexts, config preview, and launch.

Exit criteria:

- TUI uses application services;
- no separate security logic;
- keyboard help present;
- mutation confirmation screens present;
- golden view tests for core screens.

### M10 - Hardening and release

Outcome: V1 is secure enough for public open-source release.

Exit criteria:

- security review complete;
- docs complete;
- packages built;
- checksums/signing in place;
- platform smoke tests pass;
- cut list applied if necessary.

## 4. Decision gates

- Gate A - No-private-key-custody enforcement: no private-key read path exists in normal V1 behavior.
- Gate B - Renderer safety: include install is reversible and non-destructive.
- Gate C - Diagnostics usefulness: three representative user failures can be diagnosed from fixtures or real environments.
- Gate D - Launcher safety: launcher is useful without broadening default access.
- Gate E - Windows/WSL viability: Mode A is stable; at least one Mode B bridge path is approved or explicitly cut with rationale.
- Gate F - Bridge release decision: WSL Mode B ships stable only if small, auditable, reversible, session-scoped, permission-checked, and fail-closed.
- Gate G - TUI scope control: TUI supports core visibility and launch, not terminal/host-manager sprawl.
- Gate H - Release trust: public release does not overclaim security.

## 5. Workstreams

- Core application services: data model, config parsing, inventory, renderer, diagnostics, launcher, cert inspector, transport model.
- Platform integration: Linux/macOS probes, Windows OpenSSH probes, WSL Mode A, WSL Mode B bridge implementation, container/devcontainer detection, path normalization.
- Security: threat model, redaction, private-key read prevention, bridge review, subprocess execution review, logging review, release trust posture.
- CLI UX: command structure, output format, help text, examples, JSON output, shell completions.
- TUI UX: screen map, keyboard model, view components, confirmation flows, visual diagnostics, accessibility basics.
- Documentation and release: README, security policy, install docs, platform guides, WSL guide, container guide, external transport guide, troubleshooting, packaging.
- Vendor-neutral provider policy: define provider interfaces around OpenSSH-compatible agent operations, not brands.

## 6. Recommended repository structure

```text
heimdall/
  cmd/heimdall/
    main.go
  internal/
    app/
    cli/
    config/
    model/
    inventory/
    openssh/
    doctor/
    launcher/
    platform/
    bridge/
    certs/
    transport/
    redact/
    logging/
    tui/
  pkg/
    heimdallapi/
  testdata/
    ssh_config/
    ssh_add/
    ssh_keygen/
    windows/
    wsl/
    containers/
  docs/
    architecture.md
    security.md
    no-private-key-custody.md
    wsl.md
    containers.md
    transports.md
    certificates.md
    troubleshooting.md
  scripts/
    test-windows.ps1
    test-wsl.sh
  .github/workflows/
    ci.yml
    release.yml
  goreleaser.yml
  go.mod
  README.md
  SECURITY.md
```

Structure rules:

- `internal/openssh` owns command invocation and rendering.
- `internal/doctor` owns findings and rules.
- `internal/tui` calls services; it does not own security decisions.
- `internal/bridge` remains small and auditable.
- `pkg/heimdallapi` is optional and should stay empty until there is a real external API need.

## 7. Architecture spikes and risk-retirement tasks

- Private-key non-custody spike: prove implementation can inventory identities without private-key reads.
- `ssh -G` effective config spike: determine reliable parsing for effective config across platforms.
- Windows OpenSSH named-pipe spike: understand detection and safe probing of Windows agent pipe.
- WSL Mode A spike: validate WSL Git using Windows `ssh.exe` flow.
- WSL Mode B bridge risk-retirement path: retire enough risk to implement one scoped bridge path as stable V1 capability.
- Container socket exposure spike: support container/devcontainer workflows safely.
- External transport classification spike: distinguish transport failure from identity failure.
- TUI service-boundary spike: prove TUI can reuse CLI services without duplicate logic.

## 8. Implementation phases

1. Research and architecture spikes.
2. Core data model and config schema.
3. Identity and agent inventory.
4. Managed SSH config renderer.
5. Diagnostics engine MVP.
6. Context launcher MVP.
7. Windows OpenSSH support.
8. WSL Mode A.
9. WSL Mode B bridge implementation.
10. Container/devcontainer bridge implementation track.
11. Certificate inspection and external refresh hooks.
12. External transport integration via `ProxyCommand`.
13. TUI MVP.
14. Security hardening.
15. Packaging and release.
16. Documentation and public launch.

## 9. Sequencing logic

1. Research first because Windows/WSL/bridge behavior can break architecture assumptions.
2. Config/data model before features because renderer, doctor, launcher, and TUI need the same model.
3. Inventory before rendering because users need to know what identities and agents exist.
4. Renderer before doctor MVP because many findings compare desired route, generated route, and effective route.
5. Doctor before launcher because the product wedge is diagnosis, not command wrapping.
6. Launcher before bridges because scoped subprocess behavior is useful without bridge complexity.
7. Windows/WSL Mode A before Mode B, while preserving Mode B as a narrow V1 target for Linux-native WSL tools.
8. Bridge implementation and security gates before TUI polish.
9. TUI after CLI because CLI must remain fully capable.
10. Security hardening before packaging because packaging a security-sensitive tool without review erodes trust.

## 10. Validation strategy

### 10.1 Test pyramid

- Unit tests for models, config validation, redaction, renderers, parsers.
- Golden tests for CLI output and generated config.
- Integration tests with fake OpenSSH tools.
- Platform smoke tests on real OSes.
- Manual scenario tests for Windows/WSL and password-manager agents.
- Security tests for refusal behavior and redaction.
- TUI snapshot/model tests.

### 10.2 Fake command harness

Build a fake command runner that simulates `ssh -G`, `ssh -vvv`, `ssh-add`, `ssh-keygen`, Windows service state, and transport command failures.

### 10.3 Manual scenario suite

Scenarios include Linux with no agent, Linux with many identities, macOS password-manager socket, Windows service stopped, Windows identities loaded, WSL Windows-vs-Linux mismatch, WSL Mode A, WSL Mode B stable path or withheld execution, container socket variants, expired certs, missing `iroh-ssh`, ProxyJump mismatch, and coding agent broad access.

## 11. Security review checkpoints

1. Data model/config.
2. Inventory.
3. Renderer/include install.
4. Diagnostics.
5. Launcher.
6. Bridge.
7. Release.

Each checkpoint must review private-key custody, redaction, subprocess execution, generated file permissions, bridge permissions, logging behavior, and known limitations.

## 12. TUI design checkpoints

- Service boundary: TUI uses same services as CLI; no duplicate diagnostic or security logic.
- Core screens: dashboard, diagnostics, identities, agents, contexts, config preview, session launcher.
- Confirmation UX: include install shows exact diff; forwarding, bridge, and container flows show risk.
- Scope control: no terminal emulator, SFTP pane, cloud host sync, or host-manager sprawl.

## 13. Documentation checklist

Required docs:

- README with product thesis and non-goals;
- quickstart;
- install guide;
- `heimdall doctor` guide;
- identity and agent inventory guide;
- managed SSH config guide;
- context launcher guide;
- forwarding policy guide;
- Windows OpenSSH guide;
- WSL Mode A vs Mode B guide;
- container/devcontainer guide;
- certificate guide;
- `iroh-ssh`/external transport guide;
- security model;
- no-private-key-custody guarantee;
- threat model and limitations;
- troubleshooting;
- contribution guide;
- release verification guide.

Docs must explicitly say Heimdall does not store private keys or passphrases, does not replace OpenSSH, does not solve remote reachability, and treats agent sockets and forwarding as credential delegation.

## 14. Packaging/release checklist

Pre-release:

- CI green on Linux/macOS/Windows;
- tests pass;
- security review complete;
- dependency review complete;
- docs complete;
- sample configs validated;
- release notes drafted.

Release artifacts:

- Linux amd64/arm64;
- macOS amd64/arm64;
- Windows amd64/arm64 if feasible;
- checksums;
- signatures where practical;
- SBOM where practical;
- shell completions;
- man page or markdown command reference.

Distribution:

- GitHub Releases;
- Homebrew tap;
- Scoop/Winget plan;
- optional Debian/RPM after V1.0 confidence.

## 15. Testing matrix

| Area | Linux | macOS | Windows | WSL | Container |
| --- | --- | --- | --- | --- | --- |
| Config parse/validate | automated | automated | automated | automated | n/a |
| Public key inventory | automated | automated | automated | automated | automated |
| Agent probe | automated + manual | automated + manual | manual/CI | manual | automated |
| Generated config | automated | automated | automated | automated | n/a |
| Include install | automated temp dirs | automated temp dirs | automated/manual | automated temp dirs | n/a |
| Doctor global | automated | automated | automated/manual | automated/manual | automated |
| Doctor host | automated fixtures | automated fixtures | automated fixtures | automated fixtures | n/a |
| Run launcher | automated | automated | automated/manual | automated/manual | n/a |
| Windows doctor | n/a | n/a | automated/manual | callable from WSL | n/a |
| WSL Mode A | n/a | n/a | n/a | manual/fixture | n/a |
| WSL Mode B | n/a | n/a | n/a | stable selected path plus manual/security tests | n/a |
| Container doctor | automated with Docker | manual | manual | manual | automated |
| Certs | automated | automated | automated | automated | n/a |
| Transport routes | automated fixtures | automated fixtures | automated fixtures | automated fixtures | n/a |
| TUI | automated model tests | automated model tests | smoke | smoke | n/a |

## 16. Risk register

| Risk | Impact | Probability | Mitigation |
| --- | --- | --- | --- |
| Product drifts into generic SSH host manager | High | Medium | Keep host routes tied to identity/context; no terminal emulator, SFTP pane, cloud host sync, or bookmark-first UX. |
| Product drifts into vault-like behavior | Critical | Medium | No private key reads/import/storage; embedded key rejection tests; docs point to existing agents/password managers. |
| Windows/WSL complexity overwhelms V1 | High | High | Make Mode A default; constrain Mode B to one audited, useful bridge path. |
| Bridge mode expands into daemon-heavy architecture | High | Medium | Session-scoped helper only; no default daemon; Gate F approves only a small auditable path. |
| Unsafe agent socket exposure | Critical | Medium | Explicit warnings; scoped sockets; permission tests; no silent container/WSL mounts; fail closed. |
| Users misunderstand external transport vs SSH identity failures | Medium | High | Phase classification; transport handoff messages; docs state Heimdall does not solve reachability. |
| Generated config conflicts with existing config | High | Medium | Managed fragment only; `ssh -G` validation; diff; backup; rollback. |
| Password-manager agent compatibility issues | Medium | High | Treat providers as OpenSSH-compatible agents; avoid vault/database/internal IPC assumptions. |
| Diagnostics produce false confidence | High | Medium | Confidence levels; evidence-first findings; active probe consent; avoid overclaiming. |
| Private key file accidentally read by inventory | Critical | Low/Medium | File access wrapper tests; no private-key parsing; security review. |

## 17. Cut-if-needed list

Cut in this order under schedule pressure:

1. TUI polish beyond the minimal doctor/inventory/context surface.
2. Container bridge beyond doctor/detection/snippet generation.
3. External transport integration beyond generic `ProxyCommand` and `ProxyJump` support.
4. Certificate refresh hooks beyond inspection and explicit dry-run hooks.
5. Advanced onboarding flows.
6. Hardware key polish.
7. Log/event browser.
8. Optional WSL Mode B variants beyond the one validated stable path.
9. Post-V1 roadmap detail.

Do not cut the no-private-key-custody boundary, no passphrase storage, managed config strategy, core diagnostics, identity and agent inventory, config rendering, context launcher, Windows/WSL Mode A diagnostics, WSL Mode B threat model/stable-path attempt/security gate, or security review.

Cut rule for WSL Mode B: do not ship a vague prototype simply to claim support. Ship one small, reviewed, operational path or cut the bridge feature with a clear ADR and keep Mode A plus diagnostics.

## 18. Post-V1 roadmap

### 18.1 V1.1 candidates

- polish TUI;
- improve Windows named-pipe compatibility;
- broaden WSL Mode B after validated V1 usage;
- improve container bridge with scoped sockets;
- better hardware-key detection;
- richer certificate refresh integrations;
- more examples for 1Password/KeePassXC;
- Homebrew/Scoop/Winget packaging improvements.

### 18.2 V1.2 candidates

- policy templates for common contexts;
- richer transport diagnostics plug-ins;
- richer shell completion and command reference;
- optional local encrypted storage for non-secret metadata only;
- host-route import from existing SSH config with review, not automatic rewrite;
- destination-constrained agent key assistance where supported.

### 18.3 V2 candidates requiring major review

- persistent local daemon;
- richer bridge broker with policy enforcement;
- plugin system;
- local MCP server;
- team-shared read-only policy templates;
- deeper certificate workflow integrations.

### 18.4 Still discouraged post-V1

- private-key custody;
- passphrase storage;
- cloud sync of secrets;
- enterprise PAM;
- SSH client replacement;
- transport implementation;
- remote inventory scanning.

## 19. Spec-to-plan traceability

| Spec requirement | Plan phases |
| --- | --- |
| Identity control plane, not host manager/vault/client/transport | Phases 1, 14, 16; Gate G; Risk register |
| No private key custody | Phases 1, 2, 3, 14; Gate A |
| Managed OpenSSH config fragment | Phases 2, 4, 5; Gate B |
| `heimdall doctor` flagship | Phase 5; Gate C |
| Identity and agent inventory | Phase 3 |
| Context launching | Phase 6; Gate D |
| TUI control surface | Phase 13; Gate G |
| Windows OpenSSH support | Phase 7 |
| WSL Mode A | Phase 8; Gate E |
| WSL Mode B bridge | Phase 9; Gate F |
| Container/devcontainer workflows | Phase 10 |
| Forwarding policy | Phases 2, 4, 5, 6, 14 |
| Remote hop / bastion workflows | Phases 4, 5, 12 |
| External transport via ProxyCommand, especially iroh-ssh | Phase 12 |
| Certificate visibility and refresh hooks | Phase 11 |
| Optional ephemeral broker/helper | Phases 9 and 10 |
| Logging and diagnostics redaction | Phases 2, 5, 6, 14 |
| Packaging and release | Phase 15 |
| Documentation and public launch | Phase 16 |

## 20. Initial backlog by component

### 20.1 CLI backlog

- root command and global flags;
- doctor, host doctor, platform doctors, forwarding, certs, and transport doctors;
- identities, agents, contexts, context add;
- run and ssh;
- config render, install-include, doctor, diff, rollback;
- WSL Mode A and Mode B commands;
- container bridge snippets;
- transport add and doctor;
- certs;
- TUI.

### 20.2 Diagnostic rule backlog

- missing include;
- stale generated config;
- broken `SSH_AUTH_SOCK`;
- empty agent;
- too many identities;
- missing `IdentitiesOnly`;
- unexpected `IdentityAgent`;
- global `ForwardAgent yes`;
- expired/missing cert;
- Windows OpenSSH missing;
- Windows agent service stopped;
- WSL Windows-vs-Linux identity mismatch;
- container socket missing/dead;
- `ProxyCommand` binary missing;
- coding agent broad access.

### 20.3 Docs backlog

- quickstart examples;
- sample config for GitHub;
- sample config for homelab with bastion;
- sample config for `iroh-ssh`;
- sample WSL Mode A setup;
- sample WSL Mode B bridge setup, warning, and refusal cases;
- sample devcontainer snippet;
- cert inspection examples;
- doctor output examples.

## 21. Implementation notes and constraints

- Avoid magical config expansion.
- Prefer command runners over direct shell.
- Keep bridge code isolated.
- Treat password managers as external providers.
- Treat active probes as privacy-sensitive.
- Make generated config boring.
- Use confidence levels honestly.

## 22. Public launch acceptance checklist

Heimdall is ready for initial public release when all are true:

- `heimdall doctor` finds real issues and explains them clearly.
- Inventory works without private-key custody.
- Managed config render/install/rollback is safe.
- Context launcher works and fails closed.
- Linux/macOS are solid.
- Windows doctor is useful.
- WSL Mode A is useful.
- WSL Mode B has one stable reviewed path, or runtime bridge commands are explicitly withheld/cut.
- Container/devcontainer support at least diagnoses and generates snippets.
- Certificate inspection works.
- External transport support is explicitly limited to OpenSSH config integration.
- TUI MVP does not block CLI and does not drift into generic host manager.
- Security docs are blunt.
- Release artifacts are checksummed and, where practical, signed.
- README says what Heimdall refuses to do.
