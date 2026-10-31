# Heimdall — Product and Technical Specification

**Version:** 0.1.0  
**Status:** Implementation-planning draft; product direction established, technical gates not yet executed  
**Prepared:** October 1, 2026  
**Companion:** [plan.md](plan.md)  
**Working release:** Single-owner, local-first V1 with a standalone CLI and built-in TUI  
**Implementation language:** Rust + Ratatui, selected at G02 on 2026-10-31 (docs/decisions/0002, 0004)

> Set up access once. Your terminals, tools, and agents work across environments. Heimdall handles the machinery.

## Reading this document

This is a specification for a proposed product, not documentation for software that already exists. No implementation, interoperability result, performance measurement, security review, or user-research outcome is claimed here. External technical facts have source references; proposed behavior is the design to build and test.

**MUST / MUST NOT** identify release requirements within the stated support scope. **SHOULD** identifies a default that can change only with a recorded reason and corresponding tests. **MAY** identifies an optional capability. A feature being optional for a user is different from its implementation being optional for a release.

The current conversation's confirmed decisions supersede older thin-wrapper, no-daemon, no-custody, and transport-exclusion assumptions. They do not authorize exporting existing private keys, enrolling machines, or modifying live accounts during development. This document authorizes no external action.

`spec.md` defines behavior and release obligations. `plan.md` defines how to establish feasibility and deliver them. The plan cannot silently weaken this specification to make a milestone pass. Proposed defaults and gated implementation choices are explicitly distinguished from user-confirmed requirements.

### Contents

1. [Mission and product boundaries](#1-mission-and-product-boundaries)
2. [Decision ledger](#2-decision-ledger)
3. [Release scope and platform contract](#3-release-scope-and-platform-contract)
4. [Domain model](#4-domain-model)
5. [User experience and automatic activation](#5-user-experience-and-automatic-activation)
6. [Access semantics and time](#6-access-semantics-and-time)
7. [Credential mechanisms and enrollment](#7-credential-mechanisms-and-enrollment)
8. [Environments, portability, and delegation](#8-environments-portability-and-delegation)
9. [Destinations, routes, and host trust](#9-destinations-routes-and-host-trust)
10. [OpenSSH and consumer integration](#10-openssh-and-consumer-integration)
11. [CLI, API, and agent contracts](#11-cli-api-and-agent-contracts)
12. [TUI behavior](#12-tui-behavior)
13. [Runtime architecture and state](#13-runtime-architecture-and-state)
14. [Threat model and safeguards](#14-threat-model-and-safeguards)
15. [Reliability, performance, and distribution](#15-reliability-performance-and-distribution)
16. [Requirements registry](#16-requirements-registry)
17. [Acceptance scenarios](#17-acceptance-scenarios)
18. [Decision gates and non-goals](#18-decision-gates-and-non-goals)
19. [Research basis and source register](#19-research-basis-and-source-register)

## 1. Mission and product boundaries

### 1.1 The outcome

Heimdall is a personal SSH access system. It owns establishing, using, maintaining, and moving SSH access across machines and execution environments. Its customers should make meaningful decisions about access, not repeatedly coordinate password-manager CLIs, agents, sockets, executable paths, approval persistence, certificate refresh, or tunnel processes.

The initial user is a technical individual operating Windows, a Mac, WSL, homelab hosts, remote VPSs, containers, and coding tools. The product starts with this demanding personal workflow and can be publicly distributed. It does not start as a multitenant enterprise access platform.

The central promise has two parts:

- Routine work in a configured, trusted environment requires no additional approval or setup within its saved authorization.
- A user can determine what access exists, why it exists, where it is being used, and how to stop it without learning the implementation.

Heimdall should be ambitious about accomplishing that outcome and selective about implementing the underlying technology. Owning setup and operation of an existing component is acceptable; reimplementing a mature component without an established need is not a goal.

### 1.2 What Heimdall owns

Heimdall owns identity selection, supported credential lifecycle management, local consumer integration, environment-specific access paths, optional connectivity helpers, configuration reconciliation, predictable unattended access, portable intent, readiness checks, and recovery of resources it manages.

Diagnostics are an instrument of repair. A diagnostic report that merely tells the user to perform routine plumbing is not sufficient when Heimdall already has authority and a supported mechanism to fix it.

For destinations whose authentication cannot change, Heimdall owns the full supported client-side experience. For destinations where account credentials can be registered, it can additionally automate enrollment. For administrable destinations, it can establish deeper credential lifecycle and trust infrastructure. These capabilities coexist; remote enrollment is never a prerequisite for ordinary use.

### 1.3 What the promise does not mean

A provider that will not sign while locked and a server that requires a fresh human authentication factor cannot be made unattended by changing a local label. Heimdall must discover a suitable authorized mechanism, help establish it where permitted, and otherwise accurately describe the supported workflow. It must not pretend to have reproduced the provider's security properties after changing them.

"Works across environments" means portable access intent and supported access preparation. It does not mean live process migration, filesystem synchronization, coding-conversation synchronization, moving a sleeping machine's execution elsewhere, or universal support for every embedded SSH implementation.

"Agent-first" means deterministic, composable interfaces and minimal infrastructure reasoning for callers. Heimdall must not require an LLM, model subscription, a particular harness, MCP, or a mandatory hosted account to function.

### 1.4 Success and falsification

Success is demonstrated against the user's recurring work, not the number of adapters or settings implemented. The release must outperform a documented baseline of correctly configured OpenSSH and supported providers on repeated setup steps, interruptions, cross-environment recovery, and agent task completion.

The product hypothesis is weakened if its ordinary use requires more mental bookkeeping than that baseline, if a custom launcher becomes necessary for every basic SSH use, or if the fixed-authentication path is materially neglected. Such evidence should change scope or implementation—not be hidden by adding UI polish.

## 2. Decision ledger

### 2.1 Confirmed product direction

| ID | Decision | Consequence |
|---|---|---|
| C01 | A standalone CLI and built-in TUI are both central. | No TUI-only functionality; no GUI required. |
| C02 | The language was left open until G02. | Go/Bubble Tea, Rust/Ratatui and TypeScript/OpenTUI were evaluated; Rust + Ratatui was selected on 2026-10-31 (ADR-0002). |
| C03 | Heimdall should own the whole SSH access experience, not remain a meek wrapper. | Provisioning, services, credential management, and repair are legitimate options. |
| C04 | First-class use includes homelab hosts, VPSs, and fixed-authentication destinations. | No forced enrollment or certificate-only architecture. |
| C05 | Approved work normally continues through desktop and personal-vault lock until its configured deadline. | Use an actually available execution credential or signer; disclose and configure this behavior. |
| C06 | Explicitly trusted projects may activate access automatically under a preapproved policy. | No repeated approval for equivalent work. |
| C07 | Low cognitive load is a release requirement. | Routine users should not manage leases, refresh timers, or socket paths. |
| C08 | Agent-first and composable architecture is required. | Stable structured contracts, resumability, and useful primitives are core. |
| C09 | Access must follow the execution environment. | Remote work should not depend unnecessarily on the controlling laptop. |
| C10 | Iroh and T3's approaches should inform the design. | Evaluate reuse and learn lifecycle patterns without copying their entire products. |
| C11 | Windows/WSL cannot be an afterthought. | Native Windows and both WSL access paths require explicit validation. |
| C12 | Configuration adoption must be reversible and non-destructive. | Managed projections and deliberate adoption rather than arbitrary rewriting. |
| C13 | Personal use first, with a credible path to public distribution. | Local-first operation and maintainable packaging; no enterprise account prerequisite. |

Earlier acceptance of Go/Bubble Tea is historical, not a present language decision. Earlier preferences for no credential custody, no daemon, and external-only transport have been reopened. Creating managed execution credentials is a candidate; automatically extracting personal-vault keys is not approved.

### 2.2 Proposed defaults for this draft

These make the draft implementable without claiming that the user explicitly chose each one. Gate G01 in the plan records any changes.

| ID | Draft default | Why it is provisional |
|---|---|---|
| P01 | A small per-user access runtime, started and supervised automatically after setup. | Windows endpoint behavior and secure store availability must validate the process shape. |
| P02 | Single owner; each execution environment has its own identity and authority realization. | Remote management remains deliberately small, not a fleet service. |
| P03 | Convenient environment-level access for ordinary trusted tools; explicit bindings for concurrent/project-specific work. | No claim of hostile same-user process isolation. |
| P04 | New trusted-work sessions inherit a 12-hour maximum window, visible and adjustable during setup. | A usability default, not an evidence-derived optimum; no recurring duration form. |
| P05 | Automatic access is opt-in when a project is first trusted; routine renewal under that decision is silent. | Trust is stored outside the repository. |
| P06 | Existing dedicated sessions may remain connected after ordinary expiry; new authentication stops. Owned shared masters stop admissions through a verified control operation or are closed. | Users can choose a stricter disconnect policy; strict means controlled connections, not arbitrary remote processes. |
| P07 | OpenSSH remains the reference SSH client; no new general-purpose SSH client implementation. | Alternative clients must pass adapter conformance tests. |
| P08 | A transactional local state store; SQLite is the starting candidate. | Validate permissions, crash behavior, migrations, and Windows file semantics. |
| P09 | No telemetry by default, no public relay without a disclosed opt-in, no automatic installation of arbitrary plugins. | Public distribution and optional connectivity must not change these silently. |
| P10 | Local configuration is human-editable TOML with a generated JSON schema. | Syntax is a proposal; semantic model is the binding contract. |

The numeric session default, storage implementation, supported OS floors, selected credential recipe, local IPC transport, remote control transport, and language are not settled technical facts. Each has an explicit decision gate.

## 3. Release scope and platform contract

### 3.1 V1 is an end-to-end slice, not a diagnostics MVP

A development milestone can be narrow. A release described as V1 must meet the entire required scope below or clearly be called a preview. Failure of a mandatory gate must not silently convert a requirement into documentation-only support.

| Capability | V1 obligation | User choice |
|---|---|---|
| Existing-access adoption and ordinary SSH/Git use | Required | No remote modification necessary. |
| CLI and useful TUI with shared operations | Required | Either interface can be used independently. |
| Native agent and 1Password reference integrations | Required on declared matrix | Provider remains optional; no mandatory vendor. |
| At least one end-to-end managed execution-credential recipe | Required | Enrollment remains opt-in. |
| Trusted-project automatic activation | Required | Personal profiles also work without any repository. |
| Desktop/vault-lock continuity | Required for the managed recipe on supported local environments | Fixed-provider limitations reported precisely. |
| Windows native, WSL Mode A, scoped opt-in WSL Mode B | Required, with actual host tests | WSL is not mandatory for Windows use. |
| Linux and macOS workflows | Required | Exact version floors set by G01. |
| Remote Linux execution environment independent of controller presence | Required | No installation on fixed-auth destinations. |
| Local Linux-container binding and expiry behavior | Required | Does not imply sandboxing hostile containers or universal Docker Desktop parity. |
| Multiple routes and a usable bastion flow | Required | Direct SSH remains baseline. |
| One integrated or managed Iroh/Pigeons reference flow | V1 target requiring G06; mandatory for an Iroh-enabled V1 claim | Entire feature opt-in; no external-network exposure by default. |
| Bound operation IDs, status/events, cancellation, idempotent preparation | Required | Hidden from ordinary UI unless helpful. |
| Delegation data model and one tested narrower binding | Required | Cross-boundary isolation claims only on validated mechanisms. |
| Standalone SDK(s), MCP adapter, automated hosted-account enrollment | Later, unless a tiny adapter is justified by a proven core | Not prerequisites for core behavior. |
| Managed Windows remote runner, full OCI orchestration, multi-owner policy | Later | Not silently implied by local Windows or container support. |

An Iroh research failure requires a recorded release-scope decision; it may produce a named transport preview or defer the integration, but never a fabricated assertion that it is supported. The existing-access, Windows/WSL, managed unattended, CLI/TUI, and agent contracts are not eligible for this transport-specific deferral.

### 3.2 Initial validation targets

The initial test architectures are Windows x86-64, WSL2 Linux x86-64, macOS arm64, and Linux x86-64 plus arm64. G01 selects supported OS/distribution releases and minimum SSH versions from actual clean-machine tests. An untested architecture is not supported merely because it compiles.

Windows tests include the installed Windows OpenSSH client, PowerShell, and the relevant named-pipe/credential-store behavior. WSL tests include both Windows-SSH execution and Linux-native agent access. Linux tests include a desktop/user service and a headless remote runner. macOS tests distinguish screen lock, account logout, sleep, and reboot.

Lock continuity does not imply that computation continues while a machine sleeps or is powered off. On wake or restart, absolute deadlines and explicit pauses still apply. Headless boot persistence is a separate capability that must identify whose credentials are available and why.

### 3.3 Compatibility labels

Each provider × client × environment × mechanism combination has one of: `verified`, `supported-with-limitations`, `experimental`, `unsupported`, or `not-tested`. Record versions, observation time, test IDs, and limitations. A detected executable does not establish support. A reachable socket does not establish permission to sign. A successful login does not establish the ability to log in after lock or expiry.

## 4. Domain model

### 4.1 Objects

| Object | Meaning and key fields |
|---|---|
| Owner | The person controlling a personal installation; not a multi-tenant organization. |
| Device | A cryptographically enrolled machine identity with label, public identity, lifecycle state, and recovery history. |
| Environment | The actual execution/OS-principal boundary: native session, WSL distribution, container context, or remote runner. Has a stable ID, device association, capabilities, local realization, and management permissions. |
| Destination | A logical target machine/service plus separately represented remote accounts, known host identity, labels, and authorized routes. |
| Access relationship | Environment + destination + account + available enrollment/credential capabilities. Authority can vary by account on the same host. |
| Identity reference | Stable logical identity name linked to public fingerprints and one or more supported signing/credential sources. Never a private key in portable configuration. |
| Route | Direct address, jump path, or approved transport endpoint. A route is reachability information, not permission or host identity. |
| Profile | Named access intent with a resolved set of destinations/accounts and preferences. Mutable definition, immutable resolved snapshot for active work. |
| Workspace | A locally enrolled checkout/worktree identity associated with a project manifest and a separately persisted trust decision. A Git remote URL is descriptive, not proof of identity. |
| Standing policy | A saved user decision permitting automatic creation of bounded access under defined scope and environments. Includes limits, pause/cutoff state, and policy revision. |
| Work binding | A stable association between a running context and a resolved environment/profile snapshot. Contains a work ID, optional parent, and lifecycle. |
| Grant | Effective permission for a binding with start/deadline, scope, parent, policy revision, source of authorization, enforcement evidence, and revocation state. Not normally exposed as a mandatory UI concept. |
| Credential instance | A key handle, certificate, provider session, or supported signer binding used to realize a grant. Its lifetime may be shorter than the grant. |
| Operation | A durable operation ID, request identity, request hash, effect classification, state, result, and recovery metadata. |
| Managed resource | An endpoint, process, file generation, trust entry, certificate, route helper, or remote enrollment owned by a specific generation. |

### 4.2 Identity distinctions

A device public key, an Iroh endpoint ID, an SSH host key, an SSH user key, a certificate-authority key, and a Unix account are different identities. None can substitute for another without an explicit authenticated binding. Friendly aliases may change; durable IDs must not silently change when routes, IP addresses, or display names change.

A workspace ID identifies an adopted checkout, not a trusted security principal by itself. A caller-supplied `agent_name` or PID is metadata, not authentication. PID reuse must not make a stale process record authoritative.

### 4.3 Capability and guarantee reporting

Guarantees are structured, not a single "secure" badge. Results distinguish:

- Identity selection: enforced by client configuration, signer filtering, or another named mechanism.
- Destination/account restriction: unenforced intent, client routing, authenticated agent restriction, verified server principals, or isolated execution boundary.
- Credential availability: current-only, available through a deadline, refresh-dependent, or interaction-required.
- Expiry: new signing, new authentication, controlled connections, and remote process effects as separate fields.
- Revocation: applied locally, acknowledged remotely, pending, or bounded only by an already-issued credential's expiry.
- Isolation: shared OS-user environment, separately authenticated service boundary, or a specifically tested isolated workload.

Every enforcement claim references evidence, supported versions, and a test. Unknown remains a valid state. A noninteractive caller can request a minimum capability and receive `CAPABILITY_UNAVAILABLE` rather than silently weaker access.

## 5. User experience and automatic activation

### 5.1 Normal vocabulary

Use machines, identities, projects, access, and activity. Avoid presenting leases, issuers, policy epochs, and token lifetimes as onboarding concepts. Advanced details remain available and accurate. Credentials are not marketed as temporary if a saved authorization effectively permits continuous renewal.

The default TUI answers: What is available? Where is work running? Does anything need attention? How do I pause or stop access? Successful background maintenance should usually be invisible.

### 5.2 First-run setup

A first run must provide a useful path with existing access before proposing migration. Passive discovery inventories supported clients, configured identities, provider endpoints, and known aliases without triggering external authentication. Explain uncertain findings rather than inventing effective configuration.

Adoption previews the exact locally managed files, service/endpoint changes, and optional integrations. A normal user need not inspect every line, but changes must be inspectable. Permission to adopt is not permission to rewrite unrelated configuration or replace another global agent without explanation.

The selected setup may offer improved unattended access when the user can enroll a working credential. Remote changes are a distinct step, with a demonstrated rollback path and retained access. Installing optional transport does not automatically expose every local service.

A representative first-trust message is:

> Use Homelab development access automatically for this project? Work can continue while your desktop and password manager are locked, using your saved session limits. You can pause or remove access at any time.

Show the destination/account scope and execution environments in an immediately available detail view. The default session window is disclosed here and in settings, not requested again on each use.

### 5.3 Automatic project activation

A trusted workspace can activate access on an explicit `ensure`/`run`, an installed shell integration, or a supported environment integration. Shell integration is opt-in and executes only Heimdall's installed code. A repository manifest never introduces shell hooks, downloads, arbitrary adapter executables, or approval decisions.

Automatic activation resolves the requested intent against the saved policy and current environment identity. It creates or reuses an appropriate binding/grant, prepares consumer integration, and returns usable state. Equivalent activity does not trigger a new human prompt.

Ordinary source edits and branch changes do not revoke the workspace's saved trust. Changes to requested access, remote accounts, execution environments, hook references, or policy-sensitive manifest content are evaluated as access changes. Only the added authority requires a decision; unaffected authorized access remains usable where possible.

Trust is neither granted to every clone with the same remote URL nor transferred through a copied `.git` directory. Moving a checkout can be reconciled using local enrollment records and owner confirmation when identity is ambiguous. Worktrees and submodules have documented treatment; parent-directory trust is not silently recursive.

### 5.4 Repository-free use

A personal profile can support normal administrative SSH use without a workspace or agent. `ssh lab-server` should work after supported setup. Project-specific restrictions require a bound context where the integration can establish that context; Heimdall must not pretend a standard agent protocol message securely identifies a repository or current working directory.

### 5.5 Interruptions

Silent operations include equivalent access preparation, credential renewal within a grant, helper recovery, duplicate requests, and route recovery consistent with host trust. Interruptions are reserved for newly requested authority, material changes in trust, explicit user-imposed limits, or a real inability to continue.

One logical decision should generate one coalesced approval request, even with concurrent callers. A denied or dismissed request does not generate a retry notification storm. There are cooldowns and a visible pending state. Human-only provider dialogs are described as provider interactions, not disguised as Heimdall's permission prompts.

### 5.6 Control without ceremony

Provide an immediately accessible pause of automatic access, a stop for selected work, and revoke/remove actions with differentiated effects. Pausing a saved policy prevents future automatic activations; it need not terminate existing work unless requested. "Stop Heimdall access for this profile" must revoke active applicable grants and block reactivation, not merely kill a helper that the supervisor immediately restarts.

A user can inspect advanced duration settings, change the lock behavior, choose stricter connection termination, or explicitly configure a continuous runner. These are preferences, not required daily administration.

## 6. Access semantics and time

### 6.1 Standing permission versus bounded work

A saved policy can outlive a grant. It permits creation of new bounded work sessions under explicit scope. An individual grant has an immutable maximum deadline. Credential renewal maintains that grant; it never extends the deadline or adds destinations/accounts.

A normal duration limit bounds the current work binding. New, genuinely separate work can receive a fresh grant under the saved policy. This is not a claim that all future access disappears after the first session ends. Documentation and UI must make this distinction discoverable.

An explicit command such as "stop automatic access at 02:00" creates a policy cutoff for the selected scope, not just a credential timestamp. After that cutoff, new work IDs, restarted agents, or repeated requests must not reactivate access until the cutoff is deliberately cleared. User pauses and cutoffs outrank standing automatic permission.

A continuing work binding cannot reset its expiry by changing a request ID. Fresh work identifiers are not an anti-malware boundary when the same authenticated caller is already authorized to create new work under a standing policy. Hard stops use the policy cutoff, and stronger workload identity requires the isolation mechanism declared in the guarantee report.

### 6.2 Effective authority

The effective set is the intersection of the owner's saved policy, enrolled environment permissions, requested resolved scope, parent delegation (if any), destination capability, and active pause/cutoff constraints. Explicit deny and pause override allow. Command-line options may narrow or request authority; they cannot grant new authority.

Resolve a profile into a destination/account snapshot at activation. Adding another host to the profile does not silently widen an existing grant. A dynamic group can be supported only as a separately disclosed standing rule with bounded semantics; it is not the default.

Requests use absolute RFC 3339 timestamps with offsets or durations converted once at creation. Store UTC, display local time with timezone context, and retain the original intended deadline. Ambiguous local times require disambiguation at the human input boundary; machine requests must be unambiguous.

### 6.3 Grant state machine

| State | Meaning | Allowed transitions |
|---|---|---|
| `requested` | Intent recorded; no usable access promised. | `preparing`, `awaiting_approval`, `denied`, `cancelled` |
| `awaiting_approval` | Additional owner/provider action required. | `preparing`, `denied`, `cancelled`, `expired` |
| `preparing` | Authorized resources are being reconciled. | `active`, `degraded`, `failed`, `cancelled`, `revoked`, `expired` |
| `active` | Specified capability verified within recorded evidence freshness. | `degraded`, `expired`, `revoking`, `released` |
| `degraded` | Some capability unavailable; authorized repair may proceed. | `active`, `failed`, `expired`, `revoking`, `released` |
| `revoking` | Local denial applied; remote effects may be pending. | `revoked` or remains pending with explicit evidence |
| `revoked` / `expired` / `released` / `denied` / `cancelled` | Terminal for that grant. | No reactivation of the same grant; a separately authorized operation may create new work. |
| `failed` | Required preparation could not complete. | No hidden access promise; recovery creates a new attempt tied to the original operation and unchanged authority. |

The state machine must be executable/testable. A `released` consumer reference need not revoke a shared grant still used by other authorized bindings. Reference counts are ownership-aware and cannot retain access past expiry.

### 6.4 Lock, sleep, logout, and reboot

Desktop and personal-vault lock do not, by default, end an approved managed-access session. This is achieved by a suitable credential/signer lifecycle—not by keeping the personal vault unlocked or suppressing its controls. Users can choose lock-revokes behavior.

Sleep stops local execution; it does not suspend the deadline. On wake, check validity before any new signing or admission. Logout/reboot may make a store or service unavailable. A supported recovery can restore only unexpired authorized state; it cannot infer renewed permission from a saved process file.

Use monotonic elapsed time within a process and persisted absolute deadlines across restarts. Detect implausible clock rollback, bound tolerated skew, and stop issuance when the authority cannot establish safe time. Server clock errors must be diagnosed distinctly. No claim protects against a fully compromised root/admin controlling both the clock and enforcement.

### 6.5 Credential renewal and offline coverage

A credential's not-after time cannot exceed the effective grant or applicable parent/cutoff. A short refreshable credential is useful only if the executing environment can actually obtain replacement credentials without the controlling laptop.

Before reporting unattended readiness, compute `usable_until`, `refresh_dependency`, `offline_until`, and the conditions under which they remain true. To meet a longer offline job, Heimdall may arrange an authorized bounded credential covering that interval or use an available approved issuer. It must not copy an unrestricted issuer key to a worker or claim that a fifteen-minute cached credential covers an overnight disconnection.

Longer offline validity and faster remote revocation are a tradeoff. The selected managed recipe must state the maximum residual remote-access window after revocation when the destination or runner cannot be reached. A short internal rotation cadence does not eliminate an already-issued credential's validity.

### 6.6 Deadline effects

Separate the end of new signing, new SSH authentication, reusable connection admissions, controlled live connections, and remote processes. OpenSSH multiplexing can reuse an authenticated master without a fresh key operation; `ControlPersist` is not a Heimdall grant timer. [S01]

The default blocks new Heimdall-mediated authentication at expiry. Heimdall-owned multiplexed masters must not accept new sessions beyond their grant; close them at expiry unless a tested mechanism can stop admissions independently. Default bounded contexts SHOULD disable multiplexing when graceful channel-level enforcement cannot be established.

Existing dedicated nonmultiplexed connections may remain usable under the draft graceful policy. This is not command-level completion enforcement: an existing interactive shell or forwarding session can still carry new activity. The UI detail must say "New connections stop at the deadline; existing sessions may stay connected," rather than imply all work ends then. Strict disconnect closes owned connections at expiry. Detached remote processes are not automatically terminated, and unmanaged connections outside Heimdall are not controlled. No deadline UX may imply stronger effects than its mechanism provides.

### 6.7 Revocation and delegation

Revocation immediately denies new local operations for the affected grant and descendants. Persist a tombstone/generation before acknowledging local success. Invalidate approval races, renewals, and retries against the previous generation.

Remote enforcement is acknowledged separately. Offline runtimes may continue with previously issued credentials until their validity or local grant ends. Report `local_applied`, `remote_pending`, and `latest_possible_credential_expiry`; do not report universal immediate revocation without evidence.

A delegated grant is a subset of parent scope and has an equal or earlier deadline. Parent expiry, revocation, and applicable policy cutoff cascade. Copying a credential with all parent privileges is not narrower delegation. Server principals, signer restrictions, or a validated isolated binding must support the claim.

## 7. Credential mechanisms and enrollment

### 7.1 Mechanism-neutral, not mechanism-oblivious

At least one complete managed execution-credential recipe is required. The selection is gated, not assumed. The candidate set includes device/work-specific keys protected by an appropriate signer, standard SSH certificates, and integration with an existing issuer. Native or external agents remain usable without migration.

1Password documents that remembered approvals do not keep its private keys available after the app locks. Its approval model distinguishes requesting applications/sessions, so a shared relay may also change attribution. These are reasons to test a different execution-credential lifecycle and provider attribution—not to claim that a relay preserves every provider property. [S06][S07]

The 1Password Environments MCP server manages environment variables and local mounts; it is not the foundation of Heimdall's SSH design. SSH Bookmarks already offers host/key configuration, so reproducing that feature alone is not sufficient product differentiation. [S08][S09]

### 7.2 Credential classes

| Class | Required treatment | Unattended expectation |
|---|---|---|
| Existing external signer | Discover and use its documented interface; preserve provider controls; no automatic key extraction. | Based on verified provider capability, not assumed. |
| Existing file-backed/native-agent identity | Adopt explicitly; preserve source ownership; never weaken passphrases or file permissions silently. | Depends on agent/store lifecycle and requested continuity. |
| Heimdall-managed execution key | Generated for a defined environment/access purpose; protected at rest and through a signer where supported. | V1 recipe must validate lock continuity and expiry behavior. |
| SSH user certificate | Public certificate plus separate private signing-key handle; validate principals, validity, issuer trust, and extensions. | Refresh or preissuance must cover the intended work. |
| Hardware presence-required identity | Preserve touch/PIN policy. | Cannot promise unattended use when the hardware requires presence. |
| Password/keyboard-interactive/MFA destination | Preserve native supported interaction; diagnose accurately; no credential scraping. | Supported interactively; automatic use only through an authorized mechanism that actually permits it. |

Git signing and arbitrary signing are not implicitly authorized by permission for SSH authentication. The signing adapter must distinguish purpose and reject unsupported request types. Session-bound restrictions must use tested protocol support and established libraries, not guessed parsing or custom cryptography. [S03]

### 7.3 Custody rules

Managing a working private key is custody, even if ephemeral. Documentation must say so. The V1 managed recipe must define generation, storage, unlocking, use while locked, loss, rotation, backup policy, destruction, and recovery for every private-key class.

Existing personal-vault keys must not be exported automatically. Portable manifests, ordinary JSON results, arguments, environment variables, logs, diagnostics, and clipboard flows must not contain private keys, passphrases, or reusable bearer credentials. Public identifiers can still be sensitive metadata and require redaction options.

Use platform-supported secret storage or a reviewed encrypted store with an explicit availability model. A mode that cannot retrieve a key after lock must not be called lock-independent. Falling back to plaintext because a keychain is unavailable is prohibited. Access under the same logged-in OS user is not represented as protection against a fully compromised user session.

Private authority/CA keys must be separated from worker credentials and excluded from project-access endpoints. No worker receives an unrestricted CA private key as a shortcut to renewal. Where a per-user issuer is used, its actual same-user compromise boundary must be disclosed; stronger issuer isolation requires an actual separate service/account or external issuer.

### 7.4 Three enrollment capabilities

1. **Existing access only:** no remote mutation. Configure the supported local path, preserve the existing auth mechanism, and diagnose its limits.
2. **Account-level control:** add a dedicated key or permitted certificate-authority entry to the account's actual supported key registry. Do not require system administration when account authority is sufficient.
3. **Authentication administration:** configure approved server trust/principal rules or integrate an existing issuer. Remote service installation is optional and justified by needed capability.

OpenSSH supports `cert-authority` and principal restrictions in authorized-key records; server configuration controls whether and where such records are read. A successful login does not prove that a guessed `~/.ssh/authorized_keys` file is the authoritative registry. [S04][S05]

### 7.5 Enrollment transaction

The transaction records: authenticated destination identity, account, observed capability, requested change, preimage/version, new credential reference, verification plan, owner decision, and rollback constraints.

Required sequence: inspect permitted state; produce a scoped change; record intent durably; add alongside a known-working path; independently authenticate with only the new mechanism; record observed success; switch the local preference; retire older access only through the approved policy.

Verification must disable unintended fallback and connection reuse, use the selected credential, and establish a fresh authentication. Reusing an old multiplexed connection is not enrollment verification.

A broken network after a mutation yields `outcome_unknown` until reconciled. Do not append another key blindly. Identify only Heimdall-owned records by stable marker/fingerprint and compare current state before rollback. Preserve unrelated options, comments, newline/encoding behavior, permissions, and concurrent administrator edits.

Remote file updates must be atomic where supported. Do not rewrite a shared account file from a stale snapshot. Detect insufficient authority and preserve current access. Never require disabling host verification to bootstrap enrollment.

### 7.6 Certificates and destination restrictions

A certificate's validity/principals are supported OpenSSH mechanisms; they do not automatically encode Heimdall's desired per-host authorization. [S10]

If the same CA and broad principals are trusted on multiple hosts, a credential may be usable on all of them. A claim of per-destination scope requires verified server-side principal mapping, a suitably restricted agent, or another named enforcement mechanism. Prefer distinct destination/account principal assignments for a managed recipe and test attempted use against another enrolled host.

Unknown critical options, mismatched certificate/key pairs, invalid validity intervals, unexpected principals, and unrecognized issuers must fail closed for managed issuance. A certificate listing operation is passive; acquiring or refreshing one is an authorized effectful operation.

An existing issuer such as an OpenSSH-compatible Smallstep deployment is a candidate building block, not a mandatory dependency or evidence that Heimdall's integration already works. [S11]

### 7.7 Removing access and recovery

Uninstalling the CLI must not accidentally strand remote accounts. Provide an inventory of managed remote changes and a deliberate unenrollment flow. Local removal cannot promise remote key removal when the target is offline. Preserve a human-readable recovery bundle with public metadata and instructions, never unencrypted private keys.

Losing a device should allow disabling its future automatic access and removing its enrolled credentials through reachable trusted authority. Device replacement creates a new identity; copying a state directory cannot silently impersonate the lost device.

## 8. Environments, portability, and delegation

### 8.1 Environment-local authority

The environment executing the SSH-dependent work owns its active credential realization, local endpoints, process state, and deadlines. A controller selects and manages that environment; its own local sockets, filesystem paths, or credentials must not be substituted silently.

This follows a useful architectural distinction in T3 Code: environment state/execution remains separate from the route used to reach it. Heimdall applies the distinction to access rather than recreating T3's coding interface. [S16]

A remote Linux runner must continue approved onward SSH work after its controlling laptop disconnects, provided the runner itself remains operational and required destinations/credential dependencies remain available. Preflight must detect dependencies on the departing device.

### 8.2 Stable bindings and concurrency

A binding pins environment ID, profile revision, resolved destination/account scope, credential mechanism, and grant. A TUI's selected environment or another shell's default may affect new requests only. It must not redirect existing jobs.

Concurrent preparation is single-flight for equivalent work where safe, with separate references for independent callers. Unrelated scopes or credentials must not be merged merely to save a process. Shared resources are tagged with scope compatibility and generation; cleanup cannot kill a replacement owned by another live binding.

### 8.3 Portability classes

- **Portable intent:** labels, profiles, destination public identity references, approved route descriptions, requested project access, and preferences.
- **Local authority:** device enrollment, workspace trust decisions, policy revisions, signer/credential handles, OS permissions, and machine-specific integrations.
- **Ephemeral/durable runtime state:** operations, grants, endpoints, process ownership, expiry, and revocation tombstones, with distinct retention policies.

Only portable intent is a normal dotfiles export. Even that export can reveal infrastructure names or public endpoints; provide redaction and a preview. Import never executes repository commands, installs a service, trusts a key, or grants access merely because the file says so.

### 8.4 Windows and WSL

**Mode A — Windows SSH authority:** supported WSL consumers invoke Windows `ssh.exe` as appropriate. Test argument quoting, exit behavior, input/output, filesystem path differences, Git configuration, and key/public-certificate file access. 1Password documents forwarding the SSH operation to Windows for its WSL integration. [S12]

**Mode B — Linux-native scoped bridge:** a Linux agent endpoint makes the selected supported upstream access available to native WSL consumers. The bridge is opt-in, limited to the intended owner/context, lifecycle-supervised, and not a generic unauthenticated TCP agent proxy. Distribution restart, socket deletion, host lock, multiple distributions, and stale pipe recovery are required tests.

Do not assume Windows OpenSSH accepts arbitrary Unix-style `IdentityAgent` endpoints. Verify the actual Windows client/provider versions and named-pipe selection behavior. If a supported scoped path needs a packaged helper or a selected alternative executable, install/configure it visibly and preserve the system client's existing setup. Claiming a per-job endpoint while all jobs actually use a broad global pipe is prohibited.

Windows OpenSSH's service/account and key-permission requirements are a separate integration concern from Unix file modes. The release must test them rather than equating Windows administrator elevation with a key-use approval. [S13]

### 8.5 Containers, bastions, and remote hops

The first container recipe binds a prepared, explicitly scoped endpoint into an identified local Linux container context with correct ownership and cleanup. Never mount an unrestricted personal agent as the default shortcut. Do not expose the control/approval interface alongside the signing endpoint.

Container UID mappings, rootless operation, host-path visibility, and endpoint disappearance require tests. Access to a privileged host container engine may itself confer broad host control; the recipe must not claim protection against that authority. Docker Desktop and devcontainer variants remain separately labeled until tested.

Bastion routing should prefer ordinary `ProxyJump` or supported transport composition when credentials need not be forwarded. Agent forwarding is a separate explicit capability, disabled by default. A forwarded endpoint is scoped only to the extent its actual protocol/provider can enforce; a socket filter is not automatically a host restriction. [S03]

### 8.6 Pairing and remote control

Pairing authenticates the environment/device and establishes explicit management permissions. Connectivity success alone is not pairing. Viewing status, requesting allowed work, approving new access, changing issuer trust, and enrolling another controller are distinct permissions.

A minimal V1 pairing flow may bootstrap over already host-verified SSH and use an established mutually authenticated channel afterward. G07 chooses the concrete mechanism. Do not invent a cryptographic handshake, treat possession of an Iroh endpoint ID as management authority, or grant owner access to every paired consumer.

Invitations, if used, are short-lived, one-use, bound to the intended role and receiving identity, and excluded from logs and URL query strings. Generic Iroh tickets are reusable connection artifacts and must not be assumed to have these invitation properties. [S15]

### 8.7 Delegation boundaries

The V1 narrower-binding demonstration can use a verified signer plus managed certificate/principal configuration, or a separately enforced execution context. It must prove both scope attenuation and expiry inheritance. A convenience-only same-user binding is still useful, but labeled as such.

Delegation does not grant the right to approve additional access, mint an issuer, expand a profile, or extend a deadline. Workers receive handles to narrowly permitted operations, not owner-management credentials.

## 9. Destinations, routes, and host trust

### 9.1 Route-independent destination identity

A destination can have direct, bastion, and optional Iroh routes. Route selection is constrained by authenticated destination identity, account, approved infrastructure, and user preferences. Recovery cannot silently turn `lab-server` into a different machine.

Use stable host-trust bindings even when a transport connects through loopback, a changing IP, or an ephemeral port. Generated configuration must bind aliases/host-key lookup consistently and test host-key changes on each route. Automatically accepting a replacement host key to make recovery succeed is prohibited.

Unknown hosts need an intentional trust-establishment flow. `ssh-keyscan`-style unauthenticated observation is a candidate fingerprint, not proof of host identity. Existing verified trust may be adopted; do not downgrade it. Credential trust and host trust remain separate.

### 9.2 Iroh integration hypothesis

Iroh provides encrypted endpoint connections and stable cryptographic endpoint identifiers; Pigeons already connects ordinary SSH through a `ProxyCommand` and an Iroh-backed route. Heimdall should evaluate embedding or supervising those mechanisms rather than building a competing transport protocol. [S14][S19]

The reference flow must include persistent endpoint identity, authenticated pairing/host trust, explicit remote installation, direct/relay operation where supported, health and recovery, clean removal, and normal SSH consumer compatibility. Merely launching a proof-of-concept tunnel is not the complete feature.

Iroh relays cannot read payloads but can observe connection metadata. Its documented shared infrastructure has operational/privacy limitations; optional transport setup must disclose the infrastructure used and permit approved alternatives. [S20]

No network listener, port mapping, relay publication, or discovery advertisement is enabled by passive inspection. A user's opt-in chooses the scope. A transport error must not erase host trust, broaden access, or cause fallback through infrastructure outside the saved policy.

### 9.3 Recovery, not magical session migration

Heimdall can repair connectivity for future operations and preserve existing sessions only where the selected transport demonstrably supports it. It must not claim an arbitrary live TCP SSH session survives switching independent routes. Lost interactive sessions are reported; commands whose completion is uncertain are not automatically replayed.

T3's single-owner connection supervision and distinction between reconnecting and replaying mutations are useful precedents. Heimdall adopts the behavioral goals without requiring the same implementation. [S17][S18]

## 10. OpenSSH and consumer integration

### 10.1 Managed projections

Heimdall's portable model is not a wholesale replacement for OpenSSH configuration. Generate a bounded include, public-key/certificate material where needed, and supported consumer configuration. A representative Unix include is:

```sshconfig
Include ~/.config/heimdall/ssh_config
```

This is a proposed default location, not a universal Windows path. Resolve platform paths using the declared client and installation layout.

OpenSSH generally uses the first obtained value for many options; some directives such as identity entries accumulate. Include position and wildcard precedence matter. Heimdall must not assume a last-write-wins merge. [S01]

Adoption compares the effective relevant behavior before and after, provides a diff, snapshots original content, uses atomic generation/replace, and records ownership. Existing user edits are preserved. A stale backup cannot overwrite a subsequently edited configuration; produce a conflict and a targeted repair instead.

### 10.2 Passive means passive

Default `doctor` performs bounded local inspection only. It must not initiate provider authentication, network traffic, signing, shell hooks, config mutations, or service installation. Ordinary read-only access to a local state store is permitted. Contacting an agent—even to list keys—is an explicit local probe if it could trigger provider behavior.

`ssh -G` evaluates configuration; `Match exec` may run commands. Consequently, evaluating arbitrary user configuration is not equivalent to passive parsing. Use a nonexecuting parser for inspection, identify unsupported/dynamic constructs as unresolved, and require an explicit evaluation/probe capability before invoking executable configuration. [S01][S02]

Diagnostics distinguish static observation, agent contact, network reachability, host verification, authentication, and authorized mutation. The advanced `--active-probe` workflow states which levels it will perform and supports a noninteractive bounded mode.

### 10.3 Ordinary clients and bound contexts

After setup, an environment's default authorized aliases must work with ordinary supported `ssh`, Git-over-SSH, SCP, and SFTP without a mandatory `heimdall run` prefix. The service/configuration projection can establish the necessary access automatically under saved personal policy.

Project-specific or concurrent scoped work may use `heimdall run -- <argv>`, a supported shell/environment integration, or a bound client configuration. A wrapper is an optional stronger context tool, not the only way to use the product.

Binding must account for configuration that overrides environment variables, Git's selected SSH executable, embedded libraries that ignore OpenSSH config, and clients with incompatible agent support. Do not set `SSH_AUTH_SOCK` and assume that every consumer uses it. Consumer detection is evidence, not a universal compatibility claim.

### 10.4 Process contract

`run` receives an argument vector after `--` and launches without shell interpolation. Shell execution is explicit via the user's chosen shell. Preserve stdin/stdout/stderr, terminal interaction, working directory, applicable environment, child exit status, cancellation, and signals to the extent defined by the platform.

Do not put banners or JSON on protocol stdout. Transport helpers are byte-clean. Normal command diagnostics go to stderr. Windows console control, Ctrl-C, resize behavior, process trees, paths with spaces/Unicode, and PowerShell/cmd quoting need real tests.

After child launch, the command's exit status is the child's status under the platform contract. Prelaunch Heimdall failures have documented codes. Machine orchestration that needs unambiguous distinction uses an operation result or side-channel metadata; it must not infer setup failure from a code the child can also produce.

## 11. CLI, API, and agent contracts

### 11.1 Everyday command surface

Command names are proposed for v0.1; semantics are normative. Freeze names at G08 before public compatibility promises.

```text
heimdall                         # TUI on a TTY; help/status without a TTY
heimdall setup                   # adopt supported local access
heimdall connect lab-server      # convenience; ordinary ssh also works
heimdall run --profile homelab -- <tool> [args...]
heimdall status
heimdall doctor                  # passive by default
heimdall tui
```

Advanced namespaces include `access`, `project`, `environment`, `destination`, `identity`, `config`, `operation`, and `service`. Avoid loading every advanced operation into an agent's initial tool surface. The initial primitives are inspect, ensure access, bind/launch, delegate, observe, and release/revoke.

OpenAI's function-calling guidance favors predictable structures, avoiding model-supplied fields already known by the application, combining invariably sequential operations, and keeping the initial tool surface small. These inform the contract; they do not make OpenAI a runtime dependency. [S24]

### 11.2 Common machine contract

All ordinary structured results have `schema_version`, `operation_id` when applicable, `state`, `code`, `data`, `warnings`, and `next` fields. Stable semantic codes are not localized. Human text may change without breaking machine callers. IDs are opaque references, not bearer credentials.

Unknown noncritical fields must be tolerated by readers; an unsupported schema major version or required capability must be rejected explicitly. Omitted values differ from `null`, and `unknown` differs from false. Timestamps use RFC 3339 with explicit offsets. No terminal escape sequences or markup are embedded in machine strings as an instruction channel.

Support JSON for final results and NDJSON for event streams. Pagination and event cursors are opaque. Cursors are scoped to the authenticated reader; an expired cursor returns a snapshot/resynchronization instruction. No private keys or reusable approval secrets appear in these outputs.

### 11.3 Ensure access

Illustrative invocation:

```bash
heimdall access ensure \
  --profile homelab-dev \
  --environment lab-runner \
  --work-id work_42 \
  --until 2026-10-02T02:00:00-04:00 \
  --request-id req_42 \
  --non-interactive --json
```

A normal trusted request usually omits the deadline and environment when the authenticated context already supplies them. The explicit example demonstrates the advanced contract, not a required daily ritual. `--until` bounds that work binding; it is not an implicit profile-wide cutoff. A separate owner action such as `access cutoff --profile homelab-dev --at <timestamp>` schedules the policy-level hard stop. A user-facing request to stop all automatic access at a time must use that policy action, not merely set a credential or binding deadline.

Illustrative completed response:

```json
{
  "schema_version": "1",
  "operation_id": "op_42",
  "state": "succeeded",
  "code": "ACCESS_READY",
  "data": {
    "binding_id": "binding_42",
    "environment_id": "env_runner",
    "profile_revision": 3,
    "grant_id": "grant_42",
    "expires_at": "2026-10-02T06:00:00Z",
    "usable_until": "2026-10-02T06:00:00Z",
    "offline_until": "2026-10-02T06:00:00Z",
    "credential_mechanism": "managed_certificate",
    "enforcement": {
      "destination_scope": "verified_server_principals",
      "new_authentication_expiry": "credential_and_signer",
      "workload_isolation": "shared_os_user",
      "existing_connections": "graceful_dedicated_connections"
    }
  },
  "warnings": [],
  "next": {"action": "use_binding", "binding_id": "binding_42"}
}
```

The timestamps and guarantees above are a schema example for a fixture that satisfies them, not the assumed behavior of every provider. The implementation must populate them from its chosen mechanism and evidence.

Additional authority yields an operation in `awaiting_approval`, with a nonsecret request reference and the minimum requested change. It does not hang invisibly waiting for a desktop prompt. In `--non-interactive` mode, no browser/dialog/terminal prompt is opened by Heimdall. A separately authorized UI can present the decision and the caller can observe the same operation.

### 11.4 Operations, idempotency, and uncertain effects

Idempotency identity consists of authenticated owner/caller context, operation kind, and request ID. Canonical parameter hashes include environment, scope revision, deadline intent, work ID, and requested capability. Reuse with different parameters returns `REQUEST_CONFLICT`.

Retries retrieve the same operation/result rather than create duplicate keys or enrollment records. Idempotency records persist across service restart and long enough to cover supported retries; retention is documented and a too-old key cannot silently claim deduplication.

Operation states include `queued`, `running`, `awaiting_approval`, `succeeded`, `failed`, `cancelled`, and `outcome_unknown`. A caller timeout is not cancellation. Cancellation is explicit, idempotent, and reports whether an irreversible or uncertain external step may have occurred.

Resource preparation is retryable according to its reconciler. Arbitrary child/remote commands are not automatically replayable. Return evidence of what was attempted, not a false exactly-once guarantee across a network partition.

### 11.5 Events and bounded work

Events contain schema version, event ID, operation/resource reference, environment, timestamp, type, sequence/cursor, and redacted payload. Delivery is at least once; consumers deduplicate by event ID. Cross-environment ordering is not claimed. A snapshot includes its cursor boundary so a reconnecting observer can resume without silently missing state.

Bound queues, request sizes, concurrent sign/probe operations, retry counts, and event buffering. Emit backpressure or resync requirements rather than unbounded memory growth. One supervisor owns retries for a resource; provider adapters do not start competing retry loops.

### 11.6 Errors and exit behavior

Stable codes include `APPROVAL_REQUIRED`, `CAPABILITY_UNAVAILABLE`, `PROVIDER_LOCKED`, `INTERACTION_REQUIRED`, `HOST_TRUST_CHANGED`, `DESTINATION_UNREACHABLE`, `CREDENTIAL_EXPIRED`, `POLICY_PAUSED`, `POLICY_CUTOFF`, `REQUEST_CONFLICT`, `CONFIG_CONFLICT`, `OUTCOME_UNKNOWN`, `UNSUPPORTED_CLIENT`, and `TIME_UNCERTAIN`.

Each error has effect status, retryability, relevant resource, and a machine-readable next action. "Retryable" never means permission to replay an arbitrary remote mutation.

For non-child CLI commands, proposed codes are 0 success, 2 usage/schema error, 3 required interaction, 4 denied/paused/cutoff, 5 unavailable/transient dependency, 6 conflict, 7 uncertain external outcome, and 1 unexpected internal failure. Asynchronous accepted/pending output exits successfully only when the caller selected asynchronous behavior; the payload still reports pending. Freeze this contract before release.

### 11.7 Public API and optional adapters

A versioned authenticated local service interface exposes the same application operations used by CLI and TUI. A supported remote control channel exposes only permitted subsets. The concrete IPC/protocol is selected by G08; no global unauthenticated HTTP listener is the default.

Reusable packages should separate pure configuration/model logic from live authority. Other applications must not need to embed terminal rendering or read a private database. A tiny reference integration demonstrates the boundary before publishing multiple SDKs.

MCP and harness skills are optional adapters. They cannot approve authority simply because a model calls an `approve` tool. A skill teaches the common workflow and discovers detailed schemas on demand; it is neither a security boundary nor an executable repository policy. OpenAI's skill documentation provides a useful progressive-disclosure precedent. [S25]

## 12. TUI behavior

### 12.1 Information architecture

The default screen shows available machines/profiles, selected execution environment, active work, and actionable problems. Normal state is "Ready" or "Working," not a list of expiration alarms. Advanced detail explains the actual credential mechanism and enforcement when requested.

Views: overview, destinations, identities, projects, environments, activity, and settings. Search is immediate and does not initiate network probes. A detail panel shows status provenance and freshness. Pending decisions are coalesced by logical access change.

### 12.2 Interaction quality

Every action is keyboard-accessible and has discoverable shortcuts. Support a usable narrow terminal, resize, dark/light terminal themes, limited color, and `NO_COLOR`. Never communicate a critical state using color alone. Provide a plain non-TUI alternative for all functions and avoid continual repainting that prevents usable text/screen-reader workflows.

Suspend/resume terminal rendering around interactive SSH. Restore terminal mode after cancellation, panic, resize, and child exit. Long operations remain cancellable and never freeze input. Do not log full terminal contents or session transcripts by default.

### 12.3 Approval and stop UX

Approvals describe destinations/accounts, environments, continued work while locked, and applicable limits. Advanced cryptographic details are secondary. A materially broader request highlights only the added authority and cannot conceal it in a generic "fix connection" button.

Stop actions distinguish pause future automatic access, end this work binding, revoke a grant and descendants, and remove enrollment. Normal users get clear descriptions; advanced callers retain precise semantics. A pending remote revocation must remain visible without repeated nuisance notifications.

### 12.4 Framework choice

Use a maintained, reputable framework. Bubble Tea, Ratatui, and OpenTUI are the evaluated candidates; OpenTUI's TypeScript-facing and native components make runtime/packaging verification important. Their existence or maintainer claims do not establish Heimdall's performance or portability. [S27][S28][S29]

## 13. Runtime architecture and state

### 13.1 Logical components

These are module boundaries, not a mandate for separate microservices:

```text
Human CLI / TUI / ordinary SSH consumers / agent callers
                         |
             versioned application operations
                         |
         policy resolution + lifecycle supervisor
              /            |              \
      credential       environment      route/consumer
       adapters         adapters           adapters
              \            |              /
         owned resources + transactional state
```

The runtime SHOULD be a small supervised per-user process after setup. Pure inspection and help should work without starting live access machinery. On-demand service startup must be single-instance and must not create a new broad agent on every invocation. Elevation, when actually needed, is a distinct setup action; routine access must not require repetitive UAC/sudo.

Maintain a deterministic domain layer independent of UI, transport, and provider SDKs. Adapters declare supported operations, side effects, interaction requirements, and enforcement capability. Keep interfaces narrow; do not build a general plugin marketplace before the reference adapters prove the model.

### 13.2 Control plane versus signing/data plane

The management interface changes policy, prepares work, inspects state, and handles lifecycle. The signing interface performs only already-authorized credential operations. Transport helpers carry bytes. Exposing one must not implicitly expose the others.

Local IPC uses owner-restricted Unix sockets or named pipes with checked peer credentials/ACLs, selected at G08. Loopback TCP without authentication is not an equivalent default. Remote access uses established authenticated encryption and explicit capability negotiation. Management credentials are never placed into a general SSH agent socket.

Same-user IPC credentials identify an OS principal, not a particular friendly application name. Independent approval or isolated-workload enforcement must not rely only on an executable path, an environment variable, a caller-provided PID, or a label supplied by an agent.

### 13.3 Persistence

Separate configuration, public/materialized data, transactional runtime state, secrets, and logs. The database contains references to protected secrets, not plaintext copies. Store on supported local filesystems; do not promise that a live state database works from a cloud-sync folder or shared network volume.

Persist operations, policy revisions, grant deadlines, resource generations, enrollment ownership, idempotency records, and revocation tombstones. Ephemeral socket paths and PIDs are rediscovered/validated, not blindly resurrected. Migration must be transactional and backed up; older clients must not read a newer incompatible store as an empty installation.

A safe export has a versioned manifest, public profile data, and a list of local items that must be reenrolled. It excludes active authority by default. Import is a reviewable reconciliation operation, not a directory copy that replaces an environment identity.

### 13.4 Example portable manifest

This TOML is an illustrative schema fixture, not a command to execute:

```toml
schema_version = 1
project = "example-infrastructure"

[access]
profile = "homelab-dev"
required_capabilities = ["ssh-authentication"]

[preferences]
background_work = true
```

It requests the logical profile and expresses a preference. It does not contain `trusted = true`, a private key, a socket path, a script hook, a policy override, an issuing credential, or authority to enroll a host. An untrusted repository cannot use `background_work` to grant itself unattended access.

A separate local policy record binds the workspace to a profile revision, allowed environments, saved maximum duration, current cutoff/pause state, and the owner's verified decision. Machine-local overrides can map references but cannot widen the policy. Unknown security-sensitive keys are rejected; ordinary unknown metadata follows a documented compatibility rule.

### 13.5 Reconciliation and ownership

Each resource has an owner, generation, desired state, observed state, and last operation. Apply with compare-and-swap/version checks where available. Before deleting an endpoint, process, or config projection, verify that its current generation is the one being cleaned up.

Recovery uses bounded backoff and jitter, distinguishes unavailable dependencies from authentication denial, and stops retrying when authority expires or is revoked. A watchdog must not resurrect paused access. Mark partially successful operations honestly and provide a durable next step.

### 13.6 Observability

Local audit events cover policy changes, enrollment, pairing, credential lifecycle, managed connection admission, expiry, revocation, and uncertain effects. Do not collect shell histories or full remote commands/session transcripts by default. Public metadata such as usernames, hostnames, paths, and fingerprints can be redacted on export.

Diagnostics include adapter versions, executable provenance, capability freshness, relevant generated-config provenance, and recovery attempts. A support bundle is previewable and opt-in. Redaction is tested with canary secrets; it must not rely solely on a list of known token prefixes.

Draft defaults: retain ordinary local operational history for seven days and bounded storage, retaining necessary revocation/idempotency evidence according to their contract. These durations are tunable and validated for correctness before release. Deleting logs must not delete policy cutoffs or other authority state.

## 14. Threat model and safeguards

### 14.1 Assets and adversaries

Protect existing and managed private keys, issuer authority, owner policy, trusted host identity, environment identity, approval decisions, operation integrity, active access, and sensitive metadata.

Consider malicious repositories/manifests, prompt-injected agents, buggy clients, unauthorized local users, hostile network peers, compromised remote destinations, stale callbacks, concurrent configuration editors, stolen devices, untrusted extensions, dependency compromise, and partially failed updates.

Do not claim to defeat a fully compromised administrator/kernel, a compromised authority holding its own CA key, or another process that already possesses equivalent unrestricted credentials. Standard SSH agent sockets can be used by sufficiently privileged or same-user processes; merely changing a socket path is not a sandbox. [S30]

### 14.2 Trust-boundary table

| Boundary | Required control | Non-guarantee |
|---|---|---|
| Repository to local policy | Parse as untrusted data; authority stored externally; access changes reviewed. | A trusted project may execute arbitrary code under the user's chosen runtime; project trust is not a filesystem sandbox. |
| Agent request to approval | Independently enforced policy/owner channel; no model assertion accepted as consent. | A compromised owner session may already control policy unless a stronger boundary is deployed. |
| Consumer to signer | Endpoint access control, request validation, key allowlist, declared protocol constraints. | Shared-user endpoints do not isolate mutually hostile programs. |
| Signer to issuer | Narrow authenticated issuance API and verified scope/deadline. | No magical attenuation from handing out an issuer private key. |
| Route to host identity | Authenticated host binding and consistent key lookup. | Reachability is not host trust. |
| Controller to runner | Authenticated pairing, role/capability checks, pinned environment identity. | Pairing does not automatically authorize arbitrary downstream SSH use. |
| Local revocation to remote enforcement | Tombstones, acknowledgments, bounded validity and pending state. | Offline issued credentials may remain accepted until expiry. |

Prompt-injected content can influence an agent's requests; Heimdall must enforce authority independently of those requests. OpenAI's agent-safety guidance supports structured boundaries and constrained tool use but does not establish that any such design eliminates injection. [S33]

### 14.3 Required attack tests

Test manifest path traversal, symlink/TOCTOU replacement, shell metacharacters in labels/paths, hostile SSH config `Match exec`, forged approval metadata, request-ID collision across owners, replayed invitations, malformed/oversized agent messages, namespace confusion between signing and control, inherited authority across unrelated jobs, host alias collision, stale config rollback, and expiry/revoke races.

Test a worker trying another destination that trusts the same CA. Test a child asking for a later deadline. Test a repeated work ID after an explicit cutoff. Test a stopped service recovering while a stale signing handle remains. Test a compromised remote forwarding peer attempting to use identities outside the intended set.

### 14.4 No deceptive security shortcuts

Do not disable host verification to fix a connection; change passphrase/touch/MFA settings silently; export a vault key to avoid prompting; call plaintext fallback secure storage; call a hostname preference host enforcement; call a key filter process isolation; or call a certificate timer remote process termination.

Do not weaken consumer/provider authorization to reduce a measured prompt count. If a relay changes provider attribution, identify the new approval boundary and document it during setup. Convenience is achieved by an explicit better workflow, not hidden authority expansion.

## 15. Reliability, performance, and distribution

### 15.1 Quantitative targets

These are proposed acceptance budgets to measure on declared reference hardware, not benchmarks already achieved. Measure cold and warm behavior separately, report P50/P95, and exclude external network/provider latency only when that exclusion is explicit.

| Metric | Initial target |
|---|---|
| Warm local status/inspect, 100 destinations | P95 ≤ 100 ms excluding process startup |
| Warm already-authorized ensure, no refresh/network needed | P95 ≤ 250 ms excluding process startup |
| First useful TUI frame from local cached state | P95 ≤ 750 ms from launch |
| Responsive key handling under background operations | P95 ≤ 100 ms |
| Idle runtime CPU | < 0.5% of one logical core over a five-minute idle sample |
| Idle runtime memory | Target ≤ 150 MiB RSS/working set; report platform measurement method |
| Stable idle polling | No tight retry loop; no unrequested active credential/network probe |
| Same-authority routine human prompts | Zero in the standard trusted-work acceptance journey |
| Silent scope/deadline widening in deterministic tests | Zero |
| Secret leaks in configured canary output/artifact tests | Zero |
| Restart/recovery soak | 72 hours of scripted lifecycle/fault scenarios without unbounded resource growth |

Failure of a performance target requires a measured analysis and an explicit revised budget; it cannot justify removing security semantics or required platform support. A human-driven provider approval is timed/reported separately from Heimdall overhead.

### 15.2 Failure expectations

A provider outage affects only dependent operations, not the whole UI. Network loss does not erase configuration or identity. A unavailable issuer does not trigger an unauthorized fallback key. Corrupt local state stops unsafe operations and offers recovery rather than silently reinitializing identity.

Updates preserve active work where possible, drain owned components, and avoid rotating public identity incidentally. A mandatory emergency restart must disclose expected effects. Version mismatch is negotiated by capability; clients do not assume a remote runner has identical features.

### 15.3 Distribution and maintenance

Ship installable, versioned artifacts for the declared platform/architecture matrix. Users should not need a compiler, development SDK, or a separately managed JavaScript runtime unless an intentionally documented distribution requires one and G02 accepts that burden. Prefer bundling needed runtime components.

Signed/verifiable release artifacts, checksums, a dependency manifest/SBOM, pinned build inputs, and a vulnerability-reporting path are public-release deliverables. Document the signing/provenance actually available; do not claim a signature or reproducible build that was not produced and verified.

Setup/uninstall manage only owned service registrations, configuration projections, endpoints, and packages. Preserve preexisting SSH operation and describe remaining remote enrollment. No hidden self-update or automatic acquisition of unsigned provider helpers.

License selection and project-name/package availability are explicit release decisions, not assumed cleared. No runtime code should be copied from another project without checking its applicable license and attribution obligations.

### 15.4 Agent and user evaluation

The agent evaluation uses only shipped help, schema discovery, and optional concise skill material. It measures task completion, tool calls, context used, unnecessary human interruptions, incorrect recovery actions, and latency. Security invariants are checked deterministically, not by an LLM judge.

A normal-working-week usability scenario covers trusted-project reentry, multiple terminals, enrolled-environment changes, background work, provider/route recovery, and deliberate stopping. The participant must be able to identify what automatic access permits and how to stop it without explaining grants or certificates.

A separate developer-composition test builds a small wrapper using only the documented API. Reading private database tables, scraping the TUI, or depending on hidden CLI flags is a failure of the public building block. This is the practical application of the building-block direction, rather than a promise of ecosystem adoption. [S23]


## 16. Requirements registry

The following 80 traceable requirements collect the normative obligations above. Their surrounding sections define the detailed semantics; a short registry row does not weaken them. All are V1 obligations within the declared scope, with the explicit Iroh gate exception in §3. Each has a primary milestone and acceptance coverage in the companion plan. The acceptance cases are specifications of tests, not results.

### Everyday experience

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-ux-01"></a>R-UX-01 | Adopt existing access before requiring enrollment; ordinary supported SSH works without a mandatory launcher. | [A01](#a01), [A35](#a35) |
| <a id="r-ux-02"></a>R-UX-02 | Trusted routine work within saved authority produces no additional human approval or renewal chores. | [A02](#a02) |
| <a id="r-ux-03"></a>R-UX-03 | Disclose continued work through lock and saved limits once; expose configurable alternatives. | [A03](#a03), [A30](#a30) |
| <a id="r-ux-04"></a>R-UX-04 | Personal profiles remain useful without a repository, agent, manifest, or LLM. | [A01](#a01), [A32](#a32) |
| <a id="r-ux-05"></a>R-UX-05 | CLI and TUI use the same operations; the TUI stays responsive and restores the terminal. | [A20](#a20), [A27](#a27) |
| <a id="r-ux-06"></a>R-UX-06 | Request only newly added authority; preserve unaffected access and coalesce equivalent decisions. | [A04](#a04) |
| <a id="r-ux-07"></a>R-UX-07 | Failures provide actionable states without repeated approval dialogs or retry notification storms. | [A17](#a17), [A19](#a19) |
| <a id="r-ux-08"></a>R-UX-08 | Users can explain automatic access and stop it without understanding leases or certificates. | [A30](#a30) |

### Authorization and time

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-au-01"></a>R-AU-01 | Keep saved policy, bounded work, and rotating credentials distinct; renewal never broadens a grant. | [A05](#a05), [A08](#a08) |
| <a id="r-au-02"></a>R-AU-02 | An explicit cutoff or pause blocks reactivation, including fresh request/work identifiers. | [A05](#a05) |
| <a id="r-au-03"></a>R-AU-03 | Pin profile and environment snapshots for active bindings; changing defaults cannot redirect work. | [A04](#a04), [A16](#a16) |
| <a id="r-au-04"></a>R-AU-04 | Apply revocation locally before acknowledgment; persist tombstones and expose pending remote effects. | [A07](#a07) |
| <a id="r-au-05"></a>R-AU-05 | Expiry controls new authentication and owned multiplexing under the disclosed connection policy. | [A23](#a23) |
| <a id="r-au-06"></a>R-AU-06 | Handle sleep, restart, rollback, and skew without extending authority; report uncertain time. | [A08](#a08) |
| <a id="r-au-07"></a>R-AU-07 | Delegation is no broader or longer than its parent and cannot confer owner approval authority. | [A28](#a28) |
| <a id="r-au-08"></a>R-AU-08 | Report actual enforcement and unattended/offline coverage; reject unmet minimum capabilities. | [A10](#a10), [A11](#a11), [A24](#a24) |

### Credentials and enrollment

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-cr-01"></a>R-CR-01 | Support native-agent and 1Password reference paths without mandatory personal-key export. | [A11](#a11), [A35](#a35) |
| <a id="r-cr-02"></a>R-CR-02 | Deliver a complete managed execution-credential recipe with verified lock continuity. | [A03](#a03), [A09](#a09) |
| <a id="r-cr-03"></a>R-CR-03 | Protect managed secret material; never fall back silently to plaintext or expose secrets in ordinary outputs. | [A33](#a33) |
| <a id="r-cr-04"></a>R-CR-04 | Keep issuer authority out of project signing endpoints and worker credential exports. | [A10](#a10), [A28](#a28), [A33](#a33) |
| <a id="r-cr-05"></a>R-CR-05 | Enrollment preserves working access, verifies fresh authentication, and reconciles uncertain outcomes. | [A09](#a09) |
| <a id="r-cr-06"></a>R-CR-06 | Rotation and unenrollment modify only owned records and preserve concurrent/unrelated remote edits. | [A09](#a09), [A31](#a31) |
| <a id="r-cr-07"></a>R-CR-07 | Verify destination/account principal scope; certificates alone are not asserted to restrict hosts. | [A10](#a10) |
| <a id="r-cr-08"></a>R-CR-08 | Honor provider lock, touch, MFA, and purpose restrictions; no unattended claim without a sufficient mechanism. | [A11](#a11), [A35](#a35) |

### Execution environments

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-en-01"></a>R-EN-01 | Native Windows is a tested first-class client, including pipe/ACL and service behavior. | [A14](#a14), [A31](#a31) |
| <a id="r-en-02"></a>R-EN-02 | WSL Mode A preserves Windows-SSH behavior, paths, quoting, and Git interoperability. | [A12](#a12) |
| <a id="r-en-03"></a>R-EN-03 | Opt-in WSL Mode B provides a scoped Linux endpoint with tested isolation claims and recovery. | [A13](#a13) |
| <a id="r-en-04"></a>R-EN-04 | Linux and macOS support distinguish lock, logout, sleep, and reboot on declared architectures. | [A03](#a03), [A08](#a08), [A31](#a31) |
| <a id="r-en-05"></a>R-EN-05 | A remote Linux runner continues approved onward access independently of controller presence. | [A24](#a24) |
| <a id="r-en-06"></a>R-EN-06 | A local Linux-container recipe binds only intended access and cleans up under UID/endpoint changes. | [A15](#a15) |
| <a id="r-en-07"></a>R-EN-07 | Export portable intent, not device authority; clone/import alone cannot confer workspace trust. | [A18](#a18) |
| <a id="r-en-08"></a>R-EN-08 | Paired management roles are authenticated and bounded; route identity cannot substitute for control authority. | [A25](#a25) |

### SSH and connectivity

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-ss-01"></a>R-SS-01 | Preserve OpenSSH precedence and unknown user configuration; previews, atomic changes, and rollback are mandatory. | [A22](#a22) |
| <a id="r-ss-02"></a>R-SS-02 | Default doctor is passive, including no Match-exec evaluation, authentication, or external probes. | [A21](#a21) |
| <a id="r-ss-03"></a>R-SS-03 | Client integration verifies the actual executable/config/agent behavior, not only environment variables. | [A14](#a14), [A35](#a35) |
| <a id="r-ss-04"></a>R-SS-04 | Keep protocol and child streams byte-clean and preserve process behavior across platforms. | [A27](#a27) |
| <a id="r-ss-05"></a>R-SS-05 | Preserve destination host identity across direct, jump, and optional transport routes. | [A26](#a26) |
| <a id="r-ss-06"></a>R-SS-06 | Provide a tested bastion flow; forwarding is explicit and limitations are reported. | [A15](#a15), [A28](#a28) |
| <a id="r-ss-07"></a>R-SS-07 | Evaluate and deliver or explicitly gate the opt-in Iroh reference flow without inventing a transport protocol. | [A26](#a26) |
| <a id="r-ss-08"></a>R-SS-08 | Disclose transport infrastructure and exposure; repair cannot silently select unapproved infrastructure. | [A26](#a26) |

### Public operations and agents

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-ap-01"></a>R-AP-01 | Expose a compact intent-oriented operation model; routine callers do not orchestrate internal plumbing. | [A19](#a19), [A32](#a32) |
| <a id="r-ap-02"></a>R-AP-02 | Version schemas and capabilities; publish stable codes, typed unknown states, and meaningful next actions. | [A19](#a19), [A36](#a36) |
| <a id="r-ap-03"></a>R-AP-03 | Deduplicate retries across restart; request-key parameter mismatch is a conflict. | [A06](#a06) |
| <a id="r-ap-04"></a>R-AP-04 | Separate caller timeout, cancellation, and uncertain side effects; never promise network exactly-once execution. | [A06](#a06), [A19](#a19) |
| <a id="r-ap-05"></a>R-AP-05 | Provide resumable bounded event streams with snapshot/cursor semantics and deduplication. | [A19](#a19), [A17](#a17) |
| <a id="r-ap-06"></a>R-AP-06 | Noninteractive mode never opens Heimdall approval UI and returns explicit required interaction. | [A11](#a11), [A19](#a19) |
| <a id="r-ap-07"></a>R-AP-07 | Expose an authenticated composition interface shared by clients, without private-database dependencies. | [A32](#a32) |
| <a id="r-ap-08"></a>R-AP-08 | Ship installed-version help and compact discovery; optional skills/adapters never enforce or create consent. | [A32](#a32), [A29](#a29) |

### Runtime and recovery

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-rt-01"></a>R-RT-01 | Use one supervisor per owned resource; startup and repair are single-instance and bounded. | [A17](#a17) |
| <a id="r-rt-02"></a>R-RT-02 | Persist desired state, ownership generations, expiry, and policy revision before acknowledging effects. | [A06](#a06), [A07](#a07), [A17](#a17) |
| <a id="r-rt-03"></a>R-RT-03 | Separate control, signing, and transport endpoints; apply correct local ownership and authentication. | [A14](#a14), [A29](#a29) |
| <a id="r-rt-04"></a>R-RT-04 | Retire resources only after validating current ownership; stale cleanup cannot remove a replacement. | [A17](#a17), [A22](#a22) |
| <a id="r-rt-05"></a>R-RT-05 | Do not replay arbitrary child/remote mutations as a recovery strategy. | [A19](#a19), [A27](#a27) |
| <a id="r-rt-06"></a>R-RT-06 | Bound queues, probes, retries, and concurrency with backpressure instead of unbounded resource use. | [A19](#a19), [A34](#a34) |
| <a id="r-rt-07"></a>R-RT-07 | Recover supported unexpired state after restart without reviving pauses or resetting identities. | [A08](#a08), [A17](#a17) |
| <a id="r-rt-08"></a>R-RT-08 | State migration and corruption handling preserve recoverability and do not silently initialize a new identity. | [A31](#a31) |

### Security boundaries

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-se-01"></a>R-SE-01 | Repository content is untrusted input, not executable setup or authorization. | [A18](#a18), [A29](#a29) |
| <a id="r-se-02"></a>R-SE-02 | Agent-supplied names, paths, prompts, and approval claims do not establish authorization. | [A29](#a29) |
| <a id="r-se-03"></a>R-SE-03 | Every scope/isolation guarantee names a tested mechanism; same-user convenience is labeled honestly. | [A28](#a28), [A29](#a29) |
| <a id="r-se-04"></a>R-SE-04 | Verify host trust; never bypass verification to make enrollment or failover succeed. | [A09](#a09), [A26](#a26) |
| <a id="r-se-05"></a>R-SE-05 | Defend parsers, IPC, path operations, and helper invocation against malformed input and injection. | [A29](#a29) |
| <a id="r-se-06"></a>R-SE-06 | Prevent invitation replay, cross-owner request collisions, and signing/control purpose confusion. | [A25](#a25), [A29](#a29) |
| <a id="r-se-07"></a>R-SE-07 | Recheck policy generation before issuance and activation; stale approval cannot defeat revocation. | [A07](#a07) |
| <a id="r-se-08"></a>R-SE-08 | Collect no private keys or session transcripts in default diagnostics; support bundles are previewed/redacted. | [A33](#a33) |

### Quality and evidence

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-qu-01"></a>R-QU-01 | Maintain a versioned client/provider/environment matrix with explicit verified, limited, and untested states. | [A36](#a36) |
| <a id="r-qu-02"></a>R-QU-02 | Run native cross-platform tests; compilation alone is not interoperability proof. | [A12](#a12), [A13](#a13), [A14](#a14), [A31](#a31) |
| <a id="r-qu-03"></a>R-QU-03 | Measure local latency, first frame, idle CPU/memory, and bounded resource use against declared budgets. | [A34](#a34) |
| <a id="r-qu-04"></a>R-QU-04 | Complete fault injection and the 72-hour lifecycle soak without unbounded leaks or authority widening. | [A34](#a34) |
| <a id="r-qu-05"></a>R-QU-05 | Evaluate agents with shipped interfaces only; deterministic tests enforce security invariants. | [A32](#a32) |
| <a id="r-qu-06"></a>R-QU-06 | Compare routine friction with correctly configured baseline tools and record attributable differences. | [A02](#a02), [A30](#a30) |
| <a id="r-qu-07"></a>R-QU-07 | Trace requirements to owning milestones and acceptance evidence; do not mark planned tests passed. | [A36](#a36) |
| <a id="r-qu-08"></a>R-QU-08 | Independent review is required for public security claims; document residual risks and missing review. | [A36](#a36) |

### Delivery and lifecycle

| ID | Requirement | Acceptance coverage |
|---|---|---|
| <a id="r-di-01"></a>R-DI-01 | Publish installable artifacts for every declared target without hidden development-runtime prerequisites. | [A31](#a31) |
| <a id="r-di-02"></a>R-DI-02 | Routine operation requires no repeated elevation; service setup is scoped and reversible. | [A14](#a14), [A31](#a31) |
| <a id="r-di-03"></a>R-DI-03 | Updates drain/preserve active work or disclose interruption and support tested rollback. | [A31](#a31) |
| <a id="r-di-04"></a>R-DI-04 | Uninstall restores owned local integration without erasing unrelated SSH setup; remote residue is explicit. | [A31](#a31) |
| <a id="r-di-05"></a>R-DI-05 | Produce verified checksums/provenance, dependency inventory, license review, and a disclosure process. | [A31](#a31) |
| <a id="r-di-06"></a>R-DI-06 | Keep core operation local-first, vendor-neutral, and independent of a mandatory cloud account or LLM. | [A01](#a01), [A32](#a32) |
| <a id="r-di-07"></a>R-DI-07 | Do not enable telemetry, public exposure, or unsigned extension installation implicitly. | [A26](#a26), [A33](#a33) |
| <a id="r-di-08"></a>R-DI-08 | Freeze version floors, schema/command compatibility, license, and consequential defaults through recorded gates. | [A36](#a36) |

## 17. Acceptance scenarios

Every case specifies a fixture, action, and observable result. Use disposable credentials and authorized test destinations. Cases involving native lock, secure stores, Windows/WSL, PTYs, and installation require real platform execution; mocks alone do not close them. Pair each positive path with its negative and interrupted variants.

<a id="a01"></a>
### A01 — Existing access and repository-free use

**Fixture:** An unchanged SSH server and a correctly configured existing identity; fresh Heimdall install.

**Exercise:** Adopt access, connect with ordinary ssh, and use a personal profile without a repository.

**Pass condition:** No remote change, no required key export, no mandatory run prefix, and unaffected existing aliases still work.

<a id="a02"></a>
### A02 — A normal working week

**Fixture:** An explicitly trusted project, saved policy, and enrolled environments; instrument every UI prompt and setup command.

**Exercise:** Reenter the project, open terminals, run allowed tools, renew credentials, and recover one helper.

**Pass condition:** Zero additional same-authority approval/renewal chores within the configured window; compare measured steps against the baseline.

<a id="a03"></a>
### A03 — Approve, lock, continue

**Fixture:** A managed credential recipe on Windows, macOS, and Linux as applicable; original vault and desktop initially unlocked.

**Exercise:** Start permitted work, lock desktop and vault, then establish multiple fresh SSH connections before the deadline.

**Pass condition:** Fresh authentications succeed without the original vault remaining unlocked; configured lock-revokes alternative behaves differently as disclosed.

<a id="a04"></a>
### A04 — Access changes and snapshot isolation

**Fixture:** Two active bindings and a trusted manifest.

**Exercise:** Edit ordinary source, change branch, add a requested destination, and change the TUI default/profile definition.

**Pass condition:** Ordinary edits do not reprompt; new authority is separately evaluated; existing bindings retain their destination/account snapshots.

<a id="a05"></a>
### A05 — Expiry, automatic reentry, and hard cutoff

**Fixture:** A standing policy permits fresh bounded work; another profile has an explicit stop time.

**Exercise:** Expire one binding, retry it, start distinct permitted work, then attempt fresh work IDs after the hard cutoff.

**Pass condition:** Expired work is not extended; new work obeys standing policy; no identifier change bypasses the explicit cutoff or pause.

<a id="a06"></a>
### A06 — Idempotency and interrupted requests

**Fixture:** A preparation/enrollment fixture with persistent operation storage.

**Exercise:** Send duplicate concurrent requests, kill the caller/service, retry after restart, and reuse a key with altered parameters.

**Pass condition:** One logical effect/result is reconciled; changed parameters conflict; no duplicate credential/enrollment or restarted deadline.

<a id="a07"></a>
### A07 — Revoke races and disconnected enforcement

**Fixture:** Active parent/child grants, pending approval and renewal, and one disconnected runner/destination.

**Exercise:** Revoke while issuance and approval complete; reconnect after local tombstone persistence.

**Pass condition:** New local use fails immediately; descendants and stale callbacks cannot reactivate; remote-pending effects and maximum residual validity are truthful.

<a id="a08"></a>
### A08 — Time and machine lifecycle

**Fixture:** Controlled clocks plus a real supported OS environment.

**Exercise:** Sleep across expiry, jump clocks backward/forward, restart the service, and perform an OS logout/reboot variant.

**Pass condition:** No extra authority from time changes/restart; supported recovery restores only valid state; unavailable secure stores and uncertain time are explicit.

<a id="a09"></a>
### A09 — Enrollment, rotation, and safe rollback

**Fixture:** A disposable account with a known-working path, unrelated keys/options, and a concurrent editor.

**Exercise:** Enroll a new credential, verify fresh auth with fallback/multiplexing disabled, interrupt mutation, rotate, and attempt rollback.

**Pass condition:** Existing access survives; only owned records change; uncertain outcomes reconcile; newer edits are not overwritten.

<a id="a10"></a>
### A10 — Certificate scope and issuer separation

**Fixture:** Two hosts trusting the same CA but intended to authorize different destination/account principals.

**Exercise:** Use a narrow credential on both hosts, request broader principals, and inspect worker access to issuer material.

**Pass condition:** Only intended access succeeds where enforcement is claimed; no issuer private key or broader certificate escapes; unsupported scope is labeled rather than fabricated.

<a id="a11"></a>
### A11 — Fixed provider and interaction limits

**Fixture:** An unchanged destination using a locked or touch/MFA-required provider.

**Exercise:** Run interactive and noninteractive preparation; request unattended capability the mechanism cannot satisfy.

**Pass condition:** Ordinary supported access remains first-class; noninteractive calls return explicit interaction/capability state without a popup or an unapproved fallback.

<a id="a12"></a>
### A12 — WSL Mode A

**Fixture:** Native Windows OpenSSH and the supported provider; WSL2 and Git with paths containing spaces/Unicode.

**Exercise:** Run Git and SSH through the Windows-SSH path from WSL; interrupt commands and change public-certificate files.

**Pass condition:** Correct executable/identity, preserved I/O and status, correct path quoting, and no recurring UAC for normal work.

<a id="a13"></a>
### A13 — WSL Mode B

**Fixture:** An opted-in Linux-native scoped bridge and multiple WSL distributions.

**Exercise:** Use native Linux SSH/Git, try an unauthorized key, restart one distribution, remove its socket, and stop its binding.

**Pass condition:** Only the declared scope is available through the endpoint; no unintended distribution exposure; recovery and teardown respect ownership and deadline.

<a id="a14"></a>
### A14 — Native Windows endpoint behavior

**Fixture:** Clean Windows install with the actual target OpenSSH/provider versions and an existing agent service.

**Exercise:** Configure ordinary and scoped access, exercise named-pipe permissions/conflicts, and inspect from another OS user.

**Pass condition:** Claims match actual endpoint selection; no silent global takeover; unauthorized access fails; supported commands work without repeated elevation.

<a id="a15"></a>
### A15 — Containers, bastions, and forwarding

**Fixture:** A local Linux container plus an SSH bastion and final target; dedicated scoped access.

**Exercise:** Bind the container, change UID/endpoint state, connect via bastion without unnecessary forwarding, then explicitly test forwarding.

**Pass condition:** Only intended endpoints are exposed; cleanup works; forwarding restrictions/limitations are verified and no broad personal agent is mounted by default.

<a id="a16"></a>
### A16 — Concurrent environments

**Fixture:** Two agents bound to different environments and accounts plus an interactive TUI.

**Exercise:** Prepare simultaneously, change global defaults, and clean up one job during the other.

**Pass condition:** No cross-routing, profile widening, key leakage, or deletion of another live resource.

<a id="a17"></a>
### A17 — Crash and stale cleanup

**Fixture:** A running helper/runtime with generation-tagged resources and duplicate observers.

**Exercise:** Crash helpers, race old cleanup against replacement startup, and repeat an unavailable-provider error.

**Pass condition:** Single bounded supervisor; old cleanup cannot delete new resources; no prompt storm, identity reset, or authority extension.

<a id="a18"></a>
### A18 — Export, clones, and workspace trust

**Fixture:** A trusted local checkout, a copied clone, a worktree, a symlinked path, and a second enrolled device.

**Exercise:** Export/import intent and move/copy project files.

**Pass condition:** No keys or active authority in ordinary exports; clone/import does not self-authorize; workspace identity reconciliation is explicit when ambiguous.

<a id="a19"></a>
### A19 — Structured operations and uncertainty

**Fixture:** Schema fixtures, event consumers, delayed side effects, and a noninteractive agent caller.

**Exercise:** Exercise success, pending approval, timeout, cancel, uncertain remote mutation, duplicate events, expired cursor, and backpressure.

**Pass condition:** Stable validated schemas/codes; timeout is not cancel; no blind replay; observers can resync; output remains bounded.

<a id="a20"></a>
### A20 — TUI and accessible operation

**Fixture:** Small and large terminals, no-color mode, slow operations, and a real PTY/console.

**Exercise:** Navigate all key workflows, resize, search, suspend into SSH, cancel, and force a rendering failure.

**Pass condition:** Keyboard-complete shared operations, responsive input, clean terminal restoration, and no critical color-only meaning.

<a id="a21"></a>
### A21 — Truly passive doctor

**Fixture:** An SSH config with a canary Match exec and provider endpoint that records contacts.

**Exercise:** Run default doctor and then separately requested evaluation/probe levels.

**Pass condition:** Default performs no executable config, provider contact, signing, network, or mutation; explicit probes are correctly classified and bounded.

<a id="a22"></a>
### A22 — Configuration precedence and conflicts

**Fixture:** Nested includes, Host/Match wildcards, additive identity entries, unsupported syntax, and concurrent edits.

**Exercise:** Preview/adopt/render, evaluate only with authorization, edit originals, and attempt rollback.

**Pass condition:** Relevant behavior is correct; dynamic unknowns stay unknown; unrelated content and newer edits survive; deterministic generation is stable.

<a id="a23"></a>
### A23 — Multiplexing and deadline effects

**Fixture:** Fresh and reused SSH connections, owned masters, dedicated connections, and an unmanaged connection.

**Exercise:** Reach ordinary/strict deadlines and attempt new authentication and new multiplexed requests; test documented OpenSSH stop behavior.

**Pass condition:** Owned admission/closure matches policy; no certificate-only enforcement assumption; unmanaged/remote-process limits are accurately reported.

<a id="a24"></a>
### A24 — Remote work without its controller

**Fixture:** A paired Linux runner with onward managed and fixed-auth targets; controller holds the initial setup UI.

**Exercise:** Prepare unattended coverage, disconnect controller, continue new SSH work, and interrupt the runner issuer/network.

**Pass condition:** Approved work does not depend silently on controller sockets; offline coverage is real; missing renewal dependency is detected before a false readiness promise.

<a id="a25"></a>
### A25 — Pairing and management role boundaries

**Fixture:** An owner controller, limited consumer, expired/replayed invitation, and untrusted route peer.

**Exercise:** Pair, reuse invitation, request policy changes as consumer, replace endpoint identity, and reconnect old client version.

**Pass condition:** Authenticated environment identity/roles hold; invitations cannot replay; route access cannot grant management authority; version mismatch is explicit.

<a id="a26"></a>
### A26 — Iroh, route failover, and trust

**Fixture:** Opted-in Iroh/Pigeons reference setup plus direct and bastion routes to the same host and a wrong-host fixture.

**Exercise:** Test direct/relay behavior, helper restart, persistent endpoint identity, route change, relay-policy mismatch, and removal.

**Pass condition:** Ordinary SSH works; host identity is preserved; no unapproved infrastructure/exposure; no false live-session migration claim.

<a id="a27"></a>
### A27 — Child and protocol byte integrity

**Fixture:** Byte fixtures, interactive tools, failing children, platform path/quoting cases, and transport helper pipes.

**Exercise:** Run raw binary streams, Git/SCP/SFTP, terminal resize, Ctrl-C, missing executable, and child-specific exit codes.

**Pass condition:** No stdout contamination or shell injection; child streams/status preserved; setup failure distinguishable through structured metadata.

<a id="a28"></a>
### A28 — Narrow delegation

**Fixture:** A parent grant for several targets and a worker requesting one, with an enforced reference boundary.

**Exercise:** Delegate, attempt broader/longer scope and owner operations, forward where supported, then revoke/expire parent.

**Pass condition:** Only permitted subset succeeds; owner functions unavailable; child expiry/revocation cascades; convenience-only cases do not claim isolation.

<a id="a29"></a>
### A29 — Hostile input and authorization forgery

**Fixture:** Malformed manifests/configs/IPC/agent messages, path races, forged metadata, and an agent reading injected repository instructions.

**Exercise:** Attempt command execution through data, scope widening, false approval, cross-owner idempotency collision, and signing/control confusion.

**Pass condition:** No unauthorized mutation/authority; parsers bounded; denial is explicit; request content never becomes consent.

<a id="a30"></a>
### A30 — User comprehension and friction

**Fixture:** A participant unfamiliar with Heimdall internals and the normal-week scenario.

**Exercise:** Complete setup, ordinary work, one access expansion, and stop/pause; explain what continues while locked.

**Pass condition:** Participant understands consequential behavior and control without knowing leases/certificates; measured avoidable steps/prompts improve on baseline.

<a id="a31"></a>
### A31 — Packaging, update, recovery, and uninstall

**Fixture:** Clean machines on each declared architecture, active work, corrupted/newer-version state, and preexisting SSH configuration.

**Exercise:** Install, start, update, rollback, recover, uninstall, and inspect release artifact provenance/remote residue.

**Pass condition:** No hidden build dependencies, truthful signatures/checksums, preserved SSH setup, no identity reset, and explicit remaining remote enrollment.

<a id="a32"></a>
### A32 — Agent and developer composition

**Fixture:** At least two independent harness styles plus a small third-party wrapper using shipped contracts only.

**Exercise:** Discover capabilities, ensure trusted access, handle required approval, observe/retry, bind work, and stop it.

**Pass condition:** No bespoke hidden instructions/private DB scraping; task metrics recorded; no LLM required for core use; security judged by deterministic checks.

<a id="a33"></a>
### A33 — Secrets and data minimization

**Fixture:** Canary secrets in store/provider fixtures and identifiable public metadata.

**Exercise:** Exercise errors, crashes, export/import, logs, events, support bundles, process arguments, and update artifacts.

**Pass condition:** No secret leakage or plaintext fallback; support bundle preview/redaction works; telemetry and transcript collection remain off by default.

<a id="a34"></a>
### A34 — Performance and soak

**Fixture:** Declared reference hardware, 100 destinations, mixed workloads, and deterministic fault schedules.

**Exercise:** Measure cold/warm latency and idle CPU/memory; run the 72-hour soak with restarts, expiry, and route/provider failures.

**Pass condition:** Budgets met or explicitly revised with evidence; no unbounded queues/leaks, permission widening, or tight retry loops.

<a id="a35"></a>
### A35 — Consumer/provider reference matrix

**Fixture:** Supported native agents and 1Password with actual SSH, Git-over-SSH, SCP, and SFTP clients.

**Exercise:** Exercise normal and bound paths, wrong-key/too-many-keys fixtures, and configuration that overrides SSH_AUTH_SOCK.

**Pass condition:** Verified executable and identity are used; full compatibility table includes exact limitations; existing-auth is not a second-class path.

<a id="a36"></a>
### A36 — Release claim audit

**Fixture:** Completed requirement evidence, gate ADRs, target versions, test skips, review findings, and source snapshots.

**Exercise:** Audit every requirement, compatibility claim, numerical result, deferred feature, and source-based assertion.

**Pass condition:** No planned/skipped test labeled passed; required gaps block stable V1; experimental features remain labeled; independent review status is honest.

## 18. Decision gates and non-goals

### 18.1 Decisions that require experiments

| Gate | Decision/evidence needed | Consequence of failure |
|---|---|---|
| G01 | Baseline, supported version floors, default UX/session settings, and explicit V1 scope. | No unsupported platform/version or user-preference assertion. |
| G02 | Language/TUI/distribution choice using the same representative native/CLI/TUI slice. | Do not pick by aesthetics or run three production implementations. |
| G03 | Native Windows endpoint selection and both WSL modes, including scoped behavior. | Required release blocker; redesign the adapter/process boundary. |
| G04 | Managed credential custody/issuer recipe and lock-independent operation. | Required release blocker; a relay to a locked vault is not a substitute. |
| G05 | Automatic project activation, binding provenance, saved policy, and meaningful isolation labels. | No repository-self-authorization or invisible global-context mutation. |
| G06 | Iroh integration versus managed helper, actual network lifecycle, and license/packaging. | Named preview/deferral only through a recorded scope change; direct SSH remains complete. |
| G07 | Remote pairing/control and unattended runner independence with genuine offline coverage. | Required release blocker; do not hide laptop/issuer dependency. |
| G08 | CLI/API schema, local IPC, event/idempotency contract, and consumer binding strategy. | Freeze only after reference callers pass; no SDK proliferation. |
| G09 | Expiry/multiplexing, revocation, clocks, and renewal races on supported mechanisms. | No stronger deadline/revocation claim than the demonstrated behavior. |

OpenSSH currently documents an operation to stop a master accepting further multiplexing requests. G09 must test whether that operation, cleanup/race handling, and the installed versions meet Heimdall's graceful policy before writing new connection-control machinery. [S02]

### 18.2 Explicit non-goals for V1

A replacement general-purpose password manager; a custom SSH transport/cryptographic protocol; a mandatory SaaS control plane; a coding-agent chat interface; a multi-owner enterprise RBAC platform; comprehensive session recording; automatic synchronization of private keys through Git; universal remote process termination; a guarantee of sandboxing all same-user software; a general container scheduler; automatic enrollment into every cloud/Git vendor; a plugin marketplace; and support for every existing SSH library.

These boundaries limit implementation scope, not the product's willingness to own its promised experience. Managed execution keys, a local service, optional remote helpers, certificates, and Iroh are not excluded by these non-goals.

### 18.3 Changes and readiness

The owner can revise proposed defaults without reopening settled product goals. A mandatory behavior change requires a corresponding spec amendment, updated acceptance tests, a plan change, and an explanation of who is affected. No measurement exists until a test artifact exists. No feature is production-supported until the compatibility matrix and claim audit say so.

## 19. Research basis and source register

All sources below were accessed on October 1, 2026. They are primary project/vendor documentation or the author's own essay. Repository main-branch documentation is mutable and may describe behavior ahead of a user's installed release. Before implementation, pin selected dependency versions and record immutable commit/reference snapshots for relied-upon behavior. These sources informed the design; none certifies Heimdall.

### 19.1 Reuse and differentiation conclusions

OpenSSH already provides extensive configuration, certificate, and agent mechanisms. 1Password already addresses external signing and host/key setup. Iroh/Pigeons already addresses much of endpoint reachability and SSH transport. T3 Code/T3 Connect supplies useful environment/control/lifecycle precedents. The remaining product hypothesis is an integrated low-friction access experience for ordinary tools across mixed environments and destination policies—not novelty in a key picker or basic tunnel. [S01][S09][S14][S16][S18][S19]

Building-block quality means documented contracts and tested composition, not a sprawling initial plugin API. The current OpenAI guidance similarly favors clear outcomes, explicit constraints, compact tool contracts, and task-specific verification. These are inputs to the plan's agent handoff and evaluation design, not a dependency on any model. [S23][S24][S26][S31][S32]

### 19.2 References

<a id="s01"></a>
**S01 — [OpenSSH ssh_config manual](https://man.openbsd.org/ssh_config).** Client configuration, precedence, identity selection, Match exec, multiplexing.

<a id="s02"></a>
**S02 — [OpenSSH ssh manual](https://man.openbsd.org/ssh).** Config evaluation, process/client behavior, multiplex control including stop.

<a id="s03"></a>
**S03 — [OpenSSH agent restriction design](https://www.openssh.org/agent-restrict.html).** Destination restrictions require protocol support and authenticated bindings.

<a id="s04"></a>
**S04 — [OpenSSH sshd manual](https://man.openbsd.org/sshd).** Authorized-key options and per-account certificate-authority trust.

<a id="s05"></a>
**S05 — [OpenSSH sshd_config manual](https://man.openbsd.org/sshd_config).** Accepted authentication methods, key registries, CA and principal policy.

<a id="s06"></a>
**S06 — [1Password SSH agent security](https://www.1password.dev/ssh/agent/security).** Vault lock and requesting-application security behavior.

<a id="s07"></a>
**S07 — [1Password SSH authorization](https://www.1password.dev/ssh/agent/authorization).** Approval contexts and remembered authorization.

<a id="s08"></a>
**S08 — [1Password Environments MCP server](https://www.1password.dev/environments/mcp-server).** Environment-variable/mount scope; not an SSH credential engine.

<a id="s09"></a>
**S09 — [1Password SSH Bookmarks](https://www.1password.dev/ssh/bookmarks).** Existing host/key configuration capability; documented beta status.

<a id="s10"></a>
**S10 — [OpenSSH ssh-keygen manual](https://man.openbsd.org/ssh-keygen).** Certificate validity, principals, signing purpose, and key operations.

<a id="s11"></a>
**S11 — [Smallstep SSH certificate login tutorial](https://smallstep.com/docs/tutorials/ssh-certificate-login/).** An existing issuer-based enrollment implementation to evaluate.

<a id="s12"></a>
**S12 — [1Password WSL integration](https://www.1password.dev/ssh/integrations/wsl).** Windows SSH execution from WSL; not proof of arbitrary Linux-native bridging.

<a id="s13"></a>
**S13 — [Microsoft OpenSSH key management](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement).** Windows account, service, and key permission integration.

<a id="s14"></a>
**S14 — [Iroh endpoints](https://docs.iroh.computer/concepts/endpoints).** Cryptographic endpoint identity distinct from routing details.

<a id="s15"></a>
**S15 — [Iroh tickets](https://docs.iroh.computer/concepts/tickets).** Connection bootstrapping; not automatically one-use approval invitations.

<a id="s16"></a>
**S16 — [T3 Code remote architecture](https://github.com/pingdotgg/t3code/blob/main/docs/internals/remote.md).** Environment identity/execution independent of connection routes.

<a id="s17"></a>
**S17 — [T3 Code connection runtime](https://github.com/pingdotgg/t3code/blob/main/docs/internals/connection-runtime.md).** Connection supervision and mutation replay boundary.

<a id="s18"></a>
**S18 — [T3 Connect architecture](https://github.com/pingdotgg/t3code/blob/main/docs/internals/t3-connect.md).** Control/transport/session separation and resource lifecycle precedent.

<a id="s19"></a>
**S19 — [Pigeons repository](https://github.com/n0-computer/pigeons).** SSH-over-Iroh and ProxyCommand integration to reuse/evaluate.

<a id="s20"></a>
**S20 — [Iroh security and privacy](https://docs.iroh.computer/concepts/security-privacy).** Encrypted payloads, metadata disclosure, shared relay caveats.

<a id="s21"></a>
**S21 — [Iroh Rust documentation](https://docs.iroh.computer/languages/rust).** Native Rust interface and published platform list; validate installed versions.

<a id="s22"></a>
**S22 — [Iroh JavaScript documentation](https://docs.iroh.computer/languages/javascript).** Native bindings/platform packaging to validate, not assumed portable.

<a id="s23"></a>
**S23 — [Mitchell Hashimoto, The Building Block Economy](https://mitchellh.com/writing/building-block-economy).** April 7, 2026 essay motivating robust reusable primitives alongside a polished application.

<a id="s24"></a>
**S24 — [OpenAI function-calling guide](https://developers.openai.com/api/docs/guides/function-calling).** Compact predictable operations and moving routine orchestration into code.

<a id="s25"></a>
**S25 — [OpenAI skills guidance](https://learn.chatgpt.com/docs/build-skills).** Progressive disclosure for optional installed-version usage guidance.

<a id="s26"></a>
**S26 — [OpenAI latest-model/GPT-6 guidance](https://developers.openai.com/api/docs/guides/latest-model).** Outcome-focused instructions, action follow-through, file-instruction hygiene, verification scope.

<a id="s27"></a>
**S27 — [Bubble Tea repository](https://github.com/charmbracelet/bubbletea).** Go TUI candidate; no performance/interoperability claim for Heimdall.

<a id="s28"></a>
**S28 — [Ratatui documentation](https://ratatui.rs/).** Rust TUI candidate.

<a id="s29"></a>
**S29 — [OpenTUI repository](https://github.com/anomalyco/opentui).** TypeScript-facing TUI candidate and native/runtime packaging considerations.

<a id="s30"></a>
**S30 — [OpenSSH ssh-agent manual](https://man.openbsd.org/ssh-agent).** Agent socket and same-user/root trust limitations.

<a id="s31"></a>
**S31 — [OpenAI reasoning best practices](https://developers.openai.com/api/docs/guides/reasoning-best-practices).** Clear goals/constraints and avoiding demands for hidden chain-of-thought; some guide sections describe older models.

<a id="s32"></a>
**S32 — [OpenAI evaluation best practices](https://developers.openai.com/api/docs/guides/evaluation-best-practices).** Task-specific evaluation and evidence rather than impressionistic success.

<a id="s33"></a>
**S33 — [OpenAI agent safety guidance](https://developers.openai.com/api/docs/guides/agent-builder-safety).** Structured trust boundaries and untrusted-content handling; no claim of eliminating injection.

<a id="s34"></a>
**S34 — [T3 Code environment authentication](https://github.com/pingdotgg/t3code/blob/main/docs/internals/environment-auth.md).** Pairing/management boundaries and project-versus-sandbox distinction.


<!-- Reference-style links used throughout this file. -->
[S01]: https://man.openbsd.org/ssh_config
[S02]: https://man.openbsd.org/ssh
[S03]: https://www.openssh.org/agent-restrict.html
[S04]: https://man.openbsd.org/sshd
[S05]: https://man.openbsd.org/sshd_config
[S06]: https://www.1password.dev/ssh/agent/security
[S07]: https://www.1password.dev/ssh/agent/authorization
[S08]: https://www.1password.dev/environments/mcp-server
[S09]: https://www.1password.dev/ssh/bookmarks
[S10]: https://man.openbsd.org/ssh-keygen
[S11]: https://smallstep.com/docs/tutorials/ssh-certificate-login/
[S12]: https://www.1password.dev/ssh/integrations/wsl
[S13]: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement
[S14]: https://docs.iroh.computer/concepts/endpoints
[S15]: https://docs.iroh.computer/concepts/tickets
[S16]: https://github.com/pingdotgg/t3code/blob/main/docs/internals/remote.md
[S17]: https://github.com/pingdotgg/t3code/blob/main/docs/internals/connection-runtime.md
[S18]: https://github.com/pingdotgg/t3code/blob/main/docs/internals/t3-connect.md
[S19]: https://github.com/n0-computer/pigeons
[S20]: https://docs.iroh.computer/concepts/security-privacy
[S21]: https://docs.iroh.computer/languages/rust
[S22]: https://docs.iroh.computer/languages/javascript
[S23]: https://mitchellh.com/writing/building-block-economy
[S24]: https://developers.openai.com/api/docs/guides/function-calling
[S25]: https://learn.chatgpt.com/docs/build-skills
[S26]: https://developers.openai.com/api/docs/guides/latest-model
[S27]: https://github.com/charmbracelet/bubbletea
[S28]: https://ratatui.rs/
[S29]: https://github.com/anomalyco/opentui
[S30]: https://man.openbsd.org/ssh-agent
[S31]: https://developers.openai.com/api/docs/guides/reasoning-best-practices
[S32]: https://developers.openai.com/api/docs/guides/evaluation-best-practices
[S33]: https://developers.openai.com/api/docs/guides/agent-builder-safety
[S34]: https://github.com/pingdotgg/t3code/blob/main/docs/internals/environment-auth.md
