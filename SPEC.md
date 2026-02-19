# SPEC.md — Heimdall v0.1.0

## 1. Overview

**Heimdall** is a free and open-source, CLI-first terminal application (with a full interactive TUI) for securely managing:

- SSH connections (hosts, jump hosts, port forwards, per-host settings, known_hosts policy)
- SSH identities/keys (generation, import/export, rotation, agent integration)
- Access tokens and secrets (API tokens, credentials, environment secrets, secure notes)
- **Passkeys** (roaming FIDO2 security keys) to unlock the local vault and re-authorize sensitive actions
- Local audit logs and session history

Heimdall v0.1.0 is **local-only** and **production-ready**. It MUST NOT require any hosted service, account, or cloud sync.

**License:** MIT

**Module path:** `github.com/amanthanvi/heimdall`

---

## 2. Goals & Success Metrics

### 2.1 Goals

1. Provide a "Termius-like" outcome and workflow quality for SSH management, while remaining **CLI-first**, scriptable, and open-source.
2. Provide a secure-by-default local vault for secrets, SSH key material, and metadata with strong encryption-at-rest.
3. Support cross-platform (macOS, Linux) passkey workflows using **roaming FIDO2 security keys via CTAP2** through **libfido2**, with terminal-native touch/PIN prompts.
4. Integrate safely with existing OpenSSH tooling without breaking the user's `~/.ssh/config` or existing SSH workflows.
5. Provide deterministic output formats, exit codes, robust error handling, and strong secret redaction guarantees.

### 2.2 Non-goals

Heimdall v0.1.0:

- MUST NOT implement multi-device sync, cloud backup, accounts, or hosted services.
- MUST NOT require a browser-based WebAuthn ceremony as the primary passkey mechanism.
- MUST NOT replace the system SSH client; it MUST preserve compatibility with OpenSSH.
- MUST NOT support Windows. Only macOS and Linux are supported.
- MUST NOT attempt guaranteed secure deletion on modern filesystems/SSDs; it MAY do best-effort wiping with clear limitations documented.
- MUST NOT promise platform authenticator passkeys (Windows Hello, macOS Touch ID) — only roaming FIDO2 keys.

### 2.3 Measurable Success Metrics

Release gate requires **both** quality metrics and feature completeness:

**Quality metrics (hard gate):**

| Metric | Target | Measurement |
|--------|--------|-------------|
| SSH connect overhead | <50ms p99 vs raw `ssh` | Benchmark suite in CI |
| Vault open time (cold) | <500ms | Integration test |
| Vault open time (warm/daemon) | <50ms | Integration test |
| Data-loss bugs | 0 | Issue tracker |
| Test coverage (critical paths) | >80% | CI coverage report |
| Secret redaction violations | 0 | Structured log audit test |

**Feature completeness (hard gate):**

- All MUST requirements implemented and tested
- All exit codes tested and deterministic
- All platforms passing CI (macOS arm64, Linux amd64)
- Shell completions generated (bash, zsh, fish)
- Man pages generated
- `--json` output stable for all list/show commands

---

## 3. Assumptions & Constraints

1. Implementation language: **Go >= 1.22**.
2. Target platforms:
   - macOS 13+ (arm64 MUST, amd64 SHOULD)
   - Ubuntu 22.04+ / Debian stable (amd64 MUST, arm64 SHOULD)
3. OpenSSH client (`ssh`, `ssh-keygen`, `ssh-agent`, `ssh-add`) is available on all target platforms.
4. Heimdall is single-user per vault by default.
5. libfido2 is available or can be packaged for all supported platforms.
6. cgo is required only for the internal libfido2 wrapper; all other dependencies are pure Go.

---

## 4. User Personas & Use Cases

### 4.1 Personas

1. **SRE/Infra Engineer** — Manages dozens/hundreds of hosts, bastions, and port forwards. Needs fast search, tags, groups, templates, and predictable CLI scripting.
2. **Developer** — Needs quick connect, per-project identities, and secret injection to tools without leaking secrets.
3. **Security-conscious Operator** — Requires strong local encryption, passkey re-auth for sensitive actions, strict host key policies, and auditability.

### 4.2 Primary Use Cases

- Add and manage SSH hosts with tags/groups and per-host settings
- Connect to hosts with ProxyJump, port forwarding, and identity selection
- Generate/import/export/rotate SSH keys and integrate with agents
- Store and retrieve tokens and secrets securely; inject secrets into commands
- Unlock vault with passphrase or roaming FIDO2 security key; require re-auth for sensitive actions
- Produce local audit logs and debug bundles without leaking secrets
- Backup/restore vault contents securely
- Import hosts from existing `~/.ssh/config`

---

## 5. UX Principles (CLI/TUI)

### 5.1 Core Principles

1. **Secure-by-default**: risky operations MUST require explicit opt-in flags and/or re-auth.
2. **No surprises**: Heimdall MUST NOT modify `~/.ssh/config` or `~/.ssh/known_hosts` unless explicitly requested.
3. **Scriptable first**: every interactive flow MUST have a non-interactive equivalent using flags/stdin, with deterministic exit codes.
4. **Human-friendly**: the TUI provides host/secret selection, fingerprint confirmation, and formatted details.
5. **Redaction always**: secrets MUST NOT appear in logs, panic traces, or structured outputs unless the explicit command's purpose is to reveal them.
6. **Consistency**: command naming, flag conventions, and output formatting MUST be consistent across subcommands.

### 5.2 UX States Checklist

| State | Behavior |
|-------|----------|
| **Empty** (no hosts/keys/secrets) | TUI shows onboarding: "No hosts yet. Press 'a' to add, 'i' to import from SSH config, or '?' for help." CLI `ls` returns empty JSON array with exit 0. |
| **Error** (daemon unreachable) | CLI prints "Daemon not running. Starting..." and auto-forks. If auto-fork fails: exit 6 with guidance. |
| **Error** (vault corrupted) | Diagnostic output: what's wrong, what data may be affected, offer restore from backup or export salvageable data. |
| **Error** (FIDO device missing) | "Insert security key and touch it. Press Ctrl-C to cancel or enter passphrase instead." Timeout after 30s. |
| **Permission denied** | "Re-authentication required. Touch security key or enter passphrase." After 3 failures: exponential backoff (5s, 30s, 5 min). |
| **Degraded** (daemon died mid-session) | Active SSH sessions continue (they're child processes). New vault operations fail with "Daemon unavailable. Restarting..." |
| **Locked** | TUI shows lock screen with unlock prompt. CLI vault operations return exit 5. |
| **First run** | Interactive wizard (see 5.3). |

### 5.3 First-Run Experience (`heimdall init`)

Interactive wizard flow:
1. Welcome message + version
2. Prompt for vault passphrase (with confirmation)
3. Ask: "Enroll a FIDO2 security key for passwordless unlock? (optional)" → If yes, run enrollment flow
4. Ask: "Import hosts from ~/.ssh/config? (optional)" → If yes, parse and show preview
5. Create vault, write config, confirm success

Non-interactive mode: `heimdall init --passphrase-stdin` reads passphrase from stdin, skips optional steps.

Ctrl-C at any point: clean up partial state, exit 0, print "Setup cancelled. Run `heimdall init` to try again."

### 5.4 Vault Corruption Recovery UX

When integrity check fails at startup:
1. Print diagnostic: "Vault integrity check failed: [specific error from SQLite]"
2. Show affected scope: "This may affect [N] secrets, [N] hosts, [N] keys"
3. Offer options:
   - "Run `heimdall backup restore --from <path>` to restore from a backup"
   - "Run `heimdall vault repair` to attempt automatic recovery (best-effort)"
   - "Run `heimdall vault export-salvage --output <path>` to export readable data"

---

## 6. Functional Requirements

RFC 2119 language: MUST = required, SHOULD = recommended, MAY = optional.

### 6.1 Host & Connection Management

#### Host records

Heimdall MUST support storing SSH host entries with:
- `name` (unique, 1-128 chars, `[a-zA-Z0-9._-]`)
- `address` (hostname, FQDN, or IP address)
- `port` (1-65535, default 22)
- `user` (optional)
- `tags` (0..N, each 1-64 chars)
- `group` (optional, 1-128 chars)
- `notes` (optional, encrypted, max 10 KiB)
- `identity_ref` (optional: reference to a managed identity/key)
- `jump_chain` (0..N host references or raw `user@host:port` entries)
- `known_hosts_policy` (inherit/strict/tofu/accept-new/off)
- `agent_forwarding` (inherit/yes/no; default: no)
- `pty` (inherit/auto/force/disable)
- `env` (optional: named secret references for `secret env` wrapper usage)
- `local_forwards`, `remote_forwards`, `dynamic_forwards` (0..N each)
- `connect_timeout` (optional, default from config)
- `keepalive` settings (optional)

Host `name` MUST be stable and used as the primary reference in CLI commands.

#### Tagging, grouping, templates

Heimdall MUST support:
- Tags for search and filtering
- Groups for organization
- Host templates (parameterized settings); a host MAY inherit defaults from a template

#### Search and listing

`heimdall host ls` MUST support:
- Filtering by tag (`--tag`) and group (`--group`)
- Full-text search over name/address/user (`--search`)
- Sorting by name or last_connected
- JSON output (`--json`)

### 6.2 SSH Execution & Compatibility

#### Execution strategy

- Heimdall MUST shell out to the system `ssh` client (OpenSSH) for connections.
- Heimdall MUST NOT use a pure-Go SSH client as the primary connection mechanism.

#### Compatibility with `~/.ssh/config`

- Heimdall MUST NOT modify `~/.ssh/config`.
- Heimdall MUST allow the user's existing config to apply by default.
- Heimdall MUST apply per-host overrides via explicit `ssh` flags (`-J`, `-i`, `-p`, `-o Key=Value`).
- Heimdall MAY offer `--ignore-ssh-config` to run with `ssh -F /dev/null`.

#### SSH exit code propagation

- `heimdall connect` MUST propagate the underlying `ssh` process exit code.
- Internal Heimdall failures (before `ssh` is spawned) MUST use Heimdall exit codes (see 7.1).

#### known_hosts policy

Heimdall MUST maintain its own managed known_hosts file at `${HEIMDALL_HOME}/ssh/known_hosts`.

Policies:
- `strict`: MUST require known host key match; unknown hosts MUST fail.
- `tofu` (trust-on-first-use): Accept after user confirmation in interactive mode; non-interactive MUST fail unless `--yes` or `--accept-new`.
- `accept-new`: Accept new keys, fail on changed keys.
- `off`: Disable host key checking; MUST require `--insecure-hostkey` flag with warning.

Defaults:
- Interactive: `tofu` with confirmation prompt
- Non-interactive: `strict` unless host is already trusted

#### ProxyJump and forwarding

Heimdall MUST support:
- `ProxyJump` chains via `ssh -J` (comma-separated, per-hop identity/user supported)
- Local forwards (`-L`), remote forwards (`-R`), dynamic forwards (`-D`)
- Multiple forwards per session
- Validation of forward specifications; reject malformed addresses

Edge cases to handle:
- `IdentitiesOnly yes` MUST be set when specifying identity to avoid "too many authentication failures"
- Each hop in a ProxyJump chain MAY have a different user and identity
- `ProxyJump none` MUST be supported to override wildcard config

#### Agent forwarding

- MUST default to `no` unless explicitly enabled per-host or per-command.
- If enabled, set `-A` explicitly and include in `--print-cmd` output.

### 6.3 Identity/Key Management

#### Supported key types

| Type | Status | Default | Min Size |
|------|--------|---------|----------|
| Ed25519 | MUST support | **Default** | N/A |
| RSA | MUST support | Opt-in (`--type rsa`) | 3072-bit |

#### Supported key formats

- OpenSSH private key format (import and export)
- OpenSSH public key format / `authorized_keys` format (import and export)
- PEM and PKCS#8 formats are NOT supported in v0.1.0

#### Key storage model

- Private keys MUST be stored encrypted in the vault.
- Public keys MAY be stored in plaintext for indexing.
- Import MUST support encrypted and unencrypted OpenSSH private keys.
- Export of private keys MUST require explicit `--output` path, re-auth, and restrictive file permissions (0600).

#### Key rotation

- Generate a new key for an identity
- Keep old key as "retired" (optional) or remove explicitly
- Allow per-host identity reassignment

#### SSH agent integration

Heimdall MUST ship a managed SSH agent in v0.1.0:

**Heimdall-managed agent:**
- Runs within the daemon process (single process, separate Unix socket listener)
- Implements SSH agent protocol via `golang.org/x/crypto/ssh/agent`
- Unix socket at `${RUNTIME_DIR}/heimdall/agent.sock` (0600)
- Auto-locks when vault locks or after inactivity timeout
- Requires vault unlock before serving signing operations
- Supports `--ttl` for time-limited key loading

**External agent fallback:**
- `heimdall key agent add` MUST support adding keys to an external `ssh-agent` via secure temporary file + `ssh-add`
- Temporary key file MUST be deleted immediately after `ssh-add` completes

### 6.4 Secrets/Tokens Vault

#### Secret types

- `token` (API token, bearer token)
- `password`
- `note` (encrypted freeform text, max 1 MiB)
- `file` (encrypted blob with filename and mime-type metadata, max 50 MiB)

#### Scoped access controls

- `reveal_policy`: `always-reauth` (default) | `once-per-unlock` | `no-reauth`
- `allowed_actions`: `reveal`, `export`, `inject-to-env`
- `reveal` and `export` MUST require re-auth by default
- `inject-to-env` SHOULD require re-auth unless configured otherwise

#### Safe secret usage

- `heimdall secret env <name> --env-var <VAR_NAME> -- <cmd> [args...]` runs subprocess with secret in specified env var
- Secret value MUST NOT be printed to stdout/stderr during injection
- Env var name is user-specified via `--env-var` flag (MUST be documented and stable)

### 6.5 Passkeys & Re-auth

#### Supported authenticators (v0.1.0)

- Roaming FIDO2 security keys (USB, NFC where OS supports) via CTAP2 through libfido2
- Platform authenticators (Touch ID, etc.) explicitly deferred

#### Cryptographic mechanism

- For passwordless unlock: FIDO2 `hmac-secret` extension when supported
- If authenticator doesn't support `hmac-secret`: passkey can be used for re-auth only, not vault unlock
- Credential algorithm: ES256

#### PIN and touch UX

- Prompt: "Insert security key and touch it"
- PIN entry: no echo, no logging, supports macOS Terminal and Linux TTYs
- Support user presence (UP) at minimum; user verification (UV) when configured

#### Enrollment (CTAP2 makeCredential)

1. User runs `heimdall passkey enroll --label <label>`
2. Prompt: insert key and touch
3. PIN prompt if required by authenticator
4. Create credential with:
   - RP ID: `heimdall.cli`
   - User handle: random 32 bytes
   - Algorithm: ES256
   - Extensions: request `hmac-secret`
5. Store: credential ID, public key (COSE), AAGUID, `supports_hmac_secret`, user label
6. Record audit event

#### Vault unlock with passkey

1. Load enrollment, verify `supports_hmac_secret=true`
2. `getAssertion` with `hmac-secret` extension and vault-stored salt (32 bytes)
3. Derive KEK: `HKDF-SHA256(ikm=hmac_secret_output, salt=vault_salt, info="heimdall-vault-kek")`
4. Unwrap VMK, unlock vault

#### Re-auth flow

- Perform `getAssertion` with stored credential
- Verify signature against stored public key
- Record in-memory re-auth timestamp (PID-scoped, 60s TTL)
- Falls back to passphrase if passkey unavailable

#### Re-auth policy

Actions requiring re-auth:
- `secret show`, `secret export`, `key export`, `backup create --unencrypted`, `vault change-passphrase`, `passkey rm`, destructive deletes

#### Auth lockout

- After 3 consecutive failures: 5-second delay
- After 5 failures: 30-second delay
- After 10 failures: 5-minute lockout
- Resets on successful authentication
- All attempts logged in audit

### 6.6 Import/Export/Backup/Restore

#### Import

Heimdall MUST support importing from:
- **OpenSSH config** (`~/.ssh/config`): core connection directives (see 12.2)
- **Heimdall JSON** export format

Termius import is NOT supported in v0.1.0 (Termius uses encrypted Electron IndexedDB).

#### Export

- `heimdall export --format json --output <path>`: hosts, identity metadata, secret metadata
- `heimdall ssh-config generate --output <path>`: read-only OpenSSH config snippet rendering

#### Backup

- `heimdall backup create --output <path>` produces an encrypted archive containing:
  - Vault DB, managed known_hosts, non-secret configuration, manifest with versions and hashes
- Archive encrypted with a **separate user-provided passphrase** (not the vault unlock passphrase)
  - Argon2id → key → XChaCha20-Poly1305 wrapping the entire archive
- MUST include integrity protection (tamper-evident)
- `--unencrypted` MUST require `--yes` and re-auth

#### Restore

- `heimdall backup restore --from <path>` requires confirmation and re-auth if overwriting existing vault

### 6.7 Audit Logging & History

Heimdall MUST maintain local audit logs for:
- Vault unlock/lock
- Secret reveal/export/inject
- Key export/delete/rotate
- Passkey enroll/remove
- Host trust/known_hosts changes
- Backup create/restore
- All gRPC API calls (PID, operation, target)

Audit logs MUST:
- Be stored in the vault DB (append-only table)
- Include timestamp, action, target entity ID, outcome, and connecting PID
- NOT store secret values
- Be tamper-evident via hash chaining: `hash_i = SHA256(hash_{i-1} || canonical_json(event_i))`

Connection history (non-sensitive):
- Host ID, timestamp, duration, exit status, forwarded ports (metadata only)
- MUST NOT record session contents

### 6.8 Admin/Policy Controls

Optional read-only policy file at `${HEIMDALL_HOME}/policy.toml` or `$HEIMDALL_POLICY_FILE`.

Policy controls MAY include:
- Enforcing UV-required re-auth
- Disallowing `known_hosts_policy=off`
- Enforcing vault auto-lock timeout maximum
- Enforcing max session duration maximum
- Requiring passkey re-auth for all secret reveals

Policy MUST override user config. Heimdall MUST report policy overrides (without exposing secrets).

---

## 7. CLI Specification

### 7.1 Global Flags, Exit Codes, Output Formats

#### Global flags

All commands MUST support:
- `--help`, `--json`, `--quiet`, `--no-color`
- `--timeout <duration>` (where applicable)
- `--vault <path>`, `--config <path>`
- `--yes` / `-y` (non-interactive confirmation, where applicable)
- `--interactive` (force prompts/TUI selectors)

#### Output formats

- Human output MUST be stable and readable
- JSON output MUST be UTF-8, one object per invocation, free of secrets unless the command's purpose is to return them

#### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error (unexpected) |
| 2 | CLI usage error (invalid flags/args) |
| 3 | Not found (missing host/secret/key) |
| 4 | Permission/policy denied |
| 5 | Auth failed (vault unlock, passkey assertion) |
| 6 | Dependency missing/unavailable (ssh, libfido2, daemon) |
| 7 | IO/storage error (vault corrupted, disk error, migration) |
| 8 | Network/connection failure |
| 9+ | `heimdall connect` propagates raw `ssh` exit code |

### 7.2 Commands

#### Top-level

- `heimdall init` — Initialize vault (interactive wizard or `--passphrase-stdin`)
- `heimdall status` — Show vault lock status, daemon status, agent status
- `heimdall doctor` — Check dependencies, permissions, daemon health, libfido2 availability
- `heimdall version` — Print version, build info, enabled features

#### Vault

- `heimdall vault status`
- `heimdall vault unlock [--passphrase-stdin | --passkey <label>]`
- `heimdall vault lock`
- `heimdall vault timeout set <duration>` / `heimdall vault timeout show`
- `heimdall vault change-passphrase` (requires re-auth)

#### Daemon

- `heimdall daemon status`
- `heimdall daemon stop`
- `heimdall daemon restart`

#### Hosts

- `heimdall host add --name <name> --addr <addr> [--port N] [--user U] [--tag T]... [--group G]`
- `heimdall host edit <name>`
- `heimdall host rm <name>`
- `heimdall host ls [--tag T] [--group G] [--search Q] [--json]`
- `heimdall host show <name>`
- `heimdall host test <name> [--timeout 5s]`
- `heimdall host trust <name>`
- `heimdall host template add|edit|rm|ls|show`

#### Connect

- `heimdall connect <host>` — Interactive host selection if no argument and TTY
  - `--jump <host[,host...]>`
  - `--forward <spec>` (repeatable; `L:`, `R:`, `D:` prefixes)
  - `--pty auto|yes|no`
  - `--agent-forward yes|no`
  - `--identity <key-name>`
  - `--known-hosts strict|tofu|accept-new|off`
  - `--print-cmd` (print `ssh` command that would be executed)
  - `--dry-run` (validate and print plan without executing)
  - `--` passthrough extra `ssh` args

#### Keys / Identities

- `heimdall key gen --name <name> [--type ed25519|rsa] [--comment C]`
- `heimdall key import --from <path>` or `--stdin`
- `heimdall key export <name> --public` or `--private --output <path>` (re-auth required)
- `heimdall key ls [--json]`
- `heimdall key show <name>` (metadata + public key)
- `heimdall key rm <name>`
- `heimdall key rotate <name>`
- `heimdall key agent add <name> [--ttl <duration>]`
- `heimdall key agent rm <name>`

#### Secrets

- `heimdall secret add --name <name> --type token|password|note|file [--value-stdin | --from <path>] [--reveal-policy P]`
- `heimdall secret ls [--json]`
- `heimdall secret show <name>` (requires re-auth)
- `heimdall secret rm <name>`
- `heimdall secret export <name> --output <path>` (requires re-auth)
- `heimdall secret env <name> --env-var <VAR> -- <cmd> [args...]`
- `heimdall secret set-policy <name> --reveal-policy P`

#### Passkeys

- `heimdall passkey enroll --label <label> [--uv required|preferred|discouraged]`
- `heimdall passkey ls [--json]`
- `heimdall passkey rm <label>` (requires re-auth)
- `heimdall passkey test <label>`

#### Backup / Import / Export

- `heimdall backup create --output <path> [--passphrase-stdin]`
- `heimdall backup restore --from <path>`
- `heimdall export --format json --output <path>`
- `heimdall import --format json|ssh-config --from <path>`
- `heimdall ssh-config generate --output <path>`

#### Audit

- `heimdall audit list [--since <duration>] [--action <action>] [--json]`
- `heimdall audit verify` (verify hash chain integrity)

### 7.3 Interactive Mode/TUI Behaviors

Heimdall provides a full interactive TUI using **bubbletea** (Charm ecosystem):
- List view with search/filter for hosts, secrets, keys
- Detail pane
- Confirm dialogs for destructive actions
- TUI handles vault unlock itself (shows lock screen when locked)

TUI MUST:
- Never render secret values by default
- Require re-auth before revealing secrets
- Support `ESC` to cancel safely
- Not start if stdout is not a TTY (unless forced with `--interactive`)

Empty states show contextual onboarding guidance (see 5.2).

### 7.4 Config Files & Precedence

#### Precedence

**flags > environment variables > config file > defaults**

#### Config file

Format: **TOML** (parsed with `pelletier/go-toml`)

Locations:
- macOS: `~/Library/Application Support/Heimdall/config.toml`
- Linux: `${XDG_CONFIG_HOME:-~/.config}/heimdall/config.toml`

#### HEIMDALL_HOME

- macOS: `~/Library/Application Support/Heimdall/`
- Linux: `${XDG_DATA_HOME:-~/.local/share}/heimdall/`

#### Environment variables

- `HEIMDALL_HOME`
- `HEIMDALL_VAULT_PATH`
- `HEIMDALL_CONFIG_PATH`
- `HEIMDALL_NO_COLOR=1`
- `HEIMDALL_JSON=1`

#### Config schema

```toml
[vault]
auto_lock_timeout = "30m"     # duration string

[ssh]
known_hosts_policy_default = "tofu"  # strict|tofu|accept-new|off
forward_agent_default = false
connect_timeout = "10s"

[passkey]
uv_default = "preferred"      # required|preferred|discouraged

[daemon]
max_session_duration = "8h"
socket_dir = ""               # empty = auto ($XDG_RUNTIME_DIR or $TMPDIR)

[logging]
level = "info"                # debug|info|warn|error
file = ""                     # empty = $HEIMDALL_HOME/logs/heimdall.log
max_size_mb = 10
max_files = 5

[telemetry]
enabled = false
```

---

## 8. Architecture

### 8.1 Component Overview

```
+---------------------+        +---------------------+
|        CLI          |        |        TUI          |
| (cobra commands)    |<------>| (bubbletea + huh)   |
+----------+----------+        +----------+----------+
           |                              |
           v                              v
+--------------------------------------------------+
|              gRPC Client (Unix socket)            |
+---------------------------+----------------------+
                            |
                            v
+--------------------------------------------------+
|                  DAEMON PROCESS                   |
|                                                   |
|  +----------------+  +------------------------+   |
|  | gRPC Server    |  | SSH Agent Server       |   |
|  | (api/v1/)      |  | (agent protocol)       |   |
|  | Unix socket    |  | Unix socket            |   |
|  +-------+--------+  +-----------+------------+   |
|          |                       |                 |
|          v                       v                 |
|  +---------------------------------------------+  |
|  |           Application Core                   |  |
|  | (host svc, secret svc, connect svc, policy)  |  |
|  +---------------------+-----------------------+  |
|                         |                          |
|          +--------------+--------------+           |
|          v              v              v           |
|  +------------+  +------------+  +-----------+    |
|  | Storage    |  | Crypto     |  | FIDO2     |    |
|  | (SQLite)   |  | (AEAD,KDF) |  | (libfido2)|    |
|  +------------+  +------------+  +-----------+    |
|                                                   |
|  VMK held in memguard (mlock, non-GC heap)        |
+--------------------------------------------------+
```

### 8.2 Daemon Lifecycle

#### Socket paths and permissions

| Platform | Base Directory | Sockets |
|----------|---------------|---------|
| Linux | `$XDG_RUNTIME_DIR/heimdall/` (fallback: `$HEIMDALL_HOME/run/`) | `daemon.sock`, `agent.sock` |
| macOS | `$TMPDIR/heimdall/` (per-user temp, e.g., `/var/folders/.../T/heimdall/`) | `daemon.sock`, `agent.sock` |

- Socket directory: 0700
- Socket files: 0600
- MUST verify total socket path length < 104 bytes (macOS limit)
- MUST NOT use abstract namespace sockets (no filesystem permissions)

#### PID management

- PID file at `${HEIMDALL_HOME}/daemon.pid`
- On startup: check if PID file exists and process is alive
- If stale PID file: remove it, remove stale sockets, start fresh

#### Startup sequence

1. CLI command requires daemon → check if socket exists and is responsive
2. If socket exists: verify daemon PID via `SO_PEERCRED` / `getpeereid()` → connect
3. If socket doesn't exist or stale: CLI forks daemon as child process
4. Daemon: create socket directory (0700) → create sockets → write PID file → signal ready
5. CLI: wait for ready signal → verify daemon PID → connect

**Race condition prevention:** CLI spawns daemon as child process, then verifies PID via `SO_PEERCRED`. Never connects to a pre-existing socket without PID verification.

#### Shutdown sequence

1. Receive SIGTERM → set graceful shutdown flag
2. Stop accepting new gRPC connections
3. Wait for active SSH agent signing operations to complete (5s timeout)
4. Lock vault (zero-wipe VMK via memguard)
5. Close sockets, remove PID file
6. Exit 0

#### Signal handling

| Signal | Action |
|--------|--------|
| SIGTERM | Graceful shutdown (drain + cleanup) |
| SIGINT | Immediate shutdown (best-effort cleanup) |
| SIGHUP | Reload config + policy file without restart |

#### Service manager integration

- **Default:** CLI auto-forks daemon on first use
- **Optional:** Ship `launchd` plist (macOS) and `systemd` unit (Linux) for users who prefer OS-managed daemon
- `--no-daemon` flag for CLI: bypass daemon, open vault directly in process (single-command mode, slower)

#### Daemonless operations

These commands work without a running daemon:
- `heimdall version`
- `heimdall doctor`
- `heimdall init`
- `heimdall help`
- `heimdall daemon status` (reports daemon is not running)

All other commands require the daemon.

### 8.3 Module Boundaries

```
cmd/heimdall/           — main entrypoint, wiring, command registration
internal/cli/           — cobra commands, flag parsing, completion, man generation
internal/app/           — application services (host, secret, connect, key)
internal/policy/        — policy evaluation, deny reasons
internal/config/        — config loading (TOML/env/flags), schema validation
internal/storage/       — SQLite access, migrations, repositories
internal/crypto/        — KDF, AEAD, key wrapping, blob formats, zeroization
internal/ssh/           — ssh command planning, known_hosts management, exec
internal/agent/         — Heimdall SSH agent server (agent protocol)
internal/fido2/         — Internal libfido2 cgo wrapper, enrollment, assertion, PIN
internal/daemon/        — Daemon process management, socket lifecycle, signals
internal/grpc/          — gRPC server, services, interceptors, auth tiers
internal/audit/         — Audit event creation, hashing, verification
internal/tui/           — Bubbletea TUI components
internal/log/           — Structured logging with redaction
internal/debug/         — Sanitized debug bundle
api/v1/                 — Protobuf definitions, generated Go code
```

Dependency rules:
- `internal/crypto` MUST NOT import `storage`, `ssh`, or `cli`
- `storage` MUST NOT contain crypto logic beyond calling `internal/crypto`
- `cli` MUST NOT directly access SQLite; it MUST call via gRPC to the daemon
- `internal/fido2` MUST NOT import anything except `internal/crypto` and stdlib

### 8.4 Dependency Choices

| Dependency | Package | Rationale |
|------------|---------|-----------|
| CLI framework | `spf13/cobra` | Completions, man pages, subcommands |
| TUI | `charmbracelet/bubbletea` + `lipgloss` + `bubbles` + `huh` | Elm MVU, inline mode, company-backed |
| SQLite | `modernc.org/sqlite` | Pure Go, no cgo, eliminates C CVE surface |
| Crypto | `golang.org/x/crypto/argon2`, `chacha20poly1305`, `hkdf` | Standard Go crypto ecosystem |
| FIDO2 | Internal cgo wrapper around libfido2 | No maintained Go binding exists |
| SSH agent | `golang.org/x/crypto/ssh/agent` | Standard library, well-tested |
| Config | `pelletier/go-toml` | TOML parsing |
| gRPC | `google.golang.org/grpc` + `protobuf` | Standard, Unix socket support |
| Logging | `log/slog` with custom redaction handler | Stdlib, structured |
| Memory | `github.com/awnumar/memguard` | mlock, guard pages, non-GC allocation |

### 8.5 cgo Build Strategy

**Only libfido2 requires cgo.** All other dependencies are pure Go.

#### Build matrix

| Platform | Arch | cgo | libfido2 | CI Runner |
|----------|------|-----|----------|-----------|
| macOS 13+ | arm64 | **MUST** | Homebrew `libfido2` | GitHub Actions `macos-latest` |
| macOS 13+ | amd64 | SHOULD | Homebrew `libfido2` | GitHub Actions `macos-13` |
| Linux (Ubuntu 22.04+) | amd64 | **MUST** | `apt: libfido2-dev` | GitHub Actions `ubuntu-latest` |
| Linux (Ubuntu 22.04+) | arm64 | SHOULD | Cross-compile or native ARM runner | GitHub Actions (if available) |

#### Build flags

```
CGO_ENABLED=1
go build -tags fido2 -trimpath -ldflags="-s -w -X main.version=$(VERSION)"
```

#### No-FIDO2 build

```
CGO_ENABLED=0
go build -tags nofido2 -trimpath
```

Produces a pure-Go binary without passkey support. Passkey commands fail with exit 6 and guidance.

#### Homebrew formula

```ruby
depends_on "libfido2"  # runtime dependency (dynamically linked)
depends_on "go" => :build
```

#### Linux packages

- apt: `Depends: libfido2-1 (>= 1.14.0)`
- Document udev rules for device access if required

### 8.6 Cross-platform Considerations

#### File permissions

- Unix: 0700 on home/run directories, 0600 on vault/sockets
- Verify permissions on startup; warn if too permissive

#### Socket path length

- macOS: 104 bytes max
- Linux: 108 bytes max
- MUST validate path length during daemon startup; fail with guidance if exceeded

#### TTY and PIN input

- PIN entry MUST not echo to terminal
- Use `golang.org/x/term.ReadPassword()` for cross-platform secure input

---

## 9. Data Model & Storage

### 9.1 Entity Schemas

All entities have:
- `id` TEXT PRIMARY KEY (UUID v4)
- `created_at` TEXT NOT NULL (RFC 3339)
- `updated_at` TEXT NOT NULL (RFC 3339)
- `deleted_at` TEXT (nullable tombstone for future sync feasibility)

#### Hosts

```sql
CREATE TABLE hosts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    address     TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 22,
    "user"      TEXT,
    group_name  TEXT,
    template_id TEXT REFERENCES templates(id),
    identity_id TEXT REFERENCES identities(id),
    jump_chain  TEXT,                          -- JSON array
    known_hosts_policy TEXT NOT NULL DEFAULT 'inherit',
    agent_forwarding   TEXT NOT NULL DEFAULT 'inherit',
    pty         TEXT NOT NULL DEFAULT 'inherit',
    forwards    TEXT,                          -- JSON array of forward specs
    notes_enc   BLOB,                         -- encrypted
    notes_nonce BLOB,
    connect_timeout TEXT,
    keepalive_interval INTEGER,
    keepalive_count    INTEGER,
    last_connected_at  TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    deleted_at  TEXT
);

CREATE TABLE host_tags (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag     TEXT NOT NULL,
    PRIMARY KEY (host_id, tag)
);

CREATE INDEX idx_hosts_name ON hosts(name);
CREATE INDEX idx_hosts_group ON hosts(group_name);
CREATE INDEX idx_host_tags_tag ON host_tags(tag);
```

#### Identities (SSH Keys)

```sql
CREATE TABLE identities (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    key_type        TEXT NOT NULL,              -- 'ed25519' | 'rsa'
    public_key      TEXT NOT NULL,              -- authorized_keys format
    private_key_enc BLOB NOT NULL,              -- encrypted
    private_key_nonce BLOB NOT NULL,
    fingerprint     TEXT NOT NULL,              -- SHA256
    status          TEXT NOT NULL DEFAULT 'active', -- 'active' | 'retired'
    comment         TEXT,
    rsa_bits        INTEGER,                    -- NULL for ed25519
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT
);

CREATE UNIQUE INDEX idx_identities_name ON identities(name);
CREATE INDEX idx_identities_fingerprint ON identities(fingerprint);
```

#### Secrets

```sql
CREATE TABLE secrets (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,       -- plaintext for search
    secret_type     TEXT NOT NULL,              -- 'token' | 'password' | 'note' | 'file'
    value_enc       BLOB NOT NULL,              -- encrypted
    value_nonce     BLOB NOT NULL,
    meta            TEXT,                       -- JSON: {filename, mime_type, size}
    reveal_policy   TEXT NOT NULL DEFAULT 'always-reauth',
    allowed_actions TEXT NOT NULL DEFAULT '["reveal","export","inject-to-env"]',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT
);

CREATE UNIQUE INDEX idx_secrets_name ON secrets(name);
```

#### Passkey Enrollments

```sql
CREATE TABLE passkey_enrollments (
    id                  TEXT PRIMARY KEY,
    label               TEXT NOT NULL UNIQUE,
    cred_id             BLOB NOT NULL,
    public_key_cose     BLOB NOT NULL,
    aaguid              BLOB,
    supports_hmac_secret INTEGER NOT NULL DEFAULT 0,
    uv_policy           TEXT NOT NULL DEFAULT 'preferred',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT
);
```

#### Audit Events (append-only)

```sql
CREATE TABLE audit_events (
    id          TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,                  -- RFC 3339 with nanoseconds
    actor_pid   INTEGER,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    result      TEXT NOT NULL,                  -- 'success' | 'failure' | 'denied'
    details     TEXT,                           -- JSON, redacted
    prev_hash   TEXT,
    hash        TEXT NOT NULL
);

CREATE INDEX idx_audit_ts ON audit_events(ts);
CREATE INDEX idx_audit_action ON audit_events(action);
```

#### Session History

```sql
CREATE TABLE session_history (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id),
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    exit_code   INTEGER,
    summary     TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    deleted_at  TEXT
);

CREATE INDEX idx_sessions_host ON session_history(host_id);
CREATE INDEX idx_sessions_started ON session_history(started_at);
```

#### Vault Metadata

```sql
CREATE TABLE vault_meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
-- Keys: vault_version, schema_version, kdf_type, kdf_params (JSON),
--        salt, encrypted_master_key_blobs (JSON array), hmac_secret_salt,
--        commitment_tag, created_at, audit_chain_root
```

#### Templates

```sql
CREATE TABLE templates (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    settings    TEXT NOT NULL,                  -- JSON: default host settings
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    deleted_at  TEXT
);
```

### 9.2 Vault File/DB Format

- Single SQLite database file (`vault.db`) in `$HEIMDALL_HOME`
- WAL mode for reliability
- Plaintext metadata (host names, secret names) for search; sensitive fields encrypted as blobs
- Each encrypted blob uses a unique nonce and associated data binding: vault ID + entity type + entity ID + field name + schema version

### 9.3 Migration Strategy

- Schema versioned with integer `schema_version` in `vault_meta`
- Embedded Go migration functions, one per version increment
- Migrations run automatically on vault open, within a transaction
- Failed migrations roll back completely; vault remains at previous version
- Heimdall MUST refuse to open vaults with a newer schema version (exit 7 with guidance: "This vault was created by a newer version of Heimdall. Please upgrade or restore from backup.")
- Export format includes version and is migratable

### 9.4 Validation Rules & Limits

| Field | Rule |
|-------|------|
| Host name | 1-128 chars, `[a-zA-Z0-9._-]`, unique |
| Secret name | 1-256 chars, `[a-zA-Z0-9._-/]`, unique |
| Key name | 1-128 chars, `[a-zA-Z0-9._-]`, unique |
| Passkey label | 1-64 chars, `[a-zA-Z0-9._-]`, unique |
| Tag | 1-64 chars, `[a-zA-Z0-9._-]` |
| Group | 1-128 chars, `[a-zA-Z0-9._-/]` |
| Hostname/address | Valid hostname, FQDN, IPv4, or IPv6 |
| Port | 1-65535 |
| Note size | Max 1 MiB |
| File secret size | Max 50 MiB (configurable) |
| Max hosts | 10,000 |
| Max secrets | 50,000 |
| Max identities | 1,000 |

---

## 10. gRPC API Contract

### 10.1 Service Definitions

```protobuf
syntax = "proto3";
package heimdall.v1;

service VaultService {
    rpc Status(StatusRequest) returns (StatusResponse);
    rpc Unlock(UnlockRequest) returns (UnlockResponse);
    rpc Lock(LockRequest) returns (LockResponse);
    rpc ChangePassphrase(ChangePassphraseRequest) returns (ChangePassphraseResponse);
}

service HostService {
    rpc Create(CreateHostRequest) returns (Host);
    rpc Get(GetHostRequest) returns (Host);
    rpc List(ListHostsRequest) returns (ListHostsResponse);
    rpc Update(UpdateHostRequest) returns (Host);
    rpc Delete(DeleteHostRequest) returns (DeleteHostResponse);
    rpc Test(TestHostRequest) returns (TestHostResponse);
    rpc Trust(TrustHostRequest) returns (TrustHostResponse);
}

service SecretService {
    rpc Create(CreateSecretRequest) returns (SecretMeta);
    rpc Get(GetSecretRequest) returns (SecretMeta);
    rpc GetValue(GetSecretValueRequest) returns (SecretValue);  // Tier 2
    rpc List(ListSecretsRequest) returns (ListSecretsResponse);
    rpc Delete(DeleteSecretRequest) returns (DeleteSecretResponse);
    rpc SetPolicy(SetSecretPolicyRequest) returns (SecretMeta);
}

service KeyService {
    rpc Generate(GenerateKeyRequest) returns (KeyMeta);
    rpc Import(ImportKeyRequest) returns (KeyMeta);
    rpc Export(ExportKeyRequest) returns (ExportKeyResponse);  // Tier 2
    rpc List(ListKeysRequest) returns (ListKeysResponse);
    rpc Get(GetKeyRequest) returns (KeyMeta);
    rpc Delete(DeleteKeyRequest) returns (DeleteKeyResponse);
    rpc Rotate(RotateKeyRequest) returns (KeyMeta);
}

service PasskeyService {
    rpc Enroll(EnrollPasskeyRequest) returns (PasskeyMeta);
    rpc List(ListPasskeysRequest) returns (ListPasskeysResponse);
    rpc Remove(RemovePasskeyRequest) returns (RemovePasskeyResponse);  // Tier 2
    rpc Test(TestPasskeyRequest) returns (TestPasskeyResponse);
}

service ConnectService {
    rpc Plan(PlanConnectRequest) returns (ConnectPlan);
    rpc Execute(ExecuteConnectRequest) returns (ExecuteConnectResponse);
}

service AuditService {
    rpc List(ListAuditRequest) returns (ListAuditResponse);
    rpc Verify(VerifyAuditRequest) returns (VerifyAuditResponse);
}

service BackupService {
    rpc Create(CreateBackupRequest) returns (CreateBackupResponse);
    rpc Restore(RestoreBackupRequest) returns (RestoreBackupResponse);
}
```

### 10.2 Authorization Tiers

| Tier | Requirement | Operations |
|------|-------------|------------|
| **0** (unauthenticated) | Socket access only | `VaultService.Status`, `VaultService.Lock`, `SecretService.List` (names only), `HostService.List`, `KeyService.List`, `PasskeyService.List`, `AuditService.*` |
| **1** (unlocked vault) | Vault must be unlocked | `HostService.*`, `SecretService.Create/Get/Delete`, `KeyService.Generate/Import/Get/Delete/Rotate`, `ConnectService.*`, `PasskeyService.Enroll` |
| **2** (re-auth required) | FIDO2 touch or passphrase | `SecretService.GetValue`, `KeyService.Export`, `PasskeyService.Remove`, `VaultService.ChangePassphrase`, `BackupService.Create` (unencrypted) |

### 10.3 Error Model

gRPC standard status codes with `google.rpc.ErrorInfo` details:

| Heimdall Code | gRPC Status | When |
|---------------|-------------|------|
| `VAULT_LOCKED` | `FAILED_PRECONDITION` | Vault not unlocked |
| `REAUTH_REQUIRED` | `PERMISSION_DENIED` | Tier 2 operation without re-auth |
| `NOT_FOUND` | `NOT_FOUND` | Entity doesn't exist |
| `ALREADY_EXISTS` | `ALREADY_EXISTS` | Duplicate name |
| `POLICY_DENIED` | `PERMISSION_DENIED` | Policy file blocks action |
| `DEPENDENCY_MISSING` | `UNAVAILABLE` | libfido2, ssh not found |
| `VAULT_CORRUPTED` | `DATA_LOSS` | Integrity check failed |
| `RATE_LIMITED` | `RESOURCE_EXHAUSTED` | Rate limit exceeded |
| `AUTH_LOCKOUT` | `PERMISSION_DENIED` | Too many failed auth attempts |

### 10.4 Rate Limiting

- Per-PID token bucket tracked via `SO_PEERCRED`
- Tier 2 operations: 10 requests/minute per PID (default)
- Tier 1 operations: 100 requests/minute per PID
- Tier 0 operations: 1000 requests/minute per PID
- Configurable via policy file
- Exceeding rate returns `RESOURCE_EXHAUSTED` with retry-after hint

---

## 11. Security & Privacy

### 11.1 Threat Model

#### Assets
- Vault contents: secret values, private keys, passkey enrollment metadata
- Audit logs (integrity-sensitive)
- Known_hosts trust decisions
- VMK (in daemon memory)

#### Attackers
- **Local attacker with filesystem read access** (stolen laptop, malware reading files)
- **Local attacker with user-level execution** (processes running as same UID)
- **Remote network attacker** (MITM during SSH TOFU)
- **Supply chain attacker** (tampered binaries, dependencies)

#### Out of scope (v0.1.0)
- Kernel-level compromise / root access
- Hardware attacks against FIDO2 keys
- Users misusing `--insecure-hostkey`

### 11.2 Cryptography & Key Hierarchy

#### Primitives

| Purpose | Algorithm | Package |
|---------|-----------|---------|
| KDF | Argon2id | `golang.org/x/crypto/argon2` |
| AEAD | XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` |
| Hash | SHA-256 | `crypto/sha256` |
| Key derivation | HKDF-SHA256 | `golang.org/x/crypto/hkdf` |
| Commitment | HMAC-SHA256 | `crypto/hmac` |

#### Key hierarchy

1. **Vault Master Key (VMK):** Random 32 bytes, generated at init
2. **Key Encryption Key (KEK):** Derived from passphrase (Argon2id) or passkey (HKDF of hmac-secret output)
3. VMK is wrapped by KEK using XChaCha20-Poly1305 with unique nonce and AD containing vault ID + method type
4. **Data Encryption Keys (DEKs):** Per-record subkeys derived from VMK via HKDF with context = entity type + entity ID + field name
5. Each encrypted blob uses a fresh random nonce and AD binding: vault ID, entity type, entity ID, field name, schema version

#### Key commitment scheme

After decrypting VMK, verify: `HMAC-SHA256(VMK, "heimdall-key-commitment") == stored_commitment_tag`

This prevents key-commitment attacks where XChaCha20-Poly1305 (which is not inherently key-committing) could decrypt under multiple keys.

#### Argon2id parameters

| Parameter | Default | Constraints |
|-----------|---------|-------------|
| Memory | 256 MiB | Min 64 MiB, max 4 GiB |
| Iterations | 3 | Min 1 |
| Parallelism | min(4, runtime.NumCPU()) | |
| Output | 32 bytes | |

Parameters stored in vault metadata. Configurable at init, read-only after.

#### Nonce and salt rules

- Nonces: `crypto/rand`, MUST never repeat for the same AEAD key
- Argon2id salt: random 32 bytes per vault
- hmac-secret salt: random 32 bytes per vault, stored in vault metadata

### 11.3 VMK Memory Protection

The VMK MUST be allocated outside Go's GC-managed heap using **memguard**:

- `memguard.NewBufferFromBytes(vmk)` → creates mlock'd, guard-page-protected allocation
- `prctl(PR_SET_DUMPABLE, 0)` on Linux at daemon startup (prevents ptrace by non-root)
- `madvise(MADV_DONTDUMP)` to exclude from core dumps
- On vault lock: `buffer.Destroy()` performs guaranteed zero-wipe
- On daemon shutdown: `memguard.DestroyAll()`
- `memguard.CatchInterrupt()` for signal-based cleanup

**Documented limitation:** Go cannot guarantee complete zeroization due to GC copying. memguard mitigates but does not eliminate this. Same trust model as ssh-agent and gpg-agent.

### 11.4 Secret Handling & Redaction

#### Redaction rules

Secrets MUST NOT appear in: logs, panic output, debug bundles, error messages.

Structured redaction via `log/slog` custom handler:
- Fields named `secret`, `token`, `password`, `private_key`, `value`, `passphrase` → redacted as `[REDACTED]`
- Developers MUST use dedicated redaction helpers for potentially sensitive strings

#### Terminal output

- `secret show` prints to stdout only (not stderr), raw format by default
- `--json` for structured output with explicit fields
- Warn when printing secrets in interactive terminals
- Prefer `secret env` for safer usage

#### Clipboard

- Deferred for v0.1.0 (cross-platform safety not reliable)

### 11.5 Socket Security

- Socket directory: 0700 before creating sockets
- Sockets: 0600
- Validate `SO_PEERCRED` (Linux) / `getpeereid()` (macOS) on every connection
- Reject connections from different UID than daemon's UID
- Never use abstract namespace sockets
- Use per-user runtime directories (`$XDG_RUNTIME_DIR` or `$TMPDIR`), never `/tmp`
- Go packages: `toolman.org/net/peercred` or `github.com/joeshaw/peercred`

### 11.6 Passkey Implementation (Internal cgo Wrapper)

Heimdall uses a minimal internal cgo wrapper (~500 LOC) around libfido2, exposing only:
- `fido_dev_open` / `fido_dev_close` — device lifecycle
- `fido_cred_new` / `fido_cred_set_*` / `fido_dev_make_cred` — credential creation
- `fido_assert_new` / `fido_assert_set_*` / `fido_dev_get_assert` — assertion
- `fido_cred_hmac_secret` / `fido_assert_hmac_secret` — hmac-secret extension
- PIN collection support

Build tag: `fido2` (enabled) / `nofido2` (disabled).

If libfido2 unavailable at runtime: passkey commands fail with exit 6 and guidance. Vault still unlockable with passphrase.

### 11.7 Re-auth Policy

- Re-auth cache: 60 seconds, **PID-scoped**
  - Bind cache token to connecting socket's PID (via `SO_PEERCRED`)
  - Session A re-auth does NOT grant session B access
- Cache in-memory only, cleared on vault lock
- Configurable down to 0 (always require touch) via policy file
- Invalidated immediately when auto-lock fires

### 11.8 Auth Lockout

| Consecutive Failures | Delay |
|---------------------|-------|
| 3 | 5 seconds |
| 5 | 30 seconds |
| 10 | 5 minutes |

Resets on successful authentication. All attempts logged in audit with PID.

### 11.9 Agent Forwarding Policy

- Default: **deny** unless explicitly enabled per-host or per-command
- When enabled: set `-A` explicitly
- SHOULD implement `SSH_AGENT_CONSTRAIN_CONFIRM` for forwarded signing requests
- Log forwarded sign requests with requesting host information

### 11.10 Daemon Startup Race Prevention

1. CLI spawns daemon as child process (not "connect to whatever socket exists")
2. Wait for daemon to write PID file and create sockets
3. Verify daemon's PID via `SO_PEERCRED` before sending any data
4. If PID doesn't match expected child: abort, warn, exit 6

### 11.11 Backup Encryption

- Backup archive encrypted with a **separate user-provided passphrase**
- Not reusing the vault unlock passphrase
- Key derivation: Argon2id (same parameters as vault)
- Encryption: XChaCha20-Poly1305 wrapping the entire archive
- Includes integrity protection via AEAD authentication tag
- `--unencrypted` requires `--yes` and re-auth

### 11.12 Telemetry & Vulnerability Disclosure

- Telemetry: **off by default**. If ever implemented: opt-in, documented, no secrets/hostnames/IDs.
- `SECURITY.md` with security contact, supported versions, coordinated disclosure expectations
- Releases document security-relevant changes in changelogs

---

## 12. SSH Compatibility

### 12.1 Execution Strategy

- Shell out to system `ssh` for all connections
- Generate temporary config snippets for complex forwards (secure temp dir, deleted after use)
- `--ignore-ssh-config` for fully isolated behavior (`ssh -F /dev/null`)

### 12.2 SSH Directive Support Matrix

#### Import from `~/.ssh/config` (v0.1.0)

| Directive | Supported | Maps to |
|-----------|-----------|---------|
| `Host` | YES | `hosts.name` (if simple alias) |
| `HostName` | YES | `hosts.address` |
| `Port` | YES | `hosts.port` |
| `User` | YES | `hosts.user` |
| `IdentityFile` | YES | Creates/references identity |
| `ProxyJump` | YES | `hosts.jump_chain` |
| `LocalForward` | YES | `hosts.forwards` |
| `RemoteForward` | YES | `hosts.forwards` |
| `DynamicForward` | YES | `hosts.forwards` |
| `ForwardAgent` | YES | `hosts.agent_forwarding` |
| `IdentitiesOnly` | Noted | Applied automatically when identity specified |
| `Match` blocks | NO | Logged as warning |
| `Include` | NO | Logged as warning |
| `ProxyCommand` | NO | Logged as warning |
| All other directives | NO | Silently skipped |

#### Export via `heimdall ssh-config generate`

Generates valid OpenSSH config blocks for managed hosts. Read-only output.

### 12.3 Key Format Support Matrix

| Type | Generate | Import | Export | SSH Agent |
|------|----------|--------|--------|-----------|
| Ed25519 (OpenSSH) | YES (default) | YES | YES | YES |
| RSA 3072+ (OpenSSH) | YES (`--type rsa`) | YES | YES | YES |
| RSA < 3072 | NO | YES (warning) | YES | YES |
| ECDSA | NO | NO | NO | NO |
| PEM format | NO | NO | NO | N/A |
| PKCS#8 format | NO | NO | NO | N/A |
| OpenSSH certificates | NO | NO | NO | Passthrough |

### 12.4 known_hosts Policy & Host Key Pinning

- Heimdall-owned file: `${HEIMDALL_HOME}/ssh/known_hosts`
- Passed to `ssh` via `-o UserKnownHostsFile=<path>`
- TOFU: present fingerprint (SHA256), key type, source; prefer OpenSSH's own `StrictHostKeyChecking=ask` in interactive mode
- If `ssh-keyscan` is used: label fingerprint as **unauthenticated**, require confirmation

### 12.5 ProxyJump Edge Cases

- Handle `IdentitiesOnly yes` automatically when specifying identity (prevents "too many auth" failures)
- Support per-hop user and identity in jump chains
- `ProxyJump none` overrides wildcard config
- Validate that ProxyJump and ProxyCommand are not both specified (ProxyCommand is ignored by OpenSSH in this case)
- Warn about `CanonicalizeHostname` interactions

---

## 13. Reliability & Failure Modes

### 13.1 Performance Targets

- Daemon startup: <200ms (excluding vault unlock KDF cost)
- Vault unlock (passphrase): 0.5-2.5s depending on hardware
- Vault unlock (passkey): <1s (hardware-dependent)
- CLI command round-trip (daemon warm): <50ms
- `heimdall connect` overhead vs raw `ssh`: <50ms p99

### 13.2 Failure Modes Table

| Failure | Detection | User Impact | Recovery | Data Loss? |
|---------|-----------|-------------|----------|------------|
| Daemon crash | Stale socket, PID file | Sessions interrupted, new ops fail | Auto-restart on next CLI command | No (VMK lost, re-auth needed) |
| Vault corruption | SQLite integrity check | Can't read data | Diagnostic + guided recovery (backup restore or salvage export) | Possible |
| SQLite WAL corruption | SQLite error codes | Partial writes | WAL replay + checkpoint | Possible (last transaction) |
| FIDO device disconnected mid-auth | libfido2 error | Auth fails | Retry or fall back to passphrase | No |
| Disk full | Write error | Can't save | Alert user; read-only operations continue | No |
| Socket permission changed | Connect error | CLI can't reach daemon | Re-create socket (daemon restart) | No |
| SSH host key changed | SSH error | Connection refused | User confirmation flow (trust or reject) | No |
| Import file malformed | Parse error | Partial import | Report per-entry errors, import valid entries | No |
| libfido2 missing | dlopen error | Passkey commands fail | Exit 6 with install guidance; passphrase still works | No |
| Daemon restart race | PID mismatch | Potential socket hijack | Abort + warn + exit 6 | No |
| Rate limit exceeded | Token bucket empty | Operation denied | Wait and retry; `RESOURCE_EXHAUSTED` with retry-after | No |
| Schema version mismatch | Version check | Can't open vault | Upgrade Heimdall or restore from backup | No |

### 13.3 Crash Recovery

- **SQLite WAL** handles DB consistency for single-statement operations
- **Application-level write-ahead** for multi-step operations (e.g., key rotation):
  1. Write intent record (operation type, target entity, timestamp) to `pending_ops` table
  2. Execute steps
  3. On completion: delete intent record
  4. On daemon restart: check `pending_ops`, complete or rollback each pending operation
- `PRAGMA wal_autocheckpoint=0` — checkpoint only at controlled points
- WAL file permissions: 0600 (same as vault DB)

#### Rollback attack prevention

- Monotonic version counter stored in vault AND in a separate file (`${HEIMDALL_HOME}/vault.version`)
- On open: verify DB version >= file version; reject rollbacks
- HMAC the version: `HMAC-SHA256(VMK, version_counter)` stored alongside

### 13.4 Max Session Duration

- Default: 8 hours (configurable via config and policy)
- After max duration: daemon stops responding to SSH agent signing requests for that session's keys
- Existing TCP connections survive (SSH protocol handles this), but no new channels requiring agent forwarding
- Logged in audit when session is terminated

### 13.5 Vault Rollback Policy

- Heimdall MUST refuse to open vaults with a newer `schema_version`
- Exit 7 with guidance: "This vault was created by Heimdall vX.Y. Please upgrade or restore from backup."
- Users SHOULD backup before upgrading (`heimdall backup create`)
- No reverse migrations in v0.1.0

---

## 14. Observability

### 14.1 Logging

- Format: structured JSON (production), human-readable (development, default when TTY)
- Engine: `log/slog` with custom redaction handler
- Output: stderr + file (configurable)
- File location: `${HEIMDALL_HOME}/logs/heimdall.log`

#### Log levels

| Level | Usage |
|-------|-------|
| ERROR | Auth failures, corruption, unrecoverable errors |
| WARN | Stale socket, retry, degraded operation, policy override |
| INFO | Session start/end, lock/unlock, config reload |
| DEBUG | gRPC calls, SQL queries, timing (dev only) |

#### Rotation

Built-in rotation:
- Max file size: 10 MiB (configurable)
- Max files: 5 (configurable)
- Rotated files: `heimdall.log.1`, `heimdall.log.2`, etc.

#### Redaction

- Fields `secret`, `token`, `password`, `private_key`, `value`, `passphrase` → `[REDACTED]`
- Stack traces in logs MUST NOT contain secret values
- Panic recovery handler strips sensitive data before logging

### 14.2 Audit Log

- Storage: `audit_events` table in vault DB (append-only)
- Fields: timestamp, action, actor PID, target type/ID, result, details (JSON, redacted)
- Hash chain: `hash_i = SHA256(hash_{i-1} || canonical_json(event_i))`
- Chain root stored in `vault_meta` for quick verification
- Retention: configurable, default 90 days
- Query: `heimdall audit list --since 7d --action connect --json`
- Verify: `heimdall audit verify` checks hash chain integrity

### 14.3 Debug Bundle

`heimdall debug bundle --output <path>` collects:
- Version/build info
- OS info
- Dependency checks (ssh, libfido2 versions)
- Sanitized config (no secrets)
- Recent audit metadata (redacted)
- Daemon status and uptime
- Log tail (last 100 lines, redacted)

MUST NOT include vault contents, private keys, or secret values.

---

## 15. Testing & Acceptance Criteria

### 15.1 Platform Support Matrix

| Platform | Arch | Status | CI |
|----------|------|--------|----|
| macOS 13+ | arm64 | **MUST** | GitHub Actions `macos-latest` |
| macOS 13+ | amd64 | SHOULD | GitHub Actions `macos-13` |
| Ubuntu 22.04+ | amd64 | **MUST** | GitHub Actions `ubuntu-latest` |
| Ubuntu 22.04+ | arm64 | SHOULD | Native ARM runner (if available) |
| Fedora 38+ | amd64 | MAY | Manual validation |

### 15.2 Test Layers

1. **Unit tests** — crypto blob encode/decode, KDF validation, policy evaluation, redaction rules, validation rules
2. **Integration tests** — SQLite migrations, repository CRUD with encryption, agent protocol, gRPC services, daemon lifecycle
3. **E2E tests** — CLI commands, exit codes, JSON output stability, `connect --dry-run`, host key policy behaviors, import/export round-trips
4. **Crypto KATs** — Deterministic test vectors for wrapping/unwrapping, AEAD encoding, HKDF derivation
5. **Fuzzing** — Import format parsers, blob decoding, config parsing, forward spec parsing

CI MUST include:
- `go test ./...` with race detector
- `govulncheck`, `staticcheck`
- Linting and formatting (`gofmt`, `goimports`)
- Build validation for both `fido2` and `nofido2` tags

### 15.3 FIDO2 Testing

- **CI:** SoftFIDO2 virtual authenticator (`bulwarkid/virtual-fido` or equivalent) for enrollment, unlock, re-auth flows
- **Pre-release:** Manual YubiKey 5 series validation (enroll, unlock, re-auth, PIN flows)
- **Unit tests:** Mock the internal cgo wrapper interface for non-FIDO tests

### 15.4 Per-Feature Acceptance Criteria

#### Host Management
- CRUD operations work via CLI and TUI
- Names are unique; duplicate rejected with exit 2
- Import from SSH config produces hosts with correct fields
- `--json` output is stable and parseable
- Tags and groups filter correctly

#### SSH Connect
- `connect` spawns `ssh` with correct flags
- ProxyJump chains work with multi-hop
- Port forwarding specs are validated
- `--print-cmd` shows redacted command
- `--dry-run` validates without executing
- Exit code propagates from `ssh`

#### Key Management
- Ed25519 and RSA generation works
- Import handles encrypted and unencrypted OpenSSH keys
- Export private key requires re-auth and creates 0600 file
- Agent add/remove works with managed agent
- Key rotation creates new key, retires old

#### Secrets
- Add/show/rm for all types (token, password, note, file)
- `secret show` requires re-auth
- `secret env` injects value without printing
- File secrets up to 50 MiB
- Reveal policy enforcement works

#### Passkeys
- Enroll with SoftFIDO2 succeeds
- Vault unlock with hmac-secret works
- Re-auth assertion works
- Lockout after 3 failures triggers delay
- Remove requires re-auth

#### Daemon
- Auto-start on first command
- Lock after timeout
- Sessions survive lock
- Max session duration enforced
- SIGHUP reloads config
- Stale socket detected and cleaned

### 15.5 Release Gate

**All of the following MUST pass:**

Quality:
- [ ] Zero data-loss bugs in test suite
- [ ] SSH connect overhead <50ms p99 (benchmark)
- [ ] Vault open <500ms cold (integration test)
- [ ] Test coverage >80% critical paths
- [ ] Zero secret redaction violations
- [ ] `govulncheck` clean

Completeness:
- [ ] All MUST requirements implemented and tested
- [ ] All exit codes deterministic (tested)
- [ ] macOS arm64 + Linux amd64 CI green
- [ ] Shell completions generated (bash, zsh, fish)
- [ ] Man pages generated
- [ ] `--json` stable for all list/show commands
- [ ] SoftFIDO2 passkey flows pass in CI
- [ ] Import from SSH config tested
- [ ] Backup create/restore round-trip tested

---

## 16. Packaging & Distribution

### Packaging targets

- Standalone binaries for macOS and Linux (amd64 + arm64)
- Homebrew formula (macOS + Linux): `depends_on "libfido2"`
- apt package (Debian/Ubuntu): `Depends: libfido2-1 (>= 1.14.0)`
- rpm package (Fedora): MAY in v0.1.0

### Supply chain integrity

- Checksums (SHA256) for all release artifacts
- SBOM (SPDX or CycloneDX)
- Signed provenance (recommended: SLSA-compatible)
- Fixed Go toolchain version in CI, `-trimpath`

### Update mechanism

- Package-manager updates only in v0.1.0
- No self-update mechanism (deferred until signature verification is implemented)

---

## 17. Release Plan (v0.1.0)

Release gating criteria (MUST pass):

1. **Security** — vault encryption verified, no secret leaks in logs, re-auth enforced, key commitment verified
2. **Cross-platform** — install/run on macOS arm64 + Linux amd64; passkey flows work with SoftFIDO2
3. **SSH parity** — ProxyJump, forwards, identity selection, known_hosts policy validated
4. **UX/CLI** — completions, man pages, deterministic exit codes, `--json` stable
5. **Documentation** — README.md, SECURITY.md, SPEC.md finalized, packaging instructions

---

## 18. Future Roadmap

Explicitly deferred beyond v0.1.0:

- Multi-device sync (requires separate design and threat model)
- Platform authenticator passkeys (Touch ID, etc.)
- Windows support
- Full encrypted-metadata mode (hiding secret names)
- Advanced RBAC / multi-user vaults
- Clipboard support (cross-platform safety)
- ECDSA / PEM / PKCS#8 key format support
- OpenSSH certificate management
- Self-update mechanism with signature verification
- Termius import
- `Match` and `Include` directive support in SSH config import

---

## 19. Decision Log

| # | Decision | Alternatives Considered | Rationale |
|---|----------|------------------------|-----------|
| 1 | Background daemon holds VMK in memory | Per-command unlock, kernel keyring | Same model as ssh-agent/gpg-agent; avoids repeated KDF |
| 2 | Daemon serializes all vault access (single SQLite writer) | Per-process locking, shared memory | Eliminates concurrency bugs; SQLite single-writer |
| 3 | Ship managed SSH agent in v0.1.0 | External ssh-agent only | Better UX; auto-lock integration; controlled key lifetime |
| 4 | Hybrid auto-fork + optional launchd/systemd | Service-only, CLI-only | Best of both: zero-config default, power-user option |
| 5 | gRPC over Unix domain socket for IPC | REST, raw protobuf, JSON-RPC | Typed contracts, streaming, standard tooling |
| 6 | User-specified env var via `--env-var` flag | Fixed env var name, multiple env vars | Flexible; avoids name collisions; explicit |
| 7 | Full bubbletea TUI (Charm ecosystem) | tview, tcell, no TUI | Elm MVU, inline mode, company-backed, huh for forms |
| 8 | Stale socket detection + auto-restart | Manual restart, always-on service | Zero-friction recovery; user doesn't need to know |
| 9 | SQLite WAL + application-level write-ahead for multi-step ops | WAL only, external transaction log | Handles both single and multi-step operations correctly |
| 10 | Internal cgo wrapper for libfido2 (~500 LOC) | go-libfido2 binding, fido2-token CLI | go-libfido2 abandoned; wrapper gives version control |
| 11 | Single process (gRPC + SSH agent on separate sockets) | Separate daemon processes | Shared VMK; simpler; separate processes = weak isolation anyway |
| 12 | Propagate raw SSH exit code | Map all to Heimdall codes | Better for scripting; internal failures use Heimdall codes |
| 13 | Plaintext secret names in SQLite | Encrypted names | Enables search-while-locked, completions; same model as `pass` |
| 14 | macOS + Linux only (Windows dropped) | Cross-platform with Windows | Reduces scope; libfido2 packaging on Windows unreliable |
| 15 | Auto-lock default 30 minutes, configurable | Fixed timeout, no auto-lock | Balances security and usability; policy can override |
| 16 | Stderr + file logging | File only, syslog | Immediate feedback + persistent record |
| 17 | TUI handles vault unlock (lock screen) | CLI-only unlock | Natural UX; user doesn't leave TUI to unlock |
| 18 | MIT license | Apache 2.0, GPL | Maximum adoption; simple; no patent clauses needed |
| 19 | Quality + completeness release gate | Quality only, feature-only | Both dimensions required for production-ready release |
| 20 | SSH config import only (Termius dropped) | SSH config + Termius JSON | Termius uses encrypted Electron IndexedDB; impractical |
| 21 | Full dynamic shell completions via daemon | Static completions | Host/secret/key names available for tab-complete |
| 22 | Sessions survive vault lock | Kill sessions on lock | Matches ssh-agent behavior; less disruptive |
| 23 | Read-only ssh-config generate command | Write to ~/.ssh/config | Safe; no modification of user's config |
| 24 | Public versioned gRPC API (api/v1/) | Private/internal API | Enables third-party integrations; stable contract |
| 25 | modernc.org/sqlite (pure Go) | mattn/go-sqlite3 (cgo) | CVE-2025-6965 (CVSS 9.8), CVE-2025-29087; eliminates C attack surface |
| 26 | Module path: github.com/amanthanvi/heimdall | — | Owner's namespace |
| 27 | Key commitment HMAC tag after VMK decryption | No commitment | XChaCha20-Poly1305 is not key-committing; one HMAC fixes it |
| 28 | PID-scoped re-auth cache via SO_PEERCRED | Global cache | Prevents cross-process cache abuse by same-user malware |
| 29 | memguard for VMK (non-GC heap, mlock, guard pages) | Regular []byte | Go GC copies/moves data; memguard allocates via mmap outside GC |
| 30 | TOML config format | YAML, JSON | Simple, human-readable, no whitespace gotchas |
| 31 | $XDG_RUNTIME_DIR socket paths | /tmp, ~/.heimdall | Per-user, tmpfs, 0700; avoids symlink races |
| 32 | SIGTERM=graceful, SIGHUP=reload, SIGINT=immediate | Simpler signal handling | Standard daemon pattern; config reload without restart |
| 33 | gRPC standard status + Heimdall ErrorInfo details | Custom error envelope | Leverages gRPC ecosystem (interceptors, status checks) |
| 34 | Core SSH directives for import | Full directive parsing | Covers 90% of use cases; avoid parsing complexity |
| 35 | Per-PID token bucket rate limiting | Global, none | Distinguishes legitimate from malicious callers |
| 36 | Exponential backoff auth lockout (3/5/10 failures) | No lockout, hard lockout | Balanced: slows attacks without penalizing hardware glitches |
| 37 | Ed25519 + RSA (3072+) in OpenSSH format only | +ECDSA, +PEM | Covers >95% of keys; minimizes format parsing surface |
| 38 | SoftFIDO2 virtual authenticator in CI | Mock only, hardware only | Real CTAP2 flow testing; hardware for pre-release |
| 39 | Built-in log rotation (10MB, 5 files) | External logrotate | Cross-platform, zero-config |
| 40 | Interactive init wizard with sensible defaults | Minimal, full TUI wizard | Good DX for first-run; non-interactive mode for scripting |
| 41 | Daemonless: version/doctor/init/help only | Read-only ops, everything | Clear boundary; daemon = required for all data operations |
| 42 | Helpful TUI onboarding for empty states | Blank, ASCII art | Guides new users without being intrusive |
| 43 | Diagnostic + guided vault corruption recovery | Error + docs link, auto-repair | Actionable guidance at a critical moment |
| 44 | macOS arm64 + Linux amd64 MUST; others SHOULD | All 4 MUST | Primary dev + server targets; pragmatic CI budget |
| 45 | Embedded Go migrations with version table | golang-migrate, raw SQL | No external dependency; transactional; automatic |
| 46 | 8-hour max session duration (configurable) | No max, 24h | Covers workday; policy can enforce shorter |
| 47 | Separate passphrase-derived key for backup encryption | Vault passphrase, age format | Independent of vault; backup sits in untrusted storage |
| 48 | Refuse newer vault versions; recommend backup/restore | Backward compat, no rollback | Clear boundary; no reverse migration complexity |

---

## 20. Open Questions & Risks

### Open Questions

1. Should `heimdall vault repair` attempt SQLite integrity repair automatically, or only offer backup restore? (Deferred to implementation spike)
2. What is the optimal `pending_ops` cleanup strategy for write-ahead intent records? (Deferred to implementation)
3. Should the gRPC API proto definitions be published as a separate Go module for third-party clients? (Decide at v0.1.0 release)
4. Should `heimdall doctor` attempt to detect udev rules issues on Linux for FIDO2 device access? (Nice-to-have)

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Internal libfido2 wrapper takes longer than expected | Medium | Schedule slip | Start with enrollment + unlock; re-auth can follow. Shell out to `fido2-token` as fallback. |
| modernc.org/sqlite performance differs from mattn | Low | Latency regression | Benchmark early in implementation. Vault operations are small and infrequent. |
| bubbletea v2 breaks API before stable release | Low | Rework TUI code | Target bubbletea v1 (stable). Migrate to v2 when stable. |
| SoftFIDO2 doesn't fully replicate hardware behavior | Medium | False positive CI | Manual hardware validation gate before each release. |
| Socket path length exceeds 104 bytes on macOS | Low | Daemon won't start | Validate at startup; use short paths; document constraint. |
| memguard interacts poorly with Go runtime in edge cases | Low | Memory issues | Extensive integration testing; memguard is well-tested with Go. |

### Assumptions

- Users have OpenSSH installed on all target platforms
- libfido2 >= 1.14.0 is packagable for macOS (Homebrew) and Linux (apt/rpm)
- FIDO2 security keys support at least ES256 and user presence
- SQLite WAL mode provides sufficient reliability for a single-user vault
- `$XDG_RUNTIME_DIR` exists on modern Linux systems with systemd

---

*Last updated: 2026-02-19*
*Status: Approved for implementation*
*DRI: Aman Thanvi (@amanthanvi)*
