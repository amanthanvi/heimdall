# Heimdall Security-Core Reboot Spec

Status: current product contract for this repository.

This spec replaces the earlier broad v0.x contract. If another document in the
repo conflicts with this file, this file wins. Deferred and historical material
belongs in [docs/reboot/FUTURE-BACKLOG.md](/Users/amanthanvi/GitRepos/heimdall/docs/reboot/FUTURE-BACKLOG.md)
or in archival planning docs such as `claude-*` and `docs/v2/*`.

## 1. Product

Heimdall is a local-first Go CLI for a solo operator who wants one trustworthy
place to manage:

- SSH hosts and connection defaults
- Vault-backed SSH keys
- Vault-backed secrets
- Encrypted backups
- Tamper-evident local audit history

The rebooted product is intentionally CLI-first. The product goal is coherent,
truthful behavior, not breadth.

## 2. Scope

The rebooted release ships these top-level commands:

- `init`
- `status`
- `doctor`
- `vault`
- `daemon`
- `host`
- `connect`
- `key`
- `secret`
- `backup`
- `audit`
- `version`

The reboot does not promise compatibility with earlier broad specs, docs, or
half-implemented surfaces.

## 3. Non-Goals

The following are explicitly out of scope for the rebooted release:

- Full TUI workflows
- Public `import` and `export` commands
- Managed `ssh-config` commands and fragment syncing
- Templates
- Compliance and reporting surfaces
- Repair and salvage workflows
- Daemonless operation
- Team and shared-vault workflows

Some internal code for deferred areas may still exist in the repo. That does
not make those surfaces part of the product contract.

## 4. Operating Model

Heimdall is local-only and single-operator:

- One operator controls the workstation and the local vault.
- The daemon runs on the same machine as the CLI.
- The CLI is the user-facing contract.
- The daemon exposes gRPC for local process boundaries, not as a networked
  multi-user service.

## 5. Truth Rules

The reboot follows these rules:

- The public CLI surface must only expose supported workflows.
- CLI flags that affect persisted host connection defaults must map to typed
  fields, not hidden side-channel metadata.
- `connect` planning must have one source of truth: app-layer intent mapped into
  `internal/ssh` command building.
- If a feature is deferred, it should be absent or clearly marked deferred. It
  must not appear as a first-class shipped workflow.

## 6. Canonical Data Model

### 6.1 Host

The canonical persisted host model for the reboot includes:

- `name`
- `address`
- `port`
- `user`
- `tags`
- `notes`
- `key_name`
- `identity_path`
- `proxy_jump`
- `known_hosts_policy`
- `forward_agent`

Current rules:

- `name` is the stable operator-facing identifier.
- `notes` are encrypted at rest.
- `key_name` and `identity_path` are mutually exclusive defaults for auth.
- `proxy_jump` is a typed default, not hidden in `env_refs`.
- `known_hosts_policy` is a typed default, not hidden in `env_refs`.
- `forward_agent` is a typed default, not hidden in `env_refs`.
- `env_refs` does not exist in the rebooted product model or storage schema.

Not yet first-class in this reboot contract:

- Persisted default forwards
- Persisted host-level secret bindings

Those remain future work and are tracked in
[docs/reboot/FUTURE-BACKLOG.md](/Users/amanthanvi/GitRepos/heimdall/docs/reboot/FUTURE-BACKLOG.md).

### 6.2 Key

The canonical key metadata includes:

- `name`
- `key_type`
- `public_key`
- `status`
- timestamps

Heimdall stores private key material encrypted in the vault. Key import supports
OpenSSH and PEM/PKCS#8 parse paths.

### 6.3 Secret

The canonical secret model includes:

- `name`
- encrypted secret bytes
- `reveal_policy`
- size metadata

### 6.4 Audit Event

The canonical audit event includes:

- `action`
- `target_type`
- `target_id`
- `result`
- canonicalized details JSON
- previous hash
- event hash
- timestamp

## 7. Command Contracts

### 7.1 `init`

`init` bootstraps a new local vault and config.

Contract:

- Creates the local config and vault paths if they do not already exist.
- Supports non-interactive initialization with `--yes` and a passphrase.
- Does not import SSH config.
- Does not enroll passkeys during init.
- Leaves the daemon available for follow-on commands.

### 7.2 `status`

`status` reports current local state for:

- daemon reachability
- vault lock state
- live VMK state
- key health summary
- audit availability

`status` does not claim ssh-config sync state in the reboot.

### 7.3 `vault`

`vault` manages lock and unlock state.

Contract:

- `vault unlock` derives or unwraps key material for the live session.
- `vault lock` clears live key material and resets re-auth state.
- Re-auth state is local and time-bounded.

### 7.4 `daemon`

`daemon` manages the local background process.

Contract:

- Uses `daemon.info` JSON as the lifecycle record.
- The runtime socket lives under the runtime directory.
- Restarting the daemon requires unlocking again.
- Session expiry stops signing; it does not forcibly kill active SSH sessions.

### 7.5 `host`

`host` is the canonical way to manage connection metadata.

Required subcommands:

- `host add`
- `host edit`
- `host show`
- `host list`
- `host remove`

Supported persistent defaults on `host add` and `host edit`:

- `--key`
- `--identity-file`
- `--proxy-jump`
- `--known-hosts-policy`
- `--forward-agent`
- `--notes`
- `--tag`

Required behavior:

- `host add/edit/show/list` round-trip through the canonical host model.
- `group` is not part of the reboot contract.
- Hidden connect defaults are not part of the reboot contract.

### 7.6 `connect`

`connect` is a CLI-owned SSH execution workflow.

Architecture contract:

- The app layer plans intent.
- `ConnectService.Plan` returns a typed command plan.
- `internal/ssh.CommandBuilder` is the only renderer for the SSH invocation.
- The CLI executes the local `ssh` process directly.

Behavior contract:

- `connect --dry-run` prints or emits the planned SSH command and does not emit
  connect audit events.
- `connect --print-cmd` prints a redacted command form when available.
- `connect --key <name>` uses the managed agent path from the daemon.
- `connect --identity-file <path>` uses the local identity file path directly.
- `connect` rejects simultaneous key and identity-file auth.
- `connect --ignore-ssh-config` runs `ssh -F /dev/null`.
- `connect --no-proxy-jump` disables any host default proxy jump.

Known hosts policy values:

- `strict`
- `tofu`
- `accept-new`
- `off`

Rules:

- `strict` uses `StrictHostKeyChecking=yes`.
- `tofu` and `accept-new` use `StrictHostKeyChecking=accept-new`.
- `off` requires `--insecure-hostkey`.

### 7.7 `key`

Required shipped workflows:

- `key generate`
- `key import`
- `key list`
- `key show`
- `key rotate`
- `key remove`
- `key export`
- `key agent add`
- `key agent remove`

Rules:

- Private key export requires re-auth.
- Managed-agent flows are session-scoped and daemon-mediated.

### 7.8 `secret`

Required shipped workflows:

- `secret add`
- `secret list`
- `secret show`
- `secret env`
- `secret export`
- `secret remove`

Rules:

- Secret reveal and export require re-auth where configured.
- `secret env` injects values in the CLI process before subprocess execution.
- Secrets must never appear in logs or audit details.

### 7.9 `backup`

Required shipped workflows:

- `backup create`
- `backup restore`

Rules:

- Backups are encrypted archives.
- Restore replaces vault data on disk.
- After restore, the daemon should be restarted and the restored vault unlocked
  with the source vault credentials.
- Restore authentication failures must fail cleanly.

### 7.11 `audit`

Required shipped workflows:

- `audit list`
- `audit verify`

Rules:

- Audit events form a hash chain.
- `audit verify` must detect tampering.
- Audit details must redact secrets and sensitive material.

## 8. Reuse Boundary

The reboot treats the existing codebase as infrastructure, not as truth.

Verified or expected-reuse security/runtime spine:

- `internal/crypto`
- encrypted-record handling in `internal/storage`
- rollback protection
- audit hash-chain logic
- re-auth cache and lockout handling
- daemon socket and `daemon.info` lifecycle
- backup encryption primitives
- FIDO2 / nofido2 gating

Product layers subject to reboot-level cleanup:

- host model and migrations
- app-layer request/response types
- gRPC/proto contract
- CLI help and public command surface
- onboarding flow

See [docs/reboot/PACKAGE-AUDIT.md](/Users/amanthanvi/GitRepos/heimdall/docs/reboot/PACKAGE-AUDIT.md)
for the current package-by-package disposition.

## 9. Exit Codes

The CLI uses stable semantic exit codes for common categories:

- success
- usage error
- not found
- permission / re-auth required
- unavailable
- internal error

The exact numeric mapping lives in the CLI implementation and tests.

## 10. Verification Standard

The reboot is considered truthful only if these workflows work end to end:

- `init`
- `vault unlock`
- `host add/edit/show/list`
- `connect --dry-run`
- `secret env`
- `backup create/restore`
- `audit list/verify`

Verification commands for this repo:

```bash
go test -race ./internal/crypto ./internal/storage ./internal/audit ./internal/daemon ./internal/grpc ./internal/app ./internal/cli ./cmd/heimdall
go test -race ./internal/integration -count=1 -tags integration
go test -tags nofido2 -race ./...
go vet ./...
```

## 11. Deferred Work

Deferred and future-facing items are intentionally not part of the rebooted
contract. They are tracked separately in
[docs/reboot/FUTURE-BACKLOG.md](/Users/amanthanvi/GitRepos/heimdall/docs/reboot/FUTURE-BACKLOG.md).
