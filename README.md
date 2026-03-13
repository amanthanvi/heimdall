# Heimdall

Heimdall is a local-first Go CLI for a solo operator who wants one place to
manage SSH hosts, vault-backed keys, secrets, backups, and a
tamper-evident local audit log.

The authoritative product contract is
[SPEC.md](/Users/amanthanvi/GitRepos/heimdall/SPEC.md).
Historical planning material in `claude-*` and `docs/v2/*` is not the current
product truth.

## Reboot Scope

Shipped top-level commands:

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

Deferred public surfaces:

- `tui`
- `import`
- `export`
- `ssh-config`
- `templates`
- compliance / reporting
- repair / salvage

See
[docs/reboot/FUTURE-BACKLOG.md](/Users/amanthanvi/GitRepos/heimdall/docs/reboot/FUTURE-BACKLOG.md)
for the deferred list and
[docs/reboot/PACKAGE-AUDIT.md](/Users/amanthanvi/GitRepos/heimdall/docs/reboot/PACKAGE-AUDIT.md)
for package disposition.

## Build

Prerequisites:

- Go 1.26+
- `libfido2` if building with FIDO2 support

Build the CLI:

```bash
make build
```

Output:

- `dist/heimdall`

## Quickstart

```bash
# 1) Initialize the local vault and config
heimdall init --yes --passphrase "dev-pass"

# 2) Unlock the vault
heimdall vault unlock --passphrase "dev-pass"

# 3) Create a managed SSH key
heimdall key generate --name deploy

# 4) Add a host with typed connection defaults
heimdall host add \
  --name prod \
  --address 10.0.0.10 \
  --user ubuntu \
  --key deploy \
  --proxy-jump bastion \
  --known-hosts-policy accept-new

# 5) Preview the SSH command without connecting
heimdall connect prod --dry-run

# 6) Inject a secret into a subprocess environment
heimdall secret env api_token --env-var API_TOKEN -- sh -c 'test -n "$API_TOKEN"'

# 7) Verify the audit chain
heimdall audit verify

# 8) Create an encrypted backup
heimdall backup create --output ./vault.backup.hdl --passphrase "backup-pass"
```

## Host Defaults

The rebooted host model stores connection defaults only as typed fields.

Current typed host defaults:

- `--key`
- `--identity-file`
- `--proxy-jump`
- `--known-hosts-policy`
- `--forward-agent`
- `--notes`
- `--tag`

Use `heimdall --json host show <name>` to inspect the persisted host record.

## Connect Behavior

`heimdall connect` is CLI-owned. The daemon plans the SSH command, and the CLI
spawns `ssh` locally.

Examples:

```bash
# Managed vault key
heimdall connect prod --key deploy

# Local identity file
heimdall connect prod --identity-file ~/.ssh/id_ed25519

# Ignore user ssh_config entirely
heimdall connect prod --ignore-ssh-config

# Disable any host default proxy jump
heimdall connect prod --no-proxy-jump
```

`--dry-run` prints the planned command and does not emit connect audit events.

## Backup Restore

```bash
heimdall --config ./target-config.toml --vault ./target-vault.db init --yes --passphrase "target-pass"
heimdall --config ./target-config.toml --vault ./target-vault.db vault unlock --passphrase "target-pass"
rm -f ./target-vault.db
heimdall --config ./target-config.toml --vault ./target-vault.db backup restore --from ./vault.backup.hdl --passphrase "backup-pass"
heimdall --config ./target-config.toml --vault ./target-vault.db daemon restart
heimdall --config ./target-config.toml --vault ./target-vault.db vault unlock --passphrase "source-vault-pass"
```

Rules:

- Backups are encrypted.
- Restore replaces the on-disk vault.
- After restore, restart the daemon and unlock with the source vault
  credentials from the backup.

## Validation

```bash
go test -race ./internal/crypto ./internal/storage ./internal/audit ./internal/daemon ./internal/grpc ./internal/app ./internal/cli ./cmd/heimdall
go test -race ./internal/integration -count=1 -tags integration
go test -tags nofido2 -race ./...
go vet ./...
```

## Release and Security

- Release runbook: `docs/RELEASING.md`
- Security disclosure policy: `SECURITY.md`
