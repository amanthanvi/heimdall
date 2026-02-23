# Heimdall

Heimdall is a local-first Go CLI for vault-backed SSH host, key, secret, and backup workflows.
Current stable release: `v0.1.14`.

## Quickstart

### Prerequisites

- Go 1.26+
- `libfido2` if you build with the `fido2` tag

### Build

```bash
make build
```

Binary output:

- `dist/heimdall`

## Install with Homebrew

```bash
brew tap amanthanvi/tap
brew install amanthanvi/tap/heimdall
heimdall version
```

Homebrew artifacts are built with the nofido2/static profile for portability.
If you need FIDO2/passkey features, build from source with `make build` (requires `libfido2`).
The command examples below use the installed `heimdall` binary; when running from source, replace `heimdall` with `./dist/heimdall`.

### Initialize and run a basic lifecycle

```bash
# 1) Initialize local vault + config
heimdall init --yes --passphrase "dev-pass"

# 2) Unlock vault (daemon auto-starts on demand)
heimdall vault unlock --passphrase "dev-pass"

# 3) Add host metadata
heimdall host add --name prod --address 10.0.0.10 --user ubuntu --key deploy

# 4) Preview SSH command without executing
heimdall connect prod --dry-run

# 5) Connect with vault key via managed agent
heimdall connect prod --key deploy

# 6) Lock vault
heimdall vault lock
```

### Restore backup into a target vault

```bash
# 1) Initialize + unlock target once
heimdall --config ./target-config.toml --vault ./target-vault.db init --yes --passphrase "target-pass"
heimdall --config ./target-config.toml --vault ./target-vault.db vault unlock --passphrase "target-pass"

# 2) If replacing an existing vault file, remove it first
rm -f ./target-vault.db

# 3) Restore backup payload
heimdall --config ./target-config.toml --vault ./target-vault.db backup restore --from ./vault.backup.hdl --passphrase "backup-pass"

# 4) Reopen database handle + unlock restored vault
heimdall --config ./target-config.toml --vault ./target-vault.db daemon restart
heimdall --config ./target-config.toml --vault ./target-vault.db vault unlock --passphrase "source-vault-pass"
```

Notes:
- `backup restore --overwrite` requires a recent re-authentication window.
- Restoring into an uninitialized target path can fail daemon startup.
- Restored vault unlock credentials come from the backup source vault.
- `export/import --format json` is metadata-oriented; use `backup create/restore` to move encrypted private keys and secret values.

## Shell Completions

Install completions as a first-class setup step:

```bash
heimdall completion install --shell zsh --verify
```

After upgrading Heimdall, rerun completion install with `--overwrite` to refresh shell scripts:

```bash
heimdall completion install --shell zsh --verify --overwrite
```

If completion output ever shows raw directive tokens like `:0` or `:4`, upgrade to `v0.1.14+`, rerun completion install, and restart your shell session.

You can still generate raw scripts directly with the built-in completion command.

## CLI Command Updates (Breaking)

- `host ls` → `host list`
- `host rm` → `host remove`
- `host add --addr` → `host add --address`
- `key gen` → `key generate`
- `key ls` → `key list`
- `key rm` → `key remove`
- `secret ls` → `secret list`
- `secret rm` → `secret remove`

Legacy names now return explicit usage errors with the exact replacement command.

### Bash

```bash
heimdall completion bash > "$(brew --prefix)/etc/bash_completion.d/heimdall"
```

### Zsh

```bash
mkdir -p "${HOME}/.zfunc"
heimdall completion zsh > "${HOME}/.zfunc/_heimdall"
```

### Fish

```bash
mkdir -p "${HOME}/.config/fish/completions"
heimdall completion fish > "${HOME}/.config/fish/completions/heimdall.fish"
```

## Validation Commands

```bash
go test -race ./...
go vet ./...
go test -tags=integration -race ./internal/integration -count=1
go test -run='^$' -bench='Benchmark(VaultOpenCold|CLIRoundTrip|KeyDerivation)$' -benchmem ./internal/crypto ./internal/cli
```

## Release

- GoReleaser config: `.goreleaser.yml`
- Homebrew artifacts are `tar.gz` archives named `heimdall-<os>-<arch>.tar.gz` containing the `heimdall` binary.
- Homebrew formula source of truth: `homebrew-tap/Formula/heimdall.rb`.
- Security disclosure policy: `SECURITY.md`
