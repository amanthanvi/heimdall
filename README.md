# Heimdall

Heimdall is a local-first Go CLI for vault-backed SSH host, key, secret, and backup workflows.
Current stable release: `v0.1.3`.

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
heimdall host add --name prod --addr 10.0.0.10 --user ubuntu

# 4) Preview SSH command without executing
heimdall connect prod --dry-run

# 5) Lock vault
heimdall vault lock
```

## Shell Completions

Generate completions with the built-in Cobra completion command.

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
