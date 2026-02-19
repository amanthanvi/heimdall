# Heimdall

Heimdall is a local-first Go CLI for vault-backed SSH host, key, secret, and backup workflows.

## Quickstart

### Prerequisites

- Go 1.23+
- `libfido2` if you build with the `fido2` tag

### Build

```bash
make build
```

Binary output:

- `dist/heimdall`

### Initialize and run a basic lifecycle

```bash
# 1) Initialize local vault + config
./dist/heimdall init --yes

# 2) Unlock vault (daemon auto-starts on demand)
./dist/heimdall vault unlock --passphrase "dev-pass"

# 3) Add host metadata
./dist/heimdall host add --name prod --addr 10.0.0.10 --user ubuntu

# 4) Preview SSH command without executing
./dist/heimdall connect prod --dry-run

# 5) Lock vault
./dist/heimdall vault lock
```

## Shell Completions

Generate completions with the built-in Cobra completion command.

### Bash

```bash
./dist/heimdall completion bash > /usr/local/etc/bash_completion.d/heimdall
```

### Zsh

```bash
mkdir -p "${HOME}/.zfunc"
./dist/heimdall completion zsh > "${HOME}/.zfunc/_heimdall"
```

### Fish

```bash
mkdir -p "${HOME}/.config/fish/completions"
./dist/heimdall completion fish > "${HOME}/.config/fish/completions/heimdall.fish"
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
- Security disclosure policy: `SECURITY.md`
