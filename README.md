# Heimdall

Heimdall is a local-first SSH identity control plane.

It inventories OpenSSH-compatible agents and public identities, renders a Heimdall-owned OpenSSH config fragment, diagnoses identity-routing failures, and launches scoped SSH-aware commands without storing private keys or replacing OpenSSH.

## Implemented V1 Scope

- `heimdall doctor` flagship diagnostics, passive by default.
- Strict YAML config with unknown-field rejection.
- Public key, certificate, agent, socket, platform, WSL, container, and transport inventory.
- Managed OpenSSH fragment rendering.
- Include install with dry-run behavior, backups, and rollback.
- Scoped `heimdall run` and `heimdall ssh` child environments.
- External transports through OpenSSH `ProxyCommand`/`ProxyJump`.
- Minimal TUI dashboard over the same doctor service as the CLI.

## Non-Goals

Heimdall is not a vault, SSH client, SSH agent, VPN, transport layer, enterprise PAM product, cloud sync service, MCP server, or remote inventory scanner. It never stores passphrases, OAuth tokens, refresh-hook tokens, or private key material.

## Quickstart

Create `~/.config/heimdall/config.yaml` with the identity and agent references Heimdall may use:

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
identities:
  github-personal:
    public_key_path: ~/.ssh/id_ed25519_github.pub
    private_key_path_ref: ~/.ssh/id_ed25519_github
    agent_selector: personal
```

Run:

```sh
heimdall context add github-personal --host github.com --user git --identity github-personal --agent personal --identities-only --dry-run
heimdall context add github-personal --host github.com --user git --identity github-personal --agent personal --identities-only --yes
heimdall config doctor
heimdall doctor
heimdall ssh --context github-personal github.com -T
heimdall run --context github-personal -- git ls-remote git@github.com:owner/repo.git
heimdall config install-include --dry-run
heimdall completion bash
```

`context add` and `transport add` mutate only Heimdall config, print the minimal YAML snippet they add, and refuse mutation unless `--yes` is present. Review `--dry-run` output first.

`heimdall run` and `heimdall ssh` render the managed OpenSSH fragment for the scoped child launch and do not require a global Include to be installed. `install-include` is optional for native `ssh` or Git commands run outside Heimdall; it refuses mutation unless `--yes` is present.

## Security Model

Private key paths are references only. Heimdall may `stat` a private key path for existence and permissions, but it does not read private key bytes. Inventory reads public `.pub` files and certificate files, calls `ssh-add`/`ssh-keygen`, and renders OpenSSH config.

Active host probes require `--active-probe`. Today that active probe is an `ssh -G <host>` effective-config check; it does not attempt authentication. By default, `doctor` does not contact hosts, execute transport commands, invoke ProxyCommand, or attempt authentication.

Agent sockets and agent forwarding are credential delegation. Scoped launch commands set `SSH_AUTH_SOCK` only for the child process and fail closed when the configured agent is unavailable. Before execution they atomically render the managed fragment, set `GIT_SSH_COMMAND=ssh -F <shell-escaped-fragment>` for Git-aware children, pass `-F <fragment>` to direct OpenSSH invocations, and do not rewrite `HOME` or install a global Include.

## Session Bridge

Heimdall supports a narrow session-scoped bridge. It creates a private Unix socket under a 0700 runtime directory, relays raw bytes to either an upstream Unix agent socket or an explicit argv helper such as `npiperelay.exe`, gives that socket only to the launched child process, and removes it after the child exits or the TTL expires.

Example WSL Mode B bridge through an explicit helper:

```yaml
bridges:
  wsl-personal:
    type: wsl
    scope: session
    ttl: 30m
    command: ["npiperelay.exe", "-ei", "-s", "//./pipe/openssh-ssh-agent"]
```

Run a scoped child:

```sh
heimdall run --context github-personal --bridge wsl-personal -- git fetch
```

No global bridge daemon is installed. Shell profiles are not modified. Unsupported persistent/global exposure remains out of scope.

Certificate refresh hooks preview by default:

```sh
heimdall certs refresh github
heimdall certs refresh github --execute
```

Hooks are argv arrays in config; Heimdall does not store provider tokens.

## Development

```sh
go test ./...
go run ./cmd/heimdall --help
```

CI runs formatting, vet, tests, and a build matrix.

See [docs/commands.md](docs/commands.md) for the command reference.
