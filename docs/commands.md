# Command Reference

Global flags:

- `--config <path>`: Heimdall config path.
- `--format human|json|yaml`: output format.
- `--dry-run`: preview intended changes.
- `--redaction low|default|high`: output redaction level.
- `--unsafe-full-output`: disable default redaction for local troubleshooting.
- `--yes`: confirm explicit mutations after review.

Primary commands:

- `heimdall doctor`: passive local diagnostics.
- `heimdall doctor host <host>`: host-route diagnostics; no network contact unless `--active-probe`.
- `heimdall doctor windows|wsl|container|forwarding|certs`: focused passive diagnostics.
- `heimdall identities`: configured public identity inventory.
- `heimdall agents`: configured agent inventory.
- `heimdall contexts`: context listing.
- `heimdall config doctor`: strict config validation.
- `heimdall config render [--write]`: render the Heimdall-owned OpenSSH fragment.
- `heimdall config diff`: compare current fragment to render output.
- `heimdall config install-include --dry-run|--yes`: append the managed Include line with backup support.
- `heimdall config rollback --yes <backup-path>`: restore a backup.
- `heimdall run --context <ctx> [--bridge <bridge>] -- <cmd>`: scoped child command.
- `heimdall ssh --context <ctx> [--bridge <bridge>] <host> [args...]`: scoped OpenSSH invocation.
- `heimdall wsl mode-a doctor`: WSL Mode A diagnostics.
- `heimdall wsl mode-a configure-git --dry-run|--yes`: preview or set Git `core.sshCommand=ssh.exe`.
- `heimdall wsl bridge doctor`: bridge runtime permission check.
- `heimdall wsl bridge start --bridge <name>`: foreground session bridge.
- `heimdall bridge container`: explicit container socket snippet.
- `heimdall transport add`: transport YAML snippet.
- `heimdall transport doctor`: passive transport diagnostics.
- `heimdall certs`: configured certificate inspection.
- `heimdall certs refresh <name> [--execute]`: preview or run a configured certificate refresh hook.
- `heimdall tui`: TUI dashboard over the same services.
- `heimdall completion bash|zsh|fish|powershell`: shell completions.

