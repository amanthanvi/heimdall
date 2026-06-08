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
- `heimdall doctor windows|wsl|container|forwarding|certs`: focused passive diagnostics; findings are filtered to the requested area (`HD-WIN-*`; `HD-WSL-*` plus `HD-WIN-*` for WSL Mode A; `HD-CONTAINER-*`; `HD-FWD-*`; or `HD-CERT-*`).
- `heimdall identities`: configured public identity inventory.
- `heimdall agents`: configured agent inventory.
- `heimdall contexts`: context listing.
- `heimdall context add <ctx> --host <host> [--hostname <name>] [--user <user>] [--port <port>] [--identity <identity>] [--agent <agent>] [--identities-only] [--certificate-file <path>] [--forward-agent yes|no|ask] [--proxy-jump <jump>] [--proxy-command <cmd>] [--transport <name>] --dry-run|--yes`: add a spec-style `contexts.<ctx>.routes[]` entry to Heimdall config and print the minimal YAML snippet plus render suggestion.
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
- `heimdall transport add <name> --type proxy_command --binary <bin> [--arg <arg> ...] --dry-run|--yes`: add an external transport template to Heimdall config.
- `heimdall transport doctor`: passive transport diagnostics.
- `heimdall certs`: configured certificate inspection.
- `heimdall certs refresh <name> [--execute]`: preview or run a configured certificate refresh hook.
- `heimdall tui`: TUI dashboard over the same services.
- `heimdall completion bash|zsh|fish|powershell`: shell completions.

