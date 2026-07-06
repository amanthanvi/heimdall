# Command Reference

Global flags:

- `--config <path>`: Heimdall config path.
- `--format human|json|yaml`: output format.
- `--json`: alias for `--format json`; cannot be combined with `--format` values other than `json`.
- `--dry-run`: preview intended changes.
- `--verbose`: verbose diagnostics flag; currently reserved by commands.
- `--no-color`: disable color output flag; currently reserved by commands.
- `--redaction low|default|high`: output redaction level.
- `--unsafe-full-output`: disable default redaction for local troubleshooting.
- `--yes`: confirm explicit mutations after review.

Use `--format json` or `--json` for machine-readable output. `--json --format json` is accepted; `--json --format yaml` and other conflicting combinations are rejected. The CLI does not currently provide `--show-sensitive` or `--show-public-keys` aliases.

Primary commands:

- `heimdall doctor`: passive local diagnostics.
- `heimdall doctor host <host>`: host-route diagnostics; `--active-probe` currently runs `ssh -G <host>` to compare effective OpenSSH config, without attempting authentication.
- `heimdall doctor windows|wsl|container|forwarding|certs`: focused passive diagnostics; findings are filtered to the requested area (`HD-WIN-*`; `HD-WSL-*` plus `HD-WIN-*` for WSL Mode A; `HD-CONTAINER-*`; `HD-FWD-*`; or `HD-CERT-*`).
- `heimdall doctor transport <host>`: host-route diagnostics focused on a transport route; passive unless `--active-probe` is set.
- Doctor flags: `--fragment <path>`, `--ssh-config <path>`, `--active-probe`, `--fail-on warning`, `--strict` as an alias for `--fail-on warning`, and `--redact` as an alias for shareable high-redaction output.
- `heimdall identities`: configured public identity inventory.
- `heimdall agents`: configured agent inventory.
- `heimdall contexts`: context listing.
- `heimdall context add <ctx> --host <host> [--hostname <name>] [--user <user>] [--port <port>] [--identity <identity>] [--agent <agent>] [--identities-only] [--certificate-file <path>] [--forward-agent yes|no|ask] [--proxy-jump <jump>] [--proxy-command <cmd>] [--transport <name>] --dry-run|--yes`: add a spec-style `contexts.<ctx>.routes[]` entry to Heimdall config and print the minimal YAML snippet plus render suggestion.
- `heimdall config doctor` or `heimdall config validate`: strict config validation.
- `heimdall config render [--write]`: render the Heimdall-owned OpenSSH fragment.
- `heimdall config diff`: compare current fragment to render output.
- `heimdall config install-include --dry-run|--yes`: append the managed Include line with backup support.
- `heimdall config rollback --yes <backup-path>`: restore a backup.
- Config flags: `--fragment <path>` and `--ssh-config <path>`.
- `heimdall run --context <ctx> [--bridge <bridge>] [--bridge-runtime-dir <dir>] [--fragment <path>] -- <cmd>`: scoped child command.
- `heimdall ssh --context <ctx> [--bridge <bridge>] [--bridge-runtime-dir <dir>] [--fragment <path>] <host> [args...]`: scoped OpenSSH invocation through the same launcher.
- `heimdall wsl mode-a doctor`: WSL Mode A diagnostics.
- `heimdall wsl mode-a configure-git --dry-run|--yes`: preview or set Git `core.sshCommand=ssh.exe`.
- `heimdall wsl bridge doctor`: bridge runtime permission check.
- `heimdall wsl bridge start [--bridge <name>] [--bridge-runtime-dir <dir>]`: foreground session bridge. `--bridge` may be omitted only when exactly one bridge is configured. Stop with interrupt or TTL expiry; there is no `heimdall wsl bridge stop` command today.
- `heimdall bridge container`: explicit container socket snippet.
- `heimdall transport add <name> --type proxy_command --binary <bin> [--arg <arg> ...] --dry-run|--yes`: add an external transport template to Heimdall config.
- `heimdall transport doctor`: runs the shared passive doctor engine, including configured transport findings.
- `heimdall certs`: configured certificate inspection.
- `heimdall certs refresh <name> [--context <ctx>] [--execute]`: preview or run a configured certificate refresh hook. When the certificate declares an identity, `--context` verifies that the context uses that identity.
- `heimdall tui`: TUI dashboard over the same services.
- `heimdall version`: print version information. `heimdall doctor --version` is also supported.
- `heimdall completion bash|zsh|fish|powershell`: shell completions.

Scoped launch contract:

- `--fragment <path>` defaults to the Heimdall-managed OpenSSH fragment path.
- Non-dry launches first resolve the scoped context/bridge preview, then atomically render the current Heimdall config to that fragment before starting the child.
- The child environment removes inherited `SSH_AUTH_SOCK` and `GIT_SSH_COMMAND`, then sets `SSH_AUTH_SOCK` to the selected context, matched route, or bridge socket and `GIT_SSH_COMMAND=ssh -F <shell-escaped-fragment>`.
- If the launched argv is `ssh` or `ssh.exe`, including `heimdall ssh`, Heimdall injects `-F <fragment>` into that argv unless the argv already has `-F`.
- Dry-runs do not write the fragment; they show `ssh_config_path`, final argv, env delta, bridge, and warnings.
- Scoped launches do not install or require a global `Include`, rewrite `HOME`, clear unrelated Git/SSH variables, mutate shell profiles, or replace OpenSSH.

Gaps versus current `spec.md` and `plan.md` rewrites:

- No `heimdall wsl bridge start --context <ctx> -- <cmd>` form exists; use `heimdall run --context <ctx> --bridge <bridge> -- <cmd>` for child-scoped bridge launch.
- No `heimdall wsl bridge stop` command exists; foreground bridges stop on interrupt or TTL expiry.
- No full multi-view TUI, launch preview UI, log/event view, or TUI mutation flow exists yet; the current TUI is a minimal doctor dashboard.
