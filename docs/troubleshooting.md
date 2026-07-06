# Troubleshooting

Start with:

```sh
heimdall doctor
heimdall doctor host <host>
```

Useful checks:

- native `ssh` or Git outside Heimdall missing routes: run `heimdall config install-include --dry-run`;
- native `ssh` or Git outside Heimdall using stale routes: run `heimdall config render --write`;
- `heimdall run` or `heimdall ssh` scoped route issue: run the same command with `--dry-run --format json` and inspect `ssh_config_path`, `GIT_SSH_COMMAND`, final argv, and `SSH_AUTH_SOCK`;
- wrong key: verify context identity and `IdentitiesOnly yes`;
- empty agent: load the key into the selected OpenSSH-compatible agent;
- WSL mismatch: try `heimdall wsl mode-a doctor`;
- WSL native tool needs an agent: use `heimdall run --bridge <bridge> -- <cmd>` with a session bridge;
- container failure: use explicit socket snippets, never copied keys;
- transport failure: check `HD-TRANSPORT-*` findings before debugging identity.

Use `--format json` for machine-readable reports. Redaction is enabled by default.
