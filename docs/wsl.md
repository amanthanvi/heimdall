# WSL

## Mode A

Mode A uses Windows OpenSSH from WSL where tools can call `ssh.exe`.

```sh
heimdall wsl mode-a doctor
heimdall wsl mode-a configure-git --dry-run
```

The configure command previews by default and mutates only with explicit `--yes`:

```sh
heimdall wsl mode-a configure-git --dry-run
heimdall wsl mode-a configure-git --yes
```

## Mode B

Mode B would expose a scoped Unix socket inside WSL for Linux-native tools that require `SSH_AUTH_SOCK`. This is credential delegation and must be opt-in, session-scoped, permission-checked, reversible, and fail-closed.

Heimdall supports a narrow Mode B session bridge. It does not parse SSH-agent protocol messages and does not store secrets. It relays bytes between a private Unix socket and either an upstream Unix socket or an explicit argv helper.

Example with `npiperelay.exe`:

```yaml
bridges:
  wsl-personal:
    type: wsl
    scope: session
    ttl: 30m
    command: ["npiperelay.exe", "-ei", "-s", "//./pipe/openssh-ssh-agent"]
```

Use it only for a child process:

```sh
heimdall run --context github-personal --bridge wsl-personal -- git fetch
```

Foreground bridge diagnostics:

```sh
heimdall wsl bridge doctor
heimdall wsl bridge start --bridge wsl-personal
```

`wsl bridge start` runs a foreground bridge only. For a child process with a scoped bridge socket, use `heimdall run --context <ctx> --bridge <bridge> -- <cmd>`. There is no separate `wsl bridge stop` command today; stop a foreground bridge with interrupt or let TTL expiry close it.

The runtime directory must be private. Heimdall refuses broad permissions and removes the session socket on normal shutdown or TTL expiry. It does not modify shell profiles or install a daemon.
