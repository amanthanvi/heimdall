# G03 WSL probe harness

Executable probes for WSL Mode A (Windows `ssh.exe` from WSL, acceptance A12) and Mode B (Linux-native
scoped endpoint, A13), plan.md §3 G03, spec §8.4. Design, sources, and pass/fail criteria:
`docs/research/g03-windows-wsl.md`. Bash + Python 3 stdlib + OpenSSH tools; no dependency on the
(unselected) production language.

**First run in WSL: 2026-10-06** (`run_g03_wsl_probes.sh` only; owner's Windows 11 PC, WSL 3.0.1,
Ubuntu 24.04; research doc §0.2). Harness fixes from that run are in `CHANGELOG-native.md`.
`run_g03_wsl_lifecycle.sh` has still never run (no disposable second distribution, no terminate rights).
Outside WSL every probe is recorded `blocked`. The Mode B mechanics were also self-tested on macOS with
`selftest_unix.sh` (records labeled `G03-harness-selftest-unix-*`, which are not G03 evidence).

## Files

| File | Role |
|---|---|
| `run_g03_wsl_probes.sh` | In-distribution probes: `env`, `a-exec`, `a-io`, `a-quoting`, `a-git`, `a-cert`, `a-elevation`, `b-perms`, `b-unauthorized`, `b-relay`, `b-deletion`, `b-stale`, `b-teardown`, `b-lock`. |
| `run_g03_wsl_lifecycle.sh` | Controller-distribution probes against a disposable target distribution: `multi` (multi-distribution and Windows exposure), `restart`, `idle`. |
| `agent_proxy.py` | Mode B prototype endpoint: filtering, instrumented agent proxy (peer-UID check, key allowlist, mutation/extension refusal, size/idle/concurrency bounds, deadline, live/stale/replacement-safe lifecycle). Upstream: fixture `ssh-agent` socket or a per-connection command such as `powershell.exe PipeStdioRelay.ps1`. Measurement tool, not the Heimdall bridge. |
| `agent_client.py` | Minimal agent client for crafted requests (list, sign for a given key, raw types, oversize frame, banner). |
| `exposure_listener.py` | Inert banner listener (Unix path, abstract namespace, 127.0.0.1 TCP) for reachability measurements; never speaks the agent protocol. |
| `argv_fidelity.py` | Runs the shared quoting cases through an SSH client with an exact argv and compares remote output byte-for-byte. |
| `evidence.py` | Evidence record writer (tests/evidence/record.schema.json) and observation helpers; redacts user/host names. |
| `g03_common.sh` | Shared shell helpers (owned-process tracking, case files, fixtures, Windows interop helpers). |
| `selftest_unix.sh` | Harness self-test of the Mode B mechanics on any Unix host. |

## Safety model (defaults)

- `SSH_AUTH_SOCK` is unset at start. Linux tools only ever see a fixture socket in an explicit, scoped
  environment. Linux `ssh` is not used against your configuration; Windows `ssh.exe` always gets
  `-F <fixture config>`, `IdentityFile=none`, fixture known_hosts, an explicit
  `IdentityAgent //./pipe/<fixture pipe>` from the manifest (or the WSLENV-propagated form), and an
  explicit Windows-side `SSH_AUTH_SOCK` = the manifest's decoy pipe (else a non-existent sentinel pipe)
  passed through `WSLENV=SSH_AUTH_SOCK/w` (`/w` = "only be included when running Win32 from WSL",
  WSL filesystems.md, G03-S15), so it never starts with the system default pipe. Before the first
  `ssh.exe` run, `cmd.exe` must echo exactly that value back through the same WSLENV entry; if it does
  not, every Mode A probe is `blocked` instead of running `ssh.exe` with an unset Windows-side
  `SSH_AUTH_SOCK`. The ssh row that leaves the `IdentityAgent $VAR` variable unset runs only while
  `\\.\pipe\openssh-ssh-agent` does not exist (passive name enumeration).
- Owner state read: the WSL networking mode. `wslinfo --networking-mode` is used when present; only
  without it is the `[wsl2] networkingMode` key of the owner's `%USERPROFILE%\.wslconfig` read. Only a
  known mode word (`none`, `nat`, `bridged`, `mirrored`, `consomme`, `virtioproxy`) is recorded; any other
  value, the profile path and the rest of the file are not.
- Python runs with `PYTHONDONTWRITEBYTECODE=1` (set by `g03_init`), so no `__pycache__` is written.
- Disposable keys only: per-run ed25519 keys in a 0700 scratch directory (deleted on exit) loaded into a
  harness-started `/usr/bin/ssh-agent`; the Windows side uses the instrumented agent's in-memory keys.
- `HOME` points into scratch for Linux `ssh-add`/`ssh-keygen` and Git; Git also runs with an empty global
  config and `GIT_CONFIG_NOSYSTEM=1`.
- Only harness-started processes are stopped, by PID plus recorded start time; a PID without a recorded
  start time is never signalled (also inside the lifecycle target's stop script).
- Listeners: Unix sockets in private directories; the exposure probe's inert listeners bind 127.0.0.1 or
  the abstract namespace / `/mnt/wsl` inside a disposable target distribution only, for at most 300 s.
- Disruptive actions are gated: `run_g03_wsl_lifecycle.sh --allow-terminate-target` is required before
  `wsl.exe --terminate <target>`; use a disposable target distribution.
- The lifecycle keepalive session is started as `wsl.exe` itself (`exec`, so the controller tracks the
  interop process, not a wrapping subshell) and its target-side `sleep` records its PID and start token;
  it is stopped inside the target only when PID, start token and process name all match, then on the
  controller side through the owned-PID check (also on exit).
- Optional inputs that carry authority are fixture-only: `--ca-key` must be the disposable M00-T03 user CA.

## Preconditions

A WSL2 distribution with interop on a native Windows 11 x86-64 host; `python3`, OpenSSH client tools,
git; for Mode A and the relay probe: the Windows instrumented agent running
(`Invoke-G03WindowsProbes.ps1 -ServeAgentForWsl`, pass its manifest with `--win-manifest`) and a
disposable SSH fixture reachable **from Windows** (`--ssh-host/--ssh-port/--ssh-user/--known-hosts`), with
manifest key 1 (`public_key_dir\probe-key-1.pub`) authorized on the fixture account for the I/O, quoting,
and Git probes; a second disposable distribution for `run_g03_wsl_lifecycle.sh`; optionally a second Linux
account usable through `sudo -n -u` (`--other-linux-user`).

## Running

```bash
# Inside the WSL distribution under test (repository visible, e.g. under /mnt/c):
tests/native/wsl/run_g03_wsl_probes.sh \
  --win-manifest "$(wslpath -u 'C:\...\runs\<run-id>\wsl-agent-manifest.json')" \
  --ssh-host 127.0.0.1 --ssh-port <port> --ssh-user enroll --known-hosts /path/to/fixture/known_hosts \
  --git-url ssh://enroll@127.0.0.1:<port>/srv/git/probe.git \
  --other-linux-user g03other --no-uac-observed

# Host lock (operator locks Windows during the window):
tests/native/wsl/run_g03_wsl_probes.sh --probes b-lock --lock-window-minutes 6

# From a controller distribution, against a disposable target distribution:
tests/native/wsl/run_g03_wsl_lifecycle.sh --target-distro g03-target --allow-terminate-target

# Harness self-test on any Unix host (not G03 evidence):
tests/native/wsl/selftest_unix.sh
```

Output: `tests/evidence/artifacts/g03/runs/<run-id>/` (`records/`, `artifacts/<case>/`,
`artifacts/proxy-logs/`). Promote records over the `blocked` placeholders in `tests/evidence/` in the
integrating commit. Status convention as in `tests/native/windows/README.md` (gate-probe convention in
`tests/evidence/README.md`); self-test records carry no requirement IDs.

## Known limits

Executed in WSL on 2026-10-06 (`CHANGELOG-native.md`): interop argv conversion (17 cases exact), Linux,
`\\wsl.localhost` UNC and Windows spaced/Unicode `-F` paths, WSLENV `/w` propagation and the decoy gate,
Windows process counting (relay command-line count, `ssh` image count), `wslinfo --networking-mode`
(prints `nat`), interop child token, the Mode B proxy mechanics and the PowerShell relay. Windows tools are
found through the PATH extension of fix 1 when the session PATH lacks them.

Still unexecuted: the `.wslconfig` fallback for the networking mode (wslinfo was present), the
other-Linux-user rows (`--other-linux-user`), the host-lock window (operator), and everything in
`run_g03_wsl_lifecycle.sh`: keepalive start/stop through interop (whether ending the Windows-side
`wsl.exe` ends the target session is [U]), multi-distribution staging (assumes the default `/mnt`
automount root), `wsl.exe` argument forwarding to the target, and `--terminate` handling. Expect harness
fixes when those run.
