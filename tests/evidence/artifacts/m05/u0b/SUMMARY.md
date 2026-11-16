# U0b spike — how long do ssh / Git wait for the agent's identities answer?

Wave 0, ADR-0011 §10 item 4. Measurement only: no repository file touched; everything ran against disposable keys,
a disposable `ssh-agent`, and a loopback-only sshd under a scratch dir (deleted afterwards; exact PIDs stopped).

| | macOS (this machine) | Linux (devbox) | Windows 11 (the owner's PC) |
|---|---|---|---|
| Client | `OpenSSH_10.5p1, LibreSSL 3.3.6` (`/usr/bin/ssh`) | `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13` | `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` (in-box `ssh.exe`) |
| Git | `git version 2.54.0 (Apple Git-157)` | `git version 2.43.0` | `git version 2.55.0.windows.3` |
| OS | Darwin 27.2.0 arm64 | Linux 6.8.0-147-generic x86_64 | Microsoft Windows NT 10.0.26300.0, Windows PowerShell 5.1 |
| Server LoginGraceTime (effective, from `sshd -T`) | 120 and 0 (two sshds) | 120 and 0 (two sshds) | n/a: a fake agent answering zero identities (login fails by design) |
| **Max delay that still succeeded, ssh** | **65 s** (D=0…30, 65 all exit 0, real login) | **≥ 30 s**, the longest tested (D=0…30: identities answer received every time, elapsed D + 0.10–0.19 s) |
| **Max delay that still succeeded, Git (`ls-remote`)** | **65 s** (all exit 0) | **≥ 30 s** (same) |
| Failure point | D=125, grace 120: ssh exit 255 / git exit 128, elapsed 125.03 s / 125.05 s | none up to 30 s (exit 255 / 128 every run: zero identities, by design) |
| Who enforced it | **server** `LoginGraceTime` (client has no agent timeout up to 65 s, see below) | no timeout observed |
| Agent requests carrying cwd / repo context | **none** (52 messages, 0 hits) | **none** (28 messages, 0 hits) |
| session-bind order | `27 session-bind@openssh.com` → `11 REQUEST_IDENTITIES` → `13 SIGN_REQUEST`, one agent connection | `27 session-bind@openssh.com` → `11 REQUEST_IDENTITIES`, one agent connection, two messages per run |

Per-run detail (every D, both clients, every message) is in `results-macos.json`, `results-linux.json` and
`results-windows.json`.
Run elapsed ≈ D + 0.05 s (macOS) / D + 0.2 s (Linux) for every successful run (D = 0, 0.5, 1, 2, 5, 10, 30 on a
grace-120 sshd, 65 on a grace-0 sshd), so ssh and Git waited for the full delayed answer each time.

## Observed

- **Delay tolerance.** ssh and Git (over ssh) completed a real publickey login after identities answers delayed
  0, 0.5, 1, 2, 5, 10, 30 s (LoginGraceTime 120) and 65 s (LoginGraceTime 0, unlimited), on both platforms.
  No client timed out on the agent. 2 s is well inside what both in-box clients tolerate.
- **Failure at D=125, LoginGraceTime 120.** Both clients failed (`Connection closed by 127.0.0.1`), no SIGN_REQUEST sent.
  The elapsed time equals D (125 s), not 120 s: the client was blocked reading the agent and only noticed the
  server's closed socket once the delayed answer arrived. The proxy never saw the client hang up mid-delay
  (`client_closed_during_delay: false`). The server bound was measured directly with a raw TCP connection that never
  authenticates: sshd closed it after **120.007 s (Linux)** and **122.43 s (macOS)**; the macOS sshd log also has
  3 `Timeout before authentication` lines (ssh, git, probe). The Linux sshd log (`-e`, default level) had no such line,
  so on Linux the 120 s is shown by the raw probe only.
- **No cwd / repo context.** Every client ran with cwd inside a Git working repository named
  `HM-SPIKE-CWD-<16 hex>`. Across 52 agent messages per platform (18 REQUEST_IDENTITIES of 1 byte, 18 session-bind
  of 208 B macOS / 240 B Linux, 16 SIGN_REQUEST of 298 B macOS / 327 B Linux) none contained the canary, the cwd
  path, the repository name, the remote repository name, or the scratch root. Only types 11, 27
  (`session-bind@openssh.com`) and 13 were ever sent; no other extension.
- **session-bind ordering.** In all 18 runs per platform (ssh and git alike) the first agent message on the
  connection was `session-bind@openssh.com` (answered immediately by the real agent; the log line is
  "bound agent to hostkey"), **then** REQUEST_IDENTITIES, then SIGN_REQUEST. The bind is sent in every case
  and precedes the identities request, so a proxy sees it before it must decide how long to delay the identities answer.

## Inference / not measured

- Whether a client agent timeout exists somewhere above 65 s is **not determined** (D=125 was ended by the server first).
  The only claim supported is: no client agent timeout up to 65 s on OpenSSH 10.5p1 and 9.6p1.
- The session-bind payload (host key, session id, signature, forwarding flag) is known from the protocol, not decoded here.
- **Windows (added 2026-11-15, the owner's PC; run by the orchestrator's PC agent).** `windows-agent-wait-spike.ps1`
  under Windows PowerShell 5.1, in-box `ssh.exe` (OpenSSH_for_Windows 9.5p2) and Git 2.55.0.windows.3, against a
  scratch sshd in WSL reached at `127.0.0.1`. The script's fake agent answers REQUEST_IDENTITIES with zero identities
  after D, so every login fails by design (ssh exit 255, git exit 128); the measured facts are `answer_received` and
  `elapsed_s`. At every D (0, 0.5, 1, 2, 5, 10, 30 s) both clients received the answer and took D + 0.10–0.19 s, with no
  timeout. Every run sent exactly two agent messages, `session-bind@openssh.com` (27) first, then REQUEST_IDENTITIES
  (11); none of the 28 carried the working directory or the canary. Results: `results-windows.json`,
  `results-windows-summary.txt`.
- **The first Windows run measured nothing** (`results-windows-backslash-run.json`: zero agent messages at every D,
  `answer_received: unknown`). OpenSSH_for_Windows 9.5p2 drops one backslash from `-o IdentityAgent=\\.\pipe\…`
  (`ssh -G` shows `\.\pipe\…`), so ssh never reached the fake agent. The re-run used `//./pipe/<name>`, which `ssh -G`
  parses unchanged; the script in `tests/native/m05/u0b/` now does the same (it is also the path Git's
  `core.sshCommand` gets). Heimdall's own rendering already writes `//./pipe/…` (`heimdall_sshconf::render::RenderPath::pipe`).
- The Windows results are redacted copies: the PC account name, the fixture account name and the PC name are replaced
  by `<user>`, `<fixture-user>` and `<pc>`, and line endings are LF. The unredacted originals stay on the PC.

## Method notes and deviations from the task text

- Client command: `ssh -F /dev/null -o IdentityAgent=<proxy> -o BatchMode=yes -o PreferredAuthentications=publickey
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<scratch>` plus `-vvv`, `-o GlobalKnownHostsFile=/dev/null` and
  an explicit nonexistent `-o IdentityFile=...` (so default `~/.ssh` keys are never probed). Git used the same
  options in `GIT_SSH_COMMAND` (`GIT_CONFIG_GLOBAL=/dev/null`).
- Runs executed up to 6 in parallel (each with its own proxy socket, all sharing one disposable agent and sshd;
  `MaxStartups 100:30:200`; `PerSourcePenalties no` on the macOS sshd, which supports it). Elapsed times are per run.
- The proxy forwards the type-11 request immediately and holds only the answer, so the delay is D measured from the request.
- sshd: `/usr/sbin/sshd -D -e` as the unprivileged owner user, `ListenAddress 127.0.0.1`, random high ports, `UsePAM no`.
- Process hygiene: PIDs recorded in each results file; all confirmed gone; scratch dirs removed on both machines
  (`scratch_removed: true`); the devbox script dir deleted. The pre-existing `ssh-agent` of the owner on this Mac was
  not touched.

## Files

Scripts in `tests/native/m05/u0b/`: `spike_agent_proxy.py`, `spike_driver.py` (run: `python3 -I
spike_driver.py --platform NAME --out FILE`, from a scratch checkout of that directory),
`windows-agent-wait-spike.ps1` (run: `powershell -NoProfile -ExecutionPolicy Bypass -File
.\windows-agent-wait-spike.ps1 -Target <host> -Port <port> -User <user>`; writes
`windows-agent-wait-spike-results.json` and `-summary.txt` into the current directory).
Results here: `results-macos.json`, `results-linux.json`, `results-windows.json` (and the first Windows run,
`results-windows-backslash-run.json`), each Windows one with its `-summary.txt`. Record:
`tests/evidence/m05-g05-agent-context.json`.
