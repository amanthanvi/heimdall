# Current state (M00-T01)

**Recorded:** 2026-10-02 · **Repository:** `/Users/amanthanvi/GitRepos/heimdall`
· **Base commit:** `60ace01` ("Initial commit", contains no files)

## Finding: greenfield

At inspection the working tree contained only:

| Path | State | Content |
|---|---|---|
| `spec.md` | untracked | Product/technical specification v0.1.0 (1,436 lines) |
| `plan.md` | untracked | Implementation/validation plan v0.1.0 (874 lines) |
| `CLAUDE.md` | untracked | Empty (0 bytes); now holds agent working rules |

There is no prior implementation, prototype, dependency manifest, CI
configuration, or test suite. **Nothing is being salvaged or continued.** No
other local directory or similarly named repository is assumed to be Heimdall
(plan.md §1.1).

## Development host observed

Observed by running the tools on 2026-10-02 (not a support claim):

| Item | Observed |
|---|---|
| OS / arch | macOS 27.0 (build 26A428), arm64 |
| OpenSSH client | `OpenSSH_10.3p1, LibreSSL 3.3.6` (`/usr/bin/ssh`) |
| Go | go1.27.1 darwin/arm64 |
| Rust | rustc 1.98.1, cargo 1.98.1 |
| Bun / Node / Deno | 1.4.2 / v24.18.0 / 2.9.7 |
| Python | 3.14.7 |
| SQLite CLI | 3.54.0 |
| Container runtime | Docker Desktop installed; daemon was not running at inspection |

## Platforms not available to this environment

Native Windows x86-64, WSL2, Linux desktop/user-session hosts, and macOS lock or
logout cycles driven by a human are not available to the agents. Gate probes
needing them are `blocked` with the exact missing platform, never simulated
(plan.md §6.5). Linux checks that run in local containers are labeled as
container results, not Linux desktop evidence.
