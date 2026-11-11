# M03 wave 3, round 4: worklog (untracked; integrator + F7)

Base `155d2f6c` (round 3 committed; §17.20 item 16 keeps M01's `ensure` repair). Devbox at `155d2f6c`: 14/14
binaries, 626 passed, 0 failed. Re-check 3 (`/tmp/hm-tools/hm-recheck3-m03w3-report.md`): fix first on W3-C03 only.

## Integrator
- W3-C03 (test fixture, `tests/integration/connections.rs:563-572`): F7 resumed.
- Integrator verification: `TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_connections` 3 runs → 0,
  42 passed each; after each, no new PPID-1 `ssh`, `sleep` or shell (the only PPID-1 shell, `/bin/bash` started
  Nov 4, predates this session, left alone).
- check.sh → **exit 0**, every step 0: 2587 passed, 0 failed, 188 ignored, 97 targets; native-harness-selftest 316/0.
  `linux-xcheck.sh --workspace` → 0; `clippy-windows.sh` → 0.
- After check.sh: two PPID-1 `sleep 300` (09:18:09, 09:18:12), the wave-1 `enroll_registry.rs` / M02 `selftest.sh`
  ones of round 3 (not the fixture's `sleep 40`); bounded, left to end.
- Scan of the changed file: no canary value, home path or private key.

## F7
- W3-C03 (test-only; `tests/integration/connections.rs`; product unchanged). Design: the server command's
  whole lifecycle is owned:
  - **Subtree walk:** at teardown, before the clients are killed, `descendants(sshd PID)` (the fixture
    sshd is this test's unreaped child, so its PID cannot be reused) walks `ps -A -o pid=,ppid=` (numbers
    only) by exact parent; each descendant's start token and **actual** image are read, then its parent
    is confirmed again, so a reused PID is never taken. This finds a command that never wrote its pidfile.
  - **Two-image receipts:** a server-command receipt keeps the image read at receipt time (the shell
    before its `exec`) plus `/bin/sleep` (same PID and start token after the `exec`); `stop_exact` tries
    each image with a fresh pin and the start token re-checked before and after it, and signals only a
    verified one. No assumed image: an image-wait is gone, and the read image is always kept.
  - **No silent discard:** `collect_remote` keeps an unread pidfile pending and returns whether all were
    read; `spawn_remote_sleep` and the unix_revoke test assert it (explicit failure at 20 s).
  - **Cancel marker:** teardown writes `remote.cancel` first; the command checks it before its pidfile and
    again before its `exec` (`[ -e … ] && exit 0`), so a delayed command cannot start its sleep afterwards.
    The 40 s self-termination after `exec` is kept.
  - **Audit (normal drop):** every receipt's identity is gone **and** the fixture sshd has no live
    descendant left (bounded 5 s each); the message counts commands that never wrote a pidfile.
  - Test hook: `World::remote_stall` (`Stall::{BeforePidfile, AfterPidfile}`) inserts `kill -STOP $$` on
    that side of the pidfile in the next `remote_command` (the before-stall also writes `$$` to a test probe
    file).
- Regressions: `remote_command_stalled_after_its_pidfile_leaves_no_process`,
  `remote_command_stalled_before_its_pidfile_leaves_no_process` (shared body: the shell stalls, a **normal**
  `drop(w)` must pass its own audit, then the exact identity must be gone; a survivor is stopped by its
  exact identity and actual image before the test fails).
  - Revert (round-3 behaviour: receipt with assumed `/bin/sleep`, pending discarded on the zero bound, no
    subtree walk): after-pidfile → exit 101 (drop audit "survived it: [80145]", then "the stalled shell
    survived the fixture's teardown"); before-pidfile → exit 101 ("the stalled shell survived the
    fixture's teardown"; its normal drop's audit had passed, as the reviewer saw). Both shells were stopped
    by the tests by exact identity (80145, 80192 gone). Restored byte-identical (cmp).
- Checks: `HM_U7_RECEIPTS=… TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_connections` 3 runs
  exit 0 (42 passed each), each followed by the exact-PID receipt audit: 92 identities, 0 survivors each.
  No `/bin/sleep`, shell or ssh process with PPID 1 started since 09:00 (covers the revert runs) remains;
  the only PPID-1 shell is a `/bin/bash` started Nov 4 (not mine). Host clippy `-p heimdall-runtime
  --all-targets --locked -D warnings` exit 0; Windows clippy (helper recreated from
  `tools/validation/clippy-windows.sh` with `cd "$(dirname "$0")"` and `"$@"`, deleted after)
  `-p heimdall-runtime --all-targets` exit 0; `linux-xcheck.sh -p heimdall-runtime` exit 0; rustfmt
  `--check` exit 0. Devbox note: the walk uses `/bin/ps` (procps) there.
