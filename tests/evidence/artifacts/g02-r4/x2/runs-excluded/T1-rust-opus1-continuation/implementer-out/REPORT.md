# X2 T1 (rust, task_id T1-rust-opus1): exec-equivalent job control for `heimdall-proto run`

Workspace: `/tmp/x2ws-5c947422/heimdall`. Scratch: `/tmp/x2ws-5c947422/scratch`. Diff: `diff.patch`. It is
`git diff` from the starting commit `0a0a5f5` and excludes `prototypes/rust/target` and `prototypes/rust/dist`.

## Provenance note (read first)

The workspace was **not** fresh when this run started. It already had a git repository with a commit
`0a0a5f5 "starting point"` (dated 2026-10-06 12:58 -0400), and that commit is used as the baseline. On top of it
were **uncommitted changes** to `src/runner.rs`, `tests/cli.rs` and `tests/pty_tui.py`: an implementation of this
task plus tests, most likely from an earlier, interrupted run of this task in the same workspace. I could not
establish who wrote them.

What I did with them:

- Saved them unchanged to `scratch/prior-uncommitted.patch` (936 lines).
- Worked out the design independently: conditional stop mirror, SIGCONT pass-through to the child, and no
  `tcsetpgrp`. It matched the draft.
- Reviewed the draft, kept it, and verified it end to end (below).
- My own changes on top: `cargo fmt` of the new test, an updated module doc in `runner.rs`, a new `REPORT.md` §17
  and header line, red proofs against a baseline build, linux zsh coverage, and ad-hoc checks (S1 with a
  controlling pty present, S4 with two suspend cycles).

If the comparison needs a single-author diff from a fresh workspace, this run does not provide one.

## What changed and why (`prototypes/rust/src/runner.rs`, Unix path only)

The round-3c design mirrored every child stop onto heimdall-proto's own PID after 200 ms. That broke three cases:

- **S1:** nobody continues the stopped launcher, so it hangs forever.
- **S3:** a SIGCONT to the launcher left the child stopped while the shell showed the job running.
- **S4:** a nested `bash -i` stops its own process group, and the outer `fg` never reached it.

The changes:

1. **The mirror is now conditional** (`parent_sees_stops`). Two conditions must both hold:
   - The parent is in another process group (a job-control shell gives each job its own group).
   - heimdall-proto is attached to its session's controlling terminal: a stdio fd is that terminal, or the
     terminal's foreground group, queried via `/dev/tty` with `O_NOCTTY|O_NONBLOCK` and never read or written, is
     heimdall-proto's or the child's group.

   Otherwise heimdall-proto keeps waiting, then reaps the child and exits with its status (S1).
2. **Settle times.** The mirror waits 20 ms (`STOP_SETTLE`). It waits 200 ms (`STOP_GRACE`, the Q18 guard
   against a stale report after Ctrl-Z and `fg`) only when heimdall-proto itself was just continued.
3. **SIGCONT pass-through** (`continue_stopped_child`, in the signal thread). SIGCONT is caught; its default
   continue action is unchanged. heimdall-proto passes it on to the child's PID when all of these hold:
   - the child is known to be stopped;
   - the child has no pending continue or exit report (so no duplicate after a group `fg`/`bg`);
   - the child is not yet reaped.

   This covers S3, and S4, where bash takes the terminal back by itself; heimdall-proto never calls `tcsetpgrp`.
4. **Unchanged:**
   - K6a: only heimdall-proto's own PID is stopped, only the child's PID is continued, and the terminal is never
     taken.
   - K16: no other program is executed.
   - The Windows path.

Tests added:

- `tests/cli.rs` `s1_third_party_stop_then_child_only_continue_non_interactive`: SIGSTOP and SIGTSTP, with
  plain exec as the control.
- `tests/pty_tui.py` cases `x2-s2…`, `x2-s3…`, `x2-s4…`, `x2-s5…`. Each runs bash and zsh, with plain exec as a
  control in a fresh interactive shell. The `Shell` helper now supports zsh, `jobs`, `$?` and markers.

`prototypes/rust/REPORT.md` §17 documents the mechanism and gaps.

## Results (real exit codes)

| Step | Exit | Result |
|---|---|---|
| `cargo fmt --check` | 0 | (after `cargo fmt`; the draft test was unformatted) |
| `cargo clippy --locked --all-targets -- -D warnings` (host) | 0 | |
| same, `--target x86_64-pc-windows-gnu` | 0 | Windows path compiles |
| `cargo test --locked -- --test-threads=4` (darwin) | 0 | lib 49, bin 4, cli 29 (incl. new S1), windows 0 |
| cli test binary vs darwin dist artifact | 0 | 29 passed |
| S1 test under a controlling pty (`scratch/adhoc/with_ctty.py`) | 0 | 1 passed |
| `prototypes/rust/build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64, windows-x64 all built |
| linux-arm64 native tests (`tools/linux_tests.sh`, debian container) | 0 | 4 + 49 + 29 passed, 1 ignored (pre-existing `linux_nproc`) |
| `tests/pty_tui.py` full, darwin dist | 0 | 30 cases passed (known Darwin limitation `run-terminal-sigint-not-doubled`, pre-existing) |
| `tests/pty_tui.py` full, linux-arm64 dist (`tools/linux_pty.sh`, python image, bash only) | 0 | 30 cases passed |
| `HP_PTY_ONLY=x2-` linux-arm64 in the harness image (bash + zsh) | 0 | S2–S5 pass, both shells |
| `HP_PTY_ONLY=x2-` darwin (bash + zsh) | 0 | S2–S5 pass, both shells |
| ad-hoc S4 two suspend/fg cycles, darwin and linux-arm64, bash + zsh outer | 0 / 0 | plain and heimdall-proto identical ($? 145/147, then 3, no jobs) |
| **Harness 2.4.2 darwin**: `tests/g02/.venv/bin/python tests/g02/conformance.py --bin dist/darwin-arm64/heimdall-proto --candidate rust --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` | **0** | **139/139**, status `verified`, verdict pass |
| **Harness 2.4.2 linux-arm64**: `sh tests/g02/linux/run.sh --artifact-dir prototypes/rust/dist/linux-arm64 --candidate rust --out scratch/harness-linux.json --artifacts-out scratch/harness-linux` | **0** | **139/139**, status `verified`, verdict pass |

Red proofs, against the baseline built from commit `0a0a5f5` sources (`scratch/base`, plus `scratch/base-linux`
for linux-arm64):

- S1 cli test: exit 101 ("no exit within 8 s of SIGCONT").
- X2 pty cases, darwin: exit 1. S3 and S4 fail; S2 and S5 pass.
- X2 pty cases, linux-arm64: exit 1, the same pattern.

So for Rust, S2 (via permitted deviation b) and S5 already matched before this change. Their tests are
regression guards. S5's deviation was Go's (§9.5).

Artifacts: see `artifacts.json`. darwin-arm64 is `37ea9ee4…` (718,368 B); linux-arm64 is `930f0d14…` (827,024 B).
Both harness runs used exactly these bytes, and no rebuild happened after them.

## Known gaps

- S2 uses deviation (b): after the mirrored stop, the job stays listed as stopped until `fg`, which ends it with
  the child's status. Option (a) is impossible for a stopped launcher.
- S3 has a short window, about 20 ms plus scheduling, between the launcher's SIGCONT and the re-mirrored SIGTTIN
  stop. In that window the shell may list the job as running while the child is already stopped by its
  background read. Plain exec has none. None of the test samples saw it.
- `parent_sees_stops` is a heuristic. A job-controlling parent with no terminal link gets no mirrored stop. A
  non-shell parent in another group that shares the terminal gets one. Neither is in S1–S5.
- Recorded and unchanged (§9.4): an explicit SIGTSTP/SIGSTOP to the launcher PID stops only the launcher.
- Not re-run: the panic-variant pty case (no `--panic-binary` build) and the rest of `selftest.sh`'s historical
  red-proof steps (they need the older round artifacts, which this workspace does not have).
- No independent (second-agent) review was done. The verification above is mine.
- The host was shared with another concurrent X2 evaluation (its own docker harness run). Timing-sensitive pty
  results ran under that load and all passed.
