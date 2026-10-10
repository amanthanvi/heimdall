# X2 T1 (rust, T1-rust-opus2): exec-equivalent job control for `heimdall-proto run`

Workspace `/tmp/x2ws-12108b4d/heimdall`, starting commit `c2d60be` ("starting point", everything as received).
Scratch and logs: `/tmp/x2ws-12108b4d/scratch/`. Changed files (see `diff.patch`): `prototypes/rust/src/runner.rs`,
`prototypes/rust/tests/cli.rs`, `prototypes/rust/tests/pty_tui.py`, `prototypes/rust/REPORT.md` (new §17).
Nothing under `docs/`, `schemas/`, `tests/g02/` or the fixtures was edited. No dependency or toolchain change.

## What changed and why (Unix `run` only; Windows path unchanged)

Starting-commit behaviour, observed with a debug build of `c2d60be` on darwin-arm64 and linux-arm64 (red runs below):
S1 hung (the launcher mirrored the child's stop onto itself and was never continued), S3 and S4 failed, S2 and S5
already behaved as required (S2 through the permitted deviation b).

1. **When a child stop is mirrored (S1).** The round-3c mirror (launcher stops its own PID with the child's stop
   signal so the shell reports the stop) now runs only in a job-control setting: the controlling terminal is on
   stdin/stdout/stderr, or its foreground process group is the launcher's or the child's. The terminal is found on
   stdio, else through `/dev/tty`, which is opened read-only (`O_NOCTTY|O_NONBLOCK`) and closed at once. That way a
   foreground job with redirected stdio is still mirrored. Without such a setting (S1: non-shell parent, no tty on
   stdio, launcher not in the terminal's foreground), the launcher leaves the stop to the child and keeps waiting.
   Plain exec's caller does the same.
2. **SIGCONT is passed on (S3).** SIGCONT is now in the caught set, unless it was inherited as ignored (K6a). Catching
   it does not suppress the continue action. While the child is known to be stopped, the forwarder sends SIGCONT to
   the child, so a continue that reaches only the launcher also reaches the child, as it would under plain exec. A
   resumed child that reads the terminal in the background is then stopped by SIGTTIN, which goes to the whole group,
   so the shell lists the job stopped.
3. **Terminal hand-back for a nested shell (S4).** At a child stop, the launcher records whether the child's own
   process group held the terminal. A nested `bash -i` takes the terminal for its own group. On the outer `fg`, the
   shell gives the terminal to the launcher's group and continues only that group. The launcher then hands the
   terminal back to the child's group (`tcsetpgrp`, called only while its own group holds the foreground) and
   continues that group. The nested shell answers again, and `exit 3` gives the outer shell `$?` = 3.
4. **Stale-stop grace (round 3c, Q18).** The 200 ms grace now restarts whenever the launcher itself receives SIGCONT
   during it, and the stop is re-checked just before the launcher stops itself. Time the launcher spends stopped
   (group Ctrl-Z, group SIGTTIN) therefore no longer counts towards the grace.
5. Shared state: a mutex-protected `JobState` (`exited`, `child_stopped`, `restore_fg`, `conts`) is used by the wait
   loop and the forwarder. The child is still signalled only under the lock with `exited == false`, so no signal goes
   to a recycled PID. The child is still reaped only after forwarding is disarmed. Still no `setpgid`. The launcher
   still stops only its own PID (K6a). K16 still holds: no program is executed.

## Tests added (the prototype's own frameworks)

- `tests/cli.rs` `x2_s1_third_party_stop_cont_without_terminal`: S1 against a plain-exec control, for SIGSTOP and
  SIGTSTP. The job runs in its own non-orphaned process group with no tty on stdio. Checks: exit 7 within 6 s of
  the SIGCONT, child reaped.
- `tests/pty_tui.py` cases `x2-s2-third-party-stop-cont-interactive`, `x2-s3-self-stop-then-cont-launcher-only`,
  `x2-s4-nested-shell-suspend-fg`, `x2-s5-sigstop-with-meta-file` and `x2-redirected-stdio-foreground-self-stop`.
  Each runs a plain-exec control and then heimdall-proto in the same `bash --norc --noprofile -i` session and in
  the same `zsh -f -i` session. It compares stop notice, `$?`, `jobs`, whether typed input reaches the child,
  process states and leftovers (S5 also checks the meta file). `Shell` gained an `argv` parameter.

## Results (real exit codes; the final artifacts unless noted)

| Step | Command (abridged) | Exit | Result |
|---|---|---|---|
| fmt | `cargo fmt --check` | 0 | clean |
| clippy host | `cargo clippy --locked --all-targets -- -D warnings` | 0 | clean |
| clippy windows | `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings` | 0 | clean |
| host unit + integration tests | `cargo test --locked -- --test-threads=4` (darwin-arm64) | 0 | lib 49, bin 4, cli 29 passed |
| build | `prototypes/rust/build.sh` | 0 | all 4 targets built: darwin-arm64, linux-x64, linux-arm64, windows-x64 |
| darwin dist CLI tests | cli test binary with `HEIMDALL_PROTO_BIN=dist/darwin-arm64/heimdall-proto` under `env -i` | 0 | 29 passed |
| darwin dist pty suite | `python3 tests/pty_tui.py dist/darwin-arm64/heimdall-proto --panic-binary …` | 0 | 32 cases; all X2 cases pass for bash and zsh; 1 pre-existing known limitation (`run-terminal-sigint-not-doubled`, darwin) |
| linux-arm64 native tests | `tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64` (debian bookworm-slim, `--network none`) | 0 | lib 49, bin 4, cli 29 passed (1 ignored: the separate nproc test) |
| linux-arm64 pty suite | `HP_LINUX_PTY_IMAGE=heimdall-g02-harness:d0c8e448a3a7 tools/linux_pty.sh arm64 dist/linux-arm64/heimdall-proto …` (the harness image, which has zsh) | 0 | 32/32 pass, X2 cases for bash 5.2 and zsh 5.9 |
| **G02 harness 2.4.2, darwin** | `tests/g02/.venv/bin/python tests/g02/conformance.py --bin dist/darwin-arm64/heimdall-proto --candidate rust --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` | **0** | **139/139**, status `verified`, verdict `pass`, digest `02f0baa7…` |
| **G02 harness 2.4.2, linux-arm64** | `sh tests/g02/linux/run.sh --artifact-dir dist/linux-arm64 --candidate rust --out scratch/harness-linux.json --artifacts-out scratch/harness-linux` | **0** | **139/139**, status `verified`, verdict `pass`, digest `36986c35…` |

Repeat runs of the X2 pty cases on the previous build, which differed from the final one only in comment lines:
darwin x3 and Linux x2, all exit 0. A first run of the X2 cases in the Linux image exposed a race in my own S2
test, not in the product: the child's "done" file is written just before it exits. The test now waits for the
exit itself. All later runs passed.

Red proofs, from a build of the starting commit (darwin debug build; linux-arm64 musl debug build of `c2d60be`):
- `x2_s1_…`: darwin exit 101, Linux exit 101 ("no exit within 6 s of SIGCONT").
- pty X2 cases: darwin exit 1 and Linux exit 1. S3 failed with "child did not resume (child T, parent S)". S4
  failed with "nested shell did not answer after fg". S2, S5 and the redirected case passed on the old build too.

Harness runs on an intermediate build (before the `/dev/tty` refinement and the comment edits) were also 139/139 on
both platforms. They are kept in `scratch/interim/` and `scratch/prev-run/` and are informational only.

## Known gaps and deviations

- **S2 uses deviation (b)** (permitted): after the launcher stops itself to report a stop, a third party continuing
  only the child is invisible to it. The job stays listed stopped until `fg`, and `fg` ends it with the child's
  status (7 in the test).
- **Redirected background job:** a background job whose stdio has no terminal is indistinguishable from S1. A child
  stop there is no longer mirrored, so the shell lists the job running while its child is stopped. Before this change
  it was mirrored. Foreground jobs with redirected stdio are still mirrored (covered by the
  `x2-redirected-stdio-foreground-self-stop` case).
- After a group `fg`/`bg` the child receives SIGCONT twice: once from the group, once passed on. The continue is
  idempotent, but a child SIGCONT handler runs twice.
- An inherited ignored SIGCONT is left untouched (K6a), and then the S3/S4 pass-on is disabled.
- The stale-stop race is narrowed but not removed: the launcher can still be stopped and continued between the final
  re-check and its own `kill`.
- Unchanged and still recorded under §9.4: an explicit SIGTSTP or SIGSTOP sent to the launcher PID stops only the
  launcher.
- Windows: compile-checked only (clippy and the `build.sh` windows-x64 build). No behaviour change, no native run.
- `selftest.sh` was not extended with the X2 steps. The steps were run individually, as listed above.
- No independent adversarial review was run. Everything above is the implementer's own verification.
