# T1-rust-opus1: exec-equivalent job control for `heimdall-proto run` (Rust prototype)

Workspace: `<x2ws>/heimdall` (git-initialised; starting commit `76e066c`, which also adds a
root `.gitignore` for `prototypes/*/target/` and `prototypes/*/dist/`). Diff: `diff.patch` (4 files, all under
`prototypes/rust/`). Nothing under `docs/`, `schemas/`, `tests/g02/` or `tests/fixtures/` was changed.

## What changed and why (`prototypes/rust/src/runner.rs`, Unix `run` only)

The round-3c design mirrors a child's stop onto heimdall-proto's own PID so the shell, which waits only for
heimdall-proto, reports the job stopped. Three of the five TASK.md scenarios failed against a plain-exec control
(measured on the unchanged code; see "Red" below):

1. **S1 (no job-control shell).** Mirroring left heimdall-proto stopped for ever once a third party continued
   only the child. Now a stop is mirrored only when a job-control shell can be watching: `/dev/tty` opens
   (read-only, `O_NOCTTY|O_NONBLOCK`, used only for queries and the S4 hand-back) **and** stdin, stdout or stderr
   is that terminal (`tcgetsid` equals our session) or our group is its foreground group. Otherwise the stop
   report is consumed and heimdall-proto keeps waiting; the child completes and is reaped, exit = child's status.
2. **S3 (SIGCONT to the launcher PID only).** After a mirrored stop heimdall-proto never continued the child.
   Now, when `kill(getpid(), sig)` returns (heimdall-proto was continued), it waits up to 10 ms for the
   group-wide continue that `fg`/`bg` send; if none reached the child, it sends the child SIGCONT, as the SIGCONT
   would under plain exec. The resumed child's background read is stopped by SIGTTIN, which is mirrored as
   SIGTTIN. A stop within 1 s after heimdall-proto's own SIGCONT is mirrored after 20 ms instead of the 200 ms Q18
   grace (it cannot be a stale report), so the shell does not list the job as running while the child is stopped.
3. **S4 (nested job-control shell).** The nested bash lives in its own group and held the terminal; the outer
   `fg` gave the terminal to heimdall-proto's group and continued only that group. Now, after the mirrored stop,
   if the child's group held the terminal before the stop, differs from ours, and our group holds it now,
   heimdall-proto `tcsetpgrp`s it back to the child's group and continues that group (`killpg`; `kill` when the
   child shares our group).

S2 already behaved as permitted deviation (b) and S5 already conformed; both are unchanged. Forwarding, exit
mapping, meta file, K6a (only our own PID is ever stopped), and the Windows path are unchanged. Module docs and
`prototypes/rust/REPORT.md` §17 describe the mechanism and gaps.

## Tests added (prototype's own framework)

- `tests/cli.rs::x2_s1_third_party_stop_cont_without_terminal` (SIGSTOP and SIGTSTP; no tty on stdio; own,
  non-orphaned group; asserts exit 7 within 6 s of SIGCONT, completion, child reaped).
- `tests/pty_tui.py`: `x2-s1-third-party-stop-cont-no-tty` (also run from a driver that owns a controlling tty),
  and `x2-s2/s3/s4/s5-*` for both `bash` and `zsh`. Each scenario runs first as plain exec (control; must show the
  TASK.md behaviour or the case fails with "control:"), then via heimdall-proto with the same assertions. `Shell`
  now takes the shell name; a missing zsh is reported as `blocked` (not a pass). Every X2 case kills the
  processes it started if it fails (found while running the red baseline: two stuck baseline launchers with a
  stopped nested bash were left by the first S4 version of the test; they were killed by exact PID).

## Results (all exit codes observed in this run)

| Step | Exit | Observed |
|---|---|---|
| `cargo fmt --check` | 0 | |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 | |
| `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings` | 0 | |
| `sh build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64, windows-x64 all `built: true`; notices generation failed (see gaps) |
| `cargo test --locked` (host) | 0 | lib 49, bin 4, cli 29 passed |
| dist darwin CLI tests (`HEIMDALL_PROTO_BIN`=dist, `env -i`) | 0 | 29 passed |
| `tests/pty_tui.py` darwin dist (+ panic binary) | 0 | 36 cases: 35 pass + pre-existing known limitation `run-terminal-sigint-not-doubled` |
| Linux arm64 native tests (`tools/linux_tests.sh`, harness image) | 0 | 49 + 4 + 29 passed, 1 ignored |
| Linux arm64 `linux_nproc` (ignored test, uid 10001) | 0 | 1 passed |
| `tests/pty_tui.py` Linux arm64 dist (harness image: bash 5.2, zsh 5.9) | 0 | 36/36 |
| X2 + K6e pty repeats, 3x each, darwin and Linux | 0 (x12) | all 9 X2 cases and both K6e cases pass every time |
| Harness darwin: `tests/g02/.venv/bin/python tests/g02/conformance.py --bin <darwin> --candidate rust ...` | 0 | 139/139, status verified, verdict pass; no assertion false (gating or not) |
| Harness Linux: `sh tests/g02/linux/run.sh --artifact-dir <linux-arm64> --candidate rust ...` | 0 | 139/139, verified/pass; no assertion false |

**Red (unchanged code, built in this workspace, digest darwin `f9a3ec8b…`, linux-arm64 `85e038b4…`):**
`x2_s1_…` cli test exit 101 ("SIGSTOP: heimdall-proto must exit with the child's status"); pty X2 cases
(exit 1 on both platforms): S1, S3 bash/zsh, S4 bash/zsh fail; S2 and S5 pass (S1 hp: "no exit within 8 s";
S3: child never resumed; S4: nested bash never answered after `fg`). The plain-exec controls passed every
scenario on both platforms.

Harness records: `../scratch/harness-darwin.json` (artifact `sha256:b82bd960…`), `../scratch/harness-linux.json`
(`sha256:657e9d1e…`); step logs and exit codes: `../scratch/verify/` (`steps.tsv`).

## Known gaps

- S2 uses permitted deviation (b) (the job stays listed stopped until `fg`; a stopped launcher cannot observe the
  child being continued).
- From code reading, not probed: after a terminal Ctrl-Z (no mirror), a SIGCONT to the launcher PID only
  re-stops the launcher after the 200 ms grace instead of continuing the child; an explicit SIGTSTP/SIGSTOP to
  the launcher PID still stops only the launcher (§9.4, recorded).
- The "job-control shell can be watching" decision is a terminal heuristic: a background job with all stdio
  redirected away from the terminal does not mirror its child's stop, so the shell would list it running.
- The hidden black-box timings are unknown; S3's "never listed running while stopped" was sampled every ~0.1 s
  from 0.1 s after the resume (8 samples), not continuously.
- `tools/gen_notices.py` fails offline here (`cargo metadata --offline` lacks some crate sources in the local
  cache), on the unchanged code too; build.sh still builds every target, but `dist/THIRD-PARTY-NOTICES.txt` is
  absent.
- `selftest.sh` was not run end to end (it writes repository evidence paths and needs round-* artifacts absent
  here); its pty step will now also run the X2 cases, and in its default python-slim Linux image the zsh cases
  report `blocked`.
- No independent (adversarial) review was available in this run; the review above is self-review.
