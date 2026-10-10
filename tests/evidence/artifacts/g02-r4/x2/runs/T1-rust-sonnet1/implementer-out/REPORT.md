# T1-rust-sonnet1: exec-equivalent job control for `heimdall-proto run`

## What changed and why
Only `prototypes/rust/src/runner.rs` (Unix `run`), tests (`tests/cli.rs`, `tests/pty_tui.py`) and a REPORT.md section 16 were touched. No Cargo/dependency change. Windows code unchanged.

Root causes found by driving real interactive bash/zsh under a pty (darwin and the linux-arm64 harness container) against plain exec:
- S1: the round-3c stop mirror stopped the launcher whenever the child was stopped, also when no job-control shell is involved; nobody ever continues the launcher, so it hung (reproduced: exit never came, 8 s timeout).
- S3 and S4: after the mirrored stop the launcher was continued (SIGCONT to the launcher PID only, or `fg` of an outer shell whose SIGCONT does not reach a nested shell that leads its own process group after `suspend`), but the child stayed stopped (reproduced: nested shell never answered after `fg`; S3 child never resumed).
- S2 and S5 already behaved as required in my runs (S2 via permitted deviation (b)); they are now covered by tests.

Changes in `runner.rs`:
1. Mirror a child stop only inside a job-control job: process group is the foreground group of the controlling terminal (`/dev/tty` + `tcgetpgrp`, std `File` and rustix, no new unsafe, no new feature) and parent is in another process group. Sampled at start, on continue reports and during the grace; sticky once seen (needed for the second stop after a background resume, which zsh sees as running after SIGCONT).
2. After a mirrored stop, when the launcher is continued and no child continue report appears within 30 ms, send SIGCONT to the child (S3, S4).
3. A stop report after the launcher's own SIGCONT is fresh, so mirrored without grace (shortens the window in which zsh lists the job as running).
4. Stop grace 200 ms -> 100 ms (margin versus the 0.5 s stop/continue gap).

## Tests (real exit codes)
- `cargo fmt --check`: 0. `cargo clippy --locked --all-targets -- -D warnings`: 0; same with `--target x86_64-pc-windows-gnu`: 0.
- `cargo test --locked` (HEIMDALL_G02_FIXTURES set): 0. lib 49, bin 4, cli 29 (includes new `x2_s1_third_party_stop_then_cont_child_only_without_terminal`, SIGSTOP and SIGTSTP) all pass. Red proof: against the pre-change binary that test fails (launcher still running 6 s after SIGCONT).
- `tests/pty_tui.py` new cases `x2-s2/s3/s4/s5`, each under bash and zsh: pass on darwin (4 runs) and in the linux-arm64 container. Red proof against the pre-change binary: `x2-s3` and `x2-s4` fail, `x2-s2` and `x2-s5` pass. Existing `k6e-*` cases pass on both platforms (3 repeats on darwin). Full `pty_tui.py` on darwin: all pass except the pre-existing known limitation `run-terminal-sigint-not-doubled` (Darwin double SIGINT) which the suite reports as a known limitation.
- Shared harness 2.4.2, darwin-arm64 (`conformance.py --bin dist/darwin-arm64/heimdall-proto`): exit 0, 139/139 pass (`/tmp/x2ws-21a86e03/scratch/harness-darwin.json`).
- Shared harness, linux-arm64 (`tests/g02/linux/run.sh --artifact-dir dist/linux-arm64`): exit 0, 139/139 pass (`/tmp/x2ws-21a86e03/scratch/harness-linux.json`).
- `build.sh`: exit 0, all four targets built (darwin-arm64, linux-x64, linux-arm64, windows-x64).

My own side-by-side driver (scratch/t/drv.py: plain exec vs launcher; S1 to S5; bash 3.2 and zsh 5.9 on darwin, bash 5.2 and zsh 5.9 on linux-arm64) gives the same stop notices and `$?` (128+signal) as plain exec, and for S2 the (b) outcome (fg ends the job with status 7, no job left, no leftover process). S4 also checked with zsh as the nested shell.

## Known gaps
- Background job (`cmd &`) of an interactive shell that never was foreground: its child's stop is not mirrored (indistinguishable from S1 under a terminal).
- S2 uses permitted deviation (b), not (a): after a mirrored stop the launcher cannot see a child-only SIGCONT.
- zsh may show the job as running for roughly 30 to 150 ms after a launcher-only SIGCONT before the child's background-read stop is mirrored (measured 34 ms on linux, about 100 to 150 ms on darwin, including measurement overhead).
- `build.sh` prints "notices generation failed" (`cargo metadata --locked --offline` fails in this environment); identical before my change, THIRD-PARTY-NOTICES.txt is not produced here.
- Windows only compile/clippy checked.
