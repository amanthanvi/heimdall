# T4-rust-sonnet1: symlinked profile path rejected

## Cause
`profile::read_bounded` (src/profile.rs), shared by `profile show` and `tui` via `load_file`, did a
`std::fs::symlink_metadata(path)` pre-check and refused anything whose own file type was not a
regular file. A symlink therefore failed with "profile path is not a regular file", even when it
pointed to a regular file. A test (`k14_non_regular_profile_files`) and a doc comment encoded this as intended.

## Fix
- Pre-check: `symlink_metadata`; if the path is a symlink, re-check with `metadata` (follows the chain).
  A link must end at a regular file; links to a FIFO, socket, device or directory still give exit 2
  USAGE_ERROR. A dangling link or a link loop fails the follow and is reported by the open as USAGE_ERROR
  (same class as a missing file). Non-symlink behaviour is unchanged.
- The pre-check is only an early refusal (avoids opening devices and sockets). The authoritative check stays the
  `fstat` of the opened descriptor (`file.metadata().is_file()`), and the open is `O_NONBLOCK`, so a link retargeted
  to a FIFO between check and open still cannot block (K14, 2 s).
- Added `O_NOCTTY` to the profile open, so that following a link to a tty cannot make it the controlling terminal.
- Windows code paths (`GetFileType` check) are unchanged; compile-checked only (windows-x64 builds), not run natively.

## Tests (prototype's own frameworks)
- `tests/cli.rs`: `k14_non_regular_profile_files` no longer asserts the old refusal;
  new `profile_symlinks_follow_to_regular_files_only`: absolute, relative, chained links and a link in a directory component give
  byte-identical JSON and plain output to the real file; link to an invalid profile reports the file's own error; links to a
  FIFO (also via a second link), socket, directory, /dev/null, a dangling link and a link loop all exit 2 USAGE_ERROR within 2 s.
- `src/profile.rs` unit test: symlink to file loads; link to directory and dangling link are USAGE_ERROR.
- `tests/pty_tui.py`: new case `tui-symlinked-profile` (registered in the case list): `tui --file` with an absolute and a relative
  link starts and quits with exit 0; a link to a FIFO exits 2 in under 2 s without entering the alternate screen.
- Sensitivity: with the original profile.rs restored, the new cli test and the pty case fail; with the fix they pass.

## Results (real exit codes)
- `cargo fmt --check`: 0. `cargo clippy --all-targets`: 0 warnings.
- `cargo test --locked --offline -- --test-threads=4` (HEIMDALL_G02_FIXTURES set): exit 0; 49 lib, 4, 29 cli tests pass (0 failed).
- `sh build.sh`: exit 0; darwin-arm64, linux-x64, linux-arm64, windows-x64 all built. The notices step printed
  "notices generation failed" because `cargo metadata --offline` cannot download `redox_syscall` in this workspace (no registry cache);
  build.sh still exits 0 and the manifest has all four targets built. Environmental, unrelated to the change.
- Darwin harness (conformance.py, harness 2.4.2): exit 0, total 139, pass 139, fail 0, error 0, skipped 0 (scratch/harness-darwin.json).
- Linux harness (tests/g02/linux/run.sh with dist/linux-arm64): exit 0, 139/139 pass (scratch/harness-linux.json; the log prints the
  in-container path /out/harness-linux.json for the record).
- Manual repro on the linux-arm64 artifact in a debian:bookworm-slim container: real file, absolute link and relative link exit 0 PROFILE_OK
  (JSON and plain); link to a FIFO exits 2 USAGE_ERROR.
- `python3 tests/pty_tui.py dist/darwin-arm64/heimdall-proto --panic-binary ...`: full run exits 1 for two reasons unrelated to this change:
  `run-terminal-sigint-not-doubled` is the documented Darwin known limitation, and `tui-panic-restores` needs target/panic/debug/heimdall-proto,
  which I did not build. The new `tui-symlinked-profile` case run alone (HP_PTY_ONLY=symlink): exit 0, passed. Other 25 cases passed in the full run
  (the symlink case was added to the list after that full run, so it was run separately).

## Known gaps
- Windows symlink behaviour is not run natively (blocked: no Windows host). Reparse-point links follow through `metadata` plus the
  `GetFileType` check, by code reading only.
- `tests/cli.rs` is Unix-only and was run on darwin only; Linux coverage of the fix is the manual container repro and the linux harness (which has no symlink check).
- Prototype REPORT.md/docs not edited (docs/ is off limits; REPORT.md does not mention the symlink refusal).
