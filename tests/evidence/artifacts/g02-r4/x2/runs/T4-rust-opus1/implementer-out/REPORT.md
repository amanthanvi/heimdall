# T4 (rust): symlinked `--file` refused by `profile show` and `tui`

## Cause

`prototypes/rust/src/profile.rs` `read_bounded` (shared by `profile show` and `tui` through
`profile::load_file`) ran a pre-open check with `std::fs::symlink_metadata(path)`. That call does not follow
the final link, so a link to a regular file was classified as "not a regular file" and refused with exit 2
`USAGE_ERROR`. A relative link failed the same way. The code comment said this closed a check/open race, but
it did not: `open` follows links anyway, and a plain path can be renamed between check and open just as
easily. The contract's K14 lists FIFO, socket, device and directory. It does not exclude links.

I reproduced the bug before the fix. The pre-fix release binary returned USAGE_ERROR "profile path is not a
regular file" for both an absolute and a relative link, and PROFILE_OK for the file itself.

## Change (only `prototypes/rust/`)

- `src/profile.rs` `read_bounded`: the pre-open check now uses `std::fs::metadata`, which follows links.
  It is only an advisory fast path. It gives the precise message ("profile path is a directory" or "not a
  regular file") and refuses a socket, which cannot be opened. A dangling link or a link loop falls through
  to the open, which fails with `USAGE_ERROR` "cannot open profile file: ...".
- The authoritative K14 check is unchanged. The open never blocks (`O_NONBLOCK`), and then `fstat` on the
  opened handle refuses anything that is not a regular file (on Windows: `GetFileType`, then handle
  metadata). So a link retargeted to a FIFO or device after the pre-check is still refused at once.
- `open_nonblocking` now also passes `O_NOCTTY`. This is hardening for that race: a terminal device that
  slips past the pre-check cannot become the controlling terminal before it is refused.
- `tui` is fixed by the same change, because it uses the same `load_file`.
- Doc comments were updated. A section 17 in `prototypes/rust/REPORT.md` describes the fix.

## Tests added or changed

- **Unit, `src/profile.rs` `symlinks_are_followed_but_k14_still_applies` (Unix):**
  - Absolute, relative and chained links load a `Profile` equal to the file's.
  - Links to a directory and to `/dev/null` keep their K14 messages.
  - A dangling link and a link loop give `USAGE_ERROR`.
- **`tests/cli.rs` `profile_show_follows_symlinks_to_regular_files`:**
  - Absolute, relative, chained and through-a-linked-directory links give the same exit status, stdout and stderr as the file, byte for byte, with and without `--json`.
  - An invalid profile behind a link gives the same `SCHEMA_INVALID` output as the file.
- **`tests/cli.rs` `k14_symlinks_to_non_regular_files`:** each of these gives exit 2 `USAGE_ERROR` within 2 s, with and without `--json`:
  - links, direct and chained, to a FIFO without a writer;
  - links to a socket, to `/dev/null`, and to a directory (absolute and relative);
  - a dangling link and a link loop.
- **`tests/cli.rs` `k14_non_regular_profile_files`:** removed the old assertion that a link to a regular file is refused (exit 2). The test now also checks the non-`--json` form, through the new helpers `profile_show_within_2s` and `assert_k14_usage_error`.
- **`tests/pty_tui.py`:**
  - New case `tui-symlinked-profile`: with an absolute, relative or chained link, the list is drawn and `q` exits 0 with termios and screen restored.
  - New case `k14-tui-symlink-to-fifo-usage-error`: exit 2 within 2 s, no alternate screen, and a USAGE_ERROR diagnostic.

## Results (real exit codes; logs are in `/tmp/x2ws-7ba23d34/scratch/`)

| Step | Exit | Result |
|---|---|---|
| `cargo fmt --check` | 0 | |
| `cargo clippy --locked --all-targets -- -D warnings` (darwin host) | 0 | |
| `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings` | 0 | Windows code compiles; it was not run |
| `HEIMDALL_G02_FIXTURES=... cargo test --locked -- --test-threads=4` (darwin-arm64) | 0 | 50 unit, 4, 30 cli, 0, 0: all passed |
| **Red proof:** new cli tests against the pre-fix binary (sha256 `0ad67eda...`) | 101 | `profile_show_follows_symlinks_to_regular_files` FAILED; the two K14 tests passed (the old code refused every link) |
| **Red proof:** `HP_PTY_ONLY=symlink pty_tui.py` against the pre-fix binary | 1 | `tui-symlinked-profile` failed ("status line 3/3 not drawn"); the K14 link case passed |
| `build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64 and windows-x64 all built |
| `pty_tui.py dist/darwin-arm64/heimdall-proto` | 0 | 28 cases. The only non-pass is the existing documented known limitation `run-terminal-sigint-not-doubled` (Darwin), which was there before this change |
| Harness 2.4.2 darwin-arm64: `tests/g02/.venv/bin/python tests/g02/conformance.py --bin dist/darwin-arm64/heimdall-proto --candidate rust ...` | 0 | **139/139 pass**, status verified, verdict pass; the record names sha256 `513c1520...` |
| Harness 2.4.2 linux-arm64: `sh tests/g02/linux/run.sh --artifact-dir dist/linux-arm64 --candidate rust ...` | 0 | **139/139 pass**, status verified, verdict pass; the record names sha256 `98ddf571...` |
| Cross-built test executables (`cargo-zigbuild test --no-run --target aarch64-unknown-linux-musl`) run by `tools/linux_tests.sh` in a linux/arm64 container | 0 | 50 unit, 4, 30 cli (1 ignored: the existing `linux_nproc` test, which needs `--ignored` and a non-root user), 0: all passed |
| `tools/linux_pty.sh arm64 dist/linux-arm64/heimdall-proto` | 0 | 28/28 pass, no known limitations |
| The bug report's reproduction against the linux-arm64 artifact (in a container) | n/a | file, absolute link and relative link: plain exit 0, and identical `--json` stdout (md5 equal). Link to a FIFO: exit 2 USAGE_ERROR |

Harness records: `/tmp/x2ws-7ba23d34/scratch/harness-darwin.json` (artifacts in `scratch/harness-darwin/`)
and `/tmp/x2ws-7ba23d34/scratch/harness-linux.json`.

## Known gaps and deviations

- **Linux test image:** `tools/linux_tests.sh` and `tools/linux_pty.sh` default to `debian:bookworm-slim@sha256:0c8b...` and `python:3.13-slim-bookworm@sha256:5024...`. Neither is present locally under those digest references (`--pull never`), and there was no network fetch. I ran both scripts with `HP_LINUX_TEST_IMAGE` / `HP_LINUX_PTY_IMAGE` set to the local harness image `heimdall-g02-harness:d0c8e448a3a7`, which is linux/arm64 and built FROM that same python digest. The shared harness's Linux run used its own normal image.
- **Windows not run:** no Windows host was available, and creating a symlink on Windows needs Developer Mode or the symlink privilege. On Windows the code path is `metadata`, which follows links, then open, then `GetFileType`. It cross-compiles and passes clippy, but that is not native evidence, so Windows symlink behaviour is unverified. No Windows test was added.
- **Race not tested:** the check/open retarget race is argued from the code. No test forces it.
- **Pre-installed tool:** `cargo-zigbuild` 0.23.4 was already in the workspace at `prototypes/rust/target/tools/bin/` and went into the starting commit. An offline `cargo install` attempt reported that it already existed and wrote two empty bookkeeping files, which I removed.
- **Byproducts removed:** the runs left `__pycache__` directories in `prototypes/rust/tools/` and `tests/fixtures/fake-agent/`. I removed both. `docs/`, `schemas/`, `tests/g02/` and the fixtures are unchanged.
- **Review:** there was no independent review. This report is self-review only.
