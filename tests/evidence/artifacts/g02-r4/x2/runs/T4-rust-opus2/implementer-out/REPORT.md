# T4-rust-opus2: symlinked `--file` rejected by `profile show` and `tui`

## Cause
`prototypes/rust/src/profile.rs` `read_bounded` ran a pre-open check with `std::fs::symlink_metadata`,
which does not follow a final symlink. A link to a regular profile therefore had file type "symlink" and was
refused with exit 2 `USAGE_ERROR` "profile path is not a regular file" before it was opened. Both
`profile show` and `tui` load through `profile::load_file` -> `read_bounded`, so both were affected. The check
was meant as a TOCTOU guard, but the authoritative K14 check is already on the opened descriptor
(`O_NONBLOCK` open + `fstat`; Windows `GetFileType`), which cannot be raced. The harness reference
implementation also follows links and decides on `fstat`. An existing test (`k14_non_regular_profile_files`)
had pinned the buggy behavior.

## Change (only `prototypes/rust/`)
- `src/profile.rs`: pre-check now uses `std::fs::metadata` (follows links, as the open does). It is kept only as
  an optimisation so FIFOs/devices/sockets/dirs behind a path are normally rejected without being opened;
  unresolvable paths (dangling link, loop, missing) fall through to the open and stay `USAGE_ERROR`. The
  non-blocking open + descriptor check (K14, section 9.6) is unchanged. Unix open adds `O_NOCTTY` (a link could now
  lead to a tty; it must never become the controlling terminal before `fstat` rejects it).
- Tests: `tests/cli.rs` new `symlinked_profile_reads_like_its_target` (absolute, relative `../dotfiles/x`,
  chained, via symlinked dir; valid and invalid profile; with and without `--json`; stdout/stderr/exit
  byte-identical to the real file; dangling link and loop -> exit 2 USAGE_ERROR). `k14_non_regular_profile_files`:
  removed the "link to regular file is refused" assertion, added absolute/relative/chained links to FIFO, dir,
  `/dev/null`, socket (each exit 2 USAGE_ERROR within 2 s). `src/profile.rs` unit test
  `symlink_to_regular_file_loads_like_the_file`. `tests/pty_tui.py` case `tui-symlinked-profile` (tui opens via
  absolute and relative link, `q` -> exit 0, terminal restored; link to FIFO -> exit 2 < 2 s, no alt screen).
- `REPORT.md`: section 17 documents the fix.

## Results (real exit codes)
| Step | Exit | Result |
|---|---|---|
| `cargo fmt --check` | 0 | clean |
| `cargo clippy --offline --all-targets` | 0 | no warnings |
| `cargo test --offline` (darwin, debug) | 0 | lib 50/50, main 4/4, cli 29/29 |
| `cargo test --test cli` with `HEIMDALL_PROTO_BIN`=darwin-arm64 artifact | 0 | 29/29 |
| `sh build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64, windows-x64 all built |
| `pty_tui.py <darwin artifact>` | 0 | all passed; `run-terminal-sigint-not-doubled` is the pre-existing documented Darwin known limitation |
| `conformance.py` darwin-arm64 artifact | 0 | 139/139 pass, status verified |
| `tests/g02/linux/run.sh` linux-arm64 artifact | 0 | 139/139 pass, status verified |
| Linux (harness image, `--network none`): lib unit tests (musl cross-built) | 0 | 50/50 |
| Linux: `tests/cli.rs` against linux-arm64 artifact | 0 | 29 passed, 1 ignored (pre-existing `linux_nproc_limit_never_orphans_child`) |
| Linux: report reproduction, fixed linux-arm64 artifact | 0 per command | abs and relative link: PROFILE_OK, exit 0, with/without `--json` |
| Linux: pty `tui-symlinked-profile` and `k14-tui-fifo-usage-error`, fixed | 0 / 0 | pass |

Red proofs (pre-fix builds from the starting commit): darwin repro -> `USAGE_ERROR` "profile path is not a
regular file" for abs and relative link; `cargo test --test cli` with the pre-fix darwin binary -> exit 101
(`symlinked_profile_reads_like_its_target` FAILED, `k14_non_regular_profile_files` ok); pty
`tui-symlinked-profile` pre-fix -> exit 1 on darwin and linux; Linux repro pre-fix -> exit 2 USAGE_ERROR.

Artifacts: darwin-arm64 sha256 1494e496db5d289bc9b95a37a5bd7194bc887f67c4fc08bbea0c6a40d4277219,
linux-arm64 sha256 9932ec08bf14ce34bed24dc0e4a63fcf27ef6de95e1d5c0f52519fff2e383fbf (see artifacts.json).
Harness records: `scratch/harness-darwin.json`, `scratch/harness-linux.json`.

## Known gaps
- Windows symlinks not exercised natively (no Windows host): blocked on native Windows. Windows path changes the
  same way (pre-check follows links; `GetFileType` after open unchanged); windows-x64 builds.
- The new profile.rs unit test was not run against pre-fix code (the CLI and pty tests carry the red proof).
- Following links is a deliberate behavior change: a link that resolves to a regular file outside the
  directory the user named is read. That is what the report asks for and matches the reference implementation.
- Local images `python:3.13-slim-bookworm`/`debian` disappeared mid-session (removed by something outside this
  task); Linux ad hoc runs used the local `heimdall-g02-harness` image by ID.
