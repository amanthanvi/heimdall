# T4 seeded bug (hidden; implementers see only specs/T4.md and a workspace built from the seeded tree)

**Base (fix round, 2026-10-06):** the seeds now sit on the post-X1b prototypes, Go `84c7665` and
Rust `001a791` (see `../BASE.json`). The frozen-base patches (`38b6b72`, `d8f0cbe`) are kept for
history in `superseded-frozen-base/`. The seed content is unchanged: both patches applied to the
post-X1b trees without conflict (Rust with a line offset, because X1b added a Windows-only
`GetFileType` block to `read_bounded` after the open).

## The bug

A `--file` path that is a **symlink to a regular profile** is refused with exit 2 `USAGE_ERROR`
`"profile path is not a regular file"`. This affects `profile show` (with and without `--json`) and
`tui`. The same profile reached by its real path works.

The seed looks like a deliberate but wrong hardening of the K14 non-regular-file check, written the
way that codebase already does it. Each version carries the same plausible but misleading comment:
"following a symlink here would let its target be retargeted to a FIFO or device between the check
and the open".

| | Go (84c7665) | Rust (001a791) |
|---|---|---|
| code | `internal/profile/profile.go` `Load`: the pre-open `os.Stat(path)` becomes `os.Lstat(path)`. The existing `!st.Mode().IsRegular()` test then rejects a symlink. | `src/profile.rs` `read_bounded`: a new `std::fs::symlink_metadata(path)` pre-check before the open rejects anything that is not `is_file()`. It uses the same message wording the function already had. |
| unit test made to assert the bug | `internal/profile/k14_test.go`: the final block "A symlink to a regular file is still accepted" now expects `USAGE_ERROR`. | `tests/cli.rs` `k14_non_regular_profile_files`: a new case says a symlink to a regular file gives exit 2 (and the regular file itself exits 0). |
| diff | `go-84c7665.patch` (2 files, +14/-8 lines, comments included) | `rust-001a791.patch` (2 files, +31/-1 lines, comments included) |

Why both test suites were edited: the base Go tree already had a unit test that accepts a symlink to
a regular file, and the Rust tree had none. Leaving Go's test alone would let `go test` point straight
at the cause in Go only. In both seeded trees the unit suite now encodes the bug, so a correct fix has
to change a test in both. That makes the diagnosis effort symmetric.

Residual asymmetry introduced by X1b (Rust only, judged minor): the Windows `GetFileType` comment in
`read_bounded` and the module comment in `src/winfile.rs` say that std's Windows `is_file()`
"only excludes directories and symlinks". It is about Windows std semantics, sits a few lines
below the seed, and does not point at the seeded pre-check more than the seed's own comment does.

## Trees and builds

- `../seeded-trees/go` = `git archive 84c7665 prototypes/go` + `go-84c7665.patch`. No `.git`,
  no `dist/`.
- `../seeded-trees/rust` = `git archive 001a791 prototypes/rust` + `rust-001a791.patch`. No
  `.git`, no `dist/`, no `target/`.
- Location: the trees were first built at `/tmp/hm-r4/seeded/{go,rust}`; on 2026-10-06 the orchestrator
  moved them to `../seeded-trees/` and deleted `/tmp/hm-r4` (disk full). Fix round 2 re-checked both tree
  digests after the move (equal to `../BASE.json`) and a `make-workspace.sh --test-build` T4 copy of each
  (`diff -r` exit 0, Rust excluding the added `target/tools`).
- Check (observed 2026-10-06): re-extracting each base tree and applying its patch with
  `patch -p1` reproduced the seeded tree exactly (`diff -r` exit 0 for both).
- Tree digests (`find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256`):
  go `88598ffc2c8fedb6447eb7c92599f277d0b42e9413faa549eef00bbcda6396aa`,
  rust `dd09515d9be70c8ded304ca45000e201c02601894fc049d94492a636ef17bd59`. `make-workspace.sh`
  refuses a seeded tree whose digest differs.
- Builds: each seeded tree was copied to scratch and built with its own unmodified `build.sh`
  (Rust with `CARGO_ZIGBUILD` pointing at the repository's pinned `cargo-zigbuild`, so with the usual
  `--remap-path-prefix` flags). All four targets built (exit 0). The darwin-arm64 and linux-arm64
  binaries are pinned in `../bin/seeded-{go,rust}/` with the sha256 in `../BASE.json`:
  - go darwin-arm64 `7ccf5a2bfe299541ecffbd8f5949f509c30fbbe9b67fd3e8002234260d61d05a`
  - go linux-arm64 `3e118cb903f983886bdaa742caa3ebb6e9e0f3554e9fd66cc39f90cfd7af9943`
  - rust darwin-arm64 `66187b16db9938919cb6a7562a67f8e9db40c42e9de19d2b816f56d3a95de530`
  - rust linux-arm64 `25af8e125d8ab1149ed7301a5ddf8bc45427eeb9ae4dc4ff9d4fe8e3a7859c00`
- The base builds were made the same way from `git archive` of the base commits. They reproduce the
  repository's current `prototypes/{go,rust}/dist` byte for byte (go `bdfd64a2…`/`18d96a07…`,
  rust `f9a3ec8b…`/`85e038b4…`), which shows the committed X1b sources are what those builds came from.

## Verification (post-X1b base, fix round 2026-10-06)

All observed; details and record paths in `../README.md` "Observed verification".

- Regenerated `git archive <base> prototypes/<lang>` + `patch -p1` < `<lang>-<base>.patch`: tree
  digests equal `../BASE.json` and `diff -r` against the seeded tree (then at `/tmp/hm-r4/seeded/<lang>`,
  now `../seeded-trees/<lang>`) exits 0 (go, rust).
- Rebuilt with each tree's own `build.sh`: darwin-arm64 and linux-arm64 binaries byte-identical to
  the pins in `../BASE.json` (also when built inside a `make-workspace.sh` T4 workspace).
- Symmetry on darwin: through an absolute and a relative symlink, seeded Go and seeded Rust both exit
  2 with byte-identical stdout and stderr; the real path exits 0 in both; the base builds exit 0 on all
  three paths.
- Hidden T4 on darwin and linux, twice (`results/2026-10-06-pinned-base`, `-2`): seeded builds 1/6
  (exit 1), base builds 6/6 (exit 0), in both languages.
- Full harness 2.4.2 run from inside the T4 workspaces on the seeded builds: 139/139 on darwin-arm64
  and on linux-arm64, Go and Rust. Unit tests of both seeded trees pass inside the workspaces (exit 0,
  no `HEIMDALL_G02_FIXTURES` needed), i.e. both suites assert the bug.
- Residual (both languages, judged comparable): each prototype's `REPORT.md` describes the base K14
  check (Go: "`Load` stats the path before opening"; Rust: "The Unix path is unchanged (O_NONBLOCK plus
  `is_file`)"), which the seeded code contradicts.

## A correct fix (for the evaluator)

Check the path without leaving the final symlink unfollowed (Go: `os.Stat`; Rust: follow the link or
drop the pre-check). Keep the existing open with `O_NONBLOCK` and the fstat regular-file check on the
open descriptor, which keeps K14. Change the seeded unit test back so it expects a symlink to a
regular file to be accepted, ideally with a symlink-to-FIFO case too. A fix that just adds
`O_NOFOLLOW`, or that resolves the path and then opens it without the descriptor check, is wrong.
`T4.still_rejected_nonregular` and the harness K14 checks catch it. The Windows code path must still
compile (`build.sh` builds windows-x64).
