# X2 T4 cross-review: six symlinked-`--file` fixes, one rubric

Task M00-T05-r4-x2-xrev-T4, 2026-10-10. One reviewer read all six T4 fixes side by side (three Go, three
Rust), rebuilt and probed them on darwin-arm64, and classified every defect with the same rubric for both
languages. This review does not compare the languages.

Everything below was executed in this task unless it says "code reading". Exit codes are the real ones. Raw,
redacted outputs are in `raw/`, and the scripts that produced them are in `scripts/`. In paths, `<home>` is
the home directory, `<scratch>` is `<home>/.local/share/heimdall-m00/r4-scratch/M00-T05-r4-x2-xrev-T4`,
and `<hidden>` is the hidden X2 directory.

## 1. Inputs and trees

- **Spec and contract:** `../../specs/T4.md`, and `docs/g02/slice-contract.md` (K14, §9.6). The seed is
  described in `../../hidden-pack/seed/SEED.md`.
- **Bases:** `git archive 84c7665 prototypes/go` and `git archive 001a791 prototypes/rust`.
- **Seeded trees:** copies of `<hidden>/seeded-trees/{go,rust}`.
- **Tree digests:** all four equal `BASE.json` (`raw/trees/tree-digests.tsv`):
  - base go `9ee4b916…`
  - base rust `58c9fef5…`
  - seeded go `88598ffc…`
  - seeded rust `dd09515d…`
- **Cell trees:** seeded tree + the implementer's `diff.patch`, applied with `git apply -p3`, exit 0 for all
  six (`scripts/prepare-trees.sh`).
- **Patch cross-check:** each evaluator `change.patch` was applied to a second copy, with its headers
  rewritten and `patch -p1`. `diff -r` against the `git apply` tree exits 0 with no output for all six
  cells (`raw/trees/patch-crosscheck.tsv`).

## 2. Builds (provenance)

`scripts/build-all.sh` copies each subject into a per-language scratch copy (`<scratch>/work/{go,rust}`) and
runs that tree's own unmodified `build.sh`. Rust gets the repository's pinned `cargo-zigbuild`, copied into
the copy's `target/tools/bin/`. Builds run offline (`GOPROXY=off GOTOOLCHAIN=local CARGO_NET_OFFLINE=true`).

**Toolchains** (`raw/builds/toolchains.txt`):

- Go: go1.27.2.
- Rust: rustc 1.99.0 (the version `build.sh` pins).

**Results:**

- Every `build.sh` exited 0 and built all four targets (darwin-arm64, linux-x64, linux-arm64, windows-x64).
  This covers the 2 bases, the 2 seeded trees and all 6 cells (`raw/builds/build-results.tsv` and
  `manifests/`).
- `gen_notices.py` failed inside `build.sh` in every Rust build because `cargo metadata --offline` was
  missing a crate. Evaluators had seen the same failure before. `build.sh` still exits 0.

**First Rust pass discarded.** It produced the base binary for all five Rust subjects. `rsync -a` keeps the
source mtimes, and cargo's mtime fingerprint then judged the kept `target/` fresh (`*.pass1-stale.*`).
The script now touches every copied source file after the reset. The second pass is the one used.

| subject | darwin-arm64 sha256 | equals |
|---|---|---|
| base-rust | `f9a3ec8b…` | BASE.json pin; linux-arm64 `85e038b4…` also equals its pin |
| seeded-rust | `66187b16…` | BASE.json pin; linux-arm64 `25af8e12…` also equals its pin |
| rust-opus1 | `513c1520…` | implementer's artifacts.json (darwin, linux-arm64 `98ddf571…`, windows `a3d88b9e…`) |
| rust-opus2 | `1494e496…` | implementer's artifacts.json (darwin, linux-arm64 `9932ec08…`) |
| rust-sonnet1 | `802553a6…` | implementer's artifacts.json (darwin, linux-arm64 `a4ee98f5…`) |
| go-opus2 | `21460121…` | implementer's and evaluator's build (darwin, linux-arm64 `a40fb865…`) |
| go-sonnet1 | `cfb023b5…` | implementer's and evaluator's build (darwin, linux-arm64 `77c25ea2…`) |
| go-opus1 | `1330a788…` | not the implementer's `c2c7c304…` (see below) |
| base-go | `f812084f…` | not the pin `bdfd64a2…` (see below) |
| seeded-go | `72be5bd7…` | not the pin `7ccf5a2b…` (see below) |

The three Go mismatches are toolchain differences:

- `go version` reports go1.27.1 for the pinned Go binaries and go1.27.2 for this rebuild.
- Homebrew's go was upgraded to 1.27.2 on 2026-10-09 at about 00:21 local time. The go-opus1 evaluation
  build is from 2026-10-08 22:49, before the upgrade. The go-opus2 and go-sonnet1 builds came later and
  match byte for byte.
- All five Go subjects here were built with the same go1.27.2.
- The go-opus1 rebuild passes hidden T4 on darwin, 6/6, exit 0 (`raw/hidden/T4-go-opus1/`).

The windows-x64 binaries of every subject are listed in `build-results.tsv`. All six cells still build every
target that `build.sh` built before.

## 3. Probe matrix (darwin-arm64)

`scripts/probe.py` takes each of the 10 builds in turn and does the following:

- It creates a fresh sandbox with `mkdtemp` under `/tmp`, which keeps AF_UNIX paths short. `/tmp` is itself
  a symlink on macOS, so every path also crosses a symlinked directory.
- It builds the layout and runs 57 cases.
- It removes the sandbox when the cases finish.

The child processes get only these variables: `PATH`, `HOME` (inside the sandbox), `LANG`, `TERM` and
`TMPDIR`. There is no `SSH_AUTH_SOCK`. Nothing listens: the socket node is bound and closed, never
`listen()`ed. A child that hangs is killed by its exact PID.

**Expectations:**

- `accept`: exit 0, `PROFILE_OK`, and stdout byte-identical to the direct path's.
- `same`: exit code, envelope code, `key_path` and message equal to the direct path's.
- `reject`: exit 2 `USAGE_ERROR` within 2 s. For the pipe and FIFO cases, every byte the probe buffered must
  still be unread after the run.
- `tui-ok`: run in a 24x80 pty that is the controlling terminal; the list with `3/3` and `lab-server`
  appears, `q` exits 0, and the alternate screen is left.
- `tui-reject`: exit 2 within 2 s, and the alternate screen is never entered.

**Deterministic TOCTOU.** `scripts/swap_open.c` is a DYLD interposer for `open`/`openat`:

- It is loaded into a copy of the binary that was re-signed ad hoc without the hardened runtime. The
  `build.sh` artifacts carry the hardened runtime, and dyld would ignore the variable for them.
- The first time the program opens the `--file` path, the hook atomically renames a prepared node over that
  path, then calls the real open. Every pre-open stat therefore saw the regular file, and the open sees the
  swapped-in target. The race window is hit on every run.
- A log line proves that each swap happened. The swap ran (`swapped 0`) in every fixed build and in both
  bases. The seeded builds refuse a link before they open it, so they never reached the swap ("no-swap").

**Positive controls.** For each cell, a `.nocheck` mutant was made with `scripts/mutate.py`; it disables the
check on the opened descriptor. Go removes the fstat `IsRegular` test and `os.SameFile`. Rust removes the Unix
`meta.is_file()` test. The mutants were built with a plain `go build` / `cargo build --release`. Each fails 4
of the 7 TOCTOU cases:

- FIFO without a writer: `SCHEMA_INVALID`.
- FIFO holding a valid profile: all 554 bytes are consumed.
- `/dev/zero`: `INPUT_TOO_LARGE`.
- A plain path swapped to a FIFO: all 554 bytes are consumed.

So the probe detects a missing descriptor check (`raw/probe/controls/`). In all six cells and both bases, the
same cases are refused and all 554 buffered bytes are still unread (`raw/probe/matrix/probe-results.json`,
`pipe_bytes_left`).

Results (`raw/probe/matrix/`): "ok"/"FAIL" is the verdict, and the number is the exit code. The longest
refusal was 0.013 s in any build; the longest TUI refusal was 0.009 s.

| case | kind | Go base | Go seeded | go-opus1 | go-opus2 | go-sonnet1 | Rust base | Rust seeded | rust-opus1 | rust-opus2 | rust-sonnet1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `abs_symlink` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `rel_symlink` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `chain_2_rel` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `chain_abs_then_link` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `chain_20` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `spaces_nonascii_link_and_target` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `parent_dir_symlink_abs` | accept | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 |
| `parent_dir_symlink_rel` | accept | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 |
| `relative_file_arg_cwd_config` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `relative_file_arg_other_cwd` | accept | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `dev_stdin_from_regular_file` | accept | **FAIL** 2 | **FAIL** 2 | **FAIL** 2 | **FAIL** 2 | **FAIL** 2 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `plain_abs_symlink` | accept-plain | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `plain_rel_symlink` | accept-plain | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `same_empty_file` | same | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 |
| `same_oversize` | same | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 |
| `same_duplicate_alias` | same | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 |
| `same_permission_denied_file` | same | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 |
| `same_permission_denied_dir` | same | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 | ok 2 | **FAIL** 2 | ok 2 | ok 2 | ok 2 |
| `same_trailing_slash_on_file_link` | same | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `fifo_direct` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_fifo_abs` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_fifo_rel` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_fifo_chain` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_fifo_with_writer_and_data` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_socket` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_directory` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_directory_rel` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_dev_null` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_dev_zero` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_dev_urandom` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `l_dev_tty` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `dangling_abs` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `dangling_rel` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `self_loop` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `loop_2` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `chain_40_eloop` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `dev_stdin_from_pipe_writer_open` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `dev_fd0_from_pipe_writer_open` | reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `plain_l_fifo` | reject-plain | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `plain_l_dev_zero` | reject-plain | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `plain_dangling` | reject-plain | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `tui_abs_symlink` | tui-ok | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `tui_rel_chain` | tui-ok | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `tui_nonascii_link` | tui-ok | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 | ok 0 | **FAIL** 2 | ok 0 | ok 0 | ok 0 |
| `tui_direct_regular` | tui-ok | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 | ok 0 |
| `tui_l_fifo` | tui-reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `tui_l_dev_null` | tui-reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `tui_l_directory` | tui-reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `tui_dangling` | tui-reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `tui_loop` | tui-reject | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |
| `toctou_to_fifo` | toctou | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 |
| `toctou_to_fifo_with_data` | toctou | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 |
| `toctou_to_dev_zero` | toctou | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 |
| `toctou_to_directory` | toctou | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 |
| `toctou_to_dangling` | toctou | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 |
| `toctou_to_other_regular` | toctou | ok 2 | ok 2 (no swap) | ok 2 | ok 2 | ok 2 | ok 0 | ok 2 (no swap) | ok 0 | ok 0 | ok 0 |
| `toctou_plain_path_to_fifo_with_data` | toctou | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 | ok 2 |

**Reading the matrix:**

- On every case, each of the six fixes behaves exactly like its unseeded base. Each seeded build fails the
  19 cases that need a final-component link to work.
- Two rows are not T4 defects:
  - **`dev_stdin_from_regular_file`.** All Go builds refuse it on macOS, including the base; see X3 below.
  - **`toctou_to_other_regular`.** Go refuses a link retargeted to another regular file, because `os.SameFile`
    fails. Rust reads the new file. Both are acceptable, the spec leaves this open, and each matches its base.

## 4. The cells' own tests, with the bug put back and with the descriptor check removed

`scripts/unit-tests.sh` runs each tree's own suite: `go test -count=1 ./...` for Go, and
`cargo test --locked --no-fail-fast` for Rust, with `HEIMDALL_G02_FIXTURES` set. Two mutants per cell come
from `scripts/mutate.py`:

- `.seed` puts the seeded `Lstat`/`symlink_metadata` behaviour back.
- `.nocheck` is the mutant from §3.

Results are in `raw/unit/unit-results.tsv`; the logs are next to it.

| subject | as delivered | `.seed` (bug back) | `.nocheck` (descriptor check removed) |
|---|---|---|---|
| go-opus1 | rc 0 | rc 1: TestK14NonRegularFiles, TestLoadSymlinkRetargetedBeforeOpen, TestLoadSymlinkToRegularFile, TestProfileShowSymlink, TestTUISymlink | **rc 1: TestLoadSymlinkRetargetedBeforeOpen** |
| go-opus2 | rc 0 | rc 1: TestLoadFollowsSymlinkToRegularFile, TestProfileShowSymlink, TestTUISymlink | rc 0 (no test notices) |
| go-sonnet1 | rc 0 | rc 1: TestLoadFollowsSymlinkToRegularFile, TestProfileShowFollowsSymlink, TestTUIFollowsSymlink | rc 0 (no test notices) |
| rust-opus1 | rc 0 | rc 101: symlinks_are_followed_but_k14_still_applies, profile_show_follows_symlinks_to_regular_files | rc 0 (no test notices) |
| rust-opus2 | rc 0 | rc 101: symlink_to_regular_file_loads_like_the_file, symlinked_profile_reads_like_its_target | rc 0 (no test notices) |
| rust-sonnet1 | rc 0 | rc 101: oversize_not_parsed_and_missing_is_usage, profile_symlinks_follow_to_regular_files_only | rc 0 (no test notices) |
| Go base (control) | rc 0 | n/a | rc 0: base Go never tested this check either |
| Rust base (control) | rc 0 | n/a | **rc 101: k14_non_regular_profile_files**. The base has no pre-check, so its K14 test exercised the descriptor check |

**Conclusions from the mutants:**

- Every cell's suite catches the reported bug coming back. The spec's "the bug cannot come back" is met in
  all six.
- Only go-opus1's suite guards the descriptor check, which the comments of all six fixes call authoritative.
- Hidden T4 does not guard it either. The six `.nocheck` mutants pass hidden T4 on darwin, 6/6, exit 0
  (`raw/hidden/summary.tsv`).
- SEED.md says a fix "that resolves the path and then opens it without the descriptor check" is caught by
  `T4.still_rejected_nonregular` and the harness K14 checks. That does not hold for the hidden T4 check when
  the fix keeps a link-following pre-check. The harness was not run on the mutants.

**Run notes:**

- The first Rust run used a TMPDIR inside `<scratch>` and failed with "path must be shorter than SUN_LEN"
  (`*.pass1-sunlen.*`). It was rerun with a short `mktemp -d /tmp/hmx4u-XXXXXX`, which was removed afterwards.
- The Rust `.seed` runs were repeated with `--no-fail-fast` (first runs `*.seed.failfast.log`). Rust
  as-delivered and `.nocheck` ran every suite, with no failures: 49 or 50 lib, 4 main and 29 or 30 cli tests.

## 5. Windows (§9.6)

**Code reading:**

- **Go.** No Go cell changes the post-open check in `Load`. On Windows, `File.Stat` is backed by
  `GetFileType`, so a pipe or character device is not `IsRegular` and is refused. The pre-check is
  `os.Stat` in go-opus1 and go-opus2, and `Lstat` then `Stat` in go-sonnet1. Either way it adds a refusal
  and cannot block, because `CreateFile` on a pipe never waits.
- **Rust.** All three Rust cells leave the `#[cfg(windows)]` `GetFileType(handle) != FILE_TYPE_DISK` block
  after the open untouched, so a named pipe given as `--file`, directly or through a link, is still refused.
- The pre-check uses std `metadata`/`symlink_metadata`, which on Windows open a handle. So the Rust fixes, like
  the seeded tree, probably add one pipe connection before the open. The base X1 run already records
  `pipe_connects: 1` as recorded-not-gated. This is not gated, and it is unverified.

**Observed cross-checks:**

- `GOOS=windows go vet ./...` and `go test -c` exit 0 for base-go and the three Go cells
  (`raw/windows/windows-go-vet.tsv`).
- `cargo check --locked --tests --target x86_64-pc-windows-gnu` exits 0 with no warnings for base-rust and
  the three Rust cells (`raw/windows/windows-rust-check.tsv`).
- The windows-x64 build of every cell succeeded in `build.sh`.
- Nothing was run natively on Windows.

## 6. Classification

**Rubric, applied identically to both languages:**

- **blocker:** a security-boundary breach (for example a FIFO or device let through), disclosure of a secret,
  or loss of user data.
- **major:** violates an explicit requirement of the spec or contract, or crashes, hangs or gives wrong
  results, on input a real user could plausibly hit, and the hidden tests miss it.
- **minor:** an unusual input, cosmetic output, a test or code-quality issue, or behaviour the spec leaves
  open.
- **pre-existing:** present in the unseeded base, and not something the task asked to change.

"none" means not a defect: either refuted by observation, or a shared evidence gap that is not a code defect.

### Cross-cell items

| id | item | applies to | rating | evidence |
|---|---|---|---|---|
| X1 | A target swapped between the pre-check and `open(2)` is opened (`O_NONBLOCK`, now also `O_NOCTTY` in all six) before the descriptor check refuses it. Example: a device. | all six | pre-existing. Go base has the same Stat-then-open window; Rust base opened every path with no pre-check at all | TOCTOU rows: refused, nothing read; `O_NOCTTY` removes the controlling-tty side effect |
| X2 | No test of the cell guards the authoritative descriptor check | go-opus2, go-sonnet1: pre-existing (base-go `.nocheck` passes its whole suite). rust-opus1/2/sonnet1: **minor**. Base Rust's `k14_non_regular_profile_files` guarded it; the link-following pre-check that the fixes keep now masks it (`.nocheck` passes every cargo suite). go-opus1: not applicable (guarded) | as stated | §4 |
| X3 | `--file /dev/stdin` with stdin redirected from a regular file is refused with `USAGE_ERROR` "not a regular file" on macOS. `stat` through devfs reports the devfs `st_dev`, `fstat` the file system's, so `os.SameFile` fails | go-opus1, go-opus2, go-sonnet1 | pre-existing (Go base identical); unusual input | `dev_stdin_from_regular_file` row; `stat -L /dev/stdin` vs `fstat(0)` checked by hand |
| X4 | Windows behaviour (symlink, junction, pipe through a link) never run natively | all six | none (shared evidence gap) | §5 |

### Per cell

| cell | defect (location) | reviewer | this review | basis |
|---|---|---|---|---|
| go-opus1 | Swap closures can call `t.Fatal` from the goroutine running `Load`; the `beforeOpen` hook is restored by hand, not `t.Cleanup` (`internal/profile/symlink_test.go`) | minor | minor | code reading |
| go-opus1 | REPORT names `statHandle` (Go stdlib internal) without saying so | minor | minor | code reading |
| go-opus1 | `runTUIFile`'s 500 ms drain slows every `runTUIEnv` caller | minor | **none (refuted)** | The drain ends at `r.done`, which closes as soon as the pty reader ends; the parent closes its slave after `Start`. TestTUIEnvironmentSelectedTerminfo took 1.53 s in go-opus1 and in go-opus2 (no drain), twice each |
| go-opus1 | X1; X3 | not listed | pre-existing ×2 | §3 |
| go-opus2 | TestLoadRetargetedSymlinkDoesNotBlock re-implements the Stat/open/fstat sequence and never reaches `Load`'s re-check; `t.Errorf` from a goroutine can run after test end on the timeout path | minor | minor | `.nocheck` suite rc 0 |
| go-opus2 | `k14_test.go` entry "symlink to symlink to fifo" depends on the `link-`+name naming of another entry | minor | minor | code reading |
| go-opus2 | TUI FIFO case: the 2 s bound includes pty setup, and the message is not checked | minor | **none** | The bound includes setup, so it is stricter, not looser. K14 requires exit 2 USAGE_ERROR; the test checks exit 2 and no alternate screen. Also true of go-sonnet1, rust-opus2 and rust-sonnet1, so rating it would be unequal |
| go-opus2 | X1; X2; X3 | not listed | pre-existing ×3 | §3, §4 |
| go-sonnet1 | `TestProfileShowFollowsSymlink` is in untagged `main_test.go`, compiled into the Windows test binary, and calls `os.Symlink` without a skip (needs privilege or Developer Mode) | minor | minor | `GOOS=windows go test -c` binary contains the test name; Windows not run |
| go-sonnet1 | `k14_test.go` final block says a retargeted link is refused but only exercises `openNoBlock` + `f.Stat` | minor | minor | `.nocheck` suite rc 0 |
| go-sonnet1 | Fixed 600 ms / 100 ms sleeps in `runTUIProcess` | minor | minor | code reading (no flake seen: suite rc 0) |
| go-sonnet1 | `open_windows.go` comment not revisited for followed links | minor | **pre-existing** | Comment unchanged from base, where `os.Stat` already followed links. The post-open `f.Stat` refuses pipes and devices |
| go-sonnet1 | **(missed)** `Lstat`, then `Stat` only for a symlink, is equivalent to one `os.Stat` and costs readers effort. This is the same pattern the rust-sonnet1 reviewer rated minor | not listed | minor | code reading; probe rows equal to go-opus1/2 |
| go-sonnet1 | X1; X2; X3 | not listed | pre-existing ×3 | §3, §4 |
| rust-opus1 | Unit test uses a PID-named temp dir with no drop guard (copies base's `hp-rs-prof-<pid>` pattern, in new code) | minor | minor | code reading |
| rust-opus1 | `pty_tui.py` `stow_layout` guards on `config/` only | minor | minor | code reading |
| rust-opus1 | Windows symlink path only cross-compiled | minor | none (X4) | §5 |
| rust-opus1 | **(missed)** X2: descriptor check no longer covered by any test | not listed | minor | §4 |
| rust-opus1 | X1 | not listed | pre-existing | §3 |
| rust-opus2 | Unit test PID temp dir cleaned only on success; the name undersells the test | minor | minor | code reading |
| rust-opus2 | Windows not native; red proofs not reproduced; unit test never run on pre-fix code | minor | **none** | X4. With the bug put back, the unit test and `symlinked_profile_reads_like_its_target` both fail (§4) |
| rust-opus2 | **(missed)** X2 | not listed | minor | §4 |
| rust-opus2 | X1 | not listed | pre-existing | §3 |
| rust-sonnet1 | Two-step `symlink_metadata` then `metadata` equals one `metadata` | minor | minor | code reading |
| rust-sonnet1 | Retargeted link can open a device before `fstat` refuses it | minor | **pre-existing** (X1) | §3 |
| rust-sonnet1 | Windows symlink behaviour untested natively | minor | none (X4) | §5 |
| rust-sonnet1 | `show_within_2s(&bad)` spawned twice; pty case covers absolute and relative links only; cli run on darwin only | minor | minor (only the duplicate spawn) | The other two parts are not defects: the TUI shares the loader that cli.rs covers for chains, and four of the six TUI tests cover only absolute and relative links (go-opus1, go-sonnet1, rust-opus2, rust-sonnet1). Where a test ran is not a code defect |
| rust-sonnet1 | **(missed)** X2 | not listed | minor | §4 |
| rust-sonnet1 | New assertions sit inside the base test whose PID temp dir has no drop guard | not listed | pre-existing | code reading |

### Counts (this review)

| cell | blocker | major | minor | pre-existing |
|---|---|---|---|---|
| go-opus1 | 0 | 0 | 2 | 2 |
| go-opus2 | 0 | 0 | 2 | 3 |
| go-sonnet1 | 0 | 0 | 4 | 4 |
| rust-opus1 | 0 | 0 | 3 | 1 |
| rust-opus2 | 0 | 0 | 2 | 1 |
| rust-sonnet1 | 0 | 0 | 3 | 2 |

There are no blockers or majors in any cell. All six fixes follow the link in the pre-check, and all six keep
the non-blocking open and the descriptor check. The deterministic race shows that this check is what stops a
swapped-in FIFO or device in every cell.

Rating changes from the cell reviewers:

- **Lowered to none:**
  - go-opus1 500 ms drain (refuted).
  - go-opus2 TUI FIFO bound.
  - rust-opus1, rust-opus2 and rust-sonnet1 Windows evidence items.
- **Lowered to pre-existing:**
  - go-sonnet1 `open_windows.go` comment.
  - rust-sonnet1 device-open race.
- **Missed by the reviewers:**
  - go-sonnet1: two-step stat (minor).
  - All three Rust cells: X2 (minor).
  - The pre-existing X1, X2 (Go) and X3 entries.

## 7. Limitations

- **Platform:**
  - The probes ran on darwin-arm64 only. linux-arm64 was covered only by the evaluators' earlier hidden-test
    and harness runs.
  - Windows was cross-compiled and type-checked only. No native Windows symlink, junction or named-pipe run
    was done.
- **TOCTOU harness:**
  - The interposer runs re-signed copies, which have no hardened runtime. Code is identical; only the
    signature differs.
  - It swaps at the first `open`/`openat` of the exact `--file` string. A program that opened the path
    another way, for example a relative `openat` with a different string, would not be raced. All six fixes
    and both bases reached the swap.
- **Go toolchain:** Go subjects were rebuilt with go1.27.2. go-opus1's evaluated binary used go1.27.1. The
  go1.27.2 build of go-opus1 passes hidden T4 on darwin.
- **Not re-run:** the full G02 harness (139 checks) was not re-run on any build, and the cells' Rust
  `pty_tui.py` cases were not run. The TUI was probed with `scripts/probe.py` instead.
- **Code reading only:**
  - The X1 side effects of opening a device beyond `/dev/zero`, the null device and a tty.
  - The Windows pipe-connection count.
- **Mutation testing:** used two mutations per cell, not a full mutation analysis.

## 8. Housekeeping

- **Scratch root:** created for this task, so it was 0 bytes before; it peaked at about 1.2 GB, mostly the
  Rust `target/`.
- **Removed at the end:** the build trees, both `work/` copies with their `target/` and `dist/`, every
  binary, the mutant and cell source trees, and the interposer dylib. The scratch root now holds only
  unredacted logs, probe output and hidden-run output (884 KB).
- **`/tmp`:** every `hmx4-*` sandbox and `hmx4u-*` test directory was removed; none remain.
- **Processes:** none started by this task are still running.
- **Repository:** nothing outside `tests/evidence/artifacts/g02-r4/x2/cross-review/T4/` was written. `scan-home.py`
  over this directory reports 0 hits.
