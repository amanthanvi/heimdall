# T4-go-opus1: `--file` symlink rejected by `profile show` and `tui` (Go prototype)

## Cause

`prototypes/go/internal/profile/profile.go` `Load` (used by both `profile show` and `tui`) checked the
path with `os.Lstat`. Lstat describes the link itself (`ModeSymlink`), so every symlink failed
`IsRegular()` with exit 2 `USAGE_ERROR` "profile path is not a regular file". That held even when the
link pointed to a regular profile. The code comment said Lstat was there to stop a check-then-open race.
The descriptor check after the open (fstat `IsRegular` plus `os.SameFile` with the first stat) already
handles that race, so refusing links gave no added protection.

## Change

- `internal/profile/profile.go`: `Load` uses `os.Stat`, which follows links the way open(2) does. All
  later checks therefore apply to the link's final target. Still unchanged:
  - the non-blocking open;
  - the fstat regular-file check and the `SameFile` check;
  - the 1 MiB bound and the error codes.

  Also added: the doc comment is rewritten, and a no-op package variable `beforeOpen` (a test hook) runs
  between the check and the open.
- `internal/profile/open_unix.go`: the open now also uses `O_NOCTTY`. A link retargeted to a tty
  inside the race window can never become the controlling terminal. The descriptor is then refused.
- `internal/profile/open_windows.go`: comment only. On Windows, `os.Stat` follows symlinks, and Go's
  `statHandle` reports pipes and character devices as non-regular. That path is compile-checked only.
- `prototypes/go/REPORT.md`: added a section describing the fix and its tests.

K14 still holds:
- A link to a FIFO, socket, device or directory is exit 2 `USAGE_ERROR`.
- A dangling link and a link loop are also exit 2 `USAGE_ERROR`, with the message "profile file cannot
  be opened".
- None of these block.

Error messages for links are the same as for their targets: a link to an oversize file gives
`INPUT_TOO_LARGE`, and a link to an invalid profile gives the same `SCHEMA_INVALID` key path.

## Tests (Go `testing`)

New: `internal/profile/symlink_test.go`, `cmd/heimdall-proto/symlink_test.go`. Changed:
`internal/profile/k14_test.go` (its last assertion required a link to a regular file to be refused, which
was the bug) and `cmd/heimdall-proto/tui_terminfo_test.go` (`runTUIEnv` now delegates to
`runTUIFile(file, env)`, which also returns the elapsed time and the pty output).

What the new tests cover:
- **Links to a regular profile.** Covered forms: absolute, relative, chained, a linked directory
  component, and a name with a space and ü. Each loads a `Profile` that is DeepEqual to the target's.
  The oversize and invalid-profile results match the target's.
- **Links that must fail.** Links to a FIFO (absolute, relative or chained), a socket, a directory or
  `/dev/null`, a dangling link, a loop, and `link-to-dir/`. Each gives `USAGE_ERROR` within 2 s.
- **Race through the `beforeOpen` hook.** If the link is retargeted to a FIFO, or its target is replaced,
  between the check and the open, the result is `USAGE_ERROR`. A mutation run in a scratch copy, with
  the fstat/SameFile check removed, made this test fail ("got SCHEMA_INVALID" / "got <nil>"). The test
  therefore guards that check.
- **`profile show` through the CLI.** With and without `--json`, absolute and relative links, and absolute
  and relative `--file` (using `t.Chdir`), the output is byte-identical to the regular file's and the exit
  code is 0. A link to a FIFO gives exit 2 `USAGE_ERROR` within 2 s.
- **`tui` in a real pty.** Through absolute and relative links, the picker draws `lab-server` and exits 0
  on `q`. A link to a FIFO exits 2 within 2 s, without drawing, and prints "not a regular file".

Red before the fix: the new and changed tests were run against the unfixed `Load`, with only the no-op
hook added. Exit 1. All the link-to-regular cases failed with "profile path is not a regular file", in
`profile show` (JSON and text) and in `tui`. The non-regular cases already passed.

## Results (real exit codes)

| Step | Exit | Result |
|---|---|---|
| `go test -count=1 ./...` (darwin-arm64, `HEIMDALL_G02_FIXTURES` set) | 0 | all packages ok |
| `go test -count=1 ./...` in `golang:1.27.1-bookworm` linux/arm64, `--network none`, `GOPROXY=off` | 0 | all packages ok; all 7 symlink/K14 tests PASS |
| `go vet ./...` for linux/{amd64,arm64} and windows/{amd64,arm64} | 0 each | |
| `sh prototypes/go/build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64 and windows-x64 all built (same targets as before) |
| `tests/g02/.venv/bin/python tests/g02/conformance.py --bin …/darwin-arm64/heimdall-proto --candidate go` | 0 | 139/139 pass, status=verified, verdict=pass |
| `sh tests/g02/linux/run.sh --artifact-dir …/linux-arm64 --candidate go` | 0 | 139/139 pass, status=verified, verdict=pass |
| Bug-report reproduction, darwin artifact (`profile show` with and without `--json`, `tui` in a pty) | 0 (driver) | regular file, absolute link and relative link: exit 0, PROFILE_OK, TUI drew and exited 0 on q. Link to FIFO: exit 2 USAGE_ERROR, TUI exited 2 in 0.00 s |
| The same reproduction, linux-arm64 artifact in `hp-g02-python-arm64:3.13-alpine`, `--network none` | 0 (driver) | same results as darwin |

Scratch outputs:
- harness records: `/tmp/x2ws-d0ea9f3d/scratch/harness-{darwin,linux}.json`, consoles `*.console.txt`,
  artifact dirs `harness-darwin/`, `harness-linux/`;
- unit test logs: `unit-darwin.txt`, `unit-linux.txt`;
- reproduction logs: `repro-darwin.txt`, `repro-darwin-tui.txt`, `repro-linux.txt`.

The canary string does not appear in `diff.patch`.

## Known gaps

- **Windows is compile-checked only** (vet and build). Native behavior has not been run for a link to a
  regular file, a link to a named pipe, or a junction.
- **The check-then-open race is tested only through the in-process hook.** No test races a real
  concurrent writer.
- **A concurrent replacement of a link's target is refused.** If the target is swapped atomically
  between the stat and the open, the result is `USAGE_ERROR` "not a regular file". That was the existing
  behavior for plain paths too. A retry would be friendlier, but it is out of scope.
- **No independent review.** No reviewer agent was available in this run; this is self-review only.
- **Housekeeping.** The harness run created `tests/g02/__pycache__` (Python bytecode), which I removed.
  `tests/g02/.venv` and the fixtures were not modified. Build outputs are in `prototypes/go/dist/`,
  which is excluded from `diff.patch`.
