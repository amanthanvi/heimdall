# T4-go-opus2: symlinked `--file` rejected by `profile show` and `tui`

## Cause
`internal/profile/profile.go` `Load` checked the path with `os.Lstat`. Lstat describes the link
itself (mode `L`), so `IsRegular()` was false for every symlink, including one that points to a regular
profile, and both `profile show` and `tui` (which share `Load`) returned exit 2 USAGE_ERROR
"profile path is not a regular file". The old unit test even asserted that refusal. The contract
(K14) only says non-regular *files* (FIFO, socket, device, directory) are refused. It says nothing
against symlinks.

## Fix
- `Load` now uses `os.Stat` (follows links), so the decision depends on the final target. The rest of
  the K14 defence is unchanged and now also covers links: open with `O_NONBLOCK` (a link retargeted to a
  FIFO after the check cannot block the open), then `fstat` on the descriptor must be a regular file and
  `os.SameFile` with the first check, so a swap between the checks is refused before any byte is read.
- `open_unix.go`: added `O_NOCTTY`, so a path swapped to a terminal in that window cannot become the
  controlling terminal before fstat refuses it. Small hardening.
- Comments updated (`profile.go`, `open_unix.go`, `open_windows.go`). The Windows path uses the same
  `Load`. On Windows it is still compile-checked only.
- `prototypes/go/REPORT.md` K14 row: noted the change.

## Tests (Go `testing`)
- `internal/profile/symlink_test.go` (new): absolute, relative, chained links and a path through a
  directory link load to the same `Profile` as the target. A link to a schema-invalid file gives the
  same error as the file. A link to an oversize file is INPUT_TOO_LARGE. Dangling links and link loops
  are USAGE_ERROR within 2 s. A link retargeted to a FIFO after Stat does not block the open and fails
  the fstat/SameFile check.
- `internal/profile/k14_test.go`: removed the "symlink to a regular file is refused" assertion (the bug).
  Added links to a FIFO (absolute, relative, chained), a socket, a directory and /dev/null. All must be
  USAGE_ERROR within 2 s.
- `cmd/heimdall-proto/symlink_test.go` (new): bug-report layout. `profile show` through each link gives
  byte-identical stdout/stderr/exit to the file, with and without `--json`. Links to a FIFO, directory,
  /dev/null or a missing file give exit 2 USAGE_ERROR within 2 s. `tui` through each link in a real pty
  draws and exits 0 on `q`. `tui` through a link to a FIFO exits 2 within 2 s without drawing.
- `tui_terminfo_test.go`: `runTUIEnv` refactored to `runTUIFile(t, file, env)`. Behaviour unchanged.
- Red/green observed: with `os.Lstat` temporarily restored, `TestLoadFollowsSymlinkToRegularFile`,
  `TestProfileShowSymlink` and `TestTUISymlink` failed. With the fix they pass.

## Results (real exit codes)
- `go vet ./...` exit 0; `GOOS=windows go vet ./...` exit 0.
- `HEIMDALL_G02_FIXTURES=<ws>/tests/fixtures/g02/profiles go test -count=1 ./...` on darwin-arm64: exit 0 (all packages ok).
- `sh prototypes/go/build.sh`: exit 0. darwin-arm64, linux-x64, linux-arm64 and windows-x64 all built
  (`built: true` in dist/manifest.json). darwin is ad-hoc signed with hardened runtime.
- Darwin harness `tests/g02/conformance.py --bin dist/darwin-arm64/heimdall-proto --candidate go`:
  exit 0, 139/139 pass, status=verified verdict=pass (scratch/harness-darwin.json).
- Linux harness `tests/g02/linux/run.sh --artifact-dir dist/linux-arm64 --candidate go`: exit 0,
  139/139 pass, status=verified verdict=pass (scratch/harness-linux.json).
- Linux unit tests: test binaries cross-compiled with `GOOS=linux GOARCH=arm64 go test -c` and run
  inside the harness image (`--network none`, uid 1000). `profile.test` exit 0, `heimdall-proto.test`
  exit 0, including the three new symlink tests (scratch/linux-unit-and-repro.log).
- Bug-report reproduction with the built artifacts:
  - darwin and linux: `profile show` on the file, the absolute link and the relative link gave exit 0,
    with and without `--json`. The JSON through the link is byte-identical to the file's. A link to a
    FIFO gave exit 2.
  - darwin `tui` via a pty probe: the file and both links drew and exited 0 on `q`. The link to a FIFO
    exited 2 immediately without drawing.

## Known gaps
- Windows behaviour is compile-checked only. `os.Stat` follows symlinks there too. No native Windows
  run was done.
- The swap race between Stat and open cannot be forced from outside. The test exercises the same
  sequence by retargeting the link between a Stat and the open.
- The harness run created `tests/fixtures/fake-agent/__pycache__/`. I deleted it, so the fixtures tree
  is unchanged.
