# T4-go-sonnet1: profile --file symlink bug

## Cause
profile.Load (prototypes/go/internal/profile/profile.go) used os.Lstat for its pre-open regular-file check
(chosen so a link could not be retargeted to a FIFO between check and open). Lstat reports a symlink as
ModeSymlink, so every link was refused as "profile path is not a regular file", even a link to a regular
file. Both `profile show` and `tui` call profile.Load, so both failed.

## Fix
- Load: Lstat first (non-links behave exactly as before, including on Windows). If the path is a symlink,
  os.Stat follows the whole chain (absolute, relative, chained, links in directory components); a dangling
  link or a loop is the existing "cannot be opened" USAGE_ERROR; a link whose final target is not a regular
  file (FIFO, socket, device, directory) is the existing "not a regular file" USAGE_ERROR.
- K14 safety is unchanged: the open is still O_NONBLOCK and the open descriptor is fstat-ed and
  must be a regular file and os.SameFile with the pre-check stat, so a regular file or link swapped to a FIFO
  after the pre-check cannot block or be read.
- open_unix.go: added O_NOCTTY to the non-blocking open, so a path swapped to a terminal device after the
  pre-check cannot become the controlling terminal.
- docs/, schemas/, tests/g02, fixtures were not touched.

## Tests (prototype's own go test framework)
- internal/profile/k14_test.go: removed the old assertion that a link to a regular file must be refused
  (it encoded the bug); added TestLoadFollowsSymlinkToRegularFile (absolute, relative, chain, link in a
  directory component, non-ASCII name) and TestLoadRejectsSymlinkToNonRegular (link to FIFO, socket,
  directory, /dev/null, dangling link, chain to FIFO, loop, each within 2 s; descriptor check on a FIFO link).
- cmd/heimdall-proto/main_test.go: TestProfileShowFollowsSymlink (absolute and relative link give byte-identical
  stdout/stderr/exit as the file, with and without --json; link to directory is USAGE_ERROR).
- cmd/heimdall-proto/tui_symlink_test.go (darwin/linux): TestTUIFollowsSymlink runs the binary on a pty:
  regular file, absolute link and relative link start the picker and `q` exits 0 with alt screen entered/left;
  a link to a FIFO exits 2 within 2 s without entering the alt screen.
- Verified the new tests fail against the original profile.go (3 failing tests) and pass with the fix.

## Results (real exit codes)
- gofmt -l: no output; go vet ./...: clean.
- `HEIMDALL_G02_FIXTURES=<ws>/tests/fixtures/g02/profiles go test ./...` in prototypes/go: exit 0, all packages ok.
- `sh prototypes/go/build.sh`: exit 0; built darwin-arm64, linux-x64, linux-arm64, windows-x64 (same four targets as before).
- Darwin harness (conformance.py --candidate go): exit 0, 139 total / 139 pass, status=verified verdict=pass.
  Record: /tmp/x2ws-348d4844/scratch/harness-darwin.json
- Linux harness (tests/g02/linux/run.sh, linux-arm64 artifact): exit 0, 139 total / 139 pass, status=verified verdict=pass.
  Record: /tmp/x2ws-348d4844/scratch/harness-linux.json
- Manual repro with the built darwin artifact: absolute and relative links to homelab.toml give PROFILE_OK;
  a link to a FIFO gives USAGE_ERROR.

## Known gaps
- Windows: compile-checked only (build.sh target built); the Windows path uses the same Lstat/Stat logic and was never run.
- The harness has no symlink check of its own; symlink behavior is covered only by the new unit tests and the manual repro.
- A symlink swapped to a character device after the pre-check is opened non-blocking with O_NOCTTY and then
  refused by the descriptor check; a device open can still have driver side effects (inherent to any open-then-check).
- The Linux unit tests were not run natively (only darwin go test); the Linux binary passed the full Linux harness.
