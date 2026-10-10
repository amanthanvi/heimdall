# T1-go-opus1: exec-equivalent job control for `heimdall-proto run` (Go prototype)

Workspace: /tmp/x2ws-4c8e064b/heimdall (git-initialised; starting commit `db74ced`). Scratch: /tmp/x2ws-4c8e064b/scratch.
Diff: `diff.patch` (git diff from `db74ced`, `prototypes/go/dist` excluded). Artifacts: `artifacts.json`.
Only `prototypes/go/` changed (internal/run, new tests, REPORT.md). `docs/`, `schemas/`, `tests/g02/` and fixtures are untouched
(a `__pycache__` the harness created under tests/fixtures/fake-agent was removed).

## What was wrong (observed on the base build; plain exec in the same environment as control)

Scenario driver: scratch/scen/scen.py (real bash/zsh in a pty; plain and heimdall-proto runs), judged by scratch/scen/compare.py.
Base results: scratch/base-s1.json, s1pty.json, base-s2345.json (darwin), base-linux.json (linux-arm64 container).

| Scenario | Base build | Cause |
|---|---|---|
| S1, controlling terminal present, stdio /dev/null | darwin SIGSTOP: exit 255 at once, child gone before its SIGCONT. darwin SIGTSTP and Linux SIGSTOP/SIGTSTP: heimdall-proto stopped itself and never exited (timeout, child zombie) | every child stop was mirrored by a self-stop even when no shell watches the job |
| S2/S4/S5 with SIGSTOP | darwin: exit 255 at once, no stop notice, meta `exit_code: -1`. Linux: stop reported as SIGTSTP (`$?` 148 vs 147) | darwin: Go's BSD `syscall.WaitStatus.Stopped()` is false for a SIGSTOP stop, so the wait loop treated it as an exit with status -1. Both: SIGSTOP was mirrored as SIGTSTP by design |
| S1 without a controlling terminal, S1 with pipe stdio, S3 | matched plain exec | - |

## What changed (prototypes/go/internal/run)

- `run_unix.go`: wait statuses decoded from the bits (`decodeWait`), same layout on Linux and BSD. A `supervisor` replaces
  `mirrorStop`/`stopSelf`:
  - a child stop is mirrored with the child's own signal (SIGSTOP included) by `kill(getpid(), sig)` (own PID only, K6a);
    SIGTTOU is still mirrored as SIGTSTP because heimdall-proto ignores SIGTTOU;
  - a stop is mirrored only if a job-control shell can be watching (terminal foreground is heimdall-proto's or the child's
    group, or a stdio fd is the controlling terminal); otherwise (S1) heimdall-proto keeps waiting, as plain exec would;
  - every SIGCONT heimdall-proto receives continues the child (after handing it the terminal if heimdall-proto's group holds
    the foreground), which is where plain exec's SIGCONT would have gone (S3, `fg`, `bg`); a zombie child is left to the reaper;
  - a stop report is acted on only if the child is still stopped (`childState`), so a stale report never stops heimdall-proto;
  - the mutex is no longer held while heimdall-proto is stopped; a `stopping` flag keeps the 50 ms handoff poll quiet;
  - orphaned group: no self-stop; terminal stops are undone, a SIGSTOP is left for its sender.
- `group_linux.go` / `group_darwin.go` / `group_other.go`: `childState` (/proc/<pid>/stat; sysctl kern.proc.pid p_stat; unknown).
- `run_windows.go`: unchanged.
- `REPORT.md`: stale statements marked "[X2 T1 update]", new section "X2 T1 (2026-10-09)".

## Tests added (Go `testing`)

- internal/run/jobctl_test.go: `TestDecodeWait` (table incl. BSD SIGSTOP and both WIFCONTINUED encodings),
  `TestDecodeWaitRealStop` (real SIGSTOP stop / continue / death / reap, with `childState`).
- cmd/heimdall-proto/jobctl_test.go (+ jcstate_{linux,darwin}_test.go): a minimal job-control shell helper (session leader on
  a pty, job in its own foreground group, WUNTRACED, `fg`/`bg` on request) records the wait statuses a shell bases its notice
  and `$?` on. Tests: S2 (SIGSTOP, SIGTSTP), S3, S5 (self and third-party SIGSTOP, `--meta-file`), Ctrl-Z/`bg`/`fg`,
  S1 with a non-shell parent (SIGSTOP, SIGTSTP).
- Red check: with the base `internal/run` code these tests fail on darwin (`exited 255` x3; S1 launcher state ""/"T") and on
  linux-arm64 (`stopped SIGTSTP` x3 for SIGSTOP; S1 launcher state "T"). With the change they pass.

## Results (real exit codes)

| Command | Exit | Result |
|---|---|---|
| `sh prototypes/go/build.sh` (final) | 0 | darwin-arm64 (signed ad-hoc, hardened runtime), linux-x64, linux-arm64, windows-x64 all built |
| `go vet ./...` for darwin/arm64, linux/arm64, linux/amd64, windows/arm64, windows/amd64; `gofmt -l` | 0 each; empty | |
| `GOOS=windows go test -c` for the 5 test packages | 0 each | Windows path compiles, tests compile |
| `go mod verify` | 0 | no dependency change |
| darwin `go test -count=1 ./...` (final) | 0 | all packages ok (scratch/unit-darwin.txt) |
| linux-arm64 test binaries (`GOOS=linux go test -c`), run in the harness image, all 5 packages (final) | 0 each | scratch/unit-linux.txt |
| job-control tests `-count=10`, darwin and linux-arm64 | 0, 0 | no flake in 10 repetitions |
| `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/go/dist/darwin-arm64/heimdall-proto --candidate go --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` | 0 | 139/139 pass, verdict pass |
| `sh tests/g02/linux/run.sh --artifact-dir prototypes/go/dist/linux-arm64 --candidate go --out scratch/harness-linux.json` | 0 | 139/139 pass, verdict pass |
| scenario driver, final binaries, plain + proto, bash and zsh (scratch/final-scen-{darwin,linux}.json) | 0, 0 | 20/20 heimdall-proto runs meet S1-S5 per platform; stop notices equal plain exec's |

An earlier build (v1, differing only in darwin `childState` for a missing pid) also passed both harnesses 139/139 (scratch/h1)
and two more full scenario passes per platform (scratch/v1-*-full{1,2}.json). The non-gating `run.k6e_child_self_stop`
notice/status comparison now equals the control for SIGSTOP too (darwin bash 145 / zsh "suspended (signal)"; Linux 147).

Scenario coverage: S1 SIGSTOP/SIGTSTP x stdio {/dev/null, pipes} x {no controlling terminal, inside a pty session};
S2 SIGSTOP/SIGTSTP; S3; S4 (outer bash and zsh, nested `bash --norc --noprofile -i`, `suspend`, `fg`, `exit 3`);
S5 self and third-party SIGSTOP with `--meta-file`; all under bash and zsh on darwin (bash 3.2.57, zsh 5.9) and in the
linux-arm64 harness container (bash 5.2.15, zsh 5.9).

## Known gaps

- S2 uses the permitted deviation (b): heimdall-proto stays stopped after the third party continues only the child, so the
  shell lists the job stopped until `fg`, which ends it with the child's status (child is a zombie until then).
- A SIGTTOU stop of the child is still reported as SIGTSTP (heimdall-proto ignores SIGTTOU). Not in S1-S5.
- The S1 rule is a heuristic: a non-shell parent that gives heimdall-proto's group the terminal foreground or the terminal on
  stdio is treated like a shell.
- Unchanged: explicit SIGTSTP/SIGSTOP to heimdall-proto's PID stops only heimdall-proto (§9.4 recorded item); SIGCONT is
  propagated to the child only in modeExclusive.
- The black-box acceptance tests were not available; my scenario driver is my own approximation of them.
- No independent (adversarial) review was performed; this is self-review only.
- Processes: only processes this task started were signalled, by exact PID; no heimdall-proto process from this workspace was
  left running at the end (other workspaces' processes were not touched).
