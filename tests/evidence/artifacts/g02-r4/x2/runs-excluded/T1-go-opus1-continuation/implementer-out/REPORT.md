# T1-go-opus1: exec-equivalent job control for `heimdall-proto run` (Go prototype)

Workspace `/tmp/x2ws-27f9aa4a/heimdall`. Starting commit `12f71db` ("x2 start"), which already existed. The
workspace also held uncommitted partial work from an earlier, interrupted attempt at this task: it had modified
`run_unix.go` and `REPORT.md`, added new proc/test files, and left `out/` empty. I did not re-commit, so that work
could not become the baseline. I measured from `12f71db`, reviewed the partial work and kept and extended what held
up. The earlier scratch files were moved, not deleted, to `scratch/prior-attempt-20261006/`. Every result below
comes from my own runs.

## What changed (only `prototypes/go`; `diff.patch`, 9 files, +1536/-88)

`internal/run/run_unix.go` (the Unix `run` launcher):

1. **Raw wait-status decode (`decodeWait`)**. Go's BSD `syscall.WaitStatus` reports a SIGSTOP stop as
   "continued": it compares the stop signal with SIGSTOP, while darwin's WIFCONTINUED marker is 0x13. On darwin a
   SIGSTOP of the child therefore made the launcher exit 255 and orphan a stopped child (§9.5). This was the root
   cause of the darwin failures in S2-SIGSTOP, S4 and S5.
2. **Mirror with the child's own stop signal**. `$?` is then 128 + the signal, as with plain exec: SIGSTOP stays
   SIGSTOP (Linux previously reported 148 instead of 147). SIGTTOU becomes SIGTSTP. A stop signal the launcher
   inherited as ignored becomes SIGSTOP. The launcher stops only itself (`kill(getpid())`, K6a).
3. **Mirror only when a job-control shell can see the stop**. That means our job or the child's group holds the
   terminal foreground, or a background job got SIGTTIN/SIGTTOU. Any other stop is left in place, as with plain
   exec, and the launcher keeps waiting (S1). A stale stop report (the child already continued, checked via
   `/proc/<pid>/stat` or darwin `kern.proc.pid`) is ignored.
4. **Orphaned groups**. modeNoTTY now also waits with WUNTRACED. When the launcher's group is orphaned, a
   SIGTSTP/SIGTTIN/SIGTTOU stop of the child is undone, because the kernel would discard it under plain exec. The
   child's own group is never orphaned, so the kernel cannot do this for us. A SIGSTOP stop is left in place.
5. **SIGCONT forwarding**. A SIGCONT the launcher receives outside its own mirrored stop is forwarded to the
   child's group. Plain exec would deliver it to the child, for example `kill -CONT %1`.
6. **`fg` of a background job whose child a third party stopped**. Because of rule 3 the shell believes the job
   is running, and bash's and zsh's `fg` then send no SIGCONT. I found this as a regression risk of the
   prior-attempt design: the job would hang with a stopped child in the foreground. The terminal-handoff poller now
   continues a stop that was left in place when the job gets the foreground.
7. **Concurrency**. The shared state now lives in a `job` struct. The mutex is no longer held while the launcher
   is stopped. A `mirroring` flag tells the SIGCONT handler to end the mirror rather than forward the signal, and
   keeps the poller off the terminal.

New `internal/run/proc_{darwin,linux,other}.go` provide `processStopped` and `selfIgnores`. The Windows path is
unchanged and builds.

S2 uses permitted deviation (b). While the launcher is stopped it cannot see the third party continue the child,
so the shell lists the job stopped until `fg`, which ends it with the child's status. S3 already worked at the
starting commit on darwin. It is kept and tested.

## Tests (prototype's Go `testing`)

`cmd/heimdall-proto/jobctl_test.go` runs every scenario first as **plain exec**, as a precondition control in the
same pty/shell environment, then under heimdall-proto, and compares the two. The shells are real
`bash --norc --noprofile -i` and `zsh -f -i`. The tests cover:

- S1: direct and ctty layouts × SIGSTOP/SIGTSTP.
- S2: bash/zsh × SIGSTOP/SIGTSTP.
- S3 and S4: bash/zsh.
- S5: bash/zsh × self/third-party, including the meta file `CHILD_EXITED {launched:true, exit_code:0, signal:null}`.
- New: the orphaned no-tty SIGTSTP/SIGSTOP case.
- New: a background job whose child a third party stops, followed by `fg` (bash/zsh).

`internal/run/wait_test.go` covers decode, process state and `mirrorSignal`.

Red checks on darwin, with scratch copies of the package:

- **Starting-commit `internal/run`, new tests:** exit 1. The new tests fail S1 ctty (both signals), S2 SIGSTOP
  (bash, zsh), S4 (bash, zsh), S5 (all 4), orphaned SIGTSTP and the background case (bash, zsh).
- **Poller continue disabled:** the background test fails, exit 1.
- **modeNoTTY WUNTRACED disabled:** orphaned SIGTSTP fails, exit 1.

## Results (real exit codes)

| Command | Exit | Result |
|---|---|---|
| `sh prototypes/go/build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64, windows-x64 all built |
| `go test -count=1 ./...` (darwin-arm64 host, bash 3.2.57, zsh 5.9) | 0 | all packages ok |
| cross-compiled `go test -c` binaries in the harness image `heimdall-g02-harness:d0c8e448a3a7` (linux-arm64, `--network none`, uid 10001, `--cap-drop ALL`, workspace read-only) | 0 (every package) | all job-control tests pass under bash 5.2 and zsh; the pre-existing `TestGuardAcceptsValidCorpus` skip is there because the image has no Go toolchain |
| `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/go/dist/darwin-arm64/heimdall-proto --candidate go --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` | 0 | 139/139 pass, verdict pass |
| `sh tests/g02/linux/run.sh --artifact-dir prototypes/go/dist/linux-arm64 --candidate go --out scratch/harness-linux.json --artifacts-out scratch/harness-linux` | 0 | 139/139 pass, verdict pass |
| `GOOS=freebsd go build ./...`; `go vet` for darwin, linux/arm64, windows/amd64 | 0 | fallback and Windows paths compile |
| `git apply` of `diff.patch` onto a clean export of `12f71db`, then build | 0 | the patch applies and builds |

Non-gating harness observation `k6e_child_self_stop`: all four forms (bash/zsh × SIGTSTP/SIGSTOP) are ok on both
OSes. The stopped-job status equals the control's (darwin 146/145, Linux 148/147), and `resumed_before_fg` is
false everywhere. Before this change, darwin SIGSTOP got no stop notice and Linux SIGSTOP was reported as 148.

Evidence (outside the workspace) is in `/tmp/x2ws-27f9aa4a/scratch/`:

- `build.log`, `unit-darwin.txt`
- `linuxtests/summary.txt`, `linuxtests/out/*.txt`
- `harness-{darwin,linux}.json` and `.log`, with per-check artifacts in `harness-{darwin,linux}/`
- `red-*.log`, made by the red-check script `tools/redcheck.sh`

## Known gaps

- **Background-job stops nobody sees.** A third party stops the child of a background job of an interactive
  shell. The shell lists the job as Running, while plain exec shows it Stopped. `fg` and `kill -CONT %n` work. `bg`
  does not continue the child, because the shell sends no SIGCONT to a job it believes is running.
- **Mirroring is decided by the terminal foreground alone.** Two cases follow from this, because a launcher inside
  the job cannot tell a job-control shell from another parent:
  - A non-shell parent that puts the launcher's group in the terminal foreground (not orphaned) gets a third-party
    stop mirrored. Nobody then continues the launcher.
  - A third-party stop of the child while a group the child created holds the terminal (a nested shell running a
    foreground command) is not mirrored.
- **SIGCONT race.** A SIGCONT that reaches the launcher within microseconds of a child's stop, before the launcher
  has stopped, can end the mirror early. This is unchanged from round 3b.
- **SIGTTOU is reported as SIGTSTP**, because the launcher ignores SIGTTOU for `tcsetpgrp`.
- **An explicit SIGTSTP/SIGSTOP to the launcher's PID** still stops only the launcher (§9.4, outside S1-S5).
- **Platform coverage.** I could not run the hidden black-box S1-S5 tests. My tests are an approximation built
  from TASK.md. Linux was tested only in the harness container on the Docker Desktop arm64 VM.
- **No independent adversarial review.** None was obtained in this run, and the design self-review is not
  independent evidence.
- **Leftover cache.** `tests/fixtures/fake-agent/__pycache__/` is an untracked bytecode cache created by running
  the harness. It is not part of the patch, and I left it in place.
