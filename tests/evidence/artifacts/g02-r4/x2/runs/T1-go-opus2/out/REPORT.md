# T1-go-opus2: exec-equivalent job control for `heimdall-proto run` (Go prototype)

Workspace: /tmp/x2ws-c8f87a99/heimdall (git init, starting commit 1f6e7a8 "starting point").
Scratch: /tmp/x2ws-c8f87a99/scratch. Patch: diff.patch (8 files, +1004/-34; no build outputs; nothing under docs/, schemas/, tests/).

## What changed and why

Baseline behaviour, checked against a plain-exec control in the same environment (my scenario driver, scratch/scen/scen.py, and the new Go tests):

| | darwin baseline | linux baseline |
|---|---|---|
| S1 (non-shell parent with a controlling terminal, stdio files) | launcher never exits (child zombie) | same |
| S2 SIGSTOP | launcher exits 255, child killed by the orphan hangup | `$?` 148, plain 147 |
| S2 SIGTSTP, S3 | ok | ok |
| S4 (nested bash `suspend`) | launcher exits 255; outer shell disrupted | ok (but stop reported as SIGTSTP) |
| S5 (SIGSTOP + --meta-file) | exit 255, meta `exit_code: -1` | `$?` 148, plain 147 |

Three causes, three fixes (prototypes/go/internal/run):

1. **darwin wait-status decoding** (new waitstatus_unix.go). Go's syscall/x-sys `WaitStatus` on BSD treats a SIGSTOP stop as a continue: it compares the stop signal with SIGSTOP, where `<sys/wait.h>` compares it with 0x13 (SIGCONT). heimdall-proto then took the stop for an exit with status -1. `wstatus` decodes the raw word as the C macros do on both OSes and `startAndWait` uses it.
2. **Exact stop signal**. `mirrorStop` used to mirror SIGSTOP as SIGTSTP. It now stops heimdall-proto with the child's own stop signal (SIGSTOP included), so the notice and `$?` (128+N) equal plain exec. Only SIGTTOU stays mapped to SIGTSTP (heimdall-proto ignores SIGTTOU for tcsetpgrp). heimdall-proto stops itself with `kill(getpid())` instead of `kill(0)` (K6a).
3. **Mirror only what a shell can see** (`shouldMirror`). A stop is mirrored when the job holds the terminal foreground (child's or heimdall-proto's group), or when it is SIGTTIN/SIGTTOU (background terminal access). A third party's stop while the job is not in the foreground (S1) is not mirrored: heimdall-proto keeps waiting, the third party's SIGCONT continues the child, and heimdall-proto exits with the child's status. In an orphaned group a SIGSTOP stop is now left in place (as with plain exec) instead of being undone.

S3 needed no change: after its own SIGCONT, heimdall-proto continues the child (and hands it the terminal only after `fg`); the child's background read then stops with SIGTTIN, which is mirrored. S2 ends via the permitted deviation (b): the job stays listed as stopped until `fg`, which ends it with the child's status.

The mechanism, the causes and the known gaps are documented in prototypes/go/REPORT.md (new section "X2 task T1"; one inline update in Round 3c) and in the header comment of run_unix.go.

Tests added (Go `testing`):
- internal/run/waitstatus_test.go: synthetic status words, real children stopped by SIGSTOP and SIGTSTP, and a `shouldMirror` table. run_test.go has a new `selfstop` helper mode.
- cmd/heimdall-proto/jobctl_test.go (+ procstate_{darwin,linux}_test.go): S1-S5 end to end, each with a plain-exec control that must behave as TASK.md says (control failure = precondition failure). S1: non-shell parent without/with a controlling terminal, stdio files/pipes, SIGSTOP/SIGTSTP. S2-S5: `bash --norc --noprofile -i` and `zsh -f -i` on a pty; S2 both signals, S5 both triggers. `-short` skips the shell scenarios.

## Results (exit codes as observed)

Build: `sh prototypes/go/build.sh` exit 0, all four targets built (darwin-arm64, linux-x64, linux-arm64, windows-x64). A final rebuild gave byte-identical darwin-arm64 and linux-arm64 artifacts to the ones tested (see artifacts.json).
Compile/vet: `go vet ./...` exit 0 for darwin, linux/arm64 and windows/amd64; `GOOS=windows go test -c ./internal/run` exit 0; gofmt clean.

Unit tests:
- darwin-arm64: `go test -count=1 -v ./...` exit 0 (scratch/darwin-gotest.log); all 5 new job-control tests and 3 new internal/run tests pass.
- linux-arm64: cross-compiled test binaries (`go test -c`, CGO_ENABLED=0) run in heimdall-g02-harness:d0c8e448a3a7 with run.sh's docker flags (uid 10001, no network, caps dropped): exit 0 for all 5 packages (scratch/linux-gotest.log). One pre-existing skip: TestGuardAcceptsValidCorpus (needs a Go toolchain in the container).
- Red check: the new cmd tests against the baseline run_unix.go (copy in scratch/redcheck, darwin) exit 1. S1 (ctty, files, SIGSTOP and SIGTSTP; proto), S2, S4 and S5 (proto, bash and zsh) failed; S3 passed.

Shared harness 2.4.2 (read-only), artifacts from this build:
- darwin: `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/go/dist/darwin-arm64/heimdall-proto --candidate go --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` exit 0, 139/139 pass, status verified, verdict pass.
- linux: `sh tests/g02/linux/run.sh --artifact-dir prototypes/go/dist/linux-arm64 --candidate go --out scratch/harness-linux.json` exit 0, 139/139 pass, status verified, verdict pass.
- No non-gating assertion failed in either record. The `run.k6e_child_self_stop` SIGSTOP observations (bash and zsh), previously deviating, now equal the direct-exec control on both OSes (darwin 145, linux 147).
- Repeat of 7 job-control/signal checks (`--only run.k6e_job_control,run.k6e_child_self_stop,run.k6a_child_self_stop_not_spread,run.k6a_pipeline_peer_not_stopped,run.k6a_background_script_tty,run.explicit_signal_with_tty,run.k6d_shared_mode_explicit_signals`): 7/7, exit 0 on each OS (status in_progress as for any partial run).

Scenario driver (scratch/scen/scen.py, plain vs proto, `--reps 2`): darwin 80/80 ok, exit 0; linux (same image) 80/80 ok, exit 0. The notice word and `$?` of every proto run equal the plain control's. All 8 S2 proto runs per OS ended through deviation (b).

## Known gaps

- S2 uses the permitted deviation (b); the job never finishes on its own while heimdall-proto is stopped.
- A third party's stop of the child while the job is in the background of an interactive shell (`&`/`bg`) is not mirrored (plain exec would show "Stopped").
- S3: between heimdall-proto's continue and the mirrored SIGTTIN stop there is a short window (not measured) in which the shell may list the job as running while the child is stopped. It was never seen in the sampled `jobs` output.
- SIGTTOU stops are reported as SIGTSTP.
- An explicit SIGTSTP/SIGSTOP to the heimdall-proto PID still stops only heimdall-proto (§9.4, recorded; outside T1).
- A non-shell parent that gives heimdall-proto's group the terminal foreground and then has a third party stop and continue only the child would still leave heimdall-proto stopped. From inside it cannot be told from a job-control shell.
- The hidden black-box tests were not available. My scenarios are my reading of TASK.md, and the timing (0.5 s, 6 s) follows it.
- The darwin harness run left a `tests/fixtures/fake-agent/__pycache__` byte-code directory; I removed it, and it is not in the patch.
