# X2 T1 (go, sonnet1): exec-equivalent job control for `heimdall-proto run`

Workspace: /tmp/x2ws-8da57df3/heimdall (git init, starting commit 654bd28). Diff: ../out/diff.patch (4 files, +680/-13, dist excluded).

## What was wrong (observed, with the starting build)

Measured with my own pty driver (bash 3.2 and zsh 5.9 on darwin-arm64; bash 5.2.15 and zsh 5.9 in the linux-arm64 harness image), plain exec as control, with the unmodified build:

1. **SIGSTOP stop of the child (S2 SIGSTOP, S4 `suspend`, S5), both platforms.** The stop was mirrored onto the launcher as SIGTSTP. So `$?` was 128+SIGTSTP (148 on linux) instead of 128+SIGSTOP (147), and zsh printed "suspended" instead of "suspended (signal)".
2. **Same on darwin, worse.** Go's `syscall.WaitStatus` on the BSDs reports a SIGSTOP stop as "continued" (`Stopped()` false). The launcher took it for an exit with `ExitStatus() == -1`, exited 255, wrote `exit_code: -1` to the meta file, and left the child stopped. In the cases I ran the child was then gone (SIGCONT got ESRCH); I infer the kernel's orphaned-group SIGHUP, I did not trace it.
3. **S1 (non-interactive parent).** If the launcher has a controlling terminal (reachable through /dev/tty), no terminal on stdio and no pipe on stdin/stdout, it chose its job-control mode and, when a third party stopped the child, stopped itself. Nobody waits for it with WUNTRACED, and the third party's SIGCONT goes to the child only, so the launcher never exited. Reproduced for SIGSTOP and SIGTSTP, stdout to file or /dev/null, on both platforms. Without a controlling terminal, or with a pipe on stdin/stdout, the old code was fine.
4. **S3** (child self-stop, SIGCONT to the launcher only) already matched plain exec in all my runs on both platforms and both shells (jobs: stopped after the background read; no "running" state while the child is stopped, sampled every 150 ms; `fg` gives the terminal back; `$?` = child's). I did not find a failing case; the new tests pin it.

## What I changed (prototypes/go/internal/run/run_unix.go)

- `stopSignal(ws)`: decodes the raw wait status (same bits on darwin and linux; linux's 0xffff "continued" is not a stop). Replaces `ws.Stopped()/StopSignal()`.
- The mirrored stop uses the child's own stop signal, SIGSTOP included. Only SIGTTOU is still mirrored as SIGTSTP (the launcher ignores SIGTTOU for `tcsetpgrp`, and os/signal cannot restore SIG_DFL). An orphaned launcher group is still not stopped (unchanged `stopSelf`).
- `mirrorStop` mirrors only when the launcher is "engaged" with a job-control parent: a terminal on stdio at start, or the launcher's or the child's process group holding the terminal foreground at start, at the handoff, or at a stop. Once engaged it stays engaged. Otherwise a stop is left alone, as plain exec leaves it (S1).
- Comments updated; a section was appended to prototypes/go/REPORT.md. No change under docs/, schemas/, tests/g02/ or the fixtures. Windows code untouched.

## Behaviour now, compared with plain exec (my driver, tests/ below)

| Scenario | Result on darwin-arm64 and linux-arm64, bash and zsh |
|---|---|
| S1, SIGSTOP and SIGTSTP; launcher in its own non-orphaned group; stdio devnull / file / pipes; with and without a controlling terminal | same as plain: exit 7 within about 1.3 s of SIGCONT, nothing left |
| S2, SIGSTOP and SIGTSTP from a third party, SIGCONT to the child only | stop notice, `$?` = 128+signal (same notice text in zsh); child not killed; then permitted deviation (b): the job stays listed as stopped; `fg` ends it with status 7, no job left, nothing left behind. Plain exec instead shows the job finishing on its own (a) |
| S3 | same as plain (see above) |
| S4 `suspend` in nested bash, `fg`, `exit 3` | same as plain: notice, `$?` 147 (linux) / 145 (darwin), prompt back after `fg`, outer `$?` 3 |
| S5 SIGSTOP by the child itself or by a third party, `--meta-file` | same as plain: notice, `$?` = 128+SIGSTOP, child stays stopped and launcher alive until `fg`, input reaches the child, `$?` 0, meta `CHILD_EXITED`, `exit_code` 0, `signal` null |

## Verification (real runs; exit codes as logged)

- `sh prototypes/go/build.sh`: all four targets built (manifest lists darwin-arm64, linux-x64, linux-arm64, windows-x64 as built); exit status was not captured separately (the compound command's `$?` was `tail`'s), the manifest is the evidence. `gofmt -l .` empty; `go vet ./...` clean for host (darwin), linux/amd64 and windows/amd64.
- `go test ./... -count=1` on darwin-arm64: all packages `ok` (cmd/heimdall-proto 58.9 s, internal/run 0.3 s, ...), exit 0.
- New tests: `TestStopSignalDecode` (internal/run) and `TestJobControl*` (cmd/heimdall-proto/jobcontrol_test.go; S1-S5, plain exec as control where the shell behaviour is compared, bash and zsh, 20+ subtests). Pass on darwin (bash 3.2, zsh 5.9). On linux-arm64 the cross-compiled test binaries ran in the harness image (bash 5.2.15, zsh 5.9): `TestJobControl*` and the `internal/run` signal tests passed (that was before a test-only edit that makes the S1 test wait for a non-empty rc file; the whole file was re-run on darwin afterwards, the edit was not re-run on linux). Only those tests ran on linux, not the whole suite. Red check: with the starting `run_unix.go` (plus a shim for `stopSignal`), the S2/S4/S5 SIGSTOP subtests, all S1 subtests and the decode test fail.
- Harness 2.4.2 on the final artifacts: `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/go/dist/darwin-arm64/heimdall-proto --candidate go ...`: 139/139, exit 0 (../out/harness-darwin.json). `sh tests/g02/linux/run.sh --artifact-dir prototypes/go/dist/linux-arm64 --candidate go ...`: 139/139, exit 0 (../out/harness-linux.json). An earlier build (before the "engaged" refinement) also gave 139/139 on both.
- Artifacts: see artifacts.json (darwin-arm64 5d0be6ef..., linux-arm64 40668676...).

## Known gaps and limits

- The hidden black-box tests are unseen; my driver is a model of S1-S5. A launcher that is engaged by a terminal on stdio always mirrors (as before).
- S2 (b): after a third-party stop the shell lists the job as stopped until `fg`, even if the child was continued and finished. This is the permitted deviation; (a) is not reachable without a second process, which K16 forbids.
- The S1 fix is a heuristic: a launcher with a controlling terminal but no terminal on stdio and a background process group never mirrors a stop until its group holds the terminal foreground. A fully redirected background job of an interactive shell (`cmd >o </dev/null &`) is therefore not stop-mirrored until it is brought to the foreground. Plain exec would show it stopped.
- SIGTTOU stops of the child are mirrored as SIGTSTP (notice and `$?` differ from plain exec). An orphaned launcher group keeps the old behaviour: the stop is not mirrored and the child is continued at once.
- Only /bin/bash 3.2 and /bin/zsh 5.9 exist on this host; bash 5.x was exercised on linux only.
- The host was heavily loaded (load average above 11) during part of the work. One apparent S1 hang in roughly 150 runs was a race in my own driver (it read the rc file between the shell creating and filling it), not a launcher hang; I fixed the driver and the new Go test for that.
- Scratch (drivers, baseline build, harness logs) is in /tmp/x2ws-8da57df3/scratch. All processes and containers I started were stopped by exact ID.
