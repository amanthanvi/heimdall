# M00-T05-parity-r3c: Go vs Rust round-3c parity on the review3c stop/continue probes

Task: run the three probes the round-3c Rust reviewer ran (third-party stop/continue of the child, SIGCONT to the
launcher after a reported self-stop, nested job-control shell) and the Go reviewer's darwin SIGSTOP case against
**both** final round-3c builds, each with a plain-exec control, on darwin-arm64 (host) and linux-arm64 (harness
image). Observation only: no prototype was rebuilt or edited. Status of this record: `verified` for what is
tabled below on the two platforms named; nothing here is gated (contract §9.4/§9.5 rule these paths
recorded-not-gated).

## Subjects and environment (observed)

| item | value |
|---|---|
| go darwin-arm64 | `31c3ee17cc256129eb2c5b1cb12e83486fe9e2cb51d6dd12642d9642697a6ea6` = `prototypes/go/dist/manifest.json` (MATCH) |
| go linux-arm64 | `d55b4ffe4bffec7aef6c6b1577d9f0dc0ac885e9326038f59a8caaa6611803a9` = manifest (MATCH) |
| rust darwin-arm64 | `496684ed337f1260193a2a805f2b44a827efe9f69db6017fe58b0877e956c47b` = `prototypes/rust/dist/manifest.json` (MATCH) |
| rust linux-arm64 | `47160fdd0ee850db6fd4bbd5f5eea6b3359f5c4925b04c5c380f9fcde84d22c0` = manifest (MATCH) |
| binaries run | byte copies of the dist files in `<scratch>/bin/{go,rust}/<platform>/heimdall-proto` (copies re-hashed, same digests: `meta/sha256-copies.txt`) |
| darwin | macOS 27.0 (26A428), Darwin 27.0.0 arm64; bash 3.2.57, zsh 5.9, Python 3.14.8; host, `SSH_AUTH_SOCK` unset |
| linux | `heimdall-g02-harness:d0c8e448a3a7` (image id `sha256:5081bb560f9b…`, arm64, base `python:3.13-slim-bookworm@sha256:5024f48b…`, the tag `tests/g02/linux/run.sh` derives); Docker 29.8.1 linux/arm64, kernel 7.0.14-linuxkit aarch64; run.sh's exact `RUN_FLAGS` (`--network none --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --memory 2g --pids-limit 4096`); only `<scratch>` mounted (rw at /w), repository not mounted; bash 5.2.15, zsh 5.9, Python 3.13.16 |
| times (UTC) | darwin main 2026-10-06T04:40:17Z–04:58:31Z; linux main 04:59:22Z–05:06:00Z; repeats after that (`meta/repeats.console.txt`) |
| exit codes | every probe invocation exit 0 (`raw/*/exit-codes.txt`, `meta/*-run_all.exit.txt`), except the deadlocked darwin attempt (`run_extra exit=143`, harness defect H5) |

## Probes (all in `probes/`)

| file | origin | used for |
|---|---|---|
| `extstop.py`, `probe.py`, `child.py` | `g02-rust/review3c/probes/scripts/`, byte-identical (sha256 in `meta/probes-sha256-final.txt`) | 1a unchanged; probe.py `explicit` + `nested_shell` unchanged (last columns of tables 2 and 3) |
| `selfstop_detail.py`, `child3c.py` | `g02-go/review3c/probes/`, byte-identical | probe 4, unchanged, SIGSTOP, `exclusive` vs `control`, triggers `read` and `ext` |
| `extstop_plus.py` | new: extstop.py's procedure + child completion marker + post-exit reaping samples | probe 1a |
| `nonorphan.py` | new: runs a command in a new, non-orphaned process group | probe 1a "non-orphaned" rows (H6) |
| `extstop_pty.py` (v2) | new: probe 1 inside an interactive bash/zsh pty, job in the foreground | probe 1b |
| `contlauncher.py`, `nested.py`, `ptyshell.py` | new: clean forms of probe.py `explicit` (last step) and `nested_shell` (H2–H4) | probes 2 and 3 |
| `run_all.sh`, `run_extra.sh`, `run_linux.sh`, `summarize.py` | new: drivers and the table generator (`python3 probes/summarize.py raw > tables`) | — |

Every pty probe starts a fresh `bash --norc --noprofile -i` / `zsh -f -i` with `HOME`/`TMPDIR` in scratch; the
plain-exec control runs the identical command without `heimdall-proto run --`. Only PIDs the probe itself
learned (child, launcher, nested shell, its own pty shell) are signalled or killed, by exact PID.

## Probe-harness defects hit (marked; none changes a tabled outcome)

- **H1 (mine, extstop_pty.py v1).** When the child was already gone 0.5 s after the stop (Go, darwin, SIGSTOP), the
  probe's own `kill(child, SIGCONT)` raised ProcessLookupError and the row was lost. v2 records `cont_sent=false`
  and continues. v1 output kept in `raw/darwin-run1/pty/` (same outcomes for every other row).
- **H2 (review3c probe.py `explicit`, unchanged).** `jobs_says_running/stopped` for the SIGCONT-to-launcher step is
  read from the 300 characters *before* the terminal echo of the typed `jobs; echo JOBS-END2` line (the expect
  matches the echo, not the command output). It reports earlier screen text, not `jobs`. Example: Go darwin bash,
  both flags false although `jobs` printed `Stopped` (`raw/darwin/probe-go/bash-transcript-explicit-hp.txt`).
  `contlauncher.py` reads the output between the echo and an arithmetic marker (`JE-$((40+2))` → `JE-42`).
- **H3 (probe.py `explicit`).** Its first two steps (explicit SIGTSTP/SIGSTOP to the launcher, §9.4 recorded) run in
  the same job. With Go they leave the job stopped again right after `fg`, so the probe's `ping` input lines are
  executed by the outer shell (`/sbin/ping` with no host prints usage; no network traffic) and the later
  SIGCONT-to-launcher step starts from a different state (probe.py column: launcher S; clean probe: launcher T).
  Probe 2 therefore uses `contlauncher.py`, which starts each target in a fresh shell.
- **H4 (probe.py `nested_shell`).** When the outer shell exits (Go, darwin) the pty returns EIO and the scenario
  records only `exception OSError(5)`. `nested.py` records the outer shell's exit status.
- **H5 (mine, ptyshell.py v1 `Shell.close`).** A blocking `waitpid` without draining the pty master deadlocked on
  darwin: the SIGKILLed outer bash stayed in state `E` (tty drain). I stopped exactly the two PIDs of that attempt
  (its `sh run_extra.sh`, SIGTERM; its python probe, SIGKILL; identity checked by PID/PPID/elapsed time first),
  fixed `close()` to drain while reaping, and reran. Partial output: `raw/darwin-extra-deadlocked/`.
- **H6 (environment).** Both the Claude Code Bash tool (darwin) and `docker run` (linux, probe tree under PID 1)
  start the probes in an **orphaned process group**; the kernel then discards SIGTSTP sent to the control's child
  (control child stays `S`). The unchanged `extstop.py` SIGTSTP rows are therefore not a SIGTSTP test in that
  setting; the round-3c Rust reviewer's own darwin run was evidently not orphaned (its control child went `T`).
  Probe 1a is repeated under `nonorphan.py`, which gives the control the expected `T`.
- **H7 (contlauncher.py recovery step).** Recovery sends `fg` immediately after SIGCONT to the child. For Rust on
  linux bash (3/3 runs) the job was reported stopped again right after that `fg` (observed: the child printed
  `BACK-tstp-1`/`READY-2`, then bash printed `Stopped` after `fg`; inferred, not measured: the child read the tty
  in the background, got SIGTTIN, and the mirrored stop landed after `fg`), the typed line went to the shell and
  `exit` gave "There are stopped jobs" (rc 1). This is a secondary field of a non-gated path, timing-dependent by
  construction (inside Rust's 200 ms mirror grace, cf. §9.4 Q18), and was not characterized further.

## Results

Rows: control (plain exec) / go / rust × platform × shell. "Matches control" is computed by `summarize.py`
with the rule stated above each table.

### Probe 1a: non-interactive parent, third-party stop then SIGCONT of the child PID

`extstop_plus.py` (same procedure as review3c `extstop.py`, plus completion/reaping fields). "as launched" = the probe's process group as the tool/container starts it, which is an orphaned process group on both platforms (the kernel discards SIGTSTP to members of such a group, see the control). "non-orphaned" = same probe under `nonorphan.py`. Matches control = same launcher result (exit 7 within 6 s) and the child ran to `exit 7`. The last column is the unchanged `extstop.py` run (as launched).

| platform | group | signal | via | states 0.5 s after stop (child/launcher) | launcher result | child completed / reaped | matches control | unchanged extstop.py |
|---|---|---|---|---|---|---|---|---|
| darwin | as launched | SIGSTOP | control | T/- | exit 7 (1.05 s) | yes / yes | - | exit 7 |
| darwin | as launched | SIGSTOP | go | T/S | exit 7 (1.05 s) | yes / yes | yes | exit 7 |
| darwin | as launched | SIGSTOP | rust | T/T | **hung** (child Z, launcher T); after manual SIGCONT to launcher: exit 7 | yes / yes | no | hung; manual CONT: exit 7 |
| darwin | as launched | SIGTSTP | control | S/- | exit 7 (1.05 s) | yes / yes | - | exit 7 |
| darwin | as launched | SIGTSTP | go | T/S | exit 7 (1.06 s) | yes / yes | yes | exit 7 |
| darwin | as launched | SIGTSTP | rust | S/S | exit 7 (1.05 s) | yes / yes | yes | exit 7 |
| darwin | non-orphaned | SIGSTOP | control | T/- | exit 7 (1.05 s) | yes / yes | - |  |
| darwin | non-orphaned | SIGSTOP | go | T/S | exit 7 (1.06 s) | yes / yes | yes |  |
| darwin | non-orphaned | SIGSTOP | rust | T/T | **hung** (child Z, launcher T); after manual SIGCONT to launcher: exit 7 | yes / yes | no |  |
| darwin | non-orphaned | SIGTSTP | control | T/- | exit 7 (1.05 s) | yes / yes | - |  |
| darwin | non-orphaned | SIGTSTP | go | T/S | exit 7 (1.06 s) | yes / yes | yes |  |
| darwin | non-orphaned | SIGTSTP | rust | T/T | **hung** (child Z, launcher T); after manual SIGCONT to launcher: exit 7 | yes / yes | no |  |
| linux | as launched | SIGSTOP | control | T/- | exit 7 (1.02 s) | yes / yes | - | exit 7 |
| linux | as launched | SIGSTOP | go | T/S | exit 7 (1.07 s) | yes / yes | yes | exit 7 |
| linux | as launched | SIGSTOP | rust | T/T | **hung** (child Z, launcher T); after manual SIGCONT to launcher: exit 7 | yes / yes | no | hung; manual CONT: exit 7 |
| linux | as launched | SIGTSTP | control | S/- | exit 7 (1.01 s) | yes / yes | - | exit 7 |
| linux | as launched | SIGTSTP | go | T/S | exit 7 (1.02 s) | yes / yes | yes | exit 7 |
| linux | as launched | SIGTSTP | rust | S/S | exit 7 (1.01 s) | yes / yes | yes | exit 7 |
| linux | non-orphaned | SIGSTOP | control | T/- | exit 7 (1.01 s) | yes / yes | - |  |
| linux | non-orphaned | SIGSTOP | go | T/S | exit 7 (1.07 s) | yes / yes | yes |  |
| linux | non-orphaned | SIGSTOP | rust | T/T | **hung** (child Z, launcher T); after manual SIGCONT to launcher: exit 7 | yes / yes | no |  |
| linux | non-orphaned | SIGTSTP | control | T/- | exit 7 (1.02 s) | yes / yes | - |  |
| linux | non-orphaned | SIGTSTP | go | T/S | exit 7 (1.02 s) | yes / yes | yes |  |
| linux | non-orphaned | SIGTSTP | rust | T/T | **hung** (child Z, launcher T); after manual SIGCONT to launcher: exit 7 | yes / yes | no |  |

### Probe 1b: interactive shell, job in the foreground, third-party stop then SIGCONT of the child PID

`extstop_pty.py` v2. Child `sh -c 'echo $$ >pf; sleep 1; echo x >pf.done; exit 7'`. After SIGCONT the probe waits 6 s, then runs `echo RC=$?; jobs`; if the job is still listed stopped it types `fg`. Matches control = same stop notice, child completed, and the job ended without user action (no stopped job left).

| platform | shell | signal | via | after stop: child/launcher, shell notice | 6 s after SIGCONT: child, launcher | child completed | shell shows (`$?`, `jobs`) | user `fg` | matches control |
|---|---|---|---|---|---|---|---|---|---|
| darwin | bash | SIGSTOP | control | T/-, stop notice | gone (reaped), - | yes | $?=145; jobs: [1]+  Exit 7                  sh -c 'echo $$ > "$1"; sleep 1... | - | - |
| darwin | bash | SIGSTOP | go | gone/gone, no stop notice | gone (reaped), gone | no | $?=255; jobs: (none) | - | no |
| darwin | bash | SIGSTOP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=145; jobs: [1]+  Stopped                 sh -c 'echo $$ > "$1"; sleep 1... | rc 7, child gone, launcher gone | no |
| darwin | bash | SIGTSTP | control | T/-, stop notice | gone (reaped), - | yes | $?=146; jobs: [1]+  Exit 7                  sh -c 'echo $$ > "$1"; sleep 1... | - | - |
| darwin | bash | SIGTSTP | go | T/T, stop notice | Z (unreaped zombie), T | yes | $?=146; jobs: [1]+  Stopped                 sh -c 'echo $$ > "$1"; sleep 1... | rc 7, child gone, launcher gone | no |
| darwin | bash | SIGTSTP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=146; jobs: [1]+  Stopped                 sh -c 'echo $$ > "$1"; sleep 1... | rc 7, child gone, launcher gone | no |
| darwin | zsh | SIGSTOP | control | T/-, stop notice | gone (reaped), - | yes | $?=145; jobs: (none) | - | - |
| darwin | zsh | SIGSTOP | go | gone/gone, no stop notice | gone (reaped), gone | no | $?=255; jobs: (none) | - | no |
| darwin | zsh | SIGSTOP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=145; jobs: [1]  + suspended (signal)  sh -c  sh | rc 7, child gone, launcher gone | no |
| darwin | zsh | SIGTSTP | control | T/-, stop notice | gone (reaped), - | yes | $?=146; jobs: (none) | - | - |
| darwin | zsh | SIGTSTP | go | T/T, stop notice | Z (unreaped zombie), T | yes | $?=146; jobs: [1]  + suspended  sh -c  sh | rc 7, child gone, launcher gone | no |
| darwin | zsh | SIGTSTP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=146; jobs: [1]  + suspended  sh -c  sh | rc 7, child gone, launcher gone | no |
| linux | bash | SIGSTOP | control | T/-, stop notice | gone (reaped), - | yes | $?=147; jobs: [1]+  Exit 7                  sh -c 'echo $$ > "$1"; sleep 1... | - | - |
| linux | bash | SIGSTOP | go | T/T, stop notice | Z (unreaped zombie), T | yes | $?=148; jobs: [1]+  Stopped                 sh -c 'echo $$ > "$1"; sleep 1... | rc 7, child gone, launcher gone | no |
| linux | bash | SIGSTOP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=147; jobs: [1]+  Stopped                 sh -c 'echo $$ > "$1"; sleep 1... | rc 7, child gone, launcher gone | no |
| linux | bash | SIGTSTP | control | T/-, stop notice | gone (reaped), - | yes | $?=148; jobs: [1]+  Exit 7                  sh -c 'echo $$ > "$1"; sleep 1... | - | - |
| linux | bash | SIGTSTP | go | T/T, stop notice | Z (unreaped zombie), T | yes | $?=148; jobs: [1]+  Stopped                 sh -c 'echo $$ > "$1"; sleep 1... | rc 7, child gone, launcher gone | no |
| linux | bash | SIGTSTP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=148; jobs: [1]+  Stopped                 sh -c 'echo $$ > "$1"; sleep 1... | rc 7, child gone, launcher gone | no |
| linux | zsh | SIGSTOP | control | T/-, stop notice | gone (reaped), - | yes | $?=147; jobs: (none) | - | - |
| linux | zsh | SIGSTOP | go | T/T, stop notice | Z (unreaped zombie), T | yes | $?=148; jobs: [1]  + suspended  sh -c  sh | rc 7, child gone, launcher gone | no |
| linux | zsh | SIGSTOP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=147; jobs: [1]  + suspended (signal)  sh -c  sh | rc 7, child gone, launcher gone | no |
| linux | zsh | SIGTSTP | control | T/-, stop notice | gone (reaped), - | yes | $?=148; jobs: (none) | - | - |
| linux | zsh | SIGTSTP | go | T/T, stop notice | Z (unreaped zombie), T | yes | $?=148; jobs: [1]  + suspended  sh -c  sh | rc 7, child gone, launcher gone | no |
| linux | zsh | SIGTSTP | rust | T/T, stop notice | Z (unreaped zombie), T | yes | $?=148; jobs: [1]  + suspended  sh -c  sh | rc 7, child gone, launcher gone | no |

### Probe 2: child self-stop reported to the shell, then SIGCONT to the launcher PID only

`contlauncher.py` (clean form of probe.py `explicit` last step; control: SIGCONT to the job's only process, the child). "K6e breach" = `jobs` says running while the child is T. Matches control = same `jobs` verdict 0.6 s and 2 s after the SIGCONT and the same child behaviour (resumed or not). The last column is the unchanged probe.py `explicit` run, whose `jobs` fields are unreliable (harness defect H2) and whose earlier steps contaminate this step for Go (H3).

| platform | shell | via | after self-stop: notice, child/launcher | after SIGCONT: child/launcher | child resumed (printed BACK) | `jobs` at 0.6 s / 2 s | K6e breach | launcher CPU 2 s | recovery (CONT child, fg) | matches control | probe.py explicit (unchanged) states |
|---|---|---|---|---|---|---|---|---|---|---|---|
| darwin | bash | control | notice, T/- | T/- | yes | stopped / stopped | no | - | ok, rc 5 | - |  |
| darwin | bash | go | notice, T/T | T/T | yes | stopped / stopped | no | 0:00.01 -> 0:00.01 | ok, rc 5 | yes | child T, launcher S |
| darwin | bash | rust | notice, T/T | T/S | no | stopped / stopped | no | 0:00.00 -> 0:00.00 | ok, rc 5 | no | child T, launcher S |
| darwin | zsh | control | notice, T/- | T/- | yes | stopped / stopped | no | - | ok, rc 5 | - |  |
| darwin | zsh | go | notice, T/T | T/T | yes | stopped / stopped | no | 0:00.01 -> 0:00.01 | ok, rc 5 | yes | child T, launcher S |
| darwin | zsh | rust | notice, T/T | T/S | no | running / running | **yes** | 0:00.01 -> 0:00.01 | ok, rc 5 | no | child T, launcher S |
| linux | bash | control | notice, T/- | T/- | yes | stopped / stopped | no | - | ok, rc 5 | - |  |
| linux | bash | go | notice, T/T | T/T | yes | stopped / stopped | no | 0 -> 0 | ok, rc 5 | yes | child T, launcher T |
| linux | bash | rust | notice, T/T | T/S | no | running / running | **yes** | 0 -> 0 | FAILED (rc 1) | no | child T, launcher S |
| linux | zsh | control | notice, T/- | T/- | yes | stopped / stopped | no | - | ok, rc 5 | - |  |
| linux | zsh | go | notice, T/T | T/T | yes | stopped / stopped | no | 0 -> 0 | ok, rc 5 | yes | child T, launcher T |
| linux | zsh | rust | notice, T/T | T/S | no | running / running | **yes** | 0 -> 0 | ok, rc 5 | no | child T, launcher S |

### Probe 3: nested job-control shell as the child (`run -- bash -i`, `suspend`, outer `fg`)

`nested.py` (extended form of probe.py `nested_shell`). "answer after fg": `echo ALIVE-$W-42` typed after `fg` is answered by the nested shell, the outer shell, or nobody. Matches control = stop notice, outer shell survives, nested shell answers after `fg`. The last column is the unchanged probe.py `nested_shell` run.

| platform | outer shell | via | after `suspend`: notice, outer prompt | nested / launcher state | outer shell | after `fg`: nested / launcher, answer | diagnostic: SIGCONT nested PID | matches control | probe.py nested_shell (unchanged) |
|---|---|---|---|---|---|---|---|---|---|
| darwin | bash | control | notice, yes | T / - | alive | S / -, nested answered | - | - | notice yes, after fg ['S', None], answers yes |
| darwin | bash | go | NO notice, yes | gone / gone | **exited (exit 255)**, pty EOF=True | not reached | - | no | exception OSError(5, 'Input/output error') |
| darwin | bash | rust | notice, yes | T / T | alive | T / S, no answer | S / S, nested answered | no | notice yes, after fg ['T', 'S'], answers no |
| darwin | zsh | control | notice, yes | T / - | alive | S / -, nested answered | - | - | notice yes, after fg ['S', None], answers yes |
| darwin | zsh | go | NO notice, yes | gone / gone | **exited (exit 255)**, pty EOF=True | not reached | - | no | exception OSError(5, 'Input/output error') |
| darwin | zsh | rust | notice, yes | T / T | alive | T / S, no answer | S / S, nested answered | no | notice yes, after fg ['T', 'S'], answers no |
| linux | bash | control | notice, yes | T / - | alive | S / -, nested answered | - | - | notice yes, after fg ['S', None], answers yes |
| linux | bash | go | notice, yes | T / T | alive | S / S, nested answered | - | yes | notice yes, after fg ['S', 'S'], answers yes |
| linux | bash | rust | notice, yes | T / T | alive | T / S, no answer | S / S, nested answered | no | notice yes, after fg ['T', 'S'], answers no |
| linux | zsh | control | notice, yes | T / - | alive | S / -, nested answered | - | - | notice yes, after fg ['S', None], answers yes |
| linux | zsh | go | notice, yes | T / T | alive | S / S, nested answered | - | yes | notice yes, after fg ['S', 'S'], answers yes |
| linux | zsh | rust | notice, yes | T / T | alive | T / S, no answer | S / S, nested answered | no | notice yes, after fg ['T', 'S'], answers no |

### Probe 4: child stopped by SIGSTOP in exclusive mode (Go review3c `selfstop_detail.py`, unchanged)

Interactive shell, foreground job, child `child3c.py read SIGSTOP`; trigger `read` = the child stops itself (`~z`), `ext` = this probe sends SIGSTOP to the exact child PID. States sampled every 0.25 s for 3 s (shown: distinct values). Matches control = shell reports the stop and the child is T (a different stop signal in `$?` is noted). `$?` 145/146 = SIGSTOP/SIGTSTP on darwin, 147/148 on linux. "not written yet": the meta file is written when the run ends, after the sampling window.

| platform | shell | trigger | via | stop reported | `$?` | child/launcher over 3 s | child log after start | meta file | matches control |
|---|---|---|---|---|---|---|---|---|---|
| darwin | bash | read | control | yes | 145 | T/- | GOT, SELFSTOP | - | - |
| darwin | bash | read | go | no | 255 | gone/gone | GOT, SELFSTOP, SIG SIGHUP, CONT, READERR, EXIT | CHILD_EXITED exit_code=-1 signal=None | no |
| darwin | bash | read | rust | yes | 145 | T/T | GOT, SELFSTOP | not written yet | yes |
| darwin | bash | ext | control | yes | 145 | T/- | - | - | - |
| darwin | bash | ext | go | no | 255 | gone/gone | SIG SIGHUP, CONT, READERR, EXIT | CHILD_EXITED exit_code=-1 signal=None | no |
| darwin | bash | ext | rust | yes | 145 | T/T | - | not written yet | yes |
| darwin | zsh | read | control | yes | 145 | T/- | GOT, SELFSTOP | - | - |
| darwin | zsh | read | go | no | 255 | gone/gone | GOT, SELFSTOP, SIG SIGHUP, CONT, READERR, EXIT | CHILD_EXITED exit_code=-1 signal=None | no |
| darwin | zsh | read | rust | yes | 145 | T/T | GOT, SELFSTOP | not written yet | yes |
| darwin | zsh | ext | control | yes | 145 | T/- | - | - | - |
| darwin | zsh | ext | go | no | 255 | gone/gone | SIG SIGHUP, CONT, READERR, EXIT | CHILD_EXITED exit_code=-1 signal=None | no |
| darwin | zsh | ext | rust | yes | 145 | T/T | - | not written yet | yes |
| linux | bash | read | control | yes | 147 | T/- | GOT, SELFSTOP | - | - |
| linux | bash | read | go | yes | 148 | T/T | GOT, SELFSTOP | not written yet | yes (`$?` 148 vs control 147) |
| linux | bash | read | rust | yes | 147 | T/T | GOT, SELFSTOP | not written yet | yes |
| linux | bash | ext | control | yes | 147 | T/- | - | - | - |
| linux | bash | ext | go | yes | 148 | T/T | - | not written yet | yes (`$?` 148 vs control 147) |
| linux | bash | ext | rust | yes | 147 | T/T | - | not written yet | yes |
| linux | zsh | read | control | yes | 147 | T/- | GOT, SELFSTOP | - | - |
| linux | zsh | read | go | yes | 148 | T/T | GOT, SELFSTOP | not written yet | yes (`$?` 148 vs control 147) |
| linux | zsh | read | rust | yes | 147 | T/T | GOT, SELFSTOP | not written yet | yes |
| linux | zsh | ext | control | yes | 147 | T/- | - | - | - |
| linux | zsh | ext | go | yes | 148 | T/T | - | not written yet | yes (`$?` 148 vs control 147) |
| linux | zsh | ext | rust | yes | 147 | T/T | - | not written yet | yes |

### Repeat stability of probes 2 and 3 (main run + repeats)

Each cell lists main / rep2 / rep3. Probe 2: `jobs` verdict 2 s after SIGCONT to the launcher, child resumed (y/n), recovery ok (y/n). Probe 3: outer shell alive after `suspend` (y/n), answer after `fg` (nested/outer/none/-).

| platform | shell | via | probe 2 | probe 3 |
|---|---|---|---|---|
| darwin | bash | control | stopped,y,y / stopped,y,y / stopped,y,y | y,nested / y,nested / y,nested |
| darwin | bash | go | stopped,y,y / stopped,y,y / stopped,y,y | n,- / n,- / n,- |
| darwin | bash | rust | stopped,n,y / stopped,n,y / stopped,n,y | y,none / y,none / y,none |
| darwin | zsh | control | stopped,y,y / stopped,y,y / stopped,y,y | y,nested / y,nested / y,nested |
| darwin | zsh | go | stopped,y,y / stopped,y,y / stopped,y,y | n,- / n,- / n,- |
| darwin | zsh | rust | running,n,y / running,n,y / running,n,y | y,none / y,none / y,none |
| linux | bash | control | stopped,y,y / stopped,y,y / stopped,y,y | y,nested / y,nested / y,nested |
| linux | bash | go | stopped,y,y / stopped,y,y / stopped,y,y | y,nested / y,nested / y,nested |
| linux | bash | rust | running,n,n / running,n,n / running,n,n | y,none / y,none / y,none |
| linux | zsh | control | stopped,y,y / stopped,y,y / stopped,y,y | y,nested / y,nested / y,nested |
| linux | zsh | go | stopped,y,y / stopped,y,y / stopped,y,y | y,nested / y,nested / y,nested |
| linux | zsh | rust | running,n,y / running,n,y / running,n,y | y,none / y,none / y,none |

## Summary of the comparison (observations; inferences marked)

| probe | control | go | rust |
|---|---|---|---|
| 1a non-interactive, stop+CONT child PID | exit 7 in ~1.05 s, child reaped | **matches** on both OSes, both signals, orphaned or not. Go does not mirror here (launcher stays `S`); its child is stopped by SIGTSTP even where the control's is not, so it runs in a separate, non-orphaned group (inference from the as-launched SIGTSTP rows). | **hangs** for SIGSTOP on both OSes, and for SIGTSTP when the group is not orphaned (launcher `T`, child `Z` unreaped); exits 7 only after a manual SIGCONT to the launcher. In an orphaned group SIGTSTP is discarded and Rust matches. Reproduces the review3c finding. |
| 1b interactive fg job, stop+CONT child PID | shell reports stopped; after the third-party CONT the job finishes by itself (`Exit 7` / done), child reaped | **does not match.** SIGTSTP (both OSes) and SIGSTOP (linux): same as Rust: both `T`, then child `Z` unreaped, launcher stays `T`, the shell keeps a stopped job until the user types `fg` (then rc 7). **darwin SIGSTOP**: launcher exits **255** within 0.5 s, no stop notice, the child is killed (did not complete; its `sh` was gone, consistent with orphaned-group SIGHUP), job gone, `$?`=255. | **does not match**, both OSes, both signals: both `T`, child `Z` unreaped, launcher `T`, shell shows a stopped job until `fg` (then rc 7). |
| 2 self-stop reported, then SIGCONT to launcher only | child resumes, reads the tty in the background and is TTIN-stopped; `jobs` = stopped | **matches** on both OSes and both shells (3/3 runs each): the child resumes (prints `BACK`), is TTIN-stopped again and the stop is mirrored; `jobs` = stopped (zsh: `suspended (tty input)`, as control). | **does not match** (3/3): child stays `T`, launcher `S`, idle (0 CPU over 2 s). `jobs` says **running** under zsh (darwin, linux) and bash 5.2 (linux) = K6e "stopped while the shell believes running"; bash 3.2 (darwin) still says stopped. Reproduces the review3c minor. |
| 3 nested `bash -i` child, `suspend`, outer `fg` | stop notice, `fg` gives the terminal back, nested shell answers | linux: **matches** (3/3, both outer shells). darwin: **does not match**, worse than Rust (3/3, both outer shells; also the unchanged probe.py in both darwin runs and the H5 attempt): no stop notice, `heimdall-proto` exits 255 and the nested shell is gone, then the **outer interactive shell itself exits** (bash prints `exit`, status 255; zsh likewise 255; pty EOF), i.e. the user's terminal session ends. | **does not match** on both OSes (3/3): notice shown, but after `fg` the nested shell stays `T` (launcher `S`) and nothing answers; the outer shell is alive but its foreground job is unusable until the nested PID is continued externally (diagnostic SIGCONT made it answer). Reproduces the review3c minor. |
| 4 child stopped by SIGSTOP, exclusive mode (Go reviewer's case) | stop reported, `$?` 145 (darwin) / 147 (linux), child `T` | darwin: **reproduces the Go review3c major** for both triggers and both shells: no stop reported, `$?`=255, child and launcher gone within 0.25 s, child log `SIGHUP, CONT, READERR 5, EXIT`, meta `CHILD_EXITED exit_code=-1 signal=null`. linux: matches (stop reported, both `T`), but `$?`=148 (mirrored as SIGTSTP) vs control 147. | **matches** on both OSes, both shells, both triggers, including the same `$?` as control (SIGSTOP mirrored as SIGSTOP). Rust's §9.5 deviation needs a continue of the child only (probes 1a/1b), which this case does not do. |

Symmetry notes for the ADR (inference from the rows above, not new measurements):

- The §9.5 Rust major ("stays stopped, never reaps, never exits" after a third-party stop+continue of the child)
  has a **Go counterpart in the interactive setting**: probe 1b shows Go (SIGTSTP both OSes, SIGSTOP on linux)
  ending in the same state as Rust (launcher `T`, child `Z`, stopped job until `fg`). Go escapes it only
  non-interactively (probe 1a), where it does not mirror at all.
- The §9.5 Go major (darwin SIGSTOP → exit 255, child lost) **extends to a nested job-control shell**, where it also
  ends the outer interactive shell (probe 3). Why the outer shell exits (right after printing its prompt it behaves as on
  end of input: bash prints `exit`) was not isolated; the nested shell had made its own process group the tty's foreground group
  before `suspend` (recorded `tpgid` = nested pgid in `before_suspend`).
- On probe 2 the ranking is reversed: Go matches the control, Rust shows the K6e "believes running" divergence.

## Limits

- One machine per platform; linux is the Docker Desktop arm64 VM (native arm64, not emulation), not bare metal.
- Probes 1a/1b/4 ran once per platform in the main run (plus darwin run 1 with the v1 harness, same outcomes
  except the H1 row); probes 2/3 ran three times per platform. Timing-sensitive fields (H7) were not stress-tested.
- Non-orphaned rows rely on `nonorphan.py`; a real terminal session or service manager may differ again.
- No Windows, no linux-x64; nothing here closes or reopens a gate (§9.4/§9.5: recorded, not gated).
- Transcripts contain only scratch paths (`<scratch>`, plus line-wrapped fragments of it). A grep over this
  directory for the home directory, the macOS per-user temp root, the canary prefix and private-key headers matched
  only this paragraph's own wording before it was rephrased; after rephrasing it matches nothing (grep exit 1).

## Layout

- `raw/darwin`, `raw/linux`: main runs (`exit-codes.txt`, `extstop-*.json`, `pty/`, `probe-{go,rust}/`, `detail/`,
  `cont/`, `nested/`, consoles, transcripts).
- `raw/{darwin,linux}-rep{2,3}`: repeats of probes 2 and 3.
- `raw/darwin-run1`: first darwin run (extstop_pty v1, H1). `raw/darwin-extra-deadlocked`: H5 partial output.
- `meta/`: sha256 checks, probe-script hashes per version (`probes-sha256*.txt`; v1 = run 1, v2 = darwin main,
  v4/linux = dedicated probes, repeats and linux), image, timings, driver consoles and exit codes.
