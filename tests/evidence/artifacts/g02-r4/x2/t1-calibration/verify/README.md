# X2 T1 calibration, independent check of scenario P1 (M00-T05-r4-x2-t1cal-verify)

Status: `implemented_unverified`. Every number below comes from a command executed by this
task and recorded under `raw/`; nothing is predicted. No third party has re-run this probe.

## What this is

An independent re-measurement of the one scenario the calibration (`../README.md`) built its
three Go "major" rows on: **P1**, a background job of an interactive shell whose stdin, stdout and
stderr are `/dev/null`, whose program is stopped by a third party, and the user's attempts to
recover. Builds were rebuilt from the pinned bases and the implementer diffs; the probe was
written from scratch for this task (`probe/probe.py`); the calibration's `README.md`,
`matrix.*`, `extra.*`, `raw/` and `scripts/` were read only after the probes had run (the task's
step 4). `../provenance.json` and `../../hidden-pack/BASE.json` were read first, as allowed.

Two things came out that the calibration does not say:

1. On darwin, with default signal dispositions, **^C ends the job in every Go cell** (the stopped
   child dies of SIGINT, the launcher exits, `$?` = 130), under bash and zsh. The calibration's
   "^Z and ^C do nothing ... darwin: ^\ ends launcher and child, rc 131" is reproduced only when
   the shell's jobs inherit SIGINT = `SIG_IGN`, which both the calibration's harness and this
   task's first run produced (see "Harness artifact"). On Linux nothing recovers, as the
   calibration says, because the kernel holds a fatal signal to a stopped process until SIGCONT.
2. The Go/Rust recovery difference in P1 is a consequence of the two baselines' process-group
   models, not of anything the six T1 implementers wrote: the Rust child shares the launcher's
   process group, so the shell's `fg` SIGCONT reaches it; the Go child is in its own group with
   the terminal handed to it, so neither `fg` nor the terminal keys reach the launcher. The Go
   model was motivated by a Go stdlib limitation (no siginfo without cgo), but the P1 recovery
   failure itself is a design choice the Go cells could have avoided within that model.

## Builds (provenance)

`probe/build_cells.sh`: one scratch copy per language from `git archive <base> prototypes/<lang>`
(tree digests equal to `BASE.json`: go `9ee4b916…`, rust `58c9fef5…`), committed as the single
commit of a scratch-local git repo; baseline built first, then per cell `git reset --hard &&
git clean -fd`, `git apply --check`, `git apply` of the implementer diff named in
`../provenance.json` (sha256 of every diff re-checked, all equal), `sh build.sh` (all four
targets; Rust with the repository's `cargo-zigbuild` copied into the copy's `target/tools/bin`),
darwin-arm64 and linux-arm64 binaries copied out before the next build. Toolchains: go1.27.2,
rustc 1.99.0 (b940084d7), zig 0.17.0, cargo-zigbuild 0.23.4; host macOS 27.0.1 (darwin-arm64).
All applies clean, all `build.sh` exits 0. Full digests and comparisons: `results/provenance.json`,
`results/builds.tsv`, `results/build-logs/`.

| build | source | darwin sha256 | linux sha256 | = calibration build | = cell's recorded artifact |
|---|---|---|---|---|---|
| base-go | 84c7665 prototypes/go | f812084ff36d… | 3e472e1b9d9d… | yes | no (BASE pins are go1.27.1 builds; same finding as the calibration) |
| T1-go-opus1 | + runs/T1-go-opus1/out/diff.patch | 457ce20fd37f… | 4ae668ad0fb6… | yes | yes |
| T1-go-opus2 | + runs/T1-go-opus2/out/diff.patch | c392df768d67… | 57baf65f9224… | yes | no (same toolchain explanation as the calibration) |
| T1-go-sonnet1 | + runs/T1-go-sonnet1/implementer/diff.patch | 5d0be6efbc4a… | 40668676204a… | yes | yes |
| base-rust | 001a791 prototypes/rust | f9a3ec8b4683… | 85e038b4728f… | yes | yes (= BASE pins) |
| T1-rust-opus1 | + runs/T1-rust-opus1/implementer/diff.patch | b82bd9600a76… | 657e9d1e3b48… | yes | yes |
| T1-rust-opus2 | + runs/T1-rust-opus2/implementer/diff.patch | 02f0baa79c5a… | 36986c356d3e… | yes | yes |
| T1-rust-sonnet1 | + runs/T1-rust-sonnet1/implementer-out/diff.patch | 92c44aa37d90… | 0ceac2939cea… | yes | yes |

Every binary probed here is byte-identical to the one the calibration probed.

## Method

`probe/probe.py` (stdlib Python; written for this task, no code shared with the calibration).
One run = one fresh interactive shell on a fresh pty (`pty.fork`; `bash --norc --noprofile -i`
or `zsh -f -i`, `TERM=dumb`, fixed prompt, zsh with `unsetopt zle promptsp promptcr banghist`).
The pty child resets the dispositions of INT, QUIT, HUP, TERM, PIPE, TSTP, TTIN, TTOU, CONT, CHLD,
USR1, USR2, ALRM, WINCH to `SIG_DFL` before `exec` (run 2; see "Harness artifact" for why), and
every record stores the probe's own inherited dispositions.

Scenario P1, as specified by the task: the shell starts `sleep 3 </dev/null >/dev/null 2>&1 &`
(plain exec) or `<binary> run -- sleep 3 </dev/null >/dev/null 2>&1 &`; the probe reads `$!`,
finds the launcher's child (`ps`/`/proc`), and, as the third party, sends SIGTSTP or SIGSTOP to
the **program's** PID with `kill(2)`. After 0.7 s it records the launcher's and the program's
state, process group, the terminal's foreground group and the ignored-signal mask (`/proc` on
Linux; `ps` plus `probe/sigign.go` via `sysctl kern.proc.pid` on darwin), then types `jobs -l`.

- **ladder** mode: (a) `fg` (9 s), (b) ^Z (4 s) then `fg` (9 s), (c) ^C (6 s), (d) ^\ (6 s); the
  first step after which the prompt returned **and** `jobs -l` listed no running/stopped job is
  the result; `$?` is read right after that prompt. `none` = nothing worked.
- **cont** mode (fresh shell): `kill -CONT %1`, wait 4.5 s, `jobs -l`, then `fg`; `cont-alone` =
  the job had already finished (`fg` answers "no such job", `$?` 1), `cont+fg` = `fg` finished it,
  `none` = still stopped.

Every process the probe started is ended by exact PID at the end of each run after re-checking
its command name and parent (SIGKILL), and the record stores what was left before and after that
(`leftover_at_end`, `leftover_after_cleanup`; the latter is empty in all 432 + 432 records).

| set | platform | shells | reps | records |
|---|---|---|---|---|
| darwin-arm64 host (macOS 27.0.1) | bash 3.2.57, zsh 5.9 | 3 per build x signal x mode | 2 x 108 |
| linux-arm64, `heimdall-g02-harness:d0c8e448a3a7` (image id 5081bb560f9b), `docker run --rm --init --network none`, bind mounts read-only, kernel 7.0.14-linuxkit | bash 5.2.15, zsh 5.9 | 3 | 2 x 108 |

9 builds (plain exec, 2 baselines, 6 cells) x 2 signals x 2 modes x 3 reps x 4 platform/shell sets
= 432 records per run. Two full runs were made: **run 1** (probe started as a `nohup … &` job,
shell dispositions not reset; `raw/run1-harness-sigign/`, JSON records only) and **run 2** (shell
started with default dispositions; `raw/run2/`, JSON records and pty transcripts). All 288 probe
invocations (144 per run, 3 reps each) exited 0. Within each run no cell had reps that disagreed. UTC timestamps are in each
record (`utc`), all 2026-10-10.

## Observed P1 table (run 2, default dispositions)

Cell format: `jobs -l` state after the third-party signal; launcher (L) and program (P) state
(`S` sleeping, `T` stopped, `-` gone); recovery step that worked; `$?` at the prompt after it.
"LEFT" = launcher and child were still alive when the ladder gave up (then killed by the probe).
Full table with reps: `results/table-run2.md`; machine-readable: `results/summary-run2.json`.

### ladder: `fg`, then ^Z + `fg`, then ^C, then ^\

| build | signal | darwin bash | darwin zsh | linux bash | linux zsh |
|---|---|---|---|---|---|
| plain exec | TSTP | Suspended; P=T; **a** `$?`=0 | suspended; P=T; **a** 0 | Stopped; P=T; **a** 0 | suspended; P=T; **a** 0 |
| plain exec | STOP | Suspended (signal); P=T; **a** 0 | suspended (signal); P=T; **a** 0 | Stopped (signal); P=T; **a** 0 | suspended (signal); P=T; **a** 0 |
| base-go | TSTP | Suspended; L=T P=T; **a** 0 | suspended; L=T P=T; **a** 0 | Stopped; L=T P=T; **a** 0 | suspended; L=T P=T; **a** 0 |
| base-go | STOP | `Exit 255`, L and P gone; `fg`: no such job, `$?`=1 | (asynchronous exit notice), job list empty, L and P gone; `fg`: no job, 1 | Stopped; L=T P=T; **a** 0 | suspended; L=T P=T; **a** 0 |
| base-rust | TSTP, STOP | Suspended; L=T P=T; **a** 0 | suspended; L=T P=T; **a** 0 | Stopped; L=T P=T; **a** 0 | suspended; L=T P=T; **a** 0 |
| T1-go-opus1 | TSTP, STOP | **Running**; L=S P=T; **c** (^C) 130 | Running; L=S P=T; **c** 130 | Running; L=S P=T; **none** LEFT | Running; L=S P=T; **none** LEFT |
| T1-go-opus2 | TSTP, STOP | Running; L=S P=T; **c** 130 | Running; L=S P=T; **c** 130 | Running; L=S P=T; **none** LEFT | Running; L=S P=T; **none** LEFT |
| T1-go-sonnet1 | TSTP, STOP | Running; L=S P=T; **c** 130 | Running; L=S P=T; **c** 130 | Running; L=S P=T; **none** LEFT | Running; L=S P=T; **none** LEFT |
| T1-rust-opus1 | TSTP, STOP | Running; L=S P=T; **b** (^Z, `fg`) 0 | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 |
| T1-rust-opus2 | TSTP, STOP | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 |
| T1-rust-sonnet1 | TSTP, STOP | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 | Running; L=S P=T; **b** 0 |

In every Go cell the stopped child was in its own process group and the launcher in another
(`child_in_launcher_group` false in all 144 Go-cell records); in every Rust cell and both
baselines' Rust side the child shared the launcher's group (true in all 108). After the hung `fg`
the terminal's foreground group was the child's group in the Go cells and the launcher's (shared)
group in the Rust cells (`steps[].procs.*.tpgid`).

### cont: `kill -CONT %1`, 4.5 s, `fg`

| build | darwin bash / zsh, linux bash / zsh |
|---|---|
| plain exec, base-go (TSTP), base-rust | job finishes on its own after `kill -CONT %1` (`Done`); `fg`: no such job (`cont-alone`) |
| base-go (STOP, darwin) | job already gone (`Exit 255`) before the `kill`; `cont-alone` |
| T1-go-opus1 | child continued and finished (`Done`); `cont-alone` in all 4 sets |
| T1-go-opus2, T1-go-sonnet1 | child stays T after `kill -CONT %1`; `fg` then hangs; **none**, LEFT, all 4 sets |
| T1-rust-opus1, T1-rust-opus2, T1-rust-sonnet1 | child continued and finished (`Done`); `cont-alone` in all 4 sets |

### Side experiments (raw/experiments/)

- `exp_stopped_signal.*.jsonl` (kernel semantics, `sleep 30` in its own process group, stopped by
  kill(2) SIGTSTP or SIGSTOP, then kill(2) SIGINT / SIGQUIT / SIGTERM, no SIGCONT): **darwin**: the
  process is a zombie within 0.5 s and `waitpid` returns the signal (2/3/15) for both stop signals;
  **linux**: the process stays `T`, `waitpid` returns nothing; after SIGCONT it dies with that
  signal. (The pty sub-cases in the same file made the child a session leader; its exit then waits
  for the pty to drain and the states are confounded, so only the kill(2) rows are used here.)
- `exp_fg_termios.darwin-arm64.go-opus1.jsonl` (go-opus1, darwin): during the hung `fg` the pty
  has ISIG on, VINTR ^C, VQUIT ^\, VSUSP ^Z in both shells; the foreground group is the child's;
  ^C returns the prompt immediately (child gone) directly after `fg`, after ^Z, after a typed `fg`,
  after ^Z + `fg`, and with the ladder's own timing (`fg` 9 s, ^Z 4 s, `fg` 9 s; 2 reps per shell).
- `exp_fg_termios.darwin-arm64.rust.jsonl` (rust-opus1 bash, rust-sonnet1 zsh, darwin): the
  foreground group is the shared group; ^C straight after the hung `fg` returns the prompt, child
  gone.

### Harness artifact (run 1 vs run 2; raw/artifact/)

Run 1 differed from run 2 in exactly the Go x darwin ladder cells: bash needed ^\ (`$?` 131),
zsh ^C (`$?` 130). Cause, established by the records: the drivers were started as `nohup … &`
jobs of a non-interactive shell, which gives an asynchronous command SIGINT and SIGQUIT =
`SIG_IGN`; bash passes the dispositions it inherited to its jobs, zsh resets INT/QUIT for its
children. Reproduced on purpose with `--no-reset-signals` under `sh -c 'trap "" INT QUIT; …'`
(`raw/artifact/`): the Go-launched `sleep` has SIGINT in its ignored mask but not SIGQUIT (the Go
runtime resets the signals it handles to default in the child; baseline run_unix.go:51-56) and the
ladder ends at ^\ with 131 (2/2); the Rust-launched `sleep` has SIGINT **and** SIGQUIT ignored
(Rust std resets only SIGPIPE; runner.rs:33-36) and recovers at ^Z + `fg`; under zsh the child's
mask has neither and ^C works. In run 2 (shell started with default dispositions) no child has
SIGINT ignored in any of the 432 records (`after_signal.program.sigign` is `[]` on Linux and
`[SIGWINCH]` on darwin, where the kernel also records default-ignored signals in that mask), and
the darwin Go cells recover at ^C under both shells.

## Mechanism

Line numbers refer to each cell's source after its diff is applied (`base-go` = 84c7665
`prototypes/go/internal/run/run_unix.go`; `base-rust` = 001a791 `prototypes/rust/src/runner.rs`).

### Why all six cells list the job as Running (the shared part)

Each cell consumes the child's stop report and then decides whether to mirror the stop onto the
launcher; in P1 every cell decides not to, because its test for "a job-control shell is watching"
is false for a background job whose stdio is redirected and whose process group is not the
terminal's foreground group:

- go-opus1 `onStop`: `if fg != sv.own && fg != sv.pid && !sv.ttyIO { return }` (run_unix.go:288-293).
- go-opus2 `shouldMirror`: true only if the foreground group is the launcher's or the child's, or
  the stop is SIGTTIN/SIGTTOU (370-376); `mirrorStop` returns at 340.
- go-sonnet1 `engaged`: `modeExclusive && (stdioHasCtty() || tcgetpgrp(ttyFD) == own)` at start
  (220), set later only when the launcher's group holds the terminal (246, 337-339); `mirrorStop`
  returns when not engaged (340-342).
- rust-opus1 `job_terminal()`: `/dev/tty` opens and (stdio is the terminal or `tcgetpgrp == getpgrp`)
  (215-236); `handle_child_stop` returns `false` otherwise (294-296).
- rust-opus2 `on_child_stop`: `job_control = on_stdio || fg == own_pg || fg == child_pg` (336),
  `return` if false (337-339).
- rust-sonnet1 `in_foreground_job()`: parent in another group and `tcgetpgrp(/dev/tty) == getpgrp`
  (205-213), sampled at start, on every continue report and during the grace (sticky `JobCtl`,
  216-233); `mirror_child_stop` returns when never seen (296-298).

These gates exist to satisfy T1's S1 (a non-shell parent, stdio not a terminal, must not see the
launcher stop itself): by process-group topology and terminal state, P1 and S1 are the same
situation. Both baselines mirror unconditionally (base-go `mirrorStop` 283-312 with `kill(0,
sig)` at 327; base-rust `mirror_child_stop` 184-227 with `kill_process(getpid(), own)` at 226) and
therefore show `Stopped`/`Suspended` in P1 like plain exec, and `fg` finishes the job (`a`). The
`$?` of the shell is 128+N with the child's own signal in both baselines (STOP included in Rust;
base-go on darwin instead decodes a SIGSTOP stop as "continued", takes it for an exit, returns 255
and leaves the child stopped in an orphaned group, where the kernel's SIGHUP ends it: the
`Exit 255` row; fixed by all three Go cells: go-opus1 `decodeWait`, go-opus2 `wstatus`
(waitstatus_unix.go), go-sonnet1 `stopSignal` 295-308).

### Go cells: why `fg`, ^Z and (on Linux) ^C/^\ do not recover

1. **Process groups and terminal.** In `modeExclusive` (chosen because a controlling terminal
   exists, stdio is not a pipe and the launcher is alone in its group; `chooseMode` base 137-146,
   unchanged in the cells) the child is started with `Setpgid: true` and, when the launcher's
   group holds the terminal, `Foreground`/`Ctty` (base 162-166; go-opus1 347-351, go-opus2 195-199,
   go-sonnet1 172-176). A 50 ms poll hands the terminal to the child's group whenever the
   launcher's group holds it (base 224-241; go-opus1 `handoff` 262-269). So after the user's `fg`
   (the shell gives the terminal to the launcher's group) the launcher passes it on to the stopped
   child's group within 50 ms; observed `tpgid` = child's pgid in every Go-cell `fg` step.
2. **`fg` sends no SIGCONT.** The shell lists the job as Running, and bash 3.2/5.2 and zsh 5.9
   continue only a job they list as stopped. Inferred, not read from shell source, but tight:
   go-opus1 continues the child on every SIGCONT it receives (`case <-cont: sv.resume()` 403,
   `resume` 239-258 with `Kill(-sv.pid, SIGCONT)` 257), `kill -CONT %1` makes its child finish in
   all 24 cont runs, and `fg` never does in its 24 ladder runs. The launcher therefore just keeps
   waiting in `Wait4(WUNTRACED)` for a child that nobody continues.
3. **Terminal keys reach only the stopped child.** With the child's group in the foreground, ^Z
   is a stop signal to an already stopped process (no effect), ^C and ^\ are SIGINT/SIGQUIT to
   it. **darwin** terminates a stopped process on a fatal signal at once (side experiment), the
   launcher's `Wait4` returns the signal status, it exits 130/131 and the prompt comes back;
   **Linux** keeps the signal pending until SIGCONT, so nothing visible happens. The launcher
   itself never receives a terminal signal (it is not in the foreground group), so its forwarding
   (`cmd.Process.Signal`, go-opus1 400) is never involved.
4. **`kill -CONT %1`** is `killpg(launcher's group, SIGCONT)`; the child is not in that group.
   go-opus1 turns the launcher's SIGCONT into `SIGCONT` to the child's group (`resume`), so the
   job finishes. go-opus2 and go-sonnet1 keep the baseline's handling: the `cont` channel (Notify
   at go-opus2 236 / go-sonnet1 213) is read only inside `stopSelf` (go-opus2 386-395,
   go-sonnet1 377-390), after the launcher stopped itself; a SIGCONT that arrives while the
   launcher is running is buffered and drained (`for len(cont) > 0 { <-cont }`, go-opus2 387-389,
   go-sonnet1 378-380) and never reaches the child.

### Rust cells: why ^Z then `fg` recovers

1. **One process group, terminal untouched.** The child is spawned with `Command::spawn`
   without `setpgid`, and the launcher never calls `tcsetpgrp` except to hand the terminal back to a
   child group that had taken it itself (base runner.rs:3-8; rust-opus1 `resume_child` 333-359,
   rust-opus2 `continue_child` 272-285, both unreached in P1). After `fg` the foreground group is
   the launcher's group, which contains the child (observed `tpgid` = launcher pgid).
2. **`fg` hangs** for the same reason as in Go: the shell sends no SIGCONT to a Running job; the
   launcher waits in `waitid` for a child nobody continues. ^C straight after `fg` would end the
   job on darwin (side experiment; the launcher also forwards the SIGINT it catches, runner.rs:
   forwarder thread) and do nothing on Linux (signal held until SIGCONT).
3. **^Z stops the launcher**, because it is in the foreground group and SIGTSTP is not in the
   handled set (`sigdisp::HANDLED` = INT, TERM, HUP, QUIT, WINCH; sigdisp.rs:23-29), so its
   default action applies. The shell now sees its own child stopped, prints `Stopped`/`suspended`
   and returns the prompt. The next **`fg`** is `killpg(group, SIGCONT)`: the SIGCONT reaches the
   `sleep` directly, it finishes, the launcher reaps it and exits 0.
   The cells' own resume logic plays no part: rust-opus1 `resume_child` and rust-sonnet1's
   `CONT_WAIT` + `kill_process(pid, Signal::CONT)` (311-333) run only after a mirrored stop, which
   P1 never has; rust-opus2's SIGCONT handler (`caught.push(libc::SIGCONT)` 408, forwarder
   441-448) additionally sends `kill(pid, SIGCONT)` to a child the `killpg` has already continued.
4. **`kill -CONT %1`** is the same `killpg` and continues the child directly in all three cells.

### Language constraint or design choice

- **The Running state (all six):** design. A gate on terminal foreground / stdio-on-tty is what
  every implementer chose to meet S1; neither language forces it, and both baselines (which do
  not have it) show the plain-exec job state in P1. Whether a launcher that is a separate process
  can satisfy S1 and P1 at once is a specification question, not a language one (a stopped
  launcher cannot observe its child being continued; a helper process could, at the cost of K16
  and complexity). None of the six tried.
- **Go recovery failure:** design, resting on a model that a Go stdlib limitation motivated. The
  separate process group plus terminal hand-off is the Go **baseline's** answer to `os/signal`
  giving no `siginfo` (run_unix.go:19-49: without `si_code` the launcher cannot tell a
  terminal-generated SIGINT, already delivered to the child through the foreground group, from a
  PID-directed one, so it isolates the child to avoid double delivery). That limitation is real
  for a `CGO_ENABLED=0` build (the Go runtime owns signal handling; `signalfd`/`sigwaitinfo` are
  not usable from pure Go). But the P1 outcome follows from choices the cells made or kept inside
  that model, each avoidable with the same stdlib: continuing a stopped child when `handoff`
  observes the launcher's group in the foreground after `fg` (go-opus1 already has `childState`);
  handling SIGCONT while running (go-opus1 does, so `kill -CONT %1` works there; go-opus2 and
  go-sonnet1 kept the baseline's `stopSelf`-only reading of the `cont` channel); or not handing
  the terminal to a stopped child so ^Z reaches the launcher. The `Setpgid`/`Foreground`/`Ctty`
  fields and `signal.Notify(SIGCONT)` used here are plain `syscall`/`os/signal` features.
- **Rust recovery success:** a consequence of the Rust **baseline's** shared-process-group model,
  which that baseline could afford because `signal-hook` (`WithRawSiginfo`) and `libc` give it
  `si_code` to drop duplicate terminal signals on Linux (and it accepts duplicates on macOS,
  runner.rs:16-26). Rust `std` has no siginfo either; the difference is that in Rust the libc-level
  API is an ordinary dependency, while in Go without cgo it is not. Nothing in the three Rust
  cells' T1 changes is exercised by the P1 recovery, so no credit for it belongs to those changes.
- **Platform:** the darwin/Linux split for ^C and ^\ on the Go cells is kernel behaviour (fatal
  signal to a stopped process: immediate on darwin, deferred on Linux), independent of language.

## Agreement with `../README.md` ("Results in brief", "Uniform classification", Appendix B P1x)

| statement in the calibration | this task's observation | agreement |
|---|---|---|
| All six cells diverge from plain exec in P1: `jobs` shows Running while the child is stopped (both signals) | same, all 4 sets, 3 reps, both signals; launcher `S`, child `T` | agree |
| Both baselines equal plain exec for SIGTSTP; base-go darwin SIGSTOP: exit 255, child disappears; fixed by the Go cells | same (`Exit 255`, L and P gone; Linux and base-rust fine; all Go cells decode SIGSTOP) | agree |
| Go cells: `fg` hangs | same, 72/72 Go ladder runs | agree |
| Go cells: ^Z does nothing | same (child already stopped; launcher not in the foreground group) | agree |
| Go cells: ^C does nothing; darwin: ^\ ends launcher and child, rc 131 | **darwin: ^C ends the job, `$?` 130, under bash and zsh (36/36 Go-cell ladder runs in run 2)**. The ^\-only outcome appears exactly when the job inherits SIGINT = IGN, which the calibration's harness produces: `scripts/run_recover.sh` starts each probe as `one "$l" &` from a non-interactive `sh` (asynchronous lists get INT and QUIT ignored) and `scripts/jcprobe.py:136-140` `default_signals()` resets only PIPE, XFSZ, TTOU, TTIN, TSTP before exec'ing the shell | **disagree on darwin** (harness artifact on the calibration side, reproduced here in run 1 and `raw/artifact/`); the Go runtime's SIGQUIT reset is why ^\ still worked there |
| Go cells, Linux: nothing works; only a signal from another terminal helps | same: ^C and ^\ are held by the kernel until the child is continued | agree |
| `kill -CONT %1` before `fg` resumes the go-opus1 child but not go-opus2's or go-sonnet1's (own process group) | same, 24/24 and 48/48 | agree |
| Rust cells: `fg` hangs, ^Z stops the job, the next `fg` runs it to completion with `$?` 0; `kill -CONT %1` also works | same, all sets | agree |
| Appendix B P1x, darwin: Go cells "running -> ctrl-backslash", Rust cells "running -> ctrl-z" (ladder order ^C, ^Z, ^\) | with default dispositions ^C ends the job straight after the hung `fg` for Go cells (36/36 in run 2 reach step c; termios experiment 10/10) and for Rust cells (rust-opus1 bash, rust-sonnet1 zsh, 1 run each: child gone, prompt back). With the calibration's order both columns would read `ctrl-c` on darwin | **disagree** (same artifact); the Rust job would then end with 130 instead of finishing with 0 |
| Appendix B P1x, Linux: Go "none", Rust "ctrl-z" | same | agree |
| no leftover process after any run; plain exec never disagreed with itself | same (0 leftovers after cleanup in 864 records; plain exec identical in all reps) | agree |
| Classification: the three Go P1 rows are major because there is "no normal recovery"; rust-sonnet1 D1 minor because ^Z + `fg` recovers | not re-classified here. The Linux facts behind the Go majors stand. On darwin the user does have a one-key way out (^C), but it kills the program (`$?` 130) where plain exec's `fg` completes it; whether that counts as "normal recovery" is the rubric's call. The Rust rows are unaffected (^Z + `fg` completes the job everywhere) | partial: facts for darwin corrected, rubric untouched |

Also consistent with the calibration's `matrix.md` P1/P1k rows (`consistent=false; jobs=running`,
`child_after_kill-CONT_%1` R/S for go-opus1 and T for go-opus2/go-sonnet1).

## Limitations

- Run 1 of this task carried the same artifact it later found in the calibration (probe started
  as a background job, INT/QUIT ignored, bash passing them on); it is kept as evidence
  (`raw/run1-harness-sigign/`, JSON records only) and superseded by run 2 for every table above.
- "`fg` sends no SIGCONT to a job the shell lists as Running" is inferred from go-opus1's
  behaviour (SIGCONT via `kill -CONT %1` finishes its job, `fg` never does), not from shell source.
- The kernel experiment's pty sub-cases are confounded (the child was the session leader; its
  exit waited for the pty to drain, shown as `?Es` on darwin); only the kill(2) rows are used.
- Linux is one container image and kernel (Docker Desktop VM); darwin is one host. bash 3.2.57
  and zsh 5.9 on darwin, bash 5.2.15 and zsh 5.9 in the container. 3 reps per cell; every cell was
  deterministic across reps, which says nothing about rarer races.
- The job's program here is `sleep 3`; the calibration used a Python child. Both ignore the
  terminal, but a program with signal handlers of its own could differ.
- Only P1 (and `kill -CONT %1`) was re-run; S1-S5, P0, P2-P14 of the calibration were not.
- `probe/sigign.go` was built offline inside the scratch Go copy (its module already requires
  x/sys) and used on darwin only; without it `sigign` is `null` on darwin.
- base-go and go-opus2 binaries differ from the recorded ones (go1.27.1 pins vs go1.27.2 here),
  the same finding and the same explanation as the calibration's; sources are identical.
- Independence: `../provenance.json` and `BASE.json` were read before the probes (allowed); the
  calibration's results and scripts only after. The probe, driver, aggregator and experiments are
  this task's own code.
- Scratch (`~/.local/share/heimdall-m00/r4-scratch/M00-T05-r4-x2-t1cal-verify/`) peaked at about
  560 MB (two source copies with Rust `target/`, 46 MB of binaries); build trees, binaries and
  scratch copies were deleted at the end (sizes in the task report).

## Files

- `README.md` (this), `results/provenance.json`, `results/builds.tsv`, `results/build-logs/`
  (per-build manifest and the last lines of each build log, scratch paths redacted).
- `probe/probe.py` (P1 probe), `probe/drive.sh` (matrix driver), `probe/aggregate.py` (tables),
  `probe/build_cells.sh`, `probe/exp_stopped_signal.py`, `probe/exp_fg_termios.py`,
  `probe/sigign.go`.
- `results/table-run2.md`, `results/summary-run2.json` (one row per cell with all reps).
- `raw/run2/<platform>-<shell>/` (one JSON per build x signal x mode with 3 records, one pty
  transcript per record, `driver.log` with probe exit codes, `stdout.log`).
- `raw/run1-harness-sigign/` (JSON records, driver/stdout logs, `table-run1.md`, `summary-run1.json`).
- `raw/artifact/` (deliberate reproduction of the disposition artifact), `raw/experiments/`.
