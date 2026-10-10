# X2 T1 calibration: one behaviour matrix, one severity rubric (M00-T05-r4-x2-t1cal)

Status: `implemented_unverified`. Every observation below was executed and recorded; the
classification applies the rubric given to this task. An independent re-classification from the same
evidence was run by a separate reviewer agent (see "Independent check"); no independent re-run of the
probes was done.

## Correction after the independent check (orchestrator, 2026-10-10)

An independent re-run of scenario P1 with its own probe and builds (`verify/`, a different model,
same digests) agrees with every P1 fact behind the classification except one, on darwin only:
the recovery-ladder runs here inherited SIGINT (and SIGQUIT) ignored, because `scripts/run_recover.sh`
starts each probe as an asynchronous list of a non-interactive `sh` and `jcprobe.py` does not reset
those two signals. With default dispositions, ^C ends the job on darwin (`$?` 130) for the Go cells,
and straight after the hung `fg` for the Rust cells too. So on darwin "^C does nothing, ^\ ends it"
(Results in brief, Uniform classification, Appendix B P1x) should read "^C ends the job (it kills the
program; plain exec's `fg` completes it)". The Linux facts stand (^C and ^\ do nothing for the Go cells
until the child is continued), as do `kill -CONT %1` and the Rust ^Z + `fg` recovery. The rubric's
"normal recovery" excludes ending the job, so the classification is unchanged. Status: P1 is
`verified` by `verify/`; the other scenarios remain `implemented_unverified`.

## Why

X2 gave task T1 (exec-equivalent job control for `heimdall-proto run`, `specs/T1.md`) to three Go
and three Rust implementers. All six pass the hidden tests. Each cell then had its own code reviewer,
so the severities in `results.json` were assigned by six different reviewers. This task measures
the job-control scenarios those reviewers raised with identical probes on every build, and classifies
every build with one rubric. It does not decide anything about the languages.

## Builds (provenance)

Scratch copies were made with `git archive` of the pinned bases (tree digests equal to `BASE.json`),
each cell's implementer diff was applied with `git apply` (all six apply cleanly), and each tree was
built with the prototype's own `build.sh` (all four targets, exit 0). For every cell the implementer
diff produces exactly the evaluated source tree: hunks byte-identical (go-sonnet1, rust-opus2) or
`diff -r` exit 0 between the tree built here and the base plus the evaluator's `change.patch`
(go-opus1, go-opus2, rust-opus1, rust-sonnet1). Details: `provenance.json`, `scripts/build_cells.sh`.

| build | source | darwin-arm64 sha256 (built here) | = recorded? | linux-arm64 sha256 (built here) | = recorded? |
|---|---|---|---|---|---|
| base-go | 84c7665 | f812084ff36d… | no (pin bdfd64a2…) | 3e472e1b9d9d… | no (pin 18d96a07…) |
| base-go-pinned | repository `prototypes/go/dist` (not rebuilt) | bdfd64a2f5a0… | yes | 18d96a07a553… | yes |
| base-rust | 001a791 | f9a3ec8b4683… | yes | 85e038b4728f… | yes |
| T1-go-opus1 | 84c7665 + out/diff.patch | 457ce20fd37f… | yes | 4ae668ad0fb6… | yes |
| T1-go-opus2 | 84c7665 + out/diff.patch | c392df768d67… | no (0faa680a…) | 57baf65f9224… | no (6e740de2…) |
| T1-go-sonnet1 | 84c7665 + implementer/diff.patch | 5d0be6efbc4a… | yes | 40668676204a… | yes |
| T1-rust-opus1 | 001a791 + implementer/diff.patch | b82bd9600a76… | yes | 657e9d1e3b48… | yes |
| T1-rust-opus2 | 001a791 + implementer/diff.patch | 02f0baa79c5a… | yes | 36986c356d3e… | yes |
| T1-rust-sonnet1 | 001a791 + implementer-out/diff.patch | 92c44aa37d90… | yes | 0ceac2939cea… | yes |

The two Go mismatches are toolchain, not source. Only go1.27.2 is installed here (`go version -m`
of every Go build made here says go1.27.2). The base pin was built with go1.27.1 (the pinned binary
says go1.27.1), so it was probed twice: `base-go` (rebuilt with go1.27.2, the toolchain of the
go-opus1 and go-sonnet1 builds, whose digests match) and `base-go-pinned` (the pinned bytes). Their
results are equal in every scenario, rep and platform/shell. For go-opus2 the evaluated darwin
artifact is 5212000 bytes, which is the size of the go1.27.1 base pin; the go1.27.2 builds of the
same sources are 5212224 bytes. That the evaluated go-opus2 artifact was built with go1.27.1 is an
inference from this size match; it could not be reproduced without go1.27.1.

## Method

Driver: `scripts/jcprobe.py` (one scenario = one fresh interactive shell on a fresh pty, or a
non-shell parent written in the probe). The probe is the third party: it sends each signal to exactly
one PID with `kill(2)`. The job's program is `scripts/child.py`, a single process (no grandchildren),
so under plain exec a signal to its PID reaches the whole job. Each scenario is run as plain exec
(the control, `plain`) and as `heimdall-proto run -- <same argv>` for every build. Shells:
`bash --norc --noprofile -i` and `zsh -f -i`, `TERM=dumb`, a fixed prompt, markers for
synchronisation. Process states come from `/proc` (Linux) or `sysctl(KERN_PROC_PID)` (darwin).
Every PID the probe learns is recorded with its start time and is signalled (SIGCONT, SIGKILL) only
if that same process still exists; after each scenario the probe checks that none is left
(`cleanup.left_after_cleanup` is empty in every run).

Platforms and repetitions (all `exit=0` for every build):

| set | platform | shell | reps | when (UTC) |
|---|---|---|---|---|
| main | darwin-arm64 (macOS 27.0.1) | bash 3.2.57 | 2 | 2026-10-10 05:12-05:31 |
| main | linux-arm64, `heimdall-g02-harness:d0c8e448a3a7`, `--network none`, caps dropped, probe is PID 1 | bash 5.2.15 | 2 | same window |
| main | darwin-arm64 | zsh 5.9 (shell scenarios only; P0/P6/P13 have no shell) | 2 | 05:32-05:48; P14 rerun later (below) |
| race | darwin and linux | bash | 10 | P10r, P11r (`scripts/jcprobe_race.py`) |
| recovery | darwin and linux | bash | 2 | P1x, P2x (`scripts/jcprobe_recover.py`) |
| P9e follow-up | darwin (bash, zsh) and linux (bash) | | 2 | P9e0-fg3, P9e-bg-fg3 (`scripts/jcprobe_p9e.py`), after the independent check |

Five builds ran concurrently per platform (each in its own pty/shell). The first zsh pass of P14
failed for every build including plain exec because of the probe itself (zsh history expansion of
`!@` in the probe's `echo "...$!@"`); it was rerun after `unsetopt bang_hist` and the rerun replaces
it in `raw/darwin-zsh` (marked `probe_rerun`).

**Recovery ladder** (the `rec` value): after the scenario's observation point the probe types `fg`
(8 s for the job to finish or stop), `fg` again, then ^Z and `fg`, then ^C. `rec` is the first step
after which the shell's prompt came back with the job ended: `none-needed` (it had already ended),
`fg`, `ctrlz+fg`, `ctrlc` (^C gave the prompt back), or `failed` (nothing worked; the probe then
kills the processes by exact PID). In P9e the ladder starts at ^Z, and there `ctrlc` only means ^C
at an idle prompt after the job had already stopped again (the job was not ended); the P9e follow-up
(P9e0-fg3, P9e-bg-fg3) replaces that with up to three `fg`. P1x/P2x escalate after a hung `fg` with
^C, ^Z, ^\ (5 s each); because ^C comes first there, a Rust child that later resumes on Linux dies of
the pending SIGINT, so P1x shows only which key returned the prompt.

### Scenarios

| ID | setup (plain exec = the same argv without the launcher) | third party / user actions | reviewer defects probed |
|---|---|---|---|
| P0-STOP, P0-TSTP | S1 with pipes: non-shell parent, job in its own non-orphaned group, stdin/stdout/stderr pipes; child sleeps 1.5 s, exits 7 | stop child, 0.5 s, SIGCONT child | go-sonnet1 (no pipe variant) |
| P1-STOP, P1-TSTP | background job (`&`) of the interactive shell, stdio redirected to /dev/null | stop child; `jobs -l`; recovery ladder | go-opus1 D1, go-opus2 D1, go-sonnet1 D3 |
| P1k-TSTP | P1, then `kill -CONT %1` before the ladder | | (expert recovery) |
| P1x-TSTP | P1, then escalating keys after a hung `fg` | | (recovery depth) |
| P2-STOP, P2-TSTP, P2k-TSTP, P2x-TSTP | as P1/P1k/P1x with stdio on the terminal (`cmd &`, never foregrounded) | | rust-sonnet1 D1, go-opus2 D1 |
| P2n-TTIN | background job with terminal stdio whose child reads the terminal (kernel SIGTTIN to the reader's group) | `jobs`, `fg`, typed line | natural variant of P2 |
| P3-STOP, P3-TSTP | non-job-control parent with terminal stdio: `bash -c '<job>; echo RC=$?'` typed at the prompt; child sleeps 2 s, exits 7 | stop child, 0.5 s, SIGCONT child only; wait 6 s for `RC=` | rust-opus1 D1, rust-opus2 D1 |
| P4-STOP, P4-TSTP | foreground job, stdio redirected | stop child; prompt, `$?`, `jobs`, ladder | go-sonnet1 D1 |
| P4t-STOP, P4t-TSTP | foreground job, terminal stdio (S2 without the SIGCONT) | same | reference |
| P5-STOP, P5-TSTP | foreground job, ^Z, `bg`, then stop child | `jobs`, ladder | go-opus2 D1 ("& or bg") |
| P6-STOP, P6-TSTP | non-shell parent on a pty (session leader) puts the job in its own group in the foreground and waits without WUNTRACED | stop child, 0.5 s, SIGCONT child only; wait 6 s | go-opus2 D1 (second case) |
| P7-TTOU, P7-TTIN | foreground job | third party sends SIGTTOU (SIGTTIN) to the child | go-opus1 D3, go-opus2 D2 |
| P7n-TTOU | background job, terminal stdio, child calls `tcsetattr` (kernel SIGTTOU) | `jobs`, `fg` | same |
| P8 | foreground job; terminal ^Z (whole group) | SIGCONT to the launcher only (plain: the child); states at 1 s and 5 s | rust-opus1 D3, rust-sonnet1 D4 |
| P9 | nested real `bash -i` as the job: `suspend`, outer `bg`, outer `fg`, `exit 3` | which shell reads the terminal after each step | rust-opus2 D2, rust-opus1 reviewer probe |
| P9e0, P9e-bg | job is a minimal job-control program (own group, takes the terminal, `suspend` = SIGSTOP to its group, never re-takes the terminal): `suspend`, [outer `bg`], outer `fg` | does the child get the terminal back and answer? `exit 3` -> `$?` | rust-opus2 D2 (restore_fg) |
| P9e0-fg3, P9e-bg-fg3 | follow-up after the independent check (`scripts/jcprobe_p9e.py`): as P9e, then up to three `fg`, each followed by a typed line | after which `fg` the child answers; where the typed lines went | same |
| P10 | foreground terminal reader; 3 x (^Z, 1.5 s, `bg` -> immediate SIGTTIN, `jobs`, `fg`); then a typed line and ^D | | go-opus1 D2, rust-sonnet1 D2/D3 |
| P11 | arm (stop child with SIGTSTP, SIGCONT to the launcher / plain: the child, `fg`), then 3 x (^Z, 1.2 s, `fg`) | job running after every `fg`, `$?` 0 | rust-sonnet1 D2/D3, go-opus1 D2 |
| P10r, P11r | P10/P11 with a check after every `fg` for an immediate re-stop, and one more `fg` if so; 10 reps | | same |
| P12-S3 | S3: child stops itself with SIGTSTP; SIGCONT to the launcher only (plain: the child); states sampled for 1 s | then `jobs`, `fg`, typed line, `$?` 6 | go-opus2 D3 (window) |
| P13-STOP, P13-TSTP | S1 in an orphaned process group (the launcher's parent has exited) | stop child, 0.5 s, SIGCONT child | go-sonnet1 D2 (orphan check) |
| P14 | another job (`sleep 30 &`) is stopped; the child moves itself into that job's group and stops itself | SIGCONT to the launcher only (plain: the child); is the other job still stopped? | rust-opus1 D2 (ungated killpg) |

### Rubric, as applied

The rubric given to this task, with the definitions used here:

- **blocker**: a security-boundary breach or loss of user data.
- **major**: diverges from plain exec in a scenario plausible for an interactive user, leaves a
  process stopped or hung or the shell's job state wrong, the user has no normal way to recover short
  of killing processes, and the divergence is new relative to the same language's baseline or is in
  a scenario S1-S5 requires.
- **minor**: needs an unusual setup, or is cosmetic, or has a normal recovery.
- **pre-existing**: the same-language baseline shows the same divergence in the same scenario and
  S1-S5 do not require it. Recorded, not counted against the change.

Definitions used:

- *Plausible for an interactive user*: an interactive bash/zsh with foreground and background jobs,
  ^Z, `fg`, `bg`, `jobs`, and a stop or continue sent to a job's process by another process (for
  example `kill -STOP <pid>` from another terminal). *Unusual setup*: a non-shell parent that hands
  the job the terminal (P6), a job-control child that never re-takes the terminal (P9e), a child
  that joins another job's process group (P14), orphaned groups (P13), and microsecond races.
- *Normal way to recover*: the shell's own job control without killing the job: `fg`, `bg`, ^Z then
  `fg`. Not normal: ^C or ^\ (they end the job), `kill` with a PID from another terminal.
  `kill -CONT %N` is recorded separately (P1k/P2k) as an expert recovery; it is not counted as normal.
- *Regression*: the same-language baseline equals plain exec in that scenario on that platform/shell
  (for SIGSTOP variants the Go baseline itself diverges on darwin, so the SIGTSTP variant decides).
- Non-behavioural reviewer defects (tests, labels, comments) cannot be probed; they are classified
  minor and marked as such.

## Results in brief

- The matrix is stable: across the 3 platform/shell sets x 2 reps, the only build whose reps
  disagreed is T1-rust-sonnet1 in P10 (darwin bash and darwin zsh: one of two reps re-stopped right
  after `fg`). No leftover process after any run; the plain-exec control never disagreed with itself.
- All six cells diverge from plain exec in P1 (background job, stdio redirected, third-party stop of
  the child): the shell lists the job as `Running` while the child is stopped. Both baselines equal
  plain exec for SIGTSTP. What differs is recovery. In the three **Go** cells `fg` hangs and ^Z and ^C
  do nothing (darwin: ^\ ends launcher and child, rc 131; Linux: nothing works); after that only a
  signal from another terminal helps. Typed before `fg`, `kill -CONT %1` resumes the go-opus1 child,
  but not the go-opus2 and go-sonnet1 children (they are in their own process group). In the three **Rust** cells `fg` hangs too, but ^Z stops the job
  and the next `fg` runs it to completion with `$?` 0; `kill -CONT %1` also works.
- go-opus2 and rust-sonnet1 also diverge in the same way with stdio on the terminal (P2; go-opus2
  also after ^Z + `bg`, P5); go-opus1, go-sonnet1, rust-opus1 and rust-opus2 equal plain exec there.
  Natural kernel stops of background jobs (SIGTTIN P2n, SIGTTOU P7n) are handled by every build
  (listed stopped, `fg` resumes; the Go builds label the SIGTTOU stop as SIGTSTP).
- Pre-existing divergences that remain in cells: every build (both baselines included) hangs in P6;
  every Go build reports a SIGTTOU stop as SIGTSTP (P7-TTOU `$?` 146/148 instead of 150, P7n label);
  the Rust baseline and rust-opus1/opus2 hang in P3 (^Z + `fg` recovers; rust-sonnet1 and all Go
  builds pass); the Rust baseline and all Rust cells leave the child stopped in P8 (`fg` recovers) and
  fail P9e-bg, and rust-sonnet1 and the Rust baseline also fail P9e0 (the cells: every `fg` re-stops
  the job at once and the next typed line runs in the outer shell; the baseline: `fg` hangs). The Go
  cells pass P9e0 and P9e-bg everywhere; the Go baseline passes them on Linux only.
- Fixed by the cells relative to their baselines (not counted): Rust S1 hang (P0) and orphaned-group
  SIGSTOP hang (P13-STOP); Go darwin SIGSTOP decode (base-go exits 255 and the child disappears in
  P1/P2/P4/P4t/P5-STOP, P9, P9e; in P6-STOP the probe's SIGCONT then finds no child, recorded as the
  only probe `error` in the data); Rust S3 (P12); P3 by rust-sonnet1; P9e0 by rust-opus1/opus2.
- Re-stop right after `fg` (P10/P10r/P11r): go-opus1 2 of 10 P10r runs on Linux; rust-sonnet1 1 of
  10 P10r on darwin plus the two P10 reps above; base-rust 1 of 10 P10r on darwin; never for plain,
  base-go, base-go-pinned, go-opus2, go-sonnet1, rust-opus1, rust-opus2. One more `fg` always resumed
  the job. (base-rust also fails P11r's arm step in all 10 Linux runs, child left stopped after `fg`;
  that is the baseline's S2/S3 failure, also visible in the main-matrix P11 on Linux.)
- S3 window (launcher running while the child is still stopped after a SIGCONT to the launcher):
  Go cells 0.1-1.2 ms (Go baseline 0.1-3.3 ms), rust-opus2 0.1-0.9 ms, rust-opus1 about 10 ms,
  rust-sonnet1 about 31 ms (the Rust baseline never continues the child: S3 failure); no
  shell-visible difference at the 1 s check in any cell. Under plain exec the child itself runs
  0.1-0.4 ms before its SIGTTIN stop.
- rust-opus1 continues the other job's stopped process group in P14 on every platform/shell (plain
  exec and every other build leave it stopped).

## Uniform classification

One row per (cell, defect): every defect the cell's reviewer listed (D1 = first defect in
`results.json`, and so on), then every further divergence the probes show for that cell (X rows).
"base" = the same-language baseline in the same scenario.

### T1-go-opus1

| defect | reviewer | probes | observation | base | class |
|---|---|---|---|---|---|
| D1 redirected background job: third-party stop not mirrored | major | P1, P1k, P1x | all sets, 2/2: `jobs` Running, child T, launcher S/R; ladder `failed` (`fg` hangs, ^Z and ^C ignored); ^\ ends both on darwin, nothing works on Linux; `kill -CONT %1` before `fg` resumes the child | TSTP = plain | **major** |
| D2 resume race after a stop longer than 1 s (code reading) | minor | P10, P10r, P11, P11r | Linux P10r: 2/10 runs re-stopped right after `fg`; a second `fg` resumed; darwin P10r 0/10, P11r 0/20, main-matrix P10 and P11 0 of 6 runs each. The predicted state (launcher stopped, child running) was not seen | base-go 0 re-stops | minor |
| D3 SIGTTOU reported as SIGTSTP | minor | P7-TTOU, P7n | `$?` 146 (darwin) / 148 (Linux) instead of 150; `Suspended: 18` / `Stopped` instead of `(tty output)` | same | pre-existing |
| D4 tests: mini-shell, sleeps, no background case | minor | none | not behavioural | | minor (non-behavioural) |
| D5 procUnknown on other platforms | minor | none | not probeable on darwin/linux; nothing observed | | minor (latent) |
| X1 non-shell parent hands job the terminal | | P6 | hangs (launcher T, child zombie) | same | pre-existing |
| X2 S3 resume window | | P12-S3 | 0.3-0.9 ms; `jobs` at 1 s = plain | | minor (cosmetic) |

### T1-go-opus2

| defect | reviewer | probes | observation | base | class |
|---|---|---|---|---|---|
| D1a background job (`&` or ^Z+`bg`, redirected or terminal stdio): third-party stop not mirrored | minor | P1, P2, P5, P1k, P2k, P1x, P2x | all sets, 2/2: Running while the child is T; ladder `failed`; ^Z/^C ignored, ^\ ends both on darwin, nothing on Linux; `kill -CONT %1` does not resume the child (its own group) | TSTP = plain | **major** |
| D1b non-shell parent hands job the terminal, continues the child only | minor | P6 | hangs | same | pre-existing |
| D2 SIGTTOU reported as SIGTSTP | minor | P7-TTOU, P7n | as go-opus1 | same | pre-existing |
| D3 S3: shell may list the job running before the child is continued | minor | P12-S3 | window 0.1-1.2 ms; `jobs` at 1 s = plain | similar (0.1-3.3 ms) | minor (cosmetic) |
| D4 tests: sleeps, hard-coded shells | minor | none | not behavioural | | minor (non-behavioural) |

### T1-go-sonnet1

| defect | reviewer | probes | observation | base | class |
|---|---|---|---|---|---|
| D1 `engaged` initializer overstated | minor | P4 | redirected foreground job = plain in every set | | minor (non-behavioural) |
| D2 orphaned-group TOCTOU for SIGSTOP | minor | P13-STOP | = plain (Linux launcher rc 7); the microsecond race was not reproduced | | minor (inferred, not observed) |
| D3 redirected background job never engaged | minor | P1, P1k, P1x | as go-opus2 D1a for P1: Running while T; ladder `failed`; `kill -CONT %1` does not resume the child | TSTP = plain | **major** |
| D4 tests do not compare notice text / branch (a) status | minor | none | not behavioural | | minor (non-behavioural) |
| D5 S1 test uses `sh 'set -m'`, no pipe variant | minor | P0 | pipes variant = plain | | minor (non-behavioural) |
| D6 tests: sleeps, S4 leftovers, cleanup | minor | none | not behavioural | | minor (non-behavioural) |
| X1 non-shell parent hands job the terminal | | P6 | hangs | same | pre-existing |
| X2 SIGTTOU reported as SIGTSTP | | P7-TTOU, P7n | as go-opus1 | same | pre-existing |
| X3 S3 resume window | | P12-S3 | 0.1-0.4 ms | | minor (cosmetic) |

### T1-rust-opus1

| defect | reviewer | probes | observation | base | class |
|---|---|---|---|---|---|
| D1 non-job-control parent with terminal stdio: launcher stops itself, hangs | minor | P3 | all sets, 2/2: no `RC=` within 6 s (launcher T, child zombie); ^Z then `fg` finishes it (inner rc 7) | same | pre-existing |
| D2 `resume_child` continues the child's whole group | minor | P14 | all sets, 2/2: the other job's stopped process is continued (plain: stays stopped) | = plain | minor (unusual setup) |
| D3 ^Z, then SIGCONT to the launcher only: re-stops | minor | P8 | child stays T, job Stopped at 5 s (plain: finished); `fg` finishes it | same | pre-existing |
| D4 pty_tui counts blocked cases as passing | minor | none | not behavioural | | minor (non-behavioural) |
| X1 redirected background job: third-party stop not mirrored (in REPORT, not in the defect list) | | P1, P1k, P1x | Running while T; `fg` hangs; ^Z then `fg` finishes with `$?` 0; `kill -CONT %1` also works | TSTP = plain | minor (normal recovery) |
| X2 non-shell parent hands job the terminal | | P6 | hangs | same | pre-existing |
| X3 job-control child: terminal not handed back after `bg` + `fg` | | P9e-bg, P9e-bg-fg3 | all sets: each `fg` re-stops the job at once ("Stopped" / "suspended (tty input)"), three `fg` never give the child the terminal, typed lines run in the outer shell; only ending the job remains. P9e0 (no `bg`) = plain | fails too (`fg` hangs) | pre-existing |
| X4 S3 resume window | | P12-S3 | about 10 ms (10.0-11.2) | | minor (cosmetic) |

### T1-rust-opus2

| defect | reviewer | probes | observation | base | class |
|---|---|---|---|---|---|
| D1 non-job-control parent with terminal stdio: hangs | minor | P3 | as rust-opus1 D1 | same | pre-existing |
| D2 `restore_fg` cleared on `bg`, so `fg` does not hand the terminal back | minor | P9e-bg, P9 | P9e-bg and P9e-bg-fg3, all sets: each `fg` re-stops the job at once, three `fg` never give the child the terminal, typed lines run in the outer shell; P9e0 (no `bg`) = plain; with a real nested bash (P9) the cell = plain exec, where after `bg` the nested bash takes the terminal itself and the outer shell exits (darwin: the nested bash exits too) | P9e-bg fails too (P9e0 too) | pre-existing |
| D3 test cleanup signals possibly recycled PIDs | minor | none | not behavioural | | minor (non-behavioural) |
| D4 test `read_line` without timeout | minor | none | not behavioural | | minor (non-behavioural) |
| X1 redirected background job: third-party stop not mirrored | | P1, P1k, P1x | as rust-opus1 X1 | TSTP = plain | minor (normal recovery) |
| X2 non-shell parent hands job the terminal | | P6 | hangs | same | pre-existing |
| X3 ^Z, then SIGCONT to the launcher only | | P8 | as rust-opus1 D3 | same | pre-existing |
| X4 S3 resume window | | P12-S3 | 0.1-0.9 ms | | minor (cosmetic) |

### T1-rust-sonnet1

| defect | reviewer | probes | observation | base | class |
|---|---|---|---|---|---|
| D1 background job (`&`) never foregrounded: stop not mirrored | major | P2, P1, P2k, P1k, P2x, P1x | all sets, 2/2: Running while T (terminal and redirected stdio; not after ^Z + `bg`, P5 = plain); `fg` hangs; ^Z then `fg` finishes with `$?` 0; `kill -CONT %1` also works | TSTP = plain | minor (normal recovery) |
| D2 `fresh_cont` outlives its stop (stale-stop race) | minor | P10, P10r, P11r | darwin: re-stop right after `fg` in P10 bash 1/2, zsh 1/2, P10r 1/10; Linux 0/12; a second `fg` resumed | base-rust darwin P10r 1/10 | pre-existing |
| D3 STOP_GRACE halved | minor | same | same observation | same | pre-existing |
| D4 ^Z, then SIGCONT to the launcher only | minor | P8 | as rust-opus1 D3 | same | pre-existing |
| D5 vacuous S4 assertion; no plain-exec control in tests | minor | none | not behavioural | | minor (non-behavioural) |
| D6 test cleanup signals possibly recycled PIDs | minor | none | not behavioural | | minor (non-behavioural) |
| D7 stray .pyc; "Round 5" labels | minor | none | not behavioural (the .pyc is only in the evaluator's diff; the implementer diff has none) | | minor (non-behavioural) |
| X1 non-shell parent hands job the terminal | | P6 | hangs | same | pre-existing |
| X2 job-control child: terminal not handed back after `suspend` (with or without `bg`) | | P9e0, P9e-bg, P9e*-fg3 | all sets: each `fg` re-stops the job at once, three `fg` never give the child the terminal, typed lines run in the outer shell. rust-opus1/opus2 pass P9e0; the S4 hidden checks with a real nested bash/zsh pass (the implementer diff adds no terminal hand-back, so the pass appears to rely on the nested shell taking the terminal itself: inference) | fails too (`fg` hangs) | pre-existing (would be major if S4 is read as any nested job-control program) |
| X3 S3 resume window | | P12-S3 | about 31 ms (30.1-32.2) | | minor (cosmetic) |

### Counts

| cell | blocker | major | minor | pre-existing | major (one line) |
|---|---|---|---|---|---|
| T1-go-opus1 | 0 | 1 | 4 | 2 | redirected background job stopped by a third party: listed Running, `fg` hangs, ^Z/^C ignored (only `kill -CONT %1` typed before `fg` helps) |
| T1-go-opus2 | 0 | 1 | 2 | 2 | any background job (`&` or `bg`, any stdio) stopped by a third party: listed Running, `fg` hangs, ^Z/^C and `kill -CONT %1` do not help |
| T1-go-sonnet1 | 0 | 1 | 6 | 2 | redirected background job stopped by a third party: listed Running, `fg` hangs, ^Z/^C and `kill -CONT %1` do not help |
| T1-rust-opus1 | 0 | 0 | 4 | 4 | |
| T1-rust-opus2 | 0 | 0 | 4 | 4 | |
| T1-rust-sonnet1 | 0 | 0 | 5 | 5 | |

Minor counts include reviewer items that are not behaviour or cannot be probed here (go-opus1 2,
go-opus2 1, go-sonnet1 4, rust-opus1 1, rust-opus2 2, rust-sonnet1 3) and the cosmetic S3-window row
every cell has. Without those, the behavioural minors are: go-opus1 1 (re-stop after `fg`), go-opus2 0,
go-sonnet1 1 (unreproduced orphan race), rust-opus1 2 (P1, P14), rust-opus2 1 (P1), rust-sonnet1 1 (P1/P2).

### Where this contradicts a reviewer

- **go-opus2 D1 (reviewer minor -> major)** and **go-sonnet1 D3 (reviewer minor -> major)**: the
  same scenario the go-opus1 reviewer rated major gives the same result in these builds (regression
  against base-go, no normal recovery), and for these two even `kill -CONT %1` does not reach the child.
  The go-opus2 case also covers `cmd &` with the terminal on stdio (P2) and ^Z + `bg` (P5).
- **rust-sonnet1 D1 (reviewer major -> minor)**: the divergence is real and a regression, but ^Z then
  `fg` recovers it on every platform and shell (the reviewer's probe stopped at `jobs -l`).
- **rust-opus1, rust-opus2**: their reviewers did not list the P1 divergence (rust-opus1's REPORT
  discloses it); it is added here as minor.
- **go-opus1 D3, go-opus2 D2 (SIGTTOU as SIGTSTP), rust-opus1 D3 and rust-sonnet1 D4 (P8),
  rust-opus2 D2 (P9e-bg), rust-opus1 D1 and rust-opus2 D1 (P3)**: observed, but the baseline already
  shows the same divergence, so pre-existing rather than minor.
- **rust-sonnet1 D2/D3**: the re-stop after `fg` was observed (not only inferred), but base-rust shows
  it too in the same probe, so pre-existing; the counts (darwin 3 of 14 runs for the cell, 1 of 14 for
  the baseline) are too small to say whether the change made it more frequent.
- **go-opus1 D2**: a re-stop after `fg` was observed (Linux 2/10) and never for base-go; minor. The
  failure mode the reviewer predicted (launcher stopped, child running) was not seen, and the probes
  cannot show which code path caused the re-stop.
- **rust-opus1 D2 (P14)**: confirmed by observation (the reviewer found it by code reading); stays minor.
- Factual statements in the reviews that the probes contradict: the rust-opus1 review says no
  regressions were found (P1 and P14 regress against base-rust); the rust-opus1 and rust-opus2 reviews
  say the P3 launcher is never resumed (^Z then `fg` finishes the job, inner `$?` 7); the go-opus2
  review finds no blocker or major defect (P1, P2 and P5 have no normal recovery).

## Independent check

A separate reviewer agent was given the same rubric, `results.json`, the scripts, `matrix.md`,
`extra.md` and `raw/`, but not this classification, and classified every cell on its own. Its result:
the same three majors (go-opus1 D1, go-opus2 D1 background-job part, go-sonnet1 D3), no blocker, no
Rust major, and the same pre-existing calls. It defined normal recovery to include `kill -CONT %N`
but required it to work after the user's natural first reaction (`fg`), which it does not in
go-opus1, so go-opus1 D1 stays major under both definitions. Differences, all in the minor or
pre-existing columns: it counted the S3 window only where a deliberate delay of 10 ms or more causes
it (rust-opus1, rust-sonnet1) plus go-opus2's listed item, not for go-opus1, go-sonnet1 or
rust-opus2; it kept rust-sonnet1 D2 and D3 as minor (mechanisms not directly probed) and recorded the
observed re-stop as a separate pre-existing row; it kept go-opus1 D2 as minor and the observed re-stop
as a separate minor row. Its counts: go-opus1 0/1/4/2, go-opus2 0/1/2/2, go-sonnet1 0/1/5/2,
rust-opus1 0/0/4/4, rust-opus2 0/0/3/4, rust-sonnet1 0/0/7/5 (blocker/major/minor/pre-existing).
It also found that the P9e ladder had recorded ^C at an idle prompt as `ctrlc`; the P9e follow-up
(P9e0-fg3, P9e-bg-fg3) was added because of that, and the P9e rows above use it.

## Limitations

- The rubric's thresholds ("plausible", "normal recovery") are applied with the definitions above.
  If `kill -CONT %1` counted as normal even though the shell shows the job as Running (no cue to use
  it) and it only works before `fg`, go-opus1 D1 would become minor; go-opus2 D1a and go-sonnet1 D3
  would stay major.
- Third-party stops of a background job's process are the only trigger for the major rows; natural
  kernel stops (SIGTTIN/SIGTTOU) of background jobs are handled by every build (P2n, P7n).
- Races: 10 reps per race probe per platform (bash only) cannot estimate small rates or distinguish
  a cell's rate from its baseline's. Five builds ran concurrently, which changes timing.
- go-opus2's recorded artifact was not reproduced byte-for-byte (go1.27.1 not installed); its
  sources are identical and the base pair shows no go1.27.1/go1.27.2 behaviour difference.
- zsh was run on darwin only (the Linux image has no zsh). Linux results come from one container
  image and kernel (Docker Desktop VM); no native Linux host.
- P9 with a real nested bash is chaotic under plain exec (after `bg` the nested bash takes the
  terminal and the outer shell exits), so it cannot test rust-opus2 D2 directly; P9e uses an
  emulated job-control child that does not re-take the terminal, which no real shell was shown to do.
- The S3 window is a process-state measurement (sampled in a tight loop); the shell's job table was
  only checked at 1 s.
- `child.py` is Python; a C program could differ in signal-restart details (for example the SIGTTOU
  probe retries `tcsetattr` on EINTR).
- Probe defects found and fixed during the runs: the zsh P14 history expansion (rerun, marked); the
  P9e recovery ladder (see Method; superseded by the P9e follow-up).
- Not probed directly here, covered only by the hidden tests (14/14 for every cell): S2's
  third-party SIGCONT of a stopped foreground child, S4 exactly as written (suspend, `fg`, `exit 3`
  with a real nested bash or zsh; P9 inserts a `bg`), and S5's `--meta-file`.
- When a cell re-stops a job right after `fg` (P10 rust-sonnet1, P9e Rust cells) the shell prompt
  returns, and a line the user types for the job runs as a shell command instead. Plain exec does the
  same whenever a job stops; it is recorded with those rows, not as a separate defect.
- Race statistics: go-opus1 Linux P10r 2/10 against 0/10 for base-go (one-sided Fisher p about 0.24);
  rust-sonnet1 darwin 3/14 against 1/14 for base-rust (p about 0.30). Neither difference is
  established.
- If a third-party stop of a background job's process is judged implausible for an interactive user,
  the three Go majors become minor; if a wrong job state alone (shell shows Running while the child
  is stopped) is judged major whatever the recovery, all six cells get a major for P1.

## Files

- `scripts/`: `build_cells.sh` (rebuild), `child.py` (job program), `jcprobe.py` (scenarios),
  `jcprobe_race.py` (P10r/P11r), `jcprobe_recover.py` (P1x/P2x), `jcprobe_p9e.py` (P9e follow-up,
  run per build with the same flags; Linux through the same `docker run` line), `run_matrix.sh`, `run_race.sh`,
  `run_recover.sh` (drivers; darwin uses private binary copies under `/tmp`, Linux the image),
  `analyze.py` (matrix), `summarize_extra.py` (race/recovery/S3 tables), `consolidate.py` (copies and
  redacts raw outputs; refuses home paths, the user name and canary strings).
- `raw/<set>/<build>.json`: every run with its observations and redacted transcript (`<tmp>`,
  `<bin>`, `<py>` placeholders; for later reps identical to rep 1 the transcript is omitted);
  `<build>.log` one line per run; `exit-codes.txt` real exit statuses of each probe process.
- `matrix.json`, `matrix.md`: the matrix below; `extra.json`, `extra.md`: the tables below;
  `provenance.json`: builds and digests.

Reproduce (paths relative to the repository root; `<scratch>` is any private directory):
`sh <calib>/scripts/build_cells.sh <scratch> <repo> T1-go-opus1 ...` after preparing `<scratch>/{go,rust}`
as described above; copy each darwin binary to `/tmp/t1cb/<build>/heimdall-proto`; then
`sh <calib>/scripts/run_matrix.sh <scratch> darwin bash 2 5`, `... linux bash 2 5`,
`... darwin zsh 2 5 <shell scenarios>`, `run_race.sh <scratch> <platform> bash 10 5 P10r,P11r`,
`run_recover.sh <scratch> <platform> bash 2 5 P1x-TSTP,P2x-TSTP`; then `consolidate.py`, `analyze.py`,
`summarize_extra.py`.

## Appendix A: full probe matrix (generated by scripts/analyze.py)

### darwin-bash

| scenario | plain | base-go | base-go-pinned | T1-go-opus1 | T1-go-opus2 | T1-go-sonnet1 | base-rust | T1-rust-opus1 | T1-rust-opus2 | T1-rust-sonnet1 |
|---|---|---|---|---|---|---|---|---|---|---|
| P0-STOP | rc=7; completed=true; child_reaped=true | = | = | = | = | = | child_reaped=false; rc=hung | = | = | = |
| P0-TSTP | rc=7; completed=true; child_reaped=true | = | = | = | = | = | child_reaped=false; rc=hung | = | = | = |
| P1-STOP | jobs=stopped[Suspended (signal): 17]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=done[Exit 255]; rc=null; rec=none-needed | completed=false; child=gone; jobs=done[Exit 255]; rc=null; rec=none-needed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg |
| P1-TSTP | jobs=stopped[Suspended: 18]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg |
| P1k-TSTP | jobs=stopped[Suspended: 18]; child=T; consistent=true; rec=fg; rc=0; completed=true; child_after_kill-CONT_%1=R | = | = | consistent=false; jobs=running | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running | consistent=false; jobs=running | consistent=false; jobs=running |
| P2-STOP | jobs=stopped[Suspended (signal): 17]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=done[Exit 255]; rc=null; rec=none-needed | completed=false; child=gone; jobs=done[Exit 255]; rc=null; rec=none-needed | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running; rec=ctrlz+fg |
| P2-TSTP | jobs=stopped[Suspended: 18]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running; rec=ctrlz+fg |
| P2k-TSTP | jobs=stopped[Suspended: 18]; child=T; consistent=true; rec=fg; rc=0; completed=true; child_after_kill-CONT_%1=R | = | = | = | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running |
| P2n-TTIN | jobs=stopped[Stopped (tty input): 21]; child=T; consistent=true; rec=fg; rc=4; out_ok=true; completed=true | = | = | = | = | = | = | = | = | = |
| P3-STOP | rc=7; rec=none-needed; inner_rc=7; completed=true | = | = | = | = | = | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | = |
| P3-TSTP | rc=7; rec=none-needed; inner_rc=7; completed=true | = | = | = | = | = | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | = |
| P4-STOP | prompt=true; notice=Stopped; $?=145; jobs=stopped[Suspended (signal): 17]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | = | = | = | = | = | = | = |
| P4-TSTP | prompt=true; notice=Stopped; $?=146; jobs=stopped[Suspended: 18]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P4t-STOP | prompt=true; notice=Stopped; $?=145; jobs=stopped[Suspended (signal): 17]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | = | = | = | = | = | = | = |
| P4t-TSTP | prompt=true; notice=Stopped; $?=146; jobs=stopped[Suspended: 18]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P5-STOP | jobs=stopped[Suspended (signal): 17]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=done[Exit 255]; rc=null; rec=none-needed | completed=false; child=gone; jobs=done[Exit 255]; rc=null; rec=none-needed | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | = |
| P5-TSTP | jobs=stopped[Suspended: 18]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | = |
| P6-STOP | rc=7; completed=true | completed=null; error=ProcessLookupError: [Errno 3] No such process; rc=null | completed=null; error=ProcessLookupError: [Errno 3] No such process; rc=null | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung |
| P6-TSTP | rc=7; completed=true | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung |
| P7-TTIN | prompt=true; notice=Stopped; $?=149; jobs=stopped[Stopped (tty input): 21]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P7-TTOU | prompt=true; notice=Stopped; $?=150; jobs=stopped[Stopped (tty output): 22]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[Suspended: 18]; $?=146 | jobs=stopped[Suspended: 18]; $?=146 | jobs=stopped[Suspended: 18]; $?=146 | jobs=stopped[Suspended: 18]; $?=146 | jobs=stopped[Suspended: 18]; $?=146 | = | = | = | = |
| P7n-TTOU | jobs=stopped[Stopped (tty output): 22]; child=T; completed_in_bg=false; consistent=true; rec=fg; rc=3 | jobs=stopped[Suspended: 18] | jobs=stopped[Suspended: 18] | jobs=stopped[Suspended: 18] | jobs=stopped[Suspended: 18] | jobs=stopped[Suspended: 18] | = | = | = | = |
| P8 | child_1s=R; jobs_1s=stopped[Suspended: 18]; completed_by_5s=true; jobs_5s=done[Done]; rec=none-needed | = | = | = | = | = | child_1s=T; completed_by_5s=false; jobs_5s=stopped[Suspended: 18]; rec=fg | child_1s=T; completed_by_5s=false; jobs_5s=stopped[Suspended: 18]; rec=fg | child_1s=T; completed_by_5s=false; jobs_5s=stopped[Suspended: 18]; rec=fg | child_1s=T; completed_by_5s=false; jobs_5s=stopped[Suspended: 18]; rec=fg |
| P9 | suspend_notice=true; who_after_bg=null; jobs_after_bg=null; who_after_fg=null; rc_after_exit=null; outer_shell_alive_at_end=false | suspend_notice=false | suspend_notice=false | = | = | = | jobs_after_bg=running; outer_shell_alive_at_end=true; who_after_bg=outer | = | = | = |
| P9e-bg | suspend_notice=true; $?=145; jobs_after_bg=stopped[Stopped (tty input): 21]; child_after_bg=T; child_answers_after_fg=true; rc_after_exit=3; rec=none-needed | child_after_bg=gone; child_answers_after_fg=false; jobs_after_bg=none; rc_after_exit=null; $?=255; rec=ctrlc; suspend_notice=false | child_after_bg=gone; child_answers_after_fg=false; jobs_after_bg=none; rc_after_exit=null; $?=255; rec=ctrlc; suspend_notice=false | = | = | = | child_answers_after_fg=false; jobs_after_bg=running; rc_after_exit=null; rec=failed | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc |
| P9e0 | suspend_notice=true; $?=145; jobs_after_bg=null; child_after_bg=null; child_answers_after_fg=true; rc_after_exit=3; rec=none-needed | child_answers_after_fg=false; rc_after_exit=null; $?=255; rec=ctrlc; suspend_notice=false | child_answers_after_fg=false; rc_after_exit=null; $?=255; rec=ctrlc; suspend_notice=false | = | = | = | child_answers_after_fg=false; rc_after_exit=null; rec=failed | = | = | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc |
| P10 | jobs=[stopped[Stopped (tty input): 21], stopped[Stopped (tty input): 21], stopped[Stopped (tty input): 21]]; child_after_bg=[T, T, T]; consistent=true; child_after_fg=[R, R, R]; echoed=true; rc=0 | = | = | = | = | = | = | = | = | child_after_fg=[R, R, T] or [R, R, R]; echoed=false or true; rc=127 or 0 ~ |
| P11 | arm_notice=true; child_after_arm_fg=R; cycle_notices=[true, true, true]; running_after_each_fg=true; finished=true; rc=0 | = | = | = | = | = | = | = | = | = |
| P12-S3 | $?=146; child_after_1s=T; consistent=true; jobs=stopped[Stopped (tty input): 21]; rec=fg; rc=6; out_ok=true | = | = | = | = | = | consistent=false; jobs=stopped[Suspended: 18] | = | = | = |
| P13-STOP | completed=true; all_gone=true; launcher_rc=null | = | = | = | = | = | all_gone=false | = | = | = |
| P13-TSTP | completed=true; all_gone=true; launcher_rc=null | = | = | = | = | = | = | = | = | = |
| P14 | notice=true; other_job_left_stopped=true | = | = | = | = | = | = | other_job_left_stopped=false | = | = |

### darwin-zsh

| scenario | plain | base-go | base-go-pinned | T1-go-opus1 | T1-go-opus2 | T1-go-sonnet1 | base-rust | T1-rust-opus1 | T1-rust-opus2 | T1-rust-sonnet1 |
|---|---|---|---|---|---|---|---|---|---|---|
| P1-STOP | jobs=stopped[suspended (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=none; rc=null; rec=none-needed | completed=false; child=gone; jobs=none; rc=null; rec=none-needed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg |
| P1-TSTP | jobs=stopped[suspended]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg |
| P1k-TSTP | jobs=stopped[suspended]; child=T; consistent=true; rec=fg; rc=0; completed=true; child_after_kill-CONT_%1=R | = | = | consistent=false; jobs=running | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running | consistent=false; jobs=running | consistent=false; jobs=running |
| P2-STOP | jobs=stopped[suspended (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=none; rc=null; rec=none-needed | completed=false; child=gone; jobs=none; rc=null; rec=none-needed | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running; rec=ctrlz+fg |
| P2-TSTP | jobs=stopped[suspended]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running; rec=ctrlz+fg |
| P2k-TSTP | jobs=stopped[suspended]; child=T; consistent=true; rec=fg; rc=0; completed=true; child_after_kill-CONT_%1=R | = | = | = | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running |
| P2n-TTIN | jobs=stopped[suspended (tty input)]; child=T; consistent=true; rec=fg; rc=4; out_ok=true; completed=true | = | = | = | = | = | = | = | = | = |
| P3-STOP | rc=7; rec=none-needed; inner_rc=7; completed=true | = | = | = | = | = | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | = |
| P3-TSTP | rc=7; rec=none-needed; inner_rc=7; completed=true | = | = | = | = | = | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | = |
| P4-STOP | prompt=true; notice=suspended (signal); $?=145; jobs=stopped[suspended (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | = | = | = | = | = | = | = |
| P4-TSTP | prompt=true; notice=suspended; $?=146; jobs=stopped[suspended]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P4t-STOP | prompt=true; notice=suspended (signal); $?=145; jobs=stopped[suspended (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | completed=false; child=gone; jobs=none; notice=null; rc=null; $?=255; rec=none-needed | = | = | = | = | = | = | = |
| P4t-TSTP | prompt=true; notice=suspended; $?=146; jobs=stopped[suspended]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P5-STOP | jobs=stopped[suspended (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | completed=false; child=gone; jobs=none; rc=null; rec=none-needed | completed=false; child=gone; jobs=none; rc=null; rec=none-needed | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | = |
| P5-TSTP | jobs=stopped[suspended]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | = |
| P7-TTIN | prompt=true; notice=suspended (tty input); $?=149; jobs=stopped[suspended (tty input)]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P7-TTOU | prompt=true; notice=suspended (tty output); $?=150; jobs=stopped[suspended (tty output)]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[suspended]; notice=suspended; $?=146 | jobs=stopped[suspended]; notice=suspended; $?=146 | jobs=stopped[suspended]; notice=suspended; $?=146 | jobs=stopped[suspended]; notice=suspended; $?=146 | jobs=stopped[suspended]; notice=suspended; $?=146 | = | = | = | = |
| P7n-TTOU | jobs=stopped[suspended (tty output)]; child=T; completed_in_bg=false; consistent=true; rec=fg; rc=3 | jobs=stopped[suspended] | jobs=stopped[suspended] | jobs=stopped[suspended] | jobs=stopped[suspended] | jobs=stopped[suspended] | = | = | = | = |
| P8 | child_1s=R; jobs_1s=running; completed_by_5s=true; jobs_5s=none; rec=none-needed | = | = | = | = | = | child_1s=T; completed_by_5s=false; jobs_1s=stopped[suspended]; jobs_5s=stopped[suspended]; rec=fg | child_1s=T; completed_by_5s=false; jobs_1s=stopped[suspended]; jobs_5s=stopped[suspended]; rec=fg | child_1s=T; completed_by_5s=false; jobs_1s=stopped[suspended]; jobs_5s=stopped[suspended]; rec=fg | child_1s=T; completed_by_5s=false; jobs_1s=stopped[suspended]; jobs_5s=stopped[suspended]; rec=fg |
| P9 | suspend_notice=true; who_after_bg=null; jobs_after_bg=null; who_after_fg=null; rc_after_exit=null; outer_shell_alive_at_end=false | suspend_notice=false | suspend_notice=false | = | = | = | jobs_after_bg=running; outer_shell_alive_at_end=true; who_after_bg=outer | = | = | = |
| P9e-bg | suspend_notice=true; $?=145; jobs_after_bg=stopped[suspended (tty input)]; child_after_bg=T; child_answers_after_fg=true; rc_after_exit=3; rec=none-needed | child_after_bg=gone; child_answers_after_fg=false; jobs_after_bg=none; rc_after_exit=null; $?=255; rec=failed; suspend_notice=false | child_after_bg=gone; child_answers_after_fg=false; jobs_after_bg=none; rc_after_exit=null; $?=255; rec=failed; suspend_notice=false | = | = | = | child_answers_after_fg=false; jobs_after_bg=running; rc_after_exit=null; rec=failed | child_answers_after_fg=false; rc_after_exit=null; rec=failed | child_answers_after_fg=false; rc_after_exit=null; rec=failed | child_answers_after_fg=false; rc_after_exit=null; rec=failed |
| P9e0 | suspend_notice=true; $?=145; jobs_after_bg=null; child_after_bg=null; child_answers_after_fg=true; rc_after_exit=3; rec=none-needed | child_answers_after_fg=false; rc_after_exit=null; $?=255; rec=failed; suspend_notice=false | child_answers_after_fg=false; rc_after_exit=null; $?=255; rec=failed; suspend_notice=false | = | = | = | child_answers_after_fg=false; rc_after_exit=null; rec=failed | = | = | child_answers_after_fg=false; rc_after_exit=null; rec=failed |
| P10 | jobs=[stopped[suspended (tty input)], stopped[suspended (tty input)], stopped[suspended (tty input)]]; child_after_bg=[T, T, T]; consistent=true; child_after_fg=[R, R, R]; echoed=true; rc=0 | = | = | = | = | = | = | = | = | child_after_fg=[R, R, R] or [T, R, R] ~ |
| P11 | arm_notice=true; child_after_arm_fg=R; cycle_notices=[true, true, true]; running_after_each_fg=true; finished=true; rc=0 | = | = | = | = | = | = | = | = | = |
| P12-S3 | $?=146; child_after_1s=T; consistent=true; jobs=stopped[suspended (tty input)]; rec=fg; rc=6; out_ok=true | = | = | = | = | = | consistent=false; jobs=running | = | = | = |
| P14 | notice=true; other_job_left_stopped=true | = | = | = | = | = | = | other_job_left_stopped=false | = | = |

### linux-bash

| scenario | plain | base-go | base-go-pinned | T1-go-opus1 | T1-go-opus2 | T1-go-sonnet1 | base-rust | T1-rust-opus1 | T1-rust-opus2 | T1-rust-sonnet1 |
|---|---|---|---|---|---|---|---|---|---|---|
| P0-STOP | rc=7; completed=true; child_reaped=true | = | = | = | = | = | child_reaped=false; rc=hung | = | = | = |
| P0-TSTP | rc=7; completed=true; child_reaped=true | = | = | = | = | = | child_reaped=false; rc=hung | = | = | = |
| P1-STOP | jobs=stopped[Stopped (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[Stopped] | jobs=stopped[Stopped] | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg |
| P1-TSTP | jobs=stopped[Stopped]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg | consistent=false; jobs=running; rec=ctrlz+fg |
| P1k-TSTP | jobs=stopped[Stopped]; child=T; consistent=true; rec=fg; rc=0; completed=true; child_after_kill-CONT_%1=S | = | = | consistent=false; jobs=running | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | consistent=false; jobs=running | consistent=false; jobs=running | consistent=false; jobs=running |
| P2-STOP | jobs=stopped[Stopped (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[Stopped] | jobs=stopped[Stopped] | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running; rec=ctrlz+fg |
| P2-TSTP | jobs=stopped[Stopped]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running; rec=ctrlz+fg |
| P2k-TSTP | jobs=stopped[Stopped]; child=T; consistent=true; rec=fg; rc=0; completed=true; child_after_kill-CONT_%1=S | = | = | = | child_after_kill-CONT_%1=T; completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | consistent=false; jobs=running |
| P2n-TTIN | jobs=stopped[Stopped (tty input)]; child=T; consistent=true; rec=fg; rc=4; out_ok=true; completed=true | = | = | = | = | = | = | = | = | = |
| P3-STOP | rc=7; rec=none-needed; inner_rc=7; completed=true | = | = | = | = | = | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | = |
| P3-TSTP | rc=7; rec=none-needed; inner_rc=7; completed=true | = | = | = | = | = | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | rc=hung; rec=ctrlz+fg | = |
| P4-STOP | prompt=true; notice=Stopped; $?=147; jobs=stopped[Stopped (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[Stopped]; $?=148 | jobs=stopped[Stopped]; $?=148 | = | = | = | = | = | = | = |
| P4-TSTP | prompt=true; notice=Stopped; $?=148; jobs=stopped[Stopped]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P4t-STOP | prompt=true; notice=Stopped; $?=147; jobs=stopped[Stopped (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[Stopped]; $?=148 | jobs=stopped[Stopped]; $?=148 | = | = | = | = | = | = | = |
| P4t-TSTP | prompt=true; notice=Stopped; $?=148; jobs=stopped[Stopped]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P5-STOP | jobs=stopped[Stopped (signal)]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[Stopped] | jobs=stopped[Stopped] | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | = |
| P5-TSTP | jobs=stopped[Stopped]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | completed=false; consistent=false; jobs=running; rc=null; rec=failed | = | = | = | = | = |
| P6-STOP | rc=7; completed=true | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung |
| P6-TSTP | rc=7; completed=true | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung | rc=hung |
| P7-TTIN | prompt=true; notice=Stopped; $?=149; jobs=stopped[Stopped (tty input)]; child=T; consistent=true; rec=fg; rc=0; completed=true | = | = | = | = | = | = | = | = | = |
| P7-TTOU | prompt=true; notice=Stopped; $?=150; jobs=stopped[Stopped (tty output)]; child=T; consistent=true; rec=fg; rc=0; completed=true | jobs=stopped[Stopped]; $?=148 | jobs=stopped[Stopped]; $?=148 | jobs=stopped[Stopped]; $?=148 | jobs=stopped[Stopped]; $?=148 | jobs=stopped[Stopped]; $?=148 | = | = | = | = |
| P7n-TTOU | jobs=stopped[Stopped (tty output)]; child=T; completed_in_bg=false; consistent=true; rec=fg; rc=3 | jobs=stopped[Stopped] | jobs=stopped[Stopped] | jobs=stopped[Stopped] | jobs=stopped[Stopped] | jobs=stopped[Stopped] | = | = | = | = |
| P8 | child_1s=S; jobs_1s=running; completed_by_5s=true; jobs_5s=done[Done]; rec=none-needed | = | = | = | = | = | child_1s=T; completed_by_5s=false; jobs_1s=stopped[Stopped]; jobs_5s=stopped[Stopped]; rec=fg | child_1s=T; completed_by_5s=false; jobs_1s=stopped[Stopped]; jobs_5s=stopped[Stopped]; rec=fg | child_1s=T; completed_by_5s=false; jobs_1s=stopped[Stopped]; jobs_5s=stopped[Stopped]; rec=fg | child_1s=T; completed_by_5s=false; jobs_1s=stopped[Stopped]; jobs_5s=stopped[Stopped]; rec=fg |
| P9 | suspend_notice=true; who_after_bg=nested; jobs_after_bg=null; who_after_fg=null; rc_after_exit=outer-gone; outer_shell_alive_at_end=false | = | = | = | = | = | jobs_after_bg=running; outer_shell_alive_at_end=true; rc_after_exit=null; who_after_bg=outer | = | = | = |
| P9e-bg | suspend_notice=true; $?=147; jobs_after_bg=stopped[Stopped (tty input)]; child_after_bg=T; child_answers_after_fg=true; rc_after_exit=3; rec=none-needed | $?=148 | $?=148 | = | = | = | child_answers_after_fg=false; jobs_after_bg=running; rc_after_exit=null; rec=failed | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc |
| P9e0 | suspend_notice=true; $?=147; jobs_after_bg=null; child_after_bg=null; child_answers_after_fg=true; rc_after_exit=3; rec=none-needed | $?=148 | $?=148 | = | = | = | child_answers_after_fg=false; rc_after_exit=null; rec=failed | = | = | child_answers_after_fg=false; rc_after_exit=null; rec=ctrlc |
| P10 | jobs=[stopped[Stopped (tty input)], stopped[Stopped (tty input)], stopped[Stopped (tty input)]]; child_after_bg=[T, T, T]; consistent=true; child_after_fg=[S, S, S]; echoed=true; rc=0 | = | = | = | = | = | = | = | = | = |
| P11 | arm_notice=true; child_after_arm_fg=S; cycle_notices=[true, true, true]; running_after_each_fg=true; finished=true; rc=0 | = | = | = | = | = | child_after_arm_fg=T | = | = | = |
| P12-S3 | $?=148; child_after_1s=T; consistent=true; jobs=stopped[Stopped (tty input)]; rec=fg; rc=6; out_ok=true | = | = | = | = | = | consistent=false; jobs=running; rec=ctrlz+fg | = | = | = |
| P13-STOP | completed=true; all_gone=true; launcher_rc=7 | = | = | = | = | = | all_gone=false; launcher_rc=null | = | = | = |
| P13-TSTP | completed=true; all_gone=true; launcher_rc=7 | = | = | = | = | = | = | = | = | = |
| P14 | notice=true; other_job_left_stopped=true | = | = | = | = | = | = | other_job_left_stopped=false | = | = |

## Appendix B: race, recovery, P9e follow-up and S3 window tables (generated by scripts/summarize_extra.py)

### Repeated race runs (P10r, P11r; 10 reps per build and platform, bash)

Cell: runs with at least one re-stop right after `fg` / runs; total re-stops; whether a second `fg` recovered every re-stop.

| build | darwin P10r | darwin P11r | linux P10r | linux P11r |
|---|---|---|---|---|
| plain | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| base-go | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| base-go-pinned | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-go-opus1 | 0/10; 0; yes | 0/10; 0; yes | 2/10; 2; yes | 0/10; 0; yes |
| T1-go-opus2 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-go-sonnet1 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| base-rust | 1/10; 2; yes | 0/10; 0; yes | 0/10; 0; yes | 10/10; 10; NO |
| T1-rust-opus1 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-rust-opus2 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-rust-sonnet1 | 1/10; 1; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |

### Escalating recovery (P1x: background job, stdio redirected; P2x: stdio on the terminal; third-party SIGTSTP of the child; 2 reps, bash)

Cell: `jobs` state after the stop; what gave the prompt back after `fg` (`fg` = the job finished; otherwise the first of ^C, ^Z, ^\ that did; `none` = nothing did).

| build | darwin P1x | darwin P2x | linux P1x | linux P2x |
|---|---|---|---|---|
| plain | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| base-go | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| base-go-pinned | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| T1-go-opus1 | running -> ctrl-backslash | stopped[Suspended: 18] -> fg | running -> none | stopped[Stopped] -> fg |
| T1-go-opus2 | running -> ctrl-backslash | running -> ctrl-backslash | running -> none | running -> none |
| T1-go-sonnet1 | running -> ctrl-backslash | stopped[Suspended: 18] -> fg | running -> none | stopped[Stopped] -> fg |
| base-rust | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| T1-rust-opus1 | running -> ctrl-z | stopped[Suspended: 18] -> fg | running -> ctrl-z | stopped[Stopped] -> fg |
| T1-rust-opus2 | running -> ctrl-z | stopped[Suspended: 18] -> fg | running -> ctrl-z | stopped[Stopped] -> fg |
| T1-rust-sonnet1 | running -> ctrl-z | running -> ctrl-z | running -> ctrl-z | running -> ctrl-z |

### P9e follow-up: repeated `fg` (P9e0-fg3: suspend, fg; P9e-bg-fg3: suspend, bg, fg; 2 reps)

Cell: after which `fg` the job-control child answered (0 = not after three) and where the typed `xq-ping` lines went (child / shell = ran as a command in the outer shell / nowhere = no answer).

| build | darwin-bash P9e0-fg3 | darwin-bash P9e-bg-fg3 | darwin-zsh P9e0-fg3 | darwin-zsh P9e-bg-fg3 | linux-bash P9e0-fg3 | linux-bash P9e-bg-fg3 |
|---|---|---|---|---|---|---|
| plain | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| base-go | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 1; child | 1; child |
| T1-go-opus1 | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| T1-go-opus2 | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| T1-go-sonnet1 | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| base-rust | 0; nowhere | 0; nowhere | 0; nowhere | 0; nowhere | 0; nowhere | 0; nowhere |
| T1-rust-opus1 | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell |
| T1-rust-opus2 | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell |
| T1-rust-sonnet1 | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell |

### S3 resume window (P12-S3)

Milliseconds, sampled every few microseconds for 1 s after the third party's SIGCONT to the launcher, during which the launcher was not stopped while the child still was (per rep). Plain exec has no launcher; `jobs` 1 s later is in the matrix.

| build | darwin-bash | linux-bash | darwin-zsh |
|---|---|---|---|
| base-go | 0.3, 0.3 | 3.3, 0.1 | 0.2, 0.2 |
| base-go-pinned | 0.3, 0.1 | 0.2, 0.6 | 0.6, 0.6 |
| T1-go-opus1 | 0.5, 0.4 | 0.9, 0.5 | 0.3, 0.6 |
| T1-go-opus2 | 0.1, 0.2 | 0.1, 1.2 | 0.3, 0.1 |
| T1-go-sonnet1 | 0.3, 0.1 | 0.1, 0.1 | 0.4, 0.3 |
| base-rust | 999.9, 999.8 | 999.9, 999.9 | 999.8, 999.9 |
| T1-rust-opus1 | 10.0, 10.4 | 11.2, 10.7 | 10.4, 10.2 |
| T1-rust-opus2 | 0.1, 0.1 | 0.9, 0.1 | 0.1, 0.1 |
| T1-rust-sonnet1 | 32.2, 31.5 | 31.3, 31.3 | 30.1, 30.3 |
