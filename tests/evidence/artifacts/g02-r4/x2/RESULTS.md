# G02 round 4, X2: which codebase do agents change more reliably? (Go vs Rust)

**Task:** M00-T05-r4-x2 (`docs/g02/round4-plan.md`, row X2). **Status:** `verified` for the cell
results (§4: every number comes from an evaluator's or reviewer's structured result, or from the
implementer transcripts, as listed in `results.json`) and for the two calibrated major families (§5:
each reproduced independently). The remaining calibrated minor and pre-existing ratings are
`implemented_unverified`. **Dates:** 2026-10-06 to 2026-10-10.
**Feeds:** ADR-0002 §7, the row "agentic and
open-source maintainability (15 %)"; secondarily "security-sensitive core (25 %)".

## 1. What was run

- **Cells:** 4 tasks × 2 languages × 3 runs = 24 cells. Runs `opus1` and `opus2` used Opus 5.5
  (`claude-opus-5-5`), run `sonnet1` used Sonnet 5.5 (`claude-sonnet-5-5`), all at effort `high`.
  Both languages got the same prompt text, the same task spec, the same model and the same effort per
  run (the implementer prompt is in the workflow scripts, copied to `workflow-scripts/`; see §3 item 3
  for the one sentence that differs between attempts).
- **Starting code:** the post-X1b prototypes, Go `84c7665` and Rust `001a791` (`hidden-pack/BASE.json`).
  T4 starts from a seeded tree with one planted bug per language (`hidden-pack/seed/`).
- **Tasks** (`specs/`):

  | Task | Kind | Hidden checks |
  |---|---|---|
  | T1 | behaviour change: exec-equivalent job control for `run` (the ADR-0002 §6.1 parity failures) | 14 (spec S1–S5), each scenario also run under plain exec as a control |
  | T2 | new CLI subcommand `profile lint` | 12 |
  | T3 | TUI feature: match underline, `?` help overlay, selection kept across filter edits | 17 |
  | T4 | diagnose and fix a user-reported bug (a symlinked `--file` is refused) | 6 |

- **Isolation.** Each implementer got its own workspace built by `hidden-pack/make-workspace.sh`: the
  repository layout reduced to one prototype (digest-checked against `BASE.json`), the contract, the
  schemas, the shared harness 2.4.2 with a fresh venv, and the fixtures. No `.git`, no other prototype,
  no evidence tree, no hidden tests. Implementers were told to work only in their workspace.
- **Per cell, after the implementer:** an evaluator (Sonnet 5.5, effort high) followed the hidden
  pack's evaluator protocol: digest checks, the hidden tests on darwin-arm64 and linux-arm64 (Docker)
  with per-platform binaries, `score.py` against the unmodified baseline (fixed/regressed), the full
  2.4.2 harness on both platforms, the unit tests and an all-target build. A code reviewer (Opus 5.5,
  effort high) who did not write the change then reviewed the diff against the spec with one rubric
  for both languages and scored spec conformance, test quality and clarity from 1 to 5.
- **Transcript audit.** `hidden-pack/audit-transcript.py` (conservative: it flags every call that could
  reach outside the workspace) ran on every implementer transcript; every flagged call was then read
  (`audit/TRIAGE.md`, `audit/x2-triage.txt`).

## 2. Fairness reviews of the task pack (before any implementer ran)

- `taskpack-review/`: the first neutrality review found 3 majors: baseline drift (the pack was built
  on the frozen pre-X1b trees), implementer isolation (a `diff -r` against the unseeded tree would
  reveal the T4 seed; the hidden dir was readable), and T1 scoring. Fixed in fix round 1.
- `taskpack-recheck/`: the recheck found one new major: the transcript audit missed relative paths,
  `cd`, globs and commands run from the repository root. The run stopped before any implementation.
- `taskpack-recheck2/`: after fix round 2 (audit rewrite), minors only.
- Residual neutrality risks, as the pack records them (`hidden-pack/README.md`, last section):
  - **T1:** the baselines fail for different root causes (Go: darwin SIGSTOP decoding and the
    reported signal; Rust: no CONT forwarding, mirroring with no tty). The work differs by language
    although the target is the same, and the darwin baselines fail different numbers of checks
    (Go 8, Rust 6). Scored by fixed/regressed/all-pass, not raw counts. Neither baseline passes the
    darwin nested-shell checks (S4), so those are `unproven` (feasibility shown only by the pack's
    Python positive control).
  - **T2:** `T2.ascii_fold_only` fails the idiomatic Go case-folding call; it counts for both
    languages because the spec states the rule.
  - **T3:** Bubble Tea v2 re-parses inline SGR, so the Go change must embed SGR in row strings, while
    Ratatui styles `Span`s. The tests accept any standard underline encoding.
  - **T4:** the Go seed changes one identifier (`Stat` to `Lstat`); the Rust seed adds a pre-check
    block. The symptom bytes are identical in both.
  - **Isolation:** same OS user, so isolation is by content plus the transcript audit, not by
    permissions.

## 3. Incidents and how they were handled

1. **Rate limits.** The second attempt (`wf_21d21205-c96`, 2026-10-06) lost 58 of 68 agents to API
   429s. Its 6 completed implementations (T2, T3, T4 × go, rust, opus1) were kept and evaluated in
   the third attempt; each started in a fresh workspace.
2. **Contaminated continuation (excluded).** The orchestrator gave the T1 opus1 workspaces of the
   killed second-attempt implementers (47 Go and 31 Rust tool calls of uncommitted work) to the third
   attempt (`wf_0c100051-5bd`) without resetting them. Both results measure two implementers' work,
   so they are kept in `runs-excluded/` (`NOTE.md`) and not scored. Both cells were rerun in fresh
   workspaces: T1-go-opus1 by `wf_9661f31f-f4b` (x2d), T1-rust-opus1 by `wf_749c87d4-6a5` after a host
   reboot killed its x2d attempt along with its `/tmp` workspace (that attempt never reached an
   evaluation; its manifest is `hidden-pack/workspaces/T1-rust-opus1.attempt-x2d-reboot.json`).
3. **Report files.** In the second attempt the Write tool refused `out/REPORT.md` for implementers; the
   orchestrator wrote those files from the implementers' structured reports. The x2c/x2d prompt adds
   one sentence telling implementers to write report files with the shell; otherwise the implementer
   prompts of x2b, x2c and x2d are identical (checked with `diff`). The six x2b cells (T2–T4 opus1)
   ran without that sentence in both languages, so every Go/Rust pair still had the same prompt.
4. **Wall time is not comparable.** Runs were spread over four days, shared the host with other
   work, and waited on rate limits. It is reported in `results.json` but not used.

## 4. Results

### 4.1 Correctness: no difference

| | Go (12 cells) | Rust (12 cells) |
|---|---|---|
| Built for all targets | 12 | 12 |
| All hidden checks pass, darwin-arm64 and linux-arm64 | 12 | 12 |
| `score.py` against the baseline | every cell all-pass, 0 regressed | every cell all-pass, 0 regressed |
| Full harness 2.4.2 as the task expects (139/139; T3 136/139, the 3 K9 checks its spec replaces) | 12 | 12 |
| Unit tests exit 0 | 12 | 12 |

T1 fixed every baseline-failing check in every cell: Go 8/8 on darwin and 6/6 on Linux, Rust 6/6 on
both (the baselines fail different checks; §2). Neither baseline passes the darwin nested-shell checks,
so the darwin pass of those two checks rests on the pack's positive control (`unproven_checks`). T3
fixed 14/14 in every cell, T4 5/5. Every hidden run passed on its first attempt, so the protocol's
reruns of failing checks never triggered. Two evaluators added repeats anyway (T1-rust-sonnet1: two
more runs per platform; T4-rust-sonnet1: one more), all passing. Most cells therefore have one hidden
run per platform, which says little about flakiness.

**Ceiling effect.** Every cell passed every hidden check, so the hidden tests did not separate the
languages at this model tier. The comparison therefore rests on the code reviews and on effort.

### 4.2 Code review

| | Go | Rust |
|---|---|---|
| Blocker / major / minor defects (as the cell reviewers rated them) | 0 / 1 / 46 | 0 / 1 / 47 |
| Mean spec conformance / test quality / clarity (1–5) | 4.92 / 4.08 / 4.33 | 4.83 / 4.25 / 4.33 |
| Lines added / removed, all 12 cells | +7,610 / −339 | +8,272 / −328 |

Both majors are in T1, in the same area: the rule each change adds for deciding whether a job-control
shell is watching, and therefore whether to mirror a child's stop.

- **T1-go-opus1:** the rule also matches a background job of an interactive shell whose stdio is
  fully redirected. A third-party stop of the child is then not mirrored, so `jobs` shows the job as
  Running while the child is stopped. The reviewer probed it (`runs/T1-go-opus1/review/`): SIGTSTP
  regresses against the baseline; SIGSTOP fixes a baseline exit 255 but lands in the same Running
  state.
- **T1-rust-sonnet1:** a K6e regression: a background job (`cmd &`) of an interactive job-control
  shell that was never in the foreground no longer gets the child's stop mirrored, so the child stays
  stopped while `jobs` shows Running.

The reviewers of other T1 cells described related limits as minor or as disclosed gaps (for example
T1-rust-opus1's implementer lists the redirected-background case among its known limitations, and its
reviewer did not rate it). Because each cell had its own reviewer, §5 measures these scenarios on all
six T1 builds with one probe set and one rubric.

### 4.3 Effort (from the implementer transcripts)

Output tokens and tool calls per cell (input tokens, including cache reads, are in the table at the end).

| Task / run | Go out tokens | Rust out tokens | Go/Rust | Go calls | Rust calls | Go/Rust |
|---|---:|---:|---:|---:|---:|---:|
| T1 opus1 | 137,283 | 116,063 | 1.18 | 78 | 73 | 1.07 |
| T1 opus2 | 116,683 | 109,394 | 1.07 | 84 | 94 | 0.89 |
| T1 sonnet1 | 145,167 | 77,024 | 1.88 | 126 | 49 | 2.57 |
| T2 opus1 | 43,795 | 38,163 | 1.15 | 40 | 37 | 1.08 |
| T2 opus2 | 33,647 | 56,850 | 0.59 | 32 | 60 | 0.53 |
| T2 sonnet1 | 19,059 | 29,642 | 0.64 | 23 | 23 | 1.00 |
| T3 opus1 | 69,498 | 58,560 | 1.19 | 78 | 54 | 1.44 |
| T3 opus2 | 94,760 | 58,289 | 1.63 | 87 | 61 | 1.43 |
| T3 sonnet1 | 31,677 | 36,484 | 0.87 | 42 | 53 | 0.79 |
| T4 opus1 | 38,661 | 38,713 | 1.00 | 45 | 56 | 0.80 |
| T4 opus2 | 24,452 | 32,761 | 0.75 | 29 | 53 | 0.55 |
| T4 sonnet1 | 15,901 | 16,677 | 0.95 | 18 | 22 | 0.82 |
| **All 12 pairs** | 770,583 | 668,620 | geometric mean **1.02** | 682 | 635 | geometric mean **0.98** |

Go used fewer output tokens in 6 of the 12 pairs and fewer tool calls in 6 of 12. Per task, Go took
more effort on T1 and T3 and Rust on T2 and T4. The per-pair ratios range from 0.53 to 2.57, so with
three runs per cell the spread within a language is as large as the difference between them.
Usage counts each streamed assistant message once (largest usage seen per message id), the method of
`audit/metrics.py`.

## 5. Calibrated review severities

Per-cell reviewers were inconsistent (T1 showed it first), so every task got a second review across
all six cells with one rubric, identical for both languages, backed by probes on rebuilt binaries.

### 5.1 T1: one probe set and rubric on all six job-control changes

Status: P1, the scenario behind every major below, is `verified` by an independent re-run with its
own probe, its own builds (same digests) and a different model (`t1-calibration/verify/`); the other
scenarios are `implemented_unverified`. Details: `t1-calibration/README.md`.

**Method.** One agent rebuilt all six T1 changes and both baselines from the pinned bases plus each
cell's diff (digests equal to the evaluated artifacts for five cells; T1-go-opus2 differs only by Go
toolchain patch version, with identical sources). It probed 20 job-control scenarios, covering every
behaviour any T1 reviewer described, on every build and on plain exec: darwin bash and zsh and
linux-arm64 bash, 2 repetitions, plus 10-repetition race probes (2,388 runs; the plain-exec control
never disagreed with itself). Then it classified every (cell, defect) with one rubric, identical for
both languages:
- **major:** diverges from plain exec in a scenario plausible for an interactive user, leaves a
  process stopped or hung or the job state wrong with no normal recovery, and is new relative to the
  same language's baseline (or is required by S1–S5).
- **minor:** an unusual setup, cosmetic, or a normal recovery exists (`fg`, `bg`, ^Z then `fg`).
- **pre-existing:** the baseline diverges the same way and S1–S5 do not require the fix.

A separate reviewer agent classified the same evidence without seeing the result and reached the same
majors.

**Result.**

| cell | reviewer's rating (blocker/major/minor) | calibrated (blocker/major/minor/pre-existing) |
|---|---|---|
| T1-go-opus1 | 0/1/4 | 0/1/4/2 |
| T1-go-opus2 | 0/0/4 | 0/1/2/2 |
| T1-go-sonnet1 | 0/0/6 | 0/1/6/2 |
| T1-rust-opus1 | 0/0/4 | 0/0/4/4 |
| T1-rust-opus2 | 0/0/4 | 0/0/4/4 |
| T1-rust-sonnet1 | 0/1/6 | 0/0/5/5 |

- **The same regression in all six cells.** In P1 (a background job of an interactive shell with
  stdio redirected; another process stops the job's child) every changed build lets the shell list
  the job as Running while the child is stopped. Both baselines behave like plain exec there. Each
  change added a rule for "is a job-control shell watching?", and every rule misses this case.
- **What separates the languages is recovery.** In the three Go cells `fg` then hangs and ^Z does
  nothing. On darwin ^C ends the job (exit 130: the program is killed, where plain exec's `fg` would
  let it finish); on Linux ^C and ^\ do nothing until another terminal continues the child. In two Go
  cells even `kill -CONT %1` cannot reach the child, which runs in its own process group. In the three
  Rust cells `fg` hangs too, but ^Z then `fg` finishes the job with status 0. Ending the job is not a
  normal recovery under the rubric, hence 3 Go majors and no Rust major. T1-go-opus2 also fails this
  way for background jobs with terminal stdio and after ^Z + `bg`. (The calibration's own darwin runs
  had inherited SIGINT ignored and recorded "^C does nothing"; the independent re-run corrected that,
  and the calibration README carries the correction.)
- **Why, per the independent re-run (mechanism, with file and line in `verify/README.md`).** The
  Running state comes from a design all six implementers chose to meet S1 (a "terminal is watching"
  gate); neither language forces it. The Go recovery failure comes from the Go *baseline's* model:
  the child runs in its own process group and is handed the terminal, which the baseline adopted
  because `os/signal` exposes no `siginfo` without cgo (it cannot tell a terminal SIGINT from a
  PID-directed one, so it isolates the child). Within that model the failure was avoidable with the
  standard library (continue a stopped child after `fg`, handle SIGCONT while running as go-opus1
  partly does, or not hand the terminal to a stopped child). The Rust recovery comes from the Rust
  *baseline's* shared-group model, which it could afford because `signal-hook`/`libc` give it
  `si_code` as an ordinary dependency; none of the Rust cells' T1 code is exercised by that
  recovery. So the difference is an architecture effect that each language's signal API shaped, not
  something the T1 implementers did better in Rust.
- **What the Rust cells keep from their baseline.** The Rust baseline diverges in more scenarios than
  the Go baseline, and the Rust changes left those as they were (not required by S1–S5): a
  non-job-control parent with terminal stdio hangs until ^Z + `fg` (P3; fixed only by rust-sonnet1),
  ^Z then SIGCONT to the launcher only leaves the child stopped (P8), and a nested job-control child
  does not get the terminal back after `bg` + `fg` (P9e). All have a normal recovery or need an unusual
  setup. rust-opus1 also continues another job's stopped process group in one constructed case (P14,
  minor). Every Go build reports a SIGTTOU stop as SIGTSTP (pre-existing, cosmetic). Every build,
  baselines included, hangs when a non-shell parent hands the job the terminal (P6).
- **Sensitivity.** The 3-to-0 split rests on two rubric readings: that a third-party stop of a
  background job's process is plausible for an interactive user (T1's own S1 is a third-party stop),
  and that `kill -CONT %1` is not a normal recovery. If third-party stops of background jobs are judged
  implausible, the Go majors become minor and the languages tie; if a wrong job state counts as major
  whatever the recovery, all six cells get a major.

### 5.2 T2, T3, T4: cross-cell reviews

Each task's six diffs were reviewed side by side by one agent that rebuilt every cell and the
baselines (sources equal to the evaluated trees; binaries byte-identical except where the host's Go
moved from 1.27.1 to 1.27.2), probed edge cases the hidden tests do not cover, and rated every defect,
including every defect any cell reviewer listed, with one rubric: **blocker** (security boundary,
secret disclosure, data loss), **major** (violates an explicit spec or contract requirement, or
crashes, hangs, corrupts the screen or gives wrong results on plausible input, and the hidden tests
miss it), **minor** (unusual input, cosmetic, test or code quality, or left open by the spec),
**pre-existing** (in the baseline, not asked to change). Probes ran on darwin-arm64.

| task | Go blocker/major/minor/pre-existing (3 cells) | Rust blocker/major/minor/pre-existing (3 cells) | record |
|---|---|---|---|
| T2 `profile lint` | 0 / 0 / 9 / 2 | 0 / 0 / 12 / 0 | `cross-review/T2/` |
| T3 TUI feature | 0 / **2** / 26 / 8 | 0 / 0 / 20 / 3 | `cross-review/T3/` (major verified in tmux and xterm.js: `T3/verify/`) |
| T4 seeded bug | 0 / 0 / 8 / 9 | 0 / 0 / 8 / 4 | `cross-review/T4/` |

- **T2:** no blocker or major. All six agree with a reference model on 400 random profiles and on
  every argument, exit-code, non-echo and no-write probe; one Go cell treats `profile lint --file
  --json` differently from `profile show` (minor). Not a defect but worth knowing: on the worst-case
  1 MiB profile two Rust cells peak at 190–205 MiB of the 256 MiB K15 limit; the other four stay at or
  below 124 MiB.
- **T3:** **go-opus1 and go-sonnet1 corrupt list rows and the status line** when a filter edit
  restyles cells next to double-width characters: on the shipped `homelab.toml` at 20x5, `/東京`
  shows `> vps- 京`; on a CJK profile a corrupted row appears at every width from 80 down to 20. Both
  embed the underline in the row text, as Bubble Tea v2 requires (§2), and that triggers a cursor bug
  in Bubble Tea's renderer that writes one column short; the Go baseline already loses a CJK filter
  character in the status line the same way (pre-existing). go-opus2 avoided it by forcing a full
  repaint while wide text is on screen. The baselines, go-opus2 and the three Rust cells render the
  same keys correctly, and the hidden tests miss it. Minors with behaviour: no underline at all when
  `TERM` is `dumb` or unset (all three Go cells); no underline for the Greek final sigma `ς`
  (rust-sonnet1). Pre-existing: Go drops combining and zero-width characters and exits 1 on
  `kill -INT`; Rust passes bidi and zero-width characters to the terminal.
- **T4:** no blocker or major. On 57 probe cases per build (link chains, loops, dangling links, links
  to FIFOs, sockets, devices and directories, permission errors, `tui --file`) every fix behaves like
  its unseeded base, all refusals within 0.013 s; a forced check-then-open race shows every fix
  refuses a swapped-in FIFO. With the seeded bug put back, every cell's own tests fail. Minor: the
  three Rust cells' tests no longer cover the check on the opened file. Pack gap: a mutant fix without
  that check still passes hidden T4 (`SEED.md` says it would not).

### 5.3 Calibrated totals

| | Go (12 cells) | Rust (12 cells) |
|---|---|---|
| Cells with a calibrated major | **5** (T1 × 3, T3 × 2) | **0** |
| Cells with a major as the cell reviewers rated them | 1 | 1 |
| Blockers | 0 | 0 |

Both Go major families trace to the Go stack rather than to one implementer: T1's to the Go
baseline's separate-process-group design, which `os/signal`'s missing `siginfo` motivated; T3's to
Bubble Tea v2's inline-SGR model and a renderer bug next to wide characters. The hidden tests missed
all five; the cell reviewers rated one of them major, two minor, and did not list the other two. If
the cells were independent, 5 of 12 against 0 of 12 would be unlikely by chance (one-sided Fisher
exact p ≈ 0.02), but they are not: the five majors come from two causes, and the T1 split depends on
the rubric reading in §5.1.

## 6. Reading for ADR-0002 (inference, for the re-score)

- **What the hidden tests measured: no difference.** All 24 cells pass every hidden check with no
  harness regression; effort is within 2 % in aggregate (geometric-mean Go/Rust ratios 1.02 for output
  tokens and 0.98 for tool calls), and each language was cheaper in half the pairs.
- **What calibrated review found: a difference in the defects agents leave behind.** 5 of 12 Go
  cells against 0 of 12 Rust cells carry a major the hidden tests miss (§5.3). Both causes sit in the
  Go stack (the signal model `os/signal` pushes toward, and Bubble Tea v2's renderer) rather than in
  the agents' skill: the T1 implementers did not do better in Rust, they inherited a more forgiving
  design; T3's Rust cells never had to embed escape codes in text. For an agent-maintained product,
  stack pitfalls that agents and reviewers do not notice are exactly the maintainability cost the row
  is meant to capture.
- **How strong:** two independent causes, three runs per cell, one task each. T1 depends on a rubric
  reading (§5.1); T3 is verified in three terminal implementations (pyte, tmux, xterm.js) and is a
  property of the bytes Bubble Tea writes. This is a real but modest signal for Rust (Ratatui) over Go
  (Bubble Tea) on the agentic-maintainability row, not a large one, and it says as much about the TUI
  library and the signal design as about the language.
- **X6** (desk research) found at most a slight, confounded lean either way, and suggested X2 decide
  the direction.
- **Ceiling:** harder tasks, weaker models or long-lived maintenance may separate the languages
  further or differently; X2 could not measure that.

## 7. Limitations

- **Sample size.** Three runs per task and language (two models). Differences smaller than the
  run-to-run spread (§4.3) cannot be detected.
- **Ceiling.** Every cell passed every hidden check (§4.1).
- **Reviewer variance.** Each cell had its own reviewer, and those ratings proved uneven: the
  cross-cell reviews (§5) moved ratings in every task and found two majors and one regression the cell
  reviewers missed. The calibrated ratings come from one reviewer per task, so they are consistent
  within a task but not independently re-rated, except the two major families (re-run independently).
- **Probe platforms.** The T2–T4 cross-reviews probed darwin-arm64 only; T1 calibration also ran
  linux-arm64. Windows was not probed for X2.
- **Different T1 starting points.** The two baselines fail T1 for different reasons (§2).
- **Same-user isolation.** Isolation relied on content and the transcript audit, not OS permissions.
  The audit found no access to hidden material, other workspaces or the repository in any scored cell.
- **One host.** All runs used one darwin-arm64 host plus its Docker linux-arm64 VM.
- **Rate limits and incidents** (§3): the excluded continuation cells and the reruns.

## 8. Files

- `results.json`: per cell, the implementer report, evaluation, review and usage (built by
  `audit/aggregate.py` from the workflow journals; home paths scrubbed).
- `runs/<cell>/`: the implementer's outputs, the evaluator's results and the reviewer's probes as each
  evaluator laid them out.
- `runs-excluded/`: the two contaminated continuation cells (`NOTE.md`).
- `specs/`, `hidden-pack/`, `taskpack-review/`, `taskpack-recheck/`, `taskpack-recheck2/`: the task
  pack and its fairness reviews.
- `audit/`: transcript audits and triage. `workflow-scripts/`: the scripts that ran the cells.
- `t1-calibration/` (with `verify/`): §5.1. `cross-review/T2|T3|T4/` (T3 with `verify/`): §5.2.

### All cells

Usage and the cell reviewers' own ratings (the calibrated ratings are in §5). The majors listed
under the table are the cell reviewers' two majors.

| cell | model | built | hidden darwin | hidden linux | harness darwin | harness linux | unit | diff +/- | blocker/major/minor | conf/tests/clarity | tool calls | out tokens | in tokens (incl. cache) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T1-go-opus1 | claude-opus-5-5 | True | 14/14 | 14/14 | 139/139 | 139/139 | 0 | +933/-101 | 0/1/4 | 4/4/4 | 78 | 137283 | 20122126 |
| T1-go-opus2 | claude-opus-5-5 | True | 14/14 | 14/14 | 139/139 | 139/139 | 0 | +1004/-34 | 0/0/4 | 5/4/4 | 84 | 116683 | 20195082 |
| T1-go-sonnet1 | claude-sonnet-5-5 | True | 14/14 | 14/14 | 139/139 | 139/139 | 0 | +680/-13 | 0/0/6 | 5/4/4 | 126 | 145167 | 32519615 |
| T1-rust-opus1 | claude-opus-5-5 | True | 14/14 | 14/14 | 139/139 | 139/139 | 0 | +826/-44 | 0/0/4 | 4/5/4 | 73 | 116063 | 17480962 |
| T1-rust-opus2 | claude-opus-5-5 | True | 14/14 | 14/14 | 139/139 | 139/139 | 0 | +723/-42 | 0/0/4 | 5/4/4 | 94 | 109394 | 22736616 |
| T1-rust-sonnet1 | claude-sonnet-5-5 | True | 14/14 | 14/14 | 139/139 | 139/139 | 0 | +470/-16 | 0/1/6 | 4/3/4 | 49 | 77024 | 9821734 |
| T2-go-opus1 | claude-opus-5-5 | True | 12/12 | 12/12 | 139/139 | 139/139 | 0 | +915/-2 | 0/0/3 | 5/4/4 | 40 | 43795 | 6206954 |
| T2-go-opus2 | claude-opus-5-5 | True | 12/12 | 12/12 | 139/139 | 139/139 | 0 | +769/-12 | 0/0/2 | 5/5/5 | 32 | 33647 | 4785363 |
| T2-go-sonnet1 | claude-sonnet-5-5 | True | 12/12 | 12/12 | 139/139 | 139/139 | 0 | +514/-10 | 0/0/4 | 5/4/4 | 23 | 19059 | 2860040 |
| T2-rust-opus1 | claude-opus-5-5 | True | 12/12 | 12/12 | 139/139 | 139/139 | 0 | +1031/-3 | 0/0/4 | 5/4/5 | 37 | 38163 | 6341636 |
| T2-rust-opus2 | claude-opus-5-5 | True | 12/12 | 12/12 | 139/139 | 139/139 | 0 | +1269/-3 | 0/0/3 | 5/5/4 | 60 | 56850 | 11500403 |
| T2-rust-sonnet1 | claude-sonnet-5-5 | True | 12/12 | 12/12 | 139/139 | 139/139 | 0 | +969/-3 | 0/0/4 | 5/4/5 | 23 | 29642 | 3387129 |
| T3-go-opus1 | claude-opus-5-5 | True | 17/17 | 17/17 | 136/139 | 136/139 | 0 | +656/-46 | 0/0/5 | 5/4/4 | 78 | 69498 | 15507349 |
| T3-go-opus2 | claude-opus-5-5 | True | 17/17 | 17/17 | 136/139 | 136/139 | 0 | +751/-38 | 0/0/4 | 5/4/4 | 87 | 94760 | 17724001 |
| T3-go-sonnet1 | claude-sonnet-5-5 | True | 17/17 | 17/17 | 136/139 | 136/139 | 0 | +264/-16 | 0/0/4 | 5/4/4 | 42 | 31677 | 5758529 |
| T3-rust-opus1 | claude-opus-5-5 | True | 17/17 | 17/17 | 136/139 | 136/139 | 0 | +719/-52 | 0/0/4 | 5/4/4 | 54 | 58560 | 9393499 |
| T3-rust-opus2 | claude-opus-5-5 | True | 17/17 | 17/17 | 136/139 | 136/139 | 0 | +1003/-47 | 0/0/4 | 5/4/4 | 61 | 58289 | 11301875 |
| T3-rust-sonnet1 | claude-sonnet-5-5 | True | 17/17 | 17/17 | 136/139 | 136/139 | 0 | +553/-38 | 0/0/5 | 5/4/4 | 53 | 36484 | 8857330 |
| T4-go-opus1 | claude-opus-5-5 | True | 6/6 | 6/6 | 139/139 | 139/139 | 0 | +446/-17 | 0/0/3 | 5/4/5 | 45 | 38661 | 6022701 |
| T4-go-opus2 | claude-opus-5-5 | True | 6/6 | 6/6 | 139/139 | 139/139 | 0 | +368/-36 | 0/0/3 | 5/4/5 | 29 | 24452 | 3772798 |
| T4-go-sonnet1 | claude-sonnet-5-5 | True | 6/6 | 6/6 | 139/139 | 139/139 | 0 | +310/-14 | 0/0/4 | 5/4/5 | 18 | 15901 | 2258714 |
| T4-rust-opus1 | claude-opus-5-5 | True | 6/6 | 6/6 | 139/139 | 139/139 | 0 | +292/-42 | 0/0/3 | 5/5/5 | 56 | 38713 | 7725155 |
| T4-rust-opus2 | claude-opus-5-5 | True | 6/6 | 6/6 | 139/139 | 139/139 | 0 | +245/-22 | 0/0/2 | 5/5/5 | 53 | 32761 | 7594210 |
| T4-rust-sonnet1 | claude-sonnet-5-5 | True | 6/6 | 6/6 | 139/139 | 139/139 | 0 | +172/-16 | 0/0/4 | 5/4/4 | 22 | 16677 | 2637862 |

- **T1-go-opus1 major** (prototypes/go/internal/run/run_unix.go supervisor.onStop: `if fg != sv.own && fg != sv.pid && !sv.ttyIO { ... return }`): The S1 rule ('no job-control shell can be watching': foreground is neither heimdall-proto's nor the child's group, and no stdio descriptor is the controlling terminal) also matches a background job of an interactive shell whose stdio is fully redirected. The launcher then does not mirror a third-party stop, and the shell lists the job as Running while the child is stopped. Reviewer probe on darwin-arm64 with bash -i, job `heimdall-proto run -- /bin/sleep 30 </dev/null >/dev/null 2>&1 &`, kill -TSTP of the child, then `jobs -l`. Plain exec gave '[1]+ Stopped'. The new build gave 'Running' with the child in T and the launcher in S. The base build gave '[1]+ Stopped', which matches plain exec. So this is a regression against TASK.md's 'without breaking any existing behaviour'. The same happens with SIGSTOP, where the base exited 255. The REPORT.md limits section discloses only the opposite misclassification (a non-shell parent treated as a shell). The hidden S1-S5 tests do not cover this case. Evidence: review/notes.txt and review/probe_bg_redirected*.out.txt.
- **T1-rust-sonnet1 major** (src/runner.rs in_foreground_job and mirror_child_stop (`if !jc.sample() { return; }`); REPORT.md section 16 known gap (1)): This is a K6e regression. A background job (`cmd &`) of an interactive job-control shell that was never in the foreground no longer gets the child stop mirrored, so the child stays stopped while the shell lists the job as Running. Round 3c mirrored this case. A read-only probe on darwin (exit 0) showed it: under plain exec `jobs -l` listed 'Suspended: 18', and under the launcher it listed 'Running'. The gap is documented, but no distinguishing signal was tried (for example, whether any of stdin, stdout or stderr is the controlling tty; S1 guarantees none is). Neither the hidden tests nor the harness cover it.
