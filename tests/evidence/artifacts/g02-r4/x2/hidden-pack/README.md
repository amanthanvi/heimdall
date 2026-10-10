# G02 round 4, X2 task pack: hidden acceptance tests (index)

**Hidden material.** Implementers never see this directory, the repository, `<hidden>/../r4-scratch`, or
the evaluator's notes. Each implementer gets one isolated workspace built by `make-workspace.sh` (its
`TASK.md` is `<repo>/tests/evidence/artifacts/g02-r4/x2/specs/<task>.md`) and nothing else: no
hidden-test command, no repository path. Context is `<repo>/docs/g02/round4-plan.md` (X2). Built by
task `M00-T05-r4-taskpack` on 2026-10-06; fixed by `M00-T05-r4-taskpack-fix` after the independent
fairness review (`<repo>/tests/evidence/artifacts/m00-wf7/taskpack-review.json`), and again by
`M00-T05-r4-taskpack-fix2` after the independent recheck of that fix
(`<repo>/tests/evidence/artifacts/g02-r4/x2/taskpack-recheck/recheck.json`).

Pack status: `implemented_unverified`. The fairness review found the pack fair with three major and
four minor issues; the first fix round addressed them. The recheck confirmed those fixes except one
major issue (the transcript audit missed relative, `cd` and glob access) and three minor ones; fix
round 2 below addresses them, together with the orchestrator's decisions and the move of the seeded
trees. Fix round 2 has not yet had an independent re-review. Paths in this file are written as
`<repo>` (repository root), `<hidden>` (this directory, `$HM_HIDDEN`) and `<home>`; no absolute home
path appears here.

## Fix round 2 (2026-10-06), recheck issue by issue

| recheck issue or orchestrator input | fix |
|---|---|
| major: `audit-transcript.py` reported CLEAN for `cd /tmp && diff -r hm-r4/seeded/go x2ws-a1b2/heimdall/prototypes/go`, `ls ../.. ; diff -r ../../hm-r4/seeded/go prototypes/go`, `diff -r /tmp/hm*/M00*/base/prototypes/go prototypes/go` and `cat ../../x2ws-zz99/...`; implementers start with their cwd at the repository root | Rewritten as a conservative reachability audit (see "Implementer isolation"). Per tool call it takes the entry's `cwd`, follows every `cd`/`pushd` in the command (pipelines, `&`, `\|\|` and subshells keep or restore the old cwd), tokenizes the command (quotes, escapes, variables, `$(...)`, backticks, `~`, globs, redirections, here-documents) and resolves every argument against every possible cwd; globs are reduced to their static prefix; unresolvable expansions are flagged; any command other than `cd` and a few file-less builtins run while a possible cwd is outside the workspace is flagged; Read/Write/Edit/Glob/Grep/LS paths (Glob and Grep default to the cwd) and absolute paths in other tools are checked; marker strings in tool inputs and outputs are kept as a second signal. Allowed: the own workspace, its parent directory itself, `--scratch` directories, and toolchain/system locations (go/cargo/rustup/zig caches and installs, `/usr`, `/bin`, `/sbin`, `/opt/homebrew`, `/Library/Developer`, Xcode and Docker app bundles, `/System`, `/dev`, `/private/var/folders`, `~/.docker`). Output is one verdict per cell, `CLEAN` or `SUSPECT` with the offending call indices and reason codes, never transcript text. `audit-selftest.py` checks 41 crafted transcripts (the recheck's 11 cases including the four it found CLEAN, six cwd-at-repo cases, 20 further evasions, the T4 reproduction with and without `--scratch /tmp/repro`, and two clean transcripts): all classify as expected (exit 0). |
| orchestrator: `/tmp/hm-r4` deleted (disk full); seeded trees moved to `<hidden>/seeded-trees/{go,rust}` | `BASE.json` `seed.<lang>.tree` is now the plain relative path (`seeded-trees/<lang>`, the move note is in `tree_note`); `make-workspace.sh` reads the seeded tree from `<hidden>/<tree>`; `verify-matrix.sh`, `SEED.md` and `evaluator-commands.json` name the new place. Both tree digests re-checked after the move (equal to `BASE.json`); `--test-build` T4 workspaces for both languages built (exit 0) and equal the seeded trees (`diff -r` exit 0). Pack-author and reviewer scratch is `<hidden>/../r4-scratch/` (mode 0700), and `--test-build` may only use `<hidden>/../r4-scratch/M00-T05-*/`. |
| minor: `score.py` accepted a record without `--expect-sha256` and a record scored with the wrong `--lang` | `--expect-sha256` is required (64 hex) and must equal the record's `binary_sha256` and `binary_sha256_after`. `run.py` has a required `--lang go\|rust\|control` that it records as `lang` (it cannot be observed black-box); `hidden.sh` requires `--lang` and passes it on, also into the container; `score.py` refuses a record whose `lang` is not `--lang` (and a baseline whose `lang`, when present, differs). |
| minor: running the pack recreated `__pycache__` (which embeds the home path) | Every pack Python call in the scripts, templates and this file is `python3 -I -B`; `PYTHONDONTWRITEBYTECODE` alone would be ignored under `-I`, so `run.py`, `score.py`, `scan-home.py`, `audit-transcript.py` and `audit-selftest.py` also set `sys.dont_write_bytecode` before importing anything of the pack. The matrix run showed the positive controls (started as programs) still wrote `__pycache__` for their imports; `pc_t1.py`, `pc_t2.py` and `pc_t3.py` now set the same flag, and after re-running their rows no `__pycache__` exists in this directory. |
| minor: `make-workspace.sh` created the parent of `--dest` before checking where it resolves | `--dest` (and `--manifest`) are resolved before anything is created: relative paths are made absolute, `.` and `..` components are refused, the nearest existing ancestor is resolved with `pwd -P` (a symlinked parent cannot hide a refused place); the result is checked against the repository, `<hidden>/..` (this directory and `r4-scratch`) and `/tmp/hm-r4`; only then is the parent created and checked again. Refusals observed with nothing created: a relative `--dest` from the repository root, `r4-scratch` without `--test-build`, this directory, a `..` path, a `/tmp` symlink to the repository, a manifest inside `--dest`, a manifest inside the repository. |
| orchestrator decision | `T2.ascii_fold_only` counts toward `all_pass` for both languages: the spec both languages get states the ASCII-only folding rule explicitly (see T2). |
| orchestrator: the host disk is nearly full | New evaluator step 11 and `cleanup-cell.sh`: copy the evaluator's build and the implementer's last build into `<eval>/out/` (with `SHA256SUMS`), then delete Rust `target/` (except `target/tools`) in the workspace and the frozen copy and any Go build or module cache inside them. |

## Fix round 1 (2026-10-06), review issue by issue

| review issue | fix |
|---|---|
| major: the baseline drifted (X1b rebuilt `prototypes/*/dist` during the review; no digest checks) | One pinned base for both languages, the post-X1b commits Go `84c7665` and Rust `001a791`, in `BASE.json` with the tree digest of each base and seeded tree and the sha256 of every darwin-arm64 and linux-arm64 subject binary under `bin/`. Rebuilt from `git archive` of the pinned commits with each tree's own `build.sh`: all 8 binaries are byte-identical to the pins, and the base ones equal `prototypes/{go,rust}/dist/manifest.json`. `verify-matrix.sh` only runs the pinned copies under `bin/`, through `hidden.sh`, which copies the binary to a private directory, checks `--expect-sha256`, and makes `run.py` mark the run `invalid` (exit 2) if the binary changes during the run. `hidden.sh` and `verify-matrix.sh` refuse a repository whose tracked `tests/g02` differs from `BASE.json` `support_commit` (`f4ecabb`, harness 2.4.2), and `docker-run.sh` refuses an image tag other than the pinned `d0c8e448a3a7`. `score.py` refuses a baseline record whose binary digest is not the pin, and a result record for a binary other than `--expect-sha256`. |
| major: T4 seeds on the old base | Both seed patches re-applied on the post-X1b trees (`seed/go-84c7665.patch`, `seed/rust-001a791.patch`; the frozen-base patches are kept in `seed/superseded-frozen-base/`). Regenerating `/tmp/hm-r4/seeded/{go,rust}` from `git archive` + patch reproduces the pinned tree digests (`diff -r` exit 0). Symmetry was re-checked: through an absolute and a relative symlink the seeded Go and Rust builds give byte-identical stdout (`USAGE_ERROR` "profile path is not a regular file") and identical stderr, exit 2; the real path gives exit 0 in both; the base builds accept the symlinks. |
| major: implementers not isolated (`diff -r` against the unseeded tree; hidden dir readable) | `make-workspace.sh` builds a workspace that mirrors the repository layout with only the cell's prototype, the contract, schemas, harness, fixtures and record schema; a fresh venv with byte copies of pyte/wcwidth (the repository venv names the repository path, so it is not copied); no `.git`, no other prototype, no evidence tree, no hidden material. It verifies the prototype tree digest against `BASE.json` and byte-scans every file (venv and binaries included) for the repository path, this directory, `/tmp/hm-r4`, `taskpack` and `g02-r4/x2`. Same-user processes can still read anything, so `audit-transcript.py` checks every implementer transcript afterwards. Never give an implementer `hidden_test_cmd` from `m00-wf7/taskpack.json`: it is superseded by `evaluator-commands.json`. |
| major: T1 baselines start from different deficits | `score.py` scores a result against the pinned baseline of the same task, language and platform: `all_pass` (yes/no), `fixed` (baseline-failing checks now passing, out of the baseline's failing checks) and `regressed` (baseline-passing checks now failing). Compare languages on these, never on raw pass counts. |
| minor: darwin `nested_shell` passed only by the Python control | `score.py` lists `T1.nested_shell_{bash,zsh}` on darwin as `unproven_checks` and also reports `all_pass_excluding_unproven` and `fixed_excluding_unproven`; a both-languages-fail result there does not discriminate. |
| minor: the scrub missed wrapped home paths | `common/hm.py` matches every path also across whitespace, JSON escapes and CSI sequences, replaces the bare user name with `<user>`, and replaces a home-path piece of 8 or more characters cut off at either end of a string with `<home-part>`; `run.py` refuses to write a record that still holds the home path. Tested on synthetic wraps and on the reviewer's 12 records that had the leak: none left. `scan-home.py` checks anything before it is copied to evidence (it flags the reviewer's leaking record). The earlier results under `results/superseded-frozen-base/` were scrubbed and scan clean. |
| minor: T2 ASCII-only folding never tested | New check `T2.ascii_fold_only` (fixture `ascii-fold.toml`: Unicode-only case pairs É/é, Ü/ü and KELVIN SIGN/k are not findings; one ASCII pair is). Its expected JSON matches `lint_ref.py`; a mutant of the positive control that lowercases with Unicode rules fails exactly this check. T2 now has 12 checks. |
| minor: `hidden_test_cmd` has one `{bin}` for both platforms and absolute home paths | `evaluator-commands.json` gives separate darwin and linux steps with the platform's own binary and digest, as templates over `$HM_REPO` and `$HM_HIDDEN`; no absolute path. |

## Layout

| path | what |
|---|---|
| `BASE.json` | The pin: base commits and tree digests, seed patches and seeded tree digests, sha256 of every subject binary, the harness `support_commit`, the Linux image tag, and the rebuild check. |
| `bin/{base,seeded}-{go,rust}/{darwin,linux}-arm64/heimdall-proto` | The pinned subject binaries (built from the pinned trees; never `prototypes/*/dist`). |
| `run.py` | Runner: `python3 -I -B run.py --task T1\|T2\|T3\|T4 --bin PATH --platform darwin\|linux --lang go\|rust\|control [--only IDS] [--out JSON] [--list] [--expect-sha256 HEX]`; the record carries `lang`. Exit 0: every selected check passed. Exit 1: a check failed or errored. Exit 2: usage or setup error, digest mismatch, or the binary changed during the run (`verdict: invalid`). |
| `hidden.sh` | Evaluator entry point for one task, platform, language and binary (private copy, digest check, darwin or Linux container); `--lang go\|rust` is required. |
| `docker-run.sh` | The same run inside the G02 Linux runner image (linux/arm64, `--network none`). |
| `verify-matrix.sh` | The RED/GREEN matrix on the pinned subjects and the positive controls, darwin and linux. `TASKS="T4"` limits it. Writes `exit-codes.tsv` (real exit statuses with the first 12 hex of each binary digest) and `inputs.txt`. |
| `make-workspace.sh` | Builds one implementer workspace (see "Implementer isolation"). |
| `audit-transcript.py` | Per-cell verdict CLEAN or SUSPECT on an implementer's transcripts: every path a tool call can reach, from its effective cwd (see "Implementer isolation"). |
| `audit-selftest.py` | Crafted-transcript self-test of `audit-transcript.py` (41 cases; writes transcripts only to `--scratch`). |
| `cleanup-cell.sh` | Evaluator step 11: keep the builds in `<eval>/out/`, delete heavy build intermediates of the cell. |
| `seeded-trees/{go,rust}` | The T4 seeded source trees (moved here from `/tmp/hm-r4/seeded/` by the orchestrator; digests in `BASE.json`). |
| `score.py`, `baseline/` | Per-language scoring against the pinned baseline records in `baseline/<platform>/<task>-<subject>.json`: `python3 -I -B score.py --task T --lang go\|rust --platform P --expect-sha256 HEX RESULT.json` (`--expect-sha256` required; the record's `lang` must match). |
| `scan-home.py` | Exit 1 if any file under the given paths holds the home path (also wrapped) or the user name. |
| `evaluator-commands.json` | Per-platform evaluator command templates, safe to copy into evidence. |
| `common/hm.py` | Shared check and record helpers. Black-box only. A failed control or precondition is reported as `error`, never as `fail`. Paths are scrubbed to `<sandbox>`, `<bin>`, `<home>`, `<user>`. |
| `common/vendor/harness_lib.py`, `pty_shim.py` | Byte copies of `tests/g02/harness_lib.py` (sha256 `3b611a1d6a7a1d7d…5fdf1b8b4`) and `tests/g02/pty_shim.py` (sha256 `7ce947695e42dba0…dbb2b3c8e6`), harness 2.4.2. Used read-only for the pty session, the pyte screen, and the SGR and termios helpers. |
| `t1/jobctl.py` | T1: 14 checks. `child_tstp.py`, `child_read.py` and `ptyshell.py` are byte copies of `tests/evidence/artifacts/g02-parity-r3c/probes/{child.py,child3c.py,ptyshell.py}` (sha256 `101fdcb8…`, `f1c389ad…`, `04c83e0b…`). |
| `t2/lint.py`, `t2/fixtures/`, `t2/expected/`, `t2/lint_ref.py` | T2: 12 checks. The expected JSON is written by hand and cross-checked against `lint_ref.py`, a reference model of the spec: all 5 fixtures MATCH. `fixtures/clean.toml` is a byte copy of `tests/fixtures/g02/profiles/homelab.toml`. |
| `t3/tui.py`, `t3/large-100.toml` | T3: 17 checks. `large-100.toml` is a byte copy of the repository fixture. |
| `t4/symlink.py` | T4: 6 checks. |
| `seed/` | The T4 seed patches and `SEED.md` (what was seeded, why it is symmetric, how it was verified, what a correct fix looks like). |
| `positive-controls/` | Implementations used only for validation; they pass the hidden tests, which shows every check can be passed. `ref/` holds byte copies of `tests/g02/reference_impl.py` and `reference_tui.py`. |
| `results/` | Observed runs. `2026-10-06-pinned-base/` and `2026-10-06-pinned-base-2/` are the matrix on the pinned base (fix round 1); `2026-10-06-fix2/` is fix round 2: `matrix/` (records carry `lang`; the source of `baseline/`), `pc-rerun-after-pc-edit/`, `score-checks.tsv` and `audit-selftest.tsv`. `superseded-frozen-base/` holds the runs on the frozen base `38b6b72`/`d8f0cbe` (history only). Each run directory has `exit-codes.tsv`, `<platform>/<task>-<subject>.json` (expected vs observed for every assertion) and `.console.txt`. |

## Implementer isolation

For each cell (task, language, run):

1. Build the workspace with a neutral random name under a common prefix, and keep the manifest in the
   evaluator's scratch (never in the workspace):
   `HM_REPO=<repo> sh <hidden>/make-workspace.sh --task T4 --lang rust --dest /tmp/x2ws-<random>/heimdall --manifest <eval>/workspace-manifest.json`.
   `--dest` is resolved before anything is created (see fix round 2) and refused inside the
   repository, `<hidden>/..` (this directory and `r4-scratch`) or `/tmp/hm-r4`; only the pack author's
   `--test-build` may use `<hidden>/../r4-scratch/M00-T05-*/`.
2. Start the implementer with only this instruction: read `TASK.md` and work inside this directory
   (the `--dest` path). No repository path, no hidden-test command. If the runner can start the agent
   with that directory as its working directory, do so. Agents launched from this orchestration start
   with their cwd at the repository root, which holds the unseeded prototypes of both languages; the
   audit flags every call made before the agent `cd`s into its workspace, so give the path first and
   expect the first call to be the `cd`.
3. Afterwards, audit the session file and the session directory (subagents, persisted tool outputs):
   `python3 -I -B <hidden>/audit-transcript.py --repo <repo> --workspace <ws> --workspace-prefix /tmp/x2ws- --scratch <session dir> <session>.jsonl <session dir>`.
   For every tool call it resolves the effective cwd (the entry's `cwd` plus every `cd` in the
   command) and every path argument, relative or absolute, glob, `~` or `$VAR` form, and flags any
   that resolves or could expand outside the workspace, its parent directory itself, the `--scratch`
   directories and the toolchain/system allowlist (the module docstring lists it). It also flags a
   command run while a possible cwd is outside the workspace, an expansion it cannot resolve, a command
   it cannot parse, Read/Write/Edit/Glob/Grep/LS paths outside (Glob and Grep default to the cwd), and
   marker strings (repository, hidden material, `r4-scratch`, `seeded-trees`, `/tmp/hm-r4`,
   `taskpack`, `g02-r4/x2`, other workspaces) in tool inputs or outputs. Output: `CALL` lines with
   call index, file, line, tool and reason codes, `ENTRY` lines for markers in persisted outputs,
   `NOTE` lines for markers in prompt or assistant text (not counted), and one `VERDICT CLEAN` (exit 0)
   or `VERDICT SUSPECT calls [...]` (exit 1). Never transcript text. A SUSPECT verdict means: inspect
   those calls by hand and record whether the cell is contaminated; a call that read the repository's
   prototypes, the hidden material, the seeded or base trees, or another workspace contaminates it.
   The audit is deliberately conservative: a clean implementer that uses `/tmp` for its own scratch
   files, unresolvable variables, or commands before its first `cd` is reported SUSPECT for review.
   `python3 -I -B <hidden>/audit-selftest.py --repo <repo> --scratch <hidden>/../r4-scratch/audit-selftest`
   re-runs the crafted cases (exit 0 when all classify as expected).
4. **T4 only.** The T4 report's reproduction steps use `/tmp/repro` (outside the workspace and shared by
   every T4 cell). Before each T4 cell remove `/tmp/repro` (only if it holds nothing but a previous
   cell's reproduction), never run two T4 cells at the same time, and audit T4 transcripts with
   `--scratch /tmp/repro` added. Otherwise a second cell meets the first cell's leftovers (`ln -s`
   fails with "File exists"), and every T4 cell is SUSPECT for following its own report. Moving the
   reproduction into the workspace would need a spec change (escalated by fix round 2, not made).

Residual: implementers run as the same OS user, so isolation is by content plus audit, not by
permission. The audit sees only what the transcript records: a program the implementer writes and
runs could compute a path at run time (the audit flags unresolvable expansions in the shell, not
inside compiled code), and tool outputs are checked for markers only. The workspace still contains
the harness's own `tests/g02/reference_impl.py` and `reference_tui.py` (needed by the harness) and
each prototype's `REPORT.md`; both are identical in kind for the two languages.

## Evaluator protocol

Set `HM_REPO=<repo>` and `HM_HIDDEN=<hidden>`; unset `SSH_AUTH_SOCK`. `evaluator-commands.json`
has every step as a template. Per cell:

1. **Pin check (once per session):** `cd "$HM_REPO" && TASKS=T4 sh "$HM_HIDDEN/verify-matrix.sh" <eval>/pin-check both`.
   It exits 2 if the repository's `tests/g02` is not the pinned harness; otherwise `exit-codes.tsv`
   must show T4 `seeded-*` exit 1 and `base-*` exit 0 with digests equal to `BASE.json`.
2. **Audit** the transcripts (above).
3. **Freeze** the implementer's prototype: `cp -R <ws>/prototypes/<lang> <eval>/frozen/<lang>` and
   remove `dist/`. Diff it against the base (T1-T3: `git archive <base commit> prototypes/<lang>`;
   T4: `<hidden>/seeded-trees/<lang>`), after checking the base copy's tree digest against `BASE.json`.
4. **Build** the frozen copy with its `build.sh` (Rust: `CARGO_ZIGBUILD=$HM_REPO/prototypes/rust/target/tools/bin/cargo-zigbuild`).
   All four targets, windows-x64 included, must build. Record the sha256 of
   `dist/darwin-arm64/heimdall-proto` and `dist/linux-arm64/heimdall-proto`.
5. **Hidden tests, darwin** (darwin-arm64 host):
   `cd "$HM_REPO" && sh "$HM_HIDDEN/hidden.sh" --task <T> --platform darwin --lang <lang> --bin <eval>/frozen/<lang>/dist/darwin-arm64/heimdall-proto --expect-sha256 <darwin sha> --out-dir <eval>/hidden-darwin`
6. **Hidden tests, linux** (linux-arm64 container):
   `cd "$HM_REPO" && sh "$HM_HIDDEN/hidden.sh" --task <T> --platform linux --lang <lang> --bin <eval>/frozen/<lang>/dist/linux-arm64/heimdall-proto --expect-sha256 <linux sha> --out-dir <eval>/hidden-linux`
   Exit 0 all pass, 1 a check failed, 2 setup error or invalid run (rerun; do not score).
7. **Score** each platform: `python3 -I -B "$HM_HIDDEN/score.py" --task <T> --lang <lang> --platform <p> --expect-sha256 <sha> <eval>/hidden-<p>/<T>-<p>.json`.
   `--expect-sha256` is required; the record must carry that digest and `lang` equal to `--lang`.
   `all_pass` covers every check of the task, `T2.ascii_fold_only` included, for both languages.
8. **Full harness 2.4.2** on both platforms, from the repository:
   `python3 -B tests/g02/conformance.py --bin <darwin bin> --candidate <lang> --out <eval>/harness-darwin.json` and
   `sh tests/g02/linux/run.sh --artifact-dir <eval>/frozen/<lang>/dist/linux-arm64 --candidate <lang> --out <eval>/harness-linux.json`.
   Expected 139/139; for T3, 136/139 with exactly `tui.filter_edit_resets_selection`, `tui.no_color`
   and `tui.large_100_filter_latency` failing (the T3 positive control shows this on both platforms).
9. **Unit tests** in the frozen copy: `go test ./...` or `cargo test --locked`, with
   `HEIMDALL_G02_FIXTURES=$HM_REPO/tests/fixtures/g02/profiles`.
10. **Evidence:** run `python3 -I -B "$HM_HIDDEN/scan-home.py"` on everything before copying it to
    `<repo>/tests/evidence`; copy command templates, never expanded command lines.
11. **Clean up** (the host disk is nearly full; never skip):
    `HM_REPO="$HM_REPO" sh "$HM_HIDDEN/cleanup-cell.sh" --lang <lang> --ws <ws> --eval <eval>`.
    It first copies `<eval>/frozen/<lang>/dist` (all four targets) to `<eval>/out/dist-frozen/` and the
    implementer's last build `<ws>/prototypes/<lang>/dist` to `<eval>/out/dist-workspace/`, writes
    `<eval>/out/SHA256SUMS`, and only then deletes Rust `target/` (except `target/tools`) in `<ws>` and
    `<eval>/frozen`, and any Go build cache (`README` + `trim.txt`) or module cache (`cache/download`)
    placed inside `<ws>` or `<eval>`. Sources, `change.patch`, records and transcripts stay; the
    reviewer works from `<eval>/out/`, the frozen sources and the records. `--dry-run` prints the plan.

### Run hygiene

- Only PIDs that a check started are signalled, and only by exact PID.
- `SSH_AUTH_SOCK` is removed.
- Every run has a private sandbox under `$TMPDIR` (default `/tmp`) with its own `HOME` and `TMPDIR`.
- There is no network use and there are no real keys.
- T2 uses a random marker per run (`HMX2LINTSECRET_…`), never a `HEIMDALL_CANARY_` value.
- The first version of this file claimed that a grep of `results/` for the home path found
  nothing; that grep missed paths split by a terminal wrap (the review's finding). After the scrub fix
  `scan-home.py`, which also matches wrapped paths, reports no hit in `results/`.

## Checks per task

### T1, exec-equivalent job control (14 checks; spec S1–S5)

Each check runs its scenario twice in the same environment: first with plain exec (the control),
then through `heimdall-proto run`.

- `T1.nonint_stop_cont_SIGSTOP|SIGTSTP` (S1). The parent is not a shell. The job runs in a new
  process group that is not orphaned (parity-r3c H6). Required: exit 7 within 6 s of the SIGCONT,
  the child completed, and the child reaped.
- `T1.pty_stop_cont_{bash,zsh}_{SIGSTOP,SIGTSTP}` (S2). Required: a stop notice, `$?` equal to the
  control's, and the child completed. Then either (a) no job is left, or (b) the permitted deviation
  applies: `fg` returns 7 and no job remains. In both cases the shell must still be alive and no
  process may be left.
- `T1.cont_launcher_only_{bash,zsh}` (S3). A SIGCONT goes to the launcher PID only. Required: the
  child resumes (it prints BACK); 2.6 s later `jobs` says stopped and never running; after `fg` the
  child reads typed input; `exit 5` gives `$?` 5.
- `T1.nested_shell_{bash,zsh}` (S4). Required: a stop notice and the outer prompt, the outer shell
  still alive, the nested shell answering after `fg`, and `exit 3` giving outer `$?` 3.
- `T1.sigstop_meta_{bash,zsh}_{read,ext}` (S5). Required: a stop notice; `$?` equal to the control's
  (128+SIGSTOP); for 3 s the child is in state T and the launcher is alive; after `fg` the child
  reads again; `quit` gives `$?` 0; the meta file holds CHILD_EXITED
  `{"launched":true,"exit_code":0,"signal":null}`.

**Why S2 has a permitted deviation.** A launcher that reports a stop to the shell has to stop
itself. A stopped process cannot run, so the launcher cannot notice that a third party continued the
child. Only a second process could wake it, and K16 forbids executing a helper. The Go runtime also
cannot fork without exec. The gated K6e self-stop check means the launcher must mirror SIGTSTP. So
plain-exec parity for S2 with SIGTSTP is not achievable together with the 2.4.2 harness. This is
inferred from the mechanism and was not proven by experiment. The deviation therefore allows "stays
stopped until `fg`, then completes". Both baselines already do this for SIGTSTP. S2 is RED only where
a baseline loses the child or reports the wrong stop signal.

**Feasibility evidence.**

- Every T1 check is passed by at least one baseline (frozen and pinned post-X1b alike) on at least one platform. The exception
  is `nested_shell` on darwin, which neither baseline passes.
- `positive-controls/pc_t1.py` passes all 14 checks on darwin and on linux. It is
  `tests/g02/reference_impl.py` with its conforming variant `run_job_control_own_group` always on,
  plus these changes:
  - It mirrors a stop with the child's own stop signal.
  - It takes the terminal back, or hands it back, only while the job holds it, and hands it back to
    the group that held it.
  - A SIGCONT to the launcher continues the child.
  - With no terminal on stdin, it never mirrors a stop.
- The same control passes all 31 `run.*` harness checks on darwin and on linux (exit 0). Those runs
  used `--only run.*`, so their verdict is "inconclusive" by design.

### T2, `profile lint` (12 checks)

These checks compare exact expected JSON for 5 fixtures:

- `all-rules.toml` fires all 5 rules, giving 13 findings, and contains near misses.
- `near-miss.toml` contains only near misses: port 22 given explicitly, port 1024, `Root`, `roots`,
  the same labels in two destinations, an empty label, and the same host on another port.
- `ascii-fold.toml` (`T2.ascii_fold_only`, fix round): Unicode-only case pairs (É/é, Ü/ü, KELVIN SIGN/k)
  in hosts and labels are not findings; one ASCII case pair is the only finding.

The checks also cover:

- `--json` given before `--file`;
- a path with spaces and non-ASCII characters;
- exit codes without `--json`;
- six profiles that each fire one rule;
- the same result as `profile show` on 11 invalid or non-regular inputs, each within 2 s. The
  inputs are: a forbidden key holding the marker, an unknown destination key, malformed TOML,
  schema_version 2, a duplicate alias, port 0, a K2 control character, an oversize file, a missing
  file, a directory and a FIFO;
- usage errors;
- no file writes;
- no echo of any distinctive profile value on stdout or stderr, with or without `--json`.

The spec folds case for ASCII letters only. Apart from `ascii-fold.toml`, the fixtures use only
ASCII hosts and labels wherever case folding decides a result. This keeps
the other T2 checks free of a bias from language idioms: Go's `strings.EqualFold` and
`strings.ToLower` fold all of Unicode, while Rust's `eq_ignore_ascii_case` folds ASCII only.
`T2.ascii_fold_only` tests the spec's ASCII-only rule directly, so the idiomatic Go call fails it and
the idiomatic Rust call passes. **Orchestrator decision (2026-10-06, recorded in fix round 2):**
`T2.ascii_fold_only` counts toward `all_pass` for both languages, because the spec both languages get
states the ASCII-only rule explicitly. (The alternative the review proposed, dropping the check and
having the code reviewer check folding by reading the code, was not taken.) `score.py` has no
exception for it.

### T3, TUI (17 checks)

- **Highlight (7 checks).** In each row, the set of underlined cells must equal the expected set
  exactly. Covered: the filters `a`, `LAB`, `EXAMPLE` and `東`; after Enter; after Esc; at 40
  columns; and with NO_COLOR (no colour SGR, and the selected row still has `> `).
- **Help (6 checks).** The 9 lines appear in order; `?` and Esc toggle the overlay; other keys are
  ignored while it is open; Ctrl-C exits 130 with the terminal restored; `?` in filter mode is filter
  text; the overlay works at 20x5.
- **Selection (3 checks).** The selection is kept across append, Backspace and Esc; it falls back to
  the first row when hidden; on large-100 it is kept at row 38.
- **`T3.k17_filter_latency` (1 check).** This replaces the harness's K9-based K17 predicate. It runs
  the same 5 × 6 edits on large-100. An update counts when the screen shows the status, a full
  contiguous window of the result, and the `> ` marker on the row selected under part C. The p95
  latency must be at most 100 ms.

**Emulator robustness.**

- SGR colon sub-parameters such as `4:1` are normalised.
- CSI `…m` sequences with a private prefix are removed before pyte sees them. An example is the
  XTMODKEYS sequence `CSI > 4 ; 2 m`, which Bubble Tea v2 emits. pyte 0.8.2 applies such a sequence
  as SGR 4. In the first dry run this made the Go baseline's whole selected row look underlined;
  this was observed and then fixed.

**Spec conflict.** The T3 spec asks to keep the selected destination across filter edits when it is
still visible (part C). That conflicts with contract K9 and with three harness checks that encode or
assume K9: `tui.filter_edit_resets_selection`, `tui.no_color` (its last step) and
`tui.large_100_filter_latency` (its update predicate). The T3 positive control fails exactly these
three on darwin and linux. The spec exempts them and moves the parts of them that are not about K9
into the hidden tests. Narrowing part C to appended characters only would leave a single harness
conflict, `tui.filter_edit_resets_selection`, but that would no longer be the feature as specified.
The orchestrator decides which version to use.

### T4, seeded bug (6 checks)

1. The reproduction: an absolute symlink.
2. A relative symlink, a chain of two links, a path with spaces and non-ASCII characters, and a
   symlinked parent directory.
3. A symlink to a FIFO, a directory or `/dev/null`, and a dangling symlink: each must still give
   USAGE_ERROR within 2 s (K14).
4. Through a symlink: an oversize file gives INPUT_TOO_LARGE, and a duplicate alias gives
   SCHEMA_INVALID with the same key_path as the direct path.
5. Plain mode (no `--json`) exits 0.
6. `tui --file <symlink>` shows 3/3, and `q` exits 0.

See `seed/SEED.md`. The post-X1b seeded builds pass all 139 checks of the 2.4.2 harness on darwin
and on linux (run from inside the T4 test workspaces, see "Observed verification"). No harness check is
related to the seed.

## Observed verification (fix round 2, 2026-10-06)

All runs below were executed in this round; exit statuses are the real ones. Results are in
`results/2026-10-06-fix2/`.

- **Matrix** (`matrix/`): `cd <repo> && HM_REPO=<repo> sh verify-matrix.sh <scratch>/vm both`, exit 0,
  16:21:34-16:44:31 UTC, `inputs.txt`: support commit `f4ecabb`, tests/g02 unchanged, image
  `sha256:5081bb560f9b`, pack_sha256 `11efbb3beec0ce5d`. All 26 rows as expected: on both platforms
  the Go and Rust baselines exit 1 (RED) on T1, T2 and T3, the positive controls exit 0 (GREEN) on
  T1-T3, the seeded builds exit 1 on T4 (1/6) and the base builds exit 0 on T4 (6/6). Every record's
  `binary_sha256` and `binary_sha256_after` equal its `BASE.json` pin; every record carries the
  expected `lang` (`go`, `rust`, `control`); no check reported `error`; the per-check statuses of all
  26 records are identical to both fix-round-1 runs (`2026-10-06-pinned-base`, `-2`). Pass counts
  are those of the fix-round-1 table above (T1 darwin Go 6/14, Rust 8/14; T1 linux 8/14 both; T2 1/12;
  T3 3/17; T4 seeded 1/6).
- **Baselines.** `baseline/` now holds the 16 baseline records of this run (they carry `lang`); the
  fix-round-1 baselines are kept in `results/2026-10-06-pinned-base/`.
- **Positive controls without `__pycache__`.** The matrix run showed that the positive controls
  (`pc_t2.py`, `pc_t3.py`), which the harness starts as programs, still wrote `__pycache__` for the
  modules they import; `run.py` itself wrote none (it sets `sys.dont_write_bytecode`). After the
  matrix, `pc_t1.py`, `pc_t2.py` and `pc_t3.py` got `sys.dont_write_bytecode = True` (no other change;
  pack_sha256 is now `0a9ca5e1bb722c83`), the three `__pycache__` directories were removed, and the
  six positive-control rows were run again (`pc-rerun-after-pc-edit/`): exit 0 and all checks pass on
  darwin and linux (T1 14/14, T2 12/12, T3 17/17). Afterwards `find <hidden> -name __pycache__` finds
  nothing.
- **score.py** (`score-checks.tsv`, records from this matrix plus crafted variants): a valid record
  scores exit 0; the same record with `--lang rust`, without `--expect-sha256`, with another binary's
  digest, with a malformed digest, without `lang`, or with a changed `binary_sha256_after`, and a
  positive-control record scored as `go`, are refused (exit 2).
- **Audit self-test** (`audit-selftest.tsv`): 41 crafted transcripts, 0 mismatches, exit 0. The four
  cases the recheck found CLEAN now give SUSPECT (`cd /tmp && diff -r hm-r4/...`:
  `cwd-outside:tmp`, `path-outside:tmp`, `marker:round4-scratch`; `ls ../.. ; diff -r ../../hm-r4/...`:
  `path-outside:tmp`, `marker:round4-scratch`; `/tmp/hm*/M00*/...`: `glob-outside:tmp`;
  `../../x2ws-zz99/...`: `marker:other-workspace`); every cwd-at-repository case gives SUSPECT; the
  clean transcripts give CLEAN. Session directories with `subagents/` and a persisted
  `tool-results/*.txt` holding a marker give SUSPECT (`ENTRY ... output-marker`), and CLEAN without
  it; a workspace inside the repository and a missing transcript are usage errors (exit 2). On six
  real transcripts of an unrelated project (250, 43, 32, 18, 46 and 40 tool calls) the tokenizer
  parsed every Bash command (0 `unparsed-command` after here-documents inside `$(...)` were handled);
  their verdicts are not meaningful for X2 because those sessions worked outside the directory given
  as workspace.
- **make-workspace.sh.** Refusals (exit 2, nothing created): relative `--dest` from the repository
  root, `r4-scratch` without `--test-build`, the hidden directory, a `..` component, a `/tmp` symlink
  to the repository, a manifest inside `--dest`, a manifest inside the repository. Built (exit 0):
  `--test-build` T4 Go and T4 Rust under `r4-scratch/M00-T05-r4-taskpack-fix2/` (prototype tree
  digests equal `BASE.json`; `diff -r` against `seeded-trees/<lang>` exit 0, Rust excluding
  `target/`), and a normal T2 Go workspace under `/tmp/x2ws-<random>/heimdall` (deleted afterwards).
  No workspace was compiled in this round.
- **cleanup-cell.sh** on a synthetic cell (fake builds, fake Rust `target/`, a fake Go build cache and
  a read-only fake module cache): `--dry-run` listed the plan and changed nothing; the real run copied
  both `dist/` trees into `out/` with `SHA256SUMS`, then deleted `target/*` except `target/tools` and
  both caches (exit 0). The repository as `--ws` and a wrong `--lang` were refused (exit 2).
- `scan-home.py` on this whole directory: 419 files, no hit (exit 0).

## Observed verification (fix round 1, 2026-10-06, pinned base)

Subjects are the pinned binaries in `bin/` (Go base `bdfd64a2…` darwin / `18d96a07…` linux, Rust base
`f9a3ec8b…` / `85e038b4…`, seeded Go `7ccf5a2b…` / `3e118cb9…`, seeded Rust `66187b16…` / `25af8e12…`)
and the positive controls. Every record's `binary_sha256` equals its pin and its
`binary_sha256_after`. No check reported `error`.

| platform | task | Go base 84c7665 | Rust base 001a791 | positive control | Go seeded | Rust seeded |
|---|---|---|---|---|---|---|
| darwin | T1 | RED 6/14, exit 1 | RED 8/14, exit 1 | GREEN 14/14, exit 0 | | |
| darwin | T2 | RED 1/12, exit 1 | RED 1/12, exit 1 | GREEN 12/12, exit 0 | | |
| darwin | T3 | RED 3/17, exit 1 | RED 3/17, exit 1 | GREEN 17/17, exit 0 | | |
| darwin | T4 | GREEN 6/6, exit 0 | GREEN 6/6, exit 0 | (bases are the control) | RED 1/6, exit 1 | RED 1/6, exit 1 |
| linux | T1 | RED 8/14, exit 1 | RED 8/14, exit 1 | GREEN 14/14, exit 0 | | |
| linux | T2 | RED 1/12, exit 1 | RED 1/12, exit 1 | GREEN 12/12, exit 0 | | |
| linux | T3 | RED 3/17, exit 1 | RED 3/17, exit 1 | GREEN 17/17, exit 0 | | |
| linux | T4 | GREEN 6/6, exit 0 | GREEN 6/6, exit 0 | | RED 1/6, exit 1 | RED 1/6, exit 1 |

Runs: `results/2026-10-06-pinned-base/` (verify-matrix.sh exit 0, 14:37-15:00 UTC) and
`results/2026-10-06-pinned-base-2/` (after the harness-pin checks were added to `hidden.sh`,
`docker-run.sh` and `verify-matrix.sh`; exit 0, 15:26-15:49 UTC; same exit table and identical
per-check statuses in all 26 records as the first run; `inputs.txt`: support commit `f4ecabb`,
tests/g02 unchanged, image `sha256:5081bb560f9b`). The free disk space on the host ran out during
the second run's linux T1 rows; no record shows an `error` check and every digest held. An earlier run of the interrupted first fix
attempt on the same pins (scratch only, not kept here) had the same exit table and identical
per-check statuses in all 26 records. `scan-home.py` reports no hit in either results directory.

T1 failures of the pinned baselines (identical to the frozen base):

- Go darwin: S2 SIGSTOP (bash, zsh), S4 (bash, zsh), S5 (all 4). Go linux: S2 SIGSTOP (bash, zsh)
  and S5 (all 4).
- Rust darwin and linux: S1 (both signals), S3 (bash, zsh), S4 (bash, zsh).

`score.py` on these records: each baseline scored against itself gives `fixed` 0/N and `regressed` 0;
each positive control gives `all_pass` true, `regressed` 0 and `fixed` N/N against both languages
(T1 darwin: Go 8/8, Rust 6/6; `fixed_excluding_unproven` Go 6/6); each base T4 record scored against
its seeded baseline gives `fixed` 5/5. A synthetic record with one baseline failure fixed and one
baseline pass broken scores `fixed` 1/6 and `regressed_checks` with that check; a record with an
`error` check, the wrong platform, a digest other than `--expect-sha256`, or a baseline whose digest
is not the pin is refused (exit 2).

**Workspaces.** Four test workspaces were built with `make-workspace.sh --test-build` (T1 go, T2 rust,
T4 go, T4 rust; each exit 0; prototype tree digests equal `BASE.json`). Inside each, the prototype's
own `build.sh` built all four targets (exit 0) and the darwin-arm64 and linux-arm64 binaries are
byte-identical to the pinned base (T1, T2) or seeded (T4) builds; `go test ./...` and
`cargo test --locked` passed (exit 0) without `HEIMDALL_G02_FIXTURES`. From the T4 workspace roots,
`python3 tests/g02/conformance.py` (darwin) and `sh tests/g02/linux/run.sh` (linux) gave 139/139
`verified` for Go and for Rust on both platforms, using the workspace's own venv (pyte 0.8.2).
`make-workspace.sh` refused a destination under `/tmp/hm-r4` without `--test-build` and one inside the
repository (exit 2, nothing created). `hidden.sh` refused a workspace as `HM_REPO`, and `docker-run.sh`
refused a changed Dockerfile (both exit 2).

**Transcript audit (fix round 1 version, superseded by fix round 2; the recheck found it missed relative, `cd` and glob access).** On synthetic transcripts `audit-transcript.py` reported every planted read
(hidden directory by `~/` path and by a `/`-escaped path, `/tmp/hm-r4`, repository
`prototypes/`, another workspace by `/tmp` and `/private/tmp` path, the repository as a search root,
in a tool output and as `cwd`) and nothing in a clean transcript whose reads stay in its workspace.
On real Claude Code transcripts it parsed the session file, `subagents/workflows/*/agent-*.jsonl` and
persisted `tool-results/*.txt` (exit 1 on a heimdall orchestration session, as expected) and reported
two unrelated-project transcripts CLEAN (exit 0).

## Residual neutrality risks (for the independent reviewer)

- **T1.** The baselines fail for different root causes (Go: decoding of the darwin SIGSTOP and
  reporting the wrong signal; Rust: no CONT forwarding and mirroring with no tty), so the work differs
  by language although the target is the same. Score by `fixed`/`regressed`/`all_pass`, not raw counts.
  S4 on darwin is passed by neither baseline; feasibility is shown only by the Python positive
  control (`unproven_checks` in `score.py`).
- **T2.** `T2.ascii_fold_only` (see T2 above) is a spec-conformance check that the idiomatic Go
  folding call fails; by orchestrator decision it counts toward `all_pass` for both languages, since
  the spec states the rule. Exit status 3 for LINT_FINDINGS
  and the new codes lie outside the frozen contract; only the spec defines them, for both languages.
- **T3.** Ratatui styles parts of a row with `Span`s; Go's Bubble Tea v2 renderer re-parses inline
  SGR, so the Go prototype has to embed SGR in its row strings. The tests accept any standard
  underline encoding.
- **T4.** The Go seed changes one identifier (`Stat` to `Lstat`); the Rust seed adds a pre-check block.
  In both, the symptom bytes are identical and the unit suite was changed to assert the bug. Each
  `REPORT.md` describes the unseeded K14 check (see `seed/SEED.md`).
- **Isolation.** Same OS user: content isolation plus transcript audit, not permissions. `/tmp/hm-r4`
  (which held unseeded Go/Rust copies) was deleted by the orchestrator; the seeded trees and all pack
  scratch now live under `<home>/.local/share/heimdall-m00/` (mode 0700, same user only). Agents
  launched by the orchestration start with their cwd at the repository root, which holds the unseeded
  prototypes of both languages; the fix-round-2 audit flags any call made from there, but it cannot
  prevent the access.
