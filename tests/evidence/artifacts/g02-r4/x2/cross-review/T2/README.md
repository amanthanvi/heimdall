# X2 task T2 (`profile lint`): cross-review of all six cells with one rubric

Task id: M00-T05-r4-x2-xrev-T2. Date: 2026-10-10. Host: darwin-arm64 (macOS 27.0). Status of this
review: `verified` for darwin-arm64 observations; Linux and Windows were not re-run here (see Limitations).

Scope: the six T2 changes (cells `T2-go-opus1`, `T2-go-opus2`, `T2-go-sonnet1`, `T2-rust-opus1`,
`T2-rust-opus2`, `T2-rust-sonnet1`) against `specs/T2.md` and `docs/g02/slice-contract.md`, with the
same probes and the same rubric for both languages. This review does not compare the languages.

Rubric (applied identically to every cell):

- **blocker**: security-boundary breach, secret disclosure, or loss of user data.
- **major**: violates an explicit requirement of the spec or contract, or crashes, hangs or gives wrong
  results, on an input or use a real user could plausibly hit, and the hidden tests do not catch it.
- **minor**: unusual input, cosmetic output, test or code-quality issue, or behaviour the spec leaves open.
- **pre-existing**: present in the baseline and not something the task asked to change.

Two tie-break rules were fixed before rating and applied to every cell:

- *Usage text.* Adding the `profile lint` line to the usage listing (all six cells do it, same text) is
  the documentation of the new command and is not counted. Changing the text of an existing command's
  error result is counted as cosmetic (minor).
- *Wall-clock assertions in tests.* Minor (flake risk) when the observed time is more than a tenth of the
  asserted bound; not a defect otherwise. Times are in `raw/test-timing.txt`.

## Result

No blocker and no major in any cell. All six builds give the reference result on 400 random
profiles and 12 hand-made edge profiles. They are deterministic, echo no profile value, behave like
`profile show` on 43 invalid or unusual inputs, and stay within K15 on 11 large profiles built to
maximise lint work (up to 1 MiB).
Every remaining item is a minor or a pre-existing behaviour.

| cell | blocker | major | minor | pre-existing |
|---|---|---|---|---|
| T2-go-opus1 | 0 | 0 | 4 | 0 |
| T2-go-opus2 | 0 | 0 | 1 | 1 |
| T2-go-sonnet1 | 0 | 0 | 4 | 1 |
| T2-rust-opus1 | 0 | 0 | 3 | 0 |
| T2-rust-opus2 | 0 | 0 | 5 | 0 |
| T2-rust-sonnet1 | 0 | 0 | 4 | 0 |

The minor counts are mostly code- and test-quality items. They say little about the cells' behaviour,
which was the same in every probe except D2 (go-opus1, `--file --json`).

## Classification, defect by defect

"Reviewer" is the cell reviewer's rating in `results.json` (`cells[].review.defects`). "—" means the
reviewer did not list the item for that cell. Evidence: P = probe below, R = read in the diff.

| id | defect | go-opus1 | go-opus2 | go-sonnet1 | rust-opus1 | rust-opus2 | rust-sonnet1 | evidence |
|---|---|---|---|---|---|---|---|---|
| D1 | The text of an existing error result changed. In `profile <anything but show/lint>` (with or without `--json`), the message `expected 'profile show'` became `expected 'profile show' or 'profile lint'`, on stderr and in the JSON `data.error.message`. Code and exit are unchanged. Rust's generic message needed no change, and the Rust cells did not change it. | minor (reviewer —) | minor (reviewer —) | minor (reviewer minor) | n/a | n/a | n/a | P12, R |
| D2 | `profile lint --file --json` is treated as a missing value: USAGE_ERROR JSON, exit 2. Go's `profile show` takes `--json` as the path. With no file of that name, show exits 2 with no JSON. With a file named `--json` in the cwd, show reads it and exits 0, while this lint refuses it. Documented by the implementer. The spec does not say whether `--json` after `--file` counts as "given" or as the value, so this is open. | minor (reviewer minor) | n/a | n/a | n/a | n/a | n/a | P6 |
| D3 | `profile lint --file --json` follows Go's `flag` package, as Go's `profile show` does: `--json` becomes the path. The result is exit 2 USAGE_ERROR with no JSON. If a file named `--json` is in the cwd, it is linted (exit 3, plain output). This is the baseline show behaviour, and the spec asks lint to match show. | n/a | pre-existing (reviewer minor) | pre-existing (reviewer —) | n/a (Rust's parser refuses it with USAGE_ERROR JSON) | n/a | n/a | P6, P12 |
| D4 | The load-error path (stderr line, optional JSON failure, exit) is a copy of show's instead of being shared, so the two can drift. Parity holds today: 0 differences in P5. go-opus2 and go-sonnet1 share one helper (`loadProfileArgs`). | minor (reviewer minor) | n/a | n/a | minor (reviewer minor) | minor (reviewer —; its summary calls it "a verbatim copy" but does not list it) | minor (reviewer minor) | R, P5 |
| D5 | The cell's no-write test watches only the profile's own directory. A write to the cwd, HOME or TMPDIR would still pass. rust-opus2's `cmd()` leaves the test process cwd in place, and its snapshot covers only the profile's temp directory. Observed: lint writes nothing (P9). | minor (reviewer minor) | n/a (watches cwd, HOME, TMPDIR) | minor (reviewer minor) | n/a (tree includes the cwd) | minor (reviewer —) | n/a (profile dir and cwd) | R, P9 |
| D6 | The doc comment on `plain()` in `src/main.rs` still lists "`version`, `profile show` and `agent list`". All three Rust cells now also use it for `profile lint`, and none updated the comment. | n/a | n/a | n/a | minor (reviewer —) | minor (reviewer —) | minor (reviewer minor) | R |
| D7 | The end-to-end CLI findings test checks only the number of findings (6), not the exact findings or their order. The other five cells have an exact-JSON CLI test. | n/a | n/a | minor (reviewer minor) | n/a | n/a | n/a | R |
| D8 | Maintainability nits: `loadProfileArgs` returns a 4-tuple, `asciiLower` uses a nested-loop fast path, and the tests ignore `os.WriteFile` errors (`_ = os.WriteFile(...)`, 2 places). | n/a | n/a | minor (reviewer minor) | n/a | n/a | n/a | R |
| D9 | Exit status 3 is not listed in `docs/`. **Refuted, not a defect.** The spec defines exit 3 and forbids editing `docs/`, and it is the same in all six cells. | n/a | not a defect (reviewer minor) | n/a | n/a | n/a | n/a | spec |
| D10 | `homelab_fixture_is_clean` passes silently when the fixture cannot be loaded (`if let Ok(p)`). No other cell has a silently passing test (grep for `t.Skip`, `if let Ok`). | n/a | n/a | n/a | minor (reviewer minor) | n/a | n/a | R |
| D11 | The 2 s bound in `run_bounded` (K14) could flake. **Not a defect** under the timing rule: it asserts the contract's own K14 bound, and lint answers those inputs in ≤ 0.01 s. go-opus1, go-opus2, rust-opus2 and rust-sonnet1 have the same kind of K14 check, and none is counted. | n/a | n/a | n/a | not a defect (reviewer minor) | n/a | n/a | P5, raw/test-timing.txt |
| D12 | A stray `tools/__pycache__` file was left in the implementer workspace. **Not a defect of the change:** it is not in `diff.patch`. | n/a | n/a | n/a | not a defect (reviewer minor) | n/a | n/a | R |
| D13 | `linear_on_many_labels` asserts < 2 s. **Not a defect** under the timing rule: the whole test takes 0.09 s in a debug build (6 runs), a margin above 20×. | n/a | n/a | n/a | n/a | not a defect (reviewer minor) | n/a | raw/test-timing.txt |
| D14 | `json_line` is a hand-written serializer that duplicates the envelope shape. A unit test checks byte identity with `Envelope::to_line`. | n/a | n/a | n/a | n/a | minor (reviewer minor) | n/a | R |
| D15 | `destination_indexes` removes repeats only between neighbours. It relies on places being in non-decreasing destination order, which only a `debug_assert` enforces. All five rules meet this today (P1 400/400). | n/a | n/a | n/a | n/a | minor (reviewer minor) | n/a | R, P1 |
| D16 | `lint_large_input_is_fast` asserts < 2 s in a debug build that spawns the binary. Observed 0.26 to 0.27 s (6 runs), about 7.5× margin, so it is minor under the timing rule. | n/a | n/a | n/a | n/a | n/a | minor (reviewer minor) | raw/test-timing.txt |
| D17 | Two non-echo needles in `lint_value_non_echo` (`lab.example`, `aman`) never occur in that test's profile, so they cannot detect a leak. The real values are covered. | n/a | n/a | n/a | n/a | n/a | minor (reviewer minor) | R |

### Ratings that differ from the cell reviewer

- **go-opus1:** D1 added (minor; missed).
- **go-opus2:**
  - D1 added (minor; missed).
  - D3: minor → pre-existing. It is show's own argv semantics, and the spec asks lint to match show.
  - D9: minor → not a defect.
- **go-sonnet1:** D3 added (pre-existing; missed).
- **rust-opus1:**
  - D6 added (minor; missed).
  - D11: minor → not a defect (timing rule).
  - D12: minor → not a defect of the change.
- **rust-opus2:**
  - D4 added (minor; missed).
  - D5 added (minor; missed).
  - D6 added (minor; missed).
  - D13: minor → not a defect (timing rule).
- **rust-sonnet1:** none. All four of its reviewer's items are confirmed as minor.

The reviewers listed no blocker or major, and this review found none.

### Observations recorded but not counted as T2 defects

- **K15 headroom.** On the worst 1 MiB profile found (B2: 262,112 labels alternating `a`/`A`,
  524,224 key paths, 13.6 MB of JSON), lint's peak RSS was:
  - rust-sonnet1 205 MiB and rust-opus1 190 MiB;
  - go cells 117 to 124 MiB and rust-opus2 117 MiB;
  - `profile show` on the same file: 95 MiB in Rust, 46 MiB in Go.

  All are within the 256 MiB bound. rust-sonnet1 varied from 181 to 205 MiB on B/B2 across runs, so
  two Rust cells keep about 20 % headroom. B2 is close to the maximum key paths per MiB: each label is
  in at most one rule 4 and one rule 5 finding, and `"a",` is the shortest repeatable label.
- **Go parser guard, pre-existing.** Go rejects schema-valid 1 MiB profiles that have more than about
  10,900 destinations with SCHEMA_INVALID ("profile structure exceeds 65536 keys and containers"). It
  does this in show and lint alike (P7 cases D to G), and K15 allows it. Rust accepts these profiles.
  Cases H to J exercise Go lint on 8,000 to 10,000 destinations.
- **`--file /dev/stdin` with stdin redirected from a regular file.** Go show and lint answer
  USAGE_ERROR, while Rust show and lint accept the profile. This is a pre-existing language difference
  in the shared loader, and every cell's lint matches its own show (P5).
- **Go's `flag` package accepts more forms than Rust's parser.** Go accepts `--json --json`,
  `--file P --file P`, `-json`, `--json=true`, `--file=P` and a trailing `--`, and Rust refuses them. Each
  cell's lint matches its own show (P6).
- **Hidden check `T2.usage_errors` does not discriminate.** It passes on both baselines, which already
  answer `profile lint ...` with exit 2 USAGE_ERROR (`raw/hidden-T2/base-*.console.txt`). Lint's usage
  handling is covered here by P6.

## Method

1. **Inputs.** The implementer `diff.patch` of every cell:
   - `runs/<cell>/implementer-out/diff.patch`;
   - for rust-sonnet1, `runs/T2-rust-sonnet1/out/diff.patch`.

   `scripts/patch_equiv.py` checked that each `diff.patch` has the same files and the same multiset of
   added and removed lines as the evaluator's `change.patch`. All six are equivalent
   (`raw/build/patch-equiv.txt`). The base commits come from `hidden-pack/BASE.json`: Go 84c7665 and
   Rust 001a791. Their `git archive` tree digests equal BASE.json (`9ee4b916…`, `58c9fef5…`).
2. **Builds** (`scripts/build_cells.sh`). There is one scratch copy per language. Before each cell, the
   sources are reset from `git archive <base> prototypes/<lang>` and the cell patch is applied with
   `git apply` (rc 0 for all six). Each tree is then built with the prototype's own `build.sh`, offline
   (`GOPROXY=off`, `CARGO_NET_OFFLINE=true`). Rust used the repository's pinned `cargo-zigbuild`, copied
   into the copy's `target/tools/bin`, and kept `target/` between cells. Every `build.sh` built all four
   targets: darwin-arm64, linux-x64, linux-arm64 and windows-x64 (`raw/build/*-summary.txt`). The
   summaries were written by the first version of the script, which named both baselines `base`. The
   Rust baseline binary was renamed to `base-rust`, and the Go baseline was rebuilt as `base-go`.
3. **Hidden pack.** `hidden-pack/run.py --task T2` was re-run on the eight rebuilt darwin binaries, with
   the sandbox in scratch (`raw/hidden-T2/`). All six cells pass 12/12, and both baselines pass 1/12
   (`T2.usage_errors`).
4. **Probes.** `scripts/probe.py` was run through `scripts/run_probes.sh` with one invocation for all
   groups (`raw/probe-results.json`, console in `raw/probe-console.txt`, matrix in
   `raw/probe-matrix.md`). Every probe runs every build with the same argv, inputs, minimal environment
   (PATH, and HOME and TMPDIR in scratch; no `SSH_AUTH_SOCK`) and timeout. The baselines have no
   `profile lint`, so they take part only where `profile show` or other commands are probed: P5 and P6
   (show column), P7 (show), P12, and P3 as a negative control (0/12).
5. **Reference model.** The model in `probe.py` was written from `specs/T2.md`. On all 400 random
   profiles it was cross-checked against the hidden pack's `t2/lint_ref.py`, and the two agree
   (`ref_models_agree: true`).
6. **Code reading.** Every non-test hunk and the relevant test hunks of the six diffs were read. Each
   D-item above that says R was confirmed in the diff text.

### Build provenance (darwin-arm64)

| build | sha256 (this rebuild) | evaluator's hidden-test binary | same? |
|---|---|---|---|
| base-go | f812084ff36d8f04d5f279ad466b1207b23fa20a1b39d0e57f56fa16a7bf9a5d | bdfd64a2… (BASE.json, go1.27.1) | no: toolchain go1.27.2 here |
| base-rust | f9a3ec8b46832bc76a7ea33489634e5316568c7d350d269a66b39bf65d5a8b18 | f9a3ec8b… (BASE.json) | yes |
| T2-go-opus1 | 5cdb5876e5f8b5f8c137a0b82af1561f387512ef14e077f4459965cf05fc6b7c | 8743d6ed… (go1.27.1) | no: toolchain |
| T2-go-opus2 | 4eca9220c24aaba9b0626700dba6482f03cd425d5ad2986ab5c43536933c220b | 97dcb086… (go1.27.1) | no: toolchain |
| T2-go-sonnet1 | 4ec6e11c045333f6f4079293883e4bb749d94d792e48a387395a0ab6a6c6345e | 4ec6e11c… (go1.27.2) | yes |
| T2-rust-opus1 | e73c91bdd257d2df3d1019889a690f47db2f08b4e2c78a6a151f98510622cb62 | e73c91bd… | yes |
| T2-rust-opus2 | e21a23ef2e30452ece36c43e501cad873c2f38f69dfe1ed2fb31a44ee8c1b42f | e21a23ef… | yes |
| T2-rust-sonnet1 | 3ae21efee251e0ff1bb7066888021545ecca6606d605439faead521be354af54 | 3ae21efe… | yes |

The three Go differences are explained by the toolchain. `go version` reports go1.27.2 for every
rebuild here, while the evaluator's opus1 and opus2 harness records and the repository's base binary
report go1.27.1 (`raw/build/go-toolchain.txt`). go-sonnet1 was evaluated with go1.27.2 and is
byte-identical. The sources are equivalent (step 1), and the rebuilt Go binaries pass the hidden T2
pack 12/12. Toolchains: go1.27.2 and rustc/cargo 1.99.0 (the pinned version).

## Probes (identical for all six cells)

| group | what it checks | gap in the hidden pack it targets |
|---|---|---|
| P1 | 400 random schema-valid profiles (seed 20261010). They combine host case variants (including Kelvin sign, long s, dotless/dotted i, NFC/NFD é), ports (absent, 1, 21, 22, 80, 443, 1023, 1024, 2222, 65535), root near-misses (including a Cyrillic look-alike) and up to 8 labels from a pool of ASCII and Unicode case pairs, `ß`/`SS`, empty labels and CJK. Ids need JSON escaping (quote, backslash, U+2028, U+200B, emoji). Each `--json` result is compared with the reference: exact `data`, envelope members, exit/code, one line ending in `\n`, no ESC. Plain-mode exit is checked on every fifth profile. | ordering and grouping beyond 5 fixtures; JSON escaping of ids |
| P2 | One profile with interleaved groups for every rule, run 40 times. | Go map-order nondeterminism |
| P3 | 12 hand-made edge profiles: an exact repeat plus a case variant in one destination (rule 4 and rule 5 together), `["",""]`, NFC vs NFD, explicit `destinations = []`, three spellings with repeats, interleaved rule 1 groups and rule 5 sets, rule 4 order, port boundaries, root look-alikes, escaped ids, and Kelvin/long-s next to an ASCII pair. | rule interactions |
| P4 | Distinctive values, including canary-prefixed ones made at run time, in name, alias, host, account, labels and nested `[meta]`. A findings profile and a clean profile are each run with and without `--json`. Stdout and stderr are searched, and so is whether ids appear without `--json`. | canary-prefixed values in valid profiles |
| P5 | 43 inputs, `profile show` vs `profile lint`: exit, state, code, key_path, ≤ 2 s, plain exit and value echo. The inputs include 0-byte, exactly 1 MiB, 1 MiB+1, BOM, CRLF, invalid UTF-8 (comment and label), NUL, duplicate key, port string, port 65536 and −1, labels with the wrong type, K2 DEL/C1/ESC, a canary-prefixed value in a forbidden or unknown key, deep arrays and inline tables (K15) and other schema errors. They also include a mode-000 file, a file in a mode-000 directory, a FIFO, a symlink to a FIFO, a symlink to a regular file, a dangling symlink, a symlink loop, a directory with a trailing `/`, `/dev/null`, `/dev/zero`, `/dev/stdin` (pipe held open, and a regular file), a bound but non-listening Unix socket file, an empty path, a path longer than PATH_MAX and a non-UTF-8 missing path. | non-regular and odd inputs beyond the 11 hidden ones |
| P6 | 23 argv templates, show vs lint (exit, JSON present, code), with a cwd that holds files named `--json` and `-`. | usage handling (the hidden check does not discriminate) |
| P7 | 11 schema-valid profiles up to 1 MiB built to maximise lint work. Wall time and peak RSS (`wait4`) are taken as the worst of 5 runs, for show, lint `--json` and lint plain, and the output is compared with the reference. | K15 for lint (not in the hidden pack) |
| P8 | Stdout is a pipe whose reader already closed, with and without `--json`. Cases: clean, findings, about 13 MB of findings, schema error and usage error. | K12 closed-stdout parity for lint |
| P9 | Snapshot of the cwd, the profile directory, HOME and TMPDIR before and after lint in both modes. | writes outside cwd and profile dir |
| P10 | Stdin is a pipe whose writer stays open. | lint must not read stdin |
| P12 | 21 existing commands, each cell vs its own rebuilt baseline, byte-for-byte: show on fixtures, usage errors, `agent list`, `run`, `tui` without a tty, `version`, `--help`. | "every other existing behaviour is unchanged" |

### Probe matrix

| probe | go-opus1 | go-opus2 | go-sonnet1 | rust-opus1 | rust-opus2 | rust-sonnet1 |
|---|---|---|---|---|---|---|
| P1 random profiles vs reference model (400; 343 with findings) | 400/400 | 400/400 | 400/400 | 400/400 | 400/400 | 400/400 |
| P1 plain exit = `--json` exit (80 runs) | yes | yes | yes | yes | yes | yes |
| P1 stderr empty on success | yes | yes | yes | yes | yes | yes |
| P2 one distinct, correct output in 40 runs | yes | yes | yes | yes | yes | yes |
| P3 edge profiles | 12/12 | 12/12 | 12/12 | 12/12 | 12/12 | 12/12 |
| P4 profile values echoed (4 runs) | none | none | none | none | none | none |
| P4 ids printed without `--json` | no | no | no | no | no | no |
| P5 inputs (43) where lint ≠ show, > 2 s or echo | 0 | 0 | 0 | 0 | 0 | 0 |
| P6 argv templates (23) where lint ≠ show | 1 (`--file --json`, D2) | 0 | 0 | 0 | 0 | 0 |
| P7 worst wall / peak RSS on 11 cases; K15 | 0.11 s / 117 MiB, within | 0.11 s / 122 MiB, within | 0.10 s / 124 MiB, within | 0.17 s / 190 MiB, within | 0.09 s / 117 MiB, within | 0.16 s / 205 MiB, within |
| P7 cases where lint ≠ reference | 4 (D–G: show rejects too, Go guard) | 4 (same) | 4 (same) | 0 | 0 | 0 |
| P8 closed-stdout exit parity | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| P9 files changed | 0 | 0 | 0 | 0 | 0 | 0 |
| P10 stdin pipe held open | exit 3, 0.00 s | exit 3, 0.00 s | exit 3, 0.00 s | exit 3, 0.00 s | exit 3, 0.00 s | exit 3, 0.00 s |
| P12 commands differing from the baseline | 11 (usage line + D1) | 11 (usage line + D1) | 11 (usage line + D1) | 11 (usage line) | 11 (usage line) | 11 (usage line) |

P12 detail: in every cell, each differing command differs only by the added
`heimdall-proto profile lint --file <path> [--json]` usage line (stderr; Rust `--help` stdout). The Go
cells additionally have the D1 message text. This was checked by removing those two strings and
comparing again. Per-case P7 numbers are in `raw/probe-matrix.md`.

## Limitations

- **darwin-arm64 only.** The probes and the hidden-pack re-run ran on darwin-arm64. linux-arm64 rests on
  the evaluators' hidden and harness runs, and Windows was not exercised; it is `blocked` for lack of a
  native Windows host. The full 139-check G02 harness and the cells' complete unit suites were not
  re-run here. Two Rust tests were re-run for timing only.
- **Go toolchain.** The Go opus1 and opus2 binaries probed here were built with go1.27.2, not the
  evaluator's go1.27.1. Source equivalence and a 12/12 hidden re-run were checked, but these are not
  the evaluated bytes. The Rust and go-sonnet1 binaries are the evaluated bytes.
- **No-write evidence is a snapshot.** P9 watches four directories. A write elsewhere would not be seen,
  and no syscall trace was taken (SIP prevents dtrace without root). By code reading, lint has no
  write call in any cell.
- **Random testing is sampling.** P1 is 400 profiles from one seed. Its pools target the
  case-folding and ordering rules, but they do not prove correctness.
- **RSS figures** come from `ru_maxrss` via `wait4`. They vary by about 10 % between runs; the table
  gives the worst of 5.
- **Rating judgment.** The two tie-break rules (usage text, timing) are this reviewer's choices. They
  were fixed before rating and applied to all six cells. With different rules, D1, D11, D13 and D16
  would move between minor and not counted, and no other rating would change.

## Reproduce

```sh
REPO=<repository root>; SCR=<scratch dir>
sh  tests/evidence/artifacts/g02-r4/x2/cross-review/T2/scripts/build_cells.sh "$REPO" "$SCR" go   base T2-go-opus1 T2-go-opus2 T2-go-sonnet1
sh  tests/evidence/artifacts/g02-r4/x2/cross-review/T2/scripts/build_cells.sh "$REPO" "$SCR" rust base T2-rust-opus1 T2-rust-opus2 T2-rust-sonnet1
sh  tests/evidence/artifacts/g02-r4/x2/cross-review/T2/scripts/run_probes.sh "$REPO" "$SCR" P1,P2,P3,P4,P5,P6,P7,P8,P9,P12 --reps 5
python3 -I tests/evidence/artifacts/g02-r4/x2/cross-review/T2/scripts/summarize.py "$SCR/probe/out/results-P1-P2-P3-P4-P5-P6-P7-P8-P9-P12.json"
```

Script sha256 (as used for the recorded run):

- build_cells.sh: d1abb4d0…
- patch_equiv.py: f464f7f3…
- probe.py: 70f646fe…
- run_probes.sh: a33a4a62…
- summarize.py: 47be6072…

Raw outputs are redacted: canary-prefixed values, the scratch path and the home path are replaced by
placeholders. A scan of `raw/` for the home path and the canary prefix finds none.

## Scratch and disk

The scratch root `~/.local/share/heimdall-m00/r4-scratch/M00-T05-r4-x2-xrev-T2/` held the build trees,
the Rust `target/`, the binaries and the probe work dirs. Its size over the task:

- before: 0 (created empty);
- at the end, before deletion: 836 MiB (work trees and Rust `target/` 797 MiB, binaries 23 MiB, probe
  fixtures 16 MiB);
- after: deleted with `rm -rf` (rc 0; the directory no longer exists).

Nothing was built inside the repository; `prototypes/rust/target` was 1.2 GB before and after.

No file was written outside the scratch root and this directory, apart from two things. `probe.py` created short-lived `/tmp/xrT2-*` socket directories and
removed them. The toolchains used their normal caches (Go build cache; the cargo registry was used
offline).
