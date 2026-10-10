# X2 T3 cross-review: one rubric, six cells (M00-T05-r4-x2-xrev-T3)

Status: `implemented_unverified`. Every observation below was executed and recorded on darwin-arm64.
The classification applies the rubric given to this task.

Two independent checks were made (`raw/independent-checks.txt`):
- A separate agent decoded the decisive byte stream (finding N1) by hand. It was given only the
  screen and the bytes, and it reached the same result.
- A separate adversarial reviewer re-checked the classification and the evidence. It confirmed N1
  and found inconsistencies in how defects were cross-applied. All of them were accepted and are
  reflected below.

Nobody has independently re-run the full probe set.

## Why

X2 gave task T3 (`specs/T3.md`: match underline, `?` help overlay, selection kept across filter
edits) to three Go and three Rust implementers. All six pass the hidden tests. Each cell had its own
code reviewer, so the severities in `results.json` (`cells[].review.defects`) came from six
different reviewers.

This review does four things:
- reviews the six diffs side by side;
- runs the same TUI probes on all six builds and on both baselines;
- confirms or refutes each reviewer-listed defect by observation where possible;
- classifies every (cell, defect) with one rubric, applied the same way to both languages.

It decides nothing about the languages.

## Builds (provenance)

The base trees are `git archive` copies of the pinned base commits. Their tree digests equal
`BASE.json`: Go `9ee4b916…`, Rust `58c9fef5…` (`raw/build/digests-and-sizes.txt`). There is one
scratch copy per language, reset between cells. Each cell's implementer `diff.patch` was applied
with `git apply`, and all six apply cleanly. Each tree was built with its own `build.sh`. For Rust,
`CARGO_ZIGBUILD` was the repository's `target/tools/bin/cargo-zigbuild`, copied into the scratch
target dir. All eight builds exit 0 with all 4 targets built (`raw/build/targets.txt`,
`raw/build/provenance-*.txt`). Only the darwin-arm64 binary was used.

Source equivalence: for every cell, base + implementer `diff.patch` and base + the evaluator's
`change.patch` give the same tree (`diff -r` exit 0; `raw/build/srccheck.txt`).

| build | source | darwin-arm64 sha256 (built here) | equals the evaluated/pinned binary? |
|---|---|---|---|
| base-go-pinned | repository `prototypes/go/dist` (not rebuilt) | `bdfd64a2f5a0…` | yes (pin; go1.27.1, 5212000 bytes) |
| base-go | 84c7665 | `f812084ff36d…` | no: go1.27.2 here (5212224 bytes); the pin is go1.27.1 (same as the T1 calibration) |
| T3-go-opus1 | 84c7665 + out/diff.patch | `3cb494cec404…` | no: the evaluated binary is `9ad3ce9cda53…`, 5228592 bytes; here 5228816. +224 bytes is the base's go1.27.1→go1.27.2 gap, so a toolchain difference is the inference |
| T3-go-opus2 | 84c7665 + out/diff.patch | `87f81fb90346…` | yes |
| T3-go-sonnet1 | 84c7665 + implementer/diff.patch | `9eb467768617…` | yes |
| base-rust | 001a791 | `f9a3ec8b4683…` | yes (pin) |
| T3-rust-opus1 | 001a791 + out/diff.patch | `9c6606190083…` | yes |
| T3-rust-opus2 | 001a791 + implementer-out/diff.patch | `7287e8c691f4…` | yes |
| T3-rust-sonnet1 | 001a791 + implementer/diff.patch | `a49cc5b0a443…` | yes |

Only go1.27.2 is installed, so the pinned go1.27.1 base was probed as well. It gives the same result
as the go1.27.2 base in every probe.

**Hidden suite on these binaries** (`raw/hidden-rerun.json`):
- Run 1, under `/usr/bin/python3` 3.9.6: 16/17 pass for all six cells.
  `T3.k17_filter_latency` errored for lack of `tomllib`. That was this task's invocation error, not
  a product result.
- Run 2 re-ran only K17 under python3 3.14.8: it passed for all six. p95: go 17.5 / 18.3 /
  18.4 ms, rust 4.2 / 3.7 / 5.0 ms.

## Method

**Terminal.** The probes use the harness 2.4.2 pty session (`tests/g02/harness_lib.py`, byte-equal
to the hidden pack's vendor copy) with pyte 0.8.2, plus the hidden T3 tests' input normalisation:
- SGR colon forms are normalised;
- CSI `…m` with a private prefix (XTMODKEYS) is removed before pyte sees it.

The environment is `TERM=xterm-256color` unless stated, with a private HOME/TMPDIR and no
`SSH_AUTH_SOCK`. Profiles are disposable files in a fresh /tmp sandbox per session.

**Emulator fixes (applied to every build alike).** `scripts/csi_audit.py` lists every CSI sequence
each of the 9 builds emits for one 15-key sequence (CJK profile, 60x10) under 7 TERM values
(`raw/csi_audit.txt`):
- Go builds emit HPA (`CSI Pn \``) under `screen`, `tmux-256color`, `linux` and `xterm-kitty`.
  go-opus2 is the exception: its full repaint avoids it.
- go-opus1, go-opus2 and go-sonnet1 also emit REP (`CSI Pn b`) under `tmux-256color` and
  `xterm-kitty`. The base never does in this sequence.

pyte 0.8.2 implements neither. It binds HPA to `'` instead of `` ` ``, and it has no REP. The first
probe run therefore showed Go rows corrupted under those TERM values, and that was an emulator
artifact. `probe_lib.Session` now implements HPA and REP as ECMA-48/xterm define them, and with
that all those TERM rows pass.

The first run also hit an oracle bug (IndexError) and is superseded. Its outputs were not kept. In
the audit, Rust emits only CUP, ED and SGR. Apart from the tab-stop reset `CSI ? 5 W`, no other
unimplemented sequence appeared in the audit. The P01-P17 sessions themselves were not audited.

**Oracle** (`scripts/probe_lib.py`, the same for every build). After every key or resize it waits
up to 2 s for the expected screen, settles 0.25 s, and checks again.

- **Not in help:** the list rows must be a contiguous run of the expected rows, starting at row 0,
  with nothing else on screen. Each expected row is:
  - the prefix `> ` or two spaces, then the alias;
  - at width 50 or more, also `  account@host:port`;
  - the whole row cut to the width by display cells.

  The run must hold the expected selection and be a full window. Exactly the cells of the first
  case-insensitive match in the alias (and in the host when shown) are underlined, and no other
  cell is. The status row must equal the language's own status text, cut to the width.
- **In help:** the nine help lines appear in order, one per row, when they fit; otherwise a clipped
  prefix of them. No alias may appear in the help area.
- **Selection:** the expected selection follows spec part C for the cells and K9 for the baselines.
  Baselines are expected to underline nothing and have no help. The window position is left free,
  because scrolling policies differ by design.
- **Matching:** case-insensitive matching uses each language's filter rule. Go uses simple
  rune-by-rune case mapping; Rust uses `str::to_lowercase`, which includes final sigma.
- **Wide characters:** a wide character whose half is overwritten vanishes, as in xterm (the
  harness `render_cells` rule).
- **Exits:** check the exit status, the `SELECTED` line, and terminal restore. Restore means the
  alternate screen is left, the cursor is shown, termios is restored, and nothing disallowed
  follows the restore.

**Probes** (`scripts/probes.py`, all nine builds):

| ID | what | sizes |
|---|---|---|
| P01 | homelab: selection moves, CJK filter, mixed case, Enter/Esc, `?` toggles, re-entering filter mode | 80x24, 50x8, 49x8, 30x6, 20x5 |
| P02 | CJK profile (`東京-サーバー-本番`, `名古屋-backup-東`, …): CJK and ASCII filters, Backspace to empty, navigation | 80x24 … 20x5 (7 sizes) |
| P03 | long names: matches past or straddling the cut, wide characters at the cut, host-only matches | 80x10 … 20x5 (7 sizes) |
| P04 | help: 10 ignored keys, resize 40x10/20x5/12x3/80x24 while open, Esc keeps the filter, `?` as filter text, Ctrl-C | 80x24 (cells) |
| P05 | tiny sizes 1x1, 2x5, 5x2, ioctl 0x0, back to 20x5 and 80x24, with help open and a CJK filter | homelab, CJK |
| P06 | exit paths with help open: SIGTERM, SIGHUP, `kill -INT`, pty hangup, Ctrl-C, `q` ignored, Esc + Enter; SIGTERM in filter mode; CJK + help at 20x5 | 80x24, 20x5 |
| P07 | NO_COLOR=1: P01/P02 sequences plus a whole-session colour-SGR scan | 80x24, 20x5, 40x10 |
| P08 | 16 TERM values (xterm-256color … xterm-ghostty, dumb, unset): `/a`, Enter, q | 80x24 |
| P09 | several keys in one write: navigation, edits, help, ignored keys; large-100 navigation plus edits in one batch | 80x24, 80x8 |
| P10 | large-100: selection at row 90, edits that keep it, Backspace to wide, 40 Up, `-db`, resize 80x5 and back | 80x24, 80x8, 20x5 |
| P11 | `cafe`+U+0301, `ΟΔΟΣ` (`ς`, `σ`), `İstanbul` (`i`), `ＦＵＬＬ` (`ｆ`, `ＦＵ`); combining marks ignored in the row comparison (see P15) | 80x24, 40x12 |
| P12 | ZWJ emoji, RLO (U+202E), ZWSP aliases. pyte stops drawing at these, so only the process state is judged; the last bytes are recorded | 80x24 |
| P13 | help open, resize, close: no residue | 80x24/30x6, 21x6/20x5/40x10 |
| P14 | the selected row disappears and reappears; empty results; Enter and `?` with nothing shown | 80x24, 20x5 |
| P15 | observation: does the U+0301 accent survive the first frame, an `e` highlight that splits it, and Esc? | 80x24 |
| P16 | seeded random walk, 6 runs x 120 keys with resizes, homelab and CJK profile | mixed |
| P17 | fresh start, `/`, one filter character, Backspace: 15 characters x 3 sizes x 2 profiles = 90 variants | 80x24, 40x10, 20x5 |

The P16 key pool depends on the simulated mode. `?` opens help only in the cells, so the walks of
cells and baselines diverge after the first `?`. P16 counts are not like-for-like across that
boundary.

## Probe matrix

`pass`, `FAIL n` (n failing steps), `skip` (not applicable). P16 and P17 show failing/total. The
per-step records are in `raw/probes/<build>.json` (screen and underline columns on every failing
step) and `matrix.json`, with a compact `matrix.md`.

| probe | variant | base-go-pinned | base-go | go-opus1 | go-opus2 | go-sonnet1 | base-rust | rust-opus1 | rust-opus2 | rust-sonnet1 |
|---|---|---|---|---|---|---|---|---|---|---|
| P01 | homelab, 5 sizes (each) | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | CJK profile, 7 sizes (each) | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P03 | long names, 7 sizes | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P04 | help behaviour | skip | skip | pass | pass | pass | skip | pass | pass | pass |
| P05 | tiny sizes, homelab | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P05 | tiny sizes, CJK | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P06 | `kill -INT` with help open | FAIL 1 | FAIL 1 | FAIL 1 | FAIL 1 | FAIL 1 | pass | pass | pass | pass |
| P06 | the other 8 exit-path cases | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P07 | NO_COLOR homelab 80x24 and 20x5 (each) | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P07 | NO_COLOR CJK 40x10 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P07 | no colour SGR in any NO_COLOR session | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | 14 TERM values (xterm-256color … xterm-ghostty) | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=dumb, TERM unset (each) | pass | pass | FAIL 2 | FAIL 2 | FAIL 2 | pass | pass | pass | pass |
| P09 | key batches, both | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P10 | large-100 scroll, 3 sizes | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P11 | Unicode case, 2 sizes (each) | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | FAIL 1 |
| P12 | zero-width/bidi, process state | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P13 | help residue after resize, 2 variants | skip | skip | pass | pass | pass | skip | pass | pass | pass |
| P14 | disappear/reappear, 2 sizes | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P15 | accent kept? (first frame / `e` highlight / after Esc) | no/no/no | no/no/no | no/no/no | no/no/no | no/no/no | yes/yes/yes | yes/yes/yes | yes/yes/yes | yes/yes/yes |
| P16 | random walk, runs with a failing step | 4/6 | 4/6 | 3/6 | 0/6 | 3/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| P17 | one-character filter, variants failing | 0/90 | 0/90 | 4/90 | 0/90 | 4/90 | 0/90 | 0/90 | 0/90 | 0/90 |

What the failures are:
- **P01, P05 CJK, P07 homelab, and every P16 failure (Go builds only):** the status line loses a
  double-width filter character. In P01 it happens when filter mode is re-entered with `京` kept:
  the screen shows `1/3 /` instead of `1/3 /京`.
- **P02, P07 CJK, P17:** a list row is corrupted (N1).
- **P11:**
  - go-opus1 and go-sonnet1: the status line shows `1/5 / Ｕ` instead of `1/5 /ＦＵ`. Both baselines
    pass this identical sequence, so it is part of N1.
  - rust-sonnet1: no underline for the filter `ς` (D19).
- **P08:** no underline at all (N2).
- **P06:** `kill -INT` exits 1 instead of 130 (P-B).

## Findings the cell reviewers did not report

**N1 (go-opus1, go-sonnet1): list rows and the status line are corrupted when the match underline
changes next to double-width text.**

Bubble Tea's cell-diff renderer (ultraviolet, pinned pseudo-version) has a cursor-position bug.
When the cursor sits on the right half of a double-width character, it emits no move for the next
column, so the next cell is written one column short. The go-opus2 implementer described this bug.
On an xterm-compatible terminal the short write erases the wide character it lands on, and the
rest of the run shifts. go-opus1 and go-sonnet1 embed the underline as SGR in the row strings, so
every filter edit restyles single cells in the middle of rows that contain CJK text. That triggers
the bug far more often than the baseline does.

Observed (`raw/repro/`):
- **R1, the shipped `homelab.toml` at 20x5, typing `/東京`:** `> vps- 京` instead of `> vps-東京`.
  The frame before leaves the cursor at column 8 (1-based). `CSI 1 d` (VPA) keeps that column, so
  `京` lands on the right half of `東`. On homelab, the same keys render correctly at 40x10 and
  80x24 (R5, R6).
- **R2, CJK profile at 80x24, `/-`:** `  名古 -bbackup-東` instead of `  名古屋-backup-東`. P02 and P17
  show a corrupted row at every width tested, 80 down to 20. At 21x6 and 20x5 the corruption hits
  rows 0-1, including an ASCII row: `> 東 --サーバー-本番`, `  la-sserver`.
- **R3, `/屋` then Backspace at 40x10:** `> 名 屋 -backup-東`. Removing an underline also triggers
  it.
- **P11:** the status line loses `Ｆ`, where both baselines render the identical sequence
  correctly.

In P17, 4 of 90 variants corrupt a row on each of these two cells. A variant is a one-character
filter or the Backspace that removes it. The baselines, go-opus2 and Rust show 0/90.

The hidden tests miss it for two reasons. homelab has a single CJK row, and P17 shows no failure
for its one-character filters. The tests never edit the filter at 20x5, which is where R1
appears.

go-opus2 shows that it was avoidable within the task: it forces a full repaint (`tea.ClearScreen`)
while double-width text is on screen. No probe here shows list-row or status-line corruption on
go-opus2.

The independent decode (`raw/independent-checks.txt`) reaches the same row 2 from the R2 bytes by
xterm rules, without pyte. The adversarial reviewer recomputed R1's column from the bytes.

Rating: **major**. It corrupts the list text (contract §5 row content) and the status line, for a
plausible input: CJK aliases, which are in the fixture and in the spec's test domain, with a short
filter, or the shipped fixture at 20x5. The hidden tests do not catch it, and it is new relative to
the same-language baseline under identical keys.

**N2 (go-opus1, go-opus2, go-sonnet1): no underline when TERM=dumb or TERM is unset.** The Go
colour profile becomes NoTTY, and all attributes are dropped. Rust underlines in both cases. The
go-opus1 and go-opus2 implementers documented this as a limitation; no reviewer listed it. Rating:
**minor** (unusual input).

**Also seen, all pre-existing (present in the same-language baselines):**
- **P-A, a status-line case of the same renderer bug.** When filter mode is re-entered with a CJK
  filter kept, both Go baselines emit identical bytes (`raw/repro/R4…`: `CSI 5 G`, `/京`, BS, EL),
  and the EL erases `京`. go-opus1 and go-sonnet1 show the same; go-opus2's repaint removes it.
- **P-B, `kill -INT` exits 1 on every Go build.** The terminal is restored. Every Rust build exits
  130.
- **P-C, Go drops zero-width code points.** Every Go build drops U+0301 from the display
  (`cafe-bar`, P15) and strips U+200B and U+202E (P12). Every Rust build keeps the accent,
  including through the underline split.
- **P-D, Rust passes bidi/zero-width code points through.** Every Rust build passes U+202E and
  U+200B to the terminal. Contract §9.2 says this is not gated.

## Rubric, as applied

- **blocker:** security-boundary breach (for example escape injection from profile data), secret
  disclosure, or loss of user data.
- **major:** violates an explicit spec or contract requirement, or crashes, hangs, corrupts the
  screen or leaves the terminal unusable, in an input or use a real user could plausibly hit, and
  the hidden tests do not catch it.
- **minor:** an unusual input, cosmetic output, a test or code-quality issue, or a behaviour the
  spec leaves open.
- **pre-existing:** present in the same-language baseline and not something the task asked to
  change. Recorded, not counted against the change.
- **refuted:** this review's label for a listed defect that is not a defect of the change, with
  the reason. Not counted.

Definitions used:
- *Plausible:* the shipped fixtures, CJK or ASCII aliases, terminals from 20x5 up, common TERM
  values (xterm*, screen*, tmux*, kitty, alacritty, ghostty, linux), and typing or pasting.
- *Unusual:* TERM=dumb or unset, Greek final sigma or Turkish dotted I in a filter, combining or
  zero-width characters, sizes below 20x5, and `kill -INT` from another process. These are this
  review's definitions, not part of the rubric. D19 depends on them: a reader who counts Greek
  aliases as plausible would rate D19 major, since spec part A requires the filter's own matching
  rule.
- *Cross-applied:* a defect one reviewer listed is checked in every cell and rated the same way
  wherever the same code pattern exists.

**Security:** no blocker in any cell.
- A control character in a profile value is rejected before the TUI starts, in all six cells
  (`SCHEMA_INVALID`, exit 2, key path only; `raw/build/k2-and-pyc-checks.txt`).
- The only sequences inserted are fixed SGR constants.
- Filter text is limited to printable characters in both languages.
- No canary or home path appears in any probe output.

## Defect catalogue

Reviewer-listed items, as generalised for cross-application:
- **D01** Go output wrapper that adds an SGR reset after XTMODKEYS, kept in product code for an
  emulator quirk.
- **D02** The wrapper `Write` return values on a short write or error.
- **D03** The highlight boundary splits a grapheme cluster (combining mark, ZWJ).
- **D04** pty/e2e tests pace keys with fixed sleeps or `read_for` gaps.
- **D05** An inaccurate comment in tests.
- **D06** go-opus2's repaint heuristic checks only the after-key state.
- **D07** The full-repaint workaround in product code, with no removal criteria.
- **D08** No unit test proves production installs the output wrapper.
- **D09** The REPORT names a different ultraviolet pseudo-version than `go.mod`.
- **D10** A vacuous "q ignored in help" assertion.
- **D11** No unit test for truncation inside an underlined span.
- **D12** The highlight matches sanitised runes while the filter matches raw ones.
- **D13** Render-time mutation of model scroll state; `refilter` uses the last frame's offset.
- **D14** The match is re-lowercased per row per frame.
- **D15** The pty-test VT model reads each SGR parameter alone (`38;5;4` would read as underline).
- **D16** The help lines are copied in a black-box test.
- **D17** A stray `tools/__pycache__/*.pyc`.
- **D18** The keep-selection lookup relies on sorted `shown` without an assertion (for rust-opus2,
  also a dense expression).
- **D19** The highlight lowercases per char while the filter uses `str::to_lowercase` (final sigma).
- **D20** The row format is duplicated without a test tying the copies together.
- **D21** The scroll-offset clamp has no unit test.

New in this review: **D22** go-sonnet1's help unit test compares against the product constant
`helpLines`, not an independent copy; plus **N1**, **N2** and **P-A..P-D** above.

## Per-cell classification

"Reviewer" is the cell reviewer's rating in `results.json`; "—" means the reviewer did not list it.
**Bold** marks a difference from the reviewer. Evidence: `obs` = observed here; `read` = code
reading.

### T3-go-opus1

| defect | reviewer | here | evidence |
|---|---|---|---|
| D01 `sgrSafeOutput` | minor | minor | read. obs: no stray sequences after restore (P06); all 14 real TERM values correct (P08) |
| D02 `Write` count on a short write | minor | minor | read |
| D03 SGR inside grapheme clusters | minor | minor | obs: Go drops U+0301 in every build including the baselines (P-C), so the split adds nothing visible; the ZWJ case cannot be drawn by pyte |
| D04 pty test sends keys after fixed 250 ms sleeps | minor | minor | read |
| D05 wrong comment in `TestHelpOverlay` | minor | minor | read |
| N1 corruption next to double-width text | — | **major** | obs: P02, P07, P11, P17, R1-R3 |
| N2 no underline with TERM=dumb/unset | — | **minor** | obs: P08 |
| D14 per-frame re-lowercasing | — | **minor** | read. K17 p95 17.5 ms |
| P-A status line, re-entering filter mode | — | pre-existing | obs: R4, identical bytes on both baselines |
| P-B `kill -INT` exits 1 | — | pre-existing | obs: P06 |
| P-C zero-width code points dropped | — | pre-existing | obs: P15, P12 |

### T3-go-opus2

| defect | reviewer | here | evidence |
|---|---|---|---|
| D06 repaint heuristic checks only the after-key state | minor | minor | obs: never failed in P01-P17 (720 random-walk keys included); the gap is real by reading |
| D01+D07 two workarounds in product code | minor | minor | read. obs: while a wide character is on screen, a key's bytes are CUP + ED + the whole frame (R1-R4); ASCII screens keep the cell diff |
| D08 production wiring of `pinnedSGROutput` untested | minor | minor | read: the e2e test passes `pinnedSGROutput{r.slave}` itself |
| D02+D09 `Write` returns 0 on error; REPORT 20261001 vs go.mod 20260703 | minor | minor | read |
| N2 no underline with TERM=dumb/unset | — | **minor** | obs: P08 |
| D04 e2e test sends keys after fixed 400/150 ms sleeps | — | **minor** | read |
| D14 per-frame re-lowercasing | — | **minor** | read. K17 p95 18.3 ms |
| D15 the test SGR parser splits on `;`/`:`, so `case "4"` | — | **minor** | read |
| D03 underline SGR at rune boundaries | — | **minor** | read. Same invisible effect as go-opus1 |
| P-B `kill -INT` exits 1 | — | pre-existing | obs |
| P-C zero-width code points dropped | — | pre-existing | obs |

P-A was not observed for go-opus2, because its repaint also covers the status line.

### T3-go-sonnet1

| defect | reviewer | here | evidence |
|---|---|---|---|
| D10 vacuous "q ignored" assertion | minor | minor | read. Confirmed: Quit is the zero value and `press` drops the cmd; go-opus1 and go-opus2 check the cmd |
| D11 no unit test for truncation inside an underlined span | minor | minor | read. obs: behaviour correct in P03 (7 sizes); go-opus1 and go-opus2 have such tests |
| D05 doc comment names `ulCells`, function is `ulText` | minor | minor | read |
| D12 sanitised-rune highlight | minor | minor | obs: unreachable. A control character is rejected at load in all six cells |
| N1 corruption next to double-width text | — | **major** | obs: P02, P07, P11, P17, R1-R3 (same bytes as go-opus1) |
| N2 no underline with TERM=dumb/unset | — | **minor** | obs: P08 |
| D14 per-frame re-lowercasing | — | **minor** | read. K17 p95 18.4 ms |
| D15 the test SGR parser splits on `;`, so `case "4"` | — | **minor** | read |
| D03 underline SGR at rune boundaries | — | **minor** | read |
| D18 `sort.SearchInts` relies on sorted `shown` (comment, no assert) | — | **minor** | read |
| D22 help unit test compares against the product constant `helpLines` | — | **minor** | read |
| P-A status line, re-entering filter mode | — | pre-existing | obs |
| P-B `kill -INT` exits 1 | — | pre-existing | obs |
| P-C zero-width code points dropped | — | pre-existing | obs |

### T3-rust-opus1

| defect | reviewer | here | evidence |
|---|---|---|---|
| D13 `render` mutates the model (`set_viewport`) | minor | minor | read. obs: window full and holding the selection in every P09/P10/P16 step |
| D14 `find_ci` re-lowercases per frame | minor | minor | read. K17 p95 4.2 ms |
| D15 pty test VT model reads each SGR parameter alone | minor | minor | read. obs: Rust emits `38;5;6` for cyan, so it is harmless today |
| D16 help lines copied in the pty test | minor | **refuted** | The nine lines are fixed by the spec, and an independent copy is the right oracle for a black-box test. Five of six cells carry one; go-sonnet1's lack of one is D22 |
| D03 spans split at char boundaries | — | **minor** | read. obs: the accent survives in P15; the ZWJ case cannot be drawn |
| D18 `binary_search` relies on sorted `shown` (no assert) | — | **minor** | read |
| D04 pty tests pace keys with fixed `read_for` gaps | — | **minor** | read. Both baselines' pty suites use the same style |
| P-D U+202E/U+200B passed through | — | pre-existing | obs: P12 |

### T3-rust-opus2

| defect | reviewer | here | evidence |
|---|---|---|---|
| D15 pty test SGR parsing per parameter | minor | minor | read |
| D17 stray `tools/__pycache__/inventory.cpython-314.pyc` | minor | **refuted** | The base `build.sh` runs `tools/gen_notices.py`, which imports `inventory`, so every build of the base writes it. The scratch tree built here had it; the evaluator's base copy had it too (`change.patch` line 1283). It is git-ignored. Not part of the change and not a defect (`raw/build/k2-and-pyc-checks.txt`) |
| D13 stale offset in one input batch | minor | minor | obs: P09 batches keep the selection visible in a full window; only the "same screen row" aim can be lost |
| D18 dense keep-selection expression, no `debug_assert` | minor | minor | read |
| D14 per-frame re-lowercasing | — | **minor** | read. K17 p95 3.7 ms |
| D03 spans split at char boundaries | — | **minor** | read. obs: P15 |
| D04 pty tests pace keys with fixed `read_for` gaps | — | **minor** | read |
| D20 row format duplicated | — | refuted (not added) | `row_line_text_matches_row_text` ties `row_line` to `row_text` at widths 20/49/50/80 |
| P-D U+202E/U+200B passed through | — | pre-existing | obs |

### T3-rust-sonnet1

| defect | reviewer | here | evidence |
|---|---|---|---|
| D19 final sigma: filter `ς` shows `ΟΔΟΣ`, no underline | minor (inferred) | minor | obs: P11 at both sizes; rust-opus1 and rust-opus2 underline `Σ`. See the *Unusual* definition |
| D20 `row_line` vs `row_text` | minor | minor | read: no test ties them |
| D21 scroll clamp has no unit test | minor | minor | read. obs: behaviour correct in P09, P10, P16 |
| D05 pty test comment describes the wrong step | minor | minor | read |
| D14 per-frame O(n·m) match with allocation | minor | minor | read. K17 p95 5.0 ms |
| D15 pty test VT model reads each SGR parameter alone | — | **minor** | read: `for part in params.split(";")` … `head == "4"` |
| D03 spans split at char boundaries | — | **minor** | read. obs: P15 |
| D04 pty tests pace keys with fixed `read_for` gaps | — | **minor** | read |
| P-D U+202E/U+200B passed through | — | pre-existing | obs |

### Counts (blocker / major / minor / pre-existing; refuted not counted)

| cell | blocker | major | minor | pre-existing | reviewer (blocker/major/minor) |
|---|---|---|---|---|---|
| T3-go-opus1 | 0 | 1 | 7 | 3 | 0/0/5 |
| T3-go-opus2 | 0 | 0 | 9 | 2 | 0/0/4 |
| T3-go-sonnet1 | 0 | 1 | 10 | 3 | 0/0/4 |
| T3-rust-opus1 | 0 | 0 | 6 | 1 | 0/0/4 |
| T3-rust-opus2 | 0 | 0 | 6 | 1 | 0/0/4 |
| T3-rust-sonnet1 | 0 | 0 | 8 | 1 | 0/0/5 |

The minor counts grew mostly from cross-applied code and test-quality items (D03, D04, D14, D15,
D18). They say little about behaviour. The behavioural differences between cells are:
- N1, major, in go-opus1 and go-sonnet1;
- N2, minor, in all three Go cells;
- D19, minor, in rust-sonnet1.

Every other probe passes in all six cells.

## Ratings that differ from the cell reviewer

- go-opus1: N1 added (major). N2 and D14 added (minor).
- go-opus2: N2, D04, D14, D15 and D03 added (minor).
- go-sonnet1: N1 added (major). N2, D14, D15, D03, D18 and D22 added (minor).
- rust-opus1: D16 changed from minor to refuted. D03, D18 and D04 added (minor).
- rust-opus2: D17 changed from minor to refuted. D14, D03 and D04 added (minor).
- rust-sonnet1: D15, D03 and D04 added (minor). D19 was inferred and is now confirmed by
  observation.

Of the 26 reviewer-listed defects, 24 keep their minor rating, and D16 and D17 are refuted.

## Limitations

- **darwin-arm64 only.** linux-arm64 and Windows were not probed. N1 lives in
  platform-independent renderer code, but that it occurs there is an inference.
- **Emulated terminal only.** No real terminal was driven. The wide-character overwrite follows
  xterm; terminals that leave half-glyphs would show N1 differently, not correctly. The column
  misplacement itself follows from the bytes on any ECMA-48 terminal.
- **pyte gaps.** Zero-width non-combining characters (ZWJ, RLO, ZWSP) stop pyte's drawing:
  - P12 judges only the process state;
  - the D03 ZWJ case could not be observed.

  HPA and REP were added to the emulator. Other sequences were audited only for one sequence per
  build and TERM.
- **go-opus1 binary.** It differs from the evaluated one by toolchain (inferred from size; go1.27.1
  is not installed). The source is identical.
- **Timing.** The oracle waits up to 2 s per key. Wrong frames that last less than the 0.25 s
  settle are not judged, including go-opus2's asynchronous repaint race (D06/D07).
- **Frequency of N1.** 4/90 one-character filter variants on the CJK profile, and on homelab only
  the two-key `/東京` at 20x5 among the sizes tried. Real-profile frequency is not measured.
- **Code-only items.** D01, D02, D04, D05, D08-D10, D13-D16, D18, D20-D22, and the ZWJ half of D03,
  were judged by reading.

## Files

- `scripts/`:
  - `build_cells.sh`: builds and provenance.
  - `srccheck.sh`: diff.patch vs change.patch.
  - `probe_lib.py`: driver, simulator, oracle and emulator fixes.
  - `probes.py`: P01-P17.
  - `summarize.py`: matrix.
  - `csi_audit.py`.
  - `repro_bytes.py` and `save_repros.sh`: R1-R6.
  - `k2_pyc_check.sh`.
- `raw/probes/<build>.json`: per-step records. Partial re-runs (P11, P13, P15, P16, P17) are merged
  and listed under `reruns`. Paths are redacted to `<home>`/`<sandbox>`.
- `raw/repro/R1-R6`: screen and bytes of the last key for all nine builds. R1-R4 were run twice with
  identical verdicts.
- `raw/independent-checks.txt`, `raw/csi_audit.txt`, `raw/hidden-rerun.json`, and `raw/build/`
  (provenance, targets, srccheck, digests and sizes, K2 and `.pyc` checks).
- `matrix.md` (compact) and `matrix.json` (every variant, with the first failure per build).

Run with `tests/g02/.venv/bin/python -I scripts/probes.py <bins-dir> <out-dir> <build>...`, using
the binaries from `build_cells.sh`. The scratch root was
`<home>/.local/share/heimdall-m00/r4-scratch/M00-T05-r4-x2-xrev-T3/`. Its build trees, Rust target
dir and binaries were deleted at the end of the task.
