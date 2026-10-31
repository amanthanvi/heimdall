# M00-T02-fix4: recheck3 R3-1, R3-2 (S34, S29 and the drift ledger), R3-3

- Task: M00-T02-fix4. Input: `../recheck3/RECHECK3.md` (read in full, with `claim-*.out`, `upstream.out`, `compare-live.out`), `../fix3/README.md`, and the task brief (orchestrator dispositions for S34 and S29).
- Run on 2026-10-31 (about 21:00-21:15 UTC), darwin. Offline checks used `python3` 3.15.2 (OpenSSL 4.1.0) and `python3.13` 3.13.18 (OpenSSL 3.5.9); every step that contacts the sources used `python3.13`, because 3.15.2 cannot reach `man.openbsd.org` and `www.openssh.org` (`docs/sources/README.md`, "Environment").
- Status: `implemented_unverified`. A mutation check (23 of 23 mutants caught) and the consistency check ran; no independent recheck has run on these changes.
- Network: HTTP GET over https only, unauthenticated, `SSH_AUTH_SOCK` unset: the 38 source URLs (`fetch --set all`), the 7 raw branch URLs (`upstream`), the pinned-commit raw URLs (`excerpts --fetch-git`, `drift_diffs.py`), the git ref advertisements (`tags`). No GitHub API, crates.io, npm or archive.org request; `archive` was not run.
- Scratch: bodies, snapshots and result files went to a `mktemp -d` directory under `/tmp` (`<tmp>` in the outputs). Deleted at the end.
- Written: `docs/sources/tools/fetch_pins.py`, `docs/sources/README.md`, `docs/sources/pins.json` (notes, `reopen_conditions` text and `fix4_edited_at_utc` only), `docs/decisions/0003-source-pins.md`, `docs/compatibility/matrix.md` (M5 and the row 13 note only), `docs/sources/drift-2026-10-31.md` (new), and this directory. Nothing committed or pushed. No pinned hash, baseline, snapshot, excerpt or claim field changed (`28_ledger_check_with_live_data.out` compares `pin`, `pin_v2`, `candidates`, `tag_pins`, `excerpt` and `claim` with git HEAD).
- Not touched: `progress.md` (it changed during this task, not by it), the fix3 and recheck3 directories.

## Item map

`F` = `docs/sources/tools/fetch_pins.py`, `ADR` = `docs/decisions/0003-source-pins.md`, `L` = `docs/sources/drift-2026-10-31.md`.

| Item | Result | What changed | Where |
|---|---|---|---|
| R3-1 (minor): `<html><head><title>Title</title>Hello world</html>` normalized to `''` | fixed | In the second (implied-head) pass, character data other than HTML whitespace (tab, LF, FF, CR, space) that is outside `<title>` and outside an open script, style, noscript or template element ends the head and is kept, as an implied `</head><body>` would. Title text, script/style/noscript/template text and whitespace between head elements stay dropped or ignored. The first pass (the v1 rule, used whenever `</head>` exists) is untouched | F:179 (`HTML_SPACE`), F:213-263 (`_TextExtractor`: `title_open` :220, `_head_only_open` :222-225, title start :234-235, title end :247-248, `handle_data` :255-261), docstring F:128-141; README:67; ADR:10, :134 |
| R3-1 selftest | 10 cases added (`check(` sites 85 to 95); the existing 8 head cases still pass | the recheck3 example, text straight after `<head>`, a `<body>` start tag alone, whitespace (space, CR LF, tab, FF) between head elements, title text alone, unclosed title, script/style/noscript text alone, text after them, a no-break space (not HTML whitespace), and text inside a closed head (v1 rule kept) | F:980-1001 |
| R3-1 mutation check | 23 of 23 caught (fix3's 18 plus 5 for the new rule); the old "`<body>` does not end the head" mutant needed the `<body>`-alone case | `mutation_check.py`; `04_mutation_check.out` | this directory |
| R3-1 `NORMALIZER_VERSION` | stays 1: no source's text changes | The second pass runs only for a document with a `<head>` and no `</head>`. On today's 38 bodies it ran for none (`second_pass=no` for all), and the committed 3622c56 normalizer, fix3 (rebuilt from the current file and checked against the hash recheck3 recorded) and fix4 give identical text for all 38. The baseline bodies are not stored; they cannot have had an unclosed head either, since the baseline snapshots hold 2202 or more normalized characters for every HTML source and v1 gave `''` for an unclosed head. The bump rule is now written down | `20_normalizer_fix3_vs_fix4.out`; README:67; ADR:10 |
| R3-3 (minor): M5 conflated run coverage | fixed | M5 now says the CTK runs load only through `ssh-add -K -S` and sign, "fixture login in v3 only (v1 left it unmeasured)", as `tests/evidence/g04-macos-secure-enclave-ctk-probe.json` records (checked: U4 measured in v3, unmeasured in v1) | matrix.md:225; ADR:135 |
| R3-2 (major): ledger | written | One row per changed source, 30 rows: id, class, citing gates and documents, whether each cited claim holds in today's text, disposition. Counts below | L (whole file); README:15; ADR:136, :162 |
| R3-2 S34 | recorded as required | Qualification (default grants now include access and relay management; shell or full-access-agent scope can mint a fully scoped session); the immutable pin stays the experiment baseline; main's defaults are not promoted into any Heimdall contract; G07's authority-boundary investigation is retained and reopened on this point (owner re-reads the section) | L:63 (row), L:69-79; pins.json:1434 (`note`), :1787-1788 (`reopen_conditions[0]`, `[1]`); ADR:163; matrix.md:147 |
| R3-2 S29 | recorded as required | Orchestrator disposition: G02 keeps the pinned, frozen TypeScript candidate; rejected on the security-assumption and child/IPC gates (ADR-0002 section 3 and 3.3), which do not depend on the Zig version; no re-test. Standing `upstream` exit 2 accepted. Also: the "Zig 0.16.0" statement in the ADR "OpenTUI native components" paragraph now carries the HEAD value | L:61 (row), L:81-87; pins.json:1221 (`note`); ADR:97, :164; README:59 |
| Re-read notes for the other drifted GitHub sources | added (ADR "Reopen conditions" step 2 asks for them for sources cited by an open gate) | S16 holds; S17 and S18 hold with qualifications | pins.json:648, :695, :742; L:51-53; ADR:165 |
| Policy text | added | The ledger is the dated record for CONTENT drift of non-GitHub sources, with three dispositions; a recorded disposition closes the question for people, not for the tool | ADR:183 (and the "Reopen conditions" bullet it extends); README:59 |
| Provenance of the pins.json edit | kept | `edit_pins_fix4.py` (asserts that no non-note field changed) | this directory |

Line numbers are for the files as left by this task.

## Ledger counts (from `L`, verified by `ledger_check.py` against the raw results)

| | Count |
|---|---|
| Rows | 30 |
| CONTENT, spec sources | 21 (S01, S02, S04-S12, S14, S15, S20-S22, S24-S26, S28, S30) |
| CONTENT, auxiliary sources | 4 (A01-A04) |
| Branch drift, quotes intact | 4 (S16, S17, S18, S34) |
| Lost fragment | 1 (S29) |
| claim unchanged, pin kept | 26 |
| qualification recorded | 4 (S17, S18, S29, S34) |
| changed/inconclusive: gate owner to re-read | 0 |

Gate with a standing action: G07 (S34: authority-boundary investigation retained, reopened on default grants; S17 and S18 carry notes for its owner). No other gate or matrix row changes. The brief listed S19 and S27 among the branch-drifted sources; `upstream` (`24_upstream.out`, and recheck3's run) found both equal to their pins, so they have no row.

## Commands and real exit codes

Each `.out` file starts with the command (`$ ...`) and ends with `exit=<code>`. Produced from the repository root by `bash tests/evidence/artifacts/review-sources/fix4/run_fix4.sh <tmp> tests/evidence/artifacts/review-sources/fix4 live`.

| Step | Output | Exit | Result |
|---|---|---|---|
| `selftest`, python3 3.15.2 | `01_` | 0 | all checks passed |
| `selftest`, python3.13 | `02_` | 0 | all checks passed |
| fix2 static check on this tree | `03_` | 0 | 412 ok, 0 failed |
| mutation check | `04_` | 0 | 23 of 23 mutants caught, baseline passes |
| `verify`, 31 committed snapshots | `05_` | 0 x 31 | all match |
| `excerpts --set all` (snapshots only) | `06_` | 3 | 31 sources, 76 fragments found; the 7 GitHub sources unchecked by design |
| `compare` baseline vs repeat; aux baseline vs itself | `07_`, `08_` | 0, 0 | 34 and 4 IDENTICAL, `off_pin=0` |
| ledger consistency check, no live data | `09_` | 0 | all OK |
| citation search | `10_` | 0 | `find_citations.py` output |
| normalizer, 3622c56 vs fix3 vs fix4 on 38 live bodies | `20_` | 0 | 38 SAME; `second_pass` ran for 0 sources; synthetic cases fix3 to fix4 |
| `fetch --set all` (python3.13) | `21_` | 0 | 38 HTTP 200, 7 GitHub blobs equal their pins |
| `compare` baseline vs fresh | `22_` | 2 | IDENTICAL 8, RAW_ONLY 2, MARKER_ONLY 3, CONTENT 21; `off_pin=21` |
| `compare` aux baseline vs fresh | `23_` | 2 | CONTENT 4 |
| `upstream` | `24_` | 2 | S16, S17, S18, S34 drifted, fragments intact; S29 drifted, fragments 1/2; S19, S27 SAME |
| `tags` | `25_` | 0 | all 14 tags SAME |
| `excerpts --set all --fetch-git` | `26_` | 0 | 38 sources, 91 fragments, all found |
| word-level drift diffs for the ledger | `27_` | 0 | input of the ledger |
| ledger consistency check with live data | `28_` | 0 | ledger ids equal the sources flagged by the raw results; pins unchanged against git HEAD; no home path or user name |

Nothing else moved since recheck3's run: the same 21 + 4 CONTENT sources, the same branch blobs, the same 14 tags.

## Not settled, and limits

- The ledger's "holds" is a textual judgment by the fix4 author from complete word-level diffs and recheck3's context reads; no independent reviewer has checked it. The behavioral claims remain with G02, G03, G04, G07 and G09.
- S34: whether a limited client can reach management authority, directly or through a shell or agent scope, is exactly what G07 still has to test; this task records the source change, it does not answer the question. The T3 Code commits that changed S16, S17, S18 and S34 on `main` were not looked up (no GitHub API request).
- `upstream` will keep exiting 2 for S29 while its quoted Zig line is absent from `HEAD` (the tool has no way to remember an accepted disposition).
- R3-1 is repaired for the HTML forms in the selftest; the normalizer is still a `html.parser` approximation of an HTML parser, not a full one (for example `<title>` is treated as the head-only element it is, but no other HTML5 insertion-mode rules are applied).
- The default `python3` (3.15.2 with OpenSSL 4.1.0) still cannot fetch the 7 OpenBSD/OpenSSH sources; the live steps used `python3.13`. The cause on the servers' side is not established (unchanged from fix3).
- `progress.md` is not updated here (outside the write scope).

## Files in this directory

- `run_fix4.sh` (driver), `mutation_check.py`, `normalizer_fix3_vs_fix4.py`, `drift_diffs.py`, `find_citations.py`, `ledger_check.py`: the checks. `edit_pins_fix4.py`: the pins.json edit, kept for provenance.
- `*.out`: outputs of the runs above. `data_fresh.json`, `data_upstream.json`, `data_tags.json`: the `fetch`, `upstream` and `tags` results with the scratch path replaced by `<tmp>`.
