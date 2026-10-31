# M00-T02-fix3: recheck2 minors n2-n10 and n13, matrix text n6 and n7

- Task: M00-T02-fix3. Input: `../recheck2/RECHECK2.md` section F (commit 3622c56).
- Run on 2026-10-31 (about 20:00-20:45 UTC), darwin, `python3` 3.15.2 (OpenSSL 4.1.0). The seven sources that this interpreter cannot reach were fetched with `python3.13` 3.13.18 (OpenSSL 3.5.9); see "Live round". The 2026-10-03 baseline used Python 3.14.8.
- Status: `implemented_unverified`. A mutation check (below) and the existing static check were run; no independent recheck has run.
- Network: HTTP GET over https only, unauthenticated, `SSH_AUTH_SOCK` unset. URLs: the 34 spec and 4 auxiliary source URLs (`fetch`), the 7 raw `upstream` URLs, the git ref advertisements listed in `pins.json` `tag_pins` (`tags`), the pinned-commit raw URLs (`excerpts --fetch-git`, and one `fetch --only S29` against a copy of pins.json with a wrong blob), and the TLS and S29 probes (`60_`-`62_`). No GitHub API, crates.io, npm or archive.org requests; `archive` was not run.
- Scratch: bodies, snapshots and crafted result files went to a `mktemp -d` directory under `/tmp` (`<tmp>` in the outputs). It was deleted at the end.
- Written: `docs/sources/tools/fetch_pins.py`, `docs/sources/README.md`, `docs/sources/pins.json`, `docs/decisions/0003-source-pins.md`, `docs/compatibility/matrix.md` (n6 and n7 only; row 3 CTK bullet and M5 untouched), and this directory. Nothing committed. No pinned hash value, baseline or snapshot changed.
- Not updated (outside the write scope): `progress.md` (line 9 still lists n2-n10 and n13 as open), `fix2/README.md` (its "benign drift" wording at :30 and :96 is historical; ADR-0003 withdraws the label).

## Finding to fix

Line numbers are for the files as left by this task. `F` = `docs/sources/tools/fetch_pins.py`.

| Finding | Fixed | What changed | Where |
|---|---|---|---|
| n2 | yes | Off-pin lines (`primary_same=no`) are always printed (also IDENTICAL ones without `--all`); the header counts `off_pin=N`; new exit 5 when nothing worse was found (precedence 2, 3, 5, 4, 0; never with `--no-pins`). One rule stated in README, ADR-0003 and `pins.json`: off-pin with text-identical class against the baseline is pin maintenance, not a reopen; an off-pin normalized-primary source is CONTENT. | F:603-613 (`compare_exit`), F:630-666 (`compare_results`, `visible_lines`), F:669-676, F:688-699; README:41, :49; ADR:15, :167-171; pins.json:1787 |
| n3 | yes | New class GONE (reference HTTP 200, second file 404 or 410), exit 2 (the table's choice; see "Not changed"). `upstream`: a 404 or 410 file is result `gone`, exit 2. Persistent FETCH_FAILED rule (same source failing on runs at least 24 h apart counts as GONE) in README, ADR and pins.json. | F:176, F:195-197, F:580-581, F:603-606, F:732-752, F:771-772; README:37-38; ADR:15, :167, :171; pins.json:1787 |
| n4 | yes | A document with a `<head>` and no `</head>` is parsed a second time with the head ending at the first start tag that cannot be in a head (`<body>` included); script, style, noscript, template and svg inside the head stay dropped. Output for every other document is unchanged (the first pass is the v1 rule), so `NORMALIZER_VERSION` stays 1. `fetch` warns on stderr below 200 normalized characters. | F:172, F:206-262 (`_TextExtractor`, `_html_text`, `normalize`), F:449-455 (`short_text_warning`); docstring "Normalization" step 2; README:66; ADR:10 |
| n5 | yes | `upstream` exit 4 is worded "drifted, quotes intact (claim not re-read)", and the run ends with a summary line. A drifted source with no quoted fragment is now exit 2 (it was 4: H8). Re-read policy for a drifted source cited by a still-open gate: ADR-0003 "Reopen conditions" (read the branch file against the claim, record `claim re-read: holds` or `changed` with the date in the source's note, reopen if changed or gone, cite only the pin until recorded); mirrored in `pins.json` `reopen_conditions[1]`. | F:732-752, F:791-792; ADR:16, :173, :155; README:58; pins.json:1788 |
| n8 | yes | Overall deadline per GET (`DEADLINE_S` = 120 s, `fetch --deadline`): cooperative checks (before each attempt, between body chunks, socket timeout capped by the time left) and a hard backstop (the GET runs in a daemon thread that is abandoned `DEADLINE_GRACE_S` = 5 s later). It returns status 0, error `DeadlineExceeded`, so the source is FETCH_FAILED. stdout is line-buffered for every subcommand. `fetch` prints `error=<name>` on a failed source's line. | F:173-174, F:283-364, F:468-522 (`cmd_fetch`), F:1178-1192 (`_positive_float`, `line_buffered`), F:1201 (`main`) |
| n9 | yes | `fetch`: 0 all fine; 2 a GitHub blob that is not the pinned blob (the condition `compare` calls CONTENT, same code); 3 a source not HTTP 200 or a network error or the deadline; 1 is now only an input error. A failed GitHub fetch is not counted as a blob mismatch (a failed body has no blob to compare). | F:197-199, F:457-466 (`fetch_exit`); docstring; README:48; ADR:15, :128 |
| n10 | yes | `contains_words()`: the fragment must occur on word boundaries (padded-space match on the `loose()` forms), used by `excerpts` and `upstream`. `excerpts --set all --fetch-git`: 38 sources, 91 fragments, all found, as before. | F:720-724, F:781, F:909, F:923, F:926; README:68; ADR:18 |
| n13 | yes | `pins.json` records `upstream` `{url, ref}` for all 7 GitHub sources (S16-S19, S27, S29, S34), not only the three named: values come from `fetch_pins.upstream_url_for()` (S19, S27, S29: `.../HEAD/README.md`, ref `HEAD`; S16-S18, S34: the `main` raw URL). `upstream` refuses (input error, exit 1) if the record differs from the derived URL, and `selftest` checks all 7. | pins.json:640, :687, :734, :781, :1128, :1213, :1426; F:755-764; selftest F:1162-1170; README:7, :63; `edit_pins_fix3.py` |
| n6 | yes | The "coarser records" list now names three records: `m00-t03-fixtures.json`, `g03-wsl-a-process-io.json` (L3) and `g03-wsl-a-executable-selection.json` (L2), and says neither WSL record has a per-row map. Row 10 "Blocked on" gains the operator item for interactive Ctrl-C and PTY resize. | matrix.md:22-30, :130-131 |
| n7 | yes | Row 9 names the unimplemented probe harness (g04 §8.2, P-W1 and P-W2). I also replaced the sentence "their `blocked_on` text says no Windows host is available; that text predates 2026-10-06": the records' current `blocked_on` no longer says that (they name the owner at the console and the probe script), so it was stale. | matrix.md:121-124 |

Beyond the findings: the live `upstream` run lost a quoted fragment of S29 (the new exit 2 fired on a real change), so a dated drift note was added to S29 in `pins.json` (`edit_pins_fix3_s29.py`; evidence `62_s29_head_vs_pinned.out`) and one bullet to ADR:155. The TLS limit is recorded in README:67 and ADR:181.

## Exit codes after fix3

| Subcommand | Code | Meaning |
|---|---|---|
| any | 1 | input error (unreadable pins or result file, empty reference file, `upstream.url` that differs from the derived URL; fetch no longer uses 1 for fetch failures) |
| any | 64 | usage error (includes `fetch --deadline 0`) |
| `fetch` | 0 | every source HTTP 200 and every GitHub blob equal to its pin |
| `fetch` | 2 | a GitHub body whose blob sha1 is not the pinned blob (new; was 1) |
| `fetch` | 3 | a source not HTTP 200, a network error or the deadline (was 1) |
| `compare` | 2 | at least one CONTENT, GONE (new) or MISSING |
| `compare` | 3 | at least one FETCH_FAILED, nothing in 2 |
| `compare` | 5 | off-pin (new): nothing in 2 or 3, at least one `primary_same=no` |
| `compare` | 4 | only RAW_ONLY / MARKER_ONLY, every one on-pin (before fix3 also off-pin ones) |
| `compare` | 0 | all IDENTICAL and none off-pin (before fix3: all IDENTICAL) |
| `upstream` | 0 | no drift |
| `upstream` | 4 | drifted, quotes intact (claim not re-read); every drifted source has at least one quoted fragment and all are present |
| `upstream` | 2 | a drifted source lost a quoted fragment, or has none to check (was 4), or its file is gone, 404 or 410 (was 3) |
| `upstream` | 3 | fetch failure, nothing in 2 |
| `tags`, `excerpts`, `verify`, `selftest` | unchanged | `tags` 0/2/3/4, `excerpts` 0/2/3, `verify` 0/3, `selftest` 0/1 |

All of it is in the script docstring, README "Exit codes", ADR-0003 (Method, "Changes in M00-T02-fix3") and `pins.json` `reproducibility.verify`, and covered by the selftest (precedence tests for each of `compare_exit`, `upstream_exit` and `fetch_exit`).

## Tests added

- `selftest` went from 29 to 85 `check(` call sites (plus 4 new rows in the `classify` table and a loop over the 7 GitHub sources); it still runs in about 2 s and makes no network request (the deadline tests use a fake opener).
  - Normalizer: no `</head>` with and without `<body>`; script, style, noscript and svg inside an unclosed head; a stray `div` in a closed head (v1 behaviour kept); no head at all; short-text warning.
  - compare: GONE for 404 and 410; not GONE for 500, for a reference that was 404, or for 404 on both sides; deadline error is FETCH_FAILED; every precedence of `compare_exit` including off-pin; off-pin lines print without `--all`; GONE and failed lines carry no `primary_same`.
  - upstream: drifted with 0/0 fragments, gone file, gone beats fetch failed. fetch: every code of `fetch_exit`, including "a failed GitHub fetch is not a blob mismatch".
  - Deadline: trickling body and stalled connect (hard deadline), `_read_all` and `_get_with_retries` on their own (cooperative deadline), `run_with_deadline`, `line_buffered`.
  - Word boundaries at start and end of a fragment; the 7 recorded `upstream` URLs against `upstream_url_for`.
- `mutation_check.py` (`29_mutation_check.out`, exit 0): the unmutated copy passes and each of 18 one-line breaks of the code is caught by a failing `selftest`. An earlier version caught 17: the cooperative deadline in `_read_all` was masked by the hard deadline, so the two cooperative checks above were added.
- CLI-level cases with crafted inputs (`make_cases.py`, outputs `12_`-`25_`, `28_`): GONE 404 and 410, a 403, off-pin by raw bytes (exit 5), the same bytes moved on a normalized-primary source (exit 4, on-pin), both together (5), two identical fresh files that are off-pin (5, and 0 with `--no-pins`), CONTENT (2), CONTENT plus GONE (2), a wrong recorded `upstream.url` (exit 1 before any GET), `--deadline 0` (64), `--deadline 0.001` (3, record has `error` DeadlineExceeded), and a wrong pinned blob for S29 (exit 2).

## Commands and real exit codes

Each `.out` file starts with the command (`$ ...`) and ends with `exit=<code>`. Produced from the repository root with `ALT_PYTHON=python3.13 bash tests/evidence/artifacts/review-sources/fix3/run_fix3.sh <tmp> tests/evidence/artifacts/review-sources/fix3 live`; `01_` and `02_` were re-run at the end on the final tree, and `55_`, `60_`-`62_` were run separately with the same wrapper format.

| Step | Output | Exit | Result |
|---|---|---|---|
| `selftest` | `01_selftest.out` | 0 | all checks passed |
| fix2 static check on this tree | `02_static_check_fix2.out` | 0 | 412 ok, 0 failed |
| mutation check | `29_mutation_check.out` | 0 | 18 of 18 mutants caught, baseline passes |
| `compare` baseline vs `fetch-repeat.json`; aux baseline vs itself (offline) | `10_`, `11_` | 0, 0 | 34 and 4 IDENTICAL, `off_pin=0` |
| crafted `compare` cases | `12_`-`22_` | 2, 2, 3, 5, 4, 5, 5, 0, 2, 2, 4 | as listed under "Tests added" |
| `upstream` with a wrong recorded URL | `23_` | 1 | input error, no GET |
| `fetch --deadline 0`; `--deadline 0.001` | `24_`, `25_` | 64, 3 | usage error; DeadlineExceeded |
| `excerpts --set all` (snapshots only) | `26_` | 3 | 31 sources, 76 fragments found; 7 GitHub sources skipped as designed |
| `verify`, 31 committed snapshots | `27_` | 0 x 31 | all match |
| `fetch --only S29` with a wrong blob in a pins copy [GET] | `28_` | 2 | blob mismatch |
| normalizer, old (3622c56) vs new on live bodies, Python 3.15.2 | `40_` | 1 | 31 SAME, 0 DIFFERENT; 7 not fetched (TLS, below) |
| the same, Python 3.13.18 | `55_` | 0 | 38 of 38 SAME; synthetic head cases: old `''`, new text |
| `fetch` runs A and B (27 snapshots each) | `41_`, `42_` | 3, 3 | 27 HTTP 200, 7 `URLError` (S01-S05, S10, S30) |
| `compare` baseline vs run A | `43_` | 2 | IDENTICAL 7, RAW_ONLY 2, MARKER_ONLY 3, CONTENT 15, FETCH_FAILED 7; `off_pin=15` |
| `compare` run A vs run B | `44_` | 3 | the 7 failed are FETCH_FAILED; of the rest 26 IDENTICAL, 1 RAW_ONLY (S11); `off_pin=15` is printed |
| `fetch` the 7 failed ids with Python 3.13.18; merge; `compare` | `51_`-`53_` | 0; ; 2 | merged (synthetic) file: IDENTICAL 8, RAW_ONLY 2, MARKER_ONLY 3, CONTENT 21, FETCH_FAILED 0; `off_pin=21` |
| `fetch --set aux`; `compare` vs `fetch-baseline-aux.json` | `45_`, `46_` | 0, 2 | A01-A04 all CONTENT (see below) |
| committed vs fresh snapshots | `47_`, `54_` | n/a | run A: 5 identical, 15 differ, 7 not fetched; aux run: 4 differ; 3.13 run: S03 identical, 6 differ |
| `upstream` | `48_` | 2 | S16, S17, S18, S34 drifted, fragments intact; S29 drifted, fragments 1/2; S19, S27 same |
| `tags` | `49_` | 0 | all 14 tags SAME |
| `excerpts --set all --fetch-git` | `50_` | 0 | 38 of 38 sources checked, 91 fragments, all found, GitHub blobs verified |
| TLS probe, Python 3.15.2 and 3.13.18; S29 diff | `60_`, `61_`, `62_` | 0, 0, 0 | see below |

## Live round: what it showed (not part of the fixes)

- 2026-10-31 is 3 weeks after the baseline. 15 of the 27 sources fetched by `python3` and 21 of 34 in the merged file are CONTENT against the baseline. I read the word-level differences of 8 of them (`S04`, `S10`, `S30`: the token `OpenBSD-8.0` appears; `S21`, `S22`, `A01`: new site navigation entries and "Back to top"; `S25`: two sentences changed; `S11`: a new heading "Credential Files"). All 8 are small insertions or edits. I did not check whether any cited excerpt is affected, and I did not re-pin anything. The old-versus-new normalizer probe (`40_`, `55_`) shows that the normalizer change is not the cause.
- TLS: `python3` 3.15.2 with OpenSSL 4.1.0 fails the handshake with `man.openbsd.org` and `www.openssh.org` (`TLSV1_ALERT_DECODE_ERROR`, `60_`); the tool of 3622c56 failed the same way before my change (checked with a copy of it in the scratch directory; that run's output was not saved). `python3.13` 3.13.18 with OpenSSL 3.5.9 fetches all seven (`61_`, `51_`). The record only says `URLError`. Cause on the server side not established.
- S03 still has its pinned raw hash under Python 3.13 (raw `28939c42...`); S01, S02, S04, S05, S10 and S30 moved.
- `upstream`: S29's README on HEAD lost the quoted fragment "Development requires Bun 1.4.1 or later and Zig 0.16.0." (HEAD says Zig 0.17.0). By ADR-0003 "Reopen conditions" that is a reopen trigger for a still-open gate that cites S29's Zig requirement. I did not check which gates cite it; that is the gate owner's call. S16, S17, S18 and S34 changed again on `main` (new branch blobs, fragments intact, claims not re-read).
- `tags`: all 14 resolved ids still equal the pins.

## Not changed, and why

- GONE has exit 2, not a new code (the table's choice): for reopen purposes a removed page is drift, the class and the output line carry the distinction, and a sixth code would be one more case for callers. The reopen-condition alternative was added as well (persistent FETCH_FAILED).
- n2 chose its own exit code (5) and a rule that differs from the old ADR text: the ADR said `primary_same=no` reopens; README said to check the snapshot first. The one rule is: reopen on CONTENT, GONE or MISSING; off-pin with identical text is pin maintenance. This is a policy choice for the owner or reviewer to confirm.
- n9 goes slightly further than the table: a failed fetch is exit 3 (was 1), so that 1 means only "input error" as the docstring always said. Scripts that tested `fetch` for exit 1 must change; no script in the repository tests it (outside `review-sources/`, the only files that mention `fetch_pins` are documents, data files and `m00-wf4/sources-fix.json`).
- `tags`: a 404 repository is still FETCH_FAILED (exit 3). my recollection is that GitHub's git endpoint answers 401 for a missing or private repository, so 404 would not be a reliable signal there; not tested.
- `verify` with an unknown `--id` still ends in a traceback (exit 1), as recheck2 noted; not one of the listed findings.
- The deadline is per source (120 s default), not per run, and the cause of the 32-minute stall in recheck2 `stall_diagnosis.out` remains unexplained: no stall occurred in these runs.
- `archive` was not run (archive.org is not a pinned source) and its two GETs now pass a larger explicit deadline (300 s, 400 s); that path is untested.
- n14, n15 and the `progress.md` update are not part of this task.

## Files in this directory

- `run_fix3.sh` (driver), `make_cases.py`, `mutation_check.py`, `normalizer_old_vs_new.py`, `merge_results.py`, `tls_probe.py`, `s29_head_vs_pinned.py`: the checks.
- `edit_pins_fix3.py`, `edit_pins_fix3_s29.py`: the `pins.json` edits, kept for provenance (the second was run twice, see its docstring).
- `*.out`, `data_*.json`: outputs of the runs above. `data_runA.json`, `data_runB.json`, `data_aux.json`, `data_alt.json`, `data_upstream.json` and `data_tags.json` are the fetch, upstream and tags results with the scratch path replaced by `<tmp>`.
