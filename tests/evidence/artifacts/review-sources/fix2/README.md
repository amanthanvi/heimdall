# M00-T02-fix2: fixes for the 2026-10-09 recheck (M1, m1-m9)

- Task: M00-T02-fix2. Input: `../recheck/RECHECK.md` (committed in 5b2c0a3).
- Run on 2026-10-09 between 05:31 and 06:14 UTC, on darwin with Python 3.14.8 (the same version as the baseline).
- Network:
  - HTTP GET only, https only, unauthenticated, with `SSH_AUTH_SOCK` unset.
  - URLs fetched: the 34 listed source URLs through the fetcher; the raw branch rendering of the 7 GitHub spec URLs
    (`upstream`); four docs.iroh.computer pages, which became A01-A04 (finding m5); and the public git ref
    advertisement of 10 GitHub repositories (`tags`; `info/refs?service=git-upload-pack`, protocol v0, no POST).
  - No GitHub API, crates.io or npm requests.
- Downloads and scratch: downloaded bodies went to `/tmp/hm-t02fix2.*`, outside the repository; `<tmp>` stands for
  that directory in the outputs. It was deleted at the end.
- Not touched: spec.md, plan.md, progress.md, ADR-0001/0002, research docs, evidence records, AGENTS.md and
  CLAUDE.md. Nothing was committed.
- Status: `implemented_unverified`. An internal adversarial review was done (see below), but no independent
  re-check has run.

## Commands and real exit codes

Each output file ends with the command's `exit=` line. The "final" files come from `run_final.sh` with the fetcher
as committed for review (06:13-06:14Z). The others are earlier runs, kept for history.

| Step | Output | Exit | Result |
|---|---|---|---|
| Fetcher as of d096a64, before any edit: `fetch` S01-S34 with 27 snapshots | `head_fetch_run1.out`, `.json` | 0 | 34 × HTTP 200 |
| d096a64 `compare`, baseline vs that run | `head_compare_baseline_run1.out` | 2 | Old two-flag output; same result as the recheck's run3 |
| d096a64 `verify`, the 27 committed snapshots | `head_verify_snapshots.out` | 0 × 27 | All match |
| Committed snapshots vs fresh ones | `head_snapshot_cmp.out` | n/a | 25 byte-identical; S26 (content edit) and S28 (live counters) differ |
| Revised `compare` on the recheck's 403-window run | `compare_recheck_run1_revised.out` | 2 | S24, S26 and S31-S33 are FETCH_FAILED 200/403 (the old compare reported them as content diffs); S28 is CONTENT |
| `upstream` (new), first run 05:36Z (old exit rule) and final 06:14Z | `upstream1.out`, `.json`; `final_upstream.out`, `.json` | 2; **4** | S16, S17, S18 and S34 drifted on main with every quoted fragment present; S19, S27 and S29 unchanged. Under the final exit rule, benign drift is 4 |
| `tags` (new): resolution run, check after fill, final check | `tags1_resolve.out` (4 = unpinned), `tags2_check.out`, `final_tags.out`, `.json` | 4, 0, 0 | 14 tags resolved; both later checks say SAME |
| `fetch --set aux` twice, then compare | `aux_run1.out`, `aux_run2.out`, `aux_compare_run1_run2.out` | 0, 0, 0 | A01-A04 identical; snapshots byte-identical |
| `excerpts --set all --fetch-git` (new), first run and final | `excerpts1.out`; `final_excerpts.out` | 0; 0 | First run: 87 fragments. Final, after quotes were added for S05 and S21: 38/38 sources checked, 91 fragments, all in their own pinned copy, 0 unchecked; GitHub blobs verified |
| Excerpts against today's text (S05, S21, S23, S24, S26, S28) | `excerpts_today.out` | 0 | All present |
| `selftest` (new) | `final_selftest.out` | 0 | All checks passed |
| Revised `fetch`, runA and runB (34 sources, 27 snapshots) | `final_fetch_runA.out`, `final_fetch_runB.out`, `.json` | 0, 0 | 34 × HTTP 200 each |
| Revised `compare`, baseline vs runA | `final_compare_baseline_runA.out` | 2 | IDENTICAL 15, RAW_ONLY 10, MARKER_ONLY 7, CONTENT 2 (S26, S28), FETCH_FAILED 0; `primary_same=no` only for S26 and S28 |
| Revised `compare`, runA vs runB | `final_compare_runA_runB.out` | 0 | 34 identical |
| Revised `compare`, baseline vs repeat (offline) | `final_compare_baseline_repeat.out` | 0 | 34 identical |
| Revised `fetch --set aux`, then compare vs `fetch-baseline-aux.json` | `final_fetch_aux.out`, `final_compare_aux_baseline.out` | 0, 0 | Identical |
| `verify`, all 31 committed snapshots | `final_verify_snapshots.out` | 0 × 31 | All match |
| Committed vs fresh snapshots; runA vs runB | `final_snapshot_cmp.out` | n/a | 56 of 58 equal; the two differences are S26 and S28, committed vs fresh |
| Offline consistency check | `static_check_fix2.out` | 0 | 412 checks, 0 failed (details below) |
| Negative control for that check: a temp matrix with 3 planted overclaims | `static_check_planted.out` | 1 | All 3 caught (4 failures) |
| Discovery GETs: Iroh pages and one ref advertisement | `discovery_gets.out` | 0 | All HTTP 200 |
| Canary-prefix scan of every changed or new file in the write scope, plus all snapshots decompressed | `canary_scan.out` | 0 | 0 hits |

The offline consistency check (`static_check_fix2.py`) covers:
- pins.json against the baselines, and the snapshots;
- primary kinds, legacy labels and tag ids;
- the ADR tables;
- matrix ids and cited records;
- every single-record observation status cell, M3's ordered verdicts, and the M4/M5 glob tallies;
- every main-table label, floor and allowed status;
- that a row naming a blocked input or record is `blocked`, and that `not_started` appears only with no evidence.

Scripts in this directory:
- `get.py`, `normtext.py`: discovery helpers;
- `edit_pins.py`: the `pins.json` edits, kept for provenance;
- `excerpts_today.py`, `static_check_fix2.py`, `canary_scan.py`, `run_final.sh`: the checks and the final suite.

## Finding → fix

| Finding | Fix | Where |
|---|---|---|
| M1 (major): matrix neither built nor delegated; v0 stale and unlinked | **Delegation:** recorded. **Matrix v1:** every row lists its pins and carries three statuses: the spec §3.3 label `not-tested`; the gate-evidence status, the lowest-standing record or needed sub-row, so 14 rows `blocked` and 2 `not_started`; and the G01 floor `blocked`. Rows 7-11 were rebuilt from the 2026-10-06 native Windows 11 / WSL2 records, and row 16 (Git for Windows MSYS ssh) was added. **Observations:** tables W1-W12, L1-L13 and M1-M5 replace the placeholder, with record statuses copied and machine-checked. **New tables:** G02 prototype platforms, and floors (all `blocked`). | `docs/compatibility/matrix.md`; ADR-0003 "Support matrix"; `docs/sources/README.md` "Support matrix" |
| m1: `compare` mislabels marker-only changes, ignores HTTP status; README:18 wrong | **Classes:** one per source: IDENTICAL, RAW_ONLY, MARKER_ONLY, CONTENT, FETCH_FAILED, MISSING, EXTRA. A git blob mismatch counts as CONTENT. **primary_same:** checked against `pin_v2`. **Exit codes:** 0/4/3/2, plus 1 for an input error and 64 for a usage error. **Tests:** the self-test covers the classes, the precedence and `primary_same`. | `fetch_pins.py` `classify`, `compare_results`, `cmd_compare`, `cmd_selftest`; README "Reading compare" |
| m2: GitHub sources pinned at a commit; branch drift unobserved | Limit documented. New `upstream` mode with exit codes 0/4/2/3. The S16, S18 and S34 drift is recorded the same way as S17's. | `fetch_pins.py` `cmd_upstream`; pins.json notes of S16-S18 and S34; ADR-0003; README |
| m3: S23 raw-primary too brittle | S23 is now normalized-primary (`pin_v2.primary_change`). The primary-kind rule is written down. | pins.json S23; ADR-0003 Method and "Pin changes"; README |
| m4: six v1 hashes called unreproducible; 13 `pin.value` hold v1 hashes | S24-S26 and S31-S33 are relabelled `legacy_raw_body_sha256_v1` (reproduced; 21 sources now carry `raw_reproduced_vs_v1_pin`). The 13 `pin.value` fields say "superseded". The optional switch to raw-primary was declined, with the reason given. | pins.json; ADR-0003; notes.md |
| m5: Iroh Go/C binding and platform claims without URL or snapshot | A01-A04 added, with snapshots and their own baseline. The claims are rewritten with quotes. "highly experimental" and "cgo" are not on the pages (E9). | pins.json `auxiliary_sources`, `candidates.iroh.other_bindings`; `fetch-baseline-aux.json`; `snapshots/A0*.txt.gz`; ADR-0003 |
| m6: header overclaims re-verification | Replaced by a provenance paragraph: what the review checked, what the recheck verified, and what is producer-observed only. | ADR-0003; pins.json `candidates_provenance` |
| m7: E6 facts miss the inbox build and LibreSSL | Added: the inbox 9.5p2 and MSI 10.0p2 facts; which probes compared the two builds; the unrecorded LibreSSL licence and inbox terms; the G03-S01/S08 positioning; the tag commit. E6 is not decided. | pins.json `candidates.win32_openssh.e6_facts`, E6; ADR-0003 E6; notes.md |
| m8: bare tags | 14 tags resolved to tag-object and commit ids, with the tag name kept as a label. The advertisement is validated. `tags` re-checks. Asset digests are stated as not recorded. | pins.json `tag_pins` and `*_commit` fields; ADR-0003; `cmd_tags`, `parse_ref_advertisement` |
| m9a | "all 34 stable" marked WITHDRAWN | pins.json `method` |
| m9b | Reopen conditions restated in v2 terms | pins.json `reopen_conditions`; ADR-0003 |
| m9c | S24 ellipses added | pins.json S24 |
| m9d | "two earlier back-to-back pairs" dropped | ADR-0003 Method |
| m9e | `excerpts` subcommand, which fails on unchecked sources; S05 and S21 gained verbatim quotes so that all 38 sources are checked | `fetch_pins.py` `cmd_excerpts`; pins.json S05, S21 |

## Internal review

An independent subagent review ran on 2026-10-09: read-only and offline, after the first pass. Its verdict was NOT YET.
Every finding was handled:

| Review finding | Disposition |
|---|---|
| A1 (major): E6 said "the G03 probes gave the same results with both builds" | Corrected. Only P-W02, P-W03 and P-A01-P-A05 compared the builds; the other Windows probes used 9.5p2 only (pins.json e6_facts[1], ADR E6). |
| A2 (major): `excerpts` exited 0 with skipped or quote-less sources, and its paths depended on the current directory | Now exits 3 when a source is unchecked. Paths resolve from the repository that holds `--pins`. S05 and S21 got quotes. |
| A3 (integration): a concurrent G04 P5 task is re-running the CTK record (uncommitted) | Matrix row 3 now cites the record at a008fd0, notes the concurrent run, and asks for a re-check when it lands (escalation 8). |
| B1 E8 count; B6 MSYS ssh-add; B8 copy `blocked_on`; N1 S28 note; N3 aux baseline note; N5 timings, Engine, rows, r3-msi10; N6 wording | Fixed. |
| B2: the static check missed planted overclaims | Check extended. The negative control now catches all three (`static_check_planted.out`). |
| B3, B4, B7: rows 13, 10, 14 contradicted the matrix's own rule | Set to `blocked`, with the missing inputs named. Row 1 was also set to `blocked`: its fixture record uses `IdentityAgent none`, so no record exercises the native agent with an existing identity. |
| B5: two records are coarser than the multi-row rule | Matrix sentence qualified; escalation 6 below. |
| B9-B13: tags parser robustness, blob mismatch, compare inputs, self-test coverage, https-only | Fixed and covered by the self-test. |
| m2 partial: `upstream` exited 2 on benign drift | Exit 4 for drift that keeps every quoted fragment; 2 only when a fragment is lost. |
| N2: no saved output for 05:36Z | `upstream1.json` saved (05:36Z); final run 06:14Z. Notes cite both. |
| N4: quote-scope limits | Documented in the docstring. |

## Escalations (not decided here)

1. **E6** (owner). Whether the Preview-only Win32-OpenSSH line, alongside the inbox build, can be a supported
   baseline. The facts are added; the question is not decided.
2. **E8** (owner). Snapshot retention. It now also covers A01-A04.
3. **E9: ADR-0002:373** (orchestrator or ADR owner). Current text: "There is no official Go binding; the community
   binding is "highly experimental", needs cgo and supports musl only". Suggested replacement: "There is no official
   Go binding; the community binding (iroh-go) is "still considered experimental" and supports Linux x86_64 and
   aarch64 (musl) only [A02]; as a binding over the iroh-ffi native library it needs cgo [inference; X5 module
   inspection]".
4. **ADR-0001 §5** (owner). The Windows and WSL2 "Blocked on" cells say "native Windows host" / "native Windows host
   with WSL2". Suggested text for both: "G01 clean-machine tests (the owner's Windows 11 PC, available since
   2026-10-06, is not a clean machine)". The floors stay `blocked` either way.
5. **docs/research/g03-windows-wsl.md §0** (G03 owner). The first table row lists 9 native Windows records as
   "verified, verdict pass". Three of them are not verified: `g03-win-git-ssh-selection` and `g03-win-process-io` are
   blocked / inconclusive, and `g03-win-stale-squat-pipe` is in_progress / inconclusive. Suggested cell: "6 verified /
   pass; git-ssh-selection and process-io blocked / inconclusive; stale-squat-pipe in_progress / inconclusive (§0.1)".
6. **Record wording** (record owners; no status changes):
   - `g04-windows-desktop-lock-probe.json`, `g04-windows-signout-reboot-probe.json`: the `blocked_on` says "none
     available on this macOS arm64 machine". A native Windows host now exists; the owner-driven lock, sign-out and
     reboot are still missing.
   - `g03-wsl-b-other-windows-user.json`: the `blocked_on` still has the pre-2026-10-06 generic text ("in-box client
     version unknown until P-W01 runs").
   - `g03-win-stale-squat-pipe.json`: its top-level status is `in_progress` while the sub-probe `cross_user_presquat`
     is `blocked`. Under the multi-row rule the top-level status would be `blocked`. This is the record owner's call.
7. **progress.md M00-T02 row** (orchestrator). Suggested notes text: "Committed in d096a64; recheck 5b2c0a3 (M1,
   m1-m9); fix2 (not yet re-checked): matrix v1 with pins and record statuses, compare classes, upstream/tags/excerpts
   checks, A01-A04, tag pins. Owner items E6, E8".
8. **Integration with the concurrent G04 P5 task** (orchestrator). When its CTK record update is committed, re-check
   matrix row 3 and M5. The status stays `blocked` in that working copy too.

## Limits

- `compare` exits 2 today because S26 changed and S28's counters moved. That is not a fetcher defect, and S28 will
  keep firing CONTENT.
- A01-A04 have only a same-day pair of runs.
- Branch drift is observed at a moment; the commits behind it were not looked up.
- Release asset digests are not recorded.
- The gate-evidence status of a matrix row is this task's conservative aggregation over existing records. It
  changes no record. Product labels stay `not-tested`.
- Fetch results hold for this host and these minutes only. The recheck saw a transient 403 window; none occurred
  today.
