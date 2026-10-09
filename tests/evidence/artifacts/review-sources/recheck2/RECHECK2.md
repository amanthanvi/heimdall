# M00-T02-recheck2: independent re-review of the M00-T02-fix2 working tree

- Subject: the uncommitted fix2 changes to `docs/compatibility/matrix.md`, `docs/decisions/0003-source-pins.md` and `docs/sources/**`, plus `tests/evidence/artifacts/review-sources/fix2/`. Input findings: `../recheck/RECHECK.md` (M1, m1-m9; committed in 5b2c0a3). Task row: plan.md:264.
- Reviewed bytes. All of these were unchanged since fix2 finished (mtime 06:10-06:16Z), before this recheck began at about 07:05Z:

  | File | sha256 |
  |---|---|
  | matrix.md | `f99c4707fcc1cd9f6f742511494e33821a7c12869a9047b15bd91695ecaabe89` |
  | 0003-source-pins.md | `82ade630677646b7c4ef162bf8350db00fba7afa4f425a8e8126491108476bcc` |
  | pins.json | `3490520c1988ef433bd06d247c7f674b7f158de8252cbb44a772fd40445a4a02` |
  | fetch_pins.py | `b022eea3872888c08d281462fd7545ba3d64488f0888f10a5a96fcd71ef63ddf` |
  | sources/README.md | `b624eb196542a30af1a385ac13b29e8b10d05c89ee010418182ae9934218ebee` |
  | notes.md | `242cdea31d9a3da61fde3955ba329aa80076abb2a79882ba49eb1f48ba955b66` |
  | snapshots/README.md | `cc27b7bc04b473d5a484536b5bd580c998ce756362aa13eba99dcaef62532ead` |
  | fetch-baseline-aux.json | `c871c698c743e60ca7d22e886278317a49e7f5047e446921ad1428476ae534b4` |
  | A01.txt.gz | `7a88d85e…` |
  | A02.txt.gz | `d8f1fd69…` |
  | A03.txt.gz | `2631bddb…` |
  | A04.txt.gz | `8386d5f4…` |

- Repository HEAD: fix2 was written against a008fd0; this recheck started at 9b3f665 and ended at 91f7a0d. None of the commits between them touches the reviewed files.
  - 9b3f665 (06:18Z, two minutes after matrix.md was last written) changes ADR-0001 §5 and g03 §0, following fix2 escalations 4 and 5.
  - 34ffe3e and 26fed81 commit the G04 P5 CTK record.
  - 91f7a0d updates progress.md.
- Run on 2026-10-09 between 07:05 and 09:30 UTC, on darwin with Python 3.14.8 (the baseline used the same version).
- Rules followed:
  - HTTP GET only, and only to URLs that are listed in `pins.json`. `urls.out` lists every URL the subcommands would fetch.
  - The three `upstream` URLs that are not listed (S19, S27 and S29 at `HEAD`) were not fetched.
  - `SSH_AUTH_SOCK` was unset for every network command.
  - Scratch went to `/tmp/hm-recheck2-*`, outside the repository; it was deleted at the end. `<tmp>` stands for it in the outputs.
  - Nothing under `docs/` was changed, and nothing was committed.
  - Repository content and downloaded pages were treated as data.

## Verdict: VERIFIED, on condition that these bytes are committed

Every RECHECK finding has a fix that is present and correct. M1, the only major, is resolved.

- The matrix is now built (v1). Its delegation is recorded in three places: matrix.md:5-8, ADR-0003:108-113 and `docs/sources/README.md`:51-53.
- I traced 20 matrix cells to their records. This covered every Windows and WSL row (7, 8, 9, 10, 11 and 16) and their observation cells. No cell is higher than its record supports, and every non-native platform is `blocked` with a named missing input.
- My own real re-run reproduces the fix2 numbers:
  - compare against the baseline: IDENTICAL 15, RAW_ONLY 10, MARKER_ONLY 7, CONTENT 2 (S26, S28), FETCH_FAILED 0;
  - `primary_same=yes` for 32 of 34;
  - all 31 committed snapshots verify;
  - fresh snapshots are byte-identical except S26 and S28;
  - A01-A04 are identical; all 14 tags are the same;
  - every one of the 91 excerpt fragments is found in its own pinned copy.

  S26 and S28 changed upstream and are expected mutable-document changes. The committed snapshots still hold the pinned text.

- E6, E8 and the new E9 are presented as open everywhere.
- I found no blocker and no major. The new findings are minor or nits, listed in section F.
  - Four of them are text-only and can be fixed at commit time without another recheck: n1 (a matrix paragraph made stale by 9b3f665), n15 (matrix row 3 and M5, made stale by the P5 commit 34ffe3e), n11 and n12.
  - The rest are follow-ups to the drift tooling and the matrix. They do not change any status.

Conditions for setting M00-T02 to `verified`:

1. The orchestrator commits the reviewed bytes. They may differ only by the text-only fixes for n1, n15, n11 and n12.
2. progress.md:9 is updated, and ADR-0003:3 ("has not been re-checked") is updated to cite this recheck.

## A. RECHECK findings: is each fix present, correct and complete?

| # | Fix location | Present | Correct | Complete | Evidence (this recheck) |
|---|---|---|---|---|---|
| M1 (major) | matrix.md:3-8 (delegation), :10-31 (three statuses; aggregation rule), :41-58 (16 rows with pins), :63-150 (row notes), :152-211 (W1-W12, L1-L13, M1-M5), :213-228 (G02), :230-242 (floors); ADR-0003:108-113; sources README:51-53 | yes | yes | yes, apart from n1 (stale after 9b3f665), n15 (stale after 34ffe3e), n6, n7 | Section D: 20 cells traced, 0 overclaims. Labels are all `not-tested` (ADR-0001 §9). The tally of 14 `blocked` and 2 `not_started` rows matches the table. `fix2_static_rerun.out`: fix2's own consistency check, re-run on this tree, gives 412 ok and 0 failed (exit 0). |
| m1 | fetch_pins.py:21-44 (classes, exits), :429-463 (`classify`, `compare_exit`), :480-532; README:27-42; ADR-0003:15 | yes | yes: marker-only, raw-only and fetch failure are separate; selftest exit 0 | partly: n2 (exit ignores `primary_same`), n3 (gone vs transient) | `03_compare_base_run1.out` (exit 2): the 7 marker-only sources (S06, S09, S12, S24, S31-S33) are now MARKER_ONLY, not content. `honesty.out` H3, H5 and selftest cover the 403 and blob cases. |
| m2 | fetch_pins.py:47-56, :257-267, :558-597; pins.json:644, :687, :730, :1406 (notes); ADR-0003:16, :137-143; README:47 | yes | yes | partly: n5, n13 | `09_upstream_listed.out` (exit 4): S16 3f9e64b, S17 35c8b0a, S18 4f3e062 and S34 132b655 drifted from the pinned blobs 43d96f8, 301e1e0, 367d911 and 2428783; fragments 2/2, 2/2, 3/3, 3/3. Same values as ADR-0003:138-143. |
| m3 | pins.json:975 (`primary_change`); ADR-0003:12, :116; README:46 | yes | yes | yes | S23 is RAW_ONLY with `primary=norm primary_same=yes` (raw 46148 to 45864 bytes, text identical). `static2.out`: the pinned hash values are unchanged from HEAD; only the primary kind moved. |
| m4 | pins.json:4 and `legacy_*` fields; ADR-0003:14, :117-118; notes.md:3, :58 | yes | yes | yes | `static2.out`: for each of the 6 `.md` sources, `legacy_raw_body_sha256_v1` equals the baseline raw hash; 21 sources have `raw_reproduced_vs_v1_pin`; no `pin.value` holds a bare 64-hex hash. |
| m5 | pins.json:1938 (`auxiliary_sources`); `fetch-baseline-aux.json`; snapshots A01-A04; ADR-0003:66-74, :99; notes.md:47-51 | yes | yes | yes (only a same-day stability record exists, as stated at ADR-0003:163) | `07_fetch_aux` exit 0; `08_compare_auxbase_aux` exit 0 (4 identical). Fresh A01-A04 snapshots are byte-identical. Excerpts 12/12. A02 contains "still considered experimental"; neither A01 nor A02 contains "highly experimental" or "cgo". |
| m6 | ADR-0003:77; pins.json:2064 | yes | yes | yes | The text scopes the review to what it checked, cites the recheck for the LICENCE, d5bfd5c and the tarball, and lists what only the producer observed. |
| m7 | pins.json:1681 (`e6_facts`), :1738; ADR-0003:127-133; notes.md:42-45 | yes | yes | yes; E6 is not decided | The facts match `g03-win-env-inventory.json`. Client-path counts per record show that only `g03-win-sshauthsock-selection` and `g03-win-identityagent-forms` exercise the MSI and MSYS clients. The five WSL Mode A records carry the r3-msi10 limitation. "Other probes used 9.5p2 only" holds. |
| m8 | pins.json:1782 (`tag_pins`, 14); ADR-0003:17, :79-93 | yes | yes | yes; asset digests are stated as not recorded | `10_tags.out` (exit 0): 14 SAME. `static2.out`: every `commit` and `ref_sha` is 40-hex; lightweight tags have ref equal to commit, annotated tags have a different ref. |
| m9a-e | pins.json:4 (WITHDRAWN); :1758 (reopen conditions in v2 terms); :991 (S24 ellipses); ADR-0003:13 (pairs sentence dropped); fetch_pins.py:66-79, :688-738 (`excerpts`) | yes | yes | yes | `11_excerpts_all_git` exit 0 (38/38 sources, 91 fragments). `12_excerpts_all_nogit` exit 3, with the 7 GitHub sources unchecked, as documented. |

## B. Commands run and real exit codes

Run from the repository root by `run.sh` (`steps.log` holds the UTC windows). Each output file ends with `exit=`.

| Step | Command (`T = python3 -I docs/sources/tools/fetch_pins.py`) | Exit | Result |
|---|---|---|---|
| 01 | `T selftest` | 0 | all checks passed |
| 02 | `T fetch --out <tmp>/run1.json --snapshots-dir <tmp>/snap1 --snapshot-ids <27 ids>` (07:21:08-07:53:40Z) | 0 | 34 × HTTP 200. S03 alone took 32 min (n8). |
| 03 | `T compare docs/sources/fetch-baseline.json <tmp>/run1.json --all` | 2 | IDENTICAL 15, RAW_ONLY 10, MARKER_ONLY 7, CONTENT 2 (S26, S28). `primary_same=no` only for S26 and S28. |
| 04 | `T fetch` again, run2 (07:53:40-07:53:56Z) | 0 | 34 × 200 |
| 05 | `T compare run1 run2 --all` | 0 | 34 identical. S26 and S28 still show `primary_same=no` (see n2). |
| 06 | `T compare fetch-baseline.json fetch-repeat.json` | 0 | 34 identical (offline) |
| 07 | `T fetch --set aux --out <tmp>/aux1.json --snapshots-dir … --snapshot-ids A01,A02,A03,A04` | 0 | 4 × 200 |
| 08 | `T compare docs/sources/fetch-baseline-aux.json <tmp>/aux1.json --all` | 0 | 4 identical, `primary_same=yes` |
| 09 | `T upstream --only S16,S17,S18,S34 --out …` | 4 | 4 drifted, all fragments present (S19, S27 and S29 not run: their URL is not listed) |
| 10 | `T tags --out …` | 0 | 14 SAME |
| 11 | `T excerpts --set all --fetch-git` | 0 | 38/38 checked, 91 fragments, 0 not found |
| 12 | `T excerpts --set all` | 3 | 7 GitHub sources unchecked, as documented |
| 13 | `T verify --fetch-result <baseline> --id <id> --snapshot docs/sources/snapshots/<id>.txt.gz`, for the 27 spec snapshots and the 4 aux snapshots | 0 × 31 | all match (`verify_snapshots_all.out`) |
| 14 | `T compare` (no arguments) | 64 | usage error |
| 15 | `T compare <baseline> <missing file>` | 1 | input error |
| 16 | `T compare … --pins <missing file>` | 1 | input error |
| 17 | `T verify --id S25 --snapshot S26.txt.gz` | 3 | MISMATCH (negative control) |

Other checks:

| Check | Output | Exit | Result |
|---|---|---|---|
| Fresh vs committed snapshots | `snapshot_cmp.out` | 0 | run1 vs committed: 25/27 equal (S26, S28 differ). run1 vs run2: 27/27 equal. aux vs committed: 4/4 equal. |
| S26 and S28 change size | `fresh_excerpts.out` | 0 | S26: 12 word-ops in the Fast-mode / EU data-residency passage; excerpt fragments 5/5 still present. S28: 8 counter tokens; 1/1 present. |
| Offline consistency (mine) | `static2.py` → `static2.out` | 0 | pins vs baselines, snapshots, HEAD hash values unchanged, tag ids, snapshot file set (31): 0 failures |
| fix2's static check, re-run on this tree | copy of `../fix2/static_check_fix2.py` → `fix2_static_rerun.out` | 0 | 412 ok, 0 failed |
| Evidence-record dump | `records.py` → `records.out` | 0 | |
| URL inventory | `urls.py` → `urls.out` | 0 | 52 URLs listed in pins.json; 3 `upstream` HEAD URLs not listed (not fetched) |
| Exit-code honesty probes (offline, using the tool's own functions) | `honesty.py` → `honesty.out` | 0 | see section C |
| Text inside `<script>`/`<template>`/`<noscript>` on 10 HTML sources (10 GETs of listed URLs) | `script_text_probe.py` → `script_text_probe.out` | 0 | see section C |
| Canary-prefix scan of the changed files, fix2, snapshots (decompressed) and this recheck's outputs | `canary.py` → `canary.out` | 0 | 218 files, 0 hits |

## C. Exit-code honesty, per subcommand

Does any class call a content change harmless, or the reverse?

- **compare, cases where the label is correct** (`03`, selftest, `honesty.out`):
  - A change in the visible text of an HTTP 200 page is always CONTENT, exit 2.
  - A git blob mismatch with identical text is CONTENT (H5). This is deliberately fail-safe.
  - A 403 bot challenge is FETCH_FAILED (exit 3), no longer reported as content.
  - MARKER_ONLY and RAW_ONLY (exit 4) mean that the normalized text is identical. That is true by construction, with the exceptions below.
- **compare, cases where a real change gets a milder class:**
  - (a) A cited page that disappears (404 or 410) is FETCH_FAILED, exit 3 (H3). ADR-0003:155 and pins.json:1758 say "FETCH_FAILED means re-run, not drift", so a removed page never reaches a reopen condition (n3).
  - (b) Text inside `head`, `script`, `style`, `noscript`, `template` or `svg` is outside the normalizer, so a change there is RAW_ONLY (H6). This scope is documented. On 10 HTML sources (`script_text_probe.out`), the prose found only inside scripts was site navigation and descriptions of other pages, not the cited body text. I found no current instance of hidden cited content. The probe is heuristic.
  - (c) Latent: a page that omits the optional `</head>` normalizes to an empty string (H7). After the first CONTENT transition, every later change on that page would be RAW_ONLY (n4). No current source is affected: every HTML source has at least 2202 normalized characters.
- **compare, the reverse direction:** S28's live counters are CONTENT on every run. This is documented (README:36, notes.md:60). A change in Python's `html.parser` or `unicodedata` would also give CONTENT; also documented (ADR-0003:162).
- **compare, `primary_same` is not part of the exit code** (n2):
  - A raw-primary source (S01-S05, S10, S30) whose bytes or markers move gets exit 4 ("text identical") with `primary_same=no` (H1, H2). ADR-0003:155 and pins.json:1758 make `primary_same=no` a reopen trigger. README:35 says MARKER_ONLY is never drift.
  - Comparing two fresh files gives exit 0 "all identical" while S26 and S28 are off their pins (`05`, H4). Without `--all`, those lines are not printed at all. fix2's own `final_compare_runA_runB.out` shows only the header and exit 0.
  - Nothing labels a changed text as identical here. The pin-integrity signal is simply not in the exit code.
- **upstream:**
  - Exit 4 is a changed upstream file whose quoted fragments survive. Each GitHub source has only 1 to 3 fragments, and a drifted file with 0/0 fragments also gives 4 (H8).
  - fix2's README calls this "benign drift" (:30, :96), and the reopen rule ignores it (ADR-0003:156). A surviving quote does not show that the claim still holds (n5).
  - A file deleted on the branch (404) is exit 3, a fetch failure (H9).
- **tags:** honest. Moved or missing is 2, fetch failure or invalid advertisement is 3, unpinned is 4. A re-created annotated tag on the same commit counts as moved (fail-safe).
- **excerpts:** honest (2 = not found, 3 = unchecked). Matching is a substring test without word boundaries, so a false "found" is possible (H10, n10).
- **fetch:** exit 1 means a non-200 response, a GitHub blob mismatch (an integrity failure) or an input error (n9).
- **verify:** honest (0 or 3; 1 on a traceback, for example an unknown id).

## D. Matrix trace (cell → record → multi-row rule)

Status values are from `records.out` and the record fields named below. "Not higher than the record" is judged against the record's own top-level status and its per-row map, where one exists.

| Cell | Matrix says | Record(s) and what they support | OK? |
|---|---|---|---|
| Row 7 gate (Windows, Win32-OpenSSH, agent service) | blocked | W1-W3, W7-W9 `verified`; `g03-win-stale-squat-pipe` `in_progress` (sub-row `cross_user_presquat` blocked); `g03-win-process-io` `blocked` (operator); `pipe-acl-other-user` `blocked`; `agent-constraints` `blocked`. Lowest is blocked. | yes |
| Row 7 "Observed" | inbox 9.5p2 / 9.5.6.3; MSI 10.0p2 / 10.0.0.0 first on PATH; build 26300.9550; non-elevated | `g03-win-env-inventory.json` (`ssh_candidates`, `path_order`, `host.services`, `elevated: false`) | yes |
| Row 8 gate (1Password pipe) | blocked; disposable 1Password account on a disposable host, `-AllowProviderContact`, admin for the service sub-probe | `g03-win-1password-coexistence.json` `blocked`, `blocked_on` has the same inputs. "Which process serves the pipe was not determined" is consistent: no record identifies the pipe server. | yes |
| Row 9 gate (Windows managed recipe) | blocked; owner-driven lock, sign-out and reboot | `g04-windows-desktop-lock-probe` and `g04-windows-signout-reboot-probe` are `blocked`. Their commands are "planned … not yet implemented", so the named missing input is incomplete (n7). | status yes; text incomplete |
| Row 10 gate (WSL Mode A) | blocked; UAC operator (L7); a host without the default pipe for the P-A01 unset-variable sub-row | L1-L6 `verified`; `g03-wsl-a-elevation` `in_progress` (operator); `executable-selection` skipped `unset_var_identityagent` by design. Blocked holds. `g03-wsl-a-process-io` also left Ctrl-C and PTY resize unrun, which the row does not mention (n6). | status yes; text incomplete |
| Row 10 "Observed" | 9.5p2 in r2; 10.0p2 in r3-msi10 for P-A01-P-A05, same status and criteria; git 2.43.0 | The r3-msi10 limitation appears in all five Mode A records; `g03-wsl-env-inventory.json` has `git version 2.43.0` | yes |
| Row 11 gate (WSL Mode B) | blocked | L9-L12 `verified`; L8 `g03-wsl-b-endpoint-perms` `in_progress`; L13 has 5 `blocked` records, and each `blocked_on` matches the inputs listed in the row note | yes |
| Row 16 gate (Git for Windows) | blocked | W2 and W3 `verified`; W4 `g03-win-git-ssh-selection` `blocked` (a disposable host with an empty `.ssh`) | yes |
| W2 | verified / pass; MSYS `ssh-add` opened the pipe as a file and sent no request | `g03-win-sshauthsock-selection.json`: `verified`/pass. The Git `target` row has `connections: 1, request_identities: 0`, and stderr is "Device or resource busy". The non-ASCII statement comes from the record's [O] supplementary diagnostic. | yes |
| W5 | in_progress / inconclusive | top-level `in_progress`/`inconclusive`; the matrix names its blocked sub-row (matrix.md:21-23, :99-100) | yes |
| W6 | blocked / inconclusive; 151-190 ms; Ctrl-C and resize not run | `blocked`/`inconclusive`; `ssh_true_wall_ms` [156, 190, 151] | yes |
| W7 | verified / pass | `verified`/pass. The `%%` statement is about the known_hosts path, not `-F` (n12, nit). | status yes |
| L3 | verified / pass | `g03-wsl-a-process-io.json` `verified`/pass (the cell copies the record; see n6) | yes, not higher than the record |
| L7 | in_progress / inconclusive | `in_progress`/`inconclusive`; `unobserved: no_uac_prompt_observed` | yes |
| L13 | blocked (5) | 5 records `blocked` | yes |
| Row 1 gate (macOS, native agent) | blocked | `m00-t03-fixtures.json` per-fixture rows 1-5 `verified`, with `IdentityAgent none`; no record exercises the agent. Blocked on ADR-0001 §6. More conservative than the record. | yes |
| Row 3 / M5 | blocked | `g04-macos-secure-enclave-ctk-probe.json` is `blocked` at a008fd0 and still `blocked` at 34ffe3e, now with verdict `fail` (row `unlocked`: `in_progress`/fail; row `lock`: `blocked`). The other five `g04-macos-*-probe` records are `blocked`. | status yes; text stale after 34ffe3e (n15) |
| M3 | verified / pass, pass, fail | after-expiry pass, stop-race pass, preconnected-after-stop `verified`/fail | yes |
| G02 windows-x64 | Go verified / fail 67/71; Rust verified / fail 68/71 | `g02-go-x1-windows` gating_pass 67/71; `g02-rust-x1-windows` 68/71 | yes |
| Floors, Windows | blocked; G01 clean-machine; E6 | consistent with ADR-0001 §5 at 9b3f665. The paragraph below the table (matrix.md:240-242) is stale (n1). | status yes; text stale |

Non-native platforms are `blocked` with the missing platform named: rows 4, 5, 6 and 13 (native Linux hosts), row 2 (a disposable 1Password account), and the floors (G01 clean machines). Docker Desktop VM containers and WSL2 Ubuntu are explicitly said not to count as Linux hosts (matrix.md:91-92, :222-223). No row is above `blocked` or `not_started`.

## E. Owner items

- **E6 is open:**
  - ADR-0003:127-133 ends "not decided here";
  - pins.json:1738 (E6) and :1672 (`status_of_e6`);
  - matrix.md:107-108 ("Open owner item") and :236;
  - notes.md:42 ("not a decision");
  - progress.md lists E6 under "Still open from the owner".
- **E8 is open:**
  - ADR-0003:135 ("the owner's decision, still open");
  - pins.json:1748 ("not decided here");
  - snapshots/README.md:14 ("E8 is still open", now covering A01-A04);
  - progress.md.

  fix2 committed four more third-party snapshots (A01-A04) while E8 is open. This is disclosed and consistent with E8's scope, which concerns publication.
- **E9 is new and open.** It is a wording correction for ADR-0002:373, assigned to the orchestrator or ADR owner (ADR-0003:136, pins.json:1753). It is not presented as decided.

  At the time of this recheck, ADR-0002 has an uncommitted edit applying E9's suggested text (mtime 06:18Z). That edit is not part of fix2, and this recheck did not review it (n14).
- None of these is decided in any reviewed artifact. This recheck does not decide them.

## F. Findings (new; none blocking)

| ID | Severity | Location | Evidence | Suggested fix |
|---|---|---|---|---|
| n1 | minor (stale) | matrix.md:240-242 | It says "ADR-0001 §5 still says … 'native Windows host' … escalated". Since 9b3f665 (06:18Z), ADR-0001 §5 reads "G01 clean-machine tests (the owner's Windows 11 PC, available since 2026-10-06, is not a clean machine)". Not a fix2 error: the commit landed two minutes after matrix.md was written. | Replace the paragraph with a one-line reference to ADR-0001 §5 at 9b3f665. Text-only; can be fixed at commit time. |
| n2 | minor | fetch_pins.py:456-463 (exit ignores `primary_same`), :498-501, :525-527 (IDENTICAL lines hidden without `--all`); README:34-35 vs ADR-0003:155 and pins.json:1758 | `honesty.out` H1/H2: a raw-primary RAW_ONLY or MARKER_ONLY source gives exit 4 with `primary_same=no`. README says MARKER_ONLY is never drift; the ADR reopens on `primary_same=no`. H4 and `05`: fresh-vs-fresh gives exit 0 with S26 and S28 off their pins. fix2's `final_compare_runA_runB.out` shows only the header and exit 0. | Always print lines with `primary_same=no`. Either give "off-pin" its own exit code, or document that the exit code compares the two files only. Make README:34-35 and ADR-0003:155 state one rule. |
| n3 | minor | fetch_pins.py:433-436 (`classify`), :579-580 (`cmd_upstream`); ADR-0003:155-156; pins.json:1758 | `honesty.out` H3: a cited page returning 404 gives FETCH_FAILED and exit 3; the docs say "re-run, not drift". H9: a file deleted on the branch gives exit 3. A removed source never reaches a reopen condition. | Split 404/410 into a GONE class with exit 2, or add a reopen condition for a source that is FETCH_FAILED on several runs over at least 24 h. |
| n4 | minor (latent) | fetch_pins.py:154-175, :178-189 (no implied end tags) | `honesty.out` H7: `<html><head><title>t</title><body><p>…</p></body></html>` normalizes to `''`. Once a page drops `</head>`, every later text change on it is RAW_ONLY (exit 4). Not triggered by any current source (the smallest HTML normalized text is 2202 characters). | End the head skip at `<body>` or at the first non-head element. Add a selftest case. Optionally warn when an HTML source normalizes to fewer than N characters. |
| n5 | minor (wording, reopen policy) | fix2 README:30, :96 ("benign drift"); ADR-0003:156; pins.json:1758; fetch_pins.py:558-566 | `09` exit 4: the S16-S18 and S34 files changed on `main`. Fragment coverage is 1 to 3 per source (`11` output). 0/0 fragments also gives 4 (H8). A surviving quote does not show the claim still holds. | Call exit 4 "drifted, quotes intact (claim not re-read)". Require a human re-read of the drifted file before relying on `main`, or reopen when a source cited by a still-open gate drifts. |
| n6 | minor | matrix.md:21-23 ("two records are coarser"), :119-122 (row 10 "Blocked on"), :188 (L3) | `g03-wsl-a-process-io.json` is `verified`, yet its limitations say "Ctrl-C … PTY resize … manual steps not run". Its Windows twin `g03-win-process-io.json` is `blocked` for the same steps. `g03-wsl-a-executable-selection.json` is `verified` with `unset_var_identityagent` "deliberately not run". Neither has a per-row map. Row status is unaffected (already `blocked`), and the cells copy the records, so this is not an overclaim. | Name both records as coarser (or add them to fix2 escalation 6 for their owners). Add "an operator for interactive Ctrl-C and PTY resize from a WSL terminal" to row 10's "Blocked on". |
| n7 | minor | matrix.md:113-117 (row 9) | `g04-windows-desktop-lock-probe.json` `commands_or_harness` reads "planned (PowerShell, not yet implemented)"; `g04-windows-signout-reboot-probe.json` reads "planned: see … §8.2 P-W2". The owner cannot unblock the row alone. | Add "the probe harness is not yet implemented (g04 §8.2)" to the row note. |
| n8 | minor (operational) | fetch_pins.py:210-241 (`http_get`: 60 s per socket operation, no overall deadline); :364 (prints not flushed) | `stall_diagnosis.out`: in run1, S03 took from 07:21:10Z to 07:53:20Z. During the stall, curl (IPv4 and IPv6) and a one-off urllib GET of the same URL returned 200 in under 1 s. The result was correct (same raw hash). run2 took 16 s for all 34 sources. Cause not established [U]. | Add an overall per-source deadline that maps to FETCH_FAILED, and flush progress lines. |
| n9 | nit | fetch_pins.py:8-10 vs :19-20, :376 | `fetch` exit 1 covers a non-200 response, a GitHub blob mismatch (integrity) and an input error. | Give a blob mismatch its own exit code. |
| n10 | nit | fetch_pins.py:544-550, :727 | `honesty.out` H10: "is not permitted by default" is found in "this is not permitted by defaults". Low risk with fragments of 12+ characters. | Match `" "+frag+" "` within `" "+copy+" "`. |
| n11 | nit | notes.md:59 | It says S23 was rebuilt "between 2026-10-03 and 2026-10-08". No record dates the change before the 2026-10-09 recheck runs; ADR-0003:116 gives the supported window. | Use ADR-0003:116's window. Text-only. |
| n12 | nit | matrix.md:171 (W7) | "In a directory containing %, only %% works" reads as `-F`. The record's [O] limitation is about the known_hosts path notation. | Say "only the `%%`-escaped known_hosts path works". Text-only. |
| n13 | nit | fetch_pins.py:263-266; pins.json | For S19, S27 and S29, `upstream` fetches `raw.githubusercontent.com/<repo>/HEAD/README.md`, which is not recorded in pins.json. S16-S18 and S34's branch URLs are recorded, as `fetched_url`. This recheck therefore did not re-observe S19, S27 or S29. | Record each source's upstream URL in pins.json. |
| n14 | integration (not a fix2 defect) | ADR-0002:373 (uncommitted, not by fix2); ADR-0003:3, :136; pins.json:1753; progress.md:9 and item 6 (91f7a0d) | ADR-0002 already carries E9's suggested text, uncommitted. progress.md:9 still says the fixes "have not been re-reviewed". progress.md item 6 plans to make the `g03-win-stale-squat-pipe` top-level status `blocked`. If that happens, update the matrix W5 cell and matrix.md:21-23 (no row status changes: row 7 is already `blocked`). | On integration: mark E9 as applied (with the commit), update progress.md and ADR-0003:3, and refresh W5 if that record changes. |
| n15 | minor (stale; text-only) | matrix.md:83-87 (row 3, CTK bullet); :211 (M5) | The matrix describes the CTK record "at commit a008fd0" as blocked on owner authorization, with an updated record "not committed when this matrix was written. Re-check this note and M5 when it is." That record is now committed (34ffe3e): `blocked`, verdict `fail`. It is now blocked on an owner-driven lock/unlock cycle, and a v3 real-store run needs confirmation that D4 covers it. Its finding: `KEYCHAIN_CERTIFICATES` does not limit which identities `ssh-add -K -S` loads. M5 gives no verdicts, while M3 bolds its `fail`. No status changes (row 3 stays `blocked`). | Rewrite the CTK bullet for 34ffe3e. In M5, note that the CTK record is blocked / **fail** and give the limit-clause finding. |

Not defects (checked):

- JSON validity: pins.json, both baselines, `fetch-repeat.json` and `archive-lookups.json` parse.
- No existing `pin_v2` hash value changed against HEAD; only S23's primary kind moved.
- Every snapshot gz and text hash matches its pin. The snapshot file set equals the pinned paths (31).
- `fetch-baseline.json` and `fetch-repeat.json` are unchanged against HEAD.
- Every GitHub permalink is a 40-hex commit, and every baseline blob equals its pinned blob.
- Every tag pin is a 40-hex commit.
- The primary-kind counts (14 raw, 20 normalized, plus 4 aux normalized) match ADR-0003:12 and README:46.
- The raw-stability counts (19 unchanged, 15 changed by 2026-10-09) match pins.json `raw_stability`.
- No canary values found.

## Limits

- Python 3.14.8 only; normalizer stability across versions is not tested.
- The `upstream` results for S19, S27 and S29 come only from fix2 (06:14Z), because their URLs are not listed. `archive` was not run, because archive.org is not a listed URL. No GitHub API, crates.io or npm requests were made: candidate versions, licences and heads were not re-observed (tag commits were).
- Fetch results hold for this host and these minutes. One request stalled (n8). No 403 window occurred.
- Matrix: 20 cells traced, not every cell. Statuses were compared at record level; no probe was re-executed.
- The script-text probe (section C(b)) is a heuristic over 10 sources; it does not prove that no cited text exists only in scripts.
- This recheck covers the working-tree bytes listed at the top; they were re-hashed at 09:25Z and were unchanged. It did not review the uncommitted ADR-0002 edit or the G04 P5 commits, apart from the CTK record's status, verdict and `blocked_on` (n15).
- Incident: while consolidating outputs, a shell redirect whose glob matched its own output file created a self-appending file in this directory, about 164 GB within roughly 2 minutes. I stopped the task and deleted the file at once; disk free space was 1.1 TB afterwards, and the file was never staged. Outputs were then consolidated with Python into `verify_snapshots_all.out`.

## Artifacts (this directory)

Scripts:
- `run.sh` (the runner);
- `records.py`, `static2.py`, `urls.py`, `honesty.py`, `script_text_probe.py`, `fresh_excerpts.py`, `canary.py`, `probe_get.py`.

Outputs, each ending with the real exit code:
- step outputs `01_…` to `17_…` (`.out`), with the 31 `verify` runs in `verify_snapshots_all.out`;
- `steps.log` (exit codes and UTC windows);
- fetch results `run1.json`, `run2.json` and `aux1.json` (temp paths redacted to `<tmp>`);
- `upstream.json`, `tags.json`;
- `static2.out`, `fix2_static_rerun.out`, `records.out`, `urls.out`, `honesty.out`, `script_text_probe.out`, `snapshot_cmp.out`, `fresh_excerpts.out`, `canary.out`, `stall_diagnosis.out`.

Downloaded bodies and fresh snapshots stayed in the scratch directory and were deleted. They are not copied here, because of E8.
