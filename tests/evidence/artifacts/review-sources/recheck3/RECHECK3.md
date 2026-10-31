# M00-T02-recheck3 — independent review

**Verdict: not verified for full closure.** The fix3 mechanisms pass the executed command and crafted-case checks, but n4 has a remaining text-loss case, and the newly exercised policy needs a recorded disposition for gate-relevant drift, especially S34 and S29. No blocker. One major gate-policy follow-up and two minor findings below. This does not invalidate the immutable pins, nor establish a failure of Heimdall code.

Scope: current uncommitted diff in docs/sources, ADR-0003 and matrix; judged against RECHECK2 section F. Reviewed file hashes are in `reviewed-hashes.json`; they were unchanged at the final check. Inputs also included plan.md and the current G04 CTK record. Fix3's report was routing context, not proof. No tracked file was edited, and no commit/push or native probe was run. All writes are in this directory. No delegation: this is the assigned review sub-agent.

## Per-finding resolution

| RECHECK2 ID | Resolution | Independent assessment |
|---|---|---|
| n2 | resolved | Off-pin IDENTICAL rows print without --all; header counts them; actual CLI returns 5. Real fresh-vs-fresh returns 5 with 25 off-pin spec+aux sources. CLI mixed cases prove 2 > 3 > 5; on-pin RAW_ONLY returns 4; identical returns 0. Documentation consistently distinguishes comparison class from pin integrity and specifies baseline comparison for policy decisions. |
| n3 | resolved | Actual crafted compare returns 2 for both 404 and 410 after a successful reference, and MISSING; upstream 404 returns 2. 503 remains fetch failure. Precedence over fetch failure passes. Persistent failures at least 24 hours apart are a documented manual escalation, not automatic state retained by the tool. |
| n4 | partly | Original examples with explicit body or a non-head start tag now work; scripts/styles remain suppressed and selftest passes. A valid omitted-head/omitted-body case with direct body text still becomes empty. See R3-1. |
| n5 | resolved in mechanism/policy | Exit 4 explicitly leaves claim interpretation unverified; a drifted source with zero fragments returns 2. Human reread and dated disposition are required before relying on main. This is a sound distinction; S34 demonstrates why the human step matters. Applying the rule to this live drift remains incomplete (R3-2). |
| n6 | resolved | Matrix names both coarse WSL records and the missing per-row status maps; row 10 names interactive Ctrl-C and PTY-resize operator input. It preserves top-level record observations without upgrading the row. |
| n7 | resolved | Row 9 names both operator and unimplemented harness, with G04 §8.2 P-W1/P-W2 reference. No implication that owner attendance alone unblocks it. |
| n8 | resolved | Cooperative deadline plus daemon-thread backstop, default 120 seconds plus documented 5-second grace, bounds caller waiting; stdout is line-buffered. Independent crafted CLI with stalled opener and 0.05-second deadline returns 3, and built-in trickling/stalled/cooperative tests pass. Abandoned threads are not forcibly canceled; the limit is per source, not whole-run or complete cancellation of outstanding I/O. This is documented. |
| n9 | resolved | Crafted CLI fetch gives 0/2/3; a GitHub mismatch beats a separate failed fetch; failed HTTP response is not itself a blob integrity failure. Input/usage codes remain separate. |
| n10 | resolved | Independent start/end boundary negatives and punctuation/emphasis positive pass; all 91 pinned excerpt fragments still pass live pinned attribution. |
| n13 | resolved | All seven branch raw URLs and refs are recorded. They agree with derivation/selftest. Real upstream ran all seven, including S19/S27/S29; no previously unlisted endpoint needed. Runtime validates a present URL; its backwards-compatible acceptance of an absent field is not a defect for this populated manifest. |

## New/residual findings

**R3-1 — minor, n4 incomplete: direct body text after omitted tags is lost.** `normalize(b'<html><head><title>Title</title>Hello world</html>', 'text/html', 'u')` returns `''` (see `finish-checks.out`). HTML permits omitted head/body end/start tags here; text itself starts the body. `_TextExtractor` only ends the head on a non-head start tag, never on non-whitespace character data outside title/script/etc. As in original n4, later real changes can become RAW_ONLY against an already-empty fetched reference. Short-text warning helps detect this but does not restore content. Add a small regression and handle direct body text while preserving title/script suppression. This is a residual old defect, not a newly demonstrated regression on current sources.

**R3-2 — major, gate-policy disposition required: S34 has meaningful authorization drift despite intact quotes.** `claim-S34.out` compares pinned and current contextual passages. Pinned text describes ordinary pairing without management authority. Current main says default grants include access/relay management and explains that shell/full-access agent capability can mint a fully scoped session. The three selected fragments survive, hence upstream returns the exit-4 class for S34. The narrow statements about attenuation and projects not being sandboxes still hold, but treating them as proof of limited-client isolation would miss this adjacent qualification. G07 explicitly asks whether pairing avoids unlimited owner authority and tests privileged management by limited clients (plan.md §3 G07); matrix row 13 cites S34. Record a dated reread identifying this qualification and reopen/retain the G07 authority-boundary investigation. Keep the immutable pin if that is the experiment's baseline; do not silently promote main's current defaults into the Heimdall contract. This is a source/gate follow-up, not evidence that the fix3 fetcher or an implemented Heimdall permission check is insecure.

**R3-3 — minor, CTK M5 summary conflates run coverage.** Row 3 explicitly confines successful fixture login to v3 and agrees with the current record: unlocked verified/fail, lock blocked, overall blocked/fail; signer-selection limit fails and D4/further real-store authority is unresolved. M5 compresses this to “CTK (two unlocked runs) ... signs and logs in”, which can imply both runs demonstrated login. The record says v1 login was unmeasured because of the probe defect; v3 measured it. Add “login in v3” to M5. No status inflation and no need to rerun CTK to fix this wording.

## Policy and live drift assessment

The CONTENT/GONE/MISSING baseline rule is consistent with plan §1.4 (preserve snapshots/commit references for relied-upon mutable docs), G01 version baselines, G02 pinned experiments and ADR-0003's reproducibility purpose. It is conservative and workable **as a review trigger**, not an automatic declaration that behavior is invalid or that every experiment needs rerunning. Off-pin identical text belongs to documented pin maintenance; fresh-vs-fresh exit 5 is not sufficient to classify baseline drift. Keeping immutable experiment pins is essential.

I independently reproduce **21/34 CONTENT**, 8 IDENTICAL, 2 RAW_ONLY and 3 MARKER_ONLY; no failed/gone/missing spec sources. Additionally **4/4 auxiliary sources are CONTENT**. The latter matter to open G02/G06 and should join the disposition ledger. All 31 old snapshots verify; this is live movement, not baseline corruption. Examples of false alarms at claim level: S04/S10/S30 gained OpenBSD-8.0 navigation; S01/S02/S05 have navigation/footer or small unrelated edits; Iroh pages gained navigation and a back-to-top label; 1Password pages moved assistant text. Thus bulk repinning or bulk marking gates failed would discard useful evidence.

Contextual reread coverage (artifacts `claim-Sxx.out`, `claim-Axx.out`, fresh allowed GETs):

| Still-open gate area | Sources examined in context | Result |
|---|---|---|
| G01/G03/G04/G07/G09 SSH config, certs, provider lock, endpoint trust | S01-S07, S10-S13, S30 | Quoted claims still hold: first-value and Match exec semantics; -G evaluation; multiplex stop; CA/principal/validity controls; approvals versus private-key availability; WSL uses Windows ssh/config; same-user/root agent trust. S03 is unchanged. Source text is not native behavioral proof. |
| G02/G06 bindings, privacy, transport | S14/S15/S19-S22, S27-S29, A01-A04 | Endpoint identity/routing separation, reusable tickets/IP disclosure, relay metadata, Rust and JS platform limitations, community experimental Go/Linux musl and source-only C claims hold. Pigeons and Bubble Tea branches equal pins. Rust/JS/aux CONTENT is navigation in inspected diffs. S29 requirement changed as below. |
| G07 remote route/supervision/authority | S16-S18/S34 branches and pinned excerpts | Route-independent identity and nonreplayed mutations hold; retry detail evolves. S18 adds an automation-webhook forwarding exception; ordinary HTTP/WebSocket session distinction and tunnel lifecycle quote remain supported. S34 has the material adjacent management-default qualification in R3-2. |

All 91 fragments were found in fresh copies of their **pinned** sources. Contextual checks of the live mutable sources found their fragments too; the only missing branch fragment is S29. These are bounded claim checks, not a full upstream implementation audit.

S29 was handled honestly as a lost fragment, exit 2, without rewriting its baseline: current HEAD requires Zig 0.17.0 while the pinned README requires 0.16.0. The broad TS/native TUI claim still holds. Fix3 records the distinction and leaves gate applicability unanswered. **G02 is plainly applicable**: OpenTUI is its candidate and distribution/toolchain evidence is part of that gate. The orchestrator should record whether G02 continues testing pinned OpenTUI or upgrades. With the pin retained, old Zig 0.16.0 evidence remains historical and valid for that pin; adopting HEAD requires checking its 0.17.0 build path. A broad “claim holds” note alone does not discharge the explicit upstream-exit-2 reopen rule. This is an integration disposition, not authorization to repin.

Recommended integration: fix R3-1/M5 wording; record a compact source-to-gate ledger for 21 spec + 4 aux changes, distinguishing claim unchanged from changed/inconclusive; explicitly assess S34 for G07 and S29 for G02. Cite this dated reread for the unchanged claim contexts while retaining pinned references. Reopen/retain investigations only as the policy prescribes; avoid retroactively erasing measured results. No repinning performed.

## Executed commands and actual exit codes

`T = /opt/homebrew/bin/python3.13 -I docs/sources/tools/fetch_pins.py`. `run_review.py`, `crafted.py`, `claims.py` and `finish_checks.py` are review harnesses; command outputs are adjacent `.out` files. Commands against the tool run as subprocesses with their true return codes, not simulated printed exits. Crafted HTTP bodies are injected only in isolated test processes; they do not count as native or live-server evidence.

| Command/check | Actual exits |
|---|---|
| T selftest | 0 |
| T verify for all committed S/A snapshots (31 commands) | 0 each |
| T excerpts --set all | 3 (7 GitHub copies intentionally unchecked) |
| T excerpts --set all --fetch-git | 0 (38 sources, 91 fragments) |
| T tags --out ... | 0 (14 equal tags) |
| T upstream --out ... | 2 (S29 lost fragment; S16/S17/S18/S34 drifted with quotes intact; S19/S27 same) |
| T fetch --set all --out fresh.json --snapshots-dir <owned temporary directory> --snapshot-ids <38 IDs> | 0 (38 HTTP 200, 7 pinned blobs match); temporary directory removed |
| T compare fetch-baseline.json fresh.json --all | 2 (21 CONTENT; four aux EXTRA informational) |
| T compare fetch-baseline-aux.json fresh.json --all | 2 (4 CONTENT; spec EXTRA informational) |
| T compare fresh.json fresh.json | 5 (25 off-pin, IDENTICAL rows visible) |
| Crafted CLI compare same / raw-on-pin / off-pin / failure / content / 404 / 410 / missing | 0 / 4 / 5 / 3 / 2 / 2 / 2 / 2 |
| Crafted CLI compare mixed precedence: content+failure+offpin / failure+offpin / offpin | 2 / 3 / 5 |
| Crafted CLI fetch success / blob mismatch / HTTP failure / stalled deadline | 0 / 2 / 3 / 3 |
| Crafted CLI upstream same / drift intact / lost / no quotes / gone / HTTP failure | 0 / 4 / 2 / 2 / 2 / 3 |
| Independent helper precedence + omitted-head/word-boundary assertions | 0 (crafted.py overall; cases in crafted-summary.json) |
| Contextual live GET/fragment/diff inspection (claims.py) | 0; 38 sources plus 7 branches inspected |
| Final hashes, git diff --check, cleanup (finish_checks.py) | 0; no reviewed-byte changes |
| Default Python S01 fetch --deadline 10 | 3 (URLError) |

Environment: default Python 3.15.2 / OpenSSL 4.1.0 reproduced the reported S01 failure. Alternative Python 3.13.18 / OpenSSL 3.5.9 completed every live fetch above. I did not independently extract the default interpreter's underlying TLS alert; the observed tool error is URLError. No Python 3.14 baseline rerun. First crafted harness attempt incorrectly constructed the expected on-pin case and failed its assertion; the fixture was corrected, and the full harness then passed. That was reviewer test setup, not a tool failure.

## Write/validation boundaries and limits

Only this recheck3 directory was created/changed. Full source snapshots and temporary crafted inputs were deleted; compact contextual excerpts, result hashes, command outputs and harnesses remain as requested evidence. Recorded diagnostic checkout paths were sanitized before finalization. No build outputs were produced. No archive/API requests, package installation, real credential/agent/keychain contact, native lock tests, baseline edits, commits, pushes, or gate-status mutations. Live observations hold for this run only. `git diff --check` passed; reviewed source hashes stayed fixed.
