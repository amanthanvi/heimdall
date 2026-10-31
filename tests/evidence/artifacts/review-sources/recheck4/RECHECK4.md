# M00-T02-recheck4 — independent review, round 2

**Verdict: verified.** Fix4 resolves R3-1, R3-2 and R3-3 as raised in recheck3. No new blocker, major or minor finding. This verifies the reviewed source-pin tooling and documentation changes; it does not close behavioral gates or select the implementation language.

Reviewed the uncommitted fix3+fix4 diff against HEAD, the complete new drift ledger, recheck3 findings, fix4 report and relevant plan/spec, ADR-0002 and CTK evidence. The fix4 report was context, not proof. Reviewed source hashes are in `reviewed-hashes.json`; they remained unchanged at finish. This assigned review sub-agent performed its own checks without nested delegation. No tracked files edited, no commit or push, no native probes, builds or real credential/store access. All writes were inside this recheck4 directory. No memory result was used (targeted registry search found no matching entry).

## Finding resolutions

| Finding | Resolution | Reasons |
|---|---|---|
| R3-1, minor, omitted-head direct text | resolved | Original `<html><head><title>Title</title>Hello world</html>` now gives `Hello world`. Both interpreter selftests pass. Twelve independent crafted assertions cover direct character data, entity decoding, inter-element whitespace, comments, title-only/unclosed-title suppression, text after script/style/noscript/template, closed-head and no-head controls. All pass (`crafted-normalizer.out`). Implementation limits the new character-data rule to the implied-head pass, outside a title and with no nested skipped element. |
| R3-2, major, source/gate dispositions | resolved | A 30-row source-to-gate ledger now covers the 21 spec CONTENT sources, four auxiliary CONTENT sources and five changed branches. It distinguishes 26 unchanged claims from four qualifications. Eight independent live contextual/diff checks support the dispositions sampled below. S34 records the changed management defaults and shell/agent authority path, retains the immutable experiment pin and explicitly retains/reopens G07 on that question in the ledger, ADR and manifest. Matrix row 13 carries the qualification and keeps the investigation open. S29 now has the requested explicit G02 disposition, authorized in the task packet: keep the frozen candidate, no re-test, accept its standing exit 2. ADR-0002 supports the stated independent rejection grounds. |
| R3-3, minor, M5 login coverage | resolved | M5 now explicitly says fixture login was measured in v3 only and v1 left it unmeasured. This agrees with the CTK record's U4 and earlier-run text. The blocked/fail status remains; textual correction makes no new native claim. |

## New findings and wording assessment

None at blocker, major or minor severity within this review scope.

S34 wording does not claim that surviving fragments prove limited-client isolation. Live text confirms management is in the default grant and explains session minting through shell or full-access-agent capability. It also preserves attenuation and project-versus-filesystem statements. Ledger/ADR/manifest keep the authority boundary an open G07 investigation; main's defaults are not adopted into Heimdall. This is a recorded source disposition, not an assertion that a native authority test ran or passed.

S29 wording does not claim HEAD was built, tested or adopted. The current README changes the development requirement from Zig 0.16.0 to 0.17.0; the TypeScript/native TUI statement survives. ADR-0002 sections 3 and 3.3 record rejection on child/IPC and Bun 1.4.2 environment-hook security grounds; the rejection stands even without K8. Those grounds do not depend on the README's Zig requirement. The prototype manifest pins `@opentui/core` 0.5.14. Retaining the frozen candidate and declining an upstream re-test is a defensible, explicit orchestrator disposition for this source change. The tool continues to expose the missing fragment with exit 2. No blanket exception suppresses future drift.

## Independent live ledger spot checks

Each `spot-<id>.out` preserves HTTP status, body digest, all changed word blocks with surrounding context, fragment checks and contextual text. For GitHub sources, compare is pinned raw commit against the live branch; others compare committed normalized snapshot against live normalized text. All eight GETs returned 200.

| Row | Live assessment |
|---|---|
| S17 | Both claims survive: supervision owns retries and reconnection does not replay mutations. Live socket-expiry policy reverses the old statement, with renewal detail. Ledger correctly records that qualification. |
| S18 | Session/transport separation and tunnel lifecycle fragments survive. Automation webhook forwarding, including optional offline holding, qualifies the general relay statement and is recorded. Existing shutdown exceptions remain in both versions. |
| S34 | Default-management grants and shell/agent minting path are materially different; ledger's qualification and open G07 action match. Filesystem scope and pre-revocation asset-URL caveats are recorded too. |
| S29 | Zig requirement fragment lost; broad native/TypeScript claim survives. No re-test disposition matches ADR-0002 as above. |
| S01, claim unchanged; G03/G09 | First-value precedence, Match exec and ControlPersist fragments remain in context. Complete changes are version navigation, an algorithm-list comma and footer date, consistent with ledger. |
| S07, claim unchanged; G03/G04 | Lock clears default approvals; timed approvals stay in memory but keys still require unlock. Complete changes are assistant disclaimer placement and back-to-top chrome. |
| S14, claim unchanged; G06/G02 | Cryptographic identity and distinct routing address remain. Changes are navigation and back-to-top chrome. |
| A02, claim unchanged; G06/G02 | Experimental Go binding, Linux musl architecture table, stable-tag intention and module host remain. Changes are navigation and back-to-top chrome. |

Fresh tool results reproduce the ledger's changed-source sets and counts: 21/34 spec CONTENT, 4/4 aux CONTENT; S16/S17/S18/S34 branch drift with fragments intact, S29 lost fragment, S19/S27 SAME. Spot checking is bounded textual review, not a full upstream implementation audit.

## Normalizer and immutable evidence

Independent live normalization of all 38 fetch-source bodies equals the committed HEAD normalizer (`normalizer-live.out`). Supplementary execution of fix4's inspected three-version comparison reconstructs fix3, checks its sha256 against recheck3's recorded hash, then compares committed 3622c56, fix3 and fix4 on 38 fresh bodies. All 38 are SAME; no real source enters the implied-head second pass (`normalizer-three-versions.out`). This confirms no current source text moved because of fix4; original baseline raw bodies are not available for replay.

`immutable-assertions.out` independently asserts every source/auxiliary `pin`, `pin_v2`, `excerpt` and `claim`, plus candidate and tag pins, equals HEAD; all tracked baseline/repeat files, snapshot files and excerpt files are byte-identical to HEAD. `pin-preservation.out` lists all manifest leaf changes: dated edit metadata, reopen-policy and reproducibility prose, source notes and explicit upstream URL/ref fields; no pin/hash/claim/excerpt edits.

## Commands and real exits

`T = python3.13 -I -B docs/sources/tools/fetch_pins.py` (3.13.18). Commands ran as real subprocesses, with stdout/stderr and return codes captured in adjacent outputs. Live commands unset SSH_AUTH_SOCK. No shell pipeline hides a test exit. `command-exits.json` records the required suite's exits; supplemental fetch/compare outputs contain their own exits.

| Command/check | Actual exit | Observed result |
|---|---|---|
| T selftest | 0 | all checks pass |
| python3 -I -B tool selftest | 0 | default interpreter also passes offline |
| T verify, each committed snapshot with its spec/aux baseline | 0 each, 31 commands | all snapshots match |
| T excerpts --set all | 3 | seven GitHub copies unchecked by design |
| T excerpts --set all --fetch-git | 0 | 38 checked, 91 fragments, none missing |
| T tags --out tags.json | 0 | 14 tags SAME |
| T upstream --out upstream.json | 2 | S29 1/2 fragments; other four changed branches intact; S19/S27 SAME |
| T fetch --set all --out fresh.json | 0 | all 38 HTTP 200, pinned blobs match |
| T compare fetch-baseline.json fresh.json --all | 2 | 8 IDENTICAL, 2 RAW_ONLY, 3 MARKER_ONLY, 21 CONTENT, no failure/gone/missing; aux EXTRA informational |
| T compare fetch-baseline-aux.json fresh.json --all | 2 | 4 CONTENT; spec EXTRA informational |
| Independent 12 crafted normalization assertions | 0 | all pass |
| Independent 38-body HEAD/current comparison and eight live spot checks | 0 | all GETs succeed; source normalization unchanged |
| Inspected fix4 normalizer_fix3_vs_fix4.py, scratch inside this directory | 0 | verified fix3 reconstruction; 38 SAME across three versions |
| Immutable assertions against git HEAD | 0 | all assertions pass |
| Final source hashes, git diff --check, evidence token scan | 0 | reviewed bytes unchanged; no whitespace errors; no home paths, canary values or private-key delimiters in review outputs |

One proposed helper invocation was rejected before execution because it included shell `rm -rf`. It was replaced by a Python subprocess driver with targeted cleanup of its own newly created scratch directory. The helper then ran successfully; scratch was removed. An intermediate diagnostic looked for compare/immutable outputs before their sequential fetch driver completed and reported missing files; after completion all outputs exist and their actual exits above were inspected. Neither event is a product finding.

## Changed files, limits and risks

Created `RECHECK4.md` and command-output artifacts only under `tests/evidence/artifacts/review-sources/recheck4/`. Transient module/scratch files were removed. Existing tracked edits and other agents' evidence were preserved. No build outputs produced.

Skipped native gate execution, upstream code audit and exhaustive HTML5 parser conformance. The normalizer remains an approximation; no source-normalization regression was observed. G07 authority behavior is still open, S29 keeps a visible accepted exit 2, and live text observations apply to this run. Other integration/escalation items outside R3-1/R3-2/R3-3 are not closed by this verdict.
