# M02 revision-4 independent design review — proceed after fixes

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved by the orchestrator on 2026-11-01. The findings and the interface reconciliation are
verbatim; the totality assessment and command table are condensed, as marked. The full
text is in the reviewer's T3 thread for task M02-T00-design-review-round4.

**Task:** M02-T00-design-review-round4
**Commit reviewed:** `99e6fc9f43fbe21d4137d3d5625f7da6b07eba90`
**Verdict:** **proceed after fixes**

Revision 4 addresses the original data-preservation failures substantially: unmatched recovery states hold, restores check active content, settlement checks expected content, and an unreceipted deterministic Git lock is foreign. Atomic setup admission is now specified correctly. Wave 0 should wait for the contract corrections below. The remaining issues concern implementability, stale held previews, recovery-history inputs, contradictory generated-test properties, and integration with ADR-0006 r2.17. This is a design assessment; no M02 implementation or native behavior was verified.

ADR7 = `docs/decisions/0007-existing-access-integration.md`; M02 = `docs/architecture/m02-plan.md`.

## Status of the previous findings

| Item | Status | Assessment and evidence |
|---|---|---|
| M2-S01 — omitted recovery states | **Partially resolved** | Missing create and post-validation rows added (ADR7:1027–1041, 1074–1088); ADR7:943–945 supplies a conservative H fallback. The frozen pure function cannot implement H0's historical lookup as typed, and the generated properties contradict some permitted actions (M2-T04–T05). |
| M2-S02 — identity-only restore/settlement | **Resolved in the design** | ADR7:390–406, 413–437; F5a, C7a, F8a (ADR7:1038, 1086, 1056); residual race disclosed at ADR7:1246–1256. |
| M2-S03 — recovery claims a foreign Git lock | **Partially resolved** | Equal-content foreign-lock scenario resolved (ADR7:760–774, G0–G3 at 1090–1102); subsequent replacement names inconsistent, especially on Windows (M2-T01). |
| M2-S04 — inventory completeness claim | **Resolved in the design** | ADR7:1353–1363; M02:730–746, 2046. |
| M2-S05 — writer has no durable target bytes | **Partially resolved** | `StepContent` and stateless execution (ADR7:824–875; M02:2376–2384, 2446–2462); the materializer lacks the expected digests and absent-base splices are undefined (M2-T02). |
| Atomic admission | **Resolved in the design** | ADR7:1183–1203; M02:2571–2579, 410–428; store uses `TransactionBehavior::Immediate` (`crates/store/src/lib.rs:286–290`). Tests planned, not run. |

## New findings

### M2-T01 — major — Claiming the Git lock invalidates the replacement primitive's name layout
**Locations:** ADR7:369–379, 736–758, 843–846; M02:892–894, 936–942. The no-replace rename moves S from `staged_name` to `<global file>.lock`, but the §5.3 primitive still consumes the staged name, and the Git rule makes the lock name the displaced name on both platforms without a different exchange procedure. **Failure:** after the claim the random staged name is absent, so the Unix exchange has no source; substituting the lock name fixes Unix, but Windows `ReplaceFileW(path, staged, backup=displaced)` would use the occupied lock name both as replacement input and backup destination. The no-replace claim itself is conservative on all three platforms; the problem is how it connects to the next step. **Fix:** specify the Git-specific name transitions through claim, forward replacement, restore and settlement per platform; freeze which name holds S and D at each phase; on Windows define a distinct displaced backup name and how Git's lock stays occupied until settlement; crash vectors around those transitions, including first creation of an absent global file.

### M2-T02 — major — The materializer cannot perform its required digest checks, and an absent-base splice is undefined
**Locations:** M02:888–891, 2448–2458; ADR7:357–360, 516–520, 867–870. The frozen `materialize(&StepContent, base: Option<&[u8]>) -> Result<Materialized, ContentError>` must check the base against `base.sha256` and the output against `target.sha256`, but neither expected digest is reachable through that signature; `Splice` carries only the removed-range digest and `Whole` only bytes. A first adoption with no user SSH config is a create step with a splice, but `Base::Absent` has no digest and `None` has no splice semantics. **Fix:** pass the `FileStep` (or its expected base and target states) to materialization; define an absent base as an empty splice input allowing only a valid insert-only range, or another explicit representation; checked range arithmetic and bounds validation; test absent SSH config and absent global Git config with a fresh writer. (The size limits are coherent as decoded-content limits.)

### M2-T03 — medium — Held-preview observations do not bind the actual changed content
**Locations:** M02:871–878, 929–932, 1303–1314, 2508–2513; ADR7:1002–1005. The held-repair preview's canonical observation records identity and only `Unchanged|Modified`; U4's `StepObservation` represents a foreign entry as `Foreign`. **Failure:** preview records `S/Modified` for bytes A; the editor rewrites the same inode to B before `keep`; the observation still equals and `keep` closes O though the preview did not describe the current edit (nothing is deleted, but the stale-preview contract is violated); two different foreign replacements are likewise invisible. **Fix:** separate recovery classification from preview fingerprints; bind identities and content digests to held previews, with an explicit representation for content unreadable within bounds; keep bytes out of receipts and output; controls for two successive in-place modifications and two different foreign replacements.

### M2-T04 — major — The frozen `decide` input cannot implement recovery from `held`
**Locations:** ADR7:960–962, 1064; M02:879–887, 2508–2513. H0 requires deciding from the receipt before `held`; `decide` receives only `last: Option<&FilePhase>`, and `held` does not contain its predecessor. **Failure:** two replace steps with the same observation (`path S, aside V`) and the same `held` payload, one held after `validated` and one after `restore_started`, need different continuations once the filesystem is recognizable; the inputs cannot distinguish them. A catch-all Hold is safe but prevents the promised retry continuation; looking up receipts inside `decide` would break its pure contract. **Fix:** freeze a normalized recovery-state input built from the receipt history (the effective phase preceding holds plus restore/settlement context), or strip held receipts before calling `decide` and make `held` outside its domain; align the generated-domain definition.

### M2-T05 — medium — The generated-test properties reject permitted recovery behavior
**Locations:** ADR7:1039–1040, 1104–1119, 1158–1172; M02:1054–1064, 1077–1085. M02:1062–1063 permits `Restore` only with unchanged S at the path, while F5b/F5c recognize an already-completed restore (D or X at the path, S aside) that must be a completion/settlement action, not another exchange; ADR7:1159–1162 permits removal only after a durable `file.settled`, but the removal shape uses locator L and writes no stage receipts (ADR7:1104–1106), so a successful R1/R2 cleaner removal fails the property; ADR7:1165–1166 permits path changes only through forward or restore exchange, omitting the specified create rollback via quarantine. **Fix:** state properties over concrete effects (performing a restore exchange vs recognizing a completed one; locator-authorized cleaner removal under its own ownership rules; content-checked create rollback); keep negative controls that foreign or modified content is preserved; do not weaken assertions ad hoc.

### M2-T06 — major — The plan does not assign ADR-0006 r2.17's adapter-timeout requirement
**Locations:** M02:342–344, 1425–1441, 1455–1458; `docs/decisions/0006-public-contract-baseline.md:1340–1345`; `crates/app/src/operations.rs:5187–5189, 5313–5329, 5481–5482`. ADR-0006 §13.20 requires bounded adapter calls when real adapters arrive in M02/M03, with a timed-out preparation treated as `Uncertain` and its cleanup intent processed in the same process; U6 bounds only the agent-listing protocol. **Failure:** preparation hangs after its effect while holding the preparing marker; cleanup defers the in-flight intent to a return path that never returns; a bounded caller wait does not end the background preparation. **Fix:** an integrator-owned runtime task and acceptance tests for timeout after effect, uncertainty settlement, release of the preparing marker, and supervisor cleanup without restart; preserve `settle_effect_in`'s transactional ownership decision; the timeout covers the actual adapter call.

## Recovery totality (condensed)
Every unobservable or unmatched combination resolves to H before mutation (ADR7:943–949); the round-3 omissions are addressed; no explicit row authorizes discarding known modified content or overwriting a known newer active edit (F5a, C7a, F8a hold). Limits: H0 needs a richer history input (T04); the Git claim/replacement sequence needs a consistent per-platform protocol (T01); the generated properties need T05's corrections. The alphabet is a classification, not independent physical identities (D may equal V, Q may identify S or D): specify role precedence or normalize observations before enumeration, and reject impossible identity/link-count combinations explicitly. Races after the final content check and Windows' internal replacement window remain disclosed and natively unverified.

## Interface reconciliation against current M01 (verbatim)

| Area | Current code and required reconciliation |
|---|---|
| **Admission/backpressure description** | U0b row 23 says backpressure is checked inside the write transaction. Current `admit` computes `allow_new` before entering it at `operations.rs:5971–5974`, then tests that captured value inside. Correct the description; preserve the separate requirement that the setup blocker check and insertion are atomic. `Authenticate` is appended conditionally on `pipeline` at `operations.rs:6017–6022`. |
| **Recovery includes cleanup intents** | U0b row 11 describes the open/unresolved loop. Current recovery subsequently completes interrupted withdrawals and processes cleanup intents regardless of operation state at `operations.rs:4090–4097`. Preserve these paths when adding local dispatch; "loop unchanged" is insufficient as the full recovery contract. |
| **Claim/effect sequences** | Preserve `PendingRemoteRevocation.claim_seq`, `RemoteObligation.effect_seq`, legacy migration, and `cleared_by_claim`: `revocation.rs:162–168, 253–259, 277–298, 394–401`. The store-wide counter is `ext.rs:1124–1138`. New literals, fixtures and migration coverage must use the current fields; do not restore round-based clearance. |
| **Durable cleanup intent** | Preserve `CleanupIntent` and its versioned store lifecycle: `revocation.rs:350–377`; `ext.rs:1144–1164, 1170–1186`. Wave-0 migration compatibility should include these existing meta records and counters, not only receipt/intent JSON. |
| **Transactional effect settlement** | Preparation-confirmation changes in U0b row 6 must preserve `settle_effect_in` and its fail-closed transaction behavior at `operations.rs:2948–2994`. Adding prepared facts must not bypass durable cleanup ownership or the post-commit processor. |
| **Pending-cleanup inspection** | Preserve ended grants with pending cleanup intents and their `cleanup_pending` field: `operations.rs:6431–6441, 6511–6513`; ADR-0006:1322–1335. This must survive inspection/result changes. |
| **Real-adapter timeout** | Add the missing runtime requirement and tests described in M2-T06 before freezing the implementation packet. Current M01's unbounded fake-adapter await is not an acceptable inherited behavior for real adapters. |
| **Content materialization** | Correct the frozen signature and absent-base rules in M2-T02. |
| **Held recovery and preview** | Correct the history input and preview fingerprints in M2-T03–T04. |
| **File identity equality** | The authoritative frozen rule at M02:2441–2445 requires birth-time presence on both identities or neither. U0's test description at 286–288 only explicitly checks differing present birth times. Add `Some` versus `None` inequality in both directions; do not implement optional birth as a wildcard. |

## Wave 0 decision
**Proceed after fixes.** Correct the frozen content, recovery-history and held-preview interfaces; specify the Git name transitions; reconcile the generated properties; add the r2.17 timeout/cleanup obligations to U0b's packet. No new owner decision is needed. Independent U0 preparation can continue, but wave 0 should not freeze the affected interfaces as revision 4 states them.

## Commands (condensed)
Read-only inspection (git, rg, nl, sed, cat) of both design documents, the round-3 review, ADR-0006, spec, plan and cited Rust sources; all exited 0 except a no-match memory search (1) and `test -d` for absent target directories (1). `check.sh`, builds, native harnesses and network were not run. Changed files: none.
