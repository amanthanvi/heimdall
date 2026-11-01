# M02 design re-review, round 2 — proceed after fixes

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved by the orchestrator on 2026-11-01. The findings are verbatim; the long
"Inferences, proving tests and exit claims" and command tables are abridged at the end,
as marked. The full text is in the reviewer's T3 thread for task
M02-T00-design-review-round2.

**Task:** M02-T00-design-review-round2
**Commit reviewed:** `8263ee6c04683fffccc95c2fb0bea4c0b75f10a6`
**Verdict:** **proceed after fixes**. Revision 2 substantially improves the design, but the transaction/recovery contract, interaction freshness, and U0b interfaces need correction before wave 0 freezes them.

This review was independent and read-only. No files were changed, committed, or pushed. No network, native harness, build, or validation suite was run. "Observed" means inspected in the committed documents or code. Failure scenarios for the proposed implementation are explicitly marked **inference**.

ADR7 = `docs/decisions/0007-existing-access-integration.md`; M02 = `docs/architecture/m02-plan.md`.

## First-review findings

| Finding | Status | Revision-2 assessment |
|---|---|---|
| M2-D01 — inherited identities defeat single-key selection | **resolved** | ADR7:144–167, :835–846 withdraw the unconditional exclusivity claim (`exclusive`/`not_exclusive`/`undetermined`); M02:294–295, :455–457, :701–702, :1089 assign coverage. Noninteractive use of additional identities is a separate problem, M2-R05. |
| M2-D02 — P changes before B conflict detection | **partially** | ADR7:362–387 separates first adoption from updates; M02:540–552 adds edit/crash scenarios. Restoring P after checking the user file conflicts with the primitive's earlier deletion of displaced P (M2-R01). |
| M2-D03 — digest races and cleanup ownership | **partially** | ADR7:280–342 and :599–622, M02:479–509, :528–564 are materially stronger; recovery still misclassifies interrupted restores and Unix settlement keeps a check-to-unlink window (M2-R02). Native exchange/Windows backup semantics unverified. |
| M2-D04 — rollback is not inherently narrowing | **partially** | ADR7:243–278, M02:313–315, :629–632 classify by approved before/after states; equality of undetermined states is insufficient (M2-R03). |
| M2-D05 — uncertain native interaction defaults to none | **partially** | ADR7:779–804 defaults to `unknown` with an attended declaration; expiry/withdrawal not carried through persisted-facts reuse, and the confirm-key test does not establish F23 (M2-R04, M2-R08). |
| M2-D06 — probe effects overstated | **partially** | ADR7:689–732 discloses hook effects accurately; the authorization check still precedes execution of a mutable real configuration tree (M2-R06). |
| M2-D07 — EOF falsely proves exec | **resolved** | ADR7:870–873, :906–942 classify Unix `launching` without further evidence as `indeterminate`; M02:798–807, :834–845 cover the failure cases. |
| M2-D08 — missing M01 integration ownership | **partially** | Ownership repaired (ADR7:41–44, :1269–1278; M02:176–228); receipt representation and declaration approval still inconsistent, and the wave-0 completion rule depends on U5 bodies (M2-R07). |
| M2-D09 — fixture overrides projection selection | **resolved** | ADR7:1038–1040, M02:58–83, :742–768, :1089. |
| M2-D10 — Git transaction/effective-selection contract | **partially** | ADR7:450–543, :982–1010; M02:567–581, :883–888, :1173–1181. Shared replacement/recovery defects apply to Git too; F22 remains an inference pending broader fixtures. |

## New findings

### M2-R01 — major — Update rollback can require a displaced file that settlement already deleted
**Locations:** ADR7:320–325, :380–387; M02:484–487, :546–551. **Observed:** the file primitive post-validates and then removes displaced D in its valid settlement path; the update protocol then checks the user file and, if changed, restores generation N by exchanging P back. **Failure (inference):** P is exchanged and post-validated, settlement deletes old P, the user-file recheck detects a concurrent edit, and there is no old P left to exchange back. **Fix:** separate exchange/post-validation from final settlement; retain displaced P until all update-level checks and durable outcome recording complete; test an edit and a process crash between primitive post-validation and transaction-level settlement.

### M2-R02 — major — Recovery does not distinguish an interrupted restore from a step that never exchanged
**Locations:** ADR7:326–335, :570–595, :612–619; M02:489–500, :536–557. **Observed:** recovery treats path = V as "not exchanged", path = S with no displaced file as "validation finished"; receipts have no restore phase; Unix settlement checks identity then unlinks the name. **Failure (inference):** an update exchanges, starts restoring, exchanges back and crashes before settlement; recovery classifies it as never exchanged. Disappearance of D does not prove validation if another writer removed it; a replacement between identity check and `unlinkat` can be deleted. **Fix:** specify recovery as a state table (forward exchange, restore exchange, deletion, base-absent creation, target-absent removal); durable restore phases; matching receipt evidence before inferring settlement from absence; missing/foreign entries produce preserved conflict state; state and enforce the directory-concurrency assumption for final unlink or avoid deleting an unvalidated named replacement; crash injection before/after the restore exchange and before each settlement receipt.

### M2-R03 — major — Undetermined behavior digests can reuse consent for a different executable condition
**Locations:** ADR7:255–273, :1314–1320; M02:280–295, :341–347. **Observed:** an undetermined directive is digested from candidate values and condition **kinds**; the digest does not bind executable condition contents or include context. **Failure (inference):** a later edit changes the `Match exec` command that selects between the same candidate HostNames; the digest is unchanged and an unattended rollback is classified as previously consented. **Fix:** conservative rule — require a new decision for an undetermined behavior-changing restore; or bind consent to the exact condition inputs and present it as authorizing that dynamic program. Test: change `Match exec` while keeping candidates and condition kind.

### M2-R04 — major — Persisted prepared facts can outlive an interaction declaration
**Locations:** ADR7:799–804; M02:198–200, :217–222, :810–816, :1235–1239. **Observed:** U0b persists prepared integration and reuses it for attached/bind/restart results; `PairIntegration` carries interaction, basis and declaration time but no expiry or declaration revision; the prelaunch check uses that returned integration. **Failure (inference):** a `none` declaration is withdrawn, invalidated or expires; a later bind reconstructs `interaction: none` from stored facts and noninteractive launch passes. **Fix:** separate historical preparation facts from current launch eligibility; revalidate declaration existence, revision, endpoint and expiry at bind/readiness and before noninteractive launch; tests for withdrawal, expiry and failed-listing invalidation between ensure and bind, including after restart.

### M2-R05 — major — Checking adopted pairs alone does not prevent interaction from inherited fallback identities
**Locations:** ADR7:145–166, :827–846, :1328–1340; M02:815, :1085. **Failure (inference):** the adopted key is declared `none`; an inherited confirm-constrained key is accepted after the adopted key is rejected, and the agent's confirmation dialog appears. Reporting `not_exclusive` does not satisfy A11's no-popup behavior. **Fix:** on the no-provider-interaction path, refuse nonexclusive/undetermined selection unless all reachable alternatives have sufficient interaction information, or require the explicit provider-interaction opt-in; add the inherited confirm-constrained-key variant to A11.

### M2-R06 — major — Configuration-command authorization is vulnerable to changes after the static pass
**Locations:** ADR7:689–707; M02:295–297, :403–404, :419–427. **Failure (inference):** static inspection finds inert configuration; an editor inserts `Match exec` before `ssh -G` opens the file; the command runs without `--allow-config-commands`. **Fix:** execute against a validated immutable snapshot preserving path semantics, or require configuration-command authorization whenever running the mutable real tree; decline the probe if snapshot equivalence cannot be established; fail closed on unreadable/unresolved includes; test a hook inserting executable configuration between inspection and SSH opening the file.

### M2-R07 — major — Wave 0's integration contract is not yet internally implementable as specified
**Observed mismatches with M01:** (1) `StageReceipt`/`EffectReceipt` (crates/domain/src/operation.rs:223–260) cannot represent S/V identities and per-file outcomes, and no typed representation or migration is specified; (2) the approval recipe writes `LocalApproval { decision, plan_digest }` for both new kinds, but `DeclareInteraction` has no `plan_digest`; (3) U0b must land with no request-reachable `todo!` while its new `Operations::drive` branches call setup/catalog bodies assigned to U5 (wave 3); (4) `operation_kind_as_str_equals_request_kind` covers every effectful request, but `Request::is_effectful` includes `Decide`/`ConfirmTime` with no `OperationKind`, and `Probe` has no Request variant. **Fix:** freeze a typed local receipt payload and a declaration-specific approval representation; one landing strategy — minimal local drivers in wave 0, or new requests fail closed and unavailable until their drivers land, with wave-0 acceptance tests; scope the kind-mapping test to journaled kinds and document Probe's mapping.

### M2-R08 — medium — Several proposed tests cannot establish the facts assigned to them
The F23 refusal test passes even with an unconstrained key (add constrained-key installation verification and an authorized disposable signing control); the Windows displaced-identity test does not inject the race inside `ReplaceFileW` (keep that claim `[U]` or use an independently justified primitive); the Git test omits both global files present, ordinary and conditional includes, multiplicity through includes and include expansion by the chosen queries.

## QR1–QR6 (abridged)
QR1 appropriate (fix freshness R04 and approval representation R07); QR2 appropriate for determined states only (R03); QR3 reasonable, reconcile "any scope" wording with system/global-only applicability; QR4 fine for reporting, insufficient for the no-popup path (R05); QR5 sound for adopted pairs, must also cover inherited alternatives and stale declarations; QR6 sound, recovery must preserve the distinction after a crash.

## P3–P6 and wave 0 (abridged)
P3 accept after R07; P4 accept (R06 still applies to doctor); P5 accept, native filesystem tests and explicit ordering still needed; P6 accept, test refusal through catalog resolution with a multi-pair profile. **Wave 0 remains blocked on design corrections**, principally R07 and the receipt/recovery decisions in R01/R02. No owner-only input is needed to resolve them.

## Inferences, proving tests, exit claims, commands (abridged)
F20 settled by evaluator-vs-`ssh -G` comparison with controls; F21 supported by the manual but the harness test only proves the supplied HOME; F22 needs the R08 Git fixtures; F23 not settled by the refusal test; F24 per-filesystem only. The process classification table is conservative for complete records; specify truncated/malformed records and conflicting sequences. A27 evidence must keep the Unix `indeterminate` qualification. No native pass is established. Commands: read-only `git`, `rg`, `nl`, `sed`, Python `gzip` reads of pinned S01; `check.sh`, builds, native harnesses and network not run. Changed files: none.
