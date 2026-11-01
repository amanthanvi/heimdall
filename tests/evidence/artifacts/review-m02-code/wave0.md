# M02-W0-code-review — d57bf7c4 — fix first

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01. Orchestrator resolution: Z01–Z03 were
fixed by the orchestrator in the commit that saves this file. Each fix has a
compile-checked or behavioural test: `projection::tests::wave0_z0{1,2,3}_*` in
heimdall-domain and `recovery::wave0_review::wave0_z03_*` in heimdall-localenv.

Reviewed commit: `d57bf7c4acb198360b3999da5507481a9f6fd8c1`
Change range: `9c458501..d57bf7c4`
Review mode: independent, read-only; no source changes, commits or pushes.

The wave-0 landing fails closed in the request, CLI and recovery paths inspected, and the offline workspace suites passed. However, three frozen recovery interfaces disagree with the accepted ADR-0007 §12.14 rulings. Correct these before downstream units build against them.

## Findings

### Z01 — High — Completed restores lose their required cause

**Location:** `crates/domain/src/projection.rs:1398`

**Defect:** `RestoreCtx::Done` is a unit variant. ADR-0007 §12.14 item 1 explicitly requires it to carry the restore cause so a recognized completed restore can distinguish a mismatch restore from a clean rollback.

**Concrete failure scenario:** U4 rebuilds recovery state after `file.restored`. A restore initiated by `FileMismatch` and one initiated by `TransactionCheck` both become `RestoreCtx::Done`. The recovery action receives no cause through this field, despite the accepted design requiring that information to determine whether a conflict artifact exists.

**Evidence:** `Due(RestoreCause)` and `Started(RestoreCause)` retain the cause; `Done` drops it. The accepted ruling says "`RestoreCtx::Done` carries its cause."

**Observed or inferred:** The type mismatch is observed directly in source. The downstream recovery consequence is inferred; the recovery builder and driver remain skeletons.

**Fix:** Make `Done` carry the required cause, reconcile its serialization and documentation, and add a small contract test showing that completed mismatch and clean rollback contexts remain distinguishable.

### Z02 — Medium — RecoveryState::build has the wrong frozen argument order

**Location:** `crates/domain/src/projection.rs:1459`

**Defect:** The implementation declares `build(step: u16, files: &[FileStep], receipts: &[StageReceipt])`. ADR-0007 §12.14 item 1 accepts `build(step, &[StageReceipt], &[FileStep])`.

**Concrete failure scenario:** U4 implements a caller against the accepted signature and cannot compile against the wave-0 API. Resolving this later requires changing an interface already declared frozen.

**Evidence:** The source places `files` second and `receipts` third; the accepted ruling places receipts second and files third. Existing tests do not call the skeleton builder and therefore do not detect the disagreement.

**Observed or inferred:** Signature disagreement observed in source; downstream compilation failure inferred from the incompatible parameter types.

**Fix:** Change the declaration to the accepted order and add a compile-checked signature assertion without executing the skeleton body.

### Z03 — Medium — StepDecision remains in the wrong crate

**Location:** `crates/localenv/src/projection/recovery.rs:85`

**Defect:** `StepDecision` is defined in `heimdall-localenv`. ADR-0007 §12.14 item 2 explicitly places it in `heimdall-domain`, alongside the other frozen recovery types. The module overview in `crates/domain/src/projection.rs:22` also contradicts that ruling by saying it stays in localenv.

**Concrete failure scenario:** A downstream unit imports the accepted domain API and finds no `heimdall_domain::projection::StepDecision`. Adding a localenv dependency to obtain it would defeat the agreed placement and can introduce a dependency cycle for app-level consumers.

**Evidence:** The enum exists in localenv and is absent from domain. Its payload types—`ForwardStep`, `RestoreStep`, `AbortStep` and `SettleStep`—also live in localenv, so moving only the outer enum would be insufficient.

**Observed or inferred:** Placement mismatch observed in source; downstream import and dependency problems inferred.

**Fix:** Move `StepDecision` and the payload types it requires into domain. Keep `decide` and `decide_item` in localenv, importing the domain types. Update the contradictory module documentation and add a compile-checked domain import test.

## Checks found sound

- **M01 preservation:** The inspected diff preserves admission's classification-before-backpressure order, interrupted-round capture, completion of interrupted withdrawals, cleanup-intent processing, claim/effect sequence semantics, `cleared_by_claim`, the CleanupIntent lifecycle, `settle_effect_in` ownership and `cleanup_pending`. The corresponding model, property and integration suites passed.
- **Materialize idempotency:** The materialize bind hash retains the M01 form. The added regression test compares it against the M01 hash input. Launch hashing excludes holder metadata as accepted by §12.14.
- **Migration 0005:** The migration is additive. The populated-v4 migration test passed, including byte preservation of old receipts, recovery intents and meta records, cleanup intents, counters and legacy claim migration.
- **Existing test edits:** The M01 model scenarios and assertions inspected were retained. Changes include default-valued new fields, the equivalent invalid-launch fixture using the new executable representation, and mechanical migration-version/fault-count updates. Thus the edits are mechanical compatibility updates, though they are not literally limited to adding struct fields.
- **Fail-closed integration:** `setup/1` is not advertised. Setup/catalog dispatch reaches unconditional `driver_unavailable` refusals before admission. New decisions are refused without consumption; cancellation of open local operations is refused. Restart leaves their operation state, intent and receipts intact, with the accepted additive lifecycle event.
- **CLI and skeleton reachability:** New handlers return the unavailable envelope without contacting the runtime. No reachable `todo!()` was found in the request, CLI or restart paths inspected. The CLI wave-0 tests passed.
- **Frozen data contracts:** StepContent's base64 forms, whole-target digest binding, absent-base splice checks, bounds, LockHolder validation and decoded armor refusal are implemented. FileIdentity equality rejects `Some(birth)` versus `None` in both directions. LocalReceipt/FilePhase includes `held`, omits `restore_conflict`, and carries the revised settlement fields. ProjectionApproval and DeclarationApproval are separate, and the local-intent update rule is add-only.
- **Atomic setup admission:** The blocker check and insertion execute within the store's `BEGIN IMMEDIATE` transaction. The admission and rollback tests passed.
- **Kind mapping:** Dotted setup serde names agree with `as_str`; the journaled-kind mapping tests passed.
- **Duplicate skeleton integration:** The inspected CLI handlers, app ports, adapter implementations and launch modules form a coherent fail-closed skeleton. No duplicate active handler or adapter registration was found. The recovery-interface discrepancies above remain unresolved.
- **Security surface:** `localenv/src/sys.rs` contains no new unsafe block yet; overview §9 describes that skeleton status. `glob =0.3.4` and `rustix =1.1.6` are pinned and recorded in `dependencies.md`; rustix already existed in the lockfile.
- **Fixtures and tests:** The marker scan found no sensitive markers in schema examples. Test-source hits were guards, synthetic rejection material and example-user path fixtures. No committed private-key body was identified in the material inspected. Every executed non-doc test target reported a nonzero test count; no assertion-free acceptance test was identified in the inspected additions.

## Commands and validation

| Command or check | Exit code | Result |
|---|---:|---|
| `git status --short`; `git rev-parse HEAD` | 0 | Clean checkout at the requested commit, before and after review |
| `git diff --stat`, targeted `git diff`, `rg`, `sed` and numbered source reads | 0 | Inspected the requested range and relevant design/code/test paths |
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | **828 passed, 0 failed, 2 ignored** |
| `cargo fmt --all --check` | 0 | Passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Host clippy passed |
| `git diff --check 9c458501..d57bf7c4` | 0 | Passed |
| Python test-log discovery/count and fixture-marker scans | 0 | All non-doc targets had tests; sensitive values suppressed |
| Initial combined build-size check | 1 | zsh rejected unmatched prototype-directory globs |
| Repeated build-size check with Bash `nullglob` | 0 | No prototype build directories present; checkout `target/` measured 3.2 GB separately |
| Python cleanup and absence assertion | 0 | Removed this checkout's `target/` and the review's temporary logs |

**Changed files:** None. Build output and review scratch logs were removed.

Not checked: native Windows/WSL behavior, native harnesses, Windows-target clippy, or the complete `check.sh` workflow; no external network access was used.
Risk: passing host suites do not close Z01–Z03 or prove the unimplemented recovery bodies; fix the frozen interfaces before proceeding to wave 1.
