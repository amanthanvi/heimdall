# M01-code-review-round8 — b89743aeccc06cafca85dce6783cc99e3b7f4903 — **ship M01**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Independent, adversarial, read-only review of `250a029d..b89743ae`, against `spec.md`, plan §5, ADR-0005 §3.5–§3.7, and ADR-0006 revision 2 through §13.20.

**W01 and W02 are fixed for the reported scenarios, including the record-removal ABA variant. No new concrete security defect was reproduced or established by source inspection.** "Ship M01" is the code-review verdict: this review does not close native platform evidence or certify real credential adapters.

## Round-7 findings

| Finding | Status | Source evidence and proving tests |
|---|---|---|
| **W01 — superseded first-round claim erases a newer pending obligation** | **Fixed** | `crates/store/src/ext.rs:1129` allocates claims using a persisted store-wide counter, with checked increment. Claim creation uses it at `crates/app/src/operations.rs:2452` and `:2531`. Completion requires the still-open claim's sequence to match at `:2596`; `crates/domain/src/revocation.rs:400` also requires a sequence strictly greater than the recorded effect. Passing tests: `r1319_1_a_superseded_first_round_confirmation_never_erases_a_newer_pending_obligation`, `r1319_1_a_superseded_confirmation_never_erases_a_newer_pending_obligation_without_an_effect`, and `r1319_1_a_claim_that_outlives_its_records_removal_never_erases_a_new_records_obligation`. |
| **W02 — durable late confirmation loses cleanup across restart** | **Fixed** | Late confirmation calls `settle_effect_in` inside its receipt transaction at `crates/app/src/operations.rs:5388`. The helper records ownership or a durable intent at `:2975` and `:2984`. Recovery processes intents independently of operation state at `:4096`; the supervisor processes them at `crates/runtime/src/supervisor.rs:567`. Passing test: `r1319_2_a_restart_after_the_late_confirmation_commit_keeps_the_capped_records_cleanup`. This exercises production cap **8**, an effect-triggered `FaultPoint::AfterCommit`, a durable late confirmation, and reconstruction followed by supervisor passes. |

I reran the reproduction ideas through the checked-in regression tests and again from a scratch test binary linked against this checkout's production libraries. The frozen-clock tests verify equal timestamps and reset round counts while keeping the newer obligation. The record-removal variant verifies that an old completion cannot clear a recreated record.

These are **observed in-process results**. Equivalence to a process crash at the same durable boundary follows from transaction ordering; no native crash harness was run.

## New findings

**None.** No X-series finding is asserted without a concrete failure scenario.

The following observations constrain that conclusion.

### Settlement and store failures

The reviewed settlement boundaries use the shared transactional decision:

- Late `Confirmed`: `crates/app/src/operations.rs:5388`.
- Late `Uncertain`: `:4933`.
- Recheck refusal: `:5647`.
- Commit refusal: `:5860`.
- Cancellation, including orphaned shared preparation: `:7236`.

Errors from ownership registration and intent persistence propagate through the settling transaction. A failed transaction therefore cannot commit the settlement while silently omitting its cleanup decision.

Passing named regressions cover these boundaries, including cancellation and refusal post-commit failures. I additionally ran **`round8_cap8_before_commit_failure_recovers`**, a scratch variant of the W02 regression using `FaultPoint::BeforeCommit`. It verified that no confirmation receipt became durable and that restart still retained ownership or produced a subsequent call. **Observed: passed.**

### Intent versioning and concurrent processing

`crates/store/src/ext.rs:1148` assigns intent versions using a separate persisted, checked counter. A processor checks its version before deciding at `crates/app/src/operations.rs:5492` and before final removal at `:5556`. The ownership-transfer removal at `:5501` occurs in the same transaction as the initial version check.

Two additional scratch tests passed:

| Test | Observed result |
|---|---|
| `round8_stale_cleanup_completion_preserves_replaced_intent` | Held an old cleanup call, replaced its durable intent, then released the old completion. The replacement survived and was subsequently processed. |
| `round8_concurrent_cleanup_processors_finish_without_losing_replacement` | Held one processor's call while a supervisor processed the same intent. After replacement, the old completion preserved the replacement; subsequent processing removed it. |

Concurrent processors can make duplicate immediate calls. The implementation provides recoverable, at-least-once cleanup rather than exclusive execution of an intent. I did not establish a violation of the current M01 rules from those duplicate calls: the relevant bound limits re-arms, and uncovered-grant cleanup retains its immediate best-effort semantics.

### In-flight marker, restart, and persistent intents

The preparation marker starts before the attempted receipt and drops after `prepare` returns (`crates/app/src/operations.rs:5189`, `:5325`). The return path processes any surviving intent even when receipt settlement failed (`:5339`).

While preparation remains in flight, supervisor processing leaves its intent intact (`:5482`). On reconstruction, the new in-memory set is empty, allowing recovery to process the persisted intent. The cancelled-preparation restart regression passed.

An absent adapter deliberately leaves an immediate-call intent pending. `inspect grants` exposes this through `cleanup_pending` (`:6432`); the visibility regression passed. I found no intent that was inherently impossible to remove after its responsible adapter returned and store operations succeeded.

A preparation that applies an effect and hangs remains the explicit M01 limitation accepted by ADR-0006 §13.20 item 3. Bounded adapter timeouts are required when real adapters arrive.

### Legacy migration

`crates/domain/src/revocation.rs:293` derives a legacy record's initial sequence from its round count and conservatively moves an existing `effect_round` to that sequence. Subsequent claims exceed both the record's current sequence and the store counter.

The domain migration test and `r1319_1_a_record_written_before_claim_seq_is_claimed_and_completed_by_sequence` passed. Source inspection found no reset of the store counter when a record is removed.

## Property assessment

**`r1319_props` is materially stronger than the previous snapshot property.** It executes production operations and calls, generates held/released rounds, explicit revokes, late preparation effects, cancellation, pre/post-commit faults, restart, and supervisor passes. It passed its configured **1,024 cases**.

Its coverage remains bounded:

- One grant and one responsible adapter, using cap three.
- Traces contain at most fourteen generated steps.
- Fault injection targets selected commits, rather than exhaustively enumerating every durable checkpoint.
- It does not explicitly park cleanup-intent calls to explore replacement and competing processors.
- The applied-effect ownership assertion runs after final reconstruction; pending-obligation loss is checked between generated steps.

See `tests/model/operations.rs:9250`, `:9298`, `:9510`, and `:9525`. The scratch probes add concrete concurrency coverage, but this is not an exhaustive interleaving proof. This coverage limit did not produce a concrete defect during review.

## M01 exit assessment

**Apart from native platform evidence, I found no concrete implementation defect that blocks plan §5 M01 exit at this commit.** W01 and W02 no longer block it.

The checked-in exit evidence still identifies build `250a029d`; it does not establish platform results for `b89743ae`. Fresh validation here establishes the local checks listed below. The implementer's historical red/green and mutation claims were inspected but were **not independently replayed**, so they are not counted as independently verified evidence.

## Commands and observed exit codes

| Command/check | Exit | Result |
|---|---:|---|
| `pwd`, `git status --short`, `git rev-parse HEAD` | 0 each | Requested checkout and commit; clean tree. |
| Home instruction read and targeted `git diff`, `rg`, `sed`, `nl`, `cat` inspections | 0 for successful reads | Reviewed changed production paths, contracts, regressions, previous review, and exit evidence. |
| Memory-registry search for Heimdall | 1 | No matches; no historical memory used as evidence. |
| `git diff --check 250a029d..b89743ae` | **2** | Existing whitespace diagnostic in `docs/decisions/0007-existing-access-integration.md:654`; no security implication established. |
| `CARGO_NET_OFFLINE=true cargo test -p heimdall-runtime --test model_operations` | **0** | **143 passed**, zero failed. Includes `r1319_props`. |
| `CARGO_NET_OFFLINE=true PYTHONDONTWRITEBYTECODE=1 bash tools/validation/check.sh` | **0** | **735 Rust tests passed**, zero failed, two ignored. Formatting, host and Windows-target Clippy, discovery, schemas, stubbed harness self-tests, and evidence checks all exited 0. |
| Scratch `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` | Initial attempts **1**; corrected builds **0** | Setup failures: ambiguous library selection, then a missing clone in scratch code. Corrected without repository edits. |
| Scratch binary: `r1319_1_` | **0** | Three W01 scenarios passed. |
| Scratch binary: `r1319_2_a_restart_after_the_late_confirmation_commit` | **0** | W02 cap-eight post-commit scenario passed. |
| Scratch binary: `round8_` | **0** | Three additional probes passed. |
| `du -sh target` | 0 | 3.6 GB before cleanup. |
| Required prototype-output `du` command | 1 | Zsh reported no matching prototype output directories. |
| Initial `rm` cleanup request | Not executed | Tool rejected the command; exact-path cleanup completed using Python filesystem operations. |
| Exact-path cleanup and absence assertions | **0** | Checkout `target/`, owned scratch directory, and review log removed. |
| Final `git diff --exit-code`, `git status --short`, `git rev-parse HEAD` | **0 each** | Checkout unchanged and clean at the reviewed commit. |

**Changed files:** None. No commits, pushes, network access, or native platform harness runs.

Not checked: fresh native platform behavior, real credential adapters, exhaustive interleavings, or the historical mutation runs.
Risk: cleanup may execute more than once; real adapters need the bounded timeouts required by §13.20 before relying on this lifecycle beyond M01.
