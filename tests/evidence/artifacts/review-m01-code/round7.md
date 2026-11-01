# M01-code-review-round7 — `250a029dc4a90e99f18aadd367520003454ccb1d` — **fix first**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Independent, adversarial, read-only review against `spec.md`, `plan.md` §5, ADR-0005 §3.5–§3.7, and ADR-0006 revision 2 through §13.18.

**Two reproduced defects block M01 exit independently of native platform evidence:** a superseded first-round confirmation can erase a newer pending obligation, and a durable late confirmation can lose its cleanup across restart.

The checked-in validation passes: **716 Rust tests passed, 0 failed, 2 ignored; `check.sh` exited 0.** Two additional throwaway tests, compiled against this checkout's production libraries, failed on their intended safety assertions.

## Disposition of the four automated findings

"Fixed" below refers to the reported scenario; it does not imply that the complete lifecycle is safe.

| Automated finding | Status | Source evidence and proving tests |
|---|---|---|
| **6230acf9: cleanup skips stopped/capped records or records without an obligation for the applying adapter** | **Fixed for the reported scenario** | `crates/app/src/operations.rs:2816` checks live ownership per applying adapter; `:2838` re-arms or adds an obligation. Cleanup returns without calling only after this transaction succeeds (`:5264`). Passing tests: `r1317_1_a_late_effect_on_a_capped_record_rearms_it_for_the_next_round`, `r1317_2_a_late_effect_with_no_obligation_for_its_adapter_adds_one`, and their restart variants. **W02 exposes an earlier durable boundary that these tests miss.** |
| **8d17ace9 [HIGH]: an in-flight revocation round clears an effect applied after its call** | **Partially fixed** | Cleanup records `effect_round` at `crates/app/src/operations.rs:2805`; completion checks the current claim and calls `cleared_by_round` at `:2552`. `crates/domain/src/revocation.rs:290` requires a strictly later round. Passing tests: `r1318_2_a_round_in_flight_when_a_late_effect_lands_does_not_clear_it`, `r1318_2_an_explicit_revokes_first_round_in_flight_does_not_clear_a_late_effect`, and the checked-in superseded-round case. **W01 reproduces a claim-identity collision that bypasses this protection.** |
| **8d17ace9 [MEDIUM]: re-arm bound keys collide across grants/adapters** | **Fixed** | `crates/app/src/operations.rs:2826` constructs the key from grant, adapter, token, and confirmed state. Empty tokens are excluded at `:2823`; legacy unscoped entries cannot equal newly scoped keys. Passing tests: `r1318_4_one_grants_rearm_never_bounds_another_grants_effect` and `r1318_4_an_unknown_or_empty_token_is_never_bounded`. |
| **8d17ace9 [MEDIUM]: reaching the re-arm bound suppresses a real late-effect call** | **Fixed for the reported scenario** | `crates/app/src/operations.rs:2835` returns bounded adapters for immediate calls; `:5273` dispatches them. Pending answers retain or add obligations at `:2883`. Passing tests: `r1318_4_a_bounded_late_effect_with_every_obligation_stopped_makes_one_immediate_call` and `r1318_4_a_pending_answer_to_a_bounded_call_is_tracked`. This does not prove crash safety between deciding and executing the call. |

The eight `r1317_*` and eleven `r1318_*` model cases also passed when compiled and run from a scratch copy outside the repository. Those runs reuse the checked-in scenarios; the two probes below add independent interleavings.

## New findings

### W01 — HIGH — A superseded first-round claim can match the new claim and erase its obligation

**Location:** `crates/app/src/operations.rs:2374`, `:2382`, `:2417`, and **`:2552`**.

**Defect:** An explicit revoke resets the record's round count and recorded effects, then identifies its new claim using only `(timestamp, round_count)`. Two first-round claims can therefore have the same identity. Completion treats an older claim as current, and its confirmation can clear the newer obligation because the explicit re-arm reset `effect_round` to zero.

Wall time is not a unique claim identifier. The reproduction uses the existing `VirtualClock` without advancing it. Production occurrence requires a repeated wall timestamp; I did not demonstrate that on a native clock.

**Concrete failure scenario:**

1. Hold a preparation before it applies its credential.
2. Start explicit revoke A. Its first-round call confirms the pre-effect state, but hold its response.
3. Release preparation. The credential applies; late-confirmation cleanup records the effect on the live obligation.
4. Start explicit revoke B at the same timestamp. It resets the count to round 1 and `effect_round` to zero. Hold B's response, which reports pending.
5. Release A's older confirmation while B's claim remains current.
6. A's `(timestamp, 1)` matches B's `(timestamp, 1)`. Completion deletes the obligation.
7. Release B's pending response. Its result reports remote pending, but completion does not recreate the deleted record. Restart leaves it absent.

**Evidence — observed:** Scratch test **`round7_first_round_claim_aba_loses_pending_obligation`** compiled successfully and failed with:

```text
old confirmation erased newer pending obligation
```

Before releasing A, the test asserted equality of both claims' timestamps and round counts, and verified the new obligation's `effect_round == Some(0)`. It then completed B, verified B's pending result, reconstructed `Operations`, and found the obligation still absent.

The checked-in superseded-round test at `tests/model/operations.rs:8389` uses an old **round 2** and a new **round 1**. It also completes the newer revoke before releasing the older response. It does not exercise this collision.

**Fix:** Give each durable claim a unique identity that survives counter resets, such as a persisted epoch and round identifier. Match completion against that identity, and order recorded effects within the same epoch. A superseded completion must not clear an effect-bearing obligation merely because wall time and the reset counter match.

### W02 — HIGH — A durable late confirmation can lose cleanup across restart

**Location:** **`crates/app/src/operations.rs:5206`**, `:5226`, `:5228`; recovery selection at `:3911` and `:3964`.

**Defect:** `confirm()` commits the late `Confirmed` receipt before invoking cleanup in a separate transaction. A failure after that commit—or a process crash at the same boundary—can prevent cleanup from recording ownership or re-arming the obligation. When the operation is already cancelled, restart excludes it from both recovery lists.

**Concrete failure scenario:**

1. Hold preparation before the credential is applied.
2. Revoke the grant and cancel the ensure operation.
3. Exhaust the covering record to the production cap of **eight** calls, all before the credential exists. The record and obligation are stopped.
4. Release preparation. The credential applies.
5. Persist its late `Confirmed` receipt, then interrupt before cleanup records ownership.
6. Restart. The operation is `Cancelled`, so recovery does not drive it. The covering record stays stopped, and subsequent supervisor passes make no call after the effect.

**Evidence — observed:** Scratch test **`round7_restart_after_confirm_commit_loses_cleanup`** used the production `FaultHook::AfterCommit` seam, armed only after the fake adapter applied its effect. It verified:

- Eight revocation calls occurred before the effect.
- The operation was cancelled and the covering record was stopped.
- The post-commit fault fired once.
- The late `Confirmed` receipt was durable.
- Restart followed by six supervisor passes made no additional adapter call.

It then failed with:

```text
late effect persisted but restart never rearmed cleanup
```

This is an observed in-process recovery failure at a durable checkpoint. The equivalent process-crash window is inferred from the transaction ordering; no native crash harness was run.

Strictly, this interrupts before `cleanup()` executes, rather than producing an unsafe successful return from it. It nevertheless leaves the system in the prohibited state: an applied effect, no live owning obligation, and no call made after the effect. It blocks the M01 crash-recovery obligation.

**Fix:** Register or re-arm cleanup ownership in the transaction that persists the late confirmation. Where cleanup must run later, persist a recoverable cleanup intent and process it even when its originating operation is settled. Cover cancellation/refusal settlement boundaries with the same recovery discipline.

## Invariant and property assessment

**`r1318_cleanup_never_leaves_an_applied_effect_unowned_and_uncalled` does not generate the dangerous lifecycle interleavings.** It passed during this review.

At `crates/app/src/operations.rs:9413`, its generator creates record snapshots; `claimed_at` is always `None` (`:9429`). It then invokes only `decide_applied_effect` (`:9469`). There is no sequence of claim, adapter call, late effect, explicit re-arm, completion, restart, or concurrent cleanup.

At `:9471`, a returned `EffectOwner::Bounded(list)` is treated as "called." The property does not execute the adapter call, verify its availability, or exercise the transaction that tracks its answer. It therefore proves a narrower decision-level property: the helper returns ownership or an instruction to call.

Other reviewed behavior:

- `round_cap` correctly applies `min(stored, configured)` at `crates/domain/src/revocation.rs:235`. The lower-cap recovery and supervisor regressions passed.
- Per-obligation attempt resets preserve a new budget when cleanup re-arms an exhausted obligation.
- Scoped known-effect keys bound re-arms. Empty/unknown tokens remain deliberately unbounded under §13.18.
- Cleanup's ownership decision and record updates share one transaction, which serializes competing decisions. That does not cover the surrounding confirmation, call, and completion boundaries demonstrated above.
- No additional concrete unbounded-call defect was reproduced.

The property should be extended with transition sequences and actual completion/call tracking. Both W01 and W02 should become regressions.

## M01 exit assessment

**Apart from native platform evidence, W01 and W02 block plan §5 M01 exit at this commit.** Passing baseline tests do not establish fail-closed revocation races or restart-safe cleanup.

The evidence record also remains incomplete for this head: `tests/evidence/m01-exit-claims.json:3` is `blocked`, and `:17` identifies build `6230acf9…`. Fresh validation here does not update its platform rows or artifact digests.

## Commands and observed exit codes

| Command/check | Exit | Observed result |
|---|---:|---|
| `pwd`; `git status --short`; `git rev-parse HEAD` | 0 each | Correct checkout, initially clean, requested commit. |
| Home instruction read; targeted `git diff`, `git show`, `rg`, `sed`, `nl`, and `cat` inspection | 0 for successful reads | Reviewed contracts, callers, revocation state, tests, earlier review material, and exit records. Exploratory reads of nonexistent split files returned 1 or 2. |
| Memory-registry search for Heimdall/M01 | 1 | No matches; no historical memory used as review evidence. |
| `git diff --check 6230acf9..250a029d` | 0 | No whitespace errors. |
| `CARGO_NET_OFFLINE=true cargo test -p heimdall-runtime --test model_operations` | **0** | **130 passed**, 0 failed. |
| `CARGO_NET_OFFLINE=true cargo test -p heimdall-app --lib r1318_` | **0** | **5 passed**, including the property. |
| Scratch `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` | Initial attempts **1**; corrected builds **0** | First omitted `serde`; a later attempt mixed feature-build libraries. Corrected by linking a consistent library set. These compilation failures were harness setup failures. |
| Scratch suite filters `r1317_` and `r1318_` | **0 each** | **8** and **11** existing regression scenarios passed. |
| Initial scratch claim probe, with newer revoke already completed | **0** | No failure in that ordering. Refined to hold the newer response in flight. |
| Final scratch suite filter `round7_` | **101** | **2 failed** on the safety assertions documented in W01 and W02. W02 also reproduced with cap eight. |
| `CARGO_NET_OFFLINE=true PYTHONDONTWRITEBYTECODE=1 bash tools/validation/check.sh` | **0** | **716 Rust tests passed, 0 failed, 2 ignored**. Formatting, host/Windows-target Clippy, discovery, schemas, stubbed harness self-tests, evidence self-tests, and validation of 86 evidence records passed. |
| `du -sh target` | 0 | 3.8 GB at the measured checkpoint. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | No matching prototype output directories. |
| Exact-path cleanup of checkout `target/` and owned scratch outputs | **0** | Build directory, scratch sources/binaries/logs, and scratch-path marker removed; absence asserted. |
| Final `git diff --exit-code`; `git status --short`; `git rev-parse HEAD` | **0 each** | Checkout unchanged and clean at `250a029dc4a90e99f18aadd367520003454ccb1d`. |

**Changed files:** None. No commits, pushes, external network access, or native harness runs.

Not checked: fresh native platform behavior, real credential adapters, or native process-crash reproduction of these two probes.
Risk: unresolved revocation obligations can disappear, and a late-applied credential can survive restart without any subsequent revocation call.
