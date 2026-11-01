# M01-code-review-round5 — `b933d3eb88a4108a9724dd93e35f9fffa23f4456` — **fix first**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Independent, read-only adversarial review of `git diff ca21d621..b933d3eb`, assessed against `spec.md`, `plan.md`, ADR-0005 §3.5–§3.7, and ADR-0006 revision 2 through §13.14.

**T01 and T02 are fixed for the round-4 failure scenarios.** Offline workspace validation exited **0**, with **675 Rust tests passed, 0 failed, 2 ignored**. Two additional probes failed: one reproduces the already-assigned §13.14 item 2 gap; the other demonstrates incorrect inspection output when revocation records overlap.

## T01 and T02 disposition

| Finding | Status | Source evidence and proving tests |
|---|---|---|
| **T01 — failed completion transactions bypass the retry cap** | **fixed** | `crates/app/src/operations.rs:2298` plans and counts the first round before its record is persisted at `:2310`. Retry rounds increment and persist their claim at `:2375`–`:2378`, before adapter invocation at `:6710`. Completion clears the matching claim at `:2427`–`:2433`; failure leaves the consumed attempt durable. Re-ran **`r1312_1_failed_completion_commits_never_allow_more_adapter_calls_than_the_cap`**, which uses `PendingCounter`, a `BeforeCommit` fault armed inside `revoke`, and the production supervisor with cap 2. It passed. **`r1312_1_a_crash_between_the_adapter_call_and_its_completion_counts_the_round`** and **`r1312_1_an_interrupted_explicit_revoke_is_not_called_again_by_recovery`** also passed. |
| **T02 — removing the original adapter falsely completes pending revocation** | **fixed** | `crates/app/src/operations.rs:2188` plans calls only for responsible adapters and retains unavailable obligations without consuming attempts. Completion at `:2425`–`:2441` removes only obligations confirmed by a responsible adapter. Re-ran **`r1312_2_removing_the_original_adapter_never_completes_its_pending_revocation`**: pending withdrawal, restart with another adapter, repeated due passes, continued pending visibility with no state change, then restoration and confirmation. It passed. **`r1312_2_an_empty_adapter_list_never_completes_a_pending_revocation`** and **`r1312_2_a_record_written_before_obligations_keeps_its_responsible_adapter`** also passed. |

These tests were executed both by workspace validation and, for the `r1312_*` suite, from a copied fixture suite compiled outside the repository against this checkout's production libraries. The crash tests reconstruct the runtime in process; they are not native process-crash evidence.

## New findings

### U01 — Minor — Overlapping revocation records overwrite the grant's retry status in inspection

**Location:** `crates/app/src/operations.rs:5618`–`:5637`, particularly `remote.insert` at `:5622`.

**Defect:** Inspection constructs one `RemoteView` per grant by replacing any previously collected view. A child can have obligations in both its own revocation record and its ancestor's record. The last record in root order determines the displayed attempts, stopped flag, and unavailable reason, regardless of the other record.

**Concrete failure scenario:**

1. Create a parent and delegated child with pending remote effects.
2. Revoke the lexicographically greater root and run its schedule to cap 3.
3. Revoke the other root with a new request.
4. Both records now contain an obligation for the child. The first record in root order remains retryable; the last is stopped.
5. Inspect the child. Its output says retries stopped, although another durable record will continue retrying it.

The reproduction chooses the revoke order from the generated IDs. It uses ordinary operations and supervisor passes; it does not edit stored records.

**Evidence — observed:** Throwaway test **`round5_overlapping_roots_inspect_combines_pending_obligations`** failed:

```text
round5 overlapping_records=2 view_attempts=3 view_stopped=true
assertion failed: one obligation remains retryable
left: Bool(true)
right: false
```

The probe asserted that both records contained the child, the first record was not stopped, and the second was stopped before inspecting it.

**Impact:** Misleading operational status. The underlying obligations remain stored, and `remote_pending` remains true. This probe did not demonstrate lost obligations or an authorization failure.

**Fix:** Aggregate all records covering a grant. The grant's stopped indicator must require every remaining obligation across those records to be stopped; unavailable reasons must also be combined. Define the attempt/timestamp aggregation consistently and add the overlapping-root regression.

### U02 — Major — An attempted effect can disappear from pending visibility when its adapter is unavailable

**Covered by §13.14 item 2.**

**Location:** `crates/app/src/operations.rs:2281`–`:2293`, especially the tracking predicate at `:2286`.

**Defect:** A responsible adapter becomes an obligation only when the grant is `Revoking` or that adapter is configured. A terminal grant with a recorded attempted effect and an unavailable adapter satisfies neither condition. The code can therefore return no pending remote effect without obtaining confirmation.

**Concrete failure scenario:**

1. Preparation records its `Attempted` receipt and returns a partial result, leaving the grant `Preparing`.
2. Restart without the preparing adapter.
3. Recovery leaves the grant terminal.
4. Explicitly revoke it.
5. No obligation is created, the revoke result lists no remote pending grant, and no pending record remains.

**Evidence — observed:** Throwaway test **`round5_attempted_prepare_missing_adapter_stays_pending`** used the existing reconciliation-stage failure fixture. It verified the partial result, the initial `Preparing` state, and the persisted preparing-adapter identity before restarting with no adapters. Its safety assertion failed:

```text
round5 missing_adapter pending_records=0 remote_pending=0 state=Failed
assertion failed: attempted effect cannot be confirmed without adapter
```

The checked-in **`r1313_2_a_grant_revoked_while_preparing_is_tracked_until_its_adapter_confirms`** passes because the responsible adapter remains configured and receives a call. It does not cover this unavailable-adapter combination.

**Fix:** Apply §13.14 item 2: retain an `adapter_unavailable` obligation when an effect receipt establishes an attempted, uncertain, or applied effect, even when the grant is terminal and no adapter call can be made. A grant with no effect receipt needs no such obligation.

## Other inspected paths and M01 exit

The preparing adapter is written with the first `Attempted` receipt at `crates/app/src/operations.rs:4660`–`:4680`. The store's add-only comparison at `crates/store/src/ext.rs:940`–`:949` rejects replacement or clearing of an already-recorded adapter. **`grant_origin_gains_its_preparing_adapter_once`** and **`r1313_1_the_preparing_adapter_stays_responsible_after_operation_retention`** passed.

Per-obligation caps, conservative conversion of old counts, and interrupted-round scheduling passed the eight `r1313_*` regressions. The `r1312_*` property test also passed. I found no additional concrete blocker in `run_round`, claim completion, startup interrupted-round marking, or the supervisor wake computation during this review.

**Apart from native platform evidence, M01 exit remains blocked at this commit by U02.** It is already covered by the parallel §13.14 item 2 assignment and needs integrated validation after that fix lands. U01 is a concrete inspection defect, but the reproduced behavior preserves pending obligations and does not independently demonstrate failure of the core revocation safety gate.

Acceptance evidence also remains tied to the earlier head: `tests/evidence/m01-exit-claims.json:3` is `in_progress`, and `:16` names `ca21d621`. Successful validation in this review does not update those records or their artifact digests.

## Commands and observed exits

| Command/check | Exit | Result |
|---|---:|---|
| `pwd`; `git status --short`; `git rev-parse HEAD`; read active home instructions | 0 each | Correct checkout and requested commit; clean tree. |
| Memory-registry `rg` search for Heimdall | 1 | No matches; no memory used as review evidence. |
| `git diff --stat ca21d621..b933d3eb`; targeted `git diff`, `rg`, `sed`, `nl`, and `cat` reads | 0 for successful reads | Inspected changed implementation, tests, contracts, earlier review material, and exit records. |
| `CARGO_NET_OFFLINE=true PYTHONDONTWRITEBYTECODE=1 bash tools/validation/check.sh` | **0** | **675 Rust tests passed, 0 failed, 2 ignored**. Formatting, host and Windows-target Clippy, test discovery, schema checks, stubbed native-harness self-tests, 25 evidence-generator tests, and validation of 86 evidence records passed. |
| Python creation and extension of `/tmp/heimdall-round5-probe/probe.rs` | 0 | Copied fixture suite plus two review probes; no repository source changes. |
| Three `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` compilations | 0 each | Scratch suite linked against checkout production libraries. |
| `/tmp/heimdall-round5-probe/probe r1312_ --test-threads=1` | **0** | Eight tests/property checks passed, including both round-4 reproduction scenarios. |
| `/tmp/heimdall-round5-probe/probe r1313_ --test-threads=1` | **0** | All eight tests passed. |
| Initial scratch run of `round5_` containing only the overlap probe | **101** | U01 assertion failed. |
| Final `/tmp/heimdall-round5-probe/probe round5_ --nocapture --test-threads=1` | **101** | Both U01 and U02 safety assertions failed. |
| Python validation-log totals | 0 | Confirmed 675 passed, 0 failed, 2 ignored; 25 evidence-generator tests and 86 valid records. |
| `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` | 1 | No matching prototype output directories. |
| `du -sh target` | 0 | 3.3 GB before cleanup. |
| Guarded Python removal of checkout `target/`, exact scratch directory, and review log | 0 | Removed build and review scratch outputs. |
| Final absence checks; `git diff --exit-code`; `git status --short`; `git rev-parse HEAD` | 0 each | Build/scratch outputs absent; checkout clean at the requested commit. |

**Changed files:** None. No commits, pushes, network access, or native remote harness runs.

Not checked: fresh native Linux/Windows/WSL behavior, real credential adapters, or actual process-crash recovery.
Risk: U02 loses truthful pending visibility until the assigned fix lands; U01 can falsely report that all retries have stopped.
