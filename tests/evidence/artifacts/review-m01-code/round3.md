# M01-code-review-round3 — `01747a6b4b04d4a8927a4407e24c514d2f715586` — **fix first**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Independent, read-only adversarial re-review of `git diff 10414f10..01747a6b`.

**The original R01–R09 defects are fixed at this commit. M01 still needs fixes before exit**, including the pending §13.9 work described below. Two additional throwaway probes reproduced §13.9 defects despite the passing baseline.

Offline validation exited **0**: **620 Rust tests passed, 0 failed, 2 ignored**, plus formatting, host and Windows-target Clippy, test discovery, schema comparison, local native-harness self-tests, and 25 evidence-generator self-tests.

No repository files were modified. No network access or native harness execution occurred. The checkout's `target/`, temporary probe directory, and temporary validation log were deleted. Final Git status was clean.

## Round-2 findings

"Fixed" addresses the original finding; it does not close related §13.9 work or current-head release evidence. Every regression test named below executed successfully through `check.sh`.

| Finding | Status | Source evidence and proving test |
|---|---|---|
| **R01 — replacement published before issuer signing** | **fixed** | `crates/app/src/operations.rs:6669` checks publication predicates and generation; `:6696` returns the fresh reservation without publishing it; `:6725` tracks the next attempt. Tests: `r138_1_a_rereservation_returns_to_the_issuer_unpublished`, `r138_1_a_revoke_between_signing_the_replacement_and_publishing_it_voids_it`, `r138_1_an_expiry_between_signing_the_replacement_and_publishing_it_voids_it`. `review_13_6_11_a_generation_still_racing_after_three_attempts_is_service_unavailable` checks exactly three round trips and that all three entries end voided. |
| **R02 — one approval wait per waiter** | **fixed** | `operations.rs:2933` spawns all continuations before waiting and uses one absolute deadline for every join. Test: `r138_2_a_decision_resuming_five_waiters_waits_one_bound_in_total`, which holds preparation while five waiters resume. This directly exercises the round-2 reproduction. |
| **R03 — retention silently loses held events** | **fixed** | `crates/app/src/events.rs:459` compares the retained tail with the page boundary inside the store transaction; `:412` forces resynchronization on `CatchUp::Trimmed`. Tests: `r03_retention_between_a_failed_catch_up_and_its_retry_requires_a_resync`, `r03_retention_gap_reaches_session_receivers_through_the_relay_as_a_lag`, `r03_age_retention_before_an_announcement_requires_a_resync`. The first reproduces the round-2 failure sequence and now observes resync instead of continuity. |
| **R04 — fully covered waiter still needs approval** | **fixed** | `operations.rs:4739` takes `proceed_covered`; `:2318` records standing-policy coverage, withdraws pending decisions, and resumes waiters. Tests: `r137_2_a_fully_covered_waiting_request_activates_without_a_decision`, `r137_2_a_fully_covered_shared_request_activates_every_waiter_once`. |
| **R05 — continuing use ignores approved delta** | **fixed** | `operations.rs:6217` persists approval with the grant; `:867` onward compares the currently required delta with the recorded grant approval. `crates/store/src/ext.rs:829` stores the basis independently of operation retention; migration `0003_grant_approval.sql:18` backfills it. Tests: `r137_3_an_approved_grant_survives_purge_of_its_operation_and_revalidates`, `r137_3_a_narrowing_outside_the_approved_delta_ends_the_grant`, `r137_3_a_narrowing_inside_the_approved_delta_and_a_pause_keep_the_grant`, `grant_approval_is_written_once_and_survives_operation_purge`. Grant-context availability has the separate S02 defect. |
| **R06 — creator cancellation fails surviving waiters** | **fixed** | `operations.rs:5550` transfers waiting ownership and pending decisions; `:1250` permits a cancelled creator to continue approved preparation for attached operations; `:1295` ends orphaned preparation. Tests: `r137_4_cancelling_the_creator_moves_the_shared_decision_to_the_oldest_waiter`, `r137_4_the_shared_grant_ends_only_when_every_waiter_cancelled`, `r137_4_a_deny_after_a_transfer_settles_every_waiter`, `r138_5_cancelling_the_creator_after_approval_leaves_the_preparation_to_the_waiters`, `r138_5_a_restart_after_the_creators_cancellation_completes_the_shared_preparation`. See S05 for the remaining active-grant branch coverage. |
| **R07 — environment writes do not move generation** | **fixed** | `crates/store/src/ext.rs:692` advances authority generation in the same transaction as every accepted environment write. Tests: `upsert_environment_advances_the_authority_generation_on_every_write`, `r137_5_an_environment_permission_change_revalidates_and_ends_the_grant`. |
| **R08 — incomplete run incorrectly classified blocked** | **fixed** | `tests/native/m01/m01-evidence.py:335` and `:339` classify missing targets and incomplete current-build runs as `in_progress`; an identified missing capability is handled separately. Tests: `test_an_expected_test_absent_from_a_current_build_run_is_in_progress`, `test_a_whole_target_absent_from_a_current_build_run_is_in_progress`, `test_the_end_to_end_flow_reports_an_incomplete_run_as_in_progress`, and the missing-capability/platform cases. |
| **R09 — missing service-stop fallback e2e test** | **fixed** | `tests/e2e/cli_m01.rs:1674`, `service_stop_falls_back_to_a_signal_when_the_control_endpoint_is_unusable`, exercises the unusable control endpoint with a valid advertisement and checks signal fallback, successful exit, termination, and advertisement removal. |

The store transfer paths read, validate, and update within the serialized transaction. Although the final `transfer_waiting_grant` SQL update predicates only on ID, the preceding owner/state checks remain protected by that transaction. I found no concurrent-caller CAS bypass in these paths. `withdraw_decision` uses the pending-state CAS in `write_decision`.

## Findings

### S01 — Major — Uncertain wall time can irreversibly expire a grant

**Covered by §13.9 item 1.**

**Location:** `crates/app/src/operations.rs:6367`, `:6393`, `:6411`.

**Defect:** After the gate returns `TIME_UNCERTAIN`, `tick` substitutes the raw wall clock and uses it to decide expiry. Conversely, continuous-budget expiry is checked only when `safe` is present.

**Concrete failure:** Activate a one-hour grant, move only the wall clock forward two hours, confirm that use returns `TIME_UNCERTAIN`, then run a scheduler pass. The grant becomes permanently `Expired`, although its trusted continuous budget has not elapsed.

**Evidence — observed:** Additional throwaway test `round3_forward_jump_must_not_expire`, compiled against this checkout's production libraries:

```text
ROUND3 forward_jump_state=Expired
assertion failed:
  left: Expired
 right: Active
```

The checked-in `r138_4_a_pause_or_uncertain_time_never_ends_a_grant` passes because its uncertain wall reading moves backwards and does not appear beyond the deadline. It does not prove the forward-jump requirement.

**Fix:** Under uncertainty, disregard apparent wall expiry and evaluate only the persisted, same-boot continuous budget. Add both tests required by §13.9 item 1: forward wall jump preserves the grant; exhausted continuous budget expires it.

### S02 — Major — A parent retained only by a child loses its revalidation context

**Covered by §13.9 item 2.**

**Location:** `crates/app/src/operations.rs:680`, `:685`, `:701`, `:703`.

**Defect:** `grant_context` searches open/unresolved operations and direct consumer bindings. Once the parent's operation is settled and its direct binding released, a child reference keeps the parent alive but supplies no accepted context.

**Concrete failure:** Create parent and delegated child grants. Release the parent's own binding. Write an unchanged environment record to cause an unrelated generation bump. Bind using the child's existing binding. Revalidation of the parent fails because its profile/caller/mechanism context cannot be reconstructed.

**Evidence — observed:** Additional throwaway test `round3_parent_without_binding_still_serves_child` failed:

```text
code: CredentialExpired
message: "the grant's authority can no longer be re-validated"
```

The checked-in `r138_4_an_undetermined_revalidation_ends_nothing` passes while checking only that grants remain active and untombstoned. It never verifies that the child can still use its authority.

**Fix:** Persist and derive revalidation context from the grant's own authoritative record, independently of consumer bindings and operation retention. Verify a child bind and issuance after releasing the parent binding and moving generation.

### S03 — Major — Interrupted withdrawals have no completion retry

**Covered by §13.9 item 3.**

**Location:** `crates/app/src/operations.rs:1709`, `:5870`, `:5900`, `:6375`.

**Defect:** Withdrawal commits the tombstone and moves grants to `Revoking` before adapter denial and completion. Completion is best effort. If it fails, or the process dies between phases, subsequent scheduler passes explicitly skip `Revoking` grants. Startup recovery does not reconstruct these withdrawal completions.

**Concrete failure:** Authority withdrawal commits successfully. The process dies before `complete_withdrawals`, or its completion transaction fails. After restart, the grant remains `Revoking`; the final authority-withdrawn lifecycle event and residual report are never completed. The same problem affects an adapter-pending withdrawal that later becomes completable.

**Evidence — inferred from production control flow:** `complete_withdrawals` logs a failed completion but leaves no retry item; `tick` skips the durable state requiring recovery. No crash probe was executed for this finding. The passing ordinary withdrawal tests exercise completion without this interruption.

**Fix:** At startup and every scheduler pass, reconstruct and idempotently complete pending withdrawals. Persist enough completion state to prevent duplicate final events and preserve the correct cascade and residual. Add the tombstone-to-completion crash test required by §13.9 item 3.

### S04 — Minor — Descriptor fallback silently leaves high inherited descriptors open

**Location:** `crates/runtime/src/platform.rs:261`, `:271`, `:334`, `:345`.

**Defect:** When `close_range` fails and descriptor enumeration is unavailable, the fallback visits only descriptors below `min(RLIMIT_NOFILE.soft, 65536)`. An already-open descriptor may exceed either bound: limits can be lowered after opening descriptors, and supported Linux limits can exceed 65,536. Both hygiene entry points return success implicitly after this incomplete scan.

**Concrete failure:** A Linux caller passes a non-CLOEXEC pipe writer at descriptor 70,000. `close_range` is unavailable or denied, and `/proc/self/fd` cannot be read. Launcher marking and runtime startup closing both miss that descriptor. The detached runtime retains the writer, preventing the caller's reader from observing EOF.

**Evidence — inferred:** The range and cap are explicit in the implementation. The new descriptor tests exercise descriptor 9 with ordinary enumeration available; they do not exercise this fallback. This platform condition was not reproduced locally.

**Fix:** Do not silently claim descriptor sanitation after a partial scan. Use a mechanism that covers the actual open set, or fail startup/spawn explicitly when complete sanitation cannot be established. Add an injected fallback test with an open descriptor above a subsequently lowered soft limit.

### S05 — Minor — Last cancellation after shared activation lacks its required test

**Covered by §13.9 item 4.**

**Location:** `crates/app/src/operations.rs:1326`; `tests/model/revocation.rs:4285`.

**Defect:** `end_orphaned_in` implements `Active`/`Degraded → Released` when the cancelled creator has no remaining attached operations or grant references. The checked-in last-cancellation regression exercises the `Preparing → Cancelled` branch.

**Concrete failure scenario to test:** Let the cancelled creator's continued preparation activate the shared grant, while preventing attached operations from committing bindings. Cancel every attached operation. The final cancellation must release the grant and clean up its credential without creating a revocation tombstone.

**Evidence — observed coverage gap, not an observed implementation failure:** The branch exists, but the required active-state test is absent.

**Fix:** Add the targeted test specified by §13.9 item 4, including state, cleanup, and absence of revocation assertions.

## Additional inspection results

- `lead_all_bounded` starts every task before joining and shares one absolute deadline. Dropping timed-out join handles detaches the work, matching the caller-timeout contract. Join failures become operation errors. I found no new sequential-wait multiplication or unbounded retry loop.
- The replacement-publication path returns at each issuer handoff and preserves the three-attempt count. Each final publication reassesses predicates in its own transaction.
- Retention resync uses forced broadcast lag. Its no-concurrent-drain assumption matches the production current-thread executor. The reported `subscriber_lagged` reason is explicitly accepted by §13.9 item 6.
- The CLI calls `close_inherited_descriptors` before constructing the Tokio runtime or opening its service files. I found no current call-order evidence that it closes a Heimdall-owned runtime descriptor. Its documented precondition remains essential.
- The inspected descriptor FFI uses integer arguments or correctly aligned writable storage. S04 concerns coverage of the fallback.
- Linux zombie handling consumes state field 3, then selects start-time field 22 correctly. `Z`/`X` returns `None`. This was source inspection and cross-target checking, not a native Linux execution.
- Migration 0003's missing-basis behavior follows the accepted §13.8 item 6 ruling: a v2 grant without recoverable approval must rely on standing policy alone.

## M01 exit

**Yes—apart from native platform evidence, work still blocks plan §5 M01 exit.**

S01–S03 require the pending §13.9 implementation and regression verification. S05 requires the expressly mandated active-state cancellation test. S04 leaves the descriptor-hygiene contract incomplete under its fallback conditions.

The acceptance records also remain stale. For example, `tests/evidence/m01-a19-operations.json:3` is `in_progress`, and `:9` identifies `f9ed3454 + uncommitted …`, not this reviewed commit. Final integrated-head evidence records and artifact digests must be regenerated; this review's passing local check does not update those records.

## Commands and observed exits

| Command/check | Exit | Result |
|---|---:|---|
| `git rev-parse HEAD`; `git status --short`; `git diff --exit-code` | 0 each | Pinned commit confirmed; checkout clean before and after review. |
| `git diff --stat 10414f10..01747a6b`; targeted `git diff` reads | 0 | Inspected relevant production, migration, test, contract, and evidence-generator changes. |
| Targeted `cat`, `sed`, `nl`, and `rg` reads | 0 for successful reads | Supporting source and contract inspection. One combined search returned 2 because it included nonexistent `crates/heimdall/src/lib.rs`; existing `main.rs`, `cli.rs`, and `service_cmd.rs` were subsequently inspected. |
| Memory-registry search for Heimdall/M01 | 1 | No matches; no memory used as review evidence. |
| `CARGO_NET_OFFLINE=true PYTHONDONTWRITEBYTECODE=1 bash tools/validation/check.sh` | **0** | 620 Rust tests passed, 0 failed, 2 ignored; every validation step passed, including 25 evidence-generator tests. |
| Python extraction of validation totals and step exits | 0 | Confirmed the totals and individual successful step exits above. |
| Initial throwaway `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` | **1** | Missing `--extern tempfile`; corrected before execution. |
| Corrected throwaway probe compilation | **0** | Built outside the repository against this checkout's production libraries and copied fixture helpers. |
| Probe binary `round3_ --nocapture` | **101** | Both additional assertions failed: uncertain forward jump expired the grant; child bind failed after releasing the parent binding and moving generation. |
| `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` | **1** | No matching prototype build-output directories. |
| `du -sh target` | 0 | 3.2 GB before cleanup. |
| Guarded Python removal of checkout `target/`, exact reviewer temporary probe directory, and temporary validation log | **0** | Removed all reviewer-created build/probe/log outputs. |
| `test ! -e target`; final Git status/diff checks | 0 each | Target removal verified; no tracked changes. |

**Changed files:** None. No commits or pushes.

Not checked: fresh native Linux/Windows/WSL execution, native lock or suspend/resume behavior, real credential adapters, or the integrated §13.9 fixes.
Risk: the passing baseline does not close the two reproduced §13.9 failures, interrupted withdrawal recovery, or the inferred descriptor fallback gap.
