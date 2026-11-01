# M01-code-review-round4 — `ca21d621b1e2448d1cb858bb6f04c46c7796872d` — **fix first**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Independent, read-only adversarial review of `git diff 01747a6b..ca21d621`, assessed against `spec.md`, `plan.md`, ADR-0005 §3.5–§3.7, and ADR-0006 revision 2 through §13.11.

**Apart from native platform evidence, two reproduced remote-revocation defects still block M01 exit.** The ordinary round-3 regressions now pass, but failed completion transactions can bypass the retry cap, and removing an adapter can cause an unresolved remote revocation to be reported as completed.

Offline validation exited **0**: **652 Rust tests passed, 0 failed, 2 ignored**. Formatting, host and Windows-target Clippy, test discovery, schema comparison, local native-harness self-tests, and all 25 evidence-generator self-tests passed. Two additional adversarial probes failed their safety assertions against the production libraries.

## S01–S05 disposition

"Fixed" refers to the original failure scenario. S03 is only partially fixed because the new recovery machinery has the defects below.

| Finding | Status | Source evidence and proving tests |
|---|---|---|
| **S01 — uncertain wall time irreversibly expires grants** | **fixed** | `crates/app/src/timegate.rs:272` uses the accepted observation for wall expiry and a fresh reading only for continuous-budget exhaustion; `:288` evaluates only that budget under uncertainty. `crates/app/src/operations.rs:6914` applies this distinction in `tick`; `:1735` does so in `grant_end`. Passing tests: `r139_1_a_forward_wall_jump_under_uncertainty_leaves_the_grant_non_terminal`, `r139_1_a_continuous_budget_running_out_under_uncertainty_expires_the_grant`, `r139_1_an_unassessed_wall_reading_after_the_gate_accepted_time_ends_nothing`, and `r139_1_an_unassessed_wall_reading_never_turns_a_withdrawal_into_an_expiry`. The first two directly exercise the round-3 reproduction ideas. |
| **S02 — parent retained only by a child loses revalidation context** | **fixed** | `crates/app/src/operations.rs:724` derives context from the persisted grant origin and approval basis. Both creation sites persist the origin (`:3516`, `:4076`). Migration `crates/store/migrations/0004_grant_origin.sql:22` backfills from recovery intents, then `:48` from direct bindings. Passing test: `r139_2_a_parent_kept_alive_by_its_child_revalidates_after_an_unrelated_generation_move` verifies child issuance, publication, and binding after the parent's direct binding is released. Migration tests `migration_0004_preserves_a_populated_v3_database_and_backfills_the_origin` and `failing_0004_step_leaves_the_v3_database_untouched` also passed. |
| **S03 — interrupted withdrawals have no completion retry** | **partially fixed** | Startup invokes recovery at `crates/app/src/operations.rs:3090`; each tick invokes it at `:6984`. The sweep at `:6269` reconstructs tombstoned roots, and completion records the report marker and event together at `:6233`. Passing tests: `r139_3_a_crash_between_the_withdrawal_tombstone_and_its_completion_completes_on_restart`, `r139_3_the_scheduler_pass_completes_an_interrupted_withdrawal_once`, and `r139_3_a_pending_remote_effect_completes_in_a_later_pass_without_a_second_report`. The original stranded-withdrawal scenario is repaired; **T01 and T02** leave the broader recovery contract incomplete. |
| **S04 — descriptor fallback silently misses high descriptors** | **fixed under the accepted §13.10 item 4 contract** | `crates/runtime/src/platform.rs:318` scans to the finite hard limit; `:331` rejects unreadable, infinite, or over-cap limits. Errors propagate before spawn through `crates/runtime/src/launcher.rs:201` and before service startup through `crates/heimdall/src/service_cmd.rs:107`. Passing tests: `hard_limit_scan_reaches_a_descriptor_above_a_lowered_soft_limit` and `unbounded_or_over_cap_hard_limit_without_enumeration_is_an_error`. This verifies the injected fallback locally, without claiming native Linux execution. |
| **S05 — missing active-state last-cancellation test** | **fixed** | `crates/app/src/operations.rs:1419` releases an active/degraded orphan with no references. Passing test `r139_4_an_activated_shared_grant_is_released_when_every_attached_operation_cancels` at `tests/model/revocation.rs:4370` checks activation before cancellation, final release, credential cleanup, no tombstone or generation movement, and no resurrection after in-process restart. |

## New findings

### T01 — Major — Failed completion transactions permit unlimited adapter rounds despite the durable cap

**Location:** `crates/app/src/operations.rs:6402`, `:6413`; `crates/runtime/src/supervisor.rs:556`.

**Defect:** A retry calls the adapters before durably consuming an attempt. The attempt count advances only in the subsequent completion transaction. If that transaction fails, the supervisor reschedules using the unchanged count. Repeated completion failures therefore allow arbitrarily many adapter calls while the persisted count remains below the cap.

A process crash after the adapter call and before that commit has the same accounting window.

**Concrete failure scenario:** A remote revocation remains pending. Configure a two-round cap, including the initial local denial. Each due retry reaches the adapter successfully, but its completion transaction fails before commit. Every subsequent due pass calls the adapter again at attempt one.

**Evidence — observed:** Throwaway test `round4_failed_completion_must_still_cap_calls`, compiled outside the repository against this checkout's production libraries:

```text
round4 calls=5 durable_attempts=1 cap=2 faults=4
assertion failed: adapter rounds exceed durable cap
```

The probe used the existing `PendingCounter` fixture, the production `FaultHook` at `BeforeCommit`, and the production supervisor with `max_attempts: 2`. It armed the fault inside each adapter revocation call, ensuring the failure occurred in the transaction following that call. Four due passes produced four additional calls and four failed commits.

The checked-in `r1310_3_a_pending_remote_effect_is_retried_on_the_jittered_schedule_up_to_the_cap` passes because every retry completion commits; its restart occurs after the cap has already been persisted (`tests/model/operations.rs:5412`).

**Fix:** Durably claim and consume a bounded round before invoking adapters. Recovery must conservatively count an interrupted claimed round as attempted. Keep the pending obligation until completion is confirmed, and preserve explicit authorized re-arm semantics. Add a regression covering failed completion commits and interruption between adapter invocation and completion.

### T02 — Major — Removing the original adapter falsely completes its pending remote revocation

**Location:** `crates/app/src/operations.rs:6173`, `:6402`, `:6409`; `crates/domain/src/revocation.rs:69`.

**Defect:** The pending record retains grant IDs but no adapter-specific unresolved obligations. A retry calls only the adapters currently configured. If the adapter that previously reported a remote effect pending is absent, an unrelated adapter's successful response—or an empty adapter list—produces an empty pending set. Completion then marks the grant revoked and deletes its pending record.

Absence of the responsible adapter provides no confirmation that its remote effect completed. This violates the requirement that pending remote revocation remain visible.

**Concrete failure scenario:** Adapter A reports a remote revocation pending. The runtime restarts with A removed from configuration and adapter B configured instead. At the next due retry, B reports nothing pending for that grant. Heimdall marks the grant `Revoked` and removes the retry record even though A's remote effect remains unresolved.

**Evidence — observed:** Throwaway test `round4_missing_adapter_must_not_clear_pending`:

```text
round4 original_adapter_calls=1 pending_records=0 grant_state=Revoked
assertion failed: unavailable original adapter cannot prove remote completion
```

The probe created a pending withdrawal using the existing `PendingCounter`, restarted through the existing "mechanism unavailable" fixture, then advanced the virtual clock to the next scheduled round. The original adapter remained pending and received no additional call.

The checked-in missing-mechanism tests exercise usable grants and their degraded transitions. The pending-revocation tests retain the original adapter. Neither covers this combination.

**Fix:** Persist the unresolved adapter obligations and retain them when the responsible adapter is unavailable. Clear an obligation only after its responsible adapter confirms completion through the supported protocol. Add a restart regression that removes the original adapter and verifies continued pending visibility, then restores it and verifies confirmed completion.

## Other inspection results and M01 exit

The ordinary degraded transitions separate capability from authority: `track_mechanism_in` checks ending conditions before changing state, and repair requires revalidation (`crates/app/src/operations.rs:1894`, `:1897`). The recorded degradation reason is removed transactionally when the grant leaves `Degraded`. No additional concrete blocker was established in those paths.

The withdrawal report marker and event share their completion transaction, so the inspected path does not commit the marker independently of the report. Ordinary restart recovery and repeated passes produced exactly one withdrawal report in the passing regressions.

**M01 should not exit at this commit, even setting native platform evidence aside.** T01 breaks bounded recovery; T02 loses truthful pending-revocation state. Both reproduce with local disposable fixtures.

Integrated-head acceptance records also remain outstanding: for example, `tests/evidence/m01-a19-operations.json:3` remains `in_progress`, and `:9` identifies an older uncommitted build. This review's successful validation does not regenerate those records or artifact digests.

## Commands and observed exits

| Command/check | Exit | Result |
|---|---:|---|
| `pwd`; `git status --short`; `git rev-parse HEAD`; read reviewer's own instruction file | 0 each | Correct checkout and commit; initially clean. |
| Memory-registry `rg` search for Heimdall | 1 | No matches; no memory used as review evidence. |
| `git diff --stat 01747a6b..ca21d621`; targeted `git diff`, `sed`, `nl`, `cat`, and `rg` reads | 0 for successful reads | Inspected changed implementation, migrations, tests, contracts, prior reviews, and evidence records. |
| `CARGO_NET_OFFLINE=true PYTHONDONTWRITEBYTECODE=1 bash tools/validation/check.sh` | **0** | 652 Rust tests passed, 0 failed, 2 ignored; every validation step passed, including 25 evidence-generator tests. |
| Python creation of copied fixture suite and two probes under `/tmp/heimdall-round4-probe` | 0 | No repository source changes. |
| Initial `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` | 1 | Missing explicit `serde` extern; corrected before execution. |
| Corrected probe compilation with explicit dependency externs | 0 | Linked against this checkout's production libraries. |
| `/tmp/heimdall-round4-probe/probe round4_ --nocapture --test-threads=1` | **101** | Both adversarial safety assertions failed, reproducing T01 and T02. |
| `/tmp/heimdall-round4-probe/probe r139_ --test-threads=1` | 0 | All nine copied `r139_*` tests/property checks passed. |
| Python validation-log totals and named-test verification | 0 | Confirmed totals and execution of migration, descriptor, and active-cancellation regressions. |
| `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` | 1 | No matching prototype output directories. |
| `du -sh target` | 0 | 3.3 GB before cleanup. |
| Guarded Python removal of checkout `target/`, exact probe directory, and validation log | 0 | Removed reviewer build and scratch outputs. |
| `test ! -e target`; final `git status --short`; `git diff --exit-code` | 0 each | Target removed; checkout clean. |

**Changed files:** None. No commits, pushes, network access, or native harness runs.

Not checked: fresh native Linux/Windows/WSL behavior, real credential adapters, or process-crash reproduction of T01; its failed-commit variant was reproduced locally.
Risk: passing baseline tests do not cover the two demonstrated remote-revocation failures.
