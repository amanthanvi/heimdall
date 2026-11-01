# M01-code-review-round2 — `10414f1022e640121213797e142a9e524e36428e` — **fix first**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Independent, read-only re-review of the changes from `93c60d3b` through `10414f10`.

The offline validation script passed: **576 Rust tests passed, 0 failed, 1 ignored**, plus formatting, host and Windows-target Clippy, test discovery, schema comparison, harness self-tests, and 15 evidence-generator self-tests. However, additional throwaway probes reproduced three defects beyond the parallel §13.7 assignments: publication before re-signing a replacement reservation, approval waits multiplied by the number of coalesced callers, and silent event loss across retention.

No repository files were modified. No network access or native harness execution occurred. This checkout's `target/` and the reviewer's temporary probe directory were deleted; final Git status was clean.

## First-review findings

"Fixed" below means the original defect is addressed at this commit. It does not imply that related native or release evidence is complete. Tests named below ran through `check.sh`, except the Windows-only test and historical Windows evidence explicitly identified.

| Finding | Status | Source evidence and regression test |
|---|---|---|
| A01 — stale issuance time | **fixed** | `crates/app/src/operations.rs:5654` assesses the gate inside the issuance transaction; `crates/app/src/timegate.rs:181` implements the transactional check. Tests: `review_a01_publish_assesses_time_inside_its_own_transaction`, `review_a01_reserve_assesses_time_inside_its_own_transaction`. Replacement signing has a separate defect, R01. |
| A02 — commit during uncertain time | **fixed** | Fresh gate checks at commit (`operations.rs:3455`), bind (`:4277`), and approval (`:5059`). Tests: `review_a02_commit_reassesses_time_with_the_gate`, `review_a02_bind_reassesses_time_in_the_admitting_transaction`, `review_a02_an_approval_reassesses_time_in_the_deciding_transaction`, `review_a02_a_widening_record_reassesses_time_in_its_transaction`. |
| A03 — preparation after authority ends | **fixed** | `operations.rs:3098` acquires an adapter slot before the transaction checking authority and recording `Attempted`; `:3190` narrows the adapter's grant to the bound. Tests: `review_a03_no_preparation_after_the_deadline_or_a_cutoff`, `review_a03_authority_is_rechecked_after_waiting_for_an_adapter_slot`, `review_a03_earlier_attempts_are_reconciled_after_authority_ended`. Environment invalidation remains assigned under §13.7 item 5; see R07. |
| A04 — unmet minimum returns readiness | **fixed** | `operations.rs:1075` checks actual facts; `:3492` applies it before activation. Tests: `review_a04_an_unmet_offline_minimum_is_capability_unavailable`, `review_a04_achieved_enforcement_below_the_minimum_is_capability_unavailable`, `review_a04_minimums_survive_coalescing`, `review_a04_minimums_survive_recovery`. The coalescing test also checks that the leader's grant stays active. |
| A05 — catch-up failure skips events | **partially** | `crates/app/src/events.rs:349` retries held announcements without advancing past an unread store failure. Tests: `failed_catch_up_read_never_advances_the_live_stream_past_a_gap`, `held_back_events_are_delivered_in_order_once_the_store_is_readable`, runtime `supervisor_delivers_held_back_events_without_a_new_commit`. Retention can still turn the held gap into silent loss: R03. |
| A06 — replacement approval retains old delta | **fixed** | `operations.rs:3865` creates the replacement using recomputed `needed`; `:5182` records approval basis. Tests: `review_a06_a_fresh_decision_recomputes_the_delta_against_current_policy`, `review_a06_a_fresh_decision_after_a_lifted_pause_completes`, `review_a06_an_approval_is_revalidated_before_preparation`; store test `recovery_intent_approval_basis_is_add_only`. Continuing-use basis is incomplete under §13.7 item 3: R05. |
| A07 — duplicate equivalent approvals | **partially** | `operations.rs:1701` finds equivalent waiting decisions and shares their grant. Tests: `review_a07_equivalent_added_authority_requests_share_one_decision`, `review_a07_a_broader_request_never_joins_a_narrower_decision`, `review_a07_cancel_and_deny_of_a_shared_decision`. The cancellation test cancels a joiner, not the creator. Creator cancellation still fails surviving waiters: R06, covered by §13.7 item 4. |
| A08 — pause ends continuing work | **fixed** | `operations.rs:872` resolves continuing work with the pause removed; `:1190` applies activation blocks according to activation type. Tests: `r136_1_pause_lets_an_existing_binding_bind_and_issue_until_its_deadline`, `r136_1_pause_refuses_new_grants_and_bindings_and_replays_recorded_results`. |
| B01 — harness deletes unowned scratch | **fixed** | `tests/native/windows-ipc/scratch-lib.sh:22` rejects unsafe names; `:46` creates run directories exclusively; `:62` restricts removal. Local `native-harness-selftest.sh` exercised existing-directory refusal, concurrent run separation, partial creation, symlink refusal, invalid names, and exact cleanup. No remote harness was run. |
| B02 — obsolete retries cause polling | **fixed** | `crates/runtime/src/supervisor.rs:455` prunes retries against current cleanup candidates and generations before scheduling. Test: `cleanup_retries_are_pruned_when_the_resource_is_replaced_or_reconciled`. |
| B03 — later harness failure exits zero | **fixed** | `tests/native/windows-ipc/run-native.sh:232` returns the initial failure or accumulated later-suite failure. Local self-test case `B03 windows-ipc: a failing later suite -> nonzero exit` also verifies retained command exits. |
| B04 — supervisor waits too long after sleep | **fixed** for the bounded-wake implementation | `supervisor.rs:303` caps waiting by `resume_bound()`. Tests: `supervisor_detects_a_sleep_across_a_deadline_within_the_resume_bound`, `supervisor_resume_check_interval_is_bounded`. This establishes simulated detection within the configured awake-time bound, not immediate native resume notification. |
| B05 — Windows FFI capacity units | **fixed** | `crates/ipc/src/windows.rs:622` passes the checked UTF-16 element count. Test: `windows::tests::client_computer_name_capacity_counts_utf16_units`, present but Windows-only; not executed locally. Windows-target Clippy passed. |
| B06 — incomplete unsafe inventory | **fixed** | `docs/architecture/overview.md:256` now includes process-identity calls and handle-inheritance handling. Documentation inspection proves this correction; no executable test establishes inventory completeness. |
| B07 — missing owner-channel shutdown | **fixed** | `crates/contract/src/request.rs:572` defines shutdown; `crates/runtime/src/dispatch.rs:215` enforces owner authorization. Tests: `shutdown_wire_form_and_predicates`, `shutdown_refused_for_a_limited_consumer_and_idempotent_for_the_owner`, `shutdown_from_the_owner_drains_and_removes_the_advertisement_and_endpoints`, `shutdown_lets_an_in_flight_durable_step_complete_before_exit`, CLI `service_stop_sends_shutdown_over_the_control_endpoint_and_is_idempotent`. Fallback evidence remains assigned: R09. |
| B08 — deterministic cleanup backoff | **fixed** | `supervisor.rs:529` uses injected jitter. Tests: `cleanup_retries_use_bounded_backoff_with_injected_jitter`, `jittered_retry_delays_stay_within_the_bounded_backoff`, `fixed_unit_one_is_the_unjittered_schedule`. |
| B09 — missing Windows runtime workflows | **partially** | Portable runtime tests now cover stale advertisement, launcher concurrency, control round trip, and shutdown. Saved `tests/evidence/artifacts/m01/rulings-13-6/windows/run2/tests.txt:146` onward reports native passes for these workflows. That is historical reported execution, not independently rerun evidence for `10414f10`; current-head release evidence remains outstanding. |
| C01 — JSON usage error lacks envelope | **fixed** | `crates/heimdall/src/main.rs:20` routes parse failures through `cli::parse_failure`; `crates/heimdall/src/cli.rs:467` emits the envelope. Binary tests: `json_usage_failures_render_exactly_one_usage_error_envelope`, `usage_failures_keep_human_help_version_and_errors`. |
| C02 — absent wildcard target loses coverage | **fixed** | `tests/native/m01/m01-evidence.py:111` validates a separate committed inventory. Self-tests: `test_removing_a_whole_wildcard_target_cannot_verify`, `test_real_a19_without_the_contracts_target_is_not_verified`, `test_dropping_one_wildcard_test_cannot_verify`, `test_generation_refuses_a_wildcard_target_with_zero_tests`. |
| C03 — nonzero command still verifies | **fixed** | `m01-evidence.py:258` validates required command exits; `:311` prevents verification on failures. Self-tests: `test_a_required_nonzero_exit_prevents_verified`, `test_unrecorded_or_malformed_exits_prevent_verified`, `test_an_expected_failing_negative_probe_is_separate_and_allows_verified`. Row classification has the separately assigned R08 deviation. |

## New findings

### R01 — Major — Replacement issuance is published before the issuer can sign it

**Location:** `crates/app/src/operations.rs:5596`, `:5601`, `:5626`, `:5584`.

**Defect:** When only the generation changes, publication creates a fresh reservation with a new serial, loops internally, and marks that reservation `published`. The issuer receives the replacement bounds only after publication.

ADR-0005 §3.5's amendment requires the fresh **reservation** to return to the issuer, which signs those exact bounds and publishes again. §13.7 item 7 confirms that ordering. There is no signing callback or issuer handoff between the internal reserve and publish transactions.

**Failure scenario:** The issuer signs serial S1. An unrelated generation change makes publication replace S1 with S2. The method returns success for a published S2, although the issuer has only signed S1. Signing S2 after this return would put signing after its final publication checks; a revoke or expiry between return and signing would receive no subsequent publication check.

**Evidence — observed:** Throwaway test `round2_rereservation_must_return_to_issuer_before_publication`, compiled against the current production libraries:

```text
ROUND2 replacement_state=Published
expected: Reserved
```

The existing `review_13_6_11_an_unrelated_generation_move_rereserves_and_publishes` passes while explicitly expecting this premature `Published` state. It proves generation retry behavior, but not the required reserve → sign → publish ordering.

**Fix:** Return the fresh reservation to the issuer before publication, or provide an explicit signing step between reservation and publication. Preserve the retry bound and require a fresh final transaction after signing. Add a test that records signing order and injects revoke/expiry between replacement signing and publication.

### R02 — Minor — Shared approval multiplies the bounded wait by every waiter

**Location:** `crates/app/src/operations.rs:5223`.

**Defect:** After one decision commits, `decide` sequentially calls `lead_bounded(..., max_wait)` for every resumed operation. Each call receives a fresh full timeout.

**Failure scenario:** Five equivalent requests await one decision. The creator's adapter remains unavailable to complete preparation. Approving the decision waits approximately five times `max_wait`; with the default 300-second limit, five waiters can occupy the approval request for about 25 minutes. The durable approval has already succeeded.

**Evidence — observed:** Throwaway test `round2_decision_wait_scales_with_waiters` held the first preparation, used five equivalent waiters, and set `max_wait = 80 ms`:

```text
ROUND2 waiters=5 max_wait_ms=80 elapsed_ms=412
```

Its assertion allowing 250 ms failed. The existing shared-approval test uses promptly completing preparation and does not exercise the wait bound.

**Fix:** Start continuation for all waiters while applying one overall deadline to the decision request, or return the durable decision result while bounded background continuation proceeds. Add a held-adapter test with several waiters that asserts a single request-level wait bound.

### R03 — Major — Retention silently discards a held-back event

**Location:** `crates/app/src/events.rs:413`, `:430`, `:398`.

**Defect:** `committed_through` treats a successful short page as complete without checking whether retention removed events after the last delivered boundary. `advance` then sends the surviving events and advances the cursor past the missing event.

**Failure scenario:** Commit N and N+1. Announce N+1 first while catch-up fails, so it is held. Retention removes N before retry. `retry_held()` reads N+1, considers catch-up complete, and sends it without `ResyncRequired`. The subscriber now has a cursor beyond N and cannot recover the lost transition.

Production retention can remove rows by age or the 100,000-row cap; the probe uses a one-row cap to reach the same boundary cheaply.

**Evidence — observed:** Throwaway test `round2_held_gap_trim_requires_resync` used the existing event fixture, one failed catch-up read, `Txn::trim_events(..., max_rows = 1)`, and `retry_held()`:

```text
ROUND2 delivered=1 resyncs=0 first_missing=true
```

The existing event property generates announcement ordering and store faults, but does not generate retention between failure and retry.

**Fix:** Check the retained tail against the delivery boundary in the catch-up transaction. When history has been removed, signal resynchronization instead of claiming continuity. Extend the property with retention steps and assert either complete delivery or an explicit resync.

## Deviations already assigned to the parallel §13.7 work

These remain present at the reviewed commit. They must be checked again after integration.

### R04 — Minor — Fully covered waiting work still requires a decision

**Covered by §13.7 item 2.**

**Location:** `crates/app/src/operations.rs:3865`.

**Defect/scenario:** Widen standing policy so that it fully covers a waiting request. The replacement path still creates an empty-delta decision rather than proceeding through standing-policy activation.

**Evidence — observed:** Throwaway `round2_fully_covered_waiter_needs_no_decision` returned `INTERACTION_REQUIRED`, rather than `ACCESS_READY`, after policy coverage expanded to include the entire request.

**Fix:** Withdraw the empty-delta decision and resume normal standing-policy resolution, retaining time, pause, cutoff, and minimum checks.

### R05 — Major — Continuing owner-approved grants do not enforce their approved delta

**Covered by §13.7 item 3.**

**Location:** `crates/app/src/operations.rs:785`, `:5182`, `:4336`.

**Defect/scenario:** Approval basis is stored on the operation intent. Continuing bind constructs an intent with `approval: None`, and `revalidate_one` accepts any `ApprovalRequired` result for an `OwnerDecision` grant. If policy originally covered h1 and the owner approved only h3, later withdrawal of h1 can be accepted as though the owner had approved both.

**Evidence — inferred from production paths:** The blanket acceptance branch does not compare the newly needed delta with the original approved delta. The add-only intent test proves preservation of an operation field, not grant-lifetime enforcement.

**Fix:** Persist approval basis with the grant and enforce scope containment within current standing authority plus the recorded approved delta on continuing use, independently of operation retention.

### R06 — Major — Cancelling the creator ends surviving approval waiters

**Covered by §13.7 item 4.**

**Location:** `crates/app/src/operations.rs:4586`.

**Defect/scenario:** A and B share a pending grant and decision. Cancelling A, the creator, cancels the grant without transferring ownership to B.

**Evidence — observed:** Throwaway `round2_cancelling_creator_preserves_waiter` retried B after cancelling A:

```text
ROUND2 surviving_waiter_code=CREDENTIAL_EXPIRED
```

The checked-in cancellation test cancels a joining caller and therefore misses this case. Shared denial is covered and passes.

**Fix:** Transfer shared ownership to the oldest remaining waiter; cancel the grant and withdraw the decision only when no waiters remain. Test creator cancellation, successive ownership transfers, last-waiter cancellation, and restart after transfer.

### R07 — Major — Environment permission changes do not invalidate the generation

**Covered by §13.7 item 5.**

**Location:** `crates/store/src/ext.rs:624`; admission consequence at `crates/app/src/operations.rs:1225`.

**Defect/scenario:** `upsert_environment` writes the record without advancing authority generation. A standing-policy request resolved while automatic activation was permitted can therefore reach its later authority checks without generation-triggered revalidation after that permission changes.

**Evidence — observed source omission; admission consequence inferred:** The write returns at `ext.rs:630` without advancing generation. The activation path uses generation changes to decide whether to resolve current authority again.

**Fix:** Advance generation on every accepted environment write. Test permission changes between resolution and attempt, attempt and commit, and reserve and publish.

### R08 — Minor — Incomplete runs can still be classified as blocked

**Covered by §13.7 item 6.**

**Location:** `tests/native/m01/m01-evidence.py:318`.

**Defect/scenario:** On a current-build platform run, omit one expected test while retaining other results from that target. This leaves `absent` nonempty without `missing_targets`; the row becomes `blocked` rather than `in_progress`.

**Evidence — observed source branch:** Whole-target omission is handled separately, but individual omissions still fall through to `status = "blocked"`. The self-test for a missing wildcard test asserts only that the result is not verified, so it passes with this incorrect classification.

**Fix:** Classify an incomplete current-build run as `in_progress`; reserve `blocked` for an identified missing platform or capability. Assert the exact status in generator tests.

### R09 — Minor — Service-stop fallback lacks its required end-to-end test

**Covered by §13.7 item 8.**

**Location:** `tests/e2e/cli_m01.rs:1384`.

**Defect/scenario:** The new service-stop test exercises successful owner-channel shutdown and idempotence. It does not make the control endpoint unusable while preserving a valid advertisement, then prove signal fallback and advertisement removal.

**Evidence — observed coverage gap:** The CLI suite passed, but the ruled failure-path case is absent. This is not evidence that fallback itself is broken.

**Fix:** Add the specified e2e test asserting exit 0, `data.via == "signal"`, exact fixture-process termination, and advertisement removal.

## M01 exit-evidence blockers

- R03 prevents closing ordered, resumable A19 event semantics. R01 prevents claiming the agreed issuance protocol, despite the passing generation-race tests.
- The assigned §13.7 items must be integrated and tested at the resulting commit. R05 and R07 concern authority enforcement; successful original reproductions do not close them.
- Existing `tests/evidence/m01-*.json` records remain `in_progress` and identify the historical `f9ed3454 + uncommitted …` build. For example, `tests/evidence/m01-a19-operations.json:9` does not identify this reviewed commit. Regenerate records and artifact digests for the final integrated head.
- Saved Windows run-2 logs report the newly portable runtime workflows passing, but do not independently establish current-head native evidence. Fresh platform evidence remains necessary for the claims it supports. Cross-compilation and local simulated sleep do not close native Windows/WSL lock or suspend/resume claims.

## Commands and observed exits

| Command/check | Exit | Result |
|---|---:|---|
| `git rev-parse HEAD`; `git status --short`; final `git diff --exit-code` | 0 each | Exact commit confirmed; clean checkout before and after review. |
| `git diff --stat 93c60d3b..10414f10`; targeted `git diff` reads | 0 | Located and inspected changed production, test, documentation, and harness paths. |
| Targeted `cat`, `sed`, `nl`, and `rg` source/contract reads | 0 for successful reads | Inspection supporting the findings above. Matchless searches returned 1; these were not validation failures. |
| reviewer's memory-registry search | 1 | No matching memory context; none used as review evidence. |
| `CARGO_NET_OFFLINE=true PYTHONDONTWRITEBYTECODE=1 bash tools/validation/check.sh` | **0** | 576 Rust tests passed, 0 failed, 1 ignored; fmt, host Clippy, Windows-target Clippy, discovery, schema, local harness self-test, and 15 evidence self-tests passed. |
| First throwaway `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` | **1** | Probe compilation omitted `--extern serde`; corrected before execution. |
| Corrected operation-probe compilation; later expanded compilation | **0 each** | Built outside the repository against current production libraries and existing fixture helpers. |
| Initial operation-probe binary, `round2_ --nocapture` | **101** | Two assertions failed: replacement already published; five waiters took 411 ms with an 80 ms wait limit. |
| Expanded operation-probe binary, `round2_ --nocapture` | **101** | Four assertions failed: the preceding two, creator cancellation, and fully covered waiting request. Wait measurement was 412 ms. |
| Event-probe `rustc --edition=2024 --test … --extern …` | **0** | Built outside the repository. |
| Event-probe binary, `round2_ --nocapture` | **101** | Retention reproduction failed its continuity/resync assertion: one delivered event, zero resyncs, first event missing. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | **1** | No matching prototype output directories existed. |
| `du -sh target` | **0** | 3.1 GB before cleanup. |
| Guarded Python removal of this checkout's `target/` and the exact reviewer-created temporary directory, with absence assertions | **0** | Both removals verified. |

**Changed files:** None. No commits or pushes.

Not checked: fresh native Windows/WSL/Linux execution, native suspend/resume, or real credential adapters; network access and native harnesses were excluded as requested.
Risk: the passing baseline does not close the reproduced protocol, bounded-wait, and event-loss defects or the assigned authority fixes.
