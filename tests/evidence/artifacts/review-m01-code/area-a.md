# M01-code-review-A — commit `93c60d3b` — **fix first**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Reviewed commit: `93c60d3b60a8828b2f431a1fef27d3047a8cc917`.

The existing suites passed, but seven focused probes reproduced gaps in time enforcement, preparation, capability minimums, approval handling, and event delivery. Findings explicitly covered by the parallel §13.6 work are marked below.

Repository files changed: **none**. No network access, commits, or pushes. The checkout's `target/` and the temporary probe directory were removed; final Git status was clean.

## Findings

### A01 — major — Issuance publishes using a stale time observation

**Location:** `crates/app/src/operations.rs:4931`, `crates/app/src/operations.rs:4941`, `crates/app/src/operations.rs:5130`.

**Defect:** `publish_issuance` obtains `(safe, time)` before entering the publication transaction. Inside that transaction, both `now` and continuous admission are evaluated from that captured observation. There is no fresh clock observation or gate assessment at publication.

**Concrete failure:** Reserve a certificate under a grant ending at 11:00. Publication's gate accepts 09:00; then the clock advances to 12:00 before the publication transaction. Publication still evaluates the grant at 09:00 and marks the entry `published`.

**Evidence:** Observed in `review_publish_uses_expired_observation`. A store `AfterCommit` hook advanced the virtual clock by three hours immediately after publication's gate transaction. Publication succeeded although the current clock exceeded the grant deadline.

ADR-0005 §3.5 step 3 requires every predicate to be reapplied against **current time**, expressly because deadlines can pass without changing a revision. ADR-0006 §14.2 requires current time evidence inside reserve and publish.

**Fix:** Assess the gate and continuous admission from a fresh observation inside the transaction performing reserve or publish. On publication refusal, void the reservation. Test expiration and clock uncertainty between the initial check and the publication transaction.

### A02 — major — Activation can commit during `TIME_UNCERTAIN`

**Location:** `crates/app/src/operations.rs:2837`, `crates/app/src/operations.rs:2930`, `crates/app/src/operations.rs:2950`.

**Defect:** The normal commit path reuses `local.safe` from `Recheck`. Its fresh observation runs only `dtime::admission`, which checks deadline, boot identity, and continuous budget; it does not detect clock rollback or skew.

**Concrete failure:** Complete `Recheck` at 09:00, then roll the wall clock back two minutes before `Commit`, without changing the continuous clock. Both admission checks remain open. The grant becomes active and the request returns `ACCESS_READY`, although a fresh gate check returns `TIME_UNCERTAIN`.

**Evidence:** Observed in `review_commit_admits_during_time_uncertain`, using a stage hook after `Recheck`. The ensure succeeded; the immediately following gate check refused time.

ADR-0006 §10 forbids admission while time is uncertain. `docs/architecture/m01-plan.md` U5 explicitly requires `TimeGate::check` before both `Recheck` and `Commit`.

**Fix:** Reassess time at commit, using the observation assessed by the gate for admission. Apply the same discipline to binding and decision transactions that currently carry an accepted time across asynchronous work.

### A03 — major — Credential preparation runs after the pinned deadline

**Location:** `crates/app/src/operations.rs:2605`, `crates/app/src/operations.rs:2628`, `crates/app/src/operations.rs:2672`.

**Defect:** Before journaling `Attempted` and calling `prepare`, the application verifies that the operation is running and the grant is `Preparing`. It does not check the grant's deadline, applicable cutoff, or current authority. A safe clock establishes confidence in time, not that the grant remains authorized.

**Concrete failure:** Resolve a two-hour grant at 09:00. Delay before `Reconcile` until 12:00, without running `tick`. The grant remains `Preparing`, so the application invokes the credential adapter. Only the later activation check rejects the expired grant.

**Evidence:** Observed in `review_prepare_runs_after_deadline`: the fake adapter recorded **one effect**, followed by `CREDENTIAL_EXPIRED`.

Spec §6.1 makes the deadline an immutable authority limit. ADR-0005 §3.5 prohibits issuance after its bound, and spec §13.5 requires reconciliation to stop when authority expires or is revoked. The final activation check does prevent an active binding in this reproduction, but it occurs after preparation's effect.

**Fix:** Validate current authority and deadline in the transaction authorizing the attempt. Recheck after waiting for an adapter slot, and require any authority-creating adapter effect to enforce its recorded bound. Preserve reconciliation of previous attempts even when authority has ended.

### A04 — major — An unmet offline minimum returns `ACCESS_READY`

**Location:** `crates/domain/src/authority.rs:327`, `crates/app/src/operations.rs:1099`, `crates/app/src/operations.rs:2986`, `crates/app/src/operations.rs:1536`.

**Defect:** Resolution checks `required.offline_until` against the authority's hard bound. Adapter selection checks capabilities and advertised destination enforcement. Neither activation nor result construction verifies that the prepared credential actually meets the requested offline minimum.

**Concrete failure:** Request offline availability through 10:30 under a grant ending at 11:00. The adapter returns offline availability only through 10:00. Ensure still succeeds with `ACCESS_READY` and `offline_until = 10:00`.

**Evidence:** Observed in `review_offline_minimum_is_not_enforced`, using the existing operations fixture.

Spec §4.3 requires `CAPABILITY_UNAVAILABLE` instead of silently weaker access. Spec §6.5 requires computing actual offline coverage before reporting readiness. ADR-0006 §5 maps the unmet minimum to exit class 4.

**Fix:** Validate prepared facts against all caller minimums before activation, including actual offline coverage and achieved enforcement. Preserve those minimums through coalescing and recovery. Add tests where the descriptor qualifies but the actual preparation result falls short.

### A05 — major — Failed event catch-up permanently skips a committed event

**Location:** `crates/app/src/events.rs:305`, `crates/app/src/events.rs:319`, `crates/app/src/events.rs:334`.

**Defect:** When announcements arrive out of order, `committed_between` recovers intervening events. If its store read fails, it returns a partial vector without an error. `announce` then advances the announced sequence to the later event and sends it. A subsequent announcement of the missing earlier event is discarded.

**Concrete failure:** Commit events N and N+1. Announce N+1 first, with one transient store failure during catch-up. The subscriber receives N+1. Announcing N afterward does nothing, and resuming from the delivered N+1 cursor cannot recover N.

**Evidence:** Observed in `review_event_catchup_failure_skips_committed_event`, using a one-shot `BeforeCommit` fault on the catch-up read. Only the second event reached the receiver; reading after its sequence returned no events.

ADR-0006 §8 requires ordered event delivery and recovery through cursors or explicit resynchronization. The comment claiming cursor resume recovers the missing events is incorrect once the later cursor has been delivered.

**Fix:** Return catch-up failure explicitly. Do not advance past the gap. Retry from the retained boundary or deliver `ResyncRequired` without claiming a continuous stream.

### A06 — major — Refreshed approval records retain an obsolete delta

**Covered by §13.6 item 2.**

**Location:** `crates/app/src/operations.rs:3322`, `crates/app/src/operations.rs:4579`.

**Defect:** When a pending decision becomes stale, `awaiting_response` clones `previous.kind` whenever a pending predecessor exists. It recomputes the current delta only when that list is empty.

**Concrete failure:** Policy covers h1; a request asks for h1+h3, so the recorded delta is h3. Remove h1 from the policy and advance the generation. A same-key retry creates a fresh decision at the new generation whose delta still names only h3, although h1+h3 now require approval.

**Evidence:** Observed in `review_fresh_decision_reuses_old_delta`. The fresh record omitted h1. Approving it caused one preparation effect, after which the pinned policy-revision check rejected activation with `CREDENTIAL_EXPIRED`.

Thus this reproduction **does not establish successful unauthorized activation**. It establishes an inaccurate confirmation record and preparation following that incomplete confirmation.

ADR-0006 §3.1 requires the exact recorded delta; §13.6 item 2 expressly requires recomputation against current policy.

**Fix:** Recompute every replacement decision's delta. Never carry the previous delta across a generation change. Revalidate that the approved record describes the authority used before preparation.

### A07 — minor — Equivalent authority requests create duplicate approval records

**Location:** `crates/app/src/operations.rs:2191`, `crates/app/src/operations.rs:2227`.

**Defect:** Added-authority resolution creates a grant and decision, then stops. Equivalent-work single-flight occurs later, so it cannot coalesce pending approvals.

**Concrete failure:** Submit two otherwise identical added-authority requests with the same work ID and different request IDs. Both return distinct decision references for the same logical decision.

**Evidence:** Observed in `review_equivalent_approvals_are_duplicated`: two pending decisions, different references, and zero preparation effects.

Spec §5.5 requires one coalesced approval request for one logical decision, including concurrent callers; R-UX-06 repeats that obligation.

**Fix:** Coalesce pending decisions using the resolved authority, generation, deadline, and work context before creating another record. Preserve each caller's operation reference and prevent broader requests from joining narrower decisions.

### A08 — major — Pause still rejects continuing work through generation revalidation

**Covered by §13.6 item 1.**

**Location:** `crates/app/src/operations.rs:723`, `crates/app/src/operations.rs:840`, `crates/app/src/operations.rs:3830`, `crates/domain/src/authority.rs:208`.

**Defect:** Pausing increments the generation. Continuing work then revalidates through the activation resolver, whose pause rule returns denial. `revalidate_one` converts that denial to `CREDENTIAL_EXPIRED`. Filtering `POLICY_PAUSED` in `drive_bind` cannot repair this earlier conversion.

**Concrete failure:** Activate a grant, pause its policy, then bind the existing binding or reserve a renewal within the original deadline. Revalidation refuses continuing work.

**Evidence:** Inferred from the production call chain; no dedicated additional probe run for this finding. The pure issuance predicate distinguishes new activation from continuing issuance, but application revalidation runs before it.

Spec §5.6 and ADR-0005 §3.5 say pause blocks new activations only. §13.6 item 1 explicitly forbids converting a pause into `CREDENTIAL_EXPIRED` for continuing work.

**Fix:** Distinguish new activation from continuation during revalidation. Permit existing work under pause while continuing to enforce tombstones, deadlines, cutoff, scope, and generation checks.

## Test coverage gaps demonstrated

- `tests/model/revocation.rs:665` changes conditions **between reserve and the publish call**. It misses changes after publication's gate assessment but before its transaction, as A01 demonstrates.
- The normal activation tests miss rollback between `Recheck` and `Commit`, as A02 demonstrates.
- `tests/model/operations.rs:525` checks that offline availability does not exceed expiry; it does not establish that offline availability meets the caller's requested minimum.
- `tests/model/events.rs:706` exercises reverse announcements with successful catch-up reads. It misses A05's transient failure.
- `tests/model/revocation.rs:1016` generates revoke, pause, immediate cutoff, approval, binding, and time advancement. It does not generate policy-scope withdrawal followed by a same-key decision refresh, the sequence in A06.

These are concrete missing cases; the cited tests are not all vacuous.

## Checked and found sound

- Idempotency keys include authenticated caller context and operation kind; classification, operation creation, recovery intent, and the initial receipt are transactional.
- Active and unresolved idempotency records do not expire. Settlement starts retention, and purge leaves expired-key markers.
- Decision completion checks attendance, owner role, pending state, expiry, and generation; consumed decisions cannot be reused.
- Recovery records pin authority and adapter identity. An attempted effect is reconciled through the recorded adapter before another preparation attempt.
- Issuance reservations from an earlier runtime instance cannot be published after restart and remain included in residual accounting.
- Tombstones and generation changes are transactional; grant snapshots and same-boot budget anchors resist extension.
- Migration tests exercise populated upgrades and transactional rollback.
- Application error mapping uses fixed messages instead of echoing adapter error text.

## Commands and validation

All Cargo commands used `--offline`.

| Command | Exit | Observed result |
|---|---:|---|
| `git rev-parse HEAD` | 0 | Exact reviewed commit, before and after review |
| `git status --short` | 0 | Clean before and after review |
| `cargo test --offline -p heimdall-app -p heimdall-domain -p heimdall-store --quiet` | 0 | 81 tests passed; doc-test targets contained zero tests |
| `cargo test --offline -p heimdall-runtime --test model_operations --test model_events --test model_timegate --quiet` | 0 | 89 tests passed |
| `cargo test --offline -p heimdall-testkit --test model_authority --test model_time --test model_lifecycle --test integration_store --quiet` | 0 | 103 tests passed |
| `rustc --test --edition=2024 --crate-name area_a_review <temporary-review.rs> -L dependency=target/debug/deps --extern … -o <temporary-review>` | 0 | Built temporary probes against existing workspace libraries |
| `<temporary-review> review_ --nocapture` — final run | 0 | Seven defect-confirmation probes passed |
| Earlier exploratory seven-probe run | 101 | Six passed; the stale-delta probe incorrectly expected activation to succeed. The revision check refused activation. The corrected probe verifies that refusal and the preceding preparation effect |
| Prototype output-size check through `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | No matching prototype output directories |
| `du -sh target` | 0 | 1.6 GB before cleanup |
| Exact-path Python cleanup with directory and symlink assertions | 0 | Removed checkout `target/` and temporary probes |
| Final absence checks for both directories | 0 | Both absent |

Routine inspection used `cat`, `sed`, `rg`, `wc`, and `nl`. Some exploratory searches returned no matches or referenced nonexistent split testkit files; inspection continued in `crates/testkit/src/lib.rs`. The initial `rm -rf` cleanup command was rejected before execution; the exact-path cleanup above completed successfully.

The temporary probes assert the defective outcomes described above; their passing status confirms reproduction, not correctness.

Not checked: native platform behavior, real SSH credentials, M03 cryptography, or the full validation script. Probes were removed as required.
Risk: the passing baseline suites do not close the demonstrated authority and event-delivery gaps.
