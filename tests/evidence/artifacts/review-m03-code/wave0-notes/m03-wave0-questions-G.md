# M03 wave 0: questions and readings from G (signature authorization, narrowing protocol)

Each item: the question, the options, the evidence, and the reading G built (fail closed where
there was a choice).

## G-Q1. The zero-gate case of the narrowing protocol — **ruled: accepted with condition**
- Ruling (orchestrator): (1) a narrowing whose affected grants have no signing gate commits in one
  transaction without pending marks; (2) the moment ANY affected grant has a gate, the full
  protocol applies to the WHOLE set without exception (marks on every member, ordered acquisition,
  rounds, key destruction under the gates, release then cleanup after release).
- Applied: the shortcut is decided on the full set read inside the transaction that commits
  (`narrowing.rs` step (1), comment "G-Q1, ruled"). A gate created after that check cannot admit a
  signature released after the commit: the signer's fresh read is a store transaction serialized
  after the commit, so it refuses. The slow path marks every member (gated or not), and the
  commit's re-read now sends ANY member no round knew (gated or not) to another round, so the whole
  set is always marked. Tests: `gated_member_of_cascade_takes_full_protocol`,
  `mixed_gated_and_ungated_set_takes_full_protocol_for_whole_set`.
- Evidence: `crates/app/src/operations/narrowing.rs` (`Operations::narrow`, step (1)); A2-Q7
  (`Narrowing::acquire` answers `NoGate`; `admit_shared` refuses `NoGate`).
- Reading built: the first read of the set runs in a write transaction that also looks for a gate
  on any member. If no member has a gate, the same transaction commits: reads, re-validation and
  commit collapse into one serializable transaction, with no marks (nothing can wait). A gate
  created while it runs admits nobody before it commits, because a signer's fresh read is a store
  transaction that the store serializes after this one. In wave 0 every narrowing takes this path,
  so M01/M02 transaction counts and fault points are unchanged (the preserve suites pass).
- Options: (a) this reading; (b) always mark and run round 0 (two extra transactions per narrowing,
  which moves store fault points that M01 tests arm, e.g. `tests/model/operations.rs:4876`).

## G-Q2. Where the revoke timestamps are stored (row 27)
- `requested_at` is `OperationRecord.created_at`, which `admit` stores from the `now` that `revoke`
  reads before the hash, the visibility check and any gate wait (verify doc row 27 inference). No
  `RecoveryIntent` field was added (about 20 literal sites; `intent_update_allowed` forbids changing
  `request`).
- `committed_at` is read inside the tombstone transaction (`narrowing::commit_time`: the gate's
  accepted time, else the raw wall clock, as `narrowing_now`) and written as `Tombstone.revoked_at`.
  No new tombstone field.
- A second revoke of an already tombstoned grant (`insert_tombstone` keeps the first): its
  `committed_at` is that drive's own reading. If its drive is interrupted between the commit and the
  settle, the later drive falls back to the stored tombstone's `revoked_at` (the first revocation's).
  Options: store `committed_at` in the operation's receipts instead.

## G-Q3. The authorization time seam (row 5; integrator reading)
- `narrowing::AuthorizationTime::{Peek (default), ReadOnly}`, set by `Operations::set_authorization_time`.
  `Peek` evaluates `heimdall_domain::time::gate` over the authorization's own transaction
  (`runtime_anchor`, `high_water_mark`, `time_confirmation`, the clock, the sync report) and writes
  nothing (`TxnGate::assess` is private to `timegate.rs`, so `authorize.rs` repeats its reads).
  `ReadOnly` calls `TimeGate::assess_read_only` on the blocking pool (wave 0: always `Uncertain`, so
  every signature is refused). U3 switches the default.

## G-Q4. The release check's in-memory time assessment
- `SignPermit` needs a non-blocking `SafeTime`. Reading built (`authorize.rs`, `AdmittedTime`): `Safe`
  while the clock is in the admitted observation's boot, its continuous reading did not go back, and
  wall progress since admission is within `TimePolicy::max_tolerated_skew` of continuous progress.
  It cannot see a store-side change (a high-water mark raised elsewhere). U2/U3 may replace it.

## G-Q5. `admit` records a re-validation
- `revalidate_chain` (ADR-0006 §13.5 ruling 2) records the new validated generation, a write inside
  the authorization transaction. F21 forbids the high-water mark write, which is not made. Option:
  a verdict-only variant that records nothing.

## G-Q6. How `narrowing_over_target` and `narrowing_set_grew` are reported
- No wire value exists for either (`RevokeNote` has `ordinary_connections_not_closed` only;
  `reason::M03` has neither). Reading built: `tracing::warn!` with the terms, the
  `NarrowingReport` (`Operations::narrowing_reports`, the hook's `NarrowingPoint::Reported`), and
  `RevokeData.{requested_at, committed_at}`. If they must reach `RevokeData.notes`, `RevokeNote`
  needs two variants (a contract change for A1/X and the golden).

## G-Q7. Row 7: which answers keep the intent
- Built: for an adapter with `remote_credential_effect`, an immediate call answering
  `OutcomeUnknown(ADAPTER_CALL_TIMED_OUT)` keeps the cleanup intent; every other answer behaves as
  in M02. ADR-0008 D7 item 5 names the timeout only. Fail-closed alternative: any non-confirming
  answer (an error or `remote_pending`) keeps it. The back-off schedule is R's
  (`process_cleanup_intent_reporting` answers `Kept`); G changed no runtime code.

## G-Q8. Row 26: "the pending mark first"
- The binding ID does not name the grant, so one store read (binding → grant and its ancestor chain)
  precedes the pending check; the pending check precedes every check of the grant and the gate wait.
  A grant with no gate registers without one: it is ordered with its narrowing by the store alone
  (G-Q1). The refusal reasons are fixed words in `ConnError::RegistrationRefused`
  (`connections.rs` `refused::*`).

## G-Q9. `admit` also checks the mark before queuing
- `tokio::sync::RwLock` queues a new reader behind a waiting writer (A3), so a signer arriving after
  the mark would wait the full `signing_gate_wait` behind the narrowing and then refuse
  `GateTimeout`. `admit` therefore checks the mark before the wait too (in memory), and still first
  after the awaited acquisition (`admit_shared`).

## G-Q10. Narrowing paths not built, or not gated — **OVERTURNED by ADR-0008 §17.16** (with V-E6(a))
- §17.16 R1: every policy action commits through `policy_commit` (`narrowing.rs`); `policy_reader`
  gives a non-empty set only for an action that reduces an existing grant's signing authority as
  the per-signature predicate sees it: a cutoff set or moved earlier, and `set_lock_behavior` to
  `revoke_on_lock` (the predicate then refuses `session_not_unlocked`).
- §17.16 follow-up (orchestrator, binding): `pause` and `set_connection_policy` were first routed
  through the protocol too, and are now removed (no-gate commit). Evidence, on the code before the
  removal (a probe test, not kept): after a committed `pause`, and after
  `set_connection_policy(existing: strict)`, a fresh `admit` for the active grant succeeded, while
  each commit had been narrowed (report `seq` set). So the predicate does not refuse on either: a
  pause blocks only new activations and bindings (`POLICY_PAUSED`; ADR-0006 §13.6 item 1;
  re-validation uses the pause-free continuing view), and a connection policy governs owned
  connections, with `GrantOrigin.connection` recorded at creation only. M01's pause semantics were
  not changed. A pause need not wait for in-flight admissions of new activations: those are refused
  in their own store transaction, which the store serializes with the pause; no gate is involved.
  Regressions: `pause_leaves_active_grant_permit_releasable_and_refuses_new_activation`,
  `strict_connection_policy_does_not_narrow_signing_authority`. `resume`, `clear_cutoff`, a later
  cutoff and widening M03 values only create decision records (empty set).
- R2 checked the same way: an environment-permission removal does reduce signing authority (the
  grant is withdrawn and `admit` refuses afterwards; `environment_permission_removal_narrows_before_commit`).
- §17.16 R2: an environment-permission removal is a narrowing commit through
  `Operations::set_environment_permissions`, which also ends the withdrawn grants in the same
  transaction (re-validation stays as recovery). No production code removes permissions through
  `Txn::upsert_environment` (`holders.rs:313` is test seeding; `testcfg.rs:584` creates all-true
  records only), so no caller needed rerouting.
- §17.16 R3: `Narrowing::acquire` releases every exclusive hold (marks kept) before deferring to an
  earlier narrowing, then restarts in global order.
- Superseded text, kept for the record:
- `PolicyAction::SetLockBehavior` (O's narrowing branch) takes no gate: it revokes nothing until a
  lock (row 25 does). The enrollment hold or removal that degrades a pair is U10's. A cutoff destroys
  no key: the affected grants end at the cutoff like expiry (ADR-0008 D7 item 8).
- An `end_in` withdrawal of a gated cascade is deferred (`Ended.gated`) and re-run under the gates by
  `complete_withdrawals`; a withdrawal found under them that needs gates outside the set defers
  again, at most `MAX_ANCESTRY` times, then is left to the next use or scheduler pass.

## G-Q11. The environment endpoint's "served" predicate
- Built: the grant has a binding in this environment that holds a slot (`Txn::slots_for_binding`
  non-empty). Wave 0 has no slots, so every environment-endpoint request is `KeyNotServed`. The key
  fingerprint is not compared (no instance table read in wave 0; the vault resolves the subject).

## G-Q12. Lock pass acknowledgment
- The acknowledged epoch is stored in the revocation's commit transaction (only when higher than the
  stored one, since `set_acknowledged_lock_epoch` refuses a lower one), and `source.acknowledge` is
  called right after the commit, before the adapters' local-denial rounds. A failed commit leaves
  the lock latched.

## G-Q13. A gate dropped while a holder still holds it (A2's lifecycle; found checking G-Q1)
- `SigningGates::release` removes the gate when the last instance goes, even if a signer still holds
  it shared ("a holder … keeps its own reference", `managed.rs:196`). A narrowing that starts after
  that sees no gate for the grant, in the zero-gate path and the full protocol alike (`acquire`
  answers `NoGate`), so it cannot wait for that holder. If the holder had already signed and was
  waiting for capacity, its release check (expiry, safe time, pending) could pass after the commit.
  It is reachable only once U10 destroys instances outside a narrowing (expiry, release of the last
  reference); in wave 0 no instance exists.
- Options (fail closed): (a) `release` keeps the gate entry while its lock has outstanding holders
  (`Arc::strong_count > 1`) and drops it when they end; (b) U10 destroys the last instance only
  under the exclusive gate, whatever the cause. Not changed by G: it alters A2's semantics.

## Requests to other agents
- R: `tests/integration/runtime_m03.rs:1468` and `:1559` fail `clippy -D warnings`
  (`needless_update` on `..Backoff::default()`); seen while running
  `cargo clippy -p heimdall-runtime --all-targets`.
