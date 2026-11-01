# M01 work breakdown (deterministic core and lifecycle substrate) — revision 2

**Inputs:** plan §5 M01 (T01–T06), §6.3 properties, §6.4 fault schedule; spec §17
A06/A07/A08/A19/A29 (model and local-runtime variants); `overview.md`; ADR-0006
revision 2; ADR-0005 §3.5/§3.6; the design review
(`tests/evidence/artifacts/review-m01-design/review.md`) and the orchestrator's
rulings on it (ADR-0006 §14.5); **revision 2.1:** the round-2 review
(`…/review-m01-design/round2/review.md`, N01–N06) and its rulings (ADR-0006 §13.4).
Items added by it are marked **⟨r2.1⟩**.
**Status discipline (wave-1 E15):** every unit is `implemented_unverified` until
U10's evidence records exist, whatever its tests say locally. Wave 1 (U1, U2, U3,
U4, U6, U6w, U7) is committed; this revision adapts it and defines wave 2.
**Skeleton rule:** every type, trait and function named below exists in `crates/`
(bodies `todo!("M01-Uxx …")` where not yet implemented). A unit replaces the bodies
it owns and adds tests. Shared signatures, tables and limits change only through the
integrator with an ADR-0006 revision.

## 0. Ground rules for every unit

* Write only inside the owner paths below (plus the unit's test files). Shared files
  (`Cargo.toml`, `Cargo.lock`, `crates/contract/**`, `crates/domain/**`,
  `crates/app/src/{ports,context,ensure}.rs`, `clippy.toml`) change only through
  the integrator.
* **Test-target convention (review F09):** every suite is a real Cargo `[[test]]`
  target with `path = "../../tests/<layer>/<name>.rs"`, hosted by the crate that
  already has the needed dependency edges: `heimdall-testkit` hosts `tests/model/*`
  and `tests/integration/store.rs`; `heimdall-contract` hosts `tests/contracts/`;
  `heimdall-ipc` hosts `tests/integration/ipc_unix.rs` and `tests/adversarial/*`;
  `heimdall-runtime` hosts `tests/integration/runtime.rs` and the U10 model
  harness `tests/model/operations.rs`; `heimdall` (bin) hosts `tests/e2e/*`. No
  `#[path]` inclusion; needed items are `pub` (`#[doc(hidden)]` if not public
  surface). `check.sh` fails any non-doctest target that reports zero tests.
* Property tests use `proptest` (≥ 256 cases, fixed default seed, committed
  `proptest-regressions/`, `PROPTEST_RNG_SEED` reproduces). Model tests are
  deterministic over `testkit::VirtualClock` + `testkit::ScriptedTimeSync` and
  `Store::open_in_memory`.
* Fault injection only through production hooks: `store::FaultHook` (durable-write
  points), `OperationsConfig.stage_hook` (`testkit::ScriptedStageHook`), and
  `testkit::FakeCredentialAdapter` scripts (`Fail`, `ApplyButLoseReply`,
  effect-token idempotency, `reconcile`). No unit needs a network, provider, or
  external host; platform-only tests are `blocked` with the platform named.
* Canaries: fixtures may contain `HEIMDALL_CANARY_*` values; `testkit::
  assert_no_canary` runs over every envelope, event payload, log line and error
  message a test produces (ADR-0004 §4).
* Every unit runs `bash tools/validation/check.sh` before hand-off and records the
  exit codes and test counts.

## 1. Units

### U1 — Contract tests and schema consistency (wave 1; adapted by U1b)

* **Owner paths:** `tests/contracts/**`, `schemas/public-api/**`,
  `schemas/examples/**`, `crates/contract/Cargo.toml` (`[[test]] contracts`).
* **Interfaces:** `contract::{Code (Clone, Unknown), Envelope, ErrorData, Request
  (Decide, ConfirmTime), Event, Snapshot, ClientMessage (Attend), ServerMessage
  (Subscribed.snapshot), schema::public_schemas, canonical}`.
* **Tests:** golden code table (29 rows, ADR-0006 §5) from the golden file and the
  ADR text; examples validate against generated schemas; unknown-field tolerance;
  unsupported major rejection; `Code::Unknown` reader fallback (exit 1, not
  success); `warnings`/`next` required in schemas, omission tolerated by readers;
  `float_roundtrip` canonical property; hello `interaction` default; schema export
  byte-identical and equal to `schemas/public-api/`.

### U2 — Authority resolution (wave 1, confirmed ADR-0006 §14.4)

* **Owner paths:** `crates/domain/src/{authority,scope,policy,profile,environment,
  evidence}.rs`, `tests/model/authority.rs`.
* **Interfaces:** `resolve_authority`, `AuthorityDecision`, `Denial` (now with
  `DeadlinePassed`).
* **Follow-up for wave 2 (integrator):** `Denial::DeadlinePassed` is emitted when the
  requested deadline is at or before `now` (currently the result carries the past
  instant; U5 maps either form to `CREDENTIAL_EXPIRED`).

### U3 — Time model and lifecycle (wave 1; rewritten by U3b for ADR-0005 §3.6)

* **Owner paths:** `crates/domain/src/{time,lifecycle,grant,revocation}.rs` (bodies
  are implemented), `tests/model/{time,lifecycle}.rs`.
* **Interfaces:** `time::{Clock, BootId, TimeSync, SyncStatus, TimeAnchor,
  TimePolicy, AttendedTimeConfirmation, GateInput, gate, next_high_water,
  GrantAnchor, anchor_grant, shorten, Admission, admission, is_expired,
  resolve_deadline}`; `lifecycle::{grant_transition, operation_transition}`.
* **Tests required (A08 model variant):** sleep across expiry; wall running; backward
  jump; forward jump without continuous progress; **same-boot restart with a stuck
  wall never extends the budget** (the formerly ignored case); same-boot restart
  keeps the remaining budget exactly; reboot below the mark refused even when
  synchronized; reboot above the mark but unsynchronized refused; reboot
  synchronized accepted with the persisted bound; attended confirmation resolves
  uncertainty without moving the deadline; the stopped-10:00/real-12:00/clock-10:01
  case refused; proptest over Pass/FrozenWall/WallJump/Restart/Reboot steps;
  **⟨r2.1⟩** N01: `shorten` reduces the existing budget by the bound reduction
  (reviewer counterexample: anchor 0, tolerance 60 s, bound 3600 → 3570, wall lagging
  60 s ⇒ admission closed by continuous 3510) and the true-bound property includes
  `Cutoff` steps; N05: a synchronized reboot 4 s below the mark is `Uncertain` and
  resolvable by an attended confirmation;
  duration-intent retry hashes equal and keeps the original instant; errors never
  echo input. Lifecycle: `OutcomeUnknown` quiescent-not-settled, settled by
  reconciliation only.

### U4 — Transactional state store (wave 1) and **U4b — design-fix store additions**

* **Owner paths:** `crates/store/**`, `tests/integration/store.rs`.
* **Interfaces (U4b):** everything in `crates/store/src/ext.rs` (ADR-0006 §14.3),
  migration `0002`, `SCHEMA_VERSION = 2`, `open_operations` = not quiescent,
  `unresolved_operations`, purge rules (settled only; markers left; nothing
  unresolved purged), `settle_idempotency`, neutral `stored_events_after`.
* **Tests required:** wave-1 suite kept; plus R2 (settle → purge → marker →
  `Expired` inside the window, `New` after `purge_markers_before`; pending keys never
  purged), R4 (release twice; foreign `LimitedConsumer` → `NotOwner`; owner role
  allowed; immutable snapshot; `policies_for`; `denied_ancestor` through a revoked
  grandparent), R5 (intent round-trip; receipts append-only, ordered), R6 (reserve →
  publish CAS; reserve → void; publish on voided → `GenerationConflict`; residual
  counts reserved+published), R7 (unresolved listed, excluded from open, survives
  purge), R8 (sequences monotonic; head/tail), R1 (grant anchor cannot lengthen in a
  boot, may be replaced in a new boot; high-water never lowers), migration 0001→0002
  on a populated database, newer `user_version` refused; fault points before/after
  commit and `Crash` in a child process (wave 1).

### U5 — Application operations (M01-T05 core + T06 part 2) — **wave 2**

* **Owner paths:** `crates/app/src/{operations,singleflight,reconcile,events,
  error,ids}.rs`, `tests/model/operations.rs` (hosted by `heimdall-runtime` as
  `[[test]] model_operations`, because it needs store + app + testkit with the
  `app` feature), `tests/model/{idempotency,revocation,events}.rs` (same host).
* **Interfaces to implement (exact names in the skeleton):** `Operations::{start
  (restart recovery), attend, inspect, ensure, bind, delegate, observe, cancel,
  release, revoke, policy, decide, confirm_time, tick}` over `Caller`;
  `SingleFlight::{join_or_lead, finish}`; `EventPublisher::{publish, publish_in,
  announce, subscribe, head_cursor}` and `events::cursor::{encode, decode,
  reader_tag}`; `OpError` mappings (overview §7).
* **Pipeline contract:** `EnsureStage` order; `RecoveryIntent` persisted before
  `Reconcile`; `StageReceipt` after every stage; `effect_token` minted and an
  `Attempted` receipt written **before** `CredentialAdapter::prepare`; on retry or
  restart with an `Attempted`/`Uncertain` receipt call `reconcile`, never `prepare`,
  until `NotApplied`; `TimeGate::check` before `Recheck`/`Commit` and in `tick`;
  `TimeGate::anchor_grant` at activation; idempotency via `classify(record, marker,
  hash, now)` with `settle_idempotency` at settlement; decisions per ADR-0006 §3.1
  (`APPROVAL_REQUIRED` + `decision_ref`; widening policy actions always create a
  decision record, **⟨r2.1⟩ N04**);
  release via `Txn::release_binding` (`AlreadyReleased` is success; `NotOwner` →
  `CAPABILITY_UNAVAILABLE`); revoke writes the tombstone before acknowledgment and
  reports the residual from `issuance_residual` ∪ adapter `RevokeOutcome`.
* **Second-round notes for U5 (ADR-0006 §13.1):** (R5, **amended by ⟨r2.1⟩ N04**)
  `Request::is_widening_policy_action()` requests (`resume`, `clear_cutoff`) and
  every added-authority `ensure`/`delegate` **always** create a server-issued decision
  record carrying the exact verbatim action or delta, **on attended sessions too**,
  and are never executed on dispatch: answer `APPROVAL_REQUIRED` with
  `next.decision_ref` on an attended session and `INTERACTION_REQUIRED` with
  `next.decision_ref` on an unattended one. The only completion is `decide` on an
  attended session (consume-once, generation-checked, expiry). `decide`/
  `confirm_time` never arrive unattended but check `Caller::is_attended()` again.
  (R7) the store methods `expired_key_marker`, `time_confirmation` and
  `pending_decisions` take no `now`/boot: the application must itself compare
  `marker_until` with `now`, the confirmation's `boot_id` with the current boot,
  and a decision's `expires_at` with `now` before relying on them. (R2) `TimeGate::
  check` persists the anchor from `next_runtime_anchor`, not the raw observation.
  (R4) `TimeGate::anchor_grant` uses `anchor_grant_with_tolerance(…,
  SafeNow::tolerance_used)` and keeps the store's `min()` result.
* **⟨r2.1⟩ Issuance predicate (N02).** Every reserve and every publish builds
  `issuance::IssuanceCheck` from current state inside its transaction: grant, the
  recorded parent (`parent`) and the chain above it (`ancestors`, grandparent first),
  policy plus `expected_policy_revision` from the grant's `ResolvedIntent`, current
  generation, tombstone (`denied_ancestor`), `permitted_extensions` for the pair, the
  gate's `TimeStatus`, and `admission = time::admission(&grant_anchor, &observation)`
  from the same observation. Publish on refusal ⇒ `void_issuance(reason)`.
* **⟨r2.2⟩ Rulings on the fixer's questions (ADR-0006 §13.5).**
  * Every ancestor must be issuable. A `delegate` therefore takes an ownership-aware
    reference on the parent, owned by the child grant. That reference is released only
    when the child reaches a terminal state, so consumers releasing the parent cannot
    move it to `released` while a live child depends on it. Test: release every
    consumer reference of a parent with an active child; the parent stays `active` and
    the child still issues. Then end the child; the parent may now become `released`.
  * The generation check compares the generation at which each grant and ancestor was
    **last validated** with the current one. When it is stale, U5 re-validates
    automatically, before reserving: it re-runs `resolve_authority` against current
    policy, cutoffs and tombstones, with unchanged scope and deadline, no widening and
    no prompt. U5 records the new validated generation, or denies. Reserve and publish
    must observe the same generation. Test: an unrelated revoke elsewhere does not
    fail a healthy grant's next issuance. A revoke of this grant's ancestor does.
  * `permitted_extensions` comes from the grant's resolved scope (its snapshot
    capabilities), never from request fields. The M03 ADR-0005 §3.4 profile/route
    derivation replaces this source later.
* **⟨r2.3⟩ Rulings on the wave-2 escalations (ADR-0006 §13.6), U5 side
  (M01-rulings-13-6-F1).**
  * Pause (item 1): new grants and new work bindings (fresh request or work ID,
    delegation, coalesced attach, new-activation issuance) ⇒ `POLICY_PAUSED`, checked
    before re-validation; re-validation and issuance within an existing grant use the
    pause-free `continuing_policy` view, so existing bindings bind and issue until
    their deadline; same-key replays return the recorded result; a request waiting
    for added authority answers `POLICY_PAUSED`, keeps waiting and gets no fresh
    decision while paused. Cutoff: existing use past `min(deadline, cutoff)` ⇒
    `CREDENTIAL_EXPIRED` (`issuance::check` now returns `CutoffPassed` only for a new
    activation, `BoundPassed` otherwise); a new activation or binding at/after it ⇒
    `POLICY_CUTOFF`. The applicable policy whose revision is pinned is the first by
    ID (blocks come from the merged view of every applicable policy).
  * Generation (item 5): `Txn::upsert_policy` bumps the authority generation on every
    accepted write (signature unchanged; `narrowing` no longer selects it). A chain
    validated at the current generation is checked against the current applicable
    revision; publish after any policy change is voided (`StaleGeneration`).
  * Parent reference (item 3, amends the ⟨r2.2⟩ bullet above): released when the
    child enters `revoking` or a terminal state (`put_grant`; verified, no change).
    Items 2 and 6 verified as implemented (strict `DECISION_STALE`; later/cleared
    cutoff is a widening decision, refused with `TIME_UNCERTAIN` while time is
    uncertain; narrowing never blocked by time).
  * Tests: `model_operations::r136_*` (items 1, 3, 5, 6), the updated
    `a19_decision_issued_under_an_older_generation_is_stale`,
    `g08_a_future_cutoff_on_any_applicable_policy_bounds_the_grant`,
    `model_revocation::a07_publish_rechecks_every_predicate_and_voids_after_each_change`
    and the property `tombstones_and_cutoffs_are_never_defeated_by_stale_callbacks_or_new_ids`
    (now also: an existing binding binds under a pause before its deadline and is
    `CREDENTIAL_EXPIRED` past it or a cutoff), `integration_store::policy_revisions_are_monotonic_and_narrowing_bumps_generation`.
* **Property tests (plan §6.3 #3–#5, #7, #8):** retry convergence/conflict/expiry
  under random interleavings and purges; stale-generation callbacks refused; unrelated
  scopes never share a grant; a released reference never retains a grant past its
  deadline; caller timeout leaves state unchanged; `OutcomeUnknown` never reported
  as `effect_status: none`; decisions consume-once under concurrent `decide`.
* **Model tests:** **A06** (duplicate concurrent requests ⇒ one operation and one
  effect counted by `FakeCredentialAdapter::effect_count`; kill the caller and retry
  ⇒ same result; altered parameters ⇒ `REQUEST_CONFLICT`; purge then retry ⇒
  `REQUEST_EXPIRED`; crash **before** the effect, **after the effect before the
  receipt** (`ApplyButLoseReply` + restart ⇒ `reconcile` ⇒ settled without a second
  effect), and **after the receipt**); **A07** (parent/child grants; revoke during a
  scripted slow `prepare` ⇒ child and parent denied, late `Prepared` ignored by the
  generation check; reserve/publish/void interleavings with revoke, cutoff, deadline
  passage and time uncertainty at reserve, sign, publish and delivery; a `reserved`
  entry at crash stays counted and is never republished; `remote_pending` and
  `latest_possible_credential_expiry` truthful; **⟨r2.1⟩** the production
  `issuance::check` run at publish after a revoke, a cutoff, a policy-revision change,
  a continuous-budget expiry, and `TIME_UNCERTAIN` each between reserve and publish
  ⇒ voided, residual still counts nothing published); **A19** (success; pending approval
  with `decision_ref`; `decide` on an unattended session ⇒ `INTERACTION_REQUIRED`;
  stale decision ⇒ `DECISION_STALE`; timeout ≠ cancel; explicit cancel reports
  `may_have_external_effect`; `OutcomeUnknown` from a scripted adapter; duplicate
  event delivery deduplicated; expired/foreign cursor ⇒ `RESYNC_REQUIRED` with a
  usable snapshot cursor; mutation during snapshot not lost; publish during
  replay-to-live delivered once; 257 events on a 256 buffer ⇒ `ResyncRequired`);
  **A29 local** (cross-owner request ID is a distinct key; another principal's
  binding ⇒ `NOT_FOUND`/`NotOwner`; request fields never widen the resolved scope;
  `agent_name`-style metadata ignored; a client-supplied "attended" value is not a
  thing: only `Attend` on an interactive session).
* **⟨r2.1⟩ Added acceptance cases (N04, N06; ADR-0006 §13.3 item 3):**
  `resume`/`clear_cutoff`/added authority on an **attended** session ⇒
  `APPROVAL_REQUIRED` + `decision_ref`, nothing executed until `decide approve`
  (unattended ⇒ `INTERACTION_REQUIRED` + `decision_ref`); a pending-approval operation
  whose grant deadline passes ⇒ the grant `expired` and the operation `failed` with
  `CREDENTIAL_EXPIRED` (nothing waits past its deadline); an expired decision ⇒
  `DECISION_STALE` while the operation stays `awaiting_approval`, and a same-key retry
  returns a fresh `decision_ref`. The lost-reply/restart A06 case with a **new**
  `FakeCredentialAdapter` instance uses `FakeCredentialAdapter::with_ledger` over the
  same ledger file; any in-process reconstruction is labelled **in-process**, never
  process-crash evidence (that is U9/U10's).
* **Fault points:** `ScriptedStageHook` before/after every `EnsureStage`; store
  `FaultAction::Fail` at `BeforeCommit` inside `Commit` ⇒ no active binding and no
  event; `AfterCommit` failure ⇒ retry replays.
* **Depends on:** U4b. **Parallel with:** U8 (against signatures), U6b/U7.

### U5t — Time gate wiring (split from U5; may run as its own unit)

* **Owner paths:** `crates/app/src/timegate.rs`, `tests/model/timegate.rs` (host:
  `heimdall-runtime`).
* **Interfaces:** `TimeGate::{check, peek, confirm_attended, anchor_grant,
  shorten_grant, admission}` over `Txn::{runtime_anchor, set_runtime_anchor,
  high_water_mark, raise_high_water_mark, grant_anchor, set_grant_anchor,
  time_confirmation, set_time_confirmation}`.
* **Tests:** the U3 A08 cases re-run through `TimeGate` + in-memory store (same
  expectations, real persistence); `Uncertain` persists nothing; `Safe` persists
  anchor + mark atomically; `confirm_attended` refuses a confirmed value outside the
  skew tolerance and never changes a `GrantAnchor.bound`.
* **Depends on:** U4b.

### U6 — Unix control endpoint (wave 1) and **U6b — session/subscription revision**

* **Owner paths:** `crates/ipc/**`, `tests/integration/ipc_unix.rs`,
  `tests/adversarial/ipc_frames.rs`.
* **Interfaces (U6b):** `session::{SessionInfo, Dispatcher::{dispatch, subscribe},
  SubscriptionStart, LiveEvent, ControlClient::{handshake(interaction), attend,
  subscribe, next_event, unsubscribe}, SubscribeOutcome}`; `negotiate` with
  `required ⊆ negotiated`; `Attend` handling; attended-only requests refused before
  dispatch on unattended sessions; `EndpointKind::Issuer`, `EndpointPaths.issuer`.
* **Tests:** wave-1 suite kept; inconsistent hello; attend on interactive vs
  non-interactive sessions; attended-only request refused pre-dispatch; publish
  during replay-to-live delivered once; two readers, two cursors; backlog-then-live
  ordering; lag → resync. **⟨r2.1⟩ N03:** oversized event in the backlog and in the
  live path ⇒ `ResyncRequired` at the last delivered cursor, subscription ended,
  further publication and lag not delivered on it, resubscribe-from-snapshot works,
  resubscribe-from-cursor meets `ResyncRequired` again. N04: widening actions on an
  attended session are dispatched (the session layer never executes; the fake
  dispatcher models the decision flow).

### U6w — Windows named-pipe endpoint (wave 1; `connect_with_owner` added)

* **Owner paths:** `crates/ipc/src/windows.rs`, `tests/native/windows-ipc/**`.
* **Interfaces:** `ServerOwner`, `connect_with_owner` (server-owner SID check),
  `connect` (test-only, no owner check), `client_sid`, `classify_path`.
* **Status:** `implemented_unverified` (no independent review yet). Native runs on
  the owner's Windows PC as the non-elevated user:
  `tests/evidence/artifacts/m01/u6w-native/r6-owner-sddl` (exit 101: Windows refused
  a descriptor owner the process does not hold, `ERROR_INVALID_OWNER`; fixed by
  always using the creating process's SID as owner) and `…/r6-owner-sddl-2` (exit 0:
  `windows::` 14/14, four binaries exit 0, canary scan 0). The cross-user refusal
  stays `blocked` on the disposable second Windows account (ADR-0004 §3).

### U7 — Signing endpoint framer (wave 1)

* **Owner paths:** `crates/ipc/src/signing.rs`, `tests/adversarial/agent_frames.rs`.
* **Note for M03:** the `Signer` implementation must call `TimeGate::check` and
  `admission` per signature (ADR-0005 §3.6).

### U8 — Runtime: service, instance, supervisor, launcher, config, telemetry, platform — **wave 2**

* **Owner paths:** `crates/runtime/**`, `schemas/configuration/**`,
  `tests/integration/runtime.rs` (host: `heimdall-runtime`).
* **Interfaces:** `Paths::discover`, `Config::{parse, max_window}`, `InstanceInfo::
  {write, read_valid}`, `Service::{start, run}` (start order per overview §3),
  `Supervisor::{run, scheduler_pass, time_guard_pass}` (gate via
  `Operations::timegate`), `launcher::ensure_running`, `telemetry::{init, redact}`,
  `platform::{SystemClock::{read_continuous, read_boot_id}, SystemTimeSync}`
  (platform FFI bodies; macOS and Linux implementable here, Windows compile-checked
  only), the `ipc::session::Dispatcher` implementation over `Operations` (building
  `app::Caller` from `SessionInfo`; adapting `app::events::SubscriptionStart` to
  `ipc::session::SubscriptionStart`), and `ControlConnection::with_server_identity`
  per listener.
* **Tests:** second `Service::start` ⇒ `AlreadyRunning`; stale `instance.json`
  ignored; eight concurrent clients start exactly one child; scheduler expires a
  grant exactly at the persisted bound and at the continuous budget end under
  `VirtualClock`, across a same-boot restart and after a reboot with sync; time
  guard refuses rollback and unsynchronized reboot, and `ensure` then returns
  `TIME_UNCERTAIN`; restart recovery (A17 local): an operation with an `Attempted`
  receipt is reconciled, not re-prepared; a paused policy stays paused; environment
  ID unchanged; **⟨r2.1⟩ N06 A17-local:** (a) a generation-N cleanup racing its
  replacement N+1 **at the actual deletion boundary** (a test hook between the
  decision to delete and the delete; N+1 created there) ⇒ N+1 survives, N is gone;
  (b) repeated `AdapterError::Unavailable` failures ⇒ retries owned by the **single**
  supervisor (no duplicate retry loop per operation or per connection), bounded
  backoff, attempts capped, then a stable failure code (**M01-wave2-gapfix:** implemented
  as `Supervisor::cleanup_pass` over `app::ports::ResourceCleaner` with the
  `app::reconcile::CleanupHook` deletion-boundary hook; tests `model_operations::g03_*`,
  `g04_*`; a failed operation `prepare` is still reported once with a stable code and not
  retried by the operations path); `redact` removes canary and key-like blocks; config rejects
  `trusted = true`; `platform::SystemClock` on this host: continuous time counts a
  short sleep-free interval monotonically and boot ID is stable across two reads
  (native sleep/reboot evidence is M04).
* **Depends on:** U4b, U5, U6b.
* **⟨r2.3⟩ ADR-0006 §13.6 items 4 and 8, U8 side (M01-rulings-13-6-F2).**
  * Item 4: supervisor-owned retries are bounded **and jittered**: `Supervisor::
    with_jitter(Arc<dyn Jitter>)` (default `RandomJitter`; tests inject a
    deterministic source), `retry_delay = Backoff::jittered(n, unit)` for the
    cleanup executor, and a jittered failed-scheduler-pass retry. M01 has no repair
    executor (no repair port before M02); it will use `retry_delay`. Verified: a
    caller's `prepare` `Unavailable` is answered once with `SERVICE_UNAVAILABLE`
    (exit 5), never retried by the supervisor loop or a restart; the same key
    replays. Tests: `integration_runtime::u8b::{cleanup_retries_use_bounded_backoff_with_injected_jitter,
    unavailable_prepare_is_answered_once_and_never_retried_by_the_supervisor_or_a_restart}`,
    property `jitter_props::jittered_retry_delays_stay_within_the_bounded_backoff`.
    `model_operations::g04_*` (unjittered offsets) must inject `FixedJitter(1.0)`.
  * Item 8: `Request::Shutdown` (`service-control/1`): owner role only, any session,
    idempotent; `OK {"stopping", "already_stopping"}` first, then the graceful drain
    (stop accepting, in-flight operations reach a durable stage, advertisement and
    endpoints removed, `run` returns `Ok`). `OperationsDispatcher::
    with_service_control`, `ipc::session::Dispatcher::replied`. Tests:
    `u8b::shutdown_*` (owner drain and file removal, limited consumer refused,
    idempotent, in-flight durable step completes before exit). Windows: the service
    path (named pipes, instance lock, `instance.json`, detached launcher) and the
    tests `service_second_start_is_already_running`,
    `service_ignores_and_replaces_a_stale_instance_json`,
    `launcher_eight_concurrent_clients_start_exactly_one_child`,
    `control_socket_round_trip_against_a_real_service` and `shutdown_*` are no longer
    `cfg(unix)`; native runs: `tests/native/m01/run-windows.sh` (pipes prefixed
    `heimdall-hmtest-`), evidence `tests/evidence/artifacts/m01/rulings-13-6/windows/`.
    The launcher clears the inherit flag on the client's own stdio before the
    detached spawn (`runtime::platform::disinherit_standard_handles`): native run 1
    showed the runtime inheriting the client's stdio pipes otherwise.

### U9 — CLI client, test adapter wiring, schema export — **wave 2**

* **Owner paths:** `crates/heimdall/src/**`, `tests/e2e/cli_m01.rs` (host:
  `heimdall` bin), `schemas/examples/**` (additions).
* **Interfaces:** `cli::dispatch` for `access ensure|release|revoke|pause|resume|
  cutoff`, `operation show|wait|cancel|events`, `decision list|approve|deny`,
  `time confirm`, `service run|status|stop`, `inspect`, `status`; interactive flow:
  stdin is a TTY and `--non-interactive` absent ⇒ hello `interactive` + `Attend`
  before an owner-present action; `--json` envelope on stdout only; exit mapping
  incl. the `ACCEPTED` rule and `Code::Unknown` ⇒ 1.
* **⟨r2.1⟩ Confirmation contract (N04; ADR-0006 §3.1, binding).** Before sending
  `Decide approve` or `ConfirmTime`, show the **exact** recorded action/delta (or the
  runtime's observed time) and require a typed `y`/`yes` (case-insensitive), default
  **No**. EOF, Ctrl-C, a timeout, a non-TTY stdin, `--non-interactive`, `n` or any
  other input sends **nothing**; the decision stays pending until it expires; exit 3,
  code `INTERACTION_REQUIRED`, `next.decision_ref`, message "not confirmed". `Attend`
  is sent only on the session that shows this prompt. `access resume|cutoff --clear`
  on a TTY therefore receives `APPROVAL_REQUIRED` + `decision_ref` and goes straight
  into this prompt + `Decide`. Help text and docs disclose that the server cannot
  verify that a client prompted (same-user imitation).
* **Tests (A19/A06 CLI variants):** every exit class 0–7 observed through the real
  binary against a service in a temp `HEIMDALL_HOME` with the fake adapter (env-gated
  test configuration, never in release builds); `--non-interactive` with a pending
  decision exits 3 with `decision_ref` and no prompt; `decision approve` from a
  non-TTY/`--non-interactive` invocation exits 3; `operation events --follow`
  resumes from `--cursor`; canary scan over all stdout/stderr. **⟨r2.1⟩ N04:** on a
  pseudo-terminal, EOF, an explicit `n`, and (separately) non-TTY stdin each leave the
  decision `pending` (checked through `decision list`) with exit 3
  `INTERACTION_REQUIRED`; `yes` completes it exactly once (a second `yes` ⇒
  `DECISION_STALE`). **⟨r2.1⟩ N06 service death:** (a) **A06 across process death**:
  service with `FakeCredentialAdapter::with_ledger(<temp ledger>)` scripted
  `ApplyButLoseReply`; kill the service process **by exact PID** (recorded from
  `instance.json` and checked against the started child) after the effect is in the
  ledger but before the receipt; restart service and client; retry the same request
  ⇒ reconciled, **exactly one** ledger entry; (b) kill the service while a caller
  waits on `operation wait`/`access ensure`, a new service replaces the socket ⇒ the
  waiting client gets a stable code (`SERVICE_UNAVAILABLE`), the retry against the new
  socket replays/reconciles, never a second effect.
* **Depends on:** U5, U6b, U8.
* **⟨r2.3⟩ ADR-0006 §13.6 items 7 and 8, U9 side (M01-rulings-13-6-F2).**
  * Item 7: on an interactive TTY session the CLI sends `Attend` **before** an
    owner-present request (`access ensure|resume|cutoff`, `decision approve|deny`,
    `time confirm`; never `pause`), so the runtime answers `APPROVAL_REQUIRED` +
    `next.decision_ref`; the prompt shows that answer and the exact recorded
    request; `Decide` only on `y`/`yes`; anything else sends nothing more (exit 3
    `INTERACTION_REQUIRED` "not confirmed"). `--non-interactive`/non-TTY never
    attends or prompts. Tests: `cli::tests` (session/prompt test seam, every
    platform) and the e2e pty cases (Unix only: `script(1)`).
  * Item 8: `service stop` sends `Request::Shutdown` on every platform
    (`data.via = "control"`), Unix SIGTERM fallback only when the endpoint is
    unusable (`"signal"`); idempotent. The e2e suite runs on Windows against
    `heimdall.exe` (`HEIMDALL_E2E_BIN`); its pty cases are `cfg(unix)`. Tests:
    `service_stop_sends_shutdown_over_the_control_endpoint_and_is_idempotent`,
    `unavailable_prepare_exits_5_once_and_the_same_key_replays_the_same_operation`.

### U10 — Cross-crate model suite and evidence records (M01 exit)

* **Owner paths:** `tests/model/operations.rs` harness glue, `tests/evidence/
  m01-*.json`, `tests/evidence/artifacts/m01/**`.
* **Does:** assembles A06/A07/A08/A19/A29 model and local-runtime runs from U3b,
  U4b, U5, U5t, U6b, U8, U9 into named cases; writes evidence records per plan §6.6
  with real exit codes and redacted logs; confirms plan §5 M01 exit evidence
  ("revocation races fail closed; no external side effects needed; crash recovery
  cannot reset a deadline, revive a pause, or change environment identity"); only
  then may units move from `implemented_unverified` to `verified` (E15).
* **⟨r2.1⟩ N06 exit cases U10 must hold before M01 exit:** U8's cleanup-vs-replacement
  race at the deletion boundary and bounded single-supervisor retry; U9's
  service-death A06 (exact-PID kill, durable ledger, exactly one effect after restart
  of service and client) and kill-while-waiting/socket replacement; U5's
  pending-approval deadline expiry and expired decision. Evidence records label each
  run **process-crash** or **in-process** truthfully; an in-process reconstruction
  never closes the process-crash claim.

## 2. Order and parallelism

```text
U1b contract tests ─┐
U3b time tests ─────┤
U4b store ──────────┼──► U5 app operations ──┐
U5t time gate ──────┤      (needs U4b)        ├──► U8 runtime ──► U9 CLI ──► U10 exit suite
U6b ipc session ────┤                         │
U6w windows ────────┤ (native run blocked)    │
U7 signing (done) ──┴─────────────────────────┘
```

U1b, U3b, U4b, U6b ran in the design-fix round. U5 and U5t start against the
skeleton now and go green as U4b lands; U8 after U4b/U5/U6b have compiling bodies;
U9 after U5, U6b, U8; U10 last. The integrator owns `Cargo.toml`, `Cargo.lock`,
`crates/contract/**`, `crates/domain/**`, `crates/app/src/{ports,context,ensure}.rs`,
`clippy.toml`, ADR-0006 and this file.

## 3. Milestone exit mapping (plan §5 M01 "Exit evidence")

| Exit claim | Evidence unit | Case IDs |
|---|---|---|
| A06/A07/A08/A19/A29 model and local-runtime variants pass | U5, U5t, U8, U9, U10 | A06, A07, A08, A19, A29 |
| Revocation races fail closed | U5 (A07 incl. reserve/publish interleavings), U3b (generation property) | A07 |
| No external side effects needed to verify core semantics | all (fake adapter only) | — |
| Crash recovery cannot reset a deadline, revive a pause, or change environment identity | U4b (fault tests), U5 (receipts/reconcile), U8 (restart recovery, ⟨r2.1⟩ cleanup race, bounded retry), U9/U10 (⟨r2.1⟩ service-death A06 by exact PID) | A06, A08, A17 (local) |
| Time rule of ADR-0005 §3.6 holds under sleep, restart, reboot, rollback | U3b, U5t, U8 | A08 |
| G08 contract baseline recorded (revision 2) | ADR-0006, U1b | A19 fixtures |
| Model portions of G05/G09 | U2 (policy/cutoff), U3b (clocks), U5 (renewal never extends; issuance predicates) | A05 model, A08 |

Native Windows/macOS/Linux lock, secure-store, sleep/reboot and cross-user cases
remain `blocked` with the exact platform named; M01 does not claim them.
