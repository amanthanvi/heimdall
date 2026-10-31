# M01 work breakdown (deterministic core and lifecycle substrate)

**Inputs:** plan §5 M01 (T01–T06), §6.3 properties, §6.4 fault schedule; spec §17
A06/A07/A08/A19/A29 (model and local-runtime variants); `overview.md`; ADR-0006.
**Skeleton:** every type, trait and function named below already exists in
`crates/` with `todo!("M01-Txx …")` bodies; a unit replaces the bodies it owns and
adds tests. No unit changes a signature, table or limit without an ADR-0006
revision (plan §7.3 "serialize changes to authority semantics").
**Statuses:** every unit is `not_started` unless stated. A unit is `verified` only
when its tests ran on this toolchain and the evidence record exists
(`tests/evidence/`, plan §6.6).

## 0. Ground rules for every unit

* Write only inside the owner paths below (plus the unit's test files). Shared files
  (`Cargo.toml`, `crates/contract/**`, `crates/domain/src/lifecycle.rs`) change only
  through the integrator with an ADR note.
* Property tests use `proptest` with `ProptestConfig { cases: ≥ 256, .. }`, commit
  `proptest-regressions/` files, and print the seed on failure (`PROPTEST_RNG_SEED`
  reproduces). Model tests are deterministic over `testkit::VirtualClock` and
  `Store::open_in_memory`.
* Fault injection uses `store::FaultHook` (durable-write points), `app::ensure::
  StageHook` (pipeline stages), and `testkit::FakeCredentialAdapter` scripts
  (adapter failures, `OutcomeUnknown`, side-effect counting). No unit needs a
  network, provider, or external host; platform-only tests are `blocked` with the
  platform named.
* Canaries: fixtures may contain `HEIMDALL_CANARY_*` values; `testkit::
  assert_no_canary` runs over every envelope, event payload, log line and error
  message a test produces (ADR-0004 §4).
* Every unit runs `tools/validation/check.sh` before hand-off and records the three
  exit codes.

## 1. Units

### U1 — Contract golden tests and schema consistency (M01-T06 part 1)

* **Owner paths:** `crates/contract/src/**` (tests only), `tests/contracts/**`,
  `schemas/public-api/**` (regenerated), `tools/validation/check.sh` (enable the
  schema diff step).
* **Implements against:** `contract::Code`, `Envelope`, `ErrorData`, `Request`,
  `Event`, `Snapshot`, `ClientMessage`/`ServerMessage`, `schema::public_schemas`,
  `canonical::{canonical_json, request_hash}`.
* **Tests required:** golden JSON for every `Code` row (exit, retryable, effect,
  next) against ADR-0006 §5; envelope fixtures for success / pending / each error
  class (plan §4.5 "example success/pending/error payloads") under
  `schemas/examples/`; unknown-field tolerance and unsupported-major rejection
  (ADR-0006 §9); canonical-JSON property: key-order independence, array-order
  dependence, hash equality ⇔ canonical-byte equality; ID parser bounds (A29
  parsers bounded); schema export is byte-identical across two runs.
* **Fault points:** none (pure).
* **Depends on:** nothing. **Parallel with:** all.

### U2 — Authority resolution and scope algebra (M01-T01)

* **Owner paths:** `crates/domain/src/{authority,scope,policy,profile,environment,
  evidence}.rs`, `tests/model/authority.rs`.
* **Implements:** `authority::resolve_authority` (spec §6.2 intersection; pause and
  cutoff override allow; parent attenuation; `RequiredCapabilities` minimums →
  `Denied(CapabilityUnavailable)`; delta classification for `ApprovalRequired`);
  `Scope::{intersect, is_subset_of, difference}` already implemented.
* **Property tests (plan §6.3 #1, #2, #3 part):** effective scope ⊆ policy ∩
  environment ∩ requested ∩ parent ∩ destination capability for all generated
  inputs (`testkit::strategies::scope`); effective deadline ≤ min(request, policy
  window, parent, cutoff); a paused or cut-off policy never yields `Allowed`
  whatever the request/work IDs; `ApprovalRequired.delta` is exactly `requested −
  covered`; resolution is a pure function (same input ⇒ same output, 1000 shuffles).
* **Model tests:** A05 model rows (fresh work after cutoff denied; expired binding
  not extended) as table tests.
* **Fault points:** none.
* **Depends on:** nothing (contract types exist). **Parallel with:** U3–U9.

### U3 — Time model, lifecycle tests, virtual-clock suite (M01-T02)

* **Owner paths:** `crates/domain/src/{time,lifecycle,grant,revocation}.rs`,
  `crates/testkit/src/lib.rs` (clock additions only), `tests/model/{time,
  lifecycle}.rs`.
* **Implements:** `time::resolve_deadline` (RFC 3339 with offset or duration, once,
  bounded by `max_window`, `Ambiguous` for local-time ambiguity),
  `time::assess_time` (rollback/skew per overview §5), tests for the already
  implemented `grant_transition` / `operation_transition`.
* **Property tests (plan §6.3 #2, #5):** for random event traces, a grant never
  re-enters `active` from a terminal state or `revoking`; `expired`/`revoked` are
  absorbing; child deadline ≤ parent for every accepted delegation (`GrantSnapshot::
  permits_child`); `assess_time` with monotone wall and matching monotonic progress
  is always `Safe`; any rollback > tolerance is `Uncertain`; forward jumps are
  `Safe`.
* **Model tests (A08 model variant):** sleep across expiry (monotonic-only advance
  then wall jump) ⇒ expired, never extended; backward jump ⇒ `TimeUncertain`; process
  restart (`VirtualClock::restart`) with persisted anchor ⇒ deadline unchanged;
  duration intent retried after restart hashes equal but resolves to the *original*
  persisted instant.
* **Fault points:** none.
* **Depends on:** nothing. **Parallel with:** U2, U4–U9.

### U4 — Transactional state store (M01-T03)

* **Owner paths:** `crates/store/**`, `tests/integration/store.rs`.
* **Implements:** `Store::{open, open_in_memory, transaction, schema_version}`,
  `migrations::apply` (backup copy before first pending step on file stores;
  `NewerSchema` refusal; `integrity_check`), every `Txn` method, retention purge,
  per-environment event sequence, CAS on resource generation
  (`GenerationConflict`), idempotency row inserted with the operation row.
* **Property tests (plan §6.3 #4, #6):** same key + same hash replays, different
  hash conflicts (through `Txn`, not only `domain::classify`); `upsert_resource`
  with a stale expected generation always fails and leaves the newer row intact;
  purge never deletes tombstones, policies, or `meta.self_environment_id` for any
  random purge instant.
* **Fault tests (plan §6.4):** `ScriptedFaults` at `BeforeCommit` ⇒ no row visible
  afterwards; at `AfterCommit` ⇒ row visible and the caller sees the error (the
  application must then treat the outcome as `Replay` on retry); `Crash` at each
  point in a child process ⇒ reopen passes `integrity_check` and shows exactly the
  committed state; corrupt a nonsecret copy ⇒ `StoreError::Corrupt`, never a fresh
  empty database; open with `user_version` = 99 ⇒ `NewerSchema`.
* **Depends on:** nothing. **Parallel with:** all; U5 and U8 consume it through the
  skeleton signatures.

### U5 — Application operations, pipeline, single-flight, events (M01-T05 core + M01-T06 part 2)

* **Owner paths:** `crates/app/src/{operations,ensure,singleflight,reconcile,
  events,error}.rs`, `tests/model/{operations,idempotency,revocation,events}.rs`.
* **Implements:** `Operations::{start (restart recovery), inspect, ensure, bind,
  delegate, observe, cancel, release, revoke, policy, tick}` over `Store`,
  `Clock`, `CredentialAdapter`, `DecisionChannel`; `EnsureStage` journaling via
  `RecoveryMetadata.last_stage`; `SingleFlight::{join_or_lead, finish}`;
  `EventPublisher::{publish, head_cursor}` and `events::cursor::{encode, decode,
  reader_tag}`; adapter-error → code mapping (overview §7).
* **Property tests (plan §6.3 #3, #4, #5, #7, #8):** random interleavings of
  `ensure` retries with the same/different hash converge/conflict; `revoke` then
  any stale callback (`generation` older) is refused; two callers with unrelated
  scopes never share a grant (equivalence key includes scope and mechanism); a
  released reference never retains a grant past its deadline; caller timeout
  (`WaitMode::Sync` expiry) leaves the operation state unchanged; `OutcomeUnknown`
  is never reported as `effect_status: none`.
* **Model tests:** **A06** (duplicate concurrent requests ⇒ one operation; kill the
  caller [drop the future] and retry ⇒ same result; altered parameters ⇒
  `REQUEST_CONFLICT`; one `FakeCredentialAdapter.effects` increment total);
  **A07** (parent/child grants, revoke during a scripted slow `prepare` ⇒ child and
  parent denied, late `Prepared` ignored by generation check, `remote_pending`
  truthful from the fake's `RevokeOutcome`); **A19** (success, pending approval via
  `DecisionChannel`, timeout ≠ cancel, explicit cancel reporting
  `may_have_external_effect`, `OutcomeUnknown` from a scripted adapter, duplicate
  event delivery deduplicated by `event_id`, expired/foreign cursor ⇒
  `RESYNC_REQUIRED` with a usable snapshot cursor, 257 events on a 256 buffer ⇒
  `ResyncRequired`); **A29 local** (cross-owner request ID is a distinct key; a
  request naming another principal's binding is `NOT_FOUND`/denied; request fields
  never widen the resolved scope; `agent_name`-style metadata is ignored).
* **Fault points:** `StageHook::before/after` at every `EnsureStage`: interruption
  before `Commit` ⇒ retry resumes from `last_stage` without a second adapter
  `prepare`; interruption after `Reconcile` with a remote-mutating fake ⇒ operation
  `OutcomeUnknown` until reconciled; store `FaultAction::Fail` at `BeforeCommit`
  inside `Commit` ⇒ no active binding and no event.
* **Depends on:** U2 (resolve_authority), U3 (resolve_deadline, assess_time), U4
  (Txn methods). Can start immediately against the signatures; its tests go green
  as U2–U4 land. **Parallel with:** U6–U9.

### U6 — Unix control endpoint and sessions (M01-T04 part 1)

* **Owner paths:** `crates/ipc/src/{unix,session,endpoint}.rs`,
  `tests/integration/ipc_unix.rs`, `tests/adversarial/ipc_frames.rs`.
* **Implements:** `unix::{Listener::bind, connect, current_uid}`,
  `EndpointPaths::for_runtime`, `ControlConnection::serve`, `ControlClient::
  {handshake, request}`, per-connection limits.
* **Tests:** bind creates `0700` dir and `0600` socket (metadata asserted); a peer
  with a different uid is rejected (simulated by `verify_peer` with a forged
  `PeerIdentity`; the real cross-user case is `blocked` on a second Unix account
  and recorded as such); hello timeout closes silent connections; oversize length
  prefix (0xFFFFFFFF) closes without allocation; truncated frame, invalid UTF-8,
  wrong first message, 17th in-flight request ⇒ `BACKPRESSURE`, 5th subscription
  ⇒ `BACKPRESSURE`; stale socket of ours replaced, foreign-uid socket left alone
  (fixture socket chowned is `blocked` without root; test the uid-mismatch branch
  with an injected stat); A29 frame corpus from `proptest` byte strategies never
  panics (`decode_frame` fuzz).
* **Fault points:** server dropped mid-response ⇒ client surfaces
  `SERVICE_UNAVAILABLE`, operation state is whatever the journal says (checked via a
  second connection).
* **Depends on:** U1 types only. **Parallel with:** all.

### U6w — Windows named-pipe endpoint (M01-T04 part 1, Windows)

* **Owner paths:** `crates/ipc/src/windows.rs`, `tests/native/windows-ipc/**`.
* **Implements:** `windows::{Listener::bind/accept, client_sid, classify_path,
  connect, current_user_sid}` with the DACL, `PIPE_REJECT_REMOTE_CLIENTS`,
  `FILE_FLAG_FIRST_PIPE_INSTANCE`, identification-level impersonation, and the
  path-classification rule (REPORT.md §16).
* **Tests:** same-user connect succeeds and `principal` reports the SID; regular
  file / `NUL` / directory as endpoint refused before any data open (file bytes and
  mtime unchanged); a pre-created pipe of the same name makes `bind` fail (first
  instance); `cargo check --target x86_64-pc-windows-gnu -p heimdall-ipc` stays
  green on every host. Cross-user rejection is `blocked` on the disposable second
  Windows account (ADR-0004 §3).
* **Status:** `blocked` for native verification until the owner's Windows PC runs
  it; compile-check is `verified` on macOS for the skeleton (see hand-off report).
* **Depends on:** U6 (shared `session`). **Parallel with:** all.

### U7 — Signing endpoint framer (M01-T04 part 2)

* **Owner paths:** `crates/ipc/src/signing.rs`, `tests/adversarial/agent_frames.rs`.
* **Implements:** `signing::serve` (length-prefixed agent frames, `classify`,
  `MAX_IDENTITIES`, idle timeout, canned answers; `Signer` wired in M03).
* **Tests:** allow-list exactness (already in-tree), oversize/truncated/zero-length
  frames close the connection, 65th identity never listed, idle close at 30 s
  (virtual time via `tokio::time::pause`), control-message bytes sent to the signing
  endpoint ⇒ `SSH_AGENT_FAILURE` and no JSON parse attempted (signing/control
  confusion, A29); REPORT.md §4 crafted-frame corpus (nkeys > 1024, string overrun,
  trailing bytes) ported as fixtures.
* **Depends on:** nothing. **Parallel with:** all.

### U8 — Runtime: service, instance, supervisor, launcher, config, telemetry (M01-T05)

* **Owner paths:** `crates/runtime/**`, `schemas/configuration/**`,
  `tests/integration/runtime.rs`.
* **Implements:** `Paths::discover`, `Config::{parse, max_window}`, `InstanceInfo::
  {write, read_valid}`, `Service::{start, run}`, `Supervisor::{run, scheduler_pass,
  time_guard_pass}`, `launcher::ensure_running`, `telemetry::{init, redact}`,
  `Service::runtime` with a bounded blocking pool; wire `ipc::Dispatcher` to
  `Operations`.
* **Tests:** second `Service::start` on the same state dir ⇒ `AlreadyRunning`
  (`InstanceLock` test already in-tree); `instance.json` with a dead pid or
  mismatched start time is ignored; `ensure_running` from 8 concurrent clients
  starts exactly one child (counted via a marker file written by `service run` in a
  temp `HEIMDALL_HOME`); scheduler expires a grant exactly at its persisted
  deadline under `VirtualClock` and after `restart()`; time guard flips
  `issuance_enabled` off on rollback and `Operations::ensure` then returns
  `TIME_UNCERTAIN`; restart recovery (A17 local part): open operation at
  `last_stage = Reconcile` is re-driven without a second adapter effect; paused
  policy stays paused across restart; environment ID unchanged across restart
  (R-RT-07); `redact` removes injected canary and key-like blocks; config rejects
  `trusted = true` and a `max_window` above the floor/ceiling.
* **Fault points:** kill the service (drop the future / `FaultAction::Crash` in a
  child) while a caller waits ⇒ caller gets `SERVICE_UNAVAILABLE`, operation state
  recoverable; shutdown during `Reconcile` drains to a durable stage.
* **Depends on:** U4, U5, U6. **Parallel with:** U7, U9 (against signatures).

### U9 — CLI client, test adapter wiring, schema export (M01-T06)

* **Owner paths:** `crates/heimdall/src/**`, `tests/e2e/cli_m01.rs`,
  `schemas/examples/**`.
* **Implements:** `cli::dispatch` for `access ensure|release|revoke|pause|resume|
  cutoff`, `operation show|wait|cancel|events`, `service run|status|stop`,
  `inspect`, `status`; `ControlClient` use; `--json` envelope on stdout, text
  otherwise, nothing else on stdout; exit mapping incl. the `ACCEPTED` rule;
  `--non-interactive` propagated as `InteractionMode`; `schema export` already
  implemented (keep).
* **Tests (A19 CLI variant, A06 CLI variant):** every outcome class reachable
  through the real binary against a service started in a temp `HEIMDALL_HOME` with
  `FakeCredentialAdapter` selected by an env-gated test configuration (never in
  release builds): exit 0/2/3/4/5/6/7 each observed and recorded; stdout is exactly
  one JSON line in `--json` mode; `operation events --follow` emits NDJSON and
  resumes from `--cursor`; duplicate `access ensure --request-id` returns the same
  `operation_id`; altered parameters exit 6; `--non-interactive` with a pending
  decision exits 3 with `decision_ref` and no prompt (R-AP-06); canary scan over
  all stdout/stderr.
* **Depends on:** U5, U6, U8. **Parallel with:** U7.

### U10 — Cross-crate model suite and evidence records (M01 exit)

* **Owner paths:** `tests/model/mod.rs` (harness), `tests/evidence/m01-*.json`.
* **Does:** assembles the A06/A07/A08/A19/A29 model and local-runtime cases from
  U2–U9 into named runs; writes evidence records per plan §6.6 with real exit codes
  and redacted logs; confirms plan §5 M01 exit evidence ("revocation races fail
  closed; no external side effects needed; crash recovery cannot reset a deadline,
  revive a pause, or change environment identity").
* **Depends on:** all units.

## 2. Order and parallelism

```text
U1 contract tests ─┐
U2 authority ──────┤
U3 time/lifecycle ─┼──► U5 app operations ──► U8 runtime ──► U9 CLI ──► U10 exit suite
U4 store ──────────┤          ▲                  ▲
U6 ipc unix ───────┼──────────┘                  │
U6w ipc windows ───┤ (blocked: native host)      │
U7 signing framer ─┴─────────────────────────────┘
```

U1–U4, U6, U6w, U7 start now in parallel against the skeleton. U5 starts now and
goes green as U2–U4 land. U8 starts once U4–U6 have compiling bodies; U9 after U5,
U6, U8. The integrator owns `Cargo.toml`, `Cargo.lock`, `crates/contract/**`,
`crates/domain/src/lifecycle.rs`, `clippy.toml` and this file.

## 3. Milestone exit mapping (plan §5 M01 "Exit evidence")

| Exit claim | Evidence unit | Case IDs |
|---|---|---|
| A06/A07/A08/A19/A29 model and local-runtime variants pass | U5, U8, U9, U10 | A06, A07, A08, A19, A29 |
| Revocation races fail closed | U5 (A07), U3 (generation property) | A07 |
| No external side effects needed to verify core semantics | all (fake adapter only) | — |
| Crash recovery cannot reset a deadline, revive a pause, or change environment identity | U4 (fault tests), U8 (restart recovery) | A08, A17 (local) |
| G08 contract baseline recorded | ADR-0006, U1 | A19 fixtures |
| Model portions of G05/G09 | U2 (policy/cutoff), U3 (clocks), U5 (renewal never extends) | A05 model, A08 |

Native Windows/macOS/Linux lock, secure-store and cross-user cases remain `blocked`
with the exact platform named; M01 does not claim them.
