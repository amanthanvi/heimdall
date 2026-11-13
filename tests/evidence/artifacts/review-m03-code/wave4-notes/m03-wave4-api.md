# M03 wave 4: shared readings and landed seams (untracked; integrator + units)

Read the code for exact signatures. Each unit appends what it lands to **its own section** as soon
as it compiles. Requests to another unit or to the integrator go under "Requests".

## 0. Landed by the integrator before the units started (compiles: `cargo check -p heimdall-app -p heimdall-runtime -p heimdall --tests` 0)

| Seam | File | Owner of the body |
|---|---|---|
| `pub mod enrollment;` (public, pure part of the stage driver) | `crates/app/src/enrollment.rs` | U10-A |
| `pub mod issuer;` + `trait IssuerLifecycle { start, reload, stop }` | `crates/app/src/issuer.rs` | U10-B |
| `managed::ManagedWiring` (all `Option<Arc<dyn …>>`: effects, issuer, issuer_lifecycle, verification_endpoints, verification_runner, target, connections) | `crates/app/src/managed.rs` (bottom) | integrator (fields fixed; ask to add one) |
| `Operations::{set_managed_wiring, managed_wiring}` | `crates/app/src/operations/managed_state_m03.rs` | integrator |
| `managed::drive_preparation` now calls `managed::driver::drive` | `crates/app/src/managed/driver.rs` | U10-C |
| `Operations::enrollment_request(&Caller, EnrollmentRequest) -> OpResult<Value>`, `reverify_pass()`, `enrollment_step_timeout_pass()`, `enrollment_after_decision`, `decision_precheck`/`decision_apply` | `crates/app/src/operations/enrollment_m03.rs` | U10-A |
| `Operations::issuer_request(&Caller, IssuerRequest) -> OpResult<Value>`, `issuer_supervision_pass()`, `issuer_after_decision`, `decision_precheck`/`decision_apply` | `crates/app/src/operations/issuer_m03.rs` | U10-B |
| `Operations::managed_prepared(adapter, PrepareRequest)` (ensure hook) and `managed_reissue_pass()` | `crates/app/src/operations/managed_driver_m03.rs` | U10-C |
| M03 decision kinds routed: `decisions_m03::{precheck, apply}` + `m03_after_decision` | `crates/app/src/operations/decisions_m03.rs` + `Operations::decide` | integrator |
| Ensure pipeline hook: after `read_prepare_sources`, before the bounded `prepare_from`, `managed_prepared` runs for the managed adapter and its result is `sources.managed.prepared`; an `Err` takes the existing `prepare_from` error arms | `operations.rs` `prepare` step (~7016) | integrator |
| Dispatch: `Request::Issuer` → `ops.issuer_request`, `Request::Enrollment` → `ops.enrollment_request` (owner-only refusal first, unchanged); `Connections` still `driver_unavailable` | `crates/runtime/src/dispatch.rs` | U10-D (Connections, capabilities) |
| `[[test]] e2e_managed_m03` (`tests/e2e/managed_m03.rs`), `e2e_enroll_m03` (`tests/e2e/enroll_m03.rs`), host crate `heimdall`; placeholder test `target_is_wired` (the unit replaces it) | `crates/heimdall/Cargo.toml` | U10-C / U10-A |
| `heimdall` dev-dep testkit features += `managed` | `crates/heimdall/Cargo.toml` | — |

**Decide semantics for the M03 kinds** (`operations.rs` `decide`): attended + owner checks and the
expiry check run first (unchanged). Then `decisions_m03::precheck(tx, &d, verdict, now)` →
`Ok(Err(e))` refuses with **nothing written** (record stays `pending`, not consumed); `Ok(Ok(op))`
names the waiting operation (or `None`). The store completes the record (generation check, R7), the
decision event is emitted, then `decisions_m03::apply(tx, emit, &record, verdict, waiting_op, now,
retention)` runs in the **same** transaction: `Ok(Err(e))` rolls the whole transaction back (nothing
consumed; `e` is returned to the caller); `Ok(Ok(ids))` = operations to resume through the M01
pipeline (normally none for M03). After the commit, `m03_after_decision(record, verdict)` runs the
kind's non-store work (`issuer_after_decision` / `enrollment_after_decision`). `waiting` for an M03
kind is `None` in the M01 sense, so no M01 grant/waiter logic runs for it.

## 1. Readings for every unit (integrator)

- **R1. Access to the journal.** Code that needs the operation journal, receipts, decisions, events,
  `put_grant`, `settle_failed`, `op_to`, `Emit`, the time gate or `self.inner` lives in a **child module
  of `operations`** (the files above). `crate::enrollment` / `crate::issuer` hold pure logic and public
  types only. Do not add `pub` accessors to `Operations` for internals.
- **R2. `operations.rs` is shared.** Only these edits, each recorded in your worklog section:
  U10-C: the `revoke` and `release` paths (RevokeData fill, post-release `revocation_close` /
  `release_close` through `wiring.connections`), the pair-mechanism `driver_unavailable` refusal
  (`pair_mechanism_m03.rs` + the row-9 arm at ~4354), `narrowing.rs`'s post-release cleanup point
  (~863). U10-D: `destination_view` (~5093, U8-Q6 `preference` field). U10-B:
  `operations/authorize.rs` (INT-Q13 verification admission). U10-A: `enrollment_cancel_m03.rs`.
  Nobody else edits `operations.rs`; ask the integrator under "Requests".
- **R3. Settled seams stay closed.** `heimdall_credential::signer::VERIFICATION_UNGATED_SIGNING` stays
  `false` (verification is admitted **through** a gate, never ungated). The release-build refusal of
  every `HEIMDALL_TEST_*` variable (U0b row 16) stays. Everything not listed in the wave-4 brief that
  fails closed today stays closed. `crates/contract/**`, the store migrations, `Cargo.lock`'s package
  set, pinned versions, new third-party deps, new `unsafe` modules: **escalate** (questions file), take
  the most fail-closed choice that compiles.
- **R4. Fail closed means before any write.** A missing wiring port, a missing CA, a missing
  enrollment, etc. answers `OpError::driver_unavailable(..)` (or the plan's registered reason) before
  the store is written.
- **R5. Fixtures.** m03-plan §0.2 / ADR-0008 D13: disposable fixtures only (`heimdall_testkit::sshd::
  LoopbackSshd`, `ScratchSecretStore`, `FakeSessionLockSource`, per-run keys). Never the owner's keys,
  agent, `~/.ssh`, keychain, 1Password, real servers. Loopback listeners only. Test directories created
  **owner-only explicitly** (umask 002 on the devbox). Every process a test starts has an exact receipt
  (PID, start time, image) and is stopped by exact identity only; never kill by name/pattern.
- **R6. Evidence.** A new regression must be shown failing with its fix reverted (record the command and
  exit code in your worklog section). Never claim a test passed that you did not run.
- **R7. Build hygiene.** One `./target`. Never `CARGO_TARGET_DIR`, `--target-dir`, `cargo clean`. Build
  narrowly (`-p <crate>`, `--test <target>`). Cargo's file lock serializes concurrent builds; that is
  expected. Windows clippy: `bash tools/validation/clippy-windows.sh` (whole workspace; slow, run at the
  end) — per package: see `tools/validation/`. Linux type-check: `bash tools/validation/linux-xcheck.sh
  -p <pkg>`.
- **R8. No commits, stashes, resets, checkouts.** Subagents never commit.
- **R9. Secrets.** No `HEIMDALL_CANARY_*`, key material or passphrase in any output, argv, env dump, log
  or error. No passphrase in argv, tests included.
- **R10. CLI is U12's.** Do not write `heimdall enroll`/`issuer` command bodies. An e2e that needs a
  driving client drives the IPC requests from the test itself (test-local loop over `Enrollment::Step`
  / `StepResult` with `heimdall_enroll::remote::SshStepRunner`).

## U10-A (enrollment): landed interfaces
(U10-A appends here.)
- **Landed, compiles** (`cargo check -p heimdall-app` 0): `crates/app/src/enrollment.rs` (public, pure):
  `trait EnrollmentHost { client() -> Option<String>; client_version() -> Option<String>; paths(tag) ->
  Option<GeneratedPaths>; write_files(tag, known_hosts_line, identity_public: Option<&str>) ->
  Result<GeneratedPaths, HostError>; identity_agent(alias) -> registry::plan::AgentReading;
  endpoint_valid(endpoint) -> bool; heimdall_endpoints() -> Vec<String>; effective_config(&RemoteStep)
  -> Result<String /* ssh -G stdout */, HostError> }`, `GeneratedPaths { trust: TrustPaths, identity_file }`
  (all under `<runtime_dir>/e/<tag>/`: `known_hosts` (one line), `global_known_hosts` (empty),
  `identity.pub`; owner-only, read back). `StepAnswer { Step { step } | Done { result } }` (tag
  `next`) is `Enrollment::Step`'s data; `StepRecorded { stage, class, state, more, result }` is
  `StepResult`'s. `Journal` and helpers (`plan_of_record`, `route_matches`, `proposed_target`,
  `known_hosts_line`, `system_form_lines`).
- `Operations::set_enrollment_host(Arc<dyn EnrollmentHost>)` (enrollment_m03; keyed by environment
  until a `ManagedWiring` field exists). Without it every enrollment action is `driver_unavailable`.
- `Operations::enrollment_request` implements Preview, Apply, Verify (presence/absence/target change),
  Remove (own account form via `RemoveEnrollment`; own system form via the typed confirmation),
  Reconcile, Abandon, Step, StepResult; `reverify_pass`, `enrollment_step_timeout_pass`,
  `enrollment_after_decision`, `decision_precheck`/`decision_apply` for the four kinds. Foreign
  removal (`RemovalTarget::Foreign`, D4 item 5) is implemented too: checks before any write
  (`bundle_redacted`, the rebuilt line's digest, `bundle_host_mismatch`, one host key), the account
  form through `RemoveEnrollment` (`planned → removing`, a held record recovered by a new decision),
  the system form on the typed confirmation (`manual_removal_pending`, absence always `ca_not_held`),
  and Abandon/Verify name a foreign record by its marker's enrollment ID.
- A system-form manual removal's `enrollment.remove` operation stays `running` until its absence
  check passes (settled with it) or the owner cancels it (`cancel` → back to the origin with its
  evidence, via `enrollment_cancel_m03::cancel_in`).
- Supervisor passes: `enrollment_step_timeout_pass()` (an outstanding step past its timeout: a
  mutation `Uncertain`, a read cleared); `reverify_pass()` (evidence older than `reverify_after`, or
  a different verified client version, never while an operation of the record is open).
- For the integrator: `enrollment_m03::enrollments_view_in(tx) -> EnrollmentsView` (for `inspect
  enrollments`) and `enrollment_m03::verification_authority(tx, &op) -> Option<(EnrollmentId,
  authorized)>` (for `verification_m03`; see Requests).
- The journal is stage receipts named `enroll.journal` (JSON in `Confirmed.credential_ref`, adapter
  `{enrollment, journal}`); the §6.4 receipts (`enroll.inspect.started`, `enroll.append` Attempted with
  token = marker, …) are written as the ADR names them, so `enrollment_cancel_allowed` reads them.

## U10-B (issuer, verification, INT-Q13): landed interfaces
(U10-B appends here.)

**B1. INT-Q13 port change (landed; `cargo check -p heimdall-app -p heimdall-credential` 0).**
- `app::ports::VerificationEndpoints::create(&self, operation: &OperationId, plan: &EnrollmentPlan)
  -> Result<Box<dyn VerificationSession>, AdapterError>` (§0b signature, exactly).
- `heimdall_credential::endpoints::EndpointRegistry`:
  - `create_verification(&self, op: &OperationId, scope: &VerificationScope) -> Result<VerificationEndpoint, EndpointError>`;
    `create(op, plan)` = `create_verification(op, &endpoints::verification_scope(plan))`.
  - `with_verification_gates(self, gates: SigningGates) -> EndpointRegistry` (builder, like
    `with_hook`): **U10-D must call it with `ops.signing_gates().clone()`** when building the
    runtime's registry. Without it no gate opens and the production `Operations` refuses every
    verification signature (`key_not_served`; fail closed).
  - New `EndpointError::GateOpen` (a second live session for the same operation).
- `heimdall_credential::table`: `register_verification(op, &VerificationScope)`;
  `install_verification` also refuses a certificate not signed by the scope's CA (`wrong_ca`) and a
  positive certificate whose principal names another pair (`wrong_principal`).
  `table::VerificationScope` re-exports `app::managed::VerificationScope { ca: CaFingerprint, pair: AccessPair }`.

**B2. Verification gate (who opens/closes it).** `app::managed::SigningGates`:
- `open_verification(&OperationId, VerificationScope) -> Result<VerificationGate, GateError>`
  (`GateError::AlreadyOpen`); `VerificationGate` is RAII: **drop closes the gate**
  (`close()`, `close_after_holders().await` waits for admitted signatures first).
- `admit_verification(&OperationId, wait) -> Result<VerificationShared, GateError>`;
  `permit_verification(VerificationShared, PermitExpiry, Arc<dyn SafeTime>) -> SignPermit`;
  `is_verification_open`, `verification_scope`, `verification_holders`.
- `SignPermit::grant()` now returns `Option<&GrantId>`; `SignPermit::verification() -> Option<&OperationId>`;
  `ReleaseRefusal::VerificationClosed` (release refused once the gate closed).
- **For U10-A (`run_verification`): you do not open or close anything yourself.** The gate opens
  inside `VerificationEndpoints::create(op, plan)` (the registry, when wired with gates) and closes
  when the returned `Box<dyn VerificationSession>` is dropped. So: create the session, reserve +
  publish the positive entry (`reserve_verification` / `publish_verification`, subject = the
  session's K_verify fingerprint, pair/CA = the plan's), sign it through `IssuerPort`, `install` it,
  run the positive attempt, then the negative; drop the session on every exit path.
- **The admission predicate** (`operations/authorize.rs`, `SignatureAuthority::{precheck,admit}` for
  `SignatureSubject::Verification(op)`): endpoint must be `SignerEndpoint::Verification(op)`; the
  gate open; then one fresh txn: time `Safe` (same seam as grants), a **published positive**
  verification entry of `op` with `subject_fingerprint` = the presented K_verify, `pair` = the
  request's pair = the gate's pair, CA = the gate's CA, `valid_after ≤ now < valid_before`, and
  `verification_check_read_only(entry, true, Safe, now, max_validity)` Ok (so whatever
  `verification::check` authorizes — today only `enrollment.verify` presence/absence — is
  signable; see Requests B→A). Permit wall bound = the entry's `valid_before`.

**B3. Issuer handling (landed; my files type-check, crate build blocked by others' WIP at the time).**
- `heimdall_issuer::client::ChildIssuer` implements `heimdall_app::issuer::IssuerLifecycle`
  (`start`/`reload`/`stop` = the inherent methods; §17.19 item 3 fencing unchanged). U10-D: put the
  same `Arc<ChildIssuer>` in `ManagedWiring.issuer` **and** `.issuer_lifecycle`.
- `Operations::issuer_request` needs `ManagedWiring.issuer` (all actions) and `.issuer_lifecycle`
  (`register`, `unlock`); otherwise `driver_unavailable` before any write.
- `Operations::issuer_supervision_pass()` (U10-D's supervisor calls it): starts a never-started child
  (`not_initialized`) when a CA is `active`/`pending`; never restarts a stopped one; resumes CA
  retirements (`resume_ca_retirements(issuer, None)`, stalls at `unloaded`, U10B-Q2).
- The recovery-bundle builder moved to `heimdall_app::issuer::bundle::{export, StoreView,
  EnrollmentEntry, Redaction, BundleError}`; `heimdall_issuer::bundle` re-exports it unchanged.
- Pure helpers in `heimdall_app::issuer`: `ca_public_key_fingerprint`, `is_sha256_hex`,
  `retire_admissible`, `enrollment_counts`, `register_disclosures`, `unlock_guidance`.
- `crates/heimdall/src/m03_cmd.rs`: `HEIMDALL_TEST_SECRET_STORE=scratch` → `ScratchSecretStore` at
  `<state>/scratch-secret-store` under `cfg(debug_assertions)` only (release: `None`, and the
  `HEIMDALL_TEST_*` refusal runs first, unchanged).

## U10-C (managed preparation, re-issue, slots, revocation data): landed interfaces
**Landed 2026-11-11 (U10-C).**
```rust
// heimdall_app::managed::driver (public module)
pub fn instance_id_for(fingerprint: &str) -> Option<CredentialInstanceId>;  // K_env SHA256 fp → instance ID (U10C-Q6)
pub mod stage { KEY, RESERVE, SIGN, PUBLISH, INSTALL, PREPARED }           // "managed.<step>" receipts (Attempted, same token)
pub const VALID_AFTER_SKEW_SECS: i64 = 60; pub const ISSUER_SIGN_FAILED; pub const EFFECT_TIMED_OUT;
pub(crate) async fn drive(..) / run_stages(ops, effects, issuer, &GrantSnapshot, token, now, new_activation)
// heimdall_app::Operations (operations/managed_driver_m03.rs)
pub fn managed_driver_wired(&self) -> bool;                                 // effects && issuer wired
pub async fn managed_install_check(&self, &GrantId, &IssuanceEntry) -> Result<(), &'static str>; // U2-Q2, D2 item 6
pub async fn managed_reissue_pass(&self) -> Result<Vec<GrantId>, OpError>;  // U0b row 8 body (no-op unwired)
pub async fn degrade_grants_under_ca(&self, &CaFingerprint, &AccessPair) -> Result<Vec<GrantId>, OpError>; // R7, for U10-A
// (crate) managed_instance_created / _installed / _destroyed (U2-Q1; gate retain / release_exclusive)
// heimdall_adapters::managed
pub trait EndCleanup { fn after_end<'a>(&'a self, &'a [GrantId]) -> Pin<Box<dyn Future<Output=Result<(),AdapterError>>+Send+'a>>; }
impl ManagedCertificateAdapter { pub fn with_cleanup(self, Arc<dyn EndCleanup>) -> Self; } // revoke(): destroy, then cleanup
// heimdall_runtime::managed_store
StoreSources::new(Arc<Store>, EnvironmentId)        // + set_lock_floor(LockBehavior), set_issuer(Arc<dyn IssuerPort>)
  impl ManagedSourceRead, GrantScopes (stored scope; records the terms), SlotStore
OpsInstallView::new(Operations)                     // impl heimdall_credential::table::InstallView
StoreCleanup::new(StoreSources, ManagedEffectsImpl, Option<Arc<ConnectionSupervisor>>) // impl EndCleanup
```
**For U10-D (`Service::start`):** one `StoreSources` (call `set_lock_floor(config floor)`, `set_issuer(child)`);
`ManagedEffectsImpl::new(table, registry, Arc::new(sources.clone()) /*GrantScopes*/, runtime_dir, SlotRoot{state_dir, env})
.with_slot_store(Arc::new(sources.clone()))`; **the same `ManagedEffectsImpl` clone** goes to the adapter
(`ManagedCertificateAdapter::new(.., Arc::new(sources.clone()), Some(effects.clone()), Some(layout)).with_cleanup(Arc::new(StoreCleanup::new(sources.clone(), effects.clone(), Some(supervisor.clone()))))`)
and to `ManagedWiring.effects` (its install record feeds `prepare_from`'s `valid_after` check); after `Operations::start`,
`table.set_install_view(Arc::new(OpsInstallView::new(ops.clone())))`. The supervisor calls `ops.managed_reissue_pass()`
at start (step 6), after the issuer returns to `ready`, and after an attended `ConfirmTime`; a store failure is an `Err`.
The expiry cleanup: the adapter's `revoke` is not called at expiry by M01; call `StoreCleanup::after_end(&expired)`
from the pass that expires grants (or ask me for an `Operations` hook).


## U10-D (runtime order, supervisor, dispatch, capabilities, classification): landed interfaces
(U10-D appends here.)

**D1. Runtime wiring (landed; `cargo check -p heimdall-runtime -p heimdall` 0).**
- `heimdall_runtime::service::ServiceOptions.managed: Option<ManagedOptions>` (production `Some(default)`,
  `with_clock` `None` = the M01/M02 runtime unchanged). `ManagedOptions { session_lock:
  SessionLockWiring::{Platform, Source(Arc<dyn SessionLockSource>), None}, lock_passes, issuer_command:
  Option<ChildCommand>, issuer_start_token: Option<StartToken>, script_pause_dir, test_key_seed (debug
  only), connection_client_args, connection_client_env }` (`..ManagedOptions::default()`).
- Start order (`Service::start_with`): `harden_process` → store/env/time gate → vault/table/late registry/
  effects/managed adapter (pushed after the configured + existing-access adapters' configured ones) →
  `Operations::start` (recovery, row 8) → floor `set_session_lock_floor(lock_floor(..))` (every runtime) →
  registry (`authority = ops`, `.with_verification_gates(ops.signing_gates().clone())`) → lock source +
  `floor_refusal` (warned; `Service::lock_floor_refusal()`) → `ops.set_managed_wiring(ManagedWiring {
  effects, issuer, issuer_lifecycle, verification_endpoints: registry, verification_runner: Verifier,
  target: LocalTargetEvaluator, connections: ManagedConnections })` → `connection_restart_pass` → issuer
  child start iff a CA is `active`/`pending` → `registry.start_environment()` (replaces M01's signing
  listener: one signer) → `ops.managed_reissue_pass()` → control endpoint → `instance.json`.
  `Service::start_steps()` lists them (`service::start_step::*`).
- Stop order (`Service::run`): stop accepting (token) → drain ops (bounded) → `ManagedConnections::shutdown`
  → `vault.destroy_all()` → issuer `stop()` → `registry.stop_all()` → lock source shutdown →
  `set_managed_wiring(default)`. A dropped service still zeroizes (Drop).
- Accessors (doc-hidden, tests): `Service::{vault, issuer, connections, endpoint_registry, start_steps,
  lock_floor_refusal}`.
- `wire_runtime_projection(store, config) -> Result<WiredProjection, StateDirMissing>` (U8-Q1, `writing`);
  the service fills a missing `state_dir` with its own; `ProjectionConfig.managed` = a store-backed
  `ManagedPairSource` (pair preference `managed_certificate` → environment endpoint + `managed_slot_paths(
  <state_dir>, dest)`, `ControlPath none`).
- `StoreSources` is built in `ManagedParts::build`; its trait impls are read through `service.rs`'s
  private `mod sources { read, scopes, slots, install_view }`, which today return the adapter crate's
  fail-closed defaults. **U10-C: when an impl lands, tell me (or edit only those four one-line bodies,
  e.g. `Arc::new(s.clone())`).**
- testcfg (`prepare`): `HEIMDALL_TEST_KEY_SEED` → `test_key_seed`, `HEIMDALL_TEST_SESSION_LOCK` →
  `FakeSessionLockSource::from_state_file` (re-read every 100 ms), `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` →
  `Verifier::with_test_pause_dir`; `HEIMDALL_TEST_SECRET_STORE=scratch`: the child's own selection.

**D2. Supervisor and connections.** `supervisor::ManagedConnections` (implements `ConnectionControl`,
emits `Connection` events): `restart_pass, deadline_pass, revocation_close, release_close,
time_uncertain_close, reap_pass, shutdown, close_request(&ConnectionId), register_request(..)`.
`Supervisor::{with_connections, with_session_lock, managed_pass(uncertain), connection_end_sweep() ->
ConnectionSweep, time_uncertain_close}`, `close_reason_for(GrantState)`, `SupervisorConfig.managed_interval`
(`DEFAULT_MANAGED_INTERVAL` 5 s). `managed_reissue_pass` = `ops.managed_reissue_pass()`.
**Dispatch**: `OperationsDispatcher::with_connections(Arc<ManagedConnections>)`; `Connections::Close` →
`{connection_id, kind, state: closed|unverified|closing}` (`NOT_FOUND` unknown); `Register` → U7
(`driver_unavailable` off Windows, `LAUNCH_FAILED connection_registration_refused` otherwise).

**D3. Capabilities, classification, preference.** `server_capabilities()` and `inspect capabilities`
offer `capability::M03_DECLARED`. `heimdall_sshconf::relevant::managed_identity_selection(eval,
identity_file, certificate_file: Option<&Path>, source)`; `observe` classifies a managed-certificate alias
by its slot (P-named `<state_dir>/managed/<dest>/…`) in the selected `ManagedIdentityForm`;
`report::MANAGED_SELECTION_CLASSIFIED = true`. `inspect destinations` items: `"preference": {"mechanism",
"projection"}` for a managed destination with a `pair_preferences` row.

## Requests (unit → unit / integrator)
(Append `- <from> → <to>: <what, exact text/signature>`; the owner answers inline.)
- U10-C → U10-A: the R7 degradation helper is `Operations::degrade_grants_under_ca(&CaFingerprint, &AccessPair) -> Result<Vec<GrantId>, OpError>` (narrowing protocol; `active → degraded pair_unenrolled`; nothing destroyed). Call it from the enrollment-removal driver after the removal commits.
- U10-C → integrator: (1) U10C-Q3: destroy K_env at narrowing.rs `UnderGates` (text in the questions file); (2) U10C-Q4 `NarrowingKind::Enrollment`; (3) heimdall `[dev-dependencies]` `heimdall-adapters`, `heimdall-credential` (and `async-trait`) would let `e2e_managed_m03` use the real adapter/signer (no package-set change); until then those cases are runtime unit tests in `managed_store.rs`. (4) I touched `operations.rs` beyond `revoke`/`release` only in the revoke path's `run_round`/`RoundAnswers` (carry `RevokeOutcome.remote_effects`) and the row-9 arm of `pin`.
- U10-D → U10-C (classification feed, D10 item 6; `MANAGED_SELECTION_CLASSIFIED` is now `true`):
  `crates/adapters/src/managed/prepare.rs` `outcome` still builds `ReportContext { selection:
  SelectionClass::Undetermined, .. }`. Please map the snapshot's observations instead: for every
  request pair, the `sources.observations` entry of its managed alias →
  `identity_selection.selection` (`Exclusive` → `SelectionClass::Exclusive`, `NotExclusive` →
  `NotExclusive`, anything else or no observation → `Undetermined`; the weakest over the pairs).
  The managed adapter's `read_sources` (your `ManagedSourceRead` over `StoreSources`) must then
  fill `IntegrationSnapshot.observations` through the projection writer's `observe` (as M02's
  `RuntimeSources::observe_aliases` does in `service.rs`). I construct `StoreSources` in
  `Service::start`; if you need the writer, add `StoreSources::with_observer(Arc<dyn
  ProjectionWriter>)` (or tell me the name) and I call it.
- U10-D → U10-C (exactly-once revoke-side close): the runtime wires `ManagedWiring.connections` with
  `heimdall_runtime::supervisor::ManagedConnections` (an emitting wrapper over U7's
  `ConnectionSupervisor`, implementing `ConnectionControl`). Every `close(c, reason)` through it emits
  one `Connection` event (`closed`, `reason`) per row actually closed, so the revoke/release side
  calls `close(c, CloseReason::Revocation | Release)` per open row of the cascade **once, after the
  gates are released**; do not emit the event yourself. The supervisor's post-tick sweep closes what
  a failed or missed call left open (the durable rows are the intent; D7 item 2) and emits only for
  rows it closes, so a row is never reported closed twice.
- U10-B → U10-A (owner of the enrollment authorization facts; or integrator if `verification_m03.rs`
  is nobody's): `verification_m03::verification_check_read_only` finds the enrollment only from a stored
  `EnrollmentRequest::Verify { enrollment_id, .. }`, and `operation_facts` authorizes only `verify`
  presence/absence. When you make `enrollment.apply` (its `EnrollAccount` basis) and target-change
  verify reservable, extend **both** (the enrollment lookup for an apply operation too), because the
  verification signing admission (U10-B) re-runs exactly `verification_check_read_only` on the
  published positive entry; otherwise E4 of an apply reserves but can never sign.
- U10-B → integrator (observed, not my files): `integration_issuer_child` (most tests) and
  `model_issuer_linearization` (5) now fail at their fixture `ensure` with `UNSUPPORTED_CLIENT
  "the credential adapter dependency spoke an unsupported protocol"`: their `FakeCredentialAdapter`
  uses mechanism `managed_certificate`, and the new ensure hook runs `managed_prepared` for it with
  no `ManagedWiring` (driver not wired → `AdapterError::Protocol`). A phase-1 fixture flip
  (wire the fixtures, or give them a non-managed mechanism); `tests/integration/issuer_child.rs:330`,
  `tests/model/issuer_linearization.rs:~520`.
- U10-B → U10-D: build the runtime `EndpointRegistry` with
  `.with_verification_gates(ops.signing_gates().clone())` (B1), and hand it to
  `ManagedWiring.verification_endpoints`. For `issuer_lifecycle` use the `ChildIssuer` itself
  (it implements `app::issuer::IssuerLifecycle`, see B3 when landed).
- U10-D → U10-B: (1) `issuer_crash_blocks_reissue_not_signing` (m03-plan U10 runtime tests): **you
  write it** (it needs your `issuer_supervision_pass` degrade/restore and the signer side); I land the
  runtime wiring it runs on (`ServiceOptions.managed`, `ManagedOptions.issuer_command` /
  `issuer_start_token` for a test child, `Service::issuer()`). Tell me here if you want it the other
  way. (2) Ack on B3: until it lands I wire `issuer_lifecycle` through a runtime newtype
  (`service.rs` `ChildLifecycle(ChildIssuer)`: start/reload/stop delegate); once `ChildIssuer:
  IssuerLifecycle` compiles I switch to the client itself. (3) Done: the registry is built
  `.with_verification_gates(ops.signing_gates().clone())` and is `ManagedWiring.verification_endpoints`.
- U10-D → U10-A: `EnrollmentHost` runtime impl — ack; I implement it in `crates/runtime/src/service.rs`
  over the wired projection (client path/version from the client inventory, `paths(tag)` under
  `<runtime_dir>/e/<tag>/`, `identity_agent` from the static evaluation with P excluded,
  `heimdall_endpoints` = control + environment + `<runtime_dir>`) **after** the start/stop order
  lands, and call `ops.set_enrollment_host(..)` in `Service::start`. Until then the host is unset
  (your fail-closed `driver_unavailable`). If you add `ManagedWiring.enrollment_host` instead, say
  so here and I fill that field.
- U10-A → integrator (verification_m03.rs is in nobody's R2 list; please apply, or authorize me to):
  in `operation_facts`, replace the `authorized` match with
  `super::enrollment_m03::verification_authority(tx, &op)?` (`Some((e, auth))` ⇒ `authorized = auth && e ==
  *enrollment`, `None` ⇒ false), and let `at_verification_stage` accept `op.state ∈ {Running,
  OutcomeUnknown}` (an apply reconciled after an uncertain append verifies while `outcome_unknown`;
  M01's lifecycle has no `outcome_unknown → running`) and the record state `RemovalVerifying` beside
  `Verifying | Reverifying` (the system form's absence check: an `enrollment.verify` mode `absence`
  whose record is `removal_verifying`, D5 §6.9). In `verification_check_read_only`, find the
  enrollment the same way (`verification_authority(tx, &op)` on `tx.operation(&entry.operation)`), not
  only from a stored `Verify` request. Until then E4 of an `enrollment.apply` and a target change
  reserve nothing (`operation_not_verifying`) and end inconclusive — fail closed. (Answers U10-B's
  request above.)
- U10-A → integrator: `ManagedWiring.enrollment_host: Option<Arc<dyn crate::enrollment::EnrollmentHost>>`
  (then I read it there and drop the environment-keyed setter). Optional; the setter works now.
- U10-A → integrator: `inspect enrollments` (`InspectSubject::Enrollments`) can answer
  `enrollment_m03::enrollments_view_in(tx)`.
- U10-A → integrator: `tests/model/operations_m03.rs` (cancel of an enrollment op before the
  `Attempted` receipt expects `driver_unavailable`) is a phase-1 assertion; with the driver the cancel
  before E3 is allowed (U10-A opens it in `enrollment_cancel_m03.rs`), so that assertion flips.
- U10-A → integrator (`operations.rs` `cancel`, ~9381): replace
  `return enrollment_cancel_m03::refusal(tx, &op).map(|e| Some(Err(e)));` with
  `return enrollment_cancel_m03::cancel_in(tx, emit, op, now, retention).map(Some);` (same `Cancelled`
  type as `cancel_local_in`). It refuses `remote_step_in_progress` exactly as before once an
  `Attempted` remote-mutation receipt exists; before that it cancels (planned → withdrawn, applying →
  failed_unwritten, the pending decision withdrawn).
- U10-A → U10-D: ack on `EnrollmentHost`; `effective_config` must run the step's client with exactly
  `heimdall_registry::step::effective_config_args(step)` (or `SshStepRunner::effective_config`), no
  user `-F`; `endpoint_valid` = `LocalTargetEvaluator::check_endpoint` present + owned + resolved not
  under `heimdall_endpoints()`. Supervisor: call `reverify_pass()` and `enrollment_step_timeout_pass()`
  each tick (both return `Ok` with nothing to do when unwired).
- U10-D → U10-A (phase-2 fail-closed finding, `integration_runtime_m03`): on an **unwired** runtime
  (`World` in `tests/integration/runtime_m03.rs`: no `set_managed_wiring`, no enrollment host),
  `Enrollment::Abandon` for an unknown enrollment answers `NOT_FOUND` but **writes first**: the meta rows
  `high_water_mark` and `runtime_anchor` appear (a persisting `TimeGate::check` before the lookup). R4:
  refuse before any write. Please read with the gate's `peek` (or check the record/wiring first) on
  that path; `w0_m03_requests_fail_closed_before_any_record` and `capabilities_offered_after_activation`
  fail on it now (`assertion ... nothing was written`). Every other M03 request writes nothing there.
  - U10-A: fixed — `Abandon`, `Step` and `StepResult` now check the ports first (`driver_unavailable`
    before any time read); every enrollment action on an unwired runtime refuses before any write.
- U10-D → U10-A (clippy, blocks every `-D warnings` run and `linux-xcheck.sh -p heimdall-runtime`):
  `cargo clippy -p heimdall-runtime -- -D warnings` fails only in your files: `enrollment_m03/steps.rs:1820`
  (collapsible_if), `enrollment_m03.rs:455` and `verify.rs:185,217` (needless_borrows_for_generic_args),
  `enrollment_m03.rs:575` (collapsible_match), `enrollment_m03.rs:883` and `verify.rs:303` (clone_on_copy),
  and `tests/e2e/enroll_m03.rs:646` (a warning).
- U10-D → U10-C (wired; answer to "For U10-D"): done as you described, with two late bindings because of
  the construction cycle: the install view is `OpsInstallView` behind a runtime `LateInstallView` (set right
  after `Operations::start`, cleared at stop; refuses `store_view_unavailable` meanwhile), and the adapter's
  `with_cleanup` is a runtime `LateCleanup` holding `StoreCleanup::new(sources, effects, Some(supervisor))`
  (set once the supervisor exists). `LateCleanup::after_end` first closes the grants' rows through
  `ManagedConnections::close_ended` (so the `Connection` events are emitted with the reason), then runs
  your `StoreCleanup` (whose own connection pass then finds them closed). `set_lock_floor(lock_floor(..))`
  and `set_issuer(child)` are called. **Open:** the expiry cleanup ("call `StoreCleanup::after_end(&expired)`
  from the pass that expires grants"): the supervisor's sweep sees only ended grants with open owned
  connection rows; it cannot enumerate held slots of ended grants (no store query lists slots). Please add
  either the `Operations` hook you offered (e.g. `Operations::ended_managed_grants() -> Vec<GrantId>` for
  grants that ended since the last call, or a store `Txn::held_slots(&EnvironmentId)`), and I call the
  cleanup from the scheduler pass.

## 0b. Added before the units started (integrator, second batch)
- `crates/runtime/src/managed_store.rs`: `pub struct StoreSources { store, environment }`,
  `StoreSources::new(Arc<Store>, EnvironmentId)` (U10-C fills the trait impls; U10-D constructs it in
  `Service::start` and hands it to the adapter, the effects and the signer table).
- `[[test]] integration_issuer_m03` (`tests/integration/issuer_m03.rs`, host `heimdall-runtime`),
  placeholder `target_is_wired` (U10-B replaces it).
- `heimdall` production dep testkit features `["app", "managed"]` (U3-Q4). `Cargo.lock` unchanged.
- **Target signature for INT-Q13 (U10-B lands it; U10-A builds to it):**
  `VerificationEndpoints::create(&self, operation: &OperationId, plan: &EnrollmentPlan)
  -> Result<Box<dyn VerificationSession>, AdapterError>` (ADR-0008 §17.19 item 5: "the verification
  factory receives the plan"; `install` then checks each certificate against the plan's CA and, for
  the positive one, the plan's pair).

## 0c. Who constructs what in the runtime (U10-D wires; others provide)
`Service::start` (U10-D) builds, in the binding start order (m03-plan U10, plus `harden_process`
first and the session-lock floor/source): `KeyVault` (`with_test_seed` only under
`cfg(debug_assertions)` from `HEIMDALL_TEST_KEY_SEED`), `SignerTable` (+ the store `InstallView` from
`StoreSources`, U10-C), `EndpointRegistry` (U2; authority = the `Operations`), `ManagedEffectsImpl`
(U6; `BindingEndpoints` = the registry, `GrantScopes`/`SlotStore` = `StoreSources`),
`ManagedCertificateAdapter` (U6; sources = `StoreSources`), `ChildIssuer` (U3; lifecycle through
`app::issuer::IssuerLifecycle`, U10-B implements it for `ChildIssuer`), `Verifier` (U5), the target
evaluator (`heimdall-localenv`), one `ConnectionSupervisor` (U7); then
`ops.set_managed_wiring(ManagedWiring { .. })`.
