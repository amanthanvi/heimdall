# M03 wave 4, round 2: ownership map, readings and landed interfaces (untracked; integrator + workers)

Round 1 is committed at `d74e35cf` (`feat/m03-wave4-activation`). The round-1 notes are archived in
`tests/evidence/artifacts/review-m03-code/wave4-notes/` — **the common brief there
(`m03-wave4-brief.md`) applies unchanged**, and `m03-wave4-api.md` there lists every round-1 interface.
The work list is **ADR-0008 §17.21** (uncommitted in this worktree: never edit the ADR).

## 0. Ownership (round 2)

| Worker | §17.21 items | Owner files (only these, plus their tests) |
|---|---|---|
| **R2-A enrollment** | 4 (journal minimized), 5 (verification authorities, own predicates), 11's enrollment plan tests: the four fence/terminate tests, `enroll_remove_lists_affected_grants_and_degrades_them`, `target_change_pass_replaces_approved_target_atomically`, `target_change_failure_or_inconclusive_keeps_approved_target_and_held`, `held_host_key_change_needs_target_reapproval_with_key_diff`, `held_removal_with_freshly_evaluated_target`, both `initial_verification_*`, `e5_rotation_keeps_projection_and_adds_issuing_ca`, `rotation_two_accounts_one_unreachable`, the host-key half of `evidence_invalidated_on_host_key_or_client_change`, the abandon path of `foreign_removal_held_recovery_by_new_decision_or_abandon`; `enroll_reconcile_applied` expects `verified` | `crates/app/src/enrollment.rs`, `crates/app/src/operations/enrollment_m03.rs` + `enrollment_m03/**`, `enrollment_cancel_m03.rs`, `crates/app/src/operations/verification_m03.rs`, `crates/domain/src/verification.rs`, `crates/enroll/**`, `crates/registry/**` (only where needed), `tests/e2e/enroll_m03.rs` |
| **R2-B issuer** | 3 (RegisterIssuer `ca_public_key` + `backup_created_at`; `IssuerRecord.store_locator`; retirement deletes exactly it; `issuer_store_locator_unrecorded`) | `crates/app/src/issuer.rs`, `crates/app/src/operations/issuer_m03.rs`, `crates/domain/src/decision.rs` (RegisterIssuer fields only), the decision golden/contract tests that cover it, `crates/store/src/ext_m03.rs` (only `IssuerRecord` + its issuer methods), `crates/issuer/**`, `crates/app/src/operations/restart_m03.rs` (only `resume_ca_retirements`'s store-deletion step), `crates/heimdall/src/m03_cmd.rs`, `tests/integration/issuer_m03.rs`, issuer/store tests touching these |
| **R2-C managed binding** | 1 (binding ID minted at resolve, step-6 materialize, endpoint named, cleanup intent, replay, M02 byte-identity, the crash regression), 2 (slots claimed in `BindForm::Launch`; `run_cmd::ManagedSlots` reads the outcome), 7 (`Txn::credential_instances_for_grant`) | `crates/domain/src/operation.rs` (`ResolvedIntent` additive field only), in `crates/app/src/operations.rs` **only** resolve's managed branch, `stage_commit`, the bind (`BindForm::Launch`) path, the cleanup-intent handling of a managed preparation; `crates/app/src/managed/driver.rs`, `crates/app/src/operations/managed_driver_m03.rs` (except D's re-issue eligibility region), `crates/adapters/src/managed/{effects,mod,files}.rs`, `crates/adapters/src/managed/prepare.rs` (the endpoint naming only; D owns its selection feed), `crates/credential/src/{endpoints,table}.rs` (binding creation/attach only), `crates/store/src/ext.rs` (only the new `credential_instances_for_grant`), `crates/runtime/src/managed_store.rs`, `crates/heimdall/src/run_cmd.rs` (`ManagedSlots` only), contract additive bind-reply field only if needed, `tests/e2e/managed_m03.rs`, `tests/integration/managed_adapter.rs` |
| **R2-D runtime** | 6 (one `reissue::eligible` in a shared crate), 8 (`Txn::{windows_pipe_token, set_windows_pipe_token}` + restart regression), 9 (mux path in P when owned masters are enabled and applied), 11: selection feed into the managed report, slot cleanup for ended grants (store query + supervisor pass), `inspect connections` read-only | `crates/runtime/src/{service,supervisor,dispatch,lib}.rs`, `crates/adapters/src/managed/reissue.rs` (move) and `prepare.rs` (selection feed only), the shared crate's new module (e.g. `crates/domain/src/reissue.rs`), in `managed_driver_m03.rs` **only** the re-issue eligibility code, `crates/store/src/{lib.rs or ext_m03.rs}` (only the new pipe-token and held-slot queries), in `operations.rs` **only** the `InspectSubject::Connections` arm, `tests/integration/runtime_m03.rs`, `tests/integration/projection_managed.rs` |

Phase 2 (after A–D): **R2-E** (integrator or one worker) writes the cross-cutting end-to-end tests that need
every piece: `enroll_preview_apply_verify_setup_apply_ensure_ssh`'s `ensure` and `ssh` legs, both
`a10_narrow_certificate_refused_on_other_host_*`, and `issuer_crash_blocks_reissue_not_signing`.

## 1. Readings
- Round-1 readings R1–R10 (archived api file) hold. In particular: store-touching driver code lives in
  child modules of `operations`; nothing reopens `VERIFICATION_UNGATED_SIGNING` (stays `false`) or the
  release-build `HEIMDALL_TEST_*` refusal.
- §17.21 authorizes: `ResolvedIntent.binding_id` (serde default, omitted when absent); an additive bind
  reply field if needed; `DecisionKind::RegisterIssuer.{ca_public_key, backup_created_at}`;
  `IssuerRecord.store_locator` in `record_json`; `Txn::credential_instances_for_grant`,
  `Txn::{windows_pipe_token, set_windows_pipe_token}`, the held-slots query — all without migrations.
  Anything else in `crates/contract/**`, migrations, `Cargo.lock`'s package set, pins, new deps, new
  `unsafe`: escalate (`.m03-wave4-r2-questions.md`).
- **M01/M02 byte-identity:** every existing-access ensure, intent and request hash stays exactly as now.
- Each new regression is shown failing with its fix reverted (worklog), real exit codes only.
- Worklogs: `.m03-wave4-r2-worklog-<A|B|C|D>.md`. Questions: `.m03-wave4-r2-questions.md` (your heading).

## R2-A landed
- **§17.21 item 4 (journal minimized).** `crate::enrollment::InspectFact` no longer holds the HM1
  stdout: `{ registry: Option<RegistryDigest { len, sha256 }>, reading: StoredReading, exit_status,
  read_continuous_ms, read_wall, boot_id, remote_now, consumed }`. `StoredReading::of(&Inspection,
  marker)` keeps the registry's metadata, the lock, and **only the lines containing the marker**
  (`marker_entries_hex`); `InspectFact::inspection()` rebuilds that minimized reading.
  `IssuedStep.{preimage, post_image}` are `RegistryDigest`s (were `*_hex` bytes). A removal's
  post-image needs the bytes: they stay in this `Operations`' memory only
  (`EnrollmentProcessState::{remember_inspected, inspected}`, 16 operations, digest-checked), and
  without them (a restart) the removal inspects again. Registry (pure): `post_image::ImageDigest`,
  `check_post_append_digest`, `check_post_remove_digest`; `classify::Expected.{preimage_digest,
  post_image_digest}` (used when the byte fields are `None`; `Expected` literals take
  `..Expected::default()`); `Inspection::{preimage_digest, without_foreign_lines}`.
- **§17.21 item 5.** `enrollment_m03::verification_authority(tx, &op) ->
  Option<VerificationAuthority { enrollment, kind: VerificationKind, authorized, at_stage }>`: one
  predicate per kind (Presence = wave 0's stored-request rule; SystemAbsence; ApplyInitial;
  TargetChange), table in its docs. Authorization is the **decision record** (approved, naming this
  operation, and for a target change this enrollment, the record's approved target and the journal's
  proposed target), never the journal's word alone; the stage is the operation's state, the record's
  state (and form), the receipts (apply: an `enroll.append` `Confirmed` with the marker; nothing
  outstanding/uncertain), and **no other open enrollment operation of the record** (the system form's
  manual `enrollment.remove` excepted for the absence check). `verification_m03::operation_facts` and
  `verification_check_read_only` use only it (the stored-request helpers there are gone).
- Driver fixes found by the tests: `fence` now fences the **uncertain step's** lock token (it used the
  fence step's own token, so every real fence answered `busy` exit 40); a reconcile `Applied` and a
  manual-recovery "line present" write the `enroll.append` `Confirmed` receipt (D5 §6.7); `enroll
  verify` from `applied_unverified` ends the lapsed `enrollment.apply` (`DECISION_STALE`,
  `approval_lapsed`) instead of leaving it open beside the verification; the re-verification pass
  re-verifies a verified pair at once on a host-key change (R2A-Q1, switch
  `HOST_KEY_CHANGE_PROMPT_REVERIFY`).
## R2-B landed
- `DecisionKind::RegisterIssuer` gains `ca_public_key: Option<String>`, `backup_created_at:
  Option<Timestamp>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`; an old record
  decodes `None` and re-encodes byte-identically). `issuer.register` writes both; approval reads them
  from the record (`issuer_m03::recorded_registration`); `None` or a key not matching the fingerprint
  is `DECISION_STALE` in the precheck (nothing written, not consumed). The join of a pending record
  requires the same key and time. `IssuerProcessState` is now empty (no map) and `DecideCtx {}` is
  empty (`m03_decide_ctx` reads `managed_ops.issuer` once so it is not dead; see Requests).
- Store (`ext_m03.rs`, no migration): `Txn::issuer_store_locator(&CaFingerprint) ->
  Result<Option<String>>`, `Txn::set_issuer_store_locator(&CaFingerprint, &str) -> Result<()>` (set
  once while `pending`/`active`; same value no-op; another value / retirement begun =
  `GenerationConflict`; missing CA = no-rows; 1..4096 bytes, no control chars). Kept in
  `issuers.record_json` key `store_locator`, **not** an `IssuerRecord` field (every `IssuerRecord {..}`
  literal stays valid); `set_issuer_state` preserves it.
- `Operations::record_issuer_store_locator(&CaFingerprint, &str) -> Result<(), OpError>` (pub): the
  sink for the K_ca put report (NOT_FOUND / CONFIG_CONFLICT / USAGE_ERROR). No production caller yet
  (R2B-Q1).
- `app::operations::CaStoreItemDeletion` gains `fn delete_recorded(&self, ca, store: StoreKind,
  locator: &str) -> Result<(), IssuerError>` (default: refuse). `delete_confirmed_absent` is now
  defaulted to a refusal and **never called** (kept so existing impls compile; remove later).
  `resume_ca_retirements`' `unloaded` step reads the recorded locator first: none → stalled
  `issuer_store_locator_unrecorded` (new `reason::M03` entry, `CAPABILITY_UNAVAILABLE`, golden
  updated), port not called; else `delete_recorded(ca, store_kind, &locator)`.
- `app::issuer::IssuerLifecycle::store_item_deletion(&self) -> Option<Arc<dyn CaStoreItemDeletion>>`
  (default `None`; `ChildIssuer` keeps the default). The supervision pass and the `RetireIssuer`
  after-decision pass it to `resume_ca_retirements` (R2B-Q2).
- `heimdall_issuer::retire::StoreItemDeletion<S>::new(store: S)` (S: `Deref<Target: SecretStore>`;
  was `new(&dyn SecretStore, &dyn RecordedItems)`); implements `delete_recorded` (product-kind check,
  then `retire::delete_recorded` of exactly that locator + absence re-read). `retire::delete_recorded`
  is now generic over `S: SecretStore + ?Sized`.
## R2-C landed
**§17.21 items 1, 2, 7 (R2-C).**
```rust
// heimdall_domain::operation::ResolvedIntent  (additive; serde default, omitted when None)
pub binding_id: Option<BindingId>,   // minted at resolve iff the pinned adapter is managed_certificate
// heimdall_store::Txn
pub fn credential_instances_for_grant(&mut self, &GrantId) -> Result<Vec<CredentialInstance>>; // any state, by id
// heimdall_app::managed::driver
pub const BINDING_GENERATION: u64 = 1;  pub mod stage { …, MATERIALIZE = "managed.materialize", … }
// heimdall_adapters::managed::effects::BindingEndpoints (adapters-local, not a port; defaults fail closed)
fn create_binding_endpoint(&self, &BindingId, generation: u64) -> Result<EndpointRef, AdapterError>; // default: Unavailable(binding_endpoint_unavailable)
fn remove_binding_endpoint(&self, &BindingId, generation: u64) -> Result<bool, AdapterError>;        // default: Ok(false)
//   impl for EndpointRegistry: create_binding (idempotent at the generation) / remove (generation-bound)
// ManagedEffectsImpl
//   materialize(b, spec): endpoint created when none runs → files → THEN attach_binding(b, grant of spec.public_key)
//   materialize(b, slots-only spec {public_key: "", certificates: [], environment_slots: true}): the slots of a
//     binding this instance materialized, from the recorded content (BINDING_NOT_MATERIALIZED otherwise)
//   clear(b, g): endpoint of g removed, detach when none left, files of g removed
pub fn clear_bindings_of(&self, &[GrantId]) -> Result<(), AdapterError>;  // called by the managed adapter's revoke
pub fn materialized_bindings(&self, &GrantId) -> Vec<BindingId>;
```
- **Pipeline.** Resolve mints the ID (`stage_resolve` → `managed_driver_m03::with_managed_binding`); the driver
  reads it from the operation whose `Attempted` receipt carries the token (`Operations::managed_binding_of_token`;
  `PrepareRequest` unchanged), step 6 `materialize`s at generation 1 (receipt `managed.materialize`),
  `prepare_from` names the endpoint (unchanged code), the commit inserts the binding under the minted ID and the
  ensure result carries this drive's `consumer.signing_endpoint`.
- **Cleanup before the commit.** Driver failure: `abandon` clears the binding + destroys the key. `prepare_from`
  failure after the driver, and a managed commit after a restart (reconcile not `Applied`): the operation fails
  with a cleanup intent (`fail_managed_preparation`, `settle_effect_in`); processing it (`process_cleanup_intent`
  → `cleanup_uncommitted_managed`) destroys keys + live instances (gate released) and clears the uncommitted
  binding through `ManagedEffects::clear` (files found on disk by marker). **After a restart the clear needs the
  effects wired**: the intent is kept by recovery (wiring is set after `Operations::start`) and completed by the
  next `process_cleanup_intents()` (the supervisor's revocation pass).
- **Bind (item 2).** `drive_bind`, `BindForm::Launch` of a `managed_certificate` binding: pass 1 checks every
  pair's slot (held by another / clearing → `CONFIG_CONFLICT managed_slot_held`, next `release_binding`, nothing
  else written) and CAS-claims them (op stays `running`); then `ManagedEffects::materialize` slots-only (files at
  each slot's store generation, then the environment listing); pass 2 settles exactly as before (holder,
  connection, result). An effect failure fails the bind `SERVICE_UNAVAILABLE` (partial; the claim stays until the
  binding/grant ends). M01/M02 binds: one pass, unchanged. No contract field. `run_cmd::ManagedSlots` is now a
  reader (`BoundSlots::of(&bind_reply)`); `require_slots` claims nothing.
- **For phase 2 (a real managed binding with a live endpoint).** Pattern: `crates/runtime/src/managed_store.rs`
  `live_tests` (`Live::process`): real `StoreSources`, `ManagedEffectsImpl` over a late `EndpointRegistry`
  (`BindingEndpoints` forwarding all three methods), `ManagedCertificateAdapter::with_cleanup(StoreCleanup)`,
  `OpsInstallView`, `ManagedWiring { effects, issuer }`; seed: managed destination (`DestinationDefinition::Managed`
  with an adopted identity), verified enrollment, issuer row, pair preference `managed_certificate` applied with
  `issuing_cas`. `ensure` must be **interactive** until R2C-Q1. In the **production runtime** the endpoint is
  created only once R2-D's `service.rs` `LateRegistry` forwards the two new `BindingEndpoints` methods (Requests).
- Shared-file edits (operations.rs): `pin` literals + `stage_resolve` minting; the prepare step's
  `catalog_mechanism` check skipped for the managed adapter (U0b row 9: the stored preference decides; the catalog
  identity is the pair's existing access) and its `Err` arm → `fail_managed_preparation` for a managed
  preparation; `stage_commit` (minted ID, signing endpoint, managed reconcile arm); `process_cleanup_intent` (one
  call); `drive_bind` (split into passes). Mechanical `binding_id: None` in `tests/integration/store.rs`,
  `tests/model/operations.rs`, `crates/store/src/lib.rs` (test literals of the full struct).
## R2-D landed
- **§17.21 item 6:** `heimdall_domain::reissue` = the one pure rule (`eligible`, `same_grant`,
  `GrantSource`, `StoreRead`, `ReissueRefusal`, `ReissuePlan`, `MANAGED_CERTIFICATE`);
  `heimdall_adapters::managed::reissue` re-exports it (`pub use heimdall_domain::reissue::*`). `app`'s
  `reissue_eligible` (managed_driver_m03.rs) reads the inputs in one txn and calls it; the copy and the
  pass's separate `lock_blocks_reissue` call are gone. No new crate edge.
- **item 8:** `Txn::windows_pipe_token() -> Result<Option<String>>`, `Txn::set_windows_pipe_token(&str)
  -> Result<()>` (meta `windows_environment_pipe_token`; set-once; 1..64 ASCII alnum). `Service::start`
  reads/creates it once (every host, managed wiring only) and names the managed `EndpointLayout::windows`
  with it; the control endpoint keeps M01's per-start token.
- **item 9:** `service.rs` `StorePairSource` renders `checked_mux_path(<runtime_dir>, dest)` iff
  `pair_masters_enabled` (R2D-Q1), not on Windows, path fits; else `ControlPath none`.
- **item 11:** `ManagedSourceRead::observations` (default empty), `prepare::selection_class`,
  `prepare::snapshot` fills observations, `outcome` feeds `ReportContext.selection`; runtime
  `sources::Observing` wraps `StoreSources`. `Txn::held_slots_of_ended_grants(&EnvironmentId) ->
  Result<Vec<(GrantId, ManagedSlot)>>`, `Txn::owned_connections() -> Result<Vec<OwnedConnection>>`.
  `Supervisor::with_end_cleanup(Arc<dyn EndCleanup>)`, `Supervisor::ended_slot_pass() ->
  Result<Vec<GrantId>, OpError>` (after each tick's sweep and in each `managed_pass`; the service wires
  the late `StoreCleanup`). `inspect connections` answers `ConnectionsView` (owner only).
## Requests
- R2-C → R2-D (`crates/runtime/src/service.rs`, `impl heimdall_adapters::managed::effects::BindingEndpoints for
  LateRegistry`): forward the two new methods, or production never creates a binding endpoint (materialize then
  fails `binding_endpoint_unavailable` and every managed ensure fails closed):
  ```rust
  fn create_binding_endpoint(&self, binding: &heimdall_contract::ids::BindingId, generation: u64)
      -> Result<EndpointRef, heimdall_app::ports::AdapterError> {
      self.get().ok_or_else(|| heimdall_app::ports::AdapterError::Unavailable(
              heimdall_adapters::managed::effects::BINDING_ENDPOINT_UNAVAILABLE.to_owned()))?
          .create_binding_endpoint(binding, generation)
  }
  fn remove_binding_endpoint(&self, binding: &heimdall_contract::ids::BindingId, generation: u64)
      -> Result<bool, heimdall_app::ports::AdapterError> {
      match self.get() { Some(r) => r.remove_binding_endpoint(binding, generation), None => Ok(false) }
  }
  ```
  (`r` is an `EndpointRegistry`; the trait must be in scope: `use heimdall_adapters::managed::effects::BindingEndpoints as _;`.)
- R2-C → integrator: R2C-Q1 (non-interactive managed ensure refused at the commit by M02 eligibility; two guards
  proposed) and R2C-Q2 (bind result names no binding endpoint → `connect` fails closed) block phase 2's
  `--non-interactive` ensure and `connect`/`ssh` legs respectively.
- R2-D → R2-C (§17.21 item 11, selection feed) — **FYI, no action needed**: I added the defaulted
  `ManagedSourceRead::observations(&self, aliases: &[String]) -> Vec<AliasObservation>` (empty) in
  `prepare.rs`; `prepare::snapshot` fills `IntegrationSnapshot.observations` from it and `outcome`
  passes `prepare::selection_class(req.pairs, &sources.observations)` as `ReportContext.selection`.
  The runtime wraps your `StoreSources` in `service.rs` (`sources::Observing`, delegating every other
  method) so `managed_store.rs` needs no change. If you add a method to `ManagedSourceRead`, tell me
  and I add its delegation there (otherwise the wrapper silently uses the trait default).
- R2-D → R2-C (slot cleanup for ended grants): my supervisor pass finds held/clearing slots of ended
  grants by the slot row's binding (`managed_slots.binding_id → bindings.grant_id`) and runs your
  `StoreCleanup::after_end(&[grant])`. `StoreCleanup::bindings_and_slots` finds bindings only through
  `grant_references` + owned connections, and `release_binding` deletes the reference, so a
  **released** binding's held slot is never found by it. Please also take the grant's slot rows by binding
  (I add `Txn::held_slots_of_ended_grants(&EnvironmentId) -> Result<Vec<(GrantId, ManagedSlot)>>`; or
  read `slots_for_binding` for every binding of the grant). Until then an expired grant whose binding
  still references it is cleared; a released one is retried each pass without effect (logged).
- R2-B → R2-D (`tests/integration/runtime_m03.rs`, your file; it **does not compile** since
  `RegisterIssuer` gained two fields): (1) line ~639 `DecisionKind::RegisterIssuer {..}` add
  `ca_public_key: None, backup_created_at: None,`. (2) `retirement_resumes_at_start_from_each_state`
  will then fail its "fakes confirm each step" half, as §17.21 item 3 requires (a CA with no recorded
  locator stops at `unloaded`, `issuer_store_locator_unrecorded`): in `seed_ca` add
  `tx.set_issuer_store_locator(&fp, &format!("fixture-locator-{n}"))?;` right after
  `tx.insert_issuer(&r)?;`, and in `impl CaStoreItemDeletion for FakeStoreItems` rename
  `fn delete_confirmed_absent(&self, _ca, _store)` to `fn delete_recorded(&self, _ca: &CaFingerprint,
  _store: StoreKind, _locator: &str)` (the old method is no longer called). The production-wiring half
  is unchanged (`unloaded` stalls, now `issuer_store_unavailable` with a locator and no port).
  - R2-D: done (both, exactly as asked); `integration_runtime_m03` 36/36 (exit 0).
- R2-B → integrator (`crates/app/src/operations/managed_state_m03.rs`, `operations.rs`): the field
  `ManagedOpsState.issuer` and `issuer_m03::IssuerProcessState` now hold nothing; please remove the
  field, then I (or you) drop the type and the one-line read in `decisions_m03::m03_decide_ctx`.
  `DecideCtx` is empty; you may remove it and its two `&m03_ctx` arguments in `Operations::decide`.
- R2-B → integrator: the m03-plan §5 item 14 reason table does not list
  `issuer_store_locator_unrecorded` (golden "source" says it transcribes that table); registered under
  §17.21 item 3's authorization. Plan text is not mine to edit.

