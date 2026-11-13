# M03 wave 4, round 3: ownership map and readings (untracked; integrator + workers)

Round 2 is committed at `e566cc46`. Work list: **ADR-0008 §17.22** (uncommitted; never edit it), from the
reviews `tests/evidence/artifacts/review-m03-code/wave4.md` (W4-R01..R09) and `wave4-security.md`
(W4-S01..S03) — read your findings there in full (scenario, location, required correction). The common
brief `tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-brief.md` applies unchanged; the
round-1/2 interfaces are in `wave4-notes/m03-wave4-api.md` and `m03-wave4-r2-api.md`.
Native at `e566cc46`: devbox 14 binaries / 631 passed / 0 failed; Windows pending.

## 0. Ownership (round 3)

| Worker | §17.22 items | Owner regions (only these, plus their tests) |
|---|---|---|
| **R3-A enrollment + evidence** | 1 (W4-S01), 2 (W4-S02), 7 (W4-R04 + R2A-Q1) | `crates/app/src/operations/enrollment_m03.rs` + `enrollment_m03/**`, `crates/app/src/enrollment.rs`, `crates/registry/**`, `crates/app/src/operations/verification_m03.rs`; for item 7 also `crates/adapters/src/managed/prepare.rs` (`pair_evidence` and evidence selection only) and `report.rs` (evidence/scope only), the `mod sources` block of `crates/runtime/src/service.rs` (the managed read sources' evaluation feed only); tests `tests/e2e/enroll_m03.rs`, `tests/integration/managed_adapter.rs` (evidence cases) |
| **R3-B issuer** | 12 (R2B-Q1/Q2), 15 (verify only) | `crates/app/src/issuer.rs`, `crates/app/src/operations/issuer_m03.rs`, `restart_m03.rs` (retirement only), `crates/contract/src/issuer.rs` (additive `store_locator` on `issuer.register`, retire confirmation; authorized), schema/golden updates they need, `crates/store/src/ext_m03.rs` (issuer methods only), `crates/issuer/**`, `crates/heimdall/src/m03_cmd.rs`; tests `tests/integration/issuer_m03.rs`, issuer/store/contract tests touching these |
| **R3-C1 managed cleanup** | 4 (W4-R01), 9 (W4-R07), 10 (W4-R08) | in `operations.rs` only `expire_grant`/expiry-at-use and the release path (`release_checked` and the reference accounting it calls); in `managed_driver_m03.rs` only the cleanup-after-end functions (`after_release_m03`, `managed_after_narrowing`, new expiry cleanup); `crates/runtime/src/managed_store.rs` `StoreCleanup` (not `StoreSources`, not `live_tests` helpers C2 needs); `crates/runtime/src/supervisor.rs` (ended-grant / cleanup passes); `crates/store/src/ext_m03.rs` (new slot/cleanup queries only); tests `tests/integration/runtime_m03.rs` (new module), runtime lib tests |
| **R3-C2 managed pipeline** | 5 (W4-R02), 6 (W4-R03), 8 (W4-R05/R06) | `crates/app/src/managed/driver.rs`; in `managed_driver_m03.rs` the driver-side functions (`managed_prepared`, `run_effect_driver`, `fail_managed_preparation`, `cleanup_uncommitted_managed`, the re-issue pass and its stages); in `operations.rs` the prepare step's managed arms, `stage_commit`, the coalescing/join path, `stage_reconcile`/recovery of a managed preparation, the managed cleanup-intent handling; `crates/adapters/src/managed/{effects,mod,files}.rs`; `crates/credential/src/{endpoints,table}.rs` (binding re-creation only); `crates/runtime/src/managed_store.rs` `live_tests` (new tests); tests `tests/e2e/managed_m03.rs` |
| **R3-D runtime + setup** | 3 (W4-S03), 11 (W4-R09), 13 (R2C-Q2), 14 (R2D-Q1 doc), 16 (R2F-Q1..Q4) | `crates/runtime/src/service.rs` **except** `mod sources`, `crates/runtime/src/dispatch.rs`, `crates/runtime/src/lib.rs`; in `operations.rs` only the bind path's facts/result (`drive_bind` result and the facts it builds) for R2C-Q2; `crates/heimdall/src/connect_cmd.rs` (D8 item 2 flow); `crates/app/src/setup.rs`, `crates/app/src/catalog.rs` (destination removal), `crates/localenv/src/projection/**` (R2F); tests `tests/integration/runtime_m03.rs` (new module), `tests/e2e/consumer_m03.rs`/a new golden test, `tests/model/setup.rs` |

`operations.rs` and `managed_driver_m03.rs` are shared by C1/C2/D in **disjoint functions**; edit only yours,
never reformat others' regions (run `rustfmt` on your files only at the end; the integrator runs
`cargo fmt --all`). Ask under "Requests" for anything else.

## 1. Readings
- R1–R10 of round 1 hold (store-touching code in `operations` child modules; `VERIFICATION_UNGATED_SIGNING`
  stays `false`; release-build `HEIMDALL_TEST_*` refusal stays; fail closed before any write).
- §17.22 authorizes: the additive `store_locator` on `issuer.register` and the retire confirmation on
  `issuer.retire` (contract, schema, golden), the restore compare-and-swap and orphan listing (item 12), the
  bind result's endpoint (item 13). Anything else in `crates/contract/**`, migrations, `Cargo.lock`'s package
  set, pins, new deps, new `unsafe`: escalate (`.m03-wave4-r3-questions.md`).
- **W4-R09 goldens (R3-D):** the base is `d6593a7c`. Produce the base bytes from that exact commit without
  touching this worktree's checkout: `git archive d6593a7c | tar -x -C <new owner-only scratch dir>`, build and
  run only what produces the golden there (its own `target/` inside the scratch dir, deleted afterwards — it is a
  separate tree, not a second target dir of this worktree), and commit the golden **file** into this tree.
  Record the exact commands.
- Every new regression is shown failing with its fix reverted (real exit codes in your worklog
  `.m03-wave4-r3-worklog-<A|B|C1|C2|D>.md`).

## R3-A landed
- §17.22 item 1: `enrollment_m03::admit::{same_foreign_descriptor, DESCRIPTOR_MISMATCH}`; held-record reuse
  refused for any other `ForeignRemovalTarget` before anything is written; the `RemoveEnrollment` precheck
  compares the decision's shown target with the record's (`DECISION_STALE`). Reason meanwhile
  `bundle_host_mismatch` (R3A-Q1).
- §17.22 item 2: `heimdall_registry::classify::{Inspection::marker_facts, MarkerFacts, MarkerClass,
  minimized_content, unrecorded_marker_line}` (`without_foreign_lines` removed); `app::enrollment::StoredReading`
  now `of(full, marker, line)` with `marker`, `own_entries`, `own_entry_hex`, `other_marker_lines`,
  `other_marker_sha256`, `marker_class` (`marker_entries_hex` removed).
- §17.22 item 7: `app::enrollment::{version_token, evidence_client_current, host_key_changed, evidence_holds}`;
  `adapters::managed::prepare::{EvidenceFeed, TargetAndClient, WithEvidenceFeed, invalidate_evidence}`,
  `ManagedSourceRead::{evaluate_target, client_version}` (default `None`), `pair_evidence(managed, pairs,
  prepared)`; runtime `mod sources::LateEvidenceFeed`, `sources::read(s, writer, feed)`.
  `passes::HOST_KEY_CHANGE_PROMPT_REVERIFY` removed; `verify_operation` records a host-key change found by the
  evaluator as `HostKeyMismatch` without a login.
## R3-B landed
- **Contract (additive, serde default, omitted when absent):** `IssuerRequest::Register.{store_locator,
  expected_store_locator}`, `IssuerRequest::Retire.deleted_locator`, `CaStatus.store_locator`,
  `OrphanStoreItem.locator` (R3B-Q1). Schemas `request`, `ipc.client-message`, `issuer-status` regenerated;
  examples `request.issuer.{register-report,register-restore,retire-confirm}.json`,
  `inspect.issuer.awaiting-deletion.json`.
- **Domain:** `DecisionKind::RegisterIssuer.{store_locator, expected_store_locator}` (`Option`, additive). Any
  literal needs `store_locator: None, expected_store_locator: None`.
- **Store (`ext_m03.rs`, issuer methods):** `Txn::{replace_issuer_store_locator(ca, expected, new),
  issuer_displaced_store_locators(ca), resolve_displaced_store_locator(ca, locator) -> bool,
  attach_register_issuer_store_locator(decision, locator)}`; `issuers.record_json` gains
  `displaced_store_locators` (additive key, no migration).
- **App:** removed `operations::CaStoreItemDeletion`, `IssuerLifecycle::store_item_deletion`,
  `Operations::record_issuer_store_locator`; `Operations::resume_ca_retirements(issuer)` takes one argument and
  never moves `unloaded` (stalled `operations::AWAITING_OWNER_DELETION`). New `issuer.retire` confirmation path.
- **Issuer crate:** removed `retire::StoreItemDeletion`; added `retire::delete_awaiting(store, ca, kind, locator)`
  (the owner-present CLI's deletion); `ceremony::RegisterRequest.{store_locator, expected_store_locator}` +
  `with_store_item`; the ceremonies send the report / the restore CAS.
- **What U12's CLI sends:** see the R3-B worklog §"U12 contract".
## R3-C1 landed
**§17.22 items 4, 9, 10.**
```rust
// heimdall_store::Txn (ext_m03.rs; no migration)
pub fn bindings_of_grant(&mut self, &GrantId) -> Result<Vec<BindingId>>;            // any state, ID order
pub fn managed_cleanup_owed(&mut self, &EnvironmentId) -> Result<Vec<GrantId>>;     // durable obligations:
//   (a) terminal grant (not revoking) with an instance pending/installed/lost; (b) any grant with a slot
//   held/clearing for a *released* binding
// heimdall_app::Operations (managed_driver_m03.rs; for the supervisor)
pub async fn managed_end_destroy_keys(&self, &GrantId) -> Result<bool, OpError>;     // ended managed grant? K_env destroyed
pub async fn managed_end_instances_destroyed(&self, &GrantId) -> Result<usize, OpError>; // after the files: instances → destroyed, gate released
```
- **Expiry (item 4).** `expire_grant` (scheduler) and `end_in`'s `Expired` arm (at use: new `Ended.expired`, handled by
  `complete_withdrawals` after the commit/gates) run `after_end_m03`: `ManagedEffects::destroy` → the adapter's `revoke`
  (bounded: `StoreCleanup`) → only if that succeeded the instances `destroyed` (gate `release_exclusive`).
  `after_release_m03` (last reference) uses the same function — **instances now move last**, not first.
- **Ended-grant pass (items 4, 9).** `Supervisor::ended_slot_pass` enumerates `held_slots_of_ended_grants ∪
  managed_cleanup_owed`; per grant: `managed_end_destroy_keys` → `EndCleanup::after_end` → (ended, on success)
  `managed_end_instances_destroyed`.
- **`StoreCleanup` (items 9, 10).** Per binding: `held → clearing` + slot files, then the binding files by generation, and
  only when both succeeded the mux path + `clearing → free`. Finds every binding of the grant (`bindings_of_grant`). For a
  grant that has **not** ended, `after_end` now cleans **only its released bindings** (was: nothing).
- **Release (item 10).** `release_checked`'s transaction: a released managed binding's held slots → `clearing`
  (`managed_driver_m03::release_binding_slots_in`), even while the grant lives on; after the commit
  `after_binding_release_m03` (`ManagedEffects::clear` at `BINDING_GENERATION`: endpoint, detach, files). The slot is
  `free` after the next ended-binding pass. The release result JSON is unchanged.
- Tests: `crates/runtime/src/managed_store/live_tests/cleanup.rs` (5; a child of `live_tests`, one `mod cleanup;` line
  there). R3C1-Q1 (managed `delegate` refused non-interactively) in the questions file.
- **For R3-C2:** if a re-issue re-materializes binding files at a new generation, `after_binding_release_m03` clears only
  `BINDING_GENERATION` at once; `StoreCleanup` clears every generation found on disk (so later generations wait for the pass).
## R3-C2 landed
**§17.22 items 5, 6, 8.** No port signature, contract, migration or dependency change.
```rust
// heimdall_app::operations::managed_driver_m03 (crate-internal)
pub(super) fn record_preparation_intent_in(tx, &GrantId, &OperationId, AdapterIdentity, token, now) -> Result<()>;
pub(super) enum IntentDisposition { Live, Follower, Other }   // Operations::cleanup_intent_disposition(&intent)
Operations::{reissue_consumers(&GrantId) -> ReissueConsumers { generation, bindings: Vec<(BindingId, holds_slots)> },
  fail_unrecoverable_preparation(&op, &grant), cleanup_follower_binding(&intent),
  materialize_follower(&op, &grant, &binding, leader_locator) -> Result<String, OpError>}
pub(super) fn follower_locator(leader: &str, dir: &Path) -> Option<String>;  with_follower_endpoint(&mut consumer, &str)
// heimdall_adapters::managed::effects
pub const BY_REFERENCE_PREFIX: &str = "SHA256:";  pub const NO_LIVE_KEY: &str = "no_live_key";
```
- **Item 8.** A managed attempt records its cleanup intent (`in_flight`) in the transaction of its `Attempted` receipt,
  before `generate_key`; the commit (and a cancelled owner's activation for others) clears it. While the operation is
  open and its preparation lives here (running, or a `pending`/`installed` instance) `process_cleanup_intent` skips it
  (whatever `origin`). Every managed failure after the attempt fails through `fail_managed_preparation` (was: only when
  `driver_ran`; `driver_ran` removed); a managed `prepare_from` timeout and an unreconcilable `Attempted`/`Uncertain`
  attempt at recovery (`stage_reconcile`, `reconcile_unresolved`) → `fail_unrecoverable_preparation` (op `failed`,
  `SERVICE_UNAVAILABLE`, effect `partial`; never `outcome_unknown`). `abandon` returns whether it cleared everything
  (all bindings materialized in the run, by generation); `cleanup_uncommitted_managed` is `false` while an instance is
  still live and destroys `lost` ones once clean.
- **Item 5.** Re-issue step 6 (`managed::driver::restore_consumers`): each live binding of the grant (an `active`
  managed binding of exactly the grant, via its references) is materialized at generation = the grant's instance
  count (≥ 2), its held slots rewritten (slots-only `materialize`) and listed, then generations
  `1..generation` cleared; a binding holding only some of its slots → `CONFIG_CONFLICT`, the grant stays
  `credential_reissue_pending`. Only then `reissue_completed`. Slots-only `materialize` is rebuilt from the signer
  (`binding_grant`, key, installed certificates) and the stored scope (`GrantScopes`), no `materialized` record.
- **Item 6.** A coalesced or decision-joined follower of a managed grant (`stage_commit`, attached): before the commit
  transaction its own binding is materialized by reference (`MaterializeSpec.public_key` = the grant's live K_env
  `SHA256:` fingerprint from its `installed` instance's entries, one empty-certificate entry per pair; the effects
  fill key and certificates), with its own intent (`Follower`: clears only that binding's files/endpoint, never the
  shared key). Its result names its own endpoint (the leader's locator with the follower's tag). Not materializable →
  refused at the commit (`SERVICE_UNAVAILABLE`, effect `none`), never `ACCESS_READY`.
- Tests: `crates/runtime/src/managed_store/live_tests/pipeline.rs` (5; `mod pipeline;` in `live_tests`). Helpers in
  `live_tests`: `Live::seeded(pairs, start)`, `seed_pairs`, `Live::process_opts(hook, Opts { fail, hold, wrap })`,
  `Hold` (in `FailPrepare`); `Live::new`/`process`/`process_with` unchanged. R2's
  `crash_between_materialize_and_commit_…` renamed `crash_after_confirmation_before_commit_leaves_no_endpoint_file_or_key`.
## R3-D landed
- **Item 3 (W4-S03):** `service.rs` `ManagedTeardown` (built right after the endpoint registry in
  `ManagedParts::start`; issuer + lock source join it at creation) owns the full end: `Drop` (unless `stop` ran)
  zeroizes, fences+stops the issuer (`ChildIssuer::stop` spawned on the current runtime), stops endpoints and the lock
  source, clears `ManagedWiring`, the late registry, install view and cleanup. `ManagedRuntime { teardown, … }`;
  `ManagedRuntime::stop(self)` takes no `ops` now. Tests `wave4::teardown_r3::*` (runtime_m03).
- **Item 11 (W4-R09):** goldens `tests/contracts/golden/m02-existing-access-ensure/{result.json,envelope.json,
  intent.json,request-hash.txt}` from base `d6593a7c`; scenario `tests/e2e/m02_ensure_golden.rs` (included by
  `e2e_consumer_m03`); test `existing_access_ensure_bytes_match_base_goldens`. Normalized: operation/grant/binding IDs.
- **Item 13 (R2C-Q2):** `OperationsDispatcher::with_binding_endpoints(Arc<dyn heimdall_runtime::connections::BindingEndpoints>)`;
  `Service::run` wires it over the late registry. A managed (`credential_mechanism == managed_certificate`) `bind`
  result's `consumer.signing_endpoint` = the live registry endpoint of that exact binding, or none; other results
  untouched; stored op result unchanged. No `operations.rs` edit. `connect_cmd::managed_launch_args` (pure) refuses
  before launch without it.
- **Item 14:** docs at `pair_masters_enabled`, `StorePairSource`, `ManagedSectionSpec.control_path`.
- **Item 16:** `ManagedPairSource::projection_pending` (new **defaulted** method, `false`); `plan.rs` `recommit_step`
  (P rewritten with identical bytes when a rendered pair's stored preference is pending → normal journaled SSH
  commit); `setup.rs` `record_managed_projection(tx, intent, aliases, generation, at)` records `existing/applied`
  (Q1); `catalog.rs` `RemoveDestination` returns the destination's preferences to `pending` (Q3, chosen). R2-F's
  `setup_switch` tests updated for Q1 (one renamed: `setup_rollback_or_existing_rendering_never_marks_managed_applied`).
## Requests
- R3-D → R3-A (FYI): my item-3 revert proofs restored `crates/runtime/src/service.rs` from a backup taken at
  16:54:47, last restore 16:55:27 (2026-11-11). An edit of yours to `mod sources` saved inside those 40 s would have
  been overwritten; please re-check your `mod sources` hunks. Later reverts toggled single lines in place.
- **R3-B → R3-A** (`tests/e2e/enroll_m03.rs` ~4464, `ca_retirement_refused_until_every_enrollment_final_or_abandoned`):
  `IssuerRequest::Retire` gained the additive `deleted_locator: Option<String>` (§17.22 item 12). The
  literal there needs `deleted_locator: None,` added (one line; behaviour unchanged). It does not compile
  until then.
- **R3-B → integrator (FYI, done by R3-B):** removing the runtime-side store-deletion seam (§17.22 item 12, D3)
  changed `Operations::resume_ca_retirements(issuer)` to one argument and removed
  `operations::CaStoreItemDeletion`. R3-B edited the two mechanical sites outside its regions: the
  `pub use restart_m03::{..}` line and the restart-recovery call `resume_ca_retirements(None)` in
  `operations.rs` (+ its comment), and in `tests/integration/runtime_m03.rs` the U0b row-23 test
  `retirement_resumes_at_start_from_each_state` (+ `FakeStoreItems` removed, the import line, and the
  `m03_decision_kinds` `RegisterIssuer` literal's two new `None` fields). No other worker's region touched.
- **R3-A → R3-D (FYI, done by R3-A; §17.22 item 7's runtime feed):** besides `mod sources`
  (`LateEvidenceFeed`, `Observing::{evaluate_target, client_version}`, `read(s, writer, feed)`), three
  mechanical lines outside it in `service.rs`: the `ManagedParts.evidence: Arc<sources::LateEvidenceFeed>`
  field (+ its `Default` in `build`), `adapter()` passing `Arc::clone(&self.evidence)` to `sources::read`, and
  in `start()` binding `TargetAndClient { target, host }` right before `ops.set_enrollment_host(host)`.
  Without them the feed is dead code (clippy) and production reports `destination_scope: unknown` always.
  Please keep them if you move that code.
- **R3-A → R3-C2 (FYI):** `prepare::pair_evidence` now takes the `&ManagedPrepared` (evidence of the
  prepared certificate's CA only) and `prepare::snapshot` drops the snapshot copy's evidence that fails the
  §17.22 item 7 comparison; `ManagedSourceRead` gained `evaluate_target` / `client_version` (defaults
  `None`: fail closed). A source that wraps another must forward them (`prepare::WithEvidenceFeed` does).
  See R3A-Q2 on the descriptor's advertised `destination_scope`.
- **R3-A → R3-C1:** `integration_managed_adapter::expired_grant_never_reissued` fails at
  `w.table().public_key(&gid).unwrap()` (~line 2583, after the grant expired): with item 4 K_env is destroyed at
  expiry, so that line (the reserve-refusal check) needs its key read **before** `w.clock.advance` / `tick`.
  Not an evidence case, so I left it to you.
- **R3-C2 → R3-C1 (FYI):** a re-issue now leaves a live binding at generation N ≥ 2 (old ones cleared), so
  `after_binding_release_m03`'s `clear(…, BINDING_GENERATION)` misses it until `StoreCleanup`'s pass (as you
  noted). If you want the release to clear at once, clear every generation on disk
  (`files::binding_directories_of`) or the effects' newest endpoint generation. No change made by me.
- **R3-C2 → R3-B / integrator (FYI):** `integration_runtime_m03::issuer_crash::issuer_crash_blocks_reissue_not_signing`
  fails here at its line ~5128 (`(GrantState::Active, None)` after `issuer_supervision_pass` while the issuer is
  down: item 15), before any re-issue; not a C2 region. Its later re-issue half now also restores the binding
  (my item 5) and should still pass once the earlier assertion does.
