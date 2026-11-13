# M03 wave 4, round 2 — worklog R2-C (managed binding)

Goal: ADR-0008 §17.21 items 1 (binding ID at resolve, step-6 materialize, endpoint named,
cleanup, replay, M02 byte-identity, crash regression), 2 (slots claimed in `BindForm::Launch`;
`run_cmd::ManagedSlots` reads the outcome), 7 (`Txn::credential_instances_for_grant`).

## Decisions
- C2-1. The driver reads the binding ID from the operation's stored intent (the open operation whose
  `Attempted` receipt carries the effect token; `ResolvedIntent.binding_id`), so `PrepareRequest`
  (frozen) is unchanged. Re-issue (no operation) materializes nothing new.
- C2-2. `ManagedEffectsImpl::materialize`: endpoint created through `BindingEndpoints` (new default
  methods `create_binding_endpoint`/`remove_binding_endpoint`; default fails closed / no-op), files
  written, **then** the binding attached (it lists only after its files exist). The grant is found by
  the spec's public key among the keys this effects instance generated. `clear(binding, g)` also
  removes the endpoint of generation `g` and detaches the binding when no endpoint remains.
- C2-3. Cleanup before commit: (a) the driver's own failure path clears the binding; (b) a failed
  `prepare_from` of a managed preparation and a managed commit after a restart (reconcile not
  `Applied`) settle the operation with a cleanup intent (`settle_effect_in`); (c) processing an intent
  whose call is made also clears the operation's uncommitted binding (files found on disk by
  marker, so after a restart too) and destroys the grant's live instances (gate released).
- C2-4. Slot claim in `drive_bind` (Launch, managed binding): txn 1 checks every slot (a held or
  clearing one refuses `CONFIG_CONFLICT managed_slot_held`, nothing else written) and CAS-claims
  them, op stays `running`; then the files + listing through `ManagedEffects::materialize` with
  `environment_slots` (slots-only spec: empty key and certificates = the content this effects
  instance materialized for the binding); txn 2 settles (holder, connection, result). An effect
  failure releases the claims and fails the bind. M01/M02 binds are unchanged (one transaction).
- C2-5. `run_cmd::ManagedSlots` → `BoundSlots`: a successful launch bind of a managed binding means
  the runtime holds every managed pair's slot; no claim from the CLI. No contract field needed.

- C2-6. The prepare step's M02 `catalog_mechanism` check (P6) is skipped for the managed adapter: a managed
  pair's catalog identity is its existing access, and U0b row 9's stored preference already decided the
  mechanism (mixing refused at resolve). Without it every production managed ensure on a catalog-managed
  destination failed `mixed_mechanisms` (found by the live tests).
- C2-7. The ensure result carries this drive's `consumer.signing_endpoint` (the stored history drops it;
  `None` for every M01/M02 adapter, so their results are unchanged).
- C2-8. Live endpoint regressions are runtime unit tests (`managed_store.rs` `live_tests`, Unix): the
  production `StoreSources`/`OpsInstallView`/`StoreCleanup` and a real `EndpointRegistry` (the adapters test
  crate has no `tokio-util` edge; the `heimdall` dev-dependency was not needed). They ensure
  **interactively** (R2C-Q1).
- Escalated: R2C-Q1 (non-interactive managed ensure refused by M02 eligibility at the commit), R2C-Q2 (bind
  result names no binding endpoint → `connect` fails closed). Request to R2-D: `LateRegistry` forwarding.
- Residuals: a crashed process's binding socket file (no listener) stays in `<runtime_dir>/b/<tag>/` (the
  files go; `ManagedDir::remove` refuses non-regular files); a cleanup intent owned by a live/re-armed
  remote obligation clears the binding only through the revocation round's `revoke` (in-process record);
  coalesced attached bindings get no endpoint of their own; re-issue does not re-materialize binding files.

## Shared-file edits
- `crates/app/src/operations.rs`: `pin` (3 literals `binding_id: None`), `stage_resolve` (mint + `with_managed_binding`),
  the prepare step (`catalog_mechanism` skip for managed; managed `Err` arm → `fail_managed_preparation`),
  `stage_commit` (minted ID, signing endpoint, managed reconcile arm), `process_cleanup_intent` (one call),
  `drive_bind` (two passes; the bind literal `binding_id: None`).
- Mechanical `binding_id: None` in full `ResolvedIntent` literals: `crates/store/src/lib.rs` (test),
  `tests/integration/store.rs`, `tests/model/operations.rs`.

## Progress
- [x] item 7  - [x] item 1  - [x] item 2  - [x] revert runs  - [x] checks

## Commands (exit codes)
- `cargo test -p heimdall --test e2e_managed_m03`: 0 (16 passed; 5 new).
- `cargo test -p heimdall-adapters --test integration_managed_adapter`: 0 (46 passed).
- `cargo test -p heimdall-runtime` (all targets): 0 (lib 36 incl. 5 new `live_tests`; runtime 59, runtime_m03 36,
  connections 43, issuer_m03 17, model_operations 186, model_operations_m03 37, setup 51, timegate 27, events 19,
  narrowing_m03 57, session_lock 4 + 1 ignored, setup_dispatch 9).
  (`model_operations_m03::existing_access_prepare_contract_unchanged` first failed 101: operations.rs must not
  name `.managed`; fixed by moving the check into `managed_driver_m03::driver_ran` and renaming two methods.)
- `cargo test -p heimdall --test e2e_run_m02 --test e2e_cli_m02`: 0 (54 + 1 ignored, 42 + 1 ignored).
- `cargo test -p heimdall --bin heimdall run_cmd`: 0 (3). `cargo test -p heimdall-app --tests`: 0.
- `cargo test -p heimdall-testkit --test integration_store`: 0 (77). `cargo test -p heimdall-store --lib`: 0 (20).
- `cargo clippy -p heimdall-app -p heimdall-adapters -p heimdall-credential -p heimdall-runtime -p heimdall-store -p heimdall --all-targets -- -D warnings`: 0 (not narrowed).
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 0. `bash tools/validation/clippy-windows.sh`: 0.
- `cargo fmt --all --check`: my files clean; remaining diffs only in operations.rs ~8459–8900 (`inspect`, R2-D's region).

### Revert runs (fix reverted → test → restored → test); `/tmp/r2c-revert.py` substitutions, removed after
| Regression | Revert | Reverted | Restored |
|---|---|---|---|
| `managed_binding_minted_at_resolve_materialized_then_committed_under_it` | no mint at resolve | 101 | 0 |
| `managed_replay_of_request_returns_same_binding` | commit mints a fresh ID | 101 | 0 |
| `managed_failure_before_commit_cleans_binding_key_and_instance` | prepare `Err` arm → `fail_running` | 101 | 0 |
| `existing_access_ensure_intent_and_result_byte_identical_to_m02` | `binding_id` serialized when `None` | 101 | 0 |
| `credential_instances_found_by_grant_query_not_fingerprint` | `instances_of` by fingerprint | 101 | 0 |
| `live_tests::managed_ensure_names_binding_endpoint_listing_grant_certificates` | step 6 skipped | 101 | 0 |
| `live_tests::managed_prepare_failure_after_materialize_leaves_no_endpoint_file_or_key` | cleanup hook no-op | 101 | 0 |
| `live_tests::crash_between_materialize_and_commit_leaves_no_endpoint_file_or_key` | restart reconcile arm removed | 101 | 0 |
| `live_tests::launch_bind_claims_the_free_slot` + `…refuses_a_held_slot_…` | bind claim skipped | 101 | 0 |
| `run_cmd::tests::the_slot_check_reads_the_bind_outcome_and_claims_nothing` | reader shows none held | 101 | 0 |
