# M03 wave 4, round 2 — worklog R2-D (runtime)

Items (ADR-0008 §17.21): 6 (one `reissue::eligible`), 8 (stable Windows pipe token), 9 (mux path in P),
11 (selection feed, slot cleanup for ended grants, `inspect connections`).

## Decisions
- D2-1 (item 6): `heimdall_domain::reissue` holds the pure rule (domain is in both graphs; no new edge;
  `crate_graph.py` OK). `heimdall_adapters::managed::reissue` is `pub use heimdall_domain::reissue::*`.
  `app`'s `reissue_eligible` gathers the inputs in one store transaction and calls
  `heimdall_domain::reissue::eligible`; the re-implemented checks and the separate
  `lock_blocks_reissue` call in the pass are gone (rule 5 now comes from the same function, with the
  effective lock behaviour + R3 floor computed as `lock_blocks_reissue` does). Inputs: stored grant
  bounded by `bound_of` (ancestors, cutoffs, anchor bound), origin, tombstone (`denied_ancestor`),
  merged-policy cutoff, gate verdict; on `Safe` time the grant is first re-anchored in this boot
  (`first_validation_anchor`, as every use does) and then `admission` is read, so a same-boot or
  re-anchored grant is `Open` and the domain rule's `NeedsAnchor → time_not_accepted` keeps round 1's
  behaviour. `heimdall_domain::reissue::MANAGED_CERTIFICATE` duplicates the app constant (app's
  `ca_issuance_m03.rs` is not mine); same string.
- D2-2 (item 8): `Txn::{windows_pipe_token, set_windows_pipe_token}` over `meta`
  (`windows_environment_pipe_token`), set-once (same value no-op, other value `GenerationConflict`,
  malformed refused). `Service::start` → `installation_pipe_token`: read or create-and-record in one
  transaction (prefix alphanumerics + 32 CSPRNG hex) for every managed start on every host; the
  managed `EndpointLayout::windows` uses it. The control endpoint keeps M01's per-start token.
- D2-3 (item 9): `StorePairSource` renders `checked_mux_path(<runtime_dir>, dest)` iff
  `pair_masters_enabled` (fail-closed merge over every current standing policy applicable to the pair
  is `owned_masters`; none → disabled), not on Windows, and the path fits; else `ControlPath none`.
  Per-grant vs per-pair reading escalated: R2D-Q1.
- D2-4 (item 11, selection): `ManagedSourceRead::observations` (defaulted, empty) + `prepare::snapshot`
  fills `IntegrationSnapshot.observations` for the request's aliases; `prepare::selection_class`
  (weakest: undetermined < not_exclusive < exclusive) feeds `ReportContext.selection`. The runtime wraps
  R2-C's `StoreSources` in `service.rs` `sources::Observing` (writer's `observe` over the stored
  projection record), so `managed_store.rs` is untouched. Per-pair `PairIntegration.identity_selection`
  left `undetermined` (outside "the ReportContext.selection feed only").
- D2-5 (item 11, slots): `Txn::held_slots_of_ended_grants(&EnvironmentId)` (join slots→bindings→grants,
  held/clearing, grant terminal or revoking). `Supervisor::with_end_cleanup(Arc<dyn EndCleanup>)` +
  `ended_slot_pass()` (after every scheduler tick's sweep and in every `managed_pass`) runs the runtime's
  `LateCleanup` (connections closed with events, then U10-C's `StoreCleanup`) per ended grant.
  Limitation (Requests → R2-C): `StoreCleanup` finds bindings by `grant_references`, which
  `release_binding` deletes, so a released binding's held slot is listed but not cleared (retried).
- D2-6 (item 11, inspect): `InspectSubject::Connections` arm: owner only (non-owner `{"connections": []}`),
  read-only, live rows only (`up`/`closing`; contract `ConnectionState` has no other), destination =
  master's mux file name or the binding's first destination, policy = D8 item 1 merge (no origin:
  strict/disabled), `closes_at` = `bound_of` for a master or under strict, else null. New store read
  `Txn::owned_connections()` (all rows). The stale comment above the `Enrollments` arm ("inspect
  connections has no reader yet") is outside my arm and was left.

## Shared/reserved edits
- `crates/app/src/operations/managed_driver_m03.rs`: only `reissue_eligible` + the pass's eligibility
  call/doc (+ `TimeStatus` import).
- `crates/app/src/operations.rs`: only the `InspectSubject::Connections` arm.
- `crates/adapters/src/managed/prepare.rs`: `observations` trait method, `selection_class`, `snapshot`'s
  observations, `outcome`'s `selection:` line, one import.
- `crates/store/src/lib.rs` (pipe token + const + validator + unit test), `ext_m03.rs`
  (`held_slots_of_ended_grants`, `owned_connections`).
- `tests/integration/runtime_m03.rs`: `DecisionKind::RegisterIssuer` fixture gained R2-B's two new
  fields (`None`), forced by R2-B's domain change.

## Progress
- [x] item 6 — [x] item 8 — [x] item 9 — [x] item 11 selection — [x] item 11 slots — [x] item 11 inspect
- [x] revert proofs — [x] full test runs — [x] clippy host — [x] linux-xcheck — [x] windows clippy — [x] fmt (my files)

## Commands (exit codes)
- `python3 -I tools/validation/crate_graph.py`: 0.
- `cargo test -p heimdall-store --lib windows_pipe_token`: 0.
- `cargo test -p heimdall-runtime --lib pair_source`: 0 (2 tests).
- `cargo test -p heimdall-runtime --test integration_runtime_m03 -- ended_grant_held_slot inspect_connections_lists`: 0.
- `cargo test -p heimdall-runtime --test integration_runtime_m03 -- round2`: 0 (2 tests).
- `cargo test -p heimdall-localenv --test integration_projection_managed`: 0 (15/15).
- `cargo test -p heimdall --test e2e_managed_m03 reissue`: 0 (2/2; exercises the unified rule through
  `managed_reissue_pass`, incl. the post-reboot re-anchor).
- Revert probes (`/tmp/r2d-probe/probe.py`: revert → run → restore → run; real exit codes):
  - item 6, re-anchor before `admission` removed → `reissue_after_reboot_waits_for_time_confirm` 101
    (managed_m03.rs:1292); restored 0.
  - item 8, `installation_pipe_token` → per-start `endpoint_token_on` → `windows_pipe_token_stable_across_runtime_restart` 101; restored 0.
  - item 9, `if false && masters` → `pair_source_renders_mux_path_only_when_owned_masters_enabled` 101; restored 0.
  - item 9, merge only over `owned_masters` policies (not fail-closed) → same test 101; restored 0 (first
    restored run 101 from another worker's concurrent compile break; re-run: reverted 101, restored 0).
  - item 11, `selection: SelectionClass::Undetermined` → `managed_report_selection_follows_alias_classification`
    101; restored 0 (first attempt hit the same concurrent compile break; re-run 101 / 0).
  - item 11, snapshot without observations → same test 101; restored 0.
  - item 11, ended-slot pass cleans nothing → `ended_grant_held_slot_cleared_by_its_generation` 101; restored 0.
  - item 11, inspect lists nothing → `inspect_connections_lists_owned_rows_owner_only` 101; restored 0.
  - item 11, owner-only check removed → same test 101; restored 0.
- R2-B's request applied in `runtime_m03.rs` (`seed_ca` records a locator; `FakeStoreItems::delete_recorded`):
  `integration_runtime_m03` 36/36, 0.
- `cargo test -p heimdall-adapters --test integration_managed_adapter`: 0 (46/46).
- `cargo test -p heimdall-store`: 0 (20 lib tests).
- `cargo test -p heimdall-runtime --no-fail-fast` (final): 0, 14 targets all ok (lib 36, runtime_m03 36,
  model_operations_m03 37 …). An earlier run had R2-C's in-progress `managed_store::live_tests` (3) and
  the round-1 `existing_access_prepare_contract_unchanged` failing; both pass in the final run.
- `cargo clippy -p heimdall-runtime -p heimdall-adapters -p heimdall-domain -p heimdall-store -p heimdall-app --all-targets -- -D warnings`: 0 (no `--no-deps` needed).
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 0.
- `bash tools/validation/clippy-windows.sh` (whole workspace): 0.
- `cargo fmt --all --check`: clean for my files (service.rs, supervisor.rs, domain/reissue.rs,
  store lib.rs/ext_m03.rs regions, runtime_m03.rs, projection_managed.rs, prepare.rs). Remaining diffs
  are other workers' files; `operations.rs` 8756/8869 is a re-indentation of the whole inspect `match`
  by another worker's edit (my `Connections` arm is inside it; not reformatted by me).
