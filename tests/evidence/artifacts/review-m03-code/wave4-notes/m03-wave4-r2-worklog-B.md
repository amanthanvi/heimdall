# M03 wave 4, round 2 — R2-B (issuer) worklog

Goal: ADR-0008 §17.21 item 3: `RegisterIssuer.{ca_public_key, backup_created_at}` (approval
reads the record, no process memory); `IssuerRecord` record_json `store_locator`; retirement
deletes exactly that locator; `issuer_store_locator_unrecorded`.

## Findings (read before coding)
- K_ca `put` happens only in the CLI-side ceremony (`ceremony::create_ca` step 6,
  `store_and_check`), **after** `issuer.register` (step 3) and **before** `Decide approve`
  (step 7). `Registered.item` / `Restored::*.item` return the `StoreItemRef` to the caller (U12's
  CLI). `Decide` carries no payload and `IssuerRequest` has no locator field: no wire path carries
  the locator to the runtime today. The issuer child never writes the store (ADR-0008 D3, line
  ~723) and only reads by fingerprint (`get`), so it has no put report either.
- The runtime process holds no `SecretStore`; the child is the only holder and may not delete.
- `IssuerRecord {..}` literals exist in 12 test files owned by 4 workers; `DecisionKind::RegisterIssuer
  {..}` literals in 3 (one is R2-D's `runtime_m03.rs:639`).

## Decisions
- B2-D1. `store_locator` lives in `issuers.record_json` but is **not a struct field** of
  `IssuerRecord`: read/written by `Txn::{issuer_store_locator, set_issuer_store_locator}`;
  `set_issuer_state` preserves it. Keeps every `IssuerRecord {..}` literal (other workers' tests)
  compiling. No migration.
- B2-D2. `RegisterIssuer` new fields are `Option`, `#[serde(default, skip_serializing_if =
  "Option::is_none")]`; an old record decodes with `None` and its approval is `DECISION_STALE`
  (precheck, nothing written). The join of a pending registration requires the same key and
  `backup_created_at` (an old-shape record is never joined).
- B2-D3. Retirement's store step reads the recorded locator first: none → stall at `unloaded`
  with `issuer_store_locator_unrecorded`, nothing called. With one, the deletion port gets
  exactly `(ca, store kind, locator)`.

- B2-D4. Registration facts on the decision; `IssuerProcessState` emptied (kept: `ManagedOpsState`
  names it), `DecideCtx {}` emptied (kept: `operations.rs` passes it). `m03_decide_ctx` reads
  `managed_ops.issuer` once so the integrator's field is not dead code (clippy) until removed.
- B2-D5. The locator sink is `Operations::record_issuer_store_locator` (set once; NOT_FOUND /
  CONFIG_CONFLICT / USAGE_ERROR). No production caller: R2B-Q1 (no wire path carries the ceremony's
  put report; the child has none). Fail closed: `issuer_store_locator_unrecorded`.
- B2-D6. The deletion port is reached through `IssuerLifecycle::store_item_deletion()` (default
  `None`; `ChildIssuer` keeps it): R2B-Q2 (the child may not write the store; the runtime holds
  none). `retire::StoreItemDeletion<S>` now takes the locator from the caller (`delete_recorded`),
  never from `RecordedItems`/listing; it also refuses an empty locator (found by revert R4: an empty
  locator through a store whose delete reports `NotFound` would read as "absent").
- B2-D7. `CaStoreItemDeletion::delete_confirmed_absent` defaulted to a refusal, never called (kept so
  R2-D's `FakeStoreItems` compiles); `delete_recorded` added (default refusal).
- B2-D8. `issuer_store_locator_unrecorded` registered in `reason::M03` (`CAPABILITY_UNAVAILABLE`) +
  `tests/contracts/golden/m03-reasons.golden.json` (§17.21 item 3 authorizes it).

## Progress
- [x] domain `RegisterIssuer` fields + `decision_kind_wire_forms` (present case, old-shape decode and
  byte-identical re-encode).
- [x] store `issuer_store_locator` / `set_issuer_store_locator`, preserved by `set_issuer_state`.
- [x] reason + golden.
- [x] `restart_m03` deletion step (locator first, then the port); `CaStoreItemDeletion::delete_recorded`.
- [x] `issuer_m03`: register writes the facts, approval reads them (stale without), join requires
  them, map removed, deletion port passed by supervision + after-decision, `record_issuer_store_locator`.
- [x] `retire::StoreItemDeletion<S>` over the recorded locator.
- [x] Regressions (issuer_m03 ×4, store_m03 ×1, issuer_store ×1 + 2 updated, managed_domain updated).
- Requests filed: R2-D (`runtime_m03.rs` RegisterIssuer literal + seed locator + fake rename; it does
  not compile until then), integrator (`ManagedOpsState.issuer`, `DecideCtx`, plan §5 item 14 text).

## Commands (exit codes)
- `cargo test -p heimdall-runtime --test integration_issuer_m03`: 0 (17 passed).
- `cargo test -p heimdall-issuer`: 0 (unit 12, issuer_child 33, issuer_store 30, linearization 6).
- `cargo test -p heimdall-testkit --test integration_store_m03`: 0 (29).
- `cargo test -p heimdall-contract --test contracts`: 0 (89).
- `cargo test -p heimdall-domain --test model_managed_domain`: 0 (21).
- `cargo test -p heimdall-store`: 0.
- `cargo clippy -p heimdall-app -p heimdall-issuer -p heimdall-store -p heimdall-domain --all-targets
  -- -D warnings`: 0.
- `cargo clippy -p heimdall-runtime --test integration_issuer_m03 -- -D warnings`: 0;
  `cargo clippy -p heimdall-contract -p heimdall-testkit --all-targets -- -D warnings`: 0.
  (`-p heimdall-runtime --tests`: 101, R2-C's `managed_store.rs` lib-test WIP: dead field, `eprintln!`.)
- `cargo test -p heimdall-runtime --test integration_runtime_m03 --no-run`: 101, only
  `runtime_m03.rs:639` RegisterIssuer literal (R2-D request).
- `rustfmt --edition 2024 --check` on each of my files: 0. (`cargo fmt --all --check` lists other
  workers' files, incl. R2-D's hunk at `ext_m03.rs:1203`, not mine.)
- `bash tools/validation/linux-xcheck.sh -p heimdall-issuer`: 101 (first run), blocked by R2-C WIP
  `managed_driver_m03.rs:1042` (`SlotState` not in scope) in heimdall-app.

## Revert runs (fix reverted → exit; restored → exit), one test each
| # | Reverted | Test | Reverted | Restored |
|---|---|---|---|---|
| R1 | register writes `ca_public_key`/`backup_created_at` (→ `None`) | issuer_m03 `issuer_registration_survives_restart_and_is_approved` | 101 | 0 |
| R1b | approval reads the record (`recorded_registration` always stale, i.e. no process memory) | same | 101 (approve after restart: DECISION_STALE) | 0 |
| R2 | stale on a missing/mismatched key (accept defaults) | issuer_m03 `issuer_register_old_shape_decision_is_stale_not_consumed` | 101 | 0 |
| R3 | exact-locator deletion (→ delete every listed item of the CA) | issuer_m03 `ca_retirement_deletes_exactly_the_recorded_store_locator` | 101 (other installation's item deleted) | 0 |
| R4 | the no-locator stall (→ `unwrap_or_default()` locator) | issuer_m03 `ca_retirement_without_recorded_locator_stops_unloaded_nothing_deleted` | 101 (reached `retired`, item still present) | 0 |
| R5 | `set_issuer_state` keeps the locator (→ writes the bare record) | store_m03 `issuer_store_locator_recorded_once_and_kept_through_transitions` | 101 | 0 |
| R6 | port's product-kind check | issuer_store `store_item_deletion_port_deletes_exactly_the_recorded_locator` | 101 | 0 |
| R7 | `skip_serializing_if` on `ca_public_key` | managed_domain `decision_kind_wire_forms` | 101 | 0 |
| R8 | `reason::M03` row | contracts `m03::contract_reason_golden` | 101 | 0 |
