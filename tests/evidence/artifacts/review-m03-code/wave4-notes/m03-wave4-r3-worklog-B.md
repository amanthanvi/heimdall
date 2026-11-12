# M03 wave 4, round 3 — R3-B (issuer) worklog

Goal: ADR-0008 §17.22 item 12 (R2B-Q1/Q2: the ceremony reports the store locator on
`issuer.register`; the runtime records it with the approval; retirement stops at `unloaded`
awaiting the owner-present CLI's deletion, confirmed on `issuer.retire`; restore CAS; displaced
items in `orphan_store_items`) and item 15 (verify only).

## Findings (before coding)
- The K_ca `put` (D4 item 1 step 6) is after `issuer.register` (step 3) and before `Decide`
  (step 7); the Linux locator (D-Bus item path) exists only after the put. So the report is a
  **second** `issuer.register` after step 6 carrying `store_locator`, joining the pending
  decision.
- `register_admissible` refuses a registered fingerprint: a log-intact restore never registered;
  its re-pointing needs a re-registration path (CAS on `expected_store_locator`).
- `CaStoreItemDeletion` / `IssuerLifecycle::store_item_deletion` / `resume_ca_retirements(_, deletion)`
  are the runtime-side deletion seam to remove (D3).
- Literals that break on new fields: `DecisionKind::RegisterIssuer` (tests/model/managed_domain.rs,
  tests/integration/runtime_m03.rs:639), `IssuerRequest::Retire` (tests/e2e/enroll_m03.rs:4464, R3-A),
  `CaStatus` (tests/e2e/issuer_ceremony.rs, tests/integration/issuer_store.rs).

## Decisions
- B3-D1. Report = a second `issuer.register` after the put with `store_locator`; joins the pending
  `RegisterIssuer` (same facts incl. `expected_store_locator`; `store_locator` not part of the identity),
  recorded once on the record (`Txn::attach_register_issuer_store_locator`, CAS on pending + none). Another
  locator on the same pending registration: CONFIG_CONFLICT, nothing written. Approval records it
  (`set_issuer_store_locator`). No report → CA recorded without locator (round-2 behaviour). (R3B-Q2)
- B3-D2. Runtime-side deletion seam removed: `operations::CaStoreItemDeletion`, `IssuerLifecycle::store_item_deletion`,
  `retire::StoreItemDeletion`, `Operations::record_issuer_store_locator`; `resume_ca_retirements(issuer)` (one arg).
  `unloaded` never moves in the runtime; stalled `store_item_awaiting_owner_deletion`
  (`operations::AWAITING_OWNER_DELETION`, report value) or `issuer_store_locator_unrecorded`. D3 documented at
  `IssuerLifecycle`, `restart_m03` and `retire`.
- B3-D3. Confirmation `issuer.retire { deleted_locator }`: owner (first) + attended (else INTERACTION_REQUIRED);
  recorded locator → CA must be `unloaded` (`deleted` completes, `retired` idempotent; else CONFIG_CONFLICT);
  displaced locator → leaves the list (any state); else CONFIG_CONFLICT / NOT_FOUND, nothing written. Answer = status.
  `retire` without confirmation on an `unloaded` CA answers the status (names the locator).
- B3-D4. Restore CAS = re-registration of a known CA through `RegisterIssuer` (R3B-Q3): needs store_locator, no
  rotation / key-only restore, CA active|pending, same public key + store kind + backup digest, recorded ==
  expected, new != recorded; checked at request and approval; apply = `replace_issuer_store_locator` (displaced →
  `displaced_store_locators` in record_json). Unknown CA: expected must be absent.
- B3-D5. Contract additions (additive, serde default/omitted): `Register.{store_locator, expected_store_locator}`,
  `Retire.deleted_locator`, `CaStatus.store_locator`, `OrphanStoreItem.locator` (last two: R3B-Q1). Domain
  `RegisterIssuer.{store_locator, expected_store_locator}`. Schemas regenerated in-process (temporary ignored
  test, removed); examples added.
- B3-D6. Ceremony (`crates/issuer`): `create_ca` reports after step 6 and requires the same decision ID;
  log-lost restore reports before approve; log-intact restore re-registers when the item's locator differs from
  `CaStatus.store_locator` (shows the decision, asks `yes`). CLI deletion helper `retire::delete_awaiting`.
- B3-D7. Item 15: no code degrades a grant on issuer unavailability (`DegradedReason::IssuerUnavailable` is set
  nowhere in app/runtime; degrade sites: lost K_env, mechanism unavailable, managed driver re-issue). The existing
  live regression `issuer_crash::issuer_crash_blocks_reissue_not_signing` accepted `degraded`; tightened to
  `(Active, None)`.

## Progress
- [x] contract / domain / store / app / issuer / ceremony / tests; schemas + examples.
- Shared-file touches (outside my regions, mechanical): `operations.rs` re-export + restart call;
  `runtime_m03.rs` row-23 test, its import, `m03_decision_kinds` literal, item-15 assertion;
  `tests/model/managed_domain.rs` (wire forms). Request to R3-A for `enroll_m03.rs:4464`.

## Commands (exit codes)
- `cargo test -p heimdall-runtime --test integration_issuer_m03`: 0 (19 passed).
- `cargo test -p heimdall-issuer`: 0 (unit 12, issuer_child 33, issuer_store 30).
- `cargo test -p heimdall --test e2e_issuer_ceremony`: 0 (4 passed, 2 ignored pre-existing).
- `cargo test -p heimdall-domain --test model_managed_domain`: 0 (21).
- `cargo test -p heimdall-testkit --test integration_store_m03`: 0 (30).
- `cargo test -p heimdall-contract`: 0 (41 + 89).
- `cargo test -p heimdall-runtime --test integration_runtime_m03 -- retirement_resumes issuer_crash`: 0 (5).

## Revert runs (mutation → exit; restored → exit)

## U12 contract (what the CLI must send)
`heimdall_issuer::ceremony::{init, rotate_begin, restore}` already drive the sequence over `OwnerSession`;
U12 implements `OwnerSession` over IPC (`register` = `Request::Issuer(RegisterRequest::to_issuer_request())`,
answer `APPROVAL_REQUIRED` with the `RegisterIssuer` decision ref → `RegisterDecision`).
1. **init / rotate-begin:** `attend`; `issuer.register {ca_public_key, store, backup_sha256, backup_created_at,
   [rotation_of]}` (no locator) → decision D; owner `yes`; backup; passphrase; `SecretStore::put` → item;
   **`issuer.register` again with the same fields + `store_locator: item.locator`** → must name D (else stop:
   `DecisionMismatch`); `Decide approve D`.
2. **log-lost restore:** as 1 with `restored_without_log: true`; report the item before `Decide approve`.
3. **log-intact restore:** `issuer.status`; put/adopt the item; if `item.locator != CaStatus.store_locator`:
   `issuer.register {same key, store, the CA's recorded backup_sha256 (= the backup file's), backup_created_at,
   store_locator: item.locator, expected_store_locator: CaStatus.store_locator (omit when absent)}` → decision;
   show it, `yes`, `Decide approve`; then `issuer.unlock`. A mismatch is `CONFIG_CONFLICT`, nothing changed.
4. **retire:** `issuer.retire {ca_fingerprint}` → `RetireIssuer` decision → `Decide approve` → the runtime unloads
   (`retiring → unloaded`). Then `issuer.status` (or `issuer.retire` again: it answers the status): the CA is
   `unloaded` with `store_locator` L. The CLI runs `retire::delete_awaiting(store, ca, CaStatus.store, L)` (exact
   delete + re-read), then on an **attended** session `issuer.retire {ca_fingerprint, deleted_locator: L}` → status
   with the CA `retired`. No `store_locator` (unrecorded): nothing to delete or confirm; stays `unloaded`.
5. **displaced items:** each `orphan_store_items[i]` with `locator: Some(L)` and `fingerprint: Some(ca)`:
   `delete_awaiting(store, ca, item.store, L)`, then attended `issuer.retire {ca_fingerprint: ca, deleted_locator: L}`.

| # | Mutation (fix reverted) | Test | Reverted | Restored |
|---|---|---|---|---|
| R1 | the report is not attached to the pending decision | issuer_m03 `issuer_register_store_locator_report_recorded_with_approval` | 101 | 0 |
| R2 | the approval does not record the reported locator | same | 101 | 0 |
| R3 | the runtime moves `unloaded → deleted` itself (round-2 behaviour, no deletion port) | issuer_m03 `ca_retirement_waits_unloaded_for_the_owner_deletion_confirmation` | 101 | 0 |
| R4 | any locator confirms the deletion | same | 101 | 0 |
| R5 | request/approval CAS comparison removed (`register_admissible`) | issuer_m03 `issuer_restore_store_locator_compare_and_swap_and_orphan_listing` | 101 | 0 |
| R6 | store-level CAS ignores `expected` | store_m03 `issuer_store_locator_compare_and_swap_keeps_displaced_items` | 101 | 0 |
| R7 | displaced items not listed in `orphan_store_items` | issuer_m03 CAS test | 101 | 0 |
| R8 | the confirmation does not resolve a displaced item | issuer_m03 CAS test | 101 | 0 |
| R9 | domain `store_locator` always serialized (old-shape record not byte-identical) | managed_domain `decision_kind_wire_forms` | 101 | 0 |
| R10 | contract `deleted_locator` always serialized | contract lib `issuer_store_item_fields_are_additive` | 101 | 0 |
| R11 | ceremony sends no store-item report | issuer_store `registered_digest_is_the_written_backup` | 101 | 0 |
| R12 | log-intact restore never re-registers a new item | issuer_store `two_installations_restore_and_retire_on_a_shared_attribute_store` | 101 | 0 |
| R13 | CLI deletion's other-CA guard removed | issuer_store `cli_store_item_deletion_deletes_exactly_the_named_locator` | 101 | 0 |
| R14 | item 15 mutation: the supervision pass degrades active grants `issuer_unavailable` while the issuer is down | runtime_m03 `issuer_crash::issuer_crash_blocks_reissue_not_signing` (tightened) | 101 (`(Degraded, Some(IssuerUnavailable))` — the old assertion accepted it) | 0 |
Harness: `/tmp/r3b-scripts/revert.sh` (exact string mutation, test, reverse mutation, test), removed at the end.

## Final checks (exit codes)
- `cargo clippy -p heimdall-app -p heimdall-issuer -p heimdall-store -p heimdall-contract -p heimdall-runtime --all-targets -- -D warnings`: 101, only
  `crates/runtime/src/managed_store.rs:1476` (`type_complexity`, R3-C2's `live_tests` WIP). Narrowed:
  `cargo clippy -p heimdall-app -p heimdall-issuer -p heimdall-store -p heimdall-contract --all-targets -- -D warnings`: 0;
  `cargo clippy -p heimdall-runtime --lib --test integration_issuer_m03 --test integration_runtime_m03 -- -D warnings`: 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall-issuer`: 0.
- `rustfmt --edition 2024 --check` on my files: 0 (my hunks in shared files checked clean).
- Reruns after the revert runs: issuer_m03 0 (19); heimdall-issuer 0 (12/33/30/6); contract 0 (41/89); store_m03 0 (30);
  managed_domain 0 (21); e2e_issuer_ceremony 0 (4, 2 ignored); heimdall-store 0 (20); runtime_m03 filtered 0 (5).
