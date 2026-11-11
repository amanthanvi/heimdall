# M03 wave 4 worklog, U10-C (managed preparation, re-issue, slots, install view, instances, revocation data)

## Goal
Prompt items 1–8 (driver body, U2-Q1 instances, U2-Q2 install view, StoreSources impls, re-issue pass,
slots + run ManagedSlots, revocation data + post-release close + CA degrade helper, pair-mechanism opening).

## Decisions
- C1. Driver = `app::managed::driver::{drive, run_stages}`; store side in `operations/managed_driver_m03.rs`.
  Each store step its own `Operations::write`; each effect a bounded port call; a `managed.<step>` stage
  receipt (`Attempted`, same token, so `last_token`/`next_stage` are unaffected) between effects
  (one per install too). Receipts go to the open operation whose `Attempted` receipt carries the token.
- C2. **Materialize not run at preparation** (U10C-Q1): the binding is minted in `stage_commit`, after
  `prepare_from`; no production path creates a binding endpoint. `materialized: None` (fail closed).
- C3. Instances (U2-Q1): ID = first 16 bytes of K_env's SHA-256 digest (`instance_id_for`), so the
  instances of a grant are found from its entries' subject fingerprints (no new store query; U10C-Q6).
  Creation retains the gate (inside the insert transaction, before the row); release of a live instance
  is `release_exclusive` after every gate is released. Lost instances hold no gate.
- C4. Install view (U2-Q2): `Operations::managed_install_check` (read-only time assessment; grant
  `preparing|active|degraded`; no tombstone on it or an ancestor; bound and budget; stored entry equal and
  published; moved generation → re-validate). Runtime `OpsInstallView`. Switch flipped (doc constant).
- C5. Unwired driver: `managed_prepared` returns `None` (not `Err`), so the managed adapter's own
  `prepare_from` refuses `MANAGED_PREPARE_WITHOUT_DRIVER` (same error arm, nothing activated); this keeps
  U6's fixture-adapter suite (46 tests) valid. Wired + managed preference → opened in `ensure_precheck`
  and the two row-9 `no_mechanism` arms (`Some(meets unattended)` when the managed adapter is configured).
- C6. Revocation cleanup: keys + instances at narrowing.rs post-release point (`managed_after_narrowing`);
  files/slots/connections in the managed adapter's `revoke` (phase 2 round, after the gates) through a new
  `EndCleanup` hook (adapters), implemented by runtime `StoreCleanup` (slots by their own generation,
  `clear_slot_path` when the pair had no master, binding files by generation, `revocation_close` /
  `release_close` / `connection_deadline_pass` by the stored end state). A cleanup or discovery failure →
  `revoke` errs → round unconfirmed → kept and retried (D7 item 2). Release: `managed_after_release`
  (keys/instances, then the adapter's `revoke` for files/connections; release rule by stored state).
- C7. RevokeData: `remote_effects` carried from the adapter's `RevokeOutcome` (RoundAnswers merge),
  `owned_connections` + `notes` filled in the settling transaction for a managed cascade (mapping
  reproduced in app; recorded). M01/M02 results unchanged.
- C8. Re-issue pass in app (U10C-Q5): candidates = managed grants `degraded credential_reissue_pending`;
  `lock_blocks_reissue`; time `Safe`, bound, budget not expired (NeedsAnchor ok: reserve anchors);
  `run_stages(.., new_activation=false)`; lost → destroyed, `Repaired` → active, `reissued` event.
- C9. `StoreSources` terms recorded in `GrantScopes::pairs` (the activation's/re-issue's first effect,
  outside the bound) from the store: lock = `effective_behavior_with_floor(origin, policies, floor)`,
  policy = `effective_policy_in`. Never defaulted.
- C10. `run`'s `ManagedSlots` kept `UnavailableSlots` (U10C-Q2: needs IPC or a runtime-side claim in bind).
- C11. Tests: e2e target uses port-level fixtures (no adapters/credential edge in `heimdall`); real
  StoreSources/StoreCleanup/ManagedEffectsImpl cases are runtime unit tests in `managed_store.rs`.

## Shared-file edits (R2)
- `operations.rs`: `release_checked` (managed release cleanup), `drive_revoke` phase 3 (`fill_revoke_data`),
  `run_round` + `RoundAnswers` (carry `remote_effects`; the revoke round), its unit test literal
  (`..RoundAnswers::default()`), the two row-9 `no_mechanism` calls (4th argument).
- `narrowing.rs`: one call at the post-release cleanup point.
- `crates/credential/src/table.rs`: `INSTALL_STORE_VIEW_WIRED = true` + module doc only.

## Progress
- [x] driver, instances, install view, re-issue, revoke data, release, CA degrade helper, opening
- [x] runtime StoreSources/OpsInstallView/StoreCleanup; adapters EndCleanup
- [x] tests + revert runs
- [x] linux-xcheck / clippy narrowed (`--no-deps`): 0; the un-narrowed forms blocked by U10-A lints

## Commands (exit codes)
- `cargo test -p heimdall --test e2e_managed_m03`: 0 (10 passed).
- `cargo test -p heimdall-runtime --lib managed_store`: 0 (3 passed).
- `cargo test -p heimdall-adapters --test integration_managed_adapter`: 0 (46 passed) after C5
  (before C5: 41 failed `UNSUPPORTED_CLIENT`, the integrator's ensure hook with no wiring).
- `cargo test -p heimdall-app --tests`: 0 (lib 48, idempotency 3, lock_behavior 16, revocation 54,
  signing_gates 29). `cargo test -p heimdall-credential --tests`: 0 (managed_signer 39 + 1 ignored).
- `cargo clippy --no-deps -p heimdall-credential -p heimdall-adapters -p heimdall-runtime --all-targets -- -D warnings`: 0.
- `cargo clippy --no-deps -p heimdall --test e2e_managed_m03 -- -D warnings`: 0.
- `cargo clippy -p heimdall-app … --all-targets -- -D warnings`: 101, only lints in
  `operations/enrollment_m03{,/steps,/verify}.rs` (U10-A's, in progress); none in my files.
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 101, same U10-A lints in app.
  `bash tools/validation/linux-xcheck.sh --no-deps -p heimdall-runtime -p heimdall-adapters -p heimdall-credential`: 0.
- Windows clippy, `clippy-windows.sh` narrowed to `--no-deps -p heimdall-runtime -p heimdall-adapters
  -p heimdall-credential -p heimdall` (run as `bash -c "$(sed …)" tools/validation/clippy-windows.sh`): 0.
- `cargo test -p heimdall-runtime --tests`: 101 — only `integration_runtime_m03`'s
  `w0_m03_requests_fail_closed_before_any_record` and `capabilities_offered_after_activation` (an M03
  request now writes `high_water_mark`/`runtime_anchor`: the issuer/enrollment request paths, not mine);
  every other runtime target passed (lib 28, setup_dispatch 9, connections 43, issuer_m03 13, runtime 59).
- `cargo test -p heimdall --tests --no-fail-fast`: 101 — only `e2e_enroll_m03` (4 verification-state
  failures, U10-A/B in progress); lib 112, cli_m01 24, cli_m02 42, cli_m03 3, consumer_m03 6,
  deadline_m03 1, issuer_ceremony 4, managed_m03 10, run_m02 54, tui_m02 17 passed.
- Scratch revert copies were in a `/tmp` dir I created; removed. `target/` not pruned (shared with three
  running workers; `target/x86_64-unknown-linux-gnu` left for the integrator).

### Revert runs (fix reverted → test run → restored → test run)
| Regression | Revert | Reverted exit | Restored exit |
|---|---|---|---|
| `terms_absent_until_recorded_never_default_continue` (U6-Q5) | `terms()` → `.or(Some(GrantTerms::default()))` | 101 | 0 |
| `cleanup_clears_each_slot_by_its_own_generation` (U6-Q4) | clear at `generation.min(1)` | 101 | 0 |
| `install_view_refuses_tombstoned_stale_or_expired_grant` | drop the stored-bounds compare | 101 | 0 |
| `credential_instance_persisted_installed_then_destroyed_with_gate` (U2-Q1) | skip `managed_instance_installed` | 101 | 0 |
| `managed_effect_steps_run_outside_store_transactions` (row 21) | no receipt between installs | 101 | 0 |
| `revoke_result_reports_requested_and_committed_at` | skip `fill_revoke_data` | 101 | 0 |
| `reissue_after_runtime_process_restart_same_boot` | pass finds no candidates | 101 | 0 |
| `reissue_after_reboot_waits_for_time_confirm` | eligibility ignores the time verdict | 101 | 0 |
| `managed_preference_refused_unwired_activates_when_wired` | opening never true | 101 | 0 |
(A first reboot revert was a no-op, exit 0; replaced by the one above.)

## Blockers
- U10-A's in-progress `enrollment_m03*` lints block the app clippy and the Linux cross-check.
