# M03 wave 4, round 3 — worklog R3-C1 (managed cleanup)

Items (ADR-0008 §17.22): 4 (W4-R01 expiry destroys K_env), 9 (W4-R07 unfinished cleanup stays
discoverable), 10 (W4-R08 releasing a binding releases its slots).

## Decisions
- C1-1. Durable obligation without migration: `Txn::managed_cleanup_owed(env)` (store, new) lists
  (a) terminal grants (not `revoking`) with a credential instance not `destroyed`
  (`pending`/`installed`/`lost`; lost → destroyed is D2's "the rule fails" row), and (b) grants with
  a slot `held`/`clearing` for a **released** binding. Ordering makes the row the obligation: the
  instance moves to `destroyed` only after the files/endpoints/slots are clean; a slot is freed only
  after its binding's files and its mux path are clean.
- C1-2. `Txn::bindings_of_grant(grant)` (any state): `StoreCleanup` now finds released bindings of a
  grant (their references are gone) for file removal.
- C1-3. Expiry (item 4): `expire_grant` (scheduler) and `end_in`'s `Expired` arm (at use; recorded in
  the new `Ended.expired`, processed by `complete_withdrawals` after the commit and the gates) call
  `after_end_m03`: K_env destroyed (`ManagedEffects::destroy`) → the adapter's `revoke` (bounded;
  `StoreCleanup` via the adapter: slots, binding endpoints/files, connections) → only on success the
  instances `destroyed` (gate `release_exclusive`). `after_release_m03` (last reference) now uses the
  same function (instances last instead of first).
- C1-4. Supervisor `ended_slot_pass` now enumerates `held_slots_of_ended_grants ∪
  managed_cleanup_owed`, and per grant: `Operations::managed_end_destroy_keys` → `EndCleanup::after_end`
  → (ended grants, on success) `Operations::managed_end_instances_destroyed`.
- C1-5. Item 9: `StoreCleanup` per binding: `held → clearing` + slot files (`begin_slot`), binding
  files by generation from disk, and only when both succeeded the mux path + `clearing → free`
  (`finish_slot`).
- C1-6. Item 10: `release_checked`'s transaction moves the released managed binding's held slots
  `held → clearing` (`managed_driver_m03::release_binding_slots_in`), whether or not the grant lives
  on; after the commit `after_binding_release_m03` removes its endpoint/listing/files
  (`ManagedEffects::clear`, best effort). `StoreCleanup` on a grant that has not ended cleans only its
  released bindings; the supervisor pass finds them through (b). K_env is untouched until the last
  reference. The slot is free after the next ended-binding pass (not inside `release` itself: the app
  has no port for slot files).
- C1-7. Regression for item 10 uses a second consumer reference (seeded binding row + reference on the
  same grant) instead of a live delegation: a live managed `delegate` is refused
  `INTERACTION_REQUIRED` (R3C1-Q1, escalated).
- Tests: `crates/runtime/src/managed_store/live_tests/cleanup.rs` (child module of C2's `live_tests`,
  one `mod cleanup;` line added there to reuse `Live`/`Process`).

## Progress
- [x] item 4  - [x] item 9  - [x] item 10  - [x] revert runs  - [x] checks (strict clippy/xcheck blocked by others; see below)

## Commands (exit codes)
- `cargo check -p heimdall-store`: 0.
- `cargo test -p heimdall-runtime --lib cleanup`: 0 (6 passed: 5 new + `cleanup_clears_each_slot_by_its_own_generation`).

### Revert runs (`/tmp/r3c1/revert.py`: in-place substitution, applied → test → restored → test)
| Regression | Revert | Reverted | Restored |
|---|---|---|---|
| `expiry_at_use_without_held_slot_…`, `expiry_by_scheduler_with_held_slot_…` (and `…survives_failure_and_restart`) | r1: `expire_grant`'s and `complete_withdrawals`' `after_end_m03` calls disabled | 101 (3 FAILED) | 0 (3 ok) |
| `expiry_cleanup_obligation_survives_failure_and_restart` | r2: `managed_cleanup_owed` (a) lists nothing | 101 | 0 |
| `unfinished_cleanup_after_slot_files_removed_is_retried_until_clean` | r3: slots freed even when the binding's files failed | 101 | 0 |
| `released_slot_holder_frees_its_slots_while_grant_stays_live` | r4: `release_binding_slots_in` moves no slot (returns `false`) | 101 | 0 |
(The first restored r1 run hit another worker's in-progress compile error in `effects.rs` (101, a build
failure, not a test result); rerun after the tree built: 0.)

### Checks
- `cargo test -p heimdall-runtime --no-fail-fast`: 13/13 test binaries ok (lib 41, setup_dispatch 9, connections 43,
  issuer_m03 19, runtime 59 + 2 ignored, runtime_m03 51, session_lock 4 + 1 ignored, events 19, narrowing_m03 57,
  operations 186, operations_m03 37, setup 51, timegate 27); the run's exit 101 was the doctest step only
  (`extern location for heimdall_app does not exist`: another worker's concurrent rebuild replaced the rlib);
  `cargo test -p heimdall-runtime --doc` rerun: 0.
- `cargo test -p heimdall --test e2e_managed_m03 --test e2e_run_m02`: 0 (16; 54 + 1 ignored).
- `cargo test -p heimdall-app --tests`: 0 (lib 50, idempotency 3, lock_behavior 16, revocation 54, signing_gates 29).
- `cargo clippy -p heimdall-app -p heimdall-runtime -p heimdall-store -p heimdall-adapters --all-targets -- -D warnings`:
  101 — only `clippy::type_complexity` at `crates/app/src/operations/issuer_m03.rs:229` (R3-B, in progress); with
  `--no-deps` on runtime/store/adapters: 101 — only `type_complexity` at `crates/runtime/src/managed_store.rs` `live_tests`
  `Opts::wrap` (R3-C2, in progress). Diagnostic `… -- -D warnings -A clippy::type_complexity` over the four crates: 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 101, the same R3-B lint (clippy `-D warnings` on app).
- `rustfmt --edition 2024 --check`: `live_tests/cleanup.rs` 0, `supervisor.rs` 0, `ext_m03.rs` my region clean (the
  file's diff at :407 `write_issuer_doc` is R3-B's); `operations.rs` / `managed_driver_m03.rs` remaining diffs are
  R3-C2's (`stage_commit` ~7938, `cleanup_follower_binding` ~1459); `managed_store.rs` remaining diffs are in
  `live_tests/pipeline.rs` (R3-C2).
- Last rerun `cargo test -p heimdall-runtime --lib` (current tree): 101 — my 5 `live_tests::cleanup` tests ok; 3 R3-C2
  tests failing (`managed_prepare_failure_after_materialize_…` "no endpoint", `pipeline::driver_cleanup_failure_…`,
  `pipeline::crash_between_materialize_and_confirmation_…`), all on the preparation-failure path R3-C2 is editing; the
  first of them passed in my earlier full run with all my changes in place.
- Scratch `/tmp/r3c1` (revert script, logs) removed.
