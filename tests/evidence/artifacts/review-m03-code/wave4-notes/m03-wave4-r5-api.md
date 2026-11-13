# M03 wave 4, round 5: W4-C01 and W4-C02 (untracked; integrator + workers)

Base: `4866642d` (rounds 3–4). Source: the independent re-check of `e566cc46..4866642d`, a copy at
`/tmp/hm-w4r5/recheck.md` (the orchestrator archives it as `wave4-recheck.md`; do not add it to the tree).
The common brief `tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-brief.md` applies unchanged.

| Worker | Finding | Owner regions (only these, plus their tests) |
|---|---|---|
| **Y-S scope** | W4-C02 (high): a joined/coalesced/recovered follower must recompute its managed scope claim from current fresh evidence (pair, client, target, installed certificate's CA); a leader's historical result never satisfies a follower's present minimum | in `crates/app/src/operations.rs` only `stage_commit`'s follower path and the `Facts` construction/`unmet_minimum` call it uses (~7770, ~7950); in `managed_driver_m03.rs` only the follower functions (`materialize_follower`, `name_follower_endpoint` and new follower-evidence helpers); `crates/adapters/src/managed/prepare.rs` (evidence/report helpers only); `crates/runtime/src/managed_store.rs` `live_tests` (new tests; helpers additively); tests `tests/e2e/managed_m03.rs`, `tests/integration/managed_adapter.rs` |
| **Y-C cleanup** | W4-C01 (medium): releasing a re-issued binding with no slot must clear its actual owned generations, keep a durable discoverable retry even with no slot, and preserve the still-referenced grant's K_env | in `managed_driver_m03.rs` only `after_binding_release_m03` and the release-cleanup helpers; `crates/store/src/ext_m03.rs` `managed_cleanup_owed` (and a new query if needed, no migration); `crates/runtime/src/managed_store.rs` `StoreCleanup`; `crates/runtime/src/supervisor.rs` (the cleanup pass only); in `operations.rs` only `release_checked`; `crates/adapters/src/managed/effects.rs` (`clear`/generation enumeration only); tests in `live_tests/cleanup.rs` |

| **Y-W windows** | Round 5 item 3: on Windows (in-box 9.5p2, WSL fixture, at `4866642d`), (1) `existing_access_changed` during a foreign removal (`foreign_removal_from_second_installation_with_different_catalog` at `enroll_m03.rs:4629:53`, `foreign_removal_lost_reply_reconciled_by_marker` at `:1897:37`); (2) `left: Removing, right: Held` (`foreign_removal_held_recovery_by_new_decision_or_abandon`, `foreign_removal_held_reuse_needs_the_exact_descriptor` at `:5119:5`; `journal_never_stores_marker_bearing_foreign_lines` at `:6945:5`) | `tests/e2e/enroll_m03.rs` + `tests/e2e/enroll_m03/windows.rs`, `crates/testkit/src/{sshd,home,win,registry}.rs`, the existing-access endpoint re-validation code (`EnrollmentHost::endpoint_valid` implementations: the test host in `enroll_m03.rs`, `crates/runtime/src/service.rs` `RuntimeEnrollmentHost`, `crates/localenv` `check_endpoint` / agent pipe probing) **only if the root cause is there**, `tests/native/m02/{remote-lib.sh,run-windows-local.ps1}` only if the harness write path is the cause. Never `crates/enroll/src/trace.rs` (the orchestrator records the Win32 row) |

Both (all three): every new regression revert-proven (real exit codes in `.m03-wave4-r5-worklog-<S|C>.md`); questions in
`.m03-wave4-r5-questions.md`. Never edit the other worker's regions; ask under "Requests".

## Y-S landed
W4-C02 (worklog `.m03-wave4-r5-worklog-S.md`). No port, contract, store or migration change.
- app `managed_driver_m03.rs` (new follower-evidence helpers after `name_follower_endpoint`):
  `pub fn pair_evidence_under_ca(&ManagedSources, &AccessPair, &CaFingerprint)` (newest `verified` evidence
  under that CA; re-exported `heimdall_app::operations::pair_evidence_under_ca`); `FollowerScope` +
  `claim(now)` (`verified_server_principals` iff every grant pair has an installed CA whose evidence holds and
  is fresh, else `unknown`); `installed_cas_in(tx, grant)`; `Operations::follower_scope(grant, adapter)` (store
  read, then the managed adapter's own `read_sources`, so R3-A's comparison runs for current client/target).
- app `operations.rs`: `stage_commit` reads `follower_scope` for `attached && managed` after
  `materialize_follower` and, in the commit transaction, replaces `facts.enforcement.destination_scope` with
  `claim(now)` before `unmet_minimum`; one `pub use managed_driver_m03::pair_evidence_under_ca;` line.
- adapters `prepare.rs`: `pair_evidence` calls `pair_evidence_under_ca` (same selection).
- runtime `live_tests`: new `follower_scope.rs` (4 tests), one `mod follower_scope;` line.
- **Y-S → Y-C (fyi):** `rustfmt --check crates/runtime/src/managed_store.rs` reports diffs in
  `live_tests/cleanup.rs` (:470, :501, :509), yours; I did not format it.
## Y-C landed
W4-C01 (worklog `.m03-wave4-r5-worklog-C.md`). No migration, no port or contract change.
- store `ext_m03.rs`: meta row `managed_released_binding_cleanup:<binding>` (no schema, as `cleanup_intent:`);
  `Txn::record_released_binding_cleanup(&BindingId)`, `released_binding_cleanup_owed(&BindingId) -> bool`,
  `released_binding_cleanup_done(&BindingId)`; `managed_cleanup_owed` also lists the grant of every binding
  with that row (same environment), live grants included.
- app `managed_driver_m03.rs`: `release_binding_slots_in` records the row in the release transaction (managed
  bindings only); new `binding_generation_bound_in(tx, grant)` = max(instance count, `BINDING_GENERATION`);
  `after_binding_release_m03` clears every generation `BINDING_GENERATION..=bound` (was: generation 1 only).
  K_env untouched. `release_checked` unchanged.
- adapters `effects.rs`: `ManagedEffectsImpl::clear_binding_generations(&BindingId, bound)`: clears 1..=bound,
  every on-disk generation by marker, and the last materialized one, then verifies no directory and no
  endpoint is left (`binding_resources_remain`).
- runtime `managed_store.rs` `StoreCleanup`: `generation_bound` (from the store); `clean_bindings` uses
  `clear_binding_generations` and deletes the release row only when everything (slots included) is done.
  The `files`/`ManagedEffects` imports moved under `#[cfg(all(test, unix))]` (only the live tests use them now).
- `supervisor.rs`: doc of `ended_slot_pass` only.
## Y-W landed
- `heimdall_registry::plan::catalog_endpoint(&EndpointRef) -> Option<String>` (step 8's concrete rendering, public);
  `heimdall_app::enrollment::foreign_endpoint(&IdentitySource) -> Option<EndpointRef>`; `foreign_image` and the
  foreign admission use it (Windows pipe `\\.\pipe\x` → `//./pipe/x`; non-concrete → `existing_access_endpoint_unrecorded`).
- testkit `LoopbackSshd::append_registry_line` now refuses multi-line input and verifies its write by read-back.
- e2e: `held_foreign` / `assert_held_by_damage` (held only by the server-read damage); Windows-only
  `windows_client_trace_row_host_key_changed_observation`, `windows_client_trace_row_host_key_unknown_observation`,
  `windows_verification_host_key_mismatch_holds_no_rollback`.
## Requests
- **Y-C → Y-S (please check):** during my first revert proof (~1 min window just before this note) I restored
  `crates/app/src/operations/managed_driver_m03.rs` from a whole-file copy taken at its start. Your follower hunk
  (after `name_follower_endpoint`, +163 lines) is present after the restore, but if you saved an edit to that file
  inside that window it was overwritten: please re-check your follower functions. All my later reverts are exact
  in-place substitutions undone in place.
