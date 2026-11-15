# M03 wave 5, round 8 — ownership (integrator)

Base `0cd94961`. Binding ADR-0008 §17.31 items 1–5; re-check `review-m03-code/wave5-recheck.md`.

| Worker | Item | Owner files |
|---|---|---|
| **P8** | 1 (W5-C01) | `crates/heimdall/src/uninstall_cmd.rs`; the runtime's instance lock (`InstanceLock`, `service.lock`: find its module in `crates/runtime/src/`, add a CLI-usable acquire if needed, additive); `tests/e2e/cli_m03/uninstall_doctor.rs`; runtime lock tests. The **writer audit** is read-only except for fixes inside these files; report every other writer with file:line and whether it takes the lock or goes through the runtime. |
| **G8** | 2 (W5-C02) | `crates/app/src/operations.rs` (reservation + admission functions only, list them), `crates/app/src/operations/{uninstall_fence_m03.rs,managed_driver_m03.rs}`, `crates/app/src/operations/enrollment_m03/steps.rs` (the `StepResult` follow-through deferral only, coordinate with L5), `crates/runtime/src/{dispatch.rs,supervisor.rs}` and the supervisor pass sites; tests in app/runtime/e2e |
| **L5** | 3 (W5-C03), 4 | `crates/app/src/operations/enrollment_m03.rs` and `enrollment_m03/**` (except G8's `StepResult` deferral in `steps.rs`), `crates/store/src/ext_m03.rs`, `tests/e2e/enroll_m03.rs`, `tests/integration/store_m03.rs` |
| **K4** | 5 (W5-C05) | `crates/heimdall/src/{issuer_cmd.rs,issuer_cmd/**}`, `crates/issuer/src/**`, `crates/app/src/operations/issuer_m03.rs`, `tests/e2e/cli_m03/issuer.rs` |

Shared-file rule: `enrollment_m03/steps.rs` is L5's, except the step-result follow-through deferral (G8).
G8 and L5 coordinate under Requests before editing it. Contract changes: none expected; escalate.

## Requests
- **L5 → G8 (steps.rs regions):** L5 edits only `removal_confirmed` (split into a shared `finish_removal`) and the `ReconcileClass::ManualRecoveryLinePresent | …LineAbsent` arm of the reconcile recording. The `StepResult` follow-through deferral is yours; L5 does not touch it.
- **G8 → L5 (steps.rs):** G8 edits only `Operations::enroll_step_result` in `enrollment_m03/steps.rs` (the `if verify_after { … }` follow-through: deferred while the fence is held or being acquired). Nothing else in `steps.rs`.
- **G8 → L5 (enrollment_m03.rs, two one-line edits; please apply, or say so and G8 applies them):** (a) first statement of `Operations::enrollment_request`: `let _admission = self.enrollment_fence_admission(&req)?;` (G8's new fn in `uninstall_fence_m03.rs`: refuses `uninstall_in_progress` for the fenced actions while another connection holds or is acquiring the fence, and holds the shared admission until the request ends; `None` for `Preview`/`StepResult` and in the holder's scope). (b) G8 treats `Operations::reverify_pass` (a supervisor pass site, G8's per R1) as G8's: its fence check becomes `let Ok(_admission) = self.uninstall_fence_admit() else { return Ok(Vec::new()) };` held across `reverify_due()`. L5: object here if you are editing that fn.
- **G8 → L5 (verify.rs, defensive, optional):** in `verify_operation`, an `Err(e)` from `run_verification` with `e.reason == Some(reason::UNINSTALL_IN_PROGRESS)` should be returned (`return Err(e)`), not recorded as an inconclusive `Observed`. With G8's boundary every verification caller already holds the admission, so this should not occur; it guards a route G8 missed.
- **G8 → K4 (issuer_m03.rs, one line):** first statement of `Operations::issuer_request`: `let _admission = self.issuer_fence_admission(&req)?;` (same semantics; `None` for `Status`, `Bundle`, `BundleWritten` and in the holder's scope).
- **G8 → L5 (`tests/e2e/enroll_m03.rs`, one item):** please add next to `mod windows;`: `/// ⟨§17.31 item 2 (W5-C02)⟩ G8's fence regressions.` `#[cfg(any(unix, windows))]` `#[path = "enroll_m03/fence.rs"]` `mod fence;` — G8 owns the new file `tests/e2e/enroll_m03/fence.rs` (uses `super::fx::*` only; no change to `fx`).
- **G8 → Integrator (blocking, Q-G8-1):** L5 and K4 finished without applying the G8 requests above. Please apply (a) `enrollment_request` and (b) `issuer_request` one-liners and (c) the `mod fence;` line, or authorize G8 to apply them (answer under `## G8` in the questions file). Everything else of G8 is landed and verified.
## Worker sections
### P8
W5-C01 landed (compiles; tests pass here). Files: `crates/heimdall/src/uninstall_cmd.rs`,
`tests/e2e/cli_m03/uninstall_doctor.rs`. **No runtime change**: the CLI uses the existing
`heimdall_runtime::InstanceLock::try_acquire` (`crates/runtime/src/instance.rs:36`, std
`File::try_lock`: flock on Unix, LockFileEx on Windows); no new dependency, no contract change.
- `stop_runtime` (now generic over `cli::Session`) is `false` on a refused/failed shutdown or a
  lost connection; `purge_after_stop` refuses on `!stopped` before reading or deleting anything.
- `purge_locked`: take `service.lock` (bounded wait `LOCK_WAIT` = 10 s, because a stopping runtime
  drops `instance.json` before its lock) -> final `Inventory::read` (`same_obligations`) -> bundle
  re-check (`enrollment_refusal` against the confirmed inventory, file + digest re-read) ->
  `purge_state` -> release. The lock file is **never deleted** (unlinking a held flock file lets a
  start-up lock a fresh inode at the same path); released only after the deletion, after which a
  start-up finds no database and starts a new installation.
- Refusals after the stop: `SERVICE_UNAVAILABLE`, exit 5, retryable, **no reason** (no existing
  reason fits: `uninstall_in_progress` means a held fence), effect `partial` (rollback/stop
  happened), report kept under the error, `next_command: heimdall uninstall --purge-state`.
  Messages: not confirmed stop / another runtime holds the lock / lock I/O failure. A changed
  inventory under the lock stays `uninstall_inventory_changed` (exit 4, partial); a bundle that no
  longer passes stays its `bundle_required`/`bundle_redacted` (exit 4, partial).
- Test hook: a `paused: impl FnOnce()` parameter of `purge_locked` between the final read and the
  deletion; production passes `|| {}`. **No `HEIMDALL_TEST_*` variable; no release-gate probe owed.**
- Tests (`uninstall_cmd::tests`): `uninstall_purge_refuses_unconfirmed_stop`,
  `uninstall_purge_excludes_runtime_start_while_locked` (real `Service::start_with` at the pause
  point -> `AlreadyRunning`, db byte-identical), `uninstall_purge_refuses_replacement_runtime`
  (real in-process replacement `Service` writes, purge refuses; brief hold is waited for),
  `recheck_purge_must_exclude_writer_after_final_read`. e2e:
  `uninstall_doctor::runtime_start_refused_while_the_purge_lock_is_held` (real `service run`,
  test config, scratch account, exit 5, db unchanged).
- Writer audit: every production read-write `Store::open` is `crates/runtime/src/service.rs:498`,
  after `InstanceLock::try_acquire` at `:493`; every CLI open is `open_read_only`; every CLI write
  goes through the runtime. No unlocked direct writer found; nothing to fix outside my files.
### G8
- **Landed (compiles; host clippy app+runtime --all-targets -D warnings exit 0):**
  - `app::operations::uninstall_fence_m03` rewritten around one boundary: state `{holder, admitted, acquiring}`
    + `Notify` (the tokio `RwLock` is gone; an admission never waits, so nested admissions cannot deadlock
    against a waiting acquisition). `Operations::uninstall_fence_admit() -> Result<FenceAdmission, OpError>`
    (new work: refused while held **or being acquired**; holder scope exempt), `enrollment_fence_admission(&req)`,
    `issuer_fence_admission(&req)`, `pub(crate) fence_admit_reservation()` (refused while held; joins while
    acquiring, so the acquisition waits for it). `FenceAdmission` is now an owned guard (no lifetime).
    `uninstall_fenced(&Request)` (re-export of `fenced`, moved from `runtime::dispatch`; dispatch keeps a thin
    wrapper). `uninstall_in_progress()` now carries effect `none`. Removed: `uninstall_fence_admission()`,
    `fence_check()`. Debug builds only: `Operations::debug_pause_next_reservation() -> ReservationPauseControl`.
  - Reservations: `reserve_issuance_with` (operations.rs) and `reserve_verification` (verification_m03.rs,
    reservation fn only; the file has no R1 owner) take `fence_admit_reservation` before their check and hold
    it to the end (store write included).
  - Routes: `Operations::decide` (approve only) admits; dispatcher uses `uninstall_fence_admit` for fenced
    requests; **pending (Q-G8-1): `enrollment_request`, `issuer_request` one-liners.**
  - Passes: `managed_reissue_pass` holds an admission for the pass (skips if refused); supervisor wraps
    `reverify_pass` the same (`supervisor.rs` `managed_pass`). Not wrapped: `issuer_supervision_pass` (no
    reservation/dispatch; it may start the issuer child the holder's inline retire needs),
    `enrollment_step_timeout_pass` (local only).
  - `enroll_step_result` (steps.rs, that fn only): result recorded; initial verification only when admitted,
    else deferred (record `applied_unverified`, op running, nothing outstanding; picked up by `enroll step`
    `Next::Verify` or `enroll reconcile`). The CLI drive then asks `step`, which is refused exit 5.
- **Tests:** app `uninstall_fence_m03::tests::{uninstall_fence_checks_work_no_request_carries (+decide),
  uninstall_fence_acquire_waits_for_admissions_in_progress (+join/refuse), uninstall_fence_dropped_acquisition_reopens_admission}`;
  `model_operations_m03::{fence_acquisition_waits_for_grant_reservation_past_its_check,
  fence_acquisition_waits_for_verification_reservation_past_its_check}`; e2e `tests/e2e/enroll_m03/fence.rs`
  (needs the `mod fence;` line, Q-G8-1(c)): `fence::{recheck_allowed_step_result_does_not_start_new_issuance_under_fence,
  deferred_verification_runs_after_the_fence_lifts, recheck_verification_reservation_refused_under_uninstall_fence,
  recheck_direct_admission_refused_under_uninstall_fence}`.
### L5
- **Item 3 (W5-C03), landed:** `enrollment_m03/steps.rs::finish_removal(tx, emit, ctx, event, updated, now)` is the one
  post-removal finalization. It clears the `late_write` residual (origin `withdrawn`/`abandoned` + D5 §6.7 via
  `verify::removal_settles_late_write`), moves the record with the caller's event, and applies the issuing-set rule
  (§17.29 items 9-10). Callers: `removal_confirmed` (remove/rollback confirmed, already removed, reconcile `applied`),
  and the manual-recovery arm for line absent with purpose removal/rollback. Its event (`ManualRecoveryLineAbsent`)
  and settlement are unchanged. Regressions (`e2e_enroll_m03`, `#[cfg(unix)]`):
  `recheck_manual_recovered_withdrawn_removal_clears_residual`, `recheck_manual_recovered_last_removal_drops_issuing_ca`.
- **Item 4:** the recovery `purpose` is not persisted where `transition_enrollment` can read it (Q-L5-13), so no
  purpose check. The round-7 hold checks cover W5-C04's three mismatches. No store change this round.
### K4
- Landed (W5-C05): `issuer_cmd::finish_retirement` separates the current item from displaced ones; after
  the current item is deleted and confirmed, a displaced item is never a failure (access-denied: kept,
  never deleted, Keychain Access note; other refusal: kept, manual-delete note). Exit 0, no restore
  advice; `render::retired` takes notes; a retired CA's orphan renders no restore advice.
- New helper `issuer_cmd::manual_delete_instruction`. Regression
  `issuer::recheck_retire_after_new_item_restore_deletes_only_current_generation` (macOS).
