# M03 wave 5 round 3 — worker U3 worklog (uninstall, inventory, fence)

Base `a4a41d9e`. Items: §17.27 item 1 (W5-R01, W5-R02), item 2 (W5-S01), item 3 for uninstall.
Owner files: see `.m03-wave5-r3-api.md` R1 row U3.

## State
- [x] Read brief, api, §17.26/§17.27, W5-R01/R02/S01, uninstall_cmd.rs, store ext_m03, bundle builder
      (`crates/app/src/issuer.rs` mod `bundle`), U2 notes.
- [x] Request to D3: `pub(super) mod world` / `pub(super) mod terminal` in enroll.rs (race e2e).
- [x] store: `Txn::outstanding_obligations()` (read-only) + `OutstandingObligations`, `OpenEnrollmentOperation`
- [x] contract: `BundleForeignRemoval` + `RecoveryBundle.foreign_removals` (additive); `Request::UninstallFence
      (UninstallFenceRequest::{Acquire,Release})` (service-control/1, Synchronous); reasons
      `uninstall_in_progress` (SERVICE_UNAVAILABLE), `uninstall_inventory_changed` (CAPABILITY_UNAVAILABLE → exit 4);
      m03-reasons golden, journaled-kinds golden, tests/contracts/m02.rs samples
- [x] bundle builder `export_with_foreign` (app/issuer.rs) + `issuer_bundle` reads foreign removals
- [x] app fence `operations/uninstall_fence_m03.rs` + gates; runtime `ConnectionScope` + arm (dispatch.rs)
- [x] uninstall: inventory, guard, ack, bundle check, fence, revalidation, final pre-purge check, retire-fate preface
- [x] unit tests: app (2), runtime dispatch (2), uninstall_cmd (4 new) pass
- [x] schemas regenerated; ADR-0006 §16.6 rows; questions Q-U3-1..4
- [x] e2e: foreign abandoned purge, withdrawn late_write purge, race, pty --json preview — all pass
- [x] revert proofs; umask 002; clippy host/windows; linux-xcheck; contracts — DONE (see Commands)

## Decisions
- "unresolved late_write" = `late_write.is_some()`: no code path clears it today (grep), so any record
  carrying it is outstanding regardless of state.

- Fence lifetime: bound to the connection (dispatcher clone = connection scope; Drop releases); one
  holder; acquire drains in-flight admissions (RwLock, ≤20 s); gates listed in uninstall_fence_m03.rs docs.
- Uninstall: one session with service-control/1 for the whole run; Shutdown sent on it (fence ends with
  runtime). Last check after shutdown, before purge_state: obligations equal to confirmed, else exit 4.

## Commands (exit codes)
- `cargo test -p heimdall-app --lib uninstall_fence` 0 (2 passed)
- `cargo test -p heimdall-runtime --lib uninstall_fence` 0 (2 passed)
- `cargo test -p heimdall --bin heimdall uninstall_cmd` 0 (15 passed)
- schemas regenerated (request, ipc.client-message, recovery-bundle: additions only); `cargo test -p heimdall-contract` 0 (43+90)
- `cargo test -p heimdall-domain --lib golden` 0; `cargo test -p heimdall --bin heimdall m03_reasons` 0
- e2e (umask 002): `uninstall_doctor::uninstall` 6 passed (0); `uninstall_json_shows_the_preview_on_the_terminal` 0
- `cargo test -p heimdall --test e2e_cli_m02 uninstall` 0 (8 passed)
- revert proofs (/tmp/u3-revert/revert.py; restore sha match each; rerun 0):
  R1-e2e 101, R1-unit 101 (foreign: Vec::new()); R2-e2e 101, R2-unit 101 (filter !is_final only);
  F1-app 101 (fence_admit never refuses); F2-dispatch 101 (scope Drop no release);
  F3-revalidate 101 (fence_and_revalidate always Ok); P1-pty 101 (old kept_remote listing)
- race appended after D3's `pub(super) mod world`: `uninstall_purge_race_with_concurrent_enrollment_keeps_state` 0;
  S1-race revert (fence call + last check removed) 101, restore sha match, rerun 0
- rustfmt --edition 2024 on owned files; host clippy (contract, store, app, runtime, heimdall --all-targets
  -D warnings) 0; clippy-windows.sh 0; linux-xcheck.sh -p heimdall -p heimdall-app -p heimdall-store
  -p heimdall-runtime -p heimdall-contract 0
- umask 002: e2e_cli_m03 full 0 (55 passed, 3 ignored); heimdall bin 0 (168); app lib 0 (60); runtime lib 0
  (60); heimdall-store 0 (21); integration_issuer_m03 0 (21); model_operations_m03 0 (37);
  integration_runtime_m03 0 (53); integration_store_m03 0 (31); e2e_enroll_m03 0 (69);
  integration_issuer_store 0 (30); e2e_cli_m02 0 (42); contract 0 (43+90)
- scratch /tmp/u3-revert, /tmp/u3-staging removed. ./target is 89G (linux cross 31G, windows cross 2.5G,
  debug 54G): left for the integrator (shared with K3/D3 runs in flight).

## Round 3b — §17.28 item 1 (Q-U3-2 ruling)
- Gate moved to dispatch (`runtime::dispatch::fenced` + ConnectionScope; non-holder fenced requests hold the
  admission guard to their end; holder runs in `app::operations::as_fence_holder`). App request gates removed;
  app keeps `fence_check` in `reserve_issuance_with` (holder scope exempt) + the two passes.
- Fenced: enrollment apply/verify/remove/reconcile/abandon/step; issuer register/unlock/retire; decide approve.
  Allowed: reads, deny, step_result, bundle_written, M01/M02 requests. Table in api § U3.
- Revalidation: `app::operations::unresolved_remote_steps` (journal outstanding|uncertain); purge refused
  `uninstall_remote_step_unresolved` (CAPABILITY_UNAVAILABLE, exit 4); golden + ADR-0006 §16.6 row 4 + questions note.
- Tests: app `uninstall_fence_checks_work_no_request_carries`, `..._acquire_waits_...`,
  `unresolved_remote_steps_lists_dispatched_and_uncertain_steps`; runtime
  `uninstall_fence_refuses_remote_and_ca_work_from_other_connections`; e2e (unix)
  `uninstall_purge_refuses_unresolved_remote_step`, `uninstall_fence_scope_end_to_end` (raw IPC holder +
  paused pre-fence step).
- Revert proofs (each: restore sha match, rerun 0): A step/abandon/retire unfenced → e2e 101, dispatch table 101;
  B step_result fenced 101; C deny fenced 101; D approve unfenced 101; E holder not exempt 101; F unresolved
  check off 101.
- Commands: host clippy 0; clippy-windows 0; linux-xcheck (heimdall, app, runtime, contract) 0; schema export
  diff 0; contract 0 (133); heimdall bin 0 (168); app lib 0 (61); runtime lib 0 (61); e2e_cli_m03 0 (58, 3
  ignored); e2e_enroll_m03 0 (69); integration_runtime_m03 0 (53); domain golden 0. All under umask 002.
- Three `hm-i-*/program/heimdall` processes (ppid 98320) seen in a name listing: not started by U3; untouched.
