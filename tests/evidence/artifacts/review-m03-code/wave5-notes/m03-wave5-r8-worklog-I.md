# M03 wave 5 round 8 — integrator worklog

Base `0cd94961`. Binding ADR-0008 §17.31 (1-5); re-check wave5-recheck.md (W5-C01..C05). No commits.
- [x] P8 (C01), G8 (C02) new workers; L5 (C03 + item 4) and K4 (C05) resumed. All parallel, background.
- L5 done: W5-C03 fixed — shared `finish_removal` (enrollment_m03/steps.rs) used by removal_confirmed
  and the manual-recovery absent arm. Regressions e2e_enroll_m03 recheck_manual_recovered_withdrawn_removal_clears_residual,
  recheck_manual_recovered_last_removal_drops_issuing_ca (unix); failed before fix (101), revert 101 -> 0.
  Item 4: purpose is journal-only (UncertainStep.purpose in enroll.journal receipt; store can't read
  it) -> not compared (Q-L5-13; option to persist it on the record). W5-C04's 3 mismatches covered by
  round-7 tests; revert re-run 101 -> 0.
- K4 done: W5-C05 fixed (issuer_cmd.rs finish_retirement; render.rs). Regression
  e2e_cli_m03 issuer::recheck_retire_after_new_item_restore_deletes_only_current_generation (macOS);
  revert 101 (exit 4 CAPABILITY_UNAVAILABLE) -> 0, shasum OK. issuer:: 3x green (1 under umask 002).
  Note: success envelopes have no effect field ("effect applied" = exit 0, OK, succeeded, no error).
  K4 reported "waiting on its own background work" — check for survivors at the end.
- P8 done: W5-C01 fixed (uninstall_cmd.rs stop_runtime confirmed + purge_locked: InstanceLock
  (runtime/src/instance.rs:36) -> final read -> bundle recheck -> delete -> release; 10 s wait; lock
  file kept). Unit regressions uninstall_cmd::tests::{uninstall_purge_refuses_unconfirmed_stop,
  uninstall_purge_excludes_runtime_start_while_locked, uninstall_purge_refuses_replacement_runtime,
  recheck_purge_must_exclude_writer_after_final_read}, each 101 when reverted -> 0, shasum OK. e2e
  uninstall_doctor::runtime_start_refused_while_the_purge_lock_is_held (passes without the fix too —
  guards the runtime's start-up order). Writer audit: only production read-write open is
  runtime/service.rs:498 after the lock at :493; all CLI paths read-only or through the runtime.
  Unconfirmed-stop refusal: SERVICE_UNAVAILABLE exit 5, no reason (a named reason = contract change).
- §17.31 item 6 (integrator): reason uninstall_shutdown_unconfirmed (SERVICE_UNAVAILABLE) in envelope
  + reason::M03 + golden + ADR-0006 row; uninstall_cmd not_purged sets it for NOT_STOPPED, next_command
  `heimdall service stop`, next_step text, message updated; asserted in
  uninstall_cmd::tests::uninstall_purge_refuses_unconfirmed_stop. Lock-held refusal (replacement
  runtime) stays reasonless — flagged Q-I-R8-1. Q-L5-13 accepted.
- Q-I-R8-1 ANSWERED/built: LOCK_HELD reuses uninstall_shutdown_unconfirmed; messages name the case; asserted in uninstall_purge_refuses_replacement_runtime; revert (LOCK_HELD excluded) 101 -> 0. ADR-0006 row updated.
- G8 done (W5-C02): one boundary in uninstall_fence_m03.rs (admit / fence_admit_reservation, no
  RwLock); both reservations hold the admission across their store write; decide(approve) + dispatcher;
  managed_reissue_pass + reverify_pass; step-result follow-through deferred (applied_unverified).
  Interleaving tests model_operations_m03 fence_acquisition_waits_for_{grant,verification}_reservation_past_its_check
  (revert 101 -> 0). Q-G8-1: integrator applied (a) enrollment_request admission, (b) issuer_request
  admission, (c) mod fence in tests/e2e/enroll_m03.rs. e2e fence:: 4 pass; reverts: deferral removed
  101 (1 failed); (a) removed 101 (direct admission); (b) removed -> no failure, so integrator added
  fence::recheck_direct_issuer_request_refused_under_uninstall_fence (revert (b) 101 -> 0).
  Q-G8-2 (verify_operation records a fence refusal as inconclusive) left for the orchestrator.
- [x] Final validation: run 1 check.sh overall 1 (clippy + clippy-windows 101: "link reference defined in list item" in tests/e2e/enroll_m03/fence.rs doc header; linux-xcheck 101 same) -> integrator fixed the doc list; run 2 check.sh every step 0 (2985 passed, 0 failed, 192 ignored), linux-xcheck 0. Release issuer lib 21p, release gate 3p; umask 002 all 0 (cli_m03 64p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 88p, ceremony 8p/2i, bin 173p). Notes archived as m03-wave5-r8-*.md.
