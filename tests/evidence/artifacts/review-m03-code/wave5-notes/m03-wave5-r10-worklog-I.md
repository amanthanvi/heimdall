# M03 wave 5 round 10 — integrator worklog

Base `faf10bba`. Binding ADR-0008 §17.32 (1-4); re-check2 W5-D01..D04. No commits. Keep target/x86_64-pc-windows-gnu warm.
- [x] P8 (D01), G8 (D02+D03), L5 (D04) resumed in parallel.
- [ ] Integrator gap audit (independent reviewer) after they land.
- L5 done (W5-D04): verify_operation joins the Operations per-operation single-flight (verify_once
  body); covers every verification route. Probe fence::recheck2_deferred_verification_is_not_duplicated_by_two_steps
  (before: 4 certs, exit 101). Converge: fence::deferred_verification_is_not_duplicated_by_step_and_reconcile,
  fence::concurrent_reverification_resumes_run_one_verification (unix); found + fixed duplicate removal
  finalization (removal_without_step re-checks in its write): removal_finding_the_line_gone_is_finished_once_by_two_steps.
  Reverts 101 -> 0. No store claim (single writer under the instance lock; crash covered by resume).
- G8 done: D02 publish_issuance re-reserve takes fence_admit_publication (refused under held fence,
  nothing written); D03 Operations::write_admitted moves the admission into the spawn_blocking
  closure; other admitted routes get a per-tokio-task counted extension for writes started from the
  admitting task. Regressions (model) recheck2_publication_must_not_rereserve_under_held_fence,
  recheck2_cancelled_reservation_keeps_admission_until_store_write_finishes,
  cancelled_verification_reservation_keeps_admission_until_store_write_finishes, (app)
  cancelled_admitted_work_keeps_admission_until_its_store_write_finishes; reverts 101 -> 0.
  Limits: issuer-child talk not covered; tasks spawned from admitted work carry no extension.
  -> audit the task-id extension design.
- P8 done (W5-D01): RecoverySnapshot (Inventory::read, one ro txn) for confirm, fence re-read and
  final locked read; unchanged_but_for(now, retired) allows only own retirement progress. Store
  TABLE_RECOVERY classifies every table (Rows/Part/Discarded) + test recovery_snapshot_classifies_every_table.
  Regressions uninstall_cmd::tests::{recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped,
  recovery_snapshot_classifies_every_table, uninstall_purge_refuses_replaced_store_locator,
  uninstall_purge_refuses_new_final_enrollment, uninstall_purge_refuses_changed_issuing_set,
  uninstall_purge_admits_only_its_own_retirement}; reverts A/B/C 101 -> 0. P8 question: open ops =
  enrollment ops only; issuance/verification certificate records out.
- [x] Independent gap audit done (findings A1-A8, L1, L2 below; all fixed except A7 recorded safe).
- P8 readings ANSWERED (-> §17.32 item 6); classification test must name excluded op kinds (to do). Audit asked to cover G8's two limits.
- P8 follow-up: OPERATION_RECOVERY classifies every OperationKind (3 enrollment kinds included; others excluded with reasons); test operation_kinds_are_classified_for_the_snapshot; mutations (remove excluded, catalog deleted) 101 -> restored, shasum OK; uninstall_cmd:: 26/26.
- Independent audit (fresh reviewer, read-only; tree restored): A1 (medium, probe 101) pre-fence
  grant reservation still signed/published/installed under a held fence; A2 (high, probe 101)
  pending RegisterIssuer decision's store locator not in the snapshot (decisions discarded); A3
  retirement allowance too broad; A4 classification test tables only; A5 ops compared by id/kind/state
  only; A6 issuer_supervision_pass no admission (loads K_ca under fence); A7 timegate anchor write
  outside write_admitted (not recovery-relevant); A8 single-flight window after a cancelled leader
  (record_verification no expected-state check); L1 cancel during frame write -> restart loads K_ca
  unadmitted; client stuck at Loading after a cancelled Load; L2 = A1.
- Assigned: G8 A1 A7; P8 A2 A3 A4 A5; L5 A8; K4 A6 L1.
- G8 A1 fixed: fence_admit_pipeline held for all of managed::driver::run_stages (extends in admitted
  work; the ensure lead takes its own new-work admission, refused while held/acquiring);
  publish_issuance refuses under a held non-holder fence (entry stays reserved). Regressions (model)
  reva_probe_pre_fence_reservation_publishes_under_held_fence, reservation_joined_during_acquisition_cannot_publish_after;
  (e2e) fence::acquisition_waits_for_in_flight_activation, fence::activation_refused_while_fence_is_being_acquired;
  reverts 101 -> 0. A7 left as is (time anchor not recovery-relevant, monotonic) — recorded.
- L5 A8 fixed: verify_operation runs the leader in its own spawned task owning the flight + a fence
  extension (released after the result write); record_verification CAS (state, op open, verdict
  count) discards a stale result. Debug hooks debug_pause_next_verification_result_write,
  debug_verify_operation, debug_verify_without_flight. Regressions fence::cancelled_verification_leader_with_a_pending_result_write_is_never_repeated
  (inline leader: 4 certs, 101), fence::verification_result_write_records_only_the_run_it_started_from
  (CAS off: 101); restored 0.
- P8 A2-A5 fixed: snapshot holds pending RegisterIssuer decisions whole (DECISION_RECOVERY lists the
  other 10 kinds); A3 retire run observed via issuer.status before/after, only that exact change
  accepted; A4 META_RECOVERY + meta/decision-kind enumeration tests + DB-level insert/modify cases;
  A5 open op = record + SHA-256 of stage receipts + outstanding token. Regressions:
  uninstall_purge_refuses_pending_registration_locator, uninstall_purge_refuses_foreign_change_after_declined_retire,
  uninstall_purge_admits_only_its_own_retirement (extended), meta_keys_are_classified_for_the_snapshot,
  decision_kinds_are_classified_for_the_snapshot, uninstall_purge_refuses_journal_change_on_unchanged_state;
  7 reverts 101 -> 0. P8 question: remote_revocation:/cleanup_intent: meta keys left out.
- P8 meta-key ruling ANSWERED (-> §17.32 item 7): remote_revocation IN (retry, list, confirm, snapshot); cleanup_intent OUT if local cleanup covers every path (verify). P8 resumed.
- K4 done: A6 issuer_supervision_pass holds uninstall_fence_admit for the whole pass (no holder
  carve-out needed: holder's retire resumes inline in decide); L1 ClientConfig.load_gate (wired in
  service.rs via Operations::issuer_load_gate, weak handle) gates every spawn+load; cancelled Load and
  cancelled start recover. Regressions integration_issuer_m03 issuer_supervision_pass_does_nothing_under_a_held_fence;
  integration_issuer_child broken_link_restart_under_a_held_fence_loads_nothing_until_the_lift,
  cancelled_load_recovers_without_an_explicit_unlock, cancelled_start_is_crashed_and_restarted_on_demand;
  reverts 101 -> 0. K4 noted a `fence_admit_pipeline` unused warning at some point — check clippy.
- P8 item-7 work: remote_revocation in snapshot + listed (report/JSON pending_remote_revocations);
  retry route missing (Operations::retry_remote_revocation only called by the supervisor) -> fail
  closed: REMOTE_REVOCATION_RETRY_ROUTE=false refuses a purge with pending records (CAPABILITY_UNAVAILABLE,
  exit 4). cleanup_intent condition NOT met before: no uninstall step removed <run>/b/* or
  <state>/managed/*; fixed: purge_state -> sweep_managed under the lock (refuses links).
  Regressions uninstall_lists_pending_remote_revocations, uninstall_purge_refuses_remote_revocation_added_in_window,
  uninstall_purge_removes_every_cleanup_intent_path, uninstall_purge_refuses_a_linked_managed_dir (unix);
  reverts 101 -> 0. Escalation Q-I-R10-1: the retry route (additive holder-only fence request variant).
- Q-I-R10-1 ANSWERED: additive holder-only RetryRemoteRevocations; switch removed. P8 resumed (contract + dispatch + fence grant).
- P8 retry route built: UninstallFenceRequest::RetryRemoteRevocations (holder-only; non-holder
  SERVICE_UNAVAILABLE/uninstall_in_progress), existing retry_remote_revocation does one ordinary round
  (no re-arm); uninstall sends it after acquire, before shutdown; lists pending in confirmation + report;
  switch removed; final check accepts exactly the retry's reported counts. Regressions
  model_operations::uninstall_fence_retry_is_one_ordinary_round, dispatch::tests::uninstall_fence_retry_is_holder_only,
  uninstall_lists_and_confirms_pending_remote_revocations, uninstall_purge_refuses_remote_revocation_added_in_window,
  uninstall_purge_admits_exactly_its_own_retry; reverts 101 -> 0. ADR-0006 §16.6 row; schema +
  journaled-kinds golden additive. Accepted: P8's test addition in tests/model/operations.rs.
- [x] Final validation: check.sh every step 0 (3024 passed, 0 failed, 192 ignored; 19 min, warm Windows target); linux-xcheck 0; umask 002 all 0 (cli_m03 64p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 98p, ceremony 8p/2i, managed 16p, bin 190p). Notes archived as m03-wave5-r10-*.md.
