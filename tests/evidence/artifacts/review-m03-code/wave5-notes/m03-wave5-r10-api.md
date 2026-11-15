# M03 wave 5, round 10 — ownership (integrator)

Base `faf10bba`. Binding ADR-0008 §17.32 items 1–4; re-check `review-m03-code/wave5-recheck2.md`.

| Worker | Item | Owner files |
|---|---|---|
| **P8** | 1 (W5-D01) | `crates/heimdall/src/uninstall_cmd.rs`, `tests/e2e/cli_m03/uninstall_doctor.rs`; read-only store helpers it needs in `crates/store/src/ext_m03.rs` (additive, a read) |
| **G8** | 2 (W5-D02), 3 (W5-D03) | `crates/app/src/operations.rs` (reservation, publication and admission code: `reserve_issuance_with`, `publish_issuance`, `reserve_entry` and callers), `crates/app/src/operations/{uninstall_fence_m03.rs,verification_m03.rs,managed_driver_m03.rs}`, the store write helper (`Operations::write` or its equivalent) if the admission must move into it; tests in app/runtime/e2e `fence.rs`, `tests/model/operations_m03.rs` |
| **L5** | 4 (W5-D04) | `crates/app/src/operations/enrollment_m03.rs` and `enrollment_m03/**` (verify, steps, passes, reconcile); tests in `tests/e2e/enroll_m03.rs` / `enroll_m03/fence.rs` (add, coordinate with G8 under Requests) |

Shared: `tests/e2e/enroll_m03/fence.rs` (G8 and L5 add tests; append only). Contract changes: none
expected; escalate.

## Requests
- **P8 (done, FYI integrator):** the §17.32 item 7 route landed in the granted files; P8 also appended
  one model test to `tests/model/operations.rs` (`uninstall_fence_retry_is_one_ordinary_round`, it
  reuses the r1310 adapter world) and one sample line to `tests/contracts/m02.rs`.
- **L5 → G8 (`tests/e2e/enroll_m03/fence.rs`, append only):** L5 appends `recheck2_deferred_verification_is_not_duplicated_by_two_steps` at the end of the file and touches nothing above it. In `enrollment_m03/**`, L5 edits `verify.rs::verify_operation` (wraps it in the per-operation flight) and nothing in the fence admission calls.
- **L5 → G8 (A8, FYI, no edit of your files):** `verify_operation` now runs its leader in a spawned task. That task owns the flight and a counted `UninstallFence::write_extension()` taken from the calling task, held until the verification and its result write finish. If you change the semantics of `write_extension`, tell L5.
## Worker sections
### P8
W5-D01 landed. Files: `crates/heimdall/src/uninstall_cmd.rs`; `crates/store/src/ext_m03.rs` (additive
reads + consts only, no migration, no write path). No contract change.
- **One type** `RecoverySnapshot`, produced by `Inventory::read` (same read-only txn) for the
  confirmation read, the fence re-read and the final read under `service.lock`. Contents: every row
  and column of each `Rows` table (`issuers` incl. `record_json` with `store_locator` and
  `displaced_store_locators` = orphan_store_items; `enrollments` in every state incl. `late_write`
  token, `removal_origin`, hold; `foreign_removals` in every state; `pair_preferences` issuing set),
  the open/unresolved enrollment operations + unresolved remote steps, the environment, and the
  projection resources not confirmed absent.
- **Final check** `Inventory::unchanged_but_for(now, retired)`: equal but for the CAs whose
  retirement this uninstall ran (fate retired or the run stopped part way): their state may move
  along retiring/unloaded/deleted/retired (+`retired_at`) and their displaced locators may only
  shrink; recorded locator and every other field must match. Projection resources must be absent.
  Otherwise `PurgeEnd::Changed` → `uninstall_inventory_changed` (exit 4, effect partial).
- **Kind enumeration**: `heimdall_store::ext_m03::TABLE_RECOVERY` classifies every schema table as
  `Rows` / `Part(reader)` / `Discarded(why)`; `RECOVERY_IGNORED_COLUMNS` lists the excluded columns
  (pair projection state/generation, mechanism, updated_at). Test
  `recovery_snapshot_classifies_every_table` compares the list with `Txn::schema_tables()` of a
  freshly migrated db (a new table fails until classified), checks each ignored column exists and
  that each `Rows`/`Part` entry has a case proving a change refuses (a new entry without a case
  panics). `recovery_rows` is `SELECT *`, so a new column of a `Rows` table joins automatically.
- **Operation kinds** (§17.32 item 6): `OPERATION_RECOVERY` (uninstall_cmd.rs) lists every
  `OperationKind` as included (`enrollment.*`) or excluded with its reason; the snapshot's open
  operations pass through it. Test `operation_kinds_are_classified_for_the_snapshot` enumerates
  `OperationKind::ALL`: a kind unlisted or listed twice, or an enrollment kind excluded, fails.
- **Audit A2-A5**: pending `RegisterIssuer` decisions are in the snapshot (`DECISION_RECOVERY`, every
  `DecisionKind` classified; `decision_kind_name` has no wildcard); `META_RECOVERY` classifies every
  meta key (only `self_environment_id` included); each open enrollment operation is compared whole
  with a SHA-256 of its stage receipts and its outstanding step token; own retirements are exactly
  the CA as this session observed it before/after each run (`OwnRetirement`; a declined run admits
  nothing). Classification test cases go through the database (insert/modify/delete where the store
  can). New tests: `uninstall_purge_refuses_pending_registration_locator` (audit probe
  `revp_probe_pending_registration_locator_is_accepted`), `..._foreign_change_after_declined_retire`,
  `..._journal_change_on_unchanged_state`, `decision_kinds_are_classified_for_the_snapshot`,
  `meta_keys_are_classified_for_the_snapshot`.
- **§17.32 item 7 (Q-I-R10-1), built:** `UninstallFenceRequest::RetryRemoteRevocations` (contract,
  schema + `journaled-kinds` golden + contract sample by addition; ADR-0006 §16.6 row), dispatcher arm
  (`as_fence_holder`), app `Operations::uninstall_fence_retry_remote_revocations` (holder-only:
  `SERVICE_UNAVAILABLE`, `uninstall_in_progress` iff another holds it; one ordinary
  `retry_remote_revocation(root, configured cap)` per record, no re-arm). Uninstall sends it after
  `acquire`, before the stop; the confirmation lists pending records and the retry; the report adds
  `remote_revocation_retries`; the final check admits exactly the answered counts
  (`meta_unchanged_but_for`). `REMOTE_REVOCATION_RETRY_ROUTE` and its refusal are removed; a purge is
  refused only if the retry request itself fails. The purge sweeps `<state>/managed` and `<run>/b`.
- Tests: `recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped` (probe, both
  variants), `recovery_snapshot_classifies_every_table`, `uninstall_purge_refuses_replaced_store_locator`,
  `uninstall_purge_refuses_new_final_enrollment`, `uninstall_purge_refuses_changed_issuing_set`,
  `uninstall_purge_admits_only_its_own_retirement`.
### G8
- **D03:** `Operations::write_admitted(Option<FenceAdmission>, f)` (private; `write` = `write_admitted(None, ..)`):
  the admission and a task extension are owned by the `spawn_blocking` closure and dropped after
  `store.transaction` returns. Admissions record `tokio::task::try_id()`; `UninstallFence::write_extension()`
  gives every write started by a task holding an admission a counted extension (covers the dispatcher,
  `enrollment_request`/`issuer_request`, `decide`, the passes and the step-result follow-through without
  call-site changes). Debug only: `Operations::debug_pause_next_reservation_write()` (pauses inside the
  blocking closure of the next admitted reservation write).
- **D02:** `publish_issuance` takes `fence_admit_publication()` (never refuses; `None` while held) into its
  write; the re-reserve branch answers `uninstall_in_progress` with no void and no reservation when `None`.
- Both reservations (`reserve_issuance_with`, `reserve_verification`) move their admission into the write.
- **Tests:** model `recheck2_publication_must_not_rereserve_under_held_fence`,
  `recheck2_cancelled_reservation_keeps_admission_until_store_write_finishes`,
  `cancelled_verification_reservation_keeps_admission_until_store_write_finishes`; app
  `uninstall_fence_m03::tests::cancelled_admitted_work_keeps_admission_until_its_store_write_finishes`.
- **Audit A1 (second pass):** `Operations::fence_admit_pipeline()` (pub(crate)): extends the current task's
  admission (re-issue pass) or takes a new Work admission (the ensure's spawned lead; refused while the fence
  is held or being acquired). `managed::driver::run_stages` (driver.rs, that fn only; no owner in R1) holds it
  for the whole pipeline (key → reserve → sign → publish → install → materialize, and abandonment), so an
  acquisition waits for in-flight issuance. `publish_issuance` without a publication admission (another
  connection holds the fence) is refused `uninstall_in_progress` before any write (the D02 re-reserve
  refusal is folded into it). Debug only: `Operations::debug_pause_next_sign()`. The issuer child and
  `issuer_m03.rs` are unchanged (no request to K4 needed): every signing route (this pipeline,
  verification) now runs under an admission.
- **Audit A7 (recommend: leave, recorded safe):** `TimeGate::check`'s blocking anchor/high-water write
  (`timegate.rs:409`) carries no extension. It is time evidence, not a recovery-relevant record: it is not in
  the uninstall inventory or P8's final comparison (CAs/locators, orphans, enrollments, foreign removals,
  open operations), it is monotonic and idempotent, and a purge deletes it with the database. Routing it
  through `write_admitted` would touch `timegate.rs` for no recovery gain.
- **Tests (A1):** model `reva_probe_pre_fence_reservation_publishes_under_held_fence`,
  `reservation_joined_during_acquisition_cannot_publish_after`; e2e `fence::acquisition_waits_for_in_flight_activation`,
  `fence::activation_refused_while_fence_is_being_acquired` (appended to `enroll_m03/fence.rs`).
### L5
- **W5-D04, landed:** `enrollment_m03/verify.rs::verify_operation` is now single-flight per operation. It joins
  the existing `Operations` per-operation flight (`inner.flights`, the `lead` pattern), and the old body is
  `verify_once`. Every route goes through it: step-result follow-through, `enroll step`'s `Next::Verify`,
  `enroll reconcile`, the verify request, the target-change decision, the re-verification pass and
  `reverify_due`'s resume. A follower returns the leader's result; a later caller finds the state moved on and does
  nothing.
- **Why no store claim:** one runtime per state DB (instance lock), so the race is in-process. A durable claim would
  outlive a crash as a stale lock that needs its own recovery, while the verdict-less resume (§17.31 item 9) already
  covers a crash.
- **Converge:** `steps.rs::removal_without_step` re-checks the record's state and the operation inside its write
  (once per operation).
- **A8 (audit), landed:** the leader runs in its own task. That task owns the flight and a fence extension, so a
  cancelled caller never releases the flight while its verification or result write is pending. The result write is a
  CAS on the start (record state, open operation, the operation's verdict count); a stale write is discarded.
  Debug hooks: `debug_pause_next_verification_result_write`, `debug_verify_operation`, `debug_verify_without_flight`.
  Tests (`fence.rs`): `cancelled_verification_leader_with_a_pending_result_write_is_never_repeated`,
  `verification_result_write_records_only_the_run_it_started_from`.
- **Tests:** `fence.rs` gets `recheck2_deferred_verification_is_not_duplicated_by_two_steps`,
  `deferred_verification_is_not_duplicated_by_step_and_reconcile` and
  `concurrent_reverification_resumes_run_one_verification` (unix). `enroll_m03.rs` gets
  `removal_finding_the_line_gone_is_finished_once_by_two_steps`.
### K4
- Landed (A6, L1): `Operations::issuer_supervision_pass` is admitted through `uninstall_fence_admit`
  (skips entirely under a non-holder fence); `Operations::issuer_load_gate()` (weak); the issuer client
  takes `ClientConfig.load_gate` before every spawn and `load` (restart deferred until the lift);
  cancelled start → `crashed`, cancelled load → retried on demand. `crates/runtime/src/service.rs`:
  only the `ChildIssuer` construction (sets the gate).
