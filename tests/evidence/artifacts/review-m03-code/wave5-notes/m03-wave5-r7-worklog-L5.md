# M03 wave 5 round 7 — worker L5 (ADR-0008 §17.30 item 8)

Base `7259203f`. No commits. No questions (no questions file created).

## Done
- `store::ext_m03::payload_agrees`: `TargetChangeApproved { hold }`, `ManualRecoveryLinePresent
  { hold, purpose }`, `ManualRecoveryLineAbsent { hold, purpose }` compared with the stored hold by
  kind (as `OwnerReverify`); refusal = inner `Err(InvalidTransition)`. `purpose` names the
  interrupted step (the journal's uncertain step), which the record does not store: not compared.
- Events with no stored restatement, left alone: `VerificationResult { verdict, approval_valid }`,
  `ReverificationResult { from, verdict }` (`from` lives in the journal), and every payload-less event.
  `OwnerCancelsManualRemoval { origin, ca_not_held_seen }` / `AbsenceVerified { origin }` are already
  checked by `removal_origin_kept`.
- Tests (tests/integration/store_m03.rs, shared helper `hold_payload_checked`):
  `transition_refuses_target_change_hold_that_differs_from_the_stored_record`,
  `transition_refuses_manual_recovery_line_present_hold_that_differs_from_the_stored_record`,
  `transition_refuses_manual_recovery_line_absent_hold_that_differs_from_the_stored_record`
  (each purpose; raw enrollment rows + events byte-identical; matching payload commits).
- Existing `second_live_enrollment_for_pair_and_ca_still_refused` sent `ManualRecoveryLinePresent
  { lock_holder_unresolved }` on a held record with no hold (now refused before its uniqueness
  check): its fixture now holds for `lock_holder_unresolved`; it still asserts the conflict.

## Commands (exit codes; umask 002)
- new tests 0. Reverts (one arm each): TargetChange 101, LinePresent 101, LineAbsent 101 (only the
  targeted test failed each time); restored shasum 3b5195a2… = before each time; reruns 0
- heimdall-store 0 (21); integration_store_m03 0 (36); model_managed_domain 0 (21; golden unchanged);
  e2e_enroll_m03 0 (81)
- host clippy (store testkit domain, all targets) 0; clippy-windows.sh 0;
  linux-xcheck -p heimdall-store -p heimdall-domain 0; rustfmt --check 0
