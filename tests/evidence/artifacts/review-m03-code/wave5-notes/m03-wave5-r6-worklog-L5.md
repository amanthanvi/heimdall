# M03 wave 5 round 6 — worker L5 (ADR-0008 §17.30 items 3-5)

Base `aa7577e3`. No commits. Questions Q-L5-9..12 under "## L5".

## Done
- Item 5 reproduced first: store test `held_removal_with_origin_stays_outside_the_pair_ca_uniqueness_index`
  (tests/integration/store_m03.rs) before the fix: exit 101,
  `GenerationConflict("enrollment enr_0101… would duplicate a live (pair, CA)")` (withdrawn case);
  abandoned-only variant: exit 101, same error for `enr_0303…`; file restored (shasum match).
  Cause: the account removal path never set `removal_origin`; the index already excludes
  `held` + `removal_origin_set = 1`. Fix in `store::ext_m03::transition_enrollment` (no migration).
- Item 4: `payload_agrees` in `transition_enrollment` (inner `Err(InvalidTransition)`); store test
  `transition_refuses_event_payload_that_differs_from_the_stored_record`; `RawDocuments::{Enrollments,Events}`.
- Item 3: `steps::removal_confirmed` gate = origin ∈ {withdrawn, abandoned} + §6.7 condition; the
  round-5 receipt stage removed. e2e: `abandoned_with_late_write_removed_after_not_after_clears_residual`,
  `abandoned_with_late_write_removed_before_not_after_keeps_residual` (real abandon, real steps).

## Commands (exit codes; umask 002)
- Revert R3a (abandoned origin not counted): after-test FAILED 101; restored 9d3fd520… = before
- R3b (§6.7 condition bypassed): before-test FAILED 101; restored 9d3fd520…
- R4 (payload check bypassed): store test FAILED 101; restored 6da3f875… = before
- R5 (origin persistence bypassed): store test FAILED 101 (GenerationConflict); restored 6da3f875…
- reruns 0. heimdall-store 0; integration_store_m03 0 (33); integration_store 0 (77);
  model_managed_domain 0 (21); heimdall-contract 0; heimdall-app --lib 0 (64); model_operations_m03 0 (37)
- e2e_enroll_m03 0 (81); e2e_cli_m03 0 (62, 3 ignored child entries)
- host clippy (store testkit domain app heimdall, all targets) 0; clippy-windows.sh 0;
  linux-xcheck -p heimdall-store -p heimdall-app -p heimdall-domain 0; rustfmt --check 0
