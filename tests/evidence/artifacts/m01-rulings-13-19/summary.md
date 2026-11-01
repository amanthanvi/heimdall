# M01-rulings-13-19: red/green and mutation evidence (ADR-0006 §13.19)

Implementation sub-agent run on 2026-11-01. The base production code is commit
8263ee6c. HEAD moved to d96a9b1c during the run (docs-only commits), but `crates/`,
`tests/model` and `tests/integration` are identical between the two. The working
tree is uncommitted. Status: `implemented_unverified`.

Every "base" run below put the base production files (`git show HEAD:<file>` for
`crates/app/src/operations.rs`, `crates/domain/src/revocation.rs`,
`crates/store/src/ext.rs` and `crates/runtime/src/supervisor.rs`) in place under the
new tests, ran them in the single `./target`, then restored the fixed files and
touched them. Exit codes are cargo's own. Output is reduced to test lines; no paths.

## Red at base

`cargo test -p heimdall-runtime --test model_operations r1319_` exited **101**:
0 passed, 11 failed.

    r1319_1_a_superseded_first_round_confirmation_never_erases_a_newer_pending_obligation ... FAILED
    r1319_1_a_superseded_confirmation_never_erases_a_newer_pending_obligation_without_an_effect ... FAILED
    r1319_2_a_restart_after_the_late_confirmation_commit_keeps_the_capped_records_cleanup ... FAILED
    r1319_2_a_restart_after_a_recheck_refusal_commit_keeps_the_capped_records_cleanup ... FAILED
    r1319_2_a_restart_after_a_cancellation_commit_keeps_the_capped_records_cleanup ... FAILED
    r1319_2_a_restart_after_a_commit_refusal_commit_makes_the_owed_immediate_call ... FAILED
    r1319_2_the_supervisor_makes_the_immediate_call_a_failed_refusal_commit_owes ... FAILED
    r1319_2_a_late_uncertain_receipt_after_a_cancellation_gets_a_call_after_the_effect ... FAILED
    r1319_2_a_late_confirmation_that_fails_to_commit_still_gets_a_call_after_the_effect ... FAILED
    r1319_2_a_restart_after_a_cancelled_preparation_applied_its_effect_makes_the_owed_call ... FAILED
    r1319_props::r1319_every_applied_effect_ends_owned_or_called_and_no_pending_obligation_is_lost ... FAILED

`... model_operations r1319_1_a_claim_that_outlives` at base exited **101**:
1 failed, "A's confirmation clears nothing of B's record".

At base the property shrank (after 60 successes) to
`[Revoke{hold, confirm}, Revoke{pending}, Release(0)]`: a superseded first-round
confirmation erases a newer pending obligation (W01).

## The W01 fix alone (W02 not yet implemented)

`... model_operations r1319_` exited **101**. The W01 regression passed. The nine
W02 cases and the property failed. The property shrank (after 228 successes) to
`[Revoke{hold, confirm}, Cancel, Revoke{confirm}, Fault{BeforeCommit, 2}, Cancel, Effect]`:
the cancelled preparation's late confirmation never commits, and after the restart no
call follows the effect (W02).

## A first W01 fix with a per-record sequence

At 1024 cases the property failed on the fixed code and shrank (0 successes on
rerun; persisted) to `[Revoke{hold, confirm}, Round{confirm}, Revoke{hold, pending},
Release(0)]`. The round removed the record, and the re-created record's sequence
restarted, so revoke A's late confirmation matched B's claim. Claim sequences now
come from a store counter that outlives every record. Regression:
`r1319_1_a_claim_that_outlives_its_records_removal_never_erases_a_new_records_obligation`.

## Green

* `... model_operations r1319_` exited **0**: 12 passed.
* `cargo test --workspace --locked --no-fail-fast` exited **0**: 734 passed,
  0 failed, 2 ignored.
* `cargo clippy --workspace --all-targets --locked -- -D warnings` exited **0**.
* The persisted regressions in `tests/model/operations.proptest-regressions` are the
  three shrunk cases above.

## Mutations

Each mutation was applied, the listed suites were run, then the file was restored
and touched, and the regressions file was restored from a snapshot.

| Mutation | Suites (exit) | Caught by |
|---|---|---|
| M1 any open claim is current (no sequence identity) | model r1319_ (101) | r1319_1_…without_an_effect, r1319_1_a_claim_that_outlives…, r1319_props |
| M2 a re-arm resets `claim_seq` | model r1319_ (0); app r1319_1 (101) | r1319_1_an_explicit_revokes_rearm_never_resets_the_claim_sequence (equivalent for claim identity once the store counter exists) |
| M3 a superseded completion clears an obligation with no recorded effect | model r1319_ (101) | r1319_props |
| M4 a claim at the effect's sequence clears it (`>=`) | model r131 (101) | r1318_2_a_round_in_flight…, r1318_2_a_restart_after_the_racing_round…, r1318_2_an_explicit_revokes_first_round_in_flight…, r1319_props |
| M5 the migration drops a legacy `effect_round` | domain r1319 (101); app r1319_1 (101) | r1319_a_record_without_claim_seq…, r1319_1_a_record_written_before_claim_seq… |
| M6 the late confirmation decides nothing in its transaction | model r131 (101) | r1317_5_a_cancel_then_a_late_confirmation_each_rearm_once |
| M7 restart recovery skips cleanup intents | model r1319_ (101) | r1319_2_a_restart_after_a_commit_refusal…, r1319_2_a_restart_after_a_cancelled_preparation… |
| M8 the supervisor skips cleanup intents | model r1319_ (101) | r1319_2_the_supervisor_makes_the_immediate_call… |
| M9 an unanswered attempt is never in flight | model r1319_ (101) | r1319_2_a_late_confirmation_that_fails_to_commit…, r1319_2_a_restart_after_a_cancelled_preparation…, r1319_props |
| M10 no processing when the preparation returns | model r1319_ (101) | r1319_2_a_late_confirmation_that_fails_to_commit… |
| M11 the late `Uncertain` receipt decides nothing | model r131 (0), model a19 (0), model_revocation (0) | **not caught**: equivalent. Every path that takes the operation out of `running` during a preparation already wrote an in-flight intent with the same unconfirmed key, and the preparation's return path processes it. |
| M12 the cancellation decides nothing in its transaction | model r1319_ (101) | r1319_2_a_late_confirmation_that_fails_to_commit…, r1319_2_a_restart_after_a_cancellation_commit…, r1319_2_a_restart_after_a_cancelled_preparation…, r1319_props |
| M13 the recheck refusal decides nothing in its transaction | model r1319_ (101) | r1319_2_a_restart_after_a_recheck_refusal_commit…, r1319_props |
| M14 the commit refusal decides nothing in its transaction | model r1319_ (101) | r1319_2_a_restart_after_a_commit_refusal_commit…, r1319_2_the_supervisor_makes_the_immediate_call… |
| M15 a call made while preparing removes the in-flight intent | model r1319_ (101) | r1319_2_a_late_confirmation_that_fails_to_commit…, r1319_2_a_restart_after_a_cancelled_preparation… |
| M16 the supervisor processes an intent while its preparation runs | model r1319_ (101) | r1319_2_a_restart_after_a_cancelled_preparation… |
| M17 a re-created record restarts its own sequence (no store counter) | model r1319_ (101) | r1319_1_a_claim_that_outlives…, r1319_props |
