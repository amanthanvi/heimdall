# M03 wave 5 round 6 — integrator worklog

Base `aa7577e3`. Binding ADR-0008 §17.30 items 3-5. No commits.
- [x] L5 done: item 5 reproduced first (integration_store_m03 held_removal_with_origin_stays_outside_the_pair_ca_uniqueness_index: GenerationConflict "would duplicate a live (pair, CA)", exit 101, withdrawn + abandoned); cause: account-form removal never set removal_origin; fix in Txn::transition_enrollment, no migration. Item 4 transition_refuses_event_payload_that_differs_from_the_stored_record (5 mismatches; hold compared by kind). Item 3 e2e_enroll_m03 abandoned_with_late_write_removed_{after_not_after_clears,before_not_after_keeps}_residual. Reverts 101->0. Q-L5-9..12.
- [x] Final validation: check.sh every step 0 (2966 passed, 0 failed, 192 ignored); linux-xcheck 0; umask 002 all 0. Notes archived as m03-wave5-r6-*.md.
- Q-L5-9 ANSWERED (-> §17.30 item 6).
