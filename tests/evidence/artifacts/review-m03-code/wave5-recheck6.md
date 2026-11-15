# Heimdall M03 wave 5, round 13: scoped re-check of the database family (reconstructed)

**Status: incomplete. Verdict: fix first.**

**What happened:**
- The Codex GPT-6.1 Sol (xhigh) scoped review of `ccd22853..b5f0a715` was stopped by its provider's content filter before it wrote its report.
- Its last message reported two blocking findings and a passing normal-start-up check.
- This record was reconstructed by the orchestrator from the reviewer's logs (real exit codes). Nothing in it is inferred beyond what those logs show.
- The orchestrator then removed the reviewer's leftover worktree and scratch tree.

## Reverts (each failed its regression, as required)
| Fix reverted | Regression | Result |
|---|---|---|
| Checkpoint before deletion | `final_review_checkpoint_puts_every_record_in_the_database_file` | FAILED |
| Checkpoint-on-close disabled | `final_review_wal_swapped_before_checkpoint_is_refused_before_any_write` | FAILED ("an unconfirmed log was checkpointed into the database file") |
| Start-up guard | `start_up_refuses_over_an_interrupted_purge_and_keeps_the_log` | FAILED |
| Deletion order | `final_review_companion_failure_preserves_database` | FAILED |
| Pending-retry display | `final_review_failed_retry_retains_pending_display_record` | FAILED |

## Probes
| Probe | Result | Classification |
|---|---|---|
| `uninstall_cmd::tests::r13_review_restore_race_preserves_replacement_record` | FAILED twice: "restore race attached an old WAL to the replacement and lost recovery record 9". | **W5-H01**: restoring the family takes several renames, and a database swapped in between them gets the old WAL. |
| `uninstall_cmd::tests::r13_review_checkpoint_probe_never_replays_unvalidated_journal` | FAILED: "checkpoint probe replayed an unvalidated hot journal and lost recovery record 9". The control run without the journal passed. | **W5-H02, BLOCKING**: the read-write checkpoint open replays a hot rollback journal into the owner's database before validation (§17.33 item 10). |
| Normal start-up with live `state.db`, `-wal` and `-shm` | ok | The start-up guard does not trip on a normal installation. |

## Limits
The run ended before its own analysis of the other questions (the crash points, the coverage of database open and create paths, and Windows by reading). Those questions carry over to the next review.
