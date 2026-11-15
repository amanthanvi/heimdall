# Heimdall M03 wave 5, round 11: fourth independent re-check (reconstructed)

**Status: incomplete; verdict fix first.**
- **Why incomplete:** the Codex GPT-6.1 Sol (xhigh) run of `06990cc8..e068e049` was stopped by its provider's content filter before it wrote its report. Its detached worktree, scratch files and build output were left behind.
- **What this record is:** the orchestrator reconstructed it from the reviewer's own command ledger (`commands.jsonl`, real exit codes) and its last message. Nothing here is inferred beyond what those show. Then the orchestrator removed the leftover worktree and scratch tree.

## Revert checks (all failed their regression, as required)
| Fix | Regression run with the fix reverted | Exit |
|---|---|---:|
| W5-E01 | `recheck3_retry_allowance_rejects_new_remote_obligation` | 101 |
| W5-E02 | `issuer::recheck3_real_issuer_*_cannot_cross_fence` | 101 |
| W5-E03 | `recheck3_fence_holder_can_finish_own_verification` | 101 |
| W5-E04 | `recheck3_purge_never_follows_runtime_root_replacement` | 101 |
| W5-E05 | `recheck3_released_holder_must_not_continue_retry_under_new_fence` | 101 |
| W5-E06 | `recheck3_purge_removes_cleanup_mux_path` | 101 |
| B1 | `retry_allowance_is_the_rounds_own_commit_not_a_reread` | 101 |
| B3 | `uninstall_purge_refuses_a_swapped_owner_only_state` | 101 |
| B4 | `uninstall_purge_link_between_passes_deletes_nothing` | 101 |
| Lease generation, lease spawn, stuck release, trusted top, Windows owner | their regressions | 101 each |

## New probes (temporary, restored byte-for-byte afterwards)
| Probe | Exit | Result | Classification (§17.33 items 6 and 10) |
|---|---:|---|---|
| `uninstall_cmd::tests::recheck4_transient_state_swap_must_keep_unconfirmed_recovery` | 101 | A transient swap of `<state>` let the final read validate a decoy database; the sweep then deleted the genuine one (holding an added CA and foreign-removal record) and reported success. | **W5-F01, MUST-FIX** (destructive, lasting loss of recovery records; item 10). The `RESIDUALS` entry `uninstall_state_swapped_and_restored_during_final_read` was inaccurate. |
| `purge_sweep::tests::recheck4_leaf_replacement_must_keep_unconfirmed_owner_data` | 101 | A file replaced between inspection and `unlinkat` was deleted. | **W5-F02, MUST-FIX** (destructive, lasting; item 10). |
| `purge_sweep::tests::recheck4_default_unix_home_with_private_group_must_pass` | 101 | The secure-path rule refuses a default Unix home that is group-writable by the user's private group (user-private-group layouts with umask 002). | **W5-F03, fix:** a legitimate default layout must pass (§17.33 item 12). It only refuses, but it blocks every purge for those users. |
| `issuer::recheck4_cancelling_stop_must_not_signal_unverified_child` | 101 | Cancelling issuer cleanup during its 5 s wait signals the child through `kill_on_drop`. | **W5-F04, RECORD.** The child is unreaped, so the handle cannot reach a reused PID; no lasting effect (reviewer's classification). |
| `uninstall_cmd::tests::recheck4_cli_crash_releases_the_real_instance_lock` | 0 | A crashed CLI releases `service.lock`. | sound |
| `recheck4_two_reissue_passes_and_ensure_do_not_duplicate_same_grant` | 0 | No duplicate re-issue of one grant. | sound (an area the round-10 audit had not checked) |
| `recheck4_production_effects_exclude_second_same_grant_reissue`, `recheck4_removal_keeps_ca_during_other_reverification` | 0 | | sound |
| Release build: `HEIMDALL_TEST_PURGE_TRUSTED_TOP`, absolute and relative | 0 | The child exits 2 and the home stays empty. | sound |

## Limits
The reviewer's run ended before:
- it wrote its own analysis of the lease, exact-child-stop and Windows paths;
- it reviewed every `RESIDUALS` entry.

Those questions carry to the re-check of round 12.
