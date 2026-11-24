# M08 W3: the unit order with owners, and the U2b brief (after the U0 handoff at `eda7d35d`)

**Status:** approved by the orchestrator, 2026-11-24, with its notes folded in (§1 H13 readers; §2.5 review).
- **Inputs:**
  - `docs/architecture/m08-w3-plan.md` (approved in outline);
  - the handoff message of 2026-11-24 (the write scope by unit);
  - `docs/architecture/m07-u0-handoff.md` and `m06-u0-handoff.md`;
  - ADR-0006 §19 (rev7 preparatory: §19.3 H1 to H15, §19.4 the restore rule);
  - `docs/architecture/u0-plan.md` §3 (H13) and §9 (lines outside U0);
  - the U0 rulings (`/tmp/hm-tools/u0-rulings.md`).
- **The branch:** `m08/w3` = `760117ee`, with `main` `eda7d35d` merged into `efe311c4`.

## 1. Units, order and owners

The integrator is the M08 track lead (this agent). It integrates, commits and runs the gates.
Workers never commit or push (AGENTS.md).

| # | Unit | Owner | Write scope (from the handoff) | Waits for | Size |
|---|---|---|---|---|---|
| 1 | **U3c**, the test-kit edge | the integrator | `crates/testkit/Cargo.toml` and its `cfg` on the strategies module; one manifest line in each crate that depends on the kit with default features off and uses the strategies; the new test `release_graph_holds_no_test_only_crate` | — | about half a day |
| 2 | **U2b**, lifecycle (§2 below) | **one implementer, Claude Opus 5.5 at the strongest effort** (authority-adjacent), with the integrator reviewing each slice; one independent review (a fresh Opus, §2.5) and one scoped re-check for the wave (ADR-0009) | as §2.2 | — (U2b-1 can start now) | about 3 to 5 days, in four slices |
| 3 | **U1b**, the new boundaries and the hostile-input table | one implementer, Claude Opus 5.5 at the strongest effort, reviewed by the integrator | `fuzz/**` (targets 12 to 15); `tests/adversarial/**` for any §14.3 row without a test; the `unsafe` inventory (a doc and a check); Q10's producers (`alias_collision` doctor finding, `AliasCollision` setup conflict) and the legacy case-variant report, in `crates/localenv/**` and the doctor's finding table; M06's follow-ups F3, F5, F6 and F8 (`crates/localenv/**`); ISS-F1, once the issuer fix's record names it | — (in parallel with U2b) | about 2 days |
| 4 | **U6b** (`support bundle`) and **U7b** (the defaults audit, then the final text and matrix) | the integrator, or one implementer for U6b | U6b: replace `rev7_cmd.rs`'s `support bundle` arm (H1) over `crates/support`. U7b: `docs/**` | U2b-2 for the bundle's state fields | about 1 day each |
| 5 | **The candidate commit** (U3b's start) | the integrator | `1.0.0-rc.1` set once, with U8's claims-table update (ASK-VERSION); the frozen feature set (default, no `iroh`); `examples/` packaged | 1 to 4 merged to `main` | — |
| 6 | **U3b, U4b, U5b, U8** | the integrator, with PC and devbox jobs | per m08-w3-plan W3-2 to W3-6 | 5 | per W3-1 |

**H13's reader side and M07.** H13 is one change, owned by U2b-2. Its readers today are M07's:
- the TUI's request paths (`crates/heimdall/src/tui/worker.rs`, `tui/m05.rs`, `tui/m07.rs`);
- the reference wrapper (`examples/reference-wrapper/reference_wrapper.py`);
- both harnesses (`examples/harnesses/cli/`, `examples/harnesses/goal-loop/`), including H2's
  frozen code-table row for `REQUEST_STALE` (u0-plan §9: M07 U5h);
- the CLI's retry path (`crates/heimdall/src/client.rs` and the commands that take
  `--request-id`).

**Granted to M08 U2b-2 for that one merge only** (the orchestrator, 2026-11-24):
- the TUI files `tui/worker.rs`, `tui/m05.rs` and `tui/m07.rs`;
- `examples/reference-wrapper/reference_wrapper.py`;
- `examples/harnesses/cli/**` and `examples/harnesses/goal-loop/**`, with H2's frozen code table.

The conditions:
1. **M07's lead reviews those diffs before the merge,** routed by the orchestrator, and their
   objections block.
2. **U2b-2 rebases on `main` just before its gate** (M07 edits `tui/` for U7b and U7a). A
   conflict that touches M07's logic, not the request path, stops the slice and goes to the
   orchestrator.
3. **After U2b-2 merges, the files return to M07.**

`crates/heimdall/src/client.rs` (the CLI retry path) and the commands that take `--request-id`
are inside U2b's scope (confirmed).

## 2. The U2b brief

### 2.1 Goal

ADR-0014 §3 in full, with §3.6, as ADR-0006 §19.4 adopts it into the contract:
- a restore recovers identity and configuration and **no authority**;
- one durable generation switch (H12);
- the restore epoch and the replay fence (H9, H13);
- attended `state restore --backup <file>`, `state reset` and `state repair` (Q8), replacing
  the skeletons in `crates/heimdall/src/rev7_cmd.rs`;
- `service stop --preview` (H2);
- the doctor finding `executable_moved` (H5);
- the residue kinds (H6);
- H15's Windows write-through.

Each lands with its emitters, every in-tree reader and its goldens (ADR-0013 §1.3).

### 2.2 Write scope (the handoff)

- `crates/stategen/**`. Its code moves into the store and runtime, or is depended on from
  there.
- The store and runtime code H12 and H13 need:
  - `crates/store/**`: migration 0014 exists; its writers, the fence table, the generation layout,
    the metadata epoch and the backup's environment binding;
  - `crates/runtime/**`: start-up from the pointer, the hello's `restore_epoch`, the server check,
    the instance lock during a restore.
- The state-path readers:
  - the runtime;
  - the read-only opens of `doctor` and the CLI;
  - `uninstall` and `purge` (the residue rows; purging every generation under the lock);
  - the Windows state-directory protection.
- `crates/heimdall/src/rev7_cmd.rs`: the `state *` arms and the `service stop --preview` arm,
  plus new `state_cmd.rs` and the stop-preview code in `service_cmd.rs`.
- The H15 write-through call in the existing Windows platform module.
- `Code::RequestStale` into `Code::all()`, `schema show codes` and `codes.json`, in the change
  that adds its emitter (ASK-CODE). Goldens move with it.
- `crates/localenv/src/projection/`: the moved-block report (`git_block_moved`).
- **H13's readers** (§1): as the orchestrator grants them.

**Not in scope:**
- M07 U3's live corrections (Q1 to Q7, Q11 to Q14);
- U1b's items;
- `support bundle` (U6b);
- H7 (U3).

### 2.3 Slices, each merged on its own with its gate

1. **U2b-1, the layout (H12).**
   - Move stategen's generation switch, pointer, operation record, staging intent and adoption
     order into the store's open path.
   - Today's flat store is adopted (intent, fence, copy, pointer, completion). Schema 14 counts
     as flat, per the ruling.
   - Start-up trusts only the pointer and never picks another generation.
   - The readers (doctor, the CLI's read-only opens, uninstall, purge) follow the pointer.
   - H15 is in this slice.
   - Tests:
     - `switch_interrupted_before_and_after_each_sync_and_the_rename`;
     - `unreadable_or_dangling_pointer_stops_and_never_picks_another_generation`;
     - `adoption_killed_at_each_step_then_older_build_then_newer_build`;
     - `older_build_on_newer_store_refuses_and_touches_nothing` (two real binaries);
     - `no_store_copy_reads_the_main_file_alone`;
     - `purge_removes_every_generation_under_the_lock`.
2. **U2b-2, the epoch and the fence (H9, H13), one change with its readers.**
   - The ledger and fence table are keyed by `stategen::ledger::key_digest` over the full
     idempotency key (N03).
   - `ServerHello.restore_epoch`.
   - `ClientMessage::Request.request_epoch`, outside every request hash (ASK-H13a).
   - `request-epoch/1` offered.
   - The server check before any write: `restore_epoch_stale`; the fence answers
     `restored_before_completion`.
   - `--request-epoch` on every command with `--request-id`, the envelope's `request_epoch`, and
     the CLI binding the hello's epoch at send.
   - A kept epoch facing a runtime that does not offer the capability refuses
     (`SCHEMA_UNSUPPORTED`).
   - `Code::RequestStale` with its emitter.
   - The readers: TUI, wrapper, H1, H2.
   - The damaged-ledger refusal (ruled 2026-11-23) carries over from stategen.
   - Tests:
     - `ledger_append_precedes_the_first_store_write`;
     - `stale_epoch_is_refused_before_any_write` (every mutating kind, through the CLI, the TUI's
       requests and the wrapper);
     - `clients_carry_the_epoch_with_a_kept_request_id`;
     - `equal_request_ids_across_clients_roles_and_kinds_have_separate_fences`;
     - `fence_retention_follows_the_idempotency_contract`.
3. **U2b-3, restore, reset and repair (H3, Q8, H4, H10).**
   - Identity binding (`backup_environment_id`).
   - Exclusion under the instance lock (refused while a runtime or issuer runs).
   - Staging and sanitization; activation by the one pointer switch.
   - The carry-forward of the more restrictive state and of later terminal records.
   - What a restore keeps, ends, quarantines and voids (ADR-0014 §3.6's table; the reasons
     `state_restored_authority_ended`, `client_quarantined_after_restore`,
     `invitation_void_after_restore`, `exposure_disabled_after_restore`).
   - `EventType::StateRestored` with `StateRestoredPayload`.
   - `state repair`: attended only. Carry the decodable records forward as fences, raise the
     epoch, truncate at the first damaged record, report the count and the residual.
   - Reset is the same switch, and discloses when no inventory is readable.
   - `STATE_UNAVAILABLE` (`ledger_damaged`, `state_corrupt`, `next.action` `owner_decision`) and
     `state_newer_than_build` (`change_client`).
   - Tests: the restore fault set of m08-plan U2b, each a focused case:
     - `restore_keeps_a_later_revoked_grant_ended`;
     - `restore_quarantines_a_later_revoked_management_client`;
     - `restore_voids_consumed_and_expired_invitations`;
     - `request_completed_after_the_backup_is_never_run_again` (both variants);
     - `old_decision_reference_is_refused_after_restore_and_reauthorization`;
     - `no_duplicate_effect_when_store_and_ledger_are_both_lost`;
     - `runner_effect_applied_after_the_backup_is_adopted_not_resent`;
     - `restore_keeps_a_retired_issuer_retired_and_an_unpaired_environment_unpaired`;
     - `restore_disables_exposure_and_closes_pending_widening_decisions`;
     - `restore_refuses_another_environments_backup_and_changes_nothing`;
     - `restore_is_refused_while_a_runtime_or_issuer_runs`.

     Plus:
     - `reset_is_attended_and_says_it_creates_a_new_identity`;
     - `reset_without_any_readable_inventory_says_so_and_refuses_non_interactive`;
     - `reset_then_restart_serves_the_new_generation`;
     - `restore_restore_reset_keeps_every_earlier_generation`;
     - `corrupt_store_stops_unsafe_operations_and_offers_recovery`;
     - `migration_ladder_keeps_identity_and_authority` (over U0's replay corpus).
4. **U2b-4, the rest.**
   - `service stop --preview` (H2): read-only, and `stop_preview_lists_what_stopping_interrupts`.
   - `executable_moved` (H5): `moved_executable_is_a_doctor_finding_and_never_a_silent_break`.
   - The residue kinds and uninstall's list (H6):
     `uninstall_lists_backups_earlier_generations_previous_binary_and_remote_pairings`.
   - `rollback_reports_a_moved_git_block`.
   - The remainder of D14's help rewrite.

### 2.4 Rules the implementer follows

- **Every backup, adoption copy, staging copy and carry-forward read goes through SQLite.** None
  copies the main database file alone (ruling of 2026-11-22).
- **Every new authority path fails closed.** The skeletons keep answering "not available in this
  build" until their slice lands (ASK-H3).
- **Fixtures only:**
  - disposable stores and keys;
  - every hand-run `heimdall` with scratch `HEIMDALL_HOME`, `HOME` and `HEIMDALL_TEST_SSH_HOME`,
    and the scratch secret, management and transport stores;
  - release binaries only in containers.
- **Native:** the switch's fault set and the restore fault set run natively on macOS, the devbox
  and Windows at each slice's merge candidate. The rename and sync calls differ, and Windows has
  no directory sync. Power loss is not tested anywhere, and the record says so.
- **Evidence:** a revert proof for each merge-blocking fix (ADR-0009). `check.sh` once per
  commit, through heavy-gate.

### 2.5 Review

- One independent review for the wave. It checks the restore protocol line by line against
  ADR-0014 §3.6 (m08-plan §0a's last row), with the fault sets run natively.
  - **Stated limit:** no other model family is available now (the others are throttled or at
    their usage limit). The reviewer is a fresh Claude Opus with no prior context, the same
    family as the implementer.
- One scoped re-check.

## 3. Order of the first days

1. U3c, by the integrator, merged first (small, and it frees the release graph).
2. U2b-1 and U1b start in parallel, in separate worktrees. U2b-1 merges after its native
   runs.
3. U2b-2 follows, with H13's readers as the orchestrator grants.
4. U2b-3, U2b-4 and U6b follow.
5. The F1 issuer fix's rerun of the probe's fresh-install case (`ss6`) runs when that fix lands
   on `main`.
