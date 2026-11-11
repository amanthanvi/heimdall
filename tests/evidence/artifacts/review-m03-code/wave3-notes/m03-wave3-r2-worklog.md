# M03 wave 3, round 2 (review fixes): worklog (untracked; integrator + agents)

## Integrator
- 2026-11-11: base `3f7a582e`. Orchestrator files present, untouched: ADR-0008 §17.20, `wave3.md`, `wave3-security.md`.
- m03-plan §0.6 amended for U7-Q1 (`runtime → sshconf`; §17.20 item 14).
- Helper `.m03-wave3-xcheck-windows.sh` recreated with the corrected `cd`.
- Split: F6 = §17.20 items 1, 2, 7, 8, 9, 10, 14 (U6-Q5, U6-Q6); F7 = items 3, 4, 5, 6, 11, 12, 13, 14 (W3-Q1, U7-Q4).
- After F6/F7 (integrator): U7-Q4 store invariant applied in `crates/store/src/ext_m03.rs`
  `Txn::insert_owned_connection` (a dedicated row needs its binding's holder). Regression
  `integration_store_m03::dedicated_owned_connection_needs_the_binding_holder`: reverted → exit 101
  (panic store_m03.rs:1445, the holder-less insert succeeded); restored → 28 passed, exit 0.
- `crates/app/src/operations/connections.rs` (U0b's file): `register_owned_connection` refuses a binding no
  launcher holds with `binding_unknown` before the gate (m03-plan §5 item 4a). Regression
  `model_narrowing_m03::registration_refused_for_a_binding_no_launcher_holds`: reverted → exit 101 (`left:
  Unavailable("store")`, `right: RegistrationRefused("binding_unknown")`); restored → 57 passed, exit 0. Fixtures of
  `register_ordered_with_revocation_by_gate`, `registration_refused_while_pending`,
  `register_refused_for_ended_or_tombstoned_grant`, `pending_mark_refuses_new_signers_and_delegations` record the
  launcher as holder (`hold_launch`).
- Stopped three orphaned round-1 U7 test masters by exact PID after verifying PID, PPID 1, start time
  (06:09:31, 06:09:31, 06:11:48, before the 06:34 commit), `/usr/bin/ssh -M`, and a ControlPath under a deleted
  `/tmp/hm-*` ScratchHome; all gone after SIGTERM.
- check.sh run 1 (round 2) → exit 1: only `test` 101 (2565 passed, 16 failed): 13 holder-less dedicated fixtures
  (connections 12, managed_adapter 1) after the store invariant, 2 model tests (fixed above), and
  `integration_projection::production_code_never_unlinks_outside_quarantine` (`sys/managed_dir.rs` `unlinkat`
  outside QuarantineDir; M02 guard kept, F6 reroutes). F6 and F7 resumed for their parts.
- Stopped two more orphaned test masters (07:43:56–57, from check.sh run 1's 12 panicking connection tests; same
  verification); F7 then made the test world stop its recorded masters on drop (exact PIDs, re-verified), proven
  with a forced panic.
- check.sh run 2 (round 2) → **exit 0**, every step 0: 2582 passed, 0 failed, 188 ignored, 97 targets;
  native-harness-selftest 316/0. `linux-xcheck.sh --workspace` → 0; `clippy-windows.sh` → 0.
- Scan of every changed/new file: no canary value, home path or private key. No orphaned `/usr/bin/ssh` (PPID 1).
  ADR-0008 diff is the orchestrator's §17.20 only (104 insertions, 0 deletions).

## Requests (agent → integrator)
- F7 → integrator (U7-Q4, §17.20 item 14; reserved `crates/store/**` or `crates/app/**`): the insertion
  invariant for **dedicated** rows must be checked where the application inserts them (the supervisor
  checks masters in its own insertion transaction, `connections::owned_row_invariant`). Exact change, in
  `crates/store/src/ext_m03.rs` `Txn::insert_owned_connection`, right after the `state != Up` check:
  ```rust
          // U7-Q4 (ADR-0008 §17.20 item 14): a dedicated row only for a launch binding with a
          // recorded holder (the enumeration of the connection passes relies on it).
          if connection.kind == ConnectionKind::Dedicated && self.binding_holder(&connection.binding)?.is_none() {
              return Err(codec::doc_error("a dedicated owned connection needs its binding's holder"));
          }
  ```
  (`ConnectionKind` from `heimdall_domain::managed`). Both app insertion paths already satisfy it:
  `register_at_bind` runs right after `claim_launch_holder` in the same transaction
  (`operations.rs:9044` and `:8849`) and writes a row only with a holder, and `register_owned_connection` runs for a
  launch binding whose launcher holds it. Please confirm with `cargo test -p heimdall-store` and
  `-p heimdall-app` model tests after applying. Fail-closed choice taken meanwhile: none needed (the
  supervisor never inserts dedicated rows).
- F7 → integrator (optional, §17.20 item 4): `connection_restart_pass` recomputes the bound as
  `min(deadline, every ancestor's deadline, every applicable cutoff, the persisted anchor's bound)`
  (`connections::restart_bound`) because `app::operations::bound_of` is private; it then uses the app's
  own `TimeGate::check` and `TimeGate::admission`. Exposing `bound_of` (for example `pub fn
  grant_bound_in(tx, env, grant, profile) -> heimdall_store::Result<Timestamp>`) would let the pass reuse
  it verbatim. Not blocking: the recomputation takes every cutoff (strictest), never a later bound.

- F6 → integrator (§17.20 item 8; reserved `crates/app/src/ports.rs`, frozen plan §5): `check_prepared`'s
  "not yet valid" needs each certificate's `valid_after`, which `PreparedCertificate` does not carry. Fail-closed
  choice taken (compiles, no port change): the adapter reads `valid_after` from `ManagedEffectsImpl`'s in-memory
  record of the install (`InstalledValidity`, the entry the signer checked the certificate against), only when its
  `issuance` and `valid_before` equal the prepared certificate's; anything else (no signer in the process, another
  entry) refuses `prepared_certificate_not_yet_valid`. Optional cleaner route, if you prefer it: add to
  `PreparedCertificate` (after `valid_before`) `/// The certificate's valid_after (§17.20 item 8).
  pub valid_after: Timestamp,` and the driver fills it from the published entry's `bounds.valid_after`; then
  `prepare::outcome`'s `valid_after_of` closure becomes `|c| Some(c.valid_after)`.
- F6 → integrator (§17.20 item 14 U6-Q6, for confirmation): the example now names `//./pipe/heimdall-<token>-b<tag>`
  (the ruling's form, rendered as P renders `IdentityAgent`), while `prepare_from` emits the endpoint **locator**
  `\\.\pipe\heimdall-<token>-b<tag>` — the form `heimdall::connect_cmd::binding_files` (U8) parses; emitting the
  rendered form would make `connect` find no binding files. Same pipe. The golden test compares `consumer` exactly
  under that one mapping (`\\.\pipe\` → `//./pipe/`). If the orchestrator wants the rendered form on the wire,
  `connect_cmd::binding_files` must accept it first (U8's file).
- F6 → integrator (info): `ManagedEffectsImpl` gained `with_slot_store(Arc<dyn SlotStore>)`; U10 must wire its
  store there (default `NoSlotStore` makes every slot write through `materialize_slot`/`materialize{environment_slots}`
  refuse). `ManagedSourceRead::terms` now returns `Option<GrantTerms>` (U10 records terms at activation).
  `files::{binding_directories_of, slots_written_by}` now return `Result`. `ManagedEffects::clear` no longer clears
  slots or the listing (slots by their own generation through `clear_slot`, U6-Q4).

## F6
Items 1, 2, 7, 8, 9, 10, 14 (U6-Q5, U6-Q6). Host macOS arm64. All commands from the worktree root.

Green runs (final state, after rustfmt):
- `cargo test -p heimdall-adapters --test integration_managed_adapter` → exit 0 (46 passed; was 38; 8 new, + 1 `#[cfg(windows)]` not built here)
- `cargo test -p heimdall-adapters --lib` → exit 0 (19 passed)
- `cargo test -p heimdall-credential --test integration_managed_signer` → exit 0 (37 passed, 1 ignored: pre-existing B2/B3/B8 cfg-ignores)
- `cargo test -p heimdall-credential --lib` → exit 0 (13); `cargo test -p heimdall-localenv --lib` → exit 0 (89, incl. 2 new `sys::managed_dir` tests)
- `cargo test -p heimdall-contract --test contracts` → exit 0 (89)
- `cargo clippy -p heimdall-adapters -p heimdall-credential -p heimdall-localenv -p heimdall-contract --all-targets -- -D warnings` → exit 0
- `bash .m03-wave3-xcheck-windows.sh -p heimdall-adapters -p heimdall-credential -p heimdall-localenv --all-targets` → exit 0
- `bash tools/validation/linux-xcheck.sh -p heimdall-adapters -p heimdall-credential -p heimdall-localenv` → exit 0
- `cargo check -p heimdall-runtime -p heimdall --tests` (dependents of the changed API) → exit 0
- `rustfmt --edition 2024 --check` on every F6 file → exit 0

Revert proofs (each: temporary edit, the named test run, file restored byte-identical by the helper, re-run green above):
- regression stale_generation_write_never_rolls_back_the_slot (marker fence removed from `files::write_generation`): reverted → exit 101 (managed_adapter.rs:4156 `matches!(late, Err(StaleGeneration(2)))`); restored → exit 0
- regression stale_generation_write_never_rolls_back_the_slot (store re-validation removed from `write_slot_locked`): reverted → exit 101 (managed_adapter.rs:4207 `materialize_slot(..).unwrap_err()` on Ok: a delayed gen-1 write published after its clear); restored → exit 0
- regression slot_claim_and_clear_are_serialized (per-slot lock removed from `ManagedSlotTable::claim`): reverted → exit 101 (managed_adapter.rs:4299 "the clear ran while the claim was between its CAS and its files"); restored → exit 0. (A first attempt hung: the test asserted before releasing the gated claim; stopped by its exact task, file restored, test fixed to release first.)
- regressions clearing_one_pair_keeps_the_other_pairs_listing + stale_clear_never_unlists_the_current_binding (`clear_slot` back to binding-wide `unmaterialize`): reverted → exit 101 (4395 left [] right [h2]; 4360 left None right Some(2)); restored → exit 0
- regression stale_clear_never_unlists_the_current_binding (binding-wide `unmaterialize` back in `clear`): reverted → exit 101 (4360 left None right Some(2)); restored → exit 0
- regression managed_files_never_follow_a_planted_directory (`ManagedDir::child` following symlinks, owner-only check skipped): reverted → exit 101 (4412 parent-symlink write accepted); restored → exit 0
- regression coverage_never_exceeds_the_shortest_certificate (`compute` bound back to the deadline): reverted → exit 101 (4583 left (22:00,22:00) right (10:15,10:15)); restored → exit 0
- regression coverage_never_exceeds_the_shortest_certificate (expiry check disabled in `check_prepared`): reverted → exit 101 (4617 `unwrap_err` on Ok); restored → exit 0
- regression aggregate_clock_is_the_weakest_now (old `(behind_upper+rtt, measured_at)` key): reverted → exit 101 (4651 left A 1362 ms right B 962 ms @ −10 000 s); restored → exit 0
- regression revoke_on_lock_grant_without_terms_never_reports_verified (terms defaulted again): reverted → exit 101 (4696 `unwrap_err` on Ok); restored → exit 0
- golden report_for_local_managed_binding_with_empty_claim_table (wording retyped as before): reverted → exit 101 (1702 left "New connections stop…" right the qualified D8 item 6 text); restored → exit 0
- golden report_for_local_managed_binding_with_empty_claim_table and contract ensure_data_managed_example_matches_plan (example endpoint back to `…-signing`): reverted → exit 101 (managed_adapter.rs:1771 consumer fragment; contracts m03.rs:350 binding endpoint form); restored → exit 0

Needs native runs: Windows `cargo test -p heimdall-adapters --test integration_managed_adapter managed_dir_windows_refuses_inherited_dacl_and_junction` (cfg(windows), never built here) and the whole `integration_managed_adapter` target (the anchored Windows file path: pin, DACL check, ReplaceFileW/MoveFileExW); devbox the same target (Linux rustix `Dir`/`renameat` path, linux_raw backend).

### F6 follow-up (integrator: check.sh findings)
- 1. `production_code_never_unlinks_outside_quarantine` (ADR-0007 §5.3 guard, unchanged): `ManagedDir::remove` no longer
  unlinks. It reads the file's identity and digest on a handle relative to the verified directory (regular, owned,
  one link only; a symlink, directory or other entry is refused `managed_dir_unsafe` and left in place), moves the
  name with no replacement into that directory's validated `.hm-quarantine` (`QuarantineDir::open_or_create_in` /
  `open_or_create_at`), and removes it with `QuarantineDir::remove_verified`; the quarantine is then
  `rmdir_if_empty`. No REMOVALS needle remains in `sys/managed_dir.rs` production text. Docs: module doc,
  `sys/mod.rs` row, overview §9 item 3 paragraph updated. Unit test updated (a symlink at a file's name is refused,
  left in place); item-7 regression extended (a symlink planted at `key.pub` inside a verified slot directory: the
  clear refuses, removes nothing; then the clear removes the generation and leaves no quarantine).
- 2. `revoke_result_lists_owned_connections_and_ordinary_note`: the fixture records the binding's holder
  (`Txn::set_binding_holder`, pid 4200) before inserting the dedicated rows. Store unchanged.
- regression managed_files_never_follow_a_planted_directory (owner-only check skipped in `ManagedDir::child`): reverted → exit 101 (managed_adapter.rs:4431 `unsafe_dir`: a 0777 level accepted); restored → exit 0
- regression managed_files_never_follow_a_planted_directory (a non-regular entry unlinked again in `ManagedDir::remove`): reverted → exit 101 (managed_adapter.rs:4559 clear of a planted `key.pub` symlink returned Ok); restored → exit 0
- `cargo test -p heimdall-localenv --test integration_projection` → exit 0 (112 passed)
- `cargo test -p heimdall-localenv --lib` → exit 0 (89); `cargo test -p heimdall-adapters --test integration_managed_adapter` → exit 0 (46)
- `cargo clippy -p heimdall-localenv -p heimdall-adapters --all-targets -- -D warnings` → exit 0
- `bash .m03-wave3-xcheck-windows.sh -p heimdall-localenv -p heimdall-adapters --all-targets` → exit 0
- `bash tools/validation/linux-xcheck.sh -p heimdall-localenv -p heimdall-adapters` → exit 0
- `rustfmt --edition 2024 --check` on F6's files → exit 0
- Windows-native still needed: the quarantine route on Windows (`open_or_create_at` under the pinned managed
  directory, `MoveFileExW` into it, the disposition delete) runs only in `integration_managed_adapter` there.

## F7
- 2026-11-11: started. Read brief, round-1 brief/notes, §17.20, wave3.md, wave3-security.md. Items 3, 4, 5, 6, 11, 12, 13, 14 (W3-Q1, U7-Q4). Files: crates/runtime/src/connections.rs, tests/integration/connections.rs, tests/e2e/deadline_m03.rs, crates/localenv/src/sys/mod.rs (U7 region), overview §9 (U7 rows).
- Landed (§17.20 items 3, 4, 5, 6, 11, 13, 14; item 12 Windows-only, compiled):
  - `crates/runtime/src/connections.rs`: per-path slot lock (`slot_lock`; start, replace, close, reap under
    it; generation reserved inside it in `replace_previous_locked`); `start_context` (binding, grant
    usable, pair in scope, effective policy `owned_masters`, binding holds the slot `held(b, g)`,
    destination) read before the spawn and **again in the recording transaction** (`record_master`; any
    change → child killed by handle, nothing recorded); readiness proven by `ssh -O check` naming the
    child's PID (`spawn_once`, `listener_pid`, `parse_check_pid`, `check_argv`); `-O exit` only to a
    proven listener (row inode + `-O check` PID + start token, `close_master_locked`); sockets removed
    only under the lock while no newer generation is open (`remove_stale_locked`); `<runtime_dir>/mux/`
    created 0700 and re-verified (real dir, owner, mode 0700; runtime dir real and owned) before every
    use, `mux_dir_unsafe`, never repaired (`ensure_mux_dir`); unproven entries at the stable path removed
    (identity re-read before unlink, under the lock) before a start and after every close pass for the
    paths of the grant's masters and its bindings' slots, plus `clear_slot_path(dest)` for U10 when it
    clears a slot without a master (`clear_unproven_locked`, `PassReport::foreign_listeners_removed`,
    `mux_path_foreign_listener_removed`, tracing warn without path); restart pass by fresh admission
    (`restart_bound` + `TimeGate::check` + `TimeGate::admission`; no gate or uncertain time → close;
    `ConnectionConfig::time_gate`, else `Operations::timegate()`); second signal re-verifies on every
    Unix (`terminate_verified`); passes return `PassResult = Result<PassReport, DiscoveryFailed>`
    (`connection_deadline_pass`, `revocation_close`, `release_close`, `time_uncertain_close`,
    `connection_restart_pass`, `reap_pass`, `close_for`; `shutdown` stays `PassReport`);
    `owned_row_invariant` (U7-Q4) checked in the master insertion transaction (violation rolls back);
    unit test `owned_launch_pins_prefix_and_master_argv_follow_the_ruling` (W3-Q1) and
    `check_answers_parse_to_the_master_pid_only`. Test hook `ConnectionConfig::after_master_ready`
    (`#[doc(hidden)]`, `None` in production).
  - `crates/localenv/src/sys/mod.rs` (U7 region only): `current_job_process_ids()` (Windows,
    `IsProcessInJob(GetCurrentProcess(), NULL)` + `QueryInformationJobObject(NULL,
    JobObjectBasicProcessIdList)`), its invariant-table row; overview §9 item 3 row added after
    `JobObject::contains_pid`.
  - `tests/integration/connections.rs`: World gains a store fault hook (`Arm`), a time gate (grants
    anchored), `hold` (slot transfer), `start`, `master_pid` (`-O check` PID), `foreign_master` (probe-owned
    master). Every start now holds the slot first. `two_successive_bindings…` asserts the listener's PID
    instead of `assert_ne!` on inodes.
  - `tests/e2e/deadline_m03.rs`: `PassResult` unwraps; `windows_register_while_suspended_under_gate`
    rewritten (gate `retain`ed in the real `Operations`' `SigningGates`, an exclusive holder: past
    `signing_gate_wait` → refused `gate_timeout`, child dies suspended; released during the wait →
    registered after the release); `windows_non_ssh_run_has_no_job_object_by_default` rewritten (real
    `heimdall run --profile ops` of a non-ssh program = this test binary's `windows_job_probe_child`
    fixture; asserts the child's immediate job is none or also holds the launcher, and that a `ping`
    grandchild outlives the launcher's normal exit; stops it by exact PID + creation time).
- Regressions (host, macOS; reverted = the minimal part of the fix removed, then restored and re-run green):
  - regression master_socket_removed_only_if_same_inode (W3-N01, rewritten): reverted (no newer-generation check in `remove_stale_locked`) → exit 101 ("generation N+1's socket kept"); restored → exit 0
  - regression concurrent_starts_of_one_slot_are_serialized (W3-R03): reverted (slot lock not taken in start) → exit 101 (`left != right` failed, generations 1 and 1); restored → exit 0
  - regression stale_close_never_controls_a_replacement_listener (W3-S03 probe): reverted (`-O exit` sent on start token alone) → exit 101 ("the unrelated replacement master was not killed"); restored → exit 0
  - regression foreign_master_at_stable_path_never_serves_after_revocation (W3-S02 probe): reverted (no unproven-entry removal before the spawn) → exit 101 (`unwrap()` on `Unavailable("mux_path_occupied")`); restored → exit 0
  - regression unsafe_mux_directory_refuses_the_start_unrepaired (item 6 dir): reverted (mux dir checked only as a directory) → exit 101 (`unwrap_err()` on `Ok`); restored → exit 0
  - regression start_master_refused_for_non_holder (W3-R05): reverted (slot-holder check removed) → exit 101 (`unwrap_err()` on `Ok`); restored → exit 0
  - regression slot_transfer_during_spawn_leaves_no_recorded_master (W3-R05): reverted (no re-read in the recording transaction) → exit 101 (`unwrap_err()` on `Ok`); restored → exit 0
  - regression restart_closes_master_whose_deadline_passed_while_absent (W3-S01 probe): reverted (keep on stored facts alone) → exit 101 (`r.closed` `[]` vs `[m]`, master in `kept`); restored → exit 0
  - regression restart_without_accepted_time_closes_masters (item 4): same revert → exit 101 (`closed` `[]`); restored → exit 0
  - regression process_that_execs_another_image_during_grace_is_not_killed (W3-R09): reverted (no re-verify before SIGKILL, i.e. Linux's old behaviour on this host) → exit 101 ("never SIGKILLed": `Closed` vs `Pending`); restored → exit 0
  - regression pass_discovery_failures_are_explicit (W3-R11): reverted (failures swallowed into `Ok`) → exit 101 (`Ok(PassReport{..})` vs `Err(DiscoveryFailed{grants:[g]})`); restored → exit 0
  - regression owned_row_invariant_checked_at_insertion (U7-Q4): reverted (invariant always true) → exit 101 ("a dedicated row needs a launch binding's holder"); restored → exit 0
  - regression (unit) owned_launch_pins_prefix_and_master_argv_follow_the_ruling (W3-Q1): reverted (all of `OWNED_LAUNCH_PINS`) → exit 101 (argv mismatch); restored → exit 0
  - Windows `windows_register_while_suspended_under_gate`, `windows_non_ssh_run_has_no_job_object_by_default`: compiled and Windows-clippy clean only; **not run, revert not run** (blocked: native Windows).
- Checks (final tree): `TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_connections` 6 runs exit 0 (38 then 39 passed); `cargo test -p heimdall --test e2e_deadline_m03` exit 0 (1 passed; Windows bodies cfg'd out); `--lib`: runtime 25 passed, localenv 89, launch 61 (+2 ignored), each exit 0; host clippy `-p heimdall-runtime -p heimdall-localenv -p heimdall-launch -p heimdall --all-targets --locked -D warnings` exit 0; Windows clippy (same packages, `--all-targets`) exit 0; `linux-xcheck.sh -p heimdall-runtime -p heimdall-localenv` exit 0; `rustfmt --edition 2024 --check` on my three files exit 0, and no diff in `sys/mod.rs` (rustfmt also walks F6's `managed_dir.rs`, which has its own diff; not mine).
- Process hygiene: reverted runs that panicked before `shutdown` orphaned 9 test masters (exact PIDs from the revert logs and start times 07:20:04–07:29:08 local); each re-verified (PPID 1, `/usr/bin/ssh`, start time, `-M -N … hm-u7-d…` args) and stopped by exact PID with SIGTERM; all gone. Green runs leave none. **Three other orphaned U7-style masters (PIDs 49439, 49507 started 06:09:31, 51013 started 06:11:48 local) predate my runs and are not mine: left alone, for the integrator.**
- Residuals / notes: removing an unproven entry does not end that listener; its open sessions are `not_controlled` (disclosed in the module docs). A legit holder master whose `-O check` fails transiently during a close pass can lose its path entry (fail closed: clients then connect directly). Ancestors above `runtime_dir` are not checked for symlinks (macOS `/tmp` is one); `runtime_dir` itself must be a real directory owned by the user. The "managed fixture" of item 12 is a `fake_agent` grant whose gate is registered through `SigningGates::retain` (a managed grant through `ensure` is `driver_unavailable` until U10). For U10: wire `ConnectionConfig::time_gate` (or pass `Some(ops)`), handle `DiscoveryFailed` by keeping the cleanup intent, call `clear_slot_path` when clearing a slot.
- Follow-up (integrator applied the U7-Q4 store check and `register_owned_connection`'s holder refusal):
  fixture fix only, no product change. `tests/integration/connections.rs`: `World::row_for` and
  `unverifiable_holder_never_signalled` now record the binding's holder (`Txn::set_binding_holder`, the
  row's own exact PID and start token, as U0b row 19 does; new helper `holder_of`) in the same transaction
  before inserting the dedicated row. `tests/e2e/deadline_m03.rs` (Windows): `world()` now binds the
  ensured binding as a **Launch** binding through `Operations::bind` (`BindForm::Launch`, executable = the
  in-box ssh, holder = this test process, which is the launcher calling `spawn_contained_and_wait`), so
  `register_owned_connection` finds a holder. `windows_launcher_death_ends_ssh_through_job` uses its own
  fixture registrar and is unaffected. Checks: `TMPDIR=/tmp cargo test -p heimdall-runtime --test
  integration_connections` 3 runs exit 0 (39 passed each); `cargo test -p heimdall --test
  e2e_deadline_m03` exit 0 (1 passed); host clippy `-p heimdall-runtime -p heimdall --all-targets --locked
  -D warnings` exit 0; `bash .m03-wave3-xcheck-windows.sh -p heimdall-runtime -p heimdall --all-targets`
  exit 0; rustfmt `--check` on my three files exit 0. The Windows bodies still need the native run.
- Hygiene follow-up (a panicking test leaked its masters): `tests/integration/connections.rs` `World`
  records every binding it creates (`bindings`); `Drop` (also on a panic, before the fixture sshd drops)
  enumerates the master rows the supervisors under test recorded for them (store read inside
  `catch_unwind`, mutexes taken poison-tolerant) and stops each by exact identity through `stop_exact`:
  start token read before and after `ProcessPin::open`, then `ProcessPin::verify` against the row's image,
  then SIGKILL, bounded wait; never by name. A master a supervisor never recorded is already killed by
  its `Starting` guard; the test's own children are killed by their handles as before.
  `no_leftover_processes` is unchanged (it asserts before the drop). Proof: a temporary `panic!` right
  after `owned_master_admits_sessions_before_deadline`'s master was up, run with `--exact` → exit 101,
  master PID 21063 printed; afterwards `ps -o pid=,ppid=,comm= -p 21063` printed nothing (exit 1);
  restored (cmp identical). Checks: `TMPDIR=/tmp cargo test -p heimdall-runtime --test
  integration_connections` 3 runs exit 0 (39 passed each); host clippy `-p heimdall-runtime --all-targets
  --locked -D warnings` exit 0; `bash .m03-wave3-xcheck-windows.sh -p heimdall-runtime --all-targets`
  exit 0; rustfmt `--check` on my three files exit 0. Orphaned `/usr/bin/ssh` with PPID 1 afterwards: 0.
