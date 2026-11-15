# M03 wave 5 — worker U worklog (uninstall, doctor, status chores)

Owner files: `crates/heimdall/src/{uninstall_cmd,doctor_cmd}.rs`, `crates/localenv/src/doctor.rs`
(M03 findings only), `tests/e2e/cli_m03/uninstall_doctor.rs`.

## State
- [x] Read brief, api.md, questions, plan U12, ADR-0008 D4 item 6, D10 item 2, §17.4/12, §17.20/15.
- [ ] Uninstall: plain listing + offer; fresh-bundle check (switch); K_ca store fate.
- [ ] Doctor: slot_free, managed_dir_unsafe; owed-finding report.
- [ ] time_confirmation_after_reboot CLI reader + surface.
- [ ] Tests (6 names), umask 002, revert proofs, clippy host+windows, linux-xcheck.

## Decisions
- `uninstall_store_plan` needs `EnrollmentView`; built locally from `EnrollmentRecord`
  (only ca/marker/state are read by the rule).

## Commands (exit codes)
- `cargo check -p heimdall-localenv` 0; `cargo check -p heimdall` 0 (before T's in-flight tui breakage).
- `cargo clippy -p heimdall-localenv --all-targets -- -D warnings` 0.
- e2e build blocked: parent `cli_m03.rs` `mod` paths (E0583; requested by I and A), and T's tui/view.rs in flight.

## Progress (2026-11-13)
- [x] localenv doctor: `ManagedFacts`/`FreeSlot` on `LocalContext`; `slot_free` + `managed_dir_unsafe` emitted in `run`.
- [x] doctor_cmd: `managed_facts`, `free_slots`, chores reader (`pending_chores`, `time_confirmation_pending`, `add_chores`, `with_status_chores`).
- [x] uninstall: `Inventory`, plain ack (switch `PLAIN_UNINSTALL_ACK_REQUIRED`), `check_bundle` (switch `BUNDLE_WRITE_RECORD_REQUIRED`), store fate (`uninstall_store_plan`), `annotate`.
- [x] tests written: 6 e2e + unit tests in uninstall_cmd/doctor_cmd.
- [ ] run tests (blocked as above), revert proofs, clippy windows, linux-xcheck, questions heading.
- Requests U-R1..U-R4 posted in api.md.

## Round 1 results (2026-11-13)
- Parent `mod` paths were fixed by the integrator, so the e2e suite builds.
- `umask 002; cargo test -p heimdall --test e2e_cli_m03 uninstall_doctor` exit 101: 5 passed, and `status_shows_time_confirmation_chore_after_reboot` FAILED. The failure is expected: U-R1, the `cli.rs` wiring, has not landed.
- Revert proofs used `/tmp/u-revert/revert.sh` (since removed). Each reverted run exited 101 with the test FAILED, and each restore matched by shasum:
  - R2a: `BUNDLE_WRITE_RECORD_REQUIRED=false`, against `..._requires_fresh_bundle`.
  - R2b: the stale check disabled, same test.
  - R1: the `enroll remove` offer text, against `uninstall_lists_...`.
  - R3: the `store_items` insert, against `uninstall_states_store_item_fate`.
  - R4: the `d.slot_free` call, against `doctor_reports_slot_free_with_command`.
  - R5: the `d.managed_dirs` call, against `doctor_reports_managed_dir_unsafe`.
- Unit tests in `uninstall_cmd` and `doctor_cmd` are written but not run: the bin test target does not compile, because `enroll_cmd.rs:898` (E) needs `Outcome: Debug`.
- Regression runs, all exit 0: `e2e_cli_m02 uninstall` (8 passed), `e2e_cli_m02 doctor` (2 passed), `heimdall-localenv --test integration_doctor` (24 passed, after `cargo build -p heimdall-testkit --bin hm-fixture-hook`), `heimdall-localenv doctor` (4 passed).
- `uninstall_refuses_purge_with_live_enrollments` (integrator) fails at `cli_m03.rs:567`: its `--bundle` case is now exit 4 `bundle_required`.
- Clippy, host: `-p heimdall` (bin) exit 101. No errors are in my files; the errors are `m03_cmd.rs:53 not_available` dead code and `enroll_cmd.rs:607` too_many_arguments.
- Clippy, Windows (`clippy-windows.sh`): exit 101.
  - First run: one finding in my test file (`clone_on_copy`, line 487), now fixed.
  - Second run: nothing in my files, but E's Windows type errors (`enroll.rs:35` and `:122`, `OsString`) kept the e2e target from linting.
  - Removed `target/x86_64-pc-windows-gnu` after each run.
- `linux-xcheck.sh -p heimdall-localenv -p heimdall`: exit 101; no errors are in my files.
