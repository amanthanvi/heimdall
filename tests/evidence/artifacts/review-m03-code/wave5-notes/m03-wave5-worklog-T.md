# M03 wave 5: worker T worklog (TUI)

Owner files: `crates/heimdall/src/tui/**` (snapshots included) and `tests/e2e/tui_m03.rs`.
Base: `main` 8710717a plus the integrator's seams. Nothing committed.

## State
All of the following is done:
- Read the briefs. One Explore helper surveyed the data sources.
- `tui/m03.rs` is new: M03 data parsed tolerantly, the wording, the readable M03 decision lines, and the fail-closed `switch` module.
- `data.rs`: adds `Destination.preference` and `Catalog.m03`. `Decision::operation()` now also reads `operation`.
- `worker.rs`:
  - `REFRESH_SUBJECTS` adds `enrollments`, `connections` and `capabilities`, and never `issuer`.
  - The `TIME_UNCERTAIN` warning is captured.
  - With no runtime connected, `Update::OfflineChores` comes from U's `doctor_cmd::pending_chores`.
  - The passive doctor sets `local.managed = doctor_cmd::managed_facts(ctx)`.
- `model.rs`:
  - New overview items: `Chore`, `Enrollment`, `LateWrite`, `ProjectionPending`, `SlotFree`.
  - New `Screen::Enrollment` and `ActivityRow::Enrollment`.
  - New Approve gate (`m03::approve_block`).
- `view.rs`: the item texts (command first), an Enrollments section in Activity, the managed-readiness block in the destination detail, the M03 decision modals, and tests in `view::tests::m03`.
- Snapshots: 12 new `m03_*` files. The M02 snapshots were verified byte-unchanged with sha256 before and after.
- `tests/e2e/tui_m03.rs`: one ungated test and four pty tests (`#[cfg(unix)]`).
- Revert proofs: 9 runs, each failed with the fix reverted and the restored sha256 matched (details below).
- Questions Q-T1..Q-T6 are written. Requests T-R1 (to I), T-R2..R4 (to integrator) and one to E are posted.

## Decisions
These are the fail-closed switches:
- `m03::switch::OWNED_MASTERS_LINE = None` (Q-T3).
- `m03::switch::disclosure_text -> None` (Q-T4). Approve is not offered for an M03 decision with an unshown disclosure.
- Hold reason (Q-T1), pair connection policy (Q-T2) and lock report (Q-T5) are parsed from additive fields. Each reads "unknown" when the field is absent.
- Time chore (Q-T6): from the runtime's `TIME_UNCERTAIN` warning while connected, from U's store reader otherwise.

## Commands and exit codes (macOS arm64 host)
- `cargo build -p heimdall`: 0.
- `cargo test -p heimdall --bin heimdall tui::`: 51 passed, exit 0, under umask 002 and under 022.
- `cargo test -p heimdall --test e2e_tui_m03 --test e2e_tui_m02`: 5 + 17 passed (1 ignored each), under umask 002 and under 022.
- `cargo clippy -p heimdall --bin heimdall --tests`: 0, with no warnings.
- Windows: `cargo clippy --target x86_64-pc-windows-gnu -p heimdall --bin heimdall --tests` with the zig shim: 0, with no warnings. The full `clippy-windows.sh` exited 101, on other workers' files at the time.
- `bash tools/validation/linux-xcheck.sh -p heimdall`: 0.

Revert runs. Each reverted run exited 101, the test failed, and the restored sha256 matched:

| Run | What was reverted |
|---|---|
| r1 | selection ignored |
| r2 | projection-pending item |
| r3 | `slot_free` arm |
| r4 | approve gate (unit) |
| r5 | issuer added to refresh |
| r6 | warnings not captured (e2e) |
| r7 | no enrollment rows (e2e) |
| r8 | approve gate (e2e) |
| r9 | search emits a network probe (e2e; listener contacted 22 times) |
