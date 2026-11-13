# M03 wave 5 round 2: worker T2 (TUI) worklog

Owner files: `crates/heimdall/src/tui/**` (snapshots included), `tests/e2e/tui_m03.rs`; my section
in `.m03-wave5-r2-api.md` (### T2), heading "## T2 (TUI)" in `.m03-wave5-r2-questions.md`.
Items (§17.25): 4, 10 (Approve limit), 15, 17, 19/20, 21 (read side).

## Decisions
- Approve limit (item 10): read-only kinds = `enroll_account`, `enroll_system_form`,
  `register_issuer` (init, rotation, restore), `retire_issuer`, and `remove_enrollment` (its
  follow-through is the CLI's step loop: `enroll_cmd::remove_flow` -> `settle` -> `drive`).
  `approve_target_change` keeps Approve: the runtime runs its verification on approval
  (`enrollment_m03.rs` `enrollment_after_decision` -> `verify_operation`), no disclosures.
  Read-only = no Approve. **§17.26 (Q-T2-1, Q-T2-2 answered):** Deny allowed on every read-only
  kind after the typed yes; implemented (round 2b, below).
- Disclosures (item 10): IS2's `heimdall_issuer::ceremony::disclosure_text(kind, &DisclosureContext
  {alias, lock})`, lock = `capabilities.lock.disclosure`; unknown kind -> `UNKNOWN_DISCLOSURE`,
  Approve blocked. Round-1 `switch` module deleted (no switches left in tui/).
- Deadline wording (19/20): runtime `wording` verbatim, else "unknown"; no local derivation.
- Time chore (15): keyed on `Warning.reason == m03_warning::TIME_CONFIRMATION_AFTER_REBOOT`.
- Lock (21): `LockReport.acknowledged_at`; decision modal shows the text only until acknowledged;
  detail shows behaviour always, plus the text (unacknowledged) or the ack time.
- Item 17: managed detail shows `crate::output::ORDINARY_CONNECTIONS_NOTE` under owned connections.

## Progress (all done unless noted)
- m03.rs, model.rs, view.rs edited; tests rewritten; new unit test
  `cli_decided_kinds_never_offer_approve_and_show_their_command`.
- Snapshots: 4 m03_* regenerated; the 23 M02 snapshots sha256-identical (checked twice).
- e2e: `enrollment_states_rendered` asserts the runtime's `hold` (E2 landed);
  `time_confirmation_chore_shown_after_reboot` asserts the runtime warning's reason (R2 landed);
  `tui_restores_terminal_after_enroll_decision` = read-only enroll + Deny of a target change.
- R2's `capabilities.lock` landed (`lock_connection_m03::add_capabilities_lock`): the e2e
  `tui_restores_terminal_after_enroll_decision` now asserts the runtime's lock text in the modal,
  then `acknowledge_lock_disclosure()` and "acknowledged ...; not shown again".
- Still unit-level: `managed_readiness_detail_exact_deadline_strings` (the `preference.
  connection_policy` object is the serde form of `ConnectionPolicyReport` with the adapters' real
  `connection_wording`); an e2e needs a seeded managed pair preference + covering policy + wired
  wording source (not attempted). `lock_disclosure_once` itself stays unit-level (its runtime
  half is in the e2e above).

## Commands and exit codes (macOS arm64)
- `cargo test -p heimdall --bin heimdall tui::` umask 022: 0 (52 passed); umask 002: 0 (52 passed).
- `cargo test -p heimdall --test e2e_tui_m03`: 0 (5 passed, 1 ignored child entry).
- `cargo test -p heimdall --test e2e_tui_m02`: 0 (17 passed, 1 ignored).
- `cargo clippy -p heimdall --no-deps --profile test --bin heimdall --test e2e_tui_m03 -- -D warnings`: 0.
- `cargo clippy -p heimdall --no-deps --bin heimdall -- -D warnings`: 0.
- Windows (zig shim, same as clippy-windows.sh): `cargo clippy --target x86_64-pc-windows-gnu -p heimdall
  --no-deps --profile test --bin heimdall --test e2e_tui_m03 --locked -- -D warnings`: 0; `--bin heimdall`: 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall`: 101 twice, both on other workers' in-flight
  code: first `heimdall-app` `clone_on_copy` (operations.rs:5171/5173, R2), last
  `heimdall-issuer` dead `write_marker` (store/test_product.rs:162, IS2). Not TUI code.
- Revert proofs (each: reverted run exit 101, test FAILED, restored sha256 matched):
  r1 time chore keyed on code only; r2 `next` read as a string; r3 model cli_only gate;
  r3b `enroll_account` not classified; r4 deadline derived from modes; r5 `acknowledged_at`
  ignored; r6 no ordinary note; r2e (e2e enrollment_states_rendered) `next` as string;
  r7e (e2e tui_restores_terminal_after_enroll_decision) model gate; r5e (same e2e)
  `acknowledged_at` ignored (timed out waiting for the acknowledged text).
- Scratch: /tmp/t2-* (revert patches, logs, zig shim, sha list) removed.

## Round 2b: §17.26 Deny on read-only decisions
- model: `cli_only` kinds force `Verdict::Deny` (Tab and Enter); Approve never sent. view: prompt
  "Approve in the CLI: run `<cmd>` · Esc: send nothing" + "Deny? Type yes"; notice text updated.
- Unit `cli_decided_kinds_never_offer_approve_and_show_their_command`: adds foreign removal; typed
  yes after 0/1/2 Tabs sends exactly one Deny; Esc, Ctrl-C, Ctrl-D byte+Enter, empty Enter, `no`,
  `nope` send nothing. `lock_disclosure_once`: typed yes on read-only kinds = Deny.
- e2e `tui_restores_terminal_after_enroll_decision` now denies the enroll decision itself (Esc and
  `no` first send nothing; Tab keeps Deny). True EOF is the hangup exit 129 (`e2e_tui_m02`
  `hangup_watchdog_exits`); the unit test uses the Ctrl-D byte.
- Snapshots: m03_decision_enroll_{120x40,40x12} regenerated; 23 M02 snapshots `git diff --quiet HEAD`.
- Revert (Deny re-blocked in model.rs): unit 101, e2e 101 (timed out waiting for the answer);
  restored sha256 0838a8c8… matched; reruns 0 and 0.
- umask 002: unit 0 (52), e2e_tui_m03 0 (5). Clippy host test/bin 0/0; Windows test/bin 0/0.
