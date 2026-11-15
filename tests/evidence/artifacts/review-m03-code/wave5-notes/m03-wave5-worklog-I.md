# M03 wave 5 — integrator worklog (resume from here)

Base: `main` at `8710717a`, branch `feat/m03-wave5-cli-tui`. Goal: U12 (m03-plan line 1833) + owed items.
Round 1 in progress. No commits (orchestrator commits).

## State
- [x] Oriented: U12 section, §0, wave-4 brief read. clap tree for M03 exists in `cli.rs` (integrator-owned).
- [x] Investigations done (3 Explore agents; conclusions folded into `.m03-wave5-api.md` R3-R5).
- [x] Seams landed (see api.md R0): contract `registry_path_invalid` + `managed_dir_unsafe` (+golden,
  plan §5 item 14, ADR-0006 §16.1 row 14); cli.rs lock-behavior/connection-policy/ensure --strict
  wired; prefer routed to `m03_cmd::destination_prefer` (async Outcome stub); cli_m03 submodules;
  `e2e_tui_m03` target. contract tests 89 passed; `cargo build -p heimdall` clean.
- [x] api.md, brief, questions (Q-I1 terminal handoff) written.
- [x] Workers E, I(=IS), U, A, T round 1 done (reports summarized below; full in their worklogs).
- [x] U-R1 wired (cli.rs status chores) -> `status_shows_time_confirmation_chore_after_reboot` passes;
  `policy_flow` pub(crate) (A request).
- [x] R: label_completed applied (ensure/delegate/bind/SetLockBehavior/inspect capabilities);
  `internal session-lock-state` implemented read-only. Q-R1 (EnsureData managed fields need frozen
  PrepareOutcome change), Q-R2 (policy view untyped), Q-R3 (signal reading).
- [x] W: integrator tests rewritten (renamed w0 -> `m03_cli_commands_answer_without_a_runtime_and_never_panic`),
  not_available helpers deleted, guard `no_m03_source_contains_the_wave_0_text`; e2e_cli_m03 31 passed.
- [x] check.sh run 1: overall 1 (test step 101: testkit guard `no_other_test_reads_the_compile_time_root`
  flagged CARGO_MANIFEST_DIR in m03_cmd.rs wave5_tests + cli_m03.rs guard) -> fixed via repo_path.
- [x] check.sh run 2: every step 0 (test totals 2859 passed, 0 failed, 191 ignored);
  linux-xcheck --workspace 0; umask 002: e2e_cli_m03 32p/2i, e2e_tui_m03 5p/1i, e2e_tui_m02 17p/1i, bin 148p.
- [x] Integrator revert proofs: U-R1 status chores (101 -> 0), ensure --strict wiring (101 -> 0),
  is_widening (no test caught it -> added `cli::tests::m03_policy_actions_attend_only_when_widening`;
  101 -> 0). clippy host 0, clippy-windows 0 after the new test.
- [ ] Integration, check.sh, linux-xcheck, U12 tests under umask 002, revert proofs.
- [x] Notes archived to `tests/evidence/artifacts/review-m03-code/wave5-notes/`, root copies removed.

## Decisions
- `not available` call sites: issuer_cmd, enroll_cmd, connections_cmd, m03_cmd (destination_prefer,
  lock_behavior, connection_policy, ensure_strict), catalog_cmd:147, cli.rs:1384, uninstall_cmd:131.
- New `[[test]] e2e_tui_m03` in crates/heimdall/Cargo.toml (integrator).

- `#[path = "cli_m03/<x>.rs"]` kept: crate-root `mod x;` resolves to tests/e2e/x.rs; precedent
  `enroll_m03.rs:48` (wave 4). §0.1's "no #[path]" is about cross-target inclusion.

## Round-1 worker outcomes (compact)
- E: all enroll forms; 9 e2e + 7 unit pass (unix-gated except bundle test). Switches
  `enroll_cmd::SCRIPT_PAUSE_POINTS_CONSUMED=false` (Q-E1), `REFUSE_UNHELD_INTERACTIVE_IDENTITY=true`
  (Q-E2/Q-I1 c). Q-E3 hold field, Q-E4 connect vs run command.
- IS: all issuer cmds; 5 e2e pass. S3 blocks register/passphrase/deletion on scratch (Q-IS1;
  `issuer_cmd::S3_TEST_STORE_DELETION=false`). last_bundle_at getter/setter in store+app,
  `RECORD_LAST_BUNDLE_AT_ON_REPLY=false` (Q-IS2). `issuer_cmd::retire_to_retired` for U.
- U: uninstall D4 item 6, doctor slot_free + managed_dir_unsafe, chores reader; 6 e2e pass.
  Switches `uninstall_cmd::BUNDLE_WRITE_RECORD_REQUIRED=true`, `PLAIN_UNINSTALL_ACK_REQUIRED=true`.
  Q-U1..U5. U's unit tests were not run (build break at the time) — integrator runs them.
- A: prefer, connections, output m03_lines, 24 help goldens, reasons exit table; strict/revoke
  e2e only partial (ensure_data drops connection_policy; label_completed no caller).
  Switch `connections_cmd::INCOMPLETE_CLOSE_IS_NONZERO`. Q-A1, Q-A2. Removed not_available helpers.
- T: tui/m03.rs + 12 snapshots; 8 plan tests pass (4 pty unix). Q-T1..T6. Switches
  `tui::m03::switch::{OWNED_MASTERS_LINE=None, disclosure_text->None}`.
