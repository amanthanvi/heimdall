# M03 wave 5 — worker E (enroll CLI) worklog

Scope: `crates/heimdall/src/enroll_cmd.rs` (+ `enroll_cmd/**`), `tests/e2e/cli_m03/enroll.rs`.
No commits. Read: AGENTS.md, brief, api.md, questions (Q-I1 option (c)), U12, §5 item 24, ADR-0008 D5.

## Decisions
- Loop: own `drive()` (not `setup_cmd::decided_request`: its `settle` would Observe 30 s x4
  on an op that waits for client steps). Uses `setup_cmd::{attend_first, confirm_and_decide,
  not_confirmed, pending_decision}`.
- Ctrl-C: a SIGINT/Ctrl-C stream registered before the first `Step`; on it during a step:
  `StepAbort::abort`, await the blocking run, send no result, print exactly
  "the change may have been applied; run `heimdall enroll reconcile <op>`" (every stage),
  envelope OUTCOME_UNKNOWN (exit 7), next reconcile.
- Pause dir (needs heimdall-registry edge): fail closed — set in a debug build, every enroll
  form except `status` is refused, USAGE_ERROR exit 2, before runtime contact. Switch
  `enroll_cmd::SCRIPT_PAUSE_POINTS_CONSUMED = false`. Request filed in api.md.
- Q-I1 (c): switch `enroll_cmd::REFUSE_UNHELD_INTERACTIVE_IDENTITY = true`; notice before the
  first interactive step; an interactive step whose access pins are not agent-held
  (IdentityAgent concrete + IdentitiesOnly=yes) is not run (refused up front).
- `--after-manual-recovery`: CLI also refuses to run any non-inspect step (never a redispatch).
- `enroll status`: inspect enrollments + destinations (alias for `slot_free_command`). The
  view has no `hold`: read it if present (additive), else say not reported; request filed.
- `remove --from-bundle`: bundle parsed locally; redacted (flag or missing host/port) refused
  `bundle_redacted` (exit 4) before runtime contact.

## Progress
- [x] enroll_cmd implemented (enroll_cmd.rs + enroll_cmd/{drive,render}.rs)
- [x] tests written (tests/e2e/cli_m03/enroll.rs: world, pty, 9 cases)
- [x] clippy host/windows, linux-xcheck
- [x] tests run (+ umask 002), revert proofs
- [x] api.md E section + Requests E-R1..R3, questions Q-E1..Q-E4

## Commands (exit codes)
- cargo clippy -p heimdall --all-targets -- -D warnings: 0
- bash tools/validation/clippy-windows.sh: 0 (heimdall checked)
- bash tools/validation/linux-xcheck.sh -p heimdall: 0
- cargo test -p heimdall --test e2e_cli_m03 enroll::: 0 (9 passed, 1 ignored = pty child entry); umask 002: 0
- cargo test -p heimdall --bin heimdall enroll_cmd: 0 (7 passed)
- full e2e_cli_m03: 101 (4 integrator/other-worker tests: w0_m03_*, m03_test_gates_* [mine: pause msg],
  uninstall_refuses_purge_* [U], status_shows_time_confirmation_* [U-R1])
- revert-all (HEAD-equivalent stub): 101, 9/9 enroll tests fail; restored, shasum identical
- revert (a) bundle redaction check: 101 (exit 5 vs 4); restored identical. NOTE: the first try of (a), before
  the test's home was put under a regular file, spawned a detached runtime (PID 69030, my test's tempdir home);
  stopped by verified PID+start+image+cwd; the test now cannot start a runtime.
- revert (b) Ctrl-C sends a result: 101; restored identical
- revert (c) typed confirmation skipped: 101 (3 tests fail); restored identical
