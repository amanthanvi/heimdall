# Worklog R (runtime-side gaps for U12), M03 wave 5

Owner files: `crates/app/src/operations.rs`, `crates/app/src/operations/*.rs`, `crates/app/src/lock.rs`
(items below only); `m03_cmd.rs` fn `internal` + a helper beside it; tests in app/runtime targets or a
new fn in `tests/e2e/cli_m03/access.rs`. No contract / migration / `app::ports` signature changes.

## Findings
- Item 1: `ManagedReport` (adapters/managed/report.rs `compute`) is built in `prepare::outcome` and
  dropped by `ManagedCertificateAdapter::prepare_from` (`.map(|(o, _)| o)`, mod.rs ~436) and by
  `reissue_from` (`let (outcome, _)`). `CredentialAdapter::prepare_from -> PrepareOutcome` (app::ports)
  has no field for any of `lock_continuity/conditions/refresh_condition/revocation/evidence/
  connection_policy`; m03-plan §0 row M2 freezes `PrepareOutcome`'s shape. App cannot compute the
  wording itself (crate graph forbids app -> localenv/adapters; DEADLINE_* live in localenv). => escalation.
- Item 3: there is no contract type for the policy result: `policy_view` is untyped JSON built in app.
  No field to fill => escalate (built behind a `false` switch).
- Item 2: test `linux_revoke_on_lock_labelled_signal_unverified` exists (tests/model/lock_behavior.rs:794)
  but calls `label_completed` by hand. Operations does not know the signal (port has no `signal()`).

## Progress
(see below)
- Item 2 DONE: `LockSignal::of_platform`, `Operations::{set_session_lock_signal, session_lock_signal}`,
  `label_grant_lock`/`label_capabilities_lock` (operations/lock.rs); wired in operations.rs `ensure`,
  `delegate`, `bind`, `policy` (SetLockBehavior), `inspect` (Capabilities). Narrowing state gains
  `lock_signal`. Test extended: tests/model/lock_behavior.rs `linux_revoke_on_lock_labelled_signal_unverified`
  (host-runnable via set_session_lock_signal(LinuxLogind)). pass exit 0; reverted wiring -> exit 101
  (panic line 874); restored shasum e801d917… ; rerun exit 0. Whole target 16 passed.
- Item 4 DONE: m03_cmd.rs `internal` arm -> `session_lock_state_envelope(env)` + `test_session_lock_state`
  (cfg debug: FakeSessionLockSource::from_state_file) + `lock_signal_name`. Platform: PlatformSessionLockSource
  start/snapshot/shutdown. Data {state, source, signal}. Manual: fake locked -> OK; platform macOS -> unlocked,
  macos_screen_lock; nothing written.
  Test: tests/e2e/cli_m03/access.rs `internal_session_lock_state_reads_the_source_read_only` pass exit 0.
  Revert (arm -> USAGE_ERROR refusal) exit 101 (access.rs:840 code 2 != 0); restore by targeted Edit; shasum
  70593a4d… (= pre-revert); rerun exit 0. NOTE: first restore by whole-file cp raced W's concurrent edits of
  m03_cmd.rs (file then held my revert text); fixed by targeted Edit; hash back to the pre-revert value.
  Never cp whole shared files again.
- Item 1, 3 escalated: questions file "## R (runtime gaps)" Q-R1, Q-R2 (no code); Q-R3 records the signal reading.
- Extra test: access.rs `lock_behavior_results_labelled_signal_unverified_on_linux_only` (passes here = absence; Linux half native).
- Item 5: access:: 8 passed (exit 0). Managed half still blocked (needs managed grant: enrolled pair + issuer child + scratch store; plus Q-R1).
- Checks: host clippy -D warnings (app+heimdall, all targets) 0; clippy-windows.sh -p heimdall-app -p heimdall 0;
  linux-xcheck -p heimdall -p heimdall-app 0; cargo check -p heimdall --release 0 (pre-existing warning SCRATCH_STORE_DIR unused in release);
  model_lock_behavior 16 passed; app lib 54; runtime model_operations 186; integration_session_lock 4 (+1 ignored native);
  e2e_managed_m03 existing_access_..._byte_identical_to_m02 passed. Removed target/release (created by my release check, 218M).
- DONE. Final report sent.
