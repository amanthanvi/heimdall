# M03 wave 5 — worker I (issuer CLI) worklog

Scope: `heimdall issuer init|status|unlock|rotate begin|retire|restore|bundle` (U12),
owner files `crates/heimdall/src/issuer_cmd.rs` (+ `issuer_cmd/**`),
`tests/e2e/cli_m03/issuer.rs`; R2 grant: `last_bundle_at` in `crates/store/src/ext_m03.rs`
+ `crates/app/src/operations/issuer_m03.rs`. No commits.

## Read (done)
AGENTS.md, brief, api.md (R0-R5), questions; m03-plan U12 + §5 item 24; ADR-0008 D4
items 1-6, §17.21-§17.24, U4-Q2 (b); wave-4 B worklogs (U12 contract). Code: ceremony.rs,
retire.rs, contract issuer.rs, app issuer_m03.rs, m03_cmd::issuer_store, setup_cmd
owner-present helpers, cli_m02 in-process runtime, runtime_m03 real-child rig,
issuer_ceremony pty pattern.

## Findings that shape the work
- S3 bites twice: `RegisterRequest::to_issuer_request` refuses a test store kind
  (register), AND `retire::delete_awaiting` refuses a test store kind (R2B deletion).
  So on the scratch store neither init's passphrase step nor the retire deletion is
  reachable through the real CLI. Escalated (Q-IS1); switch `S3_TEST_STORE_DELETION`.
- A CLI-started runtime wires the account's real `~/.ssh` (cli_m02 header): e2e tests use
  an in-process runtime with the issuer child = real binary `internal issuer` on the
  scratch store (runtime_m03 Rig pattern).
- `testkit::ca::ceremony::run` / `test_ca_ceremony_captures_passphrase_only_from_pty`:
  the self-test does not exist anywhere; `ceremony::run` passes no scratch env and
  can register only on a product store (blocked by S3 on this host).

## Decisions
- Every issuer command's success data is the runtime's `IssuerStatus` (status, init,
  rotate, restore, unlock, retire) or `RecoveryBundle` (bundle): both have schemas.
- Ceremonies need the controlling terminal; `--non-interactive` refused before any
  store/runtime contact (exit 3). Hello declared interactive when the ceremony holds
  the controlling terminal.
- retire: decided_request pattern (non-interactive creates the pending decision and
  answers exit 3 with decision_ref; no Decide).

## Progress
- [x] issuer_cmd implementation (issuer_cmd.rs + issuer_cmd/{session,render}.rs); U-R4 entry
  `retire_to_retired`.
- [x] last_bundle_at getter/setter + bundle_stale refinement, switch RECORD_LAST_BUNDLE_AT_ON_REPLY=false.
- [x] tests: tests/e2e/cli_m03/issuer.rs (5 + child entry); 2 unit tests in issuer_cmd; 3 in
  app issuer_m03 `last_bundle_tests`.
- [x] escalations Q-IS1 (S3), Q-IS2 (last_bundle_at); replies to U-R3/U-R4; api.md section I.
- [x] revert proofs R1-R4, R6 (all 101 reverted / 0 restored, sha verified); S3 switch-on run (0).
- [x] clippy windows: store+app 0; heimdall --bin 0; heimdall test profile 101 only on
  cli_m03/access.rs (A, unused import). Host clippy bin+e2e test profile: 0. linux-xcheck -p heimdall: 0.
- Done. Open: Q-IS1, Q-IS2 rulings.

## Commands (exit codes)
- cargo build -p heimdall: 0
- cargo clippy -p heimdall --bin heimdall [--profile test] -- -D warnings: 101, only in m03_cmd.rs
  (A) / enroll_cmd.rs, setup_cmd.rs (E); none in issuer_cmd.
- cargo clippy -p heimdall --test e2e_cli_m03 -- -D warnings: 101, all in cli_m03/enroll.rs (E).
- cargo clippy -p heimdall-app -p heimdall-store --all-targets -- -D warnings: 0
- windows clippy (shim as tools/validation/clippy-windows.sh) -p heimdall-store -p heimdall-app
  --all-targets: 0; -p heimdall --bin heimdall --test e2e_cli_m03: 101, errors only in enroll.rs,
  access.rs, enroll_cmd.rs, m03_cmd.rs.
- linux-xcheck -p heimdall: 101, errors only in E/A files.
- cargo test -p heimdall --bin heimdall issuer_cmd: 0 (2 passed)
- cargo test -p heimdall-app --lib last_bundle_tests: 0 (3 passed)
- cargo test -p heimdall --test e2e_cli_m03 issuer:: (umask 022 and 002): 0 (5 passed, 1 ignored child entry)
- cargo test -p heimdall-runtime --test integration_issuer_m03: 0 (21)
- S3 switch on (both consts true), issuer::issuer_retire: 0; restored, shasum OK.
- Reverts (reverted → restored): R1 bundle not owner-only/overwrites → 101/0;
  R2 retire approves without typed yes → 101/0; R3 confirm deleted_locator without deleting →
  101/0; R4 replace-orphan bundle not cross-checked → 101 (timeout 120 s)/0;
  R6 bundle_stale boundary weakened → 101/0.
- integrator's w0_m03_cli_commands_report_not_available_and_never_panic: 101 (expected: issuer
  lines no longer answer not-available).
