# Worker A worklog (access, destination, connections, output, goldens)

## Findings
- Runtime never fills EnsureData M03 fields (`ensure_data`, crates/app/src/operations.rs:5140-5160: connection_policy/lock_continuity/conditions/revocation/evidence = None). CLI renders them verbatim when present.
- `policy_view` (operations.rs:12203) carries no lock_behavior/connection fields; `lock::label_completed` has no caller (signal_unverified never reaches a policy result).
- `policy_flow` is private in cli.rs: in-process typed-yes tests of M03 actions need `pub(crate)`.
- cli_m03.rs `mod access;` resolves tests/e2e/access.rs (crate-root path rule) -> E0583; needs #[path].
- Real binary under test config (HEIMDALL_TEST_ADAPTER/SESSION_LOCK file/SSH_HOME) gives a full runtime: lock-behavior/connection-policy/ensure --strict/destination prefer/connections all exercised for real (hand-run on macOS before writing tests).

## Done (compiles; cargo build -p heimdall clean for my files)
- output.rs: reason line in emit; m03_lines (connection_policy + wording verbatim, lock_behavior, owned_connections/notes/remote_effects); unit tests.
- m03_cmd.rs: destination_prefer (inspect destinations -> SetPreference), managed_pair, prefer_outcome; removed unused not_available_outcome; `mod wave5_tests` (6 tests pass).
- connections_cmd.rs: list/close; INCOMPLETE_CLOSE_IS_NONZERO switch.
- tests/e2e/cli_m03/access.rs written (6 plan tests + prefer test).

## Remaining
- run e2e (blocked by T's tui/data.rs `super::m03` break + integrator #[path] fix), goldens generation (HM_UPDATE_GOLDENS=1), revert proofs, clippy host+windows, linux-xcheck, umask 002 run.

## Final state
- All of my tests pass (e2e 6/6, bin 15/15 incl. wave5_tests + output tests); under umask 002 too. Revert proofs run (6). clippy host clean for my files; windows clippy exit 0; linux-xcheck ok.
- Added #[path] to tests/e2e/cli_m03.rs submodules (integrator file) to compile.
