# M03 wave 3, round 2 (review fixes): shared brief (untracked; integrator)

Worktree = cwd of this file. HEAD `3f7a582e` (wave 3 committed). Two uncommitted files are the
orchestrator's and must stay exactly as they are: `docs/decisions/0008-managed-credential-integration.md`
(it adds **§17.20**) and the reviews `tests/evidence/artifacts/review-m03-code/wave3.md` (W3-R01–R11) and
`wave3-security.md` (W3-S01–S05, with probe scenarios). Do not edit them. The integrator already amended
`docs/architecture/m03-plan.md` §0.6 (U7-Q1); do not edit it.

## Binding rules
- **Every rule of the round-1 brief still applies:** `tests/evidence/artifacts/review-m03-code/wave3-notes/m03-wave3-brief.md`
  (sources, reserved files, escalation, lints, `unsafe` only in declared modules, process signalling,
  build hygiene — **never** `CARGO_TARGET_DIR`/`--target-dir`/`cargo clean`, disposable fixtures only,
  never print secrets, evidence discipline, **no commits/stash/reset/checkout, no subagents**). The
  round-1 readings R1–R9 are in `wave3-notes/m03-wave3-api.md`, the questions in
  `wave3-notes/m03-wave3-questions.md`. **ADR-0008 §17.20 rules on every finding and escalation; its
  items are the fix list, and where it differs from anything earlier, §17.20 wins.**
- Windows clippy for your packages: `bash .m03-wave3-xcheck-windows.sh -p <pkg> --all-targets`
  (fixed). Linux type-check: `bash tools/validation/linux-xcheck.sh -p <pkg>`. Do not run `check.sh`.
- **Each regression must fail with its fix reverted.** For every regression you add, temporarily revert
  the fix (or the minimal part of it), run the test, record the real failing exit code and assertion,
  restore, re-run green. Record each in the worklog as `regression <name>: reverted → exit N (<what
  failed>); restored → exit 0`. Never leave a revert in place.
- Tests count and stop only exact PIDs they started; never kill by name or pattern.
- **Native results at `3f7a582e`** (for information): Windows passed all 11 U7 `windows_*` tests and
  all of `integration_managed_adapter`; the devbox failed only W3-N01
  (`master_socket_removed_only_if_same_inode`, `assert_ne!(old, new)` with equal `(dev, ino)`: ext4 reused
  the inode). The two Windows tests §17.20 item 12 changes must keep passing natively — write them so
  they can.

## Ownership in round 2
- **Agent F6 (adapter side):** `crates/adapters/src/managed/**`, `tests/integration/managed_adapter.rs`;
  for item 2 the signer listing in `crates/credential/src/table.rs` (and the endpoint listing it feeds,
  `crates/credential/src/endpoints.rs`, only if needed) with tests in `tests/integration/managed_signer.rs`
  or the adapter suite; for item 7 any new FFI goes only in a **new file
  `crates/localenv/src/sys/managed_dir.rs`** (a submodule of the declared `sys` module, like
  `quarantine.rs`), whose `mod managed_dir; pub use managed_dir::*;` lines in `sys/mod.rs` and its rows
  in the `sys/mod.rs` table and `docs/architecture/overview.md` §9 item 3 F6 may add — **prefer the
  existing safe handle-relative patterns** (rustix `openat`/`fstat`/`unlinkat`/`renameat` with
  `O_NOFOLLOW|O_DIRECTORY`, the quarantine's identity-checked removal) so no new `unsafe` is needed;
  for item 14 U6-Q6 `schemas/examples/ensure-data.managed.json` (`consumer.signing_endpoint` only) and the
  contract tests that read it (find them: `grep -rn ensure-data.managed tests crates`).
- **Agent F7 (connection side):** `crates/runtime/src/connections.rs`, `tests/integration/connections.rs`,
  `tests/e2e/deadline_m03.rs`, `crates/launch/src/windows.rs`, the U7 parts of
  `crates/localenv/src/sys/mod.rs` (everything except F6's two `managed_dir` lines and rows),
  `crates/heimdall/src/run_cmd.rs` (only if item 12 needs it), overview §9 rows for F7's FFI.
- Both may edit `sys/mod.rs` and `overview.md` in **distinct regions**; re-read before every edit.
- Reserved-file needs (Cargo.toml dev-deps, `crates/app/**`, `crates/store/**`, contract, domain):
  write them under "Requests" in `.m03-wave3-r2-worklog.md` with exact text; take the fail-closed
  choice that compiles; the integrator applies.

## Report (final message)
Per §17.20 item you own: what changed (files, functions); each regression's name, its green command +
exit code, and its revert result (exit code + failing assertion); every other test you touched; the
commands that matter with exit codes (check, `--test` runs, clippy host, Windows clippy, linux-xcheck,
`rustfmt --check` on your files); requests for the integrator; anything left open or failing closed;
and **which tests need Windows-native or devbox runs, by exact target and name**.
