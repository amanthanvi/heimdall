# M03 wave 4, round 3 — worklog R3-C2 (managed pipeline)

Goal: ADR-0008 §17.22 items 8 (W4-R05/R06), 5 (W4-R02), 6 (W4-R03). Regions per `.m03-wave4-r3-api.md` §0.

## Decisions
- C2-1 (item 8). The cleanup intent of a managed preparation is recorded in the transaction of its `Attempted`
  receipt (before `generate_key`; `in_flight`). The commit (and a cancelled owner's activation for others) retires
  it. While the operation is open (queued/running/outcome_unknown, or continuing for others) and its preparation
  lives in this process (it is running, or the grant holds a `pending`/`installed` instance; after a restart every
  instance is `lost`/`destroyed`), `process_cleanup_intent` skips it. Every managed failure after the attempt fails
  through `fail_managed_preparation` (was: only when `driver_ran`); a managed `prepare_from` timeout and an
  unreconcilable `Attempted`/`Uncertain` attempt at recovery fail too (`fail_unrecoverable_preparation`, never
  `outcome_unknown`). `abandon` reports failures; `cleanup_uncommitted_managed` returns `false` while an instance is
  still live, so the intent is kept and retried.
- C2-2 (item 5). Re-issue step 6 restores the consumers in the driver (`restore_consumers`): every live binding of
  the grant materialized at generation = the grant's instance count (durable, grows with each K_env, ≥ 2), its held
  slots rewritten and listed (slots-only `materialize`), then generations `1..N` cleared; only then
  `reissue_completed`. Partial slot holding → `CONFIG_CONFLICT`, grant stays reissue-pending. Slots-only
  `materialize` rebuilt from the signer table + stored scope, no `materialized` record needed.
- C2-3 (item 6). A follower (coalesced or decision-joined) of a managed grant gets its own binding materialized
  before its commit, by reference to the grant's live K_env (R3C2-Q1), with its own `Follower` intent (clears only
  its binding, never the shared key). Its endpoint is the leader's locator with its own tag (R3C2-Q2). Not
  materializable → refused at the commit, never `ACCESS_READY`.
- C2-4. Real-ssh harness: `managed_store.rs` `live_tests` (cheaper than `enroll_m03`'s full enrollment world):
  `LoopbackSshd` with `TrustedUserCAKeys` + `AuthorizedPrincipalsFile` for this run's fixture CA, `ScratchHome`
  isolation, the managed identity options `connect` renders. Clock = real now (the sshd checks validity).
- C2-5. Crash simulation (W4-R05): process A on its own current-thread tokio runtime in a scoped thread, held in
  `prepare_from` (after step 6 and `managed.prepared`, before `Confirmed`), then `shutdown_background()`.

## Progress
- [x] item 8 (both regressions) - [x] item 5 - [x] item 6 (coalesced + decision-joined) - [x] revert runs
- [x] clippy - [x] fmt (own files; shared-file regions clean) - [x] linux xcheck

## Shared-file functions edited
- `crates/app/src/operations.rs`: `reconcile_unresolved` (managed Unknown/Err arm), `stage_reconcile` (existing-attempt
  managed arm; attempt txn records the intent; result arms: managed `OutcomeUnknown`, managed `Err` → 
  `fail_managed_preparation`), `process_cleanup_intent` (disposition first), `stage_commit` (follower
  materialization, follower refusal, intent retired at commit, follower endpoint, refused follower's intent processed).
- `crates/app/src/operations/managed_driver_m03.rs`: `ReissueConsumers` (new), `managed_reissue_pass` (docs),
  `reissue_consumers` (new), `reissue_completed` (docs), `driver_ran` (removed) → `record_preparation_intent_in`,
  `IntentDisposition` (new), `fail_managed_preparation` (docs), `cleanup_uncommitted_managed`,
  `instances_destroyed_after_cleanup`, `cleanup_intent_disposition`, `fail_unrecoverable_preparation`,
  `cleanup_follower_binding`, `materialize_follower`, `follower_locator`, `with_follower_endpoint` (new).
- `crates/runtime/src/managed_store.rs` `live_tests` helpers: `seed` → `seed_pairs(store, ca, pairs)`; `Hold`,
  `FailPrepare.hold`, `WrapEffects`, `Opts`, `Live::seeded`, `Live::process_opts` (new; `new`/`process`/
  `process_with` keep their signatures); `mod pipeline;`; R2 crash test renamed + docs; `CrashBeforeCommit` docs.
- Wholly mine: `crates/app/src/managed/driver.rs`, `crates/adapters/src/managed/effects.rs`,
  `crates/runtime/src/managed_store/live_tests/pipeline.rs` (new).

## Commands (exit codes)
- `cargo test -p heimdall-runtime --lib managed_store`: 0 (17 → 18 with the joined case; pipeline 5/5).
- `cargo test -p heimdall --test e2e_managed_m03`: 0 (16).
- `cargo test -p heimdall --test e2e_enroll_m03 --test e2e_run_m02 --test e2e_cli_m02`: 0 (66; 54 + 1 ignored; 42 + 1 ignored).
- `cargo test -p heimdall-runtime --test model_operations`: 0 (186).
- `cargo test -p heimdall-adapters --test integration_managed_adapter`: 101 — 47/48; `expired_grant_never_reissued`
  fails at `w.table().public_key(&gid).unwrap()` after expiry: C1's item 4 destroys K_env at expiry (R3-A → R3-C1
  request already filed). Not a C2 change.
- `cargo test -p heimdall-runtime` (all targets): 101 — `integration_runtime_m03::issuer_crash::issuer_crash_blocks_reissue_not_signing`
  fails at line ~5128 (`grant` state after `issuer_supervision_pass`, item 15 / R3-B), before any re-issue; lib 45/45,
  setup_dispatch 9, connections 43, issuer_m03 19, runtime 59 (+2 ignored), runtime_m03 50/51. Remaining targets
  re-run with `--no-fail-fast` below.
- `cargo clippy -p heimdall-app -p heimdall-adapters -p heimdall-credential -p heimdall-runtime -p heimdall --all-targets -- -D warnings`: 0 (not narrowed).
- `rustfmt --edition 2024 --check` driver.rs, effects.rs, pipeline.rs: 0; shared files: no diff in my regions.
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 0.
- Final, after the last edit: `cargo test -p heimdall-runtime --no-fail-fast`: 0 (lib 46, setup_dispatch 9,
  connections 43, issuer_m03 19, runtime 59 + 2 ignored, runtime_m03 51 (issuer_crash now passes, incl. its re-issue
  half), session_lock 4 + 1 ignored, events 19, narrowing_m03 57, model_operations 186, operations_m03 37, setup 51,
  timegate 27). `cargo test -p heimdall --test e2e_managed_m03 --test e2e_enroll_m03 --test e2e_run_m02 --test
  e2e_cli_m02 --no-fail-fast`: 0 (16; 66; 54 + 1 ignored; 42 + 1 ignored). `integration_managed_adapter`: 101, still
  only `expired_grant_never_reissued` (C1's item 4, see above).
- Scratch: `/tmp/c2-revert` and `/tmp/c2-*.txt` removed; test scratch dirs are tempdirs (removed on drop; the
  read-only injection is undone on drop). No `prototypes/*/target` in this worktree.

### Revert runs (`/tmp/c2-revert/revert.py <set> revert|restore`: in-place substitutions, restored by the inverse; removed after)
| Regression | Revert | Reverted | Restored |
|---|---|---|---|
| `pipeline::crash_between_materialize_and_confirmation_leaves_no_endpoint_file_or_key` | early intent off + recovery arms → `mark_uncertain`/`Stop` | 101 (no intent before the crash) | 0 |
| same | recovery arms only | 101 (`OutcomeUnknown` ≠ `Failed`) | 0 |
| `pipeline::driver_cleanup_failure_is_retried_until_clean` | early intent off + driver failure → `fail_running` | 101 (intent `[]`, files left) | 0 |
| `pipeline::reissue_restores_binding_endpoint_files_and_slot_so_ssh_signs_with_the_new_key` | `restore_consumers` not called | 101 (no binding endpoint after re-issue) | 0 |
| `pipeline::coalesced_follower_gets_its_own_materialized_binding_and_both_sign` | follower not materialized | 101 (follower has no endpoint) | 0 |
| `pipeline::decision_joined_follower_gets_its_own_materialized_binding_and_both_sign` | follower not materialized | 101 | 0 |
