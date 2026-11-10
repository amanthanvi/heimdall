# M03 wave 0: questions and escalations from the verifier (agent V)

Base `410ec237`. Evidence is `file:line` at that commit; the full reading is in
`docs/architecture/m03-wave0-verify.md` §5 (same numbering). Nothing here is decided. "Reading used"
is the fail-closed choice wave 0 can build against.

## E1. `domain::verification::check` has no owner for its body
* Plan U0 (`m03-plan.md:344`) freezes `verification::check` as "signature only". U0b row 4 (phase 1, `:494`)
  calls it and tests "one refusal per predicate". ADR-0008 D5 §6.5 item 2 and D3 (`:701`) define the predicates.
  No other plan line mentions the function.
* Options: (a) U0b phase 1 writes the body (pure, like `issuance::check`); (b) row 4 moves to phase 2;
  (c) U0 ships a refuse-everything body and row 4's per-predicate tests wait.
* Reading used: (a). Owner: integrator.

## E2. `enrollment_recovery_paths_each_tested` needs tests and a case index that do not exist in wave 0
* Plan `:424`, `:433`; ADR-0008 `:1147`, `:3250`. Targets are U5/U10 tests; the case index
  (`tests/native/m03/case-index.json`) is U13's; `tests/native/m03` does not exist.
* Options: (a) structural half now (stable path IDs in `domain::enrollment`, each naming a planned test;
  the existence check `blocked` until U5/U10/U13); (b) `ignored` with the missing input recorded; (c) move to U13.
* Reading used: (a), existence half reported `blocked`. Owner: integrator.

## E3. Row 16: "check.sh's release-gate step" does not exist; the release refusal is narrower than described
* `tools/validation/check.sh:91`–`:145` builds nothing in release mode. The refusal exists only in
  `service run` (`heimdall/src/service_cmd.rs:113`–`:118`, over `ALL_ENV` = `[&str; 7]`, `testcfg.rs:203`) and in
  `launch_hooks` (`testcfg.rs:150`–`:157`). `main.rs:15`–`:30` has no early check. `release_build_ignores_m03_test_gates`
  never existed.
* Options: (a) add the variables to `ALL_ENV`, an early check in `main`, and a `check.sh` step building
  `-p heimdall --release` once and running it with each variable; (b) restrict the claim to `service run`;
  (c) unit-test `testcfg::refusal(false, true)` and record the release build as `blocked`.
* Reading used: (c) now, (a) proposed. Owner: integrator (T owns `check.sh`).

## E4. "M01's 'not available in this build' envelope" is retired and guarded against
* `heimdall/src/cli.rs:12`–`:14` (retired, ADR-0007 §12.30 item 4); `cli.rs:1808` fails if any M02 source line
  contains the phrase; `tests/e2e/cli_m01.rs:1884`–`:1976` fails if any M02 command prints it.
* Options: (a) M03 commands answer `CAPABILITY_UNAVAILABLE`/`driver_unavailable`, exit 4, wording without the phrase;
  (b) reuse the phrase and amend both tests; (c) `USAGE_ERROR`, exit 2.
* Reading used: (a). Owner: integrator (U0, U12).

## E5. Row 1: `SigningSession.peer: PeerInfo` is the wrong type for the signing endpoint
* `PeerInfo` is the control hello's software name/version (`contract/src/ipc.rs:63`). The signing accept loop has
  `PeerIdentity` (`ipc/src/endpoint.rs:104`, used `runtime/src/service.rs:767`ff). ADR-0008 D2 never names `PeerInfo`.
* Options: (a) `peer: PeerIdentity`; (b) a new ipc struct. Reading used: (a). Owner: integrator.

## E6. Row 20 cannot be built as worded in four respects
* (a) Environment-permission removal has no `operations.rs` path: permissions change only through
  `Txn::upsert_environment` (`store/src/ext.rs:828`; callers `app/src/holders.rs:305`, `heimdall/src/testcfg.rs:401`,
  tests); the withdrawal is found by re-validation (`grant_end` `operations.rs:2013` → `end_in` `:2077`).
  Options: covered by the re-validation path; or a new `Operations::set_environment_permissions` that gates.
  Reading used: covered by re-validation, tested through the store.
* (b) Withdrawal at re-validation commits inside a blocking `write` closure (`end_in`, callers `:5675`, `:8566`,
  `:9568`, `:10233`, `:10388`, `:10536`); an async gate cannot be awaited there. Options: read-only detection, gate,
  then re-run `end_in` under the gates; or `end_in` returns the set and each caller loops. Reading used: the first.
* (c) The grant set of a cutoff narrowing (`Operations::policy`, `:9663`–`:9670`) is unspecified. Reading used:
  active or degraded grants of the policy's profile whose bound the cutoff lowers.
* (d) Ownership of `SigningGates` is unspecified: `Inner` (`:404`, built `:4929`) or `OperationsConfig`
  (`:360`, about 40 literals). Reading used: `Inner` + `Operations::signing_gates()`.
* Owner: integrator.

## E7. `issuer_endpoint_kind_reserved_never_bound` is false as worded
* `ipc::unix::Listener::bind(path, kind)` (`unix.rs:66`) and `windows::Listener::bind(name, kind, sid)`
  (`windows.rs:163`) accept `EndpointKind::Issuer`. The runtime binds Control and Signing only
  (`runtime/src/service.rs:648`–`:650`, `:690`–`:698`).
* Options: (a) refuse `Issuer` in both constructors; (b) a source-scan test that only Control and Signing reach a bind.
* Reading used: (b), (a) proposed. Owner: integrator (ipc).

## E8. Row 17's reason `owner_reconcile` cannot reuse `local_driver_unavailable`
* `app/src/operations.rs:5419`–`:5447` writes `driver_unavailable` (`:5428`). Plan `:2688` also lists
  `driver_unavailable (exists)` as an M03 reason, and the registry location is unstated:
  `contract::envelope::reason::ALL` is compared by equality with a transcribed M02 list
  (`tests/contracts/m02.rs:545`–`:628`), so M03 reasons need a separate list.
* Reading used: a second helper with `owner_reconcile`; a separate M03 reason list. Owner: integrator.

## E9. Row 28's validation changes `process_start_time` for some PIDs
* Linux `process_start_time` (`runtime/src/platform.rs:671`–`:692`) ignores the process group and accepts group 0
  (kernel threads; inference). The shared parser requires token 3 ≥ 1. `ProcStat` must also expose the state letter
  for the `Z`/`X` rule. Test `platform_start_time_uses_shared_parser_semantics_unchanged` and the validation disagree.
* Options: (a) `process_start_time` uses a start-time entry that does not require the group; (b) accept the change
  and rewrite the "unchanged" test. Reading used: (a). Owner: integrator.

## E10. No U0b row covers `Operations::cancel` for the enrollment kinds
* `cancel` (`operations.rs:8793`) special-cases setup and catalog (`:8816`) and settles anything else `cancelled`.
  Plan §5 item 11 and ADR-0008 §6.4 (`:1622`) require `CAPABILITY_UNAVAILABLE`/`remote_step_in_progress` once the E3
  `Attempted` receipt exists.
* Reading used: in phase 1, refuse always (no receipt can exist), write nothing. Owner: integrator (new row).

## E11. "M01 and M02 suites run unchanged" cannot be literal
* About 100 test literals break (StandingPolicy ~21, EnsureRequest 30, AdapterDescriptor 8, GrantOrigin 4,
  RemoteObligation ~7, Tombstone ~6, Enforcement 2, RevokeOutcome 1 …); `tests/integration/store.rs:1324`, `:4197`
  assert `SCHEMA_VERSION == 5`; `tests/contracts/m02.rs` sample list must cover the new `op`s; `ScriptedSigner`
  (`tests/adversarial/agent_frames.rs:58`) implements the old trait.
* Reading used: mechanical edits only (added fields at M01/M02-equivalent values; no assertion or scenario change),
  reviewed as such. Owner: integrator.

## E12. Row 18 needs a store read the plan does not list
* §5 item 18's `Txn` list has no "all non-final enrollments"; `Store::open_read_only` never migrates, so a schema-5
  file has no `enrollments` table (`uninstall_cmd.rs:272`).
* Reading used: `Txn::open_enrollments()` in `ext_m03.rs`; "table absent means none". Owner: integrator.

## E13. Plan statements that do not match the code (corrections)
* Row 19 `holders::holder_pass` is `Supervisor::holder_pass` (`supervisor.rs:440`) → `Operations::release_exited_holders`
  (`app/src/holders.rs:114`). M5's `BindForm::Launch { executable, holder }` is `Launch(LaunchBinding)` (`request.rs:532`).
  M13 is landed. `SETUP_V1`'s doc comment (`contract/src/ipc.rs:56`) is stale. §0.4 and U0b cite `7f6f1c05`/`1f5b8156`.

## E14. Exact-count source scan in `operations.rs`
* `tests/model/operations.rs:12832` pins `.reconcile(` ×4, `.revoke(` ×3, `.prepare_from(` ×1, 8 bound spans and one
  `.read_sources(` in the production part of `crates/app/src/operations.rs`. The plan does not say where the
  `ManagedEffects` calls (row 21) go.
* Reading used: `crates/app/src/managed.rs`. Owner: integrator.
