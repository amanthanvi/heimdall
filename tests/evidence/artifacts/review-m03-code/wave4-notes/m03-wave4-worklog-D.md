# M03 wave 4 worklog, U10-D (runtime order, supervisor, dispatch, capabilities, classification, preference)

## Goal
Prompt items 1–6: Service start/stop order + M03 object construction and wiring; supervisor M03 passes;
dispatch `Connections::{Close, Register}` + `Connection` events; U0b phase-2 capabilities; D10 item 6
classification; U8-Q6 `preference` on `inspect destinations`.

## Decisions
- D-1. M03 wiring is opt-in through `ServiceOptions.managed: Option<ManagedOptions>`: production
  (`ServiceOptions::production`) sets it, `ServiceOptions::with_clock` leaves it `None`, so every M01/M02
  runtime suite runs unchanged (no session-lock thread, no environment signer change).
- D-2. Environment-endpoint collision (M01 `signing` listener vs `EndpointRegistry::start_environment`
  at the same path): with managed wiring, M01's `signing` listener is **not** bound; the registry's
  environment endpoint (a `ManagedSigner` for `SignerEndpoint::Environment`) serves that path and
  `instance.json`'s `signing_endpoint` names it. Without managed wiring M01's listener and
  `options.signer` are unchanged (M01 signing suites unchanged). Windows: the managed layout's token is
  this start's instance token with the prefix's `-` dropped (`EndpointLayout::windows` takes
  alphanumerics), so both names agree (question U10-D-Q1: the token is per start, not per installation).
- D-3. Late-bound **binding endpoints** (not authority): the managed adapter (needed by
  `Operations::start`) needs the effects, which need the binding endpoints, while the registry needs
  the `Operations` (authority + `signing_gates()` for B's `with_verification_gates`). So the effects
  and the connection supervisor get `LateRegistry` (a `RwLock<Option<EndpointRegistry>>`, knows no
  endpoint until set, cleared at stop), and the registry is built right after `Operations::start` with
  the real authority. Clearing it and `set_managed_wiring(default)` at stop break the reference cycles.
- D-4. Connection events (U7-Q3 option (a)): `supervisor::ManagedConnections` wraps U7's
  `ConnectionSupervisor` and implements `ConnectionControl`; every close through it emits one
  `Connection` event per row actually closed, with the reason (owner request, each pass's reason, and
  U10-C's revoke/release calls through `wiring.connections`). Passes emit from `PassReport.closed`, so
  a row closed once is never reported again. Runtime stop's masters: `closed` with no reason (the
  contract has no `runtime_stop` reason).
- D-5. "The grants each tick ended": `Operations::tick` returns `()` (operations.rs not mine), so
  `Supervisor::connection_end_sweep` derives them from durable state after every tick and every M03
  pass: grants with open owned connections whose state is ended → `deadline` / `revocation` /
  `release` pass by `close_reason_for(state)`. That sweep is also the retry of a `DiscoveryFailed` or
  pending/failed close (D7 item 2: the durable rows are the cleanup intent); a grant whose pass finished
  is not passed again.
- D-6. M03 supervisor passes (issuer supervision, re-verify, step timeout, reap, sweep, owed
  time-uncertain close) run every `SupervisorConfig::managed_interval` (new field, default 5 s,
  jittered), only on a supervisor `with_connections`; `managed_reissue_pass` keeps running beside the
  scheduler pass (now `ops.managed_reissue_pass()`); `run_lock_passes` runs beside the loops
  (`with_session_lock`); `time_uncertain_close` when the gate leaves `Safe` (kept owed and retried).
- D-7. U8-Q1: the runtime builds every writer through the new `wire_runtime_projection`
  (`LocalProjection::writing`); `Service` fills a missing `state_dir` with its own `paths.state_dir`
  (explicit test configs had none). `wire_projection` (pub, called directly by `tests/model/setup.rs`)
  keeps `LocalProjection::new` so the M02 suites run unchanged.
- D-8. Unwired-runtime phase-2 assertions (`runtime_m03.rs`): `assert_fail_closed` (an error envelope,
  no operation, effect none) + the store snapshot unchanged; the driver picks the refusal (U10-A/B
  answer `NOT_FOUND`, owner-role, `DECISION_STALE` before needing a port). Connections unwired stay
  exactly `driver_unavailable`. A `RegisterIssuer` deny on an unwired runtime completes `denied` (B's
  semantics): the decision test accepts refused-and-pending or denied-once with nothing else written.

## Shared/reserved edits
- `crates/app/src/operations.rs`: `destination_view` (+ `preference` param) **and its one call site**
  in the `InspectSubject::Destinations` arm (reads `tx.pair_preference` in the same transaction);
  the `InspectSubject::Capabilities` list (+4 M03 names).
- `crates/adapters/src/managed/report.rs`: `MANAGED_SELECTION_CLASSIFIED = true` + doc.
- `tests/integration/managed_adapter.rs` (U6's test): the `const { assert!(!MANAGED_SELECTION_CLASSIFIED) }`
  line flipped (a compile-time assertion of the old value; forced by the flip).
- `crates/heimdall/src/testcfg.rs` `prepare`: M03 gates wired (`service_cmd.rs` unchanged: it already
  calls `prepare` on the production options, which now carry `managed`).

## Progress
- [x] capabilities (session.rs, inspect) — [x] preference — [x] classification (relevant.rs,
  observe.rs) + constant — [x] dispatch Connections + events — [x] supervisor passes — [x] Service
  start/stop + testcfg — [x] tests + revert probes — [x] clippy -D warnings / linux-xcheck —
  [x] EnrollmentHost (U10-A request; `RuntimeEnrollmentHost`, `ops.set_enrollment_host`) —
  [x] U10-C's StoreSources/OpsInstallView/StoreCleanup wired (late-bound) — [x] U10-B's
  `ChildIssuer: IssuerLifecycle` used (runtime newtype removed)
- D-9. `LateInstallView` / `LateCleanup` (service.rs `mod sources`): the same construction cycle as D-3;
  `LateCleanup::after_end` closes rows through `ManagedConnections::close_ended` (events) before
  U10-C's `StoreCleanup`. The managed adapter is registered after the M02 adapters (order unchanged).
- Not done: `issuer_crash_blocks_reissue_not_signing` (U10-B left it; a meaningful run needs an
  installed managed credential end to end, U10-C's e2e fixture). The expiry slot cleanup needs a
  U10-C hook (Requests).

## Commands (exit codes)
- `cargo check -p heimdall-app -p heimdall-ipc` 0; `cargo check -p heimdall-localenv -p heimdall-sshconf` 0.
- `cargo test -p heimdall-localenv --test integration_projection_managed inherited_identityfile` 0;
  revert (observe.rs `None => None`) 101 (panic projection_managed.rs:1195 "classified"); restored 0.
- `... managed_selection_follows` 0; revert (relevant.rs `adopted_flags.push(own && false)`) 101
  (d10_as_written NotExclusive); restored, whole target 15/15: 0.
- `cargo test -p heimdall-runtime --test integration_runtime_m03`: 30/32 pass; failing:
  `w0_m03_requests_fail_closed_before_any_record`, `capabilities_offered_after_activation` — both on
  U10-A's `Enrollment::Abandon` writing the time-gate meta before `NOT_FOUND` (Requests).
- Revert probes (`/tmp/w4d-probe/probe2.py`, each: revert → run → restore → run):
  - zeroize removed from stop + Drop → `shutdown_zeroizes_vault_and_stops_issuer` 101; restored 0.
  - issuer `stop()` removed → same test 101 ("issuer stopped"); restored 0.
  - zeroize removed → `service_stop_via_signal_fallback_still_zeroizes` 101; restored 0.
  - issuer start moved after the environment endpoint → `runtime_start_order_issuer_before_listen` 101; restored 0.
  - dispatch Connections → driver_unavailable → `connections_close_routed_for_owner_only_with_event` 101; restored 0.
  - close event emission removed → same 101; restored 0.
  - sweep filter `close_reason_for(..).filter(|_| false)` → `sweep_closes_ended_grants_connections_with_reason_once` 101; restored 0.
  - sweep revocation events removed → same 101; restored 0.
  - `.chain(M03_DECLARED)` removed → `capabilities_offered_after_activation` 101 at the offer assert
    (line 817); restored 101 at "nothing was written" (U10-A's abandon write, see above).
  - preference insert disabled → `inspect_destinations_carries_pair_preference` 101; restored 0.
- `cargo test -p heimdall-runtime --lib --test integration_runtime --test model_setup --test e2e_setup_dispatch
  --test model_timegate --test model_events --test integration_session_lock --test model_operations
  --test integration_connections`: all 0 (after D-7). `model_operations_m03`
  (`existing_access_prepare_contract_unchanged`: operations.rs:7084 `.managed`, integrator's ensure hook)
  and `model_narrowing_m03` (`authorize_refuses_each_predicate`: verification subject, U10-B) fail: not mine.
- `cargo test -p heimdall --test e2e_cli_m01 --test e2e_cli_m02 --test e2e_run_m02 --test e2e_cli_m03
  --test e2e_consumer_m03 --test e2e_deadline_m03 --test e2e_tui_m02` all 0 (production options now
  carry the managed wiring).
- Windows-target clippy (`--target x86_64-pc-windows-gnu -p heimdall-runtime -p heimdall --lib --bins
  --test integration_runtime_m03`, zig shim): 0, no warning outside app.
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 101 — only U10-A's app clippy errors.

- Later: U10-A fixed the abandon write: `integration_runtime_m03` 32/32 (0).
- `cargo test -p heimdall-runtime --lib enrollment_host` 0; revert (owner_dir follows symlinks) 101
  ("write_files(other, ..).is_err()"); restored 0.
- `cargo clippy -p heimdall-runtime -p heimdall-ipc -p heimdall-localenv -p heimdall-sshconf -p heimdall
  --all-targets -- -D warnings`: 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 0. `... -p heimdall-localenv -p
  heimdall-sshconf -p heimdall-ipc -p heimdall`: 0.
- `cargo check --release -p heimdall-runtime -p heimdall`: 0 (one warning: `m03_cmd.rs:104`
  `SCRATCH_STORE_DIR` unused in release, U10-B's).
- `cargo test --no-fail-fast -p heimdall-sshconf -p heimdall-localenv -p heimdall-ipc`: 0 (26 binaries).
- Final runtime run (13 targets): all ok except `model_narrowing_m03::authorize_refuses_each_predicate`
  (KeyNotServed vs Unavailable for a verification subject: U10-B's admission) and
  `model_operations_m03::existing_access_prepare_contract_unchanged` (operations.rs:7084 `.managed`:
  the ensure hook) — neither touches U10-D code.

## Blockers
(none of mine.) `target/x86_64-unknown-linux-gnu` 1.6G, `target/x86_64-pc-windows-gnu` 1.1G,
`target/release` 217M left for the integrator (shared with the other workers' cross runs).
