# M03 wave 5 round 10 — worker K4 (issuer under the fence) worklog

Base faf10bba. Binding ADR-0008 §17.28 item 1, §17.32. No commits.
Files: crates/app/src/operations/issuer_m03.rs, crates/issuer/src/client.rs,
crates/runtime/src/service.rs (the client's construction only), tests/integration/issuer_m03.rs,
tests/integration/issuer_child.rs. Fence API used read-only (G8 owns uninstall_fence_m03.rs).

## Decisions
- A6: `issuer_supervision_pass` takes `uninstall_fence_admit()` for its whole run; refused → does
  nothing (no child start = no K_ca load, no retirement resumed). The holder's inline retire does
  not need the pass: the RetireIssuer approve resumes the retirement inline in the decide handler
  (holder scope, `issuer_after_decision`), and `unload` with no child running is Ok. So no
  holder-requested-work carve-out was needed.
- L1: `ClientConfig.load_gate: Option<LoadGate>` (default None). `start_once` takes it before the
  spawn and holds it through the load; `load_locked` takes it before sending `load`. Deferred →
  `uninstall_in_progress`, view unchanged. `restart_cycle` waits for the lift (poll 500 ms) without
  spending an attempt. Runtime wires `Operations::issuer_load_gate()` (weak handle, no Arc cycle).
- Liveness: `View.load_in_flight` + drop guard `Unfinished`: a cancelled load leaves `loading`
  without a load in flight → `not_ready` spawns a (gated) reload. Converge: a cancelled start
  (state `starting`) becomes `crashed` → the next demand restarts.

## Commands (exit codes, umask 002)
- New: issuer_supervision_pass_does_nothing_under_a_held_fence 0;
  broken_link_restart_under_a_held_fence_loads_nothing_until_the_lift 0;
  cancelled_load_recovers_without_an_explicit_unlock 0; cancelled_start_is_crashed_and_restarted_on_demand 0.
- Reverts (each restored, sha same, rerun 0): pass admission → 101; start_once gate → 101; not_ready
  Loading branch → 101; Starting guard → 101.
- Full runs (umask 002), all 0: issuer --lib (22), --release --lib (21), integration_issuer_child (36),
  integration_issuer_m03 (22), runtime --lib (61), e2e_cli_m03 issuer:: (19 + 1 ignored pty entry),
  clippy issuer+runtime+app --all-targets, clippy-windows.sh (target/x86_64-pc-windows-gnu kept),
  linux-xcheck -p heimdall-issuer -p heimdall-runtime -p heimdall-app. Owner keychain digests unchanged.
  Scratch /tmp/k4-r10 removed. DONE.
