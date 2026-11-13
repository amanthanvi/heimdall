# M03 wave 4, round 3 — integrator worklog

Base: `e566cc46` (round 2) + uncommitted ADR-0008 §17.22 and the two reviews (orchestrator's; never edited).
Goal: §17.22 items 1–16 (17, 18 accepted as built); revert proofs; check.sh all-zero; xchecks; umask 002;
container; report with the native-run list. Windows-native results at `e566cc46` pending (forward when they come).

## Decisions
- R3-D1. Five parallel workers (A enrollment+evidence, B issuer, C1 managed cleanup, C2 managed pipeline,
  D runtime+setup) per `.m03-wave4-r3-api.md` §0.

## Commands (exit codes)
- Workers A, B, C1, C2, D returned (reports in conversation; worklogs `-A,-B,-C1,-C2,-D`).
- I-R3-1. `descriptor_mismatch` registered (`reason::M03`, `CAPABILITY_UNAVAILABLE`, golden), as §17.22 item 1
  names it (R3A-Q1 closed); `admit::DESCRIPTOR_MISMATCH` switched; the e2e expectation follows. Not in m03-plan §5
  item 14's table (plan text not editable here).
- I-R3-2. `integration_managed_adapter::expired_grant_never_reissued` read K_env after expiry; since item 4
  destroys it, the fixture reads the key before expiry and now also asserts it is gone after (48/48, exit 0).
- check.sh round-3 run 1: exit 1 — clippy-windows 101 (`runtime_m03.rs` top-level `AtomicUsize`/`Ordering` used only in the
  `#[cfg(unix)] issuer_crash` module: moved there; `clippy-windows.sh` → 0) and test 101 (2765 passed / 1 failed:
  testkit's `no_other_test_reads_the_compile_time_root` flagged R3-D's golden test reading `CARGO_MANIFEST_DIR`;
  switched to `heimdall_testkit::repo::repo_root()`; both tests → 0). Every other step 0.
- check.sh round-3 runs 2 and 3: exit 0, every step 0 — 2766 passed, 0 failed, 188 ignored, 84 targets;
  native-harness-selftest 316/0; canary count 0.
- `linux-xcheck.sh --workspace`: 0. `clippy-windows.sh`: 0 (also inside check.sh).
- umask 002 (host): e2e_consumer 7, e2e_enroll 66, e2e_managed 16, runtime lib 46, issuer_m03 19, runtime_m03 51,
  operations_m03 37, managed_adapter 48, app lib 50 — exit 0.
- Container (ubuntu:24.04 amd64 under Rosetta, OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, hmtest, --network none,
  umask 002): all of the above pass except `integration_runtime_m03` 49/2 — the two `wave4::` connection-close
  tests, the known `/proc/<pid>/exe` = `/run/rosetta/rosetta` artefact (both passed natively on the devbox at
  `e566cc46`). Image removed by name; cross dirs pruned.
- Scan: no canary value, no added private-key line, no home path; the ADR diff is only §17.22's insertion.
- Round 3b (W4-N01, Windows enrollment e2e): one worker R3-W; integrator runs checks after.
