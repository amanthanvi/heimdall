# M03 wave 4 worklog (integrator; untracked until archived)

Base: `main` at `d6593a7c` (wave 3 merged in `336c9a2f`). Worktree clean at start.

## Goal
U10 (application drivers + runtime wiring) and U0b phase 2 (activation), one integrated,
uncommitted change set, with a report (brief §7).

## Decisions
- D1. Store-touching driver code lives in **child modules of `operations`**
  (`operations/{enrollment_m03,issuer_m03,managed_driver_m03,decisions_m03}.rs`), because the journal
  helpers (`Emit`, `put_grant`, `settle_failed`, `op_to`, `inner`) are private to `operations`. The plan's
  owner paths `crates/app/src/{enrollment,issuer,managed}.rs` hold the public/pure parts; `managed.rs`
  gains the submodule `managed/driver.rs` for `drive_preparation`'s body. Recorded as a placement
  reading, not an ownership change.
- D2. M03 ports reach `Operations` through one setter, `Operations::set_managed_wiring(ManagedWiring)`
  (like `set_session_lock_source`), not through `OperationsConfig` (19 literal construction sites,
  M01/M02 suites unchanged). Every field optional; absent ⇒ fail closed.
- D3. Decision completion for the M03 kinds: precheck (nothing written on refusal) → store completion
  → apply in the same transaction (a refusal rolls back: nothing consumed) → after-commit work.
- D4. Ensure hook: the effect driver runs after `read_sources`, before the bounded `prepare_from`, only
  for `managed_certificate`; its error takes the existing error arms.
- D5. Four parallel workers (Opus), disjoint files (`.m03-wave4-api.md` §0/R2):
  A enrollment; B issuer + verification + INT-Q13; C managed preparation / re-issue / slots /
  instances / revocation data; D runtime order + supervisor + dispatch + capabilities + classification.

## Progress
- [x] Seams landed: `cargo check -p heimdall-app` 0, `-p heimdall-runtime` 0, `-p heimdall --tests` 0;
      `Cargo.lock` unchanged.
- [x] Workers A–D returned (reports in conversation; worklogs `-A/-B/-C/-D`).
- [x] Integration, phase-1 test flips, `check.sh`, Linux xcheck, Windows clippy, container pre-check.
- [x] Archive notes (`tests/evidence/artifacts/review-m03-code/wave4-notes/`).

## Commands (exit codes)
- `cargo test --workspace --locked --no-run` (baseline warm, before any edit): 0.
- `cargo check -p heimdall-app`: 0 (after seams). `cargo check -p heimdall-runtime`: 0.
  `cargo check -p heimdall --tests`: 0.

## Blockers
(none yet)
- Seams batch 2: runtime `managed_store.rs` stub (`StoreSources`), `[[test]] integration_issuer_m03`,
  e2e targets `e2e_managed_m03`/`e2e_enroll_m03`, testkit `managed` feature on heimdall prod (U3-Q4) and
  dev deps. `cargo check -p heimdall-runtime --tests -p heimdall`: 0. `Cargo.lock` unchanged.
- Common worker brief: `.m03-wave4-brief.md`. Workers A–D launched in parallel (Opus, general-purpose).

## Integration (after the workers)
- I1. A-Q2 applied in `verification_m03.rs` (U0b's reserved file): the authorization also comes from
  the enrollment driver's journal (`enrollment_m03::verification_authority`: an apply with its
  approval, a target-change verify with its approval), beside wave 0's stored-request rule for
  presence/absence verifies (kept, so the row-4 suites keep their meaning); the verification stage
  also accepts `outcome_unknown` operations and `removal_verifying` records;
  `verification_check_read_only` finds the enrollment the same way.
- I2. `operations.rs` `cancel`: enrollment operations go through `enrollment_cancel_m03::cancel_in`
  (phase-1 `refusal` removed). `tests/model/operations_m03.rs`: `enrollment_cancel_refused_writes_nothing`
  keeps the `remote_step_in_progress` half; new `enrollment_cancel_before_attempt_cancels`.
- I3. `operations.rs` `inspect`: `enrollments` → `enrollment_m03::enrollments_view_in` (owner only;
  non-owner gets an empty list), `issuer` → `issuer_request(Status)`; `connections` stays
  `driver_unavailable` (no store index of all owned connections, U7-Q4).
- I4. Process-global statics removed: A's `hosts()`/`previews()` and B's `pending_registrations()`
  became per-`Operations` state (`ManagedOpsState.{enrollment, issuer}`), so an in-process restart
  forgets them as a real one does; `decisions_m03::{precheck, apply}` take a `DecideCtx`.
- I5. U10C-Q3: `ManagedEffects::destroy` now runs **under the gates** (`narrowing.rs` step (7), both the
  gated and the fast path; `managed_destroy_under_gates`), and again (idempotent) after release.
- I6. U10C-Q4: `NarrowingKind::Enrollment` added and used by `degrade_grants_under_ca`.
- I7. `existing_access_prepare_contract_unchanged` scans `operations.rs` for `.managed`: the hook's
  snapshot write moved into `managed_driver_m03::run_effect_driver`; `managed_after_release` renamed
  `after_release_m03`. `operations.rs` names no `.managed` again.
- I8. `tests/model/narrowing_m03.rs` `authorize_refuses_each_predicate`: a verification subject with
  no open gate is `KeyNotServed` (INT-Q13), on a grant endpoint and on its own endpoint.
- I9. New regression `e2e_managed_m03::revoke_destroys_k_env_under_the_gates` (I5): with
  `managed_destroy_under_gates` removed from `narrowing.rs` → exit 101 (managed_m03.rs:1268, K_env still
  live at `UnderGates`); restored → exit 0.
- Full run 1 (`cargo test --workspace --locked --no-fail-fast`, before I7/I8, the stored-verify fallback and
  the test updates): exit 101, 2666 passed / 14 failed / 188 ignored. The 14: `model_operations_m03` row-4
  verification reserve tests (no journal in seeded ops → fixed by keeping wave 0's stored-request rule),
  `enrollment_cancel_refused_writes_nothing` (split), `model_narrowing_m03::authorize_refuses_each_predicate`
  (updated), `integration_issuer_m03` 2 verification-signature tests (same reserve cause). `e2e_enroll_m03`:
  42 passed, 0 failed (A-Q2 + cancel switch closed its 6 failures).
- After fixes: `cargo test -p heimdall-runtime --test integration_issuer_m03 --test model_narrowing_m03
  --test model_operations_m03`: 0 (13 / 57 / 37 passed). `cargo test -p heimdall --test e2e_managed_m03`: 0 (11).

## Final checks (macOS arm64, OpenSSH_10.5p1)
- `bash tools/validation/check.sh` run 1: exit 1 — fmt 1 (rustfmt drift in worker/integrator files),
  clippy 101 and clippy-windows 101 (one `collapsible_if` in `managed_destroy_under_gates`); every other step 0;
  test step 0 (2682 passed, 0 failed, 188 ignored). Fixed: `cargo fmt --all`, the lint.
- `check.sh` run 2: **exit 0**, every step 0 (fmt, clippy, clippy-windows, crate-graph, claims-table, test,
  test-discovery, schema, release-gate, native-harness-selftest 316/0, evidence-selftest, evidence-records);
  2682 passed, 0 failed, 188 ignored, 84 targets; `HEIMDALL_CANARY_` count in the log 0.
- `check.sh` run 3: **exit 0**, every step 0; 2682 passed, 0 failed, 188 ignored.
- `bash tools/validation/linux-xcheck.sh --workspace`: 0.
- Host under `umask 002`: `e2e_enroll_m03` 42, `e2e_managed_m03` 11, `integration_issuer_m03` 13,
  `integration_runtime_m03` 32, `model_operations_m03` 37 — exit 0.
- Container pre-check (validation, not evidence): `ubuntu:24.04` amd64 (Docker Desktop, Rosetta emulation),
  `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`, user `hmtest`, `--network none`, `umask 002`, Linux test binaries
  cross-built with the `linux-xcheck.sh` zig shim: `e2e_enroll_m03` 42/0, `e2e_managed_m03` 11/0,
  `integration_issuer_m03` 13/0, `model_operations_m03` 37/0; `integration_runtime_m03` 30/2 and wave 3's
  unchanged `integration_connections` 32/11 fail on exact-image verification: under the emulation
  `/proc/<pid>/exe` reads `/run/rosetta/rosetta` (probed), so `ProcessPin::verify` refuses (fail closed) —
  these need the devbox natively. Image `heimdall-w4-u2404:local` removed by name.
- Pruned `target/x86_64-unknown-linux-gnu` and `target/x86_64-pc-windows-gnu` (no cargo running); scratch
  `/tmp/hm-w4-*` removed.
- Scan of every changed/new file: no `HEIMDALL_CANARY_*=` value, no private key; only fixture paths.
