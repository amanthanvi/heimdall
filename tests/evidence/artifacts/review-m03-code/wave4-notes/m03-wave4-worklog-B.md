# M03 wave 4 — U10-B worklog (issuer handling, verification gate, INT-Q13)

## Goal
issuer::handle (status/register/unlock/retire/bundle + RegisterIssuer/RetireIssuer decisions),
IssuerLifecycle for ChildIssuer, INT-Q13 option (a) verification gate + D5 §6.5 admission,
VerificationEndpoints::create(op, plan), m03_cmd scratch store branch, tests.

## Decisions
- B-D1. Gate opened inside `EndpointRegistry::create_verification` (when built
  `with_verification_gates`), held RAII in the `VerificationEndpoint`, closed first on its drop.
  Rationale: closes on every exit path without the driver doing anything.
- B-D2. Admission predicate = published positive entry for exactly this K_verify/pair/CA within
  validity + `verification_check_read_only` re-run (reuses the reserve/publish predicate, so the
  two cannot disagree; authorization semantics stay in `verification_m03`).

## Progress
- [x] Port signature + registry + table scope (cargo check app, credential: 0).
- [x] SigningGates verification gate + SignPermit variant + authorize.rs predicate.
- [x] issuer.rs (pure: lifecycle, bundle moved from heimdall-issuer, helpers), issuer_m03.rs
      (request handling, decisions, supervision pass, after-decision), IssuerLifecycle for
      ChildIssuer, m03_cmd scratch branch. Type-check of my files clean; crate build blocked by
      U10-A `enrollment_m03.rs` (missing submodules) and `operations.rs:4272` (U10-C WIP).
- B-D3. Registration public key held in-process (U10B-Q1). B-D4. Retirement stalls at `unloaded`
  (no recorded store locator, U10B-Q2). B-D5. bundle_stale = any enrollment (U10B-Q3).
- Tests written: tests/integration/issuer_m03.rs (12), tests/model/signing_gates.rs (+4),
  tests/integration/managed_signer.rs (+2, 4 updated).
- `issuer_crash_blocks_reissue_not_signing`: left to U10-D/U10-C (re-issue pass + runtime wiring,
  not in my files).

## Commands (exit codes)
- `cargo check -p heimdall-app` (after INT-Q13 edits): 0. `cargo check -p heimdall-credential`: 0.
- `cargo test -p heimdall-app --test model_signing_gates verification`: 0 (4 passed).
- `cargo test -p heimdall-credential --test integration_managed_signer verification`: 0 (4 passed).
- `cargo check -p heimdall-issuer` (IssuerLifecycle impl + bundle re-export): 0.
- `cargo test -p heimdall-runtime --test integration_issuer_m03`: 0 (13 passed) after fixing a test
  ordering (read-only time is Uncertain until a write-side gate check anchors the boot: fail closed).
- `cargo test -p heimdall-app --test model_signing_gates`: 0 (29). `cargo test -p heimdall-credential
  --test integration_managed_signer`: 0 (39 passed, 1 ignored pre-existing).
- `cargo test -p heimdall-issuer`: unit 12/12, `integration_issuer_store` 29/29;
  `integration_issuer_child` + `model_issuer_linearization` FAIL at fixture `ensure`
  (UNSUPPORTED_CLIENT: managed_certificate fake adapter meets the new unwired ensure hook) — not my
  change; filed under Requests.
- `cargo test -p heimdall-app --lib`: blocked (another worker's `RoundAnswers` field).
- clippy `-p heimdall-app -p heimdall-credential -p heimdall-issuer -p heimdall --all-targets -D warnings`:
  101, blocked by U10-A lints (`enrollment_m03*`) and U10-A `e2e_enroll_m03` compile errors. Same
  run without `-D warnings` + `--keep-going`: no warning in any U10-B file (remaining: U10-C
  `e2e/managed_m03.rs:940`, U10-D `service.rs:1929`). `cargo clippy -p heimdall-runtime --test
  integration_issuer_m03`: 0, no warning.
- `bash tools/validation/linux-xcheck.sh -p heimdall-issuer`: 101, blocked by the same 7 U10-A lints
  in heimdall-app. Same command (same zig shim, target, `--all-targets --locked`) without
  `-D warnings`: 0; only warning U10-C `managed_driver_m03.rs:297`.
- Windows clippy: not run (whole workspace; blocked by the same lints).

## Revert runs (fix reverted → exit; restored → exit), each one test, named
| # | Reverted | Test | Reverted | Restored |
|---|---|---|---|---|
| R1 | install CA + positive-pair checks (`table.rs`) | managed_signer `verification_install_refuses_another_ca_or_another_pair` | FAILED | ok |
| R2 | gate opened at `create_verification` | managed_signer `verification_session_opens_and_closes_its_operation_gate` | 101 | 0 |
| R3 | release refused once gate closed | signing_gates `verification_permit_release_refused_after_gate_closed` | 101 | 0 |
| R4 | drop closes the gate (`close_verification` no-op) | signing_gates `verification_gate_admits_only_while_open` | 101 | 0 |
| R5 | verification admission → old `Unavailable` | issuer_m03 `verification_signature_admitted_only_through_its_operation_gate` | 101 | 0 |
| R6 | D5 §6.5 re-check skipped | issuer_m03 `verification_signature_refused_unless_operation_is_verifying` | 101 | 0 |
| R7 | register admissibility (already registered) | issuer_m03 `issuer_register_refused_not_consumed_when_precheck_fails` | 101 | 0 |
| R8 | retirement enrollment refusal | issuer_m03 `ca_retirement_refused_until_every_enrollment_final_or_abandoned` | 101 | 0 |
| R9 | bundle hostname redaction | issuer_m03 `issuer_bundle_redacts_hostnames` | 101 | 0 |
| R10 | status CA records from store | issuer_m03 `issuer_status_fills_ca_records_from_store` | 101 | 0 |
| R11 | registration sets env permissions | issuer_m03 `issuer_register_through_decision_approved` | 101 | 0 |
| R12 | retire approval → `retiring` | issuer_m03 `issuer_retire_through_decision_approve_and_deny` | 101 | 0 |
| R13 | unlock locked-store guidance | issuer_m03 `issuer_unlock_reports_locked_store_never_prompts` | 101 | 0 |
| R14 | supervision starts only `not_initialized` | issuer_m03 `issuer_supervision_starts_unstarted_child_never_a_stopped_one` | 101 | 0 |
| R15 | fail closed without wiring | issuer_m03 `issuer_requests_fail_closed_without_wiring` | 101 | 0 |
| R16 | retire precheck | issuer_m03 `issuer_retire_refused_not_consumed_when_precheck_fails` | 101 | 0 |
(R1's exit code was not captured (pipe); the FAILED/ok result lines were. R4's first attempt, removing
only the admission filter, still passed: the closed entry is also removed, a second layer.)
