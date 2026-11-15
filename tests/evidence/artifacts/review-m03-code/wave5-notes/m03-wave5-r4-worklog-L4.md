# M03 wave 5 round 4 — worker L4 (late_write clearing; ADR-0008 §17.28 item 3)

## Goal
Attended `enroll verify <e> --absence` after the residual's not-after that observes the line
absent clears `EnrollmentRecord.late_write` in the same transaction as its result; every other
outcome keeps it.

## Findings (pre-build check)
- `late_write` is set only on account-form records (uncertain Append): `abandon` from
  outcome_unknown (enrollment_m03.rs ~724), reconcile `ApprovalLapsed` -> withdrawn (steps.rs
  ~1929), manual recovery line absent -> withdrawn (steps.rs ~1991). States it can be in:
  `withdrawn`, `abandoned`, and an abandoned record's later states (`removing`,
  `remove_unknown`, `removed`, `held`).
- Before this change `enroll verify --absence` was admitted only for
  `manual_removal_pending` (system form only); every late_write state was refused
  `CONFIG_CONFLICT enrollment_state` before any remote contact. Nothing cleared the residual.
- The existing residual computation: `heimdall_registry::fence::late_write_cleared(inspect,
  residual, marker)`: the HM1 inspect's destination clock reading `remote_now` (epoch s) strictly
  past `not_after_remote` (destination-clock s from `fence::not_after_remote`), registry readable,
  no marker line, no lock with the residual's token (nor an unreadable/foreign lock).
  No local clock, no `RESIDUAL_DRIFT_PPM` (that is the revocation residual's local drift).
- The runtime Verifier's cert-refusal absence check cannot see the lock or marker lines, so it
  cannot establish D5 §6.7 absence (a lock-holding paused writer could still append).

## Decisions
- Mechanism: an `enrollment.verify` (mode absence) op for an account-form record carrying
  `late_write` issues one client-executed `inspect` (non-interactive) through the attended CLI's
  existing access, and evaluates `late_write_cleared`. The record's state never moves.
  Escalated as Q-L4-1 (reading) in the questions file.
- Admission requires an attended caller (INTERACTION_REQUIRED otherwise) and no other open
  operation of the record; an earlier unsettled late-write check is superseded.
- Store: additive `Txn::clear_late_write` (CAS on state + residual token; no migration).

## Progress
- [x] app admission / step / result
- [x] store helper
- [x] e2e regressions + obligation test (tests/e2e/enroll_m03.rs)
- [x] revert proofs, umask 002, clippy host/windows, linux-xcheck, e2e suites

## Commands (exit codes)
- `umask 002; cargo test -p heimdall --test e2e_enroll_m03 late_write` 0 (5 passed, incl. 4 new)
- R1 revert (admit.rs = HEAD, the admission arm gone): 4 new FAILED, exit 101; restored, shasum
  201da6ab42df9054847583151268c6ba43f12fa0 = before
- R2 revert (verify.rs `late_write_cleared(..)` forced `true`): before/line-present/obligation
  FAILED exit 101; forced `false`: clears/obligation FAILED exit 101; restored, shasum
  98c3b2397467cc75508825f25891fdeb8ae2a40e = before
- `umask 002; cargo test -p heimdall --test e2e_enroll_m03` 0 (73 passed)
- CLI pty test `enroll_verify_absence_clears_late_write_only_after_not_after` (cfg unix) 0; with
  admit.rs = HEAD: FAILED exit 101 (CONFIG_CONFLICT); restored shasum 201da6ab.. = before; rerun 0
- `umask 002; cargo test -p heimdall --test e2e_cli_m03` 0 (60 passed, 3 ignored child entries)
- `cargo clippy -p heimdall-app -p heimdall-store --all-targets -- -D warnings` 0
- `cargo clippy -p heimdall --test e2e_enroll_m03 --test e2e_cli_m03 -- -D warnings` 0
- `bash tools/validation/clippy-windows.sh` 101: only error crates/heimdall/src/doctor_cmd.rs:1446
  (unwrap_used; K4's doctor test, not mine); narrowed equivalent (same shim) for
  `-p heimdall-app -p heimdall-store --all-targets` 0 and `-p heimdall --test e2e_enroll_m03
  --test e2e_cli_m03` 0
- `bash tools/validation/linux-xcheck.sh -p heimdall-app -p heimdall-store` 0
- `cargo test -p heimdall-app --lib enrollment` 0 (7); `cargo test -p heimdall-store` 0 (21)
- rustfmt applied to verify.rs and tests/e2e/enroll_m03.rs (my lines only); final reruns 0
- Q-L4-1..3 written in .m03-wave5-r4-questions.md. `.m03-wave5-r4-api.md` does not exist here.
