# M03 wave 5, round 8 — questions for the orchestrator

## Integrator (I)
## P8
None. Reading taken (not a question): the post-stop refusals carry no reason (`SERVICE_UNAVAILABLE`, exit 5); an additive reason would need the integrator (`crates/contract/**`) if the orchestrator wants one.
## G8
- **Q-G8-1 (blocking three one-line edits in finished workers' files; integrator please apply or authorize G8).**
  L5 and K4 have finished without seeing G8's Requests (`.m03-wave5-r8-api.md`). §17.31 item 2's "every
  application route goes through the same boundary" and the re-check's direct-admission probe need:
  (a) `crates/app/src/operations/enrollment_m03.rs`, first statement of `Operations::enrollment_request`:
  `let _admission = self.enrollment_fence_admission(&req)?;`
  (b) `crates/app/src/operations/issuer_m03.rs`, first statement of `Operations::issuer_request`:
  `let _admission = self.issuer_fence_admission(&req)?;`
  (c) `tests/e2e/enroll_m03.rs`, next to `mod windows;`:
  `#[cfg(any(unix, windows))] #[path = "enroll_m03/fence.rs"] mod fence;` (G8's new test file).
  Without (a)/(b) the dispatcher, both reservations, approvals (`decide`), the passes and the step-result
  follow-through are fenced, but a direct in-process call of `enrollment_request`/`issuer_request` is not
  (the re-check's direct-admission probe then still fails). Options: (1) integrator applies (a)-(c)
  (recommended; they are additive guards, no behaviour change when no fence is held); (2) authorize G8 to
  apply them. G8 waits a short while, then continues with everything else.
- **Q-G8-2 (optional, L5's `verify.rs`):** `verify_operation` maps any non-internal `run_verification`
  error to an inconclusive verification and records it. With G8's boundary every verification caller
  holds the admission, so a fence refusal there should not occur; returning `Err(e)` for reason
  `uninstall_in_progress` would guard a missed route. Recommendation: apply in a later round.
## L5

**Q-L5-13 (item 4; not built, as the ruling's condition is not met): the recovery purpose is not persisted
where the store transaction can read it.**
- The event's `purpose` comes from the operation journal's uncertain step:
  `steps.rs` `reconcile_purpose(u)` over `ctx.journal.uncertain` (`UncertainStep.purpose`,
  `crates/app/src/enrollment.rs:462,471`).
- The `Journal` (`:522`) is app-defined JSON, stored opaquely in the `credential_ref` of an `enroll.journal`
  stage receipt of the *operation* (`enrollment_m03.rs:65`).
- `Txn::transition_enrollment(expected, kind, updated)` (`ext_m03.rs:946`) receives no operation ID. The store
  crate depends only on `contract` and `domain` (`crates/store/Cargo.toml`), so it cannot decode `Journal`.
- The record (`EnrollmentRecord`, `crates/domain/src/enrollment.rs:175`) and the `enrollments` columns have no
  purpose; the hold is `lock_holder_unresolved` for every purpose.
- Partial inference is possible: an account-form record carrying a `removal_origin` (§17.30 item 5) can
  only have been interrupted in a removal, so its purpose must be `removal`.
- Options: **A** keep the round-7 hold checks only (built). **B** add that partial check (refuse
  `ManualRecoveryLine*` with purpose ≠ `removal` when `removal_origin` is set). **C** persist the purpose on the
  record (a domain/store change: `hold` would carry it, an additive serde field, no migration).
- Recommendation: A now; C if the orchestrator wants the purpose checked.
## K4

## Integrator (round-8 records)
- **P8, the unconfirmed-stop refusal reason: ANSWERED (orchestrator, 2026-11-13; to be ADR-0008
  §17.31 item 6):** an additive reason `uninstall_shutdown_unconfirmed` (authorized), code
  `SERVICE_UNAVAILABLE` (exit 5, retryable), next "stop the runtime (`heimdall service stop`) or wait
  for it to stop, then run `heimdall uninstall` again"; ADR-0006 row, reasons golden, asserted in P8's
  failed-shutdown regression. Built by the integrator in round 8.
- **Q-L5-13: ANSWERED (orchestrator, 2026-11-13): accepted as reported**; `purpose` stays unchecked
  (journal-only).
- **Q-I-R8-1 (the lock-held refusal's reason; recommend):** `uninstall_shutdown_unconfirmed` is set
  only on the unconfirmed-stop refusal, as ruled. The other exit-5 purge refusal, a replacement runtime
  (or a lock I/O error) holding `service.lock` after the confirmed stop, still carries no reason.
  Options: (a) reuse `uninstall_shutdown_unconfirmed` (same remedy: stop the runtime, then uninstall
  again); (b) a second additive reason, e.g. `uninstall_runtime_running`; (c) keep it reasonless.
  Recommendation: (a), since the owner's next step is the same.
  **ANSWERED (orchestrator, 2026-11-13; §17.31 item 6): (a) accepted**; the human message names the case
  ("a runtime started again while uninstall was running" vs "the runtime did not confirm its shutdown");
  asserted in the replacement-holder regression. Built.
