# M03 wave 4 — worker U10-A (enrollment) worklog

## Goal
ADR-0008 D5 §6.4 enrollment stage driver over the store (m03-plan U10), its reconcile, system form,
foreign removal, target change, re-verification, step-timeout pass; §17.17 item 14 (domain classify).

## Decisions
- A-D1. Domain `verification::classify` gets the U5 body (`classify_evidence`), with a
  `ClassifyContext { unrecorded, offset, skew }`; `TraceEvents.host_key_failure`;
  `VerificationOutcome.unrecorded` (authorized ports field). The Verifier fills both.
- A-D2. The destination clock measurement is computed in app from the positive attempt's
  `remote_now` with t1 = before `run`, t2 = after `run` (both later/earlier than the Verifier's own
  reading: `behind_upper` and `rtt` are upper bounds, conservative). No port change.
- A-D3. Facts the M03 ports do not carry (runtime dir trust files, the client path, the Q24
  `IdentityAgent` reading, the endpoint re-validation, Heimdall's endpoints, `ssh -G`) come through a
  new port `app::enrollment::EnrollmentHost` (my file), set with `Operations::set_enrollment_host`.
  Request to the integrator: a `ManagedWiring.enrollment_host` field; to U10-D: the runtime impl.
- A-D4. The per-operation journal (approval basis, outstanding step, latest inspection, attempts)
  is persisted as stage receipts (`enroll.*` stage names); payload JSON in the receipt's
  `Confirmed.credential_ref` (fact receipts, adapter `{mechanism: "enrollment", instance: "journal"}`).
  The remote-mutation receipts are `Attempted` with effect token = marker (+`:dir`, `:rm`) per §6.4.
  Escalated as A-Q1 (no typed payload slot in the frozen `StageReceipt`).

- A-D5. Admission (apply, verify, remove) is one transaction: idempotency classify, every
  refusal, then the operation + record + decision + journal; a refusal writes nothing.
- A-D6. A removal's grant degradation runs after the decide commit (`enrollment_after_decision` →
  U10-C's `degrade_grants_under_ca`, narrowing protocol). `pair_unenrolled` still signs (D2 item 3),
  so the window between the record moving to `removing` and the degradation changes no signing.
- A-D7. An uncertain mutation moves the op `running → outcome_unknown` (M01 edge); the reconcile and a
  later verification run while the op stays `outcome_unknown` (no M01 edge back to `running`); it
  settles `succeeded`/`failed` through `ReconciledApplied`/`ReconciledNotApplied`.
- A-D8. Cancel: `enrollment_cancel_m03::cancel_in` (planned → withdrawn, applying before E3 →
  failed_unwritten, the decision withdrawn); `removing` is not cancelled. Call-site switch requested.

## Progress
- [x] Domain classify (§17.17 item 14) + `TraceEvents.host_key_failure` + `VerificationOutcome.unrecorded`;
  Verifier fills both; enroll `classify_evidence` delegates. Tests: domain `classify_follows_the_d5_table`,
  `known_offset_beyond_the_allowance`; enroll lib 13 pass.
- [x] `app::enrollment` (host port, answers, journal, pure helpers + 3 unit tests).
- [x] Driver: preview, apply (+ decisions), steps, step results, verification + E5, reconcile, abandon,
  verify modes, own removal (account via decision, system via typed confirmation), step-timeout pass,
  reverify pass, cancel_in. Foreign removal: still `driver_unavailable`.
- [x] e2e harness (`tests/e2e/enroll_m03.rs`): LoopbackSshd + FakeAgent + real SshStepRunner + real
  Verifier; fakes for issuer, verification session, target, host.
- [x] Foreign removal (account + system form), manual-removal cancel (`cancel_in`), foreign
  abandon/absence by marker, held foreign recovery.
- [ ] Blocked on the integrator (`verification_m03.rs` request, A-Q2): the initial verification of an
  `enrollment.apply`, a target change, and the absence check (record `removal_verifying`) reserve
  nothing → inconclusive (fail closed). Blocked on the `cancel` call-site switch: manual-removal cancel.

## Commands (exit codes)
- `cargo test -p heimdall-domain --lib verification`: 0 (3 passed).
- `cargo test -p heimdall-enroll --lib`: 0 (13 passed).
- `cargo test -p heimdall --test e2e_enroll_m03` (run 2): 1 — 11 passed, 3 failed
  (`enroll_preview_apply_verify_setup_apply_ensure_ssh`, `enroll_restart_leaves_operation_unresolved_and_reported`:
  the apply's verification refused `operation_not_verifying`; `enroll_system_form_…_absence_check`: the
  absence check refused at `removal_verifying`). The system form's presence verification PASSED
  end to end (verified), so the verification path itself works.
- R4 finding from U10-D (Abandon wrote time anchors on an unwired runtime): fixed (ports first in
  Abandon, Step, StepResult).
- `cargo test -p heimdall --test e2e_enroll_m03` (final): exit 101 — 36 passed, 6 failed. The 6:
  `enroll_preview_apply_verify_setup_apply_ensure_ssh`, `enroll_restart_leaves_operation_unresolved_and_reported`,
  `enroll_system_form_manual_apply_verify_and_manual_removal_with_absence_check`,
  `system_form_cancel_from_manual_pending_keeps_entry_until_absence_verified`,
  `target_change_pins_come_from_proposed_target` (A-Q2: `operation_not_verifying`), and
  `manual_removal_cancel_returns_to_origin_state_and_evidence` (the `cancel` call site still uses
  `refusal`). Each fails on exactly that refusal.
- `cargo test -p heimdall-enroll --test integration_enroll_verify`: 0 (51 passed, 1 ignored docker).
- `cargo test -p heimdall-app --lib enrollment`: 0 (4 passed).
- Revert runs (fix reverted → test → restored → test), via `/tmp` copies, `cmp` confirmed restore:
  - step-token check → `step_result_with_wrong_token_refused_nothing_recorded`: 101 → restored 0;
  - route re-evaluation → `step_refused_when_route_changed_after_approval`: 101 → restored 0;
  - one-outstanding rule → `second_step_refused_while_one_outstanding`: 101 → restored 0;
  - domain classify body → wave-0 stub → `classify_follows_the_d5_table`: 101 → restored 0;
  - outcome_unknown op lookup (late_write) → `abandon_from_outcome_unknown_remove_unknown_and_rollback_pending`:
    101 → restored 0.
- `cargo clippy -p heimdall-app -p heimdall-domain -p heimdall-registry -p heimdall-enroll --all-targets -- -D warnings`: 0.
- `cargo clippy -p heimdall --test e2e_enroll_m03 -- -D warnings`: 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall-app`: 0.
- Not run: `tools/validation/clippy-windows.sh` (whole workspace; the integrator's end-of-wave run).
- `model_operations_m03` (runtime host): 35 passed, 1 failed `existing_access_prepare_contract_unchanged`
  (`operations.rs:7084 reads .managed`: the integrator's ensure hook, not U10-A's).
