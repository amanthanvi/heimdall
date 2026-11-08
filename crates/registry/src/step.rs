//! The remote step builder (ADR-0008 D5 §6.3; m03-plan U5 `registry::step`):
//! `remote_step(stage, &EnrollmentPlan, token, hard_deadline, not_after_remote) ->
//! RemoteStep` with the full pin set and the fixed remote command, `trust_pins` and
//! `check_effective` (the `ssh -G` comparison).
//!
//! U5 fills this module. The frozen wire shape is `heimdall_contract::enrollment::
//! {RemoteStep, StepPins}` (m03-plan U0 "Frozen in wave 0").
