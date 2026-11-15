//! The client-executed loop (m03-plan U12; ADR-0008 D5 §6.3, §6.10): `Enrollment::Step`,
//! [`SshStepRunner::run`] on a blocking thread, `Enrollment::StepResult`, until the
//! runtime needs no further step (verification runs in the runtime) or the operation
//! reaches a final state.
//!
//! * **Ctrl-C** (R3). An interrupt stream is registered before the first `Step`. An
//!   interrupt while a step runs (or before it starts) aborts it ([`StepAbort`]: the
//!   step's process group is killed), sends **no** result for it, and prints exactly
//!   [`uncertain_message`]; the envelope is `OUTCOME_UNKNOWN` (exit 7) with
//!   `next: reconcile`.
//! * **TTY mode per step**, as the reference loop (`tests/e2e/enroll_m03.rs` `run_step`):
//!   `BatchMode=no` among the narrowing pins is [`TtyMode::Interactive`], anything else
//!   [`TtyMode::Batch`].
//! * **Terminal handoff (U5IO-Q3, Q-I1 option (c)).**
//!   `remote::INTERACTIVE_FOREGROUND_HANDOFF` stays `false`: an interactive step runs
//!   in ssh's own background process group, so a prompt ssh reads from the terminal
//!   would stop it until its bound. Before the first interactive step the CLI prints
//!   [`HANDOFF_NOTICE`]; with [`super::REFUSE_UNHELD_INTERACTIVE_IDENTITY`] an
//!   interactive step whose existing-access pins do not name an agent-held identity
//!   is not run at all (refused up front, nothing sent).
//! * **Manual recovery** (ADR-0008 D5 §6.7). In a `--after-manual-recovery` reconcile
//!   only `inspect` steps are run; any other stage is refused (never a redispatch).
//! * **Windows** (U5IO-Q2 (a)): the runner gets the kill-on-close job containment
//!   ([`JobContainment`]); a runner without one refuses every step.

use std::sync::Arc;

use heimdall_app::enrollment::{StepAnswer, StepRecorded};
use heimdall_contract::Code;
use heimdall_contract::enrollment::{
    EnrollmentForm, EnrollmentRequest, RemoteStage, RemoteStep, SshOption,
};
use heimdall_contract::envelope::{EffectStatus, Envelope, NextAction};
use heimdall_contract::ids::OperationId;
use heimdall_contract::request::Request;
use heimdall_enroll::remote::{SshStepRunner, StepAbort, StepRunError, TtyMode};

use crate::cli::Session;
use crate::output;
use crate::setup_cmd::Outcome;

/// The most steps one invocation drives before it stops and names `reconcile` (an
/// enrollment needs at most a handful: inspect, bootstrap, append, and their retries).
pub(super) const MAX_STEPS: usize = 32;

/// The notice before the first interactive step (Q-I1 option (c)).
pub(super) const HANDOFF_NOTICE: &str = "Remote steps run in their own process group on this \
     terminal's session. A prompt that ssh reads from this terminal (a key passphrase, a \
     password) cannot be answered while a step runs, because this build has no terminal \
     handoff: keep the identity in an agent. Even with an agent-held identity, a server \
     that falls back to password or keyboard-interactive authentication still stalls the \
     step until its time bound. A step that waits on such a prompt ends at that bound and \
     writes nothing.";

/// Exactly what the CLI prints when an interrupt aborts a step (m03-plan U12).
#[must_use]
pub(crate) fn uncertain_message(op: &OperationId) -> String {
    format!("the change may have been applied; run `heimdall enroll reconcile {op}`")
}

/// How the loop runs.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct DriveMode {
    /// A `--after-manual-recovery` reconcile: only `inspect` steps run.
    pub(super) after_manual_recovery: bool,
    /// The enrollment's form, when known (the result's wording).
    pub(super) form: Option<EnrollmentForm>,
    /// `--json`: no progress lines on stderr.
    pub(super) json: bool,
}

/// The value of pin `key`, if present.
fn pin<'a>(pins: &'a [SshOption], key: &str) -> Option<&'a str> {
    pins.iter()
        .find(|o| o.key.eq_ignore_ascii_case(key))
        .map(|o| o.value.as_str())
}

/// The step's terminal mode, as the reference loop reads it.
#[must_use]
pub(super) fn tty_mode(step: &RemoteStep) -> TtyMode {
    if step
        .pins
        .narrowing
        .0
        .iter()
        .any(|o| o.key == "BatchMode" && o.value == "no")
    {
        TtyMode::Interactive
    } else {
        TtyMode::Batch
    }
}

/// Whether an `IdentityAgent` value names a concrete agent endpoint: an absolute path
/// or a named pipe, never `none` and never `SSH_AUTH_SOCK` (ADR-0008 §17.4 item 4).
#[must_use]
pub(super) fn concrete_agent(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower == "none" || lower.contains("ssh_auth_sock") || value.is_empty() {
        return false;
    }
    value.starts_with('/')
        || value.starts_with("//./pipe/")
        || value.starts_with("\\\\.\\pipe\\")
        || (value.len() > 2 && value.as_bytes()[1] == b':')
}

/// Whether existing-access pins use an **agent-held** identity: a concrete
/// `IdentityAgent` and `IdentitiesOnly=yes` (Q-I1 option (c)).
#[must_use]
pub(super) fn agent_held(pins: &[SshOption]) -> bool {
    pin(pins, "IdentityAgent").is_some_and(concrete_agent)
        && pin(pins, "IdentitiesOnly").is_some_and(|v| v.eq_ignore_ascii_case("yes"))
}

/// [`agent_held`] for a plan's rendered invocation (`["-o", "Key=Value", …]`).
#[must_use]
pub(super) fn invocation_agent_held(invocation: &[String]) -> bool {
    let pins: Vec<SshOption> = invocation
        .iter()
        .filter_map(|a| a.split_once('='))
        .map(|(k, v)| SshOption {
            key: k.to_owned(),
            value: v.to_owned(),
        })
        .collect();
    agent_held(&pins)
}

/// The stage's wire name.
#[must_use]
pub(super) fn stage_name(stage: RemoteStage) -> &'static str {
    match stage {
        RemoteStage::Inspect => "inspect",
        RemoteStage::Bootstrap => "bootstrap",
        RemoteStage::Append => "append",
        RemoteStage::Remove => "remove",
        RemoteStage::Fence => "fence",
        _ => "unknown",
    }
}

/// An error envelope for `op` (effect as given).
fn op_error(
    code: Code,
    message: String,
    op: &OperationId,
    effect: EffectStatus,
    reason: Option<&str>,
    next: Option<&str>,
) -> Envelope<serde_json::Value> {
    let mut e = heimdall_app::OpError::new(code, message)
        .with_effect(effect)
        .with_operation(op.clone());
    if let Some(r) = reason {
        e = e.with_reason(r);
    }
    if let Some(n) = next {
        e = e.with_next(NextAction {
            action: n.to_owned(),
            operation_id: Some(op.clone()),
            ..NextAction::default()
        });
    }
    output::error_value(e.into_envelope())
}

/// The OS interrupt (Ctrl-C), registered when created: an interrupt delivered before
/// creation is not seen, one delivered after is kept until read.
pub(super) struct Interrupts {
    #[cfg(unix)]
    inner: tokio::signal::unix::Signal,
    #[cfg(windows)]
    inner: tokio::signal::windows::CtrlC,
}

impl Interrupts {
    /// Register.
    pub(super) fn new() -> std::io::Result<Interrupts> {
        #[cfg(unix)]
        let inner = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        #[cfg(windows)]
        let inner = tokio::signal::windows::ctrl_c()?;
        Ok(Interrupts { inner })
    }

    /// The next interrupt (never, once the stream has ended).
    pub(super) async fn recv(&mut self) {
        if self.inner.recv().await.is_none() {
            std::future::pending::<()>().await;
        }
    }
}

/// ⟨U5IO-Q2 (a)⟩ The Windows step containment: the client is created **suspended** in
/// a new kill-on-close job without breakaway (`JobObject::spawn_suspended`, M02's
/// primitive), then resumed; the job is the guard, so the step's client and every
/// process it starts end with the step, or with this process.
#[cfg(windows)]
pub(super) struct JobContainment;

#[cfg(windows)]
impl heimdall_enroll::remote::StepContainment for JobContainment {
    fn spawn_contained(
        &self,
        command: &mut std::process::Command,
    ) -> std::io::Result<heimdall_enroll::remote::Contained> {
        // The runner's command, moved out whole (program, arguments, environment and the
        // piped standard streams it set).
        let taken = std::mem::replace(command, std::process::Command::new(command.get_program()));
        let suspended = heimdall_localenv::sys::JobObject::spawn_suspended(taken)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let running = suspended
            .resume()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(heimdall_enroll::remote::Contained {
            child: running.child,
            guard: Box::new(running.job),
        })
    }

    fn ends_with_parent(&self) -> bool {
        true
    }
}

/// The platform's step runner.
#[must_use]
pub(super) fn runner() -> SshStepRunner {
    #[cfg(windows)]
    {
        SshStepRunner::new().with_containment(Box::new(JobContainment))
    }
    #[cfg(not(windows))]
    {
        SshStepRunner::new()
    }
}

/// How one step went.
enum Ran {
    /// It ran; this is its report.
    Report(heimdall_enroll::remote::StepReport),
    /// An interrupt aborted it (or came before it started).
    Interrupted,
    /// The runner refused it; nothing was spawned.
    Refused(StepRunError),
}

async fn run_one(
    runner: &Arc<SshStepRunner>,
    abort: &StepAbort,
    interrupts: &mut Interrupts,
    step: &RemoteStep,
    tty: TtyMode,
) -> Ran {
    let r = Arc::clone(runner);
    let s = step.clone();
    let mut handle = tokio::task::spawn_blocking(move || r.run(&s, tty));
    tokio::select! {
        biased;
        () = interrupts.recv() => {
            abort.abort();
            // The runner kills the step's process group and returns within its tick.
            let _ = handle.await;
            Ran::Interrupted
        }
        joined = &mut handle => match joined {
            Ok(Ok(report)) => Ran::Report(report),
            Ok(Err(StepRunError::Aborted)) => Ran::Interrupted,
            Ok(Err(e)) => Ran::Refused(e),
            Err(_) => Ran::Refused(StepRunError::Unavailable),
        },
    }
}

/// A finished enrollment result as the command's outcome.
pub(super) fn result_outcome(
    mut env: Envelope<serde_json::Value>,
    result: &heimdall_contract::enrollment::EnrollmentResult,
    form: Option<EnrollmentForm>,
) -> Outcome {
    env.data = serde_json::to_value(result).unwrap_or(serde_json::Value::Null);
    Outcome::of(env).with_human(super::render::result(result, form))
}

/// Drive `op` until the runtime needs no further step (module docs).
pub(super) async fn drive<S: Session>(s: &mut S, op: &OperationId, mode: DriveMode) -> Outcome {
    let mut interrupts = match Interrupts::new() {
        Ok(i) => i,
        Err(e) => {
            return Outcome::of(op_error(
                Code::InternalError,
                format!("cannot watch for Ctrl-C ({}); no step was run", e.kind()),
                op,
                EffectStatus::None,
                None,
                Some("reconcile"),
            ));
        }
    };
    let runner = Arc::new(runner());
    let abort = runner.abort_handle();
    let mut noticed = false;
    for _ in 0..MAX_STEPS {
        let env = s
            .request(Request::Enrollment(EnrollmentRequest::Step {
                operation_id: op.clone(),
            }))
            .await;
        if !env.code.is_success() {
            return Outcome::of(env);
        }
        let answer: StepAnswer = match serde_json::from_value(env.data.clone()) {
            Ok(a) => a,
            Err(_) => {
                return Outcome::of(op_error(
                    Code::InternalError,
                    "the runtime's step answer cannot be read; nothing was run".to_owned(),
                    op,
                    EffectStatus::None,
                    None,
                    Some("reconcile"),
                ));
            }
        };
        let step = match answer {
            StepAnswer::Step { step } => step,
            StepAnswer::Done { result } => {
                return result_outcome(env, &result, mode.form);
            }
            _ => {
                return Outcome::of(op_error(
                    Code::InternalError,
                    "the runtime answered a step this CLI does not know; nothing was run"
                        .to_owned(),
                    op,
                    EffectStatus::None,
                    None,
                    Some("reconcile"),
                ));
            }
        };
        let stage = stage_name(step.stage);
        if mode.after_manual_recovery && step.stage != RemoteStage::Inspect {
            return Outcome::of(op_error(
                Code::ConfigConflict,
                format!(
                    "a manual-recovery reconcile only classifies: the runtime issued a {stage} step, which was not run (never a redispatch)"
                ),
                op,
                EffectStatus::None,
                None,
                Some("reconcile"),
            ));
        }
        let tty = tty_mode(&step);
        if tty == TtyMode::Interactive {
            if super::REFUSE_UNHELD_INTERACTIVE_IDENTITY
                && !heimdall_enroll::remote::INTERACTIVE_FOREGROUND_HANDOFF
                && !agent_held(&step.pins.existing_access.0)
            {
                return Outcome::of(op_error(
                    Code::InteractionRequired,
                    format!(
                        "the {stage} step would use an identity that is not held by an agent, and a prompt on this terminal cannot be answered while a step runs; it was not run. Add the key to an agent, then run `heimdall enroll reconcile {op}`"
                    ),
                    op,
                    EffectStatus::None,
                    None,
                    Some("reconcile"),
                ));
            }
            if !noticed && !mode.json {
                output::diagnostic(HANDOFF_NOTICE);
                noticed = true;
            }
        }
        output::diagnostic(&format!("step {stage} (operation {op}): running"));
        let report = match run_one(&runner, &abort, &mut interrupts, &step, tty).await {
            Ran::Report(r) => r,
            Ran::Interrupted => {
                let msg = uncertain_message(op);
                output::diagnostic(&msg);
                return Outcome::of(op_error(
                    Code::OutcomeUnknown,
                    msg,
                    op,
                    EffectStatus::Unknown,
                    None,
                    Some("reconcile"),
                ));
            }
            Ran::Refused(e) => {
                let code = match e {
                    StepRunError::ContainmentUnavailable | StepRunError::Unavailable => {
                        Code::CapabilityUnavailable
                    }
                    _ => Code::InternalError,
                };
                return Outcome::of(op_error(
                    code,
                    format!(
                        "the {stage} step was not run ({e}); nothing was sent for it. Run `heimdall enroll reconcile {op}` once the cause is fixed"
                    ),
                    op,
                    EffectStatus::None,
                    None,
                    Some("reconcile"),
                ));
            }
        };
        let env = s
            .request(Request::Enrollment(EnrollmentRequest::StepResult {
                operation_id: op.clone(),
                step_token: step.step_token.clone(),
                exit_status: report.exit_status,
                stdout: report.stdout,
                stderr_excerpt: report.stderr_excerpt,
            }))
            .await;
        if !env.code.is_success() {
            return Outcome::of(env);
        }
        let Ok(recorded) = serde_json::from_value::<StepRecorded>(env.data.clone()) else {
            return Outcome::of(op_error(
                Code::InternalError,
                "the runtime's step record cannot be read".to_owned(),
                op,
                EffectStatus::Unknown,
                None,
                Some("reconcile"),
            ));
        };
        output::diagnostic(&format!(
            "step {stage}: {} (enrollment {})",
            recorded.class,
            recorded.state.as_str()
        ));
        if recorded.more {
            continue;
        }
        if let Some(result) = &recorded.result {
            return result_outcome(env, result, mode.form);
        }
        if let Some(error) = recorded.error.clone()
            && let Ok(detail) = serde_json::from_value::<heimdall_contract::envelope::ErrorDetail>(
                error.get("error").cloned().unwrap_or(error),
            )
        {
            return Outcome::of(output::error_value(
                heimdall_app::OpError::from_detail(detail, Some(op.clone())).into_envelope(),
            ));
        }
        // No further step and nothing settled yet: ask again (the runtime answers
        // `done` with the result, or the next step).
    }
    Outcome::of(op_error(
        Code::Accepted,
        format!(
            "the operation did not settle within {MAX_STEPS} steps; run `heimdall enroll reconcile {op}`"
        ),
        op,
        EffectStatus::Unknown,
        None,
        Some("reconcile"),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn o(k: &str, v: &str) -> SshOption {
        SshOption {
            key: k.to_owned(),
            value: v.to_owned(),
        }
    }

    #[test]
    fn agent_held_needs_a_concrete_agent_and_identities_only() {
        assert!(agent_held(&[
            o("IdentityAgent", "/tmp/a.sock"),
            o("IdentitiesOnly", "yes")
        ]));
        assert!(agent_held(&[
            o("IdentityAgent", "//./pipe/openssh-ssh-agent"),
            o("IdentitiesOnly", "yes")
        ]));
        for bad in [
            "none",
            "SSH_AUTH_SOCK",
            "$SSH_AUTH_SOCK",
            "",
            "relative/sock",
        ] {
            assert!(
                !agent_held(&[o("IdentityAgent", bad), o("IdentitiesOnly", "yes")]),
                "{bad}"
            );
        }
        assert!(!agent_held(&[
            o("IdentityAgent", "/tmp/a.sock"),
            o("IdentitiesOnly", "no")
        ]));
        assert!(!agent_held(&[o("IdentitiesOnly", "yes")]));
        assert!(invocation_agent_held(&[
            "-o".into(),
            "IdentityAgent=/tmp/a.sock".into(),
            "-o".into(),
            "IdentitiesOnly=yes".into()
        ]));
    }

    #[test]
    fn the_uncertain_message_is_exact() {
        let op = OperationId::parse("op_00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(
            uncertain_message(&op),
            "the change may have been applied; run `heimdall enroll reconcile op_00112233445566778899aabbccddeeff`"
        );
    }

    /// ADR-0008 §17.25 item 1: the notice names the residual, a server falling back to
    /// password or keyboard-interactive authentication, which still stalls the step
    /// until its bound.
    #[test]
    fn the_handoff_notice_names_the_auth_fallback_residual() {
        assert!(
            HANDOFF_NOTICE.contains(
                "a server that falls back to password or keyboard-interactive authentication still stalls the step until its time bound"
            ),
            "{HANDOFF_NOTICE}"
        );
        assert!(HANDOFF_NOTICE.contains("keep the identity in an agent"));
    }
}
