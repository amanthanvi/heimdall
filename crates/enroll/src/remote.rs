//! The CLI-side runner of client-executed remote steps (ADR-0008 D5 §6.3; m03-plan U5
//! `enroll::remote::SshStepRunner`).
//!
//! It runs the verified client named in the step with exactly the step's pins, alias,
//! remote command and script (adding and dropping nothing), writes the script only
//! after reading `HM1 ready`, ties ssh's lifetime to the CLI's (its own process group,
//! `PR_SET_PDEATHSIG` on Linux, a kill-on-close job on Windows), attaches the owner's
//! terminal only for an interactive step, and bounds everything (stdout 512 KiB,
//! stderr 64 KiB with a 4 KiB excerpt, connect 30 s, total 120 s or 300 s).
//!
//! U5 fills the body. **Wave 0:** [`SshStepRunner::run`] starts nothing and refuses
//! with [`StepRunError::Unavailable`]; no process is spawned and no script is sent.

use heimdall_contract::enrollment::RemoteStep;

/// Whether the owner's terminal is attached to the step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TtyMode {
    /// The owner's terminal is attached (a passphrase, a touch, a provider dialog).
    Interactive,
    /// No terminal; `BatchMode=yes`.
    Batch,
}

/// What the CLI sends back as `Enrollment::StepResult` (ADR-0008 D5 §6.3 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// The client's exit status.
    pub exit_status: i32,
    /// The client's stdout, at most 512 KiB.
    pub stdout: String,
    /// At most 4 KiB of stderr, redacted.
    pub stderr_excerpt: String,
}

/// Why a step was not run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StepRunError {
    /// The step runner is not in this build (wave 0; U5 fills it). Nothing ran.
    #[error("the remote step runner is not available in this build")]
    Unavailable,
}

/// The client-executed step runner.
#[derive(Debug, Default)]
pub struct SshStepRunner {
    _private: (),
}

impl SshStepRunner {
    /// A runner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `step` once.
    ///
    /// # Errors
    /// **Wave 0:** always [`StepRunError::Unavailable`]; nothing is spawned.
    pub fn run(&self, step: &RemoteStep, tty: TtyMode) -> Result<StepReport, StepRunError> {
        let _ = (step, tty);
        Err(StepRunError::Unavailable)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::enrollment::{RemoteStage, StepPins};

    #[test]
    fn wave0_runner_spawns_nothing() {
        let step = RemoteStep {
            stage: RemoteStage::Inspect,
            step_token: "0".repeat(32),
            client: "/nonexistent/heimdall-test-ssh".into(),
            pins: StepPins::default(),
            alias: "hm-test".into(),
            remote_command: "printf 'HM1 ready\\n'; exec /bin/sh -s".into(),
            script: String::new(),
            timeout_ms: 1,
            hard_deadline_ms: 1,
            not_after_remote: None,
        };
        let runner = SshStepRunner::new();
        for tty in [TtyMode::Batch, TtyMode::Interactive] {
            assert_eq!(runner.run(&step, tty), Err(StepRunError::Unavailable));
        }
    }
}
