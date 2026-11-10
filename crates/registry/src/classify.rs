//! The runtime's pure classification of a reported remote step result (ADR-0008 D5
//! §6.3, §6.7; m03-plan §5 item 19 comment, U5 "Interfaces").
//!
//! The signature of [`classify_step`] and the class set are frozen in wave 0 (U0).
//! The body is U5's. **Wave 0:** every result classifies as [`StepClass::Uncertain`],
//! the most fail-closed class: it is never read as applied (no `Confirmed` or
//! `AlreadyPresent`), and an uncertain mutating step is never redispatched without a
//! later `inspect` and reconcile.

use heimdall_contract::enrollment::RemoteStage;

/// Why a step was not applied (nothing changed on the remote).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NotAppliedReason {
    /// Exit 40: a lock exists.
    Busy,
    /// Exit 41: the remote not-after had passed.
    NotAfterPassed,
    /// Exit 42: the lock was lost before the write.
    LockLost,
    /// Exit 32: the registry's directory is absent.
    DirAbsent,
    /// Exit 33 from `bootstrap`: the parent is absent.
    ParentAbsent,
    /// Exit 33 from a locking script: the shell is not its own group leader.
    NoProcessGroup,
    /// Refused before any effect (exit 30, or no script sent).
    Refused,
}

/// The class of one step result (m03-plan U5 `classify_step`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StepClass {
    /// The effect happened and the post-write check passed.
    Confirmed,
    /// The effect was already present (exit 10 or 11).
    AlreadyPresent,
    /// Nothing changed.
    NotApplied(NotAppliedReason),
    /// The outcome is unknown: a later `inspect` and reconcile decide.
    Uncertain,
    /// Host trust failed (`HOST_TRUST_CHANGED`).
    HostTrustChanged,
    /// The existing-access provider is locked.
    ProviderLocked,
    /// The step needs the owner's interaction.
    InteractionRequired,
    /// The record goes to `held` (damaged line, concurrent change).
    Held,
}

/// A step result as the runtime received it (`Enrollment::StepResult`; ADR-0008 D5
/// §6.3 item 2). The bounds are enforced before classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    /// The client's exit status.
    pub exit_status: i32,
    /// At most 512 KiB of output (HM1 lines after the ready line).
    pub stdout: String,
    /// At most 4 KiB, redacted, diagnostics only.
    pub stderr_excerpt: String,
}

/// What the runtime expected of the step (the journal's facts at dispatch).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expected {
    /// The enrollment's marker (`heimdall:<enrollment-id>`).
    pub marker: String,
    /// The exact registry line (`append`, `remove`).
    pub line: Option<String>,
    /// The inspected preimage (`append`'s post-write check; `remove`'s compare).
    pub preimage: Option<Vec<u8>>,
    /// The expected post-image (`remove`).
    pub post_image: Option<Vec<u8>>,
}

/// Classify one step result.
///
/// **Wave 0:** returns [`StepClass::Uncertain`] for every input (U5 fills the body:
/// HM1 parsing, exit codes, the post-write checks, and the 255 rule).
#[must_use]
pub fn classify_step(stage: RemoteStage, result: &StepResult, expected: &Expected) -> StepClass {
    let _ = (stage, result, expected);
    StepClass::Uncertain
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn wave0_classification_is_never_success() {
        let stages = [
            RemoteStage::Inspect,
            RemoteStage::Bootstrap,
            RemoteStage::Append,
            RemoteStage::Remove,
            RemoteStage::Fence,
        ];
        for stage in stages {
            for exit_status in [0, 10, 11, 255] {
                let result = StepResult {
                    exit_status,
                    stdout: "HM1 ready\nHM1 v=1\n".into(),
                    stderr_excerpt: String::new(),
                };
                let class = classify_step(stage, &result, &Expected::default());
                assert_eq!(class, StepClass::Uncertain);
            }
        }
    }
}
