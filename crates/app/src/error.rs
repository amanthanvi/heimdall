//! Operation errors and their mapping to the envelope (spec §11.6; ADR-0006 §3, §5).

use heimdall_contract::envelope::{
    EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction, ResourceRef,
};
use heimdall_contract::ids::OperationId;
use heimdall_contract::{Code, OperationState};

/// A classified operation error. Every variant carries a stable code; the
/// envelope mapping is total.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct OpError {
    /// Stable code (never `Ok`/`AccessReady`/`Accepted`).
    pub code: Code,
    /// Whether any external effect happened.
    pub effect_status: EffectStatus,
    /// Resource concerned.
    pub resource: Option<ResourceRef>,
    /// Next action (defaults from the code).
    pub next: NextAction,
    /// Human text; no secrets, no terminal escapes.
    pub message: String,
    /// Operation, when one exists.
    pub operation_id: Option<OperationId>,
}

impl OpError {
    /// Build from a code with defaults.
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            effect_status: code.default_effect_status(),
            next: NextAction::for_code(code.clone()),
            code,
            resource: None,
            message: message.into(),
            operation_id: None,
        }
    }

    /// Attach a resource reference.
    #[must_use]
    pub fn with_resource(mut self, kind: &str, id: Option<String>) -> Self {
        self.resource = Some(ResourceRef {
            kind: kind.to_owned(),
            id,
        });
        self
    }

    /// Attach an operation ID.
    #[must_use]
    pub fn with_operation(mut self, id: OperationId) -> Self {
        self.operation_id = Some(id);
        self
    }

    /// Override the effect status (e.g. `Partial` after a cancelled mid-flight op).
    #[must_use]
    pub fn with_effect(mut self, effect: EffectStatus) -> Self {
        self.effect_status = effect;
        self
    }

    /// Render as the failed envelope.
    #[must_use]
    pub fn into_envelope(self) -> Envelope<ErrorData> {
        let state = match self.code {
            Code::OutcomeUnknown => OperationState::OutcomeUnknown,
            Code::OperationCancelled => OperationState::Cancelled,
            Code::ApprovalRequired => OperationState::AwaitingApproval,
            _ => OperationState::Failed,
        };
        let detail = ErrorDetail {
            code: self.code.clone(),
            effect_status: self.effect_status,
            retryable: self.code.retryable(),
            resource: self.resource,
            next: self.next.clone(),
            message: self.message,
        };
        let mut env = Envelope::failed(self.operation_id, detail);
        env.state = state;
        env.next = Some(self.next);
        env
    }
}

impl From<heimdall_store::StoreError> for OpError {
    fn from(e: heimdall_store::StoreError) -> Self {
        use heimdall_store::StoreError as S;
        let msg = match &e {
            S::NewerSchema { .. } => "state store is newer than this build".to_owned(),
            S::Corrupt(_) => "state store failed integrity check; recovery required".to_owned(),
            _ => "state store unavailable".to_owned(),
        };
        OpError::new(Code::StateUnavailable, msg).with_resource("store", None)
    }
}

impl From<crate::ids::RandomnessUnavailable> for OpError {
    fn from(_: crate::ids::RandomnessUnavailable) -> Self {
        OpError::new(Code::InternalError, "randomness unavailable")
    }
}

/// A completed (non-error) result with envelope metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Completed<T> {
    /// Operation, when one exists.
    pub operation_id: Option<OperationId>,
    /// State.
    pub state: OperationState,
    /// Success code.
    pub code: Code,
    /// Payload.
    pub data: T,
    /// Warnings.
    pub warnings: Vec<heimdall_contract::envelope::Warning>,
    /// Next action.
    pub next: Option<NextAction>,
}

impl<T> Completed<T> {
    /// Render as an envelope.
    #[must_use]
    pub fn into_envelope(self) -> Envelope<T> {
        Envelope {
            schema_version: heimdall_contract::SchemaVersion::current(),
            operation_id: self.operation_id,
            state: self.state,
            code: self.code,
            data: self.data,
            warnings: self.warnings,
            next: self.next,
        }
    }
}

/// Result alias for application operations.
pub type OpResult<T> = Result<Completed<T>, OpError>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn error_envelope_carries_code_state_and_next() {
        let e = OpError::new(Code::PolicyCutoff, "cutoff in effect").into_envelope();
        assert_eq!(e.code, Code::PolicyCutoff);
        assert_eq!(e.state, OperationState::Failed);
        assert_eq!(e.data.error.next.action, "owner_decision");
        assert!(!e.data.error.retryable);
        let unknown = OpError::new(Code::OutcomeUnknown, "lost ack").into_envelope();
        assert_eq!(unknown.state, OperationState::OutcomeUnknown);
        assert_eq!(unknown.data.error.effect_status, EffectStatus::Unknown);
    }
}
