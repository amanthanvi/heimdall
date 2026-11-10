//! Operation errors and their mapping to the envelope (spec §11.6; ADR-0006 §3, §5;
//! overview §7).
//!
//! Every classified failure crossing the application boundary is an [`OpError`].
//! The mappings from domain refusals, adapter errors, store errors and decision
//! refusals live here so every primitive renders the same condition with the same
//! code. Messages are fixed text chosen here: no adapter string, request field or
//! observed value is echoed (secrets and canaries can never reach an envelope
//! through an error message).

use heimdall_contract::envelope::{
    EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction, ResourceRef,
};
use heimdall_contract::ids::OperationId;
use heimdall_contract::{Code, OperationState};
use heimdall_domain::authority::{ActivationBlockRepr, Denial};
use heimdall_domain::decision::DecisionRefusal;
use heimdall_domain::issuance::IssuanceRefusal;
use heimdall_domain::time::DeadlineError;

use crate::ports::AdapterError;

/// A classified operation error. Every variant carries a stable code; the
/// envelope mapping is total.
///
/// Two codes that are not failures travel through this type because the
/// primitives' success payloads cannot express them (M01-U5 reading):
/// `APPROVAL_REQUIRED` / `INTERACTION_REQUIRED` **with** `next.decision_ref`
/// (the operation is `awaiting_approval`), and `ACCEPTED` (a bounded wait ended
/// while the operation is still running; the payload reports the pending state).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct OpError {
    /// Stable code (never `Ok`/`AccessReady`; `Accepted` only for a bounded wait
    /// that ended before the operation settled).
    pub code: Code,
    /// Whether any external effect happened.
    pub effect_status: EffectStatus,
    /// Resource concerned. Boxed so that the error stays small enough to travel in
    /// other enums (⟨M02⟩ the reason and the next action's provider reference made it
    /// grow).
    pub resource: Option<Box<ResourceRef>>,
    /// Next action (defaults from the code).
    pub next: NextAction,
    /// Human text; no secrets, no terminal escapes.
    pub message: String,
    /// Operation, when one exists.
    pub operation_id: Option<OperationId>,
    /// ⟨M02⟩ Stable `snake_case` sub-reason (m02-plan §5 item 14, U0b row 14; wire
    /// `data.error.reason`, the wave-0 E3 reading). Values from
    /// `heimdall_contract::envelope::reason`; never request content.
    pub reason: Option<String>,
    /// ⟨M02⟩ ADR-0007 §12.26 item 4: the configuration entries the refusal concerns
    /// (wire `data.error.entries`): the runtime's no-interaction refusal at `ensure`
    /// names the refused `IdentityFile` lines, as the CLI's pre-launch refusal does.
    /// Display paths and line numbers only; empty for every other error.
    pub entries: Vec<heimdall_contract::doctor::ConfigProvenance>,
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
            reason: None,
            entries: Vec::new(),
        }
    }

    /// ⟨M02⟩ Attach a stable sub-reason (`data.error.reason`).
    #[must_use]
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_owned());
        self
    }

    /// ⟨M02⟩ ADR-0007 §12.26 item 4: attach the configuration entries the refusal
    /// concerns (`data.error.entries`).
    #[must_use]
    pub fn with_entries(
        mut self,
        entries: Vec<heimdall_contract::doctor::ConfigProvenance>,
    ) -> Self {
        self.entries = entries;
        self
    }

    /// ⟨M02⟩ `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, effect `none`:
    /// the answer for a request, decision or cancellation whose driver is not in this
    /// build (m02-plan §5 item 4, the wave-0 fail-closed landing; ADR-0007 §12.7 QR7).
    #[must_use]
    pub fn driver_unavailable(message: &str) -> Self {
        OpError::new(Code::CapabilityUnavailable, message.to_owned())
            .with_reason(heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE)
            .with_effect(EffectStatus::None)
    }

    /// Attach a resource reference.
    #[must_use]
    pub fn with_resource(mut self, kind: &str, id: Option<String>) -> Self {
        self.resource = Some(Box::new(ResourceRef {
            kind: kind.to_owned(),
            id,
        }));
        self
    }

    /// Attach an operation ID (also carried in `next.operation_id` when the next
    /// action is about observing or reconciling that operation).
    #[must_use]
    pub fn with_operation(mut self, id: OperationId) -> Self {
        if matches!(
            self.next.action.as_str(),
            "observe" | "reconcile" | "interact" | "owner_decision"
        ) && self.next.operation_id.is_none()
        {
            self.next.operation_id = Some(id.clone());
        }
        self.operation_id = Some(id);
        self
    }

    /// Override the effect status (e.g. `Partial` after a cancelled mid-flight op).
    /// `OUTCOME_UNKNOWN` always stays `unknown` (plan §6.3 #7: an uncertain effect
    /// is never reported as not applied).
    #[must_use]
    pub fn with_effect(mut self, effect: EffectStatus) -> Self {
        self.effect_status = if self.code == Code::OutcomeUnknown {
            EffectStatus::Unknown
        } else {
            effect
        };
        self
    }

    /// Attach the nonsecret reference of a pending decision (`next.decision_ref`).
    #[must_use]
    pub fn with_decision(mut self, decision_ref: impl Into<String>) -> Self {
        self.next.decision_ref = Some(decision_ref.into());
        self
    }

    /// Replace the next action entirely.
    #[must_use]
    pub fn with_next(mut self, next: NextAction) -> Self {
        self.next = next;
        self
    }

    /// Suggested retry delay (`next.retry_after_ms`).
    #[must_use]
    pub fn with_retry_after(mut self, ms: u64) -> Self {
        self.next.retry_after_ms = Some(ms);
        self
    }

    /// Operation state this error describes: `outcome_unknown`, `cancelled`,
    /// `awaiting_approval` (approval or interaction with a decision reference),
    /// `running` for `ACCEPTED`, else `failed`.
    #[must_use]
    pub fn state(&self) -> OperationState {
        match self.code {
            Code::OutcomeUnknown => OperationState::OutcomeUnknown,
            Code::OperationCancelled => OperationState::Cancelled,
            Code::ApprovalRequired => OperationState::AwaitingApproval,
            Code::InteractionRequired if self.next.decision_ref.is_some() => {
                OperationState::AwaitingApproval
            }
            Code::Accepted => OperationState::Running,
            _ => OperationState::Failed,
        }
    }

    /// The error detail (`data.error`).
    #[must_use]
    pub fn detail(&self) -> ErrorDetail {
        ErrorDetail {
            code: self.code.clone(),
            effect_status: self.effect_status,
            retryable: self.code.retryable(),
            resource: self.resource.as_deref().cloned(),
            next: self.next.clone(),
            message: self.message.clone(),
            reason: self.reason.clone(),
            // ⟨M02⟩ ADR-0007 §12.24 item 4, §12.26 item 4: the runtime's
            // no-interaction refusal names its refused lines; a launcher's pre-launch
            // refusal sets `entries` on the detail it renders.
            entries: self.entries.clone(),
        }
    }

    /// Rebuild from a stored error detail (replay of a settled failure). ⟨M02⟩ The
    /// detail's `entries` are kept: a replayed no-interaction refusal names the same
    /// lines (ADR-0007 §12.26 item 4).
    #[must_use]
    pub fn from_detail(detail: ErrorDetail, operation_id: Option<OperationId>) -> Self {
        Self {
            code: detail.code,
            effect_status: detail.effect_status,
            resource: detail.resource.map(Box::new),
            next: detail.next,
            message: detail.message,
            operation_id,
            reason: detail.reason,
            entries: detail.entries,
        }
    }

    /// Render as the failed envelope.
    #[must_use]
    pub fn into_envelope(self) -> Envelope<ErrorData> {
        let state = self.state();
        let detail = self.detail();
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
            S::OlderSchema { .. } => {
                "state store is older than this build; it was not upgraded".to_owned()
            }
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

impl From<AdapterError> for OpError {
    /// Adapter failures by variant (overview §7). `Unavailable` of a credential
    /// adapter is a local dependency (`SERVICE_UNAVAILABLE`); destinations are
    /// reported through [`OpError::from_adapter_for`]. Adapter text is never echoed.
    fn from(e: AdapterError) -> Self {
        OpError::from_adapter_for(&e, "adapter")
    }
}

impl OpError {
    /// Map an adapter error for a resource kind: `Unavailable` is
    /// `DESTINATION_UNREACHABLE` for a `destination`, else `SERVICE_UNAVAILABLE`.
    #[must_use]
    pub fn from_adapter_for(e: &AdapterError, resource_kind: &str) -> Self {
        let (code, msg) = match e {
            AdapterError::ProviderLocked => {
                (Code::ProviderLocked, "the credential provider is locked")
            }
            AdapterError::InteractionRequired(_) => (
                Code::InteractionRequired,
                "the credential provider requires an interaction this request does not permit",
            ),
            AdapterError::Unavailable(_) if resource_kind == "destination" => (
                Code::DestinationUnreachable,
                "the destination is not reachable over any approved route",
            ),
            AdapterError::Unavailable(_) => (
                Code::ServiceUnavailable,
                "a credential adapter dependency is unavailable",
            ),
            AdapterError::CapabilityUnavailable => (
                Code::CapabilityUnavailable,
                "the credential mechanism cannot meet the requested capability",
            ),
            AdapterError::OutcomeUnknown(_) => (
                Code::OutcomeUnknown,
                "the credential effect may or may not have applied; it will be reconciled",
            ),
            AdapterError::Protocol(_) => (
                Code::UnsupportedClient,
                "the credential adapter dependency spoke an unsupported protocol",
            ),
        };
        OpError::new(code, msg).with_resource(resource_kind, None)
    }

    /// Map an authority-resolution denial (spec §6.1, §6.7; ADR-0006 §14.4).
    #[must_use]
    pub fn from_denial(denial: &Denial) -> Self {
        match denial {
            Denial::Blocked(ActivationBlockRepr::Paused { .. }) => {
                OpError::new(Code::PolicyPaused, "the standing policy is paused")
                    .with_resource("policy", None)
            }
            Denial::Blocked(ActivationBlockRepr::Cutoff { .. }) => {
                OpError::new(Code::PolicyCutoff, "a policy cutoff is in effect")
                    .with_resource("policy", None)
            }
            Denial::ExceedsParent { .. } => OpError::new(
                Code::DelegationExceedsParent,
                "the delegation is broader or longer than its parent",
            )
            .with_resource("binding", None),
            Denial::CapabilityUnavailable { .. } => OpError::new(
                Code::CapabilityUnavailable,
                "the requested minimum capability cannot be met",
            ),
            Denial::RoleForbidden => OpError::new(
                Code::CapabilityUnavailable,
                "this caller's role may only request already-allowed work",
            ),
            Denial::ParentNotUsable => OpError::new(
                Code::CredentialExpired,
                "the parent grant is not usable (expired, revoked or from an older authority generation)",
            )
            .with_resource("grant", None),
            Denial::DeadlinePassed { .. } => OpError::new(
                Code::CredentialExpired,
                "the requested deadline has already passed",
            ),
        }
    }

    /// Map a deadline-resolution failure. Errors never echo the intent.
    #[must_use]
    pub fn from_deadline(e: &DeadlineError) -> Self {
        match e {
            DeadlineError::NotInFuture => OpError::new(
                Code::CredentialExpired,
                "the requested deadline has already passed",
            ),
            DeadlineError::ExceedsMaximum => OpError::new(
                Code::UsageError,
                "the requested deadline exceeds the maximum window",
            ),
            DeadlineError::Ambiguous => OpError::new(
                Code::UsageError,
                "the requested local time is ambiguous or does not exist; send an explicit offset",
            ),
            DeadlineError::Malformed(_) => OpError::new(
                Code::UsageError,
                "the deadline must be RFC 3339 with an explicit offset or an exact duration",
            ),
        }
    }

    /// Map a refused decision completion (`DECISION_STALE`, ADR-0006 §3.1).
    #[must_use]
    pub fn from_decision_refusal(refusal: &DecisionRefusal) -> Self {
        let msg = match refusal {
            DecisionRefusal::NotPending(_) => "the decision was already completed or invalidated",
            DecisionRefusal::Expired => "the decision expired before it was completed",
            DecisionRefusal::StaleGeneration { .. } => {
                "the authority generation changed since the decision was issued"
            }
        };
        OpError::new(Code::DecisionStale, msg).with_resource("decision", None)
    }

    /// Map an issuance refusal (ADR-0005 §3.5; ADR-0006 §13.4 N02).
    #[must_use]
    pub fn from_issuance_refusal(refusal: &IssuanceRefusal) -> Self {
        use IssuanceRefusal as R;
        let (code, msg) = match refusal {
            R::TimeUncertain => (Code::TimeUncertain, "time is uncertain; issuance stopped"),
            R::PausedActivation => (Code::PolicyPaused, "the standing policy is paused"),
            R::CutoffPassed => (Code::PolicyCutoff, "a policy cutoff is in effect"),
            R::BoundPassed | R::BudgetExpired => (
                Code::CredentialExpired,
                "the grant's admission deadline has passed",
            ),
            R::GrantNotIssuable(_)
            | R::StaleGeneration
            | R::Tombstoned
            | R::StalePolicyRevision
            | R::AncestorDenied
            | R::StaleAncestor => (
                Code::CredentialExpired,
                "the grant's authority is no longer current (revoked, ended or changed)",
            ),
            R::AncestorMissing => (
                Code::StateUnavailable,
                "the grant's ancestor chain is incomplete in the state store",
            ),
            R::MechanismUnavailable => (
                Code::CapabilityUnavailable,
                "the grant's credential mechanism is unavailable",
            ),
            R::PairOutsideSnapshot
            | R::ChildExceedsParent
            | R::BoundTooLate
            | R::WrongPrincipal
            | R::UnpermittedExtension
            | R::CriticalOption
            | R::UnknownSubjectKey => (
                Code::CapabilityUnavailable,
                "the requested certificate is outside the grant's permissions",
            ),
            // M03 wave 0 (A1): fail closed until U0b
            R::UnknownCa | R::CaNotVerifiedForPair | R::CaRetiring => (
                Code::CapabilityUnavailable,
                "the certificate's CA cannot issue for this pair",
            ),
        };
        OpError::new(code, msg).with_resource("grant", None)
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
    /// A synchronous success (`state = succeeded`) with `code` and no next action.
    #[must_use]
    pub fn ok(code: Code, data: T) -> Self {
        Self {
            operation_id: None,
            state: OperationState::Succeeded,
            code,
            data,
            warnings: Vec::new(),
            next: None,
        }
    }

    /// Attach an operation ID.
    #[must_use]
    pub fn with_operation(mut self, id: OperationId) -> Self {
        self.operation_id = Some(id);
        self
    }

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

    /// Map the payload.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Completed<U> {
        Completed {
            operation_id: self.operation_id,
            state: self.state,
            code: self.code,
            data: f(self.data),
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

    #[test]
    fn decision_reference_marks_awaiting_and_outcome_unknown_stays_unknown() {
        let pending = OpError::new(Code::InteractionRequired, "needs owner")
            .with_decision("dec_1")
            .into_envelope();
        assert_eq!(pending.state, OperationState::AwaitingApproval);
        assert_eq!(pending.next.unwrap().decision_ref.as_deref(), Some("dec_1"));
        let refused = OpError::new(Code::InteractionRequired, "not attended").into_envelope();
        assert_eq!(refused.state, OperationState::Failed);
        let forced = OpError::new(Code::OutcomeUnknown, "x").with_effect(EffectStatus::None);
        assert_eq!(forced.effect_status, EffectStatus::Unknown);
        let accepted = OpError::new(Code::Accepted, "pending").into_envelope();
        assert_eq!(accepted.state, OperationState::Running);
    }

    #[test]
    fn adapter_errors_map_by_variant_without_echoing_text() {
        // Synthetic canary built at runtime (never a literal in source).
        let secret = ["HEIMDALL", "CANARY", "adapter", "text"].join("_");
        let secret = secret.as_str();
        for (e, code) in [
            (AdapterError::ProviderLocked, Code::ProviderLocked),
            (
                AdapterError::Unavailable(secret.into()),
                Code::ServiceUnavailable,
            ),
            (
                AdapterError::CapabilityUnavailable,
                Code::CapabilityUnavailable,
            ),
            (
                AdapterError::OutcomeUnknown(secret.into()),
                Code::OutcomeUnknown,
            ),
            (
                AdapterError::Protocol(secret.into()),
                Code::UnsupportedClient,
            ),
        ] {
            let op = OpError::from(e);
            assert_eq!(op.code, code);
            assert!(!op.message.contains(secret));
        }
        let dest =
            OpError::from_adapter_for(&AdapterError::Unavailable(secret.into()), "destination");
        assert_eq!(dest.code, Code::DestinationUnreachable);
    }

    /// ADR-0007 §12.26 item 4: the refused lines travel in `data.error.entries`, and
    /// a replayed stored failure keeps them.
    #[test]
    fn entries_reach_the_detail_and_survive_replay() {
        let at = |line| heimdall_contract::doctor::ConfigProvenance {
            path_display: "~/.ssh/config".to_owned(),
            line,
        };
        let e = OpError::new(Code::InteractionRequired, "not attended")
            .with_entries(vec![at(5), at(9)]);
        let detail = e.detail();
        assert_eq!(detail.entries, [at(5), at(9)]);
        let replayed = OpError::from_detail(detail, None);
        assert_eq!(replayed.entries, [at(5), at(9)]);
        assert_eq!(replayed.into_envelope().data.error.entries, [at(5), at(9)]);
        assert!(
            OpError::new(Code::InternalError, "x")
                .detail()
                .entries
                .is_empty()
        );
    }
}
