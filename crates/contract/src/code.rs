//! Stable semantic codes (spec §11.6; ADR-0006 §5).
//!
//! Codes are never localized and never carry secrets. Every error code has an
//! effect status, a retryability flag and a machine next action. "Retryable" never
//! means permission to replay an arbitrary remote mutation (spec §11.6).

use serde::{Deserialize, Serialize};

use crate::envelope::EffectStatus;
use crate::exit::ExitCode;

/// The stable code table. Spec §11.6 lists the codes marked `spec`; the others are
/// baseline additions recorded in ADR-0006 §5 (primitives-draft Q3 is folded in).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum Code {
    // --- success ---------------------------------------------------------------
    /// Synchronous read or control action completed.
    Ok,
    /// `ensure`/`bind` produced usable access (spec §11.3 example). (spec)
    AccessReady,
    /// Asynchronous request accepted; the payload reports a pending state
    /// (spec §11.6 "asynchronous accepted/pending").
    Accepted,

    // --- required interaction (exit 3) ------------------------------------------
    /// Additional owner authority is required; operation is `awaiting_approval`. (spec)
    ApprovalRequired,
    /// A provider or terminal interaction is required that non-interactive mode
    /// refuses to open (spec §11.3). (spec)
    InteractionRequired,
    /// The provider will not sign while locked (spec §7.1). (spec)
    ProviderLocked,

    // --- denied / paused / cutoff (exit 4) ----------------------------------------
    /// The minimum requested capability cannot be met (spec §4.3). (spec)
    CapabilityUnavailable,
    /// The standing policy is paused (spec §6.1). (spec)
    PolicyPaused,
    /// A policy cutoff is in effect; fresh identifiers do not bypass it (spec §6.1). (spec)
    PolicyCutoff,
    /// The applicable grant or credential has expired; renewal cannot extend it
    /// (spec §6.1). (spec)
    CredentialExpired,
    /// Destination host identity changed; recovery must not accept it silently
    /// (spec §9.1). (spec)
    HostTrustChanged,
    /// A delegation request is broader or longer than its parent (spec §6.7;
    /// primitives-draft Q3).
    DelegationExceedsParent,
    /// The operation was explicitly cancelled (spec §11.4).
    OperationCancelled,

    // --- unavailable / dependency (exit 5) ------------------------------------------
    /// Destination not reachable over any approved route. (spec)
    DestinationUnreachable,
    /// Safe time cannot be established; issuance stopped (spec §6.4). (spec)
    TimeUncertain,
    /// The SSH client or consumer is unsupported for the requested path (spec §10.3). (spec)
    UnsupportedClient,
    /// The per-user runtime cannot be reached or started (spec §13.1).
    ServiceUnavailable,
    /// The local state store is unavailable, locked, corrupt, or newer than this
    /// build; unsafe operations stop and recovery is offered (spec §13.3, §15.2).
    StateUnavailable,
    /// A bounded queue or buffer is full; retry with backoff or resync (spec §11.5).
    Backpressure,

    // --- conflict (exit 6) -------------------------------------------------------------
    /// Same idempotency key with different canonical parameters (spec §11.4). (spec)
    RequestConflict,
    /// Managed configuration conflicts with a newer user edit (spec §10.1). (spec)
    ConfigConflict,
    /// The idempotency record for this key has aged out; the retry is not silently
    /// treated as new (spec §11.4).
    RequestExpired,
    /// The event cursor is expired or foreign; take a snapshot and resume from its
    /// cursor boundary (spec §11.2, §11.5; primitives-draft Q3).
    ResyncRequired,

    // --- uncertain external outcome (exit 7) -------------------------------------------
    /// An external mutation may or may not have applied (spec §7.5, §11.4). (spec)
    OutcomeUnknown,

    // --- usage / schema (exit 2) ----------------------------------------------------------
    /// Invalid arguments or request body.
    UsageError,
    /// Unsupported schema major, protocol version, or required capability
    /// (spec §11.2).
    SchemaUnsupported,
    /// The referenced operation, binding, grant, profile, or environment is unknown
    /// to this runtime (possibly purged by retention).
    NotFound,

    // --- internal (exit 1) -----------------------------------------------------------------
    /// Unexpected internal failure; never used to hide a classified condition.
    InternalError,
}

impl Code {
    /// The wire spelling (SCREAMING_SNAKE_CASE).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Ok => "OK",
            Code::AccessReady => "ACCESS_READY",
            Code::Accepted => "ACCEPTED",
            Code::ApprovalRequired => "APPROVAL_REQUIRED",
            Code::InteractionRequired => "INTERACTION_REQUIRED",
            Code::ProviderLocked => "PROVIDER_LOCKED",
            Code::CapabilityUnavailable => "CAPABILITY_UNAVAILABLE",
            Code::PolicyPaused => "POLICY_PAUSED",
            Code::PolicyCutoff => "POLICY_CUTOFF",
            Code::CredentialExpired => "CREDENTIAL_EXPIRED",
            Code::HostTrustChanged => "HOST_TRUST_CHANGED",
            Code::DelegationExceedsParent => "DELEGATION_EXCEEDS_PARENT",
            Code::OperationCancelled => "OPERATION_CANCELLED",
            Code::DestinationUnreachable => "DESTINATION_UNREACHABLE",
            Code::TimeUncertain => "TIME_UNCERTAIN",
            Code::UnsupportedClient => "UNSUPPORTED_CLIENT",
            Code::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Code::StateUnavailable => "STATE_UNAVAILABLE",
            Code::Backpressure => "BACKPRESSURE",
            Code::RequestConflict => "REQUEST_CONFLICT",
            Code::ConfigConflict => "CONFIG_CONFLICT",
            Code::RequestExpired => "REQUEST_EXPIRED",
            Code::ResyncRequired => "RESYNC_REQUIRED",
            Code::OutcomeUnknown => "OUTCOME_UNKNOWN",
            Code::UsageError => "USAGE_ERROR",
            Code::SchemaUnsupported => "SCHEMA_UNSUPPORTED",
            Code::NotFound => "NOT_FOUND",
            Code::InternalError => "INTERNAL_ERROR",
        }
    }

    /// Every code, in table order (used by golden tests and schema export).
    #[must_use]
    pub fn all() -> &'static [Code] {
        &[
            Code::Ok,
            Code::AccessReady,
            Code::Accepted,
            Code::ApprovalRequired,
            Code::InteractionRequired,
            Code::ProviderLocked,
            Code::CapabilityUnavailable,
            Code::PolicyPaused,
            Code::PolicyCutoff,
            Code::CredentialExpired,
            Code::HostTrustChanged,
            Code::DelegationExceedsParent,
            Code::OperationCancelled,
            Code::DestinationUnreachable,
            Code::TimeUncertain,
            Code::UnsupportedClient,
            Code::ServiceUnavailable,
            Code::StateUnavailable,
            Code::Backpressure,
            Code::RequestConflict,
            Code::ConfigConflict,
            Code::RequestExpired,
            Code::ResyncRequired,
            Code::OutcomeUnknown,
            Code::UsageError,
            Code::SchemaUnsupported,
            Code::NotFound,
            Code::InternalError,
        ]
    }

    /// Whether the code reports success (including an accepted pending request).
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Code::Ok | Code::AccessReady | Code::Accepted)
    }

    /// CLI exit class for a non-child command that ends with this code
    /// (spec §11.6; ADR-0006 §6). `Accepted` exits 0 only when the caller selected
    /// asynchronous behaviour; the CLI enforces that rule, not this table.
    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        match self {
            Code::Ok | Code::AccessReady | Code::Accepted => ExitCode::Success,
            Code::ApprovalRequired | Code::InteractionRequired | Code::ProviderLocked => {
                ExitCode::InteractionRequired
            }
            Code::CapabilityUnavailable
            | Code::PolicyPaused
            | Code::PolicyCutoff
            | Code::CredentialExpired
            | Code::HostTrustChanged
            | Code::DelegationExceedsParent
            | Code::OperationCancelled => ExitCode::Denied,
            Code::DestinationUnreachable
            | Code::TimeUncertain
            | Code::UnsupportedClient
            | Code::ServiceUnavailable
            | Code::StateUnavailable
            | Code::Backpressure => ExitCode::Unavailable,
            Code::RequestConflict
            | Code::ConfigConflict
            | Code::RequestExpired
            | Code::ResyncRequired => ExitCode::Conflict,
            Code::OutcomeUnknown => ExitCode::OutcomeUnknown,
            Code::UsageError | Code::SchemaUnsupported | Code::NotFound => ExitCode::Usage,
            Code::InternalError => ExitCode::Internal,
        }
    }

    /// Whether an unchanged retry of the same request can be expected to succeed
    /// later. Retryable codes still never authorize replaying an arbitrary remote
    /// mutation (spec §11.6); `OutcomeUnknown` requires reconciliation first.
    #[must_use]
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Code::DestinationUnreachable
                | Code::TimeUncertain
                | Code::ServiceUnavailable
                | Code::StateUnavailable
                | Code::Backpressure
                | Code::ProviderLocked
        )
    }

    /// Default effect status reported with this code when the operation attaches
    /// nothing more specific (spec §11.6 "effect status").
    #[must_use]
    pub fn default_effect_status(self) -> EffectStatus {
        match self {
            Code::Ok | Code::AccessReady => EffectStatus::Applied,
            Code::OutcomeUnknown => EffectStatus::Unknown,
            Code::OperationCancelled => EffectStatus::Partial,
            _ => EffectStatus::None,
        }
    }

    /// Machine next action name attached by default (ADR-0006 §5). Operations may
    /// attach a more specific [`crate::envelope::NextAction`].
    #[must_use]
    pub fn default_next_action(self) -> &'static str {
        match self {
            Code::Ok => "none",
            Code::AccessReady => "use_binding",
            Code::Accepted | Code::ApprovalRequired => "observe",
            Code::InteractionRequired | Code::ProviderLocked => "interact",
            Code::CapabilityUnavailable | Code::DelegationExceedsParent => "narrow_request",
            Code::PolicyPaused | Code::PolicyCutoff => "owner_decision",
            Code::CredentialExpired => "new_work",
            Code::HostTrustChanged => "review_host_trust",
            Code::OperationCancelled => "none",
            Code::DestinationUnreachable
            | Code::TimeUncertain
            | Code::ServiceUnavailable
            | Code::StateUnavailable
            | Code::Backpressure => "retry_after",
            Code::UnsupportedClient => "change_client",
            Code::RequestConflict | Code::RequestExpired => "new_request_id",
            Code::ConfigConflict => "review_config",
            Code::ResyncRequired => "resync",
            Code::OutcomeUnknown => "reconcile",
            Code::UsageError | Code::SchemaUnsupported | Code::NotFound => "fix_request",
            Code::InternalError => "report",
        }
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn wire_spelling_matches_serde() {
        for code in Code::all() {
            let json = serde_json::to_string(code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            let back: Code = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *code);
        }
    }

    #[test]
    fn spec_codes_present() {
        // spec §11.6 list, verbatim.
        let required = [
            "APPROVAL_REQUIRED",
            "CAPABILITY_UNAVAILABLE",
            "PROVIDER_LOCKED",
            "INTERACTION_REQUIRED",
            "HOST_TRUST_CHANGED",
            "DESTINATION_UNREACHABLE",
            "CREDENTIAL_EXPIRED",
            "POLICY_PAUSED",
            "POLICY_CUTOFF",
            "REQUEST_CONFLICT",
            "CONFIG_CONFLICT",
            "OUTCOME_UNKNOWN",
            "UNSUPPORTED_CLIENT",
            "TIME_UNCERTAIN",
        ];
        let all: Vec<&str> = Code::all().iter().map(|c| c.as_str()).collect();
        for r in required {
            assert!(all.contains(&r), "missing spec code {r}");
        }
    }

    #[test]
    fn success_codes_exit_zero_and_errors_do_not() {
        for code in Code::all() {
            assert_eq!(
                code.is_success(),
                code.exit_code() == ExitCode::Success,
                "{code}"
            );
        }
    }

    #[test]
    fn outcome_unknown_is_never_retryable_or_not_applied() {
        assert!(!Code::OutcomeUnknown.retryable());
        assert_eq!(
            Code::OutcomeUnknown.default_effect_status(),
            EffectStatus::Unknown
        );
    }
}
