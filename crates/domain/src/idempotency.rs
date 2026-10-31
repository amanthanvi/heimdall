//! Idempotency identity, canonical request hash and retention (spec §11.4;
//! primitives-draft §5; ADR-0006 §7; plan §6.3 property 4).

use std::collections::BTreeSet;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::canonical::{CanonicalError, RequestHash, request_hash};
use heimdall_contract::ids::{BindingId, EnvironmentId, OperationId, ProfileId, RequestId, WorkId};
use heimdall_contract::request::{AccessPairRef, DeadlineIntent, RequiredCapabilities};
use serde::{Deserialize, Serialize};

use crate::operation::OperationKind;
use crate::principal::CallerContext;

/// Default retention of idempotency records after the operation reaches a
/// terminal state (spec §13.6 draft default; ADR-0006 §7.4).
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Retention floor below which configuration may not go.
pub const MIN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// `(authenticated caller context, operation kind, request ID)`. Keys are
/// namespaced by principal, so the same `request_id` from another owner is a
/// different key (spec §14.3 "request-ID collision across owners").
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdempotencyKey {
    /// Caller.
    pub caller: CallerContext,
    /// Kind.
    pub kind: OperationKind,
    /// Request ID.
    pub request_id: RequestId,
}

/// The fields that enter the canonical request hash (ADR-0006 §7.2). Delivery
/// preferences (`interaction`, `wait`) are excluded on purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HashInput<'a> {
    /// Environment (resolved to an ID before hashing).
    pub environment: &'a EnvironmentId,
    /// Profile reference.
    pub profile: Option<&'a ProfileId>,
    /// Explicit profile revision if the caller gave one.
    pub profile_revision: Option<u64>,
    /// Scope subset as submitted (sorted set).
    pub scope: &'a BTreeSet<AccessPairRef>,
    /// Deadline intent verbatim (not the resolved instant).
    pub deadline_intent: Option<&'a DeadlineIntent>,
    /// Work ID.
    pub work_id: Option<&'a WorkId>,
    /// Required capabilities.
    pub required_capabilities: &'a RequiredCapabilities,
    /// Parent binding for delegation.
    pub parent_binding: Option<&'a BindingId>,
    /// Kind-specific extra fields (e.g. grant ID for revoke), canonical JSON.
    pub extra: serde_json::Value,
}

/// Compute the canonical request hash for an operation kind.
pub fn compute_hash(
    kind: OperationKind,
    input: &HashInput<'_>,
) -> Result<RequestHash, CanonicalError> {
    let value = serde_json::to_value(input).map_err(|_| CanonicalError::NonFiniteNumber)?;
    request_hash(kind.as_str(), &value)
}

/// Persisted idempotency record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    /// Key.
    pub key: IdempotencyKey,
    /// Hash at first submission.
    pub request_hash: RequestHash,
    /// Operation created for the first submission.
    pub operation_id: OperationId,
    /// Created.
    pub created_at: Timestamp,
    /// After this instant the record may be purged and a retry is `REQUEST_EXPIRED`.
    pub expires_at: Timestamp,
}

/// Classification of an incoming request against the stored record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyOutcome {
    /// No record: create a new operation.
    New,
    /// Same key, same hash: return the existing operation.
    Replay(OperationId),
    /// Same key, different hash: `REQUEST_CONFLICT`.
    Conflict(OperationId),
    /// Record aged out: `REQUEST_EXPIRED`, never silently new.
    Expired,
}

/// Classify a retry. Pure; property tests check convergence and conflict.
#[must_use]
pub fn classify(
    existing: Option<&IdempotencyRecord>,
    hash: RequestHash,
    now: Timestamp,
) -> IdempotencyOutcome {
    match existing {
        None => IdempotencyOutcome::New,
        Some(rec) if now >= rec.expires_at => IdempotencyOutcome::Expired,
        Some(rec) if rec.request_hash == hash => {
            IdempotencyOutcome::Replay(rec.operation_id.clone())
        }
        Some(rec) => IdempotencyOutcome::Conflict(rec.operation_id.clone()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::principal::{ClientRole, PrincipalRef};

    fn rec(hash: RequestHash) -> IdempotencyRecord {
        IdempotencyRecord {
            key: IdempotencyKey {
                caller: CallerContext {
                    principal: PrincipalRef::UnixUser { uid: 501 },
                    role: ClientRole::Owner,
                },
                kind: OperationKind::Ensure,
                request_id: RequestId::parse("req_1").unwrap(),
            },
            request_hash: hash,
            operation_id: OperationId::from_random_bytes([1; 16]),
            created_at: "2026-10-01T00:00:00Z".parse().unwrap(),
            expires_at: "2026-10-08T00:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn same_hash_replays_different_hash_conflicts_old_expires() {
        let h1 = RequestHash([1; 32]);
        let h2 = RequestHash([2; 32]);
        let before: Timestamp = "2026-10-02T00:00:00Z".parse().unwrap();
        let after: Timestamp = "2026-10-09T00:00:00Z".parse().unwrap();
        assert_eq!(classify(None, h1, before), IdempotencyOutcome::New);
        assert!(matches!(
            classify(Some(&rec(h1)), h1, before),
            IdempotencyOutcome::Replay(_)
        ));
        assert!(matches!(
            classify(Some(&rec(h1)), h2, before),
            IdempotencyOutcome::Conflict(_)
        ));
        assert_eq!(
            classify(Some(&rec(h1)), h1, after),
            IdempotencyOutcome::Expired
        );
    }
}
