//! Idempotency identity, canonical request hash, retention and expired-key markers
//! (spec §11.4; primitives-draft §5; ADR-0006 §7; review F02; plan §6.3 #4).
//!
//! Protocol: a key's record is live while its operation is active or unresolved
//! (`expires_at = None`); at settlement the record gets `expires_at = terminal_at +
//! retention`. Purge removes settled operations past `expires_at` **and leaves a
//! compact [`ExpiredKeyMarker`]** (hash of the key, expiry, marker end) for
//! [`MARKER_WINDOW`]. A reused key then returns `REQUEST_EXPIRED`, never a silent
//! new operation; beyond the marker window, reuse of a years-old key is documented
//! caller error (ADR-0006 §7.4).

use std::collections::BTreeSet;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::canonical::{CanonicalError, RequestHash, request_hash};
use heimdall_contract::ids::{BindingId, EnvironmentId, OperationId, ProfileId, RequestId, WorkId};
use heimdall_contract::request::{AccessPairRef, DeadlineIntent, RequiredCapabilities};
use serde::{Deserialize, Serialize};

use crate::operation::OperationKind;
use crate::principal::CallerContext;

/// Default retention of settled operations and their idempotency records after
/// terminal completion (spec §13.6 draft default; ADR-0006 §7.4).
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Retention floor below which configuration may not go.
pub const MIN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
/// How long an expired-key marker outlives the purged record (ADR-0006 §7.4).
pub const MARKER_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

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

/// Stable hash of a key, used as the marker identity after the record is purged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyHash(pub RequestHash);

impl IdempotencyKey {
    /// SHA-256 over the canonical JSON of the key, domain-separated.
    pub fn hash(&self) -> Result<KeyHash, CanonicalError> {
        let value = serde_json::to_value(self).map_err(|_| CanonicalError::NonFiniteNumber)?;
        request_hash("idempotency-key", &value).map(KeyHash)
    }
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
    /// `None` while the operation is active or unresolved (pending keys never
    /// expire); set to `terminal_at + retention` at settlement. After it, the record
    /// may be purged into a marker and a retry is `REQUEST_EXPIRED`.
    pub expires_at: Option<Timestamp>,
}

/// Compact marker left behind when a settled record is purged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpiredKeyMarker {
    /// Hash of the purged key.
    pub key_hash: KeyHash,
    /// When the record expired.
    pub expired_at: Timestamp,
    /// After this instant the marker itself may be purged.
    pub marker_until: Timestamp,
}

/// Expiry instant for a record whose operation settled at `terminal_at`.
#[must_use]
pub fn retention_expiry(terminal_at: Timestamp, retention: Duration) -> Timestamp {
    let span = jiff::SignedDuration::try_from(retention.max(MIN_RETENTION))
        .unwrap_or(jiff::SignedDuration::MAX);
    terminal_at.checked_add(span).unwrap_or(Timestamp::MAX)
}

/// Marker end for a record that expired at `expired_at`.
#[must_use]
pub fn marker_until(expired_at: Timestamp) -> Timestamp {
    let span = jiff::SignedDuration::try_from(MARKER_WINDOW).unwrap_or(jiff::SignedDuration::MAX);
    expired_at.checked_add(span).unwrap_or(Timestamp::MAX)
}

/// Classification of an incoming request against the stored record and marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyOutcome {
    /// No record and no live marker: create a new operation.
    New,
    /// Same key, same hash: return the existing operation.
    Replay(OperationId),
    /// Same key, different hash: `REQUEST_CONFLICT`.
    Conflict(OperationId),
    /// Record aged out or marker on record: `REQUEST_EXPIRED`, never silently new.
    Expired,
}

/// Classify a retry. Pure; property tests check convergence and conflict.
#[must_use]
pub fn classify(
    existing: Option<&IdempotencyRecord>,
    marker: Option<&ExpiredKeyMarker>,
    hash: RequestHash,
    now: Timestamp,
) -> IdempotencyOutcome {
    match existing {
        Some(rec) if rec.expires_at.is_some_and(|e| now >= e) => IdempotencyOutcome::Expired,
        Some(rec) if rec.request_hash == hash => {
            IdempotencyOutcome::Replay(rec.operation_id.clone())
        }
        Some(rec) => IdempotencyOutcome::Conflict(rec.operation_id.clone()),
        None => match marker {
            Some(m) if now < m.marker_until => IdempotencyOutcome::Expired,
            _ => IdempotencyOutcome::New,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::principal::{ClientRole, PrincipalRef};

    fn key() -> IdempotencyKey {
        IdempotencyKey {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
            },
            kind: OperationKind::Ensure,
            request_id: RequestId::parse("req_1").unwrap(),
        }
    }

    fn rec(hash: RequestHash, expires_at: Option<&str>) -> IdempotencyRecord {
        IdempotencyRecord {
            key: key(),
            request_hash: hash,
            operation_id: OperationId::from_random_bytes([1; 16]),
            created_at: "2026-10-01T00:00:00Z".parse().unwrap(),
            expires_at: expires_at.map(|s| s.parse().unwrap()),
        }
    }

    #[test]
    fn same_hash_replays_different_hash_conflicts_old_expires_pending_never() {
        let h1 = RequestHash([1; 32]);
        let h2 = RequestHash([2; 32]);
        let before: Timestamp = "2026-10-02T00:00:00Z".parse().unwrap();
        let after: Timestamp = "2026-10-09T00:00:00Z".parse().unwrap();
        let settled = rec(h1, Some("2026-10-08T00:00:00Z"));
        assert_eq!(classify(None, None, h1, before), IdempotencyOutcome::New);
        assert!(matches!(
            classify(Some(&settled), None, h1, before),
            IdempotencyOutcome::Replay(_)
        ));
        assert!(matches!(
            classify(Some(&settled), None, h2, before),
            IdempotencyOutcome::Conflict(_)
        ));
        assert_eq!(
            classify(Some(&settled), None, h1, after),
            IdempotencyOutcome::Expired
        );
        let pending = rec(h1, None);
        let far: Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
        assert!(matches!(
            classify(Some(&pending), None, h1, far),
            IdempotencyOutcome::Replay(_)
        ));
    }

    #[test]
    fn marker_keeps_expired_keys_expired_for_the_window() {
        let h = RequestHash([3; 32]);
        let expired_at: Timestamp = "2026-10-08T00:00:00Z".parse().unwrap();
        let m = ExpiredKeyMarker {
            key_hash: key().hash().unwrap(),
            expired_at,
            marker_until: marker_until(expired_at),
        };
        let inside: Timestamp = "2026-10-20T00:00:00Z".parse().unwrap();
        let outside: Timestamp = "2026-12-01T00:00:00Z".parse().unwrap();
        assert_eq!(
            classify(None, Some(&m), h, inside),
            IdempotencyOutcome::Expired
        );
        assert_eq!(
            classify(None, Some(&m), h, outside),
            IdempotencyOutcome::New
        );
        assert!(retention_expiry(expired_at, Duration::from_secs(1)) > expired_at);
    }
}
