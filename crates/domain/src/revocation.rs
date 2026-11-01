//! Revocation tombstones and results (spec §6.7; R-AU-04; plan §6.3 property 3).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DestinationId, GrantId};
use serde::{Deserialize, Serialize};

use crate::policy::AuthorityGeneration;

/// A remote effect that is not yet acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEffect {
    /// Destination concerned.
    pub destination: DestinationId,
    /// Grant concerned.
    pub grant: GrantId,
    /// Latest instant an already-issued credential may still be accepted there.
    pub latest_possible_credential_expiry: Option<Timestamp>,
}

/// Why a grant was revoked (ADR-0006 §13.8 item 4). Additive: a record written
/// before the field existed reads as [`RevocationCause::Revoke`], the only cause
/// there was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevocationCause {
    /// An explicit `revoke` (the owner, or a caller holding a binding on the grant).
    #[default]
    Revoke,
    /// Re-validation found the grant's authority withdrawn: a revoke on its chain,
    /// a narrowing outside its approval, or a removed environment permission.
    AuthorityWithdrawn,
}

/// Persisted before local success is acknowledged. Invalidates approval races,
/// renewals and retries against the previous generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// Revoked grant.
    pub grant: GrantId,
    /// Descendants revoked by cascade.
    pub cascade: Vec<GrantId>,
    /// Generation after this revocation.
    pub generation: AuthorityGeneration,
    /// When applied locally.
    pub revoked_at: Timestamp,
    /// Remote effects still pending.
    pub remote_pending: Vec<RemoteEffect>,
    /// ⟨r2.5⟩ Why (ADR-0006 §13.8 item 4); `revoke` when absent from the record.
    #[serde(default)]
    pub cause: RevocationCause,
}

/// Whether an action authorized at `authorized_generation` may still proceed
/// against the current generation. Stale callbacks fail closed.
#[must_use]
pub fn generation_still_valid(
    authorized_generation: AuthorityGeneration,
    current: AuthorityGeneration,
) -> bool {
    authorized_generation == current
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_record_without_a_cause_reads_as_an_explicit_revoke() {
        let old = serde_json::json!({
            "grant": GrantId::from_random_bytes([1; 16]),
            "cascade": [],
            "generation": 3,
            "revoked_at": "2026-10-02T09:00:00Z",
            "remote_pending": [],
        });
        let t: Tombstone = serde_json::from_value(old).unwrap();
        assert_eq!(t.cause, RevocationCause::Revoke);
        let withdrawn = Tombstone {
            cause: RevocationCause::AuthorityWithdrawn,
            ..t
        };
        let v = serde_json::to_value(&withdrawn).unwrap();
        assert_eq!(v["cause"], "authority_withdrawn");
        assert_eq!(serde_json::from_value::<Tombstone>(v).unwrap(), withdrawn);
    }

    #[test]
    fn stale_generation_fails_closed() {
        let g1 = AuthorityGeneration(1);
        assert!(generation_still_valid(g1, g1));
        assert!(!generation_still_valid(g1, g1.next()));
    }
}
