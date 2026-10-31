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
mod tests {
    use super::*;

    #[test]
    fn stale_generation_fails_closed() {
        let g1 = AuthorityGeneration(1);
        assert!(generation_still_valid(g1, g1));
        assert!(!generation_still_valid(g1, g1.next()));
    }
}
