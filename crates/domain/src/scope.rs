//! Access scope: destination/account pairs plus capabilities (spec §4.1 "Access
//! relationship", §6.2 "effective set is the intersection").

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub use heimdall_contract::request::{AccessPairRef as AccessPair, Capability};

/// A set of destination/account pairs and the capabilities permitted on them.
/// Explicit sets and well-defined intersection, no policy language (plan §4.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope {
    /// Destination/account pairs.
    pub pairs: BTreeSet<AccessPair>,
    /// Capabilities permitted on every pair.
    pub capabilities: BTreeSet<Capability>,
}

impl Scope {
    /// Empty scope (no access).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether nothing is permitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty() || self.capabilities.is_empty()
    }

    /// Set intersection on pairs and on capabilities.
    #[must_use]
    pub fn intersect(&self, other: &Scope) -> Scope {
        Scope {
            pairs: self.pairs.intersection(&other.pairs).cloned().collect(),
            capabilities: self
                .capabilities
                .intersection(&other.capabilities)
                .copied()
                .collect(),
        }
    }

    /// `self ⊆ other` on both components.
    #[must_use]
    pub fn is_subset_of(&self, other: &Scope) -> bool {
        self.pairs.is_subset(&other.pairs) && self.capabilities.is_subset(&other.capabilities)
    }

    /// The part of `self` that `other` does not permit (the authority delta a new
    /// request would need; spec §5.3 "only the added authority requires a decision").
    #[must_use]
    pub fn difference(&self, other: &Scope) -> Scope {
        Scope {
            pairs: self.pairs.difference(&other.pairs).cloned().collect(),
            capabilities: self
                .capabilities
                .difference(&other.capabilities)
                .copied()
                .collect(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::ids::{AccountName, DestinationId};

    fn pair(d: &str, a: &str) -> AccessPair {
        AccessPair {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse(a).unwrap(),
        }
    }

    #[test]
    fn intersection_never_widens() {
        let a = Scope {
            pairs: [pair("h1", "u"), pair("h2", "u")].into_iter().collect(),
            capabilities: [Capability::SshAuthentication, Capability::GitSigning]
                .into_iter()
                .collect(),
        };
        let b = Scope {
            pairs: [pair("h2", "u"), pair("h3", "u")].into_iter().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        };
        let i = a.intersect(&b);
        assert!(i.is_subset_of(&a) && i.is_subset_of(&b));
        assert_eq!(i.pairs.len(), 1);
        assert_eq!(i.capabilities.len(), 1);
        assert!(a.intersect(&Scope::empty()).is_empty());
    }
}
