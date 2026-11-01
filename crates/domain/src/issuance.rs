//! Issuance substrate (ADR-0005 §3.5, §12; review F06). Pure records and the
//! refusal predicates. Cryptography and the issuer endpoint's protocol are M03; the
//! transactional reserve/publish/void methods are `heimdall_store::Txn`.
//!
//! Protocol summary: **reserve** (one transaction: run every predicate, write the
//! entry `reserved` with its complete bounds) → **sign** outside the transaction →
//! **publish** (second transaction: re-run **every** predicate with current time,
//! then `published`; else `voided` and nothing is released). A `reserved` entry
//! found after a crash stays counted in the residual until its `valid_before`
//! passes and is never published; recovery reserves afresh.

use std::collections::BTreeSet;

use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{CredentialInstanceId, GrantId, IssuanceId};
use serde::{Deserialize, Serialize};

use crate::grant::GrantSnapshot;
use crate::policy::{AuthorityGeneration, StandingPolicy};
use crate::scope::AccessPair;
use crate::time::TimeStatus;

/// Issuance-log states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    /// Bounds committed; nothing signed yet, or signed but not yet published.
    /// Counted in the residual.
    Reserved,
    /// Released to a signer. Counted in the residual.
    Published,
    /// Never released; excluded from the residual.
    Voided,
}

/// Complete certificate bounds recorded at reservation (ADR-0005 §3.5 step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateBounds {
    /// Random serial.
    pub serial: u64,
    /// Key ID string embedded in the certificate.
    pub key_id: String,
    /// The single principal (`hm:<destination>:<account>`), ADR-0005 §3.3.
    pub principal: String,
    /// Validity start.
    pub valid_after: Timestamp,
    /// Validity end; never later than `min(deadline, cutoff, parent deadline)`.
    pub valid_before: Timestamp,
    /// Extensions requested (critical options are refused outright).
    pub extensions: BTreeSet<String>,
    /// Fingerprint of the subject (working) key.
    pub subject_fingerprint: String,
}

/// Why issuance is refused (ADR-0005 §3.5 refusal list, same for reserve and publish).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum IssuanceRefusal {
    /// Grant not `preparing`/`active`/`degraded`.
    #[error("grant state {0:?} does not permit issuance")]
    GrantNotIssuable(GrantState),
    /// Generation, ancestor or policy revision moved.
    #[error("authority generation is stale")]
    StaleGeneration,
    /// Tombstone for the grant or an ancestor.
    #[error("grant or ancestor is revoked")]
    Tombstoned,
    /// Pair outside the grant's resolved snapshot.
    #[error("pair is outside the grant snapshot")]
    PairOutsideSnapshot,
    /// Child pair not a subset of the parent's.
    #[error("child pair exceeds parent")]
    ChildExceedsParent,
    /// `valid_before` later than the bound.
    #[error("requested validity exceeds the bound")]
    BoundTooLate,
    /// The bound has already passed.
    #[error("the bound has passed")]
    BoundPassed,
    /// New activation under a paused policy.
    #[error("policy is paused")]
    PausedActivation,
    /// After a cutoff.
    #[error("policy cutoff passed")]
    CutoffPassed,
    /// Subject key not registered by this environment's signer for the grant.
    #[error("subject key is not registered for this grant")]
    UnknownSubjectKey,
    /// A critical option or an extension outside the grant's permissions.
    #[error("critical option or unpermitted extension requested")]
    CriticalOption,
    /// Time gate not `Safe`.
    #[error("time is uncertain")]
    TimeUncertain,
}

/// One issuance-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceEntry {
    /// ID.
    pub id: IssuanceId,
    /// Grant.
    pub grant: GrantId,
    /// Authority generation at reservation.
    pub generation: AuthorityGeneration,
    /// Pair covered.
    pub pair: AccessPair,
    /// Bounds.
    pub bounds: CertificateBounds,
    /// State.
    pub state: IssuanceState,
    /// Reserved at.
    pub reserved_at: Timestamp,
    /// Published or voided at.
    pub settled_at: Option<Timestamp>,
    /// Why voided, when voided.
    pub void_reason: Option<IssuanceRefusal>,
}

/// Credential instance: a key handle plus per-pair certificates (ADR-0005 §12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialInstance {
    /// ID.
    pub id: CredentialInstanceId,
    /// Grant.
    pub grant: GrantId,
    /// Opaque reference to the protected working key (never the material).
    pub key_handle_ref: String,
    /// Issuance entries (one per pair) attached to this key.
    pub certificates: Vec<IssuanceId>,
    /// State.
    pub state: CredentialState,
}

/// Credential instance lifecycle (ADR-0005 §3.6 "at grant end ... destroys").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    /// Key generated, certificates pending.
    Pending,
    /// Installed in the signer.
    Installed,
    /// Key destroyed and certificates dropped.
    Destroyed,
}

/// Everything the predicates look at; built inside the reserve or publish
/// transaction from current store state and the time gate.
#[derive(Debug, Clone)]
pub struct IssuanceCheck<'a> {
    /// The grant.
    pub grant: &'a GrantSnapshot,
    /// Parent, for a delegated grant.
    pub parent: Option<&'a GrantSnapshot>,
    /// Applicable policy, if any.
    pub policy: Option<&'a StandingPolicy>,
    /// Current authority generation.
    pub current_generation: AuthorityGeneration,
    /// Tombstone exists for the grant or an ancestor.
    pub tombstoned: bool,
    /// Requested pair.
    pub pair: &'a AccessPair,
    /// Requested bounds.
    pub bounds: &'a CertificateBounds,
    /// Whether this issuance activates a new grant (pause applies) rather than
    /// re-issuing for an existing one.
    pub new_activation: bool,
    /// Subject key is registered by this environment's signer for the grant.
    pub subject_registered: bool,
    /// Critical option requested.
    pub critical_option: bool,
    /// Time gate result.
    pub time: TimeStatus,
    /// Now.
    pub now: Timestamp,
}

/// ADR-0005 §3.5 refusal list, in order. Applied identically at reserve and at
/// publish (with the then-current store state and time).
pub fn check(input: &IssuanceCheck<'_>) -> Result<(), IssuanceRefusal> {
    if !input.grant.state.permits_issuance() {
        return Err(IssuanceRefusal::GrantNotIssuable(input.grant.state));
    }
    if input.grant.generation != input.current_generation {
        return Err(IssuanceRefusal::StaleGeneration);
    }
    if input.tombstoned {
        return Err(IssuanceRefusal::Tombstoned);
    }
    if !input.grant.scope.pairs.contains(input.pair) {
        return Err(IssuanceRefusal::PairOutsideSnapshot);
    }
    if let Some(parent) = input.parent
        && !parent.scope.pairs.contains(input.pair)
    {
        return Err(IssuanceRefusal::ChildExceedsParent);
    }
    let mut bound = input.grant.deadline.effective;
    if let Some(parent) = input.parent {
        bound = bound.min(parent.deadline.effective);
    }
    if let Some(policy) = input.policy {
        if let Some(cutoff) = policy.cutoff_at {
            bound = bound.min(cutoff);
            if input.now >= cutoff {
                return Err(IssuanceRefusal::CutoffPassed);
            }
        }
        if input.new_activation && policy.blocks_activation_at(input.now).is_some() {
            return Err(IssuanceRefusal::PausedActivation);
        }
    }
    if input.now >= bound {
        return Err(IssuanceRefusal::BoundPassed);
    }
    if input.bounds.valid_before > bound {
        return Err(IssuanceRefusal::BoundTooLate);
    }
    if !input.subject_registered {
        return Err(IssuanceRefusal::UnknownSubjectKey);
    }
    if input.critical_option {
        return Err(IssuanceRefusal::CriticalOption);
    }
    if input.time != TimeStatus::Safe {
        return Err(IssuanceRefusal::TimeUncertain);
    }
    Ok(())
}

/// `latest_possible_credential_expiry` (spec §6.7; ADR-0005 §3.5): the latest
/// `valid_before` among `reserved` and `published` entries, whether or not delivery
/// was acknowledged. Only `voided` entries are excluded.
#[must_use]
pub fn residual(entries: &[IssuanceEntry]) -> Option<Timestamp> {
    entries
        .iter()
        .filter(|e| matches!(e.state, IssuanceState::Reserved | IssuanceState::Published))
        .map(|e| e.bounds.valid_before)
        .max()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(state: IssuanceState, before: &str) -> IssuanceEntry {
        IssuanceEntry {
            id: IssuanceId::from_random_bytes([1; 16]),
            grant: GrantId::from_random_bytes([2; 16]),
            generation: AuthorityGeneration(1),
            pair: AccessPair {
                destination: heimdall_contract::ids::DestinationId::parse("h").unwrap(),
                account: heimdall_contract::ids::AccountName::parse("u").unwrap(),
            },
            bounds: CertificateBounds {
                serial: 1,
                key_id: "k".into(),
                principal: "hm:h:u".into(),
                valid_after: "2026-10-02T00:00:00Z".parse().unwrap(),
                valid_before: before.parse().unwrap(),
                extensions: BTreeSet::new(),
                subject_fingerprint: "fp".into(),
            },
            state,
            reserved_at: "2026-10-02T00:00:00Z".parse().unwrap(),
            settled_at: None,
            void_reason: None,
        }
    }

    #[test]
    fn residual_counts_reserved_and_published_only() {
        let es = [
            entry(IssuanceState::Voided, "2026-10-02T09:00:00Z"),
            entry(IssuanceState::Reserved, "2026-10-02T06:00:00Z"),
            entry(IssuanceState::Published, "2026-10-02T05:00:00Z"),
        ];
        assert_eq!(residual(&es), Some("2026-10-02T06:00:00Z".parse().unwrap()));
        assert_eq!(residual(&es[..1]), None);
    }
}
