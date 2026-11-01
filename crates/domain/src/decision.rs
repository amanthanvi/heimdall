//! Server-issued decision records (ADR-0006 §3.1; review F03; spec §11.3 "a
//! separately authorized UI can present the decision", R-SE-02).
//!
//! A decision is created by the runtime (never by a client) when added authority,
//! a widening policy action, or a time confirmation needs an owner present. It
//! records the exact delta and the authority generation it was issued under. It is
//! completed **once**, only through an attended control session, and only while
//! the generation is unchanged; otherwise it is stale. Request content never
//! becomes consent: the verdict applies exactly the recorded delta, nothing wider.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DecisionId, OperationId};
use heimdall_contract::request::{PolicyAction, Verdict};
use serde::{Deserialize, Serialize};

use crate::authority::AuthorityDelta;
use crate::policy::AuthorityGeneration;
use crate::time::BootId;

/// What the owner is asked to decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecisionKind {
    /// Approve the exact added authority an operation needs (spec §5.3).
    ApproveAuthority {
        /// Operation waiting in `awaiting_approval`.
        operation: OperationId,
        /// Exactly what would be added; nothing else is granted on approval.
        delta: AuthorityDelta,
    },
    /// Perform a widening policy action (`resume`, `clear_cutoff`).
    WidenPolicy {
        /// The action, verbatim.
        action: PolicyAction,
    },
    /// Accept the runtime's current wall time for this boot (ADR-0005 §3.6).
    ConfirmTime {
        /// Boot the confirmation applies to.
        boot_id: BootId,
        /// Wall time observed by the runtime when the record was created.
        observed_wall: Timestamp,
    },
}

/// Lifecycle of a decision record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    /// Awaiting an attended verdict.
    Pending,
    /// Approved and applied (consumed).
    Approved,
    /// Denied (consumed).
    Denied,
    /// Aged out without a verdict.
    Expired,
    /// Invalidated because the authority generation moved (revocation, pause,
    /// cutoff, narrowing) after issuance.
    Stale,
    /// ⟨r2.4⟩ Withdrawn by the runtime without a verdict because no request awaits
    /// it any more: every request sharing it was cancelled, or the owner's saved
    /// standing policy came to cover the request entirely (ADR-0006 §13.7 items 2
    /// and 4). Never completable.
    Withdrawn,
}

/// The durable record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// ID (nonsecret reference carried as `next.decision_ref`).
    pub id: DecisionId,
    /// What is decided.
    pub kind: DecisionKind,
    /// Authority generation at issuance; completion requires equality.
    pub generation: AuthorityGeneration,
    /// Created.
    pub created_at: Timestamp,
    /// After this instant the record cannot be completed.
    pub expires_at: Timestamp,
    /// State.
    pub state: DecisionState,
    /// When a verdict was recorded.
    pub decided_at: Option<Timestamp>,
}

/// Why completion was refused (maps to `DECISION_STALE`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionRefusal {
    /// Already consumed, expired or stale.
    #[error("decision is {0:?}, not pending")]
    NotPending(DecisionState),
    /// Aged out.
    #[error("decision expired")]
    Expired,
    /// Authority generation moved since issuance.
    #[error("decision generation {issued:?} is stale; current is {current:?}")]
    StaleGeneration {
        /// Generation at issuance.
        issued: AuthorityGeneration,
        /// Current generation.
        current: AuthorityGeneration,
    },
}

/// Pure completion rule: the state the record moves to for `verdict` at `now`
/// under `current` generation, or the refusal. Consume-once: a non-`Pending`
/// record is refused; a stale generation is refused even for `Deny`.
pub fn complete(
    record: &DecisionRecord,
    verdict: Verdict,
    current: AuthorityGeneration,
    now: Timestamp,
) -> Result<DecisionState, DecisionRefusal> {
    if record.state != DecisionState::Pending {
        return Err(DecisionRefusal::NotPending(record.state));
    }
    if now >= record.expires_at {
        return Err(DecisionRefusal::Expired);
    }
    if record.generation != current {
        return Err(DecisionRefusal::StaleGeneration {
            issued: record.generation,
            current,
        });
    }
    Ok(match verdict {
        Verdict::Approve => DecisionState::Approved,
        Verdict::Deny => DecisionState::Denied,
    })
}

/// Default lifetime of a pending decision.
pub const DEFAULT_DECISION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(15 * 60);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn rec(state: DecisionState, generation: u64) -> DecisionRecord {
        DecisionRecord {
            id: DecisionId::from_random_bytes([9; 16]),
            kind: DecisionKind::WidenPolicy {
                action: PolicyAction::Resume {
                    policy_id: heimdall_contract::ids::PolicyId::parse("p").unwrap(),
                },
            },
            generation: AuthorityGeneration(generation),
            created_at: "2026-10-02T00:00:00Z".parse().unwrap(),
            expires_at: "2026-10-02T00:15:00Z".parse().unwrap(),
            state,
            decided_at: None,
        }
    }

    #[test]
    fn consume_once_and_stale_generation_refused() {
        let now: Timestamp = "2026-10-02T00:01:00Z".parse().unwrap();
        let pending = rec(DecisionState::Pending, 3);
        assert_eq!(
            complete(&pending, Verdict::Approve, AuthorityGeneration(3), now),
            Ok(DecisionState::Approved)
        );
        assert!(matches!(
            complete(&pending, Verdict::Deny, AuthorityGeneration(4), now),
            Err(DecisionRefusal::StaleGeneration { .. })
        ));
        let done = rec(DecisionState::Approved, 3);
        assert!(matches!(
            complete(&done, Verdict::Approve, AuthorityGeneration(3), now),
            Err(DecisionRefusal::NotPending(DecisionState::Approved))
        ));
        let late: Timestamp = "2026-10-02T00:15:00Z".parse().unwrap();
        assert_eq!(
            complete(&pending, Verdict::Approve, AuthorityGeneration(3), late),
            Err(DecisionRefusal::Expired)
        );
    }
}
