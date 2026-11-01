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
use heimdall_contract::catalog::DeclaredInteraction;
use heimdall_contract::ids::{DecisionId, IdentityId, OperationId};
use heimdall_contract::provider::EndpointRef;
use heimdall_contract::request::{PolicyAction, Verdict};
use heimdall_contract::setup::PlanDigest;
use serde::{Deserialize, Serialize};

use crate::authority::AuthorityDelta;
use crate::policy::AuthorityGeneration;
use crate::projection::ProjectionSummary;
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
    /// ⟨M02⟩ Apply a projection change whose effect needs the owner (ADR-0007 §5.2;
    /// Q1; m02-plan §5 item 17). Approval writes a `ProjectionApproval` into the
    /// waiting operation's `SetupIntent`, only when `plan_digest` equals the
    /// intent's; it carries no `AuthorityDelta`.
    ApplyProjection {
        /// The setup operation waiting in `awaiting_approval`.
        operation: OperationId,
        /// The plan the owner is shown and approves.
        plan_digest: PlanDigest,
        /// What the plan changes: the before, after and restore columns.
        summary: ProjectionSummary,
    },
    /// ⟨M02⟩ Declare that an identity needs no interaction (ADR-0007 §7; QR1).
    /// Approval copies these fields into the waiting catalog intent's
    /// `DeclarationApproval`, from which alone the declaration is built.
    DeclareInteraction {
        /// The catalog operation waiting in `awaiting_approval`.
        operation: OperationId,
        /// The identity.
        identity: IdentityId,
        /// Its public-key fingerprint when the decision was created.
        fingerprint: String,
        /// The endpoint the declaration covers.
        endpoint: EndpointRef,
        /// The declared interaction.
        interaction: DeclaredInteraction,
        /// When the declaration will lapse (`expires_at`).
        valid_until: Timestamp,
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

    fn round_trip(kind: &DecisionKind, golden: &str) {
        assert_eq!(serde_json::to_string(kind).unwrap(), golden);
        let back: DecisionKind = serde_json::from_str(golden).unwrap();
        assert_eq!(&back, kind);
        assert_eq!(serde_json::to_string(&back).unwrap(), golden);
    }

    /// m02-plan U0 `decision_kind_wire_forms`: the two M02 kinds.
    #[test]
    fn decision_kind_wire_forms() {
        use crate::projection::{ItemId, ItemRestore, ProjectionSummary, Sha256Hex, SummaryIntent};
        use heimdall_contract::provider::{EndpointKind, EndpointRef};

        let digest = Sha256Hex::of(b"restore");
        let apply = DecisionKind::ApplyProjection {
            operation: OperationId::from_random_bytes([1; 16]),
            plan_digest: PlanDigest::from_sha256([0xab; 32]),
            summary: ProjectionSummary {
                intent: SummaryIntent::Apply,
                added_aliases: vec!["work".into()],
                changed_aliases: Vec::new(),
                removed_aliases: Vec::new(),
                files: vec!["ssh/config".into(), "ssh/heimdall.conf".into()],
                git: false,
                restore: vec![ItemRestore {
                    item: ItemId::alias("work"),
                    digest: digest.clone(),
                }],
                diff_text: "+Host work\n".into(),
            },
        };
        round_trip(
            &apply,
            &format!(
                concat!(
                    r#"{{"kind":"apply_projection","operation":"op_01010101010101010101010101010101","#,
                    r#""plan_digest":"{pd}","summary":{{"intent":"apply","added_aliases":["work"],"#,
                    r#""changed_aliases":[],"removed_aliases":[],"files":["ssh/config","ssh/heimdall.conf"],"#,
                    r#""git":false,"restore":[{{"item":"alias:work","digest":"{d}"}}],"diff_text":"+Host work\n"}}}}"#
                ),
                pd = "ab".repeat(32),
                d = digest
            ),
        );
        let declare = DecisionKind::DeclareInteraction {
            operation: OperationId::from_random_bytes([2; 16]),
            identity: IdentityId::from_random_bytes([3; 16]),
            fingerprint: "SHA256:fixturefingerprint".into(),
            endpoint: EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: "/scratch/agent.sock".into(),
            },
            interaction: DeclaredInteraction::None,
            valid_until: "2026-12-01T00:00:00Z".parse().unwrap(),
        };
        round_trip(
            &declare,
            concat!(
                r#"{"kind":"declare_interaction","operation":"op_02020202020202020202020202020202","#,
                r#""identity":"idn_03030303030303030303030303030303","fingerprint":"SHA256:fixturefingerprint","#,
                r#""endpoint":{"kind":"unix_socket","locator":"/scratch/agent.sock"},"interaction":"none","#,
                r#""valid_until":"2026-12-01T00:00:00Z"}"#
            ),
        );
        // The M01 kinds keep their forms.
        round_trip(
            &DecisionKind::ConfirmTime {
                boot_id: BootId("boot-a".into()),
                observed_wall: "2026-10-02T00:00:00Z".parse().unwrap(),
            },
            r#"{"kind":"confirm_time","boot_id":"boot-a","observed_wall":"2026-10-02T00:00:00Z"}"#,
        );
        assert!(serde_json::from_str::<DecisionKind>(r#"{"kind":"local_approval"}"#).is_err());
        assert!(apply_summary_bounded(&apply));
    }

    fn apply_summary_bounded(kind: &DecisionKind) -> bool {
        match kind {
            DecisionKind::ApplyProjection { summary, .. } => summary.within_bounds(),
            _ => false,
        }
    }
}
