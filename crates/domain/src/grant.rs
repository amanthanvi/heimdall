//! Grants: immutable scope/deadline snapshots (spec §4.1 "Grant", §6.1, §6.7;
//! plan §4.3).

use heimdall_contract::ids::{BindingId, EnvironmentId, GrantId, OperationId, ProfileId};
use heimdall_contract::{GrantState, Timestamp};
use serde::{Deserialize, Serialize};

use crate::evidence::EnforcementEvidence;
use crate::operation::{AdapterIdentity, CoveredBasis};
use crate::policy::{AuthorityGeneration, ConnectionPolicy, LockBehavior, PolicyRevision};
use crate::principal::CallerContext;
use crate::scope::Scope;
use crate::time::Deadline;

/// Where the grant's authorization came from (spec §4.1 "source of authorization").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationSource {
    /// Standing policy at a revision.
    StandingPolicy {
        /// Revision.
        revision: PolicyRevision,
    },
    /// Owner decision recorded for this operation.
    OwnerDecision {
        /// Operation carrying the decision.
        operation_id: OperationId,
    },
    /// Delegated from a parent grant.
    Delegation {
        /// Parent.
        parent: GrantId,
    },
}

/// Immutable grant snapshot. Renewal maintains it; nothing extends `deadline` or
/// adds pairs (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSnapshot {
    /// Grant ID.
    pub id: GrantId,
    /// Environment pinned.
    pub environment: EnvironmentId,
    /// Effective scope at authorization.
    pub scope: Scope,
    /// Start.
    pub starts_at: Timestamp,
    /// Immutable maximum deadline.
    pub deadline: Deadline,
    /// Parent for delegation; cascades expiry/revocation/cutoff.
    pub parent: Option<GrantId>,
    /// Authorization provenance.
    pub source: AuthorizationSource,
    /// Authority generation at authorization; rechecked before activation and
    /// before every issuance (R-SE-07).
    pub generation: AuthorityGeneration,
    /// Current state.
    pub state: GrantState,
    /// Enforcement evidence recorded with the grant.
    pub enforcement: EnforcementEvidence,
}

/// ⟨r2.6⟩ Where a grant's authority was resolved, persisted **with the grant**
/// (ADR-0006 §13.9 item 2; `heimdall_store::Txn::{set_grant_origin, grant_origin}`).
///
/// Together with the snapshot (scope, deadline, environment, parent, source) and
/// the approval basis persisted with the grant, it is the whole context
/// re-validation needs (§13.5 ruling 2): no consumer binding and no operation
/// record plays a part, so a parent kept alive only by its delegated child's
/// reference (§13.5 ruling 1) re-validates like any other grant. Written once when
/// the grant is created; operation retention never touches it. A grant without a
/// recorded origin is the only case whose re-validation is undetermined (refuse
/// the use, end nothing).
///
/// Add-only afterwards (`heimdall_store::Txn::set_grant_origin`): each optional
/// field ([`Self::covered`], ⟨r2.10⟩ [`Self::adapter`]) may be recorded once when
/// absent and is then immutable; every other field never changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantOrigin {
    /// Profile pinned at resolution.
    pub profile: ProfileId,
    /// Profile revision pinned at resolution.
    pub profile_revision: u64,
    /// Applicable standing-policy revision at resolution, if any.
    pub policy_revision: Option<PolicyRevision>,
    /// The caller the authority was resolved for (its role bounds what
    /// re-resolution may accept).
    pub caller: CallerContext,
    /// Credential mechanism selected at resolution. ⟨r2.7⟩ Every use of the grant
    /// checks that it is still configured; while it is not, the use is refused and
    /// the grant is `degraded` ([`DegradedReason::MechanismUnavailable`]; ADR-0006
    /// §13.10 item 2). Re-validation of authority does not depend on it.
    pub mechanism: String,
    /// ADR-0006 §13.7 item 2: the standing policy this waiting owner-decision grant
    /// came to rest on when the saved policy covered it entirely. Absent otherwise;
    /// add-only (recorded once, never replaced or cleared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered: Option<CoveredBasis>,
    /// ⟨r2.10⟩ ADR-0006 §13.13 item 1: the full identity (mechanism **and**
    /// instance) of the adapter that prepared the grant, recorded in the transaction
    /// that writes the grant's first `Attempted` receipt, then immutable. It is the
    /// grant's responsible adapter for every later remote revocation obligation, so
    /// operation retention (which purges recovery intents and stage receipts) cannot
    /// remove it. Absent for a grant written before the field existed, and for one
    /// whose preparation was never attempted; omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterIdentity>,
    /// ⟨M03⟩ U0b row 10: the lock behaviour in force when the grant was created
    /// (ADR-0008 D9), recorded once and then immutable (add-only). Absent for an
    /// M01/M02 grant; omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_behavior: Option<LockBehavior>,
    /// ⟨M03⟩ U0b row 10: the connection policy recorded at activation (ADR-0008 D8
    /// item 1: one input of the effective, strictest policy). Add-only; omitted when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionPolicy>,
}

/// ⟨r2.7⟩ Why a `degraded` grant is degraded (spec §6.3 "some capability
/// unavailable"; ADR-0006 §13.10 item 2; `heimdall_store::Txn::{set_grant_degradation,
/// grant_degradation}`). Additive: new reasons may follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DegradedReason {
    /// The credential mechanism recorded in the grant's origin is not configured in
    /// this runtime. Every use is refused and nothing ends (an owner's configuration
    /// change can be undone before the deadline); the grant returns to `active` once
    /// the mechanism is configured again and re-validation passes.
    MechanismUnavailable,
    /// ⟨M03⟩ The grant's K_env was lost (no vault slot after a restart) and a
    /// re-issue is pending (ADR-0008 D2 table; U0b row 8). There is no key to sign
    /// with.
    CredentialReissuePending,
    /// ⟨M03⟩ The issuer is unavailable: no new certificate can be issued, but an
    /// installed key and its certificates keep signing (ADR-0008 D2 item 3).
    IssuerUnavailable,
    /// ⟨M03⟩ A pair lost its verified enrollment under the grant's CA (ADR-0008 D5
    /// §6.8, §17.3 item 3). The installed key keeps signing: the server refuses that
    /// pair itself, and the other pairs keep working.
    PairUnenrolled,
}

/// ⟨M03⟩ What a degraded grant's reason means for a signature (ADR-0008 D2 item 3;
/// U0b row 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DegradedSignRule {
    /// Signing with the installed key is permitted.
    Permit,
    /// There is no key to sign with (refused).
    NoKey,
    /// Every use is refused.
    Refuse,
}

impl DegradedReason {
    /// ⟨M03⟩ The sign rule of ADR-0008 D2 item 3 (U0b row 12): `issuer_unavailable`
    /// and `pair_unenrolled` permit signing with an installed key;
    /// `credential_reissue_pending` has no key; `mechanism_unavailable` refuses.
    #[must_use]
    pub fn sign_rule(self) -> DegradedSignRule {
        match self {
            DegradedReason::IssuerUnavailable | DegradedReason::PairUnenrolled => {
                DegradedSignRule::Permit
            }
            DegradedReason::CredentialReissuePending => DegradedSignRule::NoKey,
            DegradedReason::MechanismUnavailable => DegradedSignRule::Refuse,
        }
    }

    /// Whether a signature with an installed key is permitted for this reason.
    #[must_use]
    pub fn permits_signing(self) -> bool {
        self.sign_rule() == DegradedSignRule::Permit
    }
}

/// A consumer reference to a grant (spec §6.3 "ownership-aware reference counts").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantReference {
    /// Binding holding the reference.
    pub binding: BindingId,
    /// Grant referenced.
    pub grant: GrantId,
    /// When acquired.
    pub acquired_at: Timestamp,
}

impl GrantSnapshot {
    /// Whether `child_scope`/`child_deadline` would be a valid delegation from this
    /// grant (plan §6.3 property 2). Pure.
    #[must_use]
    pub fn permits_child(&self, child_scope: &Scope, child_deadline: Timestamp) -> bool {
        child_scope.is_subset_of(&self.scope) && child_deadline <= self.deadline.effective
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn degraded_reason_wire_form_is_snake_case() {
        let v = serde_json::to_value(DegradedReason::MechanismUnavailable).unwrap();
        assert_eq!(v, serde_json::json!("mechanism_unavailable"));
        assert_eq!(
            serde_json::from_value::<DegradedReason>(v).unwrap(),
            DegradedReason::MechanismUnavailable
        );
    }

    /// ⟨r2.10⟩ ADR-0006 §13.13 item 1: an origin written before the preparing
    /// adapter was recorded reads without it (no migration); the field round-trips
    /// with mechanism and instance and is omitted when absent.
    #[test]
    fn an_origin_without_its_preparing_adapter_reads_unchanged() {
        let old = serde_json::json!({
            "profile": "dev",
            "profile_revision": 1,
            "policy_revision": 1,
            "caller": {"principal": {"kind": "unix_user", "uid": 501}, "role": "owner"},
            "mechanism": "fake_agent",
        });
        let o: GrantOrigin = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(o.adapter, None);
        assert_eq!(
            serde_json::to_value(&o).unwrap(),
            old,
            "omitted when absent"
        );
        let with = GrantOrigin {
            adapter: Some(AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            }),
            ..o
        };
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(v["adapter"]["mechanism"], "fake_agent");
        assert_eq!(v["adapter"]["instance"], "fixture-1");
        assert_eq!(serde_json::from_value::<GrantOrigin>(v).unwrap(), with);
    }

    #[test]
    fn degraded_reason_sign_rule() {
        use DegradedReason as D;
        assert_eq!(
            D::MechanismUnavailable.sign_rule(),
            DegradedSignRule::Refuse
        );
        assert_eq!(
            D::CredentialReissuePending.sign_rule(),
            DegradedSignRule::NoKey
        );
        assert!(D::IssuerUnavailable.permits_signing());
        assert!(D::PairUnenrolled.permits_signing());
        assert_eq!(
            serde_json::to_value(D::PairUnenrolled).unwrap(),
            serde_json::json!("pair_unenrolled")
        );
    }
}
