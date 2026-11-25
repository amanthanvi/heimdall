//! ⟨rev7⟩ The access subjects of `inspect`: `grants`, `bindings` and `decisions` (ADR-0013
//! §11 D1, D9, D17).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{PreviewView, ScopeView, is_false};
use crate::Timestamp;
use crate::decision::LiftedEffect;
use crate::ids::{BindingId, DecisionId, GrantId, ProfileId, RequestId, WorkId};
use crate::state::GrantState;
use crate::trust::{DecisionScope, PolicyRevisionRef};

// --- grants ------------------------------------------------------------------------------

/// `inspect grants` data: the grants the caller may see (every grant for the owner role;
/// otherwise those with a binding the caller may act on), including an ended grant while a
/// remote revocation or a cleanup intent still covers it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantListView {
    /// The grants.
    pub grants: Vec<GrantView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantView {
    /// The grant.
    pub grant_id: GrantId,
    /// Its state.
    pub state: GrantState,
    /// Its immutable effective deadline.
    pub expires_at: Timestamp,
    /// The parent grant of a delegated grant. Omitted for a root grant (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<GrantId>,
    /// Its effective scope at authorization.
    pub scope: ScopeView,
    /// ⟨r2.7⟩ Why it is degraded. Present only while `state` is `degraded` and a reason is
    /// recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<DegradedReasonView>,
    /// ⟨r2.7⟩ A remote revocation still covers it. Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub remote_pending: bool,
    /// ⟨r2.12; D17⟩ Why its remote obligations are still pending: every reason present,
    /// each once. Omitted when none (always an array otherwise). Distinct from revision
    /// 6's environment-level `remote_pending` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_pending_reasons: Vec<RemotePendingReasonView>,
    /// ⟨r2.10⟩ Its remote retries. Present exactly when `remote_pending` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_retries: Option<RemoteRetriesView>,
    /// ⟨r2.17⟩ An applied effect of it still waits on a cleanup intent. Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub cleanup_pending: bool,
}

/// ⟨r2.7⟩ Why a `degraded` grant is degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DegradedReasonView {
    /// The grant's credential mechanism is not configured in this runtime.
    MechanismUnavailable,
    /// ⟨M03⟩ The grant's key was lost and a re-issue is pending.
    CredentialReissuePending,
    /// ⟨M03⟩ The issuer is unavailable.
    IssuerUnavailable,
    /// ⟨M03⟩ A pair lost its verified enrollment under the grant's CA.
    PairUnenrolled,
}

/// ⟨r2.9⟩ Why a remote obligation is still pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemotePendingReasonView {
    /// The responsible adapter is not configured in this runtime.
    AdapterUnavailable,
}

/// ⟨r2.10⟩ A grant's remote retries: its own obligations' highest attempt count, the last
/// round, and whether its retries stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRetriesView {
    /// The highest attempt count of its obligations.
    pub attempts: u32,
    /// The last round.
    pub last_attempt_at: Timestamp,
    /// Whether its retries stopped.
    pub stopped: bool,
}

// --- bindings ----------------------------------------------------------------------------

/// `inspect bindings` data: the live bindings the caller may act on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BindingListView {
    /// The bindings.
    pub bindings: Vec<BindingView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BindingView {
    /// The binding.
    pub binding_id: BindingId,
    /// The grant realizing it.
    pub grant_id: GrantId,
    /// Its work ID.
    pub work_id: WorkId,
    /// The profile it pins.
    pub profile: ProfileId,
    /// The profile revision pinned at activation.
    pub profile_revision: u64,
    /// Its state.
    pub state: BindingStateView,
    /// When it was created.
    pub created_at: Timestamp,
    /// **Revision 7, not emitted yet.** The request that created the binding, shown only to
    /// the caller that created it. Omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

/// A binding's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BindingStateView {
    /// Holding a reference to its grant.
    Active,
    /// Reference dropped.
    Released,
}

// --- decisions ---------------------------------------------------------------------------

/// `inspect decisions` data: the pending owner decisions (owner role only), and a local
/// widening record that lapsed at this read, shown once more as expired.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DecisionListView {
    /// The decisions.
    pub decisions: Vec<DecisionView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One decision record with its exact recorded request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DecisionView {
    /// The decision (the nonsecret `decision_ref`).
    pub decision_id: DecisionId,
    /// What is decided.
    pub kind: DecisionKindName,
    /// Its state (`pending`; `expired` for a lapsed local widening).
    pub state: DecisionStateView,
    /// When it was created.
    pub created_at: Timestamp,
    /// After this instant it cannot be completed.
    pub expires_at: Timestamp,
    /// Whether the runtime's clock is at or past `expires_at`.
    pub expired: bool,
    /// What the owner decides, by `kind`. `approve_authority`: `{operation_id, delta}`;
    /// `widen_policy`: `{action}`; `confirm_time`: `{observed_wall}`; `apply_projection`:
    /// `{operation_id, plan_digest, intent, added_aliases, changed_aliases,
    /// removed_aliases, files, git, restore, diff_text}`; `declare_interaction`:
    /// `{operation_id, identity_id, fingerprint, endpoint, interaction, valid_until}`;
    /// `add_environment`: `{environment_id, environment_kind, realization, disclosures}`;
    /// every other kind: the recorded decision kind, verbatim. Persisted content, so it
    /// keeps its recorded form (D9).
    pub request: serde_json::Value,
    /// ⟨M06 W5⟩ Why a lapsed local widening is shown expired (`approval_lapsed`). Omitted
    /// otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// ⟨rev5.1⟩ For a targeted widening, the policies its approval changes, fixed at
    /// creation. Present (possibly empty) exactly for a targeted `widen_policy` record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<PolicyRevisionRef>>,
    /// ⟨rev6.5⟩ For a targeted `resume` or `clear_cutoff`, the delivered effects it lifts.
    /// Omitted when it lifts none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifted_effects: Vec<LiftedEffect>,
    /// ⟨rev5.2⟩ For a `widen_policy` `create`, the scope its approval applies. Omitted
    /// otherwise, and when its basis or snapshot is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<DecisionScope>,
}

/// A decision's kind, as views and events name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionKindName {
    /// Approve the authority delta of an operation.
    ApproveAuthority,
    /// Widen a standing policy.
    WidenPolicy,
    /// Confirm the wall time.
    ConfirmTime,
    /// ⟨M02⟩ Apply a projection plan.
    ApplyProjection,
    /// ⟨M02⟩ Declare an identity's interaction.
    DeclareInteraction,
    /// ⟨M03⟩ Register an issuer.
    RegisterIssuer,
    /// ⟨M04⟩ Add a managed environment.
    AddEnvironment,
    /// ⟨M03⟩ Retire an issuer.
    RetireIssuer,
    /// ⟨M03⟩ Enroll an account.
    EnrollAccount,
    /// ⟨M03⟩ Enroll through the system form.
    EnrollSystemForm,
    /// ⟨M05⟩ Trust a workspace.
    TrustWorkspace,
    /// ⟨M05⟩ Reconcile a workspace.
    ReconcileWorkspace,
    /// ⟨M03⟩ Remove an enrollment.
    RemoveEnrollment,
    /// ⟨M03⟩ Approve an enrollment target change.
    ApproveTargetChange,
    /// ⟨M06⟩ A paired client's widening request, decided runner-locally.
    RemoteWidening,
}

/// A decision record's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecisionStateView {
    /// Awaiting an attended verdict.
    Pending,
    /// Approved and applied.
    Approved,
    /// Denied.
    Denied,
    /// Aged out without a verdict.
    Expired,
    /// Invalidated by an authority-generation change.
    Stale,
    /// ⟨r2.4⟩ Withdrawn by the runtime without a verdict.
    Withdrawn,
}
