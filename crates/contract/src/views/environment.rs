//! ⟨rev7⟩ `inspect environments`' own-environment keys, and `environment status` with its
//! residuals (ADR-0013 §11 D1, D9; ADR-0012 §7.1, §7.3; ADR-0013 §6.4 `remote_pending`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::PreviewView;
use crate::Timestamp;
use crate::code::Code;
use crate::controller_record::RemoteEnvironmentPin;
use crate::environment::{EnvironmentKindView, EnvironmentView};
use crate::ids::{ClientId, DeviceId, EnvironmentId, GrantId};
use crate::managed::AuthenticationResidual;
use crate::remote::{Connectivity, RemotePending};

// --- inspect environments ----------------------------------------------------------------

/// `inspect environments` data, whole: M01's keys for the runtime's own environment, which
/// every role reads, and, for the owner role, `items` (every environment the runtime
/// knows, [`crate::environment::EnvironmentsView`]'s list).
///
/// Provisional schema name `inspect-environments.full`: today's public
/// `inspect-environments` schema describes `items` only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvironmentListView {
    /// The runtime's own environment.
    pub environment_id: EnvironmentId,
    /// Whether the runtime's own environment has an enrollment record.
    pub enrolled: bool,
    /// The own environment's enrollment record: one entry when enrolled, none otherwise.
    pub environments: Vec<EnvironmentRecordView>,
    /// ⟨M04⟩ Owner role only: every environment the runtime knows, its own first. Omitted
    /// for any other role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<EnvironmentView>>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// An enrolled environment's record (M01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvironmentRecordView {
    /// The environment.
    pub id: EnvironmentId,
    /// Its device.
    pub device: DeviceId,
    /// Its kind.
    pub kind: EnvironmentKindView,
    /// Its human label. Omitted when none is set (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Its enrolled permissions.
    pub permissions: EnvironmentPermissionsView,
}

/// What an enrolled environment may do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvironmentPermissionsView {
    /// May activate automatic work under standing policies.
    pub automatic_activation: bool,
    /// May host a signing endpoint for managed credentials.
    pub managed_signing: bool,
    /// May request certificates from the per-user issuer.
    pub issuer_access: bool,
}

// --- environment status ------------------------------------------------------------------

/// `heimdall environment status --json` data: the controller's own view of its runners.
/// Reading it opens no session, except for one limited-role record named on the command
/// line (`runner_view`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvironmentStatusView {
    /// Whether management connections are possible now: `available`, or the refusal
    /// reason (`mgmt_key_store_locked`, …).
    pub management: String,
    /// One entry per recorded runner, ordered by environment ID.
    pub environments: Vec<EnvironmentStatusEntry>,
}

/// One recorded runner: the controller's record, and the remote fields when this
/// controller's state can be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnvironmentStatusEntry {
    /// The controller's record of the runner (its keys sit in this entry).
    #[serde(flatten)]
    pub record: RemoteEnvironmentPin,
    /// ⟨M06 W3; ADR-0006 §18.7 item 13⟩ The remote fields (their keys sit in this entry).
    /// All absent when the controller's state cannot be read.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteStatusView>,
    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ The runner's own view, read over one management
    /// session, for a limited-role record named on the command line. Omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_view: Option<RunnerViewEntry>,
}

/// ⟨M06⟩ The controller's view of one runner (ADR-0012 §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteStatusView {
    /// Its connectivity.
    pub connectivity: Connectivity,
    /// When a session last completed its hello. Omitted when never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
    /// The narrowing effects this controller produced that the runner has not
    /// acknowledged. Always written, possibly empty. From revision 7 (ADR-0013 §6.4) it
    /// holds at most the first 16 entries; `remote_pending_count` counts them all.
    pub remote_pending: Vec<RemotePending>,
    /// **Revision 7, not emitted yet** (ADR-0013 §6.4): how many entries `remote_pending`
    /// has in full. Omitted until emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_pending_count: Option<u32>,
    /// The last-known readiness of its grants, computed forward. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub last_known_readiness: Vec<LastKnownReadinessView>,
    /// The issuer's barrier for this runner.
    pub issuance: IssuanceGateView,
    /// The residuals of the grants this controller asked the runner to revoke. Omitted when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residuals: Vec<GrantResidual>,
    /// The cutoffs the runner's last report showed fired early under uncertain time.
    /// Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cutoffs_fired_early: Vec<EarlyCutoffView>,
    /// ⟨M06 W3⟩ The delivered grants whose last remote issuance failed. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuance_failures: Vec<IssuanceFailedView>,
}

/// One runner grant's last-known readiness: a statement about the last report, not about
/// the runner now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LastKnownReadinessView {
    /// The grant.
    pub grant: GrantId,
    /// The earliest `valid_before` of its installed certificates.
    pub offline_until: Timestamp,
    /// That bound against the controller's clock now.
    pub state: LastKnownStateView,
    /// When the report was read.
    pub observed_at: Timestamp,
}

/// Whether a last-known bound has passed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LastKnownStateView {
    /// The installed certificates were still valid at the controller's clock now.
    WithinBound,
    /// The earliest `valid_before` has passed.
    BoundPassed,
}

/// Whether this controller's issuer may issue for the runner now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssuanceGateView {
    /// The current session's report was reconciled.
    Reconciled,
    /// Gated: no reconciled report in a current session.
    AwaitingResync,
}

/// ⟨M06; ADR-0012 §7.3⟩ The residual of one grant this controller asked a runner to
/// revoke, from this controller's counted issuance history (A07's report).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantResidual {
    /// The grant.
    pub grant: GrantId,
    /// Whether the runner acknowledged the revoke (`false`: still `remote_pending`).
    pub acknowledged: bool,
    /// New authentication. Omitted when nothing counted is outstanding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_authentication: Option<AuthenticationResidual>,
    /// The same in words, never a bare deadline. Wording unchanged from revision 6.
    pub statement: String,
}

/// A delivered cutoff that fired before the owner's instant because the runner's time was
/// uncertain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EarlyCutoffView {
    /// The scope's canonical key (`all`, `policy:<id>`, …).
    pub scope: String,
    /// The controller that produced it.
    pub producer: ClientId,
    /// The owner's instant.
    pub at: Timestamp,
    /// The instant it took effect at on the runner.
    pub fired_at: Timestamp,
    /// Why it fired early: always `time_uncertain`.
    pub reason: String,
}

/// ⟨M06 W3⟩ One delivered grant whose last remote issuance failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IssuanceFailedView {
    /// The grant.
    pub grant: GrantId,
    /// When it first failed this way.
    pub at: Timestamp,
    /// The stable reason (a contract reason where one exists, else the code; for a
    /// refused runner-originated pending grant, the limit and its sentence).
    pub reason: String,
}

/// ⟨M06 W5⟩ What a limited-role runner said of itself, or why nothing was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerViewEntry {
    /// Whether the runner's view was read.
    pub read: bool,
    /// The runner's `inspect environments` data, as its limited role sees it. Present
    /// exactly when `read` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<EnvironmentListView>,
    /// The refusal's code. Present exactly when `read` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// The refusal's message. Present exactly when `read` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The refusal's reason, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
