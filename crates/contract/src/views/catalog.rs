//! ⟨rev7⟩ The catalog subjects of `inspect`: `profiles`, `destinations`, `identities` and
//! `projections` (ADR-0013 §11 D1, D9, D11). Owner role only: any other role reads the
//! same keys with empty lists (and no projection `record`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::PreviewView;
use crate::Timestamp;
use crate::doctor::AliasDefinition;
use crate::ids::{
    AccountName, DestinationId, EnvironmentId, IdentityId, OperationId, ProfileId, ResourceId,
};
use crate::managed::{ConnectionPolicyReport, PreferredMechanism};
use crate::provider::{
    DeclarationRef, EndpointRef, EvidenceBasis, InteractionKind, NoninteractiveEligibility,
};
use crate::request::{AccessPairRef, Capability};
use crate::route::RouteHealthPayload;

// --- profiles ----------------------------------------------------------------------------

/// `inspect profiles` data: the catalog's current profile definitions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProfileListView {
    /// Every profile, ordered by ID.
    pub items: Vec<ProfileView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One profile definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProfileView {
    /// The profile.
    pub profile_id: ProfileId,
    /// Its current revision.
    pub revision: u64,
    /// The owner's label. Omitted when none is set (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Its destination/account pairs.
    pub pairs: Vec<AccessPairRef>,
    /// The capabilities permitted on every pair.
    pub capabilities: Vec<Capability>,
}

// --- destinations ------------------------------------------------------------------------

/// `inspect destinations` data: every catalog destination.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DestinationListView {
    /// Every destination, ordered by ID.
    pub items: Vec<DestinationView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One catalog destination: its catalog fields, a managed definition's rendered fields,
/// and, from the runtime, the latest route-health report of the route helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DestinationView {
    /// The destination.
    pub destination_id: DestinationId,
    /// Its OpenSSH alias.
    pub alias: String,
    /// Its catalog revision.
    pub revision: u64,
    /// The owner's label. Omitted when none is set (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When it was last written.
    pub updated_at: Timestamp,
    /// `managed` (rendered into the managed file) or `observed`.
    pub definition: AliasDefinition,
    /// Managed: `HostName`. Omitted for an observed destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Managed: `Port`, when not ssh's default. Omitted otherwise (today: `null` for a
    /// managed destination without one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Managed: `User`. Omitted for an observed destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountName>,
    /// Managed: the adopted identity the alias uses. Omitted for an observed destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<IdentityId>,
    /// ⟨M04⟩ Managed: the single-hop jump destination. Omitted without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<DestinationId>,
    /// ⟨M03⟩ Managed: the stored pair preference. Omitted without a stored row, and for an
    /// observed destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preference: Option<DestinationPreferenceView>,
    /// ⟨M06 W5; D11⟩ The per-pair route status: the route helper's latest report with at
    /// least one attempt. Added today by the runtime's dispatcher
    /// (`heimdall_runtime::dispatch::add_route_health`), not by the inspect builder.
    /// Omitted when there is no report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_health: Option<RouteHealthView>,
    /// ⟨M06 W5; D11⟩ The SSH setting the route helper found defeating the catalog host-key
    /// pin, from the same report. Added by the same dispatcher step. Omitted when there is
    /// no report, or the report names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_pin_defeated: Option<HostPinDefeatedView>,
}

/// ⟨M03⟩ A managed destination's pair preference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DestinationPreferenceView {
    /// The preferred mechanism.
    pub mechanism: PreferredMechanism,
    /// Whether the projection that renders it is applied.
    pub projection: PairProjectionStatus,
    /// ⟨M03; ADR-0008 §17.25 item 19⟩ The effective connection policy and its wording, for
    /// a `managed_certificate` preference a standing policy covers. Omitted otherwise, and
    /// when the runtime has no wording source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_policy: Option<ConnectionPolicyReport>,
}

/// Whether the projection that renders a pair's preference is applied. Tagged by `state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PairProjectionStatus {
    /// Not yet applied (`setup apply` pending).
    Pending,
    /// Applied at this projection generation.
    Applied {
        /// The projection generation.
        generation: u64,
    },
}

/// ⟨M06 W5; D11⟩ The route helper's latest report for a destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RouteHealthView {
    /// The attempt's structured result (ADR-0012 §5.5 item 4).
    pub result: RouteHealthPayload,
    /// When it was reported.
    pub reported_at: Timestamp,
}

/// ⟨M06 W5; D11⟩ The setting that defeated the destination's catalog host-key pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostPinDefeatedView {
    /// One of [`crate::route::HOST_PIN_SETTINGS`].
    pub setting: String,
    /// When it was reported.
    pub reported_at: Timestamp,
}

// --- identities --------------------------------------------------------------------------

/// `inspect identities` data: the catalog's identities, each with its fresh eligibility.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityListView {
    /// Every adopted identity.
    pub identities: Vec<IdentityView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One adopted identity (public material only) with its fresh eligibility (ADR-0007 §7)
/// and its live declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityView {
    /// The identity.
    pub identity_id: IdentityId,
    /// Its catalog revision.
    pub revision: u64,
    /// Its public key's fingerprint (`SHA256:…`).
    pub fingerprint: String,
    /// The public key's type (its first token, e.g. `ssh-ed25519`).
    pub key_type: String,
    /// The mechanism its source names (`native_agent`, `onepassword`).
    pub mechanism: String,
    /// The recorded agent endpoint. Omitted when the source names none (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<EndpointRef>,
    /// The owner's label. Omitted when none is set (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The interaction, fresh.
    pub interaction: InteractionKind,
    /// How it was established.
    pub interaction_basis: EvidenceBasis,
    /// When the live declaration relied on was made. Omitted without one (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_at: Option<Timestamp>,
    /// The live declaration. Omitted without one (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<DeclarationRef>,
    /// Whether non-interactive work may use it now.
    pub noninteractive: NoninteractiveEligibility,
    /// When the runtime computed the eligibility.
    pub eligibility_checked_at: Timestamp,
}

// --- projections -------------------------------------------------------------------------

/// `inspect projections` data: this environment's projection resources and its projection
/// record, read-only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectionListView {
    /// The `config_projection` resources the projection owns.
    pub projections: Vec<ProjectionResourceView>,
    /// What each projection item last committed (subject metadata, kept: D1). Omitted
    /// until a projection is committed, and for a role that is not the owner (today:
    /// `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<ProjectionRecordView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One managed resource of the projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectionResourceView {
    /// The resource.
    pub id: ResourceId,
    /// Its kind (`config_projection` here).
    pub kind: ResourceKindView,
    /// Its owner.
    pub owner: ResourceOwnerView,
    /// Its current generation.
    pub generation: u64,
    /// Its desired state.
    pub desired: ResourceStateView,
    /// Its last observed state.
    pub observed: ResourceStateView,
    /// The last operation that touched it. Omitted when none is recorded (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_operation: Option<OperationId>,
    /// Its opaque locator (for a projection file, the canonical JSON of its path, role,
    /// file identity and digest); never a secret.
    pub locator: String,
    /// When it was last written.
    pub updated_at: Timestamp,
}

/// The kind of a runtime-owned resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceKindView {
    /// A control or signing endpoint.
    Endpoint,
    /// A supervised child process.
    Process,
    /// A generated configuration file.
    ConfigProjection,
    /// A host-trust entry.
    TrustEntry,
    /// An issued certificate.
    Certificate,
    /// A route helper.
    RouteHelper,
    /// A remote enrollment record.
    RemoteEnrollment,
    /// ⟨M03⟩ A materialized key or certificate file.
    MaterializedFile,
    /// ⟨M03⟩ An owned connection.
    Connection,
    /// ⟨M04⟩ The runtime's login entry.
    LoginEntry,
}

/// Who owns a resource. Tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceOwnerView {
    /// A binding.
    Binding {
        /// The binding.
        id: crate::ids::BindingId,
    },
    /// A grant.
    Grant {
        /// The grant.
        id: crate::ids::GrantId,
    },
    /// The runtime itself.
    Runtime,
    /// ⟨M02⟩ The managed projection of an environment.
    Projection {
        /// The environment.
        environment: EnvironmentId,
    },
}

/// A resource's desired or observed state (spec §13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceStateView {
    /// Should exist / does exist.
    Present,
    /// Should not exist / does not exist.
    Absent,
    /// Not yet observed.
    Unknown,
}

/// An environment's projection record: what each item last committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectionRecordView {
    /// The environment.
    pub environment: EnvironmentId,
    /// Each committed item's record, keyed by its [`crate::setup::ProjectionItem`] name.
    /// Always written, possibly empty.
    #[serde(default)]
    pub items: ProjectionRecordItemsView,
}

/// A projection record's items, one key per committed
/// [`crate::setup::ProjectionItem`] (the domain record's map, keyed by item name). Each
/// key is omitted until its item is committed. A key a newer item adds is tolerated on
/// read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectionRecordItemsView {
    /// The OpenSSH include block and the managed file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<ProjectionItemRecordView>,
    /// The Git include block and the managed Git file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<ProjectionItemRecordView>,
    /// ⟨M04⟩ The runtime's login entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_entry: Option<ProjectionItemRecordView>,
    /// ⟨M04⟩ A WSL distribution's Git item (Mode A).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution_git: Option<ProjectionItemRecordView>,
    /// ⟨M04⟩ A WSL distribution's projection (Mode B).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution_projection: Option<ProjectionItemRecordView>,
}

/// One projection item's last committed state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectionItemRecordView {
    /// Its last committed generation.
    pub generation: u64,
    /// Its files at that generation (each `{role, path, identity, sha256}`, the domain
    /// `ProjectionLocator`, verbatim). Always written, possibly empty.
    #[serde(default)]
    pub files: Vec<serde_json::Value>,
    /// The managed aliases rendered into the managed file (the `ssh` item); empty for
    /// `git`. Always written, possibly empty.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The global Git file the `git` item's block was written into. Omitted for the `ssh`
    /// item and for a record written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_file: Option<String>,
    /// The operation that committed it.
    pub operation: OperationId,
    /// When it was committed.
    pub committed_at: Timestamp,
}
