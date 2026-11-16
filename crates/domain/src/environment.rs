//! Execution environments and destination capability (spec §4.1 "Environment",
//! "Destination"; §8.1 environment-local authority).

use std::collections::BTreeSet;

use heimdall_contract::Timestamp;
use heimdall_contract::environment::DistributionGuid;
use heimdall_contract::ids::{DestinationId, DeviceId, EnvironmentId};
use heimdall_contract::request::DestinationScopeEnforcement;
use serde::{Deserialize, Serialize};

/// Kind of environment (spec §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentKind {
    /// Native desktop/user session.
    NativeSession,
    /// WSL distribution.
    WslDistribution,
    /// Local container context.
    Container,
    /// Remote runner.
    RemoteRunner,
}

/// What this environment may do (enrolled permissions, spec §6.2 "enrolled
/// environment permissions").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPermissions {
    /// May activate automatic work under standing policies.
    pub automatic_activation: bool,
    /// May host a signing endpoint for managed credentials.
    pub managed_signing: bool,
    /// May request certificates from the per-user issuer.
    pub issuer_access: bool,
}

/// An enrolled environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    /// Stable ID; never changes with routes or display names.
    pub id: EnvironmentId,
    /// Device association.
    pub device: DeviceId,
    /// Kind.
    pub kind: EnvironmentKind,
    /// Human label (mutable).
    pub label: Option<String>,
    /// Enrolled permissions.
    pub permissions: EnvironmentPermissions,
}

/// ⟨M04⟩ How a managed environment is realized (ADR-0010 §3–§4; ADR-0006 revision 5
/// §17). The native session is implicit: the runtime's own environment is always in its
/// managed set and has no [`ManagedEnvironment`] row.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnvironmentRealization {
    /// A WSL distribution in Mode B: its identity is the registration GUID plus the
    /// Linux account chosen at enable (ADR-0010 §3 item 1).
    Wsl {
        /// Registration GUID (identity).
        guid: DistributionGuid,
        /// Name when enabled (descriptive).
        name: String,
        /// Linux account (identity).
        account: String,
    },
    /// A local container environment with its stable directory `<runtime_dir>/c/<tag>/`
    /// (ADR-0010 §4 item 1).
    Container {
        /// Owner label.
        label: String,
        /// The 16-hex directory tag.
        dir_tag: String,
    },
}

/// ⟨M04⟩ A managed environment's lifecycle state (revision 5 §17; ADR-0010 §3 items 9–13,
/// §4 item 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ManagedState {
    /// In the set, running.
    Active,
    /// In the set; its distribution is not running (only an explicit `ensure` naming it
    /// may start it).
    NotRunning,
    /// Removed by the owner; kept as a removed identity, never a target again.
    Removed,
    /// Its distribution was unregistered; never a target again.
    Gone,
}

impl ManagedState {
    /// Whether an environment in this state is in the managed set (a valid target).
    #[must_use]
    pub fn in_set(self) -> bool {
        matches!(self, ManagedState::Active | ManagedState::NotRunning)
    }
}

/// ⟨M04⟩ One member of a runtime's managed-environment set beyond its own native session
/// (ADR-0010 §9 item 1; `managed_environments`, migration 0007). Its `environment` also
/// has an [`EnvironmentRecord`] (kind, label, permissions); this row adds ownership,
/// realization and lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEnvironment {
    /// The execution environment.
    pub environment: EnvironmentId,
    /// The runtime that manages it: that runtime's own environment ID (the store's
    /// `self_environment`). The controller principal (who sends requests) is never this
    /// environment's identity, and a row whose controller is not this runtime's own
    /// environment is not owned by it.
    pub controller: EnvironmentId,
    /// Realization.
    pub realization: EnvironmentRealization,
    /// State.
    pub state: ManagedState,
    /// Created.
    pub created_at: Timestamp,
    /// Last state change.
    pub updated_at: Timestamp,
}

impl ManagedEnvironment {
    /// The environment kind its realization implies.
    #[must_use]
    pub fn kind(&self) -> EnvironmentKind {
        match self.realization {
            EnvironmentRealization::Wsl { .. } => EnvironmentKind::WslDistribution,
            EnvironmentRealization::Container { .. } => EnvironmentKind::Container,
        }
    }
}

/// ⟨M04⟩ Whether a target environment may be used by this runtime (ADR-0010 §9 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvironmentAdmission {
    /// In this runtime's managed set: its own native session, or a row it controls in an
    /// in-set state.
    Managed,
    /// Not managed by this runtime (no row, or another runtime's): `NOT_FOUND`.
    Unmanaged,
    /// Removed or gone: `NOT_FOUND` with reason `environment_removed`.
    Removed,
}

/// ⟨M04⟩ Admit `target` for a runtime whose own environment is `own`, given its managed
/// row (if any). Pure; the replacement of every M01–M03 `target == own` equality check
/// (ADR-0010 §9 item 1: the check is replaced, never deleted).
#[must_use]
pub fn admit_environment(
    own: &EnvironmentId,
    target: &EnvironmentId,
    row: Option<&ManagedEnvironment>,
) -> EnvironmentAdmission {
    if target == own {
        return EnvironmentAdmission::Managed;
    }
    match row {
        Some(r) if r.environment == *target && r.controller == *own => {
            if r.state.in_set() {
                EnvironmentAdmission::Managed
            } else {
                EnvironmentAdmission::Removed
            }
        }
        _ => EnvironmentAdmission::Unmanaged,
    }
}

/// ⟨M04⟩ A WSL distribution's record (ADR-0010 §2 item 1; `wsl_distributions`, migration
/// 0007): a Mode A distribution has no environment record, only this one, which holds its
/// owned items by resource identity; a Mode B distribution's environment is `mode_b`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslDistributionRecord {
    /// Registration GUID.
    pub guid: DistributionGuid,
    /// Name when last observed (descriptive).
    pub name: String,
    /// Mode A enabled.
    #[serde(default)]
    pub mode_a: bool,
    /// The Mode B environment, when enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_b: Option<EnvironmentId>,
    /// Owner-retained cleanup obligation: a disable whose distribution was stopped
    /// (ADR-0010 §9 item 2), done at the next explicit start or `ensure`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cleanup_pending: bool,
    /// Last change.
    pub updated_at: Timestamp,
}

/// What a destination/account can enforce (spec §7.4 capabilities, §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationCapability {
    /// Destination.
    pub destination: DestinationId,
    /// Enrollment capability level: 1 existing-only, 2 account-level, 3 admin.
    pub enrollment_level: u8,
    /// Strongest destination-scope enforcement verified for it.
    pub scope_enforcement: DestinationScopeEnforcement,
    /// Credential mechanisms observed to work (names).
    pub mechanisms: BTreeSet<String>,
}
