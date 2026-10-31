//! Execution environments and destination capability (spec §4.1 "Environment",
//! "Destination"; §8.1 environment-local authority).

use std::collections::BTreeSet;

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
