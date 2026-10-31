//! Managed resources and ownership generations (spec §4.1 "Managed resource",
//! §13.5; R-RT-04; plan §6.3 property 6).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, GrantId, OperationId, ResourceId};
use serde::{Deserialize, Serialize};

/// Monotonic per-resource generation. Cleanup of generation N must not touch a
/// resource now owned by N+1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceGeneration(pub u64);

/// Resource kinds owned by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Control or signing endpoint (socket/pipe).
    Endpoint,
    /// Supervised child process (helper, master).
    Process,
    /// Generated configuration file.
    ConfigProjection,
    /// Host-trust entry.
    TrustEntry,
    /// Issued certificate.
    Certificate,
    /// Route helper.
    RouteHelper,
    /// Remote enrollment record.
    RemoteEnrollment,
}

/// Who owns a resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnerRef {
    /// A binding.
    Binding {
        /// ID.
        id: BindingId,
    },
    /// A grant.
    Grant {
        /// ID.
        id: GrantId,
    },
    /// The runtime itself (control endpoint, instance lock).
    Runtime,
}

/// Desired/observed resource state (spec §13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    /// Should exist / does exist.
    Present,
    /// Should not exist / does not exist.
    Absent,
    /// Not yet observed.
    Unknown,
}

/// A managed resource record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedResource {
    /// ID.
    pub id: ResourceId,
    /// Kind.
    pub kind: ResourceKind,
    /// Owner.
    pub owner: OwnerRef,
    /// Current generation.
    pub generation: ResourceGeneration,
    /// Desired state.
    pub desired: ResourceState,
    /// Last observed state.
    pub observed: ResourceState,
    /// Last operation that touched it.
    pub last_operation: Option<OperationId>,
    /// Opaque locator (path, pipe name, PID with start time); never a secret.
    pub locator: String,
    /// Updated.
    pub updated_at: Timestamp,
}

/// Whether a cleanup initiated for `cleanup_generation` may act on `current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupDecision {
    /// Same generation: proceed.
    Proceed,
    /// The resource has been replaced by a newer generation: do nothing.
    Superseded,
}

/// Pure stale-cleanup guard (R-RT-04).
#[must_use]
pub fn may_cleanup(
    cleanup_generation: ResourceGeneration,
    current: &ManagedResource,
) -> CleanupDecision {
    if current.generation == cleanup_generation {
        CleanupDecision::Proceed
    } else {
        CleanupDecision::Superseded
    }
}
