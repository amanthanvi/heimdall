//! ⟨M03⟩ Per-runtime, in-memory state of agent O's wave-0 paths (one field of
//! `Inner`): the verification entries this runtime instance reserved (U0b row 4: an
//! entry reserved before a restart is never published), and ⟨wave 4⟩ the M03 ports the
//! runtime wires ([`crate::managed::ManagedWiring`]).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::managed::ManagedWiring;

use heimdall_contract::ids::{EnrollmentId, IssuanceId, OperationId};

/// A verification entry reserved by this runtime instance: its operation and the
/// enrollment whose plan it was checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReservedVerification {
    pub(super) operation: OperationId,
    pub(super) enrollment: EnrollmentId,
}

/// See the module docs.
#[derive(Default)]
pub(super) struct ManagedOpsState {
    verification_reserved: Mutex<HashMap<IssuanceId, ReservedVerification>>,
    /// ⟨wave 4⟩ The wired M03 ports; `None` until the runtime sets them.
    wiring: RwLock<Option<Arc<ManagedWiring>>>,
    /// ⟨wave 4⟩ The issuer handling's in-memory state (pending registrations).
    pub(super) issuer: Arc<super::issuer_m03::IssuerProcessState>,
    /// ⟨wave 4⟩ The enrollment driver's in-memory state (host port, previews).
    pub(super) enrollment: super::enrollment_m03::EnrollmentProcessState,
}

impl std::fmt::Debug for ManagedOpsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedOpsState").finish_non_exhaustive()
    }
}

impl ManagedOpsState {
    pub(super) fn reserved_verification(&self, id: &IssuanceId) -> Option<ReservedVerification> {
        self.verification_reserved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    pub(super) fn track_verification(&self, id: IssuanceId, reserved: ReservedVerification) {
        self.verification_reserved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, reserved);
    }

    pub(super) fn settle_verification(&self, id: &IssuanceId) {
        self.verification_reserved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
    }
}

impl super::Operations {
    /// ⟨M03⟩ wave 4 (U10): install the M03 ports the runtime built (the managed
    /// effects, the issuer client and lifecycle, the verification factory and runner,
    /// the target evaluator, connection control). Replaces any earlier wiring. Without
    /// it every M03 path fails closed before any record is written.
    pub fn set_managed_wiring(&self, wiring: ManagedWiring) {
        *self
            .inner
            .managed_ops
            .wiring
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(wiring));
    }

    /// ⟨M03⟩ wave 4: the wired M03 ports, if any.
    #[must_use]
    pub fn managed_wiring(&self) -> Option<Arc<ManagedWiring>> {
        self.inner
            .managed_ops
            .wiring
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
