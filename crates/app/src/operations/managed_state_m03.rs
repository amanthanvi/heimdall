//! ⟨M03⟩ Per-runtime, in-memory state of agent O's wave-0 paths (one field of
//! `Inner`): the verification entries this runtime instance reserved (U0b row 4: an
//! entry reserved before a restart is never published).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use heimdall_contract::ids::{EnrollmentId, IssuanceId, OperationId};

/// A verification entry reserved by this runtime instance: its operation and the
/// enrollment whose plan it was checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReservedVerification {
    pub(super) operation: OperationId,
    pub(super) enrollment: EnrollmentId,
}

/// See the module docs.
#[derive(Debug, Default)]
pub(super) struct ManagedOpsState {
    verification_reserved: Mutex<HashMap<IssuanceId, ReservedVerification>>,
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
