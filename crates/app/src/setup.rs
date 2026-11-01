//! ⟨M02⟩ The setup entry point (m02-plan U0b row 18; U5 replaces the body in wave
//! 3, in the activation change set).
//!
//! **Fail-closed landing** (m02-plan §5 item 4, frozen; ADR-0007 §12.5 item 7 and
//! §12.7 QR7). Until the setup driver lands, every `SetupRequest` that reaches the
//! application, whatever its action, is answered `CAPABILITY_UNAVAILABLE` with
//! reason `driver_unavailable` and effect `none`, **before** any admission: no
//! idempotency record, operation row, decision, event or file access. A session
//! never gets here in wave 0: `setup/1` is not offered, so its gate answers
//! `SCHEMA_UNSUPPORTED` first.

use heimdall_contract::setup::SetupRequest;

use crate::context::Caller;
use crate::error::{OpError, OpResult};
use crate::operations::Operations;

impl Operations {
    /// `Request::Setup` (preview, apply, rollback, repair).
    ///
    /// # Errors
    /// Phase 1: always `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`,
    /// effect `none`; nothing is read or written.
    pub async fn setup(&self, caller: &Caller, req: SetupRequest) -> OpResult<serde_json::Value> {
        let _ = (caller, req);
        Err(OpError::driver_unavailable(
            "setup is not available in this build",
        ))
    }
}
