//! ⟨rev7⟩ What became of a request (the contract owner's ruling on U0-Q7): the read-only
//! primitive `heimdall inspect request <REQUEST_ID>`, answered from the idempotency record.
//! **Standalone, not served:** the CLI form answers "not available in this build" and the
//! wire form (an `inspect` subject) lands with its emitter (U3).
//!
//! It is scoped to the caller's own idempotency namespace: another caller's request ID
//! answers `not_found`, so the view is no oracle. `not_found` covers a request never received
//! and one past retention, and cannot tell them apart.

use serde::{Deserialize, Serialize};

use crate::code::Code;
use crate::ids::OperationId;
use crate::lifecycle::RestoreEpoch;

/// The state of a request, as its idempotency record says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RequestState {
    /// Received, not settled.
    InProgress,
    /// Settled, with a recorded outcome.
    Completed,
    /// Never received by this caller, or past retention: the view cannot tell which.
    NotFound,
}

/// ⟨rev7⟩ `inspect request <REQUEST_ID>`'s data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RequestView {
    /// The request's state.
    pub state: RequestState,
    /// The operation the request made, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// The recorded outcome's code, when completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// The restore epoch the request ID is held under.
    pub request_epoch: RestoreEpoch,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn not_found_names_nothing_else() {
        let v = RequestView {
            state: RequestState::NotFound,
            operation_id: None,
            code: None,
            request_epoch: RestoreEpoch(0),
        };
        assert_eq!(
            serde_json::to_value(&v).unwrap(),
            serde_json::json!({"state": "not_found", "request_epoch": 0})
        );
    }
}
