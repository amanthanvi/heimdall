//! The `agent` level: one `SSH_AGENTC_REQUEST_IDENTITIES` through the bounded agent
//! client (`heimdall_ipc::agent_client`, U6), nothing else (m02-plan U3, U6).

use heimdall_contract::doctor::ProbeRecord;

use super::ProbeContext;
use crate::agents::EndpointLocator;

/// List the identities an agent holds (fingerprints only; comments discarded).
#[must_use]
pub fn list_identities(ctx: &ProbeContext<'_>, endpoint: &EndpointLocator) -> ProbeRecord {
    let _ = (ctx, endpoint);
    todo!("M02-U3 probe::agent::list_identities")
}
