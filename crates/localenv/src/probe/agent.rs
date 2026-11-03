//! The `agent` level: one `SSH_AGENTC_REQUEST_IDENTITIES` through the bounded agent
//! client (`heimdall_ipc::agent_client`, U6), nothing else (m02-plan U3, U6).
//!
//! The endpoint's [`EndpointLocator`] is converted to the client's `AgentLocator`
//! (ADR-0007 §12.15 item 6, E-U6-2). The client sends exactly one request and reads
//! one reply within its hard bounds (2 s, 256 KiB, 1024 identities), checks the peer
//! (Unix peer UID; Windows pipe owner) before writing, and never signs, adds, removes,
//! locks or sends an extension. It runs on its own thread with its own current-thread
//! runtime, so the level works inside or outside a caller's runtime. No configuration
//! runs and no network is used: the record excludes configuration execution,
//! network, signing and mutation; agent and provider contact happen.

use std::time::Instant;

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::doctor::{ExcludedEffect, ProbeOutcome, ProbeRecord};
use heimdall_contract::provider::ProbeLevel;
use heimdall_ipc::agent_client::{AgentClientError, AgentListing, ClientBounds};

use super::ProbeContext;
use crate::agents::EndpointLocator;

/// List the identities an agent holds (fingerprints only; comments discarded).
#[must_use]
pub fn list_identities(ctx: &ProbeContext<'_>, endpoint: &EndpointLocator) -> ProbeRecord {
    list_identities_observed(ctx, endpoint).0
}

/// [`list_identities`], with the listing (or the client's error) when the call was
/// made.
pub fn list_identities_observed(
    ctx: &ProbeContext<'_>,
    endpoint: &EndpointLocator,
) -> (ProbeRecord, Result<AgentListing, AgentClientError>) {
    let started_at = Timestamp::now();
    let t0 = Instant::now();
    let target = endpoint.display(&ctx.local.paths.account_home);
    let mut record = super::record(ProbeLevel::Agent, &target, started_at);
    record
        .effects_excluded
        .remove(&ExcludedEffect::AgentContact);
    record
        .effects_excluded
        .remove(&ExcludedEffect::ProviderContact);
    let locator = endpoint.to_agent_locator();
    let bounds = ClientBounds::default();
    let result = super::block_on_fresh(async move {
        heimdall_ipc::agent_client::list_identities(&locator, &bounds).await
    })
    .unwrap_or(Err(AgentClientError::Refused(
        "the agent client did not run",
    )));
    record.duration_ms = super::elapsed_ms(t0);
    match &result {
        Ok(_) => {}
        Err(AgentClientError::Timeout) => record.outcome = ProbeOutcome::Timeout,
        Err(AgentClientError::ForeignPeer) => {
            record.outcome = ProbeOutcome::Refused;
            record.code = Some(Code::CapabilityUnavailable);
        }
        Err(AgentClientError::AgentFailure) => {
            record.outcome = ProbeOutcome::Failed;
            record.code = Some(Code::ProviderLocked);
        }
        Err(_) => {
            record.outcome = ProbeOutcome::Failed;
            record.code = Some(Code::ServiceUnavailable);
        }
    }
    (record, result)
}
