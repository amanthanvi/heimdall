//! Runtime ID generation from the OS CSPRNG (spec §4.2: durable IDs never derive
//! from routes, names, or time).

use heimdall_contract::ids::{
    BindingId, DecisionId, EventId, GrantId, IssuanceId, OperationId, ResourceId,
};

/// Failure to obtain randomness; the runtime refuses to proceed rather than fall
/// back to a weaker source.
#[derive(Debug, thiserror::Error)]
#[error("operating system randomness unavailable")]
pub struct RandomnessUnavailable;

fn random_bytes() -> Result<[u8; 16], RandomnessUnavailable> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).map_err(|_| RandomnessUnavailable)?;
    Ok(buf)
}

/// New operation ID.
pub fn new_operation_id() -> Result<OperationId, RandomnessUnavailable> {
    Ok(OperationId::from_random_bytes(random_bytes()?))
}

/// New grant ID.
pub fn new_grant_id() -> Result<GrantId, RandomnessUnavailable> {
    Ok(GrantId::from_random_bytes(random_bytes()?))
}

/// New binding ID.
pub fn new_binding_id() -> Result<BindingId, RandomnessUnavailable> {
    Ok(BindingId::from_random_bytes(random_bytes()?))
}

/// New resource ID.
pub fn new_resource_id() -> Result<ResourceId, RandomnessUnavailable> {
    Ok(ResourceId::from_random_bytes(random_bytes()?))
}

/// New event ID.
pub fn new_event_id() -> Result<EventId, RandomnessUnavailable> {
    Ok(EventId::from_random_bytes(random_bytes()?))
}

/// New decision record ID (`dec_…`, the nonsecret `next.decision_ref`).
pub fn new_decision_id() -> Result<DecisionId, RandomnessUnavailable> {
    Ok(DecisionId::from_random_bytes(random_bytes()?))
}

/// New issuance-log entry ID.
pub fn new_issuance_id() -> Result<IssuanceId, RandomnessUnavailable> {
    Ok(IssuanceId::from_random_bytes(random_bytes()?))
}

/// New effect token (`eff_<32 hex>`): minted by the application and recorded in an
/// `Attempted` receipt **before** the adapter is called (ADR-0006 §14.1). Opaque
/// and nonsecret; it identifies one effect attempt, never authorizes anything.
pub fn new_effect_token() -> Result<String, RandomnessUnavailable> {
    use std::fmt::Write as _;
    let bytes = random_bytes()?;
    let mut s = String::with_capacity(4 + 32);
    s.push_str("eff_");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

/// A random 64-bit value (certificate serials, ADR-0005 §3.5 "draw the random
/// serial").
pub fn random_u64() -> Result<u64, RandomnessUnavailable> {
    let bytes = random_bytes()?;
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[..8]);
    Ok(u64::from_le_bytes(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_distinct() {
        let a = new_operation_id().unwrap();
        let b = new_operation_id().unwrap();
        assert_ne!(a, b);
        let t1 = new_effect_token().unwrap();
        let t2 = new_effect_token().unwrap();
        assert_ne!(t1, t2);
        assert!(t1.starts_with("eff_") && t1.len() == 36);
        assert!(new_decision_id().unwrap().as_str().starts_with("dec_"));
        assert!(new_issuance_id().unwrap().as_str().starts_with("iss_"));
    }
}
