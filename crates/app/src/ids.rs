//! Runtime ID generation from the OS CSPRNG (spec §4.2: durable IDs never derive
//! from routes, names, or time).

use heimdall_contract::ids::{BindingId, EventId, GrantId, OperationId, ResourceId};

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_distinct() {
        let a = new_operation_id().unwrap();
        let b = new_operation_id().unwrap();
        assert_ne!(a, b);
    }
}
