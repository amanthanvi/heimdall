//! The `host_verification` level: verify the host key through the real tree, offering
//! nothing to sign (m02-plan U3). Needs `allow_config_commands`.

use heimdall_contract::doctor::ProbeRecord;

use super::ProbeContext;

/// Verify the host key of `alias`.
#[must_use]
pub fn verify(ctx: &ProbeContext<'_>, alias: &str) -> ProbeRecord {
    let _ = (ctx, alias);
    todo!("M02-U3 probe::host::verify")
}
