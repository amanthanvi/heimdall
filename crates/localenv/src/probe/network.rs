//! The `network` level: connect and read the server banner only; no key exchange
//! (m02-plan U3).

use heimdall_contract::doctor::ProbeRecord;

use super::ProbeContext;

/// Read the SSH banner of `host:port`.
#[must_use]
pub fn banner(ctx: &ProbeContext<'_>, host: &str, port: u16) -> ProbeRecord {
    let _ = (ctx, host, port);
    todo!("M02-U3 probe::network::banner")
}
