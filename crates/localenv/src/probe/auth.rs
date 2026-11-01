//! The `authentication` level: one real authentication through the real tree
//! (m02-plan U3). Needs `allow_config_commands`; refused non-interactively for an
//! unknown or interactive identity, or an uncleared fallback identity (Q2 as
//! qualified).

use heimdall_contract::doctor::ProbeRecord;

use super::ProbeContext;

/// Authenticate to `alias`.
#[must_use]
pub fn authenticate(ctx: &ProbeContext<'_>, alias: &str) -> ProbeRecord {
    let _ = (ctx, alias);
    todo!("M02-U3 probe::auth::authenticate")
}
