//! The `evaluate` level: `ssh -G` over the real tree (m02-plan U3; ADR-0007 §6). It
//! runs the configuration's commands, so it needs `allow_config_commands`.

use heimdall_contract::doctor::ProbeRecord;

use super::ProbeContext;

/// Run `ssh -G <alias>` under the probe's containment.
#[must_use]
pub fn ssh_g(ctx: &ProbeContext<'_>, alias: &str) -> ProbeRecord {
    let _ = (ctx, alias);
    todo!("M02-U3 probe::evaluate::ssh_g")
}
