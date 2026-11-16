//! ⟨M05⟩ Policy resolution by context on every path (ADR-0011 §10 item 1; ADR-0006
//! revision 5 §17 item 3). The pure rule is `heimdall_domain::policy::{applicable_policies,
//! resolve_policy}`; this module reads its inputs from the store for a grant and for the
//! environment-level (personal) paths, so no caller selects policies by ID or across
//! contexts.

use heimdall_contract::ids::{EnvironmentId, ProfileId};
use heimdall_domain::grant::GrantOrigin;
use heimdall_domain::policy::{PolicyContext, StandingPolicy, applicable_policies};
use heimdall_store::Txn;

/// The context a grant was resolved in: its origin's recorded workspace, personal when
/// absent (every M01–M03 grant) or when the origin is missing.
#[must_use]
pub fn grant_context(origin: Option<&GrantOrigin>) -> PolicyContext {
    PolicyContext::of_recorded(origin.and_then(|o| o.workspace.as_ref()))
}

/// The standing policies applicable to a grant: those naming its origin's profile and the
/// grant's **own** environment (ADR-0010 §9 item 1: per environment), filtered to its
/// recorded context. Empty without an origin.
///
/// # Errors
/// A store error.
pub fn grant_policies(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    origin: Option<&GrantOrigin>,
) -> heimdall_store::Result<Vec<StandingPolicy>> {
    let Some(o) = origin else {
        return Ok(Vec::new());
    };
    let all = tx.policies_for(&o.profile, environment)?;
    Ok(applicable_policies(&all, &grant_context(origin)))
}

/// The policies applicable to `profile` in `context` in `environment`.
///
/// # Errors
/// A store error.
pub fn policies_in(
    tx: &mut Txn<'_>,
    profile: &ProfileId,
    environment: &EnvironmentId,
    context: &PolicyContext,
) -> heimdall_store::Result<Vec<StandingPolicy>> {
    let all = tx.policies_for(profile, environment)?;
    Ok(applicable_policies(&all, context))
}

/// The policies governing an environment's ordinary aliases for `profile`: ordinary
/// aliases are environment-level (ADR-0011 §5.2, R3), so only personal policies apply; a
/// pair only a workspace policy holds is never rendered or activated for ordinary `ssh`.
///
/// # Errors
/// A store error.
pub fn environment_level_policies(
    tx: &mut Txn<'_>,
    profile: &ProfileId,
    environment: &EnvironmentId,
) -> heimdall_store::Result<Vec<StandingPolicy>> {
    policies_in(tx, profile, environment, &PolicyContext::Personal)
}
