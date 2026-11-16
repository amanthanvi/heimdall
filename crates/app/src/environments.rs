//! ⟨M04⟩ The managed-environment seam (ADR-0010 §9 item 1; ADR-0006 revision 5 §17).
//!
//! One runtime manages a **set** of environments: its own native session (its
//! `OperationsConfig.environment`, the store's `self_environment`) and every WSL Mode B
//! distribution and container environment it controls (`managed_environments`, migration
//! 0007). A request names its target environment, which must be in that set and owned by
//! this runtime; the authenticated controller principal (who sent the request) is never
//! the execution environment's identity. Every M01–M03 `target == own` check goes through
//! [`admit`], which replaces it (the check is replaced, never deleted).
//!
//! The realization work (endpoints and files inside a distribution or a container
//! directory, the helper channel) is the M04 track's, in its own modules; this module only
//! decides membership.

use heimdall_contract::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::EnvironmentId;
use heimdall_domain::environment::EnvironmentAdmission;
use heimdall_store::Txn;

use crate::error::OpError;

/// Admit `target` for the runtime whose own environment is `own`, inside the caller's
/// transaction: `Ok` when it is in the managed set; otherwise `NOT_FOUND` (an unmanaged
/// environment: unknown, or another runtime's) or `NOT_FOUND` with reason
/// `environment_removed` (a removed or gone identity). Nothing is written.
///
/// # Errors
/// A store error (outer); the refusal (inner).
pub fn admit(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    target: &EnvironmentId,
) -> heimdall_store::Result<Result<(), OpError>> {
    Ok(match tx.admit_environment(own, target)? {
        EnvironmentAdmission::Managed => Ok(()),
        EnvironmentAdmission::Unmanaged => Err(unmanaged()),
        EnvironmentAdmission::Removed => Err(removed()),
    })
}

/// The environments in this runtime's managed set (its own first), inside the caller's
/// transaction (`heimdall_store::Txn::managed_set`).
///
/// # Errors
/// A store error.
pub fn members(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
) -> heimdall_store::Result<std::collections::BTreeSet<EnvironmentId>> {
    Ok(tx.managed_set(own)?.into_iter().collect())
}

/// The refusal of an environment this runtime does not manage (M01's text).
#[must_use]
pub fn unmanaged() -> OpError {
    OpError::new(
        Code::NotFound,
        "the environment is not managed by this runtime",
    )
    .with_resource("environment", None)
}

/// The refusal of a removed or gone environment.
#[must_use]
pub fn removed() -> OpError {
    OpError::new(Code::NotFound, "the environment was removed")
        .with_reason(reason::ENVIRONMENT_REMOVED)
        .with_resource("environment", None)
}

impl crate::Operations {
    /// ⟨M04⟩ Take a managed environment out of the set (ADR-0010 §9 item 1; §3 item 13,
    /// §4 item 6): its row moves to `to` (`removed` by the owner, `gone` when its
    /// distribution was unregistered), which moves the authority generation, then every
    /// grant pinned to it is ended through the existing withdrawal path (its authority
    /// re-validates as withdrawn), so each grant's own cleanup (endpoints, files, slots
    /// of **that** environment, by generation) runs as for any revocation. Another
    /// environment's grants, slots and files are untouched. Returns the grants that were
    /// live in it. Idempotent for an environment already out of the set.
    ///
    /// The realization's own teardown (a container directory, a distribution's
    /// projection, the helper) is the M04 track's, called around this.
    ///
    /// # Errors
    /// `NOT_FOUND` for the runtime's own environment or an environment it does not
    /// control; a store failure.
    pub async fn retire_managed_environment(
        &self,
        environment: &EnvironmentId,
        to: heimdall_domain::environment::ManagedState,
    ) -> Result<Vec<heimdall_contract::ids::GrantId>, OpError> {
        if to.in_set() {
            return Err(OpError::new(
                Code::UsageError,
                "an environment leaves the set as removed or gone",
            ));
        }
        let own = self.environment().clone();
        let env = environment.clone();
        let at = self.local_clock_wall();
        let live = self
            .local_write(move |tx, _| {
                let Some(row) = tx
                    .managed_environment(&env)?
                    .filter(|r| r.controller == own)
                else {
                    return Ok(Err(unmanaged()));
                };
                // `removed → gone` is allowed; a terminal row is never set back in.
                if row.state != to
                    && (row.state.in_set()
                        || row.state == heimdall_domain::environment::ManagedState::Removed)
                {
                    tx.set_managed_environment_state(&env, row.state, to, at)?;
                }
                let mut live = Vec::new();
                for g in tx.grants_due(heimdall_contract::Timestamp::MAX)? {
                    if g.environment == env && g.state.permits_use() {
                        live.push(g.id);
                    }
                }
                Ok(Ok(live))
            })
            .await??;
        for g in &live {
            self.end_if_invalid(g).await;
        }
        Ok(live)
    }
}
