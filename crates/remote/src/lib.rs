//! Heimdall's remote access crate (M06; ADR-0012 §3, §7, §13).
//!
//! **State.** M06 U1 landed the library: roles and the per-request check, the verified sshd
//! policy, the management line and its port, invitations, runner-local widening and the
//! bridge. ⟨W2⟩ A **runner** runtime wires it into its dispatcher
//! (`heimdall_runtime::paired`): hello resolution, the per-frame check, the pending-session
//! path, the durable runner-local widening records ([`widening::StoreWidening`]) and
//! revocation. [`availability`] is this crate's own probe for callers outside a runner's
//! dispatcher and stays fail-closed (`driver_unavailable`).
//!
//! * [`roles`]: the role and permission model (`owner`, `requester`, `viewer`), the total
//!   per-frame check (revocation rechecked per request, the pending-client rule, no
//!   attendance for paired sessions, `role_insufficient`), and the subscription recheck
//!   (§3.7, §3.8, §3.9 item 3, §3.10). Pure.
//! * [`sshd_policy`]: the effective-policy verifier for `sshd -T` output and its runner with
//!   a scratch host key, the `management_policy: verified | owner_only` gate, and the
//!   confirming probe (§3.2).
//! * [`line`]: the forced-command management line, the authorized_keys parser, the
//!   `key_already_authorized` check and the [`line::ManagementLines`] port (§3.2, §3.5).
//! * [`invitations`]: the pending record, non-extending expiry, `join`'s compare-and-set,
//!   persist-then-rewrite with an idempotent reconciler, and client revocation (§3.9,
//!   §3.11), over the store ([`heimdall_store::ext_m06`]) and the line port.
//! * [`widening`]: no `RemoteDecide`: a paired client's widening request is a pending
//!   runner-local record; only an attended session local to the runner decides; a replay
//!   returns the recorded result (§3.10).
//! * [`bridge`]: the serve-side bridge that originates the only local hello, binds the
//!   session to one client and rejects identity frames (§3.6).
//! * [`sync`]: disconnected status, typed and keyed effects, the outbox and
//!   resynchronization (§7). Later units.
//!
//! **Edges.** Production dependencies are `heimdall-contract`, `heimdall-domain`,
//! `heimdall-store`, `heimdall-app` and `heimdall-ipc`, which the crate-graph step
//! (`tools/validation/crate_graph.py`) allows; it refuses every other workspace crate, and
//! `heimdall-app` must never import this crate, because the runtime wires it.

pub mod bridge;
pub mod invitations;
pub mod line;
pub mod roles;
pub mod sshd_policy;
pub mod sync;
#[doc(hidden)]
pub mod testing;
pub mod widening;

pub use roles::Refusal;

/// Why remote access is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// No remote-access driver is wired into request dispatch in this build.
    DriverUnavailable,
}

impl Unavailable {
    /// The stable reason token, as it appears in a `CAPABILITY_UNAVAILABLE` detail.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::DriverUnavailable => "driver_unavailable",
        }
    }
}

/// Whether remote access is available. Fails closed: always unavailable until the runtime
/// wires this crate into request dispatch (M06 W2).
///
/// # Errors
///
/// Always returns [`Unavailable::DriverUnavailable`] in this build.
pub const fn availability() -> Result<(), Unavailable> {
    Err(Unavailable::DriverUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_fails_closed_with_driver_unavailable() {
        assert_eq!(availability(), Err(Unavailable::DriverUnavailable));
        assert_eq!(
            Unavailable::DriverUnavailable.reason(),
            "driver_unavailable"
        );
    }
}
