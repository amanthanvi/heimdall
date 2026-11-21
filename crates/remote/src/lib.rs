//! Heimdall's remote access crate (M06 U0 skeleton; ADR-0012 §3, §7, §13).
//!
//! **Skeleton.** Every unit of this crate lands in M06 U1 onward. Until then the only public
//! entry point is [`availability`], which fails closed: remote access is unavailable, with the
//! reason [`Unavailable::DriverUnavailable`].
//!
//! * [`roles`]: the role and permission model (`owner`, `requester`, `viewer`) and the caller
//!   context `{principal, role, remote_client}` (§3.7, §3.8), pure.
//! * [`invitations`]: invitation pins, the one durable consumption and non-extending expiry
//!   (§3.9), and client revocation (§3.11), pure over the store seam.
//! * [`sshd_policy`]: the verified sshd policy a limited role requires before activation
//!   (§3.2): the effective-configuration check and its typed refusals.
//! * [`bridge`]: the serve-side bridge that originates the only local hello, binds the
//!   session to one client and rejects identity frames (§3.6).
//! * [`sync`]: disconnected status, typed and keyed effects, the outbox and
//!   resynchronization (§7).
//!
//! **Edges.** Production dependencies are `heimdall-contract` and `heimdall-domain`. The
//! crate-graph step (`tools/validation/crate_graph.py`) also allows `heimdall-store`,
//! `heimdall-app` and `heimdall-ipc`, and refuses every other workspace crate; `heimdall-app`
//! must never import this crate, because the runtime wires it.

pub mod bridge;
pub mod invitations;
pub mod roles;
pub mod sshd_policy;
pub mod sync;

/// Why remote access is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// No remote-access driver is implemented in this build.
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

/// Whether remote access is available. Fails closed: always unavailable until M06 U1+ land.
///
/// # Errors
///
/// Always returns [`Unavailable::DriverUnavailable`] in this skeleton.
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
