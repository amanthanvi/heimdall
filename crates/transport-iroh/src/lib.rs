//! Heimdall's Iroh transport (M06 U6a; ADR-0012 §1, §2, §13): a library. The `transport
//! connect` and `transport serve` process roles, K_iroh custody and the runtime's admission
//! authority are m06-plan U56's; they build on this crate.
//!
//! * [`ALPN`] is the wire protocol's identifier: Pigeons' `/pigeons/0`, one bidirectional
//!   stream of raw SSH bytes (§1 item 2).
//! * [`policy`]: the effective exposure policy, validated (no iroh). Every bind, relay, peer
//!   relay hint and direct address an endpoint uses comes from it; anything outside it is
//!   refused (`relay_unapproved`, `route_unapproved`), and so is a policy the endpoint cannot
//!   apply (`transport_unavailable`) (§2.1).
//! * [`target`]: the serve target, `127.0.0.1` or `::1` only, connected from a socket bound
//!   to loopback before `connect()` (§2.3 item 2).
//! * [`admission`]: the allowlist (required, nonempty) and the admission authority seam: the
//!   lease, the per-endpoint answer and the suspend / lease-loss signals (§2.3 items 1, 3-5),
//!   with an in-process implementation.
//! * [`keys`]: where K_iroh comes from ([`keys::KeySource`]); the transport never stores it
//!   (§2.4).
//! * [`lifecycle`]: the bounded close (1 s), the close codes, and why nothing here reads
//!   stdin (§1 item 5).
//! * Feature `iroh` embeds iroh `=1.4.2` (TLS through ring) with the vendored, patched netdev
//!   (§1 items 1 and 3) and adds [`endpoint`] (the endpoint built from the policy alone),
//!   [`dial`] (the dialer) and [`serve`] (the server). Without the feature the crate has no
//!   iroh at all and [`availability`] fails closed with `driver_unavailable`.
//!
//! **Edges.** Production dependencies are `heimdall-contract` only among workspace crates;
//! the crate-graph step refuses any other workspace edge, and `heimdall-app` must never
//! import this crate.

pub mod admission;
pub mod keys;
pub mod lifecycle;
pub mod policy;
pub mod target;

#[cfg(feature = "iroh")]
pub mod dial;
#[cfg(feature = "iroh")]
pub mod endpoint;
#[cfg(feature = "iroh")]
pub mod serve;

#[cfg(all(test, feature = "iroh"))]
mod e2e_tests;

/// The application-layer protocol identifier (`/pigeons/0`) every connect and serve leg uses.
pub const ALPN: &[u8] = b"/pigeons/0";

/// Why the transport is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// No transport driver is compiled into this build (feature `iroh` is off).
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

/// Whether the transport driver is compiled in. Fails closed without feature `iroh`. A
/// compiled driver is not an offered capability: whether `transport-iroh/1` is offered is
/// the capability registry's decision (m06-plan U56).
///
/// # Errors
///
/// [`Unavailable::DriverUnavailable`] when the crate is built without feature `iroh`.
pub const fn availability() -> Result<(), Unavailable> {
    if cfg!(feature = "iroh") {
        Ok(())
    } else {
        Err(Unavailable::DriverUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_pigeons_0_and_availability_follows_the_feature() {
        assert_eq!(ALPN, b"/pigeons/0");
        if cfg!(feature = "iroh") {
            assert_eq!(availability(), Ok(()));
        } else {
            assert_eq!(availability(), Err(Unavailable::DriverUnavailable));
        }
        assert_eq!(
            Unavailable::DriverUnavailable.reason(),
            "driver_unavailable"
        );
    }
}
