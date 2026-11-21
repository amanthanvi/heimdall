//! Heimdall's Iroh transport (M06 U0 skeleton; ADR-0012 §1, §2, §13).
//!
//! **Skeleton.** The `connect` and `serve` legs and the exposure policy land in M06 U2 onward.
//! Until then the default build has no iroh at all and the only entry point is
//! [`availability`], which fails closed with [`Unavailable::DriverUnavailable`].
//!
//! * [`ALPN`] is the wire protocol's identifier: Pigeons' `/pigeons/0`, one bidirectional
//!   stream of raw SSH bytes (§1 item 2).
//! * Feature `iroh` embeds iroh `=1.4.2` (TLS through ring) with the vendored, patched netdev
//!   (§1 items 1 and 3). The `endpoint` module under that feature only constructs an endpoint
//!   builder so the feature stays compile-checked (`tools/validation/check.sh`, step
//!   `iroh-check`); it binds nothing and opens no socket.
//!
//! **Edges.** Production dependencies are `heimdall-contract` only; the crate-graph step refuses
//! any other workspace edge, and `heimdall-app` must never import this crate.

#[cfg(feature = "iroh")]
pub mod endpoint;

/// The application-layer protocol identifier (`/pigeons/0`) every connect and serve leg uses.
pub const ALPN: &[u8] = b"/pigeons/0";

/// Why the transport is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// No transport driver is implemented in this build.
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

/// Whether the transport is available. Fails closed: always unavailable until M06 U2+ land.
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
    fn alpn_is_pigeons_0_and_availability_fails_closed() {
        assert_eq!(ALPN, b"/pigeons/0");
        assert_eq!(availability(), Err(Unavailable::DriverUnavailable));
        assert_eq!(
            Unavailable::DriverUnavailable.reason(),
            "driver_unavailable"
        );
    }
}
