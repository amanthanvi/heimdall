//! The endpoint builder under feature `iroh` (ADR-0012 §1, §2.1; M06 U0 compile check).
//!
//! Constructs, and never binds, an iroh endpoint builder in the most closed configuration:
//! the minimal preset, relays disabled, address lookup cleared and the portmapper disabled.
//! It exists so the iroh dependency tree and the vendored netdev patch stay compile-checked;
//! the real exposure-policy-driven construction lands in M06 U2.

use iroh::endpoint::{Builder, PortmapperConfig, presets};
use iroh::{Endpoint, RelayMode};

/// An endpoint builder that contacts nothing: no relay, no address lookup, no portmapper.
///
/// Not bound: building the builder opens no socket. Calling `bind` on it is the caller's act.
#[must_use]
pub fn closed_builder() -> Builder {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
}
