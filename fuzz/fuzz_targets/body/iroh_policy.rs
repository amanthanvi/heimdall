//! Boundary 14 (ADR-0014 §2.1), allow-list and hint parsing in `transport-iroh`: an exposure
//! policy, a route record's direct addresses and relay hints, and the peers of a serve
//! allowlist, built from attacker-chosen text and checked by the public
//! `heimdall_transport_iroh::policy::EffectivePolicy::{from_contract, approve_route}`,
//! `heimdall_contract::ids::IrohEndpointId::parse` and
//! `heimdall_transport_iroh::admission::Allowlist`.
//!
//! The input is lines: the first is the bind (`none`, `loopback`, `wildcard`, or
//! `interface <address>`); `fallback` sets the direct-fallback consent; `port <n>` names the
//! serve port; `n0` selects the public profile; `relay <url>` adds a policy relay; `hint <url>`
//! a route relay hint; `direct <socket address>` a route address; `peer <id>` an allowlist
//! entry. The invariants (ADR-0012 §2.1, §2.3 item 1): an approved route uses only the
//! policy's relays and only unicast addresses with a port inside the policy's bind scope,
//! never an empty path; an allowlist holds exactly the parsed peers.
//!
//! Shared by the fuzz target `iroh_policy` and the seed test
//! `tests/adversarial/m08_fuzz_seeds_iroh.rs`.

use std::net::SocketAddr;

use heimdall_contract::ids::IrohEndpointId;
use heimdall_contract::route::{BindScope, ExposurePolicy, InfrastructureProfile};
use heimdall_transport_iroh::admission::Allowlist;
use heimdall_transport_iroh::policy::{BindPlan, EffectivePolicy, RouteAddresses};

/// What the input reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reached {
    /// The input is not UTF-8.
    NotText,
    /// The policy was refused.
    PolicyRefused,
    /// The policy was accepted and the route refused.
    RouteRefused,
    /// The route was approved.
    RouteApproved,
}

/// Build and check the policy, route and allowlist of `data` (module docs); panics (a finding)
/// when an invariant breaks.
pub fn run(data: &[u8]) -> Reached {
    let Ok(text) = std::str::from_utf8(data) else {
        return Reached::NotText;
    };
    let mut lines = text.lines();
    let bind = match lines.next().map(str::trim) {
        Some("none") => BindScope::None,
        Some("wildcard") => BindScope::Wildcard,
        Some(l) if l.starts_with("interface ") => BindScope::Interface {
            address: l.trim_start_matches("interface ").to_owned(),
        },
        _ => BindScope::Loopback,
    };
    let (mut relays, mut hints, mut direct, mut peers) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut fallback, mut n0, mut port) = (false, false, None);
    for line in lines {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "fallback" => fallback = true,
            "n0" => n0 = true,
            "port" => port = value.parse::<u16>().ok(),
            "relay" => relays.push(value.to_owned()),
            "hint" => hints.push(value.to_owned()),
            "direct" => direct.extend(value.parse::<SocketAddr>().ok()),
            "peer" => peers.extend(IrohEndpointId::parse(value).ok()),
            _ => {}
        }
    }
    if let Ok(list) = Allowlist::new(peers.clone()) {
        assert!(
            peers.iter().all(|p| list.contains(p)) && list.iter().count() <= peers.len(),
            "an allowlist that is not its peers"
        );
    } else {
        assert!(peers.is_empty(), "a nonempty allowlist was refused");
    }
    let infrastructure = if n0 {
        InfrastructureProfile::N0Public
    } else if relays.is_empty() {
        InfrastructureProfile::None
    } else {
        InfrastructureProfile::Custom { relays }
    };
    let policy = ExposurePolicy {
        bind,
        infrastructure,
        direct_fallback: fallback,
        port,
        sshd_port: heimdall_contract::route::DEFAULT_SSHD_PORT,
    };
    let Ok(effective) = EffectivePolicy::from_contract(&policy) else {
        return Reached::PolicyRefused;
    };
    let route = RouteAddresses {
        direct,
        relay_hints: hints,
    };
    let Ok(approved) = effective.approve_route(&route) else {
        return Reached::RouteRefused;
    };
    assert!(
        approved
            .relays()
            .iter()
            .all(|r| effective.relays().contains(r)),
        "a relay hint outside the policy was approved"
    );
    assert!(
        !approved.direct().is_empty() || !approved.relays().is_empty(),
        "a route with no path was approved"
    );
    for addr in approved.direct() {
        let ip = addr.ip();
        assert!(
            addr.port() != 0
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && route.direct.contains(addr),
            "a direct address that is not a unicast endpoint of the route"
        );
        match effective.bind() {
            BindPlan::None => panic!("a direct address under a relay-only bind"),
            BindPlan::Loopback => assert!(
                ip.is_loopback(),
                "a non-loopback address under a loopback bind"
            ),
            BindPlan::Interface(bound) => {
                assert_eq!(
                    ip.is_ipv4(),
                    bound.is_ipv4(),
                    "an address of the other family"
                );
            }
            BindPlan::Wildcard => {}
        }
    }
    Reached::RouteApproved
}
