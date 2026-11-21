//! The endpoint, built from the effective exposure policy alone (feature `iroh`; ADR-0012
//! §2.1, §2.2; G06 §5).
//!
//! [`plan_endpoint`] is the only place in the crate that configures what an endpoint may
//! contact. From the validated [`EffectivePolicy`] (and, for a dialer, the route record's
//! approved addresses) it sets:
//!
//! * `presets::Minimal` (the crypto provider only);
//! * the IP transports: none (relay-only), loopback (`127.0.0.1:0` required, `[::1]:0` where
//!   the host has it), one interface address, or the wildcard pair;
//! * the relay map: disabled, or exactly the policy's relays. The peer relay hints are the
//!   same set (never taken from anywhere else);
//! * address lookup and publishing: cleared (only `n0-public` would allow them, and the
//!   policy refuses it);
//! * the portmapper: disabled (and the `portmapper` feature is not compiled);
//! * the net report: no captive-portal check; HTTPS probes only toward the policy's relays
//!   (none without relays);
//! * the DNS resolver: no nameserver at all without relays; the system's without the
//!   public fallback tier with relays (iroh's default would fall back to public resolvers);
//! * no proxy (never `proxy_from_env`);
//! * a policy hook: a dialer refuses any connect whose address set is outside the approved
//!   route or whose ALPN is not `/pigeons/0`; a serving endpoint never dials.
//!
//! Nothing binds until the caller calls `bind`. The serving side adds its ALPN and its
//! admission hook on top; neither changes what the endpoint may contact.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use heimdall_contract::ids::IrohEndpointId;
use heimdall_contract::route::ExposurePolicy;
use iroh::dns::DnsResolver;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, BindOpts, Builder, Connection, EndpointHooks,
    PortmapperConfig, presets,
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, NetReportConfig, RelayMode, RelayUrl, TransportAddr,
};

use crate::ALPN;
use crate::lifecycle::{CLOSE_BOUND, bounded};
use crate::policy::{BindPlan, EffectivePolicy, PolicyError, RouteAddresses};

/// Which side the endpoint is.
#[derive(Debug, Clone, Copy)]
pub enum Role<'a> {
    /// A dialer to `peer` through the route record's addresses.
    Dial {
        /// The serving endpoint.
        peer: &'a IrohEndpointId,
        /// The route record's addresses and hints.
        route: &'a RouteAddresses,
    },
    /// A serving endpoint (never dials).
    Serve,
}

/// An endpoint builder configured from the policy, and (for a dialer) the peer address it
/// may connect to. Unbound.
#[derive(Debug)]
pub struct EndpointPlan {
    /// The builder. Add the secret key (and, serving, the ALPN and the admission hook), then
    /// bind.
    pub builder: Builder,
    /// The peer address (dialer only): the route's approved direct addresses and relay hints.
    pub peer: Option<EndpointAddr>,
}

/// Builds the endpoint builder from `policy` alone (and the route record's addresses).
///
/// # Errors
///
/// [`PolicyError`]: `relay_unapproved` / `route_unapproved` for a hint or address outside
/// the policy; `transport_unavailable` for a policy the endpoint cannot apply (including a
/// relay URL iroh does not accept and a peer ID that is not an endpoint key).
pub fn plan_endpoint(policy: &ExposurePolicy, role: Role<'_>) -> Result<EndpointPlan, PolicyError> {
    let effective = EffectivePolicy::from_contract(policy)?;
    let relays = parse_relays(effective.relays())?;

    let mut b = Endpoint::builder(presets::Minimal)
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
        .clear_ip_transports();
    debug_assert!(!effective.lookup_allowed());
    b = if relays.is_empty() {
        b.relay_mode(RelayMode::Disabled)
    } else {
        b.relay_mode(RelayMode::custom(relays.iter().cloned()))
    };
    b = bind_transports(b, effective.bind())?;
    b = if relays.is_empty() {
        b.net_report_config(NetReportConfig::minimal())
            .dns_resolver(DnsResolver::builder().disable_fallback().build())
    } else {
        let mut net_report = NetReportConfig::default();
        net_report.captive_portal_check = false;
        b.net_report_config(net_report).dns_resolver(
            DnsResolver::builder()
                .with_system_defaults()
                .disable_fallback()
                .build(),
        )
    };

    match role {
        Role::Serve => Ok(EndpointPlan {
            builder: b.hooks(PolicyHook::Serve),
            peer: None,
        }),
        Role::Dial { peer, route } => {
            let approved = effective.approve_route(route)?;
            let peer_id =
                iroh_id(peer).ok_or(PolicyError::unavailable("peer ID is not an endpoint key"))?;
            let hint_urls = parse_relays(approved.relays())?;
            let mut addr = EndpointAddr::new(peer_id);
            for d in approved.direct() {
                addr = addr.with_ip_addr(*d);
            }
            for r in &hint_urls {
                addr = addr.with_relay_url(r.clone());
            }
            let hook = PolicyHook::Dial {
                peer: peer_id,
                direct: approved.direct().iter().copied().collect(),
                relays: relays.into_iter().collect(),
            };
            Ok(EndpointPlan {
                builder: b.hooks(hook),
                peer: Some(addr),
            })
        }
    }
}

fn parse_relays(relays: &[String]) -> Result<Vec<RelayUrl>, PolicyError> {
    relays
        .iter()
        .map(|r| {
            RelayUrl::from_str(r).map_err(|_| PolicyError::unavailable("relay URL not accepted"))
        })
        .collect()
}

fn bind_transports(b: Builder, plan: BindPlan) -> Result<Builder, PolicyError> {
    let unavailable = |_| PolicyError::unavailable("bind address not accepted");
    let optional = BindOpts::default().set_is_required(false);
    Ok(match plan {
        BindPlan::None => b,
        BindPlan::Loopback => b
            .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(unavailable)?
            .bind_addr_with_opts(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), optional)
            .map_err(unavailable)?,
        BindPlan::Interface(ip) => b.bind_addr(SocketAddr::new(ip, 0)).map_err(unavailable)?,
        BindPlan::Wildcard => b
            .bind_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .map_err(unavailable)?
            .bind_addr_with_opts(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)), optional)
            .map_err(unavailable)?,
    })
}

/// The policy's own hook (defence in depth: `plan_endpoint` already built the peer address
/// from the approved route only).
#[derive(Debug)]
enum PolicyHook {
    Dial {
        peer: EndpointId,
        direct: BTreeSet<SocketAddr>,
        relays: BTreeSet<RelayUrl>,
    },
    Serve,
}

impl PolicyHook {
    fn allows(&self, remote: &EndpointAddr, alpn: &[u8]) -> bool {
        let Self::Dial {
            peer,
            direct,
            relays,
        } = self
        else {
            return false;
        };
        alpn == ALPN
            && remote.id == *peer
            && remote.addrs.iter().all(|a| match a {
                TransportAddr::Ip(sa) => direct.contains(sa),
                TransportAddr::Relay(url) => relays.contains(url),
                _ => false,
            })
    }
}

impl EndpointHooks for PolicyHook {
    fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> impl Future<Output = BeforeConnectOutcome> + Send + 'a {
        let allowed = self.allows(remote_addr, alpn);
        async move {
            if allowed {
                BeforeConnectOutcome::Accept
            } else {
                BeforeConnectOutcome::Reject
            }
        }
    }

    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        // A dialer accepts only the peer it dialed (iroh authenticates the ID through TLS;
        // this repeats the check). A serving endpoint's admission is the server's own hook.
        let ok = match self {
            Self::Dial { peer, .. } => conn.remote_id() == *peer && conn.alpn() == ALPN,
            Self::Serve => true,
        };
        async move {
            if ok {
                AfterHandshakeOutcome::Accept
            } else {
                AfterHandshakeOutcome::Reject {
                    error_code: crate::lifecycle::CLOSE_REFUSED.into(),
                    reason: b"unexpected peer".to_vec(),
                }
            }
        }
    }
}

/// The iroh endpoint ID for a contract ID (`None` when the 64 hex characters are not an
/// Ed25519 public key).
#[must_use]
pub fn iroh_id(id: &IrohEndpointId) -> Option<EndpointId> {
    EndpointId::from_str(id.as_str()).ok()
}

/// The contract ID for an iroh endpoint ID.
#[must_use]
pub fn contract_id(id: &EndpointId) -> Option<IrohEndpointId> {
    IrohEndpointId::parse(&id.to_string()).ok()
}

/// Closes `endpoint` within [`CLOSE_BOUND`]. Returns whether the close completed in time.
pub async fn close_bounded(endpoint: &Endpoint) -> bool {
    bounded(CLOSE_BOUND, endpoint.close()).await.is_some()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_contract::route::{BindScope, InfrastructureProfile};

    use super::*;
    use crate::keys::IrohSecret;
    use crate::policy::PolicyReason;

    fn peer() -> IrohEndpointId {
        IrohSecret::generate().endpoint_id().unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn reason_of(r: Result<EndpointPlan, PolicyError>) -> PolicyReason {
        r.map(|_| ()).unwrap_err().reason
    }

    /// The dialer's peer address is the approved route only: the route's loopback addresses,
    /// no relay under the minimal policy.
    #[test]
    fn dial_plan_peer_address_comes_from_the_approved_route() {
        let p = peer();
        let route = RouteAddresses {
            direct: vec![sa("127.0.0.1:7000")],
            relay_hints: vec![],
        };
        let plan = plan_endpoint(
            &ExposurePolicy::default(),
            Role::Dial {
                peer: &p,
                route: &route,
            },
        )
        .unwrap();
        let addr = plan.peer.unwrap();
        assert_eq!(contract_id(&addr.id).unwrap(), p);
        assert_eq!(
            addr.addrs.iter().cloned().collect::<Vec<_>>(),
            vec![TransportAddr::Ip(sa("127.0.0.1:7000"))]
        );
    }

    /// ADR-0012 §2.1: a hint, address or relay outside the policy is refused before any
    /// builder exists; so is a policy the endpoint cannot apply.
    #[test]
    fn plan_refuses_hints_addresses_and_relays_outside_the_policy() {
        let p = peer();
        let custom = ExposurePolicy {
            bind: BindScope::Loopback,
            infrastructure: InfrastructureProfile::Custom {
                relays: vec!["https://relay.example.test/".into()],
            },
            direct_fallback: false,
        };
        let outside_hint = RouteAddresses {
            direct: vec![],
            relay_hints: vec!["https://elsewhere.example.test/".into()],
        };
        assert_eq!(
            reason_of(plan_endpoint(
                &custom,
                Role::Dial {
                    peer: &p,
                    route: &outside_hint
                }
            )),
            PolicyReason::RelayUnapproved
        );
        let outside_addr = RouteAddresses {
            direct: vec![sa("192.0.2.1:7000")],
            relay_hints: vec![],
        };
        assert_eq!(
            reason_of(plan_endpoint(
                &ExposurePolicy::default(),
                Role::Dial {
                    peer: &p,
                    route: &outside_addr
                }
            )),
            PolicyReason::RouteUnapproved
        );
        let n0 = ExposurePolicy {
            bind: BindScope::Loopback,
            infrastructure: InfrastructureProfile::N0Public,
            direct_fallback: false,
        };
        assert_eq!(
            reason_of(plan_endpoint(&n0, Role::Serve)),
            PolicyReason::TransportUnavailable
        );
        // A peer ID that is 64 hex characters but not an Ed25519 point.
        let not_a_key = (0u8..=255)
            .map(|b| IrohEndpointId::parse(&format!("{b:02x}").repeat(32)).unwrap())
            .find(|id| iroh_id(id).is_none())
            .expect("some repeated-byte string is not a curve point");
        let route = RouteAddresses {
            direct: vec![sa("127.0.0.1:7000")],
            relay_hints: vec![],
        };
        assert_eq!(
            reason_of(plan_endpoint(
                &ExposurePolicy::default(),
                Role::Dial {
                    peer: &not_a_key,
                    route: &route
                }
            )),
            PolicyReason::TransportUnavailable
        );
        // The custom relay map and its hints are built (nothing binds or contacts a relay).
        let plan = plan_endpoint(
            &custom,
            Role::Dial {
                peer: &p,
                route: &RouteAddresses::default(),
            },
        )
        .unwrap();
        let relays: Vec<_> = plan.peer.unwrap().relay_urls().cloned().collect();
        assert_eq!(
            relays,
            vec![RelayUrl::from_str("https://relay.example.test/").unwrap()]
        );
    }

    /// The dialer's policy hook refuses a connect outside the approved route (defence in
    /// depth for any connect that does not go through `plan_endpoint`'s peer address).
    #[test]
    fn dial_hook_refuses_addresses_outside_the_route() {
        let p = iroh_id(&peer()).unwrap();
        let hook = PolicyHook::Dial {
            peer: p,
            direct: [sa("127.0.0.1:7000")].into_iter().collect(),
            relays: BTreeSet::new(),
        };
        let ok = EndpointAddr::new(p).with_ip_addr(sa("127.0.0.1:7000"));
        assert!(hook.allows(&ok, ALPN));
        assert!(!hook.allows(&ok, b"/other/0"));
        assert!(!hook.allows(
            &EndpointAddr::new(p).with_ip_addr(sa("127.0.0.1:7001")),
            ALPN
        ));
        assert!(
            !hook.allows(
                &ok.clone()
                    .with_relay_url(RelayUrl::from_str("https://relay.example.test/").unwrap()),
                ALPN
            )
        );
        let other = iroh_id(&peer()).unwrap();
        assert!(!hook.allows(
            &EndpointAddr::new(other).with_ip_addr(sa("127.0.0.1:7000")),
            ALPN
        ));
        assert!(!PolicyHook::Serve.allows(&ok, ALPN));
    }
}
