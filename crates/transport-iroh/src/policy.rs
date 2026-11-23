//! The effective exposure policy, validated (ADR-0012 §2.1, §2.2; G06 §5). Pure: no iroh, no
//! I/O, so the default build checks the same rules the `iroh` build applies.
//!
//! [`EffectivePolicy::from_contract`] is the only way from a contract [`ExposurePolicy`] to
//! the values an endpoint is built from: its bind, its relay set (which is both the endpoint's
//! relay map and every peer relay hint) and whether learned addresses may be used.
//! [`EffectivePolicy::approve_route`] checks a route record's direct addresses and relay hints
//! against it. Anything outside the policy is refused with `relay_unapproved` or
//! `route_unapproved`; a policy this endpoint cannot apply is refused with
//! `transport_unavailable`. Address lookup is never allowed: only `n0-public` would allow it,
//! and that profile is refused here (outside V1 until m06-plan U56's capture row runs).

use std::net::{IpAddr, SocketAddr};

use heimdall_contract::envelope::reason;
use heimdall_contract::route::{BindScope, ExposurePolicy, InfrastructureProfile};

/// Which refusal reason a policy failure maps to (the contract's reason tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyReason {
    /// A relay or peer relay hint outside the policy's relay set.
    RelayUnapproved,
    /// A direct address or hint outside the policy, or no approved path at all.
    RouteUnapproved,
    /// A policy the endpoint cannot apply.
    TransportUnavailable,
}

impl PolicyReason {
    /// The stable reason token (`envelope::reason`).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::RelayUnapproved => reason::RELAY_UNAPPROVED,
            Self::RouteUnapproved => reason::ROUTE_UNAPPROVED,
            Self::TransportUnavailable => reason::TRANSPORT_UNAVAILABLE,
        }
    }
}

/// A refused policy, hint or address. The detail is a fixed text: it never echoes a URL or
/// an address (a relay URL may carry credentials).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyError {
    /// The refusal reason.
    pub reason: PolicyReason,
    /// What was refused (fixed text).
    pub detail: &'static str,
}

impl PolicyError {
    pub(crate) const fn relay(detail: &'static str) -> Self {
        Self {
            reason: PolicyReason::RelayUnapproved,
            detail,
        }
    }
    pub(crate) const fn route(detail: &'static str) -> Self {
        Self {
            reason: PolicyReason::RouteUnapproved,
            detail,
        }
    }
    pub(crate) const fn unavailable(detail: &'static str) -> Self {
        Self {
            reason: PolicyReason::TransportUnavailable,
            detail,
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason.token(), self.detail)
    }
}

impl std::error::Error for PolicyError {}

/// Where the endpoint's IP transports bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindPlan {
    /// No IP transport at all (relay-only).
    None,
    /// `127.0.0.1:0`, and `[::1]:0` where the host has it (the default).
    Loopback,
    /// One interface address, port 0 (a consented widening unless it is a loopback address).
    Interface(IpAddr),
    /// `0.0.0.0:0` and `[::]:0` (a consented widening).
    Wildcard,
}

impl BindPlan {
    /// Whether every socket this plan binds is a loopback socket (or there is none).
    #[must_use]
    pub fn is_loopback_only(self) -> bool {
        match self {
            Self::None | Self::Loopback => true,
            Self::Interface(ip) => ip.is_loopback(),
            Self::Wildcard => false,
        }
    }
}

/// The addresses a route record gives for a peer (ADR-0012 §2.1: "direct paths only to the
/// route record's own addresses").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteAddresses {
    /// The peer's direct addresses.
    pub direct: Vec<SocketAddr>,
    /// Peer relay hints. Each must be one of the policy's relays; when empty, every relay of
    /// the policy is the hint (the hint is never taken from anywhere but the policy).
    pub relay_hints: Vec<String>,
}

/// A route's approved dial targets: every direct address and relay hint is inside the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedRoute {
    direct: Vec<SocketAddr>,
    relays: Vec<String>,
}

impl ApprovedRoute {
    /// The approved direct addresses.
    #[must_use]
    pub fn direct(&self) -> &[SocketAddr] {
        &self.direct
    }

    /// The approved peer relay hints (a subset of the policy's relays).
    #[must_use]
    pub fn relays(&self) -> &[String] {
        &self.relays
    }
}

/// A contract [`ExposurePolicy`] this endpoint can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    bind: BindPlan,
    relays: Vec<String>,
    direct_fallback: bool,
    port: Option<u16>,
}

impl EffectivePolicy {
    /// Validates `policy` (ADR-0012 §2.1, §2.2).
    ///
    /// # Errors
    ///
    /// `transport_unavailable` for a policy this endpoint cannot apply:
    /// * `n0-public` (outside V1 until its capture row runs; m06-plan U56);
    /// * a `custom` profile without relays, or with a relay that is not a plain `https://`
    ///   or `http://` URL with a host and no credentials;
    /// * a relay-only bind with no relay (no transport at all);
    /// * an interface address that is not a unicast IP address;
    /// * a non-loopback bind (interface or wildcard) without the direct-fallback consent:
    ///   iroh 1.4.2's NAT traversal cannot be switched off through its public builder, so on
    ///   a non-loopback socket an address the peer advertises could be used. On a loopback
    ///   socket it cannot (a loopback socket reaches loopback only);
    /// * a bind scope or profile this build does not know;
    /// * ⟨rev6.3⟩ a named port `0`, or a named port with a relay-only bind (nothing to bind
    ///   it on).
    pub fn from_contract(policy: &ExposurePolicy) -> Result<Self, PolicyError> {
        if !policy.port_is_valid() {
            return Err(PolicyError::unavailable("port 0 is not a serve port"));
        }
        let relays = match &policy.infrastructure {
            InfrastructureProfile::None => Vec::new(),
            InfrastructureProfile::Custom { relays } => {
                if relays.is_empty() {
                    return Err(PolicyError::unavailable("custom profile without relays"));
                }
                let mut out: Vec<String> = Vec::with_capacity(relays.len());
                for relay in relays {
                    if !relay_url_is_plain(relay) {
                        return Err(PolicyError::unavailable("malformed relay URL"));
                    }
                    if !out.contains(relay) {
                        out.push(relay.clone());
                    }
                }
                out
            }
            InfrastructureProfile::N0Public => {
                return Err(PolicyError::unavailable(
                    "n0-public is outside V1 until its capture row runs",
                ));
            }
            _ => return Err(PolicyError::unavailable("unknown infrastructure profile")),
        };
        let bind = match &policy.bind {
            BindScope::None => {
                if relays.is_empty() {
                    return Err(PolicyError::unavailable("relay-only bind with no relay"));
                }
                BindPlan::None
            }
            BindScope::Loopback => BindPlan::Loopback,
            BindScope::Interface { address } => {
                let ip: IpAddr = address
                    .parse()
                    .map_err(|_| PolicyError::unavailable("interface address is not an IP"))?;
                if ip.is_unspecified() || ip.is_multicast() || is_broadcast(ip) {
                    return Err(PolicyError::unavailable(
                        "interface address is not a unicast address",
                    ));
                }
                BindPlan::Interface(ip)
            }
            BindScope::Wildcard => BindPlan::Wildcard,
            _ => return Err(PolicyError::unavailable("unknown bind scope")),
        };
        if policy.port.is_some() && bind == BindPlan::None {
            return Err(PolicyError::unavailable(
                "a named port needs an IP bind (the policy is relay-only)",
            ));
        }
        if !bind.is_loopback_only() && !policy.direct_fallback {
            return Err(PolicyError::unavailable(
                "a non-loopback bind cannot keep learned addresses out without direct fallback",
            ));
        }
        Ok(Self {
            bind,
            relays,
            direct_fallback: policy.direct_fallback,
            port: policy.port,
        })
    }

    /// ⟨rev6.3⟩ The serve port the policy names (ADR-0012 §2.1 ⟨2026-11-21⟩); `None`: any
    /// (the runtime then supplies the recorded one, or `0` at the first bind). A dialer
    /// always binds an ephemeral port.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The bind.
    #[must_use]
    pub fn bind(&self) -> BindPlan {
        self.bind
    }

    /// The relay set: the endpoint's relay map and the only source of peer relay hints.
    #[must_use]
    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// Whether learned (lookup or hole-punched) addresses may be used.
    #[must_use]
    pub fn direct_fallback(&self) -> bool {
        self.direct_fallback
    }

    /// Whether address lookup or publishing may be configured. Always `false`: only
    /// `n0-public` allows it, and [`Self::from_contract`] refuses that profile.
    #[must_use]
    pub fn lookup_allowed(&self) -> bool {
        false
    }

    /// Checks a route record's addresses and hints against the policy.
    ///
    /// # Errors
    ///
    /// * `relay_unapproved`: a relay hint that is not one of the policy's relays;
    /// * `route_unapproved`: a direct address under a relay-only bind; a non-loopback
    ///   address under a loopback bind; an address of the other family than an interface
    ///   bind; port 0, an unspecified, multicast or broadcast address; or no approved path
    ///   at all (no address and no relay).
    pub fn approve_route(&self, route: &RouteAddresses) -> Result<ApprovedRoute, PolicyError> {
        let relays = if route.relay_hints.is_empty() {
            self.relays.clone()
        } else {
            let mut out: Vec<String> = Vec::with_capacity(route.relay_hints.len());
            for hint in &route.relay_hints {
                if !self.relays.contains(hint) {
                    return Err(PolicyError::relay("relay hint outside the policy"));
                }
                if !out.contains(hint) {
                    out.push(hint.clone());
                }
            }
            out
        };
        let mut direct: Vec<SocketAddr> = Vec::with_capacity(route.direct.len());
        for addr in &route.direct {
            let ip = addr.ip();
            if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() || is_broadcast(ip) {
                return Err(PolicyError::route(
                    "direct address is not a unicast endpoint",
                ));
            }
            let allowed = match self.bind {
                BindPlan::None => false,
                BindPlan::Loopback => ip.is_loopback(),
                BindPlan::Interface(bound) if bound.is_loopback() => {
                    ip.is_loopback() && ip.is_ipv4() == bound.is_ipv4()
                }
                BindPlan::Interface(bound) => ip.is_ipv4() == bound.is_ipv4(),
                BindPlan::Wildcard => true,
            };
            if !allowed {
                return Err(PolicyError::route(
                    "direct address outside the policy's bind scope",
                ));
            }
            if !direct.contains(addr) {
                direct.push(*addr);
            }
        }
        if direct.is_empty() && relays.is_empty() {
            return Err(PolicyError::route("no approved address or relay"));
        }
        Ok(ApprovedRoute { direct, relays })
    }
}

fn is_broadcast(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

/// A plain relay URL: `https://` or `http://` (a private development relay), a nonempty
/// host, no credentials, no whitespace or control characters. iroh's own parser runs on top
/// under feature `iroh`.
fn relay_url_is_plain(url: &str) -> bool {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@') && !authority.starts_with(':')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn policy(bind: BindScope, infrastructure: InfrastructureProfile, fb: bool) -> ExposurePolicy {
        ExposurePolicy {
            bind,
            infrastructure,
            direct_fallback: fb,
            ..ExposurePolicy::default()
        }
    }

    fn custom(relays: &[&str]) -> InfrastructureProfile {
        InfrastructureProfile::Custom {
            relays: relays.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// The default policy is the minimal one: loopback bind, no relay, no lookup.
    /// ⟨rev6.3; ADR-0012 §2.1 ⟨2026-11-21⟩⟩ A named serve port is kept for the serving
    /// endpoint; `0`, or a named port with nothing to bind it on (relay-only), is refused
    /// `transport_unavailable`.
    #[test]
    fn a_named_serve_port_is_kept_and_zero_or_relay_only_is_refused() {
        let named = ExposurePolicy {
            port: Some(4433),
            ..policy(BindScope::Loopback, InfrastructureProfile::None, false)
        };
        assert_eq!(
            EffectivePolicy::from_contract(&named).unwrap().port(),
            Some(4433)
        );
        let zero = ExposurePolicy {
            port: Some(0),
            ..named.clone()
        };
        let relay_only = ExposurePolicy {
            port: Some(4433),
            ..policy(
                BindScope::None,
                custom(&["https://relay.example.test/"]),
                false,
            )
        };
        for refused in [zero, relay_only] {
            assert_eq!(
                EffectivePolicy::from_contract(&refused).unwrap_err().reason,
                PolicyReason::TransportUnavailable
            );
        }
        let any = policy(BindScope::Loopback, InfrastructureProfile::None, false);
        assert_eq!(EffectivePolicy::from_contract(&any).unwrap().port(), None);
    }

    #[test]
    fn minimal_policy_is_loopback_without_relays_or_lookup() {
        let p = EffectivePolicy::from_contract(&ExposurePolicy::default()).unwrap();
        assert_eq!(p.bind(), BindPlan::Loopback);
        assert!(p.relays().is_empty());
        assert!(!p.direct_fallback());
        assert!(!p.lookup_allowed());
    }

    /// ADR-0012 §2.1: a relay hint outside the policy is refused (`relay_unapproved`), under
    /// a custom profile and under the direct-only profile alike.
    #[test]
    fn relay_hint_outside_policy_is_refused() {
        let p = EffectivePolicy::from_contract(&policy(
            BindScope::Loopback,
            custom(&["https://relay.example.test/"]),
            false,
        ))
        .unwrap();
        let err = p
            .approve_route(&RouteAddresses {
                direct: vec![],
                relay_hints: vec!["https://other.example.test/".into()],
            })
            .unwrap_err();
        assert_eq!(err.reason, PolicyReason::RelayUnapproved);
        assert_eq!(err.reason.token(), "relay_unapproved");
        // Exact match only: a spelling the policy does not hold is outside it.
        let err = p
            .approve_route(&RouteAddresses {
                direct: vec![],
                relay_hints: vec!["https://relay.example.test".into()],
            })
            .unwrap_err();
        assert_eq!(err.reason, PolicyReason::RelayUnapproved);
        let direct_only = EffectivePolicy::from_contract(&ExposurePolicy::default()).unwrap();
        let err = direct_only
            .approve_route(&RouteAddresses {
                direct: vec![sa("127.0.0.1:7000")],
                relay_hints: vec!["https://relay.example.test/".into()],
            })
            .unwrap_err();
        assert_eq!(err.reason, PolicyReason::RelayUnapproved);
    }

    /// Without hints, the hint set is the policy's relay set, never anything else.
    #[test]
    fn relay_hints_default_to_the_policy_relays() {
        let p = EffectivePolicy::from_contract(&policy(
            BindScope::None,
            custom(&["https://a.example.test/", "https://b.example.test/"]),
            false,
        ))
        .unwrap();
        let r = p.approve_route(&RouteAddresses::default()).unwrap();
        assert_eq!(
            r.relays(),
            &["https://a.example.test/", "https://b.example.test/"]
        );
        assert!(r.direct().is_empty());
        let r = p
            .approve_route(&RouteAddresses {
                direct: vec![],
                relay_hints: vec!["https://b.example.test/".into()],
            })
            .unwrap();
        assert_eq!(r.relays(), &["https://b.example.test/"]);
    }

    /// ADR-0012 §2.1: a direct address outside the policy is refused (`route_unapproved`).
    #[test]
    fn address_outside_policy_is_refused() {
        let loopback = EffectivePolicy::from_contract(&ExposurePolicy::default()).unwrap();
        for bad in [
            "192.0.2.10:7000",
            "[2001:db8::1]:7000",
            "[::ffff:127.0.0.1]:7000",
        ] {
            let err = loopback
                .approve_route(&RouteAddresses {
                    direct: vec![sa(bad)],
                    relay_hints: vec![],
                })
                .unwrap_err();
            assert_eq!(err.reason, PolicyReason::RouteUnapproved, "{bad}");
            assert_eq!(err.reason.token(), "route_unapproved");
        }
        for bad in [
            "127.0.0.1:0",
            "0.0.0.0:7000",
            "[::]:7000",
            "224.0.0.1:7000",
            "255.255.255.255:7000",
        ] {
            let err = loopback
                .approve_route(&RouteAddresses {
                    direct: vec![sa(bad)],
                    relay_hints: vec![],
                })
                .unwrap_err();
            assert_eq!(err.reason, PolicyReason::RouteUnapproved, "{bad}");
        }
        let ok = loopback
            .approve_route(&RouteAddresses {
                direct: vec![sa("127.0.0.1:7000"), sa("[::1]:7000"), sa("127.0.0.1:7000")],
                relay_hints: vec![],
            })
            .unwrap();
        assert_eq!(ok.direct(), &[sa("127.0.0.1:7000"), sa("[::1]:7000")]);
        // Relay-only: no direct address is inside the policy.
        let relay_only = EffectivePolicy::from_contract(&policy(
            BindScope::None,
            custom(&["https://relay.example.test/"]),
            false,
        ))
        .unwrap();
        let err = relay_only
            .approve_route(&RouteAddresses {
                direct: vec![sa("127.0.0.1:7000")],
                relay_hints: vec![],
            })
            .unwrap_err();
        assert_eq!(err.reason, PolicyReason::RouteUnapproved);
        // Nothing to dial at all.
        let err = loopback
            .approve_route(&RouteAddresses::default())
            .unwrap_err();
        assert_eq!(err.reason, PolicyReason::RouteUnapproved);
        // An interface bind admits its own family only.
        let iface = EffectivePolicy::from_contract(&policy(
            BindScope::Interface {
                address: "192.0.2.5".into(),
            },
            InfrastructureProfile::None,
            true,
        ))
        .unwrap();
        assert!(
            iface
                .approve_route(&RouteAddresses {
                    direct: vec![sa("192.0.2.10:7000")],
                    relay_hints: vec![]
                })
                .is_ok()
        );
        assert_eq!(
            iface
                .approve_route(&RouteAddresses {
                    direct: vec![sa("[2001:db8::1]:7000")],
                    relay_hints: vec![]
                })
                .unwrap_err()
                .reason,
            PolicyReason::RouteUnapproved
        );
    }

    /// ADR-0012 §2.1, §2.2: a relay outside what the endpoint can apply, and a policy it
    /// cannot apply, are refused (`transport_unavailable`); a route never falls back to a
    /// profile it does not name.
    #[test]
    fn policy_the_endpoint_cannot_apply_is_refused() {
        let cases = [
            policy(BindScope::Loopback, InfrastructureProfile::N0Public, false),
            policy(BindScope::Loopback, custom(&[]), false),
            policy(BindScope::Loopback, custom(&["relay.example.test"]), false),
            policy(
                BindScope::Loopback,
                custom(&["ftp://relay.example.test/"]),
                false,
            ),
            policy(
                BindScope::Loopback,
                custom(&["https://user:pw@relay.example.test/"]),
                false,
            ),
            policy(BindScope::Loopback, custom(&["https:///path"]), false),
            policy(BindScope::Loopback, custom(&["https://a b/"]), false),
            policy(BindScope::None, InfrastructureProfile::None, false),
            policy(
                BindScope::Interface {
                    address: "not-an-ip".into(),
                },
                InfrastructureProfile::None,
                true,
            ),
            policy(
                BindScope::Interface {
                    address: "0.0.0.0".into(),
                },
                InfrastructureProfile::None,
                true,
            ),
            policy(
                BindScope::Interface {
                    address: "192.0.2.5".into(),
                },
                InfrastructureProfile::None,
                false,
            ),
            policy(BindScope::Wildcard, InfrastructureProfile::None, false),
        ];
        for case in cases {
            let err = EffectivePolicy::from_contract(&case).unwrap_err();
            assert_eq!(err.reason, PolicyReason::TransportUnavailable, "{case:?}");
            assert_eq!(err.reason.token(), "transport_unavailable");
            // The detail never echoes the policy's URLs or addresses.
            assert!(!err.to_string().contains("example.test"), "{err}");
            assert!(!err.to_string().contains("pw"), "{err}");
        }
        // Loopback interface addresses need no fallback consent; wildcard with it is applied.
        assert!(
            EffectivePolicy::from_contract(&policy(
                BindScope::Interface {
                    address: "::1".into()
                },
                InfrastructureProfile::None,
                false
            ))
            .is_ok()
        );
        assert_eq!(
            EffectivePolicy::from_contract(&policy(
                BindScope::Wildcard,
                InfrastructureProfile::None,
                true
            ))
            .unwrap()
            .bind(),
            BindPlan::Wildcard
        );
    }
}
