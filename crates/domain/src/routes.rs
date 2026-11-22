//! ⟨M06 U5a⟩ A destination's ordered approved routes (ADR-0012 §5.1, §5.3, §9 item 9;
//! m06-plan U5a). Pure.
//!
//! **The model.** A destination holds an ordered list of approved routes
//! (`heimdall_contract::route::DestinationRoute`: `direct{host, port}`, `jump{via}`,
//! `iroh{endpoint, …}`), most preferred first. A route is reachability data only: it grants
//! nothing and never changes host identity.
//!
//! **The one-element case.** The existing single route and jump fields of a managed
//! definition (`HostName`/`Port`, and M04's `jump`) are the one-element list
//! ([`approved_routes`]): a destination with no stored list has exactly that one route, with a
//! deterministic ID ([`implicit_route_id`]). Nothing is added to [`DestinationRecord`] or
//! [`DestinationDefinition`], so every stored destination, request hash and golden stays
//! byte-identical; a stored list (the W0 table `destination_routes`, read into
//! [`RouteCatalogView::routes`](crate::catalog::RouteCatalogView::routes)) replaces the
//! one-element list when it is non-empty.
//!
//! **Rendering** ([`rendering_of`], ADR-0012 §5.3): one direct or jump route keeps its native
//! rendering (`HostName`/`Port`, or ADR-0010's single-hop `ProxyJump`); more than one route, or
//! any Iroh route, renders Heimdall's own route helper (the narrow ADR-0010 §5(b) exception).
//!
//! **Host identity** ([`host_key_alias`]): every route of a destination is checked against
//! the same catalog pin, looked up under `HostKeyAlias hm-dest-<id>`.

use std::time::Duration;

use heimdall_contract::ids::{DestinationId, RouteId};
use heimdall_contract::route::{DEFAULT_IDENTIFICATION_TIMEOUT_MS, DestinationRoute, RouteSpec};
use sha2::{Digest, Sha256};

use crate::catalog::{DestinationDefinition, DestinationRecord, RouteCatalogView, RouteRefusal};

/// The `HostKeyAlias` prefix of a destination's catalog pin (ADR-0012 §5.2).
pub const HOST_KEY_ALIAS_PREFIX: &str = "hm-dest-";

/// Bound on pre-identification bytes the helper buffers (ADR-0012 §5.5 item 1).
pub const PRE_IDENTIFICATION_MAX_BYTES: usize = 8 * 1024;

/// Bound on pre-identification lines the helper buffers (ADR-0012 §5.5 item 1).
pub const PRE_IDENTIFICATION_MAX_LINES: usize = 32;

/// The `HostKeyAlias` of `destination`'s catalog pin: `hm-dest-<id>`. `None` for an ID that
/// cannot be written as a plain known-hosts name (a `:`, which OpenSSH reads as a port
/// separator in `[host]:port` forms, or more than 255 bytes in all): such a destination
/// cannot be rendered with a pin, so it gets no helper rendering (fail closed).
#[must_use]
pub fn host_key_alias(destination: &DestinationId) -> Option<String> {
    let id = destination.as_str();
    let ok = !id.is_empty()
        && HOST_KEY_ALIAS_PREFIX.len() + id.len() <= 255
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then(|| format!("{HOST_KEY_ALIAS_PREFIX}{id}"))
}

/// The ID of the one-element route of `destination` (the route its definition states):
/// `route_` and the first 32 hex digits of SHA-256 over a fixed label and the destination
/// ID. Deterministic, so a route-health result names the same route across runs.
#[must_use]
pub fn implicit_route_id(destination: &DestinationId) -> RouteId {
    let mut h = Sha256::new();
    h.update(b"heimdall.route.implicit.v1\0");
    h.update(destination.as_str().as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    RouteId::from_random_bytes(bytes)
}

/// The approved routes of `record`, most preferred first: `stored` when it is non-empty;
/// otherwise the one-element list of a managed definition (`direct{hostname, port}`, or
/// `jump{via}` for M04's single-hop jump); an observed destination has none (Heimdall renders
/// and routes nothing for it).
#[must_use]
pub fn approved_routes(
    record: &DestinationRecord,
    stored: Option<&[DestinationRoute]>,
) -> Vec<DestinationRoute> {
    if let Some(list) = stored.filter(|l| !l.is_empty()) {
        return list.to_vec();
    }
    match &record.definition {
        DestinationDefinition::Managed {
            hostname,
            port,
            jump,
            ..
        } => {
            let route = match jump {
                Some(via) => RouteSpec::Jump { via: via.clone() },
                None => RouteSpec::Direct {
                    host: hostname.clone(),
                    port: *port,
                },
            };
            vec![DestinationRoute {
                id: implicit_route_id(&record.id),
                route,
                exposure: None,
                consents: Vec::new(),
                identification_timeout_ms: None,
            }]
        }
        DestinationDefinition::Observed => Vec::new(),
    }
}

/// How a destination's alias is rendered (ADR-0012 §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteRendering {
    /// No approved route (an observed destination): nothing is rendered.
    Unrendered,
    /// One direct or jump route: the native rendering (`HostName`/`Port`, or the single-hop
    /// `ProxyJump`), unchanged.
    Native,
    /// More than one approved route, or any Iroh route: Heimdall's own route helper
    /// (`ProxyCommand "<abs heimdall>" route connect …`), the one ADR-0010 §5(b) exception.
    Helper,
}

/// The rendering of a destination whose approved routes are `routes` (ADR-0012 §5.3).
#[must_use]
pub fn rendering_of(routes: &[DestinationRoute]) -> RouteRendering {
    let iroh = routes
        .iter()
        .any(|r| matches!(r.route, RouteSpec::Iroh { .. }));
    match routes.len() {
        0 => RouteRendering::Unrendered,
        1 if !iroh => RouteRendering::Native,
        _ => RouteRendering::Helper,
    }
}

/// How long the helper waits for the server's identification line through `route`
/// (ADR-0012 §5.5 item 1): the route's own bound, or the 10 s default. A stored `0` reads as
/// 1 ms (a bound, never "wait forever").
#[must_use]
pub fn identification_timeout(route: &DestinationRoute) -> Duration {
    Duration::from_millis(
        route
            .identification_timeout_ms
            .unwrap_or(DEFAULT_IDENTIFICATION_TIMEOUT_MS)
            .max(1),
    )
}

/// Why a stored route list is refused ([`check_route_list`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteListRefusal {
    /// The destination is not a managed catalog destination (an observed one has no routes;
    /// an unknown one is `NOT_FOUND`).
    NotManaged,
    /// An empty list (remove the stored list to return to the one-element case).
    Empty,
    /// Two routes share an ID.
    DuplicateId(RouteId),
    /// The same reachability data twice.
    DuplicateRoute(RouteId),
    /// A jump route refused by ADR-0010 §5 items 1–2 (`route_chain_unsupported`,
    /// `route_dependency_out_of_scope`, or an unknown jump).
    Jump(RouteRefusal),
}

impl RouteListRefusal {
    /// The stable route reason, where the refusal has one.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            RouteListRefusal::Jump(r) => r.reason(),
            _ => None,
        }
    }
}

/// Check a route list for `destination` against the catalog `view` (ADR-0012 §5.1, §5.7):
/// a managed destination, a non-empty list with distinct IDs and distinct reachability data,
/// and every jump route a valid single hop ([`RouteCatalogView::check_jump`], which reads the
/// stored lists too: a jump whose own approved routes are anything but one direct route, or a
/// destination that is itself a jump, is `route_chain_unsupported`). The list itself is not
/// read from `view`, so a proposed list can be checked before it is stored.
///
/// # Errors
/// [`RouteListRefusal`].
pub fn check_route_list(
    view: &RouteCatalogView,
    destination: &DestinationId,
    routes: &[DestinationRoute],
) -> Result<(), RouteListRefusal> {
    match view.destinations.get(destination).map(|d| &d.definition) {
        Some(DestinationDefinition::Managed { .. }) => {}
        _ => return Err(RouteListRefusal::NotManaged),
    }
    if routes.is_empty() {
        return Err(RouteListRefusal::Empty);
    }
    for (i, r) in routes.iter().enumerate() {
        for earlier in &routes[..i] {
            if earlier.id == r.id {
                return Err(RouteListRefusal::DuplicateId(r.id.clone()));
            }
            if earlier.route == r.route {
                return Err(RouteListRefusal::DuplicateRoute(r.id.clone()));
            }
        }
        if let RouteSpec::Jump { via } = &r.route {
            view.check_jump(destination, via)
                .map_err(RouteListRefusal::Jump)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::ids::{AccountName, IdentityId, IrohEndpointId};

    fn record(id: &str, definition: DestinationDefinition) -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::parse(id).unwrap(),
            alias: format!("a-{id}"),
            revision: 1,
            definition,
            label: None,
            updated_at: "2026-11-20T12:00:00Z".parse().unwrap(),
        }
    }

    fn managed(jump: Option<&str>) -> DestinationDefinition {
        DestinationDefinition::Managed {
            hostname: "10.0.0.2".into(),
            port: Some(2222),
            account: AccountName::parse("deploy").unwrap(),
            identity: IdentityId::from_random_bytes([1; 16]),
            jump: jump.map(|j| DestinationId::parse(j).unwrap()),
        }
    }

    fn route(n: u8, spec: RouteSpec) -> DestinationRoute {
        DestinationRoute {
            id: RouteId::from_random_bytes([n; 16]),
            route: spec,
            exposure: None,
            consents: Vec::new(),
            identification_timeout_ms: None,
        }
    }

    fn direct(host: &str) -> RouteSpec {
        RouteSpec::Direct {
            host: host.into(),
            port: None,
        }
    }

    fn jump(via: &str) -> RouteSpec {
        RouteSpec::Jump {
            via: DestinationId::parse(via).unwrap(),
        }
    }

    /// ADR-0012 §9 item 9: the existing single route and jump fields are the one-element
    /// case, with a stable ID; a stored list replaces them; an observed destination has none.
    #[test]
    fn the_definition_is_the_one_element_case() {
        let d = record("lab", managed(None));
        let routes = approved_routes(&d, None);
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].route,
            RouteSpec::Direct {
                host: "10.0.0.2".into(),
                port: Some(2222)
            }
        );
        assert_eq!(routes[0].id, implicit_route_id(&d.id));
        assert_eq!(
            approved_routes(&d, Some(&[])),
            routes,
            "an empty list reads as none"
        );
        assert!(routes[0].id.as_str().starts_with("route_"));
        assert_eq!(
            implicit_route_id(&d.id),
            implicit_route_id(&DestinationId::parse("lab").unwrap()),
            "deterministic"
        );
        assert_ne!(
            implicit_route_id(&d.id),
            implicit_route_id(&DestinationId::parse("lab2").unwrap())
        );

        let routed = record("lab", managed(Some("bastion")));
        assert_eq!(approved_routes(&routed, None)[0].route, jump("bastion"));

        let stored = vec![route(1, jump("bastion")), route(2, direct("10.0.0.2"))];
        assert_eq!(approved_routes(&d, Some(&stored)), stored);
        assert!(approved_routes(&record("w", DestinationDefinition::Observed), None).is_empty());
    }

    /// ADR-0012 §5.3: one direct or jump route is native; several routes, or any Iroh route,
    /// render the helper; no route renders nothing.
    #[test]
    fn rendering_is_native_for_one_route_and_the_helper_otherwise() {
        let iroh = RouteSpec::Iroh {
            endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
            direct_addresses: Vec::new(),
            external_roost: false,
        };
        assert_eq!(rendering_of(&[]), RouteRendering::Unrendered);
        assert_eq!(
            rendering_of(&[route(1, direct("h"))]),
            RouteRendering::Native
        );
        assert_eq!(rendering_of(&[route(1, jump("b"))]), RouteRendering::Native);
        assert_eq!(
            rendering_of(&[route(1, iroh.clone())]),
            RouteRendering::Helper
        );
        assert_eq!(
            rendering_of(&[route(1, direct("h")), route(2, jump("b"))]),
            RouteRendering::Helper
        );
        assert_eq!(
            rendering_of(&[route(1, direct("h")), route(2, iroh)]),
            RouteRendering::Helper
        );
    }

    #[test]
    fn host_key_alias_and_identification_bound() {
        let alias = |s: &str| host_key_alias(&DestinationId::parse(s).unwrap());
        assert_eq!(alias("lab-1.x_y").as_deref(), Some("hm-dest-lab-1.x_y"));
        assert_eq!(
            alias("a:b"),
            None,
            "a colon is a port separator in known_hosts"
        );
        let mut r = route(1, direct("h"));
        assert_eq!(identification_timeout(&r), Duration::from_secs(10));
        r.identification_timeout_ms = Some(250);
        assert_eq!(identification_timeout(&r), Duration::from_millis(250));
        r.identification_timeout_ms = Some(0);
        assert_eq!(identification_timeout(&r), Duration::from_millis(1));
    }

    /// ADR-0012 §5.4: a helper alias's jump route is the same single-hop dependency as
    /// M04's native one, so its managed jump pair (in the same scope) is a jump pair whose
    /// certificate carries `permit-port-forwarding`; the native `route_of` is only the
    /// one-element jump list.
    #[test]
    fn helper_jump_routes_are_jump_dependencies() {
        use heimdall_contract::managed::PreferredMechanism;
        let mut v = RouteCatalogView::default();
        for (id, def) in [("final", managed(None)), ("bastion", managed(None))] {
            let r = record(id, def);
            v.destinations.insert(r.id.clone(), r);
        }
        let d = |s: &str| DestinationId::parse(s).unwrap();
        let pair = |s: &str| crate::scope::AccessPair {
            destination: d(s),
            account: AccountName::parse("deploy").unwrap(),
        };
        v.mechanisms
            .insert(pair("bastion"), PreferredMechanism::ManagedCertificate);
        v.routes.insert(
            d("final"),
            vec![route(1, direct("10.0.0.2")), route(2, jump("bastion"))],
        );
        let scope: std::collections::BTreeSet<_> = [pair("final"), pair("bastion")].into();
        assert_eq!(
            v.route_of(&pair("final")),
            None,
            "several routes: no native jump"
        );
        assert_eq!(v.jump_routes_of(&pair("final")).len(), 1);
        assert_eq!(
            crate::catalog::jump_pairs_in_scope(&scope, &v),
            [pair("bastion")].into()
        );
        // Out of the scope, the jump pair gets nothing.
        let alone: std::collections::BTreeSet<_> = [pair("final")].into();
        assert!(crate::catalog::jump_pairs_in_scope(&alone, &v).is_empty());
        // A stored one-element jump list is the native route.
        v.routes.insert(d("final"), vec![route(2, jump("bastion"))]);
        assert_eq!(
            v.route_of(&pair("final")).unwrap().unwrap().jump,
            d("bastion")
        );
    }

    /// ADR-0012 §5.7: multi-hop chains stay `route_chain_unsupported` through stored lists
    /// too (a jump whose own list has a jump, or several routes, or an Iroh route; a
    /// destination that is itself some other destination's jump); duplicates are refused.
    #[test]
    fn route_lists_keep_single_hop_jumps() {
        let mut v = RouteCatalogView::default();
        for (id, def) in [
            ("final", managed(None)),
            ("bastion", managed(None)),
            ("b2", managed(None)),
            ("watched", DestinationDefinition::Observed),
        ] {
            let r = record(id, def);
            v.destinations.insert(r.id.clone(), r);
        }
        let d = |s: &str| DestinationId::parse(s).unwrap();
        let list = [route(1, jump("bastion")), route(2, direct("10.0.0.2"))];
        assert_eq!(check_route_list(&v, &d("final"), &list), Ok(()));
        assert_eq!(
            check_route_list(&v, &d("watched"), &list),
            Err(RouteListRefusal::NotManaged)
        );
        assert_eq!(
            check_route_list(&v, &d("final"), &[]),
            Err(RouteListRefusal::Empty)
        );
        assert_eq!(
            check_route_list(
                &v,
                &d("final"),
                &[route(1, jump("bastion")), route(1, direct("x"))]
            ),
            Err(RouteListRefusal::DuplicateId(RouteId::from_random_bytes(
                [1; 16]
            )))
        );
        assert_eq!(
            check_route_list(
                &v,
                &d("final"),
                &[route(1, direct("x")), route(2, direct("x"))]
            ),
            Err(RouteListRefusal::DuplicateRoute(
                RouteId::from_random_bytes([2; 16])
            ))
        );
        // The jump's own stored list has two routes: a chain.
        v.routes.insert(
            d("bastion"),
            vec![route(3, direct("10.0.0.1")), route(4, jump("b2"))],
        );
        let refused = check_route_list(&v, &d("final"), &list).unwrap_err();
        assert_eq!(
            refused,
            RouteListRefusal::Jump(RouteRefusal::ChainUnsupported)
        );
        assert_eq!(refused.reason(), Some("route_chain_unsupported"));
        // One direct route of its own is fine.
        v.routes
            .insert(d("bastion"), vec![route(3, direct("10.0.0.1"))]);
        assert_eq!(check_route_list(&v, &d("final"), &list), Ok(()));
        // `final` now uses `bastion` through its stored list: `bastion` cannot take a jump.
        v.routes.insert(d("final"), list.to_vec());
        assert_eq!(
            check_route_list(&v, &d("bastion"), &[route(5, jump("b2"))]),
            Err(RouteListRefusal::Jump(RouteRefusal::ChainUnsupported))
        );
        assert_eq!(
            check_route_list(&v, &d("final"), &[route(6, jump("watched"))]),
            Err(RouteListRefusal::Jump(RouteRefusal::OutOfScope))
        );
        assert_eq!(
            check_route_list(&v, &d("final"), &[route(6, jump("final"))]),
            Err(RouteListRefusal::Jump(RouteRefusal::OutOfScope))
        );
    }
}
