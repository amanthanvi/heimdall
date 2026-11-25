//! ⟨M06 W3⟩ `route add|remove|prefer` (ADR-0012 §2.1, §5.1, §5.7; ADR-0006 §18 `route.*`;
//! m06-plan W2 carry-over): a destination's ordered approved routes, changed by the local
//! owner through the runtime (the store's single writer).
//!
//! * **The one-element case is made explicit** on the first change: a destination with no
//!   stored list has the one route its definition states
//!   (`heimdall_domain::routes::approved_routes`); a change stores the whole list.
//! * **`add`** appends a route after checking the proposed list
//!   (`heimdall_domain::routes::check_route_list`: a managed destination, distinct IDs and
//!   reachability data, every jump a valid single hop; refused `CONFIG_CONFLICT` with the
//!   route reason). The same reachability data again answers the existing route
//!   (`already_present`). **New or expanded exposure is a widening action** (ADR-0012 §2.1,
//!   §3.10 item 4; the contract's `route.add` docs): an Iroh route whose exposure policy
//!   widens beyond the minimal one (relays, a broader bind, direct fallback, public
//!   infrastructure), or an external roost (`transport adopt-roost`'s widening), needs an
//!   attended decision local to this host. ⟨M06 W5; ADR-0006 §18.9 item 8⟩ The runtime
//!   records that decision for the local owner ([`RouteOps::add_delta`] is the exact delta
//!   it is bound to) and, once approved in an attended local session, runs the add with it
//!   ([`crate::transport::ApprovedWidening`]): the route is stored with a recorded consent
//!   naming the decision and the delta. Without an approval of exactly that delta the add
//!   is refused `exposure_unconsented` and nothing is written. A direct or jump route, or
//!   an Iroh route under the minimal policy, adds no exposure.
//! * **`remove`** (narrowing, no decision) drops one route and its recorded consents (each
//!   removal moves the admission authority generation); the last route cannot be removed
//!   (`CONFIG_CONFLICT`: a destination keeps its definition's route); a list back to exactly
//!   the definition's route is unstored (the one-element case again).
//! * **`prefer`** moves one route first: a pure preference change among routes whose
//!   exposure is already consented needs no new decision (ADR-0012 §2.1).
//!
//! Every list write moves the authority generation in the store (`ext_routes`), so grants
//! re-validate against the new list and the projection follows it.

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{DestinationId, RouteId};
use heimdall_contract::route::{DestinationRoute, ExposurePolicy, RouteRequest, RouteSpec};
use heimdall_domain::catalog::DestinationDefinition;
use heimdall_store::{Store, Txn};
use serde::Serialize;

use crate::error::OpError;

/// A route change's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteChange {
    /// The destination.
    pub destination: DestinationId,
    /// The route added, removed or preferred.
    pub route: RouteId,
    /// The approved routes now, most preferred first.
    pub routes: Vec<RouteId>,
    /// `add` found the same reachability data already approved (nothing written).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub already_present: bool,
}

fn not_found(destination: &DestinationId) -> OpError {
    OpError::new(
        Code::NotFound,
        "no managed catalog destination with that ID",
    )
    .with_resource("destination", Some(destination.as_str().to_owned()))
    .with_effect(EffectStatus::None)
}

/// ⟨M06 W5 `w5s`, M06-W5-R02⟩ `route add` of an approved Iroh route with another exposure
/// policy: what to do instead.
pub const EXPOSURE_DIFFERS: &str = "this Iroh route is already approved with another exposure \
     policy (its relays, direct fallback, bind or infrastructure differ); nothing was changed. \
     To use the new policy, remove the route (`heimdall route remove`), then add it again with \
     that policy";

fn conflict(message: &str, why: Option<&'static str>) -> OpError {
    let e = OpError::new(Code::ConfigConflict, message.to_owned()).with_effect(EffectStatus::None);
    match why {
        Some(r) => e.with_reason(r),
        None => e,
    }
}

/// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ The refusal of a relay URL (the `position`-th of the
/// request, from 1): `USAGE_ERROR`, nothing written. The URL itself is never quoted, since
/// a refused one may hold a credential.
fn relay_refused(position: usize, why: heimdall_contract::route::RelayUrlRefusal) -> OpError {
    OpError::new(
        Code::UsageError,
        format!(
            "relay URL {position} is refused: {}; nothing was recorded",
            why.message()
        ),
    )
    .with_effect(EffectStatus::None)
}

// --- ⟨rev7; ADR-0013 §6.4, D20; ruling R-A of 2026-11-25⟩ address strings ----------------

/// An address string that is not one: `USAGE_ERROR`, next `fix_request`, effect `none`. The
/// text itself is never quoted.
fn address_invalid(message: &str) -> OpError {
    OpError::new(Code::UsageError, message.to_owned()).with_effect(EffectStatus::None)
}

/// Whether `ip` is a link-local unicast IPv6 address (`fe80::/10`).
fn link_local(ip: &std::net::Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// ⟨rev7; ruling R-A⟩ One `direct_addresses` entry of an Iroh route in its one spelling: a
/// socket address (`ip:port`, an IPv6 address bracketed), as `std::net::SocketAddr` displays
/// it (the port kept, IPv6 compressed and in lowercase). A zone is accepted only on a
/// link-local IPv6 address (`fe80::/10`), as the numeric scope `SocketAddr` parses and the
/// dialer already dials (`[fe80::1%2]:22`); an interface-name zone is not a socket address
/// (std refuses it, as it did before), and a zone on any other address is refused. A zone of
/// `0` is no zone.
///
/// # Errors
/// `USAGE_ERROR` / `item_too_large` over
/// [`MAX_ADDRESS_BYTES`](heimdall_contract::bounds::MAX_ADDRESS_BYTES); otherwise `USAGE_ERROR`
/// with next `fix_request` for a text that is not such an address.
pub fn canonical_socket_address(text: &str) -> Result<String, OpError> {
    crate::catalog::bounded_bytes(
        "direct_addresses",
        text.len(),
        heimdall_contract::bounds::MAX_ADDRESS_BYTES,
        None,
    )?;
    let addr: std::net::SocketAddr = text.parse().map_err(|_| {
        address_invalid(
            "a direct address is ip:port (an IPv6 address in brackets, a zone only on a \
             link-local address); nothing was recorded",
        )
    })?;
    if let std::net::SocketAddr::V6(v6) = &addr
        && v6.scope_id() != 0
        && !link_local(v6.ip())
    {
        return Err(address_invalid(
            "a zone is accepted only on a link-local (fe80::/10) IPv6 address; nothing was \
             recorded",
        ));
    }
    Ok(addr.to_string())
}

/// ⟨rev7; ruling R-A, and its reading for binds (2026-11-25)⟩ A `BindScope::Interface`
/// address in its one spelling: a bare IP address (no port) as `std::net::IpAddr` displays it.
/// **No zone in 1.0:** the Iroh bind planner binds no zoned address, so a zone (`%…`, any
/// value) is refused here, at write, rather than accepted and refused when the transport
/// starts; a stated limitation (`docs/user/limitations.md`). A direct address keeps its
/// numeric link-local zone ([`canonical_socket_address`]): the dialer dials it.
///
/// # Errors
/// `USAGE_ERROR` / `item_too_large` over
/// [`MAX_ADDRESS_BYTES`](heimdall_contract::bounds::MAX_ADDRESS_BYTES); otherwise `USAGE_ERROR`
/// with next `fix_request` for a text that is not a bare IP address, a zone included.
pub fn canonical_interface_address(text: &str) -> Result<String, OpError> {
    crate::catalog::bounded_bytes(
        "address",
        text.len(),
        heimdall_contract::bounds::MAX_ADDRESS_BYTES,
        None,
    )?;
    if text.contains('%') {
        return Err(address_invalid(
            "an interface bind address takes no zone in this release (the transport cannot \
             bind a zoned address); nothing was recorded",
        ));
    }
    let ip: std::net::IpAddr = text.parse().map_err(|_| {
        address_invalid("an interface address is an IP address; nothing was recorded")
    })?;
    Ok(ip.to_string())
}

/// ⟨rev7⟩ `exposure` with its interface bind address in its one spelling
/// ([`canonical_interface_address`]); every other bind is returned as it is.
///
/// # Errors
/// [`canonical_interface_address`]'s.
pub fn with_canonical_bind(exposure: &ExposurePolicy) -> Result<ExposurePolicy, OpError> {
    use heimdall_contract::route::BindScope;
    let BindScope::Interface { address } = &exposure.bind else {
        return Ok(exposure.clone());
    };
    Ok(ExposurePolicy {
        bind: BindScope::Interface {
            address: canonical_interface_address(address)?,
        },
        ..exposure.clone()
    })
}

/// ⟨rev7; D20⟩ An exposure policy in its one spelling, within its bounds: every relay URL at
/// most [`RELAY_URL_MAX_BYTES`](heimdall_contract::route::RELAY_URL_MAX_BYTES)
/// (`item_too_large`, naming its position) and in its normal form, at most
/// [`MAX_RELAYS_PER_ROUTE`](heimdall_contract::bounds::MAX_RELAYS_PER_ROUTE) distinct relays,
/// and the interface bind address canonical.
///
/// # Errors
/// `USAGE_ERROR` (`item_too_large` over a bound).
pub fn canonical_exposure(exposure: &ExposurePolicy) -> Result<ExposurePolicy, OpError> {
    use heimdall_contract::route::{InfrastructureProfile, RELAY_URL_MAX_BYTES};
    if let InfrastructureProfile::Custom { relays } = &exposure.infrastructure {
        for (i, relay) in relays.iter().enumerate() {
            crate::catalog::bounded_bytes(
                &format!("relays[{}]", i + 1),
                relay.len(),
                RELAY_URL_MAX_BYTES,
                None,
            )?;
        }
    }
    let normal = exposure
        .with_normalized_relays()
        .map_err(|(i, why)| relay_refused(i + 1, why))?;
    crate::catalog::bounded_entries(
        "relays",
        relay_count(&normal),
        heimdall_contract::bounds::MAX_RELAYS_PER_ROUTE,
        None,
    )?;
    with_canonical_bind(&normal)
}

/// The relays a policy names.
fn relay_count(exposure: &ExposurePolicy) -> usize {
    match &exposure.infrastructure {
        heimdall_contract::route::InfrastructureProfile::Custom { relays } => relays.len(),
        _ => 0,
    }
}

/// ⟨rev7; D20⟩ `route` with its direct addresses in their one spelling
/// ([`canonical_socket_address`]), at most
/// [`MAX_DIRECT_ADDRESSES_PER_ROUTE`](heimdall_contract::bounds::MAX_DIRECT_ADDRESSES_PER_ROUTE).
fn canonical_route(route: &RouteSpec) -> Result<RouteSpec, OpError> {
    let RouteSpec::Iroh {
        endpoint,
        direct_addresses,
        external_roost,
    } = route
    else {
        return Ok(route.clone());
    };
    Ok(RouteSpec::Iroh {
        endpoint: endpoint.clone(),
        direct_addresses: canonical_direct_addresses(direct_addresses)?,
        external_roost: *external_roost,
    })
}

/// ⟨rev7; D20, ruling R-A⟩ An Iroh route's direct addresses, each in its one spelling
/// ([`canonical_socket_address`]), in the order given, at most
/// [`MAX_DIRECT_ADDRESSES_PER_ROUTE`](heimdall_contract::bounds::MAX_DIRECT_ADDRESSES_PER_ROUTE)
/// of them (the CLI checks `route add --address` with it before sending, as the runtime does).
///
/// # Errors
/// `USAGE_ERROR` / `item_too_large` over a bound, or [`canonical_socket_address`]'s.
pub fn canonical_direct_addresses(addresses: &[String]) -> Result<Vec<String>, OpError> {
    crate::catalog::bounded_entries(
        "direct_addresses",
        addresses.len(),
        heimdall_contract::bounds::MAX_DIRECT_ADDRESSES_PER_ROUTE,
        None,
    )?;
    addresses
        .iter()
        .map(|a| canonical_socket_address(a))
        .collect()
}

/// ⟨rev7; D20⟩ The bounds of a destination's whole approved list after a change that adds a
/// route: at most [`MAX_ROUTES_PER_DESTINATION`](heimdall_contract::bounds::MAX_ROUTES_PER_DESTINATION)
/// routes, [`MAX_RELAYS_PER_DESTINATION`](heimdall_contract::bounds::MAX_RELAYS_PER_DESTINATION)
/// relays over all of them, [`MAX_CONSENTS_PER_ROUTE`](heimdall_contract::bounds::MAX_CONSENTS_PER_ROUTE)
/// consents on each, and the destination with its routes at most
/// [`MAX_ITEM_BYTES`](heimdall_contract::bounds::MAX_ITEM_BYTES) serialized. A change that only
/// removes or reorders routes is never refused by them, so a legacy over-limit list can always
/// be narrowed.
pub(crate) fn check_list_bounds(
    record: &heimdall_domain::catalog::DestinationRecord,
    list: &[DestinationRoute],
) -> Result<(), OpError> {
    use heimdall_contract::bounds as b;
    let at = || Some(("destination", record.id.to_string()));
    crate::catalog::bounded_entries("routes", list.len(), b::MAX_ROUTES_PER_DESTINATION, at())?;
    let relays = list
        .iter()
        .map(|r| r.exposure.as_ref().map_or(0, relay_count))
        .sum();
    crate::catalog::bounded_entries("relays", relays, b::MAX_RELAYS_PER_DESTINATION, at())?;
    for r in list {
        crate::catalog::bounded_entries(
            "consents",
            r.consents.len(),
            b::MAX_CONSENTS_PER_ROUTE,
            at(),
        )?;
    }
    crate::catalog::bounded_item(&(record, list), at())
}

/// ⟨rev7; D20⟩ A `route add`'s route and exposure in their one spelling, within their bounds:
/// [`canonical_route`] and [`canonical_exposure`].
fn canonical_add(
    route: &RouteSpec,
    exposure: Option<&ExposurePolicy>,
) -> Result<(RouteSpec, Option<ExposurePolicy>), OpError> {
    Ok((
        canonical_route(route)?,
        exposure.map(canonical_exposure).transpose()?,
    ))
}

/// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ `request` with the relay URLs of a `route add` in their
/// one spelling (`heimdall_contract::route::normalize_relay_url`), **before any record is
/// made of it**: the decision's delta, its digest and the retry lookup are all computed
/// from the result, so two spellings of one URL are one request. Every other request is
/// returned as it is. ⟨rev7; D20, ruling R-A⟩ Likewise its direct addresses and interface
/// bind address ([`canonical_socket_address`], [`canonical_interface_address`]), and its
/// per-route bounds (direct addresses, relays) are checked here, so an over-bound request
/// makes no record.
///
/// # Errors
/// `USAGE_ERROR` naming the refused URL's position and class (a scheme the relay transport
/// does not accept, userinfo, a query string, a fragment, or a malformed URL), an address that
/// is not one (`fix_request`), or `item_too_large` over a bound.
pub fn normalized(request: &RouteRequest) -> Result<std::borrow::Cow<'_, RouteRequest>, OpError> {
    let RouteRequest::Add {
        destination,
        route,
        exposure,
        request_id,
    } = request
    else {
        return Ok(std::borrow::Cow::Borrowed(request));
    };
    let (normal_route, normal_exposure) = canonical_add(route, exposure.as_ref())?;
    if &normal_route == route && &normal_exposure == exposure {
        return Ok(std::borrow::Cow::Borrowed(request));
    }
    Ok(std::borrow::Cow::Owned(RouteRequest::Add {
        destination: destination.clone(),
        route: normal_route,
        exposure: normal_exposure,
        request_id: request_id.clone(),
    }))
}

/// Whether adding `route` with `exposure` widens this host's exposure (module docs).
#[must_use]
pub fn route_widens(route: &RouteSpec, exposure: Option<&ExposurePolicy>) -> bool {
    match route {
        RouteSpec::Iroh {
            endpoint,
            external_roost,
            ..
        } => {
            let after = exposure.cloned().unwrap_or_default();
            *external_roost
                || crate::transport::widens(&crate::transport::exposure_delta(
                    Some(endpoint),
                    &ExposurePolicy::default(),
                    false,
                    &after,
                    false,
                    None,
                ))
        }
        // A direct or jump route carries no exposure policy.
        _ => false,
    }
}

/// ⟨M06 W5; ADR-0006 §18.9 item 8⟩ The exact exposure delta adding `route` with `exposure`
/// applies (what a local decision is bound to): from the minimal, non-serving policy to the
/// route's, for the route's endpoint, naming it as an external roost when it is one. `None`
/// for a direct or jump route.
#[must_use]
pub fn route_delta(
    route: &RouteSpec,
    exposure: Option<&ExposurePolicy>,
) -> Option<crate::transport::ExposureDelta> {
    match route {
        RouteSpec::Iroh {
            endpoint,
            external_roost,
            ..
        } => {
            let after = exposure.cloned().unwrap_or_default();
            Some(crate::transport::exposure_delta(
                Some(endpoint),
                &ExposurePolicy::default(),
                false,
                &after,
                false,
                external_roost.then_some(endpoint),
            ))
        }
        _ => None,
    }
}

/// The destination's managed record and its approved list (the one-element case made
/// explicit), or `None` for an unknown or observed destination.
fn load(
    tx: &mut Txn<'_>,
    destination: &DestinationId,
) -> heimdall_store::Result<
    Option<(
        heimdall_domain::catalog::DestinationRecord,
        Vec<DestinationRoute>,
    )>,
> {
    let Some(record) = tx.destination(destination)? else {
        return Ok(None);
    };
    if !matches!(record.definition, DestinationDefinition::Managed { .. }) {
        return Ok(None);
    }
    let stored = tx.destination_routes(destination)?;
    let list = heimdall_domain::routes::approved_routes(&record, Some(&stored));
    Ok(Some((record, list)))
}

/// Store `list` for `destination`, or unstore it when it is exactly the definition's own
/// route (the one-element case).
fn store_list(
    tx: &mut Txn<'_>,
    record: &heimdall_domain::catalog::DestinationRecord,
    list: &[DestinationRoute],
    now: Timestamp,
) -> heimdall_store::Result<()> {
    let implicit = heimdall_domain::routes::approved_routes(record, None);
    if list == implicit.as_slice() {
        tx.remove_destination_routes(&record.id).map(drop)
    } else {
        tx.put_destination_routes(&record.id, list, now)
    }
}

fn random_route_id() -> Result<RouteId, OpError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| OpError::from(crate::ids::RandomnessUnavailable))?;
    Ok(RouteId::from_random_bytes(b))
}

enum Outcome {
    Done(RouteChange),
    NotFound,
    Conflict(&'static str, Option<&'static str>),
    /// ⟨rev7; D20⟩ A bound the changed list would break (`item_too_large`).
    Refused(Box<OpError>),
}

/// `route add|remove|prefer` over the state store (module docs).
#[derive(Debug, Clone, Copy)]
pub struct RouteOps<'a> {
    /// The state store.
    pub store: &'a Store,
}

/// How `add` treats a widening: with the caller's approval (or none), or as a precheck that
/// writes nothing.
#[derive(Clone, Copy)]
enum Approval<'a> {
    Given(Option<&'a crate::transport::ApprovedWidening>),
    DryRun,
}

impl RouteOps<'_> {
    fn finish(destination: &DestinationId, outcome: Outcome) -> Result<RouteChange, OpError> {
        match outcome {
            Outcome::Done(c) => Ok(c),
            Outcome::NotFound => Err(not_found(destination)),
            Outcome::Conflict(m, r) => Err(conflict(m, r)),
            Outcome::Refused(e) => Err(*e),
        }
    }

    /// ⟨M06 W5⟩ The exact delta a widening `route add` applies ([`route_delta`]), `None`
    /// when the add widens nothing (no decision is needed).
    #[must_use]
    pub fn add_delta(
        route: &RouteSpec,
        exposure: Option<&ExposurePolicy>,
    ) -> Option<crate::transport::ExposureDelta> {
        route_widens(route, exposure)
            .then(|| route_delta(route, exposure))
            .flatten()
    }

    /// ⟨M06 W5⟩ What `route add` would answer apart from the consent, writing nothing:
    /// `Ok(Some(_))` when the same reachability data is already approved (the existing
    /// route), `Ok(None)` when the route would be added. Used before a local decision
    /// record is made, so a request that can never succeed creates none.
    ///
    /// # Errors
    /// [`Self::add`]'s, except `exposure_unconsented`.
    pub fn add_precheck(
        &self,
        destination: &DestinationId,
        route: &RouteSpec,
        exposure: Option<&ExposurePolicy>,
        now: Timestamp,
    ) -> Result<Option<RouteChange>, OpError> {
        let change = self.add_inner(destination, route, exposure, Approval::DryRun, now)?;
        Ok(change.already_present.then_some(change))
    }

    /// `route add` (module docs). `approved` is the claimed local decision of a widening
    /// add (`None` otherwise).
    ///
    /// # Errors
    /// `exposure_unconsented` (a widening without an approval of exactly its delta),
    /// `NOT_FOUND`, `CONFIG_CONFLICT` (with the route reason), or the store's; nothing is
    /// written on any of them.
    pub fn add(
        &self,
        destination: &DestinationId,
        route: &RouteSpec,
        exposure: Option<&ExposurePolicy>,
        approved: Option<&crate::transport::ApprovedWidening>,
        now: Timestamp,
    ) -> Result<RouteChange, OpError> {
        self.add_inner(destination, route, exposure, Approval::Given(approved), now)
    }

    fn add_inner(
        &self,
        destination: &DestinationId,
        route: &RouteSpec,
        exposure: Option<&ExposurePolicy>,
        approval: Approval<'_>,
        now: Timestamp,
    ) -> Result<RouteChange, OpError> {
        if exposure.is_some_and(|e| e.sshd_port != heimdall_contract::route::DEFAULT_SSHD_PORT) {
            // ⟨M06 W5; ADR-0012 §2.3 item 2⟩ The sshd port is the serve side's forward
            // target. A route dials an endpoint and forwards to nothing, so a value here
            // would be recorded and ignored: refused instead.
            return Err(OpError::new(
                Code::UsageError,
                crate::transport::SSHD_PORT_NOT_FOR_A_DIALER,
            )
            .with_effect(EffectStatus::None));
        }
        if !exposure.is_none_or(ExposurePolicy::port_is_valid) {
            return Err(OpError::new(Code::UsageError, "port 0 is not a port")
                .with_effect(EffectStatus::None));
        }
        // ⟨rev6.5; ADR-0006 §18.9 item 9⟩ Only a relay URL in its one spelling is ever
        // compared with an approval or stored: the runtime normalises the request before it
        // records anything ([`normalized`]); a caller that did not is refused here.
        // ⟨rev7; D20, ruling R-A⟩ So are its direct addresses and interface bind address,
        // and its per-route bounds hold.
        let (normal_route, normal_exposure) = canonical_add(route, exposure)?;
        if &normal_route != route || normal_exposure.as_ref() != exposure {
            return Err(OpError::new(
                Code::UsageError,
                "a relay URL or address of this request is not in its normal form; nothing was \
                 recorded",
            )
            .with_effect(EffectStatus::None));
        }
        // A widening add runs only with an approval of exactly its delta.
        let dry_run = matches!(approval, Approval::DryRun);
        let consent = match (Self::add_delta(route, exposure), approval) {
            (None, _) | (Some(_), Approval::DryRun) => None,
            (Some(delta), Approval::Given(Some(a))) if a.delta == delta => Some(a),
            (Some(_), Approval::Given(_)) => {
                return Err(OpError::new(
                    Code::CapabilityUnavailable,
                    "this route adds exposure, which needs an attended decision local to this \
                     host; nothing was written",
                )
                .with_reason(reason::EXPOSURE_UNCONSENTED)
                .with_effect(EffectStatus::None));
            }
        };
        let consent_id = match consent {
            Some(_) => Some(heimdall_contract::ids::ConsentId::from_random_bytes(
                crate::transport::random16()?,
            )),
            None => None,
        };
        let id = random_route_id()?;
        let outcome = self.store.transaction(|tx| {
            let Some((record, mut list)) = load(tx, destination)? else {
                return Ok(Outcome::NotFound);
            };
            if let Some(existing) = list.iter().find(|r| &r.route == route) {
                // ⟨M06 W5 `w5s`, M06-W5-R02⟩ The same Iroh endpoint under another exposure
                // policy (another relay set, direct fallback, bind or infrastructure) is not
                // the route already present: refused, as `transport enable` refuses another
                // configuration, never answered `already_present` with the request's policy
                // silently dropped.
                if matches!(route, RouteSpec::Iroh { .. })
                    && existing.exposure.clone().unwrap_or_default()
                        != exposure.cloned().unwrap_or_default()
                {
                    return Ok(Outcome::Conflict(EXPOSURE_DIFFERS, None));
                }
                return Ok(Outcome::Done(RouteChange {
                    destination: destination.clone(),
                    route: existing.id.clone(),
                    routes: list.iter().map(|r| r.id.clone()).collect(),
                    already_present: true,
                }));
            }
            list.push(DestinationRoute {
                id: id.clone(),
                route: route.clone(),
                exposure: match route {
                    RouteSpec::Iroh { .. } => exposure.cloned(),
                    _ => None,
                },
                consents: consent_id.iter().cloned().collect(),
                identification_timeout_ms: None,
            });
            // ⟨rev7; D20⟩ The destination's bounds over its whole list, before any write.
            if let Err(e) = check_list_bounds(&record, &list) {
                return Ok(Outcome::Refused(Box::new(e)));
            }
            let mut view = crate::catalog::route_view(tx)?;
            view.routes = tx.all_destination_routes()?;
            if let Err(e) = heimdall_domain::routes::check_route_list(&view, destination, &list) {
                return Ok(Outcome::Conflict(
                    "the route cannot be approved for this destination",
                    e.reason(),
                ));
            }
            if dry_run {
                // The precheck: the add would succeed; nothing is written.
                return Ok(Outcome::Done(RouteChange {
                    destination: destination.clone(),
                    route: id.clone(),
                    routes: Vec::new(),
                    already_present: false,
                }));
            }
            store_list(tx, &record, &list, now)?;
            if let (Some(a), Some(consent_id)) = (consent, consent_id.as_ref()) {
                // The recorded consent: the attended local decision and its exact delta.
                tx.insert_route_consent(&crate::transport::RouteConsentRecord {
                    consent: consent_id.clone(),
                    route: Some(id.clone()),
                    decision: a.decision.clone(),
                    delta: a.delta.clone(),
                    recorded_at: now,
                })?;
            }
            Ok(Outcome::Done(RouteChange {
                destination: destination.clone(),
                route: id.clone(),
                routes: list.iter().map(|r| r.id.clone()).collect(),
                already_present: false,
            }))
        })?;
        Self::finish(destination, outcome)
    }

    /// `route remove` (module docs).
    ///
    /// # Errors
    /// `NOT_FOUND` (destination or route), `CONFIG_CONFLICT` (the last route), or the
    /// store's; nothing is written on any of them.
    pub fn remove(
        &self,
        destination: &DestinationId,
        route: &RouteId,
        now: Timestamp,
    ) -> Result<RouteChange, OpError> {
        let outcome = self.store.transaction(|tx| {
            let Some((record, mut list)) = load(tx, destination)? else {
                return Ok(Outcome::NotFound);
            };
            let Some(at) = list.iter().position(|r| &r.id == route) else {
                return Ok(Outcome::NotFound);
            };
            if list.len() == 1 {
                return Ok(Outcome::Conflict(
                    "a destination keeps at least one approved route",
                    None,
                ));
            }
            list.remove(at);
            let mut view = crate::catalog::route_view(tx)?;
            view.routes = tx.all_destination_routes()?;
            if let Err(e) = heimdall_domain::routes::check_route_list(&view, destination, &list) {
                return Ok(Outcome::Conflict(
                    "the remaining routes cannot stand for this destination",
                    e.reason(),
                ));
            }
            // Narrowing: the route's recorded consents go with it (each removal moves the
            // admission authority generation in this transaction).
            tx.remove_route_consents(Some(route), now)?;
            store_list(tx, &record, &list, now)?;
            Ok(Outcome::Done(RouteChange {
                destination: destination.clone(),
                route: route.clone(),
                routes: list.iter().map(|r| r.id.clone()).collect(),
                already_present: false,
            }))
        })?;
        Self::finish(destination, outcome)
    }

    /// `route prefer` (module docs).
    ///
    /// # Errors
    /// `NOT_FOUND` (destination or route), or the store's.
    pub fn prefer(
        &self,
        destination: &DestinationId,
        route: &RouteId,
        now: Timestamp,
    ) -> Result<RouteChange, OpError> {
        let outcome = self.store.transaction(|tx| {
            let Some((record, mut list)) = load(tx, destination)? else {
                return Ok(Outcome::NotFound);
            };
            let Some(at) = list.iter().position(|r| &r.id == route) else {
                return Ok(Outcome::NotFound);
            };
            if at != 0 {
                let chosen = list.remove(at);
                list.insert(0, chosen);
                store_list(tx, &record, &list, now)?;
            }
            Ok(Outcome::Done(RouteChange {
                destination: destination.clone(),
                route: route.clone(),
                routes: list.iter().map(|r| r.id.clone()).collect(),
                already_present: false,
            }))
        })?;
        Self::finish(destination, outcome)
    }

    /// Run one `Request::Route` change form (`resolve_binding` is the runtime's own lookup:
    /// `driver_unavailable` here). `approved` is the claimed local decision of a widening
    /// `add` (`None` for every other request; a widening add without it is refused
    /// `exposure_unconsented`). The result as a JSON document.
    ///
    /// # Errors
    /// The operation's.
    pub fn execute(
        &self,
        request: &RouteRequest,
        approved: Option<&crate::transport::ApprovedWidening>,
        now: Timestamp,
    ) -> Result<serde_json::Value, OpError> {
        let change = match request {
            RouteRequest::Add {
                destination,
                route,
                exposure,
                ..
            } => self.add(destination, route, exposure.as_ref(), approved, now)?,
            RouteRequest::Remove { destination, route } => self.remove(destination, route, now)?,
            RouteRequest::Prefer {
                destination, route, ..
            } => self.prefer(destination, route, now)?,
            _ => {
                return Err(OpError::driver_unavailable(
                    "this route request is not a route change",
                ));
            }
        };
        serde_json::to_value(change)
            .map_err(|_| OpError::new(Code::InternalError, "a route result cannot be rendered"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use heimdall_contract::ids::{AccountName, IdentityId, IrohEndpointId};
    use heimdall_contract::route::{BindScope, InfrastructureProfile};
    use heimdall_domain::catalog::DestinationRecord;
    use heimdall_store::NoFaults;

    use super::*;

    fn t() -> Timestamp {
        "2026-11-21T12:00:00Z".parse().unwrap()
    }

    fn d(s: &str) -> DestinationId {
        DestinationId::parse(s).unwrap()
    }

    fn store_with(dests: &[(&str, Option<&str>)]) -> Store {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                for (id, jump) in dests {
                    tx.upsert_destination(&DestinationRecord {
                        id: d(id),
                        alias: format!("a-{id}"),
                        revision: 1,
                        definition: DestinationDefinition::Managed {
                            hostname: format!("{id}.lan"),
                            port: None,
                            account: AccountName::parse("deploy").unwrap(),
                            identity: IdentityId::from_random_bytes([1; 16]),
                            jump: jump.map(d),
                        },
                        label: None,
                        updated_at: t(),
                    })?;
                }
                Ok(())
            })
            .unwrap();
        store
    }

    fn direct(host: &str) -> RouteSpec {
        RouteSpec::Direct {
            host: host.into(),
            port: Some(2222),
        }
    }

    fn iroh() -> RouteSpec {
        RouteSpec::Iroh {
            endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
            direct_addresses: vec!["127.0.0.1:40001".into()],
            external_roost: false,
        }
    }

    /// Add makes the one-element case explicit and appends; the same data again is
    /// `already_present`; prefer reorders; remove narrows back to the definition's route,
    /// which is then unstored; the last route stays.
    #[test]
    fn add_prefer_remove_round_trip() {
        let store = store_with(&[("lab", None)]);
        let ops = RouteOps { store: &store };
        let implicit = heimdall_domain::routes::implicit_route_id(&d("lab"));
        let added = ops
            .add(&d("lab"), &direct("10.0.0.9"), None, None, t())
            .unwrap();
        assert_eq!(added.routes, vec![implicit.clone(), added.route.clone()]);
        let again = ops
            .add(&d("lab"), &direct("10.0.0.9"), None, None, t())
            .unwrap();
        assert!(again.already_present);
        assert_eq!(again.route, added.route);
        let minimal = ops.add(&d("lab"), &iroh(), None, None, t()).unwrap();
        assert_eq!(
            minimal.routes.len(),
            3,
            "a minimal Iroh route adds no exposure"
        );
        let preferred = ops.prefer(&d("lab"), &added.route, t()).unwrap();
        assert_eq!(preferred.routes[0], added.route);
        ops.remove(&d("lab"), &minimal.route, t()).unwrap();
        ops.remove(&d("lab"), &added.route, t()).unwrap();
        assert!(
            store
                .transaction(|tx| tx.destination_routes(&d("lab")))
                .unwrap()
                .is_empty(),
            "back to the one-element case"
        );
        let last = ops.remove(&d("lab"), &implicit, t()).unwrap_err();
        assert_eq!(last.code, Code::ConfigConflict);
        assert_eq!(
            ops.remove(&d("lab"), &added.route, t()).unwrap_err().code,
            Code::NotFound
        );
        assert_eq!(
            ops.add(&d("nope"), &direct("h"), None, None, t())
                .unwrap_err()
                .code,
            Code::NotFound
        );
    }

    /// ⟨M06 W5 `w5o` item 13; ADR-0012 §5 ⟨2026-11-22⟩⟩ The certificate-content change of a
    /// stored jump route, over `crate::catalog::jump_pairs_of` (the one input both request
    /// creation and the issuance check read) and `extension_profile`:
    /// * before any jump route is approved, no pair of the grant has
    ///   `permit-port-forwarding`;
    /// * after `route add --jump bas` for `dst`, with `dst` and `bas` under one grant, the
    ///   bastion's certificate gains **exactly** that one extension, and nothing else
    ///   changes for it;
    /// * the destination's certificate never gains it, and neither does a third pair of
    ///   the same grant that no route jumps through;
    /// * a grant that does not hold the destination gives the bastion nothing (not the
    ///   same grant), and one that does not hold the bastion gives nobody anything;
    /// * a bastion whose pair is not a managed certificate (existing access) gets nothing;
    /// * removing the route removes the extension.
    #[test]
    fn a_stored_jump_route_gives_port_forwarding_to_its_bastion_only() {
        use std::collections::BTreeSet;

        use heimdall_contract::request::{
            DeadlineIntent, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
            NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
        };
        use heimdall_domain::issuance::{
            EXTENSION_PORT_FORWARDING, EXTENSION_PTY, extension_profile,
        };
        use heimdall_domain::scope::{AccessPair, Capability, Scope};

        let store = store_with(&[("dst", None), ("bas", None), ("far", None)]);
        let ops = RouteOps { store: &store };
        let pair = |id: &str| AccessPair {
            destination: d(id),
            account: AccountName::parse("deploy").unwrap(),
        };
        let managed = |id: &str| {
            store
                .transaction(|tx| {
                    tx.set_pair_preference(
                        &heimdall_domain::enrollment::PairPreference {
                            destination: d(id),
                            account: AccountName::parse("deploy").unwrap(),
                            mechanism:
                                heimdall_contract::managed::PreferredMechanism::ManagedCertificate,
                            projection: heimdall_domain::enrollment::ProjectionStatus::Pending,
                            issuing_cas: BTreeSet::new(),
                        },
                        t(),
                    )
                })
                .unwrap();
        };
        for id in ["dst", "bas", "far"] {
            managed(id);
        }
        let grant = |ids: &[&str]| heimdall_domain::grant::GrantSnapshot {
            id: heimdall_contract::ids::GrantId::from_random_bytes([3; 16]),
            environment: heimdall_contract::ids::EnvironmentId::from_random_bytes([7; 16]),
            scope: Scope {
                pairs: ids.iter().map(|i| pair(i)).collect(),
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
            },
            starts_at: t(),
            deadline: heimdall_domain::time::Deadline {
                intent: DeadlineIntent::Duration("60m".into()),
                resolved_at: t(),
                effective: Timestamp::from_second(t().as_second() + 3600).unwrap(),
            },
            parent: None,
            source: heimdall_domain::grant::AuthorizationSource::StandingPolicy {
                revision: heimdall_domain::policy::PolicyRevision(1),
            },
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            state: heimdall_contract::GrantState::Active,
            enforcement: heimdall_domain::evidence::EnforcementEvidence {
                report: Enforcement::new(
                    DestinationScopeEnforcement::Unknown,
                    NewAuthenticationExpiry::Unknown,
                    WorkloadIsolation::SharedOsUser,
                    ExistingConnectionsPolicy::Unknown,
                    RevocationStatus::Unknown,
                ),
                evidence: Vec::new(),
            },
        };
        // The extensions of every pair of a grant over `ids`, as issuance derives them.
        let extensions = |ids: &[&str]| -> Vec<(String, BTreeSet<String>)> {
            let g = grant(ids);
            let jumps = store
                .transaction(|tx| crate::catalog::jump_pairs_of(tx, &g.scope.pairs))
                .unwrap();
            ids.iter()
                .map(|i| ((*i).to_owned(), extension_profile(&g, &pair(i), &jumps)))
                .collect()
        };
        let base: BTreeSet<String> = [EXTENSION_PTY.to_owned()].into_iter().collect();
        let with_forwarding: BTreeSet<String> = [
            EXTENSION_PTY.to_owned(),
            EXTENSION_PORT_FORWARDING.to_owned(),
        ]
        .into_iter()
        .collect();
        let all = ["dst", "bas", "far"];
        let plain = |ids: &[&str]| -> Vec<(String, BTreeSet<String>)> {
            ids.iter()
                .map(|i| ((*i).to_owned(), base.clone()))
                .collect()
        };

        // No jump route: no pair has the extension.
        assert_eq!(extensions(&all), plain(&all));

        let added = ops
            .add(
                &d("dst"),
                &RouteSpec::Jump { via: d("bas") },
                None,
                None,
                t(),
            )
            .unwrap();
        // One grant holding both: exactly the bastion, exactly the one extension.
        assert_eq!(
            extensions(&all),
            vec![
                ("dst".to_owned(), base.clone()),
                ("bas".to_owned(), with_forwarding.clone()),
                ("far".to_owned(), base.clone()),
            ]
        );
        assert_eq!(
            with_forwarding.difference(&base).collect::<Vec<_>>(),
            [EXTENSION_PORT_FORWARDING]
        );
        // Not the same grant: the bastion without the destination, and the reverse.
        assert_eq!(extensions(&["bas", "far"]), plain(&["bas", "far"]));
        assert_eq!(extensions(&["dst", "far"]), plain(&["dst", "far"]));
        // A bastion reached with existing access has no certificate to extend.
        store
            .transaction(|tx| {
                tx.set_pair_preference(
                    &heimdall_domain::enrollment::PairPreference {
                        destination: d("bas"),
                        account: AccountName::parse("deploy").unwrap(),
                        mechanism: heimdall_contract::managed::PreferredMechanism::Existing,
                        projection: heimdall_domain::enrollment::ProjectionStatus::Pending,
                        issuing_cas: BTreeSet::new(),
                    },
                    t(),
                )
            })
            .unwrap();
        assert_eq!(extensions(&all), plain(&all));
        managed("bas");
        assert_eq!(extensions(&all)[1].1, with_forwarding);
        // The route removed: the extension is gone.
        ops.remove(&d("dst"), &added.route, t()).unwrap();
        assert_eq!(extensions(&all), plain(&all));
    }

    /// New exposure is a widening: an Iroh route with relays, a broader bind, direct
    /// fallback or an external roost is refused `exposure_unconsented` with nothing written;
    /// a jump through a destination that is itself a jump is `route_chain_unsupported`.
    #[test]
    fn widening_and_chained_routes_write_nothing() {
        let store = store_with(&[("lab", None), ("hop", Some("lab")), ("far", None)]);
        let ops = RouteOps { store: &store };
        for exposure in [
            ExposurePolicy {
                infrastructure: InfrastructureProfile::Custom {
                    relays: vec!["https://relay.invalid/".into()],
                },
                ..ExposurePolicy::default()
            },
            ExposurePolicy {
                bind: BindScope::Wildcard,
                direct_fallback: true,
                ..ExposurePolicy::default()
            },
        ] {
            let e = ops
                .add(&d("far"), &iroh(), Some(&exposure), None, t())
                .unwrap_err();
            assert_eq!(e.reason.as_deref(), Some(reason::EXPOSURE_UNCONSENTED));
            assert_eq!(e.effect_status, EffectStatus::None);
        }
        // ⟨rev6.5; ADR-0006 §18.9 item 9⟩ A relay URL that is refused, or not in its one
        // spelling, never reaches the approval comparison or the store: `USAGE_ERROR`.
        for relay in ["https://relay.invalid", "https://u:p@relay.invalid/"] {
            let exposure = ExposurePolicy {
                infrastructure: InfrastructureProfile::Custom {
                    relays: vec![relay.into()],
                },
                ..ExposurePolicy::default()
            };
            let e = ops
                .add(&d("far"), &iroh(), Some(&exposure), None, t())
                .unwrap_err();
            assert_eq!(e.code, Code::UsageError, "{relay}");
            assert_eq!(e.effect_status, EffectStatus::None);
        }
        let roost = RouteSpec::Iroh {
            endpoint: IrohEndpointId::parse(&"cd".repeat(32)).unwrap(),
            direct_addresses: Vec::new(),
            external_roost: true,
        };
        assert_eq!(
            ops.add(&d("far"), &roost, None, None, t())
                .unwrap_err()
                .reason
                .as_deref(),
            Some(reason::EXPOSURE_UNCONSENTED)
        );
        // ⟨M06 W5⟩ A non-default sshd port on a route is refused (a dialer has no target),
        // on an otherwise minimal policy and before the widening check on a wider one; the
        // default value is the same request as no value.
        for exposure in [
            ExposurePolicy {
                sshd_port: 2222,
                ..ExposurePolicy::default()
            },
            ExposurePolicy {
                sshd_port: 2222,
                bind: BindScope::Wildcard,
                ..ExposurePolicy::default()
            },
        ] {
            let e = ops
                .add(&d("far"), &iroh(), Some(&exposure), None, t())
                .unwrap_err();
            assert_eq!(e.code, Code::UsageError);
            assert_eq!(e.message, crate::transport::SSHD_PORT_NOT_FOR_A_DIALER);
            assert_eq!(e.effect_status, EffectStatus::None);
        }
        let chained = ops
            .add(
                &d("far"),
                &RouteSpec::Jump { via: d("hop") },
                None,
                None,
                t(),
            )
            .unwrap_err();
        assert_eq!(chained.code, Code::ConfigConflict);
        assert_eq!(
            chained.reason.as_deref(),
            Some(reason::ROUTE_CHAIN_UNSUPPORTED)
        );
        assert!(
            store
                .transaction(|tx| tx.all_destination_routes())
                .unwrap()
                .is_empty()
        );
    }
    /// ⟨M06 W5; ADR-0006 §18.9 item 8⟩ A widening add runs only with an approval of exactly
    /// its delta: an approval of another delta writes nothing; the exact one stores the
    /// route with a recorded consent naming the decision and the delta. The precheck writes
    /// nothing and reports a route that is already approved.
    #[test]
    fn a_widening_add_runs_only_with_an_approval_of_exactly_its_delta() {
        use crate::transport::ApprovedWidening;
        let store = store_with(&[("far", None)]);
        let ops = RouteOps { store: &store };
        let exposure = ExposurePolicy {
            direct_fallback: true,
            ..ExposurePolicy::default()
        };
        let delta = RouteOps::add_delta(&iroh(), Some(&exposure)).unwrap();
        assert!(delta.direct_fallback_added);
        assert_eq!(RouteOps::add_delta(&iroh(), None), None);
        assert_eq!(RouteOps::add_delta(&direct("h"), None), None);
        assert_eq!(
            ops.add_precheck(&d("far"), &iroh(), Some(&exposure), t())
                .unwrap(),
            None
        );
        assert_eq!(
            ops.add_precheck(&d("nope"), &iroh(), Some(&exposure), t())
                .unwrap_err()
                .code,
            Code::NotFound
        );
        let decision = heimdall_contract::ids::DecisionId::from_random_bytes([5; 16]);
        let other = ApprovedWidening {
            decision: decision.clone(),
            delta: RouteOps::add_delta(
                &iroh(),
                Some(&ExposurePolicy {
                    bind: BindScope::Wildcard,
                    ..ExposurePolicy::default()
                }),
            )
            .unwrap(),
        };
        let e = ops
            .add(&d("far"), &iroh(), Some(&exposure), Some(&other), t())
            .unwrap_err();
        assert_eq!(e.reason.as_deref(), Some(reason::EXPOSURE_UNCONSENTED));
        assert!(
            store
                .transaction(|tx| Ok((tx.all_destination_routes()?, tx.all_route_consents()?)))
                .map(|(r, c)| r.is_empty() && c.is_empty())
                .unwrap(),
            "nothing written by the precheck or the refused add"
        );
        let approved = ApprovedWidening {
            decision: decision.clone(),
            delta: delta.clone(),
        };
        let added = ops
            .add(&d("far"), &iroh(), Some(&exposure), Some(&approved), t())
            .unwrap();
        assert!(!added.already_present);
        let consents = store
            .transaction(|tx| tx.route_consents(Some(&added.route)))
            .unwrap();
        assert_eq!(consents.len(), 1);
        assert_eq!(
            (&consents[0].decision, &consents[0].delta),
            (&decision, &delta)
        );
        let stored = store
            .transaction(|tx| tx.destination_routes(&d("far")))
            .unwrap();
        let route = stored.iter().find(|r| r.id == added.route).unwrap();
        assert_eq!(route.exposure.as_ref(), Some(&exposure));
        assert_eq!(route.consents, vec![consents[0].consent.clone()]);
        // The same route again is the existing one, with or without an approval.
        let again = ops
            .add_precheck(&d("far"), &iroh(), Some(&exposure), t())
            .unwrap()
            .unwrap();
        assert_eq!((again.route, again.already_present), (added.route, true));
    }

    // --- ⟨rev7; D20, ruling R-A⟩ address strings and route bounds ---------------------------

    /// `route add` as the runtime runs it (`supervise_transport`'s IPC handler): the request
    /// put in its one spelling first ([`normalized`]), then executed.
    fn add_as_the_runtime_does(
        store: &Store,
        destination: &str,
        route: RouteSpec,
        exposure: Option<ExposurePolicy>,
    ) -> Result<serde_json::Value, OpError> {
        let request = RouteRequest::Add {
            destination: d(destination),
            route,
            exposure,
            request_id: heimdall_contract::ids::RequestId::parse("r-u32").unwrap(),
        };
        let request = normalized(&request)?;
        RouteOps { store }.execute(&request, None, t())
    }

    fn iroh_at(addresses: &[&str]) -> RouteSpec {
        RouteSpec::Iroh {
            endpoint: IrohEndpointId::parse(&"cd".repeat(32)).unwrap(),
            direct_addresses: addresses.iter().map(|a| (*a).to_owned()).collect(),
            external_roost: false,
        }
    }

    fn stored(store: &Store, destination: &str) -> Vec<DestinationRoute> {
        store
            .transaction(|tx| tx.destination_routes(&d(destination)))
            .unwrap()
    }

    fn stored_addresses(store: &Store, destination: &str) -> Vec<Vec<String>> {
        stored(store, destination)
            .into_iter()
            .filter_map(|r| match r.route {
                RouteSpec::Iroh {
                    direct_addresses, ..
                } => Some(direct_addresses),
                _ => None,
            })
            .collect()
    }

    fn reason_of(e: &OpError) -> Option<&str> {
        e.reason.as_deref()
    }

    fn assert_fix_request(e: &OpError, what: &str) {
        assert_eq!(e.code, Code::UsageError, "{what}: {e:?}");
        assert_eq!(e.next.action, "fix_request", "{what}");
        assert_eq!(e.effect_status, EffectStatus::None, "{what}");
    }

    /// ⟨ruling R-A⟩ A direct address is stored as `SocketAddr` displays it: an IPv4 one as
    /// given, a non-canonical IPv6 spelling compressed and in lowercase, the port kept; a
    /// link-local IPv6 address with a numeric zone is accepted. A zone on any other address,
    /// an interface-name zone and garbage are `USAGE_ERROR` with `fix_request`; an entry over
    /// 64 bytes is `item_too_large`. A refusal writes nothing.
    #[test]
    fn direct_addresses_are_stored_canonically_and_refused_otherwise() {
        let store = store_with(&[("lab", None)]);
        add_as_the_runtime_does(
            &store,
            "lab",
            iroh_at(&[
                "127.0.0.1:40001",
                "[2001:0DB8:0000:0000:0000:0000:0000:0001]:022",
                "[fe80::1%2]:22",
            ]),
            None,
        )
        .unwrap();
        assert_eq!(
            stored_addresses(&store, "lab"),
            vec![vec![
                "127.0.0.1:40001".to_owned(),
                "[2001:db8::1]:22".to_owned(),
                "[fe80::1%2]:22".to_owned(),
            ]]
        );
        let before = stored(&store, "lab");
        for (text, what) in [
            ("[2001:db8::1%3]:22", "a zone on a global address"),
            ("[fe80::1%eth0]:22", "an interface-name zone"),
            ("not-an-address", "garbage"),
            ("10.0.0.1", "no port"),
        ] {
            let e = add_as_the_runtime_does(&store, "lab", iroh_at(&[text]), None).unwrap_err();
            assert_fix_request(&e, what);
            assert_eq!(reason_of(&e), None, "{what}");
            assert_eq!(stored(&store, "lab"), before, "{what}: nothing was written");
        }
        let long = format!("[fe80::1%{}]:22", "0".repeat(60));
        assert!(long.len() > heimdall_contract::bounds::MAX_ADDRESS_BYTES);
        let e = add_as_the_runtime_does(&store, "lab", iroh_at(&[&long]), None).unwrap_err();
        assert_eq!(reason_of(&e), Some(reason::ITEM_TOO_LARGE));
        assert_fix_request(&e, "an entry over 64 bytes");
        assert_eq!(stored(&store, "lab"), before);
        // The functions alone, as the CLI calls them.
        assert_eq!(
            canonical_socket_address("[FE80:0:0:0:0:0:0:1%0]:22").unwrap(),
            "[fe80::1]:22",
            "zone 0 is no zone"
        );
        // A route that bypassed the runtime's normalisation is refused, never stored as given.
        let e = RouteOps { store: &store }
            .add(&d("lab"), &iroh_at(&["[2001:0db8::1]:22"]), None, None, t())
            .unwrap_err();
        assert_eq!(e.code, Code::UsageError);
        assert_eq!(stored(&store, "lab"), before);
    }

    /// ⟨ruling R-A and its reading for binds⟩ `BindScope::Interface.address`: a bare IP
    /// address in its one spelling and no zone in 1.0 (a link-local numeric zone included:
    /// the bind planner cannot bind it), `item_too_large` over 64 bytes, `fix_request`
    /// otherwise; stored canonically through `route add`'s exposure.
    #[test]
    fn interface_bind_addresses_are_canonical() {
        use heimdall_contract::route::{BindScope, InfrastructureProfile};
        for (given, canonical) in [
            ("192.0.2.7", "192.0.2.7"),
            ("2001:0DB8:0000::0001", "2001:db8::1"),
            ("FE80::0001", "fe80::1"),
        ] {
            assert_eq!(
                canonical_interface_address(given).unwrap(),
                canonical,
                "{given}"
            );
        }
        for (given, what) in [
            (
                "fe80::0001%7",
                "a link-local numeric zone (no zoned bind in 1.0)",
            ),
            ("fe80::1%0", "a zero zone"),
            ("2001:db8::1%7", "a zone on a global address"),
            ("fe80::1%eth0", "an interface-name zone"),
            ("192.0.2.7%1", "a zone on IPv4"),
            ("fe80::1%", "an empty zone"),
            ("fe80::1%+1", "a signed zone"),
            ("192.0.2.7:22", "a port"),
            ("[fe80::1]", "brackets"),
            ("garbage", "garbage"),
        ] {
            let e = canonical_interface_address(given).unwrap_err();
            assert_fix_request(&e, what);
            assert_eq!(reason_of(&e), None, "{what}");
        }
        let long = format!("fe80::1%{}", "0".repeat(60));
        let e = canonical_interface_address(&long).unwrap_err();
        assert_eq!(reason_of(&e), Some(reason::ITEM_TOO_LARGE));
        // Through `route add`: recorded in its one spelling (a widening, so the precheck the
        // runtime runs before it records a decision; the decision's delta names it too).
        let store = store_with(&[("lab", None)]);
        let exposure = ExposurePolicy {
            bind: BindScope::Interface {
                address: "2001:0DB8::0001".into(),
            },
            infrastructure: InfrastructureProfile::None,
            ..ExposurePolicy::default()
        };
        let request = RouteRequest::Add {
            destination: d("lab"),
            route: iroh_at(&[]),
            exposure: Some(exposure),
            request_id: heimdall_contract::ids::RequestId::parse("r-bind").unwrap(),
        };
        let RouteRequest::Add {
            exposure: Some(normal),
            ..
        } = normalized(&request).unwrap().into_owned()
        else {
            panic!("an add");
        };
        assert_eq!(
            normal.bind,
            BindScope::Interface {
                address: "2001:db8::1".into()
            }
        );
        let delta = RouteOps::add_delta(&iroh_at(&[]), Some(&normal)).unwrap();
        assert_eq!(
            delta.bind_after,
            BindScope::Interface {
                address: "2001:db8::1".into()
            }
        );
        let mut garbage = normal.clone();
        garbage.bind = BindScope::Interface {
            address: "fe80::1%eth0".into(),
        };
        let e = normalized(&RouteRequest::Add {
            destination: d("lab"),
            route: iroh_at(&[]),
            exposure: Some(garbage),
            request_id: heimdall_contract::ids::RequestId::parse("r-bind2").unwrap(),
        })
        .unwrap_err();
        assert_fix_request(&e, "an interface-name zone through route add");
        assert!(stored(&store, "lab").is_empty(), "nothing was written");
    }

    fn relay(i: usize) -> String {
        format!("https://relay{i:02}.example.invalid/")
    }

    fn with_relays(n: std::ops::Range<usize>) -> ExposurePolicy {
        ExposurePolicy {
            infrastructure: heimdall_contract::route::InfrastructureProfile::Custom {
                relays: n.map(relay).collect(),
            },
            ..ExposurePolicy::default()
        }
    }

    /// ⟨D20⟩ Every route bound refuses a `route add` through the runtime's path with
    /// `USAGE_ERROR` / `item_too_large`, writing nothing: 4 direct addresses, 9 relays on one
    /// route, a relay URL over 2,048 bytes, a 9th route, and a 17th relay over the
    /// destination's routes. Removing and preferring are never refused by a bound.
    #[test]
    fn over_bound_route_adds_are_refused_and_change_nothing() {
        use heimdall_contract::bounds::{
            MAX_RELAYS_PER_DESTINATION, MAX_RELAYS_PER_ROUTE, MAX_ROUTES_PER_DESTINATION,
        };
        let store = store_with(&[("lab", None), ("far", None)]);
        let before = stored(&store, "lab");
        let too_long = format!("https://r.example.invalid/{}", "p".repeat(2048));
        let mut long_relay = with_relays(0..1);
        long_relay.infrastructure = heimdall_contract::route::InfrastructureProfile::Custom {
            relays: vec![too_long],
        };
        for (route, exposure, field, what) in [
            (
                iroh_at(&["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", "127.0.0.1:4"]),
                None,
                "direct_addresses",
                "4 direct addresses",
            ),
            (
                iroh_at(&[]),
                Some(with_relays(0..MAX_RELAYS_PER_ROUTE + 1)),
                "relays",
                "9 relays on a route",
            ),
            (
                iroh_at(&[]),
                Some(long_relay),
                "relays[1]",
                "a relay URL over 2,048 bytes",
            ),
        ] {
            let e = add_as_the_runtime_does(&store, "lab", route, exposure).unwrap_err();
            assert_eq!(reason_of(&e), Some(reason::ITEM_TOO_LARGE), "{what}: {e:?}");
            assert_fix_request(&e, what);
            assert!(e.message.starts_with(field), "{what}: {}", e.message);
            assert_eq!(stored(&store, "lab"), before, "{what}: nothing was written");
        }
        // Up to the destination's bound of routes (the implicit one counts), then refused.
        for i in 1..MAX_ROUTES_PER_DESTINATION {
            add_as_the_runtime_does(&store, "lab", direct(&format!("10.0.0.{i}")), None).unwrap();
        }
        let full = stored(&store, "lab");
        assert_eq!(full.len(), MAX_ROUTES_PER_DESTINATION);
        let e = add_as_the_runtime_does(&store, "lab", direct("10.0.0.99"), None).unwrap_err();
        assert_eq!(reason_of(&e), Some(reason::ITEM_TOO_LARGE));
        assert!(e.message.starts_with("routes"), "{}", e.message);
        assert_eq!(
            e.resource.as_deref().map(|r| r.id.as_deref()),
            Some(Some("lab"))
        );
        assert_eq!(stored(&store, "lab"), full, "nothing was written");
        // Relays over all of a destination's routes: 8 + 8 fit, one more does not. (The
        // relay routes are recorded directly: a relay route is a widening, whose decision
        // path is not this test's.)
        let relay_route = |n: u8, relays: std::ops::Range<usize>| DestinationRoute {
            id: heimdall_contract::ids::RouteId::from_random_bytes([n; 16]),
            route: RouteSpec::Iroh {
                endpoint: IrohEndpointId::parse(&format!("{n:02x}").repeat(32)).unwrap(),
                direct_addresses: Vec::new(),
                external_roost: false,
            },
            exposure: Some(with_relays(relays)),
            consents: Vec::new(),
            identification_timeout_ms: None,
        };
        let far = store
            .transaction(|tx| tx.destination(&d("far")))
            .unwrap()
            .unwrap();
        let mut list = heimdall_domain::routes::approved_routes(&far, None);
        list.push(relay_route(1, 0..MAX_RELAYS_PER_ROUTE));
        list.push(relay_route(
            2,
            MAX_RELAYS_PER_ROUTE..MAX_RELAYS_PER_DESTINATION,
        ));
        assert!(check_list_bounds(&far, &list).is_ok(), "16 relays fit");
        list.push(relay_route(3, 16..17));
        let e = check_list_bounds(&far, &list).unwrap_err();
        assert_eq!(reason_of(&e), Some(reason::ITEM_TOO_LARGE));
        assert!(e.message.starts_with("relays"), "{}", e.message);
        // A full (or legacy over-full) list can always be narrowed and reordered.
        let ops = RouteOps { store: &store };
        ops.prefer(&d("lab"), &full[3].id, t()).unwrap();
        ops.remove(&d("lab"), &full[3].id, t()).unwrap();
        assert_eq!(stored(&store, "lab").len(), MAX_ROUTES_PER_DESTINATION - 1);
    }

    /// ⟨D20⟩ A legacy route list over a bound (9 routes, one with an address that does not
    /// parse, written before the bounds) stays readable by ID, is never rewritten by an
    /// unrelated write (a route added to another destination), and can be narrowed; a new
    /// route on it is refused.
    #[test]
    fn a_legacy_over_limit_route_list_stays_readable_and_unrewritten() {
        let store = store_with(&[("old", None), ("other", None)]);
        let old = store
            .transaction(|tx| tx.destination(&d("old")))
            .unwrap()
            .unwrap();
        let mut legacy = heimdall_domain::routes::approved_routes(&old, None);
        legacy.push(DestinationRoute {
            id: heimdall_contract::ids::RouteId::from_random_bytes([0x70; 16]),
            route: RouteSpec::Iroh {
                endpoint: IrohEndpointId::parse(&"ef".repeat(32)).unwrap(),
                direct_addresses: vec!["[2001:0DB8::1]:22".into(), "not an address".into()],
                external_roost: false,
            },
            exposure: None,
            consents: Vec::new(),
            identification_timeout_ms: None,
        });
        for i in 0..8u8 {
            legacy.push(DestinationRoute {
                id: heimdall_contract::ids::RouteId::from_random_bytes([0x80 + i; 16]),
                route: direct(&format!("10.1.0.{i}")),
                exposure: None,
                consents: Vec::new(),
                identification_timeout_ms: None,
            });
        }
        store
            .transaction(|tx| tx.put_destination_routes(&d("old"), &legacy, t()))
            .unwrap();
        let raw = || {
            store
                .transaction(|tx| tx.all_destination_routes())
                .unwrap()
                .remove(&d("old"))
                .unwrap()
        };
        assert_eq!(raw(), legacy, "readable by ID, as stored");
        add_as_the_runtime_does(&store, "other", direct("10.2.0.1"), None).unwrap();
        assert_eq!(raw(), legacy, "an unrelated write rewrites nothing");
        let e = add_as_the_runtime_does(&store, "old", direct("10.1.0.99"), None).unwrap_err();
        assert_eq!(reason_of(&e), Some(reason::ITEM_TOO_LARGE));
        assert_eq!(raw(), legacy);
        let ops = RouteOps { store: &store };
        ops.remove(&d("old"), &legacy[2].id, t()).unwrap();
        let after = raw();
        assert_eq!(after.len(), legacy.len() - 1);
        assert_eq!(
            after[1], legacy[1],
            "the unparseable entry is kept as stored"
        );
    }
}
