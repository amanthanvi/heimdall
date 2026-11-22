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
//!   attended decision local to this host, which this build cannot record for a local
//!   session yet: refused `exposure_unconsented`, nothing written (DONE question). A direct
//!   or jump route, or an Iroh route under the minimal policy, adds no exposure.
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

fn conflict(message: &str, why: Option<&'static str>) -> OpError {
    let e = OpError::new(Code::ConfigConflict, message.to_owned()).with_effect(EffectStatus::None);
    match why {
        Some(r) => e.with_reason(r),
        None => e,
    }
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
}

/// `route add|remove|prefer` over the state store (module docs).
#[derive(Debug, Clone, Copy)]
pub struct RouteOps<'a> {
    /// The state store.
    pub store: &'a Store,
}

impl RouteOps<'_> {
    fn finish(destination: &DestinationId, outcome: Outcome) -> Result<RouteChange, OpError> {
        match outcome {
            Outcome::Done(c) => Ok(c),
            Outcome::NotFound => Err(not_found(destination)),
            Outcome::Conflict(m, r) => Err(conflict(m, r)),
        }
    }

    /// `route add` (module docs).
    ///
    /// # Errors
    /// `exposure_unconsented` (a widening), `NOT_FOUND`, `CONFIG_CONFLICT` (with the route
    /// reason), or the store's; nothing is written on any of them.
    pub fn add(
        &self,
        destination: &DestinationId,
        route: &RouteSpec,
        exposure: Option<&ExposurePolicy>,
        now: Timestamp,
    ) -> Result<RouteChange, OpError> {
        if route_widens(route, exposure) {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "this route adds exposure, which needs an attended decision local to this host; \
                 this build cannot record that decision for a local session yet, so nothing was \
                 written",
            )
            .with_reason(reason::EXPOSURE_UNCONSENTED)
            .with_effect(EffectStatus::None));
        }
        if !exposure.is_none_or(ExposurePolicy::port_is_valid) {
            return Err(OpError::new(Code::UsageError, "port 0 is not a port")
                .with_effect(EffectStatus::None));
        }
        let id = random_route_id()?;
        let outcome = self.store.transaction(|tx| {
            let Some((record, mut list)) = load(tx, destination)? else {
                return Ok(Outcome::NotFound);
            };
            if let Some(existing) = list.iter().find(|r| &r.route == route) {
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
                consents: Vec::new(),
                identification_timeout_ms: None,
            });
            let mut view = crate::catalog::route_view(tx)?;
            view.routes = tx.all_destination_routes()?;
            if let Err(e) = heimdall_domain::routes::check_route_list(&view, destination, &list) {
                return Ok(Outcome::Conflict(
                    "the route cannot be approved for this destination",
                    e.reason(),
                ));
            }
            store_list(tx, &record, &list, now)?;
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
    /// `driver_unavailable` here). The result as a JSON document.
    ///
    /// # Errors
    /// The operation's.
    pub fn execute(
        &self,
        request: &RouteRequest,
        now: Timestamp,
    ) -> Result<serde_json::Value, OpError> {
        let change = match request {
            RouteRequest::Add {
                destination,
                route,
                exposure,
                ..
            } => self.add(destination, route, exposure.as_ref(), now)?,
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
        let added = ops.add(&d("lab"), &direct("10.0.0.9"), None, t()).unwrap();
        assert_eq!(added.routes, vec![implicit.clone(), added.route.clone()]);
        let again = ops.add(&d("lab"), &direct("10.0.0.9"), None, t()).unwrap();
        assert!(again.already_present);
        assert_eq!(again.route, added.route);
        let minimal = ops.add(&d("lab"), &iroh(), None, t()).unwrap();
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
            ops.add(&d("nope"), &direct("h"), None, t())
                .unwrap_err()
                .code,
            Code::NotFound
        );
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
                    relays: vec!["https://relay.invalid".into()],
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
                .add(&d("far"), &iroh(), Some(&exposure), t())
                .unwrap_err();
            assert_eq!(e.reason.as_deref(), Some(reason::EXPOSURE_UNCONSENTED));
            assert_eq!(e.effect_status, EffectStatus::None);
        }
        let roost = RouteSpec::Iroh {
            endpoint: IrohEndpointId::parse(&"cd".repeat(32)).unwrap(),
            direct_addresses: Vec::new(),
            external_roost: true,
        };
        assert_eq!(
            ops.add(&d("far"), &roost, None, t())
                .unwrap_err()
                .reason
                .as_deref(),
            Some(reason::EXPOSURE_UNCONSENTED)
        );
        let chained = ops
            .add(&d("far"), &RouteSpec::Jump { via: d("hop") }, None, t())
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
}
