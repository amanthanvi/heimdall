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

/// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ `request` with the relay URLs of a `route add` in their
/// one spelling (`heimdall_contract::route::normalize_relay_url`), **before any record is
/// made of it**: the decision's delta, its digest and the retry lookup are all computed
/// from the result, so two spellings of one URL are one request. Every other request is
/// returned as it is.
///
/// # Errors
/// `USAGE_ERROR` naming the refused URL's position and class (a scheme the relay transport
/// does not accept, userinfo, a query string, a fragment, or a malformed URL).
pub fn normalized(request: &RouteRequest) -> Result<std::borrow::Cow<'_, RouteRequest>, OpError> {
    let RouteRequest::Add {
        destination,
        route,
        exposure: Some(exposure),
        request_id,
    } = request
    else {
        return Ok(std::borrow::Cow::Borrowed(request));
    };
    let normal = exposure
        .with_normalized_relays()
        .map_err(|(i, why)| relay_refused(i + 1, why))?;
    if &normal == exposure {
        return Ok(std::borrow::Cow::Borrowed(request));
    }
    Ok(std::borrow::Cow::Owned(RouteRequest::Add {
        destination: destination.clone(),
        route: route.clone(),
        exposure: Some(normal),
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
        if let Some(e) = exposure {
            match e.with_normalized_relays() {
                Ok(normal) if &normal == e => {}
                Ok(_) => {
                    return Err(OpError::new(
                        Code::UsageError,
                        "a relay URL of this request is not in its normal form; nothing was \
                         recorded",
                    )
                    .with_effect(EffectStatus::None));
                }
                Err((i, why)) => return Err(relay_refused(i + 1, why)),
            }
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
}
