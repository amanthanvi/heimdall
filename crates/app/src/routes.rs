//! ⟨M06 U5a⟩ The route helper's core: `heimdall route connect` for the direct and jump legs
//! (ADR-0012 §5.3–§5.5; ADR-0010 §5 items 1–4; m06-plan U5a). ⟨M06 U56⟩ The Iroh leg is a
//! port ([`legs::IrohLegDialer`], implemented by the runtime over `heimdall-transport-iroh`,
//! which this crate never imports) behind [`legs::RouteLegDialer`]; an Iroh leg sends the
//! client's identification line first ([`failover`], item 5).
//!
//! **Typed inputs** ([`HelperArgs`]): exactly `--destination <id> --account <a> --endpoint
//! <path>`, the three values the helper alias renders (the endpoint is the alias's own
//! `IdentityAgent`). No host, port, command or route text is taken from arguments or
//! configuration: the approved routes come from the catalog ([`RouteHelperPorts::route_view`]).
//!
//! **Binding resolution** (ADR-0012 §5.4): the helper asks
//! [`RouteHelperPorts::resolve_route_binding`] (`ResolveRouteBinding{destination, account,
//! endpoint}`) for the one binding served at the alias's endpoint for the caller's context.
//! [`select_route_binding`] is the rule an implementation applies to the bindings it finds:
//! zero or several at the endpoint, or one whose grant does not cover the pair, is
//! `route_binding_ambiguous`. The helper never picks a binding by destination alone, so two
//! concurrent grants on different endpoints never borrow each other's jump dependency.
//!
//! **Planning** ([`plan_routes`], pure): each approved route in preference order becomes a
//! leg. A jump route keeps ADR-0010 §5 items 1–4 unchanged: a single hop through a catalog
//! destination (`route_chain_unsupported` otherwise), authenticated by a managed pair **in the
//! resolved binding's grant** (whose certificate carries `permit-port-forwarding`) or by
//! existing access, decided by `RouteCatalogView::jump_access` over the binding's pairs. A
//! jump route whose dependency is outside that grant is not attempted
//! (`route_dependency_out_of_scope`); when no route remains, the helper refuses with that
//! reason. No route outside the catalog's approved list is ever planned.
//!
//! **Failover** ([`failover`]): the server's identification line through a candidate is the
//! establishment point; the client's bytes are held until then; pre-identification lines are
//! buffered within 8 KiB and 32 lines and forwarded unchanged; the wait is bounded (10 s by
//! default, per route). Failover happens only before the first forwarded byte, never after a
//! host-key or authentication failure, and never onto an unapproved route. Every attempt
//! produces a structured `RouteHealthPayload`; the helper's exit codes stay internal.
//!
//! **The legs** ([`legs`]): the direct leg is a TCP connect with a bounded timeout; the jump
//! leg is `ssh -F none <the jump's catalog pin> -W <final host>:<port> <jump alias>`
//! (`heimdall_registry::routes::jump_leg_args`), started non-interactively with
//! `SSH_AUTH_SOCK` removed. [`verify`] runs `ssh -G` for the `host_pin_defeated` checks of
//! both hops.

#[path = "routes_failover.rs"]
pub mod failover;
#[path = "routes_legs.rs"]
pub mod legs;
#[path = "routes_ops.rs"]
pub mod ops;
#[path = "routes_verify.rs"]
pub mod verify;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::envelope::reason;
use heimdall_contract::environment::JumpAccess;
use heimdall_contract::ids::{
    AccountName, BindingId, DestinationId, GrantId, IrohEndpointId, RouteId,
};
use heimdall_contract::route::{ExposurePolicy, RouteHealthPayload, RouteSpec};
use heimdall_domain::catalog::{
    ApprovedRoute, DestinationDefinition, RouteCatalogView, RouteRefusal,
};
use heimdall_domain::scope::AccessPair;
use tokio::io::{AsyncRead, AsyncWrite};

pub use failover::{ClientIdentification, FailoverConfig, FailoverOutcome};
/// The pure pieces the helper builds on (`heimdall-registry`), re-exported for its callers.
pub use heimdall_registry::routes::{
    DefeatKind, ExpectedProxy, HOST_PIN_DEFEATED, HostPinDefeated, JumpHop, JumpLegError,
    PinExpectation, jump_leg_args, verify_effective,
};

/// Why the helper refuses before any route is tried. Each maps to a stable reason
/// ([`RouteHelperError::reason`]); the helper's exit codes stay internal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteHelperError {
    /// The arguments are not exactly the three typed inputs.
    #[error("usage: route connect --destination <id> --account <account> --endpoint <path> ({0})")]
    Usage(&'static str),
    /// Zero or several bindings at the endpoint, or one whose grant does not cover the
    /// destination's pair (`route_binding_ambiguous`).
    #[error("no single binding at this endpoint covers the destination (route_binding_ambiguous)")]
    BindingAmbiguous,
    /// The destination has no approved route for this account (`route_unapproved`).
    #[error("the destination has no approved route for this account (route_unapproved)")]
    RouteUnapproved,
    /// Every approved route is refused by ADR-0010 §5 for this binding (the reason of the
    /// first: `route_dependency_out_of_scope` or `route_chain_unsupported`).
    #[error("no approved route can be used with this binding ({0})")]
    NoUsableRoute(&'static str),
    /// The catalog or the runtime could not be read (the text is not echoed to peers).
    #[error("the route catalog is unavailable")]
    Unavailable,
    /// ⟨M06 exit, Q-B⟩ Every leg tried is an Iroh leg and this build has no Iroh driver
    /// (`CAPABILITY_UNAVAILABLE`, `driver_unavailable`). Each attempt was recorded first.
    #[error(
        "{} (CAPABILITY_UNAVAILABLE / driver_unavailable)",
        IROH_ROUTE_PREVIEW_UNAVAILABLE
    )]
    DriverUnavailable,
}

/// ⟨M06 exit, Q-B⟩ Why a destination whose every leg is Iroh has no usable leg in a build
/// without the `iroh` feature. The same text as `heimdall_app::transport`'s Iroh preview
/// message, with the final clause for a route.
pub const IROH_ROUTE_PREVIEW_UNAVAILABLE: &str = "the Iroh transport is a preview, available \
    only in a source build with `cargo build --features iroh`; this build does not include \
    it, so this route has no usable leg";

impl RouteHelperError {
    /// The stable reason, where there is one.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            RouteHelperError::Usage(_) | RouteHelperError::Unavailable => None,
            RouteHelperError::BindingAmbiguous => Some(reason::ROUTE_BINDING_AMBIGUOUS),
            RouteHelperError::RouteUnapproved => Some(reason::ROUTE_UNAPPROVED),
            RouteHelperError::NoUsableRoute(r) => Some(r),
            RouteHelperError::DriverUnavailable => Some(reason::DRIVER_UNAVAILABLE),
        }
    }
}

// --- typed arguments ---------------------------------------------------------------------

/// The helper's typed inputs (ADR-0012 §5.3, §5.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HelperArgs {
    /// `--destination`.
    pub destination: DestinationId,
    /// `--account`.
    pub account: AccountName,
    /// `--endpoint`: the alias's rendered `IdentityAgent`, taken literally.
    pub endpoint: String,
}

impl HelperArgs {
    /// Parse the arguments after `route connect`: each of `--destination`, `--account` and
    /// `--endpoint` exactly once, each with a value, in any order, and nothing else. The
    /// endpoint must be absolute (`/…`, a drive path or `//./pipe/…`).
    ///
    /// # Errors
    /// [`RouteHelperError::Usage`].
    pub fn parse<I>(args: I) -> Result<HelperArgs, RouteHelperError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut destination = None;
        let mut account = None;
        let mut endpoint = None;
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let flag = flag
                .into_string()
                .map_err(|_| RouteHelperError::Usage("an argument is not UTF-8"))?;
            let slot = match flag.as_str() {
                "--destination" => &mut destination,
                "--account" => &mut account,
                "--endpoint" => &mut endpoint,
                _ => return Err(RouteHelperError::Usage("unexpected argument")),
            };
            let value = it
                .next()
                .ok_or(RouteHelperError::Usage("a flag has no value"))?
                .into_string()
                .map_err(|_| RouteHelperError::Usage("an argument is not UTF-8"))?;
            if slot.replace(value).is_some() {
                return Err(RouteHelperError::Usage("a flag is repeated"));
            }
        }
        let destination = DestinationId::parse(
            &destination.ok_or(RouteHelperError::Usage("--destination is required"))?,
        )
        .map_err(|_| RouteHelperError::Usage("--destination is not a destination ID"))?;
        let account =
            AccountName::parse(&account.ok_or(RouteHelperError::Usage("--account is required"))?)
                .map_err(|_| RouteHelperError::Usage("--account is not an account name"))?;
        let endpoint = endpoint.ok_or(RouteHelperError::Usage("--endpoint is required"))?;
        let b = endpoint.as_bytes();
        let absolute = endpoint.starts_with('/')
            || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/');
        if !absolute || endpoint.chars().any(char::is_control) {
            return Err(RouteHelperError::Usage(
                "--endpoint is not an absolute path",
            ));
        }
        Ok(HelperArgs {
            destination,
            account,
            endpoint,
        })
    }

    /// The destination's pair.
    #[must_use]
    pub fn pair(&self) -> AccessPair {
        AccessPair {
            destination: self.destination.clone(),
            account: self.account.clone(),
        }
    }
}

// --- binding resolution (ADR-0012 §5.4) --------------------------------------------------

/// One binding served at an endpoint for the caller's context, with its grant's pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteBinding {
    /// The binding.
    pub binding: BindingId,
    /// Its grant.
    pub grant: GrantId,
    /// The endpoint it is served at.
    pub endpoint: String,
    /// The grant's destination/account pairs.
    pub pairs: BTreeSet<AccessPair>,
}

/// ⟨M06 W3⟩ The runtime's answer to `route.resolve_binding` (ADR-0012 §5.4): the one
/// binding served at the endpoint for the caller's context, its grant and the grant's pairs.
/// The helper checks it again ([`select_route_binding`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedRouteBinding {
    /// The binding.
    pub binding: BindingId,
    /// Its grant.
    pub grant: GrantId,
    /// The endpoint it is served at.
    pub endpoint: String,
    /// The grant's destination/account pairs.
    pub pairs: Vec<AccessPair>,
}

impl From<RouteBinding> for ResolvedRouteBinding {
    fn from(b: RouteBinding) -> Self {
        Self {
            binding: b.binding,
            grant: b.grant,
            endpoint: b.endpoint,
            pairs: b.pairs.into_iter().collect(),
        }
    }
}

impl From<ResolvedRouteBinding> for RouteBinding {
    fn from(b: ResolvedRouteBinding) -> Self {
        Self {
            binding: b.binding,
            grant: b.grant,
            endpoint: b.endpoint,
            pairs: b.pairs.into_iter().collect(),
        }
    }
}

/// ⟨rev7⟩ The route facts the helper plans `destination`'s routes from, read in one
/// transaction. ⟨rev7; ruled 2026-11-25 (U3-1b's Q2)⟩ By key, never by enumerating the
/// catalog: the destination with its stored route list and pair preference, each hop its
/// routes jump through, and the destinations jumping through it
/// (`crate::catalog::route_view_of`), so a catalog at D20's maximum is planned without
/// reading every destination, and no hop is ever cut from a scan.
///
/// # Errors
/// The store's.
pub fn route_catalog_view_of(
    store: &heimdall_store::Store,
    destination: &DestinationId,
) -> heimdall_store::Result<RouteCatalogView> {
    store.transaction(|tx| crate::catalog::route_view_of(tx, [destination]))
}

/// ⟨M06 W3⟩ The route facts of the whole catalog, read in one transaction: the catalog's
/// destinations and pair preferences, and every stored route list. ⟨rev7⟩ The helper plans
/// from [`route_catalog_view_of`] instead; this whole read stays for
/// [`RouteHelperPorts::route_view`].
///
/// # Errors
/// The store's.
pub fn route_catalog_view(
    store: &heimdall_store::Store,
) -> heimdall_store::Result<RouteCatalogView> {
    store.transaction(|tx| {
        let mut view = crate::catalog::route_view(tx)?;
        view.routes = tx.all_destination_routes()?;
        Ok(view)
    })
}

/// ⟨M06 W5 `w5n`⟩ The catalog-pinned host keys of `pair`'s destination (ADR-0012 §5.1,
/// §5.7): the approved target's host key of each enrollment of the pair that carries
/// trust (`verified`, or `reverifying`, which never removes anything), as `<type>
/// <base64>`, sorted and without duplicates. A pair with no such enrollment has no pin: its
/// destination cannot be verified through the helper (fail closed).
///
/// # Errors
/// The store's.
pub fn catalog_pins(
    tx: &mut heimdall_store::Txn<'_>,
    pair: &AccessPair,
) -> heimdall_store::Result<Vec<String>> {
    use heimdall_contract::enrollment::EnrollmentState;
    let mut pins: Vec<String> = tx
        .enrollments_for_pair(pair)?
        .into_iter()
        .filter(|e| {
            matches!(
                e.state,
                EnrollmentState::Verified | EnrollmentState::Reverifying
            )
        })
        .map(|e| format!("{} {}", e.target.host_key.algorithm, e.target.host_key.key))
        .collect();
    pins.sort();
    pins.dedup();
    Ok(pins)
}

/// ⟨M06 W5 `w5n`⟩ What the projection renders the route helper from, for `destination`
/// (ADR-0012 §5.3): `Some(pins)` when its approved routes need the helper (more than one
/// route, or any Iroh route) and its ID can name a pin; the pins are its managed pair's
/// ([`catalog_pins`]) and those of the jump destination of each approved jump route, as
/// `(destination ID, "<type> <base64>")`. `None` keeps the native rendering.
///
/// # Errors
/// The store's.
pub fn helper_pins(
    tx: &mut heimdall_store::Txn<'_>,
    destination: &DestinationId,
) -> heimdall_store::Result<Option<Vec<(String, String)>>> {
    use heimdall_domain::routes::{RouteRendering, approved_routes, host_key_alias, rendering_of};
    let Some(record) = tx.destination(destination)? else {
        return Ok(None);
    };
    let DestinationDefinition::Managed { account, .. } = &record.definition else {
        return Ok(None);
    };
    let stored = tx.destination_routes(destination)?;
    let routes = approved_routes(&record, Some(&stored));
    if rendering_of(&routes) != RouteRendering::Helper || host_key_alias(destination).is_none() {
        return Ok(None);
    }
    let mut pairs = vec![AccessPair {
        destination: destination.clone(),
        account: account.clone(),
    }];
    for route in &routes {
        if let RouteSpec::Jump { via } = &route.route
            && let Some(DestinationDefinition::Managed { account, .. }) =
                tx.destination(via)?.map(|d| d.definition)
            && host_key_alias(via).is_some()
        {
            pairs.push(AccessPair {
                destination: via.clone(),
                account,
            });
        }
    }
    let mut pins = Vec::new();
    for pair in pairs {
        for key in catalog_pins(tx, &pair)? {
            pins.push((pair.destination.to_string(), key));
        }
    }
    Ok(Some(pins))
}

/// `ResolveRouteBinding`'s rule over the bindings an implementation finds for the caller's
/// context (ADR-0012 §5.4): exactly one at `endpoint`, and its grant covers `pair`.
///
/// # Errors
/// [`RouteHelperError::BindingAmbiguous`] for zero or several bindings at the endpoint, or
/// one whose grant does not cover the pair (from the helper's side there is then no binding
/// for this destination at this endpoint).
pub fn select_route_binding(
    candidates: &[RouteBinding],
    pair: &AccessPair,
    endpoint: &str,
) -> Result<RouteBinding, RouteHelperError> {
    let mut at = candidates.iter().filter(|b| b.endpoint == endpoint);
    let (Some(one), None) = (at.next(), at.next()) else {
        return Err(RouteHelperError::BindingAmbiguous);
    };
    if !one.pairs.contains(pair) {
        return Err(RouteHelperError::BindingAmbiguous);
    }
    Ok(one.clone())
}

// --- planning -------------------------------------------------------------------------

/// One leg of a planned route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegPlan {
    /// A TCP connect to `host:port`.
    Direct {
        /// Host name or address.
        host: String,
        /// Port.
        port: u16,
    },
    /// `ssh -W <final_host>:<final_port>` through the jump (ADR-0012 §5.4).
    Jump {
        /// The approved jump.
        route: ApprovedRoute,
        /// How the jump hop authenticates (ADR-0010 §5 item 2).
        access: JumpAccess,
        /// The destination's address as the jump host reaches it.
        final_host: String,
        /// Its port.
        final_port: u16,
        /// The jump leg's catalog pin and access ([`RouteHelperPorts::jump_hop`]); filled
        /// before any route is dialed.
        hop: Option<Box<JumpHop>>,
    },
    /// ⟨M06 U56⟩ An Iroh route, dialed through an [`legs::IrohLegDialer`] under the route's
    /// own exposure policy and recorded addresses only (ADR-0012 §2.1). Without a dialer it
    /// is failed over: `driver_unavailable` with no driver in the build (⟨M06 exit, Q-B⟩),
    /// refused with no verified key store.
    Iroh {
        /// The serving endpoint.
        endpoint: IrohEndpointId,
        /// The route record's direct addresses (`ip:port`).
        direct_addresses: Vec<String>,
        /// The route's effective exposure policy (the minimal policy when absent).
        exposure: ExposurePolicy,
        /// An adopted stock roost (ADR-0012 §2.8).
        external_roost: bool,
    },
}

/// One approved route, ready to be tried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRoute {
    /// The route.
    pub id: RouteId,
    /// Its leg.
    pub leg: LegPlan,
    /// Its identification bound (ADR-0012 §5.5 item 1).
    pub identification_timeout: Duration,
}

/// The routes the helper may try, in preference order, and the approved routes it may not
/// (each with its reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    /// The routes to try.
    pub routes: Vec<PlannedRoute>,
    /// Approved routes refused for this binding: `(route, reason)`.
    pub refused: Vec<(RouteId, &'static str)>,
}

/// Plan the approved routes of `pair` for `binding` (module docs).
///
/// # Errors
/// [`RouteHelperError::RouteUnapproved`] when `pair` is not the destination's managed pair
/// or the destination has no approved route; [`RouteHelperError::BindingAmbiguous`] when the
/// binding's grant does not cover `pair`; [`RouteHelperError::NoUsableRoute`] when every
/// approved route is refused.
pub fn plan_routes(
    view: &RouteCatalogView,
    pair: &AccessPair,
    binding: &RouteBinding,
) -> Result<RoutePlan, RouteHelperError> {
    if !binding.pairs.contains(pair) {
        return Err(RouteHelperError::BindingAmbiguous);
    }
    let Some(DestinationDefinition::Managed {
        hostname,
        port,
        account,
        ..
    }) = view
        .destinations
        .get(&pair.destination)
        .map(|d| &d.definition)
    else {
        return Err(RouteHelperError::RouteUnapproved);
    };
    if account != &pair.account {
        return Err(RouteHelperError::RouteUnapproved);
    }
    let approved = view.approved_routes(&pair.destination);
    if approved.is_empty() {
        return Err(RouteHelperError::RouteUnapproved);
    }
    let mut plan = RoutePlan {
        routes: Vec::new(),
        refused: Vec::new(),
    };
    for route in &approved {
        let leg = match &route.route {
            RouteSpec::Direct { host, port } => LegPlan::Direct {
                host: host.clone(),
                port: port.unwrap_or(22),
            },
            RouteSpec::Jump { via } => {
                let checked = view.check_jump(&pair.destination, via).and_then(|()| {
                    let jump_pair = view.managed_pair(via).ok_or(RouteRefusal::OutOfScope)?;
                    let approved = ApprovedRoute {
                        jump: via.clone(),
                        jump_alias: view.destinations[via].alias.clone(),
                        jump_pair,
                    };
                    let access = view.jump_access(&approved, Some(&binding.pairs))?;
                    Ok((approved, access))
                });
                match checked {
                    Ok((approved, access)) => LegPlan::Jump {
                        route: approved,
                        access,
                        final_host: hostname.clone(),
                        final_port: port.unwrap_or(22),
                        hop: None,
                    },
                    // ⟨rev7⟩ ADR-0013 §6.3 (D21): a jump that names no catalog destination
                    // (the hop is absent) leaves this route undetermined.
                    Err(r) => {
                        plan.refused.push((
                            route.id.clone(),
                            r.reason().unwrap_or(reason::ROUTE_UNDETERMINED),
                        ));
                        continue;
                    }
                }
            }
            RouteSpec::Iroh {
                endpoint,
                direct_addresses,
                external_roost,
            } => LegPlan::Iroh {
                endpoint: endpoint.clone(),
                direct_addresses: direct_addresses.clone(),
                exposure: route.exposure.clone().unwrap_or_default(),
                external_roost: *external_roost,
            },
            // A route kind this build does not know is never connected.
            _ => {
                plan.refused
                    .push((route.id.clone(), reason::TRANSPORT_UNAVAILABLE));
                continue;
            }
        };
        plan.routes.push(PlannedRoute {
            id: route.id.clone(),
            leg,
            identification_timeout: heimdall_domain::routes::identification_timeout(route),
        });
    }
    if plan.routes.is_empty() {
        let first = plan
            .refused
            .first()
            .map_or(reason::ROUTE_UNAPPROVED, |(_, r)| *r);
        return Err(RouteHelperError::NoUsableRoute(first));
    }
    Ok(plan)
}

// --- the ports and the run ----------------------------------------------------------------

/// What the helper reads from the runtime and the catalog, and where it writes route
/// health. Implemented by the runtime's client (W2); tests use fixtures.
#[async_trait]
pub trait RouteHelperPorts: Send + Sync {
    /// `ResolveRouteBinding{destination, account, endpoint}`: the one binding served at
    /// `endpoint` for the caller's context ([`select_route_binding`]).
    async fn resolve_route_binding(
        &self,
        destination: &DestinationId,
        account: &AccountName,
        endpoint: &str,
    ) -> Result<RouteBinding, RouteHelperError>;

    /// The catalog's route facts (destinations, pair preferences, stored route lists).
    async fn route_view(&self) -> Result<RouteCatalogView, RouteHelperError>;

    /// ⟨rev7; ruled 2026-11-25⟩ The route facts `pair`'s routes are planned from: what
    /// [`route_connect`] reads. A port over the store reads them by key
    /// ([`route_catalog_view_of`]: the destination, its hops and its jumpers); by default, the
    /// whole [`Self::route_view`].
    async fn route_view_of(&self, pair: &AccessPair) -> Result<RouteCatalogView, RouteHelperError> {
        let _ = pair;
        self.route_view().await
    }

    /// The jump leg's catalog pin and access for `route` (ADR-0012 §5.4): the jump's pin file
    /// and `hm-dest-<jump>` alias, and for [`JumpAccess::Managed`] the binding's endpoint and
    /// the jump pair's certificate, for [`JumpAccess::Existing`] the jump identity's endpoint
    /// and public key file.
    async fn jump_hop(
        &self,
        route: &ApprovedRoute,
        access: JumpAccess,
        binding: &RouteBinding,
    ) -> Result<JumpHop, RouteHelperError>;

    /// Record one route-health result (`route.health`, `inspect`).
    async fn record_health(&self, payload: RouteHealthPayload);
}

/// `heimdall route connect`: resolve the binding, plan the approved routes, then connect
/// with failover, forwarding between `client_in`/`client_out` (the client `ssh`'s pipes) and
/// the established leg. Refused routes are reported on `diagnostics` by ID and reason only.
///
/// # Errors
/// [`RouteHelperError`] before any route is tried; ⟨M06 exit, Q-B⟩
/// [`RouteHelperError::DriverUnavailable`] after the attempts are recorded, when nothing was
/// established and every leg tried has no driver in this build.
pub async fn route_connect<P, D, I, O>(
    args: &HelperArgs,
    ports: &P,
    dialer: &D,
    client_in: I,
    client_out: O,
    config: &FailoverConfig,
    diagnostics: &mut (dyn std::io::Write + Send),
) -> Result<FailoverOutcome, RouteHelperError>
where
    P: RouteHelperPorts + ?Sized,
    D: failover::LegDialer + ?Sized,
    I: AsyncRead + Unpin + Send + 'static,
    O: AsyncWrite + Unpin + Send + 'static,
{
    let binding = ports
        .resolve_route_binding(&args.destination, &args.account, &args.endpoint)
        .await?;
    // Defence in depth: the runtime's answer must be the binding at this endpoint, covering
    // this pair, whatever the implementation.
    let binding =
        select_route_binding(std::slice::from_ref(&binding), &args.pair(), &args.endpoint)?;
    let view = ports.route_view_of(&args.pair()).await?;
    let mut plan = plan_routes(&view, &args.pair(), &binding)?;
    for (route, why) in &plan.refused {
        let _ = writeln!(
            diagnostics,
            "heimdall route connect: route {route} not used: {why}"
        );
    }
    // The jump leg's pin and access, per route. A jump route whose hop cannot be built for
    // this binding (its dependency is outside the binding's grant, or its catalog pin or
    // identity is not there) is not attempted, like a route refused at planning; the other
    // approved routes stand. When none remains, the helper refuses with the first reason.
    let mut usable = Vec::with_capacity(plan.routes.len());
    let mut first_refusal = None;
    for mut planned in std::mem::take(&mut plan.routes) {
        if let LegPlan::Jump {
            route, access, hop, ..
        } = &mut planned.leg
        {
            match ports.jump_hop(route, *access, &binding).await {
                Ok(h) => *hop = Some(Box::new(h)),
                Err(e) => {
                    let _ = writeln!(
                        diagnostics,
                        "heimdall route connect: route {} not used: {}",
                        planned.id,
                        e.reason().unwrap_or("route_unavailable")
                    );
                    first_refusal.get_or_insert(e);
                    continue;
                }
            }
        }
        usable.push(planned);
    }
    if usable.is_empty() {
        return Err(first_refusal.unwrap_or(RouteHelperError::RouteUnapproved));
    }
    plan.routes = usable;
    let outcome = failover::run_failover(
        &args.destination,
        &args.account,
        &plan.routes,
        dialer,
        client_in,
        client_out,
        config,
        &|payload| ports.record_health(payload),
    )
    .await;
    // ⟨2026-11-21, ruling 3⟩ The precise reason a client's identification line ended the
    // connect, or kept it off an Iroh route when nothing was established (never its bytes).
    if let Some(why) = outcome.client_failure
        && (why.is_terminal() || outcome.final_route.is_none())
    {
        let _ = writeln!(diagnostics, "heimdall route connect: {}", why.message());
    }
    // ⟨M06 exit, Q-B⟩ Every leg had no driver in this build (all Iroh, no `iroh` feature).
    if outcome.final_route.is_none()
        && plan
            .routes
            .iter()
            .all(|r| outcome.driver_unavailable.contains(&r.id))
    {
        return Err(RouteHelperError::DriverUnavailable);
    }
    Ok(outcome)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::managed::PreferredMechanism;
    use heimdall_contract::route::DestinationRoute;
    use heimdall_domain::catalog::DestinationRecord;

    fn d(s: &str) -> DestinationId {
        DestinationId::parse(s).unwrap()
    }

    fn pair(dest: &str, account: &str) -> AccessPair {
        AccessPair {
            destination: d(dest),
            account: AccountName::parse(account).unwrap(),
        }
    }

    fn managed(account: &str) -> DestinationDefinition {
        DestinationDefinition::Managed {
            hostname: "10.0.0.2".into(),
            port: Some(2222),
            account: AccountName::parse(account).unwrap(),
            identity: heimdall_contract::ids::IdentityId::from_random_bytes([1; 16]),
            jump: None,
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

    /// `final` (account `deploy`) has routes [jump via `b1`, jump via `b2`, direct]; `b1`'s
    /// and `b2`'s pairs prefer managed certificates.
    fn view() -> RouteCatalogView {
        let mut v = RouteCatalogView::default();
        for (id, account) in [("final", "deploy"), ("b1", "jump"), ("b2", "jump")] {
            v.destinations.insert(
                d(id),
                DestinationRecord {
                    id: d(id),
                    alias: format!("a-{id}"),
                    revision: 1,
                    definition: managed(account),
                    label: None,
                    updated_at: "2026-11-20T12:00:00Z".parse().unwrap(),
                },
            );
        }
        for b in ["b1", "b2"] {
            v.mechanisms
                .insert(pair(b, "jump"), PreferredMechanism::ManagedCertificate);
        }
        v.routes.insert(
            d("final"),
            vec![
                route(1, RouteSpec::Jump { via: d("b1") }),
                route(2, RouteSpec::Jump { via: d("b2") }),
                route(
                    3,
                    RouteSpec::Direct {
                        host: "10.0.0.2".into(),
                        port: None,
                    },
                ),
            ],
        );
        v
    }

    fn binding(n: u8, endpoint: &str, pairs: &[AccessPair]) -> RouteBinding {
        RouteBinding {
            binding: BindingId::from_random_bytes([n; 16]),
            grant: GrantId::from_random_bytes([n; 16]),
            endpoint: endpoint.into(),
            pairs: pairs.iter().cloned().collect(),
        }
    }

    /// ⟨rev7; ruled 2026-11-25 (U3-1b's Q2)⟩ The helper plans from the pair's records read by
    /// key, never the whole catalog: over a store at D20's maximum for the destination (8
    /// approved routes, jumps through 7 hops, each hop preferring managed certificates) among
    /// 500 other destinations, one of them damaged so that any read of every destination
    /// fails, the plan is the one the whole catalog gives. The chain rule's reverse lookup
    /// holds too: once another destination jumps through `final`, its jump routes are refused
    /// exactly as over the whole catalog.
    #[test]
    fn a_store_at_the_maximum_plans_a_route_without_reading_every_destination() {
        use heimdall_contract::bounds::MAX_ROUTES_PER_DESTINATION;
        use heimdall_store::ext_m07::PageTable;
        let store =
            heimdall_store::Store::open_in_memory(std::sync::Arc::new(heimdall_store::NoFaults))
                .unwrap();
        let record = |id: &str, account: &str, jump: Option<&str>| DestinationRecord {
            id: d(id),
            alias: format!("a-{id}"),
            revision: 1,
            definition: DestinationDefinition::Managed {
                hostname: format!("{id}.lan"),
                port: None,
                account: AccountName::parse(account).unwrap(),
                identity: heimdall_contract::ids::IdentityId::from_random_bytes([1; 16]),
                jump: jump.map(d),
            },
            label: None,
            updated_at: "2026-11-25T09:00:00Z".parse().unwrap(),
        };
        let now: heimdall_contract::Timestamp = "2026-11-25T09:00:00Z".parse().unwrap();
        let hops: Vec<String> = (1..MAX_ROUTES_PER_DESTINATION)
            .map(|i| format!("hop{i}"))
            .collect();
        store
            .transaction(|tx| {
                for i in 0..500 {
                    tx.upsert_destination(&record(&format!("other{i:03}"), "x", None))?;
                }
                tx.upsert_destination(&record("final", "deploy", None))?;
                for h in &hops {
                    tx.upsert_destination(&record(h, "jump", None))?;
                    tx.set_pair_preference(
                        &heimdall_domain::enrollment::PairPreference {
                            destination: d(h),
                            account: AccountName::parse("jump").unwrap(),
                            mechanism: PreferredMechanism::ManagedCertificate,
                            projection: heimdall_domain::enrollment::ProjectionStatus::Pending,
                            issuing_cas: std::collections::BTreeSet::new(),
                        },
                        now,
                    )?;
                }
                let mut list: Vec<DestinationRoute> = hops
                    .iter()
                    .enumerate()
                    .map(|(i, h)| {
                        route(u8::try_from(i).unwrap() + 1, RouteSpec::Jump { via: d(h) })
                    })
                    .collect();
                list.push(route(
                    99,
                    RouteSpec::Direct {
                        host: "10.0.0.2".into(),
                        port: None,
                    },
                ));
                assert_eq!(list.len(), MAX_ROUTES_PER_DESTINATION);
                tx.put_destination_routes(&d("final"), &list, now)
            })
            .unwrap();
        let final_pair = pair("final", "deploy");
        let mut pairs = vec![final_pair.clone()];
        pairs.extend(hops.iter().map(|h| pair(h, "jump")));
        let b = binding(1, "/run/hm/b.sock", &pairs);
        let whole = route_catalog_view(&store).unwrap();
        let expected = plan_routes(&whole, &final_pair, &b).unwrap();
        assert_eq!(expected.routes.len(), MAX_ROUTES_PER_DESTINATION);
        store
            .transaction(|tx| tx.damage_document_for_test(PageTable::Destinations, "other250"))
            .unwrap();
        assert!(
            route_catalog_view(&store).is_err(),
            "a read of every destination meets the damaged one"
        );
        let keyed = route_catalog_view_of(&store, &d("final")).unwrap();
        assert!(
            keyed.destinations.len() <= MAX_ROUTES_PER_DESTINATION,
            "only the pair's destination and its hops: {:?}",
            keyed.destinations.keys().collect::<Vec<_>>()
        );
        let planned = plan_routes(&keyed, &final_pair, &b).unwrap();
        assert_eq!(
            format!("{:?}", planned.routes),
            format!("{:?}", expected.routes)
        );
        assert_eq!(planned.refused, expected.refused);
        // Another destination now jumps through `final`: its jump routes are a chain.
        store
            .transaction(|tx| {
                tx.upsert_destination(&record("outer", "o", Some("final")))?;
                tx.damage_document_for_test(PageTable::Destinations, "other250")
            })
            .unwrap();
        let keyed = route_catalog_view_of(&store, &d("final")).unwrap();
        let planned = plan_routes(&keyed, &final_pair, &b).unwrap();
        assert_eq!(planned.routes.len(), 1, "only the direct route stands");
        assert_eq!(planned.refused.len(), MAX_ROUTES_PER_DESTINATION - 1);
        assert!(
            planned
                .refused
                .iter()
                .all(|(_, r)| *r == reason::ROUTE_CHAIN_UNSUPPORTED),
            "{:?}",
            planned.refused
        );
    }

    #[test]
    fn helper_arguments_are_exactly_the_typed_inputs() {
        let parse = |a: &[&str]| HelperArgs::parse(a.iter().map(OsString::from));
        let ok = parse(&[
            "--destination",
            "lab",
            "--account",
            "deploy",
            "--endpoint",
            "/run/a b/agent.sock",
        ])
        .unwrap();
        assert_eq!(ok.endpoint, "/run/a b/agent.sock");
        assert_eq!(
            parse(&[
                "--endpoint",
                "//./pipe/hm",
                "--account",
                "a",
                "--destination",
                "x"
            ])
            .unwrap()
            .endpoint,
            "//./pipe/hm"
        );
        for bad in [
            &["--destination", "lab", "--account", "deploy"][..],
            &[
                "--destination",
                "lab",
                "--account",
                "deploy",
                "--endpoint",
                "rel/agent",
            ],
            &[
                "--destination",
                "lab",
                "--account",
                "deploy",
                "--endpoint",
                "/a",
                "--host",
                "h",
            ],
            &[
                "--destination",
                "lab",
                "--destination",
                "lab",
                "--account",
                "a",
                "--endpoint",
                "/a",
            ],
            &[
                "--destination",
                "a b",
                "--account",
                "deploy",
                "--endpoint",
                "/a",
            ],
            &["--destination", "lab", "--account", "deploy", "--endpoint"],
        ] {
            assert!(
                matches!(parse(bad), Err(RouteHelperError::Usage(_))),
                "{bad:?}"
            );
        }
    }

    /// ADR-0012 §5.4: zero or several bindings at the endpoint, or a grant that does not
    /// cover the pair, is `route_binding_ambiguous`; the helper never picks by destination.
    #[test]
    fn binding_resolution_refuses_ambiguity_and_uncovered_grants() {
        let p = pair("final", "deploy");
        let g1 = binding(1, "/run/e1", std::slice::from_ref(&p));
        let g2 = binding(2, "/run/e2", std::slice::from_ref(&p));
        assert_eq!(
            select_route_binding(&[g1.clone(), g2.clone()], &p, "/run/e1").unwrap(),
            g1
        );
        let refused = |c: &[RouteBinding], e: &str| select_route_binding(c, &p, e).unwrap_err();
        assert_eq!(
            refused(&[g1.clone(), g2.clone()], "/run/e3"),
            RouteHelperError::BindingAmbiguous
        );
        let twin = binding(3, "/run/e1", std::slice::from_ref(&p));
        assert_eq!(
            refused(&[g1.clone(), twin], "/run/e1"),
            RouteHelperError::BindingAmbiguous
        );
        let other = binding(4, "/run/e4", &[pair("b1", "jump")]);
        assert_eq!(
            refused(&[other], "/run/e4"),
            RouteHelperError::BindingAmbiguous
        );
        assert_eq!(
            RouteHelperError::BindingAmbiguous.reason(),
            Some("route_binding_ambiguous")
        );
    }

    /// ADR-0012 §5.4, ADR-0010 §5 item 2: two concurrent grants: the first grant's binding
    /// (final + b1) may use the jump through b1 only; b2's pair, in the second grant only, is
    /// refused for the first grant's final pair (`route_dependency_out_of_scope`), and the
    /// second grant's binding gets the opposite. No route outside the approved list appears.
    #[test]
    fn concurrent_grants_never_borrow_each_others_jump_pair() {
        let v = view();
        let p = pair("final", "deploy");
        let g1 = binding(1, "/run/e1", &[p.clone(), pair("b1", "jump")]);
        let g2 = binding(2, "/run/e2", &[p.clone(), pair("b2", "jump")]);
        let plan1 = plan_routes(&v, &p, &g1).unwrap();
        let ids = |plan: &RoutePlan| plan.routes.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
        let rid = |n: u8| RouteId::from_random_bytes([n; 16]);
        assert_eq!(ids(&plan1), [rid(1), rid(3)]);
        assert_eq!(plan1.refused, [(rid(2), "route_dependency_out_of_scope")]);
        assert!(matches!(
            &plan1.routes[0].leg,
            LegPlan::Jump { access: JumpAccess::Managed, final_host, final_port: 2222, .. } if final_host == "10.0.0.2"
        ));
        let plan2 = plan_routes(&v, &p, &g2).unwrap();
        assert_eq!(ids(&plan2), [rid(2), rid(3)]);
        assert_eq!(plan2.refused, [(rid(1), "route_dependency_out_of_scope")]);
        // With only jump routes, a grant holding neither jump pair has no usable route.
        let mut only_jumps = v.clone();
        only_jumps.routes.get_mut(&d("final")).unwrap().pop();
        let bare = binding(5, "/run/e5", std::slice::from_ref(&p));
        assert_eq!(
            plan_routes(&only_jumps, &p, &bare).unwrap_err(),
            RouteHelperError::NoUsableRoute("route_dependency_out_of_scope")
        );
        // A binding whose grant does not cover the pair, or another account: refused.
        assert_eq!(
            plan_routes(&v, &p, &binding(6, "/e", &[pair("b1", "jump")])).unwrap_err(),
            RouteHelperError::BindingAmbiguous
        );
        let wrong = pair("final", "root");
        assert_eq!(
            plan_routes(&v, &wrong, &binding(7, "/e", std::slice::from_ref(&wrong))).unwrap_err(),
            RouteHelperError::RouteUnapproved
        );
        // A jump pair with existing access (no stored preference) needs no grant scope.
        let mut existing = v.clone();
        existing.mechanisms.clear();
        let plan = plan_routes(&existing, &p, &bare).unwrap();
        assert_eq!(ids(&plan), [rid(1), rid(2), rid(3)]);
        assert!(matches!(
            &plan.routes[0].leg,
            LegPlan::Jump {
                access: JumpAccess::Existing,
                ..
            }
        ));
    }

    // --- ⟨M06 exit, Q-B⟩ an Iroh leg in a build without the `iroh` feature ----------

    use heimdall_contract::route::RouteFailureClass;

    struct HelperFixture {
        view: RouteCatalogView,
        binding: RouteBinding,
        health: std::sync::Mutex<Vec<RouteHealthPayload>>,
    }

    #[async_trait]
    impl RouteHelperPorts for HelperFixture {
        async fn resolve_route_binding(
            &self,
            _: &DestinationId,
            _: &AccountName,
            _: &str,
        ) -> Result<RouteBinding, RouteHelperError> {
            Ok(self.binding.clone())
        }
        async fn route_view(&self) -> Result<RouteCatalogView, RouteHelperError> {
            Ok(self.view.clone())
        }
        async fn jump_hop(
            &self,
            _: &ApprovedRoute,
            _: JumpAccess,
            _: &RouteBinding,
        ) -> Result<JumpHop, RouteHelperError> {
            Err(RouteHelperError::Unavailable)
        }
        async fn record_health(&self, payload: RouteHealthPayload) {
            self.health.lock().unwrap().push(payload);
        }
    }

    /// The direct leg: a server that identifies, then holds the stream until it ends.
    /// Records every route it is asked to dial.
    #[derive(Debug, Default)]
    struct DirectOnly {
        dialed: std::sync::Mutex<Vec<RouteId>>,
    }

    #[async_trait]
    impl failover::LegDialer for DirectOnly {
        async fn dial(
            &self,
            route: &PlannedRoute,
            _: Duration,
        ) -> Result<failover::Leg, failover::DialFailure> {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            self.dialed.lock().unwrap().push(route.id.clone());
            let LegPlan::Direct { .. } = route.leg else {
                return Err(failover::DialFailure::Refused);
            };
            let (client, mut server) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let _ = server.write_all(b"SSH-2.0-OpenSSH_test\r\n").await;
                let mut sink = Vec::new();
                let _ = server.read_to_end(&mut sink).await;
            });
            let (reader, writer) = tokio::io::split(client);
            Ok(failover::Leg {
                reader: Box::new(reader),
                writer: Box::new(writer),
                ending: None,
            })
        }
    }

    fn iroh_route(n: u8) -> DestinationRoute {
        route(
            n,
            RouteSpec::Iroh {
                endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
                direct_addresses: vec!["127.0.0.1:1".into()],
                external_roost: false,
            },
        )
    }

    /// Run the helper for `final`/`deploy` over `routes` with the build's dialer as a build
    /// without the `iroh` feature makes it: no Iroh dialer, `iroh_in_build` false.
    fn connect_without_iroh(
        routes: Vec<DestinationRoute>,
    ) -> (
        Result<FailoverOutcome, RouteHelperError>,
        Vec<RouteHealthPayload>,
        Vec<RouteId>,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let p = pair("final", "deploy");
        let mut v = view();
        v.routes.insert(d("final"), routes);
        let ports = HelperFixture {
            view: v,
            binding: binding(1, "/run/e1", std::slice::from_ref(&p)),
            health: std::sync::Mutex::new(Vec::new()),
        };
        let dialer = legs::RouteLegDialer {
            base: DirectOnly::default(),
            iroh: None,
            iroh_in_build: false,
        };
        let args = HelperArgs {
            destination: p.destination.clone(),
            account: p.account.clone(),
            endpoint: "/run/e1".into(),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let ended = rt.block_on(async {
            let (mut client, helper) = tokio::io::duplex(4096);
            let (helper_in, helper_out) = tokio::io::split(helper);
            // The client identifies at once, as OpenSSH does, and ends once it has the
            // server's identification.
            let user = tokio::spawn(async move {
                let _ = client.write_all(b"SSH-2.0-OpenSSH_client\r\n").await;
                let mut got = Vec::new();
                let mut chunk = [0u8; 256];
                while !got.ends_with(b"\n") {
                    match tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
                        .await
                    {
                        Ok(Ok(n)) if n > 0 => got.extend_from_slice(&chunk[..n]),
                        _ => break,
                    }
                }
                got
            });
            let mut diagnostics = Vec::new();
            let ended = route_connect(
                &args,
                &ports,
                &dialer,
                helper_in,
                helper_out,
                &FailoverConfig::default(),
                &mut diagnostics,
            )
            .await;
            let _ = user.await;
            ended
        });
        let health = ports.health.lock().unwrap().clone();
        let dialed = dialer.base.dialed.lock().unwrap().clone();
        (ended, health, dialed)
    }

    #[test]
    fn an_iroh_leg_without_the_driver_is_driver_unavailable_and_fails_over() {
        let rid = |n: u8| RouteId::from_random_bytes([n; 16]);
        let (ended, health, dialed) = connect_without_iroh(vec![
            iroh_route(1),
            route(
                2,
                RouteSpec::Direct {
                    host: "127.0.0.1".into(),
                    port: Some(2222),
                },
            ),
        ]);
        let outcome = ended.unwrap();
        // The direct leg carried the session; the Iroh leg was never dialed.
        assert_eq!(outcome.final_route, Some(rid(2)));
        assert_eq!(outcome.driver_unavailable, [rid(1)]);
        assert_eq!(dialed, [rid(2)]);
        // The attempt record: the Iroh leg as driver-unavailable, then the direct leg.
        let established = &health[0];
        assert_eq!(
            established.kind,
            heimdall_contract::route::RouteEventKind::FailedOver
        );
        assert_eq!(established.final_route, Some(rid(2)));
        let attempts: Vec<_> = established
            .attempts
            .iter()
            .map(|a| (a.route.clone(), a.failure))
            .collect();
        assert_eq!(
            attempts,
            [
                (rid(1), Some(RouteFailureClass::DriverUnavailable)),
                (rid(2), None)
            ]
        );
    }

    #[test]
    fn a_destination_whose_every_leg_is_iroh_is_refused_driver_unavailable() {
        let rid = |n: u8| RouteId::from_random_bytes([n; 16]);
        let (ended, health, dialed) = connect_without_iroh(vec![iroh_route(1), iroh_route(2)]);
        let refusal = ended.unwrap_err();
        assert_eq!(refusal, RouteHelperError::DriverUnavailable);
        assert_eq!(refusal.reason(), Some(reason::DRIVER_UNAVAILABLE));
        let text = refusal.to_string();
        assert!(text.starts_with(IROH_ROUTE_PREVIEW_UNAVAILABLE), "{text}");
        assert!(
            text.ends_with("(CAPABILITY_UNAVAILABLE / driver_unavailable)"),
            "{text}"
        );
        assert!(
            text.contains("`cargo build --features iroh`")
                && text.contains("so this route has no usable leg"),
            "{text}"
        );
        // Nothing was dialed, and both attempts were recorded before the refusal.
        assert!(dialed.is_empty());
        let [none] = health.as_slice() else {
            panic!("{health:?}");
        };
        assert_eq!(none.final_route, None);
        let attempts: Vec<_> = none
            .attempts
            .iter()
            .map(|a| (a.route.clone(), a.failure))
            .collect();
        let class = Some(RouteFailureClass::DriverUnavailable);
        assert_eq!(attempts, [(rid(1), class), (rid(2), class)]);
    }
}
