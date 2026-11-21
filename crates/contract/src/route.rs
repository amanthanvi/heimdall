//! ⟨M06⟩ ADR-0006 revision 6 (§18; ADR-0012 §2, §5, §9 items 6, 8 and 9): approved routes,
//! effective exposure policies and their consents, a destination's route list and pinned
//! host keys, the route and transport requests, and the route-health result.
//!
//! Contract types only. Wave 0 does not wire them into the catalog or the domain (m06-plan
//! U5a does): the destination object keeps its single route and jump fields, the route and
//! transport requests answer `CAPABILITY_UNAVAILABLE` / `driver_unavailable` before any
//! record is written, and `routes/1` and `transport-iroh/1` are declared and not offered.
//! A route is reachability data only: it grants nothing and never changes host identity
//! (ADR-0012 §5.1).

use serde::{Deserialize, Serialize};

use crate::ids::{
    AccountName, ConsentId, DestinationId, IrohEndpointId, KeyFingerprint, RequestId, RouteId,
};

/// Default bound on waiting for the server's SSH identification line through a candidate
/// route (ADR-0012 §5.5 item 1), in milliseconds.
pub const DEFAULT_IDENTIFICATION_TIMEOUT_MS: u64 = 10_000;

/// An approved route's reachability data (ADR-0012 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RouteSpec {
    /// A direct TCP route.
    Direct {
        /// Host name or address.
        host: String,
        /// Port; ssh's default when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    /// A single-hop jump through another catalog destination (ADR-0010 §5's semantics;
    /// multi-hop chains stay `route_chain_unsupported`).
    Jump {
        /// The jump destination.
        via: DestinationId,
    },
    /// An Iroh route to an endpoint ID under the route's exposure policy.
    Iroh {
        /// The serving endpoint.
        endpoint: IrohEndpointId,
        /// ⟨rev6.1⟩ The serving endpoint's direct addresses (`ip:port`) recorded with the
        /// route. Direct paths go only to these unless the exposure policy consents to
        /// direct fallback (ADR-0012 §2.1).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        direct_addresses: Vec<String>,
        /// The endpoint is an adopted stock Pigeons roost: external infrastructure with
        /// no allowlist, publishing to n0, on its own relay set (ADR-0012 §2.8).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        external_roost: bool,
    },
}

/// Where an endpoint binds (ADR-0012 §2.1). Anything but `loopback` or `none` needs a
/// recorded consent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum BindScope {
    /// No bind (relay-only).
    None,
    /// Loopback only (the default).
    Loopback,
    /// One non-loopback interface address (a widening).
    Interface {
        /// The address.
        address: String,
    },
    /// A wildcard bind (a widening).
    Wildcard,
}

/// Relay and lookup infrastructure (ADR-0012 §2.2). A route never falls back to a profile
/// it does not name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum InfrastructureProfile {
    /// Direct only (the default).
    None,
    /// The user's relay URLs, each consented.
    Custom {
        /// Relay URLs.
        relays: Vec<String>,
    },
    /// n0's relays plus lookup: off by default and outside V1 unless its capture row runs.
    N0Public,
}

/// One endpoint's effective exposure policy (ADR-0012 §2.1): the bind, relay map, peer
/// relay hints, direct addresses, lookup and ancillary targets are built from it alone,
/// and anything outside it is refused. The default is the minimal policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExposurePolicy {
    /// Where the endpoint binds.
    pub bind: BindScope,
    /// Relay and lookup infrastructure.
    pub infrastructure: InfrastructureProfile,
    /// Direct fallback to learned or public addresses (reveals public IPs; a widening).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub direct_fallback: bool,
}

impl Default for ExposurePolicy {
    /// The minimal policy: loopback bind, no relays, no lookup, direct paths only to the
    /// route record's own addresses.
    fn default() -> Self {
        Self {
            bind: BindScope::Loopback,
            infrastructure: InfrastructureProfile::None,
            direct_fallback: false,
        }
    }
}

/// One approved route of a destination (ADR-0012 §5.1, §9 item 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DestinationRoute {
    /// The route.
    pub id: RouteId,
    /// Its reachability data.
    pub route: RouteSpec,
    /// Its effective exposure policy (Iroh routes); the minimal policy when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<ExposurePolicy>,
    /// The recorded consents its exposure relies on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consents: Vec<ConsentId>,
    /// The identification wait for this route, in milliseconds;
    /// [`DEFAULT_IDENTIFICATION_TIMEOUT_MS`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identification_timeout_ms: Option<u64>,
}

/// One catalog-pinned host key of a destination (ADR-0012 §5.1, §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostKeyPin {
    /// The OpenSSH public key line (public text).
    pub public_key: String,
    /// Its fingerprint.
    pub fingerprint: KeyFingerprint,
}

/// A destination's approved routes, in preference order, and its pinned host keys
/// (ADR-0012 §9 item 9). The existing single route and jump fields of the destination are
/// the one-element case; wave 0 defines the type only (m06-plan U5a attaches it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DestinationRoutes {
    /// The destination.
    pub destination: DestinationId,
    /// Approved routes, most preferred first.
    pub routes: Vec<DestinationRoute>,
    /// The approved host-key set; every route is checked against it.
    pub host_keys: Vec<HostKeyPin>,
}

/// `Request::Route`, tagged by `action` (ADR-0012 §5, §9 item 6: `route add|remove|prefer`
/// and the helper's `ResolveRouteBinding`). Capability `routes/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RouteRequest {
    /// Approve a new route for a destination. New or expanded exposure is a widening
    /// action confirmed by an attended session local to the endpoint that widens
    /// (ADR-0012 §2.1, §3.10). Kind `route.add`.
    Add {
        /// The destination.
        destination: DestinationId,
        /// The route.
        route: RouteSpec,
        /// Its exposure policy (Iroh routes); the minimal policy when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exposure: Option<ExposurePolicy>,
        /// Idempotency key (ADR-0006 §7).
        request_id: RequestId,
    },
    /// Remove a route (narrowing). Kind `route.remove`.
    Remove {
        /// The destination.
        destination: DestinationId,
        /// The route.
        route: RouteId,
    },
    /// Make a route the most preferred. A pure preference change needs the routes'
    /// existing recorded consents and no new decision (ADR-0012 §2.1). Kind
    /// `route.prefer`.
    Prefer {
        /// The destination.
        destination: DestinationId,
        /// The route.
        route: RouteId,
        /// ⟨rev6.1; M06-W0-R08⟩ Optional idempotency key (ADR-0006 §7): a preference among
        /// already-consented routes needs no decision, so no terminal replay is owed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<RequestId>,
    },
    /// The route helper's lookup (ADR-0012 §5.4, `ResolveRouteBinding`): the one binding
    /// (and its grant) served at `endpoint` for the caller's context; zero or several is
    /// `route_binding_ambiguous`. Read-only. Kind `route.resolve_binding`.
    ResolveBinding {
        /// The destination.
        destination: DestinationId,
        /// The account.
        account: AccountName,
        /// The binding endpoint the alias renders (`IdentityAgent` and `--endpoint`).
        endpoint: String,
    },
}

impl RouteRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            RouteRequest::Add { .. } => "route.add",
            RouteRequest::Remove { .. } => "route.remove",
            RouteRequest::Prefer { .. } => "route.prefer",
            RouteRequest::ResolveBinding { .. } => "route.resolve_binding",
        }
    }
}

/// `Request::Transport`, tagged by `action` (ADR-0012 §2, §9 item 6: `transport
/// enable|disable` and `roost adopt`). Capability `transport-iroh/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransportRequest {
    /// Generate K_iroh in a verified platform store and, with `serve`, start the
    /// supervised serve child (ADR-0012 §2.3, §2.4). Exposure beyond the minimal policy is
    /// a widening action. Kind `transport.enable`.
    Enable {
        /// Also serve this host's sshd to enrolled clients.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        serve: bool,
        /// The endpoint's exposure policy; the minimal policy when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exposure: Option<ExposurePolicy>,
        /// Idempotency key (ADR-0006 §7).
        request_id: RequestId,
    },
    /// Stop serve, destroy K_iroh and remove every route that names it, with their
    /// projections and allowlist entries (ADR-0012 §2.5). Kind `transport.disable`.
    Disable,
    /// Adopt an existing stock Pigeons roost as a destination's Iroh route (ADR-0012
    /// §2.8): a widening action bound to the roost's endpoint ID and disclosed exposure.
    /// Kind `transport.adopt_roost`.
    AdoptRoost {
        /// The destination.
        destination: DestinationId,
        /// The roost's endpoint.
        endpoint: IrohEndpointId,
        /// The dialer's exposure policy for it; the minimal policy when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exposure: Option<ExposurePolicy>,
        /// Idempotency key (ADR-0006 §7).
        request_id: RequestId,
    },
}

impl TransportRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            TransportRequest::Enable { .. } => "transport.enable",
            TransportRequest::Disable => "transport.disable",
            TransportRequest::AdoptRoost { .. } => "transport.adopt_roost",
        }
    }
}

// --- route health (ADR-0012 §5.5 item 4, §9 item 8) --------------------------------------

/// Why one route attempt failed (ADR-0012 §5.5 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RouteFailureClass {
    /// Connect refused (or the jump leg exited) before identification.
    Refused,
    /// Connect timed out.
    Timeout,
    /// No SSH identification line within the route's bound.
    IdentificationTimeout,
    /// The Iroh serving side refused admission before identification.
    AdmissionRefused,
    /// A failure after the first forwarded byte: terminal for the attempt, never failed
    /// over.
    TerminalAfterForwarding,
    /// ⟨rev6.1⟩ The jump leg failed SSH host-key verification or authentication at the jump
    /// host before identification: terminal, never failed over (ADR-0012 §5.5 item 3).
    AuthenticationOrTrust,
}

/// One tried route of an attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouteAttempt {
    /// The route.
    pub route: RouteId,
    /// Its failure; absent when this route was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<RouteFailureClass>,
}

/// What a `route` event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RouteEventKind {
    /// `route.health`: one attempt's structured result, written for every attempt.
    Health,
    /// `route.failed_over`: the subtype of `route.health` for an attempt that moved past
    /// a failed route.
    FailedOver,
}

/// Payload of `EventType::Route` (not emitted by wave 0), also readable through
/// `inspect`. The helper's exit codes stay internal (ADR-0012 §1.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouteHealthPayload {
    /// The kind.
    pub kind: RouteEventKind,
    /// The destination.
    pub destination: DestinationId,
    /// The account.
    pub account: AccountName,
    /// Each tried route, in order.
    pub attempts: Vec<RouteAttempt>,
    /// The route finally used; absent when none was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_route: Option<RouteId>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// ADR-0012 §2.1: the default exposure is the minimal policy, and it is written out in
    /// full (no widening is ever implied by an omitted field).
    #[test]
    fn default_exposure_is_minimal() {
        let p = ExposurePolicy::default();
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            serde_json::json!({"bind": {"kind": "loopback"}, "infrastructure": {"kind": "none"}})
        );
        let back: ExposurePolicy = serde_json::from_str(
            r#"{"bind":{"kind":"loopback"},"infrastructure":{"kind":"none"}}"#,
        )
        .unwrap();
        assert!(!back.direct_fallback);
        assert!(
            serde_json::from_str::<ExposurePolicy>(r#"{"infrastructure":{"kind":"none"}}"#)
                .is_err(),
            "a policy without its bind is refused, never defaulted"
        );
    }
}
