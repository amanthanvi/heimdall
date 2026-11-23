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
    /// ⟨rev6.3⟩ The serve port (ADR-0012 §2.1 ⟨2026-11-21⟩; `heimdall transport enable
    /// --port <n>`). Omitted when none: the first successful bind's port is then recorded
    /// durably and reused at every later start. `0` is refused. A port that cannot be bound
    /// fails closed (`transport_unavailable`); changing it is `disable` then `enable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// ⟨rev6.5; ADR-0006 §18.9 item 1⟩ The local sshd port a serving endpoint forwards to
    /// (ADR-0012 §2.3 item 2 ⟨2026-11-22⟩; `heimdall transport enable --serve --sshd-port
    /// <n>`), 1–65535. Omitted when it is the default, 22. `0` is refused. The target host
    /// is `127.0.0.1` and is not part of any policy. Meaningful only with `serve`; changing
    /// it is `disable` then `enable`.
    #[schemars(range(min = 1))]
    #[serde(
        default = "default_sshd_port",
        skip_serializing_if = "is_default_sshd_port"
    )]
    pub sshd_port: u16,
}

/// The sshd port a serving endpoint forwards to when its policy names none.
pub const DEFAULT_SSHD_PORT: u16 = 22;

fn default_sshd_port() -> u16 {
    DEFAULT_SSHD_PORT
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` signature
fn is_default_sshd_port(port: &u16) -> bool {
    *port == DEFAULT_SSHD_PORT
}

impl ExposurePolicy {
    /// Whether the policy's own values are well formed: a named port is not `0`.
    #[must_use]
    pub fn port_is_valid(&self) -> bool {
        self.port != Some(0)
    }

    /// ⟨rev6.5⟩ Whether the sshd port is one a serve child may forward to (not `0`).
    #[must_use]
    pub fn sshd_port_is_valid(&self) -> bool {
        self.sshd_port != 0
    }
}

/// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ Why a relay URL is refused ([`normalize_relay_url`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelayUrlRefusal {
    /// Not one of the schemes the relay transport accepts (`https`, `http`).
    Scheme,
    /// The authority carries userinfo (`user@`, `user:password@`).
    Userinfo,
    /// A query string: it could carry a credential, and no relay needs one.
    Query,
    /// A fragment.
    Fragment,
    /// Anything else that is not a plain relay URL: no host, a host or path with characters
    /// outside the plain set (whitespace, control and percent-encoded characters included),
    /// a dot segment, a port that is not 1–65535, or more than [`RELAY_URL_MAX_BYTES`].
    Malformed,
}

impl RelayUrlRefusal {
    /// What to tell the user. Never quotes the URL (a refused one may hold a secret).
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            RelayUrlRefusal::Scheme => "a relay URL is https:// or http://",
            RelayUrlRefusal::Userinfo => {
                "a relay URL carries no user name or password (remove the part before `@`)"
            }
            RelayUrlRefusal::Query => "a relay URL carries no query string (remove `?…`)",
            RelayUrlRefusal::Fragment => "a relay URL carries no fragment (remove `#…`)",
            RelayUrlRefusal::Malformed => {
                "a relay URL is a scheme, a host, an optional port and a plain path"
            }
        }
    }
}

/// The longest relay URL accepted, in bytes.
pub const RELAY_URL_MAX_BYTES: usize = 2048;

/// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ Validate a relay URL and return its one spelling, so a
/// recorded delta, its digest and a retry all see the same text.
///
/// Accepted: `https://` or `http://` (the schemes the relay transport accepts), a host (a
/// DNS name, an IPv4 address or a bracketed IPv6 address), an optional port and an optional
/// path of unreserved characters. The normal form has the scheme and host in lowercase, no
/// default port (443 for `https`, 80 for `http`), a port without leading zeros, an address
/// in its canonical text, and `/` for an empty path. The path is otherwise kept: it is
/// case-sensitive, and percent-encoding is refused rather than decoded, so no two accepted
/// texts name one path.
///
/// # Errors
/// The [`RelayUrlRefusal`]: userinfo, any query string and a fragment are refused, so no
/// secret can arrive through a relay URL.
pub fn normalize_relay_url(text: &str) -> Result<String, RelayUrlRefusal> {
    use RelayUrlRefusal as R;
    if text.len() > RELAY_URL_MAX_BYTES || text.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(R::Malformed);
    }
    let (scheme, rest) = text.split_once("://").ok_or(R::Scheme)?;
    let (scheme, default_port) = match scheme.to_ascii_lowercase().as_str() {
        "https" => ("https", 443u16),
        "http" => ("http", 80u16),
        _ => return Err(R::Scheme),
    };
    // The classes are checked on the whole text after the scheme, most specific first, so
    // a credential is named as such wherever it sits.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return Err(R::Userinfo);
    }
    if tail.contains('#') {
        return Err(R::Fragment);
    }
    if tail.contains('?') {
        return Err(R::Query);
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (addr, after) = v6.split_once(']').ok_or(R::Malformed)?;
        let addr: std::net::Ipv6Addr = addr.parse().map_err(|_| R::Malformed)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(R::Malformed)?),
        };
        (format!("[{addr}]"), port)
    } else {
        let (name, port) = match authority.split_once(':') {
            Some((n, p)) => (n, Some(p)),
            None => (authority, None),
        };
        let name = name.to_ascii_lowercase();
        let plain = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            && !name.starts_with(['-', '.'])
            && !name.contains("..");
        if !plain {
            return Err(R::Malformed);
        }
        // A host of digits and dots is an address and has one text.
        let host = if name.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            name.parse::<std::net::Ipv4Addr>()
                .map_err(|_| R::Malformed)?
                .to_string()
        } else {
            name
        };
        (host, port)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(R::Malformed);
            }
            match p.parse::<u16>() {
                Ok(0) | Err(_) => return Err(R::Malformed),
                Ok(n) if n == default_port => None,
                Ok(n) => Some(n),
            }
        }
    };
    let path = if tail.is_empty() { "/" } else { tail };
    let plain_path = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_' | b'~'))
        && !path.split('/').any(|seg| seg == "." || seg == "..")
        && !path.contains("//");
    if !plain_path {
        return Err(R::Malformed);
    }
    Ok(match port {
        Some(n) => format!("{scheme}://{host}:{n}{path}"),
        None => format!("{scheme}://{host}{path}"),
    })
}

impl ExposurePolicy {
    /// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ This policy with every relay URL of a `custom`
    /// profile in its normal form ([`normalize_relay_url`]), sorted, each once: the set has
    /// one spelling whatever order or how often its URLs were given (a relay set has no
    /// order of preference). Every other profile is returned unchanged.
    ///
    /// # Errors
    /// The first refused URL's position (from 0) and its [`RelayUrlRefusal`].
    pub fn with_normalized_relays(&self) -> Result<Self, (usize, RelayUrlRefusal)> {
        let InfrastructureProfile::Custom { relays } = &self.infrastructure else {
            return Ok(self.clone());
        };
        let mut out: Vec<String> = Vec::with_capacity(relays.len());
        for (i, relay) in relays.iter().enumerate() {
            let normal = normalize_relay_url(relay).map_err(|why| (i, why))?;
            out.push(normal);
        }
        out.sort();
        out.dedup();
        Ok(Self {
            infrastructure: InfrastructureProfile::Custom { relays: out },
            ..self.clone()
        })
    }
}

impl Default for ExposurePolicy {
    /// The minimal policy: loopback bind, no relays, no lookup, direct paths only to the
    /// route record's own addresses, and no named port.
    fn default() -> Self {
        Self {
            bind: BindScope::Loopback,
            infrastructure: InfrastructureProfile::None,
            direct_fallback: false,
            port: None,
            sshd_port: DEFAULT_SSHD_PORT,
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
    /// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ The route helper's report of one connect (ADR-0012
    /// §5.5 item 4, §5.2). Kind `route.record_health`.
    ///
    /// * **Who may report:** only the caller for whom `endpoint` resolves, by
    ///   `resolve_binding`'s own rule, to the one binding that serves this pair there (the
    ///   helper acting for that binding). Any other caller is refused, a paired session and
    ///   another local client without that binding included.
    /// * **Typed:** every attempt names a route of the destination's stored, approved list
    ///   and an outcome class, with an optional duration of at most
    ///   [`ROUTE_ATTEMPT_DURATION_MAX_MS`]; at most [`ROUTE_HEALTH_ATTEMPTS_MAX`] attempts;
    ///   `host_pin_defeated` is one of [`HOST_PIN_SETTINGS`]. An unknown route, an unknown
    ///   setting or a value past a bound refuses the whole report. It carries no host name
    ///   and no free text.
    /// * **What it can do:** nothing but inform. A report never adds, removes or approves a
    ///   route and never relaxes a pin check: the routes a connect may use are the stored,
    ///   owner-approved, pinned ones, whatever was reported.
    /// * **Kept in memory only**, bounded per binding and in total, and lost when the
    ///   runtime restarts. The runtime emits the `route.health` event (the durable record)
    ///   and shows the latest result through `inspect destinations`.
    RecordHealth {
        /// The binding endpoint the alias renders (as in `resolve_binding`): what the
        /// runtime resolves the reporting binding from.
        endpoint: String,
        /// The attempt's result.
        result: RouteHealthPayload,
        /// The setting that defeated the destination's catalog pin (`host_pin_defeated`),
        /// one of [`HOST_PIN_SETTINGS`]; absent when the pin held.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_pin_defeated: Option<String>,
    },
}

/// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ The most attempts one route-health report may carry.
pub const ROUTE_HEALTH_ATTEMPTS_MAX: usize = 64;

/// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ The longest duration one attempt may report, in
/// milliseconds (ten minutes).
pub const ROUTE_ATTEMPT_DURATION_MAX_MS: u32 = 600_000;

/// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ Every value `host_pin_defeated` takes: the SSH setting
/// that does not hold the catalog pin, as `ssh -G` names it, or `unreadable` when the
/// effective configuration could not be read.
pub const HOST_PIN_SETTINGS: &[&str] = &[
    "proxycommand",
    "hostkeyalias",
    "userknownhostsfile",
    "globalknownhostsfile",
    "knownhostscommand",
    "stricthostkeychecking",
    "verifyhostkeydns",
    "updatehostkeys",
    "controlmaster",
    "controlpath",
    "unreadable",
];

impl RouteRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            RouteRequest::Add { .. } => "route.add",
            RouteRequest::Remove { .. } => "route.remove",
            RouteRequest::Prefer { .. } => "route.prefer",
            RouteRequest::ResolveBinding { .. } => "route.resolve_binding",
            RouteRequest::RecordHealth { .. } => "route.record_health",
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
    /// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ Rotate this device's K_iroh through the runtime (a
    /// rotation, not a widening; ADR-0012 §2.4 item 4). Local owner only: a paired session
    /// is refused `INTERACTION_REQUIRED`, reason `local_owner_required`. Retry-safe: the
    /// new key is stored as a new item and the old one is never overwritten; each recorded
    /// runner is sent `remote_environment.rotate_endpoint`, and one that fails stays
    /// recorded as pending; running the form again finishes the pending runners and mints
    /// no further key; the old K_iroh is destroyed only after every recorded runner has
    /// acknowledged or been forgotten. The result names the runners still pending. Kind
    /// `transport.rotate`.
    Rotate,
}

impl TransportRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            TransportRequest::Enable { .. } => "transport.enable",
            TransportRequest::Disable => "transport.disable",
            TransportRequest::AdoptRoost { .. } => "transport.adopt_roost",
            TransportRequest::Rotate => "transport.rotate",
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
    /// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ How long the attempt took, in milliseconds, at
    /// most [`ROUTE_ATTEMPT_DURATION_MAX_MS`]; omitted when it was not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = 600_000))]
    pub duration_ms: Option<u32>,
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

    /// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ One spelling per relay URL: scheme and host in
    /// lowercase, the default port dropped, addresses canonical, an empty path `/`; the
    /// path's own case kept.
    #[test]
    fn relay_urls_have_one_normal_form() {
        for (given, normal) in [
            ("https://relay.example.test", "https://relay.example.test/"),
            ("https://relay.example.test/", "https://relay.example.test/"),
            (
                "HTTPS://Relay.Example.TEST:443/",
                "https://relay.example.test/",
            ),
            (
                "https://relay.example.test:0443",
                "https://relay.example.test/",
            ),
            (
                "https://relay.example.test:08443/",
                "https://relay.example.test:8443/",
            ),
            ("http://relay.example.test:80", "http://relay.example.test/"),
            (
                "http://relay.example.test:443",
                "http://relay.example.test:443/",
            ),
            ("https://192.0.2.20:8443", "https://192.0.2.20:8443/"),
            ("https://[2001:DB8:0:0::1]:443/", "https://[2001:db8::1]/"),
            (
                "https://relay.example.test/Relay/v1",
                "https://relay.example.test/Relay/v1",
            ),
        ] {
            assert_eq!(normalize_relay_url(given).as_deref(), Ok(normal), "{given}");
            // The normal form is a fixed point.
            assert_eq!(
                normalize_relay_url(normal).as_deref(),
                Ok(normal),
                "{normal}"
            );
        }
        let policy = ExposurePolicy {
            infrastructure: InfrastructureProfile::Custom {
                relays: vec![
                    "https://B.example.test".into(),
                    "https://a.example.test:443/".into(),
                    "https://b.example.test/".into(),
                ],
            },
            ..ExposurePolicy::default()
        };
        assert_eq!(
            policy.with_normalized_relays().unwrap().infrastructure,
            InfrastructureProfile::Custom {
                relays: vec![
                    "https://a.example.test/".into(),
                    "https://b.example.test/".into(),
                ],
            },
            "sorted; a repeated URL once"
        );
        let minimal = ExposurePolicy::default();
        assert_eq!(minimal.with_normalized_relays().unwrap(), minimal);
    }

    /// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ Each refusal class, by name. No message quotes the
    /// URL.
    #[test]
    fn relay_urls_are_refused_by_class() {
        use RelayUrlRefusal as R;
        for (given, why) in [
            ("ftp://relay.example.test/", R::Scheme),
            ("wss://relay.example.test/", R::Scheme),
            ("relay.example.test", R::Scheme),
            ("https:/relay.example.test", R::Scheme),
            ("https://user@relay.example.test/", R::Userinfo),
            ("https://user:hunter2@relay.example.test/", R::Userinfo),
            ("https://relay.example.test/?token=hunter2", R::Query),
            ("https://relay.example.test?x", R::Query),
            ("https://relay.example.test/?", R::Query),
            ("https://relay.example.test/#frag", R::Fragment),
            ("https://relay.example.test#", R::Fragment),
            ("https://relay.example.test/?a=b#c", R::Fragment),
            ("https://", R::Malformed),
            ("https:///path", R::Malformed),
            ("https://relay.example.test:0/", R::Malformed),
            ("https://relay.example.test:65536/", R::Malformed),
            ("https://relay.example.test:/", R::Malformed),
            ("https://relay example.test/", R::Malformed),
            ("https://relay.example.test/a%2Fb", R::Malformed),
            ("https://relay.example.test/a/../b", R::Malformed),
            ("https://relay.example.test//b", R::Malformed),
            ("https://relay_example.test/", R::Malformed),
            ("https://192.0.2/", R::Malformed),
            ("https://[::1/", R::Malformed),
        ] {
            assert_eq!(normalize_relay_url(given), Err(why), "{given}");
            assert!(!why.message().contains("hunter2"));
        }
        let long = format!(
            "https://relay.example.test/{}",
            "a".repeat(RELAY_URL_MAX_BYTES)
        );
        assert_eq!(normalize_relay_url(&long), Err(R::Malformed));
        let policy = ExposurePolicy {
            infrastructure: InfrastructureProfile::Custom {
                relays: vec![
                    "https://a.example.test/".into(),
                    "https://relay.example.test/?k=v".into(),
                ],
            },
            ..ExposurePolicy::default()
        };
        assert_eq!(policy.with_normalized_relays(), Err((1, R::Query)));
    }

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
        assert_eq!(back.port, None);
        assert!(back.port_is_valid());
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 5⟩ The serve port is omitted when none (every earlier
    /// document is byte-identical) and round-trips when named; `0` is not a valid port.
    #[test]
    fn the_serve_port_is_additive() {
        let named = ExposurePolicy {
            port: Some(4433),
            ..ExposurePolicy::default()
        };
        let v = serde_json::to_value(&named).unwrap();
        assert_eq!(v["port"], 4433);
        assert_eq!(serde_json::from_value::<ExposurePolicy>(v).unwrap(), named);
        assert!(named.port_is_valid());
        let zero = ExposurePolicy {
            port: Some(0),
            ..ExposurePolicy::default()
        };
        assert!(!zero.port_is_valid());
    }

    /// ⟨rev6.5; ADR-0006 §18.9 item 1⟩ The sshd port is omitted when it is 22 (every
    /// earlier document is byte-identical and reads as 22), round-trips when named, and
    /// `0` or a value past 65535 is never a valid policy.
    #[test]
    fn the_sshd_port_is_additive_and_bounded() {
        let default = ExposurePolicy::default();
        assert_eq!(default.sshd_port, 22);
        assert!(default.sshd_port_is_valid());
        let v = serde_json::to_value(&default).unwrap();
        assert!(v.get("sshd_port").is_none(), "{v}");
        let earlier: ExposurePolicy = serde_json::from_str(
            r#"{"bind":{"kind":"loopback"},"infrastructure":{"kind":"none"}}"#,
        )
        .unwrap();
        assert_eq!(earlier, default);
        for port in [1, 2222, 65535] {
            let named = ExposurePolicy {
                sshd_port: port,
                ..ExposurePolicy::default()
            };
            let v = serde_json::to_value(&named).unwrap();
            assert_eq!(v["sshd_port"], port);
            assert_eq!(serde_json::from_value::<ExposurePolicy>(v).unwrap(), named);
            assert!(named.sshd_port_is_valid());
        }
        let zero: ExposurePolicy = serde_json::from_str(
            r#"{"bind":{"kind":"loopback"},"infrastructure":{"kind":"none"},"sshd_port":0}"#,
        )
        .unwrap();
        assert!(!zero.sshd_port_is_valid());
        for bad in ["65536", "-1", "\"22\"", "22.5"] {
            let doc = format!(
                r#"{{"bind":{{"kind":"loopback"}},"infrastructure":{{"kind":"none"}},"sshd_port":{bad}}}"#
            );
            assert!(
                serde_json::from_str::<ExposurePolicy>(&doc).is_err(),
                "{doc}"
            );
        }
    }
}
