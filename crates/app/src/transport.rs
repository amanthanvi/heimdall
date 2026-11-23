//! ⟨M06 U56⟩ `transport enable`, `transport disable` and `transport adopt_roost` (ADR-0012
//! §2.1–§2.5, §2.8, §3.10; m06-plan U56): application operations over ports. No CLI wiring
//! (the integrator's) and no transport import: K_iroh custody ([`TransportKeys`], over
//! `heimdall_credential::iroh`), the serve child's supervision ([`ServeControl`], the
//! runtime's `supervise_transport`) and the serve allowlist's enrollments
//! ([`PeerEnrollments`]) are ports.
//!
//! * **Exposure is consented per exact delta** (§2.1 ⟨r3⟩). [`exposure_delta`] names each
//!   added relay URL, the bind scope before and after, and the direct-fallback, public
//!   infrastructure, serving and external-roost changes; [`widens`] says whether it needs a
//!   recorded consent. A widening executes only with an [`ApprovedWidening`] whose delta is
//!   exactly the one computed here: the attended runner-local decision (§3.10) the caller
//!   claimed first (`heimdall_remote::widening::decide`, or a local attended `Decide`).
//!   Without one it is refused `exposure_unconsented` and nothing happens. Remote or
//!   unattended submissions never reach here: they stay pending records
//!   (`heimdall_remote::widening::submit`).
//! * **`enable`** generates K_iroh in a verified platform store ([`TransportKeys::create`]):
//!   with no verified store it is refused `transport_key_store_unavailable` before anything
//!   is recorded (§2.4 item 3), and direct and bastion routes are unaffected. The key
//!   reference (never the key) and, for a widening, the consent are recorded in one
//!   transaction; with `serve`, the serve child is started from durable state. An
//!   installation already enabled with the same configuration answers the same result;
//!   with another one it is refused `CONFIG_CONFLICT` (disable first: an exposure change is
//!   never applied in place, so narrowing always goes through `disable`'s generation bump).
//!   ⟨M06 W3⟩ The policy may name the serve `port` (ADR-0012 §2.1 ⟨2026-11-21⟩; `0` is
//!   refused); without one the serve child's first successful bind records it, and `disable`
//!   forgets it, so changing the port is `disable` then `enable`.
//!   ⟨M06 W5; ADR-0006 §18.9 item 1⟩ With `serve` the policy may name the local `sshd_port`
//!   the serve child forwards to (1–65535, 22 when omitted; the host is always `127.0.0.1`).
//!   It is part of the policy the serve consent records, so it is written in the same
//!   transaction as the other serve settings and bound to the decision's exact delta; an
//!   enabled endpoint with another sshd port is another configuration (`CONFIG_CONFLICT`:
//!   `disable`, then `enable`).
//! * **`disable`** narrows (no decision, §3.10): in one transaction it withdraws every
//!   K_iroh reference and the serving endpoint's consents, and removes every route that
//!   names one of this installation's endpoints with that route's consents; each of those
//!   moves the admission authority generation, so the bump commits before the change counts
//!   as applied (RC-R02). Then the serve allowlist's entries are cleared, the serve child is
//!   stopped (acknowledged, or stopped by its exact supervised PID, §2.3 item 4), and each
//!   platform item is destroyed and its reference row deleted. A platform item that cannot be
//!   destroyed now keeps its `destroyed` row, so a later `disable` finishes it (§2.5:
//!   removal leaves no key, route, allowlist entry or projection; the projection follows the
//!   route lists' authority-generation bump).
//! * **`adopt_roost`** is always a widening (§2.8): bound to the roost's endpoint ID and its
//!   disclosed exposure ([`ROOST_DISCLOSURE`]), recorded as the new route's consent, and the
//!   route is appended to the destination's approved routes (the one-element case made
//!   explicit first).

use std::collections::BTreeSet;

use async_trait::async_trait;
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{
    ConsentId, DecisionId, DestinationId, EnvironmentId, IrohEndpointId, RouteId,
};
use heimdall_contract::route::{
    BindScope, DEFAULT_SSHD_PORT, DestinationRoute, ExposurePolicy, InfrastructureProfile,
    RouteSpec, TransportRequest,
};
use heimdall_domain::catalog::DestinationDefinition;
use heimdall_store::{Store, Txn};
use serde::Serialize;

use crate::error::OpError;

pub use heimdall_store::ext_transport::{
    ExposureDelta, RouteConsentRecord, TransportKeyRecord, TransportKeyState, TransportRotation,
};

/// What adopting a stock roost discloses (ADR-0012 §2.8), shown before the decision and
/// returned with the result.
pub const ROOST_DISCLOSURE: [&str; 3] = [
    "the roost has no allowlist: any holder of its endpoint ID reaches its sshd",
    "the roost publishes its endpoint to n0's public discovery",
    "the roost uses its own relay set",
];

// --- exposure deltas ----------------------------------------------------------------------

/// How wide a bind is: `none` and loopback (an interface bind on a loopback address
/// included) are the minimal scope; an interface address is wider; a wildcard is widest.
fn bind_rank(bind: &BindScope) -> u8 {
    match bind {
        BindScope::Interface { address } => match address.parse::<std::net::IpAddr>() {
            Ok(ip) if ip.is_loopback() => 0,
            _ => 1,
        },
        BindScope::Wildcard => 2,
        // `none`, loopback, and any scope this build does not know ranks as widest below.
        BindScope::None | BindScope::Loopback => 0,
        _ => 3,
    }
}

fn relays(p: &ExposurePolicy) -> BTreeSet<&str> {
    match &p.infrastructure {
        InfrastructureProfile::Custom { relays } => relays.iter().map(String::as_str).collect(),
        _ => BTreeSet::new(),
    }
}

/// The exact delta from (`before`, `serve_before`) to (`after`, `serve_after`) for
/// `endpoint` (ADR-0012 §2.1 ⟨r3⟩); `roost` names an adopted stock roost (§2.8).
#[must_use]
pub fn exposure_delta(
    endpoint: Option<&IrohEndpointId>,
    before: &ExposurePolicy,
    serve_before: bool,
    after: &ExposurePolicy,
    serve_after: bool,
    roost: Option<&IrohEndpointId>,
) -> ExposureDelta {
    let had = relays(before);
    let relays_added = relays(after)
        .into_iter()
        .filter(|r| !had.contains(r))
        .map(str::to_owned)
        .collect();
    let public = |p: &ExposurePolicy| matches!(p.infrastructure, InfrastructureProfile::N0Public);
    ExposureDelta {
        endpoint: endpoint.cloned(),
        serve_before,
        serve_after,
        bind_before: before.bind.clone(),
        bind_after: after.bind.clone(),
        relays_added,
        direct_fallback_added: after.direct_fallback && !before.direct_fallback,
        public_infrastructure_added: public(after) && !public(before),
        external_roost: roost.cloned(),
        after: after.clone(),
    }
}

/// Whether `delta` widens exposure, so needs a recorded consent (ADR-0012 §2.1): serving
/// starts, the bind widens (a non-loopback interface, another interface, a wildcard), a
/// relay is added, direct fallback or public infrastructure is added, or a roost is adopted.
#[must_use]
pub fn widens(delta: &ExposureDelta) -> bool {
    let before = bind_rank(&delta.bind_before);
    let after = bind_rank(&delta.bind_after);
    let bind_widens =
        after > before || (after == 1 && before == 1 && delta.bind_after != delta.bind_before);
    (delta.serve_after && !delta.serve_before)
        || bind_widens
        || !delta.relays_added.is_empty()
        || delta.direct_fallback_added
        || delta.public_infrastructure_added
        || delta.external_roost.is_some()
}

// --- the endpoint's durable state ---------------------------------------------------------

/// This installation's Iroh endpoint as recorded: its active K_iroh reference, whether it
/// serves and its effective exposure policy (the latest endpoint-level consent's, or the
/// minimal policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointState {
    /// The active K_iroh reference.
    pub key: Option<TransportKeyRecord>,
    /// Whether the endpoint serves this host's sshd to enrolled clients.
    pub serve: bool,
    /// Its effective exposure policy.
    pub policy: ExposurePolicy,
    /// The endpoint-level consents it relies on.
    pub consents: Vec<ConsentId>,
}

/// Read [`EndpointState`] inside the caller's transaction.
///
/// # Errors
/// The store's (two active references are corrupt: fail closed).
pub fn endpoint_state(tx: &mut Txn<'_>) -> heimdall_store::Result<EndpointState> {
    let key = tx.active_transport_key()?;
    let consents = tx.route_consents(None)?;
    let (serve, policy) = match (key.as_ref(), consents.last()) {
        (Some(_), Some(c)) => (c.delta.serve_after, c.delta.after.clone()),
        _ => (false, ExposurePolicy::default()),
    };
    Ok(EndpointState {
        key,
        serve,
        policy,
        consents: consents.into_iter().map(|c| c.consent).collect(),
    })
}

// --- ports --------------------------------------------------------------------------------

/// A K_iroh just generated and stored (references only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTransportKey {
    /// The endpoint ID it authenticates as.
    pub endpoint: IrohEndpointId,
    /// The platform store's kind (`keychain`, `dpapi`, `secret_service`).
    pub store_kind: String,
    /// The item's nonsecret locator.
    pub store_ref: String,
}

/// ⟨M06 W5⟩ `route.add`'s and `transport.adopt_roost`'s refusal of a non-default
/// `exposure.sshd_port` (`USAGE_ERROR`, effect `none`): the port is the serve side's
/// forward target (`transport enable --serve --sshd-port`), and a dialer has none.
pub const SSHD_PORT_NOT_FOR_A_DIALER: &str = "the sshd port is a serve setting (`transport \
     enable --serve --sshd-port`): a route or an adopted roost is dialed and has no local sshd \
     target, so nothing was written";

/// The key store refused (`transport_key_store_unavailable`); `detail` is the fixed doctor
/// detail (`unsupported`, `locked`, `missing`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyStoreRefusal {
    /// The doctor detail.
    pub detail: &'static str,
}

impl KeyStoreRefusal {
    fn into_op_error(self) -> OpError {
        OpError::new(
            Code::CapabilityUnavailable,
            format!(
                "no verified key store for the transport key ({})",
                self.detail
            ),
        )
        .with_reason(reason::TRANSPORT_KEY_STORE_UNAVAILABLE)
        .with_effect(EffectStatus::None)
    }
}

/// K_iroh custody (ADR-0012 §2.4), implemented by the runtime over
/// `heimdall_credential::iroh`. Synchronous and bounded; never prompts.
pub trait TransportKeys: Send + Sync {
    /// Generate K_iroh in this host's verified platform store.
    ///
    /// # Errors
    /// [`KeyStoreRefusal`] when no verified store is available (nothing is generated).
    fn create(&self) -> Result<NewTransportKey, KeyStoreRefusal>;

    /// Destroy the platform item `key` names (exactly that item). An item already gone is
    /// `Ok`.
    ///
    /// # Errors
    /// [`KeyStoreRefusal`] when the store cannot destroy it now.
    fn destroy(&self, key: &TransportKeyRecord) -> Result<(), KeyStoreRefusal>;
}

/// Where Iroh admission stands after a narrowing change (ADR-0012 §2.3 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AdmissionReport {
    /// The serve child acknowledged (or was stopped by its exact PID and confirmed gone):
    /// the change is applied to Iroh admission.
    Applied,
    /// Not yet confirmed: reported `remote_pending` with this reason
    /// (`iroh_admission_closing`).
    Pending {
        /// The reason.
        reason: &'static str,
    },
    /// No serve child runs: nothing to close.
    NotServing,
}

/// The serve child's supervision as the application sees it (the runtime's
/// `supervise_transport`).
#[async_trait]
pub trait ServeControl: Send + Sync {
    /// Whether this build can apply `policy` (the transport's policy validation, without
    /// binding): `Err` carries the reason (`relay_unapproved`, `route_unapproved`,
    /// `transport_unavailable`, `driver_unavailable`).
    ///
    /// # Errors
    /// The refusal reason.
    fn check_policy(&self, policy: &ExposurePolicy) -> Result<(), &'static str>;

    /// Start serving from durable state (closure replayed first, ADR-0012 §2.3 item 5).
    ///
    /// # Errors
    /// The refusal (`transport_authority_lost`, `transport_unavailable`,
    /// `transport_key_store_unavailable`, …).
    async fn start(&self) -> Result<(), OpError>;

    /// Apply a committed narrowing change to the running serve child (suspend and
    /// acknowledge, or exact-PID stop).
    async fn apply_narrowing(&self) -> AdmissionReport;

    /// Stop the serve child (acknowledged, or stopped by its exact PID and confirmed gone).
    async fn stop(&self) -> AdmissionReport;
}

/// The serve allowlist's enrollments (the clients' Iroh endpoint IDs).
pub trait PeerEnrollments: Send + Sync {
    /// Remove every entry (ADR-0012 §2.5) **inside `tx`**, the narrowing write's
    /// transaction, moving the admission authority generation there when any entry went
    /// (⟨M06-W3-R01⟩: the entries and the generation commit together or not at all).
    /// Returns how many were removed.
    ///
    /// # Errors
    /// The store's (the whole narrowing write rolls back).
    fn clear(&self, tx: &mut Txn<'_>, now: Timestamp) -> heimdall_store::Result<usize>;
}

/// ⟨M06-W3-R01⟩ The enrollments in the state store: the runner's `remote_client_endpoints`
/// table, the same rows the serve child's allowlist is built from. Every product wiring
/// uses this one (an installation with no paired client has no rows to clear).
#[derive(Debug, Clone, Copy, Default)]
pub struct StorePeerEnrollments;

impl PeerEnrollments for StorePeerEnrollments {
    fn clear(&self, tx: &mut Txn<'_>, now: Timestamp) -> heimdall_store::Result<usize> {
        tx.clear_remote_client_endpoints(now)
    }
}

/// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ How `transport.rotate` tells one recorded runner this
/// device's new endpoint ID: `remote_environment.rotate_endpoint` on that runner's own
/// management session (the runtime's or the CLI's wiring over
/// `crate::remote_env::RemoteEnvController`). Never an unauthenticated announcement.
#[async_trait]
pub trait EndpointAnnouncer: Send + Sync {
    /// Send `endpoint` to the recorded runner `environment`. `Ok` only when the runner
    /// answered that it recorded (or already had) it.
    ///
    /// # Errors
    /// The session's or the runner's refusal: the runner stays pending.
    async fn announce(
        &self,
        environment: &EnvironmentId,
        endpoint: &IrohEndpointId,
    ) -> Result<(), OpError>;
}

/// A widening the caller has already claimed through an attended runner-local decision
/// (ADR-0012 §3.10), bound to its exact delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedWidening {
    /// The decision.
    pub decision: DecisionId,
    /// The delta it approved.
    pub delta: ExposureDelta,
}

// --- results ------------------------------------------------------------------------------

/// `transport enable`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnableResult {
    /// The endpoint ID (public).
    pub endpoint: IrohEndpointId,
    /// The platform store kind holding K_iroh.
    pub store_kind: String,
    /// Whether the endpoint serves.
    pub serve: bool,
    /// Its effective exposure policy.
    pub exposure: ExposurePolicy,
    /// The consent recorded for a widening.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent: Option<ConsentId>,
    /// The installation was already enabled with this configuration.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub already_enabled: bool,
}

/// `transport disable`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisableResult {
    /// The K_iroh references withdrawn.
    pub endpoints: Vec<IrohEndpointId>,
    /// The routes removed because they named one of them.
    pub routes_removed: Vec<RouteId>,
    /// Consents removed.
    pub consents_removed: usize,
    /// Serve allowlist entries removed.
    pub allowlist_entries_removed: usize,
    /// Iroh admission.
    pub admission: AdmissionReport,
    /// Platform items not destroyed yet (their `destroyed` rows stay; run `disable` again).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keys_pending: Vec<IrohEndpointId>,
}

/// K_iroh rotation's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RotateResult {
    /// The new endpoint ID (announced over the management channel).
    pub endpoint: IrohEndpointId,
    /// The withdrawn one.
    pub previous: IrohEndpointId,
    /// Iroh admission (the serve child replaced).
    pub admission: AdmissionReport,
    /// The previous platform item is destroyed and its row deleted. `false` while a
    /// recorded runner is still pending (the old key is kept until then), or when the item
    /// could not be destroyed now: run `transport rotate` again (`disable` finishes it too).
    pub previous_destroyed: bool,
    /// ⟨rev6.3⟩ What happened with each runner this run had to tell. Omitted when none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub runners: Vec<RunnerAnnouncement>,
    /// ⟨rev6.3⟩ The recorded runners that still have not acknowledged the new endpoint:
    /// run `transport rotate` again to finish them. Omitted when none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<EnvironmentId>,
    /// ⟨rev6.3⟩ This run continued an earlier rotation: no key was minted.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub resumed: bool,
}

/// ⟨rev6.3⟩ One runner in a rotation's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunnerAnnouncement {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// What happened.
    #[serde(flatten)]
    pub outcome: AnnouncementOutcome,
}

/// ⟨rev6.3⟩ What happened with one runner of a rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AnnouncementOutcome {
    /// The runner recorded (or already had) the new endpoint.
    Acknowledged,
    /// The runner is no longer recorded on this device: nothing to tell.
    Forgotten,
    /// The runner refused or could not be reached: it stays pending.
    Pending {
        /// The refusal's code.
        code: Code,
        /// Its reason.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// Its message.
        message: String,
    },
}

/// `transport adopt_roost`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdoptResult {
    /// The destination.
    pub destination: DestinationId,
    /// The new route.
    pub route: RouteId,
    /// The roost's endpoint.
    pub endpoint: IrohEndpointId,
    /// The consent recorded.
    pub consent: ConsentId,
    /// What the adoption discloses.
    pub disclosure: [&'static str; 3],
}

// --- the operations -----------------------------------------------------------------------

pub(crate) fn random16() -> Result<[u8; 16], OpError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| OpError::from(crate::ids::RandomnessUnavailable))?;
    Ok(b)
}

fn unconsented() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "this exposure change needs an attended decision local to this host",
    )
    .with_reason(reason::EXPOSURE_UNCONSENTED)
    .with_effect(EffectStatus::None)
}

fn policy_refused(why: &'static str) -> OpError {
    let message = if why == reason::DRIVER_UNAVAILABLE {
        IROH_PREVIEW_UNAVAILABLE
    } else {
        "the exposure policy cannot be applied"
    };
    OpError::new(Code::CapabilityUnavailable, message)
        .with_reason(why)
        .with_effect(EffectStatus::None)
}

/// ⟨M06 exit, ruling E2 (2026-11-23)⟩ The message of the `driver_unavailable` refusal of an
/// Iroh form in a build without the `iroh` feature (the V1 release artifacts): the Iroh
/// transport is a preview, built from source. The code and reason are unchanged
/// (`CAPABILITY_UNAVAILABLE` / `driver_unavailable`).
pub const IROH_PREVIEW_UNAVAILABLE: &str = "the Iroh transport is a preview, available only in \
     a source build with `cargo build --features iroh`; this build does not include it, so \
     nothing was changed";

/// ⟨M06 exit, ADR-0015⟩ The text every Iroh preview refusal starts with: the transport's
/// ([`IROH_PREVIEW_UNAVAILABLE`]) and the route helper's
/// (`crate::routes::IROH_ROUTE_PREVIEW_UNAVAILABLE`). A test pins both to it.
pub const IROH_PREVIEW_PREFIX: &str = "the Iroh transport is a preview, available only in a \
     source build with `cargo build --features iroh`; this build does not include it";

#[cfg(test)]
mod iroh_preview_message_tests {
    use super::{IROH_PREVIEW_PREFIX, IROH_PREVIEW_UNAVAILABLE};
    use crate::routes::IROH_ROUTE_PREVIEW_UNAVAILABLE;

    #[test]
    fn every_iroh_preview_refusal_shares_one_prefix() {
        assert_eq!(
            IROH_PREVIEW_UNAVAILABLE.strip_prefix(IROH_PREVIEW_PREFIX),
            Some(", so nothing was changed")
        );
        assert_eq!(
            IROH_ROUTE_PREVIEW_UNAVAILABLE.strip_prefix(IROH_PREVIEW_PREFIX),
            Some(", so this route has no usable leg")
        );
    }
}

/// The widening check: `delta` needs a consent and `approved` is exactly it.
fn consent_for<'a>(
    delta: &ExposureDelta,
    approved: Option<&'a ApprovedWidening>,
) -> Result<Option<&'a ApprovedWidening>, OpError> {
    if !widens(delta) {
        return Ok(None);
    }
    match approved {
        Some(a) if a.delta == *delta => Ok(Some(a)),
        _ => Err(unconsented()),
    }
}

/// `transport enable|disable|adopt_roost` over their ports (module docs).
pub struct TransportOps<'a> {
    /// The state store.
    pub store: &'a Store,
    /// K_iroh custody.
    pub keys: &'a dyn TransportKeys,
    /// The serve child's supervision.
    pub serve: &'a dyn ServeControl,
    /// The serve allowlist's enrollments.
    pub peers: &'a dyn PeerEnrollments,
}

impl std::fmt::Debug for TransportOps<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportOps").finish_non_exhaustive()
    }
}

impl TransportOps<'_> {
    /// The delta `transport enable` would apply (what a decision must approve): from the
    /// recorded endpoint (or the minimal, non-serving one) to `serve` and `exposure`.
    ///
    /// # Errors
    /// The store's.
    pub fn enable_delta(
        &self,
        serve: bool,
        exposure: Option<&ExposurePolicy>,
    ) -> Result<ExposureDelta, OpError> {
        let state = self.store.transaction(endpoint_state)?;
        let after = exposure.cloned().unwrap_or_default();
        Ok(exposure_delta(
            None,
            &state.policy,
            state.serve,
            &after,
            serve,
            None,
        ))
    }

    /// `transport enable` (module docs).
    ///
    /// # Errors
    /// `exposure_unconsented`, the policy's refusal, `CONFIG_CONFLICT`,
    /// `transport_key_store_unavailable`, or the store's; nothing is recorded on any of
    /// them. A serve child that cannot start after the key was recorded is the start's
    /// refusal (the key stays; `disable` removes it).
    pub async fn enable(
        &self,
        serve: bool,
        exposure: Option<ExposurePolicy>,
        approved: Option<&ApprovedWidening>,
        now: Timestamp,
    ) -> Result<EnableResult, OpError> {
        let after = exposure.unwrap_or_default();
        if let Some(already) = self.enable_checked(serve, &after)? {
            return Ok(already);
        }
        // From the minimal, non-serving endpoint (no key is active).
        let delta = exposure_delta(None, &ExposurePolicy::default(), false, &after, serve, None);
        let consent = consent_for(&delta, approved)?;
        let consent_id = match consent {
            Some(_) => Some(ConsentId::from_random_bytes(random16()?)),
            None => None,
        };
        let created = self.keys.create().map_err(KeyStoreRefusal::into_op_error)?;
        self.enable_record(serve, after, consent, consent_id, created, now)
            .await
    }

    /// What `transport enable` answers before any consent, key or record: `Ok(Some(_))`
    /// when the transport is already enabled with exactly this configuration, `Ok(None)`
    /// when it would be enabled now. ⟨M06 W5⟩ Also run before a local decision record is
    /// made, so a request that can never succeed creates none.
    ///
    /// # Errors
    /// `USAGE_ERROR`, the policy's refusal, `CONFIG_CONFLICT`, or the store's.
    pub fn enable_checked(
        &self,
        serve: bool,
        after: &ExposurePolicy,
    ) -> Result<Option<EnableResult>, OpError> {
        if !after.port_is_valid() {
            // ⟨ADR-0006 §18.7 item 5⟩ `0` is not a serve port.
            return Err(OpError::new(Code::UsageError, "port 0 is not a serve port")
                .with_effect(EffectStatus::None));
        }
        if !after.sshd_port_is_valid() {
            // ⟨ADR-0006 §18.9 item 1⟩ 1–65535 only.
            return Err(OpError::new(Code::UsageError, "port 0 is not an sshd port")
                .with_effect(EffectStatus::None));
        }
        if !serve && after.sshd_port != DEFAULT_SSHD_PORT {
            // The sshd port is a serve setting: without `serve` nothing forwards to it,
            // and no consent would record it.
            return Err(OpError::new(
                Code::UsageError,
                "the sshd port is a serve setting; name it with serve",
            )
            .with_effect(EffectStatus::None));
        }
        self.serve.check_policy(after).map_err(policy_refused)?;
        let state = self.store.transaction(endpoint_state)?;
        if let Some(key) = &state.key {
            if state.serve == serve && state.policy == *after {
                return Ok(Some(EnableResult {
                    endpoint: key.endpoint.clone(),
                    store_kind: key.store_kind.clone(),
                    serve,
                    exposure: after.clone(),
                    consent: state.consents.last().cloned(),
                    already_enabled: true,
                }));
            }
            return Err(OpError::new(
                Code::ConfigConflict,
                "the transport is already enabled with another configuration; disable it first",
            )
            .with_effect(EffectStatus::None));
        }
        Ok(None)
    }

    /// The recording half of [`Self::enable`]: the new key's reference and the consent in
    /// one transaction, then the serve child.
    async fn enable_record(
        &self,
        serve: bool,
        after: ExposurePolicy,
        consent: Option<&ApprovedWidening>,
        consent_id: Option<ConsentId>,
        created: NewTransportKey,
        now: Timestamp,
    ) -> Result<EnableResult, OpError> {
        let record = TransportKeyRecord {
            endpoint: created.endpoint.clone(),
            store_kind: created.store_kind.clone(),
            store_ref: created.store_ref.clone(),
            state: TransportKeyState::Active,
            created_at: now,
            destroyed_at: None,
        };
        let recorded = self.store.transaction(|tx| {
            tx.insert_transport_key(&record)?;
            if let (Some(a), Some(id)) = (consent, consent_id.as_ref()) {
                tx.insert_route_consent(&RouteConsentRecord {
                    consent: id.clone(),
                    route: None,
                    decision: a.decision.clone(),
                    delta: a.delta.clone(),
                    recorded_at: now,
                })?;
            }
            Ok(())
        });
        if let Err(e) = recorded {
            // Nothing references the new item: destroy it (no orphan key).
            let _ = self.keys.destroy(&record);
            return Err(e.into());
        }
        if serve {
            self.serve.start().await?;
        }
        Ok(EnableResult {
            endpoint: created.endpoint,
            store_kind: created.store_kind,
            serve,
            exposure: after,
            consent: consent_id,
            already_enabled: false,
        })
    }

    /// `transport disable` (module docs). Idempotent: with nothing enabled it removes
    /// nothing and reports admission as it stands.
    ///
    /// # Errors
    /// The store's (nothing is withdrawn then).
    pub async fn disable(&self, now: Timestamp) -> Result<DisableResult, OpError> {
        let (withdrawn, routes_removed, consents_removed, allowlist_entries_removed) =
            self.store.transaction(|tx| {
                let keys = tx.transport_keys()?;
                let mut endpoints = Vec::new();
                for k in &keys {
                    tx.destroy_transport_key(&k.endpoint, now)?;
                    endpoints.push(k.endpoint.clone());
                }
                let mut consents = tx.remove_route_consents(None, now)?;
                // ⟨ADR-0012 §2.1 ⟨2026-11-21⟩⟩ The recorded serve port goes with the endpoint: a
                // later `enable` binds afresh (changing the port is disable then enable).
                tx.clear_transport_serve_port()?;
                // ⟨rev6.3⟩ A rotation still being announced ends with the endpoint: every
                // reference, the withdrawn one it kept included, is destroyed below.
                tx.clear_transport_rotation()?;
                let ours: BTreeSet<&IrohEndpointId> = endpoints.iter().collect();
                let mut removed = Vec::new();
                for (destination, routes) in tx.all_destination_routes()? {
                    let (gone, kept): (Vec<_>, Vec<_>) = routes.into_iter().partition(|r| {
                    matches!(&r.route, RouteSpec::Iroh { endpoint, .. } if ours.contains(endpoint))
                });
                    if gone.is_empty() {
                        continue;
                    }
                    if kept.is_empty() {
                        tx.remove_destination_routes(&destination)?;
                    } else {
                        tx.put_destination_routes(&destination, &kept, now)?;
                    }
                    for r in gone {
                        consents += tx.remove_route_consents(Some(&r.id), now)?;
                        removed.push(r.id);
                    }
                }
                // ⟨M06-W3-R01⟩ The serve allowlist's entries go in this same write: they and the
                // generation they move commit together, before the child is stopped.
                let cleared = self.peers.clear(tx, now)?;
                // With nothing above narrowed and no entry cleared, no generation moved.
                Ok((keys, removed, consents, cleared))
            })?;
        // The generation moved in the commit above; stop the child (§2.5, §2.3 item 4).
        let admission = self.serve.stop().await;
        let mut keys_pending = Vec::new();
        for key in &withdrawn {
            let gone = self.keys.destroy(key).is_ok()
                && self
                    .store
                    .transaction(|tx| tx.remove_transport_key(&key.endpoint))
                    .is_ok();
            if !gone {
                keys_pending.push(key.endpoint.clone());
            }
        }
        Ok(DisableResult {
            endpoints: withdrawn.into_iter().map(|k| k.endpoint).collect(),
            routes_removed,
            consents_removed,
            allowlist_entries_removed,
            admission,
            keys_pending,
        })
    }

    /// K_iroh rotation (ADR-0012 §2.4 item 4; also the recovery of a lost key, which is
    /// treated as a rotation; ⟨rev6.3⟩ ADR-0006 §18.7 item 10, `transport.rotate`).
    ///
    /// **A fresh rotation** (no rotation is being announced): a new K_iroh in the verified
    /// store, as a **new item** (the old item is never overwritten), gives a new endpoint
    /// ID. In one transaction the old reference is withdrawn (the admission authority
    /// generation moves: rotation narrows admission), the new one recorded, and the
    /// rotation recorded with every recorded runner pending ([`TransportRotation`]). The
    /// serve child is replaced from durable state. The endpoint's consents and exposure
    /// carry over.
    ///
    /// **Per runner.** Each pending runner is sent the new endpoint ID through `announcer`
    /// (its own management session). One that acknowledges leaves the record at once (so a
    /// crash keeps the progress); one that refuses or cannot be reached **stays pending**;
    /// one no longer recorded on this device is dropped (forgotten).
    ///
    /// **A re-run** (a rotation of the active endpoint is recorded) mints **no key**: it
    /// only tells the runners still pending.
    ///
    /// **The old K_iroh** is destroyed, and its row deleted, only once no runner is pending.
    /// Until then its platform item stays (its row stays `destroyed`, withdrawn).
    ///
    /// When Iroh was the only route to a runner, the owner re-pairs the new endpoint through
    /// independently host-verified access (a direct or bastion route with the pinned host
    /// key, or at the host itself), never through an unauthenticated announcement.
    ///
    /// **Limit:** a crash between the platform store's creation of the new item and the
    /// commit leaves that item unreferenced (no row names it); the next run mints another.
    ///
    /// # Errors
    /// `transport_unavailable` when nothing is enabled, `transport_key_store_unavailable`,
    /// `driver_unavailable` when runners must be told and there is no `announcer` (checked
    /// before any key is minted), or the store's (nothing is withdrawn then).
    pub async fn rotate(
        &self,
        announcer: Option<&dyn EndpointAnnouncer>,
        now: Timestamp,
    ) -> Result<RotateResult, OpError> {
        let (state, recorded_rotation, recorded) = self.store.transaction(|tx| {
            let recorded: Vec<EnvironmentId> = tx
                .remote_environment_pins()?
                .into_iter()
                .map(|(environment, _)| environment)
                .collect();
            Ok((endpoint_state(tx)?, tx.transport_rotation()?, recorded))
        })?;
        let Some(active) = state.key else {
            return Err(
                OpError::new(Code::CapabilityUnavailable, "the transport is not enabled")
                    .with_reason(reason::TRANSPORT_UNAVAILABLE)
                    .with_effect(EffectStatus::None),
            );
        };
        // A record of a rotation the active endpoint does not continue (a disable and
        // enable in between) is stale: the fresh rotation below replaces it.
        let resumed = recorded_rotation.filter(|r| r.endpoint == active.endpoint);
        let to_tell = match &resumed {
            Some(r) => r.pending.iter().any(|e| recorded.contains(e)),
            None => !recorded.is_empty(),
        };
        if to_tell && announcer.is_none() {
            return Err(OpError::driver_unavailable(
                "this device's recorded runners must be told the new endpoint, and this \
                 caller has no management channel to them: nothing was rotated",
            )
            .with_effect(EffectStatus::None));
        }
        let was_resumed = resumed.is_some();
        let mut rotation = match resumed {
            Some(r) => r,
            None => {
                let created = self.keys.create().map_err(KeyStoreRefusal::into_op_error)?;
                let record = TransportKeyRecord {
                    endpoint: created.endpoint.clone(),
                    store_kind: created.store_kind,
                    store_ref: created.store_ref,
                    state: TransportKeyState::Active,
                    created_at: now,
                    destroyed_at: None,
                };
                let fresh = TransportRotation {
                    endpoint: created.endpoint,
                    previous: active.endpoint.clone(),
                    pending: recorded.clone(),
                    started_at: now,
                };
                let committed = self.store.transaction(|tx| {
                    tx.rotate_transport_key(&record, now)?;
                    tx.set_transport_rotation(&fresh)
                });
                if let Err(e) = committed {
                    // Our own just-created item, which no row names.
                    let _ = self.keys.destroy(&record);
                    return Err(e.into());
                }
                fresh
            }
        };
        // Also on a re-run: an earlier run may have ended between its commit and this.
        let admission = self.serve.apply_narrowing().await;
        let mut runners = Vec::new();
        for environment in rotation.pending.clone() {
            let outcome = if !recorded.contains(&environment) {
                AnnouncementOutcome::Forgotten
            } else {
                match announcer {
                    Some(a) => match a.announce(&environment, &rotation.endpoint).await {
                        Ok(()) => AnnouncementOutcome::Acknowledged,
                        Err(e) => AnnouncementOutcome::Pending {
                            code: e.code,
                            reason: e.reason,
                            message: e.message,
                        },
                    },
                    // Not reached (refused above); kept pending if it ever is.
                    None => AnnouncementOutcome::Pending {
                        code: Code::CapabilityUnavailable,
                        reason: Some(reason::DRIVER_UNAVAILABLE.to_owned()),
                        message: "no management channel".to_owned(),
                    },
                }
            };
            if !matches!(outcome, AnnouncementOutcome::Pending { .. }) {
                rotation.pending.retain(|e| e != &environment);
                // Progress is durable per runner: a failed write keeps it pending.
                if let Err(e) = self
                    .store
                    .transaction(|tx| tx.set_transport_rotation(&rotation))
                {
                    return Err(e.into());
                }
            }
            runners.push(RunnerAnnouncement {
                environment,
                outcome,
            });
        }
        // The old key goes only once no recorded runner is pending.
        let previous_destroyed = rotation.pending.is_empty() && self.finish_rotation(&rotation);
        Ok(RotateResult {
            endpoint: rotation.endpoint,
            previous: rotation.previous,
            admission,
            previous_destroyed,
            runners,
            pending: rotation.pending,
            resumed: was_resumed,
        })
    }

    /// Destroy the withdrawn item of a rotation with nobody pending, delete its row and
    /// forget the rotation record. `false` leaves the record (with nobody pending), so the
    /// next run retries.
    fn finish_rotation(&self, rotation: &TransportRotation) -> bool {
        let Ok(old) = self
            .store
            .transaction(|tx| tx.transport_key(&rotation.previous))
        else {
            return false;
        };
        let gone = match old {
            // A lost key's row may be gone already.
            None => true,
            Some(rec) if rec.state == TransportKeyState::Active => false,
            Some(rec) => {
                self.keys.destroy(&rec).is_ok()
                    && self
                        .store
                        .transaction(|tx| tx.remove_transport_key(&rec.endpoint))
                        .is_ok()
            }
        };
        gone && self
            .store
            .transaction(|tx| tx.clear_transport_rotation())
            .is_ok()
    }

    /// The delta adopting `endpoint` as a roost route with the dialer policy `exposure`
    /// applies (what the decision must approve).
    #[must_use]
    pub fn adopt_delta(
        endpoint: &IrohEndpointId,
        exposure: Option<&ExposurePolicy>,
    ) -> ExposureDelta {
        let after = exposure.cloned().unwrap_or_default();
        exposure_delta(
            Some(endpoint),
            &ExposurePolicy::default(),
            false,
            &after,
            false,
            Some(endpoint),
        )
    }

    /// `transport adopt_roost` (module docs).
    ///
    /// # Errors
    /// `exposure_unconsented` (always a widening), the policy's refusal, `NOT_FOUND` for a
    /// destination that is not a managed catalog destination, `CONFIG_CONFLICT` when the
    /// roost is already one of its routes, or the store's.
    pub async fn adopt_roost(
        &self,
        destination: &DestinationId,
        endpoint: &IrohEndpointId,
        exposure: Option<ExposurePolicy>,
        approved: Option<&ApprovedWidening>,
        now: Timestamp,
    ) -> Result<AdoptResult, OpError> {
        if exposure
            .as_ref()
            .is_some_and(|e| e.sshd_port != DEFAULT_SSHD_PORT)
        {
            // ⟨M06 W5; ADR-0012 §2.3 item 2⟩ An adopted roost is dialed, never served
            // from here: there is no local sshd target for the port to name.
            return Err(OpError::new(Code::UsageError, SSHD_PORT_NOT_FOR_A_DIALER)
                .with_effect(EffectStatus::None));
        }
        let delta = Self::adopt_delta(endpoint, exposure.as_ref());
        let Some(approved) = consent_for(&delta, approved)? else {
            return Err(unconsented());
        };
        let policy = exposure.unwrap_or_default();
        self.serve.check_policy(&policy).map_err(policy_refused)?;
        let route_id = RouteId::from_random_bytes(random16()?);
        let consent_id = ConsentId::from_random_bytes(random16()?);
        let route = Self::roost_route(&route_id, endpoint, policy, Some(&consent_id));
        let consent = RouteConsentRecord {
            consent: consent_id.clone(),
            route: Some(route_id.clone()),
            decision: approved.decision.clone(),
            delta: approved.delta.clone(),
            recorded_at: now,
        };
        let outcome = self
            .store
            .transaction(|tx| Self::adopt_in(tx, destination, &route, Some((&consent, now))))?;
        Self::adopt_outcome(destination, outcome)?;
        Ok(AdoptResult {
            destination: destination.clone(),
            route: route_id,
            endpoint: endpoint.clone(),
            consent: consent_id,
            disclosure: ROOST_DISCLOSURE,
        })
    }

    /// ⟨M06 W5⟩ What `transport adopt_roost` would refuse apart from the consent, writing
    /// nothing. Run before a local decision record is made, so a request that can never
    /// succeed creates none.
    ///
    /// # Errors
    /// [`Self::adopt_roost`]'s, except `exposure_unconsented`.
    pub fn adopt_checked(
        &self,
        destination: &DestinationId,
        endpoint: &IrohEndpointId,
        exposure: Option<&ExposurePolicy>,
    ) -> Result<(), OpError> {
        if exposure.is_some_and(|e| e.sshd_port != DEFAULT_SSHD_PORT) {
            return Err(OpError::new(Code::UsageError, SSHD_PORT_NOT_FOR_A_DIALER)
                .with_effect(EffectStatus::None));
        }
        let policy = exposure.cloned().unwrap_or_default();
        self.serve.check_policy(&policy).map_err(policy_refused)?;
        let route = Self::roost_route(
            &RouteId::from_random_bytes(random16()?),
            endpoint,
            policy,
            None,
        );
        let outcome = self
            .store
            .transaction(|tx| Self::adopt_in(tx, destination, &route, None))?;
        Self::adopt_outcome(destination, outcome)
    }

    fn roost_route(
        id: &RouteId,
        endpoint: &IrohEndpointId,
        policy: ExposurePolicy,
        consent: Option<&ConsentId>,
    ) -> DestinationRoute {
        DestinationRoute {
            id: id.clone(),
            route: RouteSpec::Iroh {
                endpoint: endpoint.clone(),
                direct_addresses: Vec::new(),
                external_roost: true,
            },
            exposure: Some(policy),
            consents: consent.into_iter().cloned().collect(),
            identification_timeout_ms: None,
        }
    }

    /// Check that `route` (a roost) can join `destination`'s approved routes and, with
    /// `write`, store the list and the consent.
    fn adopt_in(
        tx: &mut Txn<'_>,
        destination: &DestinationId,
        route: &DestinationRoute,
        write: Option<(&RouteConsentRecord, Timestamp)>,
    ) -> heimdall_store::Result<Result<(), Code>> {
        let Some(record) = tx.destination(destination)? else {
            return Ok(Err(Code::NotFound));
        };
        if !matches!(record.definition, DestinationDefinition::Managed { .. }) {
            return Ok(Err(Code::NotFound));
        }
        let RouteSpec::Iroh { endpoint, .. } = &route.route else {
            return Ok(Err(Code::ConfigConflict));
        };
        let stored = tx.destination_routes(destination)?;
        let mut list = heimdall_domain::routes::approved_routes(&record, Some(&stored));
        if list
            .iter()
            .any(|r| matches!(&r.route, RouteSpec::Iroh { endpoint: e, .. } if e == endpoint))
        {
            return Ok(Err(Code::ConfigConflict));
        }
        list.push(route.clone());
        let mut view = crate::catalog::route_view(tx)?;
        view.routes = tx.all_destination_routes()?;
        if heimdall_domain::routes::check_route_list(&view, destination, &list).is_err() {
            return Ok(Err(Code::ConfigConflict));
        }
        if let Some((consent, now)) = write {
            tx.put_destination_routes(destination, &list, now)?;
            tx.insert_route_consent(consent)?;
        }
        Ok(Ok(()))
    }

    fn adopt_outcome(
        destination: &DestinationId,
        outcome: Result<(), Code>,
    ) -> Result<(), OpError> {
        match outcome {
            Ok(()) => Ok(()),
            Err(Code::NotFound) => Err(OpError::new(
                Code::NotFound,
                "no managed catalog destination with that ID",
            )
            .with_resource("destination", Some(destination.as_str().to_owned()))
            .with_effect(EffectStatus::None)),
            Err(code) => Err(OpError::new(
                code,
                "the roost cannot be added to this destination's routes",
            )
            .with_effect(EffectStatus::None)),
        }
    }

    /// ⟨M06 W5⟩ What a widening `request` would answer apart from its consent, writing
    /// nothing ([`Self::enable_checked`], [`Self::adopt_checked`]): `Ok(Some(_))` is the
    /// answer of a request that changes nothing (already enabled exactly so).
    ///
    /// # Errors
    /// The operation's, except `exposure_unconsented`.
    pub fn precheck(
        &self,
        request: &TransportRequest,
    ) -> Result<Option<serde_json::Value>, OpError> {
        match request {
            TransportRequest::Enable {
                serve, exposure, ..
            } => {
                let after = exposure.clone().unwrap_or_default();
                self.enable_checked(*serve, &after)?
                    .map(|already| {
                        serde_json::to_value(already).map_err(|_| {
                            OpError::new(
                                Code::InternalError,
                                "a transport result cannot be rendered",
                            )
                        })
                    })
                    .transpose()
            }
            TransportRequest::AdoptRoost {
                destination,
                endpoint,
                exposure,
                ..
            } => self
                .adopt_checked(destination, endpoint, exposure.as_ref())
                .map(|()| None),
            _ => Ok(None),
        }
    }

    /// ⟨M06 W2, U56-Q6⟩ The exact exposure delta `request` applies against the recorded
    /// endpoint now ([`Self::enable_delta`], [`Self::adopt_delta`]); `None` for a narrowing
    /// form (`disable`). A runner-local decision record is bound to this delta when it is
    /// created, and its approval executes only while the delta is still exactly this one (the
    /// executor then passes it as the [`ApprovedWidening`], which [`Self::execute`] compares
    /// again with its own read).
    ///
    /// # Errors
    /// The store's; `driver_unavailable` for a form this build does not know.
    pub fn delta_of(&self, request: &TransportRequest) -> Result<Option<ExposureDelta>, OpError> {
        match request {
            TransportRequest::Enable {
                serve, exposure, ..
            } => self.enable_delta(*serve, exposure.as_ref()).map(Some),
            TransportRequest::AdoptRoost {
                endpoint, exposure, ..
            } => Ok(Some(Self::adopt_delta(endpoint, exposure.as_ref()))),
            // A rotation narrows (the old endpoint's admission ends): no decision.
            TransportRequest::Disable | TransportRequest::Rotate => Ok(None),
            _ => Err(OpError::driver_unavailable(
                "this transport request is not known to this build",
            )),
        }
    }

    /// Run one `Request::Transport` form: `approved` is the claimed runner-local decision
    /// for a widening (`None` for a direct, unattended or not-yet-decided request, which a
    /// widening refuses `exposure_unconsented`). The result as a JSON document.
    ///
    /// # Errors
    /// The operation's.
    pub async fn execute(
        &self,
        request: &TransportRequest,
        approved: Option<&ApprovedWidening>,
        now: Timestamp,
    ) -> Result<serde_json::Value, OpError> {
        let json = |v: serde_json::Result<serde_json::Value>| {
            v.map_err(|_| {
                OpError::new(Code::InternalError, "a transport result cannot be rendered")
            })
        };
        match request {
            TransportRequest::Enable {
                serve, exposure, ..
            } => json(serde_json::to_value(
                self.enable(*serve, exposure.clone(), approved, now).await?,
            )),
            TransportRequest::Disable => json(serde_json::to_value(self.disable(now).await?)),
            // ⟨rev6.3⟩ Without a management channel here: only an installation with no
            // recorded runner to tell rotates through this entry ([`Self::rotate`]).
            TransportRequest::Rotate => json(serde_json::to_value(self.rotate(None, now).await?)),
            TransportRequest::AdoptRoost {
                destination,
                endpoint,
                exposure,
                ..
            } => json(serde_json::to_value(
                self.adopt_roost(destination, endpoint, exposure.clone(), approved, now)
                    .await?,
            )),
            _ => Err(OpError::driver_unavailable(
                "this transport request is not known to this build",
            )),
        }
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
