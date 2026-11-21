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
use heimdall_contract::ids::{ConsentId, DecisionId, DestinationId, IrohEndpointId, RouteId};
use heimdall_contract::route::{
    BindScope, DestinationRoute, ExposurePolicy, InfrastructureProfile, RouteSpec, TransportRequest,
};
use heimdall_domain::catalog::DestinationDefinition;
use heimdall_store::{Store, Txn};
use serde::Serialize;

use crate::error::OpError;

pub use heimdall_store::ext_transport::{
    ExposureDelta, RouteConsentRecord, TransportKeyRecord, TransportKeyState,
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

/// The serve allowlist's enrollments (the clients' Iroh endpoint IDs). ⟨U56 DONE Q1⟩ The
/// schema has no table for them yet; the runtime supplies the implementation.
pub trait PeerEnrollments: Send + Sync {
    /// Remove every entry (ADR-0012 §2.5). Returns how many were removed.
    ///
    /// # Errors
    /// The store's, as text never echoed to peers.
    fn clear(&self) -> Result<usize, OpError>;
}

/// No enrollments are recorded (the default until the schema has them): nothing to clear.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPeerEnrollments;

impl PeerEnrollments for NoPeerEnrollments {
    fn clear(&self) -> Result<usize, OpError> {
        Ok(0)
    }
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
    /// The new endpoint ID (to announce over the management channel).
    pub endpoint: IrohEndpointId,
    /// The withdrawn one.
    pub previous: IrohEndpointId,
    /// Iroh admission (the serve child replaced).
    pub admission: AdmissionReport,
    /// The previous platform item is destroyed and its row deleted (`false`: its
    /// `destroyed` row stays; `disable` finishes it).
    pub previous_destroyed: bool,
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

fn random16() -> Result<[u8; 16], OpError> {
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
    OpError::new(
        Code::CapabilityUnavailable,
        "the exposure policy cannot be applied",
    )
    .with_reason(why)
    .with_effect(EffectStatus::None)
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
        self.serve.check_policy(&after).map_err(policy_refused)?;
        let state = self.store.transaction(endpoint_state)?;
        if let Some(key) = &state.key {
            if state.serve == serve && state.policy == after {
                return Ok(EnableResult {
                    endpoint: key.endpoint.clone(),
                    store_kind: key.store_kind.clone(),
                    serve,
                    exposure: after,
                    consent: state.consents.last().cloned(),
                    already_enabled: true,
                });
            }
            return Err(OpError::new(
                Code::ConfigConflict,
                "the transport is already enabled with another configuration; disable it first",
            )
            .with_effect(EffectStatus::None));
        }
        // From the minimal, non-serving endpoint (no key is active).
        let delta = exposure_delta(None, &ExposurePolicy::default(), false, &after, serve, None);
        let consent = consent_for(&delta, approved)?;
        let consent_id = match consent {
            Some(_) => Some(ConsentId::from_random_bytes(random16()?)),
            None => None,
        };
        let created = self.keys.create().map_err(KeyStoreRefusal::into_op_error)?;
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
        let (withdrawn, routes_removed, consents_removed) = self.store.transaction(|tx| {
            let keys = tx.transport_keys()?;
            let mut endpoints = Vec::new();
            for k in &keys {
                tx.destroy_transport_key(&k.endpoint, now)?;
                endpoints.push(k.endpoint.clone());
            }
            let mut consents = tx.remove_route_consents(None, now)?;
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
            if endpoints.is_empty() && consents == 0 && removed.is_empty() {
                // Nothing narrowed: no generation moved.
                return Ok((Vec::new(), removed, 0));
            }
            Ok((keys, removed, consents))
        })?;
        let allowlist_entries_removed = self.peers.clear()?;
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
    /// treated as a rotation): a new K_iroh in the verified store gives a new endpoint ID; in
    /// one transaction the old reference is withdrawn (the admission authority generation
    /// moves: rotation narrows admission) and the new one recorded; the serve child is
    /// replaced from durable state; then the old platform item is destroyed (already gone
    /// for a lost key) and its row deleted. The endpoint's consents and exposure carry over.
    /// The new endpoint ID is returned for the announcement to clients over the management
    /// channel; when Iroh was the only route to this host, the owner re-pairs it through
    /// independently host-verified access (a direct or bastion route with the pinned host
    /// key, or at the host itself), never through an unauthenticated announcement.
    ///
    /// # Errors
    /// `transport_unavailable` when nothing is enabled, `transport_key_store_unavailable`,
    /// or the store's (nothing is withdrawn then).
    pub async fn rotate(&self, now: Timestamp) -> Result<RotateResult, OpError> {
        let state = self.store.transaction(endpoint_state)?;
        let Some(old) = state.key else {
            return Err(
                OpError::new(Code::CapabilityUnavailable, "the transport is not enabled")
                    .with_reason(reason::TRANSPORT_UNAVAILABLE)
                    .with_effect(EffectStatus::None),
            );
        };
        let created = self.keys.create().map_err(KeyStoreRefusal::into_op_error)?;
        let record = TransportKeyRecord {
            endpoint: created.endpoint.clone(),
            store_kind: created.store_kind,
            store_ref: created.store_ref,
            state: TransportKeyState::Active,
            created_at: now,
            destroyed_at: None,
        };
        let rotated = self
            .store
            .transaction(|tx| tx.rotate_transport_key(&record, now));
        let withdrawn = match rotated {
            Ok(w) => w.unwrap_or(old),
            Err(e) => {
                let _ = self.keys.destroy(&record);
                return Err(e.into());
            }
        };
        let admission = self.serve.apply_narrowing().await;
        let old_destroyed = self.keys.destroy(&withdrawn).is_ok()
            && self
                .store
                .transaction(|tx| tx.remove_transport_key(&withdrawn.endpoint))
                .is_ok();
        Ok(RotateResult {
            endpoint: created.endpoint,
            previous: withdrawn.endpoint,
            admission,
            previous_destroyed: old_destroyed,
        })
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
        let delta = Self::adopt_delta(endpoint, exposure.as_ref());
        let Some(approved) = consent_for(&delta, approved)? else {
            return Err(unconsented());
        };
        let policy = exposure.unwrap_or_default();
        self.serve.check_policy(&policy).map_err(policy_refused)?;
        let route_id = RouteId::from_random_bytes(random16()?);
        let consent_id = ConsentId::from_random_bytes(random16()?);
        let route = DestinationRoute {
            id: route_id.clone(),
            route: RouteSpec::Iroh {
                endpoint: endpoint.clone(),
                direct_addresses: Vec::new(),
                external_roost: true,
            },
            exposure: Some(policy),
            consents: vec![consent_id.clone()],
            identification_timeout_ms: None,
        };
        let outcome = self.store.transaction(|tx| {
            let Some(record) = tx.destination(destination)? else {
                return Ok(Err(Code::NotFound));
            };
            if !matches!(record.definition, DestinationDefinition::Managed { .. }) {
                return Ok(Err(Code::NotFound));
            }
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
            tx.put_destination_routes(destination, &list, now)?;
            tx.insert_route_consent(&RouteConsentRecord {
                consent: consent_id.clone(),
                route: Some(route_id.clone()),
                decision: approved.decision.clone(),
                delta: approved.delta.clone(),
                recorded_at: now,
            })?;
            Ok(Ok(()))
        })?;
        match outcome {
            Ok(()) => Ok(AdoptResult {
                destination: destination.clone(),
                route: route_id,
                endpoint: endpoint.clone(),
                consent: consent_id,
                disclosure: ROOST_DISCLOSURE,
            }),
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
            TransportRequest::Disable => Ok(None),
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
