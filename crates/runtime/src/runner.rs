//! ⟨M06 U3⟩ The runner runtime (ADR-0012 §4; ADR-0005 §3.5–§3.7, §4.2–§4.3; m06-plan U3).
//!
//! A `remote_runner` installation (`crate::paired::init_runner`) owns its signer (K_env in
//! memory), its grants, tombstones and readiness, and cannot issue. This module serves the
//! controller's `runner/1` requests and computes the runner's readiness:
//!
//! * [`issuance`]: `prepare_remote_grant` and `install_certificate`, pinned to the issuing
//!   controller and CA, with ADR-0005 §3.5's install checks;
//! * [`time`]: the designated time source (`time_challenge` / `time_response`): fresh,
//!   nonce-bound, RTT-bounded samples that only move anchors earlier and never act as
//!   `confirm_time`;
//! * [`RunnerRuntime::readiness`]: the earliest-bound `offline_until`, the conditions and the
//!   per-component residuals (`heimdall_app::readiness`);
//! * [`launch`]: the clean-environment launch of runner work and the provenance of agents
//!   (`dependency_provenance_unknown`, `controller_dependency`);
//! * [`lifetime`]: a verified `systemd --user` unit where linger is on, else `session_scope`.
//!
//! **Wiring** (⟨M06 W3⟩): a runner runtime builds one [`RunnerRuntime`] over its store, clock
//! and the signer's vault (`crate::service`), and the dispatcher hands every paired
//! `Request::Runner` that passed `heimdall_remote::roles::check` to [`RunnerRuntime::handle`]
//! with the session's caller and its connection serial (`crate::paired::PairedRunner::
//! runner_request`). ⟨M06 U4⟩ `deliver_effect` and `authority_report` go through the runner's
//! own narrowing machinery and are served by [`effects`] ([`RunnerRuntime::serve_sync`]); the
//! synchronous [`RunnerRuntime::handle`] still refuses them (`driver_unavailable`), so a
//! caller that has no operations to apply them with applies nothing.
//!
//! **The per-session issuance gate** (⟨M06 W3; ADR-0012 §7.4 ⟨2026-11-21⟩, ADR-0006 §18.7
//! item 11⟩). The runner is the authority on resynchronization: `prepare_remote_grant` and
//! `install_certificate` are refused (`CAPABILITY_UNAVAILABLE`, reason `resync_pending`,
//! effect none) from any session that has not been served this runner's authority report
//! since its last delivered effect, whatever the controller's own barrier does. The gate is
//! keyed by the paired client and the connection's serial, so it is per session: a new
//! session starts gated. A delivered effect gates the session again until it reads a fresh
//! report (§7.4's order: effects, then the report). The gate only ever refuses: every
//! issuance check that follows it is unchanged.
//!
//! **Runner-local decisions** (⟨M06 W3; ADR-0006 §18.7 item 7⟩, [`runner_local`]): the
//! runner's own `issuer_trust` and time-source designation, the `meta` keys
//! `runner_issuer_trust:<fp>` and `runner_time_source` (§18.6 reading (b): authority-bearing,
//! compared by uninstall recovery). The widening forms need an attended local owner; the
//! narrowing forms a local owner. The caller checks who asks (the dispatcher, or the CLI's
//! direct write under the instance lock after its typed confirmation).

#[path = "runner_adapter.rs"]
pub mod adapter;
#[path = "runner_effects.rs"]
pub mod effects;
#[path = "runner_issuance.rs"]
pub mod issuance;
#[path = "runner_launch.rs"]
pub mod launch;
#[path = "runner_lifetime.rs"]
pub mod lifetime;
#[path = "runner_time.rs"]
pub mod time;

use std::sync::Arc;

use heimdall_app::readiness::{RunnerReadiness, RunnerReadinessInput, runner_readiness};
use heimdall_app::readiness_runner::runner_bound;
use heimdall_app::{OpError, OpResult};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::GrantId;
use heimdall_contract::ids::{CaFingerprint, ClientId};
use heimdall_contract::managed::DestinationClock;
use heimdall_contract::remote::{Role, RunnerLifetime, RunnerLocalRequest, RunnerRequest};
use heimdall_credential::vault::KeyVault;
use heimdall_domain::principal::CallerContext;
use heimdall_domain::time::Clock;
use heimdall_store::Store;
use heimdall_store::ext_m06::ClientState;
use heimdall_store::ext_runner::TrustedIssuer;

use self::issuance::RunnerIssuance;
use self::time::{RunnerTime, RunnerTimePolicy, TimeSession};

/// The runner runtime's issuance, time source and readiness (module docs).
pub struct RunnerRuntime {
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    issuance: RunnerIssuance,
    lifetime: RunnerLifetime,
    /// The sessions served the authority report since their last delivered effect (module
    /// docs, "The per-session issuance gate").
    resynced: std::sync::Mutex<std::collections::BTreeSet<(u64, ClientId)>>,
    /// ⟨M06 W3 grant-path⟩ Called when an install completed a grant's certificates
    /// ([`Self::on_issued`]).
    issued: std::sync::Mutex<Option<IssuedHook>>,
    /// ⟨M06 W4⟩ Realizes a further binding on an issued grant ([`Self::set_binder`]).
    binder: std::sync::Mutex<Option<Binder>>,
}

/// ⟨M06 W4⟩ What realizes a binding of a runner grant from the runner's signer, for the
/// binding's own pairs (the runner's adapter binds it over the managed effects' runner
/// materialize site).
pub type Binder = Arc<
    dyn Fn(
            &heimdall_contract::ids::BindingId,
            &GrantId,
            &std::collections::BTreeSet<heimdall_contract::request::AccessPairRef>,
        )
            -> Result<heimdall_contract::provider::EndpointRef, heimdall_app::ports::AdapterError>
        + Send
        + Sync,
>;

/// What a runner runtime calls when the controller's issuer has installed a certificate for
/// every pair of a grant: the operations waiting on that grant are driven on
/// (`heimdall_app::Operations::runner_grant_issued`).
pub type IssuedHook = Arc<dyn Fn(&GrantId) + Send + Sync>;

/// The most sessions the issuance gate remembers; past it the oldest connection is forgotten
/// (it is then gated again: fail closed).
const RESYNCED_SESSIONS: usize = 256;

impl std::fmt::Debug for RunnerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerRuntime")
            .field("issuance", &self.issuance)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

fn ok(data: impl serde::Serialize) -> OpResult<serde_json::Value> {
    let data = serde_json::to_value(data)
        .map_err(|_| OpError::new(Code::InternalError, "result encoding failed"))?;
    Ok(heimdall_app::error::Completed::ok(Code::Ok, data))
}

impl RunnerRuntime {
    /// A runner runtime over `store` and `clock`, holding K_env in `vault`, with the time
    /// policy `policy` and the detected `lifetime` (`lifetime::detect`).
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        vault: Arc<KeyVault>,
        policy: RunnerTimePolicy,
        lifetime: RunnerLifetime,
    ) -> Self {
        let time = Arc::new(RunnerTime::new(Arc::clone(&clock), policy));
        Self {
            issuance: RunnerIssuance::new(Arc::clone(&store), Arc::clone(&clock), time, vault),
            store,
            clock,
            lifetime,
            resynced: std::sync::Mutex::default(),
            issued: std::sync::Mutex::default(),
            binder: std::sync::Mutex::default(),
        }
    }

    /// The runner's store.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The runner's wall clock now.
    #[must_use]
    pub fn wall(&self) -> Timestamp {
        self.clock.wall()
    }

    /// ⟨M06 W3 grant-path⟩ Call `hook` whenever an install completes a grant's
    /// certificates (ADR-0012 §4 item 2: "the controller's host issues, and the runner
    /// installs"; the grant's waiting `ensure` then proceeds).
    pub fn on_issued(&self, hook: IssuedHook) {
        *self
            .issued
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    /// ⟨M06 W4; the attach rule⟩ Realize further bindings of an issued grant through
    /// `binder`.
    pub fn set_binder(&self, binder: Binder) {
        *self
            .binder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(binder);
    }

    /// The binder, when one is set.
    pub(crate) fn binder(&self) -> Option<Binder> {
        self.binder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn resynced(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeSet<(u64, ClientId)>> {
        self.resynced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The session `(controller, connection)` was served this runner's authority report: its
    /// issuance gate opens (module docs). Called by [`Self::serve_sync`] after the report is
    /// answered.
    pub fn note_report_served(&self, controller: &ClientId, connection: u64) {
        let mut open = self.resynced();
        open.insert((connection, controller.clone()));
        while open.len() > RESYNCED_SESSIONS {
            open.pop_first();
        }
    }

    /// The session `(controller, connection)` delivered an effect: it is gated again until
    /// it reads a fresh report.
    pub fn note_effect_delivered(&self, controller: &ClientId, connection: u64) {
        self.resynced().remove(&(connection, controller.clone()));
    }

    /// Whether the session `(controller, connection)` may prepare and install now.
    #[must_use]
    pub fn session_resynced(&self, controller: &ClientId, connection: u64) -> bool {
        self.resynced().contains(&(connection, controller.clone()))
    }

    fn issuance_gate(&self, controller: &ClientId, connection: u64) -> Result<(), OpError> {
        if self.session_resynced(controller, connection) {
            return Ok(());
        }
        Err(OpError::new(
            Code::CapabilityUnavailable,
            "issuance on this runner waits for this session's resynchronization: deliver \
             pending effects and read the authority report first",
        )
        .with_reason(reason::RESYNC_PENDING)
        .with_effect(EffectStatus::None))
    }

    /// Issuance.
    #[must_use]
    pub fn issuance(&self) -> &RunnerIssuance {
        &self.issuance
    }

    /// The time-sample state.
    #[must_use]
    pub fn time(&self) -> &Arc<RunnerTime> {
        self.issuance.time()
    }

    /// The lifetime reported.
    #[must_use]
    pub fn lifetime(&self) -> RunnerLifetime {
        self.lifetime
    }

    /// Serve one paired `runner/1` request (module docs, "Wiring"). `caller` is the paired
    /// session's (its `remote_client` is the controller); `connection` the session's serial.
    /// A caller without a paired client is refused: these requests come only from a
    /// controller. Synchronous store and vault work: call it on the blocking pool.
    ///
    /// # Errors
    ///
    /// The request's refusal.
    pub fn handle(
        &self,
        caller: &CallerContext,
        connection: u64,
        request: &RunnerRequest,
    ) -> OpResult<serde_json::Value> {
        let Some(controller) = caller.remote_client.clone() else {
            return Err(OpError::driver_unavailable(
                "runner requests are served to a paired controller only",
            ));
        };
        let session = TimeSession {
            client: controller.clone(),
            connection,
        };
        match request {
            RunnerRequest::PrepareRemoteGrant {
                grant,
                grant_generation,
            } => {
                self.issuance_gate(&controller, connection)?;
                ok(self
                    .issuance
                    .prepare(&controller, grant, *grant_generation)
                    .map_err(|e| e.to_error())?)
            }
            RunnerRequest::InstallCertificate {
                grant,
                grant_generation,
                certificate,
            } => {
                self.issuance_gate(&controller, connection)?;
                let installed = self
                    .issuance
                    .install(&controller, grant, *grant_generation, certificate)
                    .map_err(|e| e.to_error())?;
                if installed.complete {
                    let hook = self
                        .issued
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if let Some(hook) = hook {
                        hook(grant);
                    }
                }
                ok(installed)
            }
            RunnerRequest::TimeChallenge => {
                let time = self.time();
                let data = self
                    .store
                    .transaction(|tx| Ok(time.challenge(tx, &session)))?
                    .map_err(time::TimeRefusal::to_error)?;
                ok(data)
            }
            RunnerRequest::TimeResponse {
                nonce,
                controller_time,
            } => {
                let time = self.time();
                let data = self
                    .store
                    .transaction(|tx| Ok(time.respond(tx, &session, nonce, *controller_time)))?
                    .map_err(time::TimeRefusal::to_error)?;
                ok(data)
            }
            _ => Err(OpError::driver_unavailable(
                "this runner request is not available in this build",
            )),
        }
    }

    /// A runner grant's readiness (ADR-0012 §4.5; `heimdall_app::readiness`): `destination_clock`
    /// is the weakest of its pairs' measurements, `counted_expiry` the counted issuance
    /// history's latest `valid_before` when the caller knows it (`None`: `unknown`).
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for an unknown grant; `STATE_UNAVAILABLE`.
    pub fn readiness(
        &self,
        grant: &GrantId,
        destination_clock: DestinationClock,
        counted_expiry: Option<Timestamp>,
    ) -> Result<RunnerReadiness, OpError> {
        let (snapshot, parts, anchor) = self
            .store
            .transaction(|tx| {
                let Some(g) = tx.grant(grant)? else {
                    return Ok(None);
                };
                let parts = runner_bound(tx, &g)?;
                let anchor = tx.grant_anchor(grant)?;
                Ok(Some((g, parts, anchor)))
            })?
            .ok_or_else(|| {
                OpError::new(Code::NotFound, "no such grant").with_resource("grant", None)
            })?;
        let now = self.clock.observe();
        let certificate_valid_before = self
            .issuance
            .keys()
            .certificates(&snapshot.id)
            .values()
            .map(|c| c.valid_before)
            .min();
        Ok(runner_readiness(&RunnerReadinessInput {
            now: &now,
            deadline: parts.deadline,
            parent_deadline: parts.parent_deadline,
            cutoff: parts.cutoff,
            anchor: anchor.as_ref(),
            time_bounded: self.time().bounded(),
            certificate_valid_before,
            destination_clock,
            counted_expiry,
            lifetime: self.lifetime,
        }))
    }
}

/// ⟨M06 W3; ADR-0006 §18.7 item 7⟩ Apply one runner-local decision (module docs,
/// "Runner-local decisions") to this runner's store, at `now`. `attended`: the asking session
/// is an attended local owner (the CLI's direct path passes `true` only after its typed
/// confirmation on a terminal). Who asks is the caller's check; this function refuses only a
/// widening form without attendance, a store that is not a runner's, and invalid input.
///
/// * `trust_issuer`: `controller` must be an **active owner** client; the CA key must be one
///   OpenSSH public key line, whose fingerprint the runner computes. Adds (or replaces) the
///   `issuer_trust` entry of that CA.
/// * `designate_time_source`: `client` must be an active owner (`runner_time`).
/// * `distrust_issuer`, `clear_time_source`: remove the entry; `removed`/`cleared` say whether
///   one existed (idempotent).
///
/// # Errors
///
/// `INTERACTION_REQUIRED` for an unattended widening form; `CAPABILITY_UNAVAILABLE` with
/// `driver_unavailable` on a store that is not a runner's, or `role_insufficient` for a
/// controller or client that is not an active owner; `USAGE_ERROR` for a CA key that is not
/// one public key line; `STATE_UNAVAILABLE`.
pub fn runner_local(
    store: &Store,
    now: Timestamp,
    attended: bool,
    request: &RunnerLocalRequest,
) -> OpResult<serde_json::Value> {
    if request.is_widening() && !attended {
        return Err(OpError::new(
            Code::InteractionRequired,
            "this runner-local decision needs the owner attending at this runner's terminal",
        )
        .with_effect(EffectStatus::None));
    }
    let not_owner = |what: &str| {
        OpError::new(
            Code::CapabilityUnavailable,
            format!("the {what} is not an active owner client of this runner"),
        )
        .with_reason(reason::ROLE_INSUFFICIENT)
        .with_effect(EffectStatus::None)
    };
    let active_owner =
        |tx: &mut heimdall_store::Txn<'_>, c: &ClientId| -> heimdall_store::Result<bool> {
            Ok(tx
                .remote_client(c)?
                .is_some_and(|r| r.state == ClientState::Active && r.role == Role::Owner))
        };
    store.transaction(|tx| {
        if !crate::paired::is_runner(tx)? {
            return Ok(Err(OpError::driver_unavailable(
                "this installation is not a remote runner",
            )
            .with_effect(EffectStatus::None)));
        }
        let data = match request {
            RunnerLocalRequest::TrustIssuer {
                controller,
                ca_public_key,
                ..
            } => {
                let line = ca_public_key.trim();
                let Some(fp) = heimdall_issuer::remote::public_key_fingerprint(line)
                    .and_then(|f| CaFingerprint::parse(&f).ok())
                else {
                    return Ok(Err(OpError::new(
                        Code::UsageError,
                        "the CA key is not one OpenSSH public key line",
                    )
                    .with_effect(EffectStatus::None)));
                };
                if !active_owner(tx, controller)? {
                    return Ok(Err(not_owner("controller")));
                }
                let replaced = tx
                    .trusted_remote_issuer(&fp)?
                    .is_some_and(|e| &e.controller != controller || e.ca_public_key != line);
                tx.trust_remote_issuer(&TrustedIssuer {
                    ca_fingerprint: fp.clone(),
                    ca_public_key: line.to_owned(),
                    controller: controller.clone(),
                    trusted_at: now,
                })?;
                serde_json::json!({
                    "ca_fingerprint": fp,
                    "controller": controller,
                    "trusted": true,
                    "replaced": replaced,
                })
            }
            RunnerLocalRequest::DesignateTimeSource { client, .. } => {
                if let Err(e) = time::designate_time_source(tx, client, now) {
                    return Ok(Err(match e {
                        time::TimeRefusal::NotActiveOwner => not_owner("client"),
                        other => other.to_error(),
                    }));
                }
                serde_json::json!({ "client": client, "designated_at": now })
            }
            RunnerLocalRequest::DistrustIssuer { ca_fingerprint } => {
                let removed = tx.untrust_remote_issuer(ca_fingerprint)?;
                serde_json::json!({ "ca_fingerprint": ca_fingerprint, "removed": removed })
            }
            RunnerLocalRequest::ClearTimeSource => {
                let cleared = tx.clear_time_source()?;
                serde_json::json!({ "cleared": cleared })
            }
            _ => {
                return Ok(Err(OpError::new(
                    Code::UsageError,
                    "this runner-local request is not supported by this build",
                )
                .with_effect(EffectStatus::None)));
            }
        };
        Ok(Ok(heimdall_app::error::Completed::ok(Code::Ok, data)))
    })?
}
