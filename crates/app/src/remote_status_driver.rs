//! ⟨M06 W3⟩ The controller's sync and issuance driver (ADR-0012 §4.2, §7.4, §8; ADR-0006
//! §18.7 items 11–12; m06-plan U4/U4b): the production caller of
//! [`crate::remote_status::resync`], [`crate::remote_status::produce_effect`] and the issuer's
//! barrier.
//!
//! **The session adapter** ([`SessionChannel`]). A management session
//! ([`crate::remote_env::ManagementSession`]) that negotiated `runner/1` carries the
//! `runner.*` forms as [`crate::remote_env::ManagementCall::Runner`]. The runner offers
//! `runner/1` to owner sessions only, so a limited role's session never has it and the
//! adapter refuses to be built over one (`driver_unavailable`, nothing sent).
//!
//! **Reconnect** ([`ControllerSync::on_session`], [`ControllerSync::reconnect`]). Every owner
//! session runs ADR-0012 §7.4's order through `resync` before anything else is asked of the
//! runner: hello, the outbox drained oldest first, the authority report, the issuer's barrier,
//! the time sample. A session that cannot be opened is recorded
//! ([`crate::remote_status::note_open_failure`]) and the barrier stays closed; a session that
//! ends closes it ([`ControllerSync::session_closed`]).
//!
//! **Producing effects behind the local operations** ([`narrow_runner_grant`],
//! [`narrow_runner_policy`]). The owner's local `revoke`, `policy pause` and `policy cutoff`
//! name a grant or a policy. When this installation holds none of that ID and the ID is known
//! as a runner's (this controller's issuance ledger names the runner in the certificate key
//! ID, or the runner's last report listed it), the narrowing becomes a durable outbox row for
//! that runner: `remote_pending` until a reconnect delivers it and records the
//! acknowledgement. Repeating the same local request reuses the pending row.
//!
//! **Remote issuance** ([`ControllerSync::issue`], §4.2): prepare at the runner, reserve and
//! publish in this controller's ledger behind the barrier, sign with this controller's
//! issuer ([`RemoteIssuer`]), install at the runner. Nothing is prepared while the barrier is
//! closed; a grant pinned to another controller or CA is refused (`issuer_untrusted`) before
//! anything is reserved; only a published certificate is sent for installation; a refused
//! install leaves the entry counted (ADR-0005 §3.5).
//!
//! ⟨M06 W3 host; ADR-0005 §3.5 "Remote reservations"⟩ **The certificate's content is this
//! controller's.** A remote certificate's pairs, extensions and validity come from this
//! controller's own record of the grant it delivered to that runner
//! ([`deliver_runner_grant`], `heimdall_store::ext_effects::DeliveredGrant`), narrowed by the
//! runner's verified prepare answer: an answer naming a pair that was not delivered is
//! refused, and `valid_before` is the minimum of the asked lifetime, the delivered grant's
//! expiry, the effective cutoff and the runner's reported bound. Nothing is prepared for a
//! grant without such a record. The key binding the answer gave is recorded with the
//! reservation, in its transaction: it is what the issuer child (which reads only this
//! store) judges the reservation against.
//!
//! ⟨M06 W3 grant-path; ADR-0012 §4 item 2 ⟨2026-11-21⟩; ADR-0005 §3.5 condition 8 (a)⟩
//! **How that record comes to exist** ([`ControllerSync::forward_ensure`]). An `ensure`
//! naming a recorded runner's environment is forwarded over the management session. What
//! this controller asked for ([`forwarded_ask`]: the destination pairs it named, the
//! deadline it named, the base extension profile) is recorded as the delivered grant once
//! the runner names the grant it admitted. The runner's answer supplies only the grant's ID;
//! the pairs, the extensions and the expiry are this controller's own. An `ensure` that
//! names no pair or no deadline is not forwarded: the controller would have nothing of its
//! own to record. A request the runner leaves waiting for a decision at the runner
//! (`APPROVAL_REQUIRED`) records nothing; repeating it with the same request ID after the
//! decision does.
//!
//! **The hosted pass** ([`ControllerSync::maintain`]): for every grant delivered to a runner
//! whose session was just resynchronized, issue for the pairs the runner's report shows no
//! certificate for. A failure is recorded with the grant and shown by `environment status`
//! ([`crate::remote_status::RemoteStatus::issuance_failures`]); nothing is issued for it.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::controller_record::RemoteEnvironmentPin;
use heimdall_contract::envelope::{EffectStatus, Envelope, reason};
use heimdall_contract::ids::{
    CaFingerprint, ClientId, EnvironmentId, GrantId, IssuanceId, PolicyId,
};
use heimdall_contract::remote::{EffectTarget, Permission, Role, RunnerRequest};
use heimdall_contract::request::{AccessPairRef, PolicyAction};
use heimdall_contract::trust::PolicyTarget;
use heimdall_domain::issuance::{CertificateBounds, IssuanceEntry, IssuanceState, principal_for};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::time::Clock;
use heimdall_store::ext_effects::{
    AuthorityReport, DeliveredGrant, EffectKey, IssuanceFailure, OutboxEffect, PreparedBinding,
};
use heimdall_store::{Store, Txn};

use crate::error::OpError;
use crate::remote_env::{
    ManagementCall, ManagementSession, ManagementSessions, SessionName, SessionTarget,
    runner_result,
};
use crate::remote_status::{
    Narrowing, ResyncOutcome, RunnerChannel, note_open_failure, produce_effect, resync,
    session_ended,
};
use crate::remote_status_barrier::{CountedResidual, IssuerBarrier, counted_residual};

/// A management session's `runner/1` requests (module docs, "The session adapter").
pub struct SessionChannel<'s> {
    session: &'s mut dyn ManagementSession,
}

impl<'s> SessionChannel<'s> {
    /// The channel over `session`.
    ///
    /// # Errors
    ///
    /// `CAPABILITY_UNAVAILABLE` / `driver_unavailable` when the session did not negotiate
    /// `runner/1` (a limited role, or a runner without its runner runtime). Nothing is sent.
    pub fn new(session: &'s mut dyn ManagementSession) -> Result<Self, OpError> {
        if !session.runner_negotiated() {
            return Err(OpError::driver_unavailable(
                "this management session did not negotiate runner/1: the runner offers it to \
                 owner sessions only",
            )
            .with_effect(EffectStatus::None));
        }
        Ok(Self { session })
    }
}

#[async_trait::async_trait]
impl RunnerChannel for SessionChannel<'_> {
    fn environment(&self) -> &EnvironmentId {
        &self.session.hello().environment
    }

    fn client(&self) -> Option<&ClientId> {
        self.session.hello().client.as_ref()
    }

    async fn call(
        &mut self,
        request: RunnerRequest,
    ) -> Result<Envelope<serde_json::Value>, OpError> {
        self.session.call(ManagementCall::Runner(request)).await
    }
}

/// What a verified prepare answer gives the reservation ([`RemoteIssuer::verify`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSubject {
    /// K_env.pub, the subject signed for.
    pub subject_public_key: String,
    /// Its fingerprint (the reservation's subject).
    pub subject_fingerprint: String,
    /// The grant's pairs, one certificate each.
    pub pairs: Vec<AccessPairRef>,
    /// No certificate may be valid past it.
    pub bound: Timestamp,
    /// The runner's policy the grant was admitted under, when the runner stated one.
    pub policy: Option<PolicyId>,
}

/// What this controller asked of the runner, against which its answer is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAsk {
    /// The pinned runner environment.
    pub environment: EnvironmentId,
    /// The grant.
    pub grant: GrantId,
    /// Its generation.
    pub grant_generation: u64,
    /// This controller's client on that runner.
    pub controller: ClientId,
    /// The CA this controller's issuer signs with.
    pub ca_fingerprint: CaFingerprint,
}

/// This controller's issuer, as remote issuance uses it (ADR-0005 §3.5; ADR-0012 §4.2 step
/// 3). The runtime implements it over `heimdall_issuer::remote` and the issuer child.
#[async_trait::async_trait]
pub trait RemoteIssuer: Send + Sync {
    /// The CA this controller's issuer signs runner grants with.
    ///
    /// # Errors
    ///
    /// `CAPABILITY_UNAVAILABLE` for a controller without an issuer: it cannot issue or
    /// renew, and the grant runs to its bounds (ADR-0012 §8 item 3).
    fn ca(&self) -> Result<CaFingerprint, OpError>;

    /// Hold the runner's `prepare_remote_grant` answer against `ask`
    /// (`heimdall_issuer::remote::verify_prepared`): the pinned environment, the grant and
    /// generation asked for, one Ed25519 subject with the stated fingerprint, pairs inside
    /// the principal ceiling, a bound that has not passed, and no pin to another controller
    /// or CA.
    ///
    /// # Errors
    ///
    /// The refusal; `issuer_untrusted` for a grant pinned elsewhere. Nothing is reserved.
    fn verify(
        &self,
        ask: &RemoteAsk,
        answer: serde_json::Value,
        now: Timestamp,
    ) -> Result<RemoteSubject, OpError>;

    /// Sign the reserved `entry` for `subject`; the OpenSSH certificate line.
    ///
    /// # Errors
    ///
    /// The issuer's refusal or unavailability. The reservation stays counted.
    async fn sign(&self, entry: &IssuanceEntry, subject: &str) -> Result<String, OpError>;
}

/// One remote issuance request ([`ControllerSync::issue`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIssueInput {
    /// The runner's grant.
    pub grant: GrantId,
    /// Its generation on the runner.
    pub grant_generation: u64,
    /// The longest certificate validity asked for; the delivered grant's expiry, the
    /// runner's bound and a future cutoff shorten it. The extensions and the pairs are the
    /// delivered grant's, never an input here.
    pub lifetime: Duration,
}

/// One certificate a remote issuance installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCertificate {
    /// The pair.
    pub pair: AccessPairRef,
    /// The ledger entry.
    pub issuance: IssuanceId,
    /// The certificate's serial.
    pub serial: u64,
    /// Its `valid_before`.
    pub valid_before: Timestamp,
}

/// What [`ControllerSync::issue`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIssued {
    /// The grant.
    pub grant: GrantId,
    /// The certificates published and installed, by pair.
    pub certificates: Vec<RemoteCertificate>,
}

fn role_insufficient(message: &str) -> OpError {
    OpError::new(Code::CapabilityUnavailable, message)
        .with_reason(reason::ROLE_INSUFFICIENT)
        .with_effect(EffectStatus::None)
}

/// Whether the role this controller holds on a runner may issue for its grants: ADR-0012's
/// role table (`Role::permissions`; the issuance forms need `issuer_trust`,
/// `heimdall_remote::roles::classify`). Owner in today's table; no role is named here.
#[must_use]
pub fn role_may_issue(role: Role) -> bool {
    role.permissions().contains(&Permission::IssuerTrust)
}

fn not_delivered() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "this controller holds no record of delivering that grant to the runner: nothing is \
         issued for a grant whose content this controller does not hold",
    )
    .with_effect(EffectStatus::None)
}

/// Record that this controller delivered `grant` to the runner `pin` names, with exactly
/// these pairs and extensions until `expires_at`: the only content a certificate for it may
/// ever carry (module docs). Re-recording a grant may only narrow it: pairs and extensions
/// are intersected with the existing record's and the expiry never moves later, so a
/// repeated call cannot widen what an earlier one delivered.
///
/// # Errors
///
/// The store's (outer). Inner, nothing written: `role_insufficient` when this controller's
/// role there may not issue; `USAGE_ERROR` for no pair, or an expiry that has passed.
pub fn deliver_runner_grant(
    tx: &mut Txn<'_>,
    pin: &RemoteEnvironmentPin,
    grant: &GrantId,
    pairs: &BTreeSet<AccessPairRef>,
    extensions: &BTreeSet<String>,
    expires_at: Timestamp,
    now: Timestamp,
) -> heimdall_store::Result<Result<DeliveredGrant, OpError>> {
    if !role_may_issue(pin.role) {
        return Ok(Err(role_insufficient(
            "this controller's role on the runner does not let it issue for its grants",
        )));
    }
    if pairs.is_empty() || expires_at <= now {
        return Ok(Err(OpError::new(
            Code::UsageError,
            "a delivered grant needs at least one pair and an expiry that has not passed",
        )
        .with_effect(EffectStatus::None)));
    }
    let record = match tx.delivered_grant(&pin.environment, grant)? {
        Some(old) => DeliveredGrant {
            pairs: old.pairs.intersection(pairs).cloned().collect(),
            extensions: old.extensions.intersection(extensions).cloned().collect(),
            expires_at: old.expires_at.min(expires_at),
            ..old
        },
        None => DeliveredGrant {
            environment: pin.environment.clone(),
            grant: grant.clone(),
            pairs: pairs.clone(),
            extensions: extensions.clone(),
            expires_at,
            delivered_at: now,
            prepared: None,
            last_failure: None,
        },
    };
    tx.put_delivered_grant(&record)?;
    Ok(Ok(record))
}

/// What a forwarded `ensure` asks a runner for, as this controller records it
/// ([`forwarded_ask`]): the only content a certificate for the admitted grant may carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedAsk {
    /// The destination/account pairs the request named (the principals follow from them).
    pub pairs: BTreeSet<AccessPairRef>,
    /// The extensions: the base profile (`permit-pty`). The request names no capability
    /// that would add another, so none is recorded.
    pub extensions: BTreeSet<String>,
    /// The deadline the request named, resolved once on this controller's clock.
    pub expires_at: Timestamp,
}

/// The longest deadline a forwarded `ensure` may name here. The runner's own policy window
/// decides what it admits; this only keeps the arithmetic bounded.
const FORWARD_MAX_WINDOW: Duration = Duration::from_secs(366 * 24 * 3600);

fn forward_usage(message: &str) -> OpError {
    OpError::new(Code::UsageError, message).with_effect(EffectStatus::None)
}

/// What `request`, an `ensure` naming a runner's environment, asks for (module docs, "How
/// that record comes to exist"), at this controller's `now`.
///
/// # Errors
///
/// `USAGE_ERROR`, nothing sent or written: the request names no pair, names no deadline (or
/// one that cannot be read or has passed), or uses a form a runner does not serve through a
/// controller (`context`, `covered_only`).
pub fn forwarded_ask(
    request: &heimdall_contract::request::EnsureRequest,
    now: Timestamp,
) -> Result<ForwardedAsk, OpError> {
    if request.context.is_some() || request.covered_only {
        return Err(forward_usage(
            "an ensure forwarded to a runner names a profile; a working directory (context) \
             is resolved on the machine that has it",
        ));
    }
    if request.scope.is_empty() {
        return Err(forward_usage(
            "an ensure forwarded to a runner names its destination pairs (--pair): this \
             controller records exactly the pairs it asked for",
        ));
    }
    let Some(until) = &request.until else {
        return Err(forward_usage(
            "an ensure forwarded to a runner names its deadline (--until or --for): this \
             controller records exactly the deadline it asked for",
        ));
    };
    let deadline = heimdall_domain::time::resolve_deadline(until, now, FORWARD_MAX_WINDOW)
        .map_err(|_| forward_usage("the deadline cannot be read, has passed, or is too far"))?;
    Ok(ForwardedAsk {
        pairs: request.scope.clone(),
        extensions: [heimdall_domain::issuance::EXTENSION_PTY.to_owned()]
            .into_iter()
            .collect(),
        expires_at: deadline.effective,
    })
}

/// How a forwarded `ensure` stands at the runner ([`ControllerSync::forward_ensure`]).
#[derive(Debug, Clone, PartialEq)]
pub enum Forwarded {
    /// The runner admitted the grant and it awaits this controller's issuer: the delivered
    /// record is written.
    Pending {
        /// The grant the runner admitted.
        grant: GrantId,
        /// The record (boxed: it is far larger than the other variant).
        record: Box<DeliveredGrant>,
    },
    /// The runner's `ensure` succeeded (the grant is issued and bound there): its result.
    Ready {
        /// The grant.
        grant: GrantId,
        /// The runner's `ensure` result, as it answered it.
        data: serde_json::Value,
    },
}

/// The hosted driver, as the dispatcher forwards an `ensure` through it.
#[async_trait::async_trait]
pub trait EnsureForwarding: Send + Sync {
    /// Forward `request` when its environment is a runner this controller records, and
    /// answer for it; `None` when it names no recorded runner (the local answer stands).
    async fn forward(
        &self,
        request: &heimdall_contract::request::EnsureRequest,
    ) -> Option<crate::OpResult<serde_json::Value>>;
}

/// The answer to the local caller for a forwarded `ensure` whose grant awaits issuance.
#[must_use]
pub fn forwarded_pending(grant: &GrantId) -> OpError {
    OpError::new(
        Code::Accepted,
        "the runner admitted the grant; it awaits this controller's issuer (see `environment \
         status`), and repeating the request with the same request ID reads its state",
    )
    .with_resource("grant", Some(grant.to_string()))
}

/// What one hosted pass over a runner did ([`ControllerSync::maintain`]).
#[derive(Debug, Default)]
pub struct Maintained {
    /// The grants issued for.
    pub issued: Vec<RemoteIssued>,
    /// The grants whose issuance failed, with the error recorded for each.
    pub failed: Vec<(GrantId, OpError)>,
}

/// How long the runner may hold a forwarded `ensure` before it answers: its admission is
/// local store work, and the grant then waits for this controller.
const FORWARD_WAIT_MS: u64 = 5_000;

fn unreadable_answer() -> OpError {
    OpError::new(
        Code::OutcomeUnknown,
        "the runner's answer to the forwarded ensure names no grant; nothing was recorded",
    )
}

/// The skew `valid_after` is set before the issuance time (ADR-0005 §3.4).
const VALID_AFTER_SKEW: Duration = Duration::from_secs(60);

/// `t` truncated to the whole second at or before it: a certificate carries whole seconds,
/// so the ledger records exactly the bounds that are signed and never a later one.
fn whole_second(t: Timestamp) -> Timestamp {
    Timestamp::from_second(t.as_second()).unwrap_or(t)
}

/// The controller's sync and issuance driver (module docs): this controller's store, clock
/// and the issuer's barrier, which is process state.
#[derive(Clone)]
pub struct ControllerSync {
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    barrier: Arc<IssuerBarrier>,
}

impl std::fmt::Debug for ControllerSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerSync").finish_non_exhaustive()
    }
}

impl ControllerSync {
    /// A driver over this controller's `store` and `clock`, with a barrier closed for every
    /// environment.
    #[must_use]
    pub fn new(store: Arc<Store>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
            barrier: Arc::new(IssuerBarrier::new()),
        }
    }

    /// The issuer's barrier.
    #[must_use]
    pub fn barrier(&self) -> &IssuerBarrier {
        &self.barrier
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Run the reconnect order over `session`, an open session to the runner `pin` names
    /// (module docs, "Reconnect"). On success the barrier is admitted for that environment
    /// until [`Self::session_closed`].
    ///
    /// # Errors
    ///
    /// `role_insufficient` for a device that is not an owner there, `driver_unavailable` for
    /// a session without `runner/1` (nothing sent in either case); otherwise
    /// [`resync`]'s. The barrier is closed on every error.
    pub async fn on_session(
        &self,
        pin: &RemoteEnvironmentPin,
        session: &mut dyn ManagementSession,
    ) -> Result<ResyncOutcome, OpError> {
        self.barrier.close(&pin.environment);
        if pin.role != Role::Owner {
            return Err(role_insufficient(
                "only an owner controller resynchronizes with a runner",
            ));
        }
        let mut channel = SessionChannel::new(session)?;
        resync(
            &self.store,
            self.clock.as_ref(),
            &self.barrier,
            pin,
            &mut channel,
        )
        .await
    }

    /// The session to `environment` ended or was lost: issuance is gated again.
    pub fn session_closed(&self, environment: &EnvironmentId) {
        session_ended(&self.barrier, environment);
    }

    /// Open a session to the runner `pin` names and run the reconnect order over it. The
    /// session is returned open, for the issuance that follows; the caller ends it with
    /// [`Self::session_closed`].
    ///
    /// # Errors
    ///
    /// The opener's error, recorded as the environment's last failure (a changed host key is
    /// `held`); or [`Self::on_session`]'s, with the session closed.
    pub async fn reconnect(
        &self,
        sessions: &dyn ManagementSessions,
        pin: &RemoteEnvironmentPin,
    ) -> Result<(Box<dyn ManagementSession>, ResyncOutcome), OpError> {
        let target = SessionTarget {
            name: SessionName::Environment(pin.environment.clone()),
            route: pin.route.clone(),
        };
        let mut session = match sessions.open(&target).await {
            Ok(s) => s,
            Err(e) => {
                // The refusal stands whether or not the observation could be written.
                let _ = note_open_failure(
                    &self.store,
                    &self.barrier,
                    &pin.environment,
                    &e,
                    self.clock.wall(),
                );
                return Err(e);
            }
        };
        match self.on_session(pin, session.as_mut()).await {
            Ok(outcome) => Ok((session, outcome)),
            Err(e) => {
                self.session_closed(&pin.environment);
                Err(e)
            }
        }
    }

    /// Issue certificates for the runner grant `input` names, over `channel`, a session this
    /// driver resynchronized (module docs, "Remote issuance").
    ///
    /// # Errors
    ///
    /// * `role_insufficient`: this device is not an owner on that runner;
    /// * the barrier's refusal (`resync_pending`, `TIME_UNCERTAIN`, a revoked grant, a paused
    ///   or cut-off policy), before anything is prepared and again at reserve and publish;
    /// * [`RemoteIssuer`]'s refusals: no issuer, an answer that does not match the ask,
    ///   `issuer_untrusted` for a grant pinned to another controller or CA;
    /// * the runner's refusal of the prepare or of an install. A certificate already
    ///   published stays counted in this ledger.
    pub async fn issue(
        &self,
        pin: &RemoteEnvironmentPin,
        channel: &mut dyn RunnerChannel,
        issuer: &dyn RemoteIssuer,
        input: &RemoteIssueInput,
    ) -> Result<RemoteIssued, OpError> {
        if !role_may_issue(pin.role) {
            return Err(role_insufficient(
                "this controller's role on the runner does not let it issue for its grants",
            ));
        }
        let environment = &pin.environment;
        // The content is this controller's: no record, nothing prepared.
        let delivered = self
            .store
            .transaction(|tx| tx.delivered_grant(environment, &input.grant))?
            .ok_or_else(not_delivered)?;
        // Nothing is asked of the runner while the barrier is closed.
        let now = self.clock.wall();
        self.store
            .transaction(|tx| {
                self.barrier
                    .permit(tx, environment, &input.grant, None, now)
            })?
            .map_err(|r| r.to_error())?;
        let ask = RemoteAsk {
            environment: environment.clone(),
            grant: input.grant.clone(),
            grant_generation: input.grant_generation,
            controller: pin.client.clone(),
            ca_fingerprint: issuer.ca()?,
        };
        // 1. prepare (the runner generates K_env).
        let answer = runner_result(
            channel
                .call(RunnerRequest::PrepareRemoteGrant {
                    grant: input.grant.clone(),
                    grant_generation: input.grant_generation,
                })
                .await?,
        )?;
        let subject = issuer.verify(&ask, answer, self.clock.wall())?;
        // The runner's answer can only narrow: a pair this controller did not deliver is
        // never signed for, and the whole answer is refused (ADR-0005 §3.5 condition 6).
        if !subject.pairs.iter().all(|p| delivered.pairs.contains(p)) {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "the runner's answer names a pair this controller did not deliver for that \
                 grant; nothing was reserved",
            )
            .with_effect(EffectStatus::None));
        }
        let policy = subject.policy.as_ref();
        // The pairs the runner's report of this session already shows a live certificate
        // for, under this generation: nothing more is issued for them.
        let installed: BTreeSet<AccessPairRef> = self
            .barrier
            .reconciliation(environment)
            .map(|r| {
                r.report
                    .certificates
                    .into_iter()
                    .filter(|c| {
                        c.grant == ask.grant
                            && c.grant_generation == ask.grant_generation
                            && c.valid_before > now
                    })
                    .map(|c| c.pair)
                    .collect()
            })
            .unwrap_or_default();
        let mut certificates = Vec::new();
        for pair in subject.pairs.iter().filter(|p| !installed.contains(*p)) {
            // 2. reserve, behind the barrier, in one transaction with its permit and with
            // the key binding the reservation rests on.
            let now = self.clock.wall();
            let entry = self.entry(&ask, &subject, &delivered, pair, input, now)?;
            let reserved = self.store.transaction(|tx| {
                let permit = match self
                    .barrier
                    .permit(tx, environment, &ask.grant, policy, now)?
                {
                    Ok(p) => p,
                    Err(r) => return Ok(Err(r.to_error())),
                };
                // Re-read in this transaction: the record may have been narrowed or
                // forgotten since.
                let Some(mut record) = tx.delivered_grant(environment, &ask.grant)? else {
                    return Ok(Err(not_delivered()));
                };
                let Some(report_at) = self.barrier.reconciliation(environment).map(|r| r.at) else {
                    return Ok(Err(
                        crate::remote_status_barrier::BarrierRefusal::NotReconciled.to_error(),
                    ));
                };
                // The grant's expiry and a future cutoff bound the certificate.
                let mut entry = entry.clone();
                let bound = permit
                    .bound
                    .map_or(record.expires_at, |b| b.min(record.expires_at));
                entry.bounds.valid_before = whole_second(entry.bounds.valid_before.min(bound));
                entry.bounds.extensions = entry
                    .bounds
                    .extensions
                    .intersection(&record.extensions)
                    .cloned()
                    .collect();
                if !record.pairs.contains(&entry.pair) {
                    return Ok(Err(not_delivered()));
                }
                record.prepared = Some(PreparedBinding {
                    grant_generation: ask.grant_generation,
                    key_fingerprint: subject.subject_fingerprint.clone(),
                    ca_fingerprint: ask.ca_fingerprint.clone(),
                    pairs: subject.pairs.iter().cloned().collect(),
                    policy: subject.policy.clone(),
                    runner_bound: subject.bound,
                    cutoff: permit.bound,
                    report_at,
                    prepared_at: now,
                });
                tx.put_delivered_grant(&record)?;
                Ok(self
                    .barrier
                    .reserve(tx, environment, policy, &entry, now)?
                    .map(|()| entry)
                    .map_err(|r| r.to_error()))
            })?;
            let entry = reserved?;
            if entry.bounds.valid_before <= entry.bounds.valid_after {
                return Err(OpError::new(
                    Code::CredentialExpired,
                    "the grant's bound leaves no validity to certify",
                )
                .with_effect(EffectStatus::None));
            }
            // 3. sign, then publish behind the barrier (a refusal voids the reservation
            // and the certificate is never released).
            let certificate = issuer.sign(&entry, &subject.subject_public_key).await?;
            let now = self.clock.wall();
            let published = self
                .store
                .transaction(|tx| {
                    self.barrier
                        .publish(tx, environment, policy, &entry.id, now)
                })?
                .map_err(|r| r.to_error())?;
            // 4. install at the runner: only a published certificate.
            if certificate.is_empty()
                || certificate.len() > heimdall_contract::remote::MAX_CERTIFICATE_BYTES
                || certificate.contains(['\n', '\r', '\0'])
            {
                return Err(OpError::new(
                    Code::InternalError,
                    "the issuer's certificate is not one line within the size limit",
                ));
            }
            runner_result(
                channel
                    .call(RunnerRequest::InstallCertificate {
                        grant: ask.grant.clone(),
                        grant_generation: ask.grant_generation,
                        certificate,
                    })
                    .await?,
            )?;
            certificates.push(RemoteCertificate {
                pair: pair.clone(),
                issuance: published.id,
                serial: published.bounds.serial,
                valid_before: published.bounds.valid_before,
            });
        }
        Ok(RemoteIssued {
            grant: ask.grant,
            certificates,
        })
    }

    /// Forward `request`, an `ensure` naming the runner `pin` records, over `session`, a
    /// session this driver resynchronized, and record what was asked (module docs, "How
    /// that record comes to exist").
    ///
    /// # Errors
    ///
    /// * `role_insufficient`: this controller's role there may not issue (nothing sent);
    /// * [`forwarded_ask`]'s `USAGE_ERROR` (nothing sent);
    /// * the runner's refusal, unchanged: `APPROVAL_REQUIRED` with the runner-local
    ///   `decision_ref` for a request beyond its standing policy (nothing recorded), or any
    ///   other error;
    /// * `OUTCOME_UNKNOWN` for an answer that names no grant (nothing recorded).
    pub async fn forward_ensure(
        &self,
        pin: &RemoteEnvironmentPin,
        session: &mut dyn ManagementSession,
        request: &heimdall_contract::request::EnsureRequest,
    ) -> Result<Forwarded, OpError> {
        if !role_may_issue(pin.role) {
            return Err(role_insufficient(
                "this controller's role on the runner does not let it issue for its grants",
            ));
        }
        let ask = forwarded_ask(request, self.clock.wall())?;
        let mut sent = request.clone();
        sent.environment = Some(pin.environment.clone());
        // A management session is never attended, and the runner answers at once: the
        // grant waits for this controller's issuer, which is this same driver.
        sent.interaction = heimdall_contract::request::InteractionMode::NonInteractive;
        sent.wait = heimdall_contract::request::WaitMode::Sync {
            timeout_ms: FORWARD_WAIT_MS,
        };
        let answer = session.call(ManagementCall::Ensure(Box::new(sent))).await?;
        let (grant, ready) = match answer.code {
            Code::Ok | Code::AccessReady => {
                let grant = answer
                    .data
                    .get("grant_id")
                    .and_then(|g| serde_json::from_value::<GrantId>(g.clone()).ok());
                (grant, Some(answer.data))
            }
            Code::Accepted => {
                let grant =
                    serde_json::from_value::<heimdall_contract::envelope::ErrorData>(answer.data)
                        .ok()
                        .and_then(|d| d.error.resource)
                        .filter(|r| r.kind == "grant")
                        .and_then(|r| r.id)
                        .and_then(|id| GrantId::parse(&id).ok());
                (grant, None)
            }
            _ => {
                return Err(runner_result(answer)
                    .err()
                    .unwrap_or_else(unreadable_answer));
            }
        };
        let grant = grant.ok_or_else(unreadable_answer)?;
        let now = self.clock.wall();
        let record = self.store.transaction(|tx| {
            deliver_runner_grant(
                tx,
                pin,
                &grant,
                &ask.pairs,
                &ask.extensions,
                ask.expires_at,
                now,
            )
        })??;
        Ok(match ready {
            Some(data) => Forwarded::Ready { grant, data },
            None => Forwarded::Pending {
                grant,
                record: Box::new(record),
            },
        })
    }

    /// Record how the last issuance for the delivered grant `grant` ended (`None`: it
    /// succeeded). The record is what `environment status` shows; a write failure changes
    /// nothing else.
    fn note_issuance(&self, environment: &EnvironmentId, grant: &GrantId, error: Option<&OpError>) {
        let now = self.clock.wall();
        let failure = error.map(|e| IssuanceFailure {
            at: now,
            reason: crate::remote_status::failure_reason(e),
        });
        let _ = self.store.transaction(|tx| {
            if let Some(mut record) = tx.delivered_grant(environment, grant)? {
                // The same failure again keeps its first instant.
                let same = matches!((&record.last_failure, &failure),
                    (Some(a), Some(b)) if a.reason == b.reason);
                if !same && record.last_failure != failure {
                    record.last_failure = failure;
                    tx.put_delivered_grant(&record)?;
                }
            }
            Ok(())
        });
    }

    /// The hosted pass over one runner (module docs): after `report`, the authority report
    /// this session's resynchronization read, issue for every grant this controller
    /// delivered to the runner that is not revoked or expired and that the report shows a
    /// pair without a live certificate for. Each grant is independent: one's failure is
    /// recorded with it and the pass goes on. Nothing is renewed in place: the runner keeps
    /// one certificate per pair and key, so a certificate runs to its `valid_before`, which
    /// the issuance sets to the delivered grant's bound.
    pub async fn maintain(
        &self,
        pin: &RemoteEnvironmentPin,
        channel: &mut dyn RunnerChannel,
        issuer: &dyn RemoteIssuer,
        report: &AuthorityReport,
    ) -> Maintained {
        let mut out = Maintained::default();
        let environment = &pin.environment;
        let now = self.clock.wall();
        let Ok(delivered) = self
            .store
            .transaction(|tx| tx.delivered_grants(Some(environment)))
        else {
            return out;
        };
        for record in delivered {
            let revoked = report
                .tombstones
                .iter()
                .any(|t| t.grant == record.grant || t.cascade.contains(&record.grant));
            if revoked || record.expires_at <= now {
                continue;
            }
            let covered = |pair: &AccessPairRef| {
                report.certificates.iter().any(|c| {
                    c.grant == record.grant
                        && c.grant_generation == report.authority_generation
                        && c.pair == *pair
                        && c.valid_before > now
                })
            };
            if record.pairs.iter().all(covered) {
                self.note_issuance(environment, &record.grant, None);
                continue;
            }
            let lifetime =
                Duration::try_from(record.expires_at.duration_since(now)).unwrap_or(Duration::ZERO);
            let input = RemoteIssueInput {
                grant: record.grant.clone(),
                grant_generation: report.authority_generation,
                lifetime,
            };
            match self.issue(pin, channel, issuer, &input).await {
                Ok(issued) => {
                    self.note_issuance(environment, &record.grant, None);
                    out.issued.push(issued);
                }
                Err(e) => {
                    self.note_issuance(environment, &record.grant, Some(&e));
                    out.failed.push((record.grant, e));
                }
            }
        }
        out
    }

    /// The ledger entry for one pair of a verified subject. The key ID names the runner's
    /// environment (`heimdall:<environment>:<grant>:<serial>`), which is also how this
    /// ledger knows which runner a grant lives on ([`runner_of_grant`]).
    fn entry(
        &self,
        ask: &RemoteAsk,
        subject: &RemoteSubject,
        delivered: &DeliveredGrant,
        pair: &AccessPairRef,
        input: &RemoteIssueInput,
        now: Timestamp,
    ) -> Result<IssuanceEntry, OpError> {
        let random = || {
            crate::ids::random_u64()
                .map_err(|_| OpError::new(Code::InternalError, "no randomness for an issuance"))
        };
        let serial = random()?;
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&random()?.to_be_bytes());
        id[8..].copy_from_slice(&random()?.to_be_bytes());
        let unrepresentable = || {
            OpError::new(
                Code::UsageError,
                "the certificate validity is not representable",
            )
        };
        let valid_after = jiff::SignedDuration::try_from(VALID_AFTER_SKEW)
            .ok()
            .and_then(|d| now.checked_sub(d).ok())
            .ok_or_else(unrepresentable)?;
        let wanted = jiff::SignedDuration::try_from(input.lifetime)
            .ok()
            .and_then(|d| now.checked_add(d).ok())
            .ok_or_else(unrepresentable)?;
        Ok(IssuanceEntry {
            id: IssuanceId::from_random_bytes(id),
            grant: ask.grant.clone(),
            generation: AuthorityGeneration(ask.grant_generation),
            pair: pair.clone(),
            bounds: CertificateBounds {
                serial,
                key_id: format!(
                    "heimdall:{}:{}:{serial}",
                    ask.environment.as_str(),
                    ask.grant.as_str()
                ),
                principal: principal_for(pair),
                valid_after: whole_second(valid_after),
                // ADR-0005 §3.5 condition 7: never past the grant's expiry or the runner's
                // reported bound (the cutoff is applied with the permit, at the reserve).
                valid_before: whole_second(wanted.min(subject.bound).min(delivered.expires_at)),
                // Condition 6: the extensions this controller delivered, nothing else.
                extensions: delivered.extensions.clone(),
                subject_fingerprint: subject.subject_fingerprint.clone(),
                ca_fingerprint: Some(ask.ca_fingerprint.clone()),
            },
            state: IssuanceState::Reserved,
            reserved_at: now,
            settled_at: None,
            void_reason: None,
            continuing: false,
        })
    }
}

// --- producing effects behind the local operations ---------------------------------------

/// This controller's record of the runner `environment`, when it holds one.
///
/// # Errors
///
/// The store's.
pub fn pin_of(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
) -> heimdall_store::Result<Option<RemoteEnvironmentPin>> {
    Ok(pins(tx)?
        .into_iter()
        .find(|p| p.environment == *environment))
}

/// Every runner this controller records. A record that cannot be read is left out: nothing
/// is sent to a runner whose pin is not known.
///
/// # Errors
///
/// The store's.
pub fn pins(tx: &mut Txn<'_>) -> heimdall_store::Result<Vec<RemoteEnvironmentPin>> {
    Ok(tx
        .remote_environment_pins()?
        .into_iter()
        .filter_map(|(_, json)| serde_json::from_str(&json).ok())
        .collect())
}

/// The environment a certificate key ID names for `grant`
/// (`heimdall:<environment>:<grant>:<serial>`).
fn key_id_environment(key_id: &str, grant: &GrantId) -> Option<EnvironmentId> {
    let mut parts = key_id.split(':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("heimdall"), Some(env), Some(g), Some(_), None) if g == grant.as_str() => {
            EnvironmentId::parse(env).ok()
        }
        _ => None,
    }
}

/// The recorded runner the grant `grant` lives on, as this controller knows it: its issuance
/// ledger (the entries' key IDs name the runner), else a runner's last authority report that
/// listed a certificate of the grant. `None` for a grant no record ties to a runner.
///
/// # Errors
///
/// The store's.
pub fn runner_of_grant(
    tx: &mut Txn<'_>,
    grant: &GrantId,
) -> heimdall_store::Result<Option<RemoteEnvironmentPin>> {
    let pins = pins(tx)?;
    for entry in tx.issuance_entries(grant)? {
        if let Some(env) = key_id_environment(&entry.bounds.key_id, grant)
            && let Some(pin) = pins.iter().find(|p| p.environment == env)
        {
            return Ok(Some(pin.clone()));
        }
    }
    for pin in pins {
        let contact = tx.remote_contact(&pin.environment)?;
        if contact
            .last_report
            .is_some_and(|r| r.certificates.iter().any(|c| c.grant == *grant))
        {
            return Ok(Some(pin));
        }
    }
    Ok(None)
}

/// The recorded runner whose last authority report listed the policy `policy`.
///
/// # Errors
///
/// The store's.
pub fn runner_of_policy(
    tx: &mut Txn<'_>,
    policy: &PolicyId,
) -> heimdall_store::Result<Option<RemoteEnvironmentPin>> {
    for pin in pins(tx)? {
        let contact = tx.remote_contact(&pin.environment)?;
        if contact
            .last_report
            .is_some_and(|r| r.policies.contains(policy))
        {
            return Ok(Some(pin));
        }
    }
    Ok(None)
}

/// A narrowing that became an outbox row for a runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerNarrowing {
    /// The runner.
    pub environment: EnvironmentId,
    /// The effect, `remote_pending` until acknowledged.
    pub key: EffectKey,
    /// `false` when a pending row for the same narrowing already existed and was reused.
    pub produced: bool,
    /// A revoke: the grant's counted residual in this ledger.
    pub residual: Option<CountedResidual>,
}

/// The pending row of this producer that already asks for `narrowing`, if any.
fn pending_same(
    pending: &[OutboxEffect],
    producer: &ClientId,
    narrowing: &Narrowing,
) -> Option<EffectKey> {
    pending
        .iter()
        .filter(|e| e.key.producer == *producer)
        .find(|e| match (&e.key.target, narrowing) {
            (EffectTarget::GrantRevoke { grant, .. }, Narrowing::RevokeGrant { grant: g, .. }) => {
                grant == g
            }
            (EffectTarget::PolicyPause { policy, .. }, Narrowing::PausePolicy { policy: p }) => {
                policy == p
            }
            (
                EffectTarget::PolicyCutoff { scope, at, .. },
                Narrowing::Cutoff { scope: s, at: a },
            ) => scope == s && at == a,
            _ => false,
        })
        .map(|e| e.key.clone())
}

/// Put `narrowing` in the outbox for the runner `pin` names unless this controller already
/// has the same narrowing pending for it (a repeated local request).
///
/// # Errors
///
/// As [`produce_effect`].
pub fn produce_once(
    tx: &mut Txn<'_>,
    pin: &RemoteEnvironmentPin,
    narrowing: &Narrowing,
    now: Timestamp,
) -> heimdall_store::Result<Result<(EffectKey, bool), OpError>> {
    let pending = tx.remote_effect_outbox(Some(&pin.environment), true)?;
    if let Some(key) = pending_same(&pending, &pin.client, narrowing) {
        return Ok(Ok((key, false)));
    }
    Ok(produce_effect(tx, pin, narrowing, now)?.map(|key| (key, true)))
}

/// The owner's local `revoke` of a grant this installation does not hold (module docs,
/// "Producing effects behind the local operations"): `None` when no record ties the grant
/// to a runner (the local `NOT_FOUND` stands). The generation the effect carries is the
/// latest this ledger counted for the grant; it is for idempotency and audit only, and the
/// runner revokes the grant at whatever generation it has now (ADR-0012 §7.4).
///
/// # Errors
///
/// The store's (outer); `role_insufficient` when this device is not an owner on that runner
/// (inner; nothing written).
pub fn narrow_runner_grant(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    now: Timestamp,
) -> heimdall_store::Result<Option<Result<RunnerNarrowing, OpError>>> {
    let Some(pin) = runner_of_grant(tx, grant)? else {
        return Ok(None);
    };
    let grant_generation = tx
        .issuance_entries(grant)?
        .iter()
        .map(|e| e.generation.0)
        .max()
        .unwrap_or(0);
    let narrowing = Narrowing::RevokeGrant {
        grant: grant.clone(),
        grant_generation,
    };
    let residual = counted_residual(tx, grant)?;
    Ok(Some(produce_once(tx, &pin, &narrowing, now)?.map(
        |(key, produced)| RunnerNarrowing {
            environment: pin.environment.clone(),
            key,
            produced,
            residual: Some(residual),
        },
    )))
}

/// The policy a local policy action names by ID, when it names exactly one, with the
/// cutoff's instant for a cutoff.
fn named_policy(action: &PolicyAction) -> Option<(&PolicyId, Option<Timestamp>)> {
    fn one<'a>(
        policy_id: &'a Option<PolicyId>,
        target: &'a Option<PolicyTarget>,
    ) -> Option<&'a PolicyId> {
        match (policy_id, target) {
            (Some(p), None) => Some(p),
            (None, Some(PolicyTarget::Policy { policy_id })) => Some(policy_id),
            _ => None,
        }
    }
    match action {
        PolicyAction::Pause { policy_id, target } => Some((one(policy_id, target)?, None)),
        PolicyAction::Cutoff {
            policy_id,
            at,
            target,
        } => Some((one(policy_id, target)?, Some(*at))),
        _ => None,
    }
}

/// The owner's local `policy pause` or `policy cutoff` naming one policy this installation
/// does not hold (module docs): `None` when the action is another one, names a scope rather
/// than one policy, or no runner's last report listed the policy (the local answer stands).
/// A scope (`all`, a profile, a workspace) names this installation's own policies and is
/// never sent to a runner from here.
///
/// # Errors
///
/// As [`narrow_runner_grant`].
pub fn narrow_runner_policy(
    tx: &mut Txn<'_>,
    action: &PolicyAction,
    now: Timestamp,
) -> heimdall_store::Result<Option<Result<RunnerNarrowing, OpError>>> {
    let Some((policy, cutoff)) = named_policy(action) else {
        return Ok(None);
    };
    let Some(pin) = runner_of_policy(tx, policy)? else {
        return Ok(None);
    };
    let narrowing = match cutoff {
        None => Narrowing::PausePolicy {
            policy: policy.clone(),
        },
        Some(at) => Narrowing::Cutoff {
            scope: PolicyTarget::Policy {
                policy_id: policy.clone(),
            },
            at,
        },
    };
    Ok(Some(produce_once(tx, &pin, &narrowing, now)?.map(
        |(key, produced)| RunnerNarrowing {
            environment: pin.environment.clone(),
            key,
            produced,
            residual: None,
        },
    )))
}

// --- the local operations' answers ---------------------------------------------------------

fn pending_note(n: &RunnerNarrowing) -> serde_json::Value {
    serde_json::json!({
        "environment": n.environment,
        "effect": n.key.effect,
        "target": n.key.target,
        "remote_pending": true,
        "produced": n.produced,
    })
}

/// The owner's local `revoke` of the grant `grant`, which this installation does not hold
/// (the local operation answered `NOT_FOUND`): when the grant is a recorded runner's
/// ([`narrow_runner_grant`]), the revoke is a durable outbox row for that runner and the
/// answer is a revoke result with `local_applied: false` and the grant `remote_pending`,
/// with the counted residual. `None` when no record ties the grant to a runner: the local
/// answer stands.
#[must_use]
pub fn revoke_on_runner(
    store: &Store,
    grant: &GrantId,
    now: Timestamp,
) -> Option<crate::OpResult<heimdall_contract::request::RevokeData>> {
    let narrowed = match store.transaction(|tx| narrow_runner_grant(tx, grant, now)) {
        Ok(n) => n?,
        Err(e) => return Some(Err(e.into())),
    };
    Some(narrowed.map(|n| {
        crate::error::Completed::ok(
            Code::Ok,
            heimdall_contract::request::RevokeData {
                local_applied: false,
                remote_pending: vec![grant.clone()],
                latest_possible_credential_expiry: n.residual.and_then(CountedResidual::expiry),
                remote_effects: Vec::new(),
                owned_connections: Vec::new(),
                notes: Vec::new(),
                requested_at: Some(now),
                committed_at: Some(now),
            },
        )
    }))
}

/// The owner's local `policy pause` or `policy cutoff` naming one policy this installation
/// does not hold (the local operation answered `NOT_FOUND`): as [`revoke_on_runner`], for a
/// policy a recorded runner's last report listed ([`narrow_runner_policy`]).
#[must_use]
pub fn policy_on_runner(
    store: &Store,
    action: &PolicyAction,
    now: Timestamp,
) -> Option<crate::OpResult<serde_json::Value>> {
    let narrowed = match store.transaction(|tx| narrow_runner_policy(tx, action, now)) {
        Ok(n) => n?,
        Err(e) => return Some(Err(e.into())),
    };
    Some(narrowed.map(|n| crate::error::Completed::ok(Code::Ok, pending_note(&n))))
}

// --- ⟨M06 W3 host⟩ a local cutoff of every policy fans out to every owned runner -----------

/// The hosted driver, as the dispatcher's narrowing hooks use it: an effect was put in the
/// outbox and should be delivered without waiting for the next pass.
#[async_trait::async_trait]
pub trait OutboxDelivery: Send + Sync {
    /// Ask for a delivery pass now; returns at once.
    fn notify(&self);

    /// Ask for a delivery pass now and wait for it to end, at most `bound`. What was
    /// delivered is read from the outbox afterwards; nothing is reported here.
    async fn deliver(&self, bound: Duration);
}

/// The instant of a local cutoff of **every** policy (`policy cutoff` with scope `all`), the
/// only scope that fans out: a profile's or a workspace's policies are this installation's
/// own (their IDs mean nothing on a runner) and stay local.
#[must_use]
pub fn cutoff_of_all(action: &PolicyAction) -> Option<Timestamp> {
    match action {
        PolicyAction::Cutoff {
            policy_id: None,
            at,
            target: Some(PolicyTarget::All),
        } => Some(*at),
        _ => None,
    }
}

/// Put a cutoff of every policy at `at` in the outbox of every runner this controller owns
/// (ruling on `driver` Q2: it only narrows). A runner this controller is not an owner of is
/// left out: it could not deliver the effect. A repeated request reuses each pending row.
///
/// # Errors
///
/// The store's: nothing was written for any runner.
pub fn cutoff_all_on_runners(
    store: &Store,
    at: Timestamp,
    now: Timestamp,
) -> Result<Vec<RunnerNarrowing>, OpError> {
    let narrowing = Narrowing::Cutoff {
        scope: PolicyTarget::All,
        at,
    };
    Ok(store.transaction(|tx| {
        let mut out = Vec::new();
        for pin in pins(tx)? {
            if let Ok((key, produced)) = produce_once(tx, &pin, &narrowing, now)? {
                out.push(RunnerNarrowing {
                    environment: pin.environment.clone(),
                    key,
                    produced,
                    residual: None,
                });
            }
        }
        Ok(out)
    })?)
}

/// Where each of `narrowings` stands now: `{"delivered": [...], "pending": [...]}`, one
/// `{environment, effect}` per runner; delivered means the runner's acknowledgement is
/// recorded. A row that cannot be read counts as pending.
#[must_use]
pub fn runner_deliveries(store: &Store, narrowings: &[RunnerNarrowing]) -> serde_json::Value {
    let (mut delivered, mut pending) = (Vec::new(), Vec::new());
    for n in narrowings {
        let acknowledged = store
            .transaction(|tx| {
                Ok(tx
                    .remote_effect_outbox(Some(&n.environment), false)?
                    .iter()
                    .any(|row| row.key == n.key && row.ack.is_some()))
            })
            .unwrap_or(false);
        let entry = serde_json::json!({ "environment": n.environment, "effect": n.key.effect });
        if acknowledged {
            delivered.push(entry);
        } else {
            pending.push(entry);
        }
    }
    serde_json::json!({ "delivered": delivered, "pending": pending })
}
