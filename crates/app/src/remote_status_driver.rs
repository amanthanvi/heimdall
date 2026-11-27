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
//! install leaves the entry counted (ADR-0005 §3.5). ⟨M08 W4 SEC-1, S1-01; §3.5 step 3⟩ The
//! publication's transaction applies this controller's own checks of the reservation again
//! before the barrier's (`republish_checks`): the delivered record, its pairs, extensions and
//! expiry, and the standing policy it came from. A pause of that policy, or the runner's
//! removal, committed while the issuer signed voids the reservation, and nothing is sent.
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
//! the pairs, the extensions and the expiry are this controller's own. ⟨M06 W4⟩ An omitted
//! scope is resolved from this controller's own copy of the profile ([`forwarded_scope`]);
//! an `ensure` whose pairs cannot be resolved here, or that names no deadline, is not
//! forwarded: the controller would have nothing of its own to record. Each forwarded pair
//! names the CA this controller will issue from (`EnsureRequest::pair_issuers`). A request the runner leaves waiting for a decision at the runner
//! (`APPROVAL_REQUIRED`) records nothing; repeating it with the same request ID after the
//! decision does.
//!
//! ⟨M06 W4, W5; condition 8 (b); m06-plan §2 item 3⟩ **The record's second source**
//! ([`adopt_under_standing_policy`]): a standing policy held on this controller that names
//! the runner environment (created only through the attended widening, by a controller
//! whose role there may issue; it activates nothing locally). The runner's authority
//! report lists the grants that wait for their issuer; one that **one** such policy covers
//! (its profile, every pair, a deadline no later than the policy's maximum lifetime and
//! cutoff) gets its delivered record from that policy, and the record names the policy.
//! Issuance under that record needs the policy to still authorize it at the reservation.
//! A pending grant neither source covers is never signed.
//!
//! ⟨M06 W4; m06-plan §2 item 2⟩ **No routine renewal.** A remote certificate runs to the
//! grant's bound. A pair is issued for again only when the runner's report shows no live
//! certificate for it at the runner's current generation (a delivered pause or cutoff moved
//! the generation and the runner dropped K_env with its certificates), and then only once
//! the barrier lets it: after a delivered pause or cutoff, when the report shows the lift
//! and the owner's `environment resume-issuance` acknowledgement is recorded
//! ([`resume_issuance_named`]).
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
use heimdall_domain::issuance::{
    CertificateBounds, IssuanceEntry, IssuanceRefusal, IssuanceState, principal_for,
};
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

/// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ Whether the role this controller holds on a runner may
/// only **submit** a request there: it holds `request` and may not issue (`requester` in
/// today's table; no role is named here). Such a controller sends the request and records
/// nothing: it never signs, and nothing is signed on its word.
#[must_use]
pub fn role_may_only_request(role: Role) -> bool {
    role.permissions().contains(&Permission::Request) && !role_may_issue(role)
}

fn not_delivered() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "this controller holds no record of delivering that grant to the runner: nothing is \
         issued for a grant whose content this controller does not hold",
    )
    .with_effect(EffectStatus::None)
}

fn local_grant_refusal() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the runner's answer names a grant ID held by this installation: a local grant is \
         never recorded as a runner grant; nothing was recorded",
    )
    .with_effect(EffectStatus::None)
}

/// Record that this controller delivered `grant` to the runner `pin` names, with exactly
/// these pairs and extensions until `expires_at`: the only content a certificate for it may
/// ever carry (module docs). Re-recording a grant never widens it, whatever the runner's
/// answer named:
///
/// * ⟨M06 W5; M06-W4-R04⟩ an ask that lies **inside** the record (its pairs and extensions
///   are among the record's, its expiry no later) is another binding attaching to the grant
///   (the runner attaches only such a request): the record is left exactly as it is, so
///   what the grant's other bindings rely on, and a later re-issue for them, is not
///   narrowed. Everything such a binding may get was already delivered;
/// * any other ask is intersected with the record (pairs, extensions) and the expiry never
///   moves later: a faithful runner gives such a request its own grant, so an answer that
///   names this one for it can only narrow.
///
/// # Errors
///
/// The store's (outer). Inner, nothing written: `role_insufficient` when this controller's
/// role there may not issue; `CAPABILITY_UNAVAILABLE` (effect `none`) when `grant` names a
/// local grant of this installation (ruling 7); `USAGE_ERROR` for no pair, or an expiry
/// that has passed.
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
    // ⟨M08 W4 SEC-5, ruling 7⟩ A local grant of this installation is never recorded as a
    // runner grant (same code the issuer child uses for `LocalGrant`).
    if tx.grant(grant)?.is_some() {
        return Ok(Err(local_grant_refusal()));
    }
    if pairs.is_empty() || expires_at <= now {
        return Ok(Err(OpError::new(
            Code::UsageError,
            "a delivered grant needs at least one pair and an expiry that has not passed",
        )
        .with_effect(EffectStatus::None)));
    }
    let record = match tx.delivered_grant(&pin.environment, grant)? {
        Some(old)
            if pairs.is_subset(&old.pairs)
                && extensions.is_subset(&old.extensions)
                && expires_at <= old.expires_at =>
        {
            return Ok(Ok(old));
        }
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
            policy: None,
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
/// that record comes to exist"), at this controller's `now`. `request` carries its pairs
/// already resolved ([`forwarded_scope`]).
///
/// # Errors
///
/// `USAGE_ERROR`, nothing sent or written: the request names no pair, names no deadline (or
/// one that cannot be read or has passed), names an issuing CA itself, or uses a form a
/// runner does not serve through a controller (`context`, `covered_only`).
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
            "an ensure forwarded to a runner names its destination pairs (--pair), or a \
             profile this controller holds a copy of: this controller records exactly the \
             pairs it asked for",
        ));
    }
    if !request.pair_issuers.is_empty() {
        return Err(forward_usage(
            "the issuing CA of a forwarded ensure is this controller's own; a request does \
             not name it",
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

/// ⟨M06 W4 grant-e2e; m06-plan §2 "Also ruled"⟩ The pairs a forwarded `ensure` asks for:
/// the ones it names, else the scope of **this controller's own copy** of the profile it
/// names (the revision it names, else the latest here). The runner's profile is never
/// asked: what is recorded and signed for is what this controller resolved.
///
/// # Errors
///
/// The store's (outer). Inner, `USAGE_ERROR`, nothing sent: the request names no pair and
/// this controller holds no such profile (or revision), or the profile has no pair.
pub fn forwarded_scope(
    tx: &mut Txn<'_>,
    request: &heimdall_contract::request::EnsureRequest,
) -> heimdall_store::Result<Result<BTreeSet<AccessPairRef>, OpError>> {
    if !request.scope.is_empty() {
        return Ok(Ok(request.scope.clone()));
    }
    let unresolved = || {
        forward_usage(
            "the request names no destination pair and this controller holds no copy of \
             the profile to resolve them from: name the pairs (--pair)",
        )
    };
    let Some(profile) = &request.profile else {
        return Ok(Err(unresolved()));
    };
    let revision = match request.profile_revision {
        Some(r) => Some(r),
        None => tx.profile(profile)?.map(|p| p.revision),
    };
    let pairs = match revision {
        Some(r) => tx
            .profile_snapshot(profile, r)?
            .map(|s| s.scope.pairs)
            .unwrap_or_default(),
        None => BTreeSet::new(),
    };
    Ok(if pairs.is_empty() {
        Err(unresolved())
    } else {
        Ok(pairs)
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
        /// The runner's operation, when its answer named one.
        operation: Option<heimdall_contract::ids::OperationId>,
        /// The record (boxed: it is far larger than the other variant).
        record: Box<DeliveredGrant>,
    },
    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ A role that may only request submitted it and the
    /// runner admitted it: **nothing is recorded here**, and the grant waits for an owner
    /// controller's record.
    Submitted {
        /// The grant the runner admitted.
        grant: GrantId,
        /// The runner's operation, when its answer named one.
        operation: Option<heimdall_contract::ids::OperationId>,
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

    /// ⟨M06 W4⟩ `operation wait` for a forwarded `ensure` that answered pending: drive
    /// `operation`, the runner's operation that answer named, for at most `wait_ms`, and
    /// answer as [`Self::forward`] does. `None` when `operation` is not one this runtime
    /// instance forwarded (the local `NOT_FOUND` stands).
    async fn observe(
        &self,
        _operation: &heimdall_contract::ids::OperationId,
        _wait_ms: Option<u64>,
    ) -> Option<crate::OpResult<serde_json::Value>> {
        None
    }
}

/// ⟨M06 W4 grant-e2e; m06-plan §2 "Also ruled"⟩ Mark `data`, the `data` of an `ACCEPTED`
/// answer for a grant that awaits its controller's issuer, with the pending state: the
/// readiness field `refresh_dependency: controller` and the grant as a `remote_pending`
/// entry. Nothing else of `data` changes; no reason is set.
pub fn mark_pending(data: &mut serde_json::Value, grant: &GrantId) {
    if let Some(map) = data.as_object_mut() {
        map.insert(
            "refresh_dependency".to_owned(),
            serde_json::json!(heimdall_contract::request::RefreshDependency::Controller),
        );
        map.insert("remote_pending".to_owned(), serde_json::json!([grant]));
    }
}

/// The answer to the local caller for a forwarded `ensure` whose grant awaits issuance:
/// `ACCEPTED`, no reason, naming the grant and (when the runner named one) the operation
/// `operation wait` drives, with [`mark_pending`]'s data.
#[must_use]
pub fn forwarded_pending(
    grant: &GrantId,
    operation: Option<&heimdall_contract::ids::OperationId>,
) -> crate::error::Completed<serde_json::Value> {
    let mut e = OpError::new(
        Code::Accepted,
        "the runner admitted the grant; it awaits this controller's issuer (see `environment \
         status`). `operation wait`, or the same request with the same request ID, reads \
         its state",
    )
    .with_resource("grant", Some(grant.to_string()));
    if let Some(op) = operation {
        e = e.with_operation(op.clone());
    }
    let envelope = e.into_envelope();
    let mut data = serde_json::to_value(&envelope.data).unwrap_or(serde_json::Value::Null);
    mark_pending(&mut data, grant);
    crate::error::Completed {
        operation_id: envelope.operation_id,
        state: envelope.state,
        code: envelope.code,
        data,
        warnings: envelope.warnings,
        next: envelope.next,
    }
}

/// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ The answer to the local caller for an `ensure` a
/// limited role submitted ([`ControllerSync::submit_ensure`]) that the runner admitted:
/// `ACCEPTED`, no reason, naming the grant and the runner's operation, with
/// [`mark_pending`]'s data. It says who can complete it: not this device.
#[must_use]
pub fn submitted_pending(
    grant: &GrantId,
    operation: Option<&heimdall_contract::ids::OperationId>,
) -> crate::error::Completed<serde_json::Value> {
    let mut e = OpError::new(
        Code::Accepted,
        "the runner admitted the request. It stays pending until an owner controller of \
         that runner holds a record that covers it; this device's role cannot issue for \
         it. `operation wait`, or the same request with the same request ID, reads its state",
    )
    .with_resource("grant", Some(grant.to_string()));
    if let Some(op) = operation {
        e = e.with_operation(op.clone());
    }
    let envelope = e.into_envelope();
    let mut data = serde_json::to_value(&envelope.data).unwrap_or(serde_json::Value::Null);
    mark_pending(&mut data, grant);
    crate::error::Completed {
        operation_id: envelope.operation_id,
        state: envelope.state,
        code: envelope.code,
        data,
        warnings: envelope.warnings,
        next: envelope.next,
    }
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

/// `t` rounded to the whole second at or after it. A certificate's `valid_after` is
/// rounded this way: its span then never exceeds `valid_before - (now - skew)`, so a
/// certificate issued in the same second its grant was delivered stays inside the issuer's
/// validity ceiling (the delivered window plus the skew; `heimdall_issuer::check::
/// validity_within_ceiling`). Rounding down added up to a second to the span, and the
/// issuer refused a forwarded `ensure`'s first issue (⟨M06 W4⟩ found by the journey e2e).
fn whole_second_up(t: Timestamp) -> Timestamp {
    let floor = whole_second(t);
    if floor == t {
        t
    } else {
        floor
            .checked_add(jiff::SignedDuration::from_secs(1))
            .unwrap_or(t)
    }
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
            standing: crate::remote_env::SessionStanding::of_record(pin.role),
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
        // ⟨M06 W5⟩ Nor for a record whose standing policy no longer authorizes it.
        self.store
            .transaction(|tx| source_policy_bound(tx, &delivered, now))??;
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
                let permit =
                    match self
                        .barrier
                        .permit_answer(tx, environment, &ask.grant, policy, now)?
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
                // ⟨M06 W5; condition 8 (b)⟩ A record written from a standing policy is
                // signed for only while that policy still authorizes it; its cutoff bounds
                // the certificate.
                let policy_cutoff = match source_policy_bound(tx, &record, now)? {
                    Ok(c) => c,
                    Err(e) => return Ok(Err(e)),
                };
                // The grant's expiry and a future cutoff bound the certificate.
                let mut entry = entry.clone();
                let bound = permit
                    .bound
                    .map_or(record.expires_at, |b| b.min(record.expires_at));
                let bound = policy_cutoff.map_or(bound, |c| c.min(bound));
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
            let published = self.store.transaction(|tx| {
                // ⟨M08 W4 SEC-1, S1-01⟩ This controller's own checks of the reservation
                // again, in the publication's transaction: the signature took time, and
                // the owner may have paused the record's policy or removed the runner.
                if let Some(refused) = republish_checks(tx, environment, &entry, now)? {
                    return Ok(Err(refused));
                }
                Ok(self
                    .barrier
                    .publish(tx, environment, policy, &entry.id, now)?
                    .map_err(|r| r.to_error()))
            })??;
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
    /// * `OUTCOME_UNKNOWN` for an answer that names no grant (nothing recorded);
    /// * ⟨M08 W4 SEC-5, ruling 7⟩ `CAPABILITY_UNAVAILABLE`, effect `none`, for an answer
    ///   naming a grant of this installation, before anything else (nothing recorded);
    /// * ⟨M08 W4 SEC-5, item 1⟩ `OUTCOME_UNKNOWN` ("the runner's response could not be
    ///   read") for an answer whose data fails its grammar
    ///   ([`crate::remote_ingress::screen_ensure_data`]; nothing recorded).
    pub async fn forward_ensure(
        &self,
        pin: &RemoteEnvironmentPin,
        session: &mut dyn ManagementSession,
        request: &heimdall_contract::request::EnsureRequest,
        ca: &CaFingerprint,
    ) -> Result<Forwarded, OpError> {
        if !role_may_issue(pin.role) {
            return Err(role_insufficient(
                "this controller's role on the runner does not let it issue for its grants",
            ));
        }
        // The scope is this controller's: named, or resolved from its own profile.
        let mut sent = request.clone();
        sent.scope = self
            .store
            .transaction(|tx| forwarded_scope(tx, request))??;
        let ask = forwarded_ask(&sent, self.clock.wall())?;
        // Each pair names the CA this controller will issue from: the runner resolves it
        // to a managed certificate only under its `issuer_trust` for this controller.
        sent.pair_issuers = sent
            .scope
            .iter()
            .map(|pair| heimdall_contract::request::PairIssuer {
                pair: pair.clone(),
                ca_fingerprint: ca.clone(),
            })
            .collect();
        sent.environment = Some(pin.environment.clone());
        // A management session is never attended, and the runner answers at once: the
        // grant waits for this controller's issuer, which is this same driver.
        sent.interaction = heimdall_contract::request::InteractionMode::NonInteractive;
        sent.wait = heimdall_contract::request::WaitMode::Sync {
            timeout_ms: FORWARD_WAIT_MS,
        };
        let answer = session.call(ManagementCall::Ensure(Box::new(sent))).await?;
        let operation =
            crate::remote_ingress::screen_peer_operation_id(answer.operation_id.clone());
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
        // ⟨M08 W4 SEC-5, ruling 7⟩ Refuse a runner-named grant ID matching a local grant
        // outright, before anything else, with the same code the issuer child uses for
        // `LocalGrant` (`CAPABILITY_UNAVAILABLE`, effect `none`).
        if self.store.transaction(|tx| tx.grant(&grant))?.is_some() {
            return Err(local_grant_refusal());
        }
        // ⟨M08 W4 SEC-5, item 1⟩ Screen `EnsureData` at the remote ingress before recording
        // anything or returning it to callers/JSON/logs.
        let ready = match ready {
            Some(raw) => {
                let (screened_grant, screened) =
                    crate::remote_ingress::screen_ensure_data(raw, &pin.environment)?;
                if screened_grant != grant {
                    return Err(crate::remote_ingress::unreadable_runner_response());
                }
                Some(screened)
            }
            None => {
                if !crate::remote_ingress::is_generated_id(grant.as_str(), GrantId::PREFIX) {
                    return Err(crate::remote_ingress::unreadable_runner_response());
                }
                None
            }
        };
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
                operation,
                record: Box::new(record),
            },
        })
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ Submit `request`, an `ensure` naming the runner
    /// `pin` records, as a role that may only request there ([`role_may_only_request`]).
    /// One session of the limited standing is opened for it (nothing is resynchronized:
    /// such a role delivers no effect and reads no authority report), the request is sent
    /// as it was asked, and **nothing is recorded here**: no delivered-grant record, no
    /// CA named for any pair. The runner admits it under its own standing policy or a
    /// decision confirmed at the runner, and its grant then waits for an owner
    /// controller whose own record covers it.
    ///
    /// # Errors
    ///
    /// * `role_insufficient`: this controller's role there is not one that only requests
    ///   (nothing sent);
    /// * `USAGE_ERROR`, nothing sent: the request names an issuing CA or a working
    ///   directory, or no profile;
    /// * the opener's error, or a runner whose identity does not match the record
    ///   (`environment_identity_mismatch`), nothing sent;
    /// * the runner's refusal, unchanged (`APPROVAL_REQUIRED` with the runner-local
    ///   `decision_ref`, `role_insufficient`, …);
    /// * `OUTCOME_UNKNOWN` for an answer that names no grant, or ⟨M08 W4 SEC-5, item 1⟩ one
    ///   whose data fails its grammar ([`crate::remote_ingress::screen_ensure_data`]).
    pub async fn submit_ensure(
        &self,
        sessions: &dyn ManagementSessions,
        pin: &RemoteEnvironmentPin,
        request: &heimdall_contract::request::EnsureRequest,
    ) -> Result<Forwarded, OpError> {
        if !role_may_only_request(pin.role) {
            return Err(role_insufficient(
                "this controller's role on the runner does not let it submit a request there",
            ));
        }
        if !request.pair_issuers.is_empty() {
            return Err(forward_usage(
                "a request submitted to a runner by a role that cannot issue names no \
                 issuing CA: an owner controller's own record decides what is signed",
            ));
        }
        if request.context.is_some() || request.profile.is_none() {
            return Err(forward_usage(
                "a request submitted to a runner names a profile; a working directory \
                 (context) is resolved on the machine that has it",
            ));
        }
        let mut sent = request.clone();
        sent.environment = Some(pin.environment.clone());
        // A management session is never attended, and the runner answers at once.
        sent.interaction = heimdall_contract::request::InteractionMode::NonInteractive;
        sent.wait = heimdall_contract::request::WaitMode::Sync {
            timeout_ms: FORWARD_WAIT_MS,
        };
        let mut session = sessions
            .open(&SessionTarget {
                name: SessionName::Environment(pin.environment.clone()),
                route: pin.route.clone(),
                standing: crate::remote_env::SessionStanding::of_record(pin.role),
            })
            .await?;
        let hello = session.hello();
        if hello.environment != pin.environment
            || hello.client.as_ref().is_some_and(|c| *c != pin.client)
        {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "the runner's environment ID or client does not match this controller's \
                 record: held, nothing sent",
            )
            .with_reason(reason::ENVIRONMENT_IDENTITY_MISMATCH)
            .with_effect(EffectStatus::None));
        }
        let answer = session.call(ManagementCall::Ensure(Box::new(sent))).await?;
        let operation =
            crate::remote_ingress::screen_peer_operation_id(answer.operation_id.clone());
        match answer.code {
            Code::Ok | Code::AccessReady => {
                // ⟨M08 W4 SEC-5, item 1⟩ Screen `EnsureData` at the remote ingress.
                let (grant, data) =
                    crate::remote_ingress::screen_ensure_data(answer.data, &pin.environment)?;
                Ok(Forwarded::Ready { grant, data })
            }
            Code::Accepted => {
                let grant =
                    serde_json::from_value::<heimdall_contract::envelope::ErrorData>(answer.data)
                        .ok()
                        .and_then(|d| d.error.resource)
                        .filter(|r| r.kind == "grant")
                        .and_then(|r| r.id)
                        .and_then(|id| GrantId::parse(&id).ok())
                        .filter(|g| {
                            crate::remote_ingress::is_generated_id(g.as_str(), GrantId::PREFIX)
                        })
                        .ok_or_else(unreadable_answer)?;
                Ok(Forwarded::Submitted { grant, operation })
            }
            _ => Err(runner_result(answer)
                .err()
                .unwrap_or_else(unreadable_answer)),
        }
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
    /// recorded with it and the pass goes on. ⟨M06 W4⟩ There is no routine renewal: a pair
    /// with a live certificate is left alone, whatever that certificate's length.
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
        // ⟨M06 W4; condition 8 (b)⟩ A pending grant a standing policy held here covers
        // becomes a delivered record first; the loop below then issues for it as for any
        // other. One it does not cover stays pending: nothing is recorded or asked.
        let _ = self
            .store
            .transaction(|tx| adopt_under_standing_policy(tx, pin, report, now));
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
            let live = |pair: &AccessPairRef| {
                report.certificates.iter().find(|c| {
                    c.grant == record.grant
                        && c.grant_generation == report.authority_generation
                        && c.pair == *pair
                        && c.valid_before > now
                })
            };
            if record.pairs.iter().all(|p| live(p).is_some()) {
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
                valid_after: whole_second_up(valid_after),
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

// --- ⟨M06 W4, W5⟩ record source (b): a standing policy held on this controller ------------

/// Whether `policy`, a standing policy held on this controller, authorizes issuance for
/// `pairs` on the runner `environment` at `now`: a personal policy (no workspace; a
/// workspace-bound policy is ignored) that **names that runner environment**, is not
/// paused, whose cutoff has not passed, and whose scope holds **every** one of `pairs`
/// with the SSH-authentication capability. The principals follow from the pairs (one
/// account each), so they are the policy's when the pairs are.
fn policy_authorizes(
    policy: &heimdall_domain::policy::StandingPolicy,
    environment: &EnvironmentId,
    pairs: &BTreeSet<AccessPairRef>,
    now: Timestamp,
) -> bool {
    policy.workspace.is_none()
        && policy.environments.contains(environment)
        && matches!(policy.pause, heimdall_domain::policy::PauseState::Active)
        && policy.cutoff_at.is_none_or(|c| c > now)
        && !pairs.is_empty()
        && pairs.is_subset(&policy.scope.pairs)
        && policy
            .scope
            .capabilities
            .contains(&heimdall_domain::scope::Capability::SshAuthentication)
}

/// The latest deadline `policy` lets a grant adopted at `now` have: its maximum lifetime
/// from now, and its cutoff (its expiry) when it has one. `None` when not representable.
fn policy_deadline(
    policy: &heimdall_domain::policy::StandingPolicy,
    now: Timestamp,
) -> Option<Timestamp> {
    let window = jiff::SignedDuration::try_from(policy.max_window)
        .ok()
        .and_then(|d| now.checked_add(d).ok())?;
    Some(policy.cutoff_at.map_or(window, |c| c.min(window)))
}

/// ⟨M06 W5; m06-plan §2 item 3 "Coverage"⟩ The standing policy held on this controller
/// that authorizes issuance for `pending`, a grant the runner `environment` admitted and
/// reported as waiting (ADR-0005 §3.5 condition 8 (b)). **One** policy must cover the
/// whole grant; nothing is united across policies:
/// * it is for the grant's profile and [`policy_authorizes`] every pair of the grant;
/// * the grant's deadline is no later than [`policy_deadline`]: the policy's maximum
///   lifetime, counted from this controller's clock now, and its cutoff.
///
/// A grant with a pair outside the policy, or a later deadline, is not covered at all
/// (nothing is clamped: the runner's prepare answer would name that pair, and an answer
/// naming a pair outside the record is refused whole). The extensions are not the
/// grant's to ask for: the record carries the base extension profile, which is what any
/// policy grants, and the runner's answer can only narrow it.
fn covering_policy<'p>(
    policies: &'p [heimdall_domain::policy::StandingPolicy],
    environment: &EnvironmentId,
    pending: &heimdall_store::ext_effects::ReportedPendingGrant,
    now: Timestamp,
) -> Option<&'p heimdall_domain::policy::StandingPolicy> {
    policies.iter().find(|p| {
        p.profile == pending.profile
            && policy_authorizes(p, environment, &pending.pairs, now)
            && policy_deadline(p, now).is_some_and(|latest| pending.expires_at <= latest)
    })
}

/// [`heimdall_store::ext_effects::RefusedPending::limit`]: the policy's maximum lifetime.
pub const LIMIT_MAX_LIFETIME: &str = "deadline_exceeds_policy_max_lifetime";
/// [`heimdall_store::ext_effects::RefusedPending::limit`]: the policy's cutoff.
pub const LIMIT_CUTOFF: &str = "deadline_exceeds_policy_cutoff";

/// ⟨M06 W5 ruling, 2026-11-22⟩ Why no policy here covers `pending` although one holds
/// its profile and every one of its pairs: the grant's deadline is later than that policy
/// allows. The refusal names the limit exceeded, so the owner knows what to change: the
/// policy's **maximum lifetime** (counted from this controller's clock now) or its
/// **cutoff**; the cutoff when the deadline is past both and the cutoff is the earlier.
/// `None`: the grant is covered, or no policy holds its profile and pairs (then it is
/// not a deadline refusal, and nothing is said). Among several such policies, the one
/// that allows the latest deadline is named.
fn deadline_refusal(
    policies: &[heimdall_domain::policy::StandingPolicy],
    environment: &EnvironmentId,
    pending: &heimdall_store::ext_effects::ReportedPendingGrant,
    now: Timestamp,
) -> Option<heimdall_store::ext_effects::RefusedPending> {
    let (policy, latest) = policies
        .iter()
        .filter(|p| {
            p.profile == pending.profile && policy_authorizes(p, environment, &pending.pairs, now)
        })
        .filter_map(|p| Some((p, policy_deadline(p, now)?)))
        .max_by_key(|(_, latest)| *latest)?;
    if pending.expires_at <= latest {
        return None;
    }
    let asked = whole_second(pending.expires_at);
    let (limit, detail) = match policy.cutoff_at {
        Some(cutoff) if cutoff <= latest => (
            LIMIT_CUTOFF,
            format!(
                "the grant's deadline {asked} is later than the cutoff {} of policy {}: ask \
                 for a deadline no later than the cutoff, or clear the cutoff",
                whole_second(cutoff),
                policy.id.as_str()
            ),
        ),
        _ => (
            LIMIT_MAX_LIFETIME,
            format!(
                "the grant's deadline {asked} is later than the maximum lifetime of policy {} \
                 allows ({} s from this controller's clock: {}): ask for a shorter lifetime, \
                 or raise the policy's maximum lifetime",
                policy.id.as_str(),
                policy.max_window.as_secs(),
                whole_second(latest)
            ),
        ),
    };
    Some(heimdall_store::ext_effects::RefusedPending {
        grant: pending.grant.clone(),
        at: now,
        limit: limit.to_owned(),
        detail,
    })
}

fn policy_withdrawn() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the standing policy this controller recorded the grant under no longer authorizes \
         it: nothing is issued",
    )
    .with_effect(EffectStatus::None)
}

/// ⟨M06 W5⟩ For a record whose source is (b) ([`DeliveredGrant::policy`]): the policy
/// must still authorize every pair of the record now, and its cutoff bounds the
/// certificate. `Ok(None)`: a record of source (a), or no cutoff. Read in the caller's
/// transaction, so a pause, cutoff, narrowing or removal of the policy committed before
/// the reservation stops it.
///
/// # Errors
///
/// The store's (outer); [`policy_withdrawn`] (inner).
fn source_policy_bound(
    tx: &mut Txn<'_>,
    record: &DeliveredGrant,
    now: Timestamp,
) -> heimdall_store::Result<Result<Option<Timestamp>, OpError>> {
    Ok(source_policy_state(tx, record, now)?.map_err(|_| policy_withdrawn()))
}

/// [`source_policy_bound`] with the ledger's reason when the policy no longer authorizes
/// the record ⟨M08 W4 SEC-1, S1-01⟩: `CutoffPassed` when its cutoff has passed, else
/// `PausedActivation` (paused, removed, or no longer naming the runner or every pair).
///
/// # Errors
///
/// The store's (outer); the reason (inner).
fn source_policy_state(
    tx: &mut Txn<'_>,
    record: &DeliveredGrant,
    now: Timestamp,
) -> heimdall_store::Result<Result<Option<Timestamp>, IssuanceRefusal>> {
    let Some(id) = &record.policy else {
        return Ok(Ok(None));
    };
    Ok(match tx.policy(id)? {
        Some(p) if policy_authorizes(&p, &record.environment, &record.pairs, now) => {
            Ok(p.cutoff_at)
        }
        Some(p) if p.cutoff_at.is_some_and(|c| c <= now) => Err(IssuanceRefusal::CutoffPassed),
        _ => Err(IssuanceRefusal::PausedActivation),
    })
}

fn record_narrowed() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "this controller's record of the grant it delivered to the runner no longer covers \
         the signed certificate: nothing was released",
    )
    .with_effect(EffectStatus::None)
}

/// ⟨M08 W4 SEC-1, S1-01; ADR-0005 §3.5 step 3 and "Remote reservations" conditions 6–8⟩
/// This controller's own checks of a remote reservation, applied again in the
/// publication's transaction against the store as it is now (the reservation applied them
/// before the signature, which takes time):
///
/// * the record of the grant this controller delivered to the runner still exists and
///   still holds the reserved pair (the owner may have removed the runner, which forgets
///   it, or narrowed the record): `PairOutsideSnapshot` with `not_delivered()`. ⟨M08 W4
///   SEC-5, ruling 5⟩ `IssuanceRefusal` has no `NotDelivered` variant, and `Tombstoned`
///   specifically denotes a grant tombstone (`BarrierRefusal::GrantRevoked`) whereas
///   removing a runner (`RemoveEnvironment`) writes no grant tombstone and leaves runner
///   grants running to their bounds (ADR-0012 §8 item 3); keeping `PairOutsideSnapshot`
///   with `not_delivered()` avoids misstating revocation state while adding no new variant;
/// * it still holds the reserved extensions (`UnpermittedExtension`) and an expiry no
///   earlier than the certificate's `valid_before` (`BoundTooLate`);
/// * a record written from a standing policy is still authorized by it, a local `policy
///   pause` producing no outbox row for the runner: paused or withdrawn is
///   `PausedActivation`, a cutoff that passed is `CutoffPassed`, and a cutoff moved
///   before the certificate's `valid_before` is `BoundTooLate`.
///
/// A check that fails voids the reservation in this transaction (it then no longer counts,
/// and the certificate is never released) and returns the refusal. `None`: every check
/// holds, and the barrier judges next.
///
/// # Errors
///
/// The store's.
fn republish_checks(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    entry: &IssuanceEntry,
    now: Timestamp,
) -> heimdall_store::Result<Option<OpError>> {
    let refused = match tx.delivered_grant(environment, &entry.grant)? {
        None => Some((IssuanceRefusal::PairOutsideSnapshot, not_delivered())),
        Some(record) if !record.pairs.contains(&entry.pair) => {
            Some((IssuanceRefusal::PairOutsideSnapshot, not_delivered()))
        }
        Some(record) if !entry.bounds.extensions.is_subset(&record.extensions) => {
            Some((IssuanceRefusal::UnpermittedExtension, record_narrowed()))
        }
        Some(record) if entry.bounds.valid_before > record.expires_at => {
            Some((IssuanceRefusal::BoundTooLate, record_narrowed()))
        }
        Some(record) => match source_policy_state(tx, &record, now)? {
            Err(why) => Some((why, policy_withdrawn())),
            Ok(Some(cutoff)) if entry.bounds.valid_before > cutoff => {
                Some((IssuanceRefusal::BoundTooLate, policy_withdrawn()))
            }
            Ok(_) => None,
        },
    };
    let Some((why, error)) = refused else {
        return Ok(None);
    };
    if tx
        .issuance_entry(&entry.id)?
        .is_some_and(|e| e.state == IssuanceState::Reserved)
    {
        tx.void_issuance(&entry.id, &why, now)?;
    }
    Ok(Some(error))
}

/// ⟨M06 W4, W5; ADR-0005 §3.5 condition 8 (b); ADR-0012 §4 item 2 ⟨2026-11-21⟩⟩ Record
/// source (b). For every grant `report` lists as waiting for its issuer that this
/// controller holds no delivered record of: when one standing policy held **here** covers
/// it ([`covering_policy`]), write the delivered record from this controller's own policy:
/// the grant's pairs (all inside the policy's scope), the base extension profile, the
/// grant's deadline (no later than the policy allows), and the policy it came from. A
/// grant no policy here covers is left alone: it stays pending on the runner, whose
/// readiness reports the controller dependency. Returns the grants recorded.
///
/// # Errors
///
/// The store's.
pub fn adopt_under_standing_policy(
    tx: &mut Txn<'_>,
    pin: &RemoteEnvironmentPin,
    report: &AuthorityReport,
    now: Timestamp,
) -> heimdall_store::Result<Vec<GrantId>> {
    let mut adopted = Vec::new();
    let mut refused = Vec::new();
    if report.pending_grants.is_empty() || !role_may_issue(pin.role) {
        tx.set_refused_pending(&pin.environment, refused)?;
        return Ok(adopted);
    }
    let policies = tx.policies()?;
    for pending in &report.pending_grants {
        let revoked = report
            .tombstones
            .iter()
            .any(|t| t.grant == pending.grant || t.cascade.contains(&pending.grant));
        if revoked
            || tx
                .delivered_grant(&pin.environment, &pending.grant)?
                .is_some()
        {
            continue;
        }
        let Some(policy) = covering_policy(&policies, &pin.environment, pending, now) else {
            // Refused, not clamped; a deadline refusal names its limit for the owner.
            refused.extend(deadline_refusal(&policies, &pin.environment, pending, now));
            continue;
        };
        let extensions: BTreeSet<String> = [heimdall_domain::issuance::EXTENSION_PTY.to_owned()]
            .into_iter()
            .collect();
        if let Ok(mut record) = deliver_runner_grant(
            tx,
            pin,
            &pending.grant,
            &pending.pairs,
            &extensions,
            pending.expires_at,
            now,
        )? {
            record.policy = Some(policy.id.clone());
            tx.put_delivered_grant(&record)?;
            adopted.push(pending.grant.clone());
        }
    }
    tx.set_refused_pending(&pin.environment, refused)?;
    Ok(adopted)
}

// --- ⟨M06 W4⟩ the owner's acknowledgement of a lift ---------------------------------------

/// One pause or cutoff this controller produced for a runner ([`delivered_holds`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredHold {
    /// The effect.
    pub key: EffectKey,
    /// When the runner's acknowledgement of it was recorded; `None` while it is undelivered.
    pub delivered_at: Option<Timestamp>,
    /// When the owner acknowledged its lift on this controller, if they did.
    pub lift_acknowledged_at: Option<Timestamp>,
    /// Whether the runner's report this controller last read shows the effect lifted
    /// there, and when that report was read. `None`: no such report is recorded, or the
    /// effect is undelivered. An observation for the owner: the issuer's barrier judges on
    /// the report of its own open session.
    pub lift_reported: Option<LiftReported>,
}

/// What the last recorded report of a runner said about one delivered hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiftReported {
    /// Whether it showed the lift (`crate::remote_status_barrier::lift_shown`).
    pub shown: bool,
    /// When this controller read that report.
    pub at: Timestamp,
}

/// Every pause and cutoff this controller produced for the runner `environment`, in the
/// order produced: what `environment resume-issuance` shows the owner, who then names the
/// delivered ones to acknowledge.
///
/// # Errors
///
/// The store's.
pub fn delivered_holds(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
) -> heimdall_store::Result<Vec<DeliveredHold>> {
    let report = tx
        .remote_contact(environment)?
        .last_report
        .and_then(|r| r.revisions.map(|revisions| (r.at, revisions)));
    let mut out = Vec::new();
    for row in tx.remote_effect_outbox(Some(environment), false)? {
        if !matches!(
            row.key.target,
            EffectTarget::PolicyPause { .. } | EffectTarget::PolicyCutoff { .. }
        ) {
            continue;
        }
        let lift_acknowledged_at = tx.remote_lift_ack(&row.key)?;
        let delivered_at = row.ack.as_ref().and(row.acknowledged_at);
        let lift_reported = match (&report, delivered_at) {
            (Some((at, revisions)), Some(_)) => Some(LiftReported {
                shown: crate::remote_status_barrier::lift_shown_among(revisions, &row),
                at: *at,
            }),
            _ => None,
        };
        out.push(DeliveredHold {
            delivered_at,
            lift_acknowledged_at,
            lift_reported,
            key: row.key,
        });
    }
    Ok(out)
}

/// A hold in words, for the owner's confirmation and the command's output.
#[must_use]
pub fn hold_statement(hold: &DeliveredHold) -> String {
    match &hold.key.target {
        EffectTarget::PolicyPause { policy, .. } => format!("pause of policy {policy}"),
        EffectTarget::PolicyCutoff { scope, at, .. } => {
            let scope = heimdall_store::ext_effects::scope_key(scope)
                .unwrap_or_else(|| "an unknown scope".to_owned());
            format!("cutoff of {scope} at {at}")
        }
        _ => "an effect".to_owned(),
    }
}

/// ⟨M06 W4; ADR-0012 §7.4 ⟨2026-11-21⟩ on M06-W3-R02; ADR-0006 §18.8 item 4: "the
/// acknowledgement names the specific delivered effect and releases only that one; it never
/// pre-acknowledges a later cutoff"⟩ `controller_record.resume_issuance`: record the
/// owner's acknowledgement that **exactly the effects they were shown** (`named`, by effect
/// ID) were lifted at the runner `environment`. Only a delivered, not yet acknowledged
/// pause or cutoff of `environment` whose effect ID is in `named` gets a row. A pause or
/// cutoff delivered after the owner read the list (so not named) is left as it is and
/// keeps blocking: it is counted in `not_named`, and needs an acknowledgement of its own.
/// There is no environment-wide acknowledgement.
///
/// The rows alone reopen nothing: the issuer's barrier also needs the runner's report to
/// show each lift (`crate::remote_status_barrier`, "The way out is two-sided").
///
/// `attended`: whether the caller is the local owner in an attended session (the caller's
/// check of who it is; the typed confirmation is the CLI's). Answers `{environment,
/// acknowledged: [{effect, target}], already_acknowledged, undelivered, not_named}`.
///
/// # Errors
///
/// `INTERACTION_REQUIRED` unattended; `USAGE_ERROR` for an empty `named`; `NOT_FOUND` for
/// an environment this controller holds no record of, and for a named ID that is not a
/// delivered pause or cutoff this controller produced for `environment` (unknown, another
/// environment's, another kind of effect, or not yet delivered): the whole request is
/// refused and nothing is written, for any ID. `STATE_UNAVAILABLE` when the store fails.
/// Effect `none` in each case.
pub fn resume_issuance_named(
    store: &Store,
    environment: &EnvironmentId,
    named: &[heimdall_contract::ids::EffectId],
    attended: bool,
    now: Timestamp,
) -> Result<serde_json::Value, OpError> {
    if !attended {
        return Err(OpError::new(
            Code::InteractionRequired,
            "acknowledging a lift needs the owner in an attended session on this controller; \
             nothing was recorded",
        )
        .with_effect(EffectStatus::None));
    }
    if named.is_empty() {
        return Err(OpError::new(
            Code::UsageError,
            "an acknowledgement names the delivered effects it is for; none was named and \
             nothing was recorded",
        )
        .with_effect(EffectStatus::None));
    }
    enum Done {
        Unrecorded,
        NotDelivered,
        Written(Vec<serde_json::Value>, usize, usize, usize),
    }
    let done = store
        .transaction(|tx| {
            if pin_of(tx, environment)?.is_none() {
                return Ok(Done::Unrecorded);
            }
            let holds = delivered_holds(tx, environment)?;
            // Every named ID is a delivered pause or cutoff of this runner, or nothing is
            // written at all (the read is of this environment's outbox rows only, so an
            // ID of another environment is unknown here).
            if named.iter().any(|id| {
                !holds
                    .iter()
                    .any(|h| h.key.effect == *id && h.delivered_at.is_some())
            }) {
                return Ok(Done::NotDelivered);
            }
            let mut acknowledged = Vec::new();
            let (mut already, mut undelivered, mut not_named) = (0usize, 0usize, 0usize);
            for hold in holds {
                if hold.delivered_at.is_none() {
                    undelivered += 1;
                } else if hold.lift_acknowledged_at.is_some() {
                    already += 1;
                } else if !named.contains(&hold.key.effect) {
                    // Delivered, but not one the owner confirmed: it keeps blocking.
                    not_named += 1;
                } else if tx.acknowledge_remote_lift(environment, &hold.key, now)? {
                    acknowledged.push(serde_json::json!({
                        "effect": hold.key.effect,
                        "target": hold.key.target,
                    }));
                }
            }
            Ok(Done::Written(acknowledged, already, undelivered, not_named))
        })
        .map_err(|_| {
            OpError::new(
                Code::StateUnavailable,
                "the controller's lift acknowledgements cannot be written",
            )
            .with_effect(EffectStatus::None)
        })?;
    match done {
        Done::Unrecorded => Err(OpError::new(
            Code::NotFound,
            "this controller holds no record of that runner environment",
        )
        .with_effect(EffectStatus::None)),
        Done::NotDelivered => Err(OpError::new(
            Code::NotFound,
            "a named effect is not a pause or cutoff this controller delivered to that \
             runner environment; nothing was recorded",
        )
        .with_effect(EffectStatus::None)),
        Done::Written(acknowledged, already, undelivered, not_named) => Ok(serde_json::json!({
            "environment": environment,
            "acknowledged": acknowledged,
            "already_acknowledged": already,
            "undelivered": undelivered,
            "not_named": not_named,
        })),
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
pub(crate) fn key_id_environment(key_id: &str, grant: &GrantId) -> Option<EnvironmentId> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    // --- ⟨M06 W4 `w4c`⟩ the lift acknowledgement names its effect ------------------------

    use heimdall_contract::controller_record::{ManagementHop, ManagementRoute};
    use heimdall_contract::ids::{AccountName, DestinationId, EffectId, KeyFingerprint};
    use heimdall_store::ext_effects::{
        AppliedRecord, EffectAck, PolicyRevisionKind, PolicyRevisionRecord, ReportedPolicy,
    };

    use crate::remote_status_barrier::{BarrierRefusal, IssuancePermit, Reconciliation};

    /// A controller's store holding its record of one runner, and what the tests name.
    struct Lifts {
        store: Store,
        env: EnvironmentId,
        producer: ClientId,
        policy: PolicyId,
        grant: GrantId,
        barrier: IssuerBarrier,
    }

    fn lifts() -> Lifts {
        let store = Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap();
        let env = EnvironmentId::from_random_bytes([3; 16]);
        let producer = ClientId::from_random_bytes([1; 16]);
        let pin = RemoteEnvironmentPin {
            environment: env.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: "runner.example".into(),
                    port: None,
                    account: AccountName::parse("deploy").unwrap(),
                    host_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into()],
                },
                jump: None,
            },
            client: producer.clone(),
            role: Role::Owner,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "K".repeat(43))).unwrap(),
            label: None,
            pinned_at: at("2026-11-21T09:00:00Z"),
        };
        store
            .transaction(|tx| {
                tx.put_remote_environment_pin(
                    &pin.environment,
                    &pin.destination,
                    &pin.route.runner.account,
                    &pin.key_fingerprint,
                    &serde_json::to_string(&pin).unwrap(),
                    pin.pinned_at,
                )
            })
            .unwrap();
        Lifts {
            store,
            env,
            producer,
            policy: PolicyId::parse("pol").unwrap(),
            grant: GrantId::from_random_bytes([9; 16]),
            barrier: IssuerBarrier::default(),
        }
    }

    impl Lifts {
        /// A cutoff of the policy at `instant`, produced as effect `n`, revision `n`.
        fn cutoff(&self, n: u8, instant: &str) -> EffectKey {
            EffectKey {
                producer: self.producer.clone(),
                effect: EffectId::from_random_bytes([n; 16]),
                target: EffectTarget::PolicyCutoff {
                    scope: PolicyTarget::Policy {
                        policy_id: self.policy.clone(),
                    },
                    at: at(instant),
                    revision: u64::from(n),
                },
            }
        }

        /// A pause of the policy, produced as effect `n`, revision `n`.
        fn pause(&self, n: u8) -> EffectKey {
            EffectKey {
                producer: self.producer.clone(),
                effect: EffectId::from_random_bytes([n; 16]),
                target: EffectTarget::PolicyPause {
                    policy: self.policy.clone(),
                    revision: u64::from(n),
                },
            }
        }

        /// `key` produced here and delivered: the runner's acknowledgement recorded at `now`.
        fn deliver(&self, key: &EffectKey, now: &str) {
            self.deliver_to(&self.env, key, now);
        }

        /// [`Self::deliver`] for the runner `env`.
        fn deliver_to(&self, env: &EnvironmentId, key: &EffectKey, now: &str) {
            let cutoff_at = match &key.target {
                EffectTarget::PolicyCutoff { at, .. } => Some(*at),
                _ => None,
            };
            let ack = EffectAck {
                key: key.clone(),
                applied_at: at(now),
                record: AppliedRecord::PolicyRevision {
                    scope_key: heimdall_store::ext_effects::policy_scope_key(&self.policy),
                    runner_seq: key.target.generation(),
                    policies: vec![self.policy.clone()],
                    cutoff_at,
                    fired: cutoff_at.is_some(),
                },
            };
            self.store
                .transaction(|tx| {
                    assert!(tx.enqueue_remote_effect(env, key, at(now))?);
                    assert!(tx.acknowledge_remote_effect(&ack, at(now))?);
                    Ok(())
                })
                .unwrap();
        }

        /// The runner's durable record of the delivered effect `key`, as its report
        /// carries it, saying whether the effect is still in force there.
        fn row(key: &EffectKey, in_force: bool) -> PolicyRevisionRecord {
            let (scope, kind, cutoff_at) = match &key.target {
                EffectTarget::PolicyCutoff { scope, at, .. } => {
                    (scope.clone(), PolicyRevisionKind::Cutoff, Some(*at))
                }
                EffectTarget::PolicyPause { policy, .. } => (
                    PolicyTarget::Policy {
                        policy_id: policy.clone(),
                    },
                    PolicyRevisionKind::Pause,
                    None,
                ),
                _ => unreachable!("a pause or a cutoff"),
            };
            PolicyRevisionRecord {
                scope_key: heimdall_store::ext_effects::target_ref(&key.target).unwrap(),
                scope,
                producer: key.producer.clone(),
                revision: key.target.generation(),
                runner_seq: key.target.generation(),
                kind,
                effect: key.effect.clone(),
                received_at: at("2026-11-21T09:00:00Z"),
                cutoff_at,
                fired_uncertain_at: None,
                in_force,
            }
        }

        /// The runner's report of this session, read at `now`: the policy as it stands
        /// there (`paused`, `cutoff_at`), its time bounded. It carries the row of every
        /// effect delivered to the runner, each in force exactly while the policy is
        /// still blocked that way (the runner's owner lifts a pause by resuming the
        /// policy, a cutoff by clearing it).
        fn report(&self, paused: bool, cutoff_at: Option<&str>, now: &str) {
            let rows = self
                .store
                .transaction(|tx| tx.remote_effect_outbox(Some(&self.env), false))
                .unwrap()
                .iter()
                .filter(|e| e.ack.is_some())
                .map(|e| {
                    let in_force = match e.key.target {
                        EffectTarget::PolicyPause { .. } => paused,
                        _ => cutoff_at.is_some(),
                    };
                    Self::row(&e.key, in_force)
                })
                .collect();
            self.barrier.admit(Reconciliation {
                environment: self.env.clone(),
                at: at(now),
                report: AuthorityReport {
                    environment: self.env.clone(),
                    authority_generation: 1,
                    tombstones: Vec::new(),
                    policy_revisions: rows,
                    policies: vec![ReportedPolicy {
                        policy: self.policy.clone(),
                        revision: 1,
                        paused,
                        cutoff_at: cutoff_at.map(at),
                    }],
                    certificates: Vec::new(),
                    time_bounded: true,
                    pending_grants: Vec::new(),
                },
                revoked: Vec::new(),
                ignored_tombstones: 0,
            });
        }

        /// The barrier's answer for the grant under the policy at `now`.
        fn permit(&self, now: &str) -> Result<IssuancePermit, BarrierRefusal> {
            self.store
                .transaction(|tx| {
                    self.barrier.permit_answer(
                        tx,
                        &self.env,
                        &self.grant,
                        Some(&self.policy),
                        at(now),
                    )
                })
                .unwrap()
        }

        fn lift_ack(&self, key: &EffectKey) -> Option<Timestamp> {
            self.store
                .transaction(|tx| tx.remote_lift_ack(key))
                .unwrap()
        }
    }

    /// ⟨ADR-0006 §18.8 item 4⟩ A cutoff delivered after an acknowledgement still blocks.
    /// The first cutoff is lifted at the runner and acknowledged here, and issuance
    /// reopens. A second cutoff of the same policy is then delivered: it blocks, and it
    /// keeps blocking when the runner's report shows it lifted too, because the earlier
    /// acknowledgement named the first effect only. Naming the first effect again
    /// acknowledges nothing; only the second effect's own acknowledgement reopens.
    #[test]
    fn a_cutoff_delivered_after_an_acknowledgement_still_blocks() {
        let l = lifts();
        let first = l.cutoff(1, "2026-11-21T10:00:00Z");
        l.deliver(&first, "2026-11-21T10:00:01Z");
        // Lifted at the runner; acknowledged here, by name.
        l.report(false, None, "2026-11-21T10:05:00Z");
        assert_eq!(
            l.permit("2026-11-21T10:05:00Z"),
            Err(BarrierRefusal::PolicyCutoff),
            "the report alone reopens nothing"
        );
        let done = resume_issuance_named(
            &l.store,
            &l.env,
            std::slice::from_ref(&first.effect),
            true,
            at("2026-11-21T10:06:00Z"),
        )
        .unwrap();
        assert_eq!(done["acknowledged"].as_array().unwrap().len(), 1);
        assert_eq!(
            l.permit("2026-11-21T10:06:00Z"),
            Ok(IssuancePermit { bound: None })
        );

        // A later cutoff of the same policy, delivered after that acknowledgement.
        let second = l.cutoff(2, "2026-11-21T11:00:00Z");
        l.deliver(&second, "2026-11-21T11:00:01Z");
        assert_eq!(l.lift_ack(&second), None, "nothing acknowledged it ahead");
        l.report(false, Some("2026-11-21T11:00:00Z"), "2026-11-21T11:00:02Z");
        assert_eq!(
            l.permit("2026-11-21T11:00:02Z"),
            Err(BarrierRefusal::PolicyCutoff)
        );
        // Lifted at the runner as well: still blocked, the owner has not acknowledged it.
        l.report(false, None, "2026-11-21T11:05:00Z");
        assert_eq!(
            l.permit("2026-11-21T11:05:00Z"),
            Err(BarrierRefusal::PolicyCutoff),
            "the first effect's acknowledgement does not cover the second"
        );
        // Naming the first effect again releases nothing.
        let again = resume_issuance_named(
            &l.store,
            &l.env,
            std::slice::from_ref(&first.effect),
            true,
            at("2026-11-21T11:06:00Z"),
        )
        .unwrap();
        assert_eq!(again["acknowledged"], serde_json::json!([]));
        assert_eq!(again["already_acknowledged"], 1);
        assert_eq!(again["not_named"], 1);
        assert_eq!(l.lift_ack(&second), None);
        assert_eq!(
            l.permit("2026-11-21T11:06:00Z"),
            Err(BarrierRefusal::PolicyCutoff)
        );
        // Its own acknowledgement, with the lift the report shows, reopens.
        let done = resume_issuance_named(
            &l.store,
            &l.env,
            std::slice::from_ref(&second.effect),
            true,
            at("2026-11-21T11:07:00Z"),
        )
        .unwrap();
        assert_eq!(
            done["acknowledged"][0]["effect"],
            serde_json::json!(second.effect)
        );
        assert_eq!(
            l.permit("2026-11-21T11:07:00Z"),
            Ok(IssuancePermit { bound: None })
        );
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 4⟩ A runner with **no standing policy** stays blocked
    /// until its own owner lifts. A cutoff of every policy delivered to it (its
    /// acknowledgement names no policy; the runner keeps the revision row) is in force as
    /// long as the runner's report says so for **that effect**. The owner's
    /// acknowledgement alone reopens nothing, although the report lists no policy at all;
    /// the report alone reopens nothing either. Both keys are per effect: another effect's
    /// lift or acknowledgement releases nothing, a report without the effect's row shows
    /// no lift, and what the report lists as standing policies does not decide it.
    #[test]
    fn a_policy_less_runner_stays_blocked_until_its_own_owner_lifts() {
        let all = |l: &Lifts, n: u8, instant: &str| EffectKey {
            producer: l.producer.clone(),
            effect: EffectId::from_random_bytes([n; 16]),
            target: EffectTarget::PolicyCutoff {
                scope: PolicyTarget::All,
                at: at(instant),
                revision: u64::from(n),
            },
        };
        // Delivered: the runner's acknowledgement names `applied_to`, and it fired.
        let deliver = |l: &Lifts, key: &EffectKey, applied_to: &[PolicyId], now: &str| {
            let cutoff_at = match &key.target {
                EffectTarget::PolicyCutoff { at, .. } => Some(*at),
                _ => None,
            };
            let ack = EffectAck {
                key: key.clone(),
                applied_at: at(now),
                record: AppliedRecord::PolicyRevision {
                    scope_key: heimdall_store::ext_effects::target_ref(&key.target).unwrap(),
                    runner_seq: key.target.generation(),
                    policies: applied_to.to_vec(),
                    cutoff_at,
                    fired: cutoff_at.is_some(),
                },
            };
            l.store
                .transaction(|tx| {
                    assert!(tx.enqueue_remote_effect(&l.env, key, at(now))?);
                    assert!(tx.acknowledge_remote_effect(&ack, at(now))?);
                    Ok(())
                })
                .unwrap();
        };
        let report = |l: &Lifts,
                      policies: &[(&PolicyId, bool, Option<&str>)],
                      rows: Vec<PolicyRevisionRecord>,
                      now: &str| {
            l.barrier.admit(Reconciliation {
                environment: l.env.clone(),
                at: at(now),
                report: AuthorityReport {
                    environment: l.env.clone(),
                    authority_generation: 1,
                    tombstones: Vec::new(),
                    policy_revisions: rows,
                    policies: policies
                        .iter()
                        .map(|(policy, paused, cutoff_at)| ReportedPolicy {
                            policy: (*policy).clone(),
                            revision: 1,
                            paused: *paused,
                            cutoff_at: cutoff_at.map(at),
                        })
                        .collect(),
                    certificates: Vec::new(),
                    time_bounded: true,
                    pending_grants: Vec::new(),
                },
                revoked: Vec::new(),
                ignored_tombstones: 0,
            });
        };
        // The barrier's answer for a grant whose prepare answer names `policy`.
        let permit = |l: &Lifts, policy: Option<&PolicyId>, now: &str| {
            l.store
                .transaction(|tx| {
                    l.barrier
                        .permit_answer(tx, &l.env, &l.grant, policy, at(now))
                })
                .unwrap()
        };
        let acknowledge = |l: &Lifts, key: &EffectKey, now: &str| {
            let done = resume_issuance_named(
                &l.store,
                &l.env,
                std::slice::from_ref(&key.effect),
                true,
                at(now),
            )
            .unwrap();
            assert_eq!(done["acknowledged"].as_array().unwrap().len(), 1, "{done}");
        };
        let (in_force, lifted) = (
            |key: &EffectKey| Lifts::row(key, true),
            |key: &EffectKey| Lifts::row(key, false),
        );
        let open = Ok(IssuancePermit { bound: None });
        let cut = Err(BarrierRefusal::PolicyCutoff);

        // A runner used only through forwarded `ensure` holds no policy. Its report lists
        // none, and says the delivered cutoff is in force.
        let l = lifts();
        let cutoff = all(&l, 1, "2026-11-21T10:00:00Z");
        deliver(&l, &cutoff, &[], "2026-11-21T10:00:01Z");
        report(&l, &[], vec![in_force(&cutoff)], "2026-11-21T10:05:00Z");
        assert_eq!(permit(&l, None, "2026-11-21T10:05:00Z"), cut);
        // The owner's acknowledgement alone does not unblock it.
        acknowledge(&l, &cutoff, "2026-11-21T10:06:00Z");
        assert_eq!(
            permit(&l, None, "2026-11-21T10:06:00Z"),
            cut,
            "the owner's acknowledgement alone reopened a runner that reports the cutoff \
             in force"
        );
        assert_eq!(permit(&l, Some(&l.policy), "2026-11-21T10:06:00Z"), cut);
        // A report without the effect's row shows no lift either.
        report(&l, &[], Vec::new(), "2026-11-21T10:06:30Z");
        assert_eq!(permit(&l, None, "2026-11-21T10:06:30Z"), cut);
        // The runner's own owner lifted it: the report says so for that effect.
        report(&l, &[], vec![lifted(&cutoff)], "2026-11-21T10:07:00Z");
        assert_eq!(permit(&l, None, "2026-11-21T10:07:00Z"), open);
        assert_eq!(permit(&l, Some(&l.policy), "2026-11-21T10:07:00Z"), open);
        // A later cutoff of every policy has its own key and its own flag: the first
        // effect's lift and acknowledgement release nothing of it.
        let later = all(&l, 2, "2026-11-21T11:00:00Z");
        deliver(&l, &later, &[], "2026-11-21T11:00:01Z");
        report(
            &l,
            &[],
            vec![lifted(&cutoff), in_force(&later)],
            "2026-11-21T11:00:02Z",
        );
        assert_eq!(permit(&l, None, "2026-11-21T11:00:02Z"), cut);
        acknowledge(&l, &later, "2026-11-21T11:00:03Z");
        assert_eq!(permit(&l, None, "2026-11-21T11:00:03Z"), cut);
        report(
            &l,
            &[],
            vec![lifted(&cutoff), lifted(&later)],
            "2026-11-21T11:00:04Z",
        );
        assert_eq!(permit(&l, None, "2026-11-21T11:00:04Z"), open);

        // The report alone reopens nothing: lifted at the runner, not acknowledged here.
        let l = lifts();
        let cutoff = all(&l, 1, "2026-11-21T10:00:00Z");
        deliver(&l, &cutoff, &[], "2026-11-21T10:00:01Z");
        report(&l, &[], vec![lifted(&cutoff)], "2026-11-21T10:05:00Z");
        assert_eq!(
            permit(&l, None, "2026-11-21T10:05:00Z"),
            cut,
            "the report alone reopens nothing"
        );

        // What the report lists as standing policies does not decide the lift: a policy
        // listed with no cutoff, while the runner says the effect is in force.
        let l = lifts();
        let cutoff = all(&l, 1, "2026-11-21T10:00:00Z");
        deliver(
            &l,
            &cutoff,
            std::slice::from_ref(&l.policy),
            "2026-11-21T10:00:01Z",
        );
        acknowledge(&l, &cutoff, "2026-11-21T10:06:00Z");
        report(
            &l,
            &[(&l.policy, false, None)],
            vec![in_force(&cutoff)],
            "2026-11-21T10:07:00Z",
        );
        assert_eq!(permit(&l, Some(&l.policy), "2026-11-21T10:07:00Z"), cut);
        report(
            &l,
            &[(&l.policy, false, None)],
            vec![lifted(&cutoff)],
            "2026-11-21T10:08:00Z",
        );
        assert_eq!(permit(&l, Some(&l.policy), "2026-11-21T10:08:00Z"), open);
    }

    /// ⟨ADR-0006 §18.8 item 4⟩ The acknowledgement releases only the effect it names. The
    /// owner is shown a delivered pause; a cutoff is delivered before the confirmation is
    /// written. The named acknowledgement records the pause only: the cutoff has no row
    /// and keeps blocking once both lifts show. Unattended, with no ID, or with an ID that
    /// is no delivered pause or cutoff of this runner (unknown, another runner's, not yet
    /// delivered), the whole request is refused and nothing is written.
    #[test]
    fn a_named_acknowledgement_releases_only_the_effect_it_names() {
        let l = lifts();
        let pause = l.pause(1);
        l.deliver(&pause, "2026-11-21T10:00:01Z");
        // What the owner was shown: the pause. Then a cutoff arrives.
        let shown = vec![pause.effect.clone()];
        let cutoff = l.cutoff(2, "2026-11-21T10:01:00Z");
        l.deliver(&cutoff, "2026-11-21T10:01:01Z");
        let undelivered = l.pause(3);
        l.store
            .transaction(|tx| {
                tx.enqueue_remote_effect(&l.env, &undelivered, at("2026-11-21T10:01:02Z"))
            })
            .unwrap();
        // Another runner this controller records, with a delivered cutoff of its own.
        let other = EnvironmentId::from_random_bytes([4; 16]);
        let pin = l
            .store
            .transaction(|tx| pin_of(tx, &l.env))
            .unwrap()
            .map(|p| RemoteEnvironmentPin {
                environment: other.clone(),
                destination: DestinationId::parse("runner2").unwrap(),
                ..p
            })
            .unwrap();
        l.store
            .transaction(|tx| {
                tx.put_remote_environment_pin(
                    &pin.environment,
                    &pin.destination,
                    &pin.route.runner.account,
                    &pin.key_fingerprint,
                    &serde_json::to_string(&pin).unwrap(),
                    pin.pinned_at,
                )
            })
            .unwrap();
        let elsewhere = l.cutoff(8, "2026-11-21T10:01:30Z");
        l.deliver_to(&other, &elsewhere, "2026-11-21T10:01:31Z");
        let stranger = l.cutoff(9, "2026-11-21T10:02:00Z");

        let now = at("2026-11-21T10:02:00Z");
        let e = resume_issuance_named(&l.store, &l.env, &shown, false, now).unwrap_err();
        assert_eq!(e.code, Code::InteractionRequired);
        let e = resume_issuance_named(&l.store, &l.env, &[], true, now).unwrap_err();
        assert_eq!(e.code, Code::UsageError, "an empty list");
        assert_eq!(e.effect_status, EffectStatus::None);
        // Each named beside the pause the owner was shown: the pause gets no row either.
        for (bad, why) in [
            (&stranger, "an unknown ID"),
            (&elsewhere, "another environment's effect"),
            (&undelivered, "an effect not yet delivered"),
        ] {
            let named = [shown.clone(), vec![bad.effect.clone()]].concat();
            let e = resume_issuance_named(&l.store, &l.env, &named, true, now).unwrap_err();
            assert_eq!(e.code, Code::NotFound, "{why}");
            assert_eq!(e.effect_status, EffectStatus::None, "{why}");
            for key in [&pause, &cutoff, &undelivered, &elsewhere, &stranger] {
                assert_eq!(l.lift_ack(key), None, "{why}: nothing was written");
            }
        }

        let done = resume_issuance_named(&l.store, &l.env, &shown, true, now).unwrap();
        assert_eq!(
            done["acknowledged"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["effect"].clone())
                .collect::<Vec<_>>(),
            [serde_json::json!(pause.effect)]
        );
        assert_eq!(done["not_named"], 1, "the cutoff the owner was not shown");
        assert_eq!(done["undelivered"], 1);
        assert!(done.get("unknown").is_none());
        assert!(l.lift_ack(&pause).is_some());
        assert_eq!(l.lift_ack(&cutoff), None);
        assert_eq!(l.lift_ack(&undelivered), None);
        assert_eq!(l.lift_ack(&elsewhere), None);

        // All lifted at the runner (the third effect delivered meanwhile): the cutoff
        // blocks.
        l.store
            .transaction(|tx| {
                let ack = EffectAck {
                    key: undelivered.clone(),
                    applied_at: at("2026-11-21T10:03:00Z"),
                    record: AppliedRecord::PolicyRevision {
                        scope_key: heimdall_store::ext_effects::policy_scope_key(&l.policy),
                        runner_seq: 3,
                        policies: vec![l.policy.clone()],
                        cutoff_at: None,
                        fired: false,
                    },
                };
                tx.acknowledge_remote_effect(&ack, at("2026-11-21T10:03:00Z"))
            })
            .unwrap();
        l.report(false, None, "2026-11-21T10:05:00Z");
        assert_eq!(
            l.permit("2026-11-21T10:05:00Z"),
            Err(BarrierRefusal::PolicyCutoff),
            "the cutoff the owner was not shown was never acknowledged"
        );
    }

    /// ⟨M06 W4⟩ A certificate issued in the same second its grant was delivered (a
    /// forwarded `ensure`: asked, recorded and issued within milliseconds) stays inside the
    /// issuer's validity ceiling, which is the delivered window plus the 60 s skew.
    /// `valid_after` rounded **down** made the span up to a second longer than that, and
    /// the issuer refused the first issue; rounded up it never is.
    #[test]
    fn a_certificate_issued_right_after_delivery_stays_inside_the_delivered_window() {
        let asked = at("2026-11-21T09:00:00.100Z");
        let expires = at("2026-11-21T10:00:00.100Z"); // asked + 1 h
        let delivered = at("2026-11-21T09:00:00.150Z");
        let issued = at("2026-11-21T09:00:00.400Z");
        assert!(asked < delivered && delivered < issued);
        let skew = jiff::SignedDuration::try_from(VALID_AFTER_SKEW).unwrap();
        let ceiling = expires.duration_since(delivered) + skew;
        let valid_before = whole_second(expires);
        let from = issued.checked_sub(skew).unwrap();
        // The defect: rounding down overshoots the ceiling.
        assert!(valid_before.duration_since(whole_second(from)) > ceiling);
        // The fix: rounding up never does.
        assert!(valid_before.duration_since(whole_second_up(from)) <= ceiling);
        assert_eq!(whole_second_up(from), at("2026-11-21T08:59:01Z"));
        // A whole second is left alone.
        let whole = at("2026-11-21T08:59:01Z");
        assert_eq!(whole_second_up(whole), whole);
    }
}
