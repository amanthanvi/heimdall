//! ⟨M03⟩ U0b row 5 (G): per-signature authorization, `Operations` as the
//! [`SignatureAuthority`] (ADR-0008 D2 items 3 and 3a; §17.4 item 6, §17.10 item 1).
//!
//! * [`SignatureAuthority::precheck`] takes no gate: the pending mark, then the same
//!   predicates as `admit` in one read. An optimization only; it never admits.
//! * [`SignatureAuthority::admit`] takes the grant's gate **shared** within
//!   `signing_gate_wait` (`SigningGates::admit_shared`), whose **first** check, right
//!   after the awaited acquisition and before any store read, is the pending mark. Then
//!   one fresh store transaction checks every D2 item 3 predicate (the authorization
//!   time through the [`AuthorizationTime`] seam), and the [`SignPermit`] carries the
//!   absolute expiry: the earliest of the wall bound, the continuous budget's end, the
//!   admission limits (the bound includes every applicable cutoff and every ancestor's
//!   deadline) and the holder bound (`signing_holder_max` from this step's start),
//!   each an absolute tokio instant mapped through one paired clock observation taken
//!   before the read (§17.16, R4): the read's latency never extends a bound, and a
//!   bound that ended during the read refuses.
//!   The permit's release check (`SignPermit::may_release`) repeats the pending mark,
//!   the expiry on both clocks and safe time. The whole call is bounded by
//!   `signature_authorization_timeout`.
//!
//! **Verification signatures** (⟨M03 wave 4⟩ ADR-0008 D2 item 3 "for verification,
//! the D5 §6.5 predicate"; §17.19 item 5, INT-Q13 option (a)). A K_verify signature
//! is admitted only through its operation's **verification gate**
//! (`SigningGates::admit_verification`; opened when the verification endpoint is
//! created with the plan, closed when the session drops): no gate, a closed gate, or
//! an endpoint other than the operation's own refuses `key_not_served`. Under the
//! gate, one fresh store transaction (time assessed inside it, as for a grant) finds
//! the operation's **published positive** verification entry for exactly the
//! presented K_verify, the request's pair, and the gate's (the plan's) CA and pair,
//! within its validity, and re-runs `verification::check` over it
//! (`verification_check_read_only`: the operation is an authorized `enrollment.apply`
//! or `enrollment.verify` at its verification stage, the pair and CA are the plan's,
//! time `Safe`, …). The permit's wall bound is the entry's `valid_before`; its release
//! check also refuses once the gate is closed. Nothing here is ungated
//! (`heimdall_credential::signer::VERIFICATION_UNGATED_SIGNING` stays `false`).
//!
//! The time seam (integrator reading; questions file G-Q3): [`AuthorizationTime::Peek`]
//! evaluates the gate's rules over the authorization's own transaction, persisting
//! nothing; [`AuthorizationTime::ReadOnly`] is `TimeGate::assess_read_only` (U3), the
//! default since wave 2 (ADR-0008 §17.15 item 8). The
//! release check's in-memory assessment is relative to the admitted observation: the
//! same boot, a continuous clock that did not go back, and wall progress within the
//! skew tolerance of continuous progress (G-Q4).

use std::sync::{Arc, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::ids::{GrantId, OperationId};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::issuance::IssuanceState;
use heimdall_domain::managed::SlotState;
use heimdall_domain::time::{self as dtime, Admission, Clock, GateInput, TimeAnchor, TimeStatus};
use heimdall_domain::verification::VerificationPurpose;
use heimdall_store::Txn;
use tokio::time::Instant;

use super::lock::effective_lock_behavior;
use super::narrowing::AuthorizationTime;
use super::{
    Operations, bound_of, grant_context, mechanism_refuses, plus, revalidate_chain,
    verification_check_read_only,
};
use crate::managed::{
    GateError, PermitExpiry, SafeTime, SignPermit, SigningGates, VerificationScope,
};
use crate::ports::{
    LockState, SessionLockSource, SignRefusal, SignatureAuthority, SignatureRequestFacts,
    SignatureSubject, SignerEndpoint,
};
use crate::timegate::SafeNow;

/// What a passing authorization read found.
struct Authorized {
    safe: SafeNow,
    bound: Timestamp,
    /// The grant anchor's continuous budget end, in the admitted observation's boot.
    budget_end: Option<Duration>,
}

/// The time gate's assessment over `tx`, persisting nothing (`AuthorizationTime::Peek`).
fn assess_in(
    tx: &mut Txn<'_>,
    clock: &dyn Clock,
    sync: &dyn dtime::TimeSync,
    policy: &dtime::TimePolicy,
) -> heimdall_store::Result<Option<SafeNow>> {
    let previous = tx.runtime_anchor()?;
    let high_water = tx.high_water_mark()?;
    let now = clock.observe();
    let sync = sync.status();
    let confirmation = tx.time_confirmation()?.filter(|c| c.boot_id == now.boot_id);
    let input = GateInput {
        previous: previous.as_ref(),
        high_water,
        now: &now,
        sync,
        confirmation: confirmation.as_ref(),
        policy,
    };
    let status = dtime::gate(&input);
    let tolerance_used = dtime::accepted_tolerance(&input);
    Ok(match status {
        TimeStatus::Safe => Some(SafeNow {
            anchor: now,
            sync,
            tolerance_used,
        }),
        TimeStatus::Uncertain(_) => None,
    })
}

/// The release check's in-memory time assessment (never blocks, never reads the
/// store): relative to the admitted `Safe` observation.
struct AdmittedTime {
    clock: Arc<dyn Clock>,
    admitted: TimeAnchor,
    skew: Duration,
}

impl SafeTime for AdmittedTime {
    fn safe_wall_now(&self) -> Option<Timestamp> {
        let now = self.clock.observe();
        if now.boot_id != self.admitted.boot_id || now.continuous < self.admitted.continuous {
            return None;
        }
        let continuous = now.continuous.saturating_sub(self.admitted.continuous);
        let wall = Duration::try_from(now.wall.duration_since(self.admitted.wall)).ok()?;
        let drift = wall.abs_diff(continuous);
        (drift <= self.skew).then_some(now.wall)
    }
}

impl Operations {
    /// ⟨M03⟩ U0b rows 5 and 25: the session-lock source the per-signature check reads
    /// (`revoke_on_lock` grants need `unlocked`). Without one, such grants are refused
    /// (fail closed). The runtime installs U9's source.
    pub fn set_session_lock_source(&self, source: Arc<dyn SessionLockSource>) {
        *self
            .inner
            .narrowing
            .lock_source
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(source);
    }

    /// ⟨M03⟩ U0b row 5: where `admit` takes its time assessment ([`AuthorizationTime`];
    /// default `ReadOnly` since wave 2, ADR-0008 §17.15 item 8).
    pub fn set_authorization_time(&self, mode: AuthorizationTime) {
        *self
            .inner
            .narrowing
            .authorization_time
            .write()
            .unwrap_or_else(PoisonError::into_inner) = mode;
    }

    /// The session-lock state now (`unknown` without a source).
    pub(super) fn lock_state(&self) -> LockState {
        self.inner
            .narrowing
            .lock_source
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or(LockState::Unknown, |s| s.state())
    }

    /// One fresh authorization read (ADR-0008 D2 item 3): the time assessment, then
    /// every predicate, in one store transaction.
    async fn authorization_read(
        &self,
        facts: &SignatureRequestFacts,
        grant: &GrantId,
    ) -> Result<Authorized, SignRefusal> {
        let mode = *self
            .inner
            .narrowing
            .authorization_time
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let clock = Arc::clone(&self.inner.config.clock);
        let sync = Arc::clone(&self.inner.config.time_sync);
        let policy = self.inner.config.time_policy;
        let env = self.environment().clone();
        let adapters = self.adapter_infos();
        let gate = self.inner.timegate.in_txn();
        let lock = self.lock_state();
        // ⟨U9⟩ R3: the configured floor joins the effective behaviour.
        let floor = self.session_lock_floor();
        let endpoint = facts.endpoint.clone();
        let pair = facts.pair.clone();
        let gid = grant.clone();
        self.write(move |tx, _| {
            // ⟨§17.19 item 1, W2-R01⟩ The time verdict and the observation it judged are
            // one: both seams assess inside this transaction, and `safe` is built from
            // the assessed observation itself, never from a later `observe()`.
            let assessed = match mode {
                AuthorizationTime::ReadOnly => gate.assess_read_only(tx)?.2,
                _ => assess_in(tx, clock.as_ref(), sync.as_ref(), &policy)?,
            };
            let Some(safe) = assessed else {
                return Ok(Err(SignRefusal::TimeUncertain));
            };
            let Some(g) = tx.grant(&gid)? else {
                return Ok(Err(SignRefusal::KeyNotServed));
            };
            let served = match &endpoint {
                SignerEndpoint::Binding(b) => tx.binding(b)?.is_some_and(|rec| {
                    rec.grant == gid && rec.environment == env && rec.released_at.is_none()
                }),
                // ⟨integrator, wave-2 review⟩ D10 items 2–3: the environment endpoint
                // serves a pair only while one of the grant's unreleased bindings
                // **holds** that pair's slot here (a `clearing` slot is unlisted at
                // once). The fresh read checks it, not only the in-memory listing.
                SignerEndpoint::Environment => {
                    let mut served = false;
                    for r in tx.grant_references(&gid)? {
                        if let Some(b) = tx.binding(&r.binding)?
                            && b.grant == gid
                            && b.environment == env
                            && b.released_at.is_none()
                            && tx.slots_for_binding(&b.id)?.iter().any(|slot| {
                                slot.environment == env
                                    && slot.pair == pair
                                    && matches!(
                                        &slot.state,
                                        SlotState::Held { binding, .. } if *binding == b.id
                                    )
                            })
                        {
                            served = true;
                            break;
                        }
                    }
                    served
                }
                // The D5 §6.5 verification predicate is U5's; a grant's key is never
                // served by a verification endpoint.
                _ => false,
            };
            if !served {
                return Ok(Err(SignRefusal::KeyNotServed));
            }
            if tx.denied_ancestor(&gid)?.is_some() {
                return Ok(Err(SignRefusal::Tombstoned));
            }
            match g.state {
                GrantState::Active => {}
                GrantState::Degraded => {
                    if !tx
                        .grant_degradation(&gid)?
                        .is_some_and(|r| r.permits_signing())
                    {
                        return Ok(Err(SignRefusal::GrantNotUsable));
                    }
                }
                _ => return Ok(Err(SignRefusal::GrantNotUsable)),
            }
            let ctx = grant_context(tx, &g)?;
            let bound = bound_of(tx, &env, &g, ctx.profile.as_ref())?;
            if dtime::is_expired(safe.wall(), bound)
                || gate.admission(tx, &gid, &safe)? != Admission::Open
            {
                return Ok(Err(SignRefusal::DeadlinePassed));
            }
            if mechanism_refuses(tx, &adapters, &g)? {
                return Ok(Err(SignRefusal::MechanismNotConfigured));
            }
            // ADR-0006 §13.5 ruling 2: a moved generation re-validates automatically.
            if revalidate_chain(tx, &env, &adapters, &g, safe.wall())?.is_err() {
                return Ok(Err(SignRefusal::StaleGeneration));
            }
            if effective_lock_behavior(tx, &env, &g, ctx.profile.as_ref(), floor)?
                == LockBehavior::RevokeOnLock
                && lock != LockState::Unlocked
            {
                return Ok(Err(SignRefusal::SessionNotUnlocked));
            }
            let budget_end = tx
                .grant_anchor(&gid)?
                .filter(|a| a.anchor.boot_id == safe.anchor.boot_id)
                .map(|a| a.budget_end);
            Ok(Ok(Authorized {
                safe,
                bound,
                budget_end,
            }))
        })
        .await
        .map_err(|_| SignRefusal::Unavailable)?
    }

    /// ⟨INT-Q13⟩ One fresh verification read (module docs): the time assessment,
    /// then the operation's published positive entry for this K_verify under the
    /// gate's CA and pair, re-checked by `verification::check`, in one transaction.
    async fn verification_read(
        &self,
        facts: &SignatureRequestFacts,
        operation: &OperationId,
        scope: &VerificationScope,
    ) -> Result<Authorized, SignRefusal> {
        let mode = *self
            .inner
            .narrowing
            .authorization_time
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let clock = Arc::clone(&self.inner.config.clock);
        let sync = Arc::clone(&self.inner.config.time_sync);
        let policy = self.inner.config.time_policy;
        let gate = self.inner.timegate.in_txn();
        let max_validity = self.inner.config.limits.verification_max_validity;
        let op = operation.clone();
        let scope = scope.clone();
        let pair = facts.pair.clone();
        let key = facts.key_fingerprint.clone();
        self.write(move |tx, _| {
            let assessed = match mode {
                AuthorizationTime::ReadOnly => gate.assess_read_only(tx)?.2,
                _ => assess_in(tx, clock.as_ref(), sync.as_ref(), &policy)?,
            };
            let Some(safe) = assessed else {
                return Ok(Err(SignRefusal::TimeUncertain));
            };
            if pair != scope.pair {
                return Ok(Err(SignRefusal::KeyNotServed));
            }
            let now = safe.wall();
            let entry = tx.verification_entries(&op)?.into_iter().find(|e| {
                e.state == IssuanceState::Published
                    && e.purpose == VerificationPurpose::Positive
                    && e.operation == op
                    && e.pair == scope.pair
                    && e.bounds.ca_fingerprint.as_ref() == Some(&scope.ca)
                    && e.bounds.subject_fingerprint == key
                    && e.bounds.valid_after <= now
                    && now < e.bounds.valid_before
            });
            let Some(entry) = entry else {
                return Ok(Err(SignRefusal::KeyNotServed));
            };
            if let Err(refused) =
                verification_check_read_only(tx, &entry, true, TimeStatus::Safe, now, max_validity)?
            {
                return Ok(Err(SignRefusal::Verification(refused)));
            }
            Ok(Ok(Authorized {
                safe,
                bound: entry.bounds.valid_before,
                budget_end: None,
            }))
        })
        .await
        .map_err(|_| SignRefusal::Unavailable)?
    }

    /// ⟨INT-Q13⟩ The permit's expiry from a passing read (§17.16, R4): the earliest
    /// of the holder bound, the wall bound and the continuous budget, each mapped
    /// through the step's one paired observation.
    fn permit_expiry(
        &self,
        step_start: Instant,
        paired: &TimeAnchor,
        auth: &Authorized,
    ) -> Result<(PermitExpiry, Arc<dyn SafeTime>), SignRefusal> {
        let limits = *self.limits();
        if auth.safe.anchor.boot_id != paired.boot_id {
            return Err(SignRefusal::TimeUncertain);
        }
        // The instant at which the continuous clock reads `c`, and the wall clock `w`.
        let at_continuous = |c: Duration| step_start + c.saturating_sub(paired.continuous);
        let at_wall = |w: Timestamp| {
            step_start + Duration::try_from(w.duration_since(paired.wall)).unwrap_or(Duration::ZERO)
        };
        let mut continuous = (step_start + limits.signing_holder_max).min(at_wall(auth.bound));
        if let Some(end) = auth.budget_end {
            continuous = continuous.min(at_continuous(end));
        }
        // A bound that ended while the authorization ran refuses here.
        if continuous <= Instant::now() {
            return Err(SignRefusal::DeadlinePassed);
        }
        let wall = auth.bound.min(plus(
            paired.wall,
            continuous.saturating_duration_since(step_start),
        ));
        let time: Arc<dyn SafeTime> = Arc::new(AdmittedTime {
            clock: Arc::clone(&self.inner.config.clock),
            admitted: auth.safe.anchor.clone(),
            skew: self.inner.config.time_policy.max_tolerated_skew,
        });
        Ok((PermitExpiry::new(wall, continuous), time))
    }

    /// ⟨INT-Q13⟩ `admit` for a verification subject (module docs).
    async fn admit_verification_signature(
        &self,
        facts: &SignatureRequestFacts,
        operation: &OperationId,
    ) -> Result<SignPermit, SignRefusal> {
        // The key belongs to its own operation's endpoint only.
        if facts.endpoint != SignerEndpoint::Verification(operation.clone()) {
            return Err(SignRefusal::KeyNotServed);
        }
        let limits = *self.limits();
        let shared = self
            .signing_gates()
            .admit_verification(operation, limits.signing_gate_wait)
            .await
            .map_err(|e| match e {
                GateError::NoGate => SignRefusal::KeyNotServed,
                GateError::Timeout => SignRefusal::GateTimeout,
                _ => SignRefusal::Unavailable,
            })?;
        let step_start = Instant::now();
        let paired = self.inner.config.clock.observe();
        let auth = self
            .verification_read(facts, operation, shared.scope())
            .await?;
        // The gate closed while the read ran: refuse (dropping `shared` releases it).
        if !shared.is_open() {
            return Err(SignRefusal::KeyNotServed);
        }
        let (expiry, time) = self.permit_expiry(step_start, &paired, &auth)?;
        Ok(SigningGates::permit_verification(shared, expiry, time))
    }

    async fn admit_signature(
        &self,
        facts: &SignatureRequestFacts,
    ) -> Result<SignPermit, SignRefusal> {
        let gid = match &facts.subject {
            SignatureSubject::Grant(gid) => gid,
            SignatureSubject::Verification(op) => {
                return self.admit_verification_signature(facts, op).await;
            }
        };
        let limits = *self.limits();
        // Already marked: refuse without queueing behind the narrowing (the pre-check's
        // test, repeated here because a caller may skip the pre-check).
        if self.signing_gates().is_pending(gid) {
            return Err(SignRefusal::NarrowingPending);
        }
        // Steps 3–4: the gate shared, then the pending mark first (no store read yet).
        let shared = self
            .signing_gates()
            .admit_shared(gid, limits.signing_gate_wait)
            .await
            .map_err(|e| match e {
                GateError::NoGate => SignRefusal::KeyNotServed,
                GateError::Timeout => SignRefusal::GateTimeout,
                GateError::Pending => SignRefusal::NarrowingPending,
                _ => SignRefusal::Unavailable,
            })?;
        // ⟨§17.16, R4⟩ One paired observation at the step's start, before the
        // admission read: the tokio instant and the operations clock (wall and
        // continuous) read together. Every expiry is mapped onto the tokio clock through
        // this pair, so the authorization's own latency never extends a bound, and the
        // holder bound runs from here.
        let step_start = Instant::now();
        let paired = self.inner.config.clock.observe();
        // The fresh read under the gate (dropping `shared` on refusal releases it).
        let auth = self.authorization_read(facts, gid).await?;
        let (expiry, time) = self.permit_expiry(step_start, &paired, &auth)?;
        Ok(SigningGates::permit(shared, expiry, time))
    }
}

#[async_trait]
impl SignatureAuthority for Operations {
    async fn precheck(&self, facts: &SignatureRequestFacts) -> Result<(), SignRefusal> {
        let bound = self.limits().signature_authorization_timeout;
        let gid = match &facts.subject {
            SignatureSubject::Grant(gid) => gid,
            // ⟨INT-Q13⟩ No gate is taken: the gate's open state, then the same read.
            SignatureSubject::Verification(op) => {
                if facts.endpoint != SignerEndpoint::Verification(op.clone()) {
                    return Err(SignRefusal::KeyNotServed);
                }
                let Some(scope) = self.signing_gates().verification_scope(op) else {
                    return Err(SignRefusal::KeyNotServed);
                };
                return match tokio::time::timeout(bound, self.verification_read(facts, op, &scope))
                    .await
                {
                    Ok(r) => r.map(|_| ()),
                    Err(_) => Err(SignRefusal::AuthorizationTimeout),
                };
            }
        };
        if self.signing_gates().is_pending(gid) {
            return Err(SignRefusal::NarrowingPending);
        }
        match tokio::time::timeout(bound, self.authorization_read(facts, gid)).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(SignRefusal::AuthorizationTimeout),
        }
    }

    async fn admit(&self, facts: &SignatureRequestFacts) -> Result<SignPermit, SignRefusal> {
        let bound = self.limits().signature_authorization_timeout;
        match tokio::time::timeout(bound, self.admit_signature(facts)).await {
            Ok(r) => r,
            Err(_) => Err(SignRefusal::AuthorizationTimeout),
        }
    }
}
