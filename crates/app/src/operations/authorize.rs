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
//!   deadline) and the holder bound (`signing_holder_max` from this step's start).
//!   The permit's release check (`SignPermit::may_release`) repeats the pending mark,
//!   the expiry on both clocks and safe time. The whole call is bounded by
//!   `signature_authorization_timeout`.
//!
//! The time seam (integrator reading; questions file G-Q3): [`AuthorizationTime::Peek`]
//! evaluates the gate's rules over the authorization's own transaction, persisting
//! nothing; [`AuthorizationTime::ReadOnly`] is `TimeGate::assess_read_only` (U3). The
//! release check's in-memory assessment is relative to the admitted observation: the
//! same boot, a continuous clock that did not go back, and wall progress within the
//! skew tolerance of continuous progress (G-Q4).

use std::sync::{Arc, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::ids::GrantId;
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::time::{self as dtime, Admission, Clock, GateInput, TimeAnchor, TimeStatus};
use heimdall_store::Txn;
use tokio::time::Instant;

use super::lock::effective_lock_behavior;
use super::narrowing::AuthorizationTime;
use super::{Operations, bound_of, grant_context, mechanism_refuses, plus, revalidate_chain};
use crate::managed::{GateError, PermitExpiry, SafeTime, SignPermit, SigningGates};
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
    /// default `Peek`). U3 switches it once `TimeGate::assess_read_only` has its body.
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
        let pre: Option<SafeNow> = match mode {
            AuthorizationTime::ReadOnly => {
                let me = self.clone();
                let status = tokio::task::spawn_blocking(move || {
                    me.inner.timegate.assess_read_only(&me.inner.config.store)
                })
                .await
                .map_err(|_| SignRefusal::Unavailable)?;
                if status != TimeStatus::Safe {
                    return Err(SignRefusal::TimeUncertain);
                }
                Some(SafeNow {
                    anchor: clock.observe(),
                    sync: sync.status(),
                    tolerance_used: Duration::ZERO,
                })
            }
            _ => None,
        };
        let env = self.environment().clone();
        let adapters = self.adapter_infos();
        let gate = self.inner.timegate.in_txn();
        let lock = self.lock_state();
        let endpoint = facts.endpoint.clone();
        let gid = grant.clone();
        self.write(move |tx, _| {
            let safe = match pre {
                Some(s) => s,
                None => match assess_in(tx, clock.as_ref(), sync.as_ref(), &policy)? {
                    Some(s) => s,
                    None => return Ok(Err(SignRefusal::TimeUncertain)),
                },
            };
            let Some(g) = tx.grant(&gid)? else {
                return Ok(Err(SignRefusal::KeyNotServed));
            };
            let served = match &endpoint {
                SignerEndpoint::Binding(b) => tx.binding(b)?.is_some_and(|rec| {
                    rec.grant == gid && rec.environment == env && rec.released_at.is_none()
                }),
                SignerEndpoint::Environment => {
                    let mut served = false;
                    for r in tx.grant_references(&gid)? {
                        if let Some(b) = tx.binding(&r.binding)?
                            && b.grant == gid
                            && b.environment == env
                            && !tx.slots_for_binding(&b.id)?.is_empty()
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
            if effective_lock_behavior(tx, &env, &g, ctx.profile.as_ref())?
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

    async fn admit_signature(
        &self,
        facts: &SignatureRequestFacts,
    ) -> Result<SignPermit, SignRefusal> {
        let SignatureSubject::Grant(gid) = &facts.subject else {
            // The verification endpoint's predicate is U5's (fail closed).
            return Err(SignRefusal::Unavailable);
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
        let step_start = Instant::now();
        // The fresh read under the gate (dropping `shared` on refusal releases it).
        let auth = self.authorization_read(facts, gid).await?;
        let now = Instant::now();
        let safe_wall = auth.safe.wall();
        let mut continuous = step_start + limits.signing_holder_max;
        if let Some(end) = auth.budget_end {
            continuous = continuous.min(now + end.saturating_sub(auth.safe.anchor.continuous));
        }
        let to_bound =
            Duration::try_from(auth.bound.duration_since(safe_wall)).unwrap_or(Duration::ZERO);
        continuous = continuous.min(now + to_bound);
        let wall = auth
            .bound
            .min(plus(safe_wall, continuous.saturating_duration_since(now)));
        let time: Arc<dyn SafeTime> = Arc::new(AdmittedTime {
            clock: Arc::clone(&self.inner.config.clock),
            admitted: auth.safe.anchor.clone(),
            skew: self.inner.config.time_policy.max_tolerated_skew,
        });
        Ok(SigningGates::permit(
            shared,
            PermitExpiry::new(wall, continuous),
            time,
        ))
    }
}

#[async_trait]
impl SignatureAuthority for Operations {
    async fn precheck(&self, facts: &SignatureRequestFacts) -> Result<(), SignRefusal> {
        let SignatureSubject::Grant(gid) = &facts.subject else {
            return Err(SignRefusal::Unavailable);
        };
        if self.signing_gates().is_pending(gid) {
            return Err(SignRefusal::NarrowingPending);
        }
        let bound = self.limits().signature_authorization_timeout;
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
