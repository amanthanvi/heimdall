//! ⟨M06 U4⟩ The runner's side of typed narrowing effects and resynchronization (ADR-0012 §7;
//! ADR-0006 §18.5 readings 9 and 16; m06-plan U4).
//!
//! A controller's `runner.deliver_effect` reaches [`RunnerSync::deliver`] with the session's
//! authenticated caller. The **producer** of the effect is that caller's paired client, never
//! a request field; with the effect ID and the typed target (which carries its generation) it
//! is the effect's key (`heimdall_store::ext_effects::EffectKey`).
//!
//! **Each effect is applied through the runner's own narrowing machinery**
//! (`heimdall_app::Operations`), exactly as the same narrowing asked at the runner would be,
//! so its enforcement is the local one (ADR-0005 §6.1):
//!
//! * `grant_revoke` → `revoke`: a durable grant tombstone with its cascade, the owned
//!   dedicated sessions and masters closed at once, admissions refused. Then K_env of the
//!   grant and of every descendant is zeroized ([`RunnerSide::destroy_keys`]). A grant ID the
//!   runner does not hold still gets its tombstone, so the ID can never be used later.
//!   ⟨M08 W4 SEC-3b, R1⟩ Such a bare tombstone has no authority effect here: it is attributed
//!   to its producer and capped (`heimdall_store::ext_effects::BARE_TOMBSTONES_PER_PRODUCER`,
//!   `BARE_TOMBSTONES_TOTAL`; `BACKPRESSURE` past them, nothing recorded). A revoke of a grant
//!   the runner holds is never capped, and one of a grant already `revoked` (its known
//!   tombstone perhaps pruned since) converges on that row without revoking again.
//! * `policy_pause` → `policy pause`: running grants continue, new activations are refused.
//!   ⟨M08 W4 SEC-3b, R2⟩ A pause or cutoff whose scope matches nothing on this runner, that would
//!   add a new in-force row past `UNMATCHED_REVISIONS_PER_PRODUCER`, is refused `BACKPRESSURE`
//!   (nothing recorded); one whose scope matches a runner object never is.
//! * `policy_cutoff` → `policy cutoff` on every policy of the scope whose cutoff it shortens:
//!   the effective cutoff is `min(existing, at)`; a delivered or replayed cutoff never moves
//!   one later (that is a widening, decided at the runner). With trusted time an `at` at or
//!   before now takes effect at the durable apply, and a future `at` is kept and enforced at
//!   `at` by the supervisor's wake. Under uncertain time it fires as soon as `at` may have
//!   passed: against the upper bound of now when one is known ([`RunnerSide::now_upper_bound`]),
//!   otherwise at once ([`cutoff_apply`]).
//!
//! A narrowing never waits for safe time: every effect applies under `TIME_UNCERTAIN`.
//!
//! **Durable records, then the acknowledgement.** A pause or cutoff is also recorded as a
//! policy revision row with producer-scoped identity `(scope, producer, revision)` and the
//! runner's own order (`runner_seq`); two controllers' equal revision numbers are two rows
//! and neither replaces the other. The acknowledgement is written only in a transaction that
//! finds the record the effect names (the tombstone, or the revision row written in that same
//! transaction), and is returned only after that commit.
//!
//! **Redelivery converges.** A redelivered effect is applied again, idempotently (the local
//! narrowing is a no-op the second time; a cutoff is re-judged against the time now, so a
//! replay under uncertainty still fires), and answers the acknowledgement as recorded. A
//! crash between the apply and the acknowledgement is repaired by the redelivery.
//!
//! **A cutoff that fired under uncertain time stays fired** (ADR-0012 §7.4, ruling of
//! 2026-11-21). The instant it fired at is written into the runner's policies, so a later
//! certain reading, or a redelivery judged with trusted time, finds the policy already cut
//! off and changes nothing: only a runner-local attended `clear_cutoff` lifts it. ⟨M08 W4
//! SEC-4, S3-01⟩ That instant is never later than the earliest instant a later trusted reading
//! can show ([`trusted_floor`]): the uncertain wall clock may be fast or have jumped forward,
//! and a correction (synchronization, or an attended `confirm_time`) must not put the instant
//! back in the future. Signing, the scheduler's tick, activation and readiness all read the
//! policy's cutoff, so the latch holds for each of them. Uncertain time still ends nothing at
//! the apply (signing fails closed on `TIME_UNCERTAIN`); the next pass on trusted time ends the
//! affected grants. The revision row records the instant (`fired_uncertain_at`) whenever the
//! cutoff fired under uncertain time, which the authority report carries.
//!
//! **A revoke is never defeated by a stale generation** (same ruling). `grant_revoke` names
//! the grant; the generation it carries is part of the effect's key (idempotency and audit)
//! and is never compared with the grant's current generation: the grant is revoked as it is
//! now, with everything older.
//!
//! [`RunnerSync::authority_report`] is the runner's report for §7.4 step 3: tombstones, policy
//! revisions with their generations, and the certificates installed now.

use std::sync::Arc;
use std::time::Duration;

use heimdall_app::context::Caller;
use heimdall_app::{OpError, Operations};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{ClientId, EffectId, GrantId, PolicyId, RequestId};
use heimdall_contract::managed::ComponentResidual;
use heimdall_contract::remote::{EffectTarget, Role};
use heimdall_contract::request::{PolicyAction, RevokeRequest};
use heimdall_contract::trust::PolicyTarget;
use heimdall_domain::policy::{AuthorityGeneration, StandingPolicy};
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_domain::time::Clock;
use heimdall_store::ext_effects::{
    AppliedRecord, AuthorityReport, BareTombstone, EffectAck, EffectKey, PolicyRevisionKind,
    PolicyRevisionRecord, ReportedCertificate, policy_scope_key, scope_key, target_kind,
    target_ref,
};
use heimdall_store::ext_m06::ClientState;
use heimdall_store::{Store, Txn};
use sha2::{Digest as _, Sha256};

/// What the runner knows about now when it applies a cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NowBound {
    /// The shared time gate accepted this observation.
    Trusted(Timestamp),
    /// Time is uncertain: the wall clock as read, the latest instant now can be when a
    /// bound is known (`None`: unbounded), and the earliest instant a later trusted reading
    /// can show.
    Uncertain {
        /// The wall clock as read (not trusted).
        wall: Timestamp,
        /// The upper bound of now, when known.
        upper: Option<Timestamp>,
        /// No later trusted reading of this runner's time gate is earlier ([`trusted_floor`]).
        floor: Timestamp,
    },
}

/// ⟨M08 W4 SEC-4, S3-01⟩ The earliest instant any later trusted reading of the time gate can
/// show, given its persisted high-water mark `high_water` and its rollback tolerance
/// `rollback`. The gate accepts no wall reading, and records no attended confirmation, more
/// than `rollback` below the mark (after a reboot, none below it at all), and the mark only
/// rises (`heimdall_domain::time::gate`, `next_high_water`). With no mark, no reading was ever
/// accepted and nothing bounds the first one: the floor is then the Unix epoch.
#[must_use]
pub fn trusted_floor(high_water: Option<Timestamp>, rollback: Duration) -> Timestamp {
    match high_water {
        Some(mark) => jiff::SignedDuration::try_from(rollback)
            .ok()
            .and_then(|r| mark.checked_sub(r).ok())
            .unwrap_or(Timestamp::MIN),
        None => Timestamp::UNIX_EPOCH,
    }
}

/// How a delivered cutoff applies ([`cutoff_apply`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CutoffApply {
    /// The instant applied to the runner's policies: the owner's `at`, or an earlier instant
    /// when the cutoff fires under uncertain time. Never later than `at`.
    pub instant: Timestamp,
    /// Whether `at` had passed (trusted time), or may have passed (uncertain time), at the
    /// apply.
    pub fired: bool,
}

/// How a cutoff with the owner's instant `at` applies at `now` (module docs; ADR-0006 §18.5
/// reading 9):
/// * trusted time: the instant is `at`; it fired when `at <= now`;
/// * uncertain time with an upper bound before `at`: the instant is `at`, not fired;
/// * uncertain time otherwise (`at` may have passed): it fires now, and the instant is the
///   earliest of `at`, the wall clock and the trusted floor. ⟨SEC-4, S3-01⟩ The floor is what
///   keeps it fired: a wall clock that was fast or jumped forward is later corrected, and no
///   later trusted reading is earlier than the floor, so none finds the instant in the future.
#[must_use]
pub fn cutoff_apply(at: Timestamp, now: &NowBound) -> CutoffApply {
    match *now {
        NowBound::Trusted(now) => CutoffApply {
            instant: at,
            fired: at <= now,
        },
        NowBound::Uncertain { wall, upper, floor } => {
            if upper.is_some_and(|u| at > u) {
                CutoffApply {
                    instant: at,
                    fired: false,
                }
            } else {
                CutoffApply {
                    instant: at.min(wall).min(floor),
                    fired: true,
                }
            }
        }
    }
}

/// The effective cutoff of a policy after a delivered cutoff at `instant`:
/// `min(existing, instant)`.
#[must_use]
pub fn effective_cutoff(existing: Option<Timestamp>, instant: Timestamp) -> Timestamp {
    existing.map_or(instant, |e| e.min(instant))
}

/// The runner runtime's process state that an effect or the report needs (K_env and the
/// installed certificates live in the runner's memory, the time samples too).
pub trait RunnerSide: Send + Sync {
    /// Zeroize K_env of `grant` and drop its installed certificates; `true` when there was
    /// a key.
    fn destroy_keys(&self, grant: &GrantId) -> bool;

    /// The latest instant now can be, when this runner's time is bounded by a qualifying
    /// sample (ADR-0012 §4.4); `None` when unbounded.
    fn now_upper_bound(&self) -> Option<Timestamp>;

    /// The certificates installed now.
    fn installed_certificates(&self) -> Vec<ReportedCertificate>;

    /// Every grant that has a K_env now.
    fn keyed_grants(&self) -> Vec<GrantId>;
}

/// The runner's effect application and authority report (module docs).
#[derive(Clone)]
pub struct RunnerSync {
    store: Arc<Store>,
    operations: Operations,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for RunnerSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerSync").finish_non_exhaustive()
    }
}

fn refused(code: Code, message: &str) -> OpError {
    OpError::new(code, message).with_effect(EffectStatus::None)
}

/// ⟨M08 W4 SEC-3b; ADR-0012 §7.4 as amended 2026-11-27 (the override)⟩ A delivered effect
/// that would add history with no authority effect on this runner, past its cap: refused
/// `BACKPRESSURE`, nothing applied or recorded. It stays in the controller's outbox, so that
/// controller's issuer barrier stays closed (`OutboxPending`): fail closed.
fn backpressure(message: &str) -> OpError {
    refused(Code::Backpressure, message)
}

/// Where the tombstone a `grant_revoke` names stands after its apply.
enum RevokeRecord {
    /// The grant's tombstone (known, or bare).
    Tombstone(Tombstone),
    /// ⟨M08 W4 SEC-3b, R1⟩ The grant's `revoked` row, its known tombstone pruned since; with
    /// its descendants.
    RevokedRow(Vec<GrantId>),
    /// Held but not tombstoned: the revoke did not cover it.
    NotTombstoned,
    /// ⟨M08 W4 SEC-3b, R1⟩ A bare tombstone past its cap: nothing written.
    Capped,
}

fn not_owner() -> OpError {
    refused(
        Code::CapabilityUnavailable,
        "typed effects are delivered by an active owner controller of this runner",
    )
    .with_reason(reason::ROLE_INSUFFICIENT)
}

/// The idempotency request ID of the local `revoke` an effect drives: a digest of the
/// effect's key, so a redelivery replays the same operation and two effects never share one.
fn revoke_request_id(key: &EffectKey) -> Result<RequestId, OpError> {
    let mut h = Sha256::new();
    for part in [
        key.producer.as_str(),
        key.effect.as_str(),
        target_kind(&key.target).unwrap_or_default(),
        target_ref(&key.target).unwrap_or_default().as_str(),
    ] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.update(key.target.generation().to_be_bytes());
    let digest = h.finalize();
    let mut id = String::from("eff-");
    for b in &digest[..20] {
        id.push_str(&format!("{b:02x}"));
    }
    RequestId::parse(&id).map_err(|_| OpError::new(Code::InternalError, "request ID encoding"))
}

/// ⟨M08 W4 SEC-3b, R2⟩ A pause's or cutoff's acknowledgement, or `BACKPRESSURE` when its
/// transaction found the unmatched cap reached (`capped`) and wrote nothing.
fn unmatched_capped(
    capped: &std::sync::atomic::AtomicBool,
    acked: Result<EffectAck, OpError>,
) -> Result<EffectAck, OpError> {
    if capped.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(backpressure(
            "the scope of this pause or cutoff matches nothing on this runner, and this \
             controller's in-force revisions of such scopes are at their limit; nothing was \
             recorded (the effect stays pending)",
        ));
    }
    acked
}

/// The runner's policies a cutoff scope names (as the local targeted forms resolve it).
fn policies_of(
    tx: &mut Txn<'_>,
    scope: &PolicyTarget,
) -> heimdall_store::Result<Vec<StandingPolicy>> {
    Ok(match scope {
        PolicyTarget::Policy { policy_id } => tx.policy(policy_id)?.into_iter().collect(),
        PolicyTarget::Profile { profile } => tx
            .policies()?
            .into_iter()
            .filter(|p| p.profile == *profile)
            .collect(),
        PolicyTarget::Workspace { workspace } => tx
            .policies()?
            .into_iter()
            .filter(|p| p.workspace.as_ref() == Some(workspace))
            .collect(),
        PolicyTarget::All => tx.policies()?,
        // A scope this build does not know names nothing here (refused before: no key).
        _ => Vec::new(),
    })
}

impl RunnerSync {
    /// The runner's sync service over its store, its operations and its clock.
    #[must_use]
    pub fn new(store: Arc<Store>, operations: Operations, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            operations,
            clock,
        }
    }

    async fn read<T, F>(&self, f: F) -> Result<T, OpError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Txn<'_>) -> heimdall_store::Result<T> + Send + 'static,
    {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.transaction(f))
            .await
            .map_err(|_| OpError::new(Code::InternalError, "the store task did not complete"))?
            .map_err(OpError::from)
    }

    /// The producing controller of `caller`'s session: its paired client, which must be an
    /// active owner in the role table now.
    async fn producer(&self, caller: &Caller) -> Result<ClientId, OpError> {
        let Some(client) = caller.context.remote_client.clone() else {
            return Err(OpError::driver_unavailable(
                "runner requests are served to a paired controller only",
            )
            .with_effect(EffectStatus::None));
        };
        let c = client.clone();
        let active_owner = self
            .read(move |tx| {
                Ok(tx
                    .remote_client(&c)?
                    .is_some_and(|r| r.state == ClientState::Active && r.role == Role::Owner))
            })
            .await?;
        if active_owner && caller.context.is_owner() {
            Ok(client)
        } else {
            Err(not_owner())
        }
    }

    /// What the runner knows about now (module docs). The high-water mark is read after the
    /// gate's verdict: it only rises, so a mark read now is never above the one any later
    /// trusted reading is held to, and the floor computed from it stays valid.
    async fn now_bound(&self, side: &dyn RunnerSide) -> Result<NowBound, OpError> {
        let gate = self.operations.timegate();
        Ok(match gate.check().await {
            Ok(safe) => NowBound::Trusted(safe.wall()),
            Err(_) => {
                let rollback = gate.policy().max_tolerated_rollback;
                let mark = self.read(|tx| tx.high_water_mark()).await?;
                NowBound::Uncertain {
                    wall: self.clock.wall(),
                    upper: side.now_upper_bound(),
                    floor: trusted_floor(mark, rollback),
                }
            }
        })
    }

    /// Apply one delivered effect and acknowledge it (module docs). The acknowledgement is
    /// returned only after the durable record it names and the acknowledgement itself are
    /// committed.
    ///
    /// # Errors
    ///
    /// `CAPABILITY_UNAVAILABLE` (`driver_unavailable` for a caller that is not a paired
    /// controller, `role_insufficient` for one that is not an active owner); `USAGE_ERROR`
    /// for a target this build does not know (nothing applied); the local narrowing's own
    /// error when it could not be applied (no acknowledgement is recorded then, and the
    /// controller redelivers).
    pub async fn deliver(
        &self,
        side: &dyn RunnerSide,
        caller: &Caller,
        effect: &EffectId,
        target: &EffectTarget,
    ) -> Result<EffectAck, OpError> {
        let producer = self.producer(caller).await?;
        if target_kind(target).is_none() || target_ref(target).is_none() {
            return Err(refused(
                Code::UsageError,
                "this effect target is not supported by this build",
            ));
        }
        let key = EffectKey {
            producer,
            effect: effect.clone(),
            target: target.clone(),
        };
        let record = match target {
            EffectTarget::GrantRevoke { grant, .. } => {
                self.apply_revoke(side, caller, &key, grant).await?
            }
            EffectTarget::PolicyPause { policy, revision } => {
                self.apply_pause(caller, &key, policy, *revision).await?
            }
            EffectTarget::PolicyCutoff {
                scope,
                at,
                revision,
            } => {
                self.apply_cutoff(side, caller, &key, scope, *at, *revision)
                    .await?
            }
            _ => {
                return Err(refused(
                    Code::UsageError,
                    "this effect target is not supported by this build",
                ));
            }
        };
        self.sweep_keys(side).await?;
        Ok(record)
    }

    /// Zeroize K_env of every grant that can no longer be used (a cutoff that fired ended
    /// it like expiry, a revoke's cascade, a grant purged): after a narrowing effect is
    /// acknowledged, no key of an ended grant stays in the runner's memory. A grant the
    /// store cannot find is treated as ended.
    async fn sweep_keys(&self, side: &dyn RunnerSide) -> Result<(), OpError> {
        let keyed = side.keyed_grants();
        if keyed.is_empty() {
            return Ok(());
        }
        let ended = self
            .read(move |tx| {
                let mut ended = Vec::new();
                for g in keyed {
                    if !tx.grant(&g)?.is_some_and(|s| s.state.permits_use()) {
                        ended.push(g);
                    }
                }
                Ok(ended)
            })
            .await?;
        for g in &ended {
            side.destroy_keys(g);
        }
        Ok(())
    }

    /// Write (or rewrite the enforcement state of) the acknowledgement, in one transaction
    /// with `before` (the revision row of a policy effect). The store refuses it unless the
    /// durable record exists in that transaction.
    async fn acknowledge<F>(&self, ack: EffectAck, before: F) -> Result<EffectAck, OpError>
    where
        F: FnOnce(&mut Txn<'_>, &mut EffectAck) -> heimdall_store::Result<()> + Send + 'static,
    {
        self.read(move |tx| {
            let mut ack = ack;
            before(tx, &mut ack)?;
            // The first acknowledgement's apply time is kept: a redelivery reports when the
            // effect was first applied.
            if let Some(first) = tx.remote_effect_ack(&ack.key)? {
                ack.applied_at = first.applied_at;
            }
            tx.record_remote_effect_ack(&ack)?;
            Ok(ack)
        })
        .await
    }

    async fn apply_revoke(
        &self,
        side: &dyn RunnerSide,
        caller: &Caller,
        key: &EffectKey,
        grant: &GrantId,
    ) -> Result<EffectAck, OpError> {
        let g = grant.clone();
        let state = self
            .read(move |tx| Ok(tx.grant(&g)?.map(|s| s.state)))
            .await?;
        let mut known = state.is_some();
        // ⟨M08 W4 SEC-3b, R1⟩ A grant already `revoked` is not revoked again: its revoke
        // applied before (its request may be past its retention, `REQUEST_EXPIRED`, and the
        // known tombstone pruned since), so a late redelivery converges on the record below.
        if state.is_some() && state != Some(heimdall_contract::GrantState::Revoked) {
            let request = RevokeRequest {
                grant_id: Some(grant.clone()),
                request_id: revoke_request_id(key)?,
                target: None,
            };
            match self.operations.revoke(caller, request).await {
                Ok(done) if done.data.local_applied => {}
                Ok(_) => {
                    return Err(OpError::new(
                        Code::OutcomeUnknown,
                        "the runner's revoke did not report its local denial applied",
                    ));
                }
                // Purged between the read and the revoke: denied by the bare tombstone below.
                Err(e) if e.code == Code::NotFound => known = false,
                Err(e) => return Err(e),
            }
        }
        let now = self.clock.wall();
        let (g, producer) = (grant.clone(), key.producer.clone());
        // The tombstone the effect names: the revoke's, or a bare one for an ID this runner
        // does not hold (`insert_tombstone` keeps a first tombstone unchanged). ⟨M08 W4 SEC-3b,
        // R1⟩ A bare one is attributed to its producer and capped (it has no authority effect
        // here); a held grant's revoke never is.
        let record = self
            .read(move |tx| {
                if let Some(t) = tx.tombstone(&g)? {
                    return Ok(RevokeRecord::Tombstone(t));
                }
                if let Some(held) = tx.grant(&g)? {
                    if held.state == heimdall_contract::GrantState::Revoked {
                        return Ok(RevokeRecord::RevokedRow(tx.grant_descendants(&g)?));
                    }
                    // Held but not tombstoned: the revoke above did not cover it.
                    return Ok(RevokeRecord::NotTombstoned);
                }
                let bare = Tombstone {
                    grant: g.clone(),
                    cascade: Vec::new(),
                    generation: AuthorityGeneration(0),
                    revoked_at: now,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                };
                Ok(match tx.record_bare_tombstone(&bare, &producer)? {
                    BareTombstone::Recorded(t) | BareTombstone::Existing(t) => {
                        RevokeRecord::Tombstone(t)
                    }
                    BareTombstone::Held => RevokeRecord::NotTombstoned,
                    BareTombstone::Capped => RevokeRecord::Capped,
                })
            })
            .await?;
        let cascade = match record {
            RevokeRecord::Tombstone(t) => t.cascade,
            RevokeRecord::RevokedRow(descendants) => descendants,
            RevokeRecord::NotTombstoned => {
                return Err(OpError::new(
                    Code::OutcomeUnknown,
                    "the grant is not tombstoned after the revoke; redeliver the effect",
                ));
            }
            RevokeRecord::Capped => {
                return Err(backpressure(
                    "this runner holds no grant of that ID, and the revokes of grant IDs it does \
                     not hold are at their limit; nothing was recorded (the effect stays pending \
                     until older ones age out)",
                ));
            }
        };
        // K_env of the grant and of every descendant: zeroized now, and again on every
        // redelivery (idempotent).
        side.destroy_keys(grant);
        for d in &cascade {
            side.destroy_keys(d);
        }
        let ack = EffectAck {
            key: key.clone(),
            applied_at: now,
            record: AppliedRecord::GrantTombstone {
                grant: grant.clone(),
                known,
                cascade,
                key_destroyed: true,
                owned_dedicated_sessions: ComponentResidual::Closed,
                owned_admissions: ComponentResidual::Closed,
            },
        };
        self.acknowledge(ack, |_, _| Ok(())).await
    }

    async fn apply_pause(
        &self,
        caller: &Caller,
        key: &EffectKey,
        policy: &PolicyId,
        revision: u64,
    ) -> Result<EffectAck, OpError> {
        let action = PolicyAction::Pause {
            policy_id: Some(policy.clone()),
            target: None,
        };
        let policies = match self.operations.policy(caller, action).await {
            Ok(_) => vec![policy.clone()],
            // No such policy on this runner: the revision is still recorded.
            Err(e) if e.code == Code::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let now = self.clock.wall();
        let row = PolicyRevisionRecord {
            scope_key: policy_scope_key(policy),
            scope: PolicyTarget::Policy {
                policy_id: policy.clone(),
            },
            producer: key.producer.clone(),
            revision,
            runner_seq: 0,
            kind: PolicyRevisionKind::Pause,
            effect: key.effect.clone(),
            received_at: now,
            cutoff_at: None,
            fired_uncertain_at: None,
            in_force: true,
        };
        let ack = EffectAck {
            key: key.clone(),
            applied_at: now,
            record: AppliedRecord::PolicyRevision {
                scope_key: row.scope_key.clone(),
                runner_seq: 0,
                policies,
                cutoff_at: None,
                fired: false,
            },
        };
        let capped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&capped);
        let acked = self
            .acknowledge(ack, move |tx, ack| {
                // ⟨M08 W4 SEC-3b, R2⟩ Only a new in-force row whose scope matches nothing
                // here is capped; in the acknowledgement's own transaction.
                if tx.unmatched_revision_capped(&row)? {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(heimdall_store::StoreError::GenerationConflict(
                        "unmatched revisions at their limit".to_owned(),
                    ));
                }
                let stored = tx.record_remote_policy_revision(&row)?;
                if let AppliedRecord::PolicyRevision { runner_seq, .. } = &mut ack.record {
                    *runner_seq = stored.record().runner_seq;
                }
                Ok(())
            })
            .await;
        unmatched_capped(&capped, acked)
    }

    async fn apply_cutoff(
        &self,
        side: &dyn RunnerSide,
        caller: &Caller,
        key: &EffectKey,
        scope: &PolicyTarget,
        at: Timestamp,
        revision: u64,
    ) -> Result<EffectAck, OpError> {
        let Some(scope_key) = scope_key(scope) else {
            return Err(refused(
                Code::UsageError,
                "this cutoff scope is not supported by this build",
            ));
        };
        // A redelivery of this key may carry another instant: the row keeps the earliest,
        // and that is the owner's instant applied.
        let (sk, producer) = (scope_key.clone(), key.producer.clone());
        let recorded = self
            .read(move |tx| tx.remote_policy_revision(&sk, &producer, revision))
            .await?
            .and_then(|r| r.cutoff_at);
        let owner_at = recorded.map_or(at, |r| r.min(at));
        let now_bound = self.now_bound(side).await?;
        let uncertain = matches!(now_bound, NowBound::Uncertain { .. });
        let apply = cutoff_apply(owner_at, &now_bound);

        let s = scope.clone();
        let policies = self.read(move |tx| policies_of(tx, &s)).await?;
        let mut applied = Vec::new();
        for p in policies {
            // Only ever shorten: a policy whose cutoff is already at or before the instant is
            // left as it is (`min(existing, at)`), so nothing here can ask for a widening.
            if p.cutoff_at.is_some_and(|c| c <= apply.instant) {
                applied.push(p.id);
                continue;
            }
            // The targeted form, naming exactly this policy: with trusted time it also ends
            // the grants whose bound the cutoff has passed in the same commit (the durable
            // apply), as a cutoff asked at the runner does.
            let action = PolicyAction::Cutoff {
                policy_id: None,
                at: apply.instant,
                target: Some(PolicyTarget::Policy {
                    policy_id: p.id.clone(),
                }),
            };
            match self.operations.policy(caller, action).await {
                Ok(_) => applied.push(p.id),
                // Removed meanwhile: nothing left to cut off.
                Err(e) if e.code == Code::NotFound => {}
                Err(e) => {
                    // A concurrent local cutoff may have got there first (the request then
                    // reads as a widening and is not applied): fine when the policy's cutoff
                    // is now at or before the instant, an error otherwise.
                    let id = p.id.clone();
                    let now_cut = self
                        .read(move |tx| Ok(tx.policy(&id)?.and_then(|p| p.cutoff_at)))
                        .await?;
                    if now_cut.is_some_and(|c| c <= apply.instant) {
                        applied.push(p.id);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        let now = self.clock.wall();
        let row = PolicyRevisionRecord {
            scope_key: scope_key.clone(),
            scope: scope.clone(),
            producer: key.producer.clone(),
            revision,
            runner_seq: 0,
            kind: PolicyRevisionKind::Cutoff,
            effect: key.effect.clone(),
            received_at: now,
            cutoff_at: Some(owner_at),
            // ⟨ADR-0012 §7.4 ⟨2026-11-21⟩⟩ Fired because time was uncertain: recorded with
            // the instant applied, and kept (the store never clears it), so the report,
            // `environment status` and `doctor` can say so. ⟨SEC-4, S3-01⟩ Whenever it fired
            // under uncertain time, a wall clock already past the owner's instant included.
            fired_uncertain_at: (uncertain && apply.fired).then_some(apply.instant),
            in_force: true,
        };
        let ack = EffectAck {
            key: key.clone(),
            applied_at: now,
            record: AppliedRecord::PolicyRevision {
                scope_key,
                runner_seq: 0,
                policies: applied,
                cutoff_at: Some(owner_at),
                fired: apply.fired,
            },
        };
        let capped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&capped);
        let acked = self.acknowledge(ack, move |tx, ack| {
            // ⟨M08 W4 SEC-3b, R2⟩ As for a pause.
            if tx.unmatched_revision_capped(&row)? {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(heimdall_store::StoreError::GenerationConflict(
                    "unmatched revisions at their limit".to_owned(),
                ));
            }
            let stored = tx.record_remote_policy_revision(&row)?;
            let was_fired = tx.remote_effect_ack(&ack.key)?.is_some_and(|a| {
                matches!(a.record, AppliedRecord::PolicyRevision { fired: true, .. })
            });
            if let AppliedRecord::PolicyRevision {
                runner_seq,
                cutoff_at,
                fired,
                ..
            } = &mut ack.record
            {
                *runner_seq = stored.record().runner_seq;
                *cutoff_at = stored.record().cutoff_at;
                // Once fired, always reported fired.
                *fired = *fired || was_fired;
            }
            Ok(())
        });
        unmatched_capped(&capped, acked.await)
    }

    /// The runner's authority report (ADR-0012 §7.4 step 3) for a paired owner controller.
    ///
    /// # Errors
    ///
    /// As [`Self::deliver`] for the caller; `STATE_UNAVAILABLE`.
    pub async fn authority_report(
        &self,
        side: &dyn RunnerSide,
        caller: &Caller,
    ) -> Result<AuthorityReport, OpError> {
        self.producer(caller).await?;
        let mut report = self
            .read(|tx| tx.authority_report())
            .await?
            .ok_or_else(|| {
                OpError::driver_unavailable("this installation is not a remote runner")
            })?;
        report.certificates = side.installed_certificates();
        report.time_bounded = side.now_upper_bound().is_some();
        report
            .certificates
            .sort_by(|a, b| (a.grant.as_str(), a.serial).cmp(&(b.grant.as_str(), b.serial)));
        Ok(report)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    /// ADR-0006 §18.5 reading 9: early, late, and under uncertainty with and without a bound.
    #[test]
    fn a_cutoff_applies_by_what_is_known_about_now() {
        let at = t("2026-11-21T12:00:00Z");
        // Delivered early with trusted time: kept for the supervisor's wake.
        assert_eq!(
            cutoff_apply(at, &NowBound::Trusted(t("2026-11-21T11:00:00Z"))),
            CutoffApply {
                instant: at,
                fired: false
            }
        );
        // Delivered late (or exactly at): applies at the durable apply, with the owner's instant.
        for now in ["2026-11-21T12:00:00Z", "2026-11-21T13:00:00Z"] {
            assert_eq!(
                cutoff_apply(at, &NowBound::Trusted(t(now))),
                CutoffApply {
                    instant: at,
                    fired: true
                }
            );
        }
        // The last trusted reading was at 09:59:05 or later (a mark of 09:59:10, a 5 s
        // rollback tolerance).
        let floor = t("2026-11-21T09:59:05Z");
        // Uncertain, bounded before `at`: it cannot have passed.
        assert_eq!(
            cutoff_apply(
                at,
                &NowBound::Uncertain {
                    wall: t("2026-11-21T10:00:00Z"),
                    upper: Some(t("2026-11-21T11:59:59Z")),
                    floor,
                }
            ),
            CutoffApply {
                instant: at,
                fired: false
            }
        );
        // Uncertain, the bound reaches `at`: it may have passed, so it fires, never later
        // than the wall clock read.
        let behind = t("2026-11-21T09:00:00Z");
        assert_eq!(
            cutoff_apply(
                at,
                &NowBound::Uncertain {
                    wall: behind,
                    upper: Some(at),
                    floor,
                }
            ),
            CutoffApply {
                instant: behind,
                fired: true
            }
        );
        // ⟨SEC-4, S3-01⟩ Uncertain and unbounded: fires at once, and never later than the
        // floor, whether the wall clock jumped past `at` (example A) or is only a few minutes
        // fast (example B): a trusted reading after the correction is not before the floor.
        for wall in ["2026-11-21T14:00:00Z", "2026-11-21T10:05:00Z"] {
            assert_eq!(
                cutoff_apply(
                    at,
                    &NowBound::Uncertain {
                        wall: t(wall),
                        upper: None,
                        floor,
                    }
                ),
                CutoffApply {
                    instant: floor,
                    fired: true
                },
                "{wall}"
            );
        }
        // An owner's instant already before the floor is kept as it is.
        let past = t("2026-11-21T08:00:00Z");
        assert_eq!(
            cutoff_apply(
                past,
                &NowBound::Uncertain {
                    wall: t("2026-11-21T14:00:00Z"),
                    upper: None,
                    floor,
                }
            ),
            CutoffApply {
                instant: past,
                fired: true
            }
        );
    }

    /// ⟨SEC-4, S3-01⟩ The floor: the mark less the rollback tolerance; the epoch with no mark.
    #[test]
    fn the_trusted_floor_is_the_mark_less_the_rollback_tolerance() {
        let mark = t("2026-11-21T09:59:10Z");
        assert_eq!(
            trusted_floor(Some(mark), Duration::from_secs(5)),
            t("2026-11-21T09:59:05Z")
        );
        assert_eq!(trusted_floor(Some(mark), Duration::ZERO), mark);
        assert_eq!(
            trusted_floor(None, Duration::from_secs(5)),
            Timestamp::UNIX_EPOCH
        );
        assert_eq!(
            trusted_floor(Some(mark), Duration::MAX),
            Timestamp::MIN,
            "a tolerance too large to subtract bounds nothing"
        );
    }

    #[test]
    fn the_effective_cutoff_only_shortens() {
        let at = t("2026-11-21T12:00:00Z");
        assert_eq!(effective_cutoff(None, at), at);
        assert_eq!(
            effective_cutoff(Some(t("2026-11-21T11:00:00Z")), at),
            t("2026-11-21T11:00:00Z")
        );
        assert_eq!(effective_cutoff(Some(t("2026-11-21T13:00:00Z")), at), at);
    }

    /// The local revoke's request ID is a function of the whole key.
    #[test]
    fn the_revoke_request_id_is_a_function_of_the_key() {
        let key = |producer: u8, effect: u8, generation: u64| EffectKey {
            producer: ClientId::from_random_bytes([producer; 16]),
            effect: EffectId::from_random_bytes([effect; 16]),
            target: EffectTarget::GrantRevoke {
                grant: GrantId::from_random_bytes([9; 16]),
                grant_generation: generation,
            },
        };
        let a = revoke_request_id(&key(1, 1, 4)).unwrap();
        assert_eq!(a, revoke_request_id(&key(1, 1, 4)).unwrap());
        for other in [key(2, 1, 4), key(1, 2, 4), key(1, 1, 5)] {
            assert_ne!(a, revoke_request_id(&other).unwrap());
        }
    }
}
