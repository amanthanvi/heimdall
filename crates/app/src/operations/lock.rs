//! ⟨M03⟩ U0b row 25 (G): the lock revocation (ADR-0008 D9 items 2–3; §17.1 item 9,
//! §17.4 item 9).
//!
//! [`Operations::on_session_lock`] revokes, in one pass, every grant whose effective lock
//! behaviour is `revoke_on_lock` (the strictest of the value recorded in its origin and
//! every applicable policy of its profile), with tombstone and cascade and cause
//! `session_locked`, through the narrowing protocol (row 20): one narrowing whose set
//! is every such grant with its descendants, one tombstone per root in its commit.
//! The acknowledged epoch is stored in that commit, and the source's
//! `acknowledge(epoch)` is called only after it, so a lock whose revocations did not
//! commit stays latched and the next pass revokes again (idempotent: a grant already
//! revoking is not in the set).
//!
//! ⟨M03⟩ U9 (ADR-0008 §17.15 item 12, R3): the effective behaviour also merges the M01
//! `[session] lock_behavior` **floor** ([`Operations::set_session_lock_floor`]): `revoke`
//! from either side wins. And each pass records one `session_lock` event in its commit
//! (`{state, revoked}`; the record m03-plan §4.4 step 4 verifies), so a coalesced storm
//! of locks yields one event per pass, never one per lock.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};

use heimdall_contract::event::EventType;
use heimdall_contract::ids::{EnvironmentId, GrantId, ProfileId};
use heimdall_contract::managed::{LockBehavior, SessionLockEventPayload, SessionLockState};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::managed::LockEpoch;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_store::Txn;

use super::narrowing::{NarrowingKind, NarrowingReport, SetReader};
use super::{Operations, grant_context, revoke_locally_in};
use crate::error::OpError;
use crate::ports::SessionLockSource;

/// What one lock pass did ([`Operations::on_session_lock`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockRevocation {
    /// The epoch handled.
    pub epoch: u64,
    /// The roots revoked (each with its cascade).
    pub revoked: Vec<GrantId>,
    /// The narrowing's report (`None` when the epoch had nothing latched).
    pub report: Option<NarrowingReport>,
}

/// The effective lock behaviour of `g`: the strictest of its origin's recorded value,
/// every policy of `profile` applicable here (ADR-0008 D9 item 2) and the R3 `floor`
/// (`crate::lock::effective_behavior_with_floor`).
pub(super) fn effective_lock_behavior(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    g: &GrantSnapshot,
    profile: Option<&ProfileId>,
    floor: LockBehavior,
) -> heimdall_store::Result<LockBehavior> {
    let origin = tx.grant_origin(&g.id)?;
    let policies = match profile {
        Some(p) => tx.policies_for(p, env)?,
        None => Vec::new(),
    };
    Ok(crate::lock::effective_behavior_with_floor(
        origin.as_ref(),
        &policies,
        floor,
    ))
}

/// The lock set: every live grant (not terminal, not already revoking) whose
/// effective behaviour is `revoke_on_lock`, with its descendants.
fn lock_set(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    floor: LockBehavior,
) -> heimdall_store::Result<Vec<GrantId>> {
    let mut out: Vec<GrantId> = Vec::new();
    let mut seen: BTreeSet<GrantId> = BTreeSet::new();
    for g in tx.grants_due(Timestamp::MAX)? {
        if g.state.is_terminal() || g.state == GrantState::Revoking || seen.contains(&g.id) {
            continue;
        }
        let ctx = grant_context(tx, &g)?;
        if effective_lock_behavior(tx, env, &g, ctx.profile.as_ref(), floor)?
            != LockBehavior::RevokeOnLock
        {
            continue;
        }
        let mut ids = vec![g.id.clone()];
        ids.extend(tx.grant_descendants(&g.id)?);
        for id in ids {
            if seen.insert(id.clone()) {
                out.push(id);
            }
        }
    }
    Ok(out)
}

impl Operations {
    /// ⟨M03⟩ U9 (ADR-0008 §17.15 item 12, R3): set the M01 `[session] lock_behavior`
    /// floor (`heimdall_runtime::session_lock::lock_floor`). `revoke_on_lock` makes every
    /// grant's effective behaviour `revoke_on_lock` while it is set (the lock pass, the
    /// per-signature check); `continue` (the default) adds nothing.
    pub fn set_session_lock_floor(&self, floor: LockBehavior) {
        *self
            .inner
            .narrowing
            .lock_floor
            .write()
            .unwrap_or_else(PoisonError::into_inner) = floor;
    }

    /// ⟨M03⟩ U9: the R3 floor in force ([`Self::set_session_lock_floor`]).
    #[must_use]
    pub fn session_lock_floor(&self) -> LockBehavior {
        *self
            .inner
            .narrowing
            .lock_floor
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// ⟨M03⟩ U0b row 25: one lock pass for `epoch` (from `source.lock_epoch()`). With
    /// `epoch.observed`, every `revoke_on_lock` grant is revoked through the narrowing
    /// protocol (cause `session_locked`), and only after that commit is
    /// `source.acknowledge(epoch.epoch)` called. Without a latched lock nothing is done
    /// and nothing acknowledged.
    ///
    /// # Errors
    /// A store failure; nothing is acknowledged then (the lock stays latched).
    pub async fn on_session_lock(
        &self,
        epoch: LockEpoch,
        source: &dyn SessionLockSource,
    ) -> Result<LockRevocation, OpError> {
        if !epoch.observed {
            return Ok(LockRevocation {
                epoch: epoch.epoch,
                revoked: Vec::new(),
                report: None,
            });
        }
        let requested_at = self.inner.config.clock.wall();
        let env = self.environment().clone();
        let retention = self.retention();
        let floor = self.session_lock_floor();
        // ⟨U9⟩ The observed state the event records: `unknown` when the source reads it
        // (treated as a lock), otherwise the latched lock.
        let observed_state = if source.state() == SessionLockState::Unknown {
            SessionLockState::Unknown
        } else {
            SessionLockState::Locked
        };
        let e2 = env.clone();
        let reader: SetReader = Arc::new(move |tx: &mut Txn<'_>| lock_set(tx, &e2, floor));
        let n = epoch.epoch;
        let narrowed = self
            .narrow(
                NarrowingKind::SessionLock,
                requested_at,
                reader,
                move |tx, emit, ctx| {
                    let ids = lock_set(tx, &env, floor)?;
                    let set: BTreeSet<GrantId> = ids.iter().cloned().collect();
                    let mut roots: Vec<GrantId> = Vec::new();
                    for id in &ids {
                        let parent = tx.grant(id)?.and_then(|g| g.parent);
                        if parent.is_none_or(|p| !set.contains(&p)) {
                            roots.push(id.clone());
                        }
                    }
                    let mut revoked: Vec<(GrantId, Vec<GrantId>)> = Vec::new();
                    for root in roots {
                        let mut all = vec![root.clone()];
                        all.extend(tx.grant_descendants(&root)?);
                        let generation = tx.authority_generation()?;
                        tx.insert_tombstone(&Tombstone {
                            grant: root.clone(),
                            cascade: all[1..].to_vec(),
                            generation,
                            revoked_at: ctx.committed_at,
                            remote_pending: Vec::new(),
                            cause: RevocationCause::SessionLocked,
                        })?;
                        revoke_locally_in(
                            tx,
                            emit,
                            &all,
                            RevocationCause::SessionLocked,
                            ctx.committed_at,
                            None,
                            retention,
                        )?;
                        ctx.destroy.extend(all.iter().cloned());
                        revoked.push((root, all));
                    }
                    if tx
                        .acknowledged_lock_epoch()?
                        .is_none_or(|stored| n > stored)
                    {
                        tx.set_acknowledged_lock_epoch(n)?;
                    }
                    // ⟨U9⟩ One `session_lock` event per pass, in its commit.
                    let payload = SessionLockEventPayload {
                        state: observed_state,
                        revoked: revoked
                            .iter()
                            .flat_map(|(_, all)| all.iter().cloned())
                            .collect(),
                    };
                    emit.event(
                        tx,
                        EventType::SessionLock,
                        None,
                        None,
                        serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null),
                    )?;
                    Ok(revoked)
                },
            )
            .await?;
        // Committed: the latch may clear now. Local denial through the adapters
        // follows, outside every gate.
        source.acknowledge(epoch.epoch);
        let roots: Vec<GrantId> = narrowed.value.iter().map(|(r, _)| r.clone()).collect();
        for (root, grants) in narrowed.value {
            self.complete_withdrawal(root, grants, RevocationCause::SessionLocked)
                .await;
        }
        Ok(LockRevocation {
            epoch: epoch.epoch,
            revoked: roots,
            report: Some(narrowed.report),
        })
    }
}
