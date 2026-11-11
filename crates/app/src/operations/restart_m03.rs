//! ⟨M03⟩ Restart recovery and supervisor hooks for managed credentials (m03-plan U0b
//! rows 6, 7, 8, 17 and 23; wave 0, phase 1). A child module of
//! [`crate::operations`] (the wave-0 placement rule), so it reaches the private
//! store plumbing (`Operations::write`, `Emit`, the revocation helpers) without
//! widening their visibility.
//!
//! * **Row 8** ([`mark_lost_in`]): in restart recovery's first transaction, before
//!   any listener binds (`Service::start_with` runs `Operations::start` before it
//!   binds an endpoint), every `installed` credential instance becomes `lost` (a
//!   new process holds no vault slot) and every `pending` one `destroyed`; issuance
//!   entries are untouched, so their residual stays counted. The grant of a lost
//!   instance is degraded `credential_reissue_pending` (no key).
//! * **Row 17** ([`Operations::owner_reconcile_unresolved`]): an M03 journaled
//!   operation found by a drive stays unresolved and untouched, reported once in
//!   `runtime_lifecycle` with reason `owner_reconcile` (ADR-0008 D5 §6.4; wave-0
//!   verify E8: not M02's `driver_unavailable`).
//! * **Row 23** ([`Operations::resume_ca_retirements`]): a CA in `retiring`,
//!   `unloaded` or `deleted` resumes its retirement at its next step (ADR-0008 D4
//!   item 3), each step persisted before the next and only after its external
//!   effect was confirmed. Without an issuer child or a store-deletion step (wave
//!   0 production) it goes no further than the store alone can take it: `retiring`
//!   and `unloaded` stay, and `deleted` is never recorded without the deletion.
//! * **Row 6** ([`Operations::settle_bounded_obligations`]): the supervisor's
//!   revocation pass moves `bounded_by_expiry` obligations through
//!   [`residual_step`] on safe time only, with no adapter call and no attempt
//!   counted; a grant whose every obligation is `bounded_complete` or
//!   `nominally_expired` reaches `revoked`.
//! * **Row 7** ([`Operations::process_cleanup_intent_reporting`]): the supervisor's
//!   per-intent entry, so it can back off kept intents of adapters with a remote
//!   credential effect.

use std::collections::BTreeSet;

use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::event::EventType;
use heimdall_contract::ids::{CaFingerprint, GrantId};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::managed::{CredentialLifecycleEvent, ResidualStatus};
use heimdall_domain::grant::DegradedReason;
use heimdall_domain::issuance::{CaEvent, CredentialInstance};
use heimdall_domain::lifecycle::GrantEvent;
use heimdall_domain::operation::OperationRecord;
use heimdall_domain::revocation::{
    CleanupIntent, ObligationKind, PendingRemoteRevocation, RemoteObligation, residual_step,
};
use heimdall_store::{LostInstances, StoreError, Txn};

use super::{
    Emit, OpError, Operations, complete_revocation_in, grant_to, load_remote_record, resource,
};
use crate::ports::{IssuerError, IssuerPort};

/// The `runtime_lifecycle` reason of an M03 operation left for the owner to
/// reconcile (m03-plan U0b row 17; ADR-0008 D5 §6.4). An event payload value, not
/// an error reason (wave-0 verify E8).
pub const OWNER_RECONCILE: &str = "owner_reconcile";

// -----------------------------------------------------------------------------
// Row 8: credential instances at restart
// -----------------------------------------------------------------------------

/// U0b row 8 (ADR-0008 D2 table; F18), inside restart recovery's first
/// transaction: [`Txn::mark_lost_instances`] with an empty live set (a process
/// that has just started holds no vault slot), then each lost instance's grant is
/// degraded `credential_reissue_pending` (an `active` grant moves to `degraded`; a
/// `degraded` one takes the reason, which has no key), with one
/// `credential_lifecycle` event per changed instance (`lost` or `destroyed`).
/// Grants in any other state are left as they are.
pub(super) fn mark_lost_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
) -> heimdall_store::Result<LostInstances> {
    let changed = tx.mark_lost_instances(&BTreeSet::new())?;
    for (instance, event) in changed
        .lost
        .iter()
        .map(|i| (i, CredentialLifecycleEvent::Lost))
        .chain(
            changed
                .destroyed
                .iter()
                .map(|i| (i, CredentialLifecycleEvent::Destroyed)),
        )
    {
        lifecycle_event(tx, emit, instance, event)?;
    }
    let grants: BTreeSet<GrantId> = changed.lost.iter().map(|i| i.grant.clone()).collect();
    let reason = DegradedReason::CredentialReissuePending;
    for gid in grants {
        let Some(mut g) = tx.grant(&gid)? else {
            continue;
        };
        match g.state {
            GrantState::Active => {
                grant_to(&mut g, GrantEvent::Degrade)?;
                tx.update_grant_state(&g)?;
                tx.set_grant_degradation(&g.id, reason)?;
                emit.grant_degraded(tx, &g, reason, None)?;
            }
            GrantState::Degraded if tx.grant_degradation(&g.id)? != Some(reason) => {
                tx.set_grant_degradation(&g.id, reason)?;
                emit.grant_degraded(tx, &g, reason, None)?;
            }
            _ => {}
        }
    }
    Ok(changed)
}

fn lifecycle_event(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    instance: &CredentialInstance,
    event: CredentialLifecycleEvent,
) -> heimdall_store::Result<()> {
    emit.event(
        tx,
        EventType::CredentialLifecycle,
        None,
        Some(resource("grant", &instance.grant)),
        serde_json::json!({
            "grant_id": instance.grant,
            "credential_instance_id": instance.id,
            "event": event,
        }),
    )
}

// -----------------------------------------------------------------------------
// Row 23: CA retirement at restart
// -----------------------------------------------------------------------------

/// The store-item step of a CA retirement (ADR-0008 D4 item 3: `unloaded →
/// deleted`). Implemented over the issuer crate's secret store (U3/U4:
/// `heimdall_issuer::retire::StoreItemDeletion`); production without one passes
/// `None`.
///
/// ⟨ADR-0008 §17.21 item 3; §17.17 item 3⟩ The step deletes **exactly the locator
/// this installation recorded** for the CA (`Txn::issuer_store_locator`), which
/// [`Operations::resume_ca_retirements`] reads and passes in: never an item found
/// by listing. Both methods default to a refusal (nothing deleted).
pub trait CaStoreItemDeletion: Send + Sync {
    /// Delete exactly the store item at `locator` (the recorded `StoreItemRef`
    /// locator of `ca`'s key in a store of kind `store`), then read the store again.
    /// `Ok` only when the re-read no longer finds that locator (an item already
    /// absent counts as deleted). Items of the same CA under other locators are
    /// never touched. Synchronous and bounded, like the issuer's `SecretStore`.
    ///
    /// # Errors
    /// The store is not of kind `store`, the locator does not name `ca`, the
    /// deletion or the re-read failed, or the item is still present (nonsecret
    /// reason). The default refuses, deleting nothing.
    fn delete_recorded(
        &self,
        ca: &CaFingerprint,
        store: StoreKind,
        locator: &str,
    ) -> Result<(), IssuerError> {
        let _ = (ca, store, locator);
        Err(IssuerError::Unavailable(NO_STORE_STEP.to_owned()))
    }

    /// ⟨superseded by [`CaStoreItemDeletion::delete_recorded`], §17.21 item 3⟩ The
    /// wave-0 shape, without the recorded locator. **Never called**: kept, defaulted
    /// to a refusal, only so implementations written before the ruling still compile
    /// (to be removed once none implements it).
    ///
    /// # Errors
    /// Always refuses by default (nothing deleted).
    fn delete_confirmed_absent(
        &self,
        ca: &CaFingerprint,
        store: StoreKind,
    ) -> Result<(), IssuerError> {
        let _ = (ca, store);
        Err(IssuerError::Unavailable(NO_STORE_STEP.to_owned()))
    }
}

/// What [`Operations::resume_ca_retirements`] did (U0b row 23).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetirementResume {
    /// Every registered CA that is neither `pending` nor `active` after the pass:
    /// the issuer child must not load any of them (D4 item 3: "told not to load a
    /// `retiring` CA"; the later states hold no key to load).
    pub do_not_load: BTreeSet<CaFingerprint>,
    /// Each step persisted, in order: `(CA, from, to)`.
    pub advanced: Vec<(CaFingerprint, CaState, CaState)>,
    /// CAs whose retirement stopped short of `retired` in this pass: `(CA, the
    /// state it stays in, nonsecret reason)`.
    pub stalled: Vec<(CaFingerprint, CaState, String)>,
}

/// Reason recorded when no issuer child is available to confirm an unload.
const NO_ISSUER: &str = "issuer_unavailable";
/// Reason recorded when no store-deletion step is available.
const NO_STORE_STEP: &str = "issuer_store_unavailable";
/// ⟨§17.21 item 3⟩ Reason recorded when the CA has no recorded store locator (a
/// record written before it, or none reported): nothing is deleted.
const NO_LOCATOR: &str = heimdall_contract::envelope::reason::ISSUER_STORE_LOCATOR_UNRECORDED;

// -----------------------------------------------------------------------------
// Row 6: bounded obligations
// -----------------------------------------------------------------------------

/// What [`Operations::settle_bounded_obligations`] did (U0b row 6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundedReport {
    /// `true` when the pass had safe time; on uncertain time nothing moved.
    pub safe: bool,
    /// Obligations whose status moved: `(root, grant, new status)`.
    pub moved: Vec<(GrantId, GrantId, ResidualStatus)>,
    /// Grants that reached `revoked` because every obligation on them is
    /// `bounded_complete` or `nominally_expired`.
    pub revoked: Vec<GrantId>,
    /// Records removed because every obligation left in them is `bounded_complete`.
    pub removed: Vec<GrantId>,
    /// ⟨ADR-0008 §17.15⟩ The `nominally_expired` obligations still on record after
    /// the pass, `(root, grant)`: their records are kept (never shown as cleared,
    /// §17.1 item 10) until a measurement, or a verified removal or rejection,
    /// settles them (a later unit; wave 0 has no path that does).
    pub nominally_expired: Vec<(GrantId, GrantId)>,
    /// The earliest wall instant at which a still-pending bounded obligation may
    /// move (evaluated now; a measured bound grows slowly with the measurement's
    /// age, and the next pass re-evaluates). `None` when none is pending.
    pub next_at: Option<Timestamp>,
}

/// Whether `o` is a `bounded_by_expiry` obligation that has settled
/// (`bounded_complete` or `nominally_expired`).
fn settled_bounded(o: &RemoteObligation) -> bool {
    matches!(
        &o.kind,
        ObligationKind::BoundedByExpiry {
            status: ResidualStatus::BoundedComplete | ResidualStatus::NominallyExpired,
            ..
        }
    )
}

/// Whether `o` is a `bounded_by_expiry` obligation whose status is `status`.
fn status_is(o: &RemoteObligation, status: ResidualStatus) -> bool {
    matches!(&o.kind, ObligationKind::BoundedByExpiry { status: s, .. } if *s == status)
}

/// Whether `o` is a `bounded_complete` obligation (the only kind a record may be
/// removed for; ADR-0008 §17.15).
fn bounded_complete(o: &RemoteObligation) -> bool {
    status_is(o, ResidualStatus::BoundedComplete)
}

/// The instant at which a pending bounded obligation may next move, evaluated at
/// `now` (`None` for any other obligation).
fn bounded_next_at(o: &RemoteObligation, now: Timestamp) -> Option<Timestamp> {
    let ObligationKind::BoundedByExpiry {
        latest_valid_before,
        clock,
        status: ResidualStatus::PendingUntil,
    } = &o.kind
    else {
        return None;
    };
    match clock {
        heimdall_contract::managed::DestinationClock::Measured(m) => {
            heimdall_domain::revocation::measured_completion_bound(*latest_valid_before, m, now)
        }
        _ => Some(*latest_valid_before),
    }
}

/// Whether `record` holds only `bounded_by_expiry` obligations (and at least one):
/// the supervisor's adapter rounds have nothing to do for it.
#[must_use]
pub fn only_bounded(record: &PendingRemoteRevocation) -> bool {
    !record.obligations.is_empty()
        && record
            .obligations
            .iter()
            .all(|o| !o.kind.is_needs_remote_action())
}

// -----------------------------------------------------------------------------
// Row 7: one cleanup intent, for the supervisor's back-off
// -----------------------------------------------------------------------------

/// What [`Operations::process_cleanup_intent_reporting`] observed (U0b row 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntentOutcome {
    /// Not processed: its attempt may still be in flight in this process (its
    /// preparation's return path processes it).
    Skipped,
    /// Processed, and no longer on record (or replaced by a newer version).
    Cleared,
    /// Processed and still on record: the call it owes was not made or not
    /// answered (an unconfigured applying adapter, a failed write, or, with a
    /// remote credential effect, a timed-out immediate call).
    Kept,
}

impl Operations {
    // -------------------------------------------------------------------------
    // Row 17
    // -------------------------------------------------------------------------

    /// ⟨M03⟩ U0b row 17 (ADR-0008 D5 §6.4; wave-0 verify E8): an M03 journaled
    /// operation found by a drive (restart recovery included) stays unresolved and
    /// untouched: no receipt, no state change. One additive `runtime_lifecycle`
    /// event names it, `{phase: unresolved, operation_id, kind, state, reason:
    /// owner_reconcile}`, so the owner reconciles it once the enrollment driver
    /// exists (U10). Never fails the drive.
    pub(super) async fn owner_reconcile_unresolved(
        &self,
        op: &OperationRecord,
    ) -> Result<(), OpError> {
        if op.state.is_settled() {
            return Ok(());
        }
        let payload = serde_json::json!({
            "phase": "unresolved",
            "operation_id": op.id,
            "kind": op.kind,
            "state": op.state,
            "reason": OWNER_RECONCILE,
        });
        let id = op.id.clone();
        self.write(move |tx, emit| {
            emit.event(
                tx,
                EventType::RuntimeLifecycle,
                Some(id.clone()),
                Some(resource("operation", &id)),
                payload,
            )?;
            Ok(())
        })
        .await
    }

    // -------------------------------------------------------------------------
    // Row 23
    // -------------------------------------------------------------------------

    /// ⟨M03⟩ U0b row 23 (ADR-0008 D4 item 3): resume every CA retirement left in
    /// `retiring`, `unloaded` or `deleted`, each step persisted (a compare-and-swap
    /// on the stored state) only after its external effect was confirmed:
    ///
    /// * `retiring → unloaded`: `issuer.unload(ca)` answered `Ok` (bounded by
    ///   `Limits::adapter_call_timeout` on top of the issuer's own bound);
    /// * `unloaded → deleted`: `store_items.delete_recorded` answered `Ok` for the
    ///   CA's **recorded** store locator (ADR-0008 §17.21 item 3); a CA without one
    ///   stays `unloaded`, stalled `issuer_store_locator_unrecorded`, nothing deleted;
    /// * `deleted → retired`: the store alone (nothing external is left).
    ///
    /// A missing port, a refusal or a timeout leaves the CA where it is (listed in
    /// `stalled`); it is never moved past a step whose effect is unconfirmed. A CA
    /// another writer moved meanwhile is skipped. Restart recovery calls this with
    /// `None, None` (wave 0 has no issuer child); every CA that is not `pending` or
    /// `active` is in `do_not_load`. Idempotent: a second call finds nothing more
    /// to do.
    ///
    /// # Errors
    /// The store cannot be read or written.
    pub async fn resume_ca_retirements(
        &self,
        issuer: Option<&dyn IssuerPort>,
        store_items: Option<&dyn CaStoreItemDeletion>,
    ) -> Result<RetirementResume, OpError> {
        let mut report = RetirementResume::default();
        let cas = self.write(|tx, _| tx.issuers()).await?;
        let limit = self.adapter_limit();
        for ca in cas {
            let fp = ca.ca_fingerprint.clone();
            let mut state = ca.state;
            loop {
                let (event, confirmed) = match state {
                    CaState::Retiring => {
                        let Some(issuer) = issuer else {
                            report
                                .stalled
                                .push((fp.clone(), state, NO_ISSUER.to_owned()));
                            break;
                        };
                        let answer = tokio::time::timeout(limit, issuer.unload(&fp)).await;
                        let confirmed = match answer {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(e)) => Err(issuer_reason(&e)),
                            Err(_) => Err("issuer_request_timeout".to_owned()),
                        };
                        (CaEvent::UnloadConfirmed, confirmed)
                    }
                    CaState::Unloaded => {
                        // ⟨§17.21 item 3; §17.17 item 3⟩ Exactly the locator this
                        // installation recorded; without one nothing is deleted and
                        // nothing is guessed (never an item found by listing).
                        let id = fp.clone();
                        let Some(locator) = self
                            .write(move |tx, _| tx.issuer_store_locator(&id))
                            .await?
                        else {
                            report
                                .stalled
                                .push((fp.clone(), state, NO_LOCATOR.to_owned()));
                            break;
                        };
                        let Some(items) = store_items else {
                            report
                                .stalled
                                .push((fp.clone(), state, NO_STORE_STEP.to_owned()));
                            break;
                        };
                        let confirmed = items
                            .delete_recorded(&fp, ca.store_kind, &locator)
                            .map_err(|e| issuer_reason(&e));
                        (CaEvent::StoreItemDeleted, confirmed)
                    }
                    CaState::Deleted => (CaEvent::RetirementRecorded, Ok(())),
                    // `pending`, `active`, `retired` (and any later state): nothing
                    // to resume.
                    _ => break,
                };
                if let Err(reason) = confirmed {
                    report.stalled.push((fp.clone(), state, reason));
                    break;
                }
                let at = self.inner.config.clock.wall();
                let (ca_id, from) = (fp.clone(), state);
                let moved = self
                    .write(move |tx, _| {
                        match tx.set_issuer_state(&ca_id, from, event, at) {
                            Ok(Ok(record)) => Ok(Some(record.state)),
                            // Refused by the table, or moved by another writer
                            // meanwhile: left alone.
                            Ok(Err(_)) | Err(StoreError::GenerationConflict(_)) => Ok(None),
                            Err(e) => Err(e),
                        }
                    })
                    .await?;
                let Some(next) = moved else {
                    break;
                };
                report.advanced.push((fp.clone(), state, next));
                state = next;
            }
            if !matches!(state, CaState::Pending | CaState::Active) {
                report.do_not_load.insert(fp);
            }
        }
        Ok(report)
    }

    // -------------------------------------------------------------------------
    // Row 6
    // -------------------------------------------------------------------------

    /// ⟨M03⟩ U0b row 6 (ADR-0008 D7 item 3; §17.1 item 10): one pass over every
    /// pending remote record, run by the supervisor's revocation pass. In one
    /// transaction, with time assessed by the shared gate inside it:
    ///
    /// * each `bounded_by_expiry` obligation still `pending_until` takes
    ///   [`residual_step`]`(o, safe_now)`, where `safe_now` is `None` on uncertain
    ///   time, so **nothing moves on uncertain time**. No adapter is called and no
    ///   attempt is counted (the record's and the obligation's counts are
    ///   untouched);
    /// * every grant all of whose obligations, in every record, are
    ///   `bounded_complete` or `nominally_expired` moves `revoking → revoked`;
    /// * ⟨ADR-0008 §17.15⟩ a record holding only `bounded_complete` obligations is
    ///   removed (nothing is left to do for it). A record holding any
    ///   `nominally_expired` obligation is **kept**, whatever else it holds: such an
    ///   obligation is never turned into `bounded_complete` and never shown as
    ///   cleared (§17.1 item 10). It blocks nothing else (its grant may still reach
    ///   `revoked`), and it stays visible through the existing reporting path
    ///   (`inspect grants` lists an ended grant while a record covers it; the pass
    ///   report lists it in [`BoundedReport::nominally_expired`]) until a
    ///   measurement, or a verified removal or rejection, settles it. That settle
    ///   path is a later unit's (U10): wave 0 has neither, and `residual_step` never
    ///   moves a `nominally_expired` status.
    ///
    /// Records with no bounded obligation are not written.
    ///
    /// # Errors
    /// The store cannot be read or written.
    pub async fn settle_bounded_obligations(&self) -> Result<BoundedReport, OpError> {
        let gate = self.inner.timegate.in_txn();
        self.write(move |tx, emit| {
            let safe_now = match gate.check(tx)? {
                Ok(s) => Some(s.wall()),
                Err(_) => None,
            };
            let mut report = BoundedReport {
                safe: safe_now.is_some(),
                ..BoundedReport::default()
            };
            let roots: Vec<GrantId> = tx
                .remote_revocations()?
                .into_iter()
                .filter(|r| {
                    r.obligations
                        .iter()
                        .any(|o| !o.kind.is_needs_remote_action())
                })
                .map(|r| r.root)
                .collect();
            let mut records: Vec<PendingRemoteRevocation> = Vec::new();
            for root in roots {
                let Some(mut r) = load_remote_record(tx, &root)? else {
                    continue;
                };
                let mut changed = false;
                for o in &mut r.obligations {
                    let next = residual_step(o, safe_now);
                    if let ObligationKind::BoundedByExpiry { status, .. } = &mut o.kind
                        && *status != next
                    {
                        *status = next;
                        changed = true;
                        report.moved.push((root.clone(), o.grant.clone(), next));
                    }
                    if let Some(now) = safe_now
                        && let Some(at) = bounded_next_at(o, now)
                    {
                        report.next_at = Some(report.next_at.map_or(at, |n| n.min(at)));
                    }
                }
                if changed {
                    tx.set_remote_revocation(&r)?;
                }
                records.push(r);
            }
            // Grants with a settled bounded obligation whose every obligation, in
            // every record, is settled that way.
            let all = tx.remote_revocations()?;
            let mut candidates: BTreeSet<GrantId> = BTreeSet::new();
            for r in &records {
                candidates.extend(
                    r.obligations
                        .iter()
                        .filter(|o| settled_bounded(o))
                        .map(|o| o.grant.clone()),
                );
            }
            let ready: Vec<GrantId> = candidates
                .into_iter()
                .filter(|g| {
                    all.iter().all(|r| {
                        r.obligations
                            .iter()
                            .filter(|o| &o.grant == g)
                            .all(settled_bounded)
                            && (!r.obligations.is_empty() || !r.grants.contains(g))
                    })
                })
                .collect();
            for r in &records {
                if !r.obligations.is_empty() && r.obligations.iter().all(bounded_complete) {
                    tx.clear_remote_revocation(&r.root)?;
                    report.removed.push(r.root.clone());
                }
                report.nominally_expired.extend(
                    r.obligations
                        .iter()
                        .filter(|o| status_is(o, ResidualStatus::NominallyExpired))
                        .map(|o| (r.root.clone(), o.grant.clone())),
                );
            }
            for gid in ready {
                if tx
                    .grant(&gid)?
                    .is_some_and(|g| g.state == GrantState::Revoking)
                {
                    report.revoked.push(gid);
                }
            }
            if !report.revoked.is_empty() {
                let revoked = report.revoked.clone();
                complete_revocation_in(tx, emit, &revoked, &BTreeSet::new(), None, None)?;
            }
            Ok(report)
        })
        .await
    }

    // -------------------------------------------------------------------------
    // Row 7
    // -------------------------------------------------------------------------

    /// ⟨M03⟩ U0b row 7 (ADR-0007 §12.13; ADR-0008 D7 item 5): whether any
    /// configured adapter declares a remote credential effect
    /// (`AdapterDescriptor::remote_credential_effect`; false for every M02
    /// adapter). The supervisor backs off kept cleanup intents only then.
    #[must_use]
    pub fn has_remote_effect_adapter(&self) -> bool {
        self.inner
            .config
            .adapters
            .iter()
            .any(|a| a.descriptor().remote_credential_effect)
    }

    /// ⟨M03⟩ U0b row 7: the cleanup intents on record (the supervisor's per-intent
    /// schedule reads them).
    ///
    /// # Errors
    /// The store cannot be read.
    pub async fn cleanup_intents(&self) -> Result<Vec<CleanupIntent>, OpError> {
        self.write(|tx, _| tx.cleanup_intents()).await
    }

    /// ⟨M03⟩ U0b row 7: process one cleanup intent exactly as
    /// `process_cleanup_intents` does for each (ADR-0006 §13.19 item 2), and report
    /// whether it was skipped (still in flight here), cleared or kept, so the
    /// supervisor can schedule a kept one's retry with bounded, jittered back-off.
    pub async fn process_cleanup_intent_reporting(&self, intent: CleanupIntent) -> IntentOutcome {
        if intent.in_flight && self.is_preparing(&intent.operation) {
            return IntentOutcome::Skipped;
        }
        let (g, op, version) = (
            intent.grant.clone(),
            intent.operation.clone(),
            intent.version,
        );
        self.process_cleanup_intent(intent, false).await;
        match self.write(move |tx, _| tx.cleanup_intent(&g, &op)).await {
            Ok(Some(i)) if i.version == version => IntentOutcome::Kept,
            Ok(_) => IntentOutcome::Cleared,
            // Unreadable: treated as kept (fail closed; it is retried later).
            Err(_) => IntentOutcome::Kept,
        }
    }
}

/// A nonsecret reason for an issuer-side failure (no payload text: the issuer's
/// strings are bounded and redacted already, but only the category is recorded).
fn issuer_reason(e: &IssuerError) -> String {
    match e {
        IssuerError::Refused(_) => "issuer_refused",
        IssuerError::Unavailable(_) => NO_ISSUER,
        IssuerError::Timeout => "issuer_request_timeout",
        IssuerError::Protocol(_) => "issuer_protocol_error",
    }
    .to_owned()
}
