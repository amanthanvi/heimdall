//! ⟨M03⟩ wave 4 (U10): the store side of the managed effect driver (ADR-0008 D6 item
//! 1; U0b row 21), the credential instances (U2-Q1), the signer's install view (U2-Q2;
//! D2 item 6), the supervisor's `managed_reissue_pass` body (U0b row 8; D6 item 4), the
//! cleanup after a narrowing's gates are released (D7 item 2 step 4; U0b row 20 (10)),
//! and the degradation of the grants under a removed CA (ADR-0008 §17.3 item 3, R7).
//!
//! [`Operations::managed_prepared`] is called by the ensure pipeline after
//! `read_sources` and **before** the bounded `prepare_from`, for the managed adapter
//! only; its result becomes `IntegrationSnapshot.managed.prepared`. Every store
//! transaction here is its own `Operations::write`, outside any adapter bound.
//!
//! **Credential instances (U2-Q1).** One row per K_env, written `pending` when the key
//! is registered ([`Operations::managed_instance_created`]), `installed` when every
//! pair's certificate is installed, `destroyed` when the key is destroyed. A new
//! instance's ID is derived from K_env's SHA-256 fingerprint ([`instance_id_for`]: the
//! first 16 bytes of the digest; stable, so a repeated creation for the same key is
//! idempotent); ⟨§17.21 item 7⟩ the instances of a grant are always found through the
//! store query `Txn::credential_instances_for_grant`, never from a fingerprint. The creation of
//! an instance **retains** the grant's signing gate (with the grant's ancestor chain);
//! the release of an instance takes the gate **exclusively**
//! (`SigningGates::release_exclusive`; §17.15 item 1, G-Q13). A `lost` instance (from
//! before a restart) holds no gate in this process, so destroying it releases none.

use std::sync::Arc;

use heimdall_contract::event::EventType;
use heimdall_contract::ids::{CaFingerprint, CredentialInstanceId, GrantId, IssuanceId};
use heimdall_contract::managed::CredentialLifecycleEvent;
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::grant::{DegradedReason, GrantSnapshot};
use heimdall_domain::issuance::{
    CredentialInstance, CredentialState, IssuanceEntry, IssuanceState,
};
use heimdall_domain::lifecycle::GrantEvent;
use heimdall_domain::operation::{EffectReceipt, StageReceipt};
use heimdall_domain::scope::AccessPair;
use heimdall_domain::time::{self as dtime, Admission, TimeStatus};
use heimdall_store::Txn;

use super::ca_issuance_m03::grant_is_managed;
use super::{
    Emit, MANAGED_CERTIFICATE, MAX_ANCESTRY, Operations, bound_of, conflict, grant_context,
    grant_try, internal, narrowing, put_grant, resource, revalidate_chain,
};
use crate::error::OpError;
use crate::managed::driver::instance_id_for;
use crate::ports::{
    AdapterError, CredentialAdapter, IntegrationSnapshot, KeyRegistration, ManagedPrepared,
    PrepareRequest,
};

/// The install view's refusal codes (`InstallRefusal::View`; D2 item 6).
pub mod install_refusal {
    /// The store could not be read.
    pub const STORE: &str = "store";
    /// Time is not `Safe`.
    pub const TIME_UNCERTAIN: &str = "time_uncertain";
    /// The grant does not exist.
    pub const NO_GRANT: &str = "no_grant";
    /// The grant is not `preparing`, `active` or `degraded`.
    pub const GRANT_NOT_USABLE: &str = "grant_not_usable";
    /// A tombstone covers the grant or an ancestor.
    pub const TOMBSTONED: &str = "tombstoned";
    /// The deadline (or cutoff, or continuous budget) passed, or the certificate
    /// outlives the grant's bound.
    pub const DEADLINE_PASSED: &str = "deadline_passed";
    /// The authority generation moved and the chain no longer re-validates.
    pub const STALE_GENERATION: &str = "stale_generation";
    /// The stored entry is not this published entry of this grant.
    pub const ENTRY_MISMATCH: &str = "entry_mismatch";
}

/// The ancestor chain of `grant`, **root first, parent last** (the shape
/// `SigningGates::retain` records).
fn ancestors_root_first(
    tx: &mut Txn<'_>,
    grant: &GrantSnapshot,
) -> heimdall_store::Result<Vec<GrantId>> {
    let mut chain = Vec::new();
    let mut next = grant.parent.clone();
    while let Some(id) = next {
        if chain.len() >= MAX_ANCESTRY {
            return Err(heimdall_store::StoreError::Corrupt(
                "grant ancestry is too deep".into(),
            ));
        }
        next = tx.grant(&id)?.and_then(|g| g.parent);
        chain.push(id);
    }
    chain.reverse();
    Ok(chain)
}

/// The credential instances of `grant` this store records (ADR-0008 §17.21 item 7:
/// the store query, never an ID derived from a key fingerprint).
fn instances_of(
    tx: &mut Txn<'_>,
    grant: &GrantId,
) -> heimdall_store::Result<Vec<CredentialInstance>> {
    tx.credential_instances_for_grant(grant)
}

fn lifecycle_event(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    grant: &GrantId,
    instance: &CredentialInstanceId,
    event: CredentialLifecycleEvent,
) -> heimdall_store::Result<()> {
    emit.event(
        tx,
        EventType::CredentialLifecycle,
        None,
        Some(resource("grant", grant)),
        serde_json::json!({
            "grant_id": grant,
            "credential_instance_id": instance,
            "event": event,
        }),
    )
}

/// What the installation check of D2 item 6 found (in the read transaction).
fn install_check_in(
    tx: &mut Txn<'_>,
    ops: &InstallCtx,
    grant: &GrantId,
    entry: &IssuanceEntry,
) -> heimdall_store::Result<Result<(), &'static str>> {
    let Some(safe) = ops.gate.assess_read_only(tx)?.2 else {
        return Ok(Err(install_refusal::TIME_UNCERTAIN));
    };
    let Some(g) = tx.grant(grant)? else {
        return Ok(Err(install_refusal::NO_GRANT));
    };
    if !g.state.permits_issuance() {
        return Ok(Err(install_refusal::GRANT_NOT_USABLE));
    }
    if tx.denied_ancestor(grant)?.is_some() || tx.tombstone(grant)?.is_some() {
        return Ok(Err(install_refusal::TOMBSTONED));
    }
    let ctx = grant_context(tx, &g)?;
    let bound = bound_of(tx, &ops.env, &g, ctx.profile.as_ref())?;
    let now = safe.wall();
    if dtime::is_expired(now, bound)
        || entry.bounds.valid_before > bound
        || (g.state != GrantState::Preparing
            && ops.gate.admission(tx, grant, &safe)? != Admission::Open)
    {
        return Ok(Err(install_refusal::DEADLINE_PASSED));
    }
    let Some(stored) = tx.issuance_entry(&entry.id)? else {
        return Ok(Err(install_refusal::ENTRY_MISMATCH));
    };
    if stored.state != IssuanceState::Published
        || stored.grant != *grant
        || stored.pair != entry.pair
        || stored.bounds != entry.bounds
        || stored.generation != entry.generation
    {
        return Ok(Err(install_refusal::ENTRY_MISMATCH));
    }
    // The generation: a moved one re-validates the chain (ADR-0006 §13.5 ruling 2).
    if tx.authority_generation()? != stored.generation
        && revalidate_chain(tx, &ops.env, &ops.adapters, &g, now)?.is_err()
    {
        return Ok(Err(install_refusal::STALE_GENERATION));
    }
    Ok(Ok(()))
}

struct InstallCtx {
    gate: crate::timegate::TxnGate,
    env: heimdall_contract::ids::EnvironmentId,
    adapters: Vec<super::AdapterInfo>,
}

impl Operations {
    /// The effect driver's results for `adapter`'s preparation, or `None` when
    /// `adapter` is not the managed adapter (the M01/M02 path is unchanged) or the
    /// driver is not wired (the adapter's `prepare_from` then refuses without driver
    /// results).
    pub(super) async fn managed_prepared(
        &self,
        adapter: &Arc<dyn CredentialAdapter>,
        req: PrepareRequest<'_>,
    ) -> Option<Result<ManagedPrepared, AdapterError>> {
        if adapter.descriptor().mechanism() != MANAGED_CERTIFICATE {
            return None;
        }
        // Unwired (no effects or no issuer): no driver results. The managed adapter's
        // `prepare_from` then refuses (`MANAGED_PREPARE_WITHOUT_DRIVER`, the same
        // error arm), so nothing is activated; an `ensure` naming a managed preference
        // was refused before admission already (`ensure_precheck`).
        let wiring = self.managed_wiring()?;
        let (Some(effects), Some(issuer)) = (wiring.effects.clone(), wiring.issuer.clone()) else {
            return None;
        };
        Some(crate::managed::drive_preparation(self, effects.as_ref(), issuer.as_ref(), req).await)
    }

    /// The ensure pipeline's hook (U0b row 21): for the managed adapter, run the effect
    /// driver ([`Self::managed_prepared`]) and put its results into `sources`
    /// (`IntegrationSnapshot.managed.prepared`); a driver failure is returned and takes
    /// the same arms as a failed `prepare_from`. For any other adapter nothing happens
    /// (the existing-access contract is unchanged: `operations.rs` itself never names
    /// the snapshot's managed field).
    pub(super) async fn run_effect_driver(
        &self,
        adapter: &Arc<dyn CredentialAdapter>,
        req: PrepareRequest<'_>,
        sources: &mut IntegrationSnapshot,
    ) -> Result<(), AdapterError> {
        match self.managed_prepared(adapter, req).await {
            None => Ok(()),
            Some(Err(e)) => Err(e),
            Some(Ok(prepared)) => {
                sources
                    .managed
                    .get_or_insert_with(Default::default)
                    .prepared = Some(prepared);
                Ok(())
            }
        }
    }

    /// Whether the managed effect driver can run here: the wiring carries both the
    /// effects and the issuer client. Without them every managed path fails closed.
    #[must_use]
    pub fn managed_driver_wired(&self) -> bool {
        self.managed_wiring()
            .is_some_and(|w| w.effects.is_some() && w.issuer.is_some())
    }

    /// The bound of one driver effect the port does not bound itself (the M02 adapter
    /// call bound).
    pub(crate) fn managed_effect_limit(&self) -> std::time::Duration {
        self.adapter_limit()
    }

    /// ⟨U2-Q1⟩ Record K_env's credential instance `pending` for `grant` and retain the
    /// grant's signing gate (the gate is created with the first instance and records
    /// the grant's ancestor chain). Refused, with nothing written, for a grant that
    /// cannot be issued for (missing, ended, or under a tombstone). Idempotent for the
    /// same key: a second call finds the `pending` row and retains nothing more.
    ///
    /// # Errors
    /// [`OpError`]: the refusal, or a store failure (the gate retained for it is
    /// released again).
    pub(crate) async fn managed_instance_created(
        &self,
        grant: &GrantId,
        key: &KeyRegistration,
    ) -> Result<CredentialInstanceId, OpError> {
        let id = instance_id_for(&key.fingerprint)
            .ok_or_else(|| internal("the key fingerprint has no SHA-256 form"))?;
        let (gid, iid, handle) = (grant.clone(), id.clone(), key.slot.clone());
        let gates = self.signing_gates().clone();
        let retained = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&retained);
        let r = self
            .write(move |tx, _| {
                let Some(g) = tx.grant(&gid)? else {
                    return Ok(Err(
                        OpError::new(Code::NotFound, "unknown grant").with_resource("grant", None)
                    ));
                };
                if !g.state.permits_issuance() || tx.denied_ancestor(&gid)?.is_some() {
                    return Ok(Err(OpError::new(
                        Code::CredentialExpired,
                        "the grant can no longer be issued for",
                    )
                    .with_resource("grant", Some(gid.to_string()))));
                }
                match tx.credential_instance(&iid)? {
                    Some(i) if i.grant == gid && i.state == CredentialState::Pending => {
                        return Ok(Ok(()));
                    }
                    Some(_) => return Err(conflict("credential instance already recorded")),
                    None => {}
                }
                // The gate first (§17.15 item 1): a narrowing reading the set from now
                // on sees it and takes the full protocol.
                let ancestors = ancestors_root_first(tx, &g)?;
                gates.retain(&gid, &ancestors);
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                tx.insert_credential_instance(&CredentialInstance {
                    id: iid.clone(),
                    grant: gid.clone(),
                    key_handle_ref: handle,
                    certificates: Vec::new(),
                    state: CredentialState::Pending,
                })?;
                Ok(Ok(()))
            })
            .await;
        match r {
            Ok(Ok(())) => Ok(id),
            Ok(Err(e)) => Err(e),
            Err(e) => {
                if retained.load(std::sync::atomic::Ordering::SeqCst) {
                    self.signing_gates().release_exclusive(grant).await;
                }
                Err(e)
            }
        }
    }

    /// ⟨U2-Q1⟩ Every pair's certificate is installed: the instance becomes `installed`
    /// with its entries, with its `credential_lifecycle` event.
    ///
    /// # Errors
    /// A store failure, or an instance that is not `pending`/`installed`.
    pub(crate) async fn managed_instance_installed(
        &self,
        instance: &CredentialInstanceId,
        certificates: Vec<IssuanceId>,
    ) -> Result<(), OpError> {
        let iid = instance.clone();
        self.write(move |tx, emit| {
            let Some(mut i) = tx.credential_instance(&iid)? else {
                return Err(conflict("credential instance missing"));
            };
            if !matches!(
                i.state,
                CredentialState::Pending | CredentialState::Installed
            ) {
                return Err(conflict("credential instance is not pending"));
            }
            let first = i.state == CredentialState::Pending;
            i.state = CredentialState::Installed;
            i.certificates = certificates;
            tx.update_credential_instance(&i)?;
            if first {
                lifecycle_event(
                    tx,
                    emit,
                    &i.grant,
                    &iid,
                    CredentialLifecycleEvent::Installed,
                )?;
            }
            Ok(())
        })
        .await
    }

    /// ⟨U2-Q1⟩ The instance's key is destroyed: the row becomes `destroyed` (absorbing)
    /// with its event, and, when it was live in this process (`pending` or
    /// `installed`), the grant's gate is released **exclusively** (§17.15 item 1).
    /// Returns whether this call moved it. Never call it while holding the grant's
    /// gate (a narrowing calls it after its gates are released).
    ///
    /// # Errors
    /// A store failure.
    pub(crate) async fn managed_instance_destroyed(
        &self,
        instance: &CredentialInstanceId,
    ) -> Result<bool, OpError> {
        let iid = instance.clone();
        let moved = self
            .write(move |tx, emit| {
                let Some(mut i) = tx.credential_instance(&iid)? else {
                    return Ok(None);
                };
                let live = matches!(
                    i.state,
                    CredentialState::Pending | CredentialState::Installed
                );
                if i.state == CredentialState::Destroyed {
                    return Ok(None);
                }
                i.state = CredentialState::Destroyed;
                tx.update_credential_instance(&i)?;
                lifecycle_event(
                    tx,
                    emit,
                    &i.grant,
                    &iid,
                    CredentialLifecycleEvent::Destroyed,
                )?;
                Ok(Some((i.grant, live)))
            })
            .await?;
        let Some((grant, live)) = moved else {
            return Ok(false);
        };
        if live {
            self.signing_gates().release_exclusive(&grant).await;
        }
        Ok(true)
    }

    /// ⟨U0b row 21⟩ A stage receipt between two effects of the driver, on the open
    /// operation whose preparation attempt carries `token` (its `Attempted` receipt).
    /// Without such an operation (the re-issue pass) nothing is written.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) async fn managed_stage_receipt(
        &self,
        token: &str,
        stage_name: &'static str,
    ) -> Result<(), OpError> {
        let token = token.to_owned();
        let now = self.inner.config.clock.wall();
        self.write(move |tx, _| {
            for op in tx.open_operations()? {
                let receipts = tx.stage_receipts(&op.id)?;
                let adapter = receipts.iter().rev().find_map(|r| match &r.effect {
                    EffectReceipt::Attempted {
                        adapter,
                        effect_token,
                    } if *effect_token == token => Some(adapter.clone()),
                    _ => None,
                });
                if let Some(adapter) = adapter {
                    tx.append_stage_receipt(
                        &op.id,
                        &StageReceipt {
                            stage: stage_name.to_owned(),
                            recorded_at: now,
                            effect: EffectReceipt::Attempted {
                                adapter,
                                effect_token: token.clone(),
                            },
                            local: None,
                        },
                    )?;
                    break;
                }
            }
            Ok(())
        })
        .await
    }

    /// ⟨U2-Q2⟩ D2 item 6's read transaction for the signer's install check of the
    /// published `entry` for `grant`: time `Safe` (the read-only assessment), the grant
    /// `preparing`, `active` or `degraded`, no tombstone on it or an ancestor, its bound
    /// (deadline, cutoff, ancestors) not passed and not earlier than the certificate's
    /// `valid_before`, the continuous budget open (a grant past its first validation),
    /// the stored entry exactly this published one, and, when the authority generation
    /// moved since, the chain re-validated. Runtime wraps it as
    /// `heimdall_credential::table::InstallView`.
    ///
    /// # Errors
    /// The refusal's nonsecret code ([`install_refusal`]).
    pub async fn managed_install_check(
        &self,
        grant: &GrantId,
        entry: &IssuanceEntry,
    ) -> Result<(), &'static str> {
        let ctx = InstallCtx {
            gate: self.inner.timegate.in_txn(),
            env: self.inner.config.environment.clone(),
            adapters: self.adapter_infos(),
        };
        let (gid, e) = (grant.clone(), entry.clone());
        match self
            .write(move |tx, _| install_check_in(tx, &ctx, &gid, &e))
            .await
        {
            Ok(r) => r,
            Err(_) => Err(install_refusal::STORE),
        }
    }

    /// The body of the supervisor's `managed_reissue_pass` (U0b row 8; ADR-0008 D6
    /// item 4): re-issue each `managed_certificate` grant degraded
    /// `credential_reissue_pending` whose stored grant is still eligible, through the
    /// same stages (key, reserve, sign, publish, install) as an activation, as
    /// continuing work (`new_activation: false`): same pairs, same deadline. Never for
    /// an ended or tombstoned grant, past its bound or cutoff, on time that is not
    /// `Safe` (it stays `credential_reissue_pending` until time is accepted), or for a
    /// `revoke_on_lock` grant: exactly when [`heimdall_domain::reissue::eligible`]
    /// refuses (§17.21 item 6). A no-op while the driver is unwired. Returns the grants
    /// re-issued.
    ///
    /// # Errors
    /// [`OpError`]: a store failure is reported (W3-R11), never an empty success.
    pub async fn managed_reissue_pass(&self) -> Result<Vec<GrantId>, OpError> {
        let Some(wiring) = self.managed_wiring() else {
            return Ok(Vec::new());
        };
        let (Some(effects), Some(issuer)) = (wiring.effects.clone(), wiring.issuer.clone()) else {
            return Ok(Vec::new());
        };
        let candidates = self.reissue_candidates().await?;
        let mut done = Vec::new();
        for gid in candidates {
            // ⟨§17.21 item 6⟩ The one rule (`heimdall_domain::reissue::eligible`),
            // rule 5 included (the effective lock behaviour with the R3 floor, as
            // `Operations::lock_blocks_reissue` computes it).
            let Some((grant, now)) = self.reissue_eligible(&gid).await? else {
                continue;
            };
            let token =
                crate::ids::new_effect_token().map_err(|_| internal("randomness unavailable"))?;
            let driven = crate::managed::driver::run_stages(
                self,
                effects.as_ref(),
                issuer.as_ref(),
                &grant,
                &token,
                now,
                false,
            )
            .await;
            let Ok(prepared) = driven else {
                // The grant stays `credential_reissue_pending`; the next pass retries.
                continue;
            };
            if self.reissue_completed(&gid, &prepared.instance).await? {
                done.push(gid);
            }
        }
        Ok(done)
    }

    /// The managed grants degraded `credential_reissue_pending`.
    async fn reissue_candidates(&self) -> Result<Vec<GrantId>, OpError> {
        self.write(|tx, _| {
            let mut out = Vec::new();
            for g in tx.grants_due(Timestamp::MAX)? {
                if g.state == GrantState::Degraded
                    && tx.grant_degradation(&g.id)?
                        == Some(DegradedReason::CredentialReissuePending)
                    && grant_is_managed(tx, &g.id)?
                {
                    out.push(g.id);
                }
            }
            Ok(out)
        })
        .await
    }

    /// The stored grant, bounded by its recorded bound, when it may re-issue now.
    /// ⟨§17.21 item 6⟩ The rule is the one pure implementation,
    /// [`heimdall_domain::reissue::eligible`] (the managed adapter's `reissue_from`
    /// asks the same function); this only reads its inputs in one store transaction:
    /// the stored grant (rule 4: `GrantSource::Store`) bounded by its ancestors, every
    /// applicable cutoff and its persisted anchor bound; its origin; the tombstones of
    /// it and its ancestors; the gate's verdict; the admission check (after the first
    /// validation in this boot re-anchors it from `Safe` time, as every use does); and
    /// the effective lock behaviour with the R3 floor. A grant that is no longer a
    /// candidate (`degraded`, `credential_reissue_pending`) is skipped.
    async fn reissue_eligible(
        &self,
        grant: &GrantId,
    ) -> Result<Option<(GrantSnapshot, Timestamp)>, OpError> {
        use heimdall_domain::reissue::{GrantSource, StoreRead, eligible};
        let gate = self.inner.timegate.in_txn();
        let env = self.inner.config.environment.clone();
        let floor = self.session_lock_floor();
        let clock = Arc::clone(&self.inner.config.clock);
        let gid = grant.clone();
        self.write(move |tx, _| {
            let (Some(mut g), Some(origin)) = (tx.grant(&gid)?, tx.grant_origin(&gid)?) else {
                return Ok(None);
            };
            if g.state != GrantState::Degraded
                || tx.grant_degradation(&gid)? != Some(DegradedReason::CredentialReissuePending)
            {
                return Ok(None);
            }
            let policies = tx.policies_for(&origin.profile, &env)?;
            let lock = crate::lock::effective_behavior_with_floor(Some(&origin), &policies, floor);
            let cutoff_at = super::merged_policy(&policies).and_then(|p| p.cutoff_at);
            let tombstoned = tx.denied_ancestor(&gid)?.is_some();
            let bound = bound_of(tx, &env, &g, Some(&origin.profile))?;
            g.deadline.effective = g.deadline.effective.min(bound);
            let (time, admission, now) = match gate.check(tx)? {
                Ok(safe) => {
                    let now = safe.wall();
                    if !tombstoned && !dtime::is_expired(now, bound) {
                        super::first_validation_anchor(tx, &gate, &gid, &safe, bound)?;
                    }
                    (TimeStatus::Safe, gate.admission(tx, &gid, &safe)?, now)
                }
                // Not accepted: the rule refuses (`time_not_accepted`, or an earlier
                // rule); the wall reading is not trusted for anything else.
                Err(u) => (
                    TimeStatus::Uncertain(u),
                    Admission::NeedsAnchor,
                    clock.wall(),
                ),
            };
            let read = StoreRead {
                source: GrantSource::Store,
                tombstoned,
                cutoff_at,
                now,
            };
            Ok(eligible(&g, &origin, &time, &admission, lock, &read)
                .ok()
                .map(|()| (g, now)))
        })
        .await
    }

    /// After a re-issue: the grant's `lost` instances become `destroyed` (no gate in
    /// this process), and the grant returns to `active` (`credential_reissue_pending`
    /// repaired), with the `reissued` event. `false` when the grant moved meanwhile.
    async fn reissue_completed(
        &self,
        grant: &GrantId,
        instance: &CredentialInstanceId,
    ) -> Result<bool, OpError> {
        let (gid, iid) = (grant.clone(), instance.clone());
        self.write(move |tx, emit| {
            for mut i in instances_of(tx, &gid)? {
                if i.state == CredentialState::Lost {
                    i.state = CredentialState::Destroyed;
                    tx.update_credential_instance(&i)?;
                    lifecycle_event(tx, emit, &gid, &i.id, CredentialLifecycleEvent::Destroyed)?;
                }
            }
            let Some(mut g) = tx.grant(&gid)? else {
                return Ok(false);
            };
            if g.state != GrantState::Degraded
                || tx.grant_degradation(&gid)? != Some(DegradedReason::CredentialReissuePending)
                || !grant_try(&mut g, GrantEvent::Repaired)
            {
                return Ok(false);
            }
            put_grant(tx, emit, &g, None)?;
            lifecycle_event(tx, emit, &gid, &iid, CredentialLifecycleEvent::Reissued)?;
            Ok(true)
        })
        .await
    }

    /// ⟨wave 4, U10C-Q3⟩ D7 item 2 step 2 / U0b row 20 (10): while the narrowing
    /// still holds the gates, zeroize and unlist K_env of every destroyed grant
    /// (`ManagedEffects::destroy`: in-memory only; it takes no gate). Bounded by the
    /// adapter call limit; a failure is retried after the release.
    pub(super) async fn managed_destroy_under_gates(&self, grants: &[GrantId]) {
        if grants.is_empty() {
            return;
        }
        if let Some(effects) = self.managed_wiring().and_then(|w| w.effects.clone())
            && tokio::time::timeout(self.adapter_limit(), effects.destroy(grants))
                .await
                .is_err()
        {
            tracing::warn!(
                "managed keys not destroyed under the gates in time; retried after release"
            );
        }
    }

    /// ⟨U0b row 20 (10); D7 item 2 step 4⟩ The managed part of a narrowing's cleanup,
    /// run after every gate is released: K_env of each grant in `grants` is destroyed
    /// in the signer (idempotent; the in-memory destruction, through the wired
    /// effects), and each of its live credential instances becomes `destroyed`,
    /// releasing the gate exclusively. The slot and binding files and the owned
    /// connections follow in the managed adapter's `revoke` of the same revocation
    /// round (the runtime's cleanup), also outside every gate. A failure here is
    /// logged and left to that round and the restart recovery (the denial holds from
    /// the commit).
    pub(super) async fn managed_after_narrowing(&self, grants: &[GrantId]) {
        if grants.is_empty() {
            return;
        }
        // Idempotent repeat of the under-gates destruction (a timed-out one is retried
        // here, outside every gate).
        if let Some(effects) = self.managed_wiring().and_then(|w| w.effects.clone()) {
            let _ = tokio::time::timeout(self.adapter_limit(), effects.destroy(grants)).await;
        }
        for g in grants {
            let gid = g.clone();
            let live = self
                .write(move |tx, _| {
                    Ok(instances_of(tx, &gid)?
                        .into_iter()
                        .filter(|i| {
                            matches!(
                                i.state,
                                CredentialState::Pending | CredentialState::Installed
                            )
                        })
                        .map(|i| i.id)
                        .collect::<Vec<_>>())
                })
                .await;
            let Ok(live) = live else {
                tracing::warn!("managed cleanup: the credential instances could not be read");
                continue;
            };
            for i in live {
                if self.managed_instance_destroyed(&i).await.is_err() {
                    tracing::warn!("managed cleanup: a credential instance could not be updated");
                }
            }
        }
    }

    /// ⟨ADR-0008 §17.3 item 3, reading R7; for U10-A's enrollment removal⟩ Degrade
    /// every live `managed_certificate` grant that holds a `reserved` or `published`
    /// certificate for `pair` under `ca` (the set `report::grants_under_ca` names),
    /// through the narrowing protocol (U0b row 20: the set's gates exclusively before
    /// the commit). An `active` grant becomes `degraded` (`pair_unenrolled`, which
    /// still signs with the installed key for the other pairs; the server refuses the
    /// unenrolled pair itself); a `degraded` one takes the reason. Nothing is
    /// destroyed. Returns the grants degraded.
    ///
    /// # Errors
    /// A store failure.
    pub async fn degrade_grants_under_ca(
        &self,
        ca: &CaFingerprint,
        pair: &AccessPair,
    ) -> Result<Vec<GrantId>, OpError> {
        let requested_at = self.narrowing_now().await;
        let (ca1, pair1) = (ca.clone(), pair.clone());
        let reader: narrowing::SetReader =
            Arc::new(move |tx: &mut Txn<'_>| grants_under_ca_in(tx, &ca1, &pair1));
        let (ca2, pair2) = (ca.clone(), pair.clone());
        let narrowed = self
            .narrow(
                narrowing::NarrowingKind::Enrollment,
                requested_at,
                reader,
                move |tx, emit, _ctx| {
                    let reason = DegradedReason::PairUnenrolled;
                    let mut out = Vec::new();
                    for gid in grants_under_ca_in(tx, &ca2, &pair2)? {
                        let Some(mut g) = tx.grant(&gid)? else {
                            continue;
                        };
                        match g.state {
                            GrantState::Active => {
                                if grant_try(&mut g, GrantEvent::Degrade) {
                                    tx.update_grant_state(&g)?;
                                    tx.set_grant_degradation(&g.id, reason)?;
                                    emit.grant_degraded(tx, &g, reason, None)?;
                                    out.push(gid);
                                }
                            }
                            GrantState::Degraded
                                if tx.grant_degradation(&gid)?
                                    == Some(DegradedReason::CredentialReissuePending) => {}
                            GrantState::Degraded => {
                                tx.set_grant_degradation(&gid, reason)?;
                                emit.grant_degraded(tx, &g, reason, None)?;
                                out.push(gid);
                            }
                            _ => {}
                        }
                    }
                    Ok(out)
                },
            )
            .await?;
        Ok(narrowed.value)
    }
}

/// The live managed grants with a `reserved` or `published` entry for `pair` under
/// `ca` (R7's set, read in `tx`).
fn grants_under_ca_in(
    tx: &mut Txn<'_>,
    ca: &CaFingerprint,
    pair: &AccessPair,
) -> heimdall_store::Result<Vec<GrantId>> {
    let mut out = Vec::new();
    for g in tx.grants_due(Timestamp::MAX)? {
        if !matches!(
            g.state,
            GrantState::Active | GrantState::Degraded | GrantState::Preparing
        ) || !grant_is_managed(tx, &g.id)?
        {
            continue;
        }
        let under = tx.issuance_entries(&g.id)?.into_iter().any(|e| {
            e.pair == *pair
                && e.bounds.ca_fingerprint.as_ref() == Some(ca)
                && matches!(e.state, IssuanceState::Reserved | IssuanceState::Published)
        });
        if under {
            out.push(g.id);
        }
    }
    Ok(out)
}

/// ⟨D7 item 2 steps 5–6; F15⟩ The managed part of a revoke result, in the settling
/// transaction: when any grant of the cascade is `managed_certificate`, the
/// adapter's per-pair rows (`remote_effects`, as the round carried them from its
/// `RevokeOutcome`), every owned connection of the cascade as the store shows it now
/// (after the cleanup's closes), and the fixed note `ordinary_connections_not_closed`.
/// An M01/M02 cascade's result is unchanged.
pub(super) fn fill_revoke_data(
    tx: &mut Txn<'_>,
    grants: &[GrantId],
    data: &mut heimdall_contract::request::RevokeData,
    remote_effects: Vec<heimdall_contract::managed::RemoteEffectReport>,
) -> heimdall_store::Result<()> {
    use heimdall_contract::managed::{
        OwnedConnectionReport, OwnedConnectionReportState, RevokeNote,
    };
    use heimdall_domain::managed::OwnedConnectionState;
    let mut managed = false;
    for g in grants {
        managed |= grant_is_managed(tx, g)?;
    }
    if !managed {
        return Ok(());
    }
    data.remote_effects = remote_effects;
    let mut rows = Vec::new();
    for g in grants {
        rows.extend(tx.owned_connections_for_grant(g)?);
    }
    data.owned_connections = rows
        .iter()
        .map(|c| OwnedConnectionReport {
            id: c.id.clone(),
            kind: c.kind,
            state: match c.state {
                OwnedConnectionState::Closed => OwnedConnectionReportState::Closed,
                OwnedConnectionState::Unverified => OwnedConnectionReportState::Unverified,
                _ => OwnedConnectionReportState::Closing,
            },
        })
        .collect();
    data.notes = vec![RevokeNote::OrdinaryConnectionsNotClosed];
    Ok(())
}

impl Operations {
    /// ⟨D7 item 7⟩ After the last reference of `grant` was released: when it is a
    /// `managed_certificate` grant, its keys and live instances are destroyed (as a
    /// narrowing's cleanup does) and its responsible adapter's `revoke` runs, bounded,
    /// for the files and the owned connections (the runtime's cleanup applies the
    /// release rule: masters closed, dedicated connections by the policy). A failure
    /// is logged; the supervisor's passes close what is left.
    pub(super) async fn after_release_m03(&self, grant: &GrantId, now: Timestamp) {
        let gid = grant.clone();
        let identity = self
            .write(move |tx, _| {
                if !grant_is_managed(tx, &gid)? {
                    return Ok(None);
                }
                Ok(tx.grant_origin(&gid)?.and_then(|o| o.adapter))
            })
            .await;
        let identity = match identity {
            Ok(Some(i)) => i,
            Ok(None) => return,
            Err(_) => {
                tracing::warn!("managed release cleanup: the grant could not be read");
                return;
            }
        };
        self.managed_after_narrowing(std::slice::from_ref(grant))
            .await;
        let Some(adapter) = self.adapter(Some(&identity)) else {
            return;
        };
        if super::bounded_adapter_call(self.adapter_limit(), adapter.revoke(grant, now))
            .await
            .is_err()
        {
            tracing::warn!("managed release cleanup: the adapter's cleanup did not complete");
        }
    }
}

// --- ⟨M03 wave 4, ADR-0008 §17.21 item 1⟩ the binding minted at resolve ---------------

/// Whether the effect driver's results are in `sources` (the managed adapter's
/// preparation ran its effects: key, certificates, binding endpoint and files), so a
/// later failure needs the cleanup intent. Always `false` for an existing-access
/// adapter, whose snapshot has no managed part (`operations.rs` never names it).
pub(super) fn driver_ran(sources: &IntegrationSnapshot) -> bool {
    sources
        .managed
        .as_ref()
        .is_some_and(|m| m.prepared.is_some())
}

/// The binding ID of a `managed_certificate` resolution (§17.21 item 1): `binding` is
/// recorded in the intent of an allowed or waiting resolution whose adapter is the
/// managed one; every other resolution is returned unchanged (its intent, and so its
/// stored bytes and request hash, exactly as in M01/M02).
pub(super) fn with_managed_binding(
    r: super::Resolution,
    binding: &heimdall_contract::ids::BindingId,
) -> super::Resolution {
    fn managed(i: &heimdall_domain::operation::ResolvedIntent) -> bool {
        i.adapter
            .as_ref()
            .is_some_and(|a| a.mechanism == MANAGED_CERTIFICATE)
    }
    match r {
        super::Resolution::Allowed(mut i) => {
            if managed(&i) {
                i.binding_id = Some(binding.clone());
            }
            super::Resolution::Allowed(i)
        }
        super::Resolution::Approval(mut a) => {
            if managed(&a.intent) {
                a.intent.binding_id = Some(binding.clone());
            }
            super::Resolution::Approval(a)
        }
    }
}

impl Operations {
    /// ⟨§17.21 item 1⟩ The binding ID minted at resolve for the open operation whose
    /// preparation attempt carries `token` (its `Attempted` receipt): the effect driver
    /// materializes the binding under it (step 6). `None` without such an operation
    /// (the re-issue pass) or for an intent with no minted ID.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) async fn managed_binding_of_token(
        &self,
        token: &str,
    ) -> Result<Option<heimdall_contract::ids::BindingId>, OpError> {
        let token = token.to_owned();
        self.write(move |tx, _| {
            for op in tx.open_operations()? {
                let carries = tx.stage_receipts(&op.id)?.iter().any(|r| {
                    matches!(&r.effect, EffectReceipt::Attempted { effect_token, .. }
                        if *effect_token == token)
                });
                if carries {
                    return Ok(tx
                        .recovery_intent(&op.id)?
                        .and_then(|i| i.resolved)
                        .and_then(|r| r.binding_id));
                }
            }
            Ok(None)
        })
        .await
    }

    /// ⟨§17.21 item 1⟩ A managed preparation that failed **after** the effect driver
    /// ran (its `prepare_from` refused, or, after a restart, its effect could not be
    /// reconciled): as `fail_running` (the grant `PreparationFailed`, the operation
    /// failed with `err`), and, in the same transaction, the cleanup decision for the
    /// applied effect ([`super::settle_effect_in`]), so the key, the binding endpoint
    /// and the binding files never outlive the failure, a crash included. Returns the
    /// cleanup intent to process after the commit (the prepare step's return path
    /// processes it in any case).
    ///
    /// # Errors
    /// A store failure.
    pub(super) async fn fail_managed_preparation(
        &self,
        id: &heimdall_contract::ids::OperationId,
        err: OpError,
        grant: &GrantId,
    ) -> Result<Option<heimdall_domain::revocation::CleanupIntent>, OpError> {
        use heimdall_contract::OperationState;
        let (id, gid) = (id.clone(), grant.clone());
        let clock = self.clock();
        let retention = self.retention();
        let cap = self
            .inner
            .revocation_cap
            .load(std::sync::atomic::Ordering::SeqCst);
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id)? else {
                return Ok(None);
            };
            let continuing = super::continues_for_others(tx, &op)?;
            if !continuing
                && !matches!(
                    op.state,
                    OperationState::Running | OperationState::OutcomeUnknown
                )
            {
                return Ok(None);
            }
            let now = clock.wall();
            if let Some(mut g) = tx.grant(&gid)?
                && grant_try(&mut g, GrantEvent::PreparationFailed)
            {
                put_grant(tx, emit, &g, Some(&id))?;
            }
            if !continuing {
                super::settle_failed(tx, emit, &mut op, &err, now, retention)?;
            }
            super::settle_effect_in(tx, &gid, &id, cap, now)
        })
        .await
    }

    /// ⟨§17.21 item 1⟩ The managed part of a cleanup intent whose call is made (after
    /// the adapters' `revoke`): for a `managed_certificate` grant, its keys are destroyed
    /// and its live credential instances become `destroyed` (the gate released, as a
    /// narrowing's cleanup does), and the binding minted for the intent's operation, when
    /// it was never committed, loses its endpoint and files (`ManagedEffects::clear` at
    /// [`crate::managed::driver::BINDING_GENERATION`]; the files are found on disk by
    /// their marker, so this also holds after a restart). `false` when the clear failed
    /// (the intent is kept and retried); `true` otherwise, and for any other grant.
    pub(super) async fn cleanup_uncommitted_managed(
        &self,
        intent: &heimdall_domain::revocation::CleanupIntent,
    ) -> bool {
        let (gid, op) = (intent.grant.clone(), intent.operation.clone());
        let read = self
            .write(move |tx, _| {
                if !grant_is_managed(tx, &gid)? {
                    return Ok(None);
                }
                let minted = tx
                    .recovery_intent(&op)?
                    .and_then(|i| i.resolved)
                    .and_then(|r| r.binding_id);
                let uncommitted = match minted {
                    Some(b) if tx.binding(&b)?.is_none() => Some(b),
                    _ => None,
                };
                Ok(Some(uncommitted))
            })
            .await;
        let uncommitted = match read {
            Ok(None) => return true,
            Ok(Some(u)) => u,
            Err(_) => return false,
        };
        self.managed_after_narrowing(std::slice::from_ref(&intent.grant))
            .await;
        let Some(binding) = uncommitted else {
            return true;
        };
        let Some(effects) = self.managed_wiring().and_then(|w| w.effects.clone()) else {
            // No effects in this process: nothing of this process holds the binding;
            // its files wait for a runtime with the effects (the intent is kept).
            return false;
        };
        effects
            .clear(&binding, crate::managed::driver::BINDING_GENERATION)
            .is_ok()
    }
}

// --- ⟨M03 wave 4, ADR-0008 §17.21 item 2⟩ the slots of a managed launch bind -----------

/// The refusal of a managed launch bind whose slot for `pair` cannot be claimed (D10
/// item 2; §17.21 item 2): `CONFIG_CONFLICT`, reason `managed_slot_held`, next
/// `release_binding`, nothing written but the failed operation.
fn slot_refusal(
    binding: &heimdall_contract::ids::BindingId,
    state: &heimdall_domain::managed::SlotState,
) -> OpError {
    let message = match state {
        heimdall_domain::managed::SlotState::Clearing { .. } => {
            "this pair's managed slot is still being cleared; retry, or use `heimdall connect`, which needs no slot"
        }
        _ => {
            "another binding holds this pair's managed slot; release it, or use `heimdall connect`, which needs no slot"
        }
    };
    OpError::new(Code::ConfigConflict, message)
        .with_effect(heimdall_contract::EffectStatus::None)
        .with_reason(heimdall_contract::envelope::reason::MANAGED_SLOT_HELD)
        .with_resource("binding", Some(binding.to_string()))
        .with_next(heimdall_contract::NextAction {
            action: "release_binding".to_owned(),
            ..heimdall_contract::NextAction::default()
        })
}

/// ⟨§17.21 item 2⟩ In the bind's transaction: every pair of the managed binding `b`
/// must be claimable by it (`free`, or already held by it); any other state refuses
/// ([`slot_refusal`]) before anything is claimed. Then each slot is claimed (CAS
/// `free(g) → held(b, g + 1)`, idempotent for the holder).
///
/// # Errors
/// A store failure (the whole transaction rolls back).
pub(super) fn claim_bind_slots_in(
    tx: &mut Txn<'_>,
    environment: &heimdall_contract::ids::EnvironmentId,
    b: &heimdall_domain::binding::BindingRecord,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), OpError>> {
    use heimdall_domain::managed::{SlotEvent, slot_transition};
    let claim = SlotEvent::Claim {
        binding: b.id.clone(),
    };
    for pair in &b.scope.pairs {
        let state = tx.slot(environment, pair)?;
        if slot_transition(&state, &claim).is_err() {
            return Ok(Err(slot_refusal(&b.id, &state)));
        }
    }
    for pair in &b.scope.pairs {
        if tx.claim_slot(environment, pair, &b.id, now)?.is_err() {
            return Err(heimdall_store::StoreError::Corrupt(
                "a checked slot claim was refused".into(),
            ));
        }
    }
    Ok(Ok(()))
}

impl Operations {
    /// ⟨§17.21 item 2⟩ After the claim committed: each claimed slot's files are
    /// written at its own store generation, then the environment endpoint lists the
    /// key (`ManagedEffects::materialize` with `environment_slots` and a slots-only
    /// spec: the content the preparation materialized for the binding).
    ///
    /// # Errors
    /// `driver_unavailable` without the effects; the effects' refusal otherwise.
    pub(super) async fn write_bind_slots_managed(
        &self,
        binding: &heimdall_contract::ids::BindingId,
    ) -> Result<(), AdapterError> {
        let Some(effects) = self.managed_wiring().and_then(|w| w.effects.clone()) else {
            return Err(AdapterError::Unavailable(
                heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE.to_owned(),
            ));
        };
        effects
            .materialize(
                binding,
                &crate::ports::MaterializeSpec {
                    generation: crate::managed::driver::BINDING_GENERATION,
                    public_key: String::new(),
                    certificates: Vec::new(),
                    environment_slots: true,
                },
            )
            .map(|_| ())
    }

    /// ⟨§17.21 item 2⟩ The slot files of a claimed launch bind could not be written:
    /// the bind fails (`SERVICE_UNAVAILABLE`, effect `partial`). The claim stays (the
    /// binding holds the slots with no files, so ssh fails closed for the aliases)
    /// until the binding or its grant ends, whose cleanup clears them; a later launch
    /// bind of the same binding claims them again idempotently.
    ///
    /// # Errors
    /// A store failure.
    pub(super) async fn fail_managed_bind(
        &self,
        id: &heimdall_contract::ids::OperationId,
        cause: AdapterError,
    ) -> Result<(), OpError> {
        let _ = cause;
        let err = OpError::new(
            Code::ServiceUnavailable,
            "the managed slot files could not be written; nothing was launched",
        )
        .with_effect(heimdall_contract::EffectStatus::Partial);
        let id = id.clone();
        let clock = self.clock();
        let retention = self.retention();
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id)? else {
                return Ok(());
            };
            if op.state.is_quiescent() {
                return Ok(());
            }
            super::settle_failed(tx, emit, &mut op, &err, clock.wall(), retention)
        })
        .await
    }
}
