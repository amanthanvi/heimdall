//! ⟨M06 U4⟩ The issuer's reconciliation barrier (ADR-0012 §7.4 step 4, §7.3; ADR-0005 §3.5,
//! §6.1–§6.2; m06-plan U4).
//!
//! A controller's issuer keeps its ledger in the controller's own store: the issuance log
//! (`reserve_issuance` / `publish_issuance`) and the grant tombstones its publish re-reads
//! (`heimdall_store::ext`). For a runner's grant the ledger is keyed by the runner's grant ID.
//! After every reconnect the issuer must read the runner's authority report **before any new
//! reserve or publish**:
//!
//! * a grant another controller tombstoned on the runner is **marked revoked in this ledger**
//!   (its tombstone is written here, so a reservation made before is voided at publish and no
//!   new one is admitted), and its counted certificates enter the residual
//!   ([`reconcile_in`]);
//! * a paused or cut-off policy blocks issuance for that scope ([`IssuerBarrier::permit`]).
//!
//! [`IssuerBarrier`] is the gate. It is process state, one entry per runner environment, and
//! it is **closed** for an environment until that environment's report was reconciled in the
//! current management session ([`IssuerBarrier::admit`]); a new session, a lost session or a
//! failed step closes it again ([`IssuerBarrier::close`]). Issuance is permitted only when,
//! at the moment of the reserve or the publish and in its transaction:
//!
//! 1. the report of this session was reconciled;
//! 2. this controller's outbox for the runner is drained (every narrowing effect it produced
//!    is acknowledged);
//! 3. the runner's time is bounded;
//! 4. the grant is tombstoned neither in this ledger nor in the report (a tombstoned grant is
//!    never reactivated);
//! 5. the grant's policy, when known, is neither paused nor past its cutoff, and no cutoff of
//!    every policy has passed (a fresh work ID cannot pass a reconciled pause or cutoff). A
//!    future cutoff bounds the certificate ([`IssuancePermit::bound`]).
//!
//! The runner applies the same rules to what it installs; this barrier keeps the issuer from
//! signing what the runner would have to refuse, and keeps the residual counted.
//!
//! **Residuals** ([`counted_residual`]): `latest_possible_credential_expiry` comes from the
//! counted issuance history, where reserved and published entries count until their
//! `valid_before`. A controller with no entry for the grant has no counted history and
//! reports `unknown`, never a guess. The destination-clock error is always stated with it
//! ([`residual_statement`]): unmeasured is "until `valid_before` plus an unmeasured
//! destination-clock error", never a bare deadline.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{EnvironmentId, GrantId, IssuanceId, PolicyId};
use heimdall_contract::managed::{AuthenticationResidual, DestinationClock};
use heimdall_domain::issuance::{IssuanceEntry, IssuanceRefusal, IssuanceState};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_store::Txn;
use heimdall_store::ext_effects::{AuthorityReport, PolicyRevisionKind};

use crate::error::OpError;
use crate::readiness::{ResidualEnd, authentication_residual, residual_end};

/// What the counted issuance history says about a grant's outstanding credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountedResidual {
    /// This controller holds no issuance entry for the grant: it cannot know.
    Unknown,
    /// It holds the history and nothing counted is outstanding (every entry was voided).
    NoneOutstanding,
    /// The latest `valid_before` among the reserved and published entries.
    Until(Timestamp),
}

impl CountedResidual {
    /// `latest_possible_credential_expiry` as the contract carries it: `None` for
    /// [`CountedResidual::Unknown`] and for [`CountedResidual::NoneOutstanding`] (the two are
    /// told apart only by this type).
    #[must_use]
    pub fn expiry(self) -> Option<Timestamp> {
        match self {
            CountedResidual::Until(t) => Some(t),
            _ => None,
        }
    }
}

/// The counted residual of `grant` in this controller's ledger (module docs).
///
/// # Errors
///
/// The store's.
pub fn counted_residual(
    tx: &mut Txn<'_>,
    grant: &GrantId,
) -> heimdall_store::Result<CountedResidual> {
    let entries = tx.issuance_entries(grant)?;
    if entries.is_empty() {
        return Ok(CountedResidual::Unknown);
    }
    Ok(match heimdall_domain::issuance::residual(&entries) {
        Some(t) => CountedResidual::Until(t),
        None => CountedResidual::NoneOutstanding,
    })
}

/// The new-authentication residual of a counted history with the destination clock's error
/// (ADR-0012 §7.3): `None` when nothing counted is outstanding.
#[must_use]
pub fn authentication_residual_of(
    counted: CountedResidual,
    destination_clock: DestinationClock,
) -> Option<AuthenticationResidual> {
    match counted {
        CountedResidual::NoneOutstanding => None,
        other => Some(authentication_residual(other.expiry(), destination_clock)),
    }
}

/// The residual in words (the status view and the revoke result): never a bare deadline.
#[must_use]
pub fn residual_statement(residual: Option<&AuthenticationResidual>) -> String {
    match residual.map(residual_end) {
        None => "no issued credential is outstanding".to_owned(),
        Some(ResidualEnd::Unknown) => {
            "unknown: this controller does not hold the grant's counted issuance history".to_owned()
        }
        Some(ResidualEnd::AtMost(t)) => {
            format!("until {t} (valid_before plus the measured destination-clock error)")
        }
        Some(ResidualEnd::PlusUnmeasuredClockError(t)) => {
            format!("until {t} (valid_before) plus an unmeasured destination-clock error")
        }
    }
}

/// One grant the report's reconciliation marked revoked in this ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedByReport {
    /// The grant.
    pub grant: GrantId,
    /// Whether this reconciliation wrote the ledger's tombstone (`false`: it was there).
    pub marked_now: bool,
    /// Its counted certificates: the residual.
    pub residual: CountedResidual,
}

/// The outcome of reading one authority report against this controller's ledger
/// ([`reconcile_in`]): handed to [`IssuerBarrier::admit`] once its transaction committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// When it was read (the controller's clock).
    pub at: Timestamp,
    /// The report.
    pub report: AuthorityReport,
    /// The grants of this ledger the report shows tombstoned.
    pub revoked: Vec<RevokedByReport>,
}

/// Read `report` against this controller's ledger, in the caller's transaction (module
/// docs): every tombstoned grant (and each descendant its tombstone covers) that this ledger
/// has an issuance entry for gets this ledger's tombstone when it has none, and its counted
/// residual is returned. Reserved entries are left to the publish, which voids them on the
/// tombstone. A report for another environment than `environment` is not read: `None`,
/// nothing written (the caller holds the environment, `environment_identity_mismatch`).
///
/// # Errors
///
/// The store's.
pub fn reconcile_in(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    report: AuthorityReport,
    now: Timestamp,
) -> heimdall_store::Result<Option<Reconciliation>> {
    if report.environment != *environment {
        return Ok(None);
    }
    let mut seen = BTreeSet::new();
    let mut revoked = Vec::new();
    for t in &report.tombstones {
        for grant in std::iter::once(&t.grant).chain(t.cascade.iter()) {
            if !seen.insert(grant.clone()) {
                continue;
            }
            let residual = counted_residual(tx, grant)?;
            if residual == CountedResidual::Unknown {
                // Not this issuer's grant: nothing in this ledger to mark. The barrier still
                // refuses it from the report.
                continue;
            }
            let marked_now = tx.tombstone(grant)?.is_none();
            if marked_now {
                tx.insert_tombstone(&Tombstone {
                    grant: grant.clone(),
                    cascade: Vec::new(),
                    generation: AuthorityGeneration(0),
                    revoked_at: now,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::AuthorityWithdrawn,
                })?;
            }
            revoked.push(RevokedByReport {
                grant: grant.clone(),
                marked_now,
                residual,
            });
        }
    }
    Ok(Some(Reconciliation {
        environment: environment.clone(),
        at: now,
        report,
        revoked,
    }))
}

/// Why the barrier refuses a reserve or a publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierRefusal {
    /// The runner's report was not reconciled in the current session.
    NotReconciled,
    /// This controller still has unacknowledged narrowing effects for the runner.
    OutboxPending,
    /// The runner's time is not bounded.
    TimeUnbounded,
    /// The grant is tombstoned (in this ledger or on the runner).
    GrantRevoked,
    /// The grant's policy is paused.
    PolicyPaused,
    /// A cutoff of the grant's scope has passed.
    PolicyCutoff,
}

impl BarrierRefusal {
    /// The refusal as an error. Nothing was issued (`effect: none`).
    #[must_use]
    pub fn to_error(&self) -> OpError {
        let e = match self {
            // ⟨ADR-0006 §18.7 item 11⟩ Both transient gates carry `resync_pending`.
            BarrierRefusal::NotReconciled => OpError::new(
                Code::CapabilityUnavailable,
                "issuance for this runner waits for its authority report: reconnect and \
                 resynchronize first",
            )
            .with_reason(reason::RESYNC_PENDING),
            BarrierRefusal::OutboxPending => OpError::new(
                Code::CapabilityUnavailable,
                "issuance for this runner waits until every narrowing effect this controller \
                 produced is acknowledged",
            )
            .with_reason(reason::RESYNC_PENDING),
            BarrierRefusal::TimeUnbounded => OpError::new(
                Code::TimeUncertain,
                "the runner's time is not bounded by a qualifying sample",
            ),
            BarrierRefusal::GrantRevoked => OpError::new(
                Code::CredentialExpired,
                "the grant is revoked; a revoked grant is never issued for again",
            ),
            BarrierRefusal::PolicyPaused => {
                OpError::new(Code::PolicyPaused, "the runner's standing policy is paused")
            }
            BarrierRefusal::PolicyCutoff => OpError::new(
                Code::PolicyCutoff,
                "a policy cutoff is in effect on the runner",
            ),
        };
        e.with_effect(EffectStatus::None)
    }
}

/// What a permitted issuance must respect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuancePermit {
    /// A future cutoff of the grant's scope: no certificate may be valid past it.
    pub bound: Option<Timestamp>,
}

#[derive(Debug, Clone)]
struct Open {
    reconciliation: Reconciliation,
    time_bounded: bool,
}

/// The issuer's reconciliation barrier (module docs).
#[derive(Debug, Default)]
pub struct IssuerBarrier {
    open: Mutex<HashMap<EnvironmentId, Open>>,
}

impl IssuerBarrier {
    /// A barrier closed for every environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<EnvironmentId, Open>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Close the barrier for `environment`: a management session opened, ended, or a
    /// resynchronization step failed.
    pub fn close(&self, environment: &EnvironmentId) {
        self.lock().remove(environment);
    }

    /// The report of the current session was reconciled and its transaction committed. The
    /// runner's time counts as bounded when the report says so; [`Self::time_sampled`] sets
    /// it after this controller's own qualifying sample.
    pub fn admit(&self, reconciliation: Reconciliation) {
        let time_bounded = reconciliation.report.time_bounded;
        self.lock().insert(
            reconciliation.environment.clone(),
            Open {
                reconciliation,
                time_bounded,
            },
        );
    }

    /// This controller's time sample was accepted by the runner in the current session.
    /// Nothing happens while the barrier is closed for `environment`.
    pub fn time_sampled(&self, environment: &EnvironmentId) {
        if let Some(open) = self.lock().get_mut(environment) {
            open.time_bounded = true;
        }
    }

    /// The reconciliation the barrier holds for `environment`, when one was admitted in the
    /// current session.
    #[must_use]
    pub fn reconciliation(&self, environment: &EnvironmentId) -> Option<Reconciliation> {
        self.lock()
            .get(environment)
            .map(|o| o.reconciliation.clone())
    }

    /// Whether a reserve or publish for `grant` (under the runner's `policy`, when this
    /// controller knows it) is permitted now (module docs, rules 1–5), judged in the
    /// caller's transaction.
    ///
    /// # Errors
    ///
    /// The store's (outer); the refusal (inner).
    pub fn permit(
        &self,
        tx: &mut Txn<'_>,
        environment: &EnvironmentId,
        grant: &GrantId,
        policy: Option<&PolicyId>,
        now: Timestamp,
    ) -> heimdall_store::Result<Result<IssuancePermit, BarrierRefusal>> {
        let Some(open) = self.lock().get(environment).cloned() else {
            return Ok(Err(BarrierRefusal::NotReconciled));
        };
        if !tx.remote_effect_outbox(Some(environment), true)?.is_empty() {
            return Ok(Err(BarrierRefusal::OutboxPending));
        }
        if !open.time_bounded {
            return Ok(Err(BarrierRefusal::TimeUnbounded));
        }
        let report = &open.reconciliation.report;
        let reported = report
            .tombstones
            .iter()
            .any(|t| t.grant == *grant || t.cascade.contains(grant));
        if reported || tx.tombstone(grant)?.is_some() {
            return Ok(Err(BarrierRefusal::GrantRevoked));
        }
        let mut bound: Option<Timestamp> = None;
        let mut cut = |at: Timestamp| -> bool {
            if at <= now {
                return true;
            }
            bound = Some(bound.map_or(at, |b| b.min(at)));
            false
        };
        // A delivered cutoff of every policy applies whatever the grant's policy.
        for row in &report.policy_revisions {
            if row.kind == PolicyRevisionKind::Cutoff
                && row.scope_key == "all"
                && let Some(at) = row.cutoff_at
                && cut(at)
            {
                return Ok(Err(BarrierRefusal::PolicyCutoff));
            }
        }
        if let Some(policy) = policy {
            // The runner's policy as it is now: every applied pause and cutoff, delivered or
            // decided at the runner.
            if let Some(p) = report.policies.iter().find(|p| p.policy == *policy) {
                if p.paused {
                    return Ok(Err(BarrierRefusal::PolicyPaused));
                }
                if let Some(at) = p.cutoff_at
                    && cut(at)
                {
                    return Ok(Err(BarrierRefusal::PolicyCutoff));
                }
            }
            // And the delivered revisions naming it, should the runner hold no such policy.
            let key = heimdall_store::ext_effects::policy_scope_key(policy);
            for row in report
                .policy_revisions
                .iter()
                .filter(|r| r.scope_key == key)
            {
                match (row.kind, row.cutoff_at) {
                    (PolicyRevisionKind::Pause, _) => {
                        return Ok(Err(BarrierRefusal::PolicyPaused));
                    }
                    (PolicyRevisionKind::Cutoff, Some(at)) if cut(at) => {
                        return Ok(Err(BarrierRefusal::PolicyCutoff));
                    }
                    _ => {}
                }
            }
        }
        Ok(Ok(IssuancePermit { bound }))
    }

    /// Reserve `entry` in this ledger for a runner's grant, behind the barrier: nothing is
    /// reserved unless [`Self::permit`] passes in this transaction, and a certificate valid
    /// past a future cutoff is refused.
    ///
    /// # Errors
    ///
    /// The store's (outer); the refusal (inner).
    pub fn reserve(
        &self,
        tx: &mut Txn<'_>,
        environment: &EnvironmentId,
        policy: Option<&PolicyId>,
        entry: &IssuanceEntry,
        now: Timestamp,
    ) -> heimdall_store::Result<Result<(), BarrierRefusal>> {
        match self.permit(tx, environment, &entry.grant, policy, now)? {
            Err(r) => Ok(Err(r)),
            Ok(permit) if permit.bound.is_some_and(|b| entry.bounds.valid_before > b) => {
                Ok(Err(BarrierRefusal::PolicyCutoff))
            }
            Ok(_) => {
                tx.reserve_issuance(entry)?;
                Ok(Ok(()))
            }
        }
    }

    /// Publish a reserved entry of a runner's grant, behind the barrier. A refusal voids the
    /// reservation in the same transaction (it then no longer counts in the residual), so
    /// nothing reserved before a revocation, pause or cutoff is ever released. An entry that
    /// is not reserved is left as it is.
    ///
    /// # Errors
    ///
    /// The store's (outer); the refusal (inner).
    pub fn publish(
        &self,
        tx: &mut Txn<'_>,
        environment: &EnvironmentId,
        policy: Option<&PolicyId>,
        id: &IssuanceId,
        now: Timestamp,
    ) -> heimdall_store::Result<Result<IssuanceEntry, BarrierRefusal>> {
        let Some(entry) = tx.issuance_entry(id)? else {
            return Err(heimdall_store::StoreError::GenerationConflict(format!(
                "issuance {id} is not reserved"
            )));
        };
        let refusal = match self.permit(tx, environment, &entry.grant, policy, now)? {
            Err(r) => r,
            Ok(permit) if permit.bound.is_some_and(|b| entry.bounds.valid_before > b) => {
                BarrierRefusal::PolicyCutoff
            }
            Ok(_) => return Ok(Ok(tx.publish_issuance(id, now)?)),
        };
        // Not reconciled, outbox pending and unbounded time are transient: the reservation is
        // kept (and counted) for a retry after the resynchronization. A revoked grant, a
        // pause or a cutoff ends it.
        if entry.state == IssuanceState::Reserved {
            let reason = match refusal {
                BarrierRefusal::GrantRevoked => Some(IssuanceRefusal::Tombstoned),
                BarrierRefusal::PolicyPaused => Some(IssuanceRefusal::PausedActivation),
                BarrierRefusal::PolicyCutoff => Some(IssuanceRefusal::CutoffPassed),
                _ => None,
            };
            if let Some(reason) = reason {
                tx.void_issuance(id, &reason, now)?;
            }
        }
        Ok(Err(refusal))
    }
}
