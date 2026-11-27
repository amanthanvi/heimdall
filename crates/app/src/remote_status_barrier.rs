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
//!   ([`reconcile_in`]). ⟨M08 W4 SEC-1, S2-04⟩ Only a grant this controller delivered to
//!   that runner: an entry naming anything else is dropped and counted, and changes nothing
//!   here;
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
//! ⟨M06-W3-R02⟩ **The runner's prepare answer cannot talk its way past a pause or cutoff**
//! ([`IssuerBarrier::permit_answer`], which the reserve and the publish use). The policy a
//! prepare answer names is the runner's word, so:
//!
//! * a cutoff of **every** policy that this controller itself delivered to the runner (its
//!   own outbox row, pending rows already refuse under rule 2) applies to all issuance for
//!   that runner whatever the report or the answer says;
//! * a pause or a single-policy cutoff this controller delivered applies to an answer naming
//!   that policy whatever the report says;
//! * ⟨W3.1 re-check⟩ a delivered cutoff whose acknowledgement says it **fired** (its
//!   instant had passed, or may have passed under uncertain time) refuses outright where it
//!   applies, and for every policy the acknowledgement said it applied to; the owner's
//!   later instant only bounds a cutoff that has not fired;
//! * while **any** pause or cutoff holds for the runner (in its report's policies or
//!   delivered revisions, or in an effect this controller delivered), an answer that names
//!   no policy, or one the report does not list, is refused
//!   ([`BarrierRefusal::PolicyUnnamed`]).
//!
//! ⟨M06 W4; ADR-0012 §7.4 ⟨2026-11-21⟩; ADR-0006 §18.8 item 4⟩ **The way out is two-sided**
//! ([`lift_shown`], `Txn::remote_lift_ack`). A pause or cutoff this controller delivered
//! stops counting only when **both** hold, judged in the reserve's and the publish's own
//! transaction:
//!
//! 1. the runner's report of this session says **that effect** is no longer in force
//!    ([`lift_shown`]): its own delivered revision row carries `in_force: false`, which only
//!    a runner-local lift (an attended `resume` or `clear_cutoff` at the runner) clears.
//!    ⟨W5; ADR-0006 §18.9 item 4⟩ This replaces reading "nothing in the effect's scope is in
//!    force", under which a runner with no standing policy showed the lift from delivery
//!    on and the owner's acknowledgement was the only key;
//! 2. the owner's acknowledgement of that effect's lift is recorded on this controller
//!    (`heimdall environment resume-issuance`, attended).
//!
//! Neither alone reopens anything. The effect's own row in the report's delivered revisions
//! (which the runner keeps as the record after a lift) stops counting with it.
//!
//! ⟨W5 `w5l`; ADR-0012 §7.4 ⟨2026-11-22⟩ "Two owner controllers"⟩ Another controller's
//! delivered revisions are not this controller's to acknowledge. They count exactly as the
//! report states them: **in force** blocks this controller too; one the runner reports as
//! lifted does not, with no acknowledgement here (the delivering controller stays blocked
//! by it until its own two keys clear). ⟨M08 W4 SEC-1, S3-02⟩ An in-force row is judged as
//! this controller's own rows are: a cutoff that fired early under uncertain time refuses
//! whatever its instant, and a `profile:` or `workspace:` scope covers the grant's policy
//! unless the report shows it did not apply to that policy.
//!
//! Which standing policy a grant really belongs to is still the runner's statement until the
//! controller holds its own policy record (m06-plan W4, record source (b)).
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
use heimdall_contract::remote::EffectTarget;
use heimdall_contract::trust::PolicyTarget;
use heimdall_domain::issuance::{IssuanceEntry, IssuanceRefusal, IssuanceState};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_store::Txn;
use heimdall_store::ext_effects::{
    AppliedRecord, AuthorityReport, OutboxEffect, PolicyRevisionKind, PolicyRevisionRecord,
};

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
    Ok(counted_residual_of(&tx.issuance_entries(grant)?))
}

/// [`counted_residual`] of a grant's entries, already read.
fn counted_residual_of(entries: &[IssuanceEntry]) -> CountedResidual {
    if entries.is_empty() {
        return CountedResidual::Unknown;
    }
    match heimdall_domain::issuance::residual(entries) {
        Some(t) => CountedResidual::Until(t),
        None => CountedResidual::NoneOutstanding,
    }
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
    /// ⟨M08 W4 SEC-1, S2-04⟩ The report's tombstone entries (tombstoned grants and cascade
    /// entries) this reconciliation did not take: each grant this controller did not deliver
    /// to that runner (a grant of this installation, another runner's, an ID it never
    /// issued for), and each entry past [`MAX_RECONCILED_TOMBSTONES`]. Nothing is written
    /// for them. The report itself still refuses issuance for every grant it names, in this
    /// session (rule 4).
    pub ignored_tombstones: usize,
}

/// ⟨M08 W4 SEC-1, S2-04⟩ The most distinct tombstone entries (tombstoned grants and cascade
/// entries) one reconciliation takes from a report, newest first; the rest are counted in
/// [`Reconciliation::ignored_tombstones`].
pub const MAX_RECONCILED_TOMBSTONES: usize = 4096;

/// ⟨M08 W4 SEC-1, S2-04; spec §8.1⟩ Whether `grant` is one this controller delivered to the
/// runner `environment`: its delivered-grant record for that runner, or an issuance entry
/// of this ledger whose key ID names that runner. Never a grant of this installation: a
/// runner's report does not alter authority in another environment.
fn delivered_to(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    grant: &GrantId,
    entries: &[IssuanceEntry],
) -> heimdall_store::Result<bool> {
    if tx.grant(grant)?.is_some() {
        return Ok(false);
    }
    Ok(tx.delivered_grant(environment, grant)?.is_some()
        || entries.iter().any(|e| {
            crate::remote_status_driver::key_id_environment(&e.bounds.key_id, grant).as_ref()
                == Some(environment)
        }))
}

/// Read `report` against this controller's ledger, in the caller's transaction (module
/// docs): every tombstoned grant (and each descendant its tombstone covers) gets this
/// ledger's tombstone when it has none, ⟨M06-W3-R02⟩ whether or not this ledger holds an
/// issuance entry for it (the issuer child's own check reads this ledger, so a grant another
/// controller revoked is refused there too, and stays refused after this session). The
/// counted residual of each grant this ledger has entries for is returned. Reserved entries
/// are left to the publish, which voids them on the tombstone. A report for another
/// environment than `environment` is not read: `None`, nothing written (the caller holds
/// the environment, `environment_identity_mismatch`).
///
/// ⟨M08 W4 SEC-1, S2-04; spec §8.1; ADR-0012 §3.10 T-RA6⟩ Only for a grant this controller
/// delivered to **that** runner ([`delivered_to`]). The report is the runner's word, and a
/// runner's word does not alter authority elsewhere: an entry naming a grant of this
/// installation, a grant delivered to another runner, or an ID this controller never issued
/// for is dropped and counted ([`Reconciliation::ignored_tombstones`]), and nothing is
/// written for it. At most [`MAX_RECONCILED_TOMBSTONES`] distinct entries are taken, newest
/// first (the report lists tombstones in the runner's apply order). So the store's
/// tombstone write, which also moves this controller's authority generation, happens only
/// for a grant of that runner that this controller delivered and that has no tombstone here
/// yet.
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
    let mut ignored = 0usize;
    for t in report.tombstones.iter().rev() {
        for grant in std::iter::once(&t.grant).chain(t.cascade.iter()) {
            if seen.contains(grant) {
                continue;
            }
            if seen.len() >= MAX_RECONCILED_TOMBSTONES {
                ignored += 1;
                continue;
            }
            seen.insert(grant.clone());
            let entries = tx.issuance_entries(grant)?;
            if !delivered_to(tx, environment, grant, &entries)? {
                ignored += 1;
                continue;
            }
            let residual = counted_residual_of(&entries);
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
            if residual == CountedResidual::Unknown {
                // No counted history here: the tombstone above denies the ID, and there is
                // no residual of this ledger's to report.
                continue;
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
        ignored_tombstones: ignored,
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
    /// ⟨M06-W3-R02⟩ A pause or cutoff holds for the runner and its prepare answer names no
    /// policy, or one its report does not list: the answer cannot show the grant is outside
    /// the hold.
    PolicyUnnamed {
        /// Whether a pause is among what holds (else only cutoffs are).
        paused: bool,
    },
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
            BarrierRefusal::PolicyUnnamed { paused } => OpError::new(
                if *paused {
                    Code::PolicyPaused
                } else {
                    Code::PolicyCutoff
                },
                "a pause or cutoff holds on the runner, and its answer names no policy its \
                 report lists; nothing is issued",
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

/// ⟨M06 W4; W5, ADR-0006 §18.9 item 4⟩ Whether `report` shows that the delivered pause or
/// cutoff `effect` (an acknowledged row of this controller's outbox) is no longer in force
/// at the runner (module docs, "The way out is two-sided", item 1): the report carries
/// **that effect's** own revision row, and the row says it is not in force.
///
/// Only the runner's own owner clears that flag, by lifting the effect at the runner. What
/// the report lists as standing policies does not decide it: a runner with no standing
/// policy, or one that no longer lists the policy, still reports the effect in force. A
/// report without the row (or from a runner that does not state the flag) shows no lift.
/// `false` for a row without an acknowledgement, or one that is not a pause or a cutoff.
#[must_use]
pub fn lift_shown(report: &AuthorityReport, effect: &OutboxEffect) -> bool {
    lift_shown_among(&report.policy_revisions, effect)
}

/// [`lift_shown`] over a report's delivered revisions alone.
#[must_use]
pub fn lift_shown_among(revisions: &[PolicyRevisionRecord], effect: &OutboxEffect) -> bool {
    matches!(
        effect.ack.as_ref().map(|a| &a.record),
        Some(AppliedRecord::PolicyRevision { .. })
    ) && matches!(
        effect.key.target,
        EffectTarget::PolicyPause { .. } | EffectTarget::PolicyCutoff { .. }
    ) && revisions
        .iter()
        .any(|r| revision_of(r, effect) && !r.in_force)
}

/// Whether the report's delivered revision `row` is the durable record of the outbox
/// effect `effect`.
fn revision_of(row: &PolicyRevisionRecord, effect: &OutboxEffect) -> bool {
    row.producer == effect.key.producer
        && row.effect == effect.key.effect
        && row.revision == effect.key.target.generation()
        && heimdall_store::ext_effects::target_ref(&effect.key.target).as_deref()
            == Some(row.scope_key.as_str())
}

/// ⟨M08 W4 SEC-1, S3-02⟩ What one delivered revision that covers the grant's policy refuses,
/// judged as this controller's own outbox rows are: a pause refuses; a cutoff that **fired**
/// (it took effect at the runner's apply because the runner's time was uncertain,
/// [`PolicyRevisionRecord::fired_uncertain_at`]) refuses whatever its instant; a cutoff
/// whose instant has passed refuses; a future one bounds the certificate (`cut`).
fn revision_refusal(
    row: &PolicyRevisionRecord,
    cut: &mut impl FnMut(Timestamp) -> bool,
) -> Option<BarrierRefusal> {
    match row.kind {
        PolicyRevisionKind::Pause => Some(BarrierRefusal::PolicyPaused),
        PolicyRevisionKind::Cutoff => (row.fired_uncertain_at.is_some()
            || row.cutoff_at.is_some_and(cut))
        .then_some(BarrierRefusal::PolicyCutoff),
    }
}

/// ⟨M08 W4 SEC-5, ruling 4; ADR-0012 §7.4⟩ Whether a delivered revision row whose scope is
/// `all` or an unknown scope (`unknown`) applies unconditionally to every issuance for this
/// runner (including a policy created after the row fired, and checks before the runner
/// named a policy).
fn revision_applies_unconditionally(row: &PolicyRevisionRecord) -> bool {
    row.scope_key == "all" || row.scope_key == crate::remote_status::UNKNOWN_SCOPE_KEY
}

/// ⟨M08 W4 SEC-5, ruling 4; ADR-0012 §7.4⟩ Whether a delivered revision row applies to a
/// specific named `policy` (after unconditional `all`/`unknown` rows were already judged):
/// * `policy:P` applies iff `P == policy` (and when the answer names no policy, the naming
///   rule refuses it as `PolicyUnnamed`);
/// * `profile:` and `workspace:` apply unless the report shows that `policy` is outside that
///   scope by membership. Because `AuthorityReport`'s `ReportedPolicy` carries no profile or
///   workspace membership fields, policy creation time (`!paused` / `cutoff_at: None`) is
///   never evidence that an in-force revision does not apply, so `profile:`, `workspace:`,
///   and any other scope fail closed.
fn revision_covers_policy(row: &PolicyRevisionRecord, policy_key: &str) -> bool {
    match row.scope_key.as_str() {
        // Already judged unconditionally before `if answered`.
        "all" => false,
        k if k == crate::remote_status::UNKNOWN_SCOPE_KEY => false,
        k if k == policy_key => true,
        // Another named policy only: never covers `policy`.
        k if k.starts_with("policy:") => false,
        // `profile:`, `workspace:`, or any unrecognized scope: fail closed.
        _ => true,
    }
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

    /// Whether issuance for `grant` (under the runner's `policy`, when this controller knows
    /// it) is permitted now (module docs, rules 1–5), judged in the caller's transaction.
    /// This is the check **before the runner was asked**: no policy is claimed yet, so a
    /// missing one is not held against the grant ([`Self::permit_answer`] does that).
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
        self.judge(tx, environment, grant, policy, false, now)
    }

    /// ⟨M06-W3-R02⟩ [`Self::permit`] for a reserve or a publish, where `policy` is what the
    /// runner's **prepare answer** named: while any pause or cutoff holds for the runner, an
    /// answer that names no policy, or one the runner's report does not list, is refused
    /// (module docs).
    ///
    /// # Errors
    ///
    /// The store's (outer); the refusal (inner).
    pub fn permit_answer(
        &self,
        tx: &mut Txn<'_>,
        environment: &EnvironmentId,
        grant: &GrantId,
        policy: Option<&PolicyId>,
        now: Timestamp,
    ) -> heimdall_store::Result<Result<IssuancePermit, BarrierRefusal>> {
        self.judge(tx, environment, grant, policy, true, now)
    }

    fn judge(
        &self,
        tx: &mut Txn<'_>,
        environment: &EnvironmentId,
        grant: &GrantId,
        policy: Option<&PolicyId>,
        answered: bool,
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
        // ⟨M06-W3-R02⟩ What this controller itself delivered (its outbox; every row is
        // acknowledged here, a pending one refused above). The runner's report and answer
        // cannot hide these.
        // ⟨M06 W4⟩ An effect stops counting only when the report shows its lift and the
        // owner's acknowledgement of it is recorded here.
        let mut held_pause = false;
        let mut held_cutoff = false;
        let mut lifted: Vec<OutboxEffect> = Vec::new();
        let mut own: Vec<OutboxEffect> = Vec::new();
        for row in tx.remote_effect_outbox(Some(environment), false)? {
            if lift_shown(report, &row) && tx.remote_lift_ack(&row.key)?.is_some() {
                lifted.push(row);
                continue;
            }
            own.push(row.clone());
            match &row.key.target {
                EffectTarget::PolicyPause { policy: paused, .. } => {
                    held_pause = true;
                    if policy == Some(paused) {
                        return Ok(Err(BarrierRefusal::PolicyPaused));
                    }
                }
                EffectTarget::PolicyCutoff { scope, at, .. } => {
                    held_cutoff = true;
                    // ⟨W3.1 re-check, low finding 1⟩ What the runner's acknowledgement
                    // said: the policies the cutoff applied to, and whether it fired at
                    // the apply (its instant had passed, or may have under uncertain
                    // time).
                    let (applied_to, fired) = match row.ack.as_ref().map(|a| &a.record) {
                        Some(AppliedRecord::PolicyRevision {
                            policies, fired, ..
                        }) => (policies.as_slice(), *fired),
                        _ => (&[][..], false),
                    };
                    let applies = match scope {
                        // Every policy: all issuance for this runner.
                        PolicyTarget::All => true,
                        PolicyTarget::Policy { policy_id } => policy == Some(policy_id),
                        // Another scope: which policies it covers is the runner's to say
                        // (the naming rule below then holds the answer to the report).
                        _ => false,
                    };
                    // A cutoff that fired blocks outright where it applies, also where
                    // the runner said it applied, whatever instant the owner named and
                    // whatever the report shows now: a future instant only bounds a
                    // cutoff that has not fired. Only the two-sided lift ends it.
                    let fired_on =
                        fired && (applies || policy.is_some_and(|id| applied_to.contains(id)));
                    if fired_on || (applies && cut(*at)) {
                        return Ok(Err(BarrierRefusal::PolicyCutoff));
                    }
                }
                _ => {}
            }
        }
        // The report's delivered revisions that count: without the records of this
        // controller's lifted effects, and ⟨W5 `w5l`⟩ without another controller's effect
        // the runner reports as no longer in force. A lifted row of an effect this
        // controller delivered itself keeps counting until its own owner acknowledged the
        // lift (it is in `own`, which the loop above already held against the grant).
        let revisions: Vec<&PolicyRevisionRecord> = report
            .policy_revisions
            .iter()
            .filter(|r| !lifted.iter().any(|e| revision_of(r, e)))
            .filter(|r| r.in_force || own.iter().any(|e| revision_of(r, e)))
            .collect();
        // A delivered revision of every policy (`all`) or an unknown scope (`unknown`)
        // applies whatever the grant's policy, including a policy created after it fired.
        // ⟨M08 W4 SEC-1, S3-02; SEC-5, ruling 4⟩ Judged as this controller's own rows are: a
        // cutoff that fired refuses outright, whatever its instant (a future one only bounds
        // a cutoff that has not fired), also when another controller delivered it.
        for row in revisions
            .iter()
            .filter(|r| revision_applies_unconditionally(r))
        {
            if let Some(refusal) = revision_refusal(row, &mut cut) {
                return Ok(Err(refusal));
            }
        }
        if answered {
            // ⟨M06-W3-R02⟩ While anything holds, the answer must name a listed policy.
            held_pause |= report.policies.iter().any(|p| p.paused)
                || revisions
                    .iter()
                    .any(|r| r.kind == PolicyRevisionKind::Pause);
            held_cutoff |= report.policies.iter().any(|p| p.cutoff_at.is_some())
                || revisions
                    .iter()
                    .any(|r| r.kind == PolicyRevisionKind::Cutoff);
            let listed = policy.is_some_and(|id| report.policies.iter().any(|p| p.policy == *id));
            if (held_pause || held_cutoff) && !listed {
                return Ok(Err(BarrierRefusal::PolicyUnnamed { paused: held_pause }));
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
            // And the delivered revisions naming it, or covering it by scope (`profile:`,
            // `workspace:`: fail closed because `ReportedPolicy` carries no membership
            // fields; policy creation time never exempts a policy from an in-force row).
            let key = heimdall_store::ext_effects::policy_scope_key(policy);
            for row in &revisions {
                if revision_covers_policy(row, &key)
                    && let Some(refusal) = revision_refusal(row, &mut cut)
                {
                    return Ok(Err(refusal));
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
        match self.permit_answer(tx, environment, &entry.grant, policy, now)? {
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
        let refusal = match self.permit_answer(tx, environment, &entry.grant, policy, now)? {
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
                BarrierRefusal::PolicyPaused | BarrierRefusal::PolicyUnnamed { paused: true } => {
                    Some(IssuanceRefusal::PausedActivation)
                }
                BarrierRefusal::PolicyCutoff | BarrierRefusal::PolicyUnnamed { paused: false } => {
                    Some(IssuanceRefusal::CutoffPassed)
                }
                _ => None,
            };
            if let Some(reason) = reason {
                tx.void_issuance(id, &reason, now)?;
            }
        }
        Ok(Err(refusal))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use heimdall_contract::ids::{ClientId, EffectId, ProfileId, WorkspaceId};
    use heimdall_store::ext_effects::{
        AuthorityReport, PolicyRevisionKind, PolicyRevisionRecord, ReportedPolicy,
    };
    use heimdall_store::{NoFaults, Store};

    use super::*;

    /// ⟨M08 W4 SEC-5, ruling 4; ADR-0012 §7.4⟩ While a delivered revision row is in force,
    /// policy creation time (no `cutoff_at` / not `paused` on the listed policy) is never
    /// evidence that the row does not apply:
    /// * `all` always applies;
    /// * `policy:P` applies iff the answer names `P` or names no policy;
    /// * `profile:` and `workspace:` fail closed unless membership shows otherwise (the
    ///   report carries no membership fields);
    /// * an unknown scope (`unknown`) fails closed.
    #[test]
    fn fired_cutoff_scope_rules_do_not_exempt_later_policies_or_unknown_scopes() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let env = EnvironmentId::from_random_bytes([1; 16]);
        let grant = GrantId::from_random_bytes([2; 16]);
        let producer = ClientId::from_random_bytes([3; 16]);
        let new_policy = PolicyId::parse("created_after").unwrap();
        let other_policy = PolicyId::parse("other_policy").unwrap();
        let t0: Timestamp = "2026-11-26T12:00:00Z".parse().unwrap();
        let fired = t0.checked_add(Duration::from_secs(3600)).unwrap();
        let future_at = t0.checked_add(Duration::from_secs(6 * 3600)).unwrap();

        let cases = [
            (
                "all",
                "all".to_owned(),
                PolicyTarget::All,
                Some(&new_policy),
                Err(BarrierRefusal::PolicyCutoff),
            ),
            (
                "policy:same",
                format!("policy:{}", new_policy.as_str()),
                PolicyTarget::Policy {
                    policy_id: new_policy.clone(),
                },
                Some(&new_policy),
                Err(BarrierRefusal::PolicyCutoff),
            ),
            (
                "policy:other",
                format!("policy:{}", other_policy.as_str()),
                PolicyTarget::Policy {
                    policy_id: other_policy.clone(),
                },
                Some(&new_policy),
                Ok(()),
            ),
            (
                "policy:unnamed",
                format!("policy:{}", other_policy.as_str()),
                PolicyTarget::Policy {
                    policy_id: other_policy.clone(),
                },
                None,
                Err(BarrierRefusal::PolicyUnnamed { paused: false }),
            ),
            (
                "profile:ops",
                "profile:ops".to_owned(),
                PolicyTarget::Profile {
                    profile: ProfileId::parse("ops").unwrap(),
                },
                Some(&new_policy),
                Err(BarrierRefusal::PolicyCutoff),
            ),
            (
                "workspace:ws",
                format!(
                    "workspace:{}",
                    WorkspaceId::from_random_bytes([9; 16]).as_str()
                ),
                PolicyTarget::Workspace {
                    workspace: WorkspaceId::from_random_bytes([9; 16]),
                },
                Some(&new_policy),
                Err(BarrierRefusal::PolicyCutoff),
            ),
            (
                "unknown_scope",
                crate::remote_status::UNKNOWN_SCOPE_KEY.to_owned(),
                PolicyTarget::All,
                Some(&new_policy),
                Err(BarrierRefusal::PolicyCutoff),
            ),
        ];

        for (label, scope_key, scope, answer_policy, wanted) in cases {
            let barrier = IssuerBarrier::new();
            let report = AuthorityReport {
                environment: env.clone(),
                authority_generation: 1,
                tombstones: Vec::new(),
                policy_revisions: vec![PolicyRevisionRecord {
                    scope_key,
                    scope,
                    producer: producer.clone(),
                    revision: 1,
                    runner_seq: 1,
                    kind: PolicyRevisionKind::Cutoff,
                    effect: EffectId::from_random_bytes([4; 16]),
                    received_at: t0,
                    cutoff_at: Some(future_at),
                    fired_uncertain_at: Some(fired),
                    in_force: true,
                }],
                // `new_policy` was created after the cutoff fired: not paused, no `cutoff_at`.
                policies: vec![ReportedPolicy {
                    policy: new_policy.clone(),
                    revision: 1,
                    paused: false,
                    cutoff_at: None,
                }],
                certificates: Vec::new(),
                time_bounded: true,
                pending_grants: Vec::new(),
            };
            barrier.admit(Reconciliation {
                environment: env.clone(),
                at: t0,
                report,
                revoked: Vec::new(),
                ignored_tombstones: 0,
            });
            let got = store
                .transaction(|tx| barrier.permit_answer(tx, &env, &grant, answer_policy, t0))
                .unwrap()
                .map(|_| ());
            assert_eq!(got, wanted, "{label}");
        }
    }
}
