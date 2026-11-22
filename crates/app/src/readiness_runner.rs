//! ⟨M06 U3⟩ The runner's own view of one of its grants (ADR-0012 §4.2 step 4, §4.5; ADR-0005
//! §3.5 step 4, §3.6 "Runner deadline"): its bound, its runner anchor and the install check.
//! Read inside the caller's store transaction, so the runner's install of a certificate judges
//! the grant, its generation, its tombstones and its deadline in the same transaction that pins
//! the issuer.
//!
//! * [`runner_bound`]: `min(D, every ancestor's deadline, the effective cutoff)`, never later
//!   than a bound already persisted with the grant's anchor (the rule of the local
//!   transactions, mirrored from the grant's own records).
//! * [`derived_budget_end`]: the runner's deadline on its own continuous clock from one
//!   qualifying time exchange `(t₁, T_c, t₂)`: `t₂ + (bound − (T_c + (t₂ − t₁)))`. The
//!   controller's time at t₂ lies in `[T_c, T_c + (t₂ − t₁)]` and the upper end is taken, so
//!   it may stop early, never late.
//! * [`shorten_runner_anchor`]: the grant's anchor in this boot becomes the earliest of its
//!   existing budget, the wall-clock branch and the derived deadline. It only ever moves
//!   earlier (the store refuses a longer budget); another boot's anchor is void and replaced.
//! * [`runner_install_check`]: ADR-0005 §3.5's refusal list against the runner's own store,
//!   through the very predicate the local reserve, publish and issuer read-only checks share
//!   (`operations::issuance_check_read_only`), with the runner's time (`Safe` only under a
//!   qualifying sample) and its anchor. The CA is judged by the caller against
//!   `issuer_trust` (the bounds name none, so the local CA registry plays no part).

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{GrantId, IssuanceId};
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::issuance::{CertificateBounds, IssuanceEntry, IssuanceRefusal, IssuanceState};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::scope::AccessPair;
use heimdall_domain::time::{GrantAnchor, TimeAnchor, TimeStatus};
use heimdall_store::{StoreError, Txn};

use crate::operations::IssuanceFacts;

/// The deepest ancestry followed (as the local transactions').
const MAX_ANCESTRY: usize = 64;

/// The grant's absolute bound and its parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerBound {
    /// `min(D, ancestors, cutoff)`, never later than a persisted anchor's bound.
    pub bound: Timestamp,
    /// The grant's deadline (D).
    pub deadline: Timestamp,
    /// The earliest ancestor deadline, if any.
    pub parent_deadline: Option<Timestamp>,
    /// The effective cutoff of the grant's policy, if any.
    pub cutoff: Option<Timestamp>,
}

/// [`RunnerBound`] of `grant` inside `tx` (module docs).
///
/// # Errors
///
/// A store error; an ancestry deeper than 64 is corrupt.
pub fn runner_bound(
    tx: &mut Txn<'_>,
    grant: &GrantSnapshot,
) -> heimdall_store::Result<RunnerBound> {
    let mut parent_deadline: Option<Timestamp> = None;
    let mut next = grant.parent.clone();
    let mut depth = 0;
    while let Some(id) = next {
        depth += 1;
        if depth > MAX_ANCESTRY {
            return Err(StoreError::Corrupt("grant ancestry is too deep".into()));
        }
        let Some(g) = tx.grant(&id)? else {
            break;
        };
        parent_deadline =
            Some(parent_deadline.map_or(g.deadline.effective, |p| p.min(g.deadline.effective)));
        next = g.parent.clone();
    }
    let origin = tx.grant_origin(&grant.id)?;
    let context = crate::policy_context::grant_context(origin.as_ref());
    let cutoff = match &origin {
        Some(o) => {
            let policies = tx.policies_for(&o.profile, &grant.environment)?;
            heimdall_domain::policy::resolve_policy(&policies, &context).and_then(|p| p.cutoff_at)
        }
        None => None,
    };
    let mut bound = grant.deadline.effective;
    for t in [parent_deadline, cutoff].into_iter().flatten() {
        bound = bound.min(t);
    }
    if let Some(a) = tx.grant_anchor(&grant.id)? {
        bound = bound.min(a.bound);
    }
    Ok(RunnerBound {
        bound,
        deadline: grant.deadline.effective,
        parent_deadline,
        cutoff,
    })
}

/// One qualifying time exchange (ADR-0005 §3.6 "Runner deadline"): the runner's continuous
/// clock when it issued the nonce (`t1`) and when the answer arrived (`t2`), in `boot`, and
/// the controller's wall time bound to the nonce (`controller_time`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeExchange {
    /// The boot both readings belong to.
    pub boot_id: heimdall_domain::time::BootId,
    /// Continuous clock at the challenge.
    pub t1: Duration,
    /// Continuous clock at the answer.
    pub t2: Duration,
    /// The controller's wall time T_c.
    pub controller_time: Timestamp,
}

/// The runner's deadline for `bound` on its continuous clock (module docs): `t2 + (bound −
/// (T_c + (t2 − t1)))`, saturating at `t2` when that is already past.
#[must_use]
pub fn derived_budget_end(exchange: &TimeExchange, bound: Timestamp) -> Duration {
    let rtt = exchange.t2.saturating_sub(exchange.t1);
    let rtt = jiff::SignedDuration::try_from(rtt).unwrap_or(jiff::SignedDuration::MAX);
    let controller_upper = exchange
        .controller_time
        .checked_add(rtt)
        .unwrap_or(Timestamp::MAX);
    let left = Duration::try_from(bound.duration_since(controller_upper)).unwrap_or(Duration::ZERO);
    exchange.t2.saturating_add(left)
}

/// Shorten `grant`'s runner anchor from `exchange` (module docs): in `now`'s boot the anchor's
/// budget becomes the earliest of the stored budget, the wall-clock branch at `now` (applied
/// only when `wall_trusted`) and [`derived_budget_end`]; its bound is `bound` (never later
/// than a stored one). Nothing is written, and `None` returned, when `exchange` belongs to
/// another boot than `now`.
///
/// # Errors
///
/// A store error.
pub fn shorten_runner_anchor(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    bound: Timestamp,
    exchange: &TimeExchange,
    now: &TimeAnchor,
    wall_trusted: bool,
) -> heimdall_store::Result<Option<GrantAnchor>> {
    if exchange.boot_id != now.boot_id {
        return Ok(None);
    }
    let mut budget_end = derived_budget_end(exchange, bound);
    if wall_trusted {
        let wall_left =
            Duration::try_from(bound.duration_since(now.wall)).unwrap_or(Duration::ZERO);
        budget_end = budget_end.min(now.continuous.saturating_add(wall_left));
    }
    let candidate = match tx.grant_anchor(grant)? {
        Some(stored) if stored.anchor.boot_id == now.boot_id => GrantAnchor {
            grant: grant.clone(),
            anchor: stored.anchor.clone(),
            bound: stored.bound.min(bound),
            budget_end: stored.budget_end.min(budget_end),
        },
        Some(stored) => GrantAnchor {
            grant: grant.clone(),
            anchor: now.clone(),
            bound: stored.bound.min(bound),
            budget_end,
        },
        None => GrantAnchor {
            grant: grant.clone(),
            anchor: now.clone(),
            bound,
            budget_end,
        },
    };
    if tx.grant_anchor(grant)?.as_ref() == Some(&candidate) {
        return Ok(Some(candidate));
    }
    Ok(Some(tx.set_grant_anchor(&candidate)?))
}

/// ADR-0005 §3.5's refusal list for installing one certificate of `grant` for `pair` on the
/// runner (module docs). `bounds` are the certificate's own (serial, key ID, principal,
/// validity, extensions, subject) **without** a CA; `generation` is the generation the
/// controller named; `time` is `Safe` only under a qualifying time sample in `now`'s boot;
/// `critical_option` whether the certificate carries one. The caller has already checked that
/// the subject is the K_env it registered for this grant and generation. A grant still
/// `preparing` is a new activation (a pause refuses it); an `active` or `degraded` one is a
/// re-issue within the grant, which a pause does not block (ADR-0005 §3.7).
///
/// **Two passes, one transaction.** The first is the shared predicate itself
/// (`operations::issuance_check_read_only`: grant state, generation and its judged
/// re-validation, tombstones, ancestry, policy revision, pair, principal, then the rest). For a
/// `managed_certificate` grant that predicate next asks the **local** CA registry, which on a
/// runner holds none of the controller's CAs (the runner judges the CA against
/// `issuer_trust`, ADR-0012 §4.2): a CA-registry refusal there means every predicate before it
/// held, and the second pass runs the remaining ones through `heimdall_domain::issuance::check`
/// with no CA input: cutoff and pause for a new activation, the bound, time and the runner
/// anchor's admission, `valid_before`, critical options, permitted extensions, and, as the first
/// pass does after its verdict, the generation the controller named and a degradation that
/// refuses every use.
///
/// # Errors
///
/// A store error. The verdict is the inner result.
#[allow(clippy::too_many_arguments)]
pub fn runner_install_check(
    tx: &mut Txn<'_>,
    grant: &GrantSnapshot,
    pair: &AccessPair,
    bounds: &CertificateBounds,
    generation: u64,
    critical_option: bool,
    time: TimeStatus,
    now: &TimeAnchor,
) -> heimdall_store::Result<Result<(), IssuanceRefusal>> {
    if bounds.ca_fingerprint.is_some() {
        // The runner judges the CA against issuer_trust; a CA here would reach the local
        // registry, which holds none of the controller's.
        return Ok(Err(IssuanceRefusal::UnknownCa));
    }
    let new_activation = grant.state == heimdall_contract::GrantState::Preparing;
    let entry = IssuanceEntry {
        id: IssuanceId::from_random_bytes([0; 16]),
        grant: grant.id.clone(),
        generation: AuthorityGeneration(generation),
        pair: pair.clone(),
        bounds: bounds.clone(),
        state: IssuanceState::Published,
        reserved_at: now.wall,
        settled_at: None,
        void_reason: None,
        continuing: !new_activation,
    };
    let facts = IssuanceFacts {
        new_activation,
        subject_registered: true,
        critical_option,
    };
    match crate::operations::issuance_check_read_only(tx, &entry, &facts, now, &time)? {
        Err(
            IssuanceRefusal::UnknownCa
            | IssuanceRefusal::CaNotVerifiedForPair
            | IssuanceRefusal::CaRetiring,
        ) => {}
        verdict => return Ok(verdict),
    }
    after_ca(tx, grant, pair, bounds, generation, &facts, time, now)
}

/// The second pass of [`runner_install_check`]: the predicates after the CA check, with no CA
/// input, over the grant and its chain at the current generation (the first pass judged them
/// current) and the applicable policy view.
#[allow(clippy::too_many_arguments)]
fn after_ca(
    tx: &mut Txn<'_>,
    grant: &GrantSnapshot,
    pair: &AccessPair,
    bounds: &CertificateBounds,
    generation: u64,
    facts: &IssuanceFacts,
    time: TimeStatus,
    now: &TimeAnchor,
) -> heimdall_store::Result<Result<(), IssuanceRefusal>> {
    let current = tx.authority_generation()?;
    if current.0 != generation {
        return Ok(Err(IssuanceRefusal::StaleGeneration));
    }
    // As the first pass would after an `Ok`: a grant degraded for a reason whose rule refuses
    // every use is refused (a re-issue after a restart is not such a reason).
    if grant.state == heimdall_contract::GrantState::Degraded
        && tx
            .grant_degradation(&grant.id)?
            .is_some_and(crate::operations::degraded_refuses_use)
    {
        return Ok(Err(IssuanceRefusal::MechanismUnavailable));
    }
    let at_current = |mut g: GrantSnapshot| {
        g.generation = current;
        g
    };
    let mut chain = Vec::new();
    let mut next = grant.parent.clone();
    while let Some(id) = next {
        if chain.len() >= MAX_ANCESTRY {
            return Err(StoreError::Corrupt("grant ancestry is too deep".into()));
        }
        let Some(g) = tx.grant(&id)? else {
            break;
        };
        next = g.parent.clone();
        chain.push(at_current(g));
    }
    let origin = tx.grant_origin(&grant.id)?;
    let context = crate::policy_context::grant_context(origin.as_ref());
    let policy = match &origin {
        Some(o) => {
            let policies = tx.policies_for(&o.profile, &grant.environment)?;
            heimdall_domain::policy::resolve_policy(&policies, &context).map(|mut p| {
                if !facts.new_activation {
                    // Continuing work does not see a pause (ADR-0006 §13.6 item 1).
                    p.pause = heimdall_domain::policy::PauseState::Active;
                }
                p
            })
        }
        None => None,
    };
    let mut subject = at_current(grant.clone());
    if let (heimdall_domain::grant::AuthorizationSource::StandingPolicy { revision }, Some(p)) =
        (&mut subject.source, &policy)
    {
        *revision = p.revision;
    }
    let tombstoned = tx.denied_ancestor(&grant.id)?.is_some();
    let jump_pairs = crate::catalog::jump_pairs_of(tx, &grant.scope.pairs)?;
    let permitted = heimdall_domain::issuance::extension_profile(grant, pair, &jump_pairs);
    let admission = match (time, tx.grant_anchor(&grant.id)?) {
        (TimeStatus::Safe, Some(anchor)) => heimdall_domain::time::admission(&anchor, now),
        _ => heimdall_domain::time::Admission::NeedsAnchor,
    };
    let (parent, ancestors) = match chain.split_first() {
        Some((p, rest)) => (Some(p), rest),
        None => (None, &[][..]),
    };
    Ok(heimdall_domain::issuance::check(
        &heimdall_domain::issuance::IssuanceCheck {
            grant: &subject,
            parent,
            ancestors,
            policy: policy.as_ref(),
            expected_policy_revision: policy.as_ref().map(|p| p.revision),
            current_generation: current,
            tombstoned,
            pair,
            bounds,
            permitted_extensions: &permitted,
            new_activation: facts.new_activation,
            subject_registered: facts.subject_registered,
            critical_option: facts.critical_option,
            time,
            admission,
            now: now.wall,
            enrolled_cas: None,
        },
    ))
}
