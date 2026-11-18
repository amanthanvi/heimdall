//! ⟨M05⟩ U3: stop, targets and precedence (ADR-0011 §7, §7.3; m05-plan U3; plan §5 M05-T04,
//! T06; spec §5.6, §6.1, §13.5; R-AU-02), and the orchestrator's ruling I-1.
//!
//! **Targets** (ADR-0011 §7.3). `pause`, `resume`, `cutoff` and `clear_cutoff` with a
//! `target` (`policy`, `profile`, `workspace`, `all`), and `stop {target}`, resolve the
//! target to its standing policies **inside the transaction that applies it**
//! ([`resolve_target`]); an empty set is `NOT_FOUND` / `policy_target_empty` and writes
//! nothing.
//!
//! * A **narrowing** (`pause`, `stop`, a first or an earlier `cutoff`) applies at once: one
//!   transaction under the narrowing protocol (the generation moves once as every other
//!   transaction sees it), one `policy_history` row per changed policy (cause `narrowing`),
//!   and a cutoff's set is the grants whose bound it lowers, which end when it has passed
//!   (as any narrowing ends the grants outside their basis). Never blocked by uncertain
//!   time.
//! * A **widening** (`resume`, `clear_cutoff`, a later `cutoff`) writes **one** `WidenPolicy`
//!   record for the whole set and nothing else. The policies it widens and the revision of
//!   each are its [`DecisionBasis::Targeted`], fixed at creation (I5): approval applies the
//!   recorded action to exactly that set ([`apply`]), and a policy removed or revised since
//!   makes the record stale (`DECISION_STALE`, not consumed: [`precheck`]). Refused while
//!   time is uncertain.
//! * A targeted `cutoff` can be both: it narrows the policies with no cutoff or a later one
//!   (applied now) and widens those with an earlier one (the record). The narrowing part is
//!   never held back by the widening part; the answer is then the widening's
//!   `APPROVAL_REQUIRED` (or `INTERACTION_REQUIRED`, or `TIME_UNCERTAIN`) with effect
//!   `partial`.
//! * **Independence of blocks** (§7.3): `resume` changes only the pause and
//!   `clear_cutoff` only the cutoff ([`apply_change`]); nothing here moves a grant out of a
//!   terminal state.
//!
//! **Stop (policy target)** (§7.2): in the same transaction every policy of the target is
//! paused **and** every live grant resting on one of them (the policy is applicable in the
//! grant's recorded context: [`crate::policy_context::grant_policies`]) is revoked now, with
//! its descendants (a tombstone with cause `authority_withdrawn`, local denial, then the
//! adapters' rounds after the commit, `Operations::complete_withdrawals`). Whatever the
//! request or work ID, new activations are then `POLICY_PAUSED` until an attended `resume`;
//! ended grants stay ended.
//!
//! **Stop (work)** (§7.2; `revoke {target: work}`): a journaled `revoke` operation
//! ([`Operations::revoke_work`], driven by [`Operations::drive_work_stop`]). Its first
//! transaction, under the narrowing protocol, records the [`WorkStop`] and, as an explicit
//! revoke (tombstone, local denial and the first round claimed in that transaction), revokes
//! every grant of the work that no other work references, with its cascade; for a grant
//! other work shares it releases only this work's bindings (their slot references go with
//! them, U6's accounting) and revokes the children delegated through those bindings. Other
//! work is unaffected. The work ID never reactivates: [`work_stop_refusal`] answers every
//! later `ensure`, `delegate` and `bind` for it `CREDENTIAL_EXPIRED` / `work_stopped` before
//! any record is written, and again at resolution and at every activation check
//! (`activation_refusal`).
//!
//! **Ruling I-1** ([`reuse_in`]): an `ensure` (never a delegation) whose
//! work ID already holds an active standing-policy grant in the same environment, with every
//! pin equal to what the request resolves to (profile and profile revision, resolved scope,
//! mechanism, context, the deadline after the `work_deadline` cap; and the same caller),
//! attaches to it as a **separate reference** (a new binding on that grant, as a
//! single-flight follower does), with no second preparation. This happens in the
//! transaction that resolves the request, so the grant is re-validated at exactly the
//! generation the request was resolved at (`activation_refusal`, as for a new binding); one
//! that fails is not reused. Any differing pin keeps M01's path: a separate grant, capped at
//! the work's first deadline. A request that resolves to a pending decision is not
//! "allowed", so it never attaches.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{BindingId, DecisionId, EnvironmentId, GrantId, OperationId, WorkId};
use heimdall_contract::request::{
    PolicyAction, Request, RequiredCapabilities, RevokeData, RevokeRequest, Verdict,
};
use heimdall_contract::trust::{
    PolicyRevisionRef, PolicyTarget, PolicyTargetEntry, PolicyTargetResult, RevokeTarget,
};
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::binding::{BindingRecord, BindingState, ReleaseOutcome, may_act_on};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
use heimdall_domain::idempotency::{HashInput, IdempotencyKey, IdempotencyOutcome, compute_hash};
use heimdall_domain::lifecycle::{GrantEvent, OperationEvent};
use heimdall_domain::operation::{
    EffectClass, EffectReceipt, OperationKind, OperationRecord, ResolvedIntent,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_domain::workspace::{BindingContext, DecisionBasis, PolicyChangeCause, WorkStop};
use heimdall_store::Txn;

use super::narrowing::{NarrowingKind, SetReader};
use super::{
    Activation, AdapterInfo, Emit, Ended, Operations, Round, RoundAnswers, WorkState,
    activation_refusal, ancestry, approval_needed, bound_of, claim_first_round_in,
    complete_round_in, end_in, forget_interrupted, grant_try, internal, managed_driver_m03, op_to,
    plus, put_grant, receipt, render_settled, revoke_locally_in, settle_failed, settle_succeeded,
    trust_m05,
};
use crate::context::Caller;
use crate::ensure::EnsureStage;
use crate::error::{Completed, OpError, OpResult};
use crate::timegate::uncertain;

// ---------------------------------------------------------------------------------
// Gating
// ---------------------------------------------------------------------------------

/// Whether this unit serves `action`: `pause`, `resume`, `cutoff` and `clear_cutoff` with a
/// `target`, and `stop` (`Operations::policy` routes them here after its owner-role and
/// selector checks).
pub(super) fn serves(action: &PolicyAction) -> bool {
    match action {
        PolicyAction::Pause { target, .. }
        | PolicyAction::Resume { target, .. }
        | PolicyAction::Cutoff { target, .. }
        | PolicyAction::ClearCutoff { target, .. } => target.is_some(),
        PolicyAction::Stop { .. } => true,
        _ => false,
    }
}

/// Whether this unit applies a `WidenPolicy` record carrying `action`: a targeted
/// `resume`, `clear_cutoff` or `cutoff` (`trust_m05::{precheck, apply}` route them here).
pub(super) fn serves_widening(action: &PolicyAction) -> bool {
    matches!(
        action,
        PolicyAction::Resume {
            target: Some(_),
            ..
        } | PolicyAction::ClearCutoff {
            target: Some(_),
            ..
        } | PolicyAction::Cutoff {
            target: Some(_),
            ..
        }
    )
}

fn target_of(action: &PolicyAction) -> Option<&PolicyTarget> {
    match action {
        PolicyAction::Pause { target, .. }
        | PolicyAction::Resume { target, .. }
        | PolicyAction::Cutoff { target, .. }
        | PolicyAction::ClearCutoff { target, .. } => target.as_ref(),
        PolicyAction::Stop { target } => Some(target),
        _ => None,
    }
}

fn stale(msg: &str) -> OpError {
    OpError::new(Code::DecisionStale, msg.to_owned())
}

fn target_empty() -> OpError {
    OpError::new(Code::NotFound, "the target names no standing policy")
        .with_reason(reason::POLICY_TARGET_EMPTY)
        .with_resource("policy", None)
}

/// `CREDENTIAL_EXPIRED` / `work_stopped` (ADR-0011 §7.2 "Stop (work)").
fn work_stopped() -> OpError {
    OpError::new(
        Code::CredentialExpired,
        "this work was stopped and never reactivates; new work needs a new work ID",
    )
    .with_reason(reason::WORK_STOPPED)
}

// ---------------------------------------------------------------------------------
// The work-stop check (ADR-0011 §7.2 "Stop (work)")
// ---------------------------------------------------------------------------------

/// ⟨M05⟩ `CREDENTIAL_EXPIRED` / `work_stopped` when `work_id` was stopped in `environment`.
/// A stopped work ID never reactivates: this is asked before any record of an `ensure`, a
/// `delegate` (its own work ID and its parent binding's) or a `bind` is written, again at
/// resolution (`resolve_in`), and at every activation check (`activation_refusal`: a new
/// grant, a new binding, continuing use), so a stop committed at any point in between is
/// seen by the next transaction that would activate.
///
/// # Errors
/// A store failure.
pub(super) fn work_stop_refusal(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    work_id: &WorkId,
) -> heimdall_store::Result<Option<OpError>> {
    Ok(tx.work_stop(environment, work_id)?.map(|_| work_stopped()))
}

/// The work an `ensure` or `delegate` operation creates its binding for: its
/// operation's environment (where the binding is recorded) and its work ID.
pub(super) fn work_of(st: &WorkState) -> Option<(EnvironmentId, WorkId)> {
    match st.request()? {
        Request::Ensure(r) => Some((st.op.environment.clone(), r.work_id)),
        Request::Delegate(r) => Some((st.op.environment.clone(), r.work_id)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------
// Targets: resolution and classification
// ---------------------------------------------------------------------------------

/// The standing policies `target` names, by ID, read in the caller's transaction: one
/// policy; every policy for a profile (personal and workspace); every policy of a
/// workspace; every policy.
fn resolve_target(
    tx: &mut Txn<'_>,
    target: &PolicyTarget,
) -> heimdall_store::Result<Vec<StandingPolicy>> {
    Ok(match target {
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
        // A target this build does not know names nothing (fail closed: no write).
        _ => Vec::new(),
    })
}

/// How a targeted action relates to one stored policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Unchanged,
    Narrows,
    Widens,
}

/// Classified against the stored policy, in the transaction that writes (as M01's
/// single-policy cutoff is): a pause or stop narrows an active policy; a resume widens a
/// paused one; a clear widens a set cutoff; a cutoff narrows a policy with none or a later
/// one and widens one with an earlier one.
fn change_of(action: &PolicyAction, p: &StandingPolicy) -> Change {
    let paused = matches!(p.pause, PauseState::Paused { .. });
    match action {
        PolicyAction::Pause { .. } | PolicyAction::Stop { .. } if paused => Change::Unchanged,
        PolicyAction::Pause { .. } | PolicyAction::Stop { .. } => Change::Narrows,
        PolicyAction::Resume { .. } if paused => Change::Widens,
        PolicyAction::ClearCutoff { .. } if p.cutoff_at.is_some() => Change::Widens,
        PolicyAction::Cutoff { at, .. } => match p.cutoff_at {
            None => Change::Narrows,
            Some(c) if *at < c => Change::Narrows,
            Some(c) if *at == c => Change::Unchanged,
            Some(_) => Change::Widens,
        },
        _ => Change::Unchanged,
    }
}

/// Apply `action`'s own change to `p`, and nothing else (ADR-0011 §7.3: `resume` never
/// clears a cutoff, `clear_cutoff` never resumes a pause).
fn apply_change(action: &PolicyAction, p: &mut StandingPolicy, now: Timestamp) {
    match action {
        PolicyAction::Pause { .. } | PolicyAction::Stop { .. } => {
            p.pause = PauseState::Paused { since: now };
        }
        PolicyAction::Resume { .. } => p.pause = PauseState::Active,
        PolicyAction::ClearCutoff { .. } => p.cutoff_at = None,
        PolicyAction::Cutoff { at, .. } => p.cutoff_at = Some(*at),
        _ => {}
    }
}

/// Write `p` at its next revision as the owner's change at `now`, with its event and its
/// history row (ADR-0011 §4.4).
fn write_revision(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    p: &mut StandingPolicy,
    cause: PolicyChangeCause,
    narrowing: bool,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    p.revision = PolicyRevision(p.revision.0.saturating_add(1));
    p.source = PolicySource::OwnerDecision { decided_at: now };
    tx.upsert_policy(p, narrowing)?;
    emit.policy(tx, p)?;
    trust_m05::record_change(tx, p, cause, now)
}

/// Every `active` or `degraded` grant resting on `p`: a grant of `p`'s profile in whose own
/// environment and recorded context `p` is applicable (ADR-0011 §10 item 1; so a personal
/// policy's grants include that profile's workspace work, and a workspace policy's never
/// reach personal work or another workspace).
fn resting_on(tx: &mut Txn<'_>, p: &StandingPolicy) -> heimdall_store::Result<Vec<GrantSnapshot>> {
    let mut out = Vec::new();
    for g in tx.grants_due(Timestamp::MAX)? {
        if !g.state.permits_use() {
            continue;
        }
        let origin = tx.grant_origin(&g.id)?;
        if origin.as_ref().is_none_or(|o| o.profile != p.profile) {
            continue;
        }
        if crate::policy_context::grant_policies(tx, &g.environment, origin.as_ref())?
            .iter()
            .any(|q| q.id == p.id)
        {
            out.push(g);
        }
    }
    Ok(out)
}

/// The narrowing set of a targeted action, read in a transaction (ADR-0008 §17.16 R1's
/// rule, per policy of the target): for `stop`, every live grant resting on one of them,
/// with its descendants; for a `cutoff`, the live grants of the policies it narrows whose
/// bound it lowers, with their descendants; otherwise empty (a pause stops only new
/// activations; a widening writes a record only).
fn target_set(tx: &mut Txn<'_>, action: &PolicyAction) -> heimdall_store::Result<Vec<GrantId>> {
    let Some(target) = target_of(action) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for p in resolve_target(tx, target)? {
        let lowers_to = match action {
            PolicyAction::Stop { .. } => None,
            PolicyAction::Cutoff { at, .. } if change_of(action, &p) == Change::Narrows => {
                Some(*at)
            }
            _ => continue,
        };
        for g in resting_on(tx, &p)? {
            if seen.contains(&g.id) {
                continue;
            }
            if let Some(at) = lowers_to
                && at >= bound_of(tx, &g, Some(&p.profile))?
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
    }
    Ok(out)
}

fn target_reader(action: PolicyAction) -> SetReader {
    Arc::new(move |tx: &mut Txn<'_>| target_set(tx, &action))
}

/// The revocation roots of `chosen`: each chosen grant none of whose ancestors is chosen,
/// with its descendants (its cascade, the root first), in ID order.
fn roots_of(
    tx: &mut Txn<'_>,
    chosen: &BTreeSet<GrantId>,
) -> heimdall_store::Result<Vec<(GrantId, Vec<GrantId>)>> {
    let mut out = Vec::new();
    for id in chosen {
        let Some(g) = tx.grant(id)? else {
            continue;
        };
        if !g.state.permits_use() || ancestry(tx, &g)?.iter().any(|a| chosen.contains(&a.id)) {
            continue;
        }
        let mut all = vec![id.clone()];
        all.extend(tx.grant_descendants(id)?);
        out.push((id.clone(), all));
    }
    Ok(out)
}

/// Revoke `root` and its cascade `all` in the caller's transaction: the tombstone, then
/// local denial (every grant leaves usable states; every request waiting for approval on
/// one of them ends now).
#[allow(clippy::too_many_arguments)]
fn tombstone_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    root: &GrantId,
    all: &[GrantId],
    cause: RevocationCause,
    revoked_at: Timestamp,
    now: Timestamp,
    op: Option<&OperationId>,
    retention: std::time::Duration,
) -> heimdall_store::Result<()> {
    let generation = tx.authority_generation()?;
    tx.insert_tombstone(&Tombstone {
        grant: root.clone(),
        cascade: all.iter().skip(1).cloned().collect(),
        generation,
        revoked_at,
        remote_pending: Vec::new(),
        cause,
    })?;
    revoke_locally_in(tx, emit, all, cause, now, op, retention)
}

// ---------------------------------------------------------------------------------
// Targeted policy actions and `stop`
// ---------------------------------------------------------------------------------

/// What a targeted action came to.
enum Targeted {
    /// Applied, or nothing to change: every policy of the target after it, with whether
    /// it changed, and the grants a `stop` revoked.
    Applied {
        policies: Vec<(StandingPolicy, bool)>,
        revoked: Vec<GrantId>,
    },
    /// The widening part's one record; `applied` when a narrowing part was applied too.
    Decision { decision: DecisionId, applied: bool },
}

/// One unexpired pending `WidenPolicy` record for exactly `action` over exactly `basis`
/// at `current` (one logical decision, one record: spec §5.5).
fn pending_record(
    tx: &mut Txn<'_>,
    action: &PolicyAction,
    basis: &DecisionBasis,
    now: Timestamp,
    current: heimdall_domain::policy::AuthorityGeneration,
) -> heimdall_store::Result<Option<DecisionId>> {
    for d in tx.pending_decisions()? {
        if matches!(&d.kind, DecisionKind::WidenPolicy { action: a } if a == action)
            && now < d.expires_at
            && d.generation == current
            && tx.decision_basis(&d.id)?.as_ref() == Some(basis)
        {
            return Ok(Some(d.id));
        }
    }
    Ok(None)
}

/// A targeted action's result ([`PolicyTargetResult`], ADR-0006 §17.9 C2): the target,
/// whether anything changed, and every policy of the target after it; for `stop`, the
/// grants it revoked.
fn targeted_view(
    action: &PolicyAction,
    policies: &[(StandingPolicy, bool)],
    revoked: &[GrantId],
) -> Result<serde_json::Value, OpError> {
    let result = PolicyTargetResult {
        target: target_of(action)
            .cloned()
            .ok_or_else(|| internal("not a targeted policy action"))?,
        changed: policies.iter().any(|(_, c)| *c) || !revoked.is_empty(),
        policies: policies
            .iter()
            .map(|(p, changed)| PolicyTargetEntry {
                policy_id: p.id.clone(),
                revision: p.revision.0,
                paused: matches!(p.pause, PauseState::Paused { .. }),
                cutoff_at: p.cutoff_at,
                changed: *changed,
            })
            .collect(),
        revoked: matches!(action, PolicyAction::Stop { .. }).then(|| revoked.to_vec()),
    };
    serde_json::to_value(result).map_err(|_| internal("the result could not be rendered"))
}

impl Operations {
    /// ⟨M05⟩ A targeted `pause`, `resume`, `cutoff` or `clear_cutoff`, or `stop {target}`
    /// (module documentation). The target is resolved, every policy classified and the
    /// narrowing part applied in **one** transaction under the narrowing protocol; a
    /// widening part writes one decision record.
    pub(super) async fn policy_targeted(
        &self,
        caller: &Caller,
        req: PolicyAction,
    ) -> OpResult<serde_json::Value> {
        let Some(target) = target_of(&req).cloned() else {
            return Err(internal("not a targeted policy action"));
        };
        let attended = caller.is_attended();
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let own = self.environment().clone();
        let adapters = self.adapter_infos();
        let retention = self.retention();
        let requested_at = self.inner.config.clock.wall();
        let kind = if matches!(req, PolicyAction::Cutoff { .. }) {
            NarrowingKind::Cutoff
        } else {
            NarrowingKind::Policy
        };
        let action = req.clone();
        let narrowed = self
            .narrow(
                kind,
                requested_at,
                target_reader(req.clone()),
                move |tx, emit, ctx| {
                    let assessed = gate.check(tx)?;
                    let now = match &assessed {
                        Ok(s) => s.wall(),
                        Err(_) => gate.clock().wall(),
                    };
                    let policies = resolve_target(tx, &target)?;
                    if policies.is_empty() {
                        return Ok((Err(target_empty()), Ended::default()));
                    }
                    // The set, read before anything is written (the commit's own re-read).
                    let set = target_set(tx, &action)?;
                    let mut widened: BTreeMap<_, _> = BTreeMap::new();
                    let mut after = Vec::new();
                    let mut applied = false;
                    for mut p in policies {
                        match change_of(&action, &p) {
                            Change::Unchanged => after.push((p, false)),
                            Change::Widens => {
                                widened.insert(p.id.clone(), p.revision);
                                after.push((p, false));
                            }
                            Change::Narrows => {
                                apply_change(&action, &mut p, now);
                                write_revision(
                                    tx,
                                    emit,
                                    &mut p,
                                    PolicyChangeCause::Narrowing,
                                    true,
                                    now,
                                )?;
                                applied = true;
                                after.push((p, true));
                            }
                        }
                    }
                    let mut ended = Ended::default();
                    let mut revoked = Vec::new();
                    match &action {
                        // ADR-0011 §7.2 "Stop (policy target)": revoked now, with the
                        // cascade, whatever the time status (a narrowing never waits).
                        PolicyAction::Stop { .. } => {
                            let chosen: BTreeSet<GrantId> = set.iter().cloned().collect();
                            for (root, all) in roots_of(tx, &chosen)? {
                                tombstone_in(
                                    tx,
                                    emit,
                                    &root,
                                    &all,
                                    RevocationCause::AuthorityWithdrawn,
                                    ctx.committed_at,
                                    now,
                                    None,
                                    retention,
                                )?;
                                revoked.extend(all.iter().cloned());
                                ended.withdrawn.push((root, all));
                            }
                        }
                        // A grant whose bound the new cutoff has passed ends now, as at
                        // any detection (uncertain time ends nothing: the next use or
                        // scheduler pass detects it).
                        PolicyAction::Cutoff { .. } => {
                            if let Ok(safe) = &assessed {
                                for g in &set {
                                    ended.extend(end_in(
                                        tx, emit, &own, &adapters, &gate, g, safe, None, retention,
                                    )?);
                                }
                            }
                        }
                        _ => {}
                    }
                    ctx.destroy = ended
                        .withdrawn
                        .iter()
                        .flat_map(|(_, all)| all.iter().cloned())
                        .collect();
                    if widened.is_empty() {
                        return Ok((
                            Ok(Targeted::Applied {
                                policies: after,
                                revoked,
                            }),
                            ended,
                        ));
                    }
                    let effect = if applied {
                        EffectStatus::Partial
                    } else {
                        EffectStatus::None
                    };
                    if let Err(u) = &assessed {
                        return Ok((Err(uncertain(u).with_effect(effect)), ended));
                    }
                    let basis = DecisionBasis::Targeted { policies: widened };
                    let current = tx.authority_generation()?;
                    if let Some(existing) = pending_record(tx, &action, &basis, now, current)? {
                        return Ok((
                            Ok(Targeted::Decision {
                                decision: existing,
                                applied,
                            }),
                            ended,
                        ));
                    }
                    let d = DecisionRecord {
                        id: decision_id,
                        kind: DecisionKind::WidenPolicy {
                            action: action.clone(),
                        },
                        generation: current,
                        created_at: now,
                        expires_at: plus(now, lifetime),
                        state: DecisionState::Pending,
                        decided_at: None,
                    };
                    tx.prune_decision_bases()?;
                    tx.insert_decision(&d)?;
                    tx.put_decision_basis(&d.id, &basis)?;
                    emit.decision(tx, &d, None)?;
                    Ok((
                        Ok(Targeted::Decision {
                            decision: d.id,
                            applied,
                        }),
                        ended,
                    ))
                },
            )
            .await?;
        let (outcome, ended) = narrowed.value;
        self.complete_withdrawals(ended).await;
        match outcome? {
            Targeted::Applied { policies, revoked } => Ok(Completed::ok(
                Code::Ok,
                targeted_view(&req, &policies, &revoked)?,
            )),
            Targeted::Decision { decision, applied } => {
                let mut e = approval_needed(
                    attended,
                    decision.as_str(),
                    "widening a standing policy needs an attended owner decision",
                )
                .with_resource("decision", Some(decision.to_string()));
                if applied {
                    e = e.with_effect(EffectStatus::Partial);
                }
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------------
// Decide: a targeted widening's record
// ---------------------------------------------------------------------------------

/// The policies record `d` lists, each still at the revision it was listed at;
/// `DECISION_STALE` when its basis is missing or one of them was removed or revised since
/// (ADR-0011 I5).
fn listed(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
) -> heimdall_store::Result<Result<Vec<StandingPolicy>, OpError>> {
    let Some(DecisionBasis::Targeted { policies }) = tx.decision_basis(&d.id)? else {
        return Ok(Err(stale(
            "the decision's basis is unknown; request it again",
        )));
    };
    if policies.is_empty() {
        return Ok(Err(stale("the decision lists no policy; request it again")));
    }
    let mut out = Vec::new();
    for (id, revision) in policies {
        match tx.policy(&id)? {
            Some(p) if p.revision == revision => out.push(p),
            _ => {
                return Ok(Err(stale(
                    "a policy the decision lists was removed or changed since; request it again",
                )));
            }
        }
    }
    Ok(Ok(out))
}

/// ⟨M05⟩ Revision 5.1 (§17.9 C1): the policies a targeted `WidenPolicy` record lists, with
/// the revision each was listed at, read from its decision basis (fixed at creation, I5),
/// for the decision view. `None` for every other record, so its view is unchanged.
///
/// # Errors
/// A store failure.
pub(super) fn listed_policies(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
) -> heimdall_store::Result<Option<Vec<PolicyRevisionRef>>> {
    if !matches!(d.kind, DecisionKind::WidenPolicy { .. }) {
        return Ok(None);
    }
    Ok(match tx.decision_basis(&d.id)? {
        Some(DecisionBasis::Targeted { policies }) => Some(
            policies
                .into_iter()
                .map(|(policy_id, revision)| PolicyRevisionRef {
                    policy_id,
                    revision: revision.0,
                })
                .collect(),
        ),
        _ => None,
    })
}

/// ⟨M05⟩ Inside `decide`'s transaction, **before** the record is completed: an approval of
/// a targeted widening needs every policy it lists unchanged since (ADR-0011 I5); a refusal
/// writes nothing and leaves the record pending (not consumed). Denials need no check.
///
/// # Errors
/// A store failure.
pub(super) fn precheck(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    verdict: Verdict,
) -> heimdall_store::Result<Result<(), OpError>> {
    if verdict == Verdict::Deny {
        return Ok(Ok(()));
    }
    Ok(listed(tx, d)?.map(|_| ()))
}

/// ⟨M05⟩ Inside `decide`'s transaction, **after** the record was completed: an approval
/// applies the recorded action to exactly the listed policies (one revision and one
/// `policy_history` row each, cause the decision), changing only the action's own field
/// (§7.3 independence); a denial records nothing (the owner's own request has no
/// cooldown, ADR-0011 §4.3). No request waits on these records. A refusal here rolls the
/// whole transaction back (nothing consumed).
///
/// # Errors
/// A store failure.
pub(super) fn apply(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &DecisionRecord,
    action: &PolicyAction,
    verdict: Verdict,
    now: Timestamp,
) -> heimdall_store::Result<Result<Vec<OperationId>, OpError>> {
    if verdict == Verdict::Approve {
        let policies = match listed(tx, record)? {
            Ok(p) => p,
            Err(e) => return Ok(Err(e)),
        };
        for mut p in policies {
            apply_change(action, &mut p, now);
            write_revision(
                tx,
                emit,
                &mut p,
                PolicyChangeCause::Decision {
                    decision: record.id.clone(),
                },
                false,
                now,
            )?;
        }
    }
    tx.delete_decision_basis(&record.id)?;
    Ok(Ok(Vec::new()))
}

// ---------------------------------------------------------------------------------
// Stop (work): `revoke {target: work}`
// ---------------------------------------------------------------------------------

/// What phase 1 of a work stop revokes and releases.
#[derive(Debug, Default)]
struct WorkPlan {
    /// Revocation roots, each with its cascade (the root first).
    revoke: Vec<(GrantId, Vec<GrantId>)>,
    /// This work's active bindings on grants other work shares.
    release: Vec<BindingRecord>,
}

/// Whether an active binding of **other** work references `g` (a single-flight follower's
/// separate reference, ADR-0006 §13.5). A delegated child's reference on its parent is not
/// other work sharing it: the child is revoked with its parent's cascade.
fn shared_with_other_work(
    tx: &mut Txn<'_>,
    g: &GrantId,
    environment: &EnvironmentId,
    work: &WorkId,
) -> heimdall_store::Result<bool> {
    for r in tx.grant_references(g)? {
        if let Some(b) = tx.binding(&r.binding)?
            && b.grant == *g
            && b.state == BindingState::Active
            && (b.environment != *environment || b.work_id != *work)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The live grants in `parent`'s subtree delegated through one of `mine` (a binding of the
/// stopped work): each such child's own binding names one of `mine` as its parent.
fn delegated_through(
    tx: &mut Txn<'_>,
    parent: &GrantId,
    mine: &BTreeSet<BindingId>,
) -> heimdall_store::Result<Vec<GrantId>> {
    let mut out = Vec::new();
    for d in tx.grant_descendants(parent)? {
        if !tx.grant(&d)?.is_some_and(|g| g.state.permits_use()) {
            continue;
        }
        for r in tx.grant_references(&d)? {
            if let Some(b) = tx.binding(&r.binding)?
                && b.grant == d
                && b.parent.as_ref().is_some_and(|p| mine.contains(p))
            {
                out.push(d.clone());
                break;
            }
        }
    }
    Ok(out)
}

/// What stopping `work` in `environment` does now, read in the caller's transaction: every
/// live grant this work holds (an active binding of it) that no other work references is
/// revoked with its cascade; on a grant other work shares, this work's bindings are
/// released and the children delegated through them revoked.
fn work_plan(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    work: &WorkId,
) -> heimdall_store::Result<WorkPlan> {
    let bindings = tx.bindings_for_work(environment, work)?;
    let mine: BTreeSet<BindingId> = bindings.iter().map(|b| b.id.clone()).collect();
    let held: BTreeSet<GrantId> = bindings
        .iter()
        .filter(|b| b.state == BindingState::Active)
        .map(|b| b.grant.clone())
        .collect();
    let mut chosen = BTreeSet::new();
    let mut release = Vec::new();
    for gid in &held {
        if !tx.grant(gid)?.is_some_and(|g| g.state.permits_use()) {
            continue;
        }
        if shared_with_other_work(tx, gid, environment, work)? {
            release.extend(
                bindings
                    .iter()
                    .filter(|b| b.state == BindingState::Active && b.grant == *gid)
                    .cloned(),
            );
            chosen.extend(delegated_through(tx, gid, &mine)?);
        } else {
            chosen.insert(gid.clone());
        }
    }
    Ok(WorkPlan {
        revoke: roots_of(tx, &chosen)?,
        release,
    })
}

/// The revocations an earlier phase 1 of this work stop committed (a restart or a same-key
/// retry completes them from their records): every tombstoned grant this work bound, and
/// every tombstoned child delegated through one of its bindings, with its cascade.
fn stopped_roots(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    work: &WorkId,
) -> heimdall_store::Result<Vec<(GrantId, Vec<GrantId>)>> {
    let bindings = tx.bindings_for_work(environment, work)?;
    let mine: BTreeSet<BindingId> = bindings.iter().map(|b| b.id.clone()).collect();
    let mut candidates: BTreeSet<GrantId> = BTreeSet::new();
    for b in &bindings {
        candidates.insert(b.grant.clone());
        for d in tx.grant_descendants(&b.grant)? {
            for r in tx.grant_references(&d)? {
                if let Some(c) = tx.binding(&r.binding)?
                    && c.grant == d
                    && c.parent.as_ref().is_some_and(|p| mine.contains(p))
                {
                    candidates.insert(d.clone());
                }
            }
        }
    }
    let mut out: Vec<(GrantId, Vec<GrantId>)> = Vec::new();
    let mut covered = BTreeSet::new();
    for g in candidates {
        if covered.contains(&g) {
            continue;
        }
        let Some(t) = tx.tombstone(&g)? else {
            continue;
        };
        if t.cause != RevocationCause::Revoke {
            continue;
        }
        let mut all = vec![g.clone()];
        all.extend(t.cascade.iter().filter(|c| **c != g).cloned());
        covered.extend(all.iter().cloned());
        out.push((g, all));
    }
    Ok(out)
}

fn work_reader(environment: EnvironmentId, work: WorkId) -> SetReader {
    Arc::new(move |tx: &mut Txn<'_>| {
        Ok(work_plan(tx, &environment, &work)?
            .revoke
            .into_iter()
            .flat_map(|(_, all)| all)
            .collect())
    })
}

/// Whether `caller` may stop `work`: the owner may stop any work ID (a stop only ever
/// narrows); anyone else only a work with at least one binding, every one of which it may
/// act on (binding IDs and work IDs are not bearer credentials, spec §11.2).
fn may_stop(
    tx: &mut Txn<'_>,
    caller: &CallerContext,
    environment: &EnvironmentId,
    work: &WorkId,
) -> heimdall_store::Result<bool> {
    if caller.is_owner() {
        return Ok(true);
    }
    let bindings = tx.bindings_for_work(environment, work)?;
    Ok(!bindings.is_empty() && bindings.iter().all(|b| may_act_on(b, caller)))
}

/// Release one binding of a stopped work on a shared grant, as `release` does (the store's
/// release, a managed binding's slot rows and its slot references, U6's accounting; the
/// grant's last reference releases it, never revokes). Returns whether it was a managed
/// binding (its endpoint and files go after the commit) and the grant when this released
/// it.
fn release_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    b: &BindingRecord,
    caller: &CallerContext,
    now: Timestamp,
) -> heimdall_store::Result<(bool, Option<GrantId>)> {
    let ReleaseOutcome::Released {
        remaining_references,
    } = tx.release_binding(&b.id, caller, now)?
    else {
        return Ok((false, None));
    };
    let managed = managed_driver_m03::release_binding_slots_in(tx, b, now)?;
    let mut released = None;
    if remaining_references == 0
        && let Some(mut g) = tx.grant(&b.grant)?
        && grant_try(&mut g, GrantEvent::LastReferenceReleased)
    {
        put_grant(tx, emit, &g, None)?;
        released = Some(g.id);
    }
    Ok((managed, released))
}

/// What phase 1 of a work stop committed (or found committed).
#[derive(Debug, Default)]
struct Phase1 {
    roots: Vec<(GrantId, Vec<GrantId>)>,
    rounds: Vec<Round>,
    managed: Vec<BindingId>,
    released: Vec<GrantId>,
    committed: bool,
    refused: Option<OpError>,
}

impl Operations {
    /// ⟨M05⟩ `revoke {target: work {environment, work_id}}` (ADR-0011 §7.2 "Stop (work)"):
    /// admitted as a `revoke` operation (idempotent by request ID; the hash names the
    /// target, so the same request ID naming a grant is `REQUEST_CONFLICT`), then driven by
    /// [`Operations::drive_work_stop`]. The environment defaults to the runtime's own and
    /// must be in its managed set; a caller other than the owner sees `NOT_FOUND` unless it
    /// may act on every binding of the work. Nothing is written for a refusal.
    pub(super) async fn revoke_work(
        &self,
        caller: &Caller,
        req: RevokeRequest,
    ) -> OpResult<RevokeData> {
        let Some(RevokeTarget::Work {
            environment,
            work_id,
        }) = req.target.clone()
        else {
            return Err(OpError::new(
                Code::UsageError,
                "this revoke target is not available in this build",
            ));
        };
        let own = self.environment().clone();
        let environment = environment.unwrap_or_else(|| own.clone());
        let (ctx, own2, env2, work2) = (
            caller.context.clone(),
            own.clone(),
            environment.clone(),
            work_id.clone(),
        );
        let visible = self
            .write(move |tx, _| {
                if let Err(e) = crate::environments::admit(tx, &own2, &env2)? {
                    return Ok(Err(e));
                }
                Ok(Ok(may_stop(tx, &ctx, &env2, &work2)?))
            })
            .await??;
        if !visible {
            return Err(OpError::new(Code::NotFound, "unknown work").with_resource("work", None));
        }
        let now = self.narrowing_now().await;
        let target = RevokeTarget::Work {
            environment: Some(environment.clone()),
            work_id: work_id.clone(),
        };
        let hash = compute_hash(
            OperationKind::Revoke,
            &HashInput {
                environment: &own,
                profile: None,
                profile_revision: None,
                scope: &BTreeSet::new(),
                deadline_intent: None,
                work_id: Some(&work_id),
                required_capabilities: &RequiredCapabilities::default(),
                parent_binding: None,
                extra: serde_json::json!({ "target": target }),
            },
        )
        .map_err(|_| OpError::new(Code::UsageError, "the request cannot be canonicalized"))?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind: OperationKind::Revoke,
            request_id: req.request_id.clone(),
        };
        // The stored request names the environment resolved now, so a restart drives
        // exactly this work.
        let stored = RevokeRequest {
            target: Some(target),
            ..req
        };
        let request_json = serde_json::to_value(Request::Revoke(stored))
            .map_err(|_| internal("request is not serializable"))?;
        let outcome = self
            .admit(
                key,
                hash,
                OperationKind::Revoke,
                EffectClass::LocalResources,
                request_json,
                now,
                false,
                None,
                own,
            )
            .await?;
        if let Some(e) = Self::refuse_outcome(&outcome) {
            return Err(e);
        }
        let IdempotencyOutcome::Replay(id) = outcome else {
            return Err(internal("unexpected idempotency outcome"));
        };
        if let Some(Err(e)) = self
            .lead_bounded(&id, false, Some(self.inner.config.limits.max_wait))
            .await
        {
            return Err(e);
        }
        let st = self.load_work(&id).await?;
        render_settled::<RevokeData>(&st.op)
    }

    /// ⟨M05⟩ Drive a stored work stop (`drive_revoke` routes a `revoke` with a target
    /// here), in the phases of an explicit revoke:
    ///
    /// 1. once, under the narrowing protocol over the grants it revokes: the
    ///    [`WorkStop`], each unshared grant's tombstone and local denial with the first
    ///    round claimed (cause `revoke`), and this work's bindings on shared grants
    ///    released; the caller's standing is checked again in this transaction;
    /// 2. the claimed rounds (local denial through the responsible adapters);
    /// 3. settle with the residual (`complete_round_in` per root; the managed rows).
    ///
    /// A later drive (restart recovery, a same-key retry) finds phase 1 committed and
    /// completes from the records without calling the adapters again.
    #[allow(clippy::too_many_lines)]
    pub(super) async fn drive_work_stop(&self, id: &OperationId) -> Result<(), OpError> {
        let st = self.load_work(id).await?;
        if st.op.state.is_quiescent() {
            return Ok(());
        }
        let Some(Request::Revoke(RevokeRequest {
            target:
                Some(RevokeTarget::Work {
                    environment,
                    work_id,
                }),
            ..
        })) = st.request()
        else {
            return Err(internal("the stored revoke names no work"));
        };
        let environment = environment.unwrap_or_else(|| self.environment().clone());
        let now = self.narrowing_now().await;
        let retention = self.retention();
        let configured = self.adapter_identities();
        let cap = self.inner.revocation_cap.load(Ordering::SeqCst);
        let interrupted = Arc::clone(&self.inner.interrupted_rounds);
        let requested_at = st.op.created_at;
        let (id2, env2, work2) = (id.clone(), environment.clone(), work_id.clone());
        let narrowed = self
            .narrow(
                NarrowingKind::Revoke,
                requested_at,
                work_reader(environment.clone(), work_id.clone()),
                move |tx, emit, ctx| {
                    let Some(mut op) = tx.operation(&id2)? else {
                        return Ok(Phase1::default());
                    };
                    if op.state != OperationState::Queued {
                        return Ok(Phase1 {
                            roots: stopped_roots(tx, &env2, &work2)?,
                            ..Phase1::default()
                        });
                    }
                    // The caller's standing, again in the transaction that writes (a
                    // binding another caller made since admission is not this caller's).
                    if !may_stop(tx, &op.key.caller, &env2, &work2)? {
                        let err = OpError::new(Code::NotFound, "unknown work")
                            .with_resource("work", None);
                        settle_failed(tx, emit, &mut op, &err, now, retention)?;
                        return Ok(Phase1 {
                            refused: Some(err),
                            ..Phase1::default()
                        });
                    }
                    let plan = work_plan(tx, &env2, &work2)?;
                    if tx.work_stop(&env2, &work2)?.is_none() {
                        tx.insert_work_stop(&WorkStop {
                            environment: env2.clone(),
                            work_id: work2.clone(),
                            stopped_at: ctx.committed_at,
                        })?;
                    }
                    let mut rounds = Vec::new();
                    for (root, all) in &plan.revoke {
                        tombstone_in(
                            tx,
                            emit,
                            root,
                            all,
                            RevocationCause::Revoke,
                            ctx.committed_at,
                            now,
                            Some(&id2),
                            retention,
                        )?;
                        // An explicit revoke re-arms the bounded schedule (ADR-0006
                        // §13.11 item 4), claimed with the tombstone (§13.12).
                        let round =
                            claim_first_round_in(tx, root, all, &configured, now, true, cap)?;
                        forget_interrupted(&interrupted, root);
                        rounds.push(round);
                    }
                    ctx.destroy = plan
                        .revoke
                        .iter()
                        .flat_map(|(_, all)| all.iter().cloned())
                        .collect();
                    let mut managed = Vec::new();
                    let mut released = Vec::new();
                    for b in &plan.release {
                        let (is_managed, ended) = release_in(tx, emit, b, &op.key.caller, now)?;
                        if is_managed {
                            managed.push(b.id.clone());
                        }
                        released.extend(ended);
                    }
                    op_to(&mut op, OperationEvent::Start, now)?;
                    tx.update_operation(&op)?;
                    emit.op(tx, &op)?;
                    Ok(Phase1 {
                        roots: plan.revoke,
                        rounds,
                        managed,
                        released,
                        committed: true,
                        refused: None,
                    })
                },
            )
            .await?;
        let committed_here = narrowed
            .value
            .committed
            .then_some(narrowed.report.committed_at);
        let phase = narrowed.value;
        if let Some(e) = phase.refused {
            return Err(e);
        }
        // Phase 2: each claimed round (none when phase 1 was committed earlier).
        let mut answers = Vec::with_capacity(phase.roots.len());
        for i in 0..phase.roots.len() {
            let round = phase.rounds.get(i).cloned().unwrap_or_default();
            answers.push(self.run_round(&round, now).await);
        }
        let claims: Vec<Option<u64>> = phase.rounds.iter().map(|r| r.claim).collect();
        // Phase 3: settle with the residual of every root.
        let (id3, env3, work3, roots) = (
            id.clone(),
            environment.clone(),
            work_id.clone(),
            phase.roots.clone(),
        );
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id3)? else {
                return Ok(());
            };
            if op.state != OperationState::Running {
                return Ok(());
            }
            let mut data = RevokeData {
                local_applied: true,
                remote_pending: Vec::new(),
                latest_possible_credential_expiry: None,
                remote_effects: Vec::new(),
                owned_connections: Vec::new(),
                notes: Vec::new(),
                requested_at: None,
                committed_at: None,
            };
            let mut all_grants = Vec::new();
            let mut merged = RoundAnswers::default();
            for (i, (root, all)) in roots.iter().enumerate() {
                let claim = claims.get(i).copied().flatten();
                let a = answers.get(i).cloned().unwrap_or_default();
                let d = complete_round_in(tx, emit, root, all, claim, &a, None, Some(&id3))?;
                for g in d.remote_pending {
                    if !data.remote_pending.contains(&g) {
                        data.remote_pending.push(g);
                    }
                }
                data.latest_possible_credential_expiry = match (
                    data.latest_possible_credential_expiry,
                    d.latest_possible_credential_expiry,
                ) {
                    (Some(x), Some(y)) => Some(x.max(y)),
                    (x, y) => x.or(y),
                };
                merged.merge_remote_effects(a.remote_effects);
                all_grants.extend(all.iter().cloned());
            }
            managed_driver_m03::fill_revoke_data(
                tx,
                &all_grants,
                &mut data,
                merged.remote_effects,
            )?;
            // ⟨M03⟩ U0b row 27 (G), as for a grant revoke: the stored originals.
            data.requested_at = Some(op.created_at);
            data.committed_at = match committed_here {
                Some(t) => Some(t),
                None => tx.work_stop(&env3, &work3)?.map(|s| s.stopped_at),
            };
            let value = serde_json::to_value(&data)?;
            settle_succeeded(tx, emit, &mut op, Code::Ok, value, now, retention)
        })
        .await?;
        // After the commit and outside every gate: the released managed bindings'
        // endpoints and files, and a grant whose last reference went (never expected on a
        // shared grant; handled as `release` does).
        for b in &phase.managed {
            self.after_binding_release_m03(b).await;
        }
        for g in &phase.released {
            self.after_release_m03(g, now).await;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------
// Ruling I-1: an `ensure` of a work ID reuses its active grant when every pin matches
// ---------------------------------------------------------------------------------

/// The grant an `ensure` of `work` resolved as `resolved` may attach to (module
/// documentation, "Ruling I-1"), read and re-validated in the caller's transaction.
#[allow(clippy::too_many_arguments)]
fn reusable_grant(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    adapters: &[AdapterInfo],
    op: &OperationRecord,
    work: &WorkId,
    resolved: &ResolvedIntent,
    now: Timestamp,
) -> heimdall_store::Result<Option<GrantId>> {
    let Some(adapter) = resolved.adapter.as_ref() else {
        return Ok(None);
    };
    let context = match &resolved.workspace {
        Some(w) => BindingContext::Workspace {
            workspace: w.clone(),
        },
        None => BindingContext::Personal,
    };
    let mut seen = BTreeSet::new();
    for b in tx.bindings_for_work(&op.environment, work)? {
        if b.state != BindingState::Active || b.parent.is_some() || !seen.insert(b.grant.clone()) {
            continue;
        }
        let Some(g) = tx.grant(&b.grant)? else {
            continue;
        };
        let pinned = g.state.permits_use()
            && g.parent.is_none()
            && g.environment == op.environment
            && matches!(g.source, AuthorizationSource::StandingPolicy { .. })
            && g.scope == resolved.scope
            && g.deadline.effective == resolved.deadline.effective
            && b.profile == resolved.profile
            && b.profile_revision == resolved.profile_revision
            && b.scope == resolved.scope
            && b.mechanism == adapter.mechanism;
        if !pinned {
            continue;
        }
        let Some(origin) = tx.grant_origin(&g.id)? else {
            continue;
        };
        let same_origin = origin.profile == resolved.profile
            && origin.profile_revision == resolved.profile_revision
            && origin.mechanism == adapter.mechanism
            && origin.adapter.as_ref().is_none_or(|a| a == adapter)
            && origin.workspace == resolved.workspace
            && origin.caller == op.key.caller;
        if !same_origin
            || tx
                .binding_context(&b.id)?
                .unwrap_or(BindingContext::Personal)
                != context
        {
            continue;
        }
        // Re-validated at the current generation, exactly as the attached binding's own
        // activation will be (state, tombstones, environment, pause and cutoff, the
        // chain's re-validation, the policy revision, the bound, the work stop, the
        // mechanism): a grant that fails is not reused.
        let probe = ResolvedIntent {
            grant: Some(g.id.clone()),
            ..resolved.clone()
        };
        if activation_refusal(
            tx,
            own,
            adapters,
            &probe,
            &g,
            now,
            Activation::NewBinding,
            Some((&op.environment, work)),
        )?
        .is_some()
        {
            continue;
        }
        return Ok(Some(g.id));
    }
    Ok(None)
}

/// ⟨M05⟩ Ruling I-1, in the transaction that resolved an operation's request as allowed
/// (after its intent and `ResolveMechanism` receipt are written; time assessed safe there):
/// when it is an `ensure` whose work ID holds a reusable grant ([`reusable_grant`]), the
/// intent pins that grant and `Coalesce` and `Reconcile` are recorded as not attempted,
/// exactly as for a single-flight follower, so `Recheck` and `Commit` give it a **new
/// binding** on that grant (`Activation::NewBinding`, its facts from the grant's stored
/// history) and nothing is prepared again. Re-validation happens at the generation the
/// request was just resolved at. Returns whether it attached.
///
/// # Errors
/// A store failure.
pub(super) fn reuse_in(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    adapters: &[AdapterInfo],
    op: &OperationRecord,
    kind: OperationKind,
    work: &WorkId,
    now: Timestamp,
) -> heimdall_store::Result<bool> {
    if kind != OperationKind::Ensure {
        return Ok(false);
    }
    let Some(mut intent) = tx.recovery_intent(&op.id)? else {
        return Ok(false);
    };
    let Some(resolved) = intent.resolved.clone().filter(|r| r.grant.is_none()) else {
        return Ok(false);
    };
    let Some(gid) = reusable_grant(tx, own, adapters, op, work, &resolved, now)? else {
        return Ok(false);
    };
    if let Some(r) = intent.resolved.as_mut() {
        r.grant = Some(gid);
    }
    tx.set_recovery_intent(&op.id, &intent)?;
    tx.append_stage_receipt(
        &op.id,
        &receipt(EnsureStage::Coalesce, now, EffectReceipt::NotAttempted),
    )?;
    tx.append_stage_receipt(
        &op.id,
        &receipt(EnsureStage::Reconcile, now, EffectReceipt::NotAttempted),
    )?;
    Ok(true)
}
