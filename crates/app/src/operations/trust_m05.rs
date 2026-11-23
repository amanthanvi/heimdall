//! ⟨M05⟩ U2: trust records, standing-policy actions and their decisions (ADR-0011 §2.1,
//! §2.4, §3.1, §3.4, §4.4; §10 items 1, 2, 5, 7; ADR-0006 revision 5 §17.6 R5-Q3).
//!
//! **I1, one path creates or widens authority.** Standing policies, workspace records and
//! an environment's `automatic_activation` are created or widened here **only** by an
//! attended owner `decide` applying a recorded decision ([`apply`], called from
//! `Operations::decide` after the record is completed in the same transaction). Every
//! owner `policy` request that would widen writes a decision record and nothing else;
//! every narrowing applies at once through the narrowing protocol (one transaction, the
//! generation moves, and only the grants outside their basis end).
//!
//! **I5, a decision's action is fixed at creation from server-side state.** A
//! `trust_workspace` request is compared with what the server observes (the access digest)
//! and computes (the proposal: the manifest's request ∩ the profile's latest snapshot); a
//! mismatch writes nothing. What a record was created from (the observation, the profile
//! revision) is kept beside it as its [`DecisionBasis`], and approval re-probes the
//! working directory **before** its transaction and requires the observation to be
//! unchanged inside it (`DECISION_STALE`, not consumed, otherwise).
//!
//! The requests served here: `create`, `extend_scope`, `narrow_scope`, `set_max_window`,
//! `remove`, `trust_workspace`, `reconcile_workspace`. U3's (targets, `stop`) are
//! `stop_m05`'s, and so are the `WidenPolicy` records of a targeted action ([`precheck`]
//! and [`apply`] hand them over).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{
    AccountName, BindingId, DecisionId, DestinationId, EnvironmentId, GrantId, OperationId,
    PolicyId, WorkspaceId,
};
use heimdall_contract::request::{AccessPairRef, Capability, PolicyAction, Verdict};
use heimdall_contract::trust::{
    DefaultProfileView, PoliciesView, PolicyRevisionView, PolicyView, TrustProposal, WorkContext,
};
use heimdall_contract::{Code, GrantState, OperationState, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::grant::GrantOrigin;
use heimdall_domain::operation::OperationKind;
use heimdall_domain::policy::{
    DEFAULT_MAX_WINDOW, LockBehavior, PauseState, PolicyContext, PolicyRevision, PolicySource,
    StandingPolicy, parse_max_window, strictest_lock_behavior,
};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::Scope;
use heimdall_domain::time as dtime;
use heimdall_domain::workspace::{
    BindingContext, DecisionBasis, DecisionCooldown, PolicyChangeCause, PolicyHistoryEntry,
    WorkspaceMatch, WorkspaceRecord, WorkspaceState, quoted_label,
};
use heimdall_store::Txn;

use super::narrowing::{NarrowingKind, SetReader};
use super::{
    AdapterInfo, Emit, Ended, Operations, PolicyOutcome, approval_needed, current_delta,
    decision_owner, delta_is_empty, end_in, grant_context, internal, merged_policy, plus,
    policy_view, proceed_covered, unenrolled, waiting,
};
use crate::context::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::ports::{ProbeError, ProbedWorkspace, WorkspaceProbe};
use crate::timegate::uncertain;

// ---------------------------------------------------------------------------------
// Gating and wiring
// ---------------------------------------------------------------------------------

/// Whether this unit serves `action` (U3's targeted forms and `stop` are `stop_m05`'s).
pub(super) fn serves(action: &PolicyAction) -> bool {
    matches!(
        action,
        PolicyAction::Create { .. }
            | PolicyAction::ExtendScope { .. }
            | PolicyAction::NarrowScope { .. }
            | PolicyAction::SetMaxWindow { .. }
            | PolicyAction::Remove { .. }
            | PolicyAction::TrustWorkspace { .. }
            | PolicyAction::ReconcileWorkspace { .. }
    )
}

/// Whether this unit applies a `WidenPolicy` record carrying `action`.
pub(super) fn serves_widening(action: &PolicyAction) -> bool {
    matches!(
        action,
        PolicyAction::Create { .. }
            | PolicyAction::ExtendScope { .. }
            | PolicyAction::SetMaxWindow { .. }
    )
}

/// The refusal of a workspace request or decision when no [`WorkspaceProbe`] is set.
pub(super) fn no_probe() -> OpError {
    OpError::driver_unavailable("workspace trust is not available in this runtime")
}

fn stale(msg: &str) -> OpError {
    OpError::new(Code::DecisionStale, msg.to_owned())
}

pub(super) fn usage(msg: &str) -> OpError {
    OpError::new(Code::UsageError, msg.to_owned())
}

pub(super) fn changed_since_review() -> OpError {
    usage("the workspace changed since it was reviewed; review it again")
        .with_effect(heimdall_contract::envelope::EffectStatus::None)
}

fn unknown_policy() -> OpError {
    OpError::new(Code::NotFound, "unknown policy").with_resource("policy", None)
}

fn random16() -> Result<[u8; 16], OpError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| {
        OpError::new(
            Code::InternalError,
            "operating system randomness unavailable",
        )
    })?;
    Ok(b)
}

/// A fresh policy ID (`pol_<32 hex>`; spec §4.2: durable IDs never derive from names or
/// time).
fn new_policy_id() -> Result<PolicyId, OpError> {
    use std::fmt::Write as _;
    let mut s = String::from("pol_");
    for b in random16()? {
        let _ = write!(s, "{b:02x}");
    }
    PolicyId::parse(&s).map_err(|_| internal("a policy ID could not be formed"))
}

impl Operations {
    /// ⟨M05⟩ Set the workspace observer (ADR-0011 §2.2–§2.3), once; a later call is
    /// ignored and returns `false`. Without one, `trust_workspace`, `reconcile_workspace`
    /// and their decisions answer `CAPABILITY_UNAVAILABLE` / `driver_unavailable` before
    /// any record is written or consumed.
    pub fn set_workspace_probe(&self, probe: Arc<dyn WorkspaceProbe>) -> bool {
        self.inner.workspace_probe.set(probe).is_ok()
    }

    pub(super) fn workspace_probe(&self) -> Option<Arc<dyn WorkspaceProbe>> {
        self.inner.workspace_probe.get().cloned()
    }

    /// Run the probe outside any transaction (it performs file I/O).
    pub(super) async fn probe_workspace(
        &self,
        probe: Arc<dyn WorkspaceProbe>,
        environment: EnvironmentId,
        cwd: String,
        records: Vec<WorkspaceRecord>,
    ) -> Result<Result<ProbedWorkspace, ProbeError>, OpError> {
        tokio::task::spawn_blocking(move || probe.probe(&environment, &cwd, &records))
            .await
            .map_err(super::join_error)
    }

    /// The environment's active workspace records, in one transaction.
    pub(super) async fn active_records(&self) -> Result<Vec<WorkspaceRecord>, OpError> {
        let own = self.environment().clone();
        self.write(move |tx, _| active_records(tx, &own)).await
    }
}

pub(super) fn active_records(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
) -> heimdall_store::Result<Vec<WorkspaceRecord>> {
    Ok(tx
        .workspaces_in_environment(environment)?
        .into_iter()
        .filter(|r| r.state == WorkspaceState::Active)
        .collect())
}

pub(super) fn probe_error(e: ProbeError) -> OpError {
    match e {
        ProbeError::IdentityUnavailable => OpError::new(
            Code::CapabilityUnavailable,
            "this filesystem has no stable file identity, so a workspace cannot be trusted here",
        )
        .with_reason(reason::WORKSPACE_IDENTITY_UNAVAILABLE),
        ProbeError::Manifest { reason: r } => {
            let r = if r == reason::MANIFEST_AUTHORITY_KEY {
                reason::MANIFEST_AUTHORITY_KEY
            } else {
                reason::MANIFEST_INVALID
            };
            usage("the workspace manifest is refused").with_reason(r)
        }
        ProbeError::Io => OpError::new(Code::NotFound, "the working directory could not be read"),
    }
}

// ---------------------------------------------------------------------------------
// History, cooldown bookkeeping, small writers
// ---------------------------------------------------------------------------------

/// Record an applied policy change (ADR-0011 §4.4): its `policy_history` row (revision,
/// the record as applied, cause, time), and the deletion of the policy's cooldowns of any
/// other revision (§4.3: a cooldown lasts until the revision changes). Called in the
/// transaction that writes the policy, for every action, M01–M03 ones included.
pub(super) fn record_change(
    tx: &mut Txn<'_>,
    p: &StandingPolicy,
    cause: PolicyChangeCause,
    at: Timestamp,
) -> heimdall_store::Result<()> {
    tx.append_policy_history(&PolicyHistoryEntry {
        policy: p.id.clone(),
        revision: p.revision,
        record: p.clone(),
        cause,
        at,
    })?;
    for c in tx.decision_cooldowns_for_policy(&p.id)? {
        if c.revision != p.revision {
            tx.delete_decision_cooldown(&c.key)?;
        }
    }
    Ok(())
}

/// Write `p` at its next revision as the owner's change at `now`, with its event and
/// history row.
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
    record_change(tx, p, cause, now)
}

/// Set an environment's `automatic_activation` (ADR-0011 §3.1: the approving decision
/// sets it). Only ever called from [`apply`].
fn allow_automatic_activation(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
) -> heimdall_store::Result<()> {
    let mut rec = tx
        .environment(environment)?
        .unwrap_or_else(|| unenrolled(environment));
    if !rec.permissions.automatic_activation {
        rec.permissions.automatic_activation = true;
        tx.upsert_environment(&rec)?;
    }
    Ok(())
}

/// ADR-0011 §3.1 "at most one personal policy per environment is marked `default`": every
/// other personal default sharing an environment with `keep` loses the flag (its own
/// revision and history row).
fn move_default(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    keep: &StandingPolicy,
    decision: &DecisionId,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    if !keep.default || keep.workspace.is_some() {
        return Ok(());
    }
    for mut q in tx.policies()? {
        if q.id != keep.id
            && q.workspace.is_none()
            && q.default
            && !q.environments.is_disjoint(&keep.environments)
        {
            q.default = false;
            write_revision(
                tx,
                emit,
                &mut q,
                PolicyChangeCause::Decision {
                    decision: decision.clone(),
                },
                true,
                now,
            )?;
        }
    }
    Ok(())
}

/// The first policy (by ID) of a workspace: production creates one.
pub(super) fn workspace_policy(
    tx: &mut Txn<'_>,
    workspace: &WorkspaceId,
) -> heimdall_store::Result<Option<StandingPolicy>> {
    Ok(tx
        .policies()?
        .into_iter()
        .find(|p| p.workspace.as_ref() == Some(workspace)))
}

/// Whether a personal policy for `profile` already applies in one of `environments`
/// (production keeps one per profile and environment; ADR-0006 §17.6 R5-Q10).
fn personal_exists(
    tx: &mut Txn<'_>,
    profile: &heimdall_contract::ids::ProfileId,
    environments: &BTreeSet<EnvironmentId>,
) -> heimdall_store::Result<bool> {
    for e in environments {
        if tx
            .policies_for(profile, e)?
            .iter()
            .any(|p| p.workspace.is_none())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn admit_all(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    environments: &BTreeSet<EnvironmentId>,
) -> heimdall_store::Result<Result<(), OpError>> {
    for e in environments {
        if let Err(err) = crate::environments::admit(tx, own, e)? {
            return Ok(Err(err));
        }
    }
    Ok(Ok(()))
}

/// What the environments of a personal `create` are ([`admit_create`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreateTarget {
    /// Environments of this runtime's managed set: the policy applies locally.
    Managed,
    /// ⟨M06 W5; record source (b)⟩ One recorded runner environment: the policy is only
    /// this controller's authorization to sign that runner's pending grants.
    Runner,
}

/// ⟨M06 W5; m06-plan §2 item 3 "Record source (b)"; ADR-0005 §3.5 condition 8 (b)⟩ Admit
/// the environments of a personal `create`. The managed set, as ever; and, for exactly one
/// more case, a **single recorded runner environment** on which this controller holds a
/// role the role table allows to issue (`role_may_issue`; no role is named here). That
/// policy activates nothing locally (see [`names_unmanaged`]), so it can neither be the
/// `default` nor be mixed with another environment. Everything else is refused as before:
/// an environment that is neither managed nor a recorded runner keeps the managed-set
/// refusal.
fn admit_create(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    environments: &BTreeSet<EnvironmentId>,
    default: bool,
) -> heimdall_store::Result<Result<CreateTarget, OpError>> {
    let mut runner = None;
    for e in environments {
        let Err(refusal) = crate::environments::admit(tx, own, e)? else {
            continue;
        };
        match crate::remote_status_driver::pin_of(tx, e)? {
            Some(pin) => runner = Some(pin),
            None => return Ok(Err(refusal)),
        }
    }
    let Some(pin) = runner else {
        return Ok(Ok(CreateTarget::Managed));
    };
    if environments.len() != 1 {
        return Ok(Err(usage(
            "a policy that names a runner environment names that environment only",
        )));
    }
    if default {
        return Ok(Err(usage(
            "a policy that names a runner environment activates nothing here and cannot be the default",
        )));
    }
    if !crate::remote_status_driver::role_may_issue(pin.role) {
        return Ok(Err(OpError::new(
            Code::CapabilityUnavailable,
            "this controller's role on the runner does not let it issue for its grants",
        )
        .with_reason(heimdall_contract::envelope::reason::ROLE_INSUFFICIENT)
        .with_effect(heimdall_contract::EffectStatus::None)));
    }
    Ok(Ok(CreateTarget::Runner))
}

/// ⟨M06 W5; record source (b)⟩ Whether `p` names an environment outside this runtime's
/// managed set that was never in it: a policy created for a runner ([`admit_create`]; no
/// other path stores one). Such a policy never gains another environment, so it can never
/// start applying locally.
fn names_unmanaged(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    p: &StandingPolicy,
) -> heimdall_store::Result<bool> {
    for e in &p.environments {
        if tx.admit_environment(own, e)?
            == heimdall_domain::environment::EnvironmentAdmission::Unmanaged
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The profile's current definition (its latest snapshot), or `NOT_FOUND`.
pub(super) fn latest_profile(
    tx: &mut Txn<'_>,
    profile: &heimdall_contract::ids::ProfileId,
) -> heimdall_store::Result<Result<ProfileDefinition, OpError>> {
    Ok(tx.profile(profile)?.ok_or_else(|| {
        OpError::new(Code::NotFound, "unknown profile").with_resource("profile", None)
    }))
}

/// A29: request content never widens the profile.
fn within_profile(
    profile: &ProfileDefinition,
    pairs: &BTreeSet<AccessPairRef>,
    capabilities: &BTreeSet<Capability>,
) -> Result<(), OpError> {
    if !pairs.is_subset(&profile.scope.pairs) {
        return Err(usage("the requested pairs are outside the profile")
            .with_resource("profile", Some(profile.id.to_string())));
    }
    if !capabilities.is_subset(&profile.scope.capabilities) {
        return Err(usage("the requested capabilities are outside the profile")
            .with_resource("profile", Some(profile.id.to_string())));
    }
    Ok(())
}

/// The window a `create` asks for: its string, or the default (P04), never above `max`.
fn create_window(text: Option<&String>, max: Duration) -> Result<Duration, OpError> {
    match text {
        Some(t) => parse_max_window(t, max).map_err(|e| usage(&e.to_string())),
        None => Ok(DEFAULT_MAX_WINDOW.min(max)),
    }
}

// ---------------------------------------------------------------------------------
// Owner policy actions: create, extend_scope, narrow_scope, set_max_window, remove
// ---------------------------------------------------------------------------------

/// How an action relates to the stored policy, read in the committing transaction.
enum Class {
    Unchanged(Box<StandingPolicy>),
    /// A widening: a decision record (with its basis, when it has one), recording the
    /// replacement action when there is one (an owner `extend_scope` records only what it
    /// adds, spec §12.3), else the request's action verbatim.
    Widening(Option<DecisionBasis>, Option<Box<PolicyAction>>),
    Narrowing(Box<StandingPolicy>, Narrow),
}

enum Narrow {
    RemovePairs(BTreeSet<AccessPairRef>),
    Window(Duration),
    RevokeOnLock,
    Remove,
}

#[allow(clippy::too_many_lines)]
fn classify(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    action: &PolicyAction,
    max: Duration,
) -> heimdall_store::Result<Result<Class, OpError>> {
    macro_rules! refuse {
        ($e:expr) => {
            return Ok(Err($e))
        };
    }
    macro_rules! policy {
        ($id:expr) => {
            match tx.policy($id)? {
                Some(p) => p,
                None => refuse!(unknown_policy()),
            }
        };
    }
    Ok(Ok(match action {
        PolicyAction::Create {
            profile,
            environments,
            max_window,
            default,
        } => {
            if let Err(e) = admit_create(tx, own, environments, *default)? {
                refuse!(e);
            }
            let def = match latest_profile(tx, profile)? {
                Ok(d) => d,
                Err(e) => refuse!(e),
            };
            if let Err(e) = create_window(max_window.as_ref(), max) {
                refuse!(e);
            }
            if personal_exists(tx, profile, environments)? {
                refuse!(usage(
                    "a personal policy for this profile already applies in that environment; extend it instead"
                ));
            }
            Class::Widening(
                Some(DecisionBasis::Create {
                    profile_revision: def.revision,
                }),
                None,
            )
        }
        PolicyAction::ExtendScope {
            policy_id,
            pairs,
            capabilities,
            environments,
            background_work,
        } => {
            let p = policy!(policy_id);
            let def = match latest_profile(tx, &p.profile)? {
                Ok(d) => d,
                Err(e) => refuse!(e),
            };
            if let Err(e) = within_profile(&def, pairs, capabilities) {
                refuse!(e);
            }
            if let Err(e) = admit_all(tx, own, environments)? {
                refuse!(e);
            }
            // ⟨M06 W5⟩ A runner's policy stays that runner's alone.
            if !environments.is_subset(&p.environments) && names_unmanaged(tx, own, &p)? {
                refuse!(usage(
                    "a policy that names a runner environment names that environment only"
                ));
            }
            let adds = !pairs.is_subset(&p.scope.pairs)
                || !capabilities.is_subset(&p.scope.capabilities)
                || !environments.is_subset(&p.environments)
                || (*background_work == Some(true) && p.lock_behavior != LockBehavior::Continue);
            let narrows =
                *background_work == Some(false) && p.lock_behavior == LockBehavior::Continue;
            if adds {
                // Review shows only the added authority (spec §12.3; W3, from U9a): the
                // record carries what the policy lacks, never what it already has. The
                // action is still fixed from server state at creation (ADR-0011 I5), and a
                // `background_work: false` part is kept as requested (applied whole).
                let added = PolicyAction::ExtendScope {
                    policy_id: policy_id.clone(),
                    pairs: pairs.difference(&p.scope.pairs).cloned().collect(),
                    capabilities: capabilities
                        .difference(&p.scope.capabilities)
                        .copied()
                        .collect(),
                    environments: environments.difference(&p.environments).cloned().collect(),
                    background_work: match background_work {
                        Some(true) if p.lock_behavior == LockBehavior::Continue => None,
                        other => *other,
                    },
                };
                Class::Widening(None, Some(Box::new(added)))
            } else if narrows {
                Class::Narrowing(Box::new(p), Narrow::RevokeOnLock)
            } else {
                Class::Unchanged(Box::new(p))
            }
        }
        PolicyAction::NarrowScope { policy_id, pairs } => {
            let p = policy!(policy_id);
            let removed: BTreeSet<AccessPairRef> =
                pairs.intersection(&p.scope.pairs).cloned().collect();
            if removed.is_empty() {
                Class::Unchanged(Box::new(p))
            } else {
                Class::Narrowing(Box::new(p), Narrow::RemovePairs(removed))
            }
        }
        PolicyAction::SetMaxWindow {
            policy_id,
            max_window,
        } => {
            let p = policy!(policy_id);
            let w = match parse_max_window(max_window, max) {
                Ok(w) => w,
                Err(e) => refuse!(usage(&e.to_string())),
            };
            // Widening iff longer than the stored window, compared here, in the
            // transaction that writes (as a cutoff is).
            match w.cmp(&p.max_window) {
                std::cmp::Ordering::Greater => Class::Widening(None, None),
                std::cmp::Ordering::Equal => Class::Unchanged(Box::new(p)),
                std::cmp::Ordering::Less => Class::Narrowing(Box::new(p), Narrow::Window(w)),
            }
        }
        PolicyAction::Remove { policy_id } => {
            let p = policy!(policy_id);
            Class::Narrowing(Box::new(p), Narrow::Remove)
        }
        _ => refuse!(OpError::driver_unavailable(
            "this policy action is not available in this build"
        )),
    }))
}

/// The live grants `p` applies to (their own environment, their recorded context;
/// ADR-0011 §10 item 1), each with its descendants.
fn live_grants_of(
    tx: &mut Txn<'_>,
    p: &StandingPolicy,
    touches: impl Fn(&heimdall_domain::grant::GrantSnapshot) -> bool,
) -> heimdall_store::Result<Vec<GrantId>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for g in tx.grants_due(Timestamp::MAX)? {
        if !g.state.permits_use() || seen.contains(&g.id) || !touches(&g) {
            continue;
        }
        if grant_context(tx, &g)?.profile.as_ref() != Some(&p.profile) {
            continue;
        }
        let origin = tx.grant_origin(&g.id)?;
        if !crate::policy_context::grant_policies(tx, &g.environment, origin.as_ref())?
            .iter()
            .any(|q| q.id == p.id)
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

/// The narrowing set of an M05 action (ADR-0008 §17.16 R1's rule for M05): empty unless
/// the action narrows the stored policy; then the live grants it applies to that the
/// change can touch, with their descendants.
fn narrowing_set(tx: &mut Txn<'_>, action: &PolicyAction) -> heimdall_store::Result<Vec<GrantId>> {
    let pid = match action {
        PolicyAction::NarrowScope { policy_id, .. }
        | PolicyAction::Remove { policy_id }
        | PolicyAction::SetMaxWindow { policy_id, .. }
        | PolicyAction::ExtendScope { policy_id, .. } => policy_id,
        _ => return Ok(Vec::new()),
    };
    let Some(p) = tx.policy(pid)? else {
        return Ok(Vec::new());
    };
    match action {
        PolicyAction::NarrowScope { pairs, .. } => {
            let removed: BTreeSet<AccessPairRef> =
                pairs.intersection(&p.scope.pairs).cloned().collect();
            if removed.is_empty() {
                return Ok(Vec::new());
            }
            live_grants_of(tx, &p, |g| !g.scope.pairs.is_disjoint(&removed))
        }
        PolicyAction::Remove { .. } => live_grants_of(tx, &p, |_| true),
        PolicyAction::SetMaxWindow { max_window, .. } => {
            match parse_max_window(max_window, Duration::MAX) {
                Ok(w) if w < p.max_window => live_grants_of(tx, &p, |_| true),
                _ => Ok(Vec::new()),
            }
        }
        PolicyAction::ExtendScope {
            pairs,
            capabilities,
            environments,
            background_work,
            ..
        } => {
            let adds = !pairs.is_subset(&p.scope.pairs)
                || !capabilities.is_subset(&p.scope.capabilities)
                || !environments.is_subset(&p.environments)
                || (*background_work == Some(true) && p.lock_behavior != LockBehavior::Continue);
            if !adds && *background_work == Some(false) && p.lock_behavior == LockBehavior::Continue
            {
                live_grants_of(tx, &p, |_| true)
            } else {
                Ok(Vec::new())
            }
        }
        _ => Ok(Vec::new()),
    }
}

fn m05_reader(action: PolicyAction) -> SetReader {
    Arc::new(move |tx: &mut Txn<'_>| narrowing_set(tx, &action))
}

/// Apply a narrowing now (ADR-0011 §4.4: only the owner narrows; no decision).
fn apply_narrowing(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    mut p: StandingPolicy,
    change: Narrow,
    now: Timestamp,
) -> heimdall_store::Result<StandingPolicy> {
    match change {
        Narrow::RemovePairs(removed) => {
            p.scope.pairs = p.scope.pairs.difference(&removed).cloned().collect();
        }
        Narrow::Window(w) => p.max_window = w,
        Narrow::RevokeOnLock => p.lock_behavior = LockBehavior::RevokeOnLock,
        Narrow::Remove => {
            // The policy goes; its workspace record goes `stale` (records go only
            // `active → stale`, ADR-0006 §17.6 item 17); its cooldowns go with it; the
            // history keeps one last row, the record as removed.
            tx.delete_policy(&p.id)?;
            if let Some(ws) = &p.workspace
                && tx
                    .workspace(ws)?
                    .is_some_and(|r| r.state == WorkspaceState::Active)
            {
                tx.set_workspace_state(ws, WorkspaceState::Active, WorkspaceState::Stale)?;
            }
            for c in tx.decision_cooldowns_for_policy(&p.id)? {
                tx.delete_decision_cooldown(&c.key)?;
            }
            p.revision = PolicyRevision(p.revision.0.saturating_add(1));
            p.source = PolicySource::OwnerDecision { decided_at: now };
            p.default = false;
            emit.policy(tx, &p)?;
            tx.append_policy_history(&PolicyHistoryEntry {
                policy: p.id.clone(),
                revision: p.revision,
                record: p.clone(),
                cause: PolicyChangeCause::Narrowing,
                at: now,
            })?;
            return Ok(p);
        }
    }
    write_revision(tx, emit, &mut p, PolicyChangeCause::Narrowing, true, now)?;
    Ok(p)
}

/// One unexpired pending `WidenPolicy` record for exactly `action` at `current`.
fn pending_widening(
    tx: &mut Txn<'_>,
    action: &PolicyAction,
    now: Timestamp,
    current: heimdall_domain::policy::AuthorityGeneration,
) -> heimdall_store::Result<Option<DecisionRecord>> {
    Ok(tx.pending_decisions()?.into_iter().find(|d| {
        matches!(&d.kind, DecisionKind::WidenPolicy { action: a } if a == action)
            && now < d.expires_at
            && d.generation == current
    }))
}

impl Operations {
    /// ⟨M05⟩ The owner-channel actions this unit serves (`policy()` routes them here after
    /// its owner-role and selector checks).
    pub(super) async fn policy_m05(
        &self,
        caller: &Caller,
        req: PolicyAction,
    ) -> OpResult<serde_json::Value> {
        let attended = caller.is_attended();
        let outcome = match &req {
            PolicyAction::TrustWorkspace { .. } | PolicyAction::ReconcileWorkspace { .. } => {
                self.workspace_action(req.clone()).await?
            }
            _ => self.policy_change(req.clone()).await?,
        };
        match outcome {
            PolicyOutcome::Applied(p, changed) => {
                Ok(Completed::ok(Code::Ok, policy_view(&p, changed, &req)))
            }
            PolicyOutcome::Decision(dec) => Err(approval_needed(
                attended,
                dec.as_str(),
                "widening a standing policy needs an attended owner decision",
            )
            .with_resource("decision", Some(dec.to_string()))),
        }
    }

    /// `create`, `extend_scope`, `narrow_scope`, `set_max_window`, `remove`: classified
    /// against the stored policy inside the committing transaction, which runs under the
    /// narrowing protocol (the M01–M03 `policy()` pattern). A widening writes its decision
    /// record only (not under `TIME_UNCERTAIN`; an equal pending record is returned); a
    /// narrowing applies now, moves the generation, and ends the grants of its set that
    /// no longer validate.
    async fn policy_change(&self, req: PolicyAction) -> Result<PolicyOutcome, OpError> {
        let max = self.inner.config.default_window;
        // Pure checks before anything is read.
        match &req {
            PolicyAction::Create {
                environments,
                max_window,
                ..
            } => {
                if environments.is_empty() {
                    return Err(usage("a policy names the environments it applies in"));
                }
                create_window(max_window.as_ref(), max)?;
            }
            PolicyAction::SetMaxWindow { max_window, .. } => {
                parse_max_window(max_window, max).map_err(|e| usage(&e.to_string()))?;
            }
            // ⟨M03⟩ `background_work: false` records `revoke_on_lock`, so the M03 rule
            // applies: refused before anything is written without a usable lock signal
            // (ADR-0008 D9 item 3).
            PolicyAction::ExtendScope {
                policy_id,
                background_work: Some(false),
                ..
            } => {
                if let Some(e) = self.policy_refusal_m03(&PolicyAction::SetLockBehavior {
                    policy_id: policy_id.clone(),
                    behavior: LockBehavior::RevokeOnLock,
                }) {
                    return Err(e);
                }
            }
            _ => {}
        }
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let own = self.environment().clone();
        let adapters = self.adapter_infos();
        let retention = self.retention();
        let requested_at = self.inner.config.clock.wall();
        let action = req.clone();
        let narrowed = self
            .narrow(
                NarrowingKind::Policy,
                requested_at,
                m05_reader(req.clone()),
                move |tx, emit, ctx| {
                    let assessed = gate.check(tx)?;
                    let now = match &assessed {
                        Ok(s) => s.wall(),
                        Err(_) => gate.clock().wall(),
                    };
                    let class = match classify(tx, &own, &action, max)? {
                        Ok(c) => c,
                        Err(e) => return Ok(Err(e)),
                    };
                    match class {
                        Class::Unchanged(p) => {
                            Ok(Ok((PolicyOutcome::Applied(p, false), Ended::default())))
                        }
                        Class::Widening(basis, replacement) => {
                            if let Err(u) = &assessed {
                                return Ok(Err(uncertain(u)));
                            }
                            let action = replacement.map_or_else(|| action.clone(), |a| *a);
                            let current = tx.authority_generation()?;
                            if let Some(existing) = pending_widening(tx, &action, now, current)? {
                                return Ok(Ok((
                                    PolicyOutcome::Decision(existing.id),
                                    Ended::default(),
                                )));
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
                            if let Some(b) = &basis {
                                tx.put_decision_basis(&d.id, b)?;
                            }
                            emit.decision(tx, &d, None)?;
                            Ok(Ok((PolicyOutcome::Decision(d.id), Ended::default())))
                        }
                        Class::Narrowing(p, change) => {
                            // The set, read before the write (the commit's own re-read).
                            let set = narrowing_set(tx, &action)?;
                            let p = apply_narrowing(tx, emit, *p, change, now)?;
                            let mut ended = Ended::default();
                            if let Ok(safe) = &assessed {
                                for g in &set {
                                    ended.extend(end_in(
                                        tx, emit, &own, &adapters, &gate, g, safe, None, retention,
                                    )?);
                                }
                            }
                            ctx.destroy = ended
                                .withdrawn
                                .iter()
                                .flat_map(|(_, all)| all.iter().cloned())
                                .collect();
                            Ok(Ok((PolicyOutcome::Applied(Box::new(p), true), ended)))
                        }
                    }
                },
            )
            .await?;
        let (outcome, ended) = narrowed.value?;
        self.complete_withdrawals(ended).await;
        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------------
// Workspace actions: trust_workspace, reconcile_workspace
// ---------------------------------------------------------------------------------

/// What a workspace request comes to.
pub(super) enum Built {
    /// Already trusted (or a member) with a workspace policy: no new record.
    Existing(Box<StandingPolicy>),
    /// The record to create, with its basis.
    Record(Box<DecisionKind>, Option<DecisionBasis>),
}

/// Resolve one manifest environment token against the local catalog: an environment of
/// the managed set whose record label or ID is the token; `native` names the runtime's
/// own environment.
fn resolve_environment(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    token: &str,
) -> heimdall_store::Result<Option<EnvironmentId>> {
    if token == "native" {
        return Ok(Some(own.clone()));
    }
    for e in crate::environments::members(tx, own)? {
        if e.as_str() == token
            || tx
                .environment(&e)?
                .and_then(|r| r.label)
                .is_some_and(|l| l == token)
        {
            return Ok(Some(e));
        }
    }
    Ok(None)
}

/// The proposal the server computes for a manifest root (ADR-0011 I5): the manifest's
/// request ∩ the profile's latest snapshot, its pair and environment tokens resolved
/// against the local catalog. A list the manifest names of which nothing resolves is
/// refused (`manifest_invalid`): an empty list would mean "the whole profile" or "this
/// environment", which the manifest did not ask for.
pub(super) fn manifest_proposal(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    m: &crate::ports::ProbedManifest,
    def: &ProfileDefinition,
) -> heimdall_store::Result<Result<TrustProposal, OpError>> {
    let invalid = |msg: &str| usage(msg).with_reason(reason::MANIFEST_INVALID);
    let mut pairs = BTreeSet::new();
    for token in &m.pairs {
        let parsed = token.split_once(':').and_then(|(d, a)| {
            Some(AccessPairRef {
                destination: DestinationId::parse(d).ok()?,
                account: AccountName::parse(a).ok()?,
            })
        });
        let Some(pair) = parsed else {
            return Ok(Err(invalid("a manifest pair is not destination:account")));
        };
        if def.scope.pairs.contains(&pair) {
            pairs.insert(pair);
        }
    }
    if !m.pairs.is_empty() && pairs.is_empty() {
        return Ok(Err(invalid(
            "none of the manifest's pairs is in the profile",
        )));
    }
    let mut environments = BTreeSet::new();
    for token in &m.environments {
        if let Some(e) = resolve_environment(tx, own, token)? {
            environments.insert(e);
        }
    }
    if !m.environments.is_empty() && environments.is_empty() {
        return Ok(Err(invalid(
            "none of the manifest's environments is known here",
        )));
    }
    let mut capabilities = BTreeSet::new();
    for token in &m.capabilities {
        if let Ok(c) =
            serde_json::from_value::<Capability>(serde_json::Value::String(token.clone()))
            && def.scope.capabilities.contains(&c)
        {
            capabilities.insert(c);
        }
    }
    if !m.capabilities.is_empty() && capabilities.is_empty() {
        return Ok(Err(invalid(
            "none of the manifest's capabilities is in the profile",
        )));
    }
    Ok(Ok(TrustProposal {
        profile: def.id.clone(),
        pairs,
        environments,
        capabilities,
        background_work: m.background_work,
    }))
}

/// ⟨rev5.2 item 21⟩ The proposal `inspect workspace` shows an owner for a manifest root:
/// exactly what [`build_trust`] computes and compares a `trust_workspace` request with
/// (the same [`manifest_proposal`] over the manifest's profile's latest snapshot). `None`
/// when the manifest names an unknown profile or asks for something that does not resolve:
/// the request then reaches [`build_trust`], which refuses it with its stable reason.
pub(super) fn manifest_proposal_view(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    m: &crate::ports::ProbedManifest,
) -> heimdall_store::Result<Option<TrustProposal>> {
    let Some(def) = tx.profile(&m.profile)? else {
        return Ok(None);
    };
    Ok(manifest_proposal(tx, own, m, &def)?.ok())
}

fn digest_ok(d: &str) -> bool {
    d.is_empty() || (d.len() == 64 && d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

#[allow(clippy::too_many_lines)]
pub(super) fn build_trust(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    action: &PolicyAction,
    o: &ProbedWorkspace,
) -> heimdall_store::Result<Result<Built, OpError>> {
    macro_rules! refuse {
        ($e:expr) => {
            return Ok(Err($e))
        };
    }
    let PolicyAction::TrustWorkspace {
        cwd,
        access_digest,
        proposal,
    } = action
    else {
        refuse!(internal("not a trust_workspace action"));
    };
    let Some(root) = o.root.clone() else {
        refuse!(usage(
            "there is no workspace root above the working directory"
        ));
    };
    let Some(root_identity) = o.root_identity.clone() else {
        refuse!(probe_error(ProbeError::IdentityUnavailable));
    };
    match &o.matched {
        Some(WorkspaceMatch::Trusted { workspace } | WorkspaceMatch::Member { workspace }) => {
            if let Some(p) = workspace_policy(tx, workspace)? {
                return Ok(Ok(Built::Existing(Box::new(p))));
            }
        }
        Some(WorkspaceMatch::Ambiguous { workspace, .. }) => {
            refuse!(
                usage("the checkout partly matches a trusted workspace; reconcile it instead")
                    .with_resource("workspace", Some(workspace.to_string()))
            );
        }
        _ => {}
    }
    let (server, digest, label, def) = match &o.manifest {
        Some(m) => {
            let Some(def) = tx.profile(&m.profile)? else {
                refuse!(
                    OpError::new(
                        Code::NotFound,
                        "the manifest names a profile this catalog does not have"
                    )
                    .with_reason(reason::MANIFEST_PROFILE_UNKNOWN)
                );
            };
            let server = match manifest_proposal(tx, own, m, &def)? {
                Ok(p) => p,
                Err(e) => refuse!(e),
            };
            // I5: the request must describe exactly what the server observes and
            // computes; otherwise nothing is written.
            if *access_digest != m.access_digest || *proposal != server {
                refuse!(changed_since_review());
            }
            (
                server,
                Some(m.access_digest.clone()),
                m.project_label.as_deref().and_then(quoted_label),
                def,
            )
        }
        None => {
            // A manifest-less root: the trust record supplies the request, validated as a
            // subset of the profile. A reviewed digest with no manifest now: it changed.
            if !access_digest.is_empty() {
                refuse!(changed_since_review());
            }
            let def = match latest_profile(tx, &proposal.profile)? {
                Ok(d) => d,
                Err(e) => refuse!(e),
            };
            if let Err(e) = within_profile(&def, &proposal.pairs, &proposal.capabilities) {
                refuse!(e);
            }
            if let Err(e) = admit_all(tx, own, &proposal.environments)? {
                refuse!(e);
            }
            (proposal.clone(), None, None, def)
        }
    };
    let action = PolicyAction::TrustWorkspace {
        cwd: cwd.clone(),
        access_digest: access_digest.clone(),
        proposal: server,
    };
    let lock_disclosure = tx.lock_disclosure_ack()?.is_none();
    Ok(Ok(Built::Record(
        Box::new(DecisionKind::TrustWorkspace {
            action,
            project_label: label,
            lock_disclosure,
        }),
        Some(DecisionBasis::Trust {
            environment: own.clone(),
            root,
            root_identity,
            git_common_identity: o.git_common_identity.clone(),
            access_digest: digest,
            profile_revision: def.revision,
        }),
    )))
}

pub(super) fn build_reconcile(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    action: &PolicyAction,
    o: &ProbedWorkspace,
) -> heimdall_store::Result<Result<Built, OpError>> {
    let PolicyAction::ReconcileWorkspace { workspace, .. } = action else {
        return Ok(Err(internal("not a reconcile_workspace action")));
    };
    let unknown =
        || OpError::new(Code::NotFound, "unknown workspace").with_resource("workspace", None);
    match tx.workspace(workspace)? {
        Some(r) if r.environment == *own && r.state == WorkspaceState::Active => {}
        _ => return Ok(Err(unknown())),
    }
    let Some(p) = workspace_policy(tx, workspace)? else {
        return Ok(Err(unknown()));
    };
    let Some(root) = o.root.clone() else {
        return Ok(Err(usage(
            "there is no workspace root above the working directory",
        )));
    };
    let Some(root_identity) = o.root_identity.clone() else {
        return Ok(Err(probe_error(ProbeError::IdentityUnavailable)));
    };
    Ok(match &o.matched {
        Some(
            WorkspaceMatch::Trusted { workspace: w } | WorkspaceMatch::Member { workspace: w },
        ) if w == workspace => Ok(Built::Existing(Box::new(p))),
        // ADR-0011 I5: the record is bound to the observation it was created from; the
        // approval re-checks it and writes the new workspace record from it.
        Some(WorkspaceMatch::Ambiguous { workspace: w, why }) if w == workspace => {
            Ok(Built::Record(
                Box::new(DecisionKind::ReconcileWorkspace {
                    action: action.clone(),
                    why: *why,
                }),
                Some(DecisionBasis::Reconcile {
                    environment: own.clone(),
                    root,
                    root_identity,
                    git_common_identity: o.git_common_identity.clone(),
                }),
            ))
        }
        _ => Err(usage(
            "the working directory is not a moved or re-cloned checkout of that workspace",
        )),
    })
}

/// The pending record a workspace request may reuse: the same kind, the same verbatim
/// action, the same basis, unexpired, at `current`.
fn pending_workspace_record(
    tx: &mut Txn<'_>,
    kind: &DecisionKind,
    basis: Option<&DecisionBasis>,
    now: Timestamp,
    current: heimdall_domain::policy::AuthorityGeneration,
) -> heimdall_store::Result<(Option<DecisionId>, Vec<DecisionId>)> {
    let action_of = |k: &DecisionKind| match k {
        DecisionKind::TrustWorkspace { action, .. }
        | DecisionKind::ReconcileWorkspace { action, .. } => Some(action.clone()),
        _ => None,
    };
    let mine = action_of(kind);
    let mut reuse = None;
    let mut superseded = Vec::new();
    for d in tx.pending_decisions()? {
        if action_of(&d.kind) != mine
            || std::mem::discriminant(&d.kind) != std::mem::discriminant(kind)
            || now >= d.expires_at
            || d.generation != current
        {
            continue;
        }
        if d.kind == *kind && tx.decision_basis(&d.id)?.as_ref() == basis {
            reuse = Some(d.id);
        } else {
            // The same action over another observation: the older record no longer
            // describes the server's state, so it is withdrawn (one pending record per
            // action).
            superseded.push(d.id);
        }
    }
    Ok((reuse, superseded))
}

impl Operations {
    /// `trust_workspace` and `reconcile_workspace` (ADR-0011 §2.1, §2.3): records are read
    /// in a transaction, the probe runs outside any transaction, and the writing
    /// transaction re-checks the records it relied on.
    async fn workspace_action(&self, req: PolicyAction) -> Result<PolicyOutcome, OpError> {
        let Some(probe) = self.workspace_probe() else {
            return Err(no_probe());
        };
        let cwd = match &req {
            PolicyAction::TrustWorkspace {
                cwd, access_digest, ..
            } => {
                if !digest_ok(access_digest) {
                    return Err(usage("the access digest is lowercase hex SHA-256"));
                }
                cwd.clone()
            }
            PolicyAction::ReconcileWorkspace { cwd, .. } => cwd.clone(),
            _ => return Err(internal("not a workspace action")),
        };
        if (WorkContext { cwd: cwd.clone() }).validate().is_err() {
            return Err(usage(
                "the working directory is an absolute path of 1 to 4096 bytes without NUL",
            ));
        }
        let own = self.environment().clone();
        let records = self.active_records().await?;
        let observed = self
            .probe_workspace(probe, own.clone(), cwd, records.clone())
            .await?
            .map_err(probe_error)?;
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        self.write(move |tx, emit| {
            let assessed = gate.check(tx)?;
            let now = match &assessed {
                Ok(s) => s.wall(),
                Err(_) => gate.clock().wall(),
            };
            // What the probe matched against must still be what is stored.
            if active_records(tx, &own)? != records {
                return Ok(Err(changed_since_review()));
            }
            let built = match &req {
                PolicyAction::TrustWorkspace { .. } => build_trust(tx, &own, &req, &observed)?,
                _ => build_reconcile(tx, &own, &req, &observed)?,
            };
            let (kind, basis) = match built {
                Err(e) => return Ok(Err(e)),
                Ok(Built::Existing(p)) => return Ok(Ok(PolicyOutcome::Applied(p, false))),
                Ok(Built::Record(kind, basis)) => (*kind, basis),
            };
            if let Err(u) = &assessed {
                return Ok(Err(uncertain(u)));
            }
            // ⟨M05⟩ U4, ruling I-5: an owner-initiated trust always creates (or shares) its
            // record and clears the requester cooldown of its key.
            if let Some(key) = trust_cooldown_key_of(&kind, basis.as_ref()) {
                tx.delete_decision_cooldown(&key)?;
            }
            let id = write_workspace_record(tx, emit, kind, basis, now, decision_id, lifetime)?;
            Ok(Ok(PolicyOutcome::Decision(id)))
        })
        .await?
    }
}

/// ⟨M05⟩ Write (or reuse) the pending `TrustWorkspace` / `ReconcileWorkspace` record for
/// `kind` with its `basis`, at safe time `now`, in the caller's transaction: an equal
/// pending record (same action, same basis, unexpired, current generation) is reused; a
/// pending record of the same action over another observation is withdrawn (one pending
/// record per action). Shared by the owner channel (`policy`) and the requester path
/// (`ensure` with `context`, `context_m05`).
pub(super) fn write_workspace_record(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    kind: DecisionKind,
    basis: Option<DecisionBasis>,
    now: Timestamp,
    decision_id: DecisionId,
    lifetime: Duration,
) -> heimdall_store::Result<DecisionId> {
    let current = tx.authority_generation()?;
    let (reuse, superseded) = pending_workspace_record(tx, &kind, basis.as_ref(), now, current)?;
    if let Some(id) = reuse {
        return Ok(id);
    }
    for id in superseded {
        let withdrawn = tx.withdraw_decision(&id)?;
        tx.delete_decision_basis(&id)?;
        emit.decision(tx, &withdrawn, None)?;
    }
    let d = DecisionRecord {
        id: decision_id,
        kind,
        generation: current,
        created_at: now,
        expires_at: plus(now, lifetime),
        state: DecisionState::Pending,
        decided_at: None,
    };
    tx.prune_decision_bases()?;
    tx.insert_decision(&d)?;
    if let Some(b) = &basis {
        tx.put_decision_basis(&d.id, b)?;
    }
    emit.decision(tx, &d, None)?;
    Ok(d.id)
}

// ---------------------------------------------------------------------------------
// ⟨M05⟩ U4: the trust cooldown (orchestrator ruling I-5)
// ---------------------------------------------------------------------------------

/// The cooldown key of a `TrustWorkspace` record built over `basis` (the workspace's
/// environment and root identity, and the server-computed proposal;
/// `heimdall_domain::workspace::trust_cooldown_key`). `None` for any other kind.
pub(super) fn trust_cooldown_key_of(
    kind: &DecisionKind,
    basis: Option<&DecisionBasis>,
) -> Option<String> {
    let (
        DecisionKind::TrustWorkspace {
            action: PolicyAction::TrustWorkspace { proposal, .. },
            ..
        },
        Some(DecisionBasis::Trust {
            environment,
            root_identity,
            ..
        }),
    ) = (kind, basis)
    else {
        return None;
    };
    Some(heimdall_domain::workspace::trust_cooldown_key(
        environment,
        root_identity,
        proposal,
    ))
}

/// The sentinel policy ID of a trust cooldown row
/// (`heimdall_domain::workspace::TRUST_COOLDOWN_POLICY`).
fn trust_cooldown_policy() -> Result<PolicyId, OpError> {
    PolicyId::parse(heimdall_domain::workspace::TRUST_COOLDOWN_POLICY)
        .map_err(|_| internal("the trust cooldown sentinel is not a policy ID"))
}

/// Ruling I-5: a **denied** `TrustWorkspace` cools its key down for the policy's default
/// window (P04: 12 h, never above the runtime's maximum `max`), from the denial. The row
/// names the sentinel policy at revision 0 and the denied record. Runs in the denial's
/// transaction, before the record's basis is deleted. A record without its basis (it
/// cannot be keyed) records nothing.
fn record_trust_cooldown(
    tx: &mut Txn<'_>,
    record: &DecisionRecord,
    max: Duration,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), OpError>> {
    let basis = tx.decision_basis(&record.id)?;
    let Some(key) = trust_cooldown_key_of(&record.kind, basis.as_ref()) else {
        return Ok(Ok(()));
    };
    let Some(DecisionBasis::Trust { environment, .. }) = basis else {
        return Ok(Ok(()));
    };
    let policy = match trust_cooldown_policy() {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    tx.put_decision_cooldown(&DecisionCooldown {
        key,
        policy,
        revision: PolicyRevision(0),
        environment,
        decision: record.id.clone(),
        until: plus(now, DEFAULT_MAX_WINDOW.min(max)),
    })?;
    Ok(Ok(()))
}

/// Ruling I-5, the requester side: the live cooldown of a requester-raised trust of
/// `key` at `now` (the denied record and when it ends); an elapsed row is deleted.
pub(super) fn trust_cooldown(
    tx: &mut Txn<'_>,
    key: &str,
    now: Timestamp,
) -> heimdall_store::Result<Option<(DecisionId, Timestamp)>> {
    let Some(c) = tx.decision_cooldown(key)? else {
        return Ok(None);
    };
    if now < c.until {
        return Ok(Some((c.decision, c.until)));
    }
    tx.delete_decision_cooldown(key)?;
    Ok(None)
}

// ---------------------------------------------------------------------------------
// Decide: preparation, pre-completion checks, application
// ---------------------------------------------------------------------------------

/// What `decide` prepares for an M05 record before its transaction (I/O never inside it):
/// the approval-time observation, fresh IDs, and the bounds.
pub(super) struct DecideM05 {
    observed: Option<Result<ProbedWorkspace, ProbeError>>,
    /// Fresh IDs for what an approval may create; `None` for an M01–M03 record.
    ids: Option<(PolicyId, WorkspaceId)>,
    max: Duration,
    own: EnvironmentId,
    adapters: Vec<AdapterInfo>,
}

impl Operations {
    /// ⟨M05⟩ Before `decide`'s transaction: for a `TrustWorkspace` or `ReconcileWorkspace`
    /// record, refuse without a probe (either verdict, nothing consumed), and for an
    /// approval re-probe the recorded working directory now.
    pub(super) async fn decide_m05_prepare(
        &self,
        decision: &DecisionId,
        verdict: Verdict,
    ) -> Result<DecideM05, OpError> {
        let mut out = DecideM05 {
            observed: None,
            ids: None,
            max: self.inner.config.default_window,
            own: self.environment().clone(),
            adapters: self.adapter_infos(),
        };
        let id = decision.clone();
        let record = self.write(move |tx, _| tx.decision(&id)).await?;
        if record.as_ref().is_some_and(|d| d.kind.is_m05()) {
            out.ids = Some((
                new_policy_id()?,
                WorkspaceId::from_random_bytes(random16()?),
            ));
        }
        let cwd = match record.map(|d| d.kind) {
            Some(
                DecisionKind::TrustWorkspace {
                    action: PolicyAction::TrustWorkspace { cwd, .. },
                    ..
                }
                | DecisionKind::ReconcileWorkspace {
                    action: PolicyAction::ReconcileWorkspace { cwd, .. },
                    ..
                },
            ) => cwd,
            Some(DecisionKind::TrustWorkspace { .. } | DecisionKind::ReconcileWorkspace { .. }) => {
                return Err(stale("the decision's action is malformed")
                    .with_resource("decision", Some(decision.to_string())));
            }
            _ => return Ok(out),
        };
        let Some(probe) = self.workspace_probe() else {
            return Err(no_probe().with_resource("decision", Some(decision.to_string())));
        };
        if verdict == Verdict::Approve {
            let records = self.active_records().await?;
            out.observed = Some(
                self.probe_workspace(probe, out.own.clone(), cwd, records)
                    .await?,
            );
        }
        Ok(out)
    }
}

/// The approval-time observation, required to have a root and its identity.
fn observed_now(m05: &DecideM05) -> Result<&ProbedWorkspace, OpError> {
    match &m05.observed {
        Some(Ok(o)) if o.root.is_some() && o.root_identity.is_some() => Ok(o),
        _ => Err(stale(
            "the workspace can no longer be observed as it was; review it again",
        )),
    }
}

/// ⟨M05⟩ Inside `decide`'s transaction, **before** the record is completed: whether the
/// record may be applied now. A refusal writes nothing and leaves the record pending (not
/// consumed). Denials need no check.
pub(super) fn precheck(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    verdict: Verdict,
    m05: &DecideM05,
) -> heimdall_store::Result<Result<(), OpError>> {
    if let DecisionKind::WidenPolicy { action } = &d.kind {
        // ⟨M05 U3⟩ A targeted block action's record is `stop_m05`'s.
        if super::stop_m05::serves_widening(action) {
            return super::stop_m05::precheck(tx, d, verdict);
        }
        if !serves_widening(action) {
            return Ok(Err(OpError::driver_unavailable(
                "this decision kind is not available in this build",
            )));
        }
    }
    if verdict == Verdict::Deny {
        return Ok(Ok(()));
    }
    Ok(match &d.kind {
        DecisionKind::WidenPolicy { action } => check_widening(tx, d, action, m05)?,
        DecisionKind::TrustWorkspace { action, .. } => check_trust(tx, d, action, m05)?,
        DecisionKind::ReconcileWorkspace { action, why } => {
            check_reconcile(tx, d, action, *why, m05)?
        }
        _ => Err(internal("not an M05 decision")),
    })
}

fn check_widening(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    action: &PolicyAction,
    m05: &DecideM05,
) -> heimdall_store::Result<Result<(), OpError>> {
    Ok(match action {
        PolicyAction::Create {
            profile,
            environments,
            max_window,
            default,
        } => {
            let Some(DecisionBasis::Create { profile_revision }) = tx.decision_basis(&d.id)? else {
                return Ok(Err(stale(
                    "the decision's basis is unknown; request it again",
                )));
            };
            if tx.profile_snapshot(profile, profile_revision)?.is_none() {
                return Ok(Err(stale(
                    "the profile revision is unknown; request it again",
                )));
            }
            if admit_create(tx, &m05.own, environments, *default)?.is_err() {
                return Ok(Err(stale(
                    "an environment of the policy is no longer managed, or this controller's role on the runner no longer lets it issue",
                )));
            }
            if personal_exists(tx, profile, environments)? {
                return Ok(Err(stale(
                    "a personal policy for this profile already applies in that environment",
                )));
            }
            create_window(max_window.as_ref(), m05.max)
                .map(|_| ())
                .map_err(|_| stale("the window is no longer allowed"))
        }
        PolicyAction::ExtendScope {
            policy_id,
            pairs,
            capabilities,
            environments,
            ..
        } => {
            let Some(p) = tx.policy(policy_id)? else {
                return Ok(Err(stale("the policy no longer exists")));
            };
            let Some(def) = tx.profile(&p.profile)? else {
                return Ok(Err(stale("the policy's profile no longer exists")));
            };
            if within_profile(&def, pairs, capabilities).is_err() {
                return Ok(Err(stale("the profile no longer holds the added scope")));
            }
            if admit_all(tx, &m05.own, environments)?.is_err() {
                return Ok(Err(stale("an added environment is no longer managed")));
            }
            if !environments.is_subset(&p.environments) && names_unmanaged(tx, &m05.own, &p)? {
                return Ok(Err(stale(
                    "a policy that names a runner environment names that environment only",
                )));
            }
            Ok(())
        }
        PolicyAction::SetMaxWindow {
            policy_id,
            max_window,
        } => {
            if tx.policy(policy_id)?.is_none() {
                return Ok(Err(stale("the policy no longer exists")));
            }
            parse_max_window(max_window, m05.max)
                .map(|_| ())
                .map_err(|_| stale("the window is no longer allowed"))
        }
        _ => Err(OpError::driver_unavailable(
            "this decision kind is not available in this build",
        )),
    })
}

fn check_trust(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    action: &PolicyAction,
    m05: &DecideM05,
) -> heimdall_store::Result<Result<(), OpError>> {
    let PolicyAction::TrustWorkspace { proposal, .. } = action else {
        return Ok(Err(stale("the decision's action is malformed")));
    };
    let Some(DecisionBasis::Trust {
        environment,
        root,
        root_identity,
        git_common_identity,
        access_digest,
        profile_revision,
    }) = tx.decision_basis(&d.id)?
    else {
        return Ok(Err(stale(
            "the decision's observation is unknown; review it again",
        )));
    };
    let o = match observed_now(m05) {
        Ok(o) => o,
        Err(e) => return Ok(Err(e)),
    };
    // The approval-time re-probe must still equal what the record was created from: the
    // root, its identity, the Git common directory's identity (present or absent alike;
    // review M05-W1-R01: a replaced or reinitialized `.git` would otherwise hand its own
    // linked worktrees membership the owner never reviewed, ADR-0011 §2.3), and the
    // access digest (ADR-0011 I5).
    let same_common = match (&git_common_identity, &o.git_common_identity) {
        (None, None) => true,
        (Some(a), Some(b)) => a.same_file(b),
        _ => false,
    };
    let same = o.root.as_deref() == Some(root.as_str())
        && o.root_identity
            .as_ref()
            .is_some_and(|i| i.same_file(&root_identity))
        && same_common
        && o.manifest.as_ref().map(|m| &m.access_digest) == access_digest.as_ref()
        && environment == m05.own;
    if !same {
        return Ok(Err(stale(
            "the workspace changed since the decision; review it again",
        )));
    }
    if tx
        .profile_snapshot(&proposal.profile, profile_revision)?
        .is_none()
    {
        return Ok(Err(stale(
            "the profile revision is unknown; review it again",
        )));
    }
    if admit_all(tx, &m05.own, &proposal.environments)?.is_err() {
        return Ok(Err(stale(
            "an environment of the proposal is no longer managed",
        )));
    }
    Ok(Ok(()))
}

fn check_reconcile(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    action: &PolicyAction,
    why: heimdall_domain::workspace::AmbiguityReason,
    m05: &DecideM05,
) -> heimdall_store::Result<Result<(), OpError>> {
    let PolicyAction::ReconcileWorkspace { workspace, .. } = action else {
        return Ok(Err(stale("the decision's action is malformed")));
    };
    let Some(basis) = tx.decision_basis(&d.id)? else {
        return Ok(Err(stale(
            "the decision's observation is unknown; review it again",
        )));
    };
    let o = match observed_now(m05) {
        Ok(o) => o,
        Err(e) => return Ok(Err(e)),
    };
    // The approval-time re-probe must still be exactly the checkout the record was created
    // from (ADR-0011 I5): its root, its identity and its Git common directory, still
    // ambiguous against the same record for the same reason.
    let still = matches!(
        &o.matched,
        Some(WorkspaceMatch::Ambiguous { workspace: w, why: y }) if w == workspace && *y == why
    ) && same_reconcile_observation(&basis, o, &m05.own);
    if !still {
        return Ok(Err(stale(
            "the checkout no longer matches the workspace as it did; review it again",
        )));
    }
    if !tx
        .workspace(workspace)?
        .is_some_and(|r| r.state == WorkspaceState::Active)
        || workspace_policy(tx, workspace)?.is_none()
    {
        return Ok(Err(stale("the workspace or its policy no longer exists")));
    }
    Ok(Ok(()))
}

/// Whether `o` is still exactly the observation a reconcile record was created from:
/// the same environment, root, root identity and Git common-directory identity.
fn same_reconcile_observation(
    basis: &DecisionBasis,
    o: &ProbedWorkspace,
    own: &EnvironmentId,
) -> bool {
    let DecisionBasis::Reconcile {
        environment,
        root,
        root_identity,
        git_common_identity,
    } = basis
    else {
        return false;
    };
    let same_common = match (git_common_identity, &o.git_common_identity) {
        (None, None) => true,
        (Some(a), Some(b)) => a.same_file(b),
        _ => false,
    };
    environment == own
        && o.root.as_deref() == Some(root.as_str())
        && o.root_identity
            .as_ref()
            .is_some_and(|i| i.same_file(root_identity))
        && same_common
}

/// ⟨M05⟩ Inside `decide`'s transaction, **after** the record was completed: apply exactly
/// what it records (approval), or record a denial's cooldown. Returns the operations a
/// widening now covers (ADR-0006 §13.7 item 2), which `decide` drives like its own
/// waiters. A refusal here rolls the whole transaction back (nothing consumed).
pub(super) fn apply(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &DecisionRecord,
    verdict: Verdict,
    m05: &DecideM05,
    now: Timestamp,
) -> heimdall_store::Result<Result<Vec<OperationId>, OpError>> {
    // ⟨M05 U3⟩ A targeted block action's record is `stop_m05`'s.
    if let DecisionKind::WidenPolicy { action } = &record.kind
        && super::stop_m05::serves_widening(action)
    {
        return super::stop_m05::apply(tx, emit, record, action, verdict, now);
    }
    let cause = PolicyChangeCause::Decision {
        decision: record.id.clone(),
    };
    let Some(ids) = &m05.ids else {
        return Ok(Err(internal("the decision was not prepared")));
    };
    let applied = match (&record.kind, verdict) {
        (DecisionKind::WidenPolicy { action }, Verdict::Approve) => {
            apply_widening(tx, emit, record, action, m05, &ids.0, cause, now)?
        }
        (DecisionKind::WidenPolicy { action }, Verdict::Deny) => {
            if matches!(action, PolicyAction::ExtendScope { .. }) {
                super::review_m05::record_cooldowns(tx, record, action, now)?;
            }
            Ok(false)
        }
        (
            DecisionKind::TrustWorkspace {
                action,
                lock_disclosure,
                ..
            },
            Verdict::Approve,
        ) => apply_trust(
            tx,
            emit,
            record,
            action,
            *lock_disclosure,
            m05,
            ids,
            cause,
            now,
        )?,
        (DecisionKind::ReconcileWorkspace { action, .. }, Verdict::Approve) => {
            apply_reconcile(tx, emit, record, action, m05, &ids.1, cause, now)?
        }
        // ⟨M05⟩ U4, ruling I-5: a denied trust cools its key down (requester-raised trusts
        // of the same workspace identity and proposal get `decision_cooldown`, no record).
        (DecisionKind::TrustWorkspace { .. }, _) => {
            record_trust_cooldown(tx, record, m05.max, now)?.map(|()| false)
        }
        // No cooldown is specified for a denied reconcile decision: nothing is recorded.
        (DecisionKind::ReconcileWorkspace { .. }, _) => Ok(false),
        _ => Err(internal("not an M05 decision")),
    };
    tx.delete_decision_basis(&record.id)?;
    match applied {
        Err(e) => Ok(Err(e)),
        Ok(false) => Ok(Ok(Vec::new())),
        Ok(true) => Ok(Ok(covered_waiters(tx, emit, &m05.own, &m05.adapters, now)?)),
    }
}

/// `WidenPolicy{create | extend_scope | set_max_window}` approval: exactly the action.
#[allow(clippy::too_many_arguments)]
fn apply_widening(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &DecisionRecord,
    action: &PolicyAction,
    m05: &DecideM05,
    new_policy: &PolicyId,
    cause: PolicyChangeCause,
    now: Timestamp,
) -> heimdall_store::Result<Result<bool, OpError>> {
    match action {
        PolicyAction::Create {
            profile,
            environments,
            max_window,
            default,
        } => {
            let Some(DecisionBasis::Create { profile_revision }) = tx.decision_basis(&record.id)?
            else {
                return Ok(Err(stale("the decision's basis is unknown")));
            };
            let Some(snapshot) = tx.profile_snapshot(profile, profile_revision)? else {
                return Ok(Err(stale("the profile revision is unknown")));
            };
            let Ok(window) = create_window(max_window.as_ref(), m05.max) else {
                return Ok(Err(stale("the window is no longer allowed")));
            };
            // ⟨M06 W5; record source (b)⟩ Judged again in the transaction that writes.
            let target = match admit_create(tx, &m05.own, environments, *default)? {
                Ok(t) => t,
                Err(_) => {
                    return Ok(Err(stale(
                        "an environment of the policy is no longer managed, or this controller's role on the runner no longer lets it issue",
                    )));
                }
            };
            let p = StandingPolicy {
                id: new_policy.clone(),
                revision: PolicyRevision(1),
                profile: profile.clone(),
                workspace: None,
                scope: snapshot.scope,
                environments: environments.clone(),
                max_window: window,
                pause: PauseState::Active,
                cutoff_at: None,
                source: PolicySource::OwnerDecision { decided_at: now },
                lock_behavior: LockBehavior::default(),
                connection: Default::default(),
                default: *default,
            };
            tx.upsert_policy(&p, false)?;
            emit.policy(tx, &p)?;
            record_change(tx, &p, cause, now)?;
            // ⟨M06 W5; record source (b)⟩ A runner's policy activates nothing here: no
            // environment record, no automatic activation, no default (refused above), no
            // waiter proceeds. It is read only by
            // `remote_status_driver::adopt_under_standing_policy`.
            if target == CreateTarget::Runner {
                return Ok(Ok(false));
            }
            move_default(tx, emit, &p, &record.id, now)?;
            for e in environments {
                allow_automatic_activation(tx, e)?;
            }
            // ⟨M05⟩ Ruling I-2 (U5): an empty default-profile preference takes this
            // profile; an existing one is kept; no binding is touched.
            if *default {
                super::default_activation_m05::default_profile_on_create(
                    tx,
                    profile,
                    environments,
                )?;
            }
        }
        PolicyAction::ExtendScope {
            policy_id,
            pairs,
            capabilities,
            environments,
            background_work,
        } => {
            let Some(mut p) = tx.policy(policy_id)? else {
                return Ok(Err(stale("the policy no longer exists")));
            };
            let added: BTreeSet<EnvironmentId> =
                environments.difference(&p.environments).cloned().collect();
            p.scope.pairs.extend(pairs.iter().cloned());
            p.scope.capabilities.extend(capabilities.iter().copied());
            p.environments.extend(environments.iter().cloned());
            match background_work {
                Some(true) => p.lock_behavior = LockBehavior::Continue,
                Some(false) => p.lock_behavior = LockBehavior::RevokeOnLock,
                None => {}
            }
            write_revision(tx, emit, &mut p, cause, false, now)?;
            move_default(tx, emit, &p, &record.id, now)?;
            for e in &added {
                allow_automatic_activation(tx, e)?;
            }
        }
        PolicyAction::SetMaxWindow {
            policy_id,
            max_window,
        } => {
            let Some(mut p) = tx.policy(policy_id)? else {
                return Ok(Err(stale("the policy no longer exists")));
            };
            let Ok(w) = parse_max_window(max_window, m05.max) else {
                return Ok(Err(stale("the window is no longer allowed")));
            };
            p.max_window = w;
            write_revision(tx, emit, &mut p, cause, false, now)?;
        }
        _ => {
            return Ok(Err(OpError::driver_unavailable(
                "this policy action is not available in this build",
            )));
        }
    }
    Ok(Ok(true))
}

/// The lock behaviour of a new workspace policy (ADR-0011 §10 item 2, as the brief rules
/// it): `continue` only when the reviewed proposal asked for background work; otherwise the
/// strictest lock behaviour of the personal policies for the profile in its environments,
/// the default when there are none — never wider than what the owner already approved.
fn workspace_lock_behavior(
    tx: &mut Txn<'_>,
    proposal: &TrustProposal,
    environments: &BTreeSet<EnvironmentId>,
) -> heimdall_store::Result<LockBehavior> {
    if proposal.background_work {
        return Ok(LockBehavior::Continue);
    }
    let mut strictest: Option<LockBehavior> = None;
    for e in environments {
        for p in tx.policies_for(&proposal.profile, e)? {
            if p.workspace.is_none() {
                strictest = Some(strictest.map_or(p.lock_behavior, |s| {
                    strictest_lock_behavior(s, p.lock_behavior)
                }));
            }
        }
    }
    Ok(strictest.unwrap_or_default())
}

/// `TrustWorkspace` approval, in `decide`'s transaction: the workspace record, its policy,
/// the environment's `automatic_activation`, the lock-disclosure acknowledgement when the
/// record says it was pending, and the history row (the generation moves with the
/// workspace insert and the policy write).
#[allow(clippy::too_many_arguments)]
fn apply_trust(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &DecisionRecord,
    action: &PolicyAction,
    lock_disclosure: bool,
    m05: &DecideM05,
    ids: &(PolicyId, WorkspaceId),
    cause: PolicyChangeCause,
    now: Timestamp,
) -> heimdall_store::Result<Result<bool, OpError>> {
    let PolicyAction::TrustWorkspace { proposal, .. } = action else {
        return Ok(Err(stale("the decision's action is malformed")));
    };
    let Some(DecisionBasis::Trust {
        environment,
        root,
        root_identity,
        git_common_identity,
        profile_revision,
        ..
    }) = tx.decision_basis(&record.id)?
    else {
        return Ok(Err(stale("the decision's observation is unknown")));
    };
    let Some(snapshot) = tx.profile_snapshot(&proposal.profile, profile_revision)? else {
        return Ok(Err(stale("the profile revision is unknown")));
    };
    // Review M05-W1-R01: the record carries exactly the Git common-directory identity the
    // decision was created from (and that `check_trust` found unchanged), never a later
    // observation.
    let ws = WorkspaceRecord {
        id: ids.1.clone(),
        environment: environment.clone(),
        root,
        root_identity,
        git_common_identity,
        decision: record.id.clone(),
        created_at: now,
        state: WorkspaceState::Active,
    };
    tx.insert_workspace(&ws)?;
    let pairs = if proposal.pairs.is_empty() {
        snapshot.scope.pairs.clone()
    } else {
        proposal
            .pairs
            .intersection(&snapshot.scope.pairs)
            .cloned()
            .collect()
    };
    let capabilities = if proposal.capabilities.is_empty() {
        snapshot.scope.capabilities.clone()
    } else {
        proposal
            .capabilities
            .intersection(&snapshot.scope.capabilities)
            .copied()
            .collect()
    };
    let environments = if proposal.environments.is_empty() {
        [environment].into_iter().collect()
    } else {
        proposal.environments.clone()
    };
    let lock_behavior = workspace_lock_behavior(tx, proposal, &environments)?;
    let p = StandingPolicy {
        id: ids.0.clone(),
        revision: PolicyRevision(1),
        profile: proposal.profile.clone(),
        workspace: Some(ws.id.clone()),
        scope: Scope {
            pairs,
            capabilities,
        },
        environments: environments.clone(),
        max_window: DEFAULT_MAX_WINDOW.min(m05.max),
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::OwnerDecision { decided_at: now },
        lock_behavior,
        connection: Default::default(),
        default: false,
    };
    tx.upsert_policy(&p, false)?;
    emit.policy(tx, &p)?;
    record_change(tx, &p, cause, now)?;
    for e in &environments {
        allow_automatic_activation(tx, e)?;
    }
    if lock_disclosure {
        tx.set_lock_disclosure_ack(now)?;
    }
    Ok(Ok(true))
}

/// `ReconcileWorkspace` approval: the old record goes `stale`, a **new** record (new ID) is
/// written for the approval-time observation, and the workspace's policy moves to it (its
/// revision and history row). Grants of the old record are never revived: they keep their
/// recorded context, which no policy names any more.
#[allow(clippy::too_many_arguments)]
fn apply_reconcile(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &DecisionRecord,
    action: &PolicyAction,
    m05: &DecideM05,
    new_workspace: &WorkspaceId,
    cause: PolicyChangeCause,
    now: Timestamp,
) -> heimdall_store::Result<Result<bool, OpError>> {
    let PolicyAction::ReconcileWorkspace { workspace, .. } = action else {
        return Ok(Err(stale("the decision's action is malformed")));
    };
    // The new record is written from the observation the decision was created from (and
    // that `check_reconcile` found unchanged), never from a later one.
    let basis = tx.decision_basis(&record.id)?;
    let Some(o) = observed_now(m05).ok() else {
        return Ok(Err(stale("the workspace can no longer be observed")));
    };
    let Some(DecisionBasis::Reconcile {
        root,
        root_identity,
        git_common_identity,
        ..
    }) = basis.filter(|b| same_reconcile_observation(b, o, &m05.own))
    else {
        return Ok(Err(stale(
            "the checkout changed since the decision; review it again",
        )));
    };
    let Some(old) = tx.workspace(workspace)? else {
        return Ok(Err(stale("the workspace no longer exists")));
    };
    tx.set_workspace_state(workspace, WorkspaceState::Active, WorkspaceState::Stale)?;
    let new = WorkspaceRecord {
        id: new_workspace.clone(),
        environment: old.environment,
        root,
        root_identity,
        git_common_identity,
        decision: record.id.clone(),
        created_at: now,
        state: WorkspaceState::Active,
    };
    tx.insert_workspace(&new)?;
    for mut p in tx.policies()? {
        if p.workspace.as_ref() == Some(workspace) {
            p.workspace = Some(new.id.clone());
            write_revision(tx, emit, &mut p, cause.clone(), false, now)?;
        }
    }
    Ok(Ok(false))
}

/// ⟨M05⟩ After a widening was applied in this transaction (ADR-0006 §13.7 item 2 through
/// its existing machinery): every request `awaiting_approval` whose waiting grant the
/// current policy, in the request's own context, now covers entirely proceeds with no
/// further decision (`proceed_covered`: its pending `ApproveAuthority` records are
/// withdrawn, not consumed). A paused, expired or still uncovered request keeps waiting.
fn covered_waiters(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    own: &EnvironmentId,
    adapters: &[AdapterInfo],
    now: Timestamp,
) -> heimdall_store::Result<Vec<OperationId>> {
    let mut resumed = Vec::new();
    for listed in tx.open_operations()? {
        let Some(op) = tx.operation(&listed.id)? else {
            continue;
        };
        if op.state != OperationState::AwaitingApproval
            || !matches!(op.kind, OperationKind::Ensure | OperationKind::Delegate)
        {
            continue;
        }
        let Some(resolved) = tx.recovery_intent(&op.id)?.and_then(|i| i.resolved) else {
            continue;
        };
        let Some(g) = resolved
            .grant
            .as_ref()
            .map(|g| tx.grant(g))
            .transpose()?
            .flatten()
        else {
            continue;
        };
        if !waiting(&g)
            || g.state != GrantState::AwaitingApproval
            || dtime::is_expired(now, resolved.deadline.effective)
        {
            continue;
        }
        let context = PolicyContext::of_recorded(resolved.workspace.as_ref());
        let policies = tx.policies_for(&resolved.profile, &op.environment)?;
        if merged_policy(&policies, &context)
            .is_some_and(|p| matches!(p.pause, PauseState::Paused { .. }))
        {
            continue;
        }
        let Some(needed) = current_delta(tx, own, adapters, &g, now)? else {
            continue;
        };
        if !delta_is_empty(&needed) {
            continue;
        }
        let owner = decision_owner(Some(&g), &op.id);
        let current = tx.authority_generation()?;
        resumed.extend(proceed_covered(
            tx,
            emit,
            own,
            &g,
            &owner,
            &resolved.profile,
            current,
            now,
        )?);
    }
    Ok(resumed)
}

// ---------------------------------------------------------------------------------
// Pins: the grant origin's policy, the binding's context (ADR-0011 §5.1)
// ---------------------------------------------------------------------------------

/// ⟨M05⟩ A standing-policy grant's origin records the policy its authority rests on: the
/// first applicable policy of its recorded context (`applicable_policies`). Every other
/// origin (an explicit one-off approval, a delegation) keeps `policy_id` absent.
pub(super) fn with_policy_id(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    mut origin: GrantOrigin,
) -> heimdall_store::Result<GrantOrigin> {
    let context = crate::policy_context::grant_context(Some(&origin));
    origin.policy_id =
        crate::policy_context::policies_in(tx, &origin.profile, environment, &context)?
            .first()
            .map(|p| p.id.clone());
    Ok(origin)
}

/// ⟨M05⟩ A new binding pins its context once (`bindings.context_json`): its grant
/// origin's workspace, else personal.
pub(super) fn pin_binding_context(
    tx: &mut Txn<'_>,
    binding: &BindingId,
    grant: &GrantId,
) -> heimdall_store::Result<()> {
    let context = match tx.grant_origin(grant)?.and_then(|o| o.workspace) {
        Some(workspace) => BindingContext::Workspace { workspace },
        None => BindingContext::Personal,
    };
    tx.set_binding_context(binding, &context)
}

// ---------------------------------------------------------------------------------
// inspect policies
// ---------------------------------------------------------------------------------

/// ⟨M05⟩ `inspect policies` (ADR-0011 §4.4): every standing policy with its personal
/// `default` flag, pause, cutoff and applied revisions (cause, decision, time).
pub(super) fn policies_view(
    tx: &mut Txn<'_>,
    own: &heimdall_contract::ids::EnvironmentId,
) -> heimdall_store::Result<PoliciesView> {
    let mut items = Vec::new();
    for p in tx.policies()? {
        let history = tx
            .policy_history(&p.id)?
            .into_iter()
            .map(|h| {
                let (cause, decision_id) = match h.cause {
                    PolicyChangeCause::Decision { decision } => ("decision", Some(decision)),
                    _ => ("narrowing", None),
                };
                PolicyRevisionView {
                    revision: h.revision.0,
                    cause: cause.to_owned(),
                    decision_id,
                    at: h.at,
                }
            })
            .collect();
        items.push(PolicyView {
            policy_id: p.id.clone(),
            revision: p.revision.0,
            profile: p.profile.clone(),
            workspace_id: p.workspace.clone(),
            environments: p.environments.iter().cloned().collect(),
            default: p.default,
            paused_since: match p.pause {
                PauseState::Paused { since } => Some(since),
                PauseState::Active => None,
            },
            cutoff_at: p.cutoff_at,
            history,
        });
    }
    // ⟨M05⟩ Revision 5.1 (§17.9): the default-profile preferences of the managed set.
    let mut default_profiles = Vec::new();
    for environment in crate::environments::members(tx, own)? {
        if let Some(profile) = tx.default_profile(&environment)? {
            default_profiles.push(DefaultProfileView {
                environment_id: environment,
                profile_id: profile,
            });
        }
    }
    Ok(PoliciesView {
        items,
        default_profiles,
    })
}
