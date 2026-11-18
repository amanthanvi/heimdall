//! ⟨M05⟩ U4: context activation, `ensure` by working directory (ADR-0011 §2.2–§2.3,
//! §3.1–§3.4, §4, §5.3; §10 items 1–3, 7; ADR-0006 revision 5 §17.3–§17.4, §17.6 R5-Q1,
//! R5-Q8, R5-Q9; orchestrator rulings I-4, I-5).
//!
//! **Invariants kept on every path.** A manifest only ever makes a **request** (I2): its
//! values resolve against the local catalog and the profile's latest snapshot, and the
//! resulting scope is what is asked, never what is granted. Identity comes from the
//! runtime's own observation matched against the owner-recorded workspace records (I3,
//! `ports::WorkspaceProbe`). A decision's action is fixed at creation from server-side
//! state (I5: the trust proposal is computed here, never taken from the request). A
//! `covered_only` request **never creates a decision record** (§3.2, ruling 3), whatever
//! the match, the cooldowns or a race with a narrowing. Activation always uses the
//! policy's recorded lock behaviour (ruling 2): the manifest's `background_work` only
//! decides coverage and what a decision would add.
//!
//! **Resolution, once, at admission.** [`Operations::ensure_in_context`] reads the active
//! workspace records (a transaction), probes the working directory (outside any
//! transaction: file I/O), then plans in one transaction that first re-checks the records
//! it matched against (a change re-probes, at most [`MAX_PLAN_ATTEMPTS`] times). The plan
//! either refuses (nothing admitted; a workspace decision may have been written), or fixes
//! a [`Resolution`] — the context, the resolved profile and revision, the pairs, the
//! capability restriction, the access digest and the route — which is stored **with the
//! operation**, inside its recovery intent's request object under [`RESOLUTION_KEY`]
//! (one atomic admission; no schema change; the public request form is unchanged). The
//! pipeline and restart recovery overlay exactly that resolution ([`overlay`]); an
//! admitted operation is never re-probed.
//!
//! **The match** (ADR-0011 §2.3 through `heimdall_project::match_workspace`):
//!
//! | Match | Context | Request | Not covered, foreground | `covered_only` |
//! |---|---|---|---|---|
//! | no root | personal | the request's profile, else the environment's default profile (`USAGE_ERROR` with neither) | the M01 pipeline (a one-off `ApproveAuthority`) | requested ∩ personal coverage |
//! | `Trusted` / `Member` | the workspace's policy (`PolicyContext::Workspace`) | the manifest's request ∩ the latest profile snapshot, or the policy's own scope without a manifest | one coalesced `WidenPolicy{extend_scope}` with only the added authority; the request **waits** and resumes through `covered_waiters` when an approval covers it ([`Route::Extension`]) | requested ∩ workspace coverage |
//! | `Untrusted` | personal | as for `Trusted` (the manifest, or the request/default profile at a manifest-less root) | covered entirely by personal policy (lock behaviour included, Q10) → activates; otherwise one server-built `TrustWorkspace` (`workspace_untrusted`), subject to the trust cooldown | requested ∩ personal coverage |
//! | `Ambiguous` | personal (R5-Q8) | as for `Untrusted` | covered entirely by personal policy → activates; otherwise one `ReconcileWorkspace` (`workspace_ambiguous`) bound to its observation | requested ∩ personal coverage |
//!
//! A request that names something **outside** its manifest (an explicit `until`, a
//! `scope` beyond the manifest's request, or an environment the manifest does not list)
//! stays the M01 pipeline in its context: anything uncovered is a one-off
//! `ApproveAuthority`, unchanged (ADR-0011 §4.1).
//!
//! **How a request continues after a trust or reconcile decision** (ADR-0011 §3.4: first
//! trust = 1 decision, everything after = 0). Those two decisions are raised **before
//! admission**: no operation exists for the refused request, so its request ID is not
//! bound to the pre-trust resolution (its hash would carry no workspace; the trusted
//! re-entry's carries one, so reusing the ID across an admitted pre-trust operation would
//! be `REQUEST_CONFLICT`). The caller re-issues the same request after the owner decided;
//! the re-entry then resolves `Trusted` (or, after a reconcile, `Trusted` at the new root)
//! under the workspace policy the approval wrote, which covers the reviewed request
//! exactly, so it activates with **no further decision**; every later re-entry, shell and
//! fresh work ID likewise. A manifest delta of a trusted workspace, by contrast, **is**
//! admitted and waits (option B's resume), because its context and digest do not change
//! when the owner approves. A delta that is only the lock behaviour (`background_work`
//! asked, `revoke_on_lock` recorded) cannot be expressed as a waiting grant (re-validation
//! does not judge lock behaviour), so it is raised before admission like a trust.
//!
//! **Ruling I-4 (`manifest_basis`).** Not added. Every ADR-0011 §3.4 row it would serve
//! already holds without it: coverage is computed from the manifest's request against
//! the policy's current scope, so an edit or branch switch with the same access digest
//! asks for exactly what is covered (0 decisions), and going back to an approved digest
//! asks for a subset of the policy, which only ever widens through approved extensions
//! (0 decisions). A recorded digest would only matter to treat "a digest other than the
//! approved one" as a change in itself, which §3.4 does not ask for (a narrower manifest
//! never narrows a policy, §4.2).
//!
//! **Mechanism groups** (ADR-0011 §5.3, Q7): a `mixed_mechanisms` refusal carries
//! `next.groups` ([`with_mechanism_groups`]); each group re-requested under the same work
//! ID activates as its own binding, and the M01 `work_deadline` caps every later group at
//! the earliest group's deadline.

use std::collections::BTreeSet;
use std::time::Duration;

use heimdall_contract::envelope::{MechanismGroup, NextAction, reason};
use heimdall_contract::ids::{
    DecisionId, EnvironmentId, GrantId, OperationId, ProfileId, WorkspaceId,
};
use heimdall_contract::request::{
    AccessPairRef, Capability, EnsureData, EnsureRequest, PolicyAction, RequiredCapabilities,
};
use heimdall_contract::trust::{
    ContextKind, ContextProvenance, ContextReport, TrustProposal, WorkContext, WorkspaceMatchView,
    WorkspaceView,
};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::authority::{AuthorityDelta, Denial};
use heimdall_domain::idempotency::{HashInput, compute_hash};
use heimdall_domain::operation::OperationKind;
use heimdall_domain::policy::{
    PolicyContext, ScopeDelta, StandingPolicy, coverage, resolve_policy,
};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Scope};
use heimdall_domain::workspace::WorkspaceMatch;
use heimdall_store::Txn;
use serde::{Deserialize, Serialize};

use super::pair_mechanism_m03::{self, ContextHashExtras};
use super::review_m05::{Extension, raise_extension};
use super::trust_m05::{
    self, Built, active_records, changed_since_review, no_probe, probe_error, usage,
    workspace_policy,
};
use super::{AdapterInfo, Emit, Operations, approval_needed, internal, select_adapter};
use crate::context::Caller;
use crate::error::{OpError, OpResult};
use crate::ports::{ProbedManifest, ProbedWorkspace};
use crate::timegate::{TxnGate, uncertain};

/// The key under which an admitted `ensure` with `context` stores its [`Resolution`] in
/// its recovery intent's request object (beside the request's own fields, which stay as
/// submitted; `Request` decoding ignores the key).
pub(super) const RESOLUTION_KEY: &str = "m05_resolution";

/// How often the plan re-probes when the workspace records changed between the probe
/// and its transaction (a concurrent trust or reconcile).
const MAX_PLAN_ATTEMPTS: usize = 3;

/// What an admitted context request does when its resolution needs added authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Route {
    /// The M01 pipeline: anything uncovered is a one-off `ApproveAuthority`.
    #[default]
    Standing,
    /// A trusted workspace's manifest request: the added authority is one coalesced
    /// `WidenPolicy{extend_scope}` on the workspace policy (ADR-0011 §4.1 option B); the
    /// request waits for it.
    Extension,
    /// A background request: never a decision record; added authority is `not_covered`.
    CoveredOnly,
}

/// The resolution of an `ensure` with `context`, fixed at admission (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Resolution {
    /// The workspace whose policy governs (`Trusted` / `Member`); absent: personal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) workspace: Option<WorkspaceId>,
    /// The resolved profile.
    pub(super) profile: ProfileId,
    /// Its revision, pinned at admission.
    pub(super) profile_revision: u64,
    /// The pairs to activate.
    pub(super) pairs: BTreeSet<AccessPair>,
    /// A restriction of the requested capabilities (the manifest's, the workspace
    /// policy's, or the covered ones); absent: the profile's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) capabilities: Option<BTreeSet<Capability>>,
    /// The manifest's access digest, when one was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) access_digest: Option<String>,
    /// What added authority does.
    pub(super) route: Route,
    /// The manifest's `preferences.background_work` (coverage and the delta only; never
    /// the activation's lock behaviour).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) background_work: bool,
    /// The requested pairs a `covered_only` request does not activate.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(super) uncovered: BTreeSet<AccessPair>,
}

/// The stored resolution of a request object, when it is an `ensure` with `context`.
/// `Err(())`: it has `context` but no readable resolution (fail closed).
fn stored_resolution(stored: &serde_json::Value) -> Result<Option<Resolution>, ()> {
    let has_context = stored.get("context").is_some_and(|v| !v.is_null());
    if stored.get("op").and_then(serde_json::Value::as_str) != Some("ensure") || !has_context {
        return Ok(None);
    }
    stored
        .get(RESOLUTION_KEY)
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .map(Some)
        .ok_or(())
}

/// ⟨M05⟩ The work an admitted `ensure` with `context` resolved to: `spec` (decoded from
/// the stored request) with the stored [`Resolution`] overlaid. `None` when the request
/// has `context` but its resolution is unreadable (the pipeline then refuses it, as any
/// unreadable request). Every other request is returned unchanged.
pub(super) fn overlay(
    mut spec: super::WorkSpec,
    stored: &serde_json::Value,
) -> Option<super::WorkSpec> {
    let r = match stored_resolution(stored) {
        Ok(Some(r)) => r,
        Ok(None) => return Some(spec),
        Err(()) => return None,
    };
    spec.profile = Some(r.profile.clone());
    spec.profile_revision = Some(r.profile_revision);
    spec.pairs = r.pairs.clone();
    spec.context = PolicyContext::of_recorded(r.workspace.as_ref());
    spec.m05 = Some(Box::new(r));
    Some(spec)
}

/// The capability restriction of `spec` applied to `capabilities` (resolution's
/// requested capabilities: the profile's ∩ the adapter's ∩ this).
pub(super) fn restrict_capabilities(
    spec: &super::WorkSpec,
    capabilities: BTreeSet<Capability>,
) -> BTreeSet<Capability> {
    match spec.m05.as_ref().and_then(|r| r.capabilities.as_ref()) {
        Some(c) => capabilities.intersection(c).copied().collect(),
        None => capabilities,
    }
}

/// `INTERACTION_REQUIRED`, reason `not_covered`, no decision reference: a `covered_only`
/// request found nothing (more) covered (ADR-0011 §3.2; ruling 3).
fn not_covered() -> OpError {
    OpError::new(
        Code::InteractionRequired,
        "nothing of this request is covered by the saved policy; background activation never asks",
    )
    .with_reason(reason::NOT_COVERED)
}

/// The cooldown answer (ADR-0011 §4.3; ruling I-5): `decision_cooldown` with
/// `retry_after` and the denied record's reference; no record is written.
fn cooldown(
    attended: bool,
    decision: &DecisionId,
    retry_after: Timestamp,
    now: Timestamp,
    what: &str,
) -> OpError {
    let wait = Duration::try_from(retry_after.duration_since(now)).unwrap_or(Duration::ZERO);
    let ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
    approval_needed(attended, decision.as_str(), what)
        .with_reason(reason::DECISION_COOLDOWN)
        .with_retry_after(ms)
        .with_resource("decision", Some(decision.to_string()))
}

// ---------------------------------------------------------------------------------
// The plan: one transaction after the probe
// ---------------------------------------------------------------------------------

/// What the plan decided.
enum Planned {
    /// The records changed since the probe: probe again.
    Retry,
    /// Nothing is admitted (a workspace decision may have been written).
    Refused(Box<OpError>),
    /// Admit with this resolution.
    Admit(Box<Resolution>),
}

/// Everything the plan reads outside the store.
struct PlanInput {
    own: EnvironmentId,
    environment: EnvironmentId,
    req: EnsureRequest,
    cwd: String,
    observed: ProbedWorkspace,
    records: Vec<heimdall_domain::workspace::WorkspaceRecord>,
    owner: bool,
    attended: bool,
    decision_id: DecisionId,
    lifetime: Duration,
    gate: TxnGate,
}

/// What a context asks for, before the request's own narrowing.
struct Asked {
    /// The profile's latest definition.
    def: ProfileDefinition,
    /// The pairs the manifest, the workspace policy or the profile asks for.
    base: BTreeSet<AccessPair>,
    /// The capability restriction (absent: the profile's).
    capabilities: Option<BTreeSet<Capability>>,
    /// The environments the manifest names (empty: any).
    environments: BTreeSet<EnvironmentId>,
    /// `preferences.background_work`.
    background_work: bool,
    /// The proposal a trust decision would record (the server's own, I5).
    proposal: TrustProposal,
}

/// The request a context makes (module docs, "Request" column).
fn asked_in(
    tx: &mut Txn<'_>,
    inp: &PlanInput,
    governing: Option<&StandingPolicy>,
) -> heimdall_store::Result<Result<Asked, OpError>> {
    macro_rules! refuse {
        ($e:expr) => {
            return Ok(Err($e))
        };
    }
    let other_profile = || {
        usage("the request names another profile than its workspace").with_resource("profile", None)
    };
    if let Some(m) = &inp.observed.manifest {
        return manifest_asked(tx, inp, m, governing);
    }
    if let Some(wp) = governing {
        if inp.req.profile.as_ref().is_some_and(|p| *p != wp.profile) {
            refuse!(other_profile());
        }
        let def = match trust_m05::latest_profile(tx, &wp.profile)? {
            Ok(d) => d,
            Err(e) => refuse!(e),
        };
        let base = wp
            .scope
            .pairs
            .intersection(&def.scope.pairs)
            .cloned()
            .collect();
        let capabilities = wp
            .scope
            .capabilities
            .intersection(&def.scope.capabilities)
            .copied()
            .collect();
        return Ok(Ok(Asked {
            proposal: TrustProposal {
                profile: def.id.clone(),
                pairs: BTreeSet::new(),
                environments: BTreeSet::new(),
                capabilities: BTreeSet::new(),
                background_work: false,
            },
            base,
            capabilities: Some(capabilities),
            environments: BTreeSet::new(),
            background_work: false,
            def,
        }));
    }
    // No manifest and no governing workspace: the request's profile, else the
    // environment's default-profile preference (ADR-0011 §5.1; read only by a new request
    // that omits its profile).
    let profile = match &inp.req.profile {
        Some(p) => p.clone(),
        None => match tx.default_profile(&inp.environment)? {
            Some(p) => p,
            None => refuse!(usage(
                "no profile was named and this environment has no default profile"
            )),
        },
    };
    let def = match trust_m05::latest_profile(tx, &profile)? {
        Ok(d) => d,
        Err(e) => refuse!(e),
    };
    // A manifest-less root's trust proposal is the request itself (the trust record then
    // supplies the request, ADR-0011 §2.2): its pairs (empty: the whole profile) in its
    // environment.
    let environments = if inp.environment == inp.own {
        BTreeSet::new()
    } else {
        [inp.environment.clone()].into_iter().collect()
    };
    Ok(Ok(Asked {
        proposal: TrustProposal {
            profile: def.id.clone(),
            pairs: inp.req.scope.clone(),
            environments,
            capabilities: BTreeSet::new(),
            background_work: false,
        },
        base: def.scope.pairs.clone(),
        capabilities: None,
        environments: BTreeSet::new(),
        background_work: false,
        def,
    }))
}

/// A manifest's request: its profile (which the request and a governing workspace policy
/// must name too), its tokens resolved against the local catalog ∩ the profile's latest
/// snapshot (`trust_m05::manifest_proposal`, the same computation a trust decision uses).
fn manifest_asked(
    tx: &mut Txn<'_>,
    inp: &PlanInput,
    m: &ProbedManifest,
    governing: Option<&StandingPolicy>,
) -> heimdall_store::Result<Result<Asked, OpError>> {
    let Some(def) = tx.profile(&m.profile)? else {
        return Ok(Err(OpError::new(
            Code::NotFound,
            "the manifest names a profile this catalog does not have",
        )
        .with_reason(reason::MANIFEST_PROFILE_UNKNOWN)));
    };
    if inp.req.profile.as_ref().is_some_and(|p| *p != m.profile) {
        return Ok(Err(usage(
            "the request names another profile than its workspace manifest",
        )
        .with_resource("profile", None)));
    }
    if governing.is_some_and(|wp| wp.profile != m.profile) {
        // The workspace was trusted for another profile: the manifest's request is not an
        // extension of that policy, and nothing here may move a policy to another profile.
        return Ok(Err(usage(
            "the manifest names another profile than the workspace was trusted for; remove the workspace's trust and trust it again",
        )
        .with_resource("profile", None)));
    }
    let proposal = match trust_m05::manifest_proposal(tx, &inp.own, m, &def)? {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    let base = if proposal.pairs.is_empty() {
        def.scope.pairs.clone()
    } else {
        proposal.pairs.clone()
    };
    let capabilities = (!proposal.capabilities.is_empty()).then(|| proposal.capabilities.clone());
    Ok(Ok(Asked {
        base,
        capabilities,
        environments: proposal.environments.clone(),
        background_work: proposal.background_work,
        proposal,
        def,
    }))
}

/// The plan (module docs).
#[allow(clippy::too_many_lines)]
fn plan_in(tx: &mut Txn<'_>, emit: &mut Emit, inp: &PlanInput) -> heimdall_store::Result<Planned> {
    macro_rules! refuse {
        ($e:expr) => {
            return Ok(Planned::Refused(Box::new($e)))
        };
    }
    // What the probe matched against must still be what is stored.
    if active_records(tx, &inp.own)? != inp.records {
        return Ok(Planned::Retry);
    }
    let assessed = inp.gate.check(tx)?;
    let now = match &assessed {
        Ok(s) => s.wall(),
        Err(_) => inp.gate.clock().wall(),
    };
    let o = &inp.observed;
    let req = &inp.req;
    // The workspace whose own policy governs: `Trusted` or `Member` with a policy.
    let governing: Option<(WorkspaceId, StandingPolicy)> = match &o.matched {
        Some(WorkspaceMatch::Trusted { workspace } | WorkspaceMatch::Member { workspace }) => {
            workspace_policy(tx, workspace)?.map(|p| (workspace.clone(), p))
        }
        _ => None,
    };
    let asked = match asked_in(tx, inp, governing.as_ref().map(|(_, p)| p))? {
        Ok(a) => a,
        Err(e) => refuse!(e),
    };
    // A29: request content never widens the profile.
    if !req.scope.is_subset(&asked.def.scope.pairs) {
        refuse!(
            usage("the requested scope names pairs outside the profile")
                .with_resource("profile", Some(asked.def.id.to_string()))
        );
    }
    let profile_revision = req.profile_revision.unwrap_or(asked.def.revision);
    let pairs = if req.scope.is_empty() {
        asked.base.clone()
    } else {
        req.scope.clone()
    };
    // Something outside the context's request: the M01 pipeline, unchanged.
    let explicit = req.until.is_some()
        || !pairs.is_subset(&asked.base)
        || (!asked.environments.is_empty() && !asked.environments.contains(&inp.environment));
    let workspace = governing.as_ref().map(|(w, _)| w.clone());
    let context = PolicyContext::of_recorded(workspace.as_ref());
    let policy = resolve_policy(&tx.policies_for(&asked.def.id, &inp.environment)?, &context)
        .filter(|p| p.profile == asked.def.id);
    let automatic = tx
        .environment(&inp.environment)?
        .is_some_and(|r| r.permissions.automatic_activation);
    let capabilities = asked
        .capabilities
        .clone()
        .unwrap_or_else(|| asked.def.scope.capabilities.clone());
    let digest = o.manifest.as_ref().map(|m| m.access_digest.clone());
    let resolution = |route: Route,
                      pairs: BTreeSet<AccessPair>,
                      capabilities: Option<BTreeSet<Capability>>,
                      uncovered: BTreeSet<AccessPair>| {
        Planned::Admit(Box::new(Resolution {
            workspace: workspace.clone(),
            profile: asked.def.id.clone(),
            profile_revision,
            pairs,
            capabilities,
            access_digest: digest.clone(),
            route,
            background_work: asked.background_work,
            uncovered,
        }))
    };

    // Background: requested ∩ covered, never a decision record (ruling 3).
    if req.covered_only {
        let usable = policy
            .as_ref()
            .filter(|p| automatic && p.environments.contains(&inp.environment));
        let (covered, caps): (BTreeSet<AccessPair>, BTreeSet<Capability>) = match usable {
            Some(p) => (
                pairs.intersection(&p.scope.pairs).cloned().collect(),
                capabilities
                    .intersection(&p.scope.capabilities)
                    .copied()
                    .collect(),
            ),
            None => (BTreeSet::new(), BTreeSet::new()),
        };
        if covered.is_empty() || caps.is_empty() {
            refuse!(not_covered());
        }
        let uncovered = pairs.difference(&covered).cloned().collect();
        return Ok(resolution(
            Route::CoveredOnly,
            covered,
            Some(caps),
            uncovered,
        ));
    }
    if explicit {
        return Ok(resolution(
            Route::Standing,
            pairs,
            asked.capabilities.clone(),
            BTreeSet::new(),
        ));
    }

    // A trusted (or member) workspace: its own policy alone governs.
    if let Some((_, wp)) = &governing {
        let delta = ScopeDelta {
            pairs: pairs.clone(),
            capabilities: capabilities.clone(),
            environments: [inp.environment.clone()].into_iter().collect(),
            background_work: asked.background_work,
        }
        .beyond(wp);
        let lock_only = delta.background_work
            && delta.pairs.is_empty()
            && delta.capabilities.is_empty()
            && delta.environments.is_empty();
        if lock_only {
            // Only the lock behaviour is added: raised before admission (module docs).
            if !inp.owner {
                refuse!(OpError::from_denial(&Denial::RoleForbidden));
            }
            if let Err(u) = &assessed {
                refuse!(uncertain(u));
            }
            match raise_extension(
                tx,
                emit,
                wp,
                &inp.own,
                &inp.environment,
                &delta,
                now,
                inp.decision_id.clone(),
                inp.lifetime,
            )? {
                Ok(Extension::Covered) => {}
                Ok(ext) => {
                    if let Some(e) = ext.refusal(inp.attended, now) {
                        refuse!(e);
                    }
                }
                Err(e) => refuse!(e),
            }
        }
        return Ok(resolution(
            Route::Extension,
            pairs,
            asked.capabilities.clone(),
            BTreeSet::new(),
        ));
    }

    // Personal context: no root, `Untrusted`, `Ambiguous` (R5-Q8).
    let requested = Scope {
        pairs: pairs.clone(),
        capabilities: capabilities.clone(),
    };
    let environments: BTreeSet<EnvironmentId> = [inp.environment.clone()].into_iter().collect();
    let personal_covers = automatic
        && policy.as_ref().is_some_and(|p| {
            coverage(p, &requested, &environments, asked.background_work)
                .uncovered
                .is_empty()
        });
    if o.root.is_none() || personal_covers {
        return Ok(resolution(
            Route::Standing,
            pairs,
            asked.capabilities.clone(),
            BTreeSet::new(),
        ));
    }
    // Not covered: one workspace decision, before admission (module docs).
    if !inp.owner {
        refuse!(OpError::from_denial(&Denial::RoleForbidden));
    }
    if let Err(u) = &assessed {
        refuse!(uncertain(u));
    }
    match &o.matched {
        Some(WorkspaceMatch::Ambiguous { workspace, .. }) => {
            let action = PolicyAction::ReconcileWorkspace {
                workspace: workspace.clone(),
                cwd: inp.cwd.clone(),
            };
            let (kind, basis) = match trust_m05::build_reconcile(tx, &inp.own, &action, o)? {
                Err(e) => refuse!(e),
                Ok(Built::Existing(_)) => {
                    return Ok(resolution(
                        Route::Standing,
                        pairs,
                        asked.capabilities.clone(),
                        BTreeSet::new(),
                    ));
                }
                Ok(Built::Record(kind, basis)) => (*kind, basis),
            };
            let id = trust_m05::write_workspace_record(
                tx,
                emit,
                kind,
                basis,
                now,
                inp.decision_id.clone(),
                inp.lifetime,
            )?;
            refuse!(
                approval_needed(
                    inp.attended,
                    id.as_str(),
                    "this checkout moved or was re-cloned; the owner reconciles it with its trusted workspace",
                )
                .with_reason(reason::WORKSPACE_AMBIGUOUS)
                .with_resource("decision", Some(id.to_string()))
            )
        }
        _ => {
            let action = PolicyAction::TrustWorkspace {
                cwd: inp.cwd.clone(),
                access_digest: digest.clone().unwrap_or_default(),
                proposal: asked.proposal.clone(),
            };
            let (kind, basis) = match trust_m05::build_trust(tx, &inp.own, &action, o)? {
                Err(e) => refuse!(e),
                Ok(Built::Existing(_)) => {
                    return Ok(resolution(
                        Route::Standing,
                        pairs,
                        asked.capabilities.clone(),
                        BTreeSet::new(),
                    ));
                }
                Ok(Built::Record(kind, basis)) => (*kind, basis),
            };
            // Ruling I-5: a recently denied trust of this workspace identity and proposal
            // answers `decision_cooldown`, with no record.
            if let Some(key) = trust_m05::trust_cooldown_key_of(&kind, basis.as_ref())
                && let Some((denied, until)) = trust_m05::trust_cooldown(tx, &key, now)?
            {
                refuse!(cooldown(
                    inp.attended,
                    &denied,
                    until,
                    now,
                    "the owner declined to trust this workspace recently; it is not asked again until the cooldown ends",
                ));
            }
            let id = trust_m05::write_workspace_record(
                tx,
                emit,
                kind,
                basis,
                now,
                inp.decision_id.clone(),
                inp.lifetime,
            )?;
            refuse!(
                approval_needed(
                    inp.attended,
                    id.as_str(),
                    "this workspace is not trusted and asks for more than personal access covers; the owner reviews it",
                )
                .with_reason(reason::WORKSPACE_UNTRUSTED)
                .with_resource("decision", Some(id.to_string()))
            )
        }
    }
}

impl Operations {
    /// ⟨M05⟩ `ensure` with `context` (module docs): probe, plan, then admission with the
    /// resolution and the hash extras of ADR-0006 §17.4, and the M01 pipeline.
    pub(super) async fn ensure_in_context(
        &self,
        caller: &Caller,
        req: EnsureRequest,
    ) -> OpResult<EnsureData> {
        let Some(ctx) = req.context.clone() else {
            return Err(internal("not a context request"));
        };
        // Without an observer nothing is read or written (the joint wave 0 landing).
        let Some(probe) = self.workspace_probe() else {
            return Err(no_probe());
        };
        if ctx.validate().is_err() {
            return Err(usage(
                "the working directory is an absolute path of 1 to 4096 bytes without NUL",
            )
            .with_effect(heimdall_contract::envelope::EffectStatus::None));
        }
        // ⟨M03⟩ U0b row 9 (O): `connection: graceful` is refused before anything is read
        // or written (a workspace decision included), as `ensure_precheck` refuses it.
        if req.connection.as_ref().is_some_and(|c| {
            c.existing == Some(heimdall_contract::managed::ExistingConnectionsMode::Graceful)
        }) {
            return Err(usage(
                "a request may only narrow existing connections to strict; graceful is a policy setting",
            )
            .with_effect(heimdall_contract::envelope::EffectStatus::None));
        }
        let own = self.environment().clone();
        let environment = req.environment.clone().unwrap_or_else(|| own.clone());
        {
            let (own2, target) = (own.clone(), environment.clone());
            self.write(move |tx, _| crate::environments::admit(tx, &own2, &target))
                .await??;
        }
        let mut planned = Planned::Retry;
        for _ in 0..MAX_PLAN_ATTEMPTS {
            let records = self.active_records().await?;
            let observed = self
                .probe_workspace(probe.clone(), own.clone(), ctx.cwd.clone(), records.clone())
                .await?
                .map_err(probe_error)?;
            let inp = PlanInput {
                own: own.clone(),
                environment: environment.clone(),
                req: req.clone(),
                cwd: ctx.cwd.clone(),
                observed,
                records,
                owner: caller.context.is_owner(),
                attended: caller.is_attended(),
                decision_id: crate::ids::new_decision_id()?,
                lifetime: self.inner.config.limits.decision_lifetime,
                gate: self.inner.timegate.in_txn(),
            };
            planned = self.write(move |tx, emit| plan_in(tx, emit, &inp)).await?;
            if !matches!(planned, Planned::Retry) {
                break;
            }
        }
        let resolution = match planned {
            Planned::Retry => return Err(changed_since_review()),
            Planned::Refused(e) => return Err(*e),
            Planned::Admit(r) => *r,
        };
        // ⟨M03⟩ U0b row 9 (O): the M03 pre-admission refusals, on the resolved request.
        let resolved_req = EnsureRequest {
            profile: Some(resolution.profile.clone()),
            profile_revision: Some(resolution.profile_revision),
            scope: resolution.pairs.clone(),
            context: None,
            covered_only: false,
            ..req.clone()
        };
        let precheck = self.ensure_precheck(&resolved_req).await?;
        let hash = compute_hash(
            OperationKind::Ensure,
            &HashInput {
                environment: &environment,
                profile: req.profile.as_ref(),
                profile_revision: req.profile_revision,
                scope: &req.scope,
                deadline_intent: req.until.as_ref(),
                work_id: Some(&req.work_id),
                required_capabilities: &req.required_capabilities,
                parent_binding: None,
                // ADR-0006 §17.4: with `context`, the resolved workspace and the access
                // digest enter the hash; the same request ID resolving otherwise is
                // `REQUEST_CONFLICT`.
                extra: pair_mechanism_m03::ensure_hash_extra(
                    &req,
                    Some(&ContextHashExtras {
                        workspace: resolution.workspace.as_ref(),
                        access_digest: resolution.access_digest.as_deref(),
                    }),
                ),
            },
        )
        .map_err(|_| usage("the request cannot be canonicalized"))?;
        let mut request =
            serde_json::to_value(heimdall_contract::request::Request::Ensure(req.clone()))
                .map_err(|_| internal("request is not serializable"))?;
        let stored = serde_json::to_value(&resolution)
            .map_err(|_| internal("the resolution is not serializable"))?;
        match request.as_object_mut() {
            Some(map) => {
                map.insert(RESOLUTION_KEY.to_owned(), stored);
            }
            None => return Err(internal("the request is not an object")),
        }
        let request_id = req.request_id.clone();
        let r = self
            .run_work_json(
                caller,
                OperationKind::Ensure,
                request,
                hash,
                request_id,
                req.wait,
                environment,
            )
            .await;
        let mut r = precheck.decorate(r);
        if let Ok(done) = &mut r {
            let grant = done.data.grant_id.clone();
            self.label_grant_lock(done, &grant).await;
        }
        r
    }

    /// ⟨M05⟩ U4: `inspect workspace` (`InspectRequest.cwd`; ADR-0011 §2.3): the root, the
    /// match, the workspace record, its policy, the manifest's access digest, and the
    /// context's provenance. The workspace ID, policy ID and digest are owner-only, as
    /// the other owner-sensitive subjects are; another role sees the root and the match.
    pub(super) async fn inspect_workspace(
        &self,
        caller: &Caller,
        cwd: Option<String>,
    ) -> Result<WorkspaceView, OpError> {
        let Some(probe) = self.workspace_probe() else {
            return Err(no_probe());
        };
        let Some(cwd) = cwd else {
            return Err(usage("inspect workspace names a working directory (cwd)"));
        };
        if (WorkContext { cwd: cwd.clone() }).validate().is_err() {
            return Err(usage(
                "the working directory is an absolute path of 1 to 4096 bytes without NUL",
            ));
        }
        let own = self.environment().clone();
        let records = self.active_records().await?;
        let observed = self
            .probe_workspace(probe, own, cwd.clone(), records)
            .await?
            .map_err(probe_error)?;
        let (matched, workspace) = match &observed.matched {
            None => (WorkspaceMatchView::None, None),
            Some(WorkspaceMatch::Trusted { workspace }) => {
                (WorkspaceMatchView::Trusted, Some(workspace.clone()))
            }
            Some(WorkspaceMatch::Member { workspace }) => {
                (WorkspaceMatchView::Member, Some(workspace.clone()))
            }
            Some(WorkspaceMatch::Ambiguous { workspace, .. }) => {
                (WorkspaceMatchView::Ambiguous, Some(workspace.clone()))
            }
            Some(_) => (WorkspaceMatchView::Untrusted, None),
        };
        let owner = caller.context.is_owner();
        let ws = workspace.clone();
        let policy_id = match ws {
            Some(w) if owner => {
                self.write(move |tx, _| Ok(workspace_policy(tx, &w)?.map(|p| p.id)))
                    .await?
            }
            _ => None,
        };
        Ok(WorkspaceView {
            cwd,
            root: observed.root.clone(),
            matched,
            workspace_id: workspace.filter(|_| owner),
            policy_id,
            access_digest: observed
                .manifest
                .as_ref()
                .map(|m| m.access_digest.clone())
                .filter(|_| owner),
            provenance: ContextProvenance::SameUserContext,
        })
    }
}

// ---------------------------------------------------------------------------------
// Hooks in the pipeline
// ---------------------------------------------------------------------------------

/// What resolution does with added authority (the `Approval` arm of `stage_resolve`).
pub(super) enum OnApproval {
    /// The M01 path: an `ApproveAuthority` record (or joining an equivalent one).
    Normal,
    /// Settle failed with this error; no decision record.
    Fail(Box<OpError>),
    /// Wait on this `WidenPolicy{extend_scope}` record (no `ApproveAuthority`).
    Wait,
}

/// The `extend_scope` delta of a waiting grant's `AuthorityDelta` on `policy`: the added
/// pairs and capabilities, the target environment when the policy does not list it, and
/// the manifest's lock behaviour. `None` when the delta cannot be expressed as a policy
/// extension (a longer window, or an environment whose automatic activation is off): the
/// M01 one-off path answers it.
fn extension_delta(
    policy: &StandingPolicy,
    environment: &EnvironmentId,
    delta: &AuthorityDelta,
    background_work: bool,
) -> Option<ScopeDelta> {
    if delta.extra_window.is_some() {
        return None;
    }
    let mut environments = BTreeSet::new();
    if delta.environment_not_covered {
        if policy.environments.contains(environment) {
            return None;
        }
        environments.insert(environment.clone());
    }
    Some(ScopeDelta {
        pairs: delta.added_scope.pairs.clone(),
        capabilities: delta.added_scope.capabilities.clone(),
        environments,
        background_work,
    })
}

/// Raise or join the extension a [`Route::Extension`] request's `delta` needs on its
/// workspace policy. `None`: not expressible, or nothing to extend (the M01 path).
#[allow(clippy::too_many_arguments)]
fn extension_for(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    r: &Resolution,
    own: &EnvironmentId,
    environment: &EnvironmentId,
    delta: &AuthorityDelta,
    now: Timestamp,
    decision_id: DecisionId,
    lifetime: Duration,
) -> heimdall_store::Result<Option<Result<Extension, OpError>>> {
    if r.route != Route::Extension {
        return Ok(None);
    }
    let Some(workspace) = &r.workspace else {
        return Ok(None);
    };
    let Some(policy) = workspace_policy(tx, workspace)?.filter(|p| p.profile == r.profile) else {
        return Ok(None);
    };
    let Some(scope) = extension_delta(&policy, environment, delta, r.background_work) else {
        return Ok(None);
    };
    Ok(
        match raise_extension(
            tx,
            emit,
            &policy,
            own,
            environment,
            &scope,
            now,
            decision_id,
            lifetime,
        )? {
            Ok(Extension::Covered) => None,
            other => Some(other),
        },
    )
}

/// ⟨M05⟩ `stage_resolve`'s `Approval` arm for an `ensure` with `context`: a
/// [`Route::CoveredOnly`] request fails `not_covered` with no record (ruling 3, even when a
/// narrowing raced its admission); a [`Route::Extension`] request raises or joins its
/// `WidenPolicy{extend_scope}` and waits (a cooldown fails it with `decision_cooldown`, no
/// record); everything else is the M01 path.
#[allow(clippy::too_many_arguments)]
pub(super) fn on_approval(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    spec: &super::WorkSpec,
    own: &EnvironmentId,
    environment: &EnvironmentId,
    delta: &AuthorityDelta,
    now: Timestamp,
    decision_id: DecisionId,
    lifetime: Duration,
) -> heimdall_store::Result<OnApproval> {
    let Some(r) = spec.m05.as_deref() else {
        return Ok(OnApproval::Normal);
    };
    if r.route == Route::CoveredOnly {
        return Ok(OnApproval::Fail(Box::new(not_covered())));
    }
    Ok(
        match extension_for(
            tx,
            emit,
            r,
            own,
            environment,
            delta,
            now,
            decision_id,
            lifetime,
        )? {
            None => OnApproval::Normal,
            Some(Ok(Extension::Pending { .. })) => OnApproval::Wait,
            Some(Ok(Extension::Cooldown {
                decision,
                retry_after,
            })) => OnApproval::Fail(Box::new(cooldown(
                false,
                &decision,
                retry_after,
                now,
                "the owner denied this added authority recently; it is not asked again until the cooldown ends",
            ))),
            Some(Ok(Extension::Covered)) => OnApproval::Normal,
            Some(Err(e)) => OnApproval::Fail(Box::new(e)),
        },
    )
}

/// What a waiting [`Route::Extension`] request answers (`awaiting_response`).
pub(super) enum OnWaiting {
    /// Not an extension request (or not expressible): the M01 answer.
    Normal,
    /// The pending `WidenPolicy` record that answers for it.
    Decision(DecisionId),
    /// Its extension was denied (the key cools down): the request ends with the M01
    /// denial.
    Denied(Box<OpError>),
}

/// ⟨M05⟩ `awaiting_response` for an operation whose stored request is a
/// [`Route::Extension`] context request and whose needed `delta` is not empty: its
/// coalesced `WidenPolicy` record (raised again if the last one expired unanswered), never
/// an `ApproveAuthority`; after a denial it ends.
#[allow(clippy::too_many_arguments)]
pub(super) fn on_waiting(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    stored: &serde_json::Value,
    own: &EnvironmentId,
    environment: &EnvironmentId,
    delta: &AuthorityDelta,
    now: Timestamp,
    decision_id: DecisionId,
    lifetime: Duration,
) -> heimdall_store::Result<OnWaiting> {
    let Ok(Some(r)) = stored_resolution(stored) else {
        return Ok(OnWaiting::Normal);
    };
    Ok(
        match extension_for(
            tx,
            emit,
            &r,
            own,
            environment,
            delta,
            now,
            decision_id,
            lifetime,
        )? {
            Some(Ok(Extension::Pending { decision, .. })) => OnWaiting::Decision(decision),
            Some(Ok(Extension::Cooldown { decision, .. })) => OnWaiting::Denied(Box::new(
                OpError::new(
                    Code::CapabilityUnavailable,
                    "the owner denied the requested additional authority",
                )
                .with_resource("decision", Some(decision.to_string())),
            )),
            Some(Err(e)) => OnWaiting::Denied(Box::new(e)),
            _ => OnWaiting::Normal,
        },
    )
}

/// ⟨M05⟩ At commit, the result of an `ensure` with `context` reports where its authority
/// came from (`EnsureData.context`: the context, the policy and revision its grant origin
/// records, `same_user_context`; `explicit` for a one-off approval) and the pairs a
/// `covered_only` request did not activate (`uncovered`). Every other result is
/// unchanged.
pub(super) fn decorate_commit(
    tx: &mut Txn<'_>,
    operation: &OperationId,
    grant: &GrantId,
    data: &mut EnsureData,
) -> heimdall_store::Result<()> {
    let Some(intent) = tx.recovery_intent(operation)? else {
        return Ok(());
    };
    let Ok(Some(r)) = stored_resolution(&intent.request) else {
        return Ok(());
    };
    let approved = intent
        .resolved
        .as_ref()
        .is_some_and(|i| i.approval.is_some());
    let origin = tx.grant_origin(grant)?;
    let (kind, workspace) = match (&r.workspace, approved) {
        (_, true) => (ContextKind::Explicit, r.workspace.clone()),
        (Some(w), false) => (ContextKind::Workspace, Some(w.clone())),
        (None, false) => (ContextKind::Personal, None),
    };
    let (policy_id, policy_revision) = match origin.as_ref().filter(|_| !approved) {
        Some(o) if o.policy_id.is_some() => (o.policy_id.clone(), o.policy_revision.map(|v| v.0)),
        // A waiting grant the saved policy came to cover (`proceed_covered`, e.g. after
        // its extension was approved): the policy of its context at the covered revision.
        Some(o) => match &o.covered {
            Some(c) => {
                let context = PolicyContext::of_recorded(o.workspace.as_ref());
                let first = crate::policy_context::policies_in(
                    tx,
                    &o.profile,
                    &data.environment_id,
                    &context,
                )?
                .into_iter()
                .next();
                (first.map(|p| p.id), c.policy_revision.map(|v| v.0))
            }
            None => (None, o.policy_revision.map(|v| v.0)),
        },
        None => (None, None),
    };
    data.context = Some(ContextReport {
        kind,
        workspace_id: workspace,
        policy_id,
        policy_revision,
        provenance: ContextProvenance::SameUserContext,
    });
    data.uncovered = r.uncovered.into_iter().collect::<Vec<AccessPairRef>>();
    Ok(())
}

/// ⟨M05⟩ ADR-0011 §5.3 (Q7): a `mixed_mechanisms` refusal of `pairs` carries
/// `next.groups`, one [`MechanismGroup`] per mechanism: a managed pair's
/// `managed_certificate`, an existing pair's catalog-named mechanism, and a pair the
/// catalog names none for the mechanism the M01 selection gives it (else the first
/// configured non-managed adapter's). When a pair cannot be placed, the refusal carries
/// no groups (fail closed: the caller cannot split what it cannot see). Any other error
/// is returned unchanged.
pub(super) fn with_mechanism_groups(
    tx: &mut Txn<'_>,
    e: OpError,
    pairs: &BTreeSet<AccessPair>,
    adapters: &[AdapterInfo],
    required: &RequiredCapabilities,
) -> heimdall_store::Result<OpError> {
    if e.reason.as_deref() != Some(reason::MIXED_MECHANISMS) {
        return Ok(e);
    }
    let unnamed = select_adapter(adapters, required, None)
        .map(|a| a.identity.mechanism.clone())
        .or_else(|| {
            adapters
                .iter()
                .find(|a| a.identity.mechanism != super::ca_issuance_m03::MANAGED_CERTIFICATE)
                .map(|a| a.identity.mechanism.clone())
        });
    let mut groups: std::collections::BTreeMap<String, Vec<AccessPairRef>> =
        std::collections::BTreeMap::new();
    for p in pairs {
        let one: BTreeSet<AccessPair> = [p.clone()].into_iter().collect();
        let mechanism = match pair_mechanism_m03::resolve_pairs(tx, &one)? {
            Ok(r) => match r.mechanism {
                Some(m) => m.to_owned(),
                None => match &unnamed {
                    Some(m) => m.clone(),
                    None => return Ok(e),
                },
            },
            Err(_) => return Ok(e),
        };
        groups.entry(mechanism).or_default().push(p.clone());
    }
    if groups.len() < 2 {
        return Ok(e);
    }
    let next = NextAction {
        groups: groups
            .into_iter()
            .map(|(mechanism, pairs)| MechanismGroup { mechanism, pairs })
            .collect(),
        ..e.next.clone()
    };
    Ok(e.with_next(next))
}
