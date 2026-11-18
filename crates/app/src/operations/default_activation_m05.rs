//! ⟨M05⟩ U5: the personal default and ordinary-`ssh` activation (ADR-0011 §3.1–§3.3,
//! §7, §10 items 4 and 7; ADR-0006 §17.6 R5-Q1; m05-plan U5; orchestrator ruling I-2).
//!
//! **What it activates.** Ordinary `ssh` reaches the environment endpoint, whose
//! `Signer::identities` asks the runtime's `ports::DefaultActivation` (ADR-0011 §3.2 (a)).
//! The runtime runs [`Operations::activate_default`]: the covered scope of the
//! environment's personal **`default`** policy (`StandingPolicy.default`, at most one per
//! environment, ADR-0011 §3.1) — its pairs ∩ the profile's latest definition, the managed
//! ones only (an existing-access pair's ordinary alias uses the owner's own agent and has
//! no slot) — as **new work** `default:<environment>:<n>`, then a holder-less launch bind of
//! that work's binding, which claims (or joins, ADR-0011 §5.2) each pair's ordinary-alias
//! slot so the environment endpoint lists its certificates.
//!
//! **Covered-or-nothing** (ADR-0011 §3.2; ruling D03's server half). The work is an
//! internal `ensure` (R5-Q1: not a client `EnsureRequest` with `covered_only`) whose stored
//! request carries a [`Route::CoveredOnly`] resolution under [`DEFAULT_KEY`]; the pipeline
//! overlays it ([`overlay`]), so anything the policy does not cover at resolution — a
//! narrowing that raced the plan included — fails `not_covered` in
//! `context_m05::on_approval` **before** any decision record, join or grant. Nothing here
//! ever creates a decision.
//!
//! **Precedence** (ADR-0011 §7). The plan refuses at once, before anything is admitted,
//! while the default policy (or any personal policy of its profile in the environment,
//! merged fail closed) is paused — a `stop` pauses — or past its cutoff, or while time is
//! uncertain. The pipeline checks pause and cutoff again for new work; the plan's check is
//! what keeps a background trigger from attaching an existing binding to the ordinary
//! alias under a pause (§7.2: background triggers are refused).
//!
//! **Re-entry** (ADR-0011 §3.3). Work IDs are numbered; the current work is the highest
//! `n` with a binding or a work stop ([`latest_work`]). While its binding is active,
//! usable, covers the covered set and references every pair's slot, the scope is
//! already active. Otherwise the next use starts work `n + 1`: an expired, ended, released
//! or stopped work ID is never extended (the M01 `work_deadline` would refuse it anyway).
//! A binding of the current work that covers the set but holds no slot yet is bound again
//! (its launch bind failed earlier), never replaced.
//!
//! **A caller timeout is not a cancellation** (ruling 7): the runtime runs this in a
//! task of its own, and the pipeline it starts runs to completion whatever any caller
//! does; a committed activation stays applied and the next identities request uses it.
//!
//! **Interaction.** The internal caller is the owner principal, **unattended** and
//! non-interactive (no adapter interaction, no `Attend`, no decision); the request itself
//! is `interactive` because its consumer is the owner's own `ssh`, whose other identities
//! are the owner's business (the M02 no-interaction refusal is for callers that declared
//! none).

use std::collections::BTreeSet;

use heimdall_contract::envelope::reason;
use heimdall_contract::event::EventType;
use heimdall_contract::ids::{BindingId, EnvironmentId, PolicyId, ProfileId, RequestId, WorkId};
use heimdall_contract::request::{
    BindForm, BindRequest, EnsureRequest, InteractionMode, LaunchBinding, Request,
    RequiredCapabilities, WaitMode,
};
use heimdall_contract::trust::{ActivationEventKind, ActivationEventPayload};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::binding::BindingState;
use heimdall_domain::idempotency::{HashInput, compute_hash};
use heimdall_domain::operation::OperationKind;
use heimdall_domain::policy::{PauseState, PolicyContext, StandingPolicy, resolve_policy};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::scope::{AccessPair, Capability};
use heimdall_domain::time as dtime;
use heimdall_store::Txn;

use super::ca_issuance_m03::MANAGED_CERTIFICATE;
use super::context_m05::{Resolution, Route};
use super::{Operations, internal, pair_mechanism_m03, resource, stop_m05};
use crate::context::Caller;
use crate::error::OpError;

/// The key under which the internal `ensure` stores its [`Resolution`] in its recovery
/// intent's request object (beside the request's own fields; `Request` decoding ignores
/// it). Only this module writes it: a client request is stored from its decoded form, so
/// no client field can carry it.
pub(super) const DEFAULT_KEY: &str = "m05_default_activation";

/// The work-ID prefix of the default endpoint's work (ADR-0011 §3.3).
pub const DEFAULT_WORK_PREFIX: &str = "default:";

/// The stable reasons [`DefaultOutcome::Blocked`] and the activation events carry.
pub mod blocked {
    /// The default policy (or a personal policy of its profile here) is paused or
    /// stopped.
    pub const POLICY_PAUSED: &str = "policy_paused";
    /// Past its hard cutoff.
    pub const POLICY_CUTOFF: &str = "policy_cutoff";
    /// Time is uncertain: no new activation (ADR-0006 §13.6 item 6).
    pub const TIME_UNCERTAIN: &str = "time_uncertain";
}

/// How many plan-and-act rounds one activation takes at most (an `ensure`, then the bind
/// of its binding, then one spare for a concurrent change).
const MAX_ROUNDS: usize = 3;

/// The work ID `default:<environment>:<n>`.
///
/// # Errors
/// `INTERNAL_ERROR` when it is not a valid token (it always is: an environment ID is a
/// bounded token and `n` is decimal).
pub fn default_work_id(environment: &EnvironmentId, n: u64) -> Result<WorkId, OpError> {
    WorkId::parse(&format!("{DEFAULT_WORK_PREFIX}{environment}:{n}"))
        .map_err(|_| internal("the default work ID is not a valid token"))
}

/// The basis a runtime remembers a refusal against: a refusal is not retried while the
/// default policy, its revision and the authority generation are unchanged (and its retry
/// interval has not passed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefaultBasis {
    /// The default policy.
    pub policy: PolicyId,
    /// Its revision.
    pub revision: u64,
    /// The authority generation (every pause, cutoff, narrowing, revocation and
    /// environment write moves it).
    pub generation: u64,
}

/// What the default activation of an environment came to. Nonsecret: IDs and stable
/// reason words only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultOutcome {
    /// No personal `default` policy applies to the environment.
    NoDefault,
    /// The covered scope was already active: nothing was done.
    Active {
        /// The default policy.
        policy: PolicyId,
        /// The current work.
        work_id: WorkId,
        /// Its binding.
        binding: BindingId,
    },
    /// Activated now (the work's binding holds or joined every covered pair's slot).
    Activated {
        /// The default policy.
        policy: PolicyId,
        /// The work.
        work_id: WorkId,
        /// Its binding.
        binding: BindingId,
    },
    /// A pause (or stop), a cutoff or uncertain time: nothing was started.
    Blocked {
        /// The default policy.
        policy: PolicyId,
        /// A [`blocked`] reason.
        reason: String,
    },
    /// Nothing activatable is covered (`not_covered`); no decision was created.
    NotCovered {
        /// The default policy.
        policy: PolicyId,
        /// The stable reason.
        reason: String,
    },
    /// The activation was refused or failed for another reason (its error's reason, else
    /// its code in lower case). No decision was created.
    Failed {
        /// The default policy, when it was read.
        policy: Option<PolicyId>,
        /// The stable reason.
        reason: String,
    },
}

/// The state of an environment's default activation, read in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultState {
    /// Nothing to start: no default, already active, blocked or not covered.
    Settled(DefaultOutcome),
    /// Work or a bind is needed, under this basis.
    Needed(DefaultBasis),
}

/// What the activation does next.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// The current work's binding is active and slotted.
    Active { work: WorkId, binding: BindingId },
    /// The current work's binding covers the set but does not reference every slot.
    Bind { work: WorkId, binding: BindingId },
    /// Start this new work.
    Work(WorkId),
}

/// A plan the activation acts on.
#[derive(Debug, Clone)]
struct Plan {
    policy: StandingPolicy,
    profile_revision: u64,
    pairs: BTreeSet<AccessPair>,
    capabilities: BTreeSet<Capability>,
    basis: DefaultBasis,
    step: Step,
}

/// The plan's answer.
#[derive(Debug, Clone)]
enum Planned {
    Settled(DefaultOutcome),
    Act(Box<Plan>),
}

/// The environment's personal `default` policy (ADR-0011 §3.1: at most one; the first by
/// ID should a store ever hold more).
fn default_policy(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
) -> heimdall_store::Result<Option<StandingPolicy>> {
    Ok(tx
        .policies()?
        .into_iter()
        .filter(|p| p.workspace.is_none() && p.default && p.environments.contains(environment))
        .min_by(|a, b| a.id.cmp(&b.id)))
}

/// Whether work `n` of `environment` was ever used: it has a binding, or it was stopped.
fn used(tx: &mut Txn<'_>, environment: &EnvironmentId, n: u64) -> heimdall_store::Result<bool> {
    let Ok(work) = default_work_id(environment, n) else {
        return Ok(true);
    };
    Ok(!tx.bindings_for_work(environment, &work)?.is_empty()
        || tx.work_stop(environment, &work)?.is_some())
}

/// The highest used work number of `environment` (0: none). Work numbers are used in
/// order (the next is always `latest + 1`), so the used ones form a prefix and a
/// galloping search finds its end in `O(log n)` reads. Should a same-user client have
/// used a `default:` work ID out of order, the answer is still a used number whose
/// successor is unused, and an `ensure` of an expired one is refused by `work_deadline`,
/// so a gap can only cost a retry, never extend a work.
fn latest_work(tx: &mut Txn<'_>, environment: &EnvironmentId) -> heimdall_store::Result<u64> {
    if !used(tx, environment, 1)? {
        return Ok(0);
    }
    let (mut lo, mut hi) = (1_u64, 2_u64);
    while used(tx, environment, hi)? {
        lo = hi;
        hi = match hi.checked_mul(2) {
            Some(h) => h,
            None => return Ok(lo),
        };
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if used(tx, environment, mid)? {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// The current work's binding that already serves `pairs`, if any: active, its grant
/// usable and within its bound, covering every pair. `Ok(Some((binding, slotted)))`.
fn current_binding(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    work: &WorkId,
    pairs: &BTreeSet<AccessPair>,
    now: Timestamp,
) -> heimdall_store::Result<Option<(BindingId, bool)>> {
    if tx.work_stop(environment, work)?.is_some() {
        return Ok(None);
    }
    for b in tx.bindings_for_work(environment, work)? {
        if b.state != BindingState::Active || !pairs.is_subset(&b.scope.pairs) {
            continue;
        }
        let Some(g) = tx.grant(&b.grant)? else {
            continue;
        };
        if !g.state.permits_use()
            || dtime::is_expired(now, super::bound_of(tx, &g, Some(&b.profile))?)
        {
            continue;
        }
        let mut slotted = true;
        for p in pairs {
            let refs = tx.slot_references(environment, &p.destination, &p.account)?;
            if !refs.iter().any(|r| r.binding == b.id) {
                slotted = false;
                break;
            }
        }
        return Ok(Some((b.id, slotted)));
    }
    Ok(None)
}

/// The plan (module docs), in one transaction. `now` is `None` under uncertain time.
fn plan_in(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    now: Option<Timestamp>,
) -> heimdall_store::Result<Result<Planned, OpError>> {
    let Some(p) = default_policy(tx, environment)? else {
        return Ok(Ok(Planned::Settled(DefaultOutcome::NoDefault)));
    };
    let settled = |o: DefaultOutcome| Ok(Ok(Planned::Settled(o)));
    let blocked = |reason: &str| DefaultOutcome::Blocked {
        policy: p.id.clone(),
        reason: reason.to_owned(),
    };
    let not_covered = || DefaultOutcome::NotCovered {
        policy: p.id.clone(),
        reason: reason::NOT_COVERED.to_owned(),
    };
    let Some(now) = now else {
        return settled(blocked(blocked::TIME_UNCERTAIN));
    };
    // Blocks, fail closed over the default and every personal policy of its profile here
    // (ADR-0011 §3.1; §10 item 1: personal context).
    let merged = resolve_policy(
        &tx.policies_for(&p.profile, environment)?,
        &PolicyContext::Personal,
    );
    let paused = |q: &StandingPolicy| matches!(q.pause, PauseState::Paused { .. });
    if paused(&p) || merged.as_ref().is_some_and(paused) {
        return settled(blocked(blocked::POLICY_PAUSED));
    }
    let cutoff = [p.cutoff_at, merged.as_ref().and_then(|m| m.cutoff_at)]
        .into_iter()
        .flatten()
        .min();
    if cutoff.is_some_and(|c| dtime::is_expired(now, c)) {
        return settled(blocked(blocked::POLICY_CUTOFF));
    }
    // What is covered and activatable here.
    let automatic = tx
        .environment(environment)?
        .is_some_and(|r| r.permissions.automatic_activation);
    let (Some(merged), Some(def), true) = (merged, tx.profile(&p.profile)?, automatic) else {
        return settled(not_covered());
    };
    let mut pairs = BTreeSet::new();
    for pair in p
        .scope
        .pairs
        .iter()
        .filter(|q| def.scope.pairs.contains(*q) && merged.scope.pairs.contains(*q))
    {
        let one: BTreeSet<AccessPair> = [pair.clone()].into_iter().collect();
        if let Ok(r) = pair_mechanism_m03::resolve_pairs(tx, &one)?
            && r.mechanism == Some(MANAGED_CERTIFICATE)
        {
            pairs.insert(pair.clone());
        }
    }
    let capabilities: BTreeSet<Capability> = p
        .scope
        .capabilities
        .iter()
        .filter(|c| def.scope.capabilities.contains(*c) && merged.scope.capabilities.contains(*c))
        .copied()
        .collect();
    if pairs.is_empty() || capabilities.is_empty() {
        return settled(not_covered());
    }
    let basis = DefaultBasis {
        policy: p.id.clone(),
        revision: p.revision.0,
        generation: tx.authority_generation()?.0,
    };
    // The current work, else the next one.
    let latest = latest_work(tx, environment)?;
    let mut step = None;
    if latest > 0 {
        let work = match default_work_id(environment, latest) {
            Ok(w) => w,
            Err(e) => return Ok(Err(e)),
        };
        if let Some((binding, slotted)) = current_binding(tx, environment, &work, &pairs, now)? {
            step = Some(if slotted {
                Step::Active { work, binding }
            } else {
                Step::Bind { work, binding }
            });
        }
    }
    let step = match step {
        Some(s) => s,
        None => {
            let Some(next) = latest.checked_add(1) else {
                return Ok(Err(internal("the default work numbers are exhausted")));
            };
            match default_work_id(environment, next) {
                Ok(w) => Step::Work(w),
                Err(e) => return Ok(Err(e)),
            }
        }
    };
    Ok(Ok(Planned::Act(Box::new(Plan {
        profile_revision: def.revision,
        policy: p,
        pairs,
        capabilities,
        basis,
        step,
    }))))
}

/// The stable reason of an error: its reason, else its code in lower case.
fn reason_of(e: &OpError) -> String {
    e.reason
        .clone()
        .unwrap_or_else(|| e.code.as_str().to_ascii_lowercase())
}

/// What a refused `ensure` or bind of the activation comes to.
fn refused(policy: &PolicyId, e: &OpError) -> DefaultOutcome {
    let blocked = |r: &str| DefaultOutcome::Blocked {
        policy: policy.clone(),
        reason: r.to_owned(),
    };
    match e.code {
        Code::PolicyPaused => blocked(blocked::POLICY_PAUSED),
        Code::PolicyCutoff => blocked(blocked::POLICY_CUTOFF),
        Code::TimeUncertain => blocked(blocked::TIME_UNCERTAIN),
        _ if e.reason.as_deref() == Some(reason::NOT_COVERED) => DefaultOutcome::NotCovered {
            policy: policy.clone(),
            reason: reason::NOT_COVERED.to_owned(),
        },
        _ => DefaultOutcome::Failed {
            policy: Some(policy.clone()),
            reason: reason_of(e),
        },
    }
}

/// A fresh internal request ID (`m05-default-<32 hex>`).
fn fresh_request_id() -> Result<RequestId, OpError> {
    let (a, b) = (crate::ids::random_u64()?, crate::ids::random_u64()?);
    RequestId::parse(&format!("m05-default-{a:016x}{b:016x}"))
        .map_err(|_| internal("the internal request ID is not a valid token"))
}

/// ⟨M05⟩ The work an admitted internal default `ensure` resolved to: `spec` with its
/// stored [`Resolution`] overlaid (personal context, the covered pairs and capabilities,
/// [`Route::CoveredOnly`]). `None` — the pipeline then refuses the request, as any
/// unreadable one — when the key is present but unreadable, not covered-only, names a
/// workspace, or sits beside a `context`. Every other request is returned unchanged.
pub(super) fn overlay(
    mut spec: super::WorkSpec,
    stored: &serde_json::Value,
) -> Option<super::WorkSpec> {
    let Some(value) = stored.get(DEFAULT_KEY) else {
        return Some(spec);
    };
    let r: Resolution = serde_json::from_value(value.clone()).ok()?;
    let has_context = stored.get("context").is_some_and(|v| !v.is_null());
    if r.route != Route::CoveredOnly || r.workspace.is_some() || has_context {
        return None;
    }
    spec.profile = Some(r.profile.clone());
    spec.profile_revision = Some(r.profile_revision);
    spec.pairs = r.pairs.clone();
    spec.context = PolicyContext::Personal;
    spec.m05 = Some(Box::new(r));
    Some(spec)
}

/// ⟨M05⟩ Ruling I-2, in the attended `decide` transaction that applies a
/// `create {default: true}`: each of its environments without a default-profile
/// preference gets the policy's profile; an existing preference is kept. A preference
/// only (ADR-0011 §5.1): no binding, grant or generation is touched (R-AU-03).
pub(super) fn default_profile_on_create(
    tx: &mut Txn<'_>,
    profile: &ProfileId,
    environments: &BTreeSet<EnvironmentId>,
) -> heimdall_store::Result<()> {
    for e in environments {
        if tx.default_profile(e)?.is_none() {
            tx.set_default_profile(e, profile)?;
        }
    }
    Ok(())
}

impl Operations {
    /// The plan of `environment`'s default activation, in one transaction.
    async fn default_plan(&self, environment: &EnvironmentId) -> Result<Planned, OpError> {
        let gate = self.inner.timegate.in_txn();
        let env = environment.clone();
        self.write(move |tx, _| {
            let now = gate.check(tx)?.ok().map(|s| s.wall());
            plan_in(tx, &env, now)
        })
        .await?
    }

    /// ⟨M05⟩ U5: the state of `environment`'s default activation (module docs), read in
    /// one transaction; nothing is written. The runtime's identities path answers
    /// [`DefaultState::Settled`] at once and starts (or joins) an activation only for
    /// [`DefaultState::Needed`].
    ///
    /// # Errors
    /// `STATE_UNAVAILABLE` (store).
    pub async fn default_activation_state(
        &self,
        environment: &EnvironmentId,
    ) -> Result<DefaultState, OpError> {
        Ok(match self.default_plan(environment).await? {
            Planned::Settled(o) => DefaultState::Settled(o),
            Planned::Act(p) => match p.step {
                Step::Active { work, binding } => DefaultState::Settled(DefaultOutcome::Active {
                    policy: p.policy.id,
                    work_id: work,
                    binding,
                }),
                Step::Bind { .. } | Step::Work(_) => DefaultState::Needed(p.basis),
            },
        })
    }

    /// ⟨M05⟩ U5: activate `environment`'s default personal policy's covered scope for
    /// ordinary `ssh` (module docs), as `owner` (the runtime's owner principal; unattended,
    /// so never a decision), the launch bind naming `executable` (an absolute path; the
    /// ordinary client's, informational: no holder is registered). Covered-or-nothing;
    /// never creates a decision record. On success it records one `activated` event.
    /// Every refusal is an outcome, never an error.
    pub async fn activate_default(
        &self,
        owner: &CallerContext,
        environment: &EnvironmentId,
        executable: &str,
    ) -> DefaultOutcome {
        let caller = Caller::unattended(owner.clone());
        let mut known: Option<PolicyId> = None;
        let failed = |policy: Option<PolicyId>, e: &OpError| DefaultOutcome::Failed {
            policy,
            reason: reason_of(e),
        };
        for _ in 0..MAX_ROUNDS {
            let plan = match self.default_plan(environment).await {
                Ok(Planned::Settled(o)) => return o,
                Ok(Planned::Act(p)) => *p,
                Err(e) => return failed(known, &e),
            };
            known = Some(plan.policy.id.clone());
            match &plan.step {
                Step::Active { work, binding } => {
                    return DefaultOutcome::Active {
                        policy: plan.policy.id.clone(),
                        work_id: work.clone(),
                        binding: binding.clone(),
                    };
                }
                Step::Work(work) => {
                    // New work; the next round binds it (and re-checks the blocks first).
                    if let Err(e) = self.default_ensure(&caller, environment, &plan, work).await {
                        return refused(&plan.policy.id, &e);
                    }
                }
                Step::Bind { work, binding } => {
                    return match self.default_bind(&caller, binding, executable).await {
                        Ok(()) => {
                            let _ = self
                                .record_activation_event(ActivationEventPayload {
                                    kind: ActivationEventKind::Activated,
                                    environment_id: environment.clone(),
                                    policy_id: Some(plan.policy.id.clone()),
                                    workspace_id: None,
                                    reason: None,
                                })
                                .await;
                            DefaultOutcome::Activated {
                                policy: plan.policy.id.clone(),
                                work_id: work.clone(),
                                binding: binding.clone(),
                            }
                        }
                        Err(e) => refused(&plan.policy.id, &e),
                    };
                }
            }
        }
        DefaultOutcome::Failed {
            policy: known,
            reason: "activation_unsettled".to_owned(),
        }
    }

    /// The internal covered-only `ensure` of `plan`'s new work (module docs). Returns once
    /// it settled (or the bounded wait ended, `ACCEPTED`: the work continues).
    async fn default_ensure(
        &self,
        caller: &Caller,
        environment: &EnvironmentId,
        plan: &Plan,
        work: &WorkId,
    ) -> Result<(), OpError> {
        let own = self.environment().clone();
        let max_wait = self.inner.config.limits.max_wait;
        let req = EnsureRequest {
            profile: Some(plan.policy.profile.clone()),
            profile_revision: Some(plan.profile_revision),
            scope: plan.pairs.clone(),
            environment: (*environment != own).then(|| environment.clone()),
            work_id: work.clone(),
            until: None,
            required_capabilities: RequiredCapabilities::default(),
            request_id: fresh_request_id()?,
            interaction: InteractionMode::Interactive,
            wait: WaitMode::Sync {
                timeout_ms: u64::try_from(max_wait.as_millis()).unwrap_or(u64::MAX),
            },
            connection: None,
            context: None,
            covered_only: false,
        };
        // `ensure`'s own admission checks: the managed set and a stopped work ID, before
        // any record.
        {
            let (own2, target, w) = (own.clone(), environment.clone(), work.clone());
            self.write(move |tx, _| {
                if let Err(e) = crate::environments::admit(tx, &own2, &target)? {
                    return Ok(Err(e));
                }
                Ok(stop_m05::work_stop_refusal(tx, &target, &w)?.map_or(Ok(()), Err))
            })
            .await??;
        }
        self.ensure_precheck(&req).await?;
        let hash = compute_hash(
            OperationKind::Ensure,
            &HashInput {
                environment,
                profile: req.profile.as_ref(),
                profile_revision: req.profile_revision,
                scope: &req.scope,
                deadline_intent: None,
                work_id: Some(&req.work_id),
                required_capabilities: &req.required_capabilities,
                parent_binding: None,
                extra: serde_json::json!({
                    "m05_default_activation": true,
                    "ensure": pair_mechanism_m03::ensure_hash_extra(&req, None),
                }),
            },
        )
        .map_err(|_| internal("the default activation request cannot be canonicalized"))?;
        let resolution = Resolution {
            workspace: None,
            profile: plan.policy.profile.clone(),
            profile_revision: plan.profile_revision,
            pairs: plan.pairs.clone(),
            capabilities: Some(plan.capabilities.clone()),
            access_digest: None,
            route: Route::CoveredOnly,
            background_work: false,
            uncovered: BTreeSet::new(),
        };
        let mut request = serde_json::to_value(Request::Ensure(req.clone()))
            .map_err(|_| internal("the request is not serializable"))?;
        let stored = serde_json::to_value(&resolution)
            .map_err(|_| internal("the resolution is not serializable"))?;
        match request.as_object_mut() {
            Some(map) => {
                map.insert(DEFAULT_KEY.to_owned(), stored);
            }
            None => return Err(internal("the request is not an object")),
        }
        self.run_work_json(
            caller,
            OperationKind::Ensure,
            request,
            hash,
            req.request_id.clone(),
            req.wait,
            environment.clone(),
        )
        .await
        .map(|_| ())
    }

    /// The holder-less launch bind that claims (or joins) the binding's slots.
    async fn default_bind(
        &self,
        caller: &Caller,
        binding: &BindingId,
        executable: &str,
    ) -> Result<(), OpError> {
        self.bind(
            caller,
            BindRequest {
                binding_id: binding.clone(),
                form: BindForm::Launch(LaunchBinding {
                    executable: executable.to_owned(),
                    holder: None,
                }),
                request_id: fresh_request_id()?,
            },
        )
        .await
        .map(|_| ())
    }

    /// ⟨M05⟩ U5: append one `EventType::Activation` event (ADR-0006 §17 item 8). The
    /// runtime rate-limits `blocked` and `not_covered` (at most one per policy, kind and
    /// reason per hour) before it calls this; [`Self::activate_default`] records
    /// `activated` itself.
    ///
    /// # Errors
    /// `STATE_UNAVAILABLE` (store).
    pub async fn record_activation_event(
        &self,
        payload: ActivationEventPayload,
    ) -> Result<(), OpError> {
        let value = serde_json::to_value(&payload)
            .map_err(|_| internal("the activation event is not serializable"))?;
        let res = payload.policy_id.as_ref().map(|p| resource("policy", p));
        self.write(move |tx, emit| emit.event(tx, EventType::Activation, None, res, value))
            .await
    }
}
