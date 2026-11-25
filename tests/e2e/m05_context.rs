//! ⟨M05⟩ U4 journeys: `ensure` with `context` in process, through the production
//! `Operations` over an in-memory store, with the runtime's **real** workspace observer
//! (`workspace_observe::RealWorkspaceProbe`) over scratch Git repositories created per run
//! (`heimdall_testkit::workspace`; no owner repository, key or configuration is read).
//!
//! * `a02_trusted_week_zero_same_authority_prompts`: first trust = 1 decision; then
//!   re-entry, three concurrent "shells" (`covered_only`, distinct work IDs), re-issue
//!   within a grant, expiry and re-entry under fresh work IDs: 0 further decision records
//!   (counted from the store). The hook, `ssh`/`git` and provider-prompt rows of A02 are
//!   added in waves 3–4 (the shell integration and ordinary-`ssh` activation).
//! * `a04_edits_branches_and_added_destination`: source edits and branch switches keeping
//!   the access digest → 0 decisions; an added destination → exactly 1 decision showing
//!   only that pair (shared by a concurrent requester); the waiting request resumes when
//!   it is approved; two live bindings' pins unchanged throughout.
//! * `a18_copy_clone_worktree_symlink_move_submodule`: ADR-0011 §2.3's table end to end.
//! * `covered_only_creates_no_decision_when_uncovered`: ruling 3's server half.
//! * `mixed_groups_share_one_work_id_and_later_groups_are_capped`: ruling 7's example.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
use heimdall_contract::envelope::{MechanismGroup, reason};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, DeviceId, EnvironmentId, IdentityId, PolicyId,
    ProfileId, RequestId, WorkId, WorkspaceId,
};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{
    DecideRequest, DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest,
    ExistingConnectionsPolicy, InspectRequest, InspectSubject, InteractionMode,
    NewAuthenticationExpiry, ObserveRequest, PolicyAction, RefreshDependency, RequiredCapabilities,
    RevocationStatus, Verdict, WaitMode, WorkloadIsolation,
};
use heimdall_contract::trust::{ContextKind, WorkContext, WorkspaceMatchView, WorkspaceView};
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::catalog::{
    DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource, InteractionProfile,
};
use heimdall_domain::decision::DecisionKind;
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock as _, SyncStatus, TimePolicy};
use heimdall_domain::workspace::BindingContext;
use heimdall_runtime::workspace_observe::RealWorkspaceProbe;
use heimdall_store::Store;
use heimdall_testkit::workspace::{Scratch, manifest, write_manifest};
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock};

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-18T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn dev() -> ProfileId {
    ProfileId::parse("dev").unwrap()
}

fn pair(d: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

fn pairs(ds: &[&str]) -> BTreeSet<AccessPair> {
    ds.iter().map(|d| pair(d)).collect()
}

fn ssh() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn owner_ctx() -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
        remote_client: None,
    }
}

/// The person at a terminal (`run`, `ensure` in the foreground; decides).
fn attended() -> Caller {
    Caller {
        context: owner_ctx(),
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

/// A background trigger (the shell hook): unattended, never prompts.
fn background() -> Caller {
    Caller::unattended(owner_ctx())
}

fn descriptor(mechanism: &str) -> AdapterDescriptor {
    AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: mechanism.into(),
            instance: "fixture-1".into(),
        },
        capabilities: ssh(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: EnforcementEvidence {
            report: Enforcement {
                destination_scope: DestinationScopeEnforcement::ClientRouting,
                new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
                workload_isolation: WorkloadIsolation::SharedOsUser,
                existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
                revocation: RevocationStatus::LocalApplied,
                identity_selection: None,
                new_signing_expiry: None,
                owned_multiplexing: None,
                remote_processes: None,
                unmanaged_connections: None,
                issuer_isolation: None,
                ordinary_aliases: None,
                owner_functions: None,
            },
            evidence: Vec::new(),
        },
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: t0()
            .checked_add(jiff::SignedDuration::from_hours(48))
            .unwrap(),
        offline_until: t0()
            .checked_add(jiff::SignedDuration::from_hours(48))
            .unwrap(),
        refresh_dependency: RefreshDependency::None,
        enforcement: EnforcementEvidence::unknown(),
        credential_ref: "fixture-credential".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    ops: Operations,
    s: Scratch,
}

/// The production `Operations` over `store` (a restart is a second call), without a
/// workspace probe.
async fn start(store: &Arc<Store>, clock: &Arc<VirtualClock>, mechanisms: &[&str]) -> Operations {
    let adapters = mechanisms
        .iter()
        .map(|m| {
            FakeCredentialAdapter::new(descriptor(m), vec![FakeStep::Prepare(outcome())])
                as Arc<dyn CredentialAdapter>
        })
        .collect();
    start_with(store, clock, adapters).await
}

/// [`start`] with the caller's adapters (a test that holds a preparation keeps its fake).
async fn start_with(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    adapters: Vec<Arc<dyn CredentialAdapter>>,
) -> Operations {
    Operations::start(OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters,
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap()
}

/// A runtime with profile `dev` (h1..h4 as `deploy`), the environment with automatic
/// activation off (a first trust turns it on), no standing policy unless `personal`
/// names the pairs of a personal one, and the real workspace observer.
async fn world(personal: Option<&[&str]>, mechanisms: &[&str]) -> World {
    let adapters = mechanisms
        .iter()
        .map(|m| {
            FakeCredentialAdapter::new(descriptor(m), vec![FakeStep::Prepare(outcome())])
                as Arc<dyn CredentialAdapter>
        })
        .collect();
    world_with(personal, adapters).await
}

/// [`world`] with the caller's adapters.
async fn world_with(personal: Option<&[&str]>, adapters: Vec<Arc<dyn CredentialAdapter>>) -> World {
    let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: personal.is_some(),
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            tx.upsert_profile(&ProfileDefinition {
                id: dev(),
                revision: 1,
                scope: Scope {
                    pairs: pairs(&["h1", "h2", "h3", "h4"]),
                    capabilities: ssh(),
                },
                label: None,
            })?;
            if let Some(p) = personal {
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("pol_personal").unwrap(),
                        revision: PolicyRevision(1),
                        profile: dev(),
                        workspace: None,
                        scope: Scope {
                            pairs: pairs(p),
                            capabilities: ssh(),
                        },
                        environments: [env_id()].into_iter().collect(),
                        max_window: 12 * HOUR,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: Default::default(),
                        connection: Default::default(),
                        default: true,
                    },
                    false,
                )?;
            }
            Ok(())
        })
        .unwrap();
    let clock = VirtualClock::at(t0());
    let ops = start_with(&store, &clock, adapters).await;
    assert!(ops.set_workspace_probe(Arc::new(RealWorkspaceProbe)));
    World {
        store,
        clock,
        ops,
        s: Scratch::new().unwrap(),
    }
}

impl World {
    fn decisions(&self) -> u64 {
        self.store
            .transaction(|tx| tx.table_counts())
            .unwrap()
            .decisions
    }

    fn grants(&self) -> u64 {
        self.store
            .transaction(|tx| tx.table_counts())
            .unwrap()
            .grants
    }

    fn kind_of(&self, d: &DecisionId) -> DecisionKind {
        self.store
            .transaction(|tx| tx.decision(d))
            .unwrap()
            .unwrap()
            .kind
    }

    async fn decide(&self, d: &DecisionId, verdict: Verdict) {
        let r = self
            .ops
            .decide(
                &attended(),
                DecideRequest {
                    decision_id: d.clone(),
                    verdict,
                },
            )
            .await;
        assert!(r.is_ok(), "decide {d}: {:?}", r.err());
    }

    async fn inspect(&self, cwd: &Path) -> WorkspaceView {
        let r = self
            .ops
            .inspect(
                &attended(),
                InspectRequest {
                    subject: InspectSubject::Workspace,
                    preview: None,
                    cwd: Some(cwd.to_str().unwrap().to_owned()),
                    redact: false,
                    select: None,
                    page: None,
                },
            )
            .await
            .unwrap();
        serde_json::from_value(r.data).unwrap()
    }

    /// Trust `repo` the way a person does: a foreground `ensure` raises the trust
    /// decision, the owner approves it, and the same request then activates. Returns the
    /// workspace and the activation.
    async fn trust(&self, repo: &Path, rid: &str) -> (WorkspaceId, EnsureData) {
        let req = ctx_req(repo, rid, &format!("work-{rid}"));
        let e = self.ops.ensure(&attended(), req.clone()).await.unwrap_err();
        assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
        assert_eq!(e.reason.as_deref(), Some(reason::WORKSPACE_UNTRUSTED));
        assert!(e.operation_id.is_none(), "nothing is admitted before trust");
        let d = decision_of(&e);
        assert!(matches!(
            self.kind_of(&d),
            DecisionKind::TrustWorkspace { .. }
        ));
        self.decide(&d, Verdict::Approve).await;
        let done = ok(self.ops.ensure(&attended(), req).await);
        let ctx = done.context.clone().expect("a context report");
        assert_eq!(ctx.kind, ContextKind::Workspace);
        (ctx.workspace_id.clone().unwrap(), done)
    }
}

fn ctx_req(cwd: &Path, rid: &str, work: &str) -> EnsureRequest {
    EnsureRequest {
        profile: None,
        profile_revision: None,
        scope: BTreeSet::new(),
        environment: None,
        work_id: WorkId::parse(work).unwrap(),
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(rid).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::default(),
        connection: None,
        context: Some(WorkContext {
            cwd: cwd.to_str().unwrap().to_owned(),
        }),
        covered_only: false,
        pair_issuers: Vec::new(),
    }
}

fn shell_req(cwd: &Path, rid: &str, work: &str) -> EnsureRequest {
    EnsureRequest {
        covered_only: true,
        pair_issuers: Vec::new(),
        ..ctx_req(cwd, rid, work)
    }
}

fn ok(r: OpResult<EnsureData>) -> EnsureData {
    match r {
        Ok(c) => c.data,
        Err(e) => panic!("{:?} {:?}: {}", e.code, e.reason, e.message),
    }
}

fn decision_of(e: &OpError) -> DecisionId {
    DecisionId::parse(
        e.next
            .decision_ref
            .as_deref()
            .expect("a decision reference"),
    )
    .unwrap()
}

// =================================================================================
// A02: zero additional same-authority prompts after the first trust
// =================================================================================

/// A02 (server rows): first trust = 1 decision; re-entry, three concurrent shells,
/// re-issue within a grant, expiry and re-entry under fresh work IDs = 0 further decision
/// records. (The hook, `ssh`/`git` and provider-prompt rows are added in waves 3–4.)
#[tokio::test]
async fn a02_trusted_week_zero_same_authority_prompts() {
    let w = world(None, &["fake_agent"]).await;
    let repo =
        w.s.init_repo(
            "infra",
            Some(&manifest(
                "example-infrastructure",
                "dev",
                &["h1:deploy", "h2:deploy"],
                false,
            )),
        )
        .unwrap();
    std::fs::create_dir_all(repo.join("modules/net")).unwrap();
    assert_eq!(w.decisions(), 0);

    // First trust: exactly one decision record.
    let (ws, first) = w.trust(&repo.join("modules/net"), "first").await;
    assert_eq!(w.decisions(), 1, "first trust = 1 decision");
    assert_eq!(
        first.context.as_ref().unwrap().workspace_id.as_ref(),
        Some(&ws)
    );
    assert!(first.context.as_ref().unwrap().policy_id.is_some());

    // Re-entry from another directory of the workspace, under a fresh work ID.
    let again = ok(w
        .ops
        .ensure(&attended(), ctx_req(&repo, "reentry", "work-reentry"))
        .await);
    assert_eq!(
        again.context.as_ref().unwrap().workspace_id,
        Some(ws.clone())
    );

    // Three concurrent shells (covered_only, distinct work IDs).
    let mut tasks = Vec::new();
    for n in 1..=3 {
        let ops = w.ops.clone();
        let req = shell_req(&repo, &format!("shell-{n}"), &format!("shell-501-1-{n}"));
        tasks.push(tokio::spawn(
            async move { ops.ensure(&background(), req).await },
        ));
    }
    for t in tasks {
        let d = ok(t.await.unwrap());
        assert!(d.uncovered.is_empty());
        assert_eq!(d.context.unwrap().kind, ContextKind::Workspace);
    }

    // Re-issue within a grant: the same request (a replay) and the same work again.
    let replay = ok(w
        .ops
        .ensure(&attended(), ctx_req(&repo, "reentry", "work-reentry"))
        .await);
    assert_eq!(replay.binding_id, again.binding_id, "a replay converges");
    ok(w.ops
        .ensure(&attended(), ctx_req(&repo, "reentry-2", "work-reentry"))
        .await);
    assert_eq!(w.decisions(), 1);

    // Expiry, then re-entry under fresh work IDs (spec §6.1: new work, fresh grant).
    w.clock.advance(13 * HOUR);
    w.ops.tick().await.unwrap();
    let expired = w
        .ops
        .ensure(&attended(), ctx_req(&repo, "late-old", "work-reentry"))
        .await
        .unwrap_err();
    assert_eq!(
        expired.code,
        Code::CredentialExpired,
        "an expired work ID stays expired"
    );
    let later = ok(w
        .ops
        .ensure(&attended(), ctx_req(&repo, "late", "work-next-day"))
        .await);
    assert!(
        later.expires_at
            > t0()
                .checked_add(jiff::SignedDuration::from_hours(13))
                .unwrap()
    );
    ok(w.ops
        .ensure(
            &background(),
            shell_req(&repo, "late-shell", "shell-501-2-1"),
        )
        .await);
    assert_eq!(
        w.decisions(),
        1,
        "after the first trust: 0 further decision records"
    );
}

// =================================================================================
// A04: edits, branches and an added destination
// =================================================================================

/// A04: source edits and branch switches keep the access digest → 0 decisions; an added
/// destination → exactly 1 decision showing only that pair, shared by a concurrent
/// requester; approving it resumes the waiting request; two live bindings' pins are
/// unchanged throughout.
#[tokio::test]
async fn a04_edits_branches_and_added_destination() {
    let w = world(None, &["fake_agent"]).await;
    let text = manifest("app", "dev", &["h1:deploy", "h2:deploy"], false);
    let repo = w.s.init_repo("app", Some(&text)).unwrap();
    let (ws, first) = w.trust(&repo, "trust").await;
    let shell = ok(w
        .ops
        .ensure(&background(), shell_req(&repo, "shell", "shell-1"))
        .await);
    let pins = |w: &World| {
        w.store
            .transaction(|tx| {
                let mut out = Vec::new();
                for b in [&first.binding_id, &shell.binding_id] {
                    out.push((tx.binding(b)?, tx.binding_context(b)?));
                }
                Ok(out)
            })
            .unwrap()
    };
    let before = pins(&w);
    assert_eq!(w.decisions(), 1);

    // Source edits and a branch switch: the access digest is unchanged.
    std::fs::write(repo.join("main.tf"), b"resource {}\n").unwrap();
    w.s.commit_all(&repo, "edit").unwrap();
    w.s.git(&repo, &["checkout", "-q", "-b", "feature"])
        .unwrap();
    std::fs::write(repo.join("main.tf"), b"resource { changed }\n").unwrap();
    w.s.commit_all(&repo, "feature edit").unwrap();
    for (rid, work) in [("edit-1", "work-edit-1"), ("edit-2", "work-edit-2")] {
        let d = ok(w.ops.ensure(&attended(), ctx_req(&repo, rid, work)).await);
        assert_eq!(d.context.unwrap().workspace_id, Some(ws.clone()));
    }
    assert_eq!(w.decisions(), 1, "edits and branch switches: 0 decisions");

    // An added destination: exactly one decision, showing only the added pair.
    write_manifest(
        &repo,
        &manifest(
            "app",
            "dev",
            &["h1:deploy", "h2:deploy", "h3:deploy"],
            false,
        ),
    )
    .unwrap();
    w.s.commit_all(&repo, "add h3").unwrap();
    let mut tasks = Vec::new();
    for n in 0..2 {
        let ops = w.ops.clone();
        let req = ctx_req(&repo, &format!("added-{n}"), &format!("work-added-{n}"));
        tasks.push(tokio::spawn(
            async move { ops.ensure(&attended(), req).await },
        ));
    }
    let mut refs = BTreeSet::new();
    let mut waiting = Vec::new();
    for t in tasks {
        let e = t.await.unwrap().unwrap_err();
        assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
        refs.insert(decision_of(&e));
        waiting.push(e.operation_id.clone().expect("the request waits"));
    }
    assert_eq!(refs.len(), 1, "concurrent requesters share one record");
    assert_eq!(w.decisions(), 2, "an added destination: exactly 1 decision");
    let d = refs.into_iter().next().unwrap();
    match w.kind_of(&d) {
        DecisionKind::WidenPolicy {
            action:
                PolicyAction::ExtendScope {
                    pairs: added,
                    capabilities,
                    environments,
                    background_work,
                    ..
                },
        } => {
            assert_eq!(added, pairs(&["h3"]), "only the added pair");
            assert!(capabilities.is_empty() && environments.is_empty());
            assert_eq!(background_work, None);
        }
        other => panic!("{other:?}"),
    }
    // Background activation meanwhile: the covered pairs, the added one reported.
    let bg = ok(w
        .ops
        .ensure(&background(), shell_req(&repo, "shell-2", "shell-2"))
        .await);
    assert_eq!(bg.uncovered, vec![pair("h3")]);
    assert_eq!(w.decisions(), 2);
    assert_eq!(pins(&w), before, "live bindings keep their pins");

    // Approval: the waiting requests resume with no further decision.
    w.decide(&d, Verdict::Approve).await;
    for op in &waiting {
        let seen = w
            .ops
            .observe(
                &attended(),
                ObserveRequest::Operation {
                    operation_id: op.clone(),
                    wait_ms: Some(10_000),
                },
            )
            .await
            .unwrap();
        assert_eq!(seen.state, OperationState::Succeeded, "{op}");
    }
    // The resumed request's result reports the workspace policy at its new revision.
    let resumed = w
        .ops
        .ensure(&attended(), ctx_req(&repo, "added-0", "work-added-0"))
        .await
        .unwrap()
        .data
        .context
        .unwrap();
    assert_eq!(resumed.kind, ContextKind::Workspace);
    assert!(resumed.policy_id.is_some());
    assert_eq!(resumed.policy_revision, Some(2));
    let all = ok(w
        .ops
        .ensure(&attended(), ctx_req(&repo, "after", "work-after"))
        .await);
    assert_eq!(all.context.unwrap().workspace_id, Some(ws));
    assert_eq!(w.decisions(), 2);
    assert_eq!(pins(&w), before, "live bindings keep their pins");
}

/// "Restart never re-probes an admitted operation": a context request admitted and
/// waiting on its extension survives a restart into a runtime that has **no** workspace
/// observer at all; approving the extension resumes it, and it completes under exactly
/// the resolution its admission stored (its workspace context in the result).
#[tokio::test]
async fn restart_never_reprobes_an_admitted_context_request() {
    let mut w = world(None, &["fake_agent"]).await;
    let repo =
        w.s.init_repo("app", Some(&manifest("app", "dev", &["h1:deploy"], false)))
            .unwrap();
    let (ws, _) = w.trust(&repo, "trust").await;
    write_manifest(
        &repo,
        &manifest("app", "dev", &["h1:deploy", "h2:deploy"], false),
    )
    .unwrap();
    let e = w
        .ops
        .ensure(&attended(), ctx_req(&repo, "wait", "work-wait"))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let op = e.operation_id.clone().unwrap();
    let d = decision_of(&e);
    // The restarted runtime has no observer: any probe of the admitted request would be
    // refused `driver_unavailable`.
    w.ops = start(&w.store, &w.clock, &["fake_agent"]).await;
    w.decide(&d, Verdict::Approve).await;
    let seen = w
        .ops
        .observe(
            &attended(),
            ObserveRequest::Operation {
                operation_id: op.clone(),
                wait_ms: Some(10_000),
            },
        )
        .await
        .unwrap();
    assert_eq!(seen.state, OperationState::Succeeded);
    let row = w
        .store
        .transaction(|tx| tx.operation(&op))
        .unwrap()
        .unwrap();
    let data: EnsureData = serde_json::from_value(row.result.unwrap()).unwrap();
    let ctx = data.context.unwrap();
    assert_eq!(ctx.kind, ContextKind::Workspace);
    assert_eq!(ctx.workspace_id, Some(ws));
    assert_eq!(w.decisions(), 2, "the trust and the one extension");
}

// =================================================================================
// ADR-0006 revision 5.2 item 21: the server-built trust proposal
// =================================================================================

/// `inspect workspace`'s `proposal` is exactly what `trust_workspace` accepts (the client
/// never reads the manifest, ADR-0011 §2.2): a request built only from the inspect answer
/// raises the trust decision, whose recorded action is that proposal; a request built from
/// an answer that went stale (the manifest changed after the inspect) is refused
/// `USAGE_ERROR` with nothing written. A manifest-less root, a root whose manifest names an
/// unknown profile and a non-workspace directory carry no proposal.
#[tokio::test]
async fn the_inspected_proposal_is_what_trust_workspace_accepts() {
    let w = world(None, &["fake_agent"]).await;
    let repo =
        w.s.init_repo(
            "infra",
            Some(&manifest("infra", "dev", &["h1:deploy"], true)),
        )
        .unwrap();
    let cwd = repo.to_str().unwrap().to_owned();
    let request = |v: &WorkspaceView| PolicyAction::TrustWorkspace {
        cwd: cwd.clone(),
        access_digest: v.access_digest.clone().unwrap_or_default(),
        proposal: v
            .proposal
            .clone()
            .expect("a manifest root carries a proposal"),
    };

    let view = w.inspect(&repo).await;
    assert_eq!(view.matched, WorkspaceMatchView::Untrusted);
    let proposal = view.proposal.clone().unwrap();
    assert_eq!(proposal.profile, dev());
    assert_eq!(proposal.pairs.len(), 1);
    assert!(proposal.background_work);
    assert!(view.access_digest.is_some());

    // The manifest changes after the inspect: the stale request is refused, nothing written.
    write_manifest(
        &repo,
        &manifest("infra", "dev", &["h1:deploy", "h2:deploy"], true),
    )
    .unwrap();
    let before = w.store.transaction(|tx| tx.table_counts()).unwrap();
    let stale = w.ops.policy(&attended(), request(&view)).await.unwrap_err();
    assert_eq!(stale.code, Code::UsageError, "{stale:?}");
    assert!(
        stale.message.contains("changed since it was reviewed"),
        "{stale:?}"
    );
    assert_eq!(
        w.store.transaction(|tx| tx.table_counts()).unwrap(),
        before,
        "a stale proposal writes nothing"
    );
    assert_eq!(w.decisions(), 0);

    // A fresh inspect: its proposal differs, and a request built only from it is accepted.
    let fresh = w.inspect(&repo).await;
    let fresh_proposal = fresh.proposal.clone().unwrap();
    assert_ne!(fresh_proposal, proposal);
    assert_eq!(fresh_proposal.pairs.len(), 2);
    let raised = w
        .ops
        .policy(&attended(), request(&fresh))
        .await
        .unwrap_err();
    assert_eq!(raised.code, Code::ApprovalRequired, "{raised:?}");
    assert_eq!(w.decisions(), 1);
    let DecisionKind::TrustWorkspace { action, .. } = w.kind_of(&decision_of(&raised)) else {
        panic!("a trust decision");
    };
    let PolicyAction::TrustWorkspace {
        proposal: recorded, ..
    } = action
    else {
        panic!("a trust action");
    };
    assert_eq!(
        recorded, fresh_proposal,
        "the record is the inspected proposal"
    );

    // No proposal: no manifest, an unknown profile, no workspace.
    let bare = w.s.init_repo("bare", None).unwrap();
    let v = w.inspect(&bare).await;
    assert_eq!(v.matched, WorkspaceMatchView::Untrusted);
    assert!(v.proposal.is_none() && v.access_digest.is_none());
    let other =
        w.s.init_repo("other", Some(&manifest("other", "nosuch", &[], false)))
            .unwrap();
    let v = w.inspect(&other).await;
    assert!(v.access_digest.is_some(), "the manifest was read");
    assert!(v.proposal.is_none(), "an unknown profile has no proposal");
    let outside = w.s.path("not-a-workspace");
    std::fs::create_dir_all(&outside).unwrap();
    let v = w.inspect(&outside).await;
    assert_eq!(v.matched, WorkspaceMatchView::None);
    assert!(v.proposal.is_none());
}

// =================================================================================
// A18: copies, clones, worktrees, symlinks, moves and submodules (ADR-0011 §2.3)
// =================================================================================

/// A18: the same checkout and a symlinked path are trusted; a `cp -R` copy and a `git
/// clone` are untrusted; a verified `git worktree add` is a member (0 decisions); a copied
/// worktree is untrusted; a same-filesystem `mv` and a re-clone at the same path are
/// ambiguous (one `ReconcileWorkspace` each, no workspace grant); a submodule is its own
/// workspace.
#[tokio::test]
async fn a18_copy_clone_worktree_symlink_move_submodule() {
    let w = world(None, &["fake_agent"]).await;
    let text = manifest("orig", "dev", &["h1:deploy"], false);
    let upstream = w.s.init_repo("upstream", Some(&text)).unwrap();
    let orig = w.s.clone_repo(&upstream, "orig").unwrap();
    let (ws, _) = w.trust(&orig, "trust").await;
    let trusted = w.decisions();
    assert_eq!(trusted, 1);

    // Same checkout, and through a symlinked path: trusted.
    std::fs::create_dir_all(orig.join("src")).unwrap();
    let view = w.inspect(&orig.join("src")).await;
    assert_eq!(view.matched, WorkspaceMatchView::Trusted);
    assert_eq!(view.workspace_id, Some(ws.clone()));
    assert!(view.policy_id.is_some() && view.access_digest.is_some());
    let link = w.s.symlink_dir(&orig, "orig-link").unwrap();
    let view = w.inspect(&link.join("src")).await;
    assert_eq!(view.matched, WorkspaceMatchView::Trusted);
    assert_eq!(view.root.as_deref(), orig.to_str(), "the canonical root");

    // A `cp -R` copy and a `git clone`: untrusted.
    let copy = w.s.copy_tree(&orig, "orig-copy").unwrap();
    assert_eq!(
        w.inspect(&copy).await.matched,
        WorkspaceMatchView::Untrusted
    );
    let clone = w.s.clone_repo(&upstream, "orig-clone").unwrap();
    assert_eq!(
        w.inspect(&clone).await.matched,
        WorkspaceMatchView::Untrusted
    );

    // A verified linked worktree: a member, activating with no decision.
    let wt = w.s.worktree_add(&orig, "orig-wt", "wt-branch").unwrap();
    let view = w.inspect(&wt).await;
    assert_eq!(view.matched, WorkspaceMatchView::Member);
    assert_eq!(view.workspace_id, Some(ws.clone()));
    let member = ok(w
        .ops
        .ensure(&attended(), ctx_req(&wt, "member", "work-member"))
        .await);
    assert_eq!(member.context.unwrap().workspace_id, Some(ws.clone()));
    assert_eq!(w.decisions(), trusted, "a verified worktree: 0 decisions");

    // A copied worktree: its back-link names the original, so untrusted.
    let wt_copy = w.s.copy_tree(&wt, "orig-wt-copy").unwrap();
    assert_eq!(
        w.inspect(&wt_copy).await.matched,
        WorkspaceMatchView::Untrusted
    );

    // A submodule inside the trusted checkout: its own workspace.
    let sub_src =
        w.s.init_repo(
            "sub-src",
            Some(&manifest("sub", "dev", &["h2:deploy"], false)),
        )
        .unwrap();
    let sub = w.s.add_submodule(&orig, &sub_src, "vendor/sub").unwrap();
    let view = w.inspect(&sub).await;
    assert_eq!(
        view.root.as_deref(),
        sub.to_str(),
        "the submodule is its own root"
    );
    assert_eq!(view.matched, WorkspaceMatchView::Untrusted);
    assert_ne!(view.workspace_id, Some(ws.clone()));

    // A same-filesystem move: ambiguous; one `ReconcileWorkspace`, no workspace grant.
    let grants = w.grants();
    let moved = w.s.move_tree(&orig, "orig-moved").unwrap();
    assert_eq!(
        w.inspect(&moved).await.matched,
        WorkspaceMatchView::Ambiguous
    );
    let e = w
        .ops
        .ensure(&attended(), ctx_req(&moved, "moved", "work-moved"))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    assert_eq!(e.reason.as_deref(), Some(reason::WORKSPACE_AMBIGUOUS));
    assert!(matches!(
        w.kind_of(&decision_of(&e)),
        DecisionKind::ReconcileWorkspace { .. }
    ));
    assert_eq!(w.decisions(), trusted + 1);

    // A re-clone at the original path: ambiguous too (same path, other identity).
    let recloned = w.s.clone_repo(&upstream, "orig").unwrap();
    assert_eq!(
        w.inspect(&recloned).await.matched,
        WorkspaceMatchView::Ambiguous
    );
    let e = w
        .ops
        .ensure(&attended(), ctx_req(&recloned, "recloned", "work-recloned"))
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::WORKSPACE_AMBIGUOUS));
    assert_eq!(w.decisions(), trusted + 2);
    assert_eq!(
        w.grants(),
        grants,
        "an ambiguous checkout gets no workspace grant"
    );
}

// =================================================================================
// Ruling 3: covered_only never creates a decision record
// =================================================================================

/// Ruling 3 (server half): an untrusted manifest and a trusted manifest that adds a
/// pair, asked with `covered_only` → decision rows unchanged; `not_covered` (no decision
/// reference) when nothing is covered, `uncovered` otherwise.
#[tokio::test]
async fn covered_only_creates_no_decision_when_uncovered() {
    // No standing policy: an untrusted manifest has nothing covered.
    let w = world(None, &["fake_agent"]).await;
    let untrusted =
        w.s.init_repo(
            "untrusted",
            Some(&manifest("u", "dev", &["h1:deploy"], true)),
        )
        .unwrap();
    let e = w
        .ops
        .ensure(&background(), shell_req(&untrusted, "bg-1", "shell-1"))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired, "{e:?}");
    assert_eq!(e.reason.as_deref(), Some(reason::NOT_COVERED));
    assert!(e.next.decision_ref.is_none());
    // Even from an attended caller: a background request never asks.
    let e = w
        .ops
        .ensure(&attended(), shell_req(&untrusted, "bg-2", "shell-2"))
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::NOT_COVERED));
    assert_eq!(w.decisions(), 0, "no decision row");

    // A trusted manifest that adds a pair: the covered part activates, the added pair
    // is reported, no decision row.
    let repo =
        w.s.init_repo(
            "trusted",
            Some(&manifest("t", "dev", &["h1:deploy"], false)),
        )
        .unwrap();
    w.trust(&repo, "trust").await;
    let rows = w.decisions();
    write_manifest(
        &repo,
        &manifest("t", "dev", &["h1:deploy", "h4:deploy"], true),
    )
    .unwrap();
    let d = ok(w
        .ops
        .ensure(&background(), shell_req(&repo, "bg-3", "shell-3"))
        .await);
    assert_eq!(d.uncovered, vec![pair("h4")]);
    assert_eq!(d.context.unwrap().kind, ContextKind::Workspace);
    // A manifest asking only for what the policy lacks: nothing covered.
    write_manifest(&repo, &manifest("t", "dev", &["h4:deploy"], false)).unwrap();
    let e = w
        .ops
        .ensure(&background(), shell_req(&repo, "bg-4", "shell-4"))
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::NOT_COVERED));
    assert!(e.next.decision_ref.is_none());
    assert_eq!(w.decisions(), rows, "decision rows unchanged");

    // With a personal policy covering h1 only, an untrusted manifest asking h1 and h2:
    // h1 activates under personal policy, h2 is reported, no decision row.
    let w = world(Some(&["h1"]), &["fake_agent"]).await;
    let repo =
        w.s.init_repo(
            "partial",
            Some(&manifest("p", "dev", &["h1:deploy", "h2:deploy"], false)),
        )
        .unwrap();
    let d = ok(w
        .ops
        .ensure(&background(), shell_req(&repo, "bg-5", "shell-5"))
        .await);
    assert_eq!(d.uncovered, vec![pair("h2")]);
    assert_eq!(d.context.unwrap().kind, ContextKind::Personal);
    assert_eq!(w.decisions(), 0);
}

// =================================================================================
// Ruling 7: one mixed-profile example
// =================================================================================

fn endpoint(locator: &str) -> EndpointRef {
    EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: locator.into(),
    }
}

fn identity(id: [u8; 16], source: IdentitySource, key: &str, fp: &str) -> IdentityRecord {
    IdentityRecord {
        id: IdentityId::from_random_bytes(id),
        revision: 1,
        interaction: InteractionProfile::default_for(&source, key),
        source,
        public_key: key.to_owned(),
        fingerprint: fp.to_owned(),
        label: None,
        adopted_at: t0(),
        updated_at: t0(),
    }
}

fn destination(d: &str, identity: [u8; 16]) -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::parse(d).unwrap(),
        alias: d.into(),
        revision: 1,
        definition: DestinationDefinition::Managed {
            hostname: format!("{d}.example.invalid"),
            port: None,
            account: AccountName::parse("deploy").unwrap(),
            identity: IdentityId::from_random_bytes(identity),
            jump: None,
        },
        label: None,
        updated_at: t0(),
    }
}

/// Ruling 7: a profile whose pairs name two mechanisms is refused `mixed_mechanisms`
/// with `next.groups`; each group re-requested under the same work ID activates as its
/// own binding, and the later group's deadline is at or before the earlier group's.
#[tokio::test]
async fn mixed_groups_share_one_work_id_and_later_groups_are_capped() {
    let w = world(Some(&["h1", "h2"]), &["native_agent", "onepassword"]).await;
    w.store
        .transaction(|tx| {
            tx.upsert_identity(&identity(
                [21; 16],
                IdentitySource::NativeAgent {
                    endpoint: endpoint("/scratch/agent.sock"),
                },
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUwYmZpeHR1cmUAAAAAAAAAAAAAAAAAAAAAAAAA m05",
                "SHA256:m05nativeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ))?;
            tx.upsert_identity(&identity(
                [22; 16],
                IdentitySource::OnePassword { endpoint: None },
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUwYnZhdWx0AAAAAAAAAAAAAAAAAAAAAAAAAAAA m05",
                "SHA256:m05vaultAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ))?;
            tx.upsert_destination(&destination("h1", [21; 16]))?;
            tx.upsert_destination(&destination("h2", [22; 16]))?;
            Ok(())
        })
        .unwrap();
    let req = |rid: &str, scope: BTreeSet<AccessPair>| EnsureRequest {
        profile: Some(dev()),
        scope,
        context: None,
        interaction: InteractionMode::Interactive,
        ..ctx_req(Path::new("/"), rid, "work-mixed")
    };
    let e = w
        .ops
        .ensure(&attended(), req("mixed", pairs(&["h1", "h2"])))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some(reason::MIXED_MECHANISMS));
    let groups = e.next.groups.clone();
    assert_eq!(
        groups,
        vec![
            MechanismGroup {
                mechanism: "native_agent".into(),
                pairs: vec![pair("h1")],
            },
            MechanismGroup {
                mechanism: "onepassword".into(),
                pairs: vec![pair("h2")],
            },
        ]
    );
    // Each group under the same work ID, the second one later.
    let first = ok(w
        .ops
        .ensure(
            &attended(),
            req("group-0", groups[0].pairs.iter().cloned().collect()),
        )
        .await);
    w.clock.advance(HOUR);
    let second = ok(w
        .ops
        .ensure(
            &attended(),
            req("group-1", groups[1].pairs.iter().cloned().collect()),
        )
        .await);
    assert_ne!(first.binding_id, second.binding_id, "one binding per group");
    assert_eq!(first.credential_mechanism, "native_agent");
    assert_eq!(second.credential_mechanism, "onepassword");
    assert!(
        second.expires_at <= first.expires_at,
        "the later group is capped at the earliest group's deadline"
    );
    let now = w.clock.wall();
    assert!(now > t0());
}

/// ⟨Integrator, W2⟩ Equivalent work never coalesces across contexts (ADR-0011 §5.1, §10
/// item 1; `EquivalenceKey::workspace`). A trusted workspace's request is preparing, held
/// by the adapter, when a personal request with the same profile, revision, scope,
/// mechanism and deadline arrives. The personal request gets its own grant, and each
/// binding pins its own context. Before the fix it attached to the workspace grant as a
/// single-flight follower, so a stop, pause or cutoff of the workspace would have ended
/// personal work.
#[tokio::test]
async fn equivalent_work_never_coalesces_across_contexts() {
    let fake =
        FakeCredentialAdapter::new(descriptor("fake_agent"), vec![FakeStep::Prepare(outcome())]);
    let w = world_with(None, vec![fake.clone() as Arc<dyn CredentialAdapter>]).await;
    let repo =
        w.s.init_repo(
            "proj",
            Some(&manifest("p", "dev", &["h1:deploy", "h2:deploy"], false)),
        )
        .unwrap();
    let (ws, _) = w.trust(&repo, "t").await;
    // Then a personal policy covering the same pairs (the owner's own, stored directly: how
    // it was approved is not what this test is about).
    w.store
        .transaction(|tx| {
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol_personal").unwrap(),
                    revision: PolicyRevision(1),
                    profile: dev(),
                    workspace: None,
                    scope: Scope {
                        pairs: pairs(&["h1", "h2"]),
                        capabilities: ssh(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: 12 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                    default: true,
                },
                false,
            )
        })
        .unwrap();

    fake.arm(FakeStep::HangBeforeEffect(outcome()));
    let ops = w.ops.clone();
    let wreq = ctx_req(&repo, "ws-lead", "ws-work");
    let leader = tokio::spawn(async move { ops.ensure(&attended(), wreq).await });
    for _ in 0..1000 {
        if fake.hangs_entered() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(fake.hangs_entered(), 1, "the workspace preparation is held");

    let personal = EnsureRequest {
        profile: Some(dev()),
        scope: pairs(&["h1", "h2"]),
        context: None,
        ..ctx_req(&repo, "personal", "personal-work")
    };
    let ops = w.ops.clone();
    let follower = tokio::spawn(async move { ops.ensure(&attended(), personal).await });
    // Give a would-be follower time to reach the leader's flight.
    tokio::time::sleep(Duration::from_millis(200)).await;
    fake.release_hangs();
    let lead = ok(leader.await.unwrap());
    let pers = ok(follower.await.unwrap());

    assert_eq!(
        lead.context.as_ref().unwrap().workspace_id.as_ref(),
        Some(&ws)
    );
    // A request without `context` keeps its M01–M03 result form (no context report).
    assert!(pers.context.is_none());
    assert_ne!(
        pers.grant_id, lead.grant_id,
        "personal work never attaches to a workspace grant"
    );
    let contexts = w
        .store
        .transaction(|tx| {
            Ok((
                tx.binding_context(&lead.binding_id)?,
                tx.binding_context(&pers.binding_id)?,
            ))
        })
        .unwrap();
    assert_eq!(
        contexts,
        (
            Some(BindingContext::Workspace { workspace: ws }),
            Some(BindingContext::Personal)
        )
    );
}
