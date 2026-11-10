//! M03 wave 0, runtime rows (m03-plan U0b rows 6, 7 (supervisor part), 8, 13, 14,
//! 17, 23, 28; wave-0 verify E7; §5 item 22; `w0_no_reachable_todo`).
//!
//! Everything runs in process over the production `heimdall_app::Operations`, the
//! runtime's `OperationsDispatcher` and `Supervisor`, `Store::open_in_memory`,
//! `testkit::VirtualClock`, `testkit::ScriptedTimeSync` and
//! `testkit::FakeCredentialAdapter`. Every "restart" is an **in-process**
//! reconstruction (a new `Operations::start` over the same store), not
//! process-crash evidence. Store rows the wave-0 production paths never write (an
//! M03 operation, a credential instance, a bounded obligation, a CA) are seeded
//! through the store's own `Txn` methods.
//!
//! Platform notes: the `/proc` parts of row 28 run only on Linux; E7's Windows half
//! compiles everywhere it builds and needs a native Windows run to be meaningful.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::{CaStoreItemDeletion, Limits, OWNER_RECONCILE, RetirementResume};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, IssuanceRef, IssuerError,
    IssuerPort, IssuerStatusSnapshot, LockContinuity, PrepareOutcome,
};
use heimdall_app::reconcile::Backoff;
use heimdall_app::{Attendance, Caller, Operations, OperationsConfig};
use heimdall_contract::canonical::RequestHash;
use heimdall_contract::enrollment::{DisclosureKind, RegistryRef, RegistryResolvedBy};
use heimdall_contract::envelope::{EffectStatus, Envelope};
use heimdall_contract::event::{EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, CaFingerprint, CredentialInstanceId, DecisionId, DestinationId, DeviceId,
    EnrollmentId, EnvironmentId, GrantId, IssuanceId, OperationId, PolicyId, ProfileId, RequestId,
    WorkId,
};
use heimdall_contract::ipc::capability;
use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
use heimdall_contract::managed::{
    ClockMeasurement, DestinationClock, IssuerIsolation, ResidualStatus,
};
use heimdall_contract::request::{
    DecideRequest, DestinationScopeEnforcement, Enforcement, EnsureRequest,
    ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry, RefreshDependency,
    Request, RequiredCapabilities, RevocationStatus, Verdict, WaitMode, WorkloadIsolation,
};
use heimdall_contract::{Code, GrantState, OperationState, Timestamp};
use heimdall_domain::decision::{
    DecisionKind, DecisionRecord, DecisionState, EnrollmentPlanSummary, SystemFormLines,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::DegradedReason;
use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
use heimdall_domain::issuance::{
    CaEvent, CertificateBounds, CredentialInstance, CredentialState, IssuanceEntry, IssuanceState,
};
use heimdall_domain::operation::{
    AdapterIdentity, EffectClass, OperationKind, OperationRecord, RecoveryIntent, RecoveryMetadata,
};
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::revocation::{
    CleanupIntent, ObligationKind, PendingRemoteRevocation, RemoteObligation, Tombstone,
};
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher, owner_only_m03};
use heimdall_runtime::supervisor::{FixedJitter, Supervisor, SupervisorConfig};
use heimdall_store::{IssuerRecord, RawDocuments, Store};
use heimdall_testkit::{
    FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock, assert_no_canary,
};
use tokio_util::sync::CancellationToken;

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-09T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn shift_ms(t: Timestamp, ms: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_millis(ms))
        .unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([0x31; 16])
}

fn ctx(role: ClientRole) -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role,
    }
}

fn attended(role: ClientRole) -> Caller {
    Caller {
        context: ctx(role),
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn unattended(role: ClientRole) -> Caller {
    Caller::unattended(ctx(role))
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
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
        },
        evidence: Vec::new(),
    }
}

fn fake_identity() -> AdapterIdentity {
    AdapterIdentity {
        mechanism: "fake_agent".into(),
        instance: "fixture-1".into(),
    }
}

fn descriptor(remote_effect: bool) -> AdapterDescriptor {
    AdapterDescriptor {
        identity: fake_identity(),
        capabilities: ssh_only(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: enforcement(),
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: remote_effect,
    }
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: shift(t0(), 12 * 3600),
        offline_until: shift(t0(), 3600),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "opaque-fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
    }
}

fn seed(store: &Store) {
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([0x32; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            let scope = Scope {
                pairs: [pair("h1", "deploy"), pair("h2", "deploy")]
                    .into_iter()
                    .collect(),
                capabilities: ssh_only(),
            };
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("dev").unwrap(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope,
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                },
                false,
            )?;
            Ok(())
        })
        .unwrap();
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    limits: Limits,
    ops: Operations,
}

impl World {
    async fn new() -> Self {
        Self::with(false, Limits::default()).await
    }

    async fn with(remote_effect: bool, limits: Limits) -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let fake =
            FakeCredentialAdapter::new(descriptor(remote_effect), [FakeStep::Prepare(outcome())]);
        let ops = Operations::start(config_of(&store, &clock, &sync, &fake, limits))
            .await
            .unwrap();
        Self {
            store,
            clock,
            sync,
            fake,
            limits,
            ops,
        }
    }

    async fn restart(&mut self) {
        self.ops = Operations::start(config_of(
            &self.store,
            &self.clock,
            &self.sync,
            &self.fake,
            self.limits,
        ))
        .await
        .unwrap();
    }

    fn dispatcher(&self) -> OperationsDispatcher {
        let relay = EventRelay::spawn(&self.ops, CancellationToken::new());
        OperationsDispatcher::new(self.ops.clone(), relay, self.clock.clone())
    }

    fn supervisor(&self) -> Supervisor {
        Supervisor::new(self.ops.clone(), SupervisorConfig::default())
            .with_state(self.store.clone(), self.clock.clone())
            .with_jitter(Arc::new(FixedJitter(1.0)))
    }

    fn events(&self) -> Vec<heimdall_contract::event::Event> {
        let page = self
            .store
            .transaction(|tx| tx.stored_events_after(&env_id(), 0, &EventFilter::default(), 10_000))
            .unwrap();
        page.events
            .into_iter()
            .map(|e| {
                assert_no_canary(&serde_json::to_string(&e.event).unwrap());
                e.event
            })
            .collect()
    }

    /// Everything a request could have written: row counts, every raw document
    /// table, open and unresolved operations, pending decisions, and the events.
    fn snapshot(&self) -> String {
        self.store
            .transaction(|tx| {
                let mut out = format!("{:?}\n", tx.table_counts()?);
                for which in [
                    RawDocuments::StageReceipts,
                    RawDocuments::RecoveryIntents,
                    RawDocuments::Meta,
                    RawDocuments::IssuanceLog,
                    RawDocuments::CredentialInstances,
                    RawDocuments::Destinations,
                    RawDocuments::Identities,
                    RawDocuments::InteractionDeclarations,
                    RawDocuments::ProjectionRecords,
                    RawDocuments::ProjectionConsent,
                    RawDocuments::Resources,
                ] {
                    out.push_str(&format!("{which:?} {:?}\n", tx.raw_documents(which)?));
                }
                out.push_str(&format!("{:?}\n", tx.open_operations()?));
                out.push_str(&format!("{:?}\n", tx.unresolved_operations()?));
                out.push_str(&format!("{:?}\n", tx.pending_decisions()?));
                out.push_str(&format!("{:?}\n", tx.remote_revocations()?));
                out.push_str(&format!("{:?}\n", tx.issuers()?));
                out.push_str(&format!("{:?}\n", tx.open_enrollments()?));
                Ok(out)
            })
            .unwrap()
            + &format!("{:?}", self.events())
    }

    async fn ensure_grant(&self, request: &str) -> GrantId {
        let r = self
            .ops
            .ensure(&unattended(ClientRole::Owner), ensure_req(request))
            .await
            .unwrap();
        r.data.grant_id
    }

    fn grant_state(&self, g: &GrantId) -> GrantState {
        self.store
            .transaction(|tx| tx.grant(g))
            .unwrap()
            .unwrap()
            .state
    }
}

fn config_of(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    sync: &Arc<ScriptedTimeSync>,
    fake: &Arc<FakeCredentialAdapter>,
    limits: Limits,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits,
        default_window: HOUR,
        projection: None,
    }
}

fn ensure_req(request_id: &str) -> EnsureRequest {
    EnsureRequest {
        profile: ProfileId::parse("dev").unwrap(),
        profile_revision: None,
        scope: [pair("h1", "deploy")].into_iter().collect(),
        environment: None,
        work_id: WorkId::parse(&format!("work-{request_id}")).unwrap(),
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(request_id).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 30_000 },
        connection: None,
    }
}

/// The repository root through `HM_REPO_ROOT` (ADR-0007 §12.32 item 3).
fn repo_root() -> std::path::PathBuf {
    heimdall_testkit::repo::repo_root()
}

fn request(v: serde_json::Value) -> Request {
    serde_json::from_value(v).unwrap()
}

fn example(name: &str) -> Request {
    let path = repo_root().join("schemas/examples").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {}", path.display(), e.kind()));
    request(serde_json::from_str(&text).unwrap())
}

/// Every M03 request variant (m03-plan §5 items 2, 3, 4a): five issuer actions,
/// eight enrollment actions and the two connection actions.
fn m03_requests() -> Vec<Request> {
    let mut out: Vec<Request> = [
        "request.issuer.status.json",
        "request.issuer.register.json",
        "request.issuer.unlock.json",
        "request.issuer.retire.json",
        "request.issuer.bundle.json",
        "request.enrollment.preview.json",
        "request.enrollment.apply.json",
        "request.enrollment.verify.json",
        "request.enrollment.remove.json",
        "request.enrollment.reconcile.json",
        "request.enrollment.abandon.json",
        "request.enrollment.step.json",
        "request.enrollment.step-result.json",
    ]
    .into_iter()
    .map(example)
    .collect();
    out.push(request(serde_json::json!({
        "op": "connections", "action": "close",
        "connection_id": "conn_00112233445566778899aabbccddeeff"
    })));
    out.push(request(serde_json::json!({
        "op": "connections", "action": "register",
        "binding_id": "binding_0123456789abcdef0123456789abcdef", "pid": 4242,
        "created_at": "2026-11-10T14:05:00Z",
        "image": "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
    })));
    out
}

/// One of every request variant (as `tests/contracts/m02.rs::one_of_every_request`).
fn every_request() -> Vec<Request> {
    let mut out: Vec<Request> = [
        "request.ensure.json",
        "request.revoke.json",
        "request.policy-cutoff.json",
        "request.observe-events.json",
        "request.decide.json",
        "request.confirm-time.json",
        "request.shutdown.json",
        "request.bind-launch.json",
        "request.setup.preview-apply.json",
        "request.setup.apply.json",
        "request.setup.rollback.json",
        "request.setup.repair.json",
        "request.catalog.upsert-destination.json",
        "request.catalog.remove-destination.json",
        "request.catalog.adopt-identity.json",
        "request.catalog.remove-identity.json",
        "request.catalog.upsert-profile.json",
        "request.catalog.remove-profile.json",
        "request.catalog.declare-interaction.json",
        "request.catalog.withdraw-declaration.json",
    ]
    .into_iter()
    .map(example)
    .collect();
    out.extend([
        request(serde_json::json!({"op": "inspect", "subject": "identities"})),
        request(serde_json::json!({"op": "inspect", "subject": "enrollments"})),
        request(serde_json::json!({"op": "inspect", "subject": "issuer"})),
        request(serde_json::json!({"op": "inspect", "subject": "connections"})),
        request(serde_json::json!({
            "op": "delegate",
            "parent_binding_id": "binding_0123456789abcdef0123456789abcdef",
            "scope": [{"destination": "dest-1", "account": "deploy"}],
            "work_id": "work-43",
            "request_id": "req-0401"
        })),
        request(serde_json::json!({"op": "cancel", "operation_id": "op_00112233445566778899aabbccddeeff"})),
        request(serde_json::json!({"op": "release", "binding_id": "binding_0123456789abcdef0123456789abcdef"})),
        request(serde_json::json!({
            "op": "catalog", "action": "set_preference", "destination": "dest-lab",
            "account": "deploy", "mechanism": "managed_certificate", "request_id": "req-0209"
        })),
    ]);
    out.extend(m03_requests());
    out
}

fn reason_of(env: &Envelope<serde_json::Value>) -> Option<&str> {
    env.data["error"]["reason"].as_str()
}

fn assert_driver_unavailable(env: &Envelope<serde_json::Value>, what: &str) {
    assert_eq!(
        env.code,
        Code::CapabilityUnavailable,
        "{what}: {:?}",
        env.data
    );
    assert_eq!(
        reason_of(env),
        Some("driver_unavailable"),
        "{what}: {:?}",
        env.data
    );
    assert_eq!(env.operation_id, None, "{what}: no operation");
    assert_eq!(
        env.data["error"]["effect_status"],
        serde_json::json!(EffectStatus::None),
        "{what}: {:?}",
        env.data
    );
}

// --- seeded records -----------------------------------------------------------------

fn seed_operation(w: &World, n: u8, kind: OperationKind, state: OperationState) -> OperationId {
    let id = OperationId::from_random_bytes([n; 16]);
    let rid = RequestId::parse(&format!("w0-r-{n}")).unwrap();
    let op = OperationRecord {
        id: id.clone(),
        kind,
        environment: env_id(),
        key: IdempotencyKey {
            caller: ctx(ClientRole::Owner),
            kind,
            request_id: rid,
        },
        request_hash: RequestHash([n; 32]),
        effect_class: kind.m03_effect_class().unwrap_or(EffectClass::Local),
        state,
        code: None,
        effect_status: EffectStatus::None,
        result: None,
        created_at: t0(),
        updated_at: t0(),
        cancellation: None,
        recovery: RecoveryMetadata::default(),
    };
    let idem = IdempotencyRecord {
        key: op.key.clone(),
        request_hash: op.request_hash,
        operation_id: op.id.clone(),
        created_at: op.created_at,
        expires_at: None,
    };
    w.store
        .transaction(|tx| {
            tx.insert_operation(&op, &idem)?;
            tx.set_recovery_intent(
                &id,
                &RecoveryIntent {
                    request: serde_json::json!({ "op": "enrollment", "kind": kind.as_str() }),
                    resolved: None,
                    local: None,
                },
            )
        })
        .unwrap();
    id
}

fn ca(n: u8) -> CaFingerprint {
    let c = char::from(b'A' + n);
    CaFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
}

fn plan_summary() -> EnrollmentPlanSummary {
    use heimdall_contract::enrollment::{ApprovedHostKey, ApprovedTarget, EnrollmentForm, NoProxy};
    EnrollmentPlanSummary {
        destination_id: DestinationId::parse("lab").unwrap(),
        alias: "lab".into(),
        account: AccountName::parse("deploy").unwrap(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "$HOME/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: "1".repeat(64),
        ca_fingerprint: ca(0),
        approved_target: ApprovedTarget {
            hostname: "lab.example.invalid".into(),
            port: 22,
            user: AccountName::parse("deploy").unwrap(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "A".into(),
                fingerprint: format!("SHA256:{}", "A".repeat(43)),
            },
        },
        invocation: vec!["-o".into(), "IdentitiesOnly=yes".into()],
        host_trust: vec!["StrictHostKeyChecking=yes".into()],
        bootstrap: false,
        disclosures: vec![DisclosureKind::CaTrustBlastRadius],
    }
}

/// One decision kind of each M03 kind (m03-plan §5 item 10).
fn m03_decision_kinds() -> Vec<DecisionKind> {
    let op = OperationId::from_random_bytes([0x51; 16]);
    let digest = heimdall_contract::setup::PlanDigest::from_sha256([0x52; 32]);
    let summary = plan_summary();
    vec![
        DecisionKind::RegisterIssuer {
            ca_fingerprint: ca(0),
            store: StoreKind::LinuxSecretService,
            backup_sha256: "2".repeat(64),
            rotation_of: None,
            restored_without_log: false,
            disclosures: vec![DisclosureKind::SameUserIssuerBoundary],
        },
        DecisionKind::RetireIssuer {
            ca_fingerprint: ca(0),
            abandoned_enrollments: Vec::new(),
        },
        DecisionKind::EnrollAccount {
            operation: op.clone(),
            plan_digest: digest.clone(),
            summary: summary.clone(),
        },
        DecisionKind::EnrollSystemForm {
            operation: op.clone(),
            plan_digest: digest,
            summary: summary.clone(),
            sshd_lines: SystemFormLines {
                trusted_user_ca_keys_line: "ssh-ed25519 AAAASYNTHETICPLACEHOLDERNOTAKEY".into(),
                principals_line: "hm:lab:deploy".into(),
                sshd_directives: vec!["TrustedUserCAKeys /etc/ssh/heimdall_ca.pub".into()],
            },
        },
        DecisionKind::RemoveEnrollment {
            operation: op.clone(),
            target: heimdall_contract::enrollment::RemovalTarget::Enrollment {
                enrollment_id: EnrollmentId::from_random_bytes([0x53; 16]),
            },
            invocation: vec!["-o".into(), "IdentitiesOnly=yes".into()],
            affected_grants: Vec::new(),
            pair_residual_until: None,
            fresh_target: None,
        },
        DecisionKind::ApproveTargetChange {
            operation: op,
            enrollment: EnrollmentId::from_random_bytes([0x54; 16]),
            approved: summary.approved_target.clone(),
            proposed: summary.approved_target,
        },
    ]
}

fn insert_decision(w: &World, n: u8, kind: DecisionKind) -> DecisionId {
    let id = DecisionId::from_random_bytes([n; 16]);
    w.store
        .transaction(|tx| {
            let generation = tx.authority_generation()?;
            tx.insert_decision(&DecisionRecord {
                id: id.clone(),
                kind,
                generation,
                created_at: t0(),
                expires_at: shift(t0(), 3600),
                state: DecisionState::Pending,
                decided_at: None,
            })
        })
        .unwrap();
    id
}

fn decision_state(w: &World, d: &DecisionId) -> DecisionState {
    w.store
        .transaction(|tx| tx.decision(d))
        .unwrap()
        .unwrap()
        .state
}

// =================================================================================
// Row 13: dispatch arms
// =================================================================================

/// U0b row 13, phase 1: every `Request::{Issuer, Enrollment, Connections}` reaching
/// the real dispatcher from the owner on an attended session answers
/// `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, effect `none`, with no
/// operation ID, and nothing in the store changes (row counts, every raw document
/// table, operations, decisions, events). Unattended, `Issuer::Unlock` is refused
/// `INTERACTION_REQUIRED` first (attended-only), also writing nothing.
#[tokio::test]
async fn w0_m03_requests_fail_closed_before_any_record() {
    let w = World::new().await;
    let d = w.dispatcher();
    let before = w.snapshot();
    for r in m03_requests() {
        let what = format!(
            "{} {:?}",
            r.kind(),
            serde_json::to_value(&r).unwrap()["action"]
        );
        let env = d.handle_as(&attended(ClientRole::Owner), r.clone()).await;
        assert_no_canary(&serde_json::to_string(&env).unwrap());
        assert_driver_unavailable(&env, &what);
        let env = d.handle_as(&unattended(ClientRole::Owner), r.clone()).await;
        if r.requires_attended_session() {
            assert_eq!(env.code, Code::InteractionRequired, "{what}");
        } else {
            assert_driver_unavailable(&env, &what);
        }
    }
    assert_eq!(w.snapshot(), before, "nothing was written");
}

/// U0b row 13 (F20): `Enrollment::{Step, StepResult, Reconcile}` and
/// `Connections::{Close, Register}` are refused for any role but owner, with
/// `CAPABILITY_UNAVAILABLE` and **no** `driver_unavailable` reason (the role
/// refusal comes first: authorization before capability, so a non-owner learns
/// nothing about this build's drivers); the other M03 requests answer
/// `driver_unavailable` to a non-owner as to the owner. Nothing is written.
#[tokio::test]
async fn step_and_reconcile_refused_for_non_owner_role() {
    let w = World::new().await;
    let d = w.dispatcher();
    let before = w.snapshot();
    let mut owner_only = 0;
    for r in m03_requests() {
        let what = format!(
            "{} {:?}",
            r.kind(),
            serde_json::to_value(&r).unwrap()["action"]
        );
        let env = d
            .handle_as(&attended(ClientRole::LimitedConsumer), r.clone())
            .await;
        if owner_only_m03(&r) {
            owner_only += 1;
            assert_eq!(env.code, Code::CapabilityUnavailable, "{what}");
            assert_eq!(reason_of(&env), None, "{what}: {:?}", env.data);
            assert!(
                env.data["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("owner role"),
                "{what}: {:?}",
                env.data
            );
            // The owner gets the driver answer for the same request.
            let env = d.handle_as(&attended(ClientRole::Owner), r.clone()).await;
            assert_driver_unavailable(&env, &what);
        } else {
            assert_driver_unavailable(&env, &what);
        }
    }
    assert_eq!(
        owner_only, 5,
        "step, step_result, reconcile, close, register"
    );
    assert_eq!(w.snapshot(), before, "nothing was written");
}

/// U0b row 13 / §5 item 15: the four M03 capabilities are declared and **not
/// offered**: not in the server's offer, not in `inspect capabilities`, a hello
/// requiring one is refused, and on a negotiated session an M03 request is refused
/// `SCHEMA_UNSUPPORTED` by the session gate before dispatch.
#[tokio::test]
async fn w0_m03_capabilities_not_offered() {
    use heimdall_contract::ipc::{PeerInfo, PrincipalInfo};
    use heimdall_ipc::session::{
        ConnectionLimits, ControlClient, ControlConnection, server_capabilities,
    };
    let offered = server_capabilities();
    for c in capability::M03_DECLARED {
        assert!(!offered.contains(c), "{c} offered");
    }
    let w = World::new().await;
    let inspect = w
        .ops
        .inspect(
            &unattended(ClientRole::Owner),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Capabilities,
                preview: None,
            },
        )
        .await
        .unwrap();
    let text = serde_json::to_string(&inspect.data).unwrap();
    for c in capability::M03_DECLARED {
        assert!(
            !text.contains(c),
            "{c} listed by inspect capabilities: {text}"
        );
    }
    let open = |required: BTreeSet<String>| {
        let ops = w.ops.clone();
        let clock = w.clock.clone();
        async move {
            let (server, stream) = tokio::io::duplex(1 << 16);
            let relay = EventRelay::spawn(&ops, CancellationToken::new());
            let dispatcher = OperationsDispatcher::new(ops, relay, clock);
            let served = tokio::spawn(async move {
                let _ = ControlConnection::new(server, ConnectionLimits::default())
                    .with_server_identity(
                        env_id(),
                        PeerInfo {
                            name: "heimdall".into(),
                            version: "test".into(),
                        },
                    )
                    .serve(
                        PrincipalInfo::OsUserUnix { uid: 501 },
                        dispatcher,
                        CancellationToken::new(),
                    )
                    .await;
            });
            let client = ControlClient::handshake(
                stream,
                PeerInfo {
                    name: "w0-m03".into(),
                    version: "0".into(),
                },
                required,
                InteractionMode::NonInteractive,
            )
            .await;
            (client, served)
        }
    };
    for c in capability::M03_DECLARED {
        let (client, _served) = open([c.to_owned()].into_iter().collect()).await;
        assert!(client.is_err(), "a hello requiring {c} is refused");
    }
    let before = w.snapshot();
    let (client, _served) = open(BTreeSet::new()).await;
    let mut client = client.unwrap();
    for r in m03_requests() {
        let env = client.request(r.clone()).await.unwrap();
        assert_eq!(
            env.code,
            Code::SchemaUnsupported,
            "{}: {:?}",
            r.kind(),
            env.data
        );
    }
    assert_eq!(w.snapshot(), before, "nothing was written");
}

// =================================================================================
// Row 14: decision kinds
// =================================================================================

/// U0b row 14, phase 1: a pending decision record of each M03 kind, decided
/// (approve and deny) through the real dispatcher on an attended owner session, is
/// refused `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) and stays `pending`: not
/// consumed, no decision event, no operation touched.
#[tokio::test]
async fn w0_new_decision_kinds_refused_not_consumed() {
    let w = World::new().await;
    let d = w.dispatcher();
    let ids: Vec<DecisionId> = m03_decision_kinds()
        .into_iter()
        .enumerate()
        .map(|(i, k)| {
            assert!(k.is_m03());
            insert_decision(&w, 0x60 + u8::try_from(i).unwrap(), k)
        })
        .collect();
    assert_eq!(ids.len(), 6);
    let decision_events = |w: &World| {
        w.events()
            .into_iter()
            .filter(|e| e.event_type == EventType::Decision)
            .count()
    };
    let events_before = decision_events(&w);
    let counts_before = w.store.transaction(|tx| tx.table_counts()).unwrap();
    for id in &ids {
        for verdict in [Verdict::Approve, Verdict::Deny] {
            let env = d
                .handle_as(
                    &attended(ClientRole::Owner),
                    Request::Decide(DecideRequest {
                        decision_id: id.clone(),
                        verdict,
                    }),
                )
                .await;
            assert_driver_unavailable(&env, &format!("{id} {verdict:?}"));
            assert_eq!(decision_state(&w, id), DecisionState::Pending, "{id}");
        }
    }
    assert_eq!(decision_events(&w), events_before);
    assert_eq!(
        w.store.transaction(|tx| tx.table_counts()).unwrap(),
        counts_before
    );
    let pending: BTreeSet<DecisionId> = w
        .store
        .transaction(|tx| tx.pending_decisions())
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert!(ids.iter().all(|id| pending.contains(id)));
}

// =================================================================================
// Row 17: M03 operations at restart
// =================================================================================

/// The `runtime_lifecycle` payloads naming `id`.
fn lifecycle_for(w: &World, id: &OperationId) -> Vec<serde_json::Value> {
    w.events()
        .into_iter()
        .filter(|e| e.event_type == EventType::RuntimeLifecycle)
        .map(|e| e.payload)
        .filter(|p| p["operation_id"] == serde_json::json!(id))
        .collect()
}

/// U0b row 17 (ADR-0008 D5 §6.4): open operations of every M03 journaled kind, in
/// every open state, stay unresolved and untouched across a restart (record,
/// recovery intent and receipts unchanged) and are reported once per restart in
/// `runtime_lifecycle` with `{phase: unresolved, kind, reason: owner_reconcile}`
/// (wave-0 verify E8: not `driver_unavailable`).
#[tokio::test]
async fn w0_open_enrollment_operations_stay_unresolved_at_restart() {
    let mut w = World::new().await;
    let mut seeded = Vec::new();
    let mut n = 0x70u8;
    for kind in OperationKind::ENROLLMENT {
        for state in [
            OperationState::Queued,
            OperationState::Running,
            OperationState::AwaitingApproval,
            OperationState::OutcomeUnknown,
        ] {
            seeded.push((seed_operation(&w, n, kind, state), kind, state));
            n += 1;
        }
    }
    let read = |w: &World, id: &OperationId| {
        w.store
            .transaction(|tx| {
                Ok((
                    tx.operation(id)?,
                    tx.recovery_intent(id)?,
                    tx.stage_receipts(id)?,
                ))
            })
            .unwrap()
    };
    let before: Vec<_> = seeded.iter().map(|(id, _, _)| read(&w, id)).collect();
    w.restart().await;
    let after: Vec<_> = seeded.iter().map(|(id, _, _)| read(&w, id)).collect();
    assert_eq!(after, before, "untouched");
    for (id, kind, state) in &seeded {
        let reported = lifecycle_for(&w, id);
        assert_eq!(reported.len(), 1, "{id}: reported once");
        let p = &reported[0];
        assert_eq!(p["phase"], "unresolved");
        assert_eq!(p["kind"], kind.as_str());
        assert_eq!(p["state"], serde_json::json!(state));
        assert_eq!(p["reason"], OWNER_RECONCILE);
        assert_eq!(p["reason"], "owner_reconcile");
    }
    // A second restart reports them again and still touches nothing.
    w.restart().await;
    let again: Vec<_> = seeded.iter().map(|(id, _, _)| read(&w, id)).collect();
    assert_eq!(again, before);
    for (id, _, _) in &seeded {
        assert_eq!(lifecycle_for(&w, id).len(), 2, "{id}");
    }
}

// =================================================================================
// Row 8: credential instances at restart
// =================================================================================

fn instance(
    n: u8,
    grant: &GrantId,
    state: CredentialState,
    certs: Vec<IssuanceId>,
) -> CredentialInstance {
    CredentialInstance {
        id: CredentialInstanceId::from_random_bytes([n; 16]),
        grant: grant.clone(),
        key_handle_ref: format!("vault-slot-{n}"),
        certificates: certs,
        state,
    }
}

fn issuance(n: u8, grant: &GrantId, p: &AccessPair, valid_before: Timestamp) -> IssuanceEntry {
    IssuanceEntry {
        id: IssuanceId::from_random_bytes([n; 16]),
        grant: grant.clone(),
        generation: AuthorityGeneration(0),
        pair: p.clone(),
        bounds: CertificateBounds {
            serial: u64::from(n),
            key_id: format!("key-{n}"),
            principal: format!("hm:{}:{}", p.destination, p.account),
            valid_after: t0(),
            valid_before,
            extensions: BTreeSet::new(),
            subject_fingerprint: "SHA256:synthetic".into(),
            ca_fingerprint: Some(ca(1)),
        },
        state: IssuanceState::Reserved,
        reserved_at: t0(),
        settled_at: None,
        void_reason: None,
    }
}

fn instance_state(w: &World, id: &CredentialInstanceId) -> CredentialState {
    w.store
        .transaction(|tx| tx.credential_instance(id))
        .unwrap()
        .unwrap()
        .state
}

fn lifecycle_events(w: &World, event: &str) -> Vec<serde_json::Value> {
    w.events()
        .into_iter()
        .filter(|e| e.event_type == EventType::CredentialLifecycle)
        .map(|e| e.payload)
        .filter(|p| p["event"] == event)
        .collect()
}

/// U0b row 8 (ADR-0008 D2 table; F18): an `installed` credential instance becomes
/// `lost` at restart (the new process holds no vault slot), in restart recovery's
/// first transaction, which `Service::start_with` runs before it binds any
/// listener. A `destroyed` one is untouched. One `credential_lifecycle` `lost`
/// event names it. Idempotent across a second restart.
#[tokio::test]
async fn installed_instances_become_lost_at_restart() {
    let mut w = World::new().await;
    let g = w.ensure_grant("req-row8-a").await;
    let installed = instance(1, &g, CredentialState::Installed, Vec::new());
    let destroyed = instance(2, &g, CredentialState::Destroyed, Vec::new());
    w.store
        .transaction(|tx| {
            tx.insert_credential_instance(&installed)?;
            tx.insert_credential_instance(&destroyed)
        })
        .unwrap();
    w.restart().await;
    assert_eq!(instance_state(&w, &installed.id), CredentialState::Lost);
    assert_eq!(
        instance_state(&w, &destroyed.id),
        CredentialState::Destroyed
    );
    let lost = lifecycle_events(&w, "lost");
    assert_eq!(lost.len(), 1);
    assert_eq!(
        lost[0]["credential_instance_id"],
        serde_json::json!(installed.id)
    );
    assert_eq!(lost[0]["grant_id"], serde_json::json!(g));
    w.restart().await;
    assert_eq!(instance_state(&w, &installed.id), CredentialState::Lost);
    assert_eq!(lifecycle_events(&w, "lost").len(), 1, "idempotent");
}

/// U0b row 8 ⟨r2⟩ (F18): a `pending` instance becomes `destroyed` at restart, and
/// its `reserved`/`published` issuance entries are untouched and stay counted in
/// the residual (`issuance_residual` and the pair residual are unchanged).
#[tokio::test]
async fn pending_instances_destroyed_at_restart_entries_still_counted() {
    let mut w = World::new().await;
    let g = w.ensure_grant("req-row8-b").await;
    let p = pair("h1", "deploy");
    let reserved = issuance(1, &g, &p, shift(t0(), 600));
    let published = issuance(2, &g, &p, shift(t0(), 900));
    let pending = instance(
        3,
        &g,
        CredentialState::Pending,
        vec![reserved.id.clone(), published.id.clone()],
    );
    let residual = |w: &World| {
        w.store
            .transaction(|tx| {
                Ok((
                    tx.issuance_residual(std::slice::from_ref(&g))?,
                    tx.pair_residual(&p, None)?,
                    tx.issuance_entries(&g)?,
                ))
            })
            .unwrap()
    };
    w.store
        .transaction(|tx| {
            tx.reserve_issuance(&reserved)?;
            tx.reserve_issuance(&published)?;
            tx.publish_issuance(&published.id, t0())?;
            tx.insert_credential_instance(&pending)
        })
        .unwrap();
    let before = residual(&w);
    assert_eq!(before.0, Some(shift(t0(), 900)));
    w.restart().await;
    assert_eq!(instance_state(&w, &pending.id), CredentialState::Destroyed);
    assert_eq!(residual(&w), before, "entries untouched and still counted");
    let states: Vec<IssuanceState> = residual(&w).2.into_iter().map(|e| e.state).collect();
    assert_eq!(states, [IssuanceState::Reserved, IssuanceState::Published]);
    let destroyed = lifecycle_events(&w, "destroyed");
    assert_eq!(destroyed.len(), 1);
    assert_eq!(
        destroyed[0]["credential_instance_id"],
        serde_json::json!(pending.id)
    );
    // No grant change for a destroyed pending instance.
    assert_eq!(w.grant_state(&g), GrantState::Active);
}

/// U0b row 8: the grant of a lost instance is degraded `credential_reissue_pending`
/// in the same transaction (an `active` grant moves to `degraded`, with a
/// `grant_state_changed` event carrying the reason); a grant in another state is
/// left alone. The supervisor's `managed_reissue_pass` hook exists and, with no
/// managed adapter registered, changes nothing.
#[tokio::test]
async fn lost_instance_grant_degraded_credential_reissue_pending() {
    let mut w = World::new().await;
    let g = w.ensure_grant("req-row8-c").await;
    let other = w.ensure_grant("req-row8-d").await;
    w.store
        .transaction(|tx| {
            tx.insert_credential_instance(&instance(
                4,
                &g,
                CredentialState::Installed,
                Vec::new(),
            ))?;
            // The other grant is revoking: its lost instance leaves it alone.
            let mut s = tx.grant(&other)?.unwrap();
            s.state = GrantState::Revoking;
            tx.update_grant_state(&s)?;
            tx.insert_credential_instance(&instance(
                5,
                &other,
                CredentialState::Installed,
                Vec::new(),
            ))
        })
        .unwrap();
    w.restart().await;
    assert_eq!(w.grant_state(&g), GrantState::Degraded);
    assert_eq!(
        w.store.transaction(|tx| tx.grant_degradation(&g)).unwrap(),
        Some(DegradedReason::CredentialReissuePending)
    );
    let changed: Vec<serde_json::Value> = w
        .events()
        .into_iter()
        .filter(|e| e.event_type == EventType::GrantStateChanged)
        .map(|e| e.payload)
        .filter(|p| p["grant_id"] == serde_json::json!(g) && p["state"] == "degraded")
        .collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["reason"], "credential_reissue_pending");
    assert_eq!(w.grant_state(&other), GrantState::Revoking);
    assert_eq!(
        w.store
            .transaction(|tx| tx.grant_degradation(&other))
            .unwrap(),
        None
    );
    let before = w.snapshot();
    let sup = w.supervisor();
    assert!(sup.managed_reissue_pass().await.unwrap().is_empty());
    assert_eq!(
        w.snapshot(),
        before,
        "the hook is a no-op without the managed adapter"
    );
}

// =================================================================================
// Row 6: bounded obligations
// =================================================================================

fn bounded(
    grant: &GrantId,
    adapter: AdapterIdentity,
    latest_valid_before: Timestamp,
    clock: DestinationClock,
) -> RemoteObligation {
    RemoteObligation {
        grant: grant.clone(),
        adapter,
        reason: None,
        attempts: Some(0),
        stopped: false,
        effect_round: None,
        effect_seq: None,
        kind: ObligationKind::BoundedByExpiry {
            latest_valid_before,
            clock,
            status: ResidualStatus::PendingUntil,
        },
    }
}

fn needs_action(grant: &GrantId, adapter: AdapterIdentity) -> RemoteObligation {
    RemoteObligation {
        grant: grant.clone(),
        adapter,
        reason: None,
        attempts: Some(0),
        stopped: false,
        effect_round: None,
        effect_seq: None,
        kind: ObligationKind::NeedsRemoteAction,
    }
}

/// A `revoking` grant with a pending remote record holding `obligations`.
async fn revoking_with(
    w: &World,
    request: &str,
    obligations: impl Fn(&GrantId) -> Vec<RemoteObligation>,
) -> GrantId {
    let g = w.ensure_grant(request).await;
    let obligations = obligations(&g);
    w.store
        .transaction(|tx| {
            let mut s = tx.grant(&g)?.unwrap();
            s.state = GrantState::Revoking;
            tx.update_grant_state(&s)?;
            let generation = tx.authority_generation()?;
            tx.insert_tombstone(&Tombstone {
                grant: g.clone(),
                cascade: Vec::new(),
                generation,
                revoked_at: t0(),
                remote_pending: Vec::new(),
                cause: Default::default(),
            })?;
            tx.set_remote_revocation(&PendingRemoteRevocation {
                root: g.clone(),
                grants: vec![g.clone()],
                attempts: 0,
                last_attempt_at: t0(),
                stopped: false,
                obligations,
                claimed_at: None,
                rearmed_effects: Vec::new(),
                cap: Some(8),
                claim_seq: Some(0),
            })
        })
        .unwrap();
    g
}

fn record_of(w: &World, root: &GrantId) -> Option<PendingRemoteRevocation> {
    w.store
        .transaction(|tx| tx.remote_revocation(root))
        .unwrap()
}

fn status_of(o: &RemoteObligation) -> Option<ResidualStatus> {
    match &o.kind {
        ObligationKind::BoundedByExpiry { status, .. } => Some(*status),
        _ => None,
    }
}

fn measured() -> DestinationClock {
    DestinationClock::Measured(ClockMeasurement {
        behind_upper_ms: 2_000,
        rtt_ms: 500,
        measured_at: t0(),
    })
}

/// Advance the virtual wall and continuous clocks together to `at`.
fn advance_to(w: &World, at: Timestamp) {
    let by = at.duration_since(w.clock.wall());
    w.clock.advance(Duration::try_from(by).unwrap());
}

/// U0b row 6 (ADR-0008 D7 item 3; §17.1 item 10): a measured `bounded_by_expiry`
/// obligation stays `pending_until` until `latest_valid_before + behind_upper + rtt
/// + 100 ppm × age` has passed on safe time, then becomes `bounded_complete`; the
/// grant reaches `revoked` and the record is removed. No adapter call is made.
#[tokio::test]
async fn bounded_obligation_completes_after_measured_bound_on_safe_time() {
    let w = World::new().await;
    let lvb = shift(t0(), 3600);
    let g = revoking_with(&w, "req-row6-a", |g| {
        vec![bounded(g, fake_identity(), lvb, measured())]
    })
    .await;
    let sup = w.supervisor();
    // The bound evaluated at lvb + 2.8 s: 2.5 s + 100 ppm × 3602.8 s = 2.5 + 0.361
    // (rounded up to the millisecond) = lvb + 2.861 s.
    advance_to(&w, shift_ms(lvb, 2_800));
    let r = sup.revocation_pass().await.unwrap();
    let b = r.bounded.unwrap();
    assert!(b.safe);
    assert!(b.moved.is_empty(), "{b:?}");
    assert!(b.next_at.is_some_and(|t| t > w.clock.wall()));
    assert_eq!(w.grant_state(&g), GrantState::Revoking);
    assert_eq!(
        record_of(&w, &g)
            .unwrap()
            .obligations
            .iter()
            .map(status_of)
            .collect::<Vec<_>>(),
        [Some(ResidualStatus::PendingUntil)]
    );
    advance_to(&w, shift_ms(lvb, 2_900));
    let r = sup.revocation_pass().await.unwrap();
    let b = r.bounded.unwrap();
    assert_eq!(
        b.moved,
        [(g.clone(), g.clone(), ResidualStatus::BoundedComplete)]
    );
    assert_eq!(b.revoked, std::slice::from_ref(&g));
    assert_eq!(b.removed, std::slice::from_ref(&g));
    assert_eq!(w.grant_state(&g), GrantState::Revoked);
    assert!(record_of(&w, &g).is_none());
    assert!(
        w.fake.revocations.lock().unwrap().is_empty(),
        "no adapter call"
    );
}

/// U0b row 6: an unmeasured obligation becomes `nominally_expired` once
/// `latest_valid_before` has passed on safe time and **never** `bounded_complete`
/// (never shown as cleared): in a record that still holds other work it stays
/// recorded `nominally_expired` however long after, and its grant stays `revoking`
/// while another obligation on it is unresolved. A grant whose only obligation is
/// unmeasured reaches `revoked` once it is `nominally_expired`, and its record is
/// kept (ADR-0008 §17.15).
#[tokio::test]
async fn unmeasured_obligation_becomes_nominally_expired_never_cleared() {
    let w = World::new().await;
    let lvb = shift(t0(), 1800);
    let elsewhere = AdapterIdentity {
        mechanism: "not_configured".into(),
        instance: "x".into(),
    };
    let mixed = revoking_with(&w, "req-row6-b", |g| {
        vec![
            needs_action(g, elsewhere.clone()),
            bounded(g, fake_identity(), lvb, DestinationClock::Unmeasured),
        ]
    })
    .await;
    let alone = revoking_with(&w, "req-row6-c", |g| {
        vec![bounded(
            g,
            fake_identity(),
            lvb,
            DestinationClock::Unmeasured,
        )]
    })
    .await;
    let sup = w.supervisor();
    advance_to(&w, shift(lvb, -1));
    let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
    assert!(b.moved.is_empty());
    advance_to(&w, lvb);
    let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
    let moved: std::collections::HashSet<(GrantId, ResidualStatus)> =
        b.moved.iter().map(|(_, g, s)| (g.clone(), *s)).collect();
    assert_eq!(
        moved,
        [
            (mixed.clone(), ResidualStatus::NominallyExpired),
            (alone.clone(), ResidualStatus::NominallyExpired)
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(b.revoked, std::slice::from_ref(&alone));
    assert_eq!(w.grant_state(&alone), GrantState::Revoked);
    assert!(record_of(&w, &alone).is_some(), "kept (§17.15)");
    assert_eq!(w.grant_state(&mixed), GrantState::Revoking);
    for days in [1, 30, 365] {
        advance_to(&w, shift(lvb, days * 86_400));
        let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
        assert!(b.moved.is_empty(), "day {days}: {b:?}");
        let r = record_of(&w, &mixed).unwrap();
        let statuses: Vec<Option<ResidualStatus>> = r.obligations.iter().map(status_of).collect();
        assert_eq!(
            statuses,
            [None, Some(ResidualStatus::NominallyExpired)],
            "day {days}"
        );
        assert_eq!(w.grant_state(&mixed), GrantState::Revoking);
    }
    assert!(
        w.fake.revocations.lock().unwrap().is_empty(),
        "no adapter call"
    );
}

/// ADR-0008 §17.15 (ruling on R4; §17.1 item 10): a `nominally_expired`
/// obligation keeps its record: the grant still moves `revoking → revoked` (the
/// obligation blocks nothing else), the record stays with the obligation recorded
/// `nominally_expired` pass after pass (never removed, never `bounded_complete`),
/// it is listed in the pass report, and `inspect grants` keeps listing the ended
/// grant (the existing reporting path for a grant a record covers). No adapter
/// call; the grant moves once (one `revoked` state event).
#[tokio::test]
async fn nominally_expired_obligation_keeps_record_grant_still_revoked() {
    let w = World::new().await;
    let lvb = shift(t0(), 900);
    let g = revoking_with(&w, "req-row6-ne", |g| {
        vec![bounded(
            g,
            fake_identity(),
            lvb,
            DestinationClock::Unmeasured,
        )]
    })
    .await;
    let sup = w.supervisor();
    advance_to(&w, lvb);
    let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
    assert_eq!(b.revoked, std::slice::from_ref(&g));
    assert!(b.removed.is_empty(), "{b:?}");
    assert_eq!(b.nominally_expired, [(g.clone(), g.clone())]);
    assert_eq!(w.grant_state(&g), GrantState::Revoked);
    for days in [1, 90, 3650] {
        advance_to(&w, shift(lvb, days * 86_400));
        let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
        assert!(
            b.moved.is_empty() && b.revoked.is_empty() && b.removed.is_empty(),
            "{b:?}"
        );
        assert_eq!(b.nominally_expired, [(g.clone(), g.clone())], "day {days}");
        let r = record_of(&w, &g).expect("the record is kept");
        assert_eq!(
            r.obligations.iter().map(status_of).collect::<Vec<_>>(),
            [Some(ResidualStatus::NominallyExpired)],
            "day {days}"
        );
    }
    let inspect = w
        .ops
        .inspect(
            &unattended(ClientRole::Owner),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Grants,
                preview: None,
            },
        )
        .await
        .unwrap();
    let text = serde_json::to_string(&inspect.data).unwrap();
    assert!(
        text.contains(g.as_str()),
        "the ended grant stays listed: {text}"
    );
    let revoked_events = w
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == EventType::GrantStateChanged
                && e.payload["grant_id"] == serde_json::json!(g)
                && e.payload["state"] == "revoked"
        })
        .count();
    assert_eq!(revoked_events, 1);
    assert!(
        w.fake.revocations.lock().unwrap().is_empty(),
        "no adapter call"
    );
}

/// ADR-0008 §17.15: a record holding only `bounded_complete` obligations is removed
/// (two grants, both measured, both past their bounds); a record that also holds a
/// `nominally_expired` obligation is not, though both its grants reach `revoked`.
#[tokio::test]
async fn bounded_complete_only_record_removed() {
    let w = World::new().await;
    let lvb = shift(t0(), 900);
    let complete = revoking_with(&w, "req-row6-bc", |g| {
        vec![
            bounded(g, fake_identity(), lvb, measured()),
            bounded(g, fake_identity(), shift(lvb, -60), measured()),
        ]
    })
    .await;
    let mixed = revoking_with(&w, "req-row6-bm", |g| {
        vec![
            bounded(g, fake_identity(), lvb, measured()),
            bounded(g, fake_identity(), lvb, DestinationClock::Unmeasured),
        ]
    })
    .await;
    let sup = w.supervisor();
    advance_to(&w, shift(lvb, 60));
    let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
    assert_eq!(b.removed, std::slice::from_ref(&complete));
    assert!(record_of(&w, &complete).is_none());
    assert_eq!(w.grant_state(&complete), GrantState::Revoked);
    let kept = record_of(&w, &mixed).expect("kept: it holds a nominally_expired obligation");
    assert_eq!(
        kept.obligations.iter().map(status_of).collect::<Vec<_>>(),
        [
            Some(ResidualStatus::BoundedComplete),
            Some(ResidualStatus::NominallyExpired)
        ]
    );
    assert_eq!(b.nominally_expired, [(mixed.clone(), mixed.clone())]);
    assert_eq!(w.grant_state(&mixed), GrantState::Revoked);
    let mut revoked = b.revoked.clone();
    revoked.sort();
    let mut expected = vec![complete, mixed];
    expected.sort();
    assert_eq!(revoked, expected);
}

/// U0b row 6: on uncertain time nothing moves (fail closed), even long past every
/// bound; once safe time returns the obligation settles.
#[tokio::test]
async fn bounded_obligation_never_moves_on_uncertain_time() {
    let w = World::new().await;
    let lvb = shift(t0(), 600);
    let g = revoking_with(&w, "req-row6-d", |g| {
        vec![
            bounded(g, fake_identity(), lvb, DestinationClock::Unmeasured),
            bounded(g, fake_identity(), lvb, measured()),
        ]
    })
    .await;
    // A reboot with no synchronization and no confirmation: no safe time.
    w.sync.set(SyncStatus::Unknown);
    w.clock.reboot(shift(lvb, 7 * 86_400));
    assert!(matches!(
        w.ops.timegate().peek().await.unwrap(),
        heimdall_domain::time::TimeStatus::Uncertain(_)
    ));
    let sup = w.supervisor();
    let before = record_of(&w, &g).unwrap();
    for _ in 0..3 {
        let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
        assert!(!b.safe);
        assert!(b.moved.is_empty() && b.revoked.is_empty() && b.removed.is_empty());
        assert_eq!(record_of(&w, &g).unwrap(), before);
        assert_eq!(w.grant_state(&g), GrantState::Revoking);
    }
    w.sync.set(SyncStatus::Synchronized);
    let b = sup.revocation_pass().await.unwrap().bounded.unwrap();
    assert!(b.safe);
    assert_eq!(b.revoked, std::slice::from_ref(&g));
    assert_eq!(w.grant_state(&g), GrantState::Revoked);
}

/// U0b row 6: a bounded obligation consumes no attempt and causes no adapter call,
/// even when its adapter identity is configured and many passes run while it is
/// pending: the record's `attempts`, `claim_seq` and the obligation's `attempts`
/// are unchanged, no round is scheduled for a record of bounded obligations only,
/// and the adapter's `revoke` is never called. In a mixed record the M01 round
/// still calls (and counts) only the `needs_remote_action` obligation.
#[tokio::test]
async fn bounded_obligation_consumes_no_attempt() {
    let w = World::new().await;
    let lvb = shift(t0(), 7200);
    let g = revoking_with(&w, "req-row6-e", |g| {
        vec![bounded(g, fake_identity(), lvb, measured())]
    })
    .await;
    let sup = w.supervisor().with_revocation_backoff(Backoff {
        base: Duration::from_millis(10),
        max: Duration::from_millis(40),
        max_attempts: 3,
    });
    let before = record_of(&w, &g).unwrap();
    for i in 0..10 {
        let r = sup.revocation_pass().await.unwrap();
        assert!(
            r.scheduled.iter().all(|(root, ..)| root != &g),
            "pass {i}: {r:?}"
        );
        assert!(r.retried.is_empty() && r.waiting.is_empty() && r.stopped.is_empty());
        w.clock.advance(Duration::from_secs(60));
    }
    let after = record_of(&w, &g).unwrap();
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.claim_seq, before.claim_seq);
    assert_eq!(after.obligations[0].attempts, Some(0));
    assert!(!after.stopped && !after.obligations[0].stopped);
    assert!(w.fake.revocations.lock().unwrap().is_empty());

    // Mixed: the M01 round calls the configured adapter for the needs-action
    // obligation only; the bounded one keeps zero attempts.
    let m = revoking_with(&w, "req-row6-f", |g| {
        vec![
            needs_action(g, fake_identity()),
            bounded(g, fake_identity(), lvb, measured()),
        ]
    })
    .await;
    for _ in 0..6 {
        sup.revocation_pass().await.unwrap();
        w.clock.advance(Duration::from_secs(1));
    }
    let calls = w
        .fake
        .revocations
        .lock()
        .unwrap()
        .iter()
        .filter(|x| **x == m)
        .count();
    assert!(calls >= 1, "the needs-action obligation was called");
    let r = record_of(&w, &m).unwrap();
    assert_eq!(
        r.obligations.len(),
        1,
        "the confirmed needs-action obligation cleared"
    );
    assert_eq!(
        status_of(&r.obligations[0]),
        Some(ResidualStatus::PendingUntil)
    );
    assert_eq!(
        r.obligations[0].attempts,
        Some(0),
        "no attempt counted for it"
    );
    assert_eq!(w.grant_state(&m), GrantState::Revoking);
}

// =================================================================================
// Row 7 (supervisor part): kept cleanup intents
// =================================================================================

fn intent(grant: &GrantId, operation: &OperationId, adapter: AdapterIdentity) -> CleanupIntent {
    CleanupIntent {
        grant: grant.clone(),
        operation: operation.clone(),
        adapter: Some(adapter),
        effect_token: "eff-w0-row7".into(),
        confirmed: false,
        in_flight: false,
        version: 0,
        recorded_at: t0(),
    }
}

/// U0b row 7, supervisor part (ADR-0007 §12.13; ADR-0008 D7 item 5). With an
/// adapter that declares a remote credential effect configured, a cleanup intent
/// that a processing leaves on record (here: its applying adapter is not
/// configured, so no call can follow the effect; with U0b row 7's app part, also a
/// timed-out immediate call) is processed again only after the bounded, jittered
/// back-off on the continuous clock, `retry_delay(backoff, n, jitter)`, and not
/// again in this process once `n` reaches `max_attempts`. Without such an adapter
/// (every M02 adapter) the M02 behaviour is unchanged: every pass processes it, no
/// schedule.
#[tokio::test]
async fn kept_cleanup_intents_retried_with_bounded_jittered_backoff() {
    let backoff = Backoff {
        base: Duration::from_millis(100),
        max: Duration::from_millis(400),
        max_attempts: 4,
    };
    let elsewhere = AdapterIdentity {
        mechanism: "not_configured".into(),
        instance: "x".into(),
    };
    // M02: unchanged.
    let w = World::new().await;
    let g = w.ensure_grant("req-row7-a").await;
    let op = OperationId::from_random_bytes([0x7a; 16]);
    w.store
        .transaction(|tx| tx.record_cleanup_intent(&intent(&g, &op, elsewhere.clone())))
        .unwrap();
    let sup = w.supervisor().with_revocation_backoff(backoff);
    for _ in 0..3 {
        let r = sup.revocation_pass().await.unwrap();
        assert!(r.intents_scheduled.is_empty() && r.intents_stopped.is_empty());
    }
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intent(&g, &op))
            .unwrap()
            .is_some()
    );

    // With a remote-effect adapter: backed off, then capped.
    let w = World::with(true, Limits::default()).await;
    let g = w.ensure_grant("req-row7-b").await;
    w.store
        .transaction(|tx| tx.record_cleanup_intent(&intent(&g, &op, elsewhere.clone())))
        .unwrap();
    let jitter = 0.5;
    let sup = w
        .supervisor()
        .with_revocation_backoff(backoff)
        .with_jitter(Arc::new(FixedJitter(jitter)));
    let mut delays = Vec::new();
    for n in 1..backoff.max_attempts {
        let r = sup.revocation_pass().await.unwrap();
        assert_eq!(r.intents_scheduled.len(), 1, "processing {n}: {r:?}");
        let (rg, rop, attempts, delay) = r.intents_scheduled[0].clone();
        assert_eq!((rg, rop, attempts), (g.clone(), op.clone(), n));
        assert_eq!(delay, backoff.jittered(n, jitter));
        assert!(delay >= backoff.delay(n) / 2 && delay <= backoff.max);
        assert!(r.next_due_in.is_some_and(|d| d <= delay));
        // Not processed again before its delay.
        w.clock
            .advance(delay.saturating_sub(Duration::from_millis(1)));
        let r = sup.revocation_pass().await.unwrap();
        assert!(r.intents_scheduled.is_empty(), "early pass {n}: {r:?}");
        w.clock.advance(Duration::from_millis(1));
        delays.push(delay);
    }
    let r = sup.revocation_pass().await.unwrap();
    assert_eq!(r.intents_stopped, [(g.clone(), op.clone())]);
    for _ in 0..3 {
        w.clock.advance(Duration::from_secs(3600));
        let r = sup.revocation_pass().await.unwrap();
        assert!(r.intents_scheduled.is_empty() && r.intents_stopped.is_empty());
    }
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intent(&g, &op))
            .unwrap()
            .is_some(),
        "kept for the next restart"
    );
    assert!(delays.windows(2).all(|d| d[0] <= d[1]), "{delays:?}");
}

/// U0b row 7 with its app part (agent G's `process_cleanup_intent` change): an
/// immediate revoke to an adapter with a remote credential effect that times out
/// keeps the intent; the supervisor makes the next call only after the jittered
/// back-off (no call in between), and once that call is answered the intent is
/// cleared.
#[tokio::test]
async fn timed_out_remote_effect_intent_retried_after_backoff() {
    let limits = Limits {
        adapter_call_timeout: Duration::from_millis(50),
        ..Limits::default()
    };
    let w = World::with(true, limits).await;
    let g = w.ensure_grant("req-row7-c").await;
    let op = OperationId::from_random_bytes([0x7c; 16]);
    w.store
        .transaction(|tx| tx.record_cleanup_intent(&intent(&g, &op, fake_identity())))
        .unwrap();
    let backoff = Backoff {
        base: Duration::from_millis(200),
        max: Duration::from_millis(800),
        max_attempts: 5,
    };
    let sup = w
        .supervisor()
        .with_revocation_backoff(backoff)
        .with_jitter(Arc::new(FixedJitter(0.25)));
    w.fake.arm(FakeStep::HangRevoke);
    let r = sup.revocation_pass().await.unwrap();
    assert_eq!(w.fake.hangs_entered(), 1, "the immediate call was made");
    assert_eq!(w.fake.hangs_dropped(), 1, "and dropped at its bound");
    assert!(w.fake.revocations.lock().unwrap().is_empty());
    assert_eq!(r.intents_scheduled.len(), 1, "{r:?}");
    let delay = r.intents_scheduled[0].3;
    assert_eq!(delay, backoff.jittered(1, 0.25));
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intent(&g, &op))
            .unwrap()
            .is_some(),
        "kept after the timeout"
    );
    w.clock
        .advance(delay.saturating_sub(Duration::from_millis(1)));
    sup.revocation_pass().await.unwrap();
    assert!(
        w.fake.revocations.lock().unwrap().is_empty(),
        "no call before the delay"
    );
    w.clock.advance(Duration::from_millis(1));
    let r = sup.revocation_pass().await.unwrap();
    assert!(
        r.intents_scheduled.is_empty() && r.intents_stopped.is_empty(),
        "{r:?}"
    );
    assert_eq!(
        *w.fake.revocations.lock().unwrap(),
        std::slice::from_ref(&g)
    );
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intent(&g, &op))
            .unwrap()
            .is_none(),
        "cleared once answered"
    );
}

// =================================================================================
// Row 23: CA retirement at restart
// =================================================================================

fn issuer_record(n: u8) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: ca(n),
        public_key: format!("ssh-ed25519 AAAASYNTHETIC{n}"),
        state: CaState::Active,
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: "3".repeat(64),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: shift(t0(), i64::from(n)),
        retired_at: None,
    }
}

/// Register CA `n` and move it along D4 item 3 until `state`.
fn seed_ca(w: &World, n: u8, state: CaState) -> CaFingerprint {
    let r = issuer_record(n);
    let fp = r.ca_fingerprint.clone();
    w.store
        .transaction(|tx| {
            tx.insert_issuer(&r)?;
            let path = [
                (CaState::Active, CaEvent::RetireApproved),
                (CaState::Retiring, CaEvent::UnloadConfirmed),
                (CaState::Unloaded, CaEvent::StoreItemDeleted),
                (CaState::Deleted, CaEvent::RetirementRecorded),
            ];
            for (from, event) in path {
                if from == state {
                    break;
                }
                tx.set_issuer_state(&fp, from, event, t0())?.unwrap();
            }
            Ok(())
        })
        .unwrap();
    fp
}

fn ca_state(w: &World, fp: &CaFingerprint) -> CaState {
    w.store
        .transaction(|tx| tx.issuer(fp))
        .unwrap()
        .unwrap()
        .state
}

/// A scripted issuer child: `unload` answers `Ok` unless told to fail; counts calls.
struct FakeIssuer {
    fail: bool,
    unloads: Mutex<Vec<CaFingerprint>>,
}

impl IssuerPort for FakeIssuer {
    fn status(&self) -> IssuerStatusSnapshot {
        IssuerStatusSnapshot {
            status: IssuerStatus {
                state: IssuerState::Ready,
                reason: None,
                cas: Vec::new(),
                orphan_store_items: Vec::new(),
                issuer_isolation: IssuerIsolation::SameUserProcess,
                bundle_stale: false,
            },
        }
    }

    fn sign<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _entry: IssuanceRef,
        _subject: &'life1 str,
    ) -> Pin<Box<dyn Future<Output = Result<String, IssuerError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async { Err(IssuerError::Unavailable("fixture".into())) })
    }

    fn unload<'life0, 'life1, 'async_trait>(
        &'life0 self,
        ca: &'life1 CaFingerprint,
    ) -> Pin<Box<dyn Future<Output = Result<(), IssuerError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.unloads.lock().unwrap().push(ca.clone());
            if self.fail {
                Err(IssuerError::Timeout)
            } else {
                Ok(())
            }
        })
    }
}

/// A scripted store-deletion step.
struct FakeStoreItems {
    fail: bool,
    deletes: AtomicUsize,
}

impl CaStoreItemDeletion for FakeStoreItems {
    fn delete_confirmed_absent(
        &self,
        _ca: &CaFingerprint,
        _store: StoreKind,
    ) -> Result<(), IssuerError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(IssuerError::Unavailable("store locked".into()))
        } else {
            Ok(())
        }
    }
}

/// U0b row 23 (ADR-0008 D4 item 3): a CA in `retiring`, `unloaded` or `deleted`
/// resumes its retirement at its next step, each step persisted only after its
/// external effect was confirmed.
///
/// * Production wiring at restart (no issuer child, no store-deletion step, wave
///   0): `retiring` and `unloaded` stay where they are (never marked further
///   without the effect), `deleted` completes to `retired`; every CA that is not
///   `pending`/`active` is reported as not to be loaded.
/// * With fakes: `retiring → unloaded → deleted → retired` (one unload, one
///   deletion), `unloaded → deleted → retired`; a failed unload keeps `retiring`, a
///   failed deletion keeps `unloaded`; `active` is untouched. A second call does
///   nothing more (idempotent).
#[tokio::test]
async fn retirement_resumes_at_start_from_each_state() {
    // Production wiring through a restart.
    let mut w = World::new().await;
    let active = seed_ca(&w, 0, CaState::Active);
    let retiring = seed_ca(&w, 1, CaState::Retiring);
    let unloaded = seed_ca(&w, 2, CaState::Unloaded);
    let deleted = seed_ca(&w, 3, CaState::Deleted);
    w.restart().await;
    assert_eq!(ca_state(&w, &active), CaState::Active);
    assert_eq!(ca_state(&w, &retiring), CaState::Retiring);
    assert_eq!(ca_state(&w, &unloaded), CaState::Unloaded);
    assert_eq!(ca_state(&w, &deleted), CaState::Retired);
    let r = w.ops.resume_ca_retirements(None, None).await.unwrap();
    assert_eq!(
        r.do_not_load,
        [retiring.clone(), unloaded.clone(), deleted.clone()]
            .into_iter()
            .collect()
    );
    assert!(
        r.advanced.is_empty(),
        "nothing more without the issuer: {r:?}"
    );
    assert_eq!(
        r.stalled
            .iter()
            .map(|(fp, s, _)| (fp.clone(), *s))
            .collect::<Vec<_>>(),
        [
            (retiring.clone(), CaState::Retiring),
            (unloaded.clone(), CaState::Unloaded)
        ]
    );

    // Fakes that confirm each step.
    let issuer = FakeIssuer {
        fail: false,
        unloads: Mutex::new(Vec::new()),
    };
    let items = FakeStoreItems {
        fail: false,
        deletes: AtomicUsize::new(0),
    };
    let r: RetirementResume = w
        .ops
        .resume_ca_retirements(Some(&issuer), Some(&items))
        .await
        .unwrap();
    assert_eq!(
        r.advanced,
        [
            (retiring.clone(), CaState::Retiring, CaState::Unloaded),
            (retiring.clone(), CaState::Unloaded, CaState::Deleted),
            (retiring.clone(), CaState::Deleted, CaState::Retired),
            (unloaded.clone(), CaState::Unloaded, CaState::Deleted),
            (unloaded.clone(), CaState::Deleted, CaState::Retired),
        ]
    );
    assert!(r.stalled.is_empty());
    assert_eq!(
        *issuer.unloads.lock().unwrap(),
        std::slice::from_ref(&retiring)
    );
    assert_eq!(items.deletes.load(Ordering::SeqCst), 2);
    for fp in [&retiring, &unloaded, &deleted] {
        assert_eq!(ca_state(&w, fp), CaState::Retired, "{fp}");
        assert!(
            w.store
                .transaction(|tx| tx.issuer(fp))
                .unwrap()
                .unwrap()
                .retired_at
                .is_some()
        );
    }
    assert_eq!(ca_state(&w, &active), CaState::Active);
    let again = w
        .ops
        .resume_ca_retirements(Some(&issuer), Some(&items))
        .await
        .unwrap();
    assert!(
        again.advanced.is_empty() && again.stalled.is_empty(),
        "idempotent"
    );
    assert_eq!(issuer.unloads.lock().unwrap().len(), 1);

    // Failing steps keep the state.
    let w = World::new().await;
    let retiring = seed_ca(&w, 4, CaState::Retiring);
    let unloaded = seed_ca(&w, 5, CaState::Unloaded);
    let issuer = FakeIssuer {
        fail: true,
        unloads: Mutex::new(Vec::new()),
    };
    let items = FakeStoreItems {
        fail: true,
        deletes: AtomicUsize::new(0),
    };
    let r = w
        .ops
        .resume_ca_retirements(Some(&issuer), Some(&items))
        .await
        .unwrap();
    assert!(r.advanced.is_empty());
    assert_eq!(ca_state(&w, &retiring), CaState::Retiring);
    assert_eq!(ca_state(&w, &unloaded), CaState::Unloaded);
    assert_eq!(r.stalled.len(), 2);
    assert!(r.do_not_load.contains(&retiring) && r.do_not_load.contains(&unloaded));
}

// =================================================================================
// Row 28: procstat
// =================================================================================

/// The pre-M03 Linux rule of `process_start_time` (`platform.rs` at 410ec237),
/// kept here verbatim as the oracle: cut at the last `)`, refuse a missing or `Z`/`X`
/// first token, take token 20 if it is all digits. (The boot-ID prefix is added by
/// both and left out.)
fn old_rule(stat: &str) -> Option<String> {
    let after = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = after.split_whitespace();
    if matches!(fields.next(), Some("Z" | "X") | None) {
        return None;
    }
    let start = fields.nth(18)?;
    if start.is_empty() || !start.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(start.to_owned())
}

fn stat_line(comm: &str, state: &str, pgrp: &str, start: &str) -> String {
    format!(
        "4242 ({comm}) {state} 1 {pgrp} 4242 0 -1 4194304 10 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 200 18446744073709551615\n"
    )
}

/// U0b row 28 (ADR-0008 §17.13 item 2; wave-0 verify E9 reading (a)):
/// `process_start_time` now reads `/proc/<pid>/stat` through the shared parser and
/// its semantics are unchanged: on every synthetic line a kernel can produce (any
/// `comm`, every state letter, process group 0 or any value, canonical decimal start
/// times, short and malformed lines) `stat_start_time` agrees with the old rule
/// (`Z`/`X` refused, group 0 accepted). The documented deltas are only for text no
/// kernel produces (a multi-letter state, a start time with leading zeros or beyond
/// `u64`). On Linux, this process's own start time equals the old rule over its own
/// `/proc/self/stat`, with the boot-ID prefix.
#[test]
fn platform_start_time_uses_shared_parser_semantics_unchanged() {
    use heimdall_runtime::platform::stat_start_time;
    let comms = [
        "sh",
        "a b",
        "x) (y",
        "evil) R 1 9 9",
        "new\nline",
        ")",
        "(",
        "z) Z 1",
    ];
    let states = ["R", "S", "D", "Z", "X", "T", "t", "I", "W", "P"];
    let groups = ["0", "1", "77", "4194304", "-1", "x"];
    let starts = ["0", "1", "123456", "18446744073709551615"];
    let mut checked = 0;
    for comm in comms {
        for state in states {
            for pgrp in groups {
                for start in starts {
                    let line = stat_line(comm, state, pgrp, start);
                    assert_eq!(
                        stat_start_time(&line).map(|s| s.to_string()),
                        old_rule(&line),
                        "{line:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 1000);
    // Short and malformed lines: both refuse.
    for line in [
        "",
        "4242 sh S 1 2",
        "4242 (sh) S 1 77 4242",
        "4242 (sh)",
        "4242 (sh) S 1 77 4242 0 -1 4194304 10 0 0 0 1 2 0 0 20 0 1 0",
        &stat_line("sh", "S", "7", "-1"),
        &stat_line("sh", "S", "7", "1.5"),
        &stat_line("sh", "S", "7", "abc"),
    ] {
        assert_eq!(
            stat_start_time(line).map(|s| s.to_string()),
            old_rule(line),
            "{line:?}"
        );
        assert_eq!(stat_start_time(line), None, "{line:?}");
    }
    // Deltas no kernel produces (recorded, not hidden): the old rule accepted these.
    for (line, old) in [
        (stat_line("sh", "SS", "7", "5"), Some("5")),
        (stat_line("sh", "S", "7", "007"), Some("007")),
        (
            stat_line("sh", "S", "7", "99999999999999999999999"),
            Some("99999999999999999999999"),
        ),
    ] {
        assert_eq!(old_rule(&line).as_deref(), old, "{line:?}");
    }
    assert_eq!(stat_start_time(&stat_line("sh", "SS", "7", "5")), None);
    assert_eq!(stat_start_time(&stat_line("sh", "S", "7", "007")), Some(7));
    assert_eq!(
        stat_start_time(&stat_line("sh", "S", "7", "99999999999999999999999")),
        None
    );

    #[cfg(target_os = "linux")]
    {
        let own = std::fs::read_to_string("/proc/self/stat").unwrap();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let expected = format!("{}:{}", boot.trim(), old_rule(&own).unwrap());
        assert_eq!(
            heimdall_runtime::platform::process_start_time(std::process::id()),
            Some(expected)
        );
    }
}

/// U0b row 28 at the runtime level: `comm` with spaces, parentheses (including a
/// fake state and fields inside it) and a newline never shifts the fields
/// `stat_start_time` reads. On Linux, a real child whose executable name carries
/// spaces and parentheses has a start time, equal for two reads.
#[test]
fn procstat_comm_with_spaces_parentheses_and_newline() {
    use heimdall_runtime::platform::stat_start_time;
    for comm in [
        "sh",
        "a b",
        "x) (y",
        "evil) R 1 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9 9",
        "new\nline",
        ")",
        ") Z 1 1",
        "((((",
    ] {
        assert_eq!(
            stat_start_time(&stat_line(comm, "S", "77", "123456")),
            Some(123_456),
            "{comm:?}"
        );
        assert_eq!(
            stat_start_time(&stat_line(comm, "S", "0", "42")),
            Some(42),
            "{comm:?}: group 0"
        );
        assert_eq!(
            stat_start_time(&stat_line(comm, "Z", "77", "42")),
            None,
            "{comm:?}: zombie"
        );
        assert_eq!(
            stat_start_time(&stat_line(comm, "X", "77", "42")),
            None,
            "{comm:?}: dead"
        );
    }
    #[cfg(target_os = "linux")]
    {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("a b) (c");
        std::os::unix::fs::symlink("/bin/sleep", &link).unwrap();
        let mut child = std::process::Command::new(&link)
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let first = heimdall_runtime::platform::process_start_time(child.id());
        let second = heimdall_runtime::platform::process_start_time(child.id());
        // Stopped by its own handle (exact PID), then reaped.
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(first.is_some());
        assert_eq!(first, second);
    }
}

// =================================================================================
// E7: the issuer endpoint kind is reserved
// =================================================================================

/// Wave-0 verify E7 (ADR-0008 Q1): `EndpointKind::Issuer` is reserved and never
/// bound. On Unix `Listener::bind` refuses it with the typed
/// `IssuerEndpointReserved` (`ErrorKind::Unsupported`) before anything is created
/// (the missing runtime directory stays missing), while the control kind binds in
/// the same place. The Windows constructor has the same refusal (compiled for the
/// Windows target; needs a native Windows run).
#[tokio::test]
async fn issuer_endpoint_kind_reserved_never_bound() {
    use heimdall_ipc::EndpointKind;
    #[cfg(unix)]
    {
        use heimdall_ipc::unix::{IssuerEndpointReserved, Listener};
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("rt");
        let path = dir.join("issuer.sock");
        let e = Listener::bind(&path, EndpointKind::Issuer).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
        assert!(
            e.get_ref()
                .and_then(|i| i.downcast_ref::<IssuerEndpointReserved>())
                .is_some(),
            "{e}"
        );
        assert!(!dir.exists(), "nothing was created");
        // Control binds where Issuer was refused.
        let control = Listener::bind(&dir.join("control.sock"), EndpointKind::Control).unwrap();
        drop(control);
    }
    #[cfg(windows)]
    {
        use heimdall_ipc::windows::{IssuerEndpointReserved, Listener};
        let name = format!(r"\\.\pipe\heimdall-w0-issuer-{}", std::process::id());
        let e = Listener::bind(&name, EndpointKind::Issuer, "S-1-5-21-1-2-3-1001").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
        assert!(
            e.get_ref()
                .and_then(|i| i.downcast_ref::<IssuerEndpointReserved>())
                .is_some(),
            "{e}"
        );
    }
}

// =================================================================================
// §5 item 22: configuration
// =================================================================================

/// m03-plan §5 item 22: `lock_behavior` and `registry_path` are refused under
/// `[x]`, at any depth inside it and whatever their spelling (`-` and case
/// normalized). Outside `[x]` the typed schema governs: the M01 session default
/// `session.lock_behavior` still parses, and `registry_path` is an unknown key
/// (refused as such).
#[test]
fn config_refuses_lock_behavior_and_registry_path() {
    use heimdall_runtime::config::{Config, ConfigError, FORBIDDEN_UNDER_X};
    assert_eq!(FORBIDDEN_UNDER_X, ["lock_behavior", "registry_path"]);
    for (key, expected) in [
        ("lock_behavior", "lock_behavior"),
        ("lock-behavior", "lock_behavior"),
        ("LOCK_BEHAVIOR", "lock_behavior"),
        ("registry_path", "registry_path"),
        ("Registry-Path", "registry_path"),
    ] {
        for text in [
            format!("schema_version = 1\n[x]\n{key} = \"revoke\"\n"),
            format!("schema_version = 1\n[x.managed]\n{key} = \"/home/u/.ssh/authorized_keys\"\n"),
            format!("schema_version = 1\n[x]\nlist = [{{ {key} = 1 }}]\n"),
            format!("schema_version = 1\n[x.a.b]\nc = {{ {key} = true }}\n"),
        ] {
            match Config::parse(&text) {
                Err(ConfigError::ForbiddenKey(k)) => assert_eq!(k, expected, "{text:?}"),
                other => panic!("{text:?}: expected ForbiddenKey, got {other:?}"),
            }
        }
    }
    // Outside `[x]`: the typed M01 key is unchanged; `registry_path` is unknown.
    let c = Config::parse(
        "schema_version = 1\n[session]\nmax_window = \"8h\"\nlock_behavior = \"revoke\"\n",
    )
    .unwrap();
    assert_eq!(
        c.session.lock_behavior,
        heimdall_runtime::config::LockBehavior::Revoke
    );
    for text in [
        "schema_version = 1\nregistry_path = \"/x\"\n",
        "schema_version = 1\n[session]\nmax_window = \"8h\"\nregistry_path = \"/x\"\n",
    ] {
        assert!(
            matches!(Config::parse(text), Err(ConfigError::Parse(_))),
            "{text:?}"
        );
    }
    // An ordinary `[x]` key is still tolerated.
    assert!(Config::parse("schema_version = 1\n[x]\nnote = \"lock\"\n").is_ok());
}

// =================================================================================
// w0_no_reachable_todo
// =================================================================================

/// Run `f` on its own task: a panic (a reachable `todo!()` included) is a test
/// failure that names `what`.
async fn no_panic<F, T>(what: &str, f: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::spawn(f).await {
        Ok(v) => v,
        Err(e) => panic!(
            "{what}: panicked or cancelled ({})",
            if e.is_panic() { "panic" } else { "cancelled" }
        ),
    }
}

/// The `*.rs` files under `crates/*/src`, recursively.
fn production_sources() -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for c in std::fs::read_dir(repo_root().join("crates")).unwrap() {
        let src = c.unwrap().path().join("src");
        if src.is_dir() {
            walk(&src, &mut out);
        }
    }
    out
}

/// m03-plan U0b wave-0 acceptance: no `todo!()` is reachable.
///
/// 1. Every `Request` variant (one of each, M03 ones included) through the real
///    dispatcher, as owner and as a limited consumer, attended and not: none panics,
///    and each M03 one answers its fail-closed result (`driver_unavailable`, or the
///    owner-role refusal, or `INTERACTION_REQUIRED` for an unattended
///    attended-only request).
/// 2. Restart recovery with an open operation of every M03 kind and a pending
///    decision of every M03 kind on record, a credential instance, a CA in each
///    retirement state and a bounded obligation: none panics.
/// 3. Every supervisor pass (time guard, scheduler with the revocation pass and the
///    bounded step, holder, cleanup, managed re-issue), before and after every
///    deadline: none panics.
/// 4. A source scan: no `todo!(` or `unimplemented!(` on a non-comment line of any
///    `crates/*/src/**/*.rs`.
///
/// CLI paths are `e2e_cli_m03`'s (the `heimdall` crate is not a dependency here).
#[tokio::test]
async fn w0_no_reachable_todo() {
    // 1. The dispatch table.
    let w = World::new().await;
    let d = w.dispatcher();
    let requests = every_request();
    assert!(requests.len() >= 40, "{}", requests.len());
    for r in requests {
        let m03 = matches!(
            r,
            Request::Issuer(_) | Request::Enrollment(_) | Request::Connections(_)
        );
        for caller in [
            attended(ClientRole::Owner),
            unattended(ClientRole::Owner),
            attended(ClientRole::LimitedConsumer),
        ] {
            let what = format!(
                "{} as {:?}/{}",
                r.kind(),
                caller.context.role,
                caller.is_attended()
            );
            let (d2, r2, c2) = (d.clone(), r.clone(), caller.clone());
            let env = no_panic(&what, async move { d2.handle_as(&c2, r2).await }).await;
            assert_no_canary(&serde_json::to_string(&env).unwrap());
            if !m03 {
                continue;
            }
            if r.requires_attended_session() && !caller.is_attended() {
                assert_eq!(env.code, Code::InteractionRequired, "{what}");
            } else if owner_only_m03(&r) && !caller.context.is_owner() {
                assert_eq!(env.code, Code::CapabilityUnavailable, "{what}");
                assert_eq!(reason_of(&env), None, "{what}");
            } else {
                assert_driver_unavailable(&env, &what);
            }
        }
    }

    // 2. Restart recovery with every M03 operation and decision kind present.
    let mut w = World::new().await;
    let ops: Vec<OperationId> = (0x90u8..)
        .zip(OperationKind::ENROLLMENT)
        .map(|(n, kind)| seed_operation(&w, n, kind, OperationState::Running))
        .collect();
    let decisions: Vec<DecisionId> = m03_decision_kinds()
        .into_iter()
        .enumerate()
        .map(|(i, k)| insert_decision(&w, 0xa0 + u8::try_from(i).unwrap(), k))
        .collect();
    let g = w.ensure_grant("req-todo-a").await;
    w.store
        .transaction(|tx| {
            tx.insert_credential_instance(&instance(9, &g, CredentialState::Installed, Vec::new()))
        })
        .unwrap();
    for (i, s) in [
        CaState::Active,
        CaState::Retiring,
        CaState::Unloaded,
        CaState::Deleted,
    ]
    .into_iter()
    .enumerate()
    {
        seed_ca(&w, 10 + u8::try_from(i).unwrap(), s);
    }
    let b = revoking_with(&w, "req-todo-b", |g| {
        vec![bounded(
            g,
            fake_identity(),
            shift(t0(), 60),
            DestinationClock::Unmeasured,
        )]
    })
    .await;
    let config = config_of(&w.store, &w.clock, &w.sync, &w.fake, w.limits);
    let restarted = no_panic("restart recovery", async move {
        Operations::start(config).await
    })
    .await;
    assert!(restarted.is_ok());
    w.restart().await;
    for id in &ops {
        assert_eq!(
            w.store
                .transaction(|tx| tx.operation(id))
                .unwrap()
                .unwrap()
                .state,
            OperationState::Running
        );
    }
    for id in &decisions {
        assert_eq!(decision_state(&w, id), DecisionState::Pending);
    }

    // 3. Every supervisor pass, before and after every deadline.
    let sup = Arc::new(w.supervisor());
    for step in 0..3 {
        let s = sup.clone();
        no_panic("time guard", async move { s.time_guard_pass().await })
            .await
            .unwrap();
        let s = sup.clone();
        no_panic("scheduler", async move { s.scheduler_pass().await })
            .await
            .unwrap();
        let s = sup.clone();
        no_panic("revocation", async move { s.revocation_pass().await })
            .await
            .unwrap();
        let s = sup.clone();
        no_panic("holder", async move { s.holder_pass().await })
            .await
            .unwrap();
        let s = sup.clone();
        no_panic("cleanup", async move { s.cleanup_pass().await })
            .await
            .unwrap();
        let s = sup.clone();
        no_panic(
            "managed re-issue",
            async move { s.managed_reissue_pass().await },
        )
        .await
        .unwrap();
        if step == 1 {
            w.clock.advance(Duration::from_secs(2 * 86_400));
        } else {
            w.clock.advance(Duration::from_secs(61));
        }
    }
    assert_eq!(
        w.grant_state(&b),
        GrantState::Revoked,
        "the bounded step ran"
    );
    // The M03 decisions are not consumed by the passes either (an expired one is
    // refused as stale, never completed).
    for id in &decisions {
        assert_ne!(decision_state(&w, id), DecisionState::Approved);
    }

    // 4. Source scan.
    let mut hits = Vec::new();
    let sources = production_sources();
    assert!(sources.len() > 50, "{}", sources.len());
    for path in sources {
        let text = std::fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains("todo!(") || code.contains("unimplemented!(") {
                hits.push(format!("{}:{}", path.display(), i + 1));
            }
        }
    }
    assert!(hits.is_empty(), "reachable placeholders: {hits:?}");
}
