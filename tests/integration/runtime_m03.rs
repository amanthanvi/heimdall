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

/// ⟨wave 4⟩ U0b phase 2 on an **unwired** runtime: the request is refused (an error
/// envelope), with no operation ID and effect `none`. Which refusal is the driver's:
/// `driver_unavailable` where the missing port is the first thing it meets, or the
/// refusal it reaches first without writing (an unknown record, the owner role, a
/// stale decision). The callers also check that nothing was written.
fn assert_fail_closed(env: &Envelope<serde_json::Value>, what: &str) {
    assert!(
        env.data.get("error").is_some(),
        "{what}: refused, got {:?} {:?}",
        env.code,
        env.data
    );
    assert!(
        !matches!(env.code, Code::Ok | Code::AccessReady | Code::Accepted),
        "{what}: {:?}",
        env.code
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
            ca_public_key: None,
            backup_created_at: None,
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

/// U0b row 13, phase 2 (wave 4), on an **unwired** runtime (no M03 port set, no
/// connection control: what every M01/M02 runtime is): every `Request::{Issuer,
/// Enrollment, Connections}` reaching the real dispatcher from the owner on an attended
/// session still answers `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, effect
/// `none`, with no operation ID, and nothing in the store changes (row counts, every raw
/// document table, operations, decisions, events). Unattended, `Issuer::Unlock` is
/// refused `INTERACTION_REQUIRED` first (attended-only), also writing nothing. (Phase 1
/// asserted the same of the fail-closed arms; phase 2 routes to U10's drivers, which
/// fail closed before any write without their ports.)
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
        assert_fail_closed(&env, &what);
        let env = d.handle_as(&unattended(ClientRole::Owner), r.clone()).await;
        if r.requires_attended_session() {
            assert_eq!(env.code, Code::InteractionRequired, "{what}");
        } else {
            assert_fail_closed(&env, &what);
        }
    }
    // Connection control is the runtime's: unwired, exactly `driver_unavailable`.
    for r in m03_requests()
        .into_iter()
        .filter(|r| matches!(r, Request::Connections(_)))
    {
        let env = d.handle_as(&attended(ClientRole::Owner), r.clone()).await;
        assert_driver_unavailable(&env, r.kind());
    }
    assert_eq!(w.snapshot(), before, "nothing was written");
}

/// U0b row 13 (F20), phase 2 on an unwired runtime: `Enrollment::{Step, StepResult,
/// Reconcile}` and `Connections::{Close, Register}` are refused for any role but owner,
/// with `CAPABILITY_UNAVAILABLE` and **no** `driver_unavailable` reason (the role
/// refusal comes first: authorization before capability, so a non-owner learns
/// nothing about this build's drivers); the other M03 requests are refused to a
/// non-owner too (the driver's fail-closed answer). Nothing is written.
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
            // The owner gets the driver's (fail-closed) answer for the same request.
            let env = d.handle_as(&attended(ClientRole::Owner), r.clone()).await;
            assert_fail_closed(&env, &what);
        } else {
            assert_fail_closed(&env, &what);
        }
    }
    assert_eq!(
        owner_only, 5,
        "step, step_result, reconcile, close, register"
    );
    assert_eq!(w.snapshot(), before, "nothing was written");
}

/// `capabilities_offered_after_activation` (U0b row 13, phase 2; retires
/// `w0_m03_capabilities_not_offered`; §5 item 15): the four M03 capabilities are
/// offered by the server and listed by `inspect capabilities` (the two lists agree), a
/// hello requiring each is accepted, and on a session that negotiated them an M03
/// request is dispatched (an unwired runtime answers `driver_unavailable`, writing
/// nothing), while a session that did not negotiate them is still refused
/// `SCHEMA_UNSUPPORTED` by the gate before dispatch.
#[tokio::test]
async fn capabilities_offered_after_activation() {
    use heimdall_contract::ipc::{PeerInfo, PrincipalInfo};
    use heimdall_ipc::session::{ConnectionLimits, ControlConnection, server_capabilities};
    let offered = server_capabilities();
    for c in capability::M03_DECLARED {
        assert!(offered.contains(c), "{c} not offered");
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
    let listed: BTreeSet<String> = inspect.data["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(listed, offered, "inspect capabilities lists the offer");
    let open = |required: BTreeSet<String>, offer: BTreeSet<String>| {
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
            let client = RawClient::handshake(stream, offer, required).await;
            (client, served)
        }
    };
    let before = w.snapshot();
    // A hello requiring each M03 capability is accepted.
    for c in capability::M03_DECLARED {
        let required: BTreeSet<String> = [c.to_owned()].into_iter().collect();
        let (client, _served) = open(required.clone(), required).await;
        let client = client.unwrap();
        assert!(client.negotiated.contains(c), "{c} negotiated");
    }
    // Negotiated: dispatched, and an unwired runtime answers `driver_unavailable`.
    let all: BTreeSet<String> = capability::M03_DECLARED
        .iter()
        .map(|c| (*c).to_owned())
        .collect();
    let (client, _served) = open(BTreeSet::new(), all).await;
    let mut client = client.unwrap();
    for r in m03_requests() {
        let env = client.request(r.clone()).await;
        assert_ne!(
            env.code,
            Code::SchemaUnsupported,
            "{}: dispatched",
            r.kind()
        );
        if r.requires_attended_session() {
            assert_eq!(env.code, Code::InteractionRequired, "{}", r.kind());
        } else {
            assert_fail_closed(&env, r.kind());
        }
    }
    // Not negotiated: refused by the gate before dispatch.
    let (client, _served) = open(BTreeSet::new(), BTreeSet::new()).await;
    let mut client = client.unwrap();
    for r in m03_requests() {
        let env = client.request(r.clone()).await;
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

/// A control client that offers exactly the capabilities it is given (the production
/// `ControlClient` offers every capability the server serves). Frames are the
/// production codec's (`heimdall_ipc::frame`).
struct RawClient {
    stream: tokio::io::DuplexStream,
    buf: Vec<u8>,
    seq: u64,
    /// The capabilities the server's hello negotiated.
    negotiated: BTreeSet<String>,
}

impl RawClient {
    /// Send a hello offering `capabilities` and requiring `required`; `Err` is the
    /// server's rejection.
    async fn handshake(
        mut stream: tokio::io::DuplexStream,
        capabilities: BTreeSet<String>,
        required: BTreeSet<String>,
    ) -> Result<Self, Box<Envelope<heimdall_contract::envelope::ErrorData>>> {
        use heimdall_contract::ipc::{ClientHello, ClientMessage, PeerInfo, ServerMessage};
        use heimdall_ipc::frame::{CONTROL_LIMIT, encode_frame};
        use tokio::io::AsyncWriteExt;
        let hello = ClientMessage::Hello(ClientHello {
            protocol: heimdall_contract::PROTOCOL_VERSION,
            schema_version: heimdall_contract::SchemaVersion::current(),
            client: PeerInfo {
                name: "w4-m03".into(),
                version: "0".into(),
            },
            capabilities,
            required,
            interaction: InteractionMode::NonInteractive,
        });
        stream
            .write_all(&encode_frame(&hello, CONTROL_LIMIT).unwrap())
            .await
            .unwrap();
        let mut me = Self {
            stream,
            buf: Vec::new(),
            seq: 0,
            negotiated: BTreeSet::new(),
        };
        match me.next().await {
            ServerMessage::Hello(h) => {
                me.negotiated = h.capabilities;
                Ok(me)
            }
            ServerMessage::Reject(env) => Err(Box::new(env)),
            _ => panic!("unexpected first server frame"),
        }
    }

    async fn next(&mut self) -> heimdall_contract::ipc::ServerMessage {
        use heimdall_ipc::frame::{CONTROL_LIMIT, decode_frame};
        use tokio::io::AsyncReadExt;
        loop {
            if let Some((msg, used)) =
                decode_frame::<heimdall_contract::ipc::ServerMessage>(&self.buf, CONTROL_LIMIT)
                    .unwrap()
            {
                self.buf.drain(..used);
                return msg;
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the server closed the connection");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Send `request` and return its response.
    async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
        use heimdall_contract::ipc::{ClientMessage, ServerMessage};
        use heimdall_ipc::frame::{CONTROL_LIMIT, encode_frame};
        use tokio::io::AsyncWriteExt;
        self.seq += 1;
        let seq = self.seq;
        let frame = encode_frame(&ClientMessage::Request { seq, request }, CONTROL_LIMIT).unwrap();
        self.stream.write_all(&frame).await.unwrap();
        loop {
            if let ServerMessage::Response {
                in_reply_to,
                envelope,
            } = self.next().await
                && in_reply_to == seq
            {
                return envelope;
            }
        }
    }
}

// =================================================================================
// Row 14: decision kinds
// =================================================================================

/// U0b row 14, phase 2 (wave 4) on an unwired runtime: a pending decision record of
/// each M03 kind, decided (approve and deny) through the real dispatcher on an attended
/// owner session, is refused (the kind's fail-closed answer: `driver_unavailable` where
/// its completion needs a missing M03 port, or the refusal its precheck reaches first,
/// such as `DECISION_STALE` for a registration whose key this runtime does not hold) and
/// stays `pending`: not consumed, no decision event, no operation touched. (Completion
/// with the ports wired is U10-A's and U10-B's.)
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
    let counts = |w: &World| {
        let c = w.store.transaction(|tx| tx.table_counts()).unwrap();
        (
            c.operations,
            c.grants,
            c.identities,
            c.destinations,
            c.idempotency,
        )
    };
    let counts_before = counts(&w);
    let owner = attended(ClientRole::Owner);
    let decide = |id: &DecisionId, verdict| {
        d.handle_as(
            &owner,
            Request::Decide(DecideRequest {
                decision_id: id.clone(),
                verdict,
            }),
        )
    };
    let mut denied = 0;
    for id in &ids {
        // Approve: the completion needs the kind's M03 port (or its precheck refuses
        // first): refused, not consumed, no decision event.
        let events = decision_events(&w);
        let env = decide(id, Verdict::Approve).await;
        assert_fail_closed(&env, &format!("{id} approve"));
        assert_eq!(decision_state(&w, id), DecisionState::Pending, "{id}");
        assert_eq!(decision_events(&w), events, "{id}: no decision event");
        // Deny: either refused the same way, or (phase 2) completed `denied` exactly
        // once with its decision event and nothing else written: no operation, grant
        // or catalog record is touched.
        let env = decide(id, Verdict::Deny).await;
        match decision_state(&w, id) {
            DecisionState::Pending => {
                assert_fail_closed(&env, &format!("{id} deny"));
                assert_eq!(decision_events(&w), events, "{id}");
            }
            DecisionState::Denied => {
                assert_eq!(env.code, Code::Ok, "{id}: {:?}", env.data);
                assert_eq!(env.data["operation_id"], serde_json::Value::Null);
                assert_eq!(decision_events(&w), events + 1, "{id}: one decision event");
                denied += 1;
            }
            other => panic!("{id}: {other:?}"),
        }
        assert_eq!(counts(&w), counts_before, "{id}: nothing else written");
    }
    let pending = w
        .store
        .transaction(|tx| tx.pending_decisions())
        .unwrap()
        .len();
    assert_eq!(pending + denied, ids.len());
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
        continuing: false,
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
            // ⟨§17.21 item 3 (R2-B)⟩ retirement deletes exactly the recorded store item.
            tx.set_issuer_store_locator(&fp, &format!("fixture-locator-{n}"))?;
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
    fn delete_recorded(
        &self,
        _ca: &CaFingerprint,
        _store: StoreKind,
        _locator: &str,
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
                // ⟨wave 4⟩ Phase 2, unwired: the driver's fail-closed answer.
                assert_fail_closed(&env, &what);
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

/// ⟨M03 wave 3, round 3⟩ The production anchors of the managed files (ADR-0008 §17.20
/// item 7): `Paths::ensure` creates `state_dir` and `runtime_dir` (and the other
/// directories) owner-only **whatever the umask**, tightens an existing owned directory
/// an older install left looser, and `ManagedDir::open_root` then accepts them; an anchor
/// loosened after `ensure` is refused (`managed_dir_unsafe`), never repaired by the
/// managed code. The umask is set in a **child process** (a re-execution of this test
/// binary through `/bin/sh -c 'umask 002 …'`), never in this parallel test process.
#[cfg(unix)]
mod umask_anchors {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use heimdall_localenv::sys::{ManagedDir, ManagedDirError};
    use heimdall_runtime::paths::Paths;

    const HOME_ENV: &str = "HM_W3_UMASK_CHILD_HOME";

    /// The child entry (a no-op unless re-executed by [`ensure_under_umask_002`]): it
    /// runs the production `Paths::ensure` under the inherited umask, plus a control
    /// directory made with the default mode, which shows the umask in effect.
    #[test]
    fn umask_child_entry() {
        let Some(home) = std::env::var_os(HOME_ENV) else {
            return;
        };
        let home = Path::new(&home);
        std::fs::create_dir(home.join("control")).unwrap();
        Paths::under(home).ensure().unwrap();
        std::process::exit(0);
    }

    fn ensure_under_umask_002(home: &Path) {
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(
                "umask 002 && exec \"$0\" --exact umask_anchors::umask_child_entry \
                 --nocapture --test-threads=1 -q",
            )
            .arg(exe)
            .env(HOME_ENV, home)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "the umask-002 child failed: {status:?}");
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn production_anchors_are_owner_only_under_umask_002() {
        // A fresh install under umask 002.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        ensure_under_umask_002(&home);
        assert_eq!(
            mode(&home.join("control")),
            0o775,
            "control: the child ran under umask 002"
        );
        let paths = Paths::under(&home);
        for dir in [
            &paths.config_dir,
            &paths.state_dir,
            &paths.runtime_dir,
            &paths.log_dir,
        ] {
            assert_eq!(mode(dir), 0o700, "{}", dir.display());
        }
        for anchor in [&paths.state_dir, &paths.runtime_dir] {
            assert!(
                ManagedDir::open_root(anchor).unwrap().is_some(),
                "open_root accepts {}",
                anchor.display()
            );
        }

        // An older install left the anchors 0775: `ensure` (under umask 002 again)
        // tightens them, and `open_root` accepts them.
        let older = tmp.path().join("older");
        let paths = Paths::under(&older);
        for anchor in [&paths.state_dir, &paths.runtime_dir] {
            std::fs::create_dir_all(anchor).unwrap();
            std::fs::set_permissions(anchor, std::fs::Permissions::from_mode(0o775)).unwrap();
            assert!(
                matches!(
                    ManagedDir::open_root(anchor),
                    Err(ManagedDirError::Unsafe(_))
                ),
                "before ensure, a 0775 anchor is refused"
            );
        }
        ensure_under_umask_002(&older);
        for anchor in [&paths.state_dir, &paths.runtime_dir] {
            assert_eq!(mode(anchor), 0o700, "{}", anchor.display());
            assert!(ManagedDir::open_root(anchor).unwrap().is_some());
        }

        // Loosened after `ensure`: the managed code refuses it and repairs nothing.
        std::fs::set_permissions(&paths.state_dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        let refused = ManagedDir::open_root(&paths.state_dir);
        assert!(
            matches!(refused, Err(ManagedDirError::Unsafe(_))),
            "{refused:?}"
        );
        assert_eq!(mode(&paths.state_dir), 0o775, "never repaired by open_root");
    }
}

// =================================================================================
// ⟨M03⟩ Wave 4 (U10-D): the runtime start and stop order, dispatch of
// `Connections`, the `Connection` events, the post-tick sweep
// =================================================================================

/// m03-plan U10 "Runtime" tests over a real `Service` with the managed wiring: a
/// scratch home, the virtual clock, testkit's `FakeSessionLockSource`, and an issuer
/// child that is this test binary re-executed through `/bin/sh` into
/// `w4_issuer_child_entry` (`heimdall_issuer::child::run` over testkit's
/// `ScratchSecretStore` holding a per-run K_ca; its protocol output on descriptor 3).
/// Every process the tests start is this binary or `/bin/sleep`, stopped by its own
/// handle or by the client's exact identity; the issuer child is stopped by the stop
/// order under test (or by its client's `kill_on_drop`).
#[cfg(unix)]
mod wave4 {
    use super::*;

    use std::path::{Path, PathBuf};

    use heimdall_contract::ids::{BindingId, ConnectionId, WorkId};
    use heimdall_contract::managed::{CloseReason, ConnectionsRequest, SessionLockState};
    use heimdall_credential::cert::SecretCaKey;
    use heimdall_domain::binding::{BindingRecord, BindingState};
    use heimdall_domain::grant::{AuthorizationSource, GrantOrigin, GrantSnapshot};
    use heimdall_domain::managed::{
        ConnectionKind, OwnedConnection, OwnedConnectionState, SlotState,
    };
    use heimdall_domain::policy::AuthorityGeneration;
    use heimdall_domain::time::Deadline;
    use heimdall_issuer::client::ChildCommand;
    use heimdall_issuer::store::SecretStore;
    use heimdall_runtime::connections::{ConnectionConfig, ConnectionSupervisor};
    use heimdall_runtime::platform::process_start_time;
    use heimdall_runtime::service::{
        ManagedOptions, STATE_DB_FILE, ServiceOptions, SessionLockWiring, start_step,
    };
    use heimdall_runtime::supervisor::ManagedConnections;
    use heimdall_runtime::{Config, Paths, Service};
    use heimdall_store::IssuerRecord;
    use heimdall_testkit::scratch_store::ScratchSecretStore;
    use heimdall_testkit::session_lock::FakeSessionLockSource;

    const CHILD_DB_ENV: &str = "HM_W4D_CHILD_DB";
    const CHILD_STORE_ENV: &str = "HM_W4D_CHILD_STORE";
    const CHILD_WALL_ENV: &str = "HM_W4D_CHILD_WALL";

    /// The issuer child (a no-op unless re-executed by [`Rig::child_command`]).
    #[test]
    fn w4_issuer_child_entry() {
        let (Some(db), Some(store), Some(wall)) = (
            std::env::var_os(CHILD_DB_ENV),
            std::env::var_os(CHILD_STORE_ENV),
            std::env::var_os(CHILD_WALL_ENV),
        ) else {
            return;
        };
        let clock = VirtualClock::at(wall.to_str().unwrap().parse().unwrap());
        let out = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/fd/3")
            .unwrap();
        let store = Box::new(ScratchSecretStore::new(PathBuf::from(store)));
        let status =
            heimdall_issuer::child::run(std::io::stdin(), out, store, Path::new(&db), clock);
        std::process::exit(status);
    }

    /// A scratch home whose store has this file's environment and, with `ca`, one
    /// registered `active` CA whose K_ca is in the scratch secret store.
    struct Rig {
        _tmp: tempfile::TempDir,
        home: PathBuf,
        secret_store: PathBuf,
        clock: Arc<VirtualClock>,
        sync: Arc<ScriptedTimeSync>,
    }

    impl Rig {
        fn new(ca: bool) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("hh");
            let paths = Paths::under(&home);
            paths.ensure().unwrap();
            let secret_store = tmp.path().join("store");
            std::fs::create_dir(&secret_store).unwrap();
            let store = Store::open(
                &paths.state_dir.join(STATE_DB_FILE),
                Arc::new(heimdall_store::NoFaults),
            )
            .unwrap();
            seed(&store);
            if ca {
                let k_ca = SecretCaKey::generate().unwrap();
                let fp = k_ca.fingerprint().unwrap();
                let public = k_ca.public_openssh().unwrap();
                ScratchSecretStore::new(secret_store.clone())
                    .put(&fp, &k_ca)
                    .unwrap();
                drop(k_ca);
                store
                    .transaction(|tx| {
                        tx.insert_issuer(&IssuerRecord {
                            ca_fingerprint: fp.clone(),
                            public_key: public.clone(),
                            state: CaState::Active,
                            store_kind: StoreKind::LinuxSecretService,
                            backup_sha256: "ab".repeat(32),
                            backup_created_at: t0(),
                            restored_without_log: false,
                            created_at: t0(),
                            retired_at: None,
                        })
                    })
                    .unwrap();
            }
            drop(store);
            Self {
                _tmp: tmp,
                home,
                secret_store,
                clock: VirtualClock::at(t0()),
                sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            }
        }

        fn paths(&self) -> Paths {
            Paths::under(&self.home)
        }

        fn child_command(&self) -> ChildCommand {
            let exe = std::env::current_exe().unwrap();
            ChildCommand {
                program: PathBuf::from("/bin/sh"),
                args: vec![
                    "-c".into(),
                    "exec 3>&1 1>/dev/null 2>/dev/null; exec \"$0\" --exact wave4::w4_issuer_child_entry --nocapture --test-threads=1 -q".into(),
                    exe.into_os_string(),
                ],
                env: vec![
                    (
                        CHILD_DB_ENV.into(),
                        self.paths().state_dir.join(STATE_DB_FILE).into_os_string(),
                    ),
                    (CHILD_STORE_ENV.into(), self.secret_store.clone().into_os_string()),
                    (CHILD_WALL_ENV.into(), t0().to_string().into()),
                ],
            }
        }

        /// Managed options: the fake lock source (unlocked), the test child, and a start
        /// token that also records, at each spawn, which runtime files already exist.
        fn options(&self, spawned: Arc<Mutex<Vec<(bool, bool, bool)>>>) -> ServiceOptions {
            let mut o = ServiceOptions::with_clock(self.clock.clone(), self.sync.clone());
            o.endpoint_prefix = "hmtest-".to_owned();
            let run = self.paths().runtime_dir;
            o.managed = Some(ManagedOptions {
                session_lock: SessionLockWiring::Source(Arc::new(FakeSessionLockSource::new(
                    SessionLockState::Unlocked,
                ))),
                issuer_command: Some(self.child_command()),
                issuer_start_token: Some(Arc::new(move |pid| {
                    spawned.lock().unwrap().push((
                        run.join("control.sock").exists(),
                        run.join("signing.sock").exists(),
                        run.join("instance.json").exists(),
                    ));
                    process_start_time(pid)
                })),
                ..ManagedOptions::default()
            });
            o
        }

        async fn start(&self, spawned: Arc<Mutex<Vec<(bool, bool, bool)>>>) -> Service {
            Service::start_with(
                self.paths(),
                Config::default(),
                self.options(spawned),
                CancellationToken::new(),
            )
            .await
            .unwrap()
        }
    }

    fn position(steps: &[&str], step: &str) -> usize {
        steps
            .iter()
            .position(|s| *s == step)
            .unwrap_or_else(|| panic!("{step} not in {steps:?}"))
    }

    /// m03-plan U10 `runtime_start_order_issuer_before_listen`: with a CA registered,
    /// the issuer child is started (and `ready`) before the environment endpoint, the
    /// control endpoint and `instance.json` exist; the binding order of the start is
    /// recovery, the session lock, the connection restart pass, the issuer, the
    /// environment endpoint, the re-issue pass, then the control endpoint and
    /// `instance.json`. Exactly one signer serves the environment path: the advertised
    /// signing endpoint is the managed registry's environment endpoint.
    #[tokio::test]
    async fn runtime_start_order_issuer_before_listen() {
        let rig = Rig::new(true);
        let spawned = Arc::new(Mutex::new(Vec::new()));
        let svc = rig.start(spawned.clone()).await;
        let steps = svc.start_steps();
        let order = [
            start_step::REGISTRY,
            start_step::SESSION_LOCK,
            start_step::WIRING,
            start_step::CONNECTION_RESTART_PASS,
            start_step::ISSUER_START,
            start_step::ENVIRONMENT_ENDPOINT,
            start_step::MANAGED_REISSUE_PASS,
            start_step::CONTROL_ENDPOINT,
            start_step::INSTANCE_FILE,
        ];
        for pair in order.windows(2) {
            assert!(
                position(&steps, pair[0]) < position(&steps, pair[1]),
                "{} before {}: {steps:?}",
                pair[0],
                pair[1]
            );
        }
        // Observed from the child's spawn: nothing listened yet.
        let seen = spawned.lock().unwrap().clone();
        assert_eq!(
            seen.first(),
            Some(&(false, false, false)),
            "at the issuer's spawn no control endpoint, environment endpoint or advertisement existed: {seen:?}"
        );
        let issuer = svc.issuer().unwrap();
        assert_eq!(issuer.state(), IssuerState::Ready, "ready before listening");
        assert_eq!(
            svc.instance().signing_endpoint,
            svc.endpoint_registry().unwrap().environment().locator,
            "one signer at the environment endpoint"
        );
        assert!(Path::new(&svc.instance().signing_endpoint).exists());
        let child = issuer.identity().unwrap();
        drop(svc);
        issuer.stop().await;
        let _ = child;
    }

    /// The same start without a registered CA starts no issuer child.
    #[tokio::test]
    async fn runtime_start_without_ca_starts_no_issuer() {
        let rig = Rig::new(false);
        let spawned = Arc::new(Mutex::new(Vec::new()));
        let svc = rig.start(spawned.clone()).await;
        let steps = svc.start_steps();
        assert!(steps.contains(&start_step::ISSUER_NOT_NEEDED), "{steps:?}");
        assert!(!steps.contains(&start_step::ISSUER_START), "{steps:?}");
        assert!(spawned.lock().unwrap().is_empty(), "no child spawned");
        assert!(svc.issuer().unwrap().identity().is_none());
    }

    /// Wait (bounded) until the exact process `pid` with start token `token` is gone.
    async fn gone(pid: u32, token: &str) -> bool {
        for _ in 0..200 {
            if process_start_time(pid).as_deref() != Some(token) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    /// m03-plan U10 `shutdown_zeroizes_vault_and_stops_issuer`: the stop order (stop
    /// accepting, close owned masters, zeroize the vault, shut the issuer down, remove
    /// the endpoints): after `run` returns, the vault holds no key, the issuer child
    /// (exact PID and start token) is gone and its client reports it stopped, and the
    /// environment endpoint and `instance.json` are removed.
    #[tokio::test]
    async fn shutdown_zeroizes_vault_and_stops_issuer() {
        let rig = Rig::new(true);
        let token = CancellationToken::new();
        let svc = Service::start_with(
            rig.paths(),
            Config::default(),
            rig.options(Arc::new(Mutex::new(Vec::new()))),
            token.clone(),
        )
        .await
        .unwrap();
        let vault = svc.vault().unwrap();
        vault.generate_ed25519().unwrap();
        vault.generate_ed25519().unwrap();
        assert_eq!(vault.len(), 2);
        let issuer = svc.issuer().unwrap();
        let child = issuer.identity().unwrap();
        let child_token = child.start_token.clone().unwrap();
        let signing = PathBuf::from(&svc.instance().signing_endpoint);
        let runtime_dir = rig.paths().runtime_dir;
        let running = tokio::spawn(svc.run());
        token.cancel();
        running.await.unwrap().unwrap();
        assert!(vault.is_empty(), "the vault was zeroized");
        assert_eq!(issuer.state(), IssuerState::Unavailable, "issuer stopped");
        assert!(
            gone(child.pid, &child_token).await,
            "the issuer child exited"
        );
        assert!(!signing.exists(), "the environment endpoint was removed");
        assert!(!runtime_dir.join("instance.json").exists());
    }

    /// m03-plan U10 `service_stop_via_signal_fallback_still_zeroizes` (ADR-0006 §13.7
    /// item 8): the control endpoint is made unusable (its socket replaced by a listener
    /// that never answers a hello) while the advertisement stays valid, so the stop
    /// cannot come over the control endpoint; the runtime is then stopped by SIGTERM,
    /// delivered by exact PID (this process, the runtime's) to a handler that cancels the
    /// service token, which is what `heimdall service run`'s signal handler does
    /// (`service_cmd::stop_on_signal`; the CLI's fallback to that signal is M01's
    /// `service_stop_falls_back_to_a_signal_when_the_control_endpoint_is_unusable`). The
    /// vault is still zeroized and the issuer stopped.
    #[tokio::test]
    async fn service_stop_via_signal_fallback_still_zeroizes() {
        use tokio::signal::unix::{SignalKind, signal};
        let rig = Rig::new(true);
        let token = CancellationToken::new();
        let svc = Service::start_with(
            rig.paths(),
            Config::default(),
            rig.options(Arc::new(Mutex::new(Vec::new()))),
            token.clone(),
        )
        .await
        .unwrap();
        let vault = svc.vault().unwrap();
        vault.generate_ed25519().unwrap();
        let issuer = svc.issuer().unwrap();
        let child = issuer.identity().unwrap();
        let control = svc.endpoints().control.clone();
        let running = tokio::spawn(svc.run());
        // The control endpoint becomes unusable; the advertisement stays.
        std::fs::remove_file(&control).unwrap();
        let dead = std::os::unix::net::UnixListener::bind(&control).unwrap();
        assert!(rig.paths().runtime_dir.join("instance.json").exists());
        let probe = tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::UnixStream::connect(&control),
        )
        .await;
        assert!(
            probe.is_ok(),
            "the replaced endpoint accepts but never answers"
        );
        // The signal handler `service run` installs: SIGTERM cancels the service token.
        let mut term = signal(SignalKind::terminate()).unwrap();
        let stop = token.clone();
        let handler = tokio::spawn(async move {
            term.recv().await;
            stop.cancel();
        });
        let status = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        tokio::time::timeout(Duration::from_secs(30), handler)
            .await
            .unwrap()
            .unwrap();
        running.await.unwrap().unwrap();
        assert!(vault.is_empty(), "zeroized after the signal stop");
        assert_eq!(issuer.state(), IssuerState::Unavailable);
        assert!(gone(child.pid, child.start_token.as_deref().unwrap()).await);
        assert!(!rig.paths().runtime_dir.join("instance.json").exists());
        drop(dead);
    }

    // --- Connections dispatch and events ------------------------------------------------

    /// A grant in `state` with a launch binding held by a process, and a dedicated owned
    /// connection row for a live `/bin/sleep` child of this test (its exact identity).
    struct Row {
        grant: GrantId,
        connection: OwnedConnection,
        child: std::process::Child,
    }

    fn seed_row(w: &World, n: u8, state: GrantState) -> Row {
        let caller = ctx(ClientRole::Owner);
        let scope = Scope {
            pairs: [pair("h1", "deploy")].into_iter().collect(),
            capabilities: ssh_only(),
        };
        let g = GrantSnapshot {
            id: GrantId::from_random_bytes([n; 16]),
            environment: env_id(),
            scope: scope.clone(),
            starts_at: t0(),
            deadline: Deadline {
                intent: heimdall_contract::request::DeadlineIntent::Duration("1h".into()),
                resolved_at: t0(),
                effective: shift(t0(), 3600),
            },
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(0),
            state,
            enforcement: EnforcementEvidence::unknown(),
        };
        let b = BindingRecord {
            id: BindingId::from_random_bytes([n; 16]),
            environment: env_id(),
            grant: g.id.clone(),
            work_id: WorkId::parse(&format!("w4-{n}")).unwrap(),
            owner: caller.clone(),
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            scope,
            mechanism: "managed_certificate".into(),
            parent: None,
            created_at: t0(),
            released_at: None,
            state: BindingState::Active,
        };
        let origin = GrantOrigin {
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            policy_revision: None,
            caller,
            mechanism: "managed_certificate".into(),
            covered: None,
            adapter: None,
            lock_behavior: None,
            connection: None,
        };
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut token = None;
        for _ in 0..100 {
            token = process_start_time(pid);
            if token.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let c = OwnedConnection {
            id: ConnectionId::from_random_bytes([n; 16]),
            kind: ConnectionKind::Dedicated,
            binding: b.id.clone(),
            grant: g.id.clone(),
            pid,
            start_token: token.unwrap(),
            image: "/bin/sleep".into(),
            control_path: None,
            generation: 0,
            state: OwnedConnectionState::Up,
            started_at: t0(),
        };
        w.store
            .transaction(|tx| {
                tx.insert_grant(&g)?;
                tx.set_grant_origin(&g.id, &origin)?;
                tx.insert_binding(&b)?;
                tx.set_binding_holder(
                    &b.id,
                    &heimdall_domain::holder::ProcessHolder {
                        pid: c.pid,
                        started_at: c.start_token.clone(),
                    },
                )?;
                tx.insert_owned_connection(&c)
            })
            .unwrap();
        Row {
            grant: g.id,
            connection: c,
            child,
        }
    }

    impl Drop for Row {
        fn drop(&mut self) {
            // Our own child, by its handle.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn connections(w: &World, runtime_dir: &Path) -> Arc<ManagedConnections> {
        struct NoEndpoints;
        impl heimdall_runtime::connections::BindingEndpoints for NoEndpoints {
            fn endpoint(&self, _: &BindingId) -> Option<heimdall_contract::provider::EndpointRef> {
                None
            }
        }
        let mut config = ConnectionConfig::new(
            runtime_dir.to_path_buf(),
            PathBuf::from("/bin/sleep"),
            Arc::new(NoEndpoints),
            Arc::new(FixedJitter(1.0)),
        );
        config.close_grace = Duration::from_millis(500);
        let sup = Arc::new(ConnectionSupervisor::new(
            w.store.clone(),
            Some(w.ops.clone()),
            config,
        ));
        Arc::new(ManagedConnections::new(sup, w.store.clone(), w.ops.clone()))
    }

    /// The `Connection` events, as `(connection, event, reason)`.
    fn connection_events(w: &World) -> Vec<(String, String, Option<String>)> {
        w.events()
            .into_iter()
            .filter(|e| e.event_type == EventType::Connection)
            .map(|e| {
                (
                    e.payload["connection_id"].as_str().unwrap().to_owned(),
                    e.payload["event"].as_str().unwrap().to_owned(),
                    e.payload["reason"].as_str().map(str::to_owned),
                )
            })
            .collect()
    }

    fn exited(child: &mut std::process::Child) -> bool {
        for _ in 0..200 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// U0b row 13 phase 2 (F20; m03-plan §5 item 4a), wired: `Connections::Close` from
    /// the owner reaches U7's supervisor through the dispatcher, closes the verified
    /// process, moves the row to `closed` and emits exactly one `Connection` event
    /// `{closed, reason: owner_request}`; a second close answers `closed` again and
    /// emits nothing. A non-owner is refused first (no reason, nothing closed, no
    /// event); an unknown connection is `NOT_FOUND`; `Register` on Unix is
    /// `driver_unavailable` (Windows only); an unwired dispatcher answers
    /// `driver_unavailable` for both.
    #[tokio::test]
    async fn connections_close_routed_for_owner_only_with_event() {
        let w = World::new().await;
        let dir = tempfile::tempdir().unwrap();
        let mut row = seed_row(&w, 0x91, GrantState::Active);
        let c = connections(&w, dir.path());
        let d = w.dispatcher().with_connections(c);
        let close = Request::Connections(ConnectionsRequest::Close {
            connection_id: row.connection.id.clone(),
        });
        // Non-owner: refused before anything.
        let before = w.snapshot();
        let env = d
            .handle_as(&attended(ClientRole::LimitedConsumer), close.clone())
            .await;
        assert_eq!(env.code, Code::CapabilityUnavailable);
        assert_eq!(reason_of(&env), None, "{:?}", env.data);
        assert_eq!(w.snapshot(), before, "nothing written for a non-owner");
        assert!(matches!(row.child.try_wait(), Ok(None)), "not signalled");
        // Unwired: driver_unavailable.
        let env = w
            .dispatcher()
            .handle_as(&attended(ClientRole::Owner), close.clone())
            .await;
        assert_driver_unavailable(&env, "unwired close");
        assert_eq!(w.snapshot(), before);
        // Owner, wired: closed, with its event.
        let env = d
            .handle_as(&attended(ClientRole::Owner), close.clone())
            .await;
        assert_eq!(env.code, Code::Ok, "{:?}", env.data);
        assert_eq!(env.data["state"], "closed", "{:?}", env.data);
        assert_eq!(env.data["kind"], "dedicated");
        assert!(exited(&mut row.child), "the verified process was closed");
        let state = w
            .store
            .transaction(|tx| tx.owned_connection(&row.connection.id))
            .unwrap()
            .unwrap()
            .state;
        assert_eq!(state, OwnedConnectionState::Closed);
        let id = row.connection.id.to_string();
        assert_eq!(
            connection_events(&w),
            vec![(
                id.clone(),
                "closed".to_owned(),
                Some("owner_request".to_owned())
            )]
        );
        // Idempotent: closed again, no second event.
        let env = d.handle_as(&attended(ClientRole::Owner), close).await;
        assert_eq!(env.data["state"], "closed");
        assert_eq!(connection_events(&w).len(), 1);
        // Unknown connection.
        let env = d
            .handle_as(
                &attended(ClientRole::Owner),
                Request::Connections(ConnectionsRequest::Close {
                    connection_id: ConnectionId::from_random_bytes([0x99; 16]),
                }),
            )
            .await;
        assert_eq!(env.code, Code::NotFound, "{:?}", env.data);
        // Register: Windows only.
        let register = Request::Connections(ConnectionsRequest::Register {
            binding_id: row.connection.binding.clone(),
            pid: 4242,
            created_at: t0(),
            image: "/usr/bin/ssh".into(),
        });
        let env = d
            .handle_as(&attended(ClientRole::LimitedConsumer), register.clone())
            .await;
        assert_eq!(env.code, Code::CapabilityUnavailable);
        assert_eq!(reason_of(&env), None, "the role refusal first");
        let env = d.handle_as(&attended(ClientRole::Owner), register).await;
        assert_driver_unavailable(&env, "register on unix");
        assert_eq!(connection_events(&w).len(), 1);
    }

    /// ADR-0008 D7 item 2 (U7-Q3; §17.20 item 13): the supervisor's post-tick sweep
    /// closes the owned connections of an ended grant by the reason its stored state
    /// gives (here `revoked` → `revocation_close`, which closes dedicated connections
    /// under both policies), emits one `Connection` event `{closed, revocation}` per row
    /// it closed, and does not pass the grant again; a live grant's row is untouched.
    #[tokio::test]
    async fn sweep_closes_ended_grants_connections_with_reason_once() {
        let w = World::new().await;
        let dir = tempfile::tempdir().unwrap();
        let mut revoked = seed_row(&w, 0x92, GrantState::Revoked);
        let mut live = seed_row(&w, 0x93, GrantState::Active);
        let sup = w.supervisor().with_connections(connections(&w, dir.path()));
        let sweep = sup.connection_end_sweep().await;
        assert_eq!(
            sweep.handled,
            vec![(revoked.grant.clone(), CloseReason::Revocation)],
            "{sweep:?}"
        );
        assert!(exited(&mut revoked.child));
        assert!(
            matches!(live.child.try_wait(), Ok(None)),
            "the live grant's row is kept"
        );
        let id = revoked.connection.id.to_string();
        assert_eq!(
            connection_events(&w),
            vec![(id, "closed".to_owned(), Some("revocation".to_owned()))]
        );
        let again = sup.connection_end_sweep().await;
        assert!(
            again.handled.is_empty() && again.retry.is_empty(),
            "{again:?}"
        );
        assert_eq!(connection_events(&w).len(), 1, "never reported twice");
    }

    // --- wave 4, round 2 (ADR-0008 §17.21 item 11) ---------------------------------------

    /// A grant in `state` (with its origin) and an active binding referencing it, whose
    /// slot for `<dest>/deploy` is `held` at generation 2 (a first holding was cleared
    /// to `free(1)`), all in `store`.
    fn seed_held_slot(store: &Store, n: u8, state: GrantState, dest: &str) -> GrantId {
        let caller = ctx(ClientRole::Owner);
        let scope = Scope {
            pairs: [pair(dest, "deploy")].into_iter().collect(),
            capabilities: ssh_only(),
        };
        let g = GrantSnapshot {
            id: GrantId::from_random_bytes([n; 16]),
            environment: env_id(),
            scope: scope.clone(),
            starts_at: t0(),
            deadline: Deadline {
                intent: heimdall_contract::request::DeadlineIntent::Duration("1h".into()),
                resolved_at: t0(),
                effective: shift(t0(), 3600),
            },
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(0),
            state,
            enforcement: EnforcementEvidence::unknown(),
        };
        let b = BindingRecord {
            id: BindingId::from_random_bytes([n; 16]),
            environment: env_id(),
            grant: g.id.clone(),
            work_id: WorkId::parse(&format!("w4s-{n}")).unwrap(),
            owner: caller.clone(),
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            scope,
            mechanism: "managed_certificate".into(),
            parent: None,
            created_at: t0(),
            released_at: None,
            state: BindingState::Active,
        };
        let origin = GrantOrigin {
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            policy_revision: None,
            caller,
            mechanism: "managed_certificate".into(),
            covered: None,
            adapter: None,
            lock_behavior: None,
            connection: None,
        };
        let p = pair(dest, "deploy");
        store
            .transaction(|tx| {
                tx.insert_grant(&g)?;
                tx.set_grant_origin(&g.id, &origin)?;
                tx.insert_binding(&b)?;
                tx.add_grant_reference(&heimdall_domain::grant::GrantReference {
                    binding: b.id.clone(),
                    grant: g.id.clone(),
                    acquired_at: t0(),
                })?;
                tx.claim_slot(&env_id(), &p, &b.id, t0())?.unwrap();
                tx.release_slot(&env_id(), &p, &b.id, 1, t0())?.unwrap();
                tx.slot_files_removed(&env_id(), &p, 1, t0())?.unwrap();
                let held = tx.claim_slot(&env_id(), &p, &b.id, t0())?.unwrap();
                assert_eq!(
                    held,
                    SlotState::Held {
                        binding: b.id.clone(),
                        generation: 2
                    }
                );
                Ok(())
            })
            .unwrap();
        g.id
    }

    /// ADR-0008 §17.21 item 11 (slot cleanup when a grant ends; round 1's open U10-D
    /// request): an **expired** grant's held slot (M01's expiry calls no adapter
    /// `revoke`) is found by the store query (`held_slots_of_ended_grants`) and cleared
    /// by the supervisor's ended-slot pass through U10-C's `StoreCleanup`, by its own
    /// generation (`held(b, 2)` → `free(2)`, never another generation); a live grant's
    /// held slot is untouched; a second pass finds nothing.
    #[tokio::test]
    async fn ended_grant_held_slot_cleared_by_its_generation() {
        let rig = Rig::new(false);
        let svc = rig.start(Arc::new(Mutex::new(Vec::new()))).await;
        let store = svc.store().clone();
        let expired = seed_held_slot(&store, 0xa1, GrantState::Expired, "h1");
        // A live grant holding another pair's slot.
        let _live = seed_held_slot(&store, 0xa2, GrantState::Active, "h2");
        let ended = store
            .transaction(|tx| tx.held_slots_of_ended_grants(&env_id()))
            .unwrap();
        assert_eq!(
            ended.iter().map(|(g, _)| g.clone()).collect::<Vec<_>>(),
            vec![expired.clone()],
            "only the ended grant's slot is listed: {ended:?}"
        );
        let sup = svc.supervisor();
        let cleaned = sup.ended_slot_pass().await.unwrap();
        assert_eq!(cleaned, vec![expired.clone()]);
        let slot = store
            .transaction(|tx| tx.slot(&env_id(), &pair("h1", "deploy")))
            .unwrap();
        assert_eq!(
            slot,
            SlotState::Free { generation: 2 },
            "cleared by its own generation"
        );
        assert!(
            store
                .transaction(|tx| tx.held_slots_of_ended_grants(&env_id()))
                .unwrap()
                .is_empty()
        );
        assert!(sup.ended_slot_pass().await.unwrap().is_empty());
        assert_eq!(
            store
                .transaction(|tx| tx.slot(&env_id(), &pair("h2", "deploy")))
                .unwrap(),
            SlotState::Held {
                binding: BindingId::from_random_bytes([0xa2; 16]),
                generation: 2
            },
            "the live grant's slot is untouched"
        );
    }

    /// ⟨integrator, round 2 (R2-D → R2-C request)⟩ A **released** binding's grant
    /// reference is gone, yet its slot row still names it: once the grant ends, the
    /// ended-slot pass still clears that slot by its own generation.
    #[tokio::test]
    async fn released_binding_held_slot_cleared_after_grant_ends() {
        let rig = Rig::new(false);
        let svc = rig.start(Arc::new(Mutex::new(Vec::new()))).await;
        let store = svc.store().clone();
        let ended = seed_held_slot(&store, 0xa3, GrantState::Expired, "h3");
        store
            .transaction(|tx| {
                tx.remove_grant_reference(&heimdall_domain::grant::GrantReference {
                    binding: BindingId::from_random_bytes([0xa3; 16]),
                    grant: ended.clone(),
                    acquired_at: t0(),
                })
                .map(|_| ())
            })
            .unwrap();
        let cleaned = svc.supervisor().ended_slot_pass().await.unwrap();
        assert_eq!(cleaned, vec![ended.clone()]);
        assert_eq!(
            store
                .transaction(|tx| tx.slot(&env_id(), &pair("h3", "deploy")))
                .unwrap(),
            SlotState::Free { generation: 2 },
            "the released binding's slot is cleared by its own generation"
        );
    }

    /// ADR-0008 §17.21 item 11 (`inspect connections`, §5 item 4): read-only over the
    /// owned-connection rows, owner only like decisions. Each live row is listed in the
    /// shape of `schemas/examples/inspect.connections.json` (`ConnectionsView`): its
    /// kind, binding, grant, the binding's destination, its start, the grant's effective
    /// policy (D8 item 1), `closes_at` (the grant's bound under `strict`, `null` for a
    /// dedicated connection under `graceful`) and its state; a closed row is not
    /// listed; no PID, start token or image appears. A non-owner gets an empty list.
    /// Nothing is written.
    #[tokio::test]
    async fn inspect_connections_lists_owned_rows_owner_only() {
        use heimdall_contract::managed::{
            ConnectionPolicy, ConnectionsView, ExistingConnectionsMode, MultiplexingMode,
        };
        let w = World::new().await;
        let graceful = seed_row(&w, 0xb1, GrantState::Active);
        let strict = seed_row(&w, 0xb2, GrantState::Active);
        let closed = seed_row(&w, 0xb3, GrantState::Active);
        w.store
            .transaction(|tx| {
                tx.close_owned_connection(
                    &closed.connection.id,
                    closed.connection.generation,
                    OwnedConnectionState::Closed,
                )
                .map(|_| ())
            })
            .unwrap();
        let inspect = |role| {
            let ops = w.ops.clone();
            async move {
                ops.inspect(
                    &unattended(role),
                    heimdall_contract::request::InspectRequest {
                        subject: heimdall_contract::request::InspectSubject::Connections,
                        preview: None,
                    },
                )
                .await
                .unwrap()
                .data
            }
        };
        let before = w.snapshot();
        let data = inspect(ClientRole::Owner).await;
        assert_eq!(w.snapshot(), before, "read-only");
        let text = data.to_string();
        for (pid, token) in [
            (graceful.connection.pid, &graceful.connection.start_token),
            (strict.connection.pid, &strict.connection.start_token),
        ] {
            assert!(!text.contains(&format!("\"pid\":{pid}")), "{text}");
            assert!(!text.contains(token.as_str()), "no start token: {text}");
        }
        assert!(!text.contains("/bin/sleep"), "no image: {text}");
        let example: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(repo_root().join("schemas/examples/inspect.connections.json"))
                .unwrap(),
        )
        .unwrap();
        serde_json::from_value::<ConnectionsView>(example.clone()).unwrap();
        let view: ConnectionsView = serde_json::from_value(data.clone()).unwrap();
        let keys = |v: &serde_json::Value| -> BTreeSet<String> {
            v.as_object().unwrap().keys().cloned().collect()
        };
        let example_keys = keys(&example["connections"][0]);
        for entry in data["connections"].as_array().unwrap() {
            assert_eq!(keys(entry), example_keys, "the example's shape: {entry}");
        }
        assert_eq!(
            view.connections.len(),
            2,
            "the closed row is not listed: {data}"
        );
        let entry = |id: &ConnectionId| {
            view.connections
                .iter()
                .find(|c| &c.id == id)
                .unwrap_or_else(|| panic!("{id} listed: {data}"))
                .clone()
        };
        let g = entry(&graceful.connection.id);
        assert_eq!(g.kind, ConnectionKind::Dedicated);
        assert_eq!(g.binding_id, graceful.connection.binding);
        assert_eq!(g.grant_id, graceful.grant);
        assert_eq!(g.destination_id, DestinationId::parse("h1").unwrap());
        assert_eq!(g.started_at, t0());
        assert_eq!(
            g.policy,
            ConnectionPolicy {
                existing: ExistingConnectionsMode::Graceful,
                multiplexing: MultiplexingMode::Disabled,
            }
        );
        assert_eq!(g.closes_at, None, "dedicated under graceful");
        assert_eq!(data["connections"][0]["state"], "up");
        assert_eq!(entry(&strict.connection.id).closes_at, None);
        // A current applicable policy narrows to `strict` (D8 item 1's merge): the
        // dedicated connections now close at the grant's bound.
        w.store
            .transaction(|tx| {
                let mut p = tx.policy(&PolicyId::parse("pol").unwrap())?.unwrap();
                p.revision = PolicyRevision(2);
                p.connection.existing = ExistingConnectionsMode::Strict;
                tx.upsert_policy(&p, true).map(|_| ())
            })
            .unwrap();
        let view: ConnectionsView =
            serde_json::from_value(inspect(ClientRole::Owner).await).unwrap();
        let s = view
            .connections
            .iter()
            .find(|c| c.id == strict.connection.id)
            .unwrap();
        assert_eq!(s.policy.existing, ExistingConnectionsMode::Strict);
        assert_eq!(s.closes_at, Some(shift(t0(), 3600)), "strict: at the bound");
        // Not the owner: nothing listed.
        assert_eq!(
            inspect(ClientRole::LimitedConsumer).await,
            serde_json::json!({ "connections": [] })
        );
        drop((graceful, strict, closed));
    }
}

/// U8-Q6 (ADR-0008 D8 item 2; additive): `inspect destinations` carries, for a managed
/// destination whose (destination, account) pair has a stored preference, `"preference":
/// {"mechanism", "projection"}` in the shape `connect` reads
/// (`connect_cmd::managed_pair_of`: `managed_certificate` with `{"state": "applied",
/// "generation": N}` takes the managed flow); a pair without a row, and an observed
/// destination, carry no `preference` key (M02's listing).
#[tokio::test]
async fn inspect_destinations_carries_pair_preference() {
    use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
    use heimdall_domain::enrollment::{PairPreference, ProjectionStatus};
    let w = World::new().await;
    let identity = heimdall_contract::ids::IdentityId::from_random_bytes([0x41; 16]);
    let managed = |id: &str| DestinationRecord {
        id: DestinationId::parse(id).unwrap(),
        alias: id.into(),
        revision: 1,
        definition: DestinationDefinition::Managed {
            hostname: format!("{id}.example.invalid"),
            port: None,
            account: AccountName::parse("deploy").unwrap(),
            identity: identity.clone(),
        },
        label: None,
        updated_at: t0(),
    };
    w.store
        .transaction(|tx| {
            tx.upsert_destination(&managed("lab"))?;
            tx.upsert_destination(&managed("plain"))?;
            tx.upsert_destination(&managed("pend"))?;
            tx.upsert_destination(&DestinationRecord {
                id: DestinationId::parse("obs").unwrap(),
                alias: "obs".into(),
                revision: 1,
                definition: DestinationDefinition::Observed,
                label: None,
                updated_at: t0(),
            })?;
            for (d, projection) in [
                ("lab", ProjectionStatus::Applied { generation: 3 }),
                ("pend", ProjectionStatus::Pending),
            ] {
                tx.set_pair_preference(
                    &PairPreference {
                        destination: DestinationId::parse(d).unwrap(),
                        account: AccountName::parse("deploy").unwrap(),
                        mechanism:
                            heimdall_contract::managed::PreferredMechanism::ManagedCertificate,
                        projection,
                        issuing_cas: BTreeSet::new(),
                    },
                    t0(),
                )?;
            }
            Ok(())
        })
        .unwrap();
    let r = w
        .ops
        .inspect(
            &unattended(ClientRole::Owner),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Destinations,
                preview: None,
            },
        )
        .await
        .unwrap();
    let items = r.data["items"].as_array().unwrap();
    let item = |id: &str| {
        items
            .iter()
            .find(|i| i["destination_id"] == id)
            .unwrap_or_else(|| panic!("{id} listed: {items:?}"))
    };
    assert_eq!(
        item("lab")["preference"],
        serde_json::json!({
            "mechanism": "managed_certificate",
            "projection": {"state": "applied", "generation": 3},
        })
    );
    assert_eq!(
        item("pend")["preference"],
        serde_json::json!({"mechanism": "managed_certificate", "projection": {"state": "pending"}})
    );
    assert!(item("plain").get("preference").is_none(), "no row, no key");
    assert!(item("obs").get("preference").is_none(), "observed: no key");
    // The M02 fields are unchanged.
    assert_eq!(item("lab")["definition"], "managed");
    assert_eq!(item("lab")["account"], "deploy");
}

// =================================================================================
// M03 wave 4, round 2 (ADR-0008 §17.21 items 8 and 11)
// =================================================================================

mod round2 {
    use super::*;

    use heimdall_contract::managed::SessionLockState;
    use heimdall_runtime::service::{
        ManagedOptions, STATE_DB_FILE, ServiceOptions, SessionLockWiring,
    };
    use heimdall_runtime::{Config, Paths, Service};
    use heimdall_testkit::session_lock::FakeSessionLockSource;

    /// A scratch home whose store has this file's environment (no CA, so no issuer
    /// child is started), and managed options with an unlocked fake lock source.
    struct Home {
        _tmp: tempfile::TempDir,
        home: std::path::PathBuf,
        clock: Arc<VirtualClock>,
        sync: Arc<ScriptedTimeSync>,
    }

    impl Home {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("hh");
            let paths = Paths::under(&home);
            paths.ensure().unwrap();
            let store = Store::open(
                &paths.state_dir.join(STATE_DB_FILE),
                Arc::new(heimdall_store::NoFaults),
            )
            .unwrap();
            seed(&store);
            drop(store);
            Self {
                _tmp: tmp,
                home,
                clock: VirtualClock::at(t0()),
                sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            }
        }

        fn options(&self) -> ServiceOptions {
            let mut o = ServiceOptions::with_clock(self.clock.clone(), self.sync.clone());
            o.endpoint_prefix = "hmtest-".to_owned();
            o.managed = Some(ManagedOptions {
                session_lock: SessionLockWiring::Source(Arc::new(FakeSessionLockSource::new(
                    SessionLockState::Unlocked,
                ))),
                ..ManagedOptions::default()
            });
            o
        }

        /// Start a managed runtime, observe it, and stop it through its own stop order.
        async fn run_once<T>(&self, observe: impl FnOnce(&Service) -> T) -> T {
            let token = CancellationToken::new();
            let svc = Service::start_with(
                Paths::under(&self.home),
                Config::default(),
                self.options(),
                token.clone(),
            )
            .await
            .unwrap();
            let seen = observe(&svc);
            let running = tokio::spawn(svc.run());
            token.cancel();
            running.await.unwrap().unwrap();
            seen
        }
    }

    /// What one start shows: the stored installation token, the environment pipe it
    /// names as P renders it, and the managed registry's environment endpoint.
    fn observed(svc: &Service) -> (Option<String>, Option<String>, String) {
        let token = svc
            .store()
            .transaction(|tx| tx.windows_pipe_token())
            .unwrap();
        let rendered = token
            .as_deref()
            .and_then(heimdall_credential::endpoints::rendered_environment_pipe);
        let live = svc.endpoint_registry().unwrap().environment().locator;
        (token, rendered, live)
    }

    /// ADR-0008 §17.21 item 8 (U10-D-Q1 option (a); D10 item 1), the store/token part on
    /// every host: the first managed start records the installation's Windows
    /// environment pipe token (`Txn::windows_pipe_token`), and a restart over the same
    /// state directory reuses it, so the environment pipe name P renders
    /// (`//./pipe/heimdall-<token>-signing`) and the endpoint the runtime serves are
    /// unchanged. (Replaces round 1's
    /// `windows_token_change_makes_p_stale_and_ensure_projection_pending`.) On Windows the
    /// served endpoint is that pipe; the live-pipe half is
    /// `windows_native_restart_p_still_names_live_pipe_ensure_not_projection_pending`.
    #[tokio::test]
    async fn windows_pipe_token_stable_across_runtime_restart() {
        let home = Home::new();
        let (t1, r1, live1) = home.run_once(observed).await;
        let t1 = t1.expect("the first managed start records the installation token");
        assert!(
            t1.starts_with("hmtest") && t1.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{t1}"
        );
        let (t2, r2, live2) = home.run_once(observed).await;
        assert_eq!(t2.as_deref(), Some(t1.as_str()), "the token is reused");
        assert_eq!(r2, r1, "the environment pipe P names is unchanged");
        assert_eq!(
            r1.as_deref(),
            Some(format!("//./pipe/heimdall-{t1}-signing").as_str())
        );
        assert_eq!(live2, live1, "the served environment endpoint is unchanged");
        if cfg!(windows) {
            assert_eq!(live1, format!(r"\\.\pipe\heimdall-{t1}-signing"));
        }
    }

    /// ADR-0008 §17.21 item 8, the Windows-native half (needs a real named pipe; not run
    /// on this host): after a runtime restart over the same state directory, the pipe P
    /// names (`//./pipe/heimdall-<token>-signing`, the same name in `\\.\pipe\` form) is
    /// the pipe the new runtime serves (a client connects to it), so ordinary `ssh` keeps
    /// reaching the signer and nothing marks the pair's projection pending: the pair
    /// preference's projection status is unchanged (`applied`), so `ensure` does not
    /// answer `projection_pending`.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_native_restart_p_still_names_live_pipe_ensure_not_projection_pending() {
        use heimdall_domain::enrollment::{PairPreference, ProjectionStatus};
        let home = Home::new();
        let p = pair("h1", "deploy");
        {
            let store = Store::open(
                &Paths::under(&home.home).state_dir.join(STATE_DB_FILE),
                Arc::new(heimdall_store::NoFaults),
            )
            .unwrap();
            store
                .transaction(|tx| {
                    tx.set_pair_preference(
                        &PairPreference {
                            destination: p.destination.clone(),
                            account: p.account.clone(),
                            mechanism:
                                heimdall_contract::managed::PreferredMechanism::ManagedCertificate,
                            projection: ProjectionStatus::Applied { generation: 1 },
                            issuing_cas: BTreeSet::new(),
                        },
                        t0(),
                    )
                })
                .unwrap();
        }
        let (_, rendered1, _) = home.run_once(observed).await;
        let token = CancellationToken::new();
        let svc = Service::start_with(
            Paths::under(&home.home),
            Config::default(),
            home.options(),
            token.clone(),
        )
        .await
        .unwrap();
        let (_, rendered2, live) = observed(&svc);
        assert_eq!(rendered2, rendered1, "P still names the same pipe");
        assert_eq!(
            rendered2.unwrap().replace('/', "\\"),
            live,
            "P's pipe is the one this runtime serves"
        );
        tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&live)
            .expect("the pipe P names is live after the restart");
        let preference = svc
            .store()
            .transaction(|tx| tx.pair_preference(&p))
            .unwrap()
            .unwrap();
        assert_eq!(
            preference.projection,
            ProjectionStatus::Applied { generation: 1 },
            "the restart marks nothing pending"
        );
        let running = tokio::spawn(svc.run());
        token.cancel();
        running.await.unwrap().unwrap();
    }

    // --- the selection classification feeds the report (§17.21 item 11) -------------

    fn selection_pair(dest: &str) -> heimdall_app::ports::PreparePair {
        use heimdall_domain::catalog::{IdentityRecord, IdentitySource, InteractionProfile};
        heimdall_app::ports::PreparePair {
            destination: DestinationId::parse(dest).unwrap(),
            account: AccountName::parse("deploy").unwrap(),
            identity: IdentityRecord {
                id: heimdall_contract::ids::IdentityId::from_random_bytes([1; 16]),
                revision: 1,
                source: IdentitySource::PublicKeyFile {
                    path: "/nonexistent/fixture.pub".into(),
                },
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture".into(),
                fingerprint: "SHA256:fixture".into(),
                interaction: InteractionProfile {
                    interaction: heimdall_contract::provider::InteractionKind::Unknown,
                    basis: heimdall_contract::provider::EvidenceBasis::Inferred,
                },
                label: None,
                adopted_at: t0(),
                updated_at: t0(),
            },
            alias: Some(format!("{dest}-alias")),
        }
    }

    fn observation(
        alias: &str,
        selection: Option<heimdall_contract::provider::IdentitySelection>,
    ) -> heimdall_contract::doctor::AliasObservation {
        heimdall_contract::doctor::AliasObservation {
            alias: alias.into(),
            definition: heimdall_contract::doctor::AliasDefinition::Managed,
            behavior: Vec::new(),
            identity_selection: selection.map(|selection| {
                heimdall_contract::provider::IdentitySelectionReport {
                    selection,
                    entries: Vec::new(),
                    identities_only: heimdall_contract::provider::IdentitiesOnly::DeterminedYes,
                }
            }),
        }
    }

    fn verified_enrollment(
        n: u8,
        ca: &CaFingerprint,
        p: &AccessPair,
    ) -> heimdall_domain::enrollment::EnrollmentRecord {
        use heimdall_domain::enrollment::{
            ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
            ExistingAccessRecord, NoProxy, RegistryCanonical, marker_for,
        };
        let id = EnrollmentId::from_random_bytes([n; 16]);
        EnrollmentRecord {
            marker: marker_for(&id),
            id,
            destination: p.destination.clone(),
            account: p.account.clone(),
            ca_fingerprint: ca.clone(),
            form: EnrollmentForm::Account,
            registry: RegistryRef {
                path_display: "~/.ssh/authorized_keys".into(),
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            registry_canonical: RegistryCanonical {
                path: None,
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            line_sha256: "ab".repeat(32),
            target: ApprovedTarget {
                hostname: "example.invalid".into(),
                port: 22,
                user: p.account.clone(),
                proxy: NoProxy::None,
                host_key: ApprovedHostKey {
                    algorithm: "ssh-ed25519".into(),
                    key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                    fingerprint: "SHA256:hostfixture".into(),
                },
            },
            existing_access: ExistingAccessRecord {
                identity: heimdall_contract::ids::IdentityId::from_random_bytes([n; 16]),
                endpoint: None,
                public_key_file: None,
            },
            hold: None,
            removal_origin: None,
            late_write: None,
            state: EnrollmentState::Verified,
            verified_at: Some(t0()),
            evidence: None,
            created_at: t0(),
            updated_at: t0(),
        }
    }

    /// The managed report's `identity_selection` for `pairs` with `observations`, from
    /// U6's `prepare::outcome` over a snapshot holding verified enrollments and the
    /// driver's results (one valid certificate per pair).
    fn report_selection(
        pairs: &[heimdall_app::ports::PreparePair],
        observations: Vec<heimdall_contract::doctor::AliasObservation>,
    ) -> Option<heimdall_contract::managed::IdentitySelectionEnforcement> {
        use heimdall_adapters::managed::prepare::{GrantTerms, outcome};
        use heimdall_app::ports::{
            IntegrationSnapshot, KeyRegistration, ManagedPrepared, ManagedSources, PrepareRequest,
            PreparedCertificate,
        };
        let ca = ca(7);
        let access: Vec<AccessPair> = pairs
            .iter()
            .map(|p| AccessPair {
                destination: p.destination.clone(),
                account: p.account.clone(),
            })
            .collect();
        let scope = Scope {
            pairs: access.iter().cloned().collect(),
            capabilities: ssh_only(),
        };
        let grant = heimdall_domain::grant::GrantSnapshot {
            id: GrantId::from_random_bytes([0xc1; 16]),
            environment: env_id(),
            scope: scope.clone(),
            starts_at: t0(),
            deadline: heimdall_domain::time::Deadline {
                intent: heimdall_contract::request::DeadlineIntent::Duration("1h".into()),
                resolved_at: t0(),
                effective: shift(t0(), 3600),
            },
            parent: None,
            source: heimdall_domain::grant::AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(0),
            state: GrantState::Preparing,
            enforcement: EnforcementEvidence::unknown(),
        };
        let snapshot = IntegrationSnapshot {
            observations,
            managed: Some(ManagedSources {
                enrollments: access
                    .iter()
                    .enumerate()
                    .map(|(i, p)| verified_enrollment(0x60 + i as u8, &ca, p))
                    .collect(),
                issuing_cas: access
                    .iter()
                    .map(|p| (p.clone(), [ca.clone()].into_iter().collect()))
                    .collect(),
                prepared: Some(ManagedPrepared {
                    instance: CredentialInstanceId::from_random_bytes([0xc2; 16]),
                    key: KeyRegistration {
                        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIkenv".into(),
                        fingerprint: "SHA256:kenv".into(),
                        slot: "slot-1".into(),
                    },
                    certificates: access
                        .iter()
                        .enumerate()
                        .map(|(i, p)| PreparedCertificate {
                            pair: p.clone(),
                            issuance: IssuanceId::from_random_bytes([0x70 + i as u8; 16]),
                            ca: ca.clone(),
                            valid_before: shift(t0(), 1800),
                        })
                        .collect(),
                    materialized: None,
                }),
                ..ManagedSources::default()
            }),
            ..IntegrationSnapshot::default()
        };
        let required = RequiredCapabilities::default();
        let (o, report) = outcome(
            &PrepareRequest {
                grant: &grant,
                scope: &scope,
                required: &required,
                interactive: false,
                effect_token: "tok",
                now: shift(t0(), 60),
                pairs,
            },
            &snapshot,
            Some(&GrantTerms::default()),
            None,
            heimdall_adapters::managed::report::current_platform(),
            &ssh_only().into_iter().collect(),
            &|_| Some(t0()),
        )
        .unwrap();
        assert_eq!(
            o.enforcement.report.identity_selection,
            report.enforcement.identity_selection
        );
        report.enforcement.identity_selection
    }

    /// ADR-0008 §17.21 item 11 (D10 item 6; `MANAGED_SELECTION_CLASSIFIED` is true): the
    /// managed adapter's report takes the actual classification of the request pairs'
    /// managed aliases, the weakest over the pairs: every pair `exclusive` →
    /// `identity_selection: client_configuration_and_signer`; one pair `not_exclusive`,
    /// `undetermined`, unobserved or without an alias → `unknown`. And the adapter's
    /// snapshot carries the source's observations of exactly the request's aliases.
    #[test]
    fn managed_report_selection_follows_alias_classification() {
        use heimdall_adapters::managed::prepare::{ManagedSourceRead, selection_class, snapshot};
        use heimdall_adapters::managed::report::SelectionClass;
        use heimdall_contract::managed::IdentitySelectionEnforcement as E;
        use heimdall_contract::provider::IdentitySelection as S;
        let pairs = [selection_pair("h1"), selection_pair("h2")];
        let both = |a, b| {
            vec![
                observation("h1-alias", Some(a)),
                observation("h2-alias", Some(b)),
            ]
        };
        assert_eq!(
            report_selection(&pairs, both(S::Exclusive, S::Exclusive)),
            Some(E::ClientConfigurationAndSigner),
            "every pair exclusive"
        );
        for (obs, what) in [
            (both(S::Exclusive, S::NotExclusive), "one not exclusive"),
            (both(S::Undetermined, S::Exclusive), "one undetermined"),
            (
                vec![observation("h1-alias", Some(S::Exclusive))],
                "one unobserved",
            ),
            (
                vec![
                    observation("h1-alias", Some(S::Exclusive)),
                    observation("h2-alias", None),
                ],
                "one not evaluated",
            ),
            (Vec::new(), "nothing observed"),
        ] {
            assert_eq!(report_selection(&pairs, obs), Some(E::Unknown), "{what}");
        }
        // The class itself, weakest over the pairs.
        assert_eq!(
            selection_class(&pairs, &both(S::Exclusive, S::Exclusive)),
            SelectionClass::Exclusive
        );
        assert_eq!(
            selection_class(&pairs, &both(S::NotExclusive, S::Exclusive)),
            SelectionClass::NotExclusive
        );
        assert_eq!(
            selection_class(&pairs, &both(S::NotExclusive, S::Undetermined)),
            SelectionClass::Undetermined
        );
        let mut no_alias = selection_pair("h1");
        no_alias.alias = None;
        assert_eq!(
            selection_class(&[no_alias], &both(S::Exclusive, S::Exclusive)),
            SelectionClass::Undetermined
        );
        // The snapshot asks the source for exactly the request's aliases.
        struct Seen(Mutex<Vec<String>>);
        impl ManagedSourceRead for Seen {
            fn observations(
                &self,
                aliases: &[String],
            ) -> Vec<heimdall_contract::doctor::AliasObservation> {
                self.0.lock().unwrap().extend(aliases.iter().cloned());
                aliases
                    .iter()
                    .map(|a| observation(a, Some(S::Exclusive)))
                    .collect()
            }
        }
        let seen = Seen(Mutex::new(Vec::new()));
        let snap = snapshot(&seen, &pairs);
        assert_eq!(
            *seen.0.lock().unwrap(),
            vec!["h1-alias".to_owned(), "h2-alias".to_owned()]
        );
        assert_eq!(snap.observations, both(S::Exclusive, S::Exclusive));
    }
}

// =================================================================================
// ⟨M03 wave 4, round 2 (R2-E)⟩ `issuer_crash_blocks_reissue_not_signing`
// =================================================================================

/// m03-plan U10 "Runtime" `issuer_crash_blocks_reissue_not_signing` (ADR-0008 D3 item 7:
/// "while the issuer is not `ready`, new activations and re-issues fail ...; existing
/// grants keep signing with their installed keys; a grant whose K_env is lost becomes
/// `degraded` with `credential_reissue_pending`"; D2 item 3: `issuer_unavailable`
/// permits signing).
///
/// **Harness** (R2-C's `managed_store::live_tests` construction, over the crate's public
/// items): the production `Operations` with the production `ManagedCertificateAdapter`,
/// the runtime's `StoreSources`, `OpsInstallView` and `StoreCleanup`, the production
/// `ManagedEffectsImpl`, `SignerTable` and `EndpointRegistry` (a real binding endpoint on
/// a Unix socket in an owner-only scratch runtime directory), and the runtime's
/// `Supervisor` for the re-issue hook. The **issuer is a port-level fixture**
/// ([`FlakyIssuer`]): a per-run K_ca signs exactly the reserved bounds for the grant's
/// live K_env (`heimdall_credential::cert::build_and_sign`, the child's code path)
/// while it is up; "the crash" makes it report `crashed` and refuse every sign
/// `issuer_unavailable`, as the real `ChildIssuer` client does while its child is down.
/// No process is started. A "restart" is an in-process reconstruction over the same
/// store (a new vault: the installed instance becomes `lost`).
#[cfg(unix)]
mod issuer_crash {
    use super::*;

    use std::io::{Read as _, Write as _};
    use std::sync::RwLock;
    use std::sync::atomic::AtomicBool;

    use heimdall_adapters::managed::ManagedCertificateAdapter;
    use heimdall_adapters::managed::effects::{BindingEndpoints, ManagedEffectsImpl};
    use heimdall_adapters::managed::files::SlotRoot;
    use heimdall_app::managed::ManagedWiring;
    use heimdall_app::ports::{AdapterError, SignerEndpoint};
    use heimdall_contract::ids::{BindingId, IdentityId};
    use heimdall_contract::managed::{ConnectionPolicy, LockBehavior, PreferredMechanism};
    use heimdall_contract::provider::EndpointRef;
    use heimdall_contract::request::EnsureData;
    use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
    use heimdall_credential::endpoints::{EndpointLayout, EndpointRegistry};
    use heimdall_credential::signer::{HookFuture, SignHook, SignStep, SignerLimits};
    use heimdall_credential::table::SignerTable;
    use heimdall_credential::vault::KeyVault;
    use heimdall_domain::catalog::{
        DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
        InteractionProfile,
    };
    use heimdall_domain::enrollment::{
        ApprovedHostKey, ApprovedTarget, EnrollmentEvidence, EnrollmentForm, EnrollmentRecord,
        EnrollmentState, ExistingAccessRecord, NoProxy, PairPreference, ProjectionStatus,
        RegistryCanonical, marker_for,
    };
    use heimdall_runtime::managed_store::{OpsInstallView, StoreCleanup, StoreSources};

    fn p1() -> AccessPair {
        pair("h1", "deploy")
    }

    fn identity_id() -> IdentityId {
        IdentityId::from_random_bytes([0x51; 16])
    }

    /// One managed pair (h1, deploy): environment, profile `dev` with a standing policy
    /// over it, the pair's existing access (an adopted public-key file, never read), a
    /// managed destination, a `verified` enrollment under the CA, the CA, and the pair
    /// preference `managed_certificate` with its projection applied.
    fn seed_managed(store: &Store, ca: &SecretCaKey) {
        let fp = ca.fingerprint().unwrap();
        let public = ca.public_openssh().unwrap();
        let p = p1();
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&EnvironmentRecord {
                    id: env_id(),
                    device: DeviceId::from_random_bytes([0x52; 16]),
                    kind: EnvironmentKind::NativeSession,
                    label: None,
                    permissions: EnvironmentPermissions {
                        automatic_activation: true,
                        managed_signing: true,
                        issuer_access: true,
                    },
                })?;
                let scope = Scope {
                    pairs: [p.clone()].into_iter().collect(),
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
                        lock_behavior: LockBehavior::Continue,
                        connection: ConnectionPolicy::default(),
                    },
                    false,
                )?;
                tx.upsert_identity(&IdentityRecord {
                    id: identity_id(),
                    revision: 1,
                    source: IdentitySource::PublicKeyFile {
                        path: "/nonexistent/fixture.pub".into(),
                    },
                    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture".into(),
                    fingerprint: "SHA256:fixture".into(),
                    interaction: InteractionProfile {
                        interaction: heimdall_contract::provider::InteractionKind::Unknown,
                        basis: heimdall_contract::provider::EvidenceBasis::Inferred,
                    },
                    label: None,
                    adopted_at: t0(),
                    updated_at: t0(),
                })?;
                tx.insert_issuer(&IssuerRecord {
                    ca_fingerprint: fp.clone(),
                    public_key: public.clone(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: t0(),
                    restored_without_log: false,
                    created_at: t0(),
                    retired_at: None,
                })?;
                tx.upsert_destination(&DestinationRecord {
                    id: p.destination.clone(),
                    alias: "h1".into(),
                    revision: 1,
                    definition: DestinationDefinition::Managed {
                        hostname: "h1.example.invalid".into(),
                        port: None,
                        account: p.account.clone(),
                        identity: identity_id(),
                    },
                    label: None,
                    updated_at: t0(),
                })?;
                let id = EnrollmentId::from_random_bytes([0x53; 16]);
                tx.seed_enrollment(&EnrollmentRecord {
                    marker: marker_for(&id),
                    id,
                    destination: p.destination.clone(),
                    account: p.account.clone(),
                    ca_fingerprint: fp.clone(),
                    form: EnrollmentForm::Account,
                    registry: RegistryRef {
                        path_display: "~/.ssh/authorized_keys".into(),
                        resolved_by: RegistryResolvedBy::RemoteHome,
                    },
                    registry_canonical: RegistryCanonical {
                        path: None,
                        resolved_by: RegistryResolvedBy::RemoteHome,
                    },
                    line_sha256: "ab".repeat(32),
                    target: ApprovedTarget {
                        hostname: "h1.example.invalid".into(),
                        port: 22,
                        user: p.account.clone(),
                        proxy: NoProxy::None,
                        host_key: ApprovedHostKey {
                            algorithm: "ssh-ed25519".into(),
                            key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                            fingerprint: "SHA256:hostfixture".into(),
                        },
                    },
                    existing_access: ExistingAccessRecord {
                        identity: identity_id(),
                        endpoint: None,
                        public_key_file: None,
                    },
                    hold: None,
                    removal_origin: None,
                    late_write: None,
                    state: EnrollmentState::Verified,
                    verified_at: Some(t0()),
                    evidence: Some(EnrollmentEvidence {
                        client: "OpenSSH_10.5p1".into(),
                        server: "OpenSSH_10.0p2".into(),
                        operation: OperationId::from_random_bytes([0x54; 16]),
                        verified_at: t0(),
                        fresh_until: shift(t0(), 90 * 86_400),
                        clock: Some(ClockMeasurement {
                            behind_upper_ms: 1400,
                            rtt_ms: 38,
                            measured_at: t0(),
                        }),
                    }),
                    created_at: t0(),
                    updated_at: t0(),
                })?;
                tx.set_pair_preference(
                    &PairPreference {
                        destination: p.destination.clone(),
                        account: p.account.clone(),
                        mechanism: PreferredMechanism::ManagedCertificate,
                        projection: ProjectionStatus::Applied { generation: 1 },
                        issuing_cas: [fp.clone()].into_iter().collect(),
                    },
                    t0(),
                )
            })
            .unwrap();
    }

    /// The fixture issuer (see the module docs): signs while `up`, refuses
    /// `issuer_unavailable` and reports `crashed` otherwise. `table` is the current
    /// process's signer table (where the grant's live K_env is).
    struct FlakyIssuer {
        store: Arc<Store>,
        table: RwLock<Option<SignerTable>>,
        ca: SecretCaKey,
        up: AtomicBool,
        signed: AtomicUsize,
        refused: AtomicUsize,
        /// What a sign answers while down (R2-F: the store reasons and a timeout).
        down: Mutex<Down>,
    }

    /// A down issuer's answer to a sign request.
    #[derive(Clone)]
    enum Down {
        /// `IssuerError::Unavailable(<reason>)`.
        Unavailable(&'static str),
        /// `IssuerError::Timeout` (no reply within the issuer's request bound).
        Timeout,
    }

    impl IssuerPort for FlakyIssuer {
        fn status(&self) -> IssuerStatusSnapshot {
            IssuerStatusSnapshot {
                status: IssuerStatus {
                    state: if self.up.load(Ordering::SeqCst) {
                        IssuerState::Ready
                    } else {
                        IssuerState::Crashed
                    },
                    reason: None,
                    cas: Vec::new(),
                    orphan_store_items: Vec::new(),
                    issuer_isolation: IssuerIsolation::SameUserProcess,
                    bundle_stale: false,
                },
            }
        }

        fn sign<'a, 'b, 'c>(
            &'a self,
            entry: IssuanceRef,
            subject: &'b str,
        ) -> Pin<Box<dyn Future<Output = Result<String, IssuerError>> + Send + 'c>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            Box::pin(async move {
                if !self.up.load(Ordering::SeqCst) {
                    self.refused.fetch_add(1, Ordering::SeqCst);
                    return Err(match self.down.lock().unwrap().clone() {
                        Down::Unavailable(why) => IssuerError::Unavailable(why.into()),
                        Down::Timeout => IssuerError::Timeout,
                    });
                }
                let refused = || IssuerError::Protocol("fixture".into());
                let e = self
                    .store
                    .transaction(|tx| tx.issuance_entry(&entry.id))
                    .map_err(|_| refused())?
                    .ok_or_else(refused)?;
                let table = self.table.read().unwrap().clone().ok_or_else(refused)?;
                let info = table.public_key(&e.grant).ok_or_else(refused)?;
                if info.openssh_line.trim() != subject.trim() {
                    return Err(refused());
                }
                let key = info.public_key().map_err(|_| refused())?;
                let cert =
                    build_and_sign(&CertificateProfile::from_bounds(&e.bounds), &key, &self.ca)
                        .map_err(|_| refused())?;
                self.signed.fetch_add(1, Ordering::SeqCst);
                cert.to_openssh().map_err(|_| refused())
            })
        }

        fn unload<'a, 'b, 'c>(
            &'a self,
            _ca: &'b CaFingerprint,
        ) -> Pin<Box<dyn Future<Output = Result<(), IssuerError>> + Send + 'c>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            Box::pin(async move { Ok(()) })
        }
    }

    /// The registry, set after `Operations::start` (the runtime's late registry).
    #[derive(Default)]
    struct Late(RwLock<Option<EndpointRegistry>>);

    impl BindingEndpoints for Late {
        fn binding_endpoint(&self, binding: &BindingId) -> Option<EndpointRef> {
            let r = self.0.read().unwrap().clone()?;
            BindingEndpoints::binding_endpoint(&r, binding)
        }
        fn create_binding_endpoint(
            &self,
            binding: &BindingId,
            generation: u64,
        ) -> Result<EndpointRef, AdapterError> {
            self.0
                .read()
                .unwrap()
                .clone()
                .ok_or_else(|| AdapterError::Unavailable("no registry".into()))?
                .create_binding_endpoint(binding, generation)
        }
        fn remove_binding_endpoint(
            &self,
            binding: &BindingId,
            generation: u64,
        ) -> Result<bool, AdapterError> {
            match self.0.read().unwrap().clone() {
                Some(r) => r.remove_binding_endpoint(binding, generation),
                None => Ok(false),
            }
        }
    }

    /// The sign steps each request reached, per endpoint (the signer's pause hook,
    /// which waits for nothing).
    #[derive(Default)]
    struct SignLog(Mutex<Vec<(SignerEndpoint, SignStep)>>);

    impl SignLog {
        fn count(&self, endpoint: &SignerEndpoint, step: SignStep) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(e, s)| e == endpoint && *s == step)
                .count()
        }
    }

    impl SignHook for SignLog {
        fn at<'a>(&'a self, endpoint: &'a SignerEndpoint, step: SignStep) -> HookFuture<'a> {
            self.0.lock().unwrap().push((endpoint.clone(), step));
            Box::pin(async {})
        }
    }

    struct Process {
        ops: Operations,
        table: SignerTable,
        registry: EndpointRegistry,
        signs: Arc<SignLog>,
        shutdown: CancellationToken,
    }

    struct Rig {
        dir: tempfile::TempDir,
        store: Arc<Store>,
        clock: Arc<VirtualClock>,
        sync: Arc<ScriptedTimeSync>,
        issuer: Arc<FlakyIssuer>,
    }

    fn owner_only(path: &std::path::Path) {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    impl Rig {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            owner_only(&dir.path().join("state"));
            owner_only(&dir.path().join("run"));
            let store =
                Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
            let ca = SecretCaKey::generate().unwrap();
            seed_managed(&store, &ca);
            let issuer = Arc::new(FlakyIssuer {
                store: store.clone(),
                table: RwLock::new(None),
                ca,
                up: AtomicBool::new(true),
                signed: AtomicUsize::new(0),
                refused: AtomicUsize::new(0),
                down: Mutex::new(Down::Unavailable("issuer_unavailable")),
            });
            Self {
                dir,
                store,
                clock: VirtualClock::at(t0()),
                sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                issuer,
            }
        }

        fn run_dir(&self) -> std::path::PathBuf {
            self.dir.path().join("run")
        }

        /// One runtime process over the shared store (its own vault, table, registry,
        /// effects and adapter).
        async fn process(&self) -> Process {
            let sources = StoreSources::new(self.store.clone(), env_id());
            let table = SignerTable::new(Arc::new(KeyVault::new()));
            let late = Arc::new(Late::default());
            let layout = EndpointLayout::unix(&self.run_dir()).unwrap();
            let effects = ManagedEffectsImpl::new(
                table.clone(),
                late.clone(),
                Arc::new(sources.clone()),
                self.run_dir(),
                SlotRoot {
                    data_dir: self.dir.path().join("state"),
                    environment: env_id(),
                },
            )
            .with_slot_store(Arc::new(sources.clone()));
            let adapter = ManagedCertificateAdapter::new(
                "managed-crash",
                Arc::new(sources.clone()),
                Some(effects.clone()),
                Some(layout.clone()),
            )
            .with_cleanup(Arc::new(StoreCleanup::new(
                sources.clone(),
                effects.clone(),
                None,
            )));
            let ops = Operations::start(OperationsConfig {
                store: self.store.clone(),
                clock: self.clock.clone(),
                time_sync: self.sync.clone(),
                time_policy: TimePolicy::default(),
                environment: env_id(),
                adapters: vec![Arc::new(adapter) as Arc<dyn CredentialAdapter>],
                stage_hook: Arc::new(NoStageHook),
                limits: Limits::default(),
                default_window: HOUR,
                projection: None,
            })
            .await
            .unwrap();
            let shutdown = CancellationToken::new();
            let signs = Arc::new(SignLog::default());
            let registry = EndpointRegistry::new(
                layout,
                heimdall_ipc::endpoint::ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()),
                table.clone(),
                Arc::new(ops.clone()),
                SignerLimits::default(),
                shutdown.clone(),
            )
            .with_hook(signs.clone());
            *late.0.write().unwrap() = Some(registry.clone());
            table.set_install_view(Arc::new(OpsInstallView::new(ops.clone())));
            *self.issuer.table.write().unwrap() = Some(table.clone());
            sources.set_issuer(self.issuer.clone() as Arc<dyn IssuerPort>);
            ops.set_managed_wiring(ManagedWiring {
                effects: Some(Arc::new(effects)),
                issuer: Some(self.issuer.clone() as Arc<dyn IssuerPort>),
                ..ManagedWiring::default()
            });
            Process {
                ops,
                table,
                registry,
                signs,
                shutdown,
            }
        }

        async fn ensure(
            &self,
            p: &Process,
            tag: &str,
        ) -> Result<EnsureData, heimdall_app::OpError> {
            let mut req = ensure_req(tag);
            // Interactive: a non-interactive managed ensure passes the commit only for an
            // alias observed `exclusive` (R2C-Q1's fix); these sources observe nothing.
            req.interaction = InteractionMode::Interactive;
            p.ops
                .ensure(&unattended(ClientRole::Owner), req)
                .await
                .map(|c| c.data)
        }

        fn grant(&self, g: &GrantId) -> (GrantState, Option<DegradedReason>) {
            self.store
                .transaction(|tx| Ok((tx.grant(g)?.unwrap().state, tx.grant_degradation(g)?)))
                .unwrap()
        }

        fn published(&self, g: &GrantId) -> usize {
            self.store
                .transaction(|tx| tx.issuance_entries(g))
                .unwrap()
                .iter()
                .filter(|e| e.state == IssuanceState::Published)
                .count()
        }

        fn instances(&self, g: &GrantId) -> Vec<CredentialState> {
            self.store
                .transaction(|tx| tx.credential_instances_for_grant(g))
                .unwrap()
                .into_iter()
                .map(|i| i.state)
                .collect()
        }
    }

    fn put_string(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&u32::try_from(b.len()).unwrap().to_be_bytes());
        out.extend_from_slice(b);
    }

    fn take_string(b: &[u8]) -> (&[u8], &[u8]) {
        let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
        (&b[4..4 + n], &b[4 + n..])
    }

    fn exchange(conn: &mut std::os::unix::net::UnixStream, body: &[u8]) -> Vec<u8> {
        let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        conn.write_all(&framed).unwrap();
        let mut len = [0u8; 4];
        conn.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
        conn.read_exact(&mut reply).unwrap();
        reply
    }

    /// A real agent-protocol client on the binding endpoint: list its identities (the
    /// grant's one certificate), then ask it to sign a userauth request (RFC 4252 §7)
    /// for `account` presenting that certificate. `Some(signature)` for an
    /// `SSH_AGENT_SIGN_RESPONSE` (14), `None` for `SSH_AGENT_FAILURE`.
    async fn sign_through(endpoint: &str, account: &str) -> Option<Vec<u8>> {
        let (endpoint, account) = (endpoint.to_owned(), account.to_owned());
        tokio::task::spawn_blocking(move || {
            let mut conn = std::os::unix::net::UnixStream::connect(&endpoint).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let listed = exchange(&mut conn, &[11]);
            assert_eq!(listed[0], 12, "an identities answer");
            assert_eq!(u32::from_be_bytes(listed[1..5].try_into().unwrap()), 1);
            let (blob, _) = take_string(&listed[5..]);
            let mut data = Vec::new();
            put_string(&mut data, &[0x5a; 32]);
            data.push(50);
            put_string(&mut data, account.as_bytes());
            put_string(&mut data, b"ssh-connection");
            put_string(&mut data, b"publickey");
            data.push(1);
            put_string(&mut data, b"ssh-ed25519-cert-v01@openssh.com");
            put_string(&mut data, blob);
            let mut req = vec![13];
            put_string(&mut req, blob);
            put_string(&mut req, &data);
            req.extend_from_slice(&0u32.to_be_bytes());
            let reply = exchange(&mut conn, &req);
            (reply[0] == 14).then(|| take_string(&reply[1..]).0.to_vec())
        })
        .await
        .unwrap()
    }

    /// After a managed grant is active, the issuer crashes: the supervision pass runs
    /// and the grant keeps its signing authority (`active`, or `degraded` only for a
    /// reason whose sign rule permits signing: R2E-Q2); a **real** sign request
    /// through the binding endpoint is admitted under the permit and signed with the
    /// installed K_env; a new activation is refused `CAPABILITY_UNAVAILABLE`,
    /// `issuer_unavailable` while the issuer is down (the fix this test guards:
    /// `Operations::prepare_error`, R2-E worklog). Then a
    /// restart loses K_env (`lost`, `credential_reissue_pending`), and
    /// `managed_reissue_pass` (the supervisor's hook) re-issues nothing while the issuer
    /// stays down: no certificate signed, nothing published, nothing installed, the
    /// grant still `credential_reissue_pending`, on every pass. Once the issuer
    /// returns, the same pass re-issues: `active` again, one more certificate published
    /// and installed.
    #[tokio::test]
    async fn issuer_crash_blocks_reissue_not_signing() {
        let w = Rig::new();
        let p = w.process().await;
        let data = w
            .ensure(&p, "crash-1")
            .await
            .unwrap_or_else(|e| panic!("ensure: {} {:?} {}", e.code, e.reason, e.message));
        let g = data.grant_id.clone();
        assert_eq!(w.grant(&g), (GrantState::Active, None));
        assert_eq!(w.issuer.signed.load(Ordering::SeqCst), 1);
        assert_eq!(w.instances(&g), vec![CredentialState::Installed]);
        let endpoint = data
            .consumer
            .signing_endpoint
            .clone()
            .expect("the ensure result names the binding endpoint");
        let binding = SignerEndpoint::Binding(data.binding_id.clone());

        // The crash.
        w.issuer.up.store(false, Ordering::SeqCst);
        p.ops.issuer_supervision_pass().await.unwrap();
        let (state, reason) = w.grant(&g);
        assert!(
            state == GrantState::Active
                || (state == GrantState::Degraded
                    && reason.is_some_and(DegradedReason::permits_signing)),
            "the grant keeps its signing authority: {state:?} {reason:?}"
        );
        // An installed key still signs: a real request through the binding endpoint.
        let signature = sign_through(&endpoint, "deploy").await;
        let signer = p.registry.signer(&binding).expect("the binding's signer");
        assert!(
            signature.is_some_and(|s| !s.is_empty()),
            "signed while the issuer is down; refusals {:?}",
            signer.refusals()
        );
        assert_eq!(
            p.signs.count(&binding, SignStep::Admitted),
            1,
            "permit held"
        );
        assert_eq!(p.signs.count(&binding, SignStep::Signed), 1);
        assert!(signer.refusals().is_empty(), "{:?}", signer.refusals());
        // A new activation needs the issuer: `CAPABILITY_UNAVAILABLE`,
        // `issuer_unavailable` (D3 item 7), nothing signed.
        let e = w.ensure(&p, "crash-2").await.unwrap_err();
        assert_eq!(
            (e.code.clone(), e.reason.as_deref()),
            (Code::CapabilityUnavailable, Some("issuer_unavailable")),
            "{e:?}"
        );
        assert_eq!(w.issuer.signed.load(Ordering::SeqCst), 1);

        // A restart while the issuer is down: K_env is lost.
        p.shutdown.cancel();
        p.registry.stop_all();
        drop(p);
        let q = w.process().await;
        assert_eq!(
            w.grant(&g),
            (
                GrantState::Degraded,
                Some(DegradedReason::CredentialReissuePending)
            )
        );
        assert_eq!(w.instances(&g), vec![CredentialState::Lost]);
        let sup = Supervisor::new(q.ops.clone(), SupervisorConfig::default())
            .with_state(w.store.clone(), w.clock.clone())
            .with_jitter(Arc::new(FixedJitter(1.0)));
        let published = w.published(&g);
        for _ in 0..2 {
            q.ops.issuer_supervision_pass().await.unwrap();
            assert!(
                sup.managed_reissue_pass().await.unwrap().is_empty(),
                "nothing re-issued while the issuer is down"
            );
            assert_eq!(
                w.grant(&g),
                (
                    GrantState::Degraded,
                    Some(DegradedReason::CredentialReissuePending)
                )
            );
            assert_eq!(w.issuer.signed.load(Ordering::SeqCst), 1, "nothing signed");
            assert_eq!(w.published(&g), published, "nothing published");
            assert!(
                !w.instances(&g).contains(&CredentialState::Installed),
                "nothing installed: {:?}",
                w.instances(&g)
            );
            assert!(q.table.public_key(&g).is_none(), "no K_env left behind");
        }
        assert!(
            w.issuer.refused.load(Ordering::SeqCst) >= 2,
            "the pass asked"
        );

        // The issuer returns: the same pass re-issues.
        w.issuer.up.store(true, Ordering::SeqCst);
        q.ops.issuer_supervision_pass().await.unwrap();
        assert_eq!(sup.managed_reissue_pass().await.unwrap(), vec![g.clone()]);
        assert_eq!(w.grant(&g), (GrantState::Active, None));
        assert_eq!(w.issuer.signed.load(Ordering::SeqCst), 2);
        assert_eq!(w.published(&g), published + 1, "one more certificate");
        assert!(w.instances(&g).contains(&CredentialState::Installed));
        assert!(
            q.table.public_key(&g).is_some(),
            "the new K_env is installed"
        );
        q.shutdown.cancel();
        q.registry.stop_all();
    }

    /// ⟨R2-F, R2E-Q3⟩ ADR-0008 D3 item 7: while the issuer is not `ready`, a new
    /// activation fails `CAPABILITY_UNAVAILABLE`, reason `issuer_unavailable` "(or the
    /// store reason)". The issuer's own store reason reaches the refusal
    /// (`issuer_store_locked`, `issuer_store_unavailable`: the driver's `sign` keeps it,
    /// `Operations::prepare_error` reports it); a timeout or any other unavailability
    /// is `issuer_unavailable`. Nothing is signed and no grant is left active.
    #[tokio::test]
    async fn refused_activation_carries_issuer_store_reason() {
        let w = Rig::new();
        let p = w.process().await;
        w.issuer.up.store(false, Ordering::SeqCst);
        let cases = [
            (
                Down::Unavailable("issuer_store_locked"),
                "issuer_store_locked",
            ),
            (
                Down::Unavailable("issuer_store_unavailable"),
                "issuer_store_unavailable",
            ),
            (Down::Timeout, "issuer_unavailable"),
            (Down::Unavailable("issuer_restarting"), "issuer_unavailable"),
            (
                Down::Unavailable("issuer_unavailable"),
                "issuer_unavailable",
            ),
        ];
        for (n, (down, want)) in cases.into_iter().enumerate() {
            *w.issuer.down.lock().unwrap() = down;
            let e = w
                .ensure(&p, &format!("store-reason-{n}"))
                .await
                .unwrap_err();
            assert_eq!(
                (e.code.clone(), e.reason.as_deref()),
                (Code::CapabilityUnavailable, Some(want)),
                "case {n}: {e:?}"
            );
        }
        assert_eq!(w.issuer.signed.load(Ordering::SeqCst), 0, "nothing signed");
        assert_eq!(w.issuer.refused.load(Ordering::SeqCst), 5);
        p.shutdown.cancel();
        p.registry.stop_all();
    }
}

// =================================================================================
// M03 wave 4, round 2, R2-F (R2E-Q1): the preference switch through `setup apply`
// =================================================================================

/// ADR-0008 D5 §6.6 and m03-plan U0b row 9: after E5 leaves a pair `managed_certificate`
/// with `projection: pending`, P keeps rendering the existing identity until the owner
/// applies the projection change through M02's setup (preview, `ApplyProjection`
/// decision, journaled apply); the pair resolves to `managed_certificate` only when the
/// projection rendering it is applied.
///
/// **Harness:** the production `Service` (managed wiring, no CA so no issuer child, a
/// fake unlocked session-lock source) with its projection writer over a scratch account
/// home, so the setup preview reads the runtime's store-backed `ManagedPairSource` and
/// the apply goes through the journaled setup driver and its store sink. Catalog: two
/// managed destinations, `h1` (alias `alpha`) and `h2` (alias `beta`), account
/// `deploy`, one adopted identity with a per-run fixture public key. Preferences are
/// seeded in the store (the enrollment that would write them is not this test's
/// subject). A test-only writer hook ([`FlipAtCommit`]) changes a preference between the
/// driver's plan recomputation and the SSH item's commit.
#[cfg(unix)]
mod setup_switch {
    use super::*;

    use heimdall_contract::managed::{PreferredMechanism, SessionLockState};
    use heimdall_contract::setup::{PreviewIntent, ProjectionItem, SetupPlan, SetupRequest};
    use heimdall_domain::catalog::{
        DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
        InteractionProfile,
    };
    use heimdall_domain::enrollment::{PairPreference, ProjectionStatus};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::{ProjectionConfig, ReplaceHook, ReplacePoint};
    use heimdall_runtime::service::{
        ManagedOptions, ProjectionWiring, STATE_DB_FILE, ServiceOptions, SessionLockWiring,
    };
    use heimdall_runtime::{Config, Paths, Service};
    use heimdall_testkit::agent::FixtureKey;
    use heimdall_testkit::session_lock::FakeSessionLockSource;

    /// A preference written by the writer hook right before the SSH item's commit (once).
    #[derive(Default)]
    struct FlipAtCommit {
        store: Mutex<Option<Arc<Store>>>,
        flip: Mutex<Option<PairPreference>>,
    }

    impl ReplaceHook for FlipAtCommit {
        fn at(&self, point: ReplacePoint, _step: u16) {
            if point != ReplacePoint::BeforeReceipt("committed") {
                return;
            }
            let Some(p) = self.flip.lock().unwrap().take() else {
                return;
            };
            let store = self
                .store
                .lock()
                .unwrap()
                .clone()
                .expect("the store is set");
            store
                .transaction(|tx| tx.set_pair_preference(&p, t0()))
                .unwrap();
        }
    }

    fn owner_only(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn preference(d: &str, mechanism: PreferredMechanism) -> PairPreference {
        PairPreference {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse("deploy").unwrap(),
            mechanism,
            projection: ProjectionStatus::Pending,
            issuing_cas: [ca(7)].into_iter().collect(),
        }
    }

    struct Rig {
        _tmp: tempfile::TempDir,
        root: std::path::PathBuf,
        hook: Arc<FlipAtCommit>,
        svc: Service,
        token: CancellationToken,
    }

    impl Rig {
        /// The runtime over a seeded store; `seeded` are the stored preferences.
        async fn start(seeded: &[PairPreference]) -> Rig {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            owner_only(&root.join("acct").join(".ssh"));
            std::fs::write(root.join("acct/.ssh/config"), b"").unwrap();
            // Owner-only explicitly: under umask 002 (the devbox) the file would be 0664,
            // which M02 classifies `unmanageable_file` (manual mode, no rollback items).
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(
                    root.join("acct/.ssh/config"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            owner_only(&root.join("etc"));
            owner_only(&root.join("cfg"));
            let paths = Paths::under(&root.join("hh"));
            paths.ensure().unwrap();
            let store = Store::open(
                &paths.state_dir.join(STATE_DB_FILE),
                Arc::new(heimdall_store::NoFaults),
            )
            .unwrap();
            seed(&store);
            let key = FixtureKey::generate();
            let identity = heimdall_contract::ids::IdentityId::from_random_bytes([0x61; 16]);
            store
                .transaction(|tx| {
                    tx.upsert_identity(&IdentityRecord {
                        id: identity.clone(),
                        revision: 1,
                        source: IdentitySource::PublicKeyFile {
                            path: "/nonexistent/fixture.pub".into(),
                        },
                        public_key: key.public_line_without_comment(),
                        fingerprint: key.fingerprint(),
                        interaction: InteractionProfile {
                            interaction: heimdall_contract::provider::InteractionKind::None,
                            basis: heimdall_contract::provider::EvidenceBasis::Inferred,
                        },
                        label: None,
                        adopted_at: t0(),
                        updated_at: t0(),
                    })?;
                    for (d, alias) in [("h1", "alpha"), ("h2", "beta")] {
                        tx.upsert_destination(&DestinationRecord {
                            id: DestinationId::parse(d).unwrap(),
                            alias: alias.into(),
                            revision: 1,
                            definition: DestinationDefinition::Managed {
                                hostname: format!("{d}.example.invalid"),
                                port: None,
                                account: AccountName::parse("deploy").unwrap(),
                                identity: identity.clone(),
                            },
                            label: None,
                            updated_at: t0(),
                        })?;
                    }
                    for p in seeded {
                        tx.set_pair_preference(p, t0())?;
                    }
                    Ok(())
                })
                .unwrap();
            drop(store);
            let hook = Arc::new(FlipAtCommit::default());
            let mut c = ProjectionConfig::new(
                SshPaths::with_test_override(root.join("acct"), root.join("etc")),
                Platform::current(),
                root.join("cfg"),
            );
            c.env = Env::from_vars([
                ("HOME", root.join("acct").display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
            ]);
            c.hook = Some(hook.clone() as Arc<dyn ReplaceHook>);
            let mut o = ServiceOptions::with_clock(
                VirtualClock::at(t0()),
                ScriptedTimeSync::new(SyncStatus::Synchronized),
            );
            o.endpoint_prefix = "hmtest-".to_owned();
            o.projection = ProjectionWiring::Config(Box::new(c));
            o.managed = Some(ManagedOptions {
                session_lock: SessionLockWiring::Source(Arc::new(FakeSessionLockSource::new(
                    SessionLockState::Unlocked,
                ))),
                ..ManagedOptions::default()
            });
            let token = CancellationToken::new();
            let svc = Service::start_with(paths, Config::default(), o, token.clone())
                .await
                .unwrap();
            *hook.store.lock().unwrap() = Some(svc.store().clone());
            Rig {
                _tmp: tmp,
                root,
                hook,
                svc,
                token,
            }
        }

        async fn stop(self) {
            let running = tokio::spawn(self.svc.run());
            self.token.cancel();
            running.await.unwrap().unwrap();
        }

        fn pref(&self, d: &str) -> Option<PairPreference> {
            self.svc
                .store()
                .transaction(|tx| tx.pair_preference(&pair(d, "deploy")))
                .unwrap()
        }

        fn set(&self, p: &PairPreference) {
            self.svc
                .store()
                .transaction(|tx| tx.set_pair_preference(p, t0()))
                .unwrap();
        }

        fn ssh_generation(&self) -> u64 {
            self.svc
                .store()
                .transaction(|tx| tx.projection_record(&env_id()))
                .unwrap()
                .and_then(|r| r.items.get(&ProjectionItem::Ssh).map(|i| i.generation))
                .expect("the SSH item is committed")
        }

        /// P as the last apply wrote it.
        fn p(&self) -> String {
            std::fs::read_to_string(self.root.join("cfg").join("ssh_config")).unwrap_or_default()
        }

        async fn preview(&self, intent: PreviewIntent) -> SetupPlan {
            let c = self
                .svc
                .operations()
                .setup(
                    &attended(ClientRole::Owner),
                    SetupRequest::Preview { intent },
                )
                .await
                .unwrap_or_else(|e| panic!("preview: {e:?}"));
            serde_json::from_value(c.data).unwrap()
        }

        /// Apply `plan` (approving the `ApplyProjection` decision when one is asked for)
        /// and answer the settled result, or the refusal.
        async fn apply(
            &self,
            plan: &SetupPlan,
            tag: &str,
        ) -> Result<serde_json::Value, heimdall_app::OpError> {
            let ops = self.svc.operations();
            let request_id = RequestId::parse(&format!("req_switch_{tag}")).unwrap();
            let req = || match plan.intent {
                PreviewIntent::Rollback { .. } => SetupRequest::Rollback {
                    plan_digest: plan.plan_digest.clone(),
                    request_id: request_id.clone(),
                },
                _ => SetupRequest::Apply {
                    plan_digest: plan.plan_digest.clone(),
                    request_id: request_id.clone(),
                },
            };
            match ops.setup(&attended(ClientRole::Owner), req()).await {
                Ok(c) => Ok(c.data),
                Err(e) if matches!(e.code, Code::ApprovalRequired | Code::InteractionRequired) => {
                    let id = e.next.decision_ref.clone().expect("a decision reference");
                    ops.decide(
                        &attended(ClientRole::Owner),
                        DecideRequest {
                            decision_id: DecisionId::parse(&id).unwrap(),
                            verdict: Verdict::Approve,
                        },
                    )
                    .await
                    .unwrap_or_else(|e| panic!("approve: {e:?}"));
                    ops.setup(&attended(ClientRole::Owner), req())
                        .await
                        .map(|c| c.data)
                }
                Err(e) => Err(e),
            }
        }

        async fn apply_ok(&self, intent: PreviewIntent, tag: &str) -> SetupPlan {
            let plan = self.preview(intent).await;
            let r = self
                .apply(&plan, tag)
                .await
                .unwrap_or_else(|e| panic!("apply {tag}: {e:?}"));
            assert!(
                r["items"]
                    .as_array()
                    .is_some_and(|i| i.iter().all(|i| i["outcome"] == "applied")),
                "{tag}: {r}"
            );
            plan
        }
    }

    fn renders_managed(plan: &SetupPlan, d: &str) -> bool {
        plan.findings.iter().any(|f| {
            f.code == heimdall_contract::doctor::finding::SLOT_FREE
                && f.subject.id.as_deref() == Some(d)
        })
    }

    fn apply_intent() -> PreviewIntent {
        PreviewIntent::Apply { include_git: false }
    }

    /// The commit of a `setup apply` whose plan renders `h1`'s managed section records
    /// `h1`'s preference `applied` at the committed SSH generation, issuing CAs and
    /// mechanism unchanged; `h2` (preference `existing`, rendered as existing access) is
    /// not written, and a pair without a stored preference gets none.
    #[tokio::test]
    async fn setup_apply_managed_rendering_marks_only_that_pair_applied() {
        let existing = preference("h2", PreferredMechanism::Existing);
        let rig = Rig::start(&[
            preference("h1", PreferredMechanism::ManagedCertificate),
            existing.clone(),
        ])
        .await;
        let plan = rig.apply_ok(apply_intent(), "first").await;
        assert!(renders_managed(&plan, "h1"), "{:?}", plan.findings);
        assert!(!renders_managed(&plan, "h2"));
        let generation = rig.ssh_generation();
        let h1 = rig.pref("h1").unwrap();
        assert_eq!(h1.projection, ProjectionStatus::Applied { generation });
        assert_eq!(h1.mechanism, PreferredMechanism::ManagedCertificate);
        assert_eq!(h1.issuing_cas, [ca(7)].into_iter().collect());
        assert_eq!(rig.pref("h2"), Some(existing), "h2 is not written");
        assert!(rig.p().contains("Host alpha"), "{}", rig.p());
        rig.stop().await;

        // A pair with no stored preference (every M02 pair) is never given one.
        let rig = Rig::start(&[preference("h1", PreferredMechanism::ManagedCertificate)]).await;
        rig.apply_ok(apply_intent(), "first").await;
        assert!(matches!(
            rig.pref("h1").unwrap().projection,
            ProjectionStatus::Applied { .. }
        ));
        assert_eq!(rig.pref("h2"), None);
        rig.stop().await;
    }

    /// A commit that renders the pair's existing-access block does not mark it applied,
    /// and a commit that no longer renders its managed section returns it to `pending`:
    /// a switch back to `existing` leaves the preference `existing`/`pending`; switching
    /// to managed again and applying marks it applied at the new generation; a rollback
    /// of the SSH item returns it to `pending` (P no longer renders it).
    #[tokio::test]
    async fn setup_rollback_or_existing_rendering_never_marks_pair_applied() {
        let rig = Rig::start(&[preference("h1", PreferredMechanism::ManagedCertificate)]).await;
        rig.apply_ok(apply_intent(), "managed").await;
        assert!(matches!(
            rig.pref("h1").unwrap().projection,
            ProjectionStatus::Applied { .. }
        ));
        // Switch back (as `destination prefer h1 existing` writes it), then apply.
        rig.set(&preference("h1", PreferredMechanism::Existing));
        let plan = rig.apply_ok(apply_intent(), "existing").await;
        assert!(!renders_managed(&plan, "h1"));
        assert_eq!(
            rig.pref("h1"),
            Some(preference("h1", PreferredMechanism::Existing)),
            "an existing-access rendering marks nothing"
        );
        // Managed again: applied at the new generation.
        rig.set(&preference("h1", PreferredMechanism::ManagedCertificate));
        rig.apply_ok(apply_intent(), "managed-again").await;
        let generation = rig.ssh_generation();
        assert_eq!(
            rig.pref("h1").unwrap().projection,
            ProjectionStatus::Applied { generation }
        );
        // A rollback of the SSH item: P is removed, the pair is pending again.
        rig.apply_ok(
            PreviewIntent::Rollback {
                keep_key_files: false,
                items: [ProjectionItem::Ssh].into_iter().collect(),
            },
            "rollback",
        )
        .await;
        assert_eq!(
            rig.pref("h1"),
            Some(preference("h1", PreferredMechanism::ManagedCertificate)),
            "a rollback returns the pair to pending"
        );
        rig.stop().await;
    }

    /// A preview that did not render the pair's managed section never marks it applied:
    /// (1) a preference changed to `managed_certificate` after the preview makes the
    /// apply of that preview stale (`CONFIG_CONFLICT`, nothing written, the pair still
    /// `pending`); (2) a preference changed to `managed_certificate` **during** the apply
    /// of an existing-access plan, after the driver's recomputation and before the SSH
    /// item's commit (the writer hook), leaves the pair `pending`: the commit records
    /// what the plan rendered, not the preference it reads. And (3) the reverse: a
    /// managed plan whose pair is switched to `existing` before the commit leaves the
    /// `existing` preference unwritten.
    #[tokio::test]
    async fn stale_preview_cannot_mark_pair_applied() {
        let rig = Rig::start(&[preference("h1", PreferredMechanism::Existing)]).await;
        // (1) stale.
        let plan = rig.preview(apply_intent()).await;
        assert!(!renders_managed(&plan, "h1"));
        let managed = preference("h1", PreferredMechanism::ManagedCertificate);
        rig.set(&managed);
        let e = rig.apply(&plan, "stale").await.unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
        assert_eq!(rig.pref("h1"), Some(managed.clone()), "still pending");
        assert!(rig.p().is_empty(), "nothing written");
        // (2) the preference moves to managed between the recomputation and the commit.
        rig.set(&preference("h1", PreferredMechanism::Existing));
        let plan = rig.preview(apply_intent()).await;
        assert!(!renders_managed(&plan, "h1"));
        *rig.hook.flip.lock().unwrap() = Some(managed.clone());
        let r = rig.apply(&plan, "race").await.unwrap();
        assert_eq!(r["items"][0]["outcome"], "applied", "{r}");
        assert!(rig.hook.flip.lock().unwrap().is_none(), "the hook ran");
        assert_eq!(
            rig.pref("h1"),
            Some(managed.clone()),
            "the commit of an existing-access rendering leaves the pair pending"
        );
        // (3) the reverse: a managed plan, the pair switched to existing before the commit.
        let plan = rig.preview(apply_intent()).await;
        assert!(renders_managed(&plan, "h1"));
        let existing = preference("h1", PreferredMechanism::Existing);
        *rig.hook.flip.lock().unwrap() = Some(existing.clone());
        rig.apply(&plan, "reverse").await.unwrap();
        assert_eq!(
            rig.pref("h1"),
            Some(existing),
            "an existing preference is never marked"
        );
        rig.stop().await;
    }
}
