//! M03 wave 0 (U0b rows 2–4, 9–12, 19, 21, 22 and escalation E10): issuance under a CA,
//! verification issuance, per-pair mechanism resolution, lock and connection policy,
//! the degraded sign rule, the bind-time owned connection, pair preferences and the
//! enrollment cancel refusal, through the production `heimdall_app::Operations`.
//!
//! Harness as `tests/model/operations.rs`: `Store::open_in_memory`, `VirtualClock`,
//! `ScriptedTimeSync` and `FakeCredentialAdapter`. Store rows M03 adds (issuers,
//! enrollments, preferences, enrollment operations) are seeded through the store's
//! `Txn` methods. Every value is synthetic (`example.invalid`, fixture keys); no
//! owner key, agent or keychain is touched. Restarts are in-process.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::{
    IssuanceFacts, IssuanceRequest, Limits, MANAGED_CERTIFICATE, Publication, VerificationRequest,
    dedicated_at_bind, degraded_refuses_use, permitted_extensions, unattended_refusal,
    verified_client_image,
};
#[cfg(unix)]
use heimdall_app::ports::ProcessLiveness;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, LockState,
    PrepareOutcome, SessionLockSource,
};
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
use heimdall_contract::canonical::RequestHash;
use heimdall_contract::catalog::CatalogRequest;
use heimdall_contract::enrollment::{EnrollmentRequest, VerifyMode};
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, DestinationId, DeviceId, EnrollmentId, EnvironmentId,
    GrantId, IdentityId, OperationId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::managed::{
    ConnectionPolicy, ConnectionRequest, ExistingConnectionsMode, LockBehavior, MultiplexingMode,
    PreferredMechanism,
};
use heimdall_contract::provider::EvidenceBasis;
use heimdall_contract::request::{
    BindForm, BindRequest, CancelRequest, ConsumerExecutable, ConsumerIntegration, ConsumerKind,
    DecideRequest, DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest,
    ExistingConnectionsPolicy, InteractionMode, LaunchBinding, NewAuthenticationExpiry,
    PolicyAction, ProcessHolder, RefreshDependency, Request, RequiredCapabilities,
    RevocationStatus, Verdict, WaitMode, WorkloadIsolation,
};
use heimdall_contract::{Code, GrantState, OperationState, Timestamp};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentEventKind, EnrollmentForm, EnrollmentRecord,
    EnrollmentState, ExistingAccessRecord, NoProxy, PairPreference, ProjectionStatus,
    RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{DegradedReason, DegradedSignRule, GrantSnapshot};
#[cfg(unix)]
use heimdall_domain::holder::HolderState;
use heimdall_domain::idempotency::{HashInput, IdempotencyKey, IdempotencyRecord, compute_hash};
use heimdall_domain::issuance::{EXTENSION_PTY, IssuanceState};
#[cfg(unix)]
use heimdall_domain::managed::{ConnectionKind, OwnedConnectionState};
use heimdall_domain::operation::{
    AdapterIdentity, EffectClass, EffectReceipt, OperationKind, OperationRecord, RecoveryIntent,
    RecoveryMetadata, StageReceipt, enrollment_stage,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_domain::verification::{VerificationPurpose, VerificationRefusal};
use heimdall_store::{IssuerRecord, Store, StoreError};
use heimdall_testkit::{
    FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock, assert_no_canary,
};

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);
const SSH: &str = if cfg!(windows) {
    "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
} else {
    "/usr/bin/ssh"
};
const OTHER_PROGRAM: &str = if cfg!(windows) {
    "C:\\Windows\\System32\\cmd.exe"
} else {
    "/bin/sh"
};

fn t0() -> Timestamp {
    "2026-11-02T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn owner() -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    }
}

fn unattended() -> Caller {
    Caller::unattended(owner())
}

fn attended() -> Caller {
    Caller {
        context: owner(),
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn h1() -> AccessPair {
    pair("h1", "deploy")
}

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn profile_id() -> ProfileId {
    ProfileId::parse("dev").unwrap()
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

/// The prepare outcome; its integration names the verified `ssh` client (row 19).
fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: shift(t0(), 12 * 3600),
        offline_until: shift(t0(), 3600),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: ConsumerIntegration {
            executables: vec![ConsumerExecutable {
                consumer: ConsumerKind::Ssh,
                path: SSH.into(),
                version: Some("OpenSSH_9.9".into()),
                sha256: None,
                basis: EvidenceBasis::Observed,
            }],
            ..ConsumerIntegration::default()
        },
    }
}

fn descriptor(mechanism: &str) -> AdapterDescriptor {
    AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: mechanism.into(),
            instance: "fixture-1".into(),
        },
        capabilities: ssh_only(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: enforcement(),
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

fn standing_policy(id: &str, lock: LockBehavior, connection: ConnectionPolicy) -> StandingPolicy {
    StandingPolicy {
        id: PolicyId::parse(id).unwrap(),
        revision: PolicyRevision(1),
        profile: profile_id(),
        workspace: None,
        scope: Scope {
            pairs: [h1(), pair("h2", "deploy")].into_iter().collect(),
            capabilities: ssh_only(),
        },
        environments: [env_id()].into_iter().collect(),
        max_window: 2 * HOUR,
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::SetupDefault,
        lock_behavior: lock,
        connection,
    }
}

fn seed(store: &Store) {
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            tx.upsert_profile(&ProfileDefinition {
                id: profile_id(),
                revision: 1,
                scope: Scope {
                    pairs: [h1(), pair("h2", "deploy"), pair("h3", "deploy")]
                        .into_iter()
                        .collect(),
                    capabilities: ssh_only(),
                },
                label: None,
            })?;
            tx.upsert_policy(
                &standing_policy("pol", LockBehavior::Continue, ConnectionPolicy::default()),
                false,
            )?;
            for d in ["h1", "h2", "h3"] {
                tx.upsert_destination(&DestinationRecord {
                    id: DestinationId::parse(d).unwrap(),
                    alias: d.into(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: t0(),
                })?;
            }
            Ok(())
        })
        .unwrap();
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    ops: Operations,
}

impl World {
    /// A world whose one adapter has `mechanism`.
    async fn with(mechanism: &str) -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let script: Vec<FakeStep> = (0..16).map(|_| FakeStep::Prepare(outcome())).collect();
        let fake = FakeCredentialAdapter::new(descriptor(mechanism), script);
        let ops = Operations::start(config_of(&store, &clock, &sync, &fake))
            .await
            .unwrap();
        Self {
            store,
            clock,
            sync,
            fake,
            ops,
        }
    }

    async fn new() -> Self {
        Self::with("fake_agent").await
    }

    /// A world whose grants record `managed_certificate` (the M03 issuance path).
    async fn managed() -> Self {
        Self::with(MANAGED_CERTIFICATE).await
    }

    /// In-process restart: a new `Operations` over the same store and adapter.
    async fn restart(&mut self) {
        self.ops = Operations::start(config_of(&self.store, &self.clock, &self.sync, &self.fake))
            .await
            .unwrap();
    }

    fn tx<R>(
        &self,
        f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<R>,
    ) -> R {
        self.store.transaction(f).unwrap()
    }

    fn generation(&self) -> u64 {
        self.tx(|tx| tx.authority_generation()).0
    }

    fn policy(&self, id: &str) -> StandingPolicy {
        self.tx(|tx| tx.policy(&PolicyId::parse(id).unwrap()))
            .unwrap()
    }

    fn operations_count(&self) -> usize {
        self.tx(|tx| tx.open_operations()).len()
    }

    async fn ensure(&self, req: EnsureRequest) -> OpResult<EnsureData> {
        self.ops.ensure(&unattended(), req).await
    }

    async fn active_grant(&self, rid: &str) -> EnsureData {
        ok(self.ensure(ensure_req(rid, &[("h1", "deploy")])).await).data
    }
}

fn config_of(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    sync: &Arc<ScriptedTimeSync>,
    fake: &Arc<FakeCredentialAdapter>,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    }
}

fn ensure_req(request_id: &str, pairs: &[(&str, &str)]) -> EnsureRequest {
    EnsureRequest {
        profile: profile_id(),
        profile_revision: None,
        scope: pairs.iter().map(|(d, a)| pair(d, a)).collect(),
        environment: None,
        work_id: WorkId::parse(&format!("w-{request_id}")).unwrap(),
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(request_id).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 30_000 },
        connection: None,
    }
}

fn rendered<T: serde::Serialize + Clone>(r: &OpResult<T>) {
    let v = match r {
        Ok(c) => serde_json::to_value(c.clone().into_envelope()).unwrap(),
        Err(e) => serde_json::to_value(e.clone().into_envelope()).unwrap(),
    };
    assert_no_canary(&v.to_string());
}

fn ok<T: serde::Serialize + Clone>(r: OpResult<T>) -> heimdall_app::error::Completed<T> {
    rendered(&r);
    match r {
        Ok(c) => c,
        Err(e) => panic!(
            "expected success, got {}: {} ({:?})",
            e.code, e.message, e.reason
        ),
    }
}

fn err<T: serde::Serialize + Clone + std::fmt::Debug>(r: OpResult<T>) -> OpError {
    rendered(&r);
    match r {
        Ok(c) => panic!("expected an error, got {:?}", c.code),
        Err(e) => e,
    }
}

// --- M03 store fixtures ---------------------------------------------------------------

/// CA fixture `n` (distinct for every `n`).
fn ca(n: u8) -> CaFingerprint {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let hi = char::from(B64[usize::from(n / 64)]);
    let lo = char::from(B64[usize::from(n % 64)]);
    CaFingerprint::parse(&format!("SHA256:{hi}{}", lo.to_string().repeat(42))).unwrap()
}

/// CA `n`, registered `n` seconds after t0 (a larger `n` is newer).
fn issuer(n: u8, state: CaState) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: ca(n),
        public_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture{n}"),
        state: if matches!(state, CaState::Pending | CaState::Active) {
            state
        } else {
            CaState::Active
        },
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: format!("{n:02x}").repeat(32),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: shift(t0(), i64::from(n)),
        retired_at: None,
    }
}

fn enrollment(n: u8, ca_n: u8, p: &AccessPair, state: EnrollmentState) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: p.destination.clone(),
        account: p.account.clone(),
        ca_fingerprint: ca(ca_n),
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
            identity: IdentityId::from_random_bytes([n; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state,
        verified_at: (state == EnrollmentState::Verified).then(t0),
        evidence: None,
        created_at: shift(t0(), i64::from(n)),
        updated_at: shift(t0(), i64::from(n)),
    }
}

impl World {
    /// Register CA `n` in `state` (moving an active CA to `retiring` or further
    /// through the domain transitions).
    fn register_ca(&self, n: u8, state: CaState) {
        self.tx(|tx| {
            tx.insert_issuer(&issuer(n, state))?;
            let steps: &[(CaState, heimdall_domain::issuance::CaEvent)] = match state {
                CaState::Retiring => &[(
                    CaState::Active,
                    heimdall_domain::issuance::CaEvent::RetireApproved,
                )],
                CaState::Retired => &[
                    (
                        CaState::Active,
                        heimdall_domain::issuance::CaEvent::RetireApproved,
                    ),
                    (
                        CaState::Retiring,
                        heimdall_domain::issuance::CaEvent::UnloadConfirmed,
                    ),
                    (
                        CaState::Unloaded,
                        heimdall_domain::issuance::CaEvent::StoreItemDeleted,
                    ),
                    (
                        CaState::Deleted,
                        heimdall_domain::issuance::CaEvent::RetirementRecorded,
                    ),
                ],
                _ => &[],
            };
            for (from, event) in steps {
                tx.set_issuer_state(&ca(n), *from, *event, t0())?.unwrap();
            }
            Ok(())
        });
    }

    fn seed_enrollment(&self, record: &EnrollmentRecord) {
        self.tx(|tx| tx.seed_enrollment(record));
    }

    fn set_preference(
        &self,
        p: &AccessPair,
        mechanism: PreferredMechanism,
        projection: ProjectionStatus,
    ) {
        self.tx(|tx| {
            let issuing_cas = tx.verified_cas_for_pair(p)?;
            tx.set_pair_preference(
                &PairPreference {
                    destination: p.destination.clone(),
                    account: p.account.clone(),
                    mechanism,
                    projection,
                    issuing_cas,
                },
                t0(),
            )
        });
    }

    fn preference(&self, p: &AccessPair) -> Option<PairPreference> {
        self.tx(|tx| tx.pair_preference(p))
    }
}

fn issuance(grant: &GrantId) -> IssuanceRequest {
    IssuanceRequest {
        grant: grant.clone(),
        pair: h1(),
        principal: "hm:h1:deploy".into(),
        key_id: "fixture-key".into(),
        valid_after: t0(),
        valid_before: shift(t0(), 1800),
        extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
        subject_fingerprint: "fixture-fingerprint".into(),
        facts: facts(),
    }
}

fn facts() -> IssuanceFacts {
    IssuanceFacts {
        new_activation: false,
        subject_registered: true,
        critical_option: false,
    }
}

fn assert_ca_refusal(e: &OpError, reason: Option<&str>) {
    assert_eq!(e.code, Code::CapabilityUnavailable, "{}", e.message);
    assert_eq!(e.message, "the certificate's CA cannot issue for this pair");
    assert_eq!(e.reason.as_deref(), reason);
}

// =================================================================================
// Row 2: the issuance check knows the CA
// =================================================================================

#[tokio::test]
async fn issuance_refuses_unknown_ca() {
    let w = World::managed().await;
    let g = w.active_grant("r2-unknown").await.grant_id;
    // No verified enrollment for the pair: nothing to select, nothing named.
    let e = w.ops.reserve_issuance(issuance(&g)).await.unwrap_err();
    assert_ca_refusal(&e, None);
    // A named CA that is not registered.
    let e = w
        .ops
        .reserve_issuance_naming_ca(issuance(&g), ca(9))
        .await
        .unwrap_err();
    assert_ca_refusal(&e, None);
    // A named CA other than the one selected (row 3: "naming another CA").
    w.register_ca(1, CaState::Active);
    w.register_ca(2, CaState::Active);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    w.seed_enrollment(&enrollment(2, 2, &h1(), EnrollmentState::Verified));
    let e = w
        .ops
        .reserve_issuance_naming_ca(issuance(&g), ca(1))
        .await
        .unwrap_err();
    assert_ca_refusal(&e, None);
    assert!(
        w.tx(|tx| tx.issuance_entries(&g)).is_empty(),
        "nothing reserved"
    );
    assert_eq!(w.tx(|tx| tx.grant(&g)).unwrap().state, GrantState::Active);
}

#[tokio::test]
async fn issuance_refuses_ca_not_verified_for_pair() {
    let w = World::managed().await;
    let g = w.active_grant("r2-notver").await.grant_id;
    w.register_ca(1, CaState::Active);
    // Verified for another pair only, and applying (not verified) for this one.
    w.seed_enrollment(&enrollment(
        1,
        1,
        &pair("h2", "deploy"),
        EnrollmentState::Verified,
    ));
    w.seed_enrollment(&enrollment(2, 1, &h1(), EnrollmentState::AppliedUnverified));
    let e = w
        .ops
        .reserve_issuance_naming_ca(issuance(&g), ca(1))
        .await
        .unwrap_err();
    assert_ca_refusal(&e, Some("pair_not_enrolled"));
    assert!(w.tx(|tx| tx.issuance_entries(&g)).is_empty());
}

#[tokio::test]
async fn issuance_refuses_ca_retiring() {
    let w = World::managed().await;
    let g = w.active_grant("r2-retiring").await.grant_id;
    w.register_ca(1, CaState::Retiring);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    // Not selectable (not active), so the named CA reaches the predicate.
    let e = w
        .ops
        .reserve_issuance_naming_ca(issuance(&g), ca(1))
        .await
        .unwrap_err();
    assert_ca_refusal(&e, Some("ca_retiring"));
    // And without naming one: nothing is selectable.
    let e = w.ops.reserve_issuance(issuance(&g)).await.unwrap_err();
    assert_ca_refusal(&e, None);
    assert!(w.tx(|tx| tx.issuance_entries(&g)).is_empty());
}

/// Row 2: the operations-level wrapper over `issuance::extension_profile` (ADR-0005
/// §3.4 as amended by ADR-0008 D6 item 1): `permit-pty` for every pair of the grant,
/// `permit-agent-forwarding` only with the capability, never port forwarding, user rc
/// or X11; nothing for a pair outside the grant. Identical to the domain profile.
#[tokio::test]
async fn extension_profile_matches_adr_0005_3_4_table() {
    let w = World::new().await;
    let g: GrantSnapshot = {
        let id = w.active_grant("r2-ext").await.grant_id;
        w.tx(|tx| tx.grant(&id)).unwrap()
    };
    let mut forwarding = g.clone();
    forwarding
        .scope
        .capabilities
        .insert(Capability::AgentForwarding);
    let never = [
        "permit-port-forwarding",
        "permit-user-rc",
        "permit-X11-forwarding",
    ];
    let table: [(&GrantSnapshot, AccessPair, &[&str]); 4] = [
        (&g, h1(), &["permit-pty"]),
        (
            &forwarding,
            h1(),
            &["permit-agent-forwarding", "permit-pty"],
        ),
        (&g, pair("h9", "deploy"), &[]),
        (&forwarding, pair("h9", "deploy"), &[]),
    ];
    for (grant, p, expected) in table {
        let got = permitted_extensions(grant, &p);
        let want: BTreeSet<String> = expected.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(got, want, "{p:?}");
        assert_eq!(
            got,
            heimdall_domain::issuance::extension_profile(grant, &p),
            "the wrapper is the domain profile"
        );
        for n in never {
            assert!(!got.contains(n));
        }
    }
    // M01 issuance through the wrapper is unchanged: a fake_agent grant reserves with
    // `permit-pty` and no CA.
    let entry = w.ops.reserve_issuance(issuance(&g.id)).await.unwrap();
    assert_eq!(entry.bounds.ca_fingerprint, None);
    assert_eq!(
        serde_json::to_value(&entry.bounds)
            .unwrap()
            .get("ca_fingerprint"),
        None,
        "an M01 entry encodes without a CA"
    );
}

// =================================================================================
// Row 3: the reserve transaction selects the CA; publish re-checks it
// =================================================================================

#[tokio::test]
async fn reserve_selects_newest_verified_ca_for_pair() {
    let w = World::managed().await;
    let g = w.active_grant("r3-select").await.grant_id;
    w.register_ca(1, CaState::Active); // oldest
    w.register_ca(2, CaState::Active); // newest active, verified
    w.register_ca(3, CaState::Pending); // newer, but pending
    w.register_ca(4, CaState::Active); // newest active, not verified for h1
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    w.seed_enrollment(&enrollment(2, 2, &h1(), EnrollmentState::Verified));
    w.seed_enrollment(&enrollment(3, 3, &h1(), EnrollmentState::Verified));
    w.seed_enrollment(&enrollment(4, 4, &h1(), EnrollmentState::Verifying));
    let entry = w.ops.reserve_issuance(issuance(&g)).await.unwrap();
    assert_eq!(entry.bounds.ca_fingerprint, Some(ca(2)));
    assert_eq!(entry.state, IssuanceState::Reserved);
    // Naming the selected CA is accepted; the published entry keeps it.
    let named = w
        .ops
        .reserve_issuance_naming_ca(issuance(&g), ca(2))
        .await
        .unwrap();
    assert_eq!(named.bounds.ca_fingerprint, Some(ca(2)));
    match w.ops.publish_issuance(&named.id, &facts()).await.unwrap() {
        Publication::Published(e) => assert_eq!(e.bounds.ca_fingerprint, Some(ca(2))),
        other => panic!("expected publication, got {other:?}"),
    }
}

#[tokio::test]
async fn publish_voids_when_enrollment_removed_between_reserve_and_publish() {
    let w = World::managed().await;
    let g = w.active_grant("r3-removed").await.grant_id;
    w.register_ca(1, CaState::Active);
    let e1 = enrollment(1, 1, &h1(), EnrollmentState::Verified);
    w.seed_enrollment(&e1);
    let entry = w.ops.reserve_issuance(issuance(&g)).await.unwrap();
    assert_eq!(entry.bounds.ca_fingerprint, Some(ca(1)));
    // The enrollment leaves `verified` (its removal is approved) in between.
    w.tx(|tx| {
        tx.transition_enrollment(
            EnrollmentState::Verified,
            EnrollmentEventKind::RemoveEnrollmentApproved,
            &e1,
        )
        .map(|r| {
            r.unwrap();
        })
    });
    let e = w
        .ops
        .publish_issuance(&entry.id, &facts())
        .await
        .unwrap_err();
    assert_ca_refusal(&e, Some("pair_not_enrolled"));
    let stored = w.tx(|tx| tx.issuance_entries(&g));
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].state, IssuanceState::Voided);
    assert_eq!(
        stored[0].void_reason,
        Some(heimdall_domain::issuance::IssuanceRefusal::CaNotVerifiedForPair)
    );
}

#[tokio::test]
async fn publish_voids_when_ca_retired_between() {
    let w = World::managed().await;
    let g = w.active_grant("r3-retired").await.grant_id;
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    let entry = w.ops.reserve_issuance(issuance(&g)).await.unwrap();
    w.tx(|tx| {
        tx.set_issuer_state(
            &ca(1),
            CaState::Active,
            heimdall_domain::issuance::CaEvent::RetireApproved,
            t0(),
        )
        .map(|r| {
            r.unwrap();
        })
    });
    let e = w
        .ops
        .publish_issuance(&entry.id, &facts())
        .await
        .unwrap_err();
    assert_ca_refusal(&e, Some("ca_retiring"));
    let stored = w.tx(|tx| tx.issuance_entries(&g));
    assert_eq!(stored[0].state, IssuanceState::Voided);
    assert_eq!(
        stored[0].void_reason,
        Some(heimdall_domain::issuance::IssuanceRefusal::CaRetiring)
    );
    assert_eq!(w.tx(|tx| tx.grant(&g)).unwrap().state, GrantState::Active);
}

// =================================================================================
// Row 4: verification issuance
// =================================================================================

/// Seed an `enrollment.verify` operation in `mode` for enrollment `n` (CA `n`, h1;
/// seeded `verifying` unless it exists), `running`, with `attempts` started attempts;
/// returns the operation.
fn seed_verify_operation(w: &World, n: u8, mode: VerifyMode, attempts: usize) -> OperationId {
    let e = enrollment(n, n, &h1(), EnrollmentState::Verifying);
    let op_id = OperationId::from_random_bytes([n; 16]);
    let key = IdempotencyKey {
        caller: owner(),
        kind: OperationKind::EnrollmentVerify,
        request_id: RequestId::parse(&format!("verify-{n}")).unwrap(),
    };
    let op = OperationRecord {
        id: op_id.clone(),
        kind: OperationKind::EnrollmentVerify,
        environment: env_id(),
        key: key.clone(),
        request_hash: RequestHash([n; 32]),
        effect_class: EffectClass::Local,
        state: OperationState::Running,
        code: None,
        effect_status: EffectStatus::None,
        result: None,
        created_at: w.clock_wall(),
        updated_at: w.clock_wall(),
        cancellation: None,
        recovery: RecoveryMetadata::default(),
    };
    let request = Request::Enrollment(EnrollmentRequest::Verify {
        enrollment_id: e.id.clone(),
        request_id: key.request_id.clone(),
        mode,
        wait: WaitMode::Async,
    });
    let now = w.clock_wall();
    w.tx(|tx| {
        if tx.issuer(&ca(n))?.is_none() {
            tx.insert_issuer(&issuer(n, CaState::Active))?;
        }
        if tx.enrollment(&e.id)?.is_none() {
            tx.seed_enrollment(&e)?;
        }
        tx.insert_operation(
            &op,
            &IdempotencyRecord {
                key: key.clone(),
                request_hash: op.request_hash,
                operation_id: op_id.clone(),
                created_at: now,
                expires_at: None,
            },
        )?;
        tx.set_recovery_intent(
            &op_id,
            &RecoveryIntent {
                request: serde_json::to_value(&request).unwrap(),
                resolved: None,
                local: None,
            },
        )?;
        for _ in 0..attempts {
            tx.append_stage_receipt(
                &op_id,
                &StageReceipt {
                    stage: enrollment_stage::VERIFY_STARTED.into(),
                    recorded_at: now,
                    effect: EffectReceipt::NotAttempted,
                    local: None,
                },
            )?;
        }
        Ok(())
    });
    op_id
}

impl World {
    fn clock_wall(&self) -> Timestamp {
        heimdall_domain::time::Clock::wall(self.clock.as_ref())
    }
}

fn verification(w: &World, op: &OperationId, n: u8) -> VerificationRequest {
    let now = w.clock_wall();
    VerificationRequest {
        operation: op.clone(),
        enrollment: EnrollmentId::from_random_bytes([n; 16]),
        pair: h1(),
        ca_fingerprint: ca(n),
        purpose: VerificationPurpose::Positive,
        principal: "hm:h1:deploy".into(),
        key_id: "verify-key".into(),
        valid_after: shift(now, -60),
        valid_before: shift(now, 300),
        extensions: BTreeSet::new(),
        subject_fingerprint: "SHA256:kverify".into(),
        subject_registered: true,
    }
}

/// Reserve `req` and expect the predicate to refuse with `refusal`, writing nothing.
async fn refused(w: &World, req: VerificationRequest, refusal: VerificationRefusal) {
    let op = req.operation.clone();
    let r = w.ops.reserve_verification(req).await.unwrap();
    assert_eq!(r, Err(refusal));
    assert!(
        w.tx(|tx| tx.verification_entries(&op)).is_empty(),
        "nothing reserved"
    );
}

#[tokio::test]
async fn verification_reserve_refuses_operation_not_verifying() {
    let w = World::new().await;
    // A target change needs `ApproveTargetChange`, which wave 0 never completes.
    let op = seed_verify_operation(&w, 41, VerifyMode::TargetChange, 1);
    refused(
        &w,
        verification(&w, &op, 41),
        VerificationRefusal::OperationNotVerifying,
    )
    .await;
    // An attempt that has not started.
    let op = seed_verify_operation(&w, 42, VerifyMode::Presence, 0);
    refused(
        &w,
        verification(&w, &op, 42),
        VerificationRefusal::OperationNotVerifying,
    )
    .await;
    // An unknown operation; another enrollment than the operation's.
    let unknown = OperationId::from_random_bytes([99; 16]);
    refused(
        &w,
        verification(&w, &unknown, 42),
        VerificationRefusal::OperationNotVerifying,
    )
    .await;
    let op = seed_verify_operation(&w, 43, VerifyMode::Presence, 1);
    let mut req = verification(&w, &op, 43);
    req.enrollment = EnrollmentId::from_random_bytes([42; 16]);
    refused(&w, req, VerificationRefusal::OperationNotVerifying).await;
}

#[tokio::test]
async fn verification_reserve_refuses_pair_mismatch() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 44, VerifyMode::Presence, 1);
    let mut req = verification(&w, &op, 44);
    req.pair = pair("h2", "deploy");
    req.principal = "hm:h2:deploy".into();
    refused(&w, req, VerificationRefusal::PairMismatch).await;
}

#[tokio::test]
async fn verification_reserve_refuses_ca_mismatch() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 45, VerifyMode::Presence, 1);
    let mut req = verification(&w, &op, 45);
    req.ca_fingerprint = ca(200);
    refused(&w, req, VerificationRefusal::CaMismatch).await;
}

#[tokio::test]
async fn verification_reserve_refuses_wrong_principal() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 46, VerifyMode::Presence, 1);
    let mut req = verification(&w, &op, 46);
    req.principal = "hm:h2:deploy".into();
    refused(&w, req.clone(), VerificationRefusal::WrongPrincipal).await;
    req.purpose = VerificationPurpose::Negative;
    req.principal = "hm:verify-negative:XYZ".into();
    refused(&w, req.clone(), VerificationRefusal::WrongPrincipal).await;
    req.principal = format!("hm:verify-negative:{}", "0a".repeat(16));
    let entry = w.ops.reserve_verification(req).await.unwrap().unwrap();
    assert_eq!(entry.purpose, VerificationPurpose::Negative);
}

#[tokio::test]
async fn verification_reserve_refuses_extensions_present() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 47, VerifyMode::Presence, 1);
    let mut req = verification(&w, &op, 47);
    req.extensions.insert(EXTENSION_PTY.to_owned());
    refused(&w, req, VerificationRefusal::ExtensionsPresent).await;
}

#[tokio::test]
async fn verification_reserve_refuses_validity_too_long() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 48, VerifyMode::Presence, 1);
    let mut req = verification(&w, &op, 48);
    req.valid_before = shift(w.clock_wall(), 301);
    refused(&w, req, VerificationRefusal::ValidityTooLong).await;
}

#[tokio::test]
async fn verification_reserve_refuses_unknown_subject_key() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 49, VerifyMode::Presence, 1);
    let mut req = verification(&w, &op, 49);
    req.subject_registered = false;
    refused(&w, req, VerificationRefusal::UnknownSubjectKey).await;
}

#[tokio::test]
async fn verification_reserve_refuses_time_uncertain() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 50, VerifyMode::Presence, 1);
    // A gate check records the high-water mark; then the wall clock rolls back below
    // it by more than the tolerance, within this boot: time is uncertain.
    w.ops.timegate().check().await.unwrap();
    w.clock.set_wall(shift(t0(), -3600));
    let req = verification(&w, &op, 50);
    refused(&w, req, VerificationRefusal::TimeUncertain).await;
}

#[tokio::test]
async fn verification_reserve_refuses_too_many_entries() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 51, VerifyMode::Presence, 1);
    for _ in 0..4 {
        w.ops
            .reserve_verification(verification(&w, &op, 51))
            .await
            .unwrap()
            .unwrap();
    }
    let r = w
        .ops
        .reserve_verification(verification(&w, &op, 51))
        .await
        .unwrap();
    assert_eq!(r, Err(VerificationRefusal::TooManyEntries), "a fifth entry");
    assert_eq!(w.tx(|tx| tx.verification_entries(&op)).len(), 4);
    // A fourth attempt is refused too.
    let op = seed_verify_operation(&w, 52, VerifyMode::Presence, 4);
    refused(
        &w,
        verification(&w, &op, 52),
        VerificationRefusal::TooManyEntries,
    )
    .await;
}

#[tokio::test]
async fn verification_entries_counted_in_pair_residual() {
    let w = World::managed().await;
    // A grant entry under CA 53 for h1 (its enrollment verified).
    w.register_ca(53, CaState::Active);
    let e = enrollment(53, 53, &h1(), EnrollmentState::Verified);
    w.seed_enrollment(&e);
    assert_eq!(
        w.ops.pair_residual(&h1(), Some(&ca(53))).await.unwrap(),
        None
    );
    let g = w.active_grant("r4-residual").await.grant_id;
    let grant_entry = w.ops.reserve_issuance(issuance(&g)).await.unwrap();
    assert_eq!(grant_entry.bounds.ca_fingerprint, Some(ca(53)));
    assert_eq!(
        w.ops.pair_residual(&h1(), Some(&ca(53))).await.unwrap(),
        Some(grant_entry.bounds.valid_before)
    );
    // The enrollment re-verifies; its verification entries, past the grant entry's
    // bound, raise the pair's residual under that CA.
    w.tx(|tx| {
        tx.transition_enrollment(
            EnrollmentState::Verified,
            EnrollmentEventKind::StartReverification,
            &e,
        )
        .map(|r| {
            r.unwrap();
        })
    });
    let op = seed_verify_operation(&w, 53, VerifyMode::Presence, 1);
    w.clock.advance(Duration::from_secs(2000));
    let entry = w
        .ops
        .reserve_verification(verification(&w, &op, 53))
        .await
        .unwrap()
        .unwrap();
    assert!(entry.bounds.valid_before > grant_entry.bounds.valid_before);
    assert_eq!(
        w.ops.pair_residual(&h1(), Some(&ca(53))).await.unwrap(),
        Some(entry.bounds.valid_before),
        "a reserved verification entry counts"
    );
    let published = w
        .ops
        .publish_verification(&entry.id, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(published.state, IssuanceState::Published);
    assert_eq!(
        w.ops.pair_residual(&h1(), Some(&ca(53))).await.unwrap(),
        Some(entry.bounds.valid_before),
        "a published one too"
    );
    // A voided entry never counts; another CA's residual is unaffected.
    w.clock.advance(Duration::from_secs(1000));
    let voided = w
        .ops
        .reserve_verification(verification(&w, &op, 53))
        .await
        .unwrap()
        .unwrap();
    let settled = w
        .ops
        .void_verification(&voided.id, VerificationRefusal::UnknownSubjectKey)
        .await
        .unwrap();
    assert_eq!(settled.state, IssuanceState::Voided);
    assert_eq!(
        w.ops.pair_residual(&h1(), Some(&ca(53))).await.unwrap(),
        Some(entry.bounds.valid_before)
    );
    assert_eq!(
        w.ops.pair_residual(&h1(), Some(&ca(54))).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn reserved_verification_never_published_after_restart() {
    let mut w = World::new().await;
    let op = seed_verify_operation(&w, 56, VerifyMode::Presence, 1);
    let entry = w
        .ops
        .reserve_verification(verification(&w, &op, 56))
        .await
        .unwrap()
        .unwrap();
    w.restart().await;
    let e = w
        .ops
        .publish_verification(&entry.id, true)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CredentialExpired);
    let stored = w.tx(|tx| tx.verification_entries(&op));
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].state, IssuanceState::Reserved, "still reserved");
    assert_eq!(
        w.ops.pair_residual(&h1(), Some(&ca(56))).await.unwrap(),
        Some(entry.bounds.valid_before),
        "and still counted"
    );
    // The restart left the enrollment operation unresolved and untouched.
    assert_eq!(
        w.tx(|tx| tx.operation(&op)).unwrap().state,
        OperationState::Running
    );
}

// =================================================================================
// Row 9: per-pair mechanism resolution, `connection`, `unattended`
// =================================================================================

fn pending() -> ProjectionStatus {
    ProjectionStatus::Pending
}

fn applied() -> ProjectionStatus {
    ProjectionStatus::Applied { generation: 1 }
}

fn warning_codes<T>(c: &heimdall_app::error::Completed<T>) -> Vec<String> {
    c.warnings.iter().map(|w| w.code.clone()).collect()
}

#[tokio::test]
async fn mechanism_per_pair_resolution_table() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));

    // No stored preference: the identity's mechanism (M02).
    let none = ok(w.ensure(ensure_req("r9-none", &[("h1", "deploy")])).await);
    assert_eq!(none.data.credential_mechanism, "fake_agent");
    assert!(none.warnings.is_empty());

    // Preference `existing`: the identity's mechanism.
    w.set_preference(&h1(), PreferredMechanism::Existing, applied());
    let existing = ok(w
        .ensure(ensure_req("r9-existing", &[("h1", "deploy")]))
        .await);
    assert_eq!(existing.data.credential_mechanism, "fake_agent");
    assert!(existing.warnings.is_empty());

    // Managed, verified, projection applied: managed_certificate, whose driver is
    // not in this build: refused before any record is written.
    w.set_preference(&h1(), PreferredMechanism::ManagedCertificate, applied());
    let before = w.operations_count();
    let effects = w.fake.effect_count();
    let managed = err(w
        .ensure(ensure_req("r9-managed", &[("h1", "deploy")]))
        .await);
    assert_eq!(managed.code, Code::CapabilityUnavailable);
    assert_eq!(managed.reason.as_deref(), Some("driver_unavailable"));
    assert_eq!(managed.effect_status, EffectStatus::None);
    assert_eq!(w.operations_count(), before, "no operation record");
    assert!(
        w.tx(|tx| tx.idempotency_record(&IdempotencyKey {
            caller: owner(),
            kind: OperationKind::Ensure,
            request_id: RequestId::parse("r9-managed").unwrap(),
        }))
        .is_none(),
        "no idempotency record"
    );
    assert_eq!(w.fake.effect_count(), effects, "no effect");

    // Managed with the projection pending: the existing mechanism, with the warning.
    w.set_preference(&h1(), PreferredMechanism::ManagedCertificate, pending());
    let p = ok(w
        .ensure(ensure_req("r9-pending", &[("h1", "deploy")]))
        .await);
    assert_eq!(p.data.credential_mechanism, "fake_agent");
    assert_eq!(warning_codes(&p), ["managed_projection_pending"]);

    // A managed pair with any other pair: mixed mechanisms (unchanged).
    w.set_preference(&h1(), PreferredMechanism::ManagedCertificate, applied());
    let mixed = err(w
        .ensure(ensure_req(
            "r9-mixed",
            &[("h1", "deploy"), ("h2", "deploy")],
        ))
        .await);
    assert_eq!(mixed.code, Code::CapabilityUnavailable);
    assert_eq!(mixed.reason.as_deref(), Some("mixed_mechanisms"));

    // Managed preference without a verified enrollment: pair_not_enrolled.
    w.set_preference(
        &pair("h2", "deploy"),
        PreferredMechanism::ManagedCertificate,
        applied(),
    );
    let unenrolled = err(w
        .ensure(ensure_req("r9-unenrolled", &[("h2", "deploy")]))
        .await);
    assert_eq!(unenrolled.code, Code::CapabilityUnavailable);
    assert_eq!(unenrolled.reason.as_deref(), Some("pair_not_enrolled"));
}

#[tokio::test]
async fn pending_projection_ensure_resolves_existing_with_warning() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    w.set_preference(&h1(), PreferredMechanism::ManagedCertificate, pending());
    let done = ok(w.ensure(ensure_req("r9-pend", &[("h1", "deploy")])).await);
    assert_eq!(done.data.credential_mechanism, "fake_agent");
    assert_eq!(warning_codes(&done), ["managed_projection_pending"]);
    let next = done.next.clone().expect("next");
    assert_eq!(next.action, "setup_apply");
    assert_eq!(next.binding_id.as_ref(), Some(&done.data.binding_id));
    // The grant records the existing mechanism; no managed access is claimed.
    let origin = w.tx(|tx| tx.grant_origin(&done.data.grant_id)).unwrap();
    assert_eq!(origin.mechanism, "fake_agent");
    // A replay answers the same way.
    let replay = ok(w.ensure(ensure_req("r9-pend", &[("h1", "deploy")])).await);
    assert_eq!(replay.data.grant_id, done.data.grant_id);
    assert_eq!(warning_codes(&replay), ["managed_projection_pending"]);
}

#[tokio::test]
async fn pending_projection_refused_only_for_managed_only_minimums() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    w.set_preference(&h1(), PreferredMechanism::ManagedCertificate, pending());
    // Minimums only managed certificates can meet.
    let mut scope = ensure_req("r9-scope", &[("h1", "deploy")]);
    scope.required_capabilities.destination_scope_at_least =
        Some(DestinationScopeEnforcement::VerifiedServerPrincipals);
    let mut unattended_req = ensure_req("r9-unatt", &[("h1", "deploy")]);
    unattended_req.required_capabilities.unattended = true;
    for req in [scope, unattended_req] {
        let e = err(w.ensure(req).await);
        assert_eq!(e.code, Code::CapabilityUnavailable);
        assert_eq!(e.reason.as_deref(), Some("projection_pending"));
        assert_eq!(e.next.action, "setup_apply");
        assert_eq!(e.effect_status, EffectStatus::None);
    }
    // An ordinary request resolves to the existing mechanism.
    let fine = ok(w.ensure(ensure_req("r9-fine", &[("h1", "deploy")])).await);
    assert_eq!(fine.data.credential_mechanism, "fake_agent");
    // Without a pending projection the same minimum is M01's refusal (no M03 reason).
    let mut plain = ensure_req("r9-plain", &[("h2", "deploy")]);
    plain.required_capabilities.destination_scope_at_least =
        Some(DestinationScopeEnforcement::VerifiedServerPrincipals);
    let e = err(w.ensure(plain).await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason, None);
}

fn m02_hash(req: &EnsureRequest) -> RequestHash {
    compute_hash(
        OperationKind::Ensure,
        &HashInput {
            environment: &env_id(),
            profile: Some(&req.profile),
            profile_revision: req.profile_revision,
            scope: &req.scope,
            deadline_intent: req.until.as_ref(),
            work_id: Some(&req.work_id),
            required_capabilities: &req.required_capabilities,
            parent_binding: None,
            extra: serde_json::Value::Null,
        },
    )
    .unwrap()
}

fn stored_hash(w: &World, op: &OperationId) -> RequestHash {
    w.tx(|tx| tx.operation(op)).unwrap().request_hash
}

#[tokio::test]
async fn connection_absent_hash_unchanged_from_m02() {
    let w = World::new().await;
    let req = ensure_req("r9-hash", &[("h1", "deploy")]);
    let done = ok(w.ensure(req.clone()).await);
    let op = done.operation_id.clone().expect("operation");
    assert_eq!(
        stored_hash(&w, &op),
        m02_hash(&req),
        "the M02 hash, byte for byte"
    );
    // The request's wire form omits the field.
    assert!(
        serde_json::to_value(&req)
            .unwrap()
            .get("connection")
            .is_none()
    );
}

#[tokio::test]
async fn strict_request_hash_differs() {
    let w = World::new().await;
    let plain = ensure_req("r9-strict", &[("h1", "deploy")]);
    let mut strict = plain.clone();
    strict.connection = Some(ConnectionRequest {
        existing: Some(ExistingConnectionsMode::Strict),
    });
    let done = ok(w.ensure(strict.clone()).await);
    let op = done.operation_id.clone().expect("operation");
    assert_ne!(stored_hash(&w, &op), m02_hash(&plain));
    // The same request ID without `connection` is another request.
    let conflict = err(w.ensure(plain).await);
    assert_eq!(conflict.code, Code::RequestConflict);
    // `graceful` in a request is a usage error, before any record.
    let before = w.operations_count();
    let mut graceful = ensure_req("r9-graceful", &[("h1", "deploy")]);
    graceful.connection = Some(ConnectionRequest {
        existing: Some(ExistingConnectionsMode::Graceful),
    });
    let e = err(w.ensure(graceful).await);
    assert_eq!(e.code, Code::UsageError);
    assert_eq!(w.operations_count(), before);
}

#[tokio::test]
async fn unattended_requires_claim_and_continue() {
    use LockBehavior::{Continue, RevokeOnLock};
    // ADR-0008 D6 item 7, in order: managed + claim, then lock behaviour, then
    // interaction.
    let table = [
        (
            false,
            true,
            Continue,
            false,
            Some("lock_continuity_unverified"),
        ),
        (
            true,
            false,
            Continue,
            false,
            Some("lock_continuity_unverified"),
        ),
        (true, true, RevokeOnLock, false, Some("lock_revokes_chosen")),
        (true, true, Continue, true, Some("interaction_required")),
        (
            false,
            false,
            RevokeOnLock,
            true,
            Some("lock_continuity_unverified"),
        ),
        (true, true, Continue, false, None),
    ];
    for (managed, claim, lock, interaction, want) in table {
        assert_eq!(
            unattended_refusal(managed, claim, lock, interaction),
            want,
            "{managed} {claim} {lock:?} {interaction}"
        );
    }
    // Through ensure: the claim table is empty and no managed mechanism exists, so
    // `unattended` is refused with its reason, before any effect.
    let w = World::new().await;
    let mut req = ensure_req("r9-unattended", &[("h1", "deploy")]);
    req.required_capabilities.unattended = true;
    let e = err(w.ensure(req).await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("lock_continuity_unverified"));
    assert_eq!(w.fake.effect_count(), 0);
}

// =================================================================================
// Row 10: GrantOrigin.{lock_behavior, connection}
// =================================================================================

#[tokio::test]
async fn origin_lock_and_connection_add_only() {
    let w = World::new().await;
    // Default policy, no `connection`: nothing recorded (an M02 origin, unchanged).
    let plain = w.active_grant("r10-plain").await;
    let o = w.tx(|tx| tx.grant_origin(&plain.grant_id)).unwrap();
    assert_eq!((o.lock_behavior, o.connection), (None, None));
    assert!(
        serde_json::to_value(&o)
            .unwrap()
            .get("lock_behavior")
            .is_none()
    );

    // A revoke-on-lock policy and a strict request: both recorded at creation.
    w.tx(|tx| {
        let mut p = standing_policy(
            "pol",
            LockBehavior::RevokeOnLock,
            ConnectionPolicy::default(),
        );
        p.revision = PolicyRevision(2);
        tx.upsert_policy(&p, true)
    });
    let mut req = ensure_req("r10-strict", &[("h1", "deploy")]);
    req.connection = Some(ConnectionRequest {
        existing: Some(ExistingConnectionsMode::Strict),
    });
    let g = ok(w.ensure(req).await).data.grant_id;
    let o = w.tx(|tx| tx.grant_origin(&g)).unwrap();
    assert_eq!(o.lock_behavior, Some(LockBehavior::RevokeOnLock));
    assert_eq!(
        o.connection,
        Some(ConnectionPolicy {
            existing: ExistingConnectionsMode::Strict,
            multiplexing: MultiplexingMode::Disabled,
        })
    );

    // Never changed afterwards: neither replaced, cleared, nor added to an origin that
    // recorded none.
    for changed in [
        heimdall_domain::grant::GrantOrigin {
            lock_behavior: Some(LockBehavior::Continue),
            ..o.clone()
        },
        heimdall_domain::grant::GrantOrigin {
            lock_behavior: None,
            ..o.clone()
        },
        heimdall_domain::grant::GrantOrigin {
            connection: None,
            ..o.clone()
        },
    ] {
        let r = w.store.transaction(|tx| tx.set_grant_origin(&g, &changed));
        assert!(matches!(r, Err(StoreError::GenerationConflict(_))), "{r:?}");
    }
    let plain_origin = w.tx(|tx| tx.grant_origin(&plain.grant_id)).unwrap();
    let added = heimdall_domain::grant::GrantOrigin {
        lock_behavior: Some(LockBehavior::RevokeOnLock),
        ..plain_origin.clone()
    };
    let r = w
        .store
        .transaction(|tx| tx.set_grant_origin(&plain.grant_id, &added));
    assert!(matches!(r, Err(StoreError::GenerationConflict(_))), "{r:?}");
    assert_eq!(w.tx(|tx| tx.grant_origin(&g)).unwrap(), o, "unchanged");
}

// =================================================================================
// Row 11: lock behaviour and connection policy
// =================================================================================

/// A session-lock source reporting a fixed state (the runtime's is U9's).
struct FixedLock(LockState, tokio::sync::Notify);

impl SessionLockSource for FixedLock {
    fn state(&self) -> LockState {
        self.0
    }
    fn lock_epoch(&self) -> heimdall_domain::managed::LockEpoch {
        heimdall_domain::managed::LockEpoch::default()
    }
    fn acknowledge(&self, _epoch: u64) {}
    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.1.notified()
    }
}

fn set_lock(policy: &str, behavior: LockBehavior) -> PolicyAction {
    PolicyAction::SetLockBehavior {
        policy_id: PolicyId::parse(policy).unwrap(),
        behavior,
    }
}

fn set_connection(
    existing: Option<ExistingConnectionsMode>,
    multiplexing: Option<MultiplexingMode>,
) -> PolicyAction {
    PolicyAction::SetConnectionPolicy {
        policy_id: policy_id(),
        existing,
        multiplexing,
    }
}

/// Apply `action`: `Ok(true)` when it took effect now, `Ok(false)` when it was
/// unchanged, `Err(decision)` when it created a widening decision record.
async fn apply_policy(
    w: &World,
    action: PolicyAction,
) -> Result<bool, heimdall_contract::ids::DecisionId> {
    match w.ops.policy(&attended(), action).await {
        Ok(done) => Ok(done.data["changed"].as_bool().unwrap()),
        Err(e) => {
            assert_eq!(e.code, Code::ApprovalRequired, "{}", e.message);
            Err(
                heimdall_contract::ids::DecisionId::parse(e.next.decision_ref.as_deref().unwrap())
                    .unwrap(),
            )
        }
    }
}

async fn approve(w: &World, decision: heimdall_contract::ids::DecisionId) {
    ok(w.ops
        .decide(
            &attended(),
            DecideRequest {
                decision_id: decision,
                verdict: Verdict::Approve,
            },
        )
        .await);
}

#[tokio::test]
async fn lock_behavior_narrowing_immediate_widening_needs_decision() {
    let w = World::new().await;
    // No lock source: `revoke_on_lock` is refused, nothing written.
    let g0 = w.generation();
    let e = err(w
        .ops
        .policy(&attended(), set_lock("pol", LockBehavior::RevokeOnLock))
        .await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));
    assert_eq!(w.policy("pol").lock_behavior, LockBehavior::Continue);
    assert_eq!(w.generation(), g0);
    // A source that reports `unavailable` is refused the same way.
    w.ops.set_session_lock_source(Arc::new(FixedLock(
        LockState::Unavailable,
        tokio::sync::Notify::new(),
    )));
    let e = err(w
        .ops
        .policy(&attended(), set_lock("pol", LockBehavior::RevokeOnLock))
        .await);
    assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));

    // With a working source, narrowing takes effect at once and moves the generation.
    w.ops.set_session_lock_source(Arc::new(FixedLock(
        LockState::Unlocked,
        tokio::sync::Notify::new(),
    )));
    let rev = w.policy("pol").revision;
    assert_eq!(
        apply_policy(&w, set_lock("pol", LockBehavior::RevokeOnLock)).await,
        Ok(true)
    );
    assert_eq!(w.policy("pol").lock_behavior, LockBehavior::RevokeOnLock);
    assert!(w.policy("pol").revision > rev);
    assert!(w.generation() > g0, "narrowing moves the generation");
    // Again: unchanged.
    assert_eq!(
        apply_policy(&w, set_lock("pol", LockBehavior::RevokeOnLock)).await,
        Ok(false)
    );

    // Widening back to `continue` needs an attended decision; nothing applies first.
    let d = apply_policy(&w, set_lock("pol", LockBehavior::Continue))
        .await
        .unwrap_err();
    assert_eq!(w.policy("pol").lock_behavior, LockBehavior::RevokeOnLock);
    // An unattended caller gets INTERACTION_REQUIRED with the same record.
    let e = err(w
        .ops
        .policy(&unattended(), set_lock("pol", LockBehavior::Continue))
        .await);
    assert_eq!(e.code, Code::InteractionRequired);
    assert_eq!(e.next.decision_ref.as_deref(), Some(d.as_str()));
    approve(&w, d).await;
    assert_eq!(w.policy("pol").lock_behavior, LockBehavior::Continue);
}

#[tokio::test]
async fn connection_policy_widening_classification() {
    use ExistingConnectionsMode::{Graceful, Strict};
    use MultiplexingMode::{Disabled, OwnedMasters};
    let w = World::new().await;
    // From the default (graceful, disabled).
    assert_eq!(
        apply_policy(&w, set_connection(Some(Graceful), None)).await,
        Ok(false)
    );
    assert_eq!(
        apply_policy(&w, set_connection(None, Some(Disabled))).await,
        Ok(false)
    );
    let g = w.generation();
    assert_eq!(
        apply_policy(&w, set_connection(Some(Strict), None)).await,
        Ok(true)
    );
    assert_eq!(w.policy("pol").connection.existing, Strict);
    assert!(
        w.generation() > g,
        "strict is narrowing: immediate, generation moved"
    );
    // owned_masters widens: a decision; nothing applies before it.
    let d = apply_policy(&w, set_connection(None, Some(OwnedMasters)))
        .await
        .unwrap_err();
    assert_eq!(w.policy("pol").connection.multiplexing, Disabled);
    approve(&w, d).await;
    assert_eq!(w.policy("pol").connection.multiplexing, OwnedMasters);
    // graceful (from strict) widens.
    let d = apply_policy(&w, set_connection(Some(Graceful), None))
        .await
        .unwrap_err();
    assert_eq!(w.policy("pol").connection.existing, Strict);
    approve(&w, d).await;
    assert_eq!(w.policy("pol").connection.existing, Graceful);
    // disabled (from owned_masters) narrows.
    assert_eq!(
        apply_policy(&w, set_connection(None, Some(Disabled))).await,
        Ok(true)
    );
    assert_eq!(w.policy("pol").connection.multiplexing, Disabled);
    // A mixed action (narrow one field, widen the other) is widening as a whole.
    assert_eq!(
        apply_policy(&w, set_connection(Some(Strict), None)).await,
        Ok(true)
    );
    let d = apply_policy(&w, set_connection(Some(Graceful), Some(Disabled)))
        .await
        .unwrap_err();
    let d2 = apply_policy(&w, set_connection(Some(Strict), Some(OwnedMasters)))
        .await
        .unwrap_err();
    assert_ne!(d, d2);
    assert_eq!(
        w.policy("pol").connection,
        ConnectionPolicy {
            existing: Strict,
            multiplexing: Disabled
        },
        "nothing of a mixed action applies before its decision"
    );
}

#[tokio::test]
async fn merged_policy_fail_closed_for_lock_and_connection() {
    let w = World::new().await;
    // A second applicable policy, after `pol` by ID (so `pol` stays the chosen one),
    // is stricter on both fields.
    w.tx(|tx| {
        tx.upsert_policy(
            &standing_policy(
                "strict-pol",
                LockBehavior::RevokeOnLock,
                ConnectionPolicy {
                    existing: ExistingConnectionsMode::Strict,
                    multiplexing: MultiplexingMode::Disabled,
                },
            ),
            true,
        )
    });
    assert_eq!(w.policy("pol").lock_behavior, LockBehavior::Continue);
    let g = w.active_grant("r11-merged").await.grant_id;
    let o = w.tx(|tx| tx.grant_origin(&g)).unwrap();
    assert_eq!(
        o.lock_behavior,
        Some(LockBehavior::RevokeOnLock),
        "strictest wins"
    );
    assert_eq!(
        o.connection.map(|c| c.existing),
        Some(ExistingConnectionsMode::Strict)
    );
    // The merge itself is the domain's fail-closed rule.
    let mut merged = standing_policy("pol", LockBehavior::Continue, ConnectionPolicy::default());
    let others = [
        standing_policy(
            "a",
            LockBehavior::Continue,
            ConnectionPolicy {
                existing: ExistingConnectionsMode::Graceful,
                multiplexing: MultiplexingMode::OwnedMasters,
            },
        ),
        standing_policy("b", LockBehavior::RevokeOnLock, ConnectionPolicy::default()),
    ];
    heimdall_domain::policy::merge_lock_and_connection(&mut merged, &others);
    assert_eq!(merged.lock_behavior, LockBehavior::RevokeOnLock);
    assert_eq!(merged.connection, ConnectionPolicy::default());
}

// =================================================================================
// Row 12: the degraded sign rule
// =================================================================================

#[tokio::test]
async fn degraded_reason_sign_rule_table() {
    use DegradedReason as R;
    let table = [
        (R::MechanismUnavailable, DegradedSignRule::Refuse, true),
        (R::CredentialReissuePending, DegradedSignRule::NoKey, false),
        (R::IssuerUnavailable, DegradedSignRule::Permit, false),
        (R::PairUnenrolled, DegradedSignRule::Permit, false),
    ];
    for (reason, rule, refuses) in table {
        assert_eq!(reason.sign_rule(), rule, "{reason:?}");
        assert_eq!(reason.permits_signing(), rule == DegradedSignRule::Permit);
        assert_eq!(degraded_refuses_use(reason), refuses, "{reason:?}");
    }
    // Operations-level: a grant degraded for a reason that permits use is not refused
    // its use (a re-issue reservation included); `mechanism_unavailable` is.
    let w = World::new().await;
    for (n, (reason, _, refuses)) in table.into_iter().enumerate() {
        let g = w.active_grant(&format!("r12-{n}")).await.grant_id;
        w.tx(|tx| {
            let mut snapshot = tx.grant(&g)?.unwrap();
            snapshot.state = GrantState::Degraded;
            tx.update_grant_state(&snapshot)?;
            tx.set_grant_degradation(&g, reason)
        });
        // The configured mechanism repairs `mechanism_unavailable` on use; probe the
        // rule without that repair through a world whose adapter is gone.
        if refuses {
            continue;
        }
        let r = w.ops.reserve_issuance(issuance(&g)).await;
        assert!(r.is_ok(), "{reason:?}: {r:?}");
    }
    let mut gone = World::new().await;
    let g = gone.active_grant("r12-gone").await.grant_id;
    gone.fake = FakeCredentialAdapter::new(descriptor("other_mechanism"), Vec::<FakeStep>::new());
    gone.restart().await;
    let e = gone.ops.reserve_issuance(issuance(&g)).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.message, "the grant's credential mechanism is unavailable");
}

// =================================================================================
// Row 19: the bind-time owned connection
// =================================================================================

fn launch(
    binding: &BindingId,
    rid: &str,
    executable: &str,
    holder: Option<ProcessHolder>,
) -> BindRequest {
    BindRequest {
        binding_id: binding.clone(),
        form: BindForm::Launch(LaunchBinding {
            executable: executable.into(),
            holder,
        }),
        request_id: RequestId::parse(rid).unwrap(),
    }
}

fn holder(pid: u32) -> ProcessHolder {
    ProcessHolder {
        pid,
        started_at: format!("start-{pid}"),
    }
}

#[cfg(unix)]
struct Exited;

#[cfg(unix)]
impl ProcessLiveness for Exited {
    fn state(&self, _holder: &ProcessHolder) -> HolderState {
        HolderState::Exited
    }
}

#[tokio::test]
async fn holder_registers_dedicated_only_for_verified_ssh() {
    let w = World::new().await;
    let data = w.active_grant("r19-only").await;
    let prepared = w.tx(|tx| tx.grant_prepared_facts(&data.grant_id));
    assert_eq!(
        verified_client_image(prepared.as_ref(), SSH).as_deref(),
        Some(SSH)
    );
    assert_eq!(
        verified_client_image(prepared.as_ref(), OTHER_PROGRAM),
        None
    );
    assert_eq!(
        verified_client_image(None, SSH),
        None,
        "no stored integration"
    );
    // Another program: the holder is claimed, no owned connection.
    ok(w.ops
        .bind(
            &unattended(),
            launch(
                &data.binding_id,
                "r19-sh",
                OTHER_PROGRAM,
                Some(holder(4100)),
            ),
        )
        .await);
    assert!(
        w.tx(|tx| tx.owned_connections_for_binding(&data.binding_id))
            .is_empty()
    );
    // The verified client without a holder: nothing to own.
    let other = w.active_grant("r19-noholder").await;
    ok(w.ops
        .bind(
            &unattended(),
            launch(&other.binding_id, "r19-nh", SSH, None),
        )
        .await);
    assert!(
        w.tx(|tx| tx.owned_connections_for_binding(&other.binding_id))
            .is_empty()
    );
}

#[tokio::test]
async fn windows_holder_never_registers_connection_itself() {
    let h = holder(4200);
    assert!(
        !dedicated_at_bind(true, Some(&h), Some(SSH)),
        "Windows: never from the holder"
    );
    assert!(!dedicated_at_bind(true, None, None));
    assert!(
        dedicated_at_bind(false, Some(&h), Some(SSH)),
        "Unix: the verified client"
    );
    assert!(!dedicated_at_bind(false, None, Some(SSH)));
    assert!(!dedicated_at_bind(false, Some(&h), None));
    if cfg!(windows) {
        let w = World::new().await;
        let data = w.active_grant("r19-win").await;
        ok(w.ops
            .bind(
                &unattended(),
                launch(&data.binding_id, "r19-w", SSH, Some(h)),
            )
            .await);
        assert!(
            w.tx(|tx| tx.owned_connections_for_binding(&data.binding_id))
                .is_empty()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unix_connection_row_written_at_bind_with_expected_image() {
    let w = World::new().await;
    let data = w.active_grant("r19-unix").await;
    let h = holder(4300);
    ok(w.ops
        .bind(
            &unattended(),
            launch(&data.binding_id, "r19-u", SSH, Some(h.clone())),
        )
        .await);
    let rows = w.tx(|tx| tx.owned_connections_for_binding(&data.binding_id));
    assert_eq!(rows.len(), 1);
    let c = &rows[0];
    assert_eq!(c.kind, ConnectionKind::Dedicated);
    assert_eq!(c.state, OwnedConnectionState::Up);
    assert_eq!(c.image, SSH, "the expected image");
    assert_eq!(
        (c.pid, c.start_token.as_str()),
        (h.pid, h.started_at.as_str())
    );
    assert_eq!(c.grant, data.grant_id);
    assert_eq!(
        w.tx(|tx| tx.binding_holder(&data.binding_id)),
        Some(h.clone())
    );
    // A replay of the same launch keeps one row.
    ok(w.ops
        .bind(
            &unattended(),
            launch(&data.binding_id, "r19-u", SSH, Some(h.clone())),
        )
        .await);
    assert_eq!(
        w.tx(|tx| tx.owned_connections_for_binding(&data.binding_id))
            .len(),
        1
    );
    // The holder pass observes the exit (or a failed exec, whose launcher then exits):
    // the binding is released and the row closed with it.
    let released = ok(w.ops.release_exited_holders(&Exited).await).data;
    assert_eq!(released, vec![data.binding_id.clone()]);
    let rows = w.tx(|tx| tx.owned_connections_for_binding(&data.binding_id));
    assert_eq!(rows[0].state, OwnedConnectionState::Closed);
}

// =================================================================================
// Row 21: existing-access preparation is unchanged
// =================================================================================

#[tokio::test]
async fn existing_access_prepare_contract_unchanged() {
    use heimdall_adapters::native_agent::NativeAgentAdapter;
    use heimdall_adapters::onepassword::OnePasswordAdapter;
    // The real existing-access adapters (no sources, no endpoint: nothing is read or
    // contacted): no remote credential effect, no managed sources in the snapshot.
    let native = NativeAgentAdapter::new("w0".into(), None);
    let onepassword = OnePasswordAdapter::new("w0".into(), None);
    let adapters: [&dyn CredentialAdapter; 2] = [&native, &onepassword];
    for a in adapters {
        assert!(
            !a.descriptor().remote_credential_effect,
            "{:?}",
            a.descriptor().identity
        );
        assert_ne!(a.descriptor().lock_continuity, LockContinuity::Verified);
        assert_eq!(a.read_sources(&[]).managed, None);
        assert_ne!(a.descriptor().identity.mechanism, MANAGED_CERTIFICATE);
    }
    // Nothing in existing-access preparation reads `IntegrationSnapshot.managed`: the
    // adapters' sources and the application's preparation path never name the field.
    let root = heimdall_testkit::repo::repo_root();
    let mut sources: Vec<std::path::PathBuf> = std::fs::read_dir(root.join("crates/adapters/src"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    sources.push(root.join("crates/app/src/operations.rs"));
    for path in sources {
        let text = std::fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            assert!(
                !code.contains(".managed") || code.contains("::managed"),
                "{}:{} reads `.managed`",
                path.display(),
                i + 1
            );
        }
    }
}

// =================================================================================
// Row 22: SetPreference and the issuing-CA set
// =================================================================================

fn set_preference_req(rid: &str, p: &AccessPair, mechanism: PreferredMechanism) -> CatalogRequest {
    CatalogRequest::SetPreference {
        destination: p.destination.clone(),
        account: p.account.clone(),
        mechanism,
        request_id: RequestId::parse(rid).unwrap(),
    }
}

#[tokio::test]
async fn set_preference_refused_without_verified_enrollment() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::AppliedUnverified));
    let e = err(w
        .ops
        .catalog(
            &attended(),
            set_preference_req("r22-1", &h1(), PreferredMechanism::ManagedCertificate),
        )
        .await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("pair_not_enrolled"));
    assert_eq!(w.preference(&h1()), None, "nothing stored");
    // Journaled under `catalog`, settled failed.
    let op = e.operation_id.clone().expect("journaled");
    let record = w.tx(|tx| tx.operation(&op)).unwrap();
    assert_eq!(record.kind, OperationKind::Catalog);
    assert_eq!(record.state, OperationState::Failed);
    // `existing` on a pair with nothing stored changes nothing.
    let done = ok(w
        .ops
        .catalog(
            &attended(),
            set_preference_req("r22-2", &h1(), PreferredMechanism::Existing),
        )
        .await);
    assert_eq!(done.data["changed"], false);
    assert_eq!(w.preference(&h1()), None);

    // With a verified enrollment: stored managed, projection pending, its CA in the
    // issuing set. It takes effect for P only through `setup apply`: ensure keeps the
    // existing mechanism and says so.
    w.register_ca(2, CaState::Active);
    w.seed_enrollment(&enrollment(2, 2, &h1(), EnrollmentState::Verified));
    let done = ok(w
        .ops
        .catalog(
            &attended(),
            set_preference_req("r22-3", &h1(), PreferredMechanism::ManagedCertificate),
        )
        .await);
    assert_eq!(done.data["changed"], true);
    let p = w.preference(&h1()).unwrap();
    assert_eq!(p.mechanism, PreferredMechanism::ManagedCertificate);
    assert_eq!(p.projection, ProjectionStatus::Pending);
    assert_eq!(p.issuing_cas, [ca(2)].into_iter().collect());
    let ensured = ok(w
        .ensure(ensure_req("r22-ensure", &[("h1", "deploy")]))
        .await);
    assert_eq!(ensured.data.credential_mechanism, "fake_agent");
    assert_eq!(warning_codes(&ensured), ["managed_projection_pending"]);
    // Switching back is local: existing, projection pending, the CA set kept.
    ok(w.ops
        .catalog(
            &attended(),
            set_preference_req("r22-4", &h1(), PreferredMechanism::Existing),
        )
        .await);
    let p = w.preference(&h1()).unwrap();
    assert_eq!(p.mechanism, PreferredMechanism::Existing);
    assert_eq!(p.projection, ProjectionStatus::Pending);
    assert_eq!(p.issuing_cas, [ca(2)].into_iter().collect());
    // A replay returns the first result.
    let replay = ok(w
        .ops
        .catalog(
            &attended(),
            set_preference_req("r22-3", &h1(), PreferredMechanism::ManagedCertificate),
        )
        .await);
    assert_eq!(replay.data["changed"], true);
}

#[tokio::test]
async fn issuing_ca_set_updated_by_e5_and_removal() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    w.register_ca(2, CaState::Active);
    w.register_ca(3, CaState::Active);
    let e1 = enrollment(1, 1, &h1(), EnrollmentState::Verified);
    let e2 = enrollment(2, 2, &h1(), EnrollmentState::Verified);
    w.seed_enrollment(&e1);
    w.seed_enrollment(&e2);
    w.seed_enrollment(&enrollment(3, 3, &h1(), EnrollmentState::Verifying));

    // E5 of the first enrollment: managed, projection pending, {CA 1}.
    let p = w.ops.add_issuing_ca(&h1(), &ca(1), true).await.unwrap();
    assert_eq!(p.mechanism, PreferredMechanism::ManagedCertificate);
    assert_eq!(p.projection, ProjectionStatus::Pending);
    assert_eq!(p.issuing_cas, [ca(1)].into_iter().collect());
    // `setup apply` renders it (U10's driver; seeded here).
    w.tx(|tx| {
        tx.set_pair_preference(
            &PairPreference {
                projection: applied(),
                ..p.clone()
            },
            t0(),
        )
    });
    // A rotation's E5 on a managed, applied pair: the CA joins, the projection stays.
    let p = w.ops.add_issuing_ca(&h1(), &ca(2), true).await.unwrap();
    assert_eq!(p.projection, applied());
    assert_eq!(p.issuing_cas, [ca(1), ca(2)].into_iter().collect());
    // A CA without a verified enrollment for the pair is refused, nothing written.
    let e = w
        .ops
        .add_issuing_ca(&h1(), &ca(3), false)
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("pair_not_enrolled"));
    assert_eq!(w.preference(&h1()).unwrap().issuing_cas.len(), 2);

    // Removing CA 1 while CA 2 stays verified: still managed, applied.
    w.tx(|tx| {
        tx.transition_enrollment(
            EnrollmentState::Verified,
            EnrollmentEventKind::RemoveEnrollmentApproved,
            &e1,
        )
        .map(|r| {
            r.unwrap();
        })
    });
    let p = w
        .ops
        .remove_issuing_ca(&h1(), &ca(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.mechanism, PreferredMechanism::ManagedCertificate);
    assert_eq!(p.projection, applied());
    assert_eq!(p.issuing_cas, [ca(2)].into_iter().collect());
    // Removing the last verified CA: back to existing, projection pending.
    let p = w
        .ops
        .remove_issuing_ca(&h1(), &ca(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.mechanism, PreferredMechanism::Existing);
    assert_eq!(p.projection, ProjectionStatus::Pending);
    assert!(p.issuing_cas.is_empty());
    // A pair with no stored preference is left alone.
    assert_eq!(
        w.ops
            .remove_issuing_ca(&pair("h3", "deploy"), &ca(1))
            .await
            .unwrap(),
        None
    );
    assert_eq!(e2.state, EnrollmentState::Verified);
}

// =================================================================================
// E10: cancel of an enrollment operation
// =================================================================================

/// ⟨M03 wave 4, U10⟩ Before any remote mutation was attempted, cancelling an open
/// enrollment operation is allowed by the rule and the driver now does it (phase 1
/// refused it `driver_unavailable`): the operation settles `cancelled`, reporting no
/// external effect.
#[tokio::test]
async fn enrollment_cancel_before_attempt_cancels() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 61, VerifyMode::Presence, 1);
    let cancel = CancelRequest {
        operation_id: op.clone(),
    };
    let _ = w.ops.cancel(&unattended(), cancel).await;
    let after = w.tx(|tx| tx.operation(&op)).unwrap();
    assert_eq!(after.state, OperationState::Cancelled);
    assert_eq!(after.effect_status, EffectStatus::None);
    assert_eq!(
        after.cancellation.map(|c| c.may_have_external_effect),
        Some(false)
    );
}

#[tokio::test]
async fn enrollment_cancel_refused_writes_nothing() {
    let w = World::new().await;
    let op = seed_verify_operation(&w, 60, VerifyMode::Presence, 1);
    let cancel = CancelRequest {
        operation_id: op.clone(),
    };
    // Once a remote mutation's `Attempted` receipt exists: remote_step_in_progress.
    w.tx(|tx| {
        tx.append_stage_receipt(
            &op,
            &StageReceipt {
                stage: enrollment_stage::APPEND.into(),
                recorded_at: t0(),
                effect: EffectReceipt::Attempted {
                    adapter: AdapterIdentity {
                        mechanism: "enrollment".into(),
                        instance: "fixture".into(),
                    },
                    effect_token: "eff_00000000000000000000000000000000".into(),
                },
                local: None,
            },
        )
    });
    let before = w.tx(|tx| tx.operation(&op)).unwrap();
    let e = err(w.ops.cancel(&unattended(), cancel).await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("remote_step_in_progress"));
    assert_eq!(e.next.action, "reconcile");
    assert_eq!(w.tx(|tx| tx.operation(&op)).unwrap(), before, "unchanged");
}
