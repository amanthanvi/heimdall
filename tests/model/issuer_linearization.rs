//! M03 wave 2 (U3): the linearization model (ADR-0005 §9.3 R2/R12; m03-plan U3; ADR-0008
//! D3 item 4, D2 items 3/3a, §17.1 item 1, §17.4 item 6, §17.7 items 2–3, §17.10 item 1,
//! §17.13 item 1).
//!
//! Everything runs in process over the production `heimdall_app::Operations` (an
//! in-memory store, the testkit's `FakeCredentialAdapter` recording
//! `managed_certificate`) and the issuer's own steps: `check::verify_reservation` (the
//! child's read-only check, D3 item 4 steps 1–3, over a read transaction with the
//! read-only time assessment) then `ca::CaSet::sign` (steps 3–5) with a real per-run
//! K_ca. The clock is the tokio clock, **paused**: wall and continuous time move only
//! when the runtime is idle or `advance` is called, so every interleaving is
//! deterministic. The signer's side is the production `SignatureAuthority`
//! (`precheck`, `admit` under the grant's signing gate, the permit's release check) with
//! gates created by `SigningGates::retain`, as the first credential instance will (U10);
//! "enqueue" is recorded only when the release check passes.
//!
//! **Pass conditions** (m03-plan U3), asserted in every case:
//! 1. no certificate is published once any predicate fails;
//! 2. the issuer refuses whenever its read-only snapshot shows a failing predicate;
//! 3. a receiver with a stale generation, a tombstone or an unsafe deadline discards;
//! 4. every `reserved`/`published` entry counts in the residual;
//! 5. a `reserved` entry is never published after a crash (a crash is the loss of the
//!    `Operations` instance: a new one starts over the same store);
//! 6. no signature is enqueued after a narrowing's commit (nor after its mark).

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::issuance_ro;
use heimdall_app::managed::SigningGates;
use heimdall_app::operations::narrowing::{
    BoundTerms, HookFuture, NarrowingHook, NarrowingKind, NarrowingPoint,
};
use heimdall_app::operations::{
    IssuanceFacts, IssuanceRequest, Limits, MANAGED_CERTIFICATE, Publication,
};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, LockState,
    PrepareOutcome, SessionLockSource, SignRefusal, SignatureAuthority, SignatureRequestFacts,
    SignatureSubject, SignerEndpoint,
};
use heimdall_app::timegate::TimeGate;
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DestinationId, DeviceId, EnrollmentId, EnvironmentId, IdentityId,
    PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
use heimdall_contract::request::{
    DeadlineIntent, DelegateRequest, DestinationScopeEnforcement, Enforcement, EnsureData,
    EnsureRequest, ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry,
    PolicyAction, RefreshDependency, RequiredCapabilities, RevocationStatus, RevokeRequest,
    WaitMode, WorkloadIsolation,
};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_credential::cert::{SecretCaKey, validate_installed};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::issuance::{EXTENSION_PTY, IssuanceEntry, IssuanceState};
use heimdall_domain::managed::LockEpoch;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimePolicy, TimeStatus};
use heimdall_issuer::ca::CaSet;
use heimdall_issuer::check::verify_reservation;
use heimdall_issuer::protocol::{IssuanceRef, IssuanceTable, IssuerRefusal};
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync};
use tokio::sync::Notify;
use tokio::time::Instant;

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-02T09:00:00Z".parse().unwrap()
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    Timestamp::from_second(t.as_second() + i64::try_from(d.as_secs()).unwrap()).unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn owner() -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    })
}

fn h1() -> AccessPair {
    AccessPair {
        destination: DestinationId::parse("h1").unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
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

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: plus(t0(), 12 * HOUR),
        offline_until: plus(t0(), HOUR),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

fn policy(lock: LockBehavior) -> StandingPolicy {
    StandingPolicy {
        id: policy_id(),
        revision: PolicyRevision(1),
        profile: ProfileId::parse("dev").unwrap(),
        workspace: None,
        scope: Scope {
            pairs: [h1()].into_iter().collect(),
            capabilities: ssh_only(),
        },
        environments: [env_id()].into_iter().collect(),
        max_window: 2 * HOUR,
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::SetupDefault,
        lock_behavior: lock,
        connection: ConnectionPolicy::default(),
    }
}

/// The operations clock on the paused tokio clock: wall = `t0 + elapsed − wall_back`,
/// continuous = `1000 s + elapsed`, one boot.
struct TokioClock {
    start: Instant,
    wall_back: Mutex<Duration>,
}

impl Clock for TokioClock {
    fn wall(&self) -> Timestamp {
        let w = plus(t0(), Instant::now().saturating_duration_since(self.start));
        let back = i64::try_from(self.wall_back.lock().unwrap().as_secs()).unwrap();
        Timestamp::from_second(w.as_second() - back).unwrap()
    }
    fn continuous(&self) -> Duration {
        Duration::from_secs(1000) + Instant::now().saturating_duration_since(self.start)
    }
    fn boot_id(&self) -> BootId {
        BootId("tokio-boot-1".into())
    }
}

/// The narrowing hook: logs the marks and commits with their instants, imposes
/// `t_read` before each read.
#[derive(Default)]
struct Hook {
    t_read: Mutex<Duration>,
    t_commit: Mutex<Duration>,
    cleanup_hold: Mutex<Option<(NarrowingKind, Duration)>>,
    log: Mutex<Vec<(Instant, NarrowingKind, NarrowingPoint)>>,
    changed: Notify,
}

impl Hook {
    fn first(&self, kind: NarrowingKind, f: impl Fn(&NarrowingPoint) -> bool) -> Option<Instant> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .find(|(_, k, p)| *k == kind && f(p))
            .map(|(i, _, _)| *i)
    }

    fn mark(&self, kind: NarrowingKind) -> Option<Instant> {
        self.first(kind, |p| matches!(p, NarrowingPoint::Marked { .. }))
    }

    async fn wait_marked(&self, kind: NarrowingKind) {
        loop {
            let n = self.changed.notified();
            tokio::pin!(n);
            n.as_mut().enable();
            if self.mark(kind).is_some() {
                return;
            }
            n.await;
        }
    }
}

impl NarrowingHook for Hook {
    fn at<'a>(&'a self, kind: NarrowingKind, point: NarrowingPoint) -> HookFuture<'a> {
        Box::pin(async move {
            self.log
                .lock()
                .unwrap()
                .push((Instant::now(), kind, point.clone()));
            self.changed.notify_waiters();
            let delay = match &point {
                NarrowingPoint::BeforeRead(_) => *self.t_read.lock().unwrap(),
                NarrowingPoint::BeforeCommit => *self.t_commit.lock().unwrap(),
                NarrowingPoint::Cleanup { .. } => match *self.cleanup_hold.lock().unwrap() {
                    Some((k, d)) if k == kind => d,
                    _ => Duration::ZERO,
                },
                _ => Duration::ZERO,
            };
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            self.changed.notify_waiters();
        })
    }
}

/// A session-lock source the test locks.
struct TestLock {
    state: Mutex<LockState>,
    epoch: Mutex<LockEpoch>,
    notify: Notify,
}

impl TestLock {
    fn lock(&self) {
        *self.state.lock().unwrap() = LockState::Locked;
        let e = *self.epoch.lock().unwrap();
        *self.epoch.lock().unwrap() = e.observe_lock();
    }
}

impl SessionLockSource for TestLock {
    fn state(&self) -> LockState {
        *self.state.lock().unwrap()
    }
    fn lock_epoch(&self) -> LockEpoch {
        *self.epoch.lock().unwrap()
    }
    fn acknowledge(&self, epoch: u64) {
        let e = *self.epoch.lock().unwrap();
        *self.epoch.lock().unwrap() = e.acknowledge(epoch);
    }
    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

/// The issuer's own steps over the runtime's store (the child's `sign` body, in
/// process): the read-only check, then the CA set's signature.
struct Issuer {
    cas: CaSet,
    gate: TimeGate,
}

impl Issuer {
    fn sign(
        &self,
        store: &Store,
        e: &IssuanceEntry,
        subject: &str,
    ) -> Result<String, IssuerRefusal> {
        let r = IssuanceRef {
            table: IssuanceTable::Grant,
            id: e.id.clone(),
        };
        let bounds = verify_reservation(store, &self.gate, &r, subject)?;
        let key = ssh_key::PublicKey::from_openssh(subject).unwrap();
        let cert = self.cas.sign(IssuanceTable::Grant, &bounds, &key)?;
        Ok(cert.to_openssh().unwrap())
    }
}

struct W {
    store: Arc<Store>,
    clock: Arc<TokioClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    limits: Limits,
    ops: Operations,
    hook: Arc<Hook>,
    lock: Arc<TestLock>,
    issuer: Issuer,
    ca: CaFingerprint,
    keys: KeyVault,
}

fn config(
    w: (
        &Arc<Store>,
        &Arc<TokioClock>,
        &Arc<ScriptedTimeSync>,
        &Arc<FakeCredentialAdapter>,
    ),
    limits: Limits,
) -> OperationsConfig {
    OperationsConfig {
        store: w.0.clone(),
        clock: w.1.clone(),
        time_sync: w.2.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![w.3.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits,
        default_window: 12 * HOUR,
        projection: None,
    }
}

async fn world(lock: LockBehavior, limits: Limits) -> W {
    let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
    let k_ca = SecretCaKey::generate().unwrap();
    let ca = k_ca.fingerprint().unwrap();
    let enrollment_id = EnrollmentId::from_random_bytes([1; 16]);
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
                id: ProfileId::parse("dev").unwrap(),
                revision: 1,
                scope: Scope {
                    pairs: [h1()].into_iter().collect(),
                    capabilities: ssh_only(),
                },
                label: None,
            })?;
            tx.upsert_policy(&policy(lock), false)?;
            tx.upsert_destination(&DestinationRecord {
                id: DestinationId::parse("h1").unwrap(),
                alias: "h1".into(),
                revision: 1,
                definition: DestinationDefinition::Observed,
                label: None,
                updated_at: t0(),
            })?;
            tx.insert_issuer(&IssuerRecord {
                ca_fingerprint: ca.clone(),
                public_key: k_ca.public_openssh().unwrap(),
                state: CaState::Active,
                store_kind: StoreKind::LinuxSecretService,
                backup_sha256: "ab".repeat(32),
                backup_created_at: t0(),
                restored_without_log: false,
                created_at: t0(),
                retired_at: None,
            })?;
            tx.seed_enrollment(&EnrollmentRecord {
                marker: marker_for(&enrollment_id),
                id: enrollment_id.clone(),
                destination: h1().destination,
                account: h1().account,
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
                    hostname: "h1.example.invalid".into(),
                    port: 22,
                    user: h1().account,
                    proxy: NoProxy::None,
                    host_key: ApprovedHostKey {
                        algorithm: "ssh-ed25519".into(),
                        key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                        fingerprint: "SHA256:hostfixture".into(),
                    },
                },
                existing_access: ExistingAccessRecord {
                    identity: IdentityId::from_random_bytes([1; 16]),
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
            })?;
            Ok(())
        })
        .unwrap();
    let clock = Arc::new(TokioClock {
        start: Instant::now(),
        wall_back: Mutex::new(Duration::ZERO),
    });
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let fake = FakeCredentialAdapter::new(
        AdapterDescriptor {
            identity: heimdall_domain::operation::AdapterIdentity {
                mechanism: MANAGED_CERTIFICATE.into(),
                instance: "fixture-1".into(),
            },
            capabilities: ssh_only(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false,
        },
        (0..32)
            .map(|_| FakeStep::Prepare(outcome()))
            .collect::<Vec<_>>(),
    );
    let ops = Operations::start(config((&store, &clock, &sync, &fake), limits))
        .await
        .unwrap();
    let hook = Arc::new(Hook::default());
    ops.set_narrowing_hook(hook.clone());
    let test_lock = Arc::new(TestLock {
        state: Mutex::new(LockState::Unlocked),
        epoch: Mutex::new(LockEpoch::default()),
        notify: Notify::new(),
    });
    ops.set_session_lock_source(test_lock.clone());
    let mut cas = CaSet::new();
    cas.insert(&ca, k_ca, CaState::Active).unwrap();
    let issuer = Issuer {
        cas,
        gate: TimeGate::new(
            store.clone(),
            clock.clone(),
            ScriptedTimeSync::new(SyncStatus::Unknown),
            TimePolicy::default(),
        ),
    };
    W {
        store,
        clock,
        sync,
        fake,
        limits,
        ops,
        hook,
        lock: test_lock,
        issuer,
        ca,
        keys: KeyVault::new(),
    }
}

impl W {
    fn gates(&self) -> &SigningGates {
        self.ops.signing_gates()
    }

    async fn root(&self, tag: &str) -> EnsureData {
        self.ops
            .ensure(
                &owner(),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: [h1()].into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("ensure {tag}: {} {}", e.code, e.message))
            .data
    }

    async fn child(&self, parent: &EnsureData, tag: &str) -> EnsureData {
        self.ops
            .delegate(
                &owner(),
                DelegateRequest {
                    parent_binding_id: parent.binding_id.clone(),
                    scope: [h1()].into_iter().collect(),
                    until: Some(DeadlineIntent::Duration("1h".into())),
                    work_id: WorkId::parse(&format!("c-{tag}")).unwrap(),
                    request_id: RequestId::parse(&format!("d-{tag}")).unwrap(),
                    required_capabilities: RequiredCapabilities::default(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("delegate {tag}: {} {}", e.code, e.message))
            .data
    }

    async fn revoke(&self, g: &EnsureData, rid: &str) {
        self.ops
            .revoke(
                &owner(),
                RevokeRequest {
                    grant_id: g.grant_id.clone(),
                    request_id: RequestId::parse(rid).unwrap(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("revoke {rid}: {} {}", e.code, e.message));
    }

    async fn cutoff(&self, at: Timestamp) {
        self.ops
            .policy(
                &owner(),
                PolicyAction::Cutoff {
                    policy_id: policy_id(),
                    at,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("cutoff: {} {}", e.code, e.message));
    }

    fn request(
        &self,
        g: &EnsureData,
        subject: &PublicKeyInfo,
        new_activation: bool,
    ) -> IssuanceRequest {
        IssuanceRequest {
            grant: g.grant_id.clone(),
            pair: h1(),
            principal: "hm:h1:deploy".into(),
            key_id: format!("heimdall:{}:{}:1", env_id().as_str(), g.grant_id.as_str()),
            valid_after: plus(self.clock.wall(), Duration::ZERO),
            valid_before: plus(self.clock.wall(), Duration::from_secs(1800)),
            extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
            subject_fingerprint: subject.fingerprint.clone(),
            facts: IssuanceFacts {
                new_activation,
                ..issuance_ro::ISSUER_FACTS
            },
        }
    }

    fn entry(&self, e: &IssuanceEntry) -> IssuanceEntry {
        self.store
            .transaction(|tx| tx.issuance_entries(&e.grant))
            .unwrap()
            .into_iter()
            .find(|x| x.id == e.id)
            .unwrap()
    }

    /// Pass condition 4: every reserved/published entry of `g` is in its residual.
    fn residual_covers(&self, g: &EnsureData) {
        let entries = self
            .store
            .transaction(|tx| tx.issuance_entries(&g.grant_id))
            .unwrap();
        let residual = self
            .store
            .transaction(|tx| tx.issuance_residual(std::slice::from_ref(&g.grant_id)))
            .unwrap();
        for e in entries
            .iter()
            .filter(|e| matches!(e.state, IssuanceState::Reserved | IssuanceState::Published))
        {
            assert!(
                residual.is_some_and(|r| r >= e.bounds.valid_before),
                "entry {} not counted",
                e.id
            );
        }
    }

    /// The receiver's check at install (pass condition 3): the grant is usable now, no
    /// tombstone, the deadline is safe on safe time, the generation the entry was
    /// published at is current; otherwise the certificate is discarded.
    fn receiver_accepts(&self, e: &IssuanceEntry) -> bool {
        let time = self.issuer.gate.assess_read_only(&self.store);
        self.store
            .transaction(|tx| {
                let g = tx.grant(&e.grant)?.unwrap();
                Ok(time == TimeStatus::Safe
                    && matches!(g.state, GrantState::Active | GrantState::Degraded)
                    && tx.denied_ancestor(&g.id)?.is_none()
                    && self.clock.wall() < g.deadline.effective
                    && e.bounds.valid_before <= g.deadline.effective
                    && tx.authority_generation()? == e.generation)
            })
            .unwrap()
    }
}

fn sign_facts(g: &EnsureData) -> SignatureRequestFacts {
    SignatureRequestFacts {
        endpoint: SignerEndpoint::Binding(g.binding_id.clone()),
        subject: SignatureSubject::Grant(g.grant_id.clone()),
        pair: h1(),
        key_fingerprint: "SHA256:fixture".into(),
    }
}

/// A test signer: admits, holds the permit for `hold`, then "enqueues" (records the
/// instant) only when the release check passes.
#[derive(Default)]
struct Signers {
    enqueued: Mutex<Vec<Instant>>,
    refused_at_release: AtomicUsize,
    refused_at_admit: Mutex<Vec<SignRefusal>>,
}

impl Signers {
    fn spawn(
        self: &Arc<Self>,
        ops: &Operations,
        g: &EnsureData,
        hold: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let (me, ops, f) = (Arc::clone(self), ops.clone(), sign_facts(g));
        tokio::spawn(async move {
            match ops.admit(&f).await {
                Ok(p) => {
                    tokio::time::sleep(hold).await;
                    if p.may_release() {
                        me.enqueued.lock().unwrap().push(Instant::now());
                    } else {
                        me.refused_at_release.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(e) => me.refused_at_admit.lock().unwrap().push(e),
            }
        })
    }

    fn none_enqueued_after(&self, mark: Instant) {
        for e in self.enqueued.lock().unwrap().iter() {
            assert!(*e < mark, "a signature was enqueued after the mark");
        }
    }
}

// =================================================================================
// The issuance interleavings (activation and re-issue, a crash at each step)
// =================================================================================

/// A narrowing or time event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Revoke,
    Cutoff,
    DelegationChange,
    DeadlinePassage,
    TimeUncertainOnset,
    LockRevocation,
}

const EVENTS: [Event; 6] = [
    Event::Revoke,
    Event::Cutoff,
    Event::DelegationChange,
    Event::DeadlinePassage,
    Event::TimeUncertainOnset,
    Event::LockRevocation,
];

/// The issuance steps; the event runs before the step at its position (4 = after
/// install).
const STEPS: [&str; 4] = ["reserve", "issuer_check_and_sign", "publish", "install"];

async fn apply_event(w: &W, event: Event, subject: &EnsureData, parent: Option<&EnsureData>) {
    match event {
        Event::Revoke => w.revoke(subject, "rv-1").await,
        // A cutoff before the reserved `valid_before`: the bound moves under it.
        Event::Cutoff => {
            w.cutoff(plus(w.clock.wall(), Duration::from_secs(600)))
                .await
        }
        // The parent of the delegated subject is revoked (the delegation is withdrawn).
        Event::DelegationChange => w.revoke(parent.unwrap(), "rv-parent").await,
        // The deadline passes with no edit (and so does the reservation's freshness).
        Event::DeadlinePassage => tokio::time::advance(3 * HOUR).await,
        // The wall clock steps back beyond the tolerance: TIME_UNCERTAIN.
        Event::TimeUncertainOnset => *w.clock.wall_back.lock().unwrap() = HOUR,
        Event::LockRevocation => {
            w.lock.lock();
            w.ops
                .on_session_lock(w.lock.lock_epoch(), w.lock.as_ref())
                .await
                .unwrap();
        }
    }
}

/// One case: `event` at `position`, crash after step `crash` (if any), for activation
/// (`reissue` false) or re-issue.
async fn issuance_case(event: Event, position: usize, crash: Option<usize>, reissue: bool) {
    let lock = if event == Event::LockRevocation {
        LockBehavior::RevokeOnLock
    } else {
        LockBehavior::Continue
    };
    let mut w = world(lock, Limits::default()).await;
    let root = w.root("root").await;
    let (subject, parent) = if event == Event::DelegationChange {
        (w.child(&root, "kid").await, Some(root.clone()))
    } else {
        (root.clone(), None)
    };
    let key = w.keys.generate_ed25519().unwrap().1;
    if reissue {
        // Re-issue: an earlier certificate was published for the grant (its instance
        // was then lost); the new one goes through the same steps.
        let first = w
            .ops
            .reserve_issuance(w.request(&subject, &key, true))
            .await
            .unwrap();
        w.issuer.sign(&w.store, &first, &key.openssh_line).unwrap();
        assert!(matches!(
            w.ops
                .publish_issuance(&first.id, &w.request(&subject, &key, true).facts)
                .await
                .unwrap(),
            Publication::Published(_)
        ));
    }
    let req = w.request(&subject, &key, !reissue);
    let mut entry: Option<IssuanceEntry> = None;
    let mut signed: Option<String> = None;
    let mut published: Option<IssuanceEntry> = None;
    let mut event_done = false;
    let mut crashed = false;
    let ctx = format!("{event:?} at {position}, crash {crash:?}, reissue {reissue}");
    for (step, name) in STEPS.iter().enumerate() {
        if step == position {
            apply_event(&w, event, &subject, parent.as_ref()).await;
            event_done = true;
        }
        match *name {
            "reserve" => {
                let r = w.ops.reserve_issuance(req.clone()).await;
                if event_done {
                    assert!(r.is_err(), "{ctx}: reserve after the event");
                    break;
                }
                entry = Some(r.unwrap());
            }
            "issuer_check_and_sign" => {
                let e = entry.as_ref().unwrap();
                let r = w.issuer.sign(&w.store, e, &key.openssh_line);
                // Pass condition 2: a failing predicate in the snapshot refuses.
                if event_done {
                    assert!(r.is_err(), "{ctx}: the issuer signed after the event");
                    signed = None;
                } else {
                    signed = Some(r.unwrap_or_else(|e| panic!("{ctx}: {e:?}")));
                }
            }
            "publish" => {
                let e = entry.as_ref().unwrap();
                let r = w.ops.publish_issuance(&e.id, &req.facts).await;
                match r {
                    Ok(Publication::Published(p)) => {
                        // Pass conditions 1 and 5.
                        assert!(!event_done, "{ctx}: published after the event");
                        assert!(!crashed, "{ctx}: published after a crash");
                        assert!(signed.is_some(), "{ctx}: published unsigned");
                        published = Some(p);
                    }
                    Ok(Publication::Rereserved { .. }) => {
                        assert!(event_done, "{ctx}: a re-reservation without a move");
                    }
                    Err(_) => assert!(event_done || crashed, "{ctx}: publish refused"),
                }
            }
            _ => {
                // Install: the receiver's check (pass condition 3).
                if let (Some(p), Some(cert)) = (&published, &signed) {
                    let accepts = w.receiver_accepts(p);
                    if event_done {
                        assert!(!accepts, "{ctx}: installed after the event");
                    } else {
                        assert!(accepts, "{ctx}: discarded a valid certificate");
                        let c = ssh_key::Certificate::from_openssh(cert).unwrap();
                        validate_installed(&c, &p.bounds, &key.fingerprint, &w.ca).unwrap();
                    }
                }
            }
        }
        if crash == Some(step) {
            // The runtime instance is lost; a new one starts over the same store.
            w.ops = Operations::start(config((&w.store, &w.clock, &w.sync, &w.fake), w.limits))
                .await
                .unwrap();
            w.ops.set_narrowing_hook(w.hook.clone());
            w.ops.set_session_lock_source(w.lock.clone());
            crashed = true;
        }
    }
    if position == STEPS.len() {
        apply_event(&w, event, &subject, parent.as_ref()).await;
        if let Some(p) = &published {
            assert!(
                !w.receiver_accepts(p),
                "{ctx}: still accepted after the event"
            );
        }
    }
    if let Some(e) = &entry {
        let stored = w.entry(e);
        // Pass condition 5: an entry reserved before a crash and not published before
        // it is never published afterwards.
        if crash.is_some_and(|c| c < 2) {
            assert_ne!(stored.state, IssuanceState::Published, "{ctx}");
        }
        // Pass condition 1.
        if position <= 2 {
            assert_ne!(stored.state, IssuanceState::Published, "{ctx}");
        }
    }
    // Pass condition 4.
    w.residual_covers(&subject);
}

/// Every event at every position, for activation and re-issue, with a crash after each
/// step (and none).
#[tokio::test(start_paused = true)]
async fn model_issuance_interleavings_activation_and_reissue() {
    let mut cases = 0;
    for event in EVENTS {
        for position in 0..=STEPS.len() {
            for crash in [None, Some(0), Some(1), Some(2), Some(3)] {
                for reissue in [false, true] {
                    issuance_case(event, position, crash, reissue).await;
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 6 * 5 * 5 * 2);
}

// =================================================================================
// The signer's steps against a narrowing
// =================================================================================

/// The signer's steps: precheck, gate (`admit`'s shared acquisition and fresh read),
/// sign, capacity, release check, enqueue. A narrowing (revoke, cutoff, delegation
/// change, lock revocation) commits between each pair; nothing is enqueued after its
/// mark, and a signature admitted before the mark is either enqueued before the
/// commit or refused at the release check.
#[tokio::test(start_paused = true)]
async fn model_signer_steps_against_each_narrowing() {
    for event in [
        Event::Revoke,
        Event::Cutoff,
        Event::DelegationChange,
        Event::LockRevocation,
    ] {
        for position in 0..=3 {
            let lock = if event == Event::LockRevocation {
                LockBehavior::RevokeOnLock
            } else {
                LockBehavior::Continue
            };
            let w = Arc::new(world(lock, Limits::default()).await);
            let root = w.root("root").await;
            w.gates().retain(&root.grant_id, &[]);
            let (subject, parent) = if event == Event::DelegationChange {
                let c = w.child(&root, "kid").await;
                w.gates()
                    .retain(&c.grant_id, std::slice::from_ref(&root.grant_id));
                (c, Some(root.clone()))
            } else {
                (root.clone(), None)
            };
            let ctx = format!("{event:?} at {position}");
            let kind = match event {
                Event::Cutoff => NarrowingKind::Cutoff,
                Event::LockRevocation => NarrowingKind::SessionLock,
                _ => NarrowingKind::Revoke,
            };
            // The event as a task (it waits for the gates the signer holds).
            let spawn_event = |w: &Arc<W>| {
                let (w, s, p) = (Arc::clone(w), subject.clone(), parent.clone());
                tokio::spawn(async move {
                    // A cutoff that lands at once makes the grant's bound pass.
                    if event == Event::Cutoff {
                        w.cutoff(plus(w.clock.wall(), Duration::from_secs(1))).await;
                        tokio::time::advance(Duration::from_secs(2)).await;
                    } else {
                        apply_event(&w, event, &s, p.as_ref()).await;
                    }
                })
            };
            let f = sign_facts(&subject);
            let mut enqueued: Option<Instant> = None;
            if position == 0 {
                spawn_event(&w).await.unwrap();
                assert!(w.ops.precheck(&f).await.is_err(), "{ctx}");
            } else {
                assert!(w.ops.precheck(&f).await.is_ok(), "{ctx}");
                let mut task = None;
                if position == 1 {
                    task = Some(spawn_event(&w));
                    w.hook.wait_marked(kind).await;
                }
                match w.ops.admit(&f).await {
                    Ok(permit) => {
                        assert!(position >= 2, "{ctx}: admitted after the mark");
                        if position == 2 {
                            // Sign and capacity run while the permit is held; the
                            // narrowing marks meanwhile.
                            task = Some(spawn_event(&w));
                            w.hook.wait_marked(kind).await;
                        }
                        if permit.may_release() {
                            enqueued = Some(Instant::now());
                        }
                        drop(permit);
                        if position == 3 {
                            // The event starts strictly after the enqueue (virtual time).
                            tokio::time::advance(Duration::from_millis(1)).await;
                            task = Some(spawn_event(&w));
                        }
                    }
                    Err(_) => assert_eq!(position, 1, "{ctx}"),
                }
                task.unwrap().await.unwrap();
            }
            if let (Some(at), Some(mark)) = (enqueued, w.hook.mark(kind)) {
                assert!(at < mark, "{ctx}: enqueued after the mark");
            }
            // After the commit nothing is admitted.
            assert!(w.ops.admit(&f).await.is_err(), "{ctx}");
        }
    }
}

/// Delegation created during a cascade, and two concurrent cascades in lock order: both
/// commit, the child of the cascade never signs after the commit, and no signature is
/// enqueued after either mark.
#[tokio::test(start_paused = true)]
async fn model_delegation_during_cascade_and_two_cascades_in_lock_order() {
    let w = Arc::new(world(LockBehavior::Continue, Limits::default()).await);
    *w.hook.t_read.lock().unwrap() = Duration::from_millis(500);
    let a = w.root("a").await;
    let b = w.root("b").await;
    w.gates().retain(&a.grant_id, &[]);
    w.gates().retain(&b.grant_id, &[]);
    let signers = Arc::new(Signers::default());
    let s1 = signers.spawn(&w.ops, &a, Duration::from_millis(200));
    let s2 = signers.spawn(&w.ops, &b, Duration::from_millis(200));
    // Two cascades at once (revoke a, revoke b), in the gates' global order.
    let (wa, wb) = (Arc::clone(&w), Arc::clone(&w));
    let (ra, rb) = (a.clone(), b.clone());
    let r1 = tokio::spawn(async move { wa.revoke(&ra, "rv-a").await });
    let r2 = tokio::spawn(async move { wb.revoke(&rb, "rv-b").await });
    // A delegation from `a` while its cascade runs: refused or cascaded.
    let child = w
        .ops
        .delegate(
            &owner(),
            DelegateRequest {
                parent_binding_id: a.binding_id.clone(),
                scope: [h1()].into_iter().collect(),
                until: Some(DeadlineIntent::Duration("1h".into())),
                work_id: WorkId::parse("c-during").unwrap(),
                request_id: RequestId::parse("d-during").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await;
    r1.await.unwrap();
    r2.await.unwrap();
    s1.await.unwrap();
    s2.await.unwrap();
    let mark = w.hook.mark(NarrowingKind::Revoke).unwrap();
    signers.none_enqueued_after(mark);
    if let Ok(c) = child {
        // A child created during the cascade is covered by it: never signs after.
        assert!(w.ops.admit(&sign_facts(&c.data)).await.is_err());
        let key = w.keys.generate_ed25519().unwrap().1;
        assert!(
            w.ops
                .reserve_issuance(w.request(&c.data, &key, true))
                .await
                .is_err()
        );
    }
    for g in [&a, &b] {
        assert!(w.ops.admit(&sign_facts(g)).await.is_err());
    }
}

// =================================================================================
// The round-4 traces and the round-5 countermodels (§17.10 item 1, §17.13 item 1)
// =================================================================================

/// §17.10 item 1, the second round-4 trace: a request pre-checked before the mark and
/// gated after it is refused (`narrowing_pending`), and the issuer refuses its entry
/// once the narrowing committed.
#[tokio::test(start_paused = true)]
async fn model_precheck_before_mark_then_gate_after_mark_refused() {
    let w = Arc::new(world(LockBehavior::Continue, Limits::default()).await);
    let g = w.root("g").await;
    w.gates().retain(&g.grant_id, &[]);
    let key = w.keys.generate_ed25519().unwrap().1;
    let entry = w
        .ops
        .reserve_issuance(w.request(&g, &key, true))
        .await
        .unwrap();
    assert!(w.ops.precheck(&sign_facts(&g)).await.is_ok());
    *w.hook.t_read.lock().unwrap() = Duration::from_secs(1);
    let (w2, g2) = (Arc::clone(&w), g.clone());
    let revoke = tokio::spawn(async move { w2.revoke(&g2, "rv").await });
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    assert_eq!(
        w.ops.admit(&sign_facts(&g)).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    revoke.await.unwrap();
    assert!(w.issuer.sign(&w.store, &entry, &key.openssh_line).is_err());
    assert!(
        w.ops
            .publish_issuance(&entry.id, &w.request(&g, &key, true).facts)
            .await
            .is_err()
    );
    w.residual_covers(&g);
}

/// Spawn a delegation that holds `parent`'s chain until `until`, then creates a child
/// (gated) and releases.
fn pre_mark_delegation(
    w: &Arc<W>,
    hold: heimdall_app::managed::DelegationHold,
    parent: &EnsureData,
    until: Duration,
    tag: &'static str,
) -> tokio::task::JoinHandle<EnsureData> {
    let (w, p) = (Arc::clone(w), parent.clone());
    tokio::spawn(async move {
        tokio::time::sleep(until).await;
        let c = w.child(&p, tag).await;
        w.gates()
            .retain(&c.grant_id, std::slice::from_ref(&p.grant_id));
        drop(hold);
        c
    })
}

/// §17.13 item 1, the round-5 multi-root countermodel with the issuer path: 8 roots, a
/// pre-mark delegation ending at 9.9 s, 2 s reads, a cutoff that moves every root's
/// bound below the reserved `valid_before`. It commits within the derived bound
/// `H + R(9, 8)`, nothing is enqueued after the mark, and the issuer refuses (and
/// publish voids) the entries reserved before the cutoff: no certificate is
/// published once the predicate fails.
#[tokio::test(start_paused = true)]
async fn model_multi_root_countermodel_within_derived_bound() {
    let reads = Duration::from_secs(2);
    let limits = Limits {
        narrowing_read_budget: reads,
        ..Limits::default()
    };
    let w = Arc::new(world(LockBehavior::Continue, limits).await);
    *w.hook.t_read.lock().unwrap() = reads;
    let key = w.keys.generate_ed25519().unwrap().1;
    let mut roots = Vec::new();
    let mut entries = Vec::new();
    for i in 0..8 {
        let g = w.root(&format!("m{i}")).await;
        w.gates().retain(&g.grant_id, &[]);
        entries.push(
            w.ops
                .reserve_issuance(w.request(&g, &key, true))
                .await
                .unwrap(),
        );
        roots.push(g);
    }
    let hold = w
        .gates()
        .hold_for_delegation(&roots[0].grant_id, &[], Duration::from_secs(1))
        .await
        .unwrap();
    let start = Instant::now();
    let d = pre_mark_delegation(&w, hold, &roots[0], Duration::from_millis(9900), "mr");
    let at = plus(w.clock.wall(), Duration::from_secs(600));
    let wc = Arc::clone(&w);
    let cut = tokio::spawn(async move { wc.cutoff(at).await });
    w.hook.wait_marked(NarrowingKind::Cutoff).await;
    let signers = Arc::new(Signers::default());
    let late = signers.spawn(&w.ops, &roots[3], Duration::ZERO);
    cut.await.unwrap();
    let _child = d.await.unwrap();
    late.await.unwrap();
    let r = w
        .ops
        .narrowing_reports()
        .into_iter()
        .rfind(|r| r.kind == NarrowingKind::Cutoff)
        .unwrap();
    assert_eq!((r.members, r.roots), (9, 8), "{r:?}");
    let terms = BoundTerms::of(&w.limits);
    assert_eq!(r.bound, terms.h + terms.work(9, 8));
    assert!(r.elapsed <= r.bound, "{r:?}");
    assert!(start.elapsed() <= r.bound + Duration::from_secs(1));
    signers.none_enqueued_after(w.hook.mark(NarrowingKind::Cutoff).unwrap());
    assert_eq!(
        signers.refused_at_admit.lock().unwrap().as_slice(),
        &[SignRefusal::NarrowingPending]
    );
    // The issuer path: every entry reserved before the cutoff is refused by the
    // issuer's snapshot and voided at publish; residuals still count them.
    for (g, e) in roots.iter().zip(&entries) {
        assert!(w.issuer.sign(&w.store, e, &key.openssh_line).is_err());
        let facts = w.request(g, &key, true).facts;
        assert!(w.ops.publish_issuance(&e.id, &facts).await.is_err());
        assert_ne!(w.entry(e).state, IssuanceState::Published);
        w.residual_covers(g);
    }
}

/// §17.13 item 1, the overlapping-narrowing countermodel with the issuer path: an
/// earlier revoke whose cleanup is held 5 s and whose reads are at the budget, and a
/// later cutoff sharing a grant. The later commits within `H + R(earlier) + R(later)`
/// without waiting for the earlier cleanup; nothing is released after either mark; the
/// issuer refuses the shared grant's entry and nothing is published.
#[tokio::test(start_paused = true)]
async fn model_overlapping_narrowings_countermodel_within_derived_bound() {
    let w = Arc::new(world(LockBehavior::Continue, Limits::default()).await);
    *w.hook.t_read.lock().unwrap() = w.limits.narrowing_read_budget;
    *w.hook.t_commit.lock().unwrap() = w.limits.narrowing_commit_budget;
    *w.hook.cleanup_hold.lock().unwrap() = Some((NarrowingKind::Revoke, Duration::from_secs(5)));
    let a = w.root("a").await;
    let b = w.root("b").await;
    w.gates().retain(&a.grant_id, &[]);
    w.gates().retain(&b.grant_id, &[]);
    let key = w.keys.generate_ed25519().unwrap().1;
    let ea = w
        .ops
        .reserve_issuance(w.request(&a, &key, true))
        .await
        .unwrap();
    let eb = w
        .ops
        .reserve_issuance(w.request(&b, &key, true))
        .await
        .unwrap();
    let signers = Arc::new(Signers::default());
    let s = signers.spawn(&w.ops, &a, Duration::from_millis(100));
    let wr = Arc::clone(&w);
    let ra = a.clone();
    let earlier = tokio::spawn(async move { wr.revoke(&ra, "rv-a").await });
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let later_start = Instant::now();
    let at = plus(w.clock.wall(), Duration::from_secs(600));
    let wc = Arc::clone(&w);
    let later = tokio::spawn(async move { wc.cutoff(at).await });
    later.await.unwrap();
    let later_elapsed = later_start.elapsed();
    earlier.await.unwrap();
    s.await.unwrap();
    let reports = w.ops.narrowing_reports();
    let re = reports
        .iter()
        .rfind(|r| r.kind == NarrowingKind::Revoke)
        .unwrap();
    let rl = reports
        .iter()
        .rfind(|r| r.kind == NarrowingKind::Cutoff)
        .unwrap();
    let terms = BoundTerms::of(&w.limits);
    let derived = terms.h + terms.work(re.members, re.roots) + terms.work(rl.members, rl.roots);
    assert!(rl.elapsed <= derived, "{rl:?} > {derived:?}");
    assert!(later_elapsed <= derived + Duration::from_secs(1));
    for kind in [NarrowingKind::Revoke, NarrowingKind::Cutoff] {
        signers.none_enqueued_after(w.hook.mark(kind).unwrap());
    }
    for (g, e) in [(&a, &ea), (&b, &eb)] {
        assert!(w.issuer.sign(&w.store, e, &key.openssh_line).is_err());
        let facts = w.request(g, &key, true).facts;
        assert!(w.ops.publish_issuance(&e.id, &facts).await.is_err());
        assert_ne!(w.entry(e).state, IssuanceState::Published);
        w.residual_covers(g);
    }
}
