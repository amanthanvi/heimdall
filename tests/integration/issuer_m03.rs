//! ⟨M03⟩ wave 4 (U10-B): the issuer request handling (ADR-0008 D3, D4; m03-plan U10
//! `issuer::handle`) and the verification signing gate (ADR-0008 §17.19 item 5,
//! INT-Q13 option (a)).
//!
//! Everything runs in process over the production `heimdall_app::Operations` on
//! `Store::open_in_memory`, `testkit::VirtualClock` and `testkit::ScriptedTimeSync`.
//! The issuer child is a **fake** `IssuerPort` + `IssuerLifecycle` (`FakeIssuer`):
//! these tests cover the runtime's request handling, decisions and store effects, not
//! the child (U3's `integration_issuer_child`) nor a platform store. No platform
//! secret store is read or written here, so no native store claim is closed by them.
//! Store rows the issuer paths read but never write (enrollments, a verifying
//! operation) are seeded through the store's own `Txn` methods.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::future::Future;
use std::pin::Pin;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::issuer::IssuerLifecycle;
use heimdall_app::managed::{ManagedWiring, ReleaseRefusal, VerificationScope};
use heimdall_app::operations::{AWAITING_OWNER_DELETION, Limits, VerificationRequest};
use heimdall_app::ports::{
    IssuanceRef, IssuerError, IssuerPort, IssuerStatusSnapshot, SignRefusal, SignatureAuthority,
    SignatureRequestFacts, SignatureSubject, SignerEndpoint,
};
use heimdall_app::{Attendance, Caller, Operations, OperationsConfig};
use heimdall_contract::canonical::RequestHash;
use heimdall_contract::enrollment::{EnrollmentRequest, VerifyMode};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DecisionId, DestinationId, DeviceId, EnrollmentId, EnvironmentId,
    IdentityId, IssuanceId, OperationId, RequestId,
};
use heimdall_contract::issuer::{
    CaState, IssuerRequest, IssuerState, IssuerStatus, RecoveryBundle, StoreKind,
};
use heimdall_contract::managed::IssuerIsolation;
use heimdall_contract::request::{DecideRequest, InteractionMode, Request, Verdict, WaitMode};
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_credential::cert::SecretCaKey;
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
use heimdall_domain::issuance::CaEvent;
use heimdall_domain::operation::{
    EffectClass, EffectReceipt, OperationKind, OperationRecord, RecoveryIntent, RecoveryMetadata,
    StageReceipt, enrollment_stage,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::scope::AccessPair;
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_domain::verification::{VerificationPurpose, VerificationRefusal};
use heimdall_issuer::retire;
use heimdall_issuer::store::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError as ScratchError, StoreItemRef,
};
use heimdall_store::{IssuerRecord, Store};
use heimdall_testkit::scratch_store::ScratchSecretStore;
use heimdall_testkit::{ScriptedTimeSync, VirtualClock, assert_no_canary};

// =================================================================================
// Harness
// =================================================================================

fn t0() -> Timestamp {
    "2026-11-11T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([0x41; 16])
}

fn ctx(role: ClientRole) -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role,
    }
}

fn attended() -> Caller {
    Caller {
        context: ctx(ClientRole::Owner),
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn unattended() -> Caller {
    Caller::unattended(ctx(ClientRole::Owner))
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

/// Standard padded base64 (the test's own; no dependency).
fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(
                    A[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap()],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// An Ed25519 OpenSSH public-key line (no comment) whose 32 key bytes are `n`.
fn ca_line(n: u8) -> String {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&[n; 32]);
    format!("ssh-ed25519 {}", b64(&blob))
}

fn ca_fp(n: u8) -> CaFingerprint {
    heimdall_app::issuer::ca_public_key_fingerprint(&ca_line(n)).unwrap()
}

fn digest(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn register_req(n: u8, rotation_of: Option<CaFingerprint>) -> IssuerRequest {
    serde_json::from_value(serde_json::json!({
        "action": "register",
        "ca_public_key": ca_line(n),
        "store": "linux_secret_service",
        "backup_sha256": digest(n),
        "backup_created_at": t0(),
        "rotation_of": rotation_of,
    }))
    .unwrap()
}

fn issuer_record(n: u8, state: CaState) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: ca_fp(n),
        public_key: ca_line(n),
        state,
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: digest(n),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: shift(t0(), i64::from(n)),
        retired_at: None,
    }
}

fn enrollment(n: u8, ca: u8, p: &AccessPair, state: EnrollmentState) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: p.destination.clone(),
        account: p.account.clone(),
        ca_fingerprint: ca_fp(ca),
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
            hostname: format!("{}.secret-host.invalid", p.destination.as_str()),
            port: 2222,
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

/// The issuer child as the runtime sees it: a scripted `IssuerPort` and lifecycle.
struct FakeIssuer {
    state: Mutex<IssuerState>,
    /// What `reload` answers (`Ok` → `ready`).
    reload_answer: Mutex<Result<(), IssuerError>>,
    starts: AtomicUsize,
    reloads: AtomicUsize,
    unloads: Mutex<Vec<CaFingerprint>>,
}

impl FakeIssuer {
    fn new(state: IssuerState) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
            reload_answer: Mutex::new(Ok(())),
            starts: AtomicUsize::new(0),
            reloads: AtomicUsize::new(0),
            unloads: Mutex::new(Vec::new()),
        })
    }
}

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl IssuerPort for FakeIssuer {
    fn status(&self) -> IssuerStatusSnapshot {
        IssuerStatusSnapshot {
            status: IssuerStatus {
                state: *self.state.lock().unwrap(),
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
    ) -> Fut<'async_trait, Result<String, IssuerError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async { Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into())) })
    }

    fn unload<'life0, 'life1, 'async_trait>(
        &'life0 self,
        ca: &'life1 CaFingerprint,
    ) -> Fut<'async_trait, Result<(), IssuerError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.unloads.lock().unwrap().push(ca.clone());
            Ok(())
        })
    }
}

impl IssuerLifecycle for FakeIssuer {
    fn start<'life0, 'async_trait>(&'life0 self) -> Fut<'async_trait, Result<(), IssuerError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.starts.fetch_add(1, Ordering::SeqCst);
            *self.state.lock().unwrap() = IssuerState::Ready;
            Ok(())
        })
    }

    fn reload<'life0, 'async_trait>(&'life0 self) -> Fut<'async_trait, Result<(), IssuerError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.reloads.fetch_add(1, Ordering::SeqCst);
            let answer = self.reload_answer.lock().unwrap().clone();
            *self.state.lock().unwrap() = match &answer {
                Ok(()) => IssuerState::Ready,
                Err(_) => IssuerState::StoreUnavailable,
            };
            answer
        })
    }

    fn stop<'life0, 'async_trait>(&'life0 self) -> Fut<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            *self.state.lock().unwrap() = IssuerState::Unavailable;
        })
    }
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    ops: Operations,
    issuer: Arc<FakeIssuer>,
}

impl World {
    /// A runtime whose environment has neither `managed_signing` nor `issuer_access`
    /// (registration sets both), with the fake issuer wired.
    async fn new() -> Self {
        let w = Self::unwired().await;
        w.wire();
        w
    }

    async fn unwired() -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        Self::seed(&store);
        Self::start(store, VirtualClock::at(t0())).await
    }

    /// ⟨§17.21 item 3⟩ A new `Operations` instance over this world's store and clock
    /// (a runtime restart: nothing of the old instance's memory survives), with a
    /// fresh fake issuer wired.
    async fn restarted(self) -> Self {
        let Self {
            store, clock, ops, ..
        } = self;
        drop(ops);
        let w = Self::start(store, clock).await;
        w.wire();
        w
    }

    fn seed(store: &Store) {
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&EnvironmentRecord {
                    id: env_id(),
                    device: DeviceId::from_random_bytes([0x42; 16]),
                    kind: EnvironmentKind::NativeSession,
                    label: None,
                    permissions: EnvironmentPermissions {
                        automatic_activation: true,
                        managed_signing: false,
                        issuer_access: false,
                    },
                })
            })
            .unwrap();
    }

    async fn start(store: Arc<Store>, clock: Arc<VirtualClock>) -> Self {
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: sync,
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: Duration::from_secs(3600),
            projection: None,
        })
        .await
        .unwrap();
        Self {
            store,
            clock,
            ops,
            issuer: FakeIssuer::new(IssuerState::NotInitialized),
        }
    }

    fn wire(&self) {
        self.ops.set_managed_wiring(ManagedWiring {
            issuer: Some(self.issuer.clone() as Arc<dyn IssuerPort>),
            issuer_lifecycle: Some(self.issuer.clone() as Arc<dyn IssuerLifecycle>),
            ..ManagedWiring::default()
        });
    }

    fn tx<R>(
        &self,
        f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<R>,
    ) -> R {
        self.store.transaction(f).unwrap()
    }

    fn register_ca(&self, n: u8, state: CaState) {
        self.tx(|tx| tx.insert_issuer(&issuer_record(n, state)));
    }

    fn seed_enrollment(&self, e: &EnrollmentRecord) {
        self.tx(|tx| tx.seed_enrollment(e));
    }

    fn decision(&self, id: &DecisionId) -> DecisionRecord {
        self.tx(|tx| tx.decision(id)).unwrap()
    }

    fn generation(&self) -> u64 {
        self.tx(|tx| tx.authority_generation()).0
    }

    /// Every table a refused request could have written.
    fn snapshot(&self) -> String {
        self.tx(|tx| {
            Ok(format!(
                "{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
                tx.table_counts()?,
                tx.pending_decisions()?,
                tx.issuers()?,
                tx.environment(&env_id())?,
                tx.authority_generation()?,
            ))
        })
    }

    async fn issuer(
        &self,
        caller: &Caller,
        req: IssuerRequest,
    ) -> Result<serde_json::Value, heimdall_app::OpError> {
        let r = self.ops.issuer_request(caller, req).await;
        if let Err(e) = &r {
            assert_no_canary(&format!("{e:?}"));
        }
        r.map(|c| {
            assert_no_canary(&c.data.to_string());
            c.data
        })
    }

    async fn decide(
        &self,
        id: &DecisionId,
        verdict: Verdict,
    ) -> Result<serde_json::Value, heimdall_app::OpError> {
        self.ops
            .decide(
                &attended(),
                DecideRequest {
                    decision_id: id.clone(),
                    verdict,
                },
            )
            .await
            .map(|c| c.data)
    }
}

/// The decision a refused register/retire request names.
fn decision_of(e: &heimdall_app::OpError) -> DecisionId {
    let r = e.resource.as_ref().unwrap_or_else(|| panic!("{e:?}"));
    assert_eq!(r.kind, "decision", "{e:?}");
    DecisionId::parse(r.id.as_deref().unwrap()).unwrap()
}

fn code(r: &Result<serde_json::Value, heimdall_app::OpError>) -> Code {
    match r {
        Ok(_) => Code::Ok,
        Err(e) => e.code.clone(),
    }
}

fn reason_of(e: &heimdall_app::OpError) -> Option<String> {
    e.reason.clone()
}

// =================================================================================
// Fail closed without the wiring (R4)
// =================================================================================

/// R4: every issuer action of a runtime without the issuer wiring answers
/// `driver_unavailable` before any record is written, and a non-owner is refused
/// first.
#[tokio::test]
async fn issuer_requests_fail_closed_without_wiring() {
    let w = World::unwired().await;
    let before = w.snapshot();
    for req in [
        IssuerRequest::Status,
        IssuerRequest::Unlock,
        register_req(1, None),
        IssuerRequest::Retire {
            ca_fingerprint: ca_fp(1),
            deleted_locator: None,
        },
        IssuerRequest::Bundle {
            redact_hostnames: false,
        },
    ] {
        let e = w.issuer(&attended(), req.clone()).await.unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable, "{req:?}");
        assert_eq!(reason_of(&e).as_deref(), Some(reason::DRIVER_UNAVAILABLE));
        let agent = Caller {
            context: ctx(ClientRole::LimitedConsumer),
            ..attended()
        };
        let e = w.issuer(&agent, req).await.unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable);
        assert_eq!(reason_of(&e), None, "the role refusal comes first");
    }
    assert_eq!(w.snapshot(), before, "nothing was written");
}

// =================================================================================
// Status
// =================================================================================

/// `issuer.status`: with no CA registered it is `not_initialized` whatever the child
/// says; with CAs, the child's observed state and **the store's CA records**
/// (`IssuerPort::status` leaves `cas` empty) with each CA's enrollment counts.
#[tokio::test]
async fn issuer_status_fills_ca_records_from_store() {
    let w = World::new().await;
    *w.issuer.state.lock().unwrap() = IssuerState::Ready;
    let s: IssuerStatus =
        serde_json::from_value(w.issuer(&attended(), IssuerRequest::Status).await.unwrap())
            .unwrap();
    assert_eq!(s.state, IssuerState::NotInitialized);
    assert_eq!(s.reason.as_deref(), Some(reason::ISSUER_NOT_INITIALIZED));
    assert!(s.cas.is_empty());

    w.register_ca(1, CaState::Active);
    w.register_ca(2, CaState::Pending);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    w.seed_enrollment(&enrollment(
        2,
        1,
        &pair("h2", "deploy"),
        EnrollmentState::Applying,
    ));
    w.seed_enrollment(&enrollment(
        3,
        1,
        &pair("h3", "deploy"),
        EnrollmentState::Abandoned,
    ));
    w.seed_enrollment(&enrollment(
        4,
        1,
        &pair("h4", "deploy"),
        EnrollmentState::Removed,
    ));
    let s: IssuerStatus = serde_json::from_value(
        w.issuer(&unattended(), IssuerRequest::Status)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(s.state, IssuerState::Ready);
    assert_eq!(s.issuer_isolation, IssuerIsolation::SameUserProcess);
    assert_eq!(s.cas.len(), 2);
    let c1 = s.cas.iter().find(|c| c.fingerprint == ca_fp(1)).unwrap();
    assert_eq!(c1.state, CaState::Active);
    assert_eq!(c1.store, StoreKind::LinuxSecretService);
    assert_eq!(c1.backup_sha256, digest(1));
    assert_eq!((c1.enrollments.verified, c1.enrollments.pending), (1, 1));
    let c2 = s.cas.iter().find(|c| c.fingerprint == ca_fp(2)).unwrap();
    assert_eq!(c2.state, CaState::Pending);
    assert_eq!((c2.enrollments.verified, c2.enrollments.pending), (0, 0));
    assert!(s.bundle_stale, "no record of a fresher bundle exists");
}

// =================================================================================
// Register (RegisterIssuer)
// =================================================================================

/// D4 item 1 steps 3 and 7: `issuer.register` always creates a `RegisterIssuer`
/// decision and never executes on dispatch (`APPROVAL_REQUIRED` attended,
/// `INTERACTION_REQUIRED` unattended, both naming the record; one logical decision,
/// one record). Approval records the CA `active` with the request's public values,
/// sets the environment's `managed_signing` and `issuer_access` (moving the
/// generation), records the lock disclosure once, and starts or reloads the child.
#[tokio::test]
async fn issuer_register_through_decision_approved() {
    let w = World::new().await;
    let gen0 = w.generation();
    let e = w
        .issuer(&attended(), register_req(1, None))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired);
    let d = decision_of(&e);
    let rec = w.decision(&d);
    assert_eq!(rec.state, DecisionState::Pending);
    let DecisionKind::RegisterIssuer {
        ca_fingerprint,
        store,
        backup_sha256,
        disclosures,
        ..
    } = &rec.kind
    else {
        panic!("{:?}", rec.kind);
    };
    assert_eq!(*ca_fingerprint, ca_fp(1));
    assert_eq!(*store, StoreKind::LinuxSecretService);
    assert_eq!(*backup_sha256, digest(1));
    assert!(
        disclosures.contains(&heimdall_contract::enrollment::DisclosureKind::LockContinuityOnce)
    );
    assert!(
        w.tx(|tx| tx.issuers()).is_empty(),
        "nothing executes on dispatch"
    );
    // The same registration joins the same record, attended or not.
    let again = w
        .issuer(&unattended(), register_req(1, None))
        .await
        .unwrap_err();
    assert_eq!(again.code, Code::InteractionRequired);
    assert_eq!(decision_of(&again), d);
    assert_eq!(w.tx(|tx| tx.pending_decisions()).len(), 1);

    let done = w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(done["state"], "approved");
    let ca = w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap();
    assert_eq!(ca.state, CaState::Active);
    assert_eq!(ca.public_key, ca_line(1));
    assert_eq!(ca.backup_sha256, digest(1));
    assert_eq!(ca.backup_created_at, t0());
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))),
        None,
        "no store item was reported: none recorded"
    );
    let env = w.tx(|tx| tx.environment(&env_id())).unwrap();
    assert!(env.permissions.managed_signing && env.permissions.issuer_access);
    assert!(
        w.generation() > gen0,
        "the permission change moved the generation"
    );
    assert!(w.tx(|tx| tx.lock_disclosure_ack()).is_some());
    assert_eq!(
        w.issuer.reloads.load(Ordering::SeqCst),
        1,
        "the child was started"
    );

    // A second registration of the same CA is refused, writing nothing.
    let before = w.snapshot();
    let e = w
        .issuer(&attended(), register_req(1, None))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(w.snapshot(), before);
    // Rotation: the new CA starts `pending`; lock continuity is not disclosed again.
    let e = w
        .issuer(&attended(), register_req(2, Some(ca_fp(1))))
        .await
        .unwrap_err();
    let d2 = decision_of(&e);
    let DecisionKind::RegisterIssuer { disclosures, .. } = &w.decision(&d2).kind else {
        panic!();
    };
    assert!(
        !disclosures.contains(&heimdall_contract::enrollment::DisclosureKind::LockContinuityOnce)
    );
    w.decide(&d2, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(2))).unwrap().state,
        CaState::Pending
    );
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 2);
}

/// A denied `RegisterIssuer` records nothing and starts nothing; a malformed request
/// is refused before any record.
#[tokio::test]
async fn issuer_register_denied_records_nothing() {
    let w = World::new().await;
    let before = w.snapshot();
    for bad in [
        serde_json::json!({"action":"register","ca_public_key": format!("{} comment", ca_line(1)),
            "store":"linux_secret_service","backup_sha256":digest(1),"backup_created_at":t0()}),
        serde_json::json!({"action":"register","ca_public_key": ca_line(1),
            "store":"linux_secret_service","backup_sha256":"NOTHEX","backup_created_at":t0()}),
        serde_json::json!({"action":"register","ca_public_key": ca_line(1),
            "store":"linux_secret_service","backup_sha256":digest(1),"backup_created_at":t0(),
            "rotation_of": ca_fp(9)}),
    ] {
        let req: IssuerRequest = serde_json::from_value(bad).unwrap();
        let e = w.issuer(&attended(), req).await.unwrap_err();
        assert!(matches!(e.code, Code::UsageError | Code::NotFound), "{e:?}");
    }
    assert_eq!(
        w.snapshot(),
        before,
        "nothing written for a refused request"
    );
    let gen0 = w.generation();
    let d = decision_of(
        &w.issuer(&attended(), register_req(1, None))
            .await
            .unwrap_err(),
    );
    w.decide(&d, Verdict::Deny).await.unwrap();
    assert_eq!(w.decision(&d).state, DecisionState::Denied);
    assert!(w.tx(|tx| tx.issuers()).is_empty());
    let env = w.tx(|tx| tx.environment(&env_id())).unwrap();
    assert!(!env.permissions.managed_signing && !env.permissions.issuer_access);
    assert_eq!(w.generation(), gen0);
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 0);
    // The denied record is consumed: approving it now is refused.
    assert!(w.decide(&d, Verdict::Approve).await.is_err());
}

/// The precheck refuses an approval with **nothing consumed** (the record stays
/// `pending`): the CA was registered meanwhile, or the record lacks the registration's
/// public key (a record written before ADR-0008 §17.21 item 3's fields).
#[tokio::test]
async fn issuer_register_refused_not_consumed_when_precheck_fails() {
    let w = World::new().await;
    let d = decision_of(
        &w.issuer(&attended(), register_req(1, None))
            .await
            .unwrap_err(),
    );
    w.register_ca(1, CaState::Active);
    let generation = w.generation();
    let r = w.decide(&d, Verdict::Approve).await;
    assert_eq!(code(&r), Code::ConfigConflict);
    assert_eq!(w.decision(&d).state, DecisionState::Pending, "not consumed");
    assert_eq!(w.generation(), generation, "nothing written");
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 0);

    // A record without the registration's public key (the old shape).
    let foreign = DecisionId::from_random_bytes([0x77; 16]);
    w.tx(|tx| {
        let generation = tx.authority_generation()?;
        tx.insert_decision(&DecisionRecord {
            id: foreign.clone(),
            kind: DecisionKind::RegisterIssuer {
                ca_fingerprint: ca_fp(3),
                store: StoreKind::LinuxSecretService,
                backup_sha256: digest(3),
                rotation_of: None,
                restored_without_log: false,
                disclosures: Vec::new(),
                ca_public_key: None,
                backup_created_at: None,
                store_locator: None,
                expected_store_locator: None,
            },
            generation,
            created_at: t0(),
            expires_at: shift(t0(), 3600),
            state: DecisionState::Pending,
            decided_at: None,
        })
    });
    let r = w.decide(&foreign, Verdict::Approve).await;
    assert_eq!(code(&r), Code::DecisionStale);
    assert_eq!(w.decision(&foreign).state, DecisionState::Pending);
    assert!(w.tx(|tx| tx.issuer(&ca_fp(3))).is_none());
}

/// ⟨ADR-0008 §17.21 item 3⟩ A pending `RegisterIssuer` carries the registration's
/// public key and backup time, so it survives a runtime restart: a **new**
/// `Operations` instance over the same store approves it, recording the CA with
/// exactly the request's public values (no process memory involved).
#[tokio::test]
async fn issuer_registration_survives_restart_and_is_approved() {
    let w = World::new().await;
    let prepared_at = shift(t0(), -600);
    let mut req = serde_json::to_value(register_req(1, None)).unwrap();
    req["backup_created_at"] = serde_json::json!(prepared_at);
    let req: IssuerRequest = serde_json::from_value(req).unwrap();
    let d = decision_of(&w.issuer(&attended(), req.clone()).await.unwrap_err());
    let DecisionKind::RegisterIssuer {
        ca_public_key,
        backup_created_at,
        ..
    } = &w.decision(&d).kind
    else {
        panic!();
    };
    assert_eq!(ca_public_key.as_deref(), Some(ca_line(1).as_str()));
    assert_eq!(*backup_created_at, Some(prepared_at));

    let w = w.restarted().await;
    // The same registration joins the surviving record.
    assert_eq!(
        decision_of(&w.issuer(&attended(), req).await.unwrap_err()),
        d
    );
    let done = w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(done["state"], "approved");
    assert_eq!(w.decision(&d).state, DecisionState::Approved);
    let ca = w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap();
    assert_eq!(ca.state, CaState::Active);
    assert_eq!(ca.public_key, ca_line(1));
    assert_eq!(ca.backup_created_at, prepared_at);
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 1);
}

/// ⟨ADR-0008 §17.21 item 3⟩ A `RegisterIssuer` record of the old shape (no
/// `ca_public_key`, no `backup_created_at`), or one whose key is not the recorded
/// fingerprint's, is refused `DECISION_STALE` on approval and **not consumed**: it
/// stays `pending`, no CA is recorded, the generation does not move. A new
/// registration of the same CA is not joined to the old record.
#[tokio::test]
async fn issuer_register_old_shape_decision_is_stale_not_consumed() {
    let w = World::new().await;
    let insert = |id: &DecisionId, key: Option<String>, at: Option<Timestamp>| {
        w.tx(|tx| {
            let generation = tx.authority_generation()?;
            tx.insert_decision(&DecisionRecord {
                id: id.clone(),
                kind: DecisionKind::RegisterIssuer {
                    ca_fingerprint: ca_fp(4),
                    store: StoreKind::LinuxSecretService,
                    backup_sha256: digest(4),
                    rotation_of: None,
                    restored_without_log: false,
                    disclosures: Vec::new(),
                    ca_public_key: key,
                    backup_created_at: at,
                    store_locator: None,
                    expected_store_locator: None,
                },
                generation,
                created_at: t0(),
                expires_at: shift(t0(), 3600),
                state: DecisionState::Pending,
                decided_at: None,
            })
        });
    };
    let old = DecisionId::from_random_bytes([0x78; 16]);
    insert(&old, None, None);
    let stored = w.tx(|tx| tx.decision(&old)).unwrap();
    let json = serde_json::to_value(&stored.kind).unwrap();
    assert!(json.get("ca_public_key").is_none() && json.get("backup_created_at").is_none());
    let only_key = DecisionId::from_random_bytes([0x79; 16]);
    insert(&only_key, Some(ca_line(4)), None);
    let wrong_key = DecisionId::from_random_bytes([0x7a; 16]);
    insert(&wrong_key, Some(ca_line(5)), Some(t0()));
    let generation = w.generation();
    for id in [&old, &only_key, &wrong_key] {
        let r = w.decide(id, Verdict::Approve).await;
        assert_eq!(code(&r), Code::DecisionStale, "{id}");
        assert_eq!(w.decision(id).state, DecisionState::Pending, "not consumed");
    }
    assert!(w.tx(|tx| tx.issuer(&ca_fp(4))).is_none());
    assert_eq!(w.generation(), generation, "nothing written");
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 0);
    // A registration now is a new record carrying the facts, never the old one.
    let d = decision_of(
        &w.issuer(&attended(), register_req(4, None))
            .await
            .unwrap_err(),
    );
    assert!(![&old, &only_key, &wrong_key].contains(&&d));
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(w.decision(&old).state, DecisionState::Pending);
}

// =================================================================================
// Retire (RetireIssuer)
// =================================================================================

/// D4 item 3, §17.1 item 7 (the retirement refusal; the enrollment states are
/// U10-A's): `issuer retire` is refused, writing nothing, while any enrollment under
/// the CA is neither final nor abandoned; once every one is, it creates a
/// `RetireIssuer` decision listing the abandoned ones.
#[tokio::test]
async fn ca_retirement_refused_until_every_enrollment_final_or_abandoned() {
    let w = World::new().await;
    // One CA per enrollment state that is neither final nor abandoned.
    let open = [
        EnrollmentState::Planned,
        EnrollmentState::Applying,
        EnrollmentState::Verifying,
        EnrollmentState::Verified,
        EnrollmentState::Held,
        EnrollmentState::Removing,
        EnrollmentState::ManualPending,
    ];
    for (i, state) in open.iter().enumerate() {
        let n = u8::try_from(10 + i).unwrap();
        w.register_ca(n, CaState::Active);
        w.seed_enrollment(&enrollment(n, n, &pair(&format!("o{n}"), "deploy"), *state));
        w.seed_enrollment(&enrollment(
            n + 40,
            n,
            &pair(&format!("r{n}"), "deploy"),
            EnrollmentState::Removed,
        ));
        let before = w.snapshot();
        let e = w
            .issuer(
                &attended(),
                IssuerRequest::Retire {
                    ca_fingerprint: ca_fp(n),
                    deleted_locator: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict, "{state:?}");
        assert_eq!(w.snapshot(), before, "nothing written ({state:?})");
    }
    // Every enrollment final or abandoned: the decision lists the abandoned ones.
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(
        30,
        1,
        &pair("a30", "deploy"),
        EnrollmentState::Abandoned,
    ));
    w.seed_enrollment(&enrollment(
        31,
        1,
        &pair("w31", "deploy"),
        EnrollmentState::Withdrawn,
    ));
    w.seed_enrollment(&enrollment(
        32,
        1,
        &pair("r32", "deploy"),
        EnrollmentState::Removed,
    ));
    let e = w
        .issuer(
            &attended(),
            IssuerRequest::Retire {
                ca_fingerprint: ca_fp(1),
                deleted_locator: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired);
    let DecisionKind::RetireIssuer {
        ca_fingerprint,
        abandoned_enrollments,
    } = w.decision(&decision_of(&e)).kind
    else {
        panic!();
    };
    assert_eq!(ca_fingerprint, ca_fp(1));
    assert_eq!(
        abandoned_enrollments,
        vec![EnrollmentId::from_random_bytes([30; 16])]
    );
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap().state,
        CaState::Active
    );
    // An unknown CA, and a CA already retiring.
    let e = w
        .issuer(
            &attended(),
            IssuerRequest::Retire {
                ca_fingerprint: ca_fp(60),
                deleted_locator: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::NotFound);
}

/// `RetireIssuer` through its decision: a denial leaves the CA `active`; an approval
/// moves it to `retiring` in the decide transaction (new reservations refused
/// `ca_retiring`), then the child is asked to unload it (`retiring → unloaded`). The
/// store item's deletion is the owner-present CLI's (§17.22 item 12), confirmed
/// against this installation's recorded locator, and none is recorded here: the CA
/// stays `unloaded`, and the supervision pass leaves it there (nothing deleted).
#[tokio::test]
async fn issuer_retire_through_decision_approve_and_deny() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(
        30,
        1,
        &pair("a30", "deploy"),
        EnrollmentState::Abandoned,
    ));
    let retire = IssuerRequest::Retire {
        ca_fingerprint: ca_fp(1),
        deleted_locator: None,
    };
    let d = decision_of(&w.issuer(&attended(), retire.clone()).await.unwrap_err());
    // Joined, not duplicated.
    assert_eq!(
        decision_of(&w.issuer(&unattended(), retire.clone()).await.unwrap_err()),
        d
    );
    w.decide(&d, Verdict::Deny).await.unwrap();
    assert_eq!(w.decision(&d).state, DecisionState::Denied);
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap().state,
        CaState::Active
    );
    assert!(w.issuer.unloads.lock().unwrap().is_empty());

    let d = decision_of(&w.issuer(&attended(), retire.clone()).await.unwrap_err());
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(w.decision(&d).state, DecisionState::Approved);
    assert_eq!(*w.issuer.unloads.lock().unwrap(), vec![ca_fp(1)]);
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap().state,
        CaState::Unloaded,
        "unloaded; the store item is never deleted without its recorded locator"
    );
    w.ops.issuer_supervision_pass().await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap().state,
        CaState::Unloaded
    );
    // ⟨§17.22 item 12⟩ Its retirement waits at `unloaded`: a second retire answers
    // the status (naming the store item to delete; none recorded here), writing
    // nothing.
    let before = w.snapshot();
    let s: IssuerStatus =
        serde_json::from_value(w.issuer(&attended(), retire).await.unwrap()).unwrap();
    assert_eq!(s.cas[0].state, CaState::Unloaded);
    assert_eq!(s.cas[0].store_locator, None);
    assert_eq!(w.snapshot(), before);
    // A CA still `retiring` refuses a second retire, writing nothing.
    w.register_ca(2, CaState::Active);
    w.tx(|tx| {
        tx.set_issuer_state(&ca_fp(2), CaState::Active, CaEvent::RetireApproved, t0())
            .map(|r| r.map(|_| ()).unwrap())
    });
    let before = w.snapshot();
    let e = w
        .issuer(
            &attended(),
            IssuerRequest::Retire {
                ca_fingerprint: ca_fp(2),
                deleted_locator: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(w.snapshot(), before);
}

/// A scratch directory created owner-only explicitly (the devbox umask is 002).
fn owner_only_dir(parent: &std::path::Path, name: &str) -> std::path::PathBuf {
    let dir = parent.join(name);
    std::fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// One OS store shared by two installations of the same OS user, over two testkit
/// `ScratchSecretStore`s (`own`: this installation's, where `put` and `get` go;
/// `other`: another installation's), labelled with the product kind the CA records
/// register (`linux_secret_service`) so the owner-present CLI's deletion
/// (`retire::delete_awaiting`, which matches a product kind exactly; a bare test kind is
/// deleted by exact locator only in debug builds, §17.25 item 7 (d)) runs over real
/// scratch files. Like a shared platform store, its `list` reports **both** installations'
/// items and its `delete` deletes whichever item the exact locator names: only the
/// exactness of the recorded locator keeps the other installation's item. No platform
/// store is touched: no native store claim is closed here.
struct SharedScratch {
    own: ScratchSecretStore,
    other: ScratchSecretStore,
}

impl SharedScratch {
    const KIND: SecretStoreKind = SecretStoreKind::Product(StoreKind::LinuxSecretService);

    fn relabel(item: StoreItemRef, kind: SecretStoreKind) -> StoreItemRef {
        StoreItemRef { kind, ..item }
    }
}

impl SecretStore for SharedScratch {
    fn kind(&self) -> SecretStoreKind {
        Self::KIND
    }
    fn availability(&self) -> StoreAvailability {
        self.own.availability()
    }
    fn put(&self, fp: &CaFingerprint, key: &SecretCaKey) -> Result<StoreItemRef, ScratchError> {
        self.own.put(fp, key).map(|i| Self::relabel(i, Self::KIND))
    }
    fn get(&self, fp: &CaFingerprint) -> Result<SecretCaKey, ScratchError> {
        self.own.get(fp)
    }
    fn delete(&self, item: &StoreItemRef) -> Result<(), ScratchError> {
        if item.kind != Self::KIND {
            return Err(ScratchError::Failed);
        }
        for inner in [&self.own, &self.other] {
            let exact = Self::relabel(item.clone(), inner.kind());
            if inner.list()?.contains(&exact) {
                return inner.delete(&exact);
            }
        }
        Err(ScratchError::NotFound)
    }
    fn list(&self) -> Result<Vec<StoreItemRef>, ScratchError> {
        let mut items = self.own.list()?;
        items.extend(self.other.list()?);
        Ok(items
            .into_iter()
            .map(|i| Self::relabel(i, Self::KIND))
            .collect())
    }
}

/// A CA record for a real generated key (`key`'s public line and fingerprint).
fn issuer_record_for(key: &SecretCaKey, state: CaState) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: key.fingerprint().unwrap(),
        public_key: key.public_openssh().unwrap(),
        state,
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: digest(1),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: t0(),
        retired_at: None,
    }
}

/// `issuer.register` for a real generated key (`key`), optionally carrying the store
/// item report (`store_locator`) and a restore's expected locator.
fn register_key_req(
    key: &SecretCaKey,
    store_locator: Option<&str>,
    expected_store_locator: Option<&str>,
) -> IssuerRequest {
    serde_json::from_value(serde_json::json!({
        "action": "register",
        "ca_public_key": key.public_openssh().unwrap(),
        "store": "linux_secret_service",
        "backup_sha256": digest(1),
        "backup_created_at": t0(),
        "store_locator": store_locator,
        "expected_store_locator": expected_store_locator,
    }))
    .unwrap()
}

/// `issuer.register` of the synthetic CA `n` with a store item report and a
/// restore's expected locator (and, for the refusals, a rotation or a key-only
/// restore).
fn register_report(
    n: u8,
    store_locator: Option<&str>,
    expected_store_locator: Option<&str>,
    rotation_of: Option<CaFingerprint>,
    restored_without_log: bool,
) -> IssuerRequest {
    serde_json::from_value(serde_json::json!({
        "action": "register",
        "ca_public_key": ca_line(n),
        "store": "linux_secret_service",
        "backup_sha256": digest(n),
        "backup_created_at": t0(),
        "rotation_of": rotation_of,
        "restored_without_log": restored_without_log,
        "store_locator": store_locator,
        "expected_store_locator": expected_store_locator,
    }))
    .unwrap()
}

fn confirm_deleted(ca: &CaFingerprint, locator: &str) -> IssuerRequest {
    IssuerRequest::Retire {
        ca_fingerprint: ca.clone(),
        deleted_locator: Some(locator.to_owned()),
    }
}

fn status_of(v: serde_json::Value) -> IssuerStatus {
    serde_json::from_value(v).unwrap()
}

/// ⟨ADR-0008 §17.22 item 12 (R2B-Q1)⟩ The ceremony reports the K_ca store item on
/// `issuer.register` after its put: the same registration with `store_locator` joins
/// the pending `RegisterIssuer` decision and is recorded on it once (the same report
/// again, or the registration without it, joins; another item is refused, writing
/// nothing); the approval records the CA **with** that locator, and `issuer.status`
/// names it. A malformed locator is refused before any record.
#[tokio::test]
async fn issuer_register_store_locator_report_recorded_with_approval() {
    let w = World::new().await;
    let d = decision_of(
        &w.issuer(&attended(), register_req(1, None))
            .await
            .unwrap_err(),
    );
    let reported = register_report(1, Some("/org/fixture/item/1"), None, None, false);
    assert_eq!(
        decision_of(&w.issuer(&attended(), reported.clone()).await.unwrap_err()),
        d,
        "the report joins the pending registration"
    );
    let DecisionKind::RegisterIssuer { store_locator, .. } = &w.decision(&d).kind else {
        panic!();
    };
    assert_eq!(store_locator.as_deref(), Some("/org/fixture/item/1"));
    assert_eq!(
        decision_of(&w.issuer(&attended(), reported).await.unwrap_err()),
        d
    );
    assert_eq!(
        decision_of(
            &w.issuer(&attended(), register_req(1, None))
                .await
                .unwrap_err()
        ),
        d
    );
    let before = w.snapshot();
    let e = w
        .issuer(
            &attended(),
            register_report(1, Some("/org/fixture/item/2"), None, None, false),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    for bad in ["", "line\nbreak"] {
        let e = w
            .issuer(
                &attended(),
                register_report(1, Some(bad), None, None, false),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::UsageError, "{bad:?}");
    }
    assert_eq!(w.snapshot(), before, "nothing written by a refused report");
    assert_eq!(w.tx(|tx| tx.pending_decisions()).len(), 1, "one record");

    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap().state,
        CaState::Active
    );
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))).as_deref(),
        Some("/org/fixture/item/1"),
        "recorded with the approval"
    );
    let s = status_of(w.issuer(&attended(), IssuerRequest::Status).await.unwrap());
    assert_eq!(
        s.cas[0].store_locator.as_deref(),
        Some("/org/fixture/item/1")
    );
    assert!(s.orphan_store_items.is_empty());
}

/// The pending `RegisterIssuer` record of `d`, encoded as the store writes it, and
/// the world's snapshot: what a refused report must leave byte-identical.
fn pending_bytes(w: &World, d: &DecisionId) -> (String, String) {
    (serde_json::to_string(&w.decision(d)).unwrap(), w.snapshot())
}

/// `req` (an `issuer.register` built by [`register_report`]) with `field` replaced.
fn with_field(req: &IssuerRequest, field: &str, v: serde_json::Value) -> IssuerRequest {
    let mut j = serde_json::to_value(req).unwrap();
    j[field] = v;
    serde_json::from_value(j).unwrap()
}

/// ⟨ADR-0008 §17.23 item 3 (R3B-Q2 (a))⟩ The store-item report (the second
/// `issuer.register`, after the put) must repeat the pending registration's facts
/// **exactly**: a report differing in any one fact (public key/fingerprint, store
/// kind, backup digest, backup time, rotation, key-only restore, expected locator)
/// is refused, creating no decision and leaving the pending one byte-identical —
/// `CONFIG_CONFLICT` when a registration of that CA is pending with other facts,
/// `DECISION_STALE` when none is (another key: a report never creates a
/// registration), `CONFIG_CONFLICT` for an expected locator on an unregistered CA.
/// The same refusals hold after the exact report attached its locator.
#[tokio::test]
async fn issuer_register_store_locator_report_must_repeat_every_fact() {
    let w = World::new().await;
    // The rotation variant needs an `active` CA to rotate (else NOT_FOUND first).
    w.register_ca(2, CaState::Active);
    let d = decision_of(
        &w.issuer(&attended(), register_req(1, None))
            .await
            .unwrap_err(),
    );
    let report = register_report(1, Some("/org/fixture/item/1"), None, None, false);
    let differing = [
        (
            "public key (another fingerprint)",
            with_field(&report, "ca_public_key", serde_json::json!(ca_line(3))),
            Code::DecisionStale,
        ),
        (
            "store kind",
            with_field(&report, "store", serde_json::json!("windows_dpapi")),
            Code::ConfigConflict,
        ),
        (
            "backup digest",
            with_field(&report, "backup_sha256", serde_json::json!(digest(9))),
            Code::ConfigConflict,
        ),
        (
            "backup time",
            with_field(
                &report,
                "backup_created_at",
                serde_json::json!(shift(t0(), 1)),
            ),
            Code::ConfigConflict,
        ),
        (
            "rotation",
            register_report(1, Some("/org/fixture/item/1"), None, Some(ca_fp(2)), false),
            Code::ConfigConflict,
        ),
        (
            "key-only restore",
            register_report(1, Some("/org/fixture/item/1"), None, None, true),
            Code::ConfigConflict,
        ),
        (
            "expected locator",
            register_report(
                1,
                Some("/org/fixture/item/1"),
                Some("/org/fixture/item/0"),
                None,
                false,
            ),
            Code::ConfigConflict,
        ),
    ];
    let refuse_all = |phase: &'static str| {
        let w = &w;
        let d = &d;
        let differing = &differing;
        async move {
            for (why, req, want) in differing {
                let before = pending_bytes(w, d);
                let e = w.issuer(&attended(), req.clone()).await.unwrap_err();
                assert_eq!(e.code, *want, "{phase}: {why}: {e:?}");
                assert_eq!(
                    pending_bytes(w, d),
                    before,
                    "{phase}: {why}: nothing created or changed"
                );
                assert_eq!(w.tx(|tx| tx.pending_decisions()).len(), 1, "{phase}: {why}");
            }
        }
    };
    refuse_all("before the report").await;
    let DecisionKind::RegisterIssuer { store_locator, .. } = &w.decision(&d).kind else {
        panic!();
    };
    assert_eq!(*store_locator, None, "nothing attached by a refused report");

    assert_eq!(
        decision_of(&w.issuer(&attended(), report).await.unwrap_err()),
        d,
        "the exact report joins"
    );
    refuse_all("after the report").await;
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))).as_deref(),
        Some("/org/fixture/item/1")
    );
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(3))),
        None,
        "no other CA registered"
    );
}

/// ⟨ADR-0008 §17.23 item 3⟩ The report attaches the locator **once**: the same
/// locator again is an idempotent answer naming the same decision with the record
/// byte-identical; a second **different** locator is refused `CONFIG_CONFLICT`,
/// leaving the record (and its first locator) byte-identical; the approval records
/// the first locator.
#[tokio::test]
async fn issuer_register_store_locator_report_attaches_once() {
    let w = World::new().await;
    let d = decision_of(
        &w.issuer(&attended(), register_req(1, None))
            .await
            .unwrap_err(),
    );
    let first = register_report(1, Some("/org/fixture/item/1"), None, None, false);
    assert_eq!(
        decision_of(&w.issuer(&attended(), first.clone()).await.unwrap_err()),
        d
    );
    let attached = pending_bytes(&w, &d);
    for n in 0..2 {
        let e = w.issuer(&attended(), first.clone()).await.unwrap_err();
        assert_eq!(e.code, Code::ApprovalRequired, "{n}: {e:?}");
        assert_eq!(decision_of(&e), d, "{n}: idempotent");
        assert_eq!(pending_bytes(&w, &d), attached, "{n}: unchanged");
    }
    let e = w
        .issuer(
            &attended(),
            register_report(1, Some("/org/fixture/item/2"), None, None, false),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    assert_eq!(
        pending_bytes(&w, &d),
        attached,
        "the second locator wrote nothing"
    );
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))).as_deref(),
        Some("/org/fixture/item/1")
    );
}

/// ⟨ADR-0008 §17.22 item 12 (R2B-Q2); D3⟩ Retirement with a real scratch store item:
/// after the child unloads K the CA stops at `unloaded`, **awaiting the deletion of
/// its recorded locator**, and nothing deletes it (the runtime holds no store
/// handle, the child only reads): the item still exists and reads after the
/// approval, the supervision pass and a resume. `issuer.status` and `retire` name the
/// locator. A confirmation is refused, changing nothing, unattended, before the
/// unload, and with another locator (the other installation's item of the same CA).
/// The owner-present CLI's deletion (`retire::delete_awaiting`) deletes exactly that
/// item; the confirmation with it reaches `retired` (once more: idempotent). The
/// other installation's item survives.
#[tokio::test]
async fn ca_retirement_waits_unloaded_for_the_owner_deletion_confirmation() {
    let w = World::new().await;
    let scratch = tempfile::tempdir().unwrap();
    let a = Arc::new(SharedScratch {
        own: ScratchSecretStore::new(owner_only_dir(scratch.path(), "a")),
        other: ScratchSecretStore::new(owner_only_dir(scratch.path(), "b")),
    });
    let b = ScratchSecretStore::new(a.other.dir());
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    // The ceremony: register, put, report, approve.
    let d = decision_of(
        &w.issuer(&attended(), register_key_req(&key, None, None))
            .await
            .unwrap_err(),
    );
    let a_item = a.put(&fp, &key).unwrap();
    let b_item = b.put(&fp, &key).unwrap();
    assert_ne!(a_item.locator, b_item.locator);
    assert_eq!(
        decision_of(
            &w.issuer(
                &attended(),
                register_key_req(&key, Some(&a_item.locator), None)
            )
            .await
            .unwrap_err()
        ),
        d
    );
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&fp)),
        Some(a_item.locator.clone())
    );
    // Before the unload: refused, nothing changes.
    let before = w.snapshot();
    let e = w
        .issuer(&attended(), confirm_deleted(&fp, &a_item.locator))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    assert_eq!(w.snapshot(), before);

    let d = decision_of(
        &w.issuer(
            &attended(),
            IssuerRequest::Retire {
                ca_fingerprint: fp.clone(),
                deleted_locator: None,
            },
        )
        .await
        .unwrap_err(),
    );
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(*w.issuer.unloads.lock().unwrap(), vec![fp.clone()]);
    assert_eq!(w.tx(|tx| tx.issuer(&fp)).unwrap().state, CaState::Unloaded);
    w.ops.issuer_supervision_pass().await.unwrap();
    let report = w
        .ops
        .resume_ca_retirements(Some(w.issuer.as_ref()))
        .await
        .unwrap();
    assert_eq!(
        report.stalled,
        vec![(
            fp.clone(),
            CaState::Unloaded,
            AWAITING_OWNER_DELETION.to_owned()
        )]
    );
    assert_eq!(w.tx(|tx| tx.issuer(&fp)).unwrap().state, CaState::Unloaded);
    assert!(
        a.list().unwrap().contains(&a_item) && a.get(&fp).unwrap().same_key(&key),
        "neither the runtime nor the child deleted the store item"
    );
    // The status, and `retire` itself, name the locator to delete.
    for req in [
        IssuerRequest::Status,
        IssuerRequest::Retire {
            ca_fingerprint: fp.clone(),
            deleted_locator: None,
        },
    ] {
        let s = status_of(w.issuer(&attended(), req).await.unwrap());
        let c = s.cas.iter().find(|c| c.fingerprint == fp).unwrap();
        assert_eq!(c.state, CaState::Unloaded);
        assert_eq!(c.store_locator.as_deref(), Some(a_item.locator.as_str()));
    }
    // Unattended, another locator, a malformed one: refused, nothing changes.
    let before = w.snapshot();
    let e = w
        .issuer(&unattended(), confirm_deleted(&fp, &a_item.locator))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    let e = w
        .issuer(&attended(), confirm_deleted(&fp, &b_item.locator))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    let e = w
        .issuer(&attended(), confirm_deleted(&ca_fp(60), &a_item.locator))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::NotFound);
    let e = w
        .issuer(&attended(), confirm_deleted(&fp, ""))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::UsageError);
    assert_eq!(w.snapshot(), before);
    assert_eq!(w.tx(|tx| tx.issuer(&fp)).unwrap().state, CaState::Unloaded);
    assert!(a.list().unwrap().contains(&a_item), "still there");

    // The owner-present CLI deletes exactly the named item, then confirms.
    retire::delete_awaiting(
        a.as_ref(),
        &fp,
        StoreKind::LinuxSecretService,
        &a_item.locator,
    )
    .unwrap();
    assert_eq!(a.get(&fp).err(), Some(ScratchError::NotFound));
    assert_eq!(b.list().unwrap(), vec![b_item.clone()]);
    let s = status_of(
        w.issuer(&attended(), confirm_deleted(&fp, &a_item.locator))
            .await
            .unwrap(),
    );
    assert_eq!(
        s.cas.iter().find(|c| c.fingerprint == fp).unwrap().state,
        CaState::Retired
    );
    let record = w.tx(|tx| tx.issuer(&fp)).unwrap();
    assert_eq!(record.state, CaState::Retired);
    assert!(record.retired_at.is_some());
    w.issuer(&attended(), confirm_deleted(&fp, &a_item.locator))
        .await
        .unwrap();
    assert_eq!(w.tx(|tx| tx.issuer(&fp)).unwrap().state, CaState::Retired);
    assert!(
        b.get(&fp).unwrap().same_key(&key),
        "the other installation's item"
    );
}

/// ⟨ADR-0008 §17.21 item 3, kept by §17.22 item 12⟩ A CA record without a recorded
/// store locator (written before the field, or approved without a report) stops at
/// `unloaded`, reported `issuer_store_locator_unrecorded`, with **nothing deleted**;
/// no locator can be confirmed for it (nothing names one). Nothing is guessed.
#[tokio::test]
async fn ca_retirement_without_recorded_locator_stops_unloaded_nothing_deleted() {
    let w = World::new().await;
    let scratch = tempfile::tempdir().unwrap();
    let a = Arc::new(SharedScratch {
        own: ScratchSecretStore::new(owner_only_dir(scratch.path(), "a")),
        other: ScratchSecretStore::new(owner_only_dir(scratch.path(), "b")),
    });
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    let item = a.put(&fp, &key).unwrap();
    w.tx(|tx| tx.insert_issuer(&issuer_record_for(&key, CaState::Active)));
    assert_eq!(w.tx(|tx| tx.issuer_store_locator(&fp)), None);

    let d = decision_of(
        &w.issuer(
            &attended(),
            IssuerRequest::Retire {
                ca_fingerprint: fp.clone(),
                deleted_locator: None,
            },
        )
        .await
        .unwrap_err(),
    );
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(*w.issuer.unloads.lock().unwrap(), vec![fp.clone()]);
    assert_eq!(w.tx(|tx| tx.issuer(&fp)).unwrap().state, CaState::Unloaded);
    let report = w
        .ops
        .resume_ca_retirements(Some(w.issuer.as_ref()))
        .await
        .unwrap();
    assert_eq!(
        report.stalled,
        vec![(
            fp.clone(),
            CaState::Unloaded,
            reason::ISSUER_STORE_LOCATOR_UNRECORDED.to_owned()
        )]
    );
    assert!(report.advanced.is_empty());
    assert!(report.do_not_load.contains(&fp));
    w.ops.issuer_supervision_pass().await.unwrap();
    let s = status_of(w.issuer(&attended(), IssuerRequest::Status).await.unwrap());
    assert_eq!(s.cas[0].store_locator, None);
    let before = w.snapshot();
    let e = w
        .issuer(&attended(), confirm_deleted(&fp, &item.locator))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(w.snapshot(), before);
    assert_eq!(w.tx(|tx| tx.issuer(&fp)).unwrap().state, CaState::Unloaded);
    assert_eq!(a.list().unwrap(), vec![item], "nothing was deleted");
    assert!(a.get(&fp).unwrap().same_key(&key));
}

/// ⟨ADR-0008 §17.22 item 12⟩ A log-intact restore that wrote a new store item
/// re-registers the known CA with `store_locator` and `expected_store_locator`; its
/// approval **compares and swaps** the recorded locator. Refused at the request,
/// writing nothing: the wrong expected locator (and none, while one is recorded), the
/// recorded item again, a rotation, a key-only restore, another backup, and an
/// expected locator for an unknown CA. Refused at the approval, **not consumed**: a
/// second restore decision whose expectation went stale. The displaced item is listed
/// in `orphan_store_items` with its locator and leaves after its deletion
/// confirmation (the same confirmation path; a second one is refused).
#[tokio::test]
async fn issuer_restore_store_locator_compare_and_swap_and_orphan_listing() {
    let w = World::new().await;
    // D4 item 1: the registration (step 3), then the put's report (after step 6).
    let d = decision_of(
        &w.issuer(&attended(), register_req(1, None))
            .await
            .unwrap_err(),
    );
    assert_eq!(
        decision_of(
            &w.issuer(
                &attended(),
                register_report(1, Some("old-1"), None, None, false),
            )
            .await
            .unwrap_err(),
        ),
        d
    );
    w.decide(&d, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))).as_deref(),
        Some("old-1")
    );
    let before = w.snapshot();
    let mut other_backup = serde_json::to_value(register_report(
        1,
        Some("new-1"),
        Some("old-1"),
        None,
        false,
    ))
    .unwrap();
    other_backup["backup_sha256"] = serde_json::json!(digest(9));
    for (why, req) in [
        (
            "wrong expected",
            register_report(1, Some("new-1"), Some("wrong"), None, false),
        ),
        (
            "none expected",
            register_report(1, Some("new-1"), None, None, false),
        ),
        (
            "already recorded",
            register_report(1, Some("old-1"), Some("old-1"), None, false),
        ),
        (
            "no report",
            register_report(1, None, Some("old-1"), None, false),
        ),
        (
            "rotation",
            register_report(1, Some("new-1"), Some("old-1"), Some(ca_fp(2)), false),
        ),
        (
            "key-only restore",
            register_report(1, Some("new-1"), Some("old-1"), None, true),
        ),
        (
            "other backup",
            serde_json::from_value(other_backup).unwrap(),
        ),
        (
            "unknown CA expecting one",
            register_report(5, Some("new-5"), Some("old-5"), None, true),
        ),
    ] {
        let e = w.issuer(&attended(), req).await.unwrap_err();
        assert!(
            matches!(e.code, Code::ConfigConflict | Code::NotFound),
            "{why}: {e:?}"
        );
    }
    assert_eq!(w.snapshot(), before, "nothing written by a refused restore");

    let swap = register_report(1, Some("new-1"), Some("old-1"), None, false);
    let d1 = decision_of(&w.issuer(&attended(), swap.clone()).await.unwrap_err());
    assert_eq!(
        decision_of(&w.issuer(&attended(), swap).await.unwrap_err()),
        d1,
        "joined"
    );
    // Another new item for the same pending restore: refused, writing nothing.
    let before = w.snapshot();
    let e = w
        .issuer(
            &attended(),
            register_report(1, Some("new-2"), Some("old-1"), None, false),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    assert_eq!(w.snapshot(), before);
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))).as_deref(),
        Some("old-1"),
        "nothing executes on dispatch"
    );
    // The recorded locator moves before the approval (another restore's swap): the
    // approval's compare-and-swap refuses, nothing consumed.
    w.tx(|tx| tx.replace_issuer_store_locator(&ca_fp(1), Some("old-1"), "moved-1"));
    let r = w.decide(&d1, Verdict::Approve).await;
    assert_eq!(code(&r), Code::ConfigConflict, "the stale expectation");
    assert_eq!(
        w.decision(&d1).state,
        DecisionState::Pending,
        "not consumed"
    );
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))).as_deref(),
        Some("moved-1")
    );
    let d3 = decision_of(
        &w.issuer(
            &attended(),
            register_report(1, Some("new-1"), Some("moved-1"), None, false),
        )
        .await
        .unwrap_err(),
    );
    w.decide(&d3, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.tx(|tx| tx.issuer_store_locator(&ca_fp(1))).as_deref(),
        Some("new-1")
    );
    let ca = w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap();
    assert_eq!(ca.state, CaState::Active, "the CA itself is unchanged");

    let orphan = |l: &str| heimdall_contract::issuer::OrphanStoreItem {
        fingerprint: Some(ca_fp(1)),
        store: StoreKind::LinuxSecretService,
        locator: Some(l.into()),
    };
    let s = status_of(w.issuer(&attended(), IssuerRequest::Status).await.unwrap());
    assert_eq!(s.cas[0].store_locator.as_deref(), Some("new-1"));
    assert_eq!(
        s.orphan_store_items,
        vec![orphan("old-1"), orphan("moved-1")]
    );
    let s = status_of(
        w.issuer(&attended(), confirm_deleted(&ca_fp(1), "old-1"))
            .await
            .unwrap(),
    );
    assert_eq!(s.orphan_store_items, vec![orphan("moved-1")]);
    let s = status_of(
        w.issuer(&attended(), confirm_deleted(&ca_fp(1), "moved-1"))
            .await
            .unwrap(),
    );
    assert!(s.orphan_store_items.is_empty(), "{s:?}");
    assert_eq!(s.cas[0].state, CaState::Active);
    assert_eq!(s.cas[0].store_locator.as_deref(), Some("new-1"));
    let before = w.snapshot();
    let e = w
        .issuer(&attended(), confirm_deleted(&ca_fp(1), "old-1"))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(w.snapshot(), before);
}

/// The retire precheck refuses an approval with nothing consumed when an enrollment
/// under the CA opened since the decision (the record stays `pending`, the CA
/// `active`).
#[tokio::test]
async fn issuer_retire_refused_not_consumed_when_precheck_fails() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    let d = decision_of(
        &w.issuer(
            &attended(),
            IssuerRequest::Retire {
                ca_fingerprint: ca_fp(1),
                deleted_locator: None,
            },
        )
        .await
        .unwrap_err(),
    );
    w.seed_enrollment(&enrollment(5, 1, &h1(), EnrollmentState::Applying));
    let r = w.decide(&d, Verdict::Approve).await;
    assert_eq!(code(&r), Code::ConfigConflict);
    assert_eq!(w.decision(&d).state, DecisionState::Pending, "not consumed");
    assert_eq!(
        w.tx(|tx| tx.issuer(&ca_fp(1))).unwrap().state,
        CaState::Active
    );
    assert!(w.issuer.unloads.lock().unwrap().is_empty());
    // A newly abandoned enrollment changes the listed set: also refused.
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    let d = decision_of(
        &w.issuer(
            &attended(),
            IssuerRequest::Retire {
                ca_fingerprint: ca_fp(1),
                deleted_locator: None,
            },
        )
        .await
        .unwrap_err(),
    );
    w.seed_enrollment(&enrollment(6, 1, &h1(), EnrollmentState::Abandoned));
    assert_eq!(
        code(&w.decide(&d, Verdict::Approve).await),
        Code::DecisionStale
    );
    assert_eq!(w.decision(&d).state, DecisionState::Pending);
}

// =================================================================================
// Unlock
// =================================================================================

/// D4 item 2, §17.17 item 10 (U4-Q2(b)): `issuer unlock` reloads through the
/// lifecycle and **reports** a locked store (`issuer_store_locked`, with how to unlock
/// it) without ever triggering a prompt; attended sessions only; with no CA it is
/// `issuer_not_initialized` and reloads nothing.
#[tokio::test]
async fn issuer_unlock_reports_locked_store_never_prompts() {
    let w = World::new().await;
    let e = w
        .issuer(&attended(), IssuerRequest::Unlock)
        .await
        .unwrap_err();
    assert_eq!(
        reason_of(&e).as_deref(),
        Some(reason::ISSUER_NOT_INITIALIZED)
    );
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 0);
    w.register_ca(1, CaState::Active);
    let e = w
        .issuer(&unattended(), IssuerRequest::Unlock)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 0);

    *w.issuer.reload_answer.lock().unwrap() =
        Err(IssuerError::Unavailable(reason::ISSUER_STORE_LOCKED.into()));
    let e = w
        .issuer(&attended(), IssuerRequest::Unlock)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(reason_of(&e).as_deref(), Some(reason::ISSUER_STORE_LOCKED));
    assert!(e.message.contains("never shows"), "{}", e.message);
    assert!(
        e.message.contains("heimdall issuer unlock"),
        "{}",
        e.message
    );
    assert_eq!(w.issuer.reloads.load(Ordering::SeqCst), 1);

    *w.issuer.reload_answer.lock().unwrap() = Ok(());
    let s: IssuerStatus =
        serde_json::from_value(w.issuer(&attended(), IssuerRequest::Unlock).await.unwrap())
            .unwrap();
    assert_eq!(s.state, IssuerState::Ready);
    assert_eq!(s.cas.len(), 1);
}

// =================================================================================
// Bundle
// =================================================================================

/// D4 item 5: `issuer.bundle` is public metadata only (CA public keys, digests, the
/// enrollment records), with hostnames and ports unless redacted; a redacted bundle
/// carries none of them and says foreign removal refuses it.
#[tokio::test]
async fn issuer_bundle_redacts_hostnames() {
    let w = World::new().await;
    w.register_ca(1, CaState::Active);
    w.seed_enrollment(&enrollment(1, 1, &h1(), EnrollmentState::Verified));
    let full: RecoveryBundle = serde_json::from_value(
        w.issuer(
            &attended(),
            IssuerRequest::Bundle {
                redact_hostnames: false,
            },
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        full.schema,
        heimdall_contract::issuer::RECOVERY_BUNDLE_SCHEMA
    );
    assert!(!full.redacted);
    assert_eq!(full.cas.len(), 1);
    assert_eq!(full.cas[0].public_key, ca_line(1));
    let e = &full.enrollments[0];
    assert_eq!(e.hostname.as_deref(), Some("h1.secret-host.invalid"));
    assert_eq!(e.port, Some(2222));
    assert_eq!(
        e.alias, "h1",
        "no catalog entry: the destination ID labels it"
    );
    assert_eq!(e.ca_public_key, ca_line(1));

    let raw = w
        .issuer(
            &attended(),
            IssuerRequest::Bundle {
                redact_hostnames: true,
            },
        )
        .await
        .unwrap();
    let text = raw.to_string();
    assert!(!text.contains("secret-host"), "{text}");
    let first = raw["enrollments"][0].as_object().unwrap();
    assert!(
        !first.contains_key("hostname") && !first.contains_key("port"),
        "{text}"
    );
    let redacted: RecoveryBundle = serde_json::from_value(raw).unwrap();
    assert!(redacted.redacted);
    assert_eq!(redacted.enrollments[0].hostname, None);
    assert_eq!(redacted.enrollments[0].port, None);
    assert!(
        redacted
            .instructions
            .iter()
            .any(|i| i.contains("bundle_redacted"))
    );
    assert_eq!(redacted.enrollments[0].marker, full.enrollments[0].marker);
}

// =================================================================================
// Supervision
// =================================================================================

/// The supervision pass starts a child that was never started once a CA is
/// registered, and never one that was stopped (§17.19 item 3).
#[tokio::test]
async fn issuer_supervision_starts_unstarted_child_never_a_stopped_one() {
    let w = World::new().await;
    w.ops.issuer_supervision_pass().await.unwrap();
    assert_eq!(
        w.issuer.starts.load(Ordering::SeqCst),
        0,
        "no CA: nothing to start"
    );
    w.register_ca(1, CaState::Active);
    w.ops.issuer_supervision_pass().await.unwrap();
    assert_eq!(w.issuer.starts.load(Ordering::SeqCst), 1);
    IssuerLifecycle::stop(w.issuer.as_ref()).await;
    w.ops.issuer_supervision_pass().await.unwrap();
    assert_eq!(
        w.issuer.starts.load(Ordering::SeqCst),
        1,
        "a stopped child stays stopped"
    );
}

// =================================================================================
// INT-Q13: the verification signing gate (ADR-0008 §17.19 item 5)
// =================================================================================

const KVERIFY: &str = "SHA256:kverify0000000000000000000000000000000000";

/// An `enrollment.verify` (presence) operation for enrollment `n` (CA 1, h1),
/// `running`, its enrollment `verifying`, one attempt started.
fn seed_verify_operation(w: &World, n: u8) -> (OperationId, EnrollmentId) {
    let e = enrollment(n, 1, &h1(), EnrollmentState::Verifying);
    let op_id = OperationId::from_random_bytes([n; 16]);
    let key = IdempotencyKey {
        caller: ctx(ClientRole::Owner),
        kind: OperationKind::EnrollmentVerify,
        request_id: RequestId::parse(&format!("verify-{n}")).unwrap(),
    };
    let now = w.clock.wall();
    let op = OperationRecord {
        id: op_id.clone(),
        kind: OperationKind::EnrollmentVerify,
        environment: env_id(),
        key: key.clone(),
        request_hash: RequestHash([n; 32]),
        effect_class: EffectClass::Local,
        state: OperationState::Running,
        code: None,
        effect_status: heimdall_contract::envelope::EffectStatus::None,
        result: None,
        created_at: now,
        updated_at: now,
        cancellation: None,
        recovery: RecoveryMetadata::default(),
    };
    let request = Request::Enrollment(EnrollmentRequest::Verify {
        enrollment_id: e.id.clone(),
        request_id: key.request_id.clone(),
        mode: VerifyMode::Presence,
        wait: WaitMode::Async,
    });
    w.tx(|tx| {
        if tx.issuer(&ca_fp(1))?.is_none() {
            tx.insert_issuer(&issuer_record(1, CaState::Active))?;
        }
        tx.seed_enrollment(&e)?;
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
        tx.append_stage_receipt(
            &op_id,
            &StageReceipt {
                stage: enrollment_stage::VERIFY_STARTED.into(),
                recorded_at: now,
                effect: EffectReceipt::NotAttempted,
                local: None,
            },
        )
    });
    (op_id, e.id)
}

/// Reserve and publish the positive verification entry of `op` for K_verify.
async fn publish_positive(w: &World, op: &OperationId, enrollment: &EnrollmentId) -> IssuanceId {
    let id = reserve_positive(w, op, enrollment).await;
    w.ops
        .publish_verification(&id, true)
        .await
        .unwrap()
        .unwrap();
    id
}

/// Reserve (only) the positive verification entry of `op` for K_verify.
async fn reserve_positive(w: &World, op: &OperationId, enrollment: &EnrollmentId) -> IssuanceId {
    let now = w.clock.wall();
    let entry = w
        .ops
        .reserve_verification(VerificationRequest {
            operation: op.clone(),
            enrollment: enrollment.clone(),
            pair: h1(),
            ca_fingerprint: ca_fp(1),
            purpose: VerificationPurpose::Positive,
            principal: "hm:h1:deploy".into(),
            key_id: "verify-key".into(),
            valid_after: shift(now, -60),
            valid_before: shift(now, 240),
            extensions: Default::default(),
            subject_fingerprint: KVERIFY.into(),
            subject_registered: true,
        })
        .await
        .unwrap()
        .unwrap();
    entry.id
}

fn vfacts(
    op: &OperationId,
    endpoint_op: &OperationId,
    p: &AccessPair,
    key: &str,
) -> SignatureRequestFacts {
    SignatureRequestFacts {
        endpoint: SignerEndpoint::Verification(endpoint_op.clone()),
        subject: SignatureSubject::Verification(op.clone()),
        pair: p.clone(),
        key_fingerprint: key.to_owned(),
    }
}

fn scope(ca: u8, p: &AccessPair) -> VerificationScope {
    VerificationScope {
        ca: ca_fp(ca),
        pair: p.clone(),
    }
}

/// INT-Q13 option (a): a verification signature is admitted **only** with a permit
/// from its own operation's verification gate and the D5 §6.5 predicate under it:
/// refused before the gate opens (before `create`); admitted while it is open, for the
/// operation's published positive entry under the plan's CA and pair; refused for a
/// gate opened with another CA or pair, another operation's endpoint, another pair or
/// key; and after the gate closes (the session's drop), new admissions are refused and
/// an admitted permit's release is refused. No ungated path exists.
#[tokio::test]
async fn verification_signature_admitted_only_through_its_operation_gate() {
    const { assert!(!heimdall_credential::signer::VERIFICATION_UNGATED_SIGNING) };
    let w = World::new().await;
    let (op, enr) = seed_verify_operation(&w, 7);
    publish_positive(&w, &op, &enr).await;
    let gates = w.ops.signing_gates().clone();
    let facts = vfacts(&op, &op, &h1(), KVERIFY);
    // Before the session's create: no gate.
    assert_eq!(w.ops.precheck(&facts).await, Err(SignRefusal::KeyNotServed));
    assert_eq!(
        w.ops.admit(&facts).await.unwrap_err(),
        SignRefusal::KeyNotServed
    );

    // A gate opened with another CA or another pair admits nothing for this plan.
    for wrong in [scope(2, &h1()), scope(1, &pair("h2", "deploy"))] {
        let g = gates.open_verification(&op, wrong.clone()).unwrap();
        assert_eq!(
            w.ops.admit(&facts).await.unwrap_err(),
            SignRefusal::KeyNotServed,
            "{wrong:?}"
        );
        drop(g);
    }

    let gate = gates.open_verification(&op, scope(1, &h1())).unwrap();
    w.ops.precheck(&facts).await.unwrap();
    let permit = w.ops.admit(&facts).await.unwrap();
    assert_eq!(permit.verification(), Some(&op));
    assert_eq!(permit.grant(), None);
    assert!(permit.may_release());
    assert!(
        permit.expires_wall() <= shift(w.clock.wall(), 240),
        "bounded by valid_before"
    );
    // Another operation's endpoint, another pair, another key: refused.
    let other = OperationId::from_random_bytes([0x99; 16]);
    for bad in [
        vfacts(&op, &other, &h1(), KVERIFY),
        vfacts(&op, &op, &pair("h2", "deploy"), KVERIFY),
        vfacts(&op, &op, &h1(), "SHA256:another"),
    ] {
        assert_eq!(
            w.ops.admit(&bad).await.unwrap_err(),
            SignRefusal::KeyNotServed,
            "{bad:?}"
        );
    }
    // The session drops: the gate closes.
    drop(gate);
    assert_eq!(
        permit.release_refusal_at(Some(w.clock.wall()), tokio::time::Instant::now()),
        Some(ReleaseRefusal::VerificationClosed)
    );
    assert!(!permit.may_release());
    drop(permit);
    assert_eq!(
        w.ops.admit(&facts).await.unwrap_err(),
        SignRefusal::KeyNotServed
    );
    assert_eq!(w.ops.precheck(&facts).await, Err(SignRefusal::KeyNotServed));
}

/// INT-Q13: with the gate open, the D5 §6.5 predicate decides: an entry only reserved
/// (not published) refuses; an operation no longer at its verification stage (no longer
/// running) refuses `verification_refused(operation_not_verifying)`.
#[tokio::test]
async fn verification_signature_refused_unless_operation_is_verifying() {
    let w = World::new().await;
    let (op, enr) = seed_verify_operation(&w, 8);
    let gates = w.ops.signing_gates().clone();
    let _gate = gates.open_verification(&op, scope(1, &h1())).unwrap();
    let facts = vfacts(&op, &op, &h1(), KVERIFY);
    let id = reserve_positive(&w, &op, &enr).await;
    assert_eq!(
        w.ops.admit(&facts).await.unwrap_err(),
        SignRefusal::KeyNotServed,
        "reserved, not published"
    );
    w.ops
        .publish_verification(&id, true)
        .await
        .unwrap()
        .unwrap();
    w.ops.admit(&facts).await.unwrap();
    // The operation is no longer running (its verification stage ended).
    w.tx(|tx| {
        let mut o = tx.operation(&op)?.unwrap();
        o.state = OperationState::Failed;
        tx.update_operation(&o)
    });
    assert_eq!(
        w.ops.admit(&facts).await.unwrap_err(),
        SignRefusal::Verification(VerificationRefusal::OperationNotVerifying)
    );
}
