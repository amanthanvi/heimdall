//! M03 wave 2 (U3): the issuer child, its protocol, the client and the read-only
//! check (m03-plan U3 "Tests"; ADR-0008 D3, D4 item 3, §17.1 item 12, §17.15 item 8).
//!
//! **Harness.** A state database in a scratch directory, seeded through the production
//! store and driven by the production `heimdall_app::Operations` (the
//! `tests/model/operations_m03.rs` pattern: `VirtualClock`, `ScriptedTimeSync`, the
//! testkit's `FakeCredentialAdapter` recording `managed_certificate`). The CA is a real
//! K_ca generated per run and kept in a per-run `ScratchSecretStore`; subject keys are
//! K_env keys of a per-run `KeyVault` (only their public lines leave it). Reservations
//! are made through `Operations::reserve_issuance`, except the ceiling cases, whose
//! entries are forced in with a test-only store write.
//!
//! **The child** runs in process (`child::run` on a thread, over two OS pipes) for the
//! protocol cases, and as a real process for the client and supervision cases (Unix:
//! this test binary re-executed through `/bin/sh`, which moves libtest's own stdout to
//! `/dev/null` and hands the protocol pipe to the child as descriptor 3). Processes are
//! ended only by the exact PID this test started. Nothing here touches an owner key,
//! agent, keychain or store.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::issuance_ro;
use heimdall_app::operations::{
    IssuanceFacts, IssuanceRequest, Limits, MANAGED_CERTIFICATE, Publication,
};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, IssuerError, IssuerPort,
    LockContinuity, PrepareOutcome,
};
use heimdall_app::timegate::TimeGate;
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DestinationId, DeviceId, EnrollmentId, EnvironmentId, GrantId,
    IdentityId, IssuanceId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, IssuerState, StoreKind};
use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, EnsureRequest, ExistingConnectionsPolicy,
    InteractionMode, NewAuthenticationExpiry, RefreshDependency, RequiredCapabilities,
    RevocationStatus, WaitMode, WorkloadIsolation,
};
use heimdall_credential::cert::{SecretCaKey, validate_installed};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::issuance::{
    CaEvent, CertificateBounds, EXTENSION_PTY, IssuanceEntry, IssuanceRefusal, IssuanceState,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy, TimeStatus, TimeUncertainty};
use heimdall_issuer::child::{self, EXIT_PROTOCOL};
use heimdall_issuer::client::{ChildCommand, ChildIssuer, ClientConfig, Jitter, backoff_ceiling};
use heimdall_issuer::protocol::{
    IssuanceRef, IssuanceTable, IssuerRefusal, LoadedCa, MAX_FRAME_BYTES, PROTOCOL, Request,
    Response, split_frame,
};
use heimdall_issuer::store::{SecretStore, StoreAvailability};
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::scratch_store::ScratchSecretStore;
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock};

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-02T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    Timestamp::from_second(t.as_second() + secs).unwrap()
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
        usable_until: shift(t0(), 12 * 3600),
        offline_until: shift(t0(), 3600),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
    }
}

fn descriptor() -> AdapterDescriptor {
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
    }
}

fn policy(pause: PauseState, cutoff_at: Option<Timestamp>, revision: u64) -> StandingPolicy {
    StandingPolicy {
        id: PolicyId::parse("pol").unwrap(),
        revision: PolicyRevision(revision),
        profile: ProfileId::parse("dev").unwrap(),
        workspace: None,
        scope: Scope {
            pairs: [h1(), pair("h2", "deploy")].into_iter().collect(),
            capabilities: ssh_only(),
        },
        environments: [env_id()].into_iter().collect(),
        max_window: 2 * HOUR,
        pause,
        cutoff_at,
        source: PolicySource::SetupDefault,
        lock_behavior: LockBehavior::Continue,
        connection: ConnectionPolicy::default(),
    }
}

fn environment_record() -> EnvironmentRecord {
    EnvironmentRecord {
        id: env_id(),
        device: DeviceId::from_random_bytes([8; 16]),
        kind: EnvironmentKind::NativeSession,
        label: None,
        permissions: EnvironmentPermissions {
            automatic_activation: true,
            managed_signing: true,
            issuer_access: true,
        },
    }
}

fn enrollment(ca: &CaFingerprint, p: &AccessPair) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([1; 16]);
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
    }
}

/// The issuer's facts, used for every reservation so reserve, publish and the issuer
/// judge the same request (U3-Q2: the issuer reads every entry as a new activation).
fn facts() -> IssuanceFacts {
    issuance_ro::ISSUER_FACTS
}

/// A world: the state database (a file unless `in_memory`), the operations, a real
/// K_ca in a scratch store, one verified enrollment for h1, one active grant.
struct World {
    dir: tempfile::TempDir,
    db: PathBuf,
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    ops: Operations,
    ca: CaFingerprint,
    ca_public: String,
    grant: GrantId,
    keys: KeyVault,
}

impl World {
    async fn new() -> Self {
        Self::build(false).await
    }

    async fn build(in_memory: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.db");
        let store = Arc::new(if in_memory {
            Store::open_in_memory(Arc::new(NoFaults)).unwrap()
        } else {
            Store::open(&db, Arc::new(NoFaults)).unwrap()
        });
        let k_ca = SecretCaKey::generate().unwrap();
        let ca = k_ca.fingerprint().unwrap();
        let ca_public = k_ca.public_openssh().unwrap();
        std::fs::create_dir(dir.path().join("store")).unwrap();
        ScratchSecretStore::new(dir.path().join("store"))
            .put(&ca, &k_ca)
            .unwrap();
        drop(k_ca);
        let rec = IssuerRecord {
            ca_fingerprint: ca.clone(),
            public_key: ca_public.clone(),
            state: CaState::Active,
            store_kind: StoreKind::LinuxSecretService,
            backup_sha256: "ab".repeat(32),
            backup_created_at: t0(),
            restored_without_log: false,
            created_at: t0(),
            retired_at: None,
        };
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&environment_record())?;
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse("dev").unwrap(),
                    revision: 1,
                    scope: Scope {
                        pairs: [h1(), pair("h2", "deploy")].into_iter().collect(),
                        capabilities: ssh_only(),
                    },
                    label: None,
                })?;
                tx.upsert_policy(&policy(PauseState::Active, None, 1), false)?;
                for d in ["h1", "h2"] {
                    tx.upsert_destination(&DestinationRecord {
                        id: DestinationId::parse(d).unwrap(),
                        alias: d.into(),
                        revision: 1,
                        definition: DestinationDefinition::Observed,
                        label: None,
                        updated_at: t0(),
                    })?;
                }
                tx.insert_issuer(&rec)?;
                tx.seed_enrollment(&enrollment(&ca, &h1()))?;
                Ok(())
            })
            .unwrap();
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let script: Vec<FakeStep> = (0..8).map(|_| FakeStep::Prepare(outcome())).collect();
        let fake = FakeCredentialAdapter::new(descriptor(), script);
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: sync,
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: vec![fake as Arc<dyn CredentialAdapter>],
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        let ensured = ops
            .ensure(
                &owner(),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: [h1()].into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse("w-u3").unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse("u3").unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
        Self {
            db,
            store,
            clock,
            ops,
            ca,
            ca_public,
            grant: ensured.data.grant_id,
            keys: KeyVault::new(),
            dir,
        }
    }

    fn scratch(&self) -> ScratchSecretStore {
        ScratchSecretStore::new(self.dir.path().join("store"))
    }

    fn key(&self) -> PublicKeyInfo {
        self.keys.generate_ed25519().unwrap().1
    }

    fn wall(&self) -> Timestamp {
        Clock::wall(self.clock.as_ref())
    }

    fn request(&self, subject: &PublicKeyInfo) -> IssuanceRequest {
        IssuanceRequest {
            grant: self.grant.clone(),
            pair: h1(),
            principal: "hm:h1:deploy".into(),
            key_id: format!("heimdall:{}:{}:1", env_id().as_str(), self.grant.as_str()),
            valid_after: shift(self.wall(), -60),
            valid_before: shift(self.wall(), 1800),
            extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
            subject_fingerprint: subject.fingerprint.clone(),
            facts: facts(),
        }
    }

    async fn reserve(&self, subject: &PublicKeyInfo) -> IssuanceEntry {
        self.ops
            .reserve_issuance(self.request(subject))
            .await
            .unwrap_or_else(|e| panic!("reserve: {} {}", e.code, e.message))
    }

    /// A reservation forced in with a test-only store write (the ceiling cases).
    fn force(
        &self,
        subject: &PublicKeyInfo,
        edit: impl FnOnce(&mut CertificateBounds),
    ) -> IssuanceEntry {
        let mut bounds = CertificateBounds {
            serial: 7,
            key_id: format!("heimdall:{}:{}:7", env_id().as_str(), self.grant.as_str()),
            principal: "hm:h1:deploy".into(),
            valid_after: shift(self.wall(), -60),
            valid_before: shift(self.wall(), 1800),
            extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
            subject_fingerprint: subject.fingerprint.clone(),
            ca_fingerprint: Some(self.ca.clone()),
        };
        edit(&mut bounds);
        let entry = IssuanceEntry {
            id: IssuanceId::from_random_bytes([0x42; 16]),
            grant: self.grant.clone(),
            generation: self
                .store
                .transaction(|tx| tx.authority_generation())
                .unwrap(),
            pair: h1(),
            bounds,
            state: IssuanceState::Reserved,
            reserved_at: self.wall(),
            settled_at: None,
            void_reason: None,
        };
        self.store
            .transaction(|tx| tx.reserve_issuance(&entry))
            .unwrap();
        entry
    }

    fn entry(&self, id: &IssuanceId) -> IssuanceEntry {
        self.store
            .transaction(|tx| tx.issuance_entries(&self.grant))
            .unwrap()
            .into_iter()
            .find(|e| e.id == *id)
            .unwrap()
    }

    // Used by the Unix process cases.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn residual(&self) -> Option<Timestamp> {
        self.store
            .transaction(|tx| tx.issuance_residual(std::slice::from_ref(&self.grant)))
            .unwrap()
    }

    /// An unrelated authority-generation move (an environment write, ADR-0006 §13.7
    /// item 5).
    fn move_generation(&self) {
        self.store
            .transaction(|tx| tx.upsert_environment(&environment_record()))
            .unwrap();
    }
}

fn grant_ref(e: &IssuanceEntry) -> IssuanceRef {
    IssuanceRef {
        table: IssuanceTable::Grant,
        id: e.id.clone(),
    }
}

// --- the in-process child ------------------------------------------------------------

/// A child running `child::run` on a thread over two OS pipes.
struct InProc {
    to: Option<std::io::PipeWriter>,
    from: std::io::PipeReader,
    buf: Vec<u8>,
    handle: std::thread::JoinHandle<i32>,
}

fn pipe_file(r: std::io::PipeReader) -> File {
    #[cfg(unix)]
    {
        File::from(std::os::fd::OwnedFd::from(r))
    }
    #[cfg(windows)]
    {
        File::from(std::os::windows::io::OwnedHandle::from(r))
    }
}

fn spawn_in_proc(w: &World, store: Box<dyn SecretStore>) -> InProc {
    let (r1, w1) = std::io::pipe().unwrap();
    let (r2, w2) = std::io::pipe().unwrap();
    let stdin = pipe_file(r1);
    let db = w.db.clone();
    let clock: Arc<dyn Clock> = w.clock.clone();
    let handle = std::thread::spawn(move || child::run(stdin, w2, store, &db, clock));
    InProc {
        to: Some(w1),
        from: r2,
        buf: Vec::new(),
        handle,
    }
}

const NONCE: &str = "0123456789abcdef0123456789abcdef";

fn rid(n: u32) -> String {
    format!("{n:032x}")
}

impl InProc {
    fn send_raw(&mut self, bytes: &[u8]) {
        let _ = self.to.as_mut().unwrap().write_all(bytes);
    }

    fn send(&mut self, r: &Request) {
        self.send_raw(&r.encode().unwrap());
    }

    fn recv(&mut self) -> Option<Response> {
        loop {
            if let Some((body, used)) = split_frame(&self.buf).unwrap() {
                let r = Response::decode(body).unwrap();
                self.buf.drain(..used);
                return Some(r);
            }
            let mut c = [0u8; 4096];
            let n = self.from.read(&mut c).unwrap_or(0);
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(&c[..n]);
        }
    }

    fn call(&mut self, r: &Request) -> Response {
        self.send(r);
        self.recv().expect("a reply")
    }

    fn hello(&mut self) -> Response {
        self.call(&Request::Hello {
            protocol: PROTOCOL.into(),
            nonce: NONCE.into(),
        })
    }

    /// `hello` then `load`, which must load the world's CA.
    fn greet(&mut self, w: &World) {
        assert!(matches!(self.hello(), Response::HelloAck { .. }));
        assert_eq!(
            self.call(&Request::Load {}),
            Response::Loaded {
                cas: vec![LoadedCa {
                    fingerprint: w.ca.clone(),
                    state: CaState::Active,
                }]
            }
        );
    }

    fn sign(&mut self, entry: &IssuanceRef, subject: &str, n: u32) -> Response {
        self.call(&Request::Sign {
            request_id: rid(n),
            reservation: entry.clone(),
            subject_public_key: subject.to_owned(),
        })
    }

    fn refusal(&mut self, entry: &IssuanceRef, subject: &str) -> IssuerRefusal {
        match self.sign(entry, subject, 9) {
            Response::Refused { reason, .. } => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// Close stdin and return the exit status.
    fn finish(mut self) -> i32 {
        drop(self.to.take());
        self.handle.join().unwrap()
    }
}

// =================================================================================
// Positive
// =================================================================================

#[tokio::test]
async fn issuer_signs_reserved_entry_with_exact_bounds() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.reserve(&k).await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    let Response::Signed {
        request_id,
        certificate,
    } = c.sign(&grant_ref(&entry), &k.openssh_line, 1)
    else {
        panic!("expected a certificate");
    };
    assert_eq!(request_id, rid(1));
    let cert = ssh_key::Certificate::from_openssh(&certificate).unwrap();
    // Exactly the reserved bounds: serial, key ID, principal, validity, extensions,
    // subject and CA (U1's installed-certificate validator).
    validate_installed(&cert, &entry.bounds, &k.fingerprint, &w.ca).unwrap();
    assert_eq!(cert.serial(), entry.bounds.serial);
    // The issuer wrote nothing: the entry is still reserved, nothing published.
    assert_eq!(w.entry(&entry.id).state, IssuanceState::Reserved);
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn hello_load_status_round_trip() {
    let w = World::new().await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    assert_eq!(
        c.hello(),
        Response::HelloAck {
            nonce: NONCE.into(),
            pid: std::process::id(),
        }
    );
    c.greet_after_hello(&w);
    assert_eq!(
        c.call(&Request::Status {}),
        Response::Status {
            cas: vec![LoadedCa {
                fingerprint: w.ca.clone(),
                state: CaState::Active,
            }],
            signed_total: 0,
            refused_total: 0,
        }
    );
    // `unload` zeroizes and confirms; the CA is gone from the status.
    assert_eq!(
        c.call(&Request::Unload {
            ca_fingerprint: w.ca.clone()
        }),
        Response::Unloaded {
            ca_fingerprint: w.ca.clone()
        }
    );
    assert_eq!(
        c.call(&Request::Status {}),
        Response::Status {
            cas: vec![],
            signed_total: 0,
            refused_total: 0,
        }
    );
    assert_eq!(c.finish(), 0);
}

impl InProc {
    fn greet_after_hello(&mut self, w: &World) {
        assert_eq!(
            self.call(&Request::Load {}),
            Response::Loaded {
                cas: vec![LoadedCa {
                    fingerprint: w.ca.clone(),
                    state: CaState::Active,
                }]
            }
        );
    }
}

#[tokio::test]
async fn issuer_exits_and_zeroizes_on_stdin_eof() {
    let w = World::new().await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    // EOF from stdin (the parent died): the child zeroizes every key (`CaSet::clear`,
    // `SecretCaKey`'s drop) and exits 0, closing its stdout.
    drop(c.to.take());
    let start = std::time::Instant::now();
    let status = c.handle.join().unwrap();
    assert_eq!(status, 0);
    assert!(start.elapsed() < Duration::from_secs(2));
    let mut rest = Vec::new();
    c.from.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "nothing after EOF");
    // `shutdown` does the same.
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    c.send(&Request::Shutdown {});
    assert_eq!(c.recv(), None);
    assert_eq!(c.finish(), 0);
}

// =================================================================================
// Negative, one per IssuerRefusal
// =================================================================================

#[tokio::test]
async fn entry_not_reserved_published_voided_missing() {
    let w = World::new().await;
    let k = w.key();
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    // Published: signed, then published by the runtime.
    let published = w.reserve(&k).await;
    assert!(matches!(
        c.sign(&grant_ref(&published), &k.openssh_line, 1),
        Response::Signed { .. }
    ));
    assert!(matches!(
        w.ops
            .publish_issuance(&published.id, &facts())
            .await
            .unwrap(),
        Publication::Published(_)
    ));
    assert_eq!(
        c.refusal(&grant_ref(&published), &k.openssh_line),
        IssuerRefusal::EntryNotReserved
    );
    // Voided: the CA retired between reserve and publish.
    let voided = w.reserve(&k).await;
    w.store
        .transaction(|tx| {
            tx.set_issuer_state(&w.ca, CaState::Active, CaEvent::RetireApproved, t0())
                .map(|r| {
                    r.unwrap();
                })
        })
        .unwrap();
    assert!(w.ops.publish_issuance(&voided.id, &facts()).await.is_err());
    assert_eq!(w.entry(&voided.id).state, IssuanceState::Voided);
    assert_eq!(
        c.refusal(&grant_ref(&voided), &k.openssh_line),
        IssuerRefusal::EntryNotReserved
    );
    // Missing.
    let missing = IssuanceRef {
        table: IssuanceTable::Grant,
        id: IssuanceId::from_random_bytes([0x99; 16]),
    };
    assert_eq!(
        c.refusal(&missing, &k.openssh_line),
        IssuerRefusal::EntryNotReserved
    );
    let missing_verification = IssuanceRef {
        table: IssuanceTable::Verification,
        id: IssuanceId::from_random_bytes([0x98; 16]),
    };
    assert_eq!(
        c.refusal(&missing_verification, &k.openssh_line),
        IssuerRefusal::EntryNotReserved
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn entry_stale_after_60s() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.reserve(&k).await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    w.clock.advance(Duration::from_secs(60));
    // At exactly 60 s it is still fresh.
    assert!(matches!(
        c.sign(&grant_ref(&entry), &k.openssh_line, 1),
        Response::Signed { .. }
    ));
    let entry = w.reserve(&k).await;
    w.clock.advance(Duration::from_secs(61));
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::EntryStale
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn subject_mismatch() {
    let w = World::new().await;
    let (k, other) = (w.key(), w.key());
    let entry = w.reserve(&k).await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    assert_eq!(
        c.refusal(&grant_ref(&entry), &other.openssh_line),
        IssuerRefusal::SubjectMismatch
    );
    // Not a key line at all is a mismatch too (never parsed further).
    assert_eq!(
        c.refusal(&grant_ref(&entry), "ssh-ed25519 notbase64"),
        IssuerRefusal::SubjectMismatch
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn predicate_refusal_after_tombstone_committed_post_reserve() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.reserve(&k).await;
    // A tombstone for the grant committed after the reservation (a test-only write,
    // so the grant row itself is untouched and only the tombstone decides).
    w.store
        .transaction(|tx| {
            let generation = tx.authority_generation()?;
            tx.insert_tombstone(&Tombstone {
                grant: w.grant.clone(),
                cascade: Vec::new(),
                generation,
                revoked_at: t0(),
                remote_pending: Vec::new(),
                cause: RevocationCause::Revoke,
            })
        })
        .unwrap();
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::Issuance(IssuanceRefusal::Tombstoned)
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn ceiling_two_principals() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.force(&k, |b| b.principal = "hm:h1:deploy,hm:h2:deploy".into());
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::CeilingExceeded
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn ceiling_x11_extension() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.force(&k, |b| {
        b.extensions.insert("permit-X11-forwarding".into());
    });
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::CeilingExceeded
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn ceiling_validity_too_long() {
    let w = World::new().await;
    let k = w.key();
    // `valid_before` within the grant's bound (the predicate would pass), but
    // `valid_after` ten days back: the span exceeds the grant's window plus 60 s.
    let entry = w.force(&k, |b| b.valid_after = shift(t0(), -10 * 86_400));
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::CeilingExceeded
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn subject_is_a_ca_key() {
    let w = World::new().await;
    // A reservation whose subject is the CA's own public key.
    let ca_key = PublicKeyInfo {
        openssh_line: w.ca_public.clone(),
        blob: Vec::new(),
        fingerprint: w.ca.as_str().to_owned(),
    };
    let entry = w.reserve(&ca_key).await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    assert_eq!(
        c.refusal(&grant_ref(&entry), &w.ca_public),
        IssuerRefusal::CeilingExceeded
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn ca_not_loaded() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.reserve(&k).await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    // No `load`: no key in memory.
    assert!(matches!(c.hello(), Response::HelloAck { .. }));
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::CaNotLoaded
    );
    // Loaded, then unloaded (retirement): refused again.
    c.greet_after_hello(&w);
    assert_eq!(
        c.call(&Request::Unload {
            ca_fingerprint: w.ca.clone()
        }),
        Response::Unloaded {
            ca_fingerprint: w.ca.clone()
        }
    );
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::CaNotLoaded
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn rate_limited_after_600_per_minute() {
    let w = World::new().await;
    // Ten subject keys (the per-subject cap is 64), 61 reservations each.
    let keys: Vec<PublicKeyInfo> = (0..10).map(|_| w.key()).collect();
    let mut entries = Vec::new();
    for k in &keys {
        for _ in 0..61 {
            entries.push((w.reserve(k).await, k.openssh_line.clone()));
        }
    }
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    for (n, (e, line)) in entries.iter().take(600).enumerate() {
        let r = c.sign(&grant_ref(e), line, u32::try_from(n).unwrap());
        assert!(matches!(r, Response::Signed { .. }), "{n}: {r:?}");
    }
    let (e, line) = &entries[600];
    assert_eq!(c.refusal(&grant_ref(e), line), IssuerRefusal::RateLimited);
    // A minute later the window has room again.
    w.clock.advance(Duration::from_secs(60));
    let fresh = w.reserve(&keys[0]).await;
    assert!(matches!(
        c.sign(&grant_ref(&fresh), &keys[0].openssh_line, 9999),
        Response::Signed { .. }
    ));
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn rate_limited_after_64_per_activation() {
    let w = World::new().await;
    let k = w.key();
    let mut entries = Vec::new();
    for _ in 0..65 {
        entries.push(w.reserve(&k).await);
    }
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    for (n, e) in entries.iter().take(64).enumerate() {
        assert!(matches!(
            c.sign(&grant_ref(e), &k.openssh_line, u32::try_from(n).unwrap()),
            Response::Signed { .. }
        ));
    }
    assert_eq!(
        c.refusal(&grant_ref(&entries[64]), &k.openssh_line),
        IssuerRefusal::RateLimited
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn ca_retiring_refused() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.reserve(&k).await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    w.store
        .transaction(|tx| {
            tx.set_issuer_state(&w.ca, CaState::Active, CaEvent::RetireApproved, t0())
                .map(|r| {
                    r.unwrap();
                })
        })
        .unwrap();
    // The child loaded the CA while active; the store now says `retiring`.
    assert_eq!(
        c.refusal(&grant_ref(&entry), &k.openssh_line),
        IssuerRefusal::Issuance(IssuanceRefusal::CaRetiring)
    );
    // A reload never loads a retiring CA again (D4 item 3).
    assert_eq!(c.call(&Request::Load {}), Response::Loaded { cas: vec![] });
    assert_eq!(c.finish(), 0);
}

/// ⟨integrator, wave-2 review⟩ D3 item 4 step 4 for a **verification** entry: the
/// child loaded the CA while `active`; the store then moves it to `retiring` before any
/// `unload` reaches the child. A reserved verification entry naming that CA is refused
/// `ca_not_loaded` from the snapshot's CA state, never signed. Control: with the CA
/// `active`, the same entry passes the CA check and reaches the predicate (which
/// refuses it here for its own reason: the forced entry has no verifying operation).
#[tokio::test]
async fn verification_entry_for_retiring_ca_refused_from_snapshot() {
    let w = World::new().await;
    let k = w.key();
    let op = heimdall_contract::ids::OperationId::from_random_bytes([0x77; 16]);
    let entry = heimdall_domain::verification::VerificationEntry {
        id: IssuanceId::from_random_bytes([0x43; 16]),
        operation: op.clone(),
        pair: h1(),
        purpose: heimdall_domain::verification::VerificationPurpose::Positive,
        bounds: CertificateBounds {
            serial: 9,
            key_id: format!("heimdall:{}:{}:9", env_id().as_str(), op.as_str()),
            principal: "hm:h1:deploy".into(),
            valid_after: shift(w.wall(), -60),
            valid_before: shift(w.wall(), 240),
            extensions: BTreeSet::new(),
            subject_fingerprint: k.fingerprint.clone(),
            ca_fingerprint: Some(w.ca.clone()),
        },
        state: IssuanceState::Reserved,
        reserved_at: w.wall(),
        settled_at: None,
        void_reason: None,
    };
    w.store
        .transaction(|tx| tx.reserve_verification(&entry))
        .unwrap();
    let reservation = IssuanceRef {
        table: IssuanceTable::Verification,
        id: entry.id.clone(),
    };
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    // Control: an active CA passes the CA check; the predicate decides.
    let control = c.refusal(&reservation, &k.openssh_line);
    assert_ne!(control, IssuerRefusal::CaNotLoaded, "{control:?}");
    assert!(
        matches!(control, IssuerRefusal::Verification(_)),
        "{control:?}"
    );
    w.store
        .transaction(|tx| {
            tx.set_issuer_state(&w.ca, CaState::Active, CaEvent::RetireApproved, t0())
                .map(|r| {
                    r.unwrap();
                })
        })
        .unwrap();
    assert_eq!(
        c.refusal(&reservation, &k.openssh_line),
        IssuerRefusal::CaNotLoaded
    );
    assert_eq!(c.finish(), 0);
}

#[tokio::test]
async fn generation_only_refusal_re_reserves_within_bound() {
    let w = World::new().await;
    let k = w.key();
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    // One unrelated move between reserve and sign.
    let entry = w.reserve(&k).await;
    w.move_generation();
    let refusal = c.refusal(&grant_ref(&entry), &k.openssh_line);
    assert_eq!(
        refusal,
        IssuerRefusal::Issuance(IssuanceRefusal::StaleGeneration)
    );
    assert!(heimdall_issuer::protocol::is_generation_only(&refusal));
    // The runtime voids, re-validates and re-reserves (publish's §13.8 item 1 path),
    // and asks again: signed and published on the second attempt.
    let Publication::Rereserved { reservation } =
        w.ops.publish_issuance(&entry.id, &facts()).await.unwrap()
    else {
        panic!("expected a re-reservation");
    };
    assert_eq!(w.entry(&entry.id).state, IssuanceState::Voided);
    assert!(matches!(
        c.sign(&grant_ref(&reservation), &k.openssh_line, 2),
        Response::Signed { .. }
    ));
    assert!(matches!(
        w.ops
            .publish_issuance(&reservation.id, &facts())
            .await
            .unwrap(),
        Publication::Published(_)
    ));
    // A generation that moves before every attempt: the bound of 3 ends it, with
    // nothing left reserved and nothing published.
    let mut current = w.reserve(&k).await;
    let mut attempts = 1;
    let end = loop {
        w.move_generation();
        assert_eq!(
            c.refusal(&grant_ref(&current), &k.openssh_line),
            IssuerRefusal::Issuance(IssuanceRefusal::StaleGeneration)
        );
        match w.ops.publish_issuance(&current.id, &facts()).await {
            Ok(Publication::Rereserved { reservation }) => {
                attempts += 1;
                current = reservation;
            }
            other => break other,
        }
    };
    assert_eq!(attempts, 3);
    let e = end.unwrap_err();
    assert_eq!(e.code, heimdall_contract::Code::ServiceUnavailable);
    let entries = w
        .store
        .transaction(|tx| tx.issuance_entries(&w.grant))
        .unwrap();
    assert!(entries.iter().all(|e| e.state != IssuanceState::Reserved));
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.state == IssuanceState::Published)
            .count(),
        1
    );
    assert_eq!(c.finish(), 0);
}

// =================================================================================
// Read-only (F21; §17.15 item 8)
// =================================================================================

/// The issuer's read-only verdict on `entry` in `store` (the child's assembly).
fn ro_verdict(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    entry: &IssuanceEntry,
    subject: &str,
) -> Result<CertificateBounds, IssuerRefusal> {
    let gate = TimeGate::new(
        store.clone(),
        clock.clone(),
        ScriptedTimeSync::new(SyncStatus::Unknown),
        TimePolicy::default(),
    );
    store
        .transaction(|tx| {
            let (now, time) = gate.assess_read_only_in(tx)?;
            issuance_ro::assess(tx, &grant_ref(entry), subject, &now, &time)
        })
        .unwrap()
}

/// One generated change between reserve and the comparison.
#[derive(Debug, Clone, Copy)]
enum Change {
    Advance(u8),
    Tombstone,
    UnrelatedGeneration,
    Pause,
    CutoffPassed,
    CutoffSoon,
    RetireCa,
    RemoveEnrollment,
}

fn apply(w: &World, change: Change) {
    match change {
        Change::Advance(s) => w.clock.advance(Duration::from_secs(u64::from(s % 20))),
        Change::Tombstone => {
            w.store
                .transaction(|tx| {
                    let generation = tx.authority_generation()?;
                    tx.insert_tombstone(&Tombstone {
                        grant: w.grant.clone(),
                        cascade: Vec::new(),
                        generation,
                        revoked_at: w.wall(),
                        remote_pending: Vec::new(),
                        cause: RevocationCause::Revoke,
                    })
                })
                .unwrap();
        }
        Change::UnrelatedGeneration => w.move_generation(),
        Change::Pause | Change::CutoffPassed | Change::CutoffSoon => {
            let current = w
                .store
                .transaction(|tx| tx.policy(&PolicyId::parse("pol").unwrap()))
                .unwrap()
                .unwrap();
            let mut p = current.clone();
            p.revision = PolicyRevision(current.revision.0 + 1);
            match change {
                Change::Pause => p.pause = PauseState::Paused { since: w.wall() },
                Change::CutoffPassed => p.cutoff_at = Some(shift(w.wall(), -1)),
                _ => p.cutoff_at = Some(shift(w.wall(), 600)),
            }
            w.store
                .transaction(|tx| tx.upsert_policy(&p, false))
                .unwrap();
        }
        Change::RetireCa => {
            w.store
                .transaction(|tx| {
                    let state = tx.issuer(&w.ca)?.unwrap().state;
                    if state == CaState::Active {
                        tx.set_issuer_state(&w.ca, state, CaEvent::RetireApproved, t0())?
                            .unwrap();
                    }
                    Ok(())
                })
                .unwrap();
        }
        Change::RemoveEnrollment => {
            w.store
                .transaction(|tx| {
                    let e = enrollment(&w.ca, &h1());
                    if tx.enrollment(&e.id)?.unwrap().state == EnrollmentState::Verified {
                        tx.transition_enrollment(
                            EnrollmentState::Verified,
                            heimdall_domain::enrollment::EnrollmentEventKind::RemoveEnrollmentApproved,
                            &e,
                        )?
                        .unwrap();
                    }
                    Ok(())
                })
                .unwrap();
        }
    }
}

fn change_strategy() -> impl proptest::strategy::Strategy<Value = Change> {
    use proptest::prelude::*;
    prop_oneof![
        any::<u8>().prop_map(Change::Advance),
        Just(Change::Tombstone),
        Just(Change::UnrelatedGeneration),
        Just(Change::Pause),
        Just(Change::CutoffPassed),
        Just(Change::CutoffSoon),
        Just(Change::RetireCa),
        Just(Change::RemoveEnrollment),
    ]
}

/// Over generated store states (a reservation, then up to three changes), the issuer's
/// read-only verdict equals the runtime's publish predicate (the reserve predicate run
/// again in the publishing transaction, the same assembly): published ⇔ `Ok` with the
/// entry's bounds; voided with reason `r` ⇔ `issuance.r`; re-reserved (only the
/// generation moved) ⇔ `issuance.stale_generation`, the generation-only refusal.
#[test]
fn issuance_ro_assess_matches_reserve_predicate() {
    use proptest::test_runner::{Config, RngSeed, TestRunner};
    let mut config = Config {
        cases: 256,
        failure_persistence: None,
        ..Config::default()
    };
    config.rng_seed = RngSeed::Fixed(0x5533_4953_5355_4552);
    let mut runner = TestRunner::new(config);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runner
        .run(
            &proptest::collection::vec(change_strategy(), 0..4),
            |changes| {
                rt.block_on(async {
                    let w = World::build(true).await;
                    let k = w.key();
                    let entry = w.reserve(&k).await;
                    for c in &changes {
                        apply(&w, *c);
                    }
                    let ro = ro_verdict(&w.store, &w.clock, &entry, &k.openssh_line);
                    let published = w.ops.publish_issuance(&entry.id, &facts()).await;
                    let stored = w.entry(&entry.id);
                    let expected = match (&published, stored.state) {
                        (Ok(Publication::Published(_)), _) => Ok(entry.bounds.clone()),
                        (Ok(Publication::Rereserved { .. }), _) => {
                            Err(IssuerRefusal::Issuance(IssuanceRefusal::StaleGeneration))
                        }
                        (Err(_), IssuanceState::Voided) => {
                            Err(IssuerRefusal::Issuance(stored.void_reason.clone().unwrap()))
                        }
                        other => panic!("unexpected publication {other:?}"),
                    };
                    assert_eq!(ro, expected, "changes {changes:?}");
                });
                Ok(())
            },
        )
        .unwrap();
}

/// F21: on a store opened with `Store::open_read_only`, the assessment and the whole
/// read-only check write nothing: the database file's bytes and the high-water mark
/// are unchanged.
#[tokio::test]
async fn assess_read_only_on_open_read_only_store_writes_nothing() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.reserve(&k).await;
    let mark = w.store.transaction(|tx| tx.high_water_mark()).unwrap();
    let anchor = w.store.transaction(|tx| tx.runtime_anchor()).unwrap();
    let snapshot = |p: &Path| {
        // The database and its write-ahead log (readers keep their read marks in the
        // shared-memory index, which is not database content).
        let mut all = std::fs::read(p).unwrap();
        if let Ok(b) = std::fs::read(PathBuf::from(format!("{}-wal", p.display()))) {
            all.extend(b);
        }
        all
    };
    let before = snapshot(&w.db);
    w.clock.advance(Duration::from_secs(5));
    let ro = Arc::new(Store::open_read_only(&w.db, Arc::new(NoFaults)).unwrap());
    let gate = TimeGate::new(
        ro.clone(),
        w.clock.clone(),
        ScriptedTimeSync::new(SyncStatus::Synchronized),
        TimePolicy::default(),
    );
    for _ in 0..3 {
        assert_eq!(gate.assess_read_only(&ro), TimeStatus::Safe);
    }
    let bounds =
        heimdall_issuer::check::verify_reservation(&ro, &gate, &grant_ref(&entry), &k.openssh_line)
            .unwrap();
    assert_eq!(bounds, entry.bounds);
    drop(gate);
    drop(ro);
    assert_eq!(snapshot(&w.db), before, "the database bytes are unchanged");
    assert_eq!(
        w.store.transaction(|tx| tx.high_water_mark()).unwrap(),
        mark
    );
    assert_eq!(
        w.store.transaction(|tx| tx.runtime_anchor()).unwrap(),
        anchor
    );
}

/// Without a same-boot anchor (no runtime anchor, no confirmation of this boot), the
/// read-only assessment is `Uncertain` even on synchronized time, where the
/// read-write gate would accept and persist the boot's first anchor.
#[tokio::test]
async fn assess_read_only_fails_closed_without_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    drop(Store::open(&db, Arc::new(NoFaults)).unwrap());
    let ro = Arc::new(Store::open_read_only(&db, Arc::new(NoFaults)).unwrap());
    let clock = VirtualClock::at(t0());
    let gate = TimeGate::new(
        ro.clone(),
        clock.clone(),
        ScriptedTimeSync::new(SyncStatus::Synchronized),
        TimePolicy::default(),
    );
    assert_eq!(
        gate.assess_read_only(&ro),
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized {
            sync: SyncStatus::Synchronized
        })
    );
    // With an anchor of another boot only: still uncertain.
    let w = World::new().await;
    w.clock.reboot(shift(t0(), 30));
    let ro = Arc::new(Store::open_read_only(&w.db, Arc::new(NoFaults)).unwrap());
    let gate = TimeGate::new(
        ro.clone(),
        w.clock.clone(),
        ScriptedTimeSync::new(SyncStatus::Synchronized),
        TimePolicy::default(),
    );
    assert!(matches!(
        gate.assess_read_only(&ro),
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
    ));
    // And the issuer refuses on that time.
    let k = w.key();
    let entry = w.force(&k, |_| {});
    assert_eq!(
        heimdall_issuer::check::verify_reservation(&ro, &gate, &grant_ref(&entry), &k.openssh_line),
        Err(IssuerRefusal::Issuance(IssuanceRefusal::TimeUncertain))
    );
}

// =================================================================================
// Channel
// =================================================================================

#[cfg(unix)]
#[tokio::test]
async fn issuer_refuses_tty_stdin() {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let w = World::new().await;
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name.to_str().unwrap())
        .unwrap();
    use std::io::IsTerminal as _;
    assert!(tty.is_terminal());
    let mut out = Vec::new();
    let status = child::run(tty, &mut out, Box::new(w.scratch()), &w.db, w.clock.clone());
    assert_eq!(status, child::EXIT_USAGE);
    assert!(out.is_empty(), "nothing written on stdout");
}

#[tokio::test]
async fn oversized_frame_closes_channel() {
    let w = World::new().await;
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.greet(&w);
    // A header declaring one byte over the limit: refused before any body arrives.
    let len = u32::try_from(MAX_FRAME_BYTES + 1).unwrap();
    c.send_raw(&len.to_be_bytes());
    assert_eq!(c.recv(), None, "the channel closes");
    assert_eq!(c.finish(), EXIT_PROTOCOL);
    // A malformed body closes it too, as does a first message other than `hello`.
    let mut c = spawn_in_proc(&w, Box::new(w.scratch()));
    c.send(&Request::Load {});
    assert_eq!(c.recv(), None);
    assert_eq!(c.finish(), EXIT_PROTOCOL);
}

// =================================================================================
// Interrupted and the client (real child processes)
// =================================================================================

#[tokio::test]
async fn store_unavailable_reports_reason_and_no_fallback() {
    let w = World::new().await;
    let k = w.key();
    let entry = w.reserve(&k).await;
    let store_dir = w.dir.path().join("store");
    let listing = |d: &Path| {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        v.sort();
        v
    };
    let before = listing(&store_dir);
    for availability in [
        StoreAvailability::Locked,
        StoreAvailability::InteractionNotAllowed,
        StoreAvailability::Missing,
        StoreAvailability::Unsupported,
    ] {
        let mut c = spawn_in_proc(
            &w,
            Box::new(ScratchSecretStore::with_availability(
                store_dir.clone(),
                availability,
            )),
        );
        assert!(matches!(c.hello(), Response::HelloAck { .. }));
        assert_eq!(
            c.call(&Request::Load {}),
            Response::StoreUnavailable {
                reason: availability
            }
        );
        // No key in memory, and no fallback key: every sign is refused.
        assert_eq!(
            c.refusal(&grant_ref(&entry), &k.openssh_line),
            IssuerRefusal::CaNotLoaded
        );
        assert_eq!(c.finish(), 0);
    }
    // The reasons the runtime reports.
    assert_eq!(
        StoreAvailability::Locked.refusal_reason(),
        Some("issuer_store_locked")
    );
    assert_eq!(
        StoreAvailability::Unsupported.refusal_reason(),
        Some("issuer_store_unavailable")
    );
    // Nothing was written: no plaintext file, no new item.
    assert_eq!(listing(&store_dir), before);
    // A store without the registered CA's item: `missing`, nothing loaded.
    std::fs::create_dir(w.dir.path().join("store2")).unwrap();
    let empty = ScratchSecretStore::new(w.dir.path().join("store2"));
    let mut c = spawn_in_proc(&w, Box::new(empty));
    assert!(matches!(c.hello(), Response::HelloAck { .. }));
    assert_eq!(
        c.call(&Request::Load {}),
        Response::StoreUnavailable {
            reason: StoreAvailability::Missing
        }
    );
    assert_eq!(c.finish(), 0);
}

/// The restart backoff on a virtual clock: every start fails at once (the program does
/// not exist), the supervisor retries with jittered delays bounded by `min(60 s,
/// 1 s·2^(n−1))`, stops after eight attempts (`unavailable`), and a new demand starts a
/// new cycle.
#[tokio::test(start_paused = true)]
async fn restart_backoff_bounded_and_jittered() {
    struct Recording(Mutex<Vec<(Duration, Duration)>>);
    impl Jitter for Recording {
        fn delay(&self, ceiling: Duration) -> Duration {
            // A jitter that varies: alternately half and all of the ceiling.
            let mut v = self.0.lock().unwrap();
            let d = if v.len().is_multiple_of(2) {
                ceiling / 2
            } else {
                ceiling
            };
            v.push((ceiling, d));
            d
        }
    }
    let jitter = Arc::new(Recording(Mutex::new(Vec::new())));
    let mut config = ClientConfig::new(
        ChildCommand {
            program: PathBuf::from("/nonexistent/heimdall-u3-no-such-issuer"),
            args: Vec::new(),
            env: Vec::new(),
        },
        Arc::new(|_| None),
    );
    config.jitter = jitter.clone();
    let issuer = ChildIssuer::new(config);
    let started = tokio::time::Instant::now();
    assert!(issuer.start().await.is_err());
    // Let the supervisor's cycle run on virtual time.
    for _ in 0..200 {
        if issuer.state() == IssuerState::Unavailable {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(issuer.state(), IssuerState::Unavailable);
    let recorded = jitter.0.lock().unwrap().clone();
    let ceilings: Vec<u64> = recorded.iter().map(|(c, _)| c.as_secs()).collect();
    assert_eq!(ceilings, vec![1, 2, 4, 8, 16, 32, 60, 60]);
    for (n, (c, d)) in recorded.iter().enumerate() {
        assert!(d <= c, "attempt {n}: {d:?} > {c:?}");
        assert_eq!(*c, backoff_ceiling(u32::try_from(n + 1).unwrap()));
    }
    let slept: Duration = recorded.iter().map(|(_, d)| *d).sum();
    assert!(started.elapsed() >= slept, "the delays were waited");
    assert!(
        started.elapsed() < slept + Duration::from_secs(10),
        "and nothing else"
    );
    // While unavailable a demand is refused at once, and starts a new cycle.
    let e = issuer
        .sign(
            IssuanceRef {
                table: IssuanceTable::Grant,
                id: IssuanceId::from_random_bytes([1; 16]),
            },
            "ssh-ed25519 AAAA",
        )
        .await
        .unwrap_err();
    assert_eq!(e, IssuerError::Unavailable("issuer_unavailable".into()));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(jitter.0.lock().unwrap().len() > 8, "a new cycle began");
}

#[cfg(unix)]
mod process {
    //! Client cases over a real child process: this test binary, re-executed through
    //! `/bin/sh` with `HM_U3_CHILD_*` set, runs `child_process_entry`, whose protocol
    //! output goes to descriptor 3 (libtest's own stdout goes to `/dev/null`).

    use super::*;

    const DB_ENV: &str = "HM_U3_CHILD_DB";
    const STORE_ENV: &str = "HM_U3_CHILD_STORE";
    const WALL_ENV: &str = "HM_U3_CHILD_WALL";
    const STALL_ENV: &str = "HM_U3_CHILD_STALL_SIGNED";
    const RUNTIME_ENV: &str = "HM_U3_RUNTIME_PIDFILE";

    /// A writer that never delivers a `signed` reply (it sleeps until killed).
    struct Stalling(File);
    impl Write for Stalling {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if buf.windows(12).any(|w| w == b"\"t\":\"signed\"") {
                std::thread::sleep(Duration::from_secs(120));
            }
            self.0.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    /// The child entry (a no-op unless re-executed by `command`).
    #[test]
    fn child_process_entry() {
        let (Some(db), Some(store), Some(wall)) = (
            std::env::var_os(DB_ENV),
            std::env::var_os(STORE_ENV),
            std::env::var_os(WALL_ENV),
        ) else {
            return;
        };
        let clock = VirtualClock::at(wall.to_str().unwrap().parse().unwrap());
        let out = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/fd/3")
            .unwrap();
        let store = Box::new(ScratchSecretStore::new(PathBuf::from(store)));
        let status = if std::env::var_os(STALL_ENV).is_some() {
            child::run(
                std::io::stdin(),
                Stalling(out),
                store,
                Path::new(&db),
                clock,
            )
        } else {
            child::run(std::io::stdin(), out, store, Path::new(&db), clock)
        };
        std::process::exit(status);
    }

    /// The child command for `w`.
    pub(super) fn command(w: &World, stall: bool) -> ChildCommand {
        let exe = std::env::current_exe().unwrap();
        let mut env = vec![
            (DB_ENV.into(), w.db.clone().into_os_string()),
            (
                STORE_ENV.into(),
                w.dir.path().join("store").into_os_string(),
            ),
            (WALL_ENV.into(), w.wall().to_string().into()),
        ];
        if stall {
            env.push((STALL_ENV.into(), "1".into()));
        }
        ChildCommand {
            program: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".into(),
                "exec 3>&1 1>/dev/null 2>/dev/null; exec \"$0\" --exact process::child_process_entry --nocapture --test-threads=1 -q".into(),
                exe.into_os_string(),
            ],
            env,
        }
    }

    /// The start token: `ps -o lstart=` (equal strings ⇔ the same process).
    pub(super) fn start_token(pid: u32) -> Option<String> {
        let out = std::process::Command::new("ps")
            .args(["-o", "lstart=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
        (!s.is_empty()).then_some(s)
    }

    fn alive(pid: u32) -> bool {
        start_token(pid).is_some()
    }

    fn kill_exact(pid: u32) {
        let status = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn client(w: &World, stall: bool) -> ChildIssuer {
        ChildIssuer::new(ClientConfig::new(command(w, stall), Arc::new(start_token)))
    }

    #[tokio::test]
    async fn client_start_sign_status_identity() {
        let w = World::new().await;
        let k = w.key();
        let entry = w.reserve(&k).await;
        let issuer = client(&w, false);
        issuer.start().await.unwrap();
        assert_eq!(issuer.state(), IssuerState::Ready);
        let id = issuer.identity().unwrap();
        assert!(id.start_token.is_some());
        assert_eq!(
            start_token(id.pid),
            id.start_token,
            "exact PID + start token"
        );
        let cert = issuer
            .sign(grant_ref(&entry), &k.openssh_line)
            .await
            .unwrap();
        let cert = ssh_key::Certificate::from_openssh(&cert).unwrap();
        validate_installed(&cert, &entry.bounds, &k.fingerprint, &w.ca).unwrap();
        let (cas, signed, refused) = issuer.child_status().await.unwrap();
        assert_eq!(cas.len(), 1);
        assert_eq!((signed, refused), (1, 0));
        issuer.stop().await;
        assert!(!alive(id.pid));
    }

    #[tokio::test]
    async fn late_reply_after_drop_is_discarded_and_nothing_published() {
        let w = World::new().await;
        let k = w.key();
        let late = w.reserve(&k).await;
        let next = w.reserve(&k).await;
        let issuer = client(&w, false);
        issuer.start().await.unwrap();
        // The adapter's future is dropped before the reply arrives.
        // `biased`: the sign is polled first (it writes its frame and waits for the
        // reply), then the ready branch wins and the sign future is dropped.
        tokio::select! {
            biased;
            _ = issuer.sign(grant_ref(&late), &k.openssh_line) => panic!("not dropped in time"),
            () = std::future::ready(()) => {}
        }
        // The next request drains the late reply (zeroized, matched to nothing) and
        // gets its own certificate, for its own entry.
        let cert = issuer
            .sign(grant_ref(&next), &k.openssh_line)
            .await
            .unwrap();
        let cert = ssh_key::Certificate::from_openssh(&cert).unwrap();
        assert_eq!(cert.serial(), next.bounds.serial);
        validate_installed(&cert, &next.bounds, &k.fingerprint, &w.ca).unwrap();
        // The child did sign the late one: two signatures, one certificate returned.
        let (_, signed, _) = issuer.child_status().await.unwrap();
        assert_eq!(signed, 2);
        // Nothing was published: both entries are still `reserved` and counted.
        assert_eq!(w.entry(&late.id).state, IssuanceState::Reserved);
        assert_eq!(w.entry(&next.id).state, IssuanceState::Reserved);
        assert_eq!(w.residual(), Some(late.bounds.valid_before));
        issuer.stop().await;
    }

    #[tokio::test]
    async fn issuer_crash_mid_sign_reservation_counted_never_published() {
        let w = World::new().await;
        let k = w.key();
        let entry = w.reserve(&k).await;
        let issuer = client(&w, true);
        issuer.start().await.unwrap();
        let pid = issuer.identity().unwrap().pid;
        let signing = {
            let issuer = issuer.clone();
            let line = k.openssh_line.clone();
            let r = grant_ref(&entry);
            tokio::spawn(async move { issuer.sign(r, &line).await })
        };
        // The child signed and is stalled before its reply: kill it by exact PID.
        tokio::time::sleep(Duration::from_millis(500)).await;
        kill_exact(pid);
        let r = signing.await.unwrap();
        assert!(matches!(r, Err(IssuerError::Unavailable(_))), "{r:?}");
        // The reservation stays counted and is never published.
        assert_eq!(w.entry(&entry.id).state, IssuanceState::Reserved);
        assert_eq!(w.residual(), Some(entry.bounds.valid_before));
        assert!(!alive(pid));
        // The supervisor restarts it; a new process, not the dead one.
        for _ in 0..100 {
            if issuer.state() == IssuerState::Ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(issuer.state(), IssuerState::Ready);
        assert_ne!(issuer.identity().unwrap().pid, pid);
        issuer.stop().await;
    }

    /// The runtime role: a process of this test binary that starts the issuer, writes
    /// the child's PID, and waits to be killed.
    #[test]
    fn runtime_process_entry() {
        let Some(pidfile) = std::env::var_os(RUNTIME_ENV) else {
            return;
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let cmd = ChildCommand {
                program: PathBuf::from(std::env::var_os("HM_U3_RT_PROGRAM").unwrap()),
                args: vec![
                    "-c".into(),
                    std::env::var_os("HM_U3_RT_SCRIPT").unwrap(),
                    std::env::current_exe().unwrap().into_os_string(),
                ],
                env: Vec::new(),
            };
            let issuer = ChildIssuer::new(ClientConfig::new(cmd, Arc::new(start_token)));
            issuer.start().await.unwrap();
            std::fs::write(&pidfile, issuer.identity().unwrap().pid.to_string()).unwrap();
            tokio::time::sleep(Duration::from_secs(300)).await;
        });
    }

    #[tokio::test]
    async fn runtime_death_closes_issuer() {
        let w = World::new().await;
        let pidfile = w.dir.path().join("issuer.pid");
        let child = command(&w, false);
        let mut runtime = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::runtime_process_entry",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env(RUNTIME_ENV, &pidfile)
            .env("HM_U3_RT_PROGRAM", &child.program)
            .env("HM_U3_RT_SCRIPT", &child.args[1])
            .envs(child.env.iter().map(|(k, v)| (k, v)))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut issuer_pid = None;
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&pidfile)
                && let Ok(p) = s.trim().parse::<u32>()
            {
                issuer_pid = Some(p);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let issuer_pid = issuer_pid.expect("the runtime started its issuer");
        assert!(alive(issuer_pid));
        // Kill the runtime by the exact PID this test spawned.
        runtime.kill().unwrap();
        runtime.wait().unwrap();
        let start = std::time::Instant::now();
        while alive(issuer_pid) && start.elapsed() < Duration::from_secs(2) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !alive(issuer_pid),
            "the issuer saw EOF and exited within 2 s"
        );
    }

    /// The issuer/client part of the lifecycle (start, issue, restart, stop): no
    /// `issuer.sock` exists in the runtime directory at any step, and the child holds
    /// no path to connect to (ADR-0008 Q1). The runtime's own start/stop is U10's.
    #[tokio::test]
    async fn issuer_path_never_exists_through_runtime_lifecycle() {
        let w = World::new().await;
        let k = w.key();
        let runtime_dir = w.dir.path().join("run");
        std::fs::create_dir(&runtime_dir).unwrap();
        let path = runtime_dir.join("issuer.sock");
        let mut cmd = command(&w, false);
        cmd.env.push(("HEIMDALL_HOME".into(), w.dir.path().into()));
        let issuer = ChildIssuer::new(ClientConfig::new(cmd, Arc::new(start_token)));
        assert!(!path.exists());
        issuer.start().await.unwrap();
        assert!(!path.exists());
        let entry = w.reserve(&k).await;
        issuer
            .sign(grant_ref(&entry), &k.openssh_line)
            .await
            .unwrap();
        assert!(!path.exists());
        issuer.stop().await;
        assert!(!path.exists());
        issuer.start().await.unwrap();
        assert!(!path.exists());
        issuer.stop().await;
        assert!(!path.exists());
        assert!(std::fs::read_dir(&runtime_dir).unwrap().next().is_none());
    }
}
