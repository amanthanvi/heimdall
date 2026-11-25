//! Spec §14.3 "a stopped service recovering with a stale signing handle", the held-connection
//! case (m08-plan §7.1, added by W2-2): a client that keeps its connection to a binding's
//! endpoint open across the runtime's stop cannot sign through it afterwards, and the restarted
//! runtime serves nothing for the lost instance.
//!
//! * **Before the stop**, the held connection lists the grant's certificate and is answered
//!   with a signature: the production `heimdall_app::Operations` is the signature authority
//!   (an in-memory store, the fake credential adapter, the grant's gate retained), the
//!   signer table holds the key, and the endpoint is the `EndpointRegistry`'s real listener.
//! * **The stop** is what the runtime's managed teardown does (`ManagedTeardown::release` in
//!   `crates/runtime/src/service.rs`): the vault is zeroized (`KeyVault::destroy_all`) and every
//!   endpoint stopped (`EndpointRegistry::stop_all`), then the operations are dropped. The held
//!   connection's next sign request is answered with no signature (its connection task ended
//!   with the endpoint's accept loop; what it reads is end of stream), and the old locator
//!   serves nothing.
//! * **The restart** opens new operations over the same store with a fresh, empty vault and
//!   table, as `crash_after_install_makes_instance_lost_at_restart`
//!   (`tests/integration/managed_signer.rs`) does: the binding's endpoint at a new generation
//!   lists nothing and answers the old request with the agent's failure frame.
//!
//! Cargo test target `adversarial_stale_signing_handle`, hosted by `heimdall-credential`. The
//! CA and every key are generated per run; the listener lives in a scratch directory
//! (`heimdall_testkit::home::Scratch`); no client program runs. Unix and Windows (the pipe
//! form of the endpoint), as the registry tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::operations::Limits;
use heimdall_app::operations::narrowing::AuthorizationTime;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
    SignatureAuthority,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, DestinationId, DeviceId, EnvironmentId, GrantId, IssuanceId, PolicyId, ProfileId,
    RequestId, WorkId,
};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::provider::EndpointRef;
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest, ExistingConnectionsPolicy,
    InteractionMode, NewAuthenticationExpiry, RefreshDependency, RequiredCapabilities,
    RevocationStatus, WaitMode, WorkloadIsolation,
};
use heimdall_credential::cert::{self, CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_credential::endpoints::{EndpointLayout, EndpointRegistry};
use heimdall_credential::signer::SignerLimits;
use heimdall_credential::table::{InstallRefusal, InstallView, SignerTable, grant_comment};
use heimdall_credential::vault::{KeyVault, SystemRng};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::issuance::{
    CertificateBounds, EXTENSION_PTY, IssuanceEntry, IssuanceState, principal_for,
};
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::resource::ResourceGeneration;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimeAnchor, TimePolicy};
use heimdall_ipc::endpoint::ExpectedOwner;
use heimdall_ipc::signing::failure_frame;
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::home::Scratch;
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const HOUR: Duration = Duration::from_secs(3600);

// --- the world: Operations over an in-memory store, a signer table, a CA ------------------

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    t.checked_add(d).unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRng::fill(&mut b).unwrap();
    b
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

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: plus(t0(), 12 * HOUR),
        offline_until: plus(t0(), HOUR),
        refresh_dependency: RefreshDependency::None,
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
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

fn descriptor() -> AdapterDescriptor {
    AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        },
        capabilities: ssh_only(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: outcome().enforcement,
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

fn seed(store: &Store) {
    let pairs: BTreeSet<AccessPair> = [h1()].into_iter().collect();
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
                    pairs: pairs.clone(),
                    capabilities: ssh_only(),
                },
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs,
                        capabilities: ssh_only(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: Default::default(),
                    default: false,
                },
                false,
            )?;
            Ok(())
        })
        .unwrap();
}

/// The operations clock on the tokio clock: wall `t0 + elapsed`, one boot.
struct TokioClock {
    start: tokio::time::Instant,
}

impl Clock for TokioClock {
    fn wall(&self) -> Timestamp {
        plus(t0(), self.start.elapsed())
    }
    fn continuous(&self) -> Duration {
        Duration::from_secs(1000) + self.start.elapsed()
    }
    fn boot_id(&self) -> BootId {
        BootId("tokio-boot-1".into())
    }
    fn observe(&self) -> TimeAnchor {
        TimeAnchor {
            wall: self.wall(),
            continuous: self.continuous(),
            boot_id: self.boot_id(),
        }
    }
}

/// Accepts every installation the table's own checks pass.
struct AcceptView;

#[async_trait]
impl InstallView for AcceptView {
    async fn check(&self, _grant: &GrantId, _entry: &IssuanceEntry) -> Result<(), InstallRefusal> {
        Ok(())
    }
}

struct World {
    store: Arc<Store>,
    clock: Arc<TokioClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    ops: Operations,
    vault: Arc<KeyVault>,
    table: SignerTable,
}

async fn start(
    store: Arc<Store>,
    clock: Arc<TokioClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
) -> World {
    let ops = OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    };
    let ops = Operations::start(ops).await.unwrap();
    ops.set_authorization_time(AuthorizationTime::ReadOnly);
    let vault = Arc::new(KeyVault::new());
    let table = SignerTable::new(vault.clone());
    table.set_install_view(Arc::new(AcceptView));
    World {
        store,
        clock,
        sync,
        fake,
        ops,
        vault,
        table,
    }
}

async fn world() -> World {
    let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
    seed(&store);
    let clock = Arc::new(TokioClock {
        start: tokio::time::Instant::now(),
    });
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let fake = FakeCredentialAdapter::new(descriptor(), vec![FakeStep::Prepare(outcome())]);
    start(store, clock, sync, fake).await
}

impl World {
    fn authority(&self) -> Arc<dyn SignatureAuthority> {
        Arc::new(self.ops.clone())
    }

    /// An active grant for `h1`, gated, its key generated and one certificate installed by a
    /// per-run CA (real wall time, an hour of validity), and its binding attached.
    async fn grant(&self, ca: &SecretCaKey) -> (EnsureData, Vec<u8>) {
        let data = self
            .ops
            .ensure(
                &Caller::unattended(CallerContext {
                    principal: PrincipalRef::UnixUser { uid: 501 },
                    role: ClientRole::Owner,
                    remote_client: None,
                }),
                EnsureRequest {
                    profile: Some(ProfileId::parse("dev").unwrap()),
                    profile_revision: None,
                    scope: [h1()].into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse("w-held").unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse("r-held").unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                    context: None,
                    covered_only: false,
                    pair_issuers: Vec::new(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message))
            .data;
        self.ops.signing_gates().retain(&data.grant_id, &[]);
        let gid = data.grant_id.clone();
        self.table.generate(&gid, &[h1()]).unwrap();
        let key = self.table.public_key(&gid).unwrap();
        let now = Timestamp::now().as_second();
        let serial = u64::from_be_bytes(random::<8>());
        let bounds = CertificateBounds {
            serial,
            key_id: cert::key_id(&env_id(), &gid, serial),
            principal: principal_for(&h1()),
            valid_after: cert::valid_after_for(Timestamp::from_second(now).unwrap()).unwrap(),
            valid_before: Timestamp::from_second(now + 3600).unwrap(),
            extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
            subject_fingerprint: key.fingerprint.clone(),
            ca_fingerprint: Some(ca.fingerprint().unwrap()),
        };
        let certificate = build_and_sign(
            &CertificateProfile::from_bounds(&bounds),
            &key.public_key().unwrap(),
            ca,
        )
        .unwrap();
        let entry = IssuanceEntry {
            id: IssuanceId::from_random_bytes(random()),
            grant: gid.clone(),
            generation: AuthorityGeneration(0),
            pair: h1(),
            bounds,
            state: IssuanceState::Published,
            reserved_at: Timestamp::from_second(now).unwrap(),
            settled_at: Some(Timestamp::from_second(now).unwrap()),
            void_reason: None,
            continuing: false,
        };
        self.table
            .install(&gid, &h1(), &certificate, &entry)
            .await
            .unwrap();
        self.table.attach_binding(&data.binding_id, &gid);
        (data, certificate.to_bytes().unwrap())
    }

    fn registry(&self, dir: &std::path::Path) -> EndpointRegistry {
        #[cfg(unix)]
        let (layout, owner) = (
            EndpointLayout::unix(dir).unwrap(),
            ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()),
        );
        #[cfg(windows)]
        let (layout, owner) = {
            let _ = dir;
            let token = heimdall_credential::endpoints::EndpointTag::generate().unwrap();
            (
                EndpointLayout::windows(&format!("u1b{token}")).unwrap(),
                ExpectedOwner::Sid(heimdall_ipc::windows::current_user_sid().unwrap()),
            )
        };
        EndpointRegistry::new(
            layout,
            owner,
            self.table.clone(),
            self.authority(),
            SignerLimits::from_limits(&Limits::default()),
            CancellationToken::new(),
        )
    }
}

// --- the agent wire ------------------------------------------------------------------------

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s);
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// A sign request for a userauth (RFC 4252 §7) of `h1`'s account presenting `cert`.
fn sign_req(cert: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    put_string(&mut data, &[0x5a; 32]);
    data.push(50);
    put_string(&mut data, b"deploy");
    put_string(&mut data, b"ssh-connection");
    put_string(&mut data, b"publickey");
    data.push(1);
    put_string(&mut data, b"ssh-ed25519-cert-v01@openssh.com");
    put_string(&mut data, cert);
    let mut body = vec![13];
    put_string(&mut body, cert);
    put_string(&mut body, &data);
    body.extend_from_slice(&0u32.to_be_bytes());
    framed(&body)
}

async fn read_frame(r: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut h = [0u8; 4];
    r.read_exact(&mut h).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(h) as usize];
    r.read_exact(&mut body).await.ok()?;
    let mut out = h.to_vec();
    out.extend_from_slice(&body);
    Some(out)
}

fn is_signature(frame: &[u8]) -> bool {
    frame.get(4) == Some(&14)
}

fn identities(frame: &[u8]) -> Vec<(Vec<u8>, String)> {
    assert_eq!(frame.get(4), Some(&12), "an identities answer");
    let take = |c: &mut &[u8]| {
        let n = u32::from_be_bytes(c[..4].try_into().unwrap()) as usize;
        let s = c[4..4 + n].to_vec();
        *c = &c[4 + n..];
        s
    };
    let mut c = &frame[5..];
    let n = u32::from_be_bytes(c[..4].try_into().unwrap());
    c = &c[4..];
    (0..n)
        .map(|_| {
            let blob = take(&mut c);
            (blob, String::from_utf8(take(&mut c)).unwrap())
        })
        .collect()
}

trait Duplex: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Duplex for T {}

#[cfg(unix)]
async fn connect(endpoint: &EndpointRef) -> std::io::Result<Box<dyn Duplex>> {
    heimdall_ipc::unix::connect(std::path::Path::new(&endpoint.locator))
        .await
        .map(|s| Box::new(s) as Box<dyn Duplex>)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

#[cfg(windows)]
async fn connect(endpoint: &EndpointRef) -> std::io::Result<Box<dyn Duplex>> {
    heimdall_ipc::windows::connect_with_owner(
        std::path::Path::new(&endpoint.locator),
        heimdall_ipc::windows::ServerOwner::CurrentUser,
    )
    .await
    .map(|s| Box::new(s) as Box<dyn Duplex>)
}

/// One exchange on `conn`: the request written, then one frame read (bounded); `None` when
/// the write fails, the stream ends, or nothing arrives within 5 s.
async fn exchange(conn: &mut Box<dyn Duplex>, request: &[u8]) -> Option<Vec<u8>> {
    if conn.write_all(request).await.is_err() {
        return None;
    }
    tokio::time::timeout(Duration::from_secs(5), read_frame(conn))
        .await
        .ok()
        .flatten()
}

/// The endpoint at `e` serves nothing: connecting fails, or a connection is never answered
/// (within a bound, for the pipe instances an aborted accept loop closes asynchronously).
async fn serves_nothing(e: &EndpointRef) -> bool {
    for _ in 0..200 {
        match connect(e).await {
            Err(_) => return true,
            Ok(mut c) => {
                if exchange(&mut c, &framed(&[11])).await.is_none() {
                    return true;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

// --- the test ----------------------------------------------------------------------------

#[tokio::test]
async fn held_binding_connection_cannot_sign_across_the_stop_and_restart() {
    let w = world().await;
    let ca = SecretCaKey::generate().unwrap();
    let (data, cert) = w.grant(&ca).await;
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("r").unwrap();
    let reg = w.registry(&dir);
    let e1 = reg
        .create_binding(&data.binding_id, ResourceGeneration(1))
        .unwrap();

    // The client connects and keeps the connection: it lists the certificate and is signed for.
    let mut held = connect(&e1).await.unwrap();
    let listed = identities(&exchange(&mut held, &framed(&[11])).await.unwrap());
    assert_eq!(listed, vec![(cert.clone(), grant_comment(&data.grant_id))]);
    let before = exchange(&mut held, &sign_req(&cert)).await.unwrap();
    assert!(
        is_signature(&before),
        "the held connection signs before the stop"
    );

    // The stop, as the runtime's managed teardown: zeroize, stop every endpoint, drop.
    w.vault.destroy_all();
    reg.stop_all();
    let World {
        store,
        clock,
        sync,
        fake,
        ops,
        table,
        ..
    } = w;
    drop(ops);
    drop(table);
    drop(reg);

    // The held connection signs nothing now, and nothing answers at the old locator.
    let after = exchange(&mut held, &sign_req(&cert)).await;
    assert!(
        after.as_deref().is_none_or(|f| !is_signature(f)),
        "a held connection signed after the stop"
    );
    assert!(after.is_none() || after.as_deref() == Some(failure_frame().as_slice()));
    assert!(
        serves_nothing(&e1).await,
        "the old locator serves after the stop"
    );

    // The restart over the same store: a fresh vault and table; the binding's endpoint at a new
    // generation lists nothing for the lost instance and refuses the old request.
    let w2 = start(store, clock, sync, fake).await;
    w2.table.attach_binding(&data.binding_id, &data.grant_id);
    let reg2 = w2.registry(&dir);
    let e2 = reg2
        .create_binding(&data.binding_id, ResourceGeneration(2))
        .unwrap();
    assert_ne!(e2.locator, e1.locator);
    let mut fresh = connect(&e2).await.unwrap();
    assert!(identities(&exchange(&mut fresh, &framed(&[11])).await.unwrap()).is_empty());
    let refused = exchange(&mut fresh, &sign_req(&cert)).await.unwrap();
    assert_eq!(refused, failure_frame());
    reg2.stop_all();
}
