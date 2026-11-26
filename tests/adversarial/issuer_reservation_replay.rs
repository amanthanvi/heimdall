//! Spec §14.3 "a stopped service recovering with a stale signing handle", the issuer case
//! (m08-plan §7.1, added by W2-2): a reservation made before the runtime restarted,
//! replayed to the restarted issuer child.
//!
//! Cargo test target `adversarial_issuer_reservation_replay`, hosted by `heimdall-issuer`.
//! The harness is `tests/integration/issuer_child.rs`'s, trimmed: a state database in a
//! scratch directory seeded through the production store, the production
//! `heimdall_app::Operations` on a `VirtualClock`, a real K_ca generated per run in a per-run
//! `ScratchSecretStore`, K_env keys of a per-run `KeyVault` (only public lines leave it), and
//! the child running in process (`child::run` on a thread over two OS pipes). Nothing here
//! touches an owner key, agent, keychain or store.
//!
//! **What holds, and what does not (observed 2026-11-24 at `c113e3f5`, reported by U1b).**
//! Restart recovery leaves the entry `reserved` by design (`mark_lost_in`: "issuance entries
//! are untouched, so their residual stays counted"), and the grant `degraded`
//! (`credential_reissue_pending`, a reason that does not refuse issuance). So:
//!
//! * **within the reservation's 60 s** the restarted child signs the replay again: a second
//!   certificate with the reservation's exact bounds, for the reservation's own subject only
//!   (the K_env whose private half the old runtime held and lost), nothing published, the
//!   residual unchanged. This is **not** the refusal m08-plan §7.1 expected; the test pins
//!   what bounds it. The M08 track lead ruled it a stated residual for 1.0 (ADR-0009 §2.1: the
//!   replay needs the issuer channel, which only the runtime holds; `docs/user/limitations.md`).
//!   The later hardening, not built: when the reservation row identifies the runtime instance
//!   that made it, the issuer refuses a reservation from an earlier instance;
//! * a replay for **any other subject key** is refused (`subject_mismatch`): a stale
//!   reservation cannot be redirected to another key;
//! * **after the 60 s** the replay is refused (`entry_stale`), and so is one after the grant
//!   was revoked, whatever its age.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::issuance_ro;
use heimdall_app::operations::{IssuanceRequest, Limits, MANAGED_CERTIFICATE};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, CaFingerprint, CredentialInstanceId, DestinationId, DeviceId, EnrollmentId,
    EnvironmentId, GrantId, IdentityId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, EnsureRequest, ExistingConnectionsPolicy,
    InteractionMode, NewAuthenticationExpiry, RefreshDependency, RequiredCapabilities,
    RevocationStatus, WaitMode, WorkloadIsolation,
};
use heimdall_credential::cert::SecretCaKey;
use heimdall_credential::vault::{KeyVault, PublicKeyInfo};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::DegradedReason;
use heimdall_domain::issuance::{
    CredentialInstance, CredentialState, EXTENSION_PTY, IssuanceEntry, IssuanceState,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_issuer::child;
use heimdall_issuer::protocol::{
    IssuanceRef, IssuanceTable, IssuerRefusal, LoadedCa, PROTOCOL, Request, Response, split_frame,
};
use heimdall_issuer::store::SecretStore;
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::scratch_store::ScratchSecretStore;
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock};

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

fn h1() -> AccessPair {
    AccessPair {
        destination: DestinationId::parse("h1").unwrap(),
        account: AccountName::parse("deploy").unwrap(),
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
            ordinary_aliases: None,
            owner_functions: None,
        },
        evidence: Vec::new(),
    }
}

fn adapter() -> Arc<FakeCredentialAdapter> {
    let outcome = PrepareOutcome {
        usable_until: shift(t0(), 12 * 3600),
        offline_until: shift(t0(), 3600),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    };
    let descriptor = AdapterDescriptor {
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
    };
    FakeCredentialAdapter::new(
        descriptor,
        (0..8).map(|_| FakeStep::Prepare(outcome.clone())),
    )
}

fn enrollment(ca: &CaFingerprint) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([1; 16]);
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
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
    }
}

/// The world: a file database, a real K_ca in a scratch store, one verified enrollment for
/// h1, one active grant, and the runtime's operations (replaced by [`World::restart`]).
// ⟨M08 W3; PC job 64⟩ Fields drop in declaration order, so the temporary directory comes last:
// every handle on its files (the store, the operations) is dropped first. On Windows an open
// file cannot be deleted, and `TempDir`'s drop swallows the error, which left fixture
// directories in TEMP.
struct World {
    db: PathBuf,
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    ops: Option<Operations>,
    ca: CaFingerprint,
    grant: GrantId,
    keys: KeyVault,
    dir: tempfile::TempDir,
}

async fn start(store: &Arc<Store>, clock: &Arc<VirtualClock>) -> Operations {
    Operations::start(OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![adapter() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap()
}

impl World {
    async fn new() -> World {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.db");
        let store = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
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
            public_key: ca_public,
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
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("pol").unwrap(),
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
                        lock_behavior: LockBehavior::Continue,
                        connection: ConnectionPolicy::default(),
                        default: false,
                    },
                    false,
                )?;
                tx.upsert_destination(&DestinationRecord {
                    id: h1().destination,
                    alias: "h1".into(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: t0(),
                })?;
                tx.insert_issuer(&rec)?;
                tx.seed_enrollment(&enrollment(&ca))?;
                Ok(())
            })
            .unwrap();
        let clock = VirtualClock::at(t0());
        let ops = start(&store, &clock).await;
        let ensured = ops
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
                    work_id: WorkId::parse("w-replay").unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse("replay").unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                    context: None,
                    covered_only: false,
                    pair_issuers: Vec::new(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
        World {
            db,
            store,
            clock,
            ops: Some(ops),
            ca,
            grant: ensured.data.grant_id,
            keys: KeyVault::new(),
            dir,
        }
    }

    fn ops(&self) -> &Operations {
        self.ops.as_ref().unwrap()
    }

    fn wall(&self) -> Timestamp {
        Clock::wall(self.clock.as_ref())
    }

    async fn reserve(&self, subject: &PublicKeyInfo) -> IssuanceEntry {
        self.ops()
            .reserve_issuance(IssuanceRequest {
                grant: self.grant.clone(),
                pair: h1(),
                principal: "hm:h1:deploy".into(),
                valid_after: shift(self.wall(), -60),
                valid_before: shift(self.wall(), 1800),
                extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
                subject_fingerprint: subject.fingerprint.clone(),
                facts: issuance_ro::ISSUER_FACTS,
            })
            .await
            .unwrap_or_else(|e| panic!("reserve: {} {}", e.code, e.message))
    }

    fn entry(&self, entry: &IssuanceEntry) -> IssuanceEntry {
        self.store
            .transaction(|tx| tx.issuance_entries(&self.grant))
            .unwrap()
            .into_iter()
            .find(|e| e.id == entry.id)
            .unwrap()
    }

    /// The runtime's restart: the operations dropped, then started again over the same
    /// store and clock, which runs restart recovery.
    async fn restart(&mut self) {
        drop(self.ops.take());
        self.ops = Some(start(&self.store, &self.clock).await);
    }

    fn child(&self) -> InProc {
        let (r1, w1) = std::io::pipe().unwrap();
        let (r2, w2) = std::io::pipe().unwrap();
        #[cfg(unix)]
        let stdin = File::from(std::os::fd::OwnedFd::from(r1));
        #[cfg(windows)]
        let stdin = File::from(std::os::windows::io::OwnedHandle::from(r1));
        let db = self.db.clone();
        let clock: Arc<dyn Clock> = self.clock.clone();
        let store: Box<dyn SecretStore> =
            Box::new(ScratchSecretStore::new(self.dir.path().join("store")));
        let handle = std::thread::spawn(move || child::run(stdin, w2, store, &db, clock));
        let mut c = InProc {
            to: Some(w1),
            from: r2,
            buf: Vec::new(),
            handle,
        };
        assert!(matches!(
            c.call(&Request::Hello {
                protocol: PROTOCOL.into(),
                nonce: "0123456789abcdef0123456789abcdef".into(),
            }),
            Response::HelloAck { .. }
        ));
        assert_eq!(
            c.call(&Request::Load {}),
            Response::Loaded {
                cas: vec![LoadedCa {
                    fingerprint: self.ca.clone(),
                    state: CaState::Active,
                }]
            }
        );
        c
    }
}

/// A child running `child::run` on a thread over two OS pipes.
struct InProc {
    to: Option<std::io::PipeWriter>,
    from: std::io::PipeReader,
    buf: Vec<u8>,
    handle: std::thread::JoinHandle<i32>,
}

impl InProc {
    fn call(&mut self, r: &Request) -> Response {
        let _ = self.to.as_mut().unwrap().write_all(&r.encode().unwrap());
        loop {
            if let Some((body, used)) = split_frame(&self.buf).unwrap() {
                let r = Response::decode(body).unwrap();
                self.buf.drain(..used);
                return r;
            }
            let mut c = [0u8; 4096];
            let n = self.from.read(&mut c).unwrap_or(0);
            assert!(n > 0, "the child closed its channel");
            self.buf.extend_from_slice(&c[..n]);
        }
    }

    fn sign(&mut self, entry: &IssuanceEntry, subject: &str, n: u32) -> Response {
        self.call(&Request::Sign {
            request_id: format!("{n:032x}"),
            reservation: IssuanceRef {
                table: IssuanceTable::Grant,
                id: entry.id.clone(),
            },
            subject_public_key: subject.to_owned(),
        })
    }

    fn finish(mut self) -> i32 {
        drop(self.to.take());
        self.handle.join().unwrap()
    }
}

/// The certificate a `signed` answer carries.
fn certificate(r: &Response) -> ssh_key::Certificate {
    match r {
        Response::Signed { certificate, .. } => {
            ssh_key::Certificate::from_openssh(certificate).unwrap()
        }
        other => panic!("expected a certificate, got {other:?}"),
    }
}

fn refusal(r: Response) -> IssuerRefusal {
    match r {
        Response::Refused { reason, .. } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A reservation made before the restart, replayed to the restarted child (module docs): the
/// grant had an installed instance, so restart recovery marks it lost and degrades the grant.
#[tokio::test]
async fn pre_restart_reservation_replay_is_bound_to_its_own_reservation_and_age() {
    let mut w = World::new().await;
    let k = w.keys.generate_ed25519().unwrap().1;
    let other = w.keys.generate_ed25519().unwrap().1;
    let entry = w.reserve(&k).await;
    let grant = w.grant.clone();
    w.store
        .transaction(|tx| {
            tx.insert_credential_instance(&CredentialInstance {
                id: CredentialInstanceId::from_random_bytes([3; 16]),
                grant: grant.clone(),
                key_handle_ref: "fixture-slot".into(),
                certificates: Vec::new(),
                state: CredentialState::Installed,
            })
        })
        .unwrap();
    let residual = |w: &World| {
        w.store
            .transaction(|tx| tx.issuance_residual(std::slice::from_ref(&w.grant)))
            .unwrap()
    };
    let counted = residual(&w);
    assert_eq!(counted, Some(entry.bounds.valid_before));

    // Before the restart: the runtime's child signs the entry; the reply is lost with the
    // runtime, so nothing is published.
    let mut first = w.child();
    let before = certificate(&first.sign(&entry, &k.openssh_line, 1));
    assert_eq!(first.finish(), 0);

    // The restart: recovery marks the instance lost and degrades the grant; the entry stays
    // reserved and counted.
    w.restart().await;
    let (state, reason) = w
        .store
        .transaction(|tx| {
            Ok((
                tx.grant(&grant)?.unwrap().state,
                tx.grant_degradation(&grant)?,
            ))
        })
        .unwrap();
    assert_eq!(state, GrantState::Degraded);
    assert_eq!(reason, Some(DegradedReason::CredentialReissuePending));
    assert_eq!(w.entry(&entry).state, IssuanceState::Reserved);

    // The replay to the restarted child, within the reservation's 60 s.
    let mut second = w.child();
    assert_eq!(
        refusal(second.sign(&entry, &other.openssh_line, 2)),
        IssuerRefusal::SubjectMismatch,
        "a stale reservation is never redirected to another key"
    );
    let replayed = certificate(&second.sign(&entry, &k.openssh_line, 3));
    // Observed: signed again (module docs). Bound: the reservation's exact bounds, its own
    // subject, nothing published, the residual unchanged.
    assert_eq!(replayed.serial(), entry.bounds.serial);
    assert_eq!(replayed.serial(), before.serial());
    assert_eq!(replayed.key_id(), entry.bounds.key_id);
    assert_eq!(
        replayed.valid_principals(),
        std::slice::from_ref(&entry.bounds.principal)
    );
    assert_eq!(
        replayed.valid_before(),
        u64::try_from(entry.bounds.valid_before.as_second()).unwrap()
    );
    assert_eq!(replayed.public_key(), before.public_key());
    assert_eq!(w.entry(&entry).state, IssuanceState::Reserved);
    assert_eq!(residual(&w), counted);

    // Past the reservation's 60 s: refused, the entry still counted.
    w.clock.advance(Duration::from_secs(61));
    assert_eq!(
        refusal(second.sign(&entry, &k.openssh_line, 4)),
        IssuerRefusal::EntryStale
    );
    assert_eq!(second.finish(), 0);
    assert_eq!(w.entry(&entry).state, IssuanceState::Reserved);
}

/// After the restart, a revocation of the grant refuses a replay of its pre-restart
/// reservation whatever its age (the issuer re-runs the predicate in its own read).
#[tokio::test]
async fn pre_restart_reservation_replay_is_refused_after_revocation() {
    let mut w = World::new().await;
    let k = w.keys.generate_ed25519().unwrap().1;
    let entry = w.reserve(&k).await;
    w.restart().await;
    w.ops()
        .revoke(
            &Caller::unattended(CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
                remote_client: None,
            }),
            heimdall_contract::request::RevokeRequest {
                grant_id: Some(w.grant.clone()),
                request_id: RequestId::parse("replay-revoke").unwrap(),
                target: None,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("revoke: {} {}", e.code, e.message));
    let mut child = w.child();
    let reason = refusal(child.sign(&entry, &k.openssh_line, 1));
    assert!(
        matches!(
            reason,
            IssuerRefusal::Issuance(_) | IssuerRefusal::EntryNotReserved
        ),
        "{reason:?}"
    );
    assert_eq!(child.finish(), 0);
}
