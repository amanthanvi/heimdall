//! ⟨M06 W3 host⟩ The issuer's reservation kind `remote` (ADR-0005 §3.5 "Remote
//! reservations", the amendment of 2026-11-21): a reservation for a grant that lives on a
//! paired runner is signed only when conditions 1–7 all hold in this controller's own store,
//! and each condition refuses when it is violated.
//!
//! The world is a controller's state database (a scratch file), a per-run K_ca in a scratch
//! secret store, one recorded runner, one grant this controller delivered to it, the key
//! binding of a verified prepare answer and a reservation. The checks run through
//! `check::assess_remote_reservation` (the exact condition) and through the real issuer child
//! (`child::run` over two pipes: the certificate, and the wire refusal). Disposable state
//! only; no platform key store is touched.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ports::{IssuanceRef, IssuanceTable, IssuerRefusal};
use heimdall_app::timegate::TimeGate;
use heimdall_contract::Timestamp;
use heimdall_contract::controller_record::{ManagementHop, ManagementRoute, RemoteEnvironmentPin};
use heimdall_contract::ids::{
    AccountName, CaFingerprint, ClientId, DestinationId, EffectId, EnvironmentId, GrantId,
    IssuanceId, KeyFingerprint, PolicyId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::remote::{EffectTarget, Role};
use heimdall_contract::request::AccessPairRef;
use heimdall_credential::cert::{SecretCaKey, validate_installed};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo};
use heimdall_domain::issuance::{
    CaEvent, CertificateBounds, IssuanceEntry, IssuanceRefusal, IssuanceState, principal_for,
};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_issuer::check::{RemoteCheckRefusal, assess_remote_reservation};
use heimdall_issuer::child;
use heimdall_issuer::protocol::{PROTOCOL, Request, Response, body_len};
use heimdall_issuer::remote::{RemoteReservationRefusal as R, role_may_issue};
use heimdall_issuer::store::SecretStore;
use heimdall_store::ext_effects::{AuthorityReport, DeliveredGrant, EffectKey, PreparedBinding};
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::scratch_store::ScratchSecretStore;
use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

const HOUR: i64 = 3600;

fn t0() -> Timestamp {
    "2026-11-21T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    Timestamp::from_second(t.as_second() + secs).unwrap()
}

fn pair(d: &str) -> AccessPairRef {
    AccessPairRef {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

fn runner_env() -> EnvironmentId {
    EnvironmentId::from_random_bytes([0x52; 16])
}

fn own_env() -> EnvironmentId {
    EnvironmentId::from_random_bytes([0x0c; 16])
}

fn grant() -> GrantId {
    GrantId::from_random_bytes([0x71; 16])
}

fn client() -> ClientId {
    ClientId::from_random_bytes([0x5c; 16])
}

/// A controller with one runner, one delivered grant, its key binding and a reservation.
struct World {
    dir: tempfile::TempDir,
    db: PathBuf,
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    gate: TimeGate,
    ca: CaFingerprint,
    key: PublicKeyInfo,
    _vault: KeyVault,
    entry: IssuanceEntry,
}

fn pin(role: Role) -> RemoteEnvironmentPin {
    RemoteEnvironmentPin {
        environment: runner_env(),
        destination: DestinationId::parse("runner1").unwrap(),
        route: ManagementRoute {
            runner: ManagementHop {
                hostname: "runner1.example".into(),
                port: None,
                account: AccountName::parse("deploy").unwrap(),
                host_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into()],
            },
            jump: None,
        },
        client: client(),
        role,
        key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "K".repeat(43))).unwrap(),
        label: None,
        pinned_at: t0(),
    }
}

fn report() -> AuthorityReport {
    AuthorityReport {
        environment: runner_env(),
        authority_generation: 7,
        tombstones: Vec::new(),
        policy_revisions: Vec::new(),
        policies: Vec::new(),
        certificates: Vec::new(),
        time_bounded: true,
    }
}

fn put_pin(store: &Store, pin: &RemoteEnvironmentPin) {
    store
        .transaction(|tx| {
            tx.put_remote_environment_pin(
                &pin.environment,
                &pin.destination,
                &pin.route.runner.account,
                &pin.key_fingerprint,
                &serde_json::to_string(pin).unwrap(),
                pin.pinned_at,
            )
        })
        .unwrap();
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.db");
        let store = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
        let k_ca = SecretCaKey::generate().unwrap();
        let ca = k_ca.fingerprint().unwrap();
        std::fs::create_dir(dir.path().join("store")).unwrap();
        ScratchSecretStore::new(dir.path().join("store"))
            .put(&ca, &k_ca)
            .unwrap();
        let record = IssuerRecord {
            ca_fingerprint: ca.clone(),
            public_key: k_ca.public_openssh().unwrap(),
            state: CaState::Active,
            store_kind: StoreKind::LinuxSecretService,
            backup_sha256: "ab".repeat(32),
            backup_created_at: t0(),
            restored_without_log: false,
            created_at: t0(),
            retired_at: None,
        };
        drop(k_ca);
        store
            .transaction(|tx| {
                tx.init_self_environment(&own_env())?;
                tx.insert_issuer(&record)
            })
            .unwrap();
        put_pin(&store, &pin(Role::Owner));
        let clock = VirtualClock::at(t0());
        let gate = TimeGate::new(
            store.clone(),
            clock.clone(),
            ScriptedTimeSync::new(SyncStatus::Synchronized),
            TimePolicy::default(),
        );
        // The runtime's same-boot anchor: the child's read-only assessment needs one.
        gate.check().await.unwrap();
        let vault = KeyVault::new();
        let key = vault.generate_ed25519().unwrap().1;
        let now = t0();
        let serial = 4242;
        let entry = IssuanceEntry {
            id: IssuanceId::from_random_bytes([0x15; 16]),
            grant: grant(),
            generation: AuthorityGeneration(7),
            pair: pair("h1"),
            bounds: CertificateBounds {
                serial,
                key_id: format!("heimdall:{}:{}:{serial}", runner_env(), grant()),
                principal: principal_for(&pair("h1")),
                valid_after: shift(now, -60),
                valid_before: shift(now, HOUR),
                extensions: BTreeSet::from(["permit-pty".to_owned()]),
                subject_fingerprint: key.fingerprint.clone(),
                ca_fingerprint: Some(ca.clone()),
            },
            state: IssuanceState::Reserved,
            reserved_at: now,
            settled_at: None,
            void_reason: None,
            continuing: false,
        };
        let w = Self {
            dir,
            db,
            store,
            clock,
            gate,
            ca,
            key,
            _vault: vault,
            entry,
        };
        // The session's report, read at t0; the delivered grant with the answer's binding.
        w.store
            .transaction(|tx| {
                tx.note_remote_seen(&runner_env(), now)?;
                tx.note_remote_report(&runner_env(), now, &report())?;
                tx.put_delivered_grant(&w.delivered())
            })
            .unwrap();
        w
    }

    fn binding(&self) -> PreparedBinding {
        PreparedBinding {
            grant_generation: 7,
            key_fingerprint: self.key.fingerprint.clone(),
            ca_fingerprint: self.ca.clone(),
            pairs: BTreeSet::from([pair("h1"), pair("h2")]),
            policy: Some(PolicyId::parse("runner-pol").unwrap()),
            runner_bound: shift(t0(), 2 * HOUR),
            cutoff: None,
            report_at: t0(),
            prepared_at: t0(),
        }
    }

    fn delivered(&self) -> DeliveredGrant {
        DeliveredGrant {
            environment: runner_env(),
            grant: grant(),
            pairs: BTreeSet::from([pair("h1"), pair("h2")]),
            extensions: BTreeSet::from(["permit-pty".to_owned()]),
            expires_at: shift(t0(), 2 * HOUR),
            delivered_at: t0(),
            prepared: Some(self.binding()),
            last_failure: None,
        }
    }

    fn put_delivered(&self, change: impl FnOnce(&mut DeliveredGrant)) {
        let mut d = self.delivered();
        change(&mut d);
        self.store
            .transaction(|tx| tx.put_delivered_grant(&d))
            .unwrap();
    }

    /// Reserve `entry` (changed by `change`) in the ledger and return its reference.
    fn reserve(&self, change: impl FnOnce(&mut IssuanceEntry)) -> IssuanceRef {
        let mut e = self.entry.clone();
        change(&mut e);
        self.store
            .transaction(|tx| tx.reserve_issuance(&e))
            .unwrap();
        IssuanceRef {
            table: IssuanceTable::Remote,
            id: e.id,
        }
    }

    fn assess(&self, entry: &IssuanceRef) -> Result<CertificateBounds, RemoteCheckRefusal> {
        self.assess_for(entry, &self.key.openssh_line)
    }

    fn assess_for(
        &self,
        entry: &IssuanceRef,
        subject: &str,
    ) -> Result<CertificateBounds, RemoteCheckRefusal> {
        self.store
            .transaction(|tx| assess_remote_reservation(tx, &self.gate, entry, subject))
            .unwrap()
    }

    fn refused(&self, entry: &IssuanceRef) -> R {
        match self.assess(entry) {
            Err(RemoteCheckRefusal::Condition(c)) => c,
            other => panic!("expected a condition's refusal, got {other:?}"),
        }
    }
}

// --- the in-process child (as `issuer_child.rs`) ---------------------------------------------

struct InProc {
    to: Option<std::io::PipeWriter>,
    from: std::io::PipeReader,
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

impl InProc {
    fn spawn(w: &World) -> Self {
        let (r1, w1) = std::io::pipe().unwrap();
        let (r2, w2) = std::io::pipe().unwrap();
        let stdin = pipe_file(r1);
        let db = w.db.clone();
        let clock: Arc<dyn Clock> = w.clock.clone();
        let store: Box<dyn SecretStore> =
            Box::new(ScratchSecretStore::new(w.dir.path().join("store")));
        let handle = std::thread::spawn(move || child::run(stdin, w2, store, &db, clock));
        let mut c = Self {
            to: Some(w1),
            from: r2,
            handle,
        };
        assert!(matches!(
            c.call(&Request::Hello {
                protocol: PROTOCOL.into(),
                nonce: "0123456789abcdef0123456789abcdef".into(),
            }),
            Response::HelloAck { .. }
        ));
        assert!(matches!(c.call(&Request::Load {}), Response::Loaded { cas } if cas.len() == 1));
        c
    }

    fn call(&mut self, r: &Request) -> Response {
        self.to
            .as_mut()
            .unwrap()
            .write_all(&r.encode().unwrap())
            .unwrap();
        let mut header = [0u8; 4];
        self.from.read_exact(&mut header).unwrap();
        let mut body = vec![0u8; body_len(header).unwrap()];
        self.from.read_exact(&mut body).unwrap();
        Response::decode(&body).unwrap()
    }

    fn sign(&mut self, entry: &IssuanceRef, subject: &str) -> Response {
        self.call(&Request::Sign {
            request_id: format!("{:032x}", 1),
            reservation: entry.clone(),
            subject_public_key: subject.to_owned(),
        })
    }

    fn finish(mut self) -> i32 {
        drop(self.to.take());
        self.handle.join().unwrap()
    }
}

// =================================================================================================

/// Every condition holds: the child signs exactly the reserved bounds for K_env, with this
/// controller's CA, and writes nothing.
#[tokio::test]
async fn a_remote_reservation_is_signed_when_every_condition_holds() {
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    assert_eq!(w.assess(&entry).unwrap(), w.entry.bounds);
    let mut c = InProc::spawn(&w);
    let Response::Signed { certificate, .. } = c.sign(&entry, &w.key.openssh_line) else {
        panic!("expected a certificate");
    };
    let cert = ssh_key::Certificate::from_openssh(&certificate).unwrap();
    validate_installed(&cert, &w.entry.bounds, &w.key.fingerprint, &w.ca).unwrap();
    assert_eq!(cert.valid_principals(), [principal_for(&pair("h1"))]);
    assert!(cert.critical_options().is_empty());
    assert_eq!(
        cert.valid_before(),
        u64::try_from(w.entry.bounds.valid_before.as_second()).unwrap()
    );
    let stored = w
        .store
        .transaction(|tx| tx.issuance_entry(&entry.id))
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.state,
        IssuanceState::Reserved,
        "the issuer wrote nothing"
    );
    // The same entry asked for as an ordinary grant reservation is refused by the local
    // predicate: this store holds no such grant. The kinds never stand in for each other.
    let as_grant = IssuanceRef {
        table: IssuanceTable::Grant,
        id: entry.id.clone(),
    };
    assert!(matches!(
        c.sign(&as_grant, &w.key.openssh_line),
        Response::Refused { .. }
    ));
    assert_eq!(c.finish(), 0);
}

/// Condition 1: a recorded paired runner, and a role the role table lets issue.
#[tokio::test]
async fn condition_1_needs_a_recorded_runner_and_an_issuing_role() {
    // The table, not a role name: exactly the roles holding the issuance forms' permission.
    for role in [Role::Owner, Role::Requester, Role::Viewer] {
        assert_eq!(
            role_may_issue(role, &grant()),
            role.permissions()
                .contains(&heimdall_contract::remote::Permission::IssuerTrust),
            "{role:?}"
        );
    }
    assert!(role_may_issue(Role::Owner, &grant()));

    let w = World::new().await;
    let entry = w.reserve(|_| {});
    for role in [Role::Requester, Role::Viewer] {
        put_pin(&w.store, &pin(role));
        assert_eq!(w.refused(&entry), R::RoleMayNotIssue, "{role:?}");
    }
    w.store
        .transaction(|tx| tx.remove_remote_environment_pin(&runner_env()))
        .unwrap();
    assert_eq!(w.refused(&entry), R::NoRunnerRecord);
    // The child answers with a wire refusal and signs nothing.
    let mut c = InProc::spawn(&w);
    assert_eq!(
        c.sign(&entry, &w.key.openssh_line),
        Response::Refused {
            request_id: format!("{:032x}", 1),
            reason: IssuerRefusal::CeilingExceeded,
        }
    );
    assert_eq!(c.finish(), 0);
}

/// Condition 2: the barrier. The reservation rests on the report on record, with the outbox
/// drained and no failed attempt since.
#[tokio::test]
async fn condition_2_needs_the_report_read_and_the_outbox_drained() {
    // An unacknowledged narrowing effect for the runner.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| {
            tx.enqueue_remote_effect(
                &runner_env(),
                &EffectKey {
                    producer: client(),
                    effect: EffectId::from_random_bytes([9; 16]),
                    target: EffectTarget::GrantRevoke {
                        grant: GrantId::from_random_bytes([0x33; 16]),
                        grant_generation: 1,
                    },
                },
                t0(),
            )
        })
        .unwrap();
    assert_eq!(w.refused(&entry), R::BarrierClosed);

    // Another report was read since the one the reservation rests on (a new session).
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| tx.note_remote_report(&runner_env(), shift(t0(), 5), &report()))
        .unwrap();
    assert_eq!(w.refused(&entry), R::BarrierClosed);

    // An attempt to reach the runner failed since.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| tx.note_remote_failure(&runner_env(), shift(t0(), 5), "unreachable"))
        .unwrap();
    assert_eq!(w.refused(&entry), R::BarrierClosed);
    assert_eq!(
        RemoteCheckRefusal::Condition(R::BarrierClosed).to_wire(),
        IssuerRefusal::EntryStale
    );
}

/// Condition 3: the runner's verified prepare answer binds K_env to the grant, its
/// generation and the pair.
#[tokio::test]
async fn condition_3_needs_the_prepare_answers_key_binding() {
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.put_delivered(|d| d.prepared = None);
    assert_eq!(w.refused(&entry), R::NoKeyBinding);

    // Another key than the one the answer bound (the `sign` request's subject).
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    let other = KeyVault::new().generate_ed25519().unwrap().1;
    assert_eq!(
        w.assess_for(&entry, &other.openssh_line),
        Err(RemoteCheckRefusal::Condition(R::KeyBindingMismatch))
    );
    // The binding names another key than the entry's subject.
    w.put_delivered(|d| d.prepared.as_mut().unwrap().key_fingerprint = other.fingerprint.clone());
    assert_eq!(w.refused(&entry), R::KeyBindingMismatch);

    // Another generation.
    let w = World::new().await;
    let entry = w.reserve(|e| e.generation = AuthorityGeneration(8));
    assert_eq!(w.refused(&entry), R::KeyBindingMismatch);

    // A pair the answer did not name.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.put_delivered(|d| d.prepared.as_mut().unwrap().pairs = BTreeSet::from([pair("h2")]));
    assert_eq!(w.refused(&entry), R::KeyBindingMismatch);
}

/// Condition 4: the grant is pinned to this controller's active CA.
#[tokio::test]
async fn condition_4_needs_this_controllers_active_ca() {
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    let other = SecretCaKey::generate().unwrap().fingerprint().unwrap();
    w.put_delivered(|d| d.prepared.as_mut().unwrap().ca_fingerprint = other.clone());
    assert_eq!(w.refused(&entry), R::CaNotPinned);

    // The entry names a CA this store does not hold.
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.ca_fingerprint = Some(other.clone()));
    w.put_delivered(|d| d.prepared.as_mut().unwrap().ca_fingerprint = other.clone());
    assert_eq!(w.refused(&entry), R::CaNotPinned);

    // The CA is no longer active.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| {
            tx.set_issuer_state(&w.ca, CaState::Active, CaEvent::RetireApproved, t0())
        })
        .unwrap()
        .unwrap();
    assert_eq!(w.refused(&entry), R::CaNotPinned);
}

/// Condition 5: the key ID names the runner's environment (and the grant).
#[tokio::test]
async fn condition_5_needs_a_key_id_naming_the_runners_environment() {
    // This controller's own environment is not a runner it records.
    let w = World::new().await;
    let entry = w.reserve(|e| {
        e.bounds.key_id = format!("heimdall:{}:{}:4242", own_env(), grant());
    });
    assert_eq!(w.refused(&entry), R::NoRunnerRecord);

    // The runner's environment, another grant.
    let w = World::new().await;
    let entry = w.reserve(|e| {
        e.bounds.key_id = format!(
            "heimdall:{}:{}:4242",
            runner_env(),
            GrantId::from_random_bytes([0x72; 16])
        );
    });
    assert_eq!(w.refused(&entry), R::KeyId);

    // No environment at all.
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.key_id = "deploy@runner".into());
    assert_eq!(w.refused(&entry), R::KeyId);
}

/// Condition 6: principals and extensions come from this controller's record of the grant
/// it delivered, never from the runner's answer or the reservation.
#[tokio::test]
async fn condition_6_signs_only_what_this_controller_delivered() {
    // No record of a delivered grant.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| tx.forget_delivered_grants(&runner_env()))
        .unwrap();
    assert_eq!(w.refused(&entry), R::NotDelivered);

    // The runner's answer names a pair (h3) the controller never delivered: an entry for
    // it is not signed, whatever the binding says.
    let w = World::new().await;
    let entry = w.reserve(|e| {
        e.pair = pair("h3");
        e.bounds.principal = principal_for(&pair("h3"));
    });
    w.put_delivered(|d| {
        d.prepared.as_mut().unwrap().pairs = BTreeSet::from([pair("h1"), pair("h3")]);
    });
    assert_eq!(w.refused(&entry), R::PrincipalNotDelivered);
    assert_eq!(
        RemoteCheckRefusal::Condition(R::PrincipalNotDelivered).to_wire(),
        IssuerRefusal::Issuance(IssuanceRefusal::WrongPrincipal)
    );
    let mut c = InProc::spawn(&w);
    assert!(matches!(
        c.sign(&entry, &w.key.openssh_line),
        Response::Refused { .. }
    ));
    assert_eq!(c.finish(), 0);

    // A principal that is not the entry's pair's.
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.principal = principal_for(&pair("h2")));
    assert_eq!(w.refused(&entry), R::PrincipalNotDelivered);

    // An extension the delivered grant does not carry.
    let w = World::new().await;
    let entry = w.reserve(|e| {
        e.bounds
            .extensions
            .insert("permit-port-forwarding".to_owned());
    });
    assert_eq!(w.refused(&entry), R::ExtensionNotDelivered);

    // An extension no certificate may carry, even when "delivered".
    let w = World::new().await;
    let entry = w.reserve(|e| {
        e.bounds
            .extensions
            .insert("permit-X11-forwarding".to_owned());
    });
    w.put_delivered(|d| {
        d.extensions.insert("permit-X11-forwarding".to_owned());
    });
    assert_eq!(w.refused(&entry), R::ExtensionNotDelivered);
}

/// Condition 7: `valid_before` is at most the minimum of the grant's expiry, the effective
/// cutoff and the runner's reported latest possible credential expiry.
#[tokio::test]
async fn condition_7_bounds_the_validity_by_expiry_cutoff_and_the_runners_bound() {
    // Past the delivered grant's expiry (the runner claims a later bound).
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.valid_before = shift(t0(), 3 * HOUR));
    w.put_delivered(|d| d.prepared.as_mut().unwrap().runner_bound = shift(t0(), 12 * HOUR));
    assert_eq!(w.refused(&entry), R::ValidityTooLate);
    assert_eq!(
        RemoteCheckRefusal::Condition(R::ValidityTooLate).to_wire(),
        IssuerRefusal::Issuance(IssuanceRefusal::BoundTooLate)
    );

    // Past the runner's reported bound (inside the grant's expiry).
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.put_delivered(|d| d.prepared.as_mut().unwrap().runner_bound = shift(t0(), HOUR / 2));
    assert_eq!(w.refused(&entry), R::ValidityTooLate);

    // Past the effective cutoff.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.put_delivered(|d| d.prepared.as_mut().unwrap().cutoff = Some(shift(t0(), HOUR / 2)));
    assert_eq!(w.refused(&entry), R::ValidityTooLate);

    // Exactly at the minimum of the three: signed.
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.valid_before = shift(t0(), HOUR / 2));
    w.put_delivered(|d| d.prepared.as_mut().unwrap().cutoff = Some(shift(t0(), HOUR / 2)));
    assert!(w.assess(&entry).is_ok());

    // A bound that has passed, and an empty validity.
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.valid_before = shift(t0(), 30));
    w.clock.advance(Duration::from_secs(45));
    assert_eq!(w.refused(&entry), R::BoundPassed);
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.valid_before = e.bounds.valid_after);
    assert_eq!(w.refused(&entry), R::BoundPassed);
}

/// The issuer's own steps still apply: the entry is `reserved` and fresh, and a grant this
/// ledger shows revoked is never issued for again.
#[tokio::test]
async fn a_stale_settled_or_revoked_remote_reservation_is_refused() {
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.clock.advance(Duration::from_secs(61));
    assert_eq!(w.assess(&entry), Err(RemoteCheckRefusal::EntryStale));

    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| tx.publish_issuance(&entry.id, t0()))
        .unwrap();
    assert_eq!(w.assess(&entry), Err(RemoteCheckRefusal::EntryNotReserved));
    let missing = IssuanceRef {
        table: IssuanceTable::Remote,
        id: IssuanceId::from_random_bytes([0x16; 16]),
    };
    assert_eq!(
        w.assess(&missing),
        Err(RemoteCheckRefusal::EntryNotReserved)
    );

    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| {
            tx.insert_tombstone(&Tombstone {
                grant: grant(),
                cascade: Vec::new(),
                generation: AuthorityGeneration(0),
                revoked_at: t0(),
                remote_pending: Vec::new(),
                cause: RevocationCause::AuthorityWithdrawn,
            })
        })
        .unwrap();
    assert_eq!(w.refused(&entry), R::GrantRevoked);

    // A grant this store itself holds is a local grant: the `remote` kind never signs for
    // it, whatever else is on record.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    let stored = w
        .store
        .transaction(|tx| tx.issuance_entry(&entry.id))
        .unwrap()
        .unwrap();
    let (owner, delivered) = (pin(Role::Owner), w.delivered());
    let contact = w
        .store
        .transaction(|tx| tx.remote_contact(&runner_env()))
        .unwrap();
    let view = |local_grant: bool| heimdall_issuer::remote::RemoteReservationView {
        entry: &stored,
        subject_fingerprint: Some(w.key.fingerprint.as_str()),
        local_grant,
        pin: Some(&owner),
        delivered: Some(&delivered),
        contact: &contact,
        outbox_pending: false,
        tombstoned: false,
        ca_active: true,
        now: t0(),
    };
    assert_eq!(
        heimdall_issuer::remote::admit_remote_reservation(&view(false)),
        Ok(())
    );
    assert_eq!(
        heimdall_issuer::remote::admit_remote_reservation(&view(true)),
        Err(R::LocalGrant)
    );
}

/// ⟨M06 W3 grant-path⟩ The wire carries only the nearest existing reason, so several
/// conditions share one (`ceiling_exceeded`, `subject_mismatch`). The controller's runtime
/// reads the condition from the same store and names it: each refusal has its own text, and
/// a reservation that every condition admits has none.
#[tokio::test]
async fn each_remote_refusal_is_named_by_its_own_text() {
    use heimdall_issuer::check::explain_remote_refusal;
    let named = |w: &World, entry: &IssuanceRef| {
        explain_remote_refusal(&w.store, &entry.id, &w.key.openssh_line, w.clock.wall())
            .map(|r| r.to_string())
    };
    // Admitted: nothing to name.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    assert_eq!(named(&w, &entry), None);

    let mut texts = BTreeSet::new();
    // No record of a delivered grant.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.store
        .transaction(|tx| tx.forget_delivered_grants(&runner_env()))
        .unwrap();
    assert_eq!(w.refused(&entry), R::NotDelivered);
    texts.insert(named(&w, &entry).unwrap());
    // A principal that is not the entry's pair's.
    let w = World::new().await;
    let entry = w.reserve(|e| e.bounds.principal = principal_for(&pair("h2")));
    assert_eq!(w.refused(&entry), R::PrincipalNotDelivered);
    texts.insert(named(&w, &entry).unwrap());
    // An extension the delivered grant does not carry.
    let w = World::new().await;
    let entry = w.reserve(|e| {
        e.bounds
            .extensions
            .insert("permit-port-forwarding".to_owned());
    });
    assert_eq!(w.refused(&entry), R::ExtensionNotDelivered);
    texts.insert(named(&w, &entry).unwrap());
    // No key binding from a prepare answer.
    let w = World::new().await;
    let entry = w.reserve(|_| {});
    w.put_delivered(|d| d.prepared = None);
    assert_eq!(w.refused(&entry), R::NoKeyBinding);
    texts.insert(named(&w, &entry).unwrap());
    assert_eq!(texts.len(), 4, "{texts:?}");
    assert!(texts.contains("no record of a grant delivered to the runner"));
    assert!(texts.contains("the principal was not delivered"));
    assert!(texts.contains("an extension was not delivered"));
    assert!(texts.contains("no key binding from the runner's prepare answer"));
    // An entry this store does not hold is not explained.
    let unknown = heimdall_contract::ids::IssuanceId::from_random_bytes([9; 16]);
    assert!(
        explain_remote_refusal(&w.store, &unknown, &w.key.openssh_line, w.clock.wall()).is_none()
    );
}
