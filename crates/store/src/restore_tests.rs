//! ⟨M08 W4 U2b-3b⟩ The restore module's focused cases, at the store (ADR-0014 §3.6's table, the
//! carry-forward, identity binding and the switch). Each case takes a backup through SQLite of
//! a real generation, changes the store after it, restores, and reads the restored generation
//! back through the store's own readers. The runtime-level cases (a request retried after the
//! restore, a client's hello, a decision reference) are in `heimdall-runtime`'s tests.
//!
//! **Not established here:** durability across power loss.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use heimdall_contract::canonical::RequestHash;
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, InvitationId, IrohEndpointId, KeyFingerprint,
    OperationId, ProfileId, RequestId,
};
use heimdall_contract::issuer::CaState;
use heimdall_contract::remote::Role;
use heimdall_contract::request::DeadlineIntent;
use heimdall_domain::decision::DecisionKind;
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
use heimdall_domain::operation::{EffectClass, OperationKind, OperationRecord, RecoveryMetadata};
use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::scope::Scope;
use heimdall_domain::time::{BootId, Deadline};
use heimdall_stategen::{Ledger, RealFs};

use super::*;
use crate::ext_m03::IssuerRecord;
use crate::ext_m06::{
    AppliedLine, ClientState, InvitationState, JoinRecord, RemoteClientRecord,
    RemoteInvitationRecord, RevocationCause as ClientRevocation,
};
use crate::ext_transport::{TransportKeyRecord, TransportKeyState};
use crate::layout;

fn t0() -> Timestamp {
    "2026-11-27T09:00:00Z".parse().unwrap()
}

fn at(secs: i64) -> Timestamp {
    t0().checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn env() -> EnvironmentId {
    EnvironmentId::from_random_bytes([1; 16])
}

const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

/// The event writer of these cases: the store's own append (the production one is the
/// application's publisher).
struct Appends;

impl RestoreEvent for Appends {
    fn append(
        &self,
        store: &Arc<Store>,
        environment: &EnvironmentId,
        payload: &StateRestoredPayload,
        at: Timestamp,
    ) -> Result<()> {
        store.transaction(|tx| {
            tx.append_event(&heimdall_contract::event::Event {
                schema_version: heimdall_contract::SchemaVersion::current(),
                event_id: heimdall_contract::ids::EventId::from_random_bytes([0; 16]),
                event_type: heimdall_contract::event::EventType::StateRestored,
                environment_id: environment.clone(),
                operation_id: None,
                resource: None,
                timestamp: at,
                cursor: heimdall_contract::event::Cursor(String::new()),
                payload: serde_json::to_value(payload).unwrap(),
            })
            .map(drop)
        })
    }
}

/// A scratch home with its first generation installed.
struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
    scratch: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("state");
        std::fs::create_dir(&root).unwrap();
        let scratch = dir.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let opened =
            layout::open_locked(&root, &RealFs, Arc::new(NoFaults), &|| Some(env()), t0()).unwrap();
        assert_eq!(opened.began, layout::Began::Installed);
        drop(opened);
        Self {
            _dir: dir,
            root,
            scratch,
        }
    }

    /// The served store, as a runtime's start opens it.
    fn open(&self) -> layout::Opened {
        layout::open_locked(
            &self.root,
            &RealFs,
            Arc::new(NoFaults),
            &|| Some(env()),
            t0(),
        )
        .unwrap()
    }

    fn write<R>(&self, f: impl FnOnce(&mut Txn<'_>) -> Result<R>) -> R {
        let opened = self.open();
        opened.store.transaction(f).unwrap()
    }

    fn read<R>(&self, f: impl FnOnce(&mut Txn<'_>) -> Result<R>) -> R {
        self.write(f)
    }

    /// A backup of the served generation, through SQLite, outside the state directory.
    fn backup(&self, name: &str) -> PathBuf {
        let out = self.scratch.join(name);
        let db = layout::db_path(&self.root).unwrap();
        let store = Store::open_read_only(&db, Arc::new(NoFaults)).unwrap();
        store.vacuum_into(&out).unwrap();
        out
    }

    fn restore(&self, backup: &Path) -> std::result::Result<RestoreOutcome, RestoreError> {
        restore_locked(
            &self.root,
            &RealFs,
            &RestoreRequest {
                backup,
                now: at(3600),
                recovery_confirmed: false,
                event: &Appends,
                operation_retention: RETENTION,
            },
        )
    }

    fn pointer(&self) -> String {
        layout::pointed_generation(&self.root)
            .unwrap()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    /// Every file under the state directory with its bytes.
    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else {
                    out.insert(
                        p.strip_prefix(base).unwrap().to_string_lossy().into_owned(),
                        std::fs::read(&p).unwrap(),
                    );
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, &mut out);
        out
    }
}

fn grant(n: u8, state: GrantState) -> GrantSnapshot {
    let starts_at = t0();
    let deadline = at(86_400);
    GrantSnapshot {
        id: GrantId::from_random_bytes([n; 16]),
        environment: env(),
        scope: Scope::empty(),
        starts_at,
        deadline: Deadline {
            intent: DeadlineIntent::Absolute(deadline.to_string()),
            resolved_at: starts_at,
            effective: deadline,
        },
        parent: None,
        source: AuthorizationSource::StandingPolicy {
            revision: PolicyRevision(1),
        },
        generation: AuthorityGeneration(0),
        state,
        enforcement: EnforcementEvidence::unknown(),
    }
}

fn policy(n: u8) -> StandingPolicy {
    StandingPolicy {
        id: PolicyId::parse(&format!("pol-{n}")).unwrap(),
        revision: PolicyRevision(1),
        profile: ProfileId::parse("default").unwrap(),
        workspace: None,
        scope: Scope::empty(),
        environments: [env()].into_iter().collect(),
        max_window: Duration::from_secs(3600),
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::SetupDefault,
        lock_behavior: Default::default(),
        connection: Default::default(),
        default: false,
    }
}

fn owner() -> CallerContext {
    CallerContext::local(PrincipalRef::UnixUser { uid: 501 }, ClientRole::Owner)
}

fn operation(n: u8, state: OperationState) -> (OperationRecord, IdempotencyRecord) {
    let key = IdempotencyKey {
        caller: owner(),
        kind: OperationKind::Ensure,
        request_id: RequestId::parse(&format!("req-{n}")).unwrap(),
    };
    let op = OperationRecord {
        id: OperationId::from_random_bytes([n; 16]),
        kind: OperationKind::Ensure,
        environment: env(),
        key: key.clone(),
        request_hash: RequestHash([n; 32]),
        effect_class: EffectClass::Local,
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
        key,
        request_hash: op.request_hash,
        operation_id: op.id.clone(),
        created_at: t0(),
        expires_at: None,
    };
    (op, idem)
}

fn succeed(tx: &mut Txn<'_>, op: &mut OperationRecord) -> Result<()> {
    op.state = OperationState::Succeeded;
    op.code = Some(heimdall_contract::Code::Ok);
    op.effect_status = EffectStatus::Applied;
    op.result = Some(serde_json::json!({ "answered": "the real one" }));
    op.updated_at = at(60);
    tx.update_operation(op)?;
    tx.settle_idempotency(&op.key, at(60 + 7 * 86_400))
}

fn decision(n: u8) -> DecisionRecord {
    DecisionRecord {
        id: DecisionId::from_random_bytes([n; 16]),
        kind: DecisionKind::WidenPolicy {
            action: heimdall_contract::request::PolicyAction::Resume {
                policy_id: None,
                target: None,
            },
        },
        generation: AuthorityGeneration(0),
        created_at: t0(),
        expires_at: at(86_400),
        state: DecisionState::Pending,
        decided_at: None,
    }
}

fn fp(c: char) -> KeyFingerprint {
    KeyFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
}

fn invited(n: u8) -> (RemoteClientRecord, RemoteInvitationRecord) {
    let client = ClientId::from_random_bytes([n; 16]);
    let invitation = InvitationId::from_random_bytes([n; 16]);
    (
        RemoteClientRecord {
            client: client.clone(),
            role: Role::Owner,
            key_fingerprint: fp('A'),
            public_key: "ssh-ed25519 AAAA".into(),
            state: ClientState::Pending,
            invitation: Some(invitation.clone()),
            revoked_generation: None,
            revocation: None,
            created_at: t0(),
            updated_at: t0(),
            line: AppliedLine::Absent,
        },
        RemoteInvitationRecord {
            invitation,
            client,
            role: Role::Owner,
            key_fingerprint: fp('A'),
            generation: 0,
            created_wall: t0(),
            created_boot_id: BootId("boot-1".into()),
            created_elapsed: Duration::from_secs(100),
            expires_wall: at(900),
            elapsed_bound: Duration::from_secs(900),
            probe_nonce: "00".repeat(16),
            state: InvitationState::Pending,
            consumed_at: None,
            join: None,
            iroh_admission: false,
        },
    )
}

fn join(tx: &mut Txn<'_>, inv: &RemoteInvitationRecord) -> Result<()> {
    tx.activate_remote_client(&JoinRecord {
        environment: env(),
        invitation: inv.invitation.clone(),
        client: inv.client.clone(),
        role: inv.role,
        generation: inv.generation,
        joined_at: at(60),
    })
    .map(drop)
}

fn issuer(n: u8, state: CaState) -> IssuerRecord {
    let c = char::from(b'A' + n % 26);
    IssuerRecord {
        ca_fingerprint: heimdall_contract::ids::CaFingerprint::parse(&format!(
            "SHA256:{}",
            c.to_string().repeat(43)
        ))
        .unwrap(),
        public_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture{n}"),
        state,
        store_kind: heimdall_contract::issuer::StoreKind::LinuxSecretService,
        backup_sha256: format!("{n:02x}").repeat(32),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: t0(),
        retired_at: None,
    }
}

fn pin(tx: &mut Txn<'_>, n: u8) -> Result<EnvironmentId> {
    let environment = EnvironmentId::from_random_bytes([n; 16]);
    tx.put_remote_environment_pin(
        &environment,
        &DestinationId::parse(&format!("runner-{n}")).unwrap(),
        &AccountName::parse("dev").unwrap(),
        &fp('H'),
        "{}",
        t0(),
    )?;
    Ok(environment)
}

/// `restore_keeps_a_later_revoked_grant_ended`, at the store (the fixture login refused with
/// its material is the runtime's case): every grant the backup holds live comes back ended,
/// with a tombstone and its hold; the one revoked after the backup keeps the replaced
/// generation's own tombstone. The epoch rises and the record says `restore`.
#[test]
fn restore_keeps_a_later_revoked_grant_ended_at_the_store() {
    let home = Home::new();
    home.write(|tx| {
        tx.insert_grant(&grant(1, GrantState::Active))?;
        tx.insert_grant(&grant(2, GrantState::Active))?;
        tx.insert_grant(&grant(3, GrantState::Expired))
    });
    let backup = home.backup("backup.db");
    let before = home.pointer();
    home.write(|tx| {
        let mut g = grant(1, GrantState::Revoked);
        tx.insert_tombstone(&Tombstone {
            grant: g.id.clone(),
            cascade: Vec::new(),
            generation: AuthorityGeneration(0),
            revoked_at: at(30),
            remote_pending: Vec::new(),
            cause: RevocationCause::Revoke,
        })?;
        g.state = GrantState::Revoked;
        tx.update_grant_state(&g)
    });
    let backup_bytes = std::fs::read(&backup).unwrap();
    let out = home.restore(&backup).unwrap();
    // The backup is only read: its bytes are as they were and nothing was written beside it.
    assert_eq!(std::fs::read(&backup).unwrap(), backup_bytes);
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = backup.as_os_str().to_owned();
        name.push(suffix);
        assert!(!PathBuf::from(name).exists(), "{suffix} beside the backup");
    }
    assert!(out.carried_forward);
    assert_eq!(
        out.left_behind.as_ref().map(GenerationName::as_str),
        Some(before.as_str())
    );
    assert_eq!(out.current.record.operation, Operation::Restore);
    assert_eq!(out.current.record.restore_epoch, 1);
    assert_ne!(home.pointer(), before);
    let mut ended = out.ended.grants_ended.clone();
    ended.sort();
    assert_eq!(
        ended,
        vec![
            grant(1, GrantState::Active).id,
            grant(2, GrantState::Active).id
        ]
    );
    home.read(|tx| {
        assert_eq!(tx.restore_epoch()?, RestoreEpoch(1));
        assert!(
            tx.live_grants()?.is_empty(),
            "no grant is live after a restore"
        );
        for n in [1, 2] {
            let id = grant(n, GrantState::Active).id;
            assert_eq!(tx.grant(&id)?.unwrap().state, GrantState::Revoked);
            assert!(tx.tombstone(&id)?.is_some(), "grant {n} has its tombstone");
            assert!(tx.restore_hold(HoldKind::Grant, id.as_str())?.is_some());
        }
        // The later revocation is the replaced generation's own record.
        let later = tx.tombstone(&grant(1, GrantState::Active).id)?.unwrap();
        assert_eq!(
            (later.revoked_at, later.cause),
            (at(30), RevocationCause::Revoke)
        );
        let restored = tx.tombstone(&grant(2, GrantState::Active).id)?.unwrap();
        assert_eq!(restored.cause, RevocationCause::AuthorityWithdrawn);
        Ok(())
    });
}

/// `restore_quarantines_a_later_revoked_management_client`, at the store: a client revoked
/// after the backup stays revoked (its tombstone carried); with the replaced generation lost,
/// every recovered client that is not revoked is quarantined (held) instead. The hold is
/// lifted only by reauthorization.
#[test]
fn restore_quarantines_a_later_revoked_management_client_at_the_store() {
    for readable in [true, false] {
        let home = Home::new();
        let (c1, i1) = invited(1);
        let (c2, i2) = invited(2);
        home.write(|tx| {
            tx.insert_remote_invitation(&c1, &i1, t0())?;
            tx.insert_remote_invitation(&c2, &i2, t0())?;
            join(tx, &i1)?;
            join(tx, &i2)
        });
        let backup = home.backup("backup.db");
        home.write(|tx| {
            tx.revoke_remote_client(&c1.client, ClientRevocation::Revoked, at(30))
                .map(drop)
        });
        if !readable {
            // The replaced generation is made unreadable.
            let db = layout::db_path(&home.root).unwrap();
            std::fs::write(&db, b"not a database any more").unwrap();
        }
        let out = home.restore(&backup).unwrap();
        assert_eq!(out.carried_forward, readable, "readable {readable}");
        home.read(|tx| {
            let one = tx.remote_client(&c1.client)?.unwrap();
            let two = tx.remote_client(&c2.client)?.unwrap();
            if readable {
                assert_eq!(
                    one.state,
                    ClientState::Revoked,
                    "the later tombstone is carried"
                );
                assert!(
                    tx.restore_hold(HoldKind::Client, c1.client.as_str())?
                        .is_none()
                );
            } else {
                assert_eq!(one.state, ClientState::Active);
                assert!(
                    tx.restore_hold(HoldKind::Client, c1.client.as_str())?
                        .is_some()
                );
            }
            assert_eq!(two.state, ClientState::Active);
            assert!(
                tx.restore_hold(HoldKind::Client, c2.client.as_str())?
                    .is_some()
            );
            // Reauthorization lifts only the client's own hold.
            assert!(tx.lift_client_hold(&c2.client)?);
            assert!(!tx.lift_client_hold(&c2.client)?);
            assert!(
                tx.restore_hold(HoldKind::Client, c2.client.as_str())?
                    .is_none()
            );
            assert!(
                tx.restore_hold(HoldKind::Invitation, i2.invitation.as_str())?
                    .is_some(),
                "the consumed invitation stays void"
            );
            Ok(())
        });
    }
}

/// `restore_voids_consumed_and_expired_invitations`, at the store: an invitation consumed
/// after the backup is void (held) and keeps its consumption; one that expired after it keeps
/// its expiry and its client's tombstone, which refuse it already. With the replaced generation
/// lost, both come back from the backup pending, and both are void.
#[test]
fn restore_voids_consumed_and_expired_invitations_at_the_store() {
    for readable in [true, false] {
        let home = Home::new();
        let (c1, i1) = invited(1);
        let (c2, i2) = invited(2);
        home.write(|tx| {
            tx.insert_remote_invitation(&c1, &i1, t0())?;
            tx.insert_remote_invitation(&c2, &i2, t0())
        });
        let backup = home.backup("backup.db");
        home.write(|tx| {
            join(tx, &i1)?;
            tx.revoke_remote_client(&c2.client, ClientRevocation::InvitationExpired, at(1000))
                .map(drop)
        });
        if !readable {
            std::fs::write(layout::db_path(&home.root).unwrap(), b"lost").unwrap();
        }
        let out = home.restore(&backup).unwrap();
        let mut voided = out.ended.invitations_voided.clone();
        voided.sort();
        let mut expected = vec![i1.invitation.as_str().to_owned()];
        if !readable {
            expected.push(i2.invitation.as_str().to_owned());
        }
        expected.sort();
        assert_eq!(voided, expected, "readable {readable}");
        home.read(|tx| {
            assert!(
                tx.restore_hold(HoldKind::Invitation, i1.invitation.as_str())?
                    .is_some()
            );
            let (one, two) = (
                tx.remote_invitation(&i1.invitation)?.unwrap().state,
                tx.remote_invitation(&i2.invitation)?.unwrap().state,
            );
            if readable {
                assert_eq!(one, InvitationState::Consumed);
                assert_eq!(two, InvitationState::Expired);
                assert_eq!(
                    tx.remote_client(&c2.client)?.unwrap().state,
                    ClientState::Revoked
                );
            } else {
                assert_eq!(
                    (one, two),
                    (InvitationState::Pending, InvitationState::Pending)
                );
                assert!(
                    tx.restore_hold(HoldKind::Invitation, i2.invitation.as_str())?
                        .is_some()
                );
            }
            Ok(())
        });
    }
}

/// `restore_keeps_a_retired_issuer_retired_and_an_unpaired_environment_unpaired`: a CA retired
/// after the backup stays retired, and an environment unpaired after it stays unpaired; the
/// environment still paired is held until reconciled.
#[test]
fn restore_keeps_a_retired_issuer_retired_and_an_unpaired_environment_unpaired() {
    let home = Home::new();
    let ca = issuer(1, CaState::Active);
    let (kept, gone) = home.write(|tx| {
        tx.insert_issuer(&ca)?;
        Ok((pin(tx, 10)?, pin(tx, 11)?))
    });
    let backup = home.backup("backup.db");
    home.write(|tx| {
        for (from, event) in [
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
        ] {
            assert!(
                tx.set_issuer_state(&ca.ca_fingerprint, from, event, at(40))?
                    .is_ok(),
                "{from:?}"
            );
        }
        tx.remove_remote_environment_pin(&gone).map(drop)
    });
    home.restore(&backup).unwrap();
    home.read(|tx| {
        let restored = tx.issuer(&ca.ca_fingerprint)?.unwrap();
        assert_eq!(
            restored.state,
            CaState::Retired,
            "a retired CA stays retired"
        );
        let pins: Vec<EnvironmentId> = tx
            .remote_environment_pins()?
            .into_iter()
            .map(|(e, _)| e)
            .collect();
        assert_eq!(
            pins,
            vec![kept.clone()],
            "an unpaired environment stays unpaired"
        );
        assert!(
            tx.restore_hold(HoldKind::Environment, kept.as_str())?
                .is_some()
        );
        assert!(
            tx.restore_hold(HoldKind::Environment, gone.as_str())?
                .is_none()
        );
        Ok(())
    });
}

/// `restore_disables_exposure_and_closes_pending_widening_decisions`: the transport's K_iroh
/// reference is withdrawn and its consents removed, the admission generation moves, the
/// exposure is held; every pending decision is closed as stale, and a decision raised after
/// the backup is carried closed, under the epoch it was minted in.
#[test]
fn restore_disables_exposure_and_closes_pending_widening_decisions() {
    let home = Home::new();
    let endpoint = IrohEndpointId::parse(&"a".repeat(64)).unwrap();
    let admission_before = home.write(|tx| {
        tx.insert_transport_key(&TransportKeyRecord {
            endpoint: endpoint.clone(),
            store_kind: "fixture".into(),
            store_ref: "fixture-item".into(),
            state: TransportKeyState::Active,
            created_at: t0(),
            destroyed_at: None,
        })?;
        tx.record_transport_serve_port(4433)?;
        tx.insert_decision(&decision(1))?;
        tx.remote_authority_generation()
    });
    let backup = home.backup("backup.db");
    home.write(|tx| tx.insert_decision(&decision(2)));
    let out = home.restore(&backup).unwrap();
    assert_eq!(
        out.ended.exposure_disabled,
        vec![EXPOSURE_TRANSPORT.to_owned()]
    );
    assert_eq!(out.ended.decisions_closed, vec![decision(1).id]);
    assert_eq!(
        out.transport_keys_withdrawn,
        vec![endpoint.as_str().to_owned()]
    );
    home.read(|tx| {
        assert!(
            tx.active_transport_key()?.is_none(),
            "the transport is not enabled"
        );
        assert_eq!(
            tx.transport_key(&endpoint)?.unwrap().state,
            TransportKeyState::Destroyed
        );
        assert_eq!(tx.transport_serve_port()?, None);
        assert!(tx.all_route_consents()?.is_empty());
        assert!(tx.remote_authority_generation()? > admission_before);
        assert!(
            tx.restore_hold(HoldKind::Exposure, EXPOSURE_TRANSPORT)?
                .is_some()
        );
        assert!(tx.pending_decisions()?.is_empty());
        for n in [1, 2] {
            assert_eq!(
                tx.decision(&decision(n).id)?.unwrap().state,
                DecisionState::Stale,
                "decision {n}"
            );
            assert_eq!(
                tx.decision_restore_epoch(&decision(n).id)?,
                Some(RestoreEpoch(0)),
                "decision {n} keeps the epoch it was minted in"
            );
        }
        Ok(())
    });
}

#[test]
fn restore_settles_runner_local_widening_as_stale() {
    use heimdall_contract::decision::{RemoteWidening, WideningOrigin};
    let home = Home::new();
    let mut pending = decision(1);
    pending.kind = DecisionKind::RemoteWidening(Box::new(RemoteWidening {
        origin: WideningOrigin::Local,
        client: None,
        request_kind: "transport.enable".into(),
        request_id: RequestId::parse("held-enable").unwrap(),
        request: serde_json::from_value(serde_json::json!({"op":"transport", "action":"enable", "serve":false, "request_id":"held-enable"})).unwrap(),
        invite: None,
        exposure: None,
    }));
    let digest = "ab".repeat(32);
    home.write(|tx| tx.insert_remote_widening(&pending, &digest, Some(&digest)));
    let backup = home.backup("backup.db");
    let restored = home.restore(&backup).unwrap();
    assert_eq!(restored.ended.decisions_closed, vec![pending.id.clone()]);
    home.read(|tx| {
        let (record, row) = tx.remote_widening(&pending.id)?.unwrap();
        assert_eq!(record.state, DecisionState::Stale);
        assert!(
            record.decided_at.is_some(),
            "the restore settled the widening"
        );
        assert_eq!(row.result, None);
        assert!(
            tx.pending_local_widening("transport.enable", &digest)?
                .is_none()
        );
        Ok(())
    });
}

/// A completed request made after the backup replays after the restore, from its carried
/// terminal record; one that never completed is fenced from the ledger; an open one in the
/// backup is closed as stale. This holds for the journal's records and for the request
/// terminal records of the kinds the journal does not hold (migration 0016).
#[test]
fn request_completed_after_the_backup_keeps_its_answer_and_the_rest_are_fenced() {
    let home = Home::new();
    let (mut open_in_backup, i0) = operation(1, OperationState::Running);
    home.write(|tx| tx.insert_operation(&open_in_backup, &i0));
    let backup = home.backup("backup.db");
    let (mut later, i1) = operation(2, OperationState::Running);
    let digest_terminal =
        crate::fence::ledger_digest(&owner(), "route.add", &RequestId::parse("rt-1").unwrap())
            .unwrap();
    let digest_unfinished =
        crate::fence::ledger_digest(&owner(), "ensure", &RequestId::parse("never").unwrap())
            .unwrap();
    home.write(|tx| {
        tx.insert_operation(&later, &i1)?;
        succeed(tx, &mut later)?;
        succeed(tx, &mut open_in_backup)?;
        tx.record_request_terminal(&digest_terminal, at(70), at(70 + 40 * 86_400))
    });
    // The ledger saw every one of them.
    let ledger = Ledger::new(RealFs, &home.root);
    for digest in [
        crate::fence::idempotency_digest(&i0.key).unwrap(),
        crate::fence::idempotency_digest(&i1.key).unwrap(),
        digest_terminal,
        digest_unfinished,
    ] {
        ledger
            .append(heimdall_stategen::Entry { epoch: 0, digest })
            .unwrap();
    }
    let out = home.restore(&backup).unwrap();
    assert!(out.ledger_readable);
    assert_eq!(
        out.fenced_requests, 1,
        "only the request that never completed"
    );
    home.read(|tx| {
        let replayed = tx.operation(&later.id)?.unwrap();
        assert_eq!(replayed.state, OperationState::Succeeded);
        assert_eq!(replayed.result, later.result, "the real recorded answer");
        assert!(tx.idempotency_record(&i1.key)?.is_some());
        // Completed after the backup, though open in it: the real answer, not a stale close.
        assert_eq!(
            tx.operation(&open_in_backup.id)?.unwrap().state,
            OperationState::Succeeded
        );
        assert!(tx.request_terminal(&digest_terminal)?.is_some());
        assert!(tx.request_fence(&digest_terminal)?.is_none());
        let fence = tx.request_fence(&digest_unfinished)?.unwrap();
        assert_eq!(fence.answer, restored_before_completion());
        assert!(
            fence.settlement.is_none(),
            "unresolved: answered after any wait"
        );
        Ok(())
    });
    // The same with the replaced generation lost: the open one is closed as stale, and every
    // ledger entry without a terminal record in the backup is fenced.
    let home = Home::new();
    let (op, idem) = operation(3, OperationState::Queued);
    home.write(|tx| tx.insert_operation(&op, &idem));
    let backup = home.backup("backup.db");
    Ledger::new(RealFs, &home.root)
        .append(heimdall_stategen::Entry {
            epoch: 0,
            digest: digest_unfinished,
        })
        .unwrap();
    std::fs::write(layout::db_path(&home.root).unwrap(), b"lost").unwrap();
    let out = home.restore(&backup).unwrap();
    assert!(!out.carried_forward);
    assert_eq!(out.ended.operations_closed, vec![op.id.clone()]);
    assert_eq!(out.fenced_requests, 1);
    home.read(|tx| {
        let closed = tx.operation(&op.id)?.unwrap();
        assert_eq!(closed.state, OperationState::Failed);
        assert_eq!(closed.code, Some(heimdall_contract::Code::RequestStale));
        assert_eq!(
            closed.result.unwrap()["error"]["reason"],
            heimdall_contract::envelope::reason::RESTORED_BEFORE_COMPLETION
        );
        Ok(())
    });
}

/// Standing policies are paused with a cutoff at the restore time, or the replaced
/// generation's earlier cutoff; workspace trust needs a new attended trust.
#[test]
fn restore_pauses_policies_with_the_earlier_cutoff() {
    let home = Home::new();
    home.write(|tx| {
        tx.upsert_policy(&policy(1), false)?;
        tx.upsert_policy(&policy(2), false).map(drop)
    });
    let backup = home.backup("backup.db");
    home.write(|tx| {
        let mut p = tx.policy(&policy(1).id)?.unwrap();
        p.cutoff_at = Some(at(10));
        p.revision = PolicyRevision(2);
        tx.upsert_policy(&p, true).map(drop)
    });
    let out = home.restore(&backup).unwrap();
    assert_eq!(out.ended.policies_paused.len(), 2);
    home.read(|tx| {
        let one = tx.policy(&policy(1).id)?.unwrap();
        let two = tx.policy(&policy(2).id)?.unwrap();
        assert_eq!(one.cutoff_at, Some(at(10)), "the earlier cutoff is kept");
        assert_eq!(
            two.cutoff_at,
            Some(at(3600)),
            "a cutoff at the restore time"
        );
        for p in [one, two] {
            assert!(matches!(p.pause, PauseState::Paused { .. }));
        }
        Ok(())
    });
}

/// The page tokens' key never travels: a backup holding one restores without it, and the
/// replaced generation's is not carried either.
#[test]
fn a_restored_store_does_not_hold_the_backups_page_token_key() {
    let home = Home::new();
    let key_of = |tx: &mut Txn<'_>| -> Result<Option<String>> { tx.meta(PAGE_TOKEN_KEY) };
    home.write(|tx| tx.set_meta(PAGE_TOKEN_KEY, &"11".repeat(32)));
    let backup = home.backup("backup.db");
    home.write(|tx| tx.set_meta(PAGE_TOKEN_KEY, &"22".repeat(32)));
    home.restore(&backup).unwrap();
    assert_eq!(home.read(key_of), None);
}

/// `restore_refuses_another_environments_backup_and_changes_nothing`, with the other refusals
/// of the protocol's item 1: not a backup, a newer schema. Nothing under the state directory
/// changes.
#[test]
fn restore_refuses_another_environments_backup_and_changes_nothing() {
    let home = Home::new();
    let other = Home::new();
    // Another installation's backup (another environment ID).
    let foreign = {
        let opened =
            layout::open_locked(&other.root, &RealFs, Arc::new(NoFaults), &|| None, t0()).unwrap();
        drop(opened);
        let db = layout::db_path(&other.root).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = ?2",
            [
                EnvironmentId::from_random_bytes([9; 16]).as_str(),
                META_SELF_ENVIRONMENT,
            ],
        )
        .unwrap();
        drop(conn);
        other.backup("foreign.db")
    };
    let garbage = home.scratch.join("garbage.db");
    std::fs::write(&garbage, b"SQLite format 3\0 and then nothing").unwrap();
    let newer = home.scratch.join("newer.db");
    {
        let conn = rusqlite::Connection::open(&newer).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); PRAGMA user_version = 99;",
        )
        .unwrap();
    }
    let before = home.snapshot();
    for (backup, expected) in [
        (&foreign, Refusal::EnvironmentMismatch),
        (
            &newer,
            Refusal::NewerThanBuild {
                found: 99,
                supported: crate::SCHEMA_VERSION,
            },
        ),
    ] {
        match home.restore(backup) {
            Err(RestoreError::Refused(r)) => assert_eq!(r, expected),
            other => panic!("{backup:?}: {other:?}"),
        }
        assert_eq!(home.snapshot(), before, "{backup:?}: nothing changed");
    }
    assert!(matches!(
        home.restore(&garbage),
        Err(RestoreError::Refused(Refusal::NotABackup(_)))
    ));
    assert_eq!(home.snapshot(), before);
}

/// `restore_restore_reset_keeps_every_earlier_generation`, with `reset_then_restart_serves_the_new_generation`
/// at the store: each operation makes a generation with its own name and record; none is
/// overwritten; start-up serves the last; the reset has a new identity at epoch 0 and names the
/// generation it replaced.
#[test]
fn restore_restore_reset_keeps_every_earlier_generation() {
    let home = Home::new();
    let install = home.pointer();
    let backup = home.backup("backup.db");
    let first = home.restore(&backup).unwrap();
    let second = home.restore(&backup).unwrap();
    assert_eq!(
        second.current.record.restore_epoch, 2,
        "every restore raises it"
    );
    let files = |name: &str| -> Vec<u8> {
        std::fs::read(home.root.join("generations").join(name).join("OPERATION")).unwrap()
    };
    let records: Vec<Vec<u8>> = [install.as_str(), first.current.name.as_str()]
        .iter()
        .map(|n| files(n))
        .collect();
    let new_env = EnvironmentId::from_random_bytes([5; 16]);
    let reset = reset_locked(&home.root, &RealFs, &new_env, at(7200), false).unwrap();
    assert_eq!(reset.current.record.operation, Operation::Reset);
    assert_eq!(reset.current.record.restore_epoch, 0);
    assert_eq!(reset.current.record.environment_id, new_env.as_str());
    assert_eq!(reset.left_behind.as_ref(), Some(&second.current.name));
    assert_eq!(
        reset.current.record.from_generation.as_ref(),
        Some(&second.current.name)
    );
    // Every earlier generation is there, under its own name, its record unchanged.
    let mut names: Vec<String> = std::fs::read_dir(home.root.join("generations"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut expected = vec![
        install.clone(),
        first.current.name.as_str().to_owned(),
        second.current.name.as_str().to_owned(),
        reset.current.name.as_str().to_owned(),
    ];
    expected.sort();
    assert_eq!(names, expected);
    assert_eq!(files(&install), records[0]);
    assert_eq!(files(first.current.name.as_str()), records[1]);
    // The restart serves the reset's generation: a new, empty store with the new identity.
    let opened = home.open();
    assert_eq!(opened.began, layout::Began::Served);
    assert_eq!(opened.current.name, reset.current.name);
    opened
        .store
        .transaction(|tx| {
            assert_eq!(tx.self_environment()?, Some(new_env.clone()));
            assert_eq!(tx.restore_epoch()?, RestoreEpoch(0));
            Ok(())
        })
        .unwrap();
}

/// The reset's inventory reads what the old store records on remote hosts; a reset refuses a
/// reset that keeps the identity.
#[test]
fn reset_lists_what_it_orphans_from_the_old_store() {
    let home = Home::new();
    let (c1, i1) = invited(1);
    home.write(|tx| {
        tx.insert_remote_invitation(&c1, &i1, t0())?;
        pin(tx, 10).map(drop)
    });
    let inventory = reset_inventory(&home.root, &RealFs).unwrap();
    assert!(inventory.readable);
    assert!(!inventory.recovery);
    assert!(
        inventory
            .orphaned
            .contains(&format!("management_line:{}", c1.client.as_str()))
    );
    assert!(inventory.orphaned.contains(&format!(
        "pairing:{}",
        EnvironmentId::from_random_bytes([10; 16]).as_str()
    )));
    assert!(matches!(
        reset_locked(&home.root, &RealFs, &env(), at(10), false),
        Err(RestoreError::Store(StoreError::Layout(
            StateError::Refused(heimdall_stategen::Refusal::ResetKeepsIdentity)
        )))
    ));
}

/// ⟨W3-R04⟩ A purge that stopped after removing the generations and before removing the
/// pointer leaves `state_corrupt`; the attended reset recovers it by the switch, says it
/// cannot list what it leaves behind, and the next start serves the new generation.
#[test]
fn reset_recovers_an_interrupted_purge() {
    let home = Home::new();
    std::fs::remove_dir_all(home.root.join("generations")).unwrap();
    assert!(matches!(
        layout::open_locked(&home.root, &RealFs, Arc::new(NoFaults), &|| Some(env()), t0()),
        Err(StoreError::Corrupt(ref m)) if m.contains("generation_missing")
    ));
    let inventory = reset_inventory(&home.root, &RealFs).unwrap();
    assert!(inventory.recovery);
    assert!(!inventory.readable, "nothing is left to list");
    let new_env = EnvironmentId::from_random_bytes([6; 16]);
    assert!(matches!(
        reset_locked(&home.root, &RealFs, &new_env, at(10), false),
        Err(RestoreError::Refused(Refusal::RecoveryNotConfirmed))
    ));
    let reset = reset_locked(&home.root, &RealFs, &new_env, at(10), true).unwrap();
    let opened = home.open();
    assert_eq!(opened.current.name, reset.current.name);
    assert_eq!(
        opened
            .store
            .transaction(|tx| tx.self_environment())
            .unwrap(),
        Some(new_env)
    );
}

/// The attended recovery from `state_corrupt` by a restore: with no readable record, only a
/// backup under this installation's own names is accepted, and the epoch is raised above
/// everything readable (the backup's and the ledger's).
#[test]
fn restore_from_state_corrupt_accepts_only_its_own_backup_names() {
    let home = Home::new();
    let gen_dir = layout::pointed_generation(&home.root).unwrap().unwrap();
    // A migration backup under its own name in the generation, and the same bytes elsewhere.
    let own = gen_dir.join(format!("{DB_FILE}.v16.backup"));
    let copy = home.backup("copy.db");
    std::fs::copy(&copy, &own).unwrap();
    Ledger::new(RealFs, &home.root)
        .append(heimdall_stategen::Entry {
            epoch: 4,
            digest: [7; 32],
        })
        .unwrap();
    // The record goes: no identity can be read.
    std::fs::remove_file(gen_dir.join(heimdall_stategen::generations::RECORD)).unwrap();
    let request = |backup: &Path, confirmed: bool| {
        restore_locked(
            &home.root,
            &RealFs,
            &RestoreRequest {
                backup,
                now: at(60),
                recovery_confirmed: confirmed,
                event: &Appends,
                operation_retention: RETENTION,
            },
        )
    };
    assert!(matches!(
        request(&copy, true),
        Err(RestoreError::Refused(Refusal::NotOwnBackup))
    ));
    assert!(matches!(
        request(&own, false),
        Err(RestoreError::Refused(Refusal::RecoveryNotConfirmed))
    ));
    let out = request(&own, true).unwrap();
    assert_eq!(
        out.current.record.restore_epoch, 5,
        "above the ledger's epoch 4"
    );
    assert!(!out.carried_forward);
    assert_eq!(home.open().current.name, out.current.name);
    assert!(is_own_backup(&home.root, &own));
    assert!(!is_own_backup(&home.root, &copy));
}

/// `state repair` (U0-Q8): the decodable records after the damage become fence records, the
/// epoch rises, and the ledger is cut at the first damaged record; a whole ledger has nothing
/// to repair.
#[test]
fn repair_fences_what_follows_the_damage_raises_the_epoch_and_cuts_the_ledger() {
    let home = Home::new();
    let ledger = Ledger::new(RealFs, &home.root);
    for n in 1..=3u8 {
        ledger
            .append(heimdall_stategen::Entry {
                epoch: 0,
                digest: [n; 32],
            })
            .unwrap();
    }
    let opened = home.open();
    assert!(matches!(
        repair_locked(&home.root, &RealFs, &opened.store, at(10)),
        Err(RestoreError::Refused(Refusal::WrongState(_)))
    ));
    let path = home.root.join(heimdall_stategen::ledger::LEDGER);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[heimdall_stategen::ledger::RECORD_LEN + 20] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let out = repair_locked(&home.root, &RealFs, &opened.store, at(10)).unwrap();
    assert_eq!(out.fenced_records, 1, "the third record");
    assert_eq!(out.dropped_records, 1, "the damaged second");
    assert_eq!(out.restore_epoch, RestoreEpoch(1));
    opened
        .store
        .transaction(|tx| {
            assert_eq!(tx.restore_epoch()?, RestoreEpoch(1));
            assert!(tx.request_fence(&[3; 32])?.is_some());
            assert!(tx.request_fence(&[1; 32])?.is_none(), "kept in the ledger");
            Ok(())
        })
        .unwrap();
    let read = ledger.read().unwrap();
    assert_eq!(read.entries.len(), 1, "cut at the first damaged record");
}

/// `runner_effect_applied_after_the_backup_is_adopted_not_resent`, at the store (ADR-0014 §3.6
/// step 7): the runner's own effect ledger is the authority. A runner restored from a backup
/// taken before it applied an effect keeps that effect's recorded acknowledgement (with the
/// tombstone it names), so a redelivery is answered from it and nothing is applied again; a
/// controller restored from before the acknowledgement keeps it, and an effect it produced
/// after the backup, as acknowledged facts, so neither is sent again.
#[test]
fn runner_effect_applied_after_the_backup_is_adopted_not_resent() {
    use crate::ext_effects::{AppliedRecord, EffectAck, EffectKey};
    use heimdall_contract::ids::EffectId;
    use heimdall_contract::managed::ComponentResidual;
    use heimdall_contract::remote::EffectTarget;
    let producer = ClientId::from_random_bytes([3; 16]);
    let key = |n: u8, g: &GrantId| EffectKey {
        producer: producer.clone(),
        effect: EffectId::parse(&format!("eff_0{n}")).unwrap(),
        target: EffectTarget::GrantRevoke {
            grant: g.clone(),
            grant_generation: 0,
        },
    };
    let ack = |k: &EffectKey| EffectAck {
        key: k.clone(),
        applied_at: at(30),
        record: AppliedRecord::GrantTombstone {
            grant: match &k.target {
                EffectTarget::GrantRevoke { grant, .. } => grant.clone(),
                _ => unreachable!(),
            },
            known: true,
            cascade: Vec::new(),
            key_destroyed: true,
            owned_dedicated_sessions: ComponentResidual::Closed,
            owned_admissions: ComponentResidual::Closed,
        },
    };
    // The runner.
    let runner = Home::new();
    let g = grant(1, GrantState::Active);
    runner.write(|tx| tx.insert_grant(&g));
    let backup = runner.backup("runner.db");
    let applied = key(1, &g.id);
    runner.write(|tx| {
        tx.insert_tombstone(&Tombstone {
            grant: g.id.clone(),
            cascade: Vec::new(),
            generation: AuthorityGeneration(0),
            revoked_at: at(30),
            remote_pending: Vec::new(),
            cause: RevocationCause::Revoke,
        })?;
        let mut revoked = g.clone();
        revoked.state = GrantState::Revoked;
        tx.update_grant_state(&revoked)?;
        tx.record_remote_effect_ack(&ack(&applied))
    });
    runner.restore(&backup).unwrap();
    runner.read(|tx| {
        assert_eq!(
            tx.remote_effect_ack(&applied)?,
            Some(ack(&applied)),
            "the redelivery's recorded answer"
        );
        assert_eq!(
            tx.tombstone(&g.id)?.map(|t| t.revoked_at),
            Some(at(30)),
            "the tombstone it names, as applied"
        );
        Ok(())
    });
    // The controller.
    let controller = Home::new();
    let (environment, earlier) = controller.write(|tx| {
        let environment = pin(tx, 20)?;
        let earlier = key(2, &GrantId::from_random_bytes([9; 16]));
        assert!(tx.enqueue_remote_effect(&environment, &earlier, t0())?);
        Ok((environment, earlier))
    });
    let backup = controller.backup("controller.db");
    let later = key(3, &GrantId::from_random_bytes([8; 16]));
    controller.write(|tx| {
        assert!(tx.acknowledge_remote_effect(&ack(&earlier), at(40))?);
        assert!(tx.enqueue_remote_effect(&environment, &later, at(41))?);
        assert!(tx.acknowledge_remote_effect(&ack(&later), at(42))?);
        Ok(())
    });
    let out = controller.restore(&backup).unwrap();
    assert_eq!(
        out.remote_effects_pending, 0,
        "nothing is pending to be sent again"
    );
    controller.read(|tx| {
        assert!(
            tx.remote_effect_outbox(Some(&environment), true)?
                .is_empty()
        );
        let all = tx.remote_effect_outbox(Some(&environment), false)?;
        assert_eq!(all.len(), 2, "both acknowledged effects are known facts");
        Ok(())
    });
}
