//! ⟨M06⟩ W1 follow-up, M06-W0-R03 (ADR-0006 §18.2 item 17, the orchestrator's ruling):
//! paired callers are client-scoped, through the real `Operations` over an in-memory store.
//! ⟨M06 W2, blocking⟩ Live events too, through the runner runtime's dispatcher and the real
//! IPC session: the runtime overrides the dispatcher's live-event visibility hook
//! (`a_paired_caller_receives_live_events_only_within_its_scope`; hosted by
//! `heimdall-runtime` since W2, which owns the override).
//!
//! Three callers on **one** OS principal: the local owner (no paired client), a paired owner
//! (client A) and a paired requester (client B). B's work is invisible to A on every path:
//! `observe` of the operation, `cancel`, binding ownership (`release`, `bind`), the snapshot,
//! event pages, a resumed subscription's backlog and the live-event visibility. Positive
//! controls: B sees its own work, the local owner keeps its global access, and A keeps the
//! named cross-controller narrowing power (it revokes B's grant, ADR-0012 §7.2, §8).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::event::{Cursor, Event, EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, BindingId, ClientId, DecisionId, DestinationId, DeviceId, EnvironmentId, GrantId,
    InvitationId, KeyFingerprint, OperationId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::ipc::{ClientHello, PeerInfo, PrincipalInfo, capability};
use heimdall_contract::remote::Role;
use heimdall_contract::request::{
    BindForm, BindRequest, CancelRequest, EnsureRequest, InteractionMode, ObserveRequest,
    RefreshDependency, ReleaseRequest, RequiredCapabilities, RevokeRequest, WaitMode,
};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_ipc::session::{
    ConnectionLimits, ControlClient, ControlConnection, SubscribeOutcome, server_capabilities,
};
use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
use heimdall_runtime::paired::{PairedRunner, RunnerOptions};
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock};
use tokio_util::sync::CancellationToken;

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn principal() -> PrincipalRef {
    PrincipalRef::UnixUser { uid: 501 }
}

fn local_owner() -> CallerContext {
    CallerContext::local(principal(), ClientRole::Owner)
}

fn paired(n: u8, role: ClientRole) -> CallerContext {
    CallerContext {
        principal: principal(),
        role,
        remote_client: Some(ClientId::from_random_bytes([n; 16])),
    }
}

fn paired_owner() -> CallerContext {
    paired(0xa1, ClientRole::Owner)
}

fn paired_requester() -> CallerContext {
    paired(0xb2, ClientRole::LimitedConsumer)
}

fn scope() -> Scope {
    Scope {
        pairs: [AccessPair {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }]
        .into_iter()
        .collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    }
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: t0()
            .checked_add(jiff::SignedDuration::from_hours(12))
            .unwrap(),
        offline_until: t0()
            .checked_add(jiff::SignedDuration::from_hours(1))
            .unwrap(),
        refresh_dependency: RefreshDependency::None,
        enforcement: EnforcementEvidence::unknown(),
        credential_ref: "paired-scope-fixture".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
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
                id: ProfileId::parse("dev").unwrap(),
                revision: 1,
                scope: scope(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: scope(),
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                    default: false,
                },
                false,
            )?;
            Ok(())
        })
        .unwrap();
}

struct World {
    store: Arc<Store>,
    ops: Operations,
    clock: Arc<VirtualClock>,
}

impl World {
    async fn new() -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
        seed(&store);
        let descriptor = AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            },
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: EnforcementEvidence::unknown(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false,
        };
        let fake = FakeCredentialAdapter::new(descriptor, [FakeStep::Prepare(outcome())]);
        let clock = VirtualClock::at(t0());
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
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
        Self { store, ops, clock }
    }

    /// `observe events` with no cursor: the snapshot, and its cursor.
    async fn snapshot(&self, who: &CallerContext) -> (serde_json::Value, Cursor) {
        self.snapshot_of(who, EventFilter::default()).await
    }

    async fn snapshot_of(
        &self,
        who: &CallerContext,
        filter: EventFilter,
    ) -> (serde_json::Value, Cursor) {
        let r = self
            .ops
            .observe(
                &Caller::unattended(who.clone()),
                ObserveRequest::Events {
                    cursor: None,
                    filter,
                    limit: None,
                },
            )
            .await
            .unwrap();
        let snap = r.data["snapshot"].clone();
        let cursor: Cursor = serde_json::from_value(snap["cursor"].clone()).unwrap();
        (snap["data"].clone(), cursor)
    }

    /// One event page after `cursor`.
    async fn page(&self, who: &CallerContext, cursor: Cursor) -> Vec<Event> {
        let r = self
            .ops
            .observe(
                &Caller::unattended(who.clone()),
                ObserveRequest::Events {
                    cursor: Some(cursor),
                    filter: EventFilter::default(),
                    limit: Some(500),
                },
            )
            .await
            .unwrap();
        serde_json::from_value(r.data["events"].clone()).unwrap()
    }
}

fn snapshot_ops(data: &serde_json::Value) -> Vec<String> {
    data["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["operation_id"].as_str().unwrap().to_owned())
        .collect()
}

/// Whether any event concerns B's operation, binding or grant.
fn concerns(events: &[Event], op: &OperationId, binding: &BindingId, grant: &GrantId) -> bool {
    events.iter().any(|e| {
        e.operation_id.as_ref() == Some(op)
            || e.resource.as_ref().is_some_and(|r| {
                r.id.as_deref() == Some(binding.as_str()) || r.id.as_deref() == Some(grant.as_str())
            })
    })
}

#[tokio::test]
async fn a_paired_owner_is_scoped_to_its_own_client_on_every_path() {
    let w = World::new().await;
    let a = paired_owner();
    let b = paired_requester();
    let local = local_owner();

    // Cursors taken before B's work, for each reader.
    let (_, a_before) = w.snapshot(&a).await;
    let (_, b_before) = w.snapshot(&b).await;
    let (_, local_before) = w.snapshot(&local).await;

    // B's work: an ensure inside standing policy.
    let ensured = w
        .ops
        .ensure(
            &Caller::unattended(b.clone()),
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: BTreeSet::new(),
                environment: None,
                work_id: WorkId::parse("work-b").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("req-b").unwrap(),
                interaction: InteractionMode::NonInteractive,
                wait: WaitMode::default(),
                connection: None,
                context: None,
                covered_only: false,
                pair_issuers: Vec::new(),
            },
        )
        .await
        .unwrap();
    assert_eq!(ensured.code, Code::AccessReady);
    let op = ensured.operation_id.clone().unwrap();
    let binding = ensured.data.binding_id.clone();
    let grant = ensured.data.grant_id.clone();
    let observe_op = |who: &CallerContext| {
        let ops = &w.ops;
        let caller = Caller::unattended(who.clone());
        let op = op.clone();
        async move {
            ops.observe(
                &caller,
                ObserveRequest::Operation {
                    operation_id: op,
                    wait_ms: None,
                },
            )
            .await
        }
    };

    // observe: B and the local owner see the operation; the paired owner does not.
    assert!(observe_op(&b).await.is_ok());
    assert!(observe_op(&local).await.is_ok());
    assert_eq!(observe_op(&a).await.unwrap_err().code, Code::NotFound);

    // cancel: refused to the paired owner as unknown, nothing changes.
    let cancel = w
        .ops
        .cancel(
            &Caller::unattended(a.clone()),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await;
    assert_eq!(cancel.unwrap_err().code, Code::NotFound);

    // Binding ownership: the paired owner may neither release nor bind B's binding.
    let release = w
        .ops
        .release(
            &Caller::unattended(a.clone()),
            ReleaseRequest {
                binding_id: binding.clone(),
            },
        )
        .await;
    assert!(release.is_err(), "{release:?}");
    let bind = w
        .ops
        .bind(
            &Caller::unattended(a.clone()),
            BindRequest {
                binding_id: binding.clone(),
                form: BindForm::Materialize,
                request_id: RequestId::parse("req-a-bind").unwrap(),
            },
        )
        .await;
    assert_eq!(bind.unwrap_err().code, Code::NotFound);
    let still_active = w
        .store
        .transaction(|tx| tx.binding(&binding))
        .unwrap()
        .unwrap();
    assert_eq!(
        still_active.state,
        heimdall_domain::binding::BindingState::Active
    );

    // The snapshot: the operation the filter names (⟨PC1⟩ its only section, ADR-0013 §5.5),
    // and without a filter the open operations, only for B and the local owner.
    let named = EventFilter {
        operation_id: Some(op.clone()),
        types: Vec::new(),
    };
    let (a_snap, _) = w.snapshot_of(&a, named.clone()).await;
    let (b_snap, _) = w.snapshot_of(&b, named.clone()).await;
    let (local_snap, _) = w.snapshot_of(&local, named).await;
    assert!(a_snap.get("operation").is_none(), "{a_snap}");
    assert_eq!(b_snap["operation"]["operation_id"], op.to_string());
    assert_eq!(local_snap["operation"]["operation_id"], op.to_string());
    for snap in [&a_snap, &b_snap, &local_snap] {
        assert!(snap.get("operations").is_none(), "{snap}");
        assert!(snap.get("pending_decisions").is_none(), "{snap}");
    }
    let (a_all, _) = w.snapshot(&a).await;
    let (b_all, _) = w.snapshot(&b).await;
    let (local_all, _) = w.snapshot(&local).await;
    assert!(!snapshot_ops(&a_all).contains(&op.to_string()));
    assert_eq!(snapshot_ops(&b_all), snapshot_ops(&local_all));

    // Event pages.
    let a_page = w.page(&a, a_before.clone()).await;
    let b_page = w.page(&b, b_before.clone()).await;
    let local_page = w.page(&local, local_before.clone()).await;
    assert!(
        concerns(&b_page, &op, &binding, &grant),
        "B sees its own work"
    );
    assert!(
        concerns(&local_page, &op, &binding, &grant),
        "the local owner sees all"
    );
    assert!(!concerns(&a_page, &op, &binding, &grant), "{a_page:#?}");

    // A resumed subscription's backlog, and the live visibility.
    let a_sub = w
        .ops
        .events()
        .subscribe(&a, EventFilter::default(), Some(a_before), true)
        .await
        .unwrap();
    let b_sub = w
        .ops
        .events()
        .subscribe(&b, EventFilter::default(), Some(b_before), true)
        .await
        .unwrap();
    let local_sub = w
        .ops
        .events()
        .subscribe(&local, EventFilter::default(), Some(local_before), true)
        .await
        .unwrap();
    assert!(!concerns(&a_sub.backlog, &op, &binding, &grant));
    assert!(concerns(&b_sub.backlog, &op, &binding, &grant));
    assert!(concerns(&local_sub.backlog, &op, &binding, &grant));
    let b_events: Vec<&Event> = local_page
        .iter()
        .filter(|e| concerns(std::slice::from_ref(e), &op, &binding, &grant))
        .collect();
    assert!(!b_events.is_empty());
    for e in &b_events {
        assert!(
            !(a_sub.visible)(e),
            "live: hidden from the paired owner: {e:?}"
        );
        assert!((b_sub.visible)(e), "live: visible to B");
        assert!((local_sub.visible)(e), "live: visible to the local owner");
    }
    // Environment-level events stay visible by role.
    if let Some(policy_like) = local_page
        .iter()
        .find(|e| e.operation_id.is_none() && e.resource.is_none())
    {
        assert!((a_sub.visible)(policy_like));
    }

    // ⟨M06 W2; the ruling on M06-W0-R03⟩ Decision and resource events are owner-role views:
    // a requester never receives one, even about its own operation or binding, while an
    // event of its own work of another type still reaches it; the local owner sees all.
    let about =
        |event_type, operation: Option<OperationId>, resource: Option<(&str, &str)>| Event {
            schema_version: heimdall_contract::SchemaVersion::current(),
            event_id: heimdall_contract::ids::EventId::from_random_bytes([0x3c; 16]),
            event_type,
            environment_id: env_id(),
            operation_id: operation,
            resource: resource.map(|(kind, id)| heimdall_contract::envelope::ResourceRef {
                kind: kind.into(),
                id: Some(id.into()),
            }),
            timestamp: t0(),
            cursor: Cursor(String::new()),
            payload: serde_json::json!({}),
        };
    let visible = |e: &Event, who: &CallerContext| {
        w.store
            .transaction(|tx| heimdall_app::events::event_visible_in(tx, e, who))
            .unwrap()
    };
    for e in [
        about(EventType::Decision, Some(op.clone()), None),
        about(
            EventType::ResourceChanged,
            None,
            Some(("binding", binding.as_str())),
        ),
    ] {
        assert!(!visible(&e, &b), "{e:?}");
        assert!(!visible(&e, &a), "{e:?}");
        assert!(visible(&e, &local), "{e:?}");
    }
    let own = about(
        EventType::GrantStateChanged,
        None,
        Some(("grant", grant.as_str())),
    );
    assert!(visible(&own, &b) && !visible(&own, &a));

    // Positive control: the named cross-controller narrowing power. The paired owner
    // revokes B's grant (ADR-0012 §7.2, §8), and B's binding then reflects it.
    let revoked = w
        .ops
        .revoke(
            &Caller::unattended(a.clone()),
            RevokeRequest {
                grant_id: Some(grant.clone()),
                request_id: RequestId::parse("req-a-revoke").unwrap(),
                target: None,
            },
        )
        .await
        .unwrap();
    assert!(revoked.data.local_applied);
    // A paired requester holds no narrowing power over another client's grant.
    let other = paired(0xc3, ClientRole::LimitedConsumer);
    let refused = w
        .ops
        .revoke(
            &Caller::unattended(other),
            RevokeRequest {
                grant_id: Some(grant.clone()),
                request_id: RequestId::parse("req-c-revoke").unwrap(),
                target: None,
            },
        )
        .await;
    assert_eq!(refused.unwrap_err().code, Code::NotFound);

    // Positive control: the local owner's global access releases B's binding.
    let released = w
        .ops
        .release(
            &Caller::unattended(local.clone()),
            ReleaseRequest {
                binding_id: binding.clone(),
            },
        )
        .await;
    assert!(released.is_ok(), "{released:?}");
}

// --- ⟨M06 W2, blocking (M06-W0-R03)⟩ live events through the runner runtime -------------------

/// Seed a paired client's active row in the runner's role table (a pending invitation
/// consumed by its join), as `heimdall_remote`'s invitation service leaves it.
fn seed_client(store: &Store, ctx: &CallerContext, role: Role, n: u8) {
    use heimdall_store::ext_m06::{
        AppliedLine, ClientState, InvitationState, JoinRecord, RemoteClientRecord,
        RemoteInvitationRecord,
    };
    let client = ctx.remote_client.clone().unwrap();
    let invitation = InvitationId::from_random_bytes([n; 16]);
    let fp = KeyFingerprint::parse(&format!(
        "SHA256:{}",
        char::from(b'A' + n % 26).to_string().repeat(43)
    ))
    .unwrap();
    let rec = RemoteClientRecord {
        client: client.clone(),
        role,
        key_fingerprint: fp.clone(),
        public_key: "ssh-ed25519 AAAA".into(),
        state: ClientState::Pending,
        invitation: Some(invitation.clone()),
        revoked_generation: None,
        revocation: None,
        created_at: t0(),
        updated_at: t0(),
        line: AppliedLine::Absent,
    };
    let generation = store.transaction(|tx| tx.authority_generation()).unwrap().0;
    let inv = RemoteInvitationRecord {
        invitation: invitation.clone(),
        client: client.clone(),
        role,
        key_fingerprint: fp,
        generation,
        created_wall: t0(),
        created_boot_id: heimdall_domain::time::BootId("boot".into()),
        created_elapsed: Duration::from_secs(1),
        expires_wall: t0()
            .checked_add(jiff::SignedDuration::from_mins(15))
            .unwrap(),
        elapsed_bound: Duration::from_secs(900),
        probe_nonce: "00".into(),
        state: InvitationState::Pending,
        consumed_at: None,
        join: None,
        iroh_admission: false,
    };
    store
        .transaction(|tx| {
            tx.insert_remote_invitation(&rec, &inv, t0())?;
            tx.activate_remote_client(&JoinRecord {
                environment: env_id(),
                invitation,
                client,
                role,
                generation,
                joined_at: t0(),
            })
            .map(drop)
        })
        .unwrap();
}

/// A hello as the runner's bridge originates it (`remote_client` from its argv), or the
/// local caller's (none).
fn hello(client: Option<&CallerContext>) -> ClientHello {
    let mut capabilities = server_capabilities();
    capabilities.insert(capability::REMOTE_CONTROL_V1.to_owned());
    ClientHello {
        protocol: heimdall_contract::PROTOCOL_VERSION,
        schema_version: heimdall_contract::SchemaVersion::current(),
        client: PeerInfo {
            name: "fixture".into(),
            version: "0".into(),
        },
        capabilities,
        required: BTreeSet::new(),
        interaction: InteractionMode::NonInteractive,
        remote_client: client.and_then(|c| c.remote_client.clone()),
    }
}

/// ⟨M06 W2⟩ An event a paired caller received carries no handle of `decision`: no
/// `decision_id`, no decision resource ID, and the ID nowhere in it.
fn assert_no_decision_handle(e: &Event, decision: &str) {
    assert!(e.payload.get("decision_id").is_none(), "{e:?}");
    if let Some(r) = &e.resource {
        assert!(r.kind != "decision" || r.id.is_none(), "{e:?}");
    }
    assert!(
        !serde_json::to_string(e).unwrap().contains(decision),
        "{e:?}"
    );
}

/// Read one subscriber's live events until it has seen `markers` policy changes (the
/// environment-level events every role sees).
async fn until_markers(
    c: &mut ControlClient<tokio::io::DuplexStream>,
    markers: usize,
) -> Vec<Event> {
    let mut seen = Vec::new();
    let mut found = 0;
    while found < markers {
        let (_, e) = tokio::time::timeout(Duration::from_secs(10), c.next_event())
            .await
            .expect("the marker arrives")
            .unwrap();
        if e.event_type == EventType::PolicyChanged {
            found += 1;
        }
        seen.push(e);
    }
    seen
}

/// ⟨M06 W2, blocking (M06-W0-R03)⟩ Live events reach a paired caller only within its client
/// scope and the environment views its role permits, through the runner runtime's
/// dispatcher (its `Dispatcher::live_visibility` override) and the real IPC session; the
/// local owner keeps every event. A paired owner receives decision events as read-only
/// owner-role views carrying no decision handle (⟨W2 fixes⟩ stripped on every paired path:
/// live, event pages, snapshot, resumed backlog, `inspect decisions`), and its `Decide` is
/// refused before dispatch; a requester's view set names no decision event. Revert proofs:
/// with the visibility override disabled (returning `None`), the paired owner receives B's
/// events and this test fails; with the redaction disabled it receives the decision handle
/// and this test fails (`target/m06-w2/runtime/revert-*.log`).
#[tokio::test]
async fn a_paired_caller_receives_live_events_only_within_its_scope() {
    let w = World::new().await;
    assert_eq!(
        heimdall_runtime::paired::init_runner(&w.store).unwrap(),
        env_id()
    );
    let a = paired_owner();
    let b = paired_requester();
    seed_client(&w.store, &a, Role::Owner, 1);
    seed_client(&w.store, &b, Role::Requester, 2);
    let stop = CancellationToken::new();
    let relay = EventRelay::spawn(&w.ops, stop.clone());
    let runner = Arc::new(PairedRunner::new(
        w.store.clone(),
        w.ops.clone(),
        w.clock.clone(),
        RunnerOptions::default(),
    ));
    let dispatcher =
        OperationsDispatcher::new(w.ops.clone(), relay, w.clock.clone()).with_runner(runner);
    let connect = |who: Option<&CallerContext>| {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let conn = ControlConnection::new(server_end, ConnectionLimits::default())
            .with_server_identity(
                env_id(),
                PeerInfo {
                    name: "runner".into(),
                    version: "0".into(),
                },
            );
        let d = dispatcher.clone();
        let s = stop.clone();
        tokio::spawn(async move {
            let _ = conn
                .serve(PrincipalInfo::OsUserUnix { uid: 501 }, d, s)
                .await;
        });
        ControlClient::handshake_hello(client_end, hello(who))
    };
    let mut a_session = connect(Some(&a)).await.unwrap();
    let mut b_session = connect(Some(&b)).await.unwrap();
    let mut local = connect(None).await.unwrap();
    assert_eq!(a_session.server().role, Some(Role::Owner));
    assert_eq!(b_session.server().role, Some(Role::Requester));
    let mut boundaries = Vec::new();
    for c in [&mut a_session, &mut b_session, &mut local] {
        let SubscribeOutcome::Subscribed { cursor, .. } =
            c.subscribe(EventFilter::default(), None).await.unwrap()
        else {
            panic!("subscribe refused");
        };
        boundaries.push(cursor);
    }
    let a_boundary = boundaries[0].clone();

    // B's work, over its own paired session.
    let ensured = b_session
        .request(
            serde_json::from_value(serde_json::json!({
                "op": "ensure", "profile": "dev", "work_id": "work-b", "request_id": "req-b",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ensured.code, Code::AccessReady, "{ensured:?}");
    let op: OperationId = serde_json::from_value(serde_json::json!(ensured.operation_id)).unwrap();
    let binding: BindingId = serde_json::from_value(ensured.data["binding_id"].clone()).unwrap();
    let grant: GrantId = serde_json::from_value(ensured.data["grant_id"].clone()).unwrap();
    // The local owner: a pause (marker), a widening resume that creates a decision record
    // (unattended: nothing executes), then a narrowing cutoff (the last marker).
    let pause = local
        .request(
            serde_json::from_str(r#"{"op":"policy","action":"pause","policy_id":"pol"}"#).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pause.code, Code::Ok, "{pause:?}");
    let resume = local
        .request(
            serde_json::from_str(r#"{"op":"policy","action":"resume","policy_id":"pol"}"#).unwrap(),
        )
        .await
        .unwrap();
    let decision = resume
        .next
        .and_then(|n| n.decision_ref)
        .expect("a decision record");
    let cutoff = local
        .request(
            serde_json::from_value(serde_json::json!({
                "op": "policy", "action": "cutoff", "policy_id": "pol",
                "at": "2026-10-02T11:00:00Z",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cutoff.code, Code::Ok, "{cutoff:?}");

    let a_events = until_markers(&mut a_session, 2).await;
    let b_events = until_markers(&mut b_session, 2).await;
    let local_events = until_markers(&mut local, 2).await;
    // Client scope: B's work reaches B and the local owner, never the paired owner.
    assert!(
        concerns(&b_events, &op, &binding, &grant),
        "B sees its own work"
    );
    assert!(
        concerns(&local_events, &op, &binding, &grant),
        "the local owner sees all"
    );
    assert!(
        !concerns(&a_events, &op, &binding, &grant),
        "the paired owner received B's work: {a_events:#?}"
    );
    // Role views: the decision event reaches the paired owner read-only, never the requester.
    // ⟨M06 W2; the orchestrator's ruling⟩ It carries no decision handle: no `decision_id`, no
    // decision resource ID, on every paired path (live here; pages, snapshot, resumed
    // backlog and `inspect decisions` below). The local owner keeps the reference.
    let a_decisions: Vec<&Event> = a_events
        .iter()
        .filter(|e| e.event_type == EventType::Decision)
        .collect();
    assert!(!a_decisions.is_empty(), "the owner-role view");
    for e in &a_decisions {
        assert_no_decision_handle(e, &decision);
    }
    assert!(
        local_events
            .iter()
            .any(|e| e.event_type == EventType::Decision
                && e.payload["decision_id"] == decision
                && e.resource.as_ref().and_then(|r| r.id.as_deref()) == Some(decision.as_str()))
    );
    assert!(!b_events.iter().any(|e| e.event_type == EventType::Decision));
    // An event page from the paired owner's boundary.
    let page = a_session
        .request(
            serde_json::from_value(serde_json::json!({
                "op": "observe", "kind": "events", "cursor": a_boundary, "limit": 500,
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.code, Code::Ok, "{page:?}");
    let paged: Vec<Event> = serde_json::from_value(page.data["events"].clone()).unwrap();
    assert!(paged.iter().any(|e| e.event_type == EventType::Decision));
    paged
        .iter()
        .for_each(|e| assert_no_decision_handle(e, &decision));
    // The snapshot (no cursor) lists the pending decision without its handle.
    let snap = a_session
        .request(
            serde_json::from_value(serde_json::json!({"op": "observe", "kind": "events"})).unwrap(),
        )
        .await
        .unwrap();
    let pending = &snap.data["snapshot"]["data"]["pending_decisions"];
    assert!(!pending.as_array().unwrap().is_empty(), "{snap:?}");
    assert!(!snap.data.to_string().contains(&decision), "{snap:?}");
    // A subscription resumed from the boundary: its backlog.
    let SubscribeOutcome::Subscribed { .. } = a_session
        .subscribe(EventFilter::default(), Some(a_boundary.clone()))
        .await
        .unwrap()
    else {
        panic!("resume refused");
    };
    let resumed = until_markers(&mut a_session, 2).await;
    assert!(resumed.iter().any(|e| e.event_type == EventType::Decision));
    resumed
        .iter()
        .for_each(|e| assert_no_decision_handle(e, &decision));
    // `inspect decisions` lists it without its handle; the local owner's names it.
    let inspect = serde_json::json!({"op": "inspect", "subject": "decisions"});
    let listed = a_session
        .request(serde_json::from_value(inspect.clone()).unwrap())
        .await
        .unwrap();
    assert_eq!(listed.code, Code::Ok, "{listed:?}");
    assert!(!listed.data.to_string().contains(&decision), "{listed:?}");
    let local_listed = local
        .request(serde_json::from_value(inspect).unwrap())
        .await
        .unwrap();
    assert!(local_listed.data.to_string().contains(&decision));
    // The reference is not usable for approval from the paired session.
    let decide = a_session
        .request(
            serde_json::from_value(serde_json::json!({
                "op": "decide", "decision_id": decision, "verdict": "approve",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decide.code, Code::InteractionRequired);
    assert_eq!(
        decide.data["error"]["reason"],
        heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED,
        "{decide:?}"
    );
    let still = w
        .store
        .transaction(|tx| tx.decision(&DecisionId::parse(&decision).unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(
        still.state,
        heimdall_domain::decision::DecisionState::Pending
    );
    stop.cancel();
}

/// ⟨M06 W1 review⟩ The snapshot's **open** operations are client-scoped too: another paired
/// owner's operation that stays open (awaiting approval: `h3` is in the profile but not in
/// the standing policy) is listed for its own client and the local owner, never for the
/// paired owner A. (The W1 case's operation settles at once, so it never reached this list.)
#[tokio::test]
async fn a_paired_owner_does_not_see_another_clients_open_operations() {
    let w = World::new().await;
    let pair = |d: &str| AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    };
    w.store
        .transaction(|tx| {
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("dev").unwrap(),
                revision: 2,
                scope: Scope {
                    pairs: [pair("h1"), pair("h3")].into_iter().collect(),
                    capabilities: [Capability::SshAuthentication].into_iter().collect(),
                },
                label: None,
            })
        })
        .unwrap();
    let a = paired_owner();
    let c = paired(0xc4, ClientRole::Owner);
    let local = local_owner();
    let refused = w
        .ops
        .ensure(
            &Caller::unattended(c.clone()),
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: ["h1", "h3"]
                    .into_iter()
                    .map(|d| heimdall_contract::request::AccessPairRef {
                        destination: DestinationId::parse(d).unwrap(),
                        account: AccountName::parse("deploy").unwrap(),
                    })
                    .collect(),
                environment: None,
                work_id: WorkId::parse("work-c").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("req-c").unwrap(),
                interaction: InteractionMode::NonInteractive,
                wait: WaitMode::default(),
                connection: None,
                context: None,
                covered_only: false,
                pair_issuers: Vec::new(),
            },
        )
        .await
        .unwrap_err();
    let op = refused.operation_id.clone().expect("an open operation");
    let state = w
        .store
        .transaction(|tx| tx.operation(&op))
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(state, heimdall_contract::OperationState::AwaitingApproval);
    let (a_snap, _) = w.snapshot(&a).await;
    let (c_snap, _) = w.snapshot(&c).await;
    let (local_snap, _) = w.snapshot(&local).await;
    assert!(snapshot_ops(&c_snap).contains(&op.to_string()), "{c_snap}");
    assert!(snapshot_ops(&local_snap).contains(&op.to_string()));
    assert!(
        !snapshot_ops(&a_snap).contains(&op.to_string()),
        "another client's open operation reached the paired owner: {a_snap}"
    );
}

/// ⟨Gemini W1 R06⟩ Client B's **unresolved** operation (outcome unknown) is listed in B's and
/// the local owner's snapshot, never in paired owner A's; and A may neither `stop` B's work
/// (`stop_m05::may_stop`) nor `delegate` from B's binding, while B and the local owner may
/// (positive controls: B delegates, the local owner stops).
#[tokio::test]
async fn a_paired_owner_cannot_reach_another_clients_unresolved_work_stop_or_delegate() {
    let w = World::new().await;
    let a = paired_owner();
    let b = paired_requester();
    let local = local_owner();
    let ensured = w
        .ops
        .ensure(
            &Caller::unattended(b.clone()),
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: BTreeSet::new(),
                environment: None,
                work_id: WorkId::parse("work-b").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("req-b").unwrap(),
                interaction: InteractionMode::NonInteractive,
                wait: WaitMode::default(),
                connection: None,
                context: None,
                covered_only: false,
                pair_issuers: Vec::new(),
            },
        )
        .await
        .unwrap();
    let binding = ensured.data.binding_id.clone();
    let settled = ensured.operation_id.clone().unwrap();

    // B's unresolved operation: B's own record, as an outcome-unknown copy under a new key.
    let unresolved = OperationId::from_random_bytes([0x5e; 16]);
    w.store
        .transaction(|tx| {
            let mut op = tx.operation(&settled)?.unwrap();
            op.id = unresolved.clone();
            op.state = heimdall_contract::OperationState::OutcomeUnknown;
            op.key.request_id = RequestId::parse("req-b-unresolved").unwrap();
            let idem = heimdall_domain::idempotency::IdempotencyRecord {
                key: op.key.clone(),
                request_hash: op.request_hash,
                operation_id: op.id.clone(),
                created_at: op.created_at,
                expires_at: None,
            };
            tx.insert_operation(&op, &idem)
        })
        .unwrap();
    let (a_snap, _) = w.snapshot(&a).await;
    let (b_snap, _) = w.snapshot(&b).await;
    let (local_snap, _) = w.snapshot(&local).await;
    assert!(
        snapshot_ops(&b_snap).contains(&unresolved.to_string()),
        "{b_snap}"
    );
    assert!(snapshot_ops(&local_snap).contains(&unresolved.to_string()));
    assert!(
        !snapshot_ops(&a_snap).contains(&unresolved.to_string()),
        "another client's unresolved operation reached the paired owner: {a_snap}"
    );

    // delegate: refused to A as unknown; B's own delegation is admitted.
    let delegate = |who: &CallerContext, rid: &str, work: &str| {
        let caller = Caller::unattended(who.clone());
        let req = heimdall_contract::request::DelegateRequest {
            parent_binding_id: binding.clone(),
            scope: BTreeSet::new(),
            until: None,
            work_id: WorkId::parse(work).unwrap(),
            request_id: RequestId::parse(rid).unwrap(),
            required_capabilities: RequiredCapabilities::default(),
        };
        let ops = &w.ops;
        async move { ops.delegate(&caller, req).await }
    };
    assert_eq!(
        delegate(&a, "req-a-delegate", "work-a-child")
            .await
            .unwrap_err()
            .code,
        Code::NotFound
    );
    let own = delegate(&b, "req-b-delegate", "work-b-child").await;
    assert!(
        own.as_ref()
            .map_or_else(|e| e.code != Code::NotFound, |_| true),
        "B's own delegation is not refused as unknown: {own:?}"
    );

    // stop: refused to A as unknown, the work keeps its binding; the local owner stops it.
    let stop = |who: &CallerContext, rid: &str| {
        let caller = Caller::unattended(who.clone());
        let req = RevokeRequest {
            grant_id: None,
            request_id: RequestId::parse(rid).unwrap(),
            target: Some(heimdall_contract::trust::RevokeTarget::Work {
                environment: None,
                work_id: WorkId::parse("work-b").unwrap(),
            }),
        };
        let ops = &w.ops;
        async move { ops.revoke(&caller, req).await }
    };
    assert_eq!(
        stop(&a, "req-a-stop").await.unwrap_err().code,
        Code::NotFound
    );
    let still = w
        .store
        .transaction(|tx| tx.binding(&binding))
        .unwrap()
        .unwrap();
    assert_eq!(still.state, heimdall_domain::binding::BindingState::Active);
    let stopped = stop(&local, "req-local-stop").await;
    assert!(
        stopped.is_ok(),
        "the local owner stops any work: {stopped:?}"
    );
}
