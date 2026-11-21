//! ⟨M06⟩ W1 follow-up, M06-W0-R03 (ADR-0006 §18.2 item 17, the orchestrator's ruling):
//! paired callers are client-scoped, through the real `Operations` over an in-memory store.
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
use heimdall_contract::event::{Cursor, Event, EventFilter};
use heimdall_contract::ids::{
    AccountName, BindingId, ClientId, DestinationId, DeviceId, EnvironmentId, GrantId, OperationId,
    PolicyId, ProfileId, RequestId, WorkId,
};
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
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock};

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
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: VirtualClock::at(t0()),
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
        Self { store, ops }
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

    // The snapshot: the operation the filter names, and the open operations, only for B
    // and the local owner.
    let named = EventFilter {
        operation_id: Some(op.clone()),
        types: Vec::new(),
    };
    let (a_snap, _) = w.snapshot_of(&a, named.clone()).await;
    let (b_snap, _) = w.snapshot_of(&b, named.clone()).await;
    let (local_snap, _) = w.snapshot_of(&local, named).await;
    assert!(a_snap["operation"].is_null(), "{a_snap}");
    assert_eq!(b_snap["operation"]["operation_id"], op.to_string());
    assert_eq!(local_snap["operation"]["operation_id"], op.to_string());
    assert!(!snapshot_ops(&a_snap).contains(&op.to_string()));
    assert_eq!(snapshot_ops(&b_snap), snapshot_ops(&local_snap));

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
