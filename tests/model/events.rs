//! M01-U5 event model suite (spec §11.5, §17 A19 event cases; ADR-0006 §8;
//! review F08).
//!
//! Exercises `heimdall_app::events::{EventPublisher, cursor}` and
//! `Operations::observe` over `Store::open_in_memory` and the production
//! publisher: snapshots with cursor boundaries, reader-scoped cursors, backlog
//! replay, resync on expired/foreign/malformed cursors, at-least-once delivery
//! deduplicated by `event_id`, a mutation during the snapshot and a publish during
//! replay-to-live delivered exactly once, lag past the 256-event buffer, and
//! retention that removes an undelivered event ⇒ an explicit resync, never a
//! silent gap (ADR-0006 §13.8 item 3; review R03).
//!
//! The session's merge (backlog, then live events with `seq > boundary_seq`, lag
//! ⇒ one `ResyncRequired`) is the IPC layer's (U6b); [`Consumer`] below applies
//! exactly that rule to what `subscribe` returns, so these tests check the
//! application's half of the contract. Interleavings are made deterministic with
//! the production store `FaultHook` (a publish injected at the boundary
//! transaction's `BeforeTransaction`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::events::{
    CursorParts, EventPublisher, SequencedEvent, SubscribeRefusal, SubscriptionStart, cursor,
};
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::event::{Cursor, Event, EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{
    EnsureRequest, InteractionMode, ObserveRequest, RefreshDependency, RequiredCapabilities,
    WaitMode,
};
use heimdall_contract::{Code, ExitCode, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, Store};
use heimdall_testkit::{
    CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock,
    assert_no_canary,
};
use tokio::sync::broadcast::error::TryRecvError;

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn reader(uid: u32) -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid },
        role: ClientRole::Owner,
    }
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn scope() -> Scope {
    Scope {
        pairs: [pair("h1", "deploy")].into_iter().collect(),
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
        credential_ref: format!("{CANARY_PREFIX}events_fixture"),
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
                    // M03 wave 0 (A1): fail closed until U0b
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                },
                false,
            )?;
            Ok(())
        })
        .unwrap();
}

/// Production `FaultHook` that, once armed, publishes one event at the next
/// `BeforeTransaction` (before the store lock is taken), i.e. between a
/// subscription creating its live receiver and reading its boundary. It also
/// fails the next `fail_commits` transactions at `BeforeCommit` (transient store
/// faults, e.g. during the publisher's catch-up read; review A05).
#[derive(Default)]
struct PublishDuringBoundary {
    armed: AtomicBool,
    publisher: OnceLock<EventPublisher>,
    injected: std::sync::Mutex<Option<SequencedEvent>>,
    fail_commits: AtomicUsize,
}

impl FaultHook for PublishDuringBoundary {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point == FaultPoint::BeforeCommit
            && self
                .fail_commits
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return FaultAction::Fail;
        }
        if point == FaultPoint::BeforeTransaction
            && self.armed.swap(false, Ordering::SeqCst)
            && let Some(p) = self.publisher.get()
        {
            let e = p
                .publish(
                    EventType::ResourceChanged,
                    None,
                    serde_json::json!({ "injected": "during_boundary" }),
                )
                .unwrap();
            *self.injected.lock().unwrap() = Some(e);
        }
        FaultAction::Continue
    }
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    ops: Operations,
    hook: Arc<PublishDuringBoundary>,
}

impl World {
    async fn new() -> Self {
        let hook = Arc::new(PublishDuringBoundary::default());
        let store = Arc::new(Store::open_in_memory(hook.clone()).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
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
            remote_credential_effect: false, // M03 wave 0 (A2)
        };
        let fake = FakeCredentialAdapter::new(descriptor, [FakeStep::Prepare(outcome())]);
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
        let _ = hook.publisher.set(ops.events().clone());
        Self {
            store,
            clock,
            ops,
            hook,
        }
    }

    fn publisher(&self) -> &EventPublisher {
        self.ops.events()
    }

    fn publish(&self, n: usize) -> Vec<SequencedEvent> {
        (0..n)
            .map(|i| {
                self.publisher()
                    .publish(
                        EventType::ResourceChanged,
                        None,
                        serde_json::json!({ "n": i }),
                    )
                    .unwrap()
            })
            .collect()
    }

    async fn ensure(&self, rid: &str) {
        let r = self
            .ops
            .ensure(
                &Caller::unattended(reader(501)),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: BTreeSet::new(),
                    environment: None,
                    work_id: WorkId::parse(&format!("work-{rid}")).unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(rid).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::default(),
                    // M03 wave 0 (A1): fail closed until U0b
                    connection: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(r.code, Code::AccessReady);
    }
}

/// The session-side merge rule applied to a `SubscriptionStart` (ADR-0006 §8):
/// backlog first, then live events strictly after the boundary, personalized for
/// the reader; a lag becomes one `ResyncRequired` carrying the last delivered
/// cursor.
struct Consumer {
    start: SubscriptionStart,
    delivered: Vec<Event>,
    last_cursor: Cursor,
    resyncs: usize,
}

impl Consumer {
    fn new(start: SubscriptionStart) -> Self {
        let mut c = Self {
            last_cursor: start.cursor.clone(),
            delivered: Vec::new(),
            resyncs: 0,
            start,
        };
        let backlog = std::mem::take(&mut c.start.backlog);
        for e in backlog {
            c.last_cursor = e.cursor.clone();
            c.delivered.push(e);
        }
        c
    }

    fn drain(&mut self) {
        loop {
            match self.start.live.try_recv() {
                Ok(ev) => {
                    if ev.seq <= self.start.boundary_seq {
                        continue; // overlap with the snapshot/backlog: drop
                    }
                    let mut e = ev.event.clone();
                    e.cursor = (self.start.cursor_for)(ev.seq);
                    self.last_cursor = e.cursor.clone();
                    self.delivered.push(e);
                }
                Err(TryRecvError::Lagged(_)) => {
                    self.resyncs += 1;
                    // Backlog dropped; the consumer must snapshot again.
                    while self.start.live.try_recv().is_ok() {}
                    return;
                }
                Err(TryRecvError::Empty | TryRecvError::Closed) => return,
            }
        }
    }

    fn ids(&self) -> Vec<String> {
        self.delivered
            .iter()
            .map(|e| e.event_id.to_string())
            .collect()
    }
}

fn scan(events: &[Event]) {
    for e in events {
        assert_no_canary(&serde_json::to_string(e).unwrap());
    }
}

#[tokio::test]
async fn subscribe_without_a_cursor_starts_from_a_consistent_snapshot() {
    let w = World::new().await;
    w.ensure("req-1").await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let snapshot = start.snapshot.clone().expect("snapshot when no cursor");
    assert_eq!(snapshot.cursor, start.cursor);
    assert_no_canary(&serde_json::to_string(&snapshot).unwrap());
    let parts = cursor::decode(&start.cursor).unwrap();
    assert_eq!(parts.reader_tag, cursor::reader_tag(&reader(501)));
    assert_eq!(parts.environment, env_id());
    assert_eq!(parts.seq, start.boundary_seq);
    assert!(start.backlog.is_empty());
    let mut c = Consumer::new(start);
    w.ensure("req-2").await;
    c.drain();
    assert!(!c.delivered.is_empty(), "live events after the boundary");
    assert!(
        c.delivered
            .iter()
            .all(|e| cursor::decode(&e.cursor).unwrap().seq > c.start.boundary_seq)
    );
    scan(&c.delivered);
}

#[tokio::test]
async fn subscribe_from_a_cursor_replays_the_backlog_personalized_for_the_reader() {
    let w = World::new().await;
    let from = w.publisher().head_cursor(&reader(501)).unwrap();
    let published = w.publish(5);
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), Some(from), true)
        .await
        .unwrap();
    assert!(start.snapshot.is_none());
    assert_eq!(start.backlog.len(), 5);
    for (e, p) in start.backlog.iter().zip(&published) {
        assert_eq!(e.event_id, p.event.event_id);
        let parts = cursor::decode(&e.cursor).unwrap();
        assert_eq!(parts.seq, p.seq);
        assert_eq!(parts.reader_tag, cursor::reader_tag(&reader(501)));
    }
    assert_eq!(start.boundary_seq, published.last().unwrap().seq);
}

#[tokio::test]
async fn foreign_malformed_and_expired_cursors_require_a_resync() {
    let w = World::new().await;
    w.publish(3);
    let mine = w.publisher().head_cursor(&reader(501)).unwrap();
    // Another reader's cursor.
    let foreign = w
        .publisher()
        .subscribe(
            &reader(502),
            EventFilter::default(),
            Some(mine.clone()),
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(foreign, SubscribeRefusal::ResyncRequired);
    // A lenient start falls back to a fresh snapshot instead.
    let lenient = w
        .publisher()
        .subscribe(
            &reader(502),
            EventFilter::default(),
            Some(mine.clone()),
            false,
        )
        .await
        .unwrap();
    assert!(lenient.snapshot.is_some());
    // Malformed, oversize and wrong-environment cursors.
    for bad in [
        Cursor("!!".into()),
        Cursor("A".repeat(400)),
        cursor::encode(&CursorParts {
            reader_tag: cursor::reader_tag(&reader(501)),
            environment: EnvironmentId::from_random_bytes([1; 16]),
            seq: 1,
        }),
    ] {
        let r = w
            .publisher()
            .subscribe(&reader(501), EventFilter::default(), Some(bad), true)
            .await;
        assert_eq!(r.unwrap_err(), SubscribeRefusal::ResyncRequired);
    }
    // Expired: retention trims the log past the cursor (tick after 8 days).
    let old = w.publisher().cursor_at(&reader(501), 1);
    w.clock.advance(8 * DAY);
    w.publish(1);
    w.ops.tick().await.unwrap();
    let expired = w
        .publisher()
        .subscribe(
            &reader(501),
            EventFilter::default(),
            Some(old.clone()),
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(expired, SubscribeRefusal::ResyncRequired);
    // Through `observe`: RESYNC_REQUIRED with a usable snapshot cursor.
    let caller = Caller::unattended(reader(501));
    let e = w
        .ops
        .observe(
            &caller,
            ObserveRequest::Events {
                cursor: Some(old),
                filter: EventFilter::default(),
                limit: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ResyncRequired);
    assert_eq!(e.code.exit_code(), ExitCode::Conflict);
    assert_eq!(e.next.action, "resync");
    let usable = e.next.cursor.clone().expect("snapshot cursor");
    let page = w
        .ops
        .observe(
            &caller,
            ObserveRequest::Events {
                cursor: Some(usable),
                filter: EventFilter::default(),
                limit: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.code, Code::Ok);
    assert_no_canary(&serde_json::to_string(&e.into_envelope()).unwrap());
}

#[tokio::test]
async fn observe_pages_events_after_a_cursor_in_order_without_gaps() {
    let w = World::new().await;
    let caller = Caller::unattended(reader(501));
    let snap = w
        .ops
        .observe(
            &caller,
            ObserveRequest::Events {
                cursor: None,
                filter: EventFilter::default(),
                limit: None,
            },
        )
        .await
        .unwrap();
    let mut c: Cursor = serde_json::from_value(snap.data["snapshot"]["cursor"].clone()).unwrap();
    let published = w.publish(5);
    let mut seen = Vec::new();
    for _ in 0..10 {
        let page = w
            .ops
            .observe(
                &caller,
                ObserveRequest::Events {
                    cursor: Some(c.clone()),
                    filter: EventFilter::default(),
                    limit: Some(2),
                },
            )
            .await
            .unwrap();
        let events: Vec<Event> = serde_json::from_value(page.data["events"].clone()).unwrap();
        scan(&events);
        assert!(events.len() <= 2);
        seen.extend(events);
        c = serde_json::from_value(page.data["cursor"].clone()).unwrap();
        if page.data["more"] == false {
            break;
        }
    }
    let ids: Vec<_> = seen.iter().map(|e| e.event_id.clone()).collect();
    let expected: Vec<_> = published.iter().map(|p| p.event.event_id.clone()).collect();
    assert_eq!(ids, expected);
}

#[tokio::test]
async fn duplicate_delivery_is_deduplicated_by_event_id() {
    let w = World::new().await;
    let from = w.publisher().head_cursor(&reader(501)).unwrap();
    w.publish(4);
    // At-least-once: the same cursor resumed twice delivers the same events.
    let a = Consumer::new(
        w.publisher()
            .subscribe(
                &reader(501),
                EventFilter::default(),
                Some(from.clone()),
                true,
            )
            .await
            .unwrap(),
    );
    let b = Consumer::new(
        w.publisher()
            .subscribe(&reader(501), EventFilter::default(), Some(from), true)
            .await
            .unwrap(),
    );
    assert_eq!(a.ids(), b.ids());
    let union: BTreeSet<String> = a.ids().into_iter().chain(b.ids()).collect();
    assert_eq!(union.len(), a.ids().len());
}

#[tokio::test]
async fn a_mutation_during_the_snapshot_is_not_lost_and_not_duplicated() {
    let w = World::new().await;
    w.publish(2);
    // The publish lands after the live receiver exists and before the boundary
    // is read.
    w.hook.armed.store(true, Ordering::SeqCst);
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let injected = w
        .hook
        .injected
        .lock()
        .unwrap()
        .clone()
        .expect("injected publish");
    // Reflected in the snapshot (at or below its boundary) ...
    assert!(injected.seq <= start.boundary_seq);
    let mut c = Consumer::new(start);
    let after = w.publish(1);
    c.drain();
    // ... and therefore not delivered again live; what follows is delivered.
    let ids = c.ids();
    assert!(!ids.contains(&injected.event.event_id.to_string()));
    assert_eq!(ids, vec![after[0].event.event_id.to_string()]);
}

#[tokio::test]
async fn a_publish_during_replay_to_live_is_delivered_exactly_once() {
    let w = World::new().await;
    let from = w.publisher().head_cursor(&reader(501)).unwrap();
    let before = w.publish(2);
    w.hook.armed.store(true, Ordering::SeqCst);
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), Some(from), true)
        .await
        .unwrap();
    let injected = w
        .hook
        .injected
        .lock()
        .unwrap()
        .clone()
        .expect("injected publish");
    let mut c = Consumer::new(start);
    let after = w.publish(1);
    c.drain();
    let expected: Vec<String> = before
        .iter()
        .chain(std::iter::once(&injected))
        .chain(&after)
        .map(|e| e.event.event_id.to_string())
        .collect();
    // Backlog (incl. the injected event) then live; the injected event also sat
    // in the live channel and was dropped as overlap.
    assert_eq!(c.ids(), expected);
    assert_eq!(c.resyncs, 0);
}

#[tokio::test]
async fn lag_past_the_256_event_buffer_yields_one_resync_required() {
    let w = World::new().await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut c = Consumer::new(start);
    assert_eq!(heimdall_contract::ipc::EVENT_BUFFER_PER_SUBSCRIPTION, 256);
    w.publish(257);
    c.drain();
    assert_eq!(c.resyncs, 1, "one ResyncRequired, backlog dropped");
    assert!(c.delivered.is_empty());
    // At exactly the buffer size nothing is lost.
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut d = Consumer::new(start);
    w.publish(256);
    d.drain();
    assert_eq!(d.resyncs, 0);
    assert_eq!(d.delivered.len(), 256);
}

#[tokio::test]
async fn operations_publish_ordered_redacted_events_per_environment() {
    let w = World::new().await;
    w.ensure("req-ev").await;
    let page = w
        .store
        .transaction(|tx| tx.stored_events_after(&env_id(), 0, &EventFilter::default(), 1000))
        .unwrap();
    let seqs: Vec<u64> = page.events.iter().map(|e| e.seq).collect();
    assert!(
        seqs.windows(2).all(|p| p[0] < p[1]),
        "monotonic per environment"
    );
    let types: Vec<EventType> = page.events.iter().map(|e| e.event.event_type).collect();
    assert!(types.contains(&EventType::RuntimeLifecycle));
    assert!(types.contains(&EventType::OperationStateChanged));
    assert!(types.contains(&EventType::GrantStateChanged));
    for e in &page.events {
        assert_eq!(e.event.environment_id, env_id());
        assert_no_canary(&serde_json::to_string(&e.event).unwrap());
    }
    let ids: BTreeSet<_> = page
        .events
        .iter()
        .map(|e| e.event.event_id.clone())
        .collect();
    assert_eq!(ids.len(), page.events.len(), "event IDs are unique");
    // Filtering by operation type.
    let only_ops = w
        .publisher()
        .subscribe(
            &reader(501),
            EventFilter {
                operation_id: None,
                types: vec![EventType::GrantStateChanged],
            },
            Some(w.publisher().cursor_at(&reader(501), 0)),
            true,
        )
        .await
        .unwrap();
    assert!(!only_ops.backlog.is_empty());
    assert!(
        only_ops
            .backlog
            .iter()
            .all(|e| e.event_type == EventType::GrantStateChanged)
    );
}

#[test]
fn cursors_round_trip_and_are_reader_scoped() {
    let parts = CursorParts {
        reader_tag: cursor::reader_tag(&reader(501)),
        environment: env_id(),
        seq: 9,
    };
    let c = cursor::encode(&parts);
    assert_eq!(cursor::decode(&c), Some(parts));
    assert_ne!(
        cursor::reader_tag(&reader(501)),
        cursor::reader_tag(&reader(502))
    );
}

/// Gap G06 (ADR-0006 §8): two writers commit `N` then `N + 1` but announce in
/// reverse order (announcements happen after commit, from different tasks). A
/// live subscriber still receives `N` before `N + 1`, exactly once each, and
/// resuming from the last delivered cursor loses nothing.
#[tokio::test]
async fn live_events_are_delivered_in_sequence_order_when_announced_in_reverse() {
    let w = World::new().await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut c = Consumer::new(start);
    let p = w.publisher().clone();
    let commit = |n: u32| {
        w.store
            .transaction(|tx| {
                p.append_in(
                    tx,
                    EventType::ResourceChanged,
                    None,
                    None,
                    serde_json::json!({ "writer": n }),
                )
            })
            .unwrap()
    };
    let first = commit(1);
    let second = commit(2);
    assert!(first.seq < second.seq);
    // Writer 2 announces first, writer 1 second.
    w.publisher().announce(second.clone());
    w.publisher().announce(first.clone());
    c.drain();
    assert_eq!(
        c.ids(),
        vec![
            first.event.event_id.to_string(),
            second.event.event_id.to_string()
        ],
        "delivered in seq order, each exactly once"
    );
    assert_eq!(c.resyncs, 0);
    scan(&c.delivered);
    // Resume from the latest delivered cursor: nothing was skipped before it,
    // and nothing after it is pending.
    let resumed = w
        .publisher()
        .subscribe(
            &reader(501),
            EventFilter::default(),
            Some(c.last_cursor.clone()),
            true,
        )
        .await
        .unwrap();
    assert!(resumed.backlog.is_empty());
    assert_eq!(resumed.boundary_seq, second.seq);
    // A later announcement continues in order.
    let third = commit(3);
    w.publisher().announce(third.clone());
    c.drain();
    assert_eq!(c.delivered.len(), 3);
    assert_eq!(
        c.delivered[2].event_id.to_string(),
        third.event.event_id.to_string()
    );
}

/// Review A05 (ADR-0006 §8): commit `N` and `N + 1`, announce `N + 1` first while
/// the publisher's catch-up read of `N` hits a one-shot store fault. The live
/// stream must not advance past the gap: `N + 1` is held back (no cursor beyond
/// `N - 1` is handed out), a resume from the last delivered cursor recovers both
/// events, the later announcement of `N` delivers `N` then `N + 1` in order and
/// exactly once, and a resume from the then-latest cursor has nothing pending.
#[tokio::test]
async fn failed_catch_up_read_never_advances_the_live_stream_past_a_gap() {
    let w = World::new().await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut c = Consumer::new(start);
    let p = w.publisher().clone();
    let commit = |n: u32| {
        w.store
            .transaction(|tx| {
                p.append_in(
                    tx,
                    EventType::ResourceChanged,
                    None,
                    None,
                    serde_json::json!({ "writer": n }),
                )
            })
            .unwrap()
    };
    let first = commit(1);
    let second = commit(2);
    assert!(first.seq < second.seq);
    // One transient store fault, consumed by the catch-up read for `first`.
    w.hook.fail_commits.store(1, Ordering::SeqCst);
    w.publisher().announce(second.clone());
    assert_eq!(
        w.hook.fail_commits.load(Ordering::SeqCst),
        0,
        "the catch-up read hit the injected fault"
    );
    c.drain();
    assert!(
        c.delivered.is_empty(),
        "nothing past the unread gap is delivered live: {:?}",
        c.ids()
    );
    // The delivered cursor still precedes the gap, so a resume recovers both.
    let recovering = w
        .publisher()
        .subscribe(
            &reader(501),
            EventFilter::default(),
            Some(c.last_cursor.clone()),
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        recovering
            .backlog
            .iter()
            .map(|e| e.event_id.to_string())
            .collect::<Vec<_>>(),
        vec![
            first.event.event_id.to_string(),
            second.event.event_id.to_string()
        ]
    );
    // The missing event is announced later: both arrive, in order, once each.
    w.publisher().announce(first.clone());
    c.drain();
    assert_eq!(
        c.ids(),
        vec![
            first.event.event_id.to_string(),
            second.event.event_id.to_string()
        ],
        "delivered in seq order, each exactly once"
    );
    assert_eq!(c.resyncs, 0);
    scan(&c.delivered);
    // Late duplicate announcements are dropped.
    w.publisher().announce(second.clone());
    w.publisher().announce(first.clone());
    c.drain();
    assert_eq!(c.delivered.len(), 2);
    // Resume from the latest delivered cursor: nothing skipped, nothing pending.
    let resumed = w
        .publisher()
        .subscribe(
            &reader(501),
            EventFilter::default(),
            Some(c.last_cursor.clone()),
            true,
        )
        .await
        .unwrap();
    assert!(resumed.backlog.is_empty());
    assert_eq!(resumed.boundary_seq, second.seq);
}

/// Review A05, persistent fault: while catch-up reads keep failing, a contiguous
/// announcement (`N` right after the last delivered sequence) is still delivered,
/// a held-back later event is never delivered ahead of an unread one, and the
/// first successful announcement afterwards delivers everything held back, in
/// order.
#[tokio::test]
async fn held_back_events_are_delivered_in_order_once_the_store_is_readable() {
    let w = World::new().await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut c = Consumer::new(start);
    let p = w.publisher().clone();
    let commit = |n: u32| {
        w.store
            .transaction(|tx| {
                p.append_in(
                    tx,
                    EventType::ResourceChanged,
                    None,
                    None,
                    serde_json::json!({ "writer": n }),
                )
            })
            .unwrap()
    };
    let e1 = commit(1);
    let e2 = commit(2);
    let e3 = commit(3);
    let e4 = commit(4);
    // Every catch-up read fails while the fault lasts.
    w.hook.fail_commits.store(usize::MAX, Ordering::SeqCst);
    w.publisher().announce(e3.clone());
    c.drain();
    assert!(c.delivered.is_empty(), "e3 is held back behind e1 and e2");
    // e1 is contiguous with the last delivered sequence: delivered without a read.
    w.publisher().announce(e1.clone());
    c.drain();
    assert_eq!(c.ids(), vec![e1.event.event_id.to_string()]);
    // e2 is contiguous too; e3 stays held back until it can be read in order.
    w.publisher().announce(e2.clone());
    c.drain();
    assert_eq!(
        c.ids(),
        vec![e1.event.event_id.to_string(), e2.event.event_id.to_string()]
    );
    // An explicit retry while the store is still unreadable delivers nothing.
    assert!(!w.publisher().retry_held(), "e3 is still held back");
    c.drain();
    assert_eq!(c.delivered.len(), 2);
    // The store recovers; the next announcement (e4) catches up e3 first.
    w.hook.fail_commits.store(0, Ordering::SeqCst);
    w.publisher().announce(e4.clone());
    c.drain();
    assert_eq!(
        c.ids(),
        [&e1, &e2, &e3, &e4]
            .iter()
            .map(|e| e.event.event_id.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(c.resyncs, 0);
    scan(&c.delivered);
    assert!(w.publisher().retry_held(), "nothing is held back any more");
}

/// Commit one event through `w`'s publisher without announcing it.
fn commit_unannounced(w: &World, n: u32) -> SequencedEvent {
    let p = w.publisher().clone();
    w.store
        .transaction(|tx| {
            p.append_in(
                tx,
                EventType::ResourceChanged,
                None,
                None,
                serde_json::json!({ "writer": n }),
            )
        })
        .unwrap()
}

/// Retention boundary of the fixture environment.
fn retained_tail(w: &World) -> u64 {
    w.store
        .transaction(|tx| tx.stored_events_after(&env_id(), 0, &EventFilter::default(), 1))
        .unwrap()
        .tail_seq
}

/// After an explicit resync the subscriber's last delivered cursor is not a
/// resume point past the gap: a strict resume from it is refused, never answered
/// with a backlog that silently skips the trimmed event.
async fn assert_resume_is_refused(w: &World, c: &Consumer) {
    let r = w
        .publisher()
        .subscribe(
            &reader(501),
            EventFilter::default(),
            Some(c.last_cursor.clone()),
            true,
        )
        .await;
    assert_eq!(r.unwrap_err(), SubscribeRefusal::ResyncRequired);
}

/// ADR-0006 §13.8 item 3 (review R03, the review's probe): commit `N` and
/// `N + 1`; announce `N + 1` while the catch-up read of `N` fails, so `N + 1` is
/// held back; retention then removes `N` (row cap) before `retry_held`. The retry
/// must not claim continuity: the subscriber gets an explicit resync carrying its
/// last delivered cursor (before `N`) and `N + 1` is never delivered as if `N`
/// had been.
#[tokio::test]
async fn r03_retention_between_a_failed_catch_up_and_its_retry_requires_a_resync() {
    let w = World::new().await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut c = Consumer::new(start);
    let before_gap = c.last_cursor.clone();
    let n = commit_unannounced(&w, 1);
    let n1 = commit_unannounced(&w, 2);
    w.hook.fail_commits.store(1, Ordering::SeqCst);
    w.publisher().announce(n1.clone());
    assert_eq!(w.hook.fail_commits.load(Ordering::SeqCst), 0);
    c.drain();
    assert!(c.delivered.is_empty(), "N + 1 is held back behind N");
    // Retention removes N (one row kept: N + 1).
    let tail = w
        .store
        .transaction(|tx| tx.trim_events(&env_id(), t0(), 1))
        .unwrap();
    assert!(tail >= n.seq && tail < n1.seq);
    w.publisher().retry_held();
    c.drain();
    assert_eq!(
        (c.delivered.len(), c.resyncs),
        (0, 1),
        "explicit resync, nothing delivered past the trimmed event: {:?}",
        c.ids()
    );
    assert_eq!(c.last_cursor, before_gap, "the last delivered cursor");
    assert_resume_is_refused(&w, &c).await;
    // Later announcements continue after the resynchronized position; the
    // trimmed history is never reported again.
    assert!(w.publisher().retry_held(), "nothing is held back any more");
    let n2 = commit_unannounced(&w, 3);
    w.publisher().announce(n2.clone());
    c.drain();
    assert_eq!(c.ids(), vec![n2.event.event_id.to_string()]);
    assert_eq!(c.resyncs, 1);
}

/// §13.8 item 3 through the runtime's relay: the retention gap reaches every
/// session's receiver as a lag (which the session turns into one
/// `ResyncRequired` at its last delivered cursor), never as the surviving event.
#[tokio::test]
async fn r03_retention_gap_reaches_session_receivers_through_the_relay_as_a_lag() {
    use tokio::sync::broadcast::error::TryRecvError as SessionRecv;
    let w = World::new().await;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let relay = heimdall_runtime::dispatch::EventRelay::spawn(&w.ops, shutdown.clone());
    let mut session = relay.subscribe();
    let boundary = w.publisher().head_cursor(&reader(501)).unwrap();
    let boundary = cursor::decode(&boundary).unwrap().seq;
    let n = commit_unannounced(&w, 1);
    let n1 = commit_unannounced(&w, 2);
    w.hook.fail_commits.store(1, Ordering::SeqCst);
    w.publisher().announce(n1.clone());
    w.store
        .transaction(|tx| tx.trim_events(&env_id(), t0(), 1))
        .unwrap();
    assert!(retained_tail(&w) >= n.seq);
    w.publisher().retry_held();
    // Let the relay task run (current-thread runtime).
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let mut lagged = false;
    let mut after_boundary = Vec::new();
    loop {
        match session.try_recv() {
            Ok(e) if e.seq > boundary => after_boundary.push(e.event.event_id.to_string()),
            Ok(_) => {}
            Err(SessionRecv::Lagged(_)) => lagged = true,
            Err(SessionRecv::Empty | SessionRecv::Closed) => break,
        }
    }
    shutdown.cancel();
    assert!(
        lagged,
        "the session receiver lags, so it emits ResyncRequired"
    );
    assert!(
        after_boundary.is_empty(),
        "nothing past the gap is relayed: {after_boundary:?}"
    );
}

/// §13.8 item 3, age retention between announcements: `N` and `N + 1` are
/// committed, retention by age removes `N` before anything is announced, then
/// `N + 1` is announced. The catch-up read sees the retained tail beyond the
/// delivery boundary in its own transaction and requires a resync.
#[tokio::test]
async fn r03_age_retention_before_an_announcement_requires_a_resync() {
    let w = World::new().await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut c = Consumer::new(start);
    let before_gap = c.last_cursor.clone();
    let n = commit_unannounced(&w, 1);
    // Events committed from here on are newer than the age cut.
    w.clock.advance(HOUR);
    let n1 = commit_unannounced(&w, 2);
    let cut = t0()
        .checked_add(jiff::SignedDuration::from_mins(30))
        .unwrap();
    assert!(n.event.timestamp < cut && n1.event.timestamp >= cut);
    let tail = w
        .store
        .transaction(|tx| tx.trim_events(&env_id(), cut, u64::MAX))
        .unwrap();
    assert!(tail >= n.seq && tail < n1.seq);
    w.publisher().announce(n1.clone());
    c.drain();
    assert_eq!((c.delivered.len(), c.resyncs), (0, 1), "{:?}", c.ids());
    assert_eq!(c.last_cursor, before_gap);
    assert!(retained_tail(&w) > cursor::decode(&before_gap).unwrap().seq);
    assert_resume_is_refused(&w, &c).await;
    // A late announcement of the trimmed event is not delivered either.
    w.publisher().announce(n.clone());
    c.drain();
    assert!(c.delivered.is_empty());
    assert_eq!(c.resyncs, 1);
}

/// §13.8 item 3, no false alarm: retention that removes only events already
/// delivered never causes a resync, and an event trimmed after its contiguous
/// announcement was fanned out (it was never missing) is delivered normally.
#[tokio::test]
async fn retention_of_delivered_history_needs_no_resync() {
    let w = World::new().await;
    let start = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let mut c = Consumer::new(start);
    let e1 = commit_unannounced(&w, 1);
    w.publisher().announce(e1.clone());
    let e2 = commit_unannounced(&w, 2);
    let e3 = commit_unannounced(&w, 3);
    // Retention removes e1 (delivered) and e2 (committed, not yet announced).
    w.store
        .transaction(|tx| tx.trim_events(&env_id(), t0(), 1))
        .unwrap();
    // e2 is the very next position: delivered as announced, no read needed.
    w.publisher().announce(e2.clone());
    w.publisher().announce(e3.clone());
    c.drain();
    assert_eq!(c.resyncs, 0);
    assert_eq!(
        c.ids(),
        [&e1, &e2, &e3]
            .iter()
            .map(|e| e.event.event_id.to_string())
            .collect::<Vec<_>>()
    );
}

// =====================================================================================
// Property (review A05; ADR-0006 §13.8 item 3, review R03): for any announcement
// order, any transient catch-up read faults, and retention (by rows and by age)
// between a failure and its retry and between announcements, the live stream is a
// gap-free, strictly increasing prefix of the committed events until, at most, one
// explicit resync; a resync happens only when retention removed an event that was
// not delivered, and after it the last delivered cursor is never a resume point
// past the gap. Every run ends in either complete delivery or an explicit resync.
// =====================================================================================

mod props_announce {
    use super::*;
    use heimdall_domain::time::Clock;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    /// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x4130_3545_5645_4e54);
        }
        c
    }

    /// Fails the next `fail_commits` transactions at `BeforeCommit`.
    #[derive(Default)]
    struct Faults {
        fail_commits: AtomicUsize,
    }

    impl FaultHook for Faults {
        fn at(&self, point: FaultPoint) -> FaultAction {
            if point == FaultPoint::BeforeCommit
                && self
                    .fail_commits
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
            {
                return FaultAction::Fail;
            }
            FaultAction::Continue
        }
    }

    /// One step of a trace.
    #[derive(Debug, Clone)]
    enum Step {
        /// Announce committed event `index` while the next `fail` store reads
        /// fail (0 = readable).
        Announce { index: usize, fail: usize },
        /// `retry_held` while the next `fail` store reads fail.
        Retry { fail: usize },
        /// Retention by row cap: keep at most `max_rows` events.
        TrimRows { max_rows: u64 },
        /// Retention by age: remove every event older than committed event
        /// `before` (one minute apart).
        TrimAge { before: usize },
    }

    /// An optional step inserted after an announcement: nothing (most often), a
    /// retry, or retention.
    fn extra(n: usize) -> impl Strategy<Value = Option<Step>> {
        prop_oneof![
            4 => Just(None),
            2 => (0usize..=2).prop_map(|fail| Some(Step::Retry { fail })),
            1 => (0..=n as u64).prop_map(|max_rows| Some(Step::TrimRows { max_rows })),
            1 => (0..=n).prop_map(|before| Some(Step::TrimAge { before })),
        ]
    }

    /// Trace plan: every committed event announced once in a shuffled order plus
    /// duplicates, each announcement with a fault count and up to two extra steps
    /// after it (so "fail, trim, retry" and "trim between announcements" occur).
    fn plan() -> impl Strategy<Value = (usize, Vec<Step>)> {
        (1usize..=10).prop_flat_map(|n| {
            let order = Just((0..n).collect::<Vec<_>>()).prop_shuffle();
            let dups = prop::collection::vec(0..n, 0..4);
            (order, dups).prop_flat_map(move |(order, dups)| {
                let all: Vec<usize> = order.into_iter().chain(dups).collect();
                let len = all.len();
                (
                    Just(n),
                    prop::collection::vec((0usize..=2, extra(n), extra(n)), len).prop_map(
                        move |per| {
                            let mut steps = Vec::new();
                            for (&index, (fail, a, b)) in all.iter().zip(per) {
                                steps.push(Step::Announce { index, fail });
                                steps.extend(a);
                                steps.extend(b);
                            }
                            steps
                        },
                    ),
                )
            })
        })
    }

    /// The live receiver as a subscriber sees it: deliveries until a lag, which
    /// is the explicit resync (the session turns it into one `ResyncRequired` at
    /// the last delivered cursor and drops the buffered rest).
    struct Live {
        rx: tokio::sync::broadcast::Receiver<Arc<SequencedEvent>>,
        delivered: Vec<SequencedEvent>,
        resynced: bool,
    }

    impl Live {
        fn drain(&mut self) {
            loop {
                match self.rx.try_recv() {
                    Ok(e) if !self.resynced => self.delivered.push((*e).clone()),
                    Ok(_) => {}
                    Err(TryRecvError::Lagged(_)) => self.resynced = true,
                    Err(TryRecvError::Empty) => return,
                    Err(e) => panic!("unexpected receiver state: {e:?}"),
                }
            }
        }
    }

    fn tail(store: &Store) -> u64 {
        store
            .transaction(|tx| tx.stored_events_after(&env_id(), 0, &EventFilter::default(), 1))
            .unwrap()
            .tail_seq
    }

    async fn trace(n: usize, steps: Vec<Step>) -> Result<(), TestCaseError> {
        let faults = Arc::new(Faults::default());
        let store = Arc::new(Store::open_in_memory(faults.clone()).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
        let publisher = EventPublisher::new(store.clone(), env_id()).with_clock(clock.clone());
        let mut live = Live {
            rx: publisher.live_receiver(),
            delivered: Vec::new(),
            resynced: false,
        };
        let committed: Vec<SequencedEvent> = (0..n)
            .map(|i| {
                clock.advance(Duration::from_secs(60));
                store
                    .transaction(|tx| {
                        publisher.append_in(
                            tx,
                            EventType::ResourceChanged,
                            None,
                            None,
                            serde_json::json!({ "writer": i }),
                        )
                    })
                    .unwrap()
            })
            .collect();
        let me = reader(501);
        let baseline = committed[0].seq - 1;
        let position = |live: &Live| {
            live.delivered
                .last()
                .map_or(baseline, |e: &SequencedEvent| e.seq)
        };
        let mut max_announced = 0u64;
        // The position the subscriber held when its resync arrived.
        let mut resynced_at: Option<u64> = None;
        for step in steps {
            let readable = match step {
                Step::Announce { index, fail } => {
                    faults.fail_commits.store(fail, Ordering::SeqCst);
                    let event = committed[index].clone();
                    max_announced = max_announced.max(event.seq);
                    publisher.announce(event);
                    faults.fail_commits.store(0, Ordering::SeqCst);
                    fail == 0
                }
                Step::Retry { fail } => {
                    faults.fail_commits.store(fail, Ordering::SeqCst);
                    publisher.retry_held();
                    faults.fail_commits.store(0, Ordering::SeqCst);
                    fail == 0
                }
                Step::TrimRows { max_rows } => {
                    store
                        .transaction(|tx| tx.trim_events(&env_id(), t0(), max_rows))
                        .unwrap();
                    false
                }
                Step::TrimAge { before } => {
                    let keep_after = committed
                        .get(before)
                        .map_or_else(|| Clock::wall(&*clock), |e| e.event.timestamp);
                    store
                        .transaction(|tx| tx.trim_events(&env_id(), keep_after, u64::MAX))
                        .unwrap();
                    false
                }
            };
            let was_resynced = live.resynced;
            live.drain();
            // Until the resync: a gap-free, strictly increasing prefix of the
            // committed events, never beyond what was announced.
            prop_assert!(live.delivered.len() <= committed.len());
            prop_assert_eq!(&live.delivered[..], &committed[..live.delivered.len()]);
            prop_assert!(live.delivered.last().is_none_or(|e| e.seq <= max_announced));
            if live.resynced && !was_resynced {
                // Justified: retention removed an event after the delivered
                // position (and continuity from there is never offered).
                let at = position(&live);
                prop_assert!(tail(&store) > at, "resync without a trimmed gap");
                resynced_at = Some(at);
            }
            if readable && !live.resynced {
                // A readable store catches up through everything announced.
                prop_assert_eq!(position(&live), max_announced);
            }
        }
        let at = position(&live);
        let strict_resume = || {
            publisher.subscribe(
                &me,
                EventFilter::default(),
                Some(publisher.cursor_at(&me, at)),
                true,
            )
        };
        if !live.resynced {
            // Before the final retry: a resume from the latest delivered position
            // recovers exactly the rest, or is refused because retention removed
            // part of it; it never skips a trimmed event silently.
            match strict_resume().await {
                Ok(resumed) => {
                    let rest: Vec<String> = committed[live.delivered.len()..]
                        .iter()
                        .map(|e| e.event.event_id.to_string())
                        .collect();
                    prop_assert_eq!(
                        resumed
                            .backlog
                            .iter()
                            .map(|e| e.event_id.to_string())
                            .collect::<Vec<_>>(),
                        rest
                    );
                }
                Err(refusal) => {
                    prop_assert_eq!(refusal, SubscribeRefusal::ResyncRequired);
                    prop_assert!(tail(&store) > at);
                }
            }
        }
        // The store is readable: an explicit retry finishes the run.
        prop_assert!(publisher.retry_held());
        let was_resynced = live.resynced;
        live.drain();
        if live.resynced {
            // Explicit resync: justified, and its cursor is not a resume point.
            let at = resynced_at.unwrap_or_else(|| position(&live));
            prop_assert!(was_resynced || tail(&store) > at);
            let refused = publisher
                .subscribe(
                    &me,
                    EventFilter::default(),
                    Some(publisher.cursor_at(&me, at)),
                    true,
                )
                .await;
            prop_assert_eq!(refused.unwrap_err(), SubscribeRefusal::ResyncRequired);
        } else {
            // Complete delivery, in order, each event once.
            prop_assert_eq!(&live.delivered[..], &committed[..]);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn live_stream_never_passes_a_gap_under_catch_up_faults_and_retention(
            (n, steps) in plan()
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(trace(n, steps))?;
        }
    }
}

/// Gap G18 (ADR-0006 §8 `Subscribed.cursor`, contract doc of
/// `ServerMessage::Subscribed`): when resuming from a cursor, the subscription's
/// cursor is the **head boundary** read in the subscription transaction (the
/// cursor after the backlog), never the client's cursor; with a snapshot it is
/// the snapshot's boundary. The last backlog event carries the same position.
#[tokio::test]
async fn subscribed_cursor_is_the_head_boundary_not_the_clients_cursor() {
    let w = World::new().await;
    let from = w.publisher().head_cursor(&reader(501)).unwrap();
    let published = w.publish(3);
    let start = w
        .publisher()
        .subscribe(
            &reader(501),
            EventFilter::default(),
            Some(from.clone()),
            true,
        )
        .await
        .unwrap();
    assert_ne!(start.cursor, from, "not the client's cursor");
    let head = published.last().unwrap().seq;
    assert_eq!(start.boundary_seq, head);
    assert_eq!(cursor::decode(&start.cursor).unwrap().seq, head);
    assert_eq!(start.backlog.last().unwrap().cursor, start.cursor);
    // Without a cursor: the snapshot's boundary, identical to `cursor`.
    let snap = w
        .publisher()
        .subscribe(&reader(501), EventFilter::default(), None, false)
        .await
        .unwrap();
    let s = snap.snapshot.as_ref().unwrap();
    assert_eq!(s.cursor, snap.cursor);
    assert_eq!(cursor::decode(&snap.cursor).unwrap().seq, head);
}
