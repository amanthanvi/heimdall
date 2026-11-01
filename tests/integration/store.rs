//! M01-U4 (M01-T03) transactional state store: integration, property (plan §6.3
//! #4, #6) and fault (plan §6.4) tests against `heimdall_store`.
//!
//! Every value is synthetic. Errors, event payloads read back and child-process
//! output pass through `heimdall_testkit::assert_no_canary`. Crash tests re-run this
//! test binary as a child (`crash_child_entry`) that aborts at a fault point.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::canonical::RequestHash;
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::event::{Cursor, Event, EventFilter, EventType};
use heimdall_contract::ids::{
    BindingId, EnvironmentId, EventId, GrantId, OperationId, PolicyId, ProfileId, RequestId,
    ResourceId,
};
use heimdall_contract::request::{Capability, DeadlineIntent};
use heimdall_contract::{GrantState, OperationState, SchemaVersion, Timestamp};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantReference, GrantSnapshot};
use heimdall_domain::idempotency::{
    IdempotencyKey, IdempotencyOutcome, IdempotencyRecord, classify,
};
use heimdall_domain::operation::{EffectClass, OperationKind, OperationRecord, RecoveryMetadata};
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_domain::revocation::Tombstone;
use heimdall_domain::scope::Scope;
use heimdall_domain::time::{Deadline, TimeAnchor};
use heimdall_store::{
    FaultAction, FaultPoint, NoFaults, Store, StoreError, event_seq, migrations::SCHEMA_VERSION,
};
use heimdall_testkit::{CANARY_PREFIX, ScriptedFaults, assert_no_canary, strategies};
use proptest::prelude::*;

// --- fixtures --------------------------------------------------------------------

fn t(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn t0() -> Timestamp {
    t("2026-10-01T00:00:00Z")
}

fn plus(base: Timestamp, secs: i64) -> Timestamp {
    base.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn no_canary(v: &impl std::fmt::Debug) {
    assert_no_canary(&format!("{v:?}"));
}

fn mem() -> Store {
    Store::open_in_memory(Arc::new(NoFaults)).unwrap()
}

fn env_id(b: u8) -> EnvironmentId {
    EnvironmentId::from_random_bytes([b; 16])
}

fn caller(uid: u32) -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid },
        role: ClientRole::Owner,
    }
}

fn op_id(n: u64) -> OperationId {
    let mut b = [0u8; 16];
    b[8..].copy_from_slice(&n.to_be_bytes());
    OperationId::from_random_bytes(b)
}

fn key(uid: u32, request: &str) -> IdempotencyKey {
    IdempotencyKey {
        caller: caller(uid),
        kind: OperationKind::Ensure,
        request_id: RequestId::parse(request).unwrap(),
    }
}

fn operation(
    n: u64,
    key: IdempotencyKey,
    hash: RequestHash,
    created: Timestamp,
    expires: Timestamp,
) -> (OperationRecord, IdempotencyRecord) {
    let op = OperationRecord {
        id: op_id(n),
        kind: key.kind,
        environment: env_id(7),
        key: key.clone(),
        request_hash: hash,
        effect_class: EffectClass::Local,
        state: OperationState::Queued,
        code: None,
        effect_status: EffectStatus::None,
        result: None,
        created_at: created,
        updated_at: created,
        cancellation: None,
        recovery: RecoveryMetadata::default(),
    };
    let idem = IdempotencyRecord {
        key,
        request_hash: hash,
        operation_id: op.id.clone(),
        created_at: created,
        expires_at: expires,
    };
    (op, idem)
}

fn simple_op(n: u64) -> (OperationRecord, IdempotencyRecord) {
    operation(
        n,
        key(501, &format!("req-{n}")),
        RequestHash([n as u8; 32]),
        t0(),
        plus(t0(), 7 * 86_400),
    )
}

fn scope(pairs: &[(&str, &str)], caps: &[Capability]) -> Scope {
    use heimdall_contract::ids::{AccountName, DestinationId};
    use heimdall_domain::scope::AccessPair;
    Scope {
        pairs: pairs
            .iter()
            .map(|(d, a)| AccessPair {
                destination: DestinationId::parse(d).unwrap(),
                account: AccountName::parse(a).unwrap(),
            })
            .collect(),
        capabilities: caps.iter().copied().collect(),
    }
}

fn grant(b: u8, parent: Option<GrantId>, deadline: Timestamp, state: GrantState) -> GrantSnapshot {
    GrantSnapshot {
        id: GrantId::from_random_bytes([b; 16]),
        environment: env_id(7),
        scope: scope(&[("h1", "u1")], &[Capability::SshAuthentication]),
        starts_at: t0(),
        deadline: Deadline {
            intent: DeadlineIntent::Duration("2h".into()),
            resolved_at: t0(),
            effective: deadline,
        },
        parent,
        source: AuthorizationSource::StandingPolicy {
            revision: PolicyRevision(1),
        },
        generation: AuthorityGeneration(0),
        state,
        enforcement: EnforcementEvidence::unknown(),
    }
}

fn policy(revision: u64) -> StandingPolicy {
    StandingPolicy {
        id: PolicyId::parse("personal").unwrap(),
        revision: PolicyRevision(revision),
        profile: ProfileId::parse("default").unwrap(),
        workspace: None,
        scope: scope(
            &[("h1", "u1"), ("h2", "u1")],
            &[Capability::SshAuthentication],
        ),
        environments: [env_id(7)].into_iter().collect(),
        max_window: Duration::from_secs(12 * 3600),
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::OwnerDecision { decided_at: t0() },
    }
}

fn resource(generation: u64, observed: ResourceState) -> ManagedResource {
    ManagedResource {
        id: ResourceId::from_random_bytes([9; 16]),
        kind: ResourceKind::Endpoint,
        owner: OwnerRef::Runtime,
        generation: ResourceGeneration(generation),
        desired: ResourceState::Present,
        observed,
        last_operation: None,
        locator: "control.sock".into(),
        updated_at: t0(),
    }
}

fn event(env: &EnvironmentId, ty: EventType, op: Option<OperationId>, at: Timestamp) -> Event {
    Event {
        schema_version: SchemaVersion::current(),
        event_id: EventId::from_random_bytes([0; 16]),
        event_type: ty,
        environment_id: env.clone(),
        operation_id: op,
        resource: None,
        timestamp: at,
        cursor: Cursor(String::new()),
        payload: serde_json::json!({"state": "running"}),
    }
}

fn tombstone(b: u8) -> Tombstone {
    Tombstone {
        grant: GrantId::from_random_bytes([b; 16]),
        cascade: Vec::new(),
        generation: AuthorityGeneration(0),
        revoked_at: t0(),
        remote_pending: Vec::new(),
    }
}

/// A per-run synthetic canary; never committed.
fn canary() -> String {
    format!("{CANARY_PREFIX}{}_{}", std::process::id(), t0().as_second())
}

fn file_db(dir: &Path) -> PathBuf {
    dir.join("state.sqlite3")
}

/// A file store holding a self environment, one operation and one tombstone.
fn fixture_file(path: &Path) {
    let s = Store::open(path, Arc::new(NoFaults)).unwrap();
    s.transaction(|tx| {
        tx.init_self_environment(&env_id(1))?;
        let (op, idem) = simple_op(1);
        tx.insert_operation(&op, &idem)?;
        tx.insert_tombstone(&tombstone(3))?;
        Ok(())
    })
    .unwrap();
}

// --- open, schema, identity ------------------------------------------------------------

#[test]
fn open_in_memory_and_file_report_current_schema() {
    assert_eq!(mem().schema_version().unwrap(), SCHEMA_VERSION);
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state database is owner-only");
    }
}

#[test]
fn self_environment_is_recorded_once_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    {
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        s.transaction(|tx| {
            assert_eq!(tx.self_environment()?, None);
            tx.init_self_environment(&env_id(1))?;
            tx.init_self_environment(&env_id(1))?; // idempotent
            Ok(())
        })
        .unwrap();
        let e = s
            .transaction(|tx| tx.init_self_environment(&env_id(2)))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)));
        no_canary(&e);
    }
    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    let id = s.transaction(|tx| tx.self_environment()).unwrap();
    assert_eq!(
        id,
        Some(env_id(1)),
        "identity unchanged across restart (R-RT-07)"
    );
}

// --- operations and idempotency ------------------------------------------------------

#[test]
fn operation_and_idempotency_round_trip_and_update() {
    let s = mem();
    let (mut op, idem) = simple_op(1);
    s.transaction(|tx| tx.insert_operation(&op, &idem)).unwrap();
    let (got_op, got_idem, open) = s
        .transaction(|tx| {
            Ok((
                tx.operation(&op.id)?,
                tx.idempotency_record(&idem.key)?,
                tx.open_operations()?,
            ))
        })
        .unwrap();
    assert_eq!(got_op.as_ref(), Some(&op));
    assert_eq!(got_idem.as_ref(), Some(&idem));
    assert_eq!(open, vec![op.clone()]);

    op.state = OperationState::Succeeded;
    op.code = Some(heimdall_contract::Code::AccessReady);
    op.effect_status = EffectStatus::Applied;
    op.result = Some(serde_json::json!({"binding_id": "binding_x"}));
    op.updated_at = plus(t0(), 60);
    s.transaction(|tx| tx.update_operation(&op)).unwrap();
    let (got, open, counts) = s
        .transaction(|tx| {
            Ok((
                tx.operation(&op.id)?,
                tx.open_operations()?,
                tx.operation_counts()?,
            ))
        })
        .unwrap();
    assert_eq!(got, Some(op.clone()));
    assert!(open.is_empty());
    assert_eq!(counts, vec![(OperationState::Succeeded, 1)]);

    // Resolved terminal states are absorbing; identity columns are immutable.
    let mut back = op.clone();
    back.state = OperationState::Running;
    let e = s.transaction(|tx| tx.update_operation(&back)).unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    let mut rehash = op.clone();
    rehash.request_hash = RequestHash([0xee; 32]);
    let e = s
        .transaction(|tx| tx.update_operation(&rehash))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    // Missing operation.
    let (ghost, _) = simple_op(99);
    assert!(s.transaction(|tx| tx.update_operation(&ghost)).is_err());
}

#[test]
fn duplicate_idempotency_key_is_refused_by_the_store() {
    let s = mem();
    let (op1, idem1) = simple_op(1);
    s.transaction(|tx| tx.insert_operation(&op1, &idem1))
        .unwrap();
    let (op2, idem2) = operation(
        2,
        idem1.key.clone(),
        RequestHash([2; 32]),
        t0(),
        plus(t0(), 60),
    );
    assert!(
        s.transaction(|tx| tx.insert_operation(&op2, &idem2))
            .is_err()
    );
    assert_eq!(s.transaction(|tx| tx.operation(&op2.id)).unwrap(), None);
}

#[test]
fn cross_owner_request_id_is_a_distinct_key() {
    let s = mem();
    let (a, ia) = operation(
        1,
        key(501, "same"),
        RequestHash([1; 32]),
        t0(),
        plus(t0(), 60),
    );
    let (b, ib) = operation(
        2,
        key(502, "same"),
        RequestHash([1; 32]),
        t0(),
        plus(t0(), 60),
    );
    s.transaction(|tx| {
        tx.insert_operation(&a, &ia)?;
        tx.insert_operation(&b, &ib)
    })
    .unwrap();
    let got = s
        .transaction(|tx| {
            Ok((
                tx.idempotency_record(&ia.key)?,
                tx.idempotency_record(&ib.key)?,
            ))
        })
        .unwrap();
    assert_eq!(got.0.unwrap().operation_id, a.id);
    assert_eq!(got.1.unwrap().operation_id, b.id);
}

// --- grants, references, tombstones -----------------------------------------------------

#[test]
fn grant_immutable_columns_and_absorbing_terminal_states() {
    let s = mem();
    let deadline = plus(t0(), 7200);
    let g = grant(1, None, deadline, GrantState::Preparing);
    s.transaction(|tx| tx.insert_grant(&g)).unwrap();

    let mut widened = g.clone();
    widened.state = GrantState::Active;
    widened.scope = scope(
        &[("h1", "u1"), ("h9", "root")],
        &[Capability::AgentForwarding],
    );
    widened.deadline.effective = plus(t0(), 86_400);
    s.transaction(|tx| tx.update_grant_state(&widened)).unwrap();
    let got = s.transaction(|tx| tx.grant(&g.id)).unwrap().unwrap();
    assert_eq!(got.state, GrantState::Active);
    assert_eq!(got.scope, g.scope, "scope never widened by a state update");
    assert_eq!(
        got.deadline, g.deadline,
        "deadline never extended by a state update"
    );

    let mut expired = got.clone();
    expired.state = GrantState::Expired;
    s.transaction(|tx| tx.update_grant_state(&expired)).unwrap();
    let mut revived = expired.clone();
    revived.state = GrantState::Active;
    let e = s
        .transaction(|tx| tx.update_grant_state(&revived))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    let state = s.transaction(|tx| tx.grant(&g.id)).unwrap().unwrap().state;
    assert_eq!(state, GrantState::Expired);
}

#[test]
fn grants_due_descendants_and_deadline_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    let d1 = plus(t0(), 3600);
    let parent = grant(1, None, d1, GrantState::Active);
    let child = grant(2, Some(parent.id.clone()), d1, GrantState::Active);
    let grandchild = grant(
        3,
        Some(child.id.clone()),
        plus(t0(), 1800),
        GrantState::Active,
    );
    let unrelated = grant(4, None, plus(t0(), 60), GrantState::Revoked);
    {
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        s.transaction(|tx| {
            for g in [&parent, &child, &grandchild, &unrelated] {
                tx.insert_grant(g)?;
            }
            Ok(())
        })
        .unwrap();
    }
    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    let (desc, leaf, due_early, due_at, after) = s
        .transaction(|tx| {
            Ok((
                tx.grant_descendants(&parent.id)?,
                tx.grant_descendants(&grandchild.id)?,
                tx.grants_due(plus(t0(), 1799))?,
                tx.grants_due(d1)?,
                tx.grant(&parent.id)?,
            ))
        })
        .unwrap();
    let mut want = vec![child.id.clone(), grandchild.id.clone()];
    want.sort();
    assert_eq!(desc, want);
    assert!(leaf.is_empty());
    assert!(due_early.is_empty(), "terminal grants are never due");
    let ids: BTreeSet<_> = due_at.iter().map(|g| g.id.clone()).collect();
    assert_eq!(
        ids,
        [parent.id.clone(), child.id.clone(), grandchild.id.clone()]
            .into_iter()
            .collect()
    );
    assert_eq!(
        after.unwrap().deadline.effective,
        d1,
        "deadline unchanged by restart"
    );
}

#[test]
fn references_are_ownership_aware() {
    let s = mem();
    let g = grant(1, None, plus(t0(), 3600), GrantState::Active);
    let r = |b: u8| GrantReference {
        binding: BindingId::from_random_bytes([b; 16]),
        grant: g.id.clone(),
        acquired_at: t0(),
    };
    let left = s
        .transaction(|tx| {
            tx.insert_grant(&g)?;
            tx.add_grant_reference(&r(1))?;
            tx.add_grant_reference(&r(1))?; // same owner twice: one reference
            tx.add_grant_reference(&r(2))?;
            let a = tx.remove_grant_reference(&r(1))?;
            let b = tx.remove_grant_reference(&r(1))?;
            let c = tx.remove_grant_reference(&r(2))?;
            Ok((a, b, c))
        })
        .unwrap();
    assert_eq!(left, (1, 1, 0));
    // A reference to an unknown grant is refused (foreign key).
    let ghost = GrantReference {
        binding: BindingId::from_random_bytes([5; 16]),
        grant: GrantId::from_random_bytes([0xaa; 16]),
        acquired_at: t0(),
    };
    assert!(s.transaction(|tx| tx.add_grant_reference(&ghost)).is_err());
}

#[test]
fn tombstones_bump_the_authority_generation_atomically() {
    let s = mem();
    let (g1, g2, g3, now) = s
        .transaction(|tx| {
            let a = tx.insert_tombstone(&tombstone(1))?;
            let b = tx.insert_tombstone(&tombstone(2))?;
            let c = tx.insert_tombstone(&tombstone(1))?; // repeat: still bumps
            Ok((a, b, c, tx.authority_generation()?))
        })
        .unwrap();
    assert_eq!(
        (g1, g2, g3, now),
        (
            AuthorityGeneration(1),
            AuthorityGeneration(2),
            AuthorityGeneration(3),
            AuthorityGeneration(3)
        )
    );
    // A failed transaction bumps nothing.
    let faults = ScriptedFaults::new([(FaultPoint::BeforeCommit, FaultAction::Fail)]);
    let s = Store::open_in_memory(faults).unwrap();
    assert!(
        s.transaction(|tx| tx.insert_tombstone(&tombstone(1)))
            .is_err()
    );
    assert_eq!(
        s.transaction(|tx| tx.authority_generation()).unwrap(),
        AuthorityGeneration(0)
    );
}

#[test]
fn policy_revisions_are_monotonic_and_narrowing_bumps_generation() {
    let s = mem();
    let p1 = policy(1);
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p1, false)).unwrap(),
        AuthorityGeneration(0)
    );
    // Stale or equal revision refused, stored policy intact.
    let e = s
        .transaction(|tx| tx.upsert_policy(&p1, false))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    // Widening without the flag: no bump.
    let mut p2 = policy(2);
    p2.max_window = Duration::from_secs(24 * 3600);
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p2, false)).unwrap(),
        AuthorityGeneration(0)
    );
    // Pause without the caller's flag is still detected as narrowing.
    let mut p3 = p2.clone();
    p3.revision = PolicyRevision(3);
    p3.pause = PauseState::Paused {
        since: plus(t0(), 10),
    };
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p3, false)).unwrap(),
        AuthorityGeneration(1)
    );
    // Caller-flagged narrowing bumps.
    let mut p4 = p3.clone();
    p4.revision = PolicyRevision(4);
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p4, true)).unwrap(),
        AuthorityGeneration(2)
    );
    // Cutoff set: bump.
    let mut p5 = p4.clone();
    p5.revision = PolicyRevision(5);
    p5.cutoff_at = Some(plus(t0(), 3600));
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p5, false)).unwrap(),
        AuthorityGeneration(3)
    );
    let stored = s.transaction(|tx| tx.policy(&p5.id)).unwrap();
    assert_eq!(stored, Some(p5));
}

// --- resources ----------------------------------------------------------------------------

#[test]
fn resource_cas_insert_update_and_reconcile_listing() {
    let s = mem();
    let r1 = resource(1, ResourceState::Unknown);
    s.transaction(|tx| tx.upsert_resource(&r1, None)).unwrap();
    assert!(matches!(
        s.transaction(|tx| tx.upsert_resource(&r1, None)),
        Err(StoreError::GenerationConflict(_))
    ));
    let need = s
        .transaction(|tx| tx.resources_needing_reconcile())
        .unwrap();
    assert_eq!(need, vec![r1.clone()]);
    let r2 = resource(2, ResourceState::Present);
    s.transaction(|tx| tx.upsert_resource(&r2, Some(ResourceGeneration(1))))
        .unwrap();
    assert!(
        s.transaction(|tx| tx.resources_needing_reconcile())
            .unwrap()
            .is_empty()
    );
    // Lowering the generation is refused even with the right expectation.
    let lower = resource(1, ResourceState::Absent);
    assert!(matches!(
        s.transaction(|tx| tx.upsert_resource(&lower, Some(ResourceGeneration(2)))),
        Err(StoreError::GenerationConflict(_))
    ));
    assert_eq!(s.transaction(|tx| tx.resource(&r2.id)).unwrap(), Some(r2));
}

// --- events -------------------------------------------------------------------------------

#[test]
fn events_have_per_environment_monotonic_sequence_filters_and_trim() {
    let s = mem();
    let a = env_id(0xa);
    let b = env_id(0xb);
    let op = op_id(5);
    let appended = s
        .transaction(|tx| {
            let mut out = Vec::new();
            for i in 0..6i64 {
                let env = if i % 2 == 0 { &a } else { &b };
                let ty = if i < 3 {
                    EventType::OperationStateChanged
                } else {
                    EventType::GrantStateChanged
                };
                let o = (i == 2).then(|| op.clone());
                out.push((
                    env.clone(),
                    tx.append_event(&event(env, ty, o, plus(t0(), i * 60)))?,
                ));
            }
            Ok(out)
        })
        .unwrap();
    // Sequence strictly increases within each environment; IDs are unique.
    let mut last: BTreeMap<EnvironmentId, u64> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for (env, (id, seq)) in &appended {
        assert!(*seq > last.get(env).copied().unwrap_or(0));
        last.insert(env.clone(), *seq);
        assert!(ids.insert(id.clone()));
    }
    let page = s
        .transaction(|tx| tx.events_after(&a, 0, &EventFilter::default(), 100))
        .unwrap();
    assert_eq!(page.events.len(), 3);
    assert_eq!(page.tail_seq, 0);
    assert_eq!(page.head_seq, last[&a]);
    let seqs: Vec<u64> = page.events.iter().map(|e| event_seq(e).unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    for e in &page.events {
        assert_eq!(e.environment_id, a);
        assert!(appended.iter().any(|(_, (id, _))| *id == e.event_id));
        no_canary(&e.payload);
    }
    // Paging, operation filter, type filter.
    let first = s
        .transaction(|tx| tx.events_after(&a, 0, &EventFilter::default(), 1))
        .unwrap();
    let rest = s
        .transaction(|tx| {
            tx.events_after(
                &a,
                event_seq(&first.events[0]).unwrap(),
                &EventFilter::default(),
                10,
            )
        })
        .unwrap();
    assert_eq!(first.events.len() + rest.events.len(), 3);
    let by_op = EventFilter {
        operation_id: Some(op.clone()),
        types: Vec::new(),
    };
    let only_op = s
        .transaction(|tx| tx.events_after(&a, 0, &by_op, 10))
        .unwrap();
    assert_eq!(only_op.events.len(), 1);
    let by_type = EventFilter {
        operation_id: None,
        types: vec![EventType::GrantStateChanged],
    };
    let only_type = s
        .transaction(|tx| tx.events_after(&a, 0, &by_type, 10))
        .unwrap();
    assert_eq!(only_type.events.len(), 1);

    // Trim by age: events of `a` at minutes 0 and 2 are older than minute 3.
    let tail = s
        .transaction(|tx| tx.trim_events(&a, plus(t0(), 180), 1000))
        .unwrap();
    assert_eq!(tail, seqs[1]);
    let page = s
        .transaction(|tx| tx.events_after(&a, 0, &EventFilter::default(), 100))
        .unwrap();
    assert_eq!(page.tail_seq, tail);
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.head_seq, last[&a]);
    // Environment `b` is untouched.
    let pb = s
        .transaction(|tx| tx.events_after(&b, 0, &EventFilter::default(), 100))
        .unwrap();
    assert_eq!((pb.events.len(), pb.tail_seq), (3, 0));
    // Trim by row cap to zero keeps head and moves tail to it; never decreases.
    let tail = s.transaction(|tx| tx.trim_events(&a, t0(), 0)).unwrap();
    assert_eq!(tail, last[&a]);
    let again = s.transaction(|tx| tx.trim_events(&a, t0(), 0)).unwrap();
    assert_eq!(again, tail);
    let page = s
        .transaction(|tx| tx.events_after(&a, 0, &EventFilter::default(), 100))
        .unwrap();
    assert!(page.events.is_empty());
    assert_eq!((page.head_seq, page.tail_seq), (tail, tail));
    // New events continue above the old head.
    let (_, next) = s
        .transaction(|tx| tx.append_event(&event(&a, EventType::Decision, None, plus(t0(), 999))))
        .unwrap();
    assert!(next > tail);
}

#[test]
fn time_anchor_round_trips() {
    let s = mem();
    assert_eq!(s.transaction(|tx| tx.time_anchor()).unwrap(), None);
    let anchor = TimeAnchor {
        wall: plus(t0(), 5),
        monotonic: Duration::from_millis(1234),
        process_generation: 7,
    };
    s.transaction(|tx| tx.set_time_anchor(&anchor)).unwrap();
    assert_eq!(s.transaction(|tx| tx.time_anchor()).unwrap(), Some(anchor));
}

// --- secrets never stored (spec §13.3) -----------------------------------------------------

#[test]
fn private_key_material_is_refused_and_never_reaches_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    let c = canary();
    {
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        let (mut op, idem) = simple_op(1);
        op.result = Some(serde_json::json!({
            "leak": format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{c}\n-----END OPENSSH PRIVATE KEY-----")
        }));
        let e = s
            .transaction(|tx| tx.insert_operation(&op, &idem))
            .unwrap_err();
        no_canary(&e);
        assert_no_canary(&e.to_string());
        assert!(!e.to_string().contains("BEGIN"));
        assert_eq!(s.transaction(|tx| tx.operation(&op.id)).unwrap(), None);
        let mut ev = event(&env_id(1), EventType::Decision, None, t0());
        ev.payload = serde_json::json!({"k": format!("-----BEGIN PRIVATE KEY-----{c}")});
        let e = s.transaction(|tx| tx.append_event(&ev)).unwrap_err();
        no_canary(&e);
        // Ordinary records still work.
        fixture_records(&s);
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut p = db.as_os_str().to_owned();
        p.push(suffix);
        if let Ok(bytes) = std::fs::read(PathBuf::from(p)) {
            let text = String::from_utf8_lossy(&bytes);
            assert_no_canary(&text);
            assert!(!text.contains("PRIVATE KEY"));
        }
    }
}

fn fixture_records(s: &Store) {
    s.transaction(|tx| {
        let (op, idem) = simple_op(2);
        tx.insert_operation(&op, &idem)?;
        tx.insert_grant(&grant(1, None, plus(t0(), 3600), GrantState::Active))?;
        tx.upsert_policy(&policy(1), false)?;
        tx.upsert_resource(&resource(1, ResourceState::Unknown), None)?;
        tx.append_event(&event(&env_id(1), EventType::Decision, None, t0()))?;
        Ok(())
    })
    .unwrap();
}

// --- fault injection (plan §6.4) -----------------------------------------------------------

#[test]
fn before_commit_failure_leaves_no_row() {
    let faults = ScriptedFaults::new([(FaultPoint::BeforeCommit, FaultAction::Fail)]);
    let s = Store::open_in_memory(faults.clone()).unwrap();
    let (op, idem) = simple_op(1);
    let e = s
        .transaction(|tx| tx.insert_operation(&op, &idem))
        .unwrap_err();
    assert!(matches!(
        e,
        StoreError::InjectedFault(FaultPoint::BeforeCommit)
    ));
    no_canary(&e);
    let (o, i) = s
        .transaction(|tx| Ok((tx.operation(&op.id)?, tx.idempotency_record(&idem.key)?)))
        .unwrap();
    assert_eq!((o, i), (None, None));
    // Opening a fresh store visits the migration points first; then the failed
    // transaction (before transaction, before commit) and the verifying one.
    assert_eq!(
        faults.visited(),
        vec![
            FaultPoint::BeforeMigration,
            FaultPoint::AfterMigration,
            FaultPoint::BeforeTransaction,
            FaultPoint::BeforeCommit,
            FaultPoint::BeforeTransaction,
            FaultPoint::BeforeCommit,
            FaultPoint::AfterCommit,
        ]
    );
}

#[test]
fn before_transaction_failure_runs_nothing() {
    let faults = ScriptedFaults::new([(FaultPoint::BeforeTransaction, FaultAction::Fail)]);
    let s = Store::open_in_memory(faults).unwrap();
    let mut ran = false;
    let e = s
        .transaction(|_| {
            ran = true;
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(
        e,
        StoreError::InjectedFault(FaultPoint::BeforeTransaction)
    ));
    assert!(!ran);
}

#[test]
fn after_commit_failure_is_visible_and_retry_replays() {
    let faults = ScriptedFaults::new([(FaultPoint::AfterCommit, FaultAction::Fail)]);
    let s = Store::open_in_memory(faults).unwrap();
    let (op, idem) = simple_op(1);
    let e = s
        .transaction(|tx| tx.insert_operation(&op, &idem))
        .unwrap_err();
    assert!(matches!(
        e,
        StoreError::InjectedFault(FaultPoint::AfterCommit)
    ));
    // The caller saw an error, but the write is durable: a retry with the same
    // key and hash must classify as Replay of the same operation.
    let (o, outcome) = s
        .transaction(|tx| {
            let rec = tx.idempotency_record(&idem.key)?;
            Ok((
                tx.operation(&op.id)?,
                classify(rec.as_ref(), idem.request_hash, plus(t0(), 1)),
            ))
        })
        .unwrap();
    assert_eq!(o, Some(op.clone()));
    assert_eq!(outcome, IdempotencyOutcome::Replay(op.id));
}

#[test]
fn error_inside_closure_rolls_back() {
    let s = mem();
    let (op, idem) = simple_op(1);
    let e = s
        .transaction(|tx| {
            tx.insert_operation(&op, &idem)?;
            tx.insert_tombstone(&tombstone(1))?;
            Err::<(), _>(StoreError::GenerationConflict("synthetic".into()))
        })
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    let (o, g) = s
        .transaction(|tx| Ok((tx.operation(&op.id)?, tx.authority_generation()?)))
        .unwrap();
    assert_eq!((o, g), (None, AuthorityGeneration(0)));
}

const CHILD_DB: &str = "HEIMDALL_TEST_STORE_CRASH_DB";
const CHILD_POINT: &str = "HEIMDALL_TEST_STORE_CRASH_POINT";

fn parse_point(s: &str) -> FaultPoint {
    match s {
        "BeforeTransaction" => FaultPoint::BeforeTransaction,
        "BeforeCommit" => FaultPoint::BeforeCommit,
        "AfterCommit" => FaultPoint::AfterCommit,
        "BeforeMigration" => FaultPoint::BeforeMigration,
        "AfterMigration" => FaultPoint::AfterMigration,
        other => panic!("unknown fault point {other}"),
    }
}

/// Child-process body for the crash tests; a no-op in a normal test run.
#[test]
fn crash_child_entry() {
    let (Ok(db), Ok(point)) = (std::env::var(CHILD_DB), std::env::var(CHILD_POINT)) else {
        return;
    };
    let point = parse_point(&point);
    let faults = ScriptedFaults::new([(point, FaultAction::Crash)]);
    let s = Store::open(Path::new(&db), faults).unwrap();
    let (op, idem) = simple_op(2);
    let _ = s.transaction(|tx| {
        tx.insert_operation(&op, &idem)?;
        tx.insert_tombstone(&tombstone(4))?;
        Ok(())
    });
    // Only reached when the crash point was not hit.
    std::process::exit(3);
}

fn run_crash_child(db: &Path, point: &str) {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "crash_child_entry",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_DB, db)
        .env(CHILD_POINT, point)
        .output()
        .unwrap();
    assert_no_canary(&String::from_utf8_lossy(&out.stdout));
    assert_no_canary(&String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "child must die at {point}");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            out.status.signal(),
            Some(6),
            "child aborted (SIGABRT) at {point}"
        );
    }
}

#[test]
fn crash_at_each_transaction_point_reopens_with_exactly_the_committed_state() {
    for (point, committed) in [
        ("BeforeTransaction", false),
        ("BeforeCommit", false),
        ("AfterCommit", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        fixture_file(&db);
        run_crash_child(&db, point);
        // Reopen runs integrity_check and foreign_key_check; it must pass.
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        let (env, op1, op2, generation) = s
            .transaction(|tx| {
                Ok((
                    tx.self_environment()?,
                    tx.operation(&op_id(1))?,
                    tx.operation(&op_id(2))?,
                    tx.authority_generation()?,
                ))
            })
            .unwrap();
        assert_eq!(
            env,
            Some(env_id(1)),
            "identity unchanged after crash at {point}"
        );
        assert!(op1.is_some(), "earlier commit survives crash at {point}");
        assert_eq!(
            op2.is_some(),
            committed,
            "op2 visibility after crash at {point}"
        );
        let want = if committed { 2 } else { 1 };
        assert_eq!(
            generation,
            AuthorityGeneration(want),
            "generation after {point}"
        );
    }
}

#[test]
fn crash_at_each_migration_point_reopens_cleanly() {
    for (point, migrated) in [("BeforeMigration", false), ("AfterMigration", true)] {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        run_crash_child(&db, point);
        let header = std::fs::read(&db).unwrap_or_default();
        let version = header
            .get(60..64)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        if !migrated {
            assert!(
                version.unwrap_or(0) == 0,
                "no committed schema before the first step"
            );
        }
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION, "after {point}");
        assert_eq!(s.transaction(|tx| tx.self_environment()).unwrap(), None);
    }
}

// --- corrupt and newer stores never become fresh installations -----------------------------

fn assert_refused_and_untouched(db: &Path, expect: fn(&StoreError) -> bool) {
    let before = std::fs::read(db).unwrap();
    for _ in 0..2 {
        let e = Store::open(db, Arc::new(NoFaults)).unwrap_err();
        assert!(expect(&e), "unexpected error kind: {e}");
        no_canary(&e);
        let text = e.to_string();
        assert!(
            !text.contains(db.parent().unwrap().to_str().unwrap()),
            "error must not reveal the path"
        );
    }
    assert_eq!(
        std::fs::read(db).unwrap(),
        before,
        "refused file is never rewritten"
    );
}

fn corrupt_copy(dir: &Path, mutate: impl FnOnce(&mut Vec<u8>)) -> PathBuf {
    let original = dir.join("original.sqlite3");
    fixture_file(&original);
    let mut wal = original.as_os_str().to_owned();
    wal.push("-wal");
    let wal_len = std::fs::metadata(PathBuf::from(wal)).map_or(0, |m| m.len());
    assert_eq!(wal_len, 0, "closed store leaves no pending WAL frames");
    let mut bytes = std::fs::read(&original).unwrap();
    mutate(&mut bytes);
    let copy = dir.join("copy.sqlite3");
    std::fs::write(&copy, bytes).unwrap();
    copy
}

fn page_size(bytes: &[u8]) -> usize {
    let raw = u16::from_be_bytes([bytes[16], bytes[17]]);
    if raw == 1 { 65_536 } else { usize::from(raw) }
}

fn is_corrupt(e: &StoreError) -> bool {
    matches!(e, StoreError::Corrupt(_))
}

#[test]
fn garbage_header_is_corrupt_not_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let db = corrupt_copy(dir.path(), |b| b[..16].copy_from_slice(b"not a database!!"));
    assert_refused_and_untouched(&db, is_corrupt);
}

#[test]
fn damaged_page_is_corrupt_not_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let db = corrupt_copy(dir.path(), |b| {
        let ps = page_size(b);
        assert!(b.len() >= 3 * ps);
        for x in &mut b[ps..2 * ps] {
            *x = 0x5a;
        }
    });
    assert_refused_and_untouched(&db, is_corrupt);
}

#[test]
fn truncated_file_is_corrupt_not_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let db = corrupt_copy(dir.path(), |b| {
        let ps = page_size(b);
        b.truncate(2 * ps);
    });
    assert_refused_and_untouched(&db, is_corrupt);
}

#[test]
fn newer_schema_is_refused_and_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let db = corrupt_copy(dir.path(), |b| {
        b[60..64].copy_from_slice(&99u32.to_be_bytes())
    });
    assert_refused_and_untouched(&db, |e| {
        matches!(
            e,
            StoreError::NewerSchema {
                found: 99,
                supported: SCHEMA_VERSION
            }
        )
    });
}

// --- property tests (plan §6.3 #4, #6) -------------------------------------------------------

fn cfg() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(cfg())]

    /// #4 through `Txn`: same key + same hash replays the first operation, a
    /// different hash conflicts naming it, and exactly one operation exists per key.
    #[test]
    fn idempotency_replays_and_conflicts_through_txn(
        submissions in prop::collection::vec((0u32..2, 0u8..4, 0u8..3), 1..40)
    ) {
        let s = mem();
        let mut model: BTreeMap<(u32, u8), (u8, OperationId)> = BTreeMap::new();
        for (n, (uid, req, h)) in submissions.into_iter().enumerate() {
            let k = key(500 + uid, &format!("req-{req}"));
            let hash = RequestHash([h; 32]);
            let now = plus(t0(), n as i64);
            let outcome = s.transaction(|tx| {
                let rec = tx.idempotency_record(&k)?;
                let outcome = classify(rec.as_ref(), hash, now);
                if outcome == IdempotencyOutcome::New {
                    let (op, idem) =
                        operation(n as u64 + 1, k.clone(), hash, now, plus(now, 86_400));
                    tx.insert_operation(&op, &idem)?;
                }
                Ok(outcome)
            }).unwrap();
            match model.get(&(uid, req)) {
                None => {
                    prop_assert_eq!(outcome, IdempotencyOutcome::New);
                    model.insert((uid, req), (h, op_id(n as u64 + 1)));
                }
                Some((mh, id)) if *mh == h => {
                    prop_assert_eq!(outcome, IdempotencyOutcome::Replay(id.clone()));
                }
                Some((_, id)) => {
                    prop_assert_eq!(outcome, IdempotencyOutcome::Conflict(id.clone()));
                }
            }
        }
        let total: u64 = s
            .transaction(|tx| tx.operation_counts())
            .unwrap()
            .into_iter()
            .map(|(_, c)| c)
            .sum();
        prop_assert_eq!(total, model.len() as u64);
    }

    /// #6: a stale expected generation always fails and leaves the newer row intact.
    #[test]
    fn resource_cas_never_lets_a_stale_writer_win(
        g0 in 0u64..50,
        attempts in prop::collection::vec((0u64..60, 0u64..70, any::<bool>()), 1..30)
    ) {
        let s = mem();
        let mut current = resource(g0, ResourceState::Unknown);
        s.transaction(|tx| tx.upsert_resource(&current, None)).unwrap();
        for (expected, new_gen, present) in attempts {
            let observed = if present { ResourceState::Present } else { ResourceState::Absent };
            let candidate = resource(new_gen, observed);
            let r = s.transaction(|tx| {
                tx.upsert_resource(&candidate, Some(ResourceGeneration(expected)))
            });
            let fresh = expected == current.generation.0 && new_gen >= expected;
            if fresh {
                prop_assert!(r.is_ok());
                current = candidate.clone();
            } else {
                prop_assert!(matches!(r, Err(StoreError::GenerationConflict(_))));
            }
            let stored = s.transaction(|tx| tx.resource(&current.id)).unwrap();
            prop_assert_eq!(stored, Some(current.clone()));
            let dup = s.transaction(|tx| tx.upsert_resource(&candidate, None));
            prop_assert!(matches!(dup, Err(StoreError::GenerationConflict(_))));
        }
    }

    /// Retention purge never deletes tombstones, policies or the self environment,
    /// and removes exactly the resolved-terminal operations whose terminal time and
    /// idempotency expiry are both before the purge instant.
    #[test]
    fn purge_keeps_authority_state_and_unexpired_records(
        ops in prop::collection::vec((0u8..7, 0i64..200, 0i64..200), 0..20),
        purge_at in 0i64..400,
        scope_seed in strategies::scope(),
    ) {
        let s = mem();
        let mut p = policy(1);
        p.scope = scope_seed;
        let states = [
            OperationState::Queued,
            OperationState::Running,
            OperationState::AwaitingApproval,
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Cancelled,
            OperationState::OutcomeUnknown,
        ];
        let mut expect_kept = BTreeSet::new();
        let before = plus(t0(), purge_at * 3600);
        s.transaction(|tx| {
            tx.init_self_environment(&env_id(1))?;
            tx.insert_tombstone(&tombstone(1))?;
            tx.upsert_policy(&p, false)?;
            for (i, (state_ix, done_h, expiry_h)) in ops.iter().enumerate() {
                let (mut op, idem) = operation(
                    i as u64 + 1,
                    key(501, &format!("r{i}")),
                    RequestHash([1; 32]),
                    t0(),
                    plus(t0(), expiry_h * 3600),
                );
                tx.insert_operation(&op, &idem)?;
                let state = states[usize::from(*state_ix)];
                if state != OperationState::Queued {
                    op.state = state;
                    op.updated_at = plus(t0(), done_h * 3600);
                    tx.update_operation(&op)?;
                }
                let resolved = matches!(
                    state,
                    OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
                );
                let purgeable = resolved && op.updated_at < before && idem.expires_at < before;
                if !purgeable {
                    expect_kept.insert(op.id.clone());
                }
            }
            Ok(())
        }).unwrap();
        let gen_before = s.transaction(|tx| tx.authority_generation()).unwrap();
        let removed = s.transaction(|tx| tx.purge_operations_before(before)).unwrap();
        prop_assert_eq!(removed as usize, ops.len() - expect_kept.len());
        s.transaction(|tx| {
            for i in 0..ops.len() {
                let id = op_id(i as u64 + 1);
                let k = key(501, &format!("r{i}"));
                let kept = tx.operation(&id)?.is_some();
                assert_eq!(kept, expect_kept.contains(&id));
                assert_eq!(tx.idempotency_record(&k)?.is_some(), kept);
            }
            assert_eq!(tx.self_environment()?, Some(env_id(1)));
            assert_eq!(tx.policy(&p.id)?, Some(p.clone()));
            assert_eq!(tx.authority_generation()?, gen_before);
            Ok(())
        }).unwrap();
        // Tombstone rows and every meta key are checked at the SQL level by the
        // crate's unit property `purge_never_touches_tombstones_policies_or_meta`
        // (no public tombstone reader exists).
    }
}
