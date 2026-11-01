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
    AccountName, BindingId, CredentialInstanceId, DecisionId, DestinationId, DeviceId,
    EnvironmentId, EventId, GrantId, IssuanceId, OperationId, PolicyId, ProfileId, RequestId,
    ResourceId, WorkId,
};
use heimdall_contract::request::{Capability, DeadlineIntent, PolicyAction, Verdict};
use heimdall_contract::{GrantState, OperationState, SchemaVersion, Timestamp};
use heimdall_domain::binding::{BindingRecord, BindingState, ReleaseOutcome};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantReference, GrantSnapshot};
use heimdall_domain::idempotency::{
    DEFAULT_RETENTION, ExpiredKeyMarker, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord,
    classify, marker_until, retention_expiry,
};
use heimdall_domain::issuance::{
    CertificateBounds, CredentialInstance, CredentialState, IssuanceEntry, IssuanceRefusal,
    IssuanceState,
};
use heimdall_domain::operation::{
    AdapterIdentity, EffectClass, EffectReceipt, OperationKind, OperationRecord, RecoveryIntent,
    RecoveryMetadata, ResolvedIntent, StageReceipt,
};
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_domain::revocation::Tombstone;
use heimdall_domain::scope::{AccessPair, Scope};
use heimdall_domain::time::{
    AttendedTimeConfirmation, BootId, Deadline, GrantAnchor, TimeAnchor, anchor_grant, shorten,
};
use heimdall_store::{
    DecisionCompletion, FaultAction, FaultPoint, NoFaults, Store, StoreError, event_seq,
    migrations::SCHEMA_VERSION,
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

/// An operation and its idempotency record as inserted: pending, so the record
/// has no expiry until `settle_idempotency` (ruling R2).
fn operation(
    n: u64,
    key: IdempotencyKey,
    hash: RequestHash,
    created: Timestamp,
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
        expires_at: None,
    };
    (op, idem)
}

fn simple_op(n: u64) -> (OperationRecord, IdempotencyRecord) {
    operation(
        n,
        key(501, &format!("req-{n}")),
        RequestHash([n as u8; 32]),
        t0(),
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

fn time_anchor(boot: &str, continuous_s: u64, wall: Timestamp) -> TimeAnchor {
    TimeAnchor {
        boot_id: BootId(boot.into()),
        continuous: Duration::from_secs(continuous_s),
        wall,
    }
}

fn limited(uid: u32) -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid },
        role: ClientRole::LimitedConsumer,
    }
}

fn binding(b: u8, grant: &GrantId, owner: CallerContext, work: &str) -> BindingRecord {
    BindingRecord {
        id: BindingId::from_random_bytes([b; 16]),
        environment: env_id(7),
        grant: grant.clone(),
        work_id: WorkId::parse(work).unwrap(),
        owner,
        profile: ProfileId::parse("default").unwrap(),
        profile_revision: 1,
        scope: scope(&[("h1", "u1")], &[Capability::SshAuthentication]),
        mechanism: "fake".into(),
        parent: None,
        created_at: plus(t0(), i64::from(b)),
        released_at: None,
        state: BindingState::Active,
    }
}

fn profile_def(revision: u64, pairs: &[(&str, &str)]) -> ProfileDefinition {
    ProfileDefinition {
        id: ProfileId::parse("default").unwrap(),
        revision,
        scope: scope(pairs, &[Capability::SshAuthentication]),
        label: Some("synthetic".into()),
    }
}

fn environment(b: u8, label: &str) -> EnvironmentRecord {
    EnvironmentRecord {
        id: env_id(b),
        device: DeviceId::from_random_bytes([b; 16]),
        kind: EnvironmentKind::NativeSession,
        label: Some(label.into()),
        permissions: EnvironmentPermissions::default(),
    }
}

fn decision(b: u8, generation: u64) -> DecisionRecord {
    DecisionRecord {
        id: DecisionId::from_random_bytes([b; 16]),
        kind: DecisionKind::WidenPolicy {
            action: PolicyAction::Resume {
                policy_id: PolicyId::parse("personal").unwrap(),
            },
        },
        generation: AuthorityGeneration(generation),
        created_at: plus(t0(), i64::from(b)),
        expires_at: plus(t0(), 900),
        state: DecisionState::Pending,
        decided_at: None,
    }
}

fn issuance(b: u8, grant: &GrantId, valid_before: Timestamp) -> IssuanceEntry {
    IssuanceEntry {
        id: IssuanceId::from_random_bytes([b; 16]),
        grant: grant.clone(),
        generation: AuthorityGeneration(0),
        pair: AccessPair {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse("u1").unwrap(),
        },
        bounds: CertificateBounds {
            serial: u64::from(b),
            key_id: format!("key-{b}"),
            principal: "hm:h1:u1".into(),
            valid_after: t0(),
            valid_before,
            extensions: BTreeSet::new(),
            subject_fingerprint: "SHA256:synthetic".into(),
        },
        state: IssuanceState::Reserved,
        reserved_at: plus(t0(), i64::from(b)),
        settled_at: None,
        void_reason: None,
    }
}

fn request_doc(n: u64) -> serde_json::Value {
    serde_json::json!({"kind": "ensure", "request_id": format!("req-{n}"), "work_id": "w"})
}

fn resolved_intent() -> ResolvedIntent {
    ResolvedIntent {
        profile: ProfileId::parse("default").unwrap(),
        profile_revision: 1,
        scope: scope(&[("h1", "u1")], &[Capability::SshAuthentication]),
        deadline: Deadline {
            intent: DeadlineIntent::Duration("2h".into()),
            resolved_at: t0(),
            effective: plus(t0(), 7200),
        },
        policy_revision: Some(PolicyRevision(1)),
        generation: AuthorityGeneration(0),
        grant: None,
        binding: None,
        adapter: None,
    }
}

fn adapter() -> AdapterIdentity {
    AdapterIdentity {
        mechanism: "fake".into(),
        instance: "fake-1".into(),
    }
}

/// Settle `op` as succeeded at `at` (wave-1 `update_operation`).
fn succeed(op: &mut OperationRecord, at: Timestamp) {
    op.state = OperationState::Succeeded;
    op.code = Some(heimdall_contract::Code::AccessReady);
    op.effect_status = EffectStatus::Applied;
    op.updated_at = at;
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
    let (op2, idem2) = operation(2, idem1.key.clone(), RequestHash([2; 32]), t0());
    assert!(
        s.transaction(|tx| tx.insert_operation(&op2, &idem2))
            .is_err()
    );
    assert_eq!(s.transaction(|tx| tx.operation(&op2.id)).unwrap(), None);
}

#[test]
fn cross_owner_request_id_is_a_distinct_key() {
    let s = mem();
    let (a, ia) = operation(1, key(501, "same"), RequestHash([1; 32]), t0());
    let (b, ib) = operation(2, key(502, "same"), RequestHash([1; 32]), t0());
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

/// Ruling: `time_anchor`/`set_time_anchor` are aliases of the runtime anchor.
#[test]
fn time_anchor_round_trips() {
    let s = mem();
    assert_eq!(s.transaction(|tx| tx.time_anchor()).unwrap(), None);
    let anchor = time_anchor("boot-a", 1234, plus(t0(), 5));
    s.transaction(|tx| tx.set_time_anchor(&anchor)).unwrap();
    let (old, new) = s
        .transaction(|tx| Ok((tx.time_anchor()?, tx.runtime_anchor()?)))
        .unwrap();
    assert_eq!(old, Some(anchor.clone()));
    assert_eq!(new, Some(anchor));
    let replaced = time_anchor("boot-b", 7, plus(t0(), 9));
    s.transaction(|tx| tx.set_runtime_anchor(&replaced))
        .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.time_anchor()).unwrap(),
        Some(replaced)
    );
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
    // Opening a fresh store visits the migration points of both steps (0001,
    // 0002) first; then the failed transaction (before transaction, before
    // commit) and the verifying one.
    assert_eq!(
        faults.visited(),
        vec![
            FaultPoint::BeforeMigration,
            FaultPoint::AfterMigration,
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
                classify(rec.as_ref(), None, idem.request_hash, plus(t0(), 1)),
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
    assert_eq!(SCHEMA_VERSION, 2);
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
    // The next version (3) is just as foreign.
    let dir = tempfile::tempdir().unwrap();
    let db = corrupt_copy(dir.path(), |b| {
        b[60..64].copy_from_slice(&(SCHEMA_VERSION + 1).to_be_bytes())
    });
    assert_refused_and_untouched(&db, |e| {
        matches!(
            e,
            StoreError::NewerSchema {
                found: 3,
                supported: 2
            }
        )
    });
}

// --- R1: time anchors, high-water mark, attended confirmation (review F01) ------------------

#[test]
fn high_water_mark_never_lowers() {
    let s = mem();
    let got = s
        .transaction(|tx| {
            let none = tx.high_water_mark()?;
            let a = tx.raise_high_water_mark(plus(t0(), 100))?;
            let b = tx.raise_high_water_mark(plus(t0(), 50))?;
            let stored = tx.high_water_mark()?;
            let c = tx.raise_high_water_mark(plus(t0(), 101))?;
            Ok((none, a, b, stored, c, tx.high_water_mark()?))
        })
        .unwrap();
    assert_eq!(
        got,
        (
            None,
            plus(t0(), 100),
            plus(t0(), 100),
            Some(plus(t0(), 100)),
            plus(t0(), 101),
            Some(plus(t0(), 101))
        )
    );
    // Survives reopen.
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    {
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        s.transaction(|tx| tx.raise_high_water_mark(plus(t0(), 7)))
            .unwrap();
    }
    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(
        s.transaction(|tx| tx.raise_high_water_mark(t0())).unwrap(),
        plus(t0(), 7)
    );
}

#[test]
fn grant_anchor_cannot_lengthen_within_a_boot_but_is_replaced_in_a_new_boot() {
    let s = mem();
    let g = GrantId::from_random_bytes([1; 16]);
    let bound = plus(t0(), 3600);
    let first = anchor_grant(g.clone(), time_anchor("boot-a", 1000, t0()), bound);
    assert_eq!(first.budget_end, Duration::from_secs(4600));
    // Same boot, later budget end (re-anchored from a later continuous reading).
    let longer = anchor_grant(g.clone(), time_anchor("boot-a", 2000, t0()), bound);
    // Same boot, same budget but a later bound.
    let later_bound = GrantAnchor {
        bound: plus(bound, 60),
        ..first.clone()
    };
    let shorter = shorten(&first, plus(t0(), 1800));
    assert!(shorter.budget_end < first.budget_end && shorter.bound < first.bound);
    let (a, b, c, kept, d, again, stored) = s
        .transaction(|tx| {
            Ok((
                tx.set_grant_anchor(&first)?,
                tx.set_grant_anchor(&longer)?,
                tx.set_grant_anchor(&later_bound)?,
                tx.grant_anchor(&g)?,
                tx.set_grant_anchor(&shorter)?,
                tx.set_grant_anchor(&first)?,
                tx.grant_anchor(&g)?,
            ))
        })
        .unwrap();
    assert_eq!(
        (&a, &b, &c),
        (&first, &first, &first),
        "refusals return the stored anchor"
    );
    assert_eq!(kept, Some(first.clone()));
    assert_eq!(d, shorter, "shortening is accepted");
    assert_eq!(
        again, shorter,
        "the earlier, longer anchor cannot come back"
    );
    assert_eq!(stored, Some(shorter.clone()));
    // A new boot: the old continuous reading means nothing; a fresh anchor (even
    // with a later budget and bound) replaces it.
    let rebooted = anchor_grant(g.clone(), time_anchor("boot-b", 5, plus(t0(), 600)), bound);
    assert!(rebooted.budget_end > shorter.budget_end && rebooted.bound > shorter.bound);
    let got = s
        .transaction(|tx| Ok((tx.set_grant_anchor(&rebooted)?, tx.grant_anchor(&g)?)))
        .unwrap();
    assert_eq!(got, (rebooted.clone(), Some(rebooted)));
    assert_eq!(
        s.transaction(|tx| tx.grant_anchor(&GrantId::from_random_bytes([2; 16])))
            .unwrap(),
        None
    );
}

#[test]
fn time_confirmation_round_trips_and_is_replaced() {
    let s = mem();
    let c1 = AttendedTimeConfirmation {
        boot_id: BootId("boot-a".into()),
        continuous: Duration::from_secs(10),
        wall: plus(t0(), 10),
        decision: DecisionId::from_random_bytes([1; 16]),
    };
    let c2 = AttendedTimeConfirmation {
        boot_id: BootId("boot-b".into()),
        decision: DecisionId::from_random_bytes([2; 16]),
        ..c1.clone()
    };
    let got = s
        .transaction(|tx| {
            let none = tx.time_confirmation()?;
            tx.set_time_confirmation(&c1)?;
            let one = tx.time_confirmation()?;
            tx.set_time_confirmation(&c2)?;
            Ok((none, one, tx.time_confirmation()?, tx.runtime_anchor()?))
        })
        .unwrap();
    assert_eq!(got, (None, Some(c1), Some(c2), None));
}

// --- R2: idempotency settlement and expired-key markers (review F02) -------------------------

#[test]
fn settle_then_purge_leaves_a_marker_that_expires_reuse_until_marker_purge() {
    let s = mem();
    let (mut op, idem) = simple_op(1);
    let settled_at = plus(t0(), 60);
    let expires = retention_expiry(settled_at, DEFAULT_RETENTION);
    s.transaction(|tx| {
        tx.insert_operation(&op, &idem)?;
        succeed(&mut op, settled_at);
        tx.update_operation(&op)?;
        tx.settle_idempotency(&idem.key, expires)?;
        // Idempotent: the first settlement wins.
        tx.settle_idempotency(&idem.key, plus(expires, 999))
    })
    .unwrap();
    let rec = s
        .transaction(|tx| tx.idempotency_record(&idem.key))
        .unwrap()
        .unwrap();
    assert_eq!(rec.expires_at, Some(expires));
    assert_eq!(
        classify(Some(&rec), None, idem.request_hash, plus(expires, -1)),
        IdempotencyOutcome::Replay(op.id.clone())
    );
    assert_eq!(
        s.transaction(|tx| tx.purge_operations_before(plus(expires, -1)))
            .unwrap(),
        0,
        "not due before expires_at"
    );
    assert_eq!(
        s.transaction(|tx| tx.purge_operations_before(expires))
            .unwrap(),
        1,
        "due at expires_at"
    );
    let key_hash = idem.key.hash().unwrap();
    let (gone_op, gone_rec, marker) = s
        .transaction(|tx| {
            Ok((
                tx.operation(&op.id)?,
                tx.idempotency_record(&idem.key)?,
                tx.expired_key_marker(&key_hash)?,
            ))
        })
        .unwrap();
    assert_eq!((gone_op, gone_rec), (None, None));
    let marker = marker.expect("purge leaves a marker");
    assert_eq!(
        marker,
        ExpiredKeyMarker {
            key_hash,
            expired_at: expires,
            marker_until: marker_until(expires),
        }
    );
    // Reuse inside the window, with the same or another hash: expired, never new.
    for h in [idem.request_hash, RequestHash([0xee; 32])] {
        assert_eq!(
            classify(None, Some(&marker), h, plus(expires, 86_400)),
            IdempotencyOutcome::Expired
        );
    }
    // Another caller's same request ID is a different key with no marker.
    let foreign = key(502, "req-1").hash().unwrap();
    assert_ne!(foreign, key_hash);
    assert_eq!(
        s.transaction(|tx| tx.expired_key_marker(&foreign)).unwrap(),
        None
    );
    assert_eq!(
        s.transaction(|tx| tx.purge_markers_before(plus(marker.marker_until, -1)))
            .unwrap(),
        0
    );
    assert_eq!(
        s.transaction(|tx| tx.purge_markers_before(marker.marker_until))
            .unwrap(),
        1
    );
    let after = s
        .transaction(|tx| tx.expired_key_marker(&key_hash))
        .unwrap();
    assert_eq!(after, None);
    assert_eq!(
        classify(None, after.as_ref(), idem.request_hash, marker.marker_until),
        IdempotencyOutcome::New
    );
    assert_eq!(
        s.transaction(|tx| tx.purge_operations_before(plus(expires, 10 * 86_400)))
            .unwrap(),
        0
    );
}

#[test]
fn pending_keys_never_expire_and_are_never_purged() {
    let s = mem();
    let far = plus(t0(), 10 * 365 * 86_400);
    let states = [
        OperationState::Queued,
        OperationState::Running,
        OperationState::AwaitingApproval,
        OperationState::OutcomeUnknown,
    ];
    for (n, state) in (1u64..).zip(states) {
        let (mut op, idem) = simple_op(n);
        s.transaction(|tx| {
            tx.insert_operation(&op, &idem)?;
            if state != OperationState::Queued {
                op.state = state;
                tx.update_operation(&op)?;
            }
            Ok(())
        })
        .unwrap();
        let e = s
            .transaction(|tx| tx.settle_idempotency(&idem.key, t0()))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)), "{state:?}");
        no_canary(&e);
    }
    // Settled but not yet given an expiry: still live.
    let (mut op5, idem5) = simple_op(5);
    s.transaction(|tx| {
        tx.insert_operation(&op5, &idem5)?;
        succeed(&mut op5, plus(t0(), 1));
        tx.update_operation(&op5)
    })
    .unwrap();
    // Even a record handed to `insert_operation` with an expiry already set does
    // not make an open or unresolved operation purgeable: purge also requires a
    // settled state.
    for (n, state) in [
        (6, OperationState::Running),
        (7, OperationState::OutcomeUnknown),
    ] {
        let (mut op, mut idem) = simple_op(n);
        op.state = state;
        idem.expires_at = Some(t0());
        s.transaction(|tx| tx.insert_operation(&op, &idem)).unwrap();
    }
    assert_eq!(
        s.transaction(|tx| tx.purge_operations_before(far)).unwrap(),
        0
    );
    s.transaction(|tx| {
        assert!(tx.operation(&op_id(6))?.is_some());
        assert!(tx.operation(&op_id(7))?.is_some());
        for n in 1..=5 {
            let (_, idem) = simple_op(n);
            let rec = tx.idempotency_record(&idem.key)?.expect("kept");
            assert_eq!(rec.expires_at, None);
            assert_eq!(
                classify(Some(&rec), None, idem.request_hash, far),
                IdempotencyOutcome::Replay(op_id(n))
            );
            assert_eq!(tx.expired_key_marker(&idem.key.hash().unwrap())?, None);
        }
        Ok(())
    })
    .unwrap();
    let (_, ghost) = simple_op(9);
    assert!(
        s.transaction(|tx| tx.settle_idempotency(&ghost.key, t0()))
            .is_err()
    );
}

// --- R3: decision records (review F03) --------------------------------------------------------

#[test]
fn decisions_complete_once_and_go_stale_when_the_generation_moves() {
    let s = mem();
    let (d1, d2, d3) = (decision(1, 0), decision(2, 0), decision(3, 0));
    s.transaction(|tx| {
        tx.insert_decision(&d1)?;
        tx.insert_decision(&d2)?;
        tx.insert_decision(&d3)
    })
    .unwrap();
    assert!(matches!(
        s.transaction(|tx| tx.insert_decision(&d1)),
        Err(StoreError::GenerationConflict(_))
    ));
    let mut decided = decision(4, 0);
    decided.state = DecisionState::Approved;
    assert!(s.transaction(|tx| tx.insert_decision(&decided)).is_err());
    let pending: Vec<_> = s
        .transaction(|tx| tx.pending_decisions())
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(pending, vec![d1.id.clone(), d2.id.clone(), d3.id.clone()]);

    let now = plus(t0(), 60);
    let first = s
        .transaction(|tx| tx.complete_decision(&d1.id, Verdict::Approve, now))
        .unwrap();
    let mut approved = d1.clone();
    approved.state = DecisionState::Approved;
    approved.decided_at = Some(now);
    assert_eq!(first, DecisionCompletion::Completed(approved.clone()));
    // Consume-once.
    let again = s
        .transaction(|tx| tx.complete_decision(&d1.id, Verdict::Deny, now))
        .unwrap();
    assert!(
        matches!(&again, DecisionCompletion::Refused { record, .. } if *record == approved),
        "{again:?}"
    );
    // Expired: refused, unchanged.
    let late = s
        .transaction(|tx| tx.complete_decision(&d2.id, Verdict::Approve, d2.expires_at))
        .unwrap();
    assert!(matches!(&late, DecisionCompletion::Refused { record, .. } if *record == d2));
    assert_eq!(
        s.transaction(|tx| tx.decision(&d2.id)).unwrap(),
        Some(d2.clone())
    );
    // The generation moves (revocation): stale even for Deny, persisted.
    s.transaction(|tx| tx.insert_tombstone(&tombstone(9)))
        .unwrap();
    let stale = s
        .transaction(|tx| tx.complete_decision(&d3.id, Verdict::Deny, now))
        .unwrap();
    let DecisionCompletion::Refused { reason, record } = stale else {
        panic!("stale decision completed");
    };
    no_canary(&reason);
    assert_eq!(record.state, DecisionState::Stale);
    assert_eq!(record.decided_at, None);
    assert_eq!(
        s.transaction(|tx| tx.decision(&d3.id)).unwrap(),
        Some(record)
    );
    let pending: Vec<_> = s
        .transaction(|tx| tx.pending_decisions())
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(pending, vec![d2.id.clone()]);
    assert!(
        s.transaction(|tx| tx.complete_decision(&decision(8, 0).id, Verdict::Approve, now))
            .is_err()
    );
}

// --- R4: bindings, profiles, environments, policy lookup, denial (review F04) ---------------

#[test]
fn binding_release_is_idempotent_and_authorized_by_ownership() {
    let s = mem();
    let g = grant(1, None, plus(t0(), 3600), GrantState::Active);
    let mine = binding(1, &g.id, limited(501), "work-a");
    let mine2 = binding(2, &g.id, limited(501), "work-a");
    let elsewhere = BindingRecord {
        environment: env_id(8),
        ..binding(3, &g.id, limited(501), "work-a")
    };
    s.transaction(|tx| {
        tx.insert_grant(&g)?;
        tx.insert_binding(&mine)?;
        tx.insert_binding(&mine2)?;
        tx.insert_binding(&elsewhere)
    })
    .unwrap();
    assert!(matches!(
        s.transaction(|tx| tx.insert_binding(&mine)),
        Err(StoreError::GenerationConflict(_))
    ));
    let ghost = binding(
        4,
        &GrantId::from_random_bytes([0xaa; 16]),
        limited(501),
        "w",
    );
    assert!(s.transaction(|tx| tx.insert_binding(&ghost)).is_err());
    let (got, work, refs, ghost_row) = s
        .transaction(|tx| {
            Ok((
                tx.binding(&mine.id)?,
                tx.bindings_for_work(&env_id(7), &WorkId::parse("work-a").unwrap())?,
                tx.grant_references(&g.id)?,
                tx.binding(&ghost.id)?,
            ))
        })
        .unwrap();
    assert_eq!(got, Some(mine.clone()));
    assert_eq!(work, vec![mine.clone(), mine2.clone()]);
    assert_eq!(ghost_row, None);
    let held: BTreeSet<_> = refs.iter().map(|r| r.binding.clone()).collect();
    assert_eq!(
        held,
        [mine.id.clone(), mine2.id.clone(), elsewhere.id.clone()]
            .into_iter()
            .collect()
    );

    let now = plus(t0(), 600);
    let release = |id: &BindingId, who: CallerContext| {
        s.transaction(|tx| tx.release_binding(id, &who, now))
            .unwrap()
    };
    // A foreign limited consumer holding the ID cannot release it.
    assert_eq!(release(&mine.id, limited(502)), ReleaseOutcome::NotOwner);
    assert_eq!(
        s.transaction(|tx| tx.binding(&mine.id))
            .unwrap()
            .unwrap()
            .state,
        BindingState::Active
    );
    assert_eq!(
        release(&mine.id, limited(501)),
        ReleaseOutcome::Released {
            remaining_references: 2
        }
    );
    assert_eq!(
        release(&mine.id, limited(501)),
        ReleaseOutcome::AlreadyReleased
    );
    assert_eq!(
        release(&mine.id, limited(502)),
        ReleaseOutcome::NotOwner,
        "ownership is checked before the released state is revealed"
    );
    let released = s.transaction(|tx| tx.binding(&mine.id)).unwrap().unwrap();
    assert_eq!(released.state, BindingState::Released);
    assert_eq!(released.released_at, Some(now));
    // The owner role may release another principal's binding.
    assert_eq!(
        release(&mine2.id, caller(503)),
        ReleaseOutcome::Released {
            remaining_references: 1
        }
    );
    // Release never revokes the grant (ADR-0006 §13.2).
    assert_eq!(
        s.transaction(|tx| tx.grant(&g.id)).unwrap().unwrap().state,
        GrantState::Active
    );
    assert!(
        s.transaction(|tx| tx.release_binding(&ghost.id, &caller(501), now))
            .is_err()
    );
}

#[test]
fn profile_snapshot_is_immutable_at_a_revision() {
    let s = mem();
    let id = ProfileId::parse("default").unwrap();
    let v1 = profile_def(1, &[("h1", "u1")]);
    s.transaction(|tx| tx.upsert_profile(&v1)).unwrap();
    // Same revision, wider scope: refused; nothing changes.
    let widened = profile_def(1, &[("h1", "u1"), ("h9", "root")]);
    let e = s.transaction(|tx| tx.upsert_profile(&widened)).unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    no_canary(&e);
    let (cur, snap) = s
        .transaction(|tx| Ok((tx.profile(&id)?, tx.profile_snapshot(&id, 1)?)))
        .unwrap();
    assert_eq!(cur, Some(v1.clone()));
    assert_eq!(snap, Some(v1.snapshot()));
    // A new revision gets its own snapshot; the old one is unchanged.
    let v2 = profile_def(2, &[("h1", "u1"), ("h2", "u1")]);
    s.transaction(|tx| {
        tx.upsert_profile(&v2)?;
        tx.upsert_profile(&v2) // identical re-upsert is a no-op
    })
    .unwrap();
    let (cur, s1, s2, s3) = s
        .transaction(|tx| {
            Ok((
                tx.profile(&id)?,
                tx.profile_snapshot(&id, 1)?,
                tx.profile_snapshot(&id, 2)?,
                tx.profile_snapshot(&id, 3)?,
            ))
        })
        .unwrap();
    assert_eq!(cur, Some(v2.clone()));
    assert_eq!(
        s1,
        Some(v1.snapshot()),
        "adding a host never widens revision 1"
    );
    assert_eq!(s2, Some(v2.snapshot()));
    assert_eq!(s3, None);
    // A stale writer cannot roll the definition back.
    assert!(matches!(
        s.transaction(|tx| tx.upsert_profile(&v1)),
        Err(StoreError::GenerationConflict(_))
    ));
    assert_eq!(s.transaction(|tx| tx.profile(&id)).unwrap(), Some(v2));
}

#[test]
fn environments_upsert_and_policies_for_matches_profile_and_environment() {
    let s = mem();
    let e7 = environment(7, "laptop");
    let renamed = EnvironmentRecord {
        label: Some("laptop-2".into()),
        ..e7.clone()
    };
    let got = s
        .transaction(|tx| {
            let none = tx.environment(&e7.id)?;
            tx.upsert_environment(&e7)?;
            let one = tx.environment(&e7.id)?;
            tx.upsert_environment(&renamed)?;
            Ok((none, one, tx.environment(&e7.id)?))
        })
        .unwrap();
    assert_eq!(got, (None, Some(e7), Some(renamed)));

    let named = |id: &str, profile: &str, envs: &[u8]| StandingPolicy {
        id: PolicyId::parse(id).unwrap(),
        profile: ProfileId::parse(profile).unwrap(),
        environments: envs.iter().map(|b| env_id(*b)).collect(),
        ..policy(1)
    };
    let policies = [
        named("personal", "default", &[7]),
        named("other-env", "default", &[8]),
        named("other-profile", "work", &[7]),
        named("both", "default", &[7, 8]),
    ];
    s.transaction(|tx| {
        for p in &policies {
            tx.upsert_policy(p, false)?;
        }
        Ok(())
    })
    .unwrap();
    let ids = |profile: &str, env: u8| -> Vec<String> {
        s.transaction(|tx| tx.policies_for(&ProfileId::parse(profile).unwrap(), &env_id(env)))
            .unwrap()
            .into_iter()
            .map(|p| p.id.as_str().to_owned())
            .collect()
    };
    assert_eq!(ids("default", 7), ["both", "personal"]);
    assert_eq!(ids("default", 8), ["both", "other-env"]);
    assert_eq!(ids("work", 7), ["other-profile"]);
    assert!(ids("work", 8).is_empty());
    assert!(ids("default", 9).is_empty());
}

#[test]
fn denied_ancestor_walks_through_a_revoked_grandparent() {
    let s = mem();
    let d = plus(t0(), 3600);
    let gp = grant(1, None, d, GrantState::Revoked);
    let parent = grant(2, Some(gp.id.clone()), d, GrantState::Active);
    let child = grant(3, Some(parent.id.clone()), d, GrantState::Active);
    let lone = grant(4, None, d, GrantState::Active);
    s.transaction(|tx| {
        for g in [&gp, &parent, &child, &lone] {
            tx.insert_grant(g)?;
        }
        tx.insert_tombstone(&tombstone(1))?; // the grandparent
        Ok(())
    })
    .unwrap();
    let got = s
        .transaction(|tx| {
            Ok((
                tx.denied_ancestor(&child.id)?,
                tx.denied_ancestor(&parent.id)?,
                tx.denied_ancestor(&gp.id)?,
                tx.denied_ancestor(&lone.id)?,
                tx.denied_ancestor(&GrantId::from_random_bytes([0xcc; 16]))?,
                tx.tombstone(&child.id)?,
                tx.tombstone(&gp.id)?.map(|t| t.generation),
            ))
        })
        .unwrap();
    assert_eq!(
        got,
        (
            Some(gp.id.clone()),
            Some(gp.id.clone()),
            Some(gp.id.clone()),
            None,
            None,
            None,
            Some(AuthorityGeneration(1))
        )
    );
    // The nearest tombstoned ancestor wins.
    s.transaction(|tx| tx.insert_tombstone(&tombstone(2)))
        .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.denied_ancestor(&child.id)).unwrap(),
        Some(parent.id.clone())
    );
}

// --- R5: recovery intent and stage receipts (review F05) -------------------------------------

#[test]
fn recovery_intent_round_trips_and_only_gains_facts() {
    let s = mem();
    let (op, idem) = simple_op(1);
    s.transaction(|tx| tx.insert_operation(&op, &idem)).unwrap();
    let bare = RecoveryIntent {
        request: request_doc(1),
        resolved: None,
    };
    let resolved = RecoveryIntent {
        resolved: Some(resolved_intent()),
        ..bare.clone()
    };
    let mut with_grant = resolved.clone();
    if let Some(r) = with_grant.resolved.as_mut() {
        r.grant = Some(GrantId::from_random_bytes([1; 16]));
        r.adapter = Some(adapter());
    }
    let got = s
        .transaction(|tx| {
            let none = tx.recovery_intent(&op.id)?;
            tx.set_recovery_intent(&op.id, &bare)?;
            let a = tx.recovery_intent(&op.id)?;
            tx.set_recovery_intent(&op.id, &resolved)?;
            let b = tx.recovery_intent(&op.id)?;
            tx.set_recovery_intent(&op.id, &with_grant)?;
            tx.set_recovery_intent(&op.id, &with_grant)?; // repeat: no-op
            Ok((none, a, b, tx.recovery_intent(&op.id)?))
        })
        .unwrap();
    assert_eq!(
        got,
        (
            None,
            Some(bare.clone()),
            Some(resolved.clone()),
            Some(with_grant.clone())
        )
    );
    // Anything that would re-resolve or rewrite the intent is refused.
    let mut other_request = with_grant.clone();
    other_request.request = request_doc(2);
    let mut moved_deadline = with_grant.clone();
    let mut reassigned = with_grant.clone();
    if let (Some(d), Some(r)) = (
        moved_deadline.resolved.as_mut(),
        reassigned.resolved.as_mut(),
    ) {
        d.deadline.effective = plus(t0(), 99_999);
        r.grant = Some(GrantId::from_random_bytes([2; 16]));
    }
    for bad in [&other_request, &moved_deadline, &reassigned, &bare] {
        let e = s
            .transaction(|tx| tx.set_recovery_intent(&op.id, bad))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)));
        no_canary(&e);
    }
    assert_eq!(
        s.transaction(|tx| tx.recovery_intent(&op.id)).unwrap(),
        Some(with_grant)
    );
    // The operation must exist.
    assert!(
        s.transaction(|tx| tx.set_recovery_intent(&op_id(77), &bare))
            .is_err()
    );
    // Key material is refused and never echoed.
    let c = canary();
    let leaky = RecoveryIntent {
        request: serde_json::json!({"k": format!("-----BEGIN OPENSSH PRIVATE KEY-----{c}")}),
        resolved: None,
    };
    let (op2, idem2) = simple_op(2);
    s.transaction(|tx| tx.insert_operation(&op2, &idem2))
        .unwrap();
    let e = s
        .transaction(|tx| tx.set_recovery_intent(&op2.id, &leaky))
        .unwrap_err();
    no_canary(&e);
    assert_no_canary(&e.to_string());
    assert_eq!(
        s.transaction(|tx| tx.recovery_intent(&op2.id)).unwrap(),
        None
    );
}

#[test]
fn stage_receipts_are_append_only_and_ordered() {
    let s = mem();
    let (op1, i1) = simple_op(1);
    let (op2, i2) = simple_op(2);
    let receipts = [
        StageReceipt {
            stage: "load_authority".into(),
            recorded_at: plus(t0(), 1),
            effect: EffectReceipt::NotAttempted,
        },
        StageReceipt {
            stage: "prepare".into(),
            recorded_at: plus(t0(), 2),
            effect: EffectReceipt::Attempted {
                adapter: adapter(),
                effect_token: "tok-1".into(),
            },
        },
        // Same instant as the previous one: order still follows append order.
        StageReceipt {
            stage: "prepare".into(),
            recorded_at: plus(t0(), 2),
            effect: EffectReceipt::Confirmed {
                adapter: adapter(),
                credential_ref: "cred-ref-1".into(),
            },
        },
    ];
    s.transaction(|tx| {
        tx.insert_operation(&op1, &i1)?;
        tx.insert_operation(&op2, &i2)?;
        for r in &receipts {
            tx.append_stage_receipt(&op1.id, r)?;
        }
        tx.append_stage_receipt(&op2.id, &receipts[0])
    })
    .unwrap();
    // A later transaction appends after the earlier ones.
    let late = StageReceipt {
        stage: "bind".into(),
        recorded_at: plus(t0(), 3),
        effect: EffectReceipt::NotAttempted,
    };
    s.transaction(|tx| tx.append_stage_receipt(&op1.id, &late))
        .unwrap();
    let (r1, r2, none) = s
        .transaction(|tx| {
            Ok((
                tx.stage_receipts(&op1.id)?,
                tx.stage_receipts(&op2.id)?,
                tx.stage_receipts(&op_id(77))?,
            ))
        })
        .unwrap();
    let mut want = receipts.to_vec();
    want.push(late);
    assert_eq!(r1, want);
    assert_eq!(r2, vec![receipts[0].clone()]);
    assert!(none.is_empty());
    assert!(
        s.transaction(|tx| tx.append_stage_receipt(&op_id(77), &receipts[0]))
            .is_err()
    );
}

// --- R6: issuance substrate (review F06; ADR-0005 §3.5) --------------------------------------

#[test]
fn issuance_reserve_publish_void_cas_and_residual() {
    let s = mem();
    let g = GrantId::from_random_bytes([1; 16]);
    let g2 = GrantId::from_random_bytes([2; 16]);
    let e1 = issuance(1, &g, t("2026-10-01T06:00:00Z"));
    let e2 = issuance(2, &g, t("2026-10-01T09:00:00Z"));
    let e3 = issuance(3, &g, t("2026-10-01T05:00:00Z"));
    let e4 = issuance(4, &g2, t("2026-10-01T07:00:00Z"));
    s.transaction(|tx| {
        for e in [&e1, &e2, &e3, &e4] {
            tx.reserve_issuance(e)?;
        }
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        s.transaction(|tx| tx.reserve_issuance(&e1)),
        Err(StoreError::GenerationConflict(_))
    ));
    let mut not_reserved = issuance(5, &g, t("2026-10-01T10:00:00Z"));
    not_reserved.state = IssuanceState::Published;
    assert!(
        s.transaction(|tx| tx.reserve_issuance(&not_reserved))
            .is_err()
    );
    // Reserved entries already count (a reservation may have been signed).
    assert_eq!(
        s.transaction(|tx| tx.issuance_residual(std::slice::from_ref(&g)))
            .unwrap(),
        Some(e2.bounds.valid_before)
    );

    let now = plus(t0(), 60);
    let published = s
        .transaction(|tx| tx.publish_issuance(&e1.id, now))
        .unwrap();
    assert_eq!(published.state, IssuanceState::Published);
    assert_eq!(published.settled_at, Some(now));
    let reason = IssuanceRefusal::StaleGeneration;
    let voided = s
        .transaction(|tx| tx.void_issuance(&e2.id, &reason, now))
        .unwrap();
    assert_eq!(voided.state, IssuanceState::Voided);
    assert_eq!(voided.void_reason, Some(reason.clone()));
    // CAS: only `reserved` moves.
    for r in [
        s.transaction(|tx| tx.publish_issuance(&e1.id, now)),
        s.transaction(|tx| tx.publish_issuance(&e2.id, now)),
        s.transaction(|tx| tx.void_issuance(&e1.id, &reason, now)),
        s.transaction(|tx| tx.void_issuance(&e2.id, &reason, now)),
    ] {
        let e = r.unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)), "{e}");
        no_canary(&e);
    }
    assert!(
        s.transaction(|tx| tx.publish_issuance(&IssuanceId::from_random_bytes([9; 16]), now))
            .is_err()
    );
    let (entries, residual, both, none) = s
        .transaction(|tx| {
            Ok((
                tx.issuance_entries(&g)?,
                tx.issuance_residual(std::slice::from_ref(&g))?,
                tx.issuance_residual(&[g.clone(), g2.clone()])?,
                tx.issuance_residual(&[])?,
            ))
        })
        .unwrap();
    let states: Vec<_> = entries.iter().map(|e| (e.id.clone(), e.state)).collect();
    assert_eq!(
        states,
        vec![
            (e1.id.clone(), IssuanceState::Published),
            (e2.id.clone(), IssuanceState::Voided),
            (e3.id.clone(), IssuanceState::Reserved),
        ]
    );
    // Voided (09:00) never counts; published (06:00) beats reserved (05:00).
    assert_eq!(residual, Some(e1.bounds.valid_before));
    assert_eq!(both, Some(e4.bounds.valid_before));
    assert_eq!(none, None);
}

#[test]
fn credential_instances_round_trip_and_destroyed_is_absorbing() {
    let s = mem();
    let g = GrantId::from_random_bytes([1; 16]);
    let pending = CredentialInstance {
        id: CredentialInstanceId::from_random_bytes([1; 16]),
        grant: g.clone(),
        key_handle_ref: "handle-1".into(),
        certificates: Vec::new(),
        state: CredentialState::Pending,
    };
    let installed = CredentialInstance {
        certificates: vec![IssuanceId::from_random_bytes([3; 16])],
        state: CredentialState::Installed,
        // A different grant/handle in the update is ignored (identity is fixed).
        grant: GrantId::from_random_bytes([2; 16]),
        key_handle_ref: "handle-other".into(),
        ..pending.clone()
    };
    let got = s
        .transaction(|tx| {
            let none = tx.credential_instance(&pending.id)?;
            tx.insert_credential_instance(&pending)?;
            let a = tx.credential_instance(&pending.id)?;
            tx.update_credential_instance(&installed)?;
            Ok((none, a, tx.credential_instance(&pending.id)?))
        })
        .unwrap();
    let want_installed = CredentialInstance {
        certificates: installed.certificates.clone(),
        state: CredentialState::Installed,
        ..pending.clone()
    };
    assert_eq!(got, (None, Some(pending.clone()), Some(want_installed)));
    assert!(matches!(
        s.transaction(|tx| tx.insert_credential_instance(&pending)),
        Err(StoreError::GenerationConflict(_))
    ));
    let destroyed = CredentialInstance {
        certificates: Vec::new(),
        state: CredentialState::Destroyed,
        ..pending.clone()
    };
    s.transaction(|tx| tx.update_credential_instance(&destroyed))
        .unwrap();
    assert!(matches!(
        s.transaction(|tx| tx.update_credential_instance(&pending)),
        Err(StoreError::GenerationConflict(_))
    ));
    assert_eq!(
        s.transaction(|tx| tx.credential_instance(&pending.id))
            .unwrap(),
        Some(destroyed)
    );
    let ghost = CredentialInstance {
        id: CredentialInstanceId::from_random_bytes([9; 16]),
        ..pending
    };
    assert!(
        s.transaction(|tx| tx.update_credential_instance(&ghost))
            .is_err()
    );
}

// --- R7: unresolved operations (review F07) ----------------------------------------------------

#[test]
fn outcome_unknown_is_unresolved_not_open_and_survives_purge() {
    let s = mem();
    let (queued, qi) = simple_op(1);
    let (mut unknown, ui) = simple_op(2);
    let (mut done, di) = simple_op(3);
    let g = grant(1, None, plus(t0(), 3600), GrantState::Active);
    let anchor = anchor_grant(
        g.id.clone(),
        time_anchor("boot-a", 1, t0()),
        plus(t0(), 3600),
    );
    let receipt = StageReceipt {
        stage: "prepare".into(),
        recorded_at: plus(t0(), 30),
        effect: EffectReceipt::Uncertain {
            adapter: adapter(),
            effect_token: "tok-2".into(),
        },
    };
    let intent = RecoveryIntent {
        request: request_doc(2),
        resolved: Some(resolved_intent()),
    };
    s.transaction(|tx| {
        tx.insert_operation(&queued, &qi)?;
        tx.insert_operation(&unknown, &ui)?;
        tx.insert_operation(&done, &di)?;
        tx.set_recovery_intent(&unknown.id, &intent)?;
        tx.append_stage_receipt(&unknown.id, &receipt)?;
        unknown.state = OperationState::OutcomeUnknown;
        unknown.effect_status = EffectStatus::Unknown;
        unknown.updated_at = plus(t0(), 60);
        tx.update_operation(&unknown)?;
        succeed(&mut done, plus(t0(), 60));
        tx.update_operation(&done)?;
        tx.settle_idempotency(&di.key, plus(t0(), 120))?;
        tx.set_recovery_intent(
            &done.id,
            &RecoveryIntent {
                request: request_doc(3),
                resolved: None,
            },
        )?;
        tx.append_stage_receipt(&done.id, &receipt)?;
        tx.insert_grant(&g)?;
        tx.insert_tombstone(&tombstone(5))?;
        tx.insert_decision(&decision(1, 1))?;
        tx.reserve_issuance(&issuance(1, &g.id, plus(t0(), 1800)))?;
        tx.set_grant_anchor(&anchor)?;
        Ok(())
    })
    .unwrap();
    let (open, unresolved) = s
        .transaction(|tx| Ok((tx.open_operations()?, tx.unresolved_operations()?)))
        .unwrap();
    assert_eq!(open, vec![queued.clone()]);
    assert_eq!(unresolved, vec![unknown.clone()]);
    let e = s
        .transaction(|tx| tx.settle_idempotency(&ui.key, plus(t0(), 120)))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));

    let far = plus(t0(), 10 * 365 * 86_400);
    assert_eq!(
        s.transaction(|tx| tx.purge_operations_before(far)).unwrap(),
        1,
        "only the settled, expired operation goes"
    );
    s.transaction(|tx| {
        assert_eq!(tx.unresolved_operations()?, vec![unknown.clone()]);
        assert_eq!(tx.open_operations()?, vec![queued.clone()]);
        assert_eq!(tx.operation(&unknown.id)?, Some(unknown.clone()));
        assert_eq!(tx.idempotency_record(&ui.key)?.unwrap().expires_at, None);
        assert_eq!(tx.recovery_intent(&unknown.id)?, Some(intent.clone()));
        assert_eq!(tx.stage_receipts(&unknown.id)?, vec![receipt.clone()]);
        // The settled operation went with its own evidence and left a marker.
        assert_eq!(tx.operation(&done.id)?, None);
        assert_eq!(tx.recovery_intent(&done.id)?, None);
        assert!(tx.stage_receipts(&done.id)?.is_empty());
        assert!(tx.expired_key_marker(&di.key.hash().unwrap())?.is_some());
        // Authority and issuance state is untouched.
        assert!(tx.tombstone(&tombstone(5).grant)?.is_some());
        assert!(tx.decision(&decision(1, 1).id)?.is_some());
        assert_eq!(tx.issuance_entries(&g.id)?.len(), 1);
        assert_eq!(tx.grant_anchor(&g.id)?, Some(anchor.clone()));
        Ok(())
    })
    .unwrap();
    // Reconciliation settles it; only then can it expire and be purged.
    unknown.state = OperationState::Failed;
    unknown.updated_at = plus(t0(), 200);
    s.transaction(|tx| {
        tx.update_operation(&unknown)?;
        tx.settle_idempotency(&ui.key, plus(t0(), 300))
    })
    .unwrap();
    assert!(
        s.transaction(|tx| tx.unresolved_operations())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.transaction(|tx| tx.purge_operations_before(far)).unwrap(),
        1
    );
}

// --- R8: neutral event sequences (review F08) --------------------------------------------------

#[test]
fn stored_events_after_sequences_are_monotonic_and_page_boundaries_match() {
    let s = mem();
    let a = env_id(0xa);
    let b = env_id(0xb);
    let appended = s
        .transaction(|tx| {
            let mut out = Vec::new();
            for i in 0..8i64 {
                let env = if i % 3 == 0 { &b } else { &a };
                let (_, seq) = tx.append_event(&event(
                    env,
                    EventType::OperationStateChanged,
                    None,
                    plus(t0(), i * 60),
                ))?;
                out.push((env.clone(), seq));
            }
            Ok(out)
        })
        .unwrap();
    let a_seqs: Vec<u64> = appended
        .iter()
        .filter(|(e, _)| *e == a)
        .map(|(_, s)| *s)
        .collect();
    let (page, boundary, generation, wave1) = s
        .transaction(|tx| {
            Ok((
                tx.stored_events_after(&a, 0, &EventFilter::default(), 100)?,
                tx.snapshot_boundary(&a)?,
                tx.authority_generation()?,
                tx.events_after(&a, 0, &EventFilter::default(), 100)?,
            ))
        })
        .unwrap();
    let seqs: Vec<u64> = page.events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, a_seqs);
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "strictly increasing");
    assert_eq!(page.head_seq, *a_seqs.last().unwrap());
    assert_eq!(page.tail_seq, 0);
    assert_eq!(boundary, (generation, page.head_seq));
    for e in &page.events {
        assert_eq!(e.event.environment_id, a);
        assert!(e.event.cursor.0.is_empty(), "storage holds no cursor");
        no_canary(&e.event.payload);
    }
    // The wave-1 form carries the same sequences in its marker.
    let markers: Vec<u64> = wave1.events.iter().map(|e| event_seq(e).unwrap()).collect();
    assert_eq!(markers, seqs);
    assert_eq!(
        (wave1.head_seq, wave1.tail_seq),
        (page.head_seq, page.tail_seq)
    );
    // Paging: continuing after the last returned sequence loses nothing.
    let mut seen = Vec::new();
    let mut after = 0;
    loop {
        let p = s
            .transaction(|tx| tx.stored_events_after(&a, after, &EventFilter::default(), 2))
            .unwrap();
        assert_eq!(p.head_seq, page.head_seq, "head is environment-wide");
        let Some(last) = p.events.last() else { break };
        after = last.seq;
        seen.extend(p.events.iter().map(|e| e.seq));
    }
    assert_eq!(seen, seqs);
    // Trim: tail moves to the trim boundary, head stays, the rest is above tail.
    let tail = s
        .transaction(|tx| tx.trim_events(&a, plus(t0(), 150), 1000))
        .unwrap();
    let trimmed = s
        .transaction(|tx| tx.stored_events_after(&a, 0, &EventFilter::default(), 100))
        .unwrap();
    assert_eq!(trimmed.tail_seq, tail);
    assert_eq!(trimmed.head_seq, page.head_seq);
    assert!(trimmed.events.iter().all(|e| e.seq > tail));
    // A revocation moves the generation, not the head; both read together.
    s.transaction(|tx| tx.insert_tombstone(&tombstone(1)))
        .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.snapshot_boundary(&a)).unwrap(),
        (generation.next(), page.head_seq)
    );
    // An empty environment.
    let empty = s
        .transaction(|tx| tx.stored_events_after(&env_id(0xc), 0, &EventFilter::default(), 10))
        .unwrap();
    assert_eq!(
        (empty.events.len(), empty.head_seq, empty.tail_seq),
        (0, 0, 0)
    );
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
                let marker = tx.expired_key_marker(&k.hash().unwrap())?;
                let outcome = classify(rec.as_ref(), marker.as_ref(), hash, now);
                if outcome == IdempotencyOutcome::New {
                    let (op, idem) = operation(n as u64 + 1, k.clone(), hash, now);
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

    /// R1: within one boot a stored grant budget never lengthens (neither its
    /// continuous budget end nor its bound); an anchor from another boot replaces it.
    #[test]
    fn grant_anchor_budget_never_lengthens_within_a_boot(
        steps in prop::collection::vec((0u8..2, 0u64..10_000, 0i64..20_000), 1..30)
    ) {
        let s = mem();
        let g = GrantId::from_random_bytes([1; 16]);
        let mut model: Option<GrantAnchor> = None;
        for (boot, continuous, bound_s) in steps {
            let candidate = anchor_grant(
                g.clone(),
                time_anchor(&format!("boot-{boot}"), continuous, t0()),
                plus(t0(), bound_s),
            );
            let got = s.transaction(|tx| tx.set_grant_anchor(&candidate)).unwrap();
            let expected = match &model {
                Some(m)
                    if m.anchor.boot_id == candidate.anchor.boot_id
                        && (candidate.budget_end > m.budget_end || candidate.bound > m.bound) =>
                {
                    m.clone()
                }
                _ => candidate.clone(),
            };
            if let Some(m) = &model
                && m.anchor.boot_id == got.anchor.boot_id
            {
                prop_assert!(got.budget_end <= m.budget_end && got.bound <= m.bound);
            }
            prop_assert_eq!(&got, &expected);
            prop_assert_eq!(
                s.transaction(|tx| tx.grant_anchor(&g)).unwrap(),
                Some(expected.clone())
            );
            model = Some(expected);
        }
    }

    /// R1: the persisted high-water mark is the running maximum of accepted times.
    #[test]
    fn high_water_mark_is_the_running_maximum(
        accepted in prop::collection::vec(-100_000i64..100_000, 1..40)
    ) {
        let s = mem();
        let mut max: Option<Timestamp> = None;
        for a in accepted {
            let at = plus(t0(), a);
            let got = s.transaction(|tx| tx.raise_high_water_mark(at)).unwrap();
            max = Some(max.map_or(at, |m| m.max(at)));
            prop_assert_eq!(Some(got), max);
            prop_assert_eq!(s.transaction(|tx| tx.high_water_mark()).unwrap(), max);
        }
    }

    /// R6: the stored residual equals the latest `valid_before` among reserved and
    /// published entries whatever reserve/publish/void sequence ran, and a settled
    /// entry never moves again.
    #[test]
    fn issuance_residual_counts_reserved_and_published_only(
        entries in prop::collection::vec((0u8..3, 1i64..100_000), 0..20)
    ) {
        let s = mem();
        let g = GrantId::from_random_bytes([1; 16]);
        let mut expected: Option<Timestamp> = None;
        for (i, (action, before_s)) in entries.iter().enumerate() {
            let e = issuance(i as u8, &g, plus(t0(), *before_s));
            s.transaction(|tx| tx.reserve_issuance(&e)).unwrap();
            match action {
                0 => {}
                1 => {
                    s.transaction(|tx| tx.publish_issuance(&e.id, t0())).unwrap();
                }
                _ => {
                    s.transaction(|tx| {
                        tx.void_issuance(&e.id, &IssuanceRefusal::BoundPassed, t0())
                    })
                    .unwrap();
                    let r = s.transaction(|tx| tx.publish_issuance(&e.id, t0()));
                    prop_assert!(matches!(r, Err(StoreError::GenerationConflict(_))));
                }
            }
            if *action != 2 {
                expected = expected.max(Some(e.bounds.valid_before));
            }
            prop_assert_eq!(
                s.transaction(|tx| tx.issuance_residual(std::slice::from_ref(&g))).unwrap(),
                expected
            );
        }
        let all = s.transaction(|tx| tx.issuance_entries(&g)).unwrap();
        prop_assert_eq!(all.len(), entries.len());
        prop_assert_eq!(heimdall_domain::issuance::residual(&all), expected);
    }

    /// Retention purge (rulings R2, R7) never deletes tombstones, policies or the
    /// self environment, and removes exactly the settled operations whose
    /// idempotency record was settled with an expiry at or before the purge
    /// instant, leaving a marker for each purged key. Pending keys (open and
    /// `outcome_unknown` operations, or settled ones not yet given an expiry) stay.
    #[test]
    fn purge_keeps_authority_state_and_unexpired_records(
        ops in prop::collection::vec((0u8..7, 0i64..200, 0i64..200, any::<bool>()), 0..20),
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
        let mut expect_marker: BTreeMap<OperationId, Timestamp> = BTreeMap::new();
        let now = plus(t0(), purge_at * 3600);
        s.transaction(|tx| {
            tx.init_self_environment(&env_id(1))?;
            tx.insert_tombstone(&tombstone(1))?;
            tx.upsert_policy(&p, false)?;
            for (i, (state_ix, done_h, expiry_h, settle)) in ops.iter().enumerate() {
                let (mut op, idem) = operation(
                    i as u64 + 1,
                    key(501, &format!("r{i}")),
                    RequestHash([1; 32]),
                    t0(),
                );
                tx.insert_operation(&op, &idem)?;
                let state = states[usize::from(*state_ix)];
                if state != OperationState::Queued {
                    op.state = state;
                    op.updated_at = plus(t0(), done_h * 3600);
                    tx.update_operation(&op)?;
                }
                let expires = plus(t0(), (done_h + expiry_h) * 3600);
                let mut settled_with_expiry = false;
                if *settle {
                    let r = tx.settle_idempotency(&idem.key, expires);
                    if state.is_settled() {
                        r?;
                        settled_with_expiry = true;
                    } else {
                        // Pending keys never get an expiry.
                        assert!(matches!(r, Err(StoreError::GenerationConflict(_))));
                    }
                }
                if settled_with_expiry && expires <= now {
                    expect_marker.insert(op.id.clone(), expires);
                } else {
                    expect_kept.insert(op.id.clone());
                }
            }
            Ok(())
        }).unwrap();
        let gen_before = s.transaction(|tx| tx.authority_generation()).unwrap();
        let removed = s.transaction(|tx| tx.purge_operations_before(now)).unwrap();
        prop_assert_eq!(removed as usize, ops.len() - expect_kept.len());
        s.transaction(|tx| {
            for i in 0..ops.len() {
                let id = op_id(i as u64 + 1);
                let k = key(501, &format!("r{i}"));
                let kept = tx.operation(&id)?.is_some();
                assert_eq!(kept, expect_kept.contains(&id));
                assert_eq!(tx.idempotency_record(&k)?.is_some(), kept);
                let marker = tx.expired_key_marker(&k.hash().unwrap())?;
                match expect_marker.get(&id) {
                    Some(expired_at) => {
                        let m = marker.expect("purged key leaves a marker");
                        assert_eq!(m.expired_at, *expired_at);
                        assert_eq!(m.marker_until, marker_until(*expired_at));
                        // A reuse inside the window is REQUEST_EXPIRED, never new.
                        assert_eq!(
                            classify(None, Some(&m), RequestHash([1; 32]), now),
                            IdempotencyOutcome::Expired
                        );
                    }
                    None => assert_eq!(marker, None),
                }
            }
            assert_eq!(tx.self_environment()?, Some(env_id(1)));
            assert_eq!(tx.policy(&p.id)?, Some(p.clone()));
            assert_eq!(tx.authority_generation()?, gen_before);
            assert!(tx.tombstone(&tombstone(1).grant)?.is_some());
            Ok(())
        }).unwrap();
        // Every meta key is checked at the SQL level by the crate's unit property
        // `purge_never_touches_tombstones_policies_or_meta`.
    }
}
