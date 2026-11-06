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
        cause: heimdall_domain::revocation::RevocationCause::Revoke,
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
        approval: None,
        covered: None,
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

/// ⟨r2.5⟩ ADR-0006 §13.8 item 4: a tombstone carries its cause; an
/// `authority_withdrawn` one round-trips through the store, and the first record
/// for a grant is kept whatever the later one's cause (evidence is never
/// rewritten).
#[test]
fn tombstone_cause_round_trips_and_the_first_record_is_kept() {
    use heimdall_domain::revocation::RevocationCause;
    let s = mem();
    let withdrawn = Tombstone {
        cause: RevocationCause::AuthorityWithdrawn,
        ..tombstone(7)
    };
    let stored = s
        .transaction(|tx| {
            tx.insert_tombstone(&withdrawn)?;
            tx.insert_tombstone(&tombstone(7))?;
            tx.tombstone(&withdrawn.grant)
        })
        .unwrap()
        .unwrap();
    assert_eq!(stored.cause, RevocationCause::AuthorityWithdrawn);
    assert_eq!(stored.grant, withdrawn.grant);
    let explicit = s
        .transaction(|tx| {
            tx.insert_tombstone(&tombstone(8))?;
            tx.tombstone(&tombstone(8).grant)
        })
        .unwrap()
        .unwrap();
    assert_eq!(explicit.cause, RevocationCause::Revoke);
}

#[test]
fn policy_revisions_are_monotonic_and_narrowing_bumps_generation() {
    // ADR-0006 §13.6 item 5: **every** change to a policy (insert, pause, cutoff,
    // narrowing, widening, any new revision) moves the authority generation, so
    // re-validation runs and a reservation made before it is voided at publish.
    let s = mem();
    let p1 = policy(1);
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p1, false)).unwrap(),
        AuthorityGeneration(1),
        "a new applicable policy is a change"
    );
    // Stale or equal revision refused, stored policy and generation intact.
    let e = s
        .transaction(|tx| tx.upsert_policy(&p1, false))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    assert_eq!(
        s.transaction(|tx| tx.authority_generation()).unwrap(),
        AuthorityGeneration(1)
    );
    // Widening without the flag: still a revision change, still a bump.
    let mut p2 = policy(2);
    p2.max_window = Duration::from_secs(24 * 3600);
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p2, false)).unwrap(),
        AuthorityGeneration(2)
    );
    // Pause without the caller's flag bumps.
    let mut p3 = p2.clone();
    p3.revision = PolicyRevision(3);
    p3.pause = PauseState::Paused {
        since: plus(t0(), 10),
    };
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p3, false)).unwrap(),
        AuthorityGeneration(3)
    );
    // Caller-flagged narrowing bumps.
    let mut p4 = p3.clone();
    p4.revision = PolicyRevision(4);
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p4, true)).unwrap(),
        AuthorityGeneration(4)
    );
    // Cutoff set: bump.
    let mut p5 = p4.clone();
    p5.revision = PolicyRevision(5);
    p5.cutoff_at = Some(plus(t0(), 3600));
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p5, false)).unwrap(),
        AuthorityGeneration(5)
    );
    // Cutoff moved later and resume (widening): bump.
    let mut p6 = p5.clone();
    p6.revision = PolicyRevision(6);
    p6.cutoff_at = Some(plus(t0(), 7200));
    p6.pause = PauseState::Active;
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p6, false)).unwrap(),
        AuthorityGeneration(6)
    );
    // Cutoff cleared: bump.
    let mut p7 = p6.clone();
    p7.revision = PolicyRevision(7);
    p7.cutoff_at = None;
    assert_eq!(
        s.transaction(|tx| tx.upsert_policy(&p7, false)).unwrap(),
        AuthorityGeneration(7)
    );
    let stored = s.transaction(|tx| tx.policy(&p7.id)).unwrap();
    assert_eq!(stored, Some(p7));
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
    // Opening a fresh store visits the migration points of every step (0001,
    // 0002, 0003, 0004, 0005) first; then the failed transaction (before
    // transaction, before commit) and the verifying one.
    assert_eq!(
        faults.visited(),
        vec![
            FaultPoint::BeforeMigration,
            FaultPoint::AfterMigration,
            FaultPoint::BeforeMigration,
            FaultPoint::AfterMigration,
            FaultPoint::BeforeMigration,
            FaultPoint::AfterMigration,
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
    assert_eq!(SCHEMA_VERSION, 5);
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
    // The next version (6) is just as foreign.
    let dir = tempfile::tempdir().unwrap();
    let db = corrupt_copy(dir.path(), |b| {
        b[60..64].copy_from_slice(&(SCHEMA_VERSION + 1).to_be_bytes())
    });
    assert_refused_and_untouched(&db, |e| {
        matches!(
            e,
            StoreError::NewerSchema {
                found: 6,
                supported: 5
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

/// ⟨M02⟩ ADR-0007 §12.22 item 10 (W3b-gaps): profile removal deletes the current
/// definition only. Every pinned snapshot stays readable (a grant resolved against it
/// keeps exactly that revision), a second removal reports nothing removed, and the
/// highest revision ever pinned survives the removal, so a later definition of the
/// same ID continues after it and never reuses a revision with other content.
#[test]
fn profile_removal_keeps_pinned_snapshots_and_the_revision_high_water_mark() {
    let s = mem();
    let id = ProfileId::parse("default").unwrap();
    let other = ProfileId::parse("other").unwrap();
    assert_eq!(
        s.transaction(|tx| tx.profile_latest_revision(&id)).unwrap(),
        None,
        "never existed"
    );
    let v1 = profile_def(1, &[("h1", "u1")]);
    let v2 = profile_def(2, &[("h1", "u1"), ("h2", "u1")]);
    s.transaction(|tx| {
        tx.upsert_profile(&v1)?;
        tx.upsert_profile(&v2)
    })
    .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.profile_latest_revision(&id)).unwrap(),
        Some(2)
    );
    // Removing a profile that does not exist removes nothing, and touches no other.
    assert!(!s.transaction(|tx| tx.remove_profile(&other)).unwrap());
    assert!(s.transaction(|tx| tx.remove_profile(&id)).unwrap());
    assert!(
        !s.transaction(|tx| tx.remove_profile(&id)).unwrap(),
        "already removed"
    );
    let (cur, s1, s2, latest) = s
        .transaction(|tx| {
            Ok((
                tx.profile(&id)?,
                tx.profile_snapshot(&id, 1)?,
                tx.profile_snapshot(&id, 2)?,
                tx.profile_latest_revision(&id)?,
            ))
        })
        .unwrap();
    assert_eq!(cur, None, "the definition is gone");
    assert_eq!(s1, Some(v1.snapshot()), "pinned snapshots are kept");
    assert_eq!(s2, Some(v2.snapshot()));
    assert_eq!(latest, Some(2), "the high-water mark survives the removal");
    // Re-creating revision 1 with other content would reuse a pinned revision: refused.
    let reused = profile_def(1, &[("h9", "root")]);
    assert!(matches!(
        s.transaction(|tx| tx.upsert_profile(&reused)),
        Err(StoreError::GenerationConflict(_))
    ));
    // A definition after the high-water mark is accepted, and its snapshot is new.
    let v3 = profile_def(3, &[("h3", "u3")]);
    s.transaction(|tx| tx.upsert_profile(&v3)).unwrap();
    let (cur, s2) = s
        .transaction(|tx| Ok((tx.profile(&id)?, tx.profile_snapshot(&id, 2)?)))
        .unwrap();
    assert_eq!(cur, Some(v3));
    assert_eq!(s2, Some(v2.snapshot()), "an older pin is never rewritten");
    // A failed transaction removes nothing.
    let e = s
        .transaction(|tx| {
            tx.remove_profile(&id)?;
            Err::<(), _>(StoreError::Corrupt("rolled back".into()))
        })
        .unwrap_err();
    assert!(matches!(e, StoreError::Corrupt(_)));
    assert!(s.transaction(|tx| tx.profile(&id)).unwrap().is_some());
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

/// Code review A06: the approval basis an added-authority intent rests on is a
/// fact the intent gains once; it is never replaced or cleared, and an intent
/// stored before the field existed reads back without one.
#[test]
fn recovery_intent_approval_basis_is_add_only() {
    use heimdall_domain::authority::AuthorityDelta;
    use heimdall_domain::operation::ApprovalBasis;
    let s = mem();
    let (op, idem) = simple_op(3);
    s.transaction(|tx| tx.insert_operation(&op, &idem)).unwrap();
    let basis = |n: u8| ApprovalBasis {
        decision: heimdall_contract::ids::DecisionId::from_random_bytes([n; 16]),
        delta: AuthorityDelta {
            added_scope: scope(&[("h3", "u1")], &[]),
            extra_window: None,
            environment_not_covered: false,
        },
        generation: AuthorityGeneration(2),
        policy_revision: Some(PolicyRevision(3)),
    };
    let waiting = RecoveryIntent {
        request: request_doc(3),
        resolved: Some(ResolvedIntent {
            grant: Some(GrantId::from_random_bytes([4; 16])),
            ..resolved_intent()
        }),
        local: None,
    };
    let mut approved = waiting.clone();
    if let Some(r) = approved.resolved.as_mut() {
        r.approval = Some(basis(1));
    }
    let mut replaced = waiting.clone();
    if let Some(r) = replaced.resolved.as_mut() {
        r.approval = Some(basis(2));
    }
    s.transaction(|tx| {
        tx.set_recovery_intent(&op.id, &waiting)?;
        tx.set_recovery_intent(&op.id, &approved)?;
        tx.set_recovery_intent(&op.id, &approved) // repeat: no-op
    })
    .unwrap();
    for bad in [&replaced, &waiting] {
        let e = s
            .transaction(|tx| tx.set_recovery_intent(&op.id, bad))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)));
    }
    assert_eq!(
        s.transaction(|tx| tx.recovery_intent(&op.id)).unwrap(),
        Some(approved)
    );
    // An intent written before the field existed has no approval basis.
    let mut old = serde_json::to_value(resolved_intent()).unwrap();
    assert!(
        old.get("approval").is_none(),
        "absent, not null, when unset"
    );
    old.as_object_mut().unwrap().remove("approval");
    let back: ResolvedIntent = serde_json::from_value(old).unwrap();
    assert_eq!(back.approval, None);
}

#[test]
fn recovery_intent_round_trips_and_only_gains_facts() {
    let s = mem();
    let (op, idem) = simple_op(1);
    s.transaction(|tx| tx.insert_operation(&op, &idem)).unwrap();
    let bare = RecoveryIntent {
        request: request_doc(1),
        resolved: None,
        local: None,
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
        local: None,
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
            local: None,
        },
        StageReceipt {
            stage: "prepare".into(),
            recorded_at: plus(t0(), 2),
            effect: EffectReceipt::Attempted {
                adapter: adapter(),
                effect_token: "tok-1".into(),
            },
            local: None,
        },
        // Same instant as the previous one: order still follows append order.
        StageReceipt {
            stage: "prepare".into(),
            recorded_at: plus(t0(), 2),
            effect: EffectReceipt::Confirmed {
                adapter: adapter(),
                credential_ref: "cred-ref-1".into(),
            },
            local: None,
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
        local: None,
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
        local: None,
    };
    let intent = RecoveryIntent {
        request: request_doc(2),
        resolved: Some(resolved_intent()),
        local: None,
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
                local: None,
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

// --- ADR-0006 §13.7 (M01-rulings-13-7-G1) ----------------------------------------

/// §13.7 item 5: every accepted environment write advances the authority generation
/// in its own transaction (as policy writes do, §13.6 item 5), so a change in
/// environment permissions triggers re-validation; a failed write moves nothing.
#[test]
fn upsert_environment_advances_the_authority_generation_on_every_write() {
    let s = mem();
    let e7 = environment(7, "laptop");
    let g0 = s.transaction(|tx| tx.authority_generation()).unwrap();
    s.transaction(|tx| tx.upsert_environment(&e7)).unwrap();
    let g1 = s.transaction(|tx| tx.authority_generation()).unwrap();
    assert_eq!(g1, g0.next(), "insert");
    let mut changed = e7.clone();
    changed.permissions.automatic_activation = true;
    s.transaction(|tx| tx.upsert_environment(&changed)).unwrap();
    let g2 = s.transaction(|tx| tx.authority_generation()).unwrap();
    assert_eq!(g2, g1.next(), "a permission change");
    s.transaction(|tx| tx.upsert_environment(&changed)).unwrap();
    let g3 = s.transaction(|tx| tx.authority_generation()).unwrap();
    assert_eq!(g3, g2.next(), "every accepted write, even an identical one");
    // A write rolled back with its transaction moves nothing.
    let r: Result<(), StoreError> = s.transaction(|tx| {
        tx.upsert_environment(&e7)?;
        Err(StoreError::GenerationConflict("rolled back".into()))
    });
    assert!(r.is_err());
    assert_eq!(s.transaction(|tx| tx.authority_generation()).unwrap(), g3);
    assert_eq!(
        s.transaction(|tx| tx.environment(&e7.id)).unwrap(),
        Some(changed)
    );
}

fn approval_basis(n: u8) -> heimdall_domain::operation::ApprovalBasis {
    heimdall_domain::operation::ApprovalBasis {
        decision: DecisionId::from_random_bytes([n; 16]),
        delta: heimdall_domain::authority::AuthorityDelta {
            added_scope: scope(&[("h3", "u1")], &[]),
            extra_window: None,
            environment_not_covered: false,
        },
        generation: AuthorityGeneration(2),
        policy_revision: Some(PolicyRevision(3)),
    }
}

/// §13.7 item 3: the approval basis is persisted with the grant, written once, and
/// survives the retention purge of the approving operation and its recovery intent;
/// state updates of the grant leave it alone.
#[test]
fn grant_approval_is_written_once_and_survives_operation_purge() {
    let s = mem();
    let g = GrantSnapshot {
        source: AuthorizationSource::OwnerDecision {
            operation_id: op_id(3),
        },
        ..grant(1, None, plus(t0(), 7200), GrantState::Preparing)
    };
    let (mut op, idem) = simple_op(3);
    s.transaction(|tx| {
        tx.insert_grant(&g)?;
        tx.insert_operation(&op, &idem)?;
        let mut intent = RecoveryIntent {
            request: request_doc(3),
            resolved: Some(ResolvedIntent {
                grant: Some(g.id.clone()),
                ..resolved_intent()
            }),
            local: None,
        };
        if let Some(r) = intent.resolved.as_mut() {
            r.approval = Some(approval_basis(1));
        }
        tx.set_recovery_intent(&op.id, &intent)?;
        assert_eq!(tx.grant_approval(&g.id)?, None);
        tx.set_grant_approval(&g.id, &approval_basis(1))?;
        tx.set_grant_approval(&g.id, &approval_basis(1)) // repeat: no-op
    })
    .unwrap();
    let e = s
        .transaction(|tx| tx.set_grant_approval(&g.id, &approval_basis(2)))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    let e = s
        .transaction(|tx| {
            tx.set_grant_approval(&GrantId::from_random_bytes([77; 16]), &approval_basis(1))
        })
        .unwrap_err();
    assert!(matches!(e, StoreError::Sqlite(_)));
    // A state update keeps the basis; the grant record itself is unchanged.
    let mut active = g.clone();
    active.state = GrantState::Active;
    s.transaction(|tx| tx.update_grant_state(&active)).unwrap();
    // Settle and purge the approving operation (its intent goes with it).
    succeed(&mut op, plus(t0(), 10));
    s.transaction(|tx| {
        tx.update_operation(&op)?;
        tx.settle_idempotency(&op.key, retention_expiry(plus(t0(), 10), DEFAULT_RETENTION))
    })
    .unwrap();
    let purged = s
        .transaction(|tx| tx.purge_operations_before(plus(t0(), 400 * 86_400)))
        .unwrap();
    assert_eq!(purged, 1);
    let (intent, basis, stored) = s
        .transaction(|tx| {
            Ok((
                tx.recovery_intent(&op.id)?,
                tx.grant_approval(&g.id)?,
                tx.grant(&g.id)?,
            ))
        })
        .unwrap();
    assert_eq!(intent, None, "the recovery intent went with its operation");
    assert_eq!(
        basis,
        Some(approval_basis(1)),
        "the basis stays with the grant"
    );
    assert_eq!(stored, Some(active));
}

/// §13.7 item 4: ownership of a waiting owner-decision grant moves by
/// compare-and-swap on the expected owner, only while the grant waits.
#[test]
fn transfer_waiting_grant_is_a_cas_on_the_owner_while_waiting() {
    let s = mem();
    let waiting = GrantSnapshot {
        source: AuthorizationSource::OwnerDecision {
            operation_id: op_id(1),
        },
        ..grant(1, None, plus(t0(), 7200), GrantState::AwaitingApproval)
    };
    let standing = grant(2, None, plus(t0(), 7200), GrantState::AwaitingApproval);
    s.transaction(|tx| {
        tx.insert_grant(&waiting)?;
        tx.insert_grant(&standing)
    })
    .unwrap();
    s.transaction(|tx| tx.transfer_waiting_grant(&waiting.id, &op_id(1), &op_id(2)))
        .unwrap();
    let moved = s.transaction(|tx| tx.grant(&waiting.id)).unwrap().unwrap();
    assert_eq!(
        moved.source,
        AuthorizationSource::OwnerDecision {
            operation_id: op_id(2)
        }
    );
    assert_eq!(
        GrantSnapshot {
            source: waiting.source.clone(),
            ..moved.clone()
        },
        waiting,
        "only the owner changed"
    );
    // A stale expectation, a non-owner-decision source, and a grant that left
    // the decision stage are refused and change nothing.
    for (gid, from) in [(&waiting.id, op_id(1)), (&standing.id, op_id(1))] {
        let e = s
            .transaction(|tx| tx.transfer_waiting_grant(gid, &from, &op_id(9)))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)));
    }
    let mut preparing = moved.clone();
    preparing.state = GrantState::Preparing;
    s.transaction(|tx| tx.update_grant_state(&preparing))
        .unwrap();
    let e = s
        .transaction(|tx| tx.transfer_waiting_grant(&waiting.id, &op_id(2), &op_id(3)))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    assert_eq!(
        s.transaction(|tx| tx.grant(&waiting.id)).unwrap(),
        Some(preparing)
    );
    let e = s
        .transaction(|tx| {
            tx.transfer_waiting_grant(&GrantId::from_random_bytes([77; 16]), &op_id(1), &op_id(2))
        })
        .unwrap_err();
    assert!(matches!(e, StoreError::Sqlite(_)));
}

/// §13.7 items 2 and 4: a pending approval record moves to another waiting
/// operation (same ID, delta, generation and expiry; still pending) by CAS, and a
/// withdrawn record is no longer pending and can never be completed.
#[test]
fn decisions_transfer_and_withdraw_by_cas_on_pending() {
    let s = mem();
    let approval = |b: u8, op: u64| DecisionRecord {
        kind: DecisionKind::ApproveAuthority {
            operation: op_id(op),
            delta: approval_basis(b).delta,
        },
        ..decision(b, 0)
    };
    let a = approval(1, 1);
    let widen = decision(2, 0);
    s.transaction(|tx| {
        tx.insert_decision(&a)?;
        tx.insert_decision(&widen)
    })
    .unwrap();
    let moved = s
        .transaction(|tx| tx.transfer_decision(&a.id, &op_id(1), &op_id(2)))
        .unwrap();
    assert_eq!(
        moved,
        DecisionRecord {
            kind: DecisionKind::ApproveAuthority {
                operation: op_id(2),
                delta: approval_basis(1).delta,
            },
            ..a.clone()
        }
    );
    assert_eq!(
        s.transaction(|tx| tx.decision(&a.id)).unwrap(),
        Some(moved.clone())
    );
    for (id, from) in [(&a.id, op_id(1)), (&widen.id, op_id(1))] {
        let e = s
            .transaction(|tx| tx.transfer_decision(id, &from, &op_id(3)))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)));
    }
    let withdrawn = s.transaction(|tx| tx.withdraw_decision(&a.id)).unwrap();
    assert_eq!(withdrawn.state, DecisionState::Withdrawn);
    assert_eq!(withdrawn.decided_at, None, "no verdict");
    let (pending, stored) = s
        .transaction(|tx| Ok((tx.pending_decisions()?, tx.decision(&a.id)?)))
        .unwrap();
    assert_eq!(pending, vec![widen.clone()]);
    assert_eq!(stored, Some(withdrawn.clone()));
    // Never completable, never withdrawn or moved again.
    let done = s
        .transaction(|tx| tx.complete_decision(&a.id, Verdict::Approve, plus(t0(), 1)))
        .unwrap();
    assert!(matches!(done, DecisionCompletion::Refused { .. }));
    for r in [
        s.transaction(|tx| tx.withdraw_decision(&a.id).map(|_| ())),
        s.transaction(|tx| {
            tx.transfer_decision(&a.id, &op_id(2), &op_id(3))
                .map(|_| ())
        }),
    ] {
        assert!(matches!(r, Err(StoreError::GenerationConflict(_))));
    }
    assert_eq!(
        s.transaction(|tx| tx.decision(&a.id)).unwrap(),
        Some(withdrawn)
    );
    let e = s
        .transaction(|tx| tx.withdraw_decision(&DecisionId::from_random_bytes([77; 16])))
        .unwrap_err();
    assert!(matches!(e, StoreError::Sqlite(_)));
}

/// §13.7 item 2: the covered basis of a recovery intent is add-only, like the
/// approval basis, and absent (not null) when unset.
#[test]
fn recovery_intent_covered_basis_is_add_only() {
    use heimdall_domain::operation::CoveredBasis;
    let s = mem();
    let (op, idem) = simple_op(5);
    s.transaction(|tx| tx.insert_operation(&op, &idem)).unwrap();
    let waiting = RecoveryIntent {
        request: request_doc(5),
        resolved: Some(ResolvedIntent {
            grant: Some(GrantId::from_random_bytes([4; 16])),
            ..resolved_intent()
        }),
        local: None,
    };
    let with = |g: u64| {
        let mut i = waiting.clone();
        if let Some(r) = i.resolved.as_mut() {
            r.covered = Some(CoveredBasis {
                generation: AuthorityGeneration(g),
                policy_revision: Some(PolicyRevision(2)),
            });
        }
        i
    };
    s.transaction(|tx| {
        tx.set_recovery_intent(&op.id, &waiting)?;
        tx.set_recovery_intent(&op.id, &with(4))?;
        tx.set_recovery_intent(&op.id, &with(4))
    })
    .unwrap();
    for bad in [with(5), waiting.clone()] {
        let e = s
            .transaction(|tx| tx.set_recovery_intent(&op.id, &bad))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)));
    }
    assert_eq!(
        s.transaction(|tx| tx.recovery_intent(&op.id)).unwrap(),
        Some(with(4))
    );
    let doc = serde_json::to_value(resolved_intent()).unwrap();
    assert!(doc.get("covered").is_none(), "absent, not null, when unset");
}

// --- ⟨r2.6⟩ ADR-0006 §13.9 items 2 and 3 (M01-rulings-13-9-J1) ---------------------

fn grant_origin(revision: u64) -> heimdall_domain::grant::GrantOrigin {
    heimdall_domain::grant::GrantOrigin {
        profile: ProfileId::parse("dev").unwrap(),
        profile_revision: revision,
        policy_revision: Some(PolicyRevision(2)),
        caller: caller(501),
        mechanism: "fake_agent".into(),
        covered: None,
        adapter: None,
    }
}

/// §13.9 item 2: the origin is persisted with the grant row, written once (the same
/// origin again is a no-op, another one conflicts), gains a covered basis only
/// add-only, survives state updates, and a grant without one reads `None`.
#[test]
fn grant_origin_is_written_once_and_gains_only_a_covered_basis() {
    let s = mem();
    let g = grant(1, None, plus(t0(), 7200), GrantState::Preparing);
    let bare = grant(2, None, plus(t0(), 7200), GrantState::Active);
    let covered = heimdall_domain::operation::CoveredBasis {
        generation: AuthorityGeneration(4),
        policy_revision: Some(PolicyRevision(3)),
    };
    s.transaction(|tx| {
        tx.insert_grant(&g)?;
        tx.insert_grant(&bare)?;
        assert_eq!(tx.grant_origin(&g.id)?, None);
        tx.set_grant_origin(&g.id, &grant_origin(1))?;
        tx.set_grant_origin(&g.id, &grant_origin(1)) // repeat: no-op
    })
    .unwrap();
    let e = s
        .transaction(|tx| tx.set_grant_origin(&g.id, &grant_origin(2)))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    let e = s
        .transaction(|tx| {
            tx.set_grant_origin(&GrantId::from_random_bytes([77; 16]), &grant_origin(1))
        })
        .unwrap_err();
    assert!(matches!(e, StoreError::Sqlite(_)));
    // Add-only: the covered basis may be added once, never replaced or cleared.
    s.transaction(|tx| {
        assert!(tx.set_grant_covered(&g.id, &covered)?);
        assert!(tx.set_grant_covered(&g.id, &covered)?, "same basis: no-op");
        assert!(
            !tx.set_grant_covered(&bare.id, &covered)?,
            "no origin to add to"
        );
        Ok(())
    })
    .unwrap();
    let other = heimdall_domain::operation::CoveredBasis {
        generation: AuthorityGeneration(5),
        ..covered.clone()
    };
    let e = s
        .transaction(|tx| tx.set_grant_covered(&g.id, &other))
        .unwrap_err();
    assert!(matches!(e, StoreError::GenerationConflict(_)));
    let e = s
        .transaction(|tx| tx.set_grant_origin(&g.id, &grant_origin(1)))
        .unwrap_err();
    assert!(
        matches!(e, StoreError::GenerationConflict(_)),
        "clearing the covered basis is refused"
    );
    let mut active = g.clone();
    active.state = GrantState::Active;
    s.transaction(|tx| tx.update_grant_state(&active)).unwrap();
    let (origin, none, stored) = s
        .transaction(|tx| {
            Ok((
                tx.grant_origin(&g.id)?,
                tx.grant_origin(&bare.id)?,
                tx.grant(&g.id)?,
            ))
        })
        .unwrap();
    let mut expected = grant_origin(1);
    expected.covered = Some(covered);
    assert_eq!(origin, Some(expected));
    assert_eq!(none, None);
    assert_eq!(stored.map(|g| g.state), Some(GrantState::Active));
}

/// ⟨r2.10⟩ ADR-0006 §13.13 item 1: the preparing adapter (mechanism and instance)
/// is added to a recorded origin once, add-only like the covered basis: the same
/// identity again is a no-op, another identity or clearing it conflicts, the two
/// optional fields are added independently (in either order), and the adapter
/// survives operation retention (it lives in the grant row).
#[test]
fn grant_origin_gains_its_preparing_adapter_once() {
    let s = mem();
    let g = grant(3, None, plus(t0(), 7200), GrantState::Preparing);
    let prepared = adapter();
    let with_adapter = heimdall_domain::grant::GrantOrigin {
        adapter: Some(prepared.clone()),
        ..grant_origin(1)
    };
    s.transaction(|tx| {
        tx.insert_grant(&g)?;
        tx.set_grant_origin(&g.id, &grant_origin(1))?;
        tx.set_grant_origin(&g.id, &with_adapter)?;
        tx.set_grant_origin(&g.id, &with_adapter) // repeat: no-op
    })
    .unwrap();
    let other = heimdall_domain::grant::GrantOrigin {
        adapter: Some(heimdall_domain::operation::AdapterIdentity {
            instance: "fixture-9".into(),
            ..prepared.clone()
        }),
        ..grant_origin(1)
    };
    for (bad, why) in [
        (&other, "another identity is refused"),
        (&grant_origin(1), "clearing the adapter is refused"),
    ] {
        let e = s
            .transaction(|tx| tx.set_grant_origin(&g.id, bad))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)), "{why}");
    }
    let covered = heimdall_domain::operation::CoveredBasis {
        generation: AuthorityGeneration(4),
        policy_revision: Some(PolicyRevision(3)),
    };
    s.transaction(|tx| {
        assert!(
            tx.set_grant_covered(&g.id, &covered)?,
            "the covered basis is added too"
        );
        Ok(())
    })
    .unwrap();
    let far = plus(t0(), 400 * 86_400);
    let origin = s
        .transaction(|tx| {
            tx.purge_operations_before(far)?;
            tx.grant_origin(&g.id)
        })
        .unwrap()
        .unwrap();
    assert_eq!(origin.adapter, Some(prepared.clone()));
    assert_eq!(origin.covered, Some(covered.clone()));
    // The other order: covered first, then the adapter.
    let h = grant(4, None, plus(t0(), 7200), GrantState::Preparing);
    s.transaction(|tx| {
        tx.insert_grant(&h)?;
        tx.set_grant_origin(&h.id, &grant_origin(1))?;
        assert!(tx.set_grant_covered(&h.id, &covered)?);
        tx.set_grant_origin(
            &h.id,
            &heimdall_domain::grant::GrantOrigin {
                covered: Some(covered.clone()),
                ..with_adapter.clone()
            },
        )?;
        assert_eq!(
            tx.grant_origin(&h.id)?.and_then(|o| o.adapter),
            Some(prepared.clone())
        );
        Ok(())
    })
    .unwrap();
}

/// §13.9 item 3: the completion report of a withdrawal is recorded once per
/// tombstoned root (`true` the first time only) and needs the root's tombstone.
#[test]
fn withdrawal_report_is_recorded_once_per_tombstoned_root() {
    let s = mem();
    let t = tombstone(9);
    s.transaction(|tx| {
        tx.insert_tombstone(&t)?;
        assert!(!tx.withdrawal_reported(&t.grant)?);
        assert!(tx.record_withdrawal_report(&t.grant)?);
        assert!(!tx.record_withdrawal_report(&t.grant)?);
        assert!(tx.withdrawal_reported(&t.grant)?);
        Ok(())
    })
    .unwrap();
    let e = s
        .transaction(|tx| tx.record_withdrawal_report(&GrantId::from_random_bytes([8; 16])))
        .unwrap_err();
    assert!(matches!(e, StoreError::Sqlite(_)));
    // A failed transaction records nothing.
    let other = tombstone(10);
    let _ = s.transaction(|tx| {
        tx.insert_tombstone(&other)?;
        tx.record_withdrawal_report(&other.grant)?;
        Err::<(), _>(StoreError::Corrupt("abort".into()))
    });
    assert!(
        !s.transaction(|tx| tx.withdrawal_reported(&other.grant))
            .unwrap()
    );
}

// --- ⟨r2.7⟩ ADR-0006 §13.10 items 2 and 3 (M01-rulings-13-10-K1) -----------------

/// §13.10 item 2: a degradation reason is recorded only for a `degraded` grant and
/// exists only while it stays `degraded` (any other state written removes it in
/// the same transaction; returning to `degraded` does not bring it back).
#[test]
fn grant_degradation_exists_only_while_the_grant_is_degraded() {
    use heimdall_domain::grant::DegradedReason;
    let s = mem();
    let mut g = grant(41, None, plus(t0(), 3600), GrantState::Active);
    let reason = DegradedReason::MechanismUnavailable;
    s.transaction(|tx| {
        tx.insert_grant(&g)?;
        assert!(matches!(
            tx.set_grant_degradation(&g.id, reason),
            Err(StoreError::GenerationConflict(_))
        ));
        assert_eq!(tx.grant_degradation(&g.id)?, None);
        Ok(())
    })
    .unwrap();
    let missing = s
        .transaction(|tx| tx.set_grant_degradation(&GrantId::from_random_bytes([42; 16]), reason))
        .unwrap_err();
    assert!(matches!(missing, StoreError::Sqlite(_)));
    g.state = GrantState::Degraded;
    s.transaction(|tx| {
        tx.update_grant_state(&g)?;
        tx.set_grant_degradation(&g.id, reason)?;
        tx.set_grant_degradation(&g.id, reason)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.grant_degradation(&g.id)).unwrap(),
        Some(reason)
    );
    // A failed transaction removes nothing.
    let mut active = g.clone();
    active.state = GrantState::Active;
    let _ = s.transaction(|tx| {
        tx.update_grant_state(&active)?;
        Err::<(), _>(StoreError::Corrupt("abort".into()))
    });
    assert_eq!(
        s.transaction(|tx| tx.grant_degradation(&g.id)).unwrap(),
        Some(reason)
    );
    s.transaction(|tx| tx.update_grant_state(&active)).unwrap();
    assert_eq!(
        s.transaction(|tx| tx.grant_degradation(&g.id)).unwrap(),
        None
    );
    s.transaction(|tx| tx.update_grant_state(&g)).unwrap();
    assert_eq!(
        s.transaction(|tx| tx.grant_degradation(&g.id)).unwrap(),
        None,
        "re-entering degraded needs a fresh reason"
    );
    s.transaction(|tx| tx.set_grant_degradation(&g.id, reason))
        .unwrap();
    let mut expired = g.clone();
    expired.state = GrantState::Expired;
    s.transaction(|tx| tx.update_grant_state(&expired)).unwrap();
    assert_eq!(
        s.transaction(|tx| tx.grant_degradation(&g.id)).unwrap(),
        None
    );
}

/// §13.10 item 3: a pending remote revocation is recorded per tombstoned root,
/// replaced by a later record for that root, listed in root order, cleared
/// idempotently; a root without a tombstone or a record naming no grant is refused.
#[test]
fn remote_revocation_records_need_a_tombstone_and_round_trip() {
    use heimdall_domain::revocation::PendingRemoteRevocation;
    let s = mem();
    let record = |b: u8, attempts: u32, stopped: bool| PendingRemoteRevocation {
        root: GrantId::from_random_bytes([b; 16]),
        grants: vec![GrantId::from_random_bytes([b; 16])],
        attempts,
        last_attempt_at: plus(t0(), i64::from(attempts)),
        stopped,
        obligations: Vec::new(),
        claimed_at: None,
        rearmed_effects: Vec::new(),
        cap: None,
        claim_seq: None,
    };
    let untombstoned = s
        .transaction(|tx| tx.set_remote_revocation(&record(51, 1, false)))
        .unwrap_err();
    assert!(matches!(untombstoned, StoreError::Sqlite(_)));
    s.transaction(|tx| {
        tx.insert_tombstone(&tombstone(51))?;
        tx.insert_tombstone(&tombstone(52))?;
        let empty = PendingRemoteRevocation {
            grants: Vec::new(),
            ..record(51, 1, false)
        };
        assert!(matches!(
            tx.set_remote_revocation(&empty),
            Err(StoreError::GenerationConflict(_))
        ));
        assert!(tx.remote_revocations()?.is_empty());
        tx.set_remote_revocation(&record(52, 1, false))?;
        tx.set_remote_revocation(&record(51, 1, false))?;
        tx.set_remote_revocation(&record(51, 3, true))?;
        Ok(())
    })
    .unwrap();
    let r51 = GrantId::from_random_bytes([51; 16]);
    assert_eq!(
        s.transaction(|tx| tx.remote_revocation(&r51)).unwrap(),
        Some(record(51, 3, true))
    );
    let all = s.transaction(|tx| tx.remote_revocations()).unwrap();
    let mut roots: Vec<GrantId> = all.iter().map(|r| r.root.clone()).collect();
    assert_eq!(all.len(), 2);
    let listed = roots.clone();
    roots.sort();
    assert_eq!(listed, roots, "ordered by root");
    s.transaction(|tx| {
        tx.clear_remote_revocation(&r51)?;
        tx.clear_remote_revocation(&r51)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.remote_revocation(&r51)).unwrap(),
        None
    );
    assert_eq!(
        s.transaction(|tx| tx.remote_revocations()).unwrap().len(),
        1
    );
}

/// ⟨r2.9⟩ ADR-0006 §13.12 item 2: a pending remote record carrying per-adapter
/// obligations must name exactly their grants in `grants`; it round-trips with its
/// obligations, their reasons and its claim; a record without obligations (the
/// pre-§13.12 shape) is still accepted and reads back without them. ⟨r2.15⟩ The
/// stored cap and each obligation's recorded effect round round-trip too
/// (ADR-0006 §13.18 items 2 and 3). ⟨r2.16⟩ So do the claim sequence and each
/// obligation's recorded effect sequence (§13.19 item 1).
#[test]
fn remote_revocation_obligations_name_exactly_the_record_grants() {
    use heimdall_domain::revocation::{
        PendingRemoteRevocation, RemoteObligation, RemotePendingReason,
    };
    let s = mem();
    let root = GrantId::from_random_bytes([61; 16]);
    let child = GrantId::from_random_bytes([62; 16]);
    let owe = |g: &GrantId, reason| RemoteObligation {
        grant: g.clone(),
        adapter: adapter(),
        reason,
        attempts: Some(2),
        stopped: false,
        effect_round: Some(1),
        effect_seq: Some(4),
    };
    let record = PendingRemoteRevocation {
        root: root.clone(),
        grants: vec![root.clone(), child.clone()],
        attempts: 2,
        last_attempt_at: plus(t0(), 2),
        stopped: false,
        obligations: vec![
            owe(&root, None),
            owe(&child, Some(RemotePendingReason::AdapterUnavailable)),
        ],
        claimed_at: Some(plus(t0(), 2)),
        rearmed_effects: Vec::new(),
        cap: Some(3),
        claim_seq: Some(5),
    };
    s.transaction(|tx| {
        tx.insert_tombstone(&tombstone(61))?;
        tx.set_remote_revocation(&record)
    })
    .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.remote_revocation(&root)).unwrap(),
        Some(record.clone())
    );
    for bad in [
        PendingRemoteRevocation {
            grants: vec![root.clone()],
            ..record.clone()
        },
        PendingRemoteRevocation {
            obligations: vec![owe(&root, None)],
            ..record.clone()
        },
    ] {
        let e = s
            .transaction(|tx| tx.set_remote_revocation(&bad))
            .unwrap_err();
        assert!(matches!(e, StoreError::GenerationConflict(_)), "{e:?}");
    }
    let legacy = PendingRemoteRevocation {
        obligations: Vec::new(),
        claimed_at: None,
        ..record.clone()
    };
    s.transaction(|tx| tx.set_remote_revocation(&legacy))
        .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.remote_revocation(&root)).unwrap(),
        Some(legacy)
    );
}

/// ⟨r2.9⟩ ADR-0006 §13.12 item 2: `grant_adapters` reads the adapter identities
/// recorded for a grant by the recovery intents that pin it and by those
/// operations' stage receipts, each once; an intent pinning another grant, a
/// `NotAttempted` receipt and a grant nothing pins contribute nothing.
#[test]
fn grant_adapters_come_from_the_intents_and_receipts_that_pin_the_grant() {
    let s = mem();
    let g = GrantId::from_random_bytes([71; 16]);
    let other_grant = GrantId::from_random_bytes([72; 16]);
    let second = AdapterIdentity {
        mechanism: "fake".into(),
        instance: "fake-2".into(),
    };
    let foreign = AdapterIdentity {
        mechanism: "fake_other".into(),
        instance: "x".into(),
    };
    let pinned = |grant: &GrantId, a: AdapterIdentity, n: u64| RecoveryIntent {
        request: request_doc(n),
        resolved: Some(ResolvedIntent {
            grant: Some(grant.clone()),
            adapter: Some(a),
            ..resolved_intent()
        }),
        local: None,
    };
    let (op1, i1) = simple_op(11);
    let (op2, i2) = simple_op(12);
    let (op3, i3) = simple_op(13);
    s.transaction(|tx| {
        tx.insert_operation(&op1, &i1)?;
        tx.insert_operation(&op2, &i2)?;
        tx.insert_operation(&op3, &i3)?;
        tx.set_recovery_intent(&op1.id, &pinned(&g, adapter(), 11))?;
        tx.append_stage_receipt(
            &op1.id,
            &StageReceipt {
                stage: "prepare".into(),
                recorded_at: plus(t0(), 1),
                effect: EffectReceipt::NotAttempted,
                local: None,
            },
        )?;
        tx.append_stage_receipt(
            &op1.id,
            &StageReceipt {
                stage: "prepare".into(),
                recorded_at: plus(t0(), 2),
                effect: EffectReceipt::Confirmed {
                    adapter: adapter(),
                    credential_ref: "cred-ref-1".into(),
                },
                local: None,
            },
        )?;
        tx.set_recovery_intent(&op2.id, &pinned(&g, adapter(), 12))?;
        tx.append_stage_receipt(
            &op2.id,
            &StageReceipt {
                stage: "prepare".into(),
                recorded_at: plus(t0(), 3),
                effect: EffectReceipt::Uncertain {
                    adapter: second.clone(),
                    effect_token: "tok-2".into(),
                },
                local: None,
            },
        )?;
        tx.set_recovery_intent(&op3.id, &pinned(&other_grant, foreign.clone(), 13))?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.grant_adapters(&g)).unwrap(),
        vec![adapter(), second]
    );
    assert_eq!(
        s.transaction(|tx| tx.grant_adapters(&other_grant)).unwrap(),
        vec![foreign]
    );
    assert!(
        s.transaction(|tx| tx.grant_adapters(&GrantId::from_random_bytes([73; 16])))
            .unwrap()
            .is_empty()
    );
}

/// ⟨r2.11⟩ ADR-0006 §13.14 item 2: `grant_has_effect_receipt` is `true` only for a
/// grant pinned by an operation with an `Attempted`, `Confirmed` or `Uncertain`
/// receipt; a `NotAttempted` receipt, an intent with no receipt, another grant's
/// receipts and a grant nothing pins give `false`.
#[test]
fn grant_has_effect_receipt_reads_only_the_effects_of_the_operations_pinning_it() {
    let s = mem();
    let grants: Vec<GrantId> = (81u8..=86)
        .map(|b| GrantId::from_random_bytes([b; 16]))
        .collect();
    let effects = [
        Some(EffectReceipt::Attempted {
            adapter: adapter(),
            effect_token: "tok-a".into(),
        }),
        Some(EffectReceipt::Confirmed {
            adapter: adapter(),
            credential_ref: "cred-ref-c".into(),
        }),
        Some(EffectReceipt::Uncertain {
            adapter: adapter(),
            effect_token: "tok-u".into(),
        }),
        Some(EffectReceipt::NotAttempted),
        None,
    ];
    s.transaction(|tx| {
        for (n, (g, effect)) in grants.iter().zip(effects.iter()).enumerate() {
            let (op, i) = simple_op(21 + n as u64);
            tx.insert_operation(&op, &i)?;
            tx.set_recovery_intent(
                &op.id,
                &RecoveryIntent {
                    request: request_doc(21 + n as u64),
                    resolved: Some(ResolvedIntent {
                        grant: Some(g.clone()),
                        adapter: Some(adapter()),
                        ..resolved_intent()
                    }),
                    local: None,
                },
            )?;
            if let Some(effect) = effect {
                tx.append_stage_receipt(
                    &op.id,
                    &StageReceipt {
                        stage: "reconcile".into(),
                        recorded_at: plus(t0(), 1),
                        effect: effect.clone(),
                        local: None,
                    },
                )?;
            }
        }
        Ok(())
    })
    .unwrap();
    let has = |g: &GrantId| s.transaction(|tx| tx.grant_has_effect_receipt(g)).unwrap();
    assert!(has(&grants[0]), "attempted");
    assert!(has(&grants[1]), "confirmed (applied)");
    assert!(has(&grants[2]), "uncertain");
    assert!(!has(&grants[3]), "not attempted");
    assert!(!has(&grants[4]), "an intent without a receipt");
    assert!(!has(&grants[5]), "a grant nothing pins");
}

/// ⟨r2.16⟩ ADR-0006 §13.19 item 2: cleanup intents are meta rows kept per (grant,
/// operation). A later intent for the same pair replaces the earlier one. Every
/// write gets a version greater than every earlier one, also after a removal, so a
/// processor can tell the intent it processed from a newer one. They list in key
/// order, clear idempotently, and survive a reopen of a file store (no migration;
/// the schema version is unchanged). Neither a tombstone nor the operation's row is
/// needed: an intent outlives its operation.
#[test]
fn r1319_cleanup_intents_are_kept_per_grant_and_operation_with_increasing_versions() {
    use heimdall_domain::revocation::CleanupIntent;
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    let g1 = GrantId::from_random_bytes([81; 16]);
    let g2 = GrantId::from_random_bytes([82; 16]);
    let op = OperationId::from_random_bytes([83; 16]);
    let intent = |g: &GrantId, confirmed: bool| CleanupIntent {
        grant: g.clone(),
        operation: op.clone(),
        adapter: Some(adapter()),
        effect_token: "eff_1".into(),
        confirmed,
        in_flight: !confirmed,
        version: 0,
        recorded_at: t0(),
    };
    let (a, b, c) = {
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        s.transaction(|tx| {
            assert!(tx.cleanup_intents()?.is_empty());
            let a = tx.record_cleanup_intent(&intent(&g1, false))?;
            let b = tx.record_cleanup_intent(&intent(&g2, true))?;
            let c = tx.record_cleanup_intent(&intent(&g1, true))?;
            Ok((a, b, c))
        })
        .unwrap()
    };
    assert!(
        a.version < b.version && b.version < c.version,
        "{a:?} {b:?} {c:?}"
    );
    assert_eq!(
        c,
        CleanupIntent {
            version: c.version,
            ..intent(&g1, true)
        }
    );
    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(
        s.transaction(|tx| tx.cleanup_intent(&g1, &op)).unwrap(),
        Some(c.clone()),
        "the later intent replaced the earlier one, and survives a reopen"
    );
    let all = s.transaction(|tx| tx.cleanup_intents()).unwrap();
    assert_eq!(all.len(), 2);
    let mut grants: Vec<GrantId> = all.iter().map(|i| i.grant.clone()).collect();
    let listed = grants.clone();
    grants.sort();
    assert_eq!(listed, grants, "ordered by grant");
    s.transaction(|tx| {
        tx.clear_cleanup_intent(&g1, &op)?;
        tx.clear_cleanup_intent(&g1, &op)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        s.transaction(|tx| tx.cleanup_intent(&g1, &op)).unwrap(),
        None
    );
    assert_eq!(s.transaction(|tx| tx.cleanup_intents()).unwrap(), vec![b]);
    let d = s
        .transaction(|tx| tx.record_cleanup_intent(&intent(&g1, false)))
        .unwrap();
    assert!(d.version > c.version, "a version is never reused");
}

// --- ⟨M02⟩ existing access: migration 0005, read-only open, catalog, declarations,
// --- projection records and atomic setup admission (m02-plan U0 Tests, §5 items
// --- 17a and 18; U0b rows 16, 20 and 23) ----------------------------------------------

mod m02 {
    use super::*;
    use heimdall_contract::catalog::DeclaredInteraction;
    use heimdall_contract::ids::IdentityId;
    use heimdall_contract::provider::{
        EndpointKind, EndpointRef, IdentitiesOnly, IdentitySelection, IdentitySelectionReport,
    };
    use heimdall_contract::setup::{
        ConflictKind, PlanDigest, PreviewIntent, ProjectionItem, RepairResolution,
    };
    use heimdall_domain::catalog::{
        CatalogAction, CatalogIntent, DeclarationEndReason, DeclarationState,
        DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
        InteractionDeclaration, InteractionProfile, PreparedFacts, PreparedPair,
    };
    use heimdall_domain::holder::ProcessHolder;
    use heimdall_domain::operation::{
        FilePhase, HoldReason, ItemPhase, LocalIntent, LocalReceipt, STAGE_SETUP_FILE,
        STAGE_SETUP_ITEM,
    };
    use heimdall_domain::projection::{
        Base, BehaviorState, ConsentRecord, ConsentedStates, FileIdentity, FileRole, FileStep,
        ItemCommit, ItemId, ItemRecord, ProjectionApproval, ProjectionLocator, ProjectionRecord,
        Rendered, SetupIntent, Sha256Hex, Target, projection_resource_id,
    };
    use heimdall_domain::revocation::{CleanupIntent, PendingRemoteRevocation, RemoteObligation};
    use heimdall_store::{EndOutcome, RawDocuments, SetupAdmitted};
    use std::sync::Barrier;

    const P: &[u8] = b"Host work\n  HostName example.invalid\n  IdentitiesOnly yes\n";

    fn setup_intent(generation: u64, intent: PreviewIntent) -> SetupIntent {
        SetupIntent {
            plan_digest: PlanDigest::from_sha256([u8::try_from(generation % 251).unwrap(); 32]),
            intent,
            generation,
            approval: None,
            consent: ConsentRecord::default(),
            files: vec![FileStep {
                role: FileRole::ManagedSsh,
                path: "/scratch/ssh/heimdall.conf".into(),
                base: Base::Absent,
                target: Target::Present {
                    sha256: Sha256Hex::of(P),
                },
                content: Rendered::from_renderer(P.to_vec()).into_whole(),
                commit: true,
                staged_name: Some(
                    ".heimdall.conf.hm-stage-00112233445566778899aabbccddeeff".into(),
                ),
                displaced_name: None,
            }],
        }
    }

    fn apply() -> PreviewIntent {
        PreviewIntent::Apply { include_git: false }
    }

    /// A setup operation (queued), its idempotency record and its intent.
    fn setup_op(
        n: u64,
        env: &EnvironmentId,
        kind: OperationKind,
        intent: PreviewIntent,
    ) -> (OperationRecord, IdempotencyRecord, RecoveryIntent) {
        let key = IdempotencyKey {
            caller: caller(501),
            kind,
            request_id: RequestId::parse(&format!("setup-{n}")).unwrap(),
        };
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&n.to_be_bytes());
        let op = OperationRecord {
            id: op_id(n),
            kind,
            environment: env.clone(),
            key: key.clone(),
            request_hash: RequestHash(hash),
            effect_class: EffectClass::LocalResources,
            state: OperationState::Queued,
            code: None,
            effect_status: EffectStatus::None,
            result: None,
            created_at: plus(t0(), i64::try_from(n % 100_000).unwrap()),
            updated_at: plus(t0(), i64::try_from(n % 100_000).unwrap()),
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        let idem = IdempotencyRecord {
            key,
            request_hash: op.request_hash,
            operation_id: op.id.clone(),
            created_at: op.created_at,
            expires_at: None,
        };
        let rec = RecoveryIntent {
            request: serde_json::json!({"action": kind.as_str(), "request_id": format!("setup-{n}")}),
            resolved: None,
            local: Some(LocalIntent::Setup(setup_intent(n.max(1), intent))),
        };
        (op, idem, rec)
    }

    fn admit(
        s: &Store,
        (op, idem, intent): &(OperationRecord, IdempotencyRecord, RecoveryIntent),
        target: Option<&OperationId>,
    ) -> SetupAdmitted {
        s.transaction(|tx| tx.insert_setup_operation(op, idem, intent, target))
            .unwrap()
    }

    fn set_state(s: &Store, id: &OperationId, state: OperationState) {
        s.transaction(|tx| {
            let mut op = tx.operation(id)?.unwrap();
            op.state = state;
            op.updated_at = plus(op.updated_at, 1);
            tx.update_operation(&op)
        })
        .unwrap();
    }

    /// What one operation left behind: (operation, idempotency record, intent).
    fn rows_of(s: &Store, op: &OperationRecord) -> (bool, bool, bool) {
        s.transaction(|tx| {
            Ok((
                tx.operation(&op.id)?.is_some(),
                tx.idempotency_record(&op.key)?.is_some(),
                tx.recovery_intent(&op.id)?.is_some(),
            ))
        })
        .unwrap()
    }

    fn held_receipt() -> StageReceipt {
        StageReceipt {
            stage: STAGE_SETUP_FILE.into(),
            recorded_at: plus(t0(), 50),
            effect: EffectReceipt::Attempted {
                adapter: AdapterIdentity {
                    mechanism: "config_projection".into(),
                    instance: env_id(40).to_string(),
                },
                effect_token: "eff_setup".into(),
            },
            local: Some(LocalReceipt::File {
                step: 0,
                phase: FilePhase::Held {
                    reason: HoldReason::ActiveEntryModified,
                    observed: Vec::new(),
                },
            }),
        }
    }

    fn held_repair(
        n: u64,
        env: &EnvironmentId,
        target: &OperationId,
    ) -> (OperationRecord, IdempotencyRecord, RecoveryIntent) {
        setup_op(
            n,
            env,
            OperationKind::SetupRepair,
            PreviewIntent::Repair {
                conflict: ConflictKind::ProjectionHeld,
                resolution: RepairResolution::RetryHeld,
                operation: Some(target.clone()),
            },
        )
    }

    // --- migration 0004 → 0005 on a populated database ---------------------------------

    /// m02-plan U0: migration 0004→0005 on a populated database. M01 stage receipts
    /// and recovery intents, pending remote revocation records (current form with
    /// `claim_seq` and `effect_seq`; legacy form with `effect_round` and no
    /// `claim_seq`), the store-wide claim counter, and cleanup intents (one in
    /// flight) with their version counter all decode unchanged and re-encode
    /// byte-identically after the migration; the legacy record still migrates
    /// through `migrate_claim_seq`; the counters keep increasing; `cleared_by_claim`
    /// answers as before.
    #[test]
    fn migration_0004_to_0005_keeps_m01_records_counters_and_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        let (r1, r2) = (
            GrantId::from_random_bytes([91; 16]),
            GrantId::from_random_bytes([92; 16]),
        );
        let legacy_obligation = RemoteObligation {
            grant: r2.clone(),
            adapter: adapter(),
            reason: None,
            attempts: None,
            stopped: false,
            effect_round: Some(2),
            effect_seq: None,
        };
        let (claim_counter, version_counter) = {
            let s4 = Store::open_at_schema_version(&db, Arc::new(NoFaults), 4).unwrap();
            assert_eq!(s4.schema_version().unwrap(), 4);
            s4.transaction(|tx| {
                tx.insert_tombstone(&tombstone(91))?;
                tx.insert_tombstone(&tombstone(92))?;
                let first = tx.next_remote_claim_seq(0)?;
                let second = tx.next_remote_claim_seq(first)?;
                tx.set_remote_revocation(&PendingRemoteRevocation {
                    root: r1.clone(),
                    grants: vec![r1.clone()],
                    attempts: 2,
                    last_attempt_at: plus(t0(), 2),
                    stopped: false,
                    obligations: vec![RemoteObligation {
                        grant: r1.clone(),
                        adapter: adapter(),
                        reason: None,
                        attempts: Some(2),
                        stopped: false,
                        effect_round: None,
                        effect_seq: Some(first),
                    }],
                    claimed_at: Some(plus(t0(), 2)),
                    rearmed_effects: Vec::new(),
                    cap: Some(8),
                    claim_seq: Some(second),
                })?;
                tx.set_remote_revocation(&PendingRemoteRevocation {
                    root: r2.clone(),
                    grants: vec![r2.clone()],
                    attempts: 3,
                    last_attempt_at: plus(t0(), 3),
                    stopped: false,
                    obligations: vec![legacy_obligation.clone()],
                    claimed_at: None,
                    rearmed_effects: Vec::new(),
                    cap: None,
                    claim_seq: None,
                })?;
                let intent = |g: &GrantId, n: u64, in_flight: bool| CleanupIntent {
                    grant: g.clone(),
                    operation: op_id(n),
                    adapter: Some(adapter()),
                    effect_token: format!("eff_{n}"),
                    confirmed: !in_flight,
                    in_flight,
                    version: 0,
                    recorded_at: plus(t0(), 4),
                };
                tx.record_cleanup_intent(&intent(&r1, 81, true))?;
                let last = tx.record_cleanup_intent(&intent(&r2, 82, false))?;
                for n in 1..=2u64 {
                    let (op, idem) = simple_op(n);
                    tx.insert_operation(&op, &idem)?;
                    tx.set_recovery_intent(
                        &op.id,
                        &RecoveryIntent {
                            request: request_doc(n),
                            resolved: (n == 2).then(resolved_intent),
                            local: None,
                        },
                    )?;
                    for (i, effect) in [
                        EffectReceipt::NotAttempted,
                        EffectReceipt::Attempted {
                            adapter: adapter(),
                            effect_token: format!("eff_{n}"),
                        },
                        EffectReceipt::Confirmed {
                            adapter: adapter(),
                            credential_ref: format!("cred_{n}"),
                        },
                        EffectReceipt::Uncertain {
                            adapter: adapter(),
                            effect_token: format!("eff_{n}"),
                        },
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        tx.append_stage_receipt(
                            &op.id,
                            &StageReceipt {
                                stage: format!("stage{i}"),
                                recorded_at: plus(t0(), i64::try_from(i).unwrap()),
                                effect,
                                local: None,
                            },
                        )?;
                    }
                }
                Ok((second, last.version))
            })
            .unwrap()
        };
        let snapshot = |s: &Store| {
            s.transaction(|tx| {
                Ok((
                    tx.raw_documents(RawDocuments::StageReceipts)?,
                    tx.raw_documents(RawDocuments::RecoveryIntents)?,
                    tx.raw_documents(RawDocuments::Meta)?,
                    tx.remote_revocations()?,
                    tx.cleanup_intents()?,
                ))
            })
            .unwrap()
        };
        let before = snapshot(&Store::open_at_schema_version(&db, Arc::new(NoFaults), 4).unwrap());
        assert_eq!(before.0.len(), 8);
        assert_eq!(before.1.len(), 2);
        assert_eq!(before.4.len(), 2);
        let probes = [None, Some(0), Some(1), Some(2), Some(3), Some(4), Some(9)];
        let cleared = |records: &[PendingRemoteRevocation]| -> Vec<bool> {
            records
                .iter()
                .flat_map(|r| r.obligations.iter())
                .flat_map(|o| probes.iter().map(|p| o.cleared_by_claim(*p)))
                .collect()
        };
        let cleared_before = cleared(&before.3);

        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 5);
        let mut backup = db.as_os_str().to_owned();
        backup.push(".v4.backup");
        assert!(PathBuf::from(backup).exists(), "v4 file backed up first");
        let after = snapshot(&s);
        assert_eq!(after.0, before.0, "stage receipts byte-identical");
        assert_eq!(after.1, before.1, "recovery intents byte-identical");
        assert_eq!(
            after.2, before.2,
            "meta records (counters, revocations, intents) byte-identical"
        );
        assert_eq!(after.3, before.3, "pending remote records decode unchanged");
        assert_eq!(after.4, before.4, "cleanup intents decode unchanged");
        assert!(after.4.iter().any(|i| i.in_flight));
        // Each M01 document decodes with `local: None` and re-encodes byte-identically.
        for (_, raw) in &after.0 {
            let r: StageReceipt = serde_json::from_str(raw).unwrap();
            assert_eq!(r.local, None);
            assert_eq!(&serde_json::to_string(&r).unwrap(), raw);
        }
        for (_, raw) in &after.1 {
            let i: RecoveryIntent = serde_json::from_str(raw).unwrap();
            assert_eq!(i.local, None);
            assert_eq!(&serde_json::to_string(&i).unwrap(), raw);
        }
        for (key, raw) in &after.2 {
            if key.starts_with("remote_revocation:") {
                let r: PendingRemoteRevocation = serde_json::from_str(raw).unwrap();
                assert_eq!(&serde_json::to_string(&r).unwrap(), raw, "{key}");
            } else if key.starts_with("cleanup_intent:") {
                let i: CleanupIntent = serde_json::from_str(raw).unwrap();
                assert_eq!(&serde_json::to_string(&i).unwrap(), raw, "{key}");
            }
        }
        assert!(after.2.iter().any(|(k, v)| k == "remote_revocation_claim_seq" && *v == claim_counter.to_string()));
        assert!(
            after
                .2
                .iter()
                .any(|(k, v)| k == "cleanup_intent_version" && *v == version_counter.to_string())
        );
        // The legacy record is still in its legacy form and migrates when loaded.
        let mut legacy = after.3.iter().find(|r| r.root == r2).unwrap().clone();
        assert_eq!(legacy.claim_seq, None);
        assert_eq!(legacy.obligations, vec![legacy_obligation]);
        legacy.migrate_claim_seq();
        assert_eq!(legacy.claim_seq, Some(3));
        assert_eq!(legacy.obligations[0].effect_seq, Some(3));
        assert_eq!(legacy.obligations[0].effect_round, None);
        // cleared_by_claim gives the same answers, and the counters keep increasing.
        assert_eq!(cleared(&after.3), cleared_before);
        let (next_seq, next_version) = s
            .transaction(|tx| {
                let seq = tx.next_remote_claim_seq(0)?;
                let v = tx.record_cleanup_intent(&before.4[0])?;
                Ok((seq, v.version))
            })
            .unwrap();
        assert!(next_seq > claim_counter, "{next_seq} > {claim_counter}");
        assert!(
            next_version > version_counter,
            "{next_version} > {version_counter}"
        );
        // The new tables start empty.
        s.transaction(|tx| {
            assert!(tx.destinations()?.is_empty());
            assert!(tx.identities()?.is_empty());
            assert!(tx.binding_holders()?.is_empty());
            assert!(tx.projection_resources(&env_id(7))?.is_empty());
            assert_eq!(tx.projection_record(&env_id(7))?, None);
            assert!(tx.open_setup_operations(&env_id(7))?.is_empty());
            Ok(())
        })
        .unwrap();
        drop(s);
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        let mut second = db.as_os_str().to_owned();
        second.push(".v4.backup.1");
        assert!(!PathBuf::from(second).exists(), "no second migration");
    }

    // --- read-only open --------------------------------------------------------------

    /// m02-plan §5 item 18, U0b row 20: `open_read_only` never creates, migrates or
    /// writes; it refuses a newer schema and reports an older one.
    #[test]
    fn open_read_only_refuses_newer_reports_older_and_never_writes() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.sqlite3");
        assert!(Store::open_read_only(&missing, Arc::new(NoFaults)).is_err());
        assert!(!missing.exists(), "a read-only open never creates");

        let old = dir.path().join("v4.sqlite3");
        drop(Store::open_at_schema_version(&old, Arc::new(NoFaults), 4).unwrap());
        let bytes = std::fs::read(&old).unwrap();
        let e = Store::open_read_only(&old, Arc::new(NoFaults)).unwrap_err();
        assert!(
            matches!(
                e,
                StoreError::OlderSchema {
                    found: 4,
                    supported: 5
                }
            ),
            "{e}"
        );
        no_canary(&e);
        assert_eq!(std::fs::read(&old).unwrap(), bytes, "never upgraded");

        let current = file_db(dir.path());
        fixture_file(&current);
        let s = Store::open_read_only(&current, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            s.transaction(|tx| tx.self_environment()).unwrap(),
            Some(env_id(1))
        );
        assert!(s.transaction(|tx| tx.destinations()).unwrap().is_empty());
        let write = s.transaction(|tx| {
            tx.init_self_environment(&env_id(1))
                .and_then(|()| tx.upsert_destination(&destination(1, "work", 1)))
        });
        assert!(write.is_err(), "a read-only store refuses writes");
        drop(s);
        let s = Store::open(&current, Arc::new(NoFaults)).unwrap();
        assert!(s.transaction(|tx| tx.destinations()).unwrap().is_empty());
        drop(s);

        // A newer user_version is refused by both opens, and the file is untouched.
        let newer = corrupt_copy(dir.path(), |b| {
            b[60..64].copy_from_slice(&(SCHEMA_VERSION + 1).to_be_bytes())
        });
        let bytes = std::fs::read(&newer).unwrap();
        assert!(matches!(
            Store::open_read_only(&newer, Arc::new(NoFaults)),
            Err(StoreError::NewerSchema {
                found: 6,
                supported: 5
            })
        ));
        assert_refused_and_untouched(&newer, |e| {
            matches!(
                e,
                StoreError::NewerSchema {
                    found: 6,
                    supported: 5
                }
            )
        });
        assert_eq!(std::fs::read(&newer).unwrap(), bytes);
    }

    // --- catalog ------------------------------------------------------------------------

    fn endpoint(locator: &str) -> EndpointRef {
        EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: locator.into(),
        }
    }

    fn destination(n: u8, alias: &str, revision: u64) -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::parse(&format!("dest{n}")).unwrap(),
            alias: alias.into(),
            revision,
            definition: DestinationDefinition::Managed {
                hostname: "example.invalid".into(),
                port: None,
                account: AccountName::parse("git").unwrap(),
                identity: IdentityId::from_random_bytes([n; 16]),
            },
            label: None,
            updated_at: t0(),
        }
    }

    fn identity(n: u8, revision: u64) -> IdentityRecord {
        let source = IdentitySource::NativeAgent {
            endpoint: endpoint("/scratch/agent.sock"),
        };
        let public_key = format!("ssh-ed25519 AAAAfixture{n} fixture");
        IdentityRecord {
            id: IdentityId::from_random_bytes([n; 16]),
            revision,
            interaction: InteractionProfile::default_for(&source, &public_key),
            source,
            public_key,
            fingerprint: format!("SHA256:fixture{n}"),
            label: None,
            adopted_at: t0(),
            updated_at: t0(),
        }
    }

    #[test]
    fn catalog_destinations_and_identities_are_unique_and_revisioned() {
        let s = mem();
        s.transaction(|tx| {
            tx.upsert_destination(&destination(1, "work", 1))?;
            tx.upsert_destination(&destination(2, "home", 1))?;
            // The alias is unique; a collision changes nothing.
            assert!(matches!(
                tx.upsert_destination(&destination(3, "work", 1)),
                Err(StoreError::GenerationConflict(_))
            ));
            // A rename keeps the destination ID; a stale revision never wins.
            tx.upsert_destination(&destination(1, "office", 2))?;
            assert!(matches!(
                tx.upsert_destination(&destination(1, "work", 1)),
                Err(StoreError::GenerationConflict(_))
            ));
            assert!(matches!(
                tx.upsert_destination(&destination(1, "elsewhere", 2)),
                Err(StoreError::GenerationConflict(_))
            ));
            tx.upsert_destination(&destination(1, "office", 2))?;
            assert_eq!(tx.destination_by_alias("work")?, None);
            assert_eq!(
                tx.destination_by_alias("office")?.map(|d| d.id),
                Some(DestinationId::parse("dest1").unwrap())
            );
            let aliases: Vec<String> = tx.destinations()?.into_iter().map(|d| d.alias).collect();
            assert_eq!(aliases, ["home", "office"]);
            assert!(tx.remove_destination(&DestinationId::parse("dest2").unwrap())?);
            assert!(!tx.remove_destination(&DestinationId::parse("dest2").unwrap())?);

            tx.upsert_identity(&identity(1, 1))?;
            let mut dup = identity(2, 1);
            dup.fingerprint = identity(1, 1).fingerprint;
            assert!(matches!(
                tx.upsert_identity(&dup),
                Err(StoreError::GenerationConflict(_))
            ));
            assert_eq!(
                tx.identity_by_fingerprint("SHA256:fixture1")?,
                Some(identity(1, 1))
            );
            let mut armored = identity(3, 1);
            armored.label = Some("-----BEGIN OPENSSH PRIVATE KEY-----".into());
            assert!(
                tx.upsert_identity(&armored).is_err(),
                "key armor is refused"
            );
            assert_eq!(tx.identities()?.len(), 1);
            Ok(())
        })
        .unwrap();
    }

    fn declaration(revision: u64, at: &str) -> InteractionDeclaration {
        InteractionDeclaration {
            revision,
            state: DeclarationState::Live,
            interaction: DeclaredInteraction::None,
            fingerprint: "SHA256:fixture1".into(),
            endpoint: endpoint(at),
            declared_at: t0(),
            expires_at: plus(t0(), 30 * 86_400),
            decision: DecisionId::from_random_bytes([5; 16]),
            ended_at: None,
            end_reason: None,
        }
    }

    /// U0b row 20: the declaration revision CAS and `end_interaction_declaration`.
    #[test]
    fn declaration_revision_cas_and_end() {
        let s = mem();
        let idn = IdentityId::from_random_bytes([1; 16]);
        s.transaction(|tx| {
            assert_eq!(
                tx.end_interaction_declaration(
                    &idn,
                    None,
                    DeclarationEndReason::OwnerWithdrawn,
                    t0()
                )?,
                EndOutcome {
                    ended: false,
                    revision: 0
                }
            );
            tx.put_interaction_declaration(&idn, 0, &declaration(1, "/scratch/a.sock"))?;
            for (expected, revision) in [(0, 1), (1, 3), (2, 3)] {
                assert!(matches!(
                    tx.put_interaction_declaration(
                        &idn,
                        expected,
                        &declaration(revision, "/scratch/a.sock")
                    ),
                    Err(StoreError::GenerationConflict(_))
                ));
            }
            let mut ended = declaration(2, "/scratch/a.sock");
            ended.state = DeclarationState::Withdrawn;
            assert!(
                tx.put_interaction_declaration(&idn, 1, &ended).is_err(),
                "written live only"
            );
            // A re-declaration is the next revision.
            tx.put_interaction_declaration(&idn, 1, &declaration(2, "/scratch/b.sock"))?;
            assert_eq!(
                tx.interaction_declaration(&idn)?.map(|d| d.revision),
                Some(2)
            );
            // A withdrawal naming the older revision leaves the newer one live.
            assert_eq!(
                tx.end_interaction_declaration(
                    &idn,
                    Some(1),
                    DeclarationEndReason::ListingMissing,
                    plus(t0(), 5)
                )?,
                EndOutcome {
                    ended: false,
                    revision: 2
                }
            );
            assert_eq!(
                tx.interaction_declaration(&idn)?.unwrap().state,
                DeclarationState::Live
            );
            assert_eq!(
                tx.end_interaction_declaration(
                    &idn,
                    Some(2),
                    DeclarationEndReason::ListingMissing,
                    plus(t0(), 6)
                )?,
                EndOutcome {
                    ended: true,
                    revision: 3
                }
            );
            let row = tx.interaction_declaration(&idn)?.unwrap();
            assert_eq!(
                (row.state, row.ended_at, row.end_reason),
                (
                    DeclarationState::Lapsed,
                    Some(plus(t0(), 6)),
                    Some(DeclarationEndReason::ListingMissing)
                )
            );
            // Not live any more: nothing to end.
            assert_eq!(
                tx.end_interaction_declaration(
                    &idn,
                    None,
                    DeclarationEndReason::OwnerWithdrawn,
                    plus(t0(), 7)
                )?,
                EndOutcome {
                    ended: false,
                    revision: 3
                }
            );
            tx.put_interaction_declaration(&idn, 3, &declaration(4, "/scratch/b.sock"))?;
            assert_eq!(
                tx.end_interaction_declaration(
                    &idn,
                    None,
                    DeclarationEndReason::OwnerWithdrawn,
                    plus(t0(), 8)
                )?,
                EndOutcome {
                    ended: true,
                    revision: 5
                }
            );
            assert_eq!(
                tx.interaction_declaration(&idn)?.unwrap().state,
                DeclarationState::Withdrawn
            );
            // Removing the identity keeps the row, so revisions are never reused.
            tx.upsert_identity(&identity(1, 1))?;
            assert!(tx.remove_identity(&idn)?);
            assert_eq!(
                tx.interaction_declaration(&idn)?.map(|d| d.revision),
                Some(5)
            );
            Ok(())
        })
        .unwrap();
    }

    // --- prepared facts, holders -----------------------------------------------------

    #[test]
    fn prepared_facts_and_binding_holders_round_trip() {
        let s = mem();
        let g = grant(70, None, plus(t0(), 7200), GrantState::Active);
        let b = binding(71, &g.id, caller(501), "work-1");
        let facts = |n: u64| PreparedFacts {
            provider: None,
            executables: Vec::new(),
            overrides: Vec::new(),
            environment: vec![("SSH_AUTH_SOCK".into(), "/scratch/agent.sock".into())],
            pairs: vec![PreparedPair {
                destination: DestinationId::parse("dest1").unwrap(),
                account: AccountName::parse("git").unwrap(),
                identity: IdentityId::from_random_bytes([1; 16]),
                mechanism: "native_agent".into(),
                endpoint: Some(endpoint("/scratch/agent.sock")),
                alias: Some("work".into()),
                identity_selection: IdentitySelectionReport {
                    selection: IdentitySelection::Exclusive,
                    entries: Vec::new(),
                    identities_only: IdentitiesOnly::DeterminedYes,
                },
                selection_observed_at: plus(t0(), i64::try_from(n).unwrap()),
            }],
            recorded_at: plus(t0(), i64::try_from(n).unwrap()),
        };
        s.transaction(|tx| {
            assert!(
                tx.set_grant_prepared_facts(&g.id, &facts(1)).is_err(),
                "the grant must exist"
            );
            tx.insert_grant(&g)?;
            assert_eq!(tx.grant_prepared_facts(&g.id)?, None);
            tx.set_grant_prepared_facts(&g.id, &facts(1))?;
            tx.set_grant_prepared_facts(&g.id, &facts(2))?;
            assert_eq!(tx.grant_prepared_facts(&g.id)?, Some(facts(2)));

            let holder = ProcessHolder {
                pid: 4242,
                started_at: "1730419200.5".into(),
            };
            assert!(
                tx.set_binding_holder(&b.id, &holder).is_err(),
                "the binding must exist"
            );
            tx.insert_binding(&b)?;
            tx.set_binding_holder(&b.id, &holder)?;
            assert!(
                tx.set_binding_holder(
                    &b.id,
                    &ProcessHolder {
                        pid: 0,
                        started_at: "x".into()
                    }
                )
                .is_err()
            );
            let replaced = ProcessHolder {
                pid: 4243,
                started_at: "1730419201.5".into(),
            };
            tx.set_binding_holder(&b.id, &replaced)?;
            assert_eq!(tx.binding_holder(&b.id)?, Some(replaced.clone()));
            assert_eq!(tx.binding_holders()?, vec![(b.id.clone(), replaced)]);
            Ok(())
        })
        .unwrap();
    }

    // --- projection resources, records, consent: one atomic commit ----------------------

    fn locator(role: FileRole, path: &str, ino: u64, birth: Option<i128>) -> ProjectionLocator {
        ProjectionLocator {
            role,
            path: path.into(),
            identity: FileIdentity::Unix { dev: 1, ino, birth },
            sha256: Sha256Hex::of(path.as_bytes()),
        }
    }

    fn item_commit(
        env: &EnvironmentId,
        op: &OperationId,
        generation: u64,
    ) -> (ItemCommit, StageReceipt) {
        let resources = vec![
            locator(
                FileRole::ManagedSsh,
                "/scratch/ssh/heimdall.conf",
                10 + generation,
                Some(7),
            ),
            locator(
                FileRole::Key,
                "/scratch/ssh/heimdall/k1.pub",
                20 + generation,
                None,
            ),
        ];
        let mut consent = ConsentRecord::default();
        let state = BehaviorState {
            digest: Sha256Hex::of(b"managed"),
            determined: true,
        };
        consent.items.insert(
            ItemId::alias("work"),
            ConsentedStates {
                managed: state.clone(),
                restore: state,
                decision: DecisionId::from_random_bytes([6; 16]),
            },
        );
        let record = ProjectionRecord {
            environment: env.clone(),
            items: [(
                ProjectionItem::Ssh,
                ItemRecord {
                    generation,
                    files: resources.clone(),
                    aliases: vec!["work".into()],
                    include_file: None,
                    operation: op.clone(),
                    committed_at: plus(t0(), 60),
                },
            )]
            .into_iter()
            .collect(),
        };
        let receipt = StageReceipt {
            stage: STAGE_SETUP_ITEM.into(),
            recorded_at: plus(t0(), 60),
            effect: EffectReceipt::Confirmed {
                adapter: AdapterIdentity {
                    mechanism: "config_projection".into(),
                    instance: env.to_string(),
                },
                credential_ref: format!("projection/ssh/{generation}"),
            },
            local: Some(LocalReceipt::Item {
                item: ProjectionItem::Ssh,
                phase: ItemPhase::Committed { generation },
            }),
        };
        (
            ItemCommit {
                item: ProjectionItem::Ssh,
                generation,
                resources,
                record,
                consent,
            },
            receipt,
        )
    }

    /// U0b row 20: `commit_projection_item` writes the receipt, the resources, the
    /// record and the consent atomically, and nothing when the store is injected to
    /// fail or a check refuses.
    #[test]
    fn commit_projection_item_is_one_transaction() {
        let env = env_id(40);
        let faults = ScriptedFaults::new([
            (FaultPoint::BeforeCommit, FaultAction::Continue),
            (FaultPoint::BeforeCommit, FaultAction::Fail),
        ]);
        let s = Store::open_in_memory(faults).unwrap();
        let setup = setup_op(1, &env, OperationKind::SetupApply, apply());
        assert_eq!(admit(&s, &setup, None), SetupAdmitted::Inserted);
        let op = setup.0.id.clone();
        let (commit, receipt) = item_commit(&env, &op, 1);
        let e = s
            .transaction(|tx| tx.commit_projection_item(&op, &commit, &receipt))
            .unwrap_err();
        assert!(matches!(
            e,
            StoreError::InjectedFault(FaultPoint::BeforeCommit)
        ));
        let nothing = |s: &Store| {
            s.transaction(|tx| {
                Ok((
                    tx.projection_resources(&env)?.is_empty(),
                    tx.projection_record(&env)?.is_none(),
                    tx.get_projection_consent(&env)?.items.is_empty(),
                    tx.stage_receipts(&op)?.is_empty(),
                ))
            })
            .unwrap()
        };
        assert_eq!(
            nothing(&s),
            (true, true, true, true),
            "a failed commit leaves nothing"
        );

        s.transaction(|tx| tx.commit_projection_item(&op, &commit, &receipt))
            .unwrap();
        s.transaction(|tx| {
            let resources = tx.projection_resources(&env)?;
            assert_eq!(resources.len(), 2);
            for r in &resources {
                assert_eq!(r.generation, ResourceGeneration(1));
                assert_eq!(
                    r.owner,
                    OwnerRef::Projection {
                        environment: env.clone()
                    }
                );
                assert_eq!(r.kind, ResourceKind::ConfigProjection);
                let l: ProjectionLocator = serde_json::from_str(&r.locator).unwrap();
                assert_eq!(r.id, projection_resource_id(&env, l.role, &l.path));
                assert_eq!(r.locator, l.canonical().unwrap());
            }
            assert_eq!(tx.projection_record(&env)?, Some(commit.record.clone()));
            assert_eq!(tx.get_projection_consent(&env)?, commit.consent);
            assert_eq!(tx.stage_receipts(&op)?, vec![receipt.clone()]);
            Ok(())
        })
        .unwrap();

        // Refusals write nothing: a stale generation, a receipt for another item or
        // generation, an operation of another environment, a non-setup operation.
        let refusals: Vec<(&str, ItemCommit, StageReceipt, OperationId)> = {
            let (c1, r1) = item_commit(&env, &op, 1);
            let (c2, mut r2) = item_commit(&env, &op, 2);
            r2.local = Some(LocalReceipt::Item {
                item: ProjectionItem::Ssh,
                phase: ItemPhase::Committed { generation: 3 },
            });
            let (mut c3, r3) = item_commit(&env, &op, 2);
            c3.record.environment = env_id(41);
            let (c4, mut r4) = item_commit(&env, &op, 2);
            r4.effect = EffectReceipt::NotAttempted;
            let (mut c5, r5) = item_commit(&env, &op, 2);
            c5.resources.push(locator(
                FileRole::GitManaged,
                "/scratch/heimdall.gitconfig",
                9,
                None,
            ));
            vec![
                ("stale generation", c1, r1, op.clone()),
                ("receipt generation", c2, r2, op.clone()),
                ("other environment", c3, r3, op.clone()),
                ("not confirmed", c4, r4, op.clone()),
                ("resource of another item", c5, r5, op.clone()),
            ]
        };
        for (name, c, r, o) in refusals {
            assert!(
                s.transaction(|tx| tx.commit_projection_item(&o, &c, &r))
                    .is_err(),
                "{name}"
            );
        }
        let (ensure, idem) = simple_op(2);
        s.transaction(|tx| tx.insert_operation(&ensure, &idem))
            .unwrap();
        let (c, r) = item_commit(&env_id(7), &ensure.id, 2);
        assert!(
            s.transaction(|tx| tx.commit_projection_item(&ensure.id, &c, &r))
                .is_err()
        );
        s.transaction(|tx| {
            assert_eq!(
                tx.stage_receipts(&op)?.len(),
                1,
                "no refused receipt was written"
            );
            assert!(
                tx.projection_resources(&env)?
                    .iter()
                    .all(|r| r.generation == ResourceGeneration(1))
            );
            Ok(())
        })
        .unwrap();

        // The next generation replaces each resource by generation CAS.
        let (c2, r2) = item_commit(&env, &op, 2);
        s.transaction(|tx| tx.commit_projection_item(&op, &c2, &r2))
            .unwrap();
        s.transaction(|tx| {
            assert!(
                tx.projection_resources(&env)?
                    .iter()
                    .all(|r| r.generation == ResourceGeneration(2))
            );
            assert_eq!(tx.stage_receipts(&op)?.len(), 2);
            Ok(())
        })
        .unwrap();
    }

    /// U0b row 20: projection resources by generation and identity CAS; birth is
    /// never a wildcard.
    #[test]
    fn projection_resource_generation_and_identity_cas() {
        let s = mem();
        let env = env_id(42);
        let l = locator(
            FileRole::ManagedSsh,
            "/scratch/ssh/heimdall.conf",
            10,
            Some(5),
        );
        let res = |generation: u64, l: &ProjectionLocator| ManagedResource {
            id: projection_resource_id(&env, l.role, &l.path),
            kind: ResourceKind::ConfigProjection,
            owner: OwnerRef::Projection {
                environment: env.clone(),
            },
            generation: ResourceGeneration(generation),
            desired: ResourceState::Present,
            observed: ResourceState::Present,
            last_operation: None,
            locator: l.canonical().unwrap(),
            updated_at: t0(),
        };
        let v2 = locator(
            FileRole::ManagedSsh,
            "/scratch/ssh/heimdall.conf",
            11,
            Some(6),
        );
        s.transaction(|tx| {
            tx.put_projection_resource(&res(1, &l), None)?;
            assert!(matches!(
                tx.put_projection_resource(&res(1, &l), None),
                Err(StoreError::GenerationConflict(_))
            ));
            let same_inode_no_birth = FileIdentity::Unix {
                dev: 1,
                ino: 10,
                birth: None,
            };
            let other_birth = FileIdentity::Unix {
                dev: 1,
                ino: 10,
                birth: Some(9),
            };
            for (generation, identity) in [
                (ResourceGeneration(2), &l.identity),
                (ResourceGeneration(1), &same_inode_no_birth),
                (ResourceGeneration(1), &other_birth),
            ] {
                assert!(matches!(
                    tx.put_projection_resource(&res(2, &v2), Some((generation, identity))),
                    Err(StoreError::GenerationConflict(_))
                ));
            }
            assert!(matches!(
                tx.put_projection_resource(
                    &res(0, &v2),
                    Some((ResourceGeneration(1), &l.identity))
                ),
                Err(StoreError::GenerationConflict(_))
            ));
            tx.put_projection_resource(&res(2, &v2), Some((ResourceGeneration(1), &l.identity)))?;
            let stored = tx.projection_resources(&env)?;
            assert_eq!(stored, vec![res(2, &v2)]);
            // Only canonical projection locators of projection-owned config files.
            let mut not_canonical = res(1, &locator(FileRole::Key, "/scratch/k.pub", 3, None));
            not_canonical.locator =
                serde_json::to_string(&locator(FileRole::Key, "/scratch/k.pub", 3, None)).unwrap();
            assert!(tx.put_projection_resource(&not_canonical, None).is_err());
            let mut runtime_owned = res(1, &locator(FileRole::Key, "/scratch/k2.pub", 4, None));
            runtime_owned.owner = OwnerRef::Runtime;
            assert!(tx.put_projection_resource(&runtime_owned, None).is_err());
            assert!(tx.projection_resources(&env_id(43))?.is_empty());
            Ok(())
        })
        .unwrap();
    }

    // --- recovery intent `local`: add-only (U0b row 16) ----------------------------------

    #[test]
    fn recovery_intent_local_is_add_only_and_never_beside_resolved() {
        let s = mem();
        let env = env_id(44);
        let (op, idem, intent) = setup_op(1, &env, OperationKind::SetupApply, apply());
        let LocalIntent::Setup(base) = intent.local.clone().unwrap() else {
            panic!("setup intent");
        };
        let with = |f: &dyn Fn(&mut SetupIntent)| {
            let mut i = base.clone();
            f(&mut i);
            RecoveryIntent {
                local: Some(LocalIntent::Setup(i)),
                ..intent.clone()
            }
        };
        let conflict =
            |r: heimdall_store::Result<()>| matches!(r, Err(StoreError::GenerationConflict(_)));
        s.transaction(|tx| {
            tx.insert_operation(&op, &idem)?;
            // Both at once is refused, on the first write too.
            let both = RecoveryIntent {
                resolved: Some(resolved_intent()),
                ..intent.clone()
            };
            assert!(conflict(tx.set_recovery_intent(&op.id, &both)));
            // None → Some is allowed.
            tx.set_recovery_intent(
                &op.id,
                &RecoveryIntent {
                    local: None,
                    ..intent.clone()
                },
            )?;
            tx.set_recovery_intent(&op.id, &intent)?;
            // Once set: no field but the approval changes, and it cannot be removed.
            assert!(conflict(
                tx.set_recovery_intent(&op.id, &with(&|i| i.generation = 9))
            ));
            assert!(conflict(tx.set_recovery_intent(
                &op.id,
                &RecoveryIntent {
                    local: None,
                    ..intent.clone()
                }
            )));
            let catalog = RecoveryIntent {
                local: Some(LocalIntent::Catalog(CatalogIntent {
                    action: CatalogAction::RemoveIdentity {
                        id: IdentityId::from_random_bytes([1; 16]),
                    },
                    approval: None,
                })),
                ..intent.clone()
            };
            assert!(conflict(tx.set_recovery_intent(&op.id, &catalog)));
            assert!(conflict(tx.set_recovery_intent(&op.id, &both)));
            // The approval goes None → Some once and is never replaced or removed.
            let approval = |n: u8| ProjectionApproval {
                decision: DecisionId::from_random_bytes([n; 16]),
                plan_digest: base.plan_digest.clone(),
            };
            let a1 = with(&|i| i.approval = Some(approval(1)));
            tx.set_recovery_intent(&op.id, &a1)?;
            tx.set_recovery_intent(&op.id, &a1)?;
            assert!(conflict(tx.set_recovery_intent(
                &op.id,
                &with(&|i| i.approval = Some(approval(2)))
            )));
            assert!(conflict(tx.set_recovery_intent(&op.id, &intent)));
            assert_eq!(tx.recovery_intent(&op.id)?, Some(a1));
            // An invalid local intent is refused before anything is written.
            let invalid = with(&|i| {
                i.files[0].target = Target::Present {
                    sha256: Sha256Hex::of(b"x"),
                }
            });
            assert!(tx.set_recovery_intent(&op.id, &invalid).is_err());
            Ok(())
        })
        .unwrap();
    }

    // --- atomic setup admission (§12.8 item 6; U0b row 23) -------------------------------

    /// Two store handles (two SQLite connections) on one file race
    /// `insert_setup_operation` for one environment from two threads released by a
    /// barrier. Over 500 rounds exactly one is inserted per round, the loser gets
    /// `InProgress` naming the winner and leaves no row; the winner is then settled.
    #[test]
    fn insert_setup_operation_check_and_insert_are_one_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        let a = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
        let b = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
        let env = env_id(45);
        for round in 0..500u64 {
            let barrier = Arc::new(Barrier::new(2));
            let handles: Vec<_> = [(Arc::clone(&a), 0u64), (Arc::clone(&b), 1u64)]
                .into_iter()
                .map(|(store, side)| {
                    let barrier = Arc::clone(&barrier);
                    let env = env.clone();
                    std::thread::spawn(move || {
                        let setup = setup_op(
                            10_000 + round * 2 + side,
                            &env,
                            OperationKind::SetupApply,
                            apply(),
                        );
                        barrier.wait();
                        let admitted = store
                            .transaction(|tx| {
                                tx.insert_setup_operation(&setup.0, &setup.1, &setup.2, None)
                            })
                            .unwrap();
                        (setup.0, admitted)
                    })
                })
                .collect();
            let results: Vec<(OperationRecord, SetupAdmitted)> =
                handles.into_iter().map(|h| h.join().unwrap()).collect();
            let winners: Vec<&OperationRecord> = results
                .iter()
                .filter(|(_, r)| *r == SetupAdmitted::Inserted)
                .map(|(op, _)| op)
                .collect();
            assert_eq!(winners.len(), 1, "round {round}: exactly one admission");
            let winner = winners[0].clone();
            let (loser, refusal) = results.iter().find(|(op, _)| op.id != winner.id).unwrap();
            assert_eq!(
                refusal,
                &SetupAdmitted::InProgress(vec![winner.id.clone()]),
                "round {round}: the loser names the winner"
            );
            assert_eq!(
                rows_of(&a, loser),
                (false, false, false),
                "round {round}: the loser left nothing"
            );
            assert_eq!(rows_of(&b, &winner), (true, true, true));
            set_state(
                if round % 2 == 0 { &a } else { &b },
                &winner.id,
                OperationState::Succeeded,
            );
        }
        let open = a.transaction(|tx| tx.open_setup_operations(&env)).unwrap();
        assert!(open.is_empty());
    }

    #[test]
    fn insert_setup_operation_blocks_on_every_open_or_unresolved_state() {
        let env = env_id(46);
        for (n, state, blocks) in [
            (1, OperationState::Queued, true),
            (2, OperationState::Running, true),
            (3, OperationState::AwaitingApproval, true),
            (4, OperationState::OutcomeUnknown, true),
            (5, OperationState::Succeeded, false),
            (6, OperationState::Failed, false),
            (7, OperationState::Cancelled, false),
        ] {
            let s = mem();
            for kind in OperationKind::SETUP {
                let blocker = setup_op(n, &env, kind, apply());
                let s2 = mem();
                assert_eq!(admit(&s2, &blocker, None), SetupAdmitted::Inserted);
                if state != OperationState::Queued {
                    set_state(&s2, &blocker.0.id, state);
                }
                let next = setup_op(100 + n, &env, OperationKind::SetupApply, apply());
                let expect = if blocks {
                    SetupAdmitted::InProgress(vec![blocker.0.id.clone()])
                } else {
                    SetupAdmitted::Inserted
                };
                assert_eq!(admit(&s2, &next, None), expect, "{kind:?} in {state:?}");
                let rows = rows_of(&s2, &next.0);
                assert_eq!(rows, (!blocks, !blocks, !blocks));
            }
            // A non-setup open operation, or a setup operation of another
            // environment, never blocks.
            let (ensure, idem) = simple_op(n);
            s.transaction(|tx| tx.insert_operation(&ensure, &idem))
                .unwrap();
            let elsewhere = setup_op(200 + n, &env_id(47), OperationKind::SetupApply, apply());
            assert_eq!(admit(&s, &elsewhere, None), SetupAdmitted::Inserted);
            let mine = setup_op(300 + n, &env, OperationKind::SetupApply, apply());
            assert_eq!(admit(&s, &mine, None), SetupAdmitted::Inserted);
        }
        // Blockers are listed oldest first.
        let s = mem();
        let older = setup_op(1, &env, OperationKind::SetupApply, apply());
        assert_eq!(admit(&s, &older, None), SetupAdmitted::Inserted);
        set_state(&s, &older.0.id, OperationState::OutcomeUnknown);
        let blockers = s.transaction(|tx| tx.open_setup_operations(&env)).unwrap();
        assert_eq!(blockers, vec![older.0.id.clone()]);
        // Caller errors are refused before anything is read or written.
        let (ensure, idem) = simple_op(9);
        let bad_kind = RecoveryIntent {
            request: request_doc(9),
            resolved: None,
            local: older.2.local.clone(),
        };
        assert!(
            s.transaction(|tx| tx.insert_setup_operation(&ensure, &idem, &bad_kind, None))
                .is_err()
        );
        let mut catalog = setup_op(10, &env, OperationKind::SetupApply, apply());
        catalog.2.local = None;
        assert!(
            s.transaction(|tx| tx.insert_setup_operation(&catalog.0, &catalog.1, &catalog.2, None))
                .is_err()
        );
        assert_eq!(rows_of(&s, &catalog.0), (false, false, false));
    }

    #[test]
    fn insert_setup_operation_repair_exception_is_exact() {
        let env = env_id(48);
        let held = |s: &Store, n: u64| {
            let o = setup_op(n, &env, OperationKind::SetupApply, apply());
            assert_eq!(admit(s, &o, None), SetupAdmitted::Inserted);
            set_state(s, &o.0.id, OperationState::OutcomeUnknown);
            s.transaction(|tx| tx.append_stage_receipt(&o.0.id, &held_receipt()))
                .unwrap();
            o.0.id
        };
        // Exactly one blocker O, outcome_unknown, last receipt held: a repair naming O
        // is admitted.
        let s = mem();
        let o = held(&s, 1);
        assert_eq!(
            admit(&s, &held_repair(2, &env, &o), Some(&o)),
            SetupAdmitted::Inserted
        );

        // Naming another operation: refused.
        let s = mem();
        let o = held(&s, 1);
        let other = op_id(77);
        assert_eq!(
            admit(&s, &held_repair(2, &env, &other), Some(&other)),
            SetupAdmitted::InProgress(vec![o.clone()])
        );
        // No target at all: refused.
        assert_eq!(
            admit(
                &s,
                &setup_op(3, &env, OperationKind::SetupRepair, apply()),
                None
            ),
            SetupAdmitted::InProgress(vec![o.clone()])
        );
        // O not held: its last receipt is not `held`, or it is not outcome_unknown.
        let s = mem();
        let o = held(&s, 1);
        let mut later = held_receipt();
        later.local = Some(LocalReceipt::File {
            step: 0,
            phase: FilePhase::Exchanged,
        });
        s.transaction(|tx| tx.append_stage_receipt(&o, &later))
            .unwrap();
        assert_eq!(
            admit(&s, &held_repair(2, &env, &o), Some(&o)),
            SetupAdmitted::InProgress(vec![o.clone()])
        );
        let s = mem();
        let o = held(&s, 1);
        set_state(&s, &o, OperationState::Running);
        assert_eq!(
            admit(&s, &held_repair(2, &env, &o), Some(&o)),
            SetupAdmitted::InProgress(vec![o.clone()])
        );
        // A second blocker exists.
        let s = mem();
        let o = held(&s, 1);
        let second = setup_op(5, &env, OperationKind::SetupRollback, apply());
        s.transaction(|tx| {
            tx.insert_operation(&second.0, &second.1)?;
            tx.set_recovery_intent(&second.0.id, &second.2)
        })
        .unwrap();
        assert_eq!(
            admit(&s, &held_repair(6, &env, &o), Some(&o)),
            SetupAdmitted::InProgress(vec![o.clone(), second.0.id.clone()])
        );
        // A target only with a held repair of kind setup.repair that names it.
        let s = mem();
        let o = held(&s, 1);
        let mut wrong_kind = held_repair(2, &env, &o);
        wrong_kind.0.kind = OperationKind::SetupApply;
        wrong_kind.0.key.kind = OperationKind::SetupApply;
        wrong_kind.1.key.kind = OperationKind::SetupApply;
        assert!(
            s.transaction(|tx| tx.insert_setup_operation(
                &wrong_kind.0,
                &wrong_kind.1,
                &wrong_kind.2,
                Some(&o)
            ))
            .is_err()
        );
        let not_held_resolution = setup_op(
            3,
            &env,
            OperationKind::SetupRepair,
            PreviewIntent::Repair {
                conflict: ConflictKind::MarkerEdited,
                resolution: RepairResolution::Rerender,
                operation: None,
            },
        );
        assert!(
            s.transaction(|tx| tx.insert_setup_operation(
                &not_held_resolution.0,
                &not_held_resolution.1,
                &not_held_resolution.2,
                Some(&o)
            ))
            .is_err()
        );
        assert_eq!(rows_of(&s, &not_held_resolution.0), (false, false, false));
    }

    /// The admission state survives a restart, and a crash (an injected failure at
    /// `BeforeCommit`) leaves no operation, idempotency record or intent.
    #[test]
    fn insert_setup_operation_state_survives_restart_and_a_crash_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        let env = env_id(49);
        let blocker = setup_op(1, &env, OperationKind::SetupApply, apply());
        {
            let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
            assert_eq!(admit(&s, &blocker, None), SetupAdmitted::Inserted);
        }
        let next = setup_op(2, &env, OperationKind::SetupRollback, apply());
        {
            let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
            assert_eq!(
                admit(&s, &next, None),
                SetupAdmitted::InProgress(vec![blocker.0.id.clone()])
            );
            set_state(&s, &blocker.0.id, OperationState::Failed);
        }
        {
            let faults = ScriptedFaults::new([(FaultPoint::BeforeCommit, FaultAction::Fail)]);
            let s = Store::open(&db, faults).unwrap();
            let e = s
                .transaction(|tx| tx.insert_setup_operation(&next.0, &next.1, &next.2, None))
                .unwrap_err();
            assert!(matches!(
                e,
                StoreError::InjectedFault(FaultPoint::BeforeCommit)
            ));
            no_canary(&e);
        }
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(
            rows_of(&s, &next.0),
            (false, false, false),
            "a crash leaves nothing"
        );
        assert!(
            s.transaction(|tx| tx.open_setup_operations(&env))
                .unwrap()
                .is_empty()
        );
        assert_eq!(admit(&s, &next, None), SetupAdmitted::Inserted);
        assert_eq!(rows_of(&s, &next.0), (true, true, true));
    }

    /// ADR-0007 §12.32 item 7 (Q01): `Txn::table_counts` counts every row of each table a
    /// purge of the state discards, whatever the row's state (an ended grant, a decided
    /// decision, a finished operation all count), including the audit events and the
    /// idempotency records the earlier counts left out. A store opened read-only counts
    /// the same and the file is left byte for byte as it was.
    #[test]
    fn table_counts_count_every_row_of_the_purged_tables_without_writing() {
        use heimdall_store::ext::TableCounts;
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        let env = env_id(7);
        {
            let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
            assert_eq!(
                s.transaction(|tx| tx.table_counts()).unwrap(),
                TableCounts::default(),
                "a fresh store counts nothing"
            );
            s.transaction(|tx| {
                for n in 1..=3 {
                    let (op, idem) = simple_op(n);
                    tx.insert_operation(&op, &idem)?;
                }
                let (mut finished, _) = simple_op(1);
                succeed(&mut finished, plus(t0(), 30));
                tx.update_operation(&finished)?;
                // A live grant and an ended one: both are rows a purge discards.
                tx.insert_grant(&grant(1, None, plus(t0(), 3600), GrantState::Active))?;
                tx.insert_grant(&grant(2, None, plus(t0(), 60), GrantState::Revoked))?;
                // A pending decision and a decided one.
                tx.insert_decision(&decision(1, 0))?;
                tx.insert_decision(&decision(2, 0))?;
                tx.complete_decision(&decision(2, 0).id, Verdict::Approve, plus(t0(), 60))?;
                tx.upsert_destination(&destination(1, "work", 1))?;
                tx.upsert_destination(&destination(2, "home", 1))?;
                tx.upsert_destination(&destination(3, "lab", 1))?;
                tx.upsert_identity(&identity(1, 1))?;
                tx.upsert_identity(&identity(2, 1))?;
                tx.upsert_profile(&profile_def(1, &[("h1", "u1")]))?;
                for i in 0..4i64 {
                    tx.append_event(&event(
                        &env,
                        EventType::OperationStateChanged,
                        None,
                        plus(t0(), i * 60),
                    ))?;
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(
                s.transaction(|tx| tx.table_counts()).unwrap(),
                TableCounts {
                    operations: 3,
                    grants: 2,
                    decisions: 2,
                    identities: 2,
                    destinations: 3,
                    profiles: 1,
                    events: 4,
                    idempotency: 3,
                }
            );
        }
        let before = std::fs::read(&db).unwrap();
        let ro = Store::open_read_only(&db, Arc::new(NoFaults)).unwrap();
        let counted = ro.transaction(|tx| tx.table_counts()).unwrap();
        assert_eq!(
            (
                counted.operations,
                counted.grants,
                counted.decisions,
                counted.identities + counted.destinations + counted.profiles,
                counted.events,
                counted.idempotency
            ),
            (3, 2, 2, 6, 4, 3),
            "a read-only store counts the same rows"
        );
        drop(ro);
        assert_eq!(
            std::fs::read(&db).unwrap(),
            before,
            "counting wrote nothing"
        );
    }
}
