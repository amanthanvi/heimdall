//! Joint wave 0 of M04 and M05 (ADR-0010 §9 item 1; ADR-0011 §10 item 5; m05-plan U0):
//! migrations 0007 and 0008 on a populated schema-6 database, and the semantics of the
//! `ext_m04` and `ext_m05` accessors that no other test covers (admission, terminal
//! states, compare-and-swap and insert-once rules, authority-generation moves).
//!
//! Every value is synthetic (fixture IDs, `example.invalid` hosts, fake public keys); no
//! owner key, agent or keychain is touched.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::environment::DistributionGuid;
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, DecisionId, DestinationId, EnrollmentId, EnvironmentId,
    GrantId, IdentityId, PolicyId, ProfileId, WorkId, WorkspaceId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{Capability, DeadlineIntent};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::binding::{BindingRecord, BindingState};
use heimdall_domain::catalog::{
    DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource, InteractionProfile,
};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{
    EnvironmentAdmission, EnvironmentRealization, ManagedEnvironment, ManagedState,
    WslDistributionRecord,
};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::projection::FileIdentity;
use heimdall_domain::scope::{AccessPair, Scope};
use heimdall_domain::time::Deadline;
use heimdall_domain::workspace::{
    BindingContext, DecisionCooldown, PolicyChangeCause, PolicyHistoryEntry, SlotReference,
    WorkStop, WorkspaceRecord, WorkspaceState,
};
use heimdall_store::{
    IssuerRecord, NoFaults, RawDocuments, Store, StoreError, Txn, migrations::SCHEMA_VERSION,
};

// --- fixtures --------------------------------------------------------------------------

fn t0() -> Timestamp {
    "2026-11-01T00:00:00Z".parse().unwrap()
}

fn plus(base: Timestamp, secs: i64) -> Timestamp {
    base.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn mem() -> Store {
    Store::open_in_memory(Arc::new(NoFaults)).unwrap()
}

fn env_id(b: u8) -> EnvironmentId {
    EnvironmentId::from_random_bytes([b; 16])
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn scope() -> Scope {
    Scope {
        pairs: [pair("h1", "u1")].into_iter().collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    }
}

fn grant(b: u8) -> GrantSnapshot {
    GrantSnapshot {
        id: GrantId::from_random_bytes([b; 16]),
        environment: env_id(7),
        scope: scope(),
        starts_at: t0(),
        deadline: Deadline {
            intent: DeadlineIntent::Duration("2h".into()),
            resolved_at: t0(),
            effective: plus(t0(), 7200),
        },
        parent: None,
        source: AuthorizationSource::StandingPolicy {
            revision: PolicyRevision(1),
        },
        generation: AuthorityGeneration(0),
        state: GrantState::Active,
        enforcement: EnforcementEvidence::unknown(),
    }
}

fn binding(b: u8, grant: &GrantId) -> BindingRecord {
    BindingRecord {
        id: BindingId::from_random_bytes([b; 16]),
        environment: env_id(7),
        grant: grant.clone(),
        work_id: WorkId::parse("w").unwrap(),
        owner: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        },
        profile: ProfileId::parse("default").unwrap(),
        profile_revision: 1,
        scope: scope(),
        mechanism: "managed_certificate".into(),
        parent: None,
        created_at: plus(t0(), i64::from(b)),
        released_at: None,
        state: BindingState::Active,
    }
}

/// A grant `g` with binding `b` on it.
fn grant_and_binding(tx: &mut Txn<'_>, g: u8, b: u8) -> BindingId {
    let gr = grant(g);
    tx.insert_grant(&gr).unwrap();
    let bd = binding(b, &gr.id);
    tx.insert_binding(&bd).unwrap();
    bd.id
}

fn ca(n: u8) -> CaFingerprint {
    let c = char::from(b'A' + n % 26);
    CaFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
}

fn issuer(n: u8) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: ca(n),
        public_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture{n}"),
        state: CaState::Active,
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: format!("{n:02x}").repeat(32),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: plus(t0(), i64::from(n)),
        retired_at: None,
    }
}

fn enrollment(n: u8, ca: &CaFingerprint, pair: &AccessPair) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: pair.destination.clone(),
        account: pair.account.clone(),
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
            hostname: "example.invalid".into(),
            port: 22,
            user: pair.account.clone(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                fingerprint: "SHA256:hostfixture".into(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes([n; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state: EnrollmentState::Planned,
        verified_at: None,
        evidence: None,
        created_at: plus(t0(), i64::from(n)),
        updated_at: plus(t0(), i64::from(n)),
    }
}

fn destination(n: u8) -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::parse(&format!("dest{n}")).unwrap(),
        alias: "work".into(),
        revision: 1,
        definition: DestinationDefinition::Managed {
            hostname: "example.invalid".into(),
            port: None,
            account: AccountName::parse("git").unwrap(),
            identity: IdentityId::from_random_bytes([n; 16]),
            jump: None,
        },
        label: None,
        updated_at: t0(),
    }
}

fn identity(n: u8) -> IdentityRecord {
    let source = IdentitySource::NativeAgent {
        endpoint: EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: "/scratch/agent.sock".into(),
        },
    };
    let public_key = format!("ssh-ed25519 AAAAfixture{n} fixture");
    IdentityRecord {
        id: IdentityId::from_random_bytes([n; 16]),
        revision: 1,
        interaction: InteractionProfile::default_for(&source, &public_key),
        source,
        public_key,
        fingerprint: format!("SHA256:fixture{n}"),
        label: None,
        adopted_at: t0(),
        updated_at: t0(),
    }
}

fn guid(n: u8) -> DistributionGuid {
    DistributionGuid::parse(&format!("{n:08x}-0000-0000-0000-000000000000")).unwrap()
}

fn managed(env: u8, controller: u8, state: ManagedState) -> ManagedEnvironment {
    ManagedEnvironment {
        environment: env_id(env),
        controller: env_id(controller),
        realization: EnvironmentRealization::Wsl {
            guid: guid(env),
            name: "fixture".into(),
            account: "user".into(),
        },
        state,
        created_at: t0(),
        updated_at: t0(),
    }
}

fn wsl_record(n: u8) -> WslDistributionRecord {
    WslDistributionRecord {
        guid: guid(n),
        name: "fixture".into(),
        mode_a: true,
        mode_b: Some(env_id(n)),
        cleanup_pending: false,
        account: None,
        namespace: None,
        updated_at: t0(),
    }
}

fn workspace(n: u8, environment: u8) -> WorkspaceRecord {
    WorkspaceRecord {
        id: WorkspaceId::from_random_bytes([n; 16]),
        environment: env_id(environment),
        root: format!("/scratch/ws{n}"),
        root_identity: FileIdentity::Unix {
            dev: 1,
            ino: u64::from(n),
            birth: Some(7),
        },
        git_common_identity: None,
        decision: DecisionId::from_random_bytes([n; 16]),
        created_at: plus(t0(), i64::from(n)),
        state: WorkspaceState::Active,
    }
}

fn policy(rev: u64) -> StandingPolicy {
    StandingPolicy {
        id: PolicyId::parse("pol").unwrap(),
        revision: PolicyRevision(rev),
        profile: ProfileId::parse("default").unwrap(),
        workspace: None,
        scope: scope(),
        environments: BTreeSet::from([env_id(7)]),
        max_window: Duration::from_secs(3600),
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::OwnerDecision { decided_at: t0() },
        lock_behavior: Default::default(),
        connection: Default::default(),
    }
}

fn history(rev: u64, cause: PolicyChangeCause) -> PolicyHistoryEntry {
    PolicyHistoryEntry {
        policy: PolicyId::parse("pol").unwrap(),
        revision: PolicyRevision(rev),
        record: policy(rev),
        cause,
        at: plus(t0(), i64::try_from(rev).unwrap()),
    }
}

fn cooldown(key: &str, policy: &str, until_secs: i64) -> DecisionCooldown {
    DecisionCooldown {
        key: key.into(),
        policy: PolicyId::parse(policy).unwrap(),
        revision: PolicyRevision(1),
        environment: env_id(7),
        decision: DecisionId::from_random_bytes([3; 16]),
        until: plus(t0(), until_secs),
    }
}

fn slot_ref(binding: &BindingId, deadline_secs: i64) -> SlotReference {
    SlotReference {
        environment: env_id(7),
        destination: DestinationId::parse("h1").unwrap(),
        account: AccountName::parse("u1").unwrap(),
        binding: binding.clone(),
        deadline: plus(t0(), deadline_secs),
        joined_at: t0(),
    }
}

fn is_conflict<T: std::fmt::Debug>(r: &Result<T, StoreError>) -> bool {
    matches!(r, Err(StoreError::GenerationConflict(_)))
}

fn is_missing<T: std::fmt::Debug>(r: &Result<T, StoreError>) -> bool {
    matches!(
        r,
        Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
    )
}

fn generation(tx: &mut Txn<'_>) -> u64 {
    tx.authority_generation().unwrap().0
}

// --- migration 0006 → 0008 -------------------------------------------------------------

/// A populated schema-6 file opens at the current schema in one open: backed up first,
/// every M01–M03 document byte-identical, the new tables empty, `bindings.context_json`
/// NULL (personal), the 0007 and 0008 accessors working, and no second migration.
#[test]
fn migration_0006_to_0008_keeps_m01_m03_rows_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.sqlite3");
    let own = env_id(7);
    let p = pair("h1", "u1");
    let (binding_id, enr_id);
    {
        let s6 = Store::open_at_schema_version(&db, Arc::new(NoFaults), 6).unwrap();
        assert_eq!(s6.schema_version().unwrap(), 6);
        (binding_id, enr_id) = s6
            .transaction(|tx| {
                tx.init_self_environment(&own)?;
                let b = grant_and_binding(tx, 1, 1);
                tx.upsert_identity(&identity(1))?;
                tx.upsert_destination(&destination(1))?;
                tx.insert_issuer(&issuer(1))?;
                let e = enrollment(1, &ca(1), &p);
                tx.insert_enrollment(&e)?;
                Ok((b, e.id))
            })
            .unwrap();
    }
    const RAW: [RawDocuments; 4] = [
        RawDocuments::Meta,
        RawDocuments::Destinations,
        RawDocuments::Identities,
        RawDocuments::Enrollments,
    ];
    type Snapshot = (
        Vec<Vec<(String, String)>>,
        Vec<BindingRecord>,
        Vec<IssuerRecord>,
    );
    let snapshot = |s: &Store| -> Snapshot {
        s.transaction(|tx| {
            let mut raw = Vec::new();
            for which in RAW {
                raw.push(tx.raw_documents(which)?);
            }
            let bindings = tx.binding(&binding_id)?.into_iter().collect();
            Ok((raw, bindings, tx.issuers()?))
        })
        .unwrap()
    };
    let before = snapshot(&Store::open_at_schema_version(&db, Arc::new(NoFaults), 6).unwrap());
    assert!(before.0.iter().all(|rows| !rows.is_empty()) && before.1.len() == 1);

    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 8);
    let mut backup = db.as_os_str().to_owned();
    backup.push(".v6.backup");
    assert!(PathBuf::from(backup).exists(), "v6 file backed up first");
    assert_eq!(
        snapshot(&s),
        before,
        "every M01–M03 document is byte-identical"
    );

    s.transaction(|tx| {
        // The new tables start empty; the old binding has no context (personal).
        assert!(tx.managed_environments()?.is_empty());
        assert!(tx.wsl_distributions()?.is_empty());
        assert!(tx.workspaces_in_environment(&own)?.is_empty());
        assert!(
            tx.policy_history(&PolicyId::parse("pol").unwrap())?
                .is_empty()
        );
        assert!(tx.decision_cooldown("k")?.is_none());
        assert!(tx.slot_references_for_binding(&binding_id)?.is_empty());
        assert!(tx.work_stop(&own, &WorkId::parse("w").unwrap())?.is_none());
        assert_eq!(tx.binding_context(&binding_id)?, None);
        // The 0007 and 0008 accessors work on the migrated file.
        tx.insert_managed_environment(&managed(8, 7, ManagedState::Active))?;
        assert_eq!(tx.managed_set(&own)?, vec![own.clone(), env_id(8)]);
        tx.put_wsl_distribution(&wsl_record(8))?;
        assert_eq!(tx.wsl_distribution(&guid(8))?, Some(wsl_record(8)));
        tx.insert_workspace(&workspace(1, 7))?;
        tx.set_binding_context(&binding_id, &BindingContext::Personal)?;
        tx.add_slot_reference(&slot_ref(&binding_id, 600))?;
        assert_eq!(
            tx.binding_context(&binding_id)?,
            Some(BindingContext::Personal)
        );
        assert!(tx.enrollment(&enr_id)?.is_some());
        Ok(())
    })
    .unwrap();
    drop(s);

    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    let mut second = db.as_os_str().to_owned();
    second.push(".v6.backup.1");
    assert!(!PathBuf::from(second).exists(), "no second migration");
    assert_eq!(
        s.transaction(|tx| tx.workspaces_in_environment(&own))
            .unwrap()
            .len(),
        1
    );
}

// --- ext_m04 ---------------------------------------------------------------------------

/// Admission, the terminal states, the managed set, insert refusals, and which writes
/// move the authority generation (ADR-0010 §9 item 1).
#[test]
fn managed_environment_admission_terminal_states_and_generation() {
    let s = mem();
    s.transaction(|tx| {
        let own = env_id(1);
        tx.init_self_environment(&own)?;
        let admit = |tx: &mut Txn<'_>, t: u8| tx.admit_environment(&own, &env_id(t)).unwrap();
        assert_eq!(admit(tx, 1), EnvironmentAdmission::Managed, "own");
        assert_eq!(admit(tx, 2), EnvironmentAdmission::Unmanaged, "no row");

        let g0 = generation(tx);
        tx.insert_managed_environment(&managed(2, 1, ManagedState::Active))?;
        tx.insert_managed_environment(&managed(3, 1, ManagedState::NotRunning))?;
        // Rows controlled by another runtime are never ours, in any state.
        tx.insert_managed_environment(&managed(4, 9, ManagedState::Active))?;
        tx.insert_managed_environment(&managed(5, 9, ManagedState::Removed))?;
        assert_eq!(generation(tx), g0 + 4, "each insert moves the generation");
        assert_eq!(admit(tx, 2), EnvironmentAdmission::Managed);
        assert_eq!(
            admit(tx, 3),
            EnvironmentAdmission::Managed,
            "not running is in the set"
        );
        assert_eq!(
            admit(tx, 4),
            EnvironmentAdmission::Unmanaged,
            "another controller"
        );
        assert_eq!(
            admit(tx, 5),
            EnvironmentAdmission::Unmanaged,
            "another controller, removed"
        );
        assert_eq!(
            tx.managed_set(&own)?,
            vec![own.clone(), env_id(2), env_id(3)]
        );
        assert_eq!(tx.managed_environments()?.len(), 4, "every state is listed");

        // Refused writes move nothing: a duplicate (a removed identity is never re-added)
        // and the runtime's own environment.
        let g = generation(tx);
        let before = tx.managed_environments()?;
        assert!(is_conflict(&tx.insert_managed_environment(&managed(
            2,
            1,
            ManagedState::Active
        ))));
        assert!(is_conflict(&tx.insert_managed_environment(&managed(
            1,
            1,
            ManagedState::Active
        ))));
        assert_eq!(generation(tx), g);
        assert_eq!(tx.managed_environments()?, before);

        // State moves: stale expectation and missing rows write nothing.
        let at = plus(t0(), 5);
        let id = env_id(2);
        assert!(is_conflict(&tx.set_managed_environment_state(
            &id,
            ManagedState::NotRunning,
            ManagedState::Removed,
            at
        )));
        assert!(is_missing(&tx.set_managed_environment_state(
            &env_id(60),
            ManagedState::Active,
            ManagedState::Removed,
            at
        )));
        assert_eq!(generation(tx), g);

        let moved = tx.set_managed_environment_state(
            &id,
            ManagedState::Active,
            ManagedState::NotRunning,
            at,
        )?;
        assert_eq!(
            (moved.state, moved.updated_at),
            (ManagedState::NotRunning, at)
        );
        assert_eq!(generation(tx), g + 1, "a state move moves the generation");
        tx.set_managed_environment_state(&id, ManagedState::NotRunning, ManagedState::Removed, at)?;
        assert_eq!(admit(tx, 2), EnvironmentAdmission::Removed);
        assert!(!tx.managed_set(&own)?.contains(&id));

        // Removed never returns; `removed → gone` is allowed; gone is final.
        let g = generation(tx);
        for to in [ManagedState::Active, ManagedState::NotRunning] {
            assert!(is_conflict(&tx.set_managed_environment_state(
                &id,
                ManagedState::Removed,
                to,
                at
            )));
        }
        assert_eq!(generation(tx), g, "refused moves write nothing");
        assert_eq!(
            tx.managed_environment(&id)?.unwrap().state,
            ManagedState::Removed
        );
        tx.set_managed_environment_state(&id, ManagedState::Removed, ManagedState::Gone, at)?;
        assert_eq!(
            admit(tx, 2),
            EnvironmentAdmission::Removed,
            "gone is removed too"
        );
        assert!(is_conflict(&tx.set_managed_environment_state(
            &id,
            ManagedState::Gone,
            ManagedState::Active,
            at
        )));
        assert_eq!(generation(tx), g + 1);
        Ok(())
    })
    .unwrap();
}

// --- ext_m05 ---------------------------------------------------------------------------

/// The 0008 accessors' compare-and-swap and insert-once rules, and which writes move the
/// authority generation (ADR-0011 §9 "Store").
#[test]
fn trusted_work_records_cas_once_rules_and_generation() {
    let s = mem();
    s.transaction(|tx| {
        let own = env_id(7);
        tx.init_self_environment(&own)?;

        // Workspaces: insert-once, listed by environment, `active → stale` only.
        let g = generation(tx);
        tx.insert_workspace(&workspace(1, 7))?;
        tx.insert_workspace(&workspace(2, 7))?;
        tx.insert_workspace(&workspace(3, 8))?;
        assert_eq!(generation(tx), g + 3);
        assert!(is_conflict(&tx.insert_workspace(&workspace(1, 7))));
        assert_eq!(generation(tx), g + 3, "a duplicate writes nothing");
        let ids = |v: Vec<WorkspaceRecord>| v.into_iter().map(|w| w.id).collect::<Vec<_>>();
        assert_eq!(
            ids(tx.workspaces_in_environment(&own)?),
            vec![workspace(1, 7).id, workspace(2, 7).id]
        );
        let ws1 = workspace(1, 7).id;
        assert_eq!(tx.workspace(&ws1)?, Some(workspace(1, 7)));
        assert!(is_conflict(&tx.set_workspace_state(
            &ws1,
            WorkspaceState::Stale,
            WorkspaceState::Active
        )));
        assert!(is_missing(&tx.set_workspace_state(
            &WorkspaceId::from_random_bytes([99; 16]),
            WorkspaceState::Active,
            WorkspaceState::Stale
        )));
        assert_eq!(generation(tx), g + 3, "refused changes write nothing");
        let stale = tx.set_workspace_state(&ws1, WorkspaceState::Active, WorkspaceState::Stale)?;
        assert_eq!(stale.state, WorkspaceState::Stale);
        assert_eq!(tx.workspace(&ws1)?.unwrap().state, WorkspaceState::Stale);
        assert_eq!(generation(tx), g + 4);
        // A stale record never returns to active, even with the right expectation.
        assert!(is_conflict(&tx.set_workspace_state(
            &ws1,
            WorkspaceState::Stale,
            WorkspaceState::Active
        )));
        assert_eq!(tx.workspace(&ws1)?.unwrap().state, WorkspaceState::Stale);

        // Work stops: insert-once, never deleted, move the generation.
        let work = WorkId::parse("work-1").unwrap();
        let stop = WorkStop {
            environment: own.clone(),
            work_id: work.clone(),
            stopped_at: t0(),
        };
        let g = generation(tx);
        assert_eq!(tx.work_stop(&own, &work)?, None);
        tx.insert_work_stop(&stop)?;
        assert_eq!(tx.work_stop(&own, &work)?, Some(stop.clone()));
        assert_eq!(generation(tx), g + 1);
        let later = WorkStop {
            stopped_at: plus(t0(), 9),
            ..stop.clone()
        };
        assert!(is_conflict(&tx.insert_work_stop(&later)));
        assert_eq!(
            tx.work_stop(&own, &work)?,
            Some(stop),
            "the first stop stands"
        );
        assert_eq!(tx.work_stop(&env_id(8), &work)?, None, "per environment");
        assert_eq!(generation(tx), g + 1);

        // The bookkeeping below moves nothing.
        let g = generation(tx);

        // Policy history: one entry per (policy, revision), listed oldest first.
        let pol = PolicyId::parse("pol").unwrap();
        let decision = PolicyChangeCause::Decision {
            decision: DecisionId::from_random_bytes([5; 16]),
        };
        tx.append_policy_history(&history(2, PolicyChangeCause::Narrowing))?;
        tx.append_policy_history(&history(1, decision.clone()))?;
        assert!(is_conflict(
            &tx.append_policy_history(&history(2, decision))
        ));
        let listed = tx.policy_history(&pol)?;
        assert_eq!(
            listed.iter().map(|h| h.revision.0).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            listed[1].cause,
            PolicyChangeCause::Narrowing,
            "the first write stands"
        );
        assert_eq!(tx.policy_history_entry(&pol, PolicyRevision(3))?, None);
        assert!(
            tx.policy_history(&PolicyId::parse("other").unwrap())?
                .is_empty()
        );

        // Cooldowns: put replaces by key, delete reports, listed per policy.
        tx.put_decision_cooldown(&cooldown("k1", "pol", 60))?;
        tx.put_decision_cooldown(&cooldown("k2", "pol", 60))?;
        tx.put_decision_cooldown(&cooldown("k3", "other", 60))?;
        tx.put_decision_cooldown(&cooldown("k1", "pol", 120))?;
        assert_eq!(
            tx.decision_cooldown("k1")?,
            Some(cooldown("k1", "pol", 120))
        );
        let keys = |v: Vec<DecisionCooldown>| v.into_iter().map(|c| c.key).collect::<Vec<_>>();
        assert_eq!(keys(tx.decision_cooldowns_for_policy(&pol)?), ["k1", "k2"]);
        assert!(tx.delete_decision_cooldown("k1")?);
        assert!(!tx.delete_decision_cooldown("k1")?);
        assert_eq!(tx.decision_cooldown("k1")?, None);
        assert_eq!(keys(tx.decision_cooldowns_for_policy(&pol)?), ["k2"]);
        assert_eq!(generation(tx), g, "history and cooldowns move nothing");

        // Slot references and binding context need a binding.
        let b1 = grant_and_binding(tx, 1, 1);
        let b2 = {
            let bd = binding(2, &grant(1).id);
            tx.insert_binding(&bd)?;
            bd.id
        };
        let g = generation(tx);
        let (d, a) = (
            DestinationId::parse("h1").unwrap(),
            AccountName::parse("u1").unwrap(),
        );
        tx.add_slot_reference(&slot_ref(&b1, 600))?;
        tx.add_slot_reference(&slot_ref(&b2, 900))?;
        assert!(is_conflict(&tx.add_slot_reference(&slot_ref(&b1, 1200))));
        let missing = BindingId::from_random_bytes([77; 16]);
        assert!(matches!(
            tx.add_slot_reference(&slot_ref(&missing, 600)),
            Err(StoreError::Sqlite(_))
        ));
        let refs = tx.slot_references(&own, &d, &a)?;
        assert_eq!(
            refs,
            vec![slot_ref(&b1, 600), slot_ref(&b2, 900)],
            "first write stands"
        );
        assert_eq!(
            tx.slot_references_for_binding(&b2)?,
            vec![slot_ref(&b2, 900)]
        );
        assert!(tx.remove_slot_reference(&own, &d, &a, &b1)?);
        assert!(!tx.remove_slot_reference(&own, &d, &a, &b1)?);
        assert_eq!(tx.slot_references(&own, &d, &a)?, vec![slot_ref(&b2, 900)]);
        assert!(tx.slot_references_for_binding(&b1)?.is_empty());

        // Binding context: set once; the same value again is a no-op.
        let ws = BindingContext::Workspace {
            workspace: ws1.clone(),
        };
        assert_eq!(tx.binding_context(&b1)?, None);
        assert_eq!(tx.binding_context(&missing)?, None);
        assert!(is_missing(&tx.set_binding_context(&missing, &ws)));
        tx.set_binding_context(&b1, &ws)?;
        tx.set_binding_context(&b1, &ws)?;
        assert!(is_conflict(
            &tx.set_binding_context(&b1, &BindingContext::Personal)
        ));
        assert_eq!(tx.binding_context(&b1)?, Some(ws));
        assert_eq!(
            tx.binding_context(&b2)?,
            None,
            "another binding is untouched"
        );
        assert_eq!(
            tx.binding(&b1)?,
            Some(binding(1, &grant(1).id)),
            "the record is untouched"
        );

        // Slot references and binding context move nothing.
        assert_eq!(generation(tx), g);
        Ok(())
    })
    .unwrap();
}
