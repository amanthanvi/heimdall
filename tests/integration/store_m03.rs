//! M03 wave 0 (U0b row 15; m03-plan §5 item 18, U0 "migration 0005→0006"): the
//! managed-credential store methods of `heimdall_store::ext_m03`, one test per method
//! group (compare-and-swap success and failure, uniqueness, foreign keys, generation
//! moves), the restart marking of credential instances (U0b row 8), and migration 0006
//! on a populated schema-5 database.
//!
//! Every value is synthetic (fixture IDs, `example.invalid` hosts, fake public keys);
//! no owner key, agent or keychain is touched. Errors pass through
//! `heimdall_testkit::assert_no_canary`.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heimdall_contract::canonical::RequestHash;
use heimdall_contract::catalog::DeclaredInteraction;
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, ConnectionId, CredentialInstanceId, DecisionId,
    DestinationId, EnrollmentId, EnvironmentId, ForeignRemovalId, GrantId, IdentityId, IssuanceId,
    OperationId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{Capability, DeadlineIntent};
use heimdall_contract::setup::{PlanDigest, PreviewIntent, ProjectionItem};
use heimdall_contract::{GrantState, OperationState, Timestamp};
use heimdall_domain::binding::{BindingRecord, BindingState};
use heimdall_domain::catalog::{
    DeclarationState, DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
    InteractionDeclaration, InteractionProfile,
};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentEventKind, EnrollmentForm, EnrollmentRecord,
    EnrollmentState, ExistingAccessRecord, ForeignRemovalRecord, ForeignRemovalTarget, NoProxy,
    PairPreference, PreferredMechanism, ProjectionStatus, RegistryCanonical, RegistryRef,
    RegistryResolvedBy, marker_for,
};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
use heimdall_domain::issuance::{
    CaEvent, CertificateBounds, CredentialInstance, CredentialState, IssuanceEntry,
    IssuanceRefusal, IssuanceState,
};
use heimdall_domain::managed::{
    ConnectionKind, OwnedConnection, OwnedConnectionState, SlotRefusal, SlotState,
};
use heimdall_domain::operation::{
    AdapterIdentity, EffectClass, EffectReceipt, ItemPhase, LocalIntent, LocalReceipt,
    OperationKind, OperationRecord, RecoveryIntent, RecoveryMetadata, STAGE_SETUP_ITEM,
    StageReceipt,
};
use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::projection::{
    Base, BehaviorState, ConsentRecord, ConsentedStates, FileIdentity, FileRole, FileStep,
    ItemCommit, ItemId, ItemRecord, ProjectionLocator, ProjectionRecord, Rendered, SetupIntent,
    Sha256Hex, Target,
};
use heimdall_domain::revocation::{
    CleanupIntent, PendingRemoteRevocation, RemoteObligation, Tombstone,
};
use heimdall_domain::scope::{AccessPair, Scope};
use heimdall_domain::time::Deadline;
use heimdall_domain::verification::{VerificationEntry, VerificationPurpose, VerificationRefusal};
use heimdall_store::{
    IssuerRecord, NoFaults, RawDocuments, SetupAdmitted, Store, StoreError, Txn,
    migrations::SCHEMA_VERSION,
};
use heimdall_testkit::assert_no_canary;

// --- fixtures --------------------------------------------------------------------------

fn t0() -> Timestamp {
    "2026-11-01T00:00:00Z".parse().unwrap()
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

fn op_id(n: u8) -> OperationId {
    OperationId::from_random_bytes([n; 16])
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn ca(n: u8) -> CaFingerprint {
    let c = char::from(b'A' + n % 26);
    CaFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
}

fn issuer(n: u8, state: CaState) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: ca(n),
        public_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture{n}"),
        state,
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

fn with_state(mut r: EnrollmentRecord, state: EnrollmentState) -> EnrollmentRecord {
    r.state = state;
    r
}

fn scope(pairs: &[(&str, &str)]) -> Scope {
    Scope {
        pairs: pairs.iter().map(|(d, a)| pair(d, a)).collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    }
}

fn grant(b: u8) -> GrantSnapshot {
    GrantSnapshot {
        id: GrantId::from_random_bytes([b; 16]),
        environment: env_id(7),
        scope: scope(&[("h1", "u1")]),
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

fn caller() -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    }
}

fn binding(b: u8, grant: &GrantId) -> BindingRecord {
    BindingRecord {
        id: BindingId::from_random_bytes([b; 16]),
        environment: env_id(7),
        grant: grant.clone(),
        work_id: WorkId::parse("w").unwrap(),
        owner: caller(),
        profile: ProfileId::parse("default").unwrap(),
        profile_revision: 1,
        scope: scope(&[("h1", "u1")]),
        mechanism: "managed_certificate".into(),
        parent: None,
        created_at: plus(t0(), i64::from(b)),
        released_at: None,
        state: BindingState::Active,
    }
}

/// A grant `g` with binding `b` on it.
fn grant_and_binding(tx: &mut Txn<'_>, g: u8, b: u8) -> (GrantId, BindingId) {
    let gr = grant(g);
    tx.insert_grant(&gr).unwrap();
    let bd = binding(b, &gr.id);
    tx.insert_binding(&bd).unwrap();
    (gr.id, bd.id)
}

fn bounds(
    n: u8,
    pair: &AccessPair,
    ca: Option<CaFingerprint>,
    valid_before: Timestamp,
) -> CertificateBounds {
    CertificateBounds {
        serial: u64::from(n),
        key_id: format!("key-{n}"),
        principal: format!("hm:{}:{}", pair.destination, pair.account),
        valid_after: t0(),
        valid_before,
        extensions: BTreeSet::new(),
        subject_fingerprint: "SHA256:synthetic".into(),
        ca_fingerprint: ca,
    }
}

fn verification(
    n: u8,
    op: &OperationId,
    pair: &AccessPair,
    ca: &CaFingerprint,
    valid_before: Timestamp,
) -> VerificationEntry {
    VerificationEntry {
        id: IssuanceId::from_random_bytes([n; 16]),
        operation: op.clone(),
        pair: pair.clone(),
        purpose: VerificationPurpose::Positive,
        bounds: bounds(n, pair, Some(ca.clone()), valid_before),
        state: IssuanceState::Reserved,
        reserved_at: plus(t0(), i64::from(n)),
        settled_at: None,
        void_reason: None,
    }
}

fn issuance(
    n: u8,
    grant: &GrantId,
    pair: &AccessPair,
    ca: Option<CaFingerprint>,
    valid_before: Timestamp,
) -> IssuanceEntry {
    IssuanceEntry {
        id: IssuanceId::from_random_bytes([n; 16]),
        grant: grant.clone(),
        generation: AuthorityGeneration(0),
        pair: pair.clone(),
        bounds: bounds(n, pair, ca, valid_before),
        state: IssuanceState::Reserved,
        reserved_at: plus(t0(), i64::from(n)),
        settled_at: None,
        void_reason: None,
    }
}

fn connection(n: u8, binding: &BindingId, grant: &GrantId, generation: u64) -> OwnedConnection {
    OwnedConnection {
        id: ConnectionId::from_random_bytes([n; 16]),
        kind: ConnectionKind::Master,
        binding: binding.clone(),
        grant: grant.clone(),
        pid: 4242,
        start_token: format!("start-{n}"),
        image: "/usr/bin/ssh".into(),
        control_path: Some("/scratch/run/mux/dest1".into()),
        generation,
        state: OwnedConnectionState::Up,
        started_at: plus(t0(), i64::from(n)),
    }
}

fn foreign(n: u8, form: EnrollmentForm) -> ForeignRemovalRecord {
    ForeignRemovalRecord {
        id: ForeignRemovalId::from_random_bytes([n; 16]),
        target: ForeignRemovalTarget {
            local_alias: "work".into(),
            bundle_destination_id: "dest9".into(),
            bundle_hostname: "example.invalid".into(),
            bundle_port: 22,
            account: AccountName::parse("git").unwrap(),
            marker: marker_for(&EnrollmentId::from_random_bytes([0xee; 16])),
            ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIforeignca".into(),
            line_sha256: "cd".repeat(32),
            registry: RegistryCanonical {
                path: Some("/home/git/.ssh/authorized_keys".into()),
                resolved_by: RegistryResolvedBy::Explicit,
            },
            form,
        },
        state: EnrollmentState::Planned,
        operation: op_id(n),
        created_at: plus(t0(), i64::from(n)),
        removal_origin: None,
    }
}

fn instance(
    n: u8,
    grant: &GrantId,
    state: CredentialState,
    certificates: Vec<IssuanceId>,
) -> CredentialInstance {
    CredentialInstance {
        id: CredentialInstanceId::from_random_bytes([n; 16]),
        grant: grant.clone(),
        key_handle_ref: format!("vault-slot-{n}"),
        certificates,
        state,
    }
}

fn is_conflict<T: std::fmt::Debug>(r: &Result<T, StoreError>) -> bool {
    matches!(r, Err(StoreError::GenerationConflict(_)))
}

fn is_missing<T: std::fmt::Debug>(r: &Result<T, StoreError>) -> bool {
    matches!(
        r,
        Err(StoreError::Sqlite(rusqlite_no_rows)) if rusqlite_no_rows.to_string().contains("no rows")
    )
}

fn is_foreign_key<T: std::fmt::Debug>(r: &Result<T, StoreError>) -> bool {
    matches!(r, Err(StoreError::Sqlite(e)) if e.to_string().contains("FOREIGN KEY"))
}

// --- issuers ---------------------------------------------------------------------------

/// `insert_issuer`, `issuer`, `issuers`: registration is `pending` or `active`, once
/// per fingerprint; listing is in registration order.
#[test]
fn insert_issuer_get_and_list() {
    let s = mem();
    s.transaction(|tx| {
        assert_eq!(tx.issuer(&ca(1))?, None);
        tx.insert_issuer(&issuer(2, CaState::Pending))?;
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let dup = tx.insert_issuer(&issuer(1, CaState::Active));
        assert!(is_conflict(&dup), "{dup:?}");
        no_canary(&dup);
        for state in [
            CaState::Retiring,
            CaState::Unloaded,
            CaState::Deleted,
            CaState::Retired,
        ] {
            assert!(tx.insert_issuer(&issuer(3, state)).is_err(), "{state:?}");
        }
        let mut retired = issuer(4, CaState::Active);
        retired.retired_at = Some(t0());
        assert!(tx.insert_issuer(&retired).is_err());
        assert_eq!(tx.issuer(&ca(1))?, Some(issuer(1, CaState::Active)));
        let listed: Vec<CaFingerprint> = tx
            .issuers()?
            .into_iter()
            .map(|i| i.ca_fingerprint)
            .collect();
        assert_eq!(listed, [ca(1), ca(2)], "registration order");
        Ok(())
    })
    .unwrap();
}

/// `set_issuer_state`: a CAS on the expected state along `ca_transition`; a stale
/// expectation is a conflict, a refused event the inner error, and `retired` stamps
/// `retired_at`.
#[test]
fn set_issuer_state_cas_along_ca_transition() {
    let s = mem();
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Pending))?;
        let missing = tx.set_issuer_state(&ca(9), CaState::Active, CaEvent::RetireApproved, t0());
        assert!(is_missing(&missing), "{missing:?}");
        // Stale expectation: nothing written.
        let stale = tx.set_issuer_state(&ca(1), CaState::Active, CaEvent::RetireApproved, t0());
        assert!(is_conflict(&stale), "{stale:?}");
        // Refused by the table: nothing written.
        let refused =
            tx.set_issuer_state(&ca(1), CaState::Pending, CaEvent::UnloadConfirmed, t0())?;
        assert!(refused.is_err());
        assert_eq!(tx.issuer(&ca(1))?.unwrap().state, CaState::Pending);
        let active = tx
            .set_issuer_state(
                &ca(1),
                CaState::Pending,
                CaEvent::FirstEnrollmentVerified,
                t0(),
            )?
            .unwrap();
        assert_eq!(active.state, CaState::Active);
        let steps = [
            (CaState::Active, CaEvent::RetireApproved, CaState::Retiring),
            (
                CaState::Retiring,
                CaEvent::UnloadConfirmed,
                CaState::Unloaded,
            ),
            (
                CaState::Unloaded,
                CaEvent::StoreItemDeleted,
                CaState::Deleted,
            ),
            (
                CaState::Deleted,
                CaEvent::RetirementRecorded,
                CaState::Retired,
            ),
        ];
        for (i, (from, event, to)) in steps.into_iter().enumerate() {
            let at = plus(t0(), 10 + i64::try_from(i).unwrap());
            let r = tx.set_issuer_state(&ca(1), from, event, at)?.unwrap();
            assert_eq!(r.state, to);
            assert_eq!(r.retired_at, (to == CaState::Retired).then_some(at));
            assert_eq!(tx.issuer(&ca(1))?, Some(r));
        }
        // `retired` is final.
        assert!(
            tx.set_issuer_state(&ca(1), CaState::Retired, CaEvent::RetireApproved, t0())?
                .is_err()
        );
        Ok(())
    })
    .unwrap();
}

// --- enrollments -----------------------------------------------------------------------

/// `insert_enrollment`: `planned` only, the marker is `heimdall:<id>`, and the CA must
/// be registered (the `enrollments → issuers` foreign key).
#[test]
fn insert_enrollment_requires_planned_marker_and_registered_ca() {
    let s = mem();
    let p = pair("dest1", "git");
    let fk = s.transaction(|tx| tx.insert_enrollment(&enrollment(1, &ca(1), &p)));
    assert!(is_foreign_key(&fk), "{fk:?}");
    no_canary(&fk);
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let mut bad_marker = enrollment(1, &ca(1), &p);
        bad_marker.marker = "heimdall:enr_other".into();
        assert!(tx.insert_enrollment(&bad_marker).is_err());
        let verified = with_state(enrollment(1, &ca(1), &p), EnrollmentState::Verified);
        assert!(tx.insert_enrollment(&verified).is_err(), "planned only");
        tx.insert_enrollment(&enrollment(1, &ca(1), &p))?;
        assert_eq!(
            tx.enrollment(&enrollment(1, &ca(1), &p).id)?,
            Some(enrollment(1, &ca(1), &p))
        );
        // Test seeding skips only the `planned` rule.
        tx.insert_issuer(&issuer(2, CaState::Active))?;
        tx.seed_enrollment(&with_state(
            enrollment(2, &ca(2), &p),
            EnrollmentState::Verified,
        ))?;
        assert!(
            tx.seed_enrollment(&enrollment(3, &ca(9), &p)).is_err(),
            "FK still applies"
        );
        Ok(())
    })
    .unwrap();
}

/// Uniqueness: the ID (and with it the marker), and one live enrollment per (pair,
/// CA). The partial index covers only the enrollment-path states (S1 ruling), so a
/// re-enrollment after a final state or `abandoned` is admitted.
#[test]
fn enrollment_uniqueness_partial_index_admits_reenrollment_after_abandoned() {
    let s = mem();
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        tx.insert_issuer(&issuer(2, CaState::Active))?;
        tx.insert_enrollment(&enrollment(1, &ca(1), &p))?;
        let dup_id = tx.insert_enrollment(&enrollment(1, &ca(2), &pair("dest2", "git")));
        assert!(is_conflict(&dup_id), "{dup_id:?}");
        // Another CA or another pair is a different key.
        tx.insert_enrollment(&enrollment(3, &ca(2), &p))?;
        tx.insert_enrollment(&enrollment(4, &ca(1), &pair("dest1", "deploy")))?;
        // planned → withdrawn (final): a new one is admitted.
        let first = enrollment(1, &ca(1), &p);
        tx.transition_enrollment(
            EnrollmentState::Planned,
            EnrollmentEventKind::DecisionWithdrawn,
            &first,
        )?
        .unwrap();
        tx.insert_enrollment(&enrollment(5, &ca(1), &p))?;
        // Drive 5 to `abandoned` (planned → applying → outcome_unknown → abandoned).
        let five = enrollment(5, &ca(1), &p);
        for (from, kind) in [
            (
                EnrollmentState::Planned,
                EnrollmentEventKind::EnrollAccountApproved,
            ),
            (
                EnrollmentState::Applying,
                EnrollmentEventKind::AppendOutcomeLost,
            ),
            (
                EnrollmentState::OutcomeUnknown,
                EnrollmentEventKind::OwnerAbandon,
            ),
        ] {
            tx.transition_enrollment(from, kind, &five)?.unwrap();
        }
        assert_eq!(
            tx.enrollment(&five.id)?.unwrap().state,
            EnrollmentState::Abandoned
        );
        // `abandoned` is not live: a re-enrollment is admitted.
        tx.insert_enrollment(&enrollment(6, &ca(1), &p))?;
        Ok(())
    })
    .unwrap();
}

/// S1 ruling, point 1: every enrollment-path state is live, so a second live
/// enrollment for the same (pair, CA) is refused whichever path state either is in,
/// and a move back onto the path that would collide fails cleanly (account form:
/// `abandoned → removing → held`).
#[test]
fn second_live_enrollment_for_pair_and_ca_still_refused() {
    let s = mem();
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let live = [
            EnrollmentState::Planned,
            EnrollmentState::Applying,
            EnrollmentState::OutcomeUnknown,
            EnrollmentState::AppliedUnverified,
            EnrollmentState::ManualPending,
            EnrollmentState::Verifying,
            EnrollmentState::Verified,
            EnrollmentState::Reverifying,
            EnrollmentState::Held,
        ];
        for (i, state) in live.into_iter().enumerate() {
            let n = u8::try_from(i).unwrap();
            let q = pair(&format!("dest{}", 10 + n), "git");
            let mut first = with_state(enrollment(10 + n, &ca(1), &q), state);
            if state == EnrollmentState::ManualPending {
                first.form = EnrollmentForm::System;
            }
            tx.seed_enrollment(&first)?;
            let second = tx.insert_enrollment(&enrollment(40 + n, &ca(1), &q));
            assert!(is_conflict(&second), "{state:?}: {second:?}");
            no_canary(&second);
        }
        // Not live: removal, rollback, abandoned and final states never block.
        let not_live = [
            EnrollmentState::RollbackPending,
            EnrollmentState::RollbackUnknown,
            EnrollmentState::Removing,
            EnrollmentState::RemoveUnknown,
            EnrollmentState::Abandoned,
            EnrollmentState::VerificationFailed,
            EnrollmentState::Removed,
            EnrollmentState::Withdrawn,
            EnrollmentState::FailedUnwritten,
        ];
        for (i, state) in not_live.into_iter().enumerate() {
            let n = u8::try_from(i).unwrap();
            let q = pair(&format!("dest{}", 60 + n), "git");
            tx.seed_enrollment(&with_state(enrollment(60 + n, &ca(1), &q), state))?;
            tx.insert_enrollment(&enrollment(90 + n, &ca(1), &q))?;
        }
        for (n, state) in [
            (120, EnrollmentState::ManualRemovalPending),
            (121, EnrollmentState::RemovalVerifying),
        ] {
            let q = pair(&format!("dest{n}"), "git");
            let mut rec = with_state(enrollment(n, &ca(1), &q), state);
            rec.form = EnrollmentForm::System;
            tx.seed_enrollment(&rec)?;
            tx.insert_enrollment(&enrollment(n + 10, &ca(1), &q))?;
        }
        // A `held` removal residual (`removal_origin` set) beside a live enrollment is
        // allowed (S1 follow-up); leaving it onto the enrollment path would make a
        // second live record and fails cleanly.
        let old = with_state(enrollment(1, &ca(1), &p), EnrollmentState::Abandoned);
        tx.seed_enrollment(&old)?;
        tx.insert_enrollment(&enrollment(2, &ca(1), &p))?;
        let mut removal = old.clone();
        removal.removal_origin = Some(heimdall_domain::enrollment::RemovalOrigin {
            state: EnrollmentState::Abandoned,
            evidence: None,
            hold: None,
            ca_not_held_seen: false,
        });
        tx.transition_enrollment(
            EnrollmentState::Abandoned,
            EnrollmentEventKind::RemoveEnrollmentApproved,
            &removal,
        )?
        .unwrap();
        tx.transition_enrollment(
            EnrollmentState::Removing,
            EnrollmentEventKind::RemovalHeld,
            &removal,
        )?
        .unwrap();
        let onto_path = tx.transition_enrollment(
            EnrollmentState::Held,
            EnrollmentEventKind::ManualRecoveryLinePresent {
                hold: heimdall_domain::enrollment::HoldKind::LockHolderUnresolved,
                // M03 wave 0 (A1): §17.15 X-Q3 field; `append` is the pre-ruling meaning.
                purpose: heimdall_domain::enrollment::RecoveryPurpose::Append,
            },
            &removal,
        );
        assert!(is_conflict(&onto_path), "{onto_path:?}");
        assert_eq!(
            tx.enrollment(&old.id)?.unwrap().state,
            EnrollmentState::Held,
            "nothing written"
        );
        // A `held` reached on the enrollment path (no removal origin) still blocks.
        let q = pair("dest200", "git");
        let path_held = with_state(enrollment(200, &ca(1), &q), EnrollmentState::Held);
        assert_eq!(path_held.removal_origin, None);
        tx.seed_enrollment(&path_held)?;
        assert!(is_conflict(&tx.insert_enrollment(&enrollment(
            201,
            &ca(1),
            &q
        ))));
        Ok(())
    })
    .unwrap();
}

/// S1 follow-up ruling: `held` reached by a removal is a residual, not a live
/// enrollment, so a removal of an abandoned line that ends in `held` sits beside the
/// pair's new live enrollment for the same CA without a conflict.
#[test]
fn removal_held_residual_outside_index_beside_live_enrollment() {
    use heimdall_domain::enrollment::RemovalOrigin;
    let s = mem();
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let old = with_state(enrollment(1, &ca(1), &p), EnrollmentState::Abandoned);
        tx.seed_enrollment(&old)?;
        tx.insert_enrollment(&enrollment(2, &ca(1), &p))?;
        let mut removal = old.clone();
        removal.removal_origin = Some(RemovalOrigin {
            state: EnrollmentState::Abandoned,
            evidence: None,
            hold: None,
            ca_not_held_seen: false,
        });
        tx.transition_enrollment(
            EnrollmentState::Abandoned,
            EnrollmentEventKind::RemoveEnrollmentApproved,
            &removal,
        )?
        .unwrap();
        let held = tx.transition_enrollment(
            EnrollmentState::Removing,
            EnrollmentEventKind::RemovalHeld,
            &removal,
        );
        assert!(matches!(held, Ok(Ok(_))), "{held:?}");
        let stored = tx.enrollment(&old.id)?.unwrap();
        assert_eq!(stored.state, EnrollmentState::Held);
        assert!(stored.removal_origin.is_some());
        // The residual can be removed again, still beside the live enrollment.
        let again = tx
            .transition_enrollment(
                EnrollmentState::Held,
                EnrollmentEventKind::RemoveEnrollmentApproved,
                &removal,
            )?
            .unwrap();
        assert_eq!(again.state, EnrollmentState::Removing);
        let states: Vec<EnrollmentState> = tx
            .enrollments_for_pair(&p)?
            .into_iter()
            .map(|r| r.state)
            .collect();
        assert_eq!(
            states,
            [EnrollmentState::Removing, EnrollmentState::Planned]
        );
        Ok(())
    })
    .unwrap();
}

/// S1 ruling, point 1: a removal in progress is not a live enrollment, so the
/// abandoned line can be removed while the pair's new enrollment is live.
#[test]
fn removing_abandoned_line_while_new_enrollment_open_is_allowed() {
    let s = mem();
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let old = with_state(enrollment(1, &ca(1), &p), EnrollmentState::Abandoned);
        tx.seed_enrollment(&old)?;
        tx.seed_enrollment(&with_state(
            enrollment(2, &ca(1), &p),
            EnrollmentState::Verified,
        ))?;
        let removing = tx
            .transition_enrollment(
                EnrollmentState::Abandoned,
                EnrollmentEventKind::RemoveEnrollmentApproved,
                &old,
            )?
            .unwrap();
        assert_eq!(removing.state, EnrollmentState::Removing);
        let lost = tx
            .transition_enrollment(
                EnrollmentState::Removing,
                EnrollmentEventKind::RemovalOutcomeLost,
                &old,
            )?
            .unwrap();
        assert_eq!(lost.state, EnrollmentState::RemoveUnknown);
        let removed = tx
            .transition_enrollment(
                EnrollmentState::RemoveUnknown,
                EnrollmentEventKind::ReconcileApplied,
                &old,
            )?
            .unwrap();
        assert_eq!(removed.state, EnrollmentState::Removed);
        assert_eq!(
            tx.verified_cas_for_pair(&p)?,
            [ca(1)].into_iter().collect(),
            "the new enrollment stays the pair's live one"
        );
        Ok(())
    })
    .unwrap();
}

/// S1 ruling, point 2 (§17.4 item 5): cancelling a manual removal returns the row to
/// its persisted `removal_origin`. From `abandoned` that is outside the index, so it
/// succeeds beside a live enrollment; a cancel naming another origin is refused; and
/// a cancel back onto the enrollment path that would collide fails cleanly.
#[test]
fn cancelling_that_removal_returns_to_abandoned() {
    use heimdall_domain::enrollment::RemovalOrigin;
    let s = mem();
    let p = pair("dest1", "git");
    let system = |r: EnrollmentRecord| EnrollmentRecord {
        form: EnrollmentForm::System,
        ..r
    };
    let origin = |state| RemovalOrigin {
        state,
        evidence: None,
        hold: None,
        ca_not_held_seen: false,
    };
    let cancel = |state| EnrollmentEventKind::OwnerCancelsManualRemoval {
        origin: state,
        ca_not_held_seen: false,
    };
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let old = system(with_state(
            enrollment(1, &ca(1), &p),
            EnrollmentState::Abandoned,
        ));
        tx.seed_enrollment(&old)?;
        tx.seed_enrollment(&with_state(
            enrollment(2, &ca(1), &p),
            EnrollmentState::Verified,
        ))?;
        let mut pending = old.clone();
        pending.removal_origin = Some(origin(EnrollmentState::Abandoned));
        let r = tx
            .transition_enrollment(
                EnrollmentState::Abandoned,
                EnrollmentEventKind::ManualRemovalConfirmed,
                &pending,
            )?
            .unwrap();
        assert_eq!(r.state, EnrollmentState::ManualRemovalPending);
        // A cancel naming an origin other than the persisted one is refused.
        let wrong = tx.transition_enrollment(
            EnrollmentState::ManualRemovalPending,
            cancel(EnrollmentState::Verified),
            &pending,
        )?;
        assert!(wrong.is_err());
        assert_eq!(
            tx.enrollment(&old.id)?.unwrap().state,
            EnrollmentState::ManualRemovalPending
        );
        let back = tx
            .transition_enrollment(
                EnrollmentState::ManualRemovalPending,
                cancel(EnrollmentState::Abandoned),
                &pending,
            )?
            .unwrap();
        assert_eq!(back.state, EnrollmentState::Abandoned);
        assert_eq!(tx.enrollment(&old.id)?, Some(back));

        // From a `verified` origin the row was the pair's one live enrollment. If a new
        // one was admitted meanwhile, the cancel back to `verified` fails cleanly.
        let q = pair("dest2", "git");
        let v = system(with_state(
            enrollment(3, &ca(1), &q),
            EnrollmentState::Verified,
        ));
        tx.seed_enrollment(&v)?;
        let mut v_pending = v.clone();
        v_pending.removal_origin = Some(origin(EnrollmentState::Verified));
        tx.transition_enrollment(
            EnrollmentState::Verified,
            EnrollmentEventKind::ManualRemovalConfirmed,
            &v_pending,
        )?
        .unwrap();
        tx.insert_enrollment(&enrollment(4, &ca(1), &q))?;
        let collide = tx.transition_enrollment(
            EnrollmentState::ManualRemovalPending,
            cancel(EnrollmentState::Verified),
            &v_pending,
        );
        assert!(is_conflict(&collide), "{collide:?}");
        assert_eq!(
            tx.enrollment(&v.id)?.unwrap().state,
            EnrollmentState::ManualRemovalPending,
            "nothing written"
        );
        Ok(())
    })
    .unwrap();
}

/// `enrollment`, `enrollment_by_marker`, `enrollments_for_pair`, `enrollments_for_ca`.
#[test]
fn enrollment_reads_by_id_marker_pair_and_ca() {
    let s = mem();
    let (p, q) = (pair("dest1", "git"), pair("dest2", "git"));
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        tx.insert_issuer(&issuer(2, CaState::Pending))?;
        tx.insert_enrollment(&enrollment(3, &ca(2), &p))?;
        tx.insert_enrollment(&enrollment(1, &ca(1), &p))?;
        tx.insert_enrollment(&enrollment(2, &ca(1), &q))?;
        let one = enrollment(1, &ca(1), &p);
        assert_eq!(tx.enrollment(&one.id)?, Some(one.clone()));
        assert_eq!(tx.enrollment_by_marker(&one.marker)?, Some(one.clone()));
        assert_eq!(tx.enrollment_by_marker("heimdall:enr_absent")?, None);
        let ids = |v: Vec<EnrollmentRecord>| v.into_iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(
            ids(tx.enrollments_for_pair(&p)?),
            [one.id.clone(), enrollment(3, &ca(2), &p).id],
            "oldest first"
        );
        assert_eq!(
            ids(tx.enrollments_for_ca(&ca(1))?),
            [one.id, enrollment(2, &ca(1), &q).id]
        );
        assert!(tx.enrollments_for_pair(&pair("dest3", "git"))?.is_empty());
        Ok(())
    })
    .unwrap();
}

/// `transition_enrollment`: a CAS on the stored state that calls the D5 §6.2 table.
#[test]
fn transition_enrollment_cas_calls_the_domain_table() {
    let s = mem();
    let p = pair("dest1", "git");
    let rec = enrollment(1, &ca(1), &p);
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let missing = tx.transition_enrollment(
            EnrollmentState::Planned,
            EnrollmentEventKind::EnrollAccountApproved,
            &rec,
        );
        assert!(is_missing(&missing), "{missing:?}");
        tx.insert_enrollment(&rec)?;
        // Stale expectation.
        let stale = tx.transition_enrollment(
            EnrollmentState::Applying,
            EnrollmentEventKind::AppendConfirmed,
            &rec,
        );
        assert!(is_conflict(&stale), "{stale:?}");
        // Refused by the table: the inner error, nothing written.
        let refused = tx.transition_enrollment(
            EnrollmentState::Planned,
            EnrollmentEventKind::AppendConfirmed,
            &rec,
        )?;
        let e = refused.unwrap_err();
        assert_eq!(e.from, EnrollmentState::Planned);
        assert_eq!(tx.enrollment(&rec.id)?, Some(rec.clone()));
        // Identity fields never change.
        let mut moved = rec.clone();
        moved.ca_fingerprint = ca(2);
        assert!(
            tx.transition_enrollment(
                EnrollmentState::Planned,
                EnrollmentEventKind::EnrollAccountApproved,
                &moved,
            )
            .is_err()
        );
        // The caller's `state` is replaced by the table's target.
        let mut updated = with_state(rec.clone(), EnrollmentState::Removed);
        updated.updated_at = plus(t0(), 100);
        let applying = tx
            .transition_enrollment(
                EnrollmentState::Planned,
                EnrollmentEventKind::EnrollAccountApproved,
                &updated,
            )?
            .unwrap();
        assert_eq!(applying.state, EnrollmentState::Applying);
        assert_eq!(applying.updated_at, plus(t0(), 100));
        assert_eq!(tx.enrollment(&rec.id)?, Some(applying.clone()));
        for (from, kind) in [
            (
                EnrollmentState::Applying,
                EnrollmentEventKind::AppendConfirmed,
            ),
            (
                EnrollmentState::AppliedUnverified,
                EnrollmentEventKind::StartVerification,
            ),
        ] {
            tx.transition_enrollment(from, kind, &applying)?.unwrap();
        }
        let mut passed = applying.clone();
        passed.verified_at = Some(plus(t0(), 200));
        let verified = tx
            .transition_enrollment(
                EnrollmentState::Verifying,
                EnrollmentEventKind::VerificationResult {
                    verdict: heimdall_domain::verification::VerificationVerdict::Passed,
                    approval_valid: true,
                },
                &passed,
            )?
            .unwrap();
        assert_eq!(verified.state, EnrollmentState::Verified);
        assert_eq!(
            tx.enrollment(&rec.id)?.unwrap().verified_at,
            Some(plus(t0(), 200))
        );
        Ok(())
    })
    .unwrap();
}

/// `open_enrollments` (verify-doc E12): every non-final enrollment, `abandoned`
/// included; a schema without the `enrollments` table has none.
#[test]
fn open_enrollments_lists_non_final_including_abandoned() {
    let s = mem();
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        for (n, state) in [
            (1, EnrollmentState::Verified),
            (2, EnrollmentState::Abandoned),
            (3, EnrollmentState::Removed),
            (4, EnrollmentState::Withdrawn),
            (5, EnrollmentState::Held),
        ] {
            tx.seed_enrollment(&with_state(
                enrollment(n, &ca(1), &pair(&format!("dest{n}"), "git")),
                state,
            ))?;
        }
        tx.insert_enrollment(&enrollment(6, &ca(1), &pair("dest6", "git")))?;
        let open: Vec<EnrollmentState> = tx
            .open_enrollments()?
            .into_iter()
            .map(|r| r.state)
            .collect();
        assert_eq!(
            open,
            [
                EnrollmentState::Verified,
                EnrollmentState::Abandoned,
                EnrollmentState::Held,
                EnrollmentState::Planned
            ]
        );
        Ok(())
    })
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("v5.sqlite3");
    let s5 = Store::open_at_schema_version(&db, Arc::new(NoFaults), 5).unwrap();
    assert!(
        s5.transaction(|tx| tx.open_enrollments())
            .unwrap()
            .is_empty()
    );
}

/// `verified_cas_for_pair`: the CAs with a `verified` enrollment for the pair.
#[test]
fn verified_cas_for_pair_counts_only_verified() {
    let s = mem();
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        for n in 1..=4 {
            tx.insert_issuer(&issuer(n, CaState::Active))?;
        }
        tx.seed_enrollment(&with_state(
            enrollment(1, &ca(1), &p),
            EnrollmentState::Verified,
        ))?;
        tx.seed_enrollment(&with_state(
            enrollment(2, &ca(2), &p),
            EnrollmentState::Verified,
        ))?;
        tx.seed_enrollment(&with_state(
            enrollment(3, &ca(3), &p),
            EnrollmentState::Reverifying,
        ))?;
        tx.seed_enrollment(&with_state(
            enrollment(4, &ca(4), &p),
            EnrollmentState::Held,
        ))?;
        tx.seed_enrollment(&with_state(
            enrollment(5, &ca(4), &pair("dest2", "git")),
            EnrollmentState::Verified,
        ))?;
        assert_eq!(
            tx.verified_cas_for_pair(&p)?,
            [ca(1), ca(2)].into_iter().collect()
        );
        assert!(tx.verified_cas_for_pair(&pair("dest9", "git"))?.is_empty());
        Ok(())
    })
    .unwrap();
}

// --- verification issuance -------------------------------------------------------------

/// `reserve_verification`, `publish_verification`, `void_verification`,
/// `verification_entries`: insert reserved with a CA; settle once by CAS.
#[test]
fn verification_reserve_publish_void_and_entries() {
    let s = mem();
    let p = pair("dest1", "git");
    let op = op_id(1);
    s.transaction(|tx| {
        let v1 = verification(1, &op, &p, &ca(1), plus(t0(), 300));
        tx.reserve_verification(&v1)?;
        assert!(is_conflict(&tx.reserve_verification(&v1)));
        let mut no_ca = verification(2, &op, &p, &ca(1), plus(t0(), 300));
        no_ca.bounds.ca_fingerprint = None;
        assert!(tx.reserve_verification(&no_ca).is_err());
        let mut published = verification(3, &op, &p, &ca(1), plus(t0(), 300));
        published.state = IssuanceState::Published;
        assert!(tx.reserve_verification(&published).is_err());
        let v2 = verification(4, &op, &p, &ca(1), plus(t0(), 300));
        tx.reserve_verification(&v2)?;
        tx.reserve_verification(&verification(5, &op_id(2), &p, &ca(1), plus(t0(), 300)))?;

        let out = tx.publish_verification(&v1.id, plus(t0(), 10))?;
        assert_eq!(out.state, IssuanceState::Published);
        assert_eq!(out.settled_at, Some(plus(t0(), 10)));
        assert!(is_conflict(
            &tx.publish_verification(&v1.id, plus(t0(), 11))
        ));
        assert!(is_conflict(&tx.void_verification(
            &v1.id,
            VerificationRefusal::TimeUncertain,
            plus(t0(), 11)
        )));
        let voided =
            tx.void_verification(&v2.id, VerificationRefusal::TooManyEntries, plus(t0(), 12))?;
        assert_eq!(voided.state, IssuanceState::Voided);
        assert_eq!(
            voided.void_reason,
            Some(VerificationRefusal::TooManyEntries)
        );
        assert!(is_missing(&tx.publish_verification(
            &IssuanceId::from_random_bytes([9; 16]),
            t0()
        )));
        let entries = tx.verification_entries(&op)?;
        assert_eq!(
            entries,
            [out, voided],
            "reservation order, this operation only"
        );
        Ok(())
    })
    .unwrap();
}

/// `pair_residual` (ADR-0008 D7 item 4; U0b row 4's
/// `verification_entries_counted_in_pair_residual` at the store level): the latest
/// `valid_before` over the pair's counted grant and verification entries, per CA.
#[test]
fn pair_residual_counts_grant_and_verification_entries_per_ca() {
    let s = mem();
    let (p, q) = (pair("dest1", "git"), pair("dest2", "git"));
    let g = GrantId::from_random_bytes([1; 16]);
    s.transaction(|tx| {
        assert_eq!(tx.pair_residual(&p, None)?, None);
        // An M01 entry (no CA) and an M03 entry under ca(1).
        tx.reserve_issuance(&issuance(1, &g, &p, None, plus(t0(), 100)))?;
        tx.reserve_issuance(&issuance(2, &g, &p, Some(ca(1)), plus(t0(), 200)))?;
        // Another pair, and a voided entry, never count.
        tx.reserve_issuance(&issuance(3, &g, &q, Some(ca(1)), plus(t0(), 9000)))?;
        let voided = issuance(4, &g, &p, Some(ca(1)), plus(t0(), 8000));
        tx.reserve_issuance(&voided)?;
        tx.void_issuance(&voided.id, &IssuanceRefusal::TimeUncertain, t0())?;
        assert_eq!(tx.pair_residual(&p, Some(&ca(1)))?, Some(plus(t0(), 200)));
        assert_eq!(tx.pair_residual(&p, None)?, Some(plus(t0(), 200)));
        assert_eq!(tx.pair_residual(&p, Some(&ca(2)))?, None);
        // A verification entry counts while reserved and published, not voided.
        let v = verification(5, &op_id(1), &p, &ca(2), plus(t0(), 300));
        tx.reserve_verification(&v)?;
        assert_eq!(tx.pair_residual(&p, Some(&ca(2)))?, Some(plus(t0(), 300)));
        assert_eq!(tx.pair_residual(&p, None)?, Some(plus(t0(), 300)));
        tx.publish_verification(&v.id, t0())?;
        assert_eq!(tx.pair_residual(&p, None)?, Some(plus(t0(), 300)));
        let w = verification(6, &op_id(1), &p, &ca(1), plus(t0(), 7000));
        tx.reserve_verification(&w)?;
        assert_eq!(tx.pair_residual(&p, Some(&ca(1)))?, Some(plus(t0(), 7000)));
        tx.void_verification(&w.id, VerificationRefusal::TimeUncertain, t0())?;
        assert_eq!(tx.pair_residual(&p, Some(&ca(1)))?, Some(plus(t0(), 200)));
        assert_eq!(tx.pair_residual(&q, None)?, Some(plus(t0(), 9000)));
        Ok(())
    })
    .unwrap();
}

// --- pair preferences ------------------------------------------------------------------

/// `set_pair_preference`, `pair_preference`, `add_issuing_ca`, `remove_issuing_ca`
/// (U0b row 22, F05).
#[test]
fn pair_preference_round_trip_and_issuing_ca_set() {
    let s = mem();
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        assert_eq!(tx.pair_preference(&p)?, None);
        assert!(is_missing(&tx.add_issuing_ca(&p, &ca(1), t0())));
        assert!(!tx.remove_issuing_ca(&p, &ca(1), t0())?);
        let pending = PairPreference {
            destination: p.destination.clone(),
            account: p.account.clone(),
            mechanism: PreferredMechanism::ManagedCertificate,
            projection: ProjectionStatus::Pending,
            issuing_cas: [ca(1)].into_iter().collect(),
        };
        tx.set_pair_preference(&pending, t0())?;
        assert_eq!(tx.pair_preference(&p)?, Some(pending.clone()));
        assert!(tx.add_issuing_ca(&p, &ca(2), t0())?);
        assert!(!tx.add_issuing_ca(&p, &ca(2), t0())?, "already present");
        assert!(tx.remove_issuing_ca(&p, &ca(1), t0())?);
        assert!(!tx.remove_issuing_ca(&p, &ca(1), t0())?);
        let stored = tx.pair_preference(&p)?.unwrap();
        assert_eq!(stored.issuing_cas, [ca(2)].into_iter().collect());
        assert_eq!(stored.mechanism, PreferredMechanism::ManagedCertificate);
        assert_eq!(stored.projection, ProjectionStatus::Pending, "untouched");
        let applied = PairPreference {
            mechanism: PreferredMechanism::Existing,
            projection: ProjectionStatus::Applied { generation: 7 },
            ..stored
        };
        tx.set_pair_preference(&applied, plus(t0(), 1))?;
        assert_eq!(tx.pair_preference(&p)?, Some(applied));
        assert_eq!(tx.pair_preference(&pair("dest1", "deploy"))?, None);
        Ok(())
    })
    .unwrap();
}

// --- managed slots ---------------------------------------------------------------------

/// `claim_slot` (CAS free → held), `release_slot` (CAS by generation),
/// `slot_files_removed`, `slot`: the generation moves on every claim and survives
/// every state; the binding must exist.
#[test]
fn slot_claim_release_cas_and_generation_moves() {
    let s = mem();
    let env = env_id(7);
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        let (_, b1) = grant_and_binding(tx, 1, 1);
        let (_, b2) = grant_and_binding(tx, 2, 2);
        assert_eq!(tx.slot(&env, &p)?, SlotState::Free { generation: 0 });
        let ghost = BindingId::from_random_bytes([99; 16]);
        assert!(is_foreign_key(&tx.claim_slot(&env, &p, &ghost, t0())));
        assert_eq!(tx.slot(&env, &p)?, SlotState::Free { generation: 0 });

        let held = SlotState::Held {
            binding: b1.clone(),
            generation: 1,
        };
        assert_eq!(tx.claim_slot(&env, &p, &b1, t0())?, Ok(held.clone()));
        assert_eq!(
            tx.claim_slot(&env, &p, &b1, t0())?,
            Ok(held.clone()),
            "idempotent"
        );
        assert_eq!(
            tx.claim_slot(&env, &p, &b2, t0())?,
            Err(SlotRefusal::ManagedSlotHeld)
        );
        // Release: a stale generation is a conflict; another holder is refused.
        assert!(is_conflict(&tx.release_slot(&env, &p, &b1, 0, t0())));
        assert_eq!(
            tx.release_slot(&env, &p, &b2, 1, t0())?,
            Err(SlotRefusal::StaleGeneration)
        );
        assert_eq!(tx.slot(&env, &p)?, held);
        assert_eq!(
            tx.release_slot(&env, &p, &b1, 1, t0())?,
            Ok(SlotState::Clearing { generation: 1 })
        );
        assert_eq!(
            tx.claim_slot(&env, &p, &b2, t0())?,
            Err(SlotRefusal::NotApplicable)
        );
        assert_eq!(
            tx.release_slot(&env, &p, &b1, 1, t0())?,
            Err(SlotRefusal::NotApplicable)
        );
        assert!(is_conflict(&tx.slot_files_removed(&env, &p, 2, t0())));
        assert_eq!(
            tx.slot_files_removed(&env, &p, 1, t0())?,
            Ok(SlotState::Free { generation: 1 })
        );
        assert_eq!(
            tx.slot_files_removed(&env, &p, 1, t0())?,
            Err(SlotRefusal::NotApplicable)
        );
        // The next claim moves the generation.
        assert_eq!(
            tx.claim_slot(&env, &p, &b2, plus(t0(), 5))?,
            Ok(SlotState::Held {
                binding: b2.clone(),
                generation: 2
            })
        );
        // Another environment's slot for the same pair is independent.
        assert_eq!(tx.slot(&env_id(8), &p)?, SlotState::Free { generation: 0 });
        assert_eq!(
            tx.release_slot(&env_id(8), &p, &b2, 0, t0())?,
            Err(SlotRefusal::NotApplicable)
        );
        Ok(())
    })
    .unwrap();
}

/// `slots_for_binding`: the slots a binding holds or is clearing, never free ones.
#[test]
fn slots_for_binding_lists_held_and_clearing() {
    let s = mem();
    let env = env_id(7);
    s.transaction(|tx| {
        let (_, b1) = grant_and_binding(tx, 1, 1);
        let (_, b2) = grant_and_binding(tx, 2, 2);
        let (p, q, r) = (
            pair("dest1", "git"),
            pair("dest2", "git"),
            pair("dest3", "git"),
        );
        tx.claim_slot(&env, &p, &b1, t0())?.unwrap();
        tx.claim_slot(&env, &q, &b1, plus(t0(), 1))?.unwrap();
        tx.claim_slot(&env, &r, &b1, t0())?.unwrap();
        tx.claim_slot(&env_id(8), &p, &b2, t0())?.unwrap();
        tx.release_slot(&env, &q, &b1, 1, plus(t0(), 2))?.unwrap();
        tx.release_slot(&env, &r, &b1, 1, t0())?.unwrap();
        tx.slot_files_removed(&env, &r, 1, t0())?.unwrap();
        let slots = tx.slots_for_binding(&b1)?;
        let got: Vec<(AccessPair, SlotState)> = slots
            .iter()
            .map(|s| (s.pair.clone(), s.state.clone()))
            .collect();
        assert_eq!(
            got,
            [
                (
                    p,
                    SlotState::Held {
                        binding: b1.clone(),
                        generation: 1
                    }
                ),
                (q, SlotState::Clearing { generation: 1 }),
            ]
        );
        assert!(
            slots
                .iter()
                .all(|s| s.environment == env && s.binding.as_ref() == Some(&b1))
        );
        assert_eq!(slots[1].updated_at, plus(t0(), 2));
        assert_eq!(tx.slots_for_binding(&b2)?.len(), 1);
        Ok(())
    })
    .unwrap();
}

// --- owned connections -----------------------------------------------------------------

/// `insert_owned_connection`, `owned_connection`, `owned_connections_for_grant`,
/// `owned_connections_for_binding`, `close_owned_connection` (CAS by generation).
#[test]
fn owned_connection_insert_and_close_by_generation() {
    let s = mem();
    s.transaction(|tx| {
        let (g, b) = grant_and_binding(tx, 1, 1);
        let ghost_g = GrantId::from_random_bytes([98; 16]);
        let ghost_b = BindingId::from_random_bytes([99; 16]);
        assert!(is_foreign_key(
            &tx.insert_owned_connection(&connection(1, &b, &ghost_g, 1))
        ));
        assert!(is_foreign_key(
            &tx.insert_owned_connection(&connection(1, &ghost_b, &g, 1))
        ));
        let mut closing = connection(1, &b, &g, 1);
        closing.state = OwnedConnectionState::Closing;
        assert!(tx.insert_owned_connection(&closing).is_err(), "inserted up");
        let master1 = connection(1, &b, &g, 1);
        tx.insert_owned_connection(&master1)?;
        assert!(is_conflict(&tx.insert_owned_connection(&master1)));
        assert_eq!(tx.owned_connection(&master1.id)?, Some(master1.clone()));

        // Generation protection: closing master 1 with generation 2 is a conflict.
        assert!(is_conflict(&tx.close_owned_connection(
            &master1.id,
            2,
            OwnedConnectionState::Closing
        )));
        assert!(
            tx.close_owned_connection(&master1.id, 1, OwnedConnectionState::Up)
                .is_err(),
            "never back to up"
        );
        let c = tx.close_owned_connection(&master1.id, 1, OwnedConnectionState::Closing)?;
        assert_eq!(c.state, OwnedConnectionState::Closing);
        assert_eq!(
            c.generation, 1,
            "the generation is the master's, never moved here"
        );
        let c = tx.close_owned_connection(&master1.id, 1, OwnedConnectionState::Closed)?;
        assert_eq!(c.state, OwnedConnectionState::Closed);
        assert_eq!(
            tx.close_owned_connection(&master1.id, 1, OwnedConnectionState::Closed)?,
            c,
            "idempotent"
        );
        assert!(is_conflict(&tx.close_owned_connection(
            &master1.id,
            1,
            OwnedConnectionState::Closing
        )));
        assert!(is_missing(&tx.close_owned_connection(
            &ConnectionId::from_random_bytes([77; 16]),
            1,
            OwnedConnectionState::Closed
        )));
        // The next master is generation 2.
        let master2 = connection(2, &b, &g, 2);
        tx.insert_owned_connection(&master2)?;
        let unverified =
            tx.close_owned_connection(&master2.id, 2, OwnedConnectionState::Unverified)?;
        assert_eq!(unverified.state, OwnedConnectionState::Unverified);
        let ids = |v: Vec<OwnedConnection>| v.into_iter().map(|c| c.id).collect::<Vec<_>>();
        assert_eq!(
            ids(tx.owned_connections_for_grant(&g)?),
            [master1.id.clone(), master2.id.clone()]
        );
        assert_eq!(
            ids(tx.owned_connections_for_binding(&b)?),
            [master1.id, master2.id]
        );
        assert!(tx.owned_connections_for_grant(&ghost_g)?.is_empty());
        Ok(())
    })
    .unwrap();
}

// --- foreign removals ------------------------------------------------------------------

/// `insert_foreign_removal`, `transition_foreign_removal`, `foreign_removal`,
/// `foreign_removals_by_marker`: no foreign key to `issuers` (F07), and the record
/// stays in the removal subset.
#[test]
fn foreign_removal_has_no_issuer_fk_and_stays_in_the_subset() {
    let s = mem();
    s.transaction(|tx| {
        assert!(tx.issuers()?.is_empty(), "no CA is registered here");
        let rec = foreign(1, EnrollmentForm::Account);
        tx.insert_foreign_removal(&rec)?;
        assert!(is_conflict(&tx.insert_foreign_removal(&rec)));
        let mut removing = foreign(2, EnrollmentForm::Account);
        removing.state = EnrollmentState::Removing;
        assert!(
            tx.insert_foreign_removal(&removing).is_err(),
            "inserted planned"
        );
        assert_eq!(tx.foreign_removal(&rec.id)?, Some(rec.clone()));

        // An own-record admission is refused for a foreign record (inner error).
        let refused = tx.transition_foreign_removal(
            EnrollmentState::Planned,
            EnrollmentEventKind::EnrollAccountApproved,
            &rec,
        )?;
        assert!(refused.is_err());
        let stale = tx.transition_foreign_removal(
            EnrollmentState::Removing,
            EnrollmentEventKind::RemovalConfirmed,
            &rec,
        );
        assert!(is_conflict(&stale), "{stale:?}");
        let mut other_target = rec.clone();
        other_target.target.line_sha256 = "00".repeat(32);
        assert!(
            tx.transition_foreign_removal(
                EnrollmentState::Planned,
                EnrollmentEventKind::RemoveEnrollmentApproved,
                &other_target,
            )
            .is_err()
        );
        let r = tx
            .transition_foreign_removal(
                EnrollmentState::Planned,
                EnrollmentEventKind::RemoveEnrollmentApproved,
                &rec,
            )?
            .unwrap();
        assert_eq!(r.state, EnrollmentState::Removing);
        // A later `RemoveEnrollment` may carry a new operation.
        let mut retry = r.clone();
        retry.operation = op_id(9);
        let lost = tx
            .transition_foreign_removal(
                EnrollmentState::Removing,
                EnrollmentEventKind::RemovalOutcomeLost,
                &retry,
            )?
            .unwrap();
        assert_eq!(
            (lost.state, lost.operation.clone()),
            (EnrollmentState::RemoveUnknown, op_id(9))
        );
        let done = tx
            .transition_foreign_removal(
                EnrollmentState::RemoveUnknown,
                EnrollmentEventKind::ReconcileApplied,
                &lost,
            )?
            .unwrap();
        assert_eq!(done.state, EnrollmentState::Removed);
        // A second attempt for the same marker is its own record.
        tx.insert_foreign_removal(&foreign(3, EnrollmentForm::System))?;
        let by_marker = tx.foreign_removals_by_marker(&rec.target.marker)?;
        assert_eq!(by_marker.len(), 2);
        assert_eq!(by_marker[0], done);
        assert!(
            tx.foreign_removals_by_marker("heimdall:enr_absent")?
                .is_empty()
        );
        Ok(())
    })
    .unwrap();
}

// --- lock disclosure and the acknowledged lock epoch -----------------------------------

/// `set_lock_disclosure_ack`, `lock_disclosure_ack`: recorded once, never repeated.
#[test]
fn lock_disclosure_ack_recorded_once() {
    let s = mem();
    s.transaction(|tx| {
        assert_eq!(tx.lock_disclosure_ack()?, None);
        assert_eq!(tx.set_lock_disclosure_ack(plus(t0(), 1))?, plus(t0(), 1));
        assert_eq!(tx.set_lock_disclosure_ack(plus(t0(), 2))?, plus(t0(), 1));
        assert_eq!(tx.lock_disclosure_ack()?, Some(plus(t0(), 1)));
        Ok(())
    })
    .unwrap();
}

/// `set_acknowledged_lock_epoch`, `acknowledged_lock_epoch` (§17.1 item 9): monotonic.
#[test]
fn acknowledged_lock_epoch_never_lowers() {
    let s = mem();
    s.transaction(|tx| {
        assert_eq!(tx.acknowledged_lock_epoch()?, None);
        assert_eq!(tx.set_acknowledged_lock_epoch(3)?, 3);
        assert_eq!(tx.set_acknowledged_lock_epoch(3)?, 3, "idempotent");
        assert!(is_conflict(&tx.set_acknowledged_lock_epoch(2)));
        assert_eq!(tx.set_acknowledged_lock_epoch(5)?, 5);
        assert_eq!(tx.acknowledged_lock_epoch()?, Some(5));
        Ok(())
    })
    .unwrap();
}

// --- restart: credential instances (U0b row 8) -----------------------------------------

/// U0b row 8 at the store level: `installed` instances without a live vault slot
/// become `lost`; live ones stay `installed`; destroyed ones are untouched.
#[test]
fn installed_instances_without_live_slot_become_lost() {
    let s = mem();
    let g = GrantId::from_random_bytes([1; 16]);
    s.transaction(|tx| {
        let gone = instance(1, &g, CredentialState::Installed, Vec::new());
        let live = instance(2, &g, CredentialState::Installed, Vec::new());
        let destroyed = instance(3, &g, CredentialState::Destroyed, Vec::new());
        for i in [&gone, &live, &destroyed] {
            tx.insert_credential_instance(i)?;
        }
        let live_ids: BTreeSet<CredentialInstanceId> = [live.id.clone()].into_iter().collect();
        let out = tx.mark_lost_instances(&live_ids)?;
        assert_eq!(out.lost.len(), 1);
        assert_eq!(out.lost[0].id, gone.id);
        assert_eq!(out.lost[0].state, CredentialState::Lost);
        assert!(out.destroyed.is_empty());
        assert_eq!(
            tx.credential_instance(&gone.id)?.unwrap().state,
            CredentialState::Lost
        );
        assert_eq!(tx.credential_instance(&live.id)?, Some(live));
        assert_eq!(tx.credential_instance(&destroyed.id)?, Some(destroyed));
        // Idempotent: a second pass changes nothing.
        let again = tx.mark_lost_instances(&live_ids)?;
        assert!(again.lost.is_empty() && again.destroyed.is_empty());
        Ok(())
    })
    .unwrap();
}

/// U0b row 8 (⟨r2⟩ F18) at the store level: every `pending` instance becomes
/// `destroyed` in the same call, and its `reserved`/`published` issuance entries stay
/// counted in the residual.
#[test]
fn pending_instances_destroyed_at_restart_entries_still_counted() {
    let s = mem();
    let g = GrantId::from_random_bytes([1; 16]);
    let p = pair("h1", "u1");
    s.transaction(|tx| {
        let reserved = issuance(1, &g, &p, Some(ca(1)), plus(t0(), 600));
        let published = issuance(2, &g, &p, Some(ca(1)), plus(t0(), 900));
        tx.reserve_issuance(&reserved)?;
        tx.reserve_issuance(&published)?;
        tx.publish_issuance(&published.id, t0())?;
        let pending = instance(
            1,
            &g,
            CredentialState::Pending,
            vec![reserved.id.clone(), published.id.clone()],
        );
        let installed = instance(2, &g, CredentialState::Installed, Vec::new());
        tx.insert_credential_instance(&pending)?;
        tx.insert_credential_instance(&installed)?;
        let before = (
            tx.issuance_residual(std::slice::from_ref(&g))?,
            tx.pair_residual(&p, None)?,
        );
        assert_eq!(before, (Some(plus(t0(), 900)), Some(plus(t0(), 900))));

        // Even an ID in the live set: a pending instance is destroyed at restart.
        let live: BTreeSet<CredentialInstanceId> = [pending.id.clone()].into_iter().collect();
        let out = tx.mark_lost_instances(&live)?;
        assert_eq!(out.destroyed.len(), 1);
        assert_eq!(out.destroyed[0].id, pending.id);
        assert_eq!(out.destroyed[0].state, CredentialState::Destroyed);
        assert_eq!(out.destroyed[0].certificates, pending.certificates);
        assert_eq!(
            out.lost.iter().map(|i| &i.id).collect::<Vec<_>>(),
            [&installed.id]
        );
        assert_eq!(
            tx.credential_instance(&pending.id)?.unwrap().state,
            CredentialState::Destroyed
        );
        // The entries are untouched and still counted.
        let states: Vec<IssuanceState> = tx
            .issuance_entries(&g)?
            .into_iter()
            .map(|e| e.state)
            .collect();
        assert_eq!(states, [IssuanceState::Reserved, IssuanceState::Published]);
        assert_eq!(
            (
                tx.issuance_residual(std::slice::from_ref(&g))?,
                tx.pair_residual(&p, None)?
            ),
            before
        );
        Ok(())
    })
    .unwrap();
}

// --- migration 0005 → 0006 -------------------------------------------------------------

fn file_db(dir: &Path) -> PathBuf {
    dir.join("state.sqlite3")
}

fn adapter() -> AdapterIdentity {
    AdapterIdentity {
        mechanism: "fake".into(),
        instance: "fake-1".into(),
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

fn endpoint(locator: &str) -> EndpointRef {
    EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: locator.into(),
    }
}

fn destination(n: u8, alias: &str) -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::parse(&format!("dest{n}")).unwrap(),
        alias: alias.into(),
        revision: 1,
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

fn identity(n: u8) -> IdentityRecord {
    let source = IdentitySource::NativeAgent {
        endpoint: endpoint("/scratch/agent.sock"),
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

fn declaration() -> InteractionDeclaration {
    InteractionDeclaration {
        revision: 1,
        state: DeclarationState::Live,
        interaction: DeclaredInteraction::None,
        fingerprint: "SHA256:fixture1".into(),
        endpoint: endpoint("/scratch/a.sock"),
        declared_at: t0(),
        expires_at: plus(t0(), 30 * 86_400),
        decision: DecisionId::from_random_bytes([5; 16]),
        ended_at: None,
        end_reason: None,
    }
}

const P: &[u8] = b"Host work\n  HostName example.invalid\n  IdentitiesOnly yes\n";

/// A queued `setup.apply` operation with its idempotency record and intent.
fn setup_op(env: &EnvironmentId) -> (OperationRecord, IdempotencyRecord, RecoveryIntent) {
    let kind = OperationKind::SetupApply;
    let key = IdempotencyKey {
        caller: caller(),
        kind,
        request_id: RequestId::parse("setup-1").unwrap(),
    };
    let op = OperationRecord {
        id: op_id(40),
        kind,
        environment: env.clone(),
        key: key.clone(),
        request_hash: RequestHash([4; 32]),
        effect_class: EffectClass::LocalResources,
        state: OperationState::Queued,
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
        created_at: op.created_at,
        expires_at: None,
    };
    let intent = SetupIntent {
        plan_digest: PlanDigest::from_sha256([1; 32]),
        intent: PreviewIntent::Apply { include_git: false },
        generation: 1,
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
            staged_name: Some(".heimdall.conf.hm-stage-00112233445566778899aabbccddeeff".into()),
            displaced_name: None,
        }],
    };
    let rec = RecoveryIntent {
        request: serde_json::json!({"action": kind.as_str(), "request_id": "setup-1"}),
        resolved: None,
        local: Some(LocalIntent::Setup(intent)),
    };
    (op, idem, rec)
}

fn item_commit(env: &EnvironmentId, op: &OperationId) -> (ItemCommit, StageReceipt) {
    let locator = |role, path: &str, ino| ProjectionLocator {
        role,
        path: path.into(),
        identity: FileIdentity::Unix {
            dev: 1,
            ino,
            birth: Some(7),
        },
        sha256: Sha256Hex::of(path.as_bytes()),
    };
    let resources = vec![
        locator(FileRole::ManagedSsh, "/scratch/ssh/heimdall.conf", 11),
        locator(FileRole::Key, "/scratch/ssh/heimdall/k1.pub", 21),
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
                generation: 1,
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
            credential_ref: "projection/ssh/1".into(),
        },
        local: Some(LocalReceipt::Item {
            item: ProjectionItem::Ssh,
            phase: ItemPhase::Committed { generation: 1 },
        }),
    };
    (
        ItemCommit {
            item: ProjectionItem::Ssh,
            generation: 1,
            resources,
            record,
            consent,
        },
        receipt,
    )
}

const RAW: [RawDocuments; 10] = [
    RawDocuments::StageReceipts,
    RawDocuments::RecoveryIntents,
    RawDocuments::Meta,
    RawDocuments::IssuanceLog,
    RawDocuments::CredentialInstances,
    RawDocuments::Destinations,
    RawDocuments::Identities,
    RawDocuments::InteractionDeclarations,
    RawDocuments::ProjectionRecords,
    RawDocuments::ProjectionConsent,
];

fn raw(s: &Store) -> Vec<Vec<(String, String)>> {
    s.transaction(|tx| {
        let mut out = Vec::new();
        for which in RAW.into_iter().chain([RawDocuments::Resources]) {
            out.push(tx.raw_documents(which)?);
        }
        Ok(out)
    })
    .unwrap()
}

/// Every stored document decodes as its type and re-encodes byte-identically.
macro_rules! reencodes {
    ($t:ty, $rows:expr) => {
        for (key, doc) in $rows {
            let v: $t = serde_json::from_str(doc).unwrap();
            assert_eq!(&serde_json::to_string(&v).unwrap(), doc, "{key}");
        }
    };
}

/// m03-plan U0: migration 0005→0006 on a populated database. The M01 and M02 rows
/// (issuance-log entries without `ca_fingerprint`, remote-revocation records in the
/// current and the legacy form, cleanup intents, catalog and projection rows, stage
/// receipts, recovery intents, credential instances) decode unchanged and re-encode
/// byte-identically; the file is backed up first; the new tables start empty.
#[test]
fn migration_0005_to_0006_keeps_m01_m02_rows_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    let env = env_id(40);
    let (r1, r2) = (
        GrantId::from_random_bytes([91; 16]),
        GrantId::from_random_bytes([92; 16]),
    );
    let g = GrantId::from_random_bytes([1; 16]);
    let p = pair("h1", "u1");
    {
        let s5 = Store::open_at_schema_version(&db, Arc::new(NoFaults), 5).unwrap();
        assert_eq!(s5.schema_version().unwrap(), 5);
        s5.transaction(|tx| {
            tx.init_self_environment(&env)?;
            // M01: issuance entries without a CA, credential instances.
            tx.reserve_issuance(&issuance(1, &g, &p, None, plus(t0(), 600)))?;
            let published = issuance(2, &g, &p, None, plus(t0(), 900));
            tx.reserve_issuance(&published)?;
            tx.publish_issuance(&published.id, t0())?;
            let voided = issuance(3, &g, &p, None, plus(t0(), 300));
            tx.reserve_issuance(&voided)?;
            tx.void_issuance(&voided.id, &IssuanceRefusal::TimeUncertain, t0())?;
            tx.insert_credential_instance(&instance(
                1,
                &g,
                CredentialState::Installed,
                vec![published.id.clone()],
            ))?;
            // M01: remote revocations (current and legacy form), cleanup intents.
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
                    kind: Default::default(),
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
                obligations: vec![RemoteObligation {
                    grant: r2.clone(),
                    adapter: adapter(),
                    reason: None,
                    attempts: None,
                    stopped: false,
                    effect_round: Some(2),
                    effect_seq: None,
                    kind: Default::default(),
                }],
                claimed_at: None,
                rearmed_effects: Vec::new(),
                cap: None,
                claim_seq: None,
            })?;
            for (grant, n, in_flight) in [(&r1, 81, true), (&r2, 82, false)] {
                tx.record_cleanup_intent(&CleanupIntent {
                    grant: grant.clone(),
                    operation: op_id(n),
                    adapter: Some(adapter()),
                    effect_token: format!("eff_{n}"),
                    confirmed: !in_flight,
                    in_flight,
                    version: 0,
                    recorded_at: plus(t0(), 4),
                })?;
            }
            // M02: catalog, declaration, projection (setup admission and an item commit).
            tx.upsert_identity(&identity(1))?;
            tx.upsert_destination(&destination(1, "work"))?;
            tx.put_interaction_declaration(
                &IdentityId::from_random_bytes([1; 16]),
                0,
                &declaration(),
            )?;
            let setup = setup_op(&env);
            assert_eq!(
                tx.insert_setup_operation(&setup.0, &setup.1, &setup.2, None)?,
                SetupAdmitted::Inserted
            );
            let (commit, receipt) = item_commit(&env, &setup.0.id);
            tx.commit_projection_item(&setup.0.id, &commit, &receipt)?;
            Ok(())
        })
        .unwrap();
    }
    let before = raw(&Store::open_at_schema_version(&db, Arc::new(NoFaults), 5).unwrap());
    for (which, rows) in RAW.iter().zip(&before) {
        assert!(!rows.is_empty(), "fixture populated {which:?}");
    }
    let typed = |s: &Store| {
        s.transaction(|tx| {
            Ok((
                tx.remote_revocations()?,
                tx.cleanup_intents()?,
                tx.issuance_entries(&g)?,
                tx.destinations()?,
                tx.identities()?,
                tx.projection_record(&env)?,
                tx.get_projection_consent(&env)?,
                tx.projection_resources(&env)?,
            ))
        })
        .unwrap()
    };
    let typed_before = typed(&Store::open_at_schema_version(&db, Arc::new(NoFaults), 5).unwrap());

    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 6);
    let mut backup = db.as_os_str().to_owned();
    backup.push(".v5.backup");
    assert!(PathBuf::from(backup).exists(), "v5 file backed up first");

    let after = raw(&s);
    assert_eq!(after, before, "every M01/M02 document is byte-identical");
    assert_eq!(typed(&s), typed_before, "and decodes unchanged");
    // Each document decodes with today's types and re-encodes byte-identically.
    reencodes!(StageReceipt, &after[0]);
    reencodes!(RecoveryIntent, &after[1]);
    for (key, doc) in &after[2] {
        if key.starts_with("remote_revocation:") {
            reencodes!(PendingRemoteRevocation, &[(key.clone(), doc.clone())]);
        } else if key.starts_with("cleanup_intent:") {
            reencodes!(CleanupIntent, &[(key.clone(), doc.clone())]);
        }
    }
    reencodes!(IssuanceEntry, &after[3]);
    for (_, doc) in &after[3] {
        assert!(
            !doc.contains("ca_fingerprint"),
            "an M01 entry carries no CA"
        );
    }
    reencodes!(CredentialInstance, &after[4]);
    reencodes!(DestinationRecord, &after[5]);
    reencodes!(IdentityRecord, &after[6]);
    reencodes!(InteractionDeclaration, &after[7]);
    reencodes!(ProjectionRecord, &after[8]);
    reencodes!(ConsentedStates, &after[9]);
    reencodes!(heimdall_domain::resource::ManagedResource, &after[10]);
    let (revocations, _, entries, ..) = typed(&s);
    assert!(entries.iter().all(|e| e.bounds.ca_fingerprint.is_none()));
    let legacy = revocations.iter().find(|r| r.root == r2).unwrap();
    assert_eq!(legacy.claim_seq, None, "the legacy form is kept as stored");
    assert_eq!(legacy.obligations[0].effect_round, Some(2));
    assert_eq!(
        s.transaction(|tx| tx.issuance_residual(std::slice::from_ref(&g)))
            .unwrap(),
        Some(plus(t0(), 900))
    );

    // The new tables start empty, and the M03 methods work on the migrated file.
    s.transaction(|tx| {
        assert!(tx.issuers()?.is_empty());
        assert!(tx.open_enrollments()?.is_empty());
        assert!(tx.enrollments_for_pair(&p)?.is_empty());
        assert_eq!(tx.pair_preference(&p)?, None);
        assert_eq!(tx.slot(&env, &p)?, SlotState::Free { generation: 0 });
        assert!(tx.owned_connections_for_grant(&g)?.is_empty());
        assert!(tx.foreign_removals_by_marker("heimdall:enr_x")?.is_empty());
        assert_eq!(tx.pair_residual(&p, None)?, Some(plus(t0(), 900)));
        assert_eq!(tx.acknowledged_lock_epoch()?, None);
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        tx.insert_enrollment(&enrollment(1, &ca(1), &p))?;
        Ok(())
    })
    .unwrap();
    drop(s);
    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    let mut second = db.as_os_str().to_owned();
    second.push(".v5.backup.1");
    assert!(!PathBuf::from(second).exists(), "no second migration");
    assert_eq!(s.transaction(|tx| tx.open_enrollments()).unwrap().len(), 1);
    // A read-only open sees the current schema.
    drop(s);
    let ro = Store::open_read_only(&db, Arc::new(NoFaults)).unwrap();
    assert_eq!(ro.transaction(|tx| tx.open_enrollments()).unwrap().len(), 1);
}

/// A newer `user_version` (7) is refused by both opens, and the file is untouched.
#[test]
fn newer_user_version_refused() {
    let dir = tempfile::tempdir().unwrap();
    let db = file_db(dir.path());
    let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
    s.transaction(|tx| tx.insert_issuer(&issuer(1, CaState::Active)))
        .unwrap();
    drop(s);
    let mut bytes = std::fs::read(&db).unwrap();
    // The SQLite header's user_version (offset 60, big-endian).
    bytes[60..64].copy_from_slice(&(SCHEMA_VERSION + 1).to_be_bytes());
    let newer = dir.path().join("newer.sqlite3");
    std::fs::write(&newer, &bytes).unwrap();
    let newer_ok = |e: &StoreError| {
        matches!(
            e,
            StoreError::NewerSchema {
                found: 7,
                supported: 6
            }
        )
    };
    let e = Store::open(&newer, Arc::new(NoFaults)).unwrap_err();
    assert!(newer_ok(&e), "{e}");
    no_canary(&e);
    let e = Store::open_read_only(&newer, Arc::new(NoFaults)).unwrap_err();
    assert!(newer_ok(&e), "{e}");
    assert_eq!(std::fs::read(&newer).unwrap(), bytes, "untouched");
    let mut backup = newer.as_os_str().to_owned();
    backup.push(".v7.backup");
    assert!(!PathBuf::from(backup).exists());
}

// --- ADR-0008 §17.16 (R5): absence history never downgrades ----------------------------

fn seen_origin(state: EnrollmentState, seen: bool) -> heimdall_domain::enrollment::RemovalOrigin {
    heimdall_domain::enrollment::RemovalOrigin {
        state,
        evidence: None,
        hold: None,
        ca_not_held_seen: seen,
    }
}

/// R5 (the reviewer's trace): a foreign system-form removal whose absence check ended
/// `ca_not_held` persists `ca_not_held_seen = true`; a cancel claiming `false` is
/// refused and writes nothing, and so is any later write that clears or resets the
/// pinned origin. The cancel with the persisted flag is admitted and keeps it.
#[test]
fn foreign_removal_cancel_cannot_downgrade_absence_history() {
    let s = mem();
    s.transaction(|tx| {
        let rec = foreign(1, EnrollmentForm::System);
        tx.insert_foreign_removal(&rec)?;
        let mut pending = rec.clone();
        pending.removal_origin = Some(seen_origin(EnrollmentState::Planned, false));
        for (from, kind) in [
            (
                EnrollmentState::Planned,
                EnrollmentEventKind::ManualRemovalConfirmed,
            ),
            (
                EnrollmentState::ManualRemovalPending,
                EnrollmentEventKind::OwnerConfirmsRemoved,
            ),
        ] {
            tx.transition_foreign_removal(from, kind, &pending)?
                .unwrap();
        }
        // The absence check cannot pass here: `ca_not_held`, recorded in the origin.
        let mut seen = pending.clone();
        seen.removal_origin = Some(seen_origin(EnrollmentState::Planned, true));
        tx.transition_foreign_removal(
            EnrollmentState::RemovalVerifying,
            EnrollmentEventKind::AbsenceNotVerified,
            &seen,
        )?
        .unwrap();
        let before = tx.foreign_removal(&rec.id)?.unwrap();
        let before_doc = serde_json::to_string(&before).unwrap();
        assert_eq!(before.state, EnrollmentState::ManualRemovalPending);
        assert!(before.removal_origin.as_ref().unwrap().ca_not_held_seen);

        // The trace: a cancel with `ca_not_held_seen: false` (and the record's flag
        // reset to match) is refused.
        let downgraded = tx.transition_foreign_removal(
            EnrollmentState::ManualRemovalPending,
            EnrollmentEventKind::OwnerCancelsManualRemoval {
                origin: EnrollmentState::Planned,
                ca_not_held_seen: false,
            },
            &pending,
        )?;
        assert!(
            downgraded.is_err(),
            "downgrading cancel admitted: {downgraded:?}"
        );
        let after = tx.foreign_removal(&rec.id)?.unwrap();
        assert_eq!(
            serde_json::to_string(&after).unwrap(),
            before_doc,
            "nothing written"
        );

        // Any other event whose record clears, resets or replaces the pinned origin.
        let mut cleared = before.clone();
        cleared.removal_origin = None;
        let mut moved = before.clone();
        moved.removal_origin = Some(seen_origin(EnrollmentState::Held, true));
        for bad in [&pending, &cleared, &moved] {
            let r = tx.transition_foreign_removal(
                EnrollmentState::ManualRemovalPending,
                EnrollmentEventKind::OwnerConfirmsRemoved,
                bad,
            )?;
            assert!(r.is_err(), "{:?}", bad.removal_origin);
            assert_eq!(
                serde_json::to_string(&tx.foreign_removal(&rec.id)?.unwrap()).unwrap(),
                before_doc
            );
        }
        // The cancel naming the persisted flag is admitted (never `planned`) and keeps it.
        let kept = tx
            .transition_foreign_removal(
                EnrollmentState::ManualRemovalPending,
                EnrollmentEventKind::OwnerCancelsManualRemoval {
                    origin: EnrollmentState::Planned,
                    ca_not_held_seen: true,
                },
                &before,
            )?
            .unwrap();
        assert_eq!(kept.state, EnrollmentState::ManualRemovalPending);
        assert_eq!(kept.removal_origin, before.removal_origin);
        Ok(())
    })
    .unwrap();
}

/// R5 for own enrollments (`transition_enrollment` had the same hole): once the
/// persisted origin has `ca_not_held_seen`, an `updated` record that clears or resets
/// it is refused whatever the event, and a cancel naming `false` is refused.
#[test]
fn enrollment_transition_cannot_downgrade_absence_history() {
    let s = mem();
    let p = pair("dest1", "git");
    s.transaction(|tx| {
        tx.insert_issuer(&issuer(1, CaState::Active))?;
        let mut rec = with_state(
            enrollment(1, &ca(1), &p),
            EnrollmentState::ManualRemovalPending,
        );
        rec.form = EnrollmentForm::System;
        rec.removal_origin = Some(seen_origin(EnrollmentState::Verified, true));
        tx.seed_enrollment(&rec)?;
        let before = serde_json::to_string(&tx.enrollment(&rec.id)?.unwrap()).unwrap();
        let mut reset = rec.clone();
        reset.removal_origin = Some(seen_origin(EnrollmentState::Verified, false));
        let mut cleared = rec.clone();
        cleared.removal_origin = None;
        for bad in [&reset, &cleared] {
            let r = tx.transition_enrollment(
                EnrollmentState::ManualRemovalPending,
                EnrollmentEventKind::OwnerConfirmsRemoved,
                bad,
            )?;
            assert!(r.is_err(), "{:?}", bad.removal_origin);
        }
        let cancel = tx.transition_enrollment(
            EnrollmentState::ManualRemovalPending,
            EnrollmentEventKind::OwnerCancelsManualRemoval {
                origin: EnrollmentState::Verified,
                ca_not_held_seen: false,
            },
            &reset,
        )?;
        assert!(cancel.is_err());
        assert_eq!(
            serde_json::to_string(&tx.enrollment(&rec.id)?.unwrap()).unwrap(),
            before,
            "nothing written"
        );
        // The same event with the pinned origin kept is admitted.
        let ok = tx
            .transition_enrollment(
                EnrollmentState::ManualRemovalPending,
                EnrollmentEventKind::OwnerConfirmsRemoved,
                &rec,
            )?
            .unwrap();
        assert_eq!(ok.state, EnrollmentState::RemovalVerifying);
        assert_eq!(ok.removal_origin, rec.removal_origin);
        Ok(())
    })
    .unwrap();
}
