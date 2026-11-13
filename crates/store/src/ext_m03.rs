//! ⟨M03⟩ Store methods for managed credentials (m03-plan §5 item 18; U0b rows 8, 15
//! and 22). Schema: `migrations/0006_managed_credentials.sql`.
//!
//! Conventions (as [`crate::ext`]): every method runs inside the caller's [`Txn`];
//! reads return `Option`/`Vec`; the store reads no clock (every instant is the
//! caller's); inserting a record whose ID (or another unique key) already exists is a
//! [`StoreError::GenerationConflict`] and leaves the stored record unchanged; updating
//! a record that does not exist is `StoreError::Sqlite(QueryReturnedNoRows)`.
//!
//! Outcomes of a compare-and-swap are typed:
//! * a **stale expectation** (the stored state or generation is not the one the caller
//!   names) is [`StoreError::GenerationConflict`], and nothing is written;
//! * a transition the **domain table refuses** (`ca_transition`,
//!   `enrollment::transition`, `foreign_transition`, `slot_transition`) is the inner
//!   `Err` of `Result<Result<T, Refusal>>`, and nothing is written;
//! * otherwise the inner `Ok` carries the record as stored.

use std::collections::BTreeSet;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, ConnectionId, CredentialInstanceId, DestinationId,
    EnrollmentId, EnvironmentId, ForeignRemovalId, GrantId, IssuanceId, OperationId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_domain::enrollment::{
    EnrollmentEvent, EnrollmentEventKind, EnrollmentRecord, EnrollmentState, ForeignRemovalRecord,
    InvalidTransition, PairPreference, ProjectionStatus, RemovalOrigin, foreign_transition,
    in_foreign_subset, marker_for, transition,
};
use heimdall_domain::issuance::{
    CaEvent, CredentialInstance, CredentialState, InvalidCaTransition, IssuanceEntry,
    IssuanceState, ca_transition,
};
use heimdall_domain::managed::{
    OwnedConnection, OwnedConnectionState, SlotEvent, SlotRefusal, SlotState, slot_transition,
};
use heimdall_domain::scope::AccessPair;
use heimdall_domain::verification::{VerificationEntry, VerificationRefusal};
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};

use crate::{Result, StoreError, Txn, codec, sql_in_list};

/// `meta`: when the lock disclosure was acknowledged (ADR-0008 D9; recorded once).
const META_LOCK_DISCLOSURE_ACK: &str = "lock_disclosure_acknowledged_at";
/// `meta`: the session-lock epoch the revocation pass last acknowledged (ADR-0008 D9;
/// §17.1 item 9). Never lowers.
const META_LOCK_ACK_EPOCH: &str = "session_lock_acknowledged_epoch";
/// `meta` (⟨wave 4, round 5, W4-C01⟩; no schema, as `cleanup_intent:`): one row per
/// released managed binding whose endpoint and files are not yet recorded removed
/// (`Txn::record_released_binding_cleanup`). Key `<prefix><binding>`, value the
/// binding ID.
const META_RELEASED_BINDING_CLEANUP_PREFIX: &str = "managed_released_binding_cleanup:";
/// `meta` (⟨wave 5, U10B-Q3 (b), ADR-0008 §17.21 item 10⟩; no schema): when the last
/// recovery bundle was built (`Txn::set_last_bundle_at`). Who records it is escalated
/// (`.m03-wave5-questions.md` Q-IS2); never lowers.
const META_LAST_BUNDLE_AT: &str = "issuer_last_bundle_at";
/// `meta` (⟨wave 5, round 2; ADR-0008 §17.25 item 8⟩; no schema, as
/// `managed_released_binding_cleanup:`): one row per recovery bundle the CLI confirmed
/// written. Key `<prefix><sha256>` (64 lowercase hex characters), value the bundle's
/// `created_at`. Never the bundle's path.
const META_BUNDLE_DIGEST_PREFIX: &str = "issuer_bundle_sha256:";

/// A registered CA, one `issuers` row (ADR-0008 D4; m03-plan §5 item 18). Public
/// metadata only: the CA's **public** key, digests and dates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRecord {
    /// The CA's fingerprint (primary key).
    pub ca_fingerprint: CaFingerprint,
    /// The CA's OpenSSH public key.
    pub public_key: String,
    /// State (D4 item 3; moved only by [`Txn::set_issuer_state`]).
    pub state: CaState,
    /// The platform store holding K_ca.
    pub store_kind: StoreKind,
    /// Hex SHA-256 of the D5 backup bytes.
    pub backup_sha256: String,
    /// When the backup was made.
    pub backup_created_at: Timestamp,
    /// A key-only restore (D4 item 4): every residual under this CA is unknown.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restored_without_log: bool,
    /// Registered at.
    pub created_at: Timestamp,
    /// When the CA reached `retired`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<Timestamp>,
}

/// ⟨ADR-0008 §17.21 item 3⟩ The longest store locator recorded.
const MAX_STORE_LOCATOR_BYTES: usize = 4096;

/// ⟨ADR-0008 §17.21 item 3⟩ An `issuers.record_json` document: the [`IssuerRecord`]
/// and the additive `store_locator` ([`Txn::issuer_store_locator`]). The locator is
/// deliberately not a field of `IssuerRecord`, so the record's shape (and every
/// caller building one) is unchanged; a document without the key (written before
/// it) reads as no recorded locator.
///
/// ⟨ADR-0008 §17.22 item 12⟩ And the additive `displaced_store_locators`: the items a
/// restore's compare-and-swap displaced ([`Txn::replace_issuer_store_locator`]), each
/// kept until the owner-present CLI confirms its deletion
/// ([`Txn::resolve_displaced_store_locator`]).
#[derive(Serialize, Deserialize)]
struct IssuerDoc {
    #[serde(flatten)]
    record: IssuerRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store_locator: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    displaced_store_locators: Vec<String>,
}

/// ⟨ADR-0008 §17.21 item 3⟩ A recordable store locator: 1 to 4096 bytes, no control
/// characters.
fn check_store_locator(locator: &str) -> Result<()> {
    if locator.is_empty()
        || locator.len() > MAX_STORE_LOCATOR_BYTES
        || locator.chars().any(char::is_control)
    {
        return Err(codec::doc_error(
            "a store locator is 1 to 4096 bytes without control characters",
        ));
    }
    Ok(())
}

/// One `managed_slots` row (ADR-0008 D10 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSlot {
    /// The environment.
    pub environment: EnvironmentId,
    /// The pair.
    pub pair: AccessPair,
    /// The slot's state.
    pub state: SlotState,
    /// The holder while `held`, the last holder while `clearing`, `None` while `free`.
    pub binding: Option<BindingId>,
    /// Last written at.
    pub updated_at: Timestamp,
}

/// ⟨ADR-0008 §17.27 item 1⟩ What [`Txn::outstanding_obligations`] reads: every
/// outstanding remote obligation, the uninstall inventory's source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutstandingObligations {
    /// Enrollments not final, or in any state with an unresolved `late_write`.
    pub enrollments: Vec<EnrollmentRecord>,
    /// Foreign removals not final.
    pub foreign_removals: Vec<ForeignRemovalRecord>,
    /// Enrollment operations open or `outcome_unknown`.
    pub operations: Vec<OpenEnrollmentOperation>,
}

/// One enrollment operation that is open or unresolved ([`OutstandingObligations`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenEnrollmentOperation {
    /// The operation.
    pub id: OperationId,
    /// Its kind (`enrollment.apply`, `.verify` or `.remove`).
    pub kind: heimdall_domain::operation::OperationKind,
    /// Its state.
    pub state: heimdall_contract::OperationState,
}

/// Result of [`Txn::mark_lost_instances`] (U0b row 8): the instances it changed, as
/// stored afterwards, each list in instance-ID order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LostInstances {
    /// `installed` instances without a live vault slot, now `lost`.
    pub lost: Vec<CredentialInstance>,
    /// `pending` instances, now `destroyed`.
    pub destroyed: Vec<CredentialInstance>,
}

/// ⟨ADR-0008 §17.23 item 3⟩ Whether two `RegisterIssuer` kinds name exactly the
/// same registration: every recorded fact equal (fingerprint, public key, store kind,
/// backup digest and time, rotation, key-only restore, expected locator). Only the
/// reported `store_locator` and the `disclosures` shown (derived from the runtime's
/// acknowledgement state, not from the request) are not facts. Anything other than
/// two registrations is `false`. Destructured exhaustively: a new field must be
/// classified here before this compiles.
#[must_use]
pub fn same_registration_facts(
    a: &heimdall_domain::decision::DecisionKind,
    b: &heimdall_domain::decision::DecisionKind,
) -> bool {
    use heimdall_domain::decision::DecisionKind;
    let (
        DecisionKind::RegisterIssuer {
            ca_fingerprint: a_fp,
            store: a_store,
            backup_sha256: a_digest,
            rotation_of: a_rotation,
            restored_without_log: a_key_only,
            disclosures: _,
            ca_public_key: a_key,
            backup_created_at: a_created,
            store_locator: _,
            expected_store_locator: a_expected,
        },
        DecisionKind::RegisterIssuer {
            ca_fingerprint: b_fp,
            store: b_store,
            backup_sha256: b_digest,
            rotation_of: b_rotation,
            restored_without_log: b_key_only,
            disclosures: _,
            ca_public_key: b_key,
            backup_created_at: b_created,
            store_locator: _,
            expected_store_locator: b_expected,
        },
    ) = (a, b)
    else {
        return false;
    };
    a_fp == b_fp
        && a_store == b_store
        && a_digest == b_digest
        && a_rotation == b_rotation
        && a_key_only == b_key_only
        && a_key == b_key
        && a_created == b_created
        && a_expected == b_expected
}

fn missing() -> StoreError {
    StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows)
}

fn conflict(what: String) -> StoreError {
    StoreError::GenerationConflict(what)
}

/// A UNIQUE or PRIMARY KEY violation is a [`StoreError::GenerationConflict`]; any
/// other error (a foreign-key violation included) stays a SQLite error.
fn unique_or(e: rusqlite::Error, what: impl FnOnce() -> String) -> StoreError {
    use rusqlite::ffi::{SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE};
    match &e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.extended_code == SQLITE_CONSTRAINT_UNIQUE
                || f.extended_code == SQLITE_CONSTRAINT_PRIMARYKEY =>
        {
            conflict(what())
        }
        _ => StoreError::Sqlite(e),
    }
}

fn parse_env(s: &str) -> Result<EnvironmentId> {
    EnvironmentId::parse(s).map_err(|_| codec::doc_error("stored environment id is malformed"))
}

fn parse_destination(s: &str) -> Result<DestinationId> {
    DestinationId::parse(s).map_err(|_| codec::doc_error("stored destination id is malformed"))
}

fn parse_account(s: &str) -> Result<AccountName> {
    AccountName::parse(s).map_err(|_| codec::doc_error("stored account is malformed"))
}

fn parse_binding(s: &str) -> Result<BindingId> {
    BindingId::parse(s).map_err(|_| codec::doc_error("stored binding id is malformed"))
}

fn by_created<T>(mut v: Vec<T>, key: impl Fn(&T) -> (Timestamp, String)) -> Vec<T> {
    v.sort_by_key(|r| key(r));
    v
}

/// The fields of an enrollment no transition may change.
fn enrollment_identity_kept(old: &EnrollmentRecord, new: &EnrollmentRecord) -> bool {
    old.id == new.id
        && old.destination == new.destination
        && old.account == new.account
        && old.ca_fingerprint == new.ca_fingerprint
        && old.form == new.form
        && old.marker == new.marker
        && old.registry == new.registry
        && old.registry_canonical == new.registry_canonical
        && old.line_sha256 == new.line_sha256
        && old.existing_access == new.existing_access
        && old.created_at == new.created_at
}

/// The persisted `removal_origin` rules shared by [`Txn::transition_enrollment`] and
/// [`Txn::transition_foreign_removal`] (ADR-0008 §17.4 item 5, §17.10 item 2, §17.16):
/// * a cancel or an absence result names the **persisted** origin (state, and for a
///   cancel `ca_not_held_seen`); a record without one, or another origin, is refused;
/// * absence history never downgrades: once the persisted origin has
///   `ca_not_held_seen`, it is pinned, and an `updated` record that clears, resets or
///   changes it is refused, whatever the event.
fn removal_origin_kept(
    stored: Option<&RemovalOrigin>,
    updated: Option<&RemovalOrigin>,
    kind: EnrollmentEventKind,
) -> bool {
    let named = match kind {
        EnrollmentEventKind::OwnerCancelsManualRemoval {
            origin,
            ca_not_held_seen,
        } => Some((origin, Some(ca_not_held_seen))),
        EnrollmentEventKind::AbsenceVerified { origin } => Some((origin, None)),
        _ => None,
    };
    if let Some((origin, seen)) = named {
        let agrees = stored.is_some_and(|o| {
            o.state == origin && seen.is_none_or(|seen| seen == o.ca_not_held_seen)
        });
        if !agrees {
            return false;
        }
    }
    !(stored.is_some_and(|o| o.ca_not_held_seen) && updated != stored)
}

/// ⟨ADR-0008 §17.30 item 4⟩ Whether `kind`'s payload agrees with the stored record
/// (the facts the app derives from it): `WithdrawnRemovalApproved { late_write }` with
/// the stored residual's presence; ⟨§17.30 item 8⟩ `OwnerReverify { hold }`,
/// `TargetChangeApproved { hold }` and `ManualRecoveryLine{Present,Absent} { hold, .. }`
/// with the stored hold's kind (no stored hold never agrees). Every other event
/// restates no stored field (outcomes, or facts the operation's journal holds), or is
/// checked by `removal_origin_kept` (the cancel and absence origins).
fn payload_agrees(stored: &EnrollmentRecord, kind: EnrollmentEventKind) -> bool {
    match kind {
        EnrollmentEventKind::WithdrawnRemovalApproved { late_write } => {
            late_write == stored.late_write.is_some()
        }
        // ⟨§17.30 items 4, 6, 8⟩ Every event that restates the stored hold, by kind (the
        // event carries only the kind). A manual-recovery event's `purpose` names the
        // interrupted step, which the record does not store: nothing to compare.
        EnrollmentEventKind::OwnerReverify { hold }
        | EnrollmentEventKind::TargetChangeApproved { hold }
        | EnrollmentEventKind::ManualRecoveryLinePresent { hold, .. }
        | EnrollmentEventKind::ManualRecoveryLineAbsent { hold, .. } => {
            stored.hold.map(|h| h.kind()) == Some(hold)
        }
        _ => true,
    }
}

/// ⟨ADR-0008 §17.30 item 5⟩ The admissions of a removal from a state outside the
/// `(pair, CA)` uniqueness index (`withdrawn` with its residual, `abandoned`): the
/// removal records that state as its origin.
fn removal_admission(expected: EnrollmentState, kind: EnrollmentEventKind) -> bool {
    matches!(
        (expected, kind),
        (
            EnrollmentState::Withdrawn,
            EnrollmentEventKind::WithdrawnRemovalApproved { .. }
        ) | (
            EnrollmentState::Abandoned,
            EnrollmentEventKind::RemoveEnrollmentApproved
        )
    )
}

fn slot_name(state: &SlotState) -> Result<&'static str> {
    match state {
        SlotState::Free { .. } => Ok("free"),
        SlotState::Held { .. } => Ok("held"),
        SlotState::Clearing { .. } => Ok("clearing"),
        _ => Err(codec::doc_error("unknown slot state")),
    }
}

fn slot_from_columns(state: &str, binding: Option<&str>, generation: i64) -> Result<SlotState> {
    let generation = codec::uint(generation)?;
    match (state, binding) {
        ("free", _) => Ok(SlotState::Free { generation }),
        ("held", Some(b)) => Ok(SlotState::Held {
            binding: parse_binding(b)?,
            generation,
        }),
        ("clearing", _) => Ok(SlotState::Clearing { generation }),
        _ => Err(codec::doc_error("stored slot state is malformed")),
    }
}

/// An owned connection's close moves only toward `closed`: `up → closing | closed |
/// unverified`, `closing → closed | unverified`, `unverified → closed`; `closed` is
/// absorbing (and closing it again is idempotent).
fn close_allowed(from: OwnedConnectionState, to: OwnedConnectionState) -> bool {
    use OwnedConnectionState as S;
    matches!(
        (from, to),
        (S::Up, S::Closing | S::Closed | S::Unverified)
            | (S::Closing, S::Closed | S::Unverified)
            | (S::Unverified, S::Closed)
            | (S::Closed, S::Closed)
    )
}

impl Txn<'_> {
    // --- issuers (ADR-0008 D4) ------------------------------------------------------------

    /// Register a CA (D4 item 1 step 7, rotation's `pending` CA, or a restore). The
    /// record is inserted `pending` or `active` with no `retired_at`; anything else is
    /// refused. A second registration of the fingerprint is a
    /// [`StoreError::GenerationConflict`].
    pub fn insert_issuer(&mut self, issuer: &IssuerRecord) -> Result<()> {
        if !matches!(issuer.state, CaState::Pending | CaState::Active)
            || issuer.retired_at.is_some()
        {
            return Err(codec::doc_error("a CA is registered pending or active"));
        }
        let n = self.tx.execute(
            "INSERT INTO issuers (ca_fingerprint, public_key, state, store_kind, backup_sha256,
                 backup_created_at, restored_without_log, created_at, retired_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)
             ON CONFLICT(ca_fingerprint) DO NOTHING",
            rusqlite::params![
                issuer.ca_fingerprint.as_str(),
                issuer.public_key,
                codec::enum_str(&issuer.state)?,
                codec::enum_str(&issuer.store_kind)?,
                issuer.backup_sha256,
                codec::ts(issuer.backup_created_at),
                i64::from(issuer.restored_without_log),
                codec::ts(issuer.created_at),
                codec::doc(issuer)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("issuer {} exists", issuer.ca_fingerprint)));
        }
        Ok(())
    }

    /// A registered CA.
    pub fn issuer(&mut self, ca: &CaFingerprint) -> Result<Option<IssuerRecord>> {
        self.one_doc(
            "SELECT record_json FROM issuers WHERE ca_fingerprint = ?1",
            [ca.as_str()],
        )
    }

    /// Every registered CA, in registration order (retired ones included).
    pub fn issuers(&mut self) -> Result<Vec<IssuerRecord>> {
        self.docs(
            "SELECT record_json FROM issuers ORDER BY created_at, ca_fingerprint",
            [],
        )
    }

    /// Move a CA along D4 item 3 (`heimdall_domain::issuance::ca_transition`), a
    /// compare-and-swap on `expected`. A missing CA is `QueryReturnedNoRows`; a stored
    /// state other than `expected` is a [`StoreError::GenerationConflict`]; an event
    /// the table refuses is the inner `Err`. Reaching `retired` sets `retired_at = at`.
    pub fn set_issuer_state(
        &mut self,
        ca: &CaFingerprint,
        expected: CaState,
        event: CaEvent,
        at: Timestamp,
    ) -> Result<std::result::Result<IssuerRecord, InvalidCaTransition>> {
        // ⟨§17.21 item 3⟩ Read and written whole, so the recorded store locator stays.
        let Some(mut doc) = self.issuer_doc(ca)? else {
            return Err(missing());
        };
        if doc.record.state != expected {
            return Err(conflict(format!("issuer {ca} is not {expected:?}")));
        }
        let next = match ca_transition(expected, event) {
            Ok(next) => next,
            Err(refused) => return Ok(Err(refused)),
        };
        doc.record.state = next;
        if next == CaState::Retired {
            doc.record.retired_at = Some(at);
        }
        let n = self.tx.execute(
            "UPDATE issuers SET state = ?2, retired_at = ?3, record_json = ?4
             WHERE ca_fingerprint = ?1 AND state = ?5",
            rusqlite::params![
                ca.as_str(),
                codec::enum_str(&doc.record.state)?,
                doc.record.retired_at.map(codec::ts),
                codec::doc(&doc)?,
                codec::enum_str(&expected)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("issuer {ca} is not {expected:?}")));
        }
        Ok(Ok(doc.record))
    }

    /// ⟨ADR-0008 §17.21 item 3; §17.17 item 3⟩ The exact store locator this
    /// installation recorded for `ca`'s K_ca item (the `StoreItemRef::locator` its
    /// `put` returned; the store kind is the record's `store_kind`), kept in the
    /// row's `record_json` under the additive key `store_locator`. `None` when the
    /// CA is not registered or nothing was recorded (a record written before the key:
    /// its retirement stops at `unloaded`, `issuer_store_locator_unrecorded`).
    pub fn issuer_store_locator(&mut self, ca: &CaFingerprint) -> Result<Option<String>> {
        Ok(self.issuer_doc(ca)?.and_then(|d| d.store_locator))
    }

    fn issuer_doc(&mut self, ca: &CaFingerprint) -> Result<Option<IssuerDoc>> {
        self.one_doc(
            "SELECT record_json FROM issuers WHERE ca_fingerprint = ?1",
            [ca.as_str()],
        )
    }

    /// ⟨ADR-0008 §17.21 item 3⟩ Record `locator` as `ca`'s K_ca store item, **once**,
    /// while the CA is `active` or `pending` (retirement deletes exactly this
    /// locator). Recording the same locator again is a no-op. Refused, writing
    /// nothing: a missing CA (`QueryReturnedNoRows`); a CA in a retirement state, or
    /// one that already has **another** locator ([`StoreError::GenerationConflict`]:
    /// this never replaces a recorded locator; only a restore's compare-and-swap does,
    /// [`Txn::replace_issuer_store_locator`], and never once a retirement began); an
    /// empty or oversized locator, or one with control characters (a document error).
    pub fn set_issuer_store_locator(&mut self, ca: &CaFingerprint, locator: &str) -> Result<()> {
        check_store_locator(locator)?;
        let Some(mut doc) = self.issuer_doc(ca)? else {
            return Err(missing());
        };
        match doc.store_locator.as_deref() {
            Some(l) if l == locator => return Ok(()),
            Some(_) => {
                return Err(conflict(format!(
                    "issuer {ca} already has a recorded store locator"
                )));
            }
            None => {}
        }
        let state = doc.record.state;
        if !matches!(state, CaState::Active | CaState::Pending) {
            return Err(conflict(format!(
                "issuer {ca} is {state:?}: its store locator is fixed"
            )));
        }
        doc.store_locator = Some(locator.to_owned());
        self.write_issuer_doc(ca, &doc, state)
    }

    /// Write `doc` back, a compare-and-swap on the stored state `state`.
    fn write_issuer_doc(
        &mut self,
        ca: &CaFingerprint,
        doc: &IssuerDoc,
        state: CaState,
    ) -> Result<()> {
        let n = self.tx.execute(
            "UPDATE issuers SET record_json = ?2 WHERE ca_fingerprint = ?1 AND state = ?3",
            rusqlite::params![ca.as_str(), codec::doc(doc)?, codec::enum_str(&state)?],
        )?;
        if n == 0 {
            return Err(conflict(format!("issuer {ca} is not {state:?}")));
        }
        Ok(())
    }

    /// ⟨ADR-0008 §17.22 item 12⟩ The store items a restore displaced from `ca`
    /// ([`Txn::replace_issuer_store_locator`]) and whose deletion is not yet
    /// confirmed, in displacement order. Empty for an unknown CA.
    pub fn issuer_displaced_store_locators(&mut self, ca: &CaFingerprint) -> Result<Vec<String>> {
        Ok(self
            .issuer_doc(ca)?
            .map(|d| d.displaced_store_locators)
            .unwrap_or_default())
    }

    /// ⟨ADR-0008 §17.22 item 12⟩ A restore's compare-and-swap of `ca`'s recorded store
    /// locator: `expected` must equal the recorded one (`None`: none recorded), and
    /// the CA must be `active` or `pending`. The recorded locator becomes `new`; the
    /// one it replaces (if any) is kept in the displaced list until its deletion is
    /// confirmed (`new` itself leaves that list if it was there). `new` equal to the
    /// recorded locator is a no-op. Refused, writing nothing: a missing CA
    /// (`QueryReturnedNoRows`); a recorded locator other than `expected`, or a CA in a
    /// retirement state ([`StoreError::GenerationConflict`]); a malformed `new` (a
    /// document error).
    pub fn replace_issuer_store_locator(
        &mut self,
        ca: &CaFingerprint,
        expected: Option<&str>,
        new: &str,
    ) -> Result<()> {
        check_store_locator(new)?;
        let Some(mut doc) = self.issuer_doc(ca)? else {
            return Err(missing());
        };
        if doc.store_locator.as_deref() != expected {
            return Err(conflict(format!(
                "issuer {ca}'s recorded store locator is not the expected one"
            )));
        }
        let state = doc.record.state;
        if !matches!(state, CaState::Active | CaState::Pending) {
            return Err(conflict(format!(
                "issuer {ca} is {state:?}: its store locator is fixed"
            )));
        }
        if expected == Some(new) {
            return Ok(());
        }
        doc.displaced_store_locators.retain(|l| l != new);
        if let Some(old) = doc.store_locator.replace(new.to_owned()) {
            doc.displaced_store_locators.push(old);
        }
        self.write_issuer_doc(ca, &doc, state)
    }

    /// ⟨ADR-0008 §17.22 item 12⟩ The owner-present CLI confirmed it deleted the
    /// displaced item `locator` of `ca`: it leaves the displaced list, in any CA
    /// state. `Ok(false)`, writing nothing, when `locator` is not displaced from `ca`
    /// (an unknown CA included).
    pub fn resolve_displaced_store_locator(
        &mut self,
        ca: &CaFingerprint,
        locator: &str,
    ) -> Result<bool> {
        let Some(mut doc) = self.issuer_doc(ca)? else {
            return Ok(false);
        };
        let before = doc.displaced_store_locators.len();
        doc.displaced_store_locators.retain(|l| l != locator);
        if doc.displaced_store_locators.len() == before {
            return Ok(false);
        }
        let state = doc.record.state;
        self.write_issuer_doc(ca, &doc, state)?;
        Ok(true)
    }

    /// ⟨ADR-0008 §17.22 item 12, §17.23 item 3⟩ Record the ceremony's store-item
    /// report on the pending `RegisterIssuer` decision `id`, once. `report` is the
    /// report as a `RegisterIssuer`: it must repeat **every** recorded fact exactly
    /// ([`same_registration_facts`]) and carry the item in its `store_locator`; it
    /// only attaches that locator. Compare-and-swap on `pending` and on no locator
    /// recorded yet; the same locator again is a no-op. The ID, facts, disclosures,
    /// generation, creation and expiry are unchanged. A fact mismatch, another
    /// recorded locator, a decision not pending or not a registration is a
    /// [`StoreError::GenerationConflict`] (nothing written); a missing decision is
    /// `QueryReturnedNoRows`; a report without a locator, or a malformed one, a
    /// document error. Returns the record after the change.
    pub fn attach_register_issuer_store_locator(
        &mut self,
        id: &heimdall_contract::ids::DecisionId,
        report: &heimdall_domain::decision::DecisionKind,
    ) -> Result<heimdall_domain::decision::DecisionRecord> {
        use heimdall_domain::decision::{DecisionKind, DecisionState};
        let DecisionKind::RegisterIssuer {
            store_locator: Some(locator),
            ..
        } = report
        else {
            return Err(codec::doc_error(
                "a store-item report is a registration carrying its store locator",
            ));
        };
        check_store_locator(locator)?;
        let Some(mut record) = self.decision(id)? else {
            return Err(missing());
        };
        if record.state != DecisionState::Pending {
            return Err(conflict(format!("decision {id} is not pending")));
        }
        if !matches!(record.kind, DecisionKind::RegisterIssuer { .. }) {
            return Err(conflict(format!("decision {id} is not a registration")));
        }
        if !same_registration_facts(&record.kind, report) {
            return Err(conflict(format!(
                "the store-item report does not repeat decision {id}'s registration"
            )));
        }
        match &mut record.kind {
            DecisionKind::RegisterIssuer { store_locator, .. } => match store_locator {
                Some(l) if l == locator => return Ok(record),
                Some(_) => {
                    return Err(conflict(format!(
                        "decision {id} already records another store item"
                    )));
                }
                None => *store_locator = Some(locator.clone()),
            },
            _ => return Err(conflict(format!("decision {id} is not a registration"))),
        }
        let n = self.tx.execute(
            "UPDATE decisions SET kind_json = ?2, record_json = ?3 WHERE id = ?1 AND state = ?4",
            rusqlite::params![
                id.as_str(),
                codec::doc(&record.kind)?,
                codec::doc(&record)?,
                codec::enum_str(&DecisionState::Pending)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("decision {id} is not pending")));
        }
        Ok(record)
    }

    // --- enrollments (ADR-0008 D5 §6.2) ---------------------------------------------------

    /// Decode `(record_json, removal_origin_set, state)` rows. A row whose columns
    /// disagree with its document (the index predicate reads the columns) is
    /// [`StoreError::Corrupt`].
    fn enrollment_rows(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<EnrollmentRecord>> {
        let mut stmt = self.tx.prepare_cached(sql)?;
        let rows = stmt.query_map(params, |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (doc, origin_set, state) = row?;
            let record: EnrollmentRecord = codec::parse_doc(&doc)?;
            if origin_set != i64::from(record.removal_origin.is_some())
                || state != codec::enum_str(&record.state)?
            {
                return Err(StoreError::Corrupt(
                    "an enrollment row disagrees with its record".into(),
                ));
            }
            out.push(record);
        }
        Ok(out)
    }

    fn write_new_enrollment(&mut self, record: &EnrollmentRecord) -> Result<()> {
        if record.marker != marker_for(&record.id) {
            return Err(codec::doc_error(
                "an enrollment's marker is heimdall:<enrollment id>",
            ));
        }
        self.tx
            .execute(
                "INSERT INTO enrollments (id, destination_id, account, ca_fingerprint, form,
                     marker, state, verified_at, record_json, removal_origin_set)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    record.id.as_str(),
                    record.destination.as_str(),
                    record.account.as_str(),
                    record.ca_fingerprint.as_str(),
                    codec::enum_str(&record.form)?,
                    record.marker,
                    codec::enum_str(&record.state)?,
                    record.verified_at.map(codec::ts),
                    codec::doc(record)?,
                    i64::from(record.removal_origin.is_some()),
                ],
            )
            .map_err(|e| {
                unique_or(e, || {
                    format!(
                        "enrollment {} duplicates an ID, a marker or a live (pair, CA)",
                        record.id
                    )
                })
            })?;
        Ok(())
    }

    /// Insert an enrollment record, created `planned` (D5 §6.2), whose marker is
    /// [`marker_for`] its ID. Its CA must be registered (a foreign-key violation is a
    /// SQLite error). A duplicate ID or marker, or a second live enrollment for the
    /// same (destination, account, CA), is a [`StoreError::GenerationConflict`]. Only
    /// the enrollment-path states are live (`planned`, `applying`, `outcome_unknown`,
    /// `applied_unverified`, `manual_pending`, `verifying`, `verified`, `reverifying`,
    /// and `held` reached on the enrollment path, i.e. without a `removal_origin`); a
    /// removal or rollback state, a `held` removal residual (`removal_origin` set),
    /// `abandoned` or a final state does not block a new one.
    pub fn insert_enrollment(&mut self, record: &EnrollmentRecord) -> Result<()> {
        if record.state != EnrollmentState::Planned {
            return Err(codec::doc_error("an enrollment is inserted planned"));
        }
        self.write_new_enrollment(record)
    }

    /// Test support (seeding model tests with an enrollment in any state, e.g. a
    /// `verified` one): [`Txn::insert_enrollment`] without the `planned` rule. Every
    /// other check and constraint applies. Never used by production code.
    #[doc(hidden)]
    pub fn seed_enrollment(&mut self, record: &EnrollmentRecord) -> Result<()> {
        self.write_new_enrollment(record)
    }

    /// An enrollment by ID.
    pub fn enrollment(&mut self, id: &EnrollmentId) -> Result<Option<EnrollmentRecord>> {
        Ok(self
            .enrollment_rows(
                "SELECT record_json, removal_origin_set, state FROM enrollments WHERE id = ?1",
                [id.as_str()],
            )?
            .pop())
    }

    /// An enrollment by its marker (`heimdall:<enrollment id>`), the remote line's key.
    pub fn enrollment_by_marker(&mut self, marker: &str) -> Result<Option<EnrollmentRecord>> {
        Ok(self
            .enrollment_rows(
                "SELECT record_json, removal_origin_set, state FROM enrollments WHERE marker = ?1",
                [marker],
            )?
            .pop())
    }

    /// Every enrollment of a pair, in every state, oldest first.
    pub fn enrollments_for_pair(&mut self, pair: &AccessPair) -> Result<Vec<EnrollmentRecord>> {
        let v = self.enrollment_rows(
            "SELECT record_json, removal_origin_set, state FROM enrollments
             WHERE destination_id = ?1 AND account = ?2",
            [pair.destination.as_str(), pair.account.as_str()],
        )?;
        Ok(by_created(v, |r: &EnrollmentRecord| {
            (r.created_at, r.id.as_str().to_owned())
        }))
    }

    /// Every enrollment under a CA, in every state, oldest first (retirement's
    /// precondition, D4 item 3, and the issuer status counts).
    pub fn enrollments_for_ca(&mut self, ca: &CaFingerprint) -> Result<Vec<EnrollmentRecord>> {
        let v = self.enrollment_rows(
            "SELECT record_json, removal_origin_set, state FROM enrollments
             WHERE ca_fingerprint = ?1",
            [ca.as_str()],
        )?;
        Ok(by_created(v, |r: &EnrollmentRecord| {
            (r.created_at, r.id.as_str().to_owned())
        }))
    }

    /// Every enrollment not in a final state (`abandoned` included: it is not final),
    /// oldest first (verify-doc E12: the uninstall read and restart). A database whose
    /// schema has no `enrollments` table (an older file read without migrating) has
    /// none.
    pub fn open_enrollments(&mut self) -> Result<Vec<EnrollmentRecord>> {
        let present: bool = self.tx.query_row(
            "SELECT count(*) > 0 FROM sqlite_schema WHERE type = 'table' AND name = 'enrollments'",
            [],
            |r| r.get(0),
        )?;
        if !present {
            return Ok(Vec::new());
        }
        let finals: Vec<EnrollmentState> = EnrollmentState::ALL
            .iter()
            .copied()
            .filter(|s| s.is_final())
            .collect();
        let sql = format!(
            "SELECT record_json, removal_origin_set, state FROM enrollments
             WHERE state NOT IN ({})",
            sql_in_list(&finals)?
        );
        let v = self.enrollment_rows(&sql, [])?;
        Ok(by_created(v, |r: &EnrollmentRecord| {
            (r.created_at, r.id.as_str().to_owned())
        }))
    }

    /// ⟨ADR-0008 §17.27 item 1 (W5-R01, W5-R02)⟩ Every outstanding remote obligation,
    /// in one read (it writes nothing, so it runs on a store opened read-only):
    /// * every enrollment that is not final, and every enrollment in **any** state
    ///   whose `late_write` residual is unresolved (the record still carries it: no
    ///   inspect after its not-after has shown absence yet), oldest first;
    /// * every foreign removal that is not final (an abandoned system-form record,
    ///   still `pending_until_line_removed`, included), oldest first;
    /// * every enrollment operation (`enrollment.*`) that is open or unresolved
    ///   (queued, running, awaiting approval, `outcome_unknown`), oldest first: an
    ///   enrollment in flight is itself an obligation.
    ///
    /// A database whose schema predates a table (an older file read without migrating)
    /// has none of its rows.
    pub fn outstanding_obligations(&mut self) -> Result<OutstandingObligations> {
        let table = |tx: &mut Self, name: &str| -> Result<bool> {
            Ok(tx.tx.query_row(
                "SELECT count(*) > 0 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [name],
                |r| r.get(0),
            )?)
        };
        let mut out = OutstandingObligations::default();
        if table(self, "enrollments")? {
            let all = self.enrollment_rows(
                "SELECT record_json, removal_origin_set, state FROM enrollments",
                [],
            )?;
            out.enrollments = by_created(
                all.into_iter()
                    .filter(|r| !r.state.is_final() || r.late_write.is_some())
                    .collect(),
                |r: &EnrollmentRecord| (r.created_at, r.id.as_str().to_owned()),
            );
        }
        if table(self, "foreign_removals")? {
            let all: Vec<ForeignRemovalRecord> =
                self.docs("SELECT record_json FROM foreign_removals", [])?;
            out.foreign_removals = by_created(
                all.into_iter().filter(|r| !r.state.is_final()).collect(),
                |r: &ForeignRemovalRecord| (r.created_at, r.id.as_str().to_owned()),
            );
        }
        let mut ops = self.open_operations()?;
        ops.extend(self.unresolved_operations()?);
        ops.retain(|o| o.kind.is_enrollment());
        ops.sort_by(|a, b| (a.created_at, a.id.as_str()).cmp(&(b.created_at, b.id.as_str())));
        ops.dedup_by(|a, b| a.id == b.id);
        out.operations = ops
            .into_iter()
            .map(|o| OpenEnrollmentOperation {
                id: o.id,
                kind: o.kind,
                state: o.state,
            })
            .collect();
        Ok(out)
    }

    /// Apply one D5 §6.2 event to an enrollment: a compare-and-swap on `expected`
    /// that calls `heimdall_domain::enrollment::transition`.
    ///
    /// `updated` is the record after the event as the caller built it (hold, removal
    /// origin, evidence, `verified_at`, `late_write`, target, `updated_at`); its
    /// `state` is ignored and replaced by the table's target. Its identity fields (ID,
    /// pair, CA, form, marker, registry, line digest, existing access, `created_at`)
    /// must equal the stored record's. A missing record is `QueryReturnedNoRows`; a
    /// stored state other than `expected` is a [`StoreError::GenerationConflict`], as
    /// is a move onto the enrollment path (the index's live states) while another live
    /// enrollment holds the same (pair, CA); an event the table refuses is the inner
    /// `Err`, as is a cancel or absence result whose `origin` is not the record's
    /// persisted `removal_origin` (§17.4 item 5).
    ///
    /// ⟨ADR-0008 §17.30 item 4⟩ An event whose payload restates a stored fact must
    /// agree with the stored record, or it is the inner `Err` with nothing written:
    /// `WithdrawnRemovalApproved { late_write }` with `stored.late_write.is_some()`, and
    /// `OwnerReverify { hold }`, ⟨item 8⟩ `TargetChangeApproved { hold }` and the
    /// manual-recovery events' `hold` with the stored hold's kind (`stored.hold.map(kind)`).
    ///
    /// ⟨§17.30 item 5⟩ An own account-form removal admitted from `withdrawn` or
    /// `abandoned` records its removal origin (that state, its evidence and hold) when
    /// the caller's record carries none, and an account-form record keeps its stored
    /// origin through every later transition whose `updated` omits it. A `held`
    /// removal residual therefore stays outside the `(pair, CA)` uniqueness index.
    pub fn transition_enrollment(
        &mut self,
        expected: EnrollmentState,
        kind: EnrollmentEventKind,
        updated: &EnrollmentRecord,
    ) -> Result<std::result::Result<EnrollmentRecord, InvalidTransition>> {
        let Some(stored) = self.enrollment(&updated.id)? else {
            return Err(missing());
        };
        if stored.state != expected {
            return Err(conflict(format!(
                "enrollment {} is not {}",
                updated.id,
                expected.as_str()
            )));
        }
        if !enrollment_identity_kept(&stored, updated) {
            return Err(codec::doc_error(
                "an enrollment transition changes only the record's mutable fields",
            ));
        }
        let event = EnrollmentEvent {
            record: stored.facts(),
            kind,
        };
        if !payload_agrees(&stored, kind) {
            return Ok(Err(InvalidTransition {
                from: expected,
                event,
            }));
        }
        let mut record = updated.clone();
        if stored.form == heimdall_contract::enrollment::EnrollmentForm::Account
            && record.removal_origin.is_none()
        {
            record.removal_origin = if removal_admission(expected, kind) {
                Some(RemovalOrigin {
                    state: expected,
                    evidence: stored.evidence.clone(),
                    hold: stored.hold,
                    ca_not_held_seen: false,
                })
            } else {
                stored.removal_origin.clone()
            };
        }
        if !removal_origin_kept(
            stored.removal_origin.as_ref(),
            record.removal_origin.as_ref(),
            kind,
        ) {
            return Ok(Err(InvalidTransition {
                from: expected,
                event,
            }));
        }
        let next = match transition(expected, event) {
            Ok(next) => next,
            Err(refused) => return Ok(Err(refused)),
        };
        record.state = next;
        let n = self
            .tx
            .execute(
                "UPDATE enrollments SET state = ?2, verified_at = ?3, record_json = ?4,
                     removal_origin_set = ?6
                 WHERE id = ?1 AND state = ?5",
                rusqlite::params![
                    record.id.as_str(),
                    codec::enum_str(&record.state)?,
                    record.verified_at.map(codec::ts),
                    codec::doc(&record)?,
                    codec::enum_str(&expected)?,
                    i64::from(record.removal_origin.is_some()),
                ],
            )
            .map_err(|e| {
                unique_or(e, || {
                    format!("enrollment {} would duplicate a live (pair, CA)", record.id)
                })
            })?;
        if n == 0 {
            return Err(conflict(format!(
                "enrollment {} is not {}",
                record.id,
                expected.as_str()
            )));
        }
        Ok(Ok(record))
    }

    /// ⟨ADR-0008 §17.28 item 3⟩ Clear an enrollment's `late_write` residual (D5 §6.7):
    /// a compare-and-swap on the stored record's `expected` state **and** its
    /// residual's `step_token`, which sets only `late_write = None` and `updated_at`.
    /// It moves no state and changes nothing else. Returns the cleared record, or
    /// `None` (nothing written) when the record is missing, in another state, or does
    /// not carry that exact residual. It never sets a residual; the caller decides,
    /// from an inspection, that absence was observed.
    pub fn clear_late_write(
        &mut self,
        id: &EnrollmentId,
        expected: EnrollmentState,
        step_token: &str,
        now: Timestamp,
    ) -> Result<Option<EnrollmentRecord>> {
        let Some(stored) = self.enrollment(id)? else {
            return Ok(None);
        };
        if stored.state != expected
            || stored.late_write.as_ref().map(|l| l.step_token.as_str()) != Some(step_token)
        {
            return Ok(None);
        }
        let mut record = stored;
        record.late_write = None;
        record.updated_at = now;
        let n = self.tx.execute(
            "UPDATE enrollments SET record_json = ?2 WHERE id = ?1 AND state = ?3",
            rusqlite::params![
                record.id.as_str(),
                codec::doc(&record)?,
                codec::enum_str(&expected)?,
            ],
        )?;
        Ok((n == 1).then_some(record))
    }

    /// The CAs with a `verified` enrollment for the pair. A `reverifying` record is not
    /// counted (the store cannot tell which state it started from; fail closed).
    pub fn verified_cas_for_pair(&mut self, pair: &AccessPair) -> Result<BTreeSet<CaFingerprint>> {
        let mut stmt = self.tx.prepare_cached(
            "SELECT ca_fingerprint FROM enrollments
             WHERE destination_id = ?1 AND account = ?2 AND state = ?3",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![
                pair.destination.as_str(),
                pair.account.as_str(),
                codec::enum_str(&EnrollmentState::Verified)?,
            ],
            |r| r.get::<_, String>(0),
        )?;
        let mut out = BTreeSet::new();
        for row in rows {
            out.insert(
                CaFingerprint::parse(&row?)
                    .map_err(|_| codec::doc_error("stored CA fingerprint is malformed"))?,
            );
        }
        Ok(out)
    }

    // --- verification issuance (ADR-0008 D5 §6.5 item 2) ---------------------------------

    /// Reserve a verification entry: insert it `reserved` with its complete bounds,
    /// which name the CA. The caller ran `heimdall_domain::verification::check` in this
    /// transaction. An entry that is not `reserved`, is settled, carries a void reason
    /// or names no CA is refused; a duplicate ID is a
    /// [`StoreError::GenerationConflict`].
    pub fn reserve_verification(&mut self, entry: &VerificationEntry) -> Result<()> {
        if entry.state != IssuanceState::Reserved
            || entry.settled_at.is_some()
            || entry.void_reason.is_some()
            || entry.bounds.ca_fingerprint.is_none()
        {
            return Err(codec::doc_error(
                "a verification entry is inserted reserved, with its CA",
            ));
        }
        let n = self.tx.execute(
            "INSERT INTO verification_issuance (id, operation_id, destination_id, account,
                 purpose, state, valid_before, reserved_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                entry.id.as_str(),
                entry.operation.as_str(),
                entry.pair.destination.as_str(),
                entry.pair.account.as_str(),
                codec::enum_str(&entry.purpose)?,
                codec::enum_str(&entry.state)?,
                codec::ts(entry.bounds.valid_before),
                codec::ts(entry.reserved_at),
                codec::doc(entry)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("verification entry {} exists", entry.id)));
        }
        Ok(())
    }

    /// ⟨M03 wave 2, integrator; U3-Q1⟩ One verification issuance entry by ID, in any
    /// state (the issuer child's D3 item 4 step 1 lookup over its read-only store).
    /// Read-only.
    pub fn verification_entry(&mut self, id: &IssuanceId) -> Result<Option<VerificationEntry>> {
        self.one_doc(
            "SELECT record_json FROM verification_issuance WHERE id = ?1",
            [id.as_str()],
        )
    }

    fn settle_verification(
        &mut self,
        id: &IssuanceId,
        to: IssuanceState,
        reason: Option<VerificationRefusal>,
        now: Timestamp,
    ) -> Result<VerificationEntry> {
        let Some(mut entry) = self.verification_entry(id)? else {
            return Err(missing());
        };
        if entry.state != IssuanceState::Reserved {
            return Err(conflict(format!("verification entry {id} is not reserved")));
        }
        entry.state = to;
        entry.settled_at = Some(now);
        entry.void_reason = reason;
        let n = self.tx.execute(
            "UPDATE verification_issuance SET state = ?2, record_json = ?3
             WHERE id = ?1 AND state = ?4",
            rusqlite::params![
                id.as_str(),
                codec::enum_str(&entry.state)?,
                codec::doc(&entry)?,
                codec::enum_str(&IssuanceState::Reserved)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("verification entry {id} is not reserved")));
        }
        Ok(entry)
    }

    /// Publish: CAS `reserved → published` at `now`; a non-reserved entry is a
    /// [`StoreError::GenerationConflict`]. The caller re-ran the predicate.
    pub fn publish_verification(
        &mut self,
        id: &IssuanceId,
        now: Timestamp,
    ) -> Result<VerificationEntry> {
        self.settle_verification(id, IssuanceState::Published, None, now)
    }

    /// Void: CAS `reserved → voided` with the reason.
    pub fn void_verification(
        &mut self,
        id: &IssuanceId,
        reason: VerificationRefusal,
        now: Timestamp,
    ) -> Result<VerificationEntry> {
        self.settle_verification(id, IssuanceState::Voided, Some(reason), now)
    }

    /// An operation's verification entries, in every state, in reservation order.
    pub fn verification_entries(
        &mut self,
        operation: &OperationId,
    ) -> Result<Vec<VerificationEntry>> {
        self.docs(
            "SELECT record_json FROM verification_issuance WHERE operation_id = ?1
             ORDER BY reserved_at, id",
            [operation.as_str()],
        )
    }

    /// The per-pair residual (ADR-0008 D7 item 4): the latest `valid_before` over the
    /// pair's `reserved` and `published` grant issuance entries **and** verification
    /// entries, under `ca` (`None`: every CA, and grant entries that name none).
    /// `None` when nothing is counted. Voided entries never count; nothing here
    /// compares with a clock.
    pub fn pair_residual(
        &mut self,
        pair: &AccessPair,
        ca: Option<&CaFingerprint>,
    ) -> Result<Option<Timestamp>> {
        let counted = sql_in_list(&[IssuanceState::Reserved, IssuanceState::Published])?;
        let under = |bound: Option<&CaFingerprint>| ca.is_none_or(|c| bound == Some(c));
        let grants: Vec<IssuanceEntry> = self.docs(
            &format!(
                "SELECT record_json FROM issuance_log WHERE state IN ({counted})
                 AND json_extract(record_json, '$.pair.destination') = ?1
                 AND json_extract(record_json, '$.pair.account') = ?2"
            ),
            [pair.destination.as_str(), pair.account.as_str()],
        )?;
        let verifications: Vec<VerificationEntry> = self.docs(
            &format!(
                "SELECT record_json FROM verification_issuance
                 WHERE destination_id = ?1 AND account = ?2 AND state IN ({counted})"
            ),
            [pair.destination.as_str(), pair.account.as_str()],
        )?;
        let from_grants = grants
            .iter()
            .filter(|e| e.pair == *pair && under(e.bounds.ca_fingerprint.as_ref()))
            .map(|e| e.bounds.valid_before);
        let from_verifications = verifications
            .iter()
            .filter(|e| under(e.bounds.ca_fingerprint.as_ref()))
            .map(|e| e.bounds.valid_before);
        Ok(from_grants.chain(from_verifications).max())
    }

    // --- pair preferences (m03-plan §5 item 4b; F05) -------------------------------------

    /// Insert or replace a pair's whole preference (mechanism, projection status and
    /// issuing-CA set) at `at`. Callers that change one part read the stored record
    /// first in the same transaction.
    pub fn set_pair_preference(
        &mut self,
        preference: &PairPreference,
        at: Timestamp,
    ) -> Result<()> {
        let (projection_state, projection_generation) = match preference.projection {
            ProjectionStatus::Pending => ("pending", None),
            ProjectionStatus::Applied { generation } => ("applied", Some(codec::int(generation)?)),
            _ => return Err(codec::doc_error("unknown projection status")),
        };
        self.tx.execute(
            "INSERT INTO pair_preferences (destination_id, account, mechanism, projection_state,
                 projection_generation, issuing_cas_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(destination_id, account) DO UPDATE SET
                 mechanism = excluded.mechanism,
                 projection_state = excluded.projection_state,
                 projection_generation = excluded.projection_generation,
                 issuing_cas_json = excluded.issuing_cas_json,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                preference.destination.as_str(),
                preference.account.as_str(),
                codec::enum_str(&preference.mechanism)?,
                projection_state,
                projection_generation,
                codec::doc(&preference.issuing_cas)?,
                codec::ts(at),
            ],
        )?;
        Ok(())
    }

    /// A pair's stored preference.
    pub fn pair_preference(&mut self, pair: &AccessPair) -> Result<Option<PairPreference>> {
        let row: Option<(String, String, Option<i64>, String)> = self
            .tx
            .query_row(
                "SELECT mechanism, projection_state, projection_generation, issuing_cas_json
                 FROM pair_preferences WHERE destination_id = ?1 AND account = ?2",
                [pair.destination.as_str(), pair.account.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((mechanism, projection_state, projection_generation, issuing)) = row else {
            return Ok(None);
        };
        let projection = match (projection_state.as_str(), projection_generation) {
            ("pending", None) => ProjectionStatus::Pending,
            ("applied", Some(g)) => ProjectionStatus::Applied {
                generation: codec::uint(g)?,
            },
            _ => return Err(codec::doc_error("stored projection status is malformed")),
        };
        Ok(Some(PairPreference {
            destination: pair.destination.clone(),
            account: pair.account.clone(),
            mechanism: codec::enum_parse(&mechanism)?,
            projection,
            issuing_cas: codec::parse_doc(&issuing)?,
        }))
    }

    /// Add `ca` to the pair's issuing-CA set (E5). `Ok(true)` when it was added,
    /// `Ok(false)` when already present. A pair without a stored preference is
    /// `QueryReturnedNoRows` (E5 writes the preference first; D5 §6.6).
    pub fn add_issuing_ca(
        &mut self,
        pair: &AccessPair,
        ca: &CaFingerprint,
        at: Timestamp,
    ) -> Result<bool> {
        let Some(mut preference) = self.pair_preference(pair)? else {
            return Err(missing());
        };
        if !preference.issuing_cas.insert(ca.clone()) {
            return Ok(false);
        }
        self.set_pair_preference(&preference, at)?;
        Ok(true)
    }

    /// Remove `ca` from the pair's issuing-CA set (removal of its enrollment).
    /// `Ok(true)` when it was removed, `Ok(false)` when absent or the pair has no
    /// stored preference. The mechanism and projection are untouched.
    pub fn remove_issuing_ca(
        &mut self,
        pair: &AccessPair,
        ca: &CaFingerprint,
        at: Timestamp,
    ) -> Result<bool> {
        let Some(mut preference) = self.pair_preference(pair)? else {
            return Ok(false);
        };
        if !preference.issuing_cas.remove(ca) {
            return Ok(false);
        }
        self.set_pair_preference(&preference, at)?;
        Ok(true)
    }

    // --- managed slots (ADR-0008 D10 item 2) ---------------------------------------------

    fn slot_row(
        &mut self,
        environment: &EnvironmentId,
        pair: &AccessPair,
    ) -> Result<Option<SlotState>> {
        let row: Option<(String, Option<String>, i64)> = self
            .tx
            .query_row(
                "SELECT state, binding_id, generation FROM managed_slots
                 WHERE environment_id = ?1 AND destination_id = ?2 AND account = ?3",
                [
                    environment.as_str(),
                    pair.destination.as_str(),
                    pair.account.as_str(),
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(state, binding, generation)| {
            slot_from_columns(&state, binding.as_deref(), generation)
        })
        .transpose()
    }

    /// Write `next` over `old` (CAS on the old state and generation; `None` inserts).
    fn write_slot(
        &mut self,
        environment: &EnvironmentId,
        pair: &AccessPair,
        old: Option<&SlotState>,
        next: &SlotState,
        binding: Option<&BindingId>,
        at: Timestamp,
    ) -> Result<()> {
        let what = || format!("slot {environment}/{}/{}", pair.destination, pair.account);
        let binding = binding.map(BindingId::as_str);
        let n = match old {
            None => self
                .tx
                .execute(
                    "INSERT INTO managed_slots (environment_id, destination_id, account,
                         binding_id, generation, state, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        environment.as_str(),
                        pair.destination.as_str(),
                        pair.account.as_str(),
                        binding,
                        codec::int(next.generation())?,
                        slot_name(next)?,
                        codec::ts(at),
                    ],
                )
                .map_err(|e| unique_or(e, what))?,
            Some(old) => self.tx.execute(
                "UPDATE managed_slots SET binding_id = ?4, generation = ?5, state = ?6,
                     updated_at = ?7
                 WHERE environment_id = ?1 AND destination_id = ?2 AND account = ?3
                   AND generation = ?8 AND state = ?9",
                rusqlite::params![
                    environment.as_str(),
                    pair.destination.as_str(),
                    pair.account.as_str(),
                    binding,
                    codec::int(next.generation())?,
                    slot_name(next)?,
                    codec::ts(at),
                    codec::int(old.generation())?,
                    slot_name(old)?,
                ],
            )?,
        };
        if n == 0 {
            return Err(conflict(what()));
        }
        Ok(())
    }

    /// A slot's state; a pair that never had a slot is `free(0)`.
    pub fn slot(&mut self, environment: &EnvironmentId, pair: &AccessPair) -> Result<SlotState> {
        Ok(self
            .slot_row(environment, pair)?
            .unwrap_or(SlotState::Free { generation: 0 }))
    }

    /// Claim the slot for `binding`: CAS `free(g) → held(binding, g + 1)`; a claim by
    /// the holder again is idempotent (`held` unchanged). Another holder is the inner
    /// `Err(ManagedSlotHeld)`, a `clearing` slot `Err(NotApplicable)`. The binding must
    /// exist (a foreign-key violation is a SQLite error).
    pub fn claim_slot(
        &mut self,
        environment: &EnvironmentId,
        pair: &AccessPair,
        binding: &BindingId,
        at: Timestamp,
    ) -> Result<std::result::Result<SlotState, SlotRefusal>> {
        let old = self.slot_row(environment, pair)?;
        let current = old.clone().unwrap_or(SlotState::Free { generation: 0 });
        let next = match slot_transition(
            &current,
            &SlotEvent::Claim {
                binding: binding.clone(),
            },
        ) {
            Ok(next) => next,
            Err(refused) => return Ok(Err(refused)),
        };
        if next != current {
            self.write_slot(environment, pair, old.as_ref(), &next, Some(binding), at)?;
        }
        Ok(Ok(next))
    }

    /// Release the slot held by `binding` at `generation`: CAS `held(binding,
    /// generation) → clearing(generation)` (the key is unlisted; the files of that
    /// generation are removed next, [`Txn::slot_files_removed`]). A stored generation
    /// other than `generation` is a [`StoreError::GenerationConflict`]; another holder
    /// is the inner `Err(StaleGeneration)`, a slot not `held` `Err(NotApplicable)`.
    pub fn release_slot(
        &mut self,
        environment: &EnvironmentId,
        pair: &AccessPair,
        binding: &BindingId,
        generation: u64,
        at: Timestamp,
    ) -> Result<std::result::Result<SlotState, SlotRefusal>> {
        let Some(old) = self.slot_row(environment, pair)? else {
            return Ok(Err(SlotRefusal::NotApplicable));
        };
        if old.generation() != generation {
            return Err(conflict(format!(
                "slot {environment}/{}/{} is not at generation {generation}",
                pair.destination, pair.account
            )));
        }
        let next = match slot_transition(
            &old,
            &SlotEvent::Release {
                binding: binding.clone(),
                generation,
            },
        ) {
            Ok(next) => next,
            Err(refused) => return Ok(Err(refused)),
        };
        self.write_slot(environment, pair, Some(&old), &next, Some(binding), at)?;
        Ok(Ok(next))
    }

    /// The files of `generation` were removed: CAS `clearing(generation) →
    /// free(generation)`. A stored generation other than `generation` is a
    /// [`StoreError::GenerationConflict`]; a slot not `clearing` is the inner
    /// `Err(NotApplicable)`.
    pub fn slot_files_removed(
        &mut self,
        environment: &EnvironmentId,
        pair: &AccessPair,
        generation: u64,
        at: Timestamp,
    ) -> Result<std::result::Result<SlotState, SlotRefusal>> {
        let Some(old) = self.slot_row(environment, pair)? else {
            return Ok(Err(SlotRefusal::NotApplicable));
        };
        if old.generation() != generation {
            return Err(conflict(format!(
                "slot {environment}/{}/{} is not at generation {generation}",
                pair.destination, pair.account
            )));
        }
        let next = match slot_transition(&old, &SlotEvent::FilesRemoved { generation }) {
            Ok(next) => next,
            Err(refused) => return Ok(Err(refused)),
        };
        self.write_slot(environment, pair, Some(&old), &next, None, at)?;
        Ok(Ok(next))
    }

    /// The slots `binding` holds, or last held and is still clearing, in
    /// (environment, destination, account) order.
    pub fn slots_for_binding(&mut self, binding: &BindingId) -> Result<Vec<ManagedSlot>> {
        type Row = (String, String, String, String, Option<String>, i64, String);
        let rows: Vec<Row> = {
            let mut stmt = self.tx.prepare_cached(
                "SELECT environment_id, destination_id, account, state, binding_id, generation,
                        updated_at
                 FROM managed_slots WHERE binding_id = ?1
                 ORDER BY environment_id, destination_id, account",
            )?;
            let rows = stmt.query_map([binding.as_str()], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        rows.into_iter()
            .map(
                |(env, destination, account, state, holder, generation, updated)| {
                    Ok(ManagedSlot {
                        environment: parse_env(&env)?,
                        pair: AccessPair {
                            destination: parse_destination(&destination)?,
                            account: parse_account(&account)?,
                        },
                        state: slot_from_columns(&state, holder.as_deref(), generation)?,
                        binding: holder.as_deref().map(parse_binding).transpose()?,
                        updated_at: codec::parse_ts(&updated)?,
                    })
                },
            )
            .collect()
    }

    /// ⟨M03 wave 4, round 2⟩ ADR-0008 §17.21 item 11: the slots of `environment` that
    /// are still `held` or `clearing` for a binding whose grant has ended (any terminal
    /// state, or `revoking`), with that grant, in (grant, destination, account) order.
    /// The supervisor's end-of-grant pass clears each by its own generation. A slot row
    /// whose binding has no grant row is not listed (the foreign keys forbid it).
    pub fn held_slots_of_ended_grants(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<Vec<(GrantId, ManagedSlot)>> {
        type Row = (
            String,
            String,
            String,
            String,
            Option<String>,
            i64,
            String,
            String,
            String,
        );
        let rows: Vec<Row> = {
            let mut stmt = self.tx.prepare_cached(
                "SELECT s.environment_id, s.destination_id, s.account, s.state, s.binding_id,
                        s.generation, s.updated_at, g.id, g.state
                 FROM managed_slots s
                 JOIN bindings b ON b.id = s.binding_id
                 JOIN grants g ON g.id = b.grant_id
                 WHERE s.environment_id = ?1 AND s.state IN ('held', 'clearing')
                 ORDER BY g.id, s.destination_id, s.account",
            )?;
            let rows = stmt.query_map([environment.as_str()], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::new();
        for (env, destination, account, state, holder, generation, updated, grant, grant_state) in
            rows
        {
            let grant_state: heimdall_contract::GrantState = codec::enum_parse(&grant_state)?;
            if !(grant_state.is_terminal()
                || grant_state == heimdall_contract::GrantState::Revoking)
            {
                continue;
            }
            let grant = GrantId::parse(&grant)
                .map_err(|_| codec::doc_error("stored grant id is malformed"))?;
            out.push((
                grant,
                ManagedSlot {
                    environment: parse_env(&env)?,
                    pair: AccessPair {
                        destination: parse_destination(&destination)?,
                        account: parse_account(&account)?,
                    },
                    state: slot_from_columns(&state, holder.as_deref(), generation)?,
                    binding: holder.as_deref().map(parse_binding).transpose()?,
                    updated_at: codec::parse_ts(&updated)?,
                },
            ));
        }
        Ok(out)
    }

    /// ⟨M03 wave 4, round 3⟩ ADR-0008 §17.22 item 7 (W4-R07) and item 10 (W4-R08):
    /// every binding whose grant is `grant`, in any state (a released binding has no
    /// grant reference any more, yet its files may remain), in ID order.
    pub fn bindings_of_grant(&mut self, grant: &GrantId) -> Result<Vec<BindingId>> {
        let ids: Vec<String> = {
            let mut stmt = self
                .tx
                .prepare_cached("SELECT id FROM bindings WHERE grant_id = ?1 ORDER BY id")?;
            let rows = stmt.query_map([grant.as_str()], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        ids.iter().map(|b| parse_binding(b)).collect()
    }

    /// ⟨M03 wave 4, round 3⟩ ADR-0008 §17.22 items 4, 9 and 10: the grants of
    /// `environment` that still owe a managed cleanup, found from durable rows only
    /// (never from in-memory state, never only from held slots), in grant order:
    ///
    /// * a grant in a **terminal** state (not `revoking`, which its revocation round
    ///   owns) with a credential instance that is not `destroyed` (`pending`,
    ///   `installed` or `lost`): its K_env, its instance and gate, its binding
    ///   endpoints and files are owed (D1, D2 table, D7 items 7–8). The instance
    ///   moves to `destroyed` last, so this row is the obligation until the rest is
    ///   done;
    /// * a grant, in any state, with a slot `held` or `clearing` for a **released**
    ///   binding (D10 item 2: `held(b, g)` → `clearing` when `b` is released, even
    ///   while the grant lives on through another reference). The slot is freed last,
    ///   so its row is the obligation for that binding's slot, files and mux path;
    /// * ⟨round 5, W4-C01⟩ a grant, in any state, with a **released** binding whose
    ///   release cleanup is not recorded done
    ///   ([`Self::record_released_binding_cleanup`], written in the release
    ///   transaction): the binding's endpoint and files of every generation it was
    ///   materialized at, with or without a slot. The row is removed only once they are
    ///   gone ([`Self::released_binding_cleanup_done`]).
    pub fn managed_cleanup_owed(&mut self, environment: &EnvironmentId) -> Result<Vec<GrantId>> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        {
            let sql = format!(
                "SELECT DISTINCT g.id, g.state FROM credential_instances c
                 JOIN grants g ON g.id = c.grant_id
                 WHERE g.environment = ?1 AND c.state IN ({})",
                sql_in_list(&[
                    CredentialState::Pending,
                    CredentialState::Installed,
                    CredentialState::Lost,
                ])?
            );
            let mut stmt = self.tx.prepare_cached(&sql)?;
            let rows: Vec<(String, String)> = stmt
                .query_map([environment.as_str()], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?;
            for (grant, state) in rows {
                let state: heimdall_contract::GrantState = codec::enum_parse(&state)?;
                if state.is_terminal() {
                    out.insert(grant);
                }
            }
        }
        {
            let mut stmt = self.tx.prepare_cached(
                "SELECT DISTINCT b.grant_id FROM managed_slots s
                 JOIN bindings b ON b.id = s.binding_id
                 WHERE s.environment_id = ?1 AND s.state IN ('held', 'clearing')
                   AND b.state = 'released'",
            )?;
            let rows: Vec<String> = stmt
                .query_map([environment.as_str()], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            out.extend(rows);
        }
        for b in self.meta_with_prefix(META_RELEASED_BINDING_CLEANUP_PREFIX)? {
            let binding = parse_binding(&b)?;
            if let Some(record) = self.binding(&binding)?
                && record.environment == *environment
            {
                out.insert(record.grant.as_str().to_owned());
            }
        }
        out.iter()
            .map(|g| {
                GrantId::parse(g).map_err(|_| codec::doc_error("stored grant id is malformed"))
            })
            .collect()
    }

    /// ⟨M03 wave 4, round 5 (W4-C01)⟩ ADR-0008 §17.22 items 9–10: in the release
    /// transaction of the managed binding `binding`, the durable obligation for its
    /// endpoint and files (every resource generation it was materialized at, a
    /// re-issue's included), held or not a slot. Idempotent. Listed through
    /// [`Self::managed_cleanup_owed`] until [`Self::released_binding_cleanup_done`].
    pub fn record_released_binding_cleanup(&mut self, binding: &BindingId) -> Result<()> {
        self.set_meta(
            &format!("{META_RELEASED_BINDING_CLEANUP_PREFIX}{binding}"),
            binding.as_str(),
        )
    }

    /// ⟨W4-C01⟩ Whether `binding`'s release cleanup is still owed.
    pub fn released_binding_cleanup_owed(&mut self, binding: &BindingId) -> Result<bool> {
        Ok(self
            .meta(&format!("{META_RELEASED_BINDING_CLEANUP_PREFIX}{binding}"))?
            .is_some())
    }

    /// ⟨W4-C01⟩ Record `binding`'s release cleanup done (its endpoint and files gone);
    /// nothing when none was owed.
    pub fn released_binding_cleanup_done(&mut self, binding: &BindingId) -> Result<()> {
        self.delete_meta(&format!("{META_RELEASED_BINDING_CLEANUP_PREFIX}{binding}"))
    }

    // --- owned connections (ADR-0008 D8 item 2) ------------------------------------------

    /// ⟨M03 wave 4, round 2⟩ §17.21 item 11 (`inspect connections`, read-only): every
    /// owned connection, in every state, oldest first.
    pub fn owned_connections(&mut self) -> Result<Vec<OwnedConnection>> {
        self.docs(
            "SELECT record_json FROM owned_connections ORDER BY started_at, id",
            [],
        )
    }

    /// Insert an owned connection, `up` (written at bind on Unix, at registration on
    /// Windows). Its binding and grant must exist (a foreign-key violation is a SQLite
    /// error); a duplicate ID is a [`StoreError::GenerationConflict`].
    pub fn insert_owned_connection(&mut self, connection: &OwnedConnection) -> Result<()> {
        if connection.state != OwnedConnectionState::Up {
            return Err(codec::doc_error("an owned connection is inserted up"));
        }
        // ⟨M03 wave 3⟩ U7-Q4 (ADR-0008 §17.20 item 14): a dedicated row only for a launch
        // binding with a recorded holder; the connection passes enumerate dedicated rows
        // through the holders, so a row without one would never be closed.
        if connection.kind == heimdall_domain::managed::ConnectionKind::Dedicated
            && self.binding_holder(&connection.binding)?.is_none()
        {
            return Err(codec::doc_error(
                "a dedicated owned connection needs its binding's holder",
            ));
        }
        let n = self.tx.execute(
            "INSERT INTO owned_connections (id, binding_id, grant_id, kind, pid, start_token,
                 image, control_path, generation, state, started_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                connection.id.as_str(),
                connection.binding.as_str(),
                connection.grant.as_str(),
                codec::enum_str(&connection.kind)?,
                i64::from(connection.pid),
                connection.start_token,
                connection.image,
                connection.control_path,
                codec::int(connection.generation)?,
                codec::enum_str(&connection.state)?,
                codec::ts(connection.started_at),
                codec::doc(connection)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!(
                "owned connection {} exists",
                connection.id
            )));
        }
        Ok(())
    }

    /// An owned connection by ID.
    pub fn owned_connection(&mut self, id: &ConnectionId) -> Result<Option<OwnedConnection>> {
        self.one_doc(
            "SELECT record_json FROM owned_connections WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// A grant's owned connections, in every state, oldest first.
    pub fn owned_connections_for_grant(&mut self, grant: &GrantId) -> Result<Vec<OwnedConnection>> {
        self.docs(
            "SELECT record_json FROM owned_connections WHERE grant_id = ?1
             ORDER BY started_at, id",
            [grant.as_str()],
        )
    }

    /// A binding's owned connections, in every state, oldest first.
    pub fn owned_connections_for_binding(
        &mut self,
        binding: &BindingId,
    ) -> Result<Vec<OwnedConnection>> {
        self.docs(
            "SELECT record_json FROM owned_connections WHERE binding_id = ?1
             ORDER BY started_at, id",
            [binding.as_str()],
        )
    }

    /// Move an owned connection toward `closed`, a compare-and-swap by generation:
    /// `up → closing | closed | unverified`, `closing → closed | unverified`,
    /// `unverified → closed`; `closed → closed` is idempotent. A stored generation
    /// other than `generation` (another master generation) or a move out of `closed`
    /// is a [`StoreError::GenerationConflict`]; a move to `up` or backwards is
    /// refused as malformed. The generation itself never changes here.
    pub fn close_owned_connection(
        &mut self,
        id: &ConnectionId,
        generation: u64,
        to: OwnedConnectionState,
    ) -> Result<OwnedConnection> {
        let Some(mut stored) = self.owned_connection(id)? else {
            return Err(missing());
        };
        if stored.generation != generation {
            return Err(conflict(format!(
                "owned connection {id} is not at generation {generation}"
            )));
        }
        if stored.state == OwnedConnectionState::Closed && to != OwnedConnectionState::Closed {
            return Err(conflict(format!("owned connection {id} is closed")));
        }
        if !close_allowed(stored.state, to) {
            return Err(codec::doc_error(
                "an owned connection only moves toward closed",
            ));
        }
        if stored.state == to {
            return Ok(stored);
        }
        let from = stored.state;
        stored.state = to;
        let n = self.tx.execute(
            "UPDATE owned_connections SET state = ?2, record_json = ?3
             WHERE id = ?1 AND generation = ?4 AND state = ?5",
            rusqlite::params![
                id.as_str(),
                codec::enum_str(&stored.state)?,
                codec::doc(&stored)?,
                codec::int(generation)?,
                codec::enum_str(&from)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!(
                "owned connection {id} is not at generation {generation}"
            )));
        }
        Ok(stored)
    }

    // --- foreign removals (ADR-0008 D4 item 5) -------------------------------------------

    /// Insert a foreign removal, created `planned`. No CA registration is needed or
    /// checked (the table has no foreign key to `issuers`). A duplicate ID is a
    /// [`StoreError::GenerationConflict`].
    pub fn insert_foreign_removal(&mut self, record: &ForeignRemovalRecord) -> Result<()> {
        if record.state != EnrollmentState::Planned {
            return Err(codec::doc_error("a foreign removal is inserted planned"));
        }
        let target = &record.target;
        let n = self.tx.execute(
            "INSERT INTO foreign_removals (id, marker, local_alias, account, ca_public_key,
                 line_sha256, state, operation_id, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                record.id.as_str(),
                target.marker,
                target.local_alias,
                target.account.as_str(),
                target.ca_public_key,
                target.line_sha256,
                codec::enum_str(&record.state)?,
                record.operation.as_str(),
                codec::doc(record)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("foreign removal {} exists", record.id)));
        }
        Ok(())
    }

    /// A foreign removal by ID.
    pub fn foreign_removal(
        &mut self,
        id: &ForeignRemovalId,
    ) -> Result<Option<ForeignRemovalRecord>> {
        self.one_doc(
            "SELECT record_json FROM foreign_removals WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Every foreign removal of a marker, in every state, oldest first.
    pub fn foreign_removals_by_marker(
        &mut self,
        marker: &str,
    ) -> Result<Vec<ForeignRemovalRecord>> {
        let v = self.docs(
            "SELECT record_json FROM foreign_removals WHERE marker = ?1",
            [marker],
        )?;
        Ok(by_created(v, |r: &ForeignRemovalRecord| {
            (r.created_at, r.id.as_str().to_owned())
        }))
    }

    /// Apply one event to a foreign removal: a compare-and-swap on `expected` that
    /// calls `heimdall_domain::enrollment::foreign_transition`, so the record never
    /// leaves the removal subset. `updated` is the record after the event (removal
    /// origin, operation); its `state` is replaced by the table's target, and its ID,
    /// target and `created_at` must equal the stored record's. A missing record is
    /// `QueryReturnedNoRows`; a stored state other than `expected` is a
    /// [`StoreError::GenerationConflict`]; an event the table refuses is the inner
    /// `Err`.
    pub fn transition_foreign_removal(
        &mut self,
        expected: EnrollmentState,
        kind: EnrollmentEventKind,
        updated: &ForeignRemovalRecord,
    ) -> Result<std::result::Result<ForeignRemovalRecord, InvalidTransition>> {
        let Some(stored) = self.foreign_removal(&updated.id)? else {
            return Err(missing());
        };
        if stored.state != expected {
            return Err(conflict(format!(
                "foreign removal {} is not {}",
                updated.id,
                expected.as_str()
            )));
        }
        if stored.id != updated.id
            || stored.target != updated.target
            || stored.created_at != updated.created_at
        {
            return Err(codec::doc_error(
                "a foreign removal transition keeps its ID and target",
            ));
        }
        // ADR-0008 §17.16 (R5): the same origin rules as `transition_enrollment`.
        if !removal_origin_kept(
            stored.removal_origin.as_ref(),
            updated.removal_origin.as_ref(),
            kind,
        ) {
            return Ok(Err(InvalidTransition {
                from: expected,
                event: EnrollmentEvent {
                    record: stored.facts(),
                    kind,
                },
            }));
        }
        let next = match foreign_transition(&stored, kind) {
            Ok(next) => next,
            Err(refused) => return Ok(Err(refused)),
        };
        if !in_foreign_subset(next) {
            return Err(codec::doc_error("a foreign removal stays in its subset"));
        }
        let mut record = updated.clone();
        record.state = next;
        let n = self.tx.execute(
            "UPDATE foreign_removals SET state = ?2, operation_id = ?3, record_json = ?4
             WHERE id = ?1 AND state = ?5",
            rusqlite::params![
                record.id.as_str(),
                codec::enum_str(&record.state)?,
                record.operation.as_str(),
                codec::doc(&record)?,
                codec::enum_str(&expected)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!(
                "foreign removal {} is not {}",
                record.id,
                expected.as_str()
            )));
        }
        Ok(Ok(record))
    }

    // --- lock disclosure and the acknowledged lock epoch (ADR-0008 D9) --------------------

    /// Record the lock disclosure's acknowledgement once: the first `at` is kept and
    /// returned by every later call.
    pub fn set_lock_disclosure_ack(&mut self, at: Timestamp) -> Result<Timestamp> {
        if let Some(first) = self.lock_disclosure_ack()? {
            return Ok(first);
        }
        self.set_meta(META_LOCK_DISCLOSURE_ACK, &codec::ts(at))?;
        Ok(at)
    }

    /// When the lock disclosure was acknowledged, if it was.
    pub fn lock_disclosure_ack(&mut self) -> Result<Option<Timestamp>> {
        self.meta(META_LOCK_DISCLOSURE_ACK)?
            .as_deref()
            .map(codec::parse_ts)
            .transpose()
    }

    /// Record that the revocation pass acknowledged lock `epoch` (§17.1 item 9). The
    /// stored epoch never lowers: an equal epoch is idempotent, a lower one is a
    /// [`StoreError::GenerationConflict`]. Returns the stored epoch.
    pub fn set_acknowledged_lock_epoch(&mut self, epoch: u64) -> Result<u64> {
        if let Some(stored) = self.acknowledged_lock_epoch()? {
            if epoch < stored {
                return Err(conflict(format!(
                    "acknowledged lock epoch {stored} is above {epoch}"
                )));
            }
            if epoch == stored {
                return Ok(stored);
            }
        }
        self.set_meta(META_LOCK_ACK_EPOCH, &epoch.to_string())?;
        Ok(epoch)
    }

    /// The last acknowledged lock epoch, if any.
    pub fn acknowledged_lock_epoch(&mut self) -> Result<Option<u64>> {
        self.meta(META_LOCK_ACK_EPOCH)?
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| codec::doc_error("stored lock epoch is malformed"))
            })
            .transpose()
    }

    // --- the last recovery bundle (U10B-Q3 (b); ADR-0008 §17.21 item 10) ------------------

    /// Record that a recovery bundle was built at `at`. The stored time never lowers: an
    /// earlier `at` keeps the stored one, which is returned.
    pub fn set_last_bundle_at(&mut self, at: Timestamp) -> Result<Timestamp> {
        if let Some(stored) = self.last_bundle_at()?
            && stored >= at
        {
            return Ok(stored);
        }
        self.set_meta(META_LAST_BUNDLE_AT, &codec::ts(at))?;
        Ok(at)
    }

    /// When the last recovery bundle was built, if one was recorded.
    pub fn last_bundle_at(&mut self) -> Result<Option<Timestamp>> {
        self.meta(META_LAST_BUNDLE_AT)?
            .as_deref()
            .map(codec::parse_ts)
            .transpose()
    }

    /// ⟨ADR-0008 §17.25 item 8⟩ Record the SHA-256 (64 lowercase hex characters) of a
    /// recovery bundle the CLI confirmed written, with its `created_at`. A digest
    /// already recorded never lowers: an earlier `created_at` keeps the stored one,
    /// which is returned. Any other digest form is refused and records nothing. The
    /// path is never recorded. (When and from which request this is called is the
    /// app's; the store only keeps the rows.)
    pub fn record_bundle_digest(
        &mut self,
        sha256: &str,
        created_at: Timestamp,
    ) -> Result<Timestamp> {
        let key = bundle_digest_key(sha256)?;
        if let Some(stored) = self
            .meta(&key)?
            .as_deref()
            .map(codec::parse_ts)
            .transpose()?
            && stored >= created_at
        {
            return Ok(stored);
        }
        self.set_meta(&key, &codec::ts(created_at))?;
        Ok(created_at)
    }

    /// ⟨ADR-0008 §17.25 item 8⟩ The `created_at` recorded with a confirmed bundle's
    /// SHA-256, or `None` when this installation recorded no such digest. A digest
    /// that is not 64 lowercase hex characters is refused.
    pub fn bundle_digest_recorded_at(&mut self, sha256: &str) -> Result<Option<Timestamp>> {
        let key = bundle_digest_key(sha256)?;
        self.meta(&key)?.as_deref().map(codec::parse_ts).transpose()
    }

    // --- restart: credential instances (U0b row 8) ----------------------------------------

    /// Restart recovery (U0b row 8; ADR-0008 D2 table; F18), in the caller's one
    /// transaction before any listener binds: every `installed` credential instance
    /// whose ID is not in `live` (the instances whose vault slot exists in this
    /// process) becomes `lost`, and every `pending` instance becomes `destroyed`.
    /// Issuance entries are not touched, so their `reserved`/`published` entries stay
    /// counted in the residual. Returns what changed.
    pub fn mark_lost_instances(
        &mut self,
        live: &BTreeSet<CredentialInstanceId>,
    ) -> Result<LostInstances> {
        let candidates: Vec<CredentialInstance> = self.docs(
            &format!(
                "SELECT record_json FROM credential_instances WHERE state IN ({}) ORDER BY id",
                sql_in_list(&[CredentialState::Installed, CredentialState::Pending])?
            ),
            [],
        )?;
        let mut out = LostInstances::default();
        for mut instance in candidates {
            let from = instance.state;
            instance.state = match from {
                CredentialState::Installed if !live.contains(&instance.id) => CredentialState::Lost,
                CredentialState::Pending => CredentialState::Destroyed,
                _ => continue,
            };
            let n = self.tx.execute(
                "UPDATE credential_instances SET state = ?2, record_json = ?3
                 WHERE id = ?1 AND state = ?4",
                rusqlite::params![
                    instance.id.as_str(),
                    codec::enum_str(&instance.state)?,
                    codec::doc(&instance)?,
                    codec::enum_str(&from)?,
                ],
            )?;
            if n == 0 {
                return Err(conflict(format!(
                    "credential instance {} changed",
                    instance.id
                )));
            }
            if instance.state == CredentialState::Lost {
                out.lost.push(instance);
            } else {
                out.destroyed.push(instance);
            }
        }
        Ok(out)
    }
}

/// The `meta` key of a confirmed bundle's digest: only 64 lowercase hex characters,
/// so no other key can be addressed through it.
fn bundle_digest_key(sha256: &str) -> Result<String> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(codec::doc_error(
            "a bundle digest must be 64 lowercase hex characters",
        ));
    }
    Ok(format!("{META_BUNDLE_DIGEST_PREFIX}{sha256}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The `enrollments` states the migration's partial UNIQUE index covers: the
    /// enrollment path (orchestrator ruling on S1, plus `manual_pending`).
    const INDEXED_ENROLLMENT_STATES: [EnrollmentState; 9] = [
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

    /// The index covers exactly the states that are not final, not `abandoned` and
    /// not a removal or rollback state, and the migration lists exactly those.
    #[test]
    fn indexed_states_are_the_enrollment_path() {
        let expected: BTreeSet<&str> = EnrollmentState::ALL
            .iter()
            .copied()
            .filter(|s| {
                !s.is_final()
                    && *s != EnrollmentState::Abandoned
                    && heimdall_domain::enrollment::removal_purpose(*s).is_none()
                    && !matches!(
                        s,
                        EnrollmentState::ManualRemovalPending | EnrollmentState::RemovalVerifying
                    )
            })
            .map(EnrollmentState::as_str)
            .collect();
        let got: BTreeSet<&str> = INDEXED_ENROLLMENT_STATES
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(got, expected);
        let sql = include_str!("../migrations/0006_managed_credentials.sql");
        let start = sql.find("WHERE state IN (").unwrap() + "WHERE state IN (".len();
        let end = start + sql[start..].find(')').unwrap();
        let listed: BTreeSet<&str> = sql[start..end]
            .split(',')
            .map(|s| s.trim().trim_matches('\''))
            .collect();
        assert_eq!(listed, expected);
        assert!(
            sql.contains("AND NOT (state = 'held' AND removal_origin_set = 1)"),
            "a held removal residual is outside the index"
        );
    }

    #[test]
    fn close_moves_only_toward_closed() {
        use OwnedConnectionState as S;
        assert!(close_allowed(S::Up, S::Closing));
        assert!(close_allowed(S::Closing, S::Closed));
        assert!(close_allowed(S::Closed, S::Closed));
        assert!(!close_allowed(S::Closing, S::Up));
        assert!(!close_allowed(S::Closed, S::Up));
        assert!(!close_allowed(S::Up, S::Up));
    }

    /// ⟨ADR-0008 §17.25 item 8⟩ A confirmed bundle's digest: recorded with its
    /// `created_at`, never lowered, refused unless 64 lowercase hex characters (and a
    /// refused digest records nothing).
    #[test]
    fn bundle_digest_records_never_lower_and_refuse_other_forms() {
        let s = crate::Store::open_in_memory(std::sync::Arc::new(crate::NoFaults)).unwrap();
        let t: Timestamp = "2026-11-13T10:00:00Z".parse().unwrap();
        let earlier: Timestamp = "2026-11-13T09:00:00Z".parse().unwrap();
        let later: Timestamp = "2026-11-13T11:00:00Z".parse().unwrap();
        let d = "ab".repeat(32);
        s.transaction(|tx| {
            assert_eq!(tx.bundle_digest_recorded_at(&d)?, None);
            assert_eq!(tx.record_bundle_digest(&d, t)?, t);
            assert_eq!(tx.record_bundle_digest(&d, earlier)?, t, "never lowers");
            assert_eq!(tx.bundle_digest_recorded_at(&d)?, Some(t));
            assert_eq!(tx.record_bundle_digest(&d, later)?, later);
            assert_eq!(tx.bundle_digest_recorded_at(&"cd".repeat(32))?, None);
            for bad in [
                "AB".repeat(32),
                "ab".repeat(31),
                format!("{}:x", "ab".repeat(31)),
            ] {
                assert!(tx.record_bundle_digest(&bad, t).is_err(), "{bad}");
                assert!(tx.bundle_digest_recorded_at(&bad).is_err(), "{bad}");
            }
            assert_eq!(tx.meta_with_prefix(META_BUNDLE_DIGEST_PREFIX)?.len(), 1);
            assert_eq!(
                tx.last_bundle_at()?,
                None,
                "a digest does not move last_bundle_at"
            );
            Ok(())
        })
        .unwrap();
    }
}
