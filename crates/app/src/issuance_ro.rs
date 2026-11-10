//! ⟨M03⟩ The read-only issuance check (m03-plan U3; ADR-0008 D3 item 4; §17.1 item
//! 12, F21).
//!
//! The issuer child opens the state database **read-only** and, before it signs an
//! entry, re-checks it here: the entry is `reserved`, fresh and for this subject,
//! and every predicate of the reserve transaction still holds in its snapshot. It
//! shares its snapshot assembly with the runtime's reserve and publish transactions,
//! so the read-only verdict equals the reserve predicate
//! (`issuance_ro_assess_matches_reserve_predicate`, U3). It writes nothing: time is
//! the read-only assessment (`TimeGate::assess_read_only`), which persists no
//! high-water mark.
//!
//! **What differs from the runtime's transactions** (they write; this cannot):
//! * a grant or ancestor last validated at an older authority generation is not
//!   re-validated here. When every other predicate holds, the stale member refuses
//!   `stale_generation` (`stale_ancestor`): the generation-only refusal the runtime
//!   answers by voiding, re-validating and re-reserving (D3 item 4);
//! * the issuance facts are the issuer's own ([`ISSUER_FACTS`]), except the
//!   activation/continuing distinction, which is read from the entry the reserve
//!   transaction persisted ([`issuer_facts`]; ADR-0008 §17.19 item 2, W2-R02, closing
//!   U3-Q2);
//! * a verification entry is judged by `verification::check` with the default
//!   `verification_max_validity` (the child has no runtime configuration).
//!
//! **Entry lookup** (questions file U3-Q1, resolved by the integrator): the entry is
//! read by ID with the store's `Txn::issuance_entry` / `Txn::verification_entry`, in
//! any state; a missing one, or one not `reserved`, is refused `entry_not_reserved`,
//! and an entry of an ended grant reaches the predicate, which refuses it.

use std::time::Duration;

use heimdall_domain::issuance::{CertificateBounds, IssuanceEntry, IssuanceState};
use heimdall_domain::projection::Sha256Hex;
use heimdall_domain::time::{TimeAnchor, TimeStatus};
use heimdall_domain::verification::VerificationEntry;
use heimdall_store::Txn;

use crate::operations::{IssuanceFacts, Limits};
use crate::ports::{IssuanceRef, IssuanceTable, IssuerRefusal};

/// The oldest reservation the issuer signs (ADR-0008 D3 item 4 step 1).
pub const MAX_RESERVATION_AGE: Duration = Duration::from_secs(60);

/// The issuance facts the issuer knows without an entry. The subject is registered
/// exactly when it matches the entry's subject fingerprint, which [`assess`] checks
/// before the predicate runs; a `sign` request carries no options, so none is
/// critical. `new_activation` here is the fail-closed reading for an entry that
/// records nothing; a grant entry's own record replaces it ([`issuer_facts`]).
pub const ISSUER_FACTS: IssuanceFacts = IssuanceFacts {
    new_activation: true,
    subject_registered: true,
    critical_option: false,
};

/// ⟨ADR-0008 §17.19 item 2, W2-R02⟩ The issuer's facts for grant `entry`: a new
/// activation unless the reserve transaction recorded the entry as continuing work
/// (`IssuanceEntry::continuing`, a renewal or re-issue within an existing grant, which
/// a pause does not block). Read from the store, never from the `sign` request. A row
/// written before the record existed reads as a new activation (fail closed).
#[must_use]
pub fn issuer_facts(entry: &IssuanceEntry) -> IssuanceFacts {
    IssuanceFacts {
        new_activation: !entry.continuing,
        ..ISSUER_FACTS
    }
}

/// A reserved entry as the issuer reads it: either table, with its bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredEntry {
    /// A grant issuance-log entry.
    Grant(IssuanceEntry),
    /// A verification issuance entry.
    Verification(VerificationEntry),
}

impl StoredEntry {
    /// The entry's state.
    #[must_use]
    pub fn state(&self) -> IssuanceState {
        match self {
            StoredEntry::Grant(e) => e.state,
            StoredEntry::Verification(e) => e.state,
        }
    }

    /// The entry's bounds.
    #[must_use]
    pub fn bounds(&self) -> &CertificateBounds {
        match self {
            StoredEntry::Grant(e) => &e.bounds,
            StoredEntry::Verification(e) => &e.bounds,
        }
    }

    /// When it was reserved.
    #[must_use]
    pub fn reserved_at(&self) -> heimdall_contract::Timestamp {
        match self {
            StoredEntry::Grant(e) => e.reserved_at,
            StoredEntry::Verification(e) => e.reserved_at,
        }
    }
}

/// Read `entry` from `txn` (module docs, "Entry lookup"). Reads only.
///
/// # Errors
/// A store read error.
pub fn stored_entry(
    txn: &mut Txn<'_>,
    entry: &IssuanceRef,
) -> heimdall_store::Result<Option<StoredEntry>> {
    match entry.table {
        IssuanceTable::Grant => Ok(txn.issuance_entry(&entry.id)?.map(StoredEntry::Grant)),
        IssuanceTable::Verification => Ok(txn
            .verification_entry(&entry.id)?
            .map(StoredEntry::Verification)),
        // A table this build does not know is never signed for.
        #[allow(unreachable_patterns)]
        _ => Ok(None),
    }
}

/// The OpenSSH `SHA256:` fingerprint of a one-line public key (`type base64 [comment]`),
/// or `None` for anything that is not one (the blob must start with its type).
#[must_use]
pub fn subject_fingerprint(line: &str) -> Option<String> {
    use base64ct::Encoding as _;
    if line.contains(['\n', '\r', '\0']) {
        return None;
    }
    let mut fields = line.split([' ', '\t']).filter(|f| !f.is_empty());
    let (kind, blob) = (fields.next()?, fields.next()?);
    let decoded = base64ct::Base64::decode_vec(blob).ok()?;
    let len = usize::try_from(u32::from_be_bytes(decoded.get(..4)?.try_into().ok()?)).ok()?;
    if decoded.get(4..4usize.checked_add(len)?)? != kind.as_bytes() {
        return None;
    }
    let hex = Sha256Hex::of(&decoded);
    let digest: Vec<u8> = (0..hex.as_str().len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.as_str().get(i * 2..i * 2 + 2)?, 16).ok())
        .collect();
    Some(format!(
        "SHA256:{}",
        base64ct::Base64Unpadded::encode_string(&digest)
    ))
}

/// Whether a reservation made at `reserved_at` is too old, or too far in the future,
/// at `now` (ADR-0008 D3 item 4 step 1; a wall clock that moved back by more than
/// the bound is stale too).
fn stale(reserved_at: heimdall_contract::Timestamp, now: heimdall_contract::Timestamp) -> bool {
    let age = now.duration_since(reserved_at).unsigned_abs();
    age > MAX_RESERVATION_AGE
}

/// The read-only check of `entry` for `subject` (an OpenSSH public-key line) in
/// `txn`, a transaction over a read-only store, at the observation `now` that the
/// read-only time assessment judged `time`. Returns the entry's bounds, which the
/// issuer then checks against its ceilings.
///
/// Step 1 (D3 item 4): the entry exists and is `reserved` (else `entry_not_reserved`),
/// was reserved at most [`MAX_RESERVATION_AGE`] before `now` (else `entry_stale`), and
/// its subject fingerprint is `subject`'s (else `subject_mismatch`). Step 2: the
/// reserve predicate over the read-only snapshot (module docs), refusing with its
/// `issuance.*` or `verification.*` reason.
///
/// The outer `Result` is a store failure; the inner one the verdict.
///
/// # Errors
/// A store error.
pub fn assess(
    txn: &mut Txn<'_>,
    entry: &IssuanceRef,
    subject: &str,
    now: &TimeAnchor,
    time: &TimeStatus,
) -> heimdall_store::Result<Result<CertificateBounds, IssuerRefusal>> {
    let Some(stored) = stored_entry(txn, entry)? else {
        return Ok(Err(IssuerRefusal::EntryNotReserved));
    };
    if stored.state() != IssuanceState::Reserved {
        return Ok(Err(IssuerRefusal::EntryNotReserved));
    }
    if stale(stored.reserved_at(), now.wall) {
        return Ok(Err(IssuerRefusal::EntryStale));
    }
    if subject_fingerprint(subject).as_deref() != Some(stored.bounds().subject_fingerprint.as_str())
    {
        return Ok(Err(IssuerRefusal::SubjectMismatch));
    }
    let verdict = match &stored {
        StoredEntry::Grant(e) => {
            crate::operations::issuance_check_read_only(txn, e, &issuer_facts(e), now, time)?
                .map_err(IssuerRefusal::Issuance)
        }
        StoredEntry::Verification(e) => crate::operations::verification_check_read_only(
            txn,
            e,
            ISSUER_FACTS.subject_registered,
            *time,
            now.wall,
            Limits::default().verification_max_validity,
        )?
        .map_err(IssuerRefusal::Verification),
    };
    Ok(verdict.map(|()| stored.bounds().clone()))
}
