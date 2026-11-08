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
//! **Wave 0:** the body is U3's. Until it lands, [`assess`] refuses every entry
//! (fail closed) with [`IssuerRefusal::EntryNotReserved`]: no reservation is
//! confirmed, so nothing is signed.

use heimdall_domain::issuance::CertificateBounds;
use heimdall_domain::time::{TimeAnchor, TimeStatus};
use heimdall_store::Txn;

use crate::ports::{IssuanceRef, IssuerRefusal};

/// The read-only check of `entry` for `subject` (an OpenSSH public-key line) in
/// `txn`, a transaction over a read-only store, at the observation `now` that the
/// read-only time assessment judged `time`. Returns the entry's bounds, which the
/// issuer then checks against its ceilings.
///
/// The outer `Result` is a store failure; the inner one the verdict.
///
/// # Errors
/// A store error. The verdict is `Err(IssuerRefusal)` for any failing predicate;
/// in wave 0 it is always [`IssuerRefusal::EntryNotReserved`].
pub fn assess(
    _txn: &mut Txn<'_>,
    _entry: &IssuanceRef,
    _subject: &str,
    _now: &TimeAnchor,
    _time: &TimeStatus,
) -> heimdall_store::Result<Result<CertificateBounds, IssuerRefusal>> {
    Ok(Err(IssuerRefusal::EntryNotReserved))
}
