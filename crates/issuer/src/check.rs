//! The issuer's reservation check (ADR-0008 D3 item 4 steps 1–3; m03-plan U3
//! `check::verify_reservation`): the entry's state and age, the subject match, the
//! pure predicate through `app::issuance_ro::assess`, and the format ceilings,
//! refusing with a [`crate::protocol::IssuerRefusal`].
//!
//! Everything is read in **one** read transaction over the read-only store, with the
//! issuer's own clock observation, assessed by `TimeGate::assess_read_only_in` (which
//! persists nothing and fails closed without an anchor).
//!
//! **Order.** A missing or settled entry refuses `entry_not_reserved` first. The
//! format ceilings (step 3) are then checked on the stored bounds **before** the
//! predicate (step 2): both only refuse, and a bound no predicate admits (two
//! principals, `permit-X11-forwarding`) is reported as the ceiling it breaks
//! (`ceiling_exceeded`) rather than as the predicate refusal that would also catch it.
//! Then `issuance_ro::assess` (step 1's age and subject, then step 2). The
//! "subject is not a CA key the issuer holds" ceiling is `ca::CaSet::sign`'s, since
//! only the CA set knows its keys.
//!
//! **The ceilings** (D3 item 4 step 3):
//! * exactly one principal, `hm:<[A-Za-z0-9._-]+>:<[A-Za-z0-9._-]+>` or
//!   `hm:verify-negative:<32 hex>` (one string from that alphabet cannot name two);
//! * no critical option (a reservation's bounds carry none, so none is ever signed);
//! * extensions ⊆ {`permit-pty`, `permit-agent-forwarding`, `permit-port-forwarding`,
//!   `permit-user-rc`}, never `permit-X11-forwarding`;
//! * `valid_before − valid_after` ≤ the grant's window (`deadline − starts_at`) plus
//!   60 s, or 300 s plus 60 s for a verification entry, and `valid_after` <
//!   `valid_before`;
//! * key ID `heimdall:<environment>:<grant | operation>:<decimal serial>`, where the
//!   environment is this store's and the ID is the entry's own grant (or operation).
//!   The serial is a decimal number but need not equal the entry's: a re-reservation
//!   keeps the key ID with a fresh serial (ADR-0006 §13.8 item 1; questions file
//!   U3-Q3).

use std::time::Duration;

use heimdall_app::issuance_ro::{self, StoredEntry};
use heimdall_app::timegate::TimeGate;
use heimdall_domain::issuance::{CertificateBounds, EXTENSION_PTY, IssuanceState};
use heimdall_domain::verification::NEGATIVE_PRINCIPAL_PREFIX;
use heimdall_store::{Store, Txn};

use crate::protocol::{IssuanceRef, IssuerRefusal, TOKEN_HEX_CHARS};

/// The extensions a certificate may ever carry (ADR-0008 D3 item 4 step 3).
pub const ALLOWED_EXTENSIONS: [&str; 4] = [
    EXTENSION_PTY,
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-user-rc",
];

/// The slack on every validity ceiling (`valid_after` is the issuance time minus
/// 60 s; ADR-0005 §3.4).
pub const VALIDITY_SLACK: Duration = Duration::from_secs(60);

/// A verification certificate's longest validity before the slack (D5 §6.5 item 2).
pub const VERIFICATION_VALIDITY: Duration = Duration::from_secs(300);

/// The key ID prefix (`cert::key_id`).
const KEY_ID_PREFIX: &str = "heimdall:";

/// Whether `s` is a non-empty run of `[A-Za-z0-9._-]`.
fn is_principal_part(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The principal ceiling: one `hm:<part>:<part>` or `hm:verify-negative:<32 hex>`.
#[must_use]
pub fn principal_within_ceiling(principal: &str) -> bool {
    if let Some(nonce) = principal.strip_prefix(NEGATIVE_PRINCIPAL_PREFIX) {
        return nonce.len() == TOKEN_HEX_CHARS
            && nonce
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    }
    let Some(rest) = principal.strip_prefix("hm:") else {
        return false;
    };
    let mut parts = rest.split(':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(d), Some(a), None) if is_principal_part(d) && is_principal_part(a)
    )
}

/// The extension ceiling.
#[must_use]
pub fn extensions_within_ceiling<'a>(mut extensions: impl Iterator<Item = &'a String>) -> bool {
    extensions.all(|e| ALLOWED_EXTENSIONS.contains(&e.as_str()))
}

/// The validity ceiling: `valid_after < valid_before` and the span is at most `window`
/// plus [`VALIDITY_SLACK`].
#[must_use]
pub fn validity_within_ceiling(bounds: &CertificateBounds, window: Duration) -> bool {
    let Ok(span) = Duration::try_from(bounds.valid_before.duration_since(bounds.valid_after))
    else {
        return false;
    };
    !span.is_zero() && span <= window.saturating_add(VALIDITY_SLACK)
}

/// The key-ID ceiling: `heimdall:<environment>:<id>:<decimal serial>`.
#[must_use]
pub fn key_id_within_ceiling(key_id: &str, environment: &str, id: &str) -> bool {
    let Some(rest) = key_id.strip_prefix(KEY_ID_PREFIX) else {
        return false;
    };
    let mut parts = rest.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(e), Some(i), Some(serial), None) => {
            e == environment
                && i == id
                && !serial.is_empty()
                && serial.bytes().all(|b| b.is_ascii_digit())
                && serial.parse::<u64>().is_ok()
        }
        _ => false,
    }
}

/// Every format ceiling of a stored entry (module docs). Reads the grant (its window)
/// and this store's environment.
fn ceilings(txn: &mut Txn<'_>, stored: &StoredEntry) -> heimdall_store::Result<bool> {
    let bounds = stored.bounds();
    let Some(environment) = txn.self_environment()? else {
        return Ok(false);
    };
    let (window, id) = match stored {
        StoredEntry::Grant(e) => {
            let window = match txn.grant(&e.grant)? {
                Some(g) => Duration::try_from(g.deadline.effective.duration_since(g.starts_at))
                    .unwrap_or(Duration::ZERO),
                // The predicate refuses a missing grant; no window can be judged.
                None => Duration::ZERO,
            };
            (window, e.grant.to_string())
        }
        StoredEntry::Verification(e) => (VERIFICATION_VALIDITY, e.operation.to_string()),
    };
    Ok(principal_within_ceiling(&bounds.principal)
        && extensions_within_ceiling(bounds.extensions.iter())
        && validity_within_ceiling(bounds, window)
        && key_id_within_ceiling(&bounds.key_id, environment.as_str(), &id))
}

/// Whether the store, in this snapshot, has `ca` registered `active` or `pending`
/// (the states that may sign a verification certificate; ADR-0008 D3 item 4 step 4,
/// D4 item 3). No CA named, or any other state, is `false`.
fn verification_ca_may_sign(
    txn: &mut Txn<'_>,
    ca: Option<&heimdall_contract::ids::CaFingerprint>,
) -> heimdall_store::Result<bool> {
    let Some(ca) = ca else {
        return Ok(false);
    };
    Ok(txn.issuers()?.iter().any(|i| {
        &i.ca_fingerprint == ca
            && matches!(
                i.state,
                heimdall_contract::issuer::CaState::Active
                    | heimdall_contract::issuer::CaState::Pending
            )
    }))
}

/// D3 item 4 steps 1–3 for `entry` and `subject` (an OpenSSH public-key line) in one
/// read transaction over `ro_store`, at a fresh observation of `time`'s clock judged
/// by the read-only assessment. Returns the bounds to sign.
///
/// # Errors
/// The [`IssuerRefusal`] of the first failing step (module docs, "Order"). A store
/// that cannot be read refuses `entry_not_reserved`: no reservation is confirmed.
pub fn verify_reservation(
    ro_store: &Store,
    time: &TimeGate,
    entry: &IssuanceRef,
    subject: &str,
) -> Result<CertificateBounds, IssuerRefusal> {
    ro_store
        .transaction(|txn| {
            let Some(stored) = issuance_ro::stored_entry(txn, entry)? else {
                return Ok(Err(IssuerRefusal::EntryNotReserved));
            };
            if stored.state() != IssuanceState::Reserved {
                return Ok(Err(IssuerRefusal::EntryNotReserved));
            }
            if !ceilings(txn, &stored)? {
                return Ok(Err(IssuerRefusal::CeilingExceeded));
            }
            // ⟨integrator, wave-2 review⟩ D3 item 4 step 4 for a verification entry, in
            // this snapshot: the predicate compares the CA with the plan's but never
            // reads its state, and the CA set holds the state it was loaded in. A CA
            // the store no longer has `active` or `pending` (retiring before its
            // `unload` arrives) signs nothing (`ca_not_loaded`). Grant entries get the
            // same check from `issuance::check` (`ca_retiring`).
            if let StoredEntry::Verification(e) = &stored
                && !verification_ca_may_sign(txn, e.bounds.ca_fingerprint.as_ref())?
            {
                return Ok(Err(IssuerRefusal::CaNotLoaded));
            }
            let (now, status) = time.assess_read_only_in(txn)?;
            issuance_ro::assess(txn, entry, subject, &now, &status)
        })
        .unwrap_or(Err(IssuerRefusal::EntryNotReserved))
}
