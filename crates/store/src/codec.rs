//! Column encodings shared by the store: fixed-width UTC timestamps (so SQL text
//! comparison equals instant comparison), enum names, JSON documents with the
//! private-key guard, and SQLite error classification.

use heimdall_contract::Timestamp;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Result, StoreError};

/// Armor suffix shared by PEM and OpenSSH private keys (`-----BEGIN OPENSSH
/// PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN ENCRYPTED
/// PRIVATE KEY-----`, ...). The store holds references to secrets, never secrets
/// (spec §13.3); a document carrying key armor is refused before any write.
const PRIVATE_KEY_ARMOR: &str = "PRIVATE KEY-----";

/// A malformed-document error with a fixed message (never echoes content).
pub(crate) fn doc_error(msg: &'static str) -> StoreError {
    StoreError::Json(<serde_json::Error as serde::ser::Error>::custom(msg))
}

/// Fixed-width UTC rendering `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`. Every timestamp
/// column the store compares in SQL uses this form, so lexicographic order equals
/// chronological order (RFC 3339 with variable fractional digits does not have
/// that property).
pub(crate) fn ts(t: Timestamp) -> String {
    let dt = jiff::tz::Offset::UTC.to_datetime(t);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.subsec_nanosecond()
    )
}

/// Parse a timestamp column.
pub(crate) fn parse_ts(s: &str) -> Result<Timestamp> {
    s.parse::<Timestamp>()
        .map_err(|_| doc_error("stored timestamp is malformed"))
}

/// The serde string form of a unit enum variant (`"succeeded"`, `"ACCESS_READY"`).
pub(crate) fn enum_str<T: Serialize>(v: &T) -> Result<String> {
    match serde_json::to_value(v)? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(doc_error("expected a unit enum variant")),
    }
}

/// Inverse of [`enum_str`].
pub(crate) fn enum_parse<T: DeserializeOwned>(s: &str) -> Result<T> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_owned(),
    ))?)
}

/// Serialize a document for a JSON column, refusing private-key material.
pub(crate) fn doc<T: Serialize + ?Sized>(v: &T) -> Result<String> {
    let s = serde_json::to_string(v)?;
    if s.contains(PRIVATE_KEY_ARMOR) {
        return Err(doc_error(
            "refusing to persist private key material (references only)",
        ));
    }
    Ok(s)
}

/// Parse a JSON column.
pub(crate) fn parse_doc<T: DeserializeOwned>(s: &str) -> Result<T> {
    Ok(serde_json::from_str(s)?)
}

/// Map SQLite corruption codes to [`StoreError::Corrupt`]; everything else stays
/// [`StoreError::Sqlite`]. Messages are fixed strings (no paths, no content).
pub(crate) fn classify(e: rusqlite::Error) -> StoreError {
    use rusqlite::ErrorCode as C;
    match e.sqlite_error_code() {
        Some(C::DatabaseCorrupt) => {
            StoreError::Corrupt("sqlite reported a malformed database".into())
        }
        Some(C::NotADatabase) => StoreError::Corrupt("file is not a state database".into()),
        _ => StoreError::Sqlite(e),
    }
}

/// [`classify`] lifted to [`StoreError`].
pub(crate) fn reclassify(e: StoreError) -> StoreError {
    match e {
        StoreError::Sqlite(inner) => classify(inner),
        other => other,
    }
}

/// `u64` → SQLite integer; values above `i64::MAX` are refused.
pub(crate) fn int(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| doc_error("integer exceeds the storable range"))
}

/// SQLite integer → `u64`; negative values are refused.
pub(crate) fn uint(v: i64) -> Result<u64> {
    u64::try_from(v).map_err(|_| doc_error("stored integer is negative"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_timestamps_sort_chronologically() {
        let a: Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
        let b: Timestamp = "2026-10-01T00:00:00.5Z".parse().unwrap();
        let c: Timestamp = "2026-10-01T00:00:01Z".parse().unwrap();
        assert_eq!(ts(a), "2026-10-01T00:00:00.000000000Z");
        assert!(ts(a) < ts(b) && ts(b) < ts(c));
        assert_eq!(parse_ts(&ts(b)).unwrap(), b);
    }

    #[test]
    fn enum_names_round_trip() {
        use heimdall_contract::OperationState;
        let s = enum_str(&OperationState::AwaitingApproval).unwrap();
        assert_eq!(s, "awaiting_approval");
        let back: OperationState = enum_parse(&s).unwrap();
        assert_eq!(back, OperationState::AwaitingApproval);
    }

    #[test]
    fn key_armor_is_refused() {
        let v = serde_json::json!({"note": "-----BEGIN OPENSSH PRIVATE KEY-----"});
        let e = doc(&v).unwrap_err();
        assert!(!e.to_string().contains("OPENSSH"));
    }
}
