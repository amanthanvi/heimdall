//! Canonical JSON and request hashing (spec §11.4; ADR-0006 §7).
//!
//! Canonical form: object keys sorted bytewise, no insignificant whitespace,
//! serde_json's number and string escaping. It does not depend on the
//! `preserve_order` feature of any dependency; keys are sorted explicitly.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 of a canonical request document. Serialized as lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestHash(pub [u8; 32]);

impl serde::Serialize for RequestHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for RequestHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        RequestHash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl schemars::JsonSchema for RequestHash {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RequestHash".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "string", "pattern": "^[0-9a-f]{64}$" })
    }
}

impl RequestHash {
    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Parse lowercase or uppercase hex.
    pub fn from_hex(s: &str) -> Result<Self, CanonicalError> {
        if s.len() != 64 {
            return Err(CanonicalError::BadHash);
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(chunk[0]).ok_or(CanonicalError::BadHash)?;
            let lo = hex_val(chunk[1]).ok_or(CanonicalError::BadHash)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Canonicalization failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalError {
    /// A float that is not finite cannot be canonicalized.
    #[error("non-finite number cannot be canonicalized")]
    NonFiniteNumber,
    /// Malformed hash string.
    #[error("malformed request hash")]
    BadHash,
}

/// Produce the canonical byte form of a JSON value.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            if let Some(f) = n.as_f64()
                && !f.is_finite()
            {
                return Err(CanonicalError::NonFiniteNumber);
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => {
            // serde_json's escaping is deterministic for a given string.
            let escaped = serde_json::to_string(s).map_err(|_| CanonicalError::NonFiniteNumber)?;
            out.extend_from_slice(escaped.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let escaped =
                    serde_json::to_string(key).map_err(|_| CanonicalError::NonFiniteNumber)?;
                out.extend_from_slice(escaped.as_bytes());
                out.push(b':');
                if let Some(v) = map.get(*key) {
                    write_canonical(v, out)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// SHA-256 over the canonical form, domain-separated by a context string so a
/// request hash can never collide with another use of the same bytes.
pub fn request_hash(context: &str, value: &Value) -> Result<RequestHash, CanonicalError> {
    let bytes = canonical_json(value)?;
    let mut hasher = Sha256::new();
    hasher.update(b"heimdall-request-hash/1\0");
    hasher.update(context.as_bytes());
    hasher.update(b"\0");
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(RequestHash(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_matter() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"d":[1,2],"c":"x"}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"c":"x","d":[1,2]},"b":1}"#).unwrap();
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(
            String::from_utf8(canonical_json(&a).unwrap()).unwrap(),
            r#"{"a":{"c":"x","d":[1,2]},"b":1}"#
        );
    }

    #[test]
    fn array_order_matters() {
        assert_ne!(
            canonical_json(&json!([1, 2])).unwrap(),
            canonical_json(&json!([2, 1])).unwrap()
        );
    }

    #[test]
    fn context_separates_hashes() {
        let v = json!({"x": 1});
        assert_ne!(
            request_hash("ensure", &v).unwrap(),
            request_hash("delegate", &v).unwrap()
        );
    }

    #[test]
    fn hex_round_trip() {
        let h = request_hash("t", &json!(null)).unwrap();
        assert_eq!(RequestHash::from_hex(&h.to_hex()).unwrap(), h);
        assert_eq!(RequestHash::from_hex("zz"), Err(CanonicalError::BadHash));
    }
}
