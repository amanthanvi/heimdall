//! Opaque identifiers (spec §4.2, §11.2). IDs are references, never bearer
//! credentials, and never change when routes, addresses, or labels change.
//!
//! Wire form: `<prefix>_<32 lowercase hex>` for runtime-generated IDs
//! (`op_`, `grant_`, `binding_`, `env_`, `evt_`, `res_`, `dev_`, `ws_`, `idn_`, ⟨M03⟩ `enr_`), and a
//! bounded caller-chosen token for `request_id`, `work_id`, profile, destination
//! and policy names. Parsing is bounded and rejects control characters.

use serde::{Deserialize, Serialize};

/// Maximum accepted length of any identifier on the wire.
pub const MAX_ID_LEN: usize = 128;

/// Identifier parse failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    /// Empty string.
    #[error("identifier is empty")]
    Empty,
    /// Longer than [`MAX_ID_LEN`].
    #[error("identifier exceeds {MAX_ID_LEN} bytes")]
    TooLong,
    /// Contains a byte outside `[A-Za-z0-9._:-]`.
    #[error("identifier contains a forbidden character")]
    ForbiddenChar,
    /// Missing or wrong prefix for a runtime-generated ID.
    #[error("identifier has the wrong prefix (expected {expected}_)")]
    WrongPrefix {
        /// The prefix this ID type requires.
        expected: &'static str,
    },
}

fn validate_token(s: &str) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > MAX_ID_LEN {
        return Err(IdError::TooLong);
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(IdError::ForbiddenChar);
    }
    Ok(())
}

macro_rules! prefixed_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Wire prefix without the underscore.
            pub const PREFIX: &'static str = $prefix;

            /// Build from 16 random bytes (hex-encoded). Callers obtain the bytes from
            /// the OS CSPRNG; this function performs no I/O.
            #[must_use]
            pub fn from_random_bytes(bytes: [u8; 16]) -> Self {
                let mut s = String::with_capacity($prefix.len() + 1 + 32);
                s.push_str($prefix);
                s.push('_');
                for b in bytes {
                    use std::fmt::Write as _;
                    let _ = write!(s, "{b:02x}");
                }
                Self(s)
            }

            /// Parse and validate a wire string.
            pub fn parse(s: &str) -> Result<Self, IdError> {
                validate_token(s)?;
                match s.split_once('_') {
                    Some((p, rest)) if p == $prefix && !rest.is_empty() => Ok(Self(s.to_owned())),
                    _ => Err(IdError::WrongPrefix { expected: $prefix }),
                }
            }

            /// The wire string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(s: String) -> Result<Self, IdError> {
                Self::parse(&s)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

macro_rules! token_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Parse and validate a wire string.
            pub fn parse(s: &str) -> Result<Self, IdError> {
                validate_token(s)?;
                Ok(Self(s.to_owned()))
            }

            /// The wire string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(s: String) -> Result<Self, IdError> {
                Self::parse(&s)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

prefixed_id!(
    /// Durable operation ID (spec §4.1 "Operation").
    OperationId, "op"
);
prefixed_id!(
    /// Grant ID (spec §4.1 "Grant").
    GrantId, "grant"
);
prefixed_id!(
    /// Work binding ID (spec §4.1 "Work binding").
    BindingId, "binding"
);
prefixed_id!(
    /// Stable environment ID (spec §4.1 "Environment").
    EnvironmentId, "env"
);
prefixed_id!(
    /// Device ID (spec §4.1 "Device").
    DeviceId, "dev"
);
prefixed_id!(
    /// Workspace (adopted checkout) ID (spec §4.1 "Workspace").
    WorkspaceId, "ws"
);
prefixed_id!(
    /// Managed resource ID (spec §4.1 "Managed resource").
    ResourceId, "res"
);
prefixed_id!(
    /// Event ID; consumers deduplicate by it (spec §11.5).
    EventId, "evt"
);
prefixed_id!(
    /// Server-issued decision record ID (ADR-0006 §3.1 attended confirmation).
    DecisionId, "dec"
);
prefixed_id!(
    /// Issuance-log entry ID (ADR-0005 §3.5 reserve/publish/void).
    IssuanceId, "iss"
);
prefixed_id!(
    /// Credential instance ID (ADR-0005 §12: key handle plus per-pair certificates).
    CredentialInstanceId, "cred"
);
prefixed_id!(
    /// Adopted existing-access identity in the catalog (ADR-0007 §7; m02-plan §5
    /// item 1). Runtime-generated at adoption; never derived from key material.
    IdentityId, "idn"
);

prefixed_id!(
    /// ⟨M03⟩ Enrollment record ID (m03-plan §5 item 1; ADR-0008 D5 §6.2). The remote
    /// marker is `heimdall:<enrollment-id>`, so the ID is the add's idempotency key.
    EnrollmentId, "enr"
);
prefixed_id!(
    /// ⟨M03⟩ Owned connection ID (an `owned_connections` row; ADR-0008 D8; m03-plan
    /// §5 items 4, 4a). Runtime-generated; never a PID.
    ConnectionId, "conn"
);
prefixed_id!(
    /// ⟨M03⟩ Foreign removal record ID (a `foreign_removals` row; ADR-0008 D4 item
    /// 5). Minted by this installation; never the bundle's marker or enrollment ID.
    ForeignRemovalId, "frm"
);

/// ⟨M03⟩ A CA public key's fingerprint: `SHA256:` followed by exactly 43 characters
/// of unpadded standard base64 (`A-Za-z0-9+/`), as `ssh-keygen -l` prints it
/// (m03-plan §5 item 1). Validated on parse and on decode; compared exactly.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct CaFingerprint(String);

/// A malformed [`CaFingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a CA fingerprint is SHA256: followed by 43 unpadded base64 characters")]
pub struct CaFingerprintError;

impl CaFingerprint {
    /// The fixed prefix.
    pub const PREFIX: &'static str = "SHA256:";
    /// The number of base64 characters after the prefix (a 32-byte digest, unpadded).
    pub const DIGEST_CHARS: usize = 43;

    /// Parse and validate a wire string.
    pub fn parse(s: &str) -> Result<Self, CaFingerprintError> {
        let Some(digest) = s.strip_prefix(Self::PREFIX) else {
            return Err(CaFingerprintError);
        };
        let ok = digest.len() == Self::DIGEST_CHARS
            && digest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(CaFingerprintError)
        }
    }

    /// The wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CaFingerprint {
    type Error = CaFingerprintError;
    fn try_from(s: String) -> Result<Self, CaFingerprintError> {
        Self::parse(&s)
    }
}

impl From<CaFingerprint> for String {
    fn from(f: CaFingerprint) -> String {
        f.0
    }
}

impl std::fmt::Display for CaFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

token_id!(
    /// Caller-chosen request ID; part of the idempotency key (spec §11.4).
    RequestId
);
token_id!(
    /// Caller-chosen work ID; a continuing binding cannot reset its expiry by
    /// changing it (spec §6.1).
    WorkId
);
token_id!(
    /// Profile name (spec §4.1 "Profile").
    ProfileId
);
token_id!(
    /// Destination ID (spec §4.1 "Destination"); route-independent.
    DestinationId
);
token_id!(
    /// Standing policy ID (spec §4.1 "Standing policy").
    PolicyId
);
token_id!(
    /// Remote account name on a destination.
    AccountName
);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_ids_round_trip() {
        let id = OperationId::from_random_bytes([0xab; 16]);
        assert!(id.as_str().starts_with("op_"));
        assert_eq!(id.as_str().len(), 3 + 32);
        let parsed = OperationId::parse(id.as_str()).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(
            GrantId::parse(id.as_str()),
            Err(IdError::WrongPrefix { expected: "grant" })
        );
    }

    #[test]
    fn tokens_are_bounded_and_sanitized() {
        assert_eq!(RequestId::parse(""), Err(IdError::Empty));
        assert_eq!(
            RequestId::parse(&"a".repeat(MAX_ID_LEN + 1)),
            Err(IdError::TooLong)
        );
        assert_eq!(RequestId::parse("req 42"), Err(IdError::ForbiddenChar));
        assert_eq!(
            RequestId::parse("req\u{1b}[31m"),
            Err(IdError::ForbiddenChar)
        );
        assert!(RequestId::parse("req_42").is_ok());
    }

    #[test]
    fn m03_ids_validate() {
        let e = EnrollmentId::from_random_bytes([0x01; 16]);
        assert!(e.as_str().starts_with("enr_"));
        let ok = format!("SHA256:{}", "a".repeat(42) + "/");
        assert_eq!(CaFingerprint::parse(&ok).unwrap().as_str(), ok);
        for bad in [
            String::new(),
            "SHA256:".to_owned(),
            format!("SHA256:{}", "a".repeat(42)),
            format!("SHA256:{}", "a".repeat(44)),
            format!("SHA256:{}=", "a".repeat(42)),
            format!("sha256:{}", "a".repeat(43)),
            format!("MD5:{}", "a".repeat(43)),
        ] {
            assert_eq!(CaFingerprint::parse(&bad), Err(CaFingerprintError), "{bad}");
        }
        let r: Result<CaFingerprint, _> = serde_json::from_str("\"SHA256:short\"");
        assert!(r.is_err());
    }

    #[test]
    fn serde_rejects_invalid() {
        let r: Result<WorkId, _> = serde_json::from_str("\"bad id\"");
        assert!(r.is_err());
    }
}
