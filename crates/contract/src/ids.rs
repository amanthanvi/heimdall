//! Opaque identifiers (spec §4.2, §11.2). IDs are references, never bearer
//! credentials, and never change when routes, addresses, or labels change.
//!
//! Wire form: `<prefix>_<32 lowercase hex>` for runtime-generated IDs
//! (`op_`, `grant_`, `binding_`, `env_`, `evt_`, `res_`, `dev_`, `ws_`), and a
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
    fn serde_rejects_invalid() {
        let r: Result<WorkId, _> = serde_json::from_str("\"bad id\"");
        assert!(r.is_err());
    }
}
