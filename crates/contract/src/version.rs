//! Schema and protocol versions (spec §11.2; ADR-0006 §9).

use serde::{Deserialize, Serialize};

/// Major version of every structured result and event. Only the major is carried;
/// additive changes do not bump it (ADR-0006 §9).
pub const SCHEMA_VERSION: &str = "1";

/// Local IPC protocol version negotiated in the hello exchange (ADR-0006 §2).
pub const PROTOCOL_VERSION: u16 = 1;

/// A `schema_version` value as received from a peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct SchemaVersion(pub String);

impl SchemaVersion {
    /// The version this build emits.
    #[must_use]
    pub fn current() -> Self {
        Self(SCHEMA_VERSION.to_owned())
    }

    /// Whether a reader built against [`SCHEMA_VERSION`] may consume a document
    /// carrying this version. Only an exact major match is supported in M01; an
    /// unsupported major must be rejected explicitly, never read as empty
    /// (spec §11.2, §13.3).
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.0 == SCHEMA_VERSION
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::current()
    }
}
