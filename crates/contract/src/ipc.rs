//! Local IPC message set and hard limits (spec §13.2, §11.5; ADR-0006 §2).
//!
//! Transport: owner-only Unix socket or owner-only named pipe, authenticated by peer
//! credentials (`heimdall-ipc`). Framing: `u32` big-endian length prefix followed by
//! one UTF-8 JSON object; frames above the per-endpoint limit are rejected and the
//! connection closed. The first frame each way is the hello exchange; afterwards the
//! client sends requests and subscriptions, the server sends responses and events.
//!
//! The signing endpoint does **not** use these messages: it speaks the bounded SSH
//! agent protocol (`heimdall_ipc::signing`). Exposing one endpoint never exposes
//! the other (spec §13.2).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::envelope::Envelope;
use crate::event::{Cursor, Event, EventFilter};
use crate::request::Request;
use crate::version::SchemaVersion;

/// Maximum control frame size (hello, request, response, event).
pub const MAX_CONTROL_FRAME_BYTES: usize = 1 << 20;
/// Maximum size of the first (hello) frame in either direction.
pub const MAX_HELLO_FRAME_BYTES: usize = 16 << 10;
/// Maximum SSH agent message accepted or produced by the signing endpoint.
pub const MAX_SIGNING_FRAME_BYTES: usize = 256 << 10;
/// Maximum concurrently outstanding requests per control connection.
pub const MAX_INFLIGHT_REQUESTS_PER_CONNECTION: usize = 16;
/// Maximum concurrent subscriptions per control connection.
pub const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 4;
/// Buffered events per subscription before the server emits `ResyncRequired` and
/// drops the backlog (spec §11.5 backpressure).
pub const EVENT_BUFFER_PER_SUBSCRIPTION: usize = 256;
/// Maximum concurrent control connections per endpoint.
pub const MAX_CONTROL_CONNECTIONS: usize = 64;
/// Maximum concurrent signing connections per endpoint.
pub const MAX_SIGNING_CONNECTIONS: usize = 64;
/// Time a connection may stay silent before the hello frame (milliseconds).
pub const HELLO_TIMEOUT_MS: u64 = 5_000;

/// Capability names negotiated in the hello exchange (ADR-0006 §2.4).
pub mod capability {
    /// The six primitives over the control endpoint.
    pub const OPERATIONS_V1: &str = "operations/1";
    /// Event subscriptions with cursors.
    pub const EVENTS_V1: &str = "events/1";
    /// Owner-channel policy actions.
    pub const OWNER_POLICY_V1: &str = "owner-policy/1";
    /// Schema export on demand (R-AP-08).
    pub const SCHEMA_DISCOVERY_V1: &str = "schema-discovery/1";
    /// Owner-channel service control: `Request::Shutdown` (ADR-0006 §2.4, §13.6
    /// item 8). A session that did not negotiate it cannot send `Shutdown`
    /// (`SCHEMA_UNSUPPORTED`).
    pub const SERVICE_CONTROL_V1: &str = "service-control/1";
}

/// Identifies the peer software; informational only, never authority (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeerInfo {
    /// Program name (`heimdall-cli`, `heimdall-tui`, a third-party wrapper).
    pub name: String,
    /// Program version.
    pub version: String,
}

/// How the server authenticated the client (reported back for transparency).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalInfo {
    /// Unix peer credentials matched the runtime's user.
    OsUserUnix {
        /// Numeric user ID.
        uid: u32,
    },
    /// Windows client SID matched the runtime's user.
    OsUserWindows {
        /// SID string; an identifier, not a secret.
        sid: String,
    },
}

/// First client frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClientHello {
    /// Protocol version the client speaks.
    pub protocol: u16,
    /// Schema major the client expects.
    pub schema_version: SchemaVersion,
    /// Client software.
    pub client: PeerInfo,
    /// Capabilities the client understands.
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    /// Capabilities the client requires; a missing one is rejected explicitly
    /// (spec §11.2 "required capability must be rejected explicitly"). Must be a
    /// subset of the negotiated set (`capabilities ∩ server offer`), ADR-0006 §2.3.
    #[serde(default)]
    pub required: BTreeSet<String>,
    /// Interaction mode of this session. `non_interactive` sessions can never
    /// become attended: `Attend` is refused with `INTERACTION_REQUIRED`
    /// (ADR-0006 §3.1). Defaults to non-interactive when omitted.
    #[serde(default)]
    pub interaction: crate::request::InteractionMode,
}

/// First server frame on success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServerHello {
    /// Protocol version in effect.
    pub protocol: u16,
    /// Schema major the server emits.
    pub schema_version: SchemaVersion,
    /// Server software.
    pub server: PeerInfo,
    /// Capabilities in effect (intersection).
    pub capabilities: BTreeSet<String>,
    /// How the client was authenticated.
    pub principal: PrincipalInfo,
    /// Environment ID of this runtime.
    pub environment_id: crate::ids::EnvironmentId,
}

/// Client to server frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientMessage {
    /// Hello (must be first).
    Hello(ClientHello),
    /// A request; `seq` is unique per connection and echoed in the response.
    Request {
        /// Per-connection sequence number.
        seq: u64,
        /// The request.
        request: Request,
    },
    /// Subscribe to events; the server replies with a `Subscribed` response.
    Subscribe {
        /// Per-connection sequence number.
        seq: u64,
        /// Filter.
        #[serde(default)]
        filter: EventFilter,
        /// Resume point; absent means "from a fresh snapshot".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_cursor: Option<Cursor>,
    },
    /// Stop a subscription.
    Unsubscribe {
        /// Per-connection sequence number.
        seq: u64,
        /// Subscription to stop.
        subscription: u64,
    },
    /// Mark this session attended (owner present at the CLI/TUI interactive flow;
    /// ADR-0006 §3.1). Only valid on a session whose hello declared `interactive`;
    /// otherwise answered `INTERACTION_REQUIRED`. The runtime, not this frame,
    /// decides attendance; the same-user terminal-imitation limit is disclosed.
    Attend {
        /// Per-connection sequence number.
        seq: u64,
    },
}

/// Server to client frames.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ServerMessage {
    /// Hello accepted.
    Hello(ServerHello),
    /// Hello rejected; the server closes the connection after this frame. The
    /// envelope carries `SCHEMA_UNSUPPORTED` or `USAGE_ERROR`.
    Reject(Envelope<crate::envelope::ErrorData>),
    /// Response to a request.
    Response {
        /// Echoed sequence number.
        in_reply_to: u64,
        /// Result envelope with the primitive's payload or an error.
        envelope: Envelope<serde_json::Value>,
    },
    /// Subscription established (ADR-0006 §8). Delivery order afterwards: retained
    /// backlog after the client's cursor (or nothing when a snapshot was taken),
    /// then live events strictly after `cursor`; overlap is deduplicated by the
    /// server, so a consumer may still deduplicate by `event_id` but need not.
    Subscribed {
        /// Echoed sequence number.
        in_reply_to: u64,
        /// Subscription handle.
        subscription: u64,
        /// Head boundary read in the subscription transaction: live events follow
        /// strictly after it. With `snapshot`, it is the snapshot's consistent
        /// boundary; without, it is the boundary **after** the backlog that
        /// follows (not the client's cursor), so a consumer resumes from the
        /// cursor of the last event it processed, not from this value, until the
        /// backlog has been consumed.
        cursor: Cursor,
        /// Present when the client sent no cursor, or sent an expired/foreign one
        /// and the server chose to resync it: a transactionally consistent view
        /// taken at `cursor`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snapshot: Option<crate::event::Snapshot<serde_json::Value>>,
    },
    /// An event for a subscription.
    Event {
        /// Subscription handle.
        subscription: u64,
        /// The event.
        event: Event,
    },
    /// The server is closing the connection (shutdown, limit, or protocol error).
    Goodbye {
        /// Reason code.
        code: crate::code::Code,
        /// Human text.
        message: String,
    },
}

// Limit ordering is a compile-time invariant.
const _: () = assert!(MAX_HELLO_FRAME_BYTES < MAX_CONTROL_FRAME_BYTES);
const _: () = assert!(MAX_SIGNING_FRAME_BYTES < MAX_CONTROL_FRAME_BYTES);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips() {
        let hello = ClientMessage::Hello(ClientHello {
            protocol: crate::PROTOCOL_VERSION,
            schema_version: SchemaVersion::current(),
            client: PeerInfo {
                name: "test".into(),
                version: "0".into(),
            },
            capabilities: [capability::OPERATIONS_V1.to_owned()].into_iter().collect(),
            required: BTreeSet::new(),
            interaction: crate::request::InteractionMode::NonInteractive,
        });
        let json = serde_json::to_string(&hello).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
    }
}
