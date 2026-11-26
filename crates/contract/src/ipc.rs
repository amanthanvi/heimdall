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
    /// Setup and catalog requests (`Request::Setup`, `Request::Catalog`; m02-plan
    /// §5 item 4). A session without it gets `SCHEMA_UNSUPPORTED`. **Not offered**
    /// until the M02 activation change set: `heimdall_ipc::session` and `inspect
    /// capabilities` do not list it yet, so no session can negotiate it.
    pub const SETUP_V1: &str = "setup/1";
    /// ⟨M03⟩ `Request::Issuer` (m03-plan §5 item 15). **Declared, not offered** in
    /// wave 0: `heimdall_ipc::session` and `inspect capabilities` do not list it
    /// until the activation change set (U0b row 13, phase 2).
    pub const ISSUER_V1: &str = "issuer/1";
    /// ⟨M03⟩ `Request::Enrollment`. Declared, not offered in wave 0.
    pub const ENROLLMENT_V1: &str = "enrollment/1";
    /// ⟨M03⟩ Managed-credential results (`ensure` with `managed_certificate`).
    /// Declared, not offered in wave 0.
    pub const MANAGED_CREDENTIALS_V1: &str = "managed-credentials/1";
    /// ⟨M03⟩ `Request::Connections`. Declared, not offered in wave 0.
    pub const CONNECTIONS_V1: &str = "connections/1";
    /// ⟨M03⟩ The four M03 capabilities, declared and **not offered** in wave 0.
    pub const M03_DECLARED: [&str; 4] = [
        ISSUER_V1,
        ENROLLMENT_V1,
        MANAGED_CREDENTIALS_V1,
        CONNECTIONS_V1,
    ];
    /// ⟨M04⟩ Revision 5 (m04-plan §5 item 1): `Request::Environment` and the
    /// environment views. **Declared, not offered** until M04 wires it.
    pub const ENVIRONMENTS_V1: &str = "environments/1";
    /// ⟨M05⟩ Revision 5 (m05-plan §4 item 10): the trusted-work forms (`ensure` with
    /// `context` or `covered_only`, the new policy actions and targets, `revoke` with a
    /// `target`, `catalog apply_import`, the M05 inspect subjects). **Declared, not
    /// offered** until M05 W3 wires it.
    pub const TRUSTED_WORK_V1: &str = "trusted-work/1";
    /// ⟨M04, M05⟩ The two revision-5 capabilities, declared and **not offered** by joint
    /// wave 0.
    pub const REVISION_5_DECLARED: [&str; 2] = [ENVIRONMENTS_V1, TRUSTED_WORK_V1];
    /// ⟨M06⟩ Revision 6 (ADR-0012 §6.3, §9 item 4): paired management clients and the
    /// controller's environment management (`Request::RemoteEnvironment`,
    /// `Request::Device`); a hello carrying `remote_client` needs a runtime that offers it.
    /// **Declared, not offered** in wave 0.
    pub const REMOTE_CONTROL_V1: &str = "remote-control/1";
    /// ⟨M06⟩ Revision 6: the runner-internal requests (`Request::Runner`). **Declared, not
    /// offered** in wave 0.
    pub const RUNNER_V1: &str = "runner/1";
    /// ⟨M06⟩ Revision 6: destinations with several approved routes (`Request::Route`,
    /// the helper's `resolve_binding`). **Declared, not offered** in wave 0.
    pub const ROUTES_V1: &str = "routes/1";
    /// ⟨M06⟩ Revision 6: the Iroh transport (`Request::Transport`, roost adoption).
    /// **Declared, not offered** in wave 0.
    pub const TRANSPORT_IROH_V1: &str = "transport-iroh/1";
    /// ⟨M06⟩ The four revision-6 capabilities, declared and **not offered** by wave 0
    /// (`heimdall_ipc::session` and `inspect capabilities` list none of them).
    pub const REVISION_6_DECLARED: [&str; 4] =
        [REMOTE_CONTROL_V1, RUNNER_V1, ROUTES_V1, TRANSPORT_IROH_V1];
    /// ⟨rev7⟩ ADR-0013 §6.1, D2: the `select` and `page` forms of `inspect`
    /// ([`crate::page`]). **Offered** (m07-plan U3) on every read role's session: every role
    /// set ([`for_role`]) holds it, and a session that did not negotiate it is refused the
    /// forms `SCHEMA_UNSUPPORTED`.
    pub const PAGES_V1: &str = "pages/1";
    /// ⟨rev7⟩ ADR-0014 H13 (ruling on ASK-H13b): the request frame's `request_epoch`
    /// ([`crate::lifecycle::REQUEST_EPOCH_FIELD`]) and the hello's `restore_epoch`.
    /// ⟨M08 U2b-2⟩ **Offered** by a runtime that checks the epoch, to the roles that send
    /// mutating requests: the owner ([`ALL`]) and ⟨follow-up A⟩ the requester
    /// ([`REQUESTER`]), not the viewer. A frame carrying `request_epoch` on a session that did
    /// not negotiate it is refused `SCHEMA_UNSUPPORTED` and never dispatched. A client holding
    /// a kept epoch refuses (`SCHEMA_UNSUPPORTED`) instead of sending it to a runtime that
    /// does not offer this; a fresh request with no kept epoch is sent without one.
    pub const REQUEST_EPOCH_V1: &str = "request-epoch/1";
    /// ⟨rev7⟩ The revision-7 capabilities declared and **not offered**: none now. `pages/1`
    /// is offered (m07-plan U3) and ⟨M08 U2b-2⟩ `request-epoch/1` left this list when the
    /// runtime began to offer it.
    pub const REVISION_7_DECLARED: [&str; 0] = [];

    /// ⟨M06⟩ Every capability name this contract defines and a runtime may offer, in
    /// declaration order: the owner role's set ([`for_role`]). ⟨M08 U2b-2⟩ With
    /// `request-epoch/1` (ADR-0014 H13), which the requester holds too ([`REQUESTER`]); a
    /// viewer's frames carry no epoch and are bound to the runner's epoch at receipt.
    pub const ALL: [&str; 18] = [
        OPERATIONS_V1,
        EVENTS_V1,
        OWNER_POLICY_V1,
        SCHEMA_DISCOVERY_V1,
        SERVICE_CONTROL_V1,
        SETUP_V1,
        ISSUER_V1,
        ENROLLMENT_V1,
        MANAGED_CREDENTIALS_V1,
        CONNECTIONS_V1,
        ENVIRONMENTS_V1,
        TRUSTED_WORK_V1,
        REMOTE_CONTROL_V1,
        RUNNER_V1,
        ROUTES_V1,
        TRANSPORT_IROH_V1,
        // ⟨rev7⟩ ADR-0013 §6.1: offered to every read role.
        PAGES_V1,
        REQUEST_EPOCH_V1,
    ];

    /// ⟨M06⟩ The `requester` role's capabilities (ADR-0012 §3.8: `view` and `request`):
    /// the primitives, events, schema discovery and managed-credential results. ⟨M08 U2b-2
    /// follow-up A; ADR-0014 H13⟩ And `request-epoch/1`: a requester sends mutating requests,
    /// so it carries the epoch it kept with a request ID ([`REQUEST_EPOCH_V1`]).
    pub const REQUESTER: [&str; 6] = [
        OPERATIONS_V1,
        EVENTS_V1,
        SCHEMA_DISCOVERY_V1,
        MANAGED_CREDENTIALS_V1,
        // ⟨rev7⟩ ADR-0013 §6.1.
        PAGES_V1,
        REQUEST_EPOCH_V1,
    ];

    /// ⟨M06⟩ The `viewer` role's capabilities (ADR-0012 §3.8: `view`): the primitives
    /// (whose effectful forms the role check refuses), events and schema discovery.
    pub const VIEWER: [&str; 4] = [OPERATIONS_V1, EVENTS_V1, SCHEMA_DISCOVERY_V1, PAGES_V1];

    /// ⟨M06⟩ Revision 6 (ADR-0012 §6.2, §9 item 4): the capabilities a role may negotiate,
    /// the `role` term of `required ⊆ offer ∩ server ∩ role`. `owner` holds every
    /// capability; `requester` and `viewer` are defined here and unused until the role
    /// table lands (m06-plan U1). A capability a role lacks never authorizes anything
    /// anyway: every request is still checked against the caller's role (ADR-0006 §2.4).
    #[must_use]
    pub fn for_role(role: crate::remote::Role) -> &'static [&'static str] {
        match role {
            crate::remote::Role::Owner => &ALL,
            crate::remote::Role::Requester => &REQUESTER,
            crate::remote::Role::Viewer => &VIEWER,
        }
    }
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
    /// ⟨M06⟩ Revision 6 (ADR-0012 §3.6, §9 item 1): the paired client a runner's bridge
    /// declares for this session. Omitted when absent, so every earlier hello is
    /// byte-identical. A runtime that does not offer `remote-control/1` refuses a hello
    /// carrying it with `SCHEMA_UNSUPPORTED` (wave 0: every runtime). It is never read
    /// from a request field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_client: Option<crate::ids::ClientId>,
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
    /// ⟨M06⟩ Revision 6 (ADR-0012 §6.2, §9 item 4): the role the session was negotiated
    /// for, when the runtime reports one (a paired client's session). Omitted when absent:
    /// the local same-user session is the owner (ADR-0006 §2.1) and its hello is
    /// byte-identical to revision 5's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<crate::remote::Role>,
    /// ⟨M06, rev6.2⟩ The paired client the session is bound to, as the runner resolved it in
    /// its role table (the bridge's argv client; ADR-0012 §3.6), reported back so the
    /// controller can check it against its own record. Omitted when absent: the local
    /// same-user session names no client, and its hello stays byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_client: Option<crate::ids::ClientId>,
    /// ⟨rev7; M08 U2b-2; ADR-0014 H13, §3.6 step 1⟩ The runtime's current restore epoch,
    /// reported on a session that negotiated `request-epoch/1`. A reader takes it as 0 when
    /// absent. The caller
    /// binds it to each request ID it mints in this session and keeps the pair for a retry.
    /// Omitted otherwise, so every earlier hello is byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_epoch: Option<crate::lifecycle::RestoreEpoch>,
}

impl ServerHello {
    /// ⟨M08 U2b-2⟩ The restore epoch this hello reports, 0 when absent (the reader's rule).
    #[must_use]
    pub fn restore_epoch(&self) -> crate::lifecycle::RestoreEpoch {
        self.restore_epoch.unwrap_or_default()
    }
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
        /// ⟨rev7; M08 U2b-2; ADR-0014 H13⟩ The restore epoch the request's ID was minted
        /// under (ruling on ASK-H13a): one field per frame, outside every canonical request
        /// hash. Only on a session that negotiated
        /// `request-epoch/1`; reads ignore it. A mutating request whose epoch is not the
        /// current one is refused `REQUEST_STALE`. Omitted when absent, so every earlier frame
        /// is byte-identical.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_epoch: Option<crate::lifecycle::RestoreEpoch>,
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
// A frame is built once per reply and serialized at once; boxing `Reject` (grown by
// ADR-0006 revision 3's error `reason` and provider interaction) would change the
// constructor every server uses, for no measurable gain.
#[allow(clippy::large_enum_variant)]
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
            remote_client: None,
        });
        let json = serde_json::to_string(&hello).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
    }
}
