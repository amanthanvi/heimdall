//! Events, cursors and snapshots (spec §11.5; ADR-0006 §8).
//!
//! Delivery is at least once; consumers deduplicate by `event_id`. Cross-environment
//! ordering is not claimed. Cursors are opaque and scoped to the authenticated
//! reader; an expired or foreign cursor yields `RESYNC_REQUIRED` with a snapshot
//! whose cursor boundary lets the reader resume without silently missing state.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::envelope::ResourceRef;
use crate::ids::{EnvironmentId, EventId, OperationId};
use crate::version::SchemaVersion;

/// Opaque, reader-scoped resumption token. Never parse it outside the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct Cursor(pub String);

/// Maximum accepted cursor length on the wire.
pub const MAX_CURSOR_LEN: usize = 256;

/// Event types emitted by the runtime (spec §13.6 audit coverage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventType {
    /// An operation changed state.
    OperationStateChanged,
    /// A grant changed state.
    GrantStateChanged,
    /// A standing policy changed (revision, pause, cutoff).
    PolicyChanged,
    /// A managed resource changed desired/observed state or generation.
    ResourceChanged,
    /// A credential lifecycle event (issued, renewed, expired, revoked).
    CredentialLifecycle,
    /// An owner decision was requested or recorded.
    Decision,
    /// The subscriber fell behind a bounded buffer; take a snapshot and resume
    /// (spec §11.5 backpressure).
    ResyncRequired,
    /// The runtime started or stopped (restart recovery boundary).
    RuntimeLifecycle,
    /// ⟨M03⟩ An enrollment record changed state (payload
    /// [`crate::managed::EnrollmentEventPayload`]).
    Enrollment,
    /// ⟨M03⟩ An owned connection started or closed (payload
    /// [`crate::managed::ConnectionEventPayload`]).
    Connection,
    /// ⟨M03⟩ A session lock was observed (payload
    /// [`crate::managed::SessionLockEventPayload`]).
    SessionLock,
    /// ⟨M05⟩ Revision 5 (m05-plan §4 item 8): a background activation was activated,
    /// blocked or not covered (payload [`crate::trust::ActivationEventPayload`]). Not
    /// emitted by joint wave 0.
    Activation,
    /// ⟨M06⟩ Revision 6 (ADR-0012 §9 item 8): `environment.connectivity_changed` (payload
    /// [`crate::remote::EnvironmentEventPayload`]). Declared, not emitted by wave 0.
    Environment,
    /// ⟨M06⟩ Revision 6: `client.enrolled`, `client.revoked` (payload
    /// [`crate::remote::ClientEventPayload`]). Declared, not emitted by wave 0.
    Client,
    /// ⟨M06⟩ Revision 6: `device.retired` (payload [`crate::remote::DeviceEventPayload`]).
    /// Declared, not emitted by wave 0.
    Device,
    /// ⟨M06⟩ Revision 6: `remote_effect.pending`, `remote_effect.acknowledged` (payload
    /// [`crate::remote::RemoteEffectEventPayload`]). Declared, not emitted by wave 0.
    RemoteEffect,
    /// ⟨M06⟩ Revision 6: `route.health` for every attempt, `route.failed_over` its subtype
    /// (payload [`crate::route::RouteHealthPayload`]). Declared, not emitted by wave 0.
    Route,
}

impl EventType {
    /// ⟨M06-W0-R10⟩ The capability a session must have negotiated to **select** this event
    /// type in a subscription or an `observe` filter, when it needs one: each revision-6
    /// family needs the capability that produces it (`remote-control/1` for the remote
    /// environment, client, device and effect families; `routes/1` for route health).
    /// Selecting one without it is refused `SCHEMA_UNSUPPORTED` at the boundary, as a
    /// request needing an unnegotiated capability is. Exhaustive, so a new type must state
    /// its capability.
    #[must_use]
    pub fn required_capability(self) -> Option<&'static str> {
        use crate::ipc::capability;
        match self {
            EventType::Environment
            | EventType::Client
            | EventType::Device
            | EventType::RemoteEffect => Some(capability::REMOTE_CONTROL_V1),
            EventType::Route => Some(capability::ROUTES_V1),
            EventType::OperationStateChanged
            | EventType::GrantStateChanged
            | EventType::PolicyChanged
            | EventType::ResourceChanged
            | EventType::CredentialLifecycle
            | EventType::Decision
            | EventType::ResyncRequired
            | EventType::RuntimeLifecycle
            | EventType::Enrollment
            | EventType::Connection
            | EventType::SessionLock
            | EventType::Activation => None,
        }
    }
}

/// One event (spec §11.5 field list).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Event {
    /// Major schema version.
    pub schema_version: SchemaVersion,
    /// Unique event ID for deduplication.
    pub event_id: EventId,
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Environment the event belongs to; ordering is only claimed within one.
    pub environment_id: EnvironmentId,
    /// Related operation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Related resource, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
    /// Runtime time of the event (RFC 3339, explicit offset).
    pub timestamp: Timestamp,
    /// Cursor positioned *after* this event.
    pub cursor: Cursor,
    /// Redacted payload; never contains private material.
    pub payload: serde_json::Value,
}

/// A snapshot with the cursor boundary it is consistent with (spec §11.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Snapshot<T> {
    /// Snapshot contents.
    pub data: T,
    /// Events after this cursor are not reflected in `data`.
    pub cursor: Cursor,
    /// Runtime time of the snapshot.
    pub taken_at: Timestamp,
}

/// Event filter for subscriptions and `observe --events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventFilter {
    /// Restrict to one operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Restrict to event types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<EventType>,
}

impl EventFilter {
    /// ⟨M06-W0-R10⟩ The capabilities the selected event types need
    /// ([`EventType::required_capability`]); empty for a filter selecting none of the
    /// revision-6 families (or no type at all).
    pub fn required_capabilities(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.types.iter().filter_map(|t| t.required_capability())
    }
}

// --- ⟨rev7⟩ ADR-0013 §5.3–§5.5, D4, D6: declared, not emitted --------------------------------

/// ⟨rev7⟩ The most operations an [`EventSnapshot`] holds (ADR-0013 §5.5). Real use stays far
/// below it: at most 32 operations run at once.
pub const SNAPSHOT_OPERATIONS_MAX: usize = 1000;
/// ⟨rev7⟩ The most pending decisions an [`EventSnapshot`] holds.
pub const SNAPSHOT_DECISIONS_MAX: usize = 256;
/// ⟨rev7⟩ An [`EventSnapshot`]'s serialized budget (768 KiB). Over any cap, the subscribe
/// (and a cursorless `observe events`) is refused `USAGE_ERROR` / `response_too_large`,
/// naming the section and the filter to use. There is no partial snapshot.
pub const SNAPSHOT_BUDGET_BYTES: usize = 768 << 10;
/// ⟨rev7⟩ The most visible events a backlog start delivers (ADR-0013 §5.3); a reader further
/// behind gets a whole snapshot start with `resync_reason: backlog_too_long`.
pub const BACKLOG_MAX: u32 = 500;

/// ⟨rev7⟩ Why a subscription started from a whole snapshot, or why a stream or a page ended
/// (ADR-0013 §5.3, §5.4). Every gap ends the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResyncReason {
    /// The live buffer (256 events) overran.
    SubscriberLagged,
    /// Retention removed events the reader had not received.
    HistoryTrimmed,
    /// An event does not fit one frame.
    EventTooLarge,
    /// The missed backlog is longer than [`BACKLOG_MAX`] visible events.
    BacklogTooLong,
    /// The cursor is beyond the head, malformed, of an unknown version, or another reader's
    /// or environment's.
    CursorInvalid,
}

/// ⟨rev7⟩ The typed `data` of a whole snapshot (ADR-0013 §5.5, D4): read in one store
/// transaction at the head boundary, whole or refused. Each section holds exactly what the
/// subscription's log and visibility deliver, and a section the filter cannot maintain is
/// omitted: `operations` only if the filter admits `operation_state_changed`,
/// `pending_decisions` only if it admits `decision` (owner role only), and only `operation`
/// with `filter.operation_id`. Its items are the typed operation and decision views.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventSnapshot<O, D> {
    /// The environment the snapshot is of.
    pub environment_id: EnvironmentId,
    /// The authority generation at the head boundary.
    pub authority_generation: u64,
    /// The open and unresolved operations the reader may see, at most
    /// [`SNAPSHOT_OPERATIONS_MAX`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<O>>,
    /// The one operation `filter.operation_id` names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<O>,
    /// The pending decisions (owner role only), at most [`SNAPSHOT_DECISIONS_MAX`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_decisions: Option<Vec<D>>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ipc::capability;

    /// ⟨M06-W0-R10⟩ The revision-6 families name the capability that produces them; every
    /// earlier type needs none.
    #[test]
    fn revision_6_event_types_need_their_capability() {
        for (t, cap) in [
            (EventType::Route, capability::ROUTES_V1),
            (EventType::Environment, capability::REMOTE_CONTROL_V1),
            (EventType::Client, capability::REMOTE_CONTROL_V1),
            (EventType::Device, capability::REMOTE_CONTROL_V1),
            (EventType::RemoteEffect, capability::REMOTE_CONTROL_V1),
        ] {
            assert_eq!(t.required_capability(), Some(cap), "{t:?}");
        }
        assert_eq!(EventType::OperationStateChanged.required_capability(), None);
        assert_eq!(EventType::Activation.required_capability(), None);
        let f: EventFilter =
            serde_json::from_str(r#"{"types":["operation_state_changed","route","client"]}"#)
                .unwrap();
        assert_eq!(
            f.required_capabilities().collect::<Vec<_>>(),
            vec![capability::ROUTES_V1, capability::REMOTE_CONTROL_V1]
        );
        assert_eq!(EventFilter::default().required_capabilities().count(), 0);
    }
}
