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

// --- ⟨rev7⟩ ADR-0013 §5.3–§5.5, D4, D6 --------------------------------------------------------

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

/// ⟨rev7; PC1⟩ The names a snapshot refusal's `data.error.section` and `data.error.narrow`
/// carry (ADR-0013 §5.5): the section over its cap, and the filter that leaves it out.
pub mod snapshot_refusal {
    /// The `operations` section.
    pub const OPERATIONS: &str = "operations";
    /// The `operation` section (the one `filter.operation_id` names).
    pub const OPERATION: &str = "operation";
    /// The `pending_decisions` section.
    pub const PENDING_DECISIONS: &str = "pending_decisions";
    /// Narrow to one operation: `filter.operation_id`.
    pub const NARROW_OPERATION_ID: &str = "filter.operation_id";
    /// Narrow by type: `filter.types`, without the section's event type
    /// (`operation_state_changed` for an operation section, `decision` for
    /// `pending_decisions`).
    pub const NARROW_TYPES: &str = "filter.types";
}

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

/// ⟨rev7⟩ The typed `data` of a whole snapshot (ADR-0013 §5.5, D4; PC1): read in one store
/// transaction at the head boundary, whole or refused. Each section holds exactly what the
/// subscription's log and visibility deliver, and a section the filter cannot maintain is
/// omitted: `operations` only if the filter admits `operation_state_changed`,
/// `pending_decisions` only if it admits `decision` (owner role only), and only `operation`
/// with `filter.operation_id`. Its items are [`SnapshotOperation`] and [`SnapshotDecision`]
/// ([`EventSnapshotData`]). There is no `boundary_seq` (§5.5) and no partial marker: a
/// snapshot over a cap is refused `USAGE_ERROR` / `response_too_large`, naming the section and
/// the filter to use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(bound(deserialize = "O: Deserialize<'de>, D: Deserialize<'de>"))]
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

/// ⟨rev7; PC1⟩ The snapshot every subscribe and cursorless `observe events` sends.
pub type EventSnapshotData = EventSnapshot<SnapshotOperation, SnapshotDecision>;

/// ⟨rev7; PC1⟩ One operation in an [`EventSnapshot`]: its identity, state and outcome, the
/// fields its `operation_state_changed` events carry, without the operation view's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotOperation {
    /// The operation.
    pub operation_id: OperationId,
    /// Its kind.
    pub kind: crate::views::operations::OperationKindView,
    /// Its state.
    pub state: crate::state::OperationState,
    /// Its result code once terminal. Omitted before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<crate::code::Code>,
    /// Its effect status.
    pub effect_status: crate::envelope::EffectStatus,
    /// When it last changed.
    pub updated_at: Timestamp,
}

/// ⟨rev7; PC1⟩ One pending decision in an [`EventSnapshot`] (owner role only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotDecision {
    /// The decision. Always present for the local owner; absent from what a paired reader
    /// receives (its delivery removes every `decision_id`, as from `decision` events).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<crate::ids::DecisionId>,
    /// What is decided.
    pub kind: crate::views::access::DecisionKindName,
    /// After this instant it cannot be completed.
    pub expires_at: Timestamp,
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

    /// ⟨PC1⟩ The typed snapshot: absent sections and an absent `code` or `decision_id` are
    /// omitted, never `null`; there is no `boundary_seq`.
    #[test]
    fn event_snapshot_omits_what_does_not_apply() {
        let doc = serde_json::json!({
            "environment_id": "env_01010101010101010101010101010101",
            "authority_generation": 3,
            "operations": [{
                "operation_id": "op_60606060606060606060606060606060",
                "kind": "setup.apply",
                "state": "running",
                "effect_status": "none",
                "updated_at": "2026-11-27T10:00:00Z"
            }],
            "pending_decisions": [{
                "kind": "remote_widening",
                "expires_at": "2026-11-27T10:15:00Z"
            }]
        });
        let typed: EventSnapshotData = serde_json::from_value(doc.clone()).unwrap();
        assert_eq!(serde_json::to_value(&typed).unwrap(), doc);
        assert!(typed.operation.is_none());
        assert!(
            typed.pending_decisions.as_ref().unwrap()[0]
                .decision_id
                .is_none()
        );
        let bare: EventSnapshotData = serde_json::from_value(serde_json::json!({
            "environment_id": "env_01010101010101010101010101010101",
            "authority_generation": 0
        }))
        .unwrap();
        let text = serde_json::to_string(&bare).unwrap();
        assert!(
            !text.contains("null") && !text.contains("boundary_seq"),
            "{text}"
        );
    }
}
