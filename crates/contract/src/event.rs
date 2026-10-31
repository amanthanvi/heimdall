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
