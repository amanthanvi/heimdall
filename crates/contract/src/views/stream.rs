//! ⟨rev7⟩ `heimdall operation events --follow`: the head line's data and the NDJSON lines
//! after it (ADR-0013 §11 D1, D6; §4 stream grammar; §5.3–§5.5).
//!
//! The stream is: one head envelope (`state: "running"`, `code: "OK"`, `next: {action:
//! "observe", cursor}`) whose `data` is a [`SubscriptionHeadView`]; then one
//! [`StreamLine`] per line.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, ErrorData};
use crate::event::{Cursor, Event, ResyncReason, Snapshot};

/// The head line's `data`: the subscription the server established.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SubscriptionHeadView {
    /// The subscription handle.
    pub subscription: u64,
    /// The server's head boundary: the snapshot's boundary with a snapshot; without one,
    /// the boundary after the backlog that follows (not the client's cursor).
    pub cursor: Cursor,
    /// **Revision 7, not emitted yet** (D6): how many backlog event lines follow the head
    /// before live events, exactly. Omitted until emitted, and with a snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backlog: Option<u32>,
    /// **Revision 7, not emitted yet** (D6): why the subscription started from a whole
    /// snapshot although the client sent a cursor. Omitted until emitted, and without
    /// such a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resync_reason: Option<ResyncReason>,
    /// The whole snapshot the subscription starts from: present when the client sent no
    /// cursor or the server resnapshotted it. Omitted when resuming from the client's
    /// cursor (today: `null`). Its `data` is today's untyped snapshot document; PC1 types
    /// it (`crate::event::EventSnapshot`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot<serde_json::Value>>,
}

/// One NDJSON line after the head: an event, or the one terminal error envelope (a
/// server `Goodbye` or a lost connection). A `resync_required` event whose payload says
/// `subscription_ended: true` is the last line too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum StreamLine {
    /// A bare event (spec §11.5), not wrapped in an envelope.
    Event(Box<Event>),
    /// The terminal error envelope.
    Error(Box<Envelope<ErrorData>>),
}
