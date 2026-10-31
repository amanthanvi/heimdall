//! Event publication and reader-scoped cursors (spec §11.5; ADR-0006 §8).
//!
//! Events are appended to the store (durable, per-environment sequence) and
//! fanned out through a bounded `tokio::sync::broadcast` channel. A lagging
//! subscriber receives `Lagged`, which the IPC server turns into a
//! `ResyncRequired` event: the consumer snapshots and resumes from the snapshot's
//! cursor. Cursors encode `(reader principal hash, environment, seq)`; a cursor
//! presented by another reader or below the retained tail is `RESYNC_REQUIRED`.

use std::sync::Arc;

use heimdall_contract::event::{Cursor, Event, EventType};
use heimdall_contract::ids::{EnvironmentId, OperationId};
use heimdall_domain::principal::CallerContext;
use heimdall_store::Store;
use tokio::sync::broadcast;

/// Decoded cursor (internal; never exposed as structure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorParts {
    /// Hash of the reader's caller context (scoping).
    pub reader_tag: [u8; 8],
    /// Environment.
    pub environment: EnvironmentId,
    /// Sequence the reader has consumed through.
    pub seq: u64,
}

/// Cursor codec: `base64url(no pad)` of a fixed little binary layout plus a
/// version byte. Opaque to callers.
pub mod cursor {
    use super::CursorParts;
    use heimdall_contract::event::Cursor;

    /// Encode.
    #[must_use]
    pub fn encode(_parts: &CursorParts) -> Cursor {
        todo!("M01-T06: version byte || reader_tag || env id len+bytes || seq (BE u64), base64url")
    }

    /// Decode; `None` for malformed, oversize, or wrong-version cursors.
    #[must_use]
    pub fn decode(_cursor: &Cursor) -> Option<CursorParts> {
        todo!("M01-T06")
    }

    /// Reader tag: first 8 bytes of SHA-256 over the canonical caller context.
    #[must_use]
    pub fn reader_tag(_caller: &heimdall_domain::principal::CallerContext) -> [u8; 8] {
        todo!("M01-T06")
    }
}

/// Publishes events durably and to live subscribers.
#[derive(Clone)]
pub struct EventPublisher {
    store: Arc<Store>,
    environment: EnvironmentId,
    live: broadcast::Sender<Arc<Event>>,
}

impl std::fmt::Debug for EventPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventPublisher")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

impl EventPublisher {
    /// New publisher with the bounded live channel
    /// (`heimdall_contract::ipc::EVENT_BUFFER_PER_SUBSCRIPTION`).
    #[must_use]
    pub fn new(store: Arc<Store>, environment: EnvironmentId) -> Self {
        let (live, _) = broadcast::channel(heimdall_contract::ipc::EVENT_BUFFER_PER_SUBSCRIPTION);
        Self {
            store,
            environment,
            live,
        }
    }

    /// Append and fan out. The payload must already be redacted.
    pub fn publish(
        &self,
        _event_type: EventType,
        _operation_id: Option<OperationId>,
        _payload: serde_json::Value,
    ) -> Result<Event, crate::OpError> {
        let _ = (&self.store, &self.environment, &self.live);
        todo!(
            "M01-T06: store.append_event inside a transaction, then live.send (ignore no-receivers)"
        )
    }

    /// Subscribe to live events (bounded; `Lagged` means resync).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.live.subscribe()
    }

    /// Cursor for "now" scoped to `caller` (snapshot boundary).
    pub fn head_cursor(&self, _caller: &CallerContext) -> Result<Cursor, crate::OpError> {
        todo!("M01-T06")
    }
}
