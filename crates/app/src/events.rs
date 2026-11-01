//! Event publication, subscriptions and reader-scoped cursors (spec §11.5;
//! ADR-0006 §8; review F08).
//!
//! The store keeps **neutral** per-environment sequence numbers. Reader-scoped
//! cursors are built **at delivery** by [`cursor::encode`] from `(reader tag,
//! environment, seq)`; the store never sees them. A subscription starts with a
//! transactionally consistent boundary: the live receiver is created first, then
//! one store transaction reads the backlog after the client's cursor (or takes a
//! snapshot when there is no usable cursor) together with the head sequence; live
//! events at or below that head are dropped (overlap deduplicated); a lagging
//! subscriber receives one `ResyncRequired` event and must snapshot again.

use std::sync::Arc;

use heimdall_contract::event::{Cursor, Event, EventFilter, EventType, Snapshot};
use heimdall_contract::ids::{EnvironmentId, OperationId};
use heimdall_domain::principal::CallerContext;
use heimdall_store::Store;
use tokio::sync::broadcast;

/// A persisted event with its neutral sequence number (what the live channel and
/// the store carry; the wire `Event.cursor` is filled at delivery).
#[derive(Debug, Clone, PartialEq)]
pub struct SequencedEvent {
    /// Store sequence (monotonic per environment, not contiguous).
    pub seq: u64,
    /// The event with an empty `cursor`.
    pub event: Event,
}

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
        todo!("M01-U5: version byte || reader_tag || env id len+bytes || seq (BE u64), base64url")
    }

    /// Decode; `None` for malformed, oversize, or wrong-version cursors.
    #[must_use]
    pub fn decode(_cursor: &Cursor) -> Option<CursorParts> {
        todo!("M01-U5")
    }

    /// Reader tag: first 8 bytes of SHA-256 over the canonical caller context.
    #[must_use]
    pub fn reader_tag(_caller: &heimdall_domain::principal::CallerContext) -> [u8; 8] {
        todo!("M01-U5")
    }
}

/// Builds reader-scoped cursors for one reader; handed to the IPC session so it can
/// personalize live events at delivery without knowing the codec.
pub type CursorBuilder = Arc<dyn Fn(u64) -> Cursor + Send + Sync>;

/// What a subscription starts with (ADR-0006 §8; review F08).
pub struct SubscriptionStart {
    /// Boundary the stream continues after, as the reader's cursor.
    pub cursor: Cursor,
    /// Highest sequence reflected in `snapshot`/`backlog`; live events with
    /// `seq <= boundary_seq` are duplicates and are dropped.
    pub boundary_seq: u64,
    /// Consistent snapshot when the client had no usable cursor.
    pub snapshot: Option<Snapshot<serde_json::Value>>,
    /// Retained events after the client's cursor, already cursor-personalized.
    pub backlog: Vec<Event>,
    /// Live receiver created **before** the boundary was read.
    pub live: broadcast::Receiver<Arc<SequencedEvent>>,
    /// Personalizes live events for this reader.
    pub cursor_for: CursorBuilder,
}

impl std::fmt::Debug for SubscriptionStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionStart")
            .field("boundary_seq", &self.boundary_seq)
            .field("backlog", &self.backlog.len())
            .finish_non_exhaustive()
    }
}

/// Why a subscription could not start from the given cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscribeRefusal {
    /// Expired, foreign or malformed cursor: the caller must resync (the runtime
    /// may instead start with a snapshot; this variant is for strict callers).
    ResyncRequired,
}

/// Publishes events durably and to live subscribers.
#[derive(Clone)]
pub struct EventPublisher {
    store: Arc<Store>,
    environment: EnvironmentId,
    live: broadcast::Sender<Arc<SequencedEvent>>,
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

    /// Append and fan out. The payload must already be redacted. Called inside the
    /// operation's own transaction via [`Self::publish_in`] when atomicity with a
    /// state change is required; this convenience opens its own.
    pub fn publish(
        &self,
        _event_type: EventType,
        _operation_id: Option<OperationId>,
        _payload: serde_json::Value,
    ) -> Result<SequencedEvent, crate::OpError> {
        let _ = (&self.store, &self.environment, &self.live);
        todo!(
            "M01-U5: store.append_event inside a transaction, then live.send (ignore no-receivers)"
        )
    }

    /// Append within an existing transaction; the live send happens after commit
    /// through [`Self::announce`].
    pub fn publish_in(
        &self,
        _tx: &mut heimdall_store::Txn<'_>,
        _event_type: EventType,
        _operation_id: Option<OperationId>,
        _payload: serde_json::Value,
    ) -> Result<SequencedEvent, crate::OpError> {
        todo!("M01-U5")
    }

    /// Fan out an event that was committed by the caller's transaction.
    pub fn announce(&self, event: SequencedEvent) {
        let _ = self.live.send(Arc::new(event));
    }

    /// Start a subscription for `caller` (ADR-0006 §8): live receiver first, then
    /// one transaction for backlog-or-snapshot plus head. A `from` cursor that is
    /// foreign, malformed or below the retained tail yields `ResyncRequired` when
    /// `strict`, else a fresh snapshot.
    pub async fn subscribe(
        &self,
        _caller: &CallerContext,
        _filter: EventFilter,
        _from: Option<Cursor>,
        _strict: bool,
    ) -> Result<SubscriptionStart, SubscribeRefusal> {
        todo!("M01-U5")
    }

    /// Cursor for "now" scoped to `caller` (snapshot boundary).
    pub fn head_cursor(&self, _caller: &CallerContext) -> Result<Cursor, crate::OpError> {
        todo!("M01-U5")
    }
}
