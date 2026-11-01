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
//!
//! Event payloads carry identifiers, states and codes only (no credential
//! material, no request text), so nothing secret can reach a subscriber.

use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::envelope::ResourceRef;
use heimdall_contract::event::{Cursor, Event, EventFilter, EventType, Snapshot};
use heimdall_contract::ids::{EnvironmentId, EventId, OperationId};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::time::Clock;
use heimdall_store::{Store, Txn};
use tokio::sync::broadcast;

/// Most retained events a subscription backlog may carry; a cursor further behind
/// starts from a snapshot instead (or `RESYNC_REQUIRED` for a strict caller), so a
/// subscription start is always bounded (spec §11.5, R-RT-06).
pub const MAX_SUBSCRIPTION_BACKLOG: u32 = 500;

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
///
/// Layout (version 1): `0x01 || reader_tag[8] || env_len (u16 BE) || env bytes ||
/// seq (u64 BE)`.
pub mod cursor {
    use super::CursorParts;
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use heimdall_contract::event::{Cursor, MAX_CURSOR_LEN};
    use heimdall_contract::ids::EnvironmentId;

    /// Current cursor layout version.
    pub const VERSION: u8 = 1;

    /// Encode.
    #[must_use]
    pub fn encode(parts: &CursorParts) -> Cursor {
        let env = parts.environment.as_str().as_bytes();
        let env_len = u16::try_from(env.len()).unwrap_or(u16::MAX);
        let env = &env[..usize::from(env_len)];
        let mut buf = Vec::with_capacity(1 + 8 + 2 + env.len() + 8);
        buf.push(VERSION);
        buf.extend_from_slice(&parts.reader_tag);
        buf.extend_from_slice(&env_len.to_be_bytes());
        buf.extend_from_slice(env);
        buf.extend_from_slice(&parts.seq.to_be_bytes());
        Cursor(Base64UrlUnpadded::encode_string(&buf))
    }

    /// Decode; `None` for malformed, oversize, or wrong-version cursors.
    #[must_use]
    pub fn decode(cursor: &Cursor) -> Option<CursorParts> {
        if cursor.0.is_empty() || cursor.0.len() > MAX_CURSOR_LEN {
            return None;
        }
        let buf = Base64UrlUnpadded::decode_vec(&cursor.0).ok()?;
        let (&version, rest) = buf.split_first()?;
        if version != VERSION || rest.len() < 8 + 2 + 8 {
            return None;
        }
        let (tag, rest) = rest.split_at(8);
        let (len, rest) = rest.split_at(2);
        let env_len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        if rest.len() != env_len + 8 {
            return None;
        }
        let (env, seq) = rest.split_at(env_len);
        let environment = EnvironmentId::parse(std::str::from_utf8(env).ok()?).ok()?;
        let mut tag_bytes = [0u8; 8];
        tag_bytes.copy_from_slice(tag);
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(seq);
        Some(CursorParts {
            reader_tag: tag_bytes,
            environment,
            seq: u64::from_be_bytes(seq_bytes),
        })
    }

    /// Reader tag: first 8 bytes of SHA-256 over the canonical caller context
    /// (domain-separated through `heimdall_contract::canonical::request_hash`).
    #[must_use]
    pub fn reader_tag(caller: &heimdall_domain::principal::CallerContext) -> [u8; 8] {
        let mut out = [0u8; 8];
        let digest = serde_json::to_value(caller).ok().and_then(|v| {
            heimdall_contract::canonical::request_hash("event-cursor-reader", &v).ok()
        });
        if let Some(d) = digest {
            out.copy_from_slice(&d.0[..8]);
        }
        out
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
    /// The state store could not be read (`STATE_UNAVAILABLE`).
    StateUnavailable,
}

/// Publishes events durably and to live subscribers.
#[derive(Clone)]
pub struct EventPublisher {
    store: Arc<Store>,
    environment: EnvironmentId,
    live: broadcast::Sender<Arc<SequencedEvent>>,
    clock: Option<Arc<dyn Clock>>,
    /// Live fan-out position (shared by clones). Live delivery is in strictly
    /// increasing `seq` order with no gaps (ADR-0006 §8; gap G06; review A05):
    /// see [`Self::announce`].
    announced: Arc<std::sync::Mutex<Announced>>,
}

/// Live fan-out position of an [`EventPublisher`].
#[derive(Debug, Default)]
struct Announced {
    /// Highest sequence fanned out so far; every committed event at or below it
    /// was fanned out (or was history when the publisher started). `None` when
    /// the head could not be read at start.
    last: Option<u64>,
    /// Highest announced sequence above `last` that is held back because the
    /// events between `last` and it could not be read yet (review A05).
    held: Option<u64>,
}

impl std::fmt::Debug for EventPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventPublisher")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

/// How a subscription's start was resolved inside the boundary transaction.
enum StartFrom {
    Backlog(Vec<heimdall_store::StoredEvent>),
    Snapshot(serde_json::Value),
    Refused,
}

impl EventPublisher {
    /// New publisher with the bounded live channel
    /// (`heimdall_contract::ipc::EVENT_BUFFER_PER_SUBSCRIPTION`). Event timestamps
    /// come from the system clock unless [`Self::with_clock`] supplies one.
    #[must_use]
    pub fn new(store: Arc<Store>, environment: EnvironmentId) -> Self {
        let (live, _) = broadcast::channel(heimdall_contract::ipc::EVENT_BUFFER_PER_SUBSCRIPTION);
        // Everything committed before this publisher existed is history (backlog
        // or snapshot), never live.
        let head = store
            .transaction(|tx| tx.snapshot_boundary(&environment))
            .ok()
            .map(|(_, head)| head);
        Self {
            store,
            environment,
            live,
            clock: None,
            announced: Arc::new(std::sync::Mutex::new(Announced {
                last: head,
                held: None,
            })),
        }
    }

    /// Use `clock` for event timestamps (the runtime's injected clock, so model
    /// tests are deterministic).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Environment the events belong to.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    fn now(&self) -> Timestamp {
        self.clock
            .as_ref()
            .map_or_else(Timestamp::now, |c| c.wall())
    }

    /// Append within `tx` (store result form, for callers already inside a store
    /// transaction closure). The live send happens after commit through
    /// [`Self::announce`].
    pub fn append_in(
        &self,
        tx: &mut Txn<'_>,
        event_type: EventType,
        operation_id: Option<OperationId>,
        resource: Option<ResourceRef>,
        payload: serde_json::Value,
    ) -> heimdall_store::Result<SequencedEvent> {
        let event = Event {
            schema_version: heimdall_contract::SchemaVersion::current(),
            // Placeholder; the store assigns the real random event ID.
            event_id: EventId::from_random_bytes([0; 16]),
            event_type,
            environment_id: self.environment.clone(),
            operation_id,
            resource,
            timestamp: self.now(),
            cursor: Cursor(String::new()),
            payload,
        };
        let (event_id, seq) = tx.append_event(&event)?;
        let mut stored = event;
        stored.event_id = event_id;
        Ok(SequencedEvent { seq, event: stored })
    }

    /// Append and fan out. The payload must already be redacted. Called inside the
    /// operation's own transaction via [`Self::publish_in`] when atomicity with a
    /// state change is required; this convenience opens its own.
    pub fn publish(
        &self,
        event_type: EventType,
        operation_id: Option<OperationId>,
        payload: serde_json::Value,
    ) -> Result<SequencedEvent, crate::OpError> {
        let event = self
            .store
            .transaction(|tx| self.append_in(tx, event_type, operation_id, None, payload))?;
        self.announce(event.clone());
        Ok(event)
    }

    /// Append within an existing transaction; the live send happens after commit
    /// through [`Self::announce`].
    pub fn publish_in(
        &self,
        tx: &mut heimdall_store::Txn<'_>,
        event_type: EventType,
        operation_id: Option<OperationId>,
        payload: serde_json::Value,
    ) -> Result<SequencedEvent, crate::OpError> {
        Ok(self.append_in(tx, event_type, operation_id, None, payload)?)
    }

    /// Fan out an event that was committed by the caller's transaction, in
    /// strictly increasing `seq` order with no gaps (ADR-0006 §8; gap G06;
    /// review A05).
    ///
    /// Commits are serialized by the store and announcements happen after commit
    /// from different tasks, so they can arrive out of order. An event with a
    /// higher sequence is committed, so every lower one that exists is committed
    /// too: when `event.seq` (or an earlier held-back announcement) is beyond the
    /// next position, every event committed in between is read back from the
    /// store and fanned out in order. An announcement at or below the last
    /// fanned-out sequence was already delivered that way and is dropped.
    ///
    /// When that catch-up read fails, the stream never advances past the gap:
    /// events read before the failure are fanned out, `event` is fanned out only
    /// if it is the very next position, and otherwise it is **held back** (not
    /// sent, no cursor beyond the gap is handed out). The next announcement
    /// retries the catch-up from the retained position through the highest
    /// held-back sequence. Until then a subscriber's latest cursor still precedes
    /// the gap, so resuming from it reads the held-back events from the store. A
    /// subscriber therefore never receives `N + 1` before `N`, and never receives
    /// `N + 1` at all while `N` is unread.
    pub fn announce(&self, event: SequencedEvent) {
        let mut st = self
            .announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(last) = st.last else {
            // The head was unreadable at start: nothing to order against yet.
            st.last = Some(event.seq);
            let _ = self.live.send(Arc::new(event));
            return;
        };
        let event = (event.seq > last).then_some(event);
        self.advance(&mut st, last, event);
    }

    /// Retry fanning out held-back events (see [`Self::announce`]) without a new
    /// announcement; `true` when nothing remains held back. The runtime may call
    /// this periodically so a held-back event is not left waiting for the next
    /// commit.
    pub fn retry_held(&self) -> bool {
        let mut st = self
            .announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(last) = st.last {
            self.advance(&mut st, last, None);
        }
        st.held.is_none()
    }

    /// Fan out everything committed in `(last, target]`, where `target` is the
    /// highest of `event` and the held-back sequence, without passing a gap.
    fn advance(&self, st: &mut Announced, last: u64, mut event: Option<SequencedEvent>) {
        let held = st.held.filter(|&h| h > last);
        let Some(target) = event.as_ref().map(|e| e.seq).max(held) else {
            st.held = None;
            return;
        };
        let mut delivered = last;
        let send = |e: SequencedEvent, delivered: &mut u64| {
            if e.seq > *delivered {
                *delivered = e.seq;
                let _ = self.live.send(Arc::new(e));
            }
        };
        let contiguous = held.is_none() && target == last + 1;
        let (read, complete) = if contiguous {
            // The next position: nothing can be missing, no read needed.
            (Vec::new(), true)
        } else {
            self.committed_through(last, target)
        };
        for stored in read {
            // The announced event itself is sent as announced, at its position.
            if let Some(e) = event.take_if(|e| e.seq <= stored.seq) {
                let same = e.seq == stored.seq;
                send(e, &mut delivered);
                if same {
                    continue;
                }
            }
            send(stored, &mut delivered);
        }
        if let Some(e) = event.take_if(|e| complete || e.seq == delivered + 1) {
            // Read completely (everything below it was fanned out), or it is the
            // very next position after the gap-free prefix that was read.
            send(e, &mut delivered);
        }
        if complete {
            delivered = delivered.max(target);
        }
        st.last = Some(delivered);
        st.held = (target > delivered).then_some(target);
    }

    /// Committed events with `after < seq <= through`, in order (bounded pages),
    /// and whether the read completed. On a store failure the events read so far
    /// are returned (a gap-free prefix) with `false`.
    fn committed_through(&self, after: u64, through: u64) -> (Vec<SequencedEvent>, bool) {
        const PAGE: u32 = 256;
        let mut out = Vec::new();
        let mut from = after;
        loop {
            let page = self.store.transaction(|tx| {
                tx.stored_events_after(&self.environment, from, &EventFilter::default(), PAGE)
            });
            let Ok(page) = page else {
                return (out, false);
            };
            let full = page.events.len() == PAGE as usize;
            for stored in page.events {
                if stored.seq > through {
                    return (out, true);
                }
                from = stored.seq;
                out.push(SequencedEvent {
                    seq: stored.seq,
                    event: stored.event,
                });
            }
            if !full || from >= through {
                return (out, true);
            }
        }
    }

    /// A live receiver (bounded; lag yields `RecvError::Lagged`).
    #[must_use]
    pub fn live_receiver(&self) -> broadcast::Receiver<Arc<SequencedEvent>> {
        self.live.subscribe()
    }

    /// Cursor for `seq` scoped to `caller`.
    #[must_use]
    pub fn cursor_at(&self, caller: &CallerContext, seq: u64) -> Cursor {
        cursor::encode(&CursorParts {
            reader_tag: cursor::reader_tag(caller),
            environment: self.environment.clone(),
            seq,
        })
    }

    /// Decode a cursor and accept it only for this reader and environment.
    #[must_use]
    pub fn cursor_for_reader(&self, caller: &CallerContext, c: &Cursor) -> Option<u64> {
        let parts = cursor::decode(c)?;
        (parts.reader_tag == cursor::reader_tag(caller) && parts.environment == self.environment)
            .then_some(parts.seq)
    }

    /// Start a subscription for `caller` (ADR-0006 §8): live receiver first, then
    /// one transaction for backlog-or-snapshot plus head. A `from` cursor that is
    /// foreign, malformed or below the retained tail yields `ResyncRequired` when
    /// `strict`, else a fresh snapshot.
    pub async fn subscribe(
        &self,
        caller: &CallerContext,
        filter: EventFilter,
        from: Option<Cursor>,
        strict: bool,
    ) -> Result<SubscriptionStart, SubscribeRefusal> {
        // 1. The live receiver exists before the boundary is read, so nothing
        //    published after the boundary can be missed.
        let live = self.live.subscribe();
        let tag = cursor::reader_tag(caller);
        let from_seq = from
            .as_ref()
            .and_then(|c| self.cursor_for_reader(caller, c));
        if from.is_some() && from_seq.is_none() && strict {
            return Err(SubscribeRefusal::ResyncRequired);
        }
        let me = self.clone();
        let reader = caller.clone();
        let joined = tokio::task::spawn_blocking(move || {
            me.store.transaction(|tx| {
                let (generation, head) = tx.snapshot_boundary(&me.environment)?;
                if let Some(seq) = from_seq {
                    let page = tx.stored_events_after(
                        &me.environment,
                        seq,
                        &filter,
                        MAX_SUBSCRIPTION_BACKLOG + 1,
                    )?;
                    let usable = seq >= page.tail_seq
                        && seq <= head
                        && page.events.len() <= MAX_SUBSCRIPTION_BACKLOG as usize;
                    if usable {
                        return Ok((StartFrom::Backlog(page.events), head));
                    }
                    if strict {
                        return Ok((StartFrom::Refused, head));
                    }
                }
                let data = snapshot_data(tx, &me.environment, &reader, &filter, generation, head)?;
                Ok((StartFrom::Snapshot(data), head))
            })
        })
        .await;
        let (start, head) = match joined {
            Ok(Ok(v)) => v,
            _ => return Err(SubscribeRefusal::StateUnavailable),
        };
        let environment = self.environment.clone();
        let cursor_for: CursorBuilder = Arc::new(move |seq| {
            cursor::encode(&CursorParts {
                reader_tag: tag,
                environment: environment.clone(),
                seq,
            })
        });
        let boundary = cursor_for(head);
        let (snapshot, backlog) = match start {
            StartFrom::Refused => return Err(SubscribeRefusal::ResyncRequired),
            StartFrom::Backlog(events) => (
                None,
                events
                    .into_iter()
                    .map(|stored| {
                        let mut e = stored.event;
                        e.cursor = cursor_for(stored.seq);
                        e
                    })
                    .collect(),
            ),
            StartFrom::Snapshot(data) => (
                Some(Snapshot {
                    data,
                    cursor: boundary.clone(),
                    taken_at: self.now(),
                }),
                Vec::new(),
            ),
        };
        Ok(SubscriptionStart {
            cursor: boundary,
            boundary_seq: head,
            snapshot,
            backlog,
            live,
            cursor_for,
        })
    }

    /// Cursor for "now" scoped to `caller` (snapshot boundary).
    pub fn head_cursor(&self, caller: &CallerContext) -> Result<Cursor, crate::OpError> {
        let (_, head) = self
            .store
            .transaction(|tx| tx.snapshot_boundary(&self.environment))?;
        Ok(self.cursor_at(caller, head))
    }
}

/// Whether `caller` may see an operation created by `owner` (same principal, or
/// the owner role).
#[must_use]
pub fn visible_to(owner: &CallerContext, caller: &CallerContext) -> bool {
    owner.principal == caller.principal || caller.is_owner()
}

/// The snapshot document consistent with a boundary: open and unresolved
/// operations the reader may see, pending decisions (owner role only), the
/// operation named by the filter, and the authority generation. Identifiers,
/// states and codes only.
pub fn snapshot_data(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    reader: &CallerContext,
    filter: &EventFilter,
    generation: heimdall_domain::policy::AuthorityGeneration,
    head: u64,
) -> heimdall_store::Result<serde_json::Value> {
    let summarize = |op: &heimdall_domain::operation::OperationRecord| {
        serde_json::json!({
            "operation_id": op.id,
            "kind": op.kind,
            "state": op.state,
            "code": op.code,
            "effect_status": op.effect_status,
            "updated_at": op.updated_at,
        })
    };
    let mut operations = Vec::new();
    for op in tx
        .open_operations()?
        .into_iter()
        .chain(tx.unresolved_operations()?)
    {
        if op.environment == *environment && visible_to(&op.key.caller, reader) {
            operations.push(summarize(&op));
        }
    }
    let operation = match &filter.operation_id {
        Some(id) => tx
            .operation(id)?
            .filter(|op| visible_to(&op.key.caller, reader))
            .map(|op| summarize(&op)),
        None => None,
    };
    let decisions: Vec<serde_json::Value> = if reader.is_owner() {
        tx.pending_decisions()?
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "decision_id": d.id,
                    "kind": decision_kind_name(&d.kind),
                    "expires_at": d.expires_at,
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(serde_json::json!({
        "environment_id": environment,
        "authority_generation": generation.0,
        "boundary_seq": head,
        "operations": operations,
        "operation": operation,
        "pending_decisions": decisions,
    }))
}

/// Stable name of a decision kind (no payload).
#[must_use]
pub fn decision_kind_name(kind: &heimdall_domain::decision::DecisionKind) -> &'static str {
    use heimdall_domain::decision::DecisionKind as K;
    match kind {
        K::ApproveAuthority { .. } => "approve_authority",
        K::WidenPolicy { .. } => "widen_policy",
        K::ConfirmTime { .. } => "confirm_time",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use base64ct::Encoding as _;
    use heimdall_domain::principal::{ClientRole, PrincipalRef};

    fn ctx(uid: u32) -> CallerContext {
        CallerContext {
            principal: PrincipalRef::UnixUser { uid },
            role: ClientRole::Owner,
        }
    }

    #[test]
    fn cursor_round_trips_and_rejects_garbage() {
        let parts = CursorParts {
            reader_tag: cursor::reader_tag(&ctx(501)),
            environment: EnvironmentId::from_random_bytes([4; 16]),
            seq: 42,
        };
        let c = cursor::encode(&parts);
        assert_eq!(cursor::decode(&c), Some(parts.clone()));
        assert!(c.0.len() <= heimdall_contract::event::MAX_CURSOR_LEN);
        assert_eq!(cursor::decode(&Cursor(String::new())), None);
        assert_eq!(cursor::decode(&Cursor("not base64!".into())), None);
        assert_eq!(cursor::decode(&Cursor("x".repeat(300))), None);
        // Wrong version byte.
        let mut raw = base64ct::Base64UrlUnpadded::decode_vec(&c.0).unwrap();
        raw[0] = 9;
        let bad = Cursor(base64ct::Base64UrlUnpadded::encode_string(&raw));
        assert_eq!(cursor::decode(&bad), None);
        // Truncated.
        let short = Cursor(c.0[..c.0.len() - 4].to_owned());
        assert_eq!(cursor::decode(&short), None);
    }

    #[test]
    fn reader_tags_differ_by_principal_and_role() {
        let a = cursor::reader_tag(&ctx(501));
        let b = cursor::reader_tag(&ctx(502));
        let mut limited = ctx(501);
        limited.role = ClientRole::LimitedConsumer;
        assert_ne!(a, b);
        assert_ne!(a, cursor::reader_tag(&limited));
        assert_eq!(a, cursor::reader_tag(&ctx(501)));
    }
}
