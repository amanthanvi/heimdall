//! Single-flight for equivalent work (spec §8.2, §5.5 "one logical decision
//! should generate one coalesced approval request"; R-RT-01).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;

use tokio::sync::watch;

/// Coalesces concurrent callers of the same key onto one in-flight computation.
/// Bounded: at most `max_inflight` distinct keys; beyond that callers get
/// [`SingleFlightError::Backpressure`].
pub struct SingleFlight<K, V> {
    inflight: Mutex<HashMap<K, watch::Receiver<Option<V>>>>,
    max_inflight: usize,
}

impl<K, V> std::fmt::Debug for SingleFlight<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleFlight")
            .field("max_inflight", &self.max_inflight)
            .finish_non_exhaustive()
    }
}

/// Single-flight failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SingleFlightError {
    /// Too many distinct keys in flight.
    #[error("too many concurrent equivalent-work keys")]
    Backpressure,
    /// The leader dropped without publishing a value.
    #[error("leader abandoned the key")]
    LeaderGone,
}

/// Outcome of [`SingleFlight::join_or_lead`].
#[derive(Debug)]
pub enum Flight<V> {
    /// This caller leads; publish through the sender when done.
    Lead(watch::Sender<Option<V>>),
    /// Another caller leads; await the receiver.
    Follow(watch::Receiver<Option<V>>),
}

impl<K: Eq + Hash + Clone, V: Clone + Send + Sync + 'static> SingleFlight<K, V> {
    /// New with the default bound.
    #[must_use]
    pub fn new() -> Self {
        Self::with_bound(256)
    }

    /// New with an explicit bound on distinct in-flight keys.
    #[must_use]
    pub fn with_bound(max_inflight: usize) -> Self {
        Self {
            inflight: Mutex::new(HashMap::new()),
            max_inflight,
        }
    }

    /// Join an existing flight or become its leader.
    pub fn join_or_lead(&self, _key: K) -> Result<Flight<V>, SingleFlightError> {
        let _ = (&self.inflight, self.max_inflight);
        todo!("M01-T05: insert watch channel under the key; remove on leader completion")
    }

    /// Leader completed: remove the key so a later equivalent request recomputes.
    pub fn finish(&self, _key: &K) {
        todo!("M01-T05")
    }
}

impl<K: Eq + Hash + Clone, V: Clone + Send + Sync + 'static> Default for SingleFlight<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
