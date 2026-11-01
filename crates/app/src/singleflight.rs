//! Single-flight for equivalent work (spec §8.2, §5.5 "one logical decision
//! should generate one coalesced approval request"; R-RT-01).
//!
//! The first caller for a key **leads**: it gets the `watch::Sender` and must
//! publish a value and call [`SingleFlight::finish`]. Concurrent callers of the
//! same key **follow**: they await the leader's value with [`follow`]. A leader
//! that drops its sender without publishing is gone; followers see
//! [`SingleFlightError::LeaderGone`] and the next `join_or_lead` starts a new
//! flight (nothing waits forever on a dead leader).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};

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

/// Whether a flight's leader is still able to publish (its sender is alive) or
/// has already published.
fn live<V>(rx: &watch::Receiver<Option<V>>) -> bool {
    rx.has_changed().is_ok() || rx.borrow().is_some()
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

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<K, watch::Receiver<Option<V>>>> {
        // The map holds only channel handles; a panic while holding the lock
        // cannot leave it inconsistent.
        self.inflight.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Join an existing flight or become its leader.
    ///
    /// An entry whose leader dropped its sender without publishing is replaced
    /// (this caller leads a new flight). At the bound, entries of dead or
    /// completed flights are pruned first; if the map is still full the caller
    /// gets `Backpressure`.
    pub fn join_or_lead(&self, key: K) -> Result<Flight<V>, SingleFlightError> {
        let mut map = self.map();
        if let Some(rx) = map.get(&key) {
            if rx.has_changed().is_ok() {
                return Ok(Flight::Follow(rx.clone()));
            }
            // Leader gone (sender dropped): start a new flight.
            map.remove(&key);
        }
        if map.len() >= self.max_inflight {
            map.retain(|_, rx| rx.has_changed().is_ok() && rx.borrow().is_none());
            if map.len() >= self.max_inflight {
                return Err(SingleFlightError::Backpressure);
            }
        }
        let (tx, rx) = watch::channel(None);
        map.insert(key, rx);
        Ok(Flight::Lead(tx))
    }

    /// Leader completed: remove the key so a later equivalent request recomputes.
    /// Only a completed or abandoned flight is removed, so a stale `finish` never
    /// removes a newer leader's flight.
    pub fn finish(&self, key: &K) {
        let mut map = self.map();
        let done = map
            .get(key)
            .is_some_and(|rx| rx.borrow().is_some() || rx.has_changed().is_err());
        if done {
            map.remove(key);
        }
    }

    /// Number of keys currently tracked (for diagnostics and tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map().values().filter(|rx| live(rx)).count()
    }

    /// Whether no key is in flight.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Eq + Hash + Clone, V: Clone + Send + Sync + 'static> Default for SingleFlight<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Await a leader's value. `LeaderGone` when the leader dropped its sender
/// without publishing.
pub async fn follow<V: Clone>(mut rx: watch::Receiver<Option<V>>) -> Result<V, SingleFlightError> {
    loop {
        if let Some(v) = rx.borrow_and_update().clone() {
            return Ok(v);
        }
        if rx.changed().await.is_err() {
            // Closed: a value may still have been published just before.
            return rx.borrow().clone().ok_or(SingleFlightError::LeaderGone);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn followers_receive_the_leaders_value_and_finish_resets() {
        let sf: SingleFlight<u32, u64> = SingleFlight::new();
        let Flight::Lead(tx) = sf.join_or_lead(1).unwrap() else {
            panic!("first caller must lead");
        };
        let Flight::Follow(rx) = sf.join_or_lead(1).unwrap() else {
            panic!("second caller must follow");
        };
        let waiter = tokio::spawn(follow(rx));
        tx.send(Some(7)).unwrap();
        sf.finish(&1);
        assert_eq!(waiter.await.unwrap(), Ok(7));
        assert!(sf.is_empty());
        assert!(matches!(sf.join_or_lead(1).unwrap(), Flight::Lead(_)));
    }

    #[tokio::test]
    async fn abandoned_leader_is_replaced_and_followers_learn_it() {
        let sf: SingleFlight<u32, u64> = SingleFlight::new();
        let Flight::Lead(tx) = sf.join_or_lead(1).unwrap() else {
            panic!("lead");
        };
        let Flight::Follow(rx) = sf.join_or_lead(1).unwrap() else {
            panic!("follow");
        };
        drop(tx);
        assert_eq!(follow(rx).await, Err(SingleFlightError::LeaderGone));
        assert!(matches!(sf.join_or_lead(1).unwrap(), Flight::Lead(_)));
    }

    #[test]
    fn bound_gives_backpressure_but_prunes_dead_flights() {
        let sf: SingleFlight<u32, u64> = SingleFlight::with_bound(2);
        let Flight::Lead(a) = sf.join_or_lead(1).unwrap() else {
            panic!("lead");
        };
        let Flight::Lead(_b) = sf.join_or_lead(2).unwrap() else {
            panic!("lead");
        };
        assert_eq!(
            sf.join_or_lead(3).unwrap_err(),
            SingleFlightError::Backpressure
        );
        drop(a);
        assert!(matches!(sf.join_or_lead(3).unwrap(), Flight::Lead(_)));
    }

    #[test]
    fn stale_finish_never_removes_a_newer_flight() {
        let sf: SingleFlight<u32, u64> = SingleFlight::new();
        let Flight::Lead(old) = sf.join_or_lead(1).unwrap() else {
            panic!("lead");
        };
        drop(old);
        let Flight::Lead(_new) = sf.join_or_lead(1).unwrap() else {
            panic!("lead");
        };
        sf.finish(&1);
        assert!(matches!(sf.join_or_lead(1).unwrap(), Flight::Follow(_)));
    }
}
