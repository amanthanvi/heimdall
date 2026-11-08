//! ⟨M03⟩ The signing gates, the pending marks and the signing permit (ADR-0008 D2
//! item 3a; m03-plan U0b row 24), and the managed effect driver's entry point (U0b
//! row 21).
//!
//! **The gate.** Each grant with a credential instance has one async reader-writer
//! lock, created with its first instance ([`SigningGates::retain`]) and dropped with
//! its last ([`SigningGates::release`]). Each gate records its grant's ancestor chain
//! (root first) at creation; the chain fixes the grant's place in the **global lock
//! order** ([`GateOrder`]: delegation depth, then grant ID) and lets the pending check
//! walk the ancestors in memory.
//!
//! * A **signer** takes one gate shared, waiting at most `signing_gate_wait`
//!   ([`SigningGates::admit_shared`]), and checks the pending mark first, before any
//!   store read. The guard becomes the [`SignPermit`], held until the response is
//!   enqueued.
//! * A **delegation** holds the gates of the parent and of every ancestor shared, in
//!   global order, root first, until the child's first install
//!   ([`SigningGates::hold_for_delegation`]); it re-checks the mark after each awaited
//!   acquisition.
//! * A **narrowing** ([`SigningGates::begin_narrowing`]) sets its pending marks before
//!   it waits for anything, then takes gates exclusively, one at a time, in global
//!   order ([`Narrowing::acquire`]); it never acquires a gate that sorts before one it
//!   holds, and it defers to any still-running narrowing with a smaller sequence
//!   number whose marks cover the gate ("earlier marks go first"). It is never
//!   aborted for time. The narrowing protocol itself (rounds, re-reads, commit) is
//!   `Operations`' (U0b row 20); this module gives it the primitives.
//!
//! **Fairness (assumption A3).** The gates are `tokio::sync::RwLock`s. Tokio's lock is
//! FIFO-fair (write-preferring): a read lock is not given out while a write request
//! queued before it waits, because the batch semaphore assigns released permits to
//! the head of its queue and a queued writer holds the permits it has been assigned
//! (`tokio::sync::RwLock` documentation, "The priority policy … is fair"). So a
//! queued exclusive request is never overtaken by a later shared one
//! (`gate_is_fair_writer_not_starved`).
//!
//! **Retiring gates** (ADR-0008 §17.15). A gate entry is never dropped while it has
//! a holder or waiter (a [`SharedGate`], a [`SignPermit`], a [`DelegationHold`], a
//! [`Narrowing`] holding or queuing for it) or while a pending mark covers it. When
//! its last instance is released in that state it is **retiring**: still seen by
//! [`SigningGates::contains`], [`SigningGates::order`], [`SigningGates::sort_global`]
//! and every acquisition, and dropped only when the last holder and covering mark go.
//! The release of a grant's last instance also takes the gate exclusively
//! ([`SigningGates::release_exclusive`], or [`Narrowing::release_instance`] under a
//! narrowing that already holds it; U10 wires it).
//!
//! **The pending mark** is in-memory and authoritative: a grant is pending when it
//! **or any ancestor** is marked by a running narrowing. Marks are kept per narrowing
//! (a set of sequence numbers per grant), so overlapping narrowings never clear each
//! other's; a narrowing clears only its own, when it ends or is dropped.
//!
//! Nothing here touches the store or awaits anything but a gate or an earlier
//! narrowing's end. The state mutex is never held across an await.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::GrantId;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, watch};
use tokio::time::Instant;

use crate::ports::{
    AdapterError, IntegrationSnapshot, IssuerPort, ManagedEffects, ManagedPrepared, PrepareRequest,
};

/// A grant's place in the global lock order (ADR-0008 D2 item 3a "Lock order"):
/// ancestors first (by delegation depth), then by grant ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GateOrder {
    /// The number of ancestors (0 for a root grant).
    pub depth: usize,
    /// The grant.
    pub grant: GrantId,
}

/// Why a gate operation did not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GateError {
    /// The grant has no gate (no credential instance): nothing can sign with it.
    #[error("no signing gate for the grant")]
    NoGate,
    /// The shared wait elapsed (`signing_gate_wait`, or the delegation's wait).
    #[error("signing gate not obtained in time")]
    Timeout,
    /// The grant or an ancestor is marked `narrowing_pending`; every gate taken was
    /// released.
    #[error("narrowing pending")]
    Pending,
    /// A narrowing asked for a gate that sorts before one it already holds (global
    /// lock order violated); nothing was acquired.
    #[error("gate requested out of global lock order")]
    OutOfOrder,
}

struct Gate {
    lock: Arc<RwLock<()>>,
    /// Root first, the parent last; the grant itself excluded.
    ancestors: Arc<[GrantId]>,
    /// Live credential instances (0: retiring).
    instances: usize,
    /// Outstanding holders and waiters ([`GateHold`]s).
    holders: usize,
}

#[derive(Default)]
struct State {
    gates: HashMap<GrantId, Gate>,
    /// Grant → the sequence numbers of the running narrowings that mark it.
    marks: HashMap<GrantId, BTreeSet<u64>>,
    /// Running narrowings by sequence number; `true` is sent when one ends.
    running: BTreeMap<u64, watch::Sender<bool>>,
    next_seq: u64,
}

impl State {
    fn marked(&self, grant: &GrantId) -> bool {
        self.marks.get(grant).is_some_and(|s| !s.is_empty())
    }

    /// Recorded chain of `grant`, if it has a gate.
    fn chain(&self, grant: &GrantId) -> Option<Arc<[GrantId]>> {
        self.gates.get(grant).map(|g| Arc::clone(&g.ancestors))
    }

    fn pending(&self, grant: &GrantId, extra: &[GrantId]) -> bool {
        if self.marked(grant) || extra.iter().any(|a| self.marked(a)) {
            return true;
        }
        self.chain(grant)
            .is_some_and(|c| c.iter().any(|a| self.marked(a)))
    }

    /// The largest sequence number below `seq` of a running narrowing whose marks
    /// cover `grant` (itself or a recorded ancestor).
    fn earlier_covering(&self, grant: &GrantId, seq: u64) -> Option<u64> {
        let chain = self.chain(grant);
        std::iter::once(grant)
            .chain(chain.iter().flat_map(|c| c.iter()))
            .filter_map(|g| self.marks.get(g))
            .filter_map(|s| s.range(..seq).next_back().copied())
            .max()
    }

    /// Take one hold on `grant`'s gate: its lock and the RAII token that keeps the
    /// entry alive. The token must never be dropped while `self`'s mutex is held.
    fn hold(
        &mut self,
        owner: &SigningGates,
        grant: &GrantId,
    ) -> Option<(Arc<RwLock<()>>, GateHold)> {
        let g = self.gates.get_mut(grant)?;
        g.holders = g.holders.saturating_add(1);
        Some((
            Arc::clone(&g.lock),
            GateHold {
                gates: owner.clone(),
                grant: grant.clone(),
            },
        ))
    }

    /// Whether `grant`'s entry may be dropped now: no instance, no holder, no
    /// covering mark.
    fn droppable(&self, grant: &GrantId) -> bool {
        self.gates
            .get(grant)
            .is_some_and(|g| g.instances == 0 && g.holders == 0)
            && !self.pending(grant, &[])
    }

    /// Drop `grant`'s entry if it is retiring and nothing keeps it.
    fn sweep_one(&mut self, grant: &GrantId) -> bool {
        if self.droppable(grant) {
            self.gates.remove(grant);
            true
        } else {
            false
        }
    }

    /// Drop every retiring entry nothing keeps (after marks are cleared).
    fn sweep(&mut self) {
        let retiring: Vec<GrantId> = self
            .gates
            .iter()
            .filter(|(_, g)| g.instances == 0)
            .map(|(id, _)| id.clone())
            .collect();
        for id in retiring {
            self.sweep_one(&id);
        }
    }

    fn order(&self, grant: &GrantId) -> Option<GateOrder> {
        self.gates.get(grant).map(|g| GateOrder {
            depth: g.ancestors.len(),
            grant: grant.clone(),
        })
    }
}

/// The per-grant signing gates and the pending marks (ADR-0008 D2 item 3a). One
/// instance per runtime, shared by `Operations` (`Operations::signing_gates`) and
/// the signer. Cloning shares it.
#[derive(Clone, Default)]
pub struct SigningGates {
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for SigningGates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.lock();
        f.debug_struct("SigningGates")
            .field("gates", &s.gates.len())
            .field("marked", &s.marks.len())
            .field("running_narrowings", &s.running.len())
            .finish()
    }
}

impl SigningGates {
    /// No gates, no marks.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // --- lifecycle --------------------------------------------------------------

    /// Count one more credential instance of `grant`, creating its gate with the
    /// first one. `ancestors` is the grant's ancestor chain, **root first, parent
    /// last** (the grant excluded); it is recorded only at creation, and fixes the
    /// grant's [`GateOrder`] and its pending coverage. Returns `true` when the gate
    /// was created. A **retiring** gate (§17.15) is revived with its same lock and
    /// chain, so its existing holders keep excluding the new instance's users;
    /// whether a new instance may be created at all is the caller's check.
    pub fn retain(&self, grant: &GrantId, ancestors: &[GrantId]) -> bool {
        let mut s = self.lock();
        if let Some(g) = s.gates.get_mut(grant) {
            g.instances = g.instances.saturating_add(1);
            return false;
        }
        s.gates.insert(
            grant.clone(),
            Gate {
                lock: Arc::new(RwLock::new(())),
                ancestors: Arc::from(ancestors),
                instances: 1,
                holders: 0,
            },
        );
        true
    }

    /// Count one credential instance of `grant` gone. With the last one the gate is
    /// dropped at once if nothing keeps it; otherwise (a holder or waiter, or a
    /// pending mark covering it) it is **retiring** and dropped when the last of
    /// those goes (ADR-0008 §17.15). Returns `true` when the entry was dropped now.
    ///
    /// **Requirement (§17.15):** the release of a grant's **last** instance takes the
    /// grant's gate exclusively. Use [`Self::release_exclusive`], or
    /// [`Narrowing::release_instance`] under a narrowing that holds the gate; a bare
    /// `release` of the last instance is for callers that already hold it so.
    pub fn release(&self, grant: &GrantId) -> bool {
        let mut s = self.lock();
        let Some(g) = s.gates.get_mut(grant) else {
            return false;
        };
        g.instances = g.instances.saturating_sub(1);
        if g.instances == 0 {
            s.sweep_one(grant)
        } else {
            false
        }
    }

    /// ⟨§17.15⟩ Release one instance of `grant` while holding its gate
    /// **exclusively**: waits (with no time limit; every holder is bounded) for the
    /// gate, releases the instance under it, then lets the gate go. Returns `true`
    /// when the entry was dropped. Never call it while holding `grant`'s gate (use
    /// [`Narrowing::release_instance`] there); it holds no other gate, so it adds no
    /// wait cycle. Dropping the future releases nothing.
    pub async fn release_exclusive(&self, grant: &GrantId) -> bool {
        let taken = self.lock().hold(self, grant);
        let Some((lock, hold)) = taken else {
            return false;
        };
        let guard = lock.write_owned().await;
        {
            let mut s = self.lock();
            if let Some(g) = s.gates.get_mut(grant) {
                g.instances = g.instances.saturating_sub(1);
            }
        }
        drop(guard);
        drop(hold);
        !self.contains(grant)
    }

    /// Whether `grant` has a gate (retiring ones included).
    #[must_use]
    pub fn contains(&self, grant: &GrantId) -> bool {
        self.lock().gates.contains_key(grant)
    }

    /// Whether `grant`'s gate is retiring: no instance left, kept by a holder or a
    /// covering mark (§17.15).
    #[must_use]
    pub fn is_retiring(&self, grant: &GrantId) -> bool {
        self.lock()
            .gates
            .get(grant)
            .is_some_and(|g| g.instances == 0)
    }

    /// Outstanding holders and waiters of `grant`'s gate.
    #[must_use]
    pub fn holders(&self, grant: &GrantId) -> usize {
        self.lock().gates.get(grant).map_or(0, |g| g.holders)
    }

    /// Live credential instances counted for `grant` (0 without a gate).
    #[must_use]
    pub fn instances(&self, grant: &GrantId) -> usize {
        self.lock().gates.get(grant).map_or(0, |g| g.instances)
    }

    /// The ancestor chain recorded with `grant`'s gate (root first).
    #[must_use]
    pub fn ancestors(&self, grant: &GrantId) -> Option<Vec<GrantId>> {
        self.lock().chain(grant).map(|c| c.to_vec())
    }

    /// `grant`'s place in the global lock order, if it has a gate.
    #[must_use]
    pub fn order(&self, grant: &GrantId) -> Option<GateOrder> {
        self.lock().order(grant)
    }

    /// The gated members of `grants` in global lock order (ungated ones omitted:
    /// they have nothing to acquire), without duplicates.
    #[must_use]
    pub fn sort_global<'a>(&self, grants: impl IntoIterator<Item = &'a GrantId>) -> Vec<GateOrder> {
        let s = self.lock();
        let set: BTreeSet<GateOrder> = grants.into_iter().filter_map(|g| s.order(g)).collect();
        set.into_iter().collect()
    }

    // --- pending marks ----------------------------------------------------------

    /// Whether `grant` or any ancestor recorded with its gate is marked
    /// `narrowing_pending`. An in-memory lookup that never awaits.
    #[must_use]
    pub fn is_pending(&self, grant: &GrantId) -> bool {
        self.lock().pending(grant, &[])
    }

    /// As [`Self::is_pending`], with `ancestors` (any order) checked as well: for a
    /// grant whose gate does not exist yet, or whose chain the caller read itself.
    #[must_use]
    pub fn is_pending_with(&self, grant: &GrantId, ancestors: &[GrantId]) -> bool {
        self.lock().pending(grant, ancestors)
    }

    /// How many running narrowings mark `grant` itself (ancestors not counted).
    #[must_use]
    pub fn mark_count(&self, grant: &GrantId) -> usize {
        self.lock().marks.get(grant).map_or(0, BTreeSet::len)
    }

    /// The sequence numbers of the narrowings still running.
    #[must_use]
    pub fn running_narrowings(&self) -> Vec<u64> {
        self.lock().running.keys().copied().collect()
    }

    // --- signers ----------------------------------------------------------------

    /// Take `grant`'s gate **shared**, waiting at most `wait` (`signing_gate_wait`).
    /// Does not check the pending mark; see [`Self::admit_shared`].
    ///
    /// # Errors
    /// [`GateError::NoGate`], [`GateError::Timeout`].
    pub async fn acquire_shared(
        &self,
        grant: &GrantId,
        wait: Duration,
    ) -> Result<SharedGate, GateError> {
        let (lock, hold, ancestors) = {
            let mut s = self.lock();
            let ancestors = s.chain(grant).ok_or(GateError::NoGate)?;
            let (lock, hold) = s.hold(self, grant).ok_or(GateError::NoGate)?;
            (lock, hold, ancestors)
        };
        let guard = tokio::time::timeout(wait, lock.read_owned())
            .await
            .map_err(|_| GateError::Timeout)?;
        Ok(SharedGate {
            gates: self.clone(),
            grant: grant.clone(),
            ancestors,
            _guard: guard,
            _hold: hold,
        })
    }

    /// Steps 3–4's start (ADR-0008 D2 item 3a): take `grant`'s gate shared within
    /// `wait`, then check the pending mark **first**, right after the awaited
    /// acquisition and before any store read. A marked grant or ancestor refuses and
    /// the gate is released at once.
    ///
    /// # Errors
    /// [`GateError::NoGate`], [`GateError::Timeout`], [`GateError::Pending`].
    pub async fn admit_shared(
        &self,
        grant: &GrantId,
        wait: Duration,
    ) -> Result<SharedGate, GateError> {
        let gate = self.acquire_shared(grant, wait).await?;
        if gate.is_pending() {
            return Err(GateError::Pending);
        }
        Ok(gate)
    }

    // --- delegations ------------------------------------------------------------

    /// ⟨r4⟩ The delegation hold (ADR-0008 D2 item 3a; Q26): the gates of `parent` and
    /// of every ancestor, taken **shared** in global order (root first), all within
    /// `wait` in total. `ancestors` is the parent's chain as the caller read it
    /// (root first, parent excluded); gates that do not exist are skipped.
    ///
    /// Refuses at once when the parent or an ancestor is pending, and re-checks the
    /// mark after **each** awaited acquisition; a mark found releases every gate
    /// taken. The caller re-checks once more, before the child's first install
    /// ([`DelegationHold::is_pending`], or [`Self::is_pending`] on the child), and
    /// bounds the hold by `delegation_gate_hold_max` ([`DelegationHold::held_for`]).
    ///
    /// # Errors
    /// [`GateError::Pending`], [`GateError::Timeout`]. A parent with no gate at all
    /// is [`GateError::NoGate`].
    pub async fn hold_for_delegation(
        &self,
        parent: &GrantId,
        ancestors: &[GrantId],
        wait: Duration,
    ) -> Result<DelegationHold, GateError> {
        if self.is_pending_with(parent, ancestors) {
            return Err(GateError::Pending);
        }
        if !self.contains(parent) {
            return Err(GateError::NoGate);
        }
        let deadline = Instant::now() + wait;
        let mut chain: Vec<GrantId> = ancestors.to_vec();
        chain.push(parent.clone());
        let ordered = self.sort_global(chain.iter());
        let mut guards = Vec::with_capacity(ordered.len());
        for o in ordered {
            let taken = self.lock().hold(self, &o.grant);
            let Some((lock, hold)) = taken else {
                continue;
            };
            let guard = tokio::time::timeout_at(deadline, lock.read_owned())
                .await
                .map_err(|_| GateError::Timeout)?;
            guards.push((o, guard, hold));
            if self.is_pending_with(parent, ancestors) {
                return Err(GateError::Pending);
            }
        }
        Ok(DelegationHold {
            gates: self.clone(),
            parent: parent.clone(),
            ancestors: ancestors.to_vec(),
            started: Instant::now(),
            guards,
        })
    }

    // --- narrowings -------------------------------------------------------------

    /// ⟨r4⟩ Start a narrowing: allocate its sequence number and mark every grant of
    /// `set` `narrowing_pending`, **before** it waits for any gate (ADR-0008 D2 item
    /// 3a). From here, every new signer and delegation under those grants (and their
    /// descendants) is refused at its first check. The marks are cleared when the
    /// returned [`Narrowing`] is finished or dropped.
    #[must_use]
    pub fn begin_narrowing(&self, set: impl IntoIterator<Item = GrantId>) -> Narrowing {
        let mut s = self.lock();
        let seq = s.next_seq;
        s.next_seq = s.next_seq.saturating_add(1);
        let (tx, _) = watch::channel(false);
        s.running.insert(seq, tx);
        let mut marked = BTreeSet::new();
        for g in set {
            s.marks.entry(g.clone()).or_default().insert(seq);
            marked.insert(g);
        }
        drop(s);
        Narrowing {
            gates: self.clone(),
            seq,
            marked,
            held: Vec::new(),
        }
    }

    /// Build the permit of an admitted signature from its shared gate (ADR-0008 D2
    /// item 3a step 4). `time` is the read-only time assessment the release check
    /// consults; it must not block.
    #[must_use]
    pub fn permit(gate: SharedGate, expiry: PermitExpiry, time: Arc<dyn SafeTime>) -> SignPermit {
        SignPermit { gate, expiry, time }
    }
}

/// A gate held shared by one signer. Dropping it releases the gate.
pub struct SharedGate {
    gates: SigningGates,
    grant: GrantId,
    ancestors: Arc<[GrantId]>,
    // Field order: the guard is released before the hold lets the entry go.
    _guard: OwnedRwLockReadGuard<()>,
    _hold: GateHold,
}

impl std::fmt::Debug for SharedGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedGate")
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

impl SharedGate {
    /// The grant.
    #[must_use]
    pub fn grant(&self) -> &GrantId {
        &self.grant
    }

    /// Whether the grant or an ancestor (the chain recorded when the gate was
    /// created) is marked now.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.gates.is_pending_with(&self.grant, &self.ancestors)
    }
}

/// The gates a delegation holds shared, root first, until the child's first install.
/// Dropping it releases them.
pub struct DelegationHold {
    gates: SigningGates,
    parent: GrantId,
    ancestors: Vec<GrantId>,
    started: Instant,
    guards: Vec<(GateOrder, OwnedRwLockReadGuard<()>, GateHold)>,
}

impl std::fmt::Debug for DelegationHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationHold")
            .field("parent", &self.parent)
            .field("held", &self.held())
            .finish_non_exhaustive()
    }
}

impl DelegationHold {
    /// The parent.
    #[must_use]
    pub fn parent(&self) -> &GrantId {
        &self.parent
    }

    /// The gates held, in the order they were taken (global order, root first).
    #[must_use]
    pub fn held(&self) -> Vec<GrantId> {
        self.guards.iter().map(|(o, ..)| o.grant.clone()).collect()
    }

    /// Whether the parent or an ancestor is marked now (the re-check before the
    /// child's first install).
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.gates.is_pending_with(&self.parent, &self.ancestors)
    }

    /// How long the gates have been held, at `now` (continuous clock). The caller
    /// aborts fail-closed past `delegation_gate_hold_max`.
    #[must_use]
    pub fn held_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.started)
    }
}

/// One narrowing's marks and exclusive gates (ADR-0008 D2 item 3a). Dropping it (or
/// [`Narrowing::finish`]) releases every gate it holds, **then** clears its own
/// marks and wakes narrowings that deferred to it.
pub struct Narrowing {
    gates: SigningGates,
    seq: u64,
    marked: BTreeSet<GrantId>,
    held: Vec<(GateOrder, OwnedRwLockWriteGuard<()>, GateHold)>,
}

impl std::fmt::Debug for Narrowing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Narrowing")
            .field("seq", &self.seq)
            .field("marked", &self.marked)
            .field("held", &self.held())
            .finish_non_exhaustive()
    }
}

/// What [`Narrowing::acquire`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acquired {
    /// The gate is now held exclusively.
    Held,
    /// The gate was already held by this narrowing.
    AlreadyHeld,
    /// The grant has no gate (no credential instance): nothing to acquire.
    NoGate,
}

impl Narrowing {
    /// The sequence number ("earlier marks go first" compares these).
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The grants this narrowing marked.
    #[must_use]
    pub fn marked(&self) -> &BTreeSet<GrantId> {
        &self.marked
    }

    /// ⟨r5⟩ Mark more grants under this narrowing's sequence number (round 1 marks
    /// every newly found descendant **before** releasing any gate). Idempotent per
    /// grant.
    pub fn mark(&mut self, grants: impl IntoIterator<Item = GrantId>) {
        let mut s = self.gates.lock();
        for g in grants {
            s.marks.entry(g.clone()).or_default().insert(self.seq);
            self.marked.insert(g);
        }
    }

    /// ⟨r6⟩ The largest sequence number below this one of a still-running narrowing
    /// whose marks cover `grant` (itself or a recorded ancestor), if any.
    #[must_use]
    pub fn earlier_covering(&self, grant: &GrantId) -> Option<u64> {
        self.gates.lock().earlier_covering(grant, self.seq)
    }

    /// ⟨r6⟩ "Earlier marks go first": wait until no still-running narrowing with a
    /// smaller sequence number covers `grant`. Holds nothing new while it waits.
    pub async fn defer_to_earlier(&self, grant: &GrantId) {
        loop {
            let rx = {
                let s = self.gates.lock();
                let Some(earlier) = s.earlier_covering(grant, self.seq) else {
                    return;
                };
                match s.running.get(&earlier) {
                    Some(tx) => tx.subscribe(),
                    // Marks are removed with the narrowing; defensive.
                    None => return,
                }
            };
            let mut rx = rx;
            // `Err` means the sender is gone: that narrowing ended too.
            let _ = rx.wait_for(|done| *done).await;
        }
    }

    /// The global order of the gates held now.
    #[must_use]
    pub fn held(&self) -> Vec<GrantId> {
        self.held.iter().map(|(o, ..)| o.grant.clone()).collect()
    }

    /// Whether this narrowing holds `grant`'s gate.
    #[must_use]
    pub fn holds(&self, grant: &GrantId) -> bool {
        self.held.iter().any(|(o, ..)| &o.grant == grant)
    }

    /// Take `grant`'s gate **exclusively**. First, under "earlier marks go first", it
    /// waits for every still-running earlier narrowing that covers `grant`; then it
    /// queues for the gate, with no time limit (a narrowing is never aborted for
    /// time; every holder is individually bounded). The gate must sort after every
    /// gate already held.
    ///
    /// # Errors
    /// [`GateError::OutOfOrder`] when `grant` sorts before (or equal to, for another
    /// grant) a gate already held; nothing is acquired.
    pub async fn acquire(&mut self, grant: &GrantId) -> Result<Acquired, GateError> {
        if self.holds(grant) {
            return Ok(Acquired::AlreadyHeld);
        }
        let Some(order) = self.gates.order(grant) else {
            return Ok(Acquired::NoGate);
        };
        if self.held.last().is_some_and(|(last, ..)| *last >= order) {
            return Err(GateError::OutOfOrder);
        }
        self.defer_to_earlier(grant).await;
        let taken = self.gates.lock().hold(&self.gates, grant);
        // Dropped while deferring: no instance, holder or covering mark was left.
        let Some((lock, hold)) = taken else {
            return Ok(Acquired::NoGate);
        };
        let guard = lock.write_owned().await;
        self.held.push((order, guard, hold));
        Ok(Acquired::Held)
    }

    /// Take the gates of `grants` exclusively in global order (ungated ones skipped).
    /// Every one must sort after the gates already held.
    ///
    /// # Errors
    /// [`GateError::OutOfOrder`], from the first gate that would violate the order;
    /// the gates acquired before it stay held.
    pub async fn acquire_all<'a>(
        &mut self,
        grants: impl IntoIterator<Item = &'a GrantId>,
    ) -> Result<(), GateError> {
        for o in self.gates.sort_global(grants) {
            self.acquire(&o.grant).await?;
        }
        Ok(())
    }

    /// ⟨§17.15⟩ Release one instance of `grant` under this narrowing's exclusive hold
    /// of its gate (key destruction under the gates). Returns whether the entry was
    /// dropped; while this narrowing holds the gate or marks cover it, it stays
    /// retiring and is dropped when they go.
    ///
    /// # Errors
    /// [`GateError::NoGate`] when this narrowing does not hold `grant`'s gate;
    /// nothing is released.
    pub fn release_instance(&self, grant: &GrantId) -> Result<bool, GateError> {
        if !self.holds(grant) {
            return Err(GateError::NoGate);
        }
        Ok(self.gates.release(grant))
    }

    /// ⟨r4⟩ Release **every** gate held, keeping the marks (round 1: release
    /// everything, then reacquire in global order).
    pub fn release_all(&mut self) {
        self.held.clear();
    }

    /// End the narrowing: release every gate, then clear this narrowing's marks and
    /// wake narrowings deferring to it. Dropping does the same.
    pub fn finish(self) {
        drop(self);
    }
}

impl Drop for Narrowing {
    fn drop(&mut self) {
        // Gates first, then the marks (D2 item 3a, "release the gates, and clear the
        // pending marks").
        self.held.clear();
        let mut s = self.gates.lock();
        for g in &self.marked {
            if let Some(set) = s.marks.get_mut(g) {
                set.remove(&self.seq);
                if set.is_empty() {
                    s.marks.remove(g);
                }
            }
        }
        // §17.15: retiring gates these marks kept can go now.
        s.sweep();
        if let Some(tx) = s.running.remove(&self.seq) {
            tx.send_replace(true);
        }
    }
}

/// One hold on a gate entry (§17.15): while any exists the entry is never dropped.
/// Dropping the last one of a retiring, unmarked gate drops the entry.
struct GateHold {
    gates: SigningGates,
    grant: GrantId,
}

impl Drop for GateHold {
    fn drop(&mut self) {
        let mut s = self.gates.lock();
        if let Some(g) = s.gates.get_mut(&self.grant) {
            g.holders = g.holders.saturating_sub(1);
        }
        s.sweep_one(&self.grant);
    }
}

// --- the signing permit ---------------------------------------------------------

/// The read-only time assessment the release check consults (ADR-0008 D2 item 3a
/// step 7), supplied by the operations layer. Must be in-memory and never block.
pub trait SafeTime: Send + Sync {
    /// `Some(accepted wall time)` while time is `Safe`; `None` otherwise.
    fn safe_wall_now(&self) -> Option<Timestamp>;
}

impl<F> SafeTime for F
where
    F: Fn() -> Option<Timestamp> + Send + Sync,
{
    fn safe_wall_now(&self) -> Option<Timestamp> {
        self()
    }
}

/// ⟨r3⟩ A permit's absolute expiry on both clocks: the earliest of the grant's wall
/// deadline, the end of its continuous budget, every admission limit and the holder
/// bound (step start + `signing_holder_max`) (ADR-0008 D2 item 3a step 4; §17.4 item
/// 6). Start from one bound and tighten with each other one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermitExpiry {
    /// The wall-clock expiry.
    pub wall: Timestamp,
    /// The continuous-clock expiry.
    pub continuous: Instant,
}

impl PermitExpiry {
    /// An expiry at `wall` and `continuous`.
    #[must_use]
    pub fn new(wall: Timestamp, continuous: Instant) -> Self {
        Self { wall, continuous }
    }

    /// The earlier of the current wall expiry and `bound`.
    #[must_use]
    pub fn tighten_wall(self, bound: Timestamp) -> Self {
        Self {
            wall: self.wall.min(bound),
            ..self
        }
    }

    /// The earlier of the current continuous expiry and `bound`.
    #[must_use]
    pub fn tighten_continuous(self, bound: Instant) -> Self {
        Self {
            continuous: self.continuous.min(bound),
            ..self
        }
    }
}

/// Why the release check refused (ADR-0008 D2 item 3a step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReleaseRefusal {
    /// The continuous-clock expiry passed.
    #[error("permit expired (continuous clock)")]
    ExpiredContinuous,
    /// Time is not `Safe`.
    #[error("time not safe")]
    TimeNotSafe,
    /// The wall-clock expiry passed.
    #[error("permit expired (wall clock)")]
    ExpiredWall,
    /// The grant or an ancestor is marked `narrowing_pending`.
    #[error("narrowing pending")]
    NarrowingPending,
}

/// ⟨r2⟩ An admitted signature's permit (ADR-0008 D2 item 3a): the grant's gate held
/// shared, with the permit's absolute expiry. Held until the response is enqueued,
/// then dropped (releasing the gate). `heimdall-credential` wraps it as an
/// `ipc::signing::PermitGuard`: [`Self::may_release`] and [`Self::expires_at`] match
/// `ipc::signing::ReleaseCheck`.
pub struct SignPermit {
    gate: SharedGate,
    expiry: PermitExpiry,
    time: Arc<dyn SafeTime>,
}

impl std::fmt::Debug for SignPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignPermit")
            .field("grant", self.gate.grant())
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}

impl SignPermit {
    /// The grant.
    #[must_use]
    pub fn grant(&self) -> &GrantId {
        self.gate.grant()
    }

    /// The absolute expiry.
    #[must_use]
    pub fn expiry(&self) -> PermitExpiry {
        self.expiry
    }

    /// ⟨r4⟩ The continuous-clock instant of the expiry; it cancels the wait for
    /// outbound capacity (step 6).
    #[must_use]
    pub fn expires_at(&self) -> Instant {
        self.expiry.continuous
    }

    /// The wall-clock expiry.
    #[must_use]
    pub fn expires_wall(&self) -> Timestamp {
        self.expiry.wall
    }

    /// The release check at explicit readings: `safe_wall` is the read-only time
    /// assessment (`None` = not `Safe`), `now` the continuous clock. `None` means the
    /// signature may be released. Refuses at or after the expiry on either clock,
    /// when time is not `Safe`, or when the grant or an ancestor is pending.
    #[must_use]
    pub fn release_refusal_at(
        &self,
        safe_wall: Option<Timestamp>,
        now: Instant,
    ) -> Option<ReleaseRefusal> {
        if now >= self.expiry.continuous {
            return Some(ReleaseRefusal::ExpiredContinuous);
        }
        let Some(wall) = safe_wall else {
            return Some(ReleaseRefusal::TimeNotSafe);
        };
        if wall >= self.expiry.wall {
            return Some(ReleaseRefusal::ExpiredWall);
        }
        if self.gate.is_pending() {
            return Some(ReleaseRefusal::NarrowingPending);
        }
        None
    }

    /// [`Self::release_refusal_at`] as a predicate.
    #[must_use]
    pub fn may_release_at(&self, safe_wall: Option<Timestamp>, now: Instant) -> bool {
        self.release_refusal_at(safe_wall, now).is_none()
    }

    /// ⟨r3⟩ The release check now (step 7): the injected time assessment and the
    /// continuous clock. Never blocks.
    #[must_use]
    pub fn may_release(&self) -> bool {
        self.may_release_at(self.time.safe_wall_now(), Instant::now())
    }
}

// --- the managed effect driver (U0b row 21) -------------------------------------

/// The `AdapterError::Protocol` text of a managed `prepare_from` called without the
/// effect driver's results (ADR-0008 D6 item 0).
pub const MANAGED_PREPARE_WITHOUT_DRIVER: &str =
    "managed preparation runs through the effect driver";

/// The `AdapterError::Protocol` text [`drive_preparation`] answers in wave 0: the
/// driver is U10's (U0b row 21, phase 2).
pub const MANAGED_DRIVER_NOT_WIRED: &str = "managed effect driver not wired (driver_unavailable)";

/// ⟨r2⟩ The managed effect driver (ADR-0008 D6 items 0–1; U0b row 21): runs the stage
/// sequence key → reserve → sign → publish → install → materialize → prepared around
/// [`ManagedEffects`] and [`IssuerPort`], doing every store transaction itself,
/// outside any adapter bound, with a stage receipt between effects. Its result goes
/// into `IntegrationSnapshot.managed.prepared`.
///
/// **Wave 0 (phase 1):** the body is U10's, so it fails closed with
/// `AdapterError::Protocol(`[`MANAGED_DRIVER_NOT_WIRED`]`)` before any effect or
/// store write.
///
/// # Errors
/// [`AdapterError`].
pub async fn drive_preparation(
    _ops: &crate::Operations,
    _effects: &dyn ManagedEffects,
    _issuer: &dyn IssuerPort,
    _req: PrepareRequest<'_>,
) -> Result<ManagedPrepared, AdapterError> {
    Err(AdapterError::Protocol(MANAGED_DRIVER_NOT_WIRED.to_owned()))
}

/// The managed adapter's `prepare_from` precondition (ADR-0008 D6 item 0): the
/// snapshot must carry the effect driver's results.
///
/// # Errors
/// `AdapterError::Protocol(`[`MANAGED_PREPARE_WITHOUT_DRIVER`]`)` without them.
pub fn driver_results(sources: &IntegrationSnapshot) -> Result<&ManagedPrepared, AdapterError> {
    sources
        .managed
        .as_ref()
        .and_then(|m| m.prepared.as_ref())
        .ok_or_else(|| AdapterError::Protocol(MANAGED_PREPARE_WITHOUT_DRIVER.to_owned()))
}
