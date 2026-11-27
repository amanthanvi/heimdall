//! ⟨M08 U2b-2; ADR-0014 §3.6 "The restore epoch and the replay fence", steps 2 to 4; H9, H13⟩
//! The server's check of every mutating request, before any store write or effect, attended
//! or not ([`RequestFence::admit`]):
//!
//! 1. **The epoch** (step 3). A frame whose `request_epoch` is present and not the runtime's
//!    current epoch is refused `REQUEST_STALE`, reason `restore_epoch_stale`, effect `none`.
//!    Nothing is read or written for it. A frame with no epoch is bound to the current epoch
//!    at receipt.
//! 2. **A decision reference** (step 2). `decide` on a recorded decision minted under another
//!    epoch is refused `DECISION_STALE`, reason `restore_epoch_stale`.
//! 3. **The fence** (step 4, lookup). A request that carries a request ID is keyed by the
//!    digest of its full idempotency key (`heimdall_store::fence::ledger_digest`: principal,
//!    caller role, `remote_client`, kind, request ID). A fence record for that digest answers
//!    its stored answer (`REQUEST_STALE`, `restored_before_completion`), or `REQUEST_EXPIRED`
//!    inside a settled key's marker window, and the request is never run.
//! 4. **The ledger** (step 4, append). Otherwise one record, the bound epoch and the digest,
//!    is appended to the request ledger and synced **before the request reaches the
//!    application**, so before its first store write. A damaged ledger refuses every append
//!    (`STATE_UNAVAILABLE`, reason `ledger_damaged`, next `owner_decision`; the ruling of
//!    2026-11-23, recovered by the attended `state repair`), and so does any other failure to
//!    append: the request does not proceed.
//!
//! Every answer to a mutating request then reports the request ID it carried and the epoch it
//! was bound to ([`RequestFence::binding`], [`Stamp::apply`], the envelope's `request_id` and
//! `request_epoch`).
//!
//! **Where the check runs** (⟨M08 U2b-2 follow-up A⟩, `crate::dispatch`): last before the
//! request runs, after the caller's role checks (a paired client's row check, the owner-only
//! forms) and the uninstall-fence admission, which is held across it and the request. A
//! request refused for its role or by the uninstall fence therefore appends nothing to the
//! ledger and writes nothing; its answer still reports the binding.
//!
//! **The epoch is read once, at start-up.** Only a restore or a repair raises it, and both hold
//! the runtime's instance lock (ADR-0014 §3.6, the restore protocol's step 2), so it cannot
//! change while this runtime serves.
//!
//! ⟨M08 W4 U2b-3a⟩ **The ledger is bounded** (the soak precondition of the U2b-2 rulings):
//!
//! * **Read once.** The ledger is read and checked whole when the fence opens (the
//!   damaged-ledger check), and its live digests are kept in memory. An append then compares
//!   the file's length with the one it last saw and appends, reading nothing
//!   (`heimdall_stategen::ledger::Ledger::append_at`): its cost does not grow with the
//!   ledger's history. The ledger is read whole again only when its length is not the
//!   expected one (a torn tail, or a change this runtime did not make) and at a trim that
//!   drops entries; damage found then refuses every append, as at the open.
//! * **Deduplicated by the key's digest.** A request whose key already has an entry appends
//!   nothing: a retry of the same full idempotency key is admitted on its first entry.
//! * **Trimmed after the marker window** (ADR-0006 §7.4). A key's settlement is kept by the
//!   ledger's digest in the store's terminal records (`heimdall_store::fence::RequestTerminal`):
//!   written when a settled journaled operation is purged (its expired-key marker is keyed by
//!   another hash) and when a request-ID request the journal does not hold completes
//!   ([`RequestFence::record_terminal`]). The retention pass marks a record trimmable once its
//!   window has ended, on the time the time gate accepted; the trim here then drops those
//!   entries by rewrite and rename (under this runtime's instance lock) and removes the
//!   records. It runs at most every ten minutes, before an admitted request's own check, and
//!   before a new key is refused at the cap below. **An entry whose settlement is unknown has
//!   no terminal record and is never dropped.**
//! * **A hard cap on live entries** (the orchestrator, 2026-11-26), checked before any append;
//!   a retry of a key already in the ledger is never refused by it. A new key is refused
//!   `BACKPRESSURE` (retryable, effect `none`, next `retry_after`), with nothing appended:
//!   - when the ledger holds [`LEDGER_LIMIT`] live entries, whoever asks;
//!   - **owner reserve:** from a caller without the owner role, when it holds
//!     `LEDGER_LIMIT - LEDGER_OWNER_RESERVE`, so the last [`LEDGER_OWNER_RESERVE`] entries are
//!     the owner role's (the local owner and paired owner clients) whatever any other
//!     principal has done. The count is the ledger's own, so it holds across restarts;
//!   - **per-principal share:** from any caller but the local owner (a paired client, by its
//!     principal and `remote_client`), when it has added [`LEDGER_CLIENT_SHARE`] live entries
//!     during this runtime's lifetime. One client's flood therefore refuses only that client,
//!     until the reserve line; the ledger holds no identifier, so the share is counted in
//!     memory and starts again at a restart (stated residual).
//!
//!   Nothing is ever evicted to make room.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_app::OpError;
use heimdall_contract::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData, NextAction, reason};
use heimdall_contract::ids::{ClientId, RequestId};
use heimdall_contract::lifecycle::RestoreEpoch;
use heimdall_contract::request::{Admission, Request};
use heimdall_domain::principal::{CallerContext, PrincipalRef};
use heimdall_store::Store;
use heimdall_store::fence::{FenceVerdict, ledger_digest};
use heimdall_store::layout::stategen::ledger::{
    Entry, Ledger, LedgerError, LedgerRead, RECORD_LEN,
};

use crate::state_store::PlatformFs;

/// ⟨M08 W4 U2b-3a⟩ The most live entries the request ledger holds (about 12 MiB of records).
/// At this count a new key is refused `BACKPRESSURE`, whoever asks (module docs). With the
/// default retention (7 days, then the 30-day marker) it allows about 7,000 new request keys a
/// day in the steady state.
pub const LEDGER_LIMIT: usize = 262_144;

/// ⟨M08 W4 U2b-3a⟩ The part of [`LEDGER_LIMIT`] only callers with the owner role may fill: a
/// caller without it is refused once the ledger holds `LEDGER_LIMIT - LEDGER_OWNER_RESERVE`
/// live entries.
pub const LEDGER_OWNER_RESERVE: usize = 65_536;

/// ⟨M08 W4 U2b-3a⟩ The most live entries one principal other than the local owner (a paired
/// client, by its principal and `remote_client`) may add during one runtime's lifetime.
pub const LEDGER_CLIENT_SHARE: usize = 32_768;

/// How often the trim runs at most (module docs).
const TRIM_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The `retry_after_ms` of the cap's `BACKPRESSURE`: room comes as entries age out, so a retry
/// soon after is pointless.
const LEDGER_FULL_RETRY_AFTER_MS: u64 = 60_000;

/// ⟨M08 W4 U2b-3a; test seam⟩ The cap's numbers ([`RequestFence::with_limits`]); production
/// uses [`LedgerLimits::DEFAULT`].
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerLimits {
    /// [`LEDGER_LIMIT`].
    pub limit: usize,
    /// [`LEDGER_OWNER_RESERVE`].
    pub owner_reserve: usize,
    /// [`LEDGER_CLIENT_SHARE`].
    pub client_share: usize,
}

impl LedgerLimits {
    /// The production numbers.
    pub const DEFAULT: Self = Self {
        limit: LEDGER_LIMIT,
        owner_reserve: LEDGER_OWNER_RESERVE,
        client_share: LEDGER_CLIENT_SHARE,
    };
}

/// What an admitted mutating request's answers report ([`RequestFence::admit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    /// The request ID the request carried.
    pub request_id: Option<RequestId>,
    /// The epoch it was bound to.
    pub epoch: RestoreEpoch,
}

impl Stamp {
    /// Report the request ID and the epoch in `env` (U0-Q5).
    pub fn apply<T>(&self, env: &mut Envelope<T>) {
        env.request_id.clone_from(&self.request_id);
        env.request_epoch = Some(self.epoch);
    }
}

/// ⟨test seam⟩ Where [`RequestFence::admit`] may be stopped, for the fault tests.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencePoint {
    /// After the ledger append returned, before the request reaches the application: a stop
    /// here leaves a ledger entry and no store record.
    AfterLedgerAppend,
}

/// ⟨test seam⟩ A stop at a [`FencePoint`]: `true` makes the request end there, unanswered by
/// the application, as a process killed at that point would leave it.
#[doc(hidden)]
pub type FenceHook = Arc<dyn Fn(FencePoint) -> bool + Send + Sync>;

/// A principal the per-principal share counts (module docs): anyone but the local owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Sharer {
    principal: PrincipalRef,
    remote_client: Option<ClientId>,
}

impl Sharer {
    /// `caller`'s share, or `None` for the local owner, who has none.
    fn of(caller: &CallerContext) -> Option<Self> {
        (!caller.has_global_access()).then(|| Self {
            principal: caller.principal.clone(),
            remote_client: caller.remote_client.clone(),
        })
    }
}

/// The ledger's live digests, as this runtime knows them (module docs).
#[derive(Debug, Default)]
struct Index {
    /// The ledger's length after its last complete record: where the next one goes.
    len: u64,
    /// Every live digest, with the number of the principal whose share it counts against when
    /// this runtime appended it (`None`: the local owner's, or an entry read at the open). A
    /// number, not the principal, so that an entry costs the same whoever sent it.
    keys: HashMap<[u8; 32], Option<u32>>,
    /// The principals this runtime has appended for, by number.
    sharers: HashMap<Sharer, u32>,
    /// Live entries per principal's number, of those this runtime appended.
    shares: HashMap<u32, usize>,
}

impl Index {
    /// The index of a ledger read whole, keeping what `earlier` knew of the entries still there.
    fn of(read: &LedgerRead, earlier: Option<Index>) -> Self {
        let earlier = earlier.unwrap_or_default();
        let mut index = Index {
            len: read.aligned_len(),
            sharers: earlier.sharers,
            ..Index::default()
        };
        let mut known = earlier.keys;
        for entry in &read.entries {
            let who = known.remove(&entry.digest).flatten();
            index.insert_numbered(entry.digest, who);
        }
        index
    }

    /// Live entries (records in the file, duplicates of an older build included).
    fn live(&self) -> usize {
        usize::try_from(self.len / RECORD_LEN as u64).unwrap_or(usize::MAX)
    }

    /// Record `digest` as live, appended for `who` (`None`: the local owner).
    fn insert(&mut self, digest: [u8; 32], who: Option<Sharer>) {
        let number = who.map(|sharer| {
            let next = u32::try_from(self.sharers.len()).unwrap_or(u32::MAX);
            *self.sharers.entry(sharer).or_insert(next)
        });
        self.insert_numbered(digest, number);
    }

    fn insert_numbered(&mut self, digest: [u8; 32], who: Option<u32>) {
        if let Some(number) = who {
            *self.shares.entry(number).or_default() += 1;
        }
        if let Some(Some(earlier)) = self.keys.insert(digest, who) {
            self.forget(earlier);
        }
    }

    fn remove(&mut self, digest: &[u8; 32]) {
        if let Some(Some(number)) = self.keys.remove(digest) {
            self.forget(number);
        }
    }

    fn forget(&mut self, number: u32) {
        if let Some(n) = self.shares.get_mut(&number) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.shares.remove(&number);
            }
        }
    }

    /// Whether a new key from `caller` must be refused at the cap (module docs).
    fn full_for(&self, caller: &CallerContext, limits: &LedgerLimits) -> bool {
        let live = self.live();
        if live >= limits.limit {
            return true;
        }
        if !caller.is_owner() && live >= limits.limit.saturating_sub(limits.owner_reserve) {
            return true;
        }
        Sharer::of(caller)
            .and_then(|s| self.sharers.get(&s))
            .is_some_and(|n| self.shares.get(n).copied().unwrap_or(0) >= limits.client_share)
    }
}

/// The request ledger with what this runtime knows of it.
struct LedgerState {
    ledger: Ledger<PlatformFs>,
    /// `None`: not read yet, or damaged or unreadable when last read (every append is then
    /// refused, and the next request reads it again).
    index: Option<Index>,
    /// When the trim last ran.
    last_trim: Option<Instant>,
}

impl LedgerState {
    /// The index, reading the ledger whole when there is none.
    fn index(&mut self) -> Result<&mut Index, LedgerError> {
        if self.index.is_none() {
            let read = self.ledger.load()?;
            self.index = Some(Index::of(&read, None));
        }
        self.index.as_mut().ok_or(LedgerError::Unreadable)
    }

    /// Read the ledger whole again, keeping what the index knew of its entries.
    fn reload(&mut self) -> Result<&mut Index, LedgerError> {
        let earlier = self.index.take();
        let read = self.ledger.load()?;
        self.index = Some(Index::of(&read, earlier));
        self.index.as_mut().ok_or(LedgerError::Unreadable)
    }
}

/// The server's epoch check, replay fence and request ledger (module docs).
pub struct RequestFence {
    store: Arc<Store>,
    ledger: Mutex<LedgerState>,
    epoch: RestoreEpoch,
    hook: Option<FenceHook>,
    limits: LedgerLimits,
}

impl std::fmt::Debug for RequestFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestFence")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Why [`RequestFence::admit`] answered instead of letting the request through.
pub type Refusal = Box<Envelope<serde_json::Value>>;

impl RequestFence {
    /// The fence of the runtime serving `store`, whose state directory is `state_dir` (the
    /// ledger lives there, outside every generation). The current epoch is read now, and the
    /// ledger is read whole once (module docs): a damaged one does not stop the open, it
    /// refuses every append.
    ///
    /// # Errors
    /// The store's refusal: a missing or malformed epoch is `state_corrupt`.
    pub fn open(store: Arc<Store>, state_dir: &Path) -> Result<Self, heimdall_store::StoreError> {
        let epoch = store.transaction(|tx| tx.restore_epoch())?;
        let mut ledger = LedgerState {
            ledger: Ledger::new(PlatformFs, state_dir),
            index: None,
            last_trim: None,
        };
        if let Err(e) = ledger.index() {
            tracing::warn!(error = %e, "the request ledger cannot be read; every request with a request ID is refused");
        }
        Ok(Self {
            ledger: Mutex::new(ledger),
            store,
            epoch,
            hook: None,
            limits: LedgerLimits::DEFAULT,
        })
    }

    /// ⟨test seam⟩ Stop admitted requests at the points `hook` says.
    #[doc(hidden)]
    #[must_use]
    pub fn with_hook(mut self, hook: FenceHook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// ⟨M08 W4 U2b-3a; test seam⟩ The cap's numbers, smaller than production's, so a test can
    /// go past them.
    #[doc(hidden)]
    #[must_use]
    pub fn with_limits(mut self, limits: LedgerLimits) -> Self {
        self.limits = limits;
        self
    }

    /// ⟨M08 W4 U2b-3a; test seam⟩ Every byte this fence has read from the request ledger: the
    /// bound test's cost proxy for an append.
    #[doc(hidden)]
    #[must_use]
    pub fn ledger_bytes_read(&self) -> u64 {
        self.lock().ledger.bytes_read()
    }

    /// ⟨M08 W4 U2b-3a; test seam⟩ Run the trim now, as the next admitted request would after
    /// its interval. Returns how many entries it dropped.
    #[doc(hidden)]
    pub fn trim_now(&self) -> usize {
        let mut state = self.lock();
        self.trim_locked(&mut state)
    }

    /// The runtime's current restore epoch (reported in the hello).
    #[must_use]
    pub fn epoch(&self) -> RestoreEpoch {
        self.epoch
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What every answer to `request`, from a frame that carried `frame_epoch`, reports: the
    /// request ID it carries and the epoch it is bound to, the frame's when present, else the
    /// current one (bound at receipt). `None` for a read, which carries no epoch and is not
    /// stamped.
    #[must_use]
    pub fn binding(&self, request: &Request, frame_epoch: Option<RestoreEpoch>) -> Option<Stamp> {
        request.is_effectful().then(|| Stamp {
            request_id: request.request_id().cloned(),
            epoch: frame_epoch.unwrap_or(self.epoch),
        })
    }

    /// ⟨M08 W4 U2b-3a⟩ The digest `request`'s terminal record is kept under when it completes
    /// ([`Self::record_terminal`]): a request with a request ID that the journal does not hold,
    /// which is every M06 request-ID kind (`remote_environment.invite`, `runner_local.*`,
    /// `route.add` and `route.prefer`, `transport.enable` and `transport.adopt_roost`) and
    /// `release`. `None` for a journaled request (its operation is its record), a read, and a
    /// request without an ID.
    #[must_use]
    pub fn terminal_key(&self, caller: &CallerContext, request: &Request) -> Option<[u8; 32]> {
        if request.admission() != Admission::Synchronous {
            return None;
        }
        let id = request.request_id()?;
        ledger_digest(caller, request.kind(), id).ok()
    }

    /// ⟨M08 W4 U2b-3a⟩ Record that the request keyed `digest` ([`Self::terminal_key`])
    /// completed at `now`: its answer was a success. A restore then counts it as a terminal
    /// record and replays a retry instead of fencing it, and the trim may drop its ledger entry
    /// once `retention` and the 30-day marker window have passed (ADR-0006 §7.4). A failure is
    /// logged: without the record a restore fences the key, so nothing runs twice.
    pub async fn record_terminal(
        self: &Arc<Self>,
        digest: [u8; 32],
        now: heimdall_contract::Timestamp,
        retention: Duration,
    ) {
        let this = Arc::clone(self);
        let written = tokio::task::spawn_blocking(move || {
            let trim_after = heimdall_domain::idempotency::marker_until(
                heimdall_domain::idempotency::retention_expiry(now, retention),
            );
            this.store
                .transaction(|tx| tx.record_request_terminal(&digest, now, trim_after))
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            tracing::warn!(
                "a completed request's terminal record was not written; a restore fences its key"
            );
        }
    }

    /// The check of one request from `caller`, whose frame carried `frame_epoch` (module docs),
    /// made after the request's role checks and uninstall-fence admission. `Ok(None)`: a read,
    /// which carries no epoch and is not checked. `Ok(Some(stamp))`: a mutating request
    /// admitted, its ledger entry durable; its answers carry `stamp` (its
    /// [`Self::binding`]).
    ///
    /// # Errors
    /// The answer that refuses the request, with nothing run: `REQUEST_STALE`,
    /// `DECISION_STALE`, `REQUEST_EXPIRED`, `BACKPRESSURE` or `STATE_UNAVAILABLE`, each stamped.
    /// A request a test hook stopped is answered `INTERNAL_ERROR` (debug test seam only).
    pub async fn admit(
        self: &Arc<Self>,
        caller: &CallerContext,
        request: &Request,
        frame_epoch: Option<RestoreEpoch>,
        now: heimdall_contract::Timestamp,
    ) -> Result<Option<Stamp>, Refusal> {
        let Some(stamp) = self.binding(request, frame_epoch) else {
            return Ok(None);
        };
        // Step 3: the epoch, before anything is read or written.
        if stamp.epoch != self.epoch {
            return Err(stamped(
                OpError::new(
                    Code::RequestStale,
                    "this request was minted under an earlier restore epoch: the state was \
                     restored since. It is never run; send a new request with a new request ID \
                     after a fresh hello",
                )
                .with_reason(reason::RESTORE_EPOCH_STALE)
                .with_effect(EffectStatus::None),
                &stamp,
            ));
        }
        // From here the stamp's epoch is the current one.
        let digest = match &stamp.request_id {
            Some(id) => match ledger_digest(caller, request.kind(), id) {
                Ok(d) => Some(d),
                Err(_) => {
                    return Err(stamped(
                        internal("the request key cannot be encoded"),
                        &stamp,
                    ));
                }
            },
            None => None,
        };
        let decision = match request {
            Request::Decide(d) => Some(d.decision_id.clone()),
            _ => None,
        };
        let journaled = matches!(request.admission(), Admission::Journaled(_));
        let this = Arc::clone(self);
        let who = caller.clone();
        let checked = tokio::task::spawn_blocking(move || {
            this.check_blocking(&who, digest, journaled, decision, now)
        })
        .await
        .unwrap_or_else(|_| Err(internal("the request check did not finish")));
        let appended = match checked {
            Ok(appended) => appended,
            Err(e) => return Err(stamped(e, &stamp)),
        };
        if appended
            && let Some(hook) = &self.hook
            && hook(FencePoint::AfterLedgerAppend)
        {
            return Err(stamped(internal("stopped by a test hook"), &stamp));
        }
        Ok(Some(stamp))
    }

    /// The store reads and the ledger append of [`Self::admit`] (blocking I/O). `Ok(true)`: an
    /// entry was appended for this request; `Ok(false)`: none was needed (no request ID, or
    /// the key already has one).
    fn check_blocking(
        &self,
        caller: &CallerContext,
        digest: Option<[u8; 32]>,
        journaled: bool,
        decision: Option<heimdall_contract::ids::DecisionId>,
        now: heimdall_contract::Timestamp,
    ) -> Result<bool, OpError> {
        // Step 2: a decision reference minted under another epoch is stale.
        if let Some(id) = decision {
            let minted = self
                .store
                .transaction(|tx| tx.decision_restore_epoch(&id))
                .map_err(|_| state_unavailable())?;
            if minted.is_some_and(|e| e != self.epoch) {
                return Err(OpError::new(
                    Code::DecisionStale,
                    "this decision was raised before the state was restored: it can no longer \
                     be approved or denied",
                )
                .with_reason(reason::RESTORE_EPOCH_STALE)
                .with_effect(EffectStatus::None));
            }
        }
        let Some(digest) = digest else {
            return Ok(false);
        };
        // One request at a time from here: the trim, the lookup and the append.
        let mut state = self.lock();
        if state.last_trim.is_none_or(|t| t.elapsed() >= TRIM_INTERVAL) {
            self.trim_locked(&mut state);
        }
        // Step 4, lookup: a fenced key is never run.
        let fence = self
            .store
            .transaction(|tx| tx.request_fence(&digest))
            .map_err(|_| state_unavailable())?;
        if let Some(fence) = fence {
            match fence.verdict(now) {
                FenceVerdict::Answer(detail) => return Err(OpError::from_detail(*detail, None)),
                FenceVerdict::Expired => {
                    return Err(OpError::new(
                        Code::RequestExpired,
                        "this request ID's record has aged out; it is not run again. Send a \
                         new request with a new request ID",
                    )
                    .with_effect(EffectStatus::None));
                }
                FenceVerdict::Lapsed => {}
            }
        }
        // Step 4, append: deduplicated by the digest, bounded by the cap, and durable before
        // the request reaches the application.
        let known = state
            .index()
            .map_err(|e| ledger_refusal(&e))?
            .keys
            .contains_key(&digest);
        if known {
            self.keep_entry(digest, journaled, now)?;
            return Ok(false);
        }
        if state
            .index()
            .is_ok_and(|i| i.full_for(caller, &self.limits))
        {
            // Room comes only from entries whose window has ended: never by eviction.
            self.trim_locked(&mut state);
            if state
                .index()
                .is_ok_and(|i| i.full_for(caller, &self.limits))
            {
                return Err(ledger_full());
            }
        }
        let entry = Entry {
            epoch: self.epoch.0,
            digest,
        };
        let expected = state.index().map_err(|e| ledger_refusal(&e))?.len;
        let len = match state.ledger.append_at(entry, expected) {
            Ok(Some(len)) => len,
            Ok(None) => {
                // A length this runtime did not leave: read the ledger whole again (the
                // damaged-ledger check), then append as before.
                // A reload that fails leaves no index: every append is refused until the
                // ledger reads whole again.
                let index = state.reload().map_err(|e| ledger_refusal(&e))?;
                if index.keys.contains_key(&digest) {
                    self.keep_entry(digest, journaled, now)?;
                    return Ok(false);
                }
                if index.full_for(caller, &self.limits) {
                    return Err(ledger_full());
                }
                state.ledger.append(entry).map_err(|e| {
                    if !matches!(e, LedgerError::Io { .. }) {
                        state.index = None;
                    }
                    ledger_refusal(&e)
                })?
            }
            Err(e) => {
                if !matches!(e, LedgerError::Io { .. }) {
                    state.index = None;
                }
                return Err(ledger_refusal(&e));
            }
        };
        let index = state.index().map_err(|e| ledger_refusal(&e))?;
        index.len = len;
        index.insert(digest, Sharer::of(caller));
        Ok(true)
    }

    /// A request with this key was admitted on its existing entry: a terminal record whose
    /// window has ended must not let the trim drop the entry now
    /// (`heimdall_store::Txn::touch_request_terminal`).
    fn keep_entry(
        &self,
        digest: [u8; 32],
        journaled: bool,
        now: heimdall_contract::Timestamp,
    ) -> Result<(), OpError> {
        let extend_to = heimdall_domain::idempotency::marker_until(
            heimdall_domain::idempotency::retention_expiry(
                now,
                heimdall_domain::idempotency::DEFAULT_RETENTION,
            ),
        );
        self.store
            .transaction(|tx| tx.touch_request_terminal(&digest, journaled, now, extend_to))
            .map_err(|_| state_unavailable())
    }

    /// The trim (module docs), with the ledger held: drop the entries whose terminal records
    /// the retention pass marked trimmable, then remove those records. Returns how many
    /// entries were dropped. A failure changes nothing durable that matters: the records stay
    /// for the next trim, and a ledger found damaged refuses every append.
    fn trim_locked(&self, state: &mut LedgerState) -> usize {
        state.last_trim = Some(Instant::now());
        if state.index.is_none() {
            return 0;
        }
        let trimmable = match self
            .store
            .transaction(|tx| tx.trimmable_request_terminals())
        {
            Ok(t) if !t.is_empty() => t,
            Ok(_) => return 0,
            Err(_) => {
                tracing::warn!("the request ledger's trim could not read the terminal records");
                return 0;
            }
        };
        let ended: HashSet<[u8; 32]> = trimmable.iter().copied().collect();
        let mut dropped = 0;
        if let Some(index) = &state.index
            && ended.iter().any(|d| index.keys.contains_key(d))
        {
            match state.ledger.trim_entries(|e| ended.contains(&e.digest)) {
                Ok(trimmed) => {
                    if let Some(index) = state.index.as_mut() {
                        index.len = trimmed.len;
                        for entry in &trimmed.dropped {
                            index.remove(&entry.digest);
                        }
                    }
                    dropped = trimmed.dropped.len();
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the request ledger could not be trimmed");
                    // An I/O error leaves the ledger whole before or after the rename: read
                    // it again (a reload that fails leaves no index). Damage refuses every
                    // append until the ledger reads whole.
                    if matches!(e, LedgerError::Io { .. }) {
                        let _ = state.reload();
                    } else {
                        state.index = None;
                    }
                    return 0;
                }
            }
        }
        if self
            .store
            .transaction(|tx| tx.remove_trimmed_request_terminals(&trimmable))
            .is_err()
        {
            tracing::warn!(
                "the trimmed keys' terminal records were not removed; the next trim does"
            );
        }
        dropped
    }
}

/// The refusal of a request the ledger could not take.
fn ledger_refusal(e: &LedgerError) -> OpError {
    match e {
        LedgerError::Damaged(_) | LedgerError::Unreadable => OpError::new(
            Code::StateUnavailable,
            "the request ledger is damaged, so no request that changes anything can be \
             accepted: repair it at this machine with `heimdall state repair`",
        )
        .with_reason(reason::LEDGER_DAMAGED)
        .with_next(NextAction {
            action: "owner_decision".to_owned(),
            ..NextAction::default()
        })
        .with_effect(EffectStatus::None),
        LedgerError::Io { .. } => OpError::new(
            Code::StateUnavailable,
            "the request ledger could not be written: nothing was run",
        )
        .with_resource("store", None)
        .with_effect(EffectStatus::None),
    }
}

/// ⟨M08 W4 U2b-3a⟩ The cap's refusal (module docs): `BACKPRESSURE`, effect `none`, next
/// `retry_after`.
fn ledger_full() -> OpError {
    OpError::new(
        Code::Backpressure,
        "the request ledger holds as many unsettled request IDs from this caller as it accepts: \
         nothing was run. Retry later, as earlier requests settle and age out; a retry of a \
         request ID already sent is still answered",
    )
    .with_retry_after(LEDGER_FULL_RETRY_AFTER_MS)
    .with_effect(EffectStatus::None)
}

fn internal(message: &str) -> OpError {
    OpError::new(Code::InternalError, message.to_owned()).with_effect(EffectStatus::None)
}

fn state_unavailable() -> OpError {
    OpError::new(Code::StateUnavailable, "state store unavailable")
        .with_resource("store", None)
        .with_effect(EffectStatus::None)
}

/// `e` as a wire envelope that reports `stamp`.
fn stamped(e: OpError, stamp: &Stamp) -> Refusal {
    let mut env = e
        .into_envelope()
        .map(|d: ErrorData| serde_json::to_value(d).unwrap_or_default());
    stamp.apply(&mut env);
    Box::new(env)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_domain::principal::ClientRole;

    fn req(v: serde_json::Value) -> Request {
        serde_json::from_value(v).unwrap()
    }

    /// ⟨M08 W4 U2b-3a⟩ Which requests get a terminal record when they complete: every request
    /// with a request ID that the journal does not hold (M06's request-ID kinds of every family,
    /// and `release` given one), keyed by the ledger's digest of the caller's full key; none
    /// for a journaled request (its operation is its record), a request without an ID, or a
    /// read. The end-to-end cases (`integration_request_epoch`) run one kind of each family
    /// through this one classification.
    #[test]
    fn terminal_keys_are_the_request_id_kinds_the_journal_does_not_hold() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        let fence = RequestFence::open(store, dir.path()).unwrap();
        let caller = CallerContext::local(PrincipalRef::UnixUser { uid: 501 }, ClientRole::Owner);
        let client = ClientId::from_random_bytes([1; 16]);
        let ca =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ca";
        let terminal = [
            serde_json::json!({"op": "remote_environment", "action": "invite",
                "environment": "env_00112233445566778899aabbccddeeff", "role": "requester",
                "key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "public_key": "ssh-ed25519 AAAA", "request_id": "r-1"}),
            serde_json::json!({"op": "runner_local", "action": "trust_issuer",
                "controller": client, "ca_public_key": ca, "request_id": "r-2"}),
            serde_json::json!({"op": "runner_local", "action": "designate_time_source",
                "client": client, "request_id": "r-3"}),
            serde_json::json!({"op": "runner_local", "action": "enroll_owner",
                "client": client, "public_key": ca, "request_id": "r-4"}),
            serde_json::json!({"op": "runner_local", "action": "policy_recheck",
                "request_id": "r-5"}),
            serde_json::json!({"op": "route", "action": "add", "destination": "lab",
                "route": {"kind": "direct", "host": "127.0.0.2"}, "request_id": "r-6"}),
            serde_json::json!({"op": "route", "action": "prefer", "destination": "lab",
                "route": "route_00112233445566778899aabbccddeeff", "request_id": "r-7"}),
            serde_json::json!({"op": "transport", "action": "enable", "request_id": "r-8"}),
            serde_json::json!({"op": "transport", "action": "adopt_roost",
                "destination": "lab", "endpoint": "ab".repeat(32), "request_id": "r-9"}),
            serde_json::json!({"op": "release",
                "binding_id": "binding_00112233445566778899aabbccddeeff", "request_id": "r-10"}),
        ];
        let mut families = std::collections::BTreeSet::new();
        for value in terminal {
            let request = req(value);
            let key = fence.terminal_key(&caller, &request);
            let id = request.request_id().unwrap();
            assert_eq!(
                key,
                Some(ledger_digest(&caller, request.kind(), id).unwrap()),
                "{}",
                request.kind()
            );
            families.insert(request.kind().split('.').next().unwrap().to_owned());
        }
        assert_eq!(
            families.into_iter().collect::<Vec<_>>(),
            [
                "release",
                "remote_environment",
                "route",
                "runner_local",
                "transport"
            ]
        );
        let none = [
            // Journaled: the operation is the record.
            serde_json::json!({"op": "revoke", "grant_id": "grant_00112233445566778899aabbccddeeff",
                "request_id": "r-11"}),
            serde_json::json!({"op": "delegate",
                "parent_binding_id": "binding_00112233445566778899aabbccddeeff",
                "scope": [], "work_id": "w", "request_id": "r-12"}),
            // No request ID.
            serde_json::json!({"op": "release",
                "binding_id": "binding_00112233445566778899aabbccddeeff"}),
            serde_json::json!({"op": "transport", "action": "disable"}),
            serde_json::json!({"op": "policy", "action": "pause", "policy_id": "pol"}),
            // A read.
            serde_json::json!({"op": "inspect", "subject": "bindings"}),
        ];
        for value in none {
            let request = req(value);
            assert_eq!(
                fence.terminal_key(&caller, &request),
                None,
                "{}",
                request.kind()
            );
        }
    }
}
