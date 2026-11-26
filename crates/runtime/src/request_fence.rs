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
//! **Not here:** the ledger's trim. Entries are kept (ADR-0006 §7.4 lets a trim drop an entry
//! only after its settled key's marker window, and an entry whose settlement is not known is
//! kept), and the ledger is read whole at each append for the damaged-ledger check, so its
//! cost grows with it. The trim waits for U2b-3 (it needs each entry's settlement, which the
//! store keeps under another key hash once the idempotency record is purged).

use std::path::Path;
use std::sync::{Arc, Mutex};

use heimdall_app::OpError;
use heimdall_contract::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData, NextAction, reason};
use heimdall_contract::ids::RequestId;
use heimdall_contract::lifecycle::RestoreEpoch;
use heimdall_contract::request::Request;
use heimdall_domain::principal::CallerContext;
use heimdall_store::Store;
use heimdall_store::fence::{FenceVerdict, ledger_digest};
use heimdall_store::layout::stategen::ledger::{Entry, Ledger, LedgerError};

use crate::state_store::PlatformFs;

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

/// The server's epoch check, replay fence and request ledger (module docs).
pub struct RequestFence {
    store: Arc<Store>,
    ledger: Mutex<Ledger<PlatformFs>>,
    epoch: RestoreEpoch,
    hook: Option<FenceHook>,
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
    /// ledger lives there, outside every generation). The current epoch is read now.
    ///
    /// # Errors
    /// The store's refusal: a missing or malformed epoch is `state_corrupt`.
    pub fn open(store: Arc<Store>, state_dir: &Path) -> Result<Self, heimdall_store::StoreError> {
        let epoch = store.transaction(|tx| tx.restore_epoch())?;
        Ok(Self {
            ledger: Mutex::new(Ledger::new(PlatformFs, state_dir)),
            store,
            epoch,
            hook: None,
        })
    }

    /// ⟨test seam⟩ Stop admitted requests at the points `hook` says.
    #[doc(hidden)]
    #[must_use]
    pub fn with_hook(mut self, hook: FenceHook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// The runtime's current restore epoch (reported in the hello).
    #[must_use]
    pub fn epoch(&self) -> RestoreEpoch {
        self.epoch
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

    /// The check of one request from `caller`, whose frame carried `frame_epoch` (module docs),
    /// made after the request's role checks and uninstall-fence admission. `Ok(None)`: a read,
    /// which carries no epoch and is not checked. `Ok(Some(stamp))`: a mutating request
    /// admitted, its ledger entry durable; its answers carry `stamp` (its
    /// [`Self::binding`]).
    ///
    /// # Errors
    /// The answer that refuses the request, with nothing run: `REQUEST_STALE`,
    /// `DECISION_STALE`, `REQUEST_EXPIRED` or `STATE_UNAVAILABLE`, each stamped. A request a
    /// test hook stopped is answered `INTERNAL_ERROR` (debug test seam only).
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
        let this = Arc::clone(self);
        let checked =
            tokio::task::spawn_blocking(move || this.check_blocking(digest, decision, now))
                .await
                .unwrap_or_else(|_| Err(internal("the request check did not finish")));
        if let Err(e) = checked {
            return Err(stamped(e, &stamp));
        }
        if digest.is_some()
            && let Some(hook) = &self.hook
            && hook(FencePoint::AfterLedgerAppend)
        {
            return Err(stamped(internal("stopped by a test hook"), &stamp));
        }
        Ok(Some(stamp))
    }

    /// The store reads and the ledger append of [`Self::admit`] (blocking I/O).
    fn check_blocking(
        &self,
        digest: Option<[u8; 32]>,
        decision: Option<heimdall_contract::ids::DecisionId>,
        now: heimdall_contract::Timestamp,
    ) -> Result<(), OpError> {
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
            return Ok(());
        };
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
        // Step 4, append: durable before the request reaches the application.
        let entry = Entry {
            epoch: self.epoch.0,
            digest,
        };
        let ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ledger.append(entry).map_err(|e| match e {
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
        })
    }
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
