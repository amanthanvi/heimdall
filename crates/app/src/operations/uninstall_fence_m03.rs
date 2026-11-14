//! ⟨M03; ADR-0008 §17.27 item 2, §17.28 item 1 (W5-S01), §17.31 item 2 (W5-C02)⟩ The
//! uninstall fence: while one control connection holds it, every **other**
//! connection's request that can start or advance remote or CA work is refused
//! `SERVICE_UNAVAILABLE`, reason `uninstall_in_progress`
//! (`heimdall_contract::request::UninstallFenceRequest`).
//!
//! **The boundary** (§17.31 item 2). One admission, [`Operations::uninstall_fence_admit`],
//! is taken by every piece of work that starts or advances remote or CA work, and held
//! until that work ends:
//! * the dispatcher, for each fenced request ([`fenced`]) from a connection that is not
//!   the holder (`heimdall_runtime::dispatch`; the request-to-verdict table is in
//!   `.m03-wave5-r3-api.md` § U3);
//! * the application routes themselves, so a caller that is not the dispatcher meets
//!   the same check: `Operations::enrollment_request` and `Operations::issuer_request`
//!   for their fenced actions ([`Operations::enrollment_fence_admission`],
//!   [`Operations::issuer_fence_admission`]) and `Operations::decide` for an approval;
//! * the supervisor passes that reserve or dispatch (`Operations::managed_reissue_pass`,
//!   the re-verification pass), which do nothing while it is refused;
//! * the deferred follow-through of a step result (initial verification): the result
//!   is recorded, and the follow-through runs only when admitted (otherwise the next
//!   `enroll step` or `enroll reconcile` after the fence is lifted runs it).
//!
//! Both **reservations** (`Operations::reserve_issuance_with`, the one choke point of
//! a grant certificate, and `Operations::reserve_verification`) take their own
//! admission ([`Operations::fence_admit_reservation`]) before their check and hold it
//! across their store write, so a reservation past its check is never overtaken by an
//! acquisition: the acquisition waits for it, or the reservation is refused.
//!
//! The holder's own work runs inside [`as_fence_holder`] and is never refused.
//!
//! **Serialization.** `acquire` first marks the fence as being acquired: from then on
//! new work ([`Operations::uninstall_fence_admit`]) is refused. It then waits (bounded by
//! [`ACQUIRE_WAIT`]) until no admission is held, and takes the fence in the same
//! critical section that observed none. A reservation may still join while the fence
//! is being acquired (it is nested inside admitted work, or is a single bounded store
//! write) and the acquisition waits for it too; once the fence is held every
//! reservation outside the holder's scope is refused. An admission never waits, so
//! nested admissions cannot deadlock against an acquisition. An inventory read after
//! `acquire` therefore sees every obligation admitted before it.
//!
//! **Revalidation input.** [`unresolved_remote_steps`]: the enrollment operations with
//! a dispatched step whose result is not recorded, or whose remote effect is unknown.
//!
//! **Lifetime** (held by one connection, identified by the runtime's dispatcher):
//! released by `release` on that connection, when that connection ends for any reason
//! (the dispatcher's per-connection guard), and with the runtime (it is never stored).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use heimdall_contract::Code;
use heimdall_contract::enrollment::EnrollmentRequest;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::OperationId;
use heimdall_contract::issuer::IssuerRequest;
use heimdall_contract::request::{Request, Verdict};
use heimdall_store::Txn;

use super::Operations;
use crate::error::OpError;

/// How long `acquire` waits for admitted work to end.
pub const ACQUIRE_WAIT: Duration = Duration::from_secs(20);

/// The fence's state (one per runtime, in `Operations`).
#[derive(Debug, Default)]
pub(crate) struct UninstallFence {
    state: Mutex<FenceState>,
    /// Woken when the last admission ends, or the fence is taken.
    changed: tokio::sync::Notify,
    /// ⟨debug builds only⟩ The next reservation's pause after its check
    /// ([`Operations::debug_pause_next_reservation`]).
    #[cfg(debug_assertions)]
    pause: Mutex<Option<ReservationPause>>,
    /// ⟨debug builds only⟩ Refuse the next reservation as fenced
    /// ([`Operations::debug_refuse_next_reservation`]).
    #[cfg(debug_assertions)]
    refuse_next: std::sync::atomic::AtomicBool,
    /// ⟨debug builds only⟩ The next reservation's pause inside its blocking store write
    /// ([`Operations::debug_pause_next_reservation_write`]).
    #[cfg(debug_assertions)]
    write_pause: Mutex<Option<ReservationPause>>,
    /// ⟨debug builds only⟩ The next managed pipeline's pause before it signs
    /// ([`Operations::debug_pause_next_sign`]).
    #[cfg(debug_assertions)]
    sign_pause: Mutex<Option<ReservationPause>>,
}

#[derive(Debug, Default)]
struct FenceState {
    /// The holding connection, if any.
    holder: Option<u64>,
    /// Admissions held now (work past its check that has not ended).
    admitted: usize,
    /// Acquisitions waiting for the admissions to end.
    acquiring: usize,
    /// ⟨§17.32 item 3⟩ The admissions held per task (the task that took them), so a
    /// store write that task starts carries its own counted extension
    /// ([`UninstallFence::write_extension`]).
    tasks: std::collections::HashMap<tokio::task::Id, usize>,
}

tokio::task_local! {
    /// Set while the holder's own request is handled ([`as_fence_holder`]).
    static FENCE_HOLDER: ();
}

/// Run `f` as the fence holder's request: the checks in this crate never refuse it.
/// (Work it spawns runs outside this scope, as any background work.)
pub async fn as_fence_holder<F: std::future::Future>(f: F) -> F::Output {
    FENCE_HOLDER.scope((), f).await
}

fn in_holder_scope() -> bool {
    FENCE_HOLDER.try_with(|()| ()).is_ok()
}

/// The refusal of fenced work (`SERVICE_UNAVAILABLE`, `uninstall_in_progress`, effect
/// `none`).
#[must_use]
pub fn uninstall_in_progress() -> OpError {
    OpError::new(
        Code::ServiceUnavailable,
        "an uninstall is in progress: no new or continued enrollment, CA or issuance work, and no approval, is admitted until it ends",
    )
    .with_reason(reason::UNINSTALL_IN_PROGRESS)
    .with_effect(EffectStatus::None)
}

/// ⟨ADR-0008 §17.27 item 2, §17.28 item 1⟩ Whether `request` can start or advance
/// remote or CA work, so that the uninstall fence refuses it from any connection but
/// the holder:
/// * fenced: `enrollment` `apply`, `verify`, `remove` (own and foreign), `reconcile`,
///   `abandon` and `step` (dispatching a remote step); `issuer` `register` (rotation
///   and restore included), `unlock` and `retire` (with or without `deleted_locator`);
///   `decide` with `approve`, whatever the kind;
/// * not fenced: every read-only request (`inspect`, `observe`, the previews, `issuer`
///   `status` and `bundle`), `decide` with `deny`, `enrollment` `step_result` (a step
///   dispatched before the fence records its truth; its follow-through is deferred),
///   `issuer` `bundle_written`, and every M01/M02 request (`ensure` and `bind` reach a
///   certificate only through the reservation, which is refused itself while the fence
///   is held). An unknown action is fenced (fail closed).
#[must_use]
pub fn fenced(request: &Request) -> bool {
    match request {
        Request::Enrollment(r) => enrollment_fenced(r),
        Request::Issuer(r) => issuer_fenced(r),
        Request::Decide(r) => r.verdict != Verdict::Deny,
        _ => false,
    }
}

fn enrollment_fenced(r: &EnrollmentRequest) -> bool {
    !matches!(
        r,
        EnrollmentRequest::Preview { .. } | EnrollmentRequest::StepResult { .. }
    )
}

fn issuer_fenced(r: &IssuerRequest) -> bool {
    !matches!(
        r,
        IssuerRequest::Status | IssuerRequest::Bundle { .. } | IssuerRequest::BundleWritten { .. }
    )
}

/// What [`Operations::uninstall_fence_acquire`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FenceAcquired {
    /// This connection now holds it (or already did).
    Held,
}

impl UninstallFence {
    fn state(&self) -> MutexGuard<'_, FenceState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn holder(&self) -> Option<u64> {
        self.state().holder
    }

    /// ⟨§17.32 item 3⟩ For a store write started by a task that holds an admission: a
    /// further counted admission, which the write's blocking closure owns until the
    /// transaction has committed or rolled back. So cancelling the task's future (and
    /// dropping its admission) never lets an acquisition complete while that write is
    /// queued or running. `None` outside a task, for a task holding none, and in the
    /// holder's scope.
    pub(crate) fn write_extension(self: &Arc<Self>) -> Option<FenceAdmission> {
        if in_holder_scope() {
            return None;
        }
        let task = tokio::task::try_id()?;
        let mut s = self.state();
        if s.tasks.get(&task).copied().unwrap_or(0) == 0 {
            return None;
        }
        s.admitted += 1;
        Some(FenceAdmission {
            fence: Some(Arc::clone(self)),
            task: None,
        })
    }

    /// ⟨debug builds only⟩ The pause the next admitted reservation write takes.
    #[cfg(debug_assertions)]
    pub(crate) fn take_write_pause(&self) -> Option<ReservationPause> {
        self.write_pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// Held by admitted work from its check until it ends: an acquisition waits for every
/// one to be dropped. The holder's scope gets one that counts nothing.
#[must_use = "the admission covers the work only while it is held"]
#[derive(Debug)]
pub struct FenceAdmission {
    fence: Option<Arc<UninstallFence>>,
    /// The task that took it (counted in `FenceState::tasks`), if any.
    task: Option<tokio::task::Id>,
}

impl FenceAdmission {
    fn none() -> Self {
        Self {
            fence: None,
            task: None,
        }
    }
}

impl Drop for FenceAdmission {
    fn drop(&mut self) {
        if let Some(fence) = self.fence.take() {
            let last = {
                let mut s = fence.state();
                s.admitted = s.admitted.saturating_sub(1);
                if let Some(task) = self.task
                    && let Some(n) = s.tasks.get_mut(&task)
                {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        s.tasks.remove(&task);
                    }
                }
                s.admitted == 0
            };
            if last {
                fence.changed.notify_waiters();
            }
        }
    }
}

/// Counts an acquisition in progress until it ends (taken, refused, timed out or
/// dropped).
struct Acquiring<'a>(&'a UninstallFence);

impl Drop for Acquiring<'_> {
    fn drop(&mut self) {
        let mut s = self.0.state();
        s.acquiring = s.acquiring.saturating_sub(1);
    }
}

/// ⟨debug builds only⟩ A reservation's pause after its fence check, before its store
/// write ([`Operations::debug_pause_next_reservation`]).
#[cfg(debug_assertions)]
#[derive(Debug)]
pub struct ReservationPause {
    reached: tokio::sync::oneshot::Sender<()>,
    resume: tokio::sync::oneshot::Receiver<()>,
}

#[cfg(debug_assertions)]
impl ReservationPause {
    /// On the blocking pool: signal `reached`, then wait for `resume` (or its drop).
    pub(crate) fn block(self) {
        let _ = self.reached.send(());
        let _ = self.resume.blocking_recv();
    }
}

/// ⟨debug builds only⟩ The test's side of a [`ReservationPause`].
#[cfg(debug_assertions)]
#[derive(Debug)]
pub struct ReservationPauseControl {
    /// Completes when the reservation has passed its check.
    pub reached: tokio::sync::oneshot::Receiver<()>,
    /// Send (or drop) to let it continue to its store write.
    pub resume: tokio::sync::oneshot::Sender<()>,
}

/// Whether new work may start now, or only a reservation may join.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// New work: refused while the fence is held or being acquired.
    Work,
    /// A reservation: refused while the fence is held; joins while it is being acquired.
    Reservation,
}

impl Operations {
    fn fence_admit(&self, kind: Admit) -> Result<FenceAdmission, OpError> {
        if in_holder_scope() {
            return Ok(FenceAdmission::none());
        }
        let fence = &self.inner.uninstall_fence;
        let mut s = fence.state();
        if s.holder.is_some() || (kind == Admit::Work && s.acquiring > 0) {
            return Err(uninstall_in_progress());
        }
        s.admitted += 1;
        let task = tokio::task::try_id();
        if let Some(t) = task {
            *s.tasks.entry(t).or_insert(0) += 1;
        }
        Ok(FenceAdmission {
            fence: Some(Arc::clone(fence)),
            task,
        })
    }

    /// ⟨§17.31 item 2⟩ The admission of work that starts or advances remote or CA work
    /// (module docs): refused while the fence is held or being acquired, unless it runs
    /// in the holder's scope; held until the work ends. Never waits.
    ///
    /// # Errors
    /// `SERVICE_UNAVAILABLE` / `uninstall_in_progress`, effect `none`.
    pub fn uninstall_fence_admit(&self) -> Result<FenceAdmission, OpError> {
        self.fence_admit(Admit::Work)
    }

    /// [`Self::uninstall_fence_admit`] for an `enrollment` request whose action is
    /// fenced ([`fenced`]); the other actions get an admission that counts nothing.
    ///
    /// # Errors
    /// As [`Self::uninstall_fence_admit`].
    pub fn enrollment_fence_admission(
        &self,
        req: &EnrollmentRequest,
    ) -> Result<FenceAdmission, OpError> {
        if enrollment_fenced(req) {
            self.uninstall_fence_admit()
        } else {
            Ok(FenceAdmission::none())
        }
    }

    /// [`Self::uninstall_fence_admit`] for an `issuer` request whose action is fenced
    /// ([`fenced`]); the other actions get an admission that counts nothing.
    ///
    /// # Errors
    /// As [`Self::uninstall_fence_admit`].
    pub fn issuer_fence_admission(&self, req: &IssuerRequest) -> Result<FenceAdmission, OpError> {
        if issuer_fenced(req) {
            self.uninstall_fence_admit()
        } else {
            Ok(FenceAdmission::none())
        }
    }

    /// ⟨§17.31 item 2⟩ A certificate reservation's admission, taken before its check and
    /// held across its store write: refused while the fence is held (unless it runs in
    /// the holder's scope); while the fence is being acquired it joins, and the
    /// acquisition waits for it.
    pub(crate) async fn fence_admit_reservation(&self) -> Result<FenceAdmission, OpError> {
        #[cfg(debug_assertions)]
        if self
            .inner
            .uninstall_fence
            .refuse_next
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(uninstall_in_progress());
        }
        let admission = self.fence_admit(Admit::Reservation)?;
        #[cfg(debug_assertions)]
        self.debug_reservation_pause().await;
        Ok(admission)
    }

    /// ⟨debug builds only; tests; ADR-0008 §17.31 item 8⟩ Refuse the next certificate
    /// reservation (grant or verification) as fenced (`uninstall_in_progress`), as if an
    /// uninstall had taken the fence just before it: the only way to reach that refusal
    /// now that every route into verification holds an admission. Release builds have
    /// no such hook.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn debug_refuse_next_reservation(&self) {
        self.inner
            .uninstall_fence
            .refuse_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// ⟨§17.28 item 1, §17.31 item 2; round-10 audit A1⟩ The admission of one managed
    /// issuance pipeline (`managed::driver::run_stages`: key, reserve, sign, publish,
    /// install, materialize), held for the whole pipeline so an acquisition waits for
    /// in-flight issuance and no step of it runs under a held fence. Inside admitted
    /// work (the re-issue pass) it extends that admission; otherwise (the ensure's
    /// spawned lead) it is new work, refused while the fence is held or being acquired.
    ///
    /// # Errors
    /// As [`Self::uninstall_fence_admit`].
    pub(crate) fn fence_admit_pipeline(&self) -> Result<FenceAdmission, OpError> {
        if in_holder_scope() {
            return Ok(FenceAdmission::none());
        }
        match self.inner.uninstall_fence.write_extension() {
            Some(extension) => Ok(extension),
            None => self.fence_admit(Admit::Work),
        }
    }

    /// ⟨debug builds only; tests⟩ Pause the next managed pipeline after its
    /// reservation, before it signs, until the returned control's `resume` is sent or
    /// dropped. Release builds have no pause.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn debug_pause_next_sign(&self) -> ReservationPauseControl {
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        *self
            .inner
            .uninstall_fence
            .sign_pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(ReservationPause {
            reached: reached_tx,
            resume: resume_rx,
        });
        ReservationPauseControl { reached, resume }
    }

    #[cfg(debug_assertions)]
    pub(crate) async fn debug_sign_pause(&self) {
        let pause = self
            .inner
            .uninstall_fence
            .sign_pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(p) = pause {
            let _ = p.reached.send(());
            let _ = p.resume.await;
        }
    }

    /// ⟨§17.32 item 2; round-10 audit A1⟩ A publication's admission
    /// (`Operations::publish_issuance`): the same as a reservation's, but never
    /// refused. `None` while another connection holds the fence: then the publication
    /// is refused before it writes anything (publishing advances CA work); otherwise
    /// held through the publication's store write.
    pub(crate) fn fence_admit_publication(&self) -> Option<FenceAdmission> {
        self.fence_admit(Admit::Reservation).ok()
    }

    /// ⟨debug builds only; tests; §17.32 item 3⟩ Pause the next admitted reservation
    /// (grant or verification) **inside** its blocking store write, before the
    /// transaction begins, until the returned control's `resume` is sent or dropped
    /// (the caller's future may be cancelled meanwhile). Release builds have no pause.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn debug_pause_next_reservation_write(&self) -> ReservationPauseControl {
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        *self
            .inner
            .uninstall_fence
            .write_pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(ReservationPause {
            reached: reached_tx,
            resume: resume_rx,
        });
        ReservationPauseControl { reached, resume }
    }

    /// ⟨debug builds only; tests⟩ Pause the next certificate reservation (grant or
    /// verification) after its fence check, before its store write, until the returned
    /// control's `resume` is sent or dropped. Release builds have no pause.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn debug_pause_next_reservation(&self) -> ReservationPauseControl {
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = tokio::sync::oneshot::channel();
        *self
            .inner
            .uninstall_fence
            .pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(ReservationPause {
            reached: reached_tx,
            resume: resume_rx,
        });
        ReservationPauseControl { reached, resume }
    }

    #[cfg(debug_assertions)]
    async fn debug_reservation_pause(&self) {
        let pause = self
            .inner
            .uninstall_fence
            .pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(p) = pause {
            let _ = p.reached.send(());
            let _ = p.resume.await;
        }
    }

    /// The connection holding the uninstall fence, if any.
    #[must_use]
    pub fn uninstall_fence_holder(&self) -> Option<u64> {
        self.inner.uninstall_fence.holder()
    }

    /// Whether the uninstall fence is held (by any connection).
    #[must_use]
    pub fn uninstall_fence_held(&self) -> bool {
        self.uninstall_fence_holder().is_some()
    }

    /// `uninstall_fence.acquire` for `connection` (the dispatcher's per-connection
    /// identity): from now on new work is refused; waits (bounded by [`ACQUIRE_WAIT`])
    /// until every admission already held has ended, then holds the fence. Idempotent
    /// on the holding connection.
    ///
    /// # Errors
    /// `SERVICE_UNAVAILABLE` / `uninstall_in_progress` while another connection holds
    /// it, or when admitted work did not end in time (nothing changed).
    pub async fn uninstall_fence_acquire(&self, connection: u64) -> Result<FenceAcquired, OpError> {
        let fence = &self.inner.uninstall_fence;
        let other_holds = || {
            OpError::new(
                Code::ServiceUnavailable,
                "another uninstall holds the fence; nothing was changed",
            )
            .with_reason(reason::UNINSTALL_IN_PROGRESS)
        };
        {
            let mut s = fence.state();
            match s.holder {
                Some(h) if h != connection => return Err(other_holds()),
                Some(_) => return Ok(FenceAcquired::Held),
                None => s.acquiring += 1,
            }
        }
        let _acquiring = Acquiring(fence);
        let wait = async {
            loop {
                let mut changed = std::pin::pin!(fence.changed.notified());
                changed.as_mut().enable();
                {
                    let mut s = fence.state();
                    match s.holder {
                        Some(h) if h != connection => return Err(other_holds()),
                        Some(_) => return Ok(FenceAcquired::Held),
                        None if s.admitted == 0 => {
                            s.holder = Some(connection);
                            drop(s);
                            fence.changed.notify_waiters();
                            return Ok(FenceAcquired::Held);
                        }
                        None => {}
                    }
                }
                changed.await;
            }
        };
        match tokio::time::timeout(ACQUIRE_WAIT, wait).await {
            Ok(r) => r,
            Err(_) => Err(OpError::new(
                Code::ServiceUnavailable,
                "work being admitted did not settle in time, so the uninstall fence was not taken; nothing was changed",
            )
            .with_reason(reason::UNINSTALL_IN_PROGRESS)),
        }
    }

    /// `uninstall_fence.release` for `connection`, and the release when that
    /// connection ends: lifts the fence if `connection` holds it, else does nothing.
    /// Returns whether the fence is still held (by another connection).
    pub fn uninstall_fence_release(&self, connection: u64) -> bool {
        let mut s = self.inner.uninstall_fence.state();
        if s.holder == Some(connection) {
            s.holder = None;
        }
        s.holder.is_some()
    }

    /// ⟨ADR-0008 §17.32 item 7; Q-I-R10-1⟩ `uninstall_fence.retry_remote_revocations`
    /// for `connection`: **exactly one** [`Operations::retry_remote_revocation`] round
    /// per pending remote revocation record, in root order, before uninstall stops the
    /// runtime. Holder-only: refused unless `connection` holds the fence.
    ///
    /// The round is the supervisor's ordinary one, never a re-arm: it is claimed with
    /// `attempts + 1` only when an adapter call is owed (`claim_retry_round_in`), a
    /// `stopped` record is answered unchanged with no call, a record at its cap is
    /// marked `stopped` with no call, and nothing resets a count or lifts a stop. The cap
    /// is the one the supervisor configured ([`Operations::set_revocation_cap`]),
    /// passed unchanged, so the round is judged by each record's
    /// `PendingRemoteRevocation::round_cap` of it, as the supervisor's are.
    ///
    /// Returns, per record: what the round did and whether the record is still pending.
    ///
    /// # Errors
    /// `SERVICE_UNAVAILABLE` when `connection` does not hold the fence (reason
    /// `uninstall_in_progress` while another connection holds it; none when nobody
    /// does), nothing attempted; a store failure reading the records.
    pub async fn uninstall_fence_retry_remote_revocations(
        &self,
        connection: u64,
    ) -> Result<Vec<RemoteRetry>, OpError> {
        match self.uninstall_fence_holder() {
            Some(h) if h == connection => {}
            other => {
                let e = OpError::new(
                    Code::ServiceUnavailable,
                    "only the connection holding the uninstall fence may retry the pending remote revocations; nothing was attempted",
                )
                .with_effect(EffectStatus::None);
                return Err(if other.is_some() {
                    e.with_reason(reason::UNINSTALL_IN_PROGRESS)
                } else {
                    e
                });
            }
        }
        let cap = self
            .inner
            .revocation_cap
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut out = Vec::new();
        for before in self.pending_remote_revocations().await? {
            let root = before.root.clone();
            let retry = match self.retry_remote_revocation(&root, cap).await {
                Ok(None) => RemoteRetry {
                    root_grant: root.to_string(),
                    outcome: RemoteRetryOutcome::Completed,
                    attempts_before: before.attempts,
                    attempts_after: before.attempts.saturating_add(1),
                    stopped: false,
                    pending: false,
                },
                Ok(Some(after)) => RemoteRetry {
                    root_grant: root.to_string(),
                    outcome: if after.attempts > before.attempts {
                        RemoteRetryOutcome::AttemptedStillPending
                    } else {
                        RemoteRetryOutcome::NotAttempted
                    },
                    attempts_before: before.attempts,
                    attempts_after: after.attempts,
                    stopped: after.stopped,
                    pending: true,
                },
                Err(_) => RemoteRetry {
                    root_grant: root.to_string(),
                    outcome: RemoteRetryOutcome::Failed,
                    attempts_before: before.attempts,
                    attempts_after: before.attempts,
                    stopped: before.stopped,
                    pending: true,
                },
            };
            out.push(retry);
        }
        Ok(out)
    }
}

/// ⟨ADR-0008 §17.32 item 7⟩ One record's answer to
/// [`Operations::uninstall_fence_retry_remote_revocations`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteRetry {
    /// The revoked root grant the record is keyed by.
    pub root_grant: String,
    /// What the one round did.
    pub outcome: RemoteRetryOutcome,
    /// The record's rounds before it.
    pub attempts_before: u32,
    /// After it (`attempts_before + 1` when a round was claimed).
    pub attempts_after: u32,
    /// Whether its retries are stopped now.
    pub stopped: bool,
    /// Whether the record is still pending.
    pub pending: bool,
}

/// What the one round of [`Operations::uninstall_fence_retry_remote_revocations`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRetryOutcome {
    /// Every obligation was confirmed: the record is gone.
    Completed,
    /// A round was claimed and called the adapters; something is still pending.
    AttemptedStillPending,
    /// No adapter call was owed or allowed (stopped, at its cap, or no responsible
    /// adapter configured): nothing was attempted, no count reset, no stop lifted.
    NotAttempted,
    /// The round failed (a store failure); the record is as it was or counted one
    /// attempt (a claimed round counts whatever fails).
    Failed,
}

/// ⟨ADR-0008 §17.28 item 1⟩ The enrollment operations (open or `outcome_unknown`) whose
/// current journal has a dispatched step without its recorded result (`outstanding`)
/// or an uncertain remote mutation (`uncertain`: its remote effect is unknown), oldest
/// first. Read-only (it runs on a store opened read-only); an operation without a
/// journal has none.
///
/// # Errors
/// A store failure.
pub fn unresolved_remote_steps(tx: &mut Txn<'_>) -> heimdall_store::Result<Vec<OperationId>> {
    let mut ops = tx.open_operations()?;
    ops.extend(tx.unresolved_operations()?);
    ops.retain(|o| o.kind.is_enrollment());
    ops.sort_by(|a, b| (a.created_at, a.id.as_str()).cmp(&(b.created_at, b.id.as_str())));
    ops.dedup_by(|a, b| a.id == b.id);
    let mut out = Vec::new();
    for op in ops {
        let receipts = tx.stage_receipts(&op.id)?;
        if super::enrollment_m03::journal_of(&receipts)
            .is_some_and(|j| j.outstanding.is_some() || j.uncertain.is_some())
        {
            out.push(op.id);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use heimdall_contract::Timestamp;
    use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, GrantId};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::scope::AccessPair;
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_store::Store;
    use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

    use super::*;
    use crate::Caller;
    use crate::ensure::NoStageHook;
    use crate::operations::{IssuanceFacts, IssuanceRequest, Limits, OperationsConfig};

    fn t0() -> Timestamp {
        "2026-11-13T09:00:00Z".parse().unwrap()
    }

    async fn ops() -> Operations {
        let env = EnvironmentId::from_random_bytes([9; 16]);
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        store
            .transaction(|tx| tx.init_self_environment(&env))
            .unwrap();
        Operations::start(OperationsConfig {
            store,
            clock: VirtualClock::at(t0()),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env,
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: Duration::from_secs(3600),
            projection: None,
        })
        .await
        .unwrap()
    }

    fn owner() -> Caller {
        Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        })
    }

    fn issuance() -> IssuanceRequest {
        IssuanceRequest {
            grant: GrantId::from_random_bytes([3; 16]),
            pair: AccessPair {
                destination: DestinationId::parse("dst-lab").unwrap(),
                account: AccountName::parse("deploy").unwrap(),
            },
            principal: "hm:dst-lab:deploy".to_owned(),
            key_id: "k".to_owned(),
            valid_after: t0(),
            valid_before: t0(),
            extensions: BTreeSet::new(),
            subject_fingerprint: "SHA256:x".to_owned(),
            facts: IssuanceFacts {
                new_activation: true,
                subject_registered: true,
                critical_option: false,
            },
        }
    }

    fn is_fenced(e: &OpError) -> bool {
        e.code == Code::ServiceUnavailable
            && e.reason.as_deref() == Some(reason::UNINSTALL_IN_PROGRESS)
    }

    /// `uninstall_fence_checks_work_no_request_carries` (ADR-0008 §17.27 item 2,
    /// §17.28 item 1): while the fence is held, a certificate reservation outside the
    /// holder's scope is refused `SERVICE_UNAVAILABLE` / `uninstall_in_progress` before
    /// anything is written, and the supervisor passes do nothing; the holder's own
    /// reservation is not refused for the fence. A second connection's `acquire` is
    /// refused; its `release` does not lift the fence; the holder's does.
    #[tokio::test]
    async fn uninstall_fence_checks_work_no_request_carries() {
        let ops = ops().await;
        if let Err(e) = ops.reserve_issuance(issuance()).await {
            assert!(!is_fenced(&e), "{e:?}");
        }
        assert_eq!(
            ops.uninstall_fence_acquire(1).await.unwrap(),
            FenceAcquired::Held
        );
        assert_eq!(
            ops.uninstall_fence_acquire(1).await.unwrap(),
            FenceAcquired::Held,
            "idempotent"
        );
        assert!(is_fenced(
            &ops.uninstall_fence_acquire(2).await.unwrap_err()
        ));
        assert_eq!(ops.uninstall_fence_holder(), Some(1));
        assert!(is_fenced(
            &ops.reserve_issuance(issuance()).await.unwrap_err()
        ));
        if let Err(e) = as_fence_holder(ops.reserve_issuance(issuance())).await {
            assert!(!is_fenced(&e), "the holder's own: {e:?}");
        }
        assert!(ops.reverify_pass().await.unwrap().is_empty());
        assert!(ops.managed_reissue_pass().await.unwrap().is_empty());
        // ⟨§17.31 item 2⟩ The application route meets the same boundary as the
        // dispatcher: an approval is refused, a denial is not.
        let attended = Caller {
            attendance: crate::Attendance::Attended { since: t0() },
            interaction: heimdall_contract::request::InteractionMode::Interactive,
            ..owner()
        };
        let decide = |verdict| heimdall_contract::request::DecideRequest {
            decision_id: heimdall_contract::ids::DecisionId::from_random_bytes([5; 16]),
            verdict,
        };
        assert!(is_fenced(
            &ops.decide(
                &attended,
                decide(heimdall_contract::request::Verdict::Approve)
            )
            .await
            .unwrap_err()
        ));
        let denied = ops
            .decide(&attended, decide(heimdall_contract::request::Verdict::Deny))
            .await;
        assert!(!denied.as_ref().is_err_and(is_fenced), "{denied:?}");
        assert!(ops.uninstall_fence_release(2), "still held by 1");
        assert!(!ops.uninstall_fence_release(1));
        assert!(!ops.uninstall_fence_held());
        if let Err(e) = ops.reserve_issuance(issuance()).await {
            assert!(!is_fenced(&e), "{e:?}");
        }
        assert_eq!(
            ops.uninstall_fence_acquire(2).await.unwrap(),
            FenceAcquired::Held
        );
    }

    /// The fence serializes with fenced requests: `acquire` waits for one already past
    /// its check (holding the admission guard).
    #[tokio::test]
    async fn uninstall_fence_acquire_waits_for_admissions_in_progress() {
        let ops = ops().await;
        let admission = ops.uninstall_fence_admit().unwrap();
        let nested = ops.uninstall_fence_admit().unwrap();
        let o2 = ops.clone();
        let acquiring = tokio::spawn(async move { o2.uninstall_fence_acquire(7).await });
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!acquiring.is_finished(), "acquire waits for the admission");
        assert!(!ops.uninstall_fence_held());
        // ⟨§17.31 item 2⟩ While it is being acquired, new work is refused at once
        // (never queued), and a reservation joins it (the acquisition waits for it).
        assert!(is_fenced(&ops.uninstall_fence_admit().unwrap_err()));
        let joined = ops.fence_admit_reservation().await.unwrap();
        drop(nested);
        drop(admission);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !acquiring.is_finished(),
            "acquire waits for the joined reservation"
        );
        drop(joined);
        assert_eq!(acquiring.await.unwrap().unwrap(), FenceAcquired::Held);
        assert_eq!(ops.uninstall_fence_holder(), Some(7));
        assert!(is_fenced(&ops.uninstall_fence_admit().unwrap_err()));
        assert!(is_fenced(&ops.fence_admit_reservation().await.unwrap_err()));
        // The holder's scope is never refused, and counts nothing.
        as_fence_holder(async {
            let _a = ops.uninstall_fence_admit().unwrap();
            let _r = ops.fence_admit_reservation().await.unwrap();
        })
        .await;
        assert!(!ops.uninstall_fence_release(7));
        drop(ops.uninstall_fence_admit().unwrap());
    }

    /// `cancelled_admitted_work_keeps_admission_until_its_store_write_finishes`
    /// (ADR-0008 §17.32 item 3, the converge class): admitted work (a fenced request or
    /// pass, whose admission is a guard on its own future) is cancelled while one of its
    /// store writes is running on the blocking pool. The write carries a counted
    /// extension of the admission, so the acquisition completes only after that
    /// transaction has ended; work that holds no admission adds none.
    #[tokio::test]
    async fn cancelled_admitted_work_keeps_admission_until_its_store_write_finishes() {
        let ops = ops().await;
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (go, go_rx) = std::sync::mpsc::channel::<()>();
        let o = ops.clone();
        let work = tokio::spawn(async move {
            let _admission = o.uninstall_fence_admit().unwrap();
            o.write(move |_, _| {
                let _ = reached_tx.send(());
                let _ = go_rx.recv();
                Ok(())
            })
            .await
        });
        reached.await.unwrap();
        work.abort();
        assert!(work.await.unwrap_err().is_cancelled());
        let o2 = ops.clone();
        let acquiring = tokio::spawn(async move { o2.uninstall_fence_acquire(11).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !acquiring.is_finished() && !ops.uninstall_fence_held(),
            "the acquisition must wait for the cancelled work's running write"
        );
        go.send(()).unwrap();
        assert_eq!(acquiring.await.unwrap().unwrap(), FenceAcquired::Held);
        assert!(!ops.uninstall_fence_release(11));
        // A write from a task holding no admission carries none.
        let o = ops.clone();
        let unadmitted = tokio::spawn(async move { o.inner.uninstall_fence.write_extension() });
        assert!(unadmitted.await.unwrap().is_none());
    }

    /// A dropped (cancelled) acquisition stops refusing new work.
    #[tokio::test]
    async fn uninstall_fence_dropped_acquisition_reopens_admission() {
        let ops = ops().await;
        let admission = ops.uninstall_fence_admit().unwrap();
        let o2 = ops.clone();
        let acquiring = tokio::spawn(async move { o2.uninstall_fence_acquire(8).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(is_fenced(&ops.uninstall_fence_admit().unwrap_err()));
        acquiring.abort();
        let _ = acquiring.await;
        drop(ops.uninstall_fence_admit().unwrap());
        drop(admission);
        assert!(!ops.uninstall_fence_held());
    }

    /// `unresolved_remote_steps_lists_dispatched_and_uncertain_steps` (ADR-0008 §17.28
    /// item 1): an open enrollment operation whose journal has a dispatched step without
    /// its result, or an uncertain mutation, is listed; one with neither, or with no
    /// journal, is not.
    #[tokio::test]
    async fn unresolved_remote_steps_lists_dispatched_and_uncertain_steps() {
        use crate::enrollment::{IssuedStep, Journal, StepPurpose, UncertainStep};
        use heimdall_contract::enrollment::RemoteStage;
        let ops = ops().await;
        let issued = IssuedStep {
            stage: RemoteStage::Append,
            token: "ab".repeat(16),
            purpose: StepPurpose::Append,
            issued_continuous_ms: 0,
            issued_wall: t0(),
            boot_id: "boot".into(),
            timeout_ms: 1,
            hard_deadline_ms: 1,
            hard_deadline_wall: t0(),
            not_after_remote: None,
            terminate: false,
            preimage: None,
            post_image: None,
        };
        let uncertain = UncertainStep {
            stage: RemoteStage::Append,
            token: "cd".repeat(16),
            not_after_remote: None,
            purpose: StepPurpose::Append,
            hard_deadline_ms: 0,
            hard_deadline_wall: t0(),
            boot_id: "boot".into(),
        };
        let journals = [
            Some(Journal {
                outstanding: Some(issued),
                ..Journal::default()
            }),
            Some(Journal {
                uncertain: Some(uncertain),
                ..Journal::default()
            }),
            Some(Journal::default()),
            None,
        ];
        let mut ids = Vec::new();
        for (n, journal) in (1u8..).zip(journals) {
            ids.push(seed_op(&ops, n, journal));
        }
        let found = ops
            .inner
            .config
            .store
            .transaction(unresolved_remote_steps)
            .unwrap();
        assert_eq!(found, ids[..2].to_vec());
    }

    /// Seed a running `enrollment.apply` operation `n` with `journal` (if any).
    fn seed_op(
        ops: &Operations,
        n: u8,
        journal: Option<crate::enrollment::Journal>,
    ) -> heimdall_contract::ids::OperationId {
        use heimdall_contract::canonical::RequestHash;
        use heimdall_contract::ids::{OperationId, RequestId};
        use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
        use heimdall_domain::operation::{
            EffectClass, OperationKind, OperationRecord, RecoveryMetadata,
        };
        let id = OperationId::from_random_bytes([n; 16]);
        let key = IdempotencyKey {
            caller: owner().context,
            kind: OperationKind::EnrollmentApply,
            request_id: RequestId::parse(&format!("seed-{n}")).unwrap(),
        };
        let at = t0().checked_add(Duration::from_secs(u64::from(n))).unwrap();
        let op = OperationRecord {
            id: id.clone(),
            kind: OperationKind::EnrollmentApply,
            environment: ops.inner.config.environment.clone(),
            key: key.clone(),
            request_hash: RequestHash([n; 32]),
            effect_class: EffectClass::RemoteMutation,
            state: heimdall_contract::OperationState::Running,
            code: None,
            effect_status: heimdall_contract::envelope::EffectStatus::Unknown,
            result: None,
            created_at: at,
            updated_at: at,
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        ops.inner
            .config
            .store
            .transaction(|tx| {
                tx.insert_operation(
                    &op,
                    &IdempotencyRecord {
                        key: key.clone(),
                        request_hash: op.request_hash,
                        operation_id: id.clone(),
                        created_at: at,
                        expires_at: None,
                    },
                )?;
                if let Some(j) = &journal {
                    super::super::enrollment_m03::put_journal(tx, &id, j, at)?;
                }
                Ok(())
            })
            .unwrap();
        id
    }
}
