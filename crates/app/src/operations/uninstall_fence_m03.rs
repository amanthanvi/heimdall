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
//! **The holder lease** (⟨§17.33 item 1⟩). The holder's exemption is a [`FenceLease`]:
//! a value scoped to the holding connection and the fence's **generation** (each
//! acquisition is a new one), never a flag. The dispatcher takes it for each of the
//! holder's requests ([`Operations::uninstall_fence_lease`]) and runs the request in
//! its scope ([`with_fence_lease`]); work spawned on the holder's behalf carries it
//! explicitly ([`spawn_with_lease`]); work the holder did not start never gains it.
//! Every exempt step re-checks it: at its start (the admissions), before each retry
//! round, and before each commit (the write closure, before the transaction, under the
//! same lock order as an admission). A released or reacquired fence refuses the step
//! (`uninstall_in_progress`). Every live lease counts as holder work: a release while
//! some is in flight only marks the fence **releasing** (leases invalid, new work still
//! refused) and the fence is lifted when the last lease ends; the release request
//! waits for that, bounded by [`RELEASE_WAIT`], and reports when the bound is hit.
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

/// ⟨§17.33 item 1⟩ How long `release` waits for the holder's in-flight work to end.
pub const RELEASE_WAIT: Duration = Duration::from_secs(20);

/// ⟨§17.33 item 9⟩ The next command a `uninstall_fence_release_stuck` refusal names.
pub const RELEASE_STUCK_NEXT_COMMAND: &str = "heimdall service stop";

/// ⟨§17.33 item 9⟩ The next step a `uninstall_fence_release_stuck` refusal names (the
/// fence is never stored, so a runtime started again has none).
pub const RELEASE_STUCK_NEXT_STEP: &str = "stop the runtime (`heimdall service stop`), then start it again (`heimdall service run --detach`)";

/// ⟨§17.33 item 9⟩ The refusal while the fence is releasing past [`RELEASE_WAIT`]
/// (`SERVICE_UNAVAILABLE`, `uninstall_fence_release_stuck`, effect `none`), naming the
/// way out ([`RELEASE_STUCK_NEXT_STEP`]).
#[must_use]
pub fn uninstall_fence_release_stuck() -> OpError {
    OpError::new(
        Code::ServiceUnavailable,
        format!(
            "an uninstall is releasing its fence, but work it started has not ended within the release's bound, so no enrollment, CA or issuance work is admitted until that work ends; to clear it, {RELEASE_STUCK_NEXT_STEP}"
        ),
    )
    .with_reason(reason::UNINSTALL_FENCE_RELEASE_STUCK)
    .with_effect(EffectStatus::None)
}

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

/// The fence's holder: its connection, the acquisition's generation, and whether a
/// release is waiting for the holder's in-flight work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Holder {
    connection: u64,
    generation: u64,
    releasing: bool,
}

#[derive(Debug, Default)]
struct FenceState {
    /// The holder, if any (also while it is releasing).
    holder: Option<Holder>,
    /// The last generation handed out (each acquisition takes the next).
    generation: u64,
    /// ⟨§17.33 item 1⟩ Live holder leases (holder work in flight).
    holder_work: usize,
    /// ⟨§17.33 item 9⟩ When the current holder started releasing (its work in flight).
    release_started: Option<tokio::time::Instant>,
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
    /// The lease the current task's work runs under ([`with_fence_lease`]).
    static FENCE_LEASE: FenceLease;
}

/// ⟨§17.33 item 1⟩ The fence holder's authority for one piece of work: the holding
/// connection and the fence's generation when it was taken. While it lives it counts
/// as holder work (a release waits for it); a clone counts too.
#[derive(Debug)]
pub struct FenceLease {
    fence: Arc<UninstallFence>,
    connection: u64,
    generation: u64,
}

impl FenceLease {
    /// The connection the lease was granted to.
    #[must_use]
    pub fn connection(&self) -> u64 {
        self.connection
    }

    /// The fence generation it was granted under.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether it still stands: the same connection holds the fence, at the same
    /// generation, and is not releasing.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.fence.state().holder
            == Some(Holder {
                connection: self.connection,
                generation: self.generation,
                releasing: false,
            })
    }

    /// [`Self::valid`] as a step's check.
    ///
    /// # Errors
    /// `SERVICE_UNAVAILABLE` / `uninstall_in_progress` when the fence was released (or
    /// is releasing) or reacquired since the lease was granted.
    pub fn check(&self) -> Result<(), OpError> {
        if self.valid() {
            Ok(())
        } else {
            Err(self.fence.refusal())
        }
    }
}

impl Clone for FenceLease {
    fn clone(&self) -> Self {
        self.fence.state().holder_work += 1;
        Self {
            fence: Arc::clone(&self.fence),
            connection: self.connection,
            generation: self.generation,
        }
    }
}

impl Drop for FenceLease {
    fn drop(&mut self) {
        let lifted = {
            let mut s = self.fence.state();
            s.holder_work = s.holder_work.saturating_sub(1);
            if s.holder_work == 0 && s.holder.is_some_and(|h| h.releasing) {
                s.holder = None;
                s.release_started = None;
                true
            } else {
                false
            }
        };
        if lifted {
            self.fence.changed.notify_waiters();
        }
    }
}

/// Run `f` under `lease` (the holder's request, or work it started).
pub async fn with_fence_lease<F: std::future::Future>(lease: FenceLease, f: F) -> F::Output {
    FENCE_LEASE.scope(lease, f).await
}

/// The current task's lease, cloned (counted), if its work runs under one.
pub(crate) fn current_lease() -> Option<FenceLease> {
    FENCE_LEASE.try_with(Clone::clone).ok()
}

/// ⟨§17.33 item 1⟩ `tokio::spawn` for work started from the current task: if that runs
/// under a holder lease, the spawned task carries a counted clone of it explicitly (so
/// the holder's own spawned work keeps its exemption, and a release waits for it);
/// otherwise it runs with none, as any background work.
pub(crate) fn spawn_with_lease<F>(f: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    match current_lease() {
        Some(lease) => tokio::spawn(with_fence_lease(lease, f)),
        None => tokio::spawn(f),
    }
}

/// The exemption of the current task: `None` when it runs under no lease; else
/// whether its lease still stands.
fn lease_scope() -> Option<Result<(), OpError>> {
    FENCE_LEASE.try_with(FenceLease::check).ok()
}

/// [`UninstallFence::refusal`] on a state already locked.
fn refusal_of(s: &FenceState) -> OpError {
    let stuck = s.holder.is_some_and(|h| h.releasing)
        && s.release_started
            .is_some_and(|t| t.elapsed() >= RELEASE_WAIT);
    if stuck {
        uninstall_fence_release_stuck()
    } else {
        uninstall_in_progress()
    }
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
        self.state().holder.map(|h| h.connection)
    }

    /// The fence's refusal now: [`uninstall_fence_release_stuck`] while it is releasing
    /// past [`RELEASE_WAIT`], else [`uninstall_in_progress`].
    pub(crate) fn refusal(&self) -> OpError {
        refusal_of(&self.state())
    }

    /// ⟨§17.32 item 3⟩ For a store write started by a task that holds an admission: a
    /// further counted admission, which the write's blocking closure owns until the
    /// transaction has committed or rolled back. So cancelling the task's future (and
    /// dropping its admission) never lets an acquisition complete while that write is
    /// queued or running. `None` outside a task, for a task holding none, and in the
    /// holder's scope.
    pub(crate) fn write_extension(self: &Arc<Self>) -> Option<FenceAdmission> {
        if lease_scope().is_some() {
            // The holder's work: its lease (carried into the write) covers it.
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
        if let Some(lease) = lease_scope() {
            // ⟨§17.33 item 1⟩ The holder's work is exempt only while its lease stands.
            return lease.map(|()| FenceAdmission::none());
        }
        let fence = &self.inner.uninstall_fence;
        let mut s = fence.state();
        if s.holder.is_some() || (kind == Admit::Work && s.acquiring > 0) {
            return Err(refusal_of(&s));
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
        if let Some(lease) = lease_scope() {
            return lease.map(|()| FenceAdmission::none());
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
                Some(h) if h.connection != connection || h.releasing => {
                    return Err(other_holds());
                }
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
                        Some(h) if h.connection != connection || h.releasing => {
                            return Err(other_holds());
                        }
                        Some(_) => return Ok(FenceAcquired::Held),
                        None if s.admitted == 0 => {
                            // ⟨§17.33 item 1⟩ Each acquisition is a new generation.
                            s.generation += 1;
                            s.holder = Some(Holder {
                                connection,
                                generation: s.generation,
                                releasing: false,
                            });
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
    /// connection ends: if `connection` holds the fence, lifts it at once when none of
    /// its holder work is in flight; otherwise marks it **releasing** (every lease
    /// invalid, new work still refused) and it is lifted when the last lease ends
    /// (⟨§17.33 item 1⟩). Another connection's release does nothing. Returns whether the
    /// fence is still held (releasing included).
    pub fn uninstall_fence_release(&self, connection: u64) -> bool {
        let fence = &self.inner.uninstall_fence;
        let lifted = {
            let mut s = fence.state();
            match s.holder {
                Some(h) if h.connection == connection && s.holder_work == 0 => {
                    s.holder = None;
                    true
                }
                Some(mut h) if h.connection == connection => {
                    if !h.releasing {
                        s.release_started = Some(tokio::time::Instant::now());
                    }
                    h.releasing = true;
                    s.holder = Some(h);
                    false
                }
                _ => false,
            }
        };
        if lifted {
            fence.changed.notify_waiters();
        }
        self.uninstall_fence_held()
    }

    /// ⟨§17.33 item 1⟩ The `release` request: [`Self::uninstall_fence_release`], then a
    /// wait (bounded by [`RELEASE_WAIT`]) until the holder's in-flight work has ended
    /// and the fence is lifted. Returns whether the fence is still held by another
    /// connection (`false`: released).
    ///
    /// # Errors
    /// `SERVICE_UNAVAILABLE` / `uninstall_in_progress` when the holder's work did not
    /// end in time: the fence stays releasing (refusing new work) and is lifted when
    /// that work ends.
    pub async fn uninstall_fence_release_waiting(&self, connection: u64) -> Result<bool, OpError> {
        let fence = &self.inner.uninstall_fence;
        let mine = |s: &FenceState| s.holder.is_some_and(|h| h.connection == connection);
        if !mine(&fence.state()) {
            return Ok(self.uninstall_fence_held());
        }
        self.uninstall_fence_release(connection);
        let wait = async {
            loop {
                let mut changed = std::pin::pin!(fence.changed.notified());
                changed.as_mut().enable();
                if !mine(&fence.state()) {
                    return;
                }
                changed.await;
            }
        };
        match tokio::time::timeout(RELEASE_WAIT, wait).await {
            Ok(()) => Ok(self.uninstall_fence_held()),
            // ⟨§17.33 item 9⟩ The bound is hit: the fence stays releasing (it is
            // lifted when that work ends), and the refusal names the way out.
            Err(_) => Err(uninstall_fence_release_stuck()),
        }
    }

    /// ⟨§17.33 item 1⟩ The holder lease for `connection`: `Some` only while
    /// `connection` holds the fence and is not releasing; it carries the current
    /// generation and counts as holder work while it lives.
    #[must_use]
    pub fn uninstall_fence_lease(&self, connection: u64) -> Option<FenceLease> {
        let fence = &self.inner.uninstall_fence;
        let mut s = fence.state();
        let h = s.holder?;
        if h.connection != connection || h.releasing {
            return None;
        }
        s.holder_work += 1;
        Some(FenceLease {
            fence: Arc::clone(fence),
            connection,
            generation: h.generation,
        })
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
        // ⟨§17.33 item 1⟩ The holder's lease for this connection (the current task's,
        // when it runs under one; it must be this connection's and still stand), held
        // for the whole retry and re-checked before each round.
        let lease = match FENCE_LEASE.try_with(Clone::clone).ok() {
            Some(l) if l.connection == connection => l.check().map(|()| Some(l))?,
            Some(_) => return Err(self.inner.uninstall_fence.refusal()),
            None => self.uninstall_fence_lease(connection),
        };
        match lease.as_ref().map(FenceLease::connection) {
            Some(_) => {}
            None => {
                let other = self.uninstall_fence_holder();
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
        let Some(lease) = lease else {
            return Err(self.inner.uninstall_fence.refusal());
        };
        for before in self.pending_remote_revocations().await? {
            lease.check()?;
            let root = before.root.clone();
            // The round runs under the lease, so each of its commits re-checks it.
            let round = with_fence_lease(lease.clone(), self.retry_remote_revocation(&root, cap));
            // ⟨§17.33 item 3 (W5-E01; audit B1)⟩ The allowance is the record the round
            // itself committed, from the round's own transaction (never a re-read, so no
            // unfenced write committed after it is ever admitted): `Some` as stored, `None`
            // when the round removed it; a failed round admits nothing (`record: None`,
            // outcome `failed`: the confirmed bytes and nothing else).
            let retry = match round.await {
                Ok(None) => RemoteRetry {
                    root_grant: root.to_string(),
                    outcome: RemoteRetryOutcome::Completed,
                    attempts_before: before.attempts,
                    attempts_after: before.attempts.saturating_add(1),
                    stopped: false,
                    pending: false,
                    record: None,
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
                    record: Some(after),
                },
                Err(_) => RemoteRetry {
                    root_grant: root.to_string(),
                    outcome: RemoteRetryOutcome::Failed,
                    attempts_before: before.attempts,
                    attempts_after: before.attempts,
                    stopped: before.stopped,
                    pending: true,
                    record: None,
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
    /// ⟨ADR-0008 §17.33 item 3 (W5-E01; audit B1)⟩ The complete record exactly as the
    /// round's own transaction committed it (its obligations with their attempts, stops
    /// and kinds, the effect and claim sequences, the re-arm history and the cap);
    /// `None` when the round removed it, or when the round failed (outcome `failed`:
    /// then nothing is admitted). The uninstall's final check admits exactly this
    /// record, byte for byte in the store's form, and nothing else.
    pub record: Option<heimdall_domain::revocation::PendingRemoteRevocation>,
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
        ops_on(store).await
    }

    /// A runtime over `store` (a restart of [`ops`]'s, when it is the same store).
    async fn ops_on(store: Arc<Store>) -> Operations {
        let env = EnvironmentId::from_random_bytes([9; 16]);
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
        if let Err(e) = with_fence_lease(
            ops.uninstall_fence_lease(1).unwrap(),
            ops.reserve_issuance(issuance()),
        )
        .await
        {
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
        // The holder's lease is never refused, and counts no admission.
        with_fence_lease(ops.uninstall_fence_lease(7).unwrap(), async {
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

    /// `holder_spawned_task_keeps_the_lease` (ADR-0008 §17.33 item 1): work spawned
    /// from the holder's work with `spawn_with_lease` carries the lease (its
    /// reservation is the holder's, admitted under the held fence) and counts as holder
    /// work: a release while it runs only marks the fence releasing, and the fence is
    /// lifted when it ends. A plain `tokio::spawn` from the same work gains nothing and
    /// is refused.
    #[tokio::test]
    async fn holder_spawned_task_keeps_the_lease() {
        let ops = ops().await;
        ops.uninstall_fence_acquire(21).await.unwrap();
        let (go, wait) = tokio::sync::oneshot::channel::<()>();
        let o = ops.clone();
        let (spawned, plain) = with_fence_lease(ops.uninstall_fence_lease(21).unwrap(), async {
            let o2 = o.clone();
            let spawned = spawn_with_lease(async move {
                let admitted = o2.fence_admit_reservation().await.map(drop);
                let _ = wait.await;
                admitted
            });
            let o3 = o.clone();
            let plain = tokio::spawn(async move { o3.fence_admit_reservation().await.map(drop) });
            (spawned, plain.await.unwrap())
        })
        .await;
        assert!(
            is_fenced(&plain.unwrap_err()),
            "a plain spawn gains no lease"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            ops.uninstall_fence_release(21),
            "releasing while the spawned work runs"
        );
        assert!(
            ops.uninstall_fence_lease(21).is_none(),
            "no lease while releasing"
        );
        go.send(()).unwrap();
        spawned.await.unwrap().unwrap();
        assert!(
            !ops.uninstall_fence_held(),
            "lifted when the holder's work ended"
        );
    }

    /// `earlier_generation_lease_is_refused` (ADR-0008 §17.33 item 1): a lease is bound
    /// to the connection **and** the fence generation it was granted under. One that
    /// outlived its generation (the same connection holding a later acquisition) is
    /// refused at each step: its check, an admission under it, and a commit under it,
    /// with nothing written. A lease of the current generation is accepted.
    #[tokio::test]
    async fn earlier_generation_lease_is_refused() {
        let ops = ops().await;
        ops.uninstall_fence_acquire(22).await.unwrap();
        let old = ops.uninstall_fence_lease(22).unwrap();
        assert_eq!(old.generation(), 1);
        // The fence was released and reacquired by the same connection while this
        // lease lived (a lease that escaped the release's wait): generation 2.
        {
            let mut s = ops.inner.uninstall_fence.state();
            let mut h = s.holder.unwrap();
            h.generation += 1;
            s.generation = h.generation;
            s.holder = Some(h);
        }
        assert!(is_fenced(&old.check().unwrap_err()));
        let o = ops.clone();
        let (admitted, written) = with_fence_lease(old, async move {
            let admitted = o.uninstall_fence_admit().map(drop);
            let written = o.write(|_, _| Ok(())).await;
            (admitted, written)
        })
        .await;
        assert!(
            is_fenced(&admitted.unwrap_err()),
            "admission under a stale lease"
        );
        assert!(
            is_fenced(&written.unwrap_err()),
            "commit under a stale lease"
        );
        let current = ops.uninstall_fence_lease(22).unwrap();
        assert_eq!(current.generation(), 2);
        current.check().unwrap();
        let o = ops.clone();
        with_fence_lease(current, async move {
            drop(o.uninstall_fence_admit().unwrap());
            o.write(|_, _| Ok(())).await.unwrap();
        })
        .await;
        assert!(!ops.uninstall_fence_release(22));
        // A new acquisition is a new generation.
        ops.uninstall_fence_acquire(23).await.unwrap();
        assert_eq!(ops.uninstall_fence_lease(23).unwrap().generation(), 3);
        assert!(ops.uninstall_fence_lease(22).is_none());
    }

    /// `fence_release_stuck_past_its_bound_refuses_with_the_restart` (ADR-0008 §17.33
    /// items 1 and 9; the named residual `uninstall_fence_release_stuck_until_holder_work_ends`):
    /// holder work that never ends keeps a released fence **releasing**. A held fence,
    /// and a releasing one before [`RELEASE_WAIT`], refuse other work
    /// `uninstall_in_progress`; the release request's bound is hit and reported; past
    /// the bound every refusal is `uninstall_fence_release_stuck`, whose message names
    /// the restart (`heimdall service stop`, then `heimdall service run --detach`). A
    /// restarted runtime over the same store has no fence (it is never stored); the
    /// work ending lifts it too.
    #[tokio::test]
    async fn fence_release_stuck_past_its_bound_refuses_with_the_restart() {
        // Virtual time: the release's 20 s bound passes at once.
        tokio::time::pause();
        let stuck = |e: &OpError| {
            e.code == Code::ServiceUnavailable
                && e.reason.as_deref() == Some(reason::UNINSTALL_FENCE_RELEASE_STUCK)
                && e.effect_status == EffectStatus::None
                && e.message.contains(
                    "stop the runtime (`heimdall service stop`), then start it again (`heimdall service run --detach`)",
                )
        };
        let in_progress = |e: &OpError| e.reason.as_deref() == Some(reason::UNINSTALL_IN_PROGRESS);
        assert_eq!(
            RELEASE_STUCK_NEXT_STEP,
            "stop the runtime (`heimdall service stop`), then start it again (`heimdall service run --detach`)"
        );
        assert_eq!(RELEASE_STUCK_NEXT_COMMAND, "heimdall service stop");
        let ops = ops().await;
        ops.uninstall_fence_acquire(31).await.unwrap();
        assert!(
            in_progress(&ops.uninstall_fence_admit().unwrap_err()),
            "held"
        );
        let never_ends = ops.uninstall_fence_lease(31).unwrap();
        assert!(ops.uninstall_fence_release(31), "releasing");
        tokio::time::advance(RELEASE_WAIT - Duration::from_secs(1)).await;
        assert!(
            in_progress(&ops.uninstall_fence_admit().unwrap_err()),
            "before the bound"
        );
        let e = ops.uninstall_fence_release_waiting(31).await.unwrap_err();
        assert!(stuck(&e), "the release's bound is hit: {e:?}");
        let e = ops.uninstall_fence_admit().unwrap_err();
        assert!(stuck(&e), "past the bound: {e:?}");
        assert!(stuck(&ops.fence_admit_reservation().await.unwrap_err()));
        assert!(ops.uninstall_fence_held(), "still releasing");
        // `heimdall service stop`, then `heimdall service run --detach`: a new runtime
        // over the same store starts with no fence.
        let restarted = ops_on(Arc::clone(&ops.inner.config.store)).await;
        assert!(!restarted.uninstall_fence_held());
        drop(restarted.uninstall_fence_admit().unwrap());
        // The holder work ending lifts it in this runtime too.
        drop(never_ends);
        assert!(!ops.uninstall_fence_held());
        drop(ops.uninstall_fence_admit().unwrap());
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
