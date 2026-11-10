//! ⟨M03⟩ U9: lock behaviour (ADR-0008 D9; §17.1 items 9 and 18, §17.15 item 12,
//! §17.16 items 1 and 6; m03-plan U9).
//!
//! * **The effective behaviour** ([`effective_behavior`],
//!   [`effective_behavior_with_floor`]): the strictest of the value a grant's origin
//!   recorded at creation, every applicable standing policy, and the M01
//!   `[session] lock_behavior` **floor** (ADR-0008 §17.15 item 12, R3): `revoke_on_lock`
//!   from any side wins, and any value this build does not know counts as
//!   `revoke_on_lock`. The operations' lock pass and per-signature check use the same
//!   function (`operations/lock.rs`).
//! * **Consumers treat every state but `unlocked` as locked** ([`treated_as_locked`]):
//!   `unknown` (and `unavailable`) refuse a `revoke_on_lock` grant's signature, and
//!   entering `unknown` runs a revocation pass ([`UNKNOWN_IS_LOCK`]).
//! * **The lock-pass driver** ([`run_lock_passes`]): waits on the source's
//!   value-less `changed()`, reads the latched epoch, and runs
//!   `Operations::on_session_lock` (U0b row 25), which acknowledges the epoch only after
//!   its revocations commit. Passes are coalesced ([`LockPassConfig::min_interval`]):
//!   a storm of lock events latches into one epoch and costs at most one pass per
//!   interval, never one pass (or one notification) per event. A failed pass leaves
//!   the lock latched and is retried. U10 runs the driver from the supervisor.
//! * **The disclosure** ([`disclosure`], [`Operations::pending_lock_disclosure`],
//!   [`Operations::acknowledge_lock_disclosure`]): conditional, stating the saved
//!   limits (§17.1 item 18; F19), shown once and recorded in
//!   `meta.lock_disclosure_acknowledged_at` (R-UX-03). The help text and the TUI detail
//!   always show the current behaviour ([`Operations::lock_disclosure`]).
//! * **Labels** ([`lock_warnings`], [`label_completed`]): Linux `revoke_on_lock` carries
//!   `signal_unverified` until B11's native evidence exists
//!   ([`LINUX_LOGIND_SIGNAL_VERIFIED`]).
//! * **Re-issue** ([`reissue_allowed`], [`Operations::lock_blocks_reissue`]): never for a
//!   `revoke_on_lock` grant after a restart (ADR-0008 D9 item 2; ADR-0005 §3.7 rule 5),
//!   so a lock missed while the runtime was down cannot leave it alive. The re-issue
//!   pass itself is U6/U10's.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::envelope::{EffectStatus, Warning, m03_warning, reason};
use heimdall_contract::ids::{GrantId, PolicyId};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::grant::GrantOrigin;
use heimdall_domain::managed::LockEpoch;
use heimdall_domain::policy::{StandingPolicy, strictest_lock_behavior};

use crate::error::{Completed, OpError};
use crate::operations::{LockRevocation, Operations};
use crate::ports::{LockState, SessionLockSource};

/// Entering `unknown` counts as a lock (ADR-0008 D9 item 3: "whenever the source
/// reports `unknown`, every `revoke_on_lock` grant is treated as locked, failing
/// closed"): the runtime's sources latch the epoch on it, and [`run_lock_passes`] runs a
/// revocation pass when the state enters `unknown`. The fail-closed reading of the
/// ADR; questions file U9-Q1.
pub const UNKNOWN_IS_LOCK: bool = true;

/// Whether the Linux logind lock signal has native evidence (B11, a Linux desktop
/// host). Until it does, Linux `revoke_on_lock` is accepted but labelled
/// `signal_unverified` in every result and in the disclosure (ADR-0008 D9 item 3;
/// F19). Flipped only by a reviewed commit after `linux_logind_lock_signal_observed` is
/// `verified`.
pub const LINUX_LOGIND_SIGNAL_VERIFIED: bool = false;

/// Default minimum time between the starts of two lock passes.
pub const LOCK_PASS_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Default delay before a failed lock pass is retried (the lock stays latched).
pub const LOCK_PASS_RETRY_AFTER: Duration = Duration::from_secs(1);

/// The platform signal a session-lock source uses (ADR-0008 D9 item 3 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LockSignal {
    /// macOS: `CGSessionCopyCurrentDictionary` (`CGSSessionScreenIsLocked`), read by the
    /// source's own thread (questions file U9-Q4).
    MacosScreenLock,
    /// Windows: `WTSRegisterSessionNotification` and `WTSSessionInfoEx`.
    WindowsSession,
    /// Linux desktop: logind `LockedHint` and the session's `Lock`/`Unlock` signals.
    LinuxLogind,
    /// No signal (Linux headless, WSL, containers, other systems): `unavailable`.
    None,
}

impl LockSignal {
    /// Whether `revoke_on_lock` over this signal is labelled `signal_unverified`
    /// (Linux until B11; [`LINUX_LOGIND_SIGNAL_VERIFIED`]).
    #[must_use]
    pub fn labelled_unverified(self) -> bool {
        self == LockSignal::LinuxLogind && !LINUX_LOGIND_SIGNAL_VERIFIED
    }

    /// Whether the signal can carry `revoke_on_lock` at all.
    #[must_use]
    pub fn available(self) -> bool {
        self != LockSignal::None
    }
}

// ----------------------------------------------------------------------------------
// The effective behaviour (pure)
// ----------------------------------------------------------------------------------

/// The effective lock behaviour of a grant with `origin` under the applicable
/// `policies` (ADR-0008 D9 item 2): the strictest of the origin's recorded value and
/// every policy. Without the R3 floor; see [`effective_behavior_with_floor`].
#[must_use]
pub fn effective_behavior(origin: &GrantOrigin, policies: &[StandingPolicy]) -> LockBehavior {
    effective_behavior_with_floor(Some(origin), policies, LockBehavior::Continue)
}

/// [`effective_behavior`] with the R3 floor (ADR-0008 §17.15 item 12: the M01
/// `[session] lock_behavior` key, merged fail closed: `revoke` from either side wins).
/// A grant without an origin (M01/M02) has only the policies and the floor.
#[must_use]
pub fn effective_behavior_with_floor(
    origin: Option<&GrantOrigin>,
    policies: &[StandingPolicy],
    floor: LockBehavior,
) -> LockBehavior {
    let recorded = origin.and_then(|o| o.lock_behavior).unwrap_or_default();
    policies
        .iter()
        .fold(strictest_lock_behavior(floor, recorded), |b, p| {
            strictest_lock_behavior(b, p.lock_behavior)
        })
}

/// The value a new grant's origin records (`None` for `continue`, so an M01/M02 origin
/// stays byte-identical; questions file O-Q10): the strictest of the applicable
/// policies and the floor. The origin recording itself is `operations`'
/// (`lock_connection_m03::with_lock_and_connection`), which passes the floor in force
/// at creation (ADR-0008 §17.17 item 4, U9-Q2).
#[must_use]
pub fn origin_behavior(policies: &[StandingPolicy], floor: LockBehavior) -> Option<LockBehavior> {
    let b = effective_behavior_with_floor(None, policies, floor);
    (b != LockBehavior::Continue).then_some(b)
}

/// Whether a consumer treats `state` as locked (fail closed: everything but
/// `unlocked`).
#[must_use]
pub fn treated_as_locked(state: LockState) -> bool {
    state != LockState::Unlocked
}

/// Whether a grant whose effective behaviour is `behavior` may sign while the source
/// reads `state` (ADR-0008 D9 item 3: `revoke_on_lock` needs `unlocked`).
#[must_use]
pub fn signs_while(behavior: LockBehavior, state: LockState) -> bool {
    behavior == LockBehavior::Continue || !treated_as_locked(state)
}

/// Whether a grant whose effective behaviour is `behavior` may be re-issued after a
/// restart (ADR-0008 D9 item 2; ADR-0005 §3.7 rule 5): never for `revoke_on_lock`.
#[must_use]
pub fn reissue_allowed(behavior: LockBehavior) -> bool {
    behavior == LockBehavior::Continue
}

/// The refusal of a configured `revoke` floor where the source is `unavailable`
/// (`CAPABILITY_UNAVAILABLE`, `lock_signal_unavailable`, as for a policy; ADR-0008 D9
/// item 3: never accepted silently). The runtime reports it at start (U10). Grants stay
/// fail closed meanwhile: a `revoke_on_lock` grant never signs while the state is not
/// `unlocked`.
#[must_use]
pub fn floor_refusal(floor: LockBehavior, state: LockState) -> Option<OpError> {
    (floor != LockBehavior::Continue && state == LockState::Unavailable).then(|| {
        OpError::new(
            Code::CapabilityUnavailable,
            "the configured lock behaviour \"revoke\" needs a session-lock signal, which is unavailable here",
        )
        .with_reason(reason::LOCK_SIGNAL_UNAVAILABLE)
        .with_effect(EffectStatus::None)
    })
}

// ----------------------------------------------------------------------------------
// Labels
// ----------------------------------------------------------------------------------

/// The warning of Linux `revoke_on_lock` until B11.
#[must_use]
pub fn signal_unverified_warning() -> Warning {
    Warning {
        code: m03_warning::SIGNAL_UNVERIFIED.to_owned(),
        message: "revoke on lock uses the logind screen-lock signal, which has not been verified on this platform yet".to_owned(),
    }
}

/// The warnings a result about `behavior` carries over `signal`: `signal_unverified`
/// for Linux `revoke_on_lock` until B11, nothing otherwise.
#[must_use]
pub fn lock_warnings(behavior: LockBehavior, signal: LockSignal) -> Vec<Warning> {
    if behavior != LockBehavior::Continue && signal.labelled_unverified() {
        vec![signal_unverified_warning()]
    } else {
        Vec::new()
    }
}

/// Add [`lock_warnings`] to a result (each code once). Every result about a
/// `revoke_on_lock` policy or grant goes through it (U10/U12 wire it on the policy,
/// ensure and capability results; questions file U9-Q3).
pub fn label_completed<T>(
    completed: &mut Completed<T>,
    behavior: LockBehavior,
    signal: LockSignal,
) {
    for w in lock_warnings(behavior, signal) {
        if !completed.warnings.iter().any(|x| x.code == w.code) {
            completed.warnings.push(w);
        }
    }
}

// ----------------------------------------------------------------------------------
// The disclosure (ADR-0008 D9 item 1; R-UX-03; F19)
// ----------------------------------------------------------------------------------

/// One applicable policy's saved limits, as the disclosure states them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedLimit {
    /// The policy.
    pub policy: PolicyId,
    /// Its maximum window for new work.
    pub max_window: Duration,
    /// Its cutoff, if any.
    pub cutoff_at: Option<Timestamp>,
    /// Its lock behaviour.
    pub lock_behavior: LockBehavior,
}

/// The lock disclosure: its facts and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockDisclosure {
    /// The strictest behaviour over the floor and the applicable policies.
    pub behavior: LockBehavior,
    /// The R3 floor in force.
    pub floor: LockBehavior,
    /// Whether the claim table reports `lock_continuity: verified` here (D12).
    pub continuity_verified: bool,
    /// The signal.
    pub signal: LockSignal,
    /// The applicable policies' limits, by policy ID.
    pub limits: Vec<SavedLimit>,
    /// `signal_unverified` where it applies.
    pub warnings: Vec<Warning>,
    /// The text shown.
    pub text: String,
    /// When the owner acknowledged it, if they did (filled by
    /// [`Operations::lock_disclosure`]).
    pub acknowledged_at: Option<Timestamp>,
}

/// A window as the disclosure writes it (`12h`, `90m`, `2h30m`, `45s`).
#[must_use]
pub fn format_window(d: Duration) -> String {
    let s = d.as_secs();
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if sec > 0 || out.is_empty() {
        out.push_str(&format!("{sec}s"));
    }
    out
}

/// The disclosure for `policies` (the policies applicable in this environment), the
/// R3 `floor`, the claim table's `lock_continuity` verdict for this platform and the
/// `signal` (ADR-0008 D9 item 1, as amended by §17.1 item 18). Pure.
///
/// It is **conditional**:
/// * the continuity sentence names each `continue` policy's limits (its maximum
///   window after approval, its cutoff) and says whether this computer's continuity is
///   verified or not yet;
/// * a `revoke_on_lock` policy is stated as ending its work at a lock, and a `revoke`
///   floor as ending all approved work;
/// * the hint to choose "revoke on lock" appears only where a signal exists, and
///   otherwise says it is unavailable here;
/// * Linux `revoke_on_lock` adds the unverified-signal sentence and the
///   `signal_unverified` warning.
#[must_use]
pub fn disclosure(
    policies: &[StandingPolicy],
    floor: LockBehavior,
    continuity_verified: bool,
    signal: LockSignal,
) -> LockDisclosure {
    let mut limits: Vec<SavedLimit> = policies
        .iter()
        .map(|p| SavedLimit {
            policy: p.id.clone(),
            max_window: p.max_window,
            cutoff_at: p.cutoff_at,
            lock_behavior: p.lock_behavior,
        })
        .collect();
    limits.sort_by(|a, b| a.policy.as_str().cmp(b.policy.as_str()));
    let behavior = effective_behavior_with_floor(None, policies, floor);
    let verified = if continuity_verified {
        "been verified"
    } else {
        "not been verified yet"
    };
    let mut sentences: Vec<String> = Vec::new();
    if floor != LockBehavior::Continue {
        sentences.push(
            "Your configuration ([session] lock_behavior = \"revoke\") ends approved work when you lock the screen.".to_owned(),
        );
    } else {
        let continuing: Vec<String> = limits
            .iter()
            .filter(|l| l.lock_behavior == LockBehavior::Continue)
            .map(|l| {
                let mut s = format!(
                    "at most {} after approval, under your saved policy \"{}\"",
                    format_window(l.max_window),
                    l.policy.as_str()
                );
                if let Some(c) = l.cutoff_at {
                    s.push_str(&format!(" (no new work after {c})"));
                }
                s
            })
            .collect();
        if continuing.is_empty() && limits.is_empty() {
            sentences.push(format!(
                "Approved work is designed to keep working while your screen or password manager is locked, until the end time you approve. On this computer that has {verified}."
            ));
        } else if !continuing.is_empty() {
            sentences.push(format!(
                "Approved work is designed to keep working while your screen or password manager is locked, until its end time: {}. On this computer that has {verified}.",
                continuing.join("; ")
            ));
        }
        for l in limits
            .iter()
            .filter(|l| l.lock_behavior != LockBehavior::Continue)
        {
            sentences.push(format!(
                "Work under your saved policy \"{}\" ends when you lock the screen (revoke on lock).",
                l.policy.as_str()
            ));
        }
        if behavior == LockBehavior::Continue
            || limits
                .iter()
                .any(|l| l.lock_behavior == LockBehavior::Continue)
        {
            if signal.available() {
                sentences.push(
                    "To stop it when you lock the screen, set lock behaviour to \"revoke on lock\"."
                        .to_owned(),
                );
            } else {
                sentences.push(
                    "Revoke on lock is not available on this computer: it has no screen-lock signal."
                        .to_owned(),
                );
            }
        }
    }
    let warnings = lock_warnings(behavior, signal);
    if !warnings.is_empty() {
        sentences
            .push("The screen-lock signal on this computer has not been verified yet.".to_owned());
    }
    LockDisclosure {
        behavior,
        floor,
        continuity_verified,
        signal,
        limits,
        warnings,
        text: sentences.join(" "),
        acknowledged_at: None,
    }
}

impl Operations {
    /// Every standing policy applicable in this environment (each profile's), by ID.
    async fn applicable_policies(&self) -> Result<Vec<StandingPolicy>, OpError> {
        let env = self.environment().clone();
        self.local_write(move |tx, _| {
            let mut out: Vec<StandingPolicy> = Vec::new();
            for profile in tx.profiles()? {
                for p in tx.policies_for(&profile.id, &env)? {
                    if !out.iter().any(|q| q.id == p.id) {
                        out.push(p);
                    }
                }
            }
            out.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
            Ok(out)
        })
        .await
    }

    /// ⟨M03⟩ U9: the current lock disclosure ([`disclosure`]) with its acknowledgement,
    /// always (the help text and the TUI detail show the current behaviour).
    /// `continuity_verified` is the claim table's `lock_continuity` verdict for this
    /// platform (D12; empty in the M03 baseline, so `false`).
    ///
    /// # Errors
    /// A store failure.
    pub async fn lock_disclosure(
        &self,
        continuity_verified: bool,
        signal: LockSignal,
    ) -> Result<LockDisclosure, OpError> {
        let policies = self.applicable_policies().await?;
        let acknowledged_at = self.local_write(|tx, _| tx.lock_disclosure_ack()).await?;
        let mut d = disclosure(
            &policies,
            self.session_lock_floor(),
            continuity_verified,
            signal,
        );
        d.acknowledged_at = acknowledged_at;
        Ok(d)
    }

    /// ⟨M03⟩ U9: the disclosure a `RegisterIssuer` or first `EnrollAccount` decision
    /// shows, or `None` once it was acknowledged (shown once; R-UX-03).
    ///
    /// # Errors
    /// A store failure.
    pub async fn pending_lock_disclosure(
        &self,
        continuity_verified: bool,
        signal: LockSignal,
    ) -> Result<Option<LockDisclosure>, OpError> {
        let d = self.lock_disclosure(continuity_verified, signal).await?;
        Ok(d.acknowledged_at.is_none().then_some(d))
    }

    /// ⟨M03⟩ U9: record the disclosure's acknowledgement once
    /// (`meta.lock_disclosure_acknowledged_at`); every later call keeps and returns the
    /// first time. Called when the owner approves the decision that showed it.
    ///
    /// # Errors
    /// A store failure.
    pub async fn acknowledge_lock_disclosure(&self) -> Result<Timestamp, OpError> {
        let now = self.local_clock().wall();
        self.local_write(move |tx, _| tx.set_lock_disclosure_ack(now))
            .await
    }

    /// ⟨M03⟩ U9: the effective lock behaviour of `grant` now (origin, the policies of its
    /// profile applicable here, and the floor); `None` for an unknown grant.
    ///
    /// # Errors
    /// A store failure.
    pub async fn effective_lock_behavior_of(
        &self,
        grant: &GrantId,
    ) -> Result<Option<LockBehavior>, OpError> {
        let env = self.environment().clone();
        let floor = self.session_lock_floor();
        let gid = grant.clone();
        self.local_write(move |tx, _| {
            if tx.grant(&gid)?.is_none() {
                return Ok(None);
            }
            let origin = tx.grant_origin(&gid)?;
            let policies = match &origin {
                Some(o) => tx.policies_for(&o.profile, &env)?,
                None => Vec::new(),
            };
            Ok(Some(effective_behavior_with_floor(
                origin.as_ref(),
                &policies,
                floor,
            )))
        })
        .await
    }

    /// ⟨M03⟩ U9: whether re-issue after a restart is refused for `grant` because its
    /// effective lock behaviour is `revoke_on_lock` ([`reissue_allowed`]). An unknown
    /// grant is refused too (fail closed). U6/U10's `managed_reissue_pass` asks this
    /// before it re-issues anything.
    ///
    /// # Errors
    /// A store failure.
    pub async fn lock_blocks_reissue(&self, grant: &GrantId) -> Result<bool, OpError> {
        Ok(self
            .effective_lock_behavior_of(grant)
            .await?
            .is_none_or(|b| !reissue_allowed(b)))
    }
}

// ----------------------------------------------------------------------------------
// The lock-pass driver
// ----------------------------------------------------------------------------------

/// The driver's coalescing (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPassConfig {
    /// The minimum time between the starts of two passes; events in between coalesce
    /// in the latch. The first pass after a quiet period starts at once.
    pub min_interval: Duration,
    /// The delay before a failed pass is retried (the lock stays latched).
    pub retry_after: Duration,
}

impl Default for LockPassConfig {
    fn default() -> Self {
        Self {
            min_interval: LOCK_PASS_MIN_INTERVAL,
            retry_after: LOCK_PASS_RETRY_AFTER,
        }
    }
}

/// What [`run_lock_passes`] did, returned when it stops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockPassReport {
    /// Passes that committed.
    pub passes: u32,
    /// Passes that failed (each retried).
    pub failures: u32,
    /// The roots revoked, in order.
    pub revoked: Vec<GrantId>,
    /// The epochs handled, in order.
    pub epochs: Vec<u64>,
}

/// Whether a pass is due: a latched lock, a state entering `unknown`
/// ([`UNKNOWN_IS_LOCK`]), or, at the driver's start, a state of `locked` or `unknown`
/// ("at start", ADR-0008 D9 item 3).
fn due(epoch: LockEpoch, state: LockState, last: Option<LockState>) -> bool {
    let lockish = state == LockState::Locked || (UNKNOWN_IS_LOCK && state == LockState::Unknown);
    epoch.observed
        || (last.is_none() && lockish)
        || (UNKNOWN_IS_LOCK && state == LockState::Unknown && last != Some(LockState::Unknown))
}

/// Run one lock pass now for whatever the source has latched (or for `unknown`), and
/// acknowledge it after the commit (`Operations::on_session_lock`).
///
/// # Errors
/// The pass's failure; nothing was acknowledged and the lock stays latched.
pub async fn lock_pass_now(
    ops: &Operations,
    source: &dyn SessionLockSource,
) -> Result<LockRevocation, OpError> {
    let epoch = source.lock_epoch();
    ops.on_session_lock(
        LockEpoch {
            epoch: epoch.epoch,
            observed: true,
        },
        source,
    )
    .await
}

/// ⟨M03⟩ U9: the lock-pass driver, until `shutdown` resolves (module docs). It never
/// calls the source in a way that blocks, and it holds no lock across an await.
pub async fn run_lock_passes<S>(
    ops: Operations,
    source: Arc<dyn SessionLockSource>,
    config: LockPassConfig,
    shutdown: S,
) -> LockPassReport
where
    S: Future<Output = ()>,
{
    let mut shutdown = std::pin::pin!(shutdown);
    let mut report = LockPassReport::default();
    let mut last: Option<LockState> = None;
    let mut pending = false;
    let mut last_start: Option<tokio::time::Instant> = None;
    loop {
        // Register the wake-up before reading, so a change in between is not lost.
        let changed = source.changed();
        let mut changed = std::pin::pin!(changed);
        changed.as_mut().enable();
        let epoch = source.lock_epoch();
        let state = source.state();
        pending |= due(epoch, state, last);
        last = Some(state);
        if pending {
            let now = tokio::time::Instant::now();
            if let Some(start) = last_start {
                let next = start + config.min_interval;
                if now < next {
                    tokio::select! {
                        () = tokio::time::sleep_until(next) => {}
                        () = &mut shutdown => return report,
                    }
                    continue;
                }
            }
            last_start = Some(now);
            match lock_pass_now(&ops, source.as_ref()).await {
                Ok(done) => {
                    pending = false;
                    report.passes = report.passes.saturating_add(1);
                    report.epochs.push(done.epoch);
                    report.revoked.extend(done.revoked);
                }
                Err(e) => {
                    report.failures = report.failures.saturating_add(1);
                    tracing::warn!(code = %e.code, "a lock pass did not commit; the lock stays latched");
                    tokio::select! {
                        () = tokio::time::sleep(config.retry_after) => {}
                        () = &mut shutdown => return report,
                    }
                }
            }
            continue;
        }
        tokio::select! {
            () = &mut changed => {}
            () = &mut shutdown => return report,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn due_rule() {
        let none = LockEpoch::default();
        let latched = LockEpoch {
            epoch: 3,
            observed: true,
        };
        assert!(due(latched, LockState::Unlocked, Some(LockState::Unlocked)));
        assert!(!due(none, LockState::Unlocked, None));
        assert!(due(none, LockState::Locked, None), "locked at start");
        assert!(due(none, LockState::Unknown, None), "unknown at start");
        assert!(due(none, LockState::Unknown, Some(LockState::Unlocked)));
        assert!(!due(none, LockState::Unknown, Some(LockState::Unknown)));
        assert!(!due(none, LockState::Unavailable, None));
        assert!(
            !due(none, LockState::Locked, Some(LockState::Unlocked)),
            "a lock without a latch is the source's to latch"
        );
    }

    #[test]
    fn windows_format() {
        assert_eq!(format_window(Duration::from_secs(12 * 3600)), "12h");
        assert_eq!(format_window(Duration::from_secs(90 * 60)), "1h30m");
        assert_eq!(format_window(Duration::from_secs(45)), "45s");
        assert_eq!(format_window(Duration::ZERO), "0s");
    }

    #[test]
    fn signs_and_reissue_rules() {
        use LockBehavior::{Continue, RevokeOnLock};
        for s in [
            LockState::Locked,
            LockState::Unknown,
            LockState::Unavailable,
        ] {
            assert!(signs_while(Continue, s));
            assert!(!signs_while(RevokeOnLock, s), "{s:?}");
        }
        assert!(signs_while(RevokeOnLock, LockState::Unlocked));
        assert!(reissue_allowed(Continue));
        assert!(!reissue_allowed(RevokeOnLock));
    }
}
