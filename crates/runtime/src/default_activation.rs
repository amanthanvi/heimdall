//! Personal default and ordinary-`ssh` activation (M05 U5; ADR-0011 §3.1–§3.3, §10 items 4
//! and 7; m05-plan U5). Owner: the M05 track.
//!
//! The runtime's implementation of `heimdall_app::ports::DefaultActivation` over
//! `Operations` ([`DefaultActivator`]), and the authority the environment endpoint's signer
//! is built with ([`ActivatingAuthority`]: the runtime's `SignatureAuthority`, unchanged,
//! plus the activation its `Signer::identities` calls).
//!
//! **One wait** ([`DefaultActivator`]'s `ensure_default`): read the state
//! (`Operations::default_activation_state`, one transaction). No default, already active,
//! blocked (pause, stop, cutoff, uncertain time) or not covered answer **at once**; so does
//! a refusal of the same basis (the default policy, its revision and the authority
//! generation) within [`RETRY_INTERVAL`]. Otherwise the caller joins the environment's one
//! activation in flight, or starts it, and waits for it until its budget ends.
//!
//! **Single-flight per environment, and a caller timeout is not a cancellation** (ADR-0011
//! §10 item 7). The activation runs in a task of its own (`Operations::activate_default`):
//! every concurrent identities request shares it, and none of them owns it, so a caller
//! whose wait ends (or whose connection drops) leaves it running; once committed it stays
//! applied and the next request finds it active. Only the runtime's shutdown stops it
//! between steps (the pipeline's own work runs to its end regardless).
//!
//! **Events** (ADR-0006 §17 item 8): `activated` once per activation (recorded by the
//! application); `blocked` and `not_covered` at most once per policy, kind and reason per
//! [`EVENT_INTERVAL`] ([`EventLimiter`]; in memory, so a restart may record one more).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use heimdall_app::Operations;
use heimdall_app::managed::SignPermit;
use heimdall_app::operations::{DefaultBasis, DefaultOutcome, DefaultState};
use heimdall_app::ports::{
    DefaultActivation, DefaultWait, SignRefusal, SignatureAuthority, SignatureRequestFacts,
};
use heimdall_contract::ids::{EnvironmentId, PolicyId};
use heimdall_contract::trust::{ActivationEventKind, ActivationEventPayload};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_ipc::endpoint::ExpectedOwner;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// How long a refused or failed activation of one basis is not retried (the next
/// identities requests of the same basis answer at once).
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// At most one `blocked` (and one `not_covered`) event per policy and reason per this
/// interval (ADR-0011 §3.2 "at most one `activation_blocked` event per policy and reason
/// per hour").
pub const EVENT_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The owner principal the activation acts as: the runtime's own user, as its control
/// endpoint authenticates the owner's CLI (`dispatch::caller_for`), so the default work's
/// bindings belong to the owner and the owner's commands see and end them.
#[must_use]
pub fn owner_context(owner: &ExpectedOwner) -> CallerContext {
    let principal = match owner {
        ExpectedOwner::Uid(uid) => PrincipalRef::UnixUser { uid: *uid },
        ExpectedOwner::Sid(sid) => PrincipalRef::WindowsUser { sid: sid.clone() },
    };
    CallerContext {
        principal,
        role: ClientRole::Owner,
    }
}

/// At most one event per policy, kind and reason per interval.
#[derive(Debug)]
pub struct EventLimiter {
    interval: Duration,
    last: HashMap<(PolicyId, ActivationEventKind, String), Instant>,
}

impl Default for EventLimiter {
    fn default() -> Self {
        EventLimiter::new(EVENT_INTERVAL)
    }
}

impl EventLimiter {
    /// A limiter with `interval`.
    #[must_use]
    pub fn new(interval: Duration) -> EventLimiter {
        EventLimiter {
            interval,
            last: HashMap::new(),
        }
    }

    /// Whether an event of `kind` for `policy` and `reason` may be recorded at `now`
    /// (and, when it may, remember it).
    pub fn admit(
        &mut self,
        policy: &PolicyId,
        kind: ActivationEventKind,
        reason: &str,
        now: Instant,
    ) -> bool {
        let interval = self.interval;
        self.last
            .retain(|_, at| now.saturating_duration_since(*at) < interval);
        let key = (policy.clone(), kind, reason.to_owned());
        if self.last.contains_key(&key) {
            return false;
        }
        self.last.insert(key, now);
        true
    }
}

/// A refusal remembered against its basis.
#[derive(Debug, Clone)]
struct Refusal {
    basis: DefaultBasis,
    until: Instant,
    answer: DefaultWait,
}

/// The environment's activation in flight.
struct Flight {
    id: u64,
    rx: watch::Receiver<Option<DefaultWait>>,
}

#[derive(Default)]
struct State {
    flight: Option<Flight>,
    next_id: u64,
    refused: Option<Refusal>,
    events: EventLimiter,
}

struct Inner {
    ops: Operations,
    environment: EnvironmentId,
    owner: CallerContext,
    executable: String,
    stop: CancellationToken,
    retry: Duration,
    state: Mutex<State>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // The state holds plain values only; a panic while holding it leaves them usable.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record `kind` for `policy` when the limiter admits it (off the caller's path).
    fn note(self: &Arc<Self>, policy: &PolicyId, kind: ActivationEventKind, reason: &str) {
        if !self
            .lock()
            .events
            .admit(policy, kind, reason, Instant::now())
        {
            return;
        }
        let payload = ActivationEventPayload {
            kind,
            environment_id: self.environment.clone(),
            policy_id: Some(policy.clone()),
            workspace_id: None,
            reason: Some(reason.to_owned()),
        };
        let ops = self.ops.clone();
        tokio::spawn(async move {
            if let Err(e) = ops.record_activation_event(payload).await {
                tracing::warn!(code = %e.code, "could not record an activation event");
            }
        });
    }

    /// The answer for an outcome nothing needs to be started for (and its event).
    fn answer(self: &Arc<Self>, outcome: &DefaultOutcome) -> DefaultWait {
        match outcome {
            DefaultOutcome::NoDefault => DefaultWait::NoDefault,
            DefaultOutcome::Active { .. } => DefaultWait::Active,
            DefaultOutcome::Activated { .. } => DefaultWait::Activated,
            DefaultOutcome::Blocked { policy, reason } => {
                self.note(policy, ActivationEventKind::Blocked, reason);
                DefaultWait::Blocked {
                    reason: reason.clone(),
                }
            }
            DefaultOutcome::NotCovered { policy, reason } => {
                self.note(policy, ActivationEventKind::NotCovered, reason);
                DefaultWait::NotCovered
            }
            DefaultOutcome::Failed { reason, .. } => DefaultWait::Failed {
                reason: reason.clone(),
            },
        }
    }

    /// The remembered answer for `basis`, while its retry interval lasts.
    fn recently_refused(&self, basis: &DefaultBasis) -> Option<DefaultWait> {
        let s = self.lock();
        s.refused
            .as_ref()
            .filter(|r| r.basis == *basis && Instant::now() < r.until)
            .map(|r| r.answer.clone())
    }

    /// Join the activation in flight, or start it.
    fn join_or_start(
        self: &Arc<Self>,
        basis: DefaultBasis,
    ) -> watch::Receiver<Option<DefaultWait>> {
        let mut s = self.lock();
        if let Some(f) = &s.flight {
            return f.rx.clone();
        }
        let (tx, rx) = watch::channel(None);
        let id = s.next_id;
        s.next_id = s.next_id.wrapping_add(1);
        s.flight = Some(Flight { id, rx: rx.clone() });
        drop(s);
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let outcome = tokio::select! {
                o = me.ops.activate_default(&me.owner, &me.environment, &me.executable) => Some(o),
                () = me.stop.cancelled() => None,
            };
            let answer = match &outcome {
                Some(o) => me.answer(o),
                None => DefaultWait::Failed {
                    reason: "runtime_stopping".to_owned(),
                },
            };
            if let Some(o) = &outcome {
                match o {
                    DefaultOutcome::Failed { reason, .. } => {
                        tracing::warn!(reason = %reason, "the default activation failed");
                    }
                    DefaultOutcome::Activated { work_id, .. } => {
                        tracing::info!(work = %work_id, "the default personal policy was activated");
                    }
                    _ => {}
                }
            }
            {
                let mut s = me.lock();
                if matches!(
                    answer,
                    DefaultWait::NotCovered
                        | DefaultWait::Failed { .. }
                        | DefaultWait::Blocked { .. }
                ) {
                    s.refused = Some(Refusal {
                        basis,
                        until: Instant::now() + me.retry,
                        answer: answer.clone(),
                    });
                }
                if s.flight.as_ref().is_some_and(|f| f.id == id) {
                    s.flight = None;
                }
            }
            let _ = tx.send(Some(answer));
        });
        rx
    }

    async fn wait_for(self: Arc<Self>, wait: Duration) -> DefaultWait {
        let deadline = Instant::now() + wait;
        let state = match tokio::time::timeout_at(
            deadline,
            self.ops.default_activation_state(&self.environment),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return DefaultWait::Failed {
                    reason: e
                        .reason
                        .clone()
                        .unwrap_or_else(|| e.code.as_str().to_ascii_lowercase()),
                };
            }
            Err(_) => return DefaultWait::Pending,
        };
        let basis = match state {
            DefaultState::Settled(o) => return self.answer(&o),
            DefaultState::Needed(b) => b,
        };
        if let Some(answer) = self.recently_refused(&basis) {
            return answer;
        }
        let mut rx = self.join_or_start(basis);
        match tokio::time::timeout_at(deadline, rx.wait_for(Option::is_some)).await {
            Ok(Ok(v)) => v.clone().unwrap_or(DefaultWait::Pending),
            // The task ended without an answer (it panicked): nothing is known.
            Ok(Err(_)) => DefaultWait::Failed {
                reason: "activation_gone".to_owned(),
            },
            Err(_) => DefaultWait::Pending,
        }
    }
}

/// The runtime's [`DefaultActivation`] for one environment (module docs). Cheap to clone.
#[derive(Clone)]
pub struct DefaultActivator {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for DefaultActivator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultActivator")
            .field("environment", &self.inner.environment)
            .finish_non_exhaustive()
    }
}

impl DefaultActivator {
    /// The activation of `environment`'s personal default over `ops`, acting as `owner`
    /// ([`owner_context`]), its launch binds naming `executable` (absolute: the ordinary
    /// `ssh` client's path, else the runtime's own executable), stopping between steps
    /// when `stop` is cancelled.
    #[must_use]
    pub fn new(
        ops: Operations,
        environment: EnvironmentId,
        owner: CallerContext,
        executable: String,
        stop: CancellationToken,
    ) -> DefaultActivator {
        DefaultActivator {
            inner: Arc::new(Inner {
                ops,
                environment,
                owner,
                executable,
                stop,
                retry: RETRY_INTERVAL,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// The same activator with another retry interval (tests). Call before first use.
    #[must_use]
    pub fn with_retry_interval(self, retry: Duration) -> DefaultActivator {
        let i = &self.inner;
        DefaultActivator {
            inner: Arc::new(Inner {
                ops: i.ops.clone(),
                environment: i.environment.clone(),
                owner: i.owner.clone(),
                executable: i.executable.clone(),
                stop: i.stop.clone(),
                retry,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Whether an activation is in flight now (tests and diagnostics).
    #[must_use]
    pub fn in_flight(&self) -> bool {
        self.inner.lock().flight.is_some()
    }
}

impl DefaultActivation for DefaultActivator {
    fn ensure_default(
        &self,
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = DefaultWait> + Send + '_>> {
        Box::pin(Arc::clone(&self.inner).wait_for(wait))
    }
}

/// The last resort of [`launch_executable`] (the platform's usual OpenSSH client path).
pub const FALLBACK_EXECUTABLE: &str = if cfg!(windows) {
    r"C:\Windows\System32\OpenSSH\ssh.exe"
} else {
    "/usr/bin/ssh"
};

/// The executable a default activation's launch bind names: the selected `ssh` client
/// when it is an absolute path, else the runtime's own executable, else `fallback`.
#[must_use]
pub fn launch_executable(ssh: Option<&std::path::Path>, fallback: &str) -> String {
    ssh.filter(|p| p.is_absolute())
        .and_then(|p| p.to_str())
        .map(str::to_owned)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .filter(|p| p.is_absolute())
                .and_then(|p| p.to_str().map(str::to_owned))
        })
        .unwrap_or_else(|| fallback.to_owned())
}

/// The environment endpoint's authority: `authority` for every signature, unchanged, and
/// `activation` for `Signer::identities` (`SignatureAuthority::default_activation`).
pub struct ActivatingAuthority {
    authority: Arc<dyn SignatureAuthority>,
    activation: Arc<dyn DefaultActivation>,
}

impl std::fmt::Debug for ActivatingAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivatingAuthority")
            .finish_non_exhaustive()
    }
}

impl ActivatingAuthority {
    /// `authority` with `activation`.
    #[must_use]
    pub fn new(
        authority: Arc<dyn SignatureAuthority>,
        activation: Arc<dyn DefaultActivation>,
    ) -> ActivatingAuthority {
        ActivatingAuthority {
            authority,
            activation,
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl SignatureAuthority for ActivatingAuthority {
    fn precheck<'a, 'b, 'c>(
        &'a self,
        facts: &'b SignatureRequestFacts,
    ) -> BoxFuture<'c, Result<(), SignRefusal>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        self.authority.precheck(facts)
    }

    fn admit<'a, 'b, 'c>(
        &'a self,
        facts: &'b SignatureRequestFacts,
    ) -> BoxFuture<'c, Result<SignPermit, SignRefusal>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        self.authority.admit(facts)
    }

    fn default_activation(&self) -> Option<&dyn DefaultActivation> {
        Some(&*self.activation)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// ADR-0011 §3.2: at most one `blocked` event per policy and reason per interval; another
    /// policy, kind or reason is its own key, and the interval's end admits the next.
    #[test]
    fn event_limiter_admits_one_per_policy_kind_and_reason_per_interval() {
        let mut l = EventLimiter::new(Duration::from_secs(3600));
        let p = PolicyId::parse("pol-a").unwrap();
        let q = PolicyId::parse("pol-b").unwrap();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert!(l.admit(&p, ActivationEventKind::Blocked, "policy_paused", at(0)));
        assert!(!l.admit(&p, ActivationEventKind::Blocked, "policy_paused", at(1)));
        assert!(!l.admit(&p, ActivationEventKind::Blocked, "policy_paused", at(3599)));
        assert!(l.admit(&p, ActivationEventKind::Blocked, "policy_cutoff", at(2)));
        assert!(l.admit(&q, ActivationEventKind::Blocked, "policy_paused", at(2)));
        assert!(l.admit(&p, ActivationEventKind::NotCovered, "policy_paused", at(2)));
        assert!(l.admit(&p, ActivationEventKind::Blocked, "policy_paused", at(3600)));
        assert!(!l.admit(&p, ActivationEventKind::Blocked, "policy_paused", at(3601)));
    }

    #[test]
    fn launch_executable_prefers_an_absolute_ssh_path() {
        let abs = if cfg!(windows) {
            std::path::PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe")
        } else {
            std::path::PathBuf::from("/usr/bin/ssh")
        };
        assert_eq!(
            launch_executable(Some(&abs), "/fallback"),
            abs.to_str().unwrap()
        );
        let relative = launch_executable(Some(std::path::Path::new("ssh")), "/fallback");
        assert!(std::path::Path::new(&relative).is_absolute() || relative == "/fallback");
    }
}
