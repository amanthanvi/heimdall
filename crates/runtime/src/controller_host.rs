//! ⟨M06 W3 host⟩ The controller's sync and issuance driver, hosted in the controller's
//! runtime (ADR-0012 §4.2, §7.1, §7.4, §8.3; ADR-0005 §3.5 "Remote reservations").
//!
//! A CLI command cannot write the controller's store while a runtime holds the instance
//! lock, and the issuer's barrier is process state, so the process that reconnects to the
//! recorded runners, drains the outbox and issues for them is the runtime. [`ControllerHost`]
//! is that task:
//!
//! * **Passes.** One pass visits every runner this installation records with a role that
//!   may deliver narrowing effects. It keeps one management session per runner open between
//!   passes; each pass runs ADR-0012 §7.4's order again over it
//!   (`ControllerSync::on_session`: effects first, then the report, the barrier, the time
//!   sample), then issues for the grants this controller delivered to that runner
//!   (`ControllerSync::maintain`). A pass runs at start, every [`ControllerHostWiring::interval`],
//!   and at once when a local narrowing became an outbox row
//!   ([`heimdall_app::remote_status_driver::OutboxDelivery`]).
//! * **Fail closed.** A session that cannot be opened, or a step that fails, closes the
//!   barrier for that runner, drops its session and records the failure in the contact
//!   record; the next pass reconnects. Nothing is issued for a runner whose pass failed. A
//!   runtime without an issuer (no CA) still resynchronizes and delivers; its issuance
//!   refuses and is recorded with each delivered grant.
//! * **Reported.** `environment status` reads what the passes recorded: connectivity (the
//!   session this instance holds, `HostedSession`), the pending effects, the last failure,
//!   and each delivered grant whose issuance failed.
//!
//! * **Backoff** (ADR-0012 §4 item 2, ⟨2026-11-21⟩ "The host's session"). While a runner is
//!   unreachable the host waits longer before each new attempt: the pass interval after the
//!   first failure, doubling with every further one, up to [`MAX_BACKOFF`]
//!   ([`backoff_delay`]). A pass inside that wait leaves the runner alone. The first success
//!   resets it. A pass the owner asked for (a forwarded `ensure`, a narrowing whose answer
//!   waits for delivery) tries at once.
//! * **Forwarding** ([`ControllerHost::forward_ensure`]). An `ensure` naming a recorded
//!   runner's environment is sent over that runner's session, and what was asked becomes this
//!   controller's delivered-grant record (`heimdall_app::remote_status_driver::forward_ensure`).
//!
//! A remote runner hosts nothing: it records no runners.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::remote_env::{ManagementSession, ManagementSessions};
use heimdall_app::remote_status::failure_reason;
use heimdall_app::remote_status_driver::{
    ControllerSync, OutboxDelivery, RemoteIssuer, SessionChannel, pins,
};
use heimdall_contract::controller_record::RemoteEnvironmentPin;
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::remote::Permission;
use heimdall_domain::time::Clock;
use heimdall_store::Store;
use heimdall_store::ext_effects::HostedSession;
use tokio_util::sync::CancellationToken;

/// How often a pass runs when nothing asks for one.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// The longest wait between two attempts to reach an unreachable runner ("about 5 minutes").
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// How long the host leaves a runner alone after its `failures`-th consecutive failed
/// attempt: `interval` after the first, doubling with each further one, never more than
/// [`MAX_BACKOFF`] (and never less than `interval`, when that is longer). Zero failures: no
/// wait.
#[must_use]
pub fn backoff_delay(interval: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let doubled = interval.saturating_mul(1u32.checked_shl(failures - 1).unwrap_or(u32::MAX));
    doubled.min(MAX_BACKOFF.max(interval))
}

/// One runner's consecutive failures and when the next attempt may start.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    failures: u32,
    not_before: tokio::time::Instant,
}

/// What the host is built from besides the runtime's own store, clock and issuer.
#[derive(Clone)]
pub struct ControllerHostWiring {
    /// Opens management sessions to the recorded runners (the CLI's wiring: K_mgmt, the
    /// recorded pins, never a prompt).
    pub sessions: Arc<dyn ManagementSessions>,
    /// The pause between passes.
    pub interval: Duration,
}

impl std::fmt::Debug for ControllerHostWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerHostWiring")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// The hosted driver (module docs).
pub struct ControllerHost {
    sync: ControllerSync,
    clock: Arc<dyn Clock>,
    sessions: Arc<dyn ManagementSessions>,
    issuer: Option<Arc<dyn RemoteIssuer>>,
    instance: String,
    interval: Duration,
    wake: tokio::sync::Notify,
    /// The sessions held between passes. Locked for a whole pass: passes never overlap.
    held: tokio::sync::Mutex<HashMap<EnvironmentId, Box<dyn ManagementSession>>>,
    /// The unreachable runners (module docs, "Backoff").
    backoff: std::sync::Mutex<HashMap<EnvironmentId, Backoff>>,
}

impl std::fmt::Debug for ControllerHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerHost").finish_non_exhaustive()
    }
}

/// The issuer of a runtime that has none: every issuance refuses, and the refusal is
/// recorded with the delivered grant.
struct NoIssuer;

#[async_trait::async_trait]
impl RemoteIssuer for NoIssuer {
    fn ca(&self) -> Result<heimdall_contract::ids::CaFingerprint, heimdall_app::OpError> {
        Err(heimdall_app::OpError::new(
            heimdall_contract::Code::CapabilityUnavailable,
            "this controller has no issuer: it cannot issue or renew for a runner's grants",
        )
        .with_reason(heimdall_contract::envelope::reason::ISSUER_UNAVAILABLE)
        .with_effect(heimdall_contract::EffectStatus::None))
    }

    fn verify(
        &self,
        _: &heimdall_app::remote_status_driver::RemoteAsk,
        _: serde_json::Value,
        _: heimdall_contract::Timestamp,
    ) -> Result<heimdall_app::remote_status_driver::RemoteSubject, heimdall_app::OpError> {
        Err(self.ca().err().unwrap_or_else(|| {
            heimdall_app::OpError::new(heimdall_contract::Code::InternalError, "no issuer")
        }))
    }

    async fn sign(
        &self,
        _: &heimdall_domain::issuance::IssuanceEntry,
        _: &str,
    ) -> Result<String, heimdall_app::OpError> {
        Err(self.ca().err().unwrap_or_else(|| {
            heimdall_app::OpError::new(heimdall_contract::Code::InternalError, "no issuer")
        }))
    }
}

impl ControllerHost {
    /// The host over this controller's `store` and `clock`, issuing through `issuer` (the
    /// runtime's issuer child, when it has one). `instance` names this runtime instance in
    /// the contact records (`heimdall_app::remote_status::instance_identity`).
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        wiring: ControllerHostWiring,
        issuer: Option<Arc<dyn RemoteIssuer>>,
        instance: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            sync: ControllerSync::new(store, clock.clone()),
            clock,
            sessions: wiring.sessions,
            issuer,
            instance,
            interval: wiring.interval,
            wake: tokio::sync::Notify::new(),
            held: tokio::sync::Mutex::new(HashMap::new()),
            backoff: std::sync::Mutex::new(HashMap::new()),
        })
    }

    fn backoffs(&self) -> std::sync::MutexGuard<'_, HashMap<EnvironmentId, Backoff>> {
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `environment` is inside its backoff wait now.
    fn backing_off(&self, environment: &EnvironmentId) -> bool {
        self.backoffs()
            .get(environment)
            .is_some_and(|b| tokio::time::Instant::now() < b.not_before)
    }

    /// An attempt to reach `environment` failed: the next one waits longer.
    fn note_unreachable(&self, environment: &EnvironmentId) {
        let mut all = self.backoffs();
        let failures = all
            .get(environment)
            .map_or(0, |b| b.failures)
            .saturating_add(1);
        all.insert(
            environment.clone(),
            Backoff {
                failures,
                not_before: tokio::time::Instant::now() + backoff_delay(self.interval, failures),
            },
        );
    }

    /// `environment` was reached: its backoff is reset.
    fn note_reached(&self, environment: &EnvironmentId) {
        self.backoffs().remove(environment);
    }

    /// The consecutive failed attempts to reach `environment` (0: reachable, or never tried).
    #[must_use]
    pub fn consecutive_failures(&self, environment: &EnvironmentId) -> u32 {
        self.backoffs().get(environment).map_or(0, |b| b.failures)
    }

    /// The driver (its barrier is this process's).
    #[must_use]
    pub fn sync(&self) -> &ControllerSync {
        &self.sync
    }

    fn store(&self) -> &Arc<Store> {
        self.sync.store()
    }

    /// The recorded runners a pass visits: those this installation's role may deliver
    /// narrowing effects to (ADR-0012's role table: `approve`). A limited role has nothing
    /// to resynchronize, so no session is opened for it.
    fn visited(&self) -> Vec<RemoteEnvironmentPin> {
        self.store()
            .transaction(pins)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.role.permissions().contains(&Permission::Approve))
            .collect()
    }

    fn mark(&self, environment: &EnvironmentId, open: bool) {
        let session = open.then(|| HostedSession {
            instance: self.instance.clone(),
            since: self.clock.wall(),
        });
        // An observation: a write failure changes nothing the barrier decides.
        let _ = self.store().transaction(|tx| {
            match (&session, tx.remote_contact(environment)?.hosted) {
                // Still the same instance's session: keep its first instant.
                (Some(new), Some(old)) if old.instance == new.instance => Ok(()),
                _ => tx.note_remote_session(environment, session.clone()),
            }
        });
    }

    /// The session to `environment` is gone: close the barrier, forget the marker and,
    /// when `error` says why, record it (the next pass reconnects).
    fn lost(&self, environment: &EnvironmentId, error: Option<&heimdall_app::OpError>) {
        self.sync.session_closed(environment);
        self.mark(environment, false);
        if let Some(e) = error {
            let why = failure_reason(e);
            let now = self.clock.wall();
            let _ = self
                .store()
                .transaction(|tx| tx.note_remote_failure(environment, now, &why));
        }
    }

    /// One pass over one runner: resynchronize over the held session, or reconnect, then
    /// issue for the delivered grants.
    /// Resynchronize with one runner: over the held session, or a new one. On success the
    /// session is held, the barrier is open and the backoff is reset. On failure the
    /// session is dropped, the failure is recorded and the next attempt waits longer.
    /// `force`: try even inside the backoff wait (the owner asked).
    async fn resynchronize(
        &self,
        pin: &RemoteEnvironmentPin,
        held: &mut HashMap<EnvironmentId, Box<dyn ManagementSession>>,
        force: bool,
    ) -> Result<heimdall_app::remote_status::ResyncOutcome, heimdall_app::OpError> {
        let environment = &pin.environment;
        // The held session first; a session that fails is dropped and one reconnect is
        // tried in the same pass.
        if let Some(session) = held.get_mut(environment) {
            match self.sync.on_session(pin, session.as_mut()).await {
                Ok(o) => {
                    self.note_reached(environment);
                    self.mark(environment, true);
                    return Ok(o);
                }
                Err(_) => {
                    held.remove(environment);
                    self.lost(environment, None);
                }
            }
        }
        if !force && self.backing_off(environment) {
            return Err(heimdall_app::OpError::new(
                heimdall_contract::Code::ServiceUnavailable,
                "the runner was unreachable; the next attempt waits for its backoff",
            )
            .with_effect(heimdall_contract::EffectStatus::None));
        }
        match self.sync.reconnect(self.sessions.as_ref(), pin).await {
            Ok((session, o)) => {
                held.insert(environment.clone(), session);
                self.note_reached(environment);
                self.mark(environment, true);
                Ok(o)
            }
            Err(e) => {
                // `reconnect` recorded an open failure; a failed step over the new
                // session is recorded here.
                self.lost(environment, Some(&e));
                self.note_unreachable(environment);
                tracing::warn!(code = %e.code, "a runner could not be resynchronized");
                Err(e)
            }
        }
    }

    async fn visit(
        &self,
        pin: &RemoteEnvironmentPin,
        held: &mut HashMap<EnvironmentId, Box<dyn ManagementSession>>,
        force: bool,
    ) {
        let environment = &pin.environment;
        let Ok(outcome) = self.resynchronize(pin, held, force).await else {
            return;
        };
        let Some(session) = held.get_mut(environment) else {
            return;
        };
        let no_issuer = NoIssuer;
        let issuer: &dyn RemoteIssuer = match &self.issuer {
            Some(i) => i.as_ref(),
            None => &no_issuer,
        };
        let maintained = match SessionChannel::new(session.as_mut()) {
            Ok(mut channel) => {
                self.sync
                    .maintain(pin, &mut channel, issuer, &outcome.report)
                    .await
            }
            Err(_) => return,
        };
        for (_, e) in &maintained.failed {
            tracing::warn!(code = %e.code, "remote issuance for a delivered grant failed");
        }
        // After an issuance the runner holds new certificates: its report is read again at
        // once, so the last-known readiness `environment status` shows is the current one
        // (and the barrier rests on a report that includes them).
        if !maintained.issued.is_empty()
            && let Err(e) = self.sync.on_session(pin, session.as_mut()).await
        {
            held.remove(environment);
            self.lost(environment, Some(&e));
            return;
        }
        // A transport failure during issuance leaves the session in an unknown state: it is
        // dropped, and the next pass reconnects and resynchronizes before anything else.
        if maintained
            .failed
            .iter()
            .any(|(_, e)| e.code == heimdall_contract::Code::OutcomeUnknown)
        {
            held.remove(environment);
            self.lost(environment, None);
        }
    }

    /// Forward `request`, an `ensure` naming a runner's environment, and answer for it
    /// (module docs, "Forwarding"). `None`: the environment is not a runner this
    /// installation records, and nothing was done. Otherwise, under the pass lock:
    /// resynchronize with that runner now, forward the request and record what was asked;
    /// when the grant then awaits this controller's issuer, issue for it in the same turn
    /// and read the request's state once more.
    pub async fn forward_ensure(
        &self,
        request: &heimdall_contract::request::EnsureRequest,
    ) -> Option<heimdall_app::OpResult<serde_json::Value>> {
        use heimdall_app::remote_status_driver::{Forwarded, forwarded_pending};
        let environment = request.environment.as_ref()?;
        let pin = self
            .store()
            .transaction(pins)
            .ok()?
            .into_iter()
            .find(|p| p.environment == *environment)?;
        let mut held = self.held.lock().await;
        Some(
            async {
                self.resynchronize(&pin, &mut held, true).await?;
                let first = self.forward_over(&pin, &mut held, request).await?;
                let grant = match first {
                    Forwarded::Ready { data, .. } => return Ok(ready(data)),
                    Forwarded::Pending { grant, .. } => grant,
                };
                // Issue now (the pass's own steps: resynchronize, issue, read the report
                // again), then read the request's state once more.
                self.visit(&pin, &mut held, true).await;
                match self.forward_over(&pin, &mut held, request).await {
                    Ok(Forwarded::Ready { data, .. }) => Ok(ready(data)),
                    _ => Err(forwarded_pending(&grant)),
                }
            }
            .await,
        )
    }

    /// One forwarded `ensure` over the held session of `pin`'s runner.
    async fn forward_over(
        &self,
        pin: &RemoteEnvironmentPin,
        held: &mut HashMap<EnvironmentId, Box<dyn ManagementSession>>,
        request: &heimdall_contract::request::EnsureRequest,
    ) -> Result<heimdall_app::remote_status_driver::Forwarded, heimdall_app::OpError> {
        let Some(session) = held.get_mut(&pin.environment) else {
            return Err(heimdall_app::OpError::new(
                heimdall_contract::Code::ServiceUnavailable,
                "the session to the runner was lost; repeat the request with the same request ID",
            ));
        };
        let forwarded = self
            .sync
            .forward_ensure(pin, session.as_mut(), request)
            .await;
        // A transport failure leaves the session in an unknown state: it is dropped, and
        // the next pass reconnects and resynchronizes before anything else.
        if forwarded
            .as_ref()
            .is_err_and(|e| e.code == heimdall_contract::Code::OutcomeUnknown)
        {
            held.remove(&pin.environment);
            self.lost(&pin.environment, None);
        }
        forwarded
    }

    /// One pass over every visited runner (module docs). Passes never overlap. A runner
    /// inside its backoff wait is left alone.
    pub async fn pass(&self) {
        self.pass_with(false).await;
    }

    /// A pass the owner asked for: every runner is tried now, whatever its backoff.
    pub async fn pass_now(&self) {
        self.pass_with(true).await;
    }

    async fn pass_with(&self, force: bool) {
        let mut held = self.held.lock().await;
        let pins = self.visited();
        // A runner no longer recorded (removed, or this device retired): its session ends.
        let gone: Vec<EnvironmentId> = held
            .keys()
            .filter(|e| !pins.iter().any(|p| p.environment == **e))
            .cloned()
            .collect();
        for environment in gone {
            held.remove(&environment);
            self.sync.session_closed(&environment);
            self.note_reached(&environment);
        }
        for pin in &pins {
            self.visit(pin, &mut held, force).await;
        }
    }

    /// Run passes until `shutdown` (module docs). Markers another instance left are cleared
    /// first; at the end every session is closed, every barrier with it.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        for pin in self.store().transaction(pins).unwrap_or_default() {
            self.mark(&pin.environment, false);
        }
        loop {
            // A pass is never cancelled part-way (a session would be left mid-exchange):
            // shutdown is observed between passes.
            self.pass().await;
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(self.interval) => {}
            }
        }
        let mut held = self.held.lock().await;
        for (environment, session) in held.drain() {
            drop(session);
            self.lost(&environment, None);
        }
    }
}

/// The runner's own `ensure` result, answered to the local caller as it stands there.
fn ready(data: serde_json::Value) -> heimdall_app::error::Completed<serde_json::Value> {
    heimdall_app::error::Completed::ok(heimdall_contract::Code::Ok, data)
}

#[async_trait::async_trait]
impl heimdall_app::remote_status_driver::EnsureForwarding for HostDelivery {
    async fn forward(
        &self,
        request: &heimdall_contract::request::EnsureRequest,
    ) -> Option<heimdall_app::OpResult<serde_json::Value>> {
        self.0.forward_ensure(request).await
    }
}

/// The host as the dispatcher's delivery hook.
#[derive(Debug, Clone)]
pub struct HostDelivery(pub Arc<ControllerHost>);

#[async_trait::async_trait]
impl OutboxDelivery for HostDelivery {
    fn notify(&self) {
        self.0.wake.notify_one();
    }

    async fn deliver(&self, bound: Duration) {
        // Its own pass (after any pass in flight), never cancelled: past `bound` the caller
        // stops waiting and the pass goes on.
        let host = Arc::clone(&self.0);
        let pass = tokio::spawn(async move { host.pass_now().await });
        let _ = tokio::time::timeout(bound, pass).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use heimdall_app::OpError;
    use heimdall_app::remote_env::SessionTarget;
    use heimdall_app::remote_status::{IssuanceGate, instance_identity, status_of_recorded};
    use heimdall_contract::Code;
    use heimdall_contract::controller_record::{ManagementHop, ManagementRoute};
    use heimdall_contract::envelope::reason;
    use heimdall_contract::ids::{AccountName, ClientId, DestinationId, KeyFingerprint};
    use heimdall_contract::remote::{Connectivity, Role};
    use heimdall_store::NoFaults;
    use heimdall_testkit::VirtualClock;

    use super::*;

    /// An opener that counts its calls and refuses each one as a changed host key.
    struct Refusing(AtomicUsize);

    #[async_trait::async_trait]
    impl ManagementSessions for Refusing {
        async fn open(&self, _: &SessionTarget) -> Result<Box<dyn ManagementSession>, OpError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(OpError::new(
                Code::HostTrustChanged,
                "the host key is not the pinned one",
            ))
        }
    }

    fn pin(byte: u8, role: Role) -> RemoteEnvironmentPin {
        RemoteEnvironmentPin {
            environment: EnvironmentId::from_random_bytes([byte; 16]),
            destination: DestinationId::parse(&format!("runner{byte}")).unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: "runner.example".into(),
                    port: None,
                    account: AccountName::parse("deploy").unwrap(),
                    host_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into()],
                },
                jump: None,
            },
            client: ClientId::from_random_bytes([byte; 16]),
            role,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "K".repeat(43))).unwrap(),
            label: None,
            pinned_at: "2026-11-21T09:00:00Z".parse().unwrap(),
        }
    }

    /// The schedule (ADR-0012 §4 item 2: a 30 s pass, doubling to about 5 minutes).
    #[test]
    fn the_backoff_doubles_from_the_pass_interval_to_five_minutes() {
        let secs = |failures| backoff_delay(DEFAULT_INTERVAL, failures).as_secs();
        assert_eq!(
            (0..=8).map(secs).collect::<Vec<_>>(),
            [0, 30, 60, 120, 240, 300, 300, 300, 300]
        );
        // Never overflows, whatever the count.
        assert_eq!(secs(u32::MAX), 300);
        // A longer configured interval is its own floor.
        assert_eq!(
            backoff_delay(Duration::from_secs(900), 3),
            Duration::from_secs(900)
        );
    }

    /// An unreachable runner is tried again only after its backoff: with a pass every 30 s
    /// the attempts fall at 0, 30, 90, 210, 450 and 750 s (waits of 30, 60, 120, 240 and
    /// 300 s); a pass the owner asked for tries at once and still counts.
    #[tokio::test(start_paused = true)]
    async fn an_unreachable_runner_is_retried_on_the_backoff_schedule() {
        let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
        let owned = pin(0x41, Role::Owner);
        store
            .transaction(|tx| {
                tx.put_remote_environment_pin(
                    &owned.environment,
                    &owned.destination,
                    &owned.route.runner.account,
                    &owned.key_fingerprint,
                    &serde_json::to_string(&owned).unwrap(),
                    owned.pinned_at,
                )
            })
            .unwrap();
        let sessions = Arc::new(Refusing(AtomicUsize::new(0)));
        let host = ControllerHost::new(
            store,
            VirtualClock::at(owned.pinned_at),
            ControllerHostWiring {
                sessions: sessions.clone(),
                interval: DEFAULT_INTERVAL,
            },
            None,
            instance_identity(7, "now"),
        );
        let mut attempts_at = Vec::new();
        for tick in 0..=30u64 {
            let before = sessions.0.load(Ordering::SeqCst);
            host.pass().await;
            if sessions.0.load(Ordering::SeqCst) > before {
                attempts_at.push(tick * 30);
            }
            tokio::time::advance(DEFAULT_INTERVAL).await;
        }
        assert_eq!(attempts_at, [0, 30, 90, 210, 450, 750]);
        assert_eq!(host.consecutive_failures(&owned.environment), 6);
        // Inside the wait, a pass the owner asked for still tries.
        let before = sessions.0.load(Ordering::SeqCst);
        host.pass().await;
        assert_eq!(
            sessions.0.load(Ordering::SeqCst),
            before,
            "inside the backoff"
        );
        host.pass_now().await;
        assert_eq!(sessions.0.load(Ordering::SeqCst), before + 1);
        assert_eq!(host.consecutive_failures(&owned.environment), 7);
    }

    /// A runner that cannot be reached fails closed and is reported: the failure is on
    /// record with its reason, the barrier stays closed, no session is marked, and
    /// `environment status` reads `unreachable` with issuance gated. A recorded runner this
    /// installation holds a limited role on is never opened.
    #[tokio::test]
    async fn an_unreachable_runner_fails_closed_and_is_reported() {
        let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
        let (owned, viewed) = (pin(0x41, Role::Owner), pin(0x42, Role::Viewer));
        store
            .transaction(|tx| {
                for p in [&owned, &viewed] {
                    tx.put_remote_environment_pin(
                        &p.environment,
                        &p.destination,
                        &p.route.runner.account,
                        &p.key_fingerprint,
                        &serde_json::to_string(p).unwrap(),
                        p.pinned_at,
                    )?;
                }
                // A marker another runtime instance left behind.
                tx.note_remote_session(
                    &owned.environment,
                    Some(HostedSession {
                        instance: instance_identity(1, "earlier"),
                        since: owned.pinned_at,
                    }),
                )
            })
            .unwrap();
        let clock = VirtualClock::at(owned.pinned_at);
        let sessions = Arc::new(Refusing(AtomicUsize::new(0)));
        let instance = instance_identity(7, "now");
        let host = ControllerHost::new(
            store.clone(),
            clock.clone(),
            ControllerHostWiring {
                sessions: sessions.clone(),
                interval: Duration::from_secs(3600),
            },
            None,
            instance.clone(),
        );
        let view = |live: Option<&str>| {
            store
                .transaction(|tx| status_of_recorded(tx, &owned.environment, live, clock.wall()))
                .unwrap()
        };
        // The stale marker says nothing to a reader of the instance running now.
        assert_ne!(view(Some(&instance)).connectivity, Connectivity::Connected);
        // ... and would only count for the instance that wrote it.
        assert_eq!(
            view(Some(&instance_identity(1, "earlier"))).connectivity,
            Connectivity::Connected
        );

        host.pass().await;
        assert_eq!(
            sessions.0.load(Ordering::SeqCst),
            1,
            "the owned runner only"
        );
        let contact = store
            .transaction(|tx| tx.remote_contact(&owned.environment))
            .unwrap();
        assert_eq!(
            contact.last_failure.map(|f| f.reason).as_deref(),
            Some(reason::ENVIRONMENT_IDENTITY_MISMATCH),
            "a changed host key is held"
        );
        assert!(contact.hosted.is_none(), "no session is marked");
        assert!(
            host.sync()
                .barrier()
                .reconciliation(&owned.environment)
                .is_none()
        );
        let status = view(Some(&instance));
        assert_eq!(
            status.connectivity,
            Connectivity::Unreachable {
                reason: reason::ENVIRONMENT_IDENTITY_MISMATCH.to_owned()
            }
        );
        assert_eq!(status.issuance, IssuanceGate::AwaitingResync);
        // The limited role's runner was never touched.
        let other = store
            .transaction(|tx| tx.remote_contact(&viewed.environment))
            .unwrap();
        assert!(other.last_failure.is_none() && other.last_seen_at.is_none());

        // The delivery hook runs a pass of its own and returns within its bound.
        HostDelivery(Arc::clone(&host))
            .deliver(Duration::from_secs(5))
            .await;
        assert_eq!(sessions.0.load(Ordering::SeqCst), 2);
    }
}
