//! ⟨M04 U4b⟩ The runtime's bridge registry and supervisor for WSL Mode B (ADR-0010 §3 items
//! 3–14; §10 item 2; the integrator's design `design-u4.md` §5).
//!
//! * [`BridgeRegistry`] holds **one helper session per Mode B environment** (a
//!   [`BridgeApi`], U4a's `heimdall_wsl::Bridge` in production) and is the
//!   [`WslRealizer`] the endpoint registry calls: it answers the helper's run directory,
//!   realizes and withdraws binding endpoints by generation, stops the helper when the last
//!   binding is withdrawn, and serves each stream a helper relays with that binding's signer
//!   ([`heimdall_credential::endpoints::EndpointRegistry::serve_wsl_stream`]).
//! * **Starting.** A bridge starts on the first realize, with
//!   [`DistributionStart::Forbidden`]: it starts only a distribution that already runs.
//!   [`WslRealizer::start`] is the one start that may start a stopped distribution, and only
//!   the owner's own `ensure` naming the environment calls it
//!   (`Operations::wsl_start_for_ensure`). The supervisor and the restart paths never do
//!   (ADR-0010 §10 item 2).
//! * **Re-check.** [`BridgeRegistry::supervise`] runs every 10 s: a GUID that discovery no
//!   longer lists retires its environment as `gone` (without a rollback of files that are
//!   gone); for an environment that has bindings, the running listing (which starts nothing)
//!   moves the row between `active` and `not_running`, and a distribution that runs again
//!   gets its helper respawned and the current generations realized again.
//! * **Leftovers.** A withdrawal that cannot reach a stopped distribution is not an error:
//!   the Windows side has already ended the binding (the signer refuses at once), and the
//!   in-distribution directory is a retained obligation the next helper start removes
//!   (`cleanup_pending`, reported by `wsl disable`).
//!
//! No method here takes a lock across a call into the helper channel.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::Duration;

use heimdall_app::Operations;
use heimdall_app::ports::{
    AdapterError, DistributionHost, DistributionStart, DistributionTarget, RunningState,
};
use heimdall_contract::Timestamp;
use heimdall_contract::environment::{DistributionGuid, HelperState};
use heimdall_contract::ids::{BindingId, EnvironmentId};
use heimdall_credential::endpoints::wsl::{WeakEndpointRegistry, WslPublic, WslRealizer};
use heimdall_domain::environment::EnvironmentRealization;
use heimdall_domain::resource::ResourceGeneration;
use heimdall_store::Store;
use heimdall_wsl::{Bridge, BridgePublic, HelperLauncher, Realized, SessionError, StreamHandler};
use tokio_util::sync::CancellationToken;

/// How often the supervisor re-checks (ADR-0010 §3 item 10).
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(10);

/// How long a `realize` may take before it is refused (the helper channel's own bound).
const REALIZE_DEADLINE_SECS: i64 = 30;

/// One helper session, as the registry uses it (`design-u4.md` §2). U4a's
/// `heimdall_wsl::Bridge` implements it; the tests' fake implements it too.
pub trait BridgeApi: Send + Sync {
    /// The helper's run directory (an absolute Linux path from its hello).
    fn run_dir(&self) -> String;
    /// Realize `tag` at `generation` (idempotent for the same tag and generation).
    ///
    /// # Errors
    /// [`SessionError`].
    fn realize(
        &self,
        tag: &str,
        generation: u64,
        public: BridgePublic,
        deadline: Timestamp,
    ) -> Result<Realized, SessionError>;
    /// Withdraw `tag` at exactly `generation`; a newer generation is never removed.
    ///
    /// # Errors
    /// [`SessionError`].
    fn withdraw(&self, tag: &str, generation: u64) -> Result<(), SessionError>;
    /// Whether the helper process and its channel are alive.
    fn alive(&self) -> bool;
    /// The bindings the helper currently serves.
    ///
    /// # Errors
    /// [`SessionError`].
    fn realized(&self) -> Result<Vec<(String, u64)>, SessionError>;
}

impl BridgeApi for Bridge {
    fn run_dir(&self) -> String {
        Bridge::run_dir(self).to_owned()
    }
    fn realize(
        &self,
        tag: &str,
        generation: u64,
        public: BridgePublic,
        deadline: Timestamp,
    ) -> Result<Realized, SessionError> {
        Bridge::realize(self, tag, generation, public, deadline)
    }
    fn withdraw(&self, tag: &str, generation: u64) -> Result<(), SessionError> {
        Bridge::withdraw(self, tag, generation)
    }
    fn alive(&self) -> bool {
        Bridge::alive(self)
    }
    fn realized(&self) -> Result<Vec<(String, u64)>, SessionError> {
        Bridge::realized(self)
    }
}

/// Starts helper sessions: the seam a test replaces with a fake.
pub trait BridgeFactory: Send + Sync {
    /// Start a helper for `target` (`start` is U3b's policy) whose relayed streams go to
    /// `streams`.
    ///
    /// # Errors
    /// [`SessionError`]; a stopped distribution without `start` is `NotRunning`.
    fn start(
        &self,
        target: &DistributionTarget,
        start: DistributionStart,
        streams: Arc<dyn StreamHandler>,
    ) -> Result<Arc<dyn BridgeApi>, SessionError>;
}

/// The production factory: `heimdall_wsl::Bridge` over a [`HelperLauncher`].
pub struct LauncherBridgeFactory {
    launcher: Arc<dyn HelperLauncher>,
}

impl LauncherBridgeFactory {
    /// A factory over `launcher` (`WslHost::launcher`).
    #[must_use]
    pub fn new(launcher: Arc<dyn HelperLauncher>) -> Self {
        Self { launcher }
    }
}

impl BridgeFactory for LauncherBridgeFactory {
    fn start(
        &self,
        target: &DistributionTarget,
        start: DistributionStart,
        streams: Arc<dyn StreamHandler>,
    ) -> Result<Arc<dyn BridgeApi>, SessionError> {
        let bridge = Bridge::start(Arc::clone(&self.launcher), target, start, streams)?;
        Ok(Arc::new(bridge))
    }
}

/// What the registry remembers of a realized tag, to realize it again after a respawn.
struct TagState {
    binding: BindingId,
    generation: u64,
    public: WslPublic,
}

/// One Mode B environment's helper and desired endpoints.
#[derive(Default)]
struct EnvState {
    bridge: Option<Arc<dyn BridgeApi>>,
    /// The tags realized (tag → binding and generation): the desired endpoint set.
    tags: BTreeMap<String, TagState>,
    /// A withdrawal could not reach the distribution: its directory is left for the next
    /// helper start.
    pending: bool,
    /// The last helper start failed for a reason other than a stopped distribution.
    helper_unavailable: bool,
}

struct Inner {
    store: Arc<Store>,
    own: EnvironmentId,
    host: Arc<dyn DistributionHost>,
    factory: Arc<dyn BridgeFactory>,
    endpoints: OnceLock<WeakEndpointRegistry>,
    runtime: tokio::runtime::Handle,
    recheck: Duration,
    /// One helper start at a time.
    start_gate: Mutex<()>,
    /// Environments whose GUID the last re-check did not find: `gone` is terminal, so a
    /// distribution must be missing from **two consecutive** listings before it retires.
    missing: Mutex<std::collections::BTreeSet<EnvironmentId>>,
    state: Mutex<BTreeMap<EnvironmentId, EnvState>>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<EnvironmentId, EnvState>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The runtime's bridge registry and supervisor (module docs). Cloning shares it.
#[derive(Clone)]
pub struct BridgeRegistry {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for BridgeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeRegistry")
            .field("environments", &self.inner.lock().len())
            .finish_non_exhaustive()
    }
}

fn adapter_error(e: SessionError) -> AdapterError {
    e.into_adapter()
}

fn unavailable(why: &str) -> AdapterError {
    AdapterError::Unavailable(why.to_owned())
}

impl BridgeRegistry {
    /// A registry for the environments `own` manages, reading their rows from `store`,
    /// asking `host` which distributions exist and run, and starting helpers through
    /// `factory`. `runtime` carries the stream-serving tasks. Attach the endpoint registry
    /// with [`Self::attach`] and install the registry with
    /// `EndpointRegistry::set_wsl_realizer`.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        own: EnvironmentId,
        host: Arc<dyn DistributionHost>,
        factory: Arc<dyn BridgeFactory>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                own,
                host,
                factory,
                endpoints: OnceLock::new(),
                runtime,
                recheck: RECHECK_INTERVAL,
                start_gate: Mutex::new(()),
                missing: Mutex::new(std::collections::BTreeSet::new()),
                state: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// The same registry with another re-check interval (the tests'). Call before sharing.
    #[must_use]
    pub fn with_recheck(self, recheck: Duration) -> Self {
        let i = &self.inner;
        Self {
            inner: Arc::new(Inner {
                store: Arc::clone(&i.store),
                own: i.own.clone(),
                host: Arc::clone(&i.host),
                factory: Arc::clone(&i.factory),
                endpoints: OnceLock::new(),
                runtime: i.runtime.clone(),
                recheck,
                start_gate: Mutex::new(()),
                missing: Mutex::new(std::collections::BTreeSet::new()),
                state: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Where relayed streams are served: the endpoint registry (held weakly). Once.
    pub fn attach(&self, endpoints: WeakEndpointRegistry) {
        let _ = self.inner.endpoints.set(endpoints);
    }

    // --- the target and the helper's life ---------------------------------------------------

    /// The target of `environment`'s helper: its row's GUID and account, and the name
    /// discovery reports now (a renamed distribution keeps its environment). A row out of the
    /// set resolves only with `any_state` (a disable's own cleanup).
    fn target_of(
        &self,
        environment: &EnvironmentId,
        any_state: bool,
    ) -> Result<DistributionTarget, AdapterError> {
        let (env, own) = (environment.clone(), self.inner.own.clone());
        let row = self
            .inner
            .store
            .transaction(|tx| {
                Ok(tx
                    .managed_environment(&env)?
                    .filter(|r| r.controller == own))
            })
            .map_err(|_| unavailable("wsl_helper_unavailable"))?;
        let Some(row) = row.filter(|r| any_state || r.state.in_set()) else {
            return Err(unavailable("wsl_helper_unavailable"));
        };
        let EnvironmentRealization::Wsl { guid, account, .. } = row.realization else {
            return Err(unavailable("wsl_helper_unavailable"));
        };
        let listed = self.inner.host.discover()?;
        let found = listed
            .into_iter()
            .find(|d| d.guid == guid)
            .ok_or_else(|| unavailable("wsl_helper_unavailable: the distribution is gone"))?;
        Ok(DistributionTarget {
            guid,
            name: found.name,
            account,
            namespace: environment.clone(),
        })
    }

    /// `environment`'s live helper, dropping a dead one (its tags stay: they are what a
    /// respawn realizes again).
    fn live_bridge(&self, environment: &EnvironmentId) -> Option<Arc<dyn BridgeApi>> {
        let mut dead = None;
        let live = {
            let mut g = self.inner.lock();
            let st = g.get_mut(environment)?;
            match st.bridge.clone() {
                Some(b) if b.alive() => Some(b),
                Some(_) => {
                    dead = st.bridge.take();
                    None
                }
                None => None,
            }
        };
        drop(dead);
        live
    }

    /// `environment`'s helper, started when none lives (module docs: `start`).
    fn ensure_bridge(
        &self,
        environment: &EnvironmentId,
        start: DistributionStart,
        any_state: bool,
    ) -> Result<Arc<dyn BridgeApi>, AdapterError> {
        if let Some(b) = self.live_bridge(environment) {
            return Ok(b);
        }
        let _gate = self
            .inner
            .start_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(b) = self.live_bridge(environment) {
            return Ok(b);
        }
        let target = self.target_of(environment, any_state)?;
        let streams: Arc<dyn StreamHandler> = Arc::new(Streams {
            inner: Arc::downgrade(&self.inner),
            environment: environment.clone(),
        });
        let bridge = match self.inner.factory.start(&target, start, streams) {
            Ok(b) => b,
            Err(e) => {
                let hard = !matches!(e, SessionError::NotRunning);
                self.inner
                    .lock()
                    .entry(environment.clone())
                    .or_default()
                    .helper_unavailable = hard;
                return Err(adapter_error(e));
            }
        };
        let tags: Vec<(String, u64, WslPublic)> = {
            let mut g = self.inner.lock();
            let st = g.entry(environment.clone()).or_default();
            st.bridge = Some(Arc::clone(&bridge));
            st.helper_unavailable = false;
            // The helper's startup removed the leftovers of a binding it was not asked to
            // realize (design §4): nothing stays pending.
            st.pending = false;
            st.tags
                .iter()
                .map(|(t, s)| (t.clone(), s.generation, s.public.clone()))
                .collect()
        };
        // A respawn realizes the current generations again.
        for (tag, generation, public) in tags {
            if let Err(e) = bridge.realize(&tag, generation, to_bridge(&public), deadline()) {
                tracing::warn!(code = %e.code(), "a Mode B endpoint could not be realized again");
            }
        }
        Ok(bridge)
    }

    /// Realize `environment`'s current generations again on its live helper (idempotent
    /// there; a deleted socket is recreated). A tag withdrawn meanwhile is withdrawn again,
    /// so a re-check never brings back the endpoint of an ended binding.
    fn realize_again(&self, environment: &EnvironmentId, bridge: &Arc<dyn BridgeApi>) {
        let tags: Vec<(String, u64, WslPublic)> = self
            .inner
            .lock()
            .get(environment)
            .map(|st| {
                st.tags
                    .iter()
                    .map(|(t, s)| (t.clone(), s.generation, s.public.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for (tag, generation, public) in tags {
            if let Err(e) = bridge.realize(&tag, generation, to_bridge(&public), deadline()) {
                tracing::warn!(code = %e.code(), "a Mode B endpoint could not be realized again");
                continue;
            }
            let still = self.inner.lock().get(environment).is_some_and(|st| {
                st.tags
                    .get(&tag)
                    .is_some_and(|t| t.generation == generation)
            });
            if !still {
                let _ = bridge.withdraw(&tag, generation);
            }
        }
    }

    /// Whether `environment` has endpoints to keep up.
    fn has_bindings(&self, environment: &EnvironmentId) -> bool {
        self.inner
            .lock()
            .get(environment)
            .is_some_and(|s| !s.tags.is_empty())
    }

    // --- the supervisor ---------------------------------------------------------------------

    /// One re-check (module docs). The supervisor calls it every [`RECHECK_INTERVAL`]; the
    /// tests call it directly.
    pub async fn tick(&self, ops: &Operations) {
        let (store, own) = (Arc::clone(&self.inner.store), self.inner.own.clone());
        let rows = tokio::task::spawn_blocking(move || {
            store.transaction(|tx| {
                Ok(tx
                    .managed_environments()?
                    .into_iter()
                    .filter(|r| r.controller == own && r.state.in_set())
                    .filter_map(|r| match r.realization {
                        EnvironmentRealization::Wsl { guid, .. } => Some((r.environment, guid)),
                        _ => None,
                    })
                    .collect::<Vec<(EnvironmentId, DistributionGuid)>>())
            })
        })
        .await;
        let Ok(Ok(rows)) = rows else { return };
        if rows.is_empty() {
            return;
        }
        let host = Arc::clone(&self.inner.host);
        let Ok(Ok(listed)) = tokio::task::spawn_blocking(move || host.discover()).await else {
            // WSL itself is unavailable: nothing can be said of any distribution.
            return;
        };
        for (environment, guid) in rows {
            if listed.iter().any(|d| d.guid == guid) {
                self.inner
                    .missing
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&environment);
            } else {
                // Unregistered (ADR-0010 §3 item 13): `gone`, its endpoints released, once
                // two listings in a row agree (`gone` is terminal).
                let confirmed = !self
                    .inner
                    .missing
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(environment.clone());
                if !confirmed {
                    continue;
                }
                if let Err(e) = ops.wsl_environment_gone(&environment).await {
                    tracing::warn!(code = %e.code, "an unregistered distribution could not be retired");
                }
                self.inner.lock().remove(&environment);
                continue;
            }
            if !self.has_bindings(&environment) {
                continue;
            }
            let host = Arc::clone(&self.inner.host);
            let g = guid.clone();
            let running = tokio::task::spawn_blocking(move || host.running(&g))
                .await
                .unwrap_or(RunningState::Unknown);
            if running == RunningState::Running {
                let _ = ops.set_environment_running(&environment, true).await;
                // Respawn, never starting a distribution: it runs (`Forbidden`). A live helper
                // realizes the current generations again (idempotent for the helper), which
                // recreates an endpoint whose socket was deleted (m04-plan U4,
                // `a13_deleted_socket_recreated`).
                let (this, env) = (self.clone(), environment.clone());
                let _ = tokio::task::spawn_blocking(move || {
                    let fresh = this.live_bridge(&env).is_none();
                    let bridge = this.ensure_bridge(&env, DistributionStart::Forbidden, false)?;
                    if !fresh {
                        this.realize_again(&env, &bridge);
                    }
                    Ok::<(), AdapterError>(())
                })
                .await;
            } else {
                let _ = ops.set_environment_running(&environment, false).await;
                // The helper died with its distribution: drop it, keep the desired set.
                let _ = self.live_bridge(&environment);
            }
        }
    }

    /// The supervisor: [`Self::tick`] every re-check interval until `stop`.
    pub async fn supervise(self, ops: Operations, stop: CancellationToken) {
        let mut every = tokio::time::interval(self.inner.recheck);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        every.tick().await;
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                _ = every.tick() => self.tick(&ops).await,
            }
        }
        // The runtime stops: each helper sees EOF, removes its endpoints and exits.
        self.shutdown();
    }

    /// End every helper (the runtime stops): each sees EOF and removes what it serves.
    pub fn shutdown(&self) {
        let states = std::mem::take(&mut *self.inner.lock());
        drop(states);
    }
}

fn deadline() -> Timestamp {
    Timestamp::from_second(Timestamp::now().as_second() + REALIZE_DEADLINE_SECS)
        .unwrap_or_else(|_| Timestamp::now())
}

fn to_bridge(p: &WslPublic) -> BridgePublic {
    BridgePublic {
        files: p.files.clone(),
        ssh_config: p.ssh_config.clone(),
        known_hosts: p.known_hosts.clone(),
    }
}

impl WslRealizer for BridgeRegistry {
    fn start(&self, environment: &EnvironmentId) -> Result<(), AdapterError> {
        self.ensure_bridge(environment, DistributionStart::Allowed, false)
            .map(|_| ())
    }

    fn run_dir(&self, environment: &EnvironmentId) -> Result<String, AdapterError> {
        let bridge = self.ensure_bridge(environment, DistributionStart::Forbidden, false)?;
        Ok(bridge.run_dir())
    }

    fn realize(
        &self,
        environment: &EnvironmentId,
        binding: &BindingId,
        tag: &str,
        generation: u64,
        public: &WslPublic,
    ) -> Result<(), AdapterError> {
        let bridge = self.ensure_bridge(environment, DistributionStart::Forbidden, false)?;
        // Remembered first: a stream may arrive the moment the endpoint listens.
        self.inner
            .lock()
            .entry(environment.clone())
            .or_default()
            .tags
            .insert(
                tag.to_owned(),
                TagState {
                    binding: binding.clone(),
                    generation,
                    public: public.clone(),
                },
            );
        match bridge.realize(tag, generation, to_bridge(public), deadline()) {
            Ok(_) => Ok(()),
            Err(e) => {
                if let Some(st) = self.inner.lock().get_mut(environment) {
                    st.tags.remove(tag);
                }
                Err(adapter_error(e))
            }
        }
    }

    fn withdraw(
        &self,
        environment: &EnvironmentId,
        tag: &str,
        generation: u64,
    ) -> Result<(), AdapterError> {
        let (bridge, last, known) = {
            let mut g = self.inner.lock();
            let Some(st) = g.get_mut(environment) else {
                return Ok(());
            };
            // A newer generation of the tag (or a tag never realized) is not this one's.
            let known = st.tags.get(tag).is_some_and(|t| t.generation == generation);
            if known {
                st.tags.remove(tag);
            }
            (st.bridge.clone(), st.tags.is_empty(), known)
        };
        if !known {
            return Ok(());
        }
        let reached = match &bridge {
            Some(b) if b.alive() => b.withdraw(tag, generation).is_ok(),
            _ => false,
        };
        let mut dead = None;
        {
            let mut g = self.inner.lock();
            if let Some(st) = g.get_mut(environment) {
                if !reached {
                    // The binding already ended on this side; the directory is left for the
                    // next helper start.
                    st.pending = true;
                }
                // It stops when the environment's last binding is withdrawn.
                if last && st.tags.is_empty() {
                    dead = st.bridge.take();
                }
            }
        }
        drop(dead);
        Ok(())
    }

    fn stop(&self, environment: &EnvironmentId, start: bool) -> Result<bool, AdapterError> {
        let (bridge, mut pending) = {
            let mut g = self.inner.lock();
            match g.remove(environment) {
                Some(st) => {
                    let alive = st.bridge.as_ref().is_some_and(|b| b.alive());
                    (st.bridge, st.pending || (!alive && !st.tags.is_empty()))
                }
                None => (None, false),
            }
        };
        // A live helper removes what it still serves when it sees EOF.
        if bridge.as_ref().is_some_and(|b| b.alive()) {
            pending = false;
        }
        drop(bridge);
        if pending && start {
            // The owner's explicit authorized start: a helper start removes the leftovers
            // (design §4), then it ends.
            if let Ok(b) = self.ensure_bridge(environment, DistributionStart::Allowed, true) {
                drop(b);
                self.inner.lock().remove(environment);
                pending = false;
            }
        }
        if pending {
            // ⟨M04 W2⟩ Remembered, so the owner's later `wsl disable --start` (or the next
            // disable's answer) still finds the leftovers it is owed, for this runtime's
            // lifetime (ADR-0010 §10: a restart in between forgets it; the leftovers hold
            // public material only).
            self.inner
                .lock()
                .entry(environment.clone())
                .or_default()
                .pending = true;
        }
        Ok(pending)
    }

    fn helper_state(&self, environment: &EnvironmentId) -> Option<HelperState> {
        let g = self.inner.lock();
        let st = g.get(environment);
        Some(match st {
            Some(s) if s.bridge.as_ref().is_some_and(|b| b.alive()) => HelperState::Running,
            Some(s) if s.helper_unavailable => HelperState::Unavailable,
            _ => HelperState::Stopped,
        })
    }
}

/// The streams of one environment's helper: each is served with the signer of the binding
/// that owns the tag (ADR-0010 §3 item 6).
struct Streams {
    inner: Weak<Inner>,
    environment: EnvironmentId,
}

impl StreamHandler for Streams {
    fn serve(&self, binding_tag: &str, stream: tokio::io::DuplexStream) -> bool {
        let Some(inner) = self.inner.upgrade() else {
            return false;
        };
        let (binding, generation) = {
            let g = inner.lock();
            let Some(t) = g
                .get(&self.environment)
                .and_then(|s| s.tags.get(binding_tag))
            else {
                return false;
            };
            (t.binding.clone(), t.generation)
        };
        let Some(endpoints) = inner
            .endpoints
            .get()
            .and_then(WeakEndpointRegistry::upgrade)
        else {
            return false;
        };
        endpoints.serve_wsl_stream(
            &inner.runtime,
            &binding,
            ResourceGeneration(generation),
            stream,
        )
    }
}
