//! The service loop hosted by `heimdall service run` (spec §13.1; overview §3, §4).
//!
//! **Start-up order** (overview §3, R-RT-07): owner-only directories → the
//! single-instance lock → open and migrate the store → environment identity (read
//! from the store; created once at first start, never changed) → the shared time
//! gate's anchor check → `Operations::start` (restart recovery: no deadline reset,
//! no pause revival, no identity change) → bind the control and signing endpoints
//! (one `ControlConnection::with_server_identity` per accepted control
//! connection, from the listener's identity) → write `instance.json` → (in
//! [`Service::run`]) the supervisor. A failure at any step returns an error and
//! leaves no advertisement behind; endpoints already bound are closed (their
//! sockets unlinked) and the lock is released when the partial state drops.
//!
//! **Shutdown** ([`Service::run`] after the token is cancelled): stop accepting,
//! let every session send `Goodbye(SERVICE_UNAVAILABLE)` and close (bounded), wait
//! (bounded) until no operation is being driven, so each rests at a durable stage
//! (anything still running resumes through restart recovery), close the
//! endpoints, remove `instance.json` (only if it is still this process's record),
//! release the lock last.
//!
//! Bounded queues (overview §4): at most `MAX_CONTROL_CONNECTIONS` control and
//! `MAX_SIGNING_CONNECTIONS` signing connections; an excess control connection is
//! accepted, sent `Goodbye(BACKPRESSURE)` and closed; an excess signing
//! connection is closed without reading.

use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::{NoStageHook, StageHook};
use heimdall_app::operations::Limits;
use heimdall_app::ports::CredentialAdapter;
use heimdall_app::{Operations, OperationsConfig, TimeGate};
use heimdall_contract::Code;
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::ipc::{
    MAX_CONTROL_CONNECTIONS, MAX_HELLO_FRAME_BYTES, MAX_SIGNING_CONNECTIONS, PeerInfo,
    ServerMessage,
};
use heimdall_domain::time::{Clock, TimePolicy, TimeSync};
use heimdall_ipc::endpoint::{ExpectedOwner, verify_peer};
use heimdall_ipc::session::{ConnectionLimits, ControlConnection};
use heimdall_ipc::signing::{NoIdentities, Signer};
use heimdall_ipc::{EndpointKind, EndpointPaths, PeerIdentity};
use heimdall_store::{FaultHook, NoFaults, Store};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Paths};
use crate::dispatch::{EventRelay, OperationsDispatcher};
use crate::instance::{INSTANCE_FILE, InstanceInfo, InstanceLock};
use crate::supervisor::{Supervisor, SupervisorConfig};

/// File name of the state database inside `Paths::state_dir`.
pub const STATE_DB_FILE: &str = "state.db";

/// Name the runtime reports in `ServerHello.server`.
pub const SERVER_NAME: &str = "heimdall-runtime";

/// Bound on waiting for sessions to say goodbye at shutdown.
const CONNECTION_DRAIN: Duration = Duration::from_secs(5);

/// Bound on writing the `Goodbye(BACKPRESSURE)` to an excess connection.
const OVERFLOW_WRITE: Duration = Duration::from_millis(200);

/// Pause after a failed `accept` (descriptor exhaustion and similar) so the loop
/// never spins.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Service start-up failure (mapped to `SERVICE_UNAVAILABLE`/`STATE_UNAVAILABLE`
/// by the CLI).
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Another instance is running.
    #[error(transparent)]
    Instance(#[from] crate::instance::InstanceError),
    /// Configuration.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// Store.
    #[error(transparent)]
    Store(#[from] heimdall_store::StoreError),
    /// Application start (restart recovery).
    #[error(transparent)]
    App(#[from] heimdall_app::OpError),
    /// Endpoint bind.
    #[error("endpoint bind failed: {0}")]
    Bind(std::io::Error),
    /// The platform clock sources (continuous clock, boot ID) are unavailable: no
    /// time safety, so the runtime does not start (ADR-0005 §3.6).
    #[error("platform clock unavailable: {0}")]
    Clock(std::io::Error),
    /// `instance.json` could not be written, or this process's start time is not
    /// available (an advertisement that can never validate is not written).
    #[error("instance advertisement failed: {0}")]
    Advertise(std::io::Error),
}

/// What the runtime is built from besides paths and configuration. Production
/// uses [`ServiceOptions::production`]; tests inject the virtual clock, scripted
/// sync, the fake adapter and production fault hooks here.
pub struct ServiceOptions {
    /// Clock (system or virtual).
    pub clock: Arc<dyn Clock>,
    /// Platform synchronization report.
    pub time_sync: Arc<dyn TimeSync>,
    /// Time plausibility policy.
    pub time_policy: TimePolicy,
    /// Credential adapters (none in an M01 production build).
    pub adapters: Vec<Arc<dyn CredentialAdapter>>,
    /// Pipeline hook (production: [`NoStageHook`]).
    pub stage_hook: Arc<dyn StageHook>,
    /// Store fault hook (production: [`NoFaults`]).
    pub store_faults: Arc<dyn FaultHook>,
    /// Application limits; `None` = defaults with the configured retention.
    pub limits: Option<Limits>,
    /// Supervisor tunables.
    pub supervisor: SupervisorConfig,
    /// Signing endpoint backend (M01: [`NoIdentities`]).
    pub signer: Arc<dyn Signer>,
    /// Bound on waiting for in-flight operations at shutdown.
    pub drain_timeout: Duration,
    /// Windows only: a fixed prefix of the pipe instance token (tests and native
    /// runs use `hmtest-` so their pipes are recognizable); empty in production,
    /// where the token is purely random (no labels, g03 §3.1 N2). At most 24
    /// characters of `[a-z0-9-]`; anything else fails the bind. Ignored on Unix.
    #[doc(hidden)]
    pub endpoint_prefix: String,
}

impl std::fmt::Debug for ServiceOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceOptions")
            .field("adapters", &self.adapters.len())
            .field("supervisor", &self.supervisor)
            .finish_non_exhaustive()
    }
}

impl ServiceOptions {
    /// Production sources: [`crate::platform::SystemClock::try_new`] (fails when
    /// the continuous clock or the boot ID cannot be read),
    /// [`crate::platform::SystemTimeSync`], no adapters, no hooks.
    pub fn production() -> std::io::Result<Self> {
        let clock = crate::platform::SystemClock::try_new()?;
        Ok(Self::with_clock(
            Arc::new(clock),
            Arc::new(crate::platform::SystemTimeSync),
        ))
    }

    /// Defaults around an explicit clock and sync source.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>, time_sync: Arc<dyn TimeSync>) -> Self {
        Self {
            clock,
            time_sync,
            time_policy: TimePolicy::default(),
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            store_faults: Arc::new(NoFaults),
            limits: None,
            supervisor: SupervisorConfig::default(),
            signer: Arc::new(NoIdentities),
            drain_timeout: Duration::from_secs(10),
            endpoint_prefix: String::new(),
        }
    }
}

/// Removes `instance.json` when dropped, if it is still this process's record.
#[derive(Debug)]
struct Advertisement {
    runtime_dir: std::path::PathBuf,
    info: InstanceInfo,
}

impl Advertisement {
    fn remove(&self) {
        // Never remove a record another instance wrote over ours.
        if let Ok(Some(current)) = InstanceInfo::read_file(&self.runtime_dir)
            && current.pid == self.info.pid
            && current.started_at == self.info.started_at
        {
            let _ = std::fs::remove_file(self.runtime_dir.join(INSTANCE_FILE));
        }
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Cancels background tasks (the event relay) when the service is dropped
/// without running.
#[derive(Debug)]
struct StopOnDrop(CancellationToken);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(unix)]
type ControlListener = heimdall_ipc::unix::Listener;
#[cfg(windows)]
type ControlListener = heimdall_ipc::windows::Listener;

/// A listener the accept loops can drive on every platform.
trait Accept: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn accept_peer(
        &self,
    ) -> impl std::future::Future<Output = std::io::Result<(Self::Stream, PeerIdentity)>> + Send;
}

#[cfg(unix)]
impl Accept for heimdall_ipc::unix::Listener {
    type Stream = tokio::net::UnixStream;
    async fn accept_peer(&self) -> std::io::Result<(Self::Stream, PeerIdentity)> {
        self.accept().await
    }
}

#[cfg(windows)]
impl Accept for heimdall_ipc::windows::Listener {
    type Stream = tokio::net::windows::named_pipe::NamedPipeServer;
    async fn accept_peer(&self) -> std::io::Result<(Self::Stream, PeerIdentity)> {
        self.accept().await
    }
}

/// A running service. Dropping it without [`Service::run`] closes its endpoints,
/// removes its advertisement and releases the lock (in that order); it does not
/// wait for in-flight work.
pub struct Service {
    // Field order is drop order: endpoints close first, the lock is released last.
    control: ControlListener,
    signing: ControlListener,
    advertisement: Advertisement,
    endpoints: EndpointPaths,
    owner: ExpectedOwner,
    server: PeerInfo,
    relay: EventRelay,
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    supervisor: SupervisorConfig,
    signer: Arc<dyn Signer>,
    drain_timeout: Duration,
    operations: Operations,
    shutdown: CancellationToken,
    _background: StopOnDrop,
    _lock: InstanceLock,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("environment", self.operations.environment())
            .finish_non_exhaustive()
    }
}

impl Service {
    /// Start-up order (R-RT-07, spec §13.3): acquire the instance lock → open and
    /// migrate the store → check time anchors → start operations (restart
    /// recovery) → bind control and signing endpoints → write `instance.json` →
    /// start the supervisor. Any failure before the endpoints are advertised
    /// leaves no advertisement behind.
    ///
    /// Uses [`ServiceOptions::production`]; a failure of the platform clock
    /// sources is [`ServiceError::Clock`].
    pub async fn start(
        paths: Paths,
        config: Config,
        shutdown: CancellationToken,
    ) -> Result<Self, ServiceError> {
        let options = ServiceOptions::production().map_err(ServiceError::Clock)?;
        Self::start_with(paths, config, options, shutdown).await
    }

    /// [`Service::start`] with explicit sources, adapters and hooks.
    pub async fn start_with(
        paths: Paths,
        config: Config,
        options: ServiceOptions,
        shutdown: CancellationToken,
    ) -> Result<Self, ServiceError> {
        config.validate()?;
        paths.ensure()?;
        // 1. Single instance (kernel-released on crash).
        let lock = InstanceLock::try_acquire(&paths.state_dir)?;

        // 2. Store: open, integrity check, migrations (with backup).
        let db = paths.state_dir.join(STATE_DB_FILE);
        let faults = options.store_faults.clone();
        let store = blocking(move || Store::open(&db, faults)).await??;
        let store = Arc::new(store);

        // 3. Environment identity: the recorded one, or a new random one at first
        //    start (recorded by `Operations::start`, never replaced).
        let environment = {
            let s = store.clone();
            match blocking(move || s.transaction(|tx| tx.self_environment())).await?? {
                Some(id) => id,
                None => new_environment_id()?,
            }
        };

        // 4. Time anchor check through the shared gate (persists on `Safe`;
        //    `Uncertain` is not fatal: passive reads continue, activation stops).
        let gate = TimeGate::new(
            store.clone(),
            options.clock.clone(),
            options.time_sync.clone(),
            options.time_policy,
        );
        match gate.check().await {
            Ok(_) => {}
            Err(e) if e.code == Code::TimeUncertain => {
                tracing::warn!("time is uncertain at start-up; activation is stopped");
            }
            Err(e) => return Err(ServiceError::App(e)),
        }

        // 5. Operations with restart recovery.
        let mut limits = options.limits.unwrap_or_default();
        if options.limits.is_none() {
            limits.operation_retention = config.retention_operations()?;
            limits.event_retention = config.retention_events()?;
        }
        let operations = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: options.clock.clone(),
            time_sync: options.time_sync.clone(),
            time_policy: options.time_policy,
            environment: environment.clone(),
            adapters: options.adapters,
            stage_hook: options.stage_hook,
            limits,
            default_window: config.max_window()?,
        })
        .await?;
        let background = StopOnDrop(shutdown.child_token());
        let relay = EventRelay::spawn(&operations, background.0.clone());

        // 6. Endpoints (distinct paths, owner-only).
        let (endpoints, control, signing, owner) =
            bind_endpoints(&paths, &options.endpoint_prefix)?;

        // 7. Advertisement, written only after both endpoints are bound.
        let started_at = InstanceInfo::current_started_at().ok_or_else(|| {
            ServiceError::Advertise(std::io::Error::other(
                "process start time unavailable on this platform",
            ))
        })?;
        let info = InstanceInfo {
            pid: std::process::id(),
            started_at,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            control_endpoint: endpoint_string(&endpoints.control)?,
            signing_endpoint: endpoint_string(&endpoints.signing)?,
        };
        info.write(&paths.runtime_dir)
            .map_err(ServiceError::Advertise)?;
        let advertisement = Advertisement {
            runtime_dir: paths.runtime_dir.clone(),
            info,
        };
        tracing::info!("runtime started");

        Ok(Self {
            control,
            signing,
            advertisement,
            endpoints,
            owner,
            server: PeerInfo {
                name: SERVER_NAME.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            relay,
            store,
            clock: options.clock,
            supervisor: options.supervisor,
            signer: options.signer,
            drain_timeout: options.drain_timeout,
            operations,
            shutdown,
            _background: background,
            _lock: lock,
        })
    }

    /// Serve until the token is cancelled or a fatal error occurs. Shutdown drains
    /// in-flight operations to a durable stage, closes endpoints, removes
    /// `instance.json`, and releases the lock last.
    pub async fn run(self) -> Result<(), ServiceError> {
        let Self {
            control,
            signing,
            advertisement,
            endpoints: _,
            owner,
            server,
            relay,
            store,
            clock,
            supervisor,
            signer,
            drain_timeout,
            operations,
            shutdown,
            _background,
            _lock,
        } = self;

        // Owner `Shutdown` requests cancel the same token a signal does, so both
        // take the graceful drain below (ADR-0006 §13.6 item 8).
        let dispatcher = OperationsDispatcher::new(operations.clone(), relay, clock.clone())
            .with_service_control(shutdown.clone());
        let environment = operations.environment().clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(serve_control(
            control,
            dispatcher,
            owner.clone(),
            environment,
            server,
            shutdown.clone(),
        ));
        tasks.spawn(serve_signing(signing, signer, owner, shutdown.clone()));
        let sup = Supervisor::new(operations.clone(), supervisor).with_state(store, clock);
        tasks.spawn(sup.run(shutdown.clone()));

        shutdown.cancelled().await;
        tracing::info!("runtime stopping");
        // Accept loops end (closing their listeners) after their sessions said
        // goodbye; the supervisor stops at its next select.
        while tasks.join_next().await.is_some() {}

        // Every operation rests at a durable stage between pipeline steps; wait
        // (bounded) for the ones being driven. Restart recovery resumes the rest.
        let waited = tokio::time::timeout(drain_timeout, async {
            while operations.running_operations() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if waited.is_err() {
            tracing::warn!(
                running = operations.running_operations(),
                "shutdown with operations still running; restart recovery resumes them"
            );
        }
        drop(advertisement);
        drop(operations);
        drop(_background);
        drop(_lock);
        tracing::info!("runtime stopped");
        Ok(())
    }

    /// The application operations (for in-process callers such as tests).
    #[must_use]
    pub fn operations(&self) -> &Operations {
        &self.operations
    }

    /// This runtime's environment ID (the one reported in `ServerHello`).
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        self.operations.environment()
    }

    /// Bound endpoint locations.
    #[must_use]
    pub fn endpoints(&self) -> &EndpointPaths {
        &self.endpoints
    }

    /// The advertisement this instance wrote.
    #[must_use]
    pub fn instance(&self) -> &InstanceInfo {
        &self.advertisement.info
    }

    /// A supervisor over this service's operations, store and clock (for
    /// virtual-clock tests that drive single passes; [`Service::run`] builds its
    /// own).
    #[must_use]
    pub fn supervisor(&self) -> Supervisor {
        Supervisor::new(self.operations.clone(), self.supervisor)
            .with_state(self.store.clone(), self.clock.clone())
    }

    /// The state store (tests inspect durable state through it).
    #[doc(hidden)]
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Convenience: a current-thread tokio runtime configured for the service.
    pub fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ServiceError> {
    tokio::task::spawn_blocking(f).await.map_err(|_| {
        ServiceError::App(heimdall_app::OpError::new(
            Code::InternalError,
            "start-up task failed",
        ))
    })
}

fn new_environment_id() -> Result<EnvironmentId, ServiceError> {
    let a = heimdall_app::ids::random_u64().map_err(heimdall_app::OpError::from)?;
    let b = heimdall_app::ids::random_u64().map_err(heimdall_app::OpError::from)?;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..].copy_from_slice(&b.to_le_bytes());
    Ok(EnvironmentId::from_random_bytes(bytes))
}

fn endpoint_string(path: &std::path::Path) -> Result<String, ServiceError> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        ServiceError::Bind(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "endpoint path is not valid UTF-8",
        ))
    })
}

#[cfg(unix)]
fn bind_endpoints(
    paths: &Paths,
    _prefix: &str,
) -> Result<
    (
        EndpointPaths,
        ControlListener,
        ControlListener,
        ExpectedOwner,
    ),
    ServiceError,
> {
    let endpoints = EndpointPaths::for_runtime(&paths.runtime_dir, "");
    let control = ControlListener::bind(&endpoints.control, EndpointKind::Control)
        .map_err(ServiceError::Bind)?;
    let signing = ControlListener::bind(&endpoints.signing, EndpointKind::Signing)
        .map_err(ServiceError::Bind)?;
    let owner = ExpectedOwner::Uid(heimdall_ipc::unix::current_uid());
    Ok((endpoints, control, signing, owner))
}

#[cfg(windows)]
fn bind_endpoints(
    paths: &Paths,
    prefix: &str,
) -> Result<
    (
        EndpointPaths,
        ControlListener,
        ControlListener,
        ExpectedOwner,
    ),
    ServiceError,
> {
    use std::fmt::Write as _;
    if prefix.len() > 24
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ServiceError::Bind(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid endpoint prefix",
        )));
    }
    // Unpredictable instance token: CSPRNG hex, no labels (g03 §3.1 N2); a test
    // prefix only makes test pipes recognizable.
    let mut token = String::with_capacity(32 + prefix.len());
    token.push_str(prefix);
    for _ in 0..2 {
        let v = heimdall_app::ids::random_u64().map_err(heimdall_app::OpError::from)?;
        let _ = write!(token, "{v:016x}");
    }
    let endpoints = EndpointPaths::for_runtime(&paths.runtime_dir, &token);
    let sid = heimdall_ipc::windows::current_user_sid().map_err(ServiceError::Bind)?;
    let control = ControlListener::bind(
        &endpoint_string(&endpoints.control)?,
        EndpointKind::Control,
        &sid,
    )
    .map_err(ServiceError::Bind)?;
    let signing = ControlListener::bind(
        &endpoint_string(&endpoints.signing)?,
        EndpointKind::Signing,
        &sid,
    )
    .map_err(ServiceError::Bind)?;
    Ok((endpoints, control, signing, ExpectedOwner::Sid(sid)))
}

/// Accept loop for the control endpoint. Each accepted, verified connection gets
/// a `ControlConnection` with this listener's server identity.
async fn serve_control<L: Accept>(
    listener: L,
    dispatcher: OperationsDispatcher,
    owner: ExpectedOwner,
    environment: EnvironmentId,
    server: PeerInfo,
    shutdown: CancellationToken,
) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept_peer() => {
                let (mut stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(kind = ?e.kind(), "control accept failed");
                        tokio::time::sleep(ACCEPT_RETRY).await;
                        continue;
                    }
                };
                let Ok(principal) = verify_peer(&peer, &owner) else {
                    tracing::warn!("control connection from another principal refused");
                    continue;
                };
                if conns.len() >= MAX_CONTROL_CONNECTIONS {
                    let goodbye = ServerMessage::Goodbye {
                        code: Code::Backpressure,
                        message: "too many control connections".to_owned(),
                    };
                    if let Ok(frame) = heimdall_ipc::encode_frame(&goodbye, MAX_HELLO_FRAME_BYTES) {
                        let _ = tokio::time::timeout(OVERFLOW_WRITE, stream.write_all(&frame)).await;
                    }
                    let _ = tokio::time::timeout(OVERFLOW_WRITE, stream.shutdown()).await;
                    continue;
                }
                let connection = ControlConnection::new(stream, ConnectionLimits::default())
                    .with_server_identity(environment.clone(), server.clone());
                let d = dispatcher.clone();
                let stop = shutdown.clone();
                conns.spawn(async move {
                    if let Err(e) = connection.serve(principal, d, stop).await {
                        tracing::debug!(error = %e, "control session ended with a protocol error");
                    }
                });
            }
        }
    }
    // Sessions saw the same token and send their goodbye; bounded wait.
    let _ = tokio::time::timeout(CONNECTION_DRAIN, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    conns.abort_all();
    drop(listener);
}

/// Accept loop for the signing endpoint (SSH agent framer, M01 signer).
async fn serve_signing<L: Accept>(
    listener: L,
    signer: Arc<dyn Signer>,
    owner: ExpectedOwner,
    shutdown: CancellationToken,
) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept_peer() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(kind = ?e.kind(), "signing accept failed");
                        tokio::time::sleep(ACCEPT_RETRY).await;
                        continue;
                    }
                };
                if verify_peer(&peer, &owner).is_err() {
                    tracing::warn!("signing connection from another principal refused");
                    continue;
                }
                if conns.len() >= MAX_SIGNING_CONNECTIONS {
                    // Closed without reading.
                    drop(stream);
                    continue;
                }
                let s = signer.clone();
                let stop = shutdown.clone();
                conns.spawn(async move {
                    let _ = heimdall_ipc::signing::serve(stream, s, stop).await;
                });
            }
        }
    }
    let _ = tokio::time::timeout(CONNECTION_DRAIN, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    conns.abort_all();
    drop(listener);
}
