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
//!
//! **⟨M02⟩ Existing-access wiring** (m02-plan U5; ADR-0007 §12.14 item 8, §12.17
//! item 11). Before `Operations::start`, [`ServiceOptions::projection`] decides the
//! managed projection: the account's real configuration in production
//! ([`ProjectionWiring::Account`]: `SshPaths::resolve`, Heimdall's configuration
//! directory, the captured environment, client discovery with local queries), an
//! explicit `ProjectionConfig` in tests, or none. A wired projection gives
//! `OperationsConfig.projection` a [`CatalogProjection`] (the `LocalProjection` with
//! the catalog as its `PublicKeySource`, filling each managed alias's key file under
//! the configuration directory, named by the key's fingerprint), and the supervisor
//! a [`ProjectionCleaner`] for its cleanup executor. With
//! [`ServiceOptions::existing_access`] the `native_agent` and `onepassword` adapters
//! are registered after any configured adapter, reading their selection, catalog and
//! client facts through [`RuntimeSources`] (the writer's `observe` over the stored
//! projection record, the catalog, the declarations, the verified clients).
//! `[setup] declaration_validity_days` becomes `Limits::declaration_validity`, the
//! lifetime of each interaction declaration the owner approves from then on
//! (ADR-0007 §12.22 item 10). [`Service::supervisor`] carries the projection cleaner,
//! so a test's `cleanup_pass` deletes what a rollback handed over exactly as the
//! running supervisor does.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use heimdall_adapters::integration::IntegrationSources;
use heimdall_adapters::native_agent::NativeAgentAdapter;
use heimdall_adapters::onepassword::OnePasswordAdapter;
use heimdall_app::ensure::{NoStageHook, StageHook};
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    CredentialAdapter, HeldStep, PreviewError, ProjectionReceipt, ProjectionReconcile,
    ProjectionWriter, ReconcileError, ResourceCleaner, StageSink,
};
use heimdall_app::reconcile::{Backoff, NoCleanupHook};
use heimdall_app::{Operations, OperationsConfig, TimeGate};
use heimdall_contract::Code;
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::ids::{EnvironmentId, IdentityId};
use heimdall_contract::ipc::{
    MAX_CONTROL_CONNECTIONS, MAX_HELLO_FRAME_BYTES, MAX_SIGNING_CONNECTIONS, PeerInfo,
    ServerMessage,
};
use heimdall_contract::provider::{EndpointKind as AgentEndpointKind, EndpointRef, EvidenceBasis};
use heimdall_contract::request::{ConsumerExecutable, ConsumerKind};
use heimdall_contract::setup::PreviewIntent;
use heimdall_domain::catalog::{IdentityRecord, InteractionDeclaration};
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::{ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent};
use heimdall_domain::time::{Clock, TimePolicy, TimeSync};
use heimdall_ipc::endpoint::{ExpectedOwner, verify_peer};
use heimdall_ipc::session::{ConnectionLimits, ControlConnection};
use heimdall_ipc::signing::{NoIdentities, Signer};
use heimdall_ipc::{EndpointKind, EndpointPaths, PeerIdentity};
use heimdall_localenv::clients::{ClientInventory, ClientKind, ClientsConfig, resolve_clients};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::cleaner::ProjectionCleaner;
use heimdall_localenv::projection::{LocalProjection, ProjectionConfig, PublicKeySource};
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
    /// Application limits; `None` = defaults with the configured retention and
    /// declaration validity.
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
    /// ⟨M02⟩ U5: the managed projection (module docs). Production:
    /// [`ProjectionWiring::Account`]; [`ServiceOptions::with_clock`]:
    /// [`ProjectionWiring::Disabled`].
    pub projection: ProjectionWiring,
    /// ⟨M02⟩ U5: register the existing-access adapters (`native_agent`,
    /// `onepassword`) after [`Self::adapters`]. Production: `true`.
    pub existing_access: bool,
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
        Ok(Self {
            projection: ProjectionWiring::Account,
            existing_access: true,
            ..Self::with_clock(Arc::new(clock), Arc::new(crate::platform::SystemTimeSync))
        })
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
            projection: ProjectionWiring::Disabled,
            existing_access: false,
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
    /// ⟨M02⟩ U5: the projection cleaner the supervisor's cleanup executor uses.
    cleaner: Option<Arc<dyn ResourceCleaner>>,
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
            // ⟨M02⟩ ADR-0007 §12.22 item 10: `[setup] declaration_validity_days`.
            limits.declaration_validity = config.declaration_validity()?;
        }
        // ⟨M02⟩ U5: the projection writer, its cleaner and the adapters.
        let wired = match options.projection {
            ProjectionWiring::Disabled => None,
            ProjectionWiring::Account => {
                account_projection(&paths).map(|c| wire_projection(store.clone(), c))
            }
            ProjectionWiring::Config(c) => Some(wire_projection(store.clone(), *c)),
        };
        let mut adapters = options.adapters;
        if options.existing_access {
            adapters.extend(existing_access_adapters(
                &store,
                &environment,
                wired.as_ref(),
                &options.clock,
            ));
        }
        let operations = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: options.clock.clone(),
            time_sync: options.time_sync.clone(),
            time_policy: options.time_policy,
            environment: environment.clone(),
            adapters,
            stage_hook: options.stage_hook,
            limits,
            default_window: config.max_window()?,
            projection: wired.as_ref().map(|w| Arc::clone(&w.writer)),
        })
        .await?;
        let cleaner: Option<Arc<dyn ResourceCleaner>> = wired.map(|w| {
            let c: Arc<dyn ResourceCleaner> = w.cleaner;
            c
        });
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
            cleaner,
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
            cleaner,
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
        let sup = with_cleaner(
            Supervisor::new(operations.clone(), supervisor).with_state(store, clock),
            cleaner,
        );
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
        with_cleaner(
            Supervisor::new(self.operations.clone(), self.supervisor)
                .with_state(self.store.clone(), self.clock.clone()),
            self.cleaner.clone(),
        )
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

// --- ⟨M02⟩ U5: existing-access wiring (module docs) ------------------------------------

/// ⟨M02⟩ How the runtime wires the managed projection.
pub enum ProjectionWiring {
    /// No projection writer: every setup request answers `CAPABILITY_UNAVAILABLE`,
    /// reason `driver_unavailable`, and no cleaner is registered.
    Disabled,
    /// The account's real configuration (production).
    Account,
    /// An explicit base configuration (tests: scratch paths, hooks, test switches).
    /// The catalog becomes its `PublicKeySource` when it names none.
    Config(Box<ProjectionConfig>),
}

impl std::fmt::Debug for ProjectionWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProjectionWiring::Disabled => "Disabled",
            ProjectionWiring::Account => "Account",
            ProjectionWiring::Config(_) => "Config",
        })
    }
}

/// ⟨M02⟩ A wired projection: the writer the operations use, its cleaner, and the
/// configuration both were built from.
pub struct WiredProjection {
    /// `OperationsConfig.projection`.
    pub writer: Arc<dyn ProjectionWriter>,
    /// The supervisor's cleaner for `config_projection` resources.
    pub cleaner: Arc<ProjectionCleaner>,
    /// The configuration (with the catalog key source).
    pub config: ProjectionConfig,
}

impl std::fmt::Debug for WiredProjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WiredProjection")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// ⟨M02⟩ Wire `config` over `store` (ADR-0007 §12.17 item 11): the catalog is the
/// `PublicKeySource` unless `config` names one, the writer is a
/// [`CatalogProjection`], and the cleaner shares the configuration.
#[must_use]
pub fn wire_projection(store: Arc<Store>, mut config: ProjectionConfig) -> WiredProjection {
    if config.keys.is_none() {
        let keys: Arc<dyn PublicKeySource> = Arc::new(CatalogKeys {
            store: Arc::clone(&store),
        });
        config.keys = Some(keys);
    }
    let writer: Arc<dyn ProjectionWriter> = Arc::new(CatalogProjection {
        inner: LocalProjection::new(config.clone()),
        store,
    });
    WiredProjection {
        writer,
        cleaner: Arc::new(ProjectionCleaner::new(config.clone())),
        config,
    }
}

/// The production projection configuration, or `None` (with a warning) when the
/// account home cannot be resolved; setup then answers `driver_unavailable`.
fn account_projection(paths: &Paths) -> Option<ProjectionConfig> {
    let ssh = match SshPaths::resolve() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("the account home is unavailable; setup is not available");
            return None;
        }
    };
    let env = Env::capture();
    let clients = resolve_clients(&env, &ssh, &ClientsConfig::default(), LocalQueries::Enabled);
    let mut config = ProjectionConfig::new(ssh, Platform::current(), paths.config_dir.clone());
    config.env = env;
    config.clients = clients;
    config.queries = LocalQueries::Enabled;
    Some(config)
}

fn with_cleaner(sup: Supervisor, cleaner: Option<Arc<dyn ResourceCleaner>>) -> Supervisor {
    match cleaner {
        Some(c) => sup.with_cleaner(c, Arc::new(NoCleanupHook), Backoff::default()),
        None => sup,
    }
}

fn read<T>(
    store: &Store,
    f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<T>,
) -> Option<T> {
    store.transaction(f).ok()
}

/// ⟨M02⟩ The catalog as the preview's `PublicKeySource`: an adopted identity's
/// one-line public key (never private material).
struct CatalogKeys {
    store: Arc<Store>,
}

impl PublicKeySource for CatalogKeys {
    fn public_key(&self, identity: &IdentityId) -> Option<String> {
        read(&self.store, |tx| tx.identity(identity))
            .flatten()
            .map(|r| r.public_key)
    }
}

/// ⟨M02⟩ The runtime's projection writer: the `LocalProjection` with each managed
/// alias's key file resolved before a preview. The setup driver leaves `key_file`
/// empty (the application does not know Heimdall's configuration directory); it is
/// `<config_dir>/keys/<fingerprint name>.pub`
/// (`heimdall_localenv::materialize::key_file_path`, ADR-0007 §12.19 item 8), from the
/// catalog's fingerprint. Every other call is the inner writer's, unchanged.
pub struct CatalogProjection {
    inner: LocalProjection,
    store: Arc<Store>,
}

impl std::fmt::Debug for CatalogProjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CatalogProjection")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl ProjectionWriter for CatalogProjection {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError> {
        let mut spec = spec.clone();
        for alias in &mut spec.aliases {
            if !alias.key_file.is_empty() {
                continue;
            }
            let fingerprint = read(&self.store, |tx| tx.identity(&alias.identity))
                .flatten()
                .map(|r| r.fingerprint)
                .ok_or_else(|| {
                    PreviewError::Unavailable(
                        "a managed alias names an identity that is not adopted".to_owned(),
                    )
                })?;
            let path = self
                .inner
                .config()
                .config_dir
                .join(heimdall_localenv::materialize::key_file_path(&fingerprint));
            alias.key_file = path
                .to_str()
                .ok_or_else(|| {
                    PreviewError::Unavailable("the key file path is not Unicode".to_owned())
                })?
                .to_owned();
        }
        self.inner.preview(&spec, intent)
    }

    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        self.inner.apply(intent, sink)
    }

    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError> {
        self.inner.reconcile(intent, receipts, sink)
    }

    fn observe(&self, record: &ProjectionRecord, aliases: &[String]) -> Vec<AliasObservation> {
        self.inner.observe(record, aliases)
    }

    fn observe_held(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
    ) -> Result<Vec<HeldStep>, ReconcileError> {
        self.inner.observe_held(intent, receipts)
    }
}

/// ⟨M02⟩ What the existing-access adapters read (`IntegrationSources`, U6): the
/// writer's static `observe` over the stored projection record, the catalog, the
/// declaration rows and the verified client executables. Passive; a store failure
/// claims nothing. ⟨M02⟩ ADR-0007 §12.23 item 2: these reads wait on the store and
/// the file system, so the operations read them only through the adapter's
/// `read_sources`, on the blocking pool and before `bounded_adapter_call`; the bounded
/// `prepare_from` sees only the in-memory snapshot.
pub struct RuntimeSources {
    store: Arc<Store>,
    environment: EnvironmentId,
    writer: Option<Arc<dyn ProjectionWriter>>,
    executables: Vec<ConsumerExecutable>,
}

impl RuntimeSources {
    /// Sources over `store` for `environment`.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        environment: EnvironmentId,
        writer: Option<Arc<dyn ProjectionWriter>>,
        clients: &ClientInventory,
    ) -> Self {
        Self {
            store,
            environment,
            writer,
            executables: executables_of(clients),
        }
    }
}

impl std::fmt::Debug for RuntimeSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeSources")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

impl IntegrationSources for RuntimeSources {
    fn observe_aliases(&self, aliases: &[String]) -> Vec<AliasObservation> {
        let Some(writer) = &self.writer else {
            return Vec::new();
        };
        match read(&self.store, |tx| tx.projection_record(&self.environment)).flatten() {
            Some(record) => writer.observe(&record, aliases),
            None => Vec::new(),
        }
    }

    fn catalog_identities(&self) -> Vec<IdentityRecord> {
        read(&self.store, |tx| tx.identities()).unwrap_or_default()
    }

    fn declaration(&self, identity: &IdentityId) -> Option<InteractionDeclaration> {
        read(&self.store, |tx| tx.interaction_declaration(identity)).flatten()
    }

    /// ⟨M02⟩ ADR-0007 §12.23 item 2: every row in one store transaction (a store
    /// failure claims nothing).
    fn declarations(
        &self,
        identities: &[IdentityId],
    ) -> BTreeMap<IdentityId, InteractionDeclaration> {
        read(&self.store, |tx| {
            let mut rows = BTreeMap::new();
            for id in identities {
                if let Some(d) = tx.interaction_declaration(id)? {
                    rows.insert(id.clone(), d);
                }
            }
            Ok(rows)
        })
        .unwrap_or_default()
    }

    fn executables(&self) -> Vec<ConsumerExecutable> {
        self.executables.clone()
    }
}

/// The selected client of each kind, as a consumer executable (observed when its
/// digest was read, inferred otherwise).
fn executables_of(clients: &ClientInventory) -> Vec<ConsumerExecutable> {
    let kinds = [
        (ClientKind::Ssh, ConsumerKind::Ssh),
        (ClientKind::Scp, ConsumerKind::Scp),
        (ClientKind::Sftp, ConsumerKind::Sftp),
        (ClientKind::Git, ConsumerKind::Git),
        (ClientKind::SshKeygen, ConsumerKind::SshKeygen),
    ];
    kinds
        .into_iter()
        .filter_map(|(kind, consumer)| {
            let c = clients.selected(kind)?;
            Some(ConsumerExecutable {
                consumer,
                path: c.path.to_str()?.to_owned(),
                version: c
                    .version
                    .as_ref()
                    .map(heimdall_localenv::local_query::version_text),
                sha256: c.sha256.clone(),
                basis: if c.sha256.is_some() {
                    EvidenceBasis::Observed
                } else {
                    EvidenceBasis::Inferred
                },
            })
        })
        .collect()
}

/// ⟨M02⟩ The existing-access adapters (m02-plan U5, U6): the native agent at the
/// runtime's `SSH_AUTH_SOCK` (an identity naming its own endpoint uses that one) and
/// 1Password (its endpoint from the catalog or configuration only; ADR-0007 §7).
fn existing_access_adapters(
    store: &Arc<Store>,
    environment: &EnvironmentId,
    wired: Option<&WiredProjection>,
    clock: &Arc<dyn Clock>,
) -> Vec<Arc<dyn CredentialAdapter>> {
    let (env, clients) = match wired {
        Some(w) => (w.config.env.clone(), w.config.clients.clone()),
        None => (Env::capture(), ClientInventory::default()),
    };
    let sources: Arc<dyn IntegrationSources> = Arc::new(RuntimeSources::new(
        Arc::clone(store),
        environment.clone(),
        wired.map(|w| Arc::clone(&w.writer)),
        &clients,
    ));
    let endpoint = env
        .get("SSH_AUTH_SOCK")
        .and_then(|v| v.to_str())
        .filter(|v| !v.is_empty())
        .map(|locator| EndpointRef {
            kind: if Platform::current().is_windows() {
                AgentEndpointKind::NamedPipe
            } else {
                AgentEndpointKind::UnixSocket
            },
            locator: locator.to_owned(),
        });
    let native: Arc<dyn CredentialAdapter> = Arc::new(
        NativeAgentAdapter::new("default".to_owned(), endpoint)
            .with_sources(Arc::clone(&sources))
            .with_clock(Arc::clone(clock)),
    );
    let onepassword: Arc<dyn CredentialAdapter> = Arc::new(
        OnePasswordAdapter::new("default".to_owned(), None)
            .with_sources(sources)
            .with_clock(Arc::clone(clock)),
    );
    vec![native, onepassword]
}
