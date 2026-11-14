//! The service loop hosted by `heimdall service run` (spec §13.1; overview §3, §4).
//!
//! **Start-up order** (overview §3, R-RT-07): owner-only directories → the
//! single-instance lock → open and migrate the store → environment identity (read
//! from the store; created once at first start, never changed) → the shared time
//! gate's anchor check → `Operations::start` (restart recovery: no deadline reset,
//! no pause revival, no identity change; ⟨M03⟩ in its first transaction installed
//! credential instances become `lost` and pending ones `destroyed`, m03-plan U0b
//! row 8, and CA retirements resume, row 23, all before any listener binds) → bind
//! the control and signing endpoints
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
//!
//! **⟨M03⟩ M03 start and stop order** (m03-plan U10; wave 4), with
//! [`ServiceOptions::managed`]: process hardening first (`harden_process`); then, after
//! the store and the time gate, the key vault (seeded from `HEIMDALL_TEST_KEY_SEED` in
//! debug builds only), the signer table, the managed effects and the managed adapter
//! (registered with the other adapters); `Operations::start` (M01/M02 recovery, U0b row
//! 8's `lost` marking); the `[session] lock_behavior` floor (every runtime) and the
//! session-lock source (on the blocking pool; a `revoke` floor without a signal is
//! reported, [`Service::lock_floor_refusal`]); the endpoint registry (authority = the
//! operations, with the verification gates); the M03 ports
//! (`Operations::set_managed_wiring`) and the enrollment host; the connection
//! supervisor's restart pass **first** (the owned masters of ended grants are closed);
//! the issuer child when a CA is registered; the environment endpoint (it serves M01's
//! signing path, so exactly one signer answers there; M01's signing listener is not
//! bound); `managed_reissue_pass`; then the control endpoint and `instance.json`
//! ([`Service::start_steps`]). **Stop:** stop accepting; close the owned masters;
//! zeroize the vault; shut the issuer down; remove the endpoints; clear the wiring.
//! ⟨§17.22 item 3⟩ A started service dropped without `run`, and a start that fails after
//! its first reference cycle, run the same teardown (`ManagedTeardown`): the issuer
//! lifecycle is fenced and stopped and the `Operations` ↔ registry ↔ authority cycles are
//! broken, so nothing keeps the child or the vault alive.

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
use crate::managed_store::StoreSources;
use crate::session_lock::PlatformSessionLockSource;
use crate::supervisor::{ManagedConnections, Supervisor, SupervisorConfig};
use heimdall_adapters::managed::ManagedCertificateAdapter;
use heimdall_adapters::managed::effects::ManagedEffectsImpl;
use heimdall_adapters::managed::files::SlotRoot;
use heimdall_app::lock::LockPassConfig;
use heimdall_app::managed::ManagedWiring;
use heimdall_app::ports::{ConnectionControl, SessionLockSource};
use heimdall_contract::issuer::CaState;
use heimdall_contract::managed::{PreferredMechanism, SessionLockState as LockState};
use heimdall_credential::endpoints::{EndpointLayout, EndpointRegistry};
use heimdall_credential::signer::SignerLimits;
use heimdall_credential::table::SignerTable;
use heimdall_credential::vault::KeyVault;
use heimdall_enroll::trace::{ClientFamily, ClientVersion};
use heimdall_enroll::verify::{Verifier, VerifierClient};
use heimdall_issuer::client::{ChildCommand, ChildIssuer, ClientConfig};
use heimdall_localenv::target::LocalTargetEvaluator;
use std::path::PathBuf;

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
// A start-up error is built at most once per runtime; boxing `App` (grown by
// ADR-0007 §12.26 item 4's `OpError::entries`) would change every `?` that converts an
// `OpError`, for no measurable gain.
#[allow(clippy::large_enum_variant)]
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
    /// ⟨M03⟩ wave 4 (m03-plan U10): the managed-credential wiring (module docs, "M03
    /// start and stop order"). Production: `Some(ManagedOptions::default())`;
    /// [`ServiceOptions::with_clock`]: `None`, the M01/M02 runtime unchanged (M01's
    /// signing endpoint with [`Self::signer`], no M03 port wired, so every M03 request
    /// answers `driver_unavailable`). With it, [`Self::signer`] is not used: the
    /// environment endpoint is the managed signer's.
    pub managed: Option<ManagedOptions>,
}

/// ⟨M03⟩ wave 4: where the session-lock state comes from (ADR-0008 D9 item 3; U9).
pub enum SessionLockWiring {
    /// `PlatformSessionLockSource::start` (production), started on the blocking pool.
    Platform,
    /// An injected source (tests: testkit's `FakeSessionLockSource`).
    Source(Arc<dyn SessionLockSource>),
    /// No source: `revoke_on_lock` grants never sign (fail closed), and a configured
    /// `revoke` floor is reported `lock_signal_unavailable`.
    None,
}

impl std::fmt::Debug for SessionLockWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SessionLockWiring::Platform => "Platform",
            SessionLockWiring::Source(_) => "Source",
            SessionLockWiring::None => "None",
        })
    }
}

/// ⟨M03⟩ wave 4 (m03-plan U10): what the managed-credential wiring takes besides the
/// paths and the configuration.
pub struct ManagedOptions {
    /// The session-lock source (production: [`SessionLockWiring::Platform`]).
    pub session_lock: SessionLockWiring,
    /// The lock passes' tunables (U9).
    pub lock_passes: LockPassConfig,
    /// The issuer child (`None`: `ChildCommand::internal_issuer()`, this executable's
    /// `internal issuer`).
    pub issuer_command: Option<ChildCommand>,
    /// The issuer child's start-token reader (`None`:
    /// [`crate::platform::process_start_time`]).
    pub issuer_start_token: Option<heimdall_issuer::client::StartToken>,
    /// **Test configuration only** (`HEIMDALL_TEST_SCRIPT_PAUSE_DIR`): the verifier's
    /// pause directory (ADR-0008 D13 item 3).
    pub script_pause_dir: Option<PathBuf>,
    /// **Test configuration only** (`HEIMDALL_TEST_KEY_SEED`, debug builds; m03-plan
    /// U0b row 16): the deterministic key seed of the vault
    /// (`KeyVault::with_test_seed`). A release build has no such field.
    #[cfg(debug_assertions)]
    pub test_key_seed: Option<Vec<u8>>,
    /// Arguments placed before `--` on every `ssh` the connection supervisor runs, and
    /// the environment of those children (tests: the client isolation arguments and a
    /// scratch `HOME`; production: none, the runtime's own).
    pub connection_client_args: Vec<std::ffi::OsString>,
    /// See [`Self::connection_client_args`].
    pub connection_client_env: Option<Vec<(std::ffi::OsString, std::ffi::OsString)>>,
}

impl Default for ManagedOptions {
    fn default() -> Self {
        Self {
            session_lock: SessionLockWiring::Platform,
            lock_passes: LockPassConfig::default(),
            issuer_command: None,
            issuer_start_token: None,
            script_pause_dir: None,
            #[cfg(debug_assertions)]
            test_key_seed: None,
            connection_client_args: Vec::new(),
            connection_client_env: None,
        }
    }
}

impl std::fmt::Debug for ManagedOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedOptions")
            .field("session_lock", &self.session_lock)
            .field("issuer_command", &self.issuer_command.is_some())
            .finish_non_exhaustive()
    }
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
            managed: Some(ManagedOptions::default()),
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
            managed: None,
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
/// wait for in-flight work. ⟨M03⟩ With the managed wiring it also zeroizes the vault,
/// stops the issuer child and clears the wiring (`ManagedTeardown`).
pub struct Service {
    // Field order is drop order: endpoints close first, the lock is released last.
    control: ControlListener,
    /// M01's signing listener; `None` with the managed wiring, whose environment
    /// endpoint serves that path instead.
    signing: Option<ControlListener>,
    /// ⟨M03⟩ wave 4: the managed-credential runtime (`None`: not wired).
    managed: Option<ManagedRuntime>,
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
        // ⟨M03⟩ m03-plan U10 (wave-1 hand-off): process hardening first, before any key
        // exists (no core dumps; Linux: not dumpable).
        if options.managed.is_some() {
            let report = heimdall_credential::sys::harden_process();
            if !report.mlock_ok {
                tracing::warn!("memory locking is unavailable; key pages may be swapped");
            }
        }
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
        // ⟨M03⟩ The endpoint owner and tokens: the control endpoint keeps M01's
        // per-start instance token; ⟨§17.21 item 8⟩ the managed endpoints are named by
        // the stable per-installation token (D10 item 1), created once and reused, so
        // P keeps naming the live environment pipe after a restart.
        let token = endpoint_token(&options.endpoint_prefix, false)?;
        let managed_token = match &options.managed {
            Some(_) => installation_pipe_token(&store, &options.endpoint_prefix).await?,
            None => String::new(),
        };
        let owner = expected_owner()?;
        // ⟨M03⟩ wave 4: what the managed adapter needs before `Operations::start`
        // (module docs): the vault, the signer table, the late-bound endpoint registry,
        // the effects and the store-backed sources.
        let mut managed_parts = match &options.managed {
            Some(m) => Some(ManagedParts::build(
                m,
                &paths,
                &store,
                &environment,
                &managed_token,
                crate::session_lock::lock_floor(&config.session),
            )?),
            None => None,
        };
        // ⟨M02⟩ U5: the projection writer, its cleaner and the adapters.
        // ⟨M03⟩ U8-Q1: every runtime writer is `LocalProjection::writing`; with the
        // managed wiring the preview reads the pair preferences (U8's
        // `ManagedPairSource`, over the store and the environment endpoint).
        let pair_source = managed_parts
            .as_ref()
            .map(|p| p.pair_source(&store, &paths, &environment));
        let with_pairs = |mut c: ProjectionConfig| {
            // The runtime's writer takes the original files' snapshots under this
            // runtime's state directory when the configuration names none (an explicit
            // test configuration); `LocalProjection::writing` refuses without one.
            if c.state_dir.is_none() {
                c.state_dir = Some(paths.state_dir.clone());
            }
            if c.managed.is_none()
                && let Some(source) = &pair_source
            {
                c.managed = Some(Arc::clone(source));
            }
            c
        };
        let wire = |c: ProjectionConfig| wire_runtime_projection(store.clone(), with_pairs(c)).ok();
        let wired = match options.projection {
            ProjectionWiring::Disabled => None,
            ProjectionWiring::Account => account_projection(&paths).and_then(wire),
            ProjectionWiring::Config(c) => wire(*c),
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
        // ⟨M03⟩ U6's managed adapter, after M02's (their order is unchanged).
        let managed_adapter = managed_parts
            .as_ref()
            .map(|parts| parts.adapter(wired.as_ref().map(|w| Arc::clone(&w.writer))));
        if let Some(a) = &managed_adapter {
            adapters.push(Arc::clone(a) as Arc<dyn CredentialAdapter>);
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
        // ⟨M03⟩ U9 (R3): the `[session] lock_behavior` floor, in every runtime.
        let floor = crate::session_lock::lock_floor(&config.session);
        operations.set_session_lock_floor(floor);
        // ⟨M03; ADR-0008 §17.25 item 19⟩ `inspect destinations`' D8 wording: the managed
        // adapter's own (`connection_policy_report`), so the destination view and the
        // ensure result say the same sentence. Without the managed wiring, none.
        if let Some(a) = managed_adapter {
            operations.set_connection_wording(Arc::new(AdapterWording(a)));
        }
        let background = StopOnDrop(shutdown.child_token());
        let relay = EventRelay::spawn(&operations, background.0.clone());

        // ⟨M03⟩ wave 4, m03-plan U10's start order after recovery: the session-lock
        // source, the connection supervisor (its restart pass first: the owned masters
        // of ended grants are closed), the issuer child when a CA is registered, the
        // environment endpoint, the re-issue pass. Then (below) the control endpoint and
        // `instance.json`.
        let managed = match (managed_parts.take(), options.managed) {
            (Some(parts), Some(m)) => Some(
                parts
                    .start(
                        m,
                        &operations,
                        &store,
                        &paths,
                        wired.as_ref(),
                        owner.clone(),
                        floor,
                        background.0.clone(),
                        endpoint_string(
                            &EndpointPaths::for_runtime(&paths.runtime_dir, &token).control,
                        )?,
                    )
                    .await?,
            ),
            _ => None,
        };
        let cleaner: Option<Arc<dyn ResourceCleaner>> = wired.map(|w| {
            let c: Arc<dyn ResourceCleaner> = w.cleaner;
            c
        });

        // 6. Endpoints (distinct paths, owner-only). With the managed wiring the
        //    environment endpoint already serves the signing path.
        let (endpoints, control, signing) = bind_endpoints(&paths, &token, managed.is_none())?;
        let mut managed = managed;
        if let Some(m) = managed.as_mut() {
            m.steps.push(start_step::CONTROL_ENDPOINT);
        }

        // 7. Advertisement, written only after both endpoints are bound.
        let started_at = InstanceInfo::current_started_at().ok_or_else(|| {
            ServiceError::Advertise(std::io::Error::other(
                "process start time unavailable on this platform",
            ))
        })?;
        let signing_endpoint = match &managed {
            Some(m) => m.teardown.registry.environment().locator,
            None => endpoint_string(&endpoints.signing)?,
        };
        let info = InstanceInfo {
            pid: std::process::id(),
            started_at,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            control_endpoint: endpoint_string(&endpoints.control)?,
            signing_endpoint,
        };
        info.write(&paths.runtime_dir)
            .map_err(ServiceError::Advertise)?;
        if let Some(m) = managed.as_mut() {
            m.steps.push(start_step::INSTANCE_FILE);
        }
        let advertisement = Advertisement {
            runtime_dir: paths.runtime_dir.clone(),
            info,
        };
        tracing::info!("runtime started");

        Ok(Self {
            control,
            signing,
            managed,
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
            managed,
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
        let mut dispatcher = OperationsDispatcher::new(operations.clone(), relay, clock.clone())
            .with_service_control(shutdown.clone());
        if let Some(m) = &managed {
            let endpoints: Arc<dyn crate::connections::BindingEndpoints> = m.teardown.late.clone();
            dispatcher = dispatcher
                .with_connections(Arc::clone(&m.connections))
                .with_binding_endpoints(endpoints);
        }
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
        // ⟨M03⟩ The signing endpoint's reference, carried by every connection's
        // `SigningSession` (U0b row 1).
        let signing_endpoint = heimdall_contract::provider::EndpointRef {
            kind: if cfg!(windows) {
                heimdall_contract::provider::EndpointKind::NamedPipe
            } else {
                heimdall_contract::provider::EndpointKind::UnixSocket
            },
            locator: advertisement.info.signing_endpoint.clone(),
        };
        if let Some(signing) = signing {
            tasks.spawn(serve_signing(
                signing,
                signing_endpoint,
                signer,
                owner,
                shutdown.clone(),
            ));
        }
        let mut sup = with_cleaner(
            Supervisor::new(operations.clone(), supervisor).with_state(store, clock),
            cleaner,
        );
        if let Some(m) = &managed {
            sup = sup
                .with_connections(Arc::clone(&m.connections))
                .with_end_cleanup(m.end_cleanup());
            if let Some(source) = &m.lock_source {
                sup = sup.with_session_lock(Arc::clone(source), m.lock_passes);
            }
        }
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
        // ⟨M03⟩ m03-plan U10's stop order (accepting already stopped above): close the
        // owned masters, zeroize the vault, shut the issuer down, remove the endpoints.
        if let Some(m) = managed {
            m.stop().await;
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
        let sup = with_cleaner(
            Supervisor::new(self.operations.clone(), self.supervisor)
                .with_state(self.store.clone(), self.clock.clone()),
            self.cleaner.clone(),
        );
        match &self.managed {
            Some(m) => sup
                .with_connections(Arc::clone(&m.connections))
                .with_end_cleanup(m.end_cleanup()),
            None => sup,
        }
    }

    /// ⟨M03⟩ The key vault of the managed wiring (tests: zeroization at stop).
    #[doc(hidden)]
    #[must_use]
    pub fn vault(&self) -> Option<Arc<KeyVault>> {
        self.managed.as_ref().map(|m| Arc::clone(&m.teardown.vault))
    }

    /// ⟨M03⟩ The issuer child's client of the managed wiring (tests).
    #[doc(hidden)]
    #[must_use]
    pub fn issuer(&self) -> Option<ChildIssuer> {
        self.managed
            .as_ref()
            .and_then(|m| m.teardown.issuer.clone())
    }

    /// ⟨M03⟩ The connection control of the managed wiring (tests).
    #[doc(hidden)]
    #[must_use]
    pub fn connections(&self) -> Option<Arc<ManagedConnections>> {
        self.managed.as_ref().map(|m| Arc::clone(&m.connections))
    }

    /// ⟨M03⟩ The managed endpoint registry (tests).
    #[doc(hidden)]
    #[must_use]
    pub fn endpoint_registry(&self) -> Option<EndpointRegistry> {
        self.managed.as_ref().map(|m| m.teardown.registry.clone())
    }

    /// ⟨M03⟩ U9: the start-up refusal of a configured `revoke` floor whose source is
    /// `unavailable` (`lock_signal_unavailable`; ADR-0008 D9 item 3: reported, never
    /// accepted silently). Grants stay fail closed meanwhile.
    #[must_use]
    pub fn lock_floor_refusal(&self) -> Option<&heimdall_app::OpError> {
        self.managed.as_ref().and_then(|m| m.floor_refusal.as_ref())
    }

    /// ⟨M03⟩ The start-up sequence of the managed wiring, in order (tests:
    /// `runtime_start_order_issuer_before_listen`): fixed step names.
    #[doc(hidden)]
    #[must_use]
    pub fn start_steps(&self) -> Vec<&'static str> {
        self.managed
            .as_ref()
            .map(|m| m.steps.clone())
            .unwrap_or_default()
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

/// ⟨M03⟩ ADR-0008 D10 item 1, §17.21 item 8: the installation's stable Windows
/// environment pipe token, read from the store (`Txn::windows_pipe_token`) or, at the
/// first managed start, created once (CSPRNG hex after the test prefix's ASCII
/// alphanumerics; `EndpointLayout::windows` takes alphanumerics only) and recorded in
/// the same transaction. Every later start reuses it, so the environment pipe P names
/// is the one this runtime serves. Recorded on every platform (the Unix layout does not
/// use it), so a state directory moved between hosts keeps it.
async fn installation_pipe_token(store: &Arc<Store>, prefix: &str) -> Result<String, ServiceError> {
    let fresh = endpoint_token_on(prefix, true, true)?;
    let s = Arc::clone(store);
    let token = blocking(move || {
        s.transaction(|tx| match tx.windows_pipe_token()? {
            Some(t) => Ok(t),
            None => {
                tx.set_windows_pipe_token(&fresh)?;
                Ok(fresh)
            }
        })
    })
    .await??;
    Ok(token)
}

/// The Windows instance token of this start (empty on Unix): CSPRNG hex, no labels
/// (g03 §3.1 N2); a test prefix only makes test pipes recognizable.
fn endpoint_token(prefix: &str, managed: bool) -> Result<String, ServiceError> {
    endpoint_token_on(prefix, managed, cfg!(windows))
}

/// [`endpoint_token`] on `windows` (else empty). A `managed` token (the managed
/// layout's) takes ASCII alphanumerics only, so the prefix's `-` are left out.
fn endpoint_token_on(prefix: &str, managed: bool, windows: bool) -> Result<String, ServiceError> {
    if !windows {
        return Ok(String::new());
    }
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
    let mut token = String::with_capacity(32 + prefix.len());
    if managed {
        token.extend(prefix.chars().filter(char::is_ascii_alphanumeric));
    } else {
        token.push_str(prefix);
    }
    for _ in 0..2 {
        let v = heimdall_app::ids::random_u64().map_err(heimdall_app::OpError::from)?;
        let _ = write!(token, "{v:016x}");
    }
    Ok(token)
}

/// The principal every endpoint accepts: this user.
#[cfg(unix)]
fn expected_owner() -> Result<ExpectedOwner, ServiceError> {
    Ok(ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()))
}

/// The principal every endpoint accepts: this user.
#[cfg(windows)]
fn expected_owner() -> Result<ExpectedOwner, ServiceError> {
    heimdall_ipc::windows::current_user_sid()
        .map(ExpectedOwner::Sid)
        .map_err(ServiceError::Bind)
}

/// Bind the control endpoint and, unless the managed environment endpoint serves the
/// signing path (`bind_signing == false`), M01's signing endpoint.
#[cfg(unix)]
fn bind_endpoints(
    paths: &Paths,
    token: &str,
    bind_signing: bool,
) -> Result<(EndpointPaths, ControlListener, Option<ControlListener>), ServiceError> {
    let endpoints = EndpointPaths::for_runtime(&paths.runtime_dir, token);
    let control = ControlListener::bind(&endpoints.control, EndpointKind::Control)
        .map_err(ServiceError::Bind)?;
    let signing = if bind_signing {
        Some(
            ControlListener::bind(&endpoints.signing, EndpointKind::Signing)
                .map_err(ServiceError::Bind)?,
        )
    } else {
        None
    };
    Ok((endpoints, control, signing))
}

/// Bind the control endpoint and, unless the managed environment endpoint serves the
/// signing path (`bind_signing == false`), M01's signing endpoint.
#[cfg(windows)]
fn bind_endpoints(
    paths: &Paths,
    token: &str,
    bind_signing: bool,
) -> Result<(EndpointPaths, ControlListener, Option<ControlListener>), ServiceError> {
    let endpoints = EndpointPaths::for_runtime(&paths.runtime_dir, token);
    let sid = heimdall_ipc::windows::current_user_sid().map_err(ServiceError::Bind)?;
    let control = ControlListener::bind(
        &endpoint_string(&endpoints.control)?,
        EndpointKind::Control,
        &sid,
    )
    .map_err(ServiceError::Bind)?;
    let signing = if bind_signing {
        Some(
            ControlListener::bind(
                &endpoint_string(&endpoints.signing)?,
                EndpointKind::Signing,
                &sid,
            )
            .map_err(ServiceError::Bind)?,
        )
    } else {
        None
    };
    Ok((endpoints, control, signing))
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
    endpoint: heimdall_contract::provider::EndpointRef,
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
                let e = endpoint.clone();
                let stop = shutdown.clone();
                conns.spawn(async move {
                    let _ = heimdall_ipc::signing::serve(stream, peer, e, s, stop).await;
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
    let inner = LocalProjection::new(config.clone());
    wired_over(store, inner, config)
}

/// ⟨M03⟩ U8-Q1 (ADR-0007 §12.34 item 6): [`wire_projection`] through
/// `LocalProjection::writing`, which refuses a configuration without a state directory
/// (so no edit of the owner's files can run without the original's snapshot). Every
/// writer [`Service::start_with`] wires is built here; [`wire_projection`] keeps M02's
/// constructor for its direct callers (the M02 suites).
///
/// # Errors
/// `StateDirMissing` when `config.state_dir` is `None`.
pub fn wire_runtime_projection(
    store: Arc<Store>,
    mut config: ProjectionConfig,
) -> Result<WiredProjection, heimdall_localenv::projection::StateDirMissing> {
    if config.keys.is_none() {
        let keys: Arc<dyn PublicKeySource> = Arc::new(CatalogKeys {
            store: Arc::clone(&store),
        });
        config.keys = Some(keys);
    }
    let inner = LocalProjection::writing(config.clone())?;
    Ok(wired_over(store, inner, config))
}

fn wired_over(
    store: Arc<Store>,
    inner: LocalProjection,
    config: ProjectionConfig,
) -> WiredProjection {
    let writer: Arc<dyn ProjectionWriter> = Arc::new(CatalogProjection { inner, store });
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
    let mut config = ProjectionConfig::new(ssh, Platform::current(), paths.config_dir.clone())
        .with_state_dir(paths.state_dir.clone());
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

// --- ⟨M03⟩ wave 4 (m03-plan U10): the managed-credential wiring --------------------------

/// The fixed names of [`Service::start_steps`], in the binding order.
pub mod start_step {
    /// The endpoint registry exists (no endpoint is bound yet).
    pub const REGISTRY: &str = "registry";
    /// The session-lock floor and source are set.
    pub const SESSION_LOCK: &str = "session_lock";
    /// `Operations::set_managed_wiring` ran.
    pub const WIRING: &str = "wiring";
    /// The connection supervisor's restart pass ran (the owned masters of ended grants
    /// closed).
    pub const CONNECTION_RESTART_PASS: &str = "connection_restart_pass";
    /// The issuer child was started (a CA is registered).
    pub const ISSUER_START: &str = "issuer_start";
    /// No CA is registered: the issuer child was not started.
    pub const ISSUER_NOT_NEEDED: &str = "issuer_not_needed";
    /// The environment endpoint is bound and serves.
    pub const ENVIRONMENT_ENDPOINT: &str = "environment_endpoint";
    /// `managed_reissue_pass` ran.
    pub const MANAGED_REISSUE_PASS: &str = "managed_reissue_pass";
    /// The control endpoint is bound.
    pub const CONTROL_ENDPOINT: &str = "control_endpoint";
    /// `instance.json` is written.
    pub const INSTANCE_FILE: &str = "instance_json";
}

/// The binding endpoints, bound late: the registry needs the `Operations` (its signature
/// authority and signing gates), which need the managed adapter, whose effects need the
/// binding endpoints. Until the registry is set (and after the stop clears it) it knows
/// no endpoint, so nothing is materialized and no master starts (fail closed). Clearing
/// it at stop also breaks the `Operations` → adapter → registry → `Operations` cycle.
#[derive(Default)]
struct LateRegistry(std::sync::RwLock<Option<EndpointRegistry>>);

impl LateRegistry {
    fn set(&self, registry: EndpointRegistry) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(registry);
    }

    fn clear(&self) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn get(&self) -> Option<EndpointRegistry> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl heimdall_adapters::managed::effects::BindingEndpoints for LateRegistry {
    fn binding_endpoint(&self, binding: &heimdall_contract::ids::BindingId) -> Option<EndpointRef> {
        self.get()
            .and_then(|r| r.binding_endpoint(binding))
            .map(|(e, _)| e)
    }

    /// ⟨§17.21 item 1⟩ Step 6's endpoint creation, through the live registry; before it
    /// is set (or after stop) the creation refuses, so the materialization fails closed.
    fn create_binding_endpoint(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
    ) -> Result<EndpointRef, heimdall_app::ports::AdapterError> {
        self.get()
            .ok_or_else(|| {
                heimdall_app::ports::AdapterError::Unavailable(
                    heimdall_adapters::managed::effects::BINDING_ENDPOINT_UNAVAILABLE.to_owned(),
                )
            })?
            .create_binding_endpoint(binding, generation)
    }

    fn remove_binding_endpoint(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
    ) -> Result<bool, heimdall_app::ports::AdapterError> {
        match self.get() {
            Some(r) => r.remove_binding_endpoint(binding, generation),
            None => Ok(false),
        }
    }
}

impl crate::connections::BindingEndpoints for LateRegistry {
    fn endpoint(&self, binding: &heimdall_contract::ids::BindingId) -> Option<EndpointRef> {
        self.get()
            .and_then(|r| r.binding_endpoint(binding))
            .map(|(e, _)| e)
    }
}

/// ⟨M03⟩ U8's `ManagedPairSource` over the store (U8-Q1/Q6 hand-off): a pair whose
/// stored preference is `managed_certificate` renders its managed section with the
/// environment endpoint and the slot paths of the one path function
/// (`content::managed_slot_paths(<state_dir>, destination)`). A store failure refuses the
/// preview, never rendering existing access instead.
///
/// ⟨§17.21 item 9; §17.22 item 14⟩ The control path: the slot's stable mux path
/// (`content::checked_mux_path(<runtime_dir>, destination)`, D8 item 3) only when owned
/// masters are enabled for the pair by the pair-level rendering rule
/// ([`pair_masters_enabled`]: every standing policy covering the pair has
/// `owned_masters`; none covering it means disabled); otherwise `ControlPath none`. Each
/// master's own grant policy is still checked when it starts. This source is read only by the setup preview, so the path reaches P only
/// through the `setup apply` of that preview (enabling masters is widening: it takes
/// effect through an approved projection). On Windows (owned masters unavailable, M-F7)
/// and for a path past the socket limit (`mux_path_too_long`): `ControlPath none`.
struct StorePairSource {
    store: Arc<Store>,
    environment: EnvironmentId,
    environment_endpoint: EndpointRef,
    state_dir: PathBuf,
    runtime_dir: PathBuf,
}

/// ⟨§17.21 item 9; ADR-0008 §17.22 item 14 (R2D-Q1, option (a))⟩ Whether owned masters
/// are enabled for `pair` in `environment`. **A pair-level rendering rule:** P renders the
/// pair's stable mux path only when **every** current standing policy covering the pair
/// (its profile defined, its environments containing `environment`, its scope naming the
/// pair) has `owned_masters`, which is D8 item 1's fail-closed merge
/// (`effective_connection_policy`, strictest wins) over them. No applicable policy means
/// disabled (the default). No grant's policy enters it (P is per pair and changes only
/// through an approved setup transaction), and it decides only what P renders: each master
/// is still started only for a grant whose **own** effective policy is `owned_masters`
/// (U7's `start_context`), checked when that master starts.
fn pair_masters_enabled(
    tx: &mut heimdall_store::Txn<'_>,
    environment: &EnvironmentId,
    pair: &heimdall_domain::scope::AccessPair,
) -> heimdall_store::Result<bool> {
    let mut applicable = Vec::new();
    for profile in tx.profiles()? {
        for p in tx.policies_for(&profile.id, environment)? {
            if p.scope.pairs.contains(pair) {
                applicable.push(p.connection);
            }
        }
    }
    let Some((first, rest)) = applicable.split_first() else {
        return Ok(false);
    };
    Ok(
        heimdall_domain::connection::effective_connection_policy(Some(*first), rest, None)
            .multiplexing
            == heimdall_contract::managed::MultiplexingMode::OwnedMasters,
    )
}

impl heimdall_localenv::projection::ManagedPairSource for StorePairSource {
    fn managed_section(
        &self,
        alias: &heimdall_domain::projection::ManagedAliasSpec,
    ) -> Result<Option<heimdall_localenv::projection::ManagedSectionSpec>, String> {
        let pair = heimdall_domain::scope::AccessPair {
            destination: alias.destination.clone(),
            account: alias.account.clone(),
        };
        let (preference, masters) = self
            .store
            .transaction(|tx| {
                let preference = tx.pair_preference(&pair)?;
                let masters = match &preference {
                    Some(p) if p.mechanism == PreferredMechanism::ManagedCertificate => {
                        pair_masters_enabled(tx, &self.environment, &pair)?
                    }
                    _ => false,
                };
                Ok((preference, masters))
            })
            .map_err(|_| "the pair preference could not be read".to_owned())?;
        match preference {
            Some(p) if p.mechanism == PreferredMechanism::ManagedCertificate => {
                let slot = heimdall_localenv::projection::content::managed_slot_paths(
                    &self.state_dir,
                    &alias.destination,
                )
                .map_err(|e| e.to_string())?;
                let control_path = if masters && cfg!(not(windows)) {
                    heimdall_localenv::projection::content::checked_mux_path(
                        &self.runtime_dir,
                        &alias.destination,
                    )
                    .ok()
                } else {
                    None
                };
                Ok(Some(heimdall_localenv::projection::ManagedSectionSpec {
                    environment_endpoint: self.environment_endpoint.clone(),
                    key_pub: slot.key_pub,
                    cert_pub: slot.cert_pub,
                    control_path,
                }))
            }
            _ => Ok(None),
        }
    }

    /// ⟨§17.22 item 16 (R2F-Q2)⟩ The pair's stored preference (either mechanism) is
    /// `pending`; no stored preference (every M02 pair) is never pending.
    fn projection_pending(
        &self,
        alias: &heimdall_domain::projection::ManagedAliasSpec,
    ) -> Result<bool, String> {
        let pair = heimdall_domain::scope::AccessPair {
            destination: alias.destination.clone(),
            account: alias.account.clone(),
        };
        self.store
            .transaction(|tx| tx.pair_preference(&pair))
            .map(|p| {
                p.is_some_and(|p| {
                    p.projection == heimdall_domain::enrollment::ProjectionStatus::Pending
                })
            })
            .map_err(|_| "the pair preference could not be read".to_owned())
    }
}

/// ⟨M03 wave 4, round 2 (R2-F)⟩ The runtime's store-backed `ManagedPairSource`
/// ([`StorePairSource`]), exactly as [`Service`] wires it into its projection writer, for
/// a harness that builds the writer itself ([`wire_runtime_projection`]) over its own
/// `Operations`: `environment_endpoint` is the managed layout's environment endpoint,
/// `state_dir` the slot data directory, `runtime_dir` the mux paths' directory.
#[must_use]
pub fn store_pair_source(
    store: Arc<Store>,
    environment: EnvironmentId,
    environment_endpoint: EndpointRef,
    state_dir: PathBuf,
    runtime_dir: PathBuf,
) -> Arc<dyn heimdall_localenv::projection::ManagedPairSource> {
    Arc::new(StorePairSource {
        store,
        environment,
        environment_endpoint,
        state_dir,
        runtime_dir,
    })
}

/// ⟨§17.25 item 19⟩ The runtime's [`heimdall_app::operations::ConnectionWording`]: the
/// managed adapter's report for the alias (its observed selection, D8 wording).
struct AdapterWording(Arc<ManagedCertificateAdapter>);

impl heimdall_app::operations::ConnectionWording for AdapterWording {
    fn report(
        &self,
        alias: &str,
        policy: &heimdall_contract::managed::ConnectionPolicy,
    ) -> Option<heimdall_contract::managed::ConnectionPolicyReport> {
        Some(self.0.connection_policy_report(alias, policy))
    }
}

/// What the managed adapter needs before `Operations::start`.
struct ManagedParts {
    vault: Arc<KeyVault>,
    table: SignerTable,
    layout: EndpointLayout,
    late: Arc<LateRegistry>,
    effects: ManagedEffectsImpl,
    sources: StoreSources,
    install_view: Arc<sources::LateInstallView>,
    cleanup: Arc<sources::LateCleanup>,
    /// ⟨R3-A, §17.22 item 7⟩ The evidence comparison's inputs, bound in `start`.
    evidence: Arc<sources::LateEvidenceFeed>,
}

/// The store-backed sources of the managed adapter (`crate::managed_store`, U10-C):
/// `StoreSources` itself for the reads, the grant scopes and the slot table; the install
/// view and the end-of-grant cleanup are bound late (they need the `Operations` and the
/// connection supervisor, which need the adapter), refusing until set and after stop.
mod sources {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, PoisonError, RwLock};

    use heimdall_adapters::managed::EndCleanup;
    use heimdall_adapters::managed::effects::{GrantScopes, SlotStore};
    use heimdall_adapters::managed::prepare::{EvidenceFeed, ManagedSourceRead};
    use heimdall_app::ports::AdapterError;
    use heimdall_contract::ids::GrantId;
    use heimdall_credential::table::{InstallRefusal, InstallView};
    use heimdall_domain::issuance::IssuanceEntry;

    use crate::managed_store::{OpsInstallView, StoreCleanup, StoreSources};
    use crate::supervisor::ManagedConnections;

    /// The managed adapter's sources, with the evidence comparison's inputs from
    /// `feed` (⟨§17.22 item 7⟩: the runtime's target evaluator and verifying client,
    /// bound once they exist).
    pub(super) fn read(
        s: &StoreSources,
        writer: Option<Arc<dyn heimdall_app::ports::ProjectionWriter>>,
        feed: Arc<LateEvidenceFeed>,
    ) -> Arc<dyn ManagedSourceRead> {
        Arc::new(Observing {
            inner: s.clone(),
            writer,
            feed,
        })
    }

    /// ⟨§17.22 item 7⟩ The evidence comparison's inputs, bound after the runtime's
    /// target evaluator and enrollment host exist (they are built with the managed
    /// wiring, after the adapter): the same evaluator and client the enrollment driver
    /// uses (`heimdall_adapters::managed::prepare::TargetAndClient`). Unset (no
    /// wired projection, so no evaluator or client; or before binding): no
    /// evaluation, so no evidence holds and every managed `destination_scope` is
    /// `unknown` (fail closed).
    #[derive(Default)]
    pub(super) struct LateEvidenceFeed(RwLock<Option<Arc<dyn EvidenceFeed>>>);

    impl LateEvidenceFeed {
        /// Bind (or clear) the feed.
        pub(super) fn set(&self, feed: Option<Arc<dyn EvidenceFeed>>) {
            *self.0.write().unwrap_or_else(PoisonError::into_inner) = feed;
        }

        fn get(&self) -> Option<Arc<dyn EvidenceFeed>> {
            self.0
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    /// ⟨§17.21 item 11⟩ `StoreSources` with D10 item 6's static observation of the
    /// managed aliases: the runtime's projection writer's `observe` over the stored
    /// projection record, exactly as M02's `RuntimeSources::observe_aliases`. No writer,
    /// no record or a store failure: no observation (every pair `undetermined`, fail
    /// closed). Every other read is `StoreSources`'.
    struct Observing {
        inner: StoreSources,
        writer: Option<Arc<dyn heimdall_app::ports::ProjectionWriter>>,
        feed: Arc<LateEvidenceFeed>,
    }

    impl ManagedSourceRead for Observing {
        fn enrollments(
            &self,
            pairs: &[heimdall_domain::scope::AccessPair],
        ) -> Vec<heimdall_domain::enrollment::EnrollmentRecord> {
            self.inner.enrollments(pairs)
        }

        fn issuing_cas(
            &self,
            pairs: &[heimdall_domain::scope::AccessPair],
        ) -> std::collections::BTreeMap<
            heimdall_domain::scope::AccessPair,
            std::collections::BTreeSet<heimdall_contract::ids::CaFingerprint>,
        > {
            self.inner.issuing_cas(pairs)
        }

        fn slots(
            &self,
            pairs: &[heimdall_domain::scope::AccessPair],
        ) -> Vec<heimdall_app::ports::ManagedSlot> {
            self.inner.slots(pairs)
        }

        fn claims(&self) -> Vec<heimdall_domain::claims::Claim> {
            self.inner.claims()
        }

        fn issuer(&self) -> Option<heimdall_app::ports::IssuerStatusSnapshot> {
            self.inner.issuer()
        }

        fn prepared(
            &self,
            pairs: &[heimdall_domain::scope::AccessPair],
        ) -> Option<heimdall_app::ports::ManagedPrepared> {
            self.inner.prepared(pairs)
        }

        fn terms(
            &self,
            grant: &GrantId,
        ) -> Option<heimdall_adapters::managed::prepare::GrantTerms> {
            self.inner.terms(grant)
        }

        fn cascade(&self, grant: &GrantId) -> Vec<GrantId> {
            self.inner.cascade(grant)
        }

        fn issuance_entries(&self, grants: &[GrantId]) -> Vec<IssuanceEntry> {
            self.inner.issuance_entries(grants)
        }

        fn key_only_restore(&self) -> bool {
            self.inner.key_only_restore()
        }

        fn recorded_outcome(
            &self,
            grant: &GrantId,
            effect_token: &str,
        ) -> Option<heimdall_app::ports::PrepareOutcome> {
            self.inner.recorded_outcome(grant, effect_token)
        }

        fn owned_connections(
            &self,
            grants: &[GrantId],
        ) -> Vec<heimdall_domain::managed::OwnedConnection> {
            self.inner.owned_connections(grants)
        }

        fn observations(
            &self,
            aliases: &[String],
        ) -> Vec<heimdall_contract::doctor::AliasObservation> {
            let Some(writer) = &self.writer else {
                return Vec::new();
            };
            let environment = self.inner.environment().clone();
            match self
                .inner
                .store()
                .transaction(|tx| tx.projection_record(&environment))
            {
                Ok(Some(record)) => writer.observe(&record, aliases),
                _ => Vec::new(),
            }
        }

        fn evaluate_target(
            &self,
            alias: &str,
        ) -> Option<heimdall_domain::enrollment::TargetEvaluation> {
            self.feed.get()?.evaluate_target(alias)
        }

        fn client_version(&self) -> Option<String> {
            self.feed.get()?.client_version()
        }
    }

    pub(super) fn scopes(s: &StoreSources) -> Arc<dyn GrantScopes> {
        Arc::new(s.clone())
    }

    pub(super) fn slots(s: &StoreSources) -> Arc<dyn SlotStore> {
        Arc::new(s.clone())
    }

    type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

    /// U2-Q2's install view, bound after `Operations::start` (`OpsInstallView`); until
    /// then and after stop every install is refused `store_view_unavailable`.
    #[derive(Default)]
    pub(super) struct LateInstallView(RwLock<Option<OpsInstallView>>);

    impl LateInstallView {
        pub(super) fn set(&self, view: Option<OpsInstallView>) {
            *self.0.write().unwrap_or_else(PoisonError::into_inner) = view;
        }
    }

    // `InstallView` is `#[async_trait]`; the desugared form.
    impl InstallView for LateInstallView {
        fn check<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            grant: &'life1 GrantId,
            entry: &'life2 IssuanceEntry,
        ) -> BoxFuture<'async_trait, Result<(), InstallRefusal>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            let view = self
                .0
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            Box::pin(async move {
                match view {
                    Some(v) => v.check(grant, entry).await,
                    None => Err(InstallRefusal::StoreViewUnavailable),
                }
            })
        }
    }

    /// The end-of-grant cleanup (U10-C's `StoreCleanup`), bound once the connection
    /// supervisor exists. It first closes the grants' owned connections through the
    /// event-emitting connection control (each closed row reported once, with the
    /// reason its grant's state gives), then runs `StoreCleanup` (slots by generation,
    /// binding files, slot paths; its own connection pass then finds those rows
    /// closed). Unset (or after stop): `Unavailable`, so the caller keeps its cleanup
    /// intent and retries (D7 item 2).
    #[derive(Default)]
    pub(super) struct LateCleanup(RwLock<Option<(StoreCleanup, Arc<ManagedConnections>)>>);

    impl LateCleanup {
        pub(super) fn set(&self, v: Option<(StoreCleanup, Arc<ManagedConnections>)>) {
            *self.0.write().unwrap_or_else(PoisonError::into_inner) = v;
        }

        fn get(&self) -> Option<(StoreCleanup, Arc<ManagedConnections>)> {
            self.0
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl EndCleanup for LateCleanup {
        fn after_end<'a>(
            &'a self,
            grants: &'a [GrantId],
        ) -> BoxFuture<'a, Result<(), AdapterError>> {
            Box::pin(async move {
                let Some((cleanup, connections)) = self.get() else {
                    return Err(AdapterError::Unavailable(
                        "managed_cleanup_unavailable".to_owned(),
                    ));
                };
                let closed = connections.close_ended(grants).await;
                let cleaned = cleanup.after_end(grants).await;
                match (closed, cleaned) {
                    (true, Ok(())) => Ok(()),
                    (_, Err(e)) => Err(e),
                    (false, Ok(())) => Err(AdapterError::Unavailable(
                        "managed_cleanup_incomplete".to_owned(),
                    )),
                }
            })
        }
    }
}

impl ManagedParts {
    fn build(
        m: &ManagedOptions,
        paths: &Paths,
        store: &Arc<Store>,
        environment: &EnvironmentId,
        token: &str,
        floor: heimdall_contract::managed::LockBehavior,
    ) -> Result<Self, ServiceError> {
        #[cfg(debug_assertions)]
        let vault = match &m.test_key_seed {
            Some(seed) => KeyVault::with_test_seed(seed).map_err(|_| {
                ServiceError::App(heimdall_app::OpError::new(
                    Code::UsageError,
                    "the test key seed must be 1 to 64 bytes",
                ))
            })?,
            None => KeyVault::new(),
        };
        #[cfg(not(debug_assertions))]
        let vault = {
            let _ = m;
            KeyVault::new()
        };
        let vault = Arc::new(vault);
        let sources = StoreSources::new(Arc::clone(store), environment.clone());
        sources.set_lock_floor(floor);
        let table = SignerTable::new(Arc::clone(&vault));
        let install_view = Arc::new(sources::LateInstallView::default());
        let view: Arc<dyn heimdall_credential::table::InstallView> = install_view.clone();
        table.set_install_view(view);
        let layout = if cfg!(windows) {
            EndpointLayout::windows(token)
        } else {
            let _ = token;
            EndpointLayout::unix(&paths.runtime_dir)
        }
        .ok_or_else(|| {
            ServiceError::Bind(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the managed endpoint layout is unavailable",
            ))
        })?;
        let late = Arc::new(LateRegistry::default());
        let endpoints: Arc<dyn heimdall_adapters::managed::effects::BindingEndpoints> =
            late.clone();
        let effects = ManagedEffectsImpl::new(
            table.clone(),
            endpoints,
            sources::scopes(&sources),
            paths.runtime_dir.clone(),
            SlotRoot {
                data_dir: paths.state_dir.clone(),
                environment: environment.clone(),
            },
        )
        .with_slot_store(sources::slots(&sources));
        Ok(Self {
            vault,
            table,
            layout,
            late,
            effects,
            sources,
            install_view,
            cleanup: Arc::new(sources::LateCleanup::default()),
            evidence: Arc::new(sources::LateEvidenceFeed::default()),
        })
    }

    fn adapter(
        &self,
        writer: Option<Arc<dyn heimdall_app::ports::ProjectionWriter>>,
    ) -> Arc<ManagedCertificateAdapter> {
        let cleanup: Arc<dyn heimdall_adapters::managed::EndCleanup> = self.cleanup.clone();
        Arc::new(
            ManagedCertificateAdapter::new(
                "default",
                sources::read(&self.sources, writer, Arc::clone(&self.evidence)),
                Some(self.effects.clone()),
                Some(self.layout.clone()),
            )
            .with_cleanup(cleanup),
        )
    }

    fn pair_source(
        &self,
        store: &Arc<Store>,
        paths: &Paths,
        environment: &EnvironmentId,
    ) -> Arc<dyn heimdall_localenv::projection::ManagedPairSource> {
        store_pair_source(
            Arc::clone(store),
            environment.clone(),
            self.layout.environment(),
            paths.state_dir.clone(),
            paths.runtime_dir.clone(),
        )
    }

    /// m03-plan U10's start order after recovery (module docs).
    #[allow(clippy::too_many_arguments)]
    async fn start(
        self,
        m: ManagedOptions,
        ops: &Operations,
        store: &Arc<Store>,
        paths: &Paths,
        wired: Option<&WiredProjection>,
        owner: ExpectedOwner,
        floor: heimdall_contract::managed::LockBehavior,
        stop: CancellationToken,
        control_locator: String,
    ) -> Result<ManagedRuntime, ServiceError> {
        let mut steps = Vec::new();
        let authority: Arc<dyn heimdall_app::ports::SignatureAuthority> = Arc::new(ops.clone());
        let registry = EndpointRegistry::new(
            self.layout.clone(),
            owner,
            self.table.clone(),
            authority,
            SignerLimits::default(),
            stop,
        )
        .with_verification_gates(ops.signing_gates().clone());
        // ⟨§17.22 item 3, W4-S03⟩ From the first reference cycle on, a failed start
        // unwinding (any `?` below) runs the full teardown: the guard owns every part
        // that `Drop` must stop or clear, and the issuer joins it the moment it exists.
        let mut teardown = ManagedTeardown {
            ops: ops.clone(),
            vault: Arc::clone(&self.vault),
            registry: registry.clone(),
            late: Arc::clone(&self.late),
            install_view: Arc::clone(&self.install_view),
            cleanup: Arc::clone(&self.cleanup),
            issuer: None,
            platform_lock: None,
            stopped: false,
        };
        self.late.set(registry.clone());
        // U2-Q2: the install view reads through the operations.
        self.install_view
            .set(Some(crate::managed_store::OpsInstallView::new(ops.clone())));
        steps.push(start_step::REGISTRY);

        // The session-lock source (U9), on the blocking pool (its start waits for the
        // first reading).
        let (lock_source, platform_lock): (
            Option<Arc<dyn SessionLockSource>>,
            Option<Arc<PlatformSessionLockSource>>,
        ) = match m.session_lock {
            SessionLockWiring::Platform => {
                let p = blocking(PlatformSessionLockSource::start).await?;
                let s: Arc<dyn SessionLockSource> = p.clone();
                (Some(s), Some(p))
            }
            SessionLockWiring::Source(s) => (Some(s), None),
            SessionLockWiring::None => (None, None),
        };
        teardown.platform_lock.clone_from(&platform_lock);
        if let Some(s) = &lock_source {
            ops.set_session_lock_source(Arc::clone(s));
        }
        // ⟨§17.25 item 23 (Q-R3)⟩ The platform source names its signal explicitly, so the
        // `signal_unverified` label never relies on `LockSignal::of_platform`'s default.
        // A source reading `unavailable` reports `LockSignal::None`, which is not stored:
        // `Operations::session_lock_signal` already answers `None` while it reads so, and
        // a stored `None` would drop the label if the source later read a state.
        if let Some(p) = &platform_lock
            && p.signal() != heimdall_app::lock::LockSignal::None
        {
            ops.set_session_lock_signal(p.signal());
        }
        let state = lock_source
            .as_ref()
            .map_or(LockState::Unavailable, |s| s.state());
        let floor_refusal = heimdall_app::lock::floor_refusal(floor, state);
        if let Some(e) = &floor_refusal {
            tracing::warn!(
                code = %e.code,
                reason = heimdall_contract::envelope::reason::LOCK_SIGNAL_UNAVAILABLE,
                "the configured lock behaviour needs a session-lock signal; revoke-on-lock grants do not sign"
            );
        }
        steps.push(start_step::SESSION_LOCK);

        // One connection supervisor (U7).
        let clients = wired.map(|w| &w.config.clients);
        let ssh = clients.and_then(|c| c.selected(ClientKind::Ssh));
        let late_endpoints: Arc<dyn crate::connections::BindingEndpoints> = self.late.clone();
        let mut conn = crate::connections::ConnectionConfig::new(
            paths.runtime_dir.clone(),
            ssh.map(|c| c.path.clone()).unwrap_or_default(),
            late_endpoints,
            Arc::new(crate::supervisor::RandomJitter),
        );
        conn.client_args = m.connection_client_args;
        conn.client_env = m.connection_client_env;
        let supervisor = Arc::new(crate::connections::ConnectionSupervisor::new(
            Arc::clone(store),
            Some(ops.clone()),
            conn,
        ));
        let connections = Arc::new(ManagedConnections::new(
            Arc::clone(&supervisor),
            Arc::clone(store),
            ops.clone(),
        ));
        // U10-C: the managed adapter's end-of-grant cleanup, now that the connection
        // supervisor exists.
        self.cleanup.set(Some((
            crate::managed_store::StoreCleanup::new(
                self.sources.clone(),
                self.effects.clone(),
                Some(supervisor),
            ),
            Arc::clone(&connections),
        )));

        // The issuer child (U3), its lifecycle, the verifier (U5), the target evaluator.
        let command = match m.issuer_command {
            Some(c) => Some(c),
            None => ChildCommand::internal_issuer().ok(),
        };
        let start_token: heimdall_issuer::client::StartToken = m
            .issuer_start_token
            .unwrap_or_else(|| Arc::new(crate::platform::process_start_time));
        // ⟨ADR-0008 §17.28 item 1, §17.32; round 10 L1⟩ Every start and load of the child
        // (K_ca read into it) takes the uninstall fence's admission first: a restart or
        // reload outside the holder's scope waits for the lift.
        let load_gate = ops.issuer_load_gate();
        let issuer = command.map(|c| {
            let mut config = ClientConfig::new(c, start_token);
            config.load_gate = Some(load_gate);
            ChildIssuer::new(config)
        });
        teardown.issuer.clone_from(&issuer);
        if let Some(i) = &issuer {
            self.sources.set_issuer(Arc::new(i.clone()));
        }
        // ⟨ADR-0008 §17.25 item 3⟩ Test configuration, debug builds only: the same
        // directory pauses the enrollment scripts, whose points the app inserts when it
        // builds a step (the CLI only validates the variable).
        #[cfg(debug_assertions)]
        ops.set_script_pause_dir(m.script_pause_dir.as_deref());
        let verifier = match (ssh, ssh.and_then(|c| c.version)) {
            (Some(c), Some(v)) => {
                let client = VerifierClient {
                    path: c.path.clone(),
                    version: ClientVersion {
                        family: if Platform::current().is_windows() {
                            ClientFamily::Win32
                        } else {
                            ClientFamily::Portable
                        },
                        major: v.major,
                        minor: v.minor,
                        portable: v.portable,
                    },
                };
                let v = Verifier::with_client(client, paths.runtime_dir.clone());
                match m.script_pause_dir {
                    Some(dir) => v.with_test_pause_dir(dir),
                    None => v,
                }
            }
            // No verified client: every verification is refused, inconclusive.
            _ => Verifier::new(),
        };
        let target = wired.map(|w| {
            let c = &w.config;
            let t = LocalTargetEvaluator::new(c.paths.clone(), c.env.clone(), c.platform)
                .with_managed_file(c.managed_ssh_path());
            let t = match ssh.and_then(|s| s.version) {
                Some(v) => t.with_client_version(v),
                None => t,
            };
            let t: Arc<dyn heimdall_app::ports::TargetEvaluator> = Arc::new(t);
            t
        });
        // U10-A's enrollment host (the runtime's files, client and endpoints); without a
        // wired projection there is no client inventory, so no host (fail closed).
        if let Some(w) = wired {
            let c = &w.config;
            let mut t = LocalTargetEvaluator::new(c.paths.clone(), c.env.clone(), c.platform)
                .with_managed_file(c.managed_ssh_path());
            if let Some(v) = ssh.and_then(|s| s.version) {
                t = t.with_client_version(v);
            }
            let host: Arc<dyn heimdall_app::enrollment::EnrollmentHost> =
                Arc::new(RuntimeEnrollmentHost {
                    runtime_dir: paths.runtime_dir.clone(),
                    client: ssh.map(|s| (s.path.clone(), s.version)),
                    target: t,
                    endpoints: vec![control_locator.clone(), registry.environment().locator],
                    windows: c.platform.is_windows(),
                });
            // ⟨R3-A, §17.22 item 7⟩ The managed sources' evidence comparison reads the
            // same evaluator and client.
            if let Some(target) = &target {
                self.evidence.set(Some(Arc::new(
                    heimdall_adapters::managed::prepare::TargetAndClient {
                        target: Arc::clone(target),
                        host: Arc::clone(&host),
                    },
                )));
            }
            ops.set_enrollment_host(host);
        }
        let effects: Arc<dyn heimdall_app::ports::ManagedEffects> = Arc::new(self.effects.clone());
        let verification: Arc<dyn heimdall_app::ports::VerificationEndpoints> =
            Arc::new(registry.clone());
        let control: Arc<dyn ConnectionControl> = connections.clone();
        ops.set_managed_wiring(ManagedWiring {
            effects: Some(effects),
            // U10-B (B3): the same client is the port and the lifecycle.
            issuer: issuer.clone().map(|i| {
                let p: Arc<dyn heimdall_app::ports::IssuerPort> = Arc::new(i);
                p
            }),
            issuer_lifecycle: issuer.clone().map(|i| {
                let l: Arc<dyn heimdall_app::issuer::IssuerLifecycle> = Arc::new(i);
                l
            }),
            verification_endpoints: Some(verification),
            verification_runner: Some(Arc::new(verifier)),
            target,
            connections: Some(control),
        });
        steps.push(start_step::WIRING);

        // U7: the restart pass first (§17.20 item 4); a discovery failure is retried by
        // the supervisor's sweep (D7 item 2).
        if let Err(f) = connections.restart_pass().await {
            tracing::warn!(
                word = f.word(),
                "connection restart pass could not enumerate"
            );
        }
        steps.push(start_step::CONNECTION_RESTART_PASS);

        // U3: the issuer child, when a CA is registered (`active` or `pending`). A
        // failed start is the supervision's restart cycle's (signing with installed
        // keys is unaffected; re-issue waits for it).
        let registered = {
            let s = Arc::clone(store);
            blocking(move || s.transaction(|tx| tx.issuers()))
                .await?
                .map_err(ServiceError::Store)?
                .iter()
                .any(|r| matches!(r.state, CaState::Active | CaState::Pending))
        };
        match (&issuer, registered) {
            (Some(i), true) => {
                if let Err(e) = i.start().await {
                    tracing::warn!(error = %e, "the issuer child did not start; it is restarted");
                }
                steps.push(start_step::ISSUER_START);
            }
            _ => steps.push(start_step::ISSUER_NOT_NEEDED),
        }

        // U2: the environment endpoint (it serves M01's signing path; one signer).
        registry.start_environment().map_err(|e| {
            ServiceError::Bind(std::io::Error::other(format!("environment endpoint: {e}")))
        })?;
        steps.push(start_step::ENVIRONMENT_ENDPOINT);

        // U10-C: re-issue the credentials of `lost` instances.
        if let Err(e) = ops.managed_reissue_pass().await {
            tracing::warn!(code = %e.code, "managed re-issue pass failed at start");
        }
        steps.push(start_step::MANAGED_REISSUE_PASS);

        Ok(ManagedRuntime {
            teardown,
            connections,
            lock_source,
            lock_passes: m.lock_passes,
            floor_refusal,
            steps,
        })
    }
}

/// The running managed wiring (module docs).
struct ManagedRuntime {
    /// What every end of this wiring undoes ([`ManagedTeardown`]).
    teardown: ManagedTeardown,
    connections: Arc<ManagedConnections>,
    lock_source: Option<Arc<dyn SessionLockSource>>,
    lock_passes: LockPassConfig,
    floor_refusal: Option<heimdall_app::OpError>,
    steps: Vec<&'static str>,
}

impl ManagedRuntime {
    /// ⟨§17.21 item 11⟩ The end-of-grant cleanup the supervisor's ended-slot pass runs
    /// (the late-bound `StoreCleanup`; unset or after stop it refuses, so the slot rows
    /// stay the intent).
    fn end_cleanup(&self) -> Arc<dyn heimdall_adapters::managed::EndCleanup> {
        self.teardown.cleanup.clone()
    }

    /// m03-plan U10's stop order, after accepting stopped: close the owned masters,
    /// zeroize the vault, shut the issuer down (awaited), remove the endpoints; then the
    /// M03 wiring is cleared (breaking the reference cycles).
    async fn stop(mut self) {
        let report = self.connections.shutdown().await;
        if !report.unverified.is_empty() || !report.failed.is_empty() {
            tracing::warn!(
                unverified = report.unverified.len(),
                failed = report.failed.len(),
                "some owned masters were not closed at stop"
            );
        }
        let t = &mut self.teardown;
        t.vault.destroy_all();
        if let Some(i) = t.issuer.take() {
            i.stop().await;
        }
        t.release();
        t.stopped = true;
        tracing::info!("managed credentials stopped: vault zeroized, issuer stopped");
    }
}

/// ⟨ADR-0008 §17.22 item 3, W4-S03⟩ What every end of a started managed wiring undoes,
/// whether `run` was entered or not: [`ManagedRuntime::stop`] (the ordinary stop), a
/// dropped [`Service`], and a start that fails after its first reference cycle exists
/// (the guard is built right after the endpoint registry, so any `?` of
/// `ManagedParts::start` or of `Service::start_with` after it unwinds through `Drop`).
///
/// The cycles it breaks: `Operations → adapters → effects → LateRegistry →
/// EndpointRegistry → SignatureAuthority (the Operations)`, `Operations →
/// ManagedWiring → {issuer lifecycle, verification endpoints (the registry),
/// connections (→ Operations)}`, the install view (`SignerTable → LateInstallView →
/// OpsInstallView (the Operations)`) and the end-of-grant cleanup (`→ connections →
/// Operations`). Without that, dropping every public handle left the issuer child alive
/// with its CA loaded and the vault retained (the reviewer's probe).
///
/// On drop (unless the ordinary stop ran): the vault is zeroized; the issuer lifecycle
/// is **fenced and stopped** (`ChildIssuer::stop`: the lifecycle is ended first, so no
/// restart or reload of it spawns a child or loads a CA, then the child is asked to exit
/// and ended through its own handle after `STOP_TIMEOUT`), spawned on the current tokio
/// runtime because `Drop` cannot await (outside a runtime the client's last handle, freed
/// once the cycles are broken, ends the child through `kill_on_drop`); the endpoints are
/// stopped; the session-lock source is shut down; and the managed wiring, the late
/// registry, the install view and the cleanup are cleared. The child is only ever ended
/// through the exact handle that spawned it.
struct ManagedTeardown {
    ops: Operations,
    vault: Arc<KeyVault>,
    registry: EndpointRegistry,
    late: Arc<LateRegistry>,
    install_view: Arc<sources::LateInstallView>,
    cleanup: Arc<sources::LateCleanup>,
    issuer: Option<ChildIssuer>,
    platform_lock: Option<Arc<PlatformSessionLockSource>>,
    /// The ordinary stop ran to its end (its issuer stop was awaited).
    stopped: bool,
}

impl ManagedTeardown {
    /// The synchronous, idempotent part of every end: zeroize, stop the endpoints and
    /// the lock source, and break the cycles.
    fn release(&mut self) {
        self.vault.destroy_all();
        self.registry.stop_all();
        if let Some(p) = &self.platform_lock {
            p.shutdown();
        }
        self.ops.set_managed_wiring(ManagedWiring::default());
        self.late.clear();
        self.install_view.set(None);
        self.cleanup.set(None);
    }
}

impl Drop for ManagedTeardown {
    fn drop(&mut self) {
        if self.stopped {
            return;
        }
        self.vault.destroy_all();
        if let Some(issuer) = self.issuer.take() {
            match tokio::runtime::Handle::try_current() {
                Ok(rt) => {
                    rt.spawn(async move { issuer.stop().await });
                }
                // No runtime to run the stop on: dropping this last handle (the cycles
                // are broken below) ends the child through its own `kill_on_drop`.
                Err(_) => drop(issuer),
            }
        }
        self.release();
        tracing::info!(
            "managed credentials torn down without stop: vault zeroized, issuer stopping"
        );
    }
}

// --- ⟨M03⟩ wave 4: the enrollment host (U10-A's `EnrollmentHost`, runtime side) ---------

/// The bound of the `ssh -G` effective-configuration check.
const EFFECTIVE_CONFIG_TIMEOUT: Duration = Duration::from_secs(10);

/// The most `ssh -G` output read.
const EFFECTIVE_CONFIG_MAX_BYTES: u64 = 1 << 20;

/// `heimdall_app::enrollment::EnrollmentHost` over this runtime (U10-A's port; ADR-0008
/// D5 §6.3): the verified client of the client inventory, the generated host-trust files
/// under `<runtime_dir>/e/<tag>/` (directories 0700, files 0600, no symlink followed,
/// contents read back and compared), the Q24 `IdentityAgent` reading and the endpoint
/// re-validation through the passive `LocalTargetEvaluator`, Heimdall's own endpoints,
/// and the bounded `ssh -G` check (it parses configuration and connects to nothing).
/// Without a verified client every call that needs one fails (fail closed).
struct RuntimeEnrollmentHost {
    runtime_dir: PathBuf,
    client: Option<(PathBuf, Option<heimdall_sshconf::eval::OpenSshVersion>)>,
    target: LocalTargetEvaluator,
    endpoints: Vec<String>,
    windows: bool,
}

/// A path as the enrollment port names it: absolute, `/` separators.
fn slash_path(p: &std::path::Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// `dir` exists as a real directory (not a symlink) owned by this user and owner-only,
/// created 0700 if absent (Unix; on Windows the runtime directory's DACL applies).
fn owner_dir(dir: &std::path::Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            return Err(std::io::Error::other("not a real directory"));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new().mode(0o700).create(dir)?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir(dir)?;
        }
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let m = std::fs::symlink_metadata(dir)?;
        if m.uid() != heimdall_ipc::unix::current_uid() {
            return Err(std::io::Error::other("directory owned by another user"));
        }
        if m.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Replace `path` with exactly `bytes` (owner-only), never following a symlink, then
/// read it back and compare.
fn write_owner_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => return Err(std::io::Error::other("a directory is in the way")),
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    if std::fs::read(path)? != bytes {
        return Err(std::io::Error::other("the written file differs"));
    }
    Ok(())
}

impl RuntimeEnrollmentHost {
    fn tag_ok(tag: &str) -> bool {
        tag.len() == 16 && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    fn dir(&self, tag: &str) -> Option<PathBuf> {
        Self::tag_ok(tag).then(|| self.runtime_dir.join("e").join(tag))
    }
}

impl heimdall_app::enrollment::EnrollmentHost for RuntimeEnrollmentHost {
    fn client(&self) -> Option<String> {
        self.client.as_ref().map(|(p, _)| slash_path(p))
    }

    fn client_version(&self) -> Option<String> {
        let (_, v) = self.client.as_ref()?;
        let v = v.as_ref()?;
        let text = heimdall_localenv::local_query::version_text(v);
        Some(if self.windows {
            format!("OpenSSH_for_Windows_{text}")
        } else {
            format!("OpenSSH_{text}")
        })
    }

    fn paths(&self, tag: &str) -> Option<heimdall_app::enrollment::GeneratedPaths> {
        let dir = self.dir(tag)?;
        Some(heimdall_app::enrollment::GeneratedPaths {
            trust: heimdall_app::enrollment::TrustPaths {
                tag: tag.to_owned(),
                user_known_hosts: slash_path(&dir.join("known_hosts")),
                global_known_hosts: slash_path(&dir.join("global_known_hosts")),
            },
            identity_file: slash_path(&dir.join("identity.pub")),
        })
    }

    fn write_files(
        &self,
        tag: &str,
        known_hosts_line: &str,
        identity_public: Option<&str>,
    ) -> Result<heimdall_app::enrollment::GeneratedPaths, heimdall_app::enrollment::HostError> {
        let fail = |what: &str| heimdall_app::enrollment::HostError(what.to_owned());
        let dir = self.dir(tag).ok_or_else(|| fail("invalid tag"))?;
        let paths = self.paths(tag).ok_or_else(|| fail("invalid tag"))?;
        if known_hosts_line.contains(['\n', '\r']) {
            return Err(fail("the known-hosts line is not one line"));
        }
        owner_dir(&self.runtime_dir.join("e")).map_err(|_| fail("enrollment directory unsafe"))?;
        owner_dir(&dir).map_err(|_| fail("enrollment directory unsafe"))?;
        write_owner_file(
            &dir.join("known_hosts"),
            format!("{known_hosts_line}\n").as_bytes(),
        )
        .map_err(|_| fail("known-hosts file not written"))?;
        write_owner_file(&dir.join("global_known_hosts"), b"")
            .map_err(|_| fail("global known-hosts file not written"))?;
        if let Some(public) = identity_public {
            if public.contains(['\n', '\r']) {
                return Err(fail("the public key is not one line"));
            }
            write_owner_file(&dir.join("identity.pub"), format!("{public}\n").as_bytes())
                .map_err(|_| fail("identity file not written"))?;
        }
        Ok(paths)
    }

    fn identity_agent(&self, alias: &str) -> heimdall_app::enrollment::AgentReading {
        use heimdall_app::enrollment::AgentReading;
        use heimdall_localenv::target::IdentityAgentEvaluation;
        match self.target.evaluate_identity_agent(alias, true) {
            IdentityAgentEvaluation::Determined(e) => AgentReading::Determined(e.locator),
            IdentityAgentEvaluation::Unset => AgentReading::Unset,
            _ => AgentReading::Undetermined,
        }
    }

    fn endpoint_valid(&self, endpoint: &str) -> bool {
        let reference = EndpointRef {
            kind: if self.windows {
                AgentEndpointKind::NamedPipe
            } else {
                AgentEndpointKind::UnixSocket
            },
            locator: endpoint.to_owned(),
        };
        let check = self.target.check_endpoint(&reference);
        // A pipe cannot be checked passively: never valid (fail closed).
        if check.presence != heimdall_localenv::agents::Presence::Present {
            return false;
        }
        let Some(resolved) = check.resolved else {
            return false;
        };
        let resolved = resolved.replace('\\', "/");
        let runtime = std::fs::canonicalize(&self.runtime_dir)
            .map_or_else(|_| slash_path(&self.runtime_dir), |p| slash_path(&p));
        let ours = |e: &String| {
            let e = e.replace('\\', "/");
            resolved == e || endpoint.replace('\\', "/") == e
        };
        !(resolved.starts_with(&format!("{runtime}/")) || self.endpoints.iter().any(ours))
    }

    fn heimdall_endpoints(&self) -> Vec<String> {
        let mut out = self.endpoints.clone();
        out.push(slash_path(&self.runtime_dir));
        out
    }

    fn effective_config(
        &self,
        step: &heimdall_contract::enrollment::RemoteStep,
    ) -> Result<String, heimdall_app::enrollment::HostError> {
        use std::io::Read as _;
        let fail = |what: &str| heimdall_app::enrollment::HostError(what.to_owned());
        let (client, _) = self
            .client
            .as_ref()
            .ok_or_else(|| fail("no verified client"))?;
        let mut child = std::process::Command::new(client)
            .args(heimdall_app::enrollment::effective_config_args(step))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| fail("the client could not run"))?;
        let mut stdout = child.stdout.take().ok_or_else(|| fail("no output"))?;
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = (&mut stdout)
                .take(EFFECTIVE_CONFIG_MAX_BYTES)
                .read_to_end(&mut out);
            out
        });
        let deadline = std::time::Instant::now() + EFFECTIVE_CONFIG_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => break None,
            }
        };
        let Some(status) = status else {
            // Our own child, by its handle.
            let _ = child.kill();
            let _ = child.wait();
            return Err(fail("the effective-configuration check timed out"));
        };
        let out = reader.join().map_err(|_| fail("no output"))?;
        if !status.success() {
            return Err(fail("the effective-configuration check failed"));
        }
        String::from_utf8(out).map_err(|_| fail("the output is not UTF-8"))
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod enrollment_host_tests {
    use super::*;
    use heimdall_app::enrollment::EnrollmentHost as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn host(runtime_dir: &std::path::Path) -> RuntimeEnrollmentHost {
        let home = runtime_dir.join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let paths = SshPaths::with_test_override(home.clone(), home.join("etc-ssh"));
        RuntimeEnrollmentHost {
            runtime_dir: runtime_dir.to_path_buf(),
            client: None,
            target: LocalTargetEvaluator::new(paths, Env::default(), Platform::current()),
            endpoints: vec![slash_path(&runtime_dir.join("signing.sock"))],
            windows: false,
        }
    }

    /// U10-A's host, runtime side: the generated files are written owner-only under
    /// `<runtime_dir>/e/<tag>/` with exactly the given bytes, a bad tag or a multi-line
    /// value is refused before any write, a symlinked tag directory is refused, and no
    /// client means no effective-configuration check (fail closed).
    #[test]
    fn enrollment_host_writes_owner_only_trust_files_and_refuses_unsafe_input() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        let h = host(&run);
        let tag = "0123456789abcdef";
        let p = h
            .write_files(
                tag,
                "hm-target-0123456789abcdef ssh-ed25519 AAAA",
                Some("ssh-ed25519 BBBB"),
            )
            .unwrap();
        let dir = run.join("e").join(tag);
        assert_eq!(
            p.trust.user_known_hosts,
            slash_path(&dir.join("known_hosts"))
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("known_hosts")).unwrap(),
            "hm-target-0123456789abcdef ssh-ed25519 AAAA\n"
        );
        assert_eq!(std::fs::read(dir.join("global_known_hosts")).unwrap(), b"");
        assert_eq!(
            std::fs::read_to_string(dir.join("identity.pub")).unwrap(),
            "ssh-ed25519 BBBB\n"
        );
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&run.join("e")), 0o700);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("known_hosts")), 0o600);
        // A rewrite replaces the bytes exactly.
        h.write_files(tag, "hm-target-0123456789abcdef ssh-ed25519 CCCC", None)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("known_hosts")).unwrap(),
            "hm-target-0123456789abcdef ssh-ed25519 CCCC\n"
        );
        // Refused before any write.
        assert!(h.write_files("../escape", "x", None).is_err());
        assert!(h.write_files("0123456789ABCDEF", "x", None).is_err());
        assert!(h.paths("short").is_none());
        let other = "fedcba9876543210";
        assert!(h.write_files(other, "a\nb", None).is_err());
        assert!(!run.join("e").join(other).exists());
        // A planted symlink as the tag directory is never followed.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, run.join("e").join(other)).unwrap();
        assert!(h.write_files(other, "line", None).is_err());
        assert!(!elsewhere.join("known_hosts").exists());
        // No verified client: no `ssh -G`, no version.
        assert!(h.client().is_none() && h.client_version().is_none());
        // Heimdall's endpoints and runtime directory are listed; one under the runtime
        // directory is never a valid existing-access endpoint.
        assert!(h.heimdall_endpoints().contains(&slash_path(&run)));
        assert!(!h.endpoint_valid(&slash_path(&run.join("signing.sock"))));
        assert!(!h.endpoint_valid("/nonexistent/agent.sock"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod pair_source_tests {
    use super::*;
    use heimdall_contract::ids::{AccountName, DestinationId, IdentityId, PolicyId, ProfileId};
    use heimdall_contract::managed::{ExistingConnectionsMode, MultiplexingMode};
    use heimdall_contract::request::Capability;
    use heimdall_domain::enrollment::{PairPreference, ProjectionStatus};
    use heimdall_domain::policy::{
        ConnectionPolicy, PauseState, PolicyRevision, PolicySource, StandingPolicy,
    };
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::projection::ManagedAliasSpec;
    use heimdall_domain::scope::{AccessPair, Scope};
    use heimdall_localenv::projection::ManagedPairSource as _;

    fn t0() -> heimdall_contract::Timestamp {
        "2026-11-11T10:00:00Z".parse().unwrap()
    }

    fn env() -> EnvironmentId {
        EnvironmentId::from_random_bytes([0x5a; 16])
    }

    fn pair() -> AccessPair {
        AccessPair {
            destination: DestinationId::parse("lab").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn alias() -> ManagedAliasSpec {
        ManagedAliasSpec {
            alias: "lab".into(),
            destination: pair().destination,
            hostname: "lab.example.invalid".into(),
            port: None,
            account: pair().account,
            identity: IdentityId::from_random_bytes([0x41; 16]),
            endpoint: None,
            key_file: "/k/lab.pub".into(),
        }
    }

    /// A store with the pair preferring `managed_certificate` and one standing policy
    /// per entry of `policies` (`(profile, multiplexing, covers the pair)`).
    fn store(policies: &[(&str, MultiplexingMode, bool)]) -> Arc<Store> {
        let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
        store
            .transaction(|tx| {
                tx.set_pair_preference(
                    &PairPreference {
                        destination: pair().destination,
                        account: pair().account,
                        mechanism: PreferredMechanism::ManagedCertificate,
                        projection: ProjectionStatus::Applied { generation: 1 },
                        issuing_cas: Default::default(),
                    },
                    t0(),
                )?;
                for (n, (profile, multiplexing, covers)) in policies.iter().enumerate() {
                    let other = AccessPair {
                        destination: DestinationId::parse("other").unwrap(),
                        account: pair().account,
                    };
                    let scope = Scope {
                        pairs: [if *covers { pair() } else { other }].into_iter().collect(),
                        capabilities: [Capability::SshAuthentication].into_iter().collect(),
                    };
                    tx.upsert_profile(&ProfileDefinition {
                        id: ProfileId::parse(profile).unwrap(),
                        revision: 1,
                        scope: scope.clone(),
                        label: None,
                    })?;
                    tx.upsert_policy(
                        &StandingPolicy {
                            id: PolicyId::parse(&format!("pol{n}")).unwrap(),
                            revision: PolicyRevision(1),
                            profile: ProfileId::parse(profile).unwrap(),
                            workspace: None,
                            scope,
                            environments: [env()].into_iter().collect(),
                            max_window: Duration::from_secs(3600),
                            pause: PauseState::Active,
                            cutoff_at: None,
                            source: PolicySource::SetupDefault,
                            lock_behavior: Default::default(),
                            connection: ConnectionPolicy {
                                existing: ExistingConnectionsMode::Graceful,
                                multiplexing: *multiplexing,
                            },
                        },
                        false,
                    )?;
                }
                Ok(())
            })
            .unwrap();
        store
    }

    fn source(store: Arc<Store>, runtime_dir: &std::path::Path) -> StorePairSource {
        StorePairSource {
            store,
            environment: env(),
            environment_endpoint: EndpointRef {
                kind: AgentEndpointKind::UnixSocket,
                locator: runtime_dir
                    .join("signing.sock")
                    .to_string_lossy()
                    .into_owned(),
            },
            state_dir: runtime_dir.join("state"),
            runtime_dir: runtime_dir.to_path_buf(),
        }
    }

    /// ADR-0008 §17.21 item 9 (U10-D-Q4 option (a); D8 items 1 and 3): the store-backed
    /// pair source renders the slot's stable mux path in P only when owned masters are
    /// enabled for the pair (every applicable standing policy `owned_masters`); with
    /// masters disabled, with any applicable policy disabled (the fail-closed merge),
    /// or with no applicable policy, `ControlPath none`. A policy that does not cover
    /// the pair does not count. (On Windows owned masters are unavailable: never a
    /// path.)
    #[test]
    fn pair_source_renders_mux_path_only_when_owned_masters_enabled() {
        use MultiplexingMode::{Disabled, OwnedMasters};
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("r");
        let path_of = |policies: &[(&str, MultiplexingMode, bool)]| {
            source(store(policies), &run)
                .managed_section(&alias())
                .unwrap()
                .expect("managed section")
                .control_path
        };
        let mux =
            heimdall_localenv::projection::content::checked_mux_path(&run, &pair().destination)
                .unwrap();
        let enabled = path_of(&[("dev", OwnedMasters, true)]);
        if cfg!(windows) {
            assert_eq!(enabled, None, "owned masters are unavailable on Windows");
        } else {
            assert_eq!(enabled, Some(mux.clone()), "enabled: the stable mux path");
            assert_eq!(
                path_of(&[("dev", OwnedMasters, true), ("ops", OwnedMasters, true)]),
                Some(mux)
            );
        }
        assert_eq!(path_of(&[("dev", Disabled, true)]), None, "disabled");
        assert_eq!(
            path_of(&[("dev", OwnedMasters, true), ("ops", Disabled, true)]),
            None,
            "one applicable policy disabled: the strictest wins"
        );
        assert_eq!(path_of(&[]), None, "no applicable policy");
        assert_eq!(
            path_of(&[("dev", OwnedMasters, false)]),
            None,
            "a policy that does not cover the pair does not enable it"
        );
    }

    /// The same source with a path past the socket limit (`mux_path_too_long`, D8 item
    /// 3) renders `ControlPath none` even with masters enabled.
    #[test]
    fn pair_source_mux_path_too_long_renders_none() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("x".repeat(120));
        let section = source(
            store(&[("dev", MultiplexingMode::OwnedMasters, true)]),
            &run,
        )
        .managed_section(&alias())
        .unwrap()
        .unwrap();
        assert_eq!(section.control_path, None);
    }
}
