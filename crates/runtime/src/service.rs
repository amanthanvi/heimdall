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

/// The issuer client's configuration as the runtime wires it: `command`, `start_token`,
/// and ⟨ADR-0008 §17.28 item 1, §17.32; round 10 L1⟩ the uninstall fence's load gate, and
/// ⟨§17.33 item 2 (W5-E02)⟩ the request hold (a `sign` holds an extension of its caller's
/// admission until its reply or its exact child's confirmed exit) and the image reader of
/// the exact-child check (`localenv::sys::ProcessPin`). Public so tests drive the real
/// `internal issuer` child through the same wiring.
#[must_use]
pub fn issuer_client_config(
    command: ChildCommand,
    start_token: heimdall_issuer::client::StartToken,
    ops: &Operations,
) -> ClientConfig {
    let mut config = ClientConfig::new(command, start_token);
    config.load_gate = Some(ops.issuer_load_gate());
    config.request_hold = Some(ops.issuer_request_hold());
    config.child_image = Some(Arc::new(|pid| {
        heimdall_localenv::sys::ProcessPin::open(pid)
            .ok()
            .flatten()
            .and_then(|p| p.image())
    }));
    // ⟨M04 U2; ADR-0010 §1 item 6⟩ On Windows the child inherits only its three standard
    // stream handles (an explicit handle list), never another inheritable handle of this
    // process.
    #[cfg(windows)]
    {
        config.spawner = Some(listed_issuer_spawner());
    }
    config
}

/// ⟨M04 U2⟩ The spawner [`issuer_client_config`] injects on Windows (public so the native
/// handle-inheritance test drives the same function the runtime uses).
#[cfg(windows)]
#[must_use]
pub fn listed_issuer_spawner() -> heimdall_issuer::client::ChildSpawner {
    Arc::new(listed_issuer_child)
}

/// ⟨M04 U2⟩ The issuer child as a handle-list child: its stdin and stdout piped, its stderr
/// null, the command's environment on top of this process's.
#[cfg(windows)]
fn listed_issuer_child(c: &ChildCommand) -> std::io::Result<heimdall_issuer::client::SpawnedChild> {
    use heimdall_localenv::sys::spawn::{ListedSpawn, ListedStdio, spawn_listed};
    let mut cmd = std::process::Command::new(&c.program);
    cmd.args(&c.args).envs(c.env.iter().map(|(k, v)| (k, v)));
    let options = ListedSpawn {
        stderr: ListedStdio::Null,
        // ⟨M03 E9; ADR-0008 §17.43, ruling I-24⟩ No console window: `spawn_listed` takes its
        // creation flags from here, not from the command (so `no_window!` would not reach it).
        creation_flags: heimdall_localenv::sys::spawn::CREATE_NO_WINDOW,
        ..ListedSpawn::piped()
    };
    let mut child = spawn_listed(&cmd, &options).map_err(std::io::Error::other)?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other("the issuer child has no pipes"));
    };
    Ok(heimdall_issuer::client::SpawnedChild {
        process: Box::new(ListedIssuerProcess(child)),
        stdin,
        stdout,
    })
}

/// ⟨M04 U2⟩ A handle-list child as the issuer client's process. Dropping it ends and reaps
/// the child, as the default spawn's `kill_on_drop` does.
#[cfg(windows)]
struct ListedIssuerProcess(heimdall_localenv::sys::spawn::ListedChild);

#[cfg(windows)]
impl heimdall_issuer::client::ChildProcess for ListedIssuerProcess {
    fn id(&self) -> Option<u32> {
        Some(self.0.id())
    }

    fn try_wait(&mut self) -> std::io::Result<bool> {
        Ok(self.0.try_wait()?.is_some())
    }

    fn start_kill(&mut self) -> std::io::Result<()> {
        self.0.kill()
    }

    fn exit_code(&mut self) -> Option<i32> {
        self.0.try_wait().ok().flatten()
    }
}

#[cfg(windows)]
impl Drop for ListedIssuerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// File name of the state database inside `Paths::state_dir`.
pub const STATE_DB_FILE: &str = "state.db";

/// ⟨ADR-0008 §17.35 item 7 (audit D1, D2)⟩ What in `state_dir` keeps the runtime from
/// creating or opening the state database: every `.hm-purge-*` entry (an interrupted
/// uninstall's quarantine: the database family's directory, or a quarantined tree), and,
/// when `state.db` is absent, its `-wal`, `-shm` and `-journal` (SQLite creating a new
/// database there would discard a log holding the only copy of commits). Sorted; empty
/// when start-up may open the store. Read after the instance lock is taken, so no
/// uninstall is moving files meanwhile.
///
/// # Errors
/// `state_dir` cannot be read.
pub fn quarantine_leftovers(
    state_dir: &std::path::Path,
) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(state_dir)? {
        let e = e?;
        if e.file_name().to_string_lossy().starts_with(".hm-purge-") {
            out.push(e.path());
        }
    }
    let present = |p: &std::path::Path| std::fs::symlink_metadata(p).is_ok();
    if !present(&state_dir.join(STATE_DB_FILE)) {
        for sfx in ["-wal", "-shm", "-journal"] {
            let p = state_dir.join(format!("{STATE_DB_FILE}{sfx}"));
            if present(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// ⟨§17.35 item 7⟩ The start-up refusal for [`quarantine_leftovers`]
/// (`SERVICE_UNAVAILABLE`, `uninstall_quarantine_present`, effect `none`).
fn quarantine_present(paths: &[std::path::PathBuf]) -> heimdall_app::OpError {
    let home = etcetera::home_dir().unwrap_or_default();
    let shown: Vec<String> = paths
        .iter()
        .map(|p| heimdall_localenv::paths::display_path(&home, p))
        .collect();
    heimdall_app::OpError::new(
        Code::ServiceUnavailable,
        format!(
            "the runtime did not start: the state directory holds an interrupted uninstall's quarantine or a database log without its database ({}), and opening the state store now could create a new database and discard commits that exist only in that log; nothing was opened or changed. Run `heimdall uninstall`, which restores the quarantined state database first",
            shown.join(", ")
        ),
    )
    .with_reason(heimdall_contract::envelope::reason::UNINSTALL_QUARANTINE_PRESENT)
    .with_effect(heimdall_contract::EffectStatus::None)
}

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
    /// ⟨M04⟩ U1: the login entry's port (`Operations::set_login_entry`): the setup item
    /// `login_entry` and `inspect capabilities` → `login_start`. `None` (the default of
    /// [`Self::with_clock`]): the item answers `driver_unavailable` and `login_start`
    /// reads `none`. `service run` wires the host's own
    /// ([`crate::autostart::port::HostLoginPort`]).
    pub login_entry: Option<Arc<dyn heimdall_app::ports::LoginEntryPort>>,
    /// ⟨M04 U3b⟩ The WSL host (`Operations::set_distribution_host`; ADR-0010 §2): `None`
    /// (the default) is the platform's own, [`heimdall_wsl::WslHost::platform`] with
    /// [`Self::wsl_helper`]: Lxss, `wsl.exe` and the bundled helper on Windows, none
    /// elsewhere (every WSL request then answers `wsl_unavailable`). A test injects its own.
    pub wsl_host: Option<Arc<dyn heimdall_app::ports::DistributionHost>>,
    /// ⟨M04 U3b⟩ The Windows path of the Linux helper binary, when not the one beside
    /// `heimdall.exe` (the debug-only test configuration's `HEIMDALL_WSL_HELPER`).
    pub wsl_helper: Option<std::path::PathBuf>,
    /// ⟨M04 U4b⟩ Starts WSL Mode B helper sessions
    /// ([`crate::wsl_bridge::BridgeFactory`]): `None` (the default) is the platform's own,
    /// [`crate::wsl_bridge::LauncherBridgeFactory`] over the platform host's launcher (on
    /// Windows; elsewhere none, so `wsl enable --mode-b` answers `driver_unavailable`). A
    /// test injects its own, with [`Self::wsl_host`].
    pub wsl_bridge: Option<Arc<dyn crate::wsl_bridge::BridgeFactory>>,
    /// ⟨M06 W2⟩ The ports of a runner's paired sessions (`crate::paired::RunnerOptions`:
    /// the authorized_keys writer, the forced command's paths, the verified sshd policy).
    /// Used only when this installation is a remote runner (`crate::paired::is_runner`,
    /// read at start); default: none, `owner_only`.
    pub runner: crate::paired::RunnerOptions,
    /// ⟨M06 W3⟩ The route and transport forms and the Iroh serve child
    /// (`crate::supervise_transport::TransportWiring`): production, this executable and the
    /// platform K_iroh store; [`Self::with_clock`]: `None` (the forms answer
    /// `driver_unavailable`, wave 0's landing).
    pub transport: Option<crate::supervise_transport::TransportWiring>,
    /// ⟨M06 W3 host⟩ The controller's hosted sync and issuance driver
    /// (`crate::controller_host`): how it opens management sessions to the recorded runners.
    /// `service run` wires the CLI's opener; `None` (the default): no host, so an outbox row
    /// waits and nothing is issued remotely. Never used by a remote runner.
    pub controller: Option<crate::controller_host::ControllerHostWiring>,
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
    /// **Test configuration only** (debug builds; ⟨M04-MC3-R03⟩): the issuer client's start
    /// diagnostics ([`ClientConfig::start_diagnostics`]). A release build has no such field.
    #[cfg(debug_assertions)]
    pub issuer_start_diagnostics: bool,
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
            #[cfg(debug_assertions)]
            issuer_start_diagnostics: false,
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
            transport: std::env::current_exe().ok().map(|program| {
                crate::supervise_transport::TransportWiring {
                    program,
                    keys: None,
                    announcer: None,
                }
            }),
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
            login_entry: None,
            wsl_host: None,
            wsl_helper: None,
            wsl_bridge: None,
            runner: crate::paired::RunnerOptions::default(),
            transport: None,
            controller: None,
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
    /// ⟨M06 W2⟩ The paired-session service when this installation is a remote runner.
    runner: Option<Arc<crate::paired::PairedRunner>>,
    /// ⟨M06 W3⟩ The serve child's supervisor and K_iroh custody
    /// ([`ServiceOptions::transport`]).
    transport: Option<(
        Arc<crate::supervise_transport::TransportSupervisor>,
        Arc<dyn heimdall_app::transport::TransportKeys>,
    )>,
    /// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ `transport.rotate`'s management channel to the
    /// recorded runners (`TransportWiring::announcer`).
    transport_announcer: Option<Arc<dyn heimdall_app::transport::EndpointAnnouncer>>,
    /// ⟨M06 W3 host⟩ The hosted controller driver's wiring ([`ServiceOptions::controller`]).
    controller: Option<crate::controller_host::ControllerHostWiring>,
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
        // ⟨M04, the Windows readiness failures⟩ Each phase's time to the advertisement, logged
        // once it is written ("the runtime advertised its endpoints").
        let phases = StartPhases::begin();
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

        // 2. ⟨ADR-0008 §17.35 item 7⟩ Before the store is created or opened: no
        //    interrupted uninstall's quarantine and no log without its database.
        let leftovers = quarantine_leftovers(&paths.state_dir).map_err(|e| {
            ServiceError::App(heimdall_app::OpError::new(
                Code::StateUnavailable,
                format!("the state directory could not be read: {e}"),
            ))
        })?;
        if !leftovers.is_empty() {
            return Err(ServiceError::App(quarantine_present(&leftovers)));
        }
        //    Store: open, integrity check, migrations (with backup).
        let db = paths.state_dir.join(STATE_DB_FILE);
        let faults = options.store_faults.clone();
        let store = blocking(move || Store::open(&db, faults)).await??;
        let phases = phases.mark("store_ms");
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
        // ⟨M06 W2⟩ A runner given its forced command but no management-line writer writes the
        // account's own authorized_keys files (`crate::paired_lines`), under the same account
        // home the projection uses: production, the account database's; a test runtime, the
        // scratch home its test configuration isolated, or none (no writer: fail closed).
        let runner_user_dir = (options.runner.lines.is_none() && options.runner.command.is_some())
            .then(|| match &options.projection {
                ProjectionWiring::Account => SshPaths::resolve().ok().map(|p| p.user_dir),
                ProjectionWiring::Config(c) => Some(c.paths.user_dir.clone()),
                ProjectionWiring::Disabled => None,
            })
            .flatten();
        // ⟨M06-W2-R02⟩ The effective sshd policy check behind that writer's files and the
        // management policy: the options' own, else the account's against the system sshd
        // (never under a test configuration's scratch home).
        let runner_sshd = options.runner.sshd.clone().or_else(|| {
            matches!(options.projection, ProjectionWiring::Account)
                .then(|| crate::paired::RunnerSshd::account(&paths.state_dir))
                .flatten()
        });
        let wired = match options.projection {
            ProjectionWiring::Disabled => None,
            ProjectionWiring::Account => account_projection(&paths).and_then(wire),
            ProjectionWiring::Config(c) => wire(*c),
        };
        let phases = phases.mark("projection_ms");
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
        // ⟨M06 W3 grant-path; ADR-0012 §4 item 2⟩ A remote runner never issues locally: its
        // `managed_certificate` adapter is the runner's (`crate::runner::adapter`), which
        // realizes a grant only from certificates the controller's issuer installed. The
        // local managed adapter (key, reserve, sign with an issuer here) is not configured
        // on a runner at all.
        let is_runner_installation = {
            let s = store.clone();
            blocking(move || s.transaction(crate::paired::is_runner)).await??
        };
        let runner_adapter = (is_runner_installation && managed_adapter.is_some()).then(|| {
            Arc::new(crate::runner::adapter::RunnerManagedAdapter::new(
                store.clone(),
            ))
        });
        match (&runner_adapter, &managed_adapter) {
            (Some(a), _) => adapters.push(Arc::clone(a) as Arc<dyn CredentialAdapter>),
            (None, Some(a)) => adapters.push(Arc::clone(a) as Arc<dyn CredentialAdapter>),
            (None, None) => {}
        }
        if let Some(parts) = managed_parts.as_mut() {
            parts.runner_adapter.clone_from(&runner_adapter);
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
        let phases = phases.mark("recovery_ms");
        // ⟨M03⟩ U9 (R3): the `[session] lock_behavior` floor, in every runtime.
        let floor = crate::session_lock::lock_floor(&config.session);
        operations.set_session_lock_floor(floor);
        // ⟨M04⟩ U1: the login entry's port (setup item, `inspect capabilities`).
        if let Some(port) = options.login_entry {
            operations.set_login_entry(port);
        }
        // ⟨M04 U3b⟩ The WSL host: the platform's own unless a test injects one. Off Windows
        // the platform's has no WSL, so it is not wired and WSL requests answer
        // `wsl_unavailable`.
        let platform_host = (options.wsl_host.is_none() && cfg!(windows))
            .then(|| heimdall_wsl::WslHost::platform(options.wsl_helper.clone()));
        // ⟨M04 U4b⟩ The Mode B helper sessions start through the same launcher.
        let wsl_bridge: Option<Arc<dyn crate::wsl_bridge::BridgeFactory>> =
            options.wsl_bridge.clone().or_else(|| {
                platform_host.as_ref().map(|h| {
                    let f: Arc<dyn crate::wsl_bridge::BridgeFactory> =
                        Arc::new(crate::wsl_bridge::LauncherBridgeFactory::new(h.launcher()));
                    f
                })
            });
        let wsl_host: Option<Arc<dyn heimdall_app::ports::DistributionHost>> =
            options.wsl_host.clone().or_else(|| {
                platform_host.map(|h| {
                    let h: Arc<dyn heimdall_app::ports::DistributionHost> = Arc::new(h);
                    h
                })
            });
        if let Some(h) = &wsl_host {
            operations.set_distribution_host(Arc::clone(h));
            // Restart recovery ran before the host was wired: a setup operation of a
            // distribution's items it left unresolved is driven again now, in the
            // background, never starting a distribution (ADR-0010 §9 item 2).
            // ⟨M04 Windows fix round⟩ Read inline; a driver task only when there is work, so a
            // runtime with nothing to drive keeps no task holding the store past its drop.
            let pending = operations.pending_distribution_setups(None).await;
            if !pending.is_empty() {
                let ops = operations.clone();
                tokio::spawn(async move { ops.drive_distribution_setups(&pending, false).await });
            }
        }
        // ⟨M05⟩ U4 (ADR-0011 §2.2–§2.3): the workspace observer behind `ensure` with
        // `context`, `inspect workspace` and the workspace decisions.
        operations.set_workspace_probe(Arc::new(crate::workspace_observe::RealWorkspaceProbe));
        // ⟨M03; ADR-0008 §17.25 item 19⟩ `inspect destinations`' D8 wording: the managed
        // adapter's own (`connection_policy_report`), so the destination view and the
        // ensure result say the same sentence. Without the managed wiring, none.
        if let Some(a) = managed_adapter {
            operations.set_connection_wording(Arc::new(AdapterWording(a)));
        }
        let background = StopOnDrop(shutdown.child_token());
        let relay = EventRelay::spawn(&operations, background.0.clone());
        // ⟨M06 W2⟩ A remote runner (its own environment record says so, the runner-init
        // marker) serves paired sessions; any other runtime refuses them.
        // ⟨M06 W3⟩ The serve child's supervisor and K_iroh custody (task 2): a runner's
        // revocations apply their narrowing there, and its approved transport records run
        // over them, unless the options name their own.
        let transport = options
            .transport
            .as_ref()
            .map(|w| w.build(&store, operations.environment()));
        let transport_announcer = options.transport.as_ref().and_then(|w| w.announcer.clone());
        let runner = {
            let s = store.clone();
            let is_runner = blocking(move || s.transaction(crate::paired::is_runner)).await??;
            let mut runner_options = options.runner.clone();
            if let Some((supervisor, keys)) = &transport {
                if runner_options.admission.is_none() {
                    runner_options.admission = Some(supervisor.clone());
                }
                if runner_options.transport.is_none() {
                    runner_options.transport = Some(crate::paired::RunnerTransport {
                        keys: keys.clone(),
                        serve: supervisor.clone(),
                        peers: Arc::new(heimdall_app::transport::StorePeerEnrollments),
                    });
                }
            }
            if let Some(dir) = &runner_user_dir {
                // ⟨M06-W2-R02⟩ A runner's files and management policy come from its
                // effective sshd policy (`paired::runner_lines`: verified, its own list and
                // `verified`; anything else, sshd's default pair and `owner_only`). Another
                // runtime runs no check.
                let sshd = runner_sshd.as_ref().filter(|_| is_runner);
                let (files, policy) = crate::paired::runner_lines(sshd, dir).await;
                let files: Arc<dyn heimdall_remote::line::ManagementLines> = Arc::new(files);
                runner_options.lines = Some(files);
                if sshd.is_some() {
                    runner_options.management_policy = policy;
                }
            }
            // ⟨M06 W3⟩ The runner runtime serves paired controllers' `runner/1` forms: K_env
            // in its own vault (memory only, zeroized with it), the default time policy, and
            // the lifetime detected read-only (`runner::lifetime::detect`).
            let runtime = if is_runner {
                let lifetime = blocking(runner_lifetime).await??;
                Some(Arc::new(crate::runner::RunnerRuntime::new(
                    store.clone(),
                    options.clock.clone(),
                    Arc::new(KeyVault::new()),
                    crate::runner::time::RunnerTimePolicy::default(),
                    lifetime,
                )))
            } else {
                None
            };
            // ⟨M06 W3 grant-path⟩ The `ensure` pipeline reads the runner's signer (a managed
            // grant waits for its issuer), and a completed install drives the waiting
            // operations on.
            if let Some(rt) = &runtime {
                let grants: Arc<dyn heimdall_app::operations::RunnerGrants> = rt.clone();
                operations.set_runner_grants(grants);
                let (ops, handle) = (operations.clone(), tokio::runtime::Handle::current());
                rt.on_issued(Arc::new(move |grant| {
                    let (ops, grant) = (ops.clone(), grant.clone());
                    handle.spawn(async move {
                        if let Err(e) = ops.runner_grant_issued(&grant).await {
                            tracing::warn!(code = %e.code, "an issued grant's waiting operations were not resumed");
                        }
                    });
                }));
            }
            runtime.map(|rt| {
                Arc::new(
                    crate::paired::PairedRunner::new(
                        store.clone(),
                        operations.clone(),
                        options.clock.clone(),
                        runner_options,
                    )
                    .with_runtime(rt),
                )
            })
        };
        // ⟨M06 W2⟩ The management lines follow the role table (persist-then-rewrite's
        // reconciler, ADR-0012 §3.9 item 6): a bootstrap owner enrolled while no runtime ran,
        // or a rewrite a crash interrupted, is written now.
        if let Some(r) = &runner {
            r.reconcile_lines().await;
        }

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
                        wsl_host.clone().zip(wsl_bridge),
                        runner.as_ref().and_then(|r| r.runtime().cloned()),
                    )
                    .await?,
            ),
            _ => None,
        };
        let phases = phases.mark("managed_ms");
        // ⟨M04 U3b⟩ A WSL distribution namespace's projection resources go to its helper
        // (never starting it); the runtime's own go to the native cleaner, as before.
        let cleaner: Option<Arc<dyn ResourceCleaner>> = wired.map(|w| {
            let native: Arc<dyn ResourceCleaner> = w.cleaner;
            let c: Arc<dyn ResourceCleaner> = Arc::new(crate::wsl_wiring::NamespaceCleaner::new(
                native,
                environment.clone(),
                store.clone(),
                wsl_host.clone(),
            ));
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
        phases.mark("advertise_ms").log();
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
            runner,
            transport,
            transport_announcer,
            controller: options.controller,
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
            runner,
            transport,
            transport_announcer,
            controller,
            shutdown,
            _background,
            _lock,
        } = self;

        // Owner `Shutdown` requests cancel the same token a signal does, so both
        // take the graceful drain below (ADR-0006 §13.6 item 8).
        let mut dispatcher = OperationsDispatcher::new(operations.clone(), relay, clock.clone())
            .with_service_control(shutdown.clone())
            // ⟨rev6.3; ADR-0006 §18.7 item 6⟩ The controller's records, written for the CLI.
            .with_controller_records(store.clone());
        // ⟨M06 W3 host⟩ The controller's driver (`crate::controller_host`): reconnect to the
        // recorded runners, drain the outbox, issue for the delivered grants. Never on a
        // runner; issuing through this runtime's issuer child when it has one.
        let host = match (&runner, controller) {
            (None, Some(wiring)) => {
                let issuer = managed
                    .as_ref()
                    .and_then(|m| m.teardown.issuer.clone())
                    .map(|child| {
                        let port: Arc<dyn heimdall_app::ports::IssuerPort> = Arc::new(child);
                        let issuer: Arc<dyn heimdall_app::remote_status_driver::RemoteIssuer> =
                            Arc::new(heimdall_issuer::remote::ChildRemoteIssuer::new(
                                store.clone(),
                                port,
                            ));
                        issuer
                    });
                let instance = heimdall_app::remote_status::instance_identity(
                    advertisement.info.pid,
                    &advertisement.info.started_at,
                );
                Some(crate::controller_host::ControllerHost::new(
                    store.clone(),
                    clock.clone(),
                    wiring,
                    issuer,
                    instance,
                ))
            }
            _ => None,
        };
        if let Some(h) = &host {
            dispatcher = dispatcher
                .with_outbox_delivery(Arc::new(crate::controller_host::HostDelivery(Arc::clone(
                    h,
                ))))
                // ⟨M06 W3 grant-path⟩ An `ensure` naming a recorded runner is forwarded.
                .with_ensure_forwarding(Arc::new(crate::controller_host::HostDelivery(
                    Arc::clone(h),
                )));
        }
        if let Some(r) = runner {
            dispatcher = dispatcher.with_runner(r);
        }
        if let Some(m) = &managed {
            let endpoints: Arc<dyn crate::connections::BindingEndpoints> = m.teardown.late.clone();
            dispatcher = dispatcher
                .with_connections(Arc::clone(&m.connections))
                .with_binding_endpoints(endpoints);
        }
        // ⟨M06 W3⟩ The route and transport forms, and the serve child under this runtime
        // (ADR-0012 §2.3 item 5: started from durable state, closure replayed first, when an
        // enabled serve policy exists; a refusal is logged and the watchdog keeps checking).
        if let Some((supervisor, keys)) = transport {
            let mut service = crate::supervise_transport::RouteTransport::new(
                store.clone(),
                supervisor.clone(),
                keys,
                Arc::new(heimdall_app::transport::StorePeerEnrollments),
            );
            // ⟨rev6.3⟩ `transport.rotate` tells the recorded runners through it.
            if let Some(a) = transport_announcer {
                service = service.with_announcer(a);
            }
            if let Some(m) = &managed {
                let endpoints: Arc<dyn crate::connections::BindingEndpoints> =
                    m.teardown.late.clone();
                service = service.with_binding_endpoints(endpoints);
                // ⟨M06 W5 `w5n`⟩ The environment endpoint as P renders it (the route
                // helper's `--endpoint` of a managed alias).
                service = service.with_environment_endpoint(
                    m.teardown.registry.layout().rendered_environment(),
                    operations.environment().clone(),
                );
            }
            dispatcher = dispatcher.with_route_transport(Arc::new(service));
            let serving = crate::supervise_transport::read_authority(
                &store,
                &crate::paired_endpoints::StorePeerEndpoints,
            )
            .map(|a| a.serve.is_some());
            if !matches!(serving, Ok(false))
                && let Err(e) = supervisor.start().await
            {
                tracing::warn!(reason = ?e.reason, "the Iroh serve child was not started");
            }
            let _watch = supervisor.spawn_watch(shutdown.clone());
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
        if let Some(h) = host {
            tasks.spawn(h.run(shutdown.clone()));
        }

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

/// ⟨M06 W3⟩ This runner runtime's lifetime (ADR-0012 §4.3; `runner::lifetime::detect`): read
/// only, bounded, and `unknown` where it cannot be determined (off Linux, or no uid).
fn runner_lifetime() -> Result<heimdall_contract::remote::RunnerLifetime, ServiceError> {
    #[cfg(target_os = "linux")]
    let uid = {
        use std::os::unix::fs::MetadataExt as _;
        // `/proc/self` belongs to this process's effective user: no unsafe call needed.
        std::fs::metadata("/proc/self").ok().map(|m| m.uid())
    };
    #[cfg(not(target_os = "linux"))]
    let uid: Option<u32> = None;
    let exe = std::env::current_exe().ok();
    Ok(match (uid, exe) {
        (Some(uid), Some(exe)) => crate::runner::lifetime::detect(uid, &exe).lifetime,
        _ => heimdall_contract::remote::RunnerLifetime::Unknown,
    })
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
///
/// ⟨M06 W3; runner Q7⟩ On a runner it also holds the runner's own binding endpoints
/// ([`RunnerBindingEndpoints`]): a binding of a grant whose K_env the runner signer holds is
/// created, found and removed there, never in the registry above (ADR-0012 §4.1, §4.6).
#[derive(Default)]
struct LateRegistry(
    std::sync::RwLock<Option<EndpointRegistry>>,
    std::sync::RwLock<Option<RunnerBindingEndpoints>>,
);

impl LateRegistry {
    fn set(&self, registry: EndpointRegistry) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(registry);
    }

    /// ⟨M06 W3⟩ The runner's binding endpoints (a runner runtime only).
    fn set_runner(&self, runner: RunnerBindingEndpoints) {
        *self
            .1
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(runner);
    }

    fn clear(&self) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let runner = self
            .1
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(r) = runner {
            r.stop_all();
        }
    }

    fn get(&self) -> Option<EndpointRegistry> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn runner(&self) -> Option<RunnerBindingEndpoints> {
        self.1
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The newest endpoint of `binding`: the runner's own for a runner grant's binding.
    fn endpoint_of(&self, binding: &heimdall_contract::ids::BindingId) -> Option<EndpointRef> {
        self.runner().and_then(|r| r.endpoint(binding)).or_else(|| {
            self.get()
                .and_then(|r| r.binding_endpoint(binding))
                .map(|(e, _)| e)
        })
    }
}

/// ⟨M06 W3; runner Q7; ADR-0012 §4.1, §4.6⟩ **A runner grant's binding endpoints.** A
/// second [`EndpointRegistry`], built here over the runner signer's own table
/// (`RunnerKeys::table`) and nothing else, so an endpoint it creates lists and signs for the
/// runner's K_env certificates of the binding's grant only: never the plain K_env, never
/// another grant's key, never a key of the runtime's local managed table, never a
/// controller's socket (nothing here opens or relays one).
///
/// **Routing is by grant.** A binding is the runner's when `grant_of` names its grant and
/// the runner signer holds a K_env for that grant now. Anything else (an unknown binding, a
/// store failure in `grant_of`, a grant the runner generated no key for) is not routed here:
/// the caller falls back to the local registry, whose table holds no key of a runner grant,
/// so such an endpoint lists nothing (fail closed). After the grant ends
/// (`RunnerKeys::destroy`) its endpoint lists nothing.
#[derive(Clone)]
pub struct RunnerBindingEndpoints {
    runtime: Arc<crate::runner::RunnerRuntime>,
    registry: EndpointRegistry,
    grant_of: Arc<GrantOfBinding>,
    /// ⟨M06 W4; ADR-0012 §4 item 2 "Attach"⟩ The binding's own pairs, when known: its
    /// endpoint and files hold the grant's certificates for those pairs only.
    pairs_of: Arc<PairsOfBinding>,
}

/// The pairs a binding holds (its own scope), read from the runner's store or, during its
/// activation, from what the attach named. `None`: not limited (the grant's own binding
/// before its row exists).
type PairsOfBinding = dyn Fn(
        &heimdall_contract::ids::BindingId,
    ) -> Option<std::collections::BTreeSet<heimdall_contract::request::AccessPairRef>>
    + Send
    + Sync;

/// The grant a binding realizes, read from the runner's store.
type GrantOfBinding = dyn Fn(&heimdall_contract::ids::BindingId) -> Option<heimdall_contract::ids::GrantId>
    + Send
    + Sync;

impl std::fmt::Debug for RunnerBindingEndpoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerBindingEndpoints")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl RunnerBindingEndpoints {
    /// The runner's binding endpoints at `layout`, accepting only `owner`, signing from
    /// `runtime`'s own signer table under `authority`; `grant_of` reads a binding's grant.
    /// Every endpoint stops when `shutdown` is cancelled.
    #[must_use]
    pub fn new(
        runtime: Arc<crate::runner::RunnerRuntime>,
        layout: EndpointLayout,
        owner: ExpectedOwner,
        authority: Arc<dyn heimdall_app::ports::SignatureAuthority>,
        limits: SignerLimits,
        shutdown: CancellationToken,
        grant_of: Arc<GrantOfBinding>,
    ) -> Self {
        let registry = EndpointRegistry::new(
            layout,
            owner,
            runtime.issuance().keys().table().clone(),
            authority,
            limits,
            shutdown,
        );
        Self {
            runtime,
            registry,
            grant_of,
            pairs_of: Arc::new(|_| None),
        }
    }

    /// [`Self::new`] reading a binding's grant from `store`.
    #[must_use]
    pub fn over_store(
        store: Arc<Store>,
        runtime: Arc<crate::runner::RunnerRuntime>,
        layout: EndpointLayout,
        owner: ExpectedOwner,
        authority: Arc<dyn heimdall_app::ports::SignatureAuthority>,
        limits: SignerLimits,
        shutdown: CancellationToken,
    ) -> Self {
        let rows = Arc::clone(&store);
        let grant_of: Arc<GrantOfBinding> = Arc::new(move |binding| {
            store
                .transaction(|tx| Ok(tx.binding(binding)?.map(|b| b.grant)))
                .ok()
                .flatten()
        });
        let mut endpoints = Self::new(
            runtime, layout, owner, authority, limits, shutdown, grant_of,
        );
        // ⟨M06 W4⟩ A binding's own scope, once its row exists.
        endpoints.pairs_of = Arc::new(move |binding| {
            rows.transaction(|tx| Ok(tx.binding(binding)?.map(|b| b.scope.pairs)))
                .ok()
                .flatten()
        });
        endpoints
    }

    /// ⟨M06 W3 grant-path⟩ Also know a binding by the grant it is being materialized for
    /// during its own activation (`crate::runner::adapter::PendingBindings`), before its row
    /// is committed. The store's row, once it exists, is asked first.
    #[must_use]
    pub fn with_pending(mut self, pending: crate::runner::adapter::PendingBindings) -> Self {
        let stored = Arc::clone(&self.grant_of);
        let pending_grants = pending.clone();
        self.grant_of =
            Arc::new(move |binding| stored(binding).or_else(|| pending_grants.grant_of(binding)));
        let stored_pairs = Arc::clone(&self.pairs_of);
        self.pairs_of =
            Arc::new(move |binding| stored_pairs(binding).or_else(|| pending.pairs_of(binding)));
        self
    }

    /// The runner grant `binding` realizes: its grant, while the runner signer holds that
    /// grant's K_env. `None` for every other binding.
    #[must_use]
    pub fn runner_grant(
        &self,
        binding: &heimdall_contract::ids::BindingId,
    ) -> Option<heimdall_contract::ids::GrantId> {
        let grant = (self.grant_of)(binding)?;
        self.runtime.issuance().keys().slot(&grant)?;
        Some(grant)
    }

    /// ⟨M06 W3 `driver`⟩ K_env.pub and the installed certificates of the runner grant
    /// `grant`, for materializing `binding` (`ManagedEffectsImpl::materialize`): only when
    /// `binding` is that grant's binding in the runner's store and the runner signer holds
    /// the grant's K_env. Public text only.
    #[must_use]
    pub fn installed(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        grant: &heimdall_contract::ids::GrantId,
    ) -> Option<(String, Vec<heimdall_app::ports::MaterializedCertificate>)> {
        if self.runner_grant(binding).as_ref() != Some(grant) {
            return None;
        }
        let keys = self.runtime.issuance().keys();
        let (_, public) = keys.public_key(grant)?;
        // ⟨M06 W4⟩ Only the binding's own pairs, when it holds a subset of the grant's.
        let own = (self.pairs_of)(binding);
        let certificates = keys
            .certificates(grant)
            .into_iter()
            .filter(|(pair, _)| own.as_ref().is_none_or(|pairs| pairs.contains(pair)))
            .map(|(pair, c)| heimdall_app::ports::MaterializedCertificate {
                pair,
                certificate: c.certificate,
            })
            .collect();
        Some((public.openssh_line, certificates))
    }

    /// Create `binding`'s endpoint at `generation` when it is a runner grant's (attached to
    /// that grant in the runner's table, so it lists that grant's certificates only, and
    /// ⟨M06 W4⟩ of those only the ones for the binding's own pairs), or
    /// return the one already running at that generation. `None` when the binding is not a
    /// runner grant's: nothing was created here.
    pub fn create(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
        placement: &heimdall_credential::endpoints::EndpointPlacement,
    ) -> Option<Result<EndpointRef, heimdall_app::ports::AdapterError>> {
        use heimdall_adapters::managed::effects::BindingEndpoints as _;
        let grant = self.runner_grant(binding)?;
        let keys = self.runtime.issuance().keys();
        // ⟨M06 W4⟩ Limited to the binding's own pairs when it holds a subset.
        let attached = match (self.pairs_of)(binding) {
            Some(pairs) => keys.attach_binding_pairs(binding, &grant, &pairs),
            None => keys.attach_binding(binding, &grant),
        };
        if !attached {
            // The grant ended in between: nothing is created, here or elsewhere.
            return Some(Err(heimdall_app::ports::AdapterError::Unavailable(
                heimdall_adapters::managed::effects::BINDING_ENDPOINT_UNAVAILABLE.to_owned(),
            )));
        }
        Some(
            self.registry
                .create_binding_endpoint_at(binding, generation, placement),
        )
    }

    /// The newest endpoint this registry runs for `binding`.
    #[must_use]
    pub fn endpoint(&self, binding: &heimdall_contract::ids::BindingId) -> Option<EndpointRef> {
        self.registry.binding_endpoint(binding).map(|(e, _)| e)
    }

    /// Remove `binding`'s endpoint of exactly `generation`; `false` when none runs here.
    ///
    /// # Errors
    /// As `EndpointRegistry::remove`.
    pub fn remove(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
    ) -> Result<bool, heimdall_app::ports::AdapterError> {
        use heimdall_adapters::managed::effects::BindingEndpoints as _;
        self.registry.remove_binding_endpoint(binding, generation)
    }

    /// Stop every endpoint (runtime stop).
    pub fn stop_all(&self) {
        self.registry.stop_all();
    }
}

impl heimdall_adapters::managed::effects::BindingEndpoints for LateRegistry {
    fn binding_endpoint(&self, binding: &heimdall_contract::ids::BindingId) -> Option<EndpointRef> {
        self.endpoint_of(binding)
    }

    /// ⟨§17.21 item 1⟩ Step 6's endpoint creation, through the live registry; before it
    /// is set (or after stop) the creation refuses, so the materialization fails closed.
    fn create_binding_endpoint(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
    ) -> Result<EndpointRef, heimdall_app::ports::AdapterError> {
        self.create_binding_endpoint_at(
            binding,
            generation,
            &heimdall_credential::endpoints::EndpointPlacement::Native,
        )
    }

    /// ⟨M06 W3 `driver`⟩ A runner grant's key and installed certificates, from the runner's
    /// own signer (`RunnerBindingEndpoints::installed`); `None` on every other runtime.
    fn runner_grant_content(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        grant: &heimdall_contract::ids::GrantId,
    ) -> Option<(String, Vec<heimdall_app::ports::MaterializedCertificate>)> {
        self.runner()?.installed(binding, grant)
    }

    /// ⟨M04⟩ U5: the same creation at a placement (a container's stable directory).
    fn create_binding_endpoint_at(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
        placement: &heimdall_credential::endpoints::EndpointPlacement,
    ) -> Result<EndpointRef, heimdall_app::ports::AdapterError> {
        // ⟨M06 W3; runner Q7⟩ A runner grant's binding is served by the runner signer only.
        if let Some(created) = self
            .runner()
            .and_then(|r| r.create(binding, generation, placement))
        {
            return created;
        }
        self.get()
            .ok_or_else(|| {
                heimdall_app::ports::AdapterError::Unavailable(
                    heimdall_adapters::managed::effects::BINDING_ENDPOINT_UNAVAILABLE.to_owned(),
                )
            })?
            .create_binding_endpoint_at(binding, generation, placement)
    }

    fn remove_container_endpoints(&self, dir_tag: &str) -> usize {
        self.get().map_or(0, |r| r.remove_container(dir_tag))
            + self
                .runner()
                .map_or(0, |r| r.registry.remove_container(dir_tag))
    }

    fn start_environment(
        &self,
        environment: &heimdall_contract::ids::EnvironmentId,
    ) -> Result<(), heimdall_app::ports::AdapterError> {
        self.get()
            .ok_or_else(|| {
                heimdall_app::ports::AdapterError::Unavailable("wsl_unavailable".to_owned())
            })?
            .start_wsl_environment(environment)
    }

    fn wsl_supported(&self) -> bool {
        self.get().is_some_and(|r| r.has_wsl_realizer())
    }

    fn stop_environment(
        &self,
        environment: &heimdall_contract::ids::EnvironmentId,
        start: bool,
    ) -> Result<bool, heimdall_app::ports::AdapterError> {
        match self.get() {
            Some(r) if r.has_wsl_realizer() => r.stop_wsl_environment(environment, start),
            _ => Ok(false),
        }
    }

    fn helper_state(
        &self,
        environment: &heimdall_contract::ids::EnvironmentId,
    ) -> Option<heimdall_contract::environment::HelperState> {
        self.get()?.wsl_helper_state(environment)
    }

    fn realize_wsl_binding(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
        public: &heimdall_credential::endpoints::wsl::WslPublic,
        start: heimdall_app::ports::DistributionStart,
    ) -> Result<(), heimdall_app::ports::AdapterError> {
        self.get()
            .ok_or_else(|| {
                heimdall_app::ports::AdapterError::Unavailable(
                    heimdall_adapters::managed::effects::BINDING_ENDPOINT_UNAVAILABLE.to_owned(),
                )
            })?
            .realize_wsl(
                binding,
                heimdall_domain::resource::ResourceGeneration(generation),
                public,
                start,
            )
    }

    fn remove_binding_endpoint(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
    ) -> Result<bool, heimdall_app::ports::AdapterError> {
        // ⟨M06 W3⟩ Whichever registry runs it (a runner grant's is the runner's).
        let runner = match self.runner() {
            Some(r) => r.remove(binding, generation)?,
            None => false,
        };
        let local = match self.get() {
            Some(r) => r.remove_binding_endpoint(binding, generation)?,
            None => false,
        };
        Ok(runner || local)
    }
}

impl crate::connections::BindingEndpoints for LateRegistry {
    fn endpoint(&self, binding: &heimdall_contract::ids::BindingId) -> Option<EndpointRef> {
        self.endpoint_of(binding)
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
        // ⟨M05⟩ P's ordinary aliases are environment-level: personal policies only
        // (ADR-0011 §5.2, §10 item 1).
        for p in
            heimdall_app::policy_context::environment_level_policies(tx, &profile.id, environment)?
        {
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

    /// ⟨M06 W5 `w5n`; ADR-0012 §5.3⟩ The route helper of a managed-certificate alias whose
    /// destination has more than one approved route, or any Iroh route: this runtime's own
    /// executable and the catalog pins (`heimdall_app::routes::helper_pins`). Without a
    /// resolvable executable path the preview is refused, never rendered without the pin.
    fn helper_route(
        &self,
        alias: &heimdall_domain::projection::ManagedAliasSpec,
    ) -> Result<Option<heimdall_localenv::projection::HelperRouteSpec>, String> {
        let pins = self
            .store
            .transaction(|tx| heimdall_app::routes::helper_pins(tx, &alias.destination))
            .map_err(|_| "the destination's routes could not be read".to_owned())?;
        let Some(pins) = pins else {
            return Ok(None);
        };
        let program = std::env::current_exe()
            .ok()
            .filter(|p| p.is_absolute())
            .ok_or_else(|| "this executable's path could not be resolved".to_owned())?;
        Ok(Some(heimdall_localenv::projection::HelperRouteSpec {
            program,
            pins,
        }))
    }

    /// ⟨M06 W5 `w5o`; ADR-0012 §5 ⟨2026-11-22⟩⟩ Whether the destination's approved routes
    /// need the route helper (`heimdall_app::routes::helper_pins` is `Some`), whatever
    /// the pair prefers.
    fn routes_need_helper(
        &self,
        alias: &heimdall_domain::projection::ManagedAliasSpec,
    ) -> Result<bool, String> {
        self.store
            .transaction(|tx| heimdall_app::routes::helper_pins(tx, &alias.destination))
            .map(|pins| pins.is_some())
            .map_err(|_| "the destination's routes could not be read".to_owned())
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

/// ⟨M04, the Windows readiness failures⟩ The start's phases, timed: each mark is the time
/// since the previous one, and the log line (once the advertisement is written) has every
/// phase and the total, in milliseconds. Facts only (no path, no identity).
struct StartPhases {
    begun: std::time::Instant,
    last: std::time::Instant,
    marks: Vec<(&'static str, u64)>,
}

impl StartPhases {
    fn begin() -> Self {
        let now = std::time::Instant::now();
        Self {
            begun: now,
            last: now,
            marks: Vec::new(),
        }
    }

    fn mark(mut self, phase: &'static str) -> Self {
        let now = std::time::Instant::now();
        let ms = u64::try_from(now.duration_since(self.last).as_millis()).unwrap_or(u64::MAX);
        self.marks.push((phase, ms));
        self.last = now;
        self
    }

    fn log(self) {
        let total = u64::try_from(self.begun.elapsed().as_millis()).unwrap_or(u64::MAX);
        let ms = |name: &str| {
            self.marks
                .iter()
                .find(|(n, _)| *n == name)
                .map_or(0, |(_, v)| *v)
        };
        tracing::info!(
            store_ms = ms("store_ms"),
            projection_ms = ms("projection_ms"),
            recovery_ms = ms("recovery_ms"),
            managed_ms = ms("managed_ms"),
            advertise_ms = ms("advertise_ms"),
            total_ms = total,
            "the runtime advertised its endpoints"
        );
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
    /// ⟨M06 W3 grant-path⟩ On a remote runner: its adapter for `managed_certificate`,
    /// bound to the runner runtime and these effects in `start`.
    runner_adapter: Option<Arc<crate::runner::adapter::RunnerManagedAdapter>>,
}

/// ⟨M06 W3 grant-path⟩ A runner grant's binding, realized through the managed effects'
/// materialize site: its endpoint is the runner's own (`RunnerBindingEndpoints`), its files
/// carry K_env.pub and the certificates the controller installed.
struct EffectsMaterializer {
    effects: ManagedEffectsImpl,
    late: Arc<LateRegistry>,
}

impl crate::runner::adapter::RunnerMaterializer for EffectsMaterializer {
    fn materialize(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        grant: &heimdall_contract::ids::GrantId,
    ) -> Result<EndpointRef, heimdall_app::ports::AdapterError> {
        use heimdall_app::ports::ManagedEffects as _;
        let spec = heimdall_app::ports::MaterializeSpec {
            generation: crate::runner::adapter::BINDING_GENERATION,
            source: heimdall_app::ports::MaterializeSource::InstalledKeyOf {
                grant: grant.clone(),
            },
            environment_slots: false,
            start: heimdall_app::ports::DistributionStart::Forbidden,
        };
        let files = self.effects.materialize(binding, &spec)?;
        files
            .endpoint
            .or_else(|| self.late.endpoint_of(binding))
            .ok_or_else(|| {
                heimdall_app::ports::AdapterError::Unavailable(
                    heimdall_adapters::managed::effects::BINDING_ENDPOINT_UNAVAILABLE.to_owned(),
                )
            })
    }

    fn clear(
        &self,
        grant: &heimdall_contract::ids::GrantId,
    ) -> Result<(), heimdall_app::ports::AdapterError> {
        self.effects.clear_bindings_of(std::slice::from_ref(grant))
    }
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

        fn host(&self) -> heimdall_domain::claims::HostFacts {
            self.inner.host()
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
            runner_adapter: None,
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
        wsl: Option<(
            Arc<dyn heimdall_app::ports::DistributionHost>,
            Arc<dyn crate::wsl_bridge::BridgeFactory>,
        )>,
        runner: Option<Arc<crate::runner::RunnerRuntime>>,
    ) -> Result<ManagedRuntime, ServiceError> {
        let mut steps = Vec::new();
        // ⟨M03-F1⟩ The verified ssh client: the claim table's client ranges are judged
        // against its version, bound to its executable's identity (ADR-0008 D12 item 2,
        // R03; no client, no claim).
        self.sources.set_verified_client(
            wired.and_then(|w| crate::managed_store::VerifiedClient::selected(&w.config.clients)),
        );
        let authority: Arc<dyn heimdall_app::ports::SignatureAuthority> = Arc::new(ops.clone());
        let supervisor_stop = stop.clone();
        // ⟨M05⟩ U5 (ADR-0011 §3.2 (a)): the environment endpoint's identities path activates
        // the personal default (covered only, single-flight, bounded wait).
        let activation = crate::default_activation::DefaultActivator::new(
            ops.clone(),
            ops.environment().clone(),
            crate::default_activation::owner_context(&owner),
            crate::default_activation::launch_executable(
                wired
                    .and_then(|w| w.config.clients.selected(ClientKind::Ssh))
                    .map(|c| c.path.as_path()),
                crate::default_activation::FALLBACK_EXECUTABLE,
            ),
            stop.clone(),
        );
        let authority: Arc<dyn heimdall_app::ports::SignatureAuthority> = Arc::new(
            crate::default_activation::ActivatingAuthority::new(authority, Arc::new(activation)),
        );
        // ⟨M06 W3; runner Q7⟩ On a runner, a runner grant's binding endpoints: the same
        // layout, owner and signature authority, over the runner signer's own table only.
        let runner_endpoints = runner.map(|rt| {
            // ⟨M06 W3 grant-path⟩ The runner's adapter realizes a grant's binding through
            // these effects; a binding in activation is known by its grant before its row
            // is committed.
            if let Some(adapter) = &self.runner_adapter {
                adapter.bind(
                    Arc::clone(&rt),
                    Arc::new(EffectsMaterializer {
                        effects: self.effects.clone(),
                        late: Arc::clone(&self.late),
                    }),
                );
            }
            let endpoints = RunnerBindingEndpoints::over_store(
                Arc::clone(store),
                rt,
                self.layout.clone(),
                owner.clone(),
                Arc::clone(&authority),
                SignerLimits::default(),
                stop.clone(),
            );
            match &self.runner_adapter {
                Some(adapter) => endpoints.with_pending(adapter.pending()),
                None => endpoints,
            }
        });
        let registry = EndpointRegistry::new(
            self.layout.clone(),
            owner,
            self.table.clone(),
            authority,
            SignerLimits::default(),
            stop,
        )
        .with_verification_gates(ops.signing_gates().clone());
        // ⟨M04 U4b⟩ WSL Mode B: the bridge supervisor is the endpoint registry's realizer
        // (it serves the streams it relays with the registry's signers). It is installed
        // before anything can materialize a Mode B binding (the re-issue pass below), and
        // re-checks every 10 s until the runtime stops (ADR-0010 §3 items 9–10, 13).
        if let Some((host, factory)) = wsl {
            let bridge = crate::wsl_bridge::BridgeRegistry::new(
                Arc::clone(store),
                ops.environment().clone(),
                host,
                factory,
                tokio::runtime::Handle::current(),
            );
            bridge.attach(registry.downgrade());
            registry.set_wsl_realizer(Arc::new(bridge.clone()));
            tokio::spawn(bridge.supervise(ops.clone(), supervisor_stop));
        }
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
        if let Some(r) = runner_endpoints {
            self.late.set_runner(r);
        }
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
        // ⟨ADR-0008 §17.28 item 1, §17.32, §17.33 item 2⟩ The fence's load gate, the
        // request hold and the exact-child check ([`issuer_client_config`]).
        #[cfg(debug_assertions)]
        let diagnostics = m.issuer_start_diagnostics;
        #[cfg(not(debug_assertions))]
        let diagnostics = false;
        let issuer = command.map(|c| {
            let mut config = issuer_client_config(c, start_token, ops);
            config.start_diagnostics = diagnostics;
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
        // ⟨M04 U2; ADR-0010 §1 item 6⟩ Started with an explicit inherited-handle list: only
        // its three standard streams (stdin and stderr null, stdout a pipe) reach the client.
        let mut cmd = std::process::Command::new(client);
        cmd.args(heimdall_app::enrollment::effective_config_args(step));
        // ⟨M04 U2⟩ What OpenSSH for Windows needs to start, from the OS, when missing.
        heimdall_localenv::sys::openssh_env::fill_openssh_environment(&mut cmd, true);
        let options = heimdall_localenv::sys::spawn::ListedSpawn {
            stdin: heimdall_localenv::sys::spawn::ListedStdio::Null,
            stderr: heimdall_localenv::sys::spawn::ListedStdio::Null,
            // ⟨M03 E9; ADR-0008 §17.43⟩ No console window (the listed spawn's own flag).
            creation_flags: heimdall_localenv::sys::spawn::CREATE_NO_WINDOW,
            ..heimdall_localenv::sys::spawn::ListedSpawn::piped()
        };
        let mut child = heimdall_localenv::sys::spawn::spawn_listed(&cmd, &options)
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
        if status != 0 {
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
        // ⟨M03 wave 6, U13⟩ The line the enrollment step actually produces is accepted
        // (a trailing terminator made every real enrollment step `driver_unavailable`).
        let target = heimdall_contract::enrollment::ApprovedTarget {
            hostname: "127.0.0.1".into(),
            port: 2222,
            user: heimdall_contract::ids::AccountName::parse("deploy").unwrap(),
            proxy: heimdall_contract::enrollment::NoProxy::None,
            host_key: heimdall_contract::enrollment::ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "DDDD".into(),
                fingerprint: "SHA256:x".into(),
            },
        };
        h.write_files(
            tag,
            &heimdall_app::enrollment::known_hosts_line(tag, &target),
            None,
        )
        .expect("the step's own known-hosts line is one line");
        assert_eq!(
            std::fs::read_to_string(dir.join("known_hosts")).unwrap(),
            "hm-target-0123456789abcdef ssh-ed25519 DDDD\n"
        );
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
            jump_alias: None,
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
                            default: false,
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
