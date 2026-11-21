//! M06 command surface (ADR-0012 §2–§5, §9 item 6; ADR-0006 §18; m06-plan U0, U2; the
//! orchestrator's naming ruling for the G08 freeze).
//!
//! * **`environment`** (op `remote_environment`; no `env` alias): `add`, `invite`, `join`,
//!   `revoke-client`, `remove`, `update`, `status`, answered by the controller operations
//!   (`heimdall_app::remote_env`) with this binary's ports: K_mgmt in the platform store
//!   (`heimdall_credential::mgmt`), the catalog's verified access read from the state
//!   database (the M03 enrollment's approved target: the owner-approved host key), the
//!   bootstrap's interactive ssh session, management sessions (the isolated `-F`
//!   configuration from `heimdall_sshconf::mgmt`, the per-session K_mgmt agent, and the IPC
//!   client over `ssh`'s standard streams), and the owner's typed `yes` on this terminal.
//!   **The controller's environment records** (`remote_environment_pins`) have no store API
//!   yet, so every command that reads or writes them answers `CAPABILITY_UNAVAILABLE` /
//!   `driver_unavailable` before anything is created, sent or destroyed (DONE question
//!   U2-Q3); `join --show-key` needs no record and works.
//! * **`device retire`**: the locally attended decision (a terminal and a typed `yes`;
//!   `--non-interactive` or a non-terminal stdin is refused `INTERACTION_REQUIRED` before
//!   anything is read).
//! * **`route add|remove|prefer`** and **`transport enable|disable|adopt-roost`**: registered
//!   (the integrator's U56) and refused "planned for M06" until they land. `roost adopt` is
//!   `transport adopt-roost` (op `transport.adopt_roost`).
//! * **`route connect`**: the `ProxyCommand` helper that rendered SSH configuration names
//!   (`heimdall_sshconf::routes`). **Hidden from help and frozen**: its words and arguments
//!   are a compatibility surface of every rendered alias. Refused "planned for M06" here
//!   until U56 wires its legs.
//!
//! Every refusal is built at run time and answered before the runtime is contacted or the
//! Heimdall home is created, except where a command needs the installation's state (named
//! in its handler).

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use heimdall_app::OpError;
use heimdall_app::remote_env::{
    AccessCatalog, AddInput, Confirmation, ControllerPorts, EnvironmentRegistry, InvitationBundle,
    InviteInput, InviteOutcome, LocalConfirm, ManagementCall, ManagementHop, ManagementRoute,
    ManagementSession, ManagementSessions, MgmtKeyInfo, MgmtKeyPort, MgmtKeyUnavailable,
    RemoteEnvController, RemoteEnvironmentRecord, SessionHello, SessionName, SessionTarget,
    VerifiedAccess, ssh as env_ssh,
};
use heimdall_contract::envelope::{EffectStatus, Envelope, NextAction, reason};
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EnvironmentId, KeyFingerprint, RequestId,
};
use heimdall_contract::remote::Role;
use heimdall_contract::request::InteractionMode;
use heimdall_contract::{Code, ExitCode};
use heimdall_credential::mgmt::{
    self, MgmtKeyStore, MgmtSigner, MgmtStoreAvailability, MgmtStoreError, SessionAgent,
};

use crate::client::{CLIENT_NAME, Ctx, error};
use crate::output;

// --- the command trees -------------------------------------------------------------------

/// `environment` subcommands (ADR-0012 §3; ADR-0006 §18 `remote_environment`).
#[derive(Debug, Subcommand)]
pub enum EnvironmentCommand {
    /// Bootstrap a runner over your existing, host-verified access: one interactive ssh
    /// session in which the runner's `heimdall remote init` enrolls this device's
    /// management key as owner, confirmed at the runner. Also repairs a lost pin or key.
    Add(EnvAddArgs),
    /// Invite another device's management key to a runner. You confirm its fingerprint
    /// here; the runner holds the invitation until it is confirmed there.
    Invite(EnvInviteArgs),
    /// On the invited device: join from the owner's invitation bundle after confirming the
    /// runner's host key and environment ID. `--show-key` prints this device's management
    /// key for the owner first.
    Join(EnvJoinArgs),
    /// Revoke one client on a runner (narrowing; no decision).
    RevokeClient(EnvRevokeArgs),
    /// Revoke this device on a runner, then forget the runner. The management key is kept.
    Remove(EnvTargetArgs),
    /// Ask a runner for its explicit, checksum-verified binary update.
    Update(EnvTargetArgs),
    /// This controller's view of its runners. Opens no connection.
    Status(EnvStatusArgs),
}

/// `environment add` arguments.
#[derive(Debug, Args)]
pub struct EnvAddArgs {
    /// The catalog destination whose verified access reaches the runner account.
    #[arg(long, value_name = "DESTINATION")]
    pub destination: String,
    /// The runner account.
    #[arg(long, value_name = "ACCOUNT")]
    pub account: String,
    /// The runner's Heimdall executable (an absolute path on the runner).
    #[arg(long, value_name = "PATH")]
    pub runner_program: String,
    /// The runner's Heimdall home (an absolute path on the runner; the management line's
    /// forced command names it).
    #[arg(long, value_name = "PATH")]
    pub runner_home: String,
    /// The expected SHA-256 of the runner's Heimdall executable (64 lowercase hex), checked
    /// on the runner before anything is written.
    #[arg(long, value_name = "HEX")]
    pub runner_sha256: Option<String>,
    /// A label for the runner.
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,
}

/// A runner role (ADR-0012 §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    /// Every permission.
    Owner,
    /// View and request.
    Requester,
    /// View only.
    Viewer,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Role {
        match r {
            RoleArg::Owner => Role::Owner,
            RoleArg::Requester => Role::Requester,
            RoleArg::Viewer => Role::Viewer,
        }
    }
}

/// `environment invite` arguments.
#[derive(Debug, Args)]
pub struct EnvInviteArgs {
    /// The runner environment.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: String,
    /// The role to offer.
    #[arg(long, value_enum)]
    pub role: RoleArg,
    /// The invited device's management key (the line its `environment join --show-key`
    /// printed).
    #[arg(long, value_name = "KEY")]
    pub public_key: String,
    /// Reuse the request ID the pending answer named, after confirming at the runner.
    #[arg(long, value_name = "ID")]
    pub request_id: Option<String>,
}

/// `environment join` arguments.
#[derive(Debug, Args)]
pub struct EnvJoinArgs {
    /// The invitation bundle file (`-`: standard input).
    #[arg(
        value_name = "BUNDLE",
        conflicts_with = "show_key",
        required_unless_present = "show_key"
    )]
    pub bundle: Option<PathBuf>,
    /// Print this device's management key and fingerprint (created when absent), for the
    /// owner's `environment invite`.
    #[arg(long)]
    pub show_key: bool,
}

/// `environment revoke-client` arguments.
#[derive(Debug, Args)]
pub struct EnvRevokeArgs {
    /// The runner environment.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: String,
    /// The client to revoke.
    #[arg(value_name = "CLIENT")]
    pub client: String,
}

/// An environment argument.
#[derive(Debug, Args)]
pub struct EnvTargetArgs {
    /// The runner environment.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: String,
}

/// `environment status` arguments.
#[derive(Debug, Args)]
pub struct EnvStatusArgs {
    /// One runner environment; every one when absent.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: Option<String>,
}

/// `device` subcommands (ADR-0012 §3.4).
#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// Retire this controller device: revoke it on every runner, then destroy its
    /// management key. Needs a terminal and a typed `yes`.
    Retire,
}

/// `route` subcommands (ADR-0012 §5). Planned for M06 until U56 lands.
#[derive(Debug, Subcommand)]
pub enum RouteCommand {
    /// Approve a route for a destination.
    Add(crate::cli::PlannedArgs),
    /// Remove an approved route.
    Remove(crate::cli::PlannedArgs),
    /// Prefer one approved route.
    Prefer(crate::cli::PlannedArgs),
    /// The ProxyCommand helper rendered SSH configuration names (frozen; not a user
    /// surface).
    #[command(hide = true)]
    Connect(crate::cli::PlannedArgs),
}

/// `transport` subcommands (ADR-0012 §1, §2, §2.8). Planned for M06 until U56 lands.
#[derive(Debug, Subcommand)]
pub enum TransportCommand {
    /// Enable the Iroh transport.
    Enable(crate::cli::PlannedArgs),
    /// Disable the Iroh transport.
    Disable(crate::cli::PlannedArgs),
    /// Adopt an existing Pigeons roost as a route (a widening, confirmed locally).
    AdoptRoost(crate::cli::PlannedArgs),
}

/// `remote` subcommands: the runner's side (ADR-0012 §3.3, §3.6). Hidden and frozen.
#[derive(Debug, Subcommand)]
pub enum RemoteCommand {
    /// On the runner, in the bootstrap's interactive ssh session: mark this installation a
    /// remote runner and enroll the controller's management key as owner, after the owner
    /// confirms its fingerprint on this terminal.
    Init(RemoteInitArgs),
    /// The forced command of a management line: bridge one paired session to this
    /// installation's runtime. Takes exactly `--client <client> --home <absolute path>`.
    Serve(crate::cli::PlannedArgs),
}

/// `remote init` arguments (the bootstrap's remote command, `heimdall_app::remote_env::ssh::
/// remote_init_command`).
#[derive(Debug, Args)]
pub struct RemoteInitArgs {
    /// The client ID the controller records for itself.
    #[arg(long, value_name = "CLIENT")]
    pub owner_client: String,
    /// The controller's management key (`ssh-ed25519 <base64>`).
    #[arg(long, value_name = "KEY")]
    pub owner_key: String,
    /// The expected SHA-256 of this runner's Heimdall executable (64 lowercase hex): the
    /// bootstrap's checksum step; refused before anything is written when it differs.
    #[arg(long, value_name = "HEX")]
    pub expect_sha256: Option<String>,
}

// --- the planned refusal -----------------------------------------------------------------

/// The message of the refusal, assembled at run time (the M02 and M03 source guards scan
/// for the unassembled text).
pub(crate) fn refusal_message() -> String {
    [
        "this command is not available",
        "in this build (planned for M06)",
    ]
    .join(" ")
}

/// The envelope a planned M06 command answers.
pub(crate) fn refusal_envelope() -> Envelope<serde_json::Value> {
    output::error_value(error(Code::UsageError, &refusal_message()))
}

/// Print [`refusal_envelope`] and return its exit code. Builds no executor, opens no store
/// and never contacts the runtime. A `--json` among the ignored arguments still selects
/// machine output.
pub(crate) fn refuse(ctx: &Ctx, args: &crate::cli::PlannedArgs) -> ExitCode {
    let json = ctx.json
        || args
            .args
            .iter()
            .take_while(|a| *a != "--")
            .any(|a| a == "--json");
    let env = refusal_envelope();
    output::emit(&env, json);
    output::exit_code_for(env.code, false)
}

/// `route …`.
pub(crate) fn route(ctx: &Ctx, command: RouteCommand) -> ExitCode {
    match command {
        RouteCommand::Add(a)
        | RouteCommand::Remove(a)
        | RouteCommand::Prefer(a)
        | RouteCommand::Connect(a) => refuse(ctx, &a),
    }
}

/// `transport …`.
pub(crate) fn transport(ctx: &Ctx, command: TransportCommand) -> ExitCode {
    match command {
        TransportCommand::Enable(a)
        | TransportCommand::Disable(a)
        | TransportCommand::AdoptRoost(a) => refuse(ctx, &a),
    }
}

// --- output ------------------------------------------------------------------------------

fn emit_error(ctx: &Ctx, e: OpError) -> ExitCode {
    let env = output::error_value(e.into_envelope());
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

fn emit_ok(ctx: &Ctx, data: serde_json::Value, human: &str) -> ExitCode {
    let env = Envelope::ok(data);
    if ctx.json {
        output::emit(&env, true);
    } else {
        output::emit_rendered(&env, false, human);
    }
    ExitCode::Success
}

fn usage(message: &str) -> OpError {
    OpError::new(Code::UsageError, message).with_effect(EffectStatus::None)
}

fn parse_environment(text: &str) -> Result<EnvironmentId, OpError> {
    EnvironmentId::parse(text).map_err(|_| usage("the environment ID is malformed"))
}

// --- K_mgmt ------------------------------------------------------------------------------

/// The debug-build test configuration of the K_mgmt store:
/// `HEIMDALL_TEST_MGMT_STORE=fixture-file:<absolute path>` selects the fixture store (test
/// kind, never a product claim), with an explicit `HEIMDALL_HOME` only. A release build
/// never reads the variable.
#[cfg(debug_assertions)]
pub(crate) const TEST_MGMT_STORE_ENV: &str = "HEIMDALL_TEST_MGMT_STORE";

/// The fixture store prefix of [`TEST_MGMT_STORE_ENV`].
#[cfg(debug_assertions)]
const FIXTURE_FILE_PREFIX: &str = "fixture-file:";

/// This installation's K_mgmt store (module docs). `environment` scopes the item.
fn mgmt_store(ctx: &Ctx, environment: &EnvironmentId) -> Result<Box<dyn MgmtKeyStore>, OpError> {
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os(TEST_MGMT_STORE_ENV) {
        let path = value
            .to_str()
            .and_then(|v| v.strip_prefix(FIXTURE_FILE_PREFIX))
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| {
                usage("HEIMDALL_TEST_MGMT_STORE: expected fixture-file:<absolute path>")
            })?;
        if ctx.home.is_none() {
            return Err(usage(
                "HEIMDALL_TEST_MGMT_STORE needs an explicit HEIMDALL_HOME (the test's scratch home)",
            ));
        }
        return Ok(Box::new(mgmt::fixture::FixtureMgmtStore::file(path)));
    }
    let _ = (ctx, environment);
    #[cfg(target_os = "macos")]
    {
        let home = heimdall_localenv::sys::account_home().map_err(|_| {
            OpError::new(
                Code::CapabilityUnavailable,
                "the account's home cannot be read, so its keychain cannot be selected",
            )
            .with_reason(reason::MGMT_KEY_STORE_UNAVAILABLE)
        })?;
        Ok(Box::new(mgmt::macos::MacosLoginKeychainMgmt::login(
            &home,
            environment,
        )))
    }
    #[cfg(windows)]
    {
        let dir = if ctx.home.is_some() {
            ctx.paths()
                .map_err(|_| usage("cannot resolve the Heimdall directories"))?
                .state_dir
                .join("mgmt")
                .join(environment.as_str())
        } else {
            mgmt::windows::WindowsDpapiMgmt::default_dir(environment)
                .map_err(|_| MgmtKeyUnavailable::StoreUnavailable.to_error())?
        };
        Ok(Box::new(mgmt::windows::WindowsDpapiMgmt::in_dir(
            dir,
            environment,
        )))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(mgmt::linux::LinuxSecretServiceMgmt::new(
            environment,
        )))
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        Ok(Box::new(mgmt::UnsupportedStore))
    }
}

fn unavailable(e: MgmtStoreError) -> MgmtKeyUnavailable {
    match e {
        MgmtStoreError::Unavailable(
            MgmtStoreAvailability::Locked | MgmtStoreAvailability::InteractionNotAllowed,
        ) => MgmtKeyUnavailable::Locked,
        MgmtStoreError::Unavailable(_) | MgmtStoreError::Corrupt => {
            MgmtKeyUnavailable::StoreUnavailable
        }
        MgmtStoreError::NotFound => MgmtKeyUnavailable::NotFound,
        _ => MgmtKeyUnavailable::Failed,
    }
}

/// [`MgmtKeyPort`] over the installation's store (absent: the installation's state could not
/// be read, so no store can be selected).
struct StoreKey {
    store: Option<Arc<dyn MgmtKeyStore>>,
}

impl StoreKey {
    fn store(&self) -> Result<&Arc<dyn MgmtKeyStore>, MgmtKeyUnavailable> {
        self.store
            .as_ref()
            .ok_or(MgmtKeyUnavailable::StoreUnavailable)
    }
}

impl MgmtKeyPort for StoreKey {
    fn check(&self) -> Result<(), MgmtKeyUnavailable> {
        match self.store()?.availability() {
            MgmtStoreAvailability::Available => Ok(()),
            other => Err(unavailable(MgmtStoreError::Unavailable(other))),
        }
    }

    fn public_key(&self, create: bool) -> Result<MgmtKeyInfo, MgmtKeyUnavailable> {
        let store = self.store()?;
        let key = if create {
            mgmt::load_or_create(store.as_ref()).map(|(k, _)| k)
        } else {
            store.load()
        }
        .map_err(unavailable)?;
        let public = key.public().map_err(|_| MgmtKeyUnavailable::Failed)?;
        Ok(MgmtKeyInfo {
            openssh_line: public.openssh_line,
            fingerprint: public.fingerprint,
        })
    }

    fn destroy(&self) -> Result<(), MgmtKeyUnavailable> {
        self.store()?.destroy().map_err(unavailable)
    }

    fn fingerprint_of(&self, openssh_line: &str) -> Option<KeyFingerprint> {
        mgmt::openssh_fingerprint(openssh_line)
    }
}

// --- the records, the catalog, the confirmation ------------------------------------------

/// The instance lock and the read-write store held by a command that writes the
/// controller's records (the CLI's direct-write pattern: `uninstall`'s purge and `remote
/// init` take the runtime's instance lock, then open the store read-write). Held for the
/// whole command, so no runtime starts while a bootstrap or retirement runs and every write
/// lands. No request form carries a controller record, so a running runtime cannot write it
/// for the CLI: the command then refuses before any effect (DONE "W2 wiring").
struct Writer {
    _lock: heimdall_runtime::InstanceLock,
    store: heimdall_store::Store,
}

fn state_refusal(message: &str) -> OpError {
    OpError::new(Code::StateUnavailable, message).with_effect(EffectStatus::None)
}

/// Take the instance lock of `paths` and open its store read-write (creating it at first
/// use), with this installation's environment ID recorded (as `remote init`'s
/// `init_runner` and the runtime's first start do).
fn writer(paths: &heimdall_runtime::Paths) -> Result<Writer, OpError> {
    paths
        .ensure()
        .map_err(|_| state_refusal("the Heimdall directories cannot be prepared"))?;
    let lock = match heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir) {
        Ok(lock) => lock,
        Err(heimdall_runtime::instance::InstanceError::AlreadyRunning) => {
            return Err(OpError::new(
                Code::ServiceUnavailable,
                "the runtime is running on this installation: this command writes the \
                 controller's records under the instance lock, so stop the runtime \
                 (`heimdall service stop`) and run it again; nothing was changed",
            )
            .with_effect(EffectStatus::None));
        }
        Err(_) => return Err(state_refusal("the instance lock cannot be taken")),
    };
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    let store = heimdall_store::Store::open(&db, Arc::new(heimdall_store::NoFaults))
        .map_err(|_| state_refusal("the state database cannot be opened"))?;
    let fresh = heimdall_app::ids::new_environment_id().map_err(|_| {
        OpError::new(
            Code::InternalError,
            "operating system randomness unavailable",
        )
    })?;
    store
        .transaction(|tx| {
            if tx.self_environment()?.is_none() {
                tx.init_self_environment(&fresh)?;
            }
            Ok(())
        })
        .map_err(|_| state_refusal("the installation's environment cannot be recorded"))?;
    Ok(Writer { _lock: lock, store })
}

/// The controller's records over `remote_environment_pins` (`Txn::remote_environment_pins`
/// and friends). Reads go through the held writer, or a read-only open (no state yet: no
/// records); writes need the writer.
struct StoreRegistry {
    db: PathBuf,
    writer: Option<Arc<Writer>>,
}

fn records_unreadable() -> OpError {
    state_refusal("the controller's remote environment records cannot be read")
}

impl StoreRegistry {
    fn decode(rows: Vec<(EnvironmentId, String)>) -> Result<Vec<RemoteEnvironmentRecord>, OpError> {
        rows.into_iter()
            .map(|(id, json)| {
                let record: RemoteEnvironmentRecord =
                    serde_json::from_str(&json).map_err(|_| records_unreadable())?;
                if record.environment == id {
                    Ok(record)
                } else {
                    Err(records_unreadable())
                }
            })
            .collect()
    }

    fn write<T>(
        &self,
        f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<T>,
    ) -> Result<T, OpError> {
        let writer = self.writer.as_ref().ok_or_else(|| {
            OpError::new(
                Code::InternalError,
                "the controller's records were opened read-only",
            )
        })?;
        writer.store.transaction(f).map_err(|_| {
            state_refusal("the controller's remote environment records cannot be written")
        })
    }
}

impl EnvironmentRegistry for StoreRegistry {
    fn list(&self) -> Result<Vec<RemoteEnvironmentRecord>, OpError> {
        let rows = match &self.writer {
            Some(w) => w.store.transaction(|tx| tx.remote_environment_pins()),
            None if !self.db.exists() => return Ok(Vec::new()),
            None => {
                heimdall_store::Store::open_read_only(&self.db, Arc::new(heimdall_store::NoFaults))
                    .and_then(|s| s.transaction(|tx| tx.remote_environment_pins()))
            }
        }
        .map_err(|_| records_unreadable())?;
        Self::decode(rows)
    }

    fn put(&self, record: &RemoteEnvironmentRecord) -> Result<(), OpError> {
        let json = serde_json::to_string(record).map_err(|_| records_unreadable())?;
        let host = record
            .route
            .runner
            .host_keys
            .first()
            .and_then(|k| mgmt::openssh_fingerprint(k))
            .ok_or_else(|| usage("the record has no pinned host key"))?;
        self.write(|tx| {
            tx.put_remote_environment_pin(
                &record.environment,
                &record.destination,
                &record.route.runner.account,
                &host,
                &json,
                record.pinned_at,
            )
        })
    }

    fn remove(&self, environment: &EnvironmentId) -> Result<bool, OpError> {
        self.write(|tx| tx.remove_remote_environment_pin(environment))
    }
}

/// The catalog's verified access, read from the state database (read-only): the
/// destination's alias, and the owner-approved target of the pair's verified M03 enrollment
/// (host name, port, account and host key). A pair with no verified enrollment has no pinned
/// key, which `add` refuses (`host_trust_undetermined`).
struct StateCatalog {
    db: PathBuf,
}

impl AccessCatalog for StateCatalog {
    fn verified_access(
        &self,
        destination: &DestinationId,
        account: &AccountName,
    ) -> Result<Option<VerifiedAccess>, OpError> {
        use heimdall_contract::enrollment::EnrollmentState;
        let unreadable = || {
            OpError::new(
                Code::StateUnavailable,
                "the installation's catalog cannot be read",
            )
        };
        let store =
            heimdall_store::Store::open_read_only(&self.db, Arc::new(heimdall_store::NoFaults))
                .map_err(|_| unreadable())?;
        let pair = heimdall_contract::request::AccessPairRef {
            destination: destination.clone(),
            account: account.clone(),
        };
        let (record, enrollments) = store
            .transaction(|tx| {
                Ok((
                    tx.destination(destination)?,
                    tx.enrollments_for_pair(&pair)?,
                ))
            })
            .map_err(|_| unreadable())?;
        let Some(record) = record else {
            return Ok(None);
        };
        let target = enrollments
            .into_iter()
            .find(|e| e.state == EnrollmentState::Verified)
            .map(|e| e.target);
        let (hostname, port, host_keys) = match target {
            Some(t) => (
                t.hostname,
                Some(t.port),
                vec![format!("{} {}", t.host_key.algorithm, t.host_key.key)],
            ),
            None => (String::new(), None, Vec::new()),
        };
        Ok(Some(VerifiedAccess {
            destination: destination.clone(),
            alias: record.alias,
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname,
                    port,
                    account: account.clone(),
                    host_keys,
                },
                jump: None,
            },
        }))
    }
}

/// The owner's typed `yes` on this terminal (ADR-0006 §3.1's prompt rules; never on a
/// non-interactive or non-terminal invocation).
struct TerminalConfirm {
    interactive: bool,
}

fn confirmation_text(what: &Confirmation) -> String {
    match what {
        Confirmation::InviteKey {
            environment,
            role,
            fingerprint,
        } => format!(
            "Invite a device to runner {} as {role:?}.\nIts management key's fingerprint is\n    {}\nConfirm that the invited device shows exactly this fingerprint.\nType yes to continue: ",
            environment.as_str(),
            fingerprint.as_str()
        ),
        Confirmation::JoinRunner {
            environment,
            host_fingerprints,
            role,
        } => format!(
            "Join runner {} as {role:?}.\nIts host key fingerprints:\n    {}\nConfirm that the owner's controller shows exactly this environment ID and these fingerprints.\nType yes to continue: ",
            environment.as_str(),
            host_fingerprints.join("\n    ")
        ),
        Confirmation::RetireDevice {
            environments,
            fingerprint,
        } => format!(
            "Retire this device: revoke it on {} runner(s), then destroy its management key {}.\nThe key cannot be recovered; this device can only rejoin by a new invitation or bootstrap.\nType yes to continue: ",
            environments.len(),
            fingerprint.as_str()
        ),
    }
}

impl TerminalConfirm {
    /// Show `text` and read a typed `yes` (default No, 120 s; never when not interactive).
    fn ask(&self, text: &str) -> bool {
        if !self.interactive {
            return false;
        }
        output::prompt(&output::sanitize_for_terminal(text));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let read = std::io::stdin().read_line(&mut line);
            let _ = tx.send(read.map(|n| (n, line)));
        });
        match rx.recv_timeout(crate::prompt::PROMPT_TIMEOUT) {
            Ok(Ok((0, _))) | Ok(Err(_)) | Err(_) => false,
            Ok(Ok((_, line))) => crate::prompt::classify(Some(&line)) == crate::prompt::Answer::Yes,
        }
    }
}

impl LocalConfirm for TerminalConfirm {
    fn confirm(&self, what: &Confirmation) -> bool {
        self.ask(&confirmation_text(what))
    }
}

// --- management sessions -----------------------------------------------------------------

/// How long a management session's hello may take (connect, authenticate, negotiate).
const SESSION_HELLO_BOUND: Duration = Duration::from_secs(30);

/// Management sessions over `ssh -F <isolated configuration>` (module docs).
struct SshSessions {
    ssh_client: Option<PathBuf>,
    /// A private directory for per-session configuration and agent sockets.
    root: PathBuf,
    key: Arc<StoreKey>,
}

type SessionStream = tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>;

/// One open management session; its scratch directory is removed when it ends.
struct SshSession {
    client: heimdall_ipc::session::ControlClient<SessionStream>,
    hello: SessionHello,
    _child: tokio::process::Child,
    agent: Option<SessionAgent>,
    dir: PathBuf,
}

impl Drop for SshSession {
    fn drop(&mut self) {
        drop(self.agent.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[async_trait::async_trait]
impl ManagementSession for SshSession {
    fn hello(&self) -> &SessionHello {
        &self.hello
    }

    async fn call(&mut self, call: ManagementCall) -> Result<Envelope<serde_json::Value>, OpError> {
        self.client.request(call.into_request()).await.map_err(|_| {
            OpError::new(
                Code::OutcomeUnknown,
                "the management session ended before the runner answered: the request may \
                 have been applied; repeat it (it is idempotent) to read the outcome",
            )
        })
    }
}

fn session_error(stderr: &[u8]) -> OpError {
    match env_ssh::classify_preflight(stderr) {
        env_ssh::PreflightVerdict::HostKeyMismatch => OpError::new(
            Code::CapabilityUnavailable,
            "the runner's host key is not the pinned key: held, nothing sent (repair the pin \
             only through independently verified access)",
        )
        .with_reason(reason::ENVIRONMENT_IDENTITY_MISMATCH),
        env_ssh::PreflightVerdict::HostVerified => OpError::new(
            Code::CapabilityUnavailable,
            "the runner refused this device's management key (revoked, an expired invitation, \
             or not enrolled)",
        ),
        env_ssh::PreflightVerdict::Unreachable => OpError::new(
            Code::DestinationUnreachable,
            "the runner could not be reached for a management session",
        ),
    }
    .with_effect(EffectStatus::None)
}

impl SshSessions {
    fn session_dir(&self) -> Result<PathBuf, OpError> {
        let mut bytes = [0u8; 6];
        heimdall_credential::vault::SystemRng::fill(&mut bytes).map_err(|_| {
            OpError::new(
                Code::InternalError,
                "operating system randomness unavailable",
            )
        })?;
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = self.root.join(name);
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|_| {
            OpError::new(
                Code::StateUnavailable,
                "the management session directory could not be created",
            )
        })?;
        Ok(dir)
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), OpError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .map_err(|_| {
            OpError::new(
                Code::StateUnavailable,
                "a management session file could not be written",
            )
        })
}

fn render_refused(_e: heimdall_sshconf::render::RenderError) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the management configuration cannot be rendered for this runner's recorded route",
    )
    .with_reason(reason::HOST_PIN_DEFEATED)
}

#[async_trait::async_trait]
impl ManagementSessions for SshSessions {
    async fn open(&self, target: &SessionTarget) -> Result<Box<dyn ManagementSession>, OpError> {
        use heimdall_sshconf::mgmt::{
            HopIdentity, MgmtHop, MgmtTarget, PinnedKey, render_mgmt_config, render_mgmt_pin_file,
        };
        use heimdall_sshconf::render::{HostName, PathStyle, RenderPath};
        if !cfg!(unix) {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "management sessions are not available on this platform in this build",
            )
            .with_reason(reason::DRIVER_UNAVAILABLE));
        }
        if target.route.jump.is_some() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "management through a jump hop is not available in this build",
            )
            .with_reason(reason::ROUTE_DEPENDENCY_OUT_OF_SCOPE));
        }
        let ssh_client = self
            .ssh_client
            .clone()
            .ok_or_else(|| OpError::new(Code::LaunchFailed, "no OpenSSH client was found"))?;
        let store = self.key.store().map_err(MgmtKeyUnavailable::to_error)?;
        let key = store.load().map_err(|e| unavailable(e).to_error())?;
        let public = key
            .public()
            .map_err(|_| MgmtKeyUnavailable::Failed.to_error())?;
        let name = match &target.name {
            SessionName::Environment(e) => e.as_str().to_owned(),
            SessionName::Bootstrap(d) => format!("bootstrap.{}", d.as_str()),
        };
        let runner = &target.route.runner;
        let dir = self.session_dir()?;
        let cleanup = |e: OpError| {
            let _ = std::fs::remove_dir_all(&dir);
            e
        };
        let socket = dir.join("a.sock");
        let pub_file = dir.join("k_mgmt.pub");
        let pins_file = dir.join("known_hosts");
        let config_file = dir.join("mgmt.conf");
        let path = |p: &Path| RenderPath::absolute(p, PathStyle::Unix).map_err(render_refused);
        let mgmt_target = (|| -> Result<MgmtTarget, OpError> {
            Ok(MgmtTarget {
                environment: name.clone(),
                hop: MgmtHop {
                    hostname: HostName::parse(&runner.hostname).map_err(render_refused)?,
                    port: runner.port,
                    user: runner.account.as_str().to_owned(),
                    pins: runner
                        .host_keys
                        .iter()
                        .map(|k| PinnedKey::parse(k))
                        .collect::<Result<_, _>>()
                        .map_err(render_refused)?,
                    identity: HopIdentity::new(path(&socket)?, path(&pub_file)?)
                        .map_err(render_refused)?,
                },
                jump: None,
            })
        })()
        .map_err(cleanup)?;
        let config = render_mgmt_config(
            &mgmt_target,
            &path(&pins_file).map_err(cleanup)?,
            PathStyle::Unix,
        )
        .map_err(render_refused)
        .map_err(cleanup)?;
        let pins = render_mgmt_pin_file(&mgmt_target)
            .map_err(render_refused)
            .map_err(cleanup)?;
        write_private(&pub_file, format!("{}\n", public.openssh_line).as_bytes())
            .map_err(cleanup)?;
        write_private(&pins_file, &pins).map_err(cleanup)?;
        write_private(&config_file, &config).map_err(cleanup)?;
        let signer = MgmtSigner::with_host_key_lines(
            key,
            [runner.account.as_str().to_owned()],
            &runner.host_keys,
        )
        .map_err(|_| cleanup(MgmtKeyUnavailable::Failed.to_error()))?;
        let agent = SessionAgent::start(&socket, signer).map_err(|_| {
            cleanup(OpError::new(
                Code::StateUnavailable,
                "the management key agent could not be started",
            ))
        })?;
        let args = env_ssh::management_args(&config_file, &mgmt_target.alias());
        let child = env_ssh::spawn_management(&ssh_client, &args).map_err(cleanup)?;
        let env_ssh::ManagementChild {
            child,
            stdin,
            stdout,
            stderr,
        } = child;
        let required: BTreeSet<String> =
            [heimdall_app::remote_env::MANAGEMENT_CAPABILITY.to_owned()].into();
        let handshake = tokio::time::timeout(
            SESSION_HELLO_BOUND,
            heimdall_ipc::session::ControlClient::handshake(
                tokio::io::join(stdout, stdin),
                heimdall_contract::ipc::PeerInfo {
                    name: CLIENT_NAME.to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                required,
                InteractionMode::NonInteractive,
            ),
        )
        .await;
        let client = match handshake {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                if let Some(heimdall_ipc::session::ServerRefusal::Rejected(env)) =
                    heimdall_ipc::session::server_refusal(&e)
                {
                    return Err(cleanup(OpError::from_detail(env.data.error.clone(), None)));
                }
                let kept = stderr
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                return Err(cleanup(session_error(&kept)));
            }
            Err(_) => {
                return Err(cleanup(OpError::new(
                    Code::DestinationUnreachable,
                    "the runner did not answer the management hello in time",
                )));
            }
        };
        let hello = SessionHello {
            environment: client.server().environment_id.clone(),
            role: client.server().role,
            client: client.server().remote_client.clone(),
        };
        Ok(Box::new(SshSession {
            client,
            hello,
            _child: child,
            agent: Some(agent),
            dir,
        }))
    }
}

// --- the handlers ------------------------------------------------------------------------

/// The verified `ssh` client (the M02 selection), when one is found.
fn ssh_client() -> Option<PathBuf> {
    use heimdall_localenv::clients::{ClientKind, ClientsConfig, selected_path};
    use heimdall_localenv::env::{Env, Platform};
    let env = Env::capture();
    let path = selected_path(&env, &ClientsConfig::default(), ClientKind::Ssh)?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    heimdall_launch::resolve::resolve_program(path.as_os_str(), &env, &cwd, Platform::current())
        .ok()
        .map(|p| p.path)
}

/// The installation's environment ID, read from the state database (read-only; `None` when
/// the installation has no state yet).
fn self_environment(db: &Path) -> Option<EnvironmentId> {
    heimdall_store::Store::open_read_only(db, Arc::new(heimdall_store::NoFaults))
        .and_then(|s| s.transaction(|tx| tx.self_environment()))
        .ok()
        .flatten()
}

/// The ports of one invocation.
struct Wiring {
    key: Arc<StoreKey>,
    registry: StoreRegistry,
    catalog: StateCatalog,
    bootstrap: env_ssh::BootstrapSsh,
    sessions: SshSessions,
    confirm: TerminalConfirm,
}

/// The ports; `write`: the command writes the controller's records, so it holds the
/// instance lock and the read-write store for its whole run ([`writer`]).
fn wiring(ctx: &Ctx, write: bool) -> Result<Wiring, OpError> {
    let paths = ctx.paths().map_err(|e| {
        OpError::new(Code::UsageError, e.data.error.message.clone()).with_effect(EffectStatus::None)
    })?;
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    let writer = if write {
        Some(Arc::new(writer(&paths)?))
    } else {
        None
    };
    let environment = match &writer {
        Some(w) => w
            .store
            .transaction(|tx| tx.self_environment())
            .ok()
            .flatten(),
        None => self_environment(&db),
    };
    let store = match environment {
        Some(environment) => Some(Arc::<dyn MgmtKeyStore>::from(mgmt_store(
            ctx,
            &environment,
        )?)),
        None => None,
    };
    let key = Arc::new(StoreKey { store });
    let ssh = ssh_client();
    let root = paths.runtime_dir.join("mgmt");
    Ok(Wiring {
        key: key.clone(),
        registry: StoreRegistry {
            db: db.clone(),
            writer,
        },
        catalog: StateCatalog { db },
        bootstrap: env_ssh::BootstrapSsh {
            // No client found: an empty path, which the adapter refuses (`LAUNCH_FAILED`).
            ssh_client: ssh.clone().unwrap_or_default(),
            scratch_dir: root.clone(),
            config: None,
            extra_options: Vec::new(),
        },
        sessions: SshSessions {
            ssh_client: ssh,
            root,
            key,
        },
        confirm: TerminalConfirm {
            interactive: ctx.interactive(),
        },
    })
}

fn now() -> heimdall_contract::Timestamp {
    heimdall_contract::Timestamp::now()
}

fn record_line(r: &RemoteEnvironmentRecord) -> String {
    format!(
        "{}  destination {}  account {}  role {:?}  client {}{}",
        r.environment.as_str(),
        r.destination.as_str(),
        r.route.runner.account.as_str(),
        r.role,
        r.client.as_str(),
        r.label
            .as_deref()
            .map(|l| format!("  label {}", output::quoted_field(l)))
            .unwrap_or_default()
    )
}

/// `environment …`.
pub(crate) fn environment(ctx: &Ctx, command: EnvironmentCommand) -> ExitCode {
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => {
            let env = output::error_value(env);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    if let EnvironmentCommand::Join(EnvJoinArgs { show_key: true, .. }) = &command {
        return show_key(ctx);
    }
    // `add` needs the owner at a terminal: refused before any state is touched.
    if matches!(command, EnvironmentCommand::Add(_)) && !ctx.interactive() {
        return emit_error(
            ctx,
            OpError::new(
                Code::InteractionRequired,
                "environment add runs an interactive ssh session with a terminal, where the \
                 runner confirms the enrollment: run it from a terminal",
            )
            .with_effect(EffectStatus::None),
        );
    }
    // The commands that write the controller's records hold the instance lock throughout.
    let write = matches!(
        command,
        EnvironmentCommand::Add(_) | EnvironmentCommand::Join(_) | EnvironmentCommand::Remove(_)
    );
    let w = match wiring(ctx, write) {
        Ok(w) => w,
        Err(e) => return emit_error(ctx, e),
    };
    let controller = RemoteEnvController::new(ControllerPorts {
        key: w.key.as_ref(),
        registry: &w.registry,
        catalog: &w.catalog,
        bootstrap: &w.bootstrap,
        sessions: &w.sessions,
        confirm: &w.confirm,
        now: now(),
    });
    let result = rt.block_on(async {
        match command {
            EnvironmentCommand::Add(a) => {
                let destination = DestinationId::parse(&a.destination)
                    .map_err(|_| usage("the destination ID is malformed"))?;
                let account = AccountName::parse(&a.account)
                    .map_err(|_| usage("the account name is malformed"))?;
                if let Some(label) = &a.label
                    && (label.is_empty()
                        || label.len() > heimdall_contract::remote::MAX_REMOTE_LABEL_BYTES
                        || label.chars().any(char::is_control))
                {
                    return Err(usage("the label must be 1 to 64 bytes without control characters"));
                }
                let record = controller
                    .add(&AddInput {
                        destination,
                        account,
                        label: a.label,
                        runner_program: a.runner_program,
                        runner_home: Some(a.runner_home),
                        runner_sha256: a.runner_sha256,
                    })
                    .await?;
                let human = format!("added {}", record_line(&record));
                Ok((serde_json::to_value(&record).unwrap_or_default(), human))
            }
            EnvironmentCommand::Invite(a) => {
                let environment = parse_environment(&a.environment)?;
                let key_fingerprint = mgmt::openssh_fingerprint(&a.public_key)
                    .ok_or_else(|| usage("--public-key is not one OpenSSH public key line"))?;
                let request_id = match a.request_id {
                    Some(id) => RequestId::parse(&id).map_err(|_| usage("the request ID is malformed"))?,
                    None => heimdall_app::remote_env::new_request_id()?,
                };
                match controller
                    .invite(&InviteInput {
                        environment: environment.clone(),
                        role: a.role.into(),
                        public_key: a.public_key,
                        key_fingerprint,
                        request_id,
                    })
                    .await?
                {
                    InviteOutcome::Created(bundle) => {
                        let value = serde_json::to_value(&*bundle).unwrap_or_default();
                        let human = format!(
                            "invitation created; give this bundle to the invited device (it is public; it grants nothing by itself):\n{}",
                            serde_json::to_string_pretty(&value).unwrap_or_default()
                        );
                        Ok((value, human))
                    }
                    InviteOutcome::Pending {
                        decision_ref,
                        request_id,
                    } => Err(OpError::new(
                        Code::ApprovalRequired,
                        format!(
                            "the runner holds the invitation for its local confirmation: confirm \
                             decision {decision_ref} at the runner, then run this command again \
                             with --request-id {}",
                            request_id.as_str()
                        ),
                    )
                    .with_effect(EffectStatus::None)
                    .with_next(NextAction {
                        action: "observe".into(),
                        decision_ref: Some(decision_ref),
                        ..NextAction::default()
                    })),
                }
            }
            EnvironmentCommand::Join(a) => {
                let bundle = read_bundle(a.bundle.as_deref())?;
                let record = controller.join(&bundle).await?;
                let human = format!("joined {}", record_line(&record));
                Ok((serde_json::to_value(&record).unwrap_or_default(), human))
            }
            EnvironmentCommand::RevokeClient(a) => {
                let environment = parse_environment(&a.environment)?;
                let client = ClientId::parse(&a.client).map_err(|_| usage("the client ID is malformed"))?;
                let data = controller.revoke_client(&environment, &client).await?;
                Ok((data, format!("revoked client {} on {}", client.as_str(), environment.as_str())))
            }
            EnvironmentCommand::Remove(a) => {
                let environment = parse_environment(&a.environment)?;
                controller.remove(&environment).await?;
                Ok((
                    serde_json::json!({ "removed": environment.as_str() }),
                    format!("removed {} (this device's management key is kept)", environment.as_str()),
                ))
            }
            EnvironmentCommand::Update(a) => {
                let environment = parse_environment(&a.environment)?;
                let data = controller.update(&environment).await?;
                Ok((data, format!("update requested on {}", environment.as_str())))
            }
            EnvironmentCommand::Status(a) => {
                let environment = a.environment.as_deref().map(parse_environment).transpose()?;
                let report = controller.status(environment.as_ref())?;
                let mut human = format!("management: {}", report.management);
                for e in &report.environments {
                    human.push('\n');
                    human.push_str(&record_line(&e.record));
                }
                Ok((serde_json::to_value(&report).unwrap_or_default(), human))
            }
        }
    });
    match result {
        Ok((data, human)) => emit_ok(ctx, data, &human),
        Err(e) => emit_error(ctx, e),
    }
}

/// The largest invitation bundle read.
const MAX_BUNDLE_BYTES: u64 = 64 * 1024;

fn read_bundle(path: Option<&Path>) -> Result<InvitationBundle, OpError> {
    let bad = || {
        usage(
            "the invitation bundle cannot be read (expected the JSON `environment invite` printed)",
        )
    };
    let mut text = Vec::new();
    match path {
        Some(p) if p.as_os_str() == "-" => {
            std::io::stdin()
                .take(MAX_BUNDLE_BYTES + 1)
                .read_to_end(&mut text)
                .map_err(|_| bad())?;
        }
        Some(p) => {
            crate::input_file::open_regular(p)
                .and_then(|f| f.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut text))
                .map_err(|_| bad())?;
        }
        None => return Err(bad()),
    }
    if text.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(usage("the invitation bundle is too large"));
    }
    serde_json::from_slice(&text).map_err(|_| bad())
}

/// `environment join --show-key`: this device's K_mgmt public key and fingerprint, created
/// when absent. The store item is scoped to the installation's environment ID: read from the
/// state database, or, on an installation with no state yet, recorded under the instance
/// lock first ([`writer`]); no runtime is started.
fn show_key(ctx: &Ctx) -> ExitCode {
    let result = (|| -> Result<(serde_json::Value, String), OpError> {
        let paths = ctx
            .paths()
            .map_err(|_| usage("cannot resolve the Heimdall directories"))?;
        let db = paths
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE);
        let environment = match self_environment(&db) {
            Some(environment) => environment,
            None => writer(&paths)?
                .store
                .transaction(|tx| tx.self_environment())
                .ok()
                .flatten()
                .ok_or_else(|| state_refusal("the installation's environment cannot be read"))?,
        };
        let store = mgmt_store(ctx, &environment)?;
        let (key, created) =
            mgmt::load_or_create(store.as_ref()).map_err(|e| unavailable(e).to_error())?;
        let public = key
            .public()
            .map_err(|_| MgmtKeyUnavailable::Failed.to_error())?;
        let kind = match store.kind() {
            mgmt::MgmtStoreKind::Product(k) => serde_json::to_value(k).unwrap_or_default(),
            mgmt::MgmtStoreKind::Test(name) => serde_json::json!({ "test": name }),
            _ => serde_json::Value::Null,
        };
        let data = serde_json::json!({
            "public_key": public.openssh_line,
            "fingerprint": public.fingerprint.as_str(),
            "created": created,
            "store": kind,
        });
        let human = format!(
            "this device's management key (send the line to the owner; compare the fingerprint when they invite it):\n{}\n{}",
            public.openssh_line,
            public.fingerprint.as_str()
        );
        Ok((data, human))
    })();
    match result {
        Ok((data, human)) => emit_ok(ctx, data, &human),
        Err(e) => emit_error(ctx, e),
    }
}

/// `device retire` (ADR-0012 §3.4, §3.10 item 4).
pub(crate) fn device(ctx: &Ctx, command: DeviceCommand) -> ExitCode {
    let DeviceCommand::Retire = command;
    if !ctx.interactive() {
        return emit_error(
            ctx,
            OpError::new(
                Code::InteractionRequired,
                "device retire needs the owner at this device's terminal (a typed yes); \
                 nothing was read, revoked or destroyed",
            )
            .with_effect(EffectStatus::None),
        );
    }
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => {
            let env = output::error_value(env);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    let w = match wiring(ctx, true) {
        Ok(w) => w,
        Err(e) => return emit_error(ctx, e),
    };
    let controller = RemoteEnvController::new(ControllerPorts {
        key: w.key.as_ref(),
        registry: &w.registry,
        catalog: &w.catalog,
        bootstrap: &w.bootstrap,
        sessions: &w.sessions,
        confirm: &w.confirm,
        now: now(),
    });
    match rt.block_on(controller.retire()) {
        Ok(outcome) => {
            let human = format!(
                "retired: revoked on {} runner(s); management key destroyed",
                outcome.revoked_on.len()
            );
            emit_ok(
                ctx,
                serde_json::to_value(&outcome).unwrap_or_default(),
                &human,
            )
        }
        Err(e) => emit_error(ctx, e),
    }
}

// --- the runner's side (`remote init`, `remote serve`) --------------------------------------

/// `remote …`.
pub(crate) fn remote(ctx: &Ctx, command: RemoteCommand) -> ExitCode {
    match command {
        RemoteCommand::Init(a) => match remote_init(ctx, &a) {
            Ok((data, human)) => emit_ok(ctx, data, &human),
            Err(e) => emit_error(ctx, e),
        },
        RemoteCommand::Serve(a) => remote_serve(&a),
    }
}

/// The SHA-256 of this executable (lowercase hex), for the bootstrap's checksum step.
fn own_sha256() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    heimdall_localenv::clients::sha256_file(&exe)
}

/// `remote init` (ADR-0012 §3.3 steps 1–3): the checksum step, then, under the instance lock
/// and after the owner's typed `yes` on this terminal (the runner-local confirmation of an
/// owner enrollment, §3.10), the runner marker (`heimdall_runtime::paired::init_runner`) and
/// the owner client (`Txn::enroll_bootstrap_owner`: idempotent for a retried bootstrap of the
/// same key). Answers the environment ID, the effective client and the management line to
/// install (no management-line writer exists in this build: `line_written: false`).
fn remote_init(ctx: &Ctx, a: &RemoteInitArgs) -> Result<(serde_json::Value, String), OpError> {
    use heimdall_remote::line::{ManagementLine, PublicKeyText};
    use heimdall_store::ext_m06::{AppliedLine, ClientState, RemoteClientRecord};
    let home = ctx
        .home
        .clone()
        .filter(|h| h.is_absolute())
        .ok_or_else(|| {
            usage("remote init needs an explicit, absolute --home (the forced command names it)")
        })?;
    let client =
        ClientId::parse(&a.owner_client).map_err(|_| usage("the client ID is malformed"))?;
    let key = PublicKeyText::parse(&a.owner_key)
        .map_err(|_| usage("--owner-key is not one ssh-ed25519 public key"))?;
    let exe = std::env::current_exe().map_err(|_| usage("cannot locate this executable"))?;
    let command = heimdall_runtime::paired::RunnerServeCommand::new(
        exe.to_str().unwrap_or_default(),
        home.to_str().unwrap_or_default(),
    )
    .map_err(|_| usage("the forced command's paths are not from the permitted character set"))?;
    if let Some(expected) = &a.expect_sha256 {
        let well_formed = expected.len() == 64
            && expected
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !well_formed {
            return Err(usage(
                "--expect-sha256 takes 64 lowercase hexadecimal characters",
            ));
        }
        if own_sha256().as_deref() != Some(expected.as_str()) {
            return Err(OpError::new(
                Code::ConfigConflict,
                "this runner's Heimdall executable does not have the expected SHA-256: nothing \
                 was written (install the verified build, then bootstrap again)",
            )
            .with_effect(EffectStatus::None));
        }
    }
    if !ctx.interactive() {
        return Err(OpError::new(
            Code::InteractionRequired,
            "remote init needs the owner at this runner's terminal (the bootstrap's \
             interactive ssh session): nothing was written",
        )
        .with_effect(EffectStatus::None));
    }
    let paths = ctx
        .paths()
        .map_err(|_| usage("cannot resolve the Heimdall directories"))?;
    let w = writer(&paths)?;
    let fingerprint = key.fingerprint();
    let confirmed = TerminalConfirm { interactive: true }.ask(&format!(
        "Make this installation a Heimdall remote runner and enroll a controller as its OWNER.\n\
         Management key fingerprint:\n    {}\nClient: {}\n\
         Compare the fingerprint with the controller's display. Anyone with a shell on this \
         account is owner of this runner too.\nType yes to continue: ",
        fingerprint.as_str(),
        client.as_str()
    ));
    if !confirmed {
        return Err(OpError::new(
            Code::InteractionRequired,
            "the owner enrollment was not confirmed: nothing was written",
        )
        .with_effect(EffectStatus::None));
    }
    let environment = heimdall_runtime::paired::init_runner(&w.store)?;
    let at = now();
    let record = RemoteClientRecord {
        client,
        role: Role::Owner,
        key_fingerprint: fingerprint.clone(),
        public_key: key.openssh(),
        state: ClientState::Active,
        invitation: None,
        revoked_generation: None,
        revocation: None,
        created_at: at,
        updated_at: at,
        line: AppliedLine::Absent,
    };
    let (owner, created) = w
        .store
        .transaction(|tx| tx.enroll_bootstrap_owner(&record, at))
        .map_err(|e| match e {
            heimdall_store::StoreError::GenerationConflict(_) => OpError::new(
                Code::CapabilityUnavailable,
                "this key is already authorized for another client of this runner",
            )
            .with_reason(reason::KEY_ALREADY_AUTHORIZED)
            .with_effect(EffectStatus::None),
            _ => state_refusal("the owner enrollment cannot be written"),
        })?;
    let line = ManagementLine {
        client: owner.client.clone(),
        command,
        key,
        expiry: None,
    }
    .render()
    .map_err(|_| usage("the management line cannot be rendered"))?;
    let data = serde_json::json!({
        "environment": environment.as_str(),
        "client": owner.client.as_str(),
        "created": created,
        "key_fingerprint": fingerprint.as_str(),
        "management_line": line,
        "line_written": false,
    });
    let human = format!(
        "this installation is remote runner {} with owner client {}{}.\nNo management-line \
         writer exists in this build: the line for this account's authorized_keys is in the \
         JSON output (`management_line`).",
        environment.as_str(),
        owner.client.as_str(),
        if created { "" } else { " (already enrolled)" }
    );
    Ok((data, human))
}

/// `remote serve --client <cid> --home <abs>` (ADR-0012 §3.6): identity and home from argv
/// only (`ServeArgs::parse`; no environment variable is read), bridged to the home's running
/// runtime. Standard output carries protocol frames only; diagnostics go to standard error.
fn remote_serve(args: &crate::cli::PlannedArgs) -> ExitCode {
    let parsed = match heimdall_runtime::paired::ServeArgs::parse(&args.args) {
        Ok(p) => p,
        Err(e) => {
            output::diagnostic(&format!("heimdall remote serve: {e}"));
            return ExitCode::Usage;
        }
    };
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(_) => return ExitCode::Unavailable,
    };
    let ended = rt.block_on(heimdall_runtime::paired::serve_bridge(
        &parsed,
        tokio::io::stdin(),
        tokio::io::stdout(),
        |home: &Path| {
            let home = home.to_path_buf();
            async move {
                crate::client::control_stream_for_home(&home)
                    .await
                    .map_err(|e| std::io::Error::other(e.data.error.message))
            }
        },
    ));
    match ended {
        Ok(_) => ExitCode::Success,
        Err(_) => ExitCode::Unavailable,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command, dispatch};

    /// The M06 command lines still planned for M06 (their arguments are accepted and
    /// ignored), including the hidden, frozen `route connect`.
    const PLANNED: &[&[&str]] = &[
        &["route", "add", "lab", "--direct", "10.0.0.1:22"],
        &["route", "remove", "lab", "route_00"],
        &["route", "prefer", "lab", "route_00"],
        &[
            "route",
            "connect",
            "--destination",
            "lab",
            "--account",
            "deploy",
            "--endpoint",
            "/run/a.sock",
        ],
        &["transport", "enable", "--serve"],
        &["transport", "disable"],
        &["transport", "adopt-roost", "lab", "--endpoint", "00"],
    ];

    /// ADR-0006 §18 (the revision-5 precedent): each planned M06 command parses, and answers
    /// `USAGE_ERROR` (exit 2, effect `none`, `fix_request`) with "(planned for M06)",
    /// without creating the Heimdall home (so without starting or contacting a runtime).
    #[test]
    fn m06_commands_refuse_as_planned_for_m06() {
        let env = refusal_envelope();
        assert_eq!(env.code, Code::UsageError);
        let error = &env.data["error"];
        assert_eq!(error["effect_status"], "none");
        assert_eq!(error["next"]["action"], "fix_request");
        assert_eq!(error["message"], refusal_message());
        assert!(refusal_message().ends_with("(planned for M06)"));
        let scratch = std::env::temp_dir().join(format!("hm-m06-w2-{}", std::process::id()));
        let home = scratch.join("never-created");
        for line in PLANNED {
            let mut argv = vec!["heimdall", "--json", "--non-interactive", "--home"];
            argv.push(home.to_str().unwrap());
            argv.extend_from_slice(line);
            let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{line:?}: {e}"));
            assert!(
                matches!(cli.command, Some(Command::Route(_) | Command::Transport(_))),
                "{line:?}"
            );
            assert_eq!(dispatch(cli), ExitCode::Usage, "{line:?}");
            assert!(!home.exists(), "{line:?} created the home");
        }
        assert!(!scratch.exists());
    }

    /// The orchestrator's naming ruling (G08 freeze): `environment` (no `env` alias),
    /// `device`, `route`, `transport` with `adopt-roost`; no top-level `roost`; `route
    /// connect` parses but is hidden.
    #[test]
    fn m06_names_follow_the_freeze() {
        for gone in [
            &["env", "status"][..],
            &["roost", "adopt", "lab"][..],
            &["transport", "connect"][..],
        ] {
            let mut argv = vec!["heimdall"];
            argv.extend_from_slice(gone);
            assert!(Cli::try_parse_from(&argv).is_err(), "{gone:?} still parses");
        }
        for line in [
            &["environment", "status"][..],
            &[
                "environment",
                "add",
                "--destination",
                "lab",
                "--account",
                "runner",
                "--runner-program",
                "/opt/heimdall",
                "--runner-home",
                "/srv/runner/heimdall",
            ][..],
            &[
                "environment",
                "invite",
                "env_00",
                "--role",
                "viewer",
                "--public-key",
                "ssh-ed25519 AAAA",
            ][..],
            &["environment", "join", "--show-key"][..],
            &["environment", "join", "bundle.json"][..],
            &["environment", "revoke-client", "env_00", "cl_00"][..],
            &["environment", "remove", "env_00"][..],
            &["environment", "update", "env_00"][..],
            &["device", "retire"][..],
        ] {
            let mut argv = vec!["heimdall"];
            argv.extend_from_slice(line);
            assert!(Cli::try_parse_from(&argv).is_ok(), "{line:?}");
        }
        assert!(Cli::try_parse_from(["heimdall", "environment", "join"]).is_err());
        assert!(
            Cli::try_parse_from(["heimdall", "environment", "join", "b.json", "--show-key"])
                .is_err()
        );
        use clap::CommandFactory as _;
        let mut top = Cli::command();
        let route = top.find_subcommand_mut("route").unwrap();
        let connect = route.find_subcommand("connect").unwrap();
        assert!(connect.is_hide_set(), "route connect is hidden");
        let help = route.render_help().to_string();
        assert!(!help.contains("connect"), "{help}");
    }

    /// ⟨W2 wiring⟩ `remote serve`'s arguments reach `ServeArgs::parse` whole: the global
    /// `--home` does not capture the bridge's own `--home` (identity and home from argv only);
    /// `remote` is hidden from the top level, and `service run --runner` parses.
    #[test]
    fn remote_serve_keeps_its_own_arguments_and_remote_is_hidden() {
        let cid = ClientId::from_random_bytes([3; 16]);
        let cli = Cli::try_parse_from([
            "heimdall",
            "remote",
            "serve",
            "--client",
            cid.as_str(),
            "--home",
            "/srv/runner/heimdall",
        ])
        .unwrap();
        assert!(
            cli.home.is_none(),
            "the global --home did not capture serve's"
        );
        let Some(Command::Remote(RemoteCommand::Serve(args))) = cli.command else {
            panic!("not remote serve");
        };
        let parsed = heimdall_runtime::paired::ServeArgs::parse(&args.args).unwrap();
        assert_eq!(parsed.client, cid);
        assert_eq!(
            parsed.home,
            std::path::PathBuf::from("/srv/runner/heimdall")
        );
        assert!(
            Cli::try_parse_from([
                "heimdall",
                "remote",
                "init",
                "--owner-client",
                cid.as_str(),
                "--owner-key",
                "ssh-ed25519 AAAA"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["heimdall", "service", "run", "--runner"]).is_ok());
        use clap::CommandFactory as _;
        let top = Cli::command();
        assert!(top.find_subcommand("remote").unwrap().is_hide_set());
        assert!(!top.clone().render_help().to_string().contains("remote "));
    }

    /// `device retire` without the owner at a terminal is refused before anything is read
    /// (no home is created).
    #[test]
    fn device_retire_needs_a_terminal() {
        let scratch = std::env::temp_dir().join(format!("hm-m06-retire-{}", std::process::id()));
        let home = scratch.join("never-created");
        let cli = Cli::try_parse_from([
            "heimdall",
            "--json",
            "--non-interactive",
            "--home",
            home.to_str().unwrap(),
            "device",
            "retire",
        ])
        .unwrap();
        assert_eq!(dispatch(cli), ExitCode::InteractionRequired);
        assert!(!home.exists());
    }

    #[test]
    fn confirmation_texts_name_what_is_confirmed() {
        let fp = KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap();
        let env = EnvironmentId::from_random_bytes([1; 16]);
        let invite = confirmation_text(&Confirmation::InviteKey {
            environment: env.clone(),
            role: Role::Viewer,
            fingerprint: fp.clone(),
        });
        assert!(invite.contains(fp.as_str()) && invite.contains(env.as_str()));
        let retire = confirmation_text(&Confirmation::RetireDevice {
            environments: vec![env.clone()],
            fingerprint: fp.clone(),
        });
        assert!(retire.contains("destroy") && retire.contains("1 runner"));
        assert!(
            !TerminalConfirm { interactive: false }.confirm(&Confirmation::RetireDevice {
                environments: vec![env],
                fingerprint: fp,
            })
        );
    }
}
