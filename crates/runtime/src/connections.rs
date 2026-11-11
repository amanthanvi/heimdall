//! ⟨M03⟩ Connection control: owned masters, owned dedicated connections and the
//! connection policies (m03-plan U7; ADR-0008 D8, D7 item 2 steps 4 and 6).
//!
//! [`ConnectionSupervisor`] implements `heimdall_app::ports::ConnectionControl`
//! (`start_master`, `close`, `register`) and carries the passes the runtime's supervisor
//! calls (U10 wires them into `supervisor.rs`):
//!
//! * [`ConnectionSupervisor::effective_policy`]: D8 item 1's fail-closed merge, through
//!   `heimdall_domain::connection::effective_connection_policy`, of the policy recorded
//!   in the grant's origin, every current applicable standing policy and the request
//!   (already folded into the origin at creation; U0b row 10). A grant with no origin,
//!   or a store failure, is [`FAIL_CLOSED_POLICY`] (`strict`, `disabled`).
//! * [`ConnectionSupervisor::connection_deadline_pass`] (at each admission deadline or
//!   cutoff), [`ConnectionSupervisor::revocation_close`] and
//!   [`ConnectionSupervisor::release_close`] (D7 item 2 step 4: called **after** the
//!   gates are released), [`ConnectionSupervisor::time_uncertain_close`]: each closes
//!   what `heimdall_domain::connection::closes` says for the event: masters always,
//!   dedicated connections by the D8 item 2 table (`graceful` keeps them at the
//!   deadline, a cutoff, release and `TIME_UNCERTAIN`; revocation closes them under both
//!   policies).
//! * [`ConnectionSupervisor::connection_restart_pass`] (first at start): closes the
//!   owned masters of grants that ended while the runtime was down, identified by their
//!   persisted PID, start token and control path; a master of a still-valid grant is
//!   kept; one whose identity does not verify is left alone and reported unverified
//!   (unmanaged).
//!
//! **Owned masters** (D8 item 3; reading R4). `ssh` runs as a **foreground child**
//! (never `-f`) with `OWNED_LAUNCH_PINS[0..2]` (`-o ForkAfterAuthentication=no`), then
//! `-M -N -o ControlMaster=yes -o ControlPersist=no -o ControlPath=<slot path>`, the
//! R3 identity options for the **binding's** endpoint and certificate
//! (`heimdall_sshconf::render::managed_identity_options`), `-o ClearAllForwardings=yes
//! -o ExitOnForwardFailure=yes -o BatchMode=yes`, then `-- <alias>`
//! ([`master_argv`]). The slot path is `<runtime_dir>/mux/<destination-id>`
//! (`heimdall_localenv::projection::content::checked_mux_path`, refused
//! `mux_path_too_long`). A started master is recorded as a `ManagedResource` (`process`,
//! owned by the binding; its locator is the JSON [`MasterLocator`]) and an
//! `owned_connections` row (kind `master`; PID, start token, control path,
//! generation). Each master is one generation of its slot path: before master N+1
//! starts, master N is closed and its socket removed only if it is still N's inode; a
//! socket nobody verifiably owns refuses the start (`mux_path_occupied`), so clients
//! connect directly. A failed start is retried, bounded
//! ([`ConnectionConfig::start_backoff`]) and jittered ([`ConnectionConfig::jitter`]);
//! no master is needed for correctness. Windows refuses `owned_masters`:
//! `CAPABILITY_UNAVAILABLE`, `multiplexing_unsupported` (M-F7).
//!
//! **Closing** (D8 item 2 "Closing", item 3). A master: `ssh -O exit -o ControlPath=<path>
//! <alias>` bounded by [`ConnectionConfig::close_grace`], then, if it still runs,
//! SIGTERM and SIGKILL after the grace to the **verified** PID, then removal of the
//! socket only if it is still the same inode. A dedicated connection: the verified PID
//! is signalled the same way (Windows: `TerminateProcess` on the verified handle).
//! Verification ([`heimdall_localenv::sys::ProcessPin`]; reading R8): the process is
//! pinned first (Linux pidfd, Windows handle, macOS PID), then its start token is read
//! from the source that wrote it (Unix
//! [`crate::platform::process_start_time`]; Windows the creation time read on the
//! handle, as `Operations::register_owned_connection` stored it) and compared, then the
//! image. A start token that differs (the PID now names another process) is
//! `unverified` and never signalled. A matching token with another image (Unix: the
//! launcher, `heimdall`, before its `exec` or after a failed one) is not signalled
//! either and stays `closing`: the next pass checks it again ([`CloseOutcome::Pending`]).
//! Nothing is ever signalled by name or pattern.
//!
//! **Registration** (Windows; D8 item 2 step 2; U0b row 26): `register` verifies, on a
//! handle it holds for the whole call, that the PID's creation time is `created_at` and
//! its image the verified client, then calls `Operations::register_owned_connection`
//! (the gate and the grant re-check are the application's). Every refusal is
//! `ConnError::RegistrationRefused` with a fixed word ([`refusal`]).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use heimdall_app::Operations;
use heimdall_app::ports::{ConnError, ConnectionControl};
use heimdall_app::reconcile::Backoff;
use heimdall_contract::Timestamp;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{BindingId, ConnectionId, GrantId, ResourceId};
use heimdall_contract::managed::CloseReason;
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_domain::connection::{
    ConnectionEnd, ConnectionKind, ConnectionPolicy, ExistingConnectionsMode, MultiplexingMode,
    closes, effective_connection_policy,
};
use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_domain::scope::AccessPair;
use heimdall_localenv::env::Platform;
use heimdall_localenv::sys::{ProcessPin, ProcessSignal, VerifiedProcess};
use heimdall_store::{RawDocuments, Store, Txn};
use serde::{Deserialize, Serialize};

use crate::supervisor::{Jitter, retry_delay};

/// The bound of `ssh -O exit` and the grace between SIGTERM and SIGKILL (D8 item 3).
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// How long a starting master may take to bind its control socket.
pub const MASTER_READY_WAIT: Duration = Duration::from_secs(15);
/// The bounded, jittered retries of a master start (D8 item 3 "Failure to start").
pub const MASTER_START_BACKOFF: Backoff = Backoff {
    base: Duration::from_millis(500),
    max: Duration::from_secs(5),
    max_attempts: 3,
};
/// The policy of a grant whose policy inputs cannot be read: the strictest (D8 item 1,
/// fail closed).
pub const FAIL_CLOSED_POLICY: ConnectionPolicy = ConnectionPolicy {
    existing: ExistingConnectionsMode::Strict,
    multiplexing: MultiplexingMode::Disabled,
};
/// How often a close polls for the process's exit.
const EXIT_POLL: Duration = Duration::from_millis(25);

/// Fixed nonsecret words carried by [`ConnError`] (never a path, PID or argv).
pub mod refusal {
    /// The effective policy does not enable owned masters (D8 item 1: a widening
    /// needs a decision and `setup apply`).
    pub const MASTERS_DISABLED: &str = "owned_masters_disabled";
    /// The binding is unknown, released, or not active.
    pub const BINDING_UNKNOWN: &str = "binding_unknown";
    /// The grant has ended.
    pub const GRANT_ENDED: &str = "grant_ended";
    /// The pair's destination is not in the catalog.
    pub const DESTINATION_UNKNOWN: &str = "destination_unknown";
    /// The binding's endpoint or files are not known here.
    pub const ENDPOINT_UNAVAILABLE: &str = "binding_endpoint_unavailable";
    /// A socket nobody verifiably owns is at the slot's mux path.
    pub const MUX_PATH_OCCUPIED: &str = "mux_path_occupied";
    /// A path cannot be written on an ssh command line.
    pub const PATH_REFUSED: &str = "path_refused";
    /// Every bounded start attempt failed.
    pub const MASTER_START_FAILED: &str = "master_start_failed";
    /// The previous master of the slot could not be closed.
    pub const PREVIOUS_MASTER_OPEN: &str = "previous_master_open";
    /// Registration exists on Windows only (U0b row 26).
    pub const WINDOWS_ONLY: &str = "registration_windows_only";
    /// The registered image is not the verified client.
    pub const IMAGE_NOT_VERIFIED_CLIENT: &str = "image_not_verified_client";
    /// The process's creation time is not the one given.
    pub const CREATION_TIME_MISMATCH: &str = "creation_time_mismatch";
    /// No process has the PID.
    pub const PROCESS_GONE: &str = "process_gone";
    /// The process could not be opened.
    pub const PROCESS_UNREADABLE: &str = "process_unreadable";
    /// This supervisor was built without `Operations`.
    pub const OPERATIONS_UNAVAILABLE: &str = "operations_unavailable";
    /// A Unix connection's process still runs another image (exec not done).
    pub const EXEC_PENDING: &str = "exec_pending";
    /// The store could not be read or written.
    pub const STORE: &str = "store";
}

/// The binding endpoint a master authenticates through (U10 implements it over the
/// signer's endpoint table; tests over a fixture). `None`: not known, so no master.
pub trait BindingEndpoints: Send + Sync {
    /// The endpoint of `binding`.
    fn endpoint(&self, binding: &BindingId) -> Option<EndpointRef>;
}

/// What the supervisor needs besides the store (all injected, so tests drive it
/// without U10).
#[derive(Clone)]
pub struct ConnectionConfig {
    /// The runtime directory (`<runtime_dir>/mux/…`, `<runtime_dir>/b/…`).
    pub runtime_dir: PathBuf,
    /// The verified `ssh` client of the client inventory (the expected image).
    pub verified_ssh: PathBuf,
    /// The platform (Windows refuses `owned_masters`).
    pub platform: Platform,
    /// The binding-endpoint lookup.
    pub endpoints: Arc<dyn BindingEndpoints>,
    /// The jitter of start retries.
    pub jitter: Arc<dyn Jitter>,
    /// The start retries.
    pub start_backoff: Backoff,
    /// `-O exit` bound and TERM → KILL grace.
    pub close_grace: Duration,
    /// How long a master may take to bind its socket.
    pub ready_wait: Duration,
    /// Arguments placed before `--` on every `ssh` this supervisor runs (the master and
    /// `-O exit`). Empty in production; tests pass the client isolation arguments
    /// (`-F <scratch config>`, the scratch known-hosts files, `BatchMode`; m03-plan
    /// §0.2).
    pub client_args: Vec<OsString>,
    /// `Some`: the `ssh` children get exactly this environment (tests: a scratch
    /// `HOME`); `None`: the runtime's own.
    pub client_env: Option<Vec<(OsString, OsString)>>,
}

impl ConnectionConfig {
    /// The production defaults around the four injected values.
    #[must_use]
    pub fn new(
        runtime_dir: PathBuf,
        verified_ssh: PathBuf,
        endpoints: Arc<dyn BindingEndpoints>,
        jitter: Arc<dyn Jitter>,
    ) -> Self {
        Self {
            runtime_dir,
            verified_ssh,
            platform: Platform::current(),
            endpoints,
            jitter,
            start_backoff: MASTER_START_BACKOFF,
            close_grace: CLOSE_GRACE,
            ready_wait: MASTER_READY_WAIT,
            client_args: Vec::new(),
            client_env: None,
        }
    }
}

/// A master's resource locator (JSON; nonsecret): what a later process needs to close
/// it by its persisted identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterLocator {
    /// The connection.
    pub connection: ConnectionId,
    /// PID.
    pub pid: u32,
    /// Start token (platform.rs).
    pub start_token: String,
    /// The slot's mux path.
    pub control_path: String,
    /// The alias `-O exit` names.
    pub alias: String,
    /// The socket's `(device, inode)` once bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode: Option<(u64, u64)>,
}

/// One close's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseOutcome {
    /// Gone: it exited, was closed, or was already closed.
    Closed,
    /// Its identity did not verify: never signalled, reported unmanaged.
    Unverified,
    /// Unix: the start token matches but the image is not yet the client (exec
    /// pending): not signalled, `closing`, checked again by the next pass.
    Pending,
    /// The close failed (bounded nonsecret text); the row stays `closing`.
    Failed(String),
}

/// What a pass did, by connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Closed.
    pub closed: Vec<ConnectionId>,
    /// Not verified (never signalled).
    pub unverified: Vec<ConnectionId>,
    /// Exec pending (Unix), retried by the next pass.
    pub pending: Vec<ConnectionId>,
    /// Kept by the policy (or a master of a still-valid grant at restart).
    pub kept: Vec<ConnectionId>,
    /// Failed closes.
    pub failed: Vec<(ConnectionId, String)>,
}

impl PassReport {
    fn record(&mut self, id: ConnectionId, outcome: CloseOutcome) {
        match outcome {
            CloseOutcome::Closed => self.closed.push(id),
            CloseOutcome::Unverified => self.unverified.push(id),
            CloseOutcome::Pending => self.pending.push(id),
            CloseOutcome::Failed(e) => self.failed.push((id, e)),
        }
    }
}

/// A master this process started. Its `Child` is a std child: a supervisor that is
/// dropped (the runtime stops) leaves its masters running, recorded, for the next
/// runtime's restart pass (D8 item 3 "Restart").
struct LiveMaster {
    connection: OwnedConnection,
    locator: MasterLocator,
    child: std::process::Child,
}

/// A master child while it is being started: killed and reaped if the start is
/// dropped or fails (the drop contract: a dropped `start_master` leaves no master).
struct Starting(Option<std::process::Child>);

impl Starting {
    fn pid(&self) -> Option<u32> {
        self.0.as_ref().map(std::process::Child::id)
    }

    fn exited(&mut self) -> bool {
        self.0
            .as_mut()
            .is_none_or(|c| !matches!(c.try_wait(), Ok(None)))
    }

    fn keep(mut self) -> Option<std::process::Child> {
        self.0.take()
    }
}

impl Drop for Starting {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            // Our own child, by its handle: never a lookup.
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Owned masters and owned dedicated connections (module docs).
pub struct ConnectionSupervisor {
    store: Arc<Store>,
    ops: Option<Operations>,
    config: ConnectionConfig,
    /// Masters started by this process, by control path.
    live: tokio::sync::Mutex<BTreeMap<PathBuf, LiveMaster>>,
    /// Master spawn attempts (observability for the bounded-retry test).
    start_attempts: AtomicU64,
}

impl std::fmt::Debug for ConnectionSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionSupervisor")
            .finish_non_exhaustive()
    }
}

fn unavailable(word: &str) -> ConnError {
    ConnError::Unavailable(word.to_owned())
}

fn refused(word: &str) -> ConnError {
    ConnError::RegistrationRefused(word.to_owned())
}

/// Run `f` in one store transaction on the blocking pool.
async fn txn<R, F>(store: &Arc<Store>, f: F) -> Result<R, ConnError>
where
    R: Send + 'static,
    F: FnOnce(&mut Txn<'_>) -> heimdall_store::Result<R> + Send + 'static,
{
    let store = Arc::clone(store);
    match tokio::task::spawn_blocking(move || store.transaction(f)).await {
        Ok(Ok(r)) => Ok(r),
        _ => Err(unavailable(refusal::STORE)),
    }
}

/// D8 item 1 in a transaction: the strictest of the grant's origin, every current
/// applicable policy of its profile in its environment, and `request`. No grant or no
/// origin: [`FAIL_CLOSED_POLICY`].
pub fn effective_policy_in(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    request: Option<&heimdall_contract::managed::ConnectionRequest>,
) -> heimdall_store::Result<ConnectionPolicy> {
    let (Some(g), Some(origin)) = (tx.grant(grant)?, tx.grant_origin(grant)?) else {
        return Ok(FAIL_CLOSED_POLICY);
    };
    let current: Vec<ConnectionPolicy> = tx
        .policies_for(&origin.profile, &g.environment)?
        .iter()
        .map(|p| p.connection)
        .collect();
    Ok(effective_connection_policy(
        origin.connection,
        &current,
        request,
    ))
}

/// A path as one `-o Keyword=<value>` value: `"…"` with `%` as `%%` (as P writes it);
/// a path with `"`, a control character or no UTF-8 form is refused.
fn quoted_path(path: &Path) -> Result<String, ConnError> {
    let text = path
        .to_str()
        .filter(|t| !t.contains('"') && !t.chars().any(char::is_control))
        .ok_or_else(|| unavailable(refusal::PATH_REFUSED))?;
    Ok(format!("\"{}\"", text.replace('%', "%%")))
}

fn safe_alias(alias: &str) -> Result<&str, ConnError> {
    if alias.is_empty()
        || alias.starts_with('-')
        || alias.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(unavailable(refusal::DESTINATION_UNKNOWN));
    }
    Ok(alias)
}

/// The owned master's argument vector after the program name (reading R4; module docs).
/// `key_pub` and `cert` are the binding's files (U6's `binding_files_for_endpoint`);
/// only the certificate is named as the identity (R3). `client_args` go right before
/// `--` ([`ConnectionConfig::client_args`]).
///
/// # Errors
/// [`ConnError::Unavailable`] (`path_refused`) for a path or endpoint that cannot be
/// rendered, or an unsafe alias.
pub fn master_argv(
    control_path: &Path,
    alias: &str,
    endpoint: &EndpointRef,
    key_pub: &Path,
    cert: &Path,
    client_args: &[OsString],
) -> Result<Vec<OsString>, ConnError> {
    use heimdall_sshconf::render::{
        ManagedIdentityForm, OWNED_LAUNCH_PINS, PathStyle, RenderPath, managed_identity_options,
    };
    let bad = |_| unavailable(refusal::PATH_REFUSED);
    let (style, endpoint, key_pub, cert) = match endpoint.kind {
        EndpointKind::NamedPipe => (
            PathStyle::Windows,
            RenderPath::pipe(&endpoint.locator).map_err(bad)?,
            RenderPath::windows(key_pub).map_err(bad)?,
            RenderPath::windows(cert).map_err(bad)?,
        ),
        _ => (
            PathStyle::Unix,
            RenderPath::unix(Path::new(&endpoint.locator)).map_err(bad)?,
            RenderPath::unix(key_pub).map_err(bad)?,
            RenderPath::unix(cert).map_err(bad)?,
        ),
    };
    let identity = managed_identity_options(
        &endpoint,
        &key_pub,
        &cert,
        style,
        ManagedIdentityForm::select(None),
    )
    .map_err(bad)?;
    let mut out: Vec<OsString> = OWNED_LAUNCH_PINS[0..2].iter().map(OsString::from).collect();
    for a in [
        "-M",
        "-N",
        "-o",
        "ControlMaster=yes",
        "-o",
        "ControlPersist=no",
        "-o",
    ] {
        out.push(a.into());
    }
    out.push(format!("ControlPath={}", quoted_path(control_path)?).into());
    out.extend(identity.into_iter().map(OsString::from));
    for a in [
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "BatchMode=yes",
    ] {
        out.push(a.into());
    }
    out.extend(client_args.iter().cloned());
    out.push("--".into());
    out.push(safe_alias(alias)?.into());
    Ok(out)
}

/// `ssh -O exit -o ControlPath=<path> [client args] -- <alias>` (D8 item 3).
///
/// # Errors
/// As [`master_argv`].
pub fn exit_argv(
    control_path: &Path,
    alias: &str,
    client_args: &[OsString],
) -> Result<Vec<OsString>, ConnError> {
    let mut out: Vec<OsString> = vec![
        "-O".into(),
        "exit".into(),
        "-o".into(),
        format!("ControlPath={}", quoted_path(control_path)?).into(),
    ];
    out.extend(client_args.iter().cloned());
    out.push("--".into());
    out.push(safe_alias(alias)?.into());
    Ok(out)
}

/// The `(device, inode)` of a socket at `path`, or `None` (absent, or not a socket).
#[must_use]
pub fn socket_inode(path: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let m = std::fs::symlink_metadata(path).ok()?;
        m.file_type().is_socket().then(|| (m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Remove the socket at `path` only if it is still `inode` (D8 item 3). Returns whether
/// it was removed.
#[must_use]
pub fn remove_socket_if_same_inode(path: &Path, inode: Option<(u64, u64)>) -> bool {
    match (inode, socket_inode(path)) {
        (Some(want), Some(now)) if want == now => std::fs::remove_file(path).is_ok(),
        _ => false,
    }
}

/// The start token of the pinned process, from the source that wrote the row (R8).
fn current_token(pin: &ProcessPin) -> Option<String> {
    #[cfg(windows)]
    {
        pin.created_at().map(|t| t.to_string())
    }
    #[cfg(not(windows))]
    {
        crate::platform::process_start_time(pin.pid())
    }
}

/// Whether `pid` still is the process `token` names.
fn still_running(pid: u32, token: &str) -> bool {
    match ProcessPin::open(pid) {
        Ok(Some(pin)) => current_token(&pin).as_deref() == Some(token),
        Ok(None) => false,
        // Cannot be opened: it may run; treat as running (a close then fails, never a
        // false "closed").
        Err(_) => true,
    }
}

/// The verification of `(pid, token, image)` (module docs).
enum Verified {
    Process(VerifiedProcess),
    Gone,
    Unverified,
    Pending,
}

fn verify(pid: u32, token: &str, image: &Path) -> Verified {
    let pin = match ProcessPin::open(pid) {
        Ok(Some(pin)) => pin,
        Ok(None) => return Verified::Gone,
        Err(_) => return Verified::Unverified,
    };
    match current_token(&pin) {
        None => Verified::Gone,
        Some(t) if t != token => Verified::Unverified,
        Some(_) => match pin.verify(true, image) {
            Some(v) => Verified::Process(v),
            None => Verified::Pending,
        },
    }
}

async fn wait_gone(pid: u32, token: &str, bound: Duration) -> bool {
    let end = Instant::now() + bound;
    loop {
        if !still_running(pid, token) {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(EXIT_POLL).await;
    }
}

/// SIGTERM, then SIGKILL after `grace`, to the verified `(pid, token, image)`.
async fn terminate_verified(pid: u32, token: &str, image: &Path, grace: Duration) -> CloseOutcome {
    let process = match verify(pid, token, image) {
        Verified::Process(p) => p,
        Verified::Gone => return CloseOutcome::Closed,
        Verified::Unverified => return CloseOutcome::Unverified,
        Verified::Pending => return CloseOutcome::Pending,
    };
    if let Err(e) = process.signal(ProcessSignal::Terminate) {
        return CloseOutcome::Failed(e.call.to_owned());
    }
    if wait_gone(pid, token, grace).await {
        return CloseOutcome::Closed;
    }
    // Still the verified process (the pin holds it on Linux and Windows). macOS pins
    // nothing, so the identity is re-verified right before the second signal, which
    // keeps the disclosed reuse window to one check-then-signal (D8 item 2 "Closing").
    #[cfg(all(unix, not(target_os = "linux")))]
    let process = match verify(pid, token, image) {
        Verified::Process(p) => p,
        Verified::Gone => return CloseOutcome::Closed,
        Verified::Unverified => return CloseOutcome::Unverified,
        Verified::Pending => return CloseOutcome::Pending,
    };
    if let Err(e) = process.signal(ProcessSignal::Kill) {
        return CloseOutcome::Failed(e.call.to_owned());
    }
    if wait_gone(pid, token, grace).await {
        CloseOutcome::Closed
    } else {
        CloseOutcome::Failed("still_running_after_kill".to_owned())
    }
}

fn resource_id(connection: &ConnectionId) -> ResourceId {
    let suffix = connection
        .as_str()
        .split_once('_')
        .map_or(connection.as_str(), |(_, s)| s);
    ResourceId::parse(&format!("{}_{suffix}", ResourceId::PREFIX))
        .unwrap_or_else(|_| ResourceId::from_random_bytes([0; 16]))
}

fn new_connection_id() -> Result<ConnectionId, ConnError> {
    let a = heimdall_app::ids::random_u64().map_err(|_| unavailable("randomness"))?;
    let b = heimdall_app::ids::random_u64().map_err(|_| unavailable("randomness"))?;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..].copy_from_slice(&b.to_le_bytes());
    Ok(ConnectionId::from_random_bytes(bytes))
}

/// Every master resource (`process`, owned by a binding, with a [`MasterLocator`]).
fn master_resources(
    tx: &mut Txn<'_>,
) -> heimdall_store::Result<Vec<(ManagedResource, MasterLocator)>> {
    let mut out = Vec::new();
    for (_, json) in tx.raw_documents(RawDocuments::Resources)? {
        let Ok(r) = serde_json::from_str::<ManagedResource>(&json) else {
            continue;
        };
        if r.kind != ResourceKind::Process || !matches!(r.owner, OwnerRef::Binding { .. }) {
            continue;
        }
        if let Ok(l) = serde_json::from_str::<MasterLocator>(&r.locator) {
            out.push((r, l));
        }
    }
    Ok(out)
}

/// Every owned connection that is not `closed` or `unverified`: the rows of the
/// bindings with a recorded holder (dedicated rows exist only for launch bindings) and
/// of the bindings owning a master resource.
fn open_rows(tx: &mut Txn<'_>) -> heimdall_store::Result<Vec<OwnedConnection>> {
    let mut bindings: BTreeSet<BindingId> =
        tx.binding_holders()?.into_iter().map(|(b, _)| b).collect();
    for (r, _) in master_resources(tx)? {
        if let OwnerRef::Binding { id } = r.owner {
            bindings.insert(id);
        }
    }
    let mut out = Vec::new();
    for b in bindings {
        out.extend(
            tx.owned_connections_for_binding(&b)?
                .into_iter()
                .filter(|c| {
                    matches!(
                        c.state,
                        OwnedConnectionState::Up | OwnedConnectionState::Closing
                    )
                }),
        );
    }
    Ok(out)
}

fn move_row(
    tx: &mut Txn<'_>,
    c: &OwnedConnection,
    to: OwnedConnectionState,
) -> heimdall_store::Result<()> {
    match tx.owned_connection(&c.id)? {
        Some(stored) if stored.state == to || stored.state == OwnedConnectionState::Closed => {
            Ok(())
        }
        Some(_) => tx
            .close_owned_connection(&c.id, c.generation, to)
            .map(|_| ()),
        None => Ok(()),
    }
}

fn resource_absent(
    tx: &mut Txn<'_>,
    c: &OwnedConnection,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    let id = resource_id(&c.id);
    if let Some(mut r) = tx.resource(&id)? {
        let expected = r.generation;
        r.desired = ResourceState::Absent;
        r.observed = ResourceState::Absent;
        r.updated_at = now;
        tx.upsert_resource(&r, Some(expected))?;
    }
    Ok(())
}

/// What `start_master` reads in one transaction.
struct MasterContext {
    alias: String,
    policy: ConnectionPolicy,
}

impl ConnectionSupervisor {
    /// Build. `ops` is needed only by [`ConnectionControl::register`] (Windows).
    #[must_use]
    pub fn new(store: Arc<Store>, ops: Option<Operations>, config: ConnectionConfig) -> Self {
        Self {
            store,
            ops,
            config,
            live: tokio::sync::Mutex::new(BTreeMap::new()),
            start_attempts: AtomicU64::new(0),
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// Master spawn attempts made so far (each retry counts).
    #[must_use]
    pub fn master_start_attempts(&self) -> u64 {
        self.start_attempts.load(Ordering::SeqCst)
    }

    /// D8 item 1: the grant's effective connection policy (module docs).
    pub async fn effective_policy(&self, grant: &GrantId) -> ConnectionPolicy {
        let g = grant.clone();
        txn(&self.store, move |tx| effective_policy_in(tx, &g, None))
            .await
            .unwrap_or(FAIL_CLOSED_POLICY)
    }

    /// The PIDs of the masters this process started and still holds (tests count and
    /// stop exactly these).
    pub async fn live_master_pids(&self) -> Vec<u32> {
        self.live
            .lock()
            .await
            .values()
            .map(|m| m.connection.pid)
            .collect()
    }

    fn ssh_command(&self, args: &[OsString]) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.config.verified_ssh);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(env) = &self.config.client_env {
            cmd.env_clear();
            for (k, v) in env {
                cmd.env(k, v);
            }
        }
        cmd
    }

    // --- start ------------------------------------------------------------------------

    async fn start_master_impl(
        &self,
        binding: &BindingId,
        pair: &AccessPair,
    ) -> Result<OwnedConnection, ConnError> {
        if self.config.platform == Platform::Windows {
            return Err(unavailable(reason::MULTIPLEXING_UNSUPPORTED));
        }
        let (b, dest) = (binding.clone(), pair.destination.clone());
        let ctx = txn(&self.store, move |tx| {
            let Some(rec) = tx.binding(&b)? else {
                return Ok(Err(refusal::BINDING_UNKNOWN));
            };
            if rec.released_at.is_some() {
                return Ok(Err(refusal::BINDING_UNKNOWN));
            }
            match tx.grant(&rec.grant)? {
                Some(g) if g.state.permits_use() => {}
                _ => return Ok(Err(refusal::GRANT_ENDED)),
            }
            let Some(d) = tx.destination(&dest)? else {
                return Ok(Err(refusal::DESTINATION_UNKNOWN));
            };
            let policy = effective_policy_in(tx, &rec.grant, None)?;
            Ok(Ok(MasterContext {
                alias: d.alias,
                policy,
            }))
        })
        .await?
        .map_err(unavailable)?;
        if ctx.policy.multiplexing != MultiplexingMode::OwnedMasters {
            return Err(unavailable(refusal::MASTERS_DISABLED));
        }
        let path = heimdall_localenv::projection::content::checked_mux_path(
            &self.config.runtime_dir,
            &pair.destination,
        )
        .map_err(unavailable)?;
        let endpoint = self
            .config
            .endpoints
            .endpoint(binding)
            .ok_or_else(|| unavailable(refusal::ENDPOINT_UNAVAILABLE))?;
        let files = heimdall_adapters::managed::files::binding_files_for_endpoint(
            &self.config.runtime_dir,
            &endpoint,
            std::slice::from_ref(&pair.destination),
        )
        .ok_or_else(|| unavailable(refusal::ENDPOINT_UNAVAILABLE))?;
        let cert = files
            .certificate(&pair.destination)
            .ok_or_else(|| unavailable(refusal::ENDPOINT_UNAVAILABLE))?
            .to_path_buf();
        let argv = master_argv(
            &path,
            &ctx.alias,
            &endpoint,
            &files.key_pub,
            &cert,
            &self.config.client_args,
        )?;
        // Generation protection: the previous master of this path first.
        let generation = self.replace_previous(&path).await?;
        if path.exists() {
            return Err(unavailable(refusal::MUX_PATH_OCCUPIED));
        }
        if let Some(parent) = path.parent() {
            create_private_dir(parent).map_err(|_| unavailable(refusal::PATH_REFUSED))?;
        }
        let (child, inode) = self.spawn_ready(&argv, &path).await?;
        self.record_master(binding, child, inode, &path, ctx.alias, generation)
            .await
    }

    /// Spawn the master with bounded, jittered retries until its socket is bound.
    async fn spawn_ready(
        &self,
        argv: &[OsString],
        path: &Path,
    ) -> Result<(Starting, (u64, u64)), ConnError> {
        let attempts = self.config.start_backoff.max_attempts.max(1);
        for attempt in 1..=attempts {
            self.start_attempts.fetch_add(1, Ordering::SeqCst);
            if let Some(ready) = self.spawn_once(argv, path).await {
                return Ok(ready);
            }
            if attempt < attempts {
                tokio::time::sleep(retry_delay(
                    &self.config.start_backoff,
                    attempt,
                    self.config.jitter.as_ref(),
                ))
                .await;
            }
        }
        Err(ConnError::Failed(refusal::MASTER_START_FAILED.to_owned()))
    }

    async fn spawn_once(&self, argv: &[OsString], path: &Path) -> Option<(Starting, (u64, u64))> {
        let mut child = Starting(Some(self.ssh_command(argv).spawn().ok()?));
        let end = Instant::now() + self.config.ready_wait;
        loop {
            if let Some(inode) = socket_inode(path) {
                return Some((child, inode));
            }
            if child.exited() || Instant::now() >= end {
                // Dropping `child` kills (a no-op once exited) and reaps it.
                return None;
            }
            tokio::time::sleep(EXIT_POLL).await;
        }
    }

    async fn record_master(
        &self,
        binding: &BindingId,
        child: Starting,
        inode: (u64, u64),
        path: &Path,
        alias: String,
        generation: u64,
    ) -> Result<OwnedConnection, ConnError> {
        let pid = child.pid();
        let token = pid.and_then(crate::platform::process_start_time);
        let (Some(pid), Some(token)) = (pid, token) else {
            drop(child);
            let _ = remove_socket_if_same_inode(path, Some(inode));
            return Err(ConnError::Failed(refusal::MASTER_START_FAILED.to_owned()));
        };
        let id = new_connection_id()?;
        let locator = MasterLocator {
            connection: id.clone(),
            pid,
            start_token: token.clone(),
            control_path: path.to_string_lossy().into_owned(),
            alias,
            inode: Some(inode),
        };
        let locator_json =
            serde_json::to_string(&locator).map_err(|_| unavailable(refusal::STORE))?;
        let image = self.config.verified_ssh.to_string_lossy().into_owned();
        let b = binding.clone();
        let control_path = locator.control_path.clone();
        let now = Timestamp::now();
        let row = txn(&self.store, move |tx| {
            // Re-checked after the spawn: a narrowing that committed meanwhile wins.
            let Some(rec) = tx.binding(&b)? else {
                return Ok(None);
            };
            match tx.grant(&rec.grant)? {
                Some(g) if g.state.permits_use() && rec.released_at.is_none() => {}
                _ => return Ok(None),
            }
            let connection = OwnedConnection {
                id: id.clone(),
                kind: ConnectionKind::Master,
                binding: b.clone(),
                grant: rec.grant.clone(),
                pid,
                start_token: token,
                image,
                control_path: Some(control_path),
                generation,
                state: OwnedConnectionState::Up,
                started_at: now,
            };
            tx.insert_owned_connection(&connection)?;
            tx.upsert_resource(
                &ManagedResource {
                    id: resource_id(&id),
                    kind: ResourceKind::Process,
                    owner: OwnerRef::Binding { id: b },
                    generation: ResourceGeneration(generation),
                    desired: ResourceState::Present,
                    observed: ResourceState::Present,
                    last_operation: None,
                    locator: locator_json,
                    updated_at: now,
                },
                None,
            )?;
            Ok(Some(connection))
        })
        .await;
        match row {
            Ok(Some(connection)) => {
                let Some(child) = child.keep() else {
                    return Err(ConnError::Failed(refusal::MASTER_START_FAILED.to_owned()));
                };
                self.live.lock().await.insert(
                    path.to_path_buf(),
                    LiveMaster {
                        connection: connection.clone(),
                        locator,
                        child,
                    },
                );
                Ok(connection)
            }
            other => {
                drop(child);
                let _ = remove_socket_if_same_inode(path, Some(inode));
                Err(other
                    .err()
                    .unwrap_or_else(|| unavailable(refusal::GRANT_ENDED)))
            }
        }
    }

    /// Close every earlier master of `path` (live here or persisted) and return the
    /// next generation. A stale socket is removed only if it is the inode a closed
    /// generation recorded.
    async fn replace_previous(&self, path: &Path) -> Result<u64, ConnError> {
        let live = self
            .live
            .lock()
            .await
            .get(path)
            .map(|m| m.connection.clone());
        if let Some(c) = live
            && self.close_one(&c).await != CloseOutcome::Closed
        {
            return Err(unavailable(refusal::PREVIOUS_MASTER_OPEN));
        }
        let wanted = path.to_string_lossy().into_owned();
        let persisted = txn(&self.store, move |tx| {
            let mut rows = Vec::new();
            let mut max = 0u64;
            for (r, l) in master_resources(tx)? {
                if l.control_path != wanted {
                    continue;
                }
                max = max.max(r.generation.0);
                if let Some(c) = tx.owned_connection(&l.connection)? {
                    rows.push((c, l));
                }
            }
            Ok((rows, max))
        })
        .await?;
        let (rows, max) = persisted;
        for (c, l) in rows {
            if matches!(
                c.state,
                OwnedConnectionState::Up | OwnedConnectionState::Closing
            ) && self.close_one(&c).await != CloseOutcome::Closed
            {
                return Err(unavailable(refusal::PREVIOUS_MASTER_OPEN));
            }
            let _ = remove_socket_if_same_inode(path, l.inode);
        }
        Ok(max.saturating_add(1))
    }

    // --- close ------------------------------------------------------------------------

    /// Close one owned connection (module docs) and record the result.
    pub async fn close_one(&self, c: &OwnedConnection) -> CloseOutcome {
        let outcome = match c.kind {
            ConnectionKind::Master => self.close_master(c).await,
            // A dedicated connection, or a kind this build does not know: the verified
            // process only (fail closed: never a broader action).
            _ => {
                if txn_move(&self.store, c, OwnedConnectionState::Closing)
                    .await
                    .is_err()
                {
                    return CloseOutcome::Failed(refusal::STORE.to_owned());
                }
                terminate_verified(
                    c.pid,
                    &c.start_token,
                    Path::new(&c.image),
                    self.config.close_grace,
                )
                .await
            }
        };
        let to = match &outcome {
            CloseOutcome::Closed => Some(OwnedConnectionState::Closed),
            CloseOutcome::Unverified => Some(OwnedConnectionState::Unverified),
            CloseOutcome::Pending | CloseOutcome::Failed(_) => None,
        };
        if let Some(to) = to {
            let row = c.clone();
            let now = Timestamp::now();
            if txn(&self.store, move |tx| {
                move_row(tx, &row, to)?;
                resource_absent(tx, &row, now)
            })
            .await
            .is_err()
            {
                return CloseOutcome::Failed(refusal::STORE.to_owned());
            }
        }
        outcome
    }

    async fn close_master(&self, c: &OwnedConnection) -> CloseOutcome {
        let Some(path) = c.control_path.as_deref().map(PathBuf::from) else {
            return CloseOutcome::Unverified;
        };
        if txn_move(&self.store, c, OwnedConnectionState::Closing)
            .await
            .is_err()
        {
            return CloseOutcome::Failed(refusal::STORE.to_owned());
        }
        let live = {
            let mut map = self.live.lock().await;
            match map.get(&path) {
                Some(m) if m.connection.id == c.id => map.remove(&path),
                _ => None,
            }
        };
        let locator = match &live {
            Some(m) => Some(m.locator.clone()),
            None => {
                let id = resource_id(&c.id);
                txn(&self.store, move |tx| tx.resource(&id))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|r| serde_json::from_str::<MasterLocator>(&r.locator).ok())
            }
        };
        let grace = self.config.close_grace;
        // 1. `-O exit`, bounded.
        if let Some(l) = &locator
            && still_running(c.pid, &c.start_token)
            && let Ok(args) = exit_argv(&path, &l.alias, &self.config.client_args)
            && let Ok(mut child) = tokio::process::Command::from(self.ssh_command(&args))
                .kill_on_drop(true)
                .spawn()
            && tokio::time::timeout(grace, child.wait()).await.is_err()
        {
            let _ = child.kill().await;
        }
        // 2. Then the verified PID, if it still runs.
        let outcome = if wait_gone(c.pid, &c.start_token, grace).await {
            CloseOutcome::Closed
        } else {
            terminate_verified(c.pid, &c.start_token, Path::new(&c.image), grace).await
        };
        if let Some(mut m) = live {
            if outcome == CloseOutcome::Closed {
                // Gone (verified above): the reap returns at once.
                let _ = m.child.wait();
            } else {
                // Keep holding our child: it stays ours to close.
                self.live.lock().await.insert(path.clone(), m);
            }
        }
        // 3. The socket, only if it is still this generation's inode.
        if outcome == CloseOutcome::Closed {
            let _ = remove_socket_if_same_inode(&path, locator.and_then(|l| l.inode));
        }
        outcome
    }

    /// Close the rows of `grants` that `event` closes; keep the others.
    pub async fn close_for(&self, grants: &[GrantId], event: ConnectionEnd) -> PassReport {
        let mut report = PassReport::default();
        for g in grants {
            let grant = g.clone();
            let found = txn(&self.store, move |tx| {
                let policy = effective_policy_in(tx, &grant, None)?;
                let rows: Vec<OwnedConnection> = tx
                    .owned_connections_for_grant(&grant)?
                    .into_iter()
                    .filter(|c| {
                        matches!(
                            c.state,
                            OwnedConnectionState::Up | OwnedConnectionState::Closing
                        )
                    })
                    .collect();
                Ok((policy, rows))
            })
            .await;
            let Ok((policy, rows)) = found else {
                continue;
            };
            for c in rows {
                if closes(c.kind, event, policy.existing) {
                    let outcome = self.close_one(&c).await;
                    report.record(c.id.clone(), outcome);
                } else {
                    report.kept.push(c.id.clone());
                }
            }
        }
        report
    }

    /// At an admission deadline (or a cutoff: `event`), for the grants it ended: masters
    /// always, dedicated connections by the policy (D8 item 2 table).
    pub async fn connection_deadline_pass(&self, ended: &[GrantId]) -> PassReport {
        self.close_for(ended, ConnectionEnd::AdmissionDeadline)
            .await
    }

    /// D7 item 2 step 4, after the gates are released: the cascade's masters and owned
    /// dedicated connections, under both policies.
    pub async fn revocation_close(&self, cascade: &[GrantId]) -> PassReport {
        self.close_for(cascade, ConnectionEnd::Revocation).await
    }

    /// D7 item 7: release of the last reference (masters; dedicated as at the deadline).
    pub async fn release_close(&self, grants: &[GrantId]) -> PassReport {
        self.close_for(grants, ConnectionEnd::Release).await
    }

    /// D7 item 10: `TIME_UNCERTAIN` closes every master and the `strict` dedicated
    /// connections; `graceful` ones are kept.
    pub async fn time_uncertain_close(&self) -> PassReport {
        let grants: Vec<GrantId> = match txn(&self.store, open_rows).await {
            Ok(rows) => rows
                .into_iter()
                .map(|c| c.grant)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            Err(_) => return PassReport::default(),
        };
        self.close_for(&grants, ConnectionEnd::TimeUncertain).await
    }

    /// D8 item 3 "Restart" (module docs): first at start.
    pub async fn connection_restart_pass(&self) -> PassReport {
        let mut report = PassReport::default();
        let found = txn(&self.store, |tx| {
            let mut out = Vec::new();
            for c in open_rows(tx)? {
                if c.kind != ConnectionKind::Master {
                    continue;
                }
                let ended = match (tx.grant(&c.grant)?, tx.binding(&c.binding)?) {
                    (Some(g), Some(b)) => {
                        !g.state.permits_use()
                            || b.released_at.is_some()
                            || tx.denied_ancestor(&c.grant)?.is_some()
                    }
                    _ => true,
                };
                out.push((c, ended));
            }
            Ok(out)
        })
        .await;
        let Ok(rows) = found else {
            return report;
        };
        for (c, ended) in rows {
            if ended {
                let outcome = self.close_one(&c).await;
                report.record(c.id.clone(), outcome);
            } else {
                report.kept.push(c.id.clone());
            }
        }
        report
    }

    /// Masters started here that exited by themselves (reaped, or no longer the process
    /// their start token names: exiting), and Windows dedicated rows whose process is
    /// gone (`Operations`' holder pass clears a Unix row with its holder; a Windows row
    /// names the registered `ssh.exe`, not the holder): rows `closed`, master resources
    /// absent, sockets removed if still the same inode.
    pub async fn reap_pass(&self) -> PassReport {
        let mut report = PassReport::default();
        let exited: Vec<LiveMaster> = {
            let mut map = self.live.lock().await;
            let mut gone: Vec<PathBuf> = Vec::new();
            for (p, m) in map.iter_mut() {
                if matches!(m.child.try_wait(), Ok(Some(_)))
                    || !still_running(m.connection.pid, &m.connection.start_token)
                {
                    gone.push(p.clone());
                }
            }
            gone.into_iter().filter_map(|p| map.remove(&p)).collect()
        };
        for mut m in exited {
            // An exiting process becomes reapable promptly; bounded.
            let end = Instant::now() + self.config.close_grace;
            while matches!(m.child.try_wait(), Ok(None)) && Instant::now() < end {
                tokio::time::sleep(EXIT_POLL).await;
            }
            if matches!(m.child.try_wait(), Ok(None)) {
                // Still running after all: keep it ours.
                self.live
                    .lock()
                    .await
                    .insert(PathBuf::from(&m.locator.control_path), m);
                continue;
            }
            let row = m.connection.clone();
            let now = Timestamp::now();
            let ok = txn(&self.store, move |tx| {
                move_row(tx, &row, OwnedConnectionState::Closed)?;
                resource_absent(tx, &row, now)
            })
            .await
            .is_ok();
            let path = PathBuf::from(&m.locator.control_path);
            let _ = remove_socket_if_same_inode(&path, m.locator.inode);
            if ok {
                report.closed.push(m.connection.id.clone());
            } else {
                report
                    .failed
                    .push((m.connection.id.clone(), refusal::STORE.to_owned()));
            }
        }
        if self.config.platform == Platform::Windows
            && let Ok(rows) = txn(&self.store, open_rows).await
        {
            for c in rows {
                if c.kind == ConnectionKind::Dedicated && !still_running(c.pid, &c.start_token) {
                    let row = c.clone();
                    let now = Timestamp::now();
                    match txn(&self.store, move |tx| {
                        move_row(tx, &row, OwnedConnectionState::Closed)?;
                        resource_absent(tx, &row, now)
                    })
                    .await
                    {
                        Ok(()) => report.closed.push(c.id.clone()),
                        Err(_) => report
                            .failed
                            .push((c.id.clone(), refusal::STORE.to_owned())),
                    }
                }
            }
        }
        report
    }

    /// Runtime exit: close every master this process started.
    pub async fn shutdown(&self) -> PassReport {
        let mut report = PassReport::default();
        let rows: Vec<OwnedConnection> = self
            .live
            .lock()
            .await
            .values()
            .map(|m| m.connection.clone())
            .collect();
        for c in rows {
            let outcome = self.close_one(&c).await;
            report.record(c.id.clone(), outcome);
        }
        report
    }

    // --- register (Windows) -------------------------------------------------------------

    async fn register_impl(
        &self,
        binding: &BindingId,
        pid: u32,
        created_at: Timestamp,
        image: &str,
    ) -> Result<OwnedConnection, ConnError> {
        if self.config.platform != Platform::Windows || !cfg!(windows) {
            return Err(refused(refusal::WINDOWS_ONLY));
        }
        let ops = self
            .ops
            .as_ref()
            .ok_or_else(|| refused(refusal::OPERATIONS_UNAVAILABLE))?;
        let expected = self.config.verified_ssh.as_path();
        let named = Path::new(image);
        if !same_image_text(named, expected) {
            return Err(refused(refusal::IMAGE_NOT_VERIFIED_CLIENT));
        }
        let pin = match ProcessPin::open(pid) {
            Ok(Some(pin)) => pin,
            Ok(None) => return Err(refused(refusal::PROCESS_GONE)),
            Err(_) => return Err(refused(refusal::PROCESS_UNREADABLE)),
        };
        let created_matches = current_token(&pin) == Some(created_at.to_string());
        if !created_matches {
            return Err(refused(refusal::CREATION_TIME_MISMATCH));
        }
        // The image is read on the same handle, which stays open (pinning the PID)
        // until the registration returns.
        // `_held` keeps the handle open (pinning the PID) to the end of this call.
        let Some(_held) = pin.verify(true, expected) else {
            return Err(refused(refusal::IMAGE_NOT_VERIFIED_CLIENT));
        };
        ops.register_owned_connection(binding, pid, created_at, &expected.to_string_lossy())
            .await
    }
}

/// The image the launcher names equals the verified client (Windows: ASCII
/// case-insensitively).
fn same_image_text(named: &Path, expected: &Path) -> bool {
    if cfg!(windows) {
        named
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
    } else {
        named == expected
    }
}

async fn txn_move(
    store: &Arc<Store>,
    c: &OwnedConnection,
    to: OwnedConnectionState,
) -> Result<(), ConnError> {
    let row = c.clone();
    txn(store, move |tx| move_row(tx, &row, to)).await
}

/// Create `dir` (and parents) owner-only (0700 on Unix).
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
        {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// The keys of the D8 item 2 table this supervisor applies, by kind and mode (a test
/// and documentation aid; the rule itself is `heimdall_domain::connection::closes`).
#[must_use]
pub fn closing_matrix() -> BTreeMap<(&'static str, &'static str, &'static str), bool> {
    let mut out = BTreeMap::new();
    for e in ConnectionEnd::ALL {
        for (mode, m) in [
            ("graceful", ExistingConnectionsMode::Graceful),
            ("strict", ExistingConnectionsMode::Strict),
        ] {
            let name = match e {
                ConnectionEnd::AdmissionDeadline => "deadline",
                ConnectionEnd::Cutoff => "cutoff",
                ConnectionEnd::Revocation => "revocation",
                ConnectionEnd::SessionLocked => "session_locked",
                ConnectionEnd::Release => "release",
                ConnectionEnd::TimeUncertain => "time_uncertain",
            };
            out.insert(("master", name, mode), closes(ConnectionKind::Master, e, m));
            out.insert(
                ("dedicated", name, mode),
                closes(ConnectionKind::Dedicated, e, m),
            );
        }
    }
    out
}

// `heimdall_app::ports::ConnectionControl` is declared with `#[async_trait]`; this is
// the desugared form (as `dispatch.rs` does for the IPC dispatcher), delegating to the
// inherent methods above.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl ConnectionControl for ConnectionSupervisor {
    fn start_master<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        binding: &'life1 BindingId,
        pair: &'life2 AccessPair,
    ) -> BoxFuture<'async_trait, Result<OwnedConnection, ConnError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.start_master_impl(binding, pair))
    }

    fn close<'life0, 'life1, 'async_trait>(
        &'life0 self,
        c: &'life1 OwnedConnection,
        reason: CloseReason,
    ) -> BoxFuture<'async_trait, Result<(), ConnError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let _ = reason;
            match self.close_one(c).await {
                CloseOutcome::Closed => Ok(()),
                CloseOutcome::Unverified => Err(ConnError::Unverified),
                CloseOutcome::Pending => Err(unavailable(refusal::EXEC_PENDING)),
                CloseOutcome::Failed(e) => Err(ConnError::Failed(e)),
            }
        })
    }

    fn register<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        binding: &'life1 BindingId,
        pid: u32,
        created_at: Timestamp,
        image: &'life2 str,
    ) -> BoxFuture<'async_trait, Result<OwnedConnection, ConnError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.register_impl(binding, pid, created_at, image))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_matrix_is_the_domain_table() {
        let m = closing_matrix();
        for ((kind, event, mode), closed) in &m {
            let expected = *kind == "master"
                || *mode == "strict"
                || matches!(*event, "revocation" | "session_locked");
            assert_eq!(*closed, expected, "{kind} {event} {mode}");
        }
        assert_eq!(m.len(), 24);
    }

    #[test]
    fn quoted_paths_escape_percent_and_refuse_quotes() {
        assert_eq!(
            quoted_path(Path::new("/r/mux/a%b")).unwrap(),
            "\"/r/mux/a%%b\""
        );
        assert!(quoted_path(Path::new("/r/\"x")).is_err());
        assert!(quoted_path(Path::new("/r/\nx")).is_err());
        assert!(safe_alias("-oProxyCommand=x").is_err());
        assert!(safe_alias("a b").is_err());
        assert_eq!(safe_alias("host-1").unwrap(), "host-1");
    }

    #[test]
    fn resource_ids_follow_connection_ids() {
        let c = ConnectionId::from_random_bytes([7; 16]);
        let r = resource_id(&c);
        assert!(r.as_str().starts_with("res_"));
        assert!(r.as_str().ends_with(&"07".repeat(16)));
    }
}
