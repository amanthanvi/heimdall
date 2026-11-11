//! ⟨M03⟩ Connection control: owned masters, owned dedicated connections and the
//! connection policies (m03-plan U7; ADR-0008 D8, D7 item 2 steps 4 and 6; §17.20 items
//! 3–6, 11, 13, 14).
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
//! * [`ConnectionSupervisor::connection_restart_pass`] (first at start; §17.20 item 4):
//!   a recovered master is **kept only if its grant is usable now** by fresh admission
//!   facts: the stored state, release and tombstones, then the absolute bound (the
//!   deadline, every ancestor's deadline, every applicable cutoff and the persisted
//!   anchor's bound) at a `Safe` observation of the time gate
//!   ([`heimdall_app::TimeGate::check`]) and the gate's admission (the continuous budget,
//!   [`heimdall_app::TimeGate::admission`]). Time that is not accepted, or no gate,
//!   closes every master (as [`ConnectionSupervisor::time_uncertain_close`] does).
//!   Closing is by the persisted PID, start token and control path; a master whose
//!   identity does not verify is never signalled and is reported unverified.
//!
//! **Every pass reports a discovery failure** (§17.20 item 13): a store failure while
//! enumerating rows is [`DiscoveryFailed`], carrying what the pass did besides, never an
//! empty [`PassReport`]. U10 keeps the cleanup intent and retries (D7 item 2).
//!
//! **Owned masters** (D8 item 3; reading R4; §17.20 item 14 W3-Q1). `ssh` runs as a
//! **foreground child** (never `-f`) with `OWNED_LAUNCH_PINS[0..2]` (`-o
//! ForkAfterAuthentication=no`), then `-M -N -o ControlMaster=yes -o ControlPersist=no
//! -o ControlPath=<slot path>`, the §17.19 item 4 identity options for the **binding's**
//! endpoint and certificate (`heimdall_sshconf::render::managed_identity_options`),
//! `-o ClearAllForwardings=yes -o ExitOnForwardFailure=yes -o BatchMode=yes`, then `--
//! <alias>` ([`master_argv`]). The slot path is `<runtime_dir>/mux/<destination-id>`
//! (`heimdall_localenv::projection::content::checked_mux_path`, refused
//! `mux_path_too_long`). A started master is recorded as a `ManagedResource` (`process`,
//! owned by the binding; its locator is the JSON [`MasterLocator`]) and an
//! `owned_connections` row (kind `master`; PID, start token, control path, generation).
//!
//! **The slot lifecycle is serialized and proven** (§17.20 items 3, 5, 6):
//!
//! * start, replace and close of one slot path run under **one per-path lock**; the
//!   master generation (one more than every generation recorded for the path) is
//!   reserved inside it;
//! * `start_master(binding, pair)` requires the pair in the binding's scope, owned
//!   multiplexing enabled for the grant (its effective policy: the origin and every
//!   current policy, so a widening needs a decision and `setup apply`), and the binding
//!   **holding the pair's slot** (`held(binding, g)`). After the spawn's awaited work,
//!   the record transaction reads the holder, the slot generation and the policy again
//!   and records nothing if any changed (the new child is killed by its handle);
//! * `<runtime_dir>/mux/` is created owner-only and **re-verified** before every use:
//!   a real directory (no symlink), owned by this user, mode 0700 (`runtime_dir` itself
//!   a real directory owned by this user); otherwise `mux_dir_unsafe`, nothing repaired;
//! * **the stable path is Heimdall's namespace.** An entry there that is not proven to be
//!   the slot holder's current master is never trusted, recorded or signalled: its path
//!   entry is removed (the entry's identity re-read right before the unlink, under the
//!   lock) before Heimdall starts its own master and when a close pass ends the slot's
//!   masters ([`ConnectionSupervisor::clear_slot_path`] for a slot cleared without one);
//!   reported `mux_path_foreign_listener_removed`
//!   ([`PassReport::foreign_listeners_removed`]). **Disclosed residual:** sessions
//!   already open through such a listener are `not_controlled`; removing its entry
//!   stops new sessions from reaching it, it does not end it;
//! * **readiness belongs to the spawned child:** a row is recorded only once `ssh -S
//!   <path> -O check` (as `-o ControlPath=<path> -O check`) answers `pid=<child's PID>`
//!   while the child runs; any other answer kills the child and records nothing;
//! * **a control command goes only to a proven listener:** before `-O exit` the path's
//!   inode must be the row's and `-O check` must report the row's PID (start token
//!   still matching). Otherwise no control command is sent; only the verified-process
//!   signal is used;
//! * a socket is removed only under the lock and only while no newer generation for the
//!   path is open in the store. An inode number never proves identity alone.
//!
//! A failed start is retried, bounded ([`ConnectionConfig::start_backoff`]) and jittered
//! ([`ConnectionConfig::jitter`]); no master is needed for correctness (clients connect
//! directly). Windows refuses `owned_masters`: `CAPABILITY_UNAVAILABLE`,
//! `multiplexing_unsupported` (M-F7).
//!
//! **Closing** (D8 item 2 "Closing", item 3). A master: the proven `-O exit` above,
//! bounded by [`ConnectionConfig::close_grace`], then, if it still runs, SIGTERM and
//! SIGKILL after the grace to the **verified** PID, then the socket as above. A dedicated
//! connection: the verified PID is signalled the same way (Windows: `TerminateProcess`
//! on the verified handle). Verification ([`heimdall_localenv::sys::ProcessPin`];
//! reading R8): the process is pinned first (Linux pidfd, Windows handle, macOS PID),
//! then its start token is read from the source that wrote it (Unix
//! [`crate::platform::process_start_time`]; Windows the creation time read on the
//! handle, as `Operations::register_owned_connection` stored it) and compared, then the
//! image. **On every Unix the identity and image are verified again right before the
//! second signal** (§17.20 item 11; Linux keeps its pidfd). A start token that differs
//! (the PID now names another process) is `unverified` and never signalled. A matching
//! token with another image (Unix: the launcher, `heimdall`, before its `exec` or after
//! a failed one; or a process that exec'd another image during the grace) is not
//! signalled either and stays `closing`: the next pass checks it again
//! ([`CloseOutcome::Pending`]). Nothing is ever signalled by name or pattern.
//!
//! **Registration** (Windows; D8 item 2 step 2; U0b row 26): `register` verifies, on a
//! handle it holds for the whole call, that the PID's creation time is `created_at` and
//! its image the verified client, then calls `Operations::register_owned_connection`
//! (the gate and the grant re-check are the application's). Every refusal is
//! `ConnError::RegistrationRefused` with a fixed word ([`refusal`]).
//!
//! **Insertion invariant** (U7-Q4; §17.20 item 14): [`owned_row_invariant`]: a
//! dedicated row only for a launch binding with a recorded holder, a master only with
//! its process resource. The supervisor checks it in its own insertion transaction; the
//! enumeration of `time_uncertain_close` and the restart pass relies on it.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use heimdall_app::ports::{ConnError, ConnectionControl};
use heimdall_app::reconcile::Backoff;
use heimdall_app::{Operations, TimeGate};
use heimdall_contract::Timestamp;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{BindingId, ConnectionId, DestinationId, GrantId, ResourceId};
use heimdall_contract::managed::CloseReason;
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_domain::connection::{
    ConnectionEnd, ConnectionKind, ConnectionPolicy, ExistingConnectionsMode, MultiplexingMode,
    closes, effective_connection_policy,
};
use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState, SlotState};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_domain::scope::AccessPair;
use heimdall_domain::time::{self as dtime, Admission};
use heimdall_localenv::env::Platform;
use heimdall_localenv::sys::{ProcessPin, ProcessSignal, VerifiedProcess};
use heimdall_store::{RawDocuments, Store, StoreError, Txn};
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
/// The deepest grant ancestry the restart pass follows (deeper: closed, fail closed).
const MAX_ANCESTRY: usize = 64;

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
    /// An entry at the slot's mux path could not be removed (§17.20 item 6).
    pub const MUX_PATH_OCCUPIED: &str = "mux_path_occupied";
    /// A path cannot be written on an ssh command line, or is a directory.
    pub const PATH_REFUSED: &str = "path_refused";
    /// Every bounded start attempt failed.
    pub const MASTER_START_FAILED: &str = "master_start_failed";
    /// The previous master of the slot could not be closed.
    pub const PREVIOUS_MASTER_OPEN: &str = "previous_master_open";
    /// ⟨§17.20 item 5⟩ The pair is not in the binding's scope.
    pub const PAIR_NOT_IN_SCOPE: &str = "pair_not_in_scope";
    /// ⟨§17.20 item 5⟩ The binding does not hold the pair's environment slot.
    pub const SLOT_NOT_HELD: &str = "managed_slot_not_held";
    /// ⟨§17.20 item 5⟩ The slot's holder, its generation or the policy changed while the
    /// master started: nothing was recorded and the new child was closed.
    pub const SLOT_CHANGED: &str = "slot_changed_during_start";
    /// ⟨§17.20 item 6⟩ `<runtime_dir>/mux/` (or the runtime directory) is not a real
    /// directory owned by this user with mode 0700. Nothing is repaired.
    pub const MUX_DIR_UNSAFE: &str = "mux_dir_unsafe";
    /// ⟨§17.20 item 6⟩ The report word of a removed unproven entry at a stable path.
    pub const FOREIGN_LISTENER_REMOVED: &str = "mux_path_foreign_listener_removed";
    /// ⟨§17.20 item 13⟩ A pass could not enumerate the rows it acts on.
    pub const DISCOVERY_FAILED: &str = "connection_discovery_failed";
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

/// A hook the supervisor calls at one fixed point (tests only).
pub type Hook = Arc<dyn Fn() + Send + Sync>;

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
    /// `-O exit` and `-O check` bound, and the TERM → KILL grace.
    pub close_grace: Duration,
    /// How long a master may take to bind its socket.
    pub ready_wait: Duration,
    /// Arguments placed before `--` on every `ssh` this supervisor runs (the master,
    /// `-O check` and `-O exit`). Empty in production; tests pass the client isolation
    /// arguments (`-F <scratch config>`, the scratch known-hosts files, `BatchMode`;
    /// m03-plan §0.2).
    pub client_args: Vec<OsString>,
    /// `Some`: the `ssh` children get exactly this environment (tests: a scratch
    /// `HOME`); `None`: the runtime's own.
    pub client_env: Option<Vec<(OsString, OsString)>>,
    /// ⟨§17.20 item 4⟩ The time gate the restart pass judges recovered masters by.
    /// `None`: the gate of the supervisor's `Operations`, if it has one; with neither,
    /// time is not accepted and the restart pass closes every master (fail closed).
    pub time_gate: Option<Arc<TimeGate>>,
    /// Test hook: called after a master's readiness is proven and before the
    /// transaction that re-checks and records it (§17.20 item 5's slot-transfer
    /// regression). `None` in production ([`ConnectionConfig::new`]).
    #[doc(hidden)]
    pub after_master_ready: Option<Hook>,
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
            time_gate: None,
            after_master_ready: None,
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
    /// The alias `-O check` and `-O exit` name.
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
    /// Unix: the start token matches but the image is not the client (exec pending, or
    /// another image exec'd during the grace): not signalled, `closing`, checked again
    /// by the next pass.
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
    /// Kept by the policy (or a master of a still-usable grant at restart).
    pub kept: Vec<ConnectionId>,
    /// Failed closes.
    pub failed: Vec<(ConnectionId, String)>,
    /// ⟨§17.20 item 6⟩ `mux_path_foreign_listener_removed`: stable paths whose unproven
    /// entry was removed (sessions already open through it are `not_controlled`).
    pub foreign_listeners_removed: Vec<PathBuf>,
    /// Stable paths whose entry could not be judged or removed (a fixed word each).
    pub paths_failed: Vec<(PathBuf, String)>,
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

/// ⟨§17.20 item 13⟩ A pass could not enumerate (some of) the rows it acts on: an
/// explicit failure, never an empty report. `report` is what the pass did besides;
/// `grants` the grants whose rows could not be read (empty: the pass's whole
/// enumeration failed). U10 keeps the cleanup intent and retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryFailed {
    /// What the pass did before and besides the failure.
    pub report: PassReport,
    /// The grants whose rows could not be read; empty when nothing could be.
    pub grants: Vec<GrantId>,
}

impl DiscoveryFailed {
    /// The fixed word ([`refusal::DISCOVERY_FAILED`]).
    #[must_use]
    pub fn word(&self) -> &'static str {
        refusal::DISCOVERY_FAILED
    }
}

/// A pass's result.
pub type PassResult = Result<PassReport, DiscoveryFailed>;

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

/// One lock per stable mux path (the slot lifecycle's serialization, §17.20 item 3).
type SlotLock = Arc<tokio::sync::Mutex<()>>;

/// Owned masters and owned dedicated connections (module docs).
pub struct ConnectionSupervisor {
    store: Arc<Store>,
    ops: Option<Operations>,
    config: ConnectionConfig,
    /// Masters started by this process, by control path. Lock order: a slot lock
    /// first, then this map (held briefly, never across a slot-lock wait).
    live: tokio::sync::Mutex<BTreeMap<PathBuf, LiveMaster>>,
    /// The per-path slot locks.
    slot_locks: std::sync::Mutex<BTreeMap<PathBuf, SlotLock>>,
    /// Every stable path whose unproven entry this supervisor removed.
    foreign_removed: std::sync::Mutex<Vec<PathBuf>>,
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

/// ⟨U7-Q4; §17.20 item 14⟩ The invariant the row enumeration of
/// [`ConnectionSupervisor::time_uncertain_close`] and the restart pass relies on,
/// checked where a row is inserted: a **dedicated** row only for a launch binding with a
/// recorded holder; a **master** only with its process resource, owned by the row's
/// binding. Any other kind: `false`.
///
/// # Errors
/// A store read error.
pub fn owned_row_invariant(tx: &mut Txn<'_>, c: &OwnedConnection) -> heimdall_store::Result<bool> {
    match c.kind {
        ConnectionKind::Master => Ok(tx.resource(&resource_id(&c.id))?.is_some_and(|r| {
            r.kind == ResourceKind::Process
                && matches!(&r.owner, OwnerRef::Binding { id } if *id == c.binding)
        })),
        ConnectionKind::Dedicated => Ok(tx.binding_holder(&c.binding)?.is_some()),
        _ => Ok(false),
    }
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

/// The owned master's argument vector after the program name (reading R4; §17.20 item
/// 14 W3-Q1; module docs). `key_pub` and `cert` are the binding's files (U6's
/// `binding_files_for_endpoint`); only the certificate is named as the identity
/// (§17.19 item 4). `client_args` go right before `--` ([`ConnectionConfig::client_args`]).
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

fn control_argv(
    op: &str,
    control_path: &Path,
    alias: &str,
    client_args: &[OsString],
) -> Result<Vec<OsString>, ConnError> {
    let mut out: Vec<OsString> = vec![
        "-O".into(),
        op.into(),
        "-o".into(),
        format!("ControlPath={}", quoted_path(control_path)?).into(),
    ];
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
    control_argv("exit", control_path, alias, client_args)
}

/// `ssh -O check -o ControlPath=<path> [client args] -- <alias>` (§17.20 item 3: the
/// proof of who listens at the path).
///
/// # Errors
/// As [`master_argv`].
pub fn check_argv(
    control_path: &Path,
    alias: &str,
    client_args: &[OsString],
) -> Result<Vec<OsString>, ConnError> {
    control_argv("check", control_path, alias, client_args)
}

/// The PID in `ssh -O check`'s answer (`Master running (pid=<N>)`), if any.
#[must_use]
pub fn parse_check_pid(text: &str) -> Option<u32> {
    let at = text.find("(pid=")? + "(pid=".len();
    let digits: String = text[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let rest = &text[at + digits.len()..];
    if !rest.starts_with(')') {
        return None;
    }
    digits.parse().ok().filter(|p| *p > 1)
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

/// Remove the socket at `path` only if it is still `inode`. Returns whether it was
/// removed. **Not a proof of identity on its own** (§17.20 item 3: an inode number can
/// be reused at once): the supervisor calls it only under the path's slot lock, with no
/// newer generation open for the path.
#[must_use]
pub fn remove_socket_if_same_inode(path: &Path, inode: Option<(u64, u64)>) -> bool {
    match (inode, socket_inode(path)) {
        (Some(want), Some(now)) if want == now => std::fs::remove_file(path).is_ok(),
        _ => false,
    }
}

/// Any entry at `path` (never followed): its `(device, inode)` and whether it is a
/// directory.
fn entry_identity(path: &Path) -> Option<((u64, u64), bool)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path).ok()?;
        Some(((m.dev(), m.ino()), m.file_type().is_dir()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// ⟨§17.20 item 6⟩ `<runtime_dir>/mux/` owner-only, re-verified: `runtime_dir` a real
/// directory owned by this user; `mux` a real directory (never a symlink) owned by
/// this user with mode exactly 0700; `path` directly in it. `create`: an absent `mux` is
/// created 0700 first (then verified like any other). `Ok(false)`: absent, not
/// created. Nothing is repaired: anything else is `mux_dir_unsafe`.
fn ensure_mux_dir(runtime_dir: &Path, path: &Path, create: bool) -> Result<bool, ConnError> {
    let mux = runtime_dir.join("mux");
    if path.parent() != Some(mux.as_path()) {
        return Err(unavailable(refusal::PATH_REFUSED));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let unsafe_dir = || unavailable(refusal::MUX_DIR_UNSAFE);
        let uid = heimdall_localenv::sys::current_uid();
        let rt = std::fs::symlink_metadata(runtime_dir).map_err(|_| unsafe_dir())?;
        if !rt.file_type().is_dir() || rt.uid() != uid {
            return Err(unsafe_dir());
        }
        match std::fs::symlink_metadata(&mux) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(false);
                }
                match std::fs::DirBuilder::new().mode(0o700).create(&mux) {
                    Ok(()) => {}
                    // Raced: verified below like any existing one.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(unsafe_dir()),
                }
            }
            Err(_) => return Err(unsafe_dir()),
        }
        let m = std::fs::symlink_metadata(&mux).map_err(|_| unsafe_dir())?;
        if !m.file_type().is_dir() || m.uid() != uid || m.mode() & 0o7777 != 0o700 {
            return Err(unsafe_dir());
        }
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = create;
        Err(unavailable(reason::MULTIPLEXING_UNSUPPORTED))
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
    // §17.20 item 11 (D8 item 2): on every Unix the start identity and the image are
    // verified again right before the second signal. Linux pins the process with its
    // pidfd (no PID reuse), but the same process may have exec'd another image during
    // the grace; macOS pins nothing (the disclosed one check-then-signal window). A
    // process that now runs another image is not signalled (`pending`).
    #[cfg(unix)]
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

fn is_open(c: &OwnedConnection) -> bool {
    matches!(
        c.state,
        OwnedConnectionState::Up | OwnedConnectionState::Closing
    )
}

/// Every owned connection that is not `closed` or `unverified`: the rows of the
/// bindings with a recorded holder (dedicated rows exist only for launch bindings) and
/// of the bindings owning a master resource ([`owned_row_invariant`]).
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
                .filter(is_open),
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

/// What `start_master` reads (and re-reads after the spawn) in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MasterContext {
    alias: String,
    grant: GrantId,
    slot_generation: u64,
}

/// §17.20 item 5's preconditions in `tx`: the binding is known and not released, its
/// grant usable, `pair` in its scope, owned multiplexing enabled by the effective
/// policy, the binding the holder of `pair`'s slot in its environment, the destination
/// known.
fn start_context(
    tx: &mut Txn<'_>,
    binding: &BindingId,
    pair: &AccessPair,
) -> heimdall_store::Result<Result<MasterContext, &'static str>> {
    let Some(rec) = tx.binding(binding)? else {
        return Ok(Err(refusal::BINDING_UNKNOWN));
    };
    if rec.released_at.is_some() {
        return Ok(Err(refusal::BINDING_UNKNOWN));
    }
    match tx.grant(&rec.grant)? {
        Some(g) if g.state.permits_use() => {}
        _ => return Ok(Err(refusal::GRANT_ENDED)),
    }
    if !rec.scope.pairs.contains(pair) {
        return Ok(Err(refusal::PAIR_NOT_IN_SCOPE));
    }
    if effective_policy_in(tx, &rec.grant, None)?.multiplexing != MultiplexingMode::OwnedMasters {
        return Ok(Err(refusal::MASTERS_DISABLED));
    }
    let slot_generation = match tx.slot(&rec.environment, pair)? {
        SlotState::Held {
            binding: holder,
            generation,
        } if holder == *binding => generation,
        _ => return Ok(Err(refusal::SLOT_NOT_HELD)),
    };
    let Some(d) = tx.destination(&pair.destination)? else {
        return Ok(Err(refusal::DESTINATION_UNKNOWN));
    };
    Ok(Ok(MasterContext {
        alias: d.alias,
        grant: rec.grant,
        slot_generation,
    }))
}

/// §17.20 item 4: the restart facts of a recovered master's grant in `tx`. `None`: the
/// grant cannot be used whatever the time (ended, released binding, tombstone, an ended
/// or missing ancestor, no origin). Otherwise its absolute bound: the deadline, every
/// ancestor's deadline, every applicable cutoff and the persisted anchor's bound.
fn restart_bound(
    tx: &mut Txn<'_>,
    c: &OwnedConnection,
) -> heimdall_store::Result<Option<Timestamp>> {
    let (Some(g), Some(b)) = (tx.grant(&c.grant)?, tx.binding(&c.binding)?) else {
        return Ok(None);
    };
    if !g.state.permits_use() || b.released_at.is_some() || tx.denied_ancestor(&g.id)?.is_some() {
        return Ok(None);
    }
    let Some(origin) = tx.grant_origin(&g.id)? else {
        return Ok(None);
    };
    let mut bound = g.deadline.effective;
    let mut next = g.parent.clone();
    let mut depth = 0usize;
    while let Some(id) = next {
        depth += 1;
        let Some(p) = tx.grant(&id)? else {
            return Ok(None);
        };
        if depth > MAX_ANCESTRY || !p.state.permits_use() {
            return Ok(None);
        }
        bound = bound.min(p.deadline.effective);
        next = p.parent.clone();
    }
    for p in tx.policies_for(&origin.profile, &g.environment)? {
        if let Some(cutoff) = p.cutoff_at {
            bound = bound.min(cutoff);
        }
    }
    if let Some(a) = tx.grant_anchor(&g.id)? {
        bound = bound.min(a.bound);
    }
    Ok(Some(bound))
}

impl ConnectionSupervisor {
    /// Build. `ops` is needed by [`ConnectionControl::register`] (Windows), and gives the
    /// restart pass its time gate when [`ConnectionConfig::time_gate`] is `None`.
    #[must_use]
    pub fn new(store: Arc<Store>, ops: Option<Operations>, config: ConnectionConfig) -> Self {
        Self {
            store,
            ops,
            config,
            live: tokio::sync::Mutex::new(BTreeMap::new()),
            slot_locks: std::sync::Mutex::new(BTreeMap::new()),
            foreign_removed: std::sync::Mutex::new(Vec::new()),
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

    /// Every stable path whose unproven entry this supervisor removed
    /// (`mux_path_foreign_listener_removed`), oldest first.
    #[must_use]
    pub fn foreign_listeners_removed(&self) -> Vec<PathBuf> {
        self.foreign_removed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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

    fn time_gate(&self) -> Option<&TimeGate> {
        self.config
            .time_gate
            .as_deref()
            .or_else(|| self.ops.as_ref().map(Operations::timegate))
    }

    fn slot_lock(&self, path: &Path) -> SlotLock {
        let mut locks = self
            .slot_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(locks.entry(path.to_path_buf()).or_default())
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

    /// The PID of the master answering `ssh -O check` at `path`, bounded by
    /// [`ConnectionConfig::close_grace`]. `None`: nothing answered (or not as a master).
    async fn listener_pid(&self, path: &Path, alias: &str) -> Option<u32> {
        let args = check_argv(path, alias, &self.config.client_args).ok()?;
        let mut std_cmd = self.ssh_command(&args);
        std_cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut cmd = tokio::process::Command::from(std_cmd);
        cmd.kill_on_drop(true);
        let out = tokio::time::timeout(self.config.close_grace, cmd.output())
            .await
            .ok()?
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_check_pid(&String::from_utf8_lossy(&out.stderr))
            .or_else(|| parse_check_pid(&String::from_utf8_lossy(&out.stdout)))
    }

    // --- the stable path (§17.20 items 3 and 6) ---------------------------------------

    /// Under `path`'s slot lock: unless the entry at `path` is proven to be `keep`'s
    /// master (its start token still matches, `-O check` names its PID, and the entry did
    /// not change meanwhile), it is never trusted, recorded or signalled: its path entry
    /// is removed, the entry's identity re-read right before the unlink. `Ok(true)`: an
    /// entry was removed (`mux_path_foreign_listener_removed`).
    async fn clear_unproven_locked(
        &self,
        path: &Path,
        keep: Option<(&OwnedConnection, &str)>,
    ) -> Result<bool, ConnError> {
        if !ensure_mux_dir(&self.config.runtime_dir, path, false)? {
            return Ok(false);
        }
        let Some((identity, is_dir)) = entry_identity(path) else {
            return Ok(false);
        };
        if is_dir {
            return Err(unavailable(refusal::PATH_REFUSED));
        }
        if let Some((row, alias)) = keep
            && still_running(row.pid, &row.start_token)
            && self.listener_pid(path, alias).await == Some(row.pid)
            && entry_identity(path).map(|e| e.0) == Some(identity)
        {
            return Ok(false);
        }
        // The same entry that was judged, re-verified right before the unlink.
        ensure_mux_dir(&self.config.runtime_dir, path, false)?;
        if entry_identity(path).map(|e| e.0) != Some(identity) {
            return Err(unavailable(refusal::MUX_PATH_OCCUPIED));
        }
        std::fs::remove_file(path).map_err(|_| unavailable(refusal::MUX_PATH_OCCUPIED))?;
        tracing::warn!(
            reason = refusal::FOREIGN_LISTENER_REMOVED,
            "an unproven entry at a managed slot's stable mux path was removed; sessions \
             already open through it are not controlled"
        );
        self.foreign_removed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(path.to_path_buf());
        Ok(true)
    }

    /// Under `path`'s slot lock: the open master row recorded for `path` with the
    /// highest generation, if its binding still holds a slot whose stable path is
    /// `path` (the slot holder's current master), with its alias.
    async fn current_master_locked(
        &self,
        path: &Path,
    ) -> Result<Option<(OwnedConnection, String)>, ConnError> {
        let wanted = path.to_string_lossy().into_owned();
        let path = path.to_path_buf();
        let runtime_dir = self.config.runtime_dir.clone();
        txn(&self.store, move |tx| {
            let mut best: Option<(OwnedConnection, String)> = None;
            for (_, l) in master_resources(tx)? {
                if l.control_path != wanted {
                    continue;
                }
                let Some(c) = tx.owned_connection(&l.connection)? else {
                    continue;
                };
                if c.state != OwnedConnectionState::Up
                    || best
                        .as_ref()
                        .is_some_and(|(b, _)| b.generation >= c.generation)
                {
                    continue;
                }
                let holds = tx.slots_for_binding(&c.binding)?.iter().any(|s| {
                    matches!(&s.state, SlotState::Held { binding, .. } if *binding == c.binding)
                        && heimdall_localenv::projection::content::checked_mux_path(
                            &runtime_dir,
                            &s.pair.destination,
                        )
                        .is_ok_and(|p| p == path)
                });
                if holds {
                    best = Some((c, l.alias));
                }
            }
            Ok(best)
        })
        .await
    }

    /// Under `path`'s slot lock: remove the socket a closed `generation` left, only
    /// while no newer generation for `path` is open in the store and the socket is still
    /// the inode that generation recorded.
    async fn remove_stale_locked(
        &self,
        path: &Path,
        generation: u64,
        inode: Option<(u64, u64)>,
    ) -> bool {
        if inode.is_none() || socket_inode(path) != inode {
            return false;
        }
        let wanted = path.to_string_lossy().into_owned();
        let newer = txn(&self.store, move |tx| {
            for (r, l) in master_resources(tx)? {
                if l.control_path == wanted
                    && r.generation.0 > generation
                    && tx
                        .owned_connection(&l.connection)?
                        .is_some_and(|c| is_open(&c))
                {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await;
        matches!(newer, Ok(false)) && remove_socket_if_same_inode(path, inode)
    }

    /// Take `path`'s slot lock and clear its unproven entry, keeping the slot holder's
    /// proven current master.
    async fn clear_path(&self, path: &Path) -> Result<bool, ConnError> {
        let lock = self.slot_lock(path);
        let _slot = lock.lock().await;
        let keep = self.current_master_locked(path).await?;
        self.clear_unproven_locked(path, keep.as_ref().map(|(c, a)| (c, a.as_str())))
            .await
    }

    /// ⟨§17.20 item 6⟩ The slot of `destination` was cleared (its grant ended) without a
    /// close pass over a master of it (U10 calls this when it clears a slot): any entry
    /// at its stable path that is not the proven master of a current slot holder is
    /// removed. `Ok(true)`: removed (`mux_path_foreign_listener_removed`).
    ///
    /// # Errors
    /// [`ConnError::Unavailable`]: `mux_dir_unsafe`, `path_refused`, `mux_path_occupied`,
    /// `store`, `mux_path_too_long`.
    pub async fn clear_slot_path(&self, destination: &DestinationId) -> Result<bool, ConnError> {
        if self.config.platform == Platform::Windows {
            return Ok(false);
        }
        let path = heimdall_localenv::projection::content::checked_mux_path(
            &self.config.runtime_dir,
            destination,
        )
        .map_err(unavailable)?;
        self.clear_path(&path).await
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
        let path = heimdall_localenv::projection::content::checked_mux_path(
            &self.config.runtime_dir,
            &pair.destination,
        )
        .map_err(unavailable)?;
        // §17.20 item 3: start, replace and close of the slot path are serialized.
        let lock = self.slot_lock(&path);
        let _slot = lock.lock().await;
        let (b, p) = (binding.clone(), pair.clone());
        let ctx = txn(&self.store, move |tx| start_context(tx, &b, &p))
            .await?
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
        // Every earlier generation of the path first; the new one is reserved here.
        let generation = self.replace_previous_locked(&path).await?;
        ensure_mux_dir(&self.config.runtime_dir, &path, true)?;
        let (child, inode) = self.spawn_ready(&argv, &path, &ctx.alias).await?;
        if let Some(hook) = &self.config.after_master_ready {
            hook();
        }
        self.record_master(binding, pair, child, inode, &path, ctx, generation)
            .await
    }

    /// Spawn the master with bounded, jittered retries until it is proven ready. Before
    /// each attempt (under the slot lock) the mux directory is re-verified and any
    /// unproven entry at the path removed.
    async fn spawn_ready(
        &self,
        argv: &[OsString],
        path: &Path,
        alias: &str,
    ) -> Result<(Starting, (u64, u64)), ConnError> {
        let attempts = self.config.start_backoff.max_attempts.max(1);
        for attempt in 1..=attempts {
            self.clear_unproven_locked(path, None).await?;
            if entry_identity(path).is_some() {
                return Err(unavailable(refusal::MUX_PATH_OCCUPIED));
            }
            self.start_attempts.fetch_add(1, Ordering::SeqCst);
            if let Some(ready) = self.spawn_once(argv, path, alias).await {
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

    /// One attempt: the child is ready only once `-O check` at `path` names **its**
    /// PID while it runs and the socket did not change meanwhile (§17.20 item 3). Any
    /// other listener's answer ends the attempt (the child is killed by its handle).
    async fn spawn_once(
        &self,
        argv: &[OsString],
        path: &Path,
        alias: &str,
    ) -> Option<(Starting, (u64, u64))> {
        let mut child = Starting(Some(self.ssh_command(argv).spawn().ok()?));
        let pid = child.pid()?;
        let end = Instant::now() + self.config.ready_wait;
        loop {
            if let Some(inode) = socket_inode(path)
                && !child.exited()
            {
                match self.listener_pid(path, alias).await {
                    Some(p) if p == pid && socket_inode(path) == Some(inode) && !child.exited() => {
                        return Some((child, inode));
                    }
                    // Another process listens there: never ours, never recorded.
                    Some(_) => return None,
                    None => {}
                }
            }
            if child.exited() || Instant::now() >= end {
                // Dropping `child` kills (a no-op once exited) and reaps it.
                return None;
            }
            tokio::time::sleep(EXIT_POLL).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_master(
        &self,
        binding: &BindingId,
        pair: &AccessPair,
        child: Starting,
        inode: (u64, u64),
        path: &Path,
        ctx: MasterContext,
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
            alias: ctx.alias.clone(),
            inode: Some(inode),
        };
        let locator_json =
            serde_json::to_string(&locator).map_err(|_| unavailable(refusal::STORE))?;
        let image = self.config.verified_ssh.to_string_lossy().into_owned();
        let (b, p) = (binding.clone(), pair.clone());
        let control_path = locator.control_path.clone();
        let now = Timestamp::now();
        let row = txn(&self.store, move |tx| {
            // §17.20 item 5: re-read after the spawn's awaited work; the holder, its
            // generation and the policy must be unchanged.
            let again = match start_context(tx, &b, &p)? {
                Ok(again) => again,
                Err(word) => return Ok(Err(word)),
            };
            if again != ctx {
                return Ok(Err(refusal::SLOT_CHANGED));
            }
            let connection = OwnedConnection {
                id: id.clone(),
                kind: ConnectionKind::Master,
                binding: b.clone(),
                grant: ctx.grant.clone(),
                pid,
                start_token: token,
                image,
                control_path: Some(control_path),
                generation,
                state: OwnedConnectionState::Up,
                started_at: now,
            };
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
            tx.insert_owned_connection(&connection)?;
            // U7-Q4: checked where the row is inserted; a violation rolls back both.
            if !owned_row_invariant(tx, &connection)? {
                return Err(StoreError::Corrupt(
                    "owned connection insertion invariant".into(),
                ));
            }
            Ok(Ok(connection))
        })
        .await;
        match row {
            Ok(Ok(connection)) => {
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
                // Our own child, by its handle; then its socket (this generation's,
                // proven above; we hold the lock and no newer generation exists).
                drop(child);
                let _ = remove_socket_if_same_inode(path, Some(inode));
                Err(match other {
                    Ok(Err(word)) => unavailable(word),
                    Err(e) => e,
                    Ok(Ok(_)) => unavailable(refusal::STORE),
                })
            }
        }
    }

    /// Under `path`'s slot lock: close every earlier master of `path` (live here or
    /// persisted) and return the next generation (one more than every generation
    /// recorded for the path).
    async fn replace_previous_locked(&self, path: &Path) -> Result<u64, ConnError> {
        let live = self
            .live
            .lock()
            .await
            .get(path)
            .map(|m| m.connection.clone());
        if let Some(c) = live
            && self.close_one_inner(&c, true).await != CloseOutcome::Closed
        {
            return Err(unavailable(refusal::PREVIOUS_MASTER_OPEN));
        }
        let wanted = path.to_string_lossy().into_owned();
        let (rows, max) = txn(&self.store, move |tx| {
            let mut rows = Vec::new();
            let mut max = 0u64;
            for (r, l) in master_resources(tx)? {
                if l.control_path != wanted {
                    continue;
                }
                max = max.max(r.generation.0);
                if let Some(c) = tx.owned_connection(&l.connection)? {
                    rows.push(c);
                }
            }
            Ok((rows, max))
        })
        .await?;
        for c in rows {
            if is_open(&c) && self.close_one_inner(&c, true).await != CloseOutcome::Closed {
                return Err(unavailable(refusal::PREVIOUS_MASTER_OPEN));
            }
        }
        max.checked_add(1)
            .ok_or_else(|| unavailable(refusal::MASTER_START_FAILED))
    }

    // --- close ------------------------------------------------------------------------

    /// Close one owned connection (module docs) and record the result. A master is
    /// closed under its slot path's lock.
    pub async fn close_one(&self, c: &OwnedConnection) -> CloseOutcome {
        self.close_one_inner(c, false).await
    }

    async fn close_one_inner(&self, c: &OwnedConnection, have_lock: bool) -> CloseOutcome {
        let outcome = match c.kind {
            ConnectionKind::Master => match c.control_path.as_deref().map(PathBuf::from) {
                None => CloseOutcome::Unverified,
                Some(path) if have_lock => self.close_master_locked(c, &path).await,
                Some(path) => {
                    let lock = self.slot_lock(&path);
                    let _slot = lock.lock().await;
                    self.close_master_locked(c, &path).await
                }
            },
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

    /// Under `path`'s slot lock (module docs, "Closing").
    async fn close_master_locked(&self, c: &OwnedConnection, path: &Path) -> CloseOutcome {
        if txn_move(&self.store, c, OwnedConnectionState::Closing)
            .await
            .is_err()
        {
            return CloseOutcome::Failed(refusal::STORE.to_owned());
        }
        let live = {
            let mut map = self.live.lock().await;
            match map.get(path) {
                Some(m) if m.connection.id == c.id => map.remove(path),
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
        // 1. `-O exit` only to a proven listener: the path is still the row's inode and
        // `-O check` names the row's PID (its start token still matching).
        if let Some(l) = &locator
            && let Some(inode) = l.inode
            && l.pid == c.pid
            && socket_inode(path) == Some(inode)
            && still_running(c.pid, &c.start_token)
            && self.listener_pid(path, &l.alias).await == Some(c.pid)
            && socket_inode(path) == Some(inode)
            && let Ok(args) = exit_argv(path, &l.alias, &self.config.client_args)
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
                self.live.lock().await.insert(path.to_path_buf(), m);
            }
        }
        // 3. The socket, under the lock, while no newer generation owns the path.
        if outcome == CloseOutcome::Closed {
            let _ = self
                .remove_stale_locked(path, c.generation, locator.and_then(|l| l.inode))
                .await;
        }
        outcome
    }

    /// Close the rows of `grants` that `event` closes; keep the others. Then, for every
    /// stable path of their masters and of their bindings' slots, remove an entry that
    /// is not a slot holder's proven current master (§17.20 item 6).
    ///
    /// # Errors
    /// [`DiscoveryFailed`] when the rows of a grant could not be read (the other
    /// grants are still processed; their results are in its `report`).
    pub async fn close_for(&self, grants: &[GrantId], event: ConnectionEnd) -> PassResult {
        let mut report = PassReport::default();
        let mut failed: Vec<GrantId> = Vec::new();
        let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
        for g in grants {
            let grant = g.clone();
            let runtime_dir = self.config.runtime_dir.clone();
            let found = txn(&self.store, move |tx| {
                let policy = effective_policy_in(tx, &grant, None)?;
                let all = tx.owned_connections_for_grant(&grant)?;
                let bindings: BTreeSet<BindingId> = all.iter().map(|c| c.binding.clone()).collect();
                let mut slot_paths = BTreeSet::new();
                for b in &bindings {
                    for s in tx.slots_for_binding(b)? {
                        if let Ok(p) = heimdall_localenv::projection::content::checked_mux_path(
                            &runtime_dir,
                            &s.pair.destination,
                        ) {
                            slot_paths.insert(p);
                        }
                    }
                }
                let rows: Vec<OwnedConnection> = all.into_iter().filter(is_open).collect();
                Ok((policy, rows, slot_paths))
            })
            .await;
            let Ok((policy, rows, slot_paths)) = found else {
                failed.push(g.clone());
                continue;
            };
            for c in rows {
                if c.kind == ConnectionKind::Master
                    && let Some(p) = &c.control_path
                {
                    paths.insert(PathBuf::from(p));
                }
                if closes(c.kind, event, policy.existing) {
                    let outcome = self.close_one(&c).await;
                    report.record(c.id.clone(), outcome);
                } else {
                    report.kept.push(c.id.clone());
                }
            }
            paths.extend(slot_paths);
        }
        if self.config.platform != Platform::Windows {
            for path in paths {
                match self.clear_path(&path).await {
                    Ok(true) => report.foreign_listeners_removed.push(path),
                    Ok(false) => {}
                    Err(e) => {
                        let word = match e {
                            ConnError::Unavailable(w) | ConnError::Failed(w) => w,
                            _ => refusal::STORE.to_owned(),
                        };
                        report.paths_failed.push((path, word));
                    }
                }
            }
        }
        if failed.is_empty() {
            Ok(report)
        } else {
            Err(DiscoveryFailed {
                report,
                grants: failed,
            })
        }
    }

    /// At an admission deadline (or a cutoff: `event`), for the grants it ended: masters
    /// always, dedicated connections by the policy (D8 item 2 table).
    ///
    /// # Errors
    /// As [`ConnectionSupervisor::close_for`].
    pub async fn connection_deadline_pass(&self, ended: &[GrantId]) -> PassResult {
        self.close_for(ended, ConnectionEnd::AdmissionDeadline)
            .await
    }

    /// D7 item 2 step 4, after the gates are released: the cascade's masters and owned
    /// dedicated connections, under both policies.
    ///
    /// # Errors
    /// As [`ConnectionSupervisor::close_for`].
    pub async fn revocation_close(&self, cascade: &[GrantId]) -> PassResult {
        self.close_for(cascade, ConnectionEnd::Revocation).await
    }

    /// D7 item 7: release of the last reference (masters; dedicated as at the deadline).
    ///
    /// # Errors
    /// As [`ConnectionSupervisor::close_for`].
    pub async fn release_close(&self, grants: &[GrantId]) -> PassResult {
        self.close_for(grants, ConnectionEnd::Release).await
    }

    /// D7 item 10: `TIME_UNCERTAIN` closes every master and the `strict` dedicated
    /// connections; `graceful` ones are kept.
    ///
    /// # Errors
    /// [`DiscoveryFailed`] (empty `grants`) when the open rows cannot be enumerated; as
    /// [`ConnectionSupervisor::close_for`] after that.
    pub async fn time_uncertain_close(&self) -> PassResult {
        let grants: Vec<GrantId> = match txn(&self.store, open_rows).await {
            Ok(rows) => rows
                .into_iter()
                .map(|c| c.grant)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            Err(_) => {
                return Err(DiscoveryFailed {
                    report: PassReport::default(),
                    grants: Vec::new(),
                });
            }
        };
        self.close_for(&grants, ConnectionEnd::TimeUncertain).await
    }

    /// D8 item 3 "Restart" as §17.20 item 4 rules it (module docs): first at start.
    ///
    /// # Errors
    /// [`DiscoveryFailed`] (empty `grants`) when the open rows cannot be enumerated.
    pub async fn connection_restart_pass(&self) -> PassResult {
        let mut report = PassReport::default();
        let found = txn(&self.store, |tx| {
            let mut out = Vec::new();
            for c in open_rows(tx)? {
                if c.kind != ConnectionKind::Master {
                    continue;
                }
                let bound = restart_bound(tx, &c)?;
                out.push((c, bound));
            }
            Ok(out)
        })
        .await;
        let Ok(rows) = found else {
            return Err(DiscoveryFailed {
                report,
                grants: Vec::new(),
            });
        };
        // Fresh time: a `Safe` observation of the gate, or none (uncertain: close).
        let gate = self.time_gate();
        let safe = match gate {
            Some(g) if !rows.is_empty() => g.check().await.ok(),
            _ => None,
        };
        for (c, bound) in rows {
            let usable = match (bound, gate, &safe) {
                (Some(bound), Some(gate), Some(safe)) => {
                    !dtime::is_expired(safe.wall(), bound)
                        && matches!(gate.admission(&c.grant, safe).await, Ok(Admission::Open))
                }
                _ => false,
            };
            if usable {
                report.kept.push(c.id.clone());
            } else {
                let outcome = self.close_one(&c).await;
                report.record(c.id.clone(), outcome);
            }
        }
        Ok(report)
    }

    /// Masters started here that exited by themselves (reaped, or no longer the process
    /// their start token names: exiting), and Windows dedicated rows whose process is
    /// gone (`Operations`' holder pass clears a Unix row with its holder; a Windows row
    /// names the registered `ssh.exe`, not the holder): rows `closed`, master resources
    /// absent, sockets removed under the slot lock while no newer generation owns the
    /// path.
    ///
    /// # Errors
    /// [`DiscoveryFailed`] (empty `grants`) when the Windows rows cannot be enumerated.
    pub async fn reap_pass(&self) -> PassResult {
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
            let path = PathBuf::from(&m.locator.control_path);
            if matches!(m.child.try_wait(), Ok(None)) {
                // Still running after all: keep it ours.
                self.live.lock().await.insert(path, m);
                continue;
            }
            let lock = self.slot_lock(&path);
            let _slot = lock.lock().await;
            let row = m.connection.clone();
            let now = Timestamp::now();
            let ok = txn(&self.store, move |tx| {
                move_row(tx, &row, OwnedConnectionState::Closed)?;
                resource_absent(tx, &row, now)
            })
            .await
            .is_ok();
            let _ = self
                .remove_stale_locked(&path, m.connection.generation, m.locator.inode)
                .await;
            if ok {
                report.closed.push(m.connection.id.clone());
            } else {
                report
                    .failed
                    .push((m.connection.id.clone(), refusal::STORE.to_owned()));
            }
        }
        if self.config.platform == Platform::Windows {
            let Ok(rows) = txn(&self.store, open_rows).await else {
                return Err(DiscoveryFailed {
                    report,
                    grants: Vec::new(),
                });
            };
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
        Ok(report)
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

    /// §17.20 item 14 (W3-Q1, option (a)): the master reuses exactly the foreground pin
    /// of `OWNED_LAUNCH_PINS`, then its own master options, then §17.19 item 4's identity
    /// options (the certificate as the identity file; never `key.pub` or
    /// `CertificateFile`).
    #[test]
    fn owned_launch_pins_prefix_and_master_argv_follow_the_ruling() {
        assert_eq!(
            heimdall_sshconf::render::OWNED_LAUNCH_PINS[0..2],
            ["-o", "ForkAfterAuthentication=no"]
        );
        let argv = master_argv(
            Path::new("/r/mux/d1"),
            "hm-d1",
            &EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: "/r/b/0123456789abcdef/agent.sock".into(),
            },
            Path::new("/r/b/0123456789abcdef/key.pub"),
            Path::new("/r/b/0123456789abcdef/cert-d1.pub"),
            &[OsString::from("-F"), OsString::from("/s/config")],
        )
        .unwrap();
        let words: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            words,
            [
                "-o",
                "ForkAfterAuthentication=no",
                "-M",
                "-N",
                "-o",
                "ControlMaster=yes",
                "-o",
                "ControlPersist=no",
                "-o",
                "ControlPath=\"/r/mux/d1\"",
                "-o",
                "IdentityAgent=\"/r/b/0123456789abcdef/agent.sock\"",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityFile=\"/r/b/0123456789abcdef/cert-d1.pub\"",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "BatchMode=yes",
                "-F",
                "/s/config",
                "--",
                "hm-d1",
            ]
        );
    }

    #[test]
    fn check_answers_parse_to_the_master_pid_only() {
        assert_eq!(parse_check_pid("Master running (pid=4242)\r\n"), Some(4242));
        assert_eq!(parse_check_pid("Master running (pid=1)\r\n"), None);
        assert_eq!(parse_check_pid("Master running (pid=12x)\r\n"), None);
        assert_eq!(
            parse_check_pid("Control socket connect(/r/mux/d1): refused"),
            None
        );
        assert_eq!(parse_check_pid(""), None);
        let a = check_argv(Path::new("/r/mux/d1"), "hm-d1", &[]).unwrap();
        assert_eq!(
            a,
            [
                "-O",
                "check",
                "-o",
                "ControlPath=\"/r/mux/d1\"",
                "--",
                "hm-d1"
            ]
            .map(OsString::from)
        );
    }
}
