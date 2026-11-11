//! The signing endpoints (ADR-0008 D2 item 2, D10 item 1; m03-plan U2
//! `EndpointRegistry`; reading R6): the environment endpoint, generation-tagged
//! binding endpoints, and per-operation verification endpoints implementing
//! `app::ports::VerificationEndpoints` (dropping a `VerificationSession` zeroizes
//! K_verify and removes the endpoint).
//!
//! **Names (R6), as pure functions** (U8 renders P from them):
//!
//! | Endpoint | Unix | Windows | Rendered in P |
//! |---|---|---|---|
//! | environment | `<runtime_dir>/signing.sock` | `\\.\pipe\heimdall-<installation token>-signing` | the Unix path; `//./pipe/heimdall-<token>-signing` |
//! | binding | `<runtime_dir>/b/<16 hex>/agent.sock` (dir 0700, socket 0600) | `\\.\pipe\heimdall-<token>-b<16 hex>` | — |
//! | verification | `<runtime_dir>/v/<16 hex>/agent.sock` | `\\.\pipe\heimdall-<token>-v<16 hex>` | — |
//!
//! The 16 hex characters are random ([`EndpointTag::generate`], the OS CSPRNG) and
//! never derived from an ID or a label (g03 §3.1 N2). The Windows token is the stable
//! per-installation `meta: windows_environment_pipe_token` (D10 item 1).
//!
//! **Transport.** Every endpoint reuses M01's listeners and peer checks
//! (`ipc::unix::Listener`: the owner-only 0700 directory, the 0600 socket, the
//! peer-UID check; `ipc::windows::Listener`: the protected owner-only DACL and the
//! client-SID check), and serves each connection through
//! `ipc::signing::serve_with_limits` with a [`ManagedSigner`]. A connection whose peer
//! is not the runtime's own principal is closed before any byte is read
//! ([`serve_connection`]). At most `MAX_SIGNING_CONNECTIONS` per endpoint.
//!
//! **Generations (R-RT-04).** A binding endpoint is a generation-tagged
//! `ManagedResource` of kind `Endpoint` ([`endpoint_resource`]); [`EndpointRegistry::remove`]
//! stops exactly the instance of that generation and locator, leaving a newer one.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::managed::{SigningGates, VerificationGate, VerificationScope};
use heimdall_app::ports::{
    AdapterError, ResourceCleaner, SignatureAuthority, SignerEndpoint, VerificationEndpoints,
    VerificationSession,
};
use heimdall_contract::Timestamp;
use heimdall_contract::enrollment::EnrollmentPlan;
use heimdall_contract::ids::{BindingId, OperationId, ResourceId};
use heimdall_contract::ipc::MAX_SIGNING_CONNECTIONS;
use heimdall_contract::provider::{EndpointKind as TransportKind, EndpointRef};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_domain::scope::AccessPair;
use heimdall_ipc::endpoint::{ExpectedOwner, PeerIdentity, verify_peer};
use heimdall_ipc::signing::{ServeLimits, Signer};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::signer::{ManagedSigner, SignHook, SignerLimits, VerificationCounters};
use crate::table::SignerTable;
use crate::vault::{RandomnessUnavailable, SystemRng};

// --- names (R6) -----------------------------------------------------------------

/// The number of hex characters of an endpoint tag.
pub const ENDPOINT_TAG_HEX: usize = 16;
/// The environment endpoint's file name in the runtime directory (M01's signing
/// endpoint).
pub const ENVIRONMENT_SOCKET: &str = "signing.sock";
/// The binding endpoints' directory under the runtime directory.
pub const BINDING_DIR: &str = "b";
/// The verification endpoints' directory under the runtime directory.
pub const VERIFICATION_DIR: &str = "v";
/// A binding or verification endpoint's socket file name.
pub const AGENT_SOCKET: &str = "agent.sock";
/// The Windows pipe-name prefix.
pub const PIPE_PREFIX: &str = r"\\.\pipe\heimdall-";
/// The Windows pipe-name prefix as P renders it (`/` separators; ADR-0008 D10 item 1).
pub const RENDERED_PIPE_PREFIX: &str = "//./pipe/heimdall-";
/// The longest installation token accepted in a pipe name.
pub const MAX_PIPE_TOKEN: usize = 64;

/// A random 16-lowercase-hex endpoint tag (ADR-0008 D2 item 2), never derived from an
/// ID or a label.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointTag(String);

impl EndpointTag {
    /// A fresh tag from the OS CSPRNG.
    ///
    /// # Errors
    /// [`RandomnessUnavailable`].
    pub fn generate() -> Result<EndpointTag, RandomnessUnavailable> {
        let mut b = [0u8; ENDPOINT_TAG_HEX / 2];
        SystemRng::fill(&mut b)?;
        let mut s = String::with_capacity(ENDPOINT_TAG_HEX);
        for byte in b {
            use std::fmt::Write as _;
            let _ = write!(s, "{byte:02x}");
        }
        Ok(EndpointTag(s))
    }

    /// Parse exactly 16 lowercase hex characters.
    #[must_use]
    pub fn parse(text: &str) -> Option<EndpointTag> {
        (text.len() == ENDPOINT_TAG_HEX
            && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then(|| EndpointTag(text.to_owned()))
    }

    /// The tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EndpointTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `token` may name Windows pipes: 1 to [`MAX_PIPE_TOKEN`] ASCII letters or
/// digits (a CSPRNG token; never a user name or label).
#[must_use]
pub fn pipe_token_ok(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_PIPE_TOKEN
        && token.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `<runtime_dir>/signing.sock`.
#[must_use]
pub fn environment_socket(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(ENVIRONMENT_SOCKET)
}

/// `<runtime_dir>/b/<tag>` (created 0700).
#[must_use]
pub fn binding_dir(runtime_dir: &Path, tag: &EndpointTag) -> PathBuf {
    runtime_dir.join(BINDING_DIR).join(tag.as_str())
}

/// `<runtime_dir>/b/<tag>/agent.sock` (0600).
#[must_use]
pub fn binding_socket(runtime_dir: &Path, tag: &EndpointTag) -> PathBuf {
    binding_dir(runtime_dir, tag).join(AGENT_SOCKET)
}

/// `<runtime_dir>/v/<tag>` (created 0700).
#[must_use]
pub fn verification_dir(runtime_dir: &Path, tag: &EndpointTag) -> PathBuf {
    runtime_dir.join(VERIFICATION_DIR).join(tag.as_str())
}

/// `<runtime_dir>/v/<tag>/agent.sock` (0600).
#[must_use]
pub fn verification_socket(runtime_dir: &Path, tag: &EndpointTag) -> PathBuf {
    verification_dir(runtime_dir, tag).join(AGENT_SOCKET)
}

/// `\\.\pipe\heimdall-<token>-signing`; `None` for an invalid token.
#[must_use]
pub fn environment_pipe(token: &str) -> Option<String> {
    pipe_token_ok(token).then(|| format!("{PIPE_PREFIX}{token}-signing"))
}

/// `\\.\pipe\heimdall-<token>-b<tag>`; `None` for an invalid token.
#[must_use]
pub fn binding_pipe(token: &str, tag: &EndpointTag) -> Option<String> {
    pipe_token_ok(token).then(|| format!("{PIPE_PREFIX}{token}-b{tag}"))
}

/// `\\.\pipe\heimdall-<token>-v<tag>`; `None` for an invalid token.
#[must_use]
pub fn verification_pipe(token: &str, tag: &EndpointTag) -> Option<String> {
    pipe_token_ok(token).then(|| format!("{PIPE_PREFIX}{token}-v{tag}"))
}

/// The environment pipe as P renders it: `//./pipe/heimdall-<token>-signing`
/// (ADR-0008 D10 item 1; F14); `None` for an invalid token.
#[must_use]
pub fn rendered_environment_pipe(token: &str) -> Option<String> {
    pipe_token_ok(token).then(|| format!("{RENDERED_PIPE_PREFIX}{token}-signing"))
}

/// Where one runtime's endpoints live: a Unix runtime directory or a Windows
/// installation token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointLayout {
    /// Unix sockets under the owner-only runtime directory (a UTF-8 path).
    Unix {
        /// The runtime directory.
        runtime_dir: PathBuf,
    },
    /// Windows named pipes named by the installation token.
    Windows {
        /// The installation token.
        token: String,
    },
}

impl EndpointLayout {
    /// The Unix layout; `None` when `runtime_dir` is not UTF-8 (a locator is a
    /// string).
    #[must_use]
    pub fn unix(runtime_dir: &Path) -> Option<EndpointLayout> {
        runtime_dir.to_str().map(|_| EndpointLayout::Unix {
            runtime_dir: runtime_dir.to_path_buf(),
        })
    }

    /// The Windows layout; `None` for an invalid token.
    #[must_use]
    pub fn windows(token: &str) -> Option<EndpointLayout> {
        pipe_token_ok(token).then(|| EndpointLayout::Windows {
            token: token.to_owned(),
        })
    }

    fn unix_ref(path: &Path) -> EndpointRef {
        EndpointRef {
            kind: TransportKind::UnixSocket,
            locator: path.to_string_lossy().into_owned(),
        }
    }

    fn pipe_ref(name: String) -> EndpointRef {
        EndpointRef {
            kind: TransportKind::NamedPipe,
            locator: name,
        }
    }

    /// The environment endpoint.
    #[must_use]
    pub fn environment(&self) -> EndpointRef {
        match self {
            EndpointLayout::Unix { runtime_dir } => {
                Self::unix_ref(&environment_socket(runtime_dir))
            }
            EndpointLayout::Windows { token } => {
                Self::pipe_ref(format!("{PIPE_PREFIX}{token}-signing"))
            }
        }
    }

    /// A binding endpoint for `tag`.
    #[must_use]
    pub fn binding(&self, tag: &EndpointTag) -> EndpointRef {
        match self {
            EndpointLayout::Unix { runtime_dir } => {
                Self::unix_ref(&binding_socket(runtime_dir, tag))
            }
            EndpointLayout::Windows { token } => {
                Self::pipe_ref(format!("{PIPE_PREFIX}{token}-b{tag}"))
            }
        }
    }

    /// A verification endpoint for `tag`.
    #[must_use]
    pub fn verification(&self, tag: &EndpointTag) -> EndpointRef {
        match self {
            EndpointLayout::Unix { runtime_dir } => {
                Self::unix_ref(&verification_socket(runtime_dir, tag))
            }
            EndpointLayout::Windows { token } => {
                Self::pipe_ref(format!("{PIPE_PREFIX}{token}-v{tag}"))
            }
        }
    }

    /// The environment endpoint as P renders it in `IdentityAgent`: the socket path
    /// on Unix, `//./pipe/heimdall-<token>-signing` on Windows.
    #[must_use]
    pub fn rendered_environment(&self) -> String {
        match self {
            EndpointLayout::Unix { runtime_dir } => environment_socket(runtime_dir)
                .to_string_lossy()
                .into_owned(),
            EndpointLayout::Windows { token } => {
                format!("{RENDERED_PIPE_PREFIX}{token}-signing")
            }
        }
    }

    /// The private directory a binding or verification endpoint creates (Unix only).
    fn endpoint_dir(&self, endpoint: &EndpointRef) -> Option<PathBuf> {
        match self {
            EndpointLayout::Unix { .. } => {
                Path::new(&endpoint.locator).parent().map(Path::to_path_buf)
            }
            EndpointLayout::Windows { .. } => None,
        }
    }
}

/// The generation-tagged `ManagedResource` of a binding endpoint (kind `Endpoint`,
/// owner the binding, the locator the socket path or pipe name; R-RT-04).
#[must_use]
pub fn endpoint_resource(
    id: ResourceId,
    binding: &BindingId,
    generation: ResourceGeneration,
    endpoint: &EndpointRef,
    updated_at: Timestamp,
) -> ManagedResource {
    ManagedResource {
        id,
        kind: ResourceKind::Endpoint,
        owner: OwnerRef::Binding {
            id: binding.clone(),
        },
        generation,
        desired: ResourceState::Present,
        observed: ResourceState::Present,
        last_operation: None,
        locator: endpoint.locator.clone(),
        updated_at,
    }
}

// --- errors ---------------------------------------------------------------------

/// Why an endpoint could not be created.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// No tag could be drawn.
    #[error("randomness unavailable")]
    RandomnessUnavailable,
    /// Not called inside a tokio runtime.
    #[error("no async runtime")]
    NoRuntime,
    /// The layout does not fit this platform (a Unix layout on Windows, or a Windows
    /// layout without a SID owner).
    #[error("endpoint layout unsupported on this platform")]
    Unsupported,
    /// The endpoint is already running.
    #[error("endpoint already running")]
    AlreadyRunning,
    /// The listener could not be bound (the bounded kind; no path is reported).
    #[error("endpoint could not be bound: {0:?}")]
    Bind(io::ErrorKind),
    /// K_verify could not be generated or registered.
    #[error("verification key unavailable")]
    Key,
    /// ⟨INT-Q13⟩ The operation's verification signing gate is already open (another
    /// session of the same operation is alive).
    #[error("verification gate already open")]
    GateOpen,
}

impl From<EndpointError> for AdapterError {
    fn from(e: EndpointError) -> Self {
        AdapterError::Unavailable(format!("signing endpoint: {e}"))
    }
}

// --- serving --------------------------------------------------------------------

/// Retry delay after a failed `accept`.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Whether a connection's transport-authenticated `peer` is the runtime's own
/// principal (M01's rule: only the same OS user).
#[must_use]
pub fn peer_admitted(peer: &PeerIdentity, owner: &ExpectedOwner) -> bool {
    verify_peer(peer, owner).is_ok()
}

/// Serve one accepted connection on `endpoint`: a peer that is not `owner` is
/// refused before a byte is read (the stream is dropped and
/// `ErrorKind::PermissionDenied` returned); otherwise the bounded framer runs with
/// `signer`.
///
/// # Errors
/// `PermissionDenied` for another principal; otherwise `serve_with_limits`' errors.
pub async fn serve_connection<S>(
    stream: S,
    peer: PeerIdentity,
    endpoint: EndpointRef,
    signer: Arc<dyn Signer>,
    owner: &ExpectedOwner,
    limits: ServeLimits,
    stop: CancellationToken,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if !peer_admitted(&peer, owner) {
        drop(stream);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "signing connection from another principal refused",
        ));
    }
    heimdall_ipc::signing::serve_with_limits(stream, peer, endpoint, signer, stop, limits).await
}

#[cfg(unix)]
type PlatformListener = heimdall_ipc::unix::Listener;
#[cfg(windows)]
type PlatformListener = heimdall_ipc::windows::Listener;

#[cfg(unix)]
fn bind_listener(
    layout: &EndpointLayout,
    endpoint: &EndpointRef,
    _owner: &ExpectedOwner,
) -> Result<PlatformListener, EndpointError> {
    if !matches!(layout, EndpointLayout::Unix { .. }) {
        return Err(EndpointError::Unsupported);
    }
    heimdall_ipc::unix::Listener::bind(
        Path::new(&endpoint.locator),
        heimdall_ipc::endpoint::EndpointKind::Signing,
    )
    .map_err(|e| EndpointError::Bind(e.kind()))
}

#[cfg(windows)]
fn bind_listener(
    layout: &EndpointLayout,
    endpoint: &EndpointRef,
    owner: &ExpectedOwner,
) -> Result<PlatformListener, EndpointError> {
    let (EndpointLayout::Windows { .. }, ExpectedOwner::Sid(sid)) = (layout, owner) else {
        return Err(EndpointError::Unsupported);
    };
    heimdall_ipc::windows::Listener::bind(
        &endpoint.locator,
        heimdall_ipc::endpoint::EndpointKind::Signing,
        sid,
    )
    .map_err(|e| EndpointError::Bind(e.kind()))
}

async fn accept_loop(
    listener: PlatformListener,
    endpoint: EndpointRef,
    signer: Arc<ManagedSigner>,
    owner: ExpectedOwner,
    limits: ServeLimits,
    stop: CancellationToken,
) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(_) => {
                        tokio::time::sleep(ACCEPT_RETRY).await;
                        continue;
                    }
                };
                if conns.len() >= MAX_SIGNING_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                let (e, s, o, st) = (endpoint.clone(), Arc::clone(&signer), owner.clone(), stop.child_token());
                conns.spawn(async move {
                    let _ = serve_connection(stream, peer, e, s, &o, limits, st).await;
                });
            }
        }
    }
    conns.abort_all();
    drop(listener);
}

/// One running endpoint: its accept loop and what to remove when it stops.
struct Running {
    endpoint: EndpointRef,
    signer: Arc<ManagedSigner>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    dir: Option<PathBuf>,
}

impl Running {
    /// Stop accepting, end every connection, remove the socket and its private
    /// directory (Unix). Synchronous; safe in `Drop`.
    fn stop(self) {
        self.stop.cancel();
        self.task.abort();
        remove_endpoint_files(&self.endpoint, self.dir.as_deref());
    }
}

#[cfg(unix)]
fn remove_endpoint_files(endpoint: &EndpointRef, dir: Option<&Path>) {
    use std::os::unix::fs::FileTypeExt;
    let path = Path::new(&endpoint.locator);
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = std::fs::remove_file(path);
    }
    if let Some(dir) = dir {
        // Only the empty, private directory this endpoint created.
        let _ = std::fs::remove_dir(dir);
    }
}

#[cfg(windows)]
fn remove_endpoint_files(_endpoint: &EndpointRef, _dir: Option<&Path>) {
    // Pipe instances end with their handles (the aborted accept loop).
}

// --- the registry ---------------------------------------------------------------

#[derive(Default)]
struct RegistryState {
    environment: Option<Running>,
    /// Binding → its endpoints by generation (a newer one may run beside an older
    /// one until the older one's cleanup removes it).
    bindings: HashMap<BindingId, BTreeMap<ResourceGeneration, Running>>,
}

struct RegistryInner {
    layout: EndpointLayout,
    owner: ExpectedOwner,
    table: SignerTable,
    authority: Arc<dyn SignatureAuthority>,
    limits: SignerLimits,
    shutdown: CancellationToken,
    hook: Option<Arc<dyn SignHook>>,
    /// ⟨INT-Q13⟩ The runtime's signing gates (`Operations::signing_gates`): each
    /// verification session opens its operation's verification gate here.
    gates: Option<SigningGates>,
    state: Mutex<RegistryState>,
}

impl RegistryInner {
    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn signer(&self, endpoint: SignerEndpoint) -> Arc<ManagedSigner> {
        let s = ManagedSigner::new(
            endpoint,
            self.table.clone(),
            Arc::clone(&self.authority),
            self.limits,
        );
        Arc::new(match &self.hook {
            Some(h) => s.with_hook(Arc::clone(h)),
            None => s,
        })
    }

    /// Bind `endpoint` and start its accept loop with `signer`.
    fn start(
        &self,
        endpoint: EndpointRef,
        signer: Arc<ManagedSigner>,
        owns_dir: bool,
    ) -> Result<Running, EndpointError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| EndpointError::NoRuntime)?;
        let listener = bind_listener(&self.layout, &endpoint, &self.owner)?;
        let stop = self.shutdown.child_token();
        let task = handle.spawn(accept_loop(
            listener,
            endpoint.clone(),
            Arc::clone(&signer),
            self.owner.clone(),
            self.limits.serve,
            stop.clone(),
        ));
        let dir = if owns_dir {
            self.layout.endpoint_dir(&endpoint)
        } else {
            None
        };
        Ok(Running {
            endpoint,
            signer,
            stop,
            task,
            dir,
        })
    }
}

/// The runtime's signing endpoints (ADR-0008 D2 item 2): the environment endpoint,
/// binding endpoints by generation, and verification endpoints. Cloning shares it.
#[derive(Clone)]
pub struct EndpointRegistry {
    inner: Arc<RegistryInner>,
}

impl std::fmt::Debug for EndpointRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.inner.lock();
        f.debug_struct("EndpointRegistry")
            .field("layout", &self.inner.layout)
            .field("environment", &s.environment.is_some())
            .field("bindings", &s.bindings.len())
            .finish_non_exhaustive()
    }
}

impl EndpointRegistry {
    /// A registry for `layout`, accepting only `owner`, signing from `table` under
    /// `authority`. Every endpoint stops when `shutdown` is cancelled.
    #[must_use]
    pub fn new(
        layout: EndpointLayout,
        owner: ExpectedOwner,
        table: SignerTable,
        authority: Arc<dyn SignatureAuthority>,
        limits: SignerLimits,
        shutdown: CancellationToken,
    ) -> EndpointRegistry {
        EndpointRegistry {
            inner: Arc::new(RegistryInner {
                layout,
                owner,
                table,
                authority,
                limits,
                shutdown,
                hook: None,
                gates: None,
                state: Mutex::new(RegistryState::default()),
            }),
        }
    }

    /// The same registry with a test-only pause hook on every signer it creates from
    /// now on. Call before creating any endpoint.
    #[must_use]
    pub fn with_hook(self, hook: Arc<dyn SignHook>) -> EndpointRegistry {
        let inner = &self.inner;
        EndpointRegistry {
            inner: Arc::new(RegistryInner {
                layout: inner.layout.clone(),
                owner: inner.owner.clone(),
                table: inner.table.clone(),
                authority: Arc::clone(&inner.authority),
                limits: inner.limits,
                shutdown: inner.shutdown.clone(),
                hook: Some(hook),
                gates: inner.gates.clone(),
                state: Mutex::new(RegistryState::default()),
            }),
        }
    }

    /// ⟨INT-Q13; ADR-0008 §17.19 item 5⟩ The same registry, opening each verification
    /// session's **verification signing gate** in `gates` (the runtime passes
    /// `Operations::signing_gates()`). The gate opens in [`Self::create_verification`]
    /// with the plan's CA and pair and closes when the session is dropped; the
    /// production `SignatureAuthority` admits a verification signature only through
    /// it. Without gates (a registry built for a fixture authority) no gate is opened,
    /// so the production authority refuses every verification signature (fail
    /// closed). Call before creating any endpoint.
    #[must_use]
    pub fn with_verification_gates(self, gates: SigningGates) -> EndpointRegistry {
        let inner = &self.inner;
        EndpointRegistry {
            inner: Arc::new(RegistryInner {
                layout: inner.layout.clone(),
                owner: inner.owner.clone(),
                table: inner.table.clone(),
                authority: Arc::clone(&inner.authority),
                limits: inner.limits,
                shutdown: inner.shutdown.clone(),
                hook: inner.hook.clone(),
                gates: Some(gates),
                state: Mutex::new(RegistryState::default()),
            }),
        }
    }

    /// The signer table.
    #[must_use]
    pub fn table(&self) -> &SignerTable {
        &self.inner.table
    }

    /// The layout.
    #[must_use]
    pub fn layout(&self) -> &EndpointLayout {
        &self.inner.layout
    }

    /// The environment endpoint's locator (bound or not).
    #[must_use]
    pub fn environment(&self) -> EndpointRef {
        self.inner.layout.environment()
    }

    /// Bind the environment endpoint and serve it (at runtime start).
    ///
    /// # Errors
    /// [`EndpointError`]; nothing runs.
    pub fn start_environment(&self) -> Result<EndpointRef, EndpointError> {
        let endpoint = self.environment();
        if self.inner.lock().environment.is_some() {
            return Err(EndpointError::AlreadyRunning);
        }
        let signer = self.inner.signer(SignerEndpoint::Environment);
        let running = self.inner.start(endpoint.clone(), signer, false)?;
        let mut s = self.inner.lock();
        if s.environment.is_some() {
            drop(s);
            running.stop();
            return Err(EndpointError::AlreadyRunning);
        }
        s.environment = Some(running);
        Ok(endpoint)
    }

    /// Create binding `binding`'s endpoint at `generation`, at a fresh random path
    /// (ADR-0008 D2 item 2): it lists and signs for the grant the binding is attached
    /// to in the table ([`SignerTable::attach_binding`]), and nothing while it is not.
    /// Record it as [`endpoint_resource`]; [`Self::remove`] removes it by generation.
    ///
    /// # Errors
    /// [`EndpointError`]; nothing runs.
    pub fn create_binding(
        &self,
        binding: &BindingId,
        generation: ResourceGeneration,
    ) -> Result<EndpointRef, EndpointError> {
        if self
            .inner
            .lock()
            .bindings
            .get(binding)
            .is_some_and(|g| g.contains_key(&generation))
        {
            return Err(EndpointError::AlreadyRunning);
        }
        let tag = EndpointTag::generate().map_err(|_| EndpointError::RandomnessUnavailable)?;
        let endpoint = self.inner.layout.binding(&tag);
        let signer = self.inner.signer(SignerEndpoint::Binding(binding.clone()));
        let running = self.inner.start(endpoint.clone(), signer, true)?;
        let mut s = self.inner.lock();
        let gens = s.bindings.entry(binding.clone()).or_default();
        if gens.contains_key(&generation) {
            drop(s);
            running.stop();
            return Err(EndpointError::AlreadyRunning);
        }
        gens.insert(generation, running);
        Ok(endpoint)
    }

    /// The newest running endpoint of `binding`, with its generation.
    #[must_use]
    pub fn binding_endpoint(
        &self,
        binding: &BindingId,
    ) -> Option<(EndpointRef, ResourceGeneration)> {
        self.inner
            .lock()
            .bindings
            .get(binding)
            .and_then(|g| g.iter().next_back())
            .map(|(g, r)| (r.endpoint.clone(), *g))
    }

    /// The signer behind a running endpoint (the newest generation for a binding), for
    /// inspection.
    #[must_use]
    pub fn signer(&self, endpoint: &SignerEndpoint) -> Option<Arc<ManagedSigner>> {
        let s = self.inner.lock();
        match endpoint {
            SignerEndpoint::Environment => s.environment.as_ref().map(|r| Arc::clone(&r.signer)),
            SignerEndpoint::Binding(b) => s
                .bindings
                .get(b)
                .and_then(|g| g.values().next_back())
                .map(|r| Arc::clone(&r.signer)),
            _ => None,
        }
    }

    /// Remove the endpoint `resource` names, **generation-bound** (R-RT-04): only the
    /// binding endpoint of exactly that generation and locator is stopped and its
    /// socket and directory removed; a newer generation is left untouched. A resource
    /// that is not a binding endpoint, or one already gone, is `Ok` (nothing of that
    /// generation remains). Idempotent.
    ///
    /// # Errors
    /// None today; the signature follows `ResourceCleaner`.
    pub fn remove(&self, resource: &ManagedResource) -> Result<(), AdapterError> {
        let (ResourceKind::Endpoint, OwnerRef::Binding { id }) = (resource.kind, &resource.owner)
        else {
            return Ok(());
        };
        let running = {
            let mut s = self.inner.lock();
            let Some(gens) = s.bindings.get_mut(id) else {
                return Ok(());
            };
            if !gens
                .get(&resource.generation)
                .is_some_and(|r| r.endpoint.locator == resource.locator)
            {
                return Ok(());
            }
            let running = gens.remove(&resource.generation);
            if gens.is_empty() {
                s.bindings.remove(id);
            }
            running
        };
        if let Some(r) = running {
            r.stop();
        }
        Ok(())
    }

    /// Stop every endpoint (runtime stop). Verification sessions stop when dropped.
    pub fn stop_all(&self) {
        let (env, bindings) = {
            let mut s = self.inner.lock();
            (s.environment.take(), std::mem::take(&mut s.bindings))
        };
        if let Some(r) = env {
            r.stop();
        }
        for r in bindings.into_values().flat_map(BTreeMap::into_values) {
            r.stop();
        }
    }

    /// Create `operation`'s verification endpoint with a fresh K_verify (ADR-0008 D5
    /// §6.5 item 1; the `VerificationEndpoints` port), bound to the plan's CA and pair
    /// (`scope`; §17.19 item 5: every certificate it installs must be signed by that
    /// CA, and the positive one must name that pair). With [`Self::with_verification_gates`]
    /// it also opens the operation's verification signing gate. The key, the gate and
    /// the endpoint end when the returned session is dropped.
    ///
    /// # Errors
    /// [`EndpointError`]; no key, no gate and no endpoint are left behind.
    pub fn create_verification(
        &self,
        operation: &OperationId,
        scope: &VerificationScope,
    ) -> Result<VerificationEndpoint, EndpointError> {
        let table = &self.inner.table;
        let gate = match &self.inner.gates {
            Some(g) => Some(
                g.open_verification(operation, scope.clone())
                    .map_err(|_| EndpointError::GateOpen)?,
            ),
            None => None,
        };
        let info = table
            .register_verification(operation, scope)
            .map_err(|_| EndpointError::Key)?;
        let started = (|| {
            let tag = EndpointTag::generate().map_err(|_| EndpointError::RandomnessUnavailable)?;
            let endpoint = self.inner.layout.verification(&tag);
            let signer = self
                .inner
                .signer(SignerEndpoint::Verification(operation.clone()));
            self.inner.start(endpoint, signer, true)
        })();
        let running = match started {
            Ok(r) => r,
            Err(e) => {
                table.destroy_verification(operation);
                return Err(e);
            }
        };
        let Some(counters) = running.signer.counters().map(Arc::clone) else {
            running.stop();
            table.destroy_verification(operation);
            return Err(EndpointError::Key);
        };
        Ok(VerificationEndpoint {
            operation: operation.clone(),
            table: table.clone(),
            public_line: info.openssh_line.clone(),
            fingerprint: info.fingerprint,
            endpoint: running.endpoint.clone(),
            counters,
            gate: Mutex::new(gate),
            running: Mutex::new(Some(running)),
        })
    }
}

/// ⟨INT-Q13⟩ The plan's CA and pair (`ca_fingerprint`, `destination_id`/`account`).
#[must_use]
pub fn verification_scope(plan: &EnrollmentPlan) -> VerificationScope {
    VerificationScope {
        ca: plan.ca_fingerprint.clone(),
        pair: AccessPair {
            destination: plan.destination_id.clone(),
            account: plan.account.clone(),
        },
    }
}

#[async_trait]
impl VerificationEndpoints for EndpointRegistry {
    async fn create(
        &self,
        operation: &OperationId,
        plan: &EnrollmentPlan,
    ) -> Result<Box<dyn VerificationSession>, AdapterError> {
        Ok(Box::new(self.create_verification(
            operation,
            &verification_scope(plan),
        )?))
    }
}

#[async_trait]
impl ResourceCleaner for EndpointRegistry {
    async fn delete(&self, resource: &ManagedResource) -> Result<(), AdapterError> {
        self.remove(resource)
    }
}

/// One operation's verification endpoint (ADR-0008 D5 §6.5; `VerificationSession`).
/// Dropping it zeroizes K_verify and removes the endpoint.
pub struct VerificationEndpoint {
    operation: OperationId,
    table: SignerTable,
    public_line: String,
    fingerprint: String,
    endpoint: EndpointRef,
    counters: Arc<VerificationCounters>,
    /// ⟨INT-Q13⟩ The operation's open verification gate (closed first on drop).
    gate: Mutex<Option<VerificationGate>>,
    running: Mutex<Option<Running>>,
}

impl std::fmt::Debug for VerificationEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationEndpoint")
            .field("operation", &self.operation)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl VerificationEndpoint {
    /// K_verify's `SHA256:` fingerprint (what [`VerificationSession::signatures`] is
    /// asked for).
    #[must_use]
    pub fn key_fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The operation.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// The signer behind the endpoint, for inspection.
    #[must_use]
    pub fn signer(&self) -> Option<Arc<ManagedSigner>> {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|r| Arc::clone(&r.signer))
    }
}

impl VerificationSession for VerificationEndpoint {
    fn public_key(&self) -> &str {
        &self.public_line
    }

    fn install(&self, certificate_line: &str) -> Result<(), AdapterError> {
        let cert = ssh_key::Certificate::from_openssh(certificate_line.trim()).map_err(|_| {
            AdapterError::Protocol("verification certificate unreadable".to_owned())
        })?;
        self.table
            .install_verification(&self.operation, &cert)
            .map_err(|e| {
                AdapterError::Protocol(format!("verification certificate refused: {}", e.code()))
            })
    }

    fn locator(&self) -> &EndpointRef {
        &self.endpoint
    }

    fn signatures(&self, key_fingerprint: &str) -> u32 {
        self.counters.signatures(key_fingerprint)
    }

    fn session_binds(&self) -> u32 {
        self.counters.session_binds()
    }
}

impl Drop for VerificationEndpoint {
    fn drop(&mut self) {
        // ⟨INT-Q13⟩ The gate first: no signature is admitted or released from here.
        drop(
            self.gate
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        self.table.destroy_verification(&self.operation);
        let running = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(r) = running {
            r.stop();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_r6() {
        let tag = EndpointTag::parse("0123456789abcdef").unwrap();
        let dir = Path::new("/run/h");
        assert_eq!(environment_socket(dir), Path::new("/run/h/signing.sock"));
        assert_eq!(
            binding_socket(dir, &tag),
            Path::new("/run/h/b/0123456789abcdef/agent.sock")
        );
        assert_eq!(
            verification_socket(dir, &tag),
            Path::new("/run/h/v/0123456789abcdef/agent.sock")
        );
        assert_eq!(
            environment_pipe("Tok3n").unwrap(),
            r"\\.\pipe\heimdall-Tok3n-signing"
        );
        assert_eq!(
            binding_pipe("Tok3n", &tag).unwrap(),
            r"\\.\pipe\heimdall-Tok3n-b0123456789abcdef"
        );
        assert_eq!(
            verification_pipe("Tok3n", &tag).unwrap(),
            r"\\.\pipe\heimdall-Tok3n-v0123456789abcdef"
        );
        assert_eq!(
            rendered_environment_pipe("Tok3n").unwrap(),
            "//./pipe/heimdall-Tok3n-signing"
        );
        assert!(environment_pipe("bad token").is_none());
        assert!(environment_pipe("").is_none());
        assert!(EndpointTag::parse("0123456789ABCDEF").is_none());
        assert!(EndpointTag::parse("0123").is_none());
        let w = EndpointLayout::windows("Tok3n").unwrap();
        assert_eq!(w.environment().locator, r"\\.\pipe\heimdall-Tok3n-signing");
        assert_eq!(w.rendered_environment(), "//./pipe/heimdall-Tok3n-signing");
        assert_eq!(
            w.binding(&tag).locator,
            r"\\.\pipe\heimdall-Tok3n-b0123456789abcdef"
        );
    }

    #[test]
    fn tags_are_random_hex() {
        let a = EndpointTag::generate().unwrap();
        let b = EndpointTag::generate().unwrap();
        assert_ne!(a, b);
        assert!(EndpointTag::parse(a.as_str()).is_some());
    }
}
