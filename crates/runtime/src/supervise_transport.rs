//! ⟨M06 U56⟩ The Iroh serve child's supervision and the runtime's admission authority
//! (ADR-0012 §2.3), the K_iroh custody adapters (§2.4) and the route helper's Iroh leg (§5.5;
//! m06-plan U56).
//!
//! **The serve child** is a separate process of the same binary (`heimdall transport serve`,
//! §1 item 1; the hidden CLI entry is the integrator's: it calls [`serve_child_stdio`]). Its
//! standard input and output are the **supervision channel**: newline-delimited JSON
//! ([`ToChild`], [`FromChild`]), each line at most [`MAX_LINE`] bytes. The child holds no
//! authority of its own: it admits and forwards only under a lease for the runtime's current
//! **admission authority generation** (`remote_authority_generation`, ruling W0C-Q4), which
//! moves on every change that narrows remote admission (a client tombstone, role narrowing,
//! transport disable, exposure narrowing, K_iroh rotation or removal) and commits before
//! the change counts as applied (RC-R02).
//!
//! * **Start** (§2.3 item 5): [`TransportSupervisor::start`] reads the authority from durable
//!   state in one transaction ([`read_authority`]): the generation, the active K_iroh
//!   reference and the endpoint's policy, and the allowlist rebuilt from the enrolled
//!   clients' endpoint IDs **excluding every tombstone** (only `active` clients of the role
//!   table). Unreadable state (corrupt or unavailable) starts nothing
//!   (`transport_authority_lost`). Then a new child starts under that generation; admission
//!   resumes only once it reports `ready` for the K_iroh the record names. After a restart
//!   this is the closure replay: a revoked endpoint is never on a new child's allowlist.
//! * **Every admission** in the child checks its lease (the transport's lease gate, on every
//!   accept, every signal and a 100 ms watchdog): the lease is the generation the runtime
//!   granted and the child acknowledged; an endpoint is admitted only when the runtime's
//!   committed generation equals it and the endpoint is admitted there.
//! * **Narrowing** ([`TransportSupervisor::apply_narrowing`], §2.3 item 4): after the commit,
//!   the supervisor re-reads the authority and sends `suspend` for the new generation with
//!   the endpoints whose admission was withdrawn (possibly none, which only moves the lease).
//!   The child closes their live connections, waits for their sessions (stream and target
//!   socket) to end, and acknowledges. Without a complete acknowledgement within
//!   [`SupervisorConfig::ack_bound`] the supervisor stops the child **by its exact
//!   supervised PID** (the process handle it spawned and has not reaped) and confirms it is
//!   gone. Only then is the change reported [`AdmissionReport::Applied`]; meanwhile
//!   [`TransportSupervisor::admission`] reports `remote_pending` with
//!   `iroh_admission_closing`. A withdrawn key or a changed policy replaces the child.
//! * **Lease loss** (§2.3 item 3): the child's input reaching EOF (the runtime exited or was
//!   killed: the pipe closes with it) is a lost lease: every stream closes at once, the
//!   endpoint closes within 1 s and the child exits. An orphan never keeps admitting.
//! * **The watchdog** ([`TransportSupervisor::spawn_watch`]) re-reads the durable generation
//!   every [`SupervisorConfig::watch_interval`] and applies any change no caller reported, so
//!   a narrowing committed by any path reaches the child; a child that exited on its own is
//!   restarted from durable state.
//!
//! **K_iroh** stays in the verified platform store (`heimdall_credential::iroh`):
//! [`StoreKeySource`] gives the transport the key for one endpoint and [`CredentialKeys`] is
//! the application's [`TransportKeys`]. With no verified store, a persistent endpoint is
//! unavailable for serving and dialing (`transport_key_store_unavailable`, plus the doctor
//! finding `heimdall_credential::iroh::doctor_finding`); direct and bastion routes are
//! unaffected.
//!
//! **The route helper's Iroh leg** ([`IrohRouteLeg`], feature `iroh`) implements
//! `heimdall_app::routes::legs::IrohLegDialer` over the transport's dialer, with the route's
//! exposure policy and recorded direct addresses only.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::OpError;
use heimdall_app::transport::{
    AdmissionReport, KeyStoreRefusal, NewTransportKey, ServeControl, TransportKeyRecord,
    TransportKeys, endpoint_state,
};
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{ClientId, IrohEndpointId};
use heimdall_contract::route::ExposurePolicy;
use heimdall_credential::iroh::{IrohKeyStore, IrohStoreAvailability, IrohStoreError};
use heimdall_store::ext_m06::ClientState;
use heimdall_store::{Store, Txn};
use heimdall_transport_iroh::admission::{
    AdmissionAuthority, AdmissionSignal, AuthorityGeneration, LeaseLoss, LeaseState, SuspendAck,
    SuspendRequest,
};
use heimdall_transport_iroh::keys::{IrohSecret, KeySource, KeySourceError};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// The supervision protocol's name and version, sent in [`ToChild::Start`].
pub const PROTOCOL: &str = "heimdall-transport-serve/1";

/// The longest supervision line accepted, newline included.
pub const MAX_LINE: usize = 1024 * 1024;

// --- the supervision protocol ---------------------------------------------------------------

/// Where K_iroh lives (a reference: the transport key row's columns, never the key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRef {
    /// The endpoint ID the key authenticates as.
    pub endpoint: IrohEndpointId,
    /// The platform store's kind.
    pub store_kind: String,
    /// The item's nonsecret locator.
    pub store_ref: String,
}

/// A message from the runtime to the serve child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToChild {
    /// The first message: the child's whole configuration and its first lease.
    Start {
        /// [`PROTOCOL`].
        protocol: String,
        /// The lease's generation.
        generation: u64,
        /// The enrolled clients' endpoint IDs (fixed for the child's life).
        allowlist: Vec<IrohEndpointId>,
        /// The endpoint's exposure policy.
        policy: ExposurePolicy,
        /// The loopback target, `127.0.0.1:<port>` or `[::1]:<port>`.
        target: String,
        /// Where K_iroh lives.
        key: KeyRef,
    },
    /// Suspend `endpoints` (possibly none), close their streams, take the lease for
    /// `generation`, acknowledge.
    Suspend {
        /// The committed generation.
        generation: u64,
        /// The endpoints whose admission was withdrawn.
        endpoints: Vec<IrohEndpointId>,
    },
}

/// A message from the serve child to the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum FromChild {
    /// Bound and admitting under `generation`.
    Ready {
        /// The serving endpoint's ID.
        endpoint: IrohEndpointId,
        /// The lease's generation.
        generation: u64,
        /// The sockets the endpoint bound (`ip:port`): what a route record's direct
        /// addresses name.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        addresses: Vec<String>,
    },
    /// Not started: the reason token.
    Refused {
        /// The reason.
        reason: String,
        /// ⟨M06 W3; ADR-0012 §2.1 ⟨2026-11-21⟩⟩ The serve port the endpoint could not bind
        /// (the policy's, or the one recorded at the first bind): `transport_unavailable`,
        /// and no other port is tried.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unbindable_port: Option<u16>,
    },
    /// A suspend's acknowledgement.
    Suspended {
        /// The generation the child now holds its lease for.
        generation: u64,
        /// Live connections closed.
        closed: usize,
        /// Every closed session ended within the child's bound.
        complete: bool,
    },
    /// The child is exiting: the reason token.
    Exiting {
        /// The reason.
        reason: String,
    },
}

/// Why a supervision line was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LineError {
    /// The channel reached EOF.
    Eof,
    /// A line longer than [`MAX_LINE`], or not one message.
    Malformed,
    /// The channel failed.
    Io,
}

/// Read one message (bounded at [`MAX_LINE`]).
///
/// # Errors
/// [`LineError`].
pub async fn read_message<R, T>(reader: &mut R) -> Result<T, LineError>
where
    R: AsyncBufRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut line = Vec::new();
    let mut limited =
        tokio::io::AsyncReadExt::take(&mut *reader, u64::try_from(MAX_LINE).unwrap_or(u64::MAX));
    let n = limited
        .read_until(b'\n', &mut line)
        .await
        .map_err(|_| LineError::Io)?;
    if n == 0 {
        return Err(LineError::Eof);
    }
    if line.last() != Some(&b'\n') {
        return Err(LineError::Malformed);
    }
    serde_json::from_slice(&line).map_err(|_| LineError::Malformed)
}

/// Write one message and flush.
///
/// # Errors
/// [`LineError::Io`].
pub async fn write_message<W, T>(writer: &mut W, message: &T) -> Result<(), LineError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_vec(message).map_err(|_| LineError::Malformed)?;
    line.push(b'\n');
    writer.write_all(&line).await.map_err(|_| LineError::Io)?;
    writer.flush().await.map_err(|_| LineError::Io)
}

// --- the child's admission authority ------------------------------------------------------

#[derive(Debug)]
struct ChildView {
    /// The runtime's committed generation (moved by each suspend).
    committed: AuthorityGeneration,
    /// The generation the child acknowledged (the lease).
    granted: AuthorityGeneration,
    admitted: BTreeSet<IrohEndpointId>,
    lost: Option<LeaseLoss>,
}

/// The serve child's [`AdmissionAuthority`], fed by the supervision channel: it mirrors the
/// runtime's committed generation and admitted set, and reports the lease the child
/// acknowledged. It holds no authority of its own.
#[derive(Debug)]
pub struct ChildAuthority {
    view: Mutex<ChildView>,
    signals: tokio::sync::Mutex<mpsc::UnboundedReceiver<AdmissionSignal>>,
    tx: mpsc::UnboundedSender<AdmissionSignal>,
}

impl ChildAuthority {
    /// An authority holding a lease for `generation` that admits `admitted`.
    #[must_use]
    pub fn new(generation: u64, admitted: impl IntoIterator<Item = IrohEndpointId>) -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            view: Mutex::new(ChildView {
                committed: AuthorityGeneration(generation),
                granted: AuthorityGeneration(generation),
                admitted: admitted.into_iter().collect(),
                lost: None,
            }),
            signals: tokio::sync::Mutex::new(rx),
            tx,
        })
    }

    fn view(&self) -> std::sync::MutexGuard<'_, ChildView> {
        self.view.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A `suspend` arrived: the committed generation moves (never back) and `endpoints`
    /// stop being admitted at once; the server is told to close their streams. Resolves
    /// with the server's report once it acknowledged, the lease moved to its generation.
    pub async fn suspend(
        &self,
        generation: u64,
        endpoints: Vec<IrohEndpointId>,
    ) -> Option<heimdall_transport_iroh::admission::SuspendReport> {
        let generation = {
            let mut v = self.view();
            if AuthorityGeneration(generation) > v.committed {
                v.committed = AuthorityGeneration(generation);
            }
            for e in &endpoints {
                v.admitted.remove(e);
            }
            v.committed
        };
        let (ack, rx) = SuspendAck::channel();
        self.tx
            .send(AdmissionSignal::Suspend(SuspendRequest {
                generation,
                endpoints,
                ack,
            }))
            .ok()?;
        let report = rx.await.ok()?;
        let mut v = self.view();
        if report.generation > v.granted {
            v.granted = report.generation;
        }
        Some(report)
    }

    /// The lease is lost for good (channel EOF or a protocol violation).
    pub fn lose(&self, loss: LeaseLoss) {
        self.view().lost = Some(loss);
        let _ = self.tx.send(AdmissionSignal::LeaseLost(loss));
    }
}

impl AdmissionAuthority for ChildAuthority {
    fn lease(&self) -> LeaseState {
        let v = self.view();
        match v.lost {
            Some(loss) => LeaseState::Lost(loss),
            None => LeaseState::Held(v.granted),
        }
    }

    fn is_admitted(&self, generation: AuthorityGeneration, endpoint: &IrohEndpointId) -> bool {
        let v = self.view();
        v.lost.is_none() && v.committed == generation && v.admitted.contains(endpoint)
    }

    async fn next_signal(&self) -> AdmissionSignal {
        let mut rx = self.signals.lock().await;
        match rx.recv().await {
            Some(signal) => signal,
            None => AdmissionSignal::LeaseLost(LeaseLoss::ChannelClosed),
        }
    }
}

// --- K_iroh custody adapters ----------------------------------------------------------------

/// The transport's [`KeySource`] for one endpoint's K_iroh in a platform store: loaded per
/// endpoint, never written anywhere else, and refused unless it authenticates as that
/// endpoint.
#[derive(Clone)]
pub struct StoreKeySource {
    store: Arc<dyn IrohKeyStore>,
    endpoint: IrohEndpointId,
}

impl std::fmt::Debug for StoreKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreKeySource")
            .field("store", &self.store.kind())
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl StoreKeySource {
    /// The key of `endpoint` in `store`.
    #[must_use]
    pub fn new(store: Arc<dyn IrohKeyStore>, endpoint: IrohEndpointId) -> Self {
        Self { store, endpoint }
    }
}

/// The transport's error for a store error (every one is `transport_key_store_unavailable`).
#[must_use]
pub fn key_source_error(e: &IrohStoreError) -> KeySourceError {
    match e {
        IrohStoreError::Unavailable(
            IrohStoreAvailability::Locked | IrohStoreAvailability::InteractionNotAllowed,
        ) => KeySourceError::Locked,
        IrohStoreError::NotFound => KeySourceError::Missing,
        IrohStoreError::Corrupt | IrohStoreError::Unavailable(IrohStoreAvailability::Corrupt) => {
            KeySourceError::Corrupt
        }
        _ => KeySourceError::StoreUnavailable,
    }
}

impl KeySource for StoreKeySource {
    fn load(&self) -> Result<IrohSecret, KeySourceError> {
        let key = self
            .store
            .load(&self.endpoint)
            .map_err(|e| key_source_error(&e))?;
        Ok(IrohSecret::from_bytes(*key.expose()))
    }
}

/// The application's [`TransportKeys`] over a platform store.
#[derive(Clone)]
pub struct CredentialKeys(pub Arc<dyn IrohKeyStore>);

impl std::fmt::Debug for CredentialKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CredentialKeys")
            .field(&self.0.kind())
            .finish()
    }
}

impl TransportKeys for CredentialKeys {
    fn create(&self) -> Result<NewTransportKey, KeyStoreRefusal> {
        let endpoint = heimdall_credential::iroh::create_key(self.0.as_ref())
            .map_err(|e| KeyStoreRefusal { detail: e.detail() })?;
        Ok(NewTransportKey {
            store_kind: self.0.kind().column().to_owned(),
            store_ref: self.0.store_ref(&endpoint),
            endpoint,
        })
    }

    fn destroy(&self, key: &TransportKeyRecord) -> Result<(), KeyStoreRefusal> {
        if key.store_kind != self.0.kind().column() {
            // Another store's item: never destroyed through this one.
            return Err(KeyStoreRefusal {
                detail: "unsupported",
            });
        }
        match self.0.destroy(&key.endpoint) {
            Ok(()) | Err(IrohStoreError::NotFound) => Ok(()),
            Err(e) => Err(KeyStoreRefusal { detail: e.detail() }),
        }
    }
}

// --- the authority, read from durable state --------------------------------------------------

/// The serve allowlist's source: the enrolled clients' Iroh endpoint IDs, read inside the
/// authority's transaction. ⟨U56 DONE Q1⟩ The schema records no client endpoint ID yet; the
/// default ([`NoPeerEndpoints`]) has none, so nothing is served (fail closed).
pub trait PeerEndpoints: Send + Sync {
    /// Every enrolled `(client, endpoint)` pair (tombstones are excluded by the caller).
    ///
    /// # Errors
    /// The store's; any error is a lost authority (`transport_authority_lost`).
    fn enrolled(&self, tx: &mut Txn<'_>)
    -> heimdall_store::Result<Vec<(ClientId, IrohEndpointId)>>;
}

/// No client endpoint is recorded (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPeerEndpoints;

impl PeerEndpoints for NoPeerEndpoints {
    fn enrolled(&self, _: &mut Txn<'_>) -> heimdall_store::Result<Vec<(ClientId, IrohEndpointId)>> {
        Ok(Vec::new())
    }
}

/// What serving needs from durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServePlan {
    /// Where K_iroh lives.
    pub key: KeyRef,
    /// The endpoint's exposure policy (as consented).
    pub policy: ExposurePolicy,
    /// ⟨M06 W3; ADR-0012 §2.1 ⟨2026-11-21⟩⟩ The serve port recorded at the first successful
    /// bind (`Txn::transport_serve_port`), used when the policy names none.
    pub recorded_port: Option<u16>,
}

impl ServePlan {
    /// The policy the child binds: the consented one, with the recorded port when it names
    /// none (`None` before the first bind: any port, then recorded).
    #[must_use]
    pub fn effective_policy(&self) -> ExposurePolicy {
        let mut policy = self.policy.clone();
        if policy.port.is_none() {
            policy.port = self.recorded_port;
        }
        policy
    }

    /// ⟨M06 W5; ADR-0012 §2.3 item 2 ⟨2026-11-22⟩⟩ The one target the child forwards to:
    /// `127.0.0.1` (fixed, never configuration) and the consented policy's `sshd_port`.
    #[must_use]
    pub fn target(&self) -> String {
        format!("{SERVE_TARGET_HOST}:{}", self.policy.sshd_port)
    }
}

/// The serve target's host (ADR-0012 §2.3 item 2): never configurable.
pub const SERVE_TARGET_HOST: std::net::Ipv4Addr = std::net::Ipv4Addr::LOCALHOST;

/// ⟨M06 W5; ADR-0006 §18.9 item 1⟩ The serve child's target check: `target` must be exactly
/// [`SERVE_TARGET_HOST`] and the port `policy` names (never `0`). Anything else is not what
/// the owner consented to, whoever sent it.
///
/// # Errors
/// `transport_unavailable`.
pub fn checked_target(
    policy: &ExposurePolicy,
    target: &str,
) -> Result<std::net::SocketAddr, &'static str> {
    let addr: std::net::SocketAddr = target.parse().map_err(|_| reason::TRANSPORT_UNAVAILABLE)?;
    let wanted = std::net::SocketAddr::from((SERVE_TARGET_HOST, policy.sshd_port));
    if !policy.sshd_port_is_valid() || addr != wanted {
        return Err(reason::TRANSPORT_UNAVAILABLE);
    }
    Ok(addr)
}

/// The IPv4 port first, else any, of the sockets a child reported bound (`ip:port`).
fn bound_port(addresses: &[String]) -> Option<u16> {
    let sockets: Vec<std::net::SocketAddr> =
        addresses.iter().filter_map(|a| a.parse().ok()).collect();
    sockets
        .iter()
        .find(|s| s.is_ipv4())
        .or_else(|| sockets.first())
        .map(std::net::SocketAddr::port)
        .filter(|p| *p != 0)
}

/// The admission authority as durable state has it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    /// `remote_authority_generation`.
    pub generation: u64,
    /// The admitted endpoints: enrolled clients that are `active` (never a tombstone).
    pub admitted: BTreeSet<IrohEndpointId>,
    /// What to serve, when the endpoint is enabled with `serve`.
    pub serve: Option<ServePlan>,
}

/// The authority could not be read: `transport_authority_lost`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorityLost;

/// Read the authority in one transaction (module docs, "Start").
///
/// # Errors
/// [`AuthorityLost`] for any store error, a corrupt record included.
pub fn read_authority(
    store: &Store,
    peers: &dyn PeerEndpoints,
) -> Result<AuthoritySnapshot, AuthorityLost> {
    store
        .transaction(|tx| {
            let generation = tx.remote_authority_generation()?;
            let state = endpoint_state(tx)?;
            let enrolled = peers.enrolled(tx)?;
            let mut admitted = BTreeSet::new();
            for (client, endpoint) in enrolled {
                let active = tx
                    .remote_client(&client)?
                    .is_some_and(|c| c.state == ClientState::Active);
                if active {
                    admitted.insert(endpoint);
                }
            }
            let serve = match state.key {
                Some(key) if state.serve => Some(ServePlan {
                    key: KeyRef {
                        endpoint: key.endpoint,
                        store_kind: key.store_kind,
                        store_ref: key.store_ref,
                    },
                    policy: state.policy,
                    recorded_port: tx.transport_serve_port()?,
                }),
                _ => None,
            };
            Ok(AuthoritySnapshot {
                generation,
                admitted,
                serve,
            })
        })
        .map_err(|_| AuthorityLost)
}

// --- the supervisor ---------------------------------------------------------------------------

/// How the serve child is started: normally the running executable with `transport serve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeSpawn {
    /// The program (an absolute path).
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// Extra environment (names and nonsecret values only).
    pub env: Vec<(OsString, OsString)>,
}

/// The supervisor's bounds. ⟨M06 W5; ADR-0012 §2.3 item 2 ⟨2026-11-22⟩⟩ The target is not
/// configuration of the supervisor: it is `127.0.0.1` and the serve policy's `sshd_port`
/// ([`ServePlan::target`]), read from durable state at every start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// How the child is started.
    pub spawn: ServeSpawn,
    /// The bound on the child's `ready`.
    pub start_bound: Duration,
    /// The bound on a suspend's acknowledgement (§2.3 item 4.3).
    pub ack_bound: Duration,
    /// The bound on a stopped child being gone (after EOF, then after the kill).
    pub stop_bound: Duration,
    /// How often the watchdog re-reads the durable generation.
    pub watch_interval: Duration,
}

impl SupervisorConfig {
    /// The defaults for `spawn`: 10 s to start, 3 s to acknowledge, 5 s to stop, a 1 s
    /// watchdog.
    #[must_use]
    pub fn new(spawn: ServeSpawn) -> Self {
        Self {
            spawn,
            start_bound: Duration::from_secs(10),
            ack_bound: Duration::from_secs(3),
            stop_bound: Duration::from_secs(5),
            watch_interval: Duration::from_secs(1),
        }
    }
}

struct Running {
    process: tokio::process::Child,
    pid: Option<u32>,
    stdin: Option<tokio::process::ChildStdin>,
    messages: mpsc::UnboundedReceiver<FromChild>,
    generation: u64,
    admitted: BTreeSet<IrohEndpointId>,
    plan: ServePlan,
    endpoint: IrohEndpointId,
    addresses: Vec<String>,
}

/// The running serve child, as the supervisor knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serving {
    /// The serving endpoint's ID.
    pub endpoint: IrohEndpointId,
    /// The generation its lease holds.
    pub generation: u64,
    /// The sockets it bound (`ip:port`).
    pub addresses: Vec<String>,
    /// Its PID.
    pub pid: Option<u32>,
}

/// The child's last suspend acknowledgement (diagnostics: what it closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Acknowledgement {
    /// The generation acknowledged.
    pub generation: u64,
    /// Live connections it closed.
    pub closed: usize,
    /// Every closed session (stream and target socket) ended within the child's bound.
    pub complete: bool,
}

impl Running {
    /// Stop the child: EOF on its channel (its lease is lost: it closes every stream and
    /// exits), then, past the bound, the kill of its exact process. `None` once it is
    /// confirmed gone; otherwise the child, still to be confirmed.
    async fn stop(mut self, bound: Duration) -> Option<Running> {
        drop(self.stdin.take());
        if matches!(
            tokio::time::timeout(bound, self.process.wait()).await,
            Ok(Ok(_))
        ) {
            return None;
        }
        self.kill(bound).await
    }

    /// Stop the child by its exact supervised PID: the handle this supervisor spawned and
    /// has not reaped, so the PID cannot have been reused. `None` once it is confirmed gone;
    /// otherwise the child, still to be confirmed.
    async fn kill(mut self, bound: Duration) -> Option<Running> {
        let _ = self.process.start_kill();
        if matches!(
            tokio::time::timeout(bound, self.process.wait()).await,
            Ok(Ok(_))
        ) {
            None
        } else {
            Some(self)
        }
    }
}

#[derive(Default)]
struct Inner {
    child: Option<Running>,
    /// Children stopped by their exact PID whose exit is not confirmed yet: admission stays
    /// `remote_pending` (`iroh_admission_closing`) until each is gone (the watchdog retries).
    unconfirmed: Vec<Running>,
}

/// The serve child's supervisor (module docs). One per runtime.
pub struct TransportSupervisor {
    store: Arc<Store>,
    peers: Arc<dyn PeerEndpoints>,
    config: SupervisorConfig,
    inner: tokio::sync::Mutex<Inner>,
    closing: AtomicBool,
    /// Children whose exit is not confirmed (mirrors `Inner::unconfirmed` for a lock-free
    /// [`TransportSupervisor::admission`]).
    unconfirmed: AtomicU64,
    spawned: AtomicU64,
    pid: Mutex<Option<u32>>,
    last_ack: Mutex<Option<Acknowledgement>>,
}

impl std::fmt::Debug for TransportSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportSupervisor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn refusal(reason_token: &str, message: &str) -> OpError {
    OpError::new(Code::CapabilityUnavailable, message.to_owned())
        .with_reason(reason_token)
        .with_effect(EffectStatus::None)
}

impl TransportSupervisor {
    /// A supervisor over `store`, with the allowlist from `peers`.
    #[must_use]
    pub fn new(store: Arc<Store>, peers: Arc<dyn PeerEndpoints>, config: SupervisorConfig) -> Self {
        Self {
            store,
            peers,
            config,
            inner: tokio::sync::Mutex::new(Inner::default()),
            closing: AtomicBool::new(false),
            unconfirmed: AtomicU64::new(0),
            spawned: AtomicU64::new(0),
            pid: Mutex::new(None),
            last_ack: Mutex::new(None),
        }
    }

    /// The child's last suspend acknowledgement.
    #[must_use]
    pub fn last_acknowledgement(&self) -> Option<Acknowledgement> {
        *self.last_ack.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many children were spawned (diagnostics and tests).
    #[must_use]
    pub fn spawned(&self) -> u64 {
        self.spawned.load(Ordering::SeqCst)
    }

    /// The running child's PID.
    #[must_use]
    pub fn child_pid(&self) -> Option<u32> {
        *self.pid.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_pid(&self, pid: Option<u32>) {
        *self.pid.lock().unwrap_or_else(PoisonError::into_inner) = pid;
    }

    /// The running child.
    pub async fn serving(&self) -> Option<Serving> {
        let inner = self.inner.lock().await;
        inner.child.as_ref().map(|c| Serving {
            endpoint: c.endpoint.clone(),
            generation: c.generation,
            addresses: c.addresses.clone(),
            pid: c.pid,
        })
    }

    /// Where Iroh admission stands now: `remote_pending` (`iroh_admission_closing`) while a
    /// narrowing is being applied, otherwise applied (or not serving).
    #[must_use]
    pub fn admission(&self) -> AdmissionReport {
        if self.closing.load(Ordering::SeqCst) || self.unconfirmed.load(Ordering::SeqCst) > 0 {
            AdmissionReport::Pending {
                reason: reason::IROH_ADMISSION_CLOSING,
            }
        } else if self.child_pid().is_some() {
            AdmissionReport::Applied
        } else {
            AdmissionReport::NotServing
        }
    }

    /// Start serving from durable state (closure replay; module docs, "Start"). A running
    /// child is kept.
    ///
    /// # Errors
    /// `transport_authority_lost` (nothing started), `transport_unavailable` (not enabled
    /// for serving, no enrolled client, or the child failed), or the child's own refusal
    /// (`transport_key_store_unavailable`, a policy reason).
    pub async fn start(&self) -> Result<(), OpError> {
        let mut inner = self.inner.lock().await;
        if inner.child.is_some() {
            return Ok(());
        }
        let snapshot = read_authority(&self.store, self.peers.as_ref()).map_err(|_| {
            refusal(
                reason::TRANSPORT_AUTHORITY_LOST,
                "the admission authority cannot be read; the serve child is not started",
            )
        })?;
        let child = self.launch(&snapshot).await?;
        self.set_pid(child.pid);
        inner.child = Some(child);
        Ok(())
    }

    async fn launch(&self, snapshot: &AuthoritySnapshot) -> Result<Running, OpError> {
        let Some(plan) = snapshot.serve.clone() else {
            return Err(refusal(
                reason::TRANSPORT_UNAVAILABLE,
                "the transport is not enabled for serving",
            ));
        };
        if snapshot.admitted.is_empty() {
            return Err(refusal(
                reason::TRANSPORT_UNAVAILABLE,
                "no enrolled client: the serve allowlist would be empty",
            ));
        }
        let spawn = &self.config.spawn;
        let mut command = heimdall_app::no_window!(tokio::process::Command::new(&spawn.program));
        command
            .args(&spawn.args)
            .envs(spawn.env.iter().map(|(k, v)| (k, v)))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        let mut process = command.spawn().map_err(|_| {
            refusal(
                reason::TRANSPORT_UNAVAILABLE,
                "the serve child could not be started",
            )
        })?;
        self.spawned.fetch_add(1, Ordering::SeqCst);
        let pid = process.id();
        let (Some(mut stdin), Some(stdout)) = (process.stdin.take(), process.stdout.take()) else {
            let _ = process.start_kill();
            let _ = process.wait().await;
            return Err(refusal(
                reason::TRANSPORT_UNAVAILABLE,
                "the serve child has no supervision channel",
            ));
        };
        let (tx, mut messages) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stdout);
            while let Ok(m) = read_message::<_, FromChild>(&mut reader).await {
                if tx.send(m).is_err() {
                    break;
                }
            }
        });
        let start = ToChild::Start {
            protocol: PROTOCOL.to_owned(),
            generation: snapshot.generation,
            allowlist: snapshot.admitted.iter().cloned().collect(),
            policy: plan.effective_policy(),
            target: plan.target(),
            key: plan.key.clone(),
        };
        let fail = |reason_token: &str, message: &str| refusal(reason_token, message);
        let ready = async {
            write_message(&mut stdin, &start).await.ok()?;
            messages.recv().await
        };
        let outcome = tokio::time::timeout(self.config.start_bound, ready).await;
        let mut running = Running {
            process,
            pid,
            stdin: Some(stdin),
            messages,
            generation: snapshot.generation,
            admitted: snapshot.admitted.clone(),
            endpoint: plan.key.endpoint.clone(),
            addresses: Vec::new(),
            plan,
        };
        match outcome {
            Ok(Some(FromChild::Ready {
                endpoint,
                generation,
                addresses,
            })) if endpoint == running.plan.key.endpoint && generation == snapshot.generation => {
                // ⟨ADR-0012 §2.1 ⟨2026-11-21⟩⟩ The first successful bind of a policy that
                // names no port records the port durably; every later start reuses it. A
                // record that cannot be written stops the child (fail closed: the routes'
                // addresses would not survive a restart).
                let first =
                    running.plan.policy.port.is_none() && running.plan.recorded_port.is_none();
                let recorded = self.store.transaction(|tx| {
                    if first && let Some(port) = bound_port(&addresses) {
                        tx.record_transport_serve_port(port)?;
                    }
                    tx.clear_transport_serve_bind_failure()?;
                    tx.transport_serve_port()
                });
                match recorded {
                    Ok(port) => {
                        if running.plan.policy.port.is_none() {
                            running.plan.recorded_port = port;
                        }
                    }
                    Err(_) => {
                        drop(running.kill(self.config.stop_bound).await);
                        return Err(fail(
                            reason::TRANSPORT_AUTHORITY_LOST,
                            "the serve port cannot be recorded; the serve child is stopped",
                        ));
                    }
                }
                running.endpoint = endpoint;
                running.addresses = addresses;
                Ok(running)
            }
            Ok(Some(FromChild::Refused {
                reason,
                unbindable_port,
            })) => {
                let token = known_reason(&reason);
                // A child that refused binds nothing; one whose exit cannot be confirmed is
                // dropped (`kill_on_drop` kills it again).
                drop(running.kill(self.config.stop_bound).await);
                if let Some(port) = unbindable_port {
                    // ⟨ADR-0012 §2.1 ⟨2026-11-21⟩⟩ Fail closed on the port (no other port is
                    // tried), and record it for the doctor's finding.
                    let _ = self
                        .store
                        .transaction(|tx| tx.record_transport_serve_bind_failure(port));
                    return Err(fail(
                        reason::TRANSPORT_UNAVAILABLE,
                        &format!(
                            "the serve port {port} cannot be bound, so the serve child is not \
                             started (`heimdall doctor` names it; to change the port, disable \
                             then enable the transport)"
                        ),
                    ));
                }
                Err(fail(token, "the serve child refused to start"))
            }
            _ => {
                drop(running.kill(self.config.stop_bound).await);
                Err(fail(
                    reason::TRANSPORT_UNAVAILABLE,
                    "the serve child did not become ready",
                ))
            }
        }
    }

    /// Apply a committed narrowing change to the running child (module docs,
    /// "Narrowing"). When the child had to be stopped (and is confirmed gone) and the
    /// endpoint still serves, closure is replayed on a fresh child from durable state.
    pub async fn apply_narrowing(&self) -> AdmissionReport {
        let mut inner = self.inner.lock().await;
        let Some(child) = inner.child.take() else {
            return AdmissionReport::NotServing;
        };
        self.closing.store(true, Ordering::SeqCst);
        let (kept, stuck) = self.narrow(child).await;
        let report = match stuck {
            Some(child) => {
                inner.unconfirmed.push(child);
                AdmissionReport::Pending {
                    reason: reason::IROH_ADMISSION_CLOSING,
                }
            }
            None => AdmissionReport::Applied,
        };
        self.unconfirmed
            .store(inner.unconfirmed.len() as u64, Ordering::SeqCst);
        match kept {
            Some(child) => inner.child = Some(child),
            None => {
                self.set_pid(None);
                if report == AdmissionReport::Applied
                    && let Ok(snapshot) = read_authority(&self.store, self.peers.as_ref())
                    && let Ok(fresh) = self.launch(&snapshot).await
                {
                    self.set_pid(fresh.pid);
                    inner.child = Some(fresh);
                }
            }
        }
        self.closing.store(false, Ordering::SeqCst);
        report
    }

    /// The narrowing proper: the child when it stays, and a stopped child whose exit is not
    /// confirmed (the change is then still pending).
    async fn narrow(&self, mut child: Running) -> (Option<Running>, Option<Running>) {
        let bound = self.config.stop_bound;
        let Ok(snapshot) = read_authority(&self.store, self.peers.as_ref()) else {
            // Fail closed: the authority cannot be read, so the child must not admit.
            return (None, child.stop(bound).await);
        };
        if snapshot.serve.as_ref() != Some(&child.plan) {
            // Disabled, rotated or narrowed exposure: the child goes.
            return (None, child.stop(bound).await);
        }
        let withdrawn: Vec<IrohEndpointId> = child
            .admitted
            .difference(&snapshot.admitted)
            .cloned()
            .collect();
        if snapshot.generation != child.generation || !withdrawn.is_empty() {
            if !self
                .suspend(&mut child, snapshot.generation, withdrawn.clone())
                .await
            {
                // No complete acknowledgement in the bound: the exact-PID stop.
                return (None, child.kill(bound).await);
            }
            child.generation = snapshot.generation;
            for e in &withdrawn {
                child.admitted.remove(e);
            }
        }
        if snapshot
            .admitted
            .difference(&child.admitted)
            .next()
            .is_some()
        {
            // A new enrollment needs a new child (the allowlist is fixed per child).
            return (None, child.stop(bound).await);
        }
        (Some(child), None)
    }

    /// Send `suspend` and wait for a complete acknowledgement of `generation` (or later).
    async fn suspend(
        &self,
        child: &mut Running,
        generation: u64,
        endpoints: Vec<IrohEndpointId>,
    ) -> bool {
        let Some(stdin) = child.stdin.as_mut() else {
            return false;
        };
        let message = ToChild::Suspend {
            generation,
            endpoints,
        };
        let wait = async {
            write_message(stdin, &message).await.ok()?;
            loop {
                match child.messages.recv().await? {
                    FromChild::Suspended {
                        generation: g,
                        closed,
                        complete,
                    } if g >= generation => {
                        *self.last_ack.lock().unwrap_or_else(PoisonError::into_inner) =
                            Some(Acknowledgement {
                                generation: g,
                                closed,
                                complete,
                            });
                        return Some(complete);
                    }
                    // An older acknowledgement, or a stray message: keep waiting.
                    FromChild::Suspended { .. } => {}
                    FromChild::Exiting { .. } | FromChild::Refused { .. } => return None,
                    FromChild::Ready { .. } => {}
                }
            }
        };
        matches!(
            tokio::time::timeout(self.config.ack_bound, wait).await,
            Ok(Some(true))
        )
    }

    /// Stop the child (module docs); applied once it is confirmed gone.
    pub async fn stop(&self) -> AdmissionReport {
        let mut inner = self.inner.lock().await;
        let Some(child) = inner.child.take() else {
            return AdmissionReport::NotServing;
        };
        self.closing.store(true, Ordering::SeqCst);
        let stuck = child.stop(self.config.stop_bound).await;
        self.set_pid(None);
        let report = match stuck {
            Some(child) => {
                inner.unconfirmed.push(child);
                AdmissionReport::Pending {
                    reason: reason::IROH_ADMISSION_CLOSING,
                }
            }
            None => AdmissionReport::Applied,
        };
        self.unconfirmed
            .store(inner.unconfirmed.len() as u64, Ordering::SeqCst);
        self.closing.store(false, Ordering::SeqCst);
        report
    }

    /// Retry the exact-PID stop of every child whose exit is not confirmed; keeps those
    /// still running.
    async fn confirm_unconfirmed(&self, inner: &mut Inner) {
        let mut still = Vec::new();
        for child in std::mem::take(&mut inner.unconfirmed) {
            if let Some(child) = child.kill(Duration::from_millis(100)).await {
                still.push(child);
            }
        }
        inner.unconfirmed = still;
        self.unconfirmed
            .store(inner.unconfirmed.len() as u64, Ordering::SeqCst);
    }

    /// One watchdog pass: a child that exited is restarted from durable state; a durable
    /// generation the child does not hold is applied.
    pub async fn watch_once(&self) -> Option<AdmissionReport> {
        let durable = self
            .store
            .transaction(|tx| tx.remote_authority_generation())
            .ok();
        let action = {
            let mut inner = self.inner.lock().await;
            if !inner.unconfirmed.is_empty() {
                self.confirm_unconfirmed(&mut inner).await;
            }
            let state = inner
                .child
                .as_mut()
                .map(|c| (matches!(c.process.try_wait(), Ok(None)), c.generation));
            match state {
                None => None,
                Some((false, _)) => {
                    inner.child = None;
                    self.set_pid(None);
                    Some(false)
                }
                Some((true, g)) if durable != Some(g) => Some(true),
                Some(_) => None,
            }
        };
        match action {
            Some(true) => Some(self.apply_narrowing().await),
            Some(false) => {
                let _ = self.start().await;
                Some(self.admission())
            }
            None => None,
        }
    }

    /// Run [`Self::watch_once`] every [`SupervisorConfig::watch_interval`] until `shutdown`.
    pub fn spawn_watch(
        self: &Arc<Self>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.config.watch_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = tick.tick() => {
                        let _ = me.watch_once().await;
                    }
                }
            }
        })
    }
}

/// A child's refusal reason, if it is one of the transport's tokens; otherwise
/// `transport_unavailable` (the child's text is never echoed).
fn known_reason(token: &str) -> &'static str {
    [
        reason::TRANSPORT_KEY_STORE_UNAVAILABLE,
        reason::TRANSPORT_AUTHORITY_LOST,
        reason::TRANSPORT_UNAVAILABLE,
        reason::RELAY_UNAPPROVED,
        reason::ROUTE_UNAPPROVED,
        reason::DRIVER_UNAVAILABLE,
    ]
    .into_iter()
    .find(|t| *t == token)
    .unwrap_or(reason::TRANSPORT_UNAVAILABLE)
}

#[async_trait]
impl ServeControl for TransportSupervisor {
    fn check_policy(&self, policy: &ExposurePolicy) -> Result<(), &'static str> {
        heimdall_transport_iroh::availability().map_err(|u| u.reason())?;
        heimdall_transport_iroh::policy::EffectivePolicy::from_contract(policy)
            .map(drop)
            .map_err(|e| e.reason.token())
    }

    async fn start(&self) -> Result<(), OpError> {
        TransportSupervisor::start(self).await
    }

    async fn apply_narrowing(&self) -> AdmissionReport {
        TransportSupervisor::apply_narrowing(self).await
    }

    async fn stop(&self) -> AdmissionReport {
        TransportSupervisor::stop(self).await
    }
}

// --- ⟨M06 W3⟩ the runtime's route and transport forms -------------------------------------------

/// ⟨M06 W3⟩ How `service run` wires the route and transport forms and the serve child
/// (`crate::service::ServiceOptions::transport`).
#[derive(Clone)]
pub struct TransportWiring {
    /// The program the serve child runs as `transport serve --environment <id>` (this
    /// executable; the hidden CLI entry calls [`serve_child_stdio`]).
    pub program: PathBuf,
    /// K_iroh custody; `None`: this installation's verified platform store
    /// (`heimdall_credential::iroh::product_store`).
    pub keys: Option<Arc<dyn IrohKeyStore>>,
    /// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ `transport.rotate`'s management channel to this
    /// device's recorded runners (the executable's wiring over its management sessions);
    /// `None`: a rotation with recorded runners is refused before any key is minted.
    pub announcer: Option<Arc<dyn heimdall_app::transport::EndpointAnnouncer>>,
}

impl std::fmt::Debug for TransportWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportWiring")
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

/// ⟨M06 W3⟩ This installation's verified platform K_iroh store for `environment`
/// (`heimdall_credential::iroh::product_store` under the account database's home), or the
/// unsupported store when the home cannot be read (every use then refuses
/// `transport_key_store_unavailable`).
///
/// ⟨M06 W5⟩ When the test variable `HEIMDALL_TEST_IROH_KEY_STORE` is set
/// (`heimdall_credential::iroh::requested_test_store`), the store it asks for is the only
/// one used and the platform store is never opened: a debug build's scratch-directory
/// fixture store (kind `fixture_store`; mechanism evidence only), or in a release build a
/// store that refuses everything. Unset, this is the platform store and nothing else.
#[must_use]
pub fn product_iroh_store(
    environment: &heimdall_contract::ids::EnvironmentId,
) -> Arc<dyn IrohKeyStore> {
    if let Some(test) =
        heimdall_credential::iroh::requested_test_store(&|name| std::env::var_os(name))
    {
        return Arc::from(test);
    }
    match heimdall_localenv::sys::account_home() {
        Ok(home) => Arc::from(heimdall_credential::iroh::product_store(environment, &home)),
        Err(_) => Arc::new(heimdall_credential::iroh::UnsupportedIrohStore),
    }
}

/// ⟨M06 W3⟩ The serve child's key factory over `keys` (the hidden `transport serve` entry):
/// the reference must name `keys`' own store kind, then [`StoreKeySource`] for its endpoint
/// (the child checks the bound endpoint against it again).
pub fn serve_key_factory(
    keys: Arc<dyn IrohKeyStore>,
) -> impl Fn(&KeyRef) -> Result<Arc<dyn KeySource>, KeySourceError> + Send + Sync {
    move |key: &KeyRef| {
        if key.store_kind != keys.kind().column() {
            return Err(KeySourceError::StoreUnavailable);
        }
        Ok(
            Arc::new(StoreKeySource::new(Arc::clone(&keys), key.endpoint.clone()))
                as Arc<dyn KeySource>,
        )
    }
}

/// ⟨M06 W3⟩ This installation's active K_iroh endpoint ID, when a verified store holds its
/// key (`keys` loads it: a locked, missing or unsupported store gives `None`). What
/// `environment join` sends as `Join.iroh_endpoint` (ADR-0006 §18.7 item 3).
#[must_use]
pub fn held_endpoint(state: &Store, keys: &dyn IrohKeyStore) -> Option<IrohEndpointId> {
    let key = state.transaction(|tx| tx.active_transport_key()).ok()??;
    if key.store_kind != keys.kind().column() {
        return None;
    }
    keys.load(&key.endpoint).ok().map(|_| key.endpoint)
}

/// ⟨M06 W3⟩ The route helper's Iroh leg with this installation's active K_iroh in `keys`, or
/// `None` (no active key, another store kind, or a build without the `iroh` feature): every
/// Iroh route is then refused and failed over, and direct and jump routes are unaffected.
#[must_use]
pub fn route_iroh_leg(
    state: &Store,
    keys: Arc<dyn IrohKeyStore>,
) -> Option<Arc<dyn heimdall_app::routes::legs::IrohLegDialer>> {
    #[cfg(feature = "iroh")]
    {
        let key = state.transaction(|tx| tx.active_transport_key()).ok()??;
        if key.store_kind != keys.kind().column() {
            return None;
        }
        let source: Arc<dyn KeySource> = Arc::new(StoreKeySource::new(keys, key.endpoint));
        Some(Arc::new(IrohRouteLeg::new(source)))
    }
    #[cfg(not(feature = "iroh"))]
    {
        let _ = (state, keys);
        None
    }
}

impl TransportWiring {
    /// The serve child's arguments for `environment` (argv only; the child reads no state:
    /// its whole configuration and its lease arrive over the supervision channel).
    #[must_use]
    pub fn serve_args(environment: &heimdall_contract::ids::EnvironmentId) -> Vec<OsString> {
        ["transport", "serve", "--environment", environment.as_str()]
            .into_iter()
            .map(OsString::from)
            .collect()
    }

    /// The supervisor and K_iroh custody for `environment` over `store`: the serve allowlist
    /// from the paired clients' recorded endpoints (`crate::paired_endpoints`).
    #[must_use]
    pub fn build(
        &self,
        store: &Arc<Store>,
        environment: &heimdall_contract::ids::EnvironmentId,
    ) -> (Arc<TransportSupervisor>, Arc<dyn TransportKeys>) {
        let keys: Arc<dyn IrohKeyStore> = match &self.keys {
            Some(k) => Arc::clone(k),
            None => product_iroh_store(environment),
        };
        let config = SupervisorConfig::new(ServeSpawn {
            program: self.program.clone(),
            args: Self::serve_args(environment),
            env: Vec::new(),
        });
        let supervisor = Arc::new(TransportSupervisor::new(
            Arc::clone(store),
            Arc::new(crate::paired_endpoints::StorePeerEndpoints),
            config,
        ));
        (supervisor, Arc::new(CredentialKeys(keys)))
    }
}

/// ⟨M06 W5 `w5n`⟩ The latest report of the route helper for one destination
/// (`route.record_health`), as `inspect destinations` shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RouteHealthReport {
    /// The attempt's structured result (ADR-0012 §5.5 item 4).
    pub result: heimdall_contract::route::RouteHealthPayload,
    /// The setting that defeated the catalog pin (`host_pin_defeated`), when the helper
    /// refused for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_pin_defeated: Option<String>,
    /// When it was reported.
    pub reported_at: heimdall_contract::Timestamp,
}

/// The bound on the attempts of one route-health report (the contract's).
pub use heimdall_contract::route::ROUTE_HEALTH_ATTEMPTS_MAX;

/// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ The reports kept for one binding: the newest this many.
pub const ROUTE_HEALTH_REPORTS_PER_BINDING: usize = 8;

/// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ The bindings whose reports are kept: beyond this, the
/// binding whose newest report is oldest is forgotten.
pub const ROUTE_HEALTH_BINDINGS_MAX: usize = 256;

/// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ The route-health reports this runtime keeps, **in
/// memory only**: per reporting binding, its newest [`ROUTE_HEALTH_REPORTS_PER_BINDING`],
/// for at most [`ROUTE_HEALTH_BINDINGS_MAX`] bindings. Nothing here is read by a connect:
/// the routes a connect may use come from the store alone.
#[derive(Debug, Default)]
struct HealthLedger {
    by_binding: std::collections::BTreeMap<
        heimdall_contract::ids::BindingId,
        std::collections::VecDeque<RouteHealthReport>,
    >,
}

impl HealthLedger {
    fn insert(&mut self, binding: heimdall_contract::ids::BindingId, report: RouteHealthReport) {
        let reports = self.by_binding.entry(binding).or_default();
        reports.push_back(report);
        while reports.len() > ROUTE_HEALTH_REPORTS_PER_BINDING {
            reports.pop_front();
        }
        while self.by_binding.len() > ROUTE_HEALTH_BINDINGS_MAX {
            let oldest = self
                .by_binding
                .iter()
                .min_by_key(|(_, r)| r.back().map(|r| r.reported_at))
                .map(|(b, _)| b.clone());
            match oldest {
                Some(b) => self.by_binding.remove(&b),
                None => break,
            };
        }
    }

    /// The newest report naming `destination` (the later insert wins a tie).
    fn latest(
        &self,
        destination: &heimdall_contract::ids::DestinationId,
    ) -> Option<RouteHealthReport> {
        self.by_binding
            .values()
            .flatten()
            .filter(|r| &r.result.destination == destination)
            .fold(None, |best: Option<&RouteHealthReport>, r| match best {
                Some(b) if b.reported_at > r.reported_at => Some(b),
                _ => Some(r),
            })
            .cloned()
    }

    fn len(&self) -> (usize, usize) {
        (
            self.by_binding.len(),
            self.by_binding
                .values()
                .map(std::collections::VecDeque::len)
                .sum(),
        )
    }
}

/// ⟨M06 W3; m06-plan W2 carry-over⟩ The route and transport forms a runtime serves
/// (ADR-0012 §2, §5; ADR-0006 §18 `route.*`, `transport.*`), over the state store, the
/// serve child's supervision and K_iroh custody:
///
/// * **`route add|remove|prefer`**: `heimdall_app::routes::ops::RouteOps`. ⟨M06 W5⟩ A
///   widening `add` from the attended local owner becomes a local decision record
///   (`crate::local_widening`; `APPROVAL_REQUIRED`) and runs when that owner approves it;
///   from that owner unattended it is `INTERACTION_REQUIRED`, naming the widening
///   (⟨rev6.5; ADR-0006 §18.9 item 10⟩); from a paired session, `exposure_unconsented`;
/// * **`route resolve_binding`** (the helper's `ResolveRouteBinding`, ADR-0012 §5.4): the
///   caller's active bindings whose live endpoint is exactly the alias's, by
///   `heimdall_app::routes::select_route_binding` (zero or several: `route_binding_ambiguous`);
/// * **`transport enable|disable|adopt_roost`**: `heimdall_app::transport::TransportOps`.
///   A narrowing or a minimal dialer endpoint runs directly. ⟨M06 W5⟩ A widening from the
///   attended local owner becomes a local decision record, as above, with nothing
///   generated or recorded until it is approved; unattended it is `INTERACTION_REQUIRED`
///   and from a paired session `exposure_unconsented`, as above.
///
/// Authorization: the changes need the owner role (a paired owner's narrowing reaches here
/// only after its frame check; its widening never does, it stays a pending runner-local
/// record); the lookup is read-only, scoped to the caller's own bindings.
pub struct RouteTransport {
    store: Arc<Store>,
    supervisor: Arc<TransportSupervisor>,
    keys: Arc<dyn TransportKeys>,
    peers: Arc<dyn heimdall_app::transport::PeerEnrollments>,
    endpoints: Option<Arc<dyn crate::connections::BindingEndpoints>>,
    /// ⟨M06 W5 `w5n`⟩ The environment endpoint as P renders it in a managed alias's
    /// `IdentityAgent` (and so in its helper's `--endpoint`), with the environment whose
    /// ordinary-alias slots it serves.
    environment_endpoint: Option<(String, heimdall_contract::ids::EnvironmentId)>,
    /// ⟨M06 W5 `w5n`; rev6.5⟩ The route-health reports since this runtime started, bounded
    /// per binding ([`HealthLedger`]; `inspect destinations` shows the latest of each
    /// destination); the durable record is the `route.health` event.
    health: std::sync::Mutex<HealthLedger>,
    /// ⟨rev6.3⟩ `transport.rotate`'s management channel to the recorded runners.
    announcer: Option<Arc<dyn heimdall_app::transport::EndpointAnnouncer>>,
    /// ⟨rev6.3⟩ One rotation at a time: a second `transport.rotate` waits, then continues
    /// the first one's record instead of minting a second key.
    rotating: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for RouteTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteTransport").finish_non_exhaustive()
    }
}

impl RouteTransport {
    /// Over `store`, the serve child's `supervisor`, K_iroh custody `keys` and the serve
    /// allowlist's `peers` (cleared on disable).
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        supervisor: Arc<TransportSupervisor>,
        keys: Arc<dyn TransportKeys>,
        peers: Arc<dyn heimdall_app::transport::PeerEnrollments>,
    ) -> Self {
        Self {
            store,
            supervisor,
            keys,
            peers,
            endpoints: None,
            environment_endpoint: None,
            health: std::sync::Mutex::new(HealthLedger::default()),
            announcer: None,
            rotating: tokio::sync::Mutex::new(()),
        }
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ The management channel `transport.rotate` tells each
    /// recorded runner the new endpoint through. Without one, a rotation on an installation
    /// that has recorded runners is refused before any key is minted.
    #[must_use]
    pub fn with_announcer(
        mut self,
        announcer: Arc<dyn heimdall_app::transport::EndpointAnnouncer>,
    ) -> Self {
        self.announcer = Some(announcer);
        self
    }

    /// The binding endpoints `resolve_binding` reads (the managed signer's registry);
    /// without them every lookup is `route_binding_ambiguous` (no binding is served at any
    /// endpoint).
    #[must_use]
    pub fn with_binding_endpoints(
        mut self,
        endpoints: Arc<dyn crate::connections::BindingEndpoints>,
    ) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// ⟨M06 W5 `w5n`; ADR-0012 §5.4⟩ The environment endpoint `resolve_binding` also
    /// answers at: `rendered` is its locator exactly as P renders it
    /// (`EndpointLayout::rendered_environment`), `environment` the environment whose slots
    /// it serves. Without it a lookup at that endpoint is `route_binding_ambiguous`.
    #[must_use]
    pub fn with_environment_endpoint(
        mut self,
        rendered: String,
        environment: heimdall_contract::ids::EnvironmentId,
    ) -> Self {
        self.environment_endpoint = Some((rendered, environment));
        self
    }

    /// The state store.
    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    /// The state store, shared.
    pub(crate) fn store_arc(&self) -> &Arc<Store> {
        &self.store
    }

    /// The serve child's supervisor.
    #[must_use]
    pub fn supervisor(&self) -> &Arc<TransportSupervisor> {
        &self.supervisor
    }

    /// K_iroh custody.
    #[must_use]
    pub fn keys(&self) -> &Arc<dyn TransportKeys> {
        &self.keys
    }

    /// The serve allowlist's enrollments.
    #[must_use]
    pub fn peers(&self) -> &Arc<dyn heimdall_app::transport::PeerEnrollments> {
        &self.peers
    }

    fn owner_only(caller: &heimdall_app::Caller) -> Result<(), OpError> {
        if caller.context.is_owner() {
            Ok(())
        } else {
            Err(OpError::new(
                Code::CapabilityUnavailable,
                "this request needs the owner role",
            )
            .with_effect(EffectStatus::None))
        }
    }

    /// One `Request::Route` form (type docs).
    ///
    /// # Errors
    /// The operation's.
    pub fn route(
        &self,
        caller: &heimdall_app::Caller,
        request: &heimdall_contract::route::RouteRequest,
        now: heimdall_contract::Timestamp,
    ) -> Result<serde_json::Value, OpError> {
        use heimdall_contract::route::RouteRequest;
        if let RouteRequest::ResolveBinding {
            destination,
            account,
            endpoint,
        } = request
        {
            return self.resolve_binding(caller, destination, account, endpoint);
        }
        if let RouteRequest::RecordHealth {
            endpoint,
            result,
            host_pin_defeated,
        } = request
        {
            return self.record_health(caller, endpoint, result, host_pin_defeated.as_deref(), now);
        }
        Self::owner_only(caller)?;
        // ⟨rev6.5; ADR-0006 §18.9 item 9⟩ The relay URLs of an `add` are validated and put
        // in their one spelling before anything is recorded: the delta, its digest, the
        // retry lookup and the stored route all see the normalised request.
        let request = &*heimdall_app::routes::ops::normalized(request)?;
        let ops = heimdall_app::routes::ops::RouteOps { store: &self.store };
        // ⟨M06 W5; ADR-0006 §18.9 item 8⟩ A widening `add` from the local owner becomes a
        // local decision record (`crate::local_widening`); from a paired session it is
        // refused as before (`exposure_unconsented`, in the operation).
        if let RouteRequest::Add {
            destination,
            route,
            exposure,
            ..
        } = request
        {
            let whole = heimdall_contract::request::Request::Route(request.clone());
            if let Some(delta) = self.widening_delta(&whole)?
                && !matches!(
                    crate::local_widening::submission_of(caller),
                    Ok(crate::local_widening::Submission::Paired)
                )
            {
                // A request that can never succeed, or that changes nothing, makes no record.
                if let Some(existing) =
                    ops.add_precheck(destination, route, exposure.as_ref(), now)?
                {
                    return serde_json::to_value(existing).map_err(|_| {
                        OpError::new(Code::InternalError, "a route result cannot be rendered")
                    });
                }
                if matches!(
                    crate::local_widening::submission_of(caller)?,
                    crate::local_widening::Submission::LocalUnattended
                ) {
                    return Err(crate::local_widening::unattended(whole.kind(), &delta));
                }
                return Err(self.submit_local_widening(&whole, &delta, now));
            }
        }
        ops.execute(request, None, now)
    }

    /// ⟨M06 W5 `w5n`; rev6.5, ADR-0006 §18.9 item 11⟩ `route.record_health`: keep the route
    /// helper's report of one connect (the dispatcher emits its `route.health` event).
    ///
    /// * **Who:** `endpoint` must resolve, for this caller and this pair, to exactly one
    ///   binding by [`Self::resolve_binding`]'s rule (the slot holder at the environment
    ///   endpoint, or the binding served at that per-binding endpoint). A paired session,
    ///   and a local caller for whom nothing resolves, are refused.
    /// * **Typed:** at most [`ROUTE_HEALTH_ATTEMPTS_MAX`] attempts, each naming one of the
    ///   destination's stored approved routes, each duration within the contract's bound;
    ///   the final route one of them and, when set, the route of the one attempt that did
    ///   not fail; `host_pin_defeated` one of the contract's settings.
    /// * **Effect:** the report is kept in the bounded in-memory ledger and nothing else is
    ///   written: no route list, consent or pin is read from it or changed by it.
    ///
    /// # Errors
    /// `CAPABILITY_UNAVAILABLE` for a paired session or a caller without the binding
    /// (`route_binding_ambiguous`); `USAGE_ERROR` for a report that does not fit the catalog
    /// or its bounds; nothing is kept on either.
    fn record_health(
        &self,
        caller: &heimdall_app::Caller,
        endpoint: &str,
        result: &heimdall_contract::route::RouteHealthPayload,
        host_pin_defeated: Option<&str>,
        now: heimdall_contract::Timestamp,
    ) -> Result<serde_json::Value, OpError> {
        use heimdall_contract::route::{HOST_PIN_SETTINGS, ROUTE_ATTEMPT_DURATION_MAX_MS};
        if caller.context.remote_client.is_some() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "route health is reported by this host's own route helper",
            )
            .with_effect(EffectStatus::None));
        }
        let refused = || {
            OpError::new(
                Code::UsageError,
                "the route-health report does not fit this destination's approved routes",
            )
            .with_effect(EffectStatus::None)
        };
        let typed = result.attempts.len() <= ROUTE_HEALTH_ATTEMPTS_MAX
            && host_pin_defeated.is_none_or(|s| HOST_PIN_SETTINGS.contains(&s))
            && result.attempts.iter().all(|a| {
                a.duration_ms
                    .is_none_or(|ms| ms <= ROUTE_ATTEMPT_DURATION_MAX_MS)
            });
        // The final route is the route of the one attempt that did not fail, and of no other.
        let used: Vec<_> = result
            .attempts
            .iter()
            .filter(|a| a.failure.is_none())
            .map(|a| &a.route)
            .collect();
        let consistent = match &result.final_route {
            Some(route) => used == [route],
            None => used.is_empty(),
        };
        if !typed || !consistent {
            return Err(refused());
        }
        // Only the binding that serves this pair at `endpoint`, for this caller.
        let resolved =
            self.resolve_binding_for(caller, &result.destination, &result.account, endpoint, true)?;
        let binding =
            serde_json::from_value::<heimdall_app::routes::ResolvedRouteBinding>(resolved)
                .map_err(|_| OpError::new(Code::InternalError, "a binding cannot be read"))?
                .binding;
        let approved = self
            .store
            .transaction(|tx| {
                let Some(record) = tx.destination(&result.destination)? else {
                    return Ok(None);
                };
                let heimdall_domain::catalog::DestinationDefinition::Managed { account, .. } =
                    &record.definition
                else {
                    return Ok(None);
                };
                if account != &result.account {
                    return Ok(None);
                }
                let stored = tx.destination_routes(&result.destination)?;
                Ok(Some(heimdall_domain::routes::approved_routes(
                    &record,
                    Some(&stored),
                )))
            })
            .map_err(OpError::from)?
            .ok_or_else(refused)?;
        let known = |id: &heimdall_contract::ids::RouteId| approved.iter().any(|r| &r.id == id);
        if !result.attempts.iter().all(|a| known(&a.route)) {
            return Err(refused());
        }
        self.health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                binding,
                RouteHealthReport {
                    result: result.clone(),
                    host_pin_defeated: host_pin_defeated.map(str::to_owned),
                    reported_at: now,
                },
            );
        Ok(serde_json::json!({ "recorded": true }))
    }

    /// The bindings and reports the health ledger holds (its bounds are tested on this).
    #[must_use]
    pub fn route_health_len(&self) -> (usize, usize) {
        self.health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// ⟨M06 W5 `w5n`⟩ The latest route-health report of `destination` since this runtime
    /// started, if its helper reported one.
    #[must_use]
    pub fn route_health(
        &self,
        destination: &heimdall_contract::ids::DestinationId,
    ) -> Option<RouteHealthReport> {
        self.health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .latest(destination)
    }

    /// `route.resolve_binding` (type docs).
    fn resolve_binding(
        &self,
        caller: &heimdall_app::Caller,
        destination: &heimdall_contract::ids::DestinationId,
        account: &heimdall_contract::ids::AccountName,
        endpoint: &str,
    ) -> Result<serde_json::Value, OpError> {
        self.resolve_binding_for(caller, destination, account, endpoint, false)
    }

    /// [`Self::resolve_binding`]; with `own_only` (⟨rev6.5; ADR-0006 §18.9 item 11⟩ the
    /// route-health report) a binding counts only when the caller is the very caller that
    /// owns it: the local owner's access to every caller's objects does not apply.
    fn resolve_binding_for(
        &self,
        caller: &heimdall_app::Caller,
        destination: &heimdall_contract::ids::DestinationId,
        account: &heimdall_contract::ids::AccountName,
        endpoint: &str,
        own_only: bool,
    ) -> Result<serde_json::Value, OpError> {
        let may = |owner: &heimdall_domain::principal::CallerContext| {
            if own_only {
                owner.same_caller(&caller.context)
            } else {
                caller.context.may_access(owner)
            }
        };
        use heimdall_app::routes::{
            ResolvedRouteBinding, RouteBinding, RouteHelperError, select_route_binding,
        };
        let ambiguous = || {
            let e = RouteHelperError::BindingAmbiguous;
            OpError::new(Code::CapabilityUnavailable, e.to_string())
                .with_reason(reason::ROUTE_BINDING_AMBIGUOUS)
                .with_effect(EffectStatus::None)
        };
        let pair = heimdall_domain::scope::AccessPair {
            destination: destination.clone(),
            account: account.clone(),
        };
        // ⟨M06 W5 `w5n`⟩ The environment endpoint (a managed alias's own `IdentityAgent`):
        // it serves a pair only through the one binding that holds the pair's
        // ordinary-alias slot (ADR-0008 D10 items 2–3: at most one binding per pair), so
        // that binding is the one served there for this pair. No slot holder, a holder
        // that is not active, not the caller's, or whose grant does not cover the pair:
        // `route_binding_ambiguous`. The helper never gets a binding by destination alone:
        // the endpoint must be this environment's and the slot must be held.
        if let Some((rendered, environment)) = &self.environment_endpoint
            && rendered == endpoint
        {
            let holder = self
                .store
                .transaction(|tx| {
                    let heimdall_domain::managed::SlotState::Held { binding, .. } =
                        tx.slot(environment, &pair)?
                    else {
                        return Ok(None);
                    };
                    tx.binding(&binding)
                })
                .map_err(OpError::from)?;
            let candidates: Vec<RouteBinding> = holder
                .into_iter()
                .filter(|b| {
                    b.state == heimdall_domain::binding::BindingState::Active
                        && b.released_at.is_none()
                        && &b.environment == environment
                        && may(&b.owner)
                })
                .map(|b| RouteBinding {
                    binding: b.id,
                    grant: b.grant,
                    endpoint: endpoint.to_owned(),
                    pairs: b.scope.pairs,
                })
                .collect();
            let one =
                select_route_binding(&candidates, &pair, endpoint).map_err(|_| ambiguous())?;
            return serde_json::to_value(ResolvedRouteBinding::from(one))
                .map_err(|_| OpError::new(Code::InternalError, "a binding cannot be rendered"));
        }
        let Some(endpoints) = &self.endpoints else {
            return Err(ambiguous());
        };
        let bindings = self
            .store
            .transaction(|tx| tx.active_bindings())
            .map_err(OpError::from)?;
        let candidates: Vec<RouteBinding> = bindings
            .into_iter()
            .filter(|b| may(&b.owner))
            .filter_map(|b| {
                let served = endpoints.endpoint(&b.id)?;
                let at = served.locator == endpoint;
                at.then_some(RouteBinding {
                    binding: b.id,
                    grant: b.grant,
                    endpoint: served.locator,
                    pairs: b.scope.pairs,
                })
            })
            .collect();
        let one = select_route_binding(&candidates, &pair, endpoint).map_err(|_| ambiguous())?;
        serde_json::to_value(ResolvedRouteBinding::from(one))
            .map_err(|_| OpError::new(Code::InternalError, "a binding cannot be rendered"))
    }

    /// One `Request::Transport` form (type docs).
    ///
    /// # Errors
    /// The operation's.
    pub async fn transport(
        &self,
        caller: &heimdall_app::Caller,
        request: &heimdall_contract::route::TransportRequest,
        now: heimdall_contract::Timestamp,
    ) -> Result<serde_json::Value, OpError> {
        let rotate = matches!(request, heimdall_contract::route::TransportRequest::Rotate);
        if rotate && caller.context.remote_client.is_some() {
            // ⟨rev6.3; ADR-0006 §18.7 items 9-10⟩ Rotating this device's key is the local
            // owner's alone; a paired session's retry can never succeed, and says so.
            return Err(OpError::new(
                Code::InteractionRequired,
                "this device's transport key is rotated by its local owner only",
            )
            .with_reason(reason::LOCAL_OWNER_REQUIRED)
            .with_effect(EffectStatus::None));
        }
        Self::owner_only(caller)?;
        let ops = heimdall_app::transport::TransportOps {
            store: &self.store,
            keys: self.keys.as_ref(),
            serve: self.supervisor.as_ref(),
            peers: self.peers.as_ref(),
        };
        if rotate {
            let _one = self.rotating.lock().await;
            let rotated = ops.rotate(self.announcer.as_deref(), now).await?;
            return serde_json::to_value(rotated).map_err(|_| {
                OpError::new(Code::InternalError, "a transport result cannot be rendered")
            });
        }
        // ⟨M06 W5; ADR-0006 §18.9 item 8⟩ A widening from the local owner becomes a local
        // decision record (`crate::local_widening`); from a paired session it is refused as
        // before (`exposure_unconsented`, in the operation).
        let whole = heimdall_contract::request::Request::Transport(request.clone());
        if let Some(delta) = self.widening_delta(&whole)?
            && !matches!(
                crate::local_widening::submission_of(caller),
                Ok(crate::local_widening::Submission::Paired)
            )
        {
            // A request that can never succeed, or that changes nothing, makes no record.
            if let Some(already) = ops.precheck(request)? {
                return Ok(already);
            }
            if matches!(
                crate::local_widening::submission_of(caller)?,
                crate::local_widening::Submission::LocalUnattended
            ) {
                return Err(crate::local_widening::unattended(whole.kind(), &delta));
            }
            return Err(self.submit_local_widening(&whole, &delta, now));
        }
        ops.execute(request, None, now).await
    }
}

// --- the serve child (feature `iroh`) -----------------------------------------------------------

/// How the child gets its K_iroh from the [`KeyRef`] the runtime sent (the integrator's
/// wiring: the platform store of this installation, checked against the reference's kind).
pub type KeySourceFactory<'a> =
    &'a (dyn Fn(&KeyRef) -> Result<Arc<dyn KeySource>, KeySourceError> + Send + Sync);

/// Why the serve child ended (internal: no exit code is public).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildExit {
    /// The lease was lost (channel EOF, a protocol violation): every stream was closed.
    LeaseLost,
    /// It never started: the reason token.
    Refused(&'static str),
    /// The endpoint closed underneath it.
    EndpointClosed,
}

impl ChildExit {
    /// A process exit code for the CLI wiring (internal: 0 after a lost lease, 1 when
    /// refused, 2 otherwise).
    #[must_use]
    pub fn code(self) -> i32 {
        match self {
            ChildExit::LeaseLost => 0,
            ChildExit::Refused(_) => 1,
            ChildExit::EndpointClosed => 2,
        }
    }
}

/// The serve child: read `start`, bind, report `ready`, then serve and apply the
/// supervision messages until the lease is lost (module docs). Reads only `input`; never a
/// standard stream.
pub async fn run_serve_child<R, W>(input: R, output: W, keys: KeySourceFactory<'_>) -> ChildExit
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    #[cfg(feature = "iroh")]
    {
        serve_child_iroh(input, output, keys).await
    }
    #[cfg(not(feature = "iroh"))]
    {
        let _ = keys;
        let mut output = output;
        drop(input);
        let _ = write_message(
            &mut output,
            &FromChild::Refused {
                reason: reason::DRIVER_UNAVAILABLE.to_owned(),
                unbindable_port: None,
            },
        )
        .await;
        ChildExit::Refused(reason::DRIVER_UNAVAILABLE)
    }
}

#[cfg(feature = "iroh")]
async fn serve_child_iroh<R, W>(input: R, mut output: W, keys: KeySourceFactory<'_>) -> ChildExit
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    use heimdall_transport_iroh::admission::Allowlist;
    use heimdall_transport_iroh::serve::{ServeConfig, ServeExit, Server};
    use heimdall_transport_iroh::target::LoopbackTarget;

    let mut input = tokio::io::BufReader::new(input);
    let refused = |token: &'static str| FromChild::Refused {
        reason: token.to_owned(),
        unbindable_port: None,
    };
    let start = read_message::<_, ToChild>(&mut input).await;
    let Ok(ToChild::Start {
        protocol,
        generation,
        allowlist,
        policy,
        target,
        key,
    }) = start
    else {
        // No lease was ever granted: nothing is bound.
        let _ = write_message(&mut output, &refused(reason::TRANSPORT_AUTHORITY_LOST)).await;
        return ChildExit::Refused(reason::TRANSPORT_AUTHORITY_LOST);
    };
    if protocol != PROTOCOL {
        let _ = write_message(&mut output, &refused(reason::TRANSPORT_UNAVAILABLE)).await;
        return ChildExit::Refused(reason::TRANSPORT_UNAVAILABLE);
    }
    // ⟨ADR-0012 §2.1 ⟨2026-11-21⟩⟩ The port the runtime asked for (named or recorded).
    let wanted_port = policy.port.filter(|p| *p != 0);
    let config = (|| {
        let allowlist = Allowlist::new(allowlist.clone()).map_err(|e| e.reason())?;
        // ⟨ADR-0006 §18.9 item 1⟩ Only the consented policy's sshd port on 127.0.0.1.
        let addr = checked_target(&policy, &target)?;
        let target = LoopbackTarget::new(addr).map_err(|_| reason::TRANSPORT_UNAVAILABLE)?;
        Ok::<_, &'static str>(ServeConfig {
            policy,
            allowlist,
            target,
        })
    })();
    let config = match config {
        Ok(c) => c,
        Err(token) => {
            let _ = write_message(&mut output, &refused(token)).await;
            return ChildExit::Refused(token);
        }
    };
    let source = match keys(&key) {
        Ok(s) => s,
        Err(e) => {
            let _ = write_message(&mut output, &refused(e.reason())).await;
            return ChildExit::Refused(e.reason());
        }
    };
    let authority = ChildAuthority::new(generation, allowlist);
    let server = match Server::bind(config, source.as_ref(), Arc::clone(&authority)).await {
        Ok(s) => s,
        Err(e) => {
            let token = known_reason(e.reason());
            let mut refusal = refused(token);
            if let (heimdall_transport_iroh::serve::ServeError::Bind, Some(port)) =
                (&e, wanted_port)
                && let FromChild::Refused {
                    unbindable_port, ..
                } = &mut refusal
            {
                *unbindable_port = Some(port);
            }
            let _ = write_message(&mut output, &refusal).await;
            return ChildExit::Refused(token);
        }
    };
    if server.endpoint_id() != &key.endpoint {
        // The store's key is not the one the runtime recorded: never serve as another
        // endpoint.
        let _ = write_message(
            &mut output,
            &refused(reason::TRANSPORT_KEY_STORE_UNAVAILABLE),
        )
        .await;
        server.shutdown_handle().shutdown();
        let _ = server.run().await;
        return ChildExit::Refused(reason::TRANSPORT_KEY_STORE_UNAVAILABLE);
    }
    // The writer task: every message to the runtime goes through it, in order.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<FromChild>();
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if write_message(&mut output, &m).await.is_err() {
                break;
            }
        }
    });
    let _ = out_tx.send(FromChild::Ready {
        endpoint: server.endpoint_id().clone(),
        generation,
        addresses: server
            .bound_sockets()
            .iter()
            .map(ToString::to_string)
            .collect(),
    });
    // The reader task: suspends are applied in order; EOF or garbage loses the lease.
    let reader_authority = Arc::clone(&authority);
    let reader_out = out_tx.clone();
    let reader = tokio::spawn(async move {
        loop {
            match read_message::<_, ToChild>(&mut input).await {
                Ok(ToChild::Suspend {
                    generation,
                    endpoints,
                }) => {
                    let Some(report) = reader_authority.suspend(generation, endpoints).await else {
                        break;
                    };
                    let _ = reader_out.send(FromChild::Suspended {
                        generation: report.generation.0,
                        closed: report.closed,
                        complete: report.complete,
                    });
                }
                Ok(ToChild::Start { .. }) | Err(LineError::Malformed) => {
                    reader_authority.lose(LeaseLoss::AuthorityUnreadable);
                    break;
                }
                Err(LineError::Eof | LineError::Io) => {
                    reader_authority.lose(LeaseLoss::ChannelClosed);
                    break;
                }
            }
        }
    });
    let exit = server.run().await;
    reader.abort();
    let (exit, token) = match exit {
        ServeExit::LeaseLost(l) => (ChildExit::LeaseLost, l.reason()),
        ServeExit::Shutdown | ServeExit::EndpointClosed => {
            (ChildExit::EndpointClosed, reason::TRANSPORT_UNAVAILABLE)
        }
    };
    let _ = out_tx.send(FromChild::Exiting {
        reason: token.to_owned(),
    });
    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
    exit
}

/// An [`AsyncRead`] over chunks a blocking thread reads from the process's standard input
/// (tokio's `io-std` is not enabled, and a blocking reader must never hold the runtime's
/// exit: the thread is detached).
struct ThreadReader {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pending: Vec<u8>,
}

impl AsyncRead for ThreadReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pending.is_empty() {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(chunk)) => self.pending = chunk,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        let n = self.pending.len().min(buf.remaining());
        buf.put_slice(&self.pending[..n]);
        self.pending.drain(..n);
        std::task::Poll::Ready(Ok(()))
    }
}

/// `heimdall transport serve`'s library half: run [`run_serve_child`] over this process's
/// standard input and output on a current-thread runtime of its own, end that runtime with
/// `shutdown_background` (so the detached standard-input reader never holds the exit, G06
/// S03), and return the internal exit code. The CLI wiring calls it and exits with the code.
#[must_use]
pub fn serve_child_stdio(keys: KeySourceFactory<'_>) -> i32 {
    use std::io::Read as _;
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return 2;
    };
    let (tx, rx) = mpsc::unbounded_channel();
    let spawned = std::thread::Builder::new()
        .name("hm-serve-stdin".into())
        .spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut chunk = vec![0u8; 16 * 1024];
            loop {
                match stdin.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(chunk[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    if spawned.is_err() {
        return 2;
    }
    let input = ThreadReader {
        rx,
        pending: Vec::new(),
    };
    let exit = runtime.block_on(async move {
        let output = StdoutWriter;
        run_serve_child(input, output, keys).await
    });
    runtime.shutdown_background();
    exit.code()
}

/// Standard output, written synchronously (each supervision line is small).
struct StdoutWriter;

impl AsyncWrite for StdoutWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::Write as _;
        std::task::Poll::Ready(std::io::stdout().write(buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::io::Write as _;
        std::task::Poll::Ready(std::io::stdout().flush())
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

// --- the route helper's Iroh leg (feature `iroh`) ---------------------------------------------

/// The route helper's Iroh leg over the transport's dialer (ADR-0012 §2.1, §5.5) with this
/// host's K_iroh.
#[cfg(feature = "iroh")]
#[derive(Clone)]
pub struct IrohRouteLeg {
    keys: Arc<dyn KeySource>,
}

#[cfg(feature = "iroh")]
impl std::fmt::Debug for IrohRouteLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohRouteLeg").finish_non_exhaustive()
    }
}

#[cfg(feature = "iroh")]
impl IrohRouteLeg {
    /// A leg dialing with `keys` (this host's K_iroh; with no verified store every Iroh
    /// route is refused and failed over).
    #[must_use]
    pub fn new(keys: Arc<dyn KeySource>) -> Self {
        Self { keys }
    }
}

#[cfg(feature = "iroh")]
struct IrohEnding {
    conn: Option<heimdall_transport_iroh::dial::PigeonsConnection>,
    result: Option<heimdall_app::routes::failover::LegEnd>,
}

#[cfg(feature = "iroh")]
impl IrohEnding {
    async fn finish(&mut self, abort: bool) -> heimdall_app::routes::failover::LegEnd {
        use heimdall_app::routes::failover::LegEnd;
        use heimdall_transport_iroh::dial::PeerClose;
        if let Some(r) = self.result {
            return r;
        }
        let Some(conn) = self.conn.take() else {
            return LegEnd::default();
        };
        // A refusal races the stream's end: give the close a moment to arrive.
        let close = if abort {
            conn.peer_close()
        } else {
            conn.closed_within(Duration::from_millis(500)).await
        };
        let r = LegEnd {
            success: !abort && matches!(close, None | Some(PeerClose::Done)),
            terminal: false,
            admission_refused: close == Some(PeerClose::AdmissionRefused),
        };
        let _ = conn.close().await;
        self.result = Some(r);
        r
    }
}

#[cfg(feature = "iroh")]
#[async_trait]
impl heimdall_app::routes::failover::LegEnding for IrohEnding {
    async fn end(&mut self) -> heimdall_app::routes::failover::LegEnd {
        self.finish(false).await
    }

    async fn abort(&mut self) -> heimdall_app::routes::failover::LegEnd {
        self.finish(true).await
    }
}

#[cfg(feature = "iroh")]
#[async_trait]
impl heimdall_app::routes::legs::IrohLegDialer for IrohRouteLeg {
    async fn dial_iroh(
        &self,
        target: heimdall_app::routes::legs::IrohLegTarget<'_>,
        connect_timeout: Duration,
    ) -> Result<heimdall_app::routes::failover::Leg, heimdall_app::routes::failover::DialFailure>
    {
        use heimdall_app::routes::failover::{DialFailure, Leg};
        use heimdall_contract::route::RouteFailureClass;
        use heimdall_transport_iroh::dial::{DialError, DialRequest, dial};
        use heimdall_transport_iroh::policy::RouteAddresses;
        let mut direct = Vec::with_capacity(target.direct_addresses.len());
        for a in target.direct_addresses {
            // A recorded address that is not `ip:port` is never dialed (route_unapproved).
            let Ok(addr) = a.parse::<std::net::SocketAddr>() else {
                return Err(DialFailure::Refused);
            };
            direct.push(addr);
        }
        let route = RouteAddresses {
            direct,
            relay_hints: Vec::new(),
        };
        let request = DialRequest {
            policy: target.exposure,
            peer: target.endpoint,
            route: &route,
            connect_timeout,
        };
        match dial(request, self.keys.as_ref()).await {
            Ok(stream) => {
                let (reader, writer, conn) = stream.into_parts();
                Ok(Leg {
                    reader: Box::new(reader),
                    writer: Box::new(writer),
                    ending: Some(Box::new(IrohEnding {
                        conn: Some(conn),
                        result: None,
                    })),
                })
            }
            Err(DialError::Failed(RouteFailureClass::Timeout)) => Err(DialFailure::Timeout),
            Err(DialError::Failed(RouteFailureClass::AdmissionRefused)) => {
                Err(DialFailure::AdmissionRefused)
            }
            // A policy refusal, no verified key store, no bind, or a refused connect: the
            // next approved route may be tried.
            Err(_) => Err(DialFailure::Refused),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn id(c: char) -> IrohEndpointId {
        IrohEndpointId::parse(&c.to_string().repeat(64)).unwrap()
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 1; ADR-0012 §2.3 item 2⟩ The serve target is
    /// `127.0.0.1` and the policy's sshd port: 22 by default, the named port otherwise; the
    /// child's check accepts exactly that target and refuses another port, another host
    /// (loopback ones included), port `0` and anything that is not a socket address.
    #[test]
    fn the_serve_target_is_the_policys_sshd_port_on_127_0_0_1_and_nothing_else() {
        let plan = |sshd_port: u16| ServePlan {
            key: KeyRef {
                endpoint: id('b'),
                store_kind: "keychain".into(),
                store_ref: "heimdall-iroh/x/y".into(),
            },
            policy: ExposurePolicy {
                sshd_port,
                ..ExposurePolicy::default()
            },
            recorded_port: Some(4433),
        };
        assert_eq!(plan(22).target(), "127.0.0.1:22");
        assert_eq!(plan(2222).target(), "127.0.0.1:2222");
        // The serve port (named or recorded) never moves the target.
        assert_eq!(plan(2222).effective_policy().sshd_port, 2222);
        for port in [22u16, 2222, 65535] {
            let p = plan(port);
            assert_eq!(
                checked_target(&p.policy, &p.target()),
                Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            );
        }
        let policy = plan(2222).policy;
        for other in [
            "127.0.0.1:22",
            "127.0.0.1:2223",
            "127.0.0.2:2222",
            "[::1]:2222",
            "0.0.0.0:2222",
            "192.0.2.1:2222",
            "localhost:2222",
            "2222",
            "",
        ] {
            assert_eq!(
                checked_target(&policy, other),
                Err(reason::TRANSPORT_UNAVAILABLE),
                "{other}"
            );
        }
        assert_eq!(
            checked_target(&plan(0).policy, "127.0.0.1:0"),
            Err(reason::TRANSPORT_UNAVAILABLE)
        );
    }

    /// ⟨M06 W5⟩ The real child entry refuses a `start` whose target is not its policy's
    /// sshd port, before any key is read or anything is bound (the key source is never
    /// asked).
    #[cfg(feature = "iroh")]
    #[tokio::test]
    async fn the_serve_child_refuses_a_target_on_another_port() {
        let start = |sshd_port: u16, target: &str| ToChild::Start {
            protocol: PROTOCOL.into(),
            generation: 1,
            allowlist: vec![id('a')],
            policy: ExposurePolicy {
                sshd_port,
                ..ExposurePolicy::default()
            },
            target: target.into(),
            key: KeyRef {
                endpoint: id('b'),
                store_kind: "keychain".into(),
                store_ref: "heimdall-iroh/x/y".into(),
            },
        };
        for (sshd_port, target) in [
            (2222, "127.0.0.1:22"),
            (22, "127.0.0.1:2222"),
            (2222, "127.0.0.2:2222"),
            (2222, "[::1]:2222"),
        ] {
            let mut input = Vec::new();
            write_message(&mut input, &start(sshd_port, target))
                .await
                .unwrap();
            let asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let seen = Arc::clone(&asked);
            let keys = move |_: &KeyRef| -> Result<Arc<dyn KeySource>, KeySourceError> {
                seen.store(true, Ordering::SeqCst);
                Err(KeySourceError::Missing)
            };
            let (reply, mut answers) = tokio::io::duplex(4096);
            let exit = run_serve_child(std::io::Cursor::new(input), reply, &keys).await;
            assert_eq!(
                exit,
                ChildExit::Refused(reason::TRANSPORT_UNAVAILABLE),
                "{target}"
            );
            assert!(!asked.load(Ordering::SeqCst), "{target}: the key was read");
            let mut reader = tokio::io::BufReader::new(&mut answers);
            let answer: FromChild = read_message(&mut reader).await.unwrap();
            assert!(
                matches!(&answer, FromChild::Refused { reason: r, .. }
                    if r == reason::TRANSPORT_UNAVAILABLE),
                "{target}: {answer:?}"
            );
        }
    }

    /// The supervision protocol round trips, refuses unknown fields and over-long lines,
    /// and reports EOF.
    #[tokio::test]
    async fn supervision_lines_round_trip_and_are_bounded() {
        let start = ToChild::Start {
            protocol: PROTOCOL.into(),
            generation: 3,
            allowlist: vec![id('a')],
            policy: ExposurePolicy::default(),
            target: "127.0.0.1:22".into(),
            key: KeyRef {
                endpoint: id('b'),
                store_kind: "keychain".into(),
                store_ref: "heimdall-iroh/x/y".into(),
            },
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &start).await.unwrap();
        write_message(
            &mut buf,
            &ToChild::Suspend {
                generation: 4,
                endpoints: vec![],
            },
        )
        .await
        .unwrap();
        let mut r = tokio::io::BufReader::new(&buf[..]);
        assert_eq!(read_message::<_, ToChild>(&mut r).await.unwrap(), start);
        assert!(matches!(
            read_message::<_, ToChild>(&mut r).await.unwrap(),
            ToChild::Suspend { generation: 4, .. }
        ));
        assert_eq!(
            read_message::<_, ToChild>(&mut r).await,
            Err(LineError::Eof)
        );
        let unknown = b"{\"t\":\"suspend\",\"generation\":1,\"endpoints\":[],\"x\":1}\n";
        let mut r = tokio::io::BufReader::new(&unknown[..]);
        assert_eq!(
            read_message::<_, ToChild>(&mut r).await,
            Err(LineError::Malformed)
        );
        let long = vec![b'x'; MAX_LINE + 10];
        let mut r = tokio::io::BufReader::new(&long[..]);
        assert_eq!(
            read_message::<_, ToChild>(&mut r).await,
            Err(LineError::Malformed)
        );
    }

    /// The child's authority: a suspend withdraws admission at once (before the
    /// acknowledgement), the lease moves only with the acknowledgement, an older
    /// generation never moves it back, and a lost lease admits nothing.
    #[tokio::test]
    async fn the_child_authority_mirrors_the_runtime_and_moves_its_lease_on_acknowledgement() {
        let auth = ChildAuthority::new(5, [id('a'), id('b')]);
        assert_eq!(auth.lease(), LeaseState::Held(AuthorityGeneration(5)));
        assert!(auth.is_admitted(AuthorityGeneration(5), &id('a')));
        let a2 = Arc::clone(&auth);
        let suspend = tokio::spawn(async move { a2.suspend(6, vec![id('a')]).await });
        let AdmissionSignal::Suspend(req) = auth.next_signal().await else {
            panic!("expected a suspend");
        };
        assert_eq!(req.generation, AuthorityGeneration(6));
        assert!(!auth.is_admitted(AuthorityGeneration(6), &id('a')));
        assert!(auth.is_admitted(AuthorityGeneration(6), &id('b')));
        assert!(!auth.is_admitted(AuthorityGeneration(5), &id('b')));
        assert_eq!(auth.lease(), LeaseState::Held(AuthorityGeneration(5)));
        req.ack
            .acknowledge(heimdall_transport_iroh::admission::SuspendReport {
                generation: req.generation,
                closed: 1,
                complete: true,
            });
        assert!(suspend.await.unwrap().unwrap().complete);
        assert_eq!(auth.lease(), LeaseState::Held(AuthorityGeneration(6)));
        // An older generation never moves the committed generation back.
        let a3 = Arc::clone(&auth);
        let stale = tokio::spawn(async move { a3.suspend(4, vec![]).await });
        let AdmissionSignal::Suspend(req) = auth.next_signal().await else {
            panic!("expected a suspend");
        };
        assert_eq!(req.generation, AuthorityGeneration(6));
        req.ack
            .acknowledge(heimdall_transport_iroh::admission::SuspendReport {
                generation: AuthorityGeneration(6),
                closed: 0,
                complete: true,
            });
        stale.await.unwrap().unwrap();
        auth.lose(LeaseLoss::ChannelClosed);
        assert_eq!(auth.lease(), LeaseState::Lost(LeaseLoss::ChannelClosed));
        assert!(!auth.is_admitted(AuthorityGeneration(6), &id('b')));
    }

    /// Store errors map to the transport's key errors (all
    /// `transport_key_store_unavailable`), and an unknown child reason is never echoed.
    #[test]
    fn key_errors_and_child_reasons_map_to_tokens() {
        assert_eq!(
            key_source_error(&IrohStoreError::Unavailable(IrohStoreAvailability::Locked)),
            KeySourceError::Locked
        );
        assert_eq!(
            key_source_error(&IrohStoreError::Unavailable(
                IrohStoreAvailability::Unsupported
            )),
            KeySourceError::StoreUnavailable
        );
        assert_eq!(
            key_source_error(&IrohStoreError::NotFound),
            KeySourceError::Missing
        );
        assert_eq!(
            known_reason("transport_key_store_unavailable"),
            "transport_key_store_unavailable"
        );
        assert_eq!(known_reason("/home/x secret"), "transport_unavailable");
    }
}
