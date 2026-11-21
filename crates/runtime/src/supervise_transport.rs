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
    /// The endpoint's exposure policy.
    pub policy: ExposurePolicy,
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

/// The supervisor's bounds and target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// How the child is started.
    pub spawn: ServeSpawn,
    /// The local sshd port the child forwards to (`127.0.0.1:<port>`).
    pub sshd_port: u16,
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
    /// The defaults for `spawn`: sshd on port 22, 10 s to start, 3 s to acknowledge, 5 s to
    /// stop, a 1 s watchdog.
    #[must_use]
    pub fn new(spawn: ServeSpawn) -> Self {
        Self {
            spawn,
            sshd_port: 22,
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
            policy: plan.policy.clone(),
            target: format!("127.0.0.1:{}", self.config.sshd_port),
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
                running.endpoint = endpoint;
                running.addresses = addresses;
                Ok(running)
            }
            Ok(Some(FromChild::Refused { reason })) => {
                let token = known_reason(&reason);
                // A child that refused binds nothing; one whose exit cannot be confirmed is
                // dropped (`kill_on_drop` kills it again).
                drop(running.kill(self.config.stop_bound).await);
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
    let config = (|| {
        let allowlist = Allowlist::new(allowlist.clone()).map_err(|e| e.reason())?;
        let addr: std::net::SocketAddr =
            target.parse().map_err(|_| reason::TRANSPORT_UNAVAILABLE)?;
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
            let _ = write_message(&mut output, &refused(token)).await;
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
