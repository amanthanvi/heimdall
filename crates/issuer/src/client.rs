//! The runtime side of the issuer (ADR-0008 D3 items 6–7; m03-plan U3
//! `client::ChildIssuer`): spawns the child with piped stdin and stdout, speaks
//! [`crate::protocol`] with a 10 s per-request bound and `request_id` matching,
//! discards and zeroizes late replies, supervises the child by exact PID and start
//! token (the D3 item 7 states, with bounded, jittered backoff), and implements
//! `app::ports::IssuerPort`.
//!
//! **The channel.** The child's stdin and stdout are the only channel; its stderr is
//! discarded here (the runtime's redacted log is U10's wiring). The child is spawned
//! `kill_on_drop`, so dropping the client ends it, and a dead runtime closes the
//! child's stdin, which the child reads as EOF.
//!
//! **One request at a time.** The link is held for a request's write and its reply.
//! Frames are read into a buffer that lives with the link, so a request future dropped
//! mid-read (the 10 s bound, or the adapter's own drop) loses nothing: its reply is
//! read by the next request **first**, matched to no pending `request_id`, zeroized
//! (a certificate) and discarded. A write cancelled half way leaves the stream unusable;
//! the next request then ends the child and the supervisor restarts it.
//!
//! **Supervision** (D3 item 7): `starting` (hello within [`HELLO_TIMEOUT`], the
//! `hello_ack` echoing the nonce and naming the spawned PID), `loading`, `ready`, or
//! `store_unavailable{reason}` (the child stays up with no key; the next demand after
//! the jittered backoff, or [`ChildIssuer::reload`] for `issuer unlock`, loads again).
//! A child that exits or breaks the protocol is `crashed` and restarted after
//! [`backoff_ceiling`]-bounded, jittered delays (base 1 s, cap 60 s), at most
//! [`MAX_RESTART_ATTEMPTS`] times, then `unavailable` until the next demand or
//! `issuer unlock`. While not `ready`, `sign` fails `issuer_unavailable` (or the store
//! reason) at once; nothing falls back to another key.
//!
//! **Identity.** The child is the exact process this client spawned: its PID (from the
//! spawn, confirmed by the `hello_ack`) and its start token, read through the
//! injected [`StartToken`] (the runtime's `platform::process_start_time`; `heimdall-
//! runtime` is not a dependency of this crate). It is only ever ended through the
//! owned process handle, never by name.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::ports::{IssuerError, IssuerPort, IssuerStatusSnapshot};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::{IssuerState, IssuerStatus};
use heimdall_contract::managed::IssuerIsolation;
use heimdall_credential::vault::SystemRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::Instant;
use zeroize::Zeroize;

use crate::protocol::{
    IssuanceRef, LoadedCa, PROTOCOL, Request, Response, TOKEN_HEX_CHARS, split_frame,
};
use crate::store::StoreAvailability;

/// The per-request bound (ADR-0008 D3 item 6), inside the 30 s adapter-call bound.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The `hello` bound of `starting` (D3 item 7).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// The restart backoff's base (D3 item 7).
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// The restart backoff's cap (D3 item 7).
pub const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// Restart attempts after a crash before `unavailable` (D3 item 7).
pub const MAX_RESTART_ATTEMPTS: u32 = 8;
/// How long `stop` waits for the child to exit after `shutdown` before ending it.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// The ceiling of the `attempt`-th restart delay (1-based): `min(cap, base·2^(n−1))`.
#[must_use]
pub fn backoff_ceiling(attempt: u32) -> Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    BACKOFF_BASE
        .saturating_mul(1u32 << doublings)
        .min(BACKOFF_CAP)
}

/// The jitter of the restart backoff (injectable; D3 item 7). `delay(ceiling)` must
/// return a delay at most `ceiling`.
pub trait Jitter: Send + Sync {
    /// The delay to wait before an attempt whose ceiling is `ceiling`.
    fn delay(&self, ceiling: Duration) -> Duration;
}

/// The production jitter: uniform in `[ceiling/2, ceiling]` from the OS CSPRNG (the
/// full ceiling if randomness is unavailable).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemJitter;

impl Jitter for SystemJitter {
    fn delay(&self, ceiling: Duration) -> Duration {
        let half = ceiling / 2;
        let mut b = [0u8; 8];
        if SystemRng::fill(&mut b).is_err() {
            return ceiling;
        }
        let span = u64::try_from(half.as_millis()).unwrap_or(u64::MAX);
        let extra = if span == 0 {
            0
        } else {
            u64::from_le_bytes(b) % span.saturating_add(1)
        };
        (half + Duration::from_millis(extra)).min(ceiling)
    }
}

/// Reads a process's opaque start token by PID (`None`: not readable).
pub type StartToken = Arc<dyn Fn(u32) -> Option<String> + Send + Sync>;

/// The exact identity of the running child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildIdentity {
    /// Its PID (from the spawn, confirmed by `hello_ack`).
    pub pid: u32,
    /// Its start token (`None` when the platform reader could not read it).
    pub start_token: Option<String>,
}

/// What to spawn as the child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildCommand {
    /// The program.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// Extra environment variables (on top of the inherited environment).
    pub env: Vec<(OsString, OsString)>,
}

impl ChildCommand {
    /// The production child: this executable, `internal issuer`.
    ///
    /// # Errors
    /// The current executable cannot be determined.
    pub fn internal_issuer() -> std::io::Result<Self> {
        Ok(Self {
            program: std::env::current_exe()?,
            args: vec!["internal".into(), "issuer".into()],
            env: Vec::new(),
        })
    }
}

/// The client's configuration.
#[derive(Clone)]
pub struct ClientConfig {
    /// The child to spawn.
    pub command: ChildCommand,
    /// The restart jitter.
    pub jitter: Arc<dyn Jitter>,
    /// The start-token reader.
    pub start_token: StartToken,
    /// The per-request bound ([`REQUEST_TIMEOUT`]).
    pub request_timeout: Duration,
    /// The hello bound ([`HELLO_TIMEOUT`]).
    pub hello_timeout: Duration,
}

impl ClientConfig {
    /// The defaults around `command`, with [`SystemJitter`] and `start_token`.
    #[must_use]
    pub fn new(command: ChildCommand, start_token: StartToken) -> Self {
        Self {
            command,
            jitter: Arc::new(SystemJitter),
            start_token,
            request_timeout: REQUEST_TIMEOUT,
            hello_timeout: HELLO_TIMEOUT,
        }
    }
}

/// The supervised view (never blocks to read).
#[derive(Debug, Clone)]
struct View {
    state: IssuerState,
    reason: Option<String>,
    cas: Vec<LoadedCa>,
    identity: Option<ChildIdentity>,
    /// When the next on-demand reload or restart may run (`store_unavailable`,
    /// `unavailable`).
    retry_at: Option<Instant>,
    /// The restart cycle in progress, if any.
    restarting: bool,
    /// The store-reload attempt count since the last success.
    reload_attempts: u32,
}

/// The live link to one child.
struct Link {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// Bytes read but not yet consumed as frames (survives a dropped request).
    buf: Vec<u8>,
    /// Replies owed for requests whose callers stopped waiting.
    outstanding: usize,
    /// A write did not finish: the stream is unusable.
    dirty: bool,
}

/// A broken link (EOF, a malformed frame, a write that failed).
#[derive(Debug)]
struct Broken;

impl Link {
    /// The next frame's reply, reading into the persistent buffer (cancel-safe).
    async fn next_reply(&mut self) -> Result<Response, Broken> {
        loop {
            match split_frame(&self.buf) {
                Ok(Some((body, used))) => {
                    let decoded = Response::decode(body);
                    // The consumed frame may hold a certificate: zeroize it.
                    let mut consumed: Vec<u8> = self.buf.drain(..used).collect();
                    consumed.zeroize();
                    return decoded.map_err(|_| Broken);
                }
                Ok(None) => {}
                Err(_) => return Err(Broken),
            }
            let mut chunk = [0u8; 4096];
            match self.stdout.read(&mut chunk).await {
                Ok(0) | Err(_) => return Err(Broken),
                Ok(n) => self.buf.extend_from_slice(chunk.get(..n).ok_or(Broken)?),
            }
        }
    }
}

/// Zeroize a reply nobody waits for (a late certificate).
fn discard(reply: Response) {
    if let Response::Signed {
        mut certificate, ..
    } = reply
    {
        certificate.zeroize();
    }
}

/// 32 lowercase hex from the OS CSPRNG.
fn token() -> Result<String, IssuerError> {
    let mut b = [0u8; TOKEN_HEX_CHARS / 2];
    SystemRng::fill(&mut b)
        .map_err(|_| IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

struct Inner {
    config: ClientConfig,
    view: Mutex<View>,
    link: tokio::sync::Mutex<Option<Link>>,
}

/// The issuer child's client (module docs).
#[derive(Clone)]
pub struct ChildIssuer {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ChildIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildIssuer")
            .field("view", &self.inner.view())
            .finish_non_exhaustive()
    }
}

impl Inner {
    fn view(&self) -> View {
        self.view
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn update(&self, f: impl FnOnce(&mut View)) {
        f(&mut self.view.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn set_state(&self, state: IssuerState, reason: Option<String>) {
        self.update(|v| {
            v.state = state;
            v.reason = reason;
        });
    }

    /// Write `request` and wait for its reply, after draining late replies.
    async fn exchange(
        &self,
        link: &mut Link,
        request: &Request,
        bound: Duration,
    ) -> Result<Response, IssuerError> {
        let frame = request
            .encode()
            .map_err(|_| IssuerError::Protocol("request not encodable".into()))?;
        let work = async {
            if link.dirty {
                return Err(Broken);
            }
            while link.outstanding > 0 {
                discard(link.next_reply().await?);
                link.outstanding -= 1;
            }
            link.dirty = true;
            link.stdin.write_all(&frame).await.map_err(|_| Broken)?;
            link.stdin.flush().await.map_err(|_| Broken)?;
            link.dirty = false;
            // Owed until read: a drop or a timeout from here leaves it to be drained.
            link.outstanding += 1;
            let reply = link.next_reply().await?;
            link.outstanding -= 1;
            Ok(reply)
        };
        match tokio::time::timeout(bound, work).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(Broken)) => Err(IssuerError::Unavailable(reason::ISSUER_RESTARTING.into())),
            Err(_) => Err(IssuerError::Timeout),
        }
    }

    /// End the link's child (exact owned handle) and mark `crashed`.
    async fn crash(self: &Arc<Self>, slot: &mut Option<Link>) {
        if let Some(mut link) = slot.take() {
            let _ = link.child.start_kill();
            let _ = link.child.wait().await;
            link.buf.zeroize();
        }
        self.update(|v| {
            v.state = IssuerState::Crashed;
            v.reason = Some(reason::ISSUER_RESTARTING.into());
            v.cas.clear();
            v.identity = None;
        });
    }

    /// Spawn, hello, load: one start attempt (`starting → loading → ready |
    /// store_unavailable`).
    async fn start_once(self: &Arc<Self>) -> Result<(), IssuerError> {
        let mut slot = self.link.lock().await;
        if let Some(mut old) = slot.take() {
            let _ = old.child.start_kill();
            let _ = old.child.wait().await;
        }
        self.set_state(IssuerState::Starting, None);
        let c = &self.config.command;
        let mut cmd = Command::new(&c.program);
        cmd.args(&c.args)
            .envs(c.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let spawned = cmd.spawn();
        let Ok(mut child) = spawned else {
            self.set_state(
                IssuerState::Crashed,
                Some(reason::ISSUER_UNAVAILABLE.into()),
            );
            return Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()));
        };
        let (Some(stdin), Some(stdout), Some(pid)) =
            (child.stdin.take(), child.stdout.take(), child.id())
        else {
            let _ = child.start_kill();
            let _ = child.wait().await;
            self.set_state(
                IssuerState::Crashed,
                Some(reason::ISSUER_UNAVAILABLE.into()),
            );
            return Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()));
        };
        let identity = ChildIdentity {
            pid,
            start_token: (self.config.start_token)(pid),
        };
        *slot = Some(Link {
            child,
            stdin,
            stdout,
            buf: Vec::new(),
            outstanding: 0,
            dirty: false,
        });
        let nonce = token()?;
        let hello = Request::Hello {
            protocol: PROTOCOL.into(),
            nonce: nonce.clone(),
        };
        let Some(link) = slot.as_mut() else {
            return Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()));
        };
        match self.exchange(link, &hello, self.config.hello_timeout).await {
            Ok(Response::HelloAck { nonce: n, pid: p }) if n == nonce && p == pid => {}
            _ => {
                self.crash(&mut slot).await;
                return Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()));
            }
        }
        self.update(|v| v.identity = Some(identity));
        self.load_locked(&mut slot).await
    }

    /// `load` over the held link (`loading → ready | store_unavailable`).
    async fn load_locked(self: &Arc<Self>, slot: &mut Option<Link>) -> Result<(), IssuerError> {
        self.set_state(IssuerState::Loading, None);
        let Some(link) = slot.as_mut() else {
            return Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()));
        };
        match self
            .exchange(link, &Request::Load {}, self.config.request_timeout)
            .await
        {
            Ok(Response::Loaded { cas }) => {
                self.update(|v| {
                    v.state = IssuerState::Ready;
                    v.reason = None;
                    v.cas = cas;
                    v.retry_at = None;
                    v.reload_attempts = 0;
                });
                Ok(())
            }
            Ok(Response::StoreUnavailable { reason: a }) => {
                let why = store_reason(a);
                let jitter = Arc::clone(&self.config.jitter);
                self.update(|v| {
                    v.reload_attempts = v.reload_attempts.saturating_add(1);
                    v.state = IssuerState::StoreUnavailable;
                    v.reason = Some(why.clone());
                    v.cas.clear();
                    v.retry_at =
                        Some(Instant::now() + jitter.delay(backoff_ceiling(v.reload_attempts)));
                });
                Err(IssuerError::Unavailable(why))
            }
            _ => {
                self.crash(slot).await;
                Err(IssuerError::Unavailable(reason::ISSUER_RESTARTING.into()))
            }
        }
    }

    /// The bounded, jittered restart cycle after a crash (D3 item 7).
    async fn restart_cycle(self: Arc<Self>) {
        for attempt in 1..=MAX_RESTART_ATTEMPTS {
            let delay = self.config.jitter.delay(backoff_ceiling(attempt));
            tokio::time::sleep(delay.min(backoff_ceiling(attempt))).await;
            match self.start_once().await {
                Ok(()) => break,
                // The child is up without its key: the store reload follows its own
                // backoff on demand.
                Err(_) if self.view().state == IssuerState::StoreUnavailable => break,
                Err(_) if attempt == MAX_RESTART_ATTEMPTS => {
                    self.set_state(
                        IssuerState::Unavailable,
                        Some(reason::ISSUER_UNAVAILABLE.into()),
                    );
                }
                Err(_) => {}
            }
        }
        self.update(|v| v.restarting = false);
    }

    /// Start a restart cycle unless one runs.
    fn supervise(self: &Arc<Self>) {
        let start = {
            let mut v = self.view.lock().unwrap_or_else(PoisonError::into_inner);
            let start = !v.restarting;
            v.restarting = true;
            start
        };
        if start {
            tokio::spawn(Arc::clone(self).restart_cycle());
        }
    }

    /// The error for a demand while not ready; kicks the on-demand recovery.
    fn not_ready(self: &Arc<Self>, view: &View) -> IssuerError {
        match view.state {
            IssuerState::Crashed | IssuerState::Unavailable => self.supervise(),
            IssuerState::StoreUnavailable if view.retry_at.is_none_or(|t| t <= Instant::now()) => {
                let me = Arc::clone(self);
                tokio::spawn(async move {
                    let mut slot = me.link.lock().await;
                    let _ = me.load_locked(&mut slot).await;
                });
            }
            _ => {}
        }
        IssuerError::Unavailable(
            view.reason
                .clone()
                .unwrap_or_else(|| reason::ISSUER_UNAVAILABLE.into()),
        )
    }
}

/// The `CAPABILITY_UNAVAILABLE` sub-reason of an unavailable store.
fn store_reason(a: StoreAvailability) -> String {
    a.refusal_reason()
        .unwrap_or(reason::ISSUER_STORE_UNAVAILABLE)
        .to_owned()
}

impl ChildIssuer {
    /// A client that has not started its child (`not_initialized`).
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                view: Mutex::new(View {
                    state: IssuerState::NotInitialized,
                    reason: Some(reason::ISSUER_NOT_INITIALIZED.into()),
                    cas: Vec::new(),
                    identity: None,
                    retry_at: None,
                    restarting: false,
                    reload_attempts: 0,
                }),
                link: tokio::sync::Mutex::new(None),
            }),
        }
    }

    /// Spawn the child and bring it to `ready` (or `store_unavailable`). A failed
    /// start is `crashed`, and the supervisor's restart cycle takes over.
    ///
    /// # Errors
    /// [`IssuerError::Unavailable`] with the reason (`issuer_store_locked`,
    /// `issuer_store_unavailable`, `issuer_unavailable`).
    pub async fn start(&self) -> Result<(), IssuerError> {
        let r = self.inner.start_once().await;
        if r.is_err() && self.inner.view().state == IssuerState::Crashed {
            self.inner.supervise();
        }
        r
    }

    /// `issuer unlock`: load the store again over the running child (or start it).
    ///
    /// # Errors
    /// As [`ChildIssuer::start`].
    pub async fn reload(&self) -> Result<(), IssuerError> {
        let mut slot = self.inner.link.lock().await;
        if slot.is_none() {
            drop(slot);
            return self.start().await;
        }
        self.inner.load_locked(&mut slot).await
    }

    /// Ask the child to exit (`stopping`): `shutdown`, then EOF; the child is ended
    /// through its handle if it has not exited within [`STOP_TIMEOUT`].
    pub async fn stop(&self) {
        let mut slot = self.inner.link.lock().await;
        self.inner.set_state(IssuerState::Stopping, None);
        if let Some(mut link) = slot.take() {
            let shutdown = Request::Shutdown {}.encode();
            if !link.dirty
                && let Ok(frame) = shutdown
            {
                let _ = link.stdin.write_all(&frame).await;
                let _ = link.stdin.flush().await;
            }
            drop(link.stdin);
            if tokio::time::timeout(STOP_TIMEOUT, link.child.wait())
                .await
                .is_err()
            {
                let _ = link.child.start_kill();
                let _ = link.child.wait().await;
            }
            link.buf.zeroize();
        }
        self.inner.update(|v| {
            v.state = IssuerState::Unavailable;
            v.reason = Some(reason::ISSUER_UNAVAILABLE.into());
            v.cas.clear();
            v.identity = None;
        });
    }

    /// The running child's exact identity.
    #[must_use]
    pub fn identity(&self) -> Option<ChildIdentity> {
        self.inner.view().identity
    }

    /// The CAs the child reported loaded.
    #[must_use]
    pub fn loaded_cas(&self) -> Vec<LoadedCa> {
        self.inner.view().cas
    }

    /// The supervised state.
    #[must_use]
    pub fn state(&self) -> IssuerState {
        self.inner.view().state
    }

    /// The child's own `status` (CAs and counters).
    ///
    /// # Errors
    /// [`IssuerError`].
    pub async fn child_status(&self) -> Result<(Vec<LoadedCa>, u64, u64), IssuerError> {
        let mut slot = self.inner.link.lock().await;
        let Some(link) = slot.as_mut() else {
            return Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()));
        };
        match self
            .inner
            .exchange(link, &Request::Status {}, self.inner.config.request_timeout)
            .await
        {
            Ok(Response::Status {
                cas,
                signed_total,
                refused_total,
            }) => Ok((cas, signed_total, refused_total)),
            Ok(_) => {
                self.inner.crash(&mut slot).await;
                self.inner.supervise();
                Err(IssuerError::Protocol("unexpected reply to status".into()))
            }
            Err(e) => {
                self.broken(&mut slot, &e).await;
                Err(e)
            }
        }
    }

    /// After a failed exchange: a broken link crashes the child and starts the
    /// restart cycle; a timeout keeps the link (its reply is drained later).
    async fn broken(&self, slot: &mut Option<Link>, e: &IssuerError) {
        if !matches!(e, IssuerError::Timeout) {
            self.inner.crash(slot).await;
            self.inner.supervise();
        }
    }
}

#[async_trait]
impl IssuerPort for ChildIssuer {
    fn status(&self) -> IssuerStatusSnapshot {
        let v = self.inner.view();
        IssuerStatusSnapshot {
            status: IssuerStatus {
                state: v.state,
                reason: v.reason,
                // The registered CAs' records are the runtime's (store) view; U10 fills them.
                cas: Vec::new(),
                orphan_store_items: Vec::new(),
                issuer_isolation: IssuerIsolation::SameUserProcess,
                bundle_stale: false,
            },
        }
    }

    async fn sign(&self, entry: IssuanceRef, subject: &str) -> Result<String, IssuerError> {
        let view = self.inner.view();
        if view.state != IssuerState::Ready {
            return Err(self.inner.not_ready(&view));
        }
        let request_id = token()?;
        let request = Request::Sign {
            request_id: request_id.clone(),
            reservation: entry,
            subject_public_key: subject.to_owned(),
        };
        let mut slot = self.inner.link.lock().await;
        let Some(link) = slot.as_mut() else {
            return Err(IssuerError::Unavailable(reason::ISSUER_UNAVAILABLE.into()));
        };
        match self
            .inner
            .exchange(link, &request, self.inner.config.request_timeout)
            .await
        {
            Ok(Response::Signed {
                request_id: id,
                certificate,
            }) if id == request_id => Ok(certificate),
            Ok(Response::Refused {
                request_id: id,
                reason: why,
            }) if id == request_id => Err(IssuerError::Refused(why)),
            Ok(other) => {
                discard(other);
                self.inner.crash(&mut slot).await;
                self.inner.supervise();
                Err(IssuerError::Protocol(
                    "reply does not match the request".into(),
                ))
            }
            Err(e) => {
                self.broken(&mut slot, &e).await;
                Err(e)
            }
        }
    }

    async fn unload(&self, ca: &CaFingerprint) -> Result<(), IssuerError> {
        let mut slot = self.inner.link.lock().await;
        let Some(link) = slot.as_mut() else {
            // No child holds any key: nothing to zeroize.
            self.inner
                .update(|v| v.cas.retain(|c| c.fingerprint != *ca));
            return Ok(());
        };
        match self
            .inner
            .exchange(
                link,
                &Request::Unload {
                    ca_fingerprint: ca.clone(),
                },
                self.inner.config.request_timeout,
            )
            .await
        {
            Ok(Response::Unloaded { ca_fingerprint }) if ca_fingerprint == *ca => {
                self.inner
                    .update(|v| v.cas.retain(|c| c.fingerprint != *ca));
                Ok(())
            }
            Ok(other) => {
                discard(other);
                self.inner.crash(&mut slot).await;
                self.inner.supervise();
                Err(IssuerError::Protocol(
                    "reply does not match the request".into(),
                ))
            }
            Err(e) => {
                self.broken(&mut slot, &e).await;
                Err(e)
            }
        }
    }
}
