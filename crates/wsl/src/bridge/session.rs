//! The Windows side of Mode B: [`Bridge`], one helper session serving one Mode B environment's
//! endpoints (ADR-0010 §3 items 3–8; design U4 §2).
//!
//! **Threads.** One reader thread takes the helper's frames; one writer thread writes the
//! frames the calls and the streams queue; the stream pumps run on a small current-thread
//! runtime of the bridge's own. [`Bridge::realize`], [`Bridge::withdraw`] and
//! [`Bridge::realized`] block (at most [`proto::BRIDGE_CALL_TIMEOUT`]) and are meant for the
//! blocking pool.
//!
//! **Streams.** The helper opens them (odd, increasing numbers). For each, the reader makes a
//! `tokio::io::duplex` pair and gives one end to the [`StreamHandler`], which serves it with the
//! binding's signer; the other end is pumped to and from `data` frames. A stream ends when the
//! handler's end closes, when the helper says `close`, or after [`proto::STREAM_IDLE`] without a
//! byte. A `close` is one-way (the receiver sends none back), and a frame for a stream that
//! already ended is dropped: the two directions cross, so the sender cannot have known.
//!
//! **Violations** end the session (the helper is killed and every later call answers
//! `wsl_helper_unavailable`): a frame the state does not expect, an unknown stream, a stream
//! number that is even or not above the last, a 65th stream of one binding, oversized or
//! malformed `data`.

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use heimdall_app::ports::{DistributionStart, DistributionTarget};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio_util::sync::CancellationToken;

use crate::client::{
    ChildGuard, Expected, HelperLauncher, HelperSession, SessionError, SessionParts,
};
use crate::proto::{
    self, ErrorKind, HelperFrame, Inbound, MAX_STREAMS_PER_BINDING, STREAM_IDLE, StreamRef,
    WindowsFrame,
};

/// The duplex pipe's capacity per stream: above one agent message.
const DUPLEX_CAPACITY: usize = proto::MAX_AGENT_MESSAGE + (32 << 10);
/// What a pump reads from the handler's end at a time.
const PUMP_CHUNK: usize = 64 << 10;
/// The frames queued towards one stream's handler.
const STREAM_QUEUE: usize = 32;

/// Where a realized binding lives inside the distribution (Linux paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realized {
    /// The signing endpoint's socket.
    pub socket: String,
    /// The binding's `ssh_config`.
    pub ssh_config: String,
}

/// The longest run directory a hello may name (a path, `PATH_MAX`); its socket paths are
/// bounded by `proto::MAX_SOCKET_PATH` at each realize.
const MAX_RUN_DIR: usize = 4096;

/// The paths a binding is realized at, from the helper's run directory (`run_dir`, from its
/// hello): Windows renders the `ssh_config` text with them **before** it calls
/// [`Bridge::realize`]. The helper answers the same two paths, and a different answer is a
/// protocol error.
#[must_use]
pub fn realized_paths(run_dir: &str, binding_tag: &str) -> Realized {
    Realized {
        socket: proto::socket_path(run_dir, binding_tag),
        ssh_config: proto::ssh_config_path(run_dir, binding_tag),
    }
}

/// The public material a binding is realized with (never a private key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgePublic {
    /// `(file name, one OpenSSH line)` per certificate and public key; names are checked
    /// against `[A-Za-z0-9._-]{1,64}`.
    pub files: Vec<(String, String)>,
    /// The rendered `ssh_config` text with the in-distribution paths **already in it**
    /// ([`realized_paths`]).
    pub ssh_config: String,
    /// The known-hosts text.
    pub known_hosts: String,
}

/// What Windows does with a stream a Linux client opened on a binding's endpoint.
pub trait StreamHandler: Send + Sync {
    /// Serve one stream of `binding_tag`'s endpoint: `stream` carries the agent protocol bytes
    /// (already admitted by the helper: peer uid, `classify`). The handler spawns its own task
    /// (on its runtime handle) and returns at once. Returning `false` refuses it (unknown tag,
    /// no signer): the bridge closes the stream.
    fn serve(&self, binding_tag: &str, stream: DuplexStream) -> bool;
}

/// What a call waits for.
enum Pending {
    Realize,
    Withdraw,
    Realized,
}

struct Call {
    kind: Pending,
    reply: mpsc::Sender<HelperFrame>,
}

struct Stream {
    tag: String,
    to_handler: tokio::sync::mpsc::Sender<Vec<u8>>,
}

#[derive(Default)]
struct Streams {
    open: HashMap<u64, Stream>,
    highest: u64,
}

struct Inner {
    run_dir: String,
    out: Mutex<Option<mpsc::Sender<WindowsFrame>>>,
    calls: Mutex<HashMap<u64, Call>>,
    streams: Mutex<Streams>,
    dead: AtomicBool,
    next_id: AtomicU64,
    handler: Arc<dyn StreamHandler>,
    rt: tokio::runtime::Handle,
    child: Mutex<ChildGuard>,
    stderr: Arc<Mutex<Vec<u8>>>,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Inner {
    fn send(&self, frame: WindowsFrame) -> Result<(), SessionError> {
        match locked(&self.out).as_ref() {
            Some(tx) => tx.send(frame).map_err(|_| SessionError::Gone),
            None => Err(SessionError::Gone),
        }
    }

    /// End the session: every call and stream fails, the writer stops and the helper is killed.
    fn fail(&self) {
        self.dead.store(true, Ordering::SeqCst);
        *locked(&self.out) = None;
        locked(&self.calls).clear();
        locked(&self.streams).open.clear();
        locked(&self.child).kill_and_reap();
    }
}

/// One helper session serving one Mode B environment's endpoints (ADR-0010 §3 items 3–8).
/// Dropping it ends the session: the helper sees EOF, removes its endpoints and exits.
pub struct Bridge {
    inner: Arc<Inner>,
    stop: CancellationToken,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("run_dir", &self.inner.run_dir)
            .field("alive", &self.alive())
            .finish_non_exhaustive()
    }
}

impl Bridge {
    /// Start a helper for `target` through `launcher` and say hello (U3a's rules). `start` is
    /// U3b's policy: `Forbidden` and a stopped distribution answer
    /// [`SessionError::NotRunning`] before anything starts. Streams go to `streams`.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn start(
        launcher: Arc<dyn HelperLauncher>,
        target: &DistributionTarget,
        start: DistributionStart,
        streams: Arc<dyn StreamHandler>,
    ) -> Result<Bridge, SessionError> {
        // ⟨M04-W2-R03⟩ Under `Forbidden`, the launcher lists the distribution immediately
        // before each `wsl.exe` call it makes, and starts nothing when one says it stopped.
        let transport = launcher.launch_under(target, start)?;
        let session = HelperSession::open(
            transport,
            &Expected {
                name: target.name.clone(),
                account: target.account.clone(),
                uid: None,
            },
        )?;
        let SessionParts {
            rx,
            writer,
            child,
            stderr,
            hello,
        } = session.into_parts();
        // A helper that serves Mode B names an absolute run directory; nothing else is used to
        // build the paths Windows renders and later checks.
        // ⟨The contract owner's ruling⟩ Its length is not bounded here: a run directory that
        // leaves no room for a socket path is refused by name at the first realize
        // (`wsl_bridge_run_dir_too_long`), never truncated; only an absurd one is not used.
        let run_dir = hello
            .run_dir
            .filter(|d| {
                d.starts_with('/')
                    && !d.ends_with('/')
                    && !d.contains(['\0', '\n', '\r'])
                    && d.len() <= MAX_RUN_DIR
            })
            .ok_or_else(|| SessionError::HelperUnavailable("no run directory".to_owned()))?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| SessionError::HelperUnavailable("no runtime".to_owned()))?;
        let stop = CancellationToken::new();
        let rt_handle = rt.handle().clone();
        let waiter = stop.clone();
        std::thread::Builder::new()
            .name("heimdall-wsl-bridge-pumps".to_owned())
            .spawn(move || rt.block_on(waiter.cancelled()))
            .map_err(|_| SessionError::HelperUnavailable("no runtime thread".to_owned()))?;

        let (out_tx, out_rx) = mpsc::channel::<WindowsFrame>();
        let inner = Arc::new(Inner {
            run_dir,
            out: Mutex::new(Some(out_tx)),
            calls: Mutex::new(HashMap::new()),
            streams: Mutex::new(Streams::default()),
            dead: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            handler: streams,
            rt: rt_handle,
            child: Mutex::new(child),
            stderr,
        });
        let bridge = Bridge {
            inner: Arc::clone(&inner),
            stop,
        };

        let writer_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("heimdall-wsl-bridge-writer".to_owned())
            .spawn(move || write_loop(&writer_inner, writer, &out_rx))
            .map_err(|_| SessionError::HelperUnavailable("no writer thread".to_owned()))?;
        let reader_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("heimdall-wsl-bridge-reader".to_owned())
            .spawn(move || read_loop(&reader_inner, &rx))
            .map_err(|_| SessionError::HelperUnavailable("no reader thread".to_owned()))?;
        Ok(bridge)
    }

    /// The helper's run directory (`<run>`, an absolute Linux path from its hello).
    #[must_use]
    pub fn run_dir(&self) -> &str {
        &self.inner.run_dir
    }

    /// Up to 64 KiB of the helper's stderr so far (diagnostics: never logged as content).
    #[must_use]
    pub fn stderr_tail(&self) -> Vec<u8> {
        locked(&self.inner.stderr).clone()
    }

    /// The helper's process ID.
    #[must_use]
    pub fn helper_pid(&self) -> u32 {
        locked(&self.inner.child).id()
    }

    /// Whether the helper process and its channel are alive.
    #[must_use]
    pub fn alive(&self) -> bool {
        !self.inner.dead.load(Ordering::SeqCst) && !locked(&self.inner.child).exited()
    }

    /// Realize `binding_tag` at `generation`. Idempotent for the same tag and generation; a
    /// newer generation replaces the files at the same path; an older one is refused.
    ///
    /// # Errors
    /// [`SessionError`]: `Remote` carries the helper's refusal (`IntentInvalid` for material it
    /// would not write, `Busy`, `Unavailable` with a reason code); a different answer than the
    /// paths [`realized_paths`] names is `Protocol`.
    pub fn realize(
        &self,
        binding_tag: &str,
        generation: u64,
        public: BridgePublic,
        deadline: heimdall_contract::Timestamp,
    ) -> Result<Realized, SessionError> {
        let public = proto::ModeBPublic {
            files: public.files,
            ssh_config: public.ssh_config,
            known_hosts: public.known_hosts,
        };
        let deadline = deadline.to_string();
        proto::check_realize(&self.inner.run_dir, binding_tag, &public, &deadline).map_err(
            |e| match e {
                // ⟨The contract owner's ruling⟩ The helper's own name for it.
                proto::PublicRefused::SocketPath => SessionError::Remote {
                    kind: ErrorKind::Unavailable,
                    message: "wsl_bridge_run_dir_too_long".to_owned(),
                },
                _ => SessionError::Remote {
                    kind: ErrorKind::IntentInvalid,
                    message: "wsl_bridge_public_refused".to_owned(),
                },
            },
        )?;
        let tag = binding_tag.to_owned();
        let reply = self.call(Pending::Realize, |id| WindowsFrame::Realize {
            id,
            binding_tag: tag,
            generation,
            public,
            deadline,
        })?;
        match reply {
            HelperFrame::RealizeOk {
                socket, ssh_config, ..
            } => {
                let want = realized_paths(&self.inner.run_dir, binding_tag);
                if socket == want.socket && ssh_config == want.ssh_config {
                    Ok(want)
                } else {
                    self.inner.fail();
                    Err(SessionError::Protocol)
                }
            }
            _ => Err(SessionError::Protocol),
        }
    }

    /// Withdraw `binding_tag` at exactly `generation`: a newer generation is never removed
    /// (R-RT-04). Withdrawing what is gone is `Ok`.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn withdraw(&self, binding_tag: &str, generation: u64) -> Result<(), SessionError> {
        if !proto::valid_tag(binding_tag) {
            return Err(SessionError::Remote {
                kind: ErrorKind::IntentInvalid,
                message: "wsl_bridge_public_refused".to_owned(),
            });
        }
        let tag = binding_tag.to_owned();
        match self.call(Pending::Withdraw, |id| WindowsFrame::Withdraw {
            id,
            binding_tag: tag,
            generation,
        })? {
            HelperFrame::WithdrawOk { .. } => Ok(()),
            _ => Err(SessionError::Protocol),
        }
    }

    /// The bindings the helper currently serves (tag, generation), from its own answer.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn realized(&self) -> Result<Vec<(String, u64)>, SessionError> {
        match self.call(Pending::Realized, |id| WindowsFrame::Realized { id })? {
            HelperFrame::RealizedOk { bindings, .. } => Ok(bindings),
            _ => Err(SessionError::Protocol),
        }
    }

    /// One request: send it and wait (bounded) for its answer. A silence ends the session.
    fn call(
        &self,
        kind: Pending,
        frame: impl FnOnce(u64) -> WindowsFrame,
    ) -> Result<HelperFrame, SessionError> {
        if self.inner.dead.load(Ordering::SeqCst) {
            return Err(SessionError::Gone);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let (reply, answer) = mpsc::channel();
        locked(&self.inner.calls).insert(id, Call { kind, reply });
        if let Err(e) = self.inner.send(frame(id)) {
            locked(&self.inner.calls).remove(&id);
            return Err(e);
        }
        match answer.recv_timeout(proto::BRIDGE_CALL_TIMEOUT) {
            Ok(HelperFrame::Error { kind, message, .. }) => {
                Err(SessionError::Remote { kind, message })
            }
            Ok(frame) => Ok(frame),
            Err(RecvTimeoutError::Timeout) => {
                self.inner.fail();
                Err(SessionError::Timeout)
            }
            Err(RecvTimeoutError::Disconnected) => Err(SessionError::Gone),
        }
    }
}

impl Drop for Bridge {
    /// The helper is asked to leave (`shutdown`, then EOF), given two seconds to remove its
    /// endpoints, and killed after that.
    fn drop(&mut self) {
        if !self.inner.dead.load(Ordering::SeqCst) {
            let _ = self.inner.send(WindowsFrame::Shutdown {});
        }
        // Closing the queue ends the writer once it has written `shutdown`; the helper's stdin
        // closes with it.
        *locked(&self.inner.out) = None;
        locked(&self.inner.child).finish(Duration::from_secs(2));
        self.inner.dead.store(true, Ordering::SeqCst);
        locked(&self.inner.calls).clear();
        locked(&self.inner.streams).open.clear();
        self.stop.cancel();
    }
}

// --- the threads --------------------------------------------------------------------------------

fn write_loop(
    inner: &Inner,
    mut writer: Box<dyn Write + Send>,
    queue: &mpsc::Receiver<WindowsFrame>,
) {
    while let Ok(frame) = queue.recv() {
        if proto::write_frame(&mut writer, &frame).is_err() {
            inner.fail();
            return;
        }
    }
}

fn read_loop(inner: &Arc<Inner>, rx: &mpsc::Receiver<Inbound<HelperFrame>>) {
    loop {
        match rx.recv() {
            Ok(Inbound::Frame(frame)) => {
                if !on_frame(inner, frame) {
                    inner.fail();
                    return;
                }
            }
            Ok(Inbound::Eof | Inbound::Broken(_)) | Err(_) => {
                inner.fail();
                return;
            }
        }
    }
}

/// Handle one helper frame; `false` is a violation (the session ends).
fn on_frame(inner: &Arc<Inner>, frame: HelperFrame) -> bool {
    match frame {
        HelperFrame::RealizeOk { id, .. }
        | HelperFrame::WithdrawOk { id }
        | HelperFrame::RealizedOk { id, .. } => {
            let Some(call) = locked(&inner.calls).remove(&id) else {
                return false;
            };
            let fits = matches!(
                (&call.kind, &frame),
                (Pending::Realize, HelperFrame::RealizeOk { .. })
                    | (Pending::Withdraw, HelperFrame::WithdrawOk { .. })
                    | (Pending::Realized, HelperFrame::RealizedOk { .. })
            );
            let _ = call.reply.send(frame);
            fits
        }
        HelperFrame::Error { id, kind, message } => {
            if id == 0 {
                return false;
            }
            let Some(call) = locked(&inner.calls).remove(&id) else {
                return false;
            };
            let _ = call.reply.send(HelperFrame::Error { id, kind, message });
            true
        }
        HelperFrame::Open {
            stream,
            binding_tag,
        } => on_open(inner, stream, binding_tag),
        HelperFrame::Data { stream, bytes_b64 } => {
            let Some(bytes) = proto::decode_data(&bytes_b64) else {
                return false;
            };
            let to_handler = {
                let streams = locked(&inner.streams);
                let open = streams.open.get(&stream);
                match proto::stream_ref(streams.highest, open.is_some(), stream) {
                    StreamRef::Unknown => return false,
                    StreamRef::Late => return true,
                    StreamRef::Open => open.map(|s| s.to_handler.clone()),
                }
            };
            if let Some(tx) = to_handler
                && tx.try_send(bytes).is_err()
            {
                // The handler does not keep up: the stream ends, the session does not.
                end_stream(inner, stream);
            }
            true
        }
        HelperFrame::Close { stream } => {
            let mut streams = locked(&inner.streams);
            let open = streams.open.contains_key(&stream);
            match proto::stream_ref(streams.highest, open, stream) {
                StreamRef::Unknown => false,
                StreamRef::Late => true,
                StreamRef::Open => {
                    // Dropping the entry ends the pump; nothing is sent back.
                    streams.open.remove(&stream);
                    true
                }
            }
        }
        // Everything else belongs to a file request's session, never to this one.
        HelperFrame::Hello(_)
        | HelperFrame::PreviewOk { .. }
        | HelperFrame::ApplyOk { .. }
        | HelperFrame::ReconcileOk { .. }
        | HelperFrame::ObserveOk { .. }
        | HelperFrame::ObserveHeldOk { .. }
        | HelperFrame::CleanOk { .. }
        | HelperFrame::SinkAppend { .. }
        | HelperFrame::SinkCommit { .. } => false,
    }
}

/// A stream ends from this side: it is dropped and the helper told, once.
fn end_stream(inner: &Inner, stream: u64) {
    if locked(&inner.streams).open.remove(&stream).is_some() {
        let _ = inner.send(WindowsFrame::Close { stream });
    }
}

fn on_open(inner: &Arc<Inner>, stream: u64, tag: String) -> bool {
    if !proto::valid_tag(&tag) {
        return false;
    }
    let (to_handler, from_helper) = tokio::sync::mpsc::channel(STREAM_QUEUE);
    {
        let mut streams = locked(&inner.streams);
        if !proto::may_open(streams.highest, stream) {
            return false;
        }
        streams.highest = stream;
        // The helper closes the 65th connection itself; a 65th stream is a violation.
        if streams.open.values().filter(|s| s.tag == tag).count() >= MAX_STREAMS_PER_BINDING {
            return false;
        }
    }
    let (client, server) = tokio::io::duplex(DUPLEX_CAPACITY);
    if !inner.handler.serve(&tag, server) {
        // Refused (unknown tag, no signer): the stream closes.
        let _ = inner.send(WindowsFrame::Close { stream });
        return true;
    }
    locked(&inner.streams)
        .open
        .insert(stream, Stream { tag, to_handler });
    inner
        .rt
        .spawn(pump(Arc::clone(inner), stream, client, from_helper));
    true
}

/// Move bytes between a handler's end of the duplex and the stream's `data` frames until the
/// stream ends.
async fn pump(
    inner: Arc<Inner>,
    stream: u64,
    client: DuplexStream,
    mut from_helper: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let (mut rd, mut wr) = tokio::io::split(client);
    let mut buf = vec![0u8; PUMP_CHUNK];
    loop {
        let step = tokio::time::timeout(STREAM_IDLE, async {
            tokio::select! {
                read = rd.read(&mut buf) => match read {
                    Ok(n) if n > 0 => Some(Step::Up(n)),
                    _ => None,
                },
                chunk = from_helper.recv() => chunk.map(Step::Down),
            }
        })
        .await;
        match step {
            Ok(Some(Step::Up(n))) => {
                let frame = WindowsFrame::Data {
                    stream,
                    bytes_b64: proto::encode_data(&buf[..n]),
                };
                if inner.send(frame).is_err() {
                    return;
                }
            }
            Ok(Some(Step::Down(chunk))) => {
                if wr.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            // The handler's end closed, or nothing moved for the idle time: the stream ends
            // from this side. `None` from the helper's queue means the helper closed it (the
            // entry is gone already, so nothing is sent).
            Ok(None) | Err(_) => break,
        }
    }
    end_stream(&inner, stream);
}

enum Step {
    Up(usize),
    Down(Vec<u8>),
}
