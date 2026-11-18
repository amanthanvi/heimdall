//! The helper's Mode B side: the Linux endpoints and the stream relay (ADR-0010 §3 items 4–5,
//! 8, 11–12; design U4 §4).
//!
//! * **`realize`** creates `<run>/b/<tag>/` (0700, through `ManagedDir`), writes `.generation`,
//!   the public files, `ssh_config` and `known_hosts` atomically, then binds `agent.sock`
//!   (0600) and listens. A stale socket there is removed only when it is the helper's own uid's
//!   and refuses connections (the P-B05 rule, `ipc::unix::classify_existing`); anything else
//!   is left alone. A newer generation rewrites the files, then swaps the listener.
//! * **Accept:** the peer's uid must equal the helper's (`SO_PEERCRED`, `getpeereid` off Linux),
//!   else the connection is closed before a byte is read. Each agent message is read with its
//!   4-byte length (at most 256 KiB), then `ipc::signing::classify` runs (defense in depth): a
//!   refused message is answered `SSH_AGENT_FAILURE` here and never forwarded. The first
//!   allowed message opens the stream (`open`, then `data`); the reply frame comes back as
//!   `data` and is written to the client. One request is in flight per connection.
//! * **`withdraw`** closes exactly that generation's listener and connections, unlinks the
//!   socket and removes the directory. EOF, `shutdown` or a protocol error withdraws everything.
//! * **Startup cleanup** (the first `realize`): every `<run>/b/<tag>/` with no live socket is
//!   removed; a live foreign socket is left alone and reported on stderr.
//! * **Never** a listener anywhere else, TCP, the abstract namespace or `/mnt/wsl`.
//!
//! The endpoints run on a current-thread tokio runtime on a thread of their own, started at
//! the first `realize`; the helper's main loop stays synchronous and hands them the frames
//! Windows sends. A helper that never realizes starts nothing and creates nothing.

use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use heimdall_ipc::signing::{classify, failure_frame};
use heimdall_ipc::unix::{Existing, PathFacts, classify_existing};
use heimdall_localenv::sys::ManagedDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::helper::lock::{self, InstanceLock};
use crate::helper::{Broken, FrameWriter, HelperEnv, identity};
use crate::proto::{
    self, ErrorKind, HelperFrame, MAX_AGENT_MESSAGE, MAX_BINDINGS, MAX_STREAMS_PER_BINDING,
    ModeBPublic, STREAM_IDLE, StreamRef, WindowsFrame,
};

/// The bridge's lock file inside `<run>`: one Mode B helper per distribution account.
const BRIDGE_LOCK: &str = "bridge.lock";
/// The generation marker inside a binding directory.
const GENERATION_FILE: &str = ".generation";
/// The socket's name inside a binding directory.
const SOCKET_FILE: &str = "agent.sock";
/// What a stream's receiving queue holds before Windows' replies are refused.
const STREAM_QUEUE: usize = 16;

type Failure = (ErrorKind, String);

fn fail(kind: ErrorKind, message: &str) -> Failure {
    (kind, message.to_owned())
}

/// What Windows sends a connection.
enum ToClient {
    Data(Vec<u8>),
}

/// An open stream as the main loop sees it.
struct Slot {
    to_client: mpsc::Sender<ToClient>,
}

/// State the connection tasks and the main loop share.
struct Shared {
    writer: FrameWriter,
    /// The helper's real effective uid (never the injected identity of a test).
    uid: u32,
    next_stream: AtomicU64,
    highest: AtomicU64,
    table: Mutex<HashMap<u64, Slot>>,
}

impl Shared {
    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Slot>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One served binding.
struct Served {
    generation: u64,
    dir: PathBuf,
    cancel: CancellationToken,
}

/// What exists once the first `realize` set it up.
struct Live {
    handle: tokio::runtime::Handle,
    stop: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
    /// `<run>/b`.
    b: ManagedDir,
    run_path: PathBuf,
    _lock: InstanceLock,
}

/// The Mode B state of one helper.
pub(crate) struct Endpoints {
    env: HelperEnv,
    shared: Arc<Shared>,
    live: Option<Live>,
    bindings: HashMap<String, Served>,
}

/// `$XDG_RUNTIME_DIR`, when it is set to an absolute path.
fn xdg_runtime(env: &HelperEnv) -> Option<PathBuf> {
    env.env
        .get("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// `<run>`'s path for this helper (nothing is created): `$XDG_RUNTIME_DIR/heimdall`, else
/// `<state base>/heimdall/run` (`~/.local/state/heimdall/run`).
pub(crate) fn run_dir_path(env: &HelperEnv) -> PathBuf {
    match xdg_runtime(env) {
        Some(xdg) => xdg.join("heimdall"),
        None => env.state_base.join("heimdall").join("run"),
    }
}

fn say(message: &str) {
    let _ = writeln!(std::io::stderr(), "wsl-helper: {message}");
}

impl Endpoints {
    pub(crate) fn new(env: &HelperEnv, writer: FrameWriter) -> Self {
        Endpoints {
            env: env.clone(),
            shared: Arc::new(Shared {
                writer,
                uid: identity::effective_uid(),
                next_stream: AtomicU64::new(1),
                highest: AtomicU64::new(0),
                table: Mutex::new(HashMap::new()),
            }),
            live: None,
            bindings: HashMap::new(),
        }
    }

    /// Serve one Mode B frame. A request is answered on the channel; a failure of the request
    /// is an `error` frame; only a broken channel or a protocol violation is returned.
    pub(crate) fn handle(&mut self, frame: WindowsFrame) -> Result<(), Broken> {
        let send = |w: &FrameWriter, f: &HelperFrame| w.send(f).map_err(|_| Broken::Gone);
        match frame {
            WindowsFrame::Realize {
                id,
                binding_tag,
                generation,
                public,
                deadline,
            } => {
                let reply = match self.realize(&binding_tag, generation, &public, &deadline) {
                    Ok((socket, ssh_config)) => HelperFrame::RealizeOk {
                        id,
                        socket,
                        ssh_config,
                    },
                    Err(f) => error_frame(id, f),
                };
                send(&self.shared.writer, &reply)
            }
            WindowsFrame::Withdraw {
                id,
                binding_tag,
                generation,
            } => {
                let reply = match self.withdraw(&binding_tag, generation) {
                    Ok(()) => HelperFrame::WithdrawOk { id },
                    Err(f) => error_frame(id, f),
                };
                send(&self.shared.writer, &reply)
            }
            WindowsFrame::Realized { id } => {
                let mut bindings: Vec<(String, u64)> = self
                    .bindings
                    .iter()
                    .map(|(t, s)| (t.clone(), s.generation))
                    .collect();
                bindings.sort();
                send(
                    &self.shared.writer,
                    &HelperFrame::RealizedOk { id, bindings },
                )
            }
            WindowsFrame::Data { stream, bytes_b64 } => {
                let bytes = proto::decode_data(&bytes_b64).ok_or(Broken::Protocol)?;
                match self.stream_ref(stream) {
                    StreamRef::Unknown => Err(Broken::Protocol),
                    StreamRef::Late => Ok(()),
                    StreamRef::Open => {
                        let sent = self
                            .shared
                            .table()
                            .get(&stream)
                            .map(|s| s.to_client.try_send(ToClient::Data(bytes)).is_ok());
                        if sent == Some(false) {
                            // The client does not keep up (or has gone): the stream ends.
                            if self.shared.table().remove(&stream).is_some() {
                                send(&self.shared.writer, &HelperFrame::Close { stream })?;
                            }
                        }
                        Ok(())
                    }
                }
            }
            WindowsFrame::Close { stream } => match self.stream_ref(stream) {
                StreamRef::Unknown => Err(Broken::Protocol),
                StreamRef::Late => Ok(()),
                StreamRef::Open => {
                    // Dropping the slot ends the connection's task; it sends nothing back.
                    self.shared.table().remove(&stream);
                    Ok(())
                }
            },
            _ => Err(Broken::Protocol),
        }
    }

    fn stream_ref(&self, stream: u64) -> StreamRef {
        let open = self.shared.table().contains_key(&stream);
        proto::stream_ref(self.shared.highest.load(Ordering::SeqCst), open, stream)
    }

    /// Withdraw everything and stop the runtime (the helper's exit path).
    pub(crate) fn shutdown(&mut self) {
        let tags: Vec<String> = self.bindings.keys().cloned().collect();
        for tag in tags {
            if let Some(served) = self.bindings.remove(&tag)
                && let Err((_, why)) = self.remove_binding(&tag, &served)
            {
                say(&format!("could not remove {tag} completely: {why}"));
            }
        }
        if let Some(mut live) = self.live.take() {
            live.stop.cancel();
            if let Some(t) = live.thread.take() {
                let _ = t.join();
            }
        }
        self.shared.table().clear();
    }

    // --- establish ---------------------------------------------------------------------

    /// The run directory, the bridge lock, the runtime and the startup cleanup, once.
    fn establish(&mut self) -> Result<(), Failure> {
        if self.live.is_some() {
            return Ok(());
        }
        let unsafe_dir = || fail(ErrorKind::Unavailable, "wsl_bridge_run_dir_unsafe");
        let run_path = run_dir_path(&self.env);
        // `<run>` is `<xdg>/heimdall` (created owner-only like the helper's state directory), or
        // `<state>/heimdall/run`.
        let run = if let Some(base) = xdg_runtime(&self.env) {
            let dir = crate::helper::heimdall_dir(&base)?;
            ManagedDir::open_root(&dir)
                .map_err(|_| unsafe_dir())?
                .ok_or_else(unsafe_dir)?
        } else {
            let state = crate::helper::heimdall_dir(&self.env.state_base)?;
            ManagedDir::open_root(&state)
                .map_err(|_| unsafe_dir())?
                .ok_or_else(unsafe_dir)?
                .child("run", true)
                .map_err(|_| unsafe_dir())?
                .ok_or_else(unsafe_dir)?
        };
        let held =
            lock::acquire(&run_path.join(BRIDGE_LOCK), self.env.lock_wait).map_err(
                |e| match e {
                    lock::LockError::Busy => {
                        fail(ErrorKind::Busy, "another bridge helper is running")
                    }
                    _ => fail(ErrorKind::Unavailable, "wsl_bridge_lock_unavailable"),
                },
            )?;
        let b = run
            .child("b", true)
            .map_err(|_| unsafe_dir())?
            .ok_or_else(unsafe_dir)?;
        clean_stale(&b, &run_path.join("b"), self.shared.uid);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| fail(ErrorKind::Unavailable, "wsl_bridge_runtime_unavailable"))?;
        let handle = rt.handle().clone();
        let stop = CancellationToken::new();
        let waiter = stop.clone();
        let thread = std::thread::Builder::new()
            .name("heimdall-wsl-endpoints".to_owned())
            .spawn(move || rt.block_on(waiter.cancelled()))
            .map_err(|_| fail(ErrorKind::Unavailable, "wsl_bridge_runtime_unavailable"))?;
        self.live = Some(Live {
            handle,
            stop,
            thread: Some(thread),
            b,
            run_path,
            _lock: held,
        });
        Ok(())
    }

    // --- realize -----------------------------------------------------------------------

    fn realize(
        &mut self,
        tag: &str,
        generation: u64,
        public: &ModeBPublic,
        deadline: &str,
    ) -> Result<(String, String), Failure> {
        let run_dir = run_dir_path(&self.env).to_string_lossy().into_owned();
        proto::check_realize(&run_dir, tag, public, deadline)
            .map_err(|_| fail(ErrorKind::IntentInvalid, "wsl_bridge_public_refused"))?;
        if self.bindings.len() >= MAX_BINDINGS && !self.bindings.contains_key(tag) {
            return Err(fail(ErrorKind::Unavailable, "wsl_bridge_too_many_bindings"));
        }
        if let Some(served) = self.bindings.get(tag)
            && served.generation > generation
        {
            return Err(fail(ErrorKind::Unavailable, "wsl_binding_generation_stale"));
        }
        self.establish()?;
        let unsafe_dir = || fail(ErrorKind::Unavailable, "wsl_bridge_run_dir_unsafe");
        // Before anything is written: a path this helper does not serve and that holds a live
        // socket, another user's or a non-socket is somebody else's, and is left untouched.
        let sock = {
            let live = self.live.as_ref().ok_or_else(unsafe_dir)?;
            live.run_path.join("b").join(tag).join(SOCKET_FILE)
        };
        if !self.bindings.contains_key(tag)
            && !matches!(
                occupant(&sock, self.shared.uid),
                Existing::Absent | Existing::DeadOurs
            )
        {
            say("an endpoint path is occupied; left in place");
            return Err(fail(ErrorKind::Unavailable, "wsl_endpoint_in_use"));
        }
        let (dir, dir_path, handle) = {
            let live = self.live.as_ref().ok_or_else(unsafe_dir)?;
            let dir = live
                .b
                .child(tag, true)
                .map_err(|_| unsafe_dir())?
                .ok_or_else(unsafe_dir)?;
            (dir, live.run_path.join("b").join(tag), live.handle.clone())
        };

        // The files first, then the listener (design §4): a client that finds the socket finds
        // the configuration beside it.
        let wrote = |r: Result<(), heimdall_localenv::sys::ManagedDirError>| {
            r.map_err(|_| fail(ErrorKind::Unavailable, "wsl_bridge_write_failed"))
        };
        wrote(dir.write_replace(GENERATION_FILE, generation.to_string().as_bytes()))?;
        let mut keep: Vec<&str> = vec![GENERATION_FILE, SOCKET_FILE, ".hm-quarantine"];
        for (name, line) in &public.files {
            wrote(dir.write_replace(name, format!("{line}\n").as_bytes()))?;
            keep.push(name);
        }
        wrote(dir.write_replace("ssh_config", public.ssh_config.as_bytes()))?;
        wrote(dir.write_replace("known_hosts", public.known_hosts.as_bytes()))?;
        keep.extend(["ssh_config", "known_hosts"]);
        // A newer generation replaces the files at the same path: what it no longer carries
        // goes.
        for name in dir.names().map_err(|_| unsafe_dir())? {
            if !keep.contains(&name.as_str()) {
                wrote(dir.remove(&name).map(drop))?;
            }
        }

        let same_generation = self
            .bindings
            .get(tag)
            .is_some_and(|s| s.generation == generation && !s.cancel.is_cancelled());
        let socket_present = same_generation
            && std::fs::symlink_metadata(&sock)
                .is_ok_and(|m| PathFacts::of(&m).uid == self.shared.uid);
        if !(same_generation && socket_present) {
            // Swap: the old generation's listener and connections end, its socket goes, then
            // the new listener binds.
            if let Some(old) = self.bindings.remove(tag) {
                old.cancel.cancel();
                unlink_own_socket(&sock, self.shared.uid);
            }
            let cancel = CancellationToken::new();
            let listener = bind(&sock, self.shared.uid)?;
            let listener = {
                let _enter = handle.enter();
                UnixListener::from_std(listener)
                    .map_err(|_| fail(ErrorKind::Unavailable, "wsl_bridge_listen_failed"))?
            };
            let ctx = Arc::new(Ctx {
                tag: tag.to_owned(),
                cancel: cancel.clone(),
                connections: AtomicUsize::new(0),
            });
            handle.spawn(accept_loop(Arc::clone(&self.shared), ctx, listener));
            self.bindings.insert(
                tag.to_owned(),
                Served {
                    generation,
                    dir: dir_path.clone(),
                    cancel,
                },
            );
        }
        Ok((
            sock.to_string_lossy().into_owned(),
            dir_path.join("ssh_config").to_string_lossy().into_owned(),
        ))
    }

    // --- withdraw ----------------------------------------------------------------------

    fn withdraw(&mut self, tag: &str, generation: u64) -> Result<(), Failure> {
        // Exactly that generation: a newer one is never removed (R-RT-04); what is not served
        // is already gone.
        if self
            .bindings
            .get(tag)
            .is_none_or(|s| s.generation != generation)
        {
            return Ok(());
        }
        let Some(served) = self.bindings.remove(tag) else {
            return Ok(());
        };
        self.remove_binding(tag, &served)
    }

    fn remove_binding(&self, tag: &str, served: &Served) -> Result<(), Failure> {
        served.cancel.cancel();
        unlink_own_socket(&served.dir.join(SOCKET_FILE), self.shared.uid);
        let incomplete = || fail(ErrorKind::Unavailable, "wsl_withdraw_incomplete");
        let Some(live) = self.live.as_ref() else {
            return Ok(());
        };
        let dir = live.b.child(tag, false).map_err(|_| incomplete())?;
        if let Some(dir) = dir {
            remove_files(&dir).map_err(|()| incomplete())?;
            let _ = std::fs::remove_dir(served.dir.join(".hm-quarantine"));
            std::fs::remove_dir(&served.dir).map_err(|_| incomplete())?;
        }
        Ok(())
    }
}

fn error_frame(id: u64, (kind, message): Failure) -> HelperFrame {
    HelperFrame::Error {
        id,
        kind,
        message: proto::bounded_message(&message),
    }
}

/// Remove every regular file of a binding directory (and its quarantine, if one is left).
fn remove_files(dir: &ManagedDir) -> Result<(), ()> {
    for name in dir.names().map_err(|_| ())? {
        if name == ".hm-quarantine" || name == SOCKET_FILE {
            continue;
        }
        dir.remove(&name).map_err(|_| ())?;
    }
    Ok(())
}

/// Unlink `path` when it is a socket this uid owns; anything else stays.
fn unlink_own_socket(path: &Path, uid: u32) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let facts = PathFacts::of(&meta);
        if facts.kind == heimdall_ipc::unix::FileKind::Socket && facts.uid == uid {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// What occupies `sock`, by the P-B05 rule: nothing, a dead socket of this uid, or something
/// this helper must leave alone.
fn occupant(sock: &Path, uid: u32) -> Existing {
    let facts = std::fs::symlink_metadata(sock)
        .ok()
        .map(|m| PathFacts::of(&m));
    classify_existing(facts, uid, || {
        std::os::unix::net::UnixStream::connect(sock).map(drop)
    })
}

/// Bind `sock` (0600). A dead socket of this uid is removed first; a live one, another user's
/// or a file that is not a socket is left in place and refuses the realization.
fn bind(sock: &Path, uid: u32) -> Result<std::os::unix::net::UnixListener, Failure> {
    match occupant(sock, uid) {
        Existing::Absent => {}
        Existing::DeadOurs => {
            let _ = std::fs::remove_file(sock);
        }
        Existing::LiveOurs | Existing::ForeignOwner | Existing::NotASocket => {
            say("an endpoint path is occupied; left in place");
            return Err(fail(ErrorKind::Unavailable, "wsl_endpoint_in_use"));
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(sock)
        .map_err(|_| fail(ErrorKind::Unavailable, "wsl_bridge_listen_failed"))?;
    let finish = || -> std::io::Result<()> {
        std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
        let meta = std::fs::symlink_metadata(sock)?;
        if meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        listener.set_nonblocking(true)
    };
    if finish().is_err() {
        drop(listener);
        let _ = std::fs::remove_file(sock);
        return Err(fail(ErrorKind::Unavailable, "wsl_bridge_listen_failed"));
    }
    Ok(listener)
}

/// Startup cleanup: every binding directory under `<run>/b` with no live socket goes; a live
/// foreign socket (or an odd entry) stays and is reported.
fn clean_stale(b: &ManagedDir, b_path: &Path, uid: u32) {
    let Ok(names) = b.names() else {
        return;
    };
    for tag in names {
        if !proto::valid_tag(&tag) || !b.is_directory(&tag).unwrap_or(false) {
            say("an unexpected entry under the endpoint directory; left in place");
            continue;
        }
        let dir_path = b_path.join(&tag);
        let sock = dir_path.join(SOCKET_FILE);
        match occupant(&sock, uid) {
            Existing::Absent | Existing::DeadOurs => {
                unlink_own_socket(&sock, uid);
                let removed = b
                    .child(&tag, false)
                    .ok()
                    .flatten()
                    .is_some_and(|d| remove_files(&d).is_ok());
                let _ = std::fs::remove_dir(dir_path.join(".hm-quarantine"));
                if !(removed && std::fs::remove_dir(&dir_path).is_ok()) {
                    say(&format!("could not remove the stale directory of {tag}"));
                }
            }
            Existing::LiveOurs | Existing::ForeignOwner | Existing::NotASocket => {
                say(&format!(
                    "a live endpoint of {tag} is not ours; left in place"
                ));
            }
        }
    }
}

// --- accept and relay -------------------------------------------------------------------------

/// One binding generation's listener context.
struct Ctx {
    tag: String,
    cancel: CancellationToken,
    connections: AtomicUsize,
}

/// Counts a connection for its binding until the connection ends.
struct Admitted(Arc<Ctx>);

impl Drop for Admitted {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn accept_loop(shared: Arc<Shared>, ctx: Arc<Ctx>, listener: UnixListener) {
    loop {
        let accepted = tokio::select! {
            () = ctx.cancel.cancelled() => return,
            r = listener.accept() => r,
        };
        let Ok((stream, _)) = accepted else {
            // A transient accept failure must not spin.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            continue;
        };
        // The 65th connection is closed at once.
        if ctx.connections.fetch_add(1, Ordering::SeqCst) >= MAX_STREAMS_PER_BINDING {
            ctx.connections.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let admitted = Admitted(Arc::clone(&ctx));
        tokio::spawn(connection(Arc::clone(&shared), admitted, stream));
    }
}

async fn connection(shared: Arc<Shared>, admitted: Admitted, stream: UnixStream) {
    let ctx = Arc::clone(&admitted.0);
    if ctx.cancel.is_cancelled() {
        return;
    }
    // Admission: the peer is this helper's uid, else nothing is read.
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == shared.uid => {}
        _ => return,
    }
    let (mut rd, mut wr) = stream.into_split();
    let mut open: Option<(u64, mpsc::Receiver<ToClient>)> = None;
    let _ = tokio::select! {
        () = ctx.cancel.cancelled() => Err(()),
        r = relay(&shared, &ctx.tag, &mut rd, &mut wr, &mut open) => r,
    };
    if let Some((id, _)) = open {
        // Ended here (not by Windows' `close`, which removed the slot first): say so.
        if shared.table().remove(&id).is_some() {
            let _ = shared.writer.send(&HelperFrame::Close { stream: id });
        }
    }
    drop(admitted);
}

/// The agent frame at the head of `rd`: `Ok(None)` for a clean end between frames.
async fn read_message(rd: &mut tokio::net::unix::OwnedReadHalf) -> Result<Option<Vec<u8>>, ()> {
    let mut header = [0u8; 4];
    if rd.read(&mut header[..1]).await.map_err(|_| ())? == 0 {
        return Ok(None);
    }
    rd.read_exact(&mut header[1..]).await.map_err(|_| ())?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_AGENT_MESSAGE {
        return Err(());
    }
    let mut frame = header.to_vec();
    frame.resize(4 + len, 0);
    rd.read_exact(&mut frame[4..]).await.map_err(|_| ())?;
    Ok(Some(frame))
}

/// Serve one client connection until it ends: `Err` for a violation or a failure (the
/// connection closes), `Ok` for a clean end.
async fn relay(
    shared: &Shared,
    tag: &str,
    rd: &mut tokio::net::unix::OwnedReadHalf,
    wr: &mut tokio::net::unix::OwnedWriteHalf,
    open: &mut Option<(u64, mpsc::Receiver<ToClient>)>,
) -> Result<(), ()> {
    loop {
        let frame = match timeout(STREAM_IDLE, read_message(rd)).await {
            Ok(Ok(Some(f))) => f,
            Ok(Ok(None)) | Err(_) => return Ok(()),
            Ok(Err(())) => return Err(()),
        };
        if classify(&frame[4..]).is_err() {
            // Refused here: answered locally, never forwarded; the connection stays usable.
            timeout(STREAM_IDLE, wr.write_all(&failure_frame()))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            continue;
        }
        if open.is_none() {
            let id = shared.next_stream.fetch_add(2, Ordering::SeqCst);
            shared.highest.fetch_max(id, Ordering::SeqCst);
            let (tx, rx) = mpsc::channel(STREAM_QUEUE);
            shared.table().insert(id, Slot { to_client: tx });
            *open = Some((id, rx));
            shared
                .writer
                .send(&HelperFrame::Open {
                    stream: id,
                    binding_tag: tag.to_owned(),
                })
                .map_err(|_| ())?;
        }
        let Some((id, rx)) = open.as_mut() else {
            return Err(());
        };
        // Nothing may be waiting from Windows before a request has gone out.
        if rx.try_recv().is_ok() {
            return Err(());
        }
        shared
            .writer
            .send(&HelperFrame::Data {
                stream: *id,
                bytes_b64: proto::encode_data(&frame),
            })
            .map_err(|_| ())?;
        let reply = reply_frame(rx).await?;
        timeout(STREAM_IDLE, wr.write_all(&reply))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
    }
}

/// Collect one whole agent frame from Windows' `data`: more bytes than one frame, a bad length
/// or a silence of [`STREAM_IDLE`] is a failure; Windows closing the stream is too (the client
/// gets EOF).
async fn reply_frame(rx: &mut mpsc::Receiver<ToClient>) -> Result<Vec<u8>, ()> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if let Some(head) = buf.first_chunk::<4>() {
            let len = u32::from_be_bytes(*head) as usize;
            if len == 0 || len > MAX_AGENT_MESSAGE {
                return Err(());
            }
            match buf.len().cmp(&(4 + len)) {
                std::cmp::Ordering::Equal => return Ok(buf),
                std::cmp::Ordering::Greater => return Err(()),
                std::cmp::Ordering::Less => {}
            }
        }
        match timeout(STREAM_IDLE, rx.recv()).await {
            Ok(Some(ToClient::Data(bytes))) => buf.extend_from_slice(&bytes),
            Ok(None) | Err(_) => return Err(()),
        }
    }
}
