//! Agent fixtures (m02-plan §0, U7; ADR-0007 §7, §9, F21, F23).
//!
//! * [`FakeAgent`]: an in-process SSH agent on a Unix socket (owner-only: `0600` in a
//!   `0700` scratch directory) or a Windows named pipe (the reviewed `heimdall-ipc`
//!   listener: protected owner-only DACL, client SID check). Its keys are Ed25519,
//!   generated in memory per run ([`FixtureKey`]), and their comments are fresh
//!   `HEIMDALL_CANARY_*` strings, so a leaked comment fails `assert_no_canary`. It
//!   logs every message it receives ([`AgentContact`]) and signs real Ed25519
//!   signatures, so a real `ssh` can log in through it.
//! * [`CountingProxy`]: a counting socket in front of a real agent; it forwards each
//!   request frame and its reply, and logs the request's message type.
//! * [`DisposableSshAgent`]: `ssh-agent -D -a <scratch>/agent.sock` with
//!   `HOME=<scratch home>` (ADR-0007 F21), optionally with the counting askpass
//!   (`SSH_ASKPASS` = `hm-fixture-hook askpass`, `SSH_ASKPASS_REQUIRE=force`), stopped
//!   by exact PID. [`DisposableSshAgent::sign_control`] is the authorized disposable
//!   signing control of ADR-0007 F23 (M2-R08). Unix only (m02-plan §4).
//!
//! None of these touches the owner's `~/.ssh`, agents or keys: every path is in a
//! scratch directory this process created, and every child runs with a cleared
//! environment.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

use crate::CANARY_PREFIX;
use crate::home::{Scratch, find_program, sh_quote, write_owner_only};
use crate::hook::HookBinary;

/// SSH agent message numbers used here (draft-miller-ssh-agent).
pub mod msg {
    /// `SSH_AGENT_FAILURE`.
    pub const FAILURE: u8 = 5;
    /// `SSH_AGENT_SUCCESS`.
    pub const SUCCESS: u8 = 6;
    /// `SSH_AGENTC_REQUEST_IDENTITIES`.
    pub const REQUEST_IDENTITIES: u8 = 11;
    /// `SSH_AGENT_IDENTITIES_ANSWER`.
    pub const IDENTITIES_ANSWER: u8 = 12;
    /// `SSH_AGENTC_SIGN_REQUEST`.
    pub const SIGN_REQUEST: u8 = 13;
    /// `SSH_AGENT_SIGN_RESPONSE`.
    pub const SIGN_RESPONSE: u8 = 14;
    /// `SSH_AGENTC_ADD_IDENTITY`.
    pub const ADD_IDENTITY: u8 = 17;
    /// `SSH_AGENTC_REMOVE_IDENTITY`.
    pub const REMOVE_IDENTITY: u8 = 18;
    /// `SSH_AGENTC_LOCK`.
    pub const LOCK: u8 = 22;
    /// `SSH_AGENTC_EXTENSION`.
    pub const EXTENSION: u8 = 27;
}

/// The largest frame any fixture reads or forwards (the agent client's bound,
/// m02-plan U6).
pub const MAX_FRAME: usize = 256 * 1024;

/// Prefix of every fixture pipe name (m02-plan §4: `heimdall-hmtest-<random>`).
pub const FIXTURE_PIPE_PREFIX: &str = "heimdall-hmtest-";

/// `n` random bytes as lowercase hex (OS randomness).
///
/// # Panics
/// When the OS refuses randomness (a broken host).
#[must_use]
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    if let Err(e) = getrandom::fill(&mut bytes) {
        panic!("OS randomness unavailable: {e}");
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh fake-agent canary comment (`HEIMDALL_CANARY_AGENT_<hex>`).
#[must_use]
pub fn canary_comment() -> String {
    format!("{CANARY_PREFIX}AGENT_{}", random_hex(8))
}

/// Whether `name` is a fixture pipe (`\\.\pipe\heimdall-hmtest-…`, ASCII
/// case-insensitive).
#[must_use]
pub fn is_fixture_pipe_name(name: &str) -> bool {
    let prefix = format!(r"\\.\pipe\{FIXTURE_PIPE_PREFIX}");
    name.len() > prefix.len()
        && name.is_char_boundary(prefix.len())
        && name[..prefix.len()].eq_ignore_ascii_case(&prefix)
}

/// Where a fixture agent listens, or where an upstream agent is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// A Unix socket path.
    UnixSocket(PathBuf),
    /// A Windows named pipe (`\\.\pipe\<name>`).
    NamedPipe(String),
}

/// The name m02-plan U7 uses for `CountingProxy`'s upstream. It is this crate's
/// [`Endpoint`], structurally identical to `heimdall_localenv::agents::EndpointLocator`;
/// the testkit does not depend on `heimdall-localenv` (whose tests depend on the
/// testkit).
pub type EndpointLocator = Endpoint;

impl Endpoint {
    /// A fresh endpoint for a fixture: on Unix `<scratch>/s<n>/<name>.sock` (in its own
    /// `0700` directory); on Windows `\\.\pipe\heimdall-hmtest-<random>-<name>`.
    ///
    /// # Errors
    /// The scratch subdirectory cannot be created.
    pub fn in_scratch(scratch: &Scratch, name: &str) -> io::Result<Endpoint> {
        #[cfg(unix)]
        {
            Ok(Endpoint::UnixSocket(
                scratch.subdir("s")?.join(format!("{name}.sock")),
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = scratch;
            Ok(Endpoint::NamedPipe(format!(
                r"\\.\pipe\{FIXTURE_PIPE_PREFIX}{}-{name}",
                random_hex(8)
            )))
        }
    }

    /// The locator string for `SSH_AUTH_SOCK` or `IdentityAgent`.
    #[must_use]
    pub fn locator(&self) -> OsString {
        match self {
            Endpoint::UnixSocket(p) => p.clone().into_os_string(),
            Endpoint::NamedPipe(n) => OsString::from(n),
        }
    }
}

/// An Ed25519 key generated in memory for one run. Its comment is a fresh canary.
/// `Debug` prints the fingerprint only.
#[derive(Clone)]
pub struct FixtureKey {
    private: PrivateKey,
}

impl fmt::Debug for FixtureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixtureKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl FixtureKey {
    /// Generate a new key from OS randomness.
    ///
    /// # Panics
    /// When the OS refuses randomness or the key cannot be built (a broken host).
    #[must_use]
    pub fn generate() -> FixtureKey {
        let mut seed = [0u8; 32];
        if let Err(e) = getrandom::fill(&mut seed) {
            panic!("OS randomness unavailable: {e}");
        }
        let keypair = Ed25519Keypair::from_seed(&seed);
        seed.fill(0);
        let private = PrivateKey::new(KeypairData::Ed25519(keypair), canary_comment())
            .expect("an Ed25519 keypair always builds a private key");
        FixtureKey { private }
    }

    /// `n` fresh keys.
    #[must_use]
    pub fn generate_many(n: usize) -> Vec<FixtureKey> {
        (0..n).map(|_| FixtureKey::generate()).collect()
    }

    /// The public key (with the canary comment).
    #[must_use]
    pub fn public(&self) -> &PublicKey {
        self.private.public_key()
    }

    /// The public key blob as the agent protocol carries it.
    #[must_use]
    pub fn public_blob(&self) -> Vec<u8> {
        self.public()
            .to_bytes()
            .expect("an Ed25519 public key always encodes")
    }

    /// `SHA256:<base64>`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.public().fingerprint(HashAlg::Sha256).to_string()
    }

    /// The canary comment.
    #[must_use]
    pub fn comment(&self) -> &str {
        self.private.comment()
    }

    /// `ssh-ed25519 <base64> <canary comment>`.
    #[must_use]
    pub fn public_line(&self) -> String {
        self.public()
            .to_openssh()
            .expect("an Ed25519 public key always encodes")
    }

    /// `ssh-ed25519 <base64>`, without the comment.
    #[must_use]
    pub fn public_line_without_comment(&self) -> String {
        let mut public = self.public().clone();
        public.set_comment("");
        public
            .to_openssh()
            .expect("an Ed25519 public key always encodes")
            .trim_end()
            .to_owned()
    }

    /// Write the public key file (`.pub` form, with the canary comment).
    ///
    /// # Errors
    /// The write fails.
    pub fn write_public(&self, path: &Path) -> io::Result<()> {
        fs::write(path, format!("{}\n", self.public_line()))
    }

    /// Write the private key in OpenSSH format, owner-only, to a new file in scratch
    /// (for `ssh-add` and file-backed identity fixtures). Never to any other place.
    ///
    /// # Errors
    /// The file exists or the write fails.
    pub fn write_private(&self, path: &Path) -> io::Result<()> {
        let text = self
            .private
            .to_openssh(LineEnding::LF)
            .map_err(|e| io::Error::other(format!("key encoding failed: {e}")))?;
        write_owner_only(path, text.as_bytes())
    }

    /// An agent-protocol signature blob (`string algorithm, string signature`) over
    /// `data`.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Option<Vec<u8>> {
        sign_encoded(&self.private, data)
    }

    /// This key with `comment` in place of its canary comment: the same key material
    /// and fingerprint (M02 wave 3c, additive). For a fixture whose client prints the
    /// comment of a key an agent holds: `ssh` names it when the agent refuses a
    /// signature (a confirm-constrained key whose askpass denies), so a canary comment
    /// would trip `assert_no_canary` on the client's own output. `comment` must not be
    /// secret.
    #[must_use]
    pub fn with_comment(&self, comment: &str) -> FixtureKey {
        let mut private = self.private.clone();
        private.set_comment(comment);
        FixtureKey { private }
    }
}

fn sign_encoded<K: ssh_key::SigningKey>(key: &K, data: &[u8]) -> Option<Vec<u8>> {
    let signature = key.try_sign(data).ok()?;
    let mut out = Vec::new();
    ssh_encoding::Encode::encode(&signature, &mut out).ok()?;
    Some(out)
}

/// The SHA-256 fingerprint of a public key blob, when it parses.
#[must_use]
pub fn blob_fingerprint(blob: &[u8]) -> Option<String> {
    PublicKey::from_bytes(blob)
        .ok()
        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
}

// --- wire helpers ----------------------------------------------------------------

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_u32(
        out,
        u32::try_from(s.len()).expect("fixture strings fit u32"),
    );
    out.extend_from_slice(s);
}

/// A frame: 4-byte big-endian length, then the payload.
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    put_string(&mut out, payload);
    out
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u32(&mut self) -> Option<u32> {
        let bytes = self.0.get(..4)?;
        self.0 = &self.0[4..];
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u32()?).ok()?;
        let s = self.0.get(..n)?;
        self.0 = &self.0[n..];
        Some(s)
    }
}

/// `SSH_AGENTC_REQUEST_IDENTITIES` payload.
#[must_use]
pub fn request_identities() -> Vec<u8> {
    vec![msg::REQUEST_IDENTITIES]
}

/// `SSH_AGENTC_SIGN_REQUEST` payload.
#[must_use]
pub fn sign_request(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut out = vec![msg::SIGN_REQUEST];
    put_string(&mut out, blob);
    put_string(&mut out, data);
    put_u32(&mut out, flags);
    out
}

/// `SSH_AGENT_IDENTITIES_ANSWER` payload for `(blob, comment)` pairs.
#[must_use]
pub fn identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![msg::IDENTITIES_ANSWER];
    put_u32(
        &mut out,
        u32::try_from(keys.len()).expect("fixture key count fits u32"),
    );
    for (blob, comment) in keys {
        put_string(&mut out, blob);
        put_string(&mut out, comment.as_bytes());
    }
    out
}

/// Parse an identities answer into `(blob, comment bytes)` pairs; `None` when it is not
/// one or is malformed.
#[must_use]
pub fn parse_identities_answer(payload: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut c = Cursor(payload);
    if c.u8()? != msg::IDENTITIES_ANSWER {
        return None;
    }
    let n = c.u32()?;
    let mut out = Vec::new();
    for _ in 0..n {
        let blob = c.string()?.to_vec();
        let comment = c.string()?.to_vec();
        out.push((blob, comment));
    }
    c.0.is_empty().then_some(out)
}

/// Parse a sign response into `(algorithm, signature bytes)`.
#[must_use]
pub fn parse_sign_response(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut c = Cursor(payload);
    if c.u8()? != msg::SIGN_RESPONSE {
        return None;
    }
    let blob = c.string()?;
    let mut inner = Cursor(blob);
    let algorithm = String::from_utf8(inner.string()?.to_vec()).ok()?;
    let signature = inner.string()?.to_vec();
    Some((algorithm, signature))
}

fn parse_sign_request(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut c = Cursor(payload);
    if c.u8()? != msg::SIGN_REQUEST {
        return None;
    }
    let blob = c.string()?;
    let data = c.string()?;
    let _flags = c.u32()?;
    Some((blob, data))
}

// --- blocking client (tests, the hook's `agent-list`) ------------------------------

/// A blocking agent connection for tests and the fixture hook. Unix sockets get read
/// and write timeouts; Windows pipes are opened as files (no timeout).
pub struct AgentConnection {
    stream: Box<dyn ReadWrite>,
}

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

impl fmt::Debug for AgentConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentConnection").finish_non_exhaustive()
    }
}

impl AgentConnection {
    /// Connect.
    ///
    /// # Errors
    /// The endpoint cannot be opened, or its kind does not exist on this platform.
    pub fn connect(endpoint: &Endpoint, timeout: Duration) -> io::Result<AgentConnection> {
        match endpoint {
            #[cfg(unix)]
            Endpoint::UnixSocket(path) => {
                let s = std::os::unix::net::UnixStream::connect(path)?;
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))?;
                Ok(AgentConnection {
                    stream: Box::new(s),
                })
            }
            #[cfg(windows)]
            Endpoint::NamedPipe(name) => {
                let _ = timeout;
                let f = fs::OpenOptions::new().read(true).write(true).open(name)?;
                Ok(AgentConnection {
                    stream: Box::new(f),
                })
            }
            #[allow(unreachable_patterns)]
            _ => {
                let _ = timeout;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "endpoint kind not available on this platform",
                ))
            }
        }
    }

    /// Send one request payload and read one reply payload.
    ///
    /// # Errors
    /// I/O failure, a closed connection, or a reply over [`MAX_FRAME`].
    pub fn request(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.stream.write_all(&frame(payload))?;
        self.stream.flush()?;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reply over the frame bound",
            ));
        }
        let mut reply = vec![0u8; n];
        self.stream.read_exact(&mut reply)?;
        Ok(reply)
    }

    /// List identities: `(blob, comment bytes)` pairs.
    ///
    /// # Errors
    /// I/O failure or a reply that is not an identities answer.
    pub fn list(&mut self) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let reply = self.request(&request_identities())?;
        parse_identities_answer(&reply)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not an identities answer"))
    }
}

// --- the background server shared by FakeAgent and CountingProxy -------------------

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
type BoxStream = Box<dyn AsyncStream>;
type ConnFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

enum FixtureListener {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener, PathBuf),
    #[cfg(windows)]
    Pipe(heimdall_ipc::windows::Listener),
}

impl FixtureListener {
    /// Bind inside the current runtime. A Unix path that already exists is refused
    /// (never removed: it is not ours).
    fn bind(endpoint: &Endpoint) -> io::Result<FixtureListener> {
        match endpoint {
            #[cfg(unix)]
            Endpoint::UnixSocket(path) => {
                use std::os::unix::fs::PermissionsExt;
                let listener = tokio::net::UnixListener::bind(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                Ok(FixtureListener::Unix(listener, path.clone()))
            }
            #[cfg(windows)]
            Endpoint::NamedPipe(name) => {
                let sid = heimdall_ipc::windows::current_user_sid()?;
                let listener = heimdall_ipc::windows::Listener::bind(
                    name,
                    heimdall_ipc::EndpointKind::Signing,
                    &sid,
                )?;
                Ok(FixtureListener::Pipe(listener))
            }
            #[allow(unreachable_patterns)]
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "endpoint kind not available on this platform",
            )),
        }
    }

    async fn accept(&self) -> io::Result<BoxStream> {
        match self {
            #[cfg(unix)]
            FixtureListener::Unix(l, _) => Ok(Box::new(l.accept().await?.0)),
            #[cfg(windows)]
            FixtureListener::Pipe(l) => Ok(Box::new(l.accept().await?.0)),
        }
    }

    /// Remove the socket file this listener created.
    fn close(self) {
        match self {
            #[cfg(unix)]
            FixtureListener::Unix(l, path) => {
                drop(l);
                let _ = fs::remove_file(path);
            }
            #[cfg(windows)]
            FixtureListener::Pipe(l) => drop(l),
        }
    }
}

async fn connect_endpoint(endpoint: &Endpoint) -> io::Result<BoxStream> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::UnixSocket(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
        #[cfg(windows)]
        Endpoint::NamedPipe(name) => Ok(Box::new(
            heimdall_ipc::windows::connect(Path::new(name)).await?,
        )),
        #[allow(unreachable_patterns)]
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "endpoint kind not available on this platform",
        )),
    }
}

async fn read_frame(s: &mut BoxStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.ok()?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return None;
    }
    let mut payload = vec![0u8; n];
    s.read_exact(&mut payload).await.ok()?;
    Some(payload)
}

/// One server thread with its own current-thread runtime. Stopping it drops the
/// runtime, which cancels every connection task and closes every stream.
struct Background {
    shutdown: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl Background {
    fn spawn<H>(name: &str, endpoint: Endpoint, on_conn: H) -> io::Result<Background>
    where
        H: Fn(BoxStream) -> ConnFuture + Send + 'static,
    {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<()>>();
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        let thread = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                rt.block_on(async move {
                    let listener = match FixtureListener::bind(&endpoint) {
                        Ok(l) => l,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    let _ = ready_tx.send(Ok(()));
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.wait_for(|stop| *stop) => break,
                            accepted = listener.accept() => match accepted {
                                Ok(stream) => {
                                    tokio::spawn(on_conn(stream));
                                }
                                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                            },
                        }
                    }
                    listener.close();
                });
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Background {
                shutdown,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "fixture server thread exited before binding",
                ))
            }
        }
    }

    fn stop(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        self.stop();
    }
}

// --- FakeAgent -----------------------------------------------------------------------

/// Where a [`AgentMode::Stall`] agent stops answering a listing or signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StallPoint {
    /// The request is read and logged; no reply byte is ever sent.
    BeforeReply,
    /// The reply's 4-byte length and its first payload byte are sent; the rest never.
    MidReply,
}

/// How the fake agent answers (m02-plan U7). Every other message type is answered
/// `SSH_AGENT_FAILURE` after it is logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentMode {
    /// Lists its keys; signs with them.
    Normal,
    /// Lists no identity and refuses every signature, as a locked `ssh-agent` does.
    Locked,
    /// Lists its keys; holds every signing request until [`FakeAgent::release_pending`]
    /// (a provider approval dialog), then signs. The release covers later requests.
    ApprovalPending,
    /// Lists its keys; refuses every signature (the owner denied).
    Deny,
    /// Lists this many extra generated keys **before** its configured keys; signs with
    /// any of them (too-many-keys fixtures, A35).
    ManyKeys(usize),
    /// Stalls listing and signing requests at the given point, holding the connection
    /// open until the peer closes it or the agent stops (drop tests, m02-plan U6).
    Stall(StallPoint),
}

/// The fake agent's configuration.
#[derive(Debug, Clone)]
pub struct FakeAgentConfig {
    /// Keys, in listing order.
    pub keys: Vec<FixtureKey>,
    /// Mode.
    pub mode: AgentMode,
}

/// One received message: its type and, for a signing request, the requested key's
/// fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentContact {
    /// The message type byte (`0` for an empty frame).
    pub msg_type: u8,
    /// `SHA256:…` of the key a signing request names.
    pub key_fp: Option<String>,
}

struct AgentShared {
    log: Mutex<Vec<AgentContact>>,
    accepted: AtomicUsize,
    open: AtomicUsize,
    approved: watch::Sender<bool>,
    mode: AgentMode,
    listed: Vec<FixtureKey>,
}

enum Reply {
    Payload(Vec<u8>),
    Stall(StallPoint, Vec<u8>),
}

impl AgentShared {
    fn failure() -> Vec<u8> {
        vec![msg::FAILURE]
    }

    fn identities(&self) -> Vec<u8> {
        let keys: Vec<(Vec<u8>, String)> = self
            .listed
            .iter()
            .map(|k| (k.public_blob(), k.comment().to_owned()))
            .collect();
        identities_answer(&keys)
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let Some((blob, data)) = parse_sign_request(payload) else {
            return Self::failure();
        };
        let Some(key) = self.listed.iter().find(|k| k.public_blob() == blob) else {
            return Self::failure();
        };
        match key.sign(data) {
            Some(signature) => {
                let mut out = vec![msg::SIGN_RESPONSE];
                put_string(&mut out, &signature);
                out
            }
            None => Self::failure(),
        }
    }

    async fn respond(&self, msg_type: u8, payload: &[u8]) -> Reply {
        match (msg_type, &self.mode) {
            (msg::REQUEST_IDENTITIES, AgentMode::Locked) => Reply::Payload(identities_answer(&[])),
            (msg::REQUEST_IDENTITIES, AgentMode::Stall(p)) => Reply::Stall(*p, self.identities()),
            (msg::REQUEST_IDENTITIES, _) => Reply::Payload(self.identities()),
            (msg::SIGN_REQUEST, AgentMode::Locked | AgentMode::Deny) => {
                Reply::Payload(Self::failure())
            }
            (msg::SIGN_REQUEST, AgentMode::Stall(p)) => Reply::Stall(*p, self.sign(payload)),
            (msg::SIGN_REQUEST, AgentMode::ApprovalPending) => {
                let mut rx = self.approved.subscribe();
                let _ = rx.wait_for(|approved| *approved).await;
                Reply::Payload(self.sign(payload))
            }
            (msg::SIGN_REQUEST, _) => Reply::Payload(self.sign(payload)),
            _ => Reply::Payload(Self::failure()),
        }
    }
}

struct OpenGuard(Arc<AgentShared>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn drain_until_closed(s: &mut BoxStream) {
    let mut sink = [0u8; 1024];
    while let Ok(n) = s.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }
}

async fn serve_agent(mut s: BoxStream, shared: Arc<AgentShared>) {
    shared.accepted.fetch_add(1, Ordering::SeqCst);
    shared.open.fetch_add(1, Ordering::SeqCst);
    let _guard = OpenGuard(Arc::clone(&shared));
    while let Some(payload) = read_frame(&mut s).await {
        let msg_type = payload.first().copied().unwrap_or(0);
        let key_fp = if msg_type == msg::SIGN_REQUEST {
            parse_sign_request(&payload).and_then(|(blob, _)| blob_fingerprint(blob))
        } else {
            None
        };
        if let Ok(mut log) = shared.log.lock() {
            log.push(AgentContact { msg_type, key_fp });
        }
        match shared.respond(msg_type, &payload).await {
            Reply::Payload(reply) => {
                if s.write_all(&frame(&reply)).await.is_err() || s.flush().await.is_err() {
                    return;
                }
            }
            Reply::Stall(point, reply) => {
                if point == StallPoint::MidReply {
                    let whole = frame(&reply);
                    let _ = s.write_all(&whole[..5.min(whole.len())]).await;
                    let _ = s.flush().await;
                }
                drain_until_closed(&mut s).await;
                return;
            }
        }
    }
}

/// An in-process fake SSH agent (m02-plan U7 `agent::FakeAgent`). Stops on drop.
pub struct FakeAgent {
    endpoint: Endpoint,
    shared: Arc<AgentShared>,
    background: Background,
}

impl fmt::Debug for FakeAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeAgent")
            .field("endpoint", &self.endpoint)
            .field("mode", &self.shared.mode)
            .finish_non_exhaustive()
    }
}

impl FakeAgent {
    /// Start serving `endpoint`.
    ///
    /// # Panics
    /// When the endpoint cannot be bound (a fixture never continues half-built).
    #[must_use]
    pub fn start(endpoint: Endpoint, config: FakeAgentConfig) -> FakeAgent {
        match FakeAgent::try_start(endpoint, config) {
            Ok(agent) => agent,
            Err(e) => panic!("FakeAgent::start failed: {e}"),
        }
    }

    /// [`start`](Self::start) without the panic.
    ///
    /// # Errors
    /// The endpoint cannot be bound.
    pub fn try_start(endpoint: Endpoint, config: FakeAgentConfig) -> io::Result<FakeAgent> {
        let mut listed = match config.mode {
            AgentMode::ManyKeys(n) => FixtureKey::generate_many(n),
            _ => Vec::new(),
        };
        listed.extend(config.keys);
        let shared = Arc::new(AgentShared {
            log: Mutex::new(Vec::new()),
            accepted: AtomicUsize::new(0),
            open: AtomicUsize::new(0),
            approved: watch::channel(false).0,
            mode: config.mode,
            listed,
        });
        let conn_shared = Arc::clone(&shared);
        let background = Background::spawn("hm-fake-agent", endpoint.clone(), move |s| {
            Box::pin(serve_agent(s, Arc::clone(&conn_shared)))
        })?;
        Ok(FakeAgent {
            endpoint,
            shared,
            background,
        })
    }

    /// Where it listens.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Every message received so far, in order.
    #[must_use]
    pub fn log(&self) -> Vec<AgentContact> {
        self.shared
            .log
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default()
    }

    /// Number of messages received.
    #[must_use]
    pub fn contact_count(&self) -> usize {
        self.shared.log.lock().map(|l| l.len()).unwrap_or(0)
    }

    /// Number of connections accepted (on Unix a connection that sends nothing is still
    /// one; on Windows the pipe listener refuses a client that has sent nothing, as it
    /// cannot identify it, so that one is not counted).
    #[must_use]
    pub fn connections(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// Number of connections currently open.
    #[must_use]
    pub fn open_connections(&self) -> usize {
        self.shared.open.load(Ordering::SeqCst)
    }

    /// The keys it lists, in order (for [`AgentMode::ManyKeys`], the generated extras
    /// first).
    #[must_use]
    pub fn listed_keys(&self) -> &[FixtureKey] {
        &self.shared.listed
    }

    /// Release held signing requests ([`AgentMode::ApprovalPending`]); later requests
    /// are answered at once.
    pub fn release_pending(&self) {
        self.shared.approved.send_replace(true);
    }

    /// Poll `pred` every 5 ms until it holds or `timeout` passes; returns whether it
    /// held.
    pub fn wait_until(&self, timeout: Duration, pred: impl Fn(&FakeAgent) -> bool) -> bool {
        let end = Instant::now() + timeout;
        loop {
            if pred(self) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Stop: close the listener and every connection, remove the socket file.
    pub fn stop(&mut self) {
        self.background.stop();
    }
}

// --- CountingProxy -------------------------------------------------------------------

struct ProxyShared {
    upstream: Endpoint,
    log: Mutex<Vec<u8>>,
    accepted: AtomicUsize,
}

async fn relay(mut client: BoxStream, shared: Arc<ProxyShared>) {
    shared.accepted.fetch_add(1, Ordering::SeqCst);
    let Ok(mut upstream) = connect_endpoint(&shared.upstream).await else {
        return;
    };
    while let Some(request) = read_frame(&mut client).await {
        if let Ok(mut log) = shared.log.lock() {
            log.push(request.first().copied().unwrap_or(0));
        }
        if upstream.write_all(&frame(&request)).await.is_err() {
            return;
        }
        let Some(reply) = read_frame(&mut upstream).await else {
            return;
        };
        if client.write_all(&frame(&reply)).await.is_err() {
            return;
        }
    }
}

/// A counting socket in front of a real agent (m02-plan U7 `agent::CountingProxy`;
/// ADR-0007 §9 item 4). Each accepted connection gets its own upstream connection;
/// request frames are forwarded one at a time with their replies, and each request's
/// message type is logged. Stops on drop.
pub struct CountingProxy {
    endpoint: Endpoint,
    shared: Arc<ProxyShared>,
    background: Background,
}

impl fmt::Debug for CountingProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CountingProxy")
            .field("endpoint", &self.endpoint)
            .field("upstream", &self.shared.upstream)
            .finish_non_exhaustive()
    }
}

impl CountingProxy {
    /// Listen on `listen` and forward to `upstream`.
    ///
    /// # Panics
    /// When `listen` cannot be bound.
    #[must_use]
    pub fn start(upstream: &EndpointLocator, listen: Endpoint) -> CountingProxy {
        match CountingProxy::try_start(upstream, listen) {
            Ok(p) => p,
            Err(e) => panic!("CountingProxy::start failed: {e}"),
        }
    }

    /// [`start`](Self::start) without the panic.
    ///
    /// # Errors
    /// `listen` cannot be bound.
    pub fn try_start(upstream: &EndpointLocator, listen: Endpoint) -> io::Result<CountingProxy> {
        let shared = Arc::new(ProxyShared {
            upstream: upstream.clone(),
            log: Mutex::new(Vec::new()),
            accepted: AtomicUsize::new(0),
        });
        let conn_shared = Arc::clone(&shared);
        let background = Background::spawn("hm-counting-proxy", listen.clone(), move |s| {
            Box::pin(relay(s, Arc::clone(&conn_shared)))
        })?;
        Ok(CountingProxy {
            endpoint: listen,
            shared,
            background,
        })
    }

    /// Where it listens.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The message type of every forwarded request, in order.
    #[must_use]
    pub fn log(&self) -> Vec<u8> {
        self.shared
            .log
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default()
    }

    /// Number of forwarded requests.
    #[must_use]
    pub fn count(&self) -> usize {
        self.shared.log.lock().map(|l| l.len()).unwrap_or(0)
    }

    /// Number of client connections accepted. On Windows a pipe client that has sent
    /// nothing cannot be identified by the listener and is refused, so it is not
    /// counted.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// Stop.
    pub fn stop(&mut self) {
        self.background.stop();
    }
}

// --- DisposableSshAgent --------------------------------------------------------------

/// What the counting askpass answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AskpassAnswer {
    /// Exit 0 with no output: the agent treats it as consent.
    #[default]
    Approve,
    /// Exit 1: the agent refuses the operation.
    Deny,
}

impl AskpassAnswer {
    /// The hook's argument (`approve` | `deny`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AskpassAnswer::Approve => "approve",
            AskpassAnswer::Deny => "deny",
        }
    }
}

/// Options of a [`DisposableSshAgent`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentOptions {
    /// When set, the agent runs with `SSH_ASKPASS` = the counting askpass, which
    /// appends one line to this file per invocation, and `SSH_ASKPASS_REQUIRE=force`.
    pub askpass_log: Option<PathBuf>,
    /// The askpass answer (changeable later with
    /// [`DisposableSshAgent::set_askpass_answer`]).
    pub askpass_answer: AskpassAnswer,
}

/// Constraints for [`DisposableSshAgent::add_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KeyConstraints {
    /// `ssh-add -c`: the agent asks through askpass before each use (F23).
    pub confirm: bool,
}

/// The signing control's observation (ADR-0007 F23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignControl {
    /// A signature was produced and `ssh-keygen -Y verify` accepted it.
    pub signed: bool,
    /// Askpass invocations the signing caused.
    pub askpass_delta: u32,
}

/// A prepared, not yet started, disposable agent: its directory layout and the exact
/// command (m02-plan U7 `disposable_agent_runs_with_scratch_home`).
#[derive(Debug)]
pub struct AgentLaunch {
    /// The command: `ssh-agent -D -a <socket>`, cleared environment, `PATH`,
    /// `HOME=<scratch home>` and, with askpass, `SSH_ASKPASS` and
    /// `SSH_ASKPASS_REQUIRE=force`.
    pub command: Command,
    /// The agent's scratch directory.
    pub dir: PathBuf,
    /// The agent's scratch `HOME`.
    pub home: PathBuf,
    /// The socket it will bind.
    pub socket: PathBuf,
    /// The askpass wrapper, when configured.
    pub askpass: Option<PathBuf>,
    askpass_log: Option<PathBuf>,
    answer_file: PathBuf,
    lock_askpass: PathBuf,
}

/// The minimal `PATH` every disposable-agent child runs with.
const CHILD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// The signing control's namespace and principal.
const SIGN_NAMESPACE: &str = "hm-fixture";
/// The fixed fixture lock passphrase for [`DisposableSshAgent::lock`] (not a secret).
const LOCK_PASSPHRASE: &str = "hm-fixture-lock";
/// Bound on every child the fixture waits for.
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// A real, disposable `ssh-agent` (m02-plan U7 `agent::DisposableSshAgent`). Stopped by
/// exact PID on [`stop`](Self::stop) or drop.
#[derive(Debug)]
pub struct DisposableSshAgent {
    /// The agent's socket (in scratch).
    pub socket: PathBuf,
    /// The agent's PID.
    pub pid: u32,
    dir: PathBuf,
    home: PathBuf,
    askpass_log: Option<PathBuf>,
    answer_file: PathBuf,
    lock_askpass: PathBuf,
    child: Option<Child>,
    seq: AtomicU32,
}

impl DisposableSshAgent {
    /// Prepare the layout and the command without starting anything.
    ///
    /// # Errors
    /// `ssh-agent` is not installed, or the layout cannot be written.
    pub fn prepare(
        scratch: &Scratch,
        options: &AgentOptions,
        hook: &HookBinary,
    ) -> io::Result<AgentLaunch> {
        let program = find_program("ssh-agent")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ssh-agent not installed"))?;
        let dir = scratch.subdir("sa")?;
        let home = dir.join("home");
        fs::create_dir(&home)?;
        let socket = dir.join("agent.sock");
        let answer_file = dir.join("askpass-answer");
        fs::write(&answer_file, options.askpass_answer.as_str())?;
        let askpass = match &options.askpass_log {
            Some(log) => {
                let wrapper = dir.join("askpass");
                let script = format!(
                    "#!/bin/sh\nexec {} askpass {} \"$(cat {})\" \"$@\"\n",
                    sh_quote(hook.path().as_os_str()),
                    sh_quote(log.as_os_str()),
                    sh_quote(answer_file.as_os_str()),
                );
                write_executable(&wrapper, &script)?;
                Some(wrapper)
            }
            None => None,
        };
        let lock_askpass = dir.join("askpass-lock");
        write_executable(
            &lock_askpass,
            &format!("#!/bin/sh\nprintf '%s\\n' '{LOCK_PASSPHRASE}'\n"),
        )?;
        let mut command = Command::new(program);
        command
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("HOME", &home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(wrapper) = &askpass {
            command
                .env("SSH_ASKPASS", wrapper)
                .env("SSH_ASKPASS_REQUIRE", "force");
        }
        Ok(AgentLaunch {
            command,
            dir,
            home,
            socket,
            askpass,
            askpass_log: options.askpass_log.clone(),
            answer_file,
            lock_askpass,
        })
    }

    /// Start with the fixture hook found by [`HookBinary::locate`].
    ///
    /// # Errors
    /// The hook or `ssh-agent` cannot be found, or the agent does not come up.
    pub fn start(scratch: &Scratch, options: AgentOptions) -> io::Result<DisposableSshAgent> {
        let hook = HookBinary::locate()?;
        DisposableSshAgent::start_with_hook(scratch, options, &hook)
    }

    /// Start with an explicit hook binary.
    ///
    /// # Errors
    /// Not Unix, `ssh-agent` missing, or the agent does not bind its socket in 10 s.
    pub fn start_with_hook(
        scratch: &Scratch,
        options: AgentOptions,
        hook: &HookBinary,
    ) -> io::Result<DisposableSshAgent> {
        if !cfg!(unix) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the disposable ssh-agent fixture is Unix only (m02-plan §4)",
            ));
        }
        let mut launch = DisposableSshAgent::prepare(scratch, &options, hook)?;
        let mut child = launch.command.spawn()?;
        let pid = child.id();
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if is_socket(&launch.socket) {
                break;
            }
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "ssh-agent exited before binding: {status}"
                )));
            }
            if Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ssh-agent did not bind its socket",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(DisposableSshAgent {
            socket: launch.socket,
            pid,
            dir: launch.dir,
            home: launch.home,
            askpass_log: launch.askpass_log,
            answer_file: launch.answer_file,
            lock_askpass: launch.lock_askpass,
            child: Some(child),
            seq: AtomicU32::new(1),
        })
    }

    /// The agent's endpoint.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::UnixSocket(self.socket.clone())
    }

    /// The agent's scratch `HOME`.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    fn tool(&self, name: &str, socket: &Path) -> io::Result<Command> {
        let program = find_program(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} not installed"))
        })?;
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", CHILD_PATH)
            .env("HOME", &self.home)
            .env("SSH_AUTH_SOCK", socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(cmd)
    }

    fn next(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Add `key` with `ssh-add` (`-c` when `confirm`). The private key is written to an
    /// owner-only scratch file for the call and removed right after.
    ///
    /// # Errors
    /// `ssh-add` is missing or fails.
    pub fn add_key(&self, key: &FixtureKey, constraints: KeyConstraints) -> io::Result<()> {
        let file = self.dir.join(format!("k{}", self.next()));
        key.write_private(&file)?;
        let mut cmd = self.tool("ssh-add", &self.socket)?;
        cmd.arg("-q");
        if constraints.confirm {
            cmd.arg("-c");
        }
        cmd.arg(&file);
        let status = run_bounded(&mut cmd);
        let removed = fs::remove_file(&file);
        let status = status?;
        removed?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("ssh-add failed: {status}")))
        }
    }

    /// Lock the agent (`ssh-add -x`, the fixed fixture passphrase through a scratch
    /// askpass).
    ///
    /// # Errors
    /// `ssh-add` is missing or fails.
    pub fn lock(&self) -> io::Result<()> {
        self.lock_op("-x")
    }

    /// Unlock the agent (`ssh-add -X`).
    ///
    /// # Errors
    /// `ssh-add` is missing or fails.
    pub fn unlock(&self) -> io::Result<()> {
        self.lock_op("-X")
    }

    fn lock_op(&self, flag: &str) -> io::Result<()> {
        let mut cmd = self.tool("ssh-add", &self.socket)?;
        cmd.arg(flag)
            .env("SSH_ASKPASS", &self.lock_askpass)
            .env("SSH_ASKPASS_REQUIRE", "force");
        let status = run_bounded(&mut cmd)?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("ssh-add {flag} failed: {status}")))
        }
    }

    /// Change the askpass answer for later prompts.
    ///
    /// # Errors
    /// The write fails.
    pub fn set_askpass_answer(&self, answer: AskpassAnswer) -> io::Result<()> {
        fs::write(&self.answer_file, answer.as_str())
    }

    /// Askpass invocations so far (lines in the askpass log; 0 without one).
    #[must_use]
    pub fn askpass_count(&self) -> u32 {
        self.askpass_log
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .map_or(0, |b| {
                u32::try_from(b.iter().filter(|&&c| c == b'\n').count()).unwrap_or(u32::MAX)
            })
    }

    /// The authorized disposable signing control (ADR-0007 F23; M2-R08): `ssh-keygen -Y
    /// sign -n hm-fixture` with `SSH_AUTH_SOCK` = this agent and only the public key
    /// file, then `ssh-keygen -Y verify` against the fixture's allowed-signers file.
    ///
    /// # Errors
    /// The tools are missing, the scratch files cannot be written, or a tool exceeds
    /// the 30 s bound.
    pub fn sign_control(&self, key: &FixtureKey, challenge: &[u8]) -> io::Result<SignControl> {
        self.sign_control_through(&self.socket, key, challenge)
    }

    /// [`sign_control`](Self::sign_control) with `SSH_AUTH_SOCK` = `socket` (for
    /// example a [`CountingProxy`] in front of this agent). The askpass delta is still
    /// this agent's.
    ///
    /// # Errors
    /// See [`sign_control`](Self::sign_control).
    pub fn sign_control_through(
        &self,
        socket: &Path,
        key: &FixtureKey,
        challenge: &[u8],
    ) -> io::Result<SignControl> {
        let d = self.dir.join(format!("sign{}", self.next()));
        fs::create_dir(&d)?;
        let public = d.join("key.pub");
        key.write_public(&public)?;
        let allowed = d.join("allowed_signers");
        fs::write(
            &allowed,
            format!(
                "{SIGN_NAMESPACE} namespaces=\"{SIGN_NAMESPACE}\" {}\n",
                key.public_line_without_comment()
            ),
        )?;
        let challenge_file = d.join("challenge");
        fs::write(&challenge_file, challenge)?;
        let signature = d.join("challenge.sig");

        let before = self.askpass_count();
        let mut sign = self.tool("ssh-keygen", socket)?;
        sign.args(["-Y", "sign", "-n", SIGN_NAMESPACE, "-f"])
            .arg(&public)
            .stdin(fs::File::open(&challenge_file)?)
            .stdout(fs::File::create(&signature)?);
        let produced = run_bounded(&mut sign)?.success()
            && fs::metadata(&signature)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
        let after = self.askpass_count();

        let signed = produced && {
            let mut verify = self.tool("ssh-keygen", socket)?;
            verify
                .args(["-Y", "verify", "-f"])
                .arg(&allowed)
                .args(["-I", SIGN_NAMESPACE, "-n", SIGN_NAMESPACE, "-s"])
                .arg(&signature)
                .env_remove("SSH_AUTH_SOCK")
                .stdin(fs::File::open(&challenge_file)?);
            run_bounded(&mut verify)?.success()
        };
        Ok(SignControl {
            signed,
            askpass_delta: after.saturating_sub(before),
        })
    }

    /// Stop by exact PID: SIGTERM (the agent removes its socket), then SIGKILL through
    /// the child handle after 5 s.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            stop_child(&mut child);
        }
    }
}

impl Drop for DisposableSshAgent {
    fn drop(&mut self) {
        self.stop();
    }
}

fn write_executable(path: &Path, script: &str) -> io::Result<()> {
    write_owner_only(path, script.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn is_socket(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Run a child to completion within [`CHILD_TIMEOUT`]; on timeout kill it through its
/// handle (exact PID) and fail.
pub(crate) fn run_bounded(cmd: &mut Command) -> io::Result<ExitStatus> {
    let mut child = cmd.spawn()?;
    let end = Instant::now() + CHILD_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture child timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Stop a child this fixture started: SIGTERM by its exact PID (Unix), wait up to 5 s,
/// then kill through the handle. The handle is not reaped before the signal, so the PID
/// cannot have been reused.
pub(crate) fn stop_child(child: &mut Child) {
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }
    #[cfg(unix)]
    {
        use rustix::process::{Pid, Signal, kill_process};
        let _ = kill_process(Pid::from_child(child), Signal::TERM);
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_keys_are_fresh_ed25519_with_canary_comments() {
        let a = FixtureKey::generate();
        let b = FixtureKey::generate();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert!(a.comment().starts_with(CANARY_PREFIX));
        assert_ne!(a.comment(), b.comment());
        assert!(a.public_line().starts_with("ssh-ed25519 "));
        assert!(!a.public_line_without_comment().contains(CANARY_PREFIX));
        assert_eq!(blob_fingerprint(&a.public_blob()), Some(a.fingerprint()));
        assert!(!format!("{a:?}").contains(CANARY_PREFIX));
        let sig = a.sign(b"data").unwrap();
        let mut c = Cursor(&sig);
        assert_eq!(c.string(), Some(&b"ssh-ed25519"[..]));
        assert_eq!(c.string().map(<[u8]>::len), Some(64));
    }

    #[test]
    fn wire_round_trips() {
        let k = FixtureKey::generate();
        let answer = identities_answer(&[(k.public_blob(), "c".to_owned())]);
        let parsed = parse_identities_answer(&answer).unwrap();
        assert_eq!(parsed, vec![(k.public_blob(), b"c".to_vec())]);
        assert_eq!(parse_identities_answer(&answer[..answer.len() - 1]), None);
        let req = sign_request(&k.public_blob(), b"xyz", 0);
        assert_eq!(
            parse_sign_request(&req),
            Some((&k.public_blob()[..], &b"xyz"[..]))
        );
        assert!(is_fixture_pipe_name(r"\\.\pipe\heimdall-hmtest-ab12-x"));
        assert!(is_fixture_pipe_name(r"\\.\PIPE\Heimdall-HMTEST-ab12-x"));
        assert!(!is_fixture_pipe_name(r"\\.\pipe\openssh-ssh-agent"));
        assert!(!is_fixture_pipe_name(r"\\.\pipe\heimdall-hmtest-"));
    }
}
