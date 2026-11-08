//! Windows endpoints: owner-only named pipes with client SID check (ADR-0006 §2.1;
//! g03 §3.1 N2; prototypes/rust/REPORT.md §16 lessons).
//!
//! Server: `tokio::net::windows::named_pipe::ServerOptions` with
//! `reject_remote_clients(true)`, `first_pipe_instance(true)` on the first
//! instance, and a `SECURITY_ATTRIBUTES` whose DACL is
//! `D:P(A;;GA;;;<owner SID>)` (protected, owner-only; further instances rely on the
//! DACL withholding `FILE_CREATE_PIPE_INSTANCE`). Names are
//! `\\.\pipe\heimdall-<unpredictable token>-<kind>` and carry no labels.
//!
//! Per connection the server impersonates at identification level
//! (`ImpersonateNamedPipeClient`), reads `TokenUser` from the thread token, reverts,
//! and requires the SID to equal the owner's. `GetNamedPipeClientProcessId` is
//! metadata only.
//!
//! Identification waits for the client's first write (W6). `ConnectNamedPipe`
//! completes when the client opens the pipe, and Windows refuses
//! `ImpersonateNamedPipeClient` with `ERROR_CANNOT_IMPERSONATE` until data has been
//! read from the pipe when the client opened without a static security context
//! (default `CreateFileW` flags, observed natively). Every client of both endpoints
//! writes first (the control hello, the ssh-agent request), so each connected
//! instance is identified only once it is readable: the reactor has completed a read
//! into the instance's own buffer, which the caller then reads first, so no client
//! byte is consumed or reordered. The wait is bounded by [`FIRST_WRITE_WAIT`]; a
//! client still silent then is disconnected and never treated as verified. Each
//! connection is identified on its own task, so a silent or slow client never holds
//! up `accept` for others; at most [`MAX_PENDING_IDENTIFICATIONS`] wait at once.
//!
//! Client: `ClientOptions::security_qos_flags(SECURITY_IDENTIFICATION |
//! SECURITY_SQOS_PRESENT)` so a rogue server cannot impersonate the client beyond
//! identification. Before opening, the path is classified: it must normalize
//! (`GetFullPathNameW`) into the `\\.\pipe\` or `\\?\pipe\` namespace, and the opened
//! handle must report `FILE_TYPE_PIPE`; anything else is refused without a data open
//! (REPORT.md §16 "classify the path before opening it").
//!
//! Client-side server check (ADR-0006 §2.1 rev2, wave-1 E14): production clients use
//! [`connect_with_owner`], which after classification and the `FILE_TYPE_PIPE`
//! check reads the pipe's owner SID from the client handle (`GetSecurityInfo` with
//! `OWNER_SECURITY_INFORMATION`) and refuses (`PermissionDenied`, before any byte is
//! written) unless it equals the expected owner: the current user
//! ([`ServerOwner::CurrentUser`]) or, for a documented elevated runtime whose pipes
//! carry its token's default owner, a configured SID ([`ServerOwner::Sid`]). This is
//! the Windows counterpart of the Unix client's server peer-credential check: a pipe
//! name squatted by another user is refused. [`connect`] has no owner check and is
//! for tests only.
//!
//! This is the crate's only `unsafe` boundary: the raw security-attributes pointer
//! passed to `create_with_security_attributes_raw`, the SDDL conversion, the
//! impersonation/token calls, and the owner query on a client handle. Each call is
//! wrapped in a safe function with documented invariants; no unsafe escapes this
//! module.

#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::ptr;
use std::time::Duration;

use tokio::io::Interest;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};
use tokio::task::JoinSet;
use windows_sys::Win32::Foundation::{
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_LOCAL, ERROR_SUCCESS, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_TYPE_PIPE, GetFileType, GetFullPathNameW, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientComputerNameW, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::endpoint::{EndpointKind, ExpectedOwner, PeerIdentity, PeerRejected, verify_peer};

/// Longest SID string accepted (revision, authority and 15 sub-authorities of at
/// most 10 digits each fit comfortably).
const MAX_SID_STRING_CHARS: usize = 192;

/// Upper bound for a `GetTokenInformation` buffer (`TokenUser` is well under 100
/// bytes); a larger reported size is treated as a failure.
const MAX_TOKEN_INFO_BYTES: u32 = 256 << 10;

/// Upper bound for a normalized endpoint path (UTF-16 units). Pipe names are short;
/// anything longer than the extended-path limit is refused unopened.
const MAX_PATH_UNITS: u32 = 32_768;

/// `ERROR_PIPE_BUSY` retries on connect (every instance momentarily taken).
const CONNECT_BUSY_RETRIES: u32 = 20;
/// Pause between `ERROR_PIPE_BUSY` retries.
const CONNECT_BUSY_BACKOFF: Duration = Duration::from_millis(25);

/// Pipe-namespace prefixes accepted after normalization (ASCII, compared
/// case-insensitively).
const PIPE_PREFIXES: [&str; 2] = [r"\\.\pipe\", r"\\?\pipe\"];

/// How long a connected client may take to send its first bytes before it is
/// disconnected unidentified (W6). Equal to the control hello deadline
/// (`HELLO_TIMEOUT_MS`): a control client silent this long is already out of time,
/// and an ssh-agent client writes its request as soon as it opens.
pub const FIRST_WRITE_WAIT: Duration =
    Duration::from_millis(heimdall_contract::ipc::HELLO_TIMEOUT_MS);

/// Connected instances waiting for their client's first write at once. While this
/// many wait, `accept` stops taking new connections (the waiting instance stays
/// listening, so the name stays held) until one is identified or times out. Equal
/// to the runtime's per-endpoint connection bound (`MAX_CONTROL_CONNECTIONS`).
pub const MAX_PENDING_IDENTIFICATIONS: usize = heimdall_contract::ipc::MAX_CONTROL_CONNECTIONS;

/// A connection whose identification finished: verified (`Some`), or refused and
/// already disconnected (`None`).
type Identified = Option<(NamedPipeServer, PeerIdentity)>;

/// What `accept` holds across calls (behind the listener's mutex, so a cancelled
/// `accept` loses nothing).
#[derive(Debug, Default)]
struct AcceptState {
    /// The instance waiting for the next client. Kept here while `accept` waits so a
    /// cancelled `accept` never closes the last instance (which would free the name
    /// for another principal to claim).
    waiting: Option<NamedPipeServer>,
    /// Connected instances being identified, one task each. Dropping the listener
    /// aborts them, which closes their instances.
    identifying: JoinSet<Identified>,
}

/// A named-pipe endpoint that creates a fresh instance per accepted client.
#[derive(Debug)]
pub struct Listener {
    kind: EndpointKind,
    name: String,
    owner_sid: String,
    /// The SID granted by the instance DACL. Always `owner_sid` outside tests; the
    /// SID-mismatch tests split the two to exercise the post-connect check.
    dacl_sid: String,
    /// [`FIRST_WRITE_WAIT`] outside tests (which shorten it).
    first_write_wait: Duration,
    state: tokio::sync::Mutex<AcceptState>,
}

impl Listener {
    /// Create the first instance (fails if the name exists) with the owner-only DACL.
    ///
    /// `name` must classify into the pipe namespace (`\\.\pipe\…`); `owner_sid` must
    /// be a literal SID string (`S-1-…`), never an SDDL alias. Must be called from
    /// within a tokio runtime with I/O enabled (the instance registers with its
    /// reactor); outside one it returns an error instead of panicking.
    pub fn bind(name: &str, kind: EndpointKind, owner_sid: &str) -> io::Result<Self> {
        Self::bind_inner(name, kind, owner_sid, owner_sid)
    }

    fn bind_inner(
        name: &str,
        kind: EndpointKind,
        owner_sid: &str,
        dacl_sid: &str,
    ) -> io::Result<Self> {
        if classify_path(Path::new(name)) != PathClass::PipeNamespace {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "endpoint name is not in the named-pipe namespace",
            ));
        }
        if !is_sid_string(owner_sid) || !is_sid_string(dacl_sid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "owner is not a literal SID string",
            ));
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other(
                "named-pipe endpoints must be bound inside a tokio runtime",
            ));
        }
        let first = create_instance(name, dacl_sid, true)?;
        Ok(Self {
            kind,
            name: name.to_owned(),
            owner_sid: owner_sid.to_owned(),
            dacl_sid: dacl_sid.to_owned(),
            first_write_wait: FIRST_WRITE_WAIT,
            state: tokio::sync::Mutex::new(AcceptState {
                waiting: Some(first),
                identifying: JoinSet::new(),
            }),
        })
    }

    /// Tests only: a shorter first-write bound.
    #[cfg(test)]
    fn with_first_write_wait(mut self, wait: Duration) -> Self {
        self.first_write_wait = wait;
        self
    }

    /// Wait for a client, verify its SID, and pre-create the next instance.
    ///
    /// A connected client is identified only after its first write has been read
    /// into the instance (module docs, W6), within [`FIRST_WRITE_WAIT`]; its bytes
    /// are then returned to the caller unconsumed and in order. Clients that stay
    /// silent past the bound, and clients whose token is not the owner's (different
    /// user, anonymous, network logon), are disconnected and the wait continues;
    /// only verified clients are returned. Identification runs per connection on
    /// its own task, so one silent client never delays another. Cancel-safe:
    /// dropping the future keeps the waiting instance and every connection still
    /// being identified.
    pub async fn accept(&self) -> io::Result<(NamedPipeServer, PeerIdentity)> {
        let mut state = self.state.lock().await;
        loop {
            if state.waiting.is_none() {
                state.waiting = Some(create_instance(&self.name, &self.dacl_sid, false)?);
            }
            let AcceptState {
                waiting,
                identifying,
            } = &mut *state;
            let room = identifying.len() < MAX_PENDING_IDENTIFICATIONS;
            let event = tokio::select! {
                // Finished identifications first: a verified client is not kept
                // waiting behind new connections.
                biased;
                Some(done) = identifying.join_next(), if !identifying.is_empty() => {
                    Event::Identified(done)
                }
                outcome = async {
                    match waiting.as_ref() {
                        Some(instance) => instance.connect().await,
                        None => Ok(()),
                    }
                }, if room => Event::Connected(outcome),
            };
            match event {
                Event::Identified(Ok(Some(verified))) => return Ok(verified),
                // Refused (already disconnected by its task).
                Event::Identified(Ok(None)) => {}
                Event::Identified(Err(err)) => {
                    if err.is_panic() {
                        std::panic::resume_unwind(err.into_panic());
                    }
                    // Aborted: only on runtime shutdown; the instance is closed.
                }
                Event::Connected(outcome) => {
                    // Keep an instance listening before the used one leaves the
                    // slot. If the replacement cannot be created, the used instance
                    // stays in the slot (a connected instance is picked up again by
                    // the next `accept`).
                    let next = create_instance(&self.name, &self.dacl_sid, false)?;
                    let Some(connected) = state.waiting.replace(next) else {
                        continue;
                    };
                    match outcome {
                        Ok(()) => {}
                        // The client closed between its open and our connect: discard.
                        Err(err) if err.raw_os_error() == Some(ERROR_NO_DATA as i32) => continue,
                        Err(err) => return Err(err),
                    }
                    state.identifying.spawn(identify(
                        connected,
                        self.kind,
                        ExpectedOwner::Sid(self.owner_sid.clone()),
                        self.first_write_wait,
                    ));
                }
            }
        }
    }

    /// Endpoint kind.
    #[must_use]
    pub fn kind(&self) -> EndpointKind {
        self.kind
    }
}

/// What one turn of the `accept` loop observed.
enum Event {
    Identified(Result<Identified, tokio::task::JoinError>),
    Connected(io::Result<()>),
}

/// Identify one connected instance (W6): wait, at most `wait`, until the client's
/// first write has been read into the instance, then check the client SID against
/// `owner`. Refused and silent clients are disconnected here and yield `None`; a
/// verified client yields its instance, with the bytes read so far still buffered
/// in it for the caller.
async fn identify(
    connected: NamedPipeServer,
    kind: EndpointKind,
    owner: ExpectedOwner,
    wait: Duration,
) -> Identified {
    let checked = match tokio::time::timeout(wait, connected.ready(Interest::READABLE)).await {
        // Readable: data (or the client's close) has been read. Only now does the
        // client token exist for a default-flags client; a client that closed
        // without writing fails the impersonation and is refused.
        Ok(Ok(_)) => client_sid(&connected).and_then(|sid| {
            let peer = PeerIdentity::Windows {
                sid,
                pid: client_pid(&connected),
            };
            verify_peer(&peer, &owner).map(|_| peer)
        }),
        Ok(Err(err)) => {
            tracing::debug!(kind = ?err.kind(), "named-pipe readiness failed");
            Err(PeerRejected::Unavailable)
        }
        // Still silent at the bound: never identified, so refused.
        Err(_elapsed) => {
            tracing::debug!("no first write within the identification bound");
            Err(PeerRejected::Unavailable)
        }
    };
    match checked {
        Ok(peer) => Some((connected, peer)),
        Err(reason) => {
            tracing::warn!(endpoint = kind.name(), %reason, "named-pipe client refused");
            // Best effort: dropping the instance closes it either way.
            let _ = connected.disconnect();
            None
        }
    }
}

/// Read the connected client's user SID at identification level.
///
/// Refuses (`PeerRejected::Remote`) a client that connected over the network, as
/// a second check behind `PIPE_REJECT_REMOTE_CLIENTS`. The check is on the
/// connection (`GetNamedPipeClientComputerNameW` answers `ERROR_PIPE_LOCAL` for a
/// local client), not on the client's logon type: a same-user process in a local
/// session that was itself opened over SSH is still a local pipe client.
///
/// Call it only after data from the client has been read (W6): before that, a
/// client that opened with default flags has no token to impersonate and the
/// answer is `Unavailable`. [`Listener::accept`] does this.
pub fn client_sid(server: &NamedPipeServer) -> Result<String, PeerRejected> {
    if connection_is_remote(server.as_raw_handle())? {
        return Err(PeerRejected::Remote);
    }
    let token = open_client_token(server.as_raw_handle())?;
    token_user_sid(&token).map_err(|_| PeerRejected::Unavailable)
}

/// Classify a candidate endpoint path before opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// Normalizes into the pipe namespace.
    PipeNamespace,
    /// Anything else (file, device, directory): refuse.
    NotPipe,
}

/// Normalize and classify (`GetFullPathNameW` then prefix check).
#[must_use]
pub fn classify_path(path: &Path) -> PathClass {
    if normalized_pipe_path(path).is_some() {
        PathClass::PipeNamespace
    } else {
        PathClass::NotPipe
    }
}

/// Whose pipe a client is willing to talk to ([`connect_with_owner`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerOwner {
    /// The pipe must be owned by this process's user SID (the normal case: the
    /// runtime runs as the same, non-elevated user).
    CurrentUser,
    /// The pipe must be owned by this literal SID string (`S-1-…`), for a
    /// documented elevated runtime whose pipes carry its token's default owner.
    /// Anything that is not a literal SID (an SDDL alias, an empty string) is
    /// refused with `InvalidInput` before any open.
    Sid(String),
}

/// Production client connect: [`connect`]'s classification, `SECURITY_IDENTIFICATION`
/// open and `FILE_TYPE_PIPE` check, then the server-owner check (ADR-0006 §2.1 rev2,
/// wave-1 E14).
///
/// The pipe's owner SID is read from the client handle (`GetSecurityInfo` with
/// `OWNER_SECURITY_INFORMATION`) and compared, case-insensitively, with the
/// expected owner. A mismatch is `PermissionDenied` and the handle is closed before
/// any byte is written, so a hello (or anything else) never reaches a pipe another
/// principal created under the runtime's name. Failure to read the owner is an
/// error, never a pass. The SIDs involved are not logged.
pub async fn connect_with_owner(path: &Path, owner: ServerOwner) -> io::Result<NamedPipeClient> {
    let expected = match owner {
        ServerOwner::CurrentUser => current_user_sid()?,
        ServerOwner::Sid(sid) => {
            if !is_sid_string(&sid) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected server owner is not a literal SID string",
                ));
            }
            sid
        }
    };
    let client = connect(path).await?;
    let actual = handle_owner_sid(client.as_raw_handle())?;
    if !actual.eq_ignore_ascii_case(&expected) {
        tracing::warn!("named-pipe endpoint owned by an unexpected principal; refused");
        drop(client);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the endpoint is not owned by the expected user",
        ));
    }
    Ok(client)
}

/// Connect with `SECURITY_IDENTIFICATION` after classification and a
/// `FILE_TYPE_PIPE` handle check. **No server-owner check; tests only. Production
/// uses [`connect_with_owner`].**
///
/// A path outside the pipe namespace is refused with `InvalidInput` before any
/// open. The normalized path (the one that was classified) is what gets opened.
/// `ERROR_PIPE_BUSY` is retried a bounded number of times; a missing pipe is
/// `NotFound` (no runtime listening).
pub async fn connect(path: &Path) -> io::Result<NamedPipeClient> {
    let Some(full) = normalized_pipe_path(path) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "endpoint is not in the named-pipe namespace",
        ));
    };
    let mut options = ClientOptions::new();
    options
        .read(true)
        .write(true)
        .pipe_mode(PipeMode::Byte)
        .security_qos_flags(SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT);
    let mut attempts = 0;
    let client = loop {
        match options.open(&full) {
            Ok(client) => break client,
            Err(err)
                if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && attempts < CONNECT_BUSY_RETRIES =>
            {
                attempts += 1;
                tokio::time::sleep(CONNECT_BUSY_BACKOFF).await;
            }
            Err(err) => return Err(err),
        }
    };
    if handle_file_type(client.as_raw_handle()) != FILE_TYPE_PIPE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "endpoint handle is not a pipe",
        ));
    }
    Ok(client)
}

/// The current process's user SID string.
pub fn current_user_sid() -> io::Result<String> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing;
    // `raw` is a valid out-pointer for the duration of the call.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken succeeded, so `raw` is a token handle we now own
    // exclusively; OwnedHandle closes it exactly once.
    let token = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
    token_user_sid(&token)
}

// ---------------------------------------------------------------------------------
// Safe wrappers around the FFI calls. Apart from `current_user_sid` above, every
// `unsafe` block in this module is below this line, and each states its invariant.
// ---------------------------------------------------------------------------------

/// Syntactic check that `s` is a literal SID string (`S-1-<authority>-<sub>…`).
/// Rejects SDDL aliases (`WD`, `BA`, …) and anything that could break out of the
/// ACE in `D:P(A;;GA;;;<sid>)`.
fn is_sid_string(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-") else {
        return false;
    };
    s.len() <= MAX_SID_STRING_CHARS
        && rest.split('-').count() >= 2
        && rest.split('-').all(|part| {
            !part.is_empty() && part.len() <= 20 && part.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Owner-only security descriptor: an explicit owner (`O:<owner>`, so a client's
/// `ServerOwner::CurrentUser` check holds even when the runtime is elevated and the
/// default owner would otherwise be the Administrators group; design-fix second
/// round R6) and a protected DACL granting `GA` (`FILE_ALL_ACCESS`) to `grantee`
/// only. The owner must be a SID the creating process holds (its own user SID):
/// Windows refuses any other owner with `ERROR_INVALID_OWNER` (observed natively,
/// `tests/evidence/artifacts/m01/u6w-native/r6-owner-sddl`), so production passes
/// the current user for both and only tests use a different grantee.
fn owner_only_sddl(owner: &str, grantee: &str) -> String {
    format!("O:{owner}D:P(A;;GA;;;{grantee})")
}

/// Memory returned by an API that documents `LocalFree` as its release function.
struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API that allocates with LocalAlloc
            // (SDDL and SID string conversions) and is freed exactly once here.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Create one pipe instance with the owner-only DACL. The descriptor's owner is
/// always the creating process's own user SID (the only owner a non-elevated
/// process may set); `dacl_sid` is the single grantee.
fn create_instance(name: &str, dacl_sid: &str, first: bool) -> io::Result<NamedPipeServer> {
    let owner = current_user_sid()?;
    let sddl: Vec<u16> = OsStr::new(&owner_only_sddl(&owner, dacl_sid))
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the call;
    // `descriptor` is a valid out-pointer; the size out-pointer may be null.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte)
        .access_inbound(true)
        .access_outbound(true);
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor
    // (`descriptor`, freed only when this function returns) outlives the call;
    // CreateNamedPipeW copies the descriptor into the kernel object.
    unsafe {
        options.create_with_security_attributes_raw(name, (&raw mut attributes).cast::<c_void>())
    }
}

/// `GetFullPathNameW` normalization, then the pipe-namespace rule. Returns the
/// normalized path to open, or `None` (refuse without opening).
fn normalized_pipe_path(path: &Path) -> Option<OsString> {
    let full = full_path_name(path.as_os_str())?;
    let text = String::from_utf16(&full).ok()?;
    let lower = text.to_ascii_lowercase();
    let prefix = PIPE_PREFIXES.iter().find(|p| lower.starts_with(**p))?;
    let rest = &text[prefix.len()..];
    if rest.is_empty() || rest.split('\\').any(|c| c == "." || c == "..") {
        return None;
    }
    Some(OsString::from_wide(&full))
}

/// `GetFullPathNameW` (pure string normalization; never opens anything).
fn full_path_name(path: &OsStr) -> Option<Vec<u16>> {
    let mut wide: Vec<u16> = path.encode_wide().collect();
    if wide.is_empty() || wide.contains(&0) {
        return None;
    }
    wide.push(0);
    let mut buffer: Vec<u16> = vec![0; 260];
    loop {
        let capacity = u32::try_from(buffer.len()).ok()?;
        // SAFETY: `wide` is NUL-terminated; `buffer` holds `capacity` u16s; the
        // file-part out-pointer may be null.
        let written = unsafe {
            GetFullPathNameW(
                wide.as_ptr(),
                capacity,
                buffer.as_mut_ptr(),
                ptr::null_mut(),
            )
        };
        if written == 0 {
            return None;
        }
        if written < capacity {
            buffer.truncate(written as usize);
            return Some(buffer);
        }
        // `written` is the required size including the terminator.
        if written > MAX_PATH_UNITS {
            return None;
        }
        buffer.resize(written as usize, 0);
    }
}

/// `GetFileType` of an open handle (`FILE_TYPE_UNKNOWN` = 0 on error).
fn handle_file_type(handle: RawHandle) -> u32 {
    // SAFETY: the caller's object owns `handle` and keeps it open for the call;
    // GetFileType only queries the device type.
    unsafe { GetFileType(handle as HANDLE) }
}

/// Owner SID (string form) of the object behind an open handle: `GetSecurityInfo`
/// with `OWNER_SECURITY_INFORMATION` (needs `READ_CONTROL`, which the client's
/// `GENERIC_READ` open includes), then `ConvertSidToStringSidW`.
fn handle_owner_sid(handle: RawHandle) -> io::Result<String> {
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the caller's object owns `handle` and keeps it open for the call; the
    // owner and descriptor out-pointers are valid for writes; group, DACL and SACL
    // are not requested, so their out-pointers may be null.
    let rc = unsafe {
        GetSecurityInfo(
            handle as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(i32::MAX),
        ));
    }
    // GetSecurityInfo allocated the descriptor with LocalAlloc; `owner` points into
    // it, so the allocation must outlive the conversion below.
    let descriptor = LocalAllocation(descriptor);
    if owner.is_null() {
        return Err(io::Error::other(
            "endpoint security descriptor has no owner",
        ));
    }
    let sid = sid_to_string(owner);
    drop(descriptor);
    sid
}

/// Client process ID (metadata only, spec §4.2).
fn client_pid(server: &NamedPipeServer) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: the server owns the handle for the duration of the call; `pid` is a
    // valid out-pointer.
    let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut pid) };
    (ok != 0).then_some(pid)
}

/// Impersonate the pipe client, open the thread token, and revert.
///
/// Invariant: no code path leaves this function while impersonating. The calls run
/// on one OS thread with no `.await` in between. If `RevertToSelf` fails the thread
/// would keep the client's identity; the process aborts rather than continue
/// (Microsoft's guidance for a failed revert).
fn open_client_token(pipe: RawHandle) -> Result<OwnedHandle, PeerRejected> {
    // SAFETY: `pipe` is a connected server handle owned by the caller for the call.
    if unsafe { ImpersonateNamedPipeClient(pipe as HANDLE) } == 0 {
        tracing::debug!(
            os_error = io::Error::last_os_error().raw_os_error(),
            "ImpersonateNamedPipeClient failed"
        );
        return Err(PeerRejected::Unavailable);
    }
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentThread is a pseudo-handle; `raw` is a valid out-pointer.
    // OpenAsSelf = TRUE checks access against the process token, so the client's
    // (identification-level) token can be opened for TOKEN_QUERY.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    let open_error = io::Error::last_os_error().raw_os_error();
    // SAFETY: plain call; ends the impersonation started above on this thread.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    if opened == 0 {
        tracing::debug!(os_error = open_error, "OpenThreadToken failed");
        return Err(PeerRejected::Unavailable);
    }
    // SAFETY: OpenThreadToken succeeded, so `raw` is a token handle we now own.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

/// `GetTokenInformation` into an 8-byte-aligned buffer.
fn token_information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let handle = token.as_raw_handle() as HANDLE;
    let mut needed = 0u32;
    // SAFETY: size query: null buffer with length 0 and a valid out-pointer; the
    // call fails with ERROR_INSUFFICIENT_BUFFER and reports the size.
    unsafe { GetTokenInformation(handle, class, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed > MAX_TOKEN_INFO_BYTES {
        return Err(io::Error::other("token information size unavailable"));
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    let mut written = 0u32;
    // SAFETY: `buffer` holds at least `needed` bytes, is 8-byte aligned (enough for
    // TOKEN_USER), and outlives the call.
    let ok = unsafe {
        GetTokenInformation(
            handle,
            class,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut written,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

/// The token's user SID as a string.
fn token_user_sid(token: &OwnedHandle) -> io::Result<String> {
    let buffer = token_information(token, TokenUser)?;
    // SAFETY: GetTokenInformation(TokenUser) filled `buffer` with a TOKEN_USER whose
    // SID pointer points inside `buffer`, which stays alive across the conversion.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_to_string(sid)
}

/// Whether the pipe client connected over the network (`ERROR_PIPE_LOCAL` means
/// local). Any other failure is treated as "cannot tell" and refused.
fn connection_is_remote(pipe: RawHandle) -> Result<bool, PeerRejected> {
    let mut name = [0u16; 256];
    // The length argument counts UTF-16 characters, not bytes (review B05).
    let capacity = utf16_capacity(&name).ok_or(PeerRejected::Unavailable)?;
    // SAFETY: `pipe` is a connected server handle owned by the caller for the call;
    // `name` provides writable storage for `capacity` UTF-16 units (`name.len()`,
    // the unit the API's length parameter counts), which outlives the call.
    let ok =
        unsafe { GetNamedPipeClientComputerNameW(pipe as HANDLE, name.as_mut_ptr(), capacity) };
    if ok != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error().raw_os_error();
    if error == Some(ERROR_PIPE_LOCAL as i32) {
        return Ok(false);
    }
    tracing::debug!(os_error = error, "GetNamedPipeClientComputerNameW failed");
    Err(PeerRejected::Unavailable)
}

/// The capacity of a UTF-16 buffer in characters (`u16` units), as the `u32`
/// length Win32 wide-string APIs take; `None` if it does not fit (fail closed).
fn utf16_capacity(buffer: &[u16]) -> Option<u32> {
    u32::try_from(buffer.len()).ok()
}

/// `ConvertSidToStringSidW`.
fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` points at a valid SID inside a buffer the caller keeps alive for
    // the call (a token-information buffer or a security descriptor); `text` is a
    // valid out-pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation(text.cast::<c_void>());
    let mut len = 0usize;
    // SAFETY: on success `text` is a NUL-terminated UTF-16 string owned by
    // `allocation`; the scan is bounded and stops at the terminator.
    while len <= MAX_SID_STRING_CHARS && unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    if len > MAX_SID_STRING_CHARS {
        return Err(io::Error::other("SID string too long"));
    }
    // SAFETY: the first `len` units were just read as initialized and non-NUL.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    let sid = String::from_utf16(units).map_err(|_| io::Error::other("SID string not UTF-16"));
    drop(allocation);
    sid
}

#[cfg(test)]
mod tests {
    //! Native Windows tests (M01-U6w; server-owner check M01-U6b). They run only on
    //! a Windows host (`cargo test -p heimdall-ipc` there, or the cross-built test
    //! binary; see tests/native/windows-ipc/README.md). Pipe names use the test
    //! prefix `hm-M01-U6w-<pid>-<n>`; temporary files live under `%TEMP%`.

    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use heimdall_contract::ipc::PrincipalInfo;
    use heimdall_testkit::{CANARY_PREFIX, assert_no_canary};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    use super::*;

    /// A well-formed SID that is not the test user (synthetic; no real account).
    const OTHER_SID: &str = "S-1-5-21-1000000001-1000000002-1000000003-1001";

    /// Synthetic canary carried through the pipe, built per run (never committed
    /// as a value); it must never appear in any error or debug text the tests
    /// produce.
    fn canary() -> String {
        format!("{CANARY_PREFIX}u6w_pipe_{:x}", std::process::id())
    }

    fn unique_pipe(tag: &str) -> String {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\hm-M01-U6w-{}-{n}-{tag}", std::process::id())
    }

    /// Review B05: `GetNamedPipeClientComputerNameW` takes the buffer length in
    /// UTF-16 characters; the capacity passed is the element count, never the
    /// byte size (which would advertise twice the real storage).
    #[test]
    fn client_computer_name_capacity_counts_utf16_units() {
        let name = [0u16; 256];
        assert_eq!(utf16_capacity(&name), Some(256));
        assert_ne!(
            utf16_capacity(&name).map(|c| c as usize),
            Some(size_of_val(&name)),
            "a byte count is not a character count"
        );
        assert_eq!(utf16_capacity(&[]), Some(0));
    }

    /// Pipe DACL as SDDL, read from an open handle.
    fn dacl_sddl(handle: RawHandle) -> String {
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: valid handle for the call; only the DACL and descriptor
        // out-pointers are requested.
        let rc = unsafe {
            GetSecurityInfo(
                handle as HANDLE,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(rc, 0, "GetSecurityInfo failed");
        let _descriptor = LocalAllocation(descriptor);
        let mut text: *mut u16 = ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: `descriptor` is valid until `_descriptor` drops; out-pointers valid.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut len,
            )
        };
        assert_ne!(ok, 0, "SDDL conversion failed");
        let _text = LocalAllocation(text.cast());
        // SAFETY: `len` UTF-16 units including the terminator were written.
        let units = unsafe { std::slice::from_raw_parts(text, len as usize) };
        String::from_utf16_lossy(units)
            .trim_end_matches('\0')
            .to_owned()
    }

    #[test]
    fn sid_string_validation_rejects_aliases_and_injection() {
        assert!(is_sid_string("S-1-5-21-1-2-3-1001"));
        assert!(is_sid_string("S-1-12-1-1-2-3-4"));
        assert!(is_sid_string(OTHER_SID));
        for bad in [
            "",
            "WD",
            "BA",
            "S-1-",
            "S-1-5",
            "s-1-5-21-1",
            "S-1-5-21-1)(A;;GA;;;WD",
            "S-1-5--21",
            "S-1-5-21-1 ",
            "S-1-5-21-123456789012345678901",
        ] {
            assert!(!is_sid_string(bad), "accepted {bad:?}");
        }
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2", "S-1-5-21-1-2"),
            "O:S-1-5-21-1-2D:P(A;;GA;;;S-1-5-21-1-2)"
        );
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2", "S-1-5-32-545"),
            "O:S-1-5-21-1-2D:P(A;;GA;;;S-1-5-32-545)"
        );
    }

    #[test]
    fn current_user_sid_is_a_literal_sid() {
        let sid = current_user_sid().unwrap();
        assert!(is_sid_string(&sid), "not a SID string");
    }

    #[test]
    fn classify_path_namespace_rules() {
        use PathClass::{NotPipe, PipeNamespace};
        let cases: [(&str, PathClass); 14] = [
            (r"\\.\pipe\hm-M01-U6w-x", PipeNamespace),
            (r"\\.\PIPE\hm-M01-U6w-x", PipeNamespace),
            (r"\\?\pipe\hm-M01-U6w-x", PipeNamespace),
            ("//./pipe/hm-M01-U6w-x", PipeNamespace),
            (r"\\.\pipe\a\..\hm-M01-U6w-x", PipeNamespace),
            (r"\\.\pipe\", NotPipe),
            (r"\\.\pipe", NotPipe),
            (r"\\?\pipe\..\hm-M01-U6w-x", NotPipe),
            (r"\\.\pipe\..\C:\Windows\win.ini", NotPipe),
            (r"\\localhost\pipe\hm-M01-U6w-x", NotPipe),
            (r"\\.\GLOBALROOT\Device\NamedPipe\hm-M01-U6w-x", NotPipe),
            ("NUL", NotPipe),
            (r"C:\Windows", NotPipe),
            ("relative-name", NotPipe),
        ];
        for (path, expected) in cases {
            assert_eq!(classify_path(Path::new(path)), expected, "{path}");
        }
        assert_eq!(classify_path(Path::new("")), NotPipe);
        assert_eq!(classify_path(Path::new("a\0b")), NotPipe);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_user_connect_reports_owner_sid_and_owner_only_dacl() {
        let sid = current_user_sid().unwrap();
        let canary = canary();
        let name = unique_pipe("control");
        let listener = Listener::bind(&name, EndpointKind::Control, &sid).unwrap();
        assert_eq!(listener.kind(), EndpointKind::Control);

        for round in 0..2 {
            // The client writes first, as every client of both endpoints does;
            // identification waits for that write (W6).
            let (accepted, client) = tokio::join!(listener.accept(), async {
                let mut client = connect(Path::new(&name)).await?;
                client.write_all(canary.as_bytes()).await?;
                io::Result::Ok(client)
            });
            let (mut server, peer) = accepted.unwrap();
            let mut client = client.unwrap();
            assert_eq!(
                peer,
                PeerIdentity::Windows {
                    sid: sid.clone(),
                    pid: Some(std::process::id()),
                },
                "round {round}"
            );
            assert_eq!(
                verify_peer(&peer, &ExpectedOwner::Sid(sid.clone())).unwrap(),
                PrincipalInfo::OsUserWindows { sid: sid.clone() }
            );
            assert_eq!(client_sid(&server).unwrap(), sid);
            assert_eq!(connection_is_remote(server.as_raw_handle()), Ok(false));

            // Both directions carry bytes unchanged.
            let mut got = vec![0u8; canary.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, canary.as_bytes());
            server.write_all(b"pong").await.unwrap();
            let mut pong = [0u8; 4];
            client.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");

            // The instance carries exactly the protected owner-only DACL.
            assert_eq!(
                dacl_sddl(client.as_raw_handle()),
                format!("D:P(A;;FA;;;{sid})")
            );
            assert_no_canary(&format!("{listener:?} {peer:?}"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_pipe_endpoints_refused_before_any_open() {
        let dir = tempfile::Builder::new()
            .prefix("hm-M01-U6w spaced ü-")
            .tempdir()
            .unwrap();
        let file = dir.path().join("endpoint fïle.bin");
        let content: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        fs::File::create(&file)
            .unwrap()
            .write_all(&content)
            .unwrap();
        let mtime = fs::metadata(&file).unwrap().modified().unwrap();
        let subdir = dir.path().join("endpoint dir");
        fs::create_dir(&subdir).unwrap();

        // Exclusive handles (share mode 0): any data open of these paths would
        // fail with a sharing violation instead of the classification refusal.
        let hold_file = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&file)
            .unwrap();
        let hold_dir = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&subdir)
            .unwrap();

        let escape = {
            let text = file.to_str().unwrap();
            PathBuf::from(format!(r"\\.\pipe\..\{text}"))
        };
        let candidates: Vec<PathBuf> = vec![
            file.clone(),
            subdir.clone(),
            PathBuf::from("NUL"),
            PathBuf::from(r"\\.\NUL"),
            escape,
            dir.path().join("missing"),
        ];
        for path in &candidates {
            assert_eq!(classify_path(path), PathClass::NotPipe);
            let err = connect(path).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
            assert_eq!(err.raw_os_error(), None, "an open was attempted: {err}");
            assert_no_canary(&err.to_string());
        }
        drop(hold_file);
        drop(hold_dir);

        assert_eq!(fs::read(&file).unwrap(), content);
        assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), mtime);
        assert!(fs::metadata(&subdir).unwrap().is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_pipe_is_not_found() {
        let err = connect(Path::new(&unique_pipe("absent")))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn existing_name_makes_bind_fail_first_instance() {
        let sid = current_user_sid().unwrap();

        // Our own listener already holds the name.
        let name = unique_pipe("control");
        let _first = Listener::bind(&name, EndpointKind::Control, &sid).unwrap();
        let err = Listener::bind(&name, EndpointKind::Control, &sid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");

        // A squatter pre-created the name (default DACL, no first-instance flag).
        let name = unique_pipe("signing");
        let squatter = ServerOptions::new().create(&name).unwrap();
        let err = Listener::bind(&name, EndpointKind::Signing, &sid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        // The squatter's pipe is untouched: a client still reaches it.
        let (connected, client) = tokio::join!(squatter.connect(), async {
            ClientOptions::new().open(&name)
        });
        connected.unwrap();
        client.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bind_refuses_non_pipe_names_and_non_sid_owners() {
        let sid = current_user_sid().unwrap();
        let err = Listener::bind(r"C:\hm-M01-U6w", EndpointKind::Control, &sid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        for owner in ["WD", "S-1-5-21-1)(A;;GA;;;WD", ""] {
            let err =
                Listener::bind(&unique_pipe("control"), EndpointKind::Control, owner).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{owner:?}");
        }
    }

    #[test]
    fn bind_outside_runtime_errors_instead_of_panicking() {
        let sid = current_user_sid().unwrap();
        let err = Listener::bind(&unique_pipe("control"), EndpointKind::Control, &sid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    /// The DACL alone keeps out a principal it does not list: with the instance
    /// granted only to another SID, this user's open is denied by the kernel.
    /// (The true cross-user case needs a second Windows account: blocked.)
    #[tokio::test(flavor = "current_thread")]
    async fn dacl_denies_unlisted_principal() {
        let name = unique_pipe("control");
        let _listener =
            Listener::bind_inner(&name, EndpointKind::Control, OTHER_SID, OTHER_SID).unwrap();
        let err = connect(Path::new(&name)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
    }

    /// The post-connect SID check: a client the DACL admits but whose SID is not the
    /// expected owner is disconnected, never returned, and the listener keeps an
    /// instance waiting.
    #[tokio::test(flavor = "current_thread")]
    async fn sid_mismatch_is_disconnected_and_listener_keeps_waiting() {
        let sid = current_user_sid().unwrap();
        let name = unique_pipe("control");
        let listener = Listener::bind_inner(&name, EndpointKind::Control, OTHER_SID, &sid).unwrap();
        let (accepted, client_read) = tokio::join!(
            tokio::time::timeout(Duration::from_millis(1500), listener.accept()),
            async {
                let mut client = connect(Path::new(&name)).await?;
                // Write first so the SID check runs (W6), then see the refusal.
                client.write_all(&FIRST_FRAME).await?;
                let mut byte = [0u8; 1];
                client.read(&mut byte).await
            }
        );
        assert!(accepted.is_err(), "a mismatched peer was returned");
        match client_read {
            Ok(n) => assert_eq!(n, 0, "refused client received data"),
            // The server's DisconnectNamedPipe surfaces as ERROR_PIPE_NOT_CONNECTED
            // (or ERROR_BROKEN_PIPE when the instance is closed first).
            Err(err) => assert!(
                [
                    Some(ERROR_PIPE_NOT_CONNECTED as i32),
                    Some(ERROR_BROKEN_PIPE as i32)
                ]
                .contains(&err.raw_os_error()),
                "{err}"
            ),
        }
        // A replacement instance exists, so the name still answers.
        let again = connect(Path::new(&name)).await;
        assert!(again.is_ok(), "no instance left after refusal");
    }

    /// E14: a same-user server is accepted under both expectations, the owner read
    /// back from the client handle is this user's SID, and bytes flow.
    #[tokio::test(flavor = "current_thread")]
    async fn connect_with_owner_accepts_a_same_user_server() {
        let sid = current_user_sid().unwrap();
        let name = unique_pipe("control");
        let listener = Listener::bind(&name, EndpointKind::Control, &sid).unwrap();
        for owner in [ServerOwner::CurrentUser, ServerOwner::Sid(sid.clone())] {
            let (accepted, client) = tokio::join!(listener.accept(), async {
                let mut client = connect_with_owner(Path::new(&name), owner.clone()).await?;
                client.write_all(b"ping").await?;
                io::Result::Ok(client)
            });
            let (mut server, peer) = accepted.unwrap();
            let client = client.unwrap_or_else(|e| panic!("{owner:?}: {e}"));
            assert_eq!(handle_owner_sid(client.as_raw_handle()).unwrap(), sid);
            assert!(matches!(peer, PeerIdentity::Windows { .. }));
            let mut got = [0u8; 4];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ping");
        }
    }

    /// E14: our own pipe, but the client expects another (synthetic) owner: refused
    /// by the owner comparison itself (no OS error), and the listener still serves
    /// a correctly-expecting client afterwards. The real cross-user case (a pipe
    /// created by a second account) is blocked: README "Not covered".
    #[tokio::test(flavor = "current_thread")]
    async fn connect_with_owner_refuses_an_unexpected_owner() {
        let sid = current_user_sid().unwrap();
        let name = unique_pipe("control");
        let listener = Listener::bind(&name, EndpointKind::Control, &sid).unwrap();
        let err = connect_with_owner(Path::new(&name), ServerOwner::Sid(OTHER_SID.into()))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert_eq!(err.raw_os_error(), None, "not the owner check: {err}");
        assert!(!err.to_string().contains(&sid), "error text names a SID");
        let (accepted, client) = tokio::join!(listener.accept(), async {
            let mut client = connect_with_owner(Path::new(&name), ServerOwner::CurrentUser).await?;
            client.write_all(&FIRST_FRAME).await?;
            io::Result::Ok(client)
        });
        accepted.unwrap();
        client.unwrap();
    }

    /// A valid first frame on the signing endpoint: ssh-agent `REQUEST_IDENTITIES`.
    const FIRST_FRAME: [u8; 5] = [0, 0, 0, 1, 11];

    /// How a test client opens the pipe.
    #[derive(Debug, Clone, Copy)]
    enum ClientOpen {
        /// `CreateFileW` without `SECURITY_SQOS_PRESENT` (testkit's
        /// `AgentConnection`, and any ssh client that opens the agent pipe with
        /// default flags): the server can impersonate only after a read.
        DefaultFlags,
        /// `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, as [`connect`] opens.
        Identification,
    }

    /// A blocking client on its own thread: open (retrying `ERROR_PIPE_BUSY`), wait
    /// `delay`, write `payload` (nothing when empty), then read once. Returns what
    /// the read produced (`Ok(empty)` on end of stream), or the open/write/read
    /// error.
    fn spawn_client(
        name: &str,
        open: ClientOpen,
        delay: Duration,
        payload: Vec<u8>,
    ) -> std::thread::JoinHandle<io::Result<Vec<u8>>> {
        use std::io::Read as _;
        let name = name.to_owned();
        std::thread::spawn(move || {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            if let ClientOpen::Identification = open {
                options.security_qos_flags(SECURITY_IDENTIFICATION);
            }
            let mut attempts = 0;
            let mut pipe = loop {
                match options.open(&name) {
                    Ok(pipe) => break pipe,
                    Err(err)
                        if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempts < 80 =>
                    {
                        attempts += 1;
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(err) => return Err(err),
                }
            };
            std::thread::sleep(delay);
            if !payload.is_empty() {
                pipe.write_all(&payload)?;
            }
            let mut reply = vec![0u8; 16];
            let n = pipe.read(&mut reply)?;
            reply.truncate(n);
            Ok(reply)
        })
    }

    async fn join_client(
        client: std::thread::JoinHandle<io::Result<Vec<u8>>>,
    ) -> io::Result<Vec<u8>> {
        tokio::task::spawn_blocking(move || client.join().unwrap())
            .await
            .unwrap()
    }

    /// W6 regression: a same-user client that opens, pauses 200 ms, then writes its
    /// first frame is accepted with the owner SID, and its bytes reach the caller
    /// unchanged and in order (including a first write larger than one internal
    /// read buffer). Before the fix the listener impersonated right after
    /// `ConnectNamedPipe`, before any data had been read, and a default-flags
    /// client was refused with `ERROR_CANNOT_IMPERSONATE` (1368) and disconnected.
    #[tokio::test(flavor = "current_thread")]
    async fn client_that_writes_late_is_accepted_with_bytes_intact() {
        let sid = current_user_sid().unwrap();
        let large: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        for open in [ClientOpen::DefaultFlags, ClientOpen::Identification] {
            for payload in [FIRST_FRAME.to_vec(), large.clone()] {
                let name = unique_pipe("signing");
                let listener = Listener::bind(&name, EndpointKind::Signing, &sid).unwrap();
                let client = spawn_client(&name, open, Duration::from_millis(200), payload.clone());
                let accepted = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                    .await
                    .unwrap_or_else(|_| panic!("{open:?}: late-writing client not accepted"));
                let (mut server, peer) = accepted.unwrap();
                assert_eq!(
                    peer,
                    PeerIdentity::Windows {
                        sid: sid.clone(),
                        pid: Some(std::process::id()),
                    },
                    "{open:?}"
                );
                let mut got = vec![0u8; payload.len()];
                tokio::time::timeout(Duration::from_secs(2), server.read_exact(&mut got))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(got == payload, "{open:?}: first bytes changed");
                server.write_all(b"ok").await.unwrap();
                assert_eq!(join_client(client).await.unwrap(), b"ok", "{open:?}");
            }
        }
    }

    /// W6: a client that connects and stays silent does not hold up `accept` for a
    /// client that writes promptly; the prompt client is returned well inside the
    /// identification bound, and it is the prompt client (its bytes), not the
    /// silent one.
    #[tokio::test(flavor = "current_thread")]
    async fn silent_client_does_not_block_a_prompt_client() {
        let sid = current_user_sid().unwrap();
        for open in [ClientOpen::DefaultFlags, ClientOpen::Identification] {
            let name = unique_pipe("signing");
            let listener = Listener::bind(&name, EndpointKind::Signing, &sid).unwrap();
            let silent = spawn_client(&name, open, Duration::ZERO, Vec::new());
            // Let the silent client take the first instance before the prompt one.
            let early = tokio::time::timeout(Duration::from_millis(150), listener.accept()).await;
            assert!(early.is_err(), "{open:?}: a silent client was returned");
            let started = std::time::Instant::now();
            let prompt = spawn_client(&name, open, Duration::ZERO, FIRST_FRAME.to_vec());
            let (mut server, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap_or_else(|_| panic!("{open:?}: prompt client blocked"))
                .unwrap();
            let mut got = [0u8; FIRST_FRAME.len()];
            tokio::time::timeout(Duration::from_secs(1), server.read_exact(&mut got))
                .await
                .unwrap_or_else(|_| panic!("{open:?}: the silent client was returned"))
                .unwrap();
            assert_eq!(got, FIRST_FRAME, "{open:?}");
            assert!(started.elapsed() < Duration::from_secs(2), "{open:?}");
            server.write_all(b"ok").await.unwrap();
            assert_eq!(join_client(prompt).await.unwrap(), b"ok", "{open:?}");
            // Closing the listener ends the silent client's connection too.
            drop(server);
            drop(listener);
            let silent = tokio::time::timeout(Duration::from_secs(10), join_client(silent))
                .await
                .unwrap_or_else(|_| panic!("{open:?}: silent client never released"));
            assert!(
                matches!(&silent, Ok(bytes) if bytes.is_empty()) || silent.is_err(),
                "{open:?}: silent client received data"
            );
        }
    }

    /// When a silent client thread opened the pipe and when its one read ended.
    struct SilentRun {
        /// Just before the successful open: the listener's connect, and so its bound,
        /// cannot start earlier.
        before_open: std::time::Instant,
        /// Just after the open returned.
        opened: std::time::Instant,
        /// Just after the read returned (end of stream or the disconnect error).
        eof: std::time::Instant,
        read: io::Result<usize>,
    }

    /// A blocking client that opens the pipe, writes nothing and reads once, timing
    /// the open and the end of its read ([`SilentRun`]).
    fn spawn_silent_client(name: &str, open: ClientOpen) -> std::thread::JoinHandle<SilentRun> {
        use std::io::Read as _;
        let name = name.to_owned();
        std::thread::spawn(move || {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            if let ClientOpen::Identification = open {
                options.security_qos_flags(SECURITY_IDENTIFICATION);
            }
            let mut attempts = 0;
            let (before_open, mut pipe) = loop {
                let before_open = std::time::Instant::now();
                match options.open(&name) {
                    Ok(pipe) => break (before_open, pipe),
                    Err(err)
                        if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempts < 80 =>
                    {
                        attempts += 1;
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(err) => panic!("{open:?}: the silent client could not open: {err}"),
                }
            };
            let opened = std::time::Instant::now();
            let mut byte = [0u8; 16];
            let read = pipe.read(&mut byte);
            SilentRun {
                before_open,
                opened,
                eof: std::time::Instant::now(),
                read,
            }
        })
    }

    /// Join a client thread without blocking the runtime, within `limit`; `None` when
    /// it is still running then (the thread is left to end with its connection).
    async fn join_within<T>(client: std::thread::JoinHandle<T>, limit: Duration) -> Option<T> {
        let deadline = std::time::Instant::now() + limit;
        while !client.is_finished() {
            if std::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Some(client.join().unwrap())
    }

    /// W6 bound (wave-6w review W6W-R03): a client that stays silent is disconnected
    /// at the first-write bound, neither before it nor long after it, is never
    /// returned as verified, and the listener still serves the next client. The
    /// client's end of stream is observed while `accept` runs, so the time measured
    /// is the disconnect's, not `accept`'s (which keeps waiting after a refusal).
    #[tokio::test(flavor = "current_thread")]
    async fn silent_client_is_refused_after_the_bound_and_listener_keeps_waiting() {
        let sid = current_user_sid().unwrap();
        let bound = Duration::from_millis(400);
        // How late after the bound the disconnect may reach the client: scheduling and
        // the reactor's turn, on a loaded host.
        let allowance = Duration::from_millis(600);
        for open in [ClientOpen::DefaultFlags, ClientOpen::Identification] {
            let name = unique_pipe("control");
            let listener = Listener::bind(&name, EndpointKind::Control, &sid)
                .unwrap()
                .with_first_write_wait(bound);
            let silent = spawn_silent_client(&name, open);
            let (accepted, released) = tokio::join!(
                tokio::time::timeout(bound + allowance, listener.accept()),
                join_within(silent, bound + allowance + Duration::from_secs(2)),
            );
            assert!(accepted.is_err(), "{open:?}: a silent client was returned");
            let run = released
                .unwrap_or_else(|| panic!("{open:?}: the silent client was never disconnected"));
            match &run.read {
                Ok(n) => assert_eq!(*n, 0, "{open:?}: refused client got data"),
                Err(err) => assert!(
                    [
                        Some(ERROR_PIPE_NOT_CONNECTED as i32),
                        Some(ERROR_BROKEN_PIPE as i32)
                    ]
                    .contains(&err.raw_os_error()),
                    "{open:?}: {err}"
                ),
            }
            let earliest = run.eof.duration_since(run.before_open);
            let latest = run.eof.duration_since(run.opened);
            assert!(
                earliest >= bound,
                "{open:?}: disconnected before the bound ({earliest:?} < {bound:?})"
            );
            assert!(
                latest <= bound + allowance,
                "{open:?}: disconnected long after the bound ({latest:?})"
            );
            // An instance is still waiting: the next client is served.
            let prompt = spawn_client(&name, open, Duration::ZERO, FIRST_FRAME.to_vec());
            let (mut server, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap_or_else(|_| panic!("{open:?}: no instance left after refusal"))
                .unwrap();
            let mut got = [0u8; FIRST_FRAME.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, FIRST_FRAME, "{open:?}");
            server.write_all(b"ok").await.unwrap();
            let reply = join_within(prompt, Duration::from_secs(2))
                .await
                .unwrap_or_else(|| panic!("{open:?}: the prompt client never finished"));
            assert_eq!(reply.unwrap(), b"ok", "{open:?}");
        }
    }

    /// W6 cancel safety: an `accept` dropped while a connected client is still
    /// being identified loses nothing; the next `accept` returns that client, with
    /// its bytes, once it writes.
    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_accept_keeps_a_connection_being_identified() {
        let sid = current_user_sid().unwrap();
        let name = unique_pipe("signing");
        let listener = Listener::bind(&name, EndpointKind::Signing, &sid).unwrap();
        let client = spawn_client(
            &name,
            ClientOpen::DefaultFlags,
            Duration::from_millis(400),
            FIRST_FRAME.to_vec(),
        );
        // Connects, starts identifying, then is cancelled before the client writes.
        let first = tokio::time::timeout(Duration::from_millis(150), listener.accept()).await;
        assert!(first.is_err(), "returned before the client wrote");
        assert_eq!(listener.state.lock().await.identifying.len(), 1);
        let (mut server, peer) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("the connection was lost with the cancelled accept")
            .unwrap();
        assert!(matches!(peer, PeerIdentity::Windows { sid: ref s, .. } if *s == sid));
        let mut got = [0u8; FIRST_FRAME.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, FIRST_FRAME);
        server.write_all(b"ok").await.unwrap();
        assert_eq!(join_client(client).await.unwrap(), b"ok");
    }

    /// W6 bound on concurrent identifications: with the pending set full of silent
    /// clients, a further client is not lost; it is served once the silent ones
    /// time out, and the name keeps answering meanwhile.
    #[tokio::test(flavor = "current_thread")]
    async fn full_identification_set_defers_but_does_not_drop_new_clients() {
        let sid = current_user_sid().unwrap();
        let name = unique_pipe("signing");
        let listener = Listener::bind(&name, EndpointKind::Signing, &sid)
            .unwrap()
            .with_first_write_wait(Duration::from_millis(1500));
        let silent: Vec<_> = (0..MAX_PENDING_IDENTIFICATIONS)
            .map(|_| {
                spawn_client(
                    &name,
                    ClientOpen::Identification,
                    Duration::ZERO,
                    Vec::new(),
                )
            })
            .collect();
        let early = tokio::time::timeout(Duration::from_millis(1000), listener.accept()).await;
        assert!(early.is_err(), "a silent client was returned");
        assert_eq!(
            listener.state.lock().await.identifying.len(),
            MAX_PENDING_IDENTIFICATIONS
        );
        let prompt = spawn_client(
            &name,
            ClientOpen::DefaultFlags,
            Duration::ZERO,
            FIRST_FRAME.to_vec(),
        );
        let (mut server, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("the deferred client was never served")
            .unwrap();
        let mut got = [0u8; FIRST_FRAME.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, FIRST_FRAME);
        server.write_all(b"ok").await.unwrap();
        assert_eq!(join_client(prompt).await.unwrap(), b"ok");
        for client in silent {
            let released = join_client(client).await;
            assert!(
                matches!(&released, Ok(bytes) if bytes.is_empty()) || released.is_err(),
                "a silent client received data"
            );
        }
    }

    /// E14: an expectation that is not a literal SID, and a path outside the pipe
    /// namespace, are refused with `InvalidInput` before any open (the absent pipe
    /// would otherwise answer `NotFound`).
    #[tokio::test(flavor = "current_thread")]
    async fn connect_with_owner_refuses_bad_input_before_any_open() {
        let absent = unique_pipe("absent");
        for bad in ["", "WD", "BA", "S-1-5-21-1)(A;;GA;;;WD", "s-1-5-21-1-2"] {
            let err = connect_with_owner(Path::new(&absent), ServerOwner::Sid(bad.into()))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}: {err}");
            assert_eq!(err.raw_os_error(), None, "{bad:?}: {err}");
        }
        for path in ["NUL", r"\\.\pipe\..\C:\Windows\win.ini", r"C:\Windows"] {
            let err = connect_with_owner(Path::new(path), ServerOwner::CurrentUser)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{path}: {err}");
            assert_eq!(err.raw_os_error(), None, "{path}: {err}");
        }
        let err = connect_with_owner(Path::new(&absent), ServerOwner::CurrentUser)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }
}
