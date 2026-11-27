//! Single-instance runtime (spec §13.1 "On-demand service startup must be
//! single-instance"; R-RT-01).
//!
//! An advisory exclusive lock on `<state_dir>/service.lock` using
//! `std::fs::File::try_lock` (stable since Rust 1.89: `flock` on Unix,
//! `LockFileEx` on Windows). The lock is held for the process lifetime; the kernel
//! releases it on crash, so no stale PID file can keep a dead instance "running".
//! `instance.json` (pid, start time, endpoint locations, version and ⟨M07 S2-07⟩ the
//! environment ID a discovering client expects in the hello) is written
//! *after* the endpoints are bound and validated by clients before use (spec §13.3
//! "Ephemeral socket paths and PIDs are rediscovered/validated"). ⟨ADR-0014 H14⟩
//! [`InstanceInfo::read_advertised`] tells nothing advertised from advertised but not
//! answering.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Held for the lifetime of the service process.
#[derive(Debug)]
pub struct InstanceLock {
    _file: std::fs::File,
    path: PathBuf,
}

/// Why the lock was not acquired.
#[derive(Debug, thiserror::Error)]
pub enum InstanceError {
    /// Another instance holds the lock.
    #[error("another runtime instance is running")]
    AlreadyRunning,
    /// I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl InstanceLock {
    /// Try to become the single instance. Non-blocking.
    pub fn try_acquire(state_dir: &Path) -> Result<Self, InstanceError> {
        let path = state_dir.join("service.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file, path }),
            Err(std::fs::TryLockError::WouldBlock) => Err(InstanceError::AlreadyRunning),
            Err(std::fs::TryLockError::Error(e)) => Err(InstanceError::Io(e)),
        }
    }

    /// Lock file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Advertised instance record (no secrets; locations only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// Process ID (metadata; validated together with `started_at`).
    pub pid: u32,
    /// Process start time as reported by the OS, to defeat PID reuse (spec §4.2).
    pub started_at: String,
    /// Build version.
    pub version: String,
    /// Control endpoint location.
    pub control_endpoint: String,
    /// Signing endpoint location.
    pub signing_endpoint: String,
    /// ⟨M07 S2-07; ADR-0013 §8⟩ The runtime's environment ID: the **expected environment
    /// ID** a discovering client requires `ServerHello.environment_id` to equal. Always
    /// written by this build; absent from an advertisement written by an earlier build,
    /// which a client refuses (`SERVICE_UNAVAILABLE` / `endpoint_untrusted`), never
    /// trusts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
}

/// ⟨M07 S2-07; ADR-0014 H14⟩ What a runtime directory advertises ([`InstanceInfo::read_advertised`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advertised {
    /// Nothing usable is advertised: no file, an oversized or malformed one, or one whose
    /// process is gone or has another start time (PID reuse). `runtime_not_running`.
    NotRunning,
    /// The advertised process is live with its recorded start time, but its endpoint does
    /// not answer (Unix: an advertised socket that is ours refuses the connection).
    /// `runtime_unreachable`.
    Unreachable(InstanceInfo),
    /// The advertised process is live, but an advertised endpoint is not one a client may
    /// use: not this runtime directory's socket, a socket that is not ours, or (Windows) a
    /// control pipe not named `\\.\pipe\heimdall-<token>-control`. `endpoint_untrusted`.
    Untrusted(InstanceInfo),
    /// Live, and its endpoints pass the checks above (Unix: they accept a connection).
    /// Still only a hint: the client verifies the server on connect.
    Live(InstanceInfo),
}

/// ⟨M07 S2-07; ADR-0013 §8 (revision 7's pipe-name MUSTs)⟩ Whether `name` is exactly
/// `\\.\pipe\heimdall-<token>-control` with a non-empty token of ASCII letters, digits and
/// `-`, at least one of them a letter or digit (the runtime's tokens are CSPRNG hex after an
/// optional test prefix). No other spelling: not `\\?\pipe\`, no other case, no other
/// suffix (`-signing`, `-issuer`), no separator, dot or other character in the token. Pure;
/// checked on every platform.
#[must_use]
pub fn is_control_pipe_name(name: &str) -> bool {
    name.strip_prefix(r"\\.\pipe\heimdall-")
        .and_then(|rest| rest.strip_suffix("-control"))
        .is_some_and(|token| {
            token.bytes().any(|b| b.is_ascii_alphanumeric())
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// File name of the advertisement inside the runtime directory.
pub const INSTANCE_FILE: &str = "instance.json";

/// Largest `instance.json` read (bytes); anything larger is ignored as stale.
pub const MAX_INSTANCE_BYTES: u64 = 64 * 1024;

impl InstanceInfo {
    /// Process start time of the **current** process in the platform form used by
    /// [`crate::platform::process_start_time`]. `None` when the platform cannot
    /// report it (the advertisement then never validates: fail closed).
    #[must_use]
    pub fn current_started_at() -> Option<String> {
        crate::platform::process_start_time(std::process::id())
    }

    /// Write atomically (temp file + rename) into the runtime dir.
    ///
    /// The temporary file is created exclusively (`create_new`) with mode `0600`
    /// on Unix, written, `fsync`ed, then renamed over `instance.json`; the
    /// directory is `fsync`ed afterwards on Unix so the rename is durable. A
    /// reader therefore sees either the previous complete file or the new one.
    pub fn write(&self, runtime_dir: &Path) -> std::io::Result<()> {
        use std::io::Write as _;

        let text = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let target = runtime_dir.join(INSTANCE_FILE);
        let (tmp, mut file) = create_temp(runtime_dir)?;
        let result = (|| {
            file.write_all(&text)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp, &target)?;
            sync_dir(runtime_dir)
        })();
        if result.is_err() {
            // Remove only the temp file this call created.
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Read and validate (pid alive with matching start time, endpoints
    /// connectable).
    ///
    /// Returns `Ok(None)` (stale or absent, to be ignored and replaced) when the
    /// file is missing, oversized, malformed, names a process that is gone or
    /// whose start time differs (PID reuse, spec §4.2), or advertises an
    /// endpoint that is not ours or does not accept connections. Returns `Err`
    /// for I/O errors and for a file that is not a regular file owned by this
    /// user without group/other write access (never trusted, never silently
    /// replaced). A `Some` result is still only a hint: clients authenticate the
    /// server on connect (peer credentials / pipe owner, hello).
    pub fn read_valid(runtime_dir: &Path) -> std::io::Result<Option<Self>> {
        Ok(match Self::read_advertised(runtime_dir)? {
            Advertised::Live(info) => Some(info),
            Advertised::NotRunning | Advertised::Unreachable(_) | Advertised::Untrusted(_) => None,
        })
    }

    /// ⟨M07 S2-07; ADR-0014 H14⟩ [`read_valid`](Self::read_valid) without collapsing its
    /// `None`: nothing advertised, advertised but its endpoint not answering, advertised
    /// with an endpoint a client may not use, or live ([`Advertised`]). The same file
    /// checks and the same `Err` cases.
    pub fn read_advertised(runtime_dir: &Path) -> std::io::Result<Advertised> {
        let Some(info) = Self::read_file(runtime_dir)? else {
            return Ok(Advertised::NotRunning);
        };
        if !info.process_matches() {
            return Ok(Advertised::NotRunning);
        }
        Ok(match endpoints_state(runtime_dir, &info) {
            EndpointState::Answer => Advertised::Live(info),
            EndpointState::NotAnswering => Advertised::Unreachable(info),
            EndpointState::Untrusted => Advertised::Untrusted(info),
        })
    }

    /// Read and parse without liveness checks (`Ok(None)` for absent, oversized
    /// or malformed). Same ownership checks as [`read_valid`](Self::read_valid).
    #[doc(hidden)]
    pub fn read_file(runtime_dir: &Path) -> std::io::Result<Option<Self>> {
        use std::io::Read as _;

        let path = runtime_dir.join(INSTANCE_FILE);
        let file = match open_no_follow(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        check_owned_file(&meta)?;
        if meta.len() > MAX_INSTANCE_BYTES {
            return Ok(None);
        }
        let mut buf = Vec::new();
        file.take(MAX_INSTANCE_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_INSTANCE_BYTES {
            return Ok(None);
        }
        Ok(serde_json::from_slice(&buf).ok())
    }

    /// The advertised pid is alive and its OS start time equals `started_at`.
    fn process_matches(&self) -> bool {
        if self.started_at.is_empty() {
            return false;
        }
        crate::platform::process_start_time(self.pid).is_some_and(|s| s == self.started_at)
    }
}

/// Exclusive temp file next to the target (same directory, so `rename` is atomic).
fn create_temp(dir: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    let pid = std::process::id();
    for attempt in 0..16u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let tmp = dir.join(format!(".{INSTANCE_FILE}.{pid}.{nanos:x}.{attempt}.tmp"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a temporary instance file",
    ))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "instance.json is a link",
        ));
    }
    std::fs::File::open(path)
}

#[cfg(unix)]
fn check_owned_file(meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let ok = meta.file_type().is_file()
        && meta.uid() == heimdall_ipc::unix::current_uid()
        && meta.mode() & 0o022 == 0;
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "instance.json is not a private regular file owned by this user",
        ))
    }
}

#[cfg(not(unix))]
fn check_owned_file(meta: &std::fs::Metadata) -> std::io::Result<()> {
    if meta.file_type().is_file() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "instance.json is not a regular file",
        ))
    }
}

/// What the advertised endpoints allow ([`endpoints_state`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointState {
    /// Usable (Unix: both accept a connection).
    Answer,
    /// Ours and where they belong, but one refuses the connection. Unix only: Windows never
    /// opens a pipe here (an open consumes a server instance), so its client's connect
    /// reports a pipe that does not answer.
    #[cfg_attr(not(unix), allow(dead_code))]
    NotAnswering,
    /// Not where they belong, or not ours.
    Untrusted,
}

/// Unix: both advertised sockets must be exactly the runtime directory's
/// `control.sock`/`signing.sock` (an advertisement cannot redirect a client
/// elsewhere) and be our own private sockets (else `Untrusted`), and accept a
/// connection (closed immediately; the server drops a connection that sends no hello;
/// else `NotAnswering`).
#[cfg(unix)]
fn endpoints_state(runtime_dir: &Path, info: &InstanceInfo) -> EndpointState {
    use heimdall_ipc::unix::{PathFacts, check_own_socket, current_uid};
    use heimdall_ipc::{EndpointKind, EndpointPaths};

    let expected = EndpointPaths::for_runtime(runtime_dir, "");
    let mut state = EndpointState::Answer;
    for (kind, advertised) in [
        (EndpointKind::Control, &info.control_endpoint),
        (EndpointKind::Signing, &info.signing_endpoint),
    ] {
        let path = expected.path(kind);
        if Path::new(advertised) != path {
            return EndpointState::Untrusted;
        }
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if check_own_socket(&PathFacts::of(&meta), current_uid()).is_err() {
                    return EndpointState::Untrusted;
                }
            }
            Err(_) => {
                state = EndpointState::NotAnswering;
                continue;
            }
        }
        if std::os::unix::net::UnixStream::connect(path).is_err() {
            state = EndpointState::NotAnswering;
        }
    }
    state
}

/// Windows: opening a pipe consumes a server instance, so liveness here rests on
/// the pid/start-time check; the client's `connect_with_owner_verified` verifies the pipe
/// owner and its server process before any data (ADR-0006 §2.1; ADR-0013 §8). The control
/// pipe must be named exactly [`is_control_pipe_name`]; the signing locator (M01's pipe or
/// the managed environment endpoint) must be in Heimdall's pipe namespace.
#[cfg(not(unix))]
fn endpoints_state(_runtime_dir: &Path, info: &InstanceInfo) -> EndpointState {
    if is_control_pipe_name(&info.control_endpoint)
        && info.signing_endpoint.starts_with(r"\\.\pipe\heimdall-")
    {
        EndpointState::Answer
    } else {
        EndpointState::Untrusted
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// ⟨M07 S2-07⟩ The control pipe name: exactly `\\.\pipe\heimdall-<token>-control`.
    #[test]
    fn control_pipe_name_is_exact() {
        for good in [
            r"\\.\pipe\heimdall-x-control",
            r"\\.\pipe\heimdall-0123456789abcdef0123456789abcdef-control",
            r"\\.\pipe\heimdall-hm-test-0a1b-control",
        ] {
            assert!(is_control_pipe_name(good), "{good}");
        }
        for bad in [
            r"\\.\pipe\heimdall-x-signing",
            r"\\.\pipe\heimdall-x-issuer",
            r"\\.\pipe\heimdall-x",
            r"\\.\pipe\heimdall--control",
            r"\\.\pipe\heimdall---control",
            r"\\.\pipe\heimdall-control",
            r"\\.\pipe\other-x-control",
            r"\\.\pipe\Heimdall-x-control",
            r"\\.\PIPE\heimdall-x-control",
            r"\\?\pipe\heimdall-x-control",
            r"\\.\pipe\heimdall-x-control-control\..\heimdall-y-control",
            r"\\.\pipe\heimdall-x.y-control",
            r"\\.\pipe\heimdall-x/y-control",
            r"\\.\pipe\heimdall-x-CONTROL",
            r"\\.\pipe\heimdall-x-control ",
            r"\\server\pipe\heimdall-x-control",
            r"C:\pipe\heimdall-x-control",
            "",
        ] {
            assert!(!is_control_pipe_name(bad), "{bad}");
        }
    }

    #[test]
    fn second_acquire_fails_while_first_is_held() {
        let _serial = crate::spawn_guard();
        let dir = tempfile::tempdir().unwrap();
        let first = InstanceLock::try_acquire(dir.path()).unwrap();
        assert!(matches!(
            InstanceLock::try_acquire(dir.path()),
            Err(InstanceError::AlreadyRunning)
        ));
        drop(first);
        assert!(InstanceLock::try_acquire(dir.path()).is_ok());
    }
}
