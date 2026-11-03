//! Single-instance runtime (spec §13.1 "On-demand service startup must be
//! single-instance"; R-RT-01).
//!
//! An advisory exclusive lock on `<state_dir>/service.lock` using
//! `std::fs::File::try_lock` (stable since Rust 1.89: `flock` on Unix,
//! `LockFileEx` on Windows). The lock is held for the process lifetime; the kernel
//! releases it on crash, so no stale PID file can keep a dead instance "running".
//! `instance.json` (pid, start time, endpoint locations, version) is written
//! *after* the endpoints are bound and validated by clients before use (spec §13.3
//! "Ephemeral socket paths and PIDs are rediscovered/validated").

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
        let Some(info) = Self::read_file(runtime_dir)? else {
            return Ok(None);
        };
        if !info.process_matches() {
            return Ok(None);
        }
        if !endpoints_connectable(runtime_dir, &info) {
            return Ok(None);
        }
        Ok(Some(info))
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

/// Unix: both advertised sockets must be exactly the runtime directory's
/// `control.sock`/`signing.sock` (an advertisement cannot redirect a client
/// elsewhere), be our own private sockets, and accept a connection (closed
/// immediately; the server drops a connection that sends no hello).
#[cfg(unix)]
fn endpoints_connectable(runtime_dir: &Path, info: &InstanceInfo) -> bool {
    use heimdall_ipc::unix::{PathFacts, check_own_socket, current_uid};
    use heimdall_ipc::{EndpointKind, EndpointPaths};

    let expected = EndpointPaths::for_runtime(runtime_dir, "");
    [
        (EndpointKind::Control, &info.control_endpoint),
        (EndpointKind::Signing, &info.signing_endpoint),
    ]
    .into_iter()
    .all(|(kind, advertised)| {
        let path = expected.path(kind);
        if Path::new(advertised) != path {
            return false;
        }
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return false;
        };
        check_own_socket(&PathFacts::of(&meta), current_uid()).is_ok()
            && std::os::unix::net::UnixStream::connect(path).is_ok()
    })
}

/// Windows: opening a pipe consumes a server instance, so liveness here rests on
/// the pid/start-time check; the client's `connect_with_owner` verifies the pipe
/// owner before any data (ADR-0006 §2.1). Names must be well-formed pipe paths.
#[cfg(not(unix))]
fn endpoints_connectable(_runtime_dir: &Path, info: &InstanceInfo) -> bool {
    [&info.control_endpoint, &info.signing_endpoint]
        .into_iter()
        .all(|p| p.starts_with(r"\\.\pipe\heimdall-"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
