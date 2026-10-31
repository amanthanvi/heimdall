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

impl InstanceInfo {
    /// Write atomically (temp file + rename) into the runtime dir.
    pub fn write(&self, _runtime_dir: &Path) -> std::io::Result<()> {
        todo!("M01-T05")
    }

    /// Read and validate (pid alive with matching start time, endpoints connectable).
    pub fn read_valid(_runtime_dir: &Path) -> std::io::Result<Option<Self>> {
        todo!("M01-T05")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_fails_while_first_is_held() {
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
