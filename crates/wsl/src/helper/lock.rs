//! One helper per (distribution, account): an exclusive `flock` on
//! `<state_dir>/wsl-helper.lock` (design U3 §2).
//!
//! A helper whose runtime died sees EOF and exits, and its lock goes with it, so a new
//! helper's reconcile never runs beside an old writer. The lock file is opened with
//! `O_NOFOLLOW`, created `0600`, and checked to be a regular file this user owns.

use std::fs::File;
use std::path::Path;
use std::time::Duration;

/// How long a helper waits for the lock before it answers `busy`.
pub const LOCK_WAIT: Duration = Duration::from_secs(10);

/// The lock file's name inside the state directory.
pub const LOCK_FILE: &str = "wsl-helper.lock";

/// Why the lock was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    /// Another helper holds it for the whole wait.
    #[error("another helper holds the instance lock")]
    Busy,
    /// The file is not a safe lock file (a symlink, not ours, not a regular file, or
    /// readable by others).
    #[error("the instance lock file is not safe")]
    Unsafe,
    /// The OS refused.
    #[error("the instance lock is unavailable")]
    Unavailable,
}

/// A held instance lock; dropping it (or the process dying) releases it.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

/// Take the lock at `path`, retrying every 50 ms for up to `wait`.
///
/// # Errors
/// [`LockError`].
#[cfg(unix)]
pub fn acquire(path: &Path, wait: Duration) -> Result<InstanceLock, LockError> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::time::Instant;

    use rustix::fs::{FlockOperation, OFlags, flock};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .map_err(|_| LockError::Unsafe)?;
    let meta = file.metadata().map_err(|_| LockError::Unavailable)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(LockError::Unsafe);
    }
    let start = Instant::now();
    loop {
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(InstanceLock { _file: file }),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK => {
                if start.elapsed() >= wait {
                    return Err(LockError::Busy);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) if e == rustix::io::Errno::INTR => {}
            Err(_) => return Err(LockError::Unavailable),
        }
    }
}

/// The helper runs on Linux only.
///
/// # Errors
/// Always [`LockError::Unavailable`].
#[cfg(not(unix))]
pub fn acquire(_path: &Path, _wait: Duration) -> Result<InstanceLock, LockError> {
    Err(LockError::Unavailable)
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_second_holder_is_busy_and_a_symlink_is_unsafe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCK_FILE);
        let first = acquire(&path, Duration::from_millis(100)).unwrap();
        assert_eq!(
            acquire(&path, Duration::from_millis(120)).unwrap_err(),
            LockError::Busy
        );
        drop(first);
        drop(acquire(&path, Duration::from_millis(100)).unwrap());

        let link = dir.path().join("link.lock");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            acquire(&link, Duration::from_millis(100)).unwrap_err(),
            LockError::Unsafe
        );
    }
}
