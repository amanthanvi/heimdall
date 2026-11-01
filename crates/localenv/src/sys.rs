//! The third `unsafe` module (overview §9 item 3; ADR-0007 §13; m02-plan U0, U3, U4).
//!
//! **Skeleton (wave 0).** No `unsafe` block exists here yet. The module opts in now so
//! the inventory is fixed before U3 and U4 write the bodies; every call below is
//! wrapped in a safe function whose invariant is documented on it, and no `unsafe`
//! leaves this module. Nothing here is reachable in this build (m02-plan "Skeleton
//! rule"): every body is `todo!("M02-U3 …")` or `todo!("M02-U4 …")`.
//!
//! The atomic exchange and the no-replace rename on Unix do **not** live here: they
//! go through rustix's reviewed safe `fs::renameat_with` (Linux `renameat2`
//! `RENAME_EXCHANGE`/`RENAME_NOREPLACE`, macOS `renameatx_np` `RENAME_SWAP`/
//! `RENAME_EXCL`; m02-plan §6 P5, checked at rustix 1.1.6). Birth time comes from
//! rustix `statx` (`STATX_BTIME`) on Linux and `fstat` (`st_birthtimespec`) on
//! macOS, both safe.
//!
//! | Function | Platform | Call (planned) | Invariant |
//! |---|---|---|---|
//! | [`account_home`] | Unix | `getpwuid_r(getuid())` | the account database's home, never `$HOME` (ADR-0007 F19); buffer grown on `ERANGE`, bounded |
//! | [`account_home`] | Windows | `SHGetKnownFolderPath(FOLDERID_Profile)` | the returned string freed with `CoTaskMemFree` exactly once |
//! | [`killpg`] | Unix | `killpg(pgid, SIGKILL)` | only a process group this process created for a probe |
//! | [`JobObject`] | Windows | `CreateJobObjectW`, `SetInformationJobObject(KILL_ON_JOB_CLOSE)`, `AssignProcessToJobObject`, `CloseHandle` | no breakaway; the handle closed exactly once, which kills the job |
//! | [`replace_file`] | Windows | `ReplaceFileW` with a backup name | the backup keeps the displaced file's identity (`windows_replace_retains_displaced_identity_without_race`) |
//! | [`handle_identity`] | Windows | `GetFileInformationByHandleEx(FileIdInfo)` | volume serial and 128-bit file ID of an open handle |
//! | [`QuarantineDir::remove_verified`] | all | Unix: `openat` + `fstat`, then `unlinkat` relative to the quarantine's directory handle; Windows: `SetFileInformationByHandle(FileDispositionInfoEx)` on a handle whose identity was checked | **the only removal in the crate**: a name inside the validated `.hm-quarantine` directory, whose identity and digest equal the expected ones at removal (ADR-0007 §5.3) |
//! | [`adopt_inherited_fd`] | Unix | `fcntl(F_GETFD)`, `fstat`, `OwnedFd::from_raw_fd`, `fcntl(F_SETFD, FD_CLOEXEC)` | `run --meta-fd`: the descriptor is open, a pipe, socket or regular file, adopted once, close-on-exec (ADR-0007 §8; U8) |
#![allow(unsafe_code)]

use std::path::PathBuf;

use heimdall_domain::projection::FileIdentity;

/// A platform call failed. The message names the call, never a path's content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{call} failed: {detail}")]
pub struct SysError {
    /// The call.
    pub call: &'static str,
    /// The OS error, redacted.
    pub detail: String,
}

/// The account's home directory from the account database (ADR-0007 F19).
///
/// # Errors
/// [`SysError`].
pub fn account_home() -> Result<PathBuf, SysError> {
    todo!("M02-U3 sys::account_home")
}

/// Kill a probe's process group.
///
/// # Errors
/// [`SysError`].
#[cfg(unix)]
pub fn killpg(pgid: u32) -> Result<(), SysError> {
    let _ = pgid;
    todo!("M02-U3 sys::killpg")
}

/// A kill-on-close job object without breakaway (Windows probes).
#[cfg(windows)]
#[derive(Debug)]
pub struct JobObject {
    _private: (),
}

#[cfg(windows)]
impl JobObject {
    /// Create the job.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn kill_on_close() -> Result<Self, SysError> {
        todo!("M02-U3 sys::JobObject::kill_on_close")
    }

    /// Put a child in the job.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn assign(&self, pid: u32) -> Result<(), SysError> {
        let _ = pid;
        todo!("M02-U3 sys::JobObject::assign")
    }
}

/// Replace `target` by `replacement` in one directory, keeping the displaced file at
/// `backup` (Windows `ReplaceFileW`).
///
/// # Errors
/// [`SysError`].
#[cfg(windows)]
pub fn replace_file(
    dir: &std::path::Path,
    target: &str,
    replacement: &str,
    backup: &str,
) -> Result<(), SysError> {
    let _ = (dir, target, replacement, backup);
    todo!("M02-U4 sys::replace_file")
}

/// The identity of an open file (Windows: volume serial and 128-bit file ID).
///
/// # Errors
/// [`SysError`].
#[cfg(windows)]
pub fn handle_identity(file: &std::fs::File) -> Result<FileIdentity, SysError> {
    let _ = file;
    todo!("M02-U4 sys::handle_identity")
}

/// What a verified removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// The entry had the expected identity and digest and was removed.
    Removed,
    /// Nothing was at the name.
    Missing,
    /// The entry's identity differs: left in place.
    IdentityMismatch,
    /// The entry's content differs: left in place (`settle_conflict{modified}`).
    ContentMismatch,
}

/// A validated `.hm-quarantine` directory (owner only, mode 0700 or an owner-only
/// DACL, no symlink or reparse point, not a mount point). Opened by
/// `projection::replace::Quarantine`.
#[derive(Debug)]
pub struct QuarantineDir {
    _private: (),
}

impl QuarantineDir {
    /// Open (validating) or create the quarantine inside `parent`.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn open_or_create(parent: &std::path::Path) -> Result<Self, SysError> {
        let _ = parent;
        todo!("M02-U4 sys::QuarantineDir::open_or_create")
    }

    /// Remove `name` from the quarantine only if, at removal, it has
    /// `expected_identity` and its content hashes to `expected_sha256` (lowercase
    /// hex). The only removal in this crate.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn remove_verified(
        &self,
        name: &str,
        expected_identity: &FileIdentity,
        expected_sha256: &str,
    ) -> Result<RemoveOutcome, SysError> {
        let _ = (name, expected_identity, expected_sha256);
        todo!("M02-U4 sys::QuarantineDir::remove_verified")
    }

    /// Remove the quarantine directory itself when it is empty; never removes an
    /// entry.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn rmdir_if_empty(self) -> Result<bool, SysError> {
        todo!("M02-U4 sys::QuarantineDir::rmdir_if_empty")
    }
}

/// Adopt the descriptor `run --meta-fd <n>` names (Unix only; ADR-0007 §8).
///
/// # Errors
/// [`SysError`] when it is not open, or is not a pipe, socket or regular file.
#[cfg(unix)]
pub fn adopt_inherited_fd(raw: i32) -> Result<std::os::fd::OwnedFd, SysError> {
    let _ = raw;
    todo!("M02-U8 sys::adopt_inherited_fd")
}
