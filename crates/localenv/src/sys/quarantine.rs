//! U4's platform calls (ADR-0007 §12.15 item 9; owner W2-U4a): Windows `ReplaceFileW`
//! and handle identity, and the quarantine with the crate's only removal. Part of the
//! `sys` unsafe module; the inventory table is in `sys/mod.rs`.

use super::SysError;
use heimdall_domain::projection::FileIdentity;

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
