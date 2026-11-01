//! The run-record side channel (m02-plan U8; ADR-0007 §8 "Side channel").
//!
//! **Invariant: no `launching` record means not launched.** Heimdall execs or spawns
//! only after `launching` was written in full (fd: the whole line; file: written and
//! fsync'd). A failed `launching` write aborts the launch (`meta_unavailable`). No
//! record ever carries `argv`.

use std::path::Path;

use heimdall_contract::run_record::RunRecord;

/// Why the side channel cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetaError {
    /// `--meta-fd` is not open, or not a pipe, socket or regular file
    /// (`USAGE_ERROR` before `ensure`).
    #[error("meta descriptor unusable")]
    BadDescriptor,
    /// `--meta-file` exists (`USAGE_ERROR` before `ensure`).
    #[error("meta file exists")]
    Exists,
    /// A write failed (`meta_unavailable` for `launching`).
    #[error("meta write failed")]
    Write,
}

/// An open side channel.
#[derive(Debug)]
pub struct SideChannel {
    _private: (),
}

impl SideChannel {
    /// Adopt `--meta-fd <n>` (Unix only): `F_GETFD`, type check, `FD_CLOEXEC`
    /// (through `heimdall_localenv::sys::adopt_inherited_fd`).
    ///
    /// # Errors
    /// [`MetaError::BadDescriptor`].
    pub fn from_fd(fd: i32) -> Result<SideChannel, MetaError> {
        let _ = fd;
        todo!("M02-U8 meta::SideChannel::from_fd")
    }

    /// Create `--meta-file <path>` exclusively (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600, or an
    /// owner-only DACL).
    ///
    /// # Errors
    /// [`MetaError`].
    pub fn create_exclusive(path: &Path) -> Result<SideChannel, MetaError> {
        let _ = path;
        todo!("M02-U8 meta::SideChannel::create_exclusive")
    }

    /// Write one record as one NDJSON line (a file write is followed by fsync).
    ///
    /// # Errors
    /// [`MetaError::Write`].
    pub fn write(&mut self, record: &RunRecord) -> Result<(), MetaError> {
        let _ = record;
        todo!("M02-U8 meta::SideChannel::write")
    }
}
