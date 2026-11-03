//! U4's platform calls (ADR-0007 §12.15 item 9; owner W2-U4a): Windows `ReplaceFileW`
//! and handle identity, and the quarantine with the crate's only removal. Part of the
//! `sys` unsafe module; the inventory table is in `sys/mod.rs`.
//!
//! **What lives here.**
//! * [`QuarantineDir`]: the validated `.hm-quarantine` directory and **the only
//!   removal in the crate**, [`QuarantineDir::remove_verified`], of a name inside it
//!   whose identity and digest equal the expected ones at removal (ADR-0007 §5.3). Its
//!   empty-directory removal ([`QuarantineDir::rmdir_if_empty`]) cannot remove an entry.
//! * [`fsentry`] (crate-internal): what one name holds, read without following it, and
//!   the no-replace rename, the atomic exchange and the exclusive create that
//!   `projection::replace` builds on. On Unix every call goes through rustix's safe
//!   wrappers relative to a directory descriptor: `openat`, `fstat`/`statat` (macOS
//!   `st_birthtimespec`), `statx` with `STATX_BTIME` (Linux), and `renameat_with`
//!   (`RENAME_EXCHANGE`/`RENAME_NOREPLACE`, macOS `RENAME_SWAP`/`RENAME_EXCL`). There is
//!   no plain-rename fallback: `ENOSYS`, `EINVAL` and `ENOTSUP` from the exchange are
//!   reported as such and become manual mode.
//! * Windows: [`replace_file`] (`ReplaceFileW`), [`handle_identity`]
//!   (`GetFileInformationByHandleEx(FileIdInfo)`), `MoveFileExW` without
//!   `MOVEFILE_REPLACE_EXISTING`, owner checks through `GetSecurityInfo`, owner-only
//!   DACLs through SDDL, and the identity-bound delete (a delete disposition set on a
//!   handle whose file ID was checked, inside `QuarantineDir`).
//!
//! **`unsafe` inventory of this file** (merged into the table in `sys/mod.rs` by the
//! wave-2 integrator):
//!
//! | Function | Platform | Call | Invariant |
//! |---|---|---|---|
//! | `fsentry::euid` | Unix | `geteuid()` | no preconditions; cannot fail |
//! | [`replace_file`], `fsentry::replace` | Windows | `ReplaceFileW(…, REPLACEFILE_WRITE_THROUGH)` | NUL-terminated wide paths that outlive the call |
//! | [`handle_identity`] | Windows | `GetFileInformationByHandleEx(FileIdInfo)` | an open handle borrowed for the call; a correctly sized `FILE_ID_INFO` |
//! | `fsentry` (Windows) | Windows | `CreateFileW`, `CreateDirectoryW`, `MoveFileExW`, `GetFileInformationByHandle`, `GetFileInformationByHandleEx(FileBasicInfo, FileAttributeTagInfo)`, `GetFinalPathNameByHandleW`, `FlushFileBuffers` | every returned handle is owned by an `OwnedHandle`/`File` and closed exactly once; buffers are sized for the call |
//! | `fsentry` (Windows) | Windows | `GetSecurityInfo(SE_FILE_OBJECT)`, `ConvertSidToStringSidW`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `LocalFree` | each `LocalAlloc`ed result is freed exactly once, after the last pointer into it is used |
//! | [`QuarantineDir::remove_verified`], [`QuarantineDir::rmdir_if_empty`] | Windows | `SetFileInformationByHandle` with a POSIX-semantics delete disposition | only on a handle opened in the quarantine with `FILE_FLAG_OPEN_REPARSE_POINT`, no write or delete sharing, and whose file ID and digest were just checked (or, for the directory, its own pinned handle) |

use super::SysError;
use heimdall_domain::projection::{FileIdentity, Sha256Hex};

/// The quarantine directory's name inside a validated directory (ADR-0007 §5.3).
pub const QUARANTINE_NAME: &str = ".hm-quarantine";

/// The most bytes a content check reads (ADR-0007 §5.3 "≤ 1 MiB").
pub(crate) const CONTENT_MAX: usize = 1 << 20;

/// Where identities come from (additive, W2-U4a). `WithoutBirth` is the **test-only**
/// identity source that m02-plan U4 `git_name_transitions_crash_at_every_point_reconciles`
/// needs ("with and without a birth time on Unix"): every Unix identity read through a
/// handle opened with it has `birth: None`, as on a filesystem that records no birth
/// time (ADR-0007 F25). Production uses `Native`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum IdentitySource {
    /// The platform's identity, with the Unix birth time where the filesystem records
    /// one.
    #[default]
    Native,
    /// Test only: Unix identities without the birth time.
    WithoutBirth,
}

impl IdentitySource {
    /// `identity` as this source reports it.
    #[must_use]
    pub fn apply(self, identity: FileIdentity) -> FileIdentity {
        match (self, identity) {
            (IdentitySource::WithoutBirth, FileIdentity::Unix { dev, ino, .. }) => {
                FileIdentity::Unix {
                    dev,
                    ino,
                    birth: None,
                }
            }
            (_, identity) => identity,
        }
    }
}

/// Why a quarantine cannot be opened (additive, W2-U4a).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuarantineError {
    /// It exists but fails validation (owner, mode exactly 0700 or an owner-only DACL,
    /// no symlink or reparse point, not a mount point): manual mode.
    #[error("quarantine directory invalid: {0}")]
    Invalid(&'static str),
    /// A platform call failed.
    #[error(transparent)]
    Sys(SysError),
}

fn sys_err(call: &'static str, e: &std::io::Error) -> SysError {
    SysError {
        call,
        detail: e
            .raw_os_error()
            .map_or_else(|| format!("{:?}", e.kind()), |c| format!("os error {c}")),
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
    fsentry::replace(dir, target, replacement, backup).map_err(|e| sys_err("ReplaceFileW", &e))
}

/// The identity of an open file (Windows: volume serial and 128-bit file ID).
///
/// # Errors
/// [`SysError`].
#[cfg(windows)]
pub fn handle_identity(file: &std::fs::File) -> Result<FileIdentity, SysError> {
    use std::os::windows::io::AsRawHandle;
    fsentry::win::file_id(file.as_raw_handle())
        .map_err(|e| sys_err("GetFileInformationByHandleEx", &e))
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
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(unix)]
    parent: std::os::fd::OwnedFd,
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
    #[cfg(windows)]
    path: std::path::PathBuf,
    source: IdentitySource,
}

/// The quarantine checks that need no I/O (ADR-0007 §5.3 "Enforcement"), separate so
/// the cases a test cannot build without privileges (another owner, a mount point)
/// are still checked: a directory, owned by `euid`, mode exactly 0700, on the
/// parent's device and not a mount root.
///
/// # Errors
/// The first failed rule, as text for the report.
#[cfg(unix)]
pub(crate) fn quarantine_meta_ok(
    meta: &fsentry::EntryMeta,
    parent_dev: u64,
    mount_root: bool,
) -> Result<(), &'static str> {
    if meta.kind != fsentry::Kind::Directory {
        return Err("not a directory");
    }
    if !meta.owned {
        return Err("not owned by the current user");
    }
    if meta.perm != 0o700 {
        return Err("mode is not exactly 0700");
    }
    let FileIdentity::Unix { dev, .. } = meta.identity else {
        return Err("not a Unix identity");
    };
    if dev != parent_dev || mount_root {
        return Err("a mount point");
    }
    Ok(())
}

/// An `openat(O_DIRECTORY|O_NOFOLLOW)` failure of the quarantine name.
#[cfg(unix)]
fn open_error(e: &std::io::Error) -> QuarantineError {
    if fsentry::is_link_error(e) {
        QuarantineError::Invalid("a symlink")
    } else if rustix::io::Errno::from_io_error(e) == Some(rustix::io::Errno::NOTDIR) {
        QuarantineError::Invalid("not a directory")
    } else {
        QuarantineError::Sys(sys_err("openat", e))
    }
}

#[cfg(unix)]
impl QuarantineDir {
    /// Open (validating) or create the quarantine inside `parent`.
    ///
    /// `parent` is opened with `O_DIRECTORY|O_NOFOLLOW` and must be owned by the
    /// current user and not writable by group or others; the quarantine is then
    /// opened relative to it ([`QuarantineDir::open_or_create_in`]).
    ///
    /// # Errors
    /// [`SysError`].
    pub fn open_or_create(parent: &std::path::Path) -> Result<Self, SysError> {
        let fd = fsentry::open_dir_path(parent).map_err(|e| sys_err("open", &e))?;
        let meta = fsentry::fstat(&fd, IdentitySource::Native).map_err(|e| sys_err("fstat", &e))?;
        if !meta.owned || meta.perm & 0o022 != 0 {
            return Err(SysError {
                call: "open",
                detail: "parent directory not owner-only".to_owned(),
            });
        }
        Self::open_or_create_in(std::os::fd::AsFd::as_fd(&fd), IdentitySource::Native).map_err(
            |e| match e {
                QuarantineError::Sys(s) => s,
                QuarantineError::Invalid(why) => SysError {
                    call: "quarantine validation",
                    detail: why.to_owned(),
                },
            },
        )
    }

    /// Additive (W2-U4a): open (validating) or create the quarantine relative to an
    /// already validated directory descriptor, with `mkdirat` mode 0700. A freshly
    /// created quarantine whose mode the umask narrowed is set to 0700 with `fchmod`
    /// before it is validated; an existing one is never changed.
    ///
    /// # Errors
    /// [`QuarantineError`].
    pub fn open_or_create_in(
        parent: std::os::fd::BorrowedFd<'_>,
        source: IdentitySource,
    ) -> Result<Self, QuarantineError> {
        if let Some(q) = Self::open_existing_in(parent, source)? {
            return Ok(q);
        }
        let created = match rustix::fs::mkdirat(
            parent,
            QUARANTINE_NAME,
            rustix::fs::Mode::from_raw_mode(0o700),
        ) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(e) => return Err(QuarantineError::Sys(sys_err("mkdirat", &e.into()))),
        };
        let fd = fsentry::open_dir_at(parent, QUARANTINE_NAME).map_err(|e| open_error(&e))?;
        if created {
            let meta = fsentry::fstat(&fd, source)
                .map_err(|e| QuarantineError::Sys(sys_err("fstat", &e)))?;
            if meta.kind == fsentry::Kind::Directory && meta.owned && meta.perm != 0o700 {
                rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(0o700))
                    .map_err(|e| QuarantineError::Sys(sys_err("fchmod", &e.into())))?;
            }
        }
        Self::validated(parent, fd, source)
    }

    /// Additive (W2-U4a): open and validate the quarantine of `parent` when it exists;
    /// `Ok(None)` when it does not. Never creates anything (passive observation).
    ///
    /// # Errors
    /// [`QuarantineError`].
    pub fn open_existing_in(
        parent: std::os::fd::BorrowedFd<'_>,
        source: IdentitySource,
    ) -> Result<Option<Self>, QuarantineError> {
        match fsentry::open_dir_at(parent, QUARANTINE_NAME) {
            Ok(fd) => Self::validated(parent, fd, source).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(open_error(&e)),
        }
    }

    fn validated(
        parent: std::os::fd::BorrowedFd<'_>,
        fd: std::os::fd::OwnedFd,
        source: IdentitySource,
    ) -> Result<Self, QuarantineError> {
        let meta =
            fsentry::fstat(&fd, source).map_err(|e| QuarantineError::Sys(sys_err("fstat", &e)))?;
        let parent_meta = fsentry::fstat(&parent, source)
            .map_err(|e| QuarantineError::Sys(sys_err("fstat", &e)))?;
        let FileIdentity::Unix {
            dev: parent_dev, ..
        } = parent_meta.identity
        else {
            return Err(QuarantineError::Invalid("not a Unix identity"));
        };
        quarantine_meta_ok(&meta, parent_dev, fsentry::is_mount_root(&fd))
            .map_err(QuarantineError::Invalid)?;
        let parent = parent
            .try_clone_to_owned()
            .map_err(|e| QuarantineError::Sys(sys_err("dup", &e)))?;
        Ok(Self { fd, parent, source })
    }

    /// The quarantine's directory descriptor (crate-internal: settlement renames into
    /// it with no-replace).
    pub(crate) fn dir(&self) -> fsentry::Dir<'_> {
        std::os::fd::AsFd::as_fd(&self.fd)
    }

    /// The identity source this quarantine reads with.
    #[must_use]
    pub fn source(&self) -> IdentitySource {
        self.source
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
        self.remove_verified_with(name, expected_identity, expected_sha256, &mut || {})
    }

    /// Additive (W2-U4a): [`QuarantineDir::remove_verified`], calling `after_check`
    /// between the final identity and content check and the removal (the test-only
    /// `ReplacePoint::AfterSettleCheck`, ADR-0007 §5.9 item 1's residual window).
    ///
    /// Unix: `openat(O_NOFOLLOW|O_NONBLOCK)` relative to the quarantine descriptor,
    /// `fstat` (regular, owned, one link, the expected identity), a read of at most
    /// 1 MiB against the digest, then a fresh `statat` of the name that must still
    /// name the checked inode, and only then the removal relative to the same
    /// descriptor.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn remove_verified_with(
        &self,
        name: &str,
        expected_identity: &FileIdentity,
        expected_sha256: &str,
        after_check: &mut dyn FnMut(),
    ) -> Result<RemoveOutcome, SysError> {
        if !fsentry::is_component(name) {
            return Err(SysError {
                call: "remove_verified",
                detail: "not a single name".to_owned(),
            });
        }
        let dir = self.dir();
        let (meta, file) = match fsentry::inspect(dir, name, self.source) {
            Ok(None) => return Ok(RemoveOutcome::Missing),
            Ok(Some(found)) => found,
            Err(e) => return Err(sys_err("openat", &e)),
        };
        let Some(file) = file else {
            return Ok(RemoveOutcome::IdentityMismatch);
        };
        if !meta.is_heimdall_shape() || !meta.identity.same_file(expected_identity) {
            return Ok(RemoveOutcome::IdentityMismatch);
        }
        match fsentry::read_bounded(&file) {
            Ok(Some(bytes)) if Sha256Hex::of(&bytes).as_str() == expected_sha256 => {}
            Ok(_) => return Ok(RemoveOutcome::ContentMismatch),
            Err(e) => return Err(sys_err("read", &e)),
        }
        after_check();
        match fsentry::lstat(dir, name, self.source) {
            Ok(Some(now)) if now.same_inode(&meta) => {}
            Ok(Some(_)) => return Ok(RemoveOutcome::IdentityMismatch),
            Ok(None) => return Ok(RemoveOutcome::Missing),
            Err(e) => return Err(sys_err("statat", &e)),
        }
        match rustix::fs::unlinkat(dir, name, rustix::fs::AtFlags::empty()) {
            Ok(()) => Ok(RemoveOutcome::Removed),
            Err(rustix::io::Errno::NOENT) => Ok(RemoveOutcome::Missing),
            Err(e) => Err(sys_err("unlinkat", &e.into())),
        }
    }

    /// Remove the quarantine directory itself when it is empty; never removes an
    /// entry (`unlinkat(AT_REMOVEDIR)` fails on a directory that has entries). The name
    /// must still be this quarantine's directory.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn rmdir_if_empty(self) -> Result<bool, SysError> {
        let parent = std::os::fd::AsFd::as_fd(&self.parent);
        let mine = fsentry::fstat(&self.fd, self.source).map_err(|e| sys_err("fstat", &e))?;
        match fsentry::lstat(parent, QUARANTINE_NAME, self.source) {
            Ok(Some(now)) if now.same_inode(&mine) => {}
            Ok(_) => return Ok(false),
            Err(e) => return Err(sys_err("statat", &e)),
        }
        match rustix::fs::unlinkat(parent, QUARANTINE_NAME, rustix::fs::AtFlags::REMOVEDIR) {
            Ok(()) => Ok(true),
            Err(
                rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST | rustix::io::Errno::NOENT,
            ) => Ok(false),
            Err(e) => Err(sys_err("unlinkat", &e.into())),
        }
    }
}

#[cfg(windows)]
impl QuarantineDir {
    /// Open (validating) or create the quarantine inside `parent`.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn open_or_create(parent: &std::path::Path) -> Result<Self, SysError> {
        Self::open_or_create_at(parent, IdentitySource::Native).map_err(|e| match e {
            QuarantineError::Sys(s) => s,
            QuarantineError::Invalid(why) => SysError {
                call: "quarantine validation",
                detail: why.to_owned(),
            },
        })
    }

    /// Additive (W2-U4a): open (validating) or create the quarantine of the directory
    /// at `parent` (its final path), created with `CreateDirectoryW` and an owner-only
    /// protected DACL.
    ///
    /// # Errors
    /// [`QuarantineError`].
    pub fn open_or_create_at(
        parent: &std::path::Path,
        source: IdentitySource,
    ) -> Result<Self, QuarantineError> {
        if let Some(q) = Self::open_existing_at(parent, source)? {
            return Ok(q);
        }
        fsentry::win::create_owner_only_dir(&parent.join(QUARANTINE_NAME))
            .map_err(|e| QuarantineError::Sys(sys_err("CreateDirectoryW", &e)))?;
        Self::open_existing_at(parent, source)?
            .ok_or(QuarantineError::Invalid("vanished after creation"))
    }

    /// Additive (W2-U4a): open and validate the quarantine of `parent` when it exists.
    ///
    /// # Errors
    /// [`QuarantineError`].
    pub fn open_existing_at(
        parent: &std::path::Path,
        source: IdentitySource,
    ) -> Result<Option<Self>, QuarantineError> {
        let path = parent.join(QUARANTINE_NAME);
        let handle = match fsentry::win::open_dir_pinned(&path, true) {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(QuarantineError::Sys(sys_err("CreateFileW", &e))),
        };
        let meta = fsentry::win::meta(&handle)
            .map_err(|e| QuarantineError::Sys(sys_err("GetFileInformationByHandle", &e)))?;
        if meta.kind == fsentry::Kind::Symlink {
            return Err(QuarantineError::Invalid("a reparse point"));
        }
        if meta.kind != fsentry::Kind::Directory {
            return Err(QuarantineError::Invalid("not a directory"));
        }
        if !meta.owned {
            return Err(QuarantineError::Invalid("not owned by the current user"));
        }
        if !fsentry::win::dacl_is_owner_only(&handle)
            .map_err(|e| QuarantineError::Sys(sys_err("GetSecurityInfo", &e)))?
        {
            return Err(QuarantineError::Invalid("DACL is not owner-only"));
        }
        Ok(Some(Self {
            handle,
            path,
            source,
        }))
    }

    /// The quarantine's path (crate-internal: settlement moves into it).
    pub(crate) fn dir(&self) -> fsentry::Dir<'_> {
        &self.path
    }

    /// The identity source this quarantine reads with.
    #[must_use]
    pub fn source(&self) -> IdentitySource {
        self.source
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
        self.remove_verified_with(name, expected_identity, expected_sha256, &mut || {})
    }

    /// Additive (W2-U4a): [`QuarantineDir::remove_verified`] with a call between the
    /// final check and the removal. Windows: the entry is opened in the quarantine
    /// with `DELETE`, `FILE_FLAG_OPEN_REPARSE_POINT` and read sharing only, so no
    /// writer can open it while it is checked; the file ID and digest are checked on
    /// that handle, and the same handle is deleted (`FileDispositionInfoEx`), which
    /// binds the removal to the checked identity.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn remove_verified_with(
        &self,
        name: &str,
        expected_identity: &FileIdentity,
        expected_sha256: &str,
        after_check: &mut dyn FnMut(),
    ) -> Result<RemoveOutcome, SysError> {
        if !fsentry::is_component(name) {
            return Err(SysError {
                call: "remove_verified",
                detail: "not a single name".to_owned(),
            });
        }
        let path = self.path.join(name);
        let file = match fsentry::win::open_for_delete(&path) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(RemoveOutcome::Missing),
            Err(e) => return Err(sys_err("CreateFileW", &e)),
        };
        let meta =
            fsentry::win::meta(&file).map_err(|e| sys_err("GetFileInformationByHandle", &e))?;
        let meta = fsentry::EntryMeta {
            identity: self.source.apply(meta.identity.clone()),
            ..meta
        };
        if !meta.is_heimdall_shape() || !meta.identity.same_file(expected_identity) {
            return Ok(RemoveOutcome::IdentityMismatch);
        }
        let file = std::fs::File::from(file);
        match fsentry::read_bounded(&file) {
            Ok(Some(bytes)) if Sha256Hex::of(&bytes).as_str() == expected_sha256 => {}
            Ok(_) => return Ok(RemoveOutcome::ContentMismatch),
            Err(e) => return Err(sys_err("ReadFile", &e)),
        }
        after_check();
        Self::disposition(std::os::windows::io::AsRawHandle::as_raw_handle(&file))
            .map_err(|e| sys_err("SetFileInformationByHandle", &e))?;
        Ok(RemoveOutcome::Removed)
    }

    /// Set a POSIX-semantics delete disposition on an open handle: the identity-bound
    /// removal of the entry the handle was opened on (a directory only when empty).
    fn disposition(handle: std::os::windows::io::RawHandle) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle,
        };
        let info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: the handle was opened with DELETE access and is open for the call;
        // `info` is a correctly sized FILE_DISPOSITION_INFO_EX that outlives it.
        let ok = unsafe {
            SetFileInformationByHandle(
                handle as HANDLE,
                FileDispositionInfoEx,
                (&raw const info).cast::<std::ffi::c_void>(),
                u32::try_from(size_of::<FILE_DISPOSITION_INFO_EX>()).unwrap_or(u32::MAX),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Remove the quarantine directory itself when it is empty, through its own
    /// pinned handle (a non-empty directory refuses the disposition); never removes an
    /// entry.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn rmdir_if_empty(self) -> Result<bool, SysError> {
        match Self::disposition(std::os::windows::io::AsRawHandle::as_raw_handle(
            &self.handle,
        )) {
            Ok(()) => Ok(true),
            Err(e) if fsentry::win::is_dir_not_empty(&e) => Ok(false),
            Err(e) => Err(sys_err("SetFileInformationByHandle", &e)),
        }
    }
}

/// What one directory entry holds, read without following it, and the renames the
/// primitive is built from (crate-internal; W2-U4a). Nothing here removes a name.
pub(crate) mod fsentry {
    use std::fs::File;
    use std::io;

    use heimdall_domain::projection::FileIdentity;

    use super::{CONTENT_MAX, IdentitySource};

    /// A directory the calls below resolve names relative to.
    #[cfg(unix)]
    pub(crate) type Dir<'a> = std::os::fd::BorrowedFd<'a>;
    /// A directory the calls below resolve names relative to (Windows: its final
    /// path, pinned open by its owner).
    #[cfg(windows)]
    pub(crate) type Dir<'a> = &'a std::path::Path;

    /// An entry's type.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Kind {
        Regular,
        Directory,
        /// A symbolic link, or any reparse point (Windows).
        Symlink,
        /// Anything else (Unix FIFOs, sockets, devices).
        #[cfg_attr(windows, allow(dead_code))]
        Other,
    }

    /// What a name holds.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct EntryMeta {
        pub(crate) identity: FileIdentity,
        pub(crate) kind: Kind,
        /// Owned by the effective user (Windows: the owner SID is the process user's).
        pub(crate) owned: bool,
        pub(crate) nlink: u64,
        pub(crate) len: u64,
        /// Unix permission bits (`st_mode & 0o7777`); 0 on Windows.
        pub(crate) perm: u32,
        /// Change time in nanoseconds (Unix `st_ctime`; Windows `ChangeTime` × 100).
        pub(crate) changed_ns: i128,
    }

    impl EntryMeta {
        /// ADR-0007 §5.7 "Normalization" rule 1: a regular file owned by the user with
        /// one link. Anything else is X whatever its identity.
        pub(crate) fn is_heimdall_shape(&self) -> bool {
            self.kind == Kind::Regular && self.owned && self.nlink == 1
        }

        /// The same inode, ignoring the birth time (a name re-check against a handle
        /// that was just checked in full).
        #[cfg(unix)]
        pub(crate) fn same_inode(&self, other: &EntryMeta) -> bool {
            match (&self.identity, &other.identity) {
                (
                    FileIdentity::Unix { dev: a, ino: b, .. },
                    FileIdentity::Unix { dev: c, ino: d, .. },
                ) => a == c && b == d,
                (a, b) => a == b,
            }
        }
    }

    /// A single path component: non-empty, not `.` or `..`, no separator or NUL, at
    /// most 255 bytes.
    pub(crate) fn is_component(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && !name.contains(['/', '\0'])
            && !(cfg!(windows) && name.contains(['\\', ':']))
    }

    /// The one entry of `dir` whose identity is `identity` (a regular file owned by
    /// the user with one link); `None` when there is none, several, or the listing
    /// fails. Used to find a settled entry's slot by Q's recorded identity.
    pub(crate) fn find_by_identity(
        dir: Dir<'_>,
        identity: &FileIdentity,
        source: IdentitySource,
    ) -> Option<String> {
        let mut found = None;
        for name in list(dir)? {
            if !is_component(&name) {
                continue;
            }
            if let Ok(Some(m)) = lstat(dir, &name, source)
                && m.is_heimdall_shape()
                && m.identity.same_file(identity)
            {
                if found.is_some() {
                    return None;
                }
                found = Some(name);
            }
        }
        found
    }

    /// The names in `dir` (without `.` and `..`), at most 4096 of them.
    #[cfg(unix)]
    fn list(dir: Dir<'_>) -> Option<Vec<String>> {
        let mut out = Vec::new();
        let mut entries = rustix::fs::Dir::read_from(dir).ok()?;
        for entry in entries.by_ref() {
            let entry = entry.ok()?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name != "." && name != ".." {
                out.push(name.to_owned());
            }
            if out.len() > 4096 {
                return None;
            }
        }
        Some(out)
    }

    /// The names in `dir`, at most 4096 of them.
    #[cfg(windows)]
    fn list(dir: Dir<'_>) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).ok()? {
            let name = entry.ok()?.file_name();
            if let Some(name) = name.to_str() {
                out.push(name.to_owned());
            }
            if out.len() > 4096 {
                return None;
            }
        }
        Some(out)
    }

    /// Read the whole file from offset 0, at most [`CONTENT_MAX`] bytes; `None` when it
    /// is longer.
    pub(crate) fn read_bounded(file: &File) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 << 10];
        let mut offset = 0u64;
        loop {
            let n = read_at(file, &mut buf, offset)?;
            if n == 0 {
                return Ok(Some(out));
            }
            out.extend_from_slice(buf.get(..n).unwrap_or_default());
            if out.len() > CONTENT_MAX {
                return Ok(None);
            }
            offset = offset.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
    }

    #[cfg(unix)]
    fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }

    #[cfg(windows)]
    fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }

    // --- Unix -------------------------------------------------------------------------

    #[cfg(unix)]
    pub(crate) use unix::*;

    #[cfg(unix)]
    mod unix {
        use std::fs::File;
        use std::io;
        use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
        use std::path::Path;

        use heimdall_domain::projection::FileIdentity;
        use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
        use rustix::io::Errno;

        use super::{EntryMeta, IdentitySource, Kind};

        /// The effective user ID.
        pub(crate) fn euid() -> u32 {
            // SAFETY: `geteuid` takes no arguments, has no preconditions and cannot
            // fail (POSIX).
            unsafe { libc::geteuid() }
        }

        /// Whether an open error means a symlink where `O_NOFOLLOW` refused to follow
        /// one (`ELOOP`; `EMLINK` on some BSDs).
        pub(crate) fn is_link_error(e: &io::Error) -> bool {
            matches!(Errno::from_io_error(e), Some(Errno::LOOP | Errno::MLINK))
        }

        /// `open(path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`.
        pub(crate) fn open_dir_path(path: &Path) -> io::Result<OwnedFd> {
            Ok(rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?)
        }

        /// `openat(dir, name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`.
        pub(crate) fn open_dir_at(dir: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
            Ok(rustix::fs::openat(
                dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?)
        }

        /// What `fd` is.
        pub(crate) fn fstat(fd: &impl AsFd, source: IdentitySource) -> io::Result<EntryMeta> {
            stat_impl(fd.as_fd(), None, source)
        }

        /// What `name` holds in `dir`, never following it; `None` when there is no
        /// entry.
        pub(crate) fn lstat(
            dir: BorrowedFd<'_>,
            name: &str,
            source: IdentitySource,
        ) -> io::Result<Option<EntryMeta>> {
            match stat_impl(dir, Some(name), source) {
                Ok(m) => Ok(Some(m)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// What `name` holds, and for a regular file an open read handle on exactly
        /// that inode (`openat(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)`, then `fstat`).
        /// `None` when there is no entry.
        pub(crate) fn inspect(
            dir: BorrowedFd<'_>,
            name: &str,
            source: IdentitySource,
        ) -> io::Result<Option<(EntryMeta, Option<File>)>> {
            let Some(before) = lstat(dir, name, source)? else {
                return Ok(None);
            };
            if before.kind != Kind::Regular {
                return Ok(Some((before, None)));
            }
            let fd = match rustix::fs::openat(
                dir,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(None),
                // Replaced by a symlink (or worse) since the lstat: report what is there.
                Err(Errno::LOOP) => return Ok(lstat(dir, name, source)?.map(|m| (m, None))),
                Err(e) => return Err(e.into()),
            };
            let meta = fstat(&fd, source)?;
            Ok(Some((meta, Some(File::from(fd)))))
        }

        /// Create `name` exclusively (`O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`) with exactly
        /// `perm` (set with `fchmod`, so the umask cannot narrow it).
        pub(crate) fn create_new(dir: BorrowedFd<'_>, name: &str, perm: u32) -> io::Result<File> {
            let fd = rustix::fs::openat(
                dir,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode_of(perm & 0o600),
            )?;
            rustix::fs::fchmod(&fd, mode_of(perm))?;
            Ok(File::from(fd))
        }

        /// No-replace rename (Linux `RENAME_NOREPLACE`, macOS `RENAME_EXCL`).
        pub(crate) fn rename_noreplace(
            from_dir: BorrowedFd<'_>,
            from: &str,
            to_dir: BorrowedFd<'_>,
            to: &str,
        ) -> io::Result<()> {
            rustix::fs::renameat_with(from_dir, from, to_dir, to, RenameFlags::NOREPLACE)?;
            sync_dir(from_dir);
            sync_dir(to_dir);
            Ok(())
        }

        /// Atomic exchange of two names in one directory (Linux `RENAME_EXCHANGE`,
        /// macOS `RENAME_SWAP`).
        pub(crate) fn exchange(dir: BorrowedFd<'_>, a: &str, b: &str) -> io::Result<()> {
            rustix::fs::renameat_with(dir, a, dir, b, RenameFlags::EXCHANGE)?;
            sync_dir(dir);
            Ok(())
        }

        /// Whether an exchange or no-replace error means the filesystem has no atomic
        /// exchange (ADR-0007 §5.3 step 9: `EINVAL`/`ENOTSUP`/`ENOSYS`).
        pub(crate) fn is_unsupported(e: &io::Error) -> bool {
            // `ENOTSUP` and `EOPNOTSUPP` are one value on Linux and two on macOS, so
            // they are compared, not matched as patterns.
            Errno::from_io_error(e).is_some_and(|n| {
                [Errno::INVAL, Errno::NOTSUP, Errno::NOSYS, Errno::OPNOTSUPP].contains(&n)
            })
        }

        /// Best-effort `fsync` of a directory so a completed rename is durable; a
        /// failure changes nothing that recovery does not observe anyway.
        pub(crate) fn sync_dir(dir: BorrowedFd<'_>) {
            let _ = rustix::fs::fsync(dir);
        }

        /// Whether `fd` is the root of a mount (Linux `STATX_ATTR_MOUNT_ROOT`; elsewhere
        /// the device comparison with the parent decides).
        pub(crate) fn is_mount_root(fd: &OwnedFd) -> bool {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                use rustix::fs::{StatxAttributes, StatxFlags};
                if let Ok(x) =
                    rustix::fs::statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::BASIC_STATS)
                {
                    return x.stx_attributes_mask.contains(StatxAttributes::MOUNT_ROOT)
                        && x.stx_attributes.contains(StatxAttributes::MOUNT_ROOT);
                }
                false
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                let _ = fd;
                false
            }
        }

        /// The type from `st_mode`'s `S_IFMT` bits (the POSIX values, equal on Linux
        /// and macOS).
        fn kind_of(mode: u32) -> Kind {
            match mode & 0o170_000 {
                0o100_000 => Kind::Regular,
                0o040_000 => Kind::Directory,
                0o120_000 => Kind::Symlink,
                _ => Kind::Other,
            }
        }

        /// `perm`'s permission bits as a rustix `Mode`, without a width cast (`mode_t`
        /// is 16 bits on macOS and 32 on Linux).
        pub(crate) fn mode_of(perm: u32) -> Mode {
            [
                (0o400, Mode::RUSR),
                (0o200, Mode::WUSR),
                (0o100, Mode::XUSR),
                (0o040, Mode::RGRP),
                (0o020, Mode::WGRP),
                (0o010, Mode::XGRP),
                (0o004, Mode::ROTH),
                (0o002, Mode::WOTH),
                (0o001, Mode::XOTH),
            ]
            .into_iter()
            .filter(|(bit, _)| perm & bit != 0)
            .fold(Mode::empty(), |m, (_, flag)| m | flag)
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn stat_impl(
            dir: BorrowedFd<'_>,
            name: Option<&str>,
            source: IdentitySource,
        ) -> io::Result<EntryMeta> {
            use rustix::fs::StatxFlags;
            let (path, flags) = match name {
                Some(n) => (n, AtFlags::SYMLINK_NOFOLLOW),
                None => ("", AtFlags::EMPTY_PATH),
            };
            let x = match rustix::fs::statx(
                dir,
                path,
                flags,
                StatxFlags::BASIC_STATS | StatxFlags::BTIME,
            ) {
                Ok(x) => x,
                Err(Errno::NOSYS | Errno::PERM) => return stat_fallback(dir, name, source),
                Err(e) => return Err(e.into()),
            };
            let birth = (x.stx_mask & StatxFlags::BTIME.bits() != 0).then(|| {
                i128::from(x.stx_btime.tv_sec) * 1_000_000_000 + i128::from(x.stx_btime.tv_nsec)
            });
            let identity = FileIdentity::Unix {
                dev: rustix::fs::makedev(x.stx_dev_major, x.stx_dev_minor),
                ino: x.stx_ino,
                birth,
            };
            let mode = u32::from(x.stx_mode);
            Ok(EntryMeta {
                identity: source.apply(identity),
                kind: kind_of(mode),
                owned: x.stx_uid == euid(),
                nlink: u64::from(x.stx_nlink),
                len: x.stx_size,
                perm: mode & 0o7777,
                changed_ns: i128::from(x.stx_ctime.tv_sec) * 1_000_000_000
                    + i128::from(x.stx_ctime.tv_nsec),
            })
        }

        /// `fstat`/`statat` when `statx` is unavailable (no birth time).
        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[allow(
            clippy::useless_conversion,
            clippy::unnecessary_fallible_conversions,
            clippy::unnecessary_cast
        )]
        fn stat_fallback(
            dir: BorrowedFd<'_>,
            name: Option<&str>,
            source: IdentitySource,
        ) -> io::Result<EntryMeta> {
            let st = match name {
                Some(n) => rustix::fs::statat(dir, n, AtFlags::SYMLINK_NOFOLLOW)?,
                None => rustix::fs::fstat(dir)?,
            };
            let mode = st.st_mode as u32;
            let identity = FileIdentity::Unix {
                dev: u64::try_from(st.st_dev).unwrap_or(u64::MAX),
                ino: u64::try_from(st.st_ino).unwrap_or(u64::MAX),
                birth: None,
            };
            Ok(EntryMeta {
                identity: source.apply(identity),
                kind: kind_of(mode),
                owned: st.st_uid == euid(),
                nlink: u64::try_from(st.st_nlink).unwrap_or(u64::MAX),
                len: u64::try_from(st.st_size).unwrap_or(0),
                perm: mode & 0o7777,
                changed_ns: i128::from(st.st_ctime) * 1_000_000_000 + i128::from(st.st_ctime_nsec),
            })
        }

        #[cfg(target_os = "macos")]
        fn stat_impl(
            dir: BorrowedFd<'_>,
            name: Option<&str>,
            source: IdentitySource,
        ) -> io::Result<EntryMeta> {
            let st = match name {
                Some(n) => rustix::fs::statat(dir, n, AtFlags::SYMLINK_NOFOLLOW)?,
                None => rustix::fs::fstat(dir)?,
            };
            // APFS and HFS+ record a birth time; a filesystem that does not reports 0.
            let birth = (st.st_birthtime > 0).then(|| {
                i128::from(st.st_birthtime) * 1_000_000_000 + i128::from(st.st_birthtime_nsec)
            });
            // `dev_t` is `i32` on macOS: reinterpret its bits (injective).
            let dev = u64::from(u32::from_ne_bytes(st.st_dev.to_ne_bytes()));
            let identity = FileIdentity::Unix {
                dev,
                ino: st.st_ino,
                birth,
            };
            let mode = u32::from(st.st_mode);
            Ok(EntryMeta {
                identity: source.apply(identity),
                kind: kind_of(mode),
                owned: st.st_uid == euid(),
                nlink: u64::from(st.st_nlink),
                len: u64::try_from(st.st_size).unwrap_or(0),
                perm: mode & 0o7777,
                changed_ns: i128::from(st.st_ctime) * 1_000_000_000 + i128::from(st.st_ctime_nsec),
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        fn stat_impl(
            dir: BorrowedFd<'_>,
            name: Option<&str>,
            source: IdentitySource,
        ) -> io::Result<EntryMeta> {
            let _ = (dir, name, source);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "file identity is implemented for Linux and macOS only",
            ))
        }
    }

    // --- Windows ----------------------------------------------------------------------

    #[cfg(windows)]
    pub(crate) use win::{create_new, inspect, is_unsupported, lstat, rename_noreplace, replace};

    /// Windows calls. Every `unsafe` block states its invariant.
    #[cfg(windows)]
    pub(crate) mod win {
        use std::ffi::{OsStr, c_void};
        use std::fs::File;
        use std::io;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
        use std::path::{Path, PathBuf};
        use std::ptr;
        use std::sync::OnceLock;

        use heimdall_domain::projection::FileIdentity;
        use windows_sys::Win32::Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_DIR_NOT_EMPTY, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
            ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE,
            HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        };
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            SECURITY_ATTRIBUTES,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FileBasicInfo, FileIdInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx, GetFinalPathNameByHandleW, MOVEFILE_WRITE_THROUGH,
            MoveFileExW, OPEN_EXISTING, READ_CONTROL, REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
        };

        use super::{EntryMeta, IdentitySource, Kind};

        fn wide(path: &Path) -> Vec<u16> {
            OsStr::new(path).encode_wide().chain(Some(0)).collect()
        }

        fn last_error() -> io::Error {
            io::Error::last_os_error()
        }

        fn is_not_found(e: &io::Error) -> bool {
            matches!(
                e.raw_os_error().and_then(|c| u32::try_from(c).ok()),
                Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
            )
        }

        /// Whether an error is "the name exists" (no-replace move or exclusive create).
        pub(crate) fn is_exists(e: &io::Error) -> bool {
            matches!(
                e.raw_os_error().and_then(|c| u32::try_from(c).ok()),
                Some(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS)
            )
        }

        /// Whether a disposition failed because the directory has entries.
        pub(crate) fn is_dir_not_empty(e: &io::Error) -> bool {
            e.raw_os_error().and_then(|c| u32::try_from(c).ok()) == Some(ERROR_DIR_NOT_EMPTY)
        }

        /// Whether a replace error means the volume cannot do it (manual mode).
        pub(crate) fn is_unsupported(e: &io::Error) -> bool {
            e.raw_os_error().and_then(|c| u32::try_from(c).ok()) == Some(ERROR_NOT_SUPPORTED)
        }

        /// `CreateFileW` returning an owned handle.
        fn create_file(
            path: &Path,
            access: u32,
            share: u32,
            disposition: u32,
            flags: u32,
            attributes: Option<&SECURITY_ATTRIBUTES>,
        ) -> io::Result<OwnedHandle> {
            let w = wide(path);
            let sa = attributes.map_or(ptr::null(), ptr::from_ref);
            // SAFETY: `w` is a NUL-terminated wide string and `sa` is null or points
            // at a SECURITY_ATTRIBUTES that outlives the call; no template handle.
            let h = unsafe {
                CreateFileW(
                    w.as_ptr(),
                    access,
                    share,
                    sa,
                    disposition,
                    flags,
                    ptr::null_mut(),
                )
            };
            if h == INVALID_HANDLE_VALUE || h.is_null() {
                return Err(last_error());
            }
            // SAFETY: CreateFileW succeeded, so `h` is a handle we now own
            // exclusively; OwnedHandle closes it exactly once.
            Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
        }

        /// Open a directory without following a reparse point and **without delete
        /// sharing**, so it cannot be renamed or removed while the handle is held.
        /// `delete` adds `DELETE` access (for the quarantine's own removal).
        pub(crate) fn open_dir_pinned(path: &Path, delete: bool) -> io::Result<OwnedHandle> {
            let mut access = FILE_READ_ATTRIBUTES | READ_CONTROL;
            if delete {
                access |= DELETE;
            }
            create_file(
                path,
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }

        /// The final path of an open handle (`GetFinalPathNameByHandleW`).
        pub(crate) fn final_path(handle: &OwnedHandle) -> io::Result<PathBuf> {
            let mut buf = vec![0u16; 1024];
            loop {
                let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
                // SAFETY: the handle is open for the call and `buf` has `cap` writable
                // UTF-16 units.
                let n = unsafe {
                    GetFinalPathNameByHandleW(
                        handle.as_raw_handle() as HANDLE,
                        buf.as_mut_ptr(),
                        cap,
                        0,
                    )
                };
                if n == 0 {
                    return Err(last_error());
                }
                let n = usize::try_from(n).unwrap_or(usize::MAX);
                if n < buf.len() {
                    buf.truncate(n);
                    return Ok(PathBuf::from(std::ffi::OsString::from(
                        String::from_utf16_lossy(&buf),
                    )));
                }
                if n > 32 << 10 {
                    return Err(io::Error::other("final path too long"));
                }
                buf = vec![0u16; n + 1];
            }
        }

        /// The process user's SID string, once.
        fn current_sid() -> io::Result<&'static str> {
            static SID: OnceLock<Option<String>> = OnceLock::new();
            SID.get_or_init(|| heimdall_ipc::windows::current_user_sid().ok())
                .as_deref()
                .ok_or_else(|| io::Error::other("current user SID unavailable"))
        }

        struct LocalAllocation(*mut c_void);

        impl Drop for LocalAllocation {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: the pointer came from an API that allocates with
                    // LocalAlloc and is freed exactly once here.
                    unsafe {
                        LocalFree(self.0);
                    }
                }
            }
        }

        fn wide_to_string(text: *const u16, max: usize) -> io::Result<String> {
            let mut len = 0usize;
            // SAFETY: `text` is a NUL-terminated UTF-16 string owned by the caller's
            // allocation; the scan is bounded by `max` and stops at the terminator.
            while len <= max && unsafe { *text.add(len) } != 0 {
                len += 1;
            }
            if len > max {
                return Err(io::Error::other("string too long"));
            }
            // SAFETY: the first `len` units were just read as initialized.
            let units = unsafe { std::slice::from_raw_parts(text, len) };
            String::from_utf16(units).map_err(|_| io::Error::other("not UTF-16"))
        }

        /// The owner SID string of the object behind `handle`.
        fn owner_sid(handle: RawHandle) -> io::Result<String> {
            let mut owner: PSID = ptr::null_mut();
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: the handle is open for the call; the owner and descriptor
            // out-pointers are valid; group, DACL and SACL are not requested.
            let rc = unsafe {
                GetSecurityInfo(
                    handle as HANDLE,
                    SE_FILE_OBJECT,
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
            let descriptor = LocalAllocation(descriptor);
            if owner.is_null() {
                return Err(io::Error::other("no owner"));
            }
            let mut text: *mut u16 = ptr::null_mut();
            // SAFETY: `owner` points into `descriptor`, alive for the call; `text` is
            // a valid out-pointer.
            if unsafe { ConvertSidToStringSidW(owner, &mut text) } == 0 {
                return Err(last_error());
            }
            let text_alloc = LocalAllocation(text.cast::<c_void>());
            let sid = wide_to_string(text, 256);
            drop(text_alloc);
            drop(descriptor);
            sid
        }

        /// Whether the object's DACL is exactly the owner-only DACL Heimdall creates:
        /// protected, one ACE granting full access to the process user.
        pub(crate) fn dacl_is_owner_only(handle: &OwnedHandle) -> io::Result<bool> {
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: the handle is open for the call; only the DACL is requested and
            // the descriptor out-pointer is valid.
            let rc = unsafe {
                GetSecurityInfo(
                    handle.as_raw_handle() as HANDLE,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
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
            let descriptor = LocalAllocation(descriptor);
            let mut text: *mut u16 = ptr::null_mut();
            // SAFETY: `descriptor` is a valid self-relative descriptor alive for the
            // call; `text` is a valid out-pointer; the length out-pointer may be null.
            let ok = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor.0,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            let text_alloc = LocalAllocation(text.cast::<c_void>());
            let sddl = wide_to_string(text, 4096);
            drop(text_alloc);
            drop(descriptor);
            let sid = current_sid()?;
            Ok(sddl? == owner_only_dacl(sid, true))
        }

        /// The protected owner-only DACL: one ACE granting full access to the process
        /// user, inherited by children for a directory.
        fn owner_only_dacl(sid: &str, directory: bool) -> String {
            let flags = if directory { "OICI" } else { "" };
            format!("D:P(A;{flags};FA;;;{sid})")
        }

        /// A self-relative owner-only descriptor for a new file or the quarantine.
        fn owner_only_descriptor(directory: bool) -> io::Result<LocalAllocation> {
            let sid = current_sid()?;
            let sddl: Vec<u16> = OsStr::new(&format!("O:{sid}{}", owner_only_dacl(sid, directory)))
                .encode_wide()
                .chain(Some(0))
                .collect();
            let mut descriptor: *mut c_void = ptr::null_mut();
            // SAFETY: `sddl` is NUL-terminated and outlives the call; `descriptor` is a
            // valid out-pointer; the size out-pointer may be null.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            Ok(LocalAllocation(descriptor))
        }

        fn attributes(descriptor: &LocalAllocation) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: 0,
            }
        }

        /// `CreateDirectoryW` with an owner-only protected DACL.
        pub(crate) fn create_owner_only_dir(path: &Path) -> io::Result<()> {
            let descriptor = owner_only_descriptor(true)?;
            let sa = attributes(&descriptor);
            let w = wide(path);
            // SAFETY: `w` is NUL-terminated; `sa` and its descriptor outlive the call.
            if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
                let e = last_error();
                if !is_exists(&e) {
                    return Err(e);
                }
            }
            Ok(())
        }

        /// The identity of an open handle (`FileIdInfo`).
        pub(crate) fn file_id(handle: RawHandle) -> io::Result<FileIdentity> {
            let mut info = FILE_ID_INFO::default();
            // SAFETY: the handle is open for the call; `info` is a correctly sized,
            // writable FILE_ID_INFO.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    handle as HANDLE,
                    FileIdInfo,
                    (&raw mut info).cast::<c_void>(),
                    u32::try_from(size_of::<FILE_ID_INFO>()).unwrap_or(u32::MAX),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            Ok(FileIdentity::Windows {
                volume: info.VolumeSerialNumber,
                file_id: info.FileId.Identifier,
            })
        }

        /// What an open handle is.
        pub(crate) fn meta(handle: &impl AsRawHandle) -> io::Result<EntryMeta> {
            let raw = handle.as_raw_handle();
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: the handle is open for the call; `info` is writable.
            if unsafe { GetFileInformationByHandle(raw as HANDLE, &mut info) } == 0 {
                return Err(last_error());
            }
            let mut basic = FILE_BASIC_INFO::default();
            // SAFETY: as above; `basic` is a correctly sized, writable FILE_BASIC_INFO.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    raw as HANDLE,
                    FileBasicInfo,
                    (&raw mut basic).cast::<c_void>(),
                    u32::try_from(size_of::<FILE_BASIC_INFO>()).unwrap_or(u32::MAX),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            let kind = if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                Kind::Symlink
            } else if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                Kind::Directory
            } else {
                Kind::Regular
            };
            let owned = owner_sid(raw)? == current_sid()?;
            Ok(EntryMeta {
                identity: file_id(raw)?,
                kind,
                owned,
                nlink: u64::from(info.nNumberOfLinks),
                len: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
                perm: 0,
                changed_ns: i128::from(basic.ChangeTime) * 100,
            })
        }

        /// Open `name` in `dir` for inspection without following a reparse point;
        /// `None` when there is no entry.
        fn open_any(path: &Path) -> io::Result<Option<OwnedHandle>> {
            match create_file(
                path,
                GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            ) {
                Ok(h) => Ok(Some(h)),
                Err(e) if is_not_found(&e) => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// What `name` holds in `dir`; `None` when there is no entry.
        pub(crate) fn lstat(
            dir: &Path,
            name: &str,
            source: IdentitySource,
        ) -> io::Result<Option<EntryMeta>> {
            Ok(inspect(dir, name, source)?.map(|(m, _)| m))
        }

        /// What `name` holds, with a read handle for a regular file.
        pub(crate) fn inspect(
            dir: &Path,
            name: &str,
            source: IdentitySource,
        ) -> io::Result<Option<(EntryMeta, Option<File>)>> {
            let Some(h) = open_any(&dir.join(name))? else {
                return Ok(None);
            };
            let mut m = meta(&h)?;
            m.identity = source.apply(m.identity);
            let file = (m.kind == Kind::Regular).then(|| File::from(h));
            Ok(Some((m, file)))
        }

        /// Open an entry in the quarantine for an identity-bound removal: `DELETE` and
        /// read access, read sharing only, no reparse following.
        pub(crate) fn open_for_delete(path: &Path) -> io::Result<Option<OwnedHandle>> {
            match create_file(
                path,
                DELETE | GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            ) {
                Ok(h) => Ok(Some(h)),
                Err(e) if is_not_found(&e) => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Create `name` exclusively with an owner-only DACL, not following a reparse
        /// point.
        pub(crate) fn create_new(dir: &Path, name: &str, perm: u32) -> io::Result<File> {
            let _ = perm;
            let descriptor = owner_only_descriptor(false)?;
            let sa = attributes(&descriptor);
            let h = create_file(
                &dir.join(name),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                Some(&sa),
            )?;
            drop(descriptor);
            Ok(File::from(h))
        }

        /// `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` (no-replace).
        pub(crate) fn rename_noreplace(
            from_dir: &Path,
            from: &str,
            to_dir: &Path,
            to: &str,
        ) -> io::Result<()> {
            let a = wide(&from_dir.join(from));
            let b = wide(&to_dir.join(to));
            // SAFETY: both strings are NUL-terminated and outlive the call.
            if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
                return Err(last_error());
            }
            Ok(())
        }

        /// `ReplaceFileW(dir\target, dir\replacement, dir\backup, WRITE_THROUGH)`.
        pub(crate) fn replace(
            dir: &Path,
            target: &str,
            replacement: &str,
            backup: &str,
        ) -> io::Result<()> {
            let t = wide(&dir.join(target));
            let r = wide(&dir.join(replacement));
            let b = wide(&dir.join(backup));
            // SAFETY: all three strings are NUL-terminated and outlive the call; the
            // exclude and reserved pointers are null as documented.
            let ok = unsafe {
                ReplaceFileW(
                    t.as_ptr(),
                    r.as_ptr(),
                    b.as_ptr(),
                    REPLACEFILE_WRITE_THROUGH,
                    ptr::null(),
                    ptr::null(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::fsentry::{EntryMeta, Kind};
    use super::*;

    fn dir_meta(perm: u32, owned: bool, dev: u64) -> EntryMeta {
        EntryMeta {
            identity: FileIdentity::Unix {
                dev,
                ino: 7,
                birth: None,
            },
            kind: Kind::Directory,
            owned,
            nlink: 2,
            len: 0,
            perm,
            changed_ns: 0,
        }
    }

    /// m02-plan U4 quarantine validation, the cases a test cannot build without
    /// privileges: another owner and a mount point (another device, or Linux's
    /// mount-root attribute). Mode and symlink are exercised on the filesystem in
    /// `tests/integration/projection_replace.rs`.
    #[test]
    fn quarantine_validation_rules() {
        assert_eq!(
            quarantine_meta_ok(&dir_meta(0o700, true, 1), 1, false),
            Ok(())
        );
        assert!(quarantine_meta_ok(&dir_meta(0o700, false, 1), 1, false).is_err());
        assert!(quarantine_meta_ok(&dir_meta(0o755, true, 1), 1, false).is_err());
        assert!(quarantine_meta_ok(&dir_meta(0o600, true, 1), 1, false).is_err());
        assert!(quarantine_meta_ok(&dir_meta(0o1700, true, 1), 1, false).is_err());
        assert!(quarantine_meta_ok(&dir_meta(0o700, true, 2), 1, false).is_err());
        assert!(quarantine_meta_ok(&dir_meta(0o700, true, 1), 1, true).is_err());
        let mut file = dir_meta(0o700, true, 1);
        file.kind = Kind::Regular;
        assert!(quarantine_meta_ok(&file, 1, false).is_err());
    }

    /// ADR-0007 §5.3 step 9: the exchange errors that mean "no atomic exchange on this
    /// filesystem" (manual mode), and only those. The APFS and ext4 harnesses support
    /// the exchange, so this branch is checked here, by errno.
    #[test]
    fn exchange_unsupported_errnos_are_manual_mode() {
        let e = std::io::Error::from_raw_os_error;
        for n in [libc::EINVAL, libc::ENOTSUP, libc::ENOSYS, libc::EOPNOTSUPP] {
            assert!(fsentry::is_unsupported(&e(n)), "{n}");
        }
        for n in [
            libc::EEXIST,
            libc::ENOENT,
            libc::EACCES,
            libc::EXDEV,
            libc::EIO,
        ] {
            assert!(!fsentry::is_unsupported(&e(n)), "{n}");
        }
        assert!(!fsentry::is_unsupported(&std::io::Error::other("x")));
    }

    #[test]
    fn identity_source_without_birth_strips_only_the_birth() {
        let id = FileIdentity::Unix {
            dev: 1,
            ino: 2,
            birth: Some(3),
        };
        assert_eq!(IdentitySource::Native.apply(id.clone()), id);
        assert_eq!(
            IdentitySource::WithoutBirth.apply(id),
            FileIdentity::Unix {
                dev: 1,
                ino: 2,
                birth: None
            }
        );
    }

    #[test]
    fn names_are_single_components() {
        for ok in ["a", ".hm-quarantine", "x.hm-1-ab"] {
            assert!(fsentry::is_component(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a\0b", &"x".repeat(256)] {
            assert!(!fsentry::is_component(bad), "{bad:?}");
        }
    }
}
