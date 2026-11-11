//! ⟨M03⟩ The managed directories' anchored file work (ADR-0008 §17.20 item 7; W3-S04):
//! every write, clear and enumeration under `<state_dir>/managed/` and
//! `<runtime_dir>/b/` goes through a [`ManagedDir`], a directory handle that was
//! verified when it was opened. Part of the `sys` module; **this file has no `unsafe`**:
//! it composes the existing handle-relative primitives of `quarantine::fsentry` (Unix:
//! rustix `openat`/`fstat`/`mkdirat`/`renameat` relative to a directory descriptor, and
//! the quarantine for every removal; Windows: the reparse-point-refusing, no-delete-sharing directory pin, the
//! owner SID and owner-only DACL checks, `CreateDirectoryW` with the owner-only DACL,
//! `ReplaceFileW` and the no-replace `MoveFileExW`), whose `unsafe` and invariants are
//! already in the `sys/mod.rs` table.
//!
//! **The rules.**
//! * **The anchor** (the state or runtime directory) is opened by its path without
//!   following its last component (Unix `O_DIRECTORY|O_NOFOLLOW`; Windows
//!   `FILE_FLAG_OPEN_REPARSE_POINT`), and must be a directory owned by the user (Unix:
//!   writable by neither group nor others). Its ancestors are the platform's (for example
//!   macOS `/var` → `/private/var`); they are resolved once, when it is opened.
//! * **Every level below the anchor** is opened relative to its verified parent handle,
//!   never by a path string on Unix: a symlink (or, on Windows, any reparse point) at a
//!   level is refused, never followed; an existing directory that is not owner-only
//!   (Unix: owned by the user and no group or other permission bit; Windows: owned by the
//!   user, with exactly Heimdall's protected owner-only DACL) is refused. **Nothing is
//!   repaired**: a refusal is [`ManagedDirError::Unsafe`] (`managed_dir_unsafe`). A
//!   missing level is created owner-only (Unix `mkdirat` 0700, set with `fchmod` because
//!   the umask may narrow it; Windows `CreateDirectoryW` with the owner-only DACL) and
//!   then verified like an existing one, so a racing creator's directory is held to the
//!   same rules.
//! * **Files** are written to a fresh exclusive temporary name in the verified
//!   directory (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0644: the slot and binding files are
//!   public, ADR-0008 D10 item 2; Windows: the owner-only DACL of `fsentry::create_new`),
//!   synced, then renamed over the name relative to the same handle. A read opens the
//!   name without following it and reads a regular file only.
//! * **Removal** goes through the crate's only removal (ADR-0007 §5.3): the file's
//!   identity and digest are read on a handle relative to the verified directory, the
//!   name is moved (no replacement) into that directory's validated `.hm-quarantine`,
//!   and `QuarantineDir::remove_verified` removes it only while it keeps that identity
//!   and digest. Only a regular single-link file of the user is ever removed; a
//!   symlink or a directory at a file's name is refused and left in place.
//!
//! **What Windows guarantees.** A directory handle is a pin opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT` and without `FILE_SHARE_DELETE`: while it is held the
//! directory cannot be renamed, removed or replaced, and names are resolved under its
//! final path (`GetFinalPathNameByHandleW`), so a path below a held pin names the
//! verified directory. A junction or symlink at a level is opened as itself and refused.
//! Names are still resolved by path under that final path (Win32 has no `openat`); the
//! file operations themselves are the M02 projection's. These Windows paths compile here
//! and need the Windows-native run (`managed_dir_windows_*` in
//! `tests/integration/managed_adapter.rs`).

use std::io::{self, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::SysError;
use super::quarantine::fsentry::{self, Kind};
use super::quarantine::{
    CONTENT_MAX, IdentitySource, QuarantineDir, QuarantineError, RemoveOutcome,
};
use heimdall_domain::projection::Sha256Hex;

/// The stable reason of a refused managed directory (ADR-0008 §17.20 item 7).
pub const MANAGED_DIR_UNSAFE: &str = "managed_dir_unsafe";

/// Why a managed directory operation did not run. Nonsecret: a fixed reason or the
/// failed call with its OS error code, never a path or content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagedDirError {
    /// A level is a symlink or reparse point, not a directory, or an existing
    /// directory that is not owner-only; or a file name holds something else than a
    /// regular file (`managed_dir_unsafe`; nothing was repaired or followed).
    #[error("managed_dir_unsafe: {0}")]
    Unsafe(&'static str),
    /// A platform call failed.
    #[error(transparent)]
    Sys(SysError),
}

fn sys(call: &'static str, e: &io::Error) -> ManagedDirError {
    ManagedDirError::Sys(SysError {
        call,
        detail: e
            .raw_os_error()
            .map_or_else(|| format!("{:?}", e.kind()), |c| format!("os error {c}")),
    })
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh name for `target` parked in the quarantine before its verified removal.
fn removal_name(target: &str) -> String {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{target}.removed-{}-{n}", std::process::id())
}

fn temp_name(target: &str) -> String {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{target}.tmp-{}-{n}", std::process::id())
}

fn component(name: &str) -> Result<(), ManagedDirError> {
    if fsentry::is_component(name) {
        Ok(())
    } else {
        Err(ManagedDirError::Unsafe("not a single name"))
    }
}

/// The permission bits a managed file is written with (public, D10 item 2).
const FILE_MODE: u32 = 0o644;

/// A verified directory: the anchor, or an owner-only level below it (module docs).
/// Every name is resolved relative to it.
#[derive(Debug)]
pub struct ManagedDir {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(windows)]
    _pin: std::os::windows::io::OwnedHandle,
    #[cfg(windows)]
    final_path: std::path::PathBuf,
}

/// Whether `meta` is an owner-only directory (Unix: owned, no group or other bit).
#[cfg(unix)]
fn owner_only(meta: &fsentry::EntryMeta) -> Result<(), ManagedDirError> {
    if meta.kind != Kind::Directory {
        return Err(ManagedDirError::Unsafe("not a directory"));
    }
    if !meta.owned {
        return Err(ManagedDirError::Unsafe("not owned by the current user"));
    }
    if meta.perm & 0o077 != 0 {
        return Err(ManagedDirError::Unsafe("directory is not owner-only"));
    }
    Ok(())
}

impl ManagedDir {
    fn dir(&self) -> fsentry::Dir<'_> {
        #[cfg(unix)]
        {
            std::os::fd::AsFd::as_fd(&self.fd)
        }
        #[cfg(windows)]
        {
            &self.final_path
        }
    }

    /// Open the anchor `path` (module docs); `Ok(None)` when it does not exist.
    ///
    /// # Errors
    /// [`ManagedDirError`].
    pub fn open_root(path: &Path) -> Result<Option<Self>, ManagedDirError> {
        #[cfg(unix)]
        {
            let fd = match fsentry::open_dir_path(path) {
                Ok(fd) => fd,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    // `O_DIRECTORY|O_NOFOLLOW` on a symlink is `ELOOP` on Linux and
                    // `ENOTDIR` on macOS: the entry itself says which it is.
                    return Err(match std::fs::symlink_metadata(path) {
                        Ok(m) if m.file_type().is_symlink() => {
                            ManagedDirError::Unsafe("a symlink where a directory must be")
                        }
                        Ok(m) if !m.file_type().is_dir() => {
                            ManagedDirError::Unsafe("not a directory")
                        }
                        _ => sys("open", &e),
                    });
                }
            };
            let meta = fsentry::fstat(&fd, IdentitySource::Native).map_err(|e| sys("fstat", &e))?;
            if meta.kind != Kind::Directory {
                return Err(ManagedDirError::Unsafe("not a directory"));
            }
            if !meta.owned || meta.perm & 0o022 != 0 {
                return Err(ManagedDirError::Unsafe(
                    "anchor directory is not controlled by its owner",
                ));
            }
            Ok(Some(Self { fd }))
        }
        #[cfg(windows)]
        {
            let pin = match fsentry::win::open_dir_pinned(path, false) {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(sys("CreateFileW", &e)),
            };
            let meta =
                fsentry::win::meta(&pin).map_err(|e| sys("GetFileInformationByHandle", &e))?;
            match meta.kind {
                Kind::Directory => {}
                Kind::Symlink => {
                    return Err(ManagedDirError::Unsafe(
                        "a reparse point where a directory must be",
                    ));
                }
                _ => return Err(ManagedDirError::Unsafe("not a directory")),
            }
            if !meta.owned {
                return Err(ManagedDirError::Unsafe("not owned by the current user"));
            }
            let final_path =
                fsentry::win::final_path(&pin).map_err(|e| sys("GetFinalPathNameByHandleW", &e))?;
            Ok(Some(Self {
                _pin: pin,
                final_path,
            }))
        }
    }

    /// Open the owner-only directory `name` inside this one; when it is absent,
    /// create it owner-only if `create`, else `Ok(None)`. A symlink or reparse point,
    /// a non-directory, or an existing directory that is not owner-only is refused.
    ///
    /// # Errors
    /// [`ManagedDirError`].
    pub fn child(&self, name: &str, create: bool) -> Result<Option<Self>, ManagedDirError> {
        component(name)?;
        #[cfg(unix)]
        {
            let dir = self.dir();
            let (mut created, mut tried) = (false, false);
            let fd = loop {
                match fsentry::open_dir_at(dir, name) {
                    Ok(fd) => break fd,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        if !create || tried {
                            return Ok(None);
                        }
                        tried = true;
                        match rustix::fs::mkdirat(dir, name, fsentry::mode_of(0o700)) {
                            Ok(()) => created = true,
                            // A racing creator's entry: verified below like any other.
                            Err(rustix::io::Errno::EXIST) => {}
                            Err(e) => return Err(sys("mkdirat", &e.into())),
                        }
                    }
                    Err(e) => {
                        return Err(match fsentry::lstat(dir, name, IdentitySource::Native) {
                            Ok(Some(m)) if m.kind == Kind::Symlink => {
                                ManagedDirError::Unsafe("a symlink where a directory must be")
                            }
                            Ok(Some(m)) if m.kind != Kind::Directory => {
                                ManagedDirError::Unsafe("not a directory")
                            }
                            _ => sys("openat", &e),
                        });
                    }
                }
            };
            let mut meta =
                fsentry::fstat(&fd, IdentitySource::Native).map_err(|e| sys("fstat", &e))?;
            // Only a level this call created is set to 0700 (the umask may have narrowed
            // it); an existing one is never changed.
            if created && meta.kind == Kind::Directory && meta.owned && meta.perm != 0o700 {
                rustix::fs::fchmod(&fd, fsentry::mode_of(0o700))
                    .map_err(|e| sys("fchmod", &e.into()))?;
                meta = fsentry::fstat(&fd, IdentitySource::Native).map_err(|e| sys("fstat", &e))?;
            }
            owner_only(&meta)?;
            Ok(Some(Self { fd }))
        }
        #[cfg(windows)]
        {
            let path = self.final_path.join(name);
            if create {
                // An existing name is not an error; it is verified below like any other.
                fsentry::win::create_owner_only_dir(&path)
                    .map_err(|e| sys("CreateDirectoryW", &e))?;
            }
            let pin = match fsentry::win::open_dir_pinned(&path, false) {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(sys("CreateFileW", &e)),
            };
            let meta =
                fsentry::win::meta(&pin).map_err(|e| sys("GetFileInformationByHandle", &e))?;
            match meta.kind {
                Kind::Directory => {}
                Kind::Symlink => {
                    return Err(ManagedDirError::Unsafe(
                        "a reparse point where a directory must be",
                    ));
                }
                _ => return Err(ManagedDirError::Unsafe("not a directory")),
            }
            if !meta.owned {
                return Err(ManagedDirError::Unsafe("not owned by the current user"));
            }
            if !fsentry::win::dacl_is_owner_only(&pin).map_err(|e| sys("GetSecurityInfo", &e))? {
                return Err(ManagedDirError::Unsafe("directory DACL is not owner-only"));
            }
            let final_path =
                fsentry::win::final_path(&pin).map_err(|e| sys("GetFinalPathNameByHandleW", &e))?;
            Ok(Some(Self {
                _pin: pin,
                final_path,
            }))
        }
    }

    /// Whether `name` holds anything (never followed).
    ///
    /// # Errors
    /// [`ManagedDirError`].
    pub fn contains(&self, name: &str) -> Result<bool, ManagedDirError> {
        component(name)?;
        fsentry::lstat(self.dir(), name, IdentitySource::Native)
            .map(|m| m.is_some())
            .map_err(|e| sys("statat", &e))
    }

    /// Whether `name` is a directory (never followed): what an enumeration opens
    /// with [`Self::child`]; anything else (a symlink, a file) is not a managed level.
    ///
    /// # Errors
    /// [`ManagedDirError`].
    pub fn is_directory(&self, name: &str) -> Result<bool, ManagedDirError> {
        component(name)?;
        fsentry::lstat(self.dir(), name, IdentitySource::Native)
            .map(|m| m.is_some_and(|m| m.kind == Kind::Directory))
            .map_err(|e| sys("statat", &e))
    }

    /// The content of the regular file `name`, at most `max` bytes; `Ok(None)` when
    /// there is no entry. Something else than a regular file, or a longer file, is
    /// [`ManagedDirError::Unsafe`].
    ///
    /// # Errors
    /// [`ManagedDirError`].
    pub fn read(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>, ManagedDirError> {
        component(name)?;
        let (meta, file) = match fsentry::inspect(self.dir(), name, IdentitySource::Native) {
            Ok(None) => return Ok(None),
            Ok(Some(found)) => found,
            Err(e) => return Err(sys("openat", &e)),
        };
        let (Kind::Regular, Some(file)) = (meta.kind, file) else {
            return Err(ManagedDirError::Unsafe("not a regular file"));
        };
        match fsentry::read_bounded(&file) {
            Ok(Some(bytes)) if bytes.len() <= max.min(CONTENT_MAX) => Ok(Some(bytes)),
            Ok(_) => Err(ManagedDirError::Unsafe("file too large")),
            Err(e) => Err(sys("read", &e)),
        }
    }

    /// Write `content` to `name` atomically (module docs): a fresh exclusive temporary
    /// name, synced, renamed over `name` relative to this directory.
    ///
    /// # Errors
    /// [`ManagedDirError`]; the temporary name is removed on failure.
    pub fn write_replace(&self, name: &str, content: &[u8]) -> Result<(), ManagedDirError> {
        component(name)?;
        let temp = temp_name(name);
        let dir = self.dir();
        let written = (|| -> io::Result<()> {
            let mut f = fsentry::create_new(dir, &temp, FILE_MODE)?;
            f.write_all(content)?;
            f.sync_all()
        })();
        if let Err(e) = written {
            let _ = self.remove(&temp);
            return Err(sys("write", &e));
        }
        if let Err(e) = self.rename_over(&temp, name) {
            let _ = self.remove(&temp);
            return Err(e);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn rename_over(&self, temp: &str, name: &str) -> Result<(), ManagedDirError> {
        let dir = self.dir();
        if fsentry::lstat(dir, name, IdentitySource::Native)
            .map_err(|e| sys("statat", &e))?
            .is_some_and(|m| m.kind == Kind::Directory)
        {
            return Err(ManagedDirError::Unsafe("a directory where a file must be"));
        }
        rustix::fs::renameat(dir, temp, dir, name).map_err(|e| sys("renameat", &e.into()))?;
        fsentry::sync_dir(dir);
        Ok(())
    }

    #[cfg(windows)]
    fn rename_over(&self, temp: &str, name: &str) -> Result<(), ManagedDirError> {
        let dir = self.dir();
        match fsentry::lstat(dir, name, IdentitySource::Native).map_err(|e| sys("statat", &e))? {
            Some(m) if m.kind == Kind::Directory => {
                Err(ManagedDirError::Unsafe("a directory where a file must be"))
            }
            Some(_) => {
                // The M02 replace primitive with a backup name, removed after.
                let backup = temp_name(&format!("{name}.old"));
                fsentry::replace(dir, name, temp, &backup).map_err(|e| sys("ReplaceFileW", &e))?;
                let _ = self.remove(&backup);
                Ok(())
            }
            None => {
                fsentry::rename_noreplace(dir, temp, dir, name).map_err(|e| sys("MoveFileExW", &e))
            }
        }
    }

    /// Remove the regular file `name` from this directory. `Ok(false)` when there is
    /// no entry. **Through the crate's only removal** (ADR-0007 §5.3): the file's
    /// identity and digest are read on an open handle relative to this verified
    /// directory, the name is moved without replacement into this directory's
    /// validated `.hm-quarantine`, and [`QuarantineDir::remove_verified`] removes it
    /// only if it still has that identity and digest; the quarantine is then removed
    /// when empty. A symlink, a directory or any other non-regular entry at the name is
    /// refused (`managed_dir_unsafe`) and left as it is.
    ///
    /// # Errors
    /// [`ManagedDirError`]; an entry that changed between the read and the removal is
    /// left in the quarantine and refused.
    pub fn remove(&self, name: &str) -> Result<bool, ManagedDirError> {
        component(name)?;
        let dir = self.dir();
        let (meta, file) = match fsentry::inspect(dir, name, IdentitySource::Native) {
            Ok(None) => return Ok(false),
            Ok(Some(found)) => found,
            Err(e) => return Err(sys("openat", &e)),
        };
        let (Kind::Regular, Some(file)) = (meta.kind, file) else {
            return Err(ManagedDirError::Unsafe("not a regular file"));
        };
        if !meta.is_heimdall_shape() {
            return Err(ManagedDirError::Unsafe(
                "not a single-link file of the current user",
            ));
        }
        let digest = match fsentry::read_bounded(&file) {
            Ok(Some(bytes)) => Sha256Hex::of(&bytes),
            Ok(None) => return Err(ManagedDirError::Unsafe("file too large")),
            Err(e) => return Err(sys("read", &e)),
        };
        drop(file);
        let quarantine = self.quarantine()?;
        let parked = removal_name(name);
        match fsentry::rename_noreplace(dir, name, quarantine.dir(), &parked) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(sys("rename", &e)),
        }
        let outcome = quarantine
            .remove_verified(&parked, &meta.identity, digest.as_str())
            .map_err(ManagedDirError::Sys)?;
        // Best effort: an entry left behind keeps the quarantine.
        let _ = quarantine.rmdir_if_empty();
        match outcome {
            RemoveOutcome::Removed | RemoveOutcome::Missing => Ok(true),
            RemoveOutcome::IdentityMismatch | RemoveOutcome::ContentMismatch => Err(
                ManagedDirError::Unsafe("changed while being removed; left in the quarantine"),
            ),
        }
    }

    /// This directory's validated quarantine, created owner-only when absent.
    fn quarantine(&self) -> Result<QuarantineDir, ManagedDirError> {
        #[cfg(unix)]
        let q = QuarantineDir::open_or_create_in(self.dir(), IdentitySource::Native);
        #[cfg(windows)]
        let q = QuarantineDir::open_or_create_at(&self.final_path, IdentitySource::Native);
        q.map_err(|e| match e {
            QuarantineError::Invalid(why) => ManagedDirError::Unsafe(why),
            QuarantineError::Sys(s) => ManagedDirError::Sys(s),
        })
    }

    /// The names in this directory (UTF-8 names only; `.` and `..` excluded).
    ///
    /// # Errors
    /// [`ManagedDirError`].
    pub fn names(&self) -> Result<Vec<String>, ManagedDirError> {
        let mut out = Vec::new();
        #[cfg(unix)]
        {
            let entries =
                rustix::fs::Dir::read_from(&self.fd).map_err(|e| sys("fdopendir", &e.into()))?;
            for entry in entries {
                let entry = entry.map_err(|e| sys("readdir", &e.into()))?;
                if let Ok(name) = entry.file_name().to_str()
                    && name != "."
                    && name != ".."
                {
                    out.push(name.to_owned());
                }
            }
        }
        #[cfg(windows)]
        {
            let entries =
                std::fs::read_dir(&self.final_path).map_err(|e| sys("FindFirstFileW", &e))?;
            for entry in entries {
                let entry = entry.map_err(|e| sys("FindNextFileW", &e))?;
                if let Some(name) = entry.file_name().to_str() {
                    out.push(name.to_owned());
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn levels_are_created_owner_only_and_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ManagedDir::open_root(tmp.path()).unwrap().unwrap();
        let a = root.child("managed", true).unwrap().unwrap();
        assert_eq!(mode(&tmp.path().join("managed")), 0o700);
        a.write_replace("x.pub", b"one\n").unwrap();
        assert_eq!(mode(&tmp.path().join("managed/x.pub")), 0o644);
        assert_eq!(a.read("x.pub", 64).unwrap().unwrap(), b"one\n");
        a.write_replace("x.pub", b"two\n").unwrap();
        assert_eq!(a.read("x.pub", 64).unwrap().unwrap(), b"two\n");
        assert_eq!(a.names().unwrap(), vec!["x.pub".to_owned()]);
        assert!(a.remove("x.pub").unwrap());
        assert!(!a.remove("x.pub").unwrap());
        // The removal went through the quarantine, which is gone again once empty.
        assert!(a.names().unwrap().is_empty());
        assert!(root.child("absent", false).unwrap().is_none());
        assert!(root.child("../x", true).is_err());
    }

    #[test]
    fn symlinks_and_open_directories_are_refused_never_repaired() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join("link")).unwrap();
        let root = ManagedDir::open_root(tmp.path()).unwrap().unwrap();
        for create in [false, true] {
            assert!(matches!(
                root.child("link", create),
                Err(ManagedDirError::Unsafe(_))
            ));
        }
        std::fs::create_dir(tmp.path().join("open")).unwrap();
        std::fs::set_permissions(
            tmp.path().join("open"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(matches!(
            root.child("open", true),
            Err(ManagedDirError::Unsafe(_))
        ));
        assert_eq!(mode(&tmp.path().join("open")), 0o777, "never repaired");
        assert!(matches!(
            ManagedDir::open_root(&tmp.path().join("link")),
            Err(ManagedDirError::Unsafe(_))
        ));
        // A symlink at a file's name is read as what it is, never followed.
        std::fs::write(elsewhere.path().join("victim"), "v").unwrap();
        std::os::unix::fs::symlink(elsewhere.path().join("victim"), tmp.path().join("f")).unwrap();
        assert!(matches!(
            root.read("f", 64),
            Err(ManagedDirError::Unsafe(_))
        ));
        assert!(matches!(root.remove("f"), Err(ManagedDirError::Unsafe(_))));
        assert!(
            tmp.path().join("f").symlink_metadata().is_ok(),
            "left in place"
        );
        assert!(elsewhere.path().join("victim").exists());
    }
}
