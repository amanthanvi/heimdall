//! ⟨ADR-0008 §17.33 items 4-5, 10 (W5-E04, W5-E06, audit B3/B4); spec §14.3⟩ The purge's
//! anchored roots and anchored deletion.
//!
//! Every path `heimdall uninstall --purge-state` deletes is reached from one of two
//! **anchored roots**, the state directory and the runtime directory, opened **once**
//! ([`Anchors::open`]) and never re-resolved by a path at deletion time:
//! * `<state>`: the state database and its `-wal`, `-shm` and `-journal` files, the
//!   snapshots (`backups/`), and the pair slots (`managed/`);
//! * `<run>`: the binding directories with their endpoint sockets and files (`b/`), and
//!   the slots' stable multiplex paths (`mux/<destination>`, which `finish_slot` and
//!   `clear_slot_path` clear; the purge discards their cleanup records).
//!
//! **The secure path (audit B3; ADR-0008 §17.33 item 12, OpenSSH `StrictModes`).** A root
//! is reached from `/`, every component opened relative to the previous descriptor without
//! following a link (`O_NOFOLLOW | O_DIRECTORY`; a link root owns, such as macOS `/var`, is
//! followed and the directory it names checked), and [`check_chain`] applied to what each
//! descriptor shows: every ancestor owned by this user or root and not writable by group
//! or others (a sticky `/tmp` included); the root owned by this user and owner-only. A
//! linked, foreign or writable ancestor, or a replaced one, refuses.
//!
//! **One handle for everything (audit B3).** The purge takes `service.lock` relative to
//! the anchored `<state>` ([`Anchors::try_lock`], the same file runtime start-up locks),
//! and checks before and after its final read and bundle check that `<state>`'s path
//! still names the anchored directory and the database file under it
//! ([`Anchors::verify`], by device and inode); a swap (to a link or to another real
//! directory) refuses, nothing deleted.
//!
//! **No partial deletion (audit B4).** [`Anchors::purge`]: a check pass over every root
//! (it deletes nothing and refuses on any link or reparse point, on a database file that
//! is not a regular file), then a second check pass and the roots' identities re-verified
//! immediately before the first unlink, then the delete pass. A link that appears during
//! the delete pass itself is removed as a link (never followed). The lock file is never
//! deleted. A root that does not exist has nothing to delete.
//!
//! **Unix:** below each root, every entry is examined with `fstatat(AT_SYMLINK_NOFOLLOW)`,
//! every directory opened relative to its parent's descriptor, every removal is `unlinkat`
//! relative to the descriptor of the directory that holds it.
//!
//! **Windows:** every component of each root's path, from the volume down, is opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` and **without**
//! `FILE_SHARE_DELETE`, and held for the whole purge, so none of them can be renamed or
//! replaced meanwhile; any reparse point (a symlink or a junction) refuses. The lock, the
//! read and the deletion then go by path below those held handles
//! (`DeleteFileW`/`RemoveDirectoryW` never follow a reparse point: on one they remove the
//! link itself). **Named residual window ([`WINDOWS_RESIDUAL`]):** inside a root, between a
//! directory's handle being closed and its own `RemoveDirectoryW`, and between a file's
//! check and its `DeleteFileW`, the entry can be replaced in place by a same-user program;
//! the call then removes that replacement entry (never a reparse target outside the
//! roots).
//!
//! **Named residual ([`STATE_READ_RESIDUAL`], every platform):** SQLite opens the
//! database by path for the final read and the bundle check. A same-user program that
//! swaps `<state>` away **and back** entirely between the two identity checks around that
//! read makes the read see another database. Spec P03 does not claim isolation from a
//! hostile same-user program.

use std::path::Path;

/// The state database's file and its SQLite companions, under `<state>`.
const DB_SUFFIXES: [&str; 4] = ["", "-wal", "-shm", "-journal"];

/// The trees under `<state>` the purge deletes: the snapshots and the pair slots
/// (`heimdall_localenv::projection::content::managed_slot_paths`).
const STATE_TREES: [&str; 2] = ["backups", "managed"];

/// The trees under `<run>` the purge deletes: the binding directories
/// (`heimdall_credential::endpoints::BINDING_DIR`) and the stable multiplex paths
/// (`heimdall_localenv::projection::content::managed_mux_path`).
const RUN_TREES: [&str; 2] = ["b", "mux"];

/// The lock file runtime start-up locks (`heimdall_runtime::instance`).
#[cfg(unix)]
const LOCK_FILE: &str = "service.lock";

/// ⟨ADR-0008 §17.33 items 4, 7⟩ The Windows residual window, named (module docs).
// The name the claims table and ADR-0008 cite; nothing reads it at run time.
#[allow(dead_code)]
pub(crate) const WINDOWS_RESIDUAL: &str = "windows_purge_entry_replaced_between_check_and_delete";

/// ⟨ADR-0008 §17.33 items 8, 10⟩ The remaining `<state>` read residual, named (module docs).
#[allow(dead_code)]
pub(crate) const STATE_READ_RESIDUAL: &str =
    "uninstall_state_swapped_and_restored_during_final_read";

/// Why the purge refused.
fn refused(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("the purge refused: {what}"),
    )
}

/// ⟨ADR-0008 §17.33 item 12⟩ What a component of a purge root's path shows: its owner,
/// its permission bits (`0o7777`, the sticky bit included) and, when it was reached
/// through a link, the link's owner. (Windows applies [`check_windows_chain`] instead.)
#[cfg_attr(not(any(unix, test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Component {
    /// The directory's owner.
    pub(crate) uid: u32,
    /// Its permission bits.
    pub(crate) mode: u32,
    /// The owner of the link it was reached through, if any.
    pub(crate) link_uid: Option<u32>,
}

/// ⟨ADR-0008 §17.33 item 12, the secure-path rule (OpenSSH `StrictModes`)⟩ `chain` is a
/// purge root's path from `/` down to the root itself (the last entry); the first
/// `trusted` entries are not checked (the walk passes 1 for a debug-only trusted top,
/// which it checks itself: this user's, owner-only, not a link).
/// * every ancestor: owned by this user (`euid`) or by root, not writable by group or
///   others (a sticky directory such as `/tmp` included: no supported platform's default
///   layout puts a root directly in one, so the ruling's exception is not taken), and
///   reached through no link that is not root's;
/// * the root: owned by this user, owner-only (no group or other bits), not a link.
///
/// # Errors
/// What refuses, as a message.
#[cfg_attr(not(any(unix, test)), allow(dead_code))]
pub(crate) fn check_chain(
    chain: &[Component],
    euid: u32,
    trusted: usize,
) -> Result<(), &'static str> {
    let Some((root, ancestors)) = chain.split_last() else {
        return Err("a purge root has no path");
    };
    for c in ancestors.iter().skip(trusted) {
        if c.link_uid.is_some_and(|l| l != 0) {
            return Err("an ancestor of a purge root is a link that is not root's");
        }
        if c.uid != 0 && c.uid != euid {
            return Err("an ancestor of a purge root is owned by another user");
        }
        if c.mode & 0o022 != 0 {
            return Err(if c.mode & 0o1000 != 0 {
                "an ancestor of a purge root is a sticky directory others can write (such as /tmp)"
            } else {
                "an ancestor of a purge root is writable by group or others"
            });
        }
    }
    if root.link_uid.is_some() {
        return Err("a purge root is a link");
    }
    if root.uid != euid || root.mode & 0o077 != 0 {
        return Err("a purge root is not an owner-only directory of this user");
    }
    Ok(())
}

/// ⟨ADR-0008 §17.33 item 12, Windows⟩ The Windows rule over each component from the
/// volume down: no reparse point; each component's owner is checked by
/// [`windows_owner_passes`] (⟨§17.33 item 13⟩, through
/// `heimdall_ipc::windows::file_owner_sid`). The default layout is
/// `%LOCALAPPDATA%\\heimdall` (`Paths::platform_defaults`).
///
/// # Errors
/// What refuses, as a message.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn check_windows_chain(reparse: &[bool]) -> Result<(), &'static str> {
    if reparse.iter().any(|r| *r) {
        return Err("a purge root or one of its ancestors is a reparse point");
    }
    Ok(())
}

/// ⟨ADR-0008 §17.33 item 13⟩ Whether a Windows path component's owner SID passes: this
/// user's (`me`), SYSTEM (`S-1-5-18`) or the Administrators group (`S-1-5-32-544`);
/// anything else refuses. SID strings compare case-insensitively.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn windows_owner_passes(owner: &str, me: &str) -> bool {
    [me, "S-1-5-18", "S-1-5-32-544"]
        .iter()
        .any(|ok| owner.eq_ignore_ascii_case(ok))
}

/// The purge's anchored roots (module docs).
pub(crate) struct Anchors {
    inner: imp::Anchors,
}

/// The held `service.lock` (released when dropped).
pub(crate) struct LockGuard {
    _inner: imp::Lock,
}

impl Anchors {
    /// Open both roots through their trusted chains (module docs). `<state>` must exist;
    /// a missing `<run>` has nothing to delete.
    ///
    /// # Errors
    /// A refusal (a linked or replaced ancestor, a root that is not this user's) or I/O.
    pub(crate) fn open(
        state_dir: &Path,
        runtime_dir: &Path,
        top: Option<&Path>,
    ) -> std::io::Result<Anchors> {
        Ok(Anchors {
            inner: imp::Anchors::open(state_dir, runtime_dir, top)?,
        })
    }

    /// Take `service.lock` through the anchored `<state>`; `None` while another process
    /// (a runtime) holds it.
    ///
    /// # Errors
    /// I/O, or a lock file that is not a regular file.
    pub(crate) fn try_lock(&self) -> std::io::Result<Option<LockGuard>> {
        Ok(self.inner.try_lock()?.map(|l| LockGuard { _inner: l }))
    }

    /// `<state>`'s and `<run>`'s paths still name the anchored directories, and the
    /// database file at `<state>/<db_file>` is the one under the anchored `<state>`.
    ///
    /// # Errors
    /// A refusal on any difference.
    pub(crate) fn verify(&self, db_file: &str) -> std::io::Result<()> {
        self.inner.verify(db_file)
    }

    /// Delete everything the purge deletes (module docs), the state database last;
    /// `between` runs after the first check pass (tests schedule a change there; the
    /// command passes a no-op).
    ///
    /// # Errors
    /// A refusal before the first unlink (nothing deleted), or an I/O failure.
    pub(crate) fn purge(&self, db_file: &str, between: impl FnOnce()) -> std::io::Result<()> {
        self.inner.check(db_file)?;
        between();
        self.inner.check(db_file)?;
        self.inner.verify(db_file)?;
        self.inner.delete(db_file)
    }
}

#[cfg(unix)]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

    use super::{DB_SUFFIXES, LOCK_FILE, RUN_TREES, STATE_TREES, refused};

    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    /// The permission bits; the field type differs by platform.
    #[allow(clippy::unnecessary_cast)]
    fn mode_bits(st: &rustix::fs::Stat) -> u32 {
        st.st_mode as u32
    }

    /// An inode's identity (device, inode); the field types differ by platform.
    #[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
    fn id(st: &rustix::fs::Stat) -> (u64, u64) {
        (st.st_dev as u64, st.st_ino as u64)
    }

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// One anchored root.
    pub(super) struct Root {
        fd: OwnedFd,
        id: (u64, u64),
        path: PathBuf,
    }

    /// Open `target` from `/`, or from the debug-only trusted `top` (module docs), one
    /// component at a time relative to the previous one and never following a link that is
    /// not root's, then apply [`super::check_chain`] to what each descriptor shows; `None`
    /// when it does not exist.
    fn open_chain(target: &Path, top: Option<&Path>) -> std::io::Result<Option<Root>> {
        use std::path::Component as C;
        if !target.is_absolute() {
            return Err(refused("a purge root is not an absolute path"));
        }
        let (start, below) = match top {
            None => (Path::new("/"), target),
            Some(top) => {
                let below = target
                    .strip_prefix(top)
                    .ok()
                    .filter(|b| !b.as_os_str().is_empty() && top.is_absolute())
                    .ok_or_else(|| {
                        refused("the trusted top is not a strict ancestor of a purge root")
                    })?;
                (top, below)
            }
        };
        let names: Vec<&OsStr> = below
            .components()
            .filter_map(|c| match c {
                C::Normal(n) => Some(Ok(n)),
                C::RootDir => None,
                _ => Some(Err(())),
            })
            .collect::<Result<_, _>>()
            .map_err(|()| refused("a purge root's path is not normalized"))?;
        let component = |st: &rustix::fs::Stat, link_uid| super::Component {
            uid: st.st_uid,
            mode: mode_bits(st) & 0o7777,
            link_uid,
        };
        // `/` itself, or the trusted top: not a link, and (the top) this user's owner-only
        // directory; the rule applies from the next component down.
        let mut fd = rustix::fs::open(start, dir_flags(), Mode::empty()).map_err(|e| match e {
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
                refused("the trusted top is a link or not a directory")
            }
            e => e.into(),
        })?;
        let first = rustix::fs::fstat(&fd)?;
        if top.is_some() && (first.st_uid != euid() || mode_bits(&first) & 0o077 != 0) {
            return Err(refused(
                "the trusted top is not an owner-only directory of this user",
            ));
        }
        let mut chain = vec![component(&first, None)];
        let last = names.len().saturating_sub(1);
        for (i, name) in names.iter().enumerate() {
            let next = match rustix::fs::openat(&fd, *name, dir_flags(), Mode::empty()) {
                Ok(next) => {
                    chain.push(component(&rustix::fs::fstat(&next)?, None));
                    next
                }
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                    let link = rustix::fs::statat(&fd, *name, AtFlags::SYMLINK_NOFOLLOW)?;
                    if FileType::from_raw_mode(link.st_mode) != FileType::Symlink
                        || link.st_uid != 0
                        || i == last
                    {
                        chain.push(super::Component {
                            uid: link.st_uid,
                            mode: mode_bits(&link) & 0o7777,
                            link_uid: Some(link.st_uid),
                        });
                        break;
                    }
                    // A system link (root's, such as macOS `/var`): followed, and the
                    // directory it names is checked like any other.
                    let next = rustix::fs::openat(
                        &fd,
                        *name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    chain.push(component(&rustix::fs::fstat(&next)?, Some(0)));
                    next
                }
                Err(e) => return Err(e.into()),
            };
            fd = next;
        }
        // The trusted top was checked above by its own (stricter) rule.
        super::check_chain(&chain, euid(), usize::from(top.is_some())).map_err(refused)?;
        let st = rustix::fs::fstat(&fd)?;
        Ok(Some(Root {
            fd,
            id: id(&st),
            path: target.to_path_buf(),
        }))
    }

    pub(super) struct Anchors {
        state: Root,
        run: Option<Root>,
    }

    /// The held lock file.
    pub(super) struct Lock {
        _file: std::fs::File,
    }

    impl Anchors {
        pub(super) fn open(
            state_dir: &Path,
            runtime_dir: &Path,
            top: Option<&Path>,
        ) -> std::io::Result<Anchors> {
            let Some(state) = open_chain(state_dir, top)? else {
                return Err(refused("the state directory does not exist"));
            };
            Ok(Anchors {
                state,
                run: open_chain(runtime_dir, top)?,
            })
        }

        pub(super) fn try_lock(&self) -> std::io::Result<Option<Lock>> {
            let fd = rustix::fs::openat(
                &self.state.fd,
                LOCK_FILE,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|e| match e {
                rustix::io::Errno::LOOP => refused("the lock file is a link"),
                e => e.into(),
            })?;
            if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
                return Err(refused("the lock file is not a regular file"));
            }
            let file = std::fs::File::from(fd);
            match file.try_lock() {
                Ok(()) => Ok(Some(Lock { _file: file })),
                Err(std::fs::TryLockError::WouldBlock) => Ok(None),
                Err(std::fs::TryLockError::Error(e)) => Err(e),
            }
        }

        pub(super) fn verify(&self, db_file: &str) -> std::io::Result<()> {
            for r in std::iter::once(&self.state).chain(self.run.as_ref()) {
                let now = rustix::fs::stat(r.path.as_path())?;
                if id(&now) != r.id {
                    return Err(refused("a purge root was replaced"));
                }
            }
            let under = kind(&self.state.fd, OsStr::new(db_file))?;
            let by_path = match rustix::fs::lstat(self.state.path.join(db_file).as_path()) {
                Ok(st) => Some(id(&st)),
                Err(rustix::io::Errno::NOENT) => None,
                Err(e) => return Err(e.into()),
            };
            if under.map(|(_, d, i)| (d, i)) != by_path {
                return Err(refused("the state database's path names another file"));
            }
            Ok(())
        }

        pub(super) fn check(&self, db_file: &str) -> std::io::Result<()> {
            self.walk(db_file, false)
        }

        pub(super) fn delete(&self, db_file: &str) -> std::io::Result<()> {
            self.walk(db_file, true)
        }

        fn walk(&self, db_file: &str, delete: bool) -> std::io::Result<()> {
            if let Some(run) = &self.run {
                for t in RUN_TREES {
                    tree(&run.fd, OsStr::new(t), delete)?;
                }
            }
            for t in STATE_TREES {
                tree(&self.state.fd, OsStr::new(t), delete)?;
            }
            db(&self.state.fd, db_file, delete)
        }
    }

    /// The entry `name` in `dir`, examined without following it; `None` when absent.
    fn kind(dir: &OwnedFd, name: &OsStr) -> std::io::Result<Option<(FileType, u64, u64)>> {
        match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => Ok(Some((
                FileType::from_raw_mode(st.st_mode),
                id(&st).0,
                id(&st).1,
            ))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Walk (and with `delete`, remove) the tree `name` in `dir`, relative to
    /// descriptors only. Checking, a link anywhere refuses; deleting, a link is removed
    /// as a link (it appeared after both checks), never followed.
    fn tree(dir: &OwnedFd, name: &OsStr, delete: bool) -> std::io::Result<()> {
        let Some((ty, dev, ino)) = kind(dir, name)? else {
            return Ok(());
        };
        match ty {
            FileType::Symlink if !delete => Err(refused("a link inside a purged directory")),
            FileType::Directory => {
                let sub = match rustix::fs::openat(dir, name, dir_flags(), Mode::empty()) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) if !delete => {
                        return Err(refused("a directory was replaced by a link"));
                    }
                    Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                        rustix::fs::unlinkat(dir, name, AtFlags::empty())?;
                        return Ok(());
                    }
                    Err(e) => return Err(e.into()),
                };
                if id(&rustix::fs::fstat(&sub)?) != (dev, ino) {
                    return Err(refused("a directory was replaced while it was examined"));
                }
                let mut names: Vec<OsString> = Vec::new();
                for e in Dir::read_from(&sub)? {
                    let e = e?;
                    let n = e.file_name().to_bytes();
                    if n != b"." && n != b".." {
                        names.push(OsStr::from_bytes(n).to_owned());
                    }
                }
                for n in &names {
                    tree(&sub, n, delete)?;
                }
                if delete {
                    rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)?;
                }
                Ok(())
            }
            _ => {
                if delete {
                    rustix::fs::unlinkat(dir, name, AtFlags::empty())?;
                }
                Ok(())
            }
        }
    }

    /// The state database's files: each must be a regular file (or absent).
    fn db(state: &OwnedFd, db_file: &str, delete: bool) -> std::io::Result<()> {
        for suffix in DB_SUFFIXES {
            let name = OsString::from(format!("{db_file}{suffix}"));
            match kind(state, &name)? {
                None => {}
                Some((FileType::RegularFile, ..)) => {
                    if delete {
                        rustix::fs::unlinkat(state, &name, AtFlags::empty())?;
                    }
                }
                Some(_) if delete => rustix::fs::unlinkat(state, &name, AtFlags::empty())?,
                Some(_) => return Err(refused("a state database file is not a regular file")),
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};

    use super::{DB_SUFFIXES, RUN_TREES, STATE_TREES, refused};

    /// `FILE_FLAG_BACKUP_SEMANTICS` (open a directory).
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// `FILE_FLAG_OPEN_REPARSE_POINT` (never follow a reparse point).
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `FILE_SHARE_READ | FILE_SHARE_WRITE`, without `FILE_SHARE_DELETE`: while held,
    /// the entry cannot be renamed or deleted (so not replaced).
    const SHARE_NO_DELETE: u32 = 0x1 | 0x2;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    /// `FILE_ATTRIBUTE_DIRECTORY`.
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    /// Open `path` without following a reparse point and pin it (no share-delete); its
    /// attributes from the handle. `None` when absent.
    fn pin(path: &Path) -> std::io::Result<Option<(std::fs::File, u32)>> {
        let f = match std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_NO_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let attrs = f.metadata()?.file_attributes();
        Ok(Some((f, attrs)))
    }

    /// Pin every component of `root`'s path from the volume down, refusing on any
    /// reparse point; `None` when the root does not exist.
    fn pin_chain(root: &Path) -> std::io::Result<Option<Vec<std::fs::File>>> {
        let me = heimdall_ipc::windows::current_user_sid()?;
        let mut held = Vec::new();
        let chain: Vec<PathBuf> = root.ancestors().map(Path::to_path_buf).collect();
        for p in chain.iter().rev() {
            if p.parent().is_none() {
                continue; // the volume root itself
            }
            match pin(p)? {
                None => return Ok(None),
                Some((_, attrs)) if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                    return Err(refused(
                        super::check_windows_chain(&[true])
                            .err()
                            .unwrap_or("a reparse point"),
                    ));
                }
                Some((_, attrs)) if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 => {
                    return Err(refused(
                        "a purge root or one of its ancestors is not a directory",
                    ));
                }
                Some((f, _)) => {
                    let owner = heimdall_ipc::windows::file_owner_sid(&f)?;
                    if !super::windows_owner_passes(&owner, &me) {
                        return Err(refused(
                            "a purge root or one of its ancestors is owned by another user (not this user, SYSTEM or Administrators)",
                        ));
                    }
                    held.push(f);
                }
            }
        }
        Ok(Some(held))
    }

    pub(super) struct Anchors {
        state: PathBuf,
        run: Option<PathBuf>,
        _held: Vec<std::fs::File>,
    }

    /// The held lock (the runtime's own lock type, by path below the pinned chain).
    pub(super) struct Lock {
        _lock: heimdall_runtime::InstanceLock,
    }

    impl Anchors {
        pub(super) fn open(
            state_dir: &Path,
            runtime_dir: &Path,
            _top: Option<&Path>,
        ) -> std::io::Result<Anchors> {
            let Some(mut held) = pin_chain(state_dir)? else {
                return Err(refused("the state directory does not exist"));
            };
            let run = match pin_chain(runtime_dir)? {
                Some(h) => {
                    held.extend(h);
                    Some(runtime_dir.to_path_buf())
                }
                None => None,
            };
            Ok(Anchors {
                state: state_dir.to_path_buf(),
                run,
                _held: held,
            })
        }

        pub(super) fn try_lock(&self) -> std::io::Result<Option<Lock>> {
            use heimdall_runtime::instance::InstanceError;
            match heimdall_runtime::InstanceLock::try_acquire(&self.state) {
                Ok(l) => Ok(Some(Lock { _lock: l })),
                Err(InstanceError::AlreadyRunning) => Ok(None),
                Err(InstanceError::Io(e)) => Err(e),
            }
        }

        /// The chain is pinned: nothing on it can be renamed or replaced while held.
        pub(super) fn verify(&self, _db_file: &str) -> std::io::Result<()> {
            Ok(())
        }

        pub(super) fn check(&self, db_file: &str) -> std::io::Result<()> {
            self.walk(db_file, false)
        }

        pub(super) fn delete(&self, db_file: &str) -> std::io::Result<()> {
            self.walk(db_file, true)
        }

        fn walk(&self, db_file: &str, delete: bool) -> std::io::Result<()> {
            if let Some(run) = &self.run {
                for t in RUN_TREES {
                    tree(&run.join(t), delete)?;
                }
            }
            for t in STATE_TREES {
                tree(&self.state.join(t), delete)?;
            }
            for suffix in DB_SUFFIXES {
                let p = self.state.join(format!("{db_file}{suffix}"));
                match pin(&p)? {
                    None => {}
                    Some((h, attrs))
                        if attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                            == 0 =>
                    {
                        drop(h);
                        if delete {
                            std::fs::remove_file(&p)?;
                        }
                    }
                    Some(_) => {
                        return Err(refused("a state database file is not a regular file"));
                    }
                }
            }
            Ok(())
        }
    }

    fn tree(path: &Path, delete: bool) -> std::io::Result<()> {
        let Some((handle, attrs)) = pin(path)? else {
            return Ok(());
        };
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            if !delete {
                return Err(refused(
                    "a reparse point (link or junction) in a purged path",
                ));
            }
            // Appeared after both checks: removed as a link, never followed.
            drop(handle);
            return if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                std::fs::remove_dir(path)
            } else {
                std::fs::remove_file(path)
            };
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            drop(handle);
            if delete {
                std::fs::remove_file(path)?;
            }
            return Ok(());
        }
        for e in std::fs::read_dir(path)? {
            tree(&e?.path(), delete)?;
        }
        // The named residual window (module docs): the handle closes before the
        // directory itself is removed.
        drop(handle);
        if delete {
            std::fs::remove_dir(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The residual's name here is the one the claims table's `RESIDUALS` lists
    /// (ADR-0008 §17.33 item 7).
    #[test]
    fn the_windows_residual_is_listed() {
        assert!(
            heimdall_domain::claims::RESIDUALS
                .iter()
                .any(|r| r.id == WINDOWS_RESIDUAL && r.platform.os == "windows")
        );
    }

    /// Both named residuals are listed (ADR-0008 §17.33 items 7, 10).
    #[test]
    fn the_state_read_residual_is_listed() {
        assert!(
            heimdall_domain::claims::RESIDUALS
                .iter()
                .any(|r| r.id == STATE_READ_RESIDUAL)
        );
    }

    /// Owner-only directories `state`, `run` (with `b/`, `mux/`) and `outside` in a fresh
    /// owner-only scratch directory, a database file and a snapshot.
    #[cfg(unix)]
    fn roots() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let state = d.path().join("state");
        let run = d.path().join("run");
        for p in [d.path(), &state, &run] {
            std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("{e}"));
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        for p in [
            run.join("b").join("t"),
            run.join("mux"),
            state.join("backups"),
        ] {
            std::fs::create_dir_all(&p).unwrap_or_else(|e| panic!("{e}"));
            std::fs::write(p.join("f"), b"x").unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(state.join("state.db"), b"db").unwrap_or_else(|e| panic!("{e}"));
        (d, state, run)
    }

    /// `uninstall_purge_link_between_passes_deletes_nothing` (ADR-0008 §17.33 item 10,
    /// audit B4): a link that appears in `<state>/managed` after the first check pass is
    /// refused by the second, before the first unlink: `b`, `mux`, `backups` and the
    /// database are all still there, and the link's target is untouched.
    #[cfg(unix)]
    #[test]
    fn uninstall_purge_link_between_passes_deletes_nothing() {
        let (d, state, run) = roots();
        let outside = d.path().join("outside");
        std::fs::create_dir(&outside).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(outside.join("keep"), b"x").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let end = anchors.purge("state.db", || {
            std::os::unix::fs::symlink(&outside, state.join("managed"))
                .unwrap_or_else(|e| panic!("{e}"));
        });
        assert!(end.is_err(), "refused");
        for p in [
            run.join("b").join("t").join("f"),
            run.join("mux").join("f"),
            state.join("backups").join("f"),
            state.join("state.db"),
        ] {
            assert!(p.exists(), "{} was deleted", p.display());
        }
        assert!(outside.join("keep").exists());
    }

    // --- ADR-0008 §17.33 item 12: the secure-path rule ---------------------------------

    const ME: u32 = 501;

    fn dir(uid: u32, mode: u32) -> Component {
        Component {
            uid,
            mode,
            link_uid: None,
        }
    }

    fn via_link(link_uid: u32, uid: u32, mode: u32) -> Component {
        Component {
            uid,
            mode,
            link_uid: Some(link_uid),
        }
    }

    /// `secure_path_accepts_the_macos_default_layouts`: `~/.local/state/heimdall` (and its
    /// `run`) as `Paths::platform_defaults` resolves it on macOS, with this Mac's observed
    /// owners and modes (`/` and `/Users` root 0755, the home and `~/.local/state` this
    /// user's 0755), and a root under the per-user `TMPDIR` (`/var`, root's link, to
    /// `/private/var`; `/var/folders` and its first level root 0755; the per-user level this
    /// user's 0755, `T` 0700).
    #[test]
    fn secure_path_accepts_the_macos_default_layouts() {
        let state = [
            dir(0, 0o755),
            dir(0, 0o755),
            dir(ME, 0o755),
            dir(ME, 0o755),
            dir(ME, 0o755),
            dir(ME, 0o700),
        ];
        assert_eq!(check_chain(&state, ME, 0), Ok(()));
        let mut run = state.to_vec();
        run.push(dir(ME, 0o700));
        assert_eq!(check_chain(&run, ME, 0), Ok(()));
        let tmpdir = [
            dir(0, 0o755),
            via_link(0, 0, 0o755),
            dir(0, 0o755),
            dir(0, 0o755),
            dir(ME, 0o755),
            dir(ME, 0o700),
        ];
        assert_eq!(check_chain(&tmpdir, ME, 0), Ok(()));
    }

    /// `secure_path_accepts_the_linux_default_layouts`: `~/.local/state/heimdall` (`/home`
    /// root 0755, the home this user's 0700) and `$XDG_RUNTIME_DIR/heimdall` under
    /// `/run/user/<uid>` (`/run` and `/run/user` root 0755, `<uid>` this user's 0700).
    #[test]
    fn secure_path_accepts_the_linux_default_layouts() {
        let state = [
            dir(0, 0o755),
            dir(0, 0o755),
            dir(ME, 0o700),
            dir(ME, 0o755),
            dir(ME, 0o755),
            dir(ME, 0o700),
        ];
        assert_eq!(check_chain(&state, ME, 0), Ok(()));
        let run = [
            dir(0, 0o755),
            dir(0, 0o755),
            dir(0, 0o755),
            dir(ME, 0o700),
            dir(ME, 0o700),
        ];
        assert_eq!(check_chain(&run, ME, 0), Ok(()));
    }

    /// `secure_path_accepts_the_windows_default_layout`: `%LOCALAPPDATA%\heimdall`
    /// (`C:\Users\<name>\AppData\Local\heimdall`, no reparse point on the way) passes;
    /// any reparse point refuses.
    #[test]
    fn secure_path_accepts_the_windows_default_layout() {
        assert_eq!(check_windows_chain(&[false; 5]), Ok(()));
        assert!(check_windows_chain(&[false, false, true, false, false]).is_err());
    }

    /// `secure_path_refuses_unsafe_ancestors_and_roots`: a group-writable ancestor, an
    /// other-writable one, a sticky `/tmp`-style parent (no exception is taken), one owned
    /// by another non-root user, a link this user owns; and a root that is not owner-only,
    /// not this user's, or a link.
    #[test]
    fn secure_path_refuses_unsafe_ancestors_and_roots() {
        let with = |ancestor: Component| [dir(0, 0o755), ancestor, dir(ME, 0o700)];
        for (bad, why) in [
            (dir(ME, 0o775), "group"),
            (dir(ME, 0o757), "others"),
            (dir(0, 0o1777), "sticky"),
            (dir(1000, 0o755), "another user"),
            (via_link(ME, ME, 0o755), "link"),
        ] {
            let Err(e) = check_chain(&with(bad), ME, 0) else {
                panic!("{why}: accepted");
            };
            assert!(e.contains(why), "{why}: {e}");
        }
        for root in [dir(ME, 0o750), dir(0, 0o700), via_link(ME, ME, 0o700)] {
            assert!(
                check_chain(&[dir(0, 0o755), root], ME, 0).is_err(),
                "{root:?}"
            );
        }
    }

    /// The same rule on real synthetic trees: owner-only roots under ancestors of this
    /// user's that others cannot write pass; making one ancestor group-writable refuses.
    #[cfg(unix)]
    #[test]
    fn secure_path_on_synthetic_trees() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let chmod = |p: &std::path::Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m))
                .unwrap_or_else(|e| panic!("{e}"));
        };
        // Linux-style: home/.local/state/heimdall and run/user/<uid>/heimdall.
        let home = d.path().join("home");
        let state = home.join(".local").join("state").join("heimdall");
        let run = d
            .path()
            .join("run")
            .join("user")
            .join("1000")
            .join("heimdall");
        for p in [&state, &run] {
            std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("{e}"));
        }
        // The scratch base is the trusted top: owner-only.
        chmod(d.path(), 0o700);
        for p in [
            &home,
            &home.join(".local"),
            &home.join(".local").join("state"),
            &d.path().join("run"),
            &d.path().join("run").join("user"),
        ] {
            chmod(p, 0o755);
        }
        for p in [
            &state,
            &run,
            &d.path().join("run").join("user").join("1000"),
        ] {
            chmod(p, 0o700);
        }
        assert!(Anchors::open(&state, &run, Some(d.path())).is_ok());
        chmod(&home.join(".local"), 0o775);
        assert!(
            Anchors::open(&state, &run, Some(d.path())).is_err(),
            "a group-writable ancestor refuses"
        );
        chmod(&home.join(".local"), 0o755);
        chmod(&d.path().join("run").join("user"), 0o1777);
        assert!(
            Anchors::open(&state, &run, Some(d.path())).is_err(),
            "a sticky parent refuses"
        );
    }

    /// `secure_path_full_chain_from_root_without_the_hook` (ADR-0008 §17.33 item 14): with
    /// no trusted top the check runs from `/`; on macOS the per-user temporary directory's
    /// chain passes it (observed: `/var` root's link, `/private/var/folders` root 0755, the
    /// per-user level this user's 0755, `T` 0700). Linux test hosts keep scratch under the
    /// sticky `/tmp`, which the rule refuses, so this runs on macOS only.
    #[cfg(target_os = "macos")]
    #[test]
    fn secure_path_full_chain_from_root_without_the_hook() {
        let (_d, state, run) = roots();
        assert!(Anchors::open(&state, &run, None).is_ok());
    }

    /// `purge_trusted_top_conditions` (ADR-0008 §17.33 item 14): the debug-only trusted
    /// top must be a strict ancestor of both roots (the root itself, or a directory beside
    /// them, refuses) and this user's owner-only directory (a group-writable top refuses);
    /// below it every component is still checked (a group-writable one refuses).
    #[cfg(unix)]
    #[test]
    fn purge_trusted_top_conditions() {
        use std::os::unix::fs::PermissionsExt as _;
        let (d, state, run) = roots();
        let chmod = |p: &std::path::Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m))
                .unwrap_or_else(|e| panic!("{e}"));
        };
        assert!(Anchors::open(&state, &run, Some(d.path())).is_ok());
        assert!(
            Anchors::open(&state, d.path(), Some(d.path())).is_err(),
            "not a strict ancestor (the top is a root itself)"
        );
        let beside = d.path().join("beside");
        std::fs::create_dir(&beside).unwrap_or_else(|e| panic!("{e}"));
        chmod(&beside, 0o700);
        assert!(
            Anchors::open(&state, &run, Some(&beside)).is_err(),
            "not an ancestor"
        );
        chmod(d.path(), 0o770);
        assert!(
            Anchors::open(&state, &run, Some(d.path())).is_err(),
            "a group-writable top"
        );
        chmod(d.path(), 0o750);
        assert!(
            Anchors::open(&state, &run, Some(d.path())).is_err(),
            "a top that is not owner-only"
        );
        chmod(d.path(), 0o700);
        // Below the top: a group-writable component.
        let deep = d.path().join("mid");
        let (s2, r2) = (deep.join("state"), deep.join("run"));
        for p in [&s2, &r2] {
            std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("{e}"));
            chmod(p, 0o700);
        }
        chmod(&deep, 0o775);
        assert!(
            Anchors::open(&s2, &r2, Some(d.path())).is_err(),
            "a group-writable component below the top"
        );
        chmod(&deep, 0o755);
        assert!(Anchors::open(&s2, &r2, Some(d.path())).is_ok());
    }

    /// `windows_owner_classification` (ADR-0008 §17.33 item 13): this user's SID, SYSTEM
    /// and Administrators pass (any case); another user's, Everyone's or Users' refuse.
    #[test]
    fn windows_owner_classification() {
        let me = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        for ok in [me, "S-1-5-18", "S-1-5-32-544", "s-1-5-18"] {
            assert!(windows_owner_passes(ok, me), "{ok}");
        }
        for bad in [
            "S-1-5-21-1111111111-2222222222-3333333333-1002",
            "S-1-1-0",
            "S-1-5-32-545",
            "",
        ] {
            assert!(!windows_owner_passes(bad, me), "{bad}");
        }
    }

    /// A linked ancestor of a root refuses the anchoring itself (audit B3).
    #[cfg(unix)]
    #[test]
    fn a_linked_ancestor_refuses_the_anchoring() {
        let (d, state, run) = roots();
        let link = d.path().join("via");
        std::os::unix::fs::symlink(d.path(), &link).unwrap_or_else(|e| panic!("{e}"));
        assert!(Anchors::open(&link.join("state"), &link.join("run"), Some(d.path())).is_err());
        assert!(Anchors::open(&state, &run, Some(d.path())).is_ok());
    }

    /// `windows_purge_refuses_a_junction_and_names_its_residual` (ADR-0008 §17.33
    /// items 4 and 7; native Windows only): a junction where the pair slots live
    /// (`<state>/managed`) refuses the purge before anything is deleted, the junction's
    /// target is untouched, and the residual window this code leaves is the one
    /// `RESIDUALS` names.
    #[cfg(windows)]
    #[test]
    fn windows_purge_refuses_a_junction_and_names_its_residual() {
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let state = d.path().join("state");
        let run = d.path().join("run");
        let outside = d.path().join("outside");
        for p in [&state, &run, &outside] {
            std::fs::create_dir(p).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(outside.join("keep"), b"x").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(state.join("state.db"), b"db").unwrap_or_else(|e| panic!("{e}"));
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(state.join("managed"))
            .arg(&outside)
            .status()
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(made.success(), "the junction fixture");
        let refused = Anchors::open(&state, &run, None).and_then(|a| a.purge("state.db", || {}));
        assert!(refused.is_err(), "refused");
        assert!(outside.join("keep").exists(), "nothing outside is touched");
        assert!(state.join("state.db").exists(), "nothing was deleted");
        the_windows_residual_is_listed();
    }
}
