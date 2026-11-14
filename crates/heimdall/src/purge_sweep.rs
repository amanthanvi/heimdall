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
//! and checks that `<state>`'s and `<run>`'s paths still name the anchored directories
//! ([`Anchors::verify`], by device and inode); a swap refuses, nothing deleted.
//!
//! **Quarantine, validate, delete (ADR-0008 §17.34 item 1; W5-F01, F02; the audit's
//! C0-C4).** [`Anchors::quarantine`]: every entry the purge removes (the database and its
//! `-wal`/`-shm`/`-journal`, `backups`, `managed`, `b`, `mux`) is inspected (each path
//! below it with its kind and identity; any link or reparse point refuses), then renamed
//! atomically and **never over anything** (Linux `RENAME_NOREPLACE`, macOS `RENAME_EXCL`,
//! Windows `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`) to a fresh random quarantine
//! name in its own anchored directory, then checked again under that name against what was
//! inspected (and every target absent at the inspection must still be absent). Then the
//! database, its `-wal` and its `-shm` are **held** at their quarantine names (a moved
//! one opened and required to be the inspected inode; an absent one created empty by the
//! purge with `O_EXCL`; Windows: all three pinned, no share-delete). The final read, the
//! snapshot comparison and the bundle check run against that quarantined database
//! ([`Quarantine::read_db`]), and before its store is dropped the read is confirmed: Unix,
//! a census of this process's regular-file descriptors finds exactly one more descriptor
//! of each held file (the ones SQLite opened, so it read those very inodes) and each
//! quarantine name still names its held file; Windows, the three are still pinned and
//! named. Then everything is checked again ([`Quarantine::validate`]) and only the
//! quarantine names are unlinked ([`Quarantine::delete`]): the trees first, the database's
//! files last, and on a failure part-way every entry not yet started is renamed back and
//! every entry left at a quarantine name reported. On any difference before the deletion
//! everything is renamed back ([`Quarantine::restore`]) and the purge refuses with nothing
//! deleted; an entry that cannot be renamed back stays in quarantine and its exact path is
//! reported. **What remains (the `RESIDUALS` entry
//! `purge_entry_placed_in_quarantine_is_deleted`):** a same-user program that finds a
//! random quarantine name can add its own entry inside a quarantined directory, or put its
//! own entry at a quarantine name, after the last check, and the deletion removes that
//! entry it placed; data at an inspected path is never removed. The lock file is never
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
//! read and the deletion then go by path below those held handles. The deletion pins each
//! entry, checks it against its inspected file ID, and keeps a directory pinned while it
//! is listed and emptied (so it cannot become a junction meanwhile); `DeleteFileW` and
//! `RemoveDirectoryW` never follow a reparse point (on one they remove the link itself),
//! so nothing outside the roots is reached. **Named residual window
//! ([`WINDOWS_RESIDUAL`]):** between an entry's unpinning and its removal, a same-user
//! program that found its random quarantine path can replace it with its own entry or
//! link, which is then removed.
//!
//! Spec P03 does not claim isolation from a hostile same-user program.

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
    /// ⟨§17.34 item 2⟩ The directory's group.
    pub(crate) gid: u32,
}

/// ⟨ADR-0008 §17.34 item 2 (W5-F03)⟩ This user's private group, as
/// `heimdall_runtime::platform::user_private_group` found it.
#[cfg_attr(not(any(unix, test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateGroup {
    /// The lookup failed: a group-writable ancestor cannot be judged, so it refuses.
    Unavailable,
    /// The primary group is not a user private group.
    None,
    /// The user's private group (primary, named as the user, no other member).
    Gid(u32),
}

/// ⟨ADR-0008 §17.33 item 12, the secure-path rule (OpenSSH `StrictModes`)⟩ `chain` is a
/// purge root's path from `/` down to the root itself (the last entry); the first
/// `trusted` entries are not checked (the walk passes 1 for a debug-only trusted top,
/// which it checks itself: this user's, owner-only, not a link).
/// * every ancestor: owned by this user (`euid`) or by root, not writable by group or
///   others (a sticky directory such as `/tmp` included: no supported platform's default
///   layout puts a root directly in one, so the ruling's exception is not taken), and
///   reached through no link that is not root's. ⟨§17.34 item 2⟩ The one exception,
///   OpenSSH's Debian `user-group-modes`: writable by its group (never by others) when
///   that group is this user's private group (`private`);
/// * the root: owned by this user, owner-only (no group or other bits), not a link.
///
/// # Errors
/// The index in `chain` of the component that refuses, and why.
#[cfg_attr(not(any(unix, test)), allow(dead_code))]
pub(crate) fn check_chain(
    chain: &[Component],
    euid: u32,
    trusted: usize,
    private: PrivateGroup,
) -> Result<(), (usize, &'static str)> {
    let Some((root, ancestors)) = chain.split_last() else {
        return Err((0, "a purge root has no path"));
    };
    for (i, c) in ancestors.iter().enumerate().skip(trusted) {
        if c.link_uid.is_some_and(|l| l != 0) {
            return Err((
                i,
                "an ancestor of a purge root is a link that is not root's",
            ));
        }
        if c.uid != 0 && c.uid != euid {
            return Err((i, "an ancestor of a purge root is owned by another user"));
        }
        if c.mode & 0o002 != 0 {
            return Err((
                i,
                if c.mode & 0o1000 != 0 {
                    "an ancestor of a purge root is a sticky directory others can write (such as /tmp)"
                } else {
                    "an ancestor of a purge root is writable by others"
                },
            ));
        }
        if c.mode & 0o020 != 0 {
            match private {
                PrivateGroup::Gid(g) if g == c.gid => {}
                PrivateGroup::Unavailable => {
                    return Err((
                        i,
                        "an ancestor of a purge root is group-writable and this user's group cannot be looked up",
                    ));
                }
                _ => {
                    return Err((
                        i,
                        "an ancestor of a purge root is writable by a group that is not this user's private group",
                    ));
                }
            }
        }
    }
    let r = chain.len() - 1;
    if root.link_uid.is_some() {
        return Err((r, "a purge root is a link"));
    }
    if root.uid != euid || root.mode & 0o077 != 0 {
        return Err((
            r,
            "a purge root is not an owner-only directory of this user",
        ));
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

    /// ⟨ADR-0008 §17.34 item 1⟩ Inspect every entry the purge will remove (refusing on
    /// any link or reparse point, or a database file that is not a regular file), then
    /// `between` (tests schedule a change there; the command passes a no-op), then rename
    /// each entry to a fresh random quarantine name in its own anchored directory, and
    /// check every quarantined entry against what was inspected. On any difference the
    /// entries are renamed back and the purge refuses ([`QuarantineError`]).
    ///
    /// # Errors
    /// A refusal, with any entry a rename-back could not restore.
    pub(crate) fn quarantine(
        &self,
        db_file: &str,
        between: impl FnOnce(),
    ) -> Result<Quarantine<'_>, QuarantineError> {
        Ok(Quarantine {
            anchors: self,
            inner: self.inner.quarantine(db_file, between)?,
        })
    }

    /// Quarantine, validate and delete in one go (the deletion without a database read).
    ///
    /// # Errors
    /// As [`Anchors::quarantine`] and [`Quarantine::delete`].
    #[cfg(test)]
    pub(crate) fn purge(&self, db_file: &str, between: impl FnOnce()) -> std::io::Result<()> {
        let q = self
            .quarantine(db_file, between)
            .map_err(QuarantineError::into_io)?;
        q.delete().map_err(QuarantineError::into_io)
    }
}

/// ⟨ADR-0008 §17.34 item 1⟩ Why the quarantine refused: the cause, and the exact paths of
/// any entry a rename-back could not restore (left in quarantine).
#[derive(Debug)]
pub(crate) struct QuarantineError {
    /// The cause.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) cause: std::io::Error,
    /// Entries left at their quarantine names.
    pub(crate) stuck: Vec<std::path::PathBuf>,
}

#[cfg(test)]
impl QuarantineError {
    fn into_io(self) -> std::io::Error {
        self.cause
    }
}

/// ⟨ADR-0008 §17.34 item 1⟩ The quarantined entries: validated against what was
/// inspected; deleted only by [`Quarantine::delete`], or renamed back by
/// [`Quarantine::restore`].
pub(crate) struct Quarantine<'a> {
    anchors: &'a Anchors,
    inner: imp::Quarantine,
}

impl Quarantine<'_> {
    /// ⟨ADR-0008 §17.34 item 1; audit C0⟩ `open` the **quarantined** database by its
    /// quarantine name in the anchored directory (Unix: resolved from the held handle,
    /// wherever the directory is now), then `read` it; the database, its `-wal` and its
    /// `-shm` are held at their quarantine names throughout (a moved one checked against
    /// its inspected identity, an absent one created empty by the purge). Before what
    /// `open` returned is dropped the read is **confirmed**: Unix, a census of this
    /// process's regular-file descriptors finds exactly one more descriptor of each held
    /// file than before the open (the ones SQLite opened), and each quarantine name still
    /// names its held file; Windows, the three stay pinned (no share-delete) and still
    /// named. `None` when there is no database; else `read`'s result and the
    /// confirmation (`Err`: what was read is not what is deleted).
    ///
    /// # Errors
    /// The census could not be taken.
    pub(crate) fn read_db<S, T>(
        &self,
        open: impl FnOnce(&Path) -> S,
        read: impl FnOnce(&S) -> T,
    ) -> std::io::Result<Option<(T, std::io::Result<()>)>> {
        self.inner.read_db(&self.anchors.inner, open, read)
    }

    /// Check every quarantined entry against what was inspected, again.
    ///
    /// # Errors
    /// A refusal on any difference.
    pub(crate) fn validate(&self) -> std::io::Result<()> {
        self.inner.validate(&self.anchors.inner)
    }

    /// Delete the quarantined entries (by their quarantine names only): the trees first,
    /// the database's files last. ⟨audit C1⟩ When a deletion fails part-way, every entry
    /// not yet started (and a failed single file) is renamed back, never over anything,
    /// and the error lists every entry left at a quarantine name.
    ///
    /// # Errors
    /// An I/O failure, with the entries left in quarantine.
    pub(crate) fn delete(self) -> Result<(), QuarantineError> {
        self.inner.delete(&self.anchors.inner)
    }

    /// Rename every quarantined entry back. `Err` with the exact paths of the entries
    /// that could not be restored (they stay at their quarantine names).
    pub(crate) fn restore(self) -> Result<(), Vec<std::path::PathBuf>> {
        self.inner.restore(&self.anchors.inner)
    }
}

/// A fresh random tag (32 hex digits) for one quarantine.
fn quarantine_tag() -> String {
    use std::hash::BuildHasher as _;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let a = std::hash::RandomState::new().hash_one((nanos, std::process::id(), 1u8));
    let b = std::hash::RandomState::new().hash_one((nanos, std::process::id(), 2u8));
    format!("{a:016x}{b:016x}")
}

/// The quarantine name of `name`: `.hm-purge-<tag>-<name>` (so the database's `-wal`,
/// `-shm` and `-journal` keep their names next to the quarantined database's, and SQLite
/// reads the log that belongs to it).
fn quarantine_name(tag: &str, name: &std::ffi::OsStr) -> std::ffi::OsString {
    let mut q = std::ffi::OsString::from(format!(".hm-purge-{tag}-"));
    q.push(name);
    q
}

#[cfg(test)]
thread_local! {
    /// ⟨ADR-0008 §17.34 item 1, tests only⟩ When set on this thread, every rename-back
    /// fails (to show a failed restore leaves the entry in quarantine and is reported).
    pub(crate) static FAIL_RESTORE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn restore_fails() -> bool {
    FAIL_RESTORE.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn restore_fails() -> bool {
    false
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
            gid: st.st_gid,
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
                            gid: link.st_gid,
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
        // ⟨§17.34 item 2⟩ The private group is looked up only when an ancestor is
        // group-writable.
        let private = if chain.iter().any(|c| c.mode & 0o020 != 0) {
            match heimdall_runtime::platform::user_private_group() {
                Ok(Some(g)) => super::PrivateGroup::Gid(g),
                Ok(None) => super::PrivateGroup::None,
                Err(_) => super::PrivateGroup::Unavailable,
            }
        } else {
            super::PrivateGroup::None
        };
        if let Err((i, why)) =
            super::check_chain(&chain, euid(), usize::from(top.is_some()), private)
        {
            let at: PathBuf = std::iter::once(start.as_os_str())
                .chain(names.iter().take(i).copied())
                .collect();
            let shown = heimdall_localenv::paths::display_path(Path::new(""), &at);
            let fix = if chain.get(i).is_some_and(|c| c.mode & 0o020 != 0) {
                format!("; fix: chmod g-w {shown}")
            } else {
                String::new()
            };
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("the purge refused: {why}: {shown}{fix}"),
            ));
        }
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

        fn root(&self, which: usize) -> Option<&Root> {
            if which == 0 {
                Some(&self.state)
            } else {
                self.run.as_ref()
            }
        }

        /// Every entry the purge removes: (root, name, whether it is a database file).
        fn targets(&self, db_file: &str) -> Vec<(usize, OsString, bool)> {
            let mut out = Vec::new();
            if self.run.is_some() {
                out.extend(RUN_TREES.iter().map(|t| (1, OsString::from(t), false)));
            }
            out.extend(STATE_TREES.iter().map(|t| (0, OsString::from(t), false)));
            out.extend(
                DB_SUFFIXES
                    .iter()
                    .map(|sfx| (0, OsString::from(format!("{db_file}{sfx}")), true)),
            );
            out
        }

        pub(super) fn quarantine(
            &self,
            db_file: &str,
            between: impl FnOnce(),
        ) -> Result<Quarantine, super::QuarantineError> {
            let err = |cause| super::QuarantineError {
                cause,
                stuck: Vec::new(),
            };
            // 1. Inspect (nothing changes; a link, or a database file that is not a
            //    regular file, refuses).
            let mut inspected = Vec::new();
            let mut absent = Vec::new();
            for (which, name, is_db) in self.targets(db_file) {
                let Some(root) = self.root(which) else {
                    continue;
                };
                match manifest(&root.fd, &name, is_db).map_err(err)? {
                    Some(m) => inspected.push((which, name, m)),
                    None => absent.push((which, name)),
                }
            }
            between();
            // 2. Quarantine: each entry renamed, relative to its anchored directory.
            let mut q = Quarantine {
                moved: Vec::new(),
                absent,
                held: Vec::new(),
                db_file: OsString::from(db_file),
                tag: super::quarantine_tag(),
            };
            for (which, name, m) in inspected {
                let Some(root) = self.root(which) else {
                    continue;
                };
                let qname = super::quarantine_name(&q.tag, &name);
                if let Err(e) = rename_no_replace(&root.fd, &name, &qname) {
                    return Err(q.refuse(self, e));
                }
                q.moved.push(Moved {
                    which,
                    name,
                    qname,
                    manifest: m,
                });
            }
            // 3. Validate every quarantined entry against what was inspected.
            if let Err(e) = q.validate(self) {
                return Err(q.refuse(self, e));
            }
            // ⟨audit C0⟩ The database, its `-wal` and `-shm`, held for the read.
            #[cfg(test)]
            super::tests::before_hold_hook(&q.tag);
            if let Err(e) = q.hold(self) {
                return Err(q.refuse(self, e));
            }
            Ok(q)
        }
    }

    /// What one entry looked like when it was inspected: each path below it (relative,
    /// the entry itself first) with its kind and identity.
    type Manifest = Vec<(PathBuf, u8, (u64, u64))>;

    fn kind_code(ty: FileType) -> u8 {
        match ty {
            FileType::Directory => 1,
            FileType::RegularFile => 2,
            FileType::Socket => 3,
            _ => 4,
        }
    }

    /// The manifest of the entry `name` in `dir` (`None` when absent); a link anywhere
    /// refuses, and so does a database file that is not a regular file.
    fn manifest(dir: &OwnedFd, name: &OsStr, is_db: bool) -> std::io::Result<Option<Manifest>> {
        let Some((ty, dev, ino)) = kind(dir, name)? else {
            return Ok(None);
        };
        if is_db && ty != FileType::RegularFile {
            return Err(refused("a state database file is not a regular file"));
        }
        let mut out = Vec::new();
        walk_manifest(dir, name, PathBuf::new(), (ty, dev, ino), &mut out)?;
        Ok(Some(out))
    }

    fn walk_manifest(
        dir: &OwnedFd,
        name: &OsStr,
        rel: PathBuf,
        (ty, dev, ino): (FileType, u64, u64),
        out: &mut Manifest,
    ) -> std::io::Result<()> {
        out.push((rel.clone(), kind_code(ty), (dev, ino)));
        match ty {
            FileType::Symlink => Err(refused("a link inside a purged directory")),
            FileType::Directory => {
                let sub = match rustix::fs::openat(dir, name, dir_flags(), Mode::empty()) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                        return Err(refused("a directory was replaced by a link"));
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
                names.sort();
                for n in &names {
                    let Some(k) = kind(&sub, n)? else {
                        return Err(refused("an entry vanished while it was examined"));
                    };
                    walk_manifest(&sub, n, rel.join(n), k, out)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// One quarantined entry.
    struct Moved {
        which: usize,
        name: OsString,
        qname: OsString,
        manifest: Manifest,
    }

    /// ⟨audit C0⟩ One of the database's files (the database, its `-wal`, its `-shm`),
    /// held by descriptor at its quarantine name for the final read.
    struct Held {
        qname: OsString,
        _fd: OwnedFd,
        id: (u64, u64),
        /// Created empty by the purge (absent at the inspection): removed by it again.
        created: bool,
    }

    pub(super) struct Quarantine {
        moved: Vec<Moved>,
        /// The targets absent at the inspection (they must still be absent).
        absent: Vec<(usize, OsString)>,
        /// The database, then its `-wal` and `-shm` (empty when there is no database).
        held: Vec<Held>,
        db_file: OsString,
        tag: String,
    }

    /// Rename `from` to `to` in `dir`, never replacing anything at `to` (Linux
    /// `RENAME_NOREPLACE`, macOS `RENAME_EXCL`).
    fn rename_no_replace(dir: &OwnedFd, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        rustix::fs::renameat_with(dir, from, dir, to, rustix::fs::RenameFlags::NOREPLACE)?;
        Ok(())
    }

    impl Quarantine {
        /// Rename everything back, then the refusal (with any entry left behind).
        fn refuse(self, a: &Anchors, cause: std::io::Error) -> super::QuarantineError {
            let stuck = self.restore(a).err().unwrap_or_default();
            super::QuarantineError { cause, stuck }
        }

        /// ⟨audit C0⟩ Hold the quarantined database, `-wal` and `-shm` by descriptor: a
        /// moved one opened at its quarantine name and required to be the inspected inode;
        /// an absent one created empty there (`O_CREAT | O_EXCL`, so nothing placed there
        /// is used). A `-journal` at its quarantine name must be the moved one.
        fn hold(&mut self, a: &Anchors) -> std::io::Result<()> {
            if !self
                .moved
                .iter()
                .any(|m| m.which == 0 && m.name == self.db_file)
            {
                return Ok(());
            }
            for sfx in ["", "-wal", "-shm", "-journal"] {
                let mut name = self.db_file.clone();
                name.push(sfx);
                let qname = super::quarantine_name(&self.tag, &name);
                let moved = self.moved.iter().find(|m| m.which == 0 && m.name == name);
                if sfx == "-journal" {
                    if moved.is_none() && kind(&a.state.fd, &qname)?.is_some() {
                        return Err(refused("a file appeared at a quarantine name"));
                    }
                    continue;
                }
                let (fd, created) = match moved {
                    Some(m) => {
                        let fd = rustix::fs::openat(
                            &a.state.fd,
                            &qname,
                            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                            Mode::empty(),
                        )?;
                        let st = rustix::fs::fstat(&fd)?;
                        let inspected = m.manifest.first().map(|e| e.2);
                        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
                            || Some(id(&st)) != inspected
                        {
                            return Err(refused(
                                "a quarantined database file is not the one inspected",
                            ));
                        }
                        (fd, false)
                    }
                    None => {
                        let fd = rustix::fs::openat(
                            &a.state.fd,
                            &qname,
                            OFlags::RDWR
                                | OFlags::CREATE
                                | OFlags::EXCL
                                | OFlags::NOFOLLOW
                                | OFlags::CLOEXEC,
                            Mode::from_raw_mode(0o600),
                        )
                        .map_err(|e| match e {
                            rustix::io::Errno::EXIST => {
                                refused("a file appeared at a quarantine name")
                            }
                            e => e.into(),
                        })?;
                        (fd, true)
                    }
                };
                let id = id(&rustix::fs::fstat(&fd)?);
                self.held.push(Held {
                    qname,
                    _fd: fd,
                    id,
                    created,
                });
            }
            Ok(())
        }

        pub(super) fn validate(&self, a: &Anchors) -> std::io::Result<()> {
            for m in &self.moved {
                let Some(root) = a.root(m.which) else {
                    return Err(refused("a purge root vanished"));
                };
                let is_db = m.name == self.db_file;
                let now = manifest(&root.fd, &m.qname, is_db)?;
                if now.as_ref() != Some(&m.manifest) {
                    return Err(refused(
                        "an entry changed between its inspection and its quarantine",
                    ));
                }
            }
            for (which, name) in &self.absent {
                if let Some(root) = a.root(*which)
                    && kind(&root.fd, name)?.is_some()
                {
                    return Err(refused("an entry appeared after the inspection"));
                }
            }
            self.held_in_place(a)
        }

        /// Every held file's quarantine name still names it.
        fn held_in_place(&self, a: &Anchors) -> std::io::Result<()> {
            for h in &self.held {
                match kind(&a.state.fd, &h.qname)? {
                    Some((FileType::RegularFile, d, i)) if (d, i) == h.id => {}
                    _ => return Err(refused("a quarantined database file was replaced")),
                }
            }
            Ok(())
        }

        /// ⟨audit C0⟩ `open` the quarantined database by its quarantine name in the
        /// anchored directory (resolved from the held handle), `read` it, and, before the
        /// store `open` returned is dropped, take a census of this process's regular-file
        /// descriptors: each held file (database, `-wal`, `-shm`) must be named by exactly
        /// one more descriptor than before (the one SQLite opened: so SQLite read those
        /// very inodes, and no file swapped in and back), and its quarantine name must
        /// still name it.
        pub(super) fn read_db<S, T>(
            &self,
            a: &Anchors,
            open: impl FnOnce(&Path) -> S,
            read: impl FnOnce(&S) -> T,
        ) -> std::io::Result<Option<(T, std::io::Result<()>)>> {
            let Some(db) = self.held.first() else {
                return Ok(None);
            };
            let before = heimdall_runtime::platform::regular_file_descriptors()?;
            let path = current_path(&a.state.fd)?.join(&db.qname);
            let store = open(&path);
            let out = read(&store);
            let confirmed = self.census(a, &before);
            drop(store);
            Ok(Some((out, confirmed)))
        }

        /// ⟨ADR-0008 §17.34 item 6⟩ The census is **per held file**: each of the database,
        /// `-wal` and `-shm` must gain exactly one more descriptor than before SQLite's
        /// open. It is not a process-wide "no other new descriptors" check, which would
        /// race with other threads of this process opening unrelated files. A file
        /// swapped in for the read (and back) still fails: SQLite's descriptor then names
        /// the swapped-in inode, so the held file shows a missing descriptor.
        fn census(&self, a: &Anchors, before: &[(u64, u64)]) -> std::io::Result<()> {
            let after = heimdall_runtime::platform::regular_file_descriptors()?;
            let count = |v: &[(u64, u64)], id: (u64, u64)| v.iter().filter(|x| **x == id).count();
            for h in &self.held {
                if count(&after, h.id) != count(before, h.id) + 1 {
                    return Err(refused(
                        "the final read did not read the quarantined database, log and index",
                    ));
                }
            }
            self.held_in_place(a)
        }

        /// ⟨audit C1⟩ Delete the quarantine names: the trees first, the database's files
        /// last (the database itself first among them). When a deletion fails, every entry
        /// not yet started is renamed back, the failed one too when it is a single file,
        /// and every entry left at a quarantine name is reported.
        pub(super) fn delete(self, a: &Anchors) -> Result<(), super::QuarantineError> {
            let Quarantine {
                moved,
                held,
                db_file,
                ..
            } = self;
            let created: Vec<(OsString, (u64, u64))> = held
                .into_iter()
                .filter(|h| h.created)
                .map(|h| (h.qname, h.id))
                .collect();
            let is_db =
                |m: &&Moved| m.which == 0 && m.name.as_bytes().starts_with(db_file.as_bytes());
            let order: Vec<&Moved> = moved
                .iter()
                .filter(|m| !is_db(m))
                .chain(moved.iter().filter(is_db))
                .collect();
            for (i, m) in order.iter().enumerate() {
                let Some(root) = a.root(m.which) else {
                    continue;
                };
                if let Err(cause) = remove_tree(&root.fd, &m.qname) {
                    let mut stuck = Vec::new();
                    let single = matches!(kind(&root.fd, &m.qname), Ok(Some((t, ..))) if t != FileType::Directory);
                    let rest = order[i + 1..].iter();
                    for r in std::iter::once(m).filter(|_| single).chain(rest) {
                        let Some(root) = a.root(r.which) else {
                            continue;
                        };
                        if super::restore_fails()
                            || rename_no_replace(&root.fd, &r.qname, &r.name).is_err()
                        {
                            stuck.push(root.path.join(&r.qname));
                        }
                    }
                    if !single && matches!(kind(&root.fd, &m.qname), Ok(Some(_)) | Err(_)) {
                        stuck.insert(0, root.path.join(&m.qname));
                    }
                    stuck.extend(remove_created(a, &created));
                    return Err(super::QuarantineError { cause, stuck });
                }
            }
            match remove_created(a, &created).first() {
                None => Ok(()),
                Some(p) => Err(super::QuarantineError {
                    cause: refused("a file the final read used could not be removed"),
                    stuck: vec![p.clone()],
                }),
            }
        }

        pub(super) fn restore(self, a: &Anchors) -> Result<(), Vec<PathBuf>> {
            let created: Vec<(OsString, (u64, u64))> = self
                .held
                .iter()
                .filter(|h| h.created)
                .map(|h| (h.qname.clone(), h.id))
                .collect();
            let mut stuck = remove_created(a, &created);
            for m in self.moved.iter().rev() {
                let Some(root) = a.root(m.which) else {
                    continue;
                };
                // Never over an entry at the original name: it stays in quarantine,
                // reported.
                if super::restore_fails() || rename_no_replace(&root.fd, &m.qname, &m.name).is_err()
                {
                    stuck.push(root.path.join(&m.qname));
                }
            }
            if stuck.is_empty() { Ok(()) } else { Err(stuck) }
        }
    }

    /// Remove the files the purge created for the read (each only while its quarantine
    /// name still names the file created); the paths of any that could not be removed.
    fn remove_created(a: &Anchors, created: &[(OsString, (u64, u64))]) -> Vec<PathBuf> {
        let mut left = Vec::new();
        for (qname, want) in created {
            match kind(&a.state.fd, qname) {
                Ok(None) => {}
                Ok(Some((FileType::RegularFile, d, i)))
                    if (d, i) == *want
                        && rustix::fs::unlinkat(&a.state.fd, qname, AtFlags::empty()).is_ok() => {}
                _ => left.push(a.state.path.join(qname)),
            }
        }
        left
    }

    /// Where the anchored directory `dir` is now (wherever it was moved since it was
    /// anchored): macOS `F_GETPATH`, Linux the `/proc/self/fd` link. A move after this is
    /// caught by the census afterwards.
    fn current_path(dir: &OwnedFd) -> std::io::Result<PathBuf> {
        #[cfg(target_vendor = "apple")]
        {
            let p = rustix::fs::getpath(dir)?;
            Ok(PathBuf::from(OsStr::from_bytes(p.as_bytes())))
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            use std::os::fd::AsRawFd as _;
            std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        }
    }

    /// Remove the tree `name` in `dir` relative to descriptors (a link is removed as a
    /// link, never followed).
    fn remove_tree(dir: &OwnedFd, name: &OsStr) -> std::io::Result<()> {
        let Some((ty, ..)) = kind(dir, name)? else {
            return Ok(());
        };
        if ty == FileType::Directory {
            let sub = match rustix::fs::openat(dir, name, dir_flags(), Mode::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                    rustix::fs::unlinkat(dir, name, AtFlags::empty())?;
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };
            let mut names: Vec<OsString> = Vec::new();
            for e in Dir::read_from(&sub)? {
                let e = e?;
                let n = e.file_name().to_bytes();
                if n != b"." && n != b".." {
                    names.push(OsStr::from_bytes(n).to_owned());
                }
            }
            for n in &names {
                remove_tree(&sub, n)?;
            }
            rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)?;
        } else {
            #[cfg(test)]
            super::tests::unlink_hook(name);
            rustix::fs::unlinkat(dir, name, AtFlags::empty())?;
        }
        Ok(())
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

        fn root(&self, which: usize) -> Option<&PathBuf> {
            if which == 0 {
                Some(&self.state)
            } else {
                self.run.as_ref()
            }
        }

        pub(super) fn quarantine(
            &self,
            db_file: &str,
            between: impl FnOnce(),
        ) -> Result<Quarantine, super::QuarantineError> {
            let err = |cause| super::QuarantineError {
                cause,
                stuck: Vec::new(),
            };
            let mut targets: Vec<(usize, String, bool)> = Vec::new();
            if self.run.is_some() {
                targets.extend(RUN_TREES.iter().map(|t| (1, (*t).to_owned(), false)));
            }
            targets.extend(STATE_TREES.iter().map(|t| (0, (*t).to_owned(), false)));
            targets.extend(
                DB_SUFFIXES
                    .iter()
                    .map(|x| (0, format!("{db_file}{x}"), true)),
            );
            let mut inspected = Vec::new();
            let mut absent = Vec::new();
            for (which, name, is_db) in targets {
                let Some(root) = self.root(which) else {
                    continue;
                };
                match manifest(&root.join(&name), is_db).map_err(err)? {
                    Some(m) => inspected.push((which, name, m)),
                    None => absent.push((which, name)),
                }
            }
            between();
            let mut q = Quarantine {
                moved: Vec::new(),
                absent,
                held: Vec::new(),
                db_file: db_file.to_owned(),
                tag: super::quarantine_tag(),
            };
            for (which, name, m) in inspected {
                let Some(root) = self.root(which) else {
                    continue;
                };
                let qname = super::quarantine_name(&q.tag, std::ffi::OsStr::new(&name));
                // `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`: never over an entry
                // at the quarantine path.
                if let Err(e) =
                    heimdall_ipc::windows::move_no_replace(&root.join(&name), &root.join(&qname))
                {
                    return Err(q.refuse(self, e));
                }
                q.moved.push(Moved {
                    which,
                    name,
                    qname: qname.to_string_lossy().into_owned(),
                    manifest: m,
                });
            }
            if let Err(e) = q.validate(self) {
                return Err(q.refuse(self, e));
            }
            // ⟨audit C0⟩ The database, its `-wal` and `-shm`, pinned for the read.
            if let Err(e) = q.hold(self) {
                return Err(q.refuse(self, e));
            }
            Ok(q)
        }
    }

    /// Each path below an entry (relative, the entry itself first) with its file ID.
    type Manifest = Vec<(PathBuf, (u64, u64))>;

    fn manifest(path: &Path, is_db: bool) -> std::io::Result<Option<Manifest>> {
        let mut out = Vec::new();
        if !walk_manifest(path, PathBuf::new(), is_db, &mut out)? {
            return Ok(None);
        }
        Ok(Some(out))
    }

    fn walk_manifest(
        path: &Path,
        rel: PathBuf,
        is_db: bool,
        out: &mut Manifest,
    ) -> std::io::Result<bool> {
        let Some((handle, attrs)) = pin(path)? else {
            return Ok(false);
        };
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused(
                "a reparse point (link or junction) in a purged path",
            ));
        }
        if is_db && attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(refused("a state database file is not a regular file"));
        }
        out.push((rel.clone(), heimdall_ipc::windows::file_id(&handle)?));
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(path)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<Result<_, _>>()?;
            names.sort();
            for n in &names {
                walk_manifest(&path.join(n), rel.join(n), false, out)?;
            }
        }
        Ok(true)
    }

    struct Moved {
        which: usize,
        name: String,
        qname: String,
        manifest: Manifest,
    }

    /// ⟨audit C0⟩ One of the database's files, pinned at its quarantine path (no
    /// share-delete: it cannot be renamed, deleted or replaced while held).
    struct Held {
        path: PathBuf,
        file: std::fs::File,
        id: (u64, u64),
        created: bool,
    }

    pub(super) struct Quarantine {
        moved: Vec<Moved>,
        absent: Vec<(usize, String)>,
        /// The database, then its `-wal` and `-shm` (empty when there is no database).
        held: Vec<Held>,
        db_file: String,
        tag: String,
    }

    impl Quarantine {
        fn refuse(self, a: &Anchors, cause: std::io::Error) -> super::QuarantineError {
            let stuck = self.restore(a).err().unwrap_or_default();
            super::QuarantineError { cause, stuck }
        }

        /// ⟨audit C0⟩ Pin the quarantined database, `-wal` and `-shm` for the whole read
        /// (a moved one checked against its inspected file ID; an absent one created empty
        /// with `create_new`); a `-journal` at its quarantine path must be the moved one.
        fn hold(&mut self, a: &Anchors) -> std::io::Result<()> {
            if !self
                .moved
                .iter()
                .any(|m| m.which == 0 && m.name == self.db_file)
            {
                return Ok(());
            }
            for sfx in ["", "-wal", "-shm", "-journal"] {
                let name = format!("{}{sfx}", self.db_file);
                let path = a.state.join(super::quarantine_name(
                    &self.tag,
                    std::ffi::OsStr::new(&name),
                ));
                let moved = self.moved.iter().find(|m| m.which == 0 && m.name == name);
                if sfx == "-journal" {
                    if moved.is_none() && std::fs::symlink_metadata(&path).is_ok() {
                        return Err(refused("a file appeared at a quarantine name"));
                    }
                    continue;
                }
                let (file, created) = match moved {
                    Some(m) => {
                        let Some((file, attrs)) = pin(&path)? else {
                            return Err(refused("a quarantined database file vanished"));
                        };
                        let inspected = m.manifest.first().map(|e| e.1);
                        if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
                            || Some(heimdall_ipc::windows::file_id(&file)?) != inspected
                        {
                            return Err(refused(
                                "a quarantined database file is not the one inspected",
                            ));
                        }
                        (file, false)
                    }
                    None => {
                        let file = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .share_mode(SHARE_NO_DELETE)
                            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                            .open(&path)
                            .map_err(|e| match e.kind() {
                                std::io::ErrorKind::AlreadyExists => {
                                    refused("a file appeared at a quarantine name")
                                }
                                _ => e,
                            })?;
                        (file, true)
                    }
                };
                let id = heimdall_ipc::windows::file_id(&file)?;
                self.held.push(Held {
                    path,
                    file,
                    id,
                    created,
                });
            }
            Ok(())
        }

        pub(super) fn validate(&self, a: &Anchors) -> std::io::Result<()> {
            for m in &self.moved {
                let Some(root) = a.root(m.which) else {
                    return Err(refused("a purge root vanished"));
                };
                let now = manifest(&root.join(&m.qname), m.name == self.db_file)?;
                if now.as_ref() != Some(&m.manifest) {
                    return Err(refused(
                        "an entry changed between its inspection and its quarantine",
                    ));
                }
            }
            for (which, name) in &self.absent {
                if let Some(root) = a.root(*which)
                    && std::fs::symlink_metadata(root.join(name)).is_ok()
                {
                    return Err(refused("an entry appeared after the inspection"));
                }
            }
            self.held_in_place()
        }

        /// Every pinned file is still the one its quarantine path names.
        fn held_in_place(&self) -> std::io::Result<()> {
            for h in &self.held {
                let named = std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(SHARE_NO_DELETE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&h.path)?;
                if heimdall_ipc::windows::file_id(&named)? != h.id
                    || heimdall_ipc::windows::file_id(&h.file)? != h.id
                {
                    return Err(refused("a quarantined database file was replaced"));
                }
            }
            Ok(())
        }

        /// ⟨audit C0⟩ `open` the quarantined database by its quarantine path and `read`
        /// it, all three files pinned throughout; before the store is dropped, each pinned
        /// file must still be the one its path names.
        pub(super) fn read_db<S, T>(
            &self,
            _a: &Anchors,
            open: impl FnOnce(&Path) -> S,
            read: impl FnOnce(&S) -> T,
        ) -> std::io::Result<Option<(T, std::io::Result<()>)>> {
            let Some(db) = self.held.first() else {
                return Ok(None);
            };
            let store = open(&db.path);
            let out = read(&store);
            let confirmed = self.held_in_place();
            drop(store);
            Ok(Some((out, confirmed)))
        }

        /// ⟨audit C1⟩ As on Unix: trees first, the database's files last; on a failure
        /// the entries not yet started (and a failed single file) are renamed back and
        /// every entry left at a quarantine path is reported.
        pub(super) fn delete(self, a: &Anchors) -> Result<(), super::QuarantineError> {
            let Quarantine {
                moved,
                held,
                db_file,
                ..
            } = self;
            // Unpinned (their handles closed) so they can be deleted.
            let created: Vec<(PathBuf, (u64, u64))> = held
                .into_iter()
                .filter(|h| h.created)
                .map(|h| (h.path, h.id))
                .collect();
            let is_db = |m: &&Moved| m.which == 0 && m.name.starts_with(&db_file);
            let order: Vec<&Moved> = moved
                .iter()
                .filter(|m| !is_db(m))
                .chain(moved.iter().filter(is_db))
                .collect();
            for (i, m) in order.iter().enumerate() {
                let Some(root) = a.root(m.which) else {
                    continue;
                };
                let at = root.join(&m.qname);
                if let Err(cause) = remove_tree(&at, Path::new(""), &m.manifest) {
                    let mut stuck = Vec::new();
                    let single = std::fs::symlink_metadata(&at).is_ok_and(|md| !md.is_dir());
                    let rest = order[i + 1..].iter();
                    for r in std::iter::once(m).filter(|_| single).chain(rest) {
                        let Some(root) = a.root(r.which) else {
                            continue;
                        };
                        let (from, to) = (root.join(&r.qname), root.join(&r.name));
                        if super::restore_fails()
                            || heimdall_ipc::windows::move_no_replace(&from, &to).is_err()
                        {
                            stuck.push(from);
                        }
                    }
                    if !single && std::fs::symlink_metadata(&at).is_ok() {
                        stuck.insert(0, at);
                    }
                    stuck.extend(remove_created(&created));
                    return Err(super::QuarantineError { cause, stuck });
                }
            }
            match remove_created(&created).first() {
                None => Ok(()),
                Some(p) => Err(super::QuarantineError {
                    cause: refused("a file the final read used could not be removed"),
                    stuck: vec![p.clone()],
                }),
            }
        }

        pub(super) fn restore(self, a: &Anchors) -> Result<(), Vec<PathBuf>> {
            let created: Vec<(PathBuf, (u64, u64))> = self
                .held
                .into_iter()
                .filter(|h| h.created)
                .map(|h| (h.path, h.id))
                .collect();
            let mut stuck = remove_created(&created);
            for m in self.moved.iter().rev() {
                let Some(root) = a.root(m.which) else {
                    continue;
                };
                let (from, to) = (root.join(&m.qname), root.join(&m.name));
                // Never over an entry at the original path (no replace): it stays in
                // quarantine, reported.
                if super::restore_fails()
                    || heimdall_ipc::windows::move_no_replace(&from, &to).is_err()
                {
                    stuck.push(from);
                }
            }
            if stuck.is_empty() { Ok(()) } else { Err(stuck) }
        }
    }

    /// Remove the files the purge created for the read (each only while its path still
    /// names the file created); the paths of any that could not be removed.
    fn remove_created(created: &[(PathBuf, (u64, u64))]) -> Vec<PathBuf> {
        let mut left = Vec::new();
        for (path, want) in created {
            let same = match pin(path) {
                Ok(None) => continue,
                Ok(Some((f, attrs))) => {
                    attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0
                        && heimdall_ipc::windows::file_id(&f).is_ok_and(|id| id == *want)
                }
                Err(_) => false,
            };
            if !same || std::fs::remove_file(path).is_err() {
                left.push(path.clone());
            }
        }
        left
    }

    /// ⟨audit C2⟩ Remove the quarantined tree at `path` (`rel` below the quarantined
    /// entry, whose inspected file IDs are `manifest`). Each entry is pinned (no
    /// share-delete, never following a reparse point) and, when it was inspected, required
    /// to be the inspected file; a directory **stays pinned** while it is listed and its
    /// entries removed, so it cannot be replaced by a junction meanwhile. A reparse point
    /// is removed as the link itself (`DeleteFileW`/`RemoveDirectoryW` never follow one),
    /// and so is one swapped in after the pin is released, so nothing outside the purge
    /// roots is reached.
    fn remove_tree(path: &Path, rel: &Path, manifest: &Manifest) -> std::io::Result<()> {
        let Some((handle, attrs)) = pin(path)? else {
            return Ok(());
        };
        if let Some((_, want)) = manifest.iter().find(|(r, _)| r == rel)
            && heimdall_ipc::windows::file_id(&handle)? != *want
        {
            return Err(refused(
                "a quarantined entry was replaced before its deletion",
            ));
        }
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            drop(handle);
            return if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                std::fs::remove_dir(path)
            } else {
                std::fs::remove_file(path)
            };
        }
        let names: Vec<std::ffi::OsString> = std::fs::read_dir(path)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        for n in &names {
            remove_tree(&path.join(n), &rel.join(n), manifest)?;
        }
        drop(handle);
        std::fs::remove_dir(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    type UnlinkHook = Option<Box<dyn FnMut(&std::ffi::OsStr)>>;

    #[cfg(unix)]
    thread_local! {
        static UNLINK_HOOK: std::cell::RefCell<UnlinkHook> =
            const { std::cell::RefCell::new(None) };
    }

    #[cfg(unix)]
    type HoldHook = Option<Box<dyn FnMut(&str)>>;

    #[cfg(unix)]
    thread_local! {
        static BEFORE_HOLD: std::cell::RefCell<HoldHook> =
            const { std::cell::RefCell::new(None) };
    }

    /// Called with the quarantine's tag after the quarantine's check, before the database
    /// files are held (tests swap a decoy in there).
    #[cfg(unix)]
    pub(super) fn before_hold_hook(tag: &str) {
        BEFORE_HOLD.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f(tag);
            }
        });
    }

    /// Called before each file's `unlinkat` (tests schedule a replacement there).
    #[cfg(unix)]
    pub(super) fn unlink_hook(name: &std::ffi::OsStr) {
        UNLINK_HOOK.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f(name);
            }
        });
    }

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
            gid: 20,
        }
    }

    /// A directory with group `gid`.
    fn dir_g(uid: u32, mode: u32, gid: u32) -> Component {
        Component {
            gid,
            ..dir(uid, mode)
        }
    }

    /// No private group (the facts every case without a group-writable ancestor uses).
    const NO_UPG: PrivateGroup = PrivateGroup::None;

    fn via_link(link_uid: u32, uid: u32, mode: u32) -> Component {
        Component {
            uid,
            mode,
            link_uid: Some(link_uid),
            gid: 20,
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
        assert_eq!(check_chain(&state, ME, 0, NO_UPG), Ok(()));
        let mut run = state.to_vec();
        run.push(dir(ME, 0o700));
        assert_eq!(check_chain(&run, ME, 0, NO_UPG), Ok(()));
        let tmpdir = [
            dir(0, 0o755),
            via_link(0, 0, 0o755),
            dir(0, 0o755),
            dir(0, 0o755),
            dir(ME, 0o755),
            dir(ME, 0o700),
        ];
        assert_eq!(check_chain(&tmpdir, ME, 0, NO_UPG), Ok(()));
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
        assert_eq!(check_chain(&state, ME, 0, NO_UPG), Ok(()));
        let run = [
            dir(0, 0o755),
            dir(0, 0o755),
            dir(0, 0o755),
            dir(ME, 0o700),
            dir(ME, 0o700),
        ];
        assert_eq!(check_chain(&run, ME, 0, NO_UPG), Ok(()));
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
            (dir(ME, 0o777), "others"),
            (dir(0, 0o1777), "sticky"),
            (dir(1000, 0o755), "another user"),
            (via_link(ME, ME, 0o755), "link"),
        ] {
            let Err((_, e)) = check_chain(&with(bad), ME, 0, NO_UPG) else {
                panic!("{why}: accepted");
            };
            assert!(e.contains(why), "{why}: {e}");
        }
        for root in [dir(ME, 0o750), dir(0, 0o700), via_link(ME, ME, 0o700)] {
            assert!(
                check_chain(&[dir(0, 0o755), root], ME, 0, NO_UPG).is_err(),
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

    /// The user private group of the probe (`staff`-style shared groups use another gid).
    const PRIV: u32 = 1001;

    /// `recheck4_default_unix_home_with_private_group_must_pass` (the fourth re-check's
    /// probe, W5-F03; ADR-0008 §17.34 item 2): a default Unix home that is group-writable
    /// by the user's private group (Debian and Ubuntu with umask 002) passes; the roots
    /// stay owner-only.
    #[test]
    fn recheck4_default_unix_home_with_private_group_must_pass() {
        let chain = [
            dir(0, 0o755),
            dir(0, 0o755),
            dir_g(ME, 0o775, PRIV),
            dir_g(ME, 0o775, PRIV),
            dir(ME, 0o755),
            dir(ME, 0o700),
        ];
        assert_eq!(
            check_chain(&chain, ME, 0, PrivateGroup::Gid(PRIV)),
            Ok(()),
            "default XDG paths in a private-group home"
        );
        let mut root = chain;
        root[5] = dir_g(ME, 0o770, PRIV);
        assert!(
            check_chain(&root, ME, 0, PrivateGroup::Gid(PRIV)).is_err(),
            "a root stays owner-only"
        );
    }

    /// `shared_group_home_still_refuses` (ADR-0008 §17.34 item 2): the same group-writable
    /// home refuses when the user's primary group is not private (another member, or a
    /// name other than the user's: the lookup answers no private group), when the
    /// directory's group is not that private group, when the group lookup is unavailable
    /// (the refusal names the directory and `chmod g-w`), and whenever others can write.
    #[test]
    fn shared_group_home_still_refuses() {
        let chain = [
            dir(0, 0o755),
            dir(0, 0o755),
            dir_g(ME, 0o775, PRIV),
            dir(ME, 0o700),
        ];
        assert!(check_chain(&chain, ME, 0, PrivateGroup::None).is_err());
        assert!(check_chain(&chain, ME, 0, PrivateGroup::Gid(PRIV + 1)).is_err());
        let Err((i, why)) = check_chain(&chain, ME, 0, PrivateGroup::Unavailable) else {
            panic!("an unavailable lookup accepted a group-writable ancestor");
        };
        assert_eq!(i, 2);
        assert!(why.contains("cannot be looked up"), "{why}");
        let others = [dir(0, 0o755), dir_g(ME, 0o777, PRIV), dir(ME, 0o700)];
        assert!(check_chain(&others, ME, 0, PrivateGroup::Gid(PRIV)).is_err());
    }

    /// The lookup runs on this host (macOS: the primary group `staff` is shared, so no
    /// private group).
    #[cfg(unix)]
    #[test]
    fn user_private_group_lookup_runs() {
        assert!(heimdall_runtime::platform::user_private_group().is_ok());
    }

    /// A refusal names the directory and, for a group-writable one, `chmod g-w`.
    #[cfg(unix)]
    #[test]
    fn a_group_writable_refusal_names_the_fix() {
        use std::os::unix::fs::PermissionsExt as _;
        let (d, state, run) = roots();
        let mid = d.path().join("mid");
        let (s2, r2) = (mid.join("state"), mid.join("run"));
        for p in [&s2, &r2] {
            std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("{e}"));
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o775))
            .unwrap_or_else(|e| panic!("{e}"));
        let Err(e) = Anchors::open(&s2, &r2, Some(d.path())) else {
            panic!("accepted");
        };
        assert!(e.to_string().contains("chmod g-w"), "{e}");
        assert!(e.to_string().contains("mid"), "{e}");
        let _ = (state, run);
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

    // --- ADR-0008 §17.34 item 1 (W5-F01, F02): quarantine, validate, then delete ---------

    /// `recheck4_leaf_replacement_must_keep_unconfirmed_owner_data` (the fourth re-check's
    /// probe, W5-F02): at a file's deletion, an actor replaces the inspected backup
    /// (`<state>/backups/victim`) with a file of its own. Only the quarantine names are
    /// removed, so the replacement at the inspected path is never deleted.
    #[cfg(unix)]
    #[test]
    fn recheck4_leaf_replacement_must_keep_unconfirmed_owner_data() {
        let (d, state, run) = roots();
        let victim = state.join("backups").join("victim");
        let unique = d.path().join("unique-owner-file");
        let old = d.path().join("old-authorized-file");
        std::fs::write(&victim, b"old authorized backup").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(&unique, b"unique owner data").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let (v, u, o) = (victim.clone(), unique.clone(), old.clone());
        UNLINK_HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |name| {
                if name == std::ffi::OsStr::new("victim") {
                    // By the inspected path: after the quarantine nothing is there.
                    if std::fs::rename(&v, &o).is_ok() {
                        let _ = std::fs::rename(&u, &v);
                    }
                }
            }));
        });
        let end = anchors.purge("state.db", || {});
        UNLINK_HOOK.with(|h| *h.borrow_mut() = None);
        assert!(end.is_ok(), "{end:?}");
        assert!(
            unique.exists() || victim.exists(),
            "an unconfirmed inode was deleted"
        );
    }

    /// `quarantine_refuses_a_leaf_replaced_before_it` (W5-F02): a backup replaced between
    /// its inspection and its quarantine no longer matches; everything is renamed back
    /// and nothing is deleted (the replacement included).
    #[cfg(unix)]
    #[test]
    fn quarantine_refuses_a_leaf_replaced_before_it() {
        let (d, state, run) = roots();
        let victim = state.join("backups").join("f");
        let unique = d.path().join("unique");
        std::fs::write(&unique, b"unique owner data").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let end = anchors.quarantine("state.db", || {
            std::fs::rename(&unique, &victim).unwrap_or_else(|e| panic!("{e}"));
        });
        let Err(e) = end else {
            panic!("a replaced leaf was quarantined")
        };
        assert!(e.stuck.is_empty(), "{:?}", e.stuck);
        assert_eq!(
            std::fs::read(&victim).unwrap_or_default(),
            b"unique owner data"
        );
        for p in [
            run.join("b").join("t").join("f"),
            run.join("mux").join("f"),
            state.join("state.db"),
        ] {
            assert!(p.exists(), "{} was not restored", p.display());
        }
    }

    /// `quarantine_failed_restore_is_left_and_reported` (ADR-0008 §17.34 item 1): when a
    /// rename-back fails, the entry stays at its quarantine name, its exact path is
    /// reported, and nothing is deleted.
    #[cfg(unix)]
    #[test]
    fn quarantine_failed_restore_is_left_and_reported() {
        let (d, state, run) = roots();
        let victim = state.join("backups").join("f");
        let unique = d.path().join("unique");
        std::fs::write(&unique, b"unique").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        FAIL_RESTORE.with(|f| f.set(true));
        let end = anchors.quarantine("state.db", || {
            std::fs::rename(&unique, &victim).unwrap_or_else(|e| panic!("{e}"));
        });
        FAIL_RESTORE.with(|f| f.set(false));
        let Err(e) = end else {
            panic!("a replaced leaf was quarantined")
        };
        assert!(!e.stuck.is_empty(), "the failed rename-back is reported");
        for p in &e.stuck {
            assert!(p.exists(), "{} is still in quarantine", p.display());
            assert!(
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(".hm-purge-")),
                "{}",
                p.display()
            );
        }
        let q = e.stuck.iter().find(|p| {
            p.ends_with(p.file_name().unwrap_or_default())
                && p.to_string_lossy().ends_with("-backups")
        });
        let q = q.unwrap_or_else(|| panic!("{:?}", e.stuck));
        assert!(q.join("f").exists(), "nothing was deleted");
    }

    /// `swap_between_quarantine_and_unlink_spares_new_data` (ADR-0008 §17.34 item 1): data
    /// placed at an inspected path after the quarantine is never deleted.
    #[cfg(unix)]
    #[test]
    fn swap_between_quarantine_and_unlink_spares_new_data() {
        let (d, state, run) = roots();
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        std::fs::create_dir(state.join("backups")).unwrap_or_else(|e| panic!("{e}"));
        let new = state.join("backups").join("placed-after");
        std::fs::write(&new, b"new owner data").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(state.join("state.db"), b"new db").unwrap_or_else(|e| panic!("{e}"));
        q.delete().unwrap_or_else(|e| panic!("{e:?}"));
        assert!(new.exists(), "data placed after the quarantine was deleted");
        assert!(state.join("state.db").exists());
        assert!(
            !run.join("b").exists(),
            "the quarantined entries were deleted"
        );
    }

    // --- the audit of the quarantine (C0, C1, C3) -----------------------------------------

    /// `quarantine_refuses_a_decoy_database_before_its_read` (audit C0): a decoy put at
    /// the database's quarantine name after the quarantine's check is refused when the
    /// database is held for the read (its inode is not the inspected one); everything is
    /// renamed back and nothing is deleted.
    #[cfg(unix)]
    #[test]
    fn quarantine_refuses_a_decoy_database_before_its_read() {
        let (d, state, run) = roots();
        let real = d.path().join("real-db");
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let (s, r) = (state.clone(), real.clone());
        BEFORE_HOLD.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |tag| {
                let q = s.join(quarantine_name(tag, std::ffi::OsStr::new("state.db")));
                std::fs::rename(&q, &r).unwrap_or_else(|e| panic!("{e}"));
                std::fs::write(&q, b"decoy").unwrap_or_else(|e| panic!("{e}"));
            }));
        });
        let end = anchors.quarantine("state.db", || {});
        BEFORE_HOLD.with(|h| *h.borrow_mut() = None);
        let Err(e) = end else {
            panic!("a decoy database was held for the final read")
        };
        assert!(e.stuck.is_empty(), "{:?}", e.stuck);
        assert_eq!(std::fs::read(&real).ok().as_deref(), Some(&b"db"[..]));
        assert!(state.join("state.db").exists() && state.join("backups").join("f").exists());
    }

    /// `probe_c1_partial_delete_leaves_hidden_db` (audit C1): a deletion failing part-way
    /// (a directory inside `managed` the purge cannot empty) leaves the database renamed
    /// back to its name (it is deleted last), and the partly deleted tree reported, never
    /// a database stranded silently at a quarantine name.
    #[cfg(unix)]
    #[test]
    fn partial_delete_renames_the_database_back() {
        use std::os::unix::fs::PermissionsExt as _;
        let (d, state, run) = roots();
        let locked = state.join("managed").join("locked");
        std::fs::create_dir_all(&locked).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(locked.join("f"), b"x").unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        let end = q.delete();
        // (Writable again, so the fixture can be removed.)
        for e in std::fs::read_dir(&state)
            .unwrap_or_else(|e| panic!("{e}"))
            .flatten()
        {
            let l = e.path().join("locked");
            if l.exists() {
                let _ = std::fs::set_permissions(&l, std::fs::Permissions::from_mode(0o700));
            }
        }
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
        let Err(e) = end else {
            panic!("the deletion could not have succeeded")
        };
        let reported = |sfx: &str| {
            e.stuck
                .iter()
                .any(|p| p.to_string_lossy().ends_with(sfx) && p.exists())
        };
        assert!(
            state.join("state.db").exists() || reported("-state.db"),
            "the database was stranded at its quarantine name, unreported"
        );
        assert_eq!(
            std::fs::read(state.join("state.db")).ok().as_deref(),
            Some(&b"db"[..]),
            "renamed back"
        );
        assert!(reported("-managed"), "the partly deleted tree is reported");
    }

    /// `restore_never_replaces_an_entry_at_the_original_name` (audit C3): the rename back
    /// is `RENAME_NOREPLACE` (macOS `RENAME_EXCL`): an entry that appeared at the original
    /// name is kept, and the quarantined one stays at its quarantine name, reported.
    #[cfg(unix)]
    #[test]
    fn restore_never_replaces_an_entry_at_the_original_name() {
        let (d, state, run) = roots();
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        std::fs::write(state.join("state.db"), b"new").unwrap_or_else(|e| panic!("{e}"));
        let Err(stuck) = q.restore() else {
            panic!("the entry at the original name was replaced")
        };
        assert_eq!(
            std::fs::read(state.join("state.db")).ok().as_deref(),
            Some(&b"new"[..])
        );
        assert!(
            stuck
                .iter()
                .any(|p| p.to_string_lossy().ends_with("-state.db")
                    && std::fs::read(p).ok().as_deref() == Some(&b"db"[..])),
            "{stuck:?}"
        );
    }

    /// `an_entry_placed_inside_a_quarantined_directory_is_deleted` (the `RESIDUALS`
    /// entry `purge_entry_placed_in_quarantine_is_deleted`, ADR-0008 §17.34 item 1): an
    /// entry an actor adds inside a quarantined directory after the last check is deleted
    /// with it (an entry it placed), while owner data at the inspected path is not.
    #[cfg(unix)]
    #[test]
    fn an_entry_placed_inside_a_quarantined_directory_is_deleted() {
        let (d, state, run) = roots();
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        let qdir = std::fs::read_dir(&state)
            .unwrap_or_else(|e| panic!("{e}"))
            .flatten()
            .map(|e| e.path())
            .find(|p| p.to_string_lossy().ends_with("-backups"))
            .unwrap_or_else(|| panic!("no quarantined backups"));
        let placed = qdir.join("placed");
        std::fs::write(&placed, b"placed").unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(state.join("backups")).unwrap_or_else(|e| panic!("{e}"));
        let owner = state.join("backups").join("owner");
        std::fs::write(&owner, b"owner").unwrap_or_else(|e| panic!("{e}"));
        q.delete().unwrap_or_else(|e| panic!("{e:?}"));
        assert!(
            !placed.exists(),
            "the entry it placed is deleted (the residual)"
        );
        assert!(owner.exists(), "owner data at the inspected path is kept");
        assert!(
            heimdall_domain::claims::RESIDUALS
                .iter()
                .any(|r| r.id == "purge_entry_placed_in_quarantine_is_deleted")
        );
    }
}
