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
//! **Quarantine, validate, delete (ADR-0008 §17.34 item 1, §17.35 items 1-2; W5-F01, F02,
//! G01, G02; the audit's C0-C4).** [`Anchors::quarantine`]: every entry the purge removes
//! (the database and its `-wal`/`-shm`/`-journal`, `backups`, `managed`, `b`, `mux`) is
//! inspected (each path below it with its kind and identity; any link or reparse point
//! refuses), then moved atomically and **never over anything** (Linux `RENAME_NOREPLACE`,
//! macOS `RENAME_EXCL`, Windows `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`): each
//! tree to a fresh random quarantine name in its own anchored directory, and the
//! **database family as one recovery unit** into one fresh owner-only quarantine
//! directory (`.hm-purge-<tag>-database`, created exclusively in `<state>`), where the
//! files keep their names, so SQLite always sees them as one unit. Then everything is
//! checked again against what was inspected (every target absent at the inspection must
//! still be absent, and the quarantine directory holds nothing else). The database, its
//! `-wal` and its `-shm` are **held** there (a moved one opened and required to be the
//! inspected inode; an absent one created empty by the purge with `O_EXCL`; Windows: all
//! three pinned, no share-delete). The final read, the snapshot comparison and the bundle
//! check run against that quarantined database ([`Quarantine::read_db`]), and before its
//! store is dropped the read is confirmed: Unix, a census of this process's regular-file
//! descriptors finds exactly one more descriptor of each held file (the ones SQLite
//! opened, so it read those very inodes) and each name still names its held file;
//! Windows, the three are still pinned and named. Then everything is checked again
//! ([`Quarantine::validate`]), the quarantined database is **checkpointed**
//! (`PRAGMA wal_checkpoint(TRUNCATE)` on a read-write connection confirmed the same way,
//! [`Quarantine::checkpoint`]) and its `-wal` must be empty, and only then is anything
//! deleted ([`Quarantine::delete`]): the trees, then the unit's companions, its database,
//! its directory. A restore ([`Quarantine::restore`]) renames each tree back, and the unit
//! only when **none** of its original names is occupied, the database first; otherwise the
//! whole unit stays in its quarantine directory, reported, and no companion is ever
//! restored alone. On a deletion failing part-way, the trees not yet started are renamed
//! back and the unit (its complete, checkpointed database among it) is restored under that
//! rule or kept, and the report lists exactly what was renamed back and what was kept. On
//! any difference before the deletion everything is restored and the purge refuses with
//! nothing deleted. **What remains (the `RESIDUALS` entry
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

    /// ⟨ADR-0008 §17.35 item 7 (audit D1, D2)⟩ Handle an interrupted uninstall's quarantine
    /// (call with the lock held): each database family unit rejoined under §17.35 item
    /// 1's rule by its record, each quarantined tree renamed back when its name is free;
    /// whatever cannot be is reported as left.
    pub(crate) fn recover(&self, db_file: &str) -> Recovered {
        self.inner.recover(db_file)
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
    /// Entries left at their quarantine names (a quarantine directory and each file in
    /// it included).
    pub(crate) stuck: Vec<std::path::PathBuf>,
    /// ⟨§17.35 item 2⟩ Entries renamed back to their names (a deletion that failed
    /// part-way).
    pub(crate) restored: Vec<std::path::PathBuf>,
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
        self.inner.read_db(&self.anchors.inner, open, read, |_| ())
    }

    /// ⟨ADR-0008 §17.35 item 2 (W5-G02)⟩ After the final checks and the last
    /// [`Quarantine::validate`], before anything is deleted: `open` a connection on the
    /// quarantined database (in its quarantine directory, as [`Quarantine::read_db`],
    /// confirmed by the same census) and `run` the checkpoint on it (`true` when it
    /// completed); then the `-wal` must be empty (zero bytes) or absent.
    ///
    /// # Errors
    /// A checkpoint that did not complete, an unconfirmed connection, or a log that is
    /// not empty afterwards.
    pub(crate) fn checkpoint<S>(
        &self,
        open: impl FnOnce(&Path) -> S,
        probe: impl FnOnce(&S) -> bool,
        run: impl FnOnce(&S) -> bool,
    ) -> std::io::Result<()> {
        // ⟨audit D3⟩ One read first (SQLite opens the database, its log and its index),
        // then the census, and only on a confirmed connection the checkpoint.
        match self.inner.read_db(&self.anchors.inner, open, probe, run)? {
            None => {}
            Some((false, _)) | Some((true, Ok(false))) => {
                return Err(refused(
                    "the checkpoint of the quarantined database did not complete",
                ));
            }
            Some((true, confirmed)) => {
                confirmed?;
            }
        }
        self.inner.wal_empty()
    }

    /// Check every quarantined entry against what was inspected, again.
    ///
    /// # Errors
    /// A refusal on any difference.
    pub(crate) fn validate(&self) -> std::io::Result<()> {
        self.inner.validate(&self.anchors.inner)
    }

    /// Delete the quarantined entries (by their quarantine names only), refused with
    /// nothing deleted unless the quarantined `-wal` is empty (⟨§17.35 item 2⟩): the trees
    /// first, then the database family (its companions, the database, its quarantine
    /// directory). ⟨audit C1; §17.35 items 1-2⟩ When a deletion fails part-way, every tree
    /// not yet started (and a failed single file) is renamed back, never over anything,
    /// the database family is restored as a unit or kept whole in its quarantine
    /// directory, and the error lists exactly the paths renamed back and the paths left
    /// in quarantine.
    ///
    /// # Errors
    /// An I/O failure, with the entries left in quarantine.
    pub(crate) fn delete(self) -> Result<(), QuarantineError> {
        self.inner.delete(&self.anchors.inner)
    }

    /// Rename every quarantined entry back (⟨§17.35 item 1⟩ the database family as one
    /// unit: only when none of its names is occupied, the database first; otherwise it
    /// stays whole in its quarantine directory). `Err` with the exact paths of the
    /// entries that could not be restored (they stay at their quarantine names).
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

/// ⟨ADR-0008 §17.35 item 7⟩ The record a database family's quarantine directory keeps
/// of its members (each family file's name and inspected identity).
const UNIT_RECORD: &str = "heimdall-purge-unit";

/// ⟨§17.35 item 7⟩ `<rest>` of a quarantine name `.hm-purge-<32 hex>-<rest>`.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
fn quarantine_rest(name: &std::ffi::OsStr) -> Option<String> {
    let s = name.to_str()?.strip_prefix(".hm-purge-")?;
    let (tag, rest) = (s.get(..32)?, s.get(32..)?.strip_prefix('-')?);
    (tag.bytes().all(|b| b.is_ascii_hexdigit()) && !rest.is_empty()).then(|| rest.to_owned())
}

/// ⟨§17.35 item 7⟩ What [`Anchors::recover`] did: the paths renamed back, and the paths
/// left (each existing; a quarantine directory and each file in it).
#[derive(Debug, Default)]
pub(crate) struct Recovered {
    /// Renamed back to their names.
    pub(crate) restored: Vec<std::path::PathBuf>,
    /// Left where they are.
    pub(crate) left: Vec<std::path::PathBuf>,
}

/// ⟨§17.35 item 7⟩ Whether `<state>` or `<run>` shows a `.hm-purge-*` entry, or a
/// database log without its database (a hint by path; the recovery itself is anchored).
pub(crate) fn leftovers_present(state_dir: &Path, runtime_dir: &Path, db_file: &str) -> bool {
    let marked = |d: &Path| {
        std::fs::read_dir(d).is_ok_and(|es| {
            es.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(".hm-purge-"))
        })
    };
    let orphan = std::fs::symlink_metadata(state_dir.join(db_file)).is_err()
        && ["-wal", "-shm", "-journal"].iter().any(|sfx| {
            std::fs::symlink_metadata(state_dir.join(format!("{db_file}{sfx}"))).is_ok()
        });
    marked(state_dir) || marked(runtime_dir) || orphan
}

#[cfg(test)]
thread_local! {
    /// ⟨tests only⟩ The family file name whose deletion is made to fail.
    pub(crate) static FAIL_UNLINK: std::cell::RefCell<Option<std::ffi::OsString>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn unlink_fails(name: &std::ffi::OsStr) -> bool {
    FAIL_UNLINK.with(|f| f.borrow().as_deref() == Some(name))
}

#[cfg(not(test))]
fn unlink_fails(_: &std::ffi::OsStr) -> bool {
    false
}

/// ⟨ADR-0008 §17.35 item 1⟩ The name of the database family's quarantine directory in
/// `<state>`: `.hm-purge-<tag>-database`.
fn unit_dir_name(tag: &str) -> std::ffi::OsString {
    quarantine_name(tag, std::ffi::OsStr::new("database"))
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
                restored: Vec::new(),
            };
            // 1. Inspect (nothing changes; a link, or a database file that is not a
            //    regular file, refuses).
            let mut trees = Vec::new();
            let mut family = Vec::new();
            let mut absent = Vec::new();
            for (which, name, is_db) in self.targets(db_file) {
                let Some(root) = self.root(which) else {
                    continue;
                };
                match manifest(&root.fd, &name, is_db).map_err(err)? {
                    Some(m) if is_db => family.push((name, m)),
                    Some(m) => trees.push((which, name, m)),
                    None => absent.push((which, name)),
                }
            }
            between();
            // 2. Quarantine: each tree renamed, relative to its anchored directory; the
            //    database family moved together into one quarantine directory.
            let mut q = Quarantine {
                moved: Vec::new(),
                absent,
                unit: None,
                db_file: OsString::from(db_file),
                tag: super::quarantine_tag(),
            };
            for (which, name, m) in trees {
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
            if !family.is_empty()
                && let Err(e) = q.make_unit(self, family)
            {
                return Err(q.refuse(self, e));
            }
            // 3. Validate every quarantined entry against what was inspected.
            if let Err(e) = q.validate(self) {
                return Err(q.refuse(self, e));
            }
            // ⟨audit C0⟩ The database, its `-wal` and `-shm`, held for the read.
            #[cfg(test)]
            super::tests::before_hold_hook(&q.tag);
            if let Err(e) = q.hold() {
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

    /// One quarantined tree.
    struct Moved {
        which: usize,
        name: OsString,
        qname: OsString,
        manifest: Manifest,
    }

    /// ⟨audit C0⟩ One of the database's files (the database, its `-wal`, its `-shm`),
    /// held by descriptor in the quarantine directory for the final read.
    struct Held {
        name: OsString,
        fd: OwnedFd,
        id: (u64, u64),
        /// Created empty by the purge (absent at the inspection): never restored.
        created: bool,
    }

    /// ⟨ADR-0008 §17.35 item 1 (W5-G01)⟩ The database family (the database, `-wal`,
    /// `-shm`, `-journal`) as one recovery unit: moved together, keeping their names, into
    /// one fresh owner-only quarantine directory created exclusively in `<state>`, held by
    /// descriptor.
    struct Unit {
        dir: OwnedFd,
        id: (u64, u64),
        /// Its name in `<state>`.
        name: OsString,
        /// The ones moved into it (every family file inspected is in its record).
        members: Vec<(OsString, Manifest)>,
        held: Vec<Held>,
    }

    pub(super) struct Quarantine {
        moved: Vec<Moved>,
        /// The targets absent at the inspection (they must still be absent).
        absent: Vec<(usize, OsString)>,
        unit: Option<Unit>,
        db_file: OsString,
        tag: String,
    }

    /// Rename `from` in `from_dir` to `to` in `to_dir`, never replacing anything at `to`
    /// (Linux `RENAME_NOREPLACE`, macOS `RENAME_EXCL`).
    fn rename_between(
        from_dir: &OwnedFd,
        from: &OsStr,
        to_dir: &OwnedFd,
        to: &OsStr,
    ) -> std::io::Result<()> {
        rustix::fs::renameat_with(
            from_dir,
            from,
            to_dir,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }

    /// [`rename_between`] within one directory.
    fn rename_no_replace(dir: &OwnedFd, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        rename_between(dir, from, dir, to)
    }

    /// The names in `dir` (`.` and `..` excluded).
    fn list(dir: &OwnedFd) -> std::io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        for e in Dir::read_from(dir)? {
            let e = e?;
            let n = e.file_name().to_bytes();
            if n != b"." && n != b".." {
                names.push(OsStr::from_bytes(n).to_owned());
            }
        }
        Ok(names)
    }

    /// The family's names, the database first.
    fn family(db_file: &OsStr) -> Vec<OsString> {
        DB_SUFFIXES
            .iter()
            .map(|sfx| {
                let mut n = db_file.to_owned();
                n.push(sfx);
                n
            })
            .collect()
    }

    impl Unit {
        /// ⟨§17.35 items 1, 7⟩ [`rejoin`] this unit (the files the purge created
        /// removed, never restored).
        fn restore(&self, a: &Anchors, db_file: &OsStr) -> (Vec<PathBuf>, Vec<PathBuf>) {
            let created: Vec<(OsString, (u64, u64))> = self
                .held
                .iter()
                .filter(|h| h.created)
                .map(|h| (h.name.clone(), h.id))
                .collect();
            rejoin(&a.state, &self.dir, &self.name, self.id, db_file, &created)
        }

        /// ⟨§17.35 item 2 (W5-G02)⟩ Delete the unit: its companions first, then the
        /// database, then its record and its directory. On a failure the complete
        /// database is still in the unit: it is restored under [`rejoin`]'s rule, or kept
        /// and reported.
        fn delete(&self, a: &Anchors, db_file: &OsStr) -> Result<(), super::QuarantineError> {
            let names = family(db_file);
            let fail = |cause: std::io::Error| {
                let (restored, stuck) = self.restore(a, db_file);
                super::QuarantineError {
                    cause,
                    stuck,
                    restored,
                }
            };
            for n in names.iter().skip(1).chain(names.first()) {
                if matches!(kind(&self.dir, n), Ok(None)) {
                    continue;
                }
                #[cfg(test)]
                super::tests::unlink_hook(n);
                if super::unlink_fails(n) {
                    return Err(fail(std::io::Error::other("injected unlink failure")));
                }
                if let Err(e) = rustix::fs::unlinkat(&self.dir, n, AtFlags::empty()) {
                    return Err(fail(e.into()));
                }
            }
            let gone = rustix::fs::unlinkat(&self.dir, RECORD, AtFlags::empty())
                .or_else(|e| {
                    if e == rustix::io::Errno::NOENT {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .map_err(std::io::Error::from)
                .and_then(|()| remove_unit_dir(&a.state, &self.name, self.id));
            gone.map_err(|cause| super::QuarantineError {
                cause,
                stuck: vec![a.state.path.join(&self.name)],
                restored: Vec::new(),
            })
        }
    }

    /// ⟨§17.35 item 7 (audit D1, D2)⟩ The unit's record of its members (each family
    /// file's name and inspected identity), written and synced before the first move, so
    /// that after a crash at any point the unit can be rejoined exactly.
    const RECORD: &str = super::UNIT_RECORD;

    fn write_record(
        dir: &OwnedFd,
        state: &OwnedFd,
        family: &[(OsString, Manifest)],
    ) -> std::io::Result<()> {
        use std::io::Write as _;
        let fd = rustix::fs::openat(
            dir,
            RECORD,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let mut text = String::new();
        for (n, m) in family {
            if let Some((_, _, (d, i))) = m.first() {
                text.push_str(&format!("{}\t{d}\t{i}\n", n.to_string_lossy()));
            }
        }
        let mut f = std::fs::File::from(fd);
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        rustix::fs::fsync(dir)?;
        rustix::fs::fsync(state)?;
        Ok(())
    }

    fn read_record(dir: &OwnedFd) -> std::io::Result<Vec<(OsString, (u64, u64))>> {
        use std::io::Read as _;
        let fd = rustix::fs::openat(
            dir,
            RECORD,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut text = String::new();
        std::fs::File::from(fd).read_to_string(&mut text)?;
        text.lines()
            .map(|l| {
                let mut f = l.split('\t');
                match (
                    f.next(),
                    f.next().map(str::parse),
                    f.next().map(str::parse),
                    f.next(),
                ) {
                    (Some(n), Some(Ok(d)), Some(Ok(i)), None) => Ok((OsString::from(n), (d, i))),
                    _ => Err(refused("the quarantine record is malformed")),
                }
            })
            .collect()
    }

    /// Remove the (empty) unit directory `name` of `state`, while it is the one created.
    fn remove_unit_dir(state: &Root, name: &OsStr, id: (u64, u64)) -> std::io::Result<()> {
        match kind(&state.fd, name)? {
            Some((FileType::Directory, d, i)) if (d, i) == id => {
                rustix::fs::unlinkat(&state.fd, name, AtFlags::REMOVEDIR)?;
                Ok(())
            }
            None => Ok(()),
            _ => Err(refused("the quarantine directory was replaced")),
        }
    }

    /// ⟨ADR-0008 §17.35 items 1 and 7⟩ Rejoin a database family's quarantine unit `dir`
    /// (`name` in `<state>`) to `<state>`, by its record: every file in it must be a
    /// recorded member still the recorded inode, or one the purge created (an index, an
    /// empty log: removed, never restored); every original family name must be free or
    /// hold that member itself (one a crash or a failed move left at its name, still the
    /// recorded inode). Then the members move back, the database first; a companion that
    /// cannot follow moves the database back in, so no companion is ever restored alone.
    /// Otherwise the whole unit stays. Returns the paths renamed back and the paths left
    /// (the directory and each file in it).
    fn rejoin(
        state: &Root,
        dir: &OwnedFd,
        name: &OsStr,
        id: (u64, u64),
        db_file: &OsStr,
        created: &[(OsString, (u64, u64))],
    ) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let here = state.path.join(name);
        let all_left = || {
            let mut left = vec![here.clone()];
            if let Ok(mut ns) = list(dir) {
                ns.sort();
                left.extend(ns.iter().map(|n| here.join(n)));
            }
            (Vec::new(), left)
        };
        if super::restore_fails() {
            return all_left();
        }
        let names = family(db_file);
        let Ok(entries) = list(dir) else {
            return all_left();
        };
        if entries.iter().any(|e| e != RECORD && !names.contains(e)) {
            return all_left();
        }
        let record = if entries.iter().any(|e| e == RECORD) {
            match read_record(dir) {
                Ok(r) => r,
                Err(_) => return all_left(),
            }
        } else if entries.is_empty() {
            Vec::new()
        } else {
            return all_left();
        };
        let recorded = |n: &OsStr| record.iter().find(|(k, _)| k == n).map(|e| e.1);
        let mut present: Vec<OsString> = Vec::new();
        for n in &names {
            let Ok(found) = kind(dir, n) else {
                return all_left();
            };
            let Some((ty, d, i)) = found else {
                continue;
            };
            match recorded(n) {
                Some(r) if r == (d, i) && ty == FileType::RegularFile => present.push(n.clone()),
                Some(_) => return all_left(),
                None => {
                    let empty = rustix::fs::statat(dir, n, AtFlags::SYMLINK_NOFOLLOW)
                        .is_ok_and(|st| st.st_size == 0);
                    let ours = created.iter().any(|(c, cid)| c == n && *cid == (d, i))
                        || (ty == FileType::RegularFile
                            && (n.as_bytes().ends_with(b"-shm") || empty));
                    if !(ours && rustix::fs::unlinkat(dir, n, AtFlags::empty()).is_ok()) {
                        return all_left();
                    }
                }
            }
        }
        for n in &names {
            match kind(&state.fd, n) {
                Ok(None) => {}
                Ok(Some((_, d, i))) if !present.contains(n) && recorded(n) == Some((d, i)) => {}
                _ => return all_left(),
            }
        }
        let mut back: Vec<&OsString> = Vec::new();
        for n in &present {
            #[cfg(test)]
            super::tests::rejoin_hook(n);
            if rename_between(dir, n, &state.fd, n).is_err() {
                let mut restored = Vec::new();
                for b in back.iter().rev() {
                    if rename_between(&state.fd, b, dir, b).is_err() {
                        restored.push(state.path.join(b));
                    }
                }
                let (_, left) = all_left();
                return (restored, left);
            }
            back.push(n);
        }
        let restored = present.iter().map(|n| state.path.join(n)).collect();
        let _ = rustix::fs::unlinkat(dir, RECORD, AtFlags::empty());
        let left = if remove_unit_dir(state, name, id).is_ok() {
            Vec::new()
        } else {
            vec![here.clone()]
        };
        (restored, left)
    }

    impl Anchors {
        /// ⟨ADR-0008 §17.35 item 7 (audit D1, D2)⟩ An interrupted uninstall's quarantine,
        /// under the lock: each database family unit in `<state>` rejoined by its record
        /// ([`rejoin`]), each quarantined tree (`.hm-purge-<tag>-<tree>` in `<state>` or
        /// `<run>`) renamed back when its name is free; anything else at a `.hm-purge-*`
        /// name, or a database log left without its database, is reported as left.
        pub(super) fn recover(&self, db_file: &str) -> super::Recovered {
            let mut out = super::Recovered::default();
            let db = OsStr::new(db_file);
            for (which, root) in [(0, Some(&self.state)), (1, self.run.as_ref())] {
                let Some(root) = root else {
                    continue;
                };
                let Ok(mut names) = list(&root.fd) else {
                    out.left.push(root.path.clone());
                    continue;
                };
                names.sort();
                for n in names {
                    let Some(rest) = super::quarantine_rest(&n) else {
                        continue;
                    };
                    let trees: &[&str] = if which == 0 { &STATE_TREES } else { &RUN_TREES };
                    if which == 0 && rest == "database" {
                        match open_unit(&root.fd, &n) {
                            Ok((fd, id)) => {
                                let (r, l) = rejoin(root, &fd, &n, id, db, &[]);
                                out.restored.extend(r);
                                out.left.extend(l);
                            }
                            Err(_) => out.left.push(root.path.join(&n)),
                        }
                    } else if trees.contains(&rest.as_str())
                        && rename_no_replace(&root.fd, &n, OsStr::new(&rest)).is_ok()
                    {
                        out.restored.push(root.path.join(&rest));
                    } else {
                        out.left.push(root.path.join(&n));
                    }
                }
            }
            if matches!(kind(&self.state.fd, db), Ok(None)) {
                for n in family(db).iter().skip(1) {
                    if !matches!(kind(&self.state.fd, n), Ok(None)) {
                        out.left.push(self.state.path.join(n));
                    }
                }
            }
            out
        }
    }

    /// A unit directory found in `<state>`: this user's, owner-only, opened relative to
    /// the anchored handle.
    fn open_unit(state: &OwnedFd, name: &OsStr) -> std::io::Result<(OwnedFd, (u64, u64))> {
        let dir = rustix::fs::openat(state, name, dir_flags(), Mode::empty())?;
        let st = rustix::fs::fstat(&dir)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory
            || st.st_uid != euid()
            || mode_bits(&st) & 0o077 != 0
        {
            return Err(refused(
                "a quarantine directory is not this user's owner-only directory",
            ));
        }
        Ok((dir, id(&st)))
    }

    impl Quarantine {
        /// Rename everything back, then the refusal (with any entry left behind).
        fn refuse(self, a: &Anchors, cause: std::io::Error) -> super::QuarantineError {
            let stuck = self.restore(a).err().unwrap_or_default();
            super::QuarantineError {
                cause,
                stuck,
                restored: Vec::new(),
            }
        }

        /// ⟨§17.35 item 1⟩ Create the quarantine directory exclusively (`mkdirat`, then
        /// opened relative to `<state>`: this user's, owner-only) and move the family into
        /// it, each file keeping its name, never over anything.
        fn make_unit(
            &mut self,
            a: &Anchors,
            family: Vec<(OsString, Manifest)>,
        ) -> std::io::Result<()> {
            let name = super::unit_dir_name(&self.tag);
            rustix::fs::mkdirat(&a.state.fd, &name, Mode::from_raw_mode(0o700)).map_err(
                |e| match e {
                    rustix::io::Errno::EXIST => refused("a quarantine directory name was taken"),
                    e => e.into(),
                },
            )?;
            let dir = rustix::fs::openat(&a.state.fd, &name, dir_flags(), Mode::empty())?;
            let st = rustix::fs::fstat(&dir)?;
            if FileType::from_raw_mode(st.st_mode) != FileType::Directory
                || st.st_uid != euid()
                || mode_bits(&st) & 0o077 != 0
            {
                return Err(refused(
                    "the quarantine directory is not an owner-only directory of this user",
                ));
            }
            let unit = self.unit.insert(Unit {
                dir,
                id: id(&st),
                name,
                members: Vec::new(),
                held: Vec::new(),
            });
            // ⟨§17.35 item 7⟩ The record first, synced: a crash after any move below
            // leaves the unit rejoinable.
            write_record(&unit.dir, &a.state.fd, &family)?;
            for (n, m) in family {
                #[cfg(test)]
                super::tests::move_hook(&n);
                rename_between(&a.state.fd, &n, &unit.dir, &n)?;
                unit.members.push((n, m));
            }
            Ok(())
        }

        /// ⟨audit C0⟩ Hold the quarantined database, `-wal` and `-shm` by descriptor in
        /// the quarantine directory: a moved one opened there and required to be the
        /// inspected inode; an absent one created empty there (`O_CREAT | O_EXCL`). A
        /// `-journal` there must be the moved one.
        fn hold(&mut self) -> std::io::Result<()> {
            let db_file = self.db_file.clone();
            let Some(unit) = self.unit.as_mut() else {
                return Ok(());
            };
            if !unit.members.iter().any(|(n, _)| *n == db_file) {
                return Ok(());
            }
            for (i, name) in family(&db_file).into_iter().enumerate() {
                let moved = unit.members.iter().find(|(n, _)| *n == name);
                if i == 3 {
                    if moved.is_none() && kind(&unit.dir, &name)?.is_some() {
                        return Err(refused("a file appeared in the quarantine directory"));
                    }
                    continue;
                }
                let (fd, created) = match moved {
                    Some((_, m)) => {
                        let fd = rustix::fs::openat(
                            &unit.dir,
                            &name,
                            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                            Mode::empty(),
                        )?;
                        let st = rustix::fs::fstat(&fd)?;
                        let inspected = m.first().map(|e| e.2);
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
                            &unit.dir,
                            &name,
                            OFlags::RDWR
                                | OFlags::CREATE
                                | OFlags::EXCL
                                | OFlags::NOFOLLOW
                                | OFlags::CLOEXEC,
                            Mode::from_raw_mode(0o600),
                        )
                        .map_err(|e| match e {
                            rustix::io::Errno::EXIST => {
                                refused("a file appeared in the quarantine directory")
                            }
                            e => e.into(),
                        })?;
                        (fd, true)
                    }
                };
                let id = id(&rustix::fs::fstat(&fd)?);
                unit.held.push(Held {
                    name,
                    fd,
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
                let now = manifest(&root.fd, &m.qname, false)?;
                if now.as_ref() != Some(&m.manifest) {
                    return Err(refused(
                        "an entry changed between its inspection and its quarantine",
                    ));
                }
            }
            if let Some(u) = &self.unit {
                match kind(&a.state.fd, &u.name)? {
                    Some((FileType::Directory, d, i)) if (d, i) == u.id => {}
                    _ => return Err(refused("the quarantine directory was replaced")),
                }
                for (n, m) in &u.members {
                    if manifest(&u.dir, n, true)?.as_ref() != Some(m) {
                        return Err(refused(
                            "an entry changed between its inspection and its quarantine",
                        ));
                    }
                }
                for n in list(&u.dir)? {
                    let ours = n == RECORD
                        || u.members.iter().any(|(k, _)| *k == n)
                        || u.held.iter().any(|h| h.created && h.name == n);
                    if !ours {
                        return Err(refused("an entry appeared in the quarantine directory"));
                    }
                }
            }
            for (which, name) in &self.absent {
                if let Some(root) = a.root(*which)
                    && kind(&root.fd, name)?.is_some()
                {
                    return Err(refused("an entry appeared after the inspection"));
                }
            }
            self.held_in_place()
        }

        /// Every held file's name in the quarantine directory still names it.
        fn held_in_place(&self) -> std::io::Result<()> {
            let Some(u) = &self.unit else {
                return Ok(());
            };
            for h in &u.held {
                match kind(&u.dir, &h.name)? {
                    Some((FileType::RegularFile, d, i)) if (d, i) == h.id => {}
                    _ => return Err(refused("a quarantined database file was replaced")),
                }
            }
            Ok(())
        }

        /// ⟨audit C0⟩ `open` the quarantined database by its name in the quarantine
        /// directory (resolved from the held handle), `use` what it returned, and, before
        /// that is dropped, take a census of this process's regular-file descriptors: each
        /// held file (database, `-wal`, `-shm`) must be named by exactly one more
        /// descriptor than before (the one SQLite opened: so SQLite used those very
        /// inodes, and no file swapped in and back), and its name must still name it.
        /// ⟨audit D3⟩ `then` runs on the same connection only after the census
        /// confirmed it (the checkpoint: nothing unconfirmed is ever written).
        pub(super) fn read_db<S, T, U>(
            &self,
            _a: &Anchors,
            open: impl FnOnce(&Path) -> S,
            read: impl FnOnce(&S) -> T,
            then: impl FnOnce(&S) -> U,
        ) -> std::io::Result<Option<(T, std::io::Result<U>)>> {
            let Some(u) = &self.unit else {
                return Ok(None);
            };
            if u.held.is_empty() {
                return Ok(None);
            }
            let before = heimdall_runtime::platform::regular_file_descriptors()?;
            let path = current_path(&u.dir)?.join(&self.db_file);
            let store = open(&path);
            let out = read(&store);
            let confirmed = self.census(&before).map(|()| then(&store));
            drop(store);
            Ok(Some((out, confirmed)))
        }

        fn census(&self, before: &[(u64, u64)]) -> std::io::Result<()> {
            let after = heimdall_runtime::platform::regular_file_descriptors()?;
            let count = |v: &[(u64, u64)], id: (u64, u64)| v.iter().filter(|x| **x == id).count();
            for h in self.unit.iter().flat_map(|u| &u.held) {
                if count(&after, h.id) != count(before, h.id) + 1 {
                    return Err(refused(
                        "the final read did not read the quarantined database, log and index",
                    ));
                }
            }
            self.held_in_place()
        }

        /// ⟨§17.35 item 2⟩ The quarantined `-wal` is empty (zero bytes) or absent, and so
        /// is the held log file.
        pub(super) fn wal_empty(&self) -> std::io::Result<()> {
            let Some(u) = &self.unit else {
                return Ok(());
            };
            let mut wal = self.db_file.clone();
            wal.push("-wal");
            match rustix::fs::statat(&u.dir, &wal, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                Ok(st)
                    if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
                        && st.st_size == 0 => {}
                Ok(_) => return Err(refused("the write-ahead log is not empty")),
                Err(e) => return Err(e.into()),
            }
            for h in u.held.iter().filter(|h| h.name == wal) {
                if rustix::fs::fstat(&h.fd)?.st_size != 0 {
                    return Err(refused("the write-ahead log is not empty"));
                }
            }
            Ok(())
        }

        /// ⟨audit C1; §17.35 item 2⟩ Delete: refused, nothing deleted, unless the
        /// quarantined `-wal` is empty; then the trees, then the database unit (its
        /// companions, the database, its directory). When a tree's deletion fails, every
        /// tree not yet started (and a failed single file) is renamed back and the unit is
        /// restored under its rule; every path renamed back and every path left in
        /// quarantine is reported.
        pub(super) fn delete(self, a: &Anchors) -> Result<(), super::QuarantineError> {
            if let Err(cause) = self.wal_empty() {
                return Err(self.refuse(a, cause));
            }
            for (i, m) in self.moved.iter().enumerate() {
                let Some(root) = a.root(m.which) else {
                    continue;
                };
                if let Err(cause) = remove_tree(&root.fd, &m.qname) {
                    let (mut stuck, mut restored) = (Vec::new(), Vec::new());
                    let single = matches!(kind(&root.fd, &m.qname), Ok(Some((t, ..))) if t != FileType::Directory);
                    let rest = self.moved[i + 1..].iter();
                    for r in std::iter::once(m).filter(|_| single).chain(rest) {
                        let Some(root) = a.root(r.which) else {
                            continue;
                        };
                        if super::restore_fails()
                            || rename_no_replace(&root.fd, &r.qname, &r.name).is_err()
                        {
                            stuck.push(root.path.join(&r.qname));
                        } else {
                            restored.push(root.path.join(&r.name));
                        }
                    }
                    if !single && matches!(kind(&root.fd, &m.qname), Ok(Some(_)) | Err(_)) {
                        stuck.insert(0, root.path.join(&m.qname));
                    }
                    if let Some(u) = &self.unit {
                        let (r, s) = u.restore(a, &self.db_file);
                        restored.extend(r);
                        stuck.extend(s);
                    }
                    return Err(super::QuarantineError {
                        cause,
                        stuck,
                        restored,
                    });
                }
            }
            match &self.unit {
                Some(u) => u.delete(a, &self.db_file),
                None => Ok(()),
            }
        }

        pub(super) fn restore(self, a: &Anchors) -> Result<(), Vec<PathBuf>> {
            let mut stuck = Vec::new();
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
            if let Some(u) = &self.unit {
                stuck.extend(u.restore(a, &self.db_file).1);
            }
            if stuck.is_empty() { Ok(()) } else { Err(stuck) }
        }
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
                restored: Vec::new(),
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
            let mut trees = Vec::new();
            let mut family = Vec::new();
            let mut absent = Vec::new();
            for (which, name, is_db) in targets {
                let Some(root) = self.root(which) else {
                    continue;
                };
                match manifest(&root.join(&name), is_db).map_err(err)? {
                    Some(m) if is_db => family.push((name, m)),
                    Some(m) => trees.push((which, name, m)),
                    None => absent.push((which, name)),
                }
            }
            between();
            let mut q = Quarantine {
                moved: Vec::new(),
                absent,
                unit: None,
                db_file: db_file.to_owned(),
                tag: super::quarantine_tag(),
            };
            for (which, name, m) in trees {
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
            if !family.is_empty()
                && let Err(e) = q.make_unit(self, family)
            {
                return Err(q.refuse(self, e));
            }
            if let Err(e) = q.validate(self) {
                return Err(q.refuse(self, e));
            }
            // ⟨audit C0⟩ The database, its `-wal` and `-shm`, pinned for the read.
            if let Err(e) = q.hold() {
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

    /// ⟨audit C0⟩ One of the database's files, pinned in the quarantine directory (no
    /// share-delete: it cannot be renamed, deleted or replaced while held).
    struct Held {
        name: String,
        file: std::fs::File,
        id: (u64, u64),
        created: bool,
    }

    /// ⟨ADR-0008 §17.35 item 1⟩ The database family as one recovery unit, in one fresh
    /// owner-only quarantine directory created exclusively in `<state>` and pinned.
    struct Unit {
        path: PathBuf,
        pin: Option<std::fs::File>,
        id: (u64, u64),
        members: Vec<(String, Manifest)>,
        held: Vec<Held>,
        /// ⟨audit D5⟩ The files the purge created (name, file ID), kept after their pins
        /// are released.
        created: Vec<(String, (u64, u64))>,
    }

    pub(super) struct Quarantine {
        moved: Vec<Moved>,
        absent: Vec<(usize, String)>,
        unit: Option<Unit>,
        db_file: String,
        tag: String,
    }

    /// The family's names, the database first.
    fn family(db_file: &str) -> Vec<String> {
        DB_SUFFIXES
            .iter()
            .map(|sfx| format!("{db_file}{sfx}"))
            .collect()
    }

    /// The file ID of the entry at `path`, opened without following a reparse point;
    /// `None` when absent.
    fn id_at(path: &Path) -> std::io::Result<Option<(u64, u64)>> {
        match pin(path)? {
            None => Ok(None),
            Some((f, _)) => Ok(Some(heimdall_ipc::windows::file_id(&f)?)),
        }
    }

    impl Unit {
        /// ⟨§17.35 items 1, 7⟩ [`rejoin`] this unit. ⟨audit D5⟩ The identities of the
        /// files the purge created are kept until the deletion ends, so none is ever
        /// restored or listed as renamed back; the pins are released first (a pinned file
        /// cannot be moved).
        fn restore(&mut self, a: &Anchors, db_file: &str) -> (Vec<PathBuf>, Vec<PathBuf>) {
            self.unpin_files();
            drop(self.pin.take());
            rejoin(&a.state, &self.path, self.id, db_file, &self.created)
        }

        /// Release the pins on the held files, keeping what the purge created.
        fn unpin_files(&mut self) {
            for h in std::mem::take(&mut self.held) {
                if h.created {
                    self.created.push((h.name, h.id));
                }
            }
        }

        /// ⟨§17.35 item 2⟩ Companions first, then the database, then its record and the
        /// directory; on a failure the complete database stays, restored under
        /// [`rejoin`]'s rule or kept and reported.
        fn delete(&mut self, a: &Anchors, db_file: &str) -> Result<(), super::QuarantineError> {
            let names = family(db_file);
            self.unpin_files();
            for n in names.iter().skip(1).chain(names.first()) {
                let p = self.path.join(n);
                if std::fs::symlink_metadata(&p).is_err() {
                    continue;
                }
                let removed = if super::unlink_fails(std::ffi::OsStr::new(n)) {
                    Err(std::io::Error::other("injected unlink failure"))
                } else {
                    std::fs::remove_file(&p)
                };
                if let Err(cause) = removed {
                    let (restored, stuck) = self.restore(a, db_file);
                    return Err(super::QuarantineError {
                        cause,
                        stuck,
                        restored,
                    });
                }
            }
            drop(self.pin.take());
            let record = self.path.join(super::UNIT_RECORD);
            let gone = match std::fs::remove_file(&record) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
            .and_then(|()| remove_unit_dir(&self.path, self.id));
            gone.map_err(|cause| super::QuarantineError {
                cause,
                stuck: vec![self.path.clone()],
                restored: Vec::new(),
            })
        }
    }

    /// ⟨§17.35 item 7⟩ The unit's record (each family file's name and inspected file
    /// ID), written and flushed before the first move.
    fn write_record(dir: &Path, family: &[(String, Manifest)]) -> std::io::Result<()> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(super::UNIT_RECORD))?;
        let mut text = String::new();
        for (n, m) in family {
            if let Some((_, (v, i))) = m.first() {
                text.push_str(&format!("{n}\t{v}\t{i}\n"));
            }
        }
        f.write_all(text.as_bytes())?;
        f.sync_all()
    }

    fn read_record(dir: &Path) -> std::io::Result<Vec<(String, (u64, u64))>> {
        let text = std::fs::read_to_string(dir.join(super::UNIT_RECORD))?;
        text.lines()
            .map(|l| {
                let mut f = l.split('\t');
                match (
                    f.next(),
                    f.next().map(str::parse),
                    f.next().map(str::parse),
                    f.next(),
                ) {
                    (Some(n), Some(Ok(v)), Some(Ok(i)), None) => Ok((n.to_owned(), (v, i))),
                    _ => Err(refused("the quarantine record is malformed")),
                }
            })
            .collect()
    }

    /// Remove the (empty) unit directory, while it is the one created.
    fn remove_unit_dir(path: &Path, id: (u64, u64)) -> std::io::Result<()> {
        match pin(path)? {
            None => Ok(()),
            Some((f, attrs)) => {
                let same = heimdall_ipc::windows::file_id(&f)? == id
                    && attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0;
                drop(f);
                if !same {
                    return Err(refused("the quarantine directory was replaced"));
                }
                std::fs::remove_dir(path)
            }
        }
    }

    /// ⟨ADR-0008 §17.35 items 1 and 7⟩ As on Unix: rejoin the unit at `here` by its
    /// record, or leave it whole. (Paths renamed back, paths left.)
    fn rejoin(
        state: &Path,
        here: &Path,
        id: (u64, u64),
        db_file: &str,
        created: &[(String, (u64, u64))],
    ) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let entries = || -> Vec<String> {
            let mut ns: Vec<String> = std::fs::read_dir(here)
                .map(|es| {
                    es.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            ns.sort();
            ns
        };
        let all_left = || {
            let mut left = vec![here.to_path_buf()];
            left.extend(entries().iter().map(|n| here.join(n)));
            (Vec::new(), left)
        };
        if super::restore_fails() {
            return all_left();
        }
        let names = family(db_file);
        let found = entries();
        if found
            .iter()
            .any(|e| e != super::UNIT_RECORD && !names.contains(e))
        {
            return all_left();
        }
        let record = if found.iter().any(|e| e == super::UNIT_RECORD) {
            match read_record(here) {
                Ok(r) => r,
                Err(_) => return all_left(),
            }
        } else if found.is_empty() {
            Vec::new()
        } else {
            return all_left();
        };
        let recorded = |n: &str| record.iter().find(|(k, _)| k == n).map(|e| e.1);
        let mut present: Vec<String> = Vec::new();
        for n in &names {
            let p = here.join(n);
            let Ok(now) = id_at(&p) else {
                return all_left();
            };
            let Some(now) = now else {
                continue;
            };
            match recorded(n) {
                Some(r) if r == now => present.push(n.clone()),
                Some(_) => return all_left(),
                None => {
                    let empty =
                        std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file() && m.len() == 0);
                    let ours = created.iter().any(|(c, cid)| c == n && *cid == now)
                        || n.ends_with("-shm")
                        || empty;
                    if !(ours && std::fs::remove_file(&p).is_ok()) {
                        return all_left();
                    }
                }
            }
        }
        for n in &names {
            match id_at(&state.join(n)) {
                Ok(None) => {}
                Ok(Some(now)) if !present.contains(n) && recorded(n) == Some(now) => {}
                _ => return all_left(),
            }
        }
        let mut back: Vec<&String> = Vec::new();
        for n in &present {
            if heimdall_ipc::windows::move_no_replace(&here.join(n), &state.join(n)).is_err() {
                let mut restored = Vec::new();
                for b in back.iter().rev() {
                    if heimdall_ipc::windows::move_no_replace(&state.join(b), &here.join(b))
                        .is_err()
                    {
                        restored.push(state.join(b));
                    }
                }
                let (_, left) = all_left();
                return (restored, left);
            }
            back.push(n);
        }
        let restored = present.iter().map(|n| state.join(n)).collect();
        let _ = std::fs::remove_file(here.join(super::UNIT_RECORD));
        let left = if remove_unit_dir(here, id).is_ok() {
            Vec::new()
        } else {
            vec![here.to_path_buf()]
        };
        (restored, left)
    }

    impl Anchors {
        /// ⟨§17.35 item 7⟩ As on Unix.
        pub(super) fn recover(&self, db_file: &str) -> super::Recovered {
            let mut out = super::Recovered::default();
            let me = heimdall_ipc::windows::current_user_sid().ok();
            for (which, root) in [(0, Some(&self.state)), (1, self.run.as_ref())] {
                let Some(root) = root else {
                    continue;
                };
                let Ok(es) = std::fs::read_dir(root) else {
                    out.left.push(root.clone());
                    continue;
                };
                let mut names: Vec<std::ffi::OsString> =
                    es.flatten().map(|e| e.file_name()).collect();
                names.sort();
                for n in names {
                    let Some(rest) = super::quarantine_rest(&n) else {
                        continue;
                    };
                    let at = root.join(&n);
                    let trees: &[&str] = if which == 0 { &STATE_TREES } else { &RUN_TREES };
                    if which == 0 && rest == "database" {
                        let ours = pin(&at).ok().flatten().and_then(|(f, attrs)| {
                            let owner = heimdall_ipc::windows::file_owner_sid(&f).ok();
                            (attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0
                                && attrs & FILE_ATTRIBUTE_DIRECTORY != 0
                                && owner.is_some()
                                && owner == me)
                                .then(|| heimdall_ipc::windows::file_id(&f).ok())
                                .flatten()
                        });
                        match ours {
                            Some(id) => {
                                let (r, l) = rejoin(root, &at, id, db_file, &[]);
                                out.restored.extend(r);
                                out.left.extend(l);
                            }
                            None => out.left.push(at),
                        }
                    } else if trees.contains(&rest.as_str())
                        && heimdall_ipc::windows::move_no_replace(&at, &root.join(&rest)).is_ok()
                    {
                        out.restored.push(root.join(&rest));
                    } else {
                        out.left.push(at);
                    }
                }
            }
            if std::fs::symlink_metadata(self.state.join(db_file)).is_err() {
                for n in family(db_file).iter().skip(1) {
                    let p = self.state.join(n);
                    if std::fs::symlink_metadata(&p).is_ok() {
                        out.left.push(p);
                    }
                }
            }
            out
        }
    }

    impl Quarantine {
        fn refuse(self, a: &Anchors, cause: std::io::Error) -> super::QuarantineError {
            let stuck = self.restore(a).err().unwrap_or_default();
            super::QuarantineError {
                cause,
                stuck,
                restored: Vec::new(),
            }
        }

        /// ⟨§17.35 item 1⟩ Create the quarantine directory exclusively, owner-only
        /// (`CreateDirectoryW` with this user's protected DACL), pin it, and move the
        /// family into it, each file keeping its name, never over anything.
        fn make_unit(
            &mut self,
            a: &Anchors,
            family: Vec<(String, Manifest)>,
        ) -> std::io::Result<()> {
            let path = a.state.join(super::unit_dir_name(&self.tag));
            heimdall_ipc::windows::create_dir_owner_only(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    refused("a quarantine directory name was taken")
                } else {
                    e
                }
            })?;
            let Some((dir, attrs)) = pin(&path)? else {
                return Err(refused("the quarantine directory vanished"));
            };
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(refused("the quarantine directory is not a directory"));
            }
            let me = heimdall_ipc::windows::current_user_sid()?;
            if heimdall_ipc::windows::file_owner_sid(&dir)? != me {
                return Err(refused("the quarantine directory is not this user's"));
            }
            let unit = self.unit.insert(Unit {
                path,
                id: heimdall_ipc::windows::file_id(&dir)?,
                pin: Some(dir),
                members: Vec::new(),
                held: Vec::new(),
                created: Vec::new(),
            });
            // ⟨§17.35 item 7⟩ The record first, flushed.
            write_record(&unit.path, &family)?;
            for (n, m) in family {
                heimdall_ipc::windows::move_no_replace(&a.state.join(&n), &unit.path.join(&n))?;
                unit.members.push((n, m));
            }
            Ok(())
        }

        /// ⟨audit C0⟩ Pin the quarantined database, `-wal` and `-shm` in the quarantine
        /// directory for the whole read (a moved one checked against its inspected file ID;
        /// an absent one created empty with `create_new`); a `-journal` there must be the
        /// moved one.
        fn hold(&mut self) -> std::io::Result<()> {
            let db_file = self.db_file.clone();
            let Some(unit) = self.unit.as_mut() else {
                return Ok(());
            };
            if !unit.members.iter().any(|(n, _)| *n == db_file) {
                return Ok(());
            }
            for (i, name) in family(&db_file).into_iter().enumerate() {
                let path = unit.path.join(&name);
                let moved = unit.members.iter().find(|(n, _)| *n == name);
                if i == 3 {
                    if moved.is_none() && std::fs::symlink_metadata(&path).is_ok() {
                        return Err(refused("a file appeared in the quarantine directory"));
                    }
                    continue;
                }
                let (file, created) = match moved {
                    Some((_, m)) => {
                        let Some((file, attrs)) = pin(&path)? else {
                            return Err(refused("a quarantined database file vanished"));
                        };
                        let inspected = m.first().map(|e| e.1);
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
                                    refused("a file appeared in the quarantine directory")
                                }
                                _ => e,
                            })?;
                        (file, true)
                    }
                };
                let id = heimdall_ipc::windows::file_id(&file)?;
                unit.held.push(Held {
                    name,
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
                let now = manifest(&root.join(&m.qname), false)?;
                if now.as_ref() != Some(&m.manifest) {
                    return Err(refused(
                        "an entry changed between its inspection and its quarantine",
                    ));
                }
            }
            if let Some(u) = &self.unit {
                if id_at(&u.path)? != Some(u.id) {
                    return Err(refused("the quarantine directory was replaced"));
                }
                for (n, m) in &u.members {
                    if manifest(&u.path.join(n), true)?.as_ref() != Some(m) {
                        return Err(refused(
                            "an entry changed between its inspection and its quarantine",
                        ));
                    }
                }
                for e in std::fs::read_dir(&u.path)? {
                    let n = e?.file_name().to_string_lossy().into_owned();
                    let ours = n == super::UNIT_RECORD
                        || u.members.iter().any(|(k, _)| *k == n)
                        || u.held.iter().any(|h| h.created && h.name == n);
                    if !ours {
                        return Err(refused("an entry appeared in the quarantine directory"));
                    }
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

        /// Every pinned file is still the one its path names.
        fn held_in_place(&self) -> std::io::Result<()> {
            let Some(u) = &self.unit else {
                return Ok(());
            };
            for h in &u.held {
                let named = std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(SHARE_NO_DELETE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(u.path.join(&h.name))?;
                if heimdall_ipc::windows::file_id(&named)? != h.id
                    || heimdall_ipc::windows::file_id(&h.file)? != h.id
                {
                    return Err(refused("a quarantined database file was replaced"));
                }
            }
            Ok(())
        }

        /// ⟨audit C0⟩ `open` the quarantined database in its quarantine directory and
        /// `read` it, all three files pinned throughout; before the store is dropped, each
        /// pinned file must still be the one its path names.
        pub(super) fn read_db<S, T, U>(
            &self,
            _a: &Anchors,
            open: impl FnOnce(&Path) -> S,
            read: impl FnOnce(&S) -> T,
            then: impl FnOnce(&S) -> U,
        ) -> std::io::Result<Option<(T, std::io::Result<U>)>> {
            let Some(u) = &self.unit else {
                return Ok(None);
            };
            if u.held.is_empty() {
                return Ok(None);
            }
            let store = open(&u.path.join(&self.db_file));
            let out = read(&store);
            let confirmed = self.held_in_place().map(|()| then(&store));
            drop(store);
            Ok(Some((out, confirmed)))
        }

        /// ⟨§17.35 item 2⟩ The quarantined `-wal` is empty (zero bytes) or absent.
        pub(super) fn wal_empty(&self) -> std::io::Result<()> {
            let Some(u) = &self.unit else {
                return Ok(());
            };
            let wal = format!("{}-wal", self.db_file);
            match std::fs::symlink_metadata(u.path.join(&wal)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Ok(m) if m.is_file() && m.len() == 0 => {}
                Ok(_) => return Err(refused("the write-ahead log is not empty")),
                Err(e) => return Err(e),
            }
            for h in u.held.iter().filter(|h| h.name == wal) {
                if h.file.metadata()?.len() != 0 {
                    return Err(refused("the write-ahead log is not empty"));
                }
            }
            Ok(())
        }

        /// ⟨audit C1; §17.35 item 2⟩ As on Unix.
        pub(super) fn delete(mut self, a: &Anchors) -> Result<(), super::QuarantineError> {
            if let Err(cause) = self.wal_empty() {
                return Err(self.refuse(a, cause));
            }
            for (i, m) in self.moved.iter().enumerate() {
                let Some(root) = a.root(m.which) else {
                    continue;
                };
                let at = root.join(&m.qname);
                if let Err(cause) = remove_tree(&at, Path::new(""), &m.manifest) {
                    let (mut stuck, mut restored) = (Vec::new(), Vec::new());
                    let single = std::fs::symlink_metadata(&at).is_ok_and(|md| !md.is_dir());
                    let rest = self.moved[i + 1..].iter();
                    for r in std::iter::once(m).filter(|_| single).chain(rest) {
                        let Some(root) = a.root(r.which) else {
                            continue;
                        };
                        let (from, to) = (root.join(&r.qname), root.join(&r.name));
                        if super::restore_fails()
                            || heimdall_ipc::windows::move_no_replace(&from, &to).is_err()
                        {
                            stuck.push(from);
                        } else {
                            restored.push(to);
                        }
                    }
                    if !single && std::fs::symlink_metadata(&at).is_ok() {
                        stuck.insert(0, at);
                    }
                    if let Some(u) = self.unit.as_mut() {
                        let (r, s) = u.restore(a, &self.db_file);
                        restored.extend(r);
                        stuck.extend(s);
                    }
                    return Err(super::QuarantineError {
                        cause,
                        stuck,
                        restored,
                    });
                }
            }
            let db_file = self.db_file.clone();
            match self.unit.as_mut() {
                Some(u) => u.delete(a, &db_file),
                None => Ok(()),
            }
        }

        pub(super) fn restore(mut self, a: &Anchors) -> Result<(), Vec<PathBuf>> {
            let mut stuck = Vec::new();
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
            let db_file = self.db_file.clone();
            if let Some(u) = self.unit.as_mut() {
                stuck.extend(u.restore(a, &db_file).1);
            }
            if stuck.is_empty() { Ok(()) } else { Err(stuck) }
        }
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
pub(crate) mod tests {
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

    /// Run `body` with `hook` called before each file's `unlinkat` (other modules' tests).
    #[cfg(unix)]
    pub(crate) fn with_unlink_hook<T>(
        hook: impl FnMut(&std::ffi::OsStr) + 'static,
        body: impl FnOnce() -> T,
    ) -> T {
        UNLINK_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        let out = body();
        UNLINK_HOOK.with(|h| *h.borrow_mut() = None);
        out
    }

    /// The database family's quarantine directory under `state`, if any.
    #[cfg(unix)]
    pub(crate) fn unit_dir(state: &std::path::Path) -> Option<std::path::PathBuf> {
        std::fs::read_dir(state)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.starts_with(".hm-purge-") && n.ends_with("-database")
                })
            })
    }

    thread_local! {
        /// ⟨§17.35 item 7⟩ A simulated crash: the phase (`"move"`, `"rejoin"`) and the
        /// family file before whose move the process stops (a panic: no cleanup runs).
        static CRASH_AT: std::cell::RefCell<Option<(&'static str, std::ffi::OsString)>> =
            const { std::cell::RefCell::new(None) };
    }

    fn crash_hook(phase: &str, name: &std::ffi::OsStr) {
        let hit = CRASH_AT.with(|c| {
            c.borrow()
                .as_ref()
                .is_some_and(|(p, n)| *p == phase && n.as_os_str() == name)
        });
        if hit {
            CRASH_AT.with(|c| *c.borrow_mut() = None);
            panic!("simulated crash before moving {}", name.to_string_lossy());
        }
    }

    /// Before each family file's move into the unit.
    #[cfg_attr(windows, allow(dead_code))]
    pub(super) fn move_hook(name: &std::ffi::OsStr) {
        crash_hook("move", name);
    }

    /// Before each member's move back out of the unit.
    #[cfg_attr(windows, allow(dead_code))]
    pub(super) fn rejoin_hook(name: &std::ffi::OsStr) {
        crash_hook("rejoin", name);
    }

    /// Run `body`, which stops (a simulated crash) just before `name` is moved in
    /// `phase`; `true` when it did.
    #[cfg(unix)]
    pub(crate) fn crashing_at(phase: &'static str, name: &str, body: impl FnOnce()) -> bool {
        CRASH_AT.with(|c| *c.borrow_mut() = Some((phase, std::ffi::OsString::from(name))));
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_err();
        CRASH_AT.with(|c| *c.borrow_mut() = None);
        crashed
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
            // A quarantine name, or a file in the database family's quarantine directory.
            assert!(
                p.iter()
                    .any(|n| n.to_string_lossy().starts_with(".hm-purge-")),
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
                let q = s.join(unit_dir_name(tag)).join("state.db");
                std::fs::rename(&q, &r).unwrap_or_else(|e| panic!("{e}"));
                std::fs::write(&q, b"decoy").unwrap_or_else(|e| panic!("{e}"));
            }));
        });
        let end = anchors.quarantine("state.db", || {});
        BEFORE_HOLD.with(|h| *h.borrow_mut() = None);
        let Err(e) = end else {
            panic!("a decoy database was held for the final read")
        };
        // The decoy is not the recorded member, so the unit is not rejoined (§17.35
        // item 1): it stays whole, reported; nothing is deleted.
        assert!(
            e.stuck.iter().any(|p| p.ends_with("state.db")),
            "{:?}",
            e.stuck
        );
        assert!(
            !state.join("state.db").exists(),
            "a decoy is never restored as the database"
        );
        assert_eq!(std::fs::read(&real).ok().as_deref(), Some(&b"db"[..]));
        assert!(state.join("backups").join("f").exists());
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
            stuck.iter().any(|p| p.ends_with("state.db")
                && p.parent()
                    .is_some_and(|d| d.to_string_lossy().ends_with("-database"))
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

    // --- ADR-0008 §17.35 items 1-2 (W5-G01, W5-G02) --------------------------------------

    /// `final_review_companion_failure_preserves_database` (ADR-0008 §17.35 item 2, the
    /// re-check's probe): the database family is deleted companions first, the database
    /// last. When a companion's deletion fails (its quarantine directory made read-only
    /// just before the `-wal` is unlinked), the complete database remains, under its
    /// normal name or in its quarantine directory, and the report names exactly where.
    #[cfg(unix)]
    #[test]
    fn final_review_companion_failure_preserves_database() {
        use std::os::unix::fs::PermissionsExt as _;
        let (d, state, run) = roots();
        std::fs::write(state.join("state.db-wal"), b"").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        let st = state.clone();
        let end = with_unlink_hook(
            move |name| {
                if name == std::ffi::OsStr::new("state.db-wal")
                    && let Some(u) = unit_dir(&st)
                {
                    let _ = std::fs::set_permissions(&u, std::fs::Permissions::from_mode(0o500));
                }
            },
            || q.delete(),
        );
        if let Some(u) = unit_dir(&state) {
            let _ = std::fs::set_permissions(&u, std::fs::Permissions::from_mode(0o700));
        }
        let Err(e) = end else {
            panic!("the companion's deletion could not have succeeded")
        };
        let normal = state.join("state.db");
        let kept = e
            .stuck
            .iter()
            .find(|p| p.ends_with("state.db") && p.exists())
            .cloned();
        let copy = if normal.exists() {
            Some(normal.clone())
        } else {
            kept
        };
        assert_eq!(
            copy.and_then(|p| std::fs::read(p).ok()).as_deref(),
            Some(&b"db"[..]),
            "database was deleted before its companion failure, with no normal or quarantined copy left"
        );
        assert_eq!(
            e.restored.contains(&normal),
            normal.exists(),
            "the report says the database was renamed back exactly when it was: {e:?}"
        );
    }

    /// `delete_refuses_a_non_empty_wal` (ADR-0008 §17.35 item 2): a quarantined `-wal`
    /// that is not empty (never checkpointed) refuses the deletion with nothing deleted:
    /// every entry is renamed back, the database with its log.
    #[cfg(unix)]
    #[test]
    fn delete_refuses_a_non_empty_wal() {
        let (d, state, run) = roots();
        std::fs::write(state.join("state.db-wal"), b"frames").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        let Err(e) = q.delete() else {
            panic!("a database family with a non-empty log was deleted")
        };
        assert!(e.stuck.is_empty(), "{:?}", e.stuck);
        assert_eq!(
            std::fs::read(state.join("state.db")).ok().as_deref(),
            Some(&b"db"[..])
        );
        assert_eq!(
            std::fs::read(state.join("state.db-wal")).ok().as_deref(),
            Some(&b"frames"[..])
        );
        assert!(state.join("backups").join("f").exists() && run.join("b").exists());
        assert!(
            !state.join("state.db-shm").exists(),
            "the purge's own -shm is removed"
        );
    }

    /// `no_purge_created_file_is_restored_or_listed_as_renamed_back` (ADR-0008 §17.35
    /// item 8, audit D5; on Windows the native run of this test closes D5): the deletion
    /// of a companion fails (injected) after the purge created the `-wal` and `-shm` it
    /// held for the read; the unit is rejoined, and neither file the purge created is
    /// restored or reported as renamed back.
    #[test]
    fn no_purge_created_file_is_restored_or_listed_as_renamed_back() {
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let (state, run) = (d.path().join("state"), d.path().join("run"));
        for p in [&state, &run] {
            std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("{e}"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
                    .unwrap_or_else(|e| panic!("{e}"));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(state.join("state.db"), b"db").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        FAIL_UNLINK.with(|f| *f.borrow_mut() = Some("state.db-shm".into()));
        let end = q.delete();
        FAIL_UNLINK.with(|f| *f.borrow_mut() = None);
        let Err(e) = end else {
            panic!("the injected failure was not reported")
        };
        assert_eq!(e.restored, vec![state.join("state.db")], "{e:?}");
        assert!(e.stuck.is_empty(), "{e:?}");
        assert_eq!(
            std::fs::read(state.join("state.db")).ok().as_deref(),
            Some(&b"db"[..])
        );
        for sfx in ["-wal", "-shm"] {
            assert!(
                !state.join(format!("state.db{sfx}")).exists(),
                "the purge's own {sfx} was restored"
            );
        }
    }

    /// `final_review_quarantine_dir_removal_failure_reports_what_is_on_disk` (ADR-0008
    /// §17.35 item 8, audit D4): the database is deleted, then the quarantine directory's
    /// removal fails (an entry appears in it); the error lists the directory, which no
    /// longer holds the database.
    #[cfg(unix)]
    #[test]
    fn final_review_quarantine_dir_removal_failure_reports_what_is_on_disk() {
        let (d, state, run) = roots();
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        let st = state.clone();
        let end = with_unlink_hook(
            move |name| {
                if name == std::ffi::OsStr::new("state.db")
                    && let Some(u) = unit_dir(&st)
                {
                    let _ = std::fs::write(u.join("placed"), b"x");
                }
            },
            || q.delete(),
        );
        let Err(e) = end else {
            panic!("the directory's removal could not have succeeded")
        };
        let u = unit_dir(&state).unwrap_or_else(|| panic!("the directory is left"));
        assert_eq!(e.stuck, vec![u.clone()]);
        assert!(!u.join("state.db").exists(), "the database was deleted");
        assert!(e.restored.is_empty());
    }
}
