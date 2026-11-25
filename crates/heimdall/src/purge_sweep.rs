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
//! **Quarantine, validate, delete (ADR-0008 §17.34 item 1, §17.35 items 1 and 7,
//! §17.36 item 1; W5-F01, F02, G01, H01, H02; the audits' C0-C4, D1-D5).** SQLite never
//! opens the owner's original database family read-write. [`Anchors::quarantine`]: a
//! family that contains a `-journal` is refused before anything moves (the store is
//! WAL-mode: a hot rollback journal is never legitimate). Every entry the purge removes
//! (the database and its `-wal`/`-shm`, `backups`, `managed`, `b`, `mux`) is inspected
//! (each path below it with its kind and identity; any link or reparse point refuses),
//! then moved atomically and **never over anything** (Linux `RENAME_NOREPLACE`, macOS
//! `RENAME_EXCL`, Windows `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`): each tree to
//! a fresh random quarantine name in its own anchored directory, and the **database
//! family as one unit** into one fresh owner-only quarantine directory
//! (`.hm-purge-<tag>-database`, created exclusively in `<state>`, its record of members
//! written and synced first), where the files keep their names. Then everything is
//! checked again against what was inspected. The database, its `-wal` and its `-shm` are
//! **held** there (a moved one opened and required to be the inspected inode; an absent
//! one created empty by the purge with `O_EXCL`; Windows: all three pinned). The final
//! read, the snapshot comparison and the bundle check run on a **read-only** connection
//! ([`Quarantine::read_db`]; the journal check repeated just before it opens), confirmed
//! before its store is dropped (Unix: a census of this process's regular-file
//! descriptors, one more descriptor of each held file; Windows: the pins), and from that
//! confirmed connection the purge writes the **recovery copy** with `VACUUM INTO`
//! (self-contained, no log) to an exclusively created file in the quarantine directory,
//! checked, synced and renamed to [`UNIT_COPY`]. Then everything is checked again
//! ([`Quarantine::validate`]) and only then is anything deleted ([`Quarantine::delete`]):
//! the trees, then the original family's companions, the original database, the
//! recovery copy, the directory; a failure at any step leaves at least the complete
//! recovery copy (restored as `state.db`, or in quarantine), reported with its exact path.
//! A restore ([`Quarantine::restore`]) renames each tree back and restores **the recovery
//! copy alone** as `state.db` by one no-replace rename (one atomic step with no log to
//! attach); the original family stays in its quarantine directory, reported, for a later
//! `heimdall uninstall` to delete once the restored database is confirmed (it opens and
//! its snapshot equals the original family's). Before the copy exists, the family stays
//! whole in its quarantine directory. Start-up refuses while any quarantine exists, and
//! `heimdall uninstall` recovers first ([`Anchors::recover`]). **What remains (the `RESIDUALS` entry
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
/// (`heimdall_credential::endpoints::BINDING_DIR`), ⟨M04⟩ the container environments' stable
/// directories (`CONTAINER_DIR`: owned resources of the container recipe, ADR-0010 §4 item 1,
/// removed by identity like the rest) and the stable multiplex paths
/// (`heimdall_localenv::projection::content::managed_mux_path`).
const RUN_TREES: [&str; 3] = ["b", "c", "mux"];

/// The lock file runtime start-up locks (`heimdall_runtime::instance`).
#[cfg(unix)]
const LOCK_FILE: &str = "service.lock";

/// ⟨M08 U2b-1; ADR-0014 §3.6⟩ The generation layout's entries under `<state>` that the
/// purge removes once the store's family and its recovery copy are deleted: the
/// temporaries, every generation (the current one with its record and migration notes,
/// and each earlier one), the flat family an adoption fenced, the request ledger, the
/// intent, and **the pointer last**.
///
/// The pointer and the generations cannot be removed in one step. A crash or I/O error
/// between these removals therefore leaves a pointer without its store, or generations
/// without a pointer. The next start then refuses with `state_corrupt`; no data is lost
/// that the owner did not confirm deleting. The named residual is
/// `purge_layout_removal_interrupted_leaves_state_corrupt`.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
const LAYOUT_ENTRIES: [&str; 11] = [
    heimdall_store::layout::stategen::generations::CURRENT_TMP,
    heimdall_store::layout::stategen::generations::INTENT_TMP,
    heimdall_store::layout::stategen::generations::GENERATIONS,
    "state.db-journal",
    "state.db-wal",
    "state.db-shm",
    heimdall_store::layout::DB_FILE,
    heimdall_store::layout::stategen::ledger::LEDGER_TMP,
    heimdall_store::layout::stategen::ledger::LEDGER,
    heimdall_store::layout::stategen::generations::INTENT,
    heimdall_store::layout::stategen::generations::CURRENT,
];

/// ⟨ADR-0008 §17.33 items 4, 7⟩ The Windows residual window, named (module docs).
// The name the claims table and ADR-0008 cite; nothing reads it at run time.
#[allow(dead_code)]
pub(crate) const WINDOWS_RESIDUAL: &str = "windows_purge_entry_replaced_between_check_and_delete";

/// ⟨ADR-0008 §17.36 item 1⟩ The refusal of a database family with a rollback journal
/// (`InvalidData`, so the command names it).
fn journal_refused() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the purge refused: the state database has a rollback journal, which a WAL-mode store never leaves; it is kept",
    )
}

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
        let family = family_dir(state_dir)?;
        Ok(Anchors {
            inner: imp::Anchors::open(state_dir, runtime_dir, family.as_deref(), top)?,
        })
    }

    /// [`Anchors::open`] with an injected private-group oracle (tests: a simulated
    /// user-private-group host, or a shared-group one).
    ///
    /// # Errors
    /// As [`Anchors::open`].
    #[cfg(all(test, unix))]
    pub(crate) fn open_with_group(
        state_dir: &Path,
        runtime_dir: &Path,
        top: Option<&Path>,
        group: &dyn Fn() -> std::io::Result<Option<u32>>,
    ) -> std::io::Result<Anchors> {
        let family = family_dir(state_dir)?;
        Ok(Anchors {
            inner: imp::Anchors::open_with_group(
                state_dir,
                runtime_dir,
                family.as_deref(),
                top,
                group,
            )?,
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

    /// ⟨ADR-0008 §17.35 item 7, §17.36 item 1⟩ Handle an interrupted uninstall's
    /// quarantine (call with the lock held): each database family unit's database is
    /// restored as its recovery copy alone (written first, from a read-only
    /// census-confirmed connection, when there is none), the original family deleted
    /// once `ops.confirm` finds the restored database equal to it; each quarantined
    /// tree renamed back when its name is free; whatever cannot be is reported as left.
    pub(crate) fn recover(&self, db_file: &str, ops: &RecoverOps<'_>) -> Recovered {
        self.inner.recover(db_file, ops)
    }

    /// ⟨M08 U2b-1; ADR-0014 §3.6⟩ After [`Quarantine::delete`] succeeded (the store's family
    /// and its recovery copy are gone), remove the generation layout's entries in
    /// `<state>` ([`LAYOUT_ENTRIES`]: every generation, the fenced flat family, the
    /// intent, the pointer last), still under the lock. Nothing in the flat layout.
    ///
    /// # Errors
    /// A removal failed: the entries still there are listed (`stuck`).
    pub(crate) fn remove_layout(&mut self) -> Result<(), QuarantineError> {
        self.inner.remove_layout()
    }

    /// Quarantine, validate and delete in one go (the deletion without a database read).
    ///
    /// # Errors
    /// As [`Anchors::quarantine`] and [`Quarantine::delete`].
    #[cfg(test)]
    pub(crate) fn purge(&self, db_file: &str, between: impl FnOnce()) -> std::io::Result<()> {
        let mut q = self
            .quarantine(db_file, between)
            .map_err(QuarantineError::into_io)?;
        q.fake_copy()?;
        q.delete(&|_| true).map_err(QuarantineError::into_io)
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
    /// ⟨ADR-0008 §17.34 item 1, §17.36 item 1; audit C0⟩ The final read and the recovery
    /// copy. `open` (a **read-only** connection: it can never roll a journal back, and a
    /// `-journal` refuses before it, checked again just before the open) the quarantined
    /// database by its name in its quarantine directory, then `read` it; the database,
    /// its `-wal` and its `-shm` are held there throughout. Before what `open` returned
    /// is dropped the read is **confirmed** (Unix: the descriptor census; Windows: the
    /// pins), and only then `copy` writes the **recovery copy** from that connection
    /// (`VACUUM INTO` an exclusively created file in the quarantine directory), which is
    /// checked, synced and renamed into place. `None` when there is no database; else
    /// `read`'s result and the confirmation (`Err`: what was read is not what is deleted,
    /// or the copy could not be written).
    ///
    /// # Errors
    /// A rollback journal, or the census could not be taken.
    pub(crate) fn read_db<S, T>(
        &mut self,
        open: impl FnOnce(&Path) -> S,
        read: impl FnOnce(&S) -> T,
        copy: impl FnOnce(&S, &Path) -> bool,
    ) -> std::io::Result<Option<(T, std::io::Result<()>)>> {
        self.inner.read_db(&self.anchors.inner, open, read, copy)
    }

    /// ⟨tests only⟩ A byte copy of the quarantined database as its recovery copy (the
    /// sweep's own tests use stand-in files, not SQLite).
    #[cfg(test)]
    pub(crate) fn fake_copy(&mut self) -> std::io::Result<()> {
        match self.read_db(
            |p| {
                let mut opened = Vec::new();
                for sfx in ["", "-wal", "-shm"] {
                    let mut n = p.as_os_str().to_owned();
                    n.push(sfx);
                    if let Ok(f) = std::fs::File::open(&n) {
                        opened.push(f);
                    }
                }
                (p.to_path_buf(), opened)
            },
            |_| (),
            |(db, _), out| std::fs::copy(db, out).is_ok(),
        )? {
            None => Ok(()),
            Some(((), confirmed)) => confirmed,
        }
    }

    /// Check every quarantined entry against what was inspected, again.
    ///
    /// # Errors
    /// A refusal on any difference.
    pub(crate) fn validate(&self) -> std::io::Result<()> {
        self.inner.validate(&self.anchors.inner)
    }

    /// Delete the quarantined entries (by their quarantine names only), refused with
    /// nothing deleted unless the database's recovery copy is complete (⟨§17.36 item 1⟩):
    /// the trees first, then the database family (its companions, the original
    /// database, the recovery copy, its quarantine directory). ⟨audit C1⟩ When a deletion
    /// fails part-way, every tree not yet started (and a failed single file) is renamed
    /// back, never over anything, the recovery copy is restored (or kept), and the error
    /// lists exactly the paths renamed back and the paths left in quarantine.
    ///
    /// # Errors
    /// An I/O failure, with the entries left in quarantine.
    /// ⟨W5-I01 (§17.38)⟩ `verify` opens the recovery copy (at the path) read-only on its
    /// own and reads it; the originals are deleted only after it passes.
    pub(crate) fn delete(self, verify: &dyn Fn(&Path) -> bool) -> Result<(), QuarantineError> {
        self.inner.delete(&self.anchors.inner, verify)
    }

    /// Rename every quarantined tree back, and ⟨§17.36 item 1⟩ restore the database as its
    /// recovery copy **alone** (one no-replace rename, when none of the family's names is
    /// occupied); the original family stays in its quarantine directory, for a later
    /// `heimdall uninstall` to delete once the restored database is confirmed. Returns
    /// the paths renamed back and the paths left (each existing).
    pub(crate) fn restore(self) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
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

/// ⟨ADR-0008 §17.36 item 1⟩ The database's complete recovery copy in its quarantine
/// directory (`VACUUM INTO` output: self-contained, no log).
pub(crate) const UNIT_COPY: &str = "heimdall-recovery-copy.db";

/// The recovery copy while it is written.
const UNIT_COPY_PART: &str = "heimdall-recovery-copy.db.part";

/// ⟨audit E2⟩ The incomplete copy and every companion SQLite can create beside it while
/// `VACUUM INTO` writes it (exact names; always the purge's own files in its own unit).
const UNIT_COPY_PART_FILES: [&str; 4] = [
    "heimdall-recovery-copy.db.part",
    "heimdall-recovery-copy.db.part-journal",
    "heimdall-recovery-copy.db.part-wal",
    "heimdall-recovery-copy.db.part-shm",
];

/// ⟨audit E1⟩ The mark, in a database family's quarantine directory, that its recovery
/// copy is confirmed and the deletion of the original family has begun.
const UNIT_DELETING: &str = "heimdall-purge-deleting";

/// ⟨§17.36 item 1⟩ What crash recovery needs from the store: `open` a read-only
/// connection, `copy` from it (`VACUUM INTO`), and `confirm` a restored database (first
/// path) against the original family's database (second path).
pub(crate) struct RecoverOps<'a> {
    /// A read-only connection on the database at the path.
    pub(crate) open: &'a dyn Fn(&Path) -> Box<dyn std::any::Any>,
    /// The recovery copy from that connection to the path; `true` when written.
    pub(crate) copy: &'a dyn Fn(&dyn std::any::Any, &Path) -> bool,
    /// The restored database opens and its snapshot equals the original family's.
    pub(crate) confirm: &'a dyn Fn(&Path, &Path) -> bool,
    /// ⟨W5-I01 (§17.38)⟩ The database at the path opens read-only on its own, passes the
    /// integrity and schema checks, and its recovery snapshot reads.
    pub(crate) check: &'a dyn Fn(&Path) -> bool,
}

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
    /// ⟨ADR-0008 §17.39 item 1⟩ A file now at the state database's name that does not
    /// pass its check against the deletion mark's binding (a recovery copy restored, or
    /// found restored, that failed its verification): the original family is kept.
    pub(crate) unverified: Vec<std::path::PathBuf>,
}

/// ⟨M08 U2b-1; ADR-0014 §3.6⟩ The directory of the store's family: the generation the
/// pointer names (`Some`), or `<state>` itself in the flat layout (`None`). It reads the
/// pointer alone: while an interrupted purge holds the family in quarantine, the
/// generation's record lists a file that is not there, and recovery must still put the
/// family back where it was. A damaged pointer refuses: the purge never guesses where the
/// store is. The store itself is checked by the purge's final read.
fn family_dir(state_dir: &Path) -> std::io::Result<Option<std::path::PathBuf>> {
    heimdall_store::layout::pointed_generation(state_dir)
        .map_err(|_| refused("the state directory's pointer is damaged (state_corrupt)"))
}

/// ⟨§17.35 item 7⟩ Whether `<state>` or `<run>` shows a `.hm-purge-*` entry, or a
/// database log without its database (a hint by path; the recovery itself is anchored).
/// ⟨M08 U2b-1⟩ The family checked is the flat one and, when the pointer names one, the
/// generation's.
pub(crate) fn leftovers_present(state_dir: &Path, runtime_dir: &Path, db_file: &str) -> bool {
    let marked = |d: &Path| {
        std::fs::read_dir(d).is_ok_and(|es| {
            es.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(".hm-purge-"))
        })
    };
    let orphan_in = |dir: &Path| {
        std::fs::symlink_metadata(dir.join(db_file)).is_err()
            && ["-wal", "-shm", "-journal"]
                .iter()
                .any(|sfx| std::fs::symlink_metadata(dir.join(format!("{db_file}{sfx}"))).is_ok())
    };
    let generation = heimdall_store::layout::pointed_db(state_dir)
        .and_then(|db| db.parent().map(Path::to_path_buf));
    marked(state_dir)
        || marked(runtime_dir)
        || orphan_in(state_dir)
        || generation.as_deref().is_some_and(orphan_in)
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
    /// ⟨ADR-0008 §17.34 item 2; §17.36's Linux test fix⟩ This user's private group, as
    /// the host reports it (`heimdall_runtime::platform::user_private_group`); tests
    /// inject another oracle ([`Anchors::open_with_group`]).
    pub(super) type GroupOracle<'a> = &'a dyn Fn() -> std::io::Result<Option<u32>>;

    fn open_chain(
        target: &Path,
        top: Option<&Path>,
        group: GroupOracle<'_>,
    ) -> std::io::Result<Option<Root>> {
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
            match group() {
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
        /// ⟨M08 U2b-1⟩ The directory of the store's family: the generation `CURRENT` names,
        /// anchored like the roots; `None` in the flat layout, where it is `<state>`.
        family: Option<Root>,
    }

    /// The held lock file.
    pub(super) struct Lock {
        _file: std::fs::File,
    }

    impl Anchors {
        pub(super) fn open(
            state_dir: &Path,
            runtime_dir: &Path,
            family_dir: Option<&Path>,
            top: Option<&Path>,
        ) -> std::io::Result<Anchors> {
            Self::open_with_group(
                state_dir,
                runtime_dir,
                family_dir,
                top,
                &heimdall_runtime::platform::user_private_group,
            )
        }

        pub(super) fn open_with_group(
            state_dir: &Path,
            runtime_dir: &Path,
            family_dir: Option<&Path>,
            top: Option<&Path>,
            group: GroupOracle<'_>,
        ) -> std::io::Result<Anchors> {
            let Some(state) = open_chain(state_dir, top, group)? else {
                return Err(refused("the state directory does not exist"));
            };
            let family = match family_dir {
                Some(dir) => Some(open_chain(dir, top, group)?.ok_or_else(|| {
                    refused("the store generation the pointer names does not exist")
                })?),
                None => None,
            };
            Ok(Anchors {
                state,
                run: open_chain(runtime_dir, top, group)?,
                family,
            })
        }

        /// ⟨M08 U2b-1⟩ The directory holding the store's family.
        fn fam(&self) -> &Root {
            self.family.as_ref().unwrap_or(&self.state)
        }

        /// ⟨M08 U2b-1; ADR-0014 §3.6⟩ After the store's family and its recovery copy are
        /// deleted, the generation layout's entries in `<state>` (`super::LAYOUT_ENTRIES`,
        /// the pointer last), each removed relative to the anchored `<state>` without
        /// following a link. Nothing in the flat layout.
        pub(super) fn remove_layout(&mut self) -> Result<(), super::QuarantineError> {
            if self.family.take().is_none() {
                return Ok(());
            }
            for name in super::LAYOUT_ENTRIES {
                if let Err(cause) = remove_tree(&self.state.fd, OsStr::new(name)) {
                    let stuck = super::LAYOUT_ENTRIES
                        .iter()
                        .map(OsStr::new)
                        .filter(|n| !matches!(kind(&self.state.fd, n), Ok(None)))
                        .map(|n| self.state.path.join(n))
                        .collect();
                    return Err(super::QuarantineError {
                        cause,
                        stuck,
                        restored: Vec::new(),
                    });
                }
            }
            let _ = rustix::fs::fsync(&self.state.fd);
            Ok(())
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
            for r in std::iter::once(&self.state)
                .chain(self.run.as_ref())
                .chain(self.family.as_ref())
            {
                let now = rustix::fs::stat(r.path.as_path())?;
                if id(&now) != r.id {
                    return Err(refused("a purge root was replaced"));
                }
            }
            let under = kind(&self.fam().fd, OsStr::new(db_file))?;
            let by_path = match rustix::fs::lstat(self.fam().path.join(db_file).as_path()) {
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
            match which {
                0 => Some(&self.state),
                1 => self.run.as_ref(),
                _ => Some(self.fam()),
            }
        }

        /// Every entry the purge removes: (root, name, whether it is a database file).
        fn targets(&self, db_file: &str) -> Vec<(usize, OsString, bool)> {
            let mut out = Vec::new();
            if self.run.is_some() {
                out.extend(RUN_TREES.iter().map(|t| (1, OsString::from(t), false)));
            }
            out.extend(STATE_TREES.iter().map(|t| (0, OsString::from(t), false)));
            // ⟨M08 U2b-1⟩ The family, in its own directory (root 2: `<state>` when flat).
            out.extend(
                DB_SUFFIXES
                    .iter()
                    .map(|sfx| (2, OsString::from(format!("{db_file}{sfx}")), true)),
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
            // ⟨§17.36 item 1⟩ A rollback journal: refused and kept, before anything moves.
            if family
                .iter()
                .any(|(n, _)| n.as_bytes().ends_with(b"-journal"))
            {
                return Err(err(super::journal_refused()));
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
        _fd: OwnedFd,
        id: (u64, u64),
        /// Created empty by the purge (absent at the inspection): never restored.
        created: bool,
    }

    /// ⟨ADR-0008 §17.35 item 1, §17.36 item 1⟩ The database family (the database, `-wal`,
    /// `-shm`) as one unit: moved together, keeping their names, into one fresh
    /// owner-only quarantine directory created exclusively in `<state>`, held by
    /// descriptor; with, once the final read is confirmed, the **recovery copy**
    /// ([`COPY`]) written from it by `VACUUM INTO`.
    struct Unit {
        dir: OwnedFd,
        id: (u64, u64),
        /// Its name in `<state>`.
        name: OsString,
        /// The ones moved into it (every family file inspected is in its record).
        members: Vec<(OsString, Manifest)>,
        held: Vec<Held>,
        /// The complete recovery copy's identity.
        copy: Option<(u64, u64)>,
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

    /// The family's names, the database first (then `-wal`, `-shm`, `-journal`).
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

    /// The unit's record of its members (each family file's name and inspected identity).
    const RECORD: &str = super::UNIT_RECORD;
    /// ⟨§17.36 item 1⟩ The complete recovery copy in the unit.
    const COPY: &str = super::UNIT_COPY;
    /// The recovery copy while it is written (renamed to [`COPY`] once complete and
    /// synced, so a crash never leaves an incomplete copy under [`COPY`]).
    const COPY_PART: &str = super::UNIT_COPY_PART;
    /// ⟨audit E1⟩ The mark that the copy is confirmed and the originals' deletion began.
    const DELETING: &str = super::UNIT_DELETING;

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

    /// The unit directory `here` and each entry in it, as they are now (sorted).
    fn left_now(dir: &OwnedFd, here: &Path) -> Vec<PathBuf> {
        let mut left = vec![here.to_path_buf()];
        if let Ok(mut ns) = list(dir) {
            ns.sort();
            left.extend(ns.iter().map(|n| here.join(n)));
        }
        left
    }

    /// ⟨ADR-0008 §17.36 item 1⟩ Restore the unit's complete recovery copy (`copy`, its
    /// identity) **alone** as `<state>/<db_file>`, by one no-replace rename, when none of
    /// the family's names in `<state>` is occupied: one atomic step, with no log to
    /// attach. The original family stays in the unit. (Paths renamed back, paths left.)
    /// ⟨M08 U2b-1⟩ `units` holds the unit (`<state>`); `state` is where the family lives
    /// (`<state>`, or the generation `CURRENT` names).
    fn restore_copy(
        units: &Root,
        state: &Root,
        dir: &OwnedFd,
        name: &OsStr,
        db_file: &OsStr,
        copy: Option<(u64, u64)>,
    ) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let here = units.path.join(name);
        let kept = |restored: Vec<PathBuf>| (restored, left_now(dir, &here));
        if super::restore_fails() {
            return kept(Vec::new());
        }
        let Some(cid) = copy else {
            return kept(Vec::new());
        };
        match kind(dir, OsStr::new(COPY)) {
            Ok(Some((FileType::RegularFile, d, i))) if (d, i) == cid => {}
            _ => return kept(Vec::new()),
        }
        if family(db_file)
            .iter()
            .any(|n| !matches!(kind(&state.fd, n), Ok(None)))
        {
            return kept(Vec::new());
        }
        #[cfg(test)]
        super::tests::step_hook("restore");
        if rename_between(dir, OsStr::new(COPY), &state.fd, db_file).is_err() {
            return kept(Vec::new());
        }
        let _ = rustix::fs::fsync(&state.fd);
        kept(vec![state.path.join(db_file)])
    }

    impl Unit {
        fn restore(&self, a: &Anchors, db_file: &OsStr) -> (Vec<PathBuf>, Vec<PathBuf>) {
            restore_copy(&a.state, a.fam(), &self.dir, &self.name, db_file, self.copy)
        }

        /// ⟨§17.36 item 1⟩ Delete the unit: the original family's companions first, then
        /// the original database, then the recovery copy, then the record and the
        /// directory. A failure before the copy is deleted restores the copy (or keeps
        /// it), reported with its exact path; after it, what is left is reported.
        fn delete(
            &self,
            a: &Anchors,
            db_file: &OsStr,
            verify: &dyn Fn(&Path) -> bool,
        ) -> Result<(), super::QuarantineError> {
            let names = family(db_file);
            let here = a.state.path.join(&self.name);
            let fail = |cause: std::io::Error| {
                let (restored, stuck) = self.restore(a, db_file);
                super::QuarantineError {
                    cause,
                    stuck,
                    restored,
                }
            };
            let keep = |cause: std::io::Error| super::QuarantineError {
                cause,
                stuck: left_now(&self.dir, &here),
                restored: Vec::new(),
            };
            // ⟨audit E1; W5-I01 (§17.38)⟩ Before the first original is unlinked: the copy
            // at its name is the one written (its identity), opens read-only on its own and
            // reads (`verify`); then the durable mark binding that copy (identity, size,
            // SHA-256) that the originals' deletion has begun. A copy that fails keeps the
            // whole unit, nothing unlinked.
            let binding = match copy_binding(&self.dir, OsStr::new(COPY)) {
                Ok(b) if Some(b.id) == self.copy => b,
                Ok(_) => return Err(keep(refused("the recovery copy was replaced"))),
                Err(e) => return Err(keep(e)),
            };
            let verified = current_path(&self.dir).is_ok_and(|d| verify(&d.join(COPY)));
            if !verified || copy_binding(&self.dir, OsStr::new(COPY)).ok() != Some(binding.clone())
            {
                return Err(keep(refused(
                    "the recovery copy does not open and read on its own",
                )));
            }
            if let Err(e) = write_marker(&self.dir, &binding) {
                return Err(fail(e));
            }
            let mut first = true;
            for n in names.iter().skip(1).chain(names.first()) {
                if matches!(kind(&self.dir, n), Ok(None)) {
                    continue;
                }
                #[cfg(test)]
                super::tests::unlink_hook(n);
                // ⟨ADR-0008 §17.39 item 2⟩ Immediately before the first original is
                // unlinked, the copy is read again by its name through a fresh descriptor
                // and must still be the bound one (identity, size, SHA-256). Otherwise
                // nothing of the family is unlinked, nothing is restored, and the unit
                // (with its mark) is kept: recovery then refuses on the mismatch too.
                // What remains after this re-check is the residual
                // `purge_recovery_copy_overwritten_between_check_and_unlink`.
                if std::mem::take(&mut first)
                    && copy_binding(&self.dir, OsStr::new(COPY)).ok().as_ref() != Some(&binding)
                {
                    return Err(keep(refused(
                        "the recovery copy changed after its check; nothing was deleted",
                    )));
                }
                if super::unlink_fails(n) {
                    return Err(fail(std::io::Error::other("injected unlink failure")));
                }
                if let Err(e) = rustix::fs::unlinkat(&self.dir, n, AtFlags::empty()) {
                    return Err(fail(e.into()));
                }
            }
            // The originals are gone: the mark goes first (and synced), so a mark always
            // has its copy beside it (or restored); then the copy, the record, the
            // directory.
            match rustix::fs::unlinkat(&self.dir, DELETING, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(fail(e.into())),
            }
            let _ = rustix::fs::fsync(&self.dir);
            #[cfg(test)]
            super::tests::step_hook("delete-copy");
            let left = |cause: std::io::Error| super::QuarantineError {
                cause,
                stuck: left_now(&self.dir, &here),
                restored: Vec::new(),
            };
            if super::unlink_fails(OsStr::new(COPY)) {
                return Err(fail(std::io::Error::other("injected unlink failure")));
            }
            match rustix::fs::unlinkat(&self.dir, COPY, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(fail(e.into())),
            }
            match rustix::fs::unlinkat(&self.dir, RECORD, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(left(e.into())),
            }
            remove_unit_dir(&a.state, &self.name, self.id).map_err(left)
        }
    }

    /// ⟨W5-I01 (§17.38)⟩ What the deletion mark binds: the recovery copy's identity, size
    /// and SHA-256.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Binding {
        id: (u64, u64),
        size: u64,
        sha256: String,
    }

    impl Binding {
        fn text(&self) -> String {
            format!(
                "copy\t{}\t{}\t{}\t{}\n",
                self.id.0, self.id.1, self.size, self.sha256
            )
        }

        fn parse(text: &str) -> Option<Binding> {
            let mut f = text.strip_suffix('\n')?.split('\t');
            let (tag, d, i, size, sha) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            (tag == "copy" && f.next().is_none() && sha.len() == 64).then_some(())?;
            Some(Binding {
                id: (d.parse().ok()?, i.parse().ok()?),
                size: size.parse().ok()?,
                sha256: sha.to_owned(),
            })
        }
    }

    /// The binding of the regular file `name` in `dir`, read through one descriptor
    /// (opened without following a link).
    fn copy_binding(dir: &OwnedFd, name: &OsStr) -> std::io::Result<Binding> {
        use std::io::Read as _;
        let fd = rustix::fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let st = rustix::fs::fstat(&fd)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(refused("the recovery copy is not a regular file"));
        }
        let mut bytes = Vec::new();
        std::fs::File::from(fd).read_to_end(&mut bytes)?;
        Ok(Binding {
            id: id(&st),
            size: bytes.len() as u64,
            sha256: heimdall_issuer::backup::sha256_hex(&bytes),
        })
    }

    /// ⟨audit E1; W5-I01⟩ The mark that the originals' deletion has begun ([`DELETING`]),
    /// binding the copy, created exclusively, written and synced, the directory synced.
    fn write_marker(dir: &OwnedFd, binding: &Binding) -> std::io::Result<()> {
        use std::io::Write as _;
        let fd = rustix::fs::openat(
            dir,
            DELETING,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let mut f = std::fs::File::from(fd);
        f.write_all(binding.text().as_bytes())?;
        f.sync_all()?;
        rustix::fs::fsync(dir)?;
        Ok(())
    }

    /// ⟨tests⟩ The deletion mark's text binding the file at `path`.
    #[cfg(test)]
    pub(super) fn marker_text_for(path: &Path) -> std::io::Result<String> {
        let parent = path.parent().unwrap_or(path);
        let dir = rustix::fs::open(parent, dir_flags(), Mode::empty())?;
        let name = path.file_name().unwrap_or_default();
        Ok(copy_binding(&dir, name)?.text())
    }

    fn read_marker(dir: &OwnedFd) -> Option<Binding> {
        use std::io::Read as _;
        let fd = rustix::fs::openat(
            dir,
            DELETING,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        let mut text = String::new();
        std::fs::File::from(fd).read_to_string(&mut text).ok()?;
        Binding::parse(&text)
    }

    impl Quarantine {
        /// Rename everything back (the database as its recovery copy, if any), then the
        /// refusal (with any entry left behind).
        fn refuse(self, a: &Anchors, cause: std::io::Error) -> super::QuarantineError {
            let (restored, stuck) = self.restore(a);
            super::QuarantineError {
                cause,
                stuck,
                restored,
            }
        }

        /// ⟨§17.35 item 1⟩ Create the quarantine directory exclusively (`mkdirat`, then
        /// opened relative to `<state>`: this user's, owner-only), write its record, and
        /// move the family into it, each file keeping its name, never over anything.
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
            let (dir, id) = open_unit(&a.state.fd, &name)?;
            let unit = self.unit.insert(Unit {
                dir,
                id,
                name,
                members: Vec::new(),
                held: Vec::new(),
                copy: None,
            });
            // ⟨§17.35 item 7⟩ The record first, synced: a crash after any move below
            // leaves the unit recoverable.
            write_record(&unit.dir, &a.state.fd, &family)?;
            for (n, m) in family {
                #[cfg(test)]
                super::tests::move_hook(&n);
                rename_between(&a.fam().fd, &n, &unit.dir, &n)?;
                unit.members.push((n, m));
            }
            Ok(())
        }

        /// ⟨audit C0; §17.36 item 1⟩ Hold the quarantined database, `-wal` and `-shm` by
        /// descriptor in the quarantine directory: a moved one opened there and required
        /// to be the inspected inode; an absent one created empty there (`O_CREAT |
        /// O_EXCL`). A `-journal` there refuses (the store is WAL-mode: a hot rollback
        /// journal is never legitimate).
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
                    if kind(&unit.dir, &name)?.is_some() {
                        return Err(super::journal_refused());
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
                        || (n == COPY && u.copy.is_some())
                        || u.members.iter().any(|(k, _)| *k == n)
                        || u.held.iter().any(|h| h.created && h.name == n);
                    if !ours {
                        return Err(refused("an entry appeared in the quarantine directory"));
                    }
                }
                if let Some(cid) = u.copy {
                    match kind(&u.dir, OsStr::new(COPY))? {
                        Some((FileType::RegularFile, d, i)) if (d, i) == cid => {}
                        _ => return Err(refused("the recovery copy was replaced")),
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

        /// ⟨audit C0; ADR-0008 §17.36 item 1⟩ The final read, on a **read-only**
        /// connection, and the recovery copy from it. Immediately before the open: no
        /// `-journal` in the unit (a read-only connection never rolls one back, but a
        /// journal is refused before anything opens). `open` the quarantined database by
        /// its name in the quarantine directory (resolved from the held handle), `read`
        /// it, and, before the store is dropped, take a census of this process's
        /// regular-file descriptors (each held file named by exactly one more descriptor
        /// than before, and its name still naming it). Only on a confirmed connection,
        /// `copy` writes the recovery copy (`VACUUM INTO`) to [`COPY_PART`], created
        /// exclusively first; it is then checked (the same inode, not empty), synced, and
        /// renamed to [`COPY`] (no-replace), and the directory synced.
        pub(super) fn read_db<S, T>(
            &mut self,
            _a: &Anchors,
            open: impl FnOnce(&Path) -> S,
            read: impl FnOnce(&S) -> T,
            copy: impl FnOnce(&S, &Path) -> bool,
        ) -> std::io::Result<Option<(T, std::io::Result<()>)>> {
            let db_file = self.db_file.clone();
            let Some(u) = &self.unit else {
                return Ok(None);
            };
            if u.held.is_empty() {
                return Ok(None);
            }
            if kind(&u.dir, &family(&db_file)[3])?.is_some() {
                return Err(super::journal_refused());
            }
            let part = rustix::fs::openat(
                &u.dir,
                COPY_PART,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|e| match e {
                rustix::io::Errno::EXIST => refused("a file appeared in the quarantine directory"),
                e => e.into(),
            })?;
            let part_id = id(&rustix::fs::fstat(&part)?);
            let before = heimdall_runtime::platform::regular_file_descriptors()?;
            let here = current_path(&u.dir)?;
            let store = open(&here.join(&db_file));
            let out = read(&store);
            let mut confirmed = self.census(&before);
            if confirmed.is_ok() {
                // Where the quarantine directory is now (resolved from its handle again).
                let written =
                    current_path(&u.dir).is_ok_and(|now| copy(&store, &now.join(COPY_PART)));
                if !written {
                    confirmed = Err(refused("the recovery copy could not be written"));
                }
            }
            drop(store);
            let confirmed = confirmed.and_then(|()| {
                #[cfg(test)]
                super::tests::step_hook("copy-written");
                match kind(&u.dir, OsStr::new(COPY_PART))? {
                    Some((FileType::RegularFile, d, i)) if (d, i) == part_id => {}
                    _ => return Err(refused("the recovery copy was replaced")),
                }
                if rustix::fs::fstat(&part)?.st_size == 0 {
                    return Err(refused("the recovery copy is empty"));
                }
                rustix::fs::fsync(&part)?;
                rename_no_replace(&u.dir, OsStr::new(COPY_PART), OsStr::new(COPY))?;
                rustix::fs::fsync(&u.dir)?;
                Ok(())
            });
            match &confirmed {
                Ok(()) => {
                    if let Some(u) = self.unit.as_mut() {
                        u.copy = Some(part_id);
                    }
                }
                Err(_) => {
                    if let Ok(Some((FileType::RegularFile, d, i))) =
                        kind(&u.dir, OsStr::new(COPY_PART))
                        && (d, i) == part_id
                    {
                        let _ = rustix::fs::unlinkat(&u.dir, COPY_PART, AtFlags::empty());
                    }
                }
            }
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

        /// ⟨audit C1; §17.36 item 1⟩ Delete: refused, nothing deleted, unless the unit
        /// holds its complete recovery copy (when it holds a database); then the trees,
        /// then the unit (its companions, the original database, the copy, the
        /// directory). When a tree's deletion fails, every tree not yet started (and a
        /// failed single file) is renamed back and the recovery copy restored; every path
        /// renamed back and every path left in quarantine is reported.
        pub(super) fn delete(
            self,
            a: &Anchors,
            verify: &dyn Fn(&Path) -> bool,
        ) -> Result<(), super::QuarantineError> {
            if let Some(u) = &self.unit
                && u.copy.is_none()
                && u.members.iter().any(|(n, _)| *n == self.db_file)
            {
                return Err(self.refuse(a, refused("the recovery copy was not written")));
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
                Some(u) => u.delete(a, &self.db_file, verify),
                None => Ok(()),
            }
        }

        /// Rename every tree back; restore the database as its recovery copy alone
        /// (§17.36 item 1), the original family kept in its quarantine directory. (Paths
        /// renamed back; paths left: the unit directory and what is in it.)
        pub(super) fn restore(self, a: &Anchors) -> (Vec<PathBuf>, Vec<PathBuf>) {
            let (mut restored, mut left) = (Vec::new(), Vec::new());
            for m in self.moved.iter().rev() {
                let Some(root) = a.root(m.which) else {
                    continue;
                };
                // Never over an entry at the original name: it stays in quarantine,
                // reported.
                if super::restore_fails() || rename_no_replace(&root.fd, &m.qname, &m.name).is_err()
                {
                    left.push(root.path.join(&m.qname));
                } else {
                    restored.push(root.path.join(&m.name));
                }
            }
            if let Some(u) = &self.unit {
                let (r, l) = u.restore(a, &self.db_file);
                restored.extend(r);
                left.extend(l);
            }
            (restored, left)
        }
    }

    impl Anchors {
        /// ⟨ADR-0008 §17.35 item 7, §17.36 item 1⟩ An interrupted uninstall's quarantine,
        /// under the lock. For each database family unit in `<state>`: an incomplete copy
        /// is removed; a family file a crash left at its name (still the recorded inode)
        /// is moved into the unit; then the database is restored as the unit's recovery
        /// copy alone (written first by `make_copy` on a read-only, census-confirmed
        /// connection when there is none), and once `confirm` finds the restored database
        /// equal to the original family, the original family is deleted. Each quarantined
        /// tree is renamed back when its name is free. Anything else is reported as left.
        pub(super) fn recover(
            &self,
            db_file: &str,
            ops: &super::RecoverOps<'_>,
        ) -> super::Recovered {
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
                                let (r, l, u) = self.recover_unit(fd, id, &n, db, ops);
                                out.restored.extend(r);
                                out.left.extend(l);
                                out.unverified.extend(u);
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
            let fam = self.fam();
            if matches!(kind(&fam.fd, db), Ok(None)) {
                for n in family(db).iter().skip(1) {
                    if !matches!(kind(&fam.fd, n), Ok(None)) {
                        out.left.push(fam.path.join(n));
                    }
                }
            }
            out
        }

        fn recover_unit(
            &self,
            dir: OwnedFd,
            id: (u64, u64),
            name: &OsStr,
            db: &OsStr,
            ops: &super::RecoverOps<'_>,
        ) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>) {
            // ⟨M08 U2b-1⟩ The unit is in `<state>`; the family goes back to its own directory.
            let units = &self.state;
            let state = self.fam();
            let here = units.path.join(name);
            let all_left = |dir: &OwnedFd| (Vec::new(), left_now(dir, &here), Vec::new());
            let names = family(db);
            // An incomplete copy is never used.
            // ⟨audit E2⟩ An incomplete copy is never used: it and the companions SQLite
            // makes while writing it (exact names in the purge's own unit) are removed.
            for part in super::UNIT_COPY_PART_FILES {
                let _ = rustix::fs::unlinkat(&dir, part, AtFlags::empty());
            }
            let Ok(entries) = list(&dir) else {
                return all_left(&dir);
            };
            if entries
                .iter()
                .any(|e| e != RECORD && e != COPY && e != DELETING && !names.contains(e))
            {
                return all_left(&dir);
            }
            let record = if entries.iter().any(|e| e == RECORD) {
                match read_record(&dir) {
                    Ok(r) => r,
                    Err(_) => return all_left(&dir),
                }
            } else if entries.is_empty() {
                Vec::new()
            } else {
                return all_left(&dir);
            };
            let recorded = |n: &OsStr| record.iter().find(|(k, _)| k == n).map(|e| e.1);
            // A journal is never used (§17.36 item 1): the unit stays, reported.
            if !matches!(kind(&dir, &names[3]), Ok(None)) {
                return all_left(&dir);
            }
            // ⟨audit E1⟩ The originals' deletion had begun (the copy was confirmed):
            // finish it, never comparing the copy with what is left of them; then the
            // copy is restored when no database is live.
            if entries.iter().any(|e| e == DELETING) {
                // ⟨W5-I01 (§17.38)⟩ Never on the mark alone. Before anything moves: the
                // copy (in the unit, or already restored as `state.db`) is the one the mark
                // binds (identity, size, SHA-256), opens read-only on its own and reads
                // (`ops.check`); every original still present is the inode the record
                // lists (or an empty file the purge created). Otherwise nothing is
                // unlinked and the unit is kept.
                let Some(bound) = read_marker(&dir) else {
                    return all_left(&dir);
                };
                let live_path = state.path.join(db);
                let bound_at = |d: &OwnedFd, n: &OsStr, p: &Path| {
                    copy_binding(d, n).ok().as_ref() == Some(&bound)
                        && (ops.check)(p)
                        && copy_binding(d, n).ok().as_ref() == Some(&bound)
                };
                let in_unit = !matches!(kind(&dir, OsStr::new(COPY)), Ok(None));
                let checked = if in_unit {
                    bound_at(&dir, OsStr::new(COPY), &here.join(COPY))
                } else {
                    bound_at(&state.fd, db, &live_path)
                };
                if !checked {
                    let (r, l, _) = all_left(&dir);
                    let found = !in_unit && !matches!(kind(&state.fd, db), Ok(None));
                    return (r, l, found.then(|| live_path.clone()).into_iter().collect());
                }
                for n in &names {
                    match kind(&dir, n) {
                        Ok(None) => {}
                        Ok(Some((FileType::RegularFile, d, i))) if recorded(n) == Some((d, i)) => {}
                        Ok(Some((FileType::RegularFile, ..)))
                            if recorded(n).is_none()
                                && n != &names[0]
                                && rustix::fs::statat(&dir, n, AtFlags::SYMLINK_NOFOLLOW)
                                    .is_ok_and(|st| st.st_size == 0) => {}
                        _ => return all_left(&dir),
                    }
                }
                #[cfg(test)]
                super::tests::step_hook("recover-checked");
                // ⟨ADR-0008 §17.39 item 1⟩ Restore first: the copy becomes `state.db` by
                // one no-replace rename (a live database keeps the unit).
                let mut restored = Vec::new();
                if in_unit {
                    if !matches!(kind(&state.fd, db), Ok(None)) {
                        return all_left(&dir);
                    }
                    let (r, _) = restore_copy(units, state, &dir, name, db, Some(bound.id));
                    if r.is_empty() {
                        return all_left(&dir);
                    }
                    restored = r;
                }
                // Then verify what is now at the live name, from a fresh read: the mark's
                // binding (identity, size, SHA-256), a read-only open with the integrity
                // and schema checks and a snapshot that reads, and the binding again.
                // Only a verified database there lets an original be unlinked; otherwise
                // every original stays in the unit and the file at `state.db` is
                // reported as unverified.
                if in_unit && !bound_at(&state.fd, db, &live_path) {
                    let (_, l, _) = all_left(&dir);
                    return (Vec::new(), l, vec![live_path]);
                }
                for n in names.iter().skip(1).chain(names.first()) {
                    if !matches!(kind(&dir, n), Ok(None))
                        && rustix::fs::unlinkat(&dir, n, AtFlags::empty()).is_err()
                    {
                        let (_, l, _) = all_left(&dir);
                        return (restored, l, Vec::new());
                    }
                }
                for n in [DELETING, RECORD] {
                    let _ = rustix::fs::unlinkat(&dir, n, AtFlags::empty());
                }
                let left = if remove_unit_dir(units, name, id).is_ok() {
                    Vec::new()
                } else {
                    left_now(&dir, &here)
                };
                return (restored, left, Vec::new());
            }
            // The members a crash left at their names (still the recorded inode) join the
            // unit first, so the copy is made from the whole family.
            for n in &names {
                if let (Ok(None), Ok(Some((_, d, i)))) = (kind(&dir, n), kind(&state.fd, n))
                    && recorded(n) == Some((d, i))
                    && rename_between(&state.fd, n, &dir, n).is_err()
                {
                    return all_left(&dir);
                }
            }
            // The purge's own files (an index, an empty log, never recorded) are removed:
            // the copy is made from the recorded family alone.
            for n in names.iter().skip(1) {
                if recorded(n).is_none()
                    && let Ok(st) = rustix::fs::statat(&dir, n, AtFlags::SYMLINK_NOFOLLOW)
                    && (n.as_bytes().ends_with(b"-shm") || st.st_size == 0)
                {
                    let _ = rustix::fs::unlinkat(&dir, n, AtFlags::empty());
                }
            }
            let has = |n: &str| !matches!(kind(&dir, OsStr::new(n)), Ok(None));
            let db_in_unit = has(&db.to_string_lossy());
            let live = !matches!(kind(&state.fd, db), Ok(None));
            let mut restored = Vec::new();
            if !live {
                if !has(COPY) {
                    if !db_in_unit {
                        // Nothing to restore: the purge had deleted the database.
                        let _ = rustix::fs::unlinkat(&dir, RECORD, AtFlags::empty());
                        let left = if remove_unit_dir(units, name, id).is_ok() {
                            Vec::new()
                        } else {
                            left_now(&dir, &here)
                        };
                        return (Vec::new(), left, Vec::new());
                    }
                    if self.copy_in_unit(&dir, id, name, db, &record, ops).is_err() {
                        return all_left(&dir);
                    }
                }
                let copy = match kind(&dir, OsStr::new(COPY)) {
                    Ok(Some((FileType::RegularFile, d, i))) => Some((d, i)),
                    _ => None,
                };
                let (r, _) = restore_copy(units, state, &dir, name, db, copy);
                if r.is_empty() {
                    return all_left(&dir);
                }
                restored = r;
            } else if has(COPY) {
                return all_left(&dir);
            }
            // The restored database confirmed against the original family, then the
            // original family deleted.
            let live_path = state.path.join(db);
            if db_in_unit {
                let original = here.join(db);
                if !(ops.confirm)(&live_path, &original) {
                    return (restored, left_now(&dir, &here), Vec::new());
                }
                for n in names.iter().skip(1).chain(names.first()) {
                    if !matches!(kind(&dir, n), Ok(None))
                        && rustix::fs::unlinkat(&dir, n, AtFlags::empty()).is_err()
                    {
                        return (restored, left_now(&dir, &here), Vec::new());
                    }
                }
            }
            let _ = rustix::fs::unlinkat(&dir, RECORD, AtFlags::empty());
            let left = if remove_unit_dir(units, name, id).is_ok() {
                Vec::new()
            } else {
                left_now(&dir, &here)
            };
            (restored, left, Vec::new())
        }

        /// Write the unit's recovery copy from its original family, through the purge's
        /// own machinery: the family held (each member the recorded inode), a read-only
        /// connection confirmed by the census, `VACUUM INTO`.
        fn copy_in_unit(
            &self,
            dir: &OwnedFd,
            id: (u64, u64),
            name: &OsStr,
            db: &OsStr,
            record: &[(OsString, (u64, u64))],
            ops: &super::RecoverOps<'_>,
        ) -> std::io::Result<()> {
            let unit_dir = rustix::io::dup(dir)?;
            let members = record
                .iter()
                .filter(|(n, rid)| {
                    matches!(kind(dir, n), Ok(Some((FileType::RegularFile, d, i))) if (d, i) == *rid)
                })
                .map(|(n, rid)| (n.clone(), vec![(PathBuf::new(), 2u8, *rid)]))
                .collect();
            let mut q = Quarantine {
                moved: Vec::new(),
                absent: Vec::new(),
                unit: Some(Unit {
                    dir: unit_dir,
                    id,
                    name: name.to_owned(),
                    members,
                    held: Vec::new(),
                    copy: None,
                }),
                db_file: db.to_owned(),
                tag: String::new(),
            };
            q.hold()?;
            match q.read_db(
                self,
                |p| (ops.open)(p),
                |_| (),
                |s: &Box<dyn std::any::Any>, p| (ops.copy)(s.as_ref(), p),
            )? {
                Some(((), confirmed)) => confirmed,
                None => Err(refused("no database to copy")),
            }
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
    /// ⟨ADR-0008 §17.39 item 3⟩ `FILE_SHARE_READ | FILE_SHARE_DELETE`, without
    /// `FILE_SHARE_WRITE`: while the recovery copy is held, no other handle can open it
    /// for writing (and the hold itself fails while one is open).
    const SHARE_NO_WRITE: u32 = 0x1 | 0x4;
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

    /// ⟨ADR-0008 §17.39 item 3⟩ Hold the recovery copy at `path` open for reading, never
    /// following a reparse point, sharing read and delete but **not write**: while held,
    /// every other open of it for writing (or truncation) fails with a sharing
    /// violation, and the hold fails while such a handle is already open. Reads by path
    /// (the binding, SQLite's read-only open) still open it; its own rename goes through
    /// it ([`heimdall_ipc::windows::rename_held_no_replace`]). Returns the handle and its
    /// file ID; a reparse point or a directory refuses.
    fn hold_copy(path: &Path) -> std::io::Result<(std::fs::File, (u64, u64))> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_NO_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let attrs = f.metadata()?.file_attributes();
        if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(refused("the recovery copy is not a regular file"));
        }
        let id = heimdall_ipc::windows::file_id(&f)?;
        Ok((f, id))
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
        /// ⟨M08 U2b-1⟩ The directory of the store's family: the generation `CURRENT` names,
        /// pinned like the roots; `None` in the flat layout, where it is `<state>`.
        family: Option<PathBuf>,
        _held: Vec<std::fs::File>,
        /// The family directory's chain, pinned apart so that it can be released before
        /// the layout is removed ([`Anchors::remove_layout`]).
        family_held: Vec<std::fs::File>,
    }

    /// The held lock (the runtime's own lock type, by path below the pinned chain).
    pub(super) struct Lock {
        _lock: heimdall_runtime::InstanceLock,
    }

    impl Anchors {
        pub(super) fn open(
            state_dir: &Path,
            runtime_dir: &Path,
            family_dir: Option<&Path>,
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
            let (family, family_held) = match family_dir {
                Some(dir) => match pin_chain(dir)? {
                    Some(h) => (Some(dir.to_path_buf()), h),
                    None => {
                        return Err(refused(
                            "the store generation the pointer names does not exist",
                        ));
                    }
                },
                None => (None, Vec::new()),
            };
            Ok(Anchors {
                state: state_dir.to_path_buf(),
                run,
                family,
                _held: held,
                family_held,
            })
        }

        /// ⟨M08 U2b-1⟩ The directory holding the store's family.
        fn fam(&self) -> &PathBuf {
            self.family.as_ref().unwrap_or(&self.state)
        }

        /// ⟨M08 U2b-1; ADR-0014 §3.6⟩ As on Unix: after the store's family and its recovery
        /// copy are deleted, the generation layout's entries in `<state>`, the pointer
        /// last. The family directory's pins are released first (a pinned directory cannot
        /// be removed). A reparse point is never followed: it refuses, and is left.
        pub(super) fn remove_layout(&mut self) -> Result<(), super::QuarantineError> {
            if self.family.take().is_none() {
                return Ok(());
            }
            drop(std::mem::take(&mut self.family_held));
            for name in super::LAYOUT_ENTRIES {
                let path = self.state.join(name);
                let removed = match std::fs::symlink_metadata(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e),
                    Ok(m) if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                        Err(refused("a layout entry is a reparse point"))
                    }
                    // Never follows a link or junction inside: it removes the link itself.
                    Ok(m) if m.is_dir() => std::fs::remove_dir_all(&path),
                    Ok(_) => std::fs::remove_file(&path),
                };
                if let Err(cause) = removed {
                    let stuck = super::LAYOUT_ENTRIES
                        .iter()
                        .map(|n| self.state.join(n))
                        .filter(|p| std::fs::symlink_metadata(p).is_ok())
                        .collect();
                    return Err(super::QuarantineError {
                        cause,
                        stuck,
                        restored: Vec::new(),
                    });
                }
            }
            Ok(())
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
            match which {
                0 => Some(&self.state),
                1 => self.run.as_ref(),
                _ => Some(self.fam()),
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
            // ⟨M08 U2b-1⟩ The family, in its own directory (root 2: `<state>` when flat).
            targets.extend(
                DB_SUFFIXES
                    .iter()
                    .map(|x| (2, format!("{db_file}{x}"), true)),
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
            // ⟨§17.36 item 1⟩ A rollback journal: refused and kept, before anything moves.
            if family.iter().any(|(n, _)| n.ends_with("-journal")) {
                return Err(err(super::journal_refused()));
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

    /// ⟨ADR-0008 §17.35 item 1, §17.36 item 1⟩ The database family as one unit, in one
    /// fresh owner-only quarantine directory created exclusively in `<state>` and pinned;
    /// with its recovery copy once the final read is confirmed.
    struct Unit {
        path: PathBuf,
        pin: Option<std::fs::File>,
        id: (u64, u64),
        members: Vec<(String, Manifest)>,
        held: Vec<Held>,
        /// The complete recovery copy's file ID.
        copy: Option<(u64, u64)>,
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

    /// The names in `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut ns: Vec<String> = std::fs::read_dir(dir)
            .map(|es| {
                es.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        ns.sort();
        ns
    }

    /// The unit directory and each entry in it, as they are now.
    fn left_now(here: &Path) -> Vec<PathBuf> {
        let mut left = vec![here.to_path_buf()];
        left.extend(names_in(here).iter().map(|n| here.join(n)));
        left
    }

    /// ⟨ADR-0008 §17.36 item 1⟩ As on Unix: the recovery copy alone becomes
    /// `<state>/<db_file>` by one no-replace move, when none of the family's names is
    /// occupied; the original family stays.
    ///
    /// ⟨ADR-0008 §17.39 item 3⟩ With `held` (the copy held by [`hold_copy`]), the file
    /// renamed is the held one, through its handle, so a file put at the copy's name is
    /// never restored instead.
    fn restore_copy(
        state: &Path,
        here: &Path,
        db_file: &str,
        copy: Option<(u64, u64)>,
        held: Option<&std::fs::File>,
    ) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let kept = |restored: Vec<PathBuf>| (restored, left_now(here));
        if super::restore_fails() {
            return kept(Vec::new());
        }
        let Some(cid) = copy else {
            return kept(Vec::new());
        };
        let at = here.join(super::UNIT_COPY);
        let same = match held {
            Some(f) => heimdall_ipc::windows::file_id(f).is_ok_and(|now| now == cid),
            None => matches!(id_at(&at), Ok(Some(now)) if now == cid),
        };
        if !same {
            return kept(Vec::new());
        }
        if family(db_file)
            .iter()
            .any(|n| std::fs::symlink_metadata(state.join(n)).is_ok())
        {
            return kept(Vec::new());
        }
        #[cfg(test)]
        super::tests::step_hook("restore");
        let moved = match held {
            Some(f) => heimdall_ipc::windows::rename_held_no_replace(f, &state.join(db_file)),
            None => heimdall_ipc::windows::move_no_replace(&at, &state.join(db_file)),
        };
        if moved.is_err() {
            return kept(Vec::new());
        }
        kept(vec![state.join(db_file)])
    }

    impl Unit {
        /// ⟨audit D5⟩ Release the pins; the files the purge created are removed (never
        /// restored, never listed as renamed back).
        fn unpin(&mut self) {
            for h in std::mem::take(&mut self.held) {
                let Held {
                    name,
                    file,
                    id,
                    created,
                } = h;
                drop(file);
                if created {
                    let p = self.path.join(&name);
                    if matches!(id_at(&p), Ok(Some(now)) if now == id) {
                        let _ = std::fs::remove_file(&p);
                    }
                }
            }
            drop(self.pin.take());
        }

        fn restore(&mut self, a: &Anchors, db_file: &str) -> (Vec<PathBuf>, Vec<PathBuf>) {
            self.restore_held(a, db_file, None)
        }

        /// [`Unit::restore`], the copy renamed through `held` when it is held.
        fn restore_held(
            &mut self,
            a: &Anchors,
            db_file: &str,
            held: Option<&std::fs::File>,
        ) -> (Vec<PathBuf>, Vec<PathBuf>) {
            self.unpin();
            restore_copy(a.fam(), &self.path, db_file, self.copy, held)
        }

        /// ⟨§17.36 item 1⟩ The original family's companions, then the original database,
        /// then the recovery copy, then the record and the directory; a failure before the
        /// copy is deleted restores the copy (or keeps it), reported.
        fn delete(
            &mut self,
            a: &Anchors,
            db_file: &str,
            verify: &dyn Fn(&Path) -> bool,
        ) -> Result<(), super::QuarantineError> {
            let names = family(db_file);
            for h in std::mem::take(&mut self.held) {
                drop(h.file);
            }
            let fail = |u: &mut Unit, held: Option<&std::fs::File>, cause: std::io::Error| {
                let (restored, stuck) = u.restore_held(a, db_file, held);
                super::QuarantineError {
                    cause,
                    stuck,
                    restored,
                }
            };
            let keep = |u: &Unit, cause: std::io::Error| super::QuarantineError {
                cause,
                stuck: left_now(&u.path),
                restored: Vec::new(),
            };
            // ⟨audit E1; W5-I01 (§17.38)⟩ As on Unix: the copy checked (its identity, it
            // opens and reads on its own), then the mark binding it, before any original
            // is deleted. ⟨ADR-0008 §17.39 item 3⟩ From before that check through the last
            // original's deletion the copy is held with no write sharing, so no other
            // handle can write it in between (the reads below open it for reading).
            let copy_path = self.path.join(super::UNIT_COPY);
            let held = match hold_copy(&copy_path) {
                Ok((f, id)) if Some(id) == self.copy => f,
                Ok(_) => return Err(keep(self, refused("the recovery copy was replaced"))),
                Err(e) => return Err(keep(self, e)),
            };
            let binding = match copy_binding(&copy_path) {
                Ok(b) if Some(b.id) == self.copy => b,
                Ok(_) => return Err(keep(self, refused("the recovery copy was replaced"))),
                Err(e) => return Err(keep(self, e)),
            };
            if !verify(&copy_path) || copy_binding(&copy_path).ok() != Some(binding.clone()) {
                return Err(keep(
                    self,
                    refused("the recovery copy does not open and read on its own"),
                ));
            }
            if let Err(cause) = write_marker(&self.path, &binding) {
                return Err(fail(self, Some(&held), cause));
            }
            let mut first = true;
            for n in names.iter().skip(1).chain(names.first()) {
                let p = self.path.join(n);
                if std::fs::symlink_metadata(&p).is_err() {
                    continue;
                }
                #[cfg(test)]
                super::tests::unlink_hook(std::ffi::OsStr::new(n));
                // ⟨ADR-0008 §17.39 item 2⟩ As on Unix: the copy read again by its path,
                // through a fresh handle, just before the first original's deletion.
                if std::mem::take(&mut first)
                    && copy_binding(&copy_path).ok().as_ref() != Some(&binding)
                {
                    return Err(keep(
                        self,
                        refused("the recovery copy changed after its check; nothing was deleted"),
                    ));
                }
                let removed = if super::unlink_fails(std::ffi::OsStr::new(n)) {
                    Err(std::io::Error::other("injected unlink failure"))
                } else {
                    std::fs::remove_file(&p)
                };
                if let Err(cause) = removed {
                    return Err(fail(self, Some(&held), cause));
                }
            }
            drop(held);
            // The mark first, so a mark always has its copy beside it (or restored).
            match std::fs::remove_file(self.path.join(super::UNIT_DELETING)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(fail(self, None, e));
                }
                _ => {}
            }
            #[cfg(test)]
            super::tests::step_hook("delete-copy");
            drop(self.pin.take());
            let copy_gone = if super::unlink_fails(std::ffi::OsStr::new(super::UNIT_COPY)) {
                Err(std::io::Error::other("injected unlink failure"))
            } else {
                match std::fs::remove_file(&copy_path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                    _ => Ok(()),
                }
            };
            if let Err(e) = copy_gone {
                return Err(fail(self, None, e));
            }
            let gone = match std::fs::remove_file(self.path.join(super::UNIT_RECORD)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
            .and_then(|()| remove_unit_dir(&self.path, self.id));
            gone.map_err(|cause| super::QuarantineError {
                cause,
                stuck: left_now(&self.path),
                restored: Vec::new(),
            })
        }
    }

    /// ⟨W5-I01 (§17.38)⟩ As on Unix: the copy's file ID, size and SHA-256.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Binding {
        id: (u64, u64),
        size: u64,
        sha256: String,
    }

    impl Binding {
        fn text(&self) -> String {
            format!(
                "copy\t{}\t{}\t{}\t{}\n",
                self.id.0, self.id.1, self.size, self.sha256
            )
        }

        fn parse(text: &str) -> Option<Binding> {
            let mut f = text.strip_suffix('\n')?.split('\t');
            let (tag, d, i, size, sha) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            (tag == "copy" && f.next().is_none() && sha.len() == 64).then_some(())?;
            Some(Binding {
                id: (d.parse().ok()?, i.parse().ok()?),
                size: size.parse().ok()?,
                sha256: sha.to_owned(),
            })
        }
    }

    /// The binding of the regular file at `path`, read through one pinned handle (never
    /// following a reparse point).
    fn copy_binding(path: &Path) -> std::io::Result<Binding> {
        use std::io::Read as _;
        let Some((mut f, attrs)) = pin(path)? else {
            return Err(refused("the recovery copy is absent"));
        };
        if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(refused("the recovery copy is not a regular file"));
        }
        let id = heimdall_ipc::windows::file_id(&f)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Ok(Binding {
            id,
            size: bytes.len() as u64,
            sha256: heimdall_issuer::backup::sha256_hex(&bytes),
        })
    }

    /// The deletion mark binding the copy, created exclusively and flushed.
    fn write_marker(dir: &Path, binding: &Binding) -> std::io::Result<()> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(super::UNIT_DELETING))?;
        f.write_all(binding.text().as_bytes())?;
        f.sync_all()
    }

    /// ⟨tests⟩ The deletion mark's text binding the file at `path`.
    #[cfg(test)]
    pub(super) fn marker_text_for(path: &Path) -> std::io::Result<String> {
        Ok(copy_binding(path)?.text())
    }

    fn read_marker(dir: &Path) -> Option<Binding> {
        Binding::parse(&std::fs::read_to_string(dir.join(super::UNIT_DELETING)).ok()?)
    }

    impl Anchors {
        /// ⟨§17.35 item 7, §17.36 item 1⟩ As on Unix.
        pub(super) fn recover(
            &self,
            db_file: &str,
            ops: &super::RecoverOps<'_>,
        ) -> super::Recovered {
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
                                let (r, l, u) = self.recover_unit(&at, id, db_file, ops);
                                out.restored.extend(r);
                                out.left.extend(l);
                                out.unverified.extend(u);
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
            if std::fs::symlink_metadata(self.fam().join(db_file)).is_err() {
                for n in family(db_file).iter().skip(1) {
                    let p = self.fam().join(n);
                    if std::fs::symlink_metadata(&p).is_ok() {
                        out.left.push(p);
                    }
                }
            }
            out
        }

        fn recover_unit(
            &self,
            here: &Path,
            id: (u64, u64),
            db_file: &str,
            ops: &super::RecoverOps<'_>,
        ) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>) {
            // ⟨M08 U2b-1⟩ The family goes back to its own directory (the unit is `here`).
            let state = self.fam();
            let all_left = || (Vec::new(), left_now(here), Vec::new());
            let names = family(db_file);
            for part in super::UNIT_COPY_PART_FILES {
                let _ = std::fs::remove_file(here.join(part));
            }
            let entries = names_in(here);
            if entries.iter().any(|e| {
                e != super::UNIT_RECORD
                    && e != super::UNIT_COPY
                    && e != super::UNIT_DELETING
                    && !names.contains(e)
            }) {
                return all_left();
            }
            let record = if entries.iter().any(|e| e == super::UNIT_RECORD) {
                match read_record(here) {
                    Ok(r) => r,
                    Err(_) => return all_left(),
                }
            } else if entries.is_empty() {
                Vec::new()
            } else {
                return all_left();
            };
            let recorded = |n: &str| record.iter().find(|(k, _)| k == n).map(|e| e.1);
            if std::fs::symlink_metadata(here.join(&names[3])).is_ok() {
                return all_left();
            }
            // ⟨audit E1⟩ As on Unix: finish deleting the originals, then restore the copy;
            // ⟨W5-I01 (§17.38)⟩ never on the mark alone: the copy (in the unit, or restored)
            // is the one the mark binds and reads on its own, and every original present is
            // the recorded file (or an empty one the purge created).
            if entries.iter().any(|e| e == super::UNIT_DELETING) {
                let Some(bound) = read_marker(here) else {
                    return all_left();
                };
                let live_path = state.join(db_file);
                let bound_at = |p: &Path| {
                    copy_binding(p).ok().as_ref() == Some(&bound)
                        && (ops.check)(p)
                        && copy_binding(p).ok().as_ref() == Some(&bound)
                };
                let in_unit = std::fs::symlink_metadata(here.join(super::UNIT_COPY)).is_ok();
                let copy_path = if in_unit {
                    here.join(super::UNIT_COPY)
                } else {
                    live_path.clone()
                };
                // ⟨ADR-0008 §17.39 item 3⟩ The copy is held with no write sharing from
                // before its check through its restore and the restored file's
                // verification; it must be the file the mark binds.
                let held = match hold_copy(&copy_path) {
                    Ok((f, now)) if now == bound.id => Some(f),
                    _ => None,
                };
                if held.is_none() || !bound_at(&copy_path) {
                    let (r, l, _) = all_left();
                    let found = !in_unit && std::fs::symlink_metadata(&live_path).is_ok();
                    return (r, l, found.then(|| live_path.clone()).into_iter().collect());
                }
                for (k, n) in names.iter().enumerate() {
                    let p = here.join(n);
                    let ok = match id_at(&p) {
                        Ok(None) => true,
                        Ok(Some(now)) => {
                            recorded(n) == Some(now)
                                || (recorded(n).is_none()
                                    && k != 0
                                    && std::fs::symlink_metadata(&p)
                                        .is_ok_and(|m| m.is_file() && m.len() == 0))
                        }
                        Err(_) => false,
                    };
                    if !ok {
                        return all_left();
                    }
                }
                #[cfg(test)]
                super::tests::step_hook("recover-checked");
                // ⟨ADR-0008 §17.39 item 1⟩ As on Unix: restore first (through the held
                // handle), then verify the file at the live name from a fresh read, and
                // only then delete the originals.
                let mut restored = Vec::new();
                if in_unit {
                    if std::fs::symlink_metadata(&live_path).is_ok() {
                        return all_left();
                    }
                    let (r, _) = restore_copy(state, here, db_file, Some(bound.id), held.as_ref());
                    if r.is_empty() {
                        return all_left();
                    }
                    restored = r;
                    if !bound_at(&live_path) {
                        return (Vec::new(), left_now(here), vec![live_path]);
                    }
                }
                drop(held);
                for n in names.iter().skip(1).chain(names.first()) {
                    let p = here.join(n);
                    if std::fs::symlink_metadata(&p).is_ok() && std::fs::remove_file(&p).is_err() {
                        return (restored, left_now(here), Vec::new());
                    }
                }
                for n in [super::UNIT_DELETING, super::UNIT_RECORD] {
                    let _ = std::fs::remove_file(here.join(n));
                }
                let left = if remove_unit_dir(here, id).is_ok() {
                    Vec::new()
                } else {
                    left_now(here)
                };
                return (restored, left, Vec::new());
            }
            for n in &names {
                if std::fs::symlink_metadata(here.join(n)).is_err()
                    && let Ok(Some(now)) = id_at(&state.join(n))
                    && recorded(n) == Some(now)
                    && heimdall_ipc::windows::move_no_replace(&state.join(n), &here.join(n))
                        .is_err()
                {
                    return all_left();
                }
            }
            // The purge's own files (an index, an empty log, never recorded) are removed.
            for n in names.iter().skip(1) {
                let p = here.join(n);
                if recorded(n).is_none()
                    && let Ok(m) = std::fs::symlink_metadata(&p)
                    && (n.ends_with("-shm") || m.len() == 0)
                {
                    let _ = std::fs::remove_file(&p);
                }
            }
            let has = |n: &str| std::fs::symlink_metadata(here.join(n)).is_ok();
            let db_in_unit = has(db_file);
            let live = std::fs::symlink_metadata(state.join(db_file)).is_ok();
            let mut restored = Vec::new();
            if !live {
                if !has(super::UNIT_COPY) {
                    if !db_in_unit {
                        let _ = std::fs::remove_file(here.join(super::UNIT_RECORD));
                        let left = if remove_unit_dir(here, id).is_ok() {
                            Vec::new()
                        } else {
                            left_now(here)
                        };
                        return (Vec::new(), left, Vec::new());
                    }
                    if self.copy_in_unit(here, id, db_file, &record, ops).is_err() {
                        return all_left();
                    }
                }
                let copy = id_at(&here.join(super::UNIT_COPY)).ok().flatten();
                let (r, _) = restore_copy(state, here, db_file, copy, None);
                if r.is_empty() {
                    return all_left();
                }
                restored = r;
            } else if has(super::UNIT_COPY) {
                return all_left();
            }
            if db_in_unit {
                if !(ops.confirm)(&state.join(db_file), &here.join(db_file)) {
                    return (restored, left_now(here), Vec::new());
                }
                for n in names.iter().skip(1).chain(names.first()) {
                    let p = here.join(n);
                    if std::fs::symlink_metadata(&p).is_ok() && std::fs::remove_file(&p).is_err() {
                        return (restored, left_now(here), Vec::new());
                    }
                }
            }
            let _ = std::fs::remove_file(here.join(super::UNIT_RECORD));
            let left = if remove_unit_dir(here, id).is_ok() {
                Vec::new()
            } else {
                left_now(here)
            };
            (restored, left, Vec::new())
        }

        fn copy_in_unit(
            &self,
            here: &Path,
            id: (u64, u64),
            db_file: &str,
            record: &[(String, (u64, u64))],
            ops: &super::RecoverOps<'_>,
        ) -> std::io::Result<()> {
            let members = record
                .iter()
                .filter(|(n, rid)| matches!(id_at(&here.join(n)), Ok(Some(now)) if now == *rid))
                .map(|(n, rid)| (n.clone(), vec![(PathBuf::new(), *rid)]))
                .collect();
            let mut q = Quarantine {
                moved: Vec::new(),
                absent: Vec::new(),
                unit: Some(Unit {
                    path: here.to_path_buf(),
                    pin: None,
                    id,
                    members,
                    held: Vec::new(),
                    copy: None,
                }),
                db_file: db_file.to_owned(),
                tag: String::new(),
            };
            q.hold()?;
            let result = match q.read_db(
                self,
                |p| (ops.open)(p),
                |_| (),
                |s: &Box<dyn std::any::Any>, p| (ops.copy)(s.as_ref(), p),
            )? {
                Some(((), confirmed)) => confirmed,
                None => Err(refused("no database to copy")),
            };
            if let Some(u) = q.unit.as_mut() {
                u.unpin();
            }
            result
        }
    }

    impl Quarantine {
        fn refuse(self, a: &Anchors, cause: std::io::Error) -> super::QuarantineError {
            let (restored, stuck) = self.restore(a);
            super::QuarantineError {
                cause,
                stuck,
                restored,
            }
        }

        /// ⟨§17.35 item 1⟩ Create the quarantine directory exclusively, owner-only
        /// (`CreateDirectoryW` with this user's protected DACL), pin it, write its record,
        /// and move the family into it, each file keeping its name, never over anything.
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
                copy: None,
            });
            write_record(&unit.path, &family)?;
            for (n, m) in family {
                #[cfg(test)]
                super::tests::move_hook(std::ffi::OsStr::new(&n));
                heimdall_ipc::windows::move_no_replace(&a.fam().join(&n), &unit.path.join(&n))?;
                unit.members.push((n, m));
            }
            Ok(())
        }

        /// ⟨audit C0; §17.36 item 1⟩ Pin the quarantined database, `-wal` and `-shm` in the
        /// quarantine directory for the whole read (a moved one checked against its
        /// inspected file ID; an absent one created empty with `create_new`); a
        /// `-journal` there refuses.
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
                    if std::fs::symlink_metadata(&path).is_ok() {
                        return Err(super::journal_refused());
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
                for n in names_in(&u.path) {
                    let ours = n == super::UNIT_RECORD
                        || (n == super::UNIT_COPY && u.copy.is_some())
                        || u.members.iter().any(|(k, _)| *k == n)
                        || u.held.iter().any(|h| h.created && h.name == n);
                    if !ours {
                        return Err(refused("an entry appeared in the quarantine directory"));
                    }
                }
                if let Some(cid) = u.copy
                    && id_at(&u.path.join(super::UNIT_COPY))? != Some(cid)
                {
                    return Err(refused("the recovery copy was replaced"));
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

        /// ⟨audit C0; §17.36 item 1⟩ As on Unix: no `-journal` just before the open; the
        /// final read on a read-only connection with all three files pinned; only on a
        /// confirmed connection, the recovery copy (`VACUUM INTO` an exclusively created
        /// file), checked, flushed and moved into place.
        pub(super) fn read_db<S, T>(
            &mut self,
            _a: &Anchors,
            open: impl FnOnce(&Path) -> S,
            read: impl FnOnce(&S) -> T,
            copy: impl FnOnce(&S, &Path) -> bool,
        ) -> std::io::Result<Option<(T, std::io::Result<()>)>> {
            let db_file = self.db_file.clone();
            let Some(u) = &self.unit else {
                return Ok(None);
            };
            if u.held.is_empty() {
                return Ok(None);
            }
            if std::fs::symlink_metadata(u.path.join(&family(&db_file)[3])).is_ok() {
                return Err(super::journal_refused());
            }
            let part_path = u.path.join(super::UNIT_COPY_PART);
            let part = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&part_path)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::AlreadyExists => {
                        refused("a file appeared in the quarantine directory")
                    }
                    _ => e,
                })?;
            let part_id = heimdall_ipc::windows::file_id(&part)?;
            let store = open(&u.path.join(&db_file));
            let out = read(&store);
            let mut confirmed = self.held_in_place();
            if confirmed.is_ok() && !copy(&store, &part_path) {
                confirmed = Err(refused("the recovery copy could not be written"));
            }
            drop(store);
            let confirmed = confirmed.and_then(|()| {
                #[cfg(test)]
                super::tests::step_hook("copy-written");
                if id_at(&part_path)? != Some(part_id) {
                    return Err(refused("the recovery copy was replaced"));
                }
                if part.metadata()?.len() == 0 {
                    return Err(refused("the recovery copy is empty"));
                }
                part.sync_all()?;
                drop(part);
                heimdall_ipc::windows::move_no_replace(&part_path, &u.path.join(super::UNIT_COPY))
            });
            match &confirmed {
                Ok(()) => {
                    if let Some(u) = self.unit.as_mut() {
                        u.copy = Some(part_id);
                    }
                }
                Err(_) => {
                    if matches!(id_at(&part_path), Ok(Some(now)) if now == part_id) {
                        let _ = std::fs::remove_file(&part_path);
                    }
                }
            }
            Ok(Some((out, confirmed)))
        }

        /// ⟨audit C1; §17.36 item 1⟩ As on Unix.
        pub(super) fn delete(
            mut self,
            a: &Anchors,
            verify: &dyn Fn(&Path) -> bool,
        ) -> Result<(), super::QuarantineError> {
            if let Some(u) = &self.unit
                && u.copy.is_none()
                && u.members.iter().any(|(n, _)| *n == self.db_file)
            {
                return Err(self.refuse(a, refused("the recovery copy was not written")));
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
                    let db_file = self.db_file.clone();
                    if let Some(u) = self.unit.as_mut() {
                        let (r, s) = u.restore(a, &db_file);
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
                Some(u) => u.delete(a, &db_file, verify),
                None => Ok(()),
            }
        }

        pub(super) fn restore(mut self, a: &Anchors) -> (Vec<PathBuf>, Vec<PathBuf>) {
            let (mut restored, mut left) = (Vec::new(), Vec::new());
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
                    left.push(from);
                } else {
                    restored.push(to);
                }
            }
            let db_file = self.db_file.clone();
            if let Some(u) = self.unit.as_mut() {
                let (r, l) = u.restore(a, &db_file);
                restored.extend(r);
                left.extend(l);
            }
            (restored, left)
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

    type UnlinkHook = Option<Box<dyn FnMut(&std::ffi::OsStr)>>;

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

    type StepAction = Option<(&'static str, Box<dyn FnMut()>)>;

    thread_local! {
        static STEP_ACTION: std::cell::RefCell<StepAction> =
            const { std::cell::RefCell::new(None) };
    }

    /// At a named step of the recovery copy's life (`"copy-written"`, `"restore"`,
    /// `"delete-copy"`): a scheduled action, or a simulated crash.
    pub(super) fn step_hook(step: &str) {
        STEP_ACTION.with(|a| {
            if let Some((at, f)) = a.borrow_mut().as_mut()
                && *at == step
            {
                f();
            }
        });
        crash_hook("step", std::ffi::OsStr::new(step));
    }

    /// Run `body` with `action` run at step `step`.
    pub(crate) fn with_step<T>(
        step: &'static str,
        action: impl FnMut() + 'static,
        body: impl FnOnce() -> T,
    ) -> T {
        STEP_ACTION.with(|a| *a.borrow_mut() = Some((step, Box::new(action))));
        let out = body();
        STEP_ACTION.with(|a| *a.borrow_mut() = None);
        out
    }

    /// Before each family file's move into the unit.
    pub(super) fn move_hook(name: &std::ffi::OsStr) {
        crash_hook("move", name);
    }

    /// Run `body`, which stops (a simulated crash) just before `name` is moved in
    /// `phase`; `true` when it did.
    pub(crate) fn crashing_at(phase: &'static str, name: &str, body: impl FnOnce()) -> bool {
        CRASH_AT.with(|c| *c.borrow_mut() = Some((phase, std::ffi::OsString::from(name))));
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_err();
        CRASH_AT.with(|c| *c.borrow_mut() = None);
        crashed
    }

    /// The deletion mark's text binding the file at `path` (its identity, size, SHA-256).
    pub(crate) fn marker_text_for(path: &std::path::Path) -> String {
        imp::marker_text_for(path).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The deletion mark's file name.
    pub(crate) const MARKER: &str = UNIT_DELETING;

    /// The recovery copy's file name.
    pub(crate) const COPY_NAME: &str = UNIT_COPY;

    /// Called before each file's `unlinkat` (tests schedule a replacement there).
    pub(super) fn unlink_hook(name: &std::ffi::OsStr) {
        crash_hook("unlink", name);
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
    fn roots() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        roots_in(None)
    }

    /// [`roots`] under `parent` (the process's temporary directory when `None`).
    fn roots_in(
        parent: Option<&std::path::Path>,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let d = match parent {
            Some(p) => tempfile::tempdir_in(p),
            None => tempfile::tempdir(),
        }
        .unwrap_or_else(|e| panic!("{e}"));
        let state = d.path().join("state");
        let run = d.path().join("run");
        for p in [d.path(), &state, &run] {
            std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("{e}"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
                    .unwrap_or_else(|e| panic!("{e}"));
            }
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
        // Refused before any recovery copy existed: the database stays whole in its
        // quarantine directory (§17.36 item 1); the trees are renamed back.
        let db = unit_dir(&state).map(|u| u.join("state.db"));
        for p in [
            run.join("b").join("t").join("f"),
            run.join("mux").join("f"),
            state.join("backups").join("f"),
            db.unwrap_or_else(|| state.join("state.db")),
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
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // ⟨§17.36: the Linux-only failure⟩ Both simulated hosts: a shared primary group,
        // and a user private group the synthetic directories carry.
        for private in [false, true] {
            let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
            let gid = std::fs::metadata(d.path())
                .map(|m| m.gid())
                .unwrap_or(u32::MAX);
            let oracle = move || Ok(private.then_some(gid));
            let open = |s: &std::path::Path, r: &std::path::Path, top: &std::path::Path| {
                Anchors::open_with_group(s, r, Some(top), &oracle)
            };
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
            assert!(open(&state, &run, d.path()).is_ok());
            chmod(&home.join(".local"), 0o775);
            assert_eq!(
                open(&state, &run, d.path()).is_err(),
                !private,
                "a group-writable ancestor refuses (unless it is the user's private group)"
            );
            chmod(&home.join(".local"), 0o755);
            chmod(&d.path().join("run").join("user"), 0o1777);
            assert!(
                open(&state, &run, d.path()).is_err(),
                "a sticky parent refuses"
            );
        }
    }

    /// `secure_path_full_chain_from_root_without_the_hook` (ADR-0008 §17.33 item 14): with
    /// no trusted top the check runs from `/`; on macOS the per-user temporary directory's
    /// chain passes it (observed: `/var` root's link, `/private/var/folders` root 0755, the
    /// per-user level this user's 0755, `T` 0700). Linux test hosts keep scratch under the
    /// sticky `/tmp`, which the rule refuses, so this runs on macOS only.
    /// ⟨M03 wave 6⟩ The roots are made under the per-user temporary directory itself
    /// (`getconf DARWIN_USER_TEMP_DIR`), not `TMPDIR`: the native harness points `TMPDIR` under
    /// the sticky `/tmp` (socket path lengths), whose chain the rule rightly refuses.
    #[cfg(target_os = "macos")]
    #[test]
    fn secure_path_full_chain_from_root_without_the_hook() {
        let out = std::process::Command::new("/usr/bin/getconf")
            .arg("DARWIN_USER_TEMP_DIR")
            .output()
            .unwrap_or_else(|e| panic!("getconf: {e}"));
        assert!(out.status.success(), "getconf DARWIN_USER_TEMP_DIR");
        let per_user = std::path::PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        assert!(per_user.is_dir(), "the per-user temporary directory exists");
        let (_d, state, run) = roots_in(Some(&per_user));
        assert!(Anchors::open(&state, &run, None).is_ok());
    }

    /// `purge_trusted_top_conditions` (ADR-0008 §17.33 item 14): the debug-only trusted
    /// top must be a strict ancestor of both roots (the root itself, or a directory beside
    /// them, refuses) and this user's owner-only directory (a group-writable top refuses);
    /// below it every component is still checked (a group-writable one refuses).
    #[cfg(unix)]
    #[test]
    fn purge_trusted_top_conditions() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // ⟨§17.36: the Linux-only failure⟩ Both simulated hosts: a shared primary group,
        // and a user private group the synthetic directories carry.
        for private in [false, true] {
            let (d, state, run) = roots();
            let gid = std::fs::metadata(d.path())
                .map(|m| m.gid())
                .unwrap_or(u32::MAX);
            let oracle = move || Ok(private.then_some(gid));
            let open = |s: &std::path::Path, r: &std::path::Path, top: &std::path::Path| {
                Anchors::open_with_group(s, r, Some(top), &oracle)
            };
            let chmod = |p: &std::path::Path, m: u32| {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(m))
                    .unwrap_or_else(|e| panic!("{e}"));
            };
            assert!(open(&state, &run, d.path()).is_ok());
            assert!(
                open(&state, d.path(), d.path()).is_err(),
                "not a strict ancestor (the top is a root itself)"
            );
            let beside = d.path().join("beside");
            std::fs::create_dir(&beside).unwrap_or_else(|e| panic!("{e}"));
            chmod(&beside, 0o700);
            assert!(open(&state, &run, &beside).is_err(), "not an ancestor");
            chmod(d.path(), 0o770);
            assert!(
                open(&state, &run, d.path()).is_err(),
                "a group-writable top"
            );
            chmod(d.path(), 0o750);
            assert!(
                open(&state, &run, d.path()).is_err(),
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
            assert_eq!(
                open(&s2, &r2, d.path()).is_err(),
                !private,
                "a group-writable component below the top (refused unless the user's private group)"
            );
            chmod(&deep, 0o755);
            assert!(open(&s2, &r2, d.path()).is_ok());
        }
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
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        // ⟨§17.36: the Linux-only failure⟩ Run against both simulated hosts: a shared
        // primary group (refused, naming the fix) and a user private group that the
        // directory carries (accepted, §17.34 item 2).
        for private in [false, true] {
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
            let gid = std::fs::metadata(&mid).map(|m| m.gid()).unwrap_or(u32::MAX);
            let oracle = move || Ok(private.then_some(gid));
            let opened = Anchors::open_with_group(&s2, &r2, Some(d.path()), &oracle);
            if private {
                assert!(
                    opened.is_ok(),
                    "a user private group's directory is refused"
                );
            } else {
                let Err(e) = opened else {
                    panic!("accepted");
                };
                assert!(e.to_string().contains("chmod g-w"), "{e}");
                assert!(e.to_string().contains("mid"), "{e}");
            }
            let _ = (state, run);
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
        // Only the database family is left (whole, in its quarantine directory: no
        // recovery copy existed yet); every tree is renamed back.
        let u = unit_dir(&state).unwrap_or_else(|| panic!("the family is kept"));
        assert!(e.stuck.iter().all(|p| p.starts_with(&u)), "{:?}", e.stuck);
        assert_eq!(
            std::fs::read(&victim).unwrap_or_default(),
            b"unique owner data"
        );
        for p in [
            run.join("b").join("t").join("f"),
            run.join("mux").join("f"),
            u.join("state.db"),
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
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(state.join("backups")).unwrap_or_else(|e| panic!("{e}"));
        let new = state.join("backups").join("placed-after");
        std::fs::write(&new, b"new owner data").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(state.join("state.db"), b"new db").unwrap_or_else(|e| panic!("{e}"));
        q.delete(&|_| true).unwrap_or_else(|e| panic!("{e:?}"));
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
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        let end = q.delete(&|_| true);
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
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(state.join("state.db"), b"new").unwrap_or_else(|e| panic!("{e}"));
        let (_, stuck) = q.restore();
        assert!(
            !stuck.is_empty(),
            "the entry at the original name was replaced"
        );
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
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
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
        q.delete(&|_| true).unwrap_or_else(|e| panic!("{e:?}"));
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
    #[test]
    fn final_review_companion_failure_preserves_database() {
        let (d, state, run) = roots();
        std::fs::write(state.join("state.db-wal"), b"").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        // Unix: the directory made read-only just before the `-wal`'s unlink (a real OS
        // error); Windows (no directory write bit): the `-wal`'s deletion fails injected.
        #[cfg(unix)]
        let end = {
            use std::os::unix::fs::PermissionsExt as _;
            let st = state.clone();
            let end = with_unlink_hook(
                move |name| {
                    if name == std::ffi::OsStr::new("state.db-wal")
                        && let Some(u) = unit_dir(&st)
                    {
                        let _ =
                            std::fs::set_permissions(&u, std::fs::Permissions::from_mode(0o500));
                    }
                },
                || q.delete(&|_| true),
            );
            if let Some(u) = unit_dir(&state) {
                let _ = std::fs::set_permissions(&u, std::fs::Permissions::from_mode(0o700));
            }
            end
        };
        #[cfg(windows)]
        let end = {
            FAIL_UNLINK.with(|f| *f.borrow_mut() = Some("state.db-wal".into()));
            let end = q.delete(&|_| true);
            FAIL_UNLINK.with(|f| *f.borrow_mut() = None);
            end
        };
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

    /// `delete_refuses_without_a_recovery_copy` (ADR-0008 §17.36 item 1): with no complete
    /// recovery copy, the deletion refuses with nothing deleted: the trees are renamed
    /// back and the database family stays whole in its quarantine directory, every byte
    /// as it was.
    #[test]
    fn delete_refuses_without_a_recovery_copy() {
        let (d, state, run) = roots();
        std::fs::write(state.join("state.db-wal"), b"frames").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        let Err(e) = q.delete(&|_| true) else {
            panic!("a database family without its recovery copy was deleted")
        };
        let u = unit_dir(&state).unwrap_or_else(|| panic!("the family is kept"));
        assert!(e.stuck.contains(&u), "{:?}", e.stuck);
        assert_eq!(
            std::fs::read(u.join("state.db")).ok().as_deref(),
            Some(&b"db"[..])
        );
        assert_eq!(
            std::fs::read(u.join("state.db-wal")).ok().as_deref(),
            Some(&b"frames"[..])
        );
        assert!(state.join("backups").join("f").exists() && run.join("b").exists());
    }

    /// `a_planted_journal_refuses_with_every_byte_unchanged` (ADR-0008 §17.36 item 1): a
    /// family that contains a `-journal` is refused before anything moves or opens: every
    /// file of the family is at its name, each byte for byte as before (compared whole and
    /// by hash), and the trees are untouched.
    #[test]
    fn a_planted_journal_refuses_with_every_byte_unchanged() {
        use std::hash::{BuildHasher as _, BuildHasherDefault, DefaultHasher};
        let (d, state, run) = roots();
        std::fs::write(state.join("state.db-wal"), b"frames").unwrap_or_else(|e| panic!("{e}"));
        let mut journal = vec![0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
        journal.resize(1024, 7);
        std::fs::write(state.join("state.db-journal"), &journal).unwrap_or_else(|e| panic!("{e}"));
        let names = ["state.db", "state.db-wal", "state.db-journal"];
        let hash = |b: &[u8]| BuildHasherDefault::<DefaultHasher>::default().hash_one(b);
        let before: Vec<(Vec<u8>, u64)> = names
            .iter()
            .map(|n| {
                let b = std::fs::read(state.join(n)).unwrap_or_else(|e| panic!("{e}"));
                let h = hash(&b);
                (b, h)
            })
            .collect();
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let Err(e) = anchors.quarantine("state.db", || {}) else {
            panic!("a family with a rollback journal was quarantined")
        };
        assert_eq!(e.cause.kind(), std::io::ErrorKind::InvalidData, "{e:?}");
        assert!(unit_dir(&state).is_none(), "nothing moved");
        for (n, (b, h)) in names.iter().zip(&before) {
            let now = std::fs::read(state.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
            assert_eq!(&now, b, "{n} changed");
            assert_eq!(hash(&now), *h, "{n}'s hash changed");
        }
        assert!(state.join("backups").join("f").exists() && run.join("b").join("t").exists());
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
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        FAIL_UNLINK.with(|f| *f.borrow_mut() = Some("state.db-shm".into()));
        let end = q.delete(&|_| true);
        FAIL_UNLINK.with(|f| *f.borrow_mut() = None);
        let Err(e) = end else {
            panic!("the injected failure was not reported")
        };
        // The recovery copy alone is restored; the original family (with the files the
        // purge created) stays in its quarantine directory, listed as left.
        assert_eq!(e.restored, vec![state.join("state.db")], "{e:?}");
        let u = unit_dir(&state).unwrap_or_else(|| panic!("the original family is kept"));
        assert!(e.stuck.iter().all(|p| p.starts_with(&u)), "{e:?}");
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
    #[test]
    fn final_review_quarantine_dir_removal_failure_reports_what_is_on_disk() {
        let (d, state, run) = roots();
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        let st = state.clone();
        let end = with_unlink_hook(
            move |name| {
                if name == std::ffi::OsStr::new("state.db")
                    && let Some(u) = unit_dir(&st)
                {
                    let _ = std::fs::write(u.join("placed"), b"x");
                }
            },
            || q.delete(&|_| true),
        );
        let Err(e) = end else {
            panic!("the directory's removal could not have succeeded")
        };
        let u = unit_dir(&state).unwrap_or_else(|| panic!("the directory is left"));
        assert_eq!(
            e.stuck,
            vec![u.clone(), u.join("placed")],
            "only what is on disk"
        );
        assert!(!u.join("state.db").exists(), "the database was deleted");
        assert!(e.restored.is_empty());
    }

    /// `w5_i01_failed_copy_check_unlinks_nothing` (W5-I01, §17.38): on the normal purge
    /// path, a recovery copy that does not open and read on its own (`verify` false) keeps
    /// the whole unit: no mark is written and no original is unlinked.
    #[test]
    fn w5_i01_failed_copy_check_unlinks_nothing() {
        let (d, state, run) = roots();
        std::fs::write(state.join("state.db-wal"), b"frames").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        let Err(e) = q.delete(&|_| false) else {
            panic!("the originals were deleted behind a copy that does not read")
        };
        let u = unit_dir(&state).unwrap_or_else(|| panic!("the unit is kept"));
        assert!(e.stuck.contains(&u), "{e:?}");
        assert_eq!(
            std::fs::read(u.join("state.db")).ok().as_deref(),
            Some(&b"db"[..])
        );
        assert_eq!(
            std::fs::read(u.join("state.db-wal")).ok().as_deref(),
            Some(&b"frames"[..])
        );
        assert!(!u.join(MARKER).exists(), "no mark without a checked copy");
    }

    // --- W5-J01 (ADR-0008 §17.39) -----------------------------------------------------------

    /// A unit stopped at the first original's deletion (`state.db-wal`): the mark is
    /// durable, and the originals (`db`, `frames`) and the stand-in copy are in the unit.
    fn unit_marked(d: &std::path::Path, state: &std::path::Path, run: &std::path::Path) {
        std::fs::write(state.join("state.db-wal"), b"frames").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(state, run, Some(d)).unwrap_or_else(|e| panic!("{e}"));
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        assert!(crashing_at("unlink", "state.db-wal", || {
            let _ = q.delete(&|_| true);
        }));
        let u = unit_dir(state).unwrap_or_else(|| panic!("no unit"));
        assert!(u.join(MARKER).exists() && u.join(COPY_NAME).exists());
    }

    /// `w5_j01_restored_copy_failing_verification_keeps_every_original` (ADR-0008 §17.39
    /// item 1): recovery acting on a mark restores the copy as `state.db` first; when the
    /// file at `state.db` then fails its verification (here `check` refuses the live
    /// name), every original stays in the unit with the mark and the record, nothing is
    /// unlinked, the unverified `state.db` is reported as such, and the start-up check
    /// refuses with `state.db` present.
    #[test]
    fn w5_j01_restored_copy_failing_verification_keeps_every_original() {
        let (d, state, run) = roots();
        unit_marked(d.path(), &state, &run);
        let u = unit_dir(&state).unwrap_or_else(|| panic!("no unit"));
        let live = state.join("state.db");
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let open = |_: &std::path::Path| -> Box<dyn std::any::Any> { Box::new(()) };
        let copy = |_: &dyn std::any::Any, _: &std::path::Path| false;
        let confirm = |_: &std::path::Path, _: &std::path::Path| false;
        let check = |p: &std::path::Path| p != live.as_path();
        let ops = RecoverOps {
            open: &open,
            copy: &copy,
            confirm: &confirm,
            check: &check,
        };
        let rec = anchors.recover("state.db", &ops);
        assert_eq!(rec.unverified, vec![live.clone()], "{rec:?}");
        assert!(rec.restored.is_empty(), "{rec:?}");
        assert!(rec.left.contains(&u), "{rec:?}");
        assert_eq!(std::fs::read(&live).ok().as_deref(), Some(&b"db"[..]));
        assert_eq!(
            std::fs::read(u.join("state.db")).ok().as_deref(),
            Some(&b"db"[..]),
            "the original database was unlinked"
        );
        assert_eq!(
            std::fs::read(u.join("state.db-wal")).ok().as_deref(),
            Some(&b"frames"[..]),
            "the original -wal was unlinked"
        );
        assert!(u.join(MARKER).exists() && u.join(UNIT_RECORD).exists());
        assert!(
            !heimdall_runtime::service::quarantine_leftovers(&state)
                .unwrap_or_else(|e| panic!("{e}"))
                .is_empty(),
            "start-up would run"
        );
        // Again: the copy is now at `state.db`, still failing; still nothing unlinked.
        let rec = anchors.recover("state.db", &ops);
        assert_eq!(rec.unverified, vec![live], "{rec:?}");
        assert_eq!(
            std::fs::read(u.join("state.db-wal")).ok().as_deref(),
            Some(&b"frames"[..])
        );
    }

    /// `w5_j01_windows_held_copy_denies_a_second_writer` (ADR-0008 §17.39 item 3; Windows
    /// only): while the recovery copy is held (on the normal path from its check through
    /// the last original's deletion; in recovery through its restore and verification), a
    /// second open of it for writing fails with `ERROR_SHARING_VIOLATION`, a read still
    /// opens it, and the deletion and the recovery complete with the copy unchanged.
    #[cfg(windows)]
    #[test]
    fn w5_j01_windows_held_copy_denies_a_second_writer() {
        type Tried = std::rc::Rc<std::cell::RefCell<Vec<(bool, bool)>>>;
        /// A write open (refused by the hold?) and a read (works?) of the copy at `p`.
        fn try_both(p: &std::path::Path, tried: &Tried) {
            let write = std::fs::OpenOptions::new().write(true).open(p);
            let refused = matches!(&write, Err(e) if e.raw_os_error() == Some(32));
            let read = std::fs::read(p).is_ok_and(|b| b == b"db");
            tried.borrow_mut().push((refused, read));
        }
        // The normal path.
        let (d, state, run) = roots();
        std::fs::write(state.join("state.db-wal"), b"frames").unwrap_or_else(|e| panic!("{e}"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let mut q = anchors
            .quarantine("state.db", || {})
            .unwrap_or_else(|e| panic!("{:?}", e.cause));
        q.fake_copy().unwrap_or_else(|e| panic!("{e}"));
        let tried: Tried = std::rc::Rc::default();
        let (t, st) = (tried.clone(), state.clone());
        let end = with_unlink_hook(
            move |n| {
                if let Some(u) = unit_dir(&st)
                    && (n == "state.db-wal" || n == "state.db")
                {
                    try_both(&u.join(COPY_NAME), &t);
                }
            },
            || q.delete(&|_| true),
        );
        end.unwrap_or_else(|e| panic!("{:?}", e.cause));
        assert_eq!(*tried.borrow(), vec![(true, true), (true, true)]);
        // Recovery.
        let (d, state, run) = roots();
        unit_marked(d.path(), &state, &run);
        let u = unit_dir(&state).unwrap_or_else(|| panic!("no unit"));
        let anchors = Anchors::open(&state, &run, Some(d.path())).unwrap_or_else(|e| panic!("{e}"));
        let open = |_: &std::path::Path| -> Box<dyn std::any::Any> { Box::new(()) };
        let copy = |_: &dyn std::any::Any, _: &std::path::Path| false;
        let confirm = |_: &std::path::Path, _: &std::path::Path| false;
        let check = |_: &std::path::Path| true;
        let ops = RecoverOps {
            open: &open,
            copy: &copy,
            confirm: &confirm,
            check: &check,
        };
        let tried: Tried = std::rc::Rc::default();
        let t = tried.clone();
        let at = u.join(COPY_NAME);
        let rec = with_step(
            "recover-checked",
            move || try_both(&at, &t),
            || anchors.recover("state.db", &ops),
        );
        assert_eq!(*tried.borrow(), vec![(true, true)]);
        assert!(rec.left.is_empty() && rec.unverified.is_empty(), "{rec:?}");
        assert_eq!(
            std::fs::read(state.join("state.db")).ok().as_deref(),
            Some(&b"db"[..])
        );
        assert!(unit_dir(&state).is_none());
    }
}
