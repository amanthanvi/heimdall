//! The file-system calls the crate makes, as a trait, so that a test can fail or stop the
//! process at any one of them ([`FaultFs`]).
//!
//! Every mutating call names its [`Point`]: the durable step it belongs to. Reads carry
//! none. [`RealFs`] is the only production implementation.

use std::cell::{Cell, RefCell};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// What a path is, without following a final symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Nothing is there.
    Missing,
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link, a reparse point or anything else: never read, written or removed
    /// through.
    Other,
}

/// The step a mutating call belongs to. The six the ADR names for the switch are
/// [`Point::StagedFileSync`], [`Point::RecordSync`], [`Point::GenerationDirSync`],
/// [`Point::TempPointerSync`], [`Point::PointerRename`] and [`Point::StateDirSync`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Point {
    /// Writing the staging intent's temporary file.
    IntentWrite,
    /// Syncing the staging intent's temporary file.
    IntentSync,
    /// Renaming the staging intent into place.
    IntentRename,
    /// Syncing the state directory after the intent's rename.
    IntentDirSync,
    /// Creating the `generations` directory or one generation directory.
    GenerationCreate,
    /// Syncing one file the caller staged (the database).
    StagedFileSync,
    /// Writing the operation record.
    RecordWrite,
    /// Syncing the operation record.
    RecordSync,
    /// Syncing the generation directory.
    GenerationDirSync,
    /// Syncing the `generations` directory, which holds the new directory's entry.
    GenerationsDirSync,
    /// Writing the temporary pointer.
    TempPointerWrite,
    /// Syncing the temporary pointer.
    TempPointerSync,
    /// Renaming the temporary pointer over `CURRENT`: the only step that changes which
    /// state is live.
    PointerRename,
    /// Syncing the state directory after the pointer's rename.
    StateDirSync,
    /// Appending to a generation's migration notes.
    MigrationAppend,
    /// Cutting a torn tail off the request ledger.
    LedgerRepair,
    /// Appending one record to the request ledger (written and synced in one call).
    LedgerAppend,
    /// Writing the ledger's replacement during a trim.
    LedgerRewrite,
    /// Syncing the ledger's replacement.
    LedgerRewriteSync,
    /// Renaming the ledger's replacement into place.
    LedgerRename,
    /// Syncing the state directory after the ledger's rename.
    LedgerDirSync,
    /// Removing a leftover (a staged generation, a temporary file, a finished intent).
    Cleanup,
}

/// The calls the crate makes. Paths are absolute and built by the crate from validated
/// names; an implementation performs the one call and nothing else.
pub trait Fs {
    /// What `path` is, without following a final symbolic link.
    fn kind(&self, path: &Path) -> io::Result<Kind>;
    /// The whole file, or `InvalidData` when it is longer than `limit` bytes.
    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>>;
    /// The names in a directory.
    fn list(&self, dir: &Path) -> io::Result<Vec<String>>;
    /// Create one directory; it must not exist.
    fn create_dir(&self, point: Point, path: &Path) -> io::Result<()>;
    /// Create a file that must not exist and write `bytes`. Not synced.
    fn write_new(&self, point: Point, path: &Path, bytes: &[u8]) -> io::Result<()>;
    /// Append `bytes` (creating the file) and sync the file.
    fn append_sync(&self, point: Point, path: &Path, bytes: &[u8]) -> io::Result<()>;
    /// Cut a file to `len` bytes and sync it.
    fn truncate_sync(&self, point: Point, path: &Path, len: u64) -> io::Result<()>;
    /// Flush a file's data and metadata to the device.
    fn sync_file(&self, point: Point, path: &Path) -> io::Result<()>;
    /// Flush a directory's entries to the device (nothing on Windows, which has no
    /// directory sync).
    fn sync_dir(&self, point: Point, path: &Path) -> io::Result<()>;
    /// Rename `from` over `to` on the same volume, replacing it atomically.
    fn rename_over(&self, point: Point, from: &Path, to: &Path) -> io::Result<()>;
    /// Remove one file.
    fn remove_file(&self, point: Point, path: &Path) -> io::Result<()>;
    /// Remove a directory and what it holds, following no link.
    fn remove_dir_all(&self, point: Point, path: &Path) -> io::Result<()>;
}

impl<F: Fs + ?Sized> Fs for &F {
    fn kind(&self, path: &Path) -> io::Result<Kind> {
        (**self).kind(path)
    }
    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        (**self).read(path, limit)
    }
    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        (**self).list(dir)
    }
    fn create_dir(&self, point: Point, path: &Path) -> io::Result<()> {
        (**self).create_dir(point, path)
    }
    fn write_new(&self, point: Point, path: &Path, bytes: &[u8]) -> io::Result<()> {
        (**self).write_new(point, path, bytes)
    }
    fn append_sync(&self, point: Point, path: &Path, bytes: &[u8]) -> io::Result<()> {
        (**self).append_sync(point, path, bytes)
    }
    fn truncate_sync(&self, point: Point, path: &Path, len: u64) -> io::Result<()> {
        (**self).truncate_sync(point, path, len)
    }
    fn sync_file(&self, point: Point, path: &Path) -> io::Result<()> {
        (**self).sync_file(point, path)
    }
    fn sync_dir(&self, point: Point, path: &Path) -> io::Result<()> {
        (**self).sync_dir(point, path)
    }
    fn rename_over(&self, point: Point, from: &Path, to: &Path) -> io::Result<()> {
        (**self).rename_over(point, from, to)
    }
    fn remove_file(&self, point: Point, path: &Path) -> io::Result<()> {
        (**self).remove_file(point, path)
    }
    fn remove_dir_all(&self, point: Point, path: &Path) -> io::Result<()> {
        (**self).remove_dir_all(point, path)
    }
}

/// The real file system, through `std` only.
///
/// **Windows:** there is no directory sync, so [`Fs::sync_dir`] does nothing there, and
/// [`Fs::rename_over`] flushes the renamed file after the rename. ADR-0014 §3.6 asks for a
/// write-through rename (`MOVEFILE_WRITE_THROUGH`), which needs an FFI call and so an
/// `unsafe` module; that is left to the integration (see the crate documentation).
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

fn open_for_sync(path: &Path) -> io::Result<File> {
    // Windows flushes only through a handle opened for writing.
    OpenOptions::new().write(true).open(path)
}

impl Fs for RealFs {
    fn kind(&self, path: &Path) -> io::Result<Kind> {
        match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_file() => Ok(Kind::File),
            Ok(m) if m.file_type().is_dir() => Ok(Kind::Dir),
            Ok(_) => Ok(Kind::Other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Kind::Missing),
            Err(e) => Err(e),
        }
    }
    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        File::open(path)?
            .take(limit.saturating_add(1))
            .read_to_end(&mut out)?;
        if out.len() as u64 > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "longer than the limit",
            ));
        }
        Ok(out)
    }
    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name().into_string();
            names.push(
                name.map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "a name is not UTF-8")
                })?,
            );
        }
        names.sort();
        Ok(names)
    }
    fn create_dir(&self, _: Point, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }
    fn write_new(&self, _: Point, path: &Path, bytes: &[u8]) -> io::Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(bytes)
    }
    fn append_sync(&self, _: Point, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().append(true).create(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
    fn truncate_sync(&self, _: Point, path: &Path, len: u64) -> io::Result<()> {
        let file = OpenOptions::new().write(true).open(path)?;
        file.set_len(len)?;
        file.sync_all()
    }
    fn sync_file(&self, _: Point, path: &Path) -> io::Result<()> {
        open_for_sync(path)?.sync_all()
    }
    #[cfg(unix)]
    fn sync_dir(&self, _: Point, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    fn sync_dir(&self, _: Point, _: &Path) -> io::Result<()> {
        Ok(())
    }
    fn rename_over(&self, _: Point, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)?;
        #[cfg(not(unix))]
        open_for_sync(to)?.sync_all()?;
        Ok(())
    }
    fn remove_file(&self, _: Point, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
    fn remove_dir_all(&self, _: Point, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
}

/// Whether a fault fires before the call is made or after it has been made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// The call is not made.
    Before,
    /// The call is made, then the fault fires.
    After,
}

/// What a fault does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The call returns an I/O error. The operation's own cleanup then runs.
    Error,
    /// The process is treated as stopped: this call and every later call through this
    /// value fail and do nothing, so no cleanup can run.
    Dead,
    /// Create this marker file and wait for ever, so that a parent process can kill this
    /// one at exactly this step.
    Park(PathBuf),
}

/// One fault: at the `nth` call (from 0) made at `point`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// The step.
    pub point: Point,
    /// Which call at that step, counted from 0.
    pub nth: u32,
    /// Before or after the call.
    pub when: When,
    /// What happens.
    pub action: Action,
}

/// A file system that fails or stops at one chosen step. Test support: it is in the crate
/// so that the fault tests and, later, the store's tests share it.
#[derive(Debug)]
pub struct FaultFs<F> {
    inner: F,
    fault: RefCell<Option<Fault>>,
    seen: RefCell<Vec<Point>>,
    dead: Cell<bool>,
    fired: Cell<bool>,
}

impl<F: Fs> FaultFs<F> {
    /// Wrap `inner` with one fault, or none.
    pub fn new(inner: F, fault: Option<Fault>) -> Self {
        Self {
            inner,
            fault: RefCell::new(fault),
            seen: RefCell::new(Vec::new()),
            dead: Cell::new(false),
            fired: Cell::new(false),
        }
    }

    /// Every mutating step attempted so far, in order.
    pub fn seen(&self) -> Vec<Point> {
        self.seen.borrow().clone()
    }

    /// Whether the fault fired.
    pub fn fired(&self) -> bool {
        self.fired.get()
    }

    fn stopped() -> io::Error {
        io::Error::other("fault: the process is stopped")
    }

    fn alive(&self) -> io::Result<()> {
        if self.dead.get() {
            Err(Self::stopped())
        } else {
            Ok(())
        }
    }

    fn fire(&self, action: &Action) -> io::Error {
        self.fired.set(true);
        match action {
            Action::Error => io::Error::other("fault: injected I/O error"),
            Action::Dead => {
                self.dead.set(true);
                Self::stopped()
            }
            Action::Park(marker) => {
                // The marker is written with std directly: it is the test's own file.
                let _ = fs::write(marker, b"parked\n");
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
        }
    }

    fn step(&self, point: Point, call: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        self.alive()?;
        let nth = self.seen.borrow().iter().filter(|p| **p == point).count() as u32;
        self.seen.borrow_mut().push(point);
        let hit = self
            .fault
            .borrow()
            .clone()
            .filter(|f| f.point == point && f.nth == nth);
        match hit {
            Some(f) if f.when == When::Before => Err(self.fire(&f.action)),
            Some(f) => {
                call()?;
                Err(self.fire(&f.action))
            }
            None => call(),
        }
    }
}

impl<F: Fs> Fs for FaultFs<F> {
    fn kind(&self, path: &Path) -> io::Result<Kind> {
        self.alive()?;
        self.inner.kind(path)
    }
    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        self.alive()?;
        self.inner.read(path, limit)
    }
    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        self.alive()?;
        self.inner.list(dir)
    }
    fn create_dir(&self, point: Point, path: &Path) -> io::Result<()> {
        self.step(point, || self.inner.create_dir(point, path))
    }
    fn write_new(&self, point: Point, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.step(point, || self.inner.write_new(point, path, bytes))
    }
    fn append_sync(&self, point: Point, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.step(point, || self.inner.append_sync(point, path, bytes))
    }
    fn truncate_sync(&self, point: Point, path: &Path, len: u64) -> io::Result<()> {
        self.step(point, || self.inner.truncate_sync(point, path, len))
    }
    fn sync_file(&self, point: Point, path: &Path) -> io::Result<()> {
        self.step(point, || self.inner.sync_file(point, path))
    }
    fn sync_dir(&self, point: Point, path: &Path) -> io::Result<()> {
        self.step(point, || self.inner.sync_dir(point, path))
    }
    fn rename_over(&self, point: Point, from: &Path, to: &Path) -> io::Result<()> {
        self.step(point, || self.inner.rename_over(point, from, to))
    }
    fn remove_file(&self, point: Point, path: &Path) -> io::Result<()> {
        self.step(point, || self.inner.remove_file(point, path))
    }
    fn remove_dir_all(&self, point: Point, path: &Path) -> io::Result<()> {
        self.step(point, || self.inner.remove_dir_all(point, path))
    }
}
