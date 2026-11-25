//! ⟨M08 U2b-1; ADR-0014 §3.6, deltas H12 and H15⟩ The runtime's store, through the generation
//! layout (`heimdall_store::layout`).
//!
//! * [`open_locked`] is the open of every writer that holds the runtime's instance lock:
//!   start-up ([`crate::Service`]) and the CLI's direct writes while no runtime runs. It
//!   serves the generation `CURRENT` names, adopts a flat store, or installs the first
//!   generation.
//! * [`PlatformFs`] makes the layout's file-system calls. Its rename is
//!   [`crate::platform::rename_replacing`]. On Windows that is the write-through
//!   `MoveFileExW` of delta H15, since Windows has no directory sync. Elsewhere it is
//!   `rename(2)`, followed by the layout's directory sync.
//! * **The Windows state-directory protection follows the pointer.** The state directory
//!   itself is checked by `Paths::ensure` (protected, owner-only). `generations/` and the
//!   served generation's directory are checked here, before the store is opened and again
//!   after a first publication. Both inherit the state directory's one owner-only entry
//!   (`platform::state_dir_acl::judge_inside`). Anything else is refused as
//!   `state_dir_unsafe` and never repaired.

use std::path::Path;
use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::EnvironmentId;
use heimdall_store::FaultHook;
use heimdall_store::layout::stategen::{Fs, Kind, Point, RealFs};
use heimdall_store::layout::{self, Opened};

use crate::service::ServiceError;

/// The layout's file system in production: `heimdall-stategen`'s [`RealFs`] for every call
/// but three. The rename is [`crate::platform::rename_replacing`] (write-through on
/// Windows). On Unix a directory is created `0700` and a file `0600`, as every Heimdall
/// directory is (`crate::paths`), so a generation passes the purge's secure-path check. On
/// Windows both inherit the protected state directory's owner-only entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformFs;

impl Fs for PlatformFs {
    fn kind(&self, path: &Path) -> std::io::Result<Kind> {
        RealFs.kind(path)
    }
    fn read(&self, path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
        RealFs.read(path, limit)
    }
    fn list(&self, dir: &Path) -> std::io::Result<Vec<String>> {
        RealFs.list(dir)
    }
    fn create_dir(&self, point: Point, path: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            let _ = point;
            std::fs::DirBuilder::new().mode(0o700).create(path)
        }
        #[cfg(not(unix))]
        {
            RealFs.create_dir(point, path)
        }
    }
    fn write_new(&self, _point: Point, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        owner_only_options()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(bytes)
    }
    fn append_sync(&self, _point: Point, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        let mut file = owner_only_options().append(true).create(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
    fn truncate_sync(&self, point: Point, path: &Path, len: u64) -> std::io::Result<()> {
        RealFs.truncate_sync(point, path, len)
    }
    fn sync_file(&self, point: Point, path: &Path) -> std::io::Result<()> {
        RealFs.sync_file(point, path)
    }
    fn sync_dir(&self, point: Point, path: &Path) -> std::io::Result<()> {
        RealFs.sync_dir(point, path)
    }
    fn rename_over(&self, _point: Point, from: &Path, to: &Path) -> std::io::Result<()> {
        crate::platform::rename_replacing(from, to)
    }
    fn remove_file(&self, point: Point, path: &Path) -> std::io::Result<()> {
        RealFs.remove_file(point, path)
    }
    fn remove_dir_all(&self, point: Point, path: &Path) -> std::io::Result<()> {
        RealFs.remove_dir_all(point, path)
    }
}

/// Open the store of `state_dir` under the runtime's instance lock, **which the caller
/// holds** ([`layout::open_locked`] with [`PlatformFs`]). A new installation's environment
/// ID is minted from the operating system's randomness.
///
/// # Errors
/// The layout's or the store's refusal ([`ServiceError::Store`]). On Windows, a
/// generation directory that is not owner-only is [`ServiceError::Config`]
/// (`state_dir_unsafe`).
pub fn open_locked(
    state_dir: &Path,
    faults: Arc<dyn FaultHook>,
    now: Timestamp,
) -> Result<Opened, ServiceError> {
    open_locked_with(state_dir, &PlatformFs, faults, now)
}

/// [`open_locked`] with another file system (the fault tests' `FaultFs` around [`PlatformFs`]).
///
/// # Errors
/// As [`open_locked`].
pub fn open_locked_with(
    state_dir: &Path,
    fs: &dyn Fs,
    faults: Arc<dyn FaultHook>,
    now: Timestamp,
) -> Result<Opened, ServiceError> {
    #[cfg(windows)]
    if let Ok(layout::Located::Generation { current, .. }) = layout::locate(state_dir) {
        windows_generation_dirs_owner_only(state_dir, &current.dir)?;
    }
    let opened = layout::open_locked(state_dir, fs, faults, &new_environment, now)?;
    #[cfg(windows)]
    windows_generation_dirs_owner_only(state_dir, &opened.current.dir)?;
    Ok(opened)
}

/// File options that create a file owner-only (`0600` on Unix; Windows inherits the state
/// directory's entry).
fn owner_only_options() -> std::fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = std::fs::OpenOptions::new();
        options.mode(0o600);
        options
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
    }
}

fn new_environment() -> Option<EnvironmentId> {
    heimdall_app::ids::new_environment_id().ok()
}

/// `generations/` and the generation directory `current` are owner-only, as inherited from
/// the protected state directory (module docs).
#[cfg(windows)]
fn windows_generation_dirs_owner_only(
    state_dir: &Path,
    current: &Path,
) -> Result<(), ServiceError> {
    use crate::platform::state_dir_acl::{Verdict, check_inside_owner_only};
    let generations = state_dir.join(layout::stategen::generations::GENERATIONS);
    for dir in [generations.as_path(), current] {
        let verdict = check_inside_owner_only(dir).map_err(crate::config::ConfigError::from)?;
        if verdict != Verdict::OwnerOnly {
            return Err(ServiceError::Config(crate::config::ConfigError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    crate::paths::StateDirUnsafe(verdict.describe()),
                ),
            )));
        }
    }
    Ok(())
}
