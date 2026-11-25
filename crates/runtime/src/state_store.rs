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

/// [`open_locked`] with another file system: the switch-fault case's `FaultFs` around
/// [`PlatformFs`] (review W3-R03; `tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation`).
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use heimdall_store::layout::stategen::generations::{CURRENT_TMP, GENERATIONS, INTENT};
    use heimdall_store::layout::stategen::{Action, Fault, FaultFs, Operation, Point, When};
    use heimdall_store::layout::{Began, Located};
    use heimdall_store::{NoFaults, Store};

    use super::*;

    fn t0() -> Timestamp {
        "2026-11-25T00:00:00Z".parse().unwrap()
    }

    /// The generation the pointer names, if any (read only).
    fn pointed(state_dir: &Path) -> Option<String> {
        match layout::locate(state_dir).unwrap() {
            Located::Generation { current, .. } => Some(current.name.as_str().to_owned()),
            Located::Flat(_) => None,
        }
    }

    fn generations(state_dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = match std::fs::read_dir(state_dir.join(GENERATIONS)) {
            Ok(rd) => rd
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    /// ⟨review W3-R03; ADR-0014 §3.6 "Platforms", delta H15⟩ The switch's pointer rename
    /// through the production file system ([`PlatformFs`]) under a fault, through
    /// [`open_locked_with`]. On Windows that rename is
    /// `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`
    /// (`crate::platform::rename_replacing`); elsewhere it is `rename(2)`.
    ///
    /// The cases are a first install and an adoption of a flat store. In each, `FaultFs`
    /// around `PlatformFs` fails or stops the process at the rename of the temporary pointer
    /// over `CURRENT`, before the call or after it is made. The restart is `open_locked`
    /// through `PlatformFs` alone. It serves only the generation the pointer names: the
    /// faulted attempt's when its rename was made, and otherwise the first publication run
    /// again. The staged leftover and the temporary pointer are gone, and the intent is
    /// complete.
    ///
    /// The `After` cases make the write-through rename and then fault; the restart's own
    /// renames are the ordinary path. The rename of the completed intent replaces an
    /// existing file. No power is cut, so durability across power loss is not established
    /// here.
    #[test]
    fn platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation() {
        let environment = EnvironmentId::from_random_bytes([1; 16]);
        let mut cases = 0;
        for adopt in [false, true] {
            for when in [When::Before, When::After] {
                for action in [Action::Error, Action::Dead] {
                    let case = format!("adopt {adopt}, {when:?}, {action:?}");
                    let dir = tempfile::tempdir().unwrap();
                    // `Paths::ensure`, so the state directory is protected on Windows and the
                    // generation directories inherit its owner-only entry.
                    let paths = crate::Paths::under(&dir.path().join("hh"));
                    paths.ensure().unwrap();
                    let state = paths.state_dir.as_path();
                    if adopt {
                        let flat =
                            Store::open(&state.join(layout::DB_FILE), Arc::new(NoFaults)).unwrap();
                        flat.transaction(|tx| tx.init_self_environment(&environment))
                            .unwrap();
                    }
                    let fs = FaultFs::new(
                        PlatformFs,
                        Some(Fault {
                            point: Point::PointerRename,
                            nth: 0,
                            when,
                            action: action.clone(),
                        }),
                    );
                    let faulted = open_locked_with(state, &fs, Arc::new(NoFaults), t0());
                    assert!(fs.fired(), "{case}: the rename was reached");
                    assert!(faulted.is_err(), "{case}: the fault is reported");
                    drop(faulted);
                    let named = pointed(state);
                    assert_eq!(
                        named.is_some(),
                        when == When::After,
                        "{case}: only the rename makes a generation current"
                    );

                    let opened = open_locked(state, Arc::new(NoFaults), t0())
                        .unwrap_or_else(|e| panic!("{case}: the restart: {e}"));
                    let served = opened.current.name.as_str().to_owned();
                    match &named {
                        Some(name) => {
                            assert_eq!(&served, name, "{case}: the pointer's generation");
                            assert_eq!(opened.began, Began::Served, "{case}");
                        }
                        None => assert!(
                            matches!(
                                (adopt, opened.began),
                                (false, Began::Installed) | (true, Began::Adopted { .. })
                            ),
                            "{case}: the first publication is run again: {:?}",
                            opened.began
                        ),
                    }
                    assert_eq!(pointed(state), Some(served.clone()), "{case}");
                    assert_eq!(
                        generations(state),
                        vec![served.clone()],
                        "{case}: only the pointer's generation is left"
                    );
                    assert!(
                        !state.join(CURRENT_TMP).exists(),
                        "{case}: the temporary pointer is left"
                    );
                    let intent = std::fs::read_to_string(state.join(INTENT)).unwrap();
                    assert!(intent.contains(r#""state":"complete""#), "{case}: {intent}");
                    let operation = if adopt {
                        Operation::Adopt
                    } else {
                        Operation::Install
                    };
                    assert_eq!(opened.current.record.operation, operation, "{case}");
                    if adopt {
                        assert_eq!(
                            opened
                                .store
                                .transaction(|tx| tx.self_environment())
                                .unwrap(),
                            Some(environment.clone()),
                            "{case}: the adopted store is served"
                        );
                    }
                    drop(opened);
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 8);
    }
}
