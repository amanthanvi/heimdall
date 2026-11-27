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
//!   served generation's directory and files are checked here before the store is opened.
//!   The entries must be owner-only (`platform::state_dir_acl::judge_inside`). Anything
//!   else is refused as `state_dir_unsafe` and never repaired.

use std::path::Path;
use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::EnvironmentId;
use heimdall_store::FaultHook;
use heimdall_store::layout::stategen::generations::{
    CURRENT, GENERATIONS, INTENT, MIGRATIONS, RECORD,
};
use heimdall_store::layout::stategen::{Fs, Kind, Point, RealFs, Startup, StateDir};
use heimdall_store::layout::{self, Opened};

use crate::platform::state_dir_acl::Verdict;
use crate::service::ServiceError;

type StateAclCheck<'a> = dyn Fn(&Path) -> std::io::Result<Verdict> + 'a;

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
    let check: Option<&StateAclCheck<'_>> =
        Some(&crate::platform::state_dir_acl::check_inside_owner_only);
    #[cfg(not(windows))]
    let check = None;
    open_locked_with_checks(state_dir, fs, faults, now, check)
}

fn open_locked_with_checks(
    state_dir: &Path,
    fs: &dyn Fs,
    faults: Arc<dyn FaultHook>,
    now: Timestamp,
    check: Option<&StateAclCheck<'_>>,
) -> Result<Opened, ServiceError> {
    if let Some(check) = check {
        check_state_entries(state_dir, fs, check)?;
    }
    let opened = layout::open_locked(state_dir, fs, faults, &new_environment, now)?;
    if let Some(check) = check {
        generation_dirs_owner_only(state_dir, &opened.current.dir, check)?;
    }
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

// --- ⟨M08 W4 U2b-3b; ADR-0014 §3.6, H3; ADR-0006 §19.4, U0-Q8⟩ restore, reset and repair ---------

/// ⟨M08 U2b-3b⟩ Check a restore before anything is written (read only):
/// [`heimdall_store::restore::plan_restore`] through [`PlatformFs`].
///
/// # Errors
/// As `plan_restore`.
pub fn plan_restore(
    state_dir: &Path,
    backup: &Path,
) -> Result<heimdall_store::restore::RestorePlan, heimdall_store::restore::RestoreError> {
    heimdall_store::restore::plan_restore(state_dir, &PlatformFs, backup)
}

/// ⟨M08 U2b-3b⟩ What a reset would orphan (read only):
/// [`heimdall_store::restore::reset_inventory`] through [`PlatformFs`].
///
/// # Errors
/// As `reset_inventory`.
pub fn reset_inventory(
    state_dir: &Path,
) -> Result<heimdall_store::restore::ResetInventory, heimdall_store::restore::RestoreError> {
    heimdall_store::restore::reset_inventory(state_dir, &PlatformFs)
}

/// ⟨M08 U2b-3b; ADR-0014 §3.6 "The restore protocol"⟩ **Restore** `backup` into `state_dir`,
/// under the runtime's instance lock, **which the caller holds** (taking it is the exclusion
/// of the protocol's item 2: a runtime holds it while it runs, and the issuer runs only as the
/// runtime's child), with the layout's calls through [`PlatformFs`] (its Windows rename is
/// write-through, H15) and the `state_restored` event through the application's publisher.
/// `retention` is the configured operation retention.
///
/// # Errors
/// As [`heimdall_store::restore::restore_locked`].
pub fn restore_locked(
    state_dir: &Path,
    backup: &Path,
    now: Timestamp,
    recovery_confirmed: bool,
    retention: std::time::Duration,
) -> Result<heimdall_store::restore::RestoreOutcome, heimdall_store::restore::RestoreError> {
    heimdall_store::restore::restore_locked(
        state_dir,
        &PlatformFs,
        &heimdall_store::restore::RestoreRequest {
            backup,
            now,
            recovery_confirmed,
            event: &heimdall_app::state_restore::RestoredEvent,
            operation_retention: retention,
        },
    )
}

/// ⟨M08 U2b-3b; ADR-0014 §3.6 "Reset is the same switch"⟩ **Reset** `state_dir` under the
/// runtime's instance lock, **which the caller holds**: a new, empty store with a new
/// environment ID (from the operating system's randomness) at epoch 0.
///
/// # Errors
/// As [`heimdall_store::restore::reset_locked`]; no randomness.
pub fn reset_locked(
    state_dir: &Path,
    now: Timestamp,
    recovery_confirmed: bool,
) -> Result<heimdall_store::restore::ResetOutcome, heimdall_store::restore::RestoreError> {
    let Some(environment) = new_environment() else {
        return Err(heimdall_store::StoreError::Corrupt(
            "operating system randomness is unavailable".to_owned(),
        )
        .into());
    };
    heimdall_store::restore::reset_locked(
        state_dir,
        &PlatformFs,
        &environment,
        now,
        recovery_confirmed,
    )
}

/// ⟨M08 U2b-3b; ADR-0006 §19.4, U0-Q8⟩ **Repair** the request ledger of `state_dir` under the
/// runtime's instance lock, **which the caller holds**: the current generation is opened as a
/// runtime's start opens it, then [`heimdall_store::restore::repair_locked`].
///
/// # Errors
/// The open's refusal (a damaged or newer store is a restore's or a reset's, not a repair's),
/// or the repair's.
pub fn repair_locked(
    state_dir: &Path,
    now: Timestamp,
) -> Result<heimdall_store::restore::RepairOutcome, heimdall_store::restore::RestoreError> {
    use heimdall_store::restore::RestoreError;
    let opened =
        open_locked(state_dir, Arc::new(heimdall_store::NoFaults), now).map_err(|e| match e {
            ServiceError::Store(s) => RestoreError::Store(s),
            other => RestoreError::Store(heimdall_store::StoreError::Corrupt(other.to_string())),
        })?;
    heimdall_store::restore::repair_locked(state_dir, &PlatformFs, &opened.store, now)
}

/// Check paths before reading the selector and before SQLite opens the selected family.
fn check_state_entries(
    root: &Path,
    fs: &dyn Fs,
    check: &StateAclCheck<'_>,
) -> Result<(), ServiceError> {
    for name in [CURRENT, INTENT] {
        check_state_file(fs, &root.join(name), check)?;
    }
    let state = StateDir::new(fs, root);
    match state.pointer() {
        Ok(Some(name)) => {
            let dir = state.generation_dir(&name);
            if matches!(fs.kind(&dir), Ok(Kind::Dir)) {
                generation_dirs_owner_only(root, &dir, check)?;
                for name in [RECORD, MIGRATIONS] {
                    check_state_file(fs, &dir.join(name), check)?;
                }
                check_database_family(fs, &dir, check)?;
                if let Ok(Startup::Serving(current)) = state.inspect() {
                    for name in &current.record.files {
                        if name != layout::DB_FILE {
                            check_state_file(fs, &dir.join(name), check)?;
                        }
                    }
                }
            }
        }
        Ok(None) => check_database_family(fs, root, check)?,
        // Layout startup retains its existing error for a malformed pointer.
        Err(_) => {}
    }
    Ok(())
}

fn check_database_family(
    fs: &dyn Fs,
    dir: &Path,
    check: &StateAclCheck<'_>,
) -> Result<(), ServiceError> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        check_state_file(fs, &dir.join(format!("{}{suffix}", layout::DB_FILE)), check)?;
    }
    Ok(())
}

fn check_state_file(
    fs: &dyn Fs,
    path: &Path,
    check: &StateAclCheck<'_>,
) -> Result<(), ServiceError> {
    match fs.kind(path) {
        Ok(Kind::Missing) => Ok(()),
        Ok(Kind::File) => require_owner_only(path, check),
        Ok(_) => Err(unsafe_state("a state file is not a regular file")),
        Err(_) => Err(unsafe_state("a state file could not be inspected")),
    }
}

fn generation_dirs_owner_only(
    state_dir: &Path,
    current: &Path,
    check: &StateAclCheck<'_>,
) -> Result<(), ServiceError> {
    let generations = state_dir.join(GENERATIONS);
    for dir in [generations.as_path(), current] {
        require_owner_only(dir, check)?;
    }
    Ok(())
}

fn require_owner_only(path: &Path, check: &StateAclCheck<'_>) -> Result<(), ServiceError> {
    let verdict = check(path)
        .map_err(|_| unsafe_state("a state entry's access-control list could not be read"))?;
    if verdict != Verdict::OwnerOnly {
        return Err(unsafe_state(verdict.describe()));
    }
    Ok(())
}

fn unsafe_state(message: &'static str) -> ServiceError {
    ServiceError::Config(crate::config::ConfigError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        crate::paths::StateDirUnsafe(message),
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use heimdall_store::layout::stategen::generations::CURRENT_TMP;
    use heimdall_store::layout::stategen::{Action, Fault, FaultFs, Operation, Point, When};
    use heimdall_store::layout::{Began, Located};
    use heimdall_store::{NoFaults, Store};

    use super::*;

    fn t0() -> Timestamp {
        "2026-11-25T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn served_state_files_require_owner_only_before_open() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::Paths::under(&dir.path().join("hh"));
        paths.ensure().unwrap();
        let state = paths.state_dir.as_path();
        let first = open_locked(state, Arc::new(NoFaults), t0()).unwrap();
        let db = first.db.clone();
        let record = first.current.dir.join(RECORD);
        drop(first);

        for path in [db, state.join(CURRENT), record, state.join(INTENT)] {
            let check = |candidate: &Path| {
                Ok(if candidate == path {
                    Verdict::ForeignAce
                } else {
                    Verdict::OwnerOnly
                })
            };
            let result =
                open_locked_with_checks(state, &PlatformFs, Arc::new(NoFaults), t0(), Some(&check));
            assert!(
                matches!(result, Err(ServiceError::Config(ref e)) if crate::paths::is_state_dir_unsafe(e)),
                "a served state file with a widened DACL was opened"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_widened_state_db_dacl_is_refused_before_sqlite_open() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::Paths::under(&dir.path().join("hh"));
        paths.ensure().unwrap();
        let state = paths.state_dir.as_path();
        let opened = open_locked(state, Arc::new(NoFaults), t0()).unwrap();
        let db = opened.db.clone();
        drop(opened);

        let status = std::process::Command::new("icacls.exe")
            .arg(&db)
            .args(["/grant", "*S-1-1-0:(R)"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "could not widen the fixture file DACL");
        let result = open_locked(state, Arc::new(NoFaults), t0());
        assert!(
            matches!(result, Err(ServiceError::Config(ref e)) if crate::paths::is_state_dir_unsafe(e)),
            "a state database with a widened DACL reached SQLite"
        );
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
