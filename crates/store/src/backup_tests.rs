//! ⟨M08 U2b-3b; S3-04, the early M09 review⟩ The pre-migration backup is written durably
//! before the migration changes the store: a temporary file, synced, renamed to its final
//! name, the directory synced. Each step is faulted through the layout's file system
//! (`heimdall_stategen::FaultFs`), the same seam as the generation switch's fault set.
//!
//! **Not established here:** durability across power loss. The faults are injected I/O
//! errors and an in-process stop; no power is cut.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use heimdall_stategen::{Action, Fault, FaultFs, Point, RealFs, When};

use super::*;

fn t0() -> Timestamp {
    "2026-11-27T00:00:00Z".parse().unwrap()
}

fn environment() -> EnvironmentId {
    EnvironmentId::from_random_bytes([3; 16])
}

/// A flat store one schema version behind this build, with its environment recorded.
fn seed_older_flat(root: &Path) -> u32 {
    let older = SCHEMA_VERSION - 1;
    let store =
        Store::open_at_schema_version(&root.join(layout::DB_FILE), Arc::new(NoFaults), older)
            .unwrap();
    store
        .transaction(|tx| tx.init_self_environment(&environment()))
        .unwrap();
    older
}

/// Every name in `dir` that begins with the database's and is not the family itself.
fn backups_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("state.db.") && !n.ends_with("-wal") && !n.ends_with("-shm"))
        .collect();
    names.sort();
    names
}

fn version_of(path: &Path) -> u32 {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    migrations::user_version(&conn).unwrap()
}

/// The served generation's directory, read from the pointer.
fn generation_dir(root: &Path) -> PathBuf {
    layout::pointed_generation(root).unwrap().unwrap()
}

/// `pre_migration_backup_is_durable_before_the_migration_at_each_step`: for a fault before
/// and after the backup's sync, its rename and its directory's sync, the open fails and the
/// generation's store is left at its old version (no migration ran without its backup);
/// nothing under a backup's name is partial (before the rename there is none; from the
/// rename on it is the complete copy); and the next start removes what an interrupted
/// backup left, writes a complete backup and migrates.
#[test]
fn pre_migration_backup_is_durable_before_the_migration_at_each_step() {
    let mut cases = 0;
    for point in [Point::BackupSync, Point::BackupRename, Point::BackupDirSync] {
        for when in [When::Before, When::After] {
            for action in [Action::Error, Action::Dead] {
                let case = format!("{point:?} {when:?} {action:?}");
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path();
                let older = seed_older_flat(root);
                let fs = FaultFs::new(
                    RealFs,
                    Some(Fault {
                        point,
                        nth: 0,
                        when,
                        action: action.clone(),
                    }),
                );
                let faulted = layout::open_locked(root, &fs, Arc::new(NoFaults), &|| None, t0());
                assert!(fs.fired(), "{case}: the step was reached");
                assert!(faulted.is_err(), "{case}: the open fails");
                drop(faulted);
                let generation = generation_dir(root);
                let db = generation.join(layout::DB_FILE);
                assert_eq!(version_of(&db), older, "{case}: no migration ran");
                let renamed = point == Point::BackupDirSync
                    || (point == Point::BackupRename && when == When::After);
                let final_name = format!("state.db.v{older}.backup");
                let found = backups_in(&generation);
                if renamed {
                    assert!(found.contains(&final_name), "{case}: {found:?}");
                    assert_eq!(
                        version_of(&generation.join(&final_name)),
                        older,
                        "{case}: the backup in place is complete"
                    );
                } else {
                    assert!(!found.contains(&final_name), "{case}: {found:?}");
                }
                // The restart: a leftover temporary file is removed, a complete backup is
                // written, and the store is migrated.
                let opened = layout::open_locked(root, &RealFs, Arc::new(NoFaults), &|| None, t0())
                    .unwrap_or_else(|e| panic!("{case}: the restart: {e}"));
                assert_eq!(opened.store.schema_version().unwrap(), SCHEMA_VERSION);
                drop(opened);
                let after = backups_in(&generation);
                assert!(
                    after.iter().all(|n| !n.ends_with(BACKUP_TEMP_SUFFIX)),
                    "{case}: the temporary file is gone: {after:?}"
                );
                let complete: Vec<&String> = after
                    .iter()
                    .filter(|n| n.starts_with(&final_name))
                    .collect();
                assert!(!complete.is_empty(), "{case}: {after:?}");
                for name in complete {
                    assert_eq!(
                        version_of(&generation.join(name)),
                        older,
                        "{case}: {name} is a complete backup at the old version"
                    );
                }
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 12);
}

/// The steps run in order: the sync, the rename and the directory's sync, all before the
/// first migration step's transaction.
#[test]
fn the_backup_is_synced_renamed_and_its_directory_synced_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    seed_older_flat(root);
    let fs = FaultFs::new(RealFs, None);
    let opened = layout::open_locked(root, &fs, Arc::new(NoFaults), &|| None, t0()).unwrap();
    drop(opened);
    let seen: Vec<Point> = fs
        .seen()
        .into_iter()
        .filter(|p| {
            matches!(
                p,
                Point::BackupSync | Point::BackupRename | Point::BackupDirSync
            )
        })
        .collect();
    assert_eq!(
        seen,
        vec![Point::BackupSync, Point::BackupRename, Point::BackupDirSync]
    );
}
