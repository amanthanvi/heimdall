//! ⟨M08 U2b-1⟩ The generation layout of the real store (ADR-0014 §3.6, delta H12): the
//! pointer switch of a first installation and of an adoption, the pointer as the only
//! authority, the adoption's fence-first order against an older build, and copies that go
//! through SQLite. Real SQLite stores in scratch directories, through
//! `heimdall_store::layout::open_locked`, the runtime's start-up open.
//!
//! **Three kinds of fault:**
//! - an injected I/O error, after which the operation's own cleanup runs;
//! - an in-process stop: no later call does anything, so no cleanup runs;
//! - a real kill of a child process (this test binary, re-run) parked at the step.
//!
//! **No test cuts power:** durability across power loss is not established here.
//!
//! **The switches of this slice.** They are the first publications: an install and an
//! adoption. A restore's and a reset's switch between two generations is exercised on a
//! stand-in store by `adversarial_stategen_switch_faults`, and reaches the real store with
//! the restore (U2b-3).
//!
//! **What is modelled (ruled 2026-11-24):** the "older build" is today's flat-layout open,
//! `Store::open_at_schema_version(<state>/state.db, …, 13)`. That is the store as the M06
//! exit build (schema 13) opens it, and it knows no generations and no fence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_contract::ids::{EnvironmentId, GrantId};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::revocation::Tombstone;
use heimdall_store::layout::stategen::generations::{
    CURRENT, CURRENT_TMP, GENERATIONS, INTENT, INTENT_TMP, MIGRATIONS, RECORD,
};
use heimdall_store::layout::stategen::{
    Action, CorruptReason, Fault, FaultFs, Fs, GenerationName, Operation, Plan, Point, RealFs,
    StateDir, When,
};
use heimdall_store::layout::{self, Began, Located, Opened};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, NoFaults, Store, StoreError};

/// The schema of the "older build" (the M06 exit build's).
const OLDER: u32 = 13;

fn t0() -> jiff::Timestamp {
    "2026-11-24T00:00:00Z".parse().unwrap()
}

fn env(n: u8) -> EnvironmentId {
    EnvironmentId::from_random_bytes([n; 16])
}

fn grant(n: u8) -> GrantId {
    GrantId::from_random_bytes([n; 16])
}

fn tombstone(n: u8) -> Tombstone {
    Tombstone {
        grant: grant(n),
        cascade: Vec::new(),
        generation: AuthorityGeneration(0),
        revoked_at: t0(),
        remote_pending: Vec::new(),
        cause: Default::default(),
    }
}

fn flat(root: &Path) -> PathBuf {
    root.join(layout::DB_FILE)
}

/// The newer build's start-up (this build): `open_locked` through `fs`.
fn start(root: &Path, fs: &dyn Fs) -> Result<Opened, StoreError> {
    layout::open_locked(root, fs, Arc::new(NoFaults), &|| Some(env(9)), t0())
}

fn start_real(root: &Path) -> Opened {
    start(root, &RealFs).unwrap_or_else(|e| panic!("start-up: {e}"))
}

/// The older build: today's flat open at schema 13. Before the fence it serves the flat
/// store and records a revocation; after it, it refuses.
fn older_build_revokes(root: &Path, n: u8) -> Result<(), StoreError> {
    let store = Store::open_at_schema_version(&flat(root), Arc::new(NoFaults), OLDER)?;
    store.transaction(|tx| tx.insert_tombstone(&tombstone(n)).map(drop))
}

/// A flat store as the older build left it: schema 13, environment 1, one revocation.
fn seed_flat(root: &Path) {
    let store = Store::open_at_schema_version(&flat(root), Arc::new(NoFaults), OLDER).unwrap();
    store
        .transaction(|tx| {
            tx.init_self_environment(&env(1))?;
            tx.insert_tombstone(&tombstone(1)).map(drop)
        })
        .unwrap();
}

fn has_tombstone(store: &Store, n: u8) -> bool {
    store
        .transaction(|tx| tx.tombstone(&grant(n)))
        .unwrap()
        .is_some()
}

/// Every file under `dir`, by relative path.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(base, &path, out);
            } else {
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn generations(root: &Path) -> Vec<String> {
    match std::fs::read_dir(root.join(GENERATIONS)) {
        Ok(rd) => {
            let mut names: Vec<String> = rd
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
        Err(_) => Vec::new(),
    }
}

/// The generation the pointer names now, if any (read only).
fn published(root: &Path) -> Option<String> {
    match layout::locate(root).unwrap() {
        Located::Generation { current, .. } => Some(current.name.as_str().to_owned()),
        Located::Flat(_) => None,
    }
}

/// The six steps ADR-0014 §3.6 names for the switch.
const ADR_POINTS: [Point; 6] = [
    Point::StagedFileSync,
    Point::RecordSync,
    Point::GenerationDirSync,
    Point::TempPointerSync,
    Point::PointerRename,
    Point::StateDirSync,
];

fn new_is_current(point: Point, when: When) -> bool {
    matches!(
        (point, when),
        (Point::PointerRename, When::After) | (Point::StateDirSync, _)
    )
}

/// The first publication a case runs: an install (empty state directory) or an adoption
/// (a flat store as the older build left it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum First {
    Install,
    Adopt,
}

fn prepare(first: First) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    if first == First::Adopt {
        seed_flat(dir.path());
    }
    dir
}

/// After a restart: one complete generation, served; the staged leftover and every temporary
/// file removed; the intent complete; for an adoption, nothing the older build wrote is
/// missing and the flat family is fenced. `published_first` is the faulted attempt's
/// generation when its rename had happened.
fn check_after_restart(root: &Path, first: First, published_first: Option<&str>, case: &str) {
    let opened = start_real(root);
    let served = opened.current.name.as_str().to_owned();
    match published_first {
        Some(name) => {
            assert_eq!(served, name, "{case}: the published generation is served");
            assert_eq!(opened.began, Began::Served, "{case}");
        }
        None => assert!(
            matches!(
                (first, opened.began),
                (First::Install, Began::Installed)
                    | (
                        First::Adopt,
                        Began::Adopted {
                            schema_version: OLDER
                        }
                    )
            ),
            "{case}: the first publication is run again: {:?}",
            opened.began
        ),
    }
    assert_eq!(
        generations(root),
        vec![served.clone()],
        "{case}: one generation, no staged leftover"
    );
    assert!(
        !root.join(CURRENT_TMP).exists() && !root.join(INTENT_TMP).exists(),
        "{case}: no temporary file is left"
    );
    let intent = std::fs::read_to_string(root.join(INTENT)).unwrap();
    assert!(intent.contains(r#""state":"complete""#), "{case}: {intent}");
    let record = opened.current.record.clone();
    assert_eq!(record.files, vec![layout::DB_FILE.to_owned()], "{case}");
    assert_eq!(
        opened
            .store
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .map(|e| e.as_str().to_owned()),
        Some(record.environment_id.clone()),
        "{case}: the record names the store's environment"
    );
    assert_eq!(
        opened.store.schema_version().unwrap(),
        heimdall_store::SCHEMA_VERSION,
        "{case}: migrated in place"
    );
    match first {
        First::Install => {
            assert_eq!(record.operation, Operation::Install, "{case}");
            assert!(
                !flat(root).exists(),
                "{case}: an install writes no flat store"
            );
        }
        First::Adopt => {
            assert_eq!(record.operation, Operation::Adopt, "{case}");
            assert_eq!(record.environment_id, env(1).as_str(), "{case}");
            assert!(
                has_tombstone(&opened.store, 1),
                "{case}: the revocation is kept"
            );
            assert!(
                matches!(
                    older_build_revokes(root, 5),
                    Err(StoreError::NewerSchema { .. })
                ),
                "{case}: the flat family is fenced for the older build"
            );
        }
    }
    drop(opened);
    // A second start-up serves the same generation and finds nothing to do.
    let again = start_real(root);
    assert_eq!(again.current.name.as_str(), served, "{case}");
    assert_eq!(again.began, Began::Served, "{case}");
    assert_eq!(again.current.recovered, Default::default(), "{case}");
}

#[test]
fn switch_interrupted_before_and_after_each_sync_and_the_rename() {
    let mut cases = 0;
    for first in [First::Install, First::Adopt] {
        for point in ADR_POINTS {
            for when in [When::Before, When::After] {
                for action in [Action::Error, Action::Dead] {
                    let case = format!("{first:?} {point:?} {when:?} {action:?}");
                    let dir = prepare(first);
                    let fs = FaultFs::new(
                        RealFs,
                        Some(Fault {
                            point,
                            nth: 0,
                            when,
                            action,
                        }),
                    );
                    let result = start(dir.path(), &fs);
                    assert!(fs.fired(), "{case}: the step was reached");
                    assert!(result.is_err(), "{case}: the failure is reported");
                    let published_first = published(dir.path());
                    assert_eq!(
                        published_first.is_some(),
                        new_is_current(point, when),
                        "{case}: only the rename makes the new generation current"
                    );
                    check_after_restart(dir.path(), first, published_first.as_deref(), &case);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 2 * 6 * 2 * 2);

    // The same steps with a real kill: a child process parks at the step and is killed.
    for first in [First::Install, First::Adopt] {
        for (index, point) in ADR_POINTS.into_iter().enumerate() {
            for when in [When::Before, When::After] {
                let case = format!("kill {first:?} {point:?} {when:?}");
                let dir = prepare(first);
                let mode = match first {
                    First::Install => "install",
                    First::Adopt => "adopt",
                };
                kill_child_at(
                    dir.path(),
                    &format!("{index}|0|{}|{mode}", when_word(when)),
                    &case,
                );
                let published_first = published(dir.path());
                assert_eq!(
                    published_first.is_some(),
                    new_is_current(point, when),
                    "{case}"
                );
                check_after_restart(dir.path(), first, published_first.as_deref(), &case);
            }
        }
    }
}

// ---- A real kill: this binary, re-run as a child that parks at one step. ----

const CHILD_ENV: &str = "HM_STORE_GENERATIONS_CHILD";

fn when_word(when: When) -> &'static str {
    if when == When::Before {
        "before"
    } else {
        "after"
    }
}

/// Every step a child can park at, by index (the six of the switch first).
const CHILD_POINTS: [Point; 10] = [
    Point::StagedFileSync,
    Point::RecordSync,
    Point::GenerationDirSync,
    Point::TempPointerSync,
    Point::PointerRename,
    Point::StateDirSync,
    Point::IntentDirSync,
    Point::GenerationCreate,
    Point::MigrationAppend,
    Point::IntentSync,
];

/// Run the child with `spec` (`<point index>|<nth>|<before|after>|<mode>`) against `root`,
/// wait until it parks at the step, and kill it.
fn kill_child_at(root: &Path, spec: &str, case: &str) {
    let exe = std::env::current_exe().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let marker = scratch.path().join("parked");
    let mut child = std::process::Command::new(&exe)
        .args(["--exact", "child_start", "--nocapture", "--test-threads=1"])
        .env(
            CHILD_ENV,
            format!("{}|{}|{spec}", root.display(), marker.display()),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !marker.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "{case}: the child ended before the step"
        );
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "{case}: the child never reached the step"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Crash (abort) right after the first explicit transaction commits.
struct CrashAfterCommit;

impl FaultHook for CrashAfterCommit {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point == FaultPoint::AfterCommit {
            FaultAction::Crash
        } else {
            FaultAction::Continue
        }
    }
}

/// Not a test of its own: the child half of the kill cases. Without the variable it does
/// nothing.
#[test]
fn child_start() {
    let Some(spec) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let spec = spec.into_string().unwrap();
    let parts: Vec<&str> = spec.split('|').collect();
    let (root, marker) = (PathBuf::from(parts[0]), PathBuf::from(parts[1]));
    if parts[2] == "seed-wal" {
        // A flat store whose only copy of a revocation is in its write-ahead log: the
        // transaction commits and the process aborts before any checkpoint.
        let store =
            Store::open_at_schema_version(&flat(&root), Arc::new(CrashAfterCommit), OLDER).unwrap();
        let _ = std::fs::write(&marker, b"opened\n");
        let _ = store.transaction(|tx| {
            tx.init_self_environment(&env(1))?;
            tx.insert_tombstone(&tombstone(3)).map(drop)
        });
        std::process::exit(3);
    }
    let point = CHILD_POINTS[parts[2].parse::<usize>().unwrap()];
    let nth = parts[3].parse::<u32>().unwrap();
    let when = if parts[4] == "before" {
        When::Before
    } else {
        When::After
    };
    let fs = FaultFs::new(
        RealFs,
        Some(Fault {
            point,
            nth,
            when,
            action: Action::Park(marker),
        }),
    );
    let _ = start(&root, &fs);
    // Reached only if the step was never made: the parent then times out and fails.
    std::process::exit(3);
}

// ---- The pointer is the only authority. ----

/// Two complete generations of the real store: `A` (adopted, earlier) and `B` (current, a
/// copy of `A` staged through SQLite as a restore will stage one). Returns their directories.
fn two_generations(root: &Path) -> (PathBuf, PathBuf) {
    seed_flat(root);
    let a = start_real(root);
    let a_db = a.db.clone();
    let a_dir = a.current.dir.clone();
    let env_a = a.current.record.environment_id.clone();
    drop(a);
    let state = StateDir::new(RealFs, root);
    let b = state
        .publish(
            Plan {
                name: GenerationName::parse("g-b").unwrap(),
                operation: Operation::Restore,
                created_at: t0(),
                backup_sha256: Some("ab".repeat(32)),
                environment_id: env_a,
                restore_epoch: 1,
            },
            |dir: &Path| -> Result<Vec<String>, StoreError> {
                Store::open_read_only(&a_db, Arc::new(NoFaults))?
                    .vacuum_into(&dir.join(layout::DB_FILE))?;
                Ok(vec![layout::DB_FILE.to_owned()])
            },
        )
        .unwrap();
    assert_eq!(start_real(root).current.name, b.name);
    (a_dir, b.dir)
}

#[test]
fn unreadable_or_dangling_pointer_stops_and_never_picks_another_generation() {
    type Damage = fn(&Path, &Path, &Path);
    let cases: Vec<(&str, CorruptReason, Damage)> = vec![
        (
            "pointer is not a pointer",
            CorruptReason::PointerMalformed,
            |r, _, _| std::fs::write(r.join(CURRENT), b"g-b\n").unwrap(),
        ),
        (
            "pointer is empty",
            CorruptReason::PointerMalformed,
            |r, _, _| std::fs::write(r.join(CURRENT), b"").unwrap(),
        ),
        (
            "pointer is cut",
            CorruptReason::PointerMalformed,
            |r, _, _| std::fs::write(r.join(CURRENT), b"heimdall-current/1\ng-b").unwrap(),
        ),
        (
            "pointer names a path",
            CorruptReason::PointerMalformed,
            |r, _, _| {
                std::fs::write(r.join(CURRENT), b"heimdall-current/1\n../state.db\n").unwrap()
            },
        ),
        (
            "pointer names a missing generation",
            CorruptReason::GenerationMissing,
            |r, _, _| std::fs::write(r.join(CURRENT), b"heimdall-current/1\ng-zz\n").unwrap(),
        ),
        (
            "pointer is a directory",
            CorruptReason::PointerUnreadable,
            |r, _, _| {
                std::fs::remove_file(r.join(CURRENT)).unwrap();
                std::fs::create_dir(r.join(CURRENT)).unwrap();
            },
        ),
        (
            "pointer is gone",
            CorruptReason::PointerMissing,
            |r, _, _| std::fs::remove_file(r.join(CURRENT)).unwrap(),
        ),
        (
            "the generation has no record",
            CorruptReason::RecordMissing,
            |_, _, b| std::fs::remove_file(b.join(RECORD)).unwrap(),
        ),
        (
            "the record is cut",
            CorruptReason::RecordDamaged,
            |_, _, b| {
                let bytes = std::fs::read(b.join(RECORD)).unwrap();
                std::fs::write(b.join(RECORD), &bytes[..bytes.len() - 9]).unwrap();
            },
        ),
        (
            "the record is another generation's",
            CorruptReason::RecordDamaged,
            |_, a, b| {
                std::fs::copy(a.join(RECORD), b.join(RECORD)).unwrap();
            },
        ),
        (
            "the database is gone",
            CorruptReason::FileMissing,
            |_, _, b| std::fs::remove_file(b.join(layout::DB_FILE)).unwrap(),
        ),
        #[cfg(unix)]
        (
            "pointer is a symbolic link",
            CorruptReason::PointerUnreadable,
            |r, _, _| {
                std::fs::rename(r.join(CURRENT), r.join("elsewhere")).unwrap();
                std::os::unix::fs::symlink(r.join("elsewhere"), r.join(CURRENT)).unwrap();
            },
        ),
    ];
    for (case, reason, damage) in cases {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (a, b) = two_generations(root);
        damage(root, &a, &b);
        let before = snapshot(root);
        let corrupt = format!("state_corrupt: {}", reason.code());
        let is_corrupt = |e: &StoreError| matches!(e, StoreError::Corrupt(m) if *m == corrupt);
        // Readers and start-up both stop; neither falls back to `A`, nor to the flat family
        // (fenced residue that the older build's data still sits in).
        match layout::db_path(root) {
            Err(e) => assert!(is_corrupt(&e), "{case}: {e}"),
            Ok(p) => panic!("{case}: a reader was given {}", p.display()),
        }
        match start(root, &RealFs) {
            Err(e) => assert!(is_corrupt(&e), "{case}: {e}"),
            Ok(o) => panic!("{case}: start-up served {}", o.current.name.as_str()),
        }
        assert_eq!(
            snapshot(root),
            before,
            "{case}: nothing was written, removed or opened (no log appeared anywhere)"
        );
    }
}

// ---- Adoption: fence first, then publish. ----

#[test]
fn adoption_killed_at_each_step_then_older_build_then_newer_build() {
    // (the case, the child's park point as "<index>|<nth>|<before|after>", fenced by then).
    let stops: [(&str, &str, bool); 7] = [
        ("before the intent", "9|0|before", false),
        ("after the intent, before the fence", "6|0|after", false),
        ("after the fence, before the copy", "7|0|before", true),
        ("after the copy, before the publication", "4|0|before", true),
        (
            "after the publication, before the completion",
            "4|0|after",
            true,
        ),
        // Completed; the generation's first start has not noted its baseline yet.
        ("after the completion", "8|0|before", true),
        // Completed and migrated in place (13 to 14); the migration's note is not written.
        ("after the completion and the migration", "8|1|before", true),
    ];
    for (case, park, fenced) in stops {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed_flat(root);

        // The newer build starts and is killed at the step.
        kill_child_at(root, &format!("{park}|adopt"), case);
        let published_first = published(root);

        // The rollback: the older build is started.
        let before_older = snapshot(root);
        let older = older_build_revokes(root, 2);
        if fenced {
            assert!(
                matches!(older, Err(StoreError::NewerSchema { .. })),
                "{case}: after the fence the older build refuses: {older:?}"
            );
            assert_eq!(snapshot(root), before_older, "{case}: and writes nothing");
        } else {
            assert!(
                older.is_ok(),
                "{case}: before the fence the older build serves the flat store: {older:?}"
            );
        }

        // The newer build is started again: it adopts, or resumes, or serves.
        let opened = start_real(root);
        if let Some(name) = &published_first {
            assert_eq!(opened.current.name.as_str(), name, "{case}");
        }
        assert_eq!(opened.current.record.operation, Operation::Adopt, "{case}");
        // Nothing the older build knew is missing, and no revocation is lost.
        assert!(
            has_tombstone(&opened.store, 1),
            "{case}: the revocation before the update"
        );
        assert_eq!(
            has_tombstone(&opened.store, 2),
            !fenced,
            "{case}: the older build's revocation is adopted exactly when it could make it"
        );
        assert_eq!(
            generations(root),
            vec![opened.current.name.as_str().to_owned()],
            "{case}"
        );
        assert!(
            !root.join(CURRENT_TMP).exists() && !root.join(INTENT_TMP).exists(),
            "{case}"
        );
        // The migration ran inside the generation, and the notes say so even when a kill
        // lost the note (rebuilt from the database's version).
        let notes = std::fs::read_to_string(opened.current.dir.join(MIGRATIONS)).unwrap();
        let pairs: Vec<(String, String)> = notes
            .lines()
            .map(|l| {
                let mut f = l.split(' ');
                (f.next().unwrap().to_owned(), f.next().unwrap().to_owned())
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("13".to_owned(), "13".to_owned()),
                ("13".to_owned(), "14".to_owned())
            ],
            "{case}: {notes}"
        );
        drop(opened);
        // The flat family is fenced, never moved and never served again.
        assert!(flat(root).exists(), "{case}");
        assert!(
            matches!(
                older_build_revokes(root, 4),
                Err(StoreError::NewerSchema { .. })
            ),
            "{case}"
        );
        assert!(
            matches!(
                Store::open(&flat(root), Arc::new(NoFaults)),
                Err(StoreError::AdoptionFenced)
            ),
            "{case}: this build never opens the fenced family as a store"
        );
        // And adoption does not run twice.
        let again = start_real(root);
        assert_eq!(again.began, Began::Served, "{case}");
    }
}

// ---- Every copy goes through SQLite. ----

#[test]
fn no_store_copy_reads_the_main_file_alone() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // A flat store at schema 13 whose revocation exists only in its write-ahead log: the
    // child commits it and aborts before any checkpoint.
    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new(&exe)
        .args(["--exact", "child_start", "--nocapture", "--test-threads=1"])
        .env(
            CHILD_ENV,
            format!(
                "{}|{}|seed-wal",
                root.display(),
                root.join("opened").display()
            ),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "the child aborted after its commit");
    let _ = std::fs::remove_file(root.join("opened"));
    let wal = root.join(format!("{}-wal", layout::DB_FILE));
    assert!(
        std::fs::metadata(&wal).unwrap().len() > 0,
        "the state is in the write-ahead log"
    );
    // The premise: the main file alone does not hold it.
    let scratch = tempfile::tempdir().unwrap();
    let alone = scratch.path().join("main-file-alone.db");
    std::fs::copy(flat(root), &alone).unwrap();
    let main_alone_has_it = Store::open_at_schema_version(&alone, Arc::new(NoFaults), OLDER)
        .ok()
        .is_some_and(|s| {
            s.transaction(|tx| tx.tombstone(&grant(3)))
                .ok()
                .flatten()
                .is_some()
        });
    assert!(
        !main_alone_has_it,
        "the main file alone lacks the revocation"
    );

    // The adoption copy sees it, and so does the migration backup inside the generation.
    let opened = start_real(root);
    assert_eq!(
        opened.began,
        Began::Adopted {
            schema_version: OLDER
        }
    );
    assert!(has_tombstone(&opened.store, 3), "the adoption copy");
    let backup = opened
        .current
        .dir
        .join(format!("{}.v13.backup", layout::DB_FILE));
    assert!(
        backup.exists(),
        "the migration in place wrote its backup in the generation"
    );
    let copy = scratch.path().join("backup-copy.db");
    std::fs::copy(&backup, &copy).unwrap();
    let in_backup = Store::open_at_schema_version(&copy, Arc::new(NoFaults), OLDER).unwrap();
    assert!(has_tombstone(&in_backup, 3), "the migration backup");
}

// ---- The regression guard of the tests/** grant (2026-11-24). ----

/// No Rust source under `tests/` builds the state database's path by hand (`<state>/state.db`,
/// or `STATE_DB_FILE` joined to a state directory): each reaches the store through
/// `heimdall_store::layout::db_path`, which follows the pointer. A scratch store that is
/// not a home's (a temporary directory's own `state.db`) is listed, by exact line, as
/// allowed.
#[test]
fn no_test_builds_the_state_database_path_by_hand() {
    // (file, exact code line with whitespace removed, why it is not a path to a home's store).
    const ALLOWED: &[(&str, &str, &str)] = &[
        (
            "tests/e2e/exit_m03/scan.rs",
            ".is_some_and(|n|n.to_string_lossy().starts_with(\"state.db\"))",
            "a file-name match inside a canary scan; it builds no path",
        ),
        (
            "tests/e2e/harness_m07.rs",
            "\"state.db\",",
            "a word the harness sources must never contain; it builds no path",
        ),
        (
            "tests/adversarial/issuer_reservation_replay.rs",
            "letdb=dir.path().join(\"state.db\");",
            "a scratch store in a temporary directory's root: no home, no layout (U1b, merged after U2b-1)",
        ),
        (
            "tests/integration/issuer_child.rs",
            "letdb=dir.path().join(\"state.db\");",
            "a scratch store in a temporary directory's root: no home, no layout",
        ),
        (
            "tests/integration/issuer_remote_m06.rs",
            "letdb=dir.path().join(\"state.db\");",
            "a scratch store in a temporary directory's root: no home, no layout",
        ),
        (
            "tests/integration/issuer_store.rs",
            "letstore=Store::open(&dir.join(\"state.db\"),Arc::new(NoFaults)).unwrap();",
            "a scratch store in a temporary directory's root: no home, no layout",
        ),
        (
            "tests/integration/remote_runtime_m06.rs",
            "letdb=dir.path().join(\"state.db\");",
            "a scratch store in a temporary directory's root: no home, no layout",
        ),
        (
            "tests/integration/transport_supervise_m06.rs",
            "letdb=dir.path().join(\"state.db\");",
            "a scratch store in a temporary directory's root: no home, no layout",
        ),
        (
            "tests/model/operations.rs",
            "Arc::new(Store::open(&dir.join(\"state.db\"),Arc::new(heimdall_store::NoFaults)).unwrap());",
            "a scratch store in a crash test's own directory: no home, no layout",
        ),
        (
            "tests/model/operations.rs",
            "&dir.path().join(\"state.db\"),",
            "a scratch store in a temporary directory's root: no home, no layout",
        ),
    ];
    let root = heimdall_testkit::repo::repo_root();
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    let mut stack = vec![root.join("tests")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path != root.join("tests").join("evidence") {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|x| x != "rs") {
                continue;
            }
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "tests/adversarial/store_generations.rs" {
                continue;
            }
            scanned += 1;
            let text = std::fs::read_to_string(&path).unwrap();
            for (n, line) in text.lines().enumerate() {
                let code: String = line
                    .split("//")
                    .next()
                    .unwrap_or("")
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                let names = code.contains("\"state.db\"") || code.contains("STATE_DB_FILE");
                if names && !ALLOWED.iter().any(|(f, l, _)| *f == rel && *l == code) {
                    offenders.push(format!("{rel}:{}: {code}", n + 1));
                }
            }
        }
    }
    assert!(scanned > 100, "scanned only {scanned} sources");
    assert!(
        offenders.is_empty(),
        "reach the store through heimdall_store::layout::db_path(state_dir):\n{}",
        offenders.join("\n")
    );
}
