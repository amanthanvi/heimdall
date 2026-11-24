//! The generation-switch fault set of ADR-0014 §3.6 (m08-plan U2b), against the provisional
//! `heimdall-stategen` crate: real files in a scratch directory, with a fault at one step.
//!
//! Three kinds of fault: an injected I/O error (the operation's own cleanup then runs), an
//! in-process stop (no later call does anything, so no cleanup runs) and a real kill of a
//! child process parked at the step. **No test cuts power:** durability across power loss
//! is not established here.
//!
//! The store is a stand-in file. The cases that need the real store, the runtime or the
//! contract (sanitization, quarantine, the epoch on requests, fence records, the older
//! and newer builds as real binaries) wait for the contract handoff.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use heimdall_stategen::generations::{
    CURRENT, CURRENT_TMP, GENERATIONS, INTENT, INTENT_TMP, MIGRATIONS, RECORD,
};
use heimdall_stategen::{
    Action, CorruptReason, Current, Fault, FaultFs, GenerationName, MigrationNote, Operation, Plan,
    Point, PublishError, RealFs, Refusal, Startup, StateDir, StateError, When,
};

const STORE: &str = "store.db";
const ENV_1: &str = "env-1";
const ENV_2: &str = "env-2";

fn name(text: &str) -> GenerationName {
    GenerationName::parse(text).unwrap()
}

fn plan(operation: Operation, generation: &str, environment: &str, epoch: u64) -> Plan {
    Plan {
        name: name(generation),
        operation,
        created_at: "2026-11-23T00:00:00Z".parse().unwrap(),
        backup_sha256: (operation == Operation::Restore).then(|| "ab".repeat(32)),
        environment_id: environment.to_owned(),
        restore_epoch: epoch,
    }
}

/// A stand-in for the caller's SQLite copy: one closed file.
fn store(content: &str) -> impl FnOnce(&Path) -> Result<Vec<String>, String> + '_ {
    move |dir| {
        std::fs::write(dir.join(STORE), content).map_err(|e| e.kind().to_string())?;
        Ok(vec![STORE.to_owned()])
    }
}

fn real(root: &Path) -> StateDir<RealFs> {
    StateDir::new(RealFs, root)
}

fn faulty(
    root: &Path,
    point: Point,
    nth: u32,
    when: When,
    action: Action,
) -> StateDir<FaultFs<RealFs>> {
    StateDir::new(
        FaultFs::new(
            RealFs,
            Some(Fault {
                point,
                nth,
                when,
                action,
            }),
        ),
        root,
    )
}

fn serving(startup: Result<Startup, StateError>) -> Current {
    match startup {
        Ok(Startup::Serving(current)) => current,
        other => panic!("expected a served generation, got {other:?}"),
    }
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

/// A state directory serving `g-a` (an install, environment 1, epoch 0).
fn installed() -> (tempfile::TempDir, BTreeMap<String, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let current = real(dir.path())
        .publish(plan(Operation::Install, "g-a", ENV_1, 0), store("install"))
        .unwrap();
    assert_eq!(
        (
            current.name.as_str(),
            current.record.operation,
            current.recovered.completed_intent
        ),
        ("g-a", Operation::Install, true)
    );
    let old = snapshot(&dir.path().join(GENERATIONS).join("g-a"));
    (dir, old)
}

fn next_plan(operation: Operation) -> Plan {
    match operation {
        Operation::Restore => plan(Operation::Restore, "g-b", ENV_1, 1),
        _ => plan(Operation::Reset, "g-b", ENV_2, 0),
    }
}

/// After a restart: the intact old generation or the complete new one, no third state, a
/// staged leftover removed, and the state directory usable again.
fn check_after_restart(
    root: &Path,
    old: &BTreeMap<String, Vec<u8>>,
    operation: Operation,
    new_is_current: bool,
    case: &str,
) {
    let state = real(root);
    let current = serving(state.open());
    let generations = root.join(GENERATIONS);
    assert_eq!(
        &snapshot(&generations.join("g-a")),
        old,
        "{case}: the earlier generation is untouched"
    );
    assert!(
        !root.join(CURRENT_TMP).exists() && !root.join(INTENT_TMP).exists(),
        "{case}: no temporary file is left"
    );
    if new_is_current {
        assert_eq!(current.name.as_str(), "g-b", "{case}");
        assert_eq!(
            (
                current.record.operation,
                current.record.from_generation.clone()
            ),
            (operation, Some(name("g-a"))),
            "{case}"
        );
        assert_eq!(
            std::fs::read(current.dir.join(STORE)).unwrap(),
            b"next",
            "{case}: the new generation is complete"
        );
        let residue = state.residue().unwrap();
        assert_eq!(residue.len(), 1, "{case}");
        assert_eq!(
            (
                residue[0].name.as_str(),
                residue[0].record.as_ref().map(|r| r.operation)
            ),
            ("g-a", Some(Operation::Install)),
            "{case}"
        );
    } else {
        assert_eq!(
            (current.name.as_str(), current.record.operation),
            ("g-a", Operation::Install),
            "{case}"
        );
        assert!(
            !generations.join("g-b").exists(),
            "{case}: the staged generation is removed"
        );
        assert_eq!(state.residue().unwrap(), vec![], "{case}");
    }
    // A second start-up finds nothing to do, and the next operation works.
    let again = serving(state.open());
    assert_eq!(
        again.recovered,
        Default::default(),
        "{case}: start-up recovery is done once"
    );
    let after = if new_is_current && operation == Operation::Reset {
        plan(Operation::Restore, "g-c", ENV_2, 1)
    } else {
        plan(Operation::Restore, "g-c", ENV_1, 2)
    };
    let next = state.publish(after, store("later")).unwrap();
    assert_eq!(serving(state.open()).name, next.name, "{case}");
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

#[test]
fn switch_interrupted_before_and_after_each_sync_and_the_rename() {
    // The ADR's six steps, and every other step the operation makes before the switch.
    let others = [
        Point::IntentWrite,
        Point::IntentSync,
        Point::IntentRename,
        Point::IntentDirSync,
        Point::GenerationCreate,
        Point::RecordWrite,
        Point::GenerationsDirSync,
        Point::TempPointerWrite,
    ];
    let mut cases = 0;
    for operation in [Operation::Restore, Operation::Reset] {
        for point in ADR_POINTS.into_iter().chain(others) {
            for when in [When::Before, When::After] {
                for action in [Action::Error, Action::Dead] {
                    let case = format!("{operation:?} {point:?} {when:?} {action:?}");
                    let (dir, old) = installed();
                    let state = faulty(dir.path(), point, 0, when, action);
                    let result = state.publish(next_plan(operation), store("next"));
                    assert!(state.fs().fired(), "{case}: the step was reached");
                    assert!(result.is_err(), "{case}: the failure is reported");
                    // Each of these is reached before the rename, so only the two switch
                    // steps can leave the new generation current.
                    check_after_restart(
                        dir.path(),
                        &old,
                        operation,
                        new_is_current(point, when),
                        &case,
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 2 * 14 * 2 * 2);
}

#[test]
fn a_failure_while_completing_the_intent_leaves_the_switch_done() {
    for point in [
        Point::IntentWrite,
        Point::IntentSync,
        Point::IntentRename,
        Point::IntentDirSync,
    ] {
        for when in [When::Before, When::After] {
            let case = format!("{point:?} {when:?}");
            let (dir, old) = installed();
            // The third intent write of the operation is the completion (the first is
            // the intent, the second the switching mark).
            let current = faulty(dir.path(), point, 2, when, Action::Dead)
                .publish(next_plan(Operation::Restore), store("next"))
                .unwrap();
            assert_eq!(
                (current.name.as_str(), current.recovered.completed_intent),
                ("g-b", false),
                "{case}"
            );
            let restarted = serving(real(dir.path()).open());
            assert_eq!(restarted.name.as_str(), "g-b", "{case}");
            check_after_restart(dir.path(), &old, Operation::Restore, true, &case);
        }
    }
}

#[test]
fn a_failure_while_writing_the_switching_mark_leaves_the_old_generation() {
    // The mark is the operation's second intent write, made before the rename.
    for point in [
        Point::IntentWrite,
        Point::IntentSync,
        Point::IntentRename,
        Point::IntentDirSync,
    ] {
        for when in [When::Before, When::After] {
            for action in [Action::Error, Action::Dead] {
                let case = format!("mark {point:?} {when:?} {action:?}");
                let (dir, old) = installed();
                let state = faulty(dir.path(), point, 1, when, action);
                assert!(
                    state
                        .publish(next_plan(Operation::Restore), store("next"))
                        .is_err(),
                    "{case}"
                );
                assert!(state.fs().fired(), "{case}");
                check_after_restart(dir.path(), &old, Operation::Restore, false, &case);
            }
        }
    }
}

/// The two branches of a missing pointer during a first publication (the contract owner's
/// ruling of 2026-11-23). `adopt` selects an adoption, otherwise an install.
fn first_publication(
    root: &Path,
    adopt: bool,
    fault: Option<(Point, u32, When)>,
) -> Result<Current, PublishError<String>> {
    let run = |state: &dyn Fn(Plan) -> Result<Current, PublishError<String>>| {
        state(plan(
            if adopt {
                Operation::Adopt
            } else {
                Operation::Install
            },
            "g-a",
            ENV_1,
            0,
        ))
    };
    match fault {
        Some((point, nth, when)) => {
            let state = faulty(root, point, nth, when, Action::Dead);
            let result = run(&|p| {
                if adopt {
                    state.adopt(p, FLAT, || Ok(()), store("install"))
                } else {
                    state.publish(p, store("install"))
                }
            });
            assert!(state.fs().fired());
            result
        }
        None => {
            let state = real(root);
            run(&|p| {
                if adopt {
                    state.adopt(p, FLAT, || Ok(()), store("install"))
                } else {
                    state.publish(p, store("install"))
                }
            })
        }
    }
}

#[test]
fn a_pointer_that_was_never_written_is_discarded_and_run_again() {
    // Stopped anywhere up to the rename: staging, the mark being written, the mark written.
    let stops = [
        (Point::RecordSync, 0, When::Before),
        (Point::TempPointerSync, 0, When::After),
        (Point::IntentSync, 1, When::Before),
        (Point::IntentRename, 1, When::After),
        (Point::IntentDirSync, 1, When::After),
        (Point::PointerRename, 0, When::Before),
    ];
    for adopt in [false, true] {
        for stop in stops {
            let case = format!("adopt={adopt} {stop:?}");
            let dir = tempfile::tempdir().unwrap();
            assert!(
                first_publication(dir.path(), adopt, Some(stop)).is_err(),
                "{case}"
            );
            let state = real(dir.path());
            assert!(
                matches!(state.inspect(), Ok(Startup::FirstPublicationPending { .. })),
                "{case}"
            );
            match state.open() {
                Ok(Startup::FirstPublicationPending { intent, .. }) => assert_eq!(
                    intent.state,
                    heimdall_stategen::IntentState::Pending,
                    "{case}"
                ),
                other => panic!("{case}: {other:?}"),
            }
            // The leftover and the temporary pointer are gone, and a second start-up
            // reads the same state: the intent went back to pending first.
            assert!(
                !dir.path().join(GENERATIONS).join("g-a").exists()
                    && !dir.path().join(CURRENT_TMP).exists(),
                "{case}"
            );
            assert!(
                matches!(state.open(), Ok(Startup::FirstPublicationPending { .. })),
                "{case}"
            );
            let current = first_publication(dir.path(), adopt, None).unwrap();
            assert_eq!(serving(state.open()).name, current.name, "{case}");
        }
    }
}

#[test]
fn a_written_pointer_that_is_gone_is_corrupt_and_nothing_is_removed() {
    // Published, with the completion mark not yet written (stopped at each step of it, or
    // straight after the rename); then something outside removes the pointer.
    let stops = [
        (Point::PointerRename, 0, When::After),
        (Point::StateDirSync, 0, When::After),
        (Point::IntentWrite, 2, When::Before),
        (Point::IntentRename, 2, When::Before),
    ];
    for adopt in [false, true] {
        for stop in stops {
            let case = format!("adopt={adopt} {stop:?}");
            let dir = tempfile::tempdir().unwrap();
            let _ = first_publication(dir.path(), adopt, Some(stop));
            assert_eq!(
                serving(real(dir.path()).inspect()).name.as_str(),
                "g-a",
                "{case}: it was published"
            );
            std::fs::remove_file(dir.path().join(CURRENT)).unwrap();
            let before = snapshot(dir.path());
            assert!(before.contains_key("generations/g-a/store.db"), "{case}");
            let state = real(dir.path());
            let corrupt = Err(StateError::Corrupt(CorruptReason::PointerMissing));
            assert_eq!(state.inspect(), corrupt, "{case}");
            assert_eq!(state.open(), corrupt, "{case}");
            assert_eq!(
                first_publication(dir.path(), adopt, None),
                Err(PublishError::State(StateError::Corrupt(
                    CorruptReason::PointerMissing
                ))),
                "{case}"
            );
            assert_eq!(
                snapshot(dir.path()),
                before,
                "{case}: the complete generation is still there"
            );
        }
    }
}

// ---- Review M08-W1-R01: a failure, and then a failure of its own cleanup. ----

fn two_faults(root: &Path, first: Option<Fault>) -> StateDir<FaultFs<RealFs>> {
    // The cleanup's removal of the staged generation is the first call at Point::Cleanup.
    let cleanup = Fault {
        point: Point::Cleanup,
        nth: 0,
        when: When::Before,
        action: Action::Error,
    };
    StateDir::new(
        FaultFs::with_faults(RealFs, first.into_iter().chain([cleanup]).collect()),
        root,
    )
}

#[test]
fn a_failed_cleanup_keeps_the_intent_so_start_up_removes_the_leftover() {
    // An install whose copy fails, and whose cleanup then fails: the next start-up sees an
    // interrupted first publication, removes the leftover and lets the install run again.
    let dir = tempfile::tempdir().unwrap();
    let failing = |d: &Path| -> Result<Vec<String>, String> {
        std::fs::write(d.join(STORE), "partial").unwrap();
        Err("copy failed".into())
    };
    let state = two_faults(dir.path(), None);
    assert_eq!(
        state.publish(plan(Operation::Install, "g-a", ENV_1, 0), failing),
        Err(PublishError::Caller("copy failed".into()))
    );
    assert!(
        dir.path().join(GENERATIONS).join("g-a").exists(),
        "the cleanup failed, so the leftover is there"
    );
    let state = real(dir.path());
    match state.open() {
        Ok(Startup::FirstPublicationPending { recovered, .. }) => {
            assert_eq!(recovered.removed_staged, Some(name("g-a")))
        }
        other => panic!("an install whose cleanup failed is pending, not corrupt: {other:?}"),
    }
    assert!(!dir.path().join(GENERATIONS).join("g-a").exists());
    let current = state
        .publish(plan(Operation::Install, "g-b", ENV_1, 0), store("install"))
        .unwrap();
    assert_eq!(serving(state.open()).name, current.name);

    // A restore whose generation directory sync fails after its record is written, and
    // whose cleanup then fails: the next start-up serves the old generation and removes the
    // staged one, which never becomes residue with a complete restore record.
    let (dir, old) = installed();
    let sync = Fault {
        point: Point::GenerationDirSync,
        nth: 0,
        when: When::Before,
        action: Action::Error,
    };
    let state = two_faults(dir.path(), Some(sync));
    assert!(matches!(
        state.publish(next_plan(Operation::Restore), store("next")),
        Err(PublishError::State(StateError::Io {
            point: Point::GenerationDirSync,
            ..
        }))
    ));
    assert!(
        dir.path()
            .join(GENERATIONS)
            .join("g-b")
            .join(RECORD)
            .exists(),
        "the staged record is there"
    );
    let state = real(dir.path());
    let current = serving(state.open());
    assert_eq!(
        (
            current.name.as_str(),
            current.recovered.removed_staged.clone()
        ),
        ("g-a", Some(name("g-b")))
    );
    assert_eq!(
        state.residue().unwrap(),
        vec![],
        "the staged restore is not residue"
    );
    check_after_restart(
        dir.path(),
        &old,
        Operation::Restore,
        false,
        "restore with a failed cleanup",
    );
}

// ---- Review M08-W1-R02: an empty or stray-only generations/ is not a lost pointer. ----

#[test]
fn an_empty_generations_directory_with_stray_files_is_still_a_new_installation() {
    let dir = tempfile::tempdir().unwrap();
    // A first install that fails cleanly after creating generations/.
    let fault = Fault {
        point: Point::RecordSync,
        nth: 0,
        when: When::Before,
        action: Action::Error,
    };
    assert!(
        faulty(dir.path(), fault.point, fault.nth, fault.when, fault.action)
            .publish(plan(Operation::Install, "g-a", ENV_1, 0), store("install"))
            .is_err()
    );
    let generations = dir.path().join(GENERATIONS);
    assert!(
        generations.is_dir() && std::fs::read_dir(&generations).unwrap().next().is_none(),
        "generations/ is left empty"
    );
    let state = real(dir.path());
    assert_eq!(state.open(), Ok(Startup::Empty));
    // Then a stray file, and a directory whose name is not a generation's.
    std::fs::write(generations.join(".DS_Store"), "finder").unwrap();
    std::fs::write(generations.join("g-x~"), "editor backup").unwrap();
    std::fs::create_dir(generations.join("notes")).unwrap();
    std::fs::write(
        generations.join("g-file"),
        "a file with a generation's name",
    )
    .unwrap();
    assert_eq!(state.inspect(), Ok(Startup::Empty));
    let current = state
        .publish(plan(Operation::Install, "g-b", ENV_1, 0), store("install"))
        .unwrap();
    assert_eq!(serving(state.open()).name, current.name);
    // A real generation directory with the pointer gone is still corrupt.
    std::fs::remove_file(dir.path().join(CURRENT)).unwrap();
    assert_eq!(
        state.open(),
        Err(StateError::Corrupt(CorruptReason::PointerMissing))
    );
}

// ---- A real kill: a child process parks at the step and the parent kills it. ----

const CHILD_ENV: &str = "HM_STATEGEN_FAULT_CHILD";

/// Not a test of its own: the child half of `switch_survives_a_kill_at_each_step`. Without
/// the variable it does nothing.
#[test]
fn child_publish() {
    let Some(spec) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let spec = spec.into_string().unwrap();
    let mut parts = spec.split('|');
    let (root, marker) = (
        PathBuf::from(parts.next().unwrap()),
        PathBuf::from(parts.next().unwrap()),
    );
    let point = ADR_POINTS[parts.next().unwrap().parse::<usize>().unwrap()];
    let when = if parts.next().unwrap() == "before" {
        When::Before
    } else {
        When::After
    };
    let operation = if parts.next().unwrap() == "restore" {
        Operation::Restore
    } else {
        Operation::Reset
    };
    let _ = faulty(&root, point, 0, when, Action::Park(marker))
        .publish(next_plan(operation), store("next"));
    // Reached only if the step was never made: the parent then times out and fails.
    std::process::exit(3);
}

#[test]
fn switch_survives_a_kill_at_each_step() {
    let exe = std::env::current_exe().unwrap();
    for operation in [Operation::Restore, Operation::Reset] {
        for (index, point) in ADR_POINTS.into_iter().enumerate() {
            for when in [When::Before, When::After] {
                let case = format!("kill {operation:?} {point:?} {when:?}");
                let (dir, old) = installed();
                let scratch = tempfile::tempdir().unwrap();
                let marker = scratch.path().join("parked");
                let spec = format!(
                    "{}|{}|{index}|{}|{}",
                    dir.path().display(),
                    marker.display(),
                    if when == When::Before {
                        "before"
                    } else {
                        "after"
                    },
                    if operation == Operation::Restore {
                        "restore"
                    } else {
                        "reset"
                    },
                );
                let mut child = std::process::Command::new(&exe)
                    .args([
                        "--exact",
                        "child_publish",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD_ENV, spec)
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
                check_after_restart(
                    dir.path(),
                    &old,
                    operation,
                    new_is_current(point, when),
                    &case,
                );
            }
        }
    }
}

// ---- The pointer is the only authority. ----

#[test]
fn unreadable_or_dangling_pointer_stops_and_never_picks_another_generation() {
    type Damage = fn(&Path);
    let cases: Vec<(&str, CorruptReason, Damage)> = vec![
        (
            "pointer is not a pointer",
            CorruptReason::PointerMalformed,
            |r| std::fs::write(r.join(CURRENT), b"g-a\n").unwrap(),
        ),
        ("pointer is empty", CorruptReason::PointerMalformed, |r| {
            std::fs::write(r.join(CURRENT), b"").unwrap()
        }),
        ("pointer is cut", CorruptReason::PointerMalformed, |r| {
            std::fs::write(r.join(CURRENT), b"heimdall-current/1\ng-b").unwrap()
        }),
        (
            "pointer names a path",
            CorruptReason::PointerMalformed,
            |r| {
                std::fs::write(r.join(CURRENT), b"heimdall-current/1\n../generations/g-a\n")
                    .unwrap()
            },
        ),
        (
            "pointer names a missing generation",
            CorruptReason::GenerationMissing,
            |r| std::fs::write(r.join(CURRENT), b"heimdall-current/1\ng-zz\n").unwrap(),
        ),
        (
            "pointer is a directory",
            CorruptReason::PointerUnreadable,
            |r| {
                std::fs::remove_file(r.join(CURRENT)).unwrap();
                std::fs::create_dir(r.join(CURRENT)).unwrap();
            },
        ),
        ("pointer is gone", CorruptReason::PointerMissing, |r| {
            std::fs::remove_file(r.join(CURRENT)).unwrap()
        }),
        (
            "the generation has no record",
            CorruptReason::RecordMissing,
            |r| std::fs::remove_file(r.join(GENERATIONS).join("g-b").join(RECORD)).unwrap(),
        ),
        ("the record is cut", CorruptReason::RecordDamaged, |r| {
            let path = r.join(GENERATIONS).join("g-b").join(RECORD);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::write(&path, &bytes[..bytes.len() - 9]).unwrap();
        }),
        (
            "the record is another generation's",
            CorruptReason::RecordDamaged,
            |r| {
                let g = r.join(GENERATIONS);
                std::fs::copy(g.join("g-a").join(RECORD), g.join("g-b").join(RECORD)).unwrap();
            },
        ),
        ("a recorded file is gone", CorruptReason::FileMissing, |r| {
            std::fs::remove_file(r.join(GENERATIONS).join("g-b").join(STORE)).unwrap()
        }),
        #[cfg(unix)]
        (
            "pointer is a symbolic link",
            CorruptReason::PointerUnreadable,
            |r| {
                std::fs::rename(r.join(CURRENT), r.join("elsewhere")).unwrap();
                std::os::unix::fs::symlink(r.join("elsewhere"), r.join(CURRENT)).unwrap();
            },
        ),
    ];
    for (case, reason, damage) in cases {
        // Two complete generations: `g-a` (earlier) and `g-b` (current).
        let (dir, _) = installed();
        let state = real(dir.path());
        state
            .publish(next_plan(Operation::Restore), store("next"))
            .unwrap();
        damage(dir.path());
        let before = snapshot(dir.path());
        let corrupt = Err(StateError::Corrupt(reason));
        assert_eq!(state.inspect(), corrupt, "{case}");
        assert_eq!(state.open(), corrupt, "{case}");
        // No operation proceeds from a corrupt state, and none falls back to `g-a`.
        for next in [
            plan(Operation::Restore, "g-c", ENV_1, 2),
            plan(Operation::Reset, "g-c", ENV_2, 0),
            plan(Operation::Install, "g-c", ENV_1, 0),
        ] {
            assert_eq!(
                state.publish(next, store("x")),
                Err(PublishError::State(StateError::Corrupt(reason))),
                "{case}"
            );
        }
        assert_eq!(
            snapshot(dir.path()),
            before,
            "{case}: nothing was written or removed"
        );
    }
}

#[test]
fn a_directory_no_intent_names_is_never_removed() {
    // A stray directory that looks like a staged generation, with no intent naming it: it
    // is residue, listed and left alone. Start-up does not judge a directory by content.
    let (dir, _) = installed();
    let state = real(dir.path());
    let generations = dir.path().join(GENERATIONS);
    std::fs::create_dir(generations.join("g-stray")).unwrap();
    std::fs::copy(
        generations.join("g-a").join(STORE),
        generations.join("g-stray").join(STORE),
    )
    .unwrap();
    std::fs::create_dir(generations.join("not-a-generation")).unwrap();
    let before = snapshot(dir.path());
    let current = serving(state.open());
    assert_eq!(
        (current.name.as_str(), current.recovered.clone()),
        ("g-a", Default::default())
    );
    assert_eq!(snapshot(dir.path()), before);
    let residue: Vec<_> = state
        .residue()
        .unwrap()
        .into_iter()
        .map(|r| (r.name, r.record.is_some()))
        .collect();
    assert_eq!(
        residue,
        vec![
            ("g-stray".to_owned(), false),
            ("not-a-generation".to_owned(), false)
        ]
    );
    // Its name is taken: an operation cannot stage over it.
    assert_eq!(
        state.publish(plan(Operation::Restore, "g-stray", ENV_1, 1), store("x")),
        Err(PublishError::State(StateError::Refused(Refusal::NameTaken)))
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn inspect_writes_nothing_and_open_removes_the_leftover() {
    let (dir, _) = installed();
    assert!(
        faulty(
            dir.path(),
            Point::PointerRename,
            0,
            When::Before,
            Action::Dead
        )
        .publish(next_plan(Operation::Restore), store("next"))
        .is_err()
    );
    let before = snapshot(dir.path());
    assert!(
        before.contains_key("generations/g-b/store.db") && before.contains_key(CURRENT_TMP),
        "the leftover is there"
    );
    let state = real(dir.path());
    assert_eq!(serving(state.inspect()).name.as_str(), "g-a");
    assert_eq!(
        snapshot(dir.path()),
        before,
        "inspect wrote and removed nothing"
    );
    let opened = serving(state.open());
    assert_eq!(
        (
            opened.recovered.removed_staged,
            opened.recovered.removed_temporary
        ),
        (Some(name("g-b")), true)
    );
}

#[test]
fn reset_then_restart_serves_the_new_generation() {
    let (dir, old) = installed();
    let state = real(dir.path());
    let reset = state
        .publish(plan(Operation::Reset, "g-b", ENV_2, 0), store("empty"))
        .unwrap();
    let current = serving(real(dir.path()).open());
    assert_eq!(current.name, reset.name);
    assert_eq!(
        (
            current.record.operation,
            current.record.environment_id.as_str(),
            current.record.restore_epoch
        ),
        (Operation::Reset, ENV_2, 0)
    );
    assert_eq!(current.record.from_generation, Some(name("g-a")));
    assert_eq!(
        current.recovered,
        Default::default(),
        "a completed reset is a completed generation, not an interrupted restore"
    );
    assert_eq!(snapshot(&dir.path().join(GENERATIONS).join("g-a")), old);
}

#[test]
fn restore_restore_reset_keeps_every_earlier_generation() {
    let (dir, _) = installed();
    let state = real(dir.path());
    let refused = |r: Refusal| Err(PublishError::State(StateError::Refused(r)));
    // What each operation must be.
    assert_eq!(
        state.publish(plan(Operation::Restore, "g-b", ENV_1, 0), store("x")),
        refused(Refusal::EpochNotRaised)
    );
    assert_eq!(
        state.publish(plan(Operation::Restore, "g-b", ENV_2, 1), store("x")),
        refused(Refusal::EnvironmentMismatch)
    );
    assert_eq!(
        state.publish(plan(Operation::Reset, "g-b", ENV_1, 0), store("x")),
        refused(Refusal::ResetKeepsIdentity)
    );
    assert_eq!(
        state.publish(plan(Operation::Reset, "g-b", ENV_2, 1), store("x")),
        refused(Refusal::EpochNotZero)
    );
    assert_eq!(
        state.publish(plan(Operation::Install, "g-b", ENV_1, 0), store("x")),
        refused(Refusal::WrongState)
    );
    assert_eq!(
        state.publish(plan(Operation::Adopt, "g-b", ENV_1, 0), store("x")),
        refused(Refusal::AdoptHasItsOwnOrder)
    );
    assert_eq!(
        state.publish(plan(Operation::Restore, "g-a", ENV_1, 1), store("x")),
        refused(Refusal::NameTaken)
    );
    let mut no_digest = plan(Operation::Restore, "g-b", ENV_1, 1);
    no_digest.backup_sha256 = None;
    assert_eq!(
        state.publish(no_digest, store("x")),
        refused(Refusal::BackupDigest)
    );
    assert_eq!(state.residue().unwrap(), vec![], "a refusal stages nothing");

    let mut kept = vec![snapshot(dir.path())];
    for (next, content) in [
        (plan(Operation::Restore, "g-b", ENV_1, 1), "restore 1"),
        (plan(Operation::Restore, "g-c", ENV_1, 2), "restore 2"),
        (plan(Operation::Reset, "g-d", ENV_2, 0), "reset"),
    ] {
        state.publish(next, store(content)).unwrap();
        // Everything that was under `generations` before is still there, byte for byte.
        let now = snapshot(dir.path());
        for (path, bytes) in kept
            .last()
            .unwrap()
            .iter()
            .filter(|(p, _)| p.starts_with("generations/"))
        {
            assert_eq!(now.get(path), Some(bytes), "{path} after {content}");
        }
        kept.push(now);
    }
    let current = serving(real(dir.path()).open());
    assert_eq!(
        (current.name.as_str(), current.record.operation),
        ("g-d", Operation::Reset)
    );
    let residue: Vec<_> = state
        .residue()
        .unwrap()
        .into_iter()
        .map(|r| {
            (
                r.name,
                r.record
                    .map(|rec| (rec.operation, rec.from_generation, rec.restore_epoch)),
            )
        })
        .collect();
    assert_eq!(
        residue,
        vec![
            ("g-a".to_owned(), Some((Operation::Install, None, 0))),
            (
                "g-b".to_owned(),
                Some((Operation::Restore, Some(name("g-a")), 1))
            ),
            (
                "g-c".to_owned(),
                Some((Operation::Restore, Some(name("g-b")), 2))
            ),
        ]
    );
}

#[test]
fn staging_refuses_an_unclosed_database_and_unreported_files() {
    type Populate = fn(&Path) -> Result<Vec<String>, String>;
    let cases: Vec<(&str, Populate, PublishError<String>)> = vec![
        (
            "a write-ahead log beside the database",
            |d| {
                std::fs::write(d.join(STORE), "x").unwrap();
                std::fs::write(d.join("store.db-wal"), "x").unwrap();
                Ok(vec![STORE.into(), "store.db-wal".into()])
            },
            StateError::Refused(Refusal::StagedNotClosed).into(),
        ),
        (
            "a file the caller did not report",
            |d| {
                std::fs::write(d.join(STORE), "x").unwrap();
                std::fs::write(d.join("extra"), "x").unwrap();
                Ok(vec![STORE.into()])
            },
            StateError::Refused(Refusal::StagedFiles).into(),
        ),
        (
            "a reported file that is not there",
            |_| Ok(vec![STORE.into()]),
            StateError::Refused(Refusal::StagedFiles).into(),
        ),
        (
            "nothing staged",
            |_| Ok(vec![]),
            StateError::Refused(Refusal::StagedFiles).into(),
        ),
        (
            "a reserved name",
            |d| {
                std::fs::write(d.join(RECORD), "x").unwrap();
                Ok(vec![RECORD.into()])
            },
            StateError::Refused(Refusal::StagedFiles).into(),
        ),
        (
            "the caller's copy fails",
            |_| Err("copy failed".into()),
            PublishError::Caller("copy failed".into()),
        ),
    ];
    for (case, populate, expected) in cases {
        let (dir, old) = installed();
        assert_eq!(
            real(dir.path()).publish(next_plan(Operation::Restore), populate),
            Err(expected),
            "{case}"
        );
        check_after_restart(dir.path(), &old, Operation::Restore, false, case);
    }
}

#[test]
fn migration_notes_never_touch_the_record_and_ignore_a_cut_line() {
    let (dir, old) = installed();
    let state = real(dir.path());
    let current = serving(state.open());
    let note = |from, to| MigrationNote {
        from,
        to,
        at: "2026-11-23T01:00:00Z".parse().unwrap(),
    };
    assert_eq!(state.migrations(&current).unwrap(), vec![]);
    state.note_migration(&current, &note(12, 13)).unwrap();
    state.note_migration(&current, &note(13, 14)).unwrap();
    let path = current.dir.join(MIGRATIONS);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(b"14 15 2026-11-2");
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        state.migrations(&current).unwrap(),
        vec![note(12, 13), note(13, 14)]
    );
    assert_eq!(
        std::fs::read(current.dir.join(RECORD)).unwrap(),
        old[RECORD]
    );
    assert_eq!(serving(state.open()).record, current.record);
}

// ---- Adoption: fence first, then publish. ----

const FLAT: &str = "flat-store.db";
const OLDER_BUILD_MAX_SCHEMA: u32 = 12;
const FENCE_SCHEMA: u32 = 1_000_000;

fn flat_read(root: &Path) -> (u32, Vec<String>) {
    let text = std::fs::read_to_string(root.join(FLAT)).unwrap();
    let mut lines = text.lines();
    let schema = lines
        .next()
        .unwrap()
        .strip_prefix("schema=")
        .unwrap()
        .parse()
        .unwrap();
    (schema, lines.map(str::to_owned).collect())
}

fn flat_write(root: &Path, schema: u32, lines: &[String]) {
    let mut text = format!("schema={schema}\n");
    for line in lines {
        text.push_str(line);
        text.push('\n');
    }
    std::fs::write(root.join(FLAT), text).unwrap();
}

/// The older build: it knows nothing of the pointer. It serves a flat store whose schema
/// it accepts, and here records a revocation; it refuses a newer schema and writes nothing.
fn older_build_starts(root: &Path) -> Result<(), &'static str> {
    let (schema, mut lines) = flat_read(root);
    if schema > OLDER_BUILD_MAX_SCHEMA {
        return Err("store_schema_newer");
    }
    lines.push("revoked:by-the-older-build".to_owned());
    flat_write(root, schema, &lines);
    Ok(())
}

/// The newer build's start-up: serve the pointer's generation, or adopt the flat store.
fn newer_build_starts<F: heimdall_stategen::Fs>(
    state: &StateDir<F>,
    generation: &str,
) -> Result<Current, PublishError<String>> {
    match state.open()? {
        Startup::Serving(current) => Ok(current),
        Startup::Empty | Startup::FirstPublicationPending { .. } => {
            let root = state.root().to_path_buf();
            let fence = || {
                let (_, lines) = flat_read(&root);
                flat_write(&root, FENCE_SCHEMA, &lines);
                Ok(())
            };
            let copy = |dir: &Path| {
                let (schema, lines) = flat_read(&root);
                assert_eq!(schema, FENCE_SCHEMA, "the copy reads the fenced family");
                std::fs::write(dir.join(STORE), lines.join("\n"))
                    .map_err(|e| e.kind().to_string())?;
                Ok(vec![STORE.to_owned()])
            };
            state.adopt(
                plan(Operation::Adopt, generation, ENV_1, 0),
                FLAT,
                fence,
                copy,
            )
        }
    }
}

#[test]
fn adoption_killed_at_each_step_then_older_build_then_newer_build() {
    // Where the newer build is stopped, and whether the fence had been set by then.
    type Stop = Option<(Point, u32, When)>;
    let stops: [(&str, Stop, bool); 6] = [
        (
            "before the intent is durable",
            Some((Point::IntentSync, 0, When::Before)),
            false,
        ),
        (
            "after the intent, before the fence",
            Some((Point::IntentDirSync, 0, When::After)),
            false,
        ),
        (
            "after the fence, before the copy",
            Some((Point::GenerationCreate, 0, When::Before)),
            true,
        ),
        (
            "after the copy, before the publication",
            Some((Point::PointerRename, 0, When::Before)),
            true,
        ),
        (
            "after the publication, before the completion",
            Some((Point::PointerRename, 0, When::After)),
            true,
        ),
        ("after the completion", None, true),
    ];
    for (case, stop, fenced) in stops {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        flat_write(
            root,
            OLDER_BUILD_MAX_SCHEMA,
            &["grant:1".to_owned(), "revoked:before-the-update".to_owned()],
        );

        // The newer build starts and is stopped.
        let first = match stop {
            Some((point, nth, when)) => {
                let state = faulty(root, point, nth, when, Action::Dead);
                let result = newer_build_starts(&state, "g-first");
                assert!(state.fs().fired() && result.is_err(), "{case}");
                None
            }
            None => Some(newer_build_starts(&real(root), "g-first").unwrap()),
        };
        assert_eq!(
            flat_read(root).0 == FENCE_SCHEMA,
            fenced,
            "{case}: the fence"
        );

        // The rollback: the older build is started.
        let before_older = snapshot(root);
        let older = older_build_starts(root);
        if fenced {
            assert_eq!(
                older,
                Err("store_schema_newer"),
                "{case}: after the fence the older build refuses"
            );
            assert_eq!(snapshot(root), before_older, "{case}: and writes nothing");
        } else {
            assert_eq!(
                older,
                Ok(()),
                "{case}: before the fence the older build serves the flat store"
            );
        }

        // The newer build is started again.
        let current = newer_build_starts(&real(root), "g-second").unwrap();
        let published_first = matches!(stop, None | Some((Point::PointerRename, _, When::After)));
        assert_eq!(
            current.name.as_str(),
            if published_first {
                "g-first"
            } else {
                "g-second"
            },
            "{case}"
        );
        assert_eq!(current.record.operation, Operation::Adopt, "{case}");
        if let Some(first) = first {
            assert_eq!(first.name, current.name, "{case}");
        }
        // One generation, complete; no staged leftover from the interrupted attempt.
        let state = real(root);
        assert_eq!(state.residue().unwrap(), vec![], "{case}");
        assert!(
            !root.join(CURRENT_TMP).exists() && !root.join(INTENT_TMP).exists(),
            "{case}"
        );
        assert_eq!(
            serving(state.open()).recovered,
            Default::default(),
            "{case}: the intent is complete"
        );
        let intent = std::fs::read_to_string(root.join(INTENT)).unwrap();
        assert!(
            intent.contains(r#""state":"complete""#) && intent.contains(FLAT),
            "{case}"
        );

        // Nothing the older build knew is missing, and no revocation is lost.
        let adopted = std::fs::read_to_string(current.dir.join(STORE)).unwrap();
        let mut expected = vec!["grant:1", "revoked:before-the-update"];
        if !fenced {
            expected.push("revoked:by-the-older-build");
        }
        assert_eq!(adopted.lines().collect::<Vec<_>>(), expected, "{case}");
        // The flat family is still there, fenced, never moved and never served again.
        assert_eq!(flat_read(root).0, FENCE_SCHEMA, "{case}");
        assert_eq!(
            older_build_starts(root),
            Err("store_schema_newer"),
            "{case}"
        );
        // Adoption does not run twice.
        assert_eq!(
            state.adopt(
                plan(Operation::Adopt, "g-third", ENV_1, 0),
                FLAT,
                || Ok::<(), String>(()),
                store("x")
            ),
            Err(PublishError::State(StateError::Refused(
                Refusal::WrongState
            ))),
            "{case}"
        );
    }
}

#[test]
fn an_interrupted_install_is_run_again() {
    for (point, when) in [
        (Point::IntentDirSync, When::After),
        (Point::RecordSync, When::Before),
        (Point::PointerRename, When::Before),
    ] {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            faulty(dir.path(), point, 0, when, Action::Dead)
                .publish(plan(Operation::Install, "g-a", ENV_1, 0), store("install"))
                .is_err()
        );
        let state = real(dir.path());
        assert!(
            matches!(state.open(), Ok(Startup::FirstPublicationPending { ref intent, .. }) if intent.operation == Operation::Install),
            "{point:?}"
        );
        // A restore or a reset has nothing to start from.
        assert_eq!(
            state.publish(plan(Operation::Reset, "g-r", ENV_2, 0), store("x")),
            Err(PublishError::State(StateError::Refused(
                Refusal::WrongState
            )))
        );
        let current = state
            .publish(plan(Operation::Install, "g-b", ENV_1, 0), store("install"))
            .unwrap();
        assert_eq!(serving(state.open()).name, current.name);
        assert_eq!(state.residue().unwrap(), vec![]);
    }
}
