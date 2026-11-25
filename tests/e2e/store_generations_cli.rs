//! ⟨M08 U2b-1⟩ The generation layout through the real binary (ADR-0014 §3.2 item 7, §3.6;
//! delta H12): the candidate build refuses a store one schema version ahead and touches
//! nothing, whether that store is in its generation or still flat. On Windows, a generation
//! directory that is not owner-only is refused like the state directory itself.
//!
//! **What is modelled (ruled 2026-11-24):** the "newer build" is the store opened with one
//! migration step beyond this build's (`Store::open_ahead_of_this_build`). It runs in the
//! generation this build's start-up published, and as a flat store. The candidate is the
//! real `heimdall` binary (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN` on a native run).
//!
//! **Isolation:** every run gets a scratch `HEIMDALL_HOME`, `HOME` and
//! `HEIMDALL_TEST_SSH_HOME`, and the scratch secret, management and transport stores.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_runtime::Paths;
use heimdall_store::migrations::Migration;
use heimdall_store::{NoFaults, SCHEMA_VERSION, Store};

/// The newer build's one extra step.
const AHEAD: Migration = Migration {
    version: SCHEMA_VERSION + 1,
    name: "a_build_ahead",
    sql: "CREATE TABLE a_build_ahead (x INTEGER) STRICT;",
};

/// A scratch root: the Heimdall home, the account home, the SSH home and the fixture stores.
struct Scratch {
    dir: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for sub in ["account", "ssh-home/.ssh", "ssh-home/etc-ssh"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        Scratch { dir }
    }

    fn paths(&self) -> Paths {
        Paths::under(&self.dir.path().join("hh"))
    }

    /// `heimdall --json --non-interactive <args>` in the scratch environment, waited for
    /// at most a minute (then killed: a refusal never runs on).
    fn heimdall(&self, args: &[&str]) -> Output {
        let root = self.dir.path();
        let bin = std::env::var("HEIMDALL_E2E_BIN")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned());
        let mut cmd = Command::new(bin);
        cmd.env_clear()
            .env("HEIMDALL_HOME", root.join("hh"))
            .env("HOME", root.join("account"))
            .env("HEIMDALL_TEST_SSH_HOME", root.join("ssh-home"))
            .env("HEIMDALL_TEST_SECRET_STORE", "scratch")
            .env(
                "HEIMDALL_TEST_MGMT_STORE",
                format!("fixture-file:{}", root.join("mgmt-store").to_str().unwrap()),
            )
            .env("HEIMDALL_TEST_IROH_KEY_STORE", root.join("iroh-store"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("LANG", "C")
            .env("TERM", "dumb")
            .current_dir(root)
            .args(["--json", "--non-interactive"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        #[cfg(windows)]
        {
            let windows = std::env::var_os("SystemRoot").expect("SystemRoot");
            cmd.env("SystemRoot", &windows)
                .env("PATH", std::path::PathBuf::from(&windows).join("System32"))
                .env("USERPROFILE", root.join("account"))
                .env("TEMP", root)
                .env("TMP", root);
        }
        let mut child = cmd.spawn().unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(60) {
                let _ = child.kill();
                panic!("heimdall {args:?} did not end");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().unwrap()
    }
}

/// Every file under `dir`, by relative path, with its bytes.
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
    // The debug test configuration's own record of each `service run` start
    // (`heimdall::testcfg::STARTS_FILE`, written before the instance lock): not the store.
    out.remove("test-service-starts");
    out
}

/// The paths whose presence or bytes differ between two snapshots.
fn changed(before: &BTreeMap<String, Vec<u8>>, after: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect()
}

fn envelope(out: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.lines().last().unwrap_or_default()).unwrap_or_else(|e| {
        panic!(
            "no JSON envelope ({e}): stdout {text:?}, stderr {:?}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// The candidate's start-up and its read-only reader on the store in `state`: the runtime
/// refuses (`STATE_UNAVAILABLE`, the store newer than this build), `doctor` reads nothing
/// it could write, and every file of the state directory is as it was.
fn candidate_refuses_and_touches_nothing(scratch: &Scratch, case: &str) {
    let state = scratch.paths().state_dir;
    let before = snapshot(&state);
    let run = scratch.heimdall(&["service", "run"]);
    assert!(
        !run.status.success(),
        "{case}: the runtime started: {run:?}"
    );
    let env = envelope(&run);
    assert_eq!(env["code"], "STATE_UNAVAILABLE", "{case}: {env}");
    let message = env["data"]["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("newer"), "{case}: {message}");
    let after = snapshot(&state);
    assert_eq!(
        changed(&before, &after),
        Vec::<String>::new(),
        "{case}: the runtime touched nothing"
    );
    // `doctor` reads through a read-only SQLite connection. Every existing file stays
    // byte-identical. For a database in write-ahead-log mode, SQLite's read-only open leaves
    // its empty log and its index beside the database (as it does for the flat store before
    // generations); nothing else may appear.
    let _doctor = scratch.heimdall(&["doctor"]);
    let after = snapshot(&state);
    let db = heimdall_store::layout::db_path(&state).unwrap();
    let rel = db
        .strip_prefix(&state)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    for path in changed(&before, &after) {
        let new_companion = !before.contains_key(&path)
            && (path == format!("{rel}-shm")
                || (path == format!("{rel}-wal") && after.get(&path).is_some_and(Vec::is_empty)));
        assert!(new_companion, "{case}: doctor touched {path}");
    }
}

#[test]
fn older_build_on_newer_store_refuses_and_touches_nothing() {
    // In its generation: this build's start-up published it, then the newer build migrated
    // it one step further, in place.
    let scratch = Scratch::new();
    let paths = scratch.paths();
    paths.ensure().unwrap();
    let db = {
        let _lock = heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir).unwrap();
        heimdall_runtime::state_store::open_locked(
            &paths.state_dir,
            Arc::new(NoFaults),
            heimdall_contract::Timestamp::now(),
        )
        .unwrap()
        .db
    };
    let newer = Store::open_ahead_of_this_build(&db, Arc::new(NoFaults), &[AHEAD]).unwrap();
    assert_eq!(newer.schema_version().unwrap(), SCHEMA_VERSION + 1);
    drop(newer);
    assert_eq!(
        heimdall_store::layout::db_path(&paths.state_dir).unwrap(),
        db
    );
    candidate_refuses_and_touches_nothing(&scratch, "a generation one schema ahead");

    // Flat, with no pointer: the adoption refuses before its intent, so no layout appears.
    let scratch = Scratch::new();
    let paths = scratch.paths();
    paths.ensure().unwrap();
    let flat = heimdall_store::layout::db_path(&paths.state_dir).unwrap();
    drop(Store::open_ahead_of_this_build(&flat, Arc::new(NoFaults), &[AHEAD]).unwrap());
    // The instance lock's file, as any earlier start leaves it (outside the store).
    drop(heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir).unwrap());
    candidate_refuses_and_touches_nothing(&scratch, "a flat store one schema ahead");
    use heimdall_store::layout::stategen::generations::{CURRENT, GENERATIONS, INTENT};
    for name in [CURRENT, INTENT, GENERATIONS] {
        assert!(
            !paths.state_dir.join(name).exists(),
            "{name} was not written"
        );
    }
}

/// ⟨M08 U2b-1; ADR-0010 §1 item 7⟩ Windows native: the generation directories inherit the
/// protected state directory's one owner-only entry. A generation directory that also
/// grants another principal is refused at start-up as `state_dir_unsafe`, and is never
/// repaired.
#[cfg(windows)]
#[test]
fn windows_generation_directory_not_owner_only_is_refused() {
    use heimdall_runtime::platform::state_dir_acl::{
        AceKind, INHERITED_ACE, Verdict, check_inside_owner_only, dacl_facts,
    };
    let scratch = Scratch::new();
    let paths = scratch.paths();
    paths.ensure().unwrap();
    let open = || {
        let _lock = heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir).unwrap();
        heimdall_runtime::state_store::open_locked(
            &paths.state_dir,
            Arc::new(NoFaults),
            heimdall_contract::Timestamp::now(),
        )
    };
    let current = open().unwrap().current.dir;
    let me = heimdall_ipc::windows::current_user_sid().unwrap();
    for dir in [current.parent().unwrap(), current.as_path()] {
        let facts = dacl_facts(dir).unwrap();
        assert_eq!(facts.owner_sid, me, "{}", dir.display());
        assert!(
            facts.aces.len() == 1
                && facts.aces[0].kind == AceKind::Allow
                && facts.aces[0].sid == me
                && facts.aces[0].flags & INHERITED_ACE != 0,
            "one inherited entry for the user: {facts:?}"
        );
        assert_eq!(check_inside_owner_only(dir).unwrap(), Verdict::OwnerOnly);
    }
    let granted = Command::new("icacls")
        .arg(&current)
        .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
        .output()
        .unwrap();
    assert!(granted.status.success(), "{granted:?}");
    let refused = open().expect_err("a generation directory others can read is refused");
    match refused {
        heimdall_runtime::service::ServiceError::Config(e) => {
            assert!(heimdall_runtime::paths::is_state_dir_unsafe(&e), "{e}");
        }
        other => panic!("{other}"),
    }
    assert_eq!(
        check_inside_owner_only(&current).unwrap(),
        Verdict::ForeignAce,
        "never repaired"
    );
}
