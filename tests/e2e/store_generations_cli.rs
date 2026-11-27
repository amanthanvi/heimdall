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

// --- ⟨M08 U2b-4⟩ H2 stop preview, H5 executable_moved, H6 residue kinds + remote pairings ----

impl Scratch {
    /// Run a specific binary (or the default `CARGO_BIN_EXE_heimdall`) with extra env vars and
    /// selectable `--json` mode.
    fn run_bin(
        &self,
        bin: &Path,
        args: &[&str],
        json: bool,
        extra_env: &[(&str, String)],
    ) -> Output {
        let root = self.dir.path();
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
            .arg("--non-interactive")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if json {
            cmd.arg("--json");
        }
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
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.args(args).spawn().unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(60) {
                let _ = child.kill();
                panic!("heimdall {args:?} did not end");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child.wait_with_output().unwrap();
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    }

    fn default_bin(&self) -> std::path::PathBuf {
        std::env::var("HEIMDALL_E2E_BIN")
            .ok()
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_BIN_EXE_heimdall")))
    }

    fn spawn_service(&self, extra_env: &[(&str, String)]) -> std::process::Child {
        let root = self.dir.path();
        let mut cmd = Command::new(self.default_bin());
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
            .env("HEIMDALL_TEST_ADAPTER", "prepare")
            .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("LANG", "C")
            .env("TERM", "dumb")
            .current_dir(root)
            .args(["service", "run"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
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
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.spawn().unwrap()
    }
}

struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// ⟨M08 U2b-4; ADR-0014 §3.2 item 2, §3.3, §3.4, H2⟩ `heimdall service stop --preview`
/// through the real binary:
/// 1. When no runtime is running, leaves `state_dir` byte-identical (not even `-wal`/`-shm`
///    created) and reports `running: false` with any migration backup count.
/// 2. With a real running runtime holding live work (`heimdall run` child), open operations
///    (`awaiting_approval`), in-memory working keys, owned master & dedicated sessions, an
///    active environment endpoint, and a migration backup, `service stop --preview` lists all
///    of them accurately (matching `StopPreview`), leaves the runtime running at the exact
///    same PID, and changes nothing.
#[test]
fn stop_preview_lists_what_stopping_interrupts() {
    use heimdall_contract::ids::{ConnectionId, CredentialInstanceId, EnvironmentId};
    use heimdall_contract::lifecycle::StopPreview;
    use heimdall_contract::managed::ConnectionKind;
    use heimdall_domain::environment::{EnvironmentRealization, ManagedEnvironment, ManagedState};
    use heimdall_domain::issuance::{CredentialInstance, CredentialState};
    use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};

    let scratch = Scratch::new();
    let paths = scratch.paths();
    paths.ensure().unwrap();
    let bin = scratch.default_bin();

    // 1. Stopped state: initialize a clean generation and plant a migration backup; verify
    //    `service stop --preview` leaves `state_dir` byte-identical.
    {
        let _lock = heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir).unwrap();
        let opened = heimdall_runtime::state_store::open_locked(
            &paths.state_dir,
            Arc::new(NoFaults),
            heimdall_contract::Timestamp::now(),
        )
        .unwrap();
        drop(opened);
    }
    std::fs::write(paths.state_dir.join("state.db.v12.backup"), b"backup").unwrap();
    let before_stopped = snapshot(&paths.state_dir);
    let stopped_out = scratch.run_bin(&bin, &["service", "stop", "--preview"], true, &[]);
    assert!(
        stopped_out.status.success(),
        "stopped preview failed: {stopped_out:?}"
    );
    let after_stopped = snapshot(&paths.state_dir);
    assert_eq!(
        changed(&before_stopped, &after_stopped),
        Vec::<String>::new(),
        "service stop --preview must leave state_dir byte-identical"
    );
    let stopped_env = envelope(&stopped_out);
    assert_eq!(stopped_env["code"], "OK", "{stopped_env}");
    let stopped_preview: StopPreview = serde_json::from_value(stopped_env["data"].clone()).unwrap();
    assert!(!stopped_preview.running);
    assert_eq!(stopped_preview.open_operations, 0);
    assert_eq!(stopped_preview.held_bindings, 0);
    assert_eq!(stopped_preview.migration_backups, 1);

    // 2. Start a real runtime in this scratch home and wait until `service status` says up.
    let mut service_guard = ChildGuard(Some(scratch.spawn_service(&[])));
    let deadline = Instant::now() + Duration::from_secs(30);
    let initial_pid = loop {
        let st = scratch.run_bin(&bin, &["service", "status"], true, &[]);
        if st.status.success() {
            let env = envelope(&st);
            if env["data"]["running"] == true {
                break env["data"]["pid"].as_u64().unwrap();
            }
        }
        assert!(
            Instant::now() < deadline,
            "runtime did not become ready in time"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // 2a. Create real pending operation: `access ensure --profile dev` requires owner approval
    //     for `h3`, so it leaves a genuine `awaiting_approval` operation in the store.
    let pending_out = scratch.run_bin(
        &bin,
        &[
            "access",
            "ensure",
            "--profile",
            "dev",
            "--work-id",
            "w-stop-preview-pending",
            "--for",
            "1h",
            "--request-id",
            "req-stop-preview-pending",
        ],
        true,
        &[],
    );
    let pending_env = envelope(&pending_out);
    assert_eq!(
        pending_env["state"], "awaiting_approval",
        "expected pending approval op: {pending_env}"
    );
    assert_eq!(
        pending_env["code"], "INTERACTION_REQUIRED",
        "expected non-interactive approval refusal: {pending_env}"
    );

    // 2b. Create real held work: launch a child through `heimdall run --profile ops` so a
    //     real live process holds an active binding in `binding_holders`.
    let root = scratch.dir.path();
    let mut run_cmd = Command::new(&bin);
    run_cmd
        .env_clear()
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
        .args(["--non-interactive", "run", "--profile", "ops", "--"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        run_cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        run_cmd.args(["/bin/sleep", "30"]);
    }
    #[cfg(windows)]
    {
        let windows = std::env::var_os("SystemRoot").expect("SystemRoot");
        let ping = std::path::PathBuf::from(&windows).join("System32/PING.EXE");
        run_cmd
            .env("SystemRoot", &windows)
            .env("PATH", std::path::PathBuf::from(&windows).join("System32"))
            .env("USERPROFILE", root.join("account"))
            .env("TEMP", root)
            .env("TMP", root)
            .args([ping.to_str().unwrap(), "127.0.0.1", "-n", "31"]);
    }
    let run_guard = ChildGuard(Some(run_cmd.spawn().unwrap()));

    // Wait for the held binding to be recorded in the store.
    let db = heimdall_store::layout::db_path(&paths.state_dir).unwrap();
    let bind_deadline = Instant::now() + Duration::from_secs(20);
    let (live_binding, live_grant, self_env) = loop {
        let store = Store::open_read_only_no_write(&db, Arc::new(NoFaults)).ok();
        let found = store.and_then(|s| {
            s.transaction(|tx| {
                let holders = tx.binding_holders()?;
                let active = tx.active_bindings()?;
                let self_env = tx.self_environment()?;
                for (bid, _) in holders {
                    if let Some(b) = active.iter().find(|b| b.id == bid) {
                        return Ok(Some((b.id.clone(), b.grant.clone(), self_env)));
                    }
                }
                Ok(None)
            })
            .ok()
            .flatten()
        });
        if let Some((b, g, Some(env))) = found {
            break (b, g, env);
        }
        assert!(
            Instant::now() < bind_deadline,
            "heimdall run did not record a held binding in time"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // 2c. Record sessions (an owned master and a dedicated connection), an in-memory working
    //     key, and an active container endpoint tied to this live grant/binding.
    let master_id = ConnectionId::from_random_bytes([70; 16]);
    let dedicated_id = ConnectionId::from_random_bytes([71; 16]);
    let container_env = EnvironmentId::from_random_bytes([72; 16]);
    let now = heimdall_contract::Timestamp::now();
    let my_pid = std::process::id();
    let my_start = heimdall_runtime::platform::process_start_time(my_pid).unwrap();
    {
        let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.insert_credential_instance(&CredentialInstance {
                    id: CredentialInstanceId::from_random_bytes([73; 16]),
                    grant: live_grant.clone(),
                    key_handle_ref: "abcdef0123456789abcdef0123456789".into(),
                    certificates: Vec::new(),
                    state: CredentialState::Installed,
                })?;
                for (cid, kind) in [
                    (master_id.clone(), ConnectionKind::Master),
                    (dedicated_id.clone(), ConnectionKind::Dedicated),
                ] {
                    tx.insert_owned_connection(&OwnedConnection {
                        id: cid,
                        kind,
                        binding: live_binding.clone(),
                        grant: live_grant.clone(),
                        pid: my_pid,
                        start_token: my_start.clone(),
                        image: "/usr/bin/ssh".into(),
                        control_path: None,
                        generation: 1,
                        state: OwnedConnectionState::Up,
                        started_at: now,
                    })?;
                }
                tx.insert_managed_environment(&ManagedEnvironment {
                    environment: container_env.clone(),
                    controller: self_env.clone(),
                    realization: EnvironmentRealization::Container {
                        label: "preview-box".into(),
                        dir_tag: "0123456789abcdef".into(),
                    },
                    state: ManagedState::Active,
                    created_at: now,
                    updated_at: now,
                })?;
                Ok(())
            })
            .unwrap();
    }

    // 3. Run `heimdall service stop --preview` (JSON + human) through the real binary.
    let preview_out = scratch.run_bin(&bin, &["service", "stop", "--preview"], true, &[]);
    assert!(
        preview_out.status.success(),
        "running preview failed: {preview_out:?}"
    );
    let preview_env = envelope(&preview_out);
    assert_eq!(preview_env["code"], "OK", "{preview_env}");
    let preview: StopPreview = serde_json::from_value(preview_env["data"].clone()).unwrap();
    assert!(preview.running);
    assert!(
        preview.open_operations >= 1,
        "expected pending operation: {preview:?}"
    );
    assert!(
        preview.held_bindings >= 1,
        "expected held binding from live heimdall run: {preview:?}"
    );
    assert!(
        preview.in_memory_keys >= 1,
        "expected in-memory working key: {preview:?}"
    );
    assert!(
        preview
            .owned_connections
            .iter()
            .any(|c| { c.kind == "master" && c.id == master_id.as_str() && c.effect == "closed" }),
        "expected master closed: {:?}",
        preview.owned_connections
    );
    assert!(
        preview.owned_connections.iter().any(|c| {
            c.kind == "connection" && c.id == dedicated_id.as_str() && c.effect == "left_to_client"
        }),
        "expected dedicated left_to_client: {:?}",
        preview.owned_connections
    );
    assert!(
        preview.environment_endpoints.iter().any(|e| {
            e.kind == "container_endpoint"
                && e.id == container_env.as_str()
                && e.effect == "unavailable_until_restart"
        }),
        "expected container endpoint: {:?}",
        preview.environment_endpoints
    );
    assert_eq!(preview.migration_backups, 1);

    let human_out = scratch.run_bin(&bin, &["service", "stop", "--preview"], false, &[]);
    assert!(human_out.status.success(), "{human_out:?}");
    let human = String::from_utf8_lossy(&human_out.stdout);
    assert!(
        human.contains("Stopping the runtime would interrupt:")
            && human.contains("Open operations:")
            && human.contains("Held bindings:")
            && human.contains("Nothing was changed."),
        "{human}"
    );

    // 4. Prove the runtime is STILL running at the exact same PID after stop --preview.
    let status_after = scratch.run_bin(&bin, &["service", "status"], true, &[]);
    assert!(
        status_after.status.success(),
        "runtime stopped during preview! {status_after:?}"
    );
    let status_env = envelope(&status_after);
    assert_eq!(status_env["data"]["running"], true);
    assert_eq!(status_env["data"]["pid"], initial_pid);

    // Cleanly end child and stop the runtime.
    drop(run_guard);
    let stop = scratch.run_bin(&bin, &["service", "stop"], true, &[]);
    assert!(stop.status.success(), "{stop:?}");
    if let Some(mut svc) = service_guard.0.take() {
        let _ = svc.wait();
    }
}

/// ⟨M08 U2b-4; ADR-0014 §3.2 item 12, §3.4, H5⟩ A login entry or route helper pointing to a
/// moved executable is reported by `heimdall doctor` as `executable_moved` with its repair
/// command, never silently rewritten; a foreign login entry is left untouched.
#[test]
fn moved_executable_is_a_doctor_finding_and_never_a_silent_break() {
    use heimdall_contract::doctor::finding;
    use heimdall_runtime::autostart::{LoginCommand, installation_token, system_host};

    let scratch = Scratch::new();
    let paths = scratch.paths();
    paths.ensure().unwrap();
    let bin = scratch.default_bin();

    #[cfg(not(windows))]
    let login_root = {
        let r = scratch.dir.path().join("login-root");
        std::fs::create_dir_all(&r).unwrap();
        r
    };
    #[cfg(windows)]
    let login_root = std::path::PathBuf::from(format!(
        "Software\\HeimdallTest\\moved-exe-{}",
        std::process::id()
    ));

    let old_exe = scratch.dir.path().join("old-install/heimdall");
    let token = installation_token(&paths.state_dir);
    let host = system_host(&token, Some(&login_root));
    let has_login_host = host.kind() != heimdall_runtime::autostart::LoginKind::None;
    if has_login_host {
        host.install(&LoginCommand::new(&old_exe).unwrap()).unwrap();
    }

    // Plant a managed ssh_config with a route helper pointing at the old executable.
    let p_path = paths.config_dir.join("ssh_config");
    let p_bytes = format!(
        "Host lab\n    HostName lab.example.invalid\n    ProxyCommand \"{}\" route connect --destination lab --account deploy --endpoint \"/tmp/s\"\n",
        old_exe.display()
    );
    std::fs::write(&p_path, &p_bytes).unwrap();

    #[cfg(not(windows))]
    let before_login = snapshot(&login_root);

    let extra = [(
        "HEIMDALL_TEST_LOGIN_ROOT",
        login_root.to_string_lossy().into_owned(),
    )];
    let out = scratch.run_bin(&bin, &["doctor"], true, &extra);
    assert!(out.status.success(), "doctor failed: {out:?}");
    let env = envelope(&out);
    let findings = env["data"]["findings"].as_array().unwrap();
    let moved: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["code"] == finding::EXECUTABLE_MOVED)
        .collect();
    if has_login_host {
        let login_finding = moved
            .iter()
            .find(|f| f["subject"]["kind"] == "login_entry")
            .unwrap_or_else(|| panic!("expected login_entry executable_moved: {findings:?}"));
        assert!(
            login_finding["message"]
                .as_str()
                .unwrap_or_default()
                .contains("heimdall service autostart enable"),
            "{login_finding}"
        );
    }
    let route_finding = moved
        .iter()
        .find(|f| f["subject"]["id"] == "route_helper")
        .unwrap_or_else(|| panic!("expected route_helper executable_moved: {findings:?}"));
    assert!(
        route_finding["message"]
            .as_str()
            .unwrap_or_default()
            .contains("heimdall setup apply"),
        "{route_finding}"
    );

    // Doctor never rewrote either entry.
    assert_eq!(
        std::fs::read_to_string(&p_path).unwrap(),
        p_bytes,
        "doctor must never silently rewrite ssh_config"
    );
    #[cfg(not(windows))]
    assert_eq!(
        snapshot(&login_root),
        before_login,
        "doctor must never silently rewrite the login entry"
    );

    // When both point to the running binary, no `executable_moved` finding is emitted.
    let current_exe = std::fs::canonicalize(&bin).unwrap_or_else(|_| bin.clone());
    if has_login_host {
        host.install(&LoginCommand::new(&current_exe).unwrap())
            .unwrap();
    }
    std::fs::write(
        &p_path,
        format!(
            "Host lab\n    HostName lab.example.invalid\n    ProxyCommand \"{}\" route connect --destination lab --account deploy --endpoint \"/tmp/s\"\n",
            current_exe.display()
        ),
    )
    .unwrap();
    let clean = scratch.run_bin(&bin, &["doctor"], true, &extra);
    assert!(clean.status.success(), "{clean:?}");
    let clean_env = envelope(&clean);
    let clean_moved: Vec<_> = clean_env["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == finding::EXECUTABLE_MOVED)
        .collect();
    assert!(
        clean_moved.is_empty(),
        "expected no executable_moved once repaired: {clean_moved:?}"
    );

    // Foreign login entry (on Unix scratch dir): never modified and never claimed as moved.
    #[cfg(not(windows))]
    if has_login_host {
        let loc = std::path::PathBuf::from(host.location());
        let foreign = b"foreign entry not owned by heimdall\n";
        std::fs::write(&loc, foreign).unwrap();
        let foreign_out = scratch.run_bin(&bin, &["doctor"], true, &extra);
        assert!(foreign_out.status.success(), "{foreign_out:?}");
        assert_eq!(
            std::fs::read(&loc).unwrap(),
            foreign,
            "doctor must never touch a foreign login entry"
        );
        let foreign_env = envelope(&foreign_out);
        assert!(
            !foreign_env["data"]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["code"] == finding::EXECUTABLE_MOVED
                    && f["subject"]["kind"] == "login_entry"),
            "foreign entry must not be reported as owned moved entry"
        );
    }

    #[cfg(windows)]
    if has_login_host {
        let _ = host.remove();
    }
}

/// ⟨M08 U2b-4; ADR-0014 §3.4, H6⟩ `heimdall uninstall` through the real binary reports:
/// - `migration_backup`,
/// - `earlier_store_generation`,
/// - `previous_binary` (`heimdall.previous` beside the executable),
/// - `git_block_moved` (moved Git include block in the other global Git file),
///
/// each with its sensitivity, plus M06 `remote_pairings` (paired remote runner environment
/// and paired remote client) with their removal commands and offline-target note.
#[test]
fn uninstall_lists_backups_earlier_generations_previous_binary_and_remote_pairings() {
    use heimdall_contract::ids::{
        AccountName, ClientId, DestinationId, DeviceId, EnvironmentId, KeyFingerprint,
    };
    use heimdall_contract::lifecycle::residue_kind;
    use heimdall_contract::remote::Role;
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_sshconf::render::{MarkerId, Newline, RenderPath, render_git_include_block};
    use heimdall_store::ext_m06::{AppliedLine, ClientState, RemoteClientRecord};

    let scratch = Scratch::new();
    let paths = scratch.paths();
    paths.ensure().unwrap();

    // Place a copy of the real binary in a scratch bin dir with `heimdall.previous` beside it.
    let bin_dir = scratch.dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    #[cfg(windows)]
    let (exe_name, prev_name) = ("heimdall.exe", "heimdall.previous.exe");
    #[cfg(not(windows))]
    let (exe_name, prev_name) = ("heimdall", "heimdall.previous");
    let copied_bin = bin_dir.join(exe_name);
    let prev_bin = bin_dir.join(prev_name);
    std::fs::copy(scratch.default_bin(), &copied_bin).unwrap();
    std::fs::write(&prev_bin, b"previous-binary-placeholder").unwrap();

    // 1. Initialize generation 1, then run `reset_locked` to create generation 2 so
    //    generation 1 becomes a genuine earlier store generation with its operation record.
    let now = heimdall_contract::Timestamp::now();
    {
        let _lock = heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir).unwrap();
        let opened =
            heimdall_runtime::state_store::open_locked(&paths.state_dir, Arc::new(NoFaults), now)
                .unwrap();
        drop(opened);
        let new_env = EnvironmentId::from_random_bytes([88; 16]);
        heimdall_store::restore::reset_locked(
            &paths.state_dir,
            &heimdall_runtime::state_store::PlatformFs,
            &new_env,
            now,
            false,
        )
        .unwrap();
    }

    // 2. Plant a migration backup beside the store.
    std::fs::write(paths.state_dir.join("state.db.v12.backup"), b"old-state").unwrap();

    // 3. Plant a moved Git include block in the XDG global Git config under scratch SSH home.
    let xdg_git = scratch.dir.path().join("ssh-home/.config/git/config");
    std::fs::create_dir_all(xdg_git.parent().unwrap()).unwrap();
    let p_git = paths.config_dir.join("gitconfig");
    let target = if cfg!(windows) {
        RenderPath::windows(&p_git).unwrap()
    } else {
        RenderPath::unix(&p_git).unwrap()
    };
    let marker = MarkerId::parse("hm-0123456789abcdef").unwrap();
    let block = render_git_include_block(&marker, &target, Newline::Lf).unwrap();
    std::fs::write(&xdg_git, &block).unwrap();

    // 4. Record M06 remote pairings (a paired remote runner environment + a paired client) in
    //    the current generation's store.
    let remote_env = EnvironmentId::from_random_bytes([91; 16]);
    let remote_client = ClientId::from_random_bytes([92; 16]);
    {
        let db = heimdall_store::layout::db_path(&paths.state_dir).unwrap();
        let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.upsert_environment(&EnvironmentRecord {
                    id: remote_env.clone(),
                    device: DeviceId::from_random_bytes([93; 16]),
                    kind: EnvironmentKind::RemoteRunner,
                    label: Some("prod-runner".into()),
                    permissions: EnvironmentPermissions::default(),
                })?;
                tx.put_remote_environment_pin(
                    &remote_env,
                    &DestinationId::parse("prod").unwrap(),
                    &AccountName::parse("runner").unwrap(),
                    &KeyFingerprint::parse("SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        .unwrap(),
                    "{}",
                    now,
                )?;
                tx.enroll_bootstrap_owner(
                    &RemoteClientRecord {
                        client: remote_client.clone(),
                        role: Role::Owner,
                        key_fingerprint: KeyFingerprint::parse(
                            "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        )
                        .unwrap(),
                        public_key: "ssh-ed25519 AAAA paired-client".into(),
                        state: ClientState::Active,
                        invitation: None,
                        revoked_generation: None,
                        revocation: None,
                        created_at: now,
                        updated_at: now,
                        line: AppliedLine::Absent,
                    },
                    now,
                )?;
                tx.set_remote_client_line(&remote_client, AppliedLine::Active)?;
                Ok(())
            })
            .unwrap();
    }

    // 5. Run uninstall through the copied real binary (JSON and human).
    let json_out = scratch.run_bin(&copied_bin, &["uninstall"], true, &[]);
    assert!(
        json_out.status.success(),
        "uninstall --json failed: {json_out:?}"
    );
    let env = envelope(&json_out);
    assert_eq!(env["code"], "OK", "{env}");
    let remaining = env["data"]["remaining"].as_array().unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../schemas/public-api/setup-result.schema.json"
    ))
    .unwrap();
    let artifact_schema = &schema["$defs"]["RemainingArtifact"];
    let properties = artifact_schema["properties"].as_object().unwrap();
    assert!(
        properties.contains_key("sensitivity"),
        "the published RemainingArtifact schema omits sensitivity"
    );
    let required = artifact_schema["required"].as_array().unwrap();
    assert!(!required.iter().any(|key| key == "sensitivity"));
    let sensitivity_ref = properties["sensitivity"]["anyOf"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|branch| branch["$ref"].as_str())
        .unwrap();
    let sensitivity = schema
        .pointer(sensitivity_ref.strip_prefix('#').unwrap())
        .unwrap();
    let tokens = sensitivity["oneOf"].as_array().unwrap();
    for item in remaining {
        assert!(
            item.as_object()
                .unwrap()
                .keys()
                .all(|key| properties.contains_key(key))
        );
        assert!(
            required
                .iter()
                .all(|key| item.get(key.as_str().unwrap()).is_some())
        );
        assert!(
            tokens
                .iter()
                .any(|variant| variant["const"] == item["sensitivity"]),
            "uninstall emitted a sensitivity outside the published schema"
        );
        let typed: heimdall_contract::setup::RemainingArtifact =
            serde_json::from_value(item.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(typed).unwrap(),
            *item,
            "uninstall residue must round-trip through the contract"
        );
    }
    for (expected_kind, expected_sensitivity) in [
        (residue_kind::MIGRATION_BACKUP, "authority_records"),
        (residue_kind::EARLIER_STORE_GENERATION, "authority_records"),
        (residue_kind::PREVIOUS_BINARY, "public"),
        (residue_kind::GIT_BLOCK_MOVED, "identifiers"),
    ] {
        let item = remaining
            .iter()
            .find(|r| r["kind"] == expected_kind)
            .unwrap_or_else(|| {
                panic!("missing residue kind `{expected_kind}` in remaining: {remaining:?}")
            });
        assert_eq!(item["sensitivity"], expected_sensitivity, "{expected_kind}");
    }

    let pairings = &env["data"]["remote_pairings"];
    let envs = pairings["environments"].as_array().unwrap();
    assert!(
        envs.iter().any(|e| {
            e["environment_id"] == remote_env.as_str()
                && e["label"] == "prod-runner"
                && e["command"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("heimdall environment remove")
        }),
        "missing paired remote environment: {pairings}"
    );
    let clients = pairings["clients"].as_array().unwrap();
    assert!(
        clients.iter().any(|c| {
            c["client_id"] == remote_client.as_str()
                && c["command"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("heimdall environment revoke-client")
        }),
        "missing paired remote client: {pairings}"
    );
    assert!(
        pairings["note"]
            .as_str()
            .unwrap_or_default()
            .contains("offline target"),
        "{pairings}"
    );

    // Human output also names each residue kind, its sensitivity, and the remote pairings.
    let human_out = scratch.run_bin(&copied_bin, &["uninstall"], false, &[]);
    assert!(human_out.status.success(), "{human_out:?}");
    let human = String::from_utf8_lossy(&human_out.stdout);
    for needle in [
        residue_kind::MIGRATION_BACKUP,
        residue_kind::EARLIER_STORE_GENERATION,
        residue_kind::PREVIOUS_BINARY,
        residue_kind::GIT_BLOCK_MOVED,
        remote_env.as_str(),
        remote_client.as_str(),
        "heimdall environment remove",
        "offline target",
    ] {
        assert!(human.contains(needle), "missing `{needle}` in:\n{human}");
    }
}
