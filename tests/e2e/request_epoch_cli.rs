//! ⟨M08 U2b-2⟩ The restore epoch through the real binary (ADR-0014 §3.6 step 3, H13; U0-Q5):
//! `--request-epoch` on the commands that take `--request-id`, the request ID and epoch every
//! mutating answer reports, the kept pair a retry passes back, and the refusal of a stale one
//! before anything is written. This is the CLI the harnesses H1 and H2 speak.
//!
//! **Modelled, not real:** nothing in this slice raises the epoch. The test raises it with the
//! store's test seam (`Txn::raise_restore_epoch_for_test`) on the stopped runtime's store,
//! standing in for U2b-3's restore.
//!
//! **Isolation:** every run gets a scratch `HEIMDALL_HOME`, `HOME` and
//! `HEIMDALL_TEST_SSH_HOME`, and the scratch secret, management and transport stores. The
//! runtime is the one the CLI starts on demand; each test stops it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_runtime::Paths;
use heimdall_store::{NoFaults, Store};
use serde_json::Value;

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

    fn state_dir(&self) -> PathBuf {
        Paths::under(&self.dir.path().join("hh")).state_dir
    }

    /// `heimdall --json --non-interactive <args>` in the scratch environment, waited for at
    /// most a minute (then killed).
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
            // The debug test configuration's synchronized clock: a catalog write needs safe
            // time, and a scratch runtime's first start has no confirmation of this boot.
            .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
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
        let out = child.wait_with_output().unwrap();
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    }

    /// Stop the runtime the CLI started, and wait until its lock is free.
    fn stop(&self) {
        let _ = self.heimdall(&["service", "stop"]);
        let started = Instant::now();
        loop {
            match heimdall_runtime::InstanceLock::try_acquire(&self.state_dir()) {
                Ok(lock) => {
                    drop(lock);
                    return;
                }
                Err(_) if started.elapsed() < Duration::from_secs(30) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("the runtime did not stop: {e}"),
            }
        }
    }

    /// The stopped runtime's store, raised to `epoch` (the test seam, module docs).
    fn raise_epoch(&self, epoch: u64) {
        let store = Store::open(
            &heimdall_store::layout::db_path(&self.state_dir()).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap();
        store
            .transaction(|tx| {
                tx.raise_restore_epoch_for_test(heimdall_contract::lifecycle::RestoreEpoch(epoch))
            })
            .unwrap();
    }

    /// What a request could have written: the store's tables but its event log (the runtime
    /// writes its own lifecycle events on its own schedule), and the request ledger.
    fn footprint(&self) -> (String, Vec<u8>) {
        let store = Store::open_read_only(
            &heimdall_store::layout::db_path(&self.state_dir()).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap();
        let mut counts = store.transaction(|tx| tx.table_counts()).unwrap();
        counts.events = 0;
        let ledger = std::fs::read(
            self.state_dir()
                .join(heimdall_store::layout::stategen::ledger::LEDGER),
        )
        .unwrap_or_default();
        (format!("{counts:?}"), ledger)
    }
}

/// Stops the runtime when a test ends, whatever happened.
struct StopOnDrop<'a>(&'a Scratch);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.heimdall(&["service", "stop"]);
    }
}

fn envelope(out: &Output) -> Value {
    [&out.stdout, &out.stderr]
        .into_iter()
        .find_map(|b| {
            String::from_utf8_lossy(b)
                .lines()
                .rev()
                .find_map(|l| serde_json::from_str::<Value>(l).ok())
        })
        .unwrap_or_else(|| {
            panic!(
                "no JSON envelope: stdout {:?}, stderr {:?}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

const ADD: &[&str] = &["profile", "create", "p1", "--label", "kept"];

fn with(base: &[&str], extra: &[&str]) -> Vec<String> {
    base.iter().chain(extra).map(|s| (*s).to_owned()).collect()
}

fn run(scratch: &Scratch, argv: &[String]) -> (Output, Value) {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = scratch.heimdall(&args);
    let env = envelope(&out);
    (out, env)
}

/// U0-Q5 through the CLI: a mutating answer names the request ID and epoch it used; the same
/// command with the kept pair (`--request-id`, `--request-epoch`) replays the same operation;
/// after the epoch has risen the same pair is `REQUEST_STALE` (exit 6) and nothing runs. A
/// retry without `--request-epoch` is bound to the epoch of its own hello at send.
#[test]
fn clients_carry_the_epoch_with_a_kept_request_id_through_the_cli() {
    let scratch = Scratch::new();
    let _stop = StopOnDrop(&scratch);
    let (out, first) = run(&scratch, &with(ADD, &["--request-id", "r-add"]));
    assert!(out.status.success(), "{first}");
    assert_eq!(first["request_id"], "r-add", "{first}");
    assert_eq!(first["request_epoch"], 0, "{first}");
    let kept = first["request_epoch"].as_u64().unwrap().to_string();
    let (out, replay) = run(
        &scratch,
        &with(ADD, &["--request-id", "r-add", "--request-epoch", &kept]),
    );
    assert!(out.status.success(), "{replay}");
    assert_eq!(replay["operation_id"], first["operation_id"], "{replay}");
    assert_eq!(replay["request_epoch"], first["request_epoch"]);
    // `--request-epoch` without `--request-id` is a usage error before anything is sent.
    let (out, usage) = run(&scratch, &with(ADD, &["--request-epoch", &kept]));
    assert_eq!(out.status.code(), Some(2), "{usage}");
    scratch.stop();
    scratch.raise_epoch(1);
    let before = scratch.footprint();
    let (out, stale) = run(
        &scratch,
        &with(ADD, &["--request-id", "r-add", "--request-epoch", &kept]),
    );
    assert_eq!(out.status.code(), Some(6), "{stale}");
    assert_eq!(stale["code"], "REQUEST_STALE", "{stale}");
    assert_eq!(stale["data"]["error"]["reason"], "restore_epoch_stale");
    assert_eq!(stale["data"]["error"]["effect_status"], "none");
    assert_eq!(stale["next"]["action"], "new_request_id", "{stale}");
    assert_eq!(
        (&stale["request_id"], &stale["request_epoch"]),
        (&first["request_id"], &first["request_epoch"])
    );
    assert_eq!(scratch.footprint(), before, "nothing written");
    // Bound at send to this hello's epoch (1): the store still holds the record, which
    // answers it; nothing runs again.
    let (out, bound) = run(&scratch, &with(ADD, &["--request-id", "r-add"]));
    assert!(out.status.success(), "{bound}");
    assert_eq!(bound["request_epoch"], 1, "{bound}");
    assert_eq!(bound["operation_id"], first["operation_id"], "{bound}");
}

/// ⟨M08 U2b-2 follow-up B⟩ `run` without `--request-id` reports the request ID it minted on
/// stderr with the epoch beside it, in the form a retry passes back (`--request-id <id>
/// --request-epoch <n>`). Passed back, they are the invocation's kept pair: answered at that
/// epoch, with nothing reported again, and refused `REQUEST_STALE` once the epoch has risen.
/// (The profile does not exist, so nothing is ever launched.)
#[test]
fn run_reports_its_minted_request_id_with_the_epoch() {
    let scratch = Scratch::new();
    let _stop = StopOnDrop(&scratch);
    // A program `run` resolves (before it mints anything); it is never started.
    #[cfg(windows)]
    let shell = std::path::Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join("cmd.exe")
        .to_str()
        .unwrap()
        .to_owned();
    #[cfg(not(windows))]
    let shell = "/bin/sh".to_owned();
    let program = ["--", shell.as_str()];
    let base = ["run", "--profile", "absent"];
    let first: Vec<&str> = base.iter().chain(&program).copied().collect();
    let out = scratch.heimdall(&first);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let line = stderr
        .lines()
        .find(|l| l.starts_with("heimdall: request ID "))
        .unwrap_or_else(|| panic!("no minted request ID reported: {stderr}"));
    let (id, retry) = line["heimdall: request ID ".len()..]
        .split_once("; retry with ")
        .unwrap_or_else(|| panic!("{line}"));
    assert_eq!(
        retry,
        format!("--request-id {id} --request-epoch 0"),
        "{line}"
    );
    let again: Vec<String> = base
        .iter()
        .copied()
        .chain(retry.split(' '))
        .chain(program.iter().copied())
        .map(str::to_owned)
        .collect();
    let (out, answer) = run(&scratch, &again);
    assert_eq!(answer["request_id"], id, "{answer}");
    assert_eq!(answer["request_epoch"], 0, "{answer}");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("heimdall: request ID "),
        "a given request ID is not reported again: {out:?}"
    );
    scratch.stop();
    scratch.raise_epoch(1);
    let (out, stale) = run(&scratch, &again);
    assert_eq!(out.status.code(), Some(6), "{stale}");
    assert_eq!(stale["code"], "REQUEST_STALE", "{stale}");
    assert_eq!(
        (&stale["request_id"], &stale["request_epoch"]),
        (&answer["request_id"], &answer["request_epoch"])
    );
}

/// ADR-0014 §3.6 step 3 through the CLI: each command that sends a mutating request with
/// `--request-id` and a `--request-epoch` that is not current is refused `REQUEST_STALE`,
/// exit 6, effect `none`, and reports the pair; the store and the request ledger are as they
/// were.
#[test]
fn stale_epoch_is_refused_before_any_write_through_the_cli() {
    let scratch = Scratch::new();
    let _stop = StopOnDrop(&scratch);
    // Start the runtime (on demand), then stop it to raise its epoch.
    let (out, _) = run(&scratch, &with(ADD, &["--request-id", "r-seed"]));
    assert!(out.status.success());
    scratch.stop();
    scratch.raise_epoch(3);
    // A request with no epoch starts the runtime again, bound to the current epoch.
    let (out, release) = run(
        &scratch,
        &with(
            &["access", "release"],
            &["binding_00112233445566778899aabbccddeeff"],
        ),
    );
    assert_ne!(release["code"], "REQUEST_STALE", "{release} {out:?}");
    assert_eq!(release["request_epoch"], 3, "{release}");
    let before = scratch.footprint();
    let grant = "grant_00112233445566778899aabbccddeeff";
    let binding = "binding_00112233445566778899aabbccddeeff";
    let commands: Vec<Vec<&str>> = vec![
        vec!["access", "ensure", "--profile", "dev", "--work-id", "w1"],
        vec!["access", "revoke", grant],
        vec!["access", "delegate", "--parent", binding, "--work-id", "w2"],
        vec!["access", "stop", "--work", "w3"],
        vec!["access", "default-profile", "dev"],
        vec!["destination", "add", "lab2", "--observed"],
        vec!["profile", "create", "p2", "--pair", "lab:deploy"],
    ];
    for (n, command) in commands.iter().enumerate() {
        let id = format!("r-stale-{n}");
        let (out, env) = run(
            &scratch,
            &with(command, &["--request-id", &id, "--request-epoch", "2"]),
        );
        assert_eq!(out.status.code(), Some(6), "{command:?}: {env}");
        assert_eq!(env["code"], "REQUEST_STALE", "{command:?}: {env}");
        assert_eq!(
            env["data"]["error"]["reason"], "restore_epoch_stale",
            "{command:?}"
        );
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{command:?}");
        assert_eq!(env["request_id"], id.as_str(), "{command:?}: {env}");
        assert_eq!(env["request_epoch"], 2, "{command:?}: {env}");
    }
    assert_eq!(
        scratch.footprint(),
        before,
        "nothing written, nothing appended"
    );
}

/// The reference wrapper's driver and the wrapper it loads, written to the scratch root (so a
/// copied test binary carries them).
#[cfg(unix)]
const WRAPPER_FILES: [(&str, &str); 3] = [
    (
        "journey.py",
        include_str!("../../examples/reference-wrapper/journey.py"),
    ),
    (
        "reference_wrapper.py",
        include_str!("../../examples/reference-wrapper/reference_wrapper.py"),
    ),
    (
        "reference_wrapper_windows.py",
        include_str!("../../examples/reference-wrapper/reference_wrapper_windows.py"),
    ),
];

/// One run of the wrapper's JSON-lines driver over `requests` (`kind`, fields with an optional
/// `request_epoch`), against the runtime serving `scratch`: each answer's envelope.
#[cfg(unix)]
fn wrapper(scratch: &Scratch, environment: &str, requests: &[Value]) -> Vec<Value> {
    use std::io::Write as _;
    let python = heimdall_testkit::home::find_program("python3")
        .expect("python3 is required for the wrapper's requests");
    let root = scratch.dir.path();
    let dir = root.join("reference-wrapper");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, source) in WRAPPER_FILES {
        std::fs::write(dir.join(name), source).unwrap();
    }
    let mut child = Command::new(python)
        .env_clear()
        .env("HOME", root.join("account"))
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(root)
        .args(["-I", "-B"])
        .arg(dir.join("journey.py"))
        .arg(root.join("hh").join("run").join("control.sock"))
        .arg(environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for request in requests {
            let line = serde_json::json!({"command": "request", "args": request});
            writeln!(stdin, "{line}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "the wrapper's driver failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["result"].clone())
        .collect()
}

/// ADR-0014 §3.6 step 3 through the reference wrapper against the real runtime: each request
/// that changes something, retried with its kept epoch after the epoch rose, is refused
/// `REQUEST_STALE` and nothing is written; a fresh request carries the hello's epoch.
#[cfg(unix)]
#[test]
fn stale_epoch_is_refused_before_any_write_through_the_wrapper() {
    let scratch = Scratch::new();
    let _stop = StopOnDrop(&scratch);
    let (out, _) = run(&scratch, &with(ADD, &["--request-id", "r-seed"]));
    assert!(out.status.success());
    scratch.stop();
    scratch.raise_epoch(5);
    let (out, _) = run(
        &scratch,
        &with(
            &["access", "release"],
            &["binding_00112233445566778899aabbccddeeff"],
        ),
    );
    let status = scratch.heimdall(&["service", "status"]);
    assert!(status.status.success(), "{out:?}");
    let environment = envelope(&status)["data"]["environment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let grant = "grant_00112233445566778899aabbccddeeff";
    let binding = "binding_00112233445566778899aabbccddeeff";
    let op = "op_00112233445566778899aabbccddeeff";
    let kept = |kind: &str, mut fields: Value| {
        fields["request_epoch"] = 4.into();
        serde_json::json!({"kind": kind, "fields": fields})
    };
    let stale = [
        kept(
            "ensure",
            serde_json::json!({"profile": "p1", "work_id": "w", "request_id": "r-w1"}),
        ),
        kept(
            "bind",
            serde_json::json!({"binding_id": binding, "request_id": "r-w2"}),
        ),
        kept(
            "delegate",
            serde_json::json!({"parent_binding_id": binding, "scope": [], "work_id": "w2", "request_id": "r-w3"}),
        ),
        kept("cancel", serde_json::json!({"operation_id": op})),
        kept("release", serde_json::json!({"binding_id": binding})),
        kept(
            "revoke",
            serde_json::json!({"grant_id": grant, "request_id": "r-w4"}),
        ),
    ];
    let before = scratch.footprint();
    for (answer, request) in wrapper(&scratch, &environment, &stale).iter().zip(&stale) {
        assert_eq!(answer["code"], "REQUEST_STALE", "{request}: {answer}");
        assert_eq!(answer["data"]["error"]["reason"], "restore_epoch_stale");
        assert_eq!(answer["request_epoch"], 4, "{answer}");
        assert_eq!(answer["request_id"], request["fields"]["request_id"]);
    }
    assert_eq!(
        scratch.footprint(),
        before,
        "nothing written, nothing appended"
    );
    let fresh =
        serde_json::json!({"kind": "revoke", "fields": {"grant_id": grant, "request_id": "r-w5"}});
    let answer = &wrapper(&scratch, &environment, &[fresh])[0];
    assert_ne!(answer["code"], "REQUEST_STALE", "{answer}");
    assert_eq!(
        answer["request_epoch"], 5,
        "bound to the hello's epoch: {answer}"
    );
}
