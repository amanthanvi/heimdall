//! M01-U9 end-to-end suite: the CLI through the **real binary**
//! (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN` for a copied binary) against a real runtime process in a temporary
//! `HEIMDALL_HOME` (spec §17 A19/A06 CLI variants; m01-plan U9; ADR-0006 §3.1,
//! §5, §6, §8, §13.4 N04/N06).
//!
//! The runtime is `heimdall service run` started by this test (foreground child,
//! exact PID known) or on demand by the CLI's launcher. It runs with the debug
//! build's env-gated test configuration (`HEIMDALL_TEST_*`, see
//! `crates/heimdall/src/testcfg.rs`): the fake credential adapter (optionally
//! with a durable effect ledger), a scripted time-sync report, a one-shot
//! production stage hook, and the fixture profile `dev` / policy `pol` (h1, h2
//! covered; h3 is added authority). The production system clock is used.
//!
//! **Process-crash label.** The two N06 cases kill the service process with
//! SIGKILL through the exact `Child` handle this test spawned (its PID checked
//! against `instance.json`), after the fake effect is durably in the ledger and
//! before its receipt: that is process-crash evidence, not an in-process
//! reconstruction.
//!
//! **Pseudo-terminal.** The owner-prompt cases run the binary under `script(1)`
//! (BSD `script -q /dev/null …` on macOS, util-linux `script -qec … /dev/null`
//! on Linux) so stdin is a terminal; input is written only after the prompt is
//! shown and stdin is kept open until the child exits. They are Unix-only; on
//! Windows (no `script(1)`) the attendance order and prompt outcomes are covered
//! by the CLI's unit tests through its session/prompt test seam (`cli::tests`),
//! and every other case here runs natively (`HEIMDALL_E2E_BIN`; ADR-0006 §13.6
//! item 8).
//!
//! **Service stop.** `heimdall service stop` sends `Request::Shutdown` over the
//! control endpoint on every platform (`via: "control"`); Unix signals are only
//! its fallback, exercised (Unix only) by replacing the control socket of a
//! running test service with a dead one while `instance.json` stays valid
//! (`via: "signal"`; ADR-0006 §13.7 item 8).
//!
//! **Canaries.** The fake adapter's credential reference carries a synthetic
//! `HEIMDALL_CANARY_*` value built at runtime by the service. Every byte of
//! stdout/stderr of every client, every service's stderr and the runtime log
//! files are scanned with `heimdall_testkit::assert_no_canary`.
//!
//! Only processes this test started are stopped: by `heimdall service stop`
//! (a `Shutdown` request to the runtime in this test's own temp home, whose
//! advertised PID it validates) or by the exact `Child` handle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::collections::BTreeSet;
#[cfg(unix)]
use std::io::Write;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use heimdall_testkit::{FakeCredentialAdapter, assert_no_canary};
use serde_json::Value;

/// The binary under test: `HEIMDALL_E2E_BIN` when set (a native run on a host
/// other than the build host copies the binary and points this at it; gap G09),
/// else the build's `CARGO_BIN_EXE_heimdall`.
fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

/// Every `HEIMDALL_TEST_*` variable (removed from inherited environments).
const TEST_VARS: [&str; 6] = [
    "HEIMDALL_TEST_ADAPTER",
    "HEIMDALL_TEST_LEDGER",
    "HEIMDALL_TEST_HANG_AFTER_EFFECT",
    "HEIMDALL_TEST_SLOW_PREPARE_MS",
    "HEIMDALL_TEST_TIME_SYNC",
    "HEIMDALL_TEST_STAGE_FAIL",
];

const SYNCED: (&str, &str) = ("HEIMDALL_TEST_TIME_SYNC", "synchronized");

// =================================================================================
// Harness
// =================================================================================

/// One finished invocation.
#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    /// The last JSON object printed (the envelope).
    fn json(&self) -> Value {
        last_json(&self.stdout).unwrap_or_else(|| {
            panic!(
                "no JSON envelope (exit {}):\nstdout: {}\nstderr: {}",
                self.code, self.stdout, self.stderr
            )
        })
    }

    fn code_str(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

fn last_json(text: &str) -> Option<Value> {
    text.lines()
        .rev()
        .map(|l| l.trim_matches(|c: char| c == '\r' || c.is_whitespace()))
        .filter_map(|l| l.find('{').map(|i| &l[i..]))
        .find_map(|l| serde_json::from_str::<Value>(l).ok())
}

fn scan(label: &str, text: &str) {
    // `assert_no_canary` panics without the text (the text may hold the canary).
    if text.contains(heimdall_testkit::CANARY_PREFIX) {
        eprintln!("canary found in {label}");
    }
    assert_no_canary(text);
}

/// A temporary `HEIMDALL_HOME` with the variables every process of this test
/// gets.
struct Home {
    dir: tempfile::TempDir,
    env: Vec<(String, String)>,
}

impl Home {
    fn new(env: &[(&str, &str)]) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("hdm")
            .tempdir()
            .expect("temp home");
        Self {
            dir,
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    fn command(&self, args: &[&str], extra: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.args(args);
        self.apply_env(&mut cmd, extra);
        cmd
    }

    fn apply_env(&self, cmd: &mut Command, extra: &[(&str, &str)]) {
        for v in TEST_VARS {
            cmd.env_remove(v);
        }
        cmd.env_remove("HEIMDALL_LOG");
        cmd.env("HEIMDALL_HOME", self.path());
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
    }

    /// Run with stdin closed (never a terminal), scanning both streams.
    fn run(&self, args: &[&str]) -> Out {
        let out = self
            .command(args, &[])
            .stdin(Stdio::null())
            .output()
            .expect("spawn heimdall");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        scan("stdout", &out.stdout);
        scan("stderr", &out.stderr);
        out
    }

    /// [`run`](Self::run) with every wait bounded by `limit`: `Err` when the
    /// client does not exit, or exits but its output pipes do not reach end of
    /// file, in time (a copy of the client's pipe held open by another process,
    /// such as a runtime that inherited it: ADR-0006 §13.8 item 7). A client
    /// still running at the bound is killed through its exact handle.
    fn run_bounded(&self, args: &[&str], limit: Duration) -> Result<Out, String> {
        let deadline = Instant::now() + limit;
        let mut child = self
            .command(args, &[])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn heimdall");
        let (tx, rx) = mpsc::channel::<(usize, Vec<u8>)>();
        let streams: [Box<dyn Read + Send>; 2] = [
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
        ];
        for (i, mut stream) in streams.into_iter().enumerate() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf);
                let _ = tx.send((i, buf));
            });
        }
        drop(tx);
        let Some(code) = wait_timeout(
            &mut child,
            deadline.saturating_duration_since(Instant::now()),
        ) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("client {args:?} did not exit within {limit:?}"));
        };
        let mut out = [Vec::new(), Vec::new()];
        for _ in 0..2 {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok((i, bytes)) => out[i] = bytes,
                Err(_) => {
                    return Err(format!(
                        "client {args:?} exited ({code}) but its output did not reach end of \
                         file within {limit:?}: another process holds its pipe"
                    ));
                }
            }
        }
        let [stdout, stderr] = out.map(|b| String::from_utf8_lossy(&b).into_owned());
        scan("stdout", &stdout);
        scan("stderr", &stderr);
        Ok(Out {
            code,
            stdout,
            stderr,
        })
    }

    /// A command running `heimdall args…` with one extra descriptor, number 9,
    /// inherited **without** close-on-exec: whatever is passed as the command's
    /// stdin becomes fd 9 of the binary (`/bin/sh` duplicates it, then `exec`s
    /// the binary with stdin from `/dev/null`; same PID). The marker for the
    /// "no inherited descriptor" checks (ADR-0006 §13.8 item 7).
    #[cfg(unix)]
    fn command_with_marker_fd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(r#"exec "$0" "$@" 9<&0 0</dev/null"#)
            .arg(bin())
            .args(args);
        self.apply_env(&mut cmd, &[]);
        cmd
    }

    /// Run with stdin on a pseudo-terminal. `input` is written once the owner
    /// prompt is visible; stdin stays open until the child exits. Unix only
    /// (`script(1)`); on Windows the prompt flows are covered by the CLI's unit
    /// tests through its test seam (`cli::tests`).
    #[cfg(unix)]
    fn run_pty(&self, args: &[&str], input: Option<&[u8]>) -> Out {
        let mut cmd = pty_command(args);
        self.apply_env(&mut cmd, &[]);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("blocked: script(1) is needed for the pseudo-terminal cases");
        let collected = Arc::new(Mutex::new(Vec::new()));
        let mut stdout = child.stdout.take().unwrap();
        let sink = collected.clone();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let mut stdin = child.stdin.take();
        if let Some(bytes) = input {
            let start = Instant::now();
            loop {
                let seen = String::from_utf8_lossy(&collected.lock().unwrap()).into_owned();
                if seen.contains("[y/N]: ") {
                    break;
                }
                if child.try_wait().unwrap().is_some() {
                    panic!("exited before the prompt: {seen}");
                }
                assert!(
                    start.elapsed() < Duration::from_secs(30),
                    "no prompt: {seen}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            let s = stdin.as_mut().unwrap();
            s.write_all(bytes).unwrap();
            s.flush().unwrap();
        }
        let status = wait_timeout(&mut child, Duration::from_secs(60)).expect("pty child exits");
        drop(stdin);
        reader.join().unwrap();
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        let stdout = String::from_utf8_lossy(&collected.lock().unwrap()).into_owned();
        scan("pty output", &stdout);
        scan("pty stderr", &err);
        Out {
            code: status,
            stdout,
            stderr: err,
        }
    }

    /// Start `service run` in the foreground as this test's child.
    fn start_service(&self, extra: &[(&str, &str)]) -> Svc {
        let mut cmd = self.command(&["service", "run"], extra);
        cmd.stdin(Stdio::null());
        self.start_service_cmd(cmd)
    }

    /// [`start_service`](Self::start_service) with a prepared `service run`
    /// command (environment and stdin already set). The command, and with it
    /// any descriptor it holds for the child, is dropped before this returns.
    fn start_service_cmd(&self, mut cmd: Command) -> Svc {
        let n = std::fs::read_dir(self.path()).unwrap().count();
        let err_path = self.file(&format!("svc-{n}.err"));
        let out_path = self.file(&format!("svc-{n}.out"));
        cmd.env("HEIMDALL_LOG", "debug")
            .stdout(std::fs::File::create(&out_path).unwrap())
            .stderr(std::fs::File::create(&err_path).unwrap());
        let child = cmd.spawn().expect("spawn service");
        drop(cmd);
        let mut svc = Svc {
            child: Some(child),
            err_path,
            out_path,
        };
        let start = Instant::now();
        loop {
            let st = self.run(&["service", "status", "--json"]);
            if st.code == 0 {
                break;
            }
            if let Some(c) = svc.child.as_mut().unwrap().try_wait().unwrap() {
                svc.scan();
                panic!(
                    "service exited early ({c}): {}",
                    std::fs::read_to_string(&svc.err_path).unwrap_or_default()
                );
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "service did not start"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The advertised PID is exactly the child we started.
        assert_eq!(self.instance_pid(), Some(svc.pid()));
        svc
    }

    fn instance_pid(&self) -> Option<u32> {
        let text = std::fs::read_to_string(self.path().join("run").join("instance.json")).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        v["pid"].as_u64().and_then(|p| u32::try_from(p).ok())
    }

    fn scan_logs(&self) {
        let log_dir = self.path().join("log");
        if let Ok(entries) = std::fs::read_dir(log_dir) {
            for e in entries.flatten() {
                if let Ok(bytes) = std::fs::read(e.path()) {
                    scan("runtime log file", &String::from_utf8_lossy(&bytes));
                }
            }
        }
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        // Stops a runtime the launcher started in this home (validated pid of
        // this home's own advertisement); a no-op when none runs.
        let _ = self
            .command(&["service", "stop", "--json"], &[])
            .stdin(Stdio::null())
            .output();
        if !std::thread::panicking() {
            self.scan_logs();
        }
    }
}

#[cfg(unix)]
fn pty_command(args: &[&str]) -> Command {
    if cfg!(target_os = "linux") {
        let bin = bin();
        let quoted: Vec<String> = std::iter::once(bin.as_str())
            .chain(args.iter().copied())
            .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
            .collect();
        let mut c = Command::new("script");
        c.args(["-q", "-e", "-c", &quoted.join(" "), "/dev/null"]);
        c
    } else {
        let mut c = Command::new("script");
        c.args(["-q", "/dev/null", &bin()]).args(args);
        c
    }
}

fn wait_timeout(child: &mut Child, limit: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s.code().unwrap_or(-1));
        }
        if start.elapsed() > limit {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A runtime process this test started.
struct Svc {
    child: Option<Child>,
    err_path: PathBuf,
    out_path: PathBuf,
}

impl Svc {
    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn scan(&self) {
        for p in [&self.err_path, &self.out_path] {
            scan(
                "service output",
                &std::fs::read_to_string(p).unwrap_or_default(),
            );
        }
    }

    /// Graceful stop through `heimdall service stop`; the child must exit 0.
    fn stop(mut self, home: &Home) {
        let out = home.run(&["service", "stop", "--json"]);
        assert_eq!(out.code, 0, "{out:?}");
        assert_eq!(out.json()["data"]["stopped"], true);
        // Through Request::Shutdown on every platform (ADR-0006 §13.6 item 8).
        assert_eq!(out.json()["data"]["via"], "control", "{out:?}");
        let mut child = self.child.take().unwrap();
        let code = wait_timeout(&mut child, Duration::from_secs(30));
        if code.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert_eq!(code, Some(0), "service exit status after stop");
        self.scan();
        assert_eq!(home.instance_pid(), None, "advertisement removed");
    }

    /// SIGKILL through the exact child handle (process death, no shutdown).
    fn kill(mut self, home: &Home) {
        let mut child = self.child.take().unwrap();
        assert_eq!(home.instance_pid(), Some(child.id()), "exact PID");
        child.kill().unwrap();
        let _ = child.wait();
        self.scan();
    }
}

impl Drop for Svc {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn ensure_args<'a>(request: &'a str, work: &'a str, pair: &'a str) -> Vec<&'a str> {
    vec![
        "access",
        "ensure",
        "--profile",
        "dev",
        "--work-id",
        work,
        "--request-id",
        request,
        "--pair",
        pair,
        "--json",
    ]
}

fn with<'a>(mut base: Vec<&'a str>, more: &[&'a str]) -> Vec<&'a str> {
    base.extend_from_slice(more);
    base
}

fn decision_ref(out: &Out) -> String {
    out.json()["next"]["decision_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("no decision_ref: {out:?}"))
        .to_owned()
}

fn pending_decisions(home: &Home) -> Vec<Value> {
    let out = home.run(&["decision", "list", "--json"]);
    assert_eq!(out.code, 0, "{out:?}");
    out.json()["data"]["decisions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn is_pending(home: &Home, decision: &str) -> bool {
    pending_decisions(home)
        .iter()
        .any(|d| d["decision_id"] == decision && d["state"] == "pending")
}

fn ledger_len(path: &Path) -> usize {
    FakeCredentialAdapter::ledger_entries(path).unwrap().len()
}

fn wait_for_file(path: &Path, limit: Duration) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < limit, "timed out waiting for a marker");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A client process left running (it waits on the runtime).
fn spawn_client(home: &Home, args: &[&str]) -> Child {
    home.command(args, &[])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn finish_client(mut child: Child, limit: Duration) -> Out {
    let code = wait_timeout(&mut child, limit);
    if code.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("client did not finish");
    }
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    scan("client stdout", &stdout);
    scan("client stderr", &stderr);
    Out {
        code: code.unwrap(),
        stdout,
        stderr,
    }
}

// =================================================================================
// A19: exit classes and the envelope
// =================================================================================

#[test]
fn every_exit_class_0_to_7_is_observed_through_the_real_binary() {
    let mut seen = BTreeSet::new();
    let mut note = |out: &Out, expected: i32, code: &str| {
        assert_eq!(out.code, expected, "{out:?}");
        if !code.is_empty() {
            assert_eq!(out.code_str(), code, "{out:?}");
        }
        seen.insert(out.code);
    };

    // --- 0, 2, 3, 4, 6 against a prepare-only runtime.
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    let ready = home.run(&ensure_args("req-1", "work-1", "h1:deploy"));
    note(&ready, 0, "ACCESS_READY");
    let env = ready.json();
    assert_eq!(env["state"], "succeeded");
    assert!(
        env["data"]["binding_id"]
            .as_str()
            .unwrap()
            .starts_with("binding_")
    );
    assert_eq!(env["next"]["action"], "use_binding");
    assert!(env["warnings"].is_array());
    // Duplicate ensure with the same request ID: the same operation.
    let again = home.run(&ensure_args("req-1", "work-1", "h1:deploy"));
    note(&again, 0, "ACCESS_READY");
    assert_eq!(again.json()["operation_id"], env["operation_id"]);
    assert_eq!(
        again.json()["data"]["binding_id"],
        env["data"]["binding_id"]
    );
    // Same key, different parameters.
    let conflict = home.run(&ensure_args("req-1", "work-other", "h1:deploy"));
    note(&conflict, 6, "REQUEST_CONFLICT");
    assert_eq!(conflict.json()["operation_id"], env["operation_id"]);
    // Usage: unknown operation, malformed ID, unknown flag (clap).
    let missing = home.run(&[
        "operation",
        "show",
        "op_00000000000000000000000000000000",
        "--json",
    ]);
    note(&missing, 2, "NOT_FOUND");
    note(
        &home.run(&["operation", "show", "not-an-id", "--json"]),
        2,
        "USAGE_ERROR",
    );
    note(&home.run(&["access", "ensure", "--no-such-flag"]), 2, "");
    // Added authority, non-interactive: exit 3 with a decision reference.
    let pending = home.run(&with(
        ensure_args("req-h3", "work-h3", "h3:deploy"),
        &["--non-interactive"],
    ));
    note(&pending, 3, "INTERACTION_REQUIRED");
    assert!(decision_ref(&pending).starts_with("dec_"));
    // Paused policy: exit 4.
    note(&home.run(&["access", "pause", "pol", "--json"]), 0, "OK");
    note(
        &home.run(&ensure_args("req-p", "work-p", "h1:deploy")),
        4,
        "POLICY_PAUSED",
    );
    svc.stop(&home);

    // --- 5 (ACCEPTED rule) and 0 (--async; operation wait) with a slow adapter.
    let slow = Home::new(&[
        SYNCED,
        ("HEIMDALL_TEST_ADAPTER", "prepare"),
        ("HEIMDALL_TEST_SLOW_PREPARE_MS", "3000"),
    ]);
    let svc = slow.start_service(&[]);
    let accepted = slow.run(&with(
        ensure_args("req-s", "work-s", "h1:deploy"),
        &["--timeout-ms", "200"],
    ));
    note(&accepted, 5, "ACCEPTED");
    let a = accepted.json();
    assert_eq!(a["state"], "running");
    assert_eq!(a["next"]["action"], "observe");
    let op = a["operation_id"].as_str().unwrap().to_owned();
    let waited = slow.run(&["operation", "wait", &op, "--timeout-ms", "20000", "--json"]);
    note(&waited, 0, "OK");
    assert_eq!(waited.json()["state"], "succeeded");
    let async_ok = slow.run(&with(
        ensure_args("req-s2", "work-s2", "h2:deploy"),
        &["--async"],
    ));
    note(&async_ok, 0, "ACCEPTED");
    let op2 = async_ok.json()["operation_id"].as_str().unwrap().to_owned();
    let w2 = slow.run(&["operation", "wait", &op2, "--timeout-ms", "20000", "--json"]);
    assert_eq!(w2.code, 0, "{w2:?}");
    svc.stop(&slow);

    // --- 7, then the same-key retry reconciles to success (one effect).
    let lost = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "lose_reply,prepare")]);
    let ledger = lost.file("effects.ledger");
    let svc = lost.start_service(&[("HEIMDALL_TEST_LEDGER", ledger.to_str().unwrap())]);
    let unknown = lost.run(&ensure_args("req-u", "work-u", "h1:deploy"));
    note(&unknown, 7, "OUTCOME_UNKNOWN");
    assert_eq!(unknown.json()["state"], "outcome_unknown");
    assert_eq!(unknown.json()["data"]["error"]["effect_status"], "unknown");
    assert_eq!(unknown.json()["data"]["error"]["retryable"], false);
    let healed = lost.run(&ensure_args("req-u", "work-u", "h1:deploy"));
    note(&healed, 0, "ACCESS_READY");
    assert_eq!(
        healed.json()["operation_id"],
        unknown.json()["operation_id"]
    );
    assert_eq!(ledger_len(&ledger), 1);
    svc.stop(&lost);

    // --- 1 through a one-shot production stage hook.
    let internal = Home::new(&[
        SYNCED,
        ("HEIMDALL_TEST_ADAPTER", "prepare"),
        (
            "HEIMDALL_TEST_STAGE_FAIL",
            "before:authenticate:INTERNAL_ERROR",
        ),
    ]);
    let svc = internal.start_service(&[]);
    note(
        &internal.run(&ensure_args("req-i", "work-i", "h1:deploy")),
        1,
        "INTERNAL_ERROR",
    );
    svc.stop(&internal);

    // --- 5 for read-only commands without a runtime; they never start one.
    let idle = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    for args in [
        vec!["status", "--json"],
        vec!["service", "status", "--json"],
        vec!["decision", "list", "--json"],
        vec!["inspect", "operations", "--json"],
        vec!["operation", "events", "--json"],
    ] {
        note(&idle.run(&args), 5, "SERVICE_UNAVAILABLE");
    }
    assert!(
        !idle.file("state/test-service-starts").exists(),
        "nothing started"
    );
    assert_eq!(idle.instance_pid(), None);

    assert_eq!(seen, (0..=7).collect::<BTreeSet<i32>>());
}

#[test]
fn human_output_goes_to_stdout_and_messages_to_stderr() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    let mut args = ensure_args("req-h", "work-h", "h3:deploy");
    args.retain(|a| *a != "--json");
    args.push("--non-interactive");
    let out = home.run(&args);
    assert_eq!(out.code, 3);
    assert!(
        out.stdout
            .starts_with("INTERACTION_REQUIRED (awaiting_approval)")
    );
    assert!(last_json(&out.stdout).is_none(), "no JSON without --json");
    assert!(out.stderr.contains("error: "));
    assert!(out.stderr.contains("decision_ref=dec_"));
    // --json: exactly one envelope line on stdout, nothing else.
    let json = home.run(&with(
        ensure_args("req-h", "work-h", "h3:deploy"),
        &["--non-interactive"],
    ));
    assert_eq!(json.stdout.lines().count(), 1);
    assert!(!json.stdout.contains('\u{1b}'));
    svc.stop(&home);
}

// =================================================================================
// A19 / N04: decisions and the owner prompt
// =================================================================================

#[cfg(unix)]
#[test]
fn non_interactive_with_a_pending_decision_exits_3_with_decision_ref_and_no_prompt() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    // Even on a terminal, --non-interactive never prompts.
    let out = home.run_pty(
        &with(
            ensure_args("req-n", "work-n", "h3:deploy"),
            &["--non-interactive"],
        ),
        None,
    );
    assert_eq!(out.code, 3, "{out:?}");
    assert!(!out.stdout.contains("[y/N]"), "no prompt: {out:?}");
    let env = out.json();
    assert_eq!(env["code"], "INTERACTION_REQUIRED");
    assert_eq!(env["state"], "awaiting_approval");
    let dec = env["next"]["decision_ref"].as_str().unwrap().to_owned();
    assert!(is_pending(&home, &dec));
    // Without a terminal, too.
    let plain = home.run(&ensure_args("req-n", "work-n", "h3:deploy"));
    assert_eq!(plain.code, 3);
    assert_eq!(plain.json()["next"]["decision_ref"], dec.as_str());
    assert!(!plain.stderr.contains("[y/N]"));
    svc.stop(&home);
}

#[test]
fn decision_approve_without_a_terminal_or_non_interactive_sends_nothing_and_exits_3() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    let pending = home.run(&ensure_args("req-d", "work-d", "h3:deploy"));
    assert_eq!(pending.code, 3);
    let dec = decision_ref(&pending);
    let op = pending.json()["operation_id"].as_str().unwrap().to_owned();

    #[allow(unused_mut)]
    let mut outs = vec![
        home.run(&["decision", "approve", &dec, "--json"]),
        home.run(&["decision", "approve", &dec, "--non-interactive", "--json"]),
        home.run(&["decision", "deny", &dec, "--json"]),
    ];
    #[cfg(unix)]
    outs.push(home.run_pty(
        &["decision", "approve", &dec, "--non-interactive", "--json"],
        None,
    ));
    for out in outs {
        assert_eq!(out.code, 3, "{out:?}");
        assert!(!out.stdout.contains("[y/N]"), "no prompt: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], "INTERACTION_REQUIRED");
        assert_eq!(env["next"]["decision_ref"], dec.as_str());
        assert!(
            env["data"]["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("not confirmed")
        );
    }
    assert!(is_pending(&home, &dec), "the decision stays pending");
    let show = home.run(&["operation", "show", &op, "--json"]);
    assert_eq!(show.json()["state"], "awaiting_approval");
    // time confirm likewise refuses without a terminal and sends nothing.
    let t = home.run(&["time", "confirm", "--json"]);
    assert_eq!(t.code, 3);
    assert_eq!(t.code_str(), "INTERACTION_REQUIRED");
    svc.stop(&home);
}

#[cfg(unix)]
#[test]
fn owner_prompt_on_a_pty_eof_and_no_keep_it_pending_yes_completes_exactly_once() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    let pending = home.run(&ensure_args("req-y", "work-y", "h3:deploy"));
    assert_eq!(pending.code, 3);
    let dec = decision_ref(&pending);
    let op = pending.json()["operation_id"].as_str().unwrap().to_owned();
    let approve = ["decision", "approve", dec.as_str(), "--json"];

    // EOF (VEOF on the terminal) sends nothing.
    let eof = home.run_pty(&approve, Some(b"\x04"));
    assert_eq!(eof.code, 3, "{eof:?}");
    // The prompt showed the exact recorded delta (h3) before anything was sent.
    assert!(eof.stdout.contains("\"destination\": \"h3\""), "{eof:?}");
    assert!(eof.stdout.contains("cannot verify"));
    assert_eq!(eof.json()["code"], "INTERACTION_REQUIRED");
    assert_eq!(eof.json()["next"]["decision_ref"], dec.as_str());
    assert!(is_pending(&home, &dec));

    // An explicit "n" sends nothing.
    let no = home.run_pty(&approve, Some(b"n\n"));
    assert_eq!(no.code, 3, "{no:?}");
    assert_eq!(no.json()["code"], "INTERACTION_REQUIRED");
    assert!(is_pending(&home, &dec));

    // Any other answer sends nothing either.
    let other = home.run_pty(&approve, Some(b"sure\n"));
    assert_eq!(other.code, 3, "{other:?}");
    assert!(is_pending(&home, &dec));
    assert_eq!(
        home.run(&["operation", "show", &op, "--json"]).json()["state"],
        "awaiting_approval"
    );

    // "yes" completes it.
    let yes = home.run_pty(&approve, Some(b"yes\n"));
    assert_eq!(yes.code, 0, "{yes:?}");
    let env = yes.json();
    assert_eq!(env["code"], "OK");
    assert_eq!(env["data"]["state"], "approved");
    assert_eq!(env["data"]["operation_state"], "succeeded");
    assert!(!is_pending(&home, &dec));
    // The original request now replays the approved operation.
    let ready = home.run(&ensure_args("req-y", "work-y", "h3:deploy"));
    assert_eq!(ready.code, 0, "{ready:?}");
    assert_eq!(ready.json()["operation_id"], op.as_str());

    // A second "yes" is refused: consume-once.
    let twice = home.run_pty(&approve, Some(b"YES\n"));
    assert_eq!(twice.code, 6, "{twice:?}");
    assert_eq!(twice.json()["code"], "DECISION_STALE");
    svc.stop(&home);
}

#[cfg(unix)]
#[test]
fn interactive_ensure_on_a_pty_prompts_then_approves_and_replays_to_access_ready() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    let out = home.run_pty(&ensure_args("req-i", "work-i", "h3:deploy"), Some(b"y\n"));
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stdout.contains("\"destination\": \"h3\""));
    // ADR-0006 §13.6 item 7: the CLI attended the session before the request, so
    // the runtime answered APPROVAL_REQUIRED (an unattended request would have
    // been answered INTERACTION_REQUIRED); the prompt shows that answer.
    assert!(
        out.stdout
            .contains("The runtime answered APPROVAL_REQUIRED"),
        "{out:?}"
    );
    let env = out.json();
    assert_eq!(env["code"], "ACCESS_READY");
    assert!(pending_decisions(&home).is_empty());
    // Declining on a terminal leaves exit 3 with the reference.
    let declined = home.run_pty(&ensure_args("req-i2", "work-i2", "h3:deploy"), Some(b"\n"));
    assert_eq!(declined.code, 3, "{declined:?}");
    assert!(
        declined
            .stdout
            .contains("The runtime answered APPROVAL_REQUIRED")
    );
    assert_eq!(declined.json()["code"], "INTERACTION_REQUIRED");
    assert!(
        declined.json()["data"]["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("not confirmed")
    );
    let dec = declined.json()["next"]["decision_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(is_pending(&home, &dec));
    svc.stop(&home);
}

#[cfg(unix)]
#[test]
fn widening_resume_needs_an_owner_decision_completed_on_a_pty() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    assert_eq!(home.run(&["access", "pause", "pol", "--json"]).code, 0);
    // Unattended resume: a decision record, nothing executed.
    let r = home.run(&["access", "resume", "pol", "--json"]);
    assert_eq!(r.code, 3, "{r:?}");
    let dec = decision_ref(&r);
    assert_eq!(
        home.run(&ensure_args("req-r1", "work-r1", "h1:deploy"))
            .code,
        4,
        "still paused"
    );
    // On a terminal: the exact action is shown; "yes" executes exactly it.
    let ok = home.run_pty(&["access", "resume", "pol", "--json"], Some(b"yes\n"));
    assert_eq!(ok.code, 0, "{ok:?}");
    assert!(ok.stdout.contains("\"action\": \"resume\""), "{ok:?}");
    // Attended before the request (§13.6 item 7): APPROVAL_REQUIRED.
    assert!(
        ok.stdout.contains("The runtime answered APPROVAL_REQUIRED"),
        "{ok:?}"
    );
    assert_eq!(
        ok.json()["data"]["decision_id"],
        dec.as_str(),
        "same record"
    );
    assert_eq!(
        home.run(&ensure_args("req-r2", "work-r2", "h1:deploy"))
            .code,
        0
    );
    // cutoff --clear without a terminal: exit 3 with a reference.
    let at = "2099-01-01T00:00:00Z";
    assert_eq!(
        home.run(&["access", "cutoff", "pol", "--at", at, "--json"])
            .code,
        0
    );
    let clear = home.run(&["access", "cutoff", "pol", "--clear", "--json"]);
    assert_eq!(clear.code, 3, "{clear:?}");
    assert!(decision_ref(&clear).starts_with("dec_"));
    // A naive local time is refused at the input boundary.
    let naive = home.run(&[
        "access",
        "cutoff",
        "pol",
        "--at",
        "2099-01-01T00:00:00",
        "--json",
    ]);
    assert_eq!(naive.code, 2);
    svc.stop(&home);
}

#[cfg(unix)]
#[test]
fn time_confirmation_on_a_pty_clears_time_uncertain_without_moving_deadlines() {
    // No scripted sync: the production stub's `unknown` at first start.
    let home = Home::new(&[("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    let uncertain = home.run(&ensure_args("req-t", "work-t", "h1:deploy"));
    assert_eq!(uncertain.code, 5, "{uncertain:?}");
    assert_eq!(uncertain.code_str(), "TIME_UNCERTAIN");
    // Declined: nothing sent, still uncertain.
    let no = home.run_pty(&["time", "confirm", "--json"], Some(b"no\n"));
    assert_eq!(no.code, 3, "{no:?}");
    assert_eq!(
        home.run(&ensure_args("req-t", "work-t", "h1:deploy")).code,
        5
    );
    let yes = home.run_pty(&["time", "confirm", "--json"], Some(b"yes\n"));
    assert_eq!(yes.code, 0, "{yes:?}");
    assert!(yes.stdout.contains("never moves a deadline"));
    assert_eq!(yes.json()["data"]["deadlines_moved"], false);
    let ready = home.run(&ensure_args("req-t", "work-t", "h1:deploy"));
    assert_eq!(ready.code, 0, "{ready:?}");
    svc.stop(&home);
}

// =================================================================================
// A19: events and cursors
// =================================================================================

struct Follower {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Follower {
    fn start(home: &Home, cursor: &str) -> Self {
        let mut child = home
            .command(
                &[
                    "operation",
                    "events",
                    "--follow",
                    "--cursor",
                    cursor,
                    "--json",
                ],
                &[],
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    fn next(&self) -> Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(20))
            .expect("an NDJSON line");
        scan("follow output", &line);
        serde_json::from_str(&line).expect("each line is one JSON value")
    }

    /// Read events until `op` reports `succeeded`; returns every event read.
    fn until_succeeded(&self, op: &str) -> Vec<Value> {
        let mut events = Vec::new();
        loop {
            let e = self.next();
            let done = e["operation_id"] == op
                && e["type"] == "operation_state_changed"
                && e["payload"]["state"] == "succeeded";
            events.push(e);
            if done {
                return events;
            }
        }
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ids(events: &[Value]) -> BTreeSet<String> {
    events
        .iter()
        .map(|e| e["event_id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn operation_events_follow_resumes_from_cursor() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let svc = home.start_service(&[]);
    assert_eq!(
        home.run(&ensure_args("req-e1", "work-e1", "h1:deploy"))
            .code,
        0
    );

    // Snapshot without a cursor.
    let snap = home.run(&["operation", "events", "--json"]);
    assert_eq!(snap.code, 0);
    let c0 = snap.json()["data"]["snapshot"]["cursor"]
        .as_str()
        .unwrap()
        .to_owned();

    // A page after the snapshot cursor holds exactly the later work.
    let e2 = home.run(&ensure_args("req-e2", "work-e2", "h2:deploy"));
    let op2 = e2.json()["operation_id"].as_str().unwrap().to_owned();
    let page = home.run(&["operation", "events", "--cursor", &c0, "--json"]);
    assert_eq!(page.code, 0, "{page:?}");
    let page_events = page.json()["data"]["events"].as_array().cloned().unwrap();
    assert!(
        page_events
            .iter()
            .any(|e| e["operation_id"] == op2.as_str())
    );
    let before = ids(&page_events);
    let c1 = page.json()["data"]["cursor"].as_str().unwrap().to_owned();

    // Follow from C1: the subscription line, then only events after C1.
    let f = Follower::start(&home, &c1);
    let head = f.next();
    assert_eq!(head["code"], "OK");
    assert_eq!(head["state"], "running");
    assert_eq!(head["data"]["cursor"], c1.as_str());
    assert!(head["data"]["snapshot"].is_null());
    let e3 = home.run(&ensure_args("req-e3", "work-e3", "h1:deploy"));
    let op3 = e3.json()["operation_id"].as_str().unwrap().to_owned();
    let live = f.until_succeeded(&op3);
    assert!(ids(&live).is_disjoint(&before), "nothing at or before C1");
    let last_cursor = live.last().unwrap()["cursor"].as_str().unwrap().to_owned();
    f.stop();

    // Work happens while nobody follows; resuming from the last cursor delivers
    // it from the backlog, and nothing from at or before C1.
    let e4 = home.run(&ensure_args("req-e4", "work-e4", "h2:deploy"));
    let op4 = e4.json()["operation_id"].as_str().unwrap().to_owned();
    let f2 = Follower::start(&home, &last_cursor);
    // Resumed, not resnapshotted: no snapshot, the backlog after the cursor
    // follows. (The subscription line's cursor is the server's head boundary,
    // after the backlog, not the client's cursor.)
    let head2 = f2.next();
    assert_eq!(head2["code"], "OK");
    assert!(head2["data"]["snapshot"].is_null());
    let resumed = f2.until_succeeded(&op4);
    assert!(ids(&resumed).is_disjoint(&before));
    let page4 = home.run(&["operation", "events", "--cursor", &last_cursor, "--json"]);
    let want: BTreeSet<String> = page4.json()["data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["operation_id"] == op4.as_str())
        .map(|e| e["event_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(!want.is_empty());
    // Delivered at least once (the op4 backlog may continue after `succeeded`).
    let mut all = resumed;
    while !want.is_subset(&ids(&all)) {
        all.push(f2.next());
    }
    f2.stop();

    // A foreign or malformed cursor is a resync instruction, never silence.
    let bad = home.run(&["operation", "events", "--cursor", "AAAA", "--json"]);
    assert_eq!(bad.code, 6, "{bad:?}");
    assert_eq!(bad.code_str(), "RESYNC_REQUIRED");
    assert!(bad.json()["next"]["cursor"].is_string());
    svc.stop(&home);
}

// =================================================================================
// Launcher: on-demand start with the real binary
// =================================================================================

/// One round of eight clients racing to start the runtime on demand in a fresh
/// home: every client answers `ACCESS_READY` with its output complete within
/// `limit` (no client pipe held by the runtime), exactly one runtime process
/// ran, and it stops on request.
fn concurrent_start_round(round: usize, limit: Duration) {
    let home = Arc::new(Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let home = home.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let req = format!("req-l{i}");
                let work = format!("work-l{i}");
                barrier.wait();
                home.run_bounded(&ensure_args(&req, &work, "h1:deploy"), limit)
            })
        })
        .collect();
    for h in handles {
        let out = h
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert_eq!(out.code, 0, "round {round}: {out:?}");
        assert_eq!(out.code_str(), "ACCESS_READY", "round {round}");
    }
    let starts = std::fs::read_to_string(home.file("state/test-service-starts")).unwrap();
    assert_eq!(
        starts.lines().count(),
        1,
        "round {round}: exactly one runtime process ran"
    );
    let pid: u32 = starts.trim().parse().unwrap();
    assert_eq!(home.instance_pid(), Some(pid), "round {round}");
    let stop = home
        .run_bounded(&["service", "stop", "--json"], limit)
        .unwrap_or_else(|e| panic!("round {round}: {e}"));
    assert_eq!(stop.code, 0, "round {round}: {stop:?}");
    assert_eq!(stop.json()["data"]["pid"], pid, "round {round}");
    assert_eq!(home.run(&["service", "status", "--json"]).code, 5);
    home.scan_logs();
}

#[test]
fn eight_concurrent_clients_start_exactly_one_runtime() {
    concurrent_start_round(0, Duration::from_secs(60));
}

/// ADR-0006 §13.8 item 7: the intermittent hang of the case above, repeated.
/// Twenty rounds in one test, each wait bounded (a hang fails the round instead
/// of blocking the suite).
#[test]
fn concurrent_start_stress_twenty_rounds_never_hang() {
    let started = Instant::now();
    for round in 0..20 {
        concurrent_start_round(round, Duration::from_secs(30));
    }
    eprintln!("20 concurrent-start rounds in {:?}", started.elapsed());
}

/// Waits, bounded, for `reader` to reach end of file: `true` when every write
/// end is closed. A reader thread left blocked after `false` ends once the
/// holder exits (the test's `Home` stops its runtime on drop).
#[cfg(unix)]
fn reaches_eof(reader: std::io::PipeReader, limit: Duration) -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = reader;
        let mut sink = Vec::new();
        let _ = tx.send(reader.read_to_end(&mut sink).map(|_| sink.len()));
    });
    matches!(rx.recv_timeout(limit), Ok(Ok(0)))
}

/// ADR-0006 §13.8 item 7, launcher side: the client inherits a marker pipe
/// (fd 9, not close-on-exec) and starts the runtime on demand; once the client
/// has exited, the runtime must not hold the marker (its reader sees end of
/// file while the runtime still runs).
#[cfg(unix)]
#[test]
fn on_demand_runtime_keeps_no_descriptor_inherited_through_its_client() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let (reader, writer) = std::io::pipe().unwrap();
    let mut cmd = home.command_with_marker_fd(&ensure_args("req-fd", "work-fd", "h1:deploy"));
    cmd.stdin(writer)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().unwrap();
    // The test's own write end goes with the command.
    drop(cmd);
    let out = finish_client(child, Duration::from_secs(60));
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.code_str(), "ACCESS_READY");
    let pid = home.instance_pid().expect("the client started a runtime");
    assert!(
        reaches_eof(reader, Duration::from_secs(30)),
        "the on-demand runtime holds a descriptor inherited from its client"
    );
    assert_eq!(home.instance_pid(), Some(pid), "the runtime still runs");
    let stop = home.run(&["service", "stop", "--json"]);
    assert_eq!(stop.code, 0, "{stop:?}");
}

/// ADR-0006 §13.8 item 7, runtime side: `service run` started with a marker
/// pipe as fd 9 (not close-on-exec) closes it at start-up (its reader sees end
/// of file while the runtime serves).
#[cfg(unix)]
#[test]
fn runtime_closes_every_descriptor_inherited_at_startup() {
    let home = Home::new(&[SYNCED]);
    let (reader, writer) = std::io::pipe().unwrap();
    let mut cmd = home.command_with_marker_fd(&["service", "run"]);
    cmd.stdin(writer);
    // Drops the command, and with it the test's own write end.
    let svc = home.start_service_cmd(cmd);
    assert!(
        reaches_eof(reader, Duration::from_secs(30)),
        "the runtime holds a descriptor inherited from its parent"
    );
    svc.stop(&home);
}

// =================================================================================
// N06: service death (process-crash evidence)
// =================================================================================

fn crash_home() -> (Home, PathBuf, PathBuf) {
    let mut home = Home::new(&[SYNCED]);
    let ledger = home.file("effects.ledger");
    let marker = home.file("effect.marker");
    home.env.push((
        "HEIMDALL_TEST_LEDGER".into(),
        ledger.to_str().unwrap().into(),
    ));
    (home, ledger, marker)
}

#[test]
fn a06_service_killed_after_the_effect_while_ensure_waits_then_restart_reconciles_once() {
    let (home, ledger, marker) = crash_home();
    let first = home.start_service(&[
        ("HEIMDALL_TEST_ADAPTER", "lose_reply"),
        ("HEIMDALL_TEST_HANG_AFTER_EFFECT", marker.to_str().unwrap()),
    ]);
    let args = ensure_args("req-k", "work-k", "h1:deploy");
    let waiting = spawn_client(&home, &args);
    wait_for_file(&marker, Duration::from_secs(30));
    assert_eq!(ledger_len(&ledger), 1, "the effect is durably applied");
    std::thread::sleep(Duration::from_millis(300));
    // Process death by exact PID, before the effect's receipt is written.
    first.kill(&home);

    let lost = finish_client(waiting, Duration::from_secs(30));
    assert_eq!(lost.code, 5, "{lost:?}");
    let env = lost.json();
    assert_eq!(env["code"], "SERVICE_UNAVAILABLE");
    assert_eq!(env["data"]["error"]["effect_status"], "unknown");

    // A new service replaces the socket; restart recovery reconciles through the
    // recorded adapter identity; the client's retry replays.
    let second = home.start_service(&[("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let retry = home.run(&args);
    assert_eq!(retry.code, 0, "{retry:?}");
    assert_eq!(retry.code_str(), "ACCESS_READY");
    let op = retry.json()["operation_id"].as_str().unwrap().to_owned();
    assert_eq!(
        home.run(&["operation", "show", &op, "--json"]).json()["state"],
        "succeeded"
    );
    assert_eq!(
        ledger_len(&ledger),
        1,
        "exactly one effect after the restart"
    );
    second.stop(&home);
}

#[test]
fn a06_service_killed_while_operation_wait_waits_then_the_new_socket_replays() {
    let (home, ledger, marker) = crash_home();
    let first = home.start_service(&[
        ("HEIMDALL_TEST_ADAPTER", "lose_reply"),
        ("HEIMDALL_TEST_HANG_AFTER_EFFECT", marker.to_str().unwrap()),
    ]);
    let args = ensure_args("req-w", "work-w", "h2:deploy");
    let accepted = home.run(&with(args.clone(), &["--async"]));
    assert_eq!(accepted.code, 0, "{accepted:?}");
    assert_eq!(accepted.code_str(), "ACCEPTED");
    let op = accepted.json()["operation_id"].as_str().unwrap().to_owned();
    let waiting = spawn_client(
        &home,
        &["operation", "wait", &op, "--timeout-ms", "120000", "--json"],
    );
    wait_for_file(&marker, Duration::from_secs(30));
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(ledger_len(&ledger), 1);
    first.kill(&home);

    let lost = finish_client(waiting, Duration::from_secs(30));
    assert_eq!(lost.code, 5, "{lost:?}");
    assert_eq!(lost.code_str(), "SERVICE_UNAVAILABLE");

    let second = home.start_service(&[("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let waited = home.run(&["operation", "wait", &op, "--timeout-ms", "20000", "--json"]);
    assert_eq!(waited.code, 0, "{waited:?}");
    assert_eq!(waited.json()["state"], "succeeded");
    let replay = home.run(&args);
    assert_eq!(replay.code, 0, "{replay:?}");
    assert_eq!(replay.json()["operation_id"], op.as_str());
    assert_eq!(ledger_len(&ledger), 1, "never a second effect");
    second.stop(&home);
}

// =================================================================================
// Test configuration guard
// =================================================================================

#[test]
fn test_configuration_requires_an_explicit_home() {
    // No HEIMDALL_HOME: refused before anything is created.
    let out = Command::new(bin())
        .args(["service", "run", "--json"])
        .env_remove("HEIMDALL_HOME")
        .env("HEIMDALL_TEST_ADAPTER", "prepare")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    scan("stdout", &stdout);
    assert_eq!(out.status.code(), Some(2), "{stdout}");
    assert_eq!(last_json(&stdout).unwrap()["code"], "USAGE_ERROR");
}

// =================================================================================
// Gap G13: a caller killed while the service runs (plan §6.4)
// =================================================================================

/// Plan §6.4 "kill a caller while the service runs": `access ensure` is killed
/// (SIGKILL through this test's exact `Child` handle) while its operation is in a
/// slow `prepare`; the service keeps the work going (a caller's death is not a
/// cancellation); a retry with the same request ID returns the same operation,
/// `ACCESS_READY`, with exactly one effect in the durable ledger.
#[test]
fn a06_caller_killed_while_the_service_runs_then_the_retry_converges_on_one_effect() {
    let (home, ledger, _marker) = crash_home();
    let svc = home.start_service(&[
        ("HEIMDALL_TEST_ADAPTER", "prepare"),
        ("HEIMDALL_TEST_SLOW_PREPARE_MS", "1500"),
    ]);
    let args = ensure_args("req-kc", "work-kc", "h1:deploy");
    let mut caller = spawn_client(&home, &args);
    // Wait until the runtime holds the caller's operation, then kill the caller.
    let start = Instant::now();
    let op = loop {
        let listed = home.run(&["inspect", "operations", "--json"]);
        if let Some(id) = listed.json()["data"]["operations"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|o| o["operation_id"].as_str())
        {
            break id.to_owned();
        }
        assert!(
            caller.try_wait().unwrap().is_none(),
            "the caller finished before it could be killed"
        );
        assert!(start.elapsed() < Duration::from_secs(30), "no operation");
        std::thread::sleep(Duration::from_millis(20));
    };
    caller.kill().unwrap();
    let status = caller.wait().unwrap();
    assert!(!status.success(), "killed caller: {status:?}");
    let mut partial = String::new();
    if let Some(mut out) = caller.stdout.take() {
        let _ = out.read_to_string(&mut partial);
    }
    scan("killed caller stdout", &partial);
    // Same request ID: the same operation, one effect.
    let retry = home.run(&args);
    assert_eq!(retry.code, 0, "{retry:?}");
    assert_eq!(retry.code_str(), "ACCESS_READY");
    assert_eq!(retry.json()["operation_id"], op.as_str(), "same operation");
    assert_eq!(ledger_len(&ledger), 1, "exactly one effect");
    let shown = home.run(&["operation", "show", &op, "--json"]);
    assert_eq!(shown.json()["state"], "succeeded");
    svc.stop(&home);
}

// =================================================================================
// Gap G17: --require-capability and inspect --preview through the CLI
// =================================================================================

/// `inspect --preview` reports `allowed`, `approval_required` (with the exact
/// delta) and `denied` without any effect, operation or decision record; and
/// `access ensure --require-capability` with an unmet minimum is
/// `CAPABILITY_UNAVAILABLE` (exit 4) with no effect.
#[test]
fn inspect_preview_and_require_capability_have_no_effect() {
    let (home, ledger, _marker) = crash_home();
    let svc = home.start_service(&[("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let preview = |args: &[&str]| {
        let mut all = vec!["inspect", "capabilities", "--json"];
        all.extend_from_slice(args);
        let out = home.run(&all);
        assert_eq!(out.code, 0, "{out:?}");
        out.json()["data"]["preview"].clone()
    };
    let allowed = preview(&["--preview", "ops", "--for", "1h"]);
    assert_eq!(allowed["outcome"], "allowed", "{allowed}");
    let approval = preview(&["--preview", "dev"]);
    assert_eq!(approval["outcome"], "approval_required", "{approval}");
    let added = approval["delta"]["added_scope"]["pairs"].to_string();
    assert!(added.contains("h3"), "exact delta names h3: {approval}");
    assert!(
        !added.contains("h1"),
        "covered pairs are not in the delta: {approval}"
    );
    let denied = preview(&["--preview", "ops", "--require-capability", "git-signing"]);
    assert_eq!(denied["outcome"], "denied", "{denied}");
    assert_eq!(denied["code"], "CAPABILITY_UNAVAILABLE", "{denied}");
    // Minimums without a preview are a usage error.
    let bad = home.run(&[
        "inspect",
        "capabilities",
        "--require-capability",
        "git-signing",
        "--json",
    ]);
    assert_eq!(bad.code, 2, "{bad:?}");
    // ensure with an unmet minimum: exit 4, nothing prepared.
    let unmet = home.run(&with(
        ensure_args("req-rc", "work-rc", "h1:deploy"),
        &["--require-capability", "git-signing"],
    ));
    assert_eq!(unmet.code, 4, "{unmet:?}");
    assert_eq!(unmet.code_str(), "CAPABILITY_UNAVAILABLE");
    // ensure with a met minimum succeeds.
    let met = home.run(&with(
        ensure_args("req-rm", "work-rm", "h1:deploy"),
        &["--require-capability", "ssh-authentication"],
    ));
    assert_eq!(met.code, 0, "{met:?}");
    assert_eq!(ledger_len(&ledger), 1, "only the met request prepared");
    // The previews created no decision record.
    assert!(pending_decisions(&home).is_empty());
    svc.stop(&home);
}

// =================================================================================
// ADR-0006 §13.6 item 8: `service stop` through Request::Shutdown
// =================================================================================

/// `heimdall service stop` asks the runtime to stop with `Request::Shutdown` over
/// the owner's control endpoint (`via: "control"`, on every platform; Unix
/// signals are only the fallback): the runtime drains, removes its advertisement
/// and endpoint, and exits 0; a repeated stop is idempotent (nothing running,
/// exit 0).
#[test]
fn service_stop_sends_shutdown_over_the_control_endpoint_and_is_idempotent() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "prepare")]);
    let mut svc = home.start_service(&[]);
    let pid = svc.pid();
    assert_eq!(
        home.run(&ensure_args("req-st", "work-st", "h1:deploy"))
            .code,
        0
    );
    let out = home.run(&["service", "stop", "--json"]);
    assert_eq!(out.code, 0, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "OK");
    assert_eq!(env["data"]["stopped"], true);
    assert_eq!(env["data"]["via"], "control", "{env}");
    assert_eq!(env["data"]["pid"], pid);
    let mut child = svc.child.take().unwrap();
    let code = wait_timeout(&mut child, Duration::from_secs(30));
    if code.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert_eq!(
        code,
        Some(0),
        "the runtime exits 0 after a Shutdown request"
    );
    svc.scan();
    assert_eq!(home.instance_pid(), None, "advertisement removed");
    #[cfg(unix)]
    assert!(
        !home.path().join("run").join("control.sock").exists(),
        "endpoint removed"
    );
    // Idempotent: nothing is running any more.
    let again = home.run(&["service", "stop", "--json"]);
    assert_eq!(again.code, 0, "{again:?}");
    assert_eq!(again.json()["data"]["running"], false);
    assert_eq!(again.json()["data"]["stopped"], false);
    assert_eq!(home.run(&["service", "status", "--json"]).code, 5);
}

/// An owner-only socket this test binds at the runtime's control endpoint path
/// in place of the runtime's own: it accepts and immediately closes every
/// connection, so `instance.json` still validates (same PID and start time, an
/// owned connectable socket at the advertised path) while no hello can complete.
#[cfg(unix)]
struct DeadControlEndpoint {
    path: PathBuf,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<usize>>,
}

#[cfg(unix)]
impl DeadControlEndpoint {
    fn replace(path: PathBuf) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::atomic::{AtomicBool, Ordering};
        std::fs::remove_file(&path).expect("remove the runtime's control socket");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind replacement");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut accepted = 0;
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    // Dropped at once: the client's hello sees end of stream.
                    Ok((stream, _)) => {
                        accepted += 1;
                        drop(stream);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            accepted
        });
        Self {
            path,
            stop,
            thread: Some(thread),
        }
    }

    /// Stop accepting; the number of connections that were accepted.
    fn close(mut self) -> usize {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let n = self.thread.take().unwrap().join().unwrap();
        // The runtime unlinks only its own socket (same device and inode).
        let _ = std::fs::remove_file(&self.path);
        n
    }
}

#[cfg(unix)]
impl Drop for DeadControlEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// ADR-0006 §13.7 item 8 (the §13.6 item 8 fallback): when the control endpoint
/// cannot be used while the advertisement stays valid, `heimdall service stop`
/// falls back to SIGTERM to the validated advertised PID (`via: "signal"`); the
/// runtime drains, removes its advertisement and exits.
///
/// Unix only. On Windows there is no signal fallback by design (§13.6 item 8,
/// `service_cmd::fallback`): an unusable endpoint is reported, or a runtime that
/// is already stopping is awaited (`via: "exited"`), so this case does not apply.
#[cfg(unix)]
#[test]
fn service_stop_falls_back_to_a_signal_when_the_control_endpoint_is_unusable() {
    let home = Home::new(&[SYNCED]);
    let mut svc = home.start_service(&[]);
    let pid = svc.pid();
    let dead = DeadControlEndpoint::replace(home.path().join("run").join("control.sock"));
    // The advertisement is still valid: status finds the live PID but no hello
    // completes over the replaced endpoint.
    let st = home.run(&["service", "status", "--json"]);
    assert_eq!(st.code, 5, "{st:?}");
    assert_eq!(st.code_str(), "SERVICE_UNAVAILABLE", "{st:?}");
    assert_eq!(
        home.instance_pid(),
        Some(pid),
        "advertisement names the live PID"
    );

    let out = home.run(&["service", "stop", "--json"]);
    assert_eq!(out.code, 0, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "OK", "{env}");
    assert_eq!(env["data"]["stopped"], true, "{env}");
    assert_eq!(env["data"]["via"], "signal", "{env}");
    assert_eq!(env["data"]["pid"], pid, "{env}");

    let mut child = svc.child.take().unwrap();
    let code = wait_timeout(&mut child, Duration::from_secs(30));
    if code.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert_eq!(
        code,
        Some(0),
        "the runtime drains and exits 0 after SIGTERM"
    );
    svc.scan();
    assert_eq!(home.instance_pid(), None, "advertisement removed");
    assert!(
        dead.close() >= 2,
        "both the status and the stop client reached the replaced endpoint"
    );
    // Nothing is running any more.
    let again = home.run(&["service", "stop", "--json"]);
    assert_eq!(again.code, 0, "{again:?}");
    assert_eq!(again.json()["data"]["stopped"], false);
}

/// ADR-0006 §13.6 item 4 (verify) through the real binary: a caller's
/// operation whose `prepare` reports `Unavailable` is answered once with
/// `SERVICE_UNAVAILABLE` (exit 5) and settled `failed`; it is not retried
/// automatically (it stays failed while the runtime keeps running), and the
/// caller's same-key retry replays the same operation.
#[test]
fn unavailable_prepare_exits_5_once_and_the_same_key_replays_the_same_operation() {
    let home = Home::new(&[SYNCED, ("HEIMDALL_TEST_ADAPTER", "unavailable,prepare")]);
    let svc = home.start_service(&[]);
    let args = ensure_args("req-ua", "work-ua", "h1:deploy");
    let first = home.run(&args);
    assert_eq!(first.code, 5, "{first:?}");
    assert_eq!(first.code_str(), "SERVICE_UNAVAILABLE");
    let op = first.json()["operation_id"].as_str().unwrap().to_owned();
    std::thread::sleep(Duration::from_millis(1500));
    // Still failed: nothing retried it (the script's next step would succeed).
    let shown = home.run(&["operation", "show", &op, "--json"]);
    assert_eq!(shown.json()["state"], "failed", "{shown:?}");
    let replay = home.run(&args);
    assert_eq!(replay.code, 5, "{replay:?}");
    assert_eq!(replay.json()["operation_id"], op.as_str());
    // A new request (new key) is a new operation and uses the next step.
    let fresh = home.run(&ensure_args("req-ua2", "work-ua2", "h1:deploy"));
    assert_eq!(fresh.code, 0, "{fresh:?}");
    svc.stop(&home);
}

// =================================================================================
// Review C01: argument (clap) failures under --json (spec §11.2; ADR-0006 §6)
// =================================================================================

/// Exactly one stdout line, a `USAGE_ERROR` envelope (exit 2, effect `none`,
/// `next.action` `fix_request`), with no terminal escapes.
fn assert_one_usage_envelope(out: &Out) {
    assert_eq!(out.code, 2, "{out:?}");
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "exactly one stdout line: {out:?}");
    assert!(out.stdout.ends_with('\n'), "{out:?}");
    assert!(!out.stdout.contains('\u{1b}'), "{out:?}");
    let env: Value = serde_json::from_str(lines[0]).expect("the line is one JSON value");
    // It is a contract envelope, not just JSON.
    let typed: heimdall_contract::envelope::Envelope<Value> =
        serde_json::from_str(lines[0]).expect("a contract envelope");
    assert_eq!(typed.code, heimdall_contract::Code::UsageError);
    assert_eq!(env["schema_version"], "1");
    assert_eq!(env["state"], "failed");
    assert_eq!(env["code"], "USAGE_ERROR");
    assert_eq!(env["data"]["error"]["code"], "USAGE_ERROR");
    assert_eq!(env["data"]["error"]["effect_status"], "none");
    assert_eq!(env["data"]["error"]["retryable"], false);
    assert_eq!(env["next"]["action"], "fix_request");
    assert!(env["warnings"].is_array());
    assert!(env.get("operation_id").is_none(), "nothing was submitted");
}

#[test]
fn json_usage_failures_render_exactly_one_usage_error_envelope() {
    let home = Home::new(&[]);
    // Unknown flag, --json before and after the subcommand.
    for args in [
        vec!["--json", "access", "ensure", "--no-such-flag"],
        vec!["access", "ensure", "--no-such-flag", "--json"],
        vec!["access", "--json", "ensure", "--no-such-flag"],
    ] {
        let out = home.run(&args);
        assert_one_usage_envelope(&out);
        assert_eq!(
            out.json()["data"]["error"]["message"],
            "unknown argument",
            "{args:?}"
        );
    }
    // Missing required arguments / subcommand.
    for (args, message) in [
        (
            vec!["--json", "operation", "show"],
            "missing required argument",
        ),
        (
            vec!["access", "ensure", "--profile", "dev", "--json"],
            "missing required argument",
        ),
        (vec!["access", "--json"], "missing subcommand"),
        (vec!["--json", "no-such-command"], "unknown command"),
        (
            vec![
                "operation",
                "wait",
                "op_x",
                "--timeout-ms",
                "soon",
                "--json",
            ],
            "invalid argument value",
        ),
    ] {
        let out = home.run(&args);
        assert_one_usage_envelope(&out);
        assert_eq!(out.json()["data"]["error"]["message"], message, "{args:?}");
    }
    // The envelope never echoes the offending argument (a value may be a secret
    // or carry terminal escapes); the human diagnostic stays on stderr.
    let echoed = home.run(&["--json", "access", "ensure", "--odd-\u{1b}[31m-flag"]);
    assert_one_usage_envelope(&echoed);
    assert!(!echoed.stdout.contains("odd-"), "{echoed:?}");
    assert!(!echoed.stderr.contains('\u{1b}'), "{echoed:?}");
    assert!(!echoed.stderr.is_empty(), "{echoed:?}");
    // Nothing started a runtime.
    assert_eq!(home.instance_pid(), None);
}

#[test]
fn usage_failures_keep_human_help_version_and_errors() {
    let home = Home::new(&[]);
    // Help and version stay human text on stdout with exit 0, --json or not.
    for args in [
        vec!["--help"],
        vec!["--json", "--help"],
        vec!["access", "ensure", "--help", "--json"],
    ] {
        let out = home.run(&args);
        assert_eq!(out.code, 0, "{out:?}");
        assert!(out.stdout.contains("Usage:"), "{out:?}");
        assert!(last_json(&out.stdout).is_none(), "{out:?}");
    }
    for args in [vec!["--version"], vec!["--json", "--version"]] {
        let out = home.run(&args);
        assert_eq!(out.code, 0, "{out:?}");
        assert!(out.stdout.starts_with("heimdall "), "{out:?}");
        assert!(last_json(&out.stdout).is_none(), "{out:?}");
    }
    // Without --json a usage failure is clap's human text on stderr, exit 2.
    let human = home.run(&["access", "ensure", "--no-such-flag"]);
    assert_eq!(human.code, 2, "{human:?}");
    assert!(human.stdout.is_empty(), "{human:?}");
    assert!(human.stderr.contains("--no-such-flag"), "{human:?}");
    // `--json` after `--` is part of the launched argv, not a Heimdall flag.
    let argv = home.run(&["run", "--no-such-flag", "--", "tool", "--json"]);
    assert_eq!(argv.code, 2, "{argv:?}");
    assert!(argv.stdout.is_empty(), "{argv:?}");
    assert!(!argv.stderr.is_empty(), "{argv:?}");
}

/// ⟨M02⟩ `w0_m02_cli_commands_report_not_available_and_never_panic` (m02-plan U0b
/// wave-0 acceptance; §5 item 4). Hosted here, a `heimdall` package target, because
/// only such a target gets the real binary (wave-0 verify E6). Every M02 command of
/// the U0 clap tree, run through the real binary, exits 2 with M01's "not available
/// in this build" envelope (`USAGE_ERROR`, effect `none`), never panics, and never
/// contacts the runtime: the Heimdall home it names is never created (an on-demand
/// start or a client connection would create it). An argument canary built at run
/// time never reaches any output. `run` and `connect` left this list when wave 3b
/// wired them (m02-plan U8); `heimdall::cli::tests::
/// run_and_connect_parse_and_refuse_before_the_runtime` and `e2e_run_m02` cover them.
#[test]
fn w0_m02_cli_commands_report_not_available_and_never_panic() {
    // ⟨M02⟩ W4-U9: `setup`, `doctor`, `destination`, `identity`, `profile` and
    // `uninstall` are wired and leave this list (`e2e_cli_m02` covers them, with the
    // argument canary).
    // ⟨M02⟩ W4-U10: `tui` is wired and leaves it too (`e2e_tui_m02` covers its
    // refusals before any terminal or runtime contact).
    let lines: Vec<Vec<&str>> = Vec::new();
    let scratch = tempfile::tempdir().expect("scratch");
    for (i, line) in lines.iter().enumerate() {
        let home = scratch.path().join(format!("home-{i}"));
        let mut cmd = Command::new(bin());
        cmd.arg("--json")
            .arg("--non-interactive")
            .arg("--home")
            .arg(&home)
            .args(line);
        for v in TEST_VARS {
            cmd.env_remove(v);
        }
        cmd.env_remove("HEIMDALL_LOG")
            .env("HEIMDALL_HOME", &home)
            .stdin(Stdio::null());
        let out = cmd.output().expect("spawn heimdall");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        scan("stdout", &out.stdout);
        scan("stderr", &out.stderr);
        assert_eq!(out.code, 2, "{line:?}: {out:?}");
        assert!(!out.stderr.contains("panicked"), "{line:?}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], "USAGE_ERROR", "{line:?}: {env}");
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{line:?}");
        assert!(
            env["data"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("not available")),
            "{line:?}: {env}"
        );
        assert!(
            !home.exists(),
            "{line:?} created the Heimdall home, so it reached for the runtime"
        );
    }
    assert_eq!(
        std::fs::read_dir(scratch.path()).map(Iterator::count).ok(),
        Some(0),
        "nothing was created under the scratch directory"
    );
}
