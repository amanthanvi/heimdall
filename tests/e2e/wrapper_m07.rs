//! M07 W3a: the independent Python wrapper talking to the real debug runtime.
#![cfg(all(unix, debug_assertions))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_app::{Attendance, Caller, OpError, Operations};
use heimdall_contract::catalog::{
    CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
    IdentitySourceSpec, IdentitySpec, ProfileSpec,
};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, IdentityId, ProfileId, RequestId,
};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{
    AccessPairRef, DecideRequest, InteractionMode, PolicyAction, Verdict,
};
use heimdall_contract::setup::{PreviewIntent, SetupPlan, SetupRequest};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_localenv::{
    env::{Env, Platform},
    paths::SshPaths,
    projection::ProjectionConfig,
};
use heimdall_runtime::{
    config::{Config, Paths},
    service::{ProjectionWiring, Service, ServiceOptions},
};
use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
use heimdall_testkit::home::{ScratchHome, find_program, ssh_option_path};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const LIMIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(20);
/// The driver and the wrapper it loads, compiled in and written to the scratch root, so a
/// copied test binary (a native run) carries them and nothing reads the compile-time root.
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
const COVERED: &str = "ops";
const PARTLY_COVERED: &str = "dev";
const EXISTING: &str = "lab-access";
const ALIAS: &str = "lab";
const OPERATIONS: &str = "operation_state_changed";
const CURRENT: &str = "1";
const EXTRA_CAPABILITY: &str = "wrapper-unknown/1";

// Baseline CLI and driver vocabulary. U3/U4b can replace the explicit endpoint seam.
mod names {
    pub const RUN: &[&str] = &["service", "run", "--detach"];
    pub const STATUS: &[&str] = &["--json", "service", "status"];
    pub const STOP: &[&str] = &["service", "stop"];
    pub const APPROVE: &[&str] = &["--json", "decision", "approve"];
    pub const SHOW_SCHEMA: &[&str] = &["schema", "show"];
    pub const CONTROL: &str = "run/control.sock";
    pub const HELLO: &str = "hello";
    pub const REQUEST: &str = "request";
    pub const ATTEND: &str = "attend";
    pub const SUBSCRIBE: &str = "subscribe";
    pub const STEP: &str = "step";
    pub const STOP_STREAM: &str = "stop_stream";
    pub const BACKPRESSURE: &str = "backpressure";
    pub const INSPECT: &str = "inspect";
    pub const ENSURE: &str = "ensure";
    pub const BIND: &str = "bind";
    pub const RELEASE: &str = "release";
    pub const SHOW: &str = "show";
    pub const WAIT: &str = "wait";
    pub const CANCEL: &str = "cancel";
    pub const EVENTS: &str = "events";
}

struct Process(Child);

impl Process {
    fn start(command: &mut Command, name: &str) -> Self {
        Self(
            command
                .spawn()
                .unwrap_or_else(|e| panic!("{name} failed to start: {}", e.kind())),
        )
    }

    fn within(&mut self, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(POLL);
        }
    }

    fn wait(&mut self, name: &str) -> ExitStatus {
        self.within(LIMIT)
            .unwrap_or_else(|| panic!("{name} did not exit within {LIMIT:?}"))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let stopped = self.within(Duration::from_secs(3)).is_some();
            if !std::thread::panicking() {
                assert!(
                    stopped,
                    "the owned fixture child did not exit after being killed"
                );
            }
        }
    }
}

struct Output {
    status: ExitStatus,
    stdout: String,
}

struct World {
    // Stop the process before dropping the scratch root, including on panic.
    service: Option<Process>,
    home: ScratchHome,
    heimdall_home: PathBuf,
    ssh_home: PathBuf,
    bin: PathBuf,
    environment: Option<String>,
}

impl World {
    fn new() -> Self {
        let home = ScratchHome::new();
        let heimdall_home = home.scratch().subdir("hm").unwrap();
        let ssh_home = home.scratch().subdir("ssh").unwrap();
        fs::create_dir_all(ssh_home.join("etc-ssh")).unwrap();
        let bin = std::env::var_os("HEIMDALL_E2E_BIN")
            .filter(|path| !path.is_empty())
            .map_or_else(
                || PathBuf::from(env!("CARGO_BIN_EXE_heimdall")),
                PathBuf::from,
            );
        let bin = bin.canonicalize().expect("debug binary");
        let world = Self {
            service: None,
            home,
            heimdall_home,
            ssh_home,
            bin,
            environment: None,
        };
        world.check_env(&world.command(&world.bin));
        world
    }

    fn command(&self, bin: &Path) -> Command {
        let mut command = Command::new(bin);
        command
            .env_clear()
            .env("PATH", PATH)
            .env("LANG", "C")
            .env("TERM", "dumb")
            .env("HOME", &self.home.git_home)
            .env("HEIMDALL_HOME", &self.heimdall_home)
            .env("HEIMDALL_TEST_SSH_HOME", &self.ssh_home)
            .current_dir(&self.home.root)
            .stdin(Stdio::null());
        command
    }

    fn check_env(&self, command: &Command) {
        let vars: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        let root = self.home.root.canonicalize().unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for (name, expected) in [
            ("HOME", &self.home.git_home),
            ("HEIMDALL_HOME", &self.heimdall_home),
            ("HEIMDALL_TEST_SSH_HOME", &self.ssh_home),
        ] {
            let path = Path::new(
                vars.get(OsStr::new(name))
                    .expect("missing rule-4 key")
                    .expect("removed rule-4 key"),
            )
            .canonicalize()
            .expect("rule-4 directory must exist");
            assert!(
                path.is_dir() && path != root && path.starts_with(&root),
                "unsafe rule-4 directory"
            );
            assert!(
                path == expected.canonicalize().unwrap(),
                "wrong directory for {name}"
            );
            assert!(seen.insert(path), "aliased rule-4 directories");
        }
        assert!(!vars.contains_key(OsStr::new("SSH_AUTH_SOCK")));
        assert!(
            self.ssh_home
                .join("etc-ssh")
                .read_dir()
                .unwrap()
                .next()
                .is_none()
        );
    }

    fn spawn(&self, command: &mut Command, name: &str) -> Process {
        self.check_env(command);
        Process::start(command, name)
    }

    fn checked_output(&self, command: &mut Command, name: &str) -> Output {
        let mut out = tempfile::tempfile_in(&self.home.root).unwrap();
        let err = tempfile::tempfile_in(&self.home.root).unwrap();
        command
            .stdout(out.try_clone().unwrap())
            .stderr(err.try_clone().unwrap());
        let status = self.spawn(command, name).wait(name);
        use std::io::{Seek as _, SeekFrom};
        out.seek(SeekFrom::Start(0)).unwrap();
        let stdout = read_output(out);
        let mut err = err;
        err.seek(SeekFrom::Start(0)).unwrap();
        let _ = read_output(err);
        Output { status, stdout }
    }

    fn cli(&self, args: &[&str]) -> Output {
        self.checked_output(self.command(&self.bin).args(args), args[0])
    }

    fn start(&mut self, extra: &[(&str, &OsStr)]) {
        assert!(self.service.is_none());
        self.service = Some(
            self.spawn(
                self.command(&self.bin)
                    .args(names::RUN)
                    .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
                    .env("HEIMDALL_TEST_SECRET_STORE", "scratch")
                    .envs(extra.iter().copied())
                    .process_group(0)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null()),
                "fixture service",
            ),
        );
        let deadline = Instant::now() + LIMIT;
        loop {
            let status = self.cli(names::STATUS);
            let service = self.service.as_mut().unwrap();
            if status.status.success() {
                let data = &parse(&status.stdout)["data"];
                assert_eq!(data["pid"].as_u64(), Some(u64::from(service.0.id())));
                let environment = field(data, "environment_id");
                if let Some(previous) = &self.environment {
                    assert!(
                        previous == environment,
                        "fixture environment changed across restart"
                    );
                }
                self.environment = Some(environment.to_owned());
                return;
            }
            assert!(
                service.0.try_wait().unwrap().is_none(),
                "fixture service exited before readiness"
            );
            assert!(
                Instant::now() < deadline,
                "service status never reported ready"
            );
            std::thread::sleep(POLL);
        }
    }

    fn stop(&mut self) {
        assert!(
            self.cli(names::STOP).status.success(),
            "service stop failed"
        );
        assert!(
            self.service
                .take()
                .unwrap()
                .wait("fixture service")
                .success()
        );
    }

    fn driver(&self) -> Driver {
        let python = find_program("python3").expect("python3 is required for the wrapper journey");
        let dir = self.home.root.join("reference-wrapper");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, source) in WRAPPER_FILES {
            std::fs::write(dir.join(name), source).unwrap();
        }
        let script = dir.join("journey.py");
        let path = self.heimdall_home.join(names::CONTROL);
        let output = tempfile::NamedTempFile::new_in(&self.home.root).unwrap();
        let error = tempfile::tempfile_in(&self.home.root).unwrap();
        let mut process = self.spawn(
            self.command(&python)
                .args(["-I", "-B"])
                .arg(script)
                .arg(path)
                .arg(self.environment.as_ref().expect("start the runtime first"))
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .stdin(Stdio::piped())
                .stdout(output.reopen().unwrap())
                .stderr(error),
            "isolated Python journey",
        );
        let reader = BufReader::new(output.reopen().unwrap());
        let stdin = process.0.stdin.take().unwrap();
        Driver {
            process,
            stdin,
            output: reader,
        }
    }

    fn approve(&self, decision: &str) {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
        fcntl_setfl(&master, fcntl_getfl(&master).unwrap() | OFlags::NONBLOCK).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = File::from(
            rustix::fs::open(
                Path::new(OsStr::from_bytes(name.as_bytes())),
                OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap(),
        );
        let mut child = self.spawn(
            self.command(&self.bin)
                .args(names::APPROVE)
                .arg(decision)
                .stdin(slave.try_clone().unwrap())
                .stdout(slave.try_clone().unwrap())
                .stderr(slave),
            "attended decision",
        );
        let mut terminal = File::from(master);
        let mut transcript = Vec::new();
        let mut confirmed = false;
        let deadline = Instant::now() + LIMIT;
        loop {
            let mut buffer = [0; 4096];
            match terminal.read(&mut buffer) {
                Ok(n) => transcript.extend(&buffer[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                // On Linux a master read after the last slave closes may return EIO.
                Err(e)
                    if e.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error())
                        && child.0.try_wait().unwrap().is_some() => {}
                Err(e) => panic!("pty read failed: {}", e.kind()),
            }
            let text = String::from_utf8_lossy(&transcript);
            heimdall_testkit::assert_no_canary(&text);
            assert!(
                transcript.len() < 64 * 1024,
                "oversized terminal transcript"
            );
            if !confirmed && text.contains("[y/N]: ") {
                terminal.write_all(b"yes\n").unwrap();
                confirmed = true;
            }
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(
                    confirmed && status.success(),
                    "the attended approval did not complete ({status})"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "terminal approval did not finish"
            );
            std::thread::sleep(POLL);
        }
    }
}

fn read_output(file: File) -> String {
    let mut text = String::new();
    file.take(2 * 1024 * 1024)
        .read_to_string(&mut text)
        .unwrap();
    heimdall_testkit::assert_no_canary(&text);
    text
}

fn parse(text: &str) -> Value {
    heimdall_testkit::assert_no_canary(text);
    serde_json::from_str(text).expect("expected one JSON result")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| panic!("missing string field {name}"))
}

fn code(value: &Value, expected: &str) {
    let actual = field(value, "code");
    assert_eq!(actual, expected);
}

struct Driver {
    process: Process,
    stdin: ChildStdin,
    output: BufReader<File>,
}

impl Driver {
    fn call(&mut self, command: &str, args: Value) -> Value {
        let line = json!({"command": command, "args": args}).to_string();
        assert!(line.len() < 4000, "oversized driver command");
        writeln!(self.stdin, "{line}").unwrap();
        let deadline = Instant::now() + LIMIT;
        let mut answer = Vec::new();
        loop {
            self.output.read_until(b'\n', &mut answer).unwrap();
            if answer.last() == Some(&b'\n') {
                let reply = parse(std::str::from_utf8(&answer).unwrap());
                assert!(
                    reply.get("driver_error").is_none(),
                    "driver failed during {command}: {}",
                    reply["driver_error"]
                );
                return reply;
            }
            if let Some(status) = self.process.0.try_wait().unwrap() {
                panic!("driver exited during {command} ({status})");
            }
            assert!(
                Instant::now() < deadline,
                "driver timed out during {command}"
            );
            std::thread::sleep(POLL);
        }
    }

    fn request(&mut self, kind: &str, fields: Value) -> Value {
        let reply = self.call(names::REQUEST, json!({"kind":kind, "fields":fields}));
        assert_eq!(reply["requests_sent"], 1);
        reply["result"].clone()
    }

    fn finish(self) {
        let Self {
            mut process, stdin, ..
        } = self;
        drop(stdin);
        assert!(process.wait("Python journey driver").success());
    }
}

fn ensure(profile: &str, work_id: &str) -> Value {
    json!({"profile": profile, "work_id": work_id, "request_id": work_id})
}

fn pair(destination: &str) -> Value {
    json!([{"destination": destination, "account": "deploy"}])
}

#[test]
fn missing_rule_four_home_prevents_process_launch() {
    let world = World::new();
    let marker = world.home.root.join("unexpected-child");
    for name in ["HOME", "HEIMDALL_HOME", "HEIMDALL_TEST_SSH_HOME"] {
        let mut command = world.command(Path::new("/usr/bin/touch"));
        command.arg(&marker).env_remove(name);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            world
                .spawn(&mut command, "rule-4 tripwire")
                .wait("rule-4 tripwire");
        }));
        assert!(refused.is_err(), "launch accepted a missing {name}");
        assert!(!marker.exists(), "launch occurred without {name}");
    }
}

#[test]
fn hello_inspect_and_version_skew() {
    let mut world = World::new();
    world.start(&[]);
    let mut driver = world.driver();
    let capabilities = driver.call(names::HELLO, json!({"required":["events/1"]}));
    assert!(
        capabilities["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("events/1"))
    );
    let inspect = driver.request(names::INSPECT, json!({"subject":"capabilities"}));
    code(&inspect, "OK");
    assert!(
        inspect["data"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("operations/1"))
    );
    let inspect = driver.request(names::INSPECT, json!({"subject":"destinations"}));
    code(&inspect, "OK");
    assert!(inspect["data"]["items"].is_array());
    for options in [
        json!({"major":"2"}),
        json!({
            "offered":[EXTRA_CAPABILITY], "required":[EXTRA_CAPABILITY],
        }),
    ] {
        let hello = driver.call(names::HELLO, options);
        code(&hello["refusal"], "SCHEMA_UNSUPPORTED");
    }
    let optional = driver.call(
        names::HELLO,
        json!({
            "offered":["events/1",EXTRA_CAPABILITY], "required":["events/1"],
        }),
    );
    assert_eq!(optional["capabilities"], json!(["events/1"]));

    for (schema, discriminator, expected) in [
        (
            "ipc.client-message",
            "type",
            &["hello", "request", "attend", "subscribe"][..],
        ),
        (
            "ipc.server-message",
            "type",
            &["hello", "reject", "response", "subscribed", "event"],
        ),
        (
            "request",
            "op",
            &["inspect", "ensure", "observe", "bind", "release", "cancel"],
        ),
    ] {
        let mut args = names::SHOW_SCHEMA.to_vec();
        args.push(schema);
        let out = world.cli(&args);
        assert!(out.status.success(), "schema show failed for {schema}");
        let printed = parse(&out.stdout);
        let nodes = printed["data"]["oneOf"]
            .as_array()
            .expect("discriminated schema");
        for tag in expected {
            assert!(
                nodes.iter().any(|node| {
                    let selector = &node["properties"][discriminator];
                    selector["const"] == *tag
                        || selector["enum"]
                            .as_array()
                            .is_some_and(|items| items.contains(&json!(tag)))
                }),
                "{schema} lacks {tag}"
            );
        }
    }
    driver.finish();
    world.stop();
}

#[test]
fn covered_ensure_replay_and_conflict() {
    let mut world = World::new();
    world.start(&[]);
    let mut driver = world.driver();
    let args = ensure(COVERED, "wrapper-covered");
    let first = driver.request(names::ENSURE, args.clone());
    code(&first, "ACCESS_READY");
    assert_eq!(first["schema_version"], CURRENT);
    assert_eq!(first["state"], "succeeded");
    let operation = field(&first, "operation_id");
    let replayed = driver.request(names::ENSURE, args.clone());
    code(&replayed, "ACCESS_READY");
    assert!(field(&replayed, "operation_id") == operation);
    assert!(field(&replayed["data"], "binding_id") == field(&first["data"], "binding_id"));
    let mut changed = args;
    changed["work_id"] = json!("different-work");
    let conflict = driver.request(names::ENSURE, changed);
    code(&conflict, "REQUEST_CONFLICT");
    assert_eq!(conflict["data"]["error"]["effect_status"], "none");
    driver.finish();
    world.stop();
}

#[test]
fn wider_scope_needs_real_terminal_approval() {
    let mut world = World::new();
    world.start(&[]);
    let mut driver = world.driver();
    let mut args = ensure(PARTLY_COVERED, "wrapper-covered-subset");
    args["scope"] = pair("h1");
    code(&driver.request(names::ENSURE, args), "ACCESS_READY");
    let args = ensure(PARTLY_COVERED, "wrapper-wider");
    let pending = driver.request(names::ENSURE, args.clone());
    // The baseline names an unattended approval requirement INTERACTION_REQUIRED.
    // Keep the typed decision reference and leave the attended decision to the CLI.
    code(&pending, "INTERACTION_REQUIRED");
    assert_eq!(pending["state"], "awaiting_approval");
    assert_eq!(pending["data"]["error"]["effect_status"], "none");
    let decision = field(&pending["next"], "decision_ref");
    let op = field(&pending, "operation_id");
    let denied = driver.call(names::ATTEND, json!({}));
    code(&denied["before"], "OK");
    code(&denied["after"], "OK");
    code(&denied["denied"], "INTERACTION_REQUIRED");
    assert_eq!(denied["denied"]["data"]["error"]["effect_status"], "none");
    assert!(
        denied["before"]["data"] == denied["after"]["data"],
        "denied attendance changed the bindings"
    );
    let still_pending = driver.request(names::SHOW, json!({"operation_id":op}));
    code(&still_pending, "OK");
    assert!(
        still_pending["state"] == pending["state"],
        "denied attendance changed the operation"
    );
    world.approve(decision);
    let ready = driver.request(names::ENSURE, args);
    code(&ready, "ACCESS_READY");
    assert!(field(&ready, "operation_id") == op);
    driver.finish();
    world.stop();
}

#[test]
fn bounded_wait_and_backpressure_leave_the_operation_running_until_cancelled() {
    let mut world = World::new();
    world.start(&[("HEIMDALL_TEST_SLOW_PREPARE_MS", OsStr::new("6500"))]);
    let mut driver = world.driver();
    let mut args = ensure(COVERED, "wrapper-held");
    args["wait"] = json!({"mode":"async"});
    let accepted = driver.request(names::ENSURE, args);
    code(&accepted, "ACCEPTED");
    let op = field(&accepted, "operation_id");
    let wait_started = Instant::now();
    let bounded = driver.request(names::WAIT, json!({"operation_id":op,"wait_ms":75}));
    assert!(wait_started.elapsed() >= Duration::from_millis(75));
    code(&bounded, "OK");
    assert_eq!(bounded["state"], "running");
    assert_eq!(bounded["next"]["action"], "observe");

    let pressure = driver.call(names::BACKPRESSURE, json!({"operation_id":op}));
    code(&pressure["refusal"], "BACKPRESSURE");
    assert_eq!(
        pressure["refusal"]["data"]["error"]["effect_status"],
        "none"
    );
    assert_eq!(pressure["defaults"]["retryable"], true);
    assert_eq!(pressure["defaults"]["success"], false);
    assert_eq!(pressure["requests_sent"], 17);
    for seq in 1..=16 {
        assert_eq!(pressure["remaining"][seq.to_string()], "OK");
    }

    let still_running = driver.request(names::SHOW, json!({"operation_id":op}));
    assert_eq!(still_running["state"], "running");
    code(
        &driver.request(names::CANCEL, json!({"operation_id":op})),
        "OK",
    );
    let cancelled = driver.request(names::SHOW, json!({"operation_id":op}));
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["data"]["code"], "OPERATION_CANCELLED");
    driver.finish();
    world.stop();
}

fn applied_event(driver: &mut Driver, operation: &str) -> String {
    for _ in 0..12 {
        let step = driver.call(names::STEP, json!({}));
        assert_eq!(
            step["continued"], true,
            "the event stream ended before applying the operation"
        );
        let applied = step["applied"].as_array().unwrap();
        if let [event, checkpoint] = applied.as_slice() {
            let event = &event["event"];
            assert_eq!(event["type"], OPERATIONS);
            assert_eq!(event["cursor"], checkpoint["checkpoint"]);
            assert_eq!(step["cursor"], checkpoint["checkpoint"]);
            if event["operation_id"] == operation {
                return field(&step, "cursor").to_owned();
            }
        }
    }
    panic!("the operation did not appear within 12 event frames");
}

fn assert_snapshot(start: &Value) {
    let cursor = field(start, "cursor");
    assert!(field(&start["head"]["snapshot"], "cursor") == cursor);
    assert!(start["applied"] == json!([{"snapshot":cursor},{"checkpoint":cursor}]));
}

#[test]
fn event_checkpoint_survives_disconnect_and_resumes_the_same_filter() {
    let mut world = World::new();
    world.start(&[]);
    let mut driver = world.driver();
    let filter = json!({"types":[OPERATIONS]});
    let start = driver.call(names::SUBSCRIBE, json!({"filter":filter}));
    assert_snapshot(&start);
    let first = driver.request(names::ENSURE, ensure(COVERED, "wrapper-events-first"));
    code(&first, "ACCESS_READY");
    let checkpoint = applied_event(&mut driver, field(&first, "operation_id"));

    world.stop();
    // Drain any already-queued events, then observe actual EOF from the stopped runtime.
    let mut previous = checkpoint;
    let mut saw_disconnect = false;
    for _ in 0..12 {
        let read = driver.call(names::STEP, json!({}));
        if read["continued"] == false {
            assert_eq!(read["ending"], "disconnected");
            assert!(read["cursor"] == previous);
            assert_eq!(read["applied"], json!([]));
            saw_disconnect = true;
            break;
        }
        previous = field(&read, "cursor").to_owned();
    }
    assert!(
        saw_disconnect,
        "stopped runtime did not disconnect the wrapper stream"
    );
    world.start(&[]);
    let second = driver.request(names::ENSURE, ensure(COVERED, "wrapper-events-offline"));
    code(&second, "ACCESS_READY");
    let resumed = driver.call(names::SUBSCRIBE, json!({}));
    assert_eq!(resumed["sent"].as_array().unwrap().len(), 1);
    assert!(resumed["sent"][0]["filter"] == filter);
    assert!(resumed["sent"][0]["from_cursor"] == previous);
    assert!(resumed["head"]["snapshot"].is_null());
    assert!(resumed["cursor"] == previous);
    assert_eq!(resumed["applied"], json!([]));
    let checkpoint = applied_event(&mut driver, field(&second, "operation_id"));
    assert!(checkpoint != previous);
    driver.call(names::STOP_STREAM, json!({}));
    driver.finish();
    world.stop();
}

#[test]
fn expired_history_recovers_with_one_subscription_and_replacement_snapshot() {
    let mut world = World::new();
    world.start(&[]);
    let mut driver = world.driver();
    let filter = json!({"types":[OPERATIONS]});
    let start = driver.call(names::SUBSCRIBE, json!({"filter":filter}));
    assert_snapshot(&start);
    let checkpoint = field(&start, "cursor");
    driver.call(names::STOP_STREAM, json!({}));
    let missed = driver.request(names::ENSURE, ensure(COVERED, "wrapper-missed-by-trim"));
    code(&missed, "ACCESS_READY");
    let retained = driver.request(names::EVENTS, json!({"cursor":checkpoint,"filter":filter}));
    code(&retained, "OK");
    assert!(
        retained["data"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| { event["operation_id"] == missed["operation_id"] })
    );
    world.stop();

    // Configure real retention and let the startup maintenance pass trim the
    // missed events. Prove the old cursor was refused before resubscribing.
    let config = Paths::under(&world.heimdall_home)
        .config_dir
        .join("config.toml");
    fs::write(
        config,
        "schema_version = 1\n[retention]\noperations = \"7d\"\nevents = \"1s\"\n",
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    world.start(&[]);
    let deadline = Instant::now() + LIMIT;
    loop {
        let page = driver.request(names::EVENTS, json!({"cursor":checkpoint,"filter":filter}));
        if page["code"] == "RESYNC_REQUIRED" {
            break;
        }
        code(&page, "OK");
        assert!(
            Instant::now() < deadline,
            "event retention did not invalidate the old checkpoint"
        );
        std::thread::sleep(POLL);
    }
    let replacement = driver.call(names::SUBSCRIBE, json!({}));
    assert_eq!(replacement["sent"].as_array().unwrap().len(), 1);
    assert!(replacement["sent"][0]["from_cursor"] == checkpoint);
    assert!(replacement["sent"][0]["filter"] == filter);
    assert_snapshot(&replacement);
    assert!(replacement["cursor"] != checkpoint);
    let current = driver.request(names::ENSURE, ensure(COVERED, "wrapper-after-trim"));
    code(&current, "ACCESS_READY");
    applied_event(&mut driver, field(&current, "operation_id"));
    driver.finish();
    world.stop();
}

#[test]
fn lost_reply_is_observed_and_reconciled_without_resending_ensure() {
    let mut world = World::new();
    let ledger = world.home.root.join("fixture-effects");
    world.start(&[
        ("HEIMDALL_TEST_ADAPTER", OsStr::new("lose_reply,prepare")),
        ("HEIMDALL_TEST_LEDGER", ledger.as_os_str()),
    ]);
    let mut driver = world.driver();
    let uncertain = driver.request(names::ENSURE, ensure(COVERED, "wrapper-lost-reply"));
    code(&uncertain, "OUTCOME_UNKNOWN");
    assert_eq!(uncertain["data"]["error"]["effect_status"], "unknown");
    assert_eq!(uncertain["data"]["error"]["retryable"], false);
    assert_eq!(uncertain["next"]["action"], "reconcile");
    let operation = field(&uncertain, "operation_id");
    let before = driver.request(names::SHOW, json!({"operation_id":operation}));
    code(&before, "OK");
    assert_eq!(before["state"], "outcome_unknown");
    world.stop();
    // Use the existing startup recovery pass and the same fixture ledger.
    world.start(&[("HEIMDALL_TEST_LEDGER", ledger.as_os_str())]);
    let reconciled = driver.request(
        names::WAIT,
        json!({"operation_id":operation,"wait_ms":1000}),
    );
    code(&reconciled, "OK");
    assert_eq!(reconciled["state"], "succeeded");
    assert!(field(&reconciled, "operation_id") == operation);
    assert_eq!(reconciled["data"]["code"], "ACCESS_READY");
    let effects = heimdall_testkit::FakeCredentialAdapter::ledger_entries(&ledger).unwrap();
    assert_eq!(effects.len(), 1, "reconciliation repeated the effect");
    driver.finish();
    world.stop();
}

async fn approve_seed(ops: &Operations, caller: &Caller, pending: OpError) {
    let decision = pending.next.decision_ref.expect("fixture seed decision");
    ops.decide(
        caller,
        DecideRequest {
            decision_id: DecisionId::parse(&decision).unwrap(),
            verdict: Verdict::Approve,
        },
    )
    .await
    .unwrap();
}

async fn seed_existing_access(
    world: &World,
    key: &FixtureKey,
    agent: &FakeAgent,
    sshd: &LoopbackSshd,
) {
    // Seed through the same operations as cli_m07. The seeder never serves these
    // requests on the wire. The Python journey connects only to the real binary
    // after the seeder and its runtime lock have been dropped.
    let paths = Paths::under(&world.heimdall_home);
    let mut projection = ProjectionConfig::new(
        SshPaths::with_test_override(world.ssh_home.clone(), world.ssh_home.join("etc-ssh")),
        Platform::current(),
        paths.config_dir.clone(),
    )
    .with_state_dir(paths.state_dir.clone());
    projection.env = Env::from_vars([
        ("HOME", world.home.git_home.display().to_string()),
        ("PATH", PATH.to_owned()),
    ]);
    let mut options = ServiceOptions::with_clock(
        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap()),
        heimdall_testkit::ScriptedTimeSync::new(heimdall_domain::time::SyncStatus::Synchronized),
    );
    options.projection = ProjectionWiring::Config(Box::new(projection));
    options.existing_access = true;
    let stop = CancellationToken::new();
    let service = tokio::time::timeout(
        LIMIT,
        Service::start_with(paths, Config::default(), options, stop.clone()),
    )
    .await
    .expect("fixture seeder did not start")
    .unwrap();
    let ops = service.operations();
    let caller = Caller {
        context: CallerContext {
            principal: PrincipalRef::UnixUser {
                uid: fs::metadata(&world.home.root).unwrap().uid(),
            },
            role: ClientRole::Owner,
            remote_client: None,
        },
        attendance: Attendance::Attended {
            since: heimdall_contract::Timestamp::now(),
        },
        interaction: InteractionMode::Interactive,
    };
    tokio::time::timeout(LIMIT, async {
        let request_id = |name| RequestId::parse(name).unwrap();
        let adopted = ops
            .catalog(
                &caller,
                CatalogRequest::AdoptIdentity {
                    identity: IdentitySpec {
                        source: IdentitySourceSpec::NativeAgent {
                            endpoint: EndpointRef {
                                kind: EndpointKind::UnixSocket,
                                locator: agent.endpoint().locator().into_string().unwrap(),
                            },
                        },
                        public_key: key.public_line_without_comment(),
                        label: None,
                    },
                    request_id: request_id("wrapper-adopt"),
                },
            )
            .await
            .unwrap();
        let identity = IdentityId::parse(field(&adopted.data, "identity_id")).unwrap();
        let account = world.checked_output(
            world.command(Path::new("/usr/bin/id")).arg("-un"),
            "fixture account",
        );
        assert!(account.status.success());
        let account = AccountName::parse(account.stdout.trim()).unwrap();
        let destination = DestinationId::parse("dst-lab").unwrap();
        ops.catalog(
            &caller,
            CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: destination.clone(),
                    alias: ALIAS.into(),
                    definition: DestinationDefinitionSpec::Managed {
                        hostname: sshd.host.clone(),
                        port: Some(sshd.port),
                        account: account.clone(),
                        identity: identity.clone(),
                        jump: None,
                    },
                    label: None,
                },
                request_id: request_id("wrapper-destination"),
            },
        )
        .await
        .unwrap();
        let profile = ProfileId::parse(EXISTING).unwrap();
        ops.catalog(
            &caller,
            CatalogRequest::UpsertProfile {
                profile: ProfileSpec {
                    id: profile.clone(),
                    pairs: [AccessPairRef {
                        destination,
                        account,
                    }]
                    .into_iter()
                    .collect(),
                    label: None,
                },
                request_id: request_id("wrapper-profile"),
            },
        )
        .await
        .unwrap();
        let preview = ops
            .setup(
                &caller,
                SetupRequest::Preview {
                    intent: PreviewIntent::Apply {
                        include_git: false,
                        items: Default::default(),
                        distribution: None,
                    },
                },
            )
            .await
            .unwrap();
        let plan: SetupPlan = serde_json::from_value(preview.data).unwrap();
        let apply = SetupRequest::Apply {
            plan_digest: plan.plan_digest,
            request_id: request_id("wrapper-apply"),
        };
        if let Err(pending) = ops.setup(&caller, apply.clone()).await {
            approve_seed(ops, &caller, pending).await;
            ops.setup(&caller, apply).await.unwrap();
        }
        let declare = CatalogRequest::DeclareInteraction {
            identity,
            interaction: DeclaredInteraction::None,
            request_id: request_id("wrapper-declare"),
        };
        let pending = ops.catalog(&caller, declare.clone()).await.unwrap_err();
        approve_seed(ops, &caller, pending).await;
        ops.catalog(&caller, declare).await.unwrap();
        let pending = ops
            .policy(
                &caller,
                PolicyAction::Create {
                    profile,
                    environments: [ops.environment().clone()].into_iter().collect(),
                    max_window: None,
                    default: false,
                },
            )
            .await
            .unwrap_err();
        approve_seed(ops, &caller, pending).await;
    })
    .await
    .expect("existing-access fixture seeding timed out");
    stop.cancel();
}

#[tokio::test(flavor = "current_thread")]
async fn materialize_log_in_and_release_through_the_wrapper() {
    assert!(
        std::env::var_os("HM_FIXTURE_SSHD_PORT").is_none(),
        "the wrapper suite starts an owned loopback sshd"
    );
    let mut world = World::new();
    let key = FixtureKey::generate().with_comment("wrapper-fixture");
    let agent = FakeAgent::start(
        Endpoint::in_scratch(world.home.scratch(), "wrapper").unwrap(),
        FakeAgentConfig {
            keys: vec![key.clone()],
            mode: AgentMode::Normal,
        },
    );
    let sshd = LoopbackSshd::start(
        world.home.scratch(),
        SshdConfig {
            authorized: vec![key.public().clone()],
            ..SshdConfig::default()
        },
    )
    .expect("the loopback sshd fixture is required");
    world.home.trust_host_key(&sshd.host_key_line).unwrap();
    seed_existing_access(&world, &key, &agent, &sshd).await;
    world.start(&[]);
    let mut driver = world.driver();
    let mut minimum = ensure(EXISTING, "wrapper-unattended");
    minimum["required_capabilities"] = json!({"unattended":true});
    let refusal = driver.request(names::ENSURE, minimum);
    code(&refusal, "CAPABILITY_UNAVAILABLE");
    assert_eq!(refusal["data"]["error"]["effect_status"], "none");
    let bindings = driver.request(names::INSPECT, json!({"subject":"bindings"}));
    code(&bindings, "OK");
    assert_eq!(bindings["data"]["bindings"], json!([]));

    let ready = driver.request(names::ENSURE, ensure(EXISTING, "wrapper-real-login"));
    code(&ready, "ACCESS_READY");
    let original = field(&ready["data"], "binding_id");
    let bound = driver.request(
        names::BIND,
        json!({"binding_id":original, "request_id":"wrapper-materialize"}),
    );
    code(&bound, "ACCESS_READY");
    let binding = field(&bound["data"], "binding_id");
    let consumer = &bound["data"]["consumer"];
    let pairs = consumer["pairs"].as_array().unwrap();
    assert_eq!(pairs.len(), 1);
    let pair = &pairs[0];
    let alias = field(pair, "alias");
    assert_eq!(alias, ALIAS);
    assert_eq!(
        pair["endpoint"]["locator"],
        agent.endpoint().locator().to_str().unwrap()
    );
    let executable = consumer["executables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["consumer"] == "ssh")
        .expect("descriptor did not supply ssh");
    let ssh = Path::new(field(executable, "path"));
    assert!(ssh.is_absolute());
    let identity = world.home.root.join("fixture-login-key");
    key.write_private(&identity).unwrap();
    let config = world.ssh_home.join(".ssh/config");
    assert!(config.is_file());
    let login = world.checked_output(
        world
            .command(ssh)
            .arg("-F")
            .arg(config)
            .args([
                "-T",
                "-oIdentityFile=none",
                "-oIdentitiesOnly=yes",
                "-oIdentityAgent=none",
                "-oCertificateFile=none",
                "-oGlobalKnownHostsFile=/dev/null",
                "-oControlMaster=no",
                "-oControlPath=none",
                "-oBatchMode=yes",
                "-oStrictHostKeyChecking=yes",
                "-oConnectTimeout=3",
            ])
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                ssh_option_path(&world.home.known_hosts)
            ))
            .arg("-i")
            .arg(identity)
            .args(["--", alias, "echo wrapper-fixture-login"]),
        "fixture SSH login",
    );
    assert!(
        login.status.success(),
        "descriptor-driven SSH login failed ({})",
        login.status
    );
    assert_eq!(login.stdout.trim(), "wrapper-fixture-login");
    let accepted = sshd.accepted_log();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].fingerprint, key.fingerprint());

    for id in std::collections::BTreeSet::from([binding, original]) {
        let release = driver.request(names::RELEASE, json!({"binding_id":id}));
        code(&release, "OK");
        assert_eq!(release["data"]["binding_id"], id);
        assert_eq!(release["data"]["outcome"]["outcome"], "released");
    }
    let released = driver.request(names::INSPECT, json!({"subject":"bindings"}));
    code(&released, "OK");
    assert!(
        !released["data"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |entry| (entry["binding_id"] == binding || entry["binding_id"] == original)
                    && entry["state"] == "active"
            )
    );
    driver.finish();
    world.stop();
}
