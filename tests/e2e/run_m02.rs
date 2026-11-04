//! M02-U8 end-to-end suite: `heimdall run` and `heimdall connect` through the **real
//! binary** (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN` for a copied binary) and
//! a real runtime process in a temporary `HEIMDALL_HOME` (m02-plan U8 "Tests (A27)",
//! R-RT-05, holders, Git under `run`; ADR-0007 §8; spec §10.4).
//!
//! The runtime is started on demand by the CLI's launcher, with the debug build's
//! env-gated test configuration (`crates/heimdall/src/testcfg.rs`): the fake credential
//! adapter and the fixture profile `ops` (one pair, covered by its standing policy, so
//! `ensure` needs no decision). Its integration names no pair, so the pre-launch
//! eligibility check has nothing to refuse here; the A11 cases that need real
//! identities, declarations and agents are in the `a11` module below.
//!
//! **Isolation.** Every process gets a cleared environment: `PATH=/usr/bin:/bin`, a
//! scratch `HOME`, `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL` in scratch, so Git
//! resolution under `run` never reads the account's Git configuration, and no
//! `SSH_AUTH_SOCK`. Only processes this test started are stopped: the runtime through
//! `heimdall service stop` on its own scratch home, children through their exact
//! `Child` handles.
//!
//! **Canaries.** Every stdout and stderr byte is scanned with
//! `heimdall_testkit::assert_no_canary`; the argument canary is also searched, as its
//! exact value, in the store files, the logs and the run records (the fake adapter's
//! own credential reference carries a `HEIMDALL_CANARY_` value the store keeps by
//! design, so the store is searched for the argument canary only).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Child;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use heimdall_contract::run_record::{LaunchClassification, RunPlatform, RunRecord, classify};
use heimdall_testkit::assert_no_canary;
use serde_json::Value;

/// The binary under test.
fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

#[cfg(unix)]
const PLATFORM: RunPlatform = RunPlatform::Unix;
#[cfg(windows)]
const PLATFORM: RunPlatform = RunPlatform::Windows;

/// One finished invocation.
#[derive(Debug)]
struct Out {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: String,
}

impl Out {
    fn code(&self) -> Option<i32> {
        self.status.code()
    }

    /// The JSON envelope `--json` printed on stderr (run and connect keep stdout for
    /// the child).
    fn envelope(&self) -> Value {
        self.stderr
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
            .unwrap_or_else(|| panic!("no envelope on stderr: {}", self.stderr))
    }
}

/// A scratch `HEIMDALL_HOME`, a scratch user `HOME`, and the cleared environment
/// every process of a test gets.
struct Rig {
    dir: tempfile::TempDir,
    started: std::sync::atomic::AtomicBool,
}

impl Rig {
    fn new() -> Rig {
        let dir = tempfile::Builder::new()
            .prefix("hrm")
            .tempdir()
            .expect("scratch");
        std::fs::create_dir(dir.path().join("u")).unwrap();
        std::fs::write(dir.path().join("u/.gitconfig"), b"").unwrap();
        std::fs::create_dir(dir.path().join("w")).unwrap();
        Rig {
            dir,
            started: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn home(&self) -> PathBuf {
        self.path().join("h")
    }

    /// A scratch working directory.
    fn work(&self) -> PathBuf {
        self.path().join("w")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    /// The environment every heimdall process gets (and, under `run`, its child).
    fn env(&self) -> Vec<(OsString, OsString)> {
        let user = self.path().join("u");
        let mut env: Vec<(OsString, OsString)> = vec![
            ("HOME".into(), user.clone().into_os_string()),
            ("HEIMDALL_HOME".into(), self.home().into_os_string()),
            ("HEIMDALL_TEST_ADAPTER".into(), "prepare".into()),
            ("HEIMDALL_TEST_TIME_SYNC".into(), "synchronized".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            (
                "GIT_CONFIG_GLOBAL".into(),
                user.join(".gitconfig").into_os_string(),
            ),
        ];
        if cfg!(windows) {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
            let mut path = PathBuf::from(&root).join("System32").into_os_string();
            path.push(";");
            path.push(&root);
            env.push(("PATH".into(), path));
            env.push(("SystemRoot".into(), root));
            env.push(("USERPROFILE".into(), user.into_os_string()));
            for k in ["TEMP", "TMP", "SystemDrive"] {
                if let Some(v) = std::env::var_os(k) {
                    env.push((k.into(), v));
                }
            }
        } else {
            env.push(("PATH".into(), "/usr/bin:/bin".into()));
        }
        env
    }

    fn command_of(&self, program: &OsStr, args: &[&OsStr], extra: &[(&str, &OsStr)]) -> Command {
        let mut cmd = Command::new(program);
        cmd.args(args).env_clear().current_dir(self.work());
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        self.started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        cmd
    }

    fn command(&self, args: &[&OsStr], extra: &[(&str, &OsStr)]) -> Command {
        self.command_of(OsStr::new(&bin()), args, extra)
    }

    /// Run with stdin closed, scanning both streams.
    fn run_with(&self, args: &[&OsStr], extra: &[(&str, &OsStr)]) -> Out {
        let out = self
            .command(args, extra)
            .stdin(Stdio::null())
            .output()
            .expect("spawn heimdall");
        finish(out)
    }

    fn run(&self, args: &[&str]) -> Out {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.run_with(&args, &[])
    }

    /// Whether this test's runtime was ever started (the launcher records each start).
    fn runtime_started(&self) -> bool {
        self.home().join("state/test-service-starts").exists()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if self.started.load(std::sync::atomic::Ordering::SeqCst) && self.home().exists() {
            let _ = self
                .command(&[OsStr::new("service"), OsStr::new("stop")], &[])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn finish(out: std::process::Output) -> Out {
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_no_canary(&String::from_utf8_lossy(&out.stdout));
    assert_no_canary(&stderr);
    Out {
        status: out.status,
        stdout: out.stdout,
        stderr,
    }
}

/// The NDJSON run records of a `--meta-file`.
fn records(path: &Path) -> Vec<RunRecord> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    assert_no_canary(&text);
    text.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("record {l}: {e}")))
        .collect()
}

fn os(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

/// `script` through the platform's shell (`/bin/sh -c`, or `cmd /d /c`).
fn shell(script: &str) -> Vec<OsString> {
    if cfg!(windows) {
        os(&["cmd", "/d", "/c", script])
    } else {
        os(&["/bin/sh", "-c", script])
    }
}

/// `heimdall --json run --profile ops [--meta-file <meta>] -- <argv>`.
fn run_args(meta: Option<&Path>, argv: &[OsString]) -> Vec<OsString> {
    let mut a = os(&["--json", "run", "--profile", "ops"]);
    if let Some(m) = meta {
        a.push("--meta-file".into());
        a.push(m.as_os_str().to_owned());
    }
    a.push("--".into());
    a.extend(argv.iter().cloned());
    a
}

fn refs(v: &[OsString]) -> Vec<&OsStr> {
    v.iter().map(OsString::as_os_str).collect()
}

#[cfg(unix)]
fn launching_ids(records: &[RunRecord]) -> (Option<String>, Option<String>) {
    match records.first() {
        Some(RunRecord::Launching {
            operation_id,
            binding_id,
            ..
        }) => (
            operation_id.as_ref().map(ToString::to_string),
            binding_id.as_ref().map(ToString::to_string),
        ),
        other => panic!("first record is not launching: {other:?}"),
    }
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

/// Wait for `cond`, bounded.
fn wait_for(what: &str, limit: Duration, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
/// A spawned heimdall process, killed through its own handle when the test fails.
struct Running(Option<Child>);

#[cfg(unix)]
impl Running {
    fn pid(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }
    fn wait(mut self, limit: Duration) -> ExitStatus {
        let mut child = self.0.take().unwrap();
        let deadline = Instant::now() + limit;
        loop {
            if let Some(s) = child.try_wait().unwrap() {
                return s;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("heimdall did not finish");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(unix)]
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// =================================================================================
// A27: launch refusals, exit statuses and the side channel
// =================================================================================

/// m02-plan U8 `a27_missing_executable_exits_127_with_prelaunch_record`: a program
/// that is not found (by name and by path) exits 127 with `LAUNCH_FAILED`
/// `not_found`, one `prelaunch_failed` record, and no request at all: the program is
/// resolved before `ensure`, so the runtime is never started.
#[test]
fn a27_missing_executable_exits_127_with_prelaunch_record() {
    let rig = Rig::new();
    for (i, program) in [
        OsString::from("hm-no-such-program-u8"),
        rig.file("missing").into_os_string(),
    ]
    .into_iter()
    .enumerate()
    {
        let meta = rig.file(&format!("meta-{i}.ndjson"));
        let out = rig.run_with(&refs(&run_args(Some(&meta), &[program])), &[]);
        assert_eq!(out.code(), Some(127), "{}", out.stderr);
        assert!(out.stdout.is_empty());
        let env = out.envelope();
        assert_eq!(env["code"], "LAUNCH_FAILED");
        assert_eq!(env["data"]["error"]["reason"], "not_found");
        let records = records(&meta);
        assert_eq!(
            classify(&records, PLATFORM),
            LaunchClassification::NotLaunched {
                code: Some(heimdall_contract::Code::LaunchFailed),
                reason: Some("not_found".to_owned()),
            }
        );
        assert!(matches!(
            records.as_slice(),
            [RunRecord::PrelaunchFailed {
                exit_code: 127,
                operation_id: None,
                binding_id: None,
                ..
            }]
        ));
    }
    assert!(!rig.runtime_started(), "nothing was requested");
}

/// m02-plan U8 `a27_not_executable_exits_126`: a file without an execute bit, named by
/// path or found on `PATH`, exits 126 (`not_executable`); a directory by path too.
#[cfg(unix)]
#[test]
fn a27_not_executable_exits_126() {
    use std::os::unix::fs::PermissionsExt as _;
    let rig = Rig::new();
    let bin_dir = rig.file("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let plain = bin_dir.join("hm-plain");
    std::fs::write(&plain, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    let path = OsString::from(format!("{}:/usr/bin:/bin", bin_dir.display()));
    for (i, program) in [
        plain.clone().into_os_string(),
        OsString::from("hm-plain"),
        bin_dir.clone().into_os_string(),
    ]
    .into_iter()
    .enumerate()
    {
        let meta = rig.file(&format!("meta-{i}.ndjson"));
        let out = rig.run_with(
            &refs(&run_args(Some(&meta), &[program])),
            &[("PATH", path.as_os_str())],
        );
        assert_eq!(out.code(), Some(126), "{}", out.stderr);
        assert_eq!(out.envelope()["data"]["error"]["reason"], "not_executable");
        assert_eq!(
            classify(&records(&meta), PLATFORM),
            LaunchClassification::NotLaunched {
                code: Some(heimdall_contract::Code::LaunchFailed),
                reason: Some("not_executable".to_owned()),
            }
        );
    }
}

/// m02-plan U8 `a27_child_exit_codes_0_to_255_preserved`: after launch the status is
/// the child's, every value 0–255, and nothing Heimdall prints reaches stdout.
#[test]
fn a27_child_exit_codes_0_to_255_preserved() {
    let rig = Rig::new();
    // One run first, so the runtime is up before the parallel runs.
    let first = rig.run_with(
        &refs(&run_args(None, &os(&["/bin/sh", "-c", "exit 0"]))),
        &[],
    );
    assert_eq!(first.code(), Some(0), "{}", first.stderr);
    let codes: Vec<i32> = (0..=255).collect();
    std::thread::scope(|scope| {
        for chunk in codes.chunks(32) {
            let rig = &rig;
            scope.spawn(move || {
                for code in chunk {
                    let argv = shell(&format!("exit {code}"));
                    let out = rig.run_with(&refs(&run_args(None, &argv)), &[]);
                    assert_eq!(out.code(), Some(*code), "{}", out.stderr);
                    assert!(out.stdout.is_empty());
                }
            });
        }
    });
}

/// m02-plan U8 `a27_windows_full_32bit_exit_code_preserved`: runs natively on Windows
/// (blocked on other hosts; the spawn-and-wait unit test covers the conversion).
#[cfg(windows)]
#[test]
fn a27_windows_full_32bit_exit_code_preserved() {
    let rig = Rig::new();
    let argv = os(&["cmd", "/d", "/c", "exit -1073741510"]);
    let meta = rig.file("meta.ndjson");
    let out = rig.run_with(&refs(&run_args(Some(&meta), &argv)), &[]);
    assert_eq!(out.status.code().map(i32::cast_unsigned), Some(0xC000_013A));
    assert_eq!(
        classify(&records(&meta), PLATFORM),
        LaunchClassification::Launched {
            exit_code: Some(3_221_225_786)
        }
    );
}

/// m02-plan U8 `a27_signal_death_preserved`: Heimdall became the child, so a child
/// killed by a signal is the process killed by that signal.
#[cfg(unix)]
#[test]
fn a27_signal_death_preserved() {
    use std::os::unix::process::ExitStatusExt as _;
    let rig = Rig::new();
    for (signal, script) in [
        (15, "kill -TERM $$"),
        (9, "kill -KILL $$"),
        (6, "kill -ABRT $$"),
    ] {
        let out = rig.run_with(&refs(&run_args(None, &os(&["/bin/sh", "-c", script]))), &[]);
        assert_eq!(out.status.signal(), Some(signal), "{}", out.stderr);
    }
}

/// m02-plan U8 `a27_child_exit_127_vs_exec_failure_distinguished_by_prelaunch_record`:
/// the exit status cannot tell a child that exits 127 from an exec that failed; the
/// side channel can.
#[cfg(unix)]
#[test]
fn a27_child_exit_127_vs_exec_failure_distinguished_by_prelaunch_record() {
    let rig = Rig::new();
    let child_meta = rig.file("child.ndjson");
    let marker = rig.file("ran");
    let script = format!("touch '{}'; exit 127", marker.display());
    let child = rig.run_with(
        &refs(&run_args(
            Some(&child_meta),
            &os(&["/bin/sh", "-c", &script]),
        )),
        &[],
    );
    assert_eq!(child.code(), Some(127));
    assert!(marker.exists(), "the child ran");
    let child_records = records(&child_meta);
    assert_eq!(
        classify(&child_records, PLATFORM),
        LaunchClassification::Indeterminate
    );
    std::fs::remove_file(&marker).unwrap();

    let failed_meta = rig.file("failed.ndjson");
    let failed = rig.run_with(
        &refs(&run_args(
            Some(&failed_meta),
            &os(&["/bin/sh", "-c", &script]),
        )),
        &[("HEIMDALL_TEST_FORCE_EXEC_FAILURE", OsStr::new("1"))],
    );
    assert_eq!(failed.code(), Some(127), "same status");
    assert!(!marker.exists(), "nothing ran");
    let failed_records = records(&failed_meta);
    assert_eq!(
        classify(&failed_records, PLATFORM),
        LaunchClassification::NotLaunched {
            code: Some(heimdall_contract::Code::LaunchFailed),
            reason: Some("exec_error".to_owned()),
        }
    );
    // Both runs bound before launching: the attempt names the operation and binding.
    for r in [&child_records, &failed_records] {
        let (op, binding) = launching_ids(r);
        assert!(op.is_some() && binding.is_some());
    }
}

/// m02-plan U8 `a27_kill_between_launching_and_exec_is_indeterminate_never_launched`:
/// held after `launching` by the test-only pause, then killed by exact PID: the
/// records end with `launching`, which reads `indeterminate`, never "launched".
#[cfg(unix)]
#[test]
fn a27_kill_between_launching_and_exec_is_indeterminate_never_launched() {
    use std::os::unix::process::ExitStatusExt as _;
    let rig = Rig::new();
    let fifo = rig.file("pause");
    mkfifo(&fifo);
    let meta = rig.file("meta.ndjson");
    let marker = rig.file("ran");
    let script = format!("touch '{}'", marker.display());
    let args = run_args(Some(&meta), &os(&["/bin/sh", "-c", &script]));
    let mut running = Running(Some(
        rig.command(
            &refs(&args),
            &[("HEIMDALL_TEST_PRE_EXEC_PAUSE", fifo.as_os_str())],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap(),
    ));
    let pid = running.pid();
    wait_for("launching", Duration::from_secs(30), || {
        std::fs::read_to_string(&meta).is_ok_and(|t| t.ends_with('\n'))
    });
    running.child().kill().unwrap();
    let status = running.wait(Duration::from_secs(10));
    assert_eq!(status.signal(), Some(9));
    let r = records(&meta);
    assert!(matches!(r.as_slice(), [RunRecord::Launching { pid: p, .. }] if *p == pid));
    assert_eq!(classify(&r, PLATFORM), LaunchClassification::Indeterminate);
    assert!(!marker.exists());
}

/// Run `heimdall` under `/bin/sh` so its descriptor 3 is the pipe this test reads
/// (`3>&1`), with stdout redirected to stderr's sink.
#[cfg(unix)]
fn with_meta_pipe(rig: &Rig, args: &[OsString], extra: &[(&str, &OsStr)]) -> Child {
    let mut sh_args = os(&["-c", "exec \"$0\" \"$@\" 3>&1 1>/dev/null"]);
    sh_args.push(bin().into());
    sh_args.extend(args.iter().cloned());
    rig.command_of(OsStr::new("/bin/sh"), &refs(&sh_args), extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[cfg(unix)]
/// `--meta-fd 3` arguments.
fn fd_args(argv: &[OsString]) -> Vec<OsString> {
    let mut a = os(&["--json", "run", "--profile", "ops", "--meta-fd", "3", "--"]);
    a.extend(argv.iter().cloned());
    a
}

/// m02-plan U8 `a27_exec_failure_with_failed_meta_write_is_indeterminate`: the
/// reader takes `launching` and closes the pipe, then the exec is forced to fail:
/// Heimdall exits 127 and does not die of SIGPIPE; what the reader saw is
/// `indeterminate`.
#[cfg(unix)]
#[test]
fn a27_exec_failure_with_failed_meta_write_is_indeterminate() {
    use std::os::unix::process::ExitStatusExt as _;
    let rig = Rig::new();
    let fifo = rig.file("pause");
    mkfifo(&fifo);
    let mut child = Running(Some(with_meta_pipe(
        &rig,
        &fd_args(&os(&["/bin/sh", "-c", "exit 0"])),
        &[
            ("HEIMDALL_TEST_PRE_EXEC_PAUSE", fifo.as_os_str()),
            ("HEIMDALL_TEST_FORCE_EXEC_FAILURE", OsStr::new("1")),
        ],
    )));
    let stdout = child.child().stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    // The reader is gone before the exec fails.
    let launching: RunRecord = serde_json::from_str(line.trim_end()).unwrap();
    drop(std::fs::OpenOptions::new().write(true).open(&fifo).unwrap());
    let mut stderr = String::new();
    child
        .child()
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait(Duration::from_secs(30));
    assert_eq!(status.signal(), None, "not killed by SIGPIPE: {stderr}");
    assert_eq!(status.code(), Some(127), "{stderr}");
    assert_eq!(
        classify(&[launching], PLATFORM),
        LaunchClassification::Indeterminate
    );
    assert!(stderr.contains("exec_error"), "{stderr}");
    assert_no_canary(&stderr);
}

/// m02-plan U8 `a27_meta_unavailable_aborts_launch_no_child`: the `launching` write
/// fails (the reader closed the pipe first), so the launch is abandoned: exit 127,
/// `meta_unavailable`, and the child never ran.
#[cfg(unix)]
#[test]
fn a27_meta_unavailable_aborts_launch_no_child() {
    use std::os::unix::process::ExitStatusExt as _;
    let rig = Rig::new();
    let marker = rig.file("ran");
    let script = format!("touch '{}'", marker.display());
    let mut child = Running(Some(with_meta_pipe(
        &rig,
        &fd_args(&os(&["/bin/sh", "-c", &script])),
        &[],
    )));
    drop(child.child().stdout.take());
    let mut stderr = String::new();
    child
        .child()
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait(Duration::from_secs(30));
    assert_eq!(status.signal(), None, "{stderr}");
    assert_eq!(status.code(), Some(127), "{stderr}");
    assert!(stderr.contains("meta_unavailable"), "{stderr}");
    assert!(!marker.exists(), "no child");
}

/// m02-plan U8 `a27_meta_file_existing_or_fd_invalid_is_usage_error_before_ensure`: an
/// existing `--meta-file` (left untouched), a descriptor that is not open, standard
/// output, and a directory descriptor are each a usage error before `ensure`: the
/// runtime is never started and no child runs.
#[cfg(unix)]
#[test]
fn a27_meta_file_existing_or_fd_invalid_is_usage_error_before_ensure() {
    let rig = Rig::new();
    let marker = rig.file("ran");
    let script = format!("touch '{}'", marker.display());
    let argv = os(&["/bin/sh", "-c", &script]);
    let existing = rig.file("existing.ndjson");
    std::fs::write(&existing, b"owner bytes").unwrap();
    let out = rig.run_with(&refs(&run_args(Some(&existing), &argv)), &[]);
    assert_eq!(out.code(), Some(2), "{}", out.stderr);
    assert_eq!(out.envelope()["code"], "USAGE_ERROR");
    assert_eq!(std::fs::read(&existing).unwrap(), b"owner bytes");
    for fd in ["9", "1", "-1"] {
        let mut a = os(&["--json", "run", "--profile", "ops", "--meta-fd", fd, "--"]);
        a.extend(argv.iter().cloned());
        let out = rig.run_with(&refs(&a), &[]);
        assert_eq!(out.code(), Some(2), "fd {fd}: {}", out.stderr);
    }
    // Descriptor 3 open on a directory: not a pipe, socket or regular file.
    let mut sh_args = os(&["-c", "exec \"$0\" \"$@\" 3<\"$HOME\""]);
    sh_args.push(bin().into());
    sh_args.extend(fd_args(&argv));
    let out = finish(
        rig.command_of(OsStr::new("/bin/sh"), &refs(&sh_args), &[])
            .stdin(Stdio::null())
            .output()
            .unwrap(),
    );
    assert_eq!(out.code(), Some(2), "{}", out.stderr);
    assert!(!marker.exists());
    assert!(!rig.runtime_started(), "usage errors come before ensure");
}

/// m02-plan U8 `a27_no_stdout_contamination_in_run_and_connect`: stdout carries
/// exactly the child's bytes (all 256 byte values), with `--json` too; a failure
/// before launch prints nothing on stdout either, for `run` and for `connect`.
#[test]
fn a27_no_stdout_contamination_in_run_and_connect() {
    let rig = Rig::new();
    let (argv, payload): (Vec<OsString>, Vec<u8>) = if cfg!(windows) {
        (shell("echo hello"), b"hello\r\n".to_vec())
    } else {
        let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let data = rig.file("payload.bin");
        std::fs::write(&data, &payload).unwrap();
        (
            vec![OsString::from("/bin/cat"), data.into_os_string()],
            payload,
        )
    };
    for json in [true, false] {
        let mut a = run_args(None, &argv);
        if !json {
            a.remove(0);
        }
        let out = rig.run_with(&refs(&a), &[]);
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        assert_eq!(out.stdout, payload, "json={json}");
    }
    let refused = rig.run_with(&refs(&run_args(None, &os(&["hm-no-such-program-u8"]))), &[]);
    assert_eq!(refused.code(), Some(127));
    assert!(refused.stdout.is_empty());
    let connect = rig.run(&["--json", "connect", "hm-unknown-alias"]);
    assert_ne!(connect.code(), Some(0));
    assert!(connect.stdout.is_empty(), "connect printed on stdout");
    assert_eq!(
        connect.envelope()["code"],
        "NOT_FOUND",
        "{}",
        connect.stderr
    );
}

#[cfg(unix)]
const METACHARACTERS: [&str; 12] = [
    "$(touch pwned)",
    "`touch pwned`",
    "a;touch pwned",
    "a|touch pwned",
    "a&&touch pwned",
    "'\"",
    "*",
    "$HOME",
    "",
    "two words",
    "--json",
    "\u{e9}\u{2028}tab\tend",
];

/// m02-plan U8 `a27_shell_metacharacters_in_argv_reach_child_verbatim`: no shell
/// interprets `argv`; Heimdall's own flags after `--` are the child's.
#[cfg(unix)]
#[test]
fn a27_shell_metacharacters_in_argv_reach_child_verbatim() {
    let rig = Rig::new();
    let out_file = rig.file("args");
    let script = "out=$1; shift; printf '%s\\0' \"$@\" > \"$out\"";
    let mut argv = os(&["/bin/sh", "-c", script, "sh"]);
    argv.push(out_file.clone().into_os_string());
    argv.extend(os(&METACHARACTERS));
    let out = rig.run_with(&refs(&run_args(None, &argv)), &[]);
    assert_eq!(out.code(), Some(0), "{}", out.stderr);
    let mut expected = Vec::new();
    for a in METACHARACTERS {
        expected.extend_from_slice(a.as_bytes());
        expected.push(0);
    }
    assert_eq!(std::fs::read(&out_file).unwrap(), expected);
    assert!(!rig.work().join("pwned").exists());
}

#[cfg(unix)]
/// The environment `/usr/bin/env -0` printed, as sorted pairs.
fn env_pairs(bytes: &[u8]) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = bytes
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .map(|e| {
            let text = String::from_utf8_lossy(e);
            let (k, v) = text.split_once('=').unwrap_or((&text, ""));
            (k.to_owned(), v.to_owned())
        })
        .collect();
    pairs.sort();
    pairs
}

/// m02-plan U8 `a27_cwd_and_env_preserved_plus_only_documented_additions`: the child
/// starts in the caller's directory with exactly the caller's environment (this
/// integration documents no addition: no pair, so no `SSH_AUTH_SOCK`; Git is never
/// injected on Unix).
#[cfg(unix)]
#[test]
fn a27_cwd_and_env_preserved_plus_only_documented_additions() {
    let rig = Rig::new();
    let extra = [
        ("HM_U8_MARKER", OsStr::new("value with spaces")),
        ("GIT_CONFIG_COUNT", OsStr::new("0")),
    ];
    let out = rig.run_with(&refs(&run_args(None, &os(&["/usr/bin/env", "-0"]))), &extra);
    assert_eq!(out.code(), Some(0), "{}", out.stderr);
    let mut expected: Vec<(String, String)> = rig
        .env()
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .chain(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.to_string_lossy().into_owned())),
        )
        .collect();
    expected.sort();
    assert_eq!(env_pairs(&out.stdout), expected);
    let pwd = rig.run_with(&refs(&run_args(None, &os(&["/bin/pwd", "-P"]))), &[]);
    assert_eq!(
        String::from_utf8_lossy(&pwd.stdout).trim_end(),
        std::fs::canonicalize(rig.work()).unwrap().to_string_lossy()
    );
}

/// The bytes of every file under `dir`.
fn all_bytes(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(all_bytes(&p));
        } else if let Ok(b) = std::fs::read(&p) {
            out.push((p, b));
        }
    }
    out
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// m02-plan U8
/// `a27_argv_canary_absent_from_ipc_store_events_logs_errors_batch_refusals_replay_and_meta`
/// (Q8 as qualified): an argument canary reaches the child, and appears nowhere
/// else: not in any envelope or diagnostic, run record, the store's files, the logs,
/// the events, nor in a replay with the same request ID or a refusal. (Batch refusals
/// are Windows-only; the refusal checked here is an exec failure and a missing
/// program.)
#[test]
fn a27_argv_canary_absent_from_ipc_store_events_logs_errors_batch_refusals_replay_and_meta() {
    let rig = Rig::new();
    let canary = format!(
        "{}ARGV_{:016x}",
        heimdall_testkit::CANARY_PREFIX,
        std::process::id() as u64 * 7919 + 17
    );
    let seen = rig.file("seen");
    let argv: Vec<OsString> = if cfg!(windows) {
        vec![
            "cmd".into(),
            "/d".into(),
            "/c".into(),
            "echo".into(),
            canary.clone().into(),
            ">".into(),
            seen.clone().into_os_string(),
        ]
    } else {
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s' \"$1\" > \"$2\"".into(),
            "sh".into(),
            canary.clone().into(),
            seen.clone().into_os_string(),
        ]
    };
    let mut scanned: Vec<(String, Vec<u8>)> = Vec::new();
    let mut run_one = |name: &str, args: Vec<OsString>, extra: &[(&str, &OsStr)]| {
        let meta = rig.file(&format!("{name}.ndjson"));
        let mut a = os(&[
            "--json",
            "run",
            "--profile",
            "ops",
            "--request-id",
            "req-canary",
        ]);
        a.push("--meta-file".into());
        a.push(meta.clone().into_os_string());
        a.push("--".into());
        a.extend(args);
        let out = rig.run_with(&refs(&a), extra);
        scanned.push((format!("{name} stderr"), out.stderr.into_bytes()));
        scanned.push((format!("{name} stdout"), out.stdout));
        scanned.push((
            format!("{name} meta"),
            std::fs::read(&meta).unwrap_or_default(),
        ));
        out.status
    };
    assert_eq!(run_one("first", argv.clone(), &[]).code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        canary,
        "the child got it"
    );
    assert_eq!(run_one("replay", argv.clone(), &[]).code(), Some(0));
    let forced = [("HEIMDALL_TEST_FORCE_EXEC_FAILURE", OsStr::new("1"))];
    if cfg!(unix) {
        assert_eq!(
            run_one("exec-failure", argv.clone(), &forced).code(),
            Some(127)
        );
    }
    let mut missing = argv.clone();
    missing[0] = "hm-no-such-program-u8".into();
    assert_eq!(run_one("missing", missing, &[]).code(), Some(127));
    let events = rig.run(&["--json", "operation", "events", "--limit", "500"]);
    scanned.push(("events".to_owned(), events.stdout.clone()));
    let ops = rig.run(&["--json", "inspect", "operations"]);
    scanned.push(("inspect".to_owned(), ops.stdout.clone()));
    for (path, bytes) in all_bytes(&rig.home()) {
        scanned.push((path.display().to_string(), bytes));
    }
    for (label, bytes) in &scanned {
        assert!(
            !contains(bytes, &canary),
            "the argument canary leaked into {label}"
        );
    }
    assert!(
        scanned
            .iter()
            .any(|(l, _)| l.ends_with(".sqlite") || l.contains("state")),
        "the store was scanned"
    );
}

/// m02-plan U8 `a27_sigpipe_ignored_by_caller_is_reset_limitation_recorded` (a
/// recorded limitation, not fidelity evidence; ADR-0007 §8): a caller that ignores
/// SIGPIPE does not pass that to the child, because std resets it before `execve`.
#[cfg(unix)]
#[test]
fn a27_sigpipe_ignored_by_caller_is_reset_limitation_recorded() {
    use std::os::unix::process::ExitStatusExt as _;
    let rig = Rig::new();
    let mut sh_args = os(&["-c", "trap '' PIPE; exec \"$0\" \"$@\""]);
    sh_args.push(bin().into());
    sh_args.extend(run_args(
        None,
        &os(&["/bin/sh", "-c", "kill -PIPE $$; echo survived"]),
    ));
    let out = finish(
        rig.command_of(OsStr::new("/bin/sh"), &refs(&sh_args), &[])
            .stdin(Stdio::null())
            .output()
            .unwrap(),
    );
    // LIMITATION (recorded): the child died of SIGPIPE although the caller ignored it.
    assert_eq!(out.status.signal(), Some(13), "{}", out.stderr);
    assert!(out.stdout.is_empty());
    eprintln!(
        "limitation recorded: a SIGPIPE disposition ignored by the caller is reset in the child"
    );
}

// =================================================================================
// A27 on Windows (native runs only; cross-checked by clippy-windows on other hosts)
// =================================================================================

/// m02-plan U8 `a27_windows_spawned_record_is_positive_launch_proof`: on Windows the
/// launcher writes `spawned` (the child's PID) after `CreateProcessW` returned, then
/// `exited`: positive launch evidence, unlike Unix.
#[cfg(windows)]
#[test]
fn a27_windows_spawned_record_is_positive_launch_proof() {
    let rig = Rig::new();
    let meta = rig.file("meta.ndjson");
    let out = rig.run_with(&refs(&run_args(Some(&meta), &shell("exit 5"))), &[]);
    assert_eq!(out.code(), Some(5), "{}", out.stderr);
    let r = records(&meta);
    match r.as_slice() {
        [
            RunRecord::Launching { pid, .. },
            RunRecord::Spawned { pid: child, .. },
            RunRecord::Exited { exit_code: 5, .. },
        ] => {
            assert_ne!(pid, child, "the launcher is not the child")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        classify(&r, PLATFORM),
        LaunchClassification::Launched { exit_code: Some(5) }
    );
}

/// The 16 argument cases of ADR-0002 §3.1 (G02 round 4, `Invoke-G02WindowsX1.ps1`):
/// every injected command is `break>hmx1injN.txt`, so a file appearing in the working
/// directory or next to the script is an injection.
#[cfg(windows)]
const BATCH_VALUES: [&str; 16] = [
    "plain",
    "two words",
    "a&break>hmx1inj1.txt",
    "a & break>hmx1inj2.txt",
    "a|break>hmx1inj3.txt",
    "a>hmx1inj4.txt",
    "a<hmx1src.txt",
    "a<hmx1src.txt&break>hmx1inj5.txt",
    "a^b",
    "a^^&break>hmx1inj6.txt",
    "%HMX1BATVAR%",
    "x%HMX1BATVAR%y",
    "a\"&break>hmx1inj8.txt",
    "a\" & break>hmx1inj9.txt",
    "a\\\"&break>hmx1inj10.txt",
    "\"a&break>hmx1inj11.txt\"",
];

/// m02-plan U8 `a27_windows_cmd_and_bat_targets_get_escaped_args`: `.cmd` and `.bat`
/// targets, with and without a space in their path, get std's batch escaping: each of
/// the 16 arguments runs the script and injects nothing, or is refused before launch;
/// never a second command.
#[cfg(windows)]
#[test]
fn a27_windows_cmd_and_bat_targets_get_escaped_args() {
    let rig = Rig::new();
    let body = "@echo off\r\nbreak>\"%~dp0ran.txt\"\r\nexit /b 0\r\n";
    for dir_name in ["bat dir", "batdir"] {
        let dir = rig.file(dir_name);
        std::fs::create_dir_all(&dir).unwrap();
        for ext in ["cmd", "bat"] {
            let script = dir.join(format!("echoargs.{ext}"));
            std::fs::write(&script, body).unwrap();
            for (i, value) in BATCH_VALUES.iter().enumerate() {
                let cwd = rig.file(&format!("cwd-{dir_name}-{ext}-{i}").replace(' ', "_"));
                std::fs::create_dir_all(&cwd).unwrap();
                std::fs::write(cwd.join("hmx1src.txt"), "src\r\n").unwrap();
                let _ = std::fs::remove_file(dir.join("ran.txt"));
                let argv = vec![script.clone().into_os_string(), OsString::from(*value)];
                let mut cmd = rig.command(
                    &refs(&run_args(None, &argv)),
                    &[("HMX1BATVAR", OsStr::new("b&break>hmx1inj7.txt"))],
                );
                let out = finish(cmd.current_dir(&cwd).stdin(Stdio::null()).output().unwrap());
                let stray: Vec<String> = std::fs::read_dir(&cwd)
                    .unwrap()
                    .chain(std::fs::read_dir(&dir).unwrap())
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with("hmx1inj"))
                    .collect();
                assert!(
                    stray.is_empty(),
                    "{ext} {dir_name} {value:?}: injected {stray:?}"
                );
                let ran = dir.join("ran.txt").exists();
                assert!(
                    (out.code() == Some(0) && ran) || (out.code() == Some(127) && !ran),
                    "{ext} {dir_name} {value:?}: exit {:?} ran {ran}: {}",
                    out.code(),
                    out.stderr
                );
            }
        }
    }
}

/// m02-plan U8 `a27_windows_batch_path_with_percent_bang_caret_refused_127`: a batch
/// script whose own path holds a character `cmd.exe` interprets is refused (127,
/// `refused_batch_path`) and never runs.
#[cfg(windows)]
#[test]
fn a27_windows_batch_path_with_percent_bang_caret_refused_127() {
    let rig = Rig::new();
    for (i, dir_name) in ["p%HMX1BATVAR%x", "b!x", "c^x", "d&x", "e(x)"]
        .iter()
        .enumerate()
    {
        let dir = rig.file(dir_name);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("t.cmd");
        std::fs::write(&script, "@echo off\r\nbreak>\"%~dp0ran.txt\"\r\n").unwrap();
        let meta = rig.file(&format!("meta-{i}.ndjson"));
        let out = rig.run_with(
            &refs(&run_args(Some(&meta), &[script.into_os_string()])),
            &[("HMX1BATVAR", OsStr::new("x"))],
        );
        assert_eq!(out.code(), Some(127), "{dir_name}: {}", out.stderr);
        assert_eq!(
            out.envelope()["data"]["error"]["reason"],
            "refused_batch_path"
        );
        assert!(!dir.join("ran.txt").exists());
        assert_eq!(
            classify(&records(&meta), PLATFORM),
            LaunchClassification::NotLaunched {
                code: Some(heimdall_contract::Code::LaunchFailed),
                reason: Some("refused_batch_path".to_owned()),
            }
        );
    }
}

/// m02-plan U8 `a27_windows_current_directory_never_searched`: a program present only
/// in the working directory is refused (127, `current_directory`), never run.
#[cfg(windows)]
#[test]
fn a27_windows_current_directory_never_searched() {
    let rig = Rig::new();
    let root = std::env::var_os("SystemRoot").unwrap();
    let cmd_exe = PathBuf::from(root).join("System32").join("cmd.exe");
    std::fs::copy(&cmd_exe, rig.work().join("hm-cwd-tool.exe")).unwrap();
    let out = rig.run_with(
        &refs(&run_args(None, &os(&["hm-cwd-tool", "/d", "/c", "exit 0"]))),
        &[],
    );
    assert_eq!(out.code(), Some(127), "{}", out.stderr);
    assert_eq!(
        out.envelope()["data"]["error"]["reason"],
        "current_directory"
    );
}

/// m02-plan U8 `windows_holder_is_launcher_and_forced_launcher_kill_is_reported`: the
/// holder is the launcher. Killing it by exact PID releases the binding at the next
/// holder pass while the child keeps running (disclosed, ADR-0007 §8); the test then
/// stops the child by its exact PID and records the limitation.
#[cfg(windows)]
#[test]
fn windows_holder_is_launcher_and_forced_launcher_kill_is_reported() {
    let rig = Rig::new();
    let meta = rig.file("meta.ndjson");
    let mut launcher = rig
        .command(
            &refs(&run_args(Some(&meta), &shell("ping -n 60 127.0.0.1 >NUL"))),
            &[],
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let child_pid = loop {
        let r = records(&meta);
        if let [
            RunRecord::Launching { pid, .. },
            RunRecord::Spawned { pid: child, .. },
            ..,
        ] = r.as_slice()
        {
            assert_eq!(*pid, launcher.id(), "the launcher holds the binding");
            break *child;
        }
        assert!(Instant::now() < deadline, "no spawned record");
        std::thread::sleep(Duration::from_millis(50));
    };
    let binding = match records(&meta).first() {
        Some(RunRecord::Launching {
            binding_id: Some(b),
            ..
        }) => b.to_string(),
        other => panic!("{other:?}"),
    };
    launcher.kill().unwrap();
    let _ = launcher.wait();
    let state = || -> String {
        let out = rig.run(&["--json", "inspect", "bindings"]);
        let env = serde_json::from_slice::<Value>(&out.stdout).unwrap();
        env["data"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["binding_id"] == binding.as_str())
            .map_or_else(
                || "absent".to_owned(),
                |b| b["state"].as_str().unwrap().to_owned(),
            )
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while state() == "active" {
        assert!(Instant::now() < deadline, "the binding was not released");
        std::thread::sleep(Duration::from_millis(200));
    }
    // The child still runs; stop it by its exact PID (it is this test's grandchild).
    let alive = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {child_pid}"), "/NH"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&alive.stdout).contains(&child_pid.to_string()),
        "the child keeps running after a forced launcher kill"
    );
    let stopped = Command::new("taskkill")
        .args(["/PID", &child_pid.to_string(), "/F"])
        .output()
        .unwrap();
    assert!(stopped.status.success());
    eprintln!(
        "limitation recorded: a forced launcher kill releases the binding while the child runs"
    );
}

// =================================================================================
// A27 on a terminal (Unix pty through rustix)
// =================================================================================

/// The pty cases: the test opens a pty pair (`openpt`, `grantpt`, `unlockpt`); a fresh
/// copy of this test binary in child mode becomes a session leader, takes the pty as
/// its controlling terminal and stdio (`setsid`, `TIOCSCTTY`, `dup2`) and execs
/// `heimdall run`, which execs the child. The child is therefore the terminal's
/// foreground process group, as in a shell, and Heimdall is no longer there to relay
/// anything.
#[cfg(unix)]
mod terminal {
    use std::os::fd::OwnedFd;
    use std::os::unix::process::CommandExt as _;

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{Winsize, tcsetwinsize};

    use super::*;

    const SLAVE: &str = "HM_U8_PTY_SLAVE";
    const ARGS: &str = "HM_U8_PTY_ARGS";

    /// Child-mode entry of the pty cases; does nothing in a normal run.
    #[test]
    #[ignore = "child-mode entry of the pty tests, started by them"]
    fn pty_child() {
        let (Some(slave), Some(args)) = (std::env::var_os(SLAVE), std::env::var(ARGS).ok()) else {
            return;
        };
        rustix::process::setsid().unwrap();
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave)
            .unwrap();
        rustix::process::ioctl_tiocsctty(&tty).unwrap();
        rustix::stdio::dup2_stdin(&tty).unwrap();
        rustix::stdio::dup2_stdout(&tty).unwrap();
        rustix::stdio::dup2_stderr(&tty).unwrap();
        drop(tty);
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        let err = Command::new(bin()).args(args).exec();
        panic!("exec failed: {err}");
    }

    pub(super) struct Pty {
        master: OwnedFd,
        slave: PathBuf,
        output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn size(rows: u16, cols: u16) -> Winsize {
        Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }

    impl Pty {
        pub(super) fn open() -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            // Drain the terminal's output so the child never blocks on it, until the
            // Pty is dropped. The master reads end-of-file or EIO while no slave is
            // open (before the child opens it, and after it exits), so neither ends
            // the drain: an exiting child's close waits for its output to drain.
            let reader = master.try_clone().unwrap();
            let sink = std::sync::Arc::clone(&output);
            let done = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut f = std::fs::File::from(reader);
                let mut buf = [0u8; 4096];
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    match f.read(&mut buf) {
                        Ok(n) if n > 0 => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            let pty = Pty {
                master,
                slave: PathBuf::from(std::ffi::OsStr::from_bytes(name.as_bytes())),
                output,
                stop,
            };
            pty.resize(24, 80);
            pty
        }

        /// `TIOCSWINSZ` through the slave (macOS refuses it on the master); the kernel
        /// signals the terminal's foreground process group.
        fn resize(&self, rows: u16, cols: u16) {
            let slave = rustix::fs::open(
                &self.slave,
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            tcsetwinsize(&slave, size(rows, cols)).unwrap();
        }

        fn write(&self, bytes: &[u8]) {
            use std::io::Write as _;
            let mut f = std::fs::File::from(self.master.try_clone().unwrap());
            f.write_all(bytes).unwrap();
        }

        /// The child-mode test entry's arguments, and its two variables for `args`.
        fn child_args(&self, args: &[OsString]) -> (Vec<OsString>, String) {
            let args: Vec<String> = args
                .iter()
                .map(|a| a.to_str().unwrap().to_owned())
                .collect();
            let json = serde_json::to_string(&args).unwrap();
            let entry = os(&[
                "--exact",
                "terminal::pty_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ]);
            (entry, json)
        }

        /// `heimdall <args>` on this terminal.
        fn start(&self, rig: &Rig, args: &[OsString]) -> Running {
            let (entry, json) = self.child_args(args);
            let exe = std::env::current_exe().unwrap();
            let cmd = rig
                .command_of(
                    exe.as_os_str(),
                    &refs(&entry),
                    &[(SLAVE, self.slave.as_os_str()), (ARGS, OsStr::new(&json))],
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Running(Some(cmd))
        }

        /// `heimdall <args>` on this terminal with exactly the environment `env` (a
        /// cleared environment otherwise) in `cwd`.
        pub(super) fn start_env(
            &self,
            env: &[(OsString, OsString)],
            cwd: &Path,
            args: &[OsString],
        ) -> Running {
            let (entry, json) = self.child_args(args);
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            cmd.args(&entry).env_clear().current_dir(cwd);
            for (k, v) in env {
                cmd.env(k, v);
            }
            let child = cmd
                .env(SLAVE, &self.slave)
                .env(ARGS, &json)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Running(Some(child))
        }

        pub(super) fn transcript(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }
    }

    use std::os::unix::ffi::OsStrExt as _;

    /// m02-plan U8 `a27_ctrl_c_reaches_child_once` (Unix pty): `^C` typed at the
    /// terminal reaches the child exactly once, and the status is the child's.
    #[test]
    fn a27_ctrl_c_reaches_child_once() {
        let rig = Rig::new();
        let pty = Pty::open();
        let hits = rig.file("int");
        let ready = rig.file("ready");
        let script = format!(
            "trap 'echo INT >> \"{}\"; exit 5' INT; touch '{}'; i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; exit 9",
            hits.display(),
            ready.display()
        );
        let running = pty.start(&rig, &run_args(None, &os(&["/bin/sh", "-c", &script])));
        wait_for("the child", Duration::from_secs(30), || ready.exists());
        pty.write(b"\x03");
        let status = running.wait(Duration::from_secs(30));
        assert_eq!(status.code(), Some(5), "{}", pty.transcript());
        assert_eq!(
            std::fs::read_to_string(&hits).unwrap(),
            "INT\n",
            "exactly once"
        );
        assert_no_canary(&pty.transcript());
    }

    /// m02-plan U8 `a27_resize_reaches_child` (Unix pty): `TIOCSWINSZ` on the
    /// terminal gives the child SIGWINCH and the new size.
    #[test]
    fn a27_resize_reaches_child() {
        let rig = Rig::new();
        let pty = Pty::open();
        let seen = rig.file("size");
        let ready = rig.file("ready");
        let script = format!(
            "trap 'stty size > \"{}\"; exit 0' WINCH; touch '{}'; i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; exit 9",
            seen.display(),
            ready.display()
        );
        let running = pty.start(&rig, &run_args(None, &os(&["/bin/sh", "-c", &script])));
        wait_for("the child", Duration::from_secs(30), || ready.exists());
        pty.resize(40, 132);
        let status = running.wait(Duration::from_secs(30));
        assert_eq!(status.code(), Some(0), "{}", pty.transcript());
        assert_eq!(std::fs::read_to_string(&seen).unwrap().trim(), "40 132");
    }
}

// =================================================================================
// R-RT-05: no blind relaunch
// =================================================================================

/// The operation and binding a `launching` or `prelaunch_failed` record names.
fn record_ids(records: &[RunRecord]) -> (Option<String>, Option<String>) {
    match records.first() {
        Some(
            RunRecord::Launching {
                operation_id,
                binding_id,
                ..
            }
            | RunRecord::PrelaunchFailed {
                operation_id,
                binding_id,
                ..
            },
        ) => (
            operation_id.as_ref().map(ToString::to_string),
            binding_id.as_ref().map(ToString::to_string),
        ),
        other => panic!("no launching or prelaunch_failed record: {other:?}"),
    }
}

/// A binding's state in `inspect bindings`, or `absent` (a released binding holds no
/// reference, so it is no longer listed).
fn binding_state(rig: &Rig, binding: &str) -> String {
    let out = rig.run(&["--json", "inspect", "bindings"]);
    let env = serde_json::from_slice::<Value>(&out.stdout).unwrap();
    env["data"]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["binding_id"] == binding)
        .map_or_else(
            || "absent".to_owned(),
            |b| b["state"].as_str().unwrap().to_owned(),
        )
}

/// One `run --profile ops --request-id <request> --meta-file <meta> -- <shell script>`
/// whose child appends a line to `count` and exits 7.
fn counted_run(rig: &Rig, request: &str, meta: &Path, count: &Path) -> Out {
    let script = if cfg!(windows) {
        format!("echo x>> \"{}\" & exit 7", count.display())
    } else {
        format!("echo x >> '{}'; exit 7", count.display())
    };
    let mut a = os(&["--json", "run", "--profile", "ops", "--request-id", request]);
    a.push("--meta-file".into());
    a.push(meta.as_os_str().to_owned());
    a.push("--".into());
    a.extend(shell(&script));
    rig.run_with(&refs(&a), &[])
}

fn line_count(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .map(|t| t.lines().count())
        .unwrap_or(0)
}

/// The refusal of a replayed `bind` whose binding the holder pass released (ADR-0007
/// §12.24 item 2): `CREDENTIAL_EXPIRED`, exit 4, `next: new_work`, the binding named
/// as the resource, and one `prelaunch_failed` record; nothing launched.
fn assert_released_refusal(out: &Out, meta: &Path) {
    assert_eq!(out.code(), Some(4), "{}", out.stderr);
    let env = out.envelope();
    assert_eq!(env["code"], "CREDENTIAL_EXPIRED", "{}", out.stderr);
    assert_eq!(env["next"]["action"], "new_work");
    assert_eq!(env["data"]["error"]["resource"]["kind"], "binding");
    assert!(out.stdout.is_empty());
    let recs = records(meta);
    assert!(
        matches!(recs.as_slice(), [RunRecord::PrelaunchFailed { .. }]),
        "{recs:?}"
    );
    assert_eq!(
        classify(&recs, PLATFORM),
        LaunchClassification::NotLaunched {
            code: Some(heimdall_contract::Code::CredentialExpired),
            reason: None,
        }
    );
}

/// m02-plan U8 `run_retry_with_same_request_id_never_relaunches_automatically`
/// (R-RT-05): a retry with the same request ID replays the same `ensure` and `bind`
/// (the same operation and binding in every record) and launches at most once per
/// explicit invocation; a runtime restart relaunches nothing, a child that failed is
/// not retried, and the runtime never launches anything itself. The first invocation
/// launches. A retry launches while the binding is still active; once the holder pass
/// has released it (its holder, the first invocation, exited), the retry is refused
/// before `launching` (ADR-0007 §12.24 item 2), which also launches nothing.
#[test]
fn run_retry_with_same_request_id_never_relaunches_automatically() {
    let rig = Rig::new();
    let count = rig.file("count");
    let mut ids = Vec::new();
    let mut launched = 0;
    let mut invoke = |n: usize| {
        let meta = rig.file(&format!("meta-{n}.ndjson"));
        let out = counted_run(&rig, "req-rt05", &meta, &count);
        if out.code() == Some(7) {
            assert!(matches!(
                records(&meta).as_slice(),
                [RunRecord::Launching { .. }]
            ));
            launched += 1;
        } else {
            assert!(n > 1, "the first invocation launches: {}", out.stderr);
            assert_released_refusal(&out, &meta);
        }
        ids.push(record_ids(&records(&meta)));
        launched
    };
    assert_eq!(invoke(1), 1);
    assert_eq!(line_count(&count), 1);
    let after_two = invoke(2);
    assert_eq!(
        line_count(&count),
        after_two,
        "at most one launch per explicit invocation, none of its own"
    );
    // Restart the runtime: recovery relaunches nothing.
    let stop = rig.run(&["--json", "service", "stop"]);
    assert_eq!(stop.code(), Some(0), "{}", stop.stderr);
    let after_three = invoke(3);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        line_count(&count),
        after_three,
        "a restart and a failed child relaunch nothing"
    );
    assert!(
        ids.iter().all(|i| *i == ids[0]),
        "the same bind replays: {ids:?}"
    );
    assert!(ids[0].0.is_some() && ids[0].1.is_some());
}

/// ADR-0007 §12.24 item 2 (regression): a retry with the same request ID replays the
/// stored `bind` result (`ACCESS_READY`) even after the holder pass released the
/// binding. `run` confirms with one `inspect bindings` that the binding is still active
/// before writing `launching`, so the replay is refused (`CREDENTIAL_EXPIRED`, exit 4,
/// a `prelaunch_failed` record naming the replayed operation and binding) and the child
/// never starts; new work (another request ID) launches.
#[test]
fn run_replay_of_a_binding_the_holder_pass_released_is_refused_and_never_launched() {
    let rig = Rig::new();
    let count = rig.file("count");
    let first = rig.file("first.ndjson");
    let out = counted_run(&rig, "req-released", &first, &count);
    assert_eq!(out.code(), Some(7), "{}", out.stderr);
    assert_eq!(line_count(&count), 1);
    let ids = record_ids(&records(&first));
    let binding = ids.1.clone().unwrap();
    // The first run's process (the holder) has exited: the holder pass (jittered,
    // default interval 5 s) releases the binding.
    wait_for("the holder pass", Duration::from_secs(30), || {
        binding_state(&rig, &binding) != "active"
    });
    let replay = rig.file("replay.ndjson");
    let out = counted_run(&rig, "req-released", &replay, &count);
    assert_released_refusal(&out, &replay);
    assert_eq!(
        record_ids(&records(&replay)),
        ids,
        "the replayed operation and binding"
    );
    assert_eq!(
        out.envelope()["data"]["error"]["resource"]["id"],
        binding.as_str()
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(line_count(&count), 1, "never launched");
    // New work launches with a new binding.
    let fresh = rig.file("fresh.ndjson");
    let out = counted_run(&rig, "req-released-new", &fresh, &count);
    assert_eq!(out.code(), Some(7), "{}", out.stderr);
    assert_eq!(line_count(&count), 2);
    assert_ne!(record_ids(&records(&fresh)).1, ids.1);
}

// =================================================================================
// Holders (Q5 as qualified)
// =================================================================================

/// The holder pass through the real runtime and the platform liveness: while `run`'s
/// child runs, its binding is active; once that exact process exits, the supervisor
/// releases the binding (jittered pass, default interval 5 s).
#[cfg(unix)]
#[test]
fn holder_pass_releases_the_binding_once_the_run_exits() {
    let rig = Rig::new();
    let fifo = rig.file("hold");
    mkfifo(&fifo);
    let meta = rig.file("meta.ndjson");
    let script = format!("read x < '{}'", fifo.display());
    let args = run_args(Some(&meta), &os(&["/bin/sh", "-c", &script]));
    let running = Running(Some(
        rig.command(&refs(&args), &[])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    wait_for("launching", Duration::from_secs(30), || {
        std::fs::read_to_string(&meta).is_ok_and(|t| t.ends_with('\n'))
    });
    let (_, binding) = launching_ids(&records(&meta));
    let binding = binding.unwrap();
    let state = |rig: &Rig| binding_state(rig, &binding);
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(state(&rig), "active", "the holder still runs");
    {
        use std::io::Write as _;
        let mut w = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        writeln!(w, "go").unwrap();
    }
    let status = running.wait(Duration::from_secs(30));
    assert_eq!(status.code(), Some(0));
    wait_for("the holder pass", Duration::from_secs(20), || {
        state(&rig) != "active"
    });
}

// =================================================================================
// Git under `run` (M2-D10)
// =================================================================================

#[cfg(unix)]
fn git(rig: &Rig, dir: &Path, args: &[&str]) {
    let out = rig
        .command_of(OsStr::new("/usr/bin/git"), &refs(&os(args)), &[])
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// m02-plan U8 `git_run_resolution_in_child_cwd_reports_local_override_and_injects_nothing`:
/// in a repository whose local configuration sets `core.sshCommand`, `launching`
/// reports that override (setting and scope, never the value) and nothing is set for
/// Git; outside it nothing is reported.
#[cfg(unix)]
#[test]
fn git_run_resolution_in_child_cwd_reports_local_override_and_injects_nothing() {
    let rig = Rig::new();
    let repo = rig.work().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&rig, &repo, &["init", "-q"]);
    git(
        &rig,
        &repo,
        &["config", "core.sshCommand", "/usr/bin/ssh -o BatchMode=yes"],
    );
    let meta = rig.file("meta.ndjson");
    let mut cmd = rig.command(
        &refs(&run_args(Some(&meta), &os(&["/usr/bin/env", "-0"]))),
        &[],
    );
    let out = finish(
        cmd.current_dir(&repo)
            .stdin(Stdio::null())
            .output()
            .unwrap(),
    );
    assert_eq!(out.code(), Some(0), "{}", out.stderr);
    match records(&meta).as_slice() {
        [
            RunRecord::Launching {
                consumer_overrides, ..
            },
        ] => {
            let text = serde_json::to_string(consumer_overrides).unwrap();
            assert_eq!(
                text,
                r#"[{"consumer":"git","setting":"core.sshCommand","source":{"kind":"git_scope","scope":"local"}}]"#
            );
            assert!(!text.contains("BatchMode"), "never the value");
        }
        other => panic!("{other:?}"),
    }
    let env = env_pairs(&out.stdout);
    assert!(
        env.iter()
            .all(|(k, _)| !k.starts_with("GIT_CONFIG_KEY") && k != "GIT_SSH_COMMAND"),
        "nothing injected on Unix"
    );
    // Outside the repository: Git's default, nothing reported.
    let plain = rig.file("plain.ndjson");
    let out = rig.run_with(&refs(&run_args(Some(&plain), &os(&["/usr/bin/true"]))), &[]);
    assert_eq!(out.code(), Some(0));
    assert!(matches!(
        records(&plain).as_slice(),
        [RunRecord::Launching { consumer_overrides, .. }] if consumer_overrides.is_empty()
    ));
}

/// A stub "client" that records which one ran: `<dir>/<name>` appends its name to
/// `<dir>/ran` and exits 1 (Git then stops).
#[cfg(unix)]
fn stub(dir: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let p = dir.join(name);
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\necho {name} >> '{}'\nexit 1\n",
            dir.join("ran").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// m02-plan U8 `git_run_injection_yields_to_dash_c_and_env` (settles F22's
/// `GIT_CONFIG_COUNT` claim on this Git): a `core.sshCommand` given through
/// `GIT_CONFIG_COUNT` (what the Windows injection appends) loses to a per-command `-c`
/// and to `GIT_SSH_COMMAND`, and wins over nothing else. Through `heimdall run` on
/// Unix the caller's entries reach Git unchanged (nothing is appended).
#[cfg(unix)]
#[test]
fn git_run_injection_yields_to_dash_c_and_env() {
    let rig = Rig::new();
    let dir = rig.file("stubs");
    std::fs::create_dir(&dir).unwrap();
    let injected = stub(&dir, "injected");
    let dash_c = stub(&dir, "dash_c");
    let env_cmd = stub(&dir, "env");
    let ran = dir.join("ran");
    let count = [
        ("GIT_CONFIG_COUNT", OsStr::new("1")),
        ("GIT_CONFIG_KEY_0", OsStr::new("core.sshCommand")),
        ("GIT_CONFIG_VALUE_0", injected.as_os_str()),
        ("GIT_TERMINAL_PROMPT", OsStr::new("0")),
    ];
    let ls_remote = |pre: &[&str], extra: &[(&str, &OsStr)]| {
        let _ = std::fs::remove_file(&ran);
        let mut argv: Vec<OsString> = vec!["/usr/bin/git".into()];
        argv.extend(os(pre));
        argv.extend(os(&["ls-remote", "ssh://fixture.invalid/repo"]));
        let mut all: Vec<(&str, &OsStr)> = count.to_vec();
        all.extend_from_slice(extra);
        let out = rig.run_with(&refs(&run_args(None, &argv)), &all);
        assert_ne!(out.code(), Some(0));
        // Git may start its SSH command more than once (a retried protocol); each
        // start names the client that ran.
        let ran: std::collections::BTreeSet<String> = std::fs::read_to_string(&ran)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        ran.into_iter().collect::<Vec<_>>().join(",")
    };
    assert_eq!(
        ls_remote(&[], &[]),
        "injected",
        "the environment entry applies"
    );
    let dash = format!("core.sshCommand={}", dash_c.display());
    assert_eq!(
        ls_remote(&["-c", &dash], &[]),
        "dash_c",
        "-c wins over GIT_CONFIG_COUNT"
    );
    assert_eq!(
        ls_remote(&[], &[("GIT_SSH_COMMAND", env_cmd.as_os_str())]),
        "env",
        "GIT_SSH_COMMAND wins over GIT_CONFIG_COUNT"
    );
}

/// m02-plan U8 `git_run_never_records_child_arguments_or_config_values`: canaries in
/// the child's arguments and in a `core.sshCommand` value reach Git and the child,
/// and appear in no record, envelope, diagnostic, store or log.
#[cfg(unix)]
#[test]
fn git_run_never_records_child_arguments_or_config_values() {
    let rig = Rig::new();
    let repo = rig.work().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&rig, &repo, &["init", "-q"]);
    let value_canary = format!(
        "{}GITVALUE_{}",
        heimdall_testkit::CANARY_PREFIX,
        std::process::id()
    );
    let arg_canary = format!(
        "{}GITARG_{}",
        heimdall_testkit::CANARY_PREFIX,
        std::process::id()
    );
    git(
        &rig,
        &repo,
        &[
            "config",
            "core.sshCommand",
            &format!("/usr/bin/ssh -o SetEnv={value_canary}"),
        ],
    );
    let meta = rig.file("meta.ndjson");
    let argv = os(&[
        "/usr/bin/git",
        "config",
        "--get",
        "core.sshCommand",
        &arg_canary,
    ]);
    let mut cmd = rig.command(&refs(&run_args(Some(&meta), &argv)), &[]);
    let out = cmd
        .current_dir(&repo)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // Git rejects the extra argument; what matters is what Heimdall recorded.
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let mut scanned = vec![
        ("meta".to_owned(), std::fs::read(&meta).unwrap()),
        ("stderr".to_owned(), stderr.clone().into_bytes()),
    ];
    for (path, bytes) in all_bytes(&rig.home()) {
        scanned.push((path.display().to_string(), bytes));
    }
    for (label, bytes) in &scanned {
        for canary in [&value_canary, &arg_canary] {
            assert!(!contains(bytes, canary), "a canary leaked into {label}");
        }
    }
    assert!(matches!(
        records(&meta).as_slice(),
        [RunRecord::Launching { .. }]
    ));
}

/// m02-plan U8 `git_run_malformed_caller_git_config_count_injects_nothing`: a
/// malformed caller `GIT_CONFIG_COUNT` reaches the child unchanged, and nothing is
/// added (the Windows rule's unit cases are in `heimdall_launch::env`).
#[cfg(unix)]
#[test]
fn git_run_malformed_caller_git_config_count_injects_nothing() {
    let rig = Rig::new();
    for count in ["abc", "", "+1", "2"] {
        let extra = [("GIT_CONFIG_COUNT", OsStr::new(count))];
        let out = rig.run_with(&refs(&run_args(None, &os(&["/usr/bin/env", "-0"]))), &extra);
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        let env = env_pairs(&out.stdout);
        assert!(env.contains(&("GIT_CONFIG_COUNT".to_owned(), count.to_owned())));
        assert!(env.iter().all(|(k, _)| !k.starts_with("GIT_CONFIG_KEY")));
    }
}

// =================================================================================
// A11 (Q2 as qualified): non-interactive launches against real existing access
// =================================================================================

/// The A11 cases: a runtime **in this test process** (`heimdall_runtime::service::
/// Service`, the existing-access adapters, the real projection writer over a
/// `ScratchHome`), and the real `heimdall` binary as its client through the
/// advertised control endpoint (the same `HEIMDALL_HOME`). Catalog, setup and
/// decisions go through `Operations` with an attended owner caller, as the CLI's owner
/// flow would; `run` and `connect` are always the binary. The identity's agent is a
/// counting `FakeAgent` in scratch; the CLI's static selection pass reads the scratch
/// home (`HEIMDALL_TEST_SSH_HOME`). The marker-file cases run nothing that contacts an
/// agent, so every "launched" is a marker file and every refusal also shows zero agent
/// contacts. The cases through a real client (`SshWorld`) run `ssh`, `scp`, `sftp` and
/// `git` with only the scratch isolation arguments, against the loopback fixture sshd;
/// the confirm-constraint cases adopt their keys at a `CountingProxy` in front of U7's
/// `DisposableSshAgent` with the counting askpass (`World::attach_real`), so every
/// agent contact and every prompt is counted.
///
/// **Restart label.** A "restart" here stops the in-process service (token, drain)
/// and starts a new one over the same directories: an in-process reconstruction, as
/// M01's suites label it, with the client still the real binary.
#[cfg(unix)]
mod a11 {
    use std::sync::Arc;

    use heimdall_app::{Attendance, Caller, OpError, Operations};
    use heimdall_contract::catalog::{
        CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
        IdentitySourceSpec, IdentitySpec, ProfileSpec, WithdrawReason,
    };
    use heimdall_contract::ids::{
        AccountName, DecisionId, DestinationId, IdentityId, PolicyId, ProfileId, RequestId,
    };
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_contract::request::{AccessPairRef, DecideRequest, InteractionMode, Verdict};
    use heimdall_contract::setup::{PreviewIntent, SetupPlan, SetupRequest};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::ProjectionConfig;
    use heimdall_runtime::config::{Config, Paths};
    use heimdall_runtime::service::{ProjectionWiring, Service, ServiceOptions};
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::home::ScratchHome;
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// A running in-process service.
    struct Running {
        ops: Operations,
        store: Arc<heimdall_store::Store>,
        token: CancellationToken,
        handle: tokio::runtime::Handle,
        thread: std::thread::JoinHandle<()>,
    }

    /// One destination of the fixture: its alias, destination ID and identity.
    struct Dest {
        alias: &'static str,
        id: &'static str,
    }

    const ALPHA: Dest = Dest {
        alias: "alpha",
        id: "dst-alpha",
    };
    const BETA: Dest = Dest {
        alias: "beta",
        id: "dst-beta",
    };

    struct World {
        home: ScratchHome,
        service: Option<Running>,
        agent: FakeAgent,
        /// A real disposable `ssh-agent` behind a counting proxy, when the test adopts
        /// its keys at the proxy instead of at the fake agent ([`World::attach_real`]).
        real: Option<RealAgent>,
        keys: Vec<FixtureKey>,
        uid: u32,
        n: std::sync::atomic::AtomicU32,
    }

    /// U7's `DisposableSshAgent` (with the counting askpass) behind a `CountingProxy`;
    /// identities adopted at the proxy's socket, so every agent contact is counted.
    struct RealAgent {
        agent: heimdall_testkit::agent::DisposableSshAgent,
        proxy: heimdall_testkit::agent::CountingProxy,
    }

    fn rid(s: &str) -> RequestId {
        RequestId::parse(s).unwrap()
    }

    impl World {
        /// A scratch home, one fake agent holding `keys` keys, the service started.
        fn new(keys: usize) -> World {
            World::with_mode(keys, AgentMode::Normal)
        }

        /// [`new`](Self::new) with the fake agent in `mode`.
        fn with_mode(keys: usize, mode: AgentMode) -> World {
            use std::os::unix::fs::MetadataExt as _;
            let home = ScratchHome::new();
            std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
            let keys = FixtureKey::generate_many(keys);
            let agent = FakeAgent::start(
                Endpoint::in_scratch(home.scratch(), "agent").unwrap(),
                FakeAgentConfig {
                    keys: keys.clone(),
                    mode,
                },
            );
            let uid = std::fs::metadata(&home.root).unwrap().uid();
            let mut w = World {
                home,
                service: None,
                agent,
                real: None,
                keys,
                uid,
                n: std::sync::atomic::AtomicU32::new(0),
            };
            w.start();
            w
        }

        /// Start U7's disposable `ssh-agent` with the counting askpass (answer
        /// `Approve`) and a counting proxy in front of it, in this world's scratch.
        /// Identities adopted afterwards are adopted at the proxy's socket.
        fn attach_real(&mut self) {
            use heimdall_testkit::agent::{
                AgentOptions, AskpassAnswer, CountingProxy, DisposableSshAgent,
            };
            let scratch = self.home.scratch();
            let agent = DisposableSshAgent::start(
                scratch,
                AgentOptions {
                    askpass_log: Some(self.home.root.join("askpass.log")),
                    askpass_answer: AskpassAnswer::Approve,
                },
            )
            .unwrap_or_else(|e| panic!("the disposable ssh-agent (hm-fixture-hook built?): {e}"));
            let proxy = CountingProxy::start(
                &agent.endpoint(),
                Endpoint::in_scratch(scratch, "proxy").unwrap(),
            );
            self.real = Some(RealAgent { agent, proxy });
        }

        fn real(&self) -> &RealAgent {
            self.real.as_ref().expect("attach_real first")
        }

        /// Add key `k` to the disposable agent, with a fixed comment that is not a
        /// canary (`ssh` prints the comment of a key whose signature the agent refuses).
        fn add_real_key(&self, k: usize, confirm: bool) {
            use heimdall_testkit::agent::KeyConstraints;
            self.real()
                .agent
                .add_key(
                    &self.keys[k].with_comment(&format!("hm-fixture-k{k}")),
                    KeyConstraints { confirm },
                )
                .unwrap();
        }

        /// ADR-0007 F23 (M2-R08): the confirm constraint is installed on this agent:
        /// one signature through the proxy, askpass `Approve`, prompts exactly once.
        fn verify_confirm_installed(&self, k: usize) {
            let real = self.real();
            let socket = match real.proxy.endpoint() {
                Endpoint::UnixSocket(p) => p.clone(),
                other => panic!("{other:?}"),
            };
            let control = real
                .agent
                .sign_control_through(&socket, &self.keys[k], b"hm-fixture U8 A11 control")
                .unwrap();
            assert!(control.signed, "{control:?}");
            assert_eq!(control.askpass_delta, 1, "the confirm constraint is active");
        }

        /// The proxy's forwarded requests and the askpass invocations so far.
        fn counts(&self) -> (usize, u32) {
            let real = self.real();
            (real.proxy.count(), real.agent.askpass_count())
        }

        fn endpoint(&self) -> EndpointRef {
            let locator = match &self.real {
                Some(real) => real.proxy.endpoint().locator(),
                None => self.agent.endpoint().locator(),
            };
            EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: locator.to_str().unwrap().to_owned(),
            }
        }

        fn projection(&self) -> ProjectionConfig {
            let paths = SshPaths::with_test_override(
                self.home.git_home.clone(),
                self.home.root.join("etc-ssh"),
            );
            let mut c =
                ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone());
            c.env = Env::from_vars([
                ("HOME", self.home.git_home.display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
                (
                    "SSH_AUTH_SOCK",
                    self.agent
                        .endpoint()
                        .locator()
                        .to_string_lossy()
                        .into_owned(),
                ),
            ]);
            c
        }

        /// Start the service on its own thread and current-thread executor; the test
        /// reaches the operations through [`World::on`].
        fn start(&mut self) {
            let projection = self.projection();
            let root = self.home.root.clone();
            let token = CancellationToken::new();
            let service_token = token.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let handle = rt.handle().clone();
                rt.block_on(async move {
                    let clock =
                        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap());
                    let mut o = ServiceOptions::with_clock(
                        clock,
                        heimdall_testkit::ScriptedTimeSync::new(
                            heimdall_domain::time::SyncStatus::Synchronized,
                        ),
                    );
                    o.projection = ProjectionWiring::Config(Box::new(projection));
                    o.existing_access = true;
                    let service = Service::start_with(
                        Paths::under(&root),
                        Config::default(),
                        o,
                        service_token,
                    )
                    .await
                    .unwrap();
                    let _ = tx.send((
                        handle,
                        service.operations().clone(),
                        Arc::clone(service.store()),
                    ));
                    let _ = service.run().await;
                });
            });
            let (handle, ops, store) = rx.recv().expect("the service started");
            self.service = Some(Running {
                ops,
                store,
                token,
                handle,
                thread,
            });
        }

        fn stop(&mut self) {
            if let Some(s) = self.service.take() {
                s.token.cancel();
                let _ = s.thread.join();
            }
        }

        /// Run `f` on the service's executor and wait for it.
        fn on<T: Send + 'static>(
            &self,
            f: impl std::future::Future<Output = T> + Send + 'static,
        ) -> T {
            let (tx, rx) = std::sync::mpsc::channel();
            self.service.as_ref().unwrap().handle.spawn(async move {
                let _ = tx.send(f.await);
            });
            rx.recv().expect("the service task finished")
        }

        fn restart(&mut self) {
            self.stop();
            self.start();
        }

        fn ops(&self) -> &Operations {
            &self.service.as_ref().unwrap().ops
        }

        fn owner(&self) -> CallerContext {
            CallerContext {
                principal: PrincipalRef::UnixUser { uid: self.uid },
                role: ClientRole::Owner,
            }
        }

        fn attended(&self) -> Caller {
            Caller {
                context: self.owner(),
                attendance: Attendance::Attended {
                    since: heimdall_contract::Timestamp::now(),
                },
                interaction: InteractionMode::Interactive,
            }
        }

        fn next_id(&self, what: &str) -> RequestId {
            let n = self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            rid(&format!("r-{what}-{n}"))
        }

        fn catalog(&self, req: CatalogRequest) -> Result<Value, OpError> {
            let caller = self.attended();
            let ops = self.ops().clone();
            self.on(async move { ops.catalog(&caller, req).await.map(|c| c.data) })
        }

        fn setup(&self, req: SetupRequest) -> Result<Value, OpError> {
            let caller = self.attended();
            let ops = self.ops().clone();
            self.on(async move { ops.setup(&caller, req).await.map(|c| c.data) })
        }

        /// Approve the decision an error names.
        fn approve(&self, e: &OpError) {
            let d = e.next.decision_ref.clone().expect("a decision reference");
            let caller = self.attended();
            let ops = self.ops().clone();
            self.on(async move {
                ops.decide(
                    &caller,
                    DecideRequest {
                        decision_id: DecisionId::parse(&d).unwrap(),
                        verdict: Verdict::Approve,
                    },
                )
                .await
                .map(|_| ())
            })
            .unwrap();
        }

        /// Adopt key `k` at the agent.
        fn adopt(&self, k: usize) -> IdentityId {
            let data = self
                .catalog(CatalogRequest::AdoptIdentity {
                    identity: IdentitySpec {
                        source: IdentitySourceSpec::NativeAgent {
                            endpoint: self.endpoint(),
                        },
                        public_key: self.keys[k].public_line_without_comment(),
                        label: None,
                    },
                    request_id: self.next_id("adopt"),
                })
                .unwrap();
            IdentityId::parse(data["identity_id"].as_str().unwrap()).unwrap()
        }

        fn destination(&self, d: &Dest, identity: &IdentityId) {
            self.catalog(CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse(d.id).unwrap(),
                    alias: d.alias.to_owned(),
                    definition: DestinationDefinitionSpec::Managed {
                        hostname: format!("{}.example.invalid", d.alias),
                        port: None,
                        account: AccountName::parse("fixture").unwrap(),
                        identity: identity.clone(),
                    },
                    label: None,
                },
                request_id: self.next_id("dest"),
            })
            .unwrap();
        }

        fn pair(d: &Dest, account: &str) -> AccessPairRef {
            AccessPairRef {
                destination: DestinationId::parse(d.id).unwrap(),
                account: AccountName::parse(account).unwrap(),
            }
        }

        /// Profile `work` over `dests`, covered by a standing policy (seeded through
        /// the store, as M01's suites do).
        fn profile(&self, dests: &[&Dest]) {
            self.profile_as(dests, "fixture");
        }

        /// [`profile`](Self::profile) with the pairs' account `account`.
        fn profile_as(&self, dests: &[&Dest], account: &str) {
            self.catalog(CatalogRequest::UpsertProfile {
                profile: ProfileSpec {
                    id: ProfileId::parse("work").unwrap(),
                    pairs: dests.iter().map(|d| World::pair(d, account)).collect(),
                    label: None,
                },
                request_id: self.next_id("profile"),
            })
            .unwrap();
            use heimdall_domain::environment::{
                EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
            };
            use heimdall_domain::policy::{
                PauseState, PolicyRevision, PolicySource, StandingPolicy,
            };
            use heimdall_domain::scope::{AccessPair, Scope};
            let store = Arc::clone(&self.service.as_ref().unwrap().store);
            let env = self.ops().environment().clone();
            let pairs: std::collections::BTreeSet<AccessPair> = dests
                .iter()
                .map(|d| AccessPair {
                    destination: DestinationId::parse(d.id).unwrap(),
                    account: AccountName::parse(account).unwrap(),
                })
                .collect();
            store
                .transaction(|tx| {
                    tx.upsert_environment(&EnvironmentRecord {
                        id: env.clone(),
                        device: heimdall_contract::ids::DeviceId::from_random_bytes([8; 16]),
                        kind: EnvironmentKind::NativeSession,
                        label: None,
                        permissions: EnvironmentPermissions {
                            automatic_activation: true,
                            managed_signing: true,
                            issuer_access: true,
                        },
                    })?;
                    tx.upsert_policy(
                        &StandingPolicy {
                            id: PolicyId::parse("pol").unwrap(),
                            revision: PolicyRevision(1),
                            profile: ProfileId::parse("work").unwrap(),
                            workspace: None,
                            scope: Scope {
                                pairs: pairs.clone(),
                                capabilities: [
                                    heimdall_contract::request::Capability::SshAuthentication,
                                ]
                                .into_iter()
                                .collect(),
                            },
                            environments: [env.clone()].into_iter().collect(),
                            max_window: Duration::from_secs(2 * 3600),
                            pause: PauseState::Active,
                            cutoff_at: None,
                            source: PolicySource::SetupDefault,
                        },
                        false,
                    )
                })
                .unwrap();
        }

        /// Preview and apply the projection (approved).
        fn project(&self) {
            let plan = self
                .setup(SetupRequest::Preview {
                    intent: PreviewIntent::Apply { include_git: false },
                })
                .unwrap();
            let plan: SetupPlan = serde_json::from_value(plan).unwrap();
            let apply = |id: RequestId| SetupRequest::Apply {
                plan_digest: plan.plan_digest.clone(),
                request_id: id,
            };
            let id = self.next_id("apply");
            if let Err(e) = self.setup(apply(id.clone())) {
                self.approve(&e);
                self.setup(apply(id)).unwrap();
            }
            assert!(self.home.config_dir.join("ssh_config").exists());
        }

        /// Declare `identity` `none` (an attended, approved decision).
        fn declare(&self, identity: &IdentityId) {
            let id = self.next_id("declare");
            let req = || CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
                request_id: id.clone(),
            };
            let e = self.catalog(req()).unwrap_err();
            self.approve(&e);
            self.catalog(req()).unwrap();
        }

        fn withdraw(&self, identity: &IdentityId, reason: WithdrawReason) {
            let data = self
                .catalog(CatalogRequest::WithdrawDeclaration {
                    identity: identity.clone(),
                    revision: None,
                    reason,
                    request_id: self.next_id("withdraw"),
                })
                .unwrap();
            assert_eq!(data["withdrawn"], true);
        }

        /// The usual fixture: identity 0 adopted for `alpha`, profile `work`, the
        /// projection applied, optionally declared.
        fn single(declared: bool) -> (World, IdentityId) {
            let w = World::new(2);
            let id = w.adopt(0);
            w.destination(&ALPHA, &id);
            w.profile(&[&ALPHA]);
            w.project();
            if declared {
                w.declare(&id);
            }
            (w, id)
        }

        fn env(&self) -> Vec<(OsString, OsString)> {
            let g = &self.home.git_home;
            vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), g.clone().into_os_string()),
                (
                    "HEIMDALL_HOME".into(),
                    self.home.root.clone().into_os_string(),
                ),
                ("HEIMDALL_TEST_SSH_HOME".into(), g.clone().into_os_string()),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                (
                    "GIT_CONFIG_GLOBAL".into(),
                    g.join(".gitconfig").into_os_string(),
                ),
            ]
        }

        fn cli(&self, args: &[OsString], extra: &[(&str, &OsStr)]) -> Command {
            let mut cmd = Command::new(bin());
            cmd.args(args).env_clear().current_dir(&self.home.root);
            for (k, v) in self.env() {
                cmd.env(k, v);
            }
            for (k, v) in extra {
                cmd.env(k, v);
            }
            cmd.stdin(Stdio::null());
            cmd
        }

        fn run_cli(&self, args: &[OsString], extra: &[(&str, &OsStr)]) -> Out {
            finish(self.cli(args, extra).output().unwrap())
        }

        fn marker(&self, name: &str) -> PathBuf {
            self.home.root.join(name)
        }

        /// `heimdall --json [--non-interactive] run --profile work [flags] --meta-file
        /// <meta> -- /bin/sh -c 'touch <marker>'`.
        fn run_args(&self, name: &str, non_interactive: bool, flags: &[&str]) -> Vec<OsString> {
            let mut a = os(&["--json"]);
            if non_interactive {
                a.push("--non-interactive".into());
            }
            a.extend(os(&["run", "--profile", "work"]));
            a.extend(os(flags));
            a.push("--meta-file".into());
            a.push(self.marker(&format!("{name}.ndjson")).into_os_string());
            a.push("--".into());
            let script = format!("touch '{}'", self.marker(name).display());
            a.extend(os(&["/bin/sh", "-c", &script]));
            a
        }

        fn launched(&self, name: &str) -> bool {
            self.marker(name).exists()
        }

        fn records(&self, name: &str) -> Vec<RunRecord> {
            records(&self.marker(&format!("{name}.ndjson")))
        }

        /// Run with a pre-check pause: `during` runs while the CLI is held after
        /// `bind`, before the pre-launch check.
        fn run_paused(
            &self,
            args: &[OsString],
            extra: &[(&str, &OsStr)],
            during: impl FnOnce(),
        ) -> Out {
            let fifo = self.home.root.join(format!(
                "pause-{}",
                self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
            mkfifo(&fifo);
            let mut all: Vec<(&str, &OsStr)> =
                vec![("HEIMDALL_TEST_PRE_CHECK_PAUSE", fifo.as_os_str())];
            all.extend_from_slice(extra);
            let child = self
                .cli(args, &all)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            // The open returns once the CLI is paused; closing it releases the CLI.
            let w = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
            during();
            drop(w);
            finish(child.wait_with_output().unwrap())
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            self.stop();
            // Stop the disposable agent (exact PID) and its proxy before the scratch
            // directory goes.
            if let Some(mut real) = self.real.take() {
                real.proxy.stop();
                real.agent.stop();
            }
        }
    }

    fn code_of(out: &Out) -> String {
        out.envelope()["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    fn reason_of(out: &Out) -> String {
        out.envelope()["data"]["error"]["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    /// The refusal shape every pre-launch eligibility refusal has (ADR-0007 §7):
    /// exit 3, `INTERACTION_REQUIRED` with `reason`, `next: interact` with a provider
    /// interaction and never a `decision_ref`, a `prelaunch_failed` record, no child,
    /// and no agent contact.
    fn assert_refused(w: &World, name: &str, out: &Out, reason: &str) {
        assert_eq!(out.code(), Some(3), "{}", out.stderr);
        assert_eq!(code_of(out), "INTERACTION_REQUIRED", "{}", out.stderr);
        assert_eq!(reason_of(out), reason, "{}", out.stderr);
        let next = &out.envelope()["next"];
        assert_eq!(next["action"], "interact");
        assert!(next.get("decision_ref").is_none_or(Value::is_null));
        assert!(!w.launched(name), "{name} launched");
        assert!(out.stdout.is_empty());
        assert_eq!(
            classify(&w.records(name), PLATFORM),
            LaunchClassification::NotLaunched {
                code: Some(heimdall_contract::Code::InteractionRequired),
                reason: Some(reason.to_owned()),
            }
        );
        assert_eq!(w.agent.contact_count(), 0, "no agent contact");
    }

    fn assert_launched(w: &World, name: &str, out: &Out) {
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        assert!(w.launched(name), "{name} did not launch: {}", out.stderr);
        assert!(matches!(
            w.records(name).as_slice(),
            [RunRecord::Launching { .. }]
        ));
    }

    /// m02-plan U8 `a11_declared_none_allows_noninteractive_launch_and_result_says_declared`.
    #[test]
    fn a11_declared_none_allows_noninteractive_launch_and_result_says_declared() {
        let (w, id) = World::single(true);
        let out = w.run_cli(&w.run_args("go", true, &[]), &[]);
        assert_launched(&w, "go", &out);
        // The result the launch relied on says `none`, basis `declared`.
        let ensured = w.run_cli(
            &os(&[
                "--json",
                "--non-interactive",
                "access",
                "ensure",
                "--profile",
                "work",
                "--work-id",
                "w-result",
                "--request-id",
                "r-result",
            ]),
            &[],
        );
        assert_eq!(ensured.code(), Some(0), "{}", ensured.stderr);
        let env: Value = serde_json::from_slice(&ensured.stdout).unwrap();
        let pair = &env["data"]["consumer"]["pairs"][0];
        assert_eq!(pair["identity"], serde_json::json!(id));
        assert_eq!(pair["interaction"], "none");
        assert_eq!(pair["interaction_basis"], "declared");
        assert_eq!(pair["noninteractive"]["eligible"], true);
        assert!(pair["declaration"]["revision"].is_u64());
        assert_eq!(w.agent.contact_count(), 0);
    }

    /// m02-plan U8 `a11_noninteractive_run_refuses_interactive_identity_before_launch`:
    /// an identity whose interaction is `unknown` (no declaration) is refused under
    /// `--non-interactive` before launch, with no agent contact; with
    /// `--allow-provider-interaction` the child launches.
    #[test]
    fn a11_noninteractive_run_refuses_interactive_identity_before_launch() {
        let (w, _) = World::single(false);
        let out = w.run_cli(&w.run_args("refused", true, &[]), &[]);
        assert_refused(&w, "refused", &out, "interaction_unknown");
        let out = w.run_cli(
            &w.run_args("allowed", true, &["--allow-provider-interaction"]),
            &[],
        );
        assert_launched(&w, "allowed", &out);
    }

    /// m02-plan U8 `a11_multi_pair_binding_refused_when_any_pair_needs_interaction`
    /// (QR5): two pairs, one declared: refused; both declared: launched.
    #[test]
    fn a11_multi_pair_binding_refused_when_any_pair_needs_interaction() {
        let w = World::new(2);
        let a = w.adopt(0);
        let b = w.adopt(1);
        w.destination(&ALPHA, &a);
        w.destination(&BETA, &b);
        w.profile(&[&ALPHA, &BETA]);
        w.project();
        w.declare(&a);
        let out = w.run_cli(&w.run_args("one", true, &[]), &[]);
        assert_refused(&w, "one", &out, "interaction_unknown");
        w.declare(&b);
        let out = w.run_cli(&w.run_args("both", true, &[]), &[]);
        assert_launched(&w, "both", &out);
    }

    /// m02-plan U8 `a11_declaration_withdrawn_after_bind_refused_before_launch`: `ensure`
    /// and `bind` report `none` (declared); the declaration is withdrawn while the CLI
    /// is held between `bind` and the check; the launch is refused.
    #[test]
    fn a11_declaration_withdrawn_after_bind_refused_before_launch() {
        let (w, id) = World::single(true);
        let out = w.run_paused(&w.run_args("w", true, &[]), &[], || {
            w.withdraw(&id, WithdrawReason::Owner);
        });
        assert_refused(&w, "w", &out, "interaction_unknown");
        // The record names the bind that relied on the declaration.
        assert!(matches!(
            w.records("w").as_slice(),
            [RunRecord::PrelaunchFailed {
                operation_id: Some(_),
                binding_id: Some(_),
                ..
            }]
        ));
    }

    /// m02-plan U8 `a11_redeclaration_after_bind_changes_revision_and_refuses_launch`:
    /// withdraw and re-declare during the pause: `none` again, but another revision,
    /// so the launch is refused; a fresh `run` launches.
    #[test]
    fn a11_redeclaration_after_bind_changes_revision_and_refuses_launch() {
        let (w, id) = World::single(true);
        let out = w.run_paused(&w.run_args("re", true, &[]), &[], || {
            w.withdraw(&id, WithdrawReason::Owner);
            w.declare(&id);
        });
        assert_refused(&w, "re", &out, "interaction_unknown");
        let out = w.run_cli(&w.run_args("fresh", true, &[]), &[]);
        assert_launched(&w, "fresh", &out);
    }

    /// m02-plan U8 `a11_declaration_expiring_between_bind_and_launch_refused`: the
    /// CLI's clock (`HEIMDALL_TEST_CLOCK_OFFSET_S`, read through a file) is moved past
    /// the declaration's `expires_at` during the pause.
    #[test]
    fn a11_declaration_expiring_between_bind_and_launch_refused() {
        let (w, _) = World::single(true);
        let offset = w.home.root.join("offset");
        std::fs::write(&offset, "0").unwrap();
        let out = w.run_paused(
            &w.run_args("exp", true, &[]),
            &[("HEIMDALL_TEST_CLOCK_OFFSET_S", offset.as_os_str())],
            || {
                let tmp = w.home.root.join("offset.tmp");
                std::fs::write(&tmp, (400 * 24 * 3600).to_string()).unwrap();
                std::fs::rename(&tmp, &offset).unwrap();
            },
        );
        assert_refused(&w, "exp", &out, "interaction_unknown");
        // Back at the real time, the same identity launches.
        std::fs::write(&offset, "0").unwrap();
        let out = w.run_cli(
            &w.run_args("now", true, &[]),
            &[("HEIMDALL_TEST_CLOCK_OFFSET_S", offset.as_os_str())],
        );
        assert_launched(&w, "now", &out);
    }

    /// The `ensure` the CLI replays: an `access ensure` with `request_id`, which also
    /// names the work (so `run --request-id <it>` replays it).
    fn ensure_first(w: &World, request_id: &str) {
        let out = w.run_cli(
            &os(&[
                "--json",
                "--non-interactive",
                "access",
                "ensure",
                "--profile",
                "work",
                "--work-id",
                request_id,
                "--request-id",
                request_id,
            ]),
            &[],
        );
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        let env: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(env["data"]["consumer"]["pairs"][0]["interaction"], "none");
    }

    /// m02-plan U8 `a11_lapse_recorded_by_failed_listing_between_ensure_and_bind_refuses_launch`:
    /// after `ensure` reported `none`, an explicit agent listing that lacks the
    /// fingerprint records `WithdrawDeclaration { reason: listing_missing }` (sent here
    /// as the doctor would, U9 owning the doctor command); the `run` that replays that
    /// `ensure` gets a fresh `bind` result and is refused. Also across a runtime restart
    /// between `ensure` and `bind` (the restart restores history, never eligibility).
    #[test]
    fn a11_lapse_recorded_by_failed_listing_between_ensure_and_bind_refuses_launch() {
        for restart in [false, true] {
            let (mut w, id) = World::single(true);
            ensure_first(&w, "req-lapse");
            if restart {
                w.restart();
            }
            w.withdraw(&id, WithdrawReason::ListingMissing);
            let out = w.run_cli(
                &w.run_args("lapse", true, &["--request-id", "req-lapse"]),
                &[],
            );
            assert_refused(&w, "lapse", &out, "interaction_unknown");
        }
    }

    /// The withdrawal and re-declaration cases with a runtime restart between `ensure`
    /// and `bind` (m02-plan U8: "each of the above also runs after a runtime restart").
    #[test]
    fn a11_withdrawal_and_redeclaration_after_a_restart_between_ensure_and_bind_refuse() {
        for redeclare in [false, true] {
            let (mut w, id) = World::single(true);
            ensure_first(&w, "req-restart");
            w.restart();
            w.withdraw(&id, WithdrawReason::Owner);
            if redeclare {
                w.declare(&id);
            }
            let out = w.run_cli(
                &w.run_args("r", true, &["--request-id", "req-restart"]),
                &[],
            );
            if redeclare {
                // The bind is fresh and sees the new declaration; the replayed
                // `ensure` result relied on the old one, but the check reads the bind
                // result, which relies on the new revision: launched.
                assert_launched(&w, "r", &out);
            } else {
                assert_refused(&w, "r", &out, "interaction_unknown");
            }
        }
    }

    /// m02-plan U8 `a11_replayed_bind_result_still_gets_prelaunch_check`: the same
    /// `bind` request ID is replayed after a withdrawal; the replayed envelope still
    /// says `none`, and the launch is refused. Also across a restart.
    #[test]
    fn a11_replayed_bind_result_still_gets_prelaunch_check() {
        for restart in [false, true] {
            let (mut w, id) = World::single(true);
            let out = w.run_cli(
                &w.run_args("first", true, &["--request-id", "req-replay"]),
                &[],
            );
            assert_launched(&w, "first", &out);
            if restart {
                w.restart();
            }
            w.withdraw(&id, WithdrawReason::Owner);
            let out = w.run_cli(
                &w.run_args("again", true, &["--request-id", "req-replay"]),
                &[],
            );
            assert_refused(&w, "again", &out, "interaction_unknown");
            // The same operation and binding replayed.
            let first = launching_ids(&w.records("first"));
            match w.records("again").as_slice() {
                [
                    RunRecord::PrelaunchFailed {
                        operation_id,
                        binding_id,
                        ..
                    },
                ] => {
                    assert_eq!(operation_id.as_ref().map(ToString::to_string), first.0);
                    assert_eq!(binding_id.as_ref().map(ToString::to_string), first.1);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// Append to the scratch user configuration (after Heimdall's include block).
    fn append_user_config(w: &World, text: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&w.home.user_config)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    /// Key `k`'s public half at `<scratch>/<name>.pub` (no private file: agent-backed).
    fn write_pub(w: &World, k: usize, name: &str) -> PathBuf {
        let path = w.home.root.join(format!("{name}.pub"));
        std::fs::write(
            &path,
            format!("{}\n", w.keys[k].public_line_without_comment()),
        )
        .unwrap();
        path
    }

    /// m02-plan U8 `a11_identityfile_added_after_ensure_is_seen_by_prelaunch_check`: a
    /// `Host *` `IdentityFile` added during the pause makes the selection
    /// `not_exclusive` with an uncleared alternative; the refusal names its line.
    #[test]
    fn a11_identityfile_added_after_ensure_is_seen_by_prelaunch_check() {
        let (w, _) = World::single(true);
        let k2 = write_pub(&w, 1, "k2");
        let out = w.run_paused(&w.run_args("added", true, &[]), &[], || {
            append_user_config(
                &w,
                &format!("Host *\n    IdentityFile \"{}\"\n", k2.display()),
            );
        });
        assert_refused(&w, "added", &out, "fallback_identity_interaction");
        let message = out.envelope()["data"]["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        // The entry is its `IdentityFile` line, 5: the include block's three lines and
        // `Host *` come first.
        assert!(
            message.contains(".ssh/config:5"),
            "names the line: {message}"
        );
        // ADR-0007 §12.24 item 4: and in `data.error.entries`.
        assert_refusal_entries(&out, &[5]);
    }

    /// m02-plan U8 `a11_fallback_cleared_when_alternative_adopted_and_declared_launches`:
    /// the inherited alternative is adopted at the same agent and declared `none`; the
    /// selection is still `not_exclusive`, every alternative is cleared, and the child
    /// launches. Undeclared, the same configuration is refused.
    #[test]
    fn a11_fallback_cleared_when_alternative_adopted_and_declared_launches() {
        let (w, _) = World::single(true);
        let k2 = write_pub(&w, 1, "k2");
        append_user_config(
            &w,
            &format!("Host *\n    IdentityFile \"{}\"\n", k2.display()),
        );
        let other = w.adopt(1);
        let out = w.run_cli(&w.run_args("undeclared", true, &[]), &[]);
        assert_refused(&w, "undeclared", &out, "fallback_identity_interaction");
        w.declare(&other);
        let out = w.run_cli(&w.run_args("cleared", true, &[]), &[]);
        assert_launched(&w, "cleared", &out);
    }

    /// m02-plan U8 `a11_file_backed_fallback_is_never_cleared`: an inherited
    /// `IdentityFile` whose private file exists (0600) is refused even when its `.pub`
    /// is adopted and declared.
    #[test]
    fn a11_file_backed_fallback_is_never_cleared() {
        use std::os::unix::fs::PermissionsExt as _;
        let (w, _) = World::single(true);
        let pub_path = write_pub(&w, 1, "id_other");
        let private = w.home.root.join("id_other");
        // A placeholder: ssh's selection only stats it (Heimdall never opens it).
        std::fs::write(&private, b"placeholder, not a key\n").unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
        append_user_config(
            &w,
            &format!("Host *\n    IdentityFile \"{}\"\n", private.display()),
        );
        let other = w.adopt(1);
        w.declare(&other);
        let out = w.run_cli(&w.run_args("file", true, &[]), &[]);
        assert_refused(&w, "file", &out, "fallback_identity_interaction");
        assert!(pub_path.exists());
    }

    /// A stub `ssh` that records its arguments and prints the 256 byte values.
    fn stub_ssh(w: &World) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = w.home.root.join("stub-bin");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ssh");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\nprintf '%s\\0' \"$@\" > '{}'\ncat '{}'\n",
                w.home.root.join("ssh-args").display(),
                w.home.root.join("bytes").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bytes: Vec<u8> = (0..=255u8).collect();
        std::fs::write(w.home.root.join("bytes"), bytes).unwrap();
        dir
    }

    /// `connect` through the verified client (a stub `ssh` first on `PATH`): a managed
    /// alias launches `ssh <alias>` with stdout exactly the client's bytes (the connect
    /// half of `a27_no_stdout_contamination_in_run_and_connect`); under
    /// `--non-interactive` the alias's identity is checked like `run`'s.
    #[test]
    fn connect_launches_the_verified_client_and_checks_the_alias_identity() {
        let (w, id) = World::single(true);
        let dir = stub_ssh(&w);
        let path = OsString::from(format!("{}:/usr/bin:/bin", dir.display()));
        let meta = w.home.root.join("connect.ndjson");
        let args = |ni: bool| {
            let mut a = os(&["--json"]);
            if ni {
                a.push("--non-interactive".into());
            }
            a.extend(os(&["connect", "alpha", "--meta-file"]));
            a.push(meta.clone().into_os_string());
            a
        };
        let out = w.run_cli(&args(true), &[("PATH", path.as_os_str())]);
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        assert_eq!(
            out.stdout,
            (0..=255u8).collect::<Vec<u8>>(),
            "stdout is the client's"
        );
        assert_eq!(
            std::fs::read(w.home.root.join("ssh-args")).unwrap(),
            b"alpha\0"
        );
        match records(&meta).as_slice() {
            [
                RunRecord::Launching {
                    executable,
                    operation_id: None,
                    binding_id: None,
                    ..
                },
            ] => assert!(executable.ends_with("stub-bin/ssh"), "{executable}"),
            other => panic!("{other:?}"),
        }
        // Withdrawn: refused before launch, nothing printed on stdout.
        w.withdraw(&id, WithdrawReason::Owner);
        std::fs::remove_file(&meta).unwrap();
        std::fs::remove_file(w.home.root.join("ssh-args")).unwrap();
        let out = w.run_cli(&args(true), &[("PATH", path.as_os_str())]);
        assert_eq!(out.code(), Some(3), "{}", out.stderr);
        assert!(out.stdout.is_empty());
        assert!(!w.home.root.join("ssh-args").exists());
        // Interactive use stays first-class: without --non-interactive it launches.
        std::fs::remove_file(&meta).unwrap();
        let out = w.run_cli(&args(false), &[("PATH", path.as_os_str())]);
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        // An alias that is not a destination is refused.
        let out = w.run_cli(
            &os(&["--json", "connect", "gamma"]),
            &[("PATH", path.as_os_str())],
        );
        assert_eq!(out.code(), Some(2));
        assert_eq!(out.envelope()["code"], "NOT_FOUND");
    }

    // -----------------------------------------------------------------------------
    // Through a real ssh client and the loopback fixture sshd
    // -----------------------------------------------------------------------------

    /// The fixture for the cases below: the A11 world (scratch home, in-process
    /// runtime, fake agent holding fixture key 0), the loopback fixture sshd
    /// accepting key 0 only, destination `alpha` managed as `127.0.0.1:<port>` for
    /// the account the non-root sshd authenticates (read at run time, never written
    /// in this file), the projection applied, and key 0 declared `none`.
    ///
    /// The session runs the account's login shell (a recorded fixture limitation,
    /// ADR-0007 §12.15 item 6): these cases need a session to carry bytes. Every
    /// client reads only the scratch configuration and known-hosts files, and the
    /// default-identity guard checks the alias before any client runs.
    struct SshWorld {
        w: World,
        sshd: heimdall_testkit::sshd::LoopbackSshd,
        ssh: PathBuf,
    }

    fn account_name() -> String {
        let out = Command::new("/usr/bin/id")
            .arg("-un")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    impl SshWorld {
        fn new() -> SshWorld {
            SshWorld::build(World::new(2), &[0], true)
        }

        /// The fixture over `w`: the fixture sshd accepting the keys `authorized`
        /// (indices into `w.keys`), key 0 adopted at `w.endpoint()` for `alpha`, the
        /// projection applied, and key 0 declared `none` when `declared`.
        fn build(w: World, authorized: &[usize], declared: bool) -> SshWorld {
            use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
            let sshd = LoopbackSshd::start(
                w.home.scratch(),
                SshdConfig {
                    authorized: authorized
                        .iter()
                        .map(|k| w.keys[*k].public().clone())
                        .collect(),
                    ..SshdConfig::default()
                },
            )
            .unwrap_or_else(|e| panic!("{e}"));
            w.home.trust_host_key(&sshd.host_key_line).unwrap();
            let id = w.adopt(0);
            let account = account_name();
            w.catalog(CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse(ALPHA.id).unwrap(),
                    alias: ALPHA.alias.to_owned(),
                    definition: DestinationDefinitionSpec::Managed {
                        hostname: sshd.host.clone(),
                        port: Some(sshd.port),
                        account: AccountName::parse(&account).unwrap(),
                        identity: id.clone(),
                    },
                    label: None,
                },
                request_id: w.next_id("dest"),
            })
            .unwrap();
            w.profile_as(&[&ALPHA], &account);
            w.project();
            if declared {
                w.declare(&id);
            }
            // The guard: in every invocation the alias's identities are scratch paths
            // and its agent is a fixture endpoint, so no client reaches the owner's
            // keys or agents.
            w.home.check_alias(ALPHA.alias).unwrap();
            let ssh = heimdall_testkit::home::find_program("ssh").expect("an ssh client");
            SshWorld { w, sshd, ssh }
        }

        /// `ssh <isolation arguments> alpha cat`.
        fn ssh_cat(&self) -> Vec<OsString> {
            let mut argv = vec![self.ssh.clone().into_os_string()];
            argv.extend(self.w.home.isolation_args());
            argv.push(ALPHA.alias.into());
            argv.push("cat".into());
            argv
        }

        /// The CLI with `stdin` written from a thread (so a full pipe never deadlocks
        /// against the child's output) and both streams collected.
        fn pipe(&self, args: &[OsString], extra: &[(&str, &OsStr)], stdin: Vec<u8>) -> Out {
            use std::io::Write as _;
            let mut child = self
                .w
                .cli(args, extra)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let writer = std::thread::spawn(move || {
                let _ = input.write_all(&stdin);
            });
            let out = child.wait_with_output().unwrap();
            writer.join().unwrap();
            finish(out)
        }
    }

    /// 1 MiB of fixed-seed pseudo-random bytes followed by all 256 byte values.
    fn binary_payload() -> Vec<u8> {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut v: Vec<u8> = (0..(1 << 20))
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect();
        v.extend(0..=255u8);
        v
    }

    /// m02-plan U8 `a27_binary_stdin_stdout_roundtrip_through_ssh`: 1 MiB of
    /// pseudo-random bytes plus all 256 byte values through `heimdall --non-interactive
    /// run --profile work -- ssh <fixture> alpha cat`, against the loopback fixture sshd,
    /// with the adopted key served by the fake agent. The bytes come back unchanged,
    /// stdout carries nothing else, the run record is a single `launching` with the
    /// operation and binding, the pre-launch check passed (the identity is declared),
    /// the sshd accepted exactly the adopted key, and the agent was contacted (it
    /// signed the login).
    #[test]
    fn a27_binary_stdin_stdout_roundtrip_through_ssh() {
        let s = SshWorld::new();
        let payload = binary_payload();
        let meta = s.w.marker("roundtrip.ndjson");
        let mut args = os(&["--json", "--non-interactive", "run", "--profile", "work"]);
        args.push("--meta-file".into());
        args.push(meta.clone().into_os_string());
        args.push("--".into());
        args.extend(s.ssh_cat());
        let out = s.pipe(&args, &[], payload.clone());
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        assert_eq!(out.stdout.len(), payload.len(), "{}", out.stderr);
        assert!(out.stdout == payload, "the bytes came back changed");
        match records(&meta).as_slice() {
            [
                RunRecord::Launching {
                    operation_id: Some(_),
                    binding_id: Some(_),
                    executable,
                    ..
                },
            ] => assert!(executable.ends_with("ssh"), "{executable}"),
            other => panic!("{other:?}"),
        }
        let accepted = s.sshd.accepted_log();
        assert!(!accepted.is_empty(), "the fixture sshd accepted no key");
        assert!(
            accepted
                .iter()
                .all(|k| k.fingerprint == s.w.keys[0].fingerprint()),
            "{accepted:?}"
        );
        assert!(
            s.w.agent.contact_count() > 0,
            "the login used the fake agent"
        );
        assert_eq!(
            s.w.home.decoy_agent().contact_count(),
            0,
            "the decoy agent was never contacted"
        );
    }

    /// `heimdall connect alpha` against the loopback fixture sshd, through the real
    /// runtime: the verified client on `PATH` is a wrapper that adds only the scratch
    /// isolation arguments (`-F`, the known-hosts files, `BatchMode`) and a remote
    /// `cat`, then execs the real ssh, so the client never reads the account's own
    /// configuration. Under `--non-interactive` the alias's identity is checked, the
    /// login uses the adopted key through the fake agent, and the bytes come back
    /// unchanged with nothing else on stdout; the run record is `launching` with no
    /// operation or binding.
    #[test]
    fn connect_reaches_the_fixture_sshd_through_the_verified_client() {
        use std::os::unix::fs::PermissionsExt as _;
        let s = SshWorld::new();
        let dir = s.w.home.root.join("wrapper-bin");
        std::fs::create_dir_all(&dir).unwrap();
        let quote = |a: &OsStr| format!("'{}'", a.to_str().unwrap().replace('\'', "'\\''"));
        let mut words = vec![quote(s.ssh.as_os_str())];
        words.extend(s.w.home.isolation_args().iter().map(|a| quote(a)));
        let wrapper = dir.join("ssh");
        std::fs::write(
            &wrapper,
            format!("#!/bin/sh\nexec {} \"$@\" cat\n", words.join(" ")),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!("{}:/usr/bin:/bin", dir.display()));
        let meta = s.w.marker("connect.ndjson");
        let mut args = os(&[
            "--json",
            "--non-interactive",
            "connect",
            "alpha",
            "--meta-file",
        ]);
        args.push(meta.clone().into_os_string());
        let payload: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
        let out = s.pipe(&args, &[("PATH", path.as_os_str())], payload.clone());
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        assert!(out.stdout == payload, "{}", out.stderr);
        match records(&meta).as_slice() {
            [
                RunRecord::Launching {
                    operation_id: None,
                    binding_id: None,
                    executable,
                    ..
                },
            ] => assert!(executable.ends_with("wrapper-bin/ssh"), "{executable}"),
            other => panic!("{other:?}"),
        }
        let accepted = s.sshd.accepted_log();
        assert!(
            !accepted.is_empty()
                && accepted
                    .iter()
                    .all(|k| k.fingerprint == s.w.keys[0].fingerprint()),
            "{accepted:?}"
        );
        assert_eq!(s.w.home.decoy_agent().contact_count(), 0);
    }

    // -----------------------------------------------------------------------------
    // Wave 3c (W3c-run): the U8 tests wave 3b did not write, and `connect` with an
    // observed alias (ADR-0007 §12.24)
    // -----------------------------------------------------------------------------

    impl SshWorld {
        /// `<ssh> <isolation arguments> alpha <remote…>`.
        fn ssh_argv(&self, remote: &[&str]) -> Vec<OsString> {
            let mut argv = vec![self.ssh.clone().into_os_string()];
            argv.extend(self.w.home.isolation_args());
            argv.push(ALPHA.alias.into());
            argv.extend(os(remote));
            argv
        }

        /// `heimdall --json [--non-interactive] run --profile work [flags] --meta-file
        /// <name>.ndjson -- <argv>` in `cwd`, with the decoy agent as `SSH_AUTH_SOCK`
        /// (a client that fell back to the session's agent would reach the decoy) and
        /// `extra`.
        fn run_in(
            &self,
            cwd: &Path,
            name: &str,
            flags: &[&str],
            argv: &[OsString],
            extra: &[(&str, &OsStr)],
        ) -> Out {
            let args = self.child_args(name, flags, argv);
            let decoy = self.w.home.decoy_agent().endpoint().locator();
            let mut all: Vec<(&str, &OsStr)> = vec![("SSH_AUTH_SOCK", decoy.as_os_str())];
            all.extend_from_slice(extra);
            finish(self.w.cli(&args, &all).current_dir(cwd).output().unwrap())
        }

        /// The arguments [`run_in`](Self::run_in) passes.
        fn child_args(&self, name: &str, flags: &[&str], argv: &[OsString]) -> Vec<OsString> {
            let mut args = os(&["--json", "--non-interactive", "run", "--profile", "work"]);
            args.extend(os(flags));
            args.push("--meta-file".into());
            args.push(self.w.marker(&format!("{name}.ndjson")).into_os_string());
            args.push("--".into());
            args.extend(argv.iter().cloned());
            args
        }

        fn run_child(&self, name: &str, flags: &[&str], argv: &[OsString]) -> Out {
            self.run_in(&self.w.home.root, name, flags, argv, &[])
        }

        /// The run launched: one `launching` record naming the operation and binding.
        fn assert_launched_record(&self, name: &str, out: &Out) {
            match self.w.records(name).as_slice() {
                [
                    RunRecord::Launching {
                        operation_id: Some(_),
                        binding_id: Some(_),
                        ..
                    },
                ] => {}
                other => panic!("{name}: {other:?}: {}", out.stderr),
            }
        }

        /// Every login the fixture sshd accepted used key `k`, and there was one.
        fn assert_only_key(&self, k: usize) {
            let accepted = self.sshd.accepted_log();
            assert!(
                !accepted.is_empty()
                    && accepted
                        .iter()
                        .all(|a| a.fingerprint == self.w.keys[k].fingerprint()),
                "{accepted:?}"
            );
        }
    }

    /// m02-plan U8 `a27_scp_and_sftp_binary_with_unicode_and_spaced_paths`: through
    /// `heimdall --non-interactive run --profile work -- scp|sftp <isolation> …` against
    /// the loopback fixture sshd (the adopted key at the fake agent, declared `none`), a
    /// binary file (1 MiB pseudo-random plus all 256 byte values) goes up and back down
    /// with `scp`, and up and down again with an `sftp` batch, between local and remote
    /// paths with spaces and non-ASCII characters. Every copy is byte-identical; each run
    /// is one `launching` record; the sshd accepted only the adopted key; the decoy
    /// agent (`SSH_AUTH_SOCK`) was never contacted. The remote paths are absolute paths
    /// in scratch: the non-root sshd runs as this account on this host.
    #[test]
    fn a27_scp_and_sftp_binary_with_unicode_and_spaced_paths() {
        let s = SshWorld::new();
        let root = s.w.home.root.clone();
        let local_dir = root.join("local dir \u{fc}");
        let remote_dir = root.join("remote dir \u{f8} \u{3b1}");
        std::fs::create_dir(&local_dir).unwrap();
        std::fs::create_dir(&remote_dir).unwrap();
        let payload = binary_payload();
        let local = local_dir.join("pay load \u{e9}.bin");
        std::fs::write(&local, &payload).unwrap();
        let isolation = s.w.home.isolation_args();
        let program = |name: &str| {
            heimdall_testkit::home::find_program(name)
                .unwrap_or_else(|| panic!("{name} is not installed"))
                .into_os_string()
        };
        let remote_arg = |p: &Path| OsString::from(format!("{}:{}", ALPHA.alias, p.display()));

        // scp up, then back down to another local name.
        let remote = remote_dir.join("up loaded \u{2713}.bin");
        let mut argv = vec![program("scp")];
        argv.extend(isolation.iter().cloned());
        argv.push(local.clone().into_os_string());
        argv.push(remote_arg(&remote));
        let out = s.run_child("scp-up", &[], &argv);
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        s.assert_launched_record("scp-up", &out);
        assert!(
            std::fs::read(&remote).unwrap() == payload,
            "scp up changed the bytes"
        );
        let back = local_dir.join("back again \u{2713}.bin");
        let mut argv = vec![program("scp")];
        argv.extend(isolation.iter().cloned());
        argv.push(remote_arg(&remote));
        argv.push(back.clone().into_os_string());
        let out = s.run_child("scp-down", &[], &argv);
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        s.assert_launched_record("scp-down", &out);
        assert!(
            std::fs::read(&back).unwrap() == payload,
            "scp down changed the bytes"
        );

        // sftp: put and get through a batch file (quoted paths).
        let remote2 = remote_dir.join("via sftp \u{fc}.bin");
        let local2 = local_dir.join("via sftp back \u{e9}.bin");
        let batch = root.join("sftp batch");
        std::fs::write(
            &batch,
            format!(
                "put \"{}\" \"{}\"\nget \"{}\" \"{}\"\n",
                local.display(),
                remote2.display(),
                remote2.display(),
                local2.display()
            ),
        )
        .unwrap();
        let mut argv = vec![program("sftp")];
        argv.extend(isolation.iter().cloned());
        argv.push("-b".into());
        argv.push(batch.into_os_string());
        argv.push(ALPHA.alias.into());
        let out = s.run_child("sftp", &[], &argv);
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        s.assert_launched_record("sftp", &out);
        assert!(
            std::fs::read(&remote2).unwrap() == payload,
            "sftp put changed the bytes"
        );
        assert!(
            std::fs::read(&local2).unwrap() == payload,
            "sftp get changed the bytes"
        );

        s.assert_only_key(0);
        assert!(
            s.w.agent.contact_count() > 0,
            "the logins used the fake agent"
        );
        assert_eq!(s.w.home.decoy_agent().contact_count(), 0);
    }

    /// m02-plan U8 `a27_git_clone_and_push_over_ssh_with_binary_blob`: Git over SSH
    /// through `heimdall --non-interactive run --profile work -- git …` against the
    /// loopback fixture sshd. A commit holding a binary blob (1 MiB pseudo-random plus
    /// all 256 byte values) is pushed to a bare repository, cloned back (the blob
    /// byte-identical), and a second binary blob is pushed from the clone and read back
    /// from the bare repository. Git runs with a scratch `HOME`, `GIT_CONFIG_NOSYSTEM=1`,
    /// a scratch `GIT_CONFIG_GLOBAL`, and `GIT_SSH_COMMAND` = ssh with only the scratch
    /// isolation arguments (`-F`, the known-hosts files, `BatchMode`); the repository
    /// paths have spaces and non-ASCII characters. Each run is one `launching` record;
    /// the sshd accepted only the adopted key; the decoy agent was never contacted.
    #[test]
    fn a27_git_clone_and_push_over_ssh_with_binary_blob() {
        let s = SshWorld::new();
        let root = s.w.home.root.clone();
        let git_program = heimdall_testkit::home::find_program("git").expect("git");
        let identity: [(&str, &str); 4] = [
            ("GIT_AUTHOR_NAME", "hm fixture"),
            ("GIT_AUTHOR_EMAIL", "fixture@example.invalid"),
            ("GIT_COMMITTER_NAME", "hm fixture"),
            ("GIT_COMMITTER_EMAIL", "fixture@example.invalid"),
        ];
        // Local Git work, directly (no SSH): the world's scratch environment only.
        let git = |dir: &Path, args: &[&OsStr]| -> Vec<u8> {
            let mut cmd = Command::new(&git_program);
            cmd.args(args).env_clear().current_dir(dir);
            for (k, v) in s.w.env() {
                cmd.env(k, v);
            }
            for (k, v) in identity {
                cmd.env(k, v);
            }
            let out = cmd.stdin(Stdio::null()).output().unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            out.stdout
        };
        let bare = root.join("remote repo \u{fc}.git");
        let src = root.join("src \u{f8}");
        git(
            &root,
            &[
                OsStr::new("init"),
                OsStr::new("-q"),
                OsStr::new("--bare"),
                OsStr::new("-b"),
                OsStr::new("main"),
                bare.as_os_str(),
            ],
        );
        git(
            &root,
            &[
                OsStr::new("init"),
                OsStr::new("-q"),
                OsStr::new("-b"),
                OsStr::new("main"),
                src.as_os_str(),
            ],
        );
        let payload = binary_payload();
        std::fs::write(src.join("blob.bin"), &payload).unwrap();
        git(&src, &[OsStr::new("add"), OsStr::new("blob.bin")]);
        git(
            &src,
            &[
                OsStr::new("commit"),
                OsStr::new("-q"),
                OsStr::new("-m"),
                OsStr::new("binary one"),
            ],
        );

        let mut words = vec![s.ssh.clone().into_os_string()];
        words.extend(s.w.home.isolation_args());
        let ssh_command = OsString::from(heimdall_testkit::home::sh_join(&words));
        let mut extra: Vec<(&str, &OsStr)> = vec![
            ("GIT_SSH_COMMAND", ssh_command.as_os_str()),
            ("GIT_SSH_VARIANT", OsStr::new("ssh")),
            ("GIT_TERMINAL_PROMPT", OsStr::new("0")),
        ];
        extra.extend(identity.iter().map(|(k, v)| (*k, OsStr::new(v))));
        let remote = OsString::from(format!("{}:{}", ALPHA.alias, bare.display()));
        let through = |cwd: &Path, name: &str, args: &[&OsStr]| {
            let mut argv = vec![git_program.clone().into_os_string()];
            argv.extend(args.iter().map(|a| a.to_os_string()));
            let out = s.run_in(cwd, name, &[], &argv, &extra);
            assert_eq!(out.code(), Some(0), "{name}: {}", out.stderr);
            s.assert_launched_record(name, &out);
        };

        // Push, then read the blob from the bare repository.
        through(
            &src,
            "push",
            &[
                OsStr::new("push"),
                OsStr::new("-q"),
                remote.as_os_str(),
                OsStr::new("main"),
            ],
        );
        let pushed = git(
            &root,
            &[
                OsStr::new("--git-dir"),
                bare.as_os_str(),
                OsStr::new("cat-file"),
                OsStr::new("blob"),
                OsStr::new("main:blob.bin"),
            ],
        );
        assert!(pushed == payload, "the pushed blob changed");

        // Clone it back.
        let dst = root.join("clone \u{e9}");
        through(
            &root,
            "clone",
            &[
                OsStr::new("clone"),
                OsStr::new("-q"),
                remote.as_os_str(),
                dst.as_os_str(),
            ],
        );
        assert!(
            std::fs::read(dst.join("blob.bin")).unwrap() == payload,
            "the cloned blob changed"
        );

        // A second binary blob pushed from the clone (its `origin` is the alias).
        let second: Vec<u8> = payload.iter().rev().map(|b| b ^ 0x5a).collect();
        std::fs::write(dst.join("second.bin"), &second).unwrap();
        git(&dst, &[OsStr::new("add"), OsStr::new("second.bin")]);
        git(
            &dst,
            &[
                OsStr::new("commit"),
                OsStr::new("-q"),
                OsStr::new("-m"),
                OsStr::new("binary two"),
            ],
        );
        through(
            &dst,
            "push-again",
            &[
                OsStr::new("push"),
                OsStr::new("-q"),
                OsStr::new("origin"),
                OsStr::new("main"),
            ],
        );
        let pushed = git(
            &root,
            &[
                OsStr::new("--git-dir"),
                bare.as_os_str(),
                OsStr::new("cat-file"),
                OsStr::new("blob"),
                OsStr::new("main:second.bin"),
            ],
        );
        assert!(pushed == second, "the second pushed blob changed");

        s.assert_only_key(0);
        assert!(
            s.w.agent.contact_count() > 0,
            "the logins used the fake agent"
        );
        assert_eq!(s.w.home.decoy_agent().contact_count(), 0);
    }

    /// m02-plan U8 `a11_confirm_constrained_native_key_refused_before_agent_contact`
    /// (M2-D05, M2-R08). U7's `DisposableSshAgent` holds key 0 added with confirmation,
    /// behind a `CountingProxy`, with the counting askpass; key 0 is adopted at the
    /// proxy (interaction `unknown`: the constraint is not passively visible, F23) and
    /// not declared. The fixture sshd accepts key 0.
    /// * **Installation verified first:** a signature through the proxy with askpass
    ///   `Approve` prompts exactly once. The proxy and askpass counts are the baseline.
    /// * Non-interactive `run -- ssh … alpha true`: exit 3, `INTERACTION_REQUIRED`,
    ///   reason `interaction_unknown`, a `prelaunch_failed` record, and proxy and
    ///   askpass deltas 0 (no agent contact at all).
    /// * **Discriminating control:** the same `run` with `--allow-provider-interaction`
    ///   launches, and with askpass `Deny` the askpass delta becomes ≥ 1 (nothing signs,
    ///   the login fails): the refusal prevented a real prompt.
    #[test]
    fn a11_confirm_constrained_native_key_refused_before_agent_contact() {
        use heimdall_testkit::agent::AskpassAnswer;
        let mut w = World::new(2);
        w.attach_real();
        w.add_real_key(0, true);
        w.verify_confirm_installed(0);
        let s = SshWorld::build(w, &[0], false);
        let base = s.w.counts();
        let argv = s.ssh_argv(&["true"]);
        let out = s.run_child("refused", &[], &argv);
        assert_refused(&s.w, "refused", &out, "interaction_unknown");
        assert_eq!(s.w.counts(), base, "proxy and askpass deltas are 0");
        assert!(s.sshd.accepted_log().is_empty());

        s.w.real()
            .agent
            .set_askpass_answer(AskpassAnswer::Deny)
            .unwrap();
        let out = s.run_child("prompted", &["--allow-provider-interaction"], &argv);
        s.assert_launched_record("prompted", &out);
        assert_ne!(out.code(), Some(0), "nothing signed: {}", out.stderr);
        let (proxy, askpass) = s.w.counts();
        assert!(proxy > base.0, "the child reached the agent");
        assert!(
            askpass > base.1,
            "the launched child prompted: the refusal prevented a real prompt"
        );
        assert!(s.sshd.accepted_log().is_empty());
        assert_eq!(s.w.home.decoy_agent().contact_count(), 0);
    }

    /// ADR-0007 §12.24 item 4: a fallback refusal's `data.error.entries` name each
    /// refused entry's file (the scratch user configuration, shown as `~/.ssh/config`)
    /// and line, in order.
    fn assert_refusal_entries(out: &Out, lines: &[u32]) {
        let env = out.envelope();
        let entries = env["data"]["error"]["entries"]
            .as_array()
            .unwrap_or_else(|| panic!("no entries: {}", out.stderr));
        let got: Vec<u32> = entries
            .iter()
            .map(|e| {
                let path = e["path_display"].as_str().unwrap();
                assert!(path.ends_with(".ssh/config"), "{path}");
                u32::try_from(e["line"].as_u64().unwrap()).unwrap()
            })
            .collect();
        assert_eq!(got, lines, "{}", out.stderr);
    }

    /// Replace the first occurrence of `from` in the scratch user configuration.
    fn edit_user_config(w: &World, from: &str, to: &str) {
        let text = std::fs::read_to_string(&w.home.user_config).unwrap();
        assert!(text.contains(from), "{text}");
        std::fs::write(&w.home.user_config, text.replacen(from, to, 1)).unwrap();
    }

    /// The 1-based line of the first line of the scratch user configuration equal to
    /// `line` (trimmed).
    fn user_config_line(w: &World, line: &str) -> u32 {
        let text = std::fs::read_to_string(&w.home.user_config).unwrap();
        let index = text
            .lines()
            .position(|l| l.trim() == line)
            .unwrap_or_else(|| panic!("{line:?} not in {text}"));
        u32::try_from(index + 1).unwrap()
    }

    /// m02-plan U8 `a11_inherited_confirm_constrained_fallback_refused_noninteractive_before_agent_contact`
    /// (M2-R05; ADR-0007 §7). The disposable agent behind the counting proxy holds key
    /// 0 ("K1", unconstrained, adopted for `alpha` and declared `none`) and key 1 ("K2",
    /// added with confirmation, installation verified by the signing control). The user
    /// file adds `Host *` / `IdentityFile <scratch>/k2.pub` with no private `k2`, so K2
    /// is agent-backed and the selection is `not_exclusive`. The fixture sshd rejects K1
    /// and accepts K2.
    /// * Non-interactive `run`: exit 3, `INTERACTION_REQUIRED`, reason
    ///   `fallback_identity_interaction`, a `prelaunch_failed` record, proxy and
    ///   askpass deltas 0. With the entry in place before `run`, the runtime already
    ///   refuses the `ensure` under the no-interaction hello (ADR-0007 §7; its error
    ///   names no line). With the entry added after `bind` (during the pre-check pause),
    ///   the CLI's pre-launch check refuses, naming the `Host *` section's entry (its
    ///   `IdentityFile` line) with its file and line in the message and in
    ///   `data.error.entries` (§12.24 item 4); deltas 0 again.
    /// * Control: with `--allow-provider-interaction` the child launches and, askpass
    ///   `Deny`, the askpass delta is ≥ 1: the fallback would have prompted.
    /// * Control: narrowed to `Host * !alpha`, the selection is exclusive; the
    ///   non-interactive `run` launches, the askpass delta is 0, and the login fails
    ///   (K1 rejected, no fallback).
    #[test]
    fn a11_inherited_confirm_constrained_fallback_refused_noninteractive_before_agent_contact() {
        use heimdall_testkit::agent::AskpassAnswer;
        let mut w = World::new(2);
        w.attach_real();
        w.add_real_key(0, false);
        w.add_real_key(1, true);
        w.verify_confirm_installed(1);
        let s = SshWorld::build(w, &[1], true);
        let k2 = write_pub(&s.w, 1, "k2");
        assert!(
            !s.w.home.root.join("k2").exists(),
            "agent-backed: no private file"
        );
        let fallback = format!("Host *\n    IdentityFile \"{}\"\n", k2.display());
        let argv = s.ssh_argv(&["true"]);
        let base = s.w.counts();

        // The entry added after `bind`: the CLI's pre-launch check refuses and names it.
        let decoy = s.w.home.decoy_agent().endpoint().locator();
        let out = s.w.run_paused(
            &s.child_args("late", &[], &argv),
            &[("SSH_AUTH_SOCK", decoy.as_os_str())],
            || append_user_config(&s.w, &fallback),
        );
        assert_refused(&s.w, "late", &out, "fallback_identity_interaction");
        assert_eq!(s.w.counts(), base, "proxy and askpass deltas are 0");
        // The entry's provenance is its `IdentityFile` line in the `Host *` section.
        let entry_line = user_config_line(&s.w, &format!("IdentityFile \"{}\"", k2.display()));
        assert_eq!(entry_line, user_config_line(&s.w, "Host *") + 1);
        let message = out.envelope()["data"]["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains(&format!(".ssh/config:{entry_line}")),
            "names the entry: {message}"
        );
        assert_refusal_entries(&out, &[entry_line]);
        s.w.home.check_alias(ALPHA.alias).unwrap();

        // The entry in place before `run`: refused all the same.
        let out = s.run_child("refused", &[], &argv);
        assert_refused(&s.w, "refused", &out, "fallback_identity_interaction");
        assert_eq!(s.w.counts(), base, "proxy and askpass deltas are 0");

        // Control 1: the fallback would have prompted.
        s.w.real()
            .agent
            .set_askpass_answer(AskpassAnswer::Deny)
            .unwrap();
        let out = s.run_child("prompted", &["--allow-provider-interaction"], &argv);
        s.assert_launched_record("prompted", &out);
        assert_ne!(out.code(), Some(0), "nothing signed: {}", out.stderr);
        let (_, askpass) = s.w.counts();
        assert!(askpass > base.1, "the fallback prompted");
        assert!(s.sshd.accepted_log().is_empty());

        // Control 2: narrowed, exclusive, launched; no prompt and no fallback.
        edit_user_config(&s.w, "Host *\n", &format!("Host * !{}\n", ALPHA.alias));
        s.w.home.check_alias(ALPHA.alias).unwrap();
        let before = s.w.counts();
        let out = s.run_child("narrowed", &[], &argv);
        s.assert_launched_record("narrowed", &out);
        assert_eq!(
            out.code(),
            Some(255),
            "K1 rejected, no fallback: {}",
            out.stderr
        );
        assert_eq!(s.w.counts().1, before.1, "no prompt");
        assert!(s.w.counts().0 > before.0, "the child used the agent");
        assert!(s.sshd.accepted_log().is_empty());
        assert_eq!(s.w.home.decoy_agent().contact_count(), 0);
    }

    /// m02-plan U8 `a11_interactive_connect_succeeds_after_provider_approval`: on a pty,
    /// interactive `heimdall connect alpha` (no `--non-interactive`) against the
    /// loopback fixture sshd, the adopted key (not declared: interaction `unknown`)
    /// served by a `FakeAgent` in `ApprovalPending` mode, as a provider's approval
    /// dialog. The verified client on `PATH` is a wrapper that adds only the scratch
    /// isolation arguments (no `BatchMode`: an interactive session) and a remote `echo`.
    /// The login waits at the agent's signature until `release_pending()`, then
    /// succeeds: ordinary interactive use stays first-class.
    #[test]
    fn a11_interactive_connect_succeeds_after_provider_approval() {
        use heimdall_testkit::agent::msg;
        use std::os::unix::fs::PermissionsExt as _;
        let s = SshWorld::build(World::with_mode(2, AgentMode::ApprovalPending), &[0], false);
        let marker = "hm-u8-connected-after-approval";
        let dir = s.w.home.root.join("wrapper-bin");
        std::fs::create_dir_all(&dir).unwrap();
        let mut words = vec![s.ssh.clone().into_os_string()];
        words.extend(s.w.home.interactive_isolation_args());
        let wrapper = dir.join("ssh");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec {} \"$@\" echo {marker}\n",
                heimdall_testkit::home::sh_join(&words)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut env: Vec<(OsString, OsString)> =
            s.w.env().into_iter().filter(|(k, _)| k != "PATH").collect();
        env.push((
            "PATH".into(),
            format!("{}:/usr/bin:/bin", dir.display()).into(),
        ));
        env.push((
            "SSH_AUTH_SOCK".into(),
            s.w.home.decoy_agent().endpoint().locator(),
        ));
        let pty = super::terminal::Pty::open();
        let running = pty.start_env(&env, &s.w.home.root, &os(&["connect", ALPHA.alias]));
        // The client asks the agent for the login signature; the provider holds it.
        assert!(
            s.w.agent.wait_until(Duration::from_secs(30), |a| {
                a.log().iter().any(|c| c.msg_type == msg::SIGN_REQUEST)
            }),
            "no signing request: {}",
            pty.transcript()
        );
        std::thread::sleep(Duration::from_millis(300));
        assert!(s.sshd.accepted_log().is_empty(), "held before approval");
        assert!(!pty.transcript().contains(marker));
        s.w.agent.release_pending();
        let status = running.wait(Duration::from_secs(60));
        assert_eq!(status.code(), Some(0), "{}", pty.transcript());
        wait_for("the session's output", Duration::from_secs(10), || {
            pty.transcript().contains(marker)
        });
        s.assert_only_key(0);
        assert_eq!(s.w.home.decoy_agent().contact_count(), 0);
        assert_no_canary(&pty.transcript());
    }

    /// ADR-0007 §12.24 item 1 (`connect`'s side): the catalog lists an observed
    /// destination `gamma` that the user's own configuration defines, and `connect
    /// gamma` accepts it under the same pre-launch check as a managed alias. Through the
    /// stub client (it records its arguments):
    /// * interactive: launched (`ssh gamma`);
    /// * non-interactive, `gamma` naming the adopted key 0 (declared `none`) at its
    ///   agent under `IdentitiesOnly yes`: launched (every entry cleared);
    /// * non-interactive without `IdentitiesOnly`: refused before launch,
    ///   `fallback_identity_interaction`;
    /// * non-interactive naming a key that is not adopted: refused, `interaction_unknown`;
    /// * an alias the catalog does not list: `NOT_FOUND`.
    #[test]
    fn connect_accepts_an_observed_alias_the_catalog_lists_under_the_same_check() {
        let (w, _) = World::single(true);
        w.catalog(CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: DestinationId::parse("dst-gamma").unwrap(),
                alias: "gamma".to_owned(),
                definition: DestinationDefinitionSpec::Observed,
                label: None,
            },
            request_id: w.next_id("dest"),
        })
        .unwrap();
        let k0 = write_pub(&w, 0, "k0");
        let k1 = write_pub(&w, 1, "k1");
        let agent = w.endpoint().locator;
        let gamma = |identity: &Path, only: bool| {
            format!(
                "Host gamma\n    HostName gamma.example.invalid\n    IdentityFile \"{}\"\n    IdentityAgent \"{agent}\"\n{}",
                identity.display(),
                if only { "    IdentitiesOnly yes\n" } else { "" }
            )
        };
        let base = std::fs::read_to_string(&w.home.user_config).unwrap();
        let set = |text: String| {
            std::fs::write(&w.home.user_config, format!("{base}{text}")).unwrap();
        };
        let dir = stub_ssh(&w);
        let path = OsString::from(format!("{}:/usr/bin:/bin", dir.display()));
        let args_file = w.home.root.join("ssh-args");
        let connect = |name: &str, ni: bool, alias: &str| {
            let _ = std::fs::remove_file(&args_file);
            let mut a = os(&["--json"]);
            if ni {
                a.push("--non-interactive".into());
            }
            a.extend(os(&["connect", alias, "--meta-file"]));
            a.push(w.marker(&format!("{name}.ndjson")).into_os_string());
            w.run_cli(&a, &[("PATH", path.as_os_str())])
        };
        set(gamma(&k0, true));
        let out = connect("interactive", false, "gamma");
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        assert_eq!(std::fs::read(&args_file).unwrap(), b"gamma\0");
        let out = connect("cleared", true, "gamma");
        assert_eq!(out.code(), Some(0), "{}", out.stderr);
        assert_eq!(std::fs::read(&args_file).unwrap(), b"gamma\0");
        assert!(matches!(
            w.records("cleared").as_slice(),
            [RunRecord::Launching {
                operation_id: None,
                binding_id: None,
                ..
            }]
        ));

        set(gamma(&k0, false));
        let out = connect("open", true, "gamma");
        assert_refused(&w, "open", &out, "fallback_identity_interaction");
        assert!(!args_file.exists(), "never launched");

        set(gamma(&k1, true));
        let out = connect("other-key", true, "gamma");
        assert_refused(&w, "other-key", &out, "interaction_unknown");
        assert!(!args_file.exists(), "never launched");

        let out = connect("unlisted", false, "delta");
        assert_eq!(out.code(), Some(2), "{}", out.stderr);
        assert_eq!(out.envelope()["code"], "NOT_FOUND");
        assert!(!args_file.exists());
    }
}
