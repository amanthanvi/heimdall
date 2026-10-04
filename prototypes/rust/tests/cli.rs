//! Black-box tests of the built binary (Unix). Fake agent endpoints live in
//! per-test temp directories; nothing touches ~/.ssh or a real agent.
#![cfg(unix)]

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Binary under test: `HEIMDALL_PROTO_BIN` (e.g. a dist/ release artifact) or the
/// cargo-built binary.
fn bin() -> String {
    std::env::var("HEIMDALL_PROTO_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_heimdall-proto").to_string())
}

/// Fixture directory: `$HEIMDALL_G02_FIXTURES` (relocated test runs, e.g. a copy of
/// this crate outside the repository or a container), else the repository layout.
fn fixtures() -> PathBuf {
    let p = std::env::var_os("HEIMDALL_G02_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/g02/profiles")
        });
    assert!(
        p.join("homelab.toml").is_file(),
        "G02 fixtures not found at {}; set HEIMDALL_G02_FIXTURES",
        p.display()
    );
    p
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        // Short base so Unix socket paths stay under the 104-byte sun_path limit on macOS.
        let base = std::env::temp_dir();
        let p = base.join(format!("hp-{tag}-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        % 1_000_000_007
}

fn cmd() -> Command {
    let mut c = Command::new(bin());
    c.env_remove("SSH_AUTH_SOCK");
    c
}

fn run(args: &[&str]) -> Output {
    cmd().args(args).stdin(Stdio::null()).output().unwrap()
}

/// Exactly one JSON document followed by "\n" on stdout.
fn one_json(o: &Output) -> Value {
    let s = std::str::from_utf8(&o.stdout).expect("stdout utf-8");
    assert!(s.ends_with('\n'), "stdout must end with newline: {s:?}");
    assert_eq!(s.matches('\n').count(), 1, "exactly one line: {s:?}");
    assert!(!s.contains('\u{1b}'), "no escapes");
    let v: Value = serde_json::from_str(s).unwrap();
    for k in [
        "schema_version",
        "state",
        "code",
        "data",
        "warnings",
        "next",
    ] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert_eq!(v["schema_version"], "1");
    v
}

fn no_canary(o: &Output) {
    for stream in [&o.stdout, &o.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains("HEIMDALL_CANARY_"),
            "canary leaked"
        );
    }
}

// ---------- profile show ----------

#[test]
fn profile_fixtures() {
    let cases: &[(&str, i32, &str)] = &[
        ("homelab.toml", 0, "PROFILE_OK"),
        ("large-100.toml", 0, "PROFILE_OK"),
        ("spaced dir ü/prøfile homelab.toml", 0, "PROFILE_OK"),
        ("invalid-forbidden-key.toml", 2, "SCHEMA_INVALID"),
        ("invalid-unknown-dest-key.toml", 2, "SCHEMA_INVALID"),
        ("invalid-malformed.toml", 2, "SCHEMA_INVALID"),
        ("invalid-schema-version.toml", 2, "SCHEMA_INVALID"),
        ("invalid-duplicate-alias.toml", 2, "SCHEMA_INVALID"),
        ("invalid-port.toml", 2, "SCHEMA_INVALID"),
        ("does-not-exist.toml", 2, "USAGE_ERROR"),
    ];
    for (name, exit, code) in cases {
        let path = fixtures().join(name);
        let o = cmd()
            .args(["profile", "show", "--file"])
            .arg(&path)
            .arg("--json")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(*exit), "{name}");
        let v = one_json(&o);
        assert_eq!(v["code"], *code, "{name}");
        no_canary(&o);
        if *exit != 0 {
            assert_eq!(v["state"], "failed");
            assert!(v["data"]["error"]["message"].is_string());
            assert!(v["data"]["error"].get("key_path").is_some());
        }
    }
    let o = run(&[
        "profile",
        "show",
        "--file",
        fixtures().join("homelab.toml").to_str().unwrap(),
        "--json",
    ]);
    let v = one_json(&o);
    assert_eq!(
        v["data"]["profile"]["destinations"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(v["data"]["profile"]["destinations"][1]["port"], 22);
    assert!(o.stderr.is_empty(), "no stderr on success");
    let o = run(&[
        "profile",
        "show",
        "--file",
        fixtures()
            .join("invalid-schema-version.toml")
            .to_str()
            .unwrap(),
        "--json",
    ]);
    let v = one_json(&o);
    assert!(v["warnings"][0].as_str().unwrap().contains('2'));
}

#[test]
fn profile_oversize() {
    let d = TempDir::new("big");
    let p = d.path().join("oversize ü.toml");
    let mut body = b"schema_version = 1\nname = \"x\"\nrevision = 1\n".to_vec();
    body.resize(1_048_577, b'#');
    std::fs::write(&p, body).unwrap();
    let o = cmd()
        .args(["profile", "show", "--file"])
        .arg(&p)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(one_json(&o)["code"], "INPUT_TOO_LARGE");
}

// ---------- usage / version ----------

#[test]
fn usage_errors_json_only_with_flag() {
    let o = run(&["bogus"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert!(!o.stderr.is_empty());
    let o = run(&["bogus", "--json"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(one_json(&o)["code"], "USAGE_ERROR");
    let o = run(&["profile", "show", "--json"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(one_json(&o)["code"], "USAGE_ERROR");
    let o = run(&["run", "echo"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    let o = run(&["run", "--"]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["tui", "--file", "x"]);
    assert_eq!(o.status.code(), Some(2), "no TTY → usage error");
    assert!(o.stdout.is_empty());
}

#[test]
fn version_json() {
    let o = run(&["version", "--json"]);
    assert_eq!(o.status.code(), Some(0));
    let v = one_json(&o);
    assert_eq!(v["code"], "VERSION_OK");
    assert_eq!(v["data"]["name"], "heimdall-proto");
    assert_eq!(v["data"]["version"], "0.0.0-g02");
    assert_eq!(v["data"]["candidate"], "rust");
    assert_eq!(v["data"]["tui_framework"], "ratatui");
    assert!(v["data"]["runtime"].as_str().unwrap().starts_with("rustc "));
    assert!(
        v["data"]["tui_framework_version"]
            .as_str()
            .unwrap()
            .starts_with("0.30.")
    );
}

// ---------- agent list ----------

fn frame(body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(body);
    v
}
fn sstr(b: &[u8]) -> Vec<u8> {
    frame(b)
}
fn one_key_answer(comment: &[u8]) -> Vec<u8> {
    let mut blob = sstr(b"ssh-ed25519");
    blob.extend_from_slice(&sstr(&[1u8; 32]));
    let mut body = vec![12u8, 0, 0, 0, 1];
    body.extend_from_slice(&sstr(&blob));
    body.extend_from_slice(&sstr(comment));
    body
}

/// Fake agent: accepts one connection, records the request, sends `reply`, then
/// optionally holds the connection open.
fn fake_agent(
    dir: &Path,
    reply: Vec<u8>,
    hold: Duration,
) -> (PathBuf, std::thread::JoinHandle<Vec<u8>>) {
    let sock = dir.join("agent ü.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut req = [0u8; 5];
        let _ = s.read_exact(&mut req);
        let _ = s.write_all(&reply);
        std::thread::sleep(hold);
        // Anything else the client sent before closing?
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut extra = Vec::new();
        let _ = s.read_to_end(&mut extra);
        let mut all = req.to_vec();
        all.extend_from_slice(&extra);
        all
    });
    (sock, h)
}

fn agent_list(sock: &Path, extra: &[&str]) -> Output {
    cmd()
        .args(["agent", "list", "--socket"])
        .arg(sock)
        .args(extra)
        .arg("--json")
        .output()
        .unwrap()
}

#[test]
fn agent_ok_and_request_bytes() {
    let d = TempDir::new("ag");
    let (sock, h) = fake_agent(
        d.path(),
        frame(&one_key_answer(b"fixture \xff key")),
        Duration::ZERO,
    );
    let o = agent_list(&sock, &[]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v = one_json(&o);
    assert_eq!(v["code"], "AGENT_OK");
    let id = &v["data"]["identities"][0];
    assert_eq!(id["key_type"], "ssh-ed25519");
    assert_eq!(id["comment"], "fixture \u{FFFD} key");
    assert!(id["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert_eq!(
        h.join().unwrap(),
        vec![0, 0, 0, 1, 11],
        "only one type-11 request is ever sent"
    );
}

#[test]
fn agent_crafted_frames() {
    let mut trailing = one_key_answer(b"c");
    trailing.push(0);
    let mut huge_nkeys = vec![12u8];
    huge_nkeys.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut str_overrun = vec![12u8, 0, 0, 0, 1];
    str_overrun.extend_from_slice(&0x7fff_ffffu32.to_be_bytes());
    let mut truncated = frame(&one_key_answer(b"comment"));
    truncated.truncate(truncated.len() - 3);
    let cases: Vec<(&str, Vec<u8>, i32, &str)> = vec![
        (
            "oversize length",
            (262_145u32).to_be_bytes().to_vec(),
            5,
            "AGENT_PROTOCOL_ERROR",
        ),
        ("huge nkeys", frame(&huge_nkeys), 5, "AGENT_PROTOCOL_ERROR"),
        (
            "string overrun",
            frame(&str_overrun),
            5,
            "AGENT_PROTOCOL_ERROR",
        ),
        ("trailing", frame(&trailing), 5, "AGENT_PROTOCOL_ERROR"),
        ("truncated", truncated, 5, "AGENT_PROTOCOL_ERROR"),
        ("wrong type", frame(&[6]), 5, "AGENT_PROTOCOL_ERROR"),
        ("failure", frame(&[5]), 5, "AGENT_REFUSED"),
    ];
    for (name, reply, exit, code) in cases {
        let d = TempDir::new("cr");
        let (sock, h) = fake_agent(d.path(), reply, Duration::ZERO);
        let o = agent_list(&sock, &["--timeout-ms", "3000"]);
        assert_eq!(o.status.code(), Some(exit), "{name}");
        let v = one_json(&o);
        assert_eq!(v["code"], code, "{name}");
        assert_eq!(v["state"], "failed");
        let _ = h.join();
    }
}

#[test]
fn agent_unavailable_and_timeout() {
    let d = TempDir::new("un");
    let o = agent_list(&d.path().join("nope.sock"), &[]);
    assert_eq!(o.status.code(), Some(5));
    assert_eq!(one_json(&o)["code"], "AGENT_UNAVAILABLE");

    // Accepts, never answers.
    let (sock, h) = fake_agent(d.path(), vec![], Duration::from_millis(1500));
    let t = Instant::now();
    let o = agent_list(&sock, &["--timeout-ms", "300"]);
    let el = t.elapsed();
    assert_eq!(o.status.code(), Some(5));
    assert_eq!(one_json(&o)["code"], "AGENT_UNAVAILABLE");
    assert!(
        el >= Duration::from_millis(300) && el < Duration::from_millis(1400),
        "{el:?}"
    );
    let _ = h.join();
}

#[test]
fn agent_cancel_sigint_within_500ms() {
    let d = TempDir::new("cx");
    let (sock, h) = fake_agent(d.path(), vec![], Duration::from_millis(3000));
    let mut child = cmd()
        .args(["agent", "list", "--socket"])
        .arg(&sock)
        .args(["--timeout-ms", "10000", "--json"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let t = Instant::now();
    assert!(shell_kill("-INT", &child.id().to_string()));
    let st = child.wait().unwrap();
    let el = t.elapsed();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(st.code(), Some(130));
    assert!(el < Duration::from_millis(500), "cancel took {el:?}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["state"], "cancelled");
    assert_eq!(v["code"], "CANCELLED");
    // The connection was closed: the fake agent's read_to_end finished (no hang).
    let _ = h.join();
}

// ---------- run ----------

#[test]
fn run_argv_bytes_passthrough() {
    let weird: Vec<OsString> = vec![
        "a b".into(),
        "q\"uo'te".into(),
        "$HOME".into(),
        "a;b".into(),
        "*".into(),
        "line1\nline2".into(),
        "ünï東京".into(),
        "--json".into(),
        "--".into(),
        "".into(),
        OsString::from_vec(vec![0x80, 0xff, b'x']),
    ];
    let o = cmd()
        .args(["run", "--", "printf", "%s\\0"])
        .args(&weird)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    let mut expect = Vec::new();
    for w in &weird {
        expect.extend_from_slice(w.as_encoded_bytes());
        expect.push(0);
    }
    assert_eq!(o.stdout, expect);
}

#[test]
fn run_binary_stdio_passthrough() {
    let data: Vec<u8> = (0u8..=255).chain([0, 0xff, 0xfe, b'\n', 0]).collect();
    let mut child = cmd()
        .args(["run", "--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&data).unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(o.stdout, data);
}

#[test]
fn run_status_and_meta() {
    let d = TempDir::new("rm");
    let meta = d.path().join("meta dir ü.json");
    let o = cmd()
        .args(["run", "--meta-file"])
        .arg(&meta)
        .args(["--", "sh", "-c", "exit 42"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(42));
    assert!(o.stdout.is_empty());
    let v: Value = serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
    assert_eq!(v["code"], "CHILD_EXITED");
    assert_eq!(v["data"]["launched"], true);
    assert_eq!(v["data"]["exit_code"], 42);
    assert_eq!(v["data"]["signal"], Value::Null);

    let o = cmd()
        .args(["run", "--meta-file"])
        .arg(&meta)
        .args(["--", "sh", "-c", "kill -KILL $$"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(137));
    let v: Value = serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
    assert_eq!(v["data"]["signal"], 9);
    assert_eq!(v["data"]["exit_code"], Value::Null);

    let o = cmd()
        .args(["run", "--meta-file"])
        .arg(&meta)
        .args(["--", "no-such-cmd-ü-heimdall"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(127));
    assert!(o.stdout.is_empty());
    assert!(!o.stderr.is_empty());
    let v: Value = serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
    assert_eq!(v["code"], "CHILD_LAUNCH_FAILED");
    assert_eq!(v["data"]["launched"], false);

    // Not executable.
    let f = d.path().join("not exec");
    std::fs::write(&f, "#!/bin/sh\n").unwrap();
    let o = cmd().arg("run").arg("--").arg(&f).output().unwrap();
    assert_eq!(o.status.code(), Some(127));
}

#[test]
fn run_inherits_env_and_cwd() {
    let d = TempDir::new("env");
    let o = cmd()
        .current_dir(d.path())
        .env("HP_TEST_VAR", "v a l ü")
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$HP_TEST_VAR\" \"$(pwd -P)\"",
        ])
        .output()
        .unwrap();
    let s = String::from_utf8(o.stdout).unwrap();
    let cwd = d.path().canonicalize().unwrap();
    assert_eq!(s, format!("v a l ü|{}", cwd.display()));
}

/// Start `run -- sh -c <script>` and wait until the child prints "ready".
fn start_ready(
    script: &str,
    meta: Option<&Path>,
) -> (std::process::Child, BufReader<std::process::ChildStdout>) {
    let mut c = cmd();
    c.arg("run");
    if let Some(m) = meta {
        c.arg("--meta-file").arg(m);
    }
    let mut child = c
        .args(["--", "sh", "-c", script])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut r = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    (child, r)
}

fn pid_alive(pid: i32) -> bool {
    shell_kill("-0", &pid.to_string())
}

/// `kill` via the shell builtin (minimal images lack /bin/kill).
fn shell_kill(sig: &str, pid: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("kill {sig} {pid} 2>/dev/null")])
        .status()
        .unwrap()
        .success()
}

#[test]
fn run_forwards_signals_and_waits() {
    for (sig, code) in [("TERM", 7), ("INT", 8), ("HUP", 9), ("QUIT", 10)] {
        let script = format!("trap 'exit {code}' {sig}; echo ready; while :; do sleep 0.02; done");
        let (mut child, _r) = start_ready(&script, None);
        assert!(shell_kill(&format!("-{sig}"), &child.id().to_string()));
        let st = child.wait().unwrap();
        assert_eq!(
            st.code(),
            Some(code),
            "SIG{sig} forwarded; parent exits with child's status"
        );
    }
    // WINCH: default action is ignore, so trap it to observe forwarding.
    let (mut child, mut r) = start_ready(
        "trap 'echo winch' WINCH; echo ready; i=0; while [ $i -lt 100 ]; do sleep 0.02; i=$((i+1)); done",
        None,
    );
    assert!(shell_kill("-WINCH", &child.id().to_string()));
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "winch");
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn run_untrapped_term_maps_to_143_and_no_zombie() {
    let d = TempDir::new("zz");
    let meta = d.path().join("m.json");
    let (mut child, mut r) = start_ready("echo ready; echo $$; exec sleep 30", Some(&meta));
    let mut pid = String::new();
    r.read_line(&mut pid).unwrap();
    let grandchild: i32 = pid.trim().parse().unwrap();
    assert!(pid_alive(grandchild));
    assert!(shell_kill("-TERM", &child.id().to_string()));
    let st = child.wait().unwrap();
    assert_eq!(st.code(), Some(143));
    let v: Value = serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
    assert_eq!(v["data"]["signal"], 15);
    assert!(
        !pid_alive(grandchild),
        "child reaped, not orphaned or zombie"
    );
}

// ---------- contract §9 clarifications ----------

/// K1 end to end: the decoded JSON strings contain no C0/DEL/C1 code point (JSON
/// escaping them would not satisfy the ruling).
#[test]
fn k1_agent_strings_have_no_control_code_points() {
    let d = TempDir::new("k1");
    let mut blob = sstr("ssh-\ted\u{85}25519\u{7f}".as_bytes());
    blob.extend_from_slice(&sstr(&[1u8; 32]));
    let mut body = vec![12u8, 0, 0, 0, 1];
    body.extend_from_slice(&sstr(&blob));
    body.extend_from_slice(&sstr(b"c\x00o\x1b[31m\tm\xc2\x9bent\xff"));
    let (sock, h) = fake_agent(d.path(), frame(&body), Duration::ZERO);
    let o = agent_list(&sock, &[]);
    assert_eq!(o.status.code(), Some(0));
    let v = one_json(&o);
    let id = &v["data"]["identities"][0];
    for f in ["key_type", "comment"] {
        let s = id[f].as_str().unwrap();
        assert!(!s.chars().any(|c| c.is_control()), "{f}: {s:?}");
        assert!(s.contains('\u{FFFD}'), "{f}: {s:?}");
    }
    assert_eq!(
        id["comment"],
        "c\u{FFFD}o\u{FFFD}[31m\u{FFFD}m\u{FFFD}ent\u{FFFD}"
    );
    let _ = h.join();
}

/// K3: peer closes before any response byte -> AGENT_UNAVAILABLE; EOF after at
/// least one byte but before a complete frame -> AGENT_PROTOCOL_ERROR.
/// K4: a type-5 frame with any payload -> AGENT_PROTOCOL_ERROR.
#[test]
fn k3_k4_eof_and_failure_frame_shape() {
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("zero-byte EOF", vec![], "AGENT_UNAVAILABLE"),
        ("1 byte then EOF", vec![0], "AGENT_PROTOCOL_ERROR"),
        (
            "length only then EOF",
            vec![0, 0, 0, 5],
            "AGENT_PROTOCOL_ERROR",
        ),
        (
            "partial body then EOF",
            vec![0, 0, 0, 5, 12, 0],
            "AGENT_PROTOCOL_ERROR",
        ),
        ("failure len 1", frame(&[5]), "AGENT_REFUSED"),
        ("failure + 1 byte", frame(&[5, 0]), "AGENT_PROTOCOL_ERROR"),
        (
            "failure + 4 bytes",
            frame(&[5, 0, 0, 0, 0]),
            "AGENT_PROTOCOL_ERROR",
        ),
    ];
    for (name, reply, code) in cases {
        let d = TempDir::new("k3");
        // hold = 0: the fake agent writes `reply`, then closes the connection.
        let (sock, h) = fake_agent(d.path(), reply, Duration::ZERO);
        let t = Instant::now();
        let o = agent_list(&sock, &["--timeout-ms", "4000"]);
        assert_eq!(o.status.code(), Some(5), "{name}");
        let v = one_json(&o);
        assert_eq!(v["code"], code, "{name}");
        assert_eq!(v["state"], "failed", "{name}");
        assert!(
            t.elapsed() < Duration::from_millis(3000),
            "{name}: decided by EOF, not by the timeout ({:?})",
            t.elapsed()
        );
        let _ = h.join();
    }
}

/// K5: CHILD_EXITED is state "succeeded" whatever the child's status;
/// CHILD_LAUNCH_FAILED is state "failed".
#[test]
fn k5_meta_state() {
    let d = TempDir::new("k5");
    let meta = d.path().join("m ü.json");
    for (argv, exit, code, state) in [
        (vec!["sh", "-c", "exit 0"], 0, "CHILD_EXITED", "succeeded"),
        (vec!["sh", "-c", "exit 42"], 42, "CHILD_EXITED", "succeeded"),
        (
            vec!["sh", "-c", "kill -KILL $$"],
            137,
            "CHILD_EXITED",
            "succeeded",
        ),
        (
            vec!["no-such-cmd-k5-ü"],
            127,
            "CHILD_LAUNCH_FAILED",
            "failed",
        ),
    ] {
        let o = cmd()
            .args(["run", "--meta-file"])
            .arg(&meta)
            .arg("--")
            .args(&argv)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(exit), "{argv:?}");
        let v: Value = serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
        assert_eq!(v["code"], code, "{argv:?}");
        assert_eq!(v["state"], state, "{argv:?}");
        assert_eq!(v["schema_version"], "1");
    }
}

/// K6: an explicit `kill -INT|-TERM <heimdall-proto pid>` reaches the child exactly
/// once. This test covers whatever terminal relationship the test process has
/// (no controlling terminal under the selftest and in containers); the pty driver
/// (tests/pty_tui.py) covers the foreground-job and background-job states.
#[test]
fn k6_explicit_signal_to_pid_reaches_child_exactly_once() {
    for sig in ["INT", "TERM"] {
        let script = format!(
            "n=0; trap 'n=$((n+1))' {sig}; echo ready; i=0; \
             while [ $i -lt 40 ]; do sleep 0.025; i=$((i+1)); done; echo count=$n; exit 3"
        );
        let (mut child, mut r) = start_ready(&script, None);
        assert!(shell_kill(&format!("-{sig}"), &child.id().to_string()));
        let st = child.wait().unwrap();
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(st.code(), Some(3), "SIG{sig}: parent waited for child");
        assert_eq!(rest.trim(), "count=1", "SIG{sig} delivered exactly once");
    }
}

// ---------- round 2 (contract §9.1 and the round-1 review) ----------

/// Fake agent that never reads the request, sends `reply`, then closes. On Linux the
/// unread request makes the close a connection reset (ECONNRESET at the client after
/// the sent bytes); Darwin reports EOF instead (K13).
fn resetting_agent(dir: &Path, reply: Vec<u8>) -> (PathBuf, std::thread::JoinHandle<()>) {
    let sock = dir.join("reset.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        // Let the client's 5-byte request land in our receive queue, unread.
        std::thread::sleep(Duration::from_millis(200));
        let _ = s.write_all(&reply);
        drop(s);
    });
    (sock, h)
}

/// Shows that `resetting_agent` really produces a reset where the platform has one:
/// a plain client receives the bytes, then ECONNRESET on Linux (EOF on Darwin).
fn observe_plain_client(reply: Vec<u8>) -> (usize, String) {
    let d = TempDir::new("k3ao");
    let (sock, h) = resetting_agent(d.path(), reply);
    let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    c.write_all(&[0, 0, 0, 1, 11]).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    let mut got = 0;
    let mut buf = [0u8; 64];
    let end = loop {
        match c.read(&mut buf) {
            Ok(0) => break "eof".to_string(),
            Ok(n) => got += n,
            Err(e) => break format!("{:?}", e.kind()),
        }
    };
    h.join().unwrap();
    (got, end)
}

/// K3a: a connection reset before any response byte is AGENT_UNAVAILABLE; after at
/// least one byte but before a complete frame it is AGENT_PROTOCOL_ERROR.
#[test]
fn k3a_reset_before_and_after_partial_frame() {
    let (got, end) = observe_plain_client(vec![0, 0, 0]);
    eprintln!("plain client: {got} bytes, then {end}");
    if cfg!(target_os = "linux") {
        assert_eq!(
            (got, end.as_str()),
            (3, "ConnectionReset"),
            "probe must produce a real reset on Linux"
        );
    }
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("reset before any byte", vec![], "AGENT_UNAVAILABLE"),
        ("reset after 1 byte", vec![0], "AGENT_PROTOCOL_ERROR"),
        ("reset after 3 bytes", vec![0, 0, 0], "AGENT_PROTOCOL_ERROR"),
        (
            "reset after header + partial body",
            vec![0, 0, 0, 9, 12, 0, 0],
            "AGENT_PROTOCOL_ERROR",
        ),
    ];
    for (name, reply, code) in cases {
        let d = TempDir::new("k3a");
        let (sock, h) = resetting_agent(d.path(), reply);
        let o = agent_list(&sock, &["--timeout-ms", "4000"]);
        h.join().unwrap();
        assert_eq!(o.status.code(), Some(5), "{name}");
        let v = one_json(&o);
        assert_eq!(v["code"], code, "{name}");
    }
}

/// Run `script` with `$0` = the binary under test, through /bin/sh.
fn sh_with_bin(script: &str) -> Command {
    let mut c = Command::new("sh");
    c.args(["-c", script, &bin()]).env_remove("SSH_AUTH_SOCK");
    c
}

/// K6a: dispositions inherited as SIG_IGN stay ignored in the child (exec
/// semantics). The child signals itself; it survives only if each is ignored.
#[test]
fn k6a_inherited_ignored_dispositions_reach_child() {
    let o = sh_with_bin(
        "trap '' HUP INT QUIT TERM; exec \"$0\" run -- sh -c \
         'kill -HUP $$; kill -INT $$; kill -QUIT $$; kill -TERM $$; echo survived'",
    )
    .output()
    .unwrap();
    assert_eq!(
        (o.status.code(), String::from_utf8_lossy(&o.stdout).trim()),
        (Some(0), "survived"),
        "child must inherit SIG_IGN for HUP/INT/QUIT/TERM"
    );
    // Not inherited as ignored -> default in the child (sanity: the probe works).
    let o = sh_with_bin("exec \"$0\" run -- sh -c 'kill -TERM $$; echo survived'")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(143));
}

/// K6a: an inherited-ignored signal sent to heimdall-proto is not forwarded; signals
/// that were not ignored still are (exactly once).
#[test]
fn k6a_inherited_ignored_signals_are_not_forwarded() {
    let mut c = sh_with_bin(
        "trap '' HUP INT QUIT; exec \"$0\" run -- sh -c \
         'n=0; trap \"n=\\$((n+1))\" TERM; echo ready; i=0; \
          while [ $i -lt 40 ]; do sleep 0.025; i=$((i+1)); done; echo alive count=$n; exit 3'",
    );
    let mut child = c.stdout(Stdio::piped()).spawn().unwrap();
    let mut r = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    let pid = child.id().to_string(); // sh exec'd heimdall-proto: same PID
    for sig in ["-HUP", "-INT", "-QUIT", "-TERM"] {
        assert!(shell_kill(sig, &pid), "{sig}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let st = child.wait().unwrap();
    let mut rest = String::new();
    r.read_to_string(&mut rest).unwrap();
    assert_eq!(
        (st.code(), rest.trim()),
        (Some(3), "alive count=1"),
        "HUP/INT/QUIT ignored and not forwarded; TERM forwarded once"
    );
}

/// Stack limitation, recorded rather than hidden: Rust std ignores SIGPIPE before
/// main and resets it to SIG_DFL in spawned children, so an inherited ignored SIGPIPE
/// is not preserved (stable Rust has no opt-out). This test asserts the limitation is
/// still present; if a toolchain change fixes it, the test fails and REPORT.md must
/// be updated.
#[test]
fn k6a_limitation_sigpipe_ignore_not_preserved_by_rust_std() {
    let o = sh_with_bin("trap '' PIPE; exec \"$0\" run -- sh -c 'kill -PIPE $$; echo survived'")
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(128 + 13),
        "observed: child killed by SIGPIPE although the caller ignored it"
    );
}

/// True if `pid` exists and is not a zombie.
fn pid_running(pid: i32) -> bool {
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        return stat
            .rsplit_once(')')
            .map(|(_, rest)| !rest.trim_start().starts_with('Z'))
            .unwrap_or(false);
    }
    pid_alive(pid)
}

/// Round-1 review (minor): without a terminal the child had its own process group, so
/// a supervisor's `killpg(SIGKILL)` on heimdall-proto's group orphaned it. With exec
/// semantics the child is in the same group and dies with it.
#[test]
fn k6a_group_sigkill_leaves_no_orphan() {
    use std::os::unix::process::CommandExt;
    let mut child = cmd()
        .args(["run", "--", "sh", "-c", "echo $$; exec sleep 30"])
        .process_group(0)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut r = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let grandchild: i32 = line.trim().parse().unwrap();
    assert!(pid_running(grandchild));
    assert!(shell_kill("-KILL", &format!("-{}", child.id())));
    let _ = child.wait();
    let t = Instant::now();
    while pid_running(grandchild) && t.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let orphan = pid_running(grandchild);
    if orphan {
        shell_kill("-KILL", &grandchild.to_string());
    }
    assert!(
        !orphan,
        "child survived killpg(SIGKILL) of heimdall-proto's group"
    );
}

fn mkfifo(path: &Path) {
    let st = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(st.success(), "mkfifo");
}

/// Round-1 review (minor): a FIFO --meta-file without a reader blocked forever after
/// the child exited. Now the open fails at once and the child's status is kept; a FIFO
/// that has a reader still receives the result.
#[test]
fn meta_file_fifo_never_blocks() {
    let d = TempDir::new("mfifo");
    let fifo = d.path().join("meta fifo");
    mkfifo(&fifo);
    let mut c = cmd()
        .args(["run", "--meta-file"])
        .arg(&fifo)
        .args(["--", "sh", "-c", "exit 4"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let t = Instant::now();
    let st = loop {
        if let Some(st) = c.try_wait().unwrap() {
            break Some(st);
        }
        if t.elapsed() > Duration::from_secs(3) {
            let _ = c.kill();
            let _ = c.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        st.and_then(|s| s.code()),
        Some(4),
        "no hang; child's status kept"
    );
    // With a reader: the JSON arrives.
    let fifo2 = fifo.clone();
    let reader = std::thread::spawn(move || std::fs::read(&fifo2).unwrap());
    std::thread::sleep(Duration::from_millis(100));
    let o = cmd()
        .args(["run", "--meta-file"])
        .arg(&fifo)
        .args(["--", "sh", "-c", "exit 5"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(5));
    let v: Value = serde_json::from_slice(&reader.join().unwrap()).unwrap();
    assert_eq!(v["code"], "CHILD_EXITED");
    assert_eq!(v["data"]["exit_code"], 5);
}

/// K14: a --file that is not a regular file is USAGE_ERROR within 2 s; the program
/// never blocks on it (FIFO without a writer, directory, character device, socket).
#[test]
fn k14_non_regular_profile_files() {
    let d = TempDir::new("k14");
    let fifo = d.path().join("profile fifo");
    mkfifo(&fifo);
    let sock = d.path().join("p.sock");
    let _l = UnixListener::bind(&sock).unwrap();
    let dir = d.path().join("a dir");
    std::fs::create_dir(&dir).unwrap();
    for p in [
        fifo.as_path(),
        dir.as_path(),
        Path::new("/dev/null"),
        sock.as_path(),
    ] {
        let mut c = cmd()
            .args(["profile", "show", "--json", "--file"])
            .arg(p)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let t = Instant::now();
        while c.try_wait().unwrap().is_none() && t.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if c.try_wait().unwrap().is_none() {
            let _ = c.kill();
            let _ = c.wait();
            panic!("{}: still running after 2 s", p.display());
        }
        let o = c.wait_with_output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{}", p.display());
        assert_eq!(one_json(&o)["code"], "USAGE_ERROR", "{}", p.display());
    }
}

/// Peak RSS (bytes) and wall time of one `profile show --json` run, measured with
/// wait4(2) for exactly that child.
fn measured_profile_show(path: &Path) -> (i32, Value, u64, Duration) {
    let t = Instant::now();
    let mut c = cmd()
        .args(["profile", "show", "--json", "--file"])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = Vec::new();
    c.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    let pid = c.id() as libc::pid_t;
    let mut status = 0;
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: test-only wait4 on our own child; `ru` is valid writable storage.
    let r = unsafe { libc::wait4(pid, &mut status, 0, ru.as_mut_ptr()) };
    assert_eq!(r, pid);
    let elapsed = t.elapsed();
    // SAFETY: wait4 succeeded and filled `ru`.
    let ru = unsafe { ru.assume_init() };
    std::mem::forget(c); // already reaped
    let maxrss = ru.ru_maxrss as u64 * if cfg!(target_os = "macos") { 1 } else { 1024 };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    (
        code,
        serde_json::from_slice(&out).unwrap_or(Value::Null),
        maxrss,
        elapsed,
    )
}

/// K15: any input up to the 1 MiB bound, including deep nesting and very wide
/// arrays/tables inside [meta], is decided within 2 s and below 256 MiB peak RSS, and
/// the result is PROFILE_OK or SCHEMA_INVALID.
#[test]
fn k15_parser_resource_bound() {
    const LIM: usize = 1_048_576;
    let head = "schema_version = 1\nname = \"x\"\nrevision = 1\n[meta]\n";
    let h2 = "schema_version = 1\nname = \"x\"\nrevision = 1\n";
    let room = LIM - head.len() - 16;
    let cases: Vec<(&str, String)> = vec![
        (
            "deep-array-open",
            format!("{head}a = {}\n", "[".repeat(room)),
        ),
        (
            "deep-array-closed",
            format!(
                "{head}a = {}{}\n",
                "[".repeat(room / 2),
                "]".repeat(room / 2)
            ),
        ),
        (
            "deep-inline-open",
            format!("{head}a = {}\n", "{b=".repeat(room / 3)),
        ),
        (
            "deep-inline-closed",
            format!(
                "{head}a = {}1{}\n",
                "{b=".repeat(room / 4),
                "}".repeat(room / 4)
            ),
        ),
        (
            "deep-dotted-key",
            format!("{head}{} = 1\n", vec!["a"; room / 2].join(".")),
        ),
        (
            "deep-table-header",
            format!("{h2}[meta.{}]\n", vec!["a"; room / 2].join(".")),
        ),
        (
            "wide-array",
            format!("{head}a = [{}]\n", "0,".repeat(room / 2)),
        ),
        (
            "wide-empty-arrays",
            format!("{head}a = [{}]\n", "[],".repeat(room / 3)),
        ),
        (
            "wide-empty-tables",
            format!("{head}a = [{}]\n", "{},".repeat(room / 3)),
        ),
        (
            "wide-strings",
            format!("{head}a = [{}]\n", "\"\",".repeat(room / 3)),
        ),
        (
            "array-of-tables",
            format!("{h2}{}", "[[meta.a]]\n".repeat(room / 11)),
        ),
        (
            "nested-2-arrays",
            format!(
                "{head}a = [{}]\n",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"
                    .repeat(room / 66)
            ),
        ),
    ];
    let d = TempDir::new("k15");
    let mut worst = (0u64, Duration::ZERO);
    for (name, text) in cases {
        let mut bytes = text.into_bytes();
        bytes.truncate(LIM);
        let p = d.path().join(format!("{name}.toml"));
        std::fs::write(&p, &bytes).unwrap();
        let (code, v, rss, dt) = measured_profile_show(&p);
        eprintln!(
            "{name}: {} bytes exit {code} {} rss {} MiB {:?}",
            bytes.len(),
            v["code"],
            rss >> 20,
            dt
        );
        assert!(
            (code, v["code"].as_str()) == (0, Some("PROFILE_OK"))
                || (code, v["code"].as_str()) == (2, Some("SCHEMA_INVALID")),
            "{name}: exit {code} {}",
            v["code"]
        );
        assert!(dt < Duration::from_secs(2), "{name}: {dt:?}");
        assert!(rss < 256 << 20, "{name}: peak RSS {rss}");
        worst = (worst.0.max(rss), worst.1.max(dt));
    }
    eprintln!(
        "K15 worst case: peak RSS {} MiB, {:?}",
        worst.0 >> 20,
        worst.1
    );
}
