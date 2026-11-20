//! The worker: this test binary re-executed under `heimdall run` on the profile's
//! managed binding (`World::spawn_worker`), the same re-execution pattern as
//! `tests/integration/issuer_child.rs`'s runtime entry. It is a same-user process
//! started on a managed binding, as A10 means it (ADR-0008 D12 item 6): it does what
//! its instruction file asks and writes what it saw to its result file, never to
//! stdout, and never prints a path, user or secret.
//!
//! Tasks (JSON objects, run in order; each result is appended and the result file is
//! rewritten after every task):
//! * `login {label, program, args, env, marker}`: a fresh login, the client run with
//!   exactly that environment, bounded; result `{exit, marker_seen, stderr}`;
//! * `fds`: its own open descriptors ([`crate::procs`]); result `{fds, pid}`;
//! * `agent_list {label, program, endpoint}`: `ssh-add -L` against `endpoint` (or this
//!   process's `SSH_AUTH_SOCK` when `endpoint` is null); result `{exit, lines}`;
//! * `signal {path}`: create the file (after the results so far are written);
//! * `wait {path, timeout_s}`: wait for the file;
//! * `dpapi {label, dir, environment, fingerprint}` (Windows): read the CA item through
//!   the product's DPAPI store; result `{read: bool, matches: bool}`;
//! * ⟨M05 exit suite⟩ `env_names`: the names (never the values) of its environment
//!   variables; result `{names}`;
//! * ⟨M05⟩ `agent_frames {label, frames}`: on one connection to its own `SSH_AUTH_SOCK`,
//!   each frame's payload sent framed and its one reply read, then an identities request;
//!   result `{replies, listed}` (reply bytes and the identity count; `error` instead when
//!   it has no endpoint or the connection broke);
//! * ⟨M05⟩ `login` with `own_agent: true` (and `ssh_add`): the login through its **own**
//!   `SSH_AUTH_SOCK` (a delegated child's endpoint): the first identity that endpoint lists
//!   is written to a file beside the result and the client gets `-o IdentityAgent=<it>`
//!   and `-o IdentityFile=<that file>` before the alias (with the projection's
//!   `IdentitiesOnly`, so only that identity is offered); with `fallback`, an endpoint
//!   that lists nothing still gets the identity the earlier login `fallback` used, so the
//!   server decides; result as `login`.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::world::run_bounded;

/// A `login` task.
pub fn login(
    label: &str,
    cmd: &(PathBuf, Vec<OsString>, Vec<(OsString, OsString)>),
    marker: &str,
) -> Value {
    let (program, args, env) = cmd;
    json!({
        "kind": "login",
        "label": label,
        "program": program,
        "args": args.iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "env": env.iter().map(|(k, v)| [k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()]).collect::<Vec<_>>(),
        "marker": marker,
    })
}

/// An `fds` task.
pub fn fds() -> Value {
    json!({ "kind": "fds" })
}

/// An `agent_list` task (`endpoint` `None`: the worker's own `SSH_AUTH_SOCK`).
pub fn agent_list(label: &str, endpoint: Option<&str>) -> Value {
    json!({
        "kind": "agent_list",
        "label": label,
        "program": crate::world::openssh("ssh-add"),
        "endpoint": endpoint,
    })
}

/// ⟨M05⟩ A `login` task through the worker's own `SSH_AUTH_SOCK` (module docs).
pub fn own_agent_login(
    label: &str,
    cmd: &(PathBuf, Vec<OsString>, Vec<(OsString, OsString)>),
    marker: &str,
) -> Value {
    let mut task = login(label, cmd, marker);
    task["own_agent"] = Value::Bool(true);
    task["ssh_add"] = json!(crate::world::openssh("ssh-add"));
    task
}

/// ⟨M05⟩ [`own_agent_login`] that, when the endpoint lists nothing, still offers the
/// identity the earlier login `fallback` of this worker used.
pub fn own_agent_login_after(
    label: &str,
    cmd: &(PathBuf, Vec<OsString>, Vec<(OsString, OsString)>),
    marker: &str,
    fallback: &str,
) -> Value {
    let mut task = own_agent_login(label, cmd, marker);
    task["fallback"] = json!(fallback);
    task
}

/// ⟨M05⟩ An `env_names` task.
pub fn env_names() -> Value {
    json!({ "kind": "env_names" })
}

/// ⟨M05⟩ An `agent_frames` task: each of `frames` is one payload (without its length).
pub fn agent_frames(label: &str, frames: &[Vec<u8>]) -> Value {
    json!({ "kind": "agent_frames", "label": label, "frames": frames })
}

/// A `signal` task.
pub fn signal(path: &Path) -> Value {
    json!({ "kind": "signal", "path": path })
}

/// A `wait` task.
pub fn wait(path: &Path, timeout: Duration) -> Value {
    json!({ "kind": "wait", "path": path, "timeout_s": timeout.as_secs() })
}

/// A `dpapi` task.
pub fn dpapi(label: &str, dir: &Path, environment: &str, fingerprint: &str) -> Value {
    json!({
        "kind": "dpapi",
        "label": label,
        "dir": dir,
        "environment": environment,
        "fingerprint": fingerprint,
    })
}

/// The result of the task labelled `label` (or of kind `kind` when unlabelled).
pub fn result<'a>(results: &'a [Value], kind: &str, label: Option<&str>) -> &'a Value {
    results
        .iter()
        .find(|r| r["kind"] == kind && label.is_none_or(|l| r["label"] == l))
        .unwrap_or_else(|| panic!("no {kind} {label:?} result in {results:?}"))
}

/// The worker's body (module docs): read the instructions at `path` and run them.
pub fn run(path: &Path) {
    let text = std::fs::read(path).expect("the worker's instructions");
    let instructions: Value = serde_json::from_slice(&text).unwrap();
    let result_path = PathBuf::from(instructions["result"].as_str().unwrap());
    let mut results: Vec<Value> = Vec::new();
    let write = |results: &[Value]| {
        let tmp = result_path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(results).unwrap()).unwrap();
        std::fs::rename(&tmp, &result_path).unwrap();
    };
    for task in instructions["tasks"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let label = task["label"].clone();
        let r = match task["kind"].as_str().unwrap_or("") {
            "login" => {
                let mut cmd = Command::new(task["program"].as_str().unwrap());
                cmd.env_clear();
                let mut args: Vec<String> = task["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_owned())
                    .collect();
                if task["own_agent"] == true {
                    match own_identity(&task, &result_path) {
                        Ok(extra) => {
                            let at = args.len().saturating_sub(2);
                            for (i, a) in extra.into_iter().enumerate() {
                                args.insert(at + i, a);
                            }
                        }
                        Err(why) => {
                            let mut r = json!({ "exit": -2, "marker_seen": false, "error": why });
                            r["kind"] = task["kind"].clone();
                            r["label"] = label;
                            results.push(r);
                            write(&results);
                            continue;
                        }
                    }
                }
                cmd.args(&args);
                for kv in task["env"].as_array().unwrap() {
                    cmd.env(kv[0].as_str().unwrap(), kv[1].as_str().unwrap());
                }
                if let Some(dir) = result_path.parent() {
                    cmd.current_dir(dir);
                }
                let out = run_bounded(&mut cmd, Duration::from_secs(60));
                let marker = task["marker"].as_str().unwrap();
                let tail: Vec<&str> = out.stderr.lines().rev().take(8).collect();
                json!({
                    "exit": out.code,
                    "marker_seen": out.stdout.lines().any(|l| l.trim() == marker),
                    "stderr": tail.into_iter().rev().collect::<Vec<_>>().join(" | "),
                })
            }
            "fds" => {
                let pid = std::process::id();
                match crate::procs::fds_of(pid) {
                    Ok(fds) => json!({
                        "pid": pid,
                        "fds": fds.iter().map(crate::procs::Fd::to_json).collect::<Vec<_>>(),
                    }),
                    Err(why) => json!({ "pid": pid, "error": why }),
                }
            }
            "agent_list" => {
                let endpoint = task["endpoint"]
                    .as_str()
                    .map(OsString::from)
                    .or_else(|| std::env::var_os("SSH_AUTH_SOCK"));
                match endpoint {
                    None => json!({ "exit": -2, "lines": [], "no_endpoint": true }),
                    Some(ep) => {
                        let mut cmd = Command::new(task["program"].as_str().unwrap());
                        cmd.arg("-L").env_clear().env("SSH_AUTH_SOCK", ep);
                        for k in ["SystemRoot", "PATH"] {
                            if let Some(v) = std::env::var_os(k) {
                                cmd.env(k, v);
                            }
                        }
                        #[cfg(windows)]
                        for (k, v) in crate::world::openssh_startup_env() {
                            cmd.env(k, v);
                        }
                        let out = run_bounded(&mut cmd, Duration::from_secs(20));
                        json!({
                            "exit": out.code,
                            "lines": out.stdout.lines().filter(|l| !l.trim().is_empty()).collect::<Vec<_>>(),
                        })
                    }
                }
            }
            "signal" => {
                write(&results);
                std::fs::write(task["path"].as_str().unwrap(), b"").unwrap();
                json!({})
            }
            "wait" => {
                let p = PathBuf::from(task["path"].as_str().unwrap());
                let limit = Duration::from_secs(task["timeout_s"].as_u64().unwrap_or(60));
                let start = Instant::now();
                while !p.exists() && start.elapsed() < limit {
                    std::thread::sleep(Duration::from_millis(50));
                }
                json!({ "seen": p.exists() })
            }
            "dpapi" => dpapi_read(&task),
            "env_names" => json!({
                "names": std::env::vars_os()
                    .map(|(k, _)| k.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
            }),
            "agent_frames" => agent_frames_run(&task),
            other => json!({ "error": format!("unknown task {other}") }),
        };
        let mut r = r;
        r["kind"] = task["kind"].clone();
        r["label"] = label;
        results.push(r);
        write(&results);
    }
}

/// ⟨M05⟩ This process's own `SSH_AUTH_SOCK` as a testkit endpoint.
fn own_endpoint() -> Option<heimdall_testkit::agent::Endpoint> {
    let sock = std::env::var_os("SSH_AUTH_SOCK")?;
    if cfg!(windows) {
        Some(heimdall_testkit::agent::Endpoint::NamedPipe(
            sock.to_string_lossy().into_owned(),
        ))
    } else {
        Some(heimdall_testkit::agent::Endpoint::UnixSocket(
            PathBuf::from(sock),
        ))
    }
}

/// ⟨M05⟩ The client options of an `own_agent` login (module docs): `-o IdentityAgent=…`
/// (a pipe in the `//./pipe/<name>` form the in-box client keeps whole) and `-o
/// IdentityFile=<the first listed identity, written beside the result>`.
fn own_identity(task: &Value, result_path: &Path) -> Result<Vec<String>, String> {
    let sock = std::env::var_os("SSH_AUTH_SOCK").ok_or("no SSH_AUTH_SOCK")?;
    let mut cmd = Command::new(task["ssh_add"].as_str().ok_or("no ssh-add")?);
    cmd.arg("-L").env_clear().env("SSH_AUTH_SOCK", &sock);
    for k in ["SystemRoot", "PATH"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    #[cfg(windows)]
    for (k, v) in crate::world::openssh_startup_env() {
        cmd.env(k, v);
    }
    let out = run_bounded(&mut cmd, Duration::from_secs(20));
    let label = task["label"].as_str().unwrap_or("own");
    let file = match out.stdout.lines().find(|l| !l.trim().is_empty()) {
        Some(first) => {
            let file = result_path.with_file_name(format!("{label}-identity.pub"));
            std::fs::write(&file, format!("{first}\n")).map_err(|e| e.kind().to_string())?;
            file
        }
        // An endpoint that lists nothing (its key destroyed): the identity an earlier
        // login of this worker used, so the server is still asked.
        None => task["fallback"]
            .as_str()
            .map(|l| result_path.with_file_name(format!("{l}-identity.pub")))
            .filter(|f| f.exists())
            .ok_or("the endpoint lists no identity")?,
    };
    let agent = sock.to_string_lossy().replace('\\', "/");
    Ok(vec![
        "-o".to_owned(),
        format!("IdentityAgent={agent}"),
        "-o".to_owned(),
        format!("IdentityFile={}", file.to_string_lossy().replace('\\', "/")),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
    ])
}

/// ⟨M05⟩ The `agent_frames` task (module docs).
fn agent_frames_run(task: &Value) -> Value {
    let Some(endpoint) = own_endpoint() else {
        return json!({ "error": "no SSH_AUTH_SOCK" });
    };
    let mut conn =
        match heimdall_testkit::agent::AgentConnection::connect(&endpoint, Duration::from_secs(10))
        {
            Ok(c) => c,
            Err(e) => return json!({ "error": format!("connect: {}", e.kind()) }),
        };
    let mut replies = Vec::new();
    for f in task["frames"].as_array().cloned().unwrap_or_default() {
        let payload: Vec<u8> = f
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
            .collect();
        match conn.request(&payload) {
            Ok(reply) => replies.push(reply),
            Err(e) => {
                return json!({ "replies": replies, "error": format!("request: {}", e.kind()) });
            }
        }
    }
    match conn.list() {
        Ok(listed) => json!({ "replies": replies, "listed": listed.len() }),
        Err(e) => json!({ "replies": replies, "error": format!("list: {}", e.kind()) }),
    }
}

/// Read the CA item through the product's DPAPI store (Windows): what a same-user
/// worker can do (ADR-0008 D12 item 6). The key is compared, never printed or kept.
fn dpapi_read(task: &Value) -> Value {
    #[cfg(windows)]
    {
        use heimdall_issuer::store::SecretStore as _;
        let env =
            heimdall_contract::ids::EnvironmentId::parse(task["environment"].as_str().unwrap())
                .unwrap();
        let fp =
            heimdall_contract::ids::CaFingerprint::parse(task["fingerprint"].as_str().unwrap())
                .unwrap();
        let store =
            heimdall_issuer::store::WindowsDpapi::in_dir(task["dir"].as_str().unwrap(), &env);
        match store.get(&fp) {
            Ok(key) => {
                json!({ "read": true, "matches": key.fingerprint().ok().as_ref() == Some(&fp) })
            }
            Err(e) => json!({ "read": false, "matches": false, "error": e.to_string() }),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = task;
        json!({ "read": false, "matches": false, "error": "Windows only" })
    }
}
