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
//!   the product's DPAPI store; result `{read: bool, matches: bool}`.
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
                for a in task["args"].as_array().unwrap() {
                    cmd.arg(a.as_str().unwrap());
                }
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
            other => json!({ "error": format!("unknown task {other}") }),
        };
        let mut r = r;
        r["kind"] = task["kind"].clone();
        r["label"] = label;
        results.push(r);
        write(&results);
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
