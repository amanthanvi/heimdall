//! ⟨M05, U8⟩ `heimdall run --parent-binding` through the **real binary** (`HEIMDALL_E2E_BIN`,
//! else `CARGO_BIN_EXE_heimdall`), its CLI-started runtime and its **real** `internal issuer`
//! child, on two real loopback `sshd`s (m05-plan U8; ADR-0011 §6; spec §14.3).
//!
//! Cargo test target `e2e_delegation_m05`, hosted by `heimdall`. The scaffolding is the exit
//! suite's [`world`] (a scratch home, the managed runtime and two pairs on two servers, each
//! trusting the CA for its own pair's principal only; see `exit_m03/world.rs`).
//!
//! * [`run_parent_binding_gives_the_worker_only_the_child_endpoint`]: the worker, started by
//!   `run --parent-binding <parent> --scope <pair 1>` as the test binary re-executed
//!   ([`probe`]), sees **no `HEIMDALL_*` variable** (the run's own environment carries
//!   `HEIMDALL_HOME` and the test configuration) and an `SSH_AUTH_SOCK` that is **not** the
//!   parent's endpoint and lists exactly the child's one certificate (the parent's lists
//!   both); its login to pair 1's server is admitted, by the child's own grant, and its
//!   attempt at pair 2's server is refused (the same CA, the other principal mapping).
//! * [`wider_or_longer_request_launches_nothing`]: a wider scope and a later `--until` are each
//!   `DELEGATION_EXCEEDS_PARENT` on stderr, the program never runs, and no grant is created.
//! * [`parent_binding_flags_are_validated_before_any_runtime_contact`] (every platform): the
//!   flag rules (`--parent-binding` conflicts with `--profile`; `--scope` and `--until` need
//!   it).
//!
//! **Platforms.** The two journeys need two loopback servers and Unix sockets: Unix only. The
//! Windows harness serves one account-form server per test thread, so the scope refusal has
//! no second server there; they are `blocked` on Windows (the live `sshd` rows in
//! `crates/runtime/src/managed_store/live_tests/delegation_m05.rs` are blocked there too).
//!
//! **Isolation** is the world's: a cleared environment, a scratch `HOME` and Heimdall home,
//! stdin closed, the decoy agent; no owner key, agent, keychain or `~/.ssh` is touched. Only
//! processes this test started are stopped (the runtime through `service stop` on its own
//! scratch home, the worker through its exact handle).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    missing_docs
)]
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

#[cfg(unix)]
#[path = "exit_m03/procs.rs"]
mod procs;
#[cfg(unix)]
#[path = "exit_m03/world.rs"]
mod world;

use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

/// The worker's instruction-file variable ([`probe`]).
const PROBE_ENV: &str = "HM_M05_DELEGATION_PROBE";

/// The binary under test.
fn bin() -> std::path::PathBuf {
    std::env::var_os("HEIMDALL_E2E_BIN")
        .filter(|p| !p.is_empty())
        .map_or_else(
            || std::path::PathBuf::from(env!("CARGO_BIN_EXE_heimdall")),
            std::path::PathBuf::from,
        )
}

/// The worker's entry when this binary is re-executed under `run --parent-binding`; a no-op
/// in the suite itself (no instructions).
#[test]
fn probe_process_entry() {
    #[cfg(unix)]
    if let Some(path) = std::env::var_os(PROBE_ENV) {
        probe(Path::new(&path));
    }
}

/// The worker: report what it can see, never a secret or a path of the owner's. Writes
/// `{env_names, auth_sock, listed, logins}` to the instructions' `result`.
#[cfg(unix)]
fn probe(path: &Path) {
    use std::time::Duration;

    use serde_json::json;
    let text = std::fs::read(path).expect("the worker's instructions");
    let ins: Value = serde_json::from_slice(&text).unwrap();
    let sock = std::env::var_os("SSH_AUTH_SOCK");
    let env_names: Vec<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    // The identities its own agent endpoint lists.
    let listed = sock.as_ref().map(|s| {
        let mut cmd = Command::new(ins["ssh_add"].as_str().unwrap());
        cmd.arg("-L").env_clear().env("SSH_AUTH_SOCK", s);
        let out = world::run_bounded(&mut cmd, Duration::from_secs(20));
        out.stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    // Fresh logins through that endpoint (`IdentityAgent` = its `SSH_AUTH_SOCK`, every
    // identity the agent lists offered): what the child's certificates are admitted by.
    let mut logins = Vec::new();
    for task in ins["logins"].as_array().cloned().unwrap_or_default() {
        let mut args: Vec<String> = task["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_owned())
            .collect();
        let at = args.len() - 2; // before `<alias>` and `echo <marker>`
        let sock = sock
            .as_ref()
            .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
        for (i, option) in [
            "-o",
            &format!("IdentityAgent={sock}"),
            "-o",
            "IdentitiesOnly=no",
            "-o",
            "PreferredAuthentications=publickey",
        ]
        .into_iter()
        .enumerate()
        {
            args.insert(at + i, option.to_owned());
        }
        let mut cmd = Command::new(task["program"].as_str().unwrap());
        cmd.args(&args).env_clear();
        for kv in task["env"].as_array().unwrap() {
            cmd.env(kv[0].as_str().unwrap(), kv[1].as_str().unwrap());
        }
        let out = world::run_bounded(&mut cmd, Duration::from_secs(60));
        let marker = task["marker"].as_str().unwrap();
        logins.push(json!({
            "label": task["label"],
            "exit": out.code,
            "marker_seen": out.stdout.lines().any(|l| l.trim() == marker),
        }));
    }
    let result = path.parent().unwrap().join("result.json");
    std::fs::write(
        &result,
        serde_json::to_vec(&json!({
            "env_names": env_names,
            "auth_sock": sock.map(|s| s.to_string_lossy().into_owned()),
            "listed": listed,
            "logins": logins,
        }))
        .unwrap(),
    )
    .unwrap();
}

/// `argv` after `--`: this test binary running only [`probe_process_entry`].
#[cfg(unix)]
fn probe_argv() -> Vec<std::ffi::OsString> {
    let mut v = vec![std::env::current_exe().unwrap().into_os_string()];
    v.extend(
        [
            "--exact",
            "probe_process_entry",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ]
        .map(std::ffi::OsString::from),
    );
    v
}

/// The last JSON object on `text` (the envelope `--json` printed).
#[cfg(unix)]
fn envelope(text: &str) -> Value {
    text.lines()
        .rev()
        .filter_map(|l| l.trim().find('{').map(|i| l.trim()[i..].to_owned()))
        .find_map(|l| serde_json::from_str::<Value>(&l).ok())
        .unwrap_or_else(|| panic!("no envelope: {text}"))
}

/// The grant ID of a certificate key ID `hm:<environment>:<grant>:<serial>`.
#[cfg(unix)]
fn grant_of(key_id: &str) -> String {
    key_id.split(':').nth(2).unwrap_or_default().to_owned()
}

#[cfg(unix)]
fn world() -> world::World {
    let (w, _ca) = world::World::start(world::WorldOptions {
        pairs: 2,
        per_pair_profiles: true,
        ..world::WorldOptions::default()
    });
    w
}

/// `heimdall run --parent-binding …` in `w`'s environment, bounded; `extra` are the flags
/// between the parent and `--`.
#[cfg(unix)]
fn run_child(
    w: &world::World,
    parent: &str,
    extra: &[&str],
    instructions: Option<&Path>,
) -> world::Out {
    let mut cmd = Command::new(bin());
    cmd.args(["--json", "run", "--parent-binding", parent])
        .args(extra)
        .arg("--")
        .args(probe_argv())
        .env_clear()
        .envs(w.env())
        .current_dir(&w.home.root);
    if let Some(i) = instructions {
        cmd.env(PROBE_ENV, i);
    }
    world::run_bounded(&mut cmd, std::time::Duration::from_secs(180))
}

#[cfg(unix)]
#[test]
fn run_parent_binding_gives_the_worker_only_the_child_endpoint() {
    use std::time::Duration;

    use serde_json::json;
    let w = world();
    let parent = w.ensure("m05-parent", "m05-parent-req");
    let parent_binding = parent["binding_id"].as_str().unwrap().to_owned();
    let parent_grant = parent["grant_id"].as_str().unwrap().to_owned();
    let parent_endpoint = parent["consumer"]["signing_endpoint"]
        .as_str()
        .expect("a managed binding names its signing endpoint")
        .to_owned();
    // The parent's own endpoint lists both certificates (the child's will list one).
    let ssh_add = world::openssh("ssh-add");
    let listed = |sock: &str| {
        let mut cmd = Command::new(&ssh_add);
        cmd.arg("-L").env_clear().env("SSH_AUTH_SOCK", sock);
        world::run_bounded(&mut cmd, Duration::from_secs(20))
            .stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let parent_lines = listed(&parent_endpoint);
    assert_eq!(parent_lines.len(), 2, "the parent holds both pairs");

    // The worker's two logins: pair 1's server (admitted) and pair 2's (refused).
    let dir = w.subdir("probe");
    let instructions = dir.join("instructions.json");
    let logins: Vec<Value> = (0..2)
        .map(|i| {
            let (program, args, env) = w.login_command(i, &format!("m05-login-{i}"));
            json!({
                "label": format!("pair{}", i + 1),
                "program": program,
                "args": args.iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>(),
                "env": env.iter().map(|(k, v)| [k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()]).collect::<Vec<_>>(),
                "marker": format!("m05-login-{i}"),
            })
        })
        .collect();
    std::fs::write(
        &instructions,
        serde_json::to_vec(&json!({ "ssh_add": ssh_add, "logins": logins })).unwrap(),
    )
    .unwrap();
    let marks = [w.pairs[0].sshd.log_mark(), w.pairs[1].sshd.log_mark()];

    let meta = dir.join("run.ndjson");
    let scope = w.pairs[0].pair_arg();
    let out = run_child(
        &w,
        &parent_binding,
        &[
            "--scope",
            &scope,
            "--request-id",
            "m05-child-req",
            "--meta-file",
            meta.to_str().unwrap(),
        ],
        Some(&instructions),
    );
    assert_eq!(
        out.code,
        0,
        "run --parent-binding: {}",
        w.redact(&format!("{out:?}"))
    );
    let seen: Value = serde_json::from_slice(
        &std::fs::read(dir.join("result.json")).expect("the worker ran and reported"),
    )
    .unwrap();

    // 1. The environment: no Heimdall variable of any kind, an endpoint that is the child's.
    let names: Vec<&str> = seen["env_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(
        names.iter().all(|n| !n.starts_with("HEIMDALL_")),
        "no locator of the runtime reaches the worker: {names:?}"
    );
    assert!(
        w.env()
            .iter()
            .any(|(k, _)| k.to_string_lossy() == "HEIMDALL_HOME"),
        "the run's own environment did carry one (the control is real)"
    );
    let sock = seen["auth_sock"].as_str().expect("the child's endpoint");
    assert_ne!(
        sock, parent_endpoint,
        "the child's endpoint, not the parent's"
    );
    let child_lines: Vec<&str> = seen["listed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert_eq!(child_lines.len(), 1, "exactly the child's one certificate");
    assert!(
        parent_lines.iter().all(|p| p != child_lines[0]),
        "its own key and certificate"
    );

    // 2. The child's own grant, a child of the parent's, authenticated pair 1 and only there.
    let launching: Value = serde_json::from_str(
        std::fs::read_to_string(&meta)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let child_binding =
        heimdall_contract::ids::BindingId::parse(launching["binding_id"].as_str().unwrap())
            .unwrap();
    let (child, child_grant) = {
        let store = w.open_store();
        let b = store
            .transaction(|tx| tx.binding(&child_binding))
            .unwrap()
            .expect("the child's binding");
        let g = store.transaction(|tx| tx.grant(&b.grant)).unwrap().unwrap();
        (b, g)
    };
    assert_eq!(
        child.parent.as_ref().map(ToString::to_string),
        Some(parent_binding.clone())
    );
    assert_eq!(
        child_grant.parent.as_ref().map(ToString::to_string),
        Some(parent_grant.clone())
    );
    assert_eq!(child.scope.pairs.len(), 1, "the narrower scope");
    let logins = seen["logins"].as_array().unwrap();
    assert_eq!(logins[0]["exit"], 0, "pair 1: {logins:?}");
    assert_eq!(logins[0]["marker_seen"], true);
    assert_ne!(logins[1]["exit"], 0, "pair 2 refuses the child: {logins:?}");
    assert_eq!(logins[1]["marker_seen"], false);
    let accepted_1 = w.accepted_since(0, marks[0]);
    assert_eq!(accepted_1.len(), 1, "{accepted_1:?}");
    assert_eq!(
        grant_of(&accepted_1[0].key_id),
        child_grant.id.to_string(),
        "the child's grant authenticated, not the parent's"
    );
    assert!(
        w.accepted_since(1, marks[1]).is_empty(),
        "the second server, which trusts the same CA under the other mapping, accepted nothing"
    );
    w.stop_runtime();
}

#[cfg(unix)]
#[test]
fn wider_or_longer_request_launches_nothing() {
    let w = world();
    // The parent holds pair 1 only; pair 2 is in the world, so a request for it is wider.
    let parent = w.ensure_on(&w.profile_of(0), "m05-narrow", "m05-narrow-req");
    let parent_binding = parent["binding_id"].as_str().unwrap().to_owned();
    let expires = parent["expires_at"].as_str().unwrap();
    let later = {
        let t: heimdall_contract::Timestamp = expires.parse().unwrap();
        heimdall_contract::Timestamp::from_second(t.as_second() + 3600)
            .unwrap()
            .to_string()
    };
    let grants_before = w
        .open_store()
        .transaction(|tx| tx.grants_due(heimdall_contract::Timestamp::MAX))
        .unwrap()
        .len();
    let dir = w.subdir("refused");
    let instructions = dir.join("instructions.json");
    std::fs::write(
        &instructions,
        serde_json::to_vec(&serde_json::json!({
            "ssh_add": world::openssh("ssh-add"),
            "logins": [],
        }))
        .unwrap(),
    )
    .unwrap();
    let both = [w.pairs[0].pair_arg(), w.pairs[1].pair_arg()];
    let first = w.pairs[0].pair_arg();
    for (what, extra) in [
        (
            "a wider scope",
            vec!["--scope", &both[0], "--scope", &both[1]],
        ),
        (
            "a later deadline",
            vec!["--scope", &first, "--until", &later],
        ),
    ] {
        let meta = dir.join(format!("{}.ndjson", what.replace(' ', "-")));
        let mut flags = extra.clone();
        flags.extend(["--meta-file", meta.to_str().unwrap()]);
        let out = run_child(&w, &parent_binding, &flags, Some(&instructions));
        assert_ne!(out.code, 0, "{what}: {out:?}");
        let env = envelope(&out.stderr);
        assert_eq!(env["code"], "DELEGATION_EXCEEDS_PARENT", "{what}: {env}");
        assert!(
            !dir.join("result.json").exists(),
            "{what}: the program never ran"
        );
        let record = std::fs::read_to_string(&meta).unwrap();
        assert!(
            record.contains("prelaunch_failed") && !record.contains("launching"),
            "{what}: {record}"
        );
    }
    let grants_after = w
        .open_store()
        .transaction(|tx| tx.grants_due(heimdall_contract::Timestamp::MAX))
        .unwrap()
        .len();
    assert_eq!(grants_after, grants_before, "no grant, so no child key");
    w.stop_runtime();
}

/// Flag rules, before any runtime contact or home creation (every platform).
#[test]
fn parent_binding_flags_are_validated_before_any_runtime_contact() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("home");
    let account = scratch.path().join("account");
    std::fs::create_dir_all(&account).unwrap();
    let run = |args: &[&str]| {
        let mut cmd = Command::new(bin());
        cmd.args(args)
            .env_clear()
            .env("HOME", &account)
            .env("USERPROFILE", &account)
            .env("HEIMDALL_HOME", &home)
            .stdin(Stdio::null());
        if cfg!(windows) {
            for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
        }
        let out = cmd.output().unwrap();
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    };
    for line in [
        &[
            "run",
            "--profile",
            "dev",
            "--parent-binding",
            "bnd",
            "--",
            "true",
        ][..],
        &["run", "--profile", "dev", "--scope", "d:a", "--", "true"],
        &[
            "run",
            "--profile",
            "dev",
            "--until",
            "2030-01-01T00:00:00Z",
            "--",
            "true",
        ],
    ] {
        let out = run(line);
        assert_eq!(out.status.code(), Some(2), "{line:?}: {out:?}");
    }
    // A malformed binding or pair, or a profile beside the parent, is the ordinary usage
    // error, before the runtime (the program resolves: it is this test binary).
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_str().unwrap();
    for line in [
        vec![
            "--json",
            "run",
            "--parent-binding",
            "not a binding",
            "--",
            exe,
        ],
        vec![
            "--json",
            "run",
            "--parent-binding",
            "binding_0123456789abcdef0123456789abcdef",
            "--scope",
            "no-colon",
            "--",
            exe,
        ],
        vec![
            "--json",
            "run",
            "--profile",
            "dev",
            "--parent-binding",
            "binding_0123456789abcdef0123456789abcdef",
            "--",
            exe,
        ],
    ] {
        let out = run(&line);
        assert_eq!(out.status.code(), Some(2), "{line:?}: {out:?}");
        let env = envelope_any(&String::from_utf8_lossy(&out.stderr));
        assert_eq!(env["code"], "USAGE_ERROR", "{line:?}");
    }
    assert!(
        !home.exists(),
        "a refused flag form created the Heimdall home"
    );
}

/// The last JSON object of `text`.
fn envelope_any(text: &str) -> Value {
    text.lines()
        .rev()
        .filter_map(|l| l.trim().find('{').map(|i| l.trim()[i..].to_owned()))
        .find_map(|l| serde_json::from_str::<Value>(&l).ok())
        .unwrap_or_else(|| panic!("no envelope: {text}"))
}
