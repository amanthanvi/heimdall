//! The M05 exit suite's own helpers (`e2e_exit_m05` submodule), built on the M03 exit
//! world ([`crate::world`], ruling I-16): read-only store readings, the clients the rows
//! run through a managed alias (`ssh`, `scp`, `git`), the shell hook, stand-in shells,
//! the exact-PID runtime stop, and the bounded waits.
//!
//! **Client isolation** (every `ssh`, `scp` and `git` here): the world's isolation
//! arguments (`-F` the scratch configuration holding the scratch projection, the scratch
//! `UserKnownHostsFile` and empty `GlobalKnownHostsFile`, `BatchMode=yes`) plus
//! `IdentitiesOnly=yes`, `ControlMaster=no` and `ControlPath=none`; the identity, agent and
//! certificate options are the projection's own (a login through a managed alias takes
//! its identity from the projection under test, so no `IdentityFile`, `IdentityAgent` or
//! `CertificateFile` override is given). The environment is the world's login
//! environment: the scratch `HOME`, `SSH_AUTH_SOCK` the world's own decoy agent (never an
//! inherited one) and, on Windows, only what the in-box client needs. `git` reaches `ssh`
//! only through `GIT_SSH_COMMAND` carrying those options, with `GIT_CONFIG_NOSYSTEM=1`,
//! `GIT_CONFIG_GLOBAL` and `HOME` in scratch.
//!
//! **Server-side scratch.** A login's remote side runs in a directory beside the server's
//! account-form registry (on a local server, under this run's scratch; on the Windows
//! harness, the WSL scratch the harness owns), and its Git runs with `HOME` there,
//! `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null`.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_contract::ids::{AccountName, BindingId, DestinationId, GrantId, WorkId};
use heimdall_domain::binding::{BindingRecord, BindingState};
use heimdall_domain::managed::SlotState;
use heimdall_domain::scope::AccessPair;
use heimdall_domain::workspace::BindingContext;
use heimdall_store::{NoFaults, Store, Txn};
use serde_json::Value;

use crate::world::{Out, World, openssh, run_bounded};

/// A fresh marker.
pub fn marker(tag: &str) -> String {
    format!("hm-m05-{tag}-{}", heimdall_testkit::agent::random_hex(6))
}

/// The grant a certificate key ID names (`heimdall:<environment>:<grant>:<serial>`).
pub fn grant_of(key_id: &str) -> String {
    key_id.split(':').nth(2).unwrap_or_default().to_owned()
}

/// The environment a certificate key ID names.
pub fn environment_of(key_id: &str) -> String {
    key_id.split(':').nth(1).unwrap_or_default().to_owned()
}

/// Wait (bounded) until `f` gives a value.
pub fn wait_for<T>(what: &str, timeout: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(start.elapsed() < timeout, "{what}: not within {timeout:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---- store readings (read-only, beside the runtime) --------------------------------------

/// Run `f` in a read-only transaction on `w`'s state database.
pub fn read<T>(w: &World, f: impl FnOnce(&mut Txn<'_>) -> heimdall_store::Result<T>) -> T {
    Store::open_read_only(&w.db(), Arc::new(NoFaults))
        .unwrap()
        .transaction(f)
        .unwrap()
}

/// Pair `i` of the world as a domain pair.
pub fn pair_of(w: &World, i: usize) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(&w.pairs[i].destination).unwrap(),
        account: AccountName::parse(&w.pairs[i].account).unwrap(),
    }
}

/// Every decision row, whatever its state, and how many are pending.
pub fn decision_rows(w: &World) -> (u64, usize) {
    read(w, |tx| {
        Ok((tx.table_counts()?.decisions, tx.pending_decisions()?.len()))
    })
}

/// The pending decisions `inspect decisions` lists (the CLI's own count).
pub fn pending_listed(w: &World) -> usize {
    let out = w.cli(&["--json", "inspect", "decisions"]);
    assert_eq!(out.code, 0, "{}", w.redact(&format!("{out:?}")));
    out.json()["data"]["decisions"]
        .as_array()
        .map_or(0, Vec::len)
}

/// The ordinary-alias slot of pair `i`.
pub fn slot(w: &World, i: usize) -> SlotState {
    let pair = pair_of(w, i);
    read(w, |tx| tx.slot(&w.environment, &pair))
}

/// The binding holding pair `i`'s slot, if it is held.
pub fn slot_holder(w: &World, i: usize) -> Option<BindingId> {
    match slot(w, i) {
        SlotState::Held { binding, .. } => Some(binding),
        _ => None,
    }
}

/// The bindings referencing pair `i`'s slot, sorted.
pub fn references(w: &World, i: usize) -> Vec<BindingId> {
    let pair = pair_of(w, i);
    let mut refs: Vec<BindingId> = read(w, |tx| {
        tx.slot_references(&w.environment, &pair.destination, &pair.account)
    })
    .into_iter()
    .map(|r| r.binding)
    .collect();
    refs.sort();
    refs
}

/// The bindings of `work` in the world's environment.
pub fn work_bindings(w: &World, work: &str) -> Vec<BindingRecord> {
    let work = WorkId::parse(work).unwrap();
    read(w, |tx| tx.bindings_for_work(&w.environment, &work))
}

/// The active bindings of `work`.
pub fn active_bindings(w: &World, work: &str) -> Vec<BindingRecord> {
    work_bindings(w, work)
        .into_iter()
        .filter(|b| b.state == BindingState::Active)
        .collect()
}

/// One binding by ID.
pub fn binding(w: &World, id: &BindingId) -> BindingRecord {
    read(w, |tx| tx.binding(id)).expect("the binding exists")
}

/// What a binding pins (ADR-0011 §5.1): environment, profile and revision, scope,
/// mechanism, grant, parent and context.
pub type Pins = (BindingRecord, Option<BindingContext>);

/// The pins of `id` (its state and release time excluded: they are not pins).
pub fn pins(w: &World, id: &BindingId) -> Pins {
    let mut b = binding(w, id);
    b.state = BindingState::Active;
    b.released_at = None;
    let context = read(w, |tx| tx.binding_context(id));
    (b, context)
}

/// The policy a grant's origin names, and its workspace (`None`: personal).
pub fn grant_policy(w: &World, grant: &GrantId) -> (Option<String>, Option<String>) {
    let origin = read(w, |tx| tx.grant_origin(grant)).expect("the grant's origin");
    (
        origin.policy_id.map(|p| p.as_str().to_owned()),
        origin.workspace.map(|ws| ws.to_string()),
    )
}

/// The default endpoint's work `n` (`default:<env>:<n>`, ADR-0011 §3.3).
pub fn default_work(w: &World, n: u64) -> String {
    heimdall_app::operations::default_work_id(&w.environment, n)
        .unwrap()
        .as_str()
        .to_owned()
}

/// The `activation` events recorded so far, oldest first (kind, policy, reason).
pub fn activation_events(w: &World) -> Vec<heimdall_contract::trust::ActivationEventPayload> {
    let filter = heimdall_contract::event::EventFilter {
        operation_id: None,
        types: vec![heimdall_contract::event::EventType::Activation],
    };
    read(w, |tx| tx.events_after(&w.environment, 0, &filter, 1000))
        .events
        .into_iter()
        .map(|e| serde_json::from_value(e.payload).unwrap())
        .collect()
}

/// How many `[y/N]` prompts and typed-confirmation invitations the binary printed in
/// transcript entries from `from` on (the A02 prompt count).
pub fn prompts_since(w: &World, from: usize) -> usize {
    let t = w.transcript.lock().unwrap();
    t.entries
        .iter()
        .skip(from)
        .map(|(_, bytes)| {
            let text = String::from_utf8_lossy(bytes);
            text.matches("[y/N]").count() + text.matches("Type 'yes'").count()
        })
        .sum()
}

/// The transcript's length now (a mark for [`prompts_since`]).
pub fn transcript_mark(w: &World) -> usize {
    w.transcript.lock().unwrap().entries.len()
}

// ---- clients through the managed alias -----------------------------------------------------

/// The isolated client options for pair `i`'s managed alias (module docs), the alias not
/// included, and the client environment.
fn managed_client(w: &World, i: usize) -> (Vec<OsString>, Vec<(OsString, OsString)>) {
    let (_, mut args, env) = w.login_command(i, "unused");
    // `login_command` ends with `<alias>` and `echo <marker>`.
    args.truncate(args.len() - 2);
    for o in ["IdentitiesOnly=yes", "ControlMaster=no", "ControlPath=none"] {
        args.push("-o".into());
        args.push(o.into());
    }
    (args, env)
}

/// `ssh <alias> <command>` through pair `i`'s managed alias (module docs), bounded.
pub fn ssh(w: &World, i: usize, command: &str) -> Out {
    let (mut args, env) = managed_client(w, i);
    args.push(w.pairs[i].alias.clone().into());
    args.push(command.into());
    let out = run_bounded(
        Command::new(openssh("ssh"))
            .args(args)
            .env_clear()
            .envs(env)
            .current_dir(&w.home.root),
        Duration::from_secs(60),
    );
    w.record_bytes("m05 ssh (stdout)", out.stdout.as_bytes());
    w.record_bytes("m05 ssh (stderr)", out.stderr.as_bytes());
    out
}

/// `scp <alias>:<remote> <local>` through pair `i`'s managed alias, bounded.
pub fn scp_get(w: &World, i: usize, remote: &str, local: &Path) -> Out {
    let (mut args, env) = managed_client(w, i);
    args.push(format!("{}:{remote}", w.pairs[i].alias).into());
    args.push(local.as_os_str().to_owned());
    let out = run_bounded(
        Command::new(openssh("scp"))
            .args(args)
            .env_clear()
            .envs(env)
            .current_dir(&w.home.root),
        Duration::from_secs(60),
    );
    w.record_bytes("m05 scp (stdout)", out.stdout.as_bytes());
    w.record_bytes("m05 scp (stderr)", out.stderr.as_bytes());
    out
}

/// One word for `sh`, single-quoted.
fn sh_word(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The Git client: Unix the system's, Windows Git for Windows on `PATH`.
fn git_program() -> PathBuf {
    #[cfg(unix)]
    for dir in ["/usr/bin", "/bin"] {
        let p = Path::new(dir).join("git");
        if p.exists() {
            return p;
        }
    }
    heimdall_testkit::home::find_program("git")
        .unwrap_or_else(|| panic!("blocked: no git client on this host"))
}

/// `git <args>` whose remote is pair `i`'s managed alias (module docs), bounded.
pub fn git(w: &World, i: usize, args: &[&str]) -> Out {
    let (ssh_args, env) = managed_client(w, i);
    let mut words = vec![sh_word(&openssh("ssh").to_string_lossy())];
    words.extend(ssh_args.iter().map(|a| sh_word(&a.to_string_lossy())));
    let mut cmd = Command::new(git_program());
    cmd.args(args).current_dir(&w.home.root);
    let gitconfig = w.home.git_home.join(".gitconfig");
    if cfg!(windows) {
        // Git for Windows cannot read its configuration in a cleared environment (the W2
        // Windows fix of `heimdall_testkit::workspace`): the environment is inherited with
        // every Git, SSH and agent variable removed, and the login environment on top.
        for (k, _) in std::env::vars_os() {
            let upper = k.to_string_lossy().to_ascii_uppercase();
            if upper.starts_with("GIT_") || upper.starts_with("SSH_") {
                cmd.env_remove(k);
            }
        }
        cmd.env("USERPROFILE", &w.home.git_home)
            .env("XDG_CONFIG_HOME", w.home.git_home.join(".config"));
    } else {
        cmd.env_clear();
    }
    cmd.envs(env)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &gitconfig)
        .env("GIT_SSH_COMMAND", words.join(" "))
        .env("GIT_SSH_VARIANT", "ssh")
        .env("GIT_TERMINAL_PROMPT", "0");
    let out = run_bounded(&mut cmd, Duration::from_secs(90));
    w.record_bytes("m05 git (stdout)", out.stdout.as_bytes());
    w.record_bytes("m05 git (stderr)", out.stderr.as_bytes());
    out
}

/// A fresh server-side scratch directory for pair `i` (module docs), not yet created: a
/// login creates it.
pub fn remote_dir(w: &World, i: usize, tag: &str) -> String {
    let registry = w.pairs[i]
        .sshd
        .registry_remote_path()
        .expect("the server has an account-form registry")
        .to_owned();
    let parent = registry
        .rsplit_once('/')
        .map_or_else(|| ".".to_owned(), |(d, _)| d.to_owned());
    format!(
        "{parent}/hm-m05-{tag}-{}",
        heimdall_testkit::agent::random_hex(4)
    )
}

/// The remote command that writes `file` holding `marker` into `dir` and a bare Git
/// repository `dir/r.git` with one commit on `main`, then prints `<marker> <commit>`.
pub fn remote_seed(dir: &str, marker: &str) -> String {
    let d = sh_word(dir);
    let r = sh_word(&format!("{dir}/r.git"));
    let f = sh_word(&format!("{dir}/m05.txt"));
    let m = sh_word(marker);
    format!(
        "mkdir -p {d} && printf '%s\\n' {m} > {f} && HOME={d} GIT_CONFIG_NOSYSTEM=1 \
         GIT_CONFIG_GLOBAL=/dev/null && export HOME GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL && \
         git init -q --bare {r} && t=$(git --git-dir={r} mktree </dev/null) && \
         c=$(git --git-dir={r} -c user.name=hm -c user.email=hm@example.invalid \
         commit-tree \"$t\" -m m05) && git --git-dir={r} update-ref refs/heads/main \"$c\" && \
         echo {m} \"$c\""
    )
}

// ---- the shell hook and stand-in shells ----------------------------------------------------

/// A stand-in for an interactive shell (Unix): a process this test started that only waits,
/// so a hook's binding has a live holder (its PID and start time) that ends when this ends.
/// Stopped through its own handle on drop (never by name or PID lookup).
#[cfg(unix)]
pub struct StandIn {
    child: Child,
    pub pid: u32,
}

#[cfg(unix)]
impl StandIn {
    /// Start one (`/bin/sleep`, its streams closed).
    pub fn start() -> StandIn {
        let child = Command::new("/bin/sleep")
            .arg("3600")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a stand-in shell");
        let pid = child.id();
        println!("m05 started-pid stand-in-shell {pid}");
        StandIn { child, pid }
    }

    /// End it now (as the shell exiting).
    pub fn end(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
impl Drop for StandIn {
    fn drop(&mut self) {
        self.end();
    }
}

/// `activate --hook --cwd <cwd> --shell-pid <pid> --seq <seq> --json`, as the shell
/// integration runs it (stdin closed): the hook's data `{state, seq, recheck_s, work_id}`.
pub fn hook(w: &World, cwd: &Path, shell_pid: u32, seq: u64) -> Value {
    let pid = shell_pid.to_string();
    let seq = seq.to_string();
    let out = w.cli(&[
        "--json",
        "activate",
        "--hook",
        "--cwd",
        cwd.to_str().unwrap(),
        "--shell-pid",
        &pid,
        "--seq",
        &seq,
    ]);
    assert_eq!(
        out.code,
        0,
        "a hook never fails: {}",
        w.redact(&format!("{out:?}"))
    );
    out.json()["data"].clone()
}

/// [`hook`] until it answers `active` (a shell re-runs it at each prompt; the hook's own
/// budget is 1 s, and an activation it stopped waiting for still completes in the
/// runtime, ADR-0011 §10 item 7). The answer that said `active`.
pub fn hook_until_active(w: &World, cwd: &Path, shell_pid: u32, seq: u64) -> Value {
    let mut last = Value::Null;
    wait_for("the hook answers active", Duration::from_secs(60), || {
        last = hook(w, cwd, shell_pid, seq);
        assert!(
            matches!(last["state"].as_str(), Some("active" | "unavailable")),
            "the hook: {last}"
        );
        (last["state"] == "active").then(|| last.clone())
    })
}

// ---- the runtime --------------------------------------------------------------------------

/// Stop `w`'s runtime by its **exact PID** (a crash, no shutdown): the PID the runtime
/// advertises in this world's own scratch home, checked alive and with an unchanged start
/// time right before the kill; then wait (bounded) until it is gone. Returns the PID and
/// its issuer child's, as found before the kill.
pub fn kill_runtime(w: &World) -> (u32, Option<u32>) {
    let pid = w.runtime_pid();
    let started =
        heimdall_runtime::platform::process_start_time(pid).expect("the runtime's start time");
    let issuer = crate::procs::issuer_child(pid);
    // Re-checked right before the signal: the same process, still this world's runtime.
    assert_eq!(
        heimdall_runtime::platform::process_start_time(pid).as_deref(),
        Some(started.as_str()),
        "the advertised runtime is the one this world started"
    );
    #[cfg(unix)]
    let status = Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .status();
    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status();
    assert!(status.is_ok_and(|s| s.success()), "the kill was delivered");
    wait_for(
        "the killed runtime is gone",
        Duration::from_secs(30),
        || (!crate::procs::alive(pid)).then_some(()),
    );
    (pid, issuer)
}

/// After [`kill_runtime`]: wait (bounded) for the old issuer child to end, then stop it by
/// its exact PID if it did not (it is this world's runtime's child: a process this test
/// started). Whether it ended by itself.
pub fn old_issuer_ended(issuer: Option<u32>) -> bool {
    let Some(pid) = issuer else { return true };
    let started = heimdall_runtime::platform::process_start_time(pid);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if !crate::procs::alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if started.is_some() && heimdall_runtime::platform::process_start_time(pid) == started {
        #[cfg(unix)]
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        #[cfg(windows)]
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status();
    }
    false
}

// ---- servers ------------------------------------------------------------------------------

/// One server in `scratch` with an (empty) account-form registry: on Windows the harness's
/// WSL sshd (`HM_FIXTURE_SSHD_*`), a test fails naming it when it is missing.
pub fn server(scratch: &heimdall_testkit::home::Scratch) -> heimdall_testkit::sshd::LoopbackSshd {
    heimdall_testkit::sshd::LoopbackSshd::start(
        scratch,
        heimdall_testkit::sshd::SshdConfig {
            registry_seed: Some(Vec::new()),
            ..heimdall_testkit::sshd::SshdConfig::default()
        },
    )
    .unwrap_or_else(|e| panic!("blocked: a fixture sshd: {e}"))
}

/// A **second, distinct** server with its own registry: on Unix another loopback `sshd`;
/// on Windows the harness's strict WSL sshd (`HM_FIXTURE_SSHD_STRICT_*`, the only second
/// server the Windows harness serves; it runs `MaxAuthTries 3`), its authorized-keys file
/// as the registry.
pub fn second_server(
    scratch: &heimdall_testkit::home::Scratch,
) -> heimdall_testkit::sshd::LoopbackSshd {
    let config = heimdall_testkit::sshd::SshdConfig {
        registry_seed: Some(Vec::new()),
        max_auth_tries: if cfg!(windows) {
            heimdall_testkit::sshd::STRICT_MAX_AUTH_TRIES
        } else {
            heimdall_testkit::sshd::SshdConfig::default().max_auth_tries
        },
        ..heimdall_testkit::sshd::SshdConfig::default()
    };
    heimdall_testkit::sshd::LoopbackSshd::start(scratch, config).unwrap_or_else(|e| {
        panic!("blocked: a second fixture sshd (Windows: HM_FIXTURE_SSHD_STRICT_*): {e}")
    })
}
