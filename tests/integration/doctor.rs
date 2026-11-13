//! The passive doctor and the explicit probe ladder (m02-plan U3 "Tests (A21)";
//! ADR-0007 §6, §9, F19).
//!
//! Cargo test target `integration_doctor` hosted by `heimdall-localenv` (review F09
//! convention). Fixtures are disposable and in scratch only (m02-plan §0):
//!
//! * `ScratchHome` (U7): the scratch home, its `.ssh/config` (the configuration under
//!   test, passed to every client as `-F`), its known-hosts files and the decoy
//!   counting agent at `SSH_AUTH_SOCK`. Product code gets the paths through
//!   `SshPaths::with_test_override` and the isolation arguments through
//!   `LocalContext::client_isolation` (the env-gated test configuration's role);
//! * the fixture hook `hm-fixture-hook` (U7) behind every `Match exec` canary, run by
//!   `/bin/sh` on Unix and `cmd /c` on Windows, in each mode: `connect` to a
//!   loopback counter this test owns, `agent-list` on a `FakeAgent`, `touch`, `escape`
//!   (an escaped child killed by its exact PID) and `revert`;
//! * an `ssh` wrapper script in scratch, configured as `[clients] ssh`, that appends
//!   one line to a scratch log for every start other than `-V` and then runs the real
//!   client: "no ssh child started" is an empty log;
//! * `FakeAgent` and `LoopbackSshd` (U7) for the agent, host-verification and
//!   authentication levels; every identity is a per-run scratch key.
//!
//! Nothing here reads the owner's `~/.ssh`, agents, keys or Git configuration: the
//! child environment is exactly the snapshot each test builds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_contract::code::Code;
use heimdall_contract::doctor::{
    AliasDefinition, Containment, DoctorReport, ExcludedEffect, ProbeOutcome, ProbeRecord,
    TreeChange, decline_reason, finding,
};
use heimdall_contract::provider::{IdentitySelection, InteractionKind, ProbeLevel};
use heimdall_localenv::agents::EndpointLocator;
use heimdall_localenv::clients::ClientsConfig;
use heimdall_localenv::doctor::{
    CatalogAlias, CatalogIdentity, DoctorRequest, INVENTORY_WORDING, LocalContext, run,
};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::probe::{self, ProbeContext, ProbeHook, ProbePoint, all_effects};
use heimdall_sshconf::limits::Limits;
use heimdall_testkit::agent::{
    AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey, StallPoint, msg,
};
use heimdall_testkit::home::{ScratchHome, find_program, ssh_config_quote};
use heimdall_testkit::hook::{HookBinary, HookMode};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

// --- fixtures ------------------------------------------------------------------------------

/// One scratch environment for the doctor.
struct Fx {
    home: ScratchHome,
    hook: HookBinary,
    /// Canonical scratch root.
    root: PathBuf,
    /// The `ssh` wrapper and its start log.
    wrapper: PathBuf,
    starts: PathBuf,
    real_ssh: PathBuf,
}

impl Fx {
    fn new() -> Fx {
        let home = ScratchHome::new();
        let hook = HookBinary::locate().expect(
            "hm-fixture-hook is not built: run `cargo build -p heimdall-testkit --bin hm-fixture-hook`",
        );
        #[cfg(unix)]
        let root = std::fs::canonicalize(&home.root).unwrap();
        #[cfg(windows)]
        let root = home.root.clone();
        let real_ssh = find_program("ssh").expect("ssh on PATH");
        let starts = root.join("ssh-starts.log");
        #[cfg(unix)]
        let wrapper = root.join("bin").join("ssh");
        #[cfg(windows)]
        let wrapper = root.join("bin").join("ssh.cmd");
        create_dir_owner_only(wrapper.parent().unwrap()).unwrap();
        #[cfg(unix)]
        write_owner_only(
            &wrapper,
            format!(
                "#!/bin/sh\ncase \"$1\" in -V) ;; *) echo run >> '{}' ;; esac\nexec '{}' \"$@\"\n",
                starts.display(),
                real_ssh.display()
            ),
        )
        .unwrap();
        #[cfg(windows)]
        write_owner_only(&wrapper, format!(
            "@echo off\r\nif not \"%~1\"==\"-V\" echo run>>\"{}\"\r\n\"{}\" %*\r\nexit /b %errorlevel%\r\n",
            starts.display(), real_ssh.display())).unwrap();
        make_executable(&wrapper);
        #[cfg(windows)]
        create_dir_owner_only(root.join("program-data")).unwrap();
        Fx {
            home,
            hook,
            root,
            wrapper,
            starts,
            real_ssh,
        }
    }

    fn paths(&self) -> SshPaths {
        SshPaths::with_test_override(self.home.git_home.clone(), self.root.join("etc-ssh"))
    }

    fn env(&self) -> Env {
        #[cfg(unix)]
        let env = Env::from_vars([
            ("PATH", OsString::from("/usr/bin:/bin")),
            ("HOME", self.home.git_home.clone().into_os_string()),
            ("SHELL", OsString::from("/bin/sh")),
            (
                "SSH_AUTH_SOCK",
                self.home.decoy_agent().endpoint().locator(),
            ),
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            (
                "GIT_CONFIG_GLOBAL",
                self.home.git_home.join(".gitconfig").into_os_string(),
            ),
        ]);
        #[cfg(windows)]
        let env = {
            let system = std::env::var_os("SystemRoot").expect("SystemRoot");
            let data = self.root.join("program-data");
            create_dir_owner_only(&data).unwrap();
            Env::from_vars([
                ("PATH", std::env::var_os("PATH").expect("PATH")),
                ("SystemRoot", system.clone()),
                ("WINDIR", system.clone()),
                (
                    "COMSPEC",
                    PathBuf::from(system)
                        .join("System32")
                        .join("cmd.exe")
                        .into_os_string(),
                ),
                ("ProgramData", data.into_os_string()),
                ("USERPROFILE", self.home.git_home.clone().into_os_string()),
                ("HOME", self.home.git_home.clone().into_os_string()),
                ("TEMP", self.root.clone().into_os_string()),
                ("TMP", self.root.clone().into_os_string()),
                (
                    "SSH_AUTH_SOCK",
                    self.home.decoy_agent().endpoint().locator(),
                ),
                ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
                (
                    "GIT_CONFIG_GLOBAL",
                    self.home.git_home.join(".gitconfig").into_os_string(),
                ),
            ])
        };
        env
    }

    fn ctx(&self) -> LocalContext {
        let mut ctx = LocalContext::new(
            self.paths(),
            self.env(),
            Platform::current(),
            ClientsConfig {
                ssh: Some(self.wrapper.clone()),
                ..ClientsConfig::default()
            },
            Limits::default(),
        );
        ctx.client_isolation = Some(self.home.isolation_args());
        ctx
    }

    fn config(&self, text: &str) {
        self.home.write_user_config(text).unwrap();
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Whether the wrapper started `ssh` for anything other than `-V`.
    fn ssh_started(&self) -> bool {
        std::fs::read_to_string(&self.starts).is_ok_and(|t| !t.is_empty())
    }

    fn exec_line(&self, mode: &HookMode) -> String {
        #[cfg(unix)]
        {
            self.hook.match_exec_line(mode)
        }
        #[cfg(windows)]
        {
            // cmd.exe needs ordinary short executable paths. Match exec
            // parses backslashes again, so use the observed slash pipe form.
            let command = self
                .hook
                .shell_command(mode)
                .replace(r"\\?\", "")
                .replace(r"\\.\pipe\", "//./pipe/");
            format!(
                "Match exec {}",
                ssh_config_quote(&command.replace('%', "%%"))
            )
        }
    }
}

/// The fixtures' files are owner-only, whatever the process umask (the devbox's is 002):
/// `ssh` refuses a configuration file, or an included one, that is group- or
/// world-writable ("Bad owner or permissions"), so a plain `fs::write` under umask 002 made
/// `ssh -G` fail and four tests fail with it (M03 wave 5, round 4, F1 follow-up).
fn write_owner_only(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// `create_dir_all`, with every directory it creates made owner-only (see
/// [`write_owner_only`]; `ssh` also checks the directories above an included file).
fn create_dir_owner_only(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    let mut created = Vec::new();
    let mut p = Some(path);
    while let Some(d) = p {
        if d.exists() {
            break;
        }
        created.push(d.to_path_buf());
        p = d.parent();
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    for d in &created {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = created;
    Ok(())
}

#[cfg(unix)]
fn make_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_p: &Path) {}

fn qp(p: &Path) -> String {
    let text = p.to_string_lossy();
    if text.starts_with(r"\\.\pipe\") {
        return ssh_config_quote(&text);
    }
    ssh_config_quote(&shown_path(p))
}

fn shown_path(p: &Path) -> String {
    let text = p.to_string_lossy().into_owned();
    #[cfg(windows)]
    let text = text
        .strip_prefix(r"\\?\")
        .unwrap_or(&text)
        .replace('\\', "/");
    text
}

fn endpoint_locator(endpoint: &Endpoint) -> EndpointLocator {
    match endpoint {
        Endpoint::UnixSocket(p) => EndpointLocator::UnixSocket(p.clone()),
        Endpoint::NamedPipe(n) => EndpointLocator::NamedPipe(n.clone()),
    }
}

fn link_dir(real: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(real, link).unwrap();
    #[cfg(windows)]
    {
        let out = Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/c", "mklink", "/J"])
            .arg(shown_path(link).replace('/', r"\"))
            .arg(shown_path(real).replace('/', r"\"))
            .output()
            .unwrap();
        assert!(out.status.success(), "scratch junction creation failed");
    }
}

fn request(levels: &[ProbeLevel], allow: bool, aliases: &[&str]) -> DoctorRequest {
    let mut set: BTreeSet<ProbeLevel> = levels.iter().copied().collect();
    set.insert(ProbeLevel::Static);
    DoctorRequest {
        levels: set,
        allow_config_commands: allow,
        aliases: Some(aliases.iter().map(|a| (*a).to_owned()).collect()),
        interactive: false,
        local_queries: LocalQueries::Enabled,
        redact: false,
    }
}

fn probe_of(report: &DoctorReport, level: ProbeLevel) -> Vec<&ProbeRecord> {
    report.probes.iter().filter(|p| p.level == level).collect()
}

fn static_record(report: &DoctorReport) -> &ProbeRecord {
    probe_of(report, ProbeLevel::Static)[0]
}

/// A loopback TCP counter: accepts, counts, closes at once.
struct Counter {
    port: u16,
    accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Counter {
    fn start() -> Counter {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, s) = (Arc::clone(&accepts), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        a.fetch_add(1, Ordering::SeqCst);
                        drop(conn);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Counter {
            port,
            accepts,
            stop,
            thread: Some(thread),
        }
    }

    fn count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for Counter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A digest of every directory name and regular file's bytes under `root`, sorted
/// (sockets and FIFOs by name only).
fn tree_digest(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let t = e.file_type().unwrap();
            if t.is_dir() {
                out.push((format!("{rel}/"), Vec::new()));
                stack.push(p);
            } else if t.is_file() {
                out.push((rel, std::fs::read(&p).unwrap_or_default()));
            } else {
                out.push((format!("{rel}@"), Vec::new()));
            }
        }
    }
    out.sort();
    out
}

/// The hook's canaries: one per mode that would show an effect.
struct Canaries {
    counter: Counter,
    agent: FakeAgent,
    touched: PathBuf,
    pidfile: PathBuf,
    lines: Vec<String>,
}

impl Canaries {
    fn new(fx: &Fx) -> Canaries {
        let counter = Counter::start();
        let agent = FakeAgent::start(
            Endpoint::in_scratch(fx.home.scratch(), "hooked").unwrap(),
            FakeAgentConfig {
                keys: vec![FixtureKey::generate()],
                mode: AgentMode::Normal,
            },
        );
        let touched = fx.path("touched");
        let pidfile = fx.path("escaped.pid");
        let lines = vec![
            fx.exec_line(&HookMode::Connect { port: counter.port }),
            fx.exec_line(&HookMode::AgentList {
                endpoint: agent.endpoint().clone(),
            }),
            fx.exec_line(&HookMode::Touch {
                path: touched.clone(),
            }),
            fx.exec_line(&HookMode::Escape {
                pidfile: pidfile.clone(),
            }),
        ];
        Canaries {
            counter,
            agent,
            touched,
            pidfile,
            lines,
        }
    }

    /// The configuration text: the alias first, then one `Match exec` per canary.
    /// Returns the text and the 1-based lines of the `Match exec` lines.
    fn config(&self, alias_block: &str) -> (String, Vec<u32>) {
        let mut text = alias_block.to_owned();
        let mut lines = Vec::new();
        for l in &self.lines {
            lines.push(u32::try_from(text.lines().count() + 1).unwrap());
            text.push_str(l);
            text.push('\n');
        }
        (text, lines)
    }

    fn kill_escaped(&self) -> bool {
        let Ok(text) = std::fs::read_to_string(&self.pidfile) else {
            return false;
        };
        #[cfg(windows)]
        {
            let pid: u32 = text.lines().next().unwrap().parse().unwrap();
            // This PID was published by our hook in this fixture's private directory.
            // Open and retain its process handle, then verify its executable and start
            // time before stopping it. Never stop a process with a reused identity.
            let script = r"$p=Get-Process -Id $args[0] -ErrorAction SilentlyContinue;
                if ($null -eq $p) { exit 0 }; $null=$p.Handle;
                $f=Get-Item -LiteralPath $args[1];
                if ($p.Path -ne $args[2] -or $p.StartTime.ToUniversalTime() -lt $f.LastWriteTimeUtc.AddSeconds(-30)) { exit 20 };
                if ($p.HasExited) { exit 0 }; $p.Kill(); $p.WaitForExit(); exit 10";
            let script_path = self.pidfile.with_extension("verify.ps1");
            write_owner_only(&script_path, script).unwrap();
            let out = Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-File"])
                .arg(&script_path)
                .arg(pid.to_string())
                .arg(&self.pidfile)
                .arg(HookBinary::locate().unwrap().path())
                .output()
                .unwrap();
            assert!(
                matches!(out.status.code(), Some(0 | 10)),
                "escaped fixture identity could not be verified"
            );
            out.status.code() == Some(10)
        }
        #[cfg(unix)]
        let pid = text.lines().next().unwrap().trim().to_owned();
        #[cfg(unix)]
        let alive = Command::new("/bin/kill")
            .args(["-0", &pid])
            .status()
            .unwrap()
            .success();
        // The escaped child is killed by its exact PID, never by name.
        #[cfg(unix)]
        let _ = Command::new("/bin/kill").args(["-9", &pid]).status();
        #[cfg(unix)]
        {
            alive
        }
    }
}

const ALIAS: &str = "hm-a21";

fn alias_block(port: u16, key: &Path) -> String {
    format!(
        "Host {ALIAS}\n  HostName 127.0.0.1\n  Port {port}\n  IdentityFile {}\n  IdentitiesOnly yes\n",
        qp(key)
    )
}

// --- the default doctor --------------------------------------------------------------------

#[test]
fn a21_default_doctor_runs_no_exec_no_agent_no_network_no_mutation() {
    let fx = Fx::new();
    let c = Canaries::new(&fx);
    let (text, exec_lines) = c.config(&alias_block(9, &fx.path("id_unused.pub")));
    fx.config(&text);
    let before = tree_digest(&fx.root);
    let report = run(&fx.ctx(), &DoctorRequest::passive());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(c.counter.count(), 0, "a network canary fired");
    assert_eq!(c.agent.contact_count(), 0, "an agent canary fired");
    assert_eq!(
        fx.home.decoy_agent().contact_count(),
        0,
        "the decoy agent was contacted"
    );
    assert!(!c.touched.exists(), "a file canary fired");
    assert!(!c.pidfile.exists(), "an escape canary fired");
    assert!(!fx.ssh_started(), "an ssh child was started");
    assert_eq!(tree_digest(&fx.root), before, "the scratch tree changed");
    assert_eq!(
        report.levels_performed,
        BTreeSet::from([ProbeLevel::Static])
    );
    assert!(report.levels_declined.is_empty());
    let st = static_record(&report);
    assert_eq!(st.outcome, ProbeOutcome::Ok);
    assert_eq!(
        st.effects_excluded,
        all_effects(),
        "effects_excluded is not complete"
    );
    assert!(st.executed_config_commands.is_empty());
    assert!(st.config_tree_changed.is_none());
    // Local queries ran (ssh -V, git), contained.
    assert_eq!(
        st.containment,
        if cfg!(windows) {
            Containment::JobObject
        } else {
            Containment::ProcessGroup
        }
    );
    let dynamic: Vec<u32> = report
        .findings
        .iter()
        .filter(|f| f.code == finding::DYNAMIC_MATCH_UNRESOLVED)
        .map(|f| {
            let p = f.provenance.as_ref().unwrap();
            assert!(p.path_display.ends_with("config"), "{}", p.path_display);
            p.line
        })
        .collect();
    assert_eq!(dynamic, exec_lines, "dynamic_match_unresolved file:line");
    assert!(report.aliases.iter().any(|a| a.alias == ALIAS));
}

#[test]
fn a21_evaluate_declined_without_allow_config_commands() {
    let fx = Fx::new();
    let c = Canaries::new(&fx);
    let (text, _) = c.config(&alias_block(9, &fx.path("id.pub")));
    fx.config(&text);
    let report = run(
        &fx.ctx(),
        &request(&[ProbeLevel::Evaluate], false, &[ALIAS]),
    );
    let r = probe_of(&report, ProbeLevel::Evaluate);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].outcome, ProbeOutcome::Declined);
    assert_eq!(
        r[0].decline_reason.as_deref(),
        Some(decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED)
    );
    assert_eq!(r[0].effects_excluded, all_effects());
    assert!(report.levels_declined.contains(&ProbeLevel::Evaluate));
    assert!(!report.levels_performed.contains(&ProbeLevel::Evaluate));
    assert!(!fx.ssh_started());
    assert!(!c.touched.exists());
    assert_eq!(c.counter.count() + c.agent.contact_count(), 0);
}

#[test]
fn a21_inert_config_still_requires_allow_config_commands() {
    let fx = Fx::new();
    fx.config(&alias_block(9, &fx.path("id.pub")));
    let hook = Arc::new(Recorder::default());
    let mut ctx = fx.ctx();
    ctx.probe_hook = Some(hook.clone());
    let levels = [
        ProbeLevel::Evaluate,
        ProbeLevel::HostVerification,
        ProbeLevel::Authentication,
    ];
    let report = run(&ctx, &request(&levels, false, &[ALIAS]));
    for level in levels {
        let r = probe_of(&report, level);
        assert_eq!(r.len(), 1, "{level:?}");
        assert!(
            r[0].executed_config_commands.is_empty(),
            "the static pass found nothing"
        );
        assert_eq!(r[0].outcome, ProbeOutcome::Declined, "{level:?}");
        assert_eq!(
            r[0].decline_reason.as_deref(),
            Some(decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED)
        );
    }
    assert!(
        hook.points().is_empty(),
        "the level reached the point before the ssh child"
    );
    assert!(!fx.ssh_started(), "an ssh child was started");
}

/// Records the hook points reached; optionally runs an action at the first one.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<(ProbePoint, ProbeLevel)>>,
    action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Recorder {
    fn with(action: impl FnOnce() + Send + 'static) -> Recorder {
        Recorder {
            seen: Mutex::new(Vec::new()),
            action: Mutex::new(Some(Box::new(action))),
        }
    }

    fn points(&self) -> Vec<(ProbePoint, ProbeLevel)> {
        self.seen.lock().unwrap().clone()
    }
}

impl ProbeHook for Recorder {
    fn at(&self, point: ProbePoint, level: ProbeLevel) {
        self.seen.lock().unwrap().push((point, level));
        if let Some(a) = self.action.lock().unwrap().take() {
            a();
        }
    }
}

fn evaluate_with_hook(
    fx: &Fx,
    allow: bool,
    action: impl FnOnce() + Send + 'static,
) -> (ProbeRecord, Arc<Recorder>) {
    let hook = Arc::new(Recorder::with(action));
    let mut ctx = fx.ctx();
    ctx.probe_hook = Some(hook.clone());
    let pctx = ProbeContext::new(&ctx, allow, false);
    (probe::evaluate::ssh_g(&pctx, ALIAS), hook)
}

#[test]
fn a21_match_exec_inserted_after_static_pass_never_runs_unauthorized() {
    let fx = Fx::new();
    let inc = fx.path("conf.d/inc.conf");
    create_dir_owner_only(inc.parent().unwrap()).unwrap();
    write_owner_only(&inc, "# included, inert\n").unwrap();
    fx.config(&format!(
        "Include {}\n{}",
        qp(&inc),
        alias_block(9, &fx.path("id.pub"))
    ));
    let touched = fx.path("inserted-ran");
    let line = format!(
        "{}\n",
        fx.exec_line(&HookMode::Touch {
            path: touched.clone()
        })
    );
    let insert = {
        let (inc, line) = (inc.clone(), line.clone());
        move || {
            let mut f = std::fs::OpenOptions::new().append(true).open(&inc).unwrap();
            f.write_all(line.as_bytes()).unwrap();
        }
    };
    // Without the flag: declined before the hook point; nothing ran.
    let (r, hook) = evaluate_with_hook(&fx, false, insert.clone());
    assert_eq!(r.outcome, ProbeOutcome::Declined);
    assert_eq!(
        r.decline_reason.as_deref(),
        Some(decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED)
    );
    assert!(hook.points().is_empty());
    assert!(!touched.exists());
    assert!(!fx.ssh_started());
    // With the flag: the inserted line runs, the tree is reported changed, and the
    // record lists only what the static pass found (nothing).
    let (r, hook) = evaluate_with_hook(&fx, true, insert);
    assert_eq!(
        hook.points(),
        vec![(ProbePoint::AfterStaticPass, ProbeLevel::Evaluate)]
    );
    assert!(fx.ssh_started());
    assert!(touched.exists(), "the inserted Match exec did not run");
    assert_eq!(
        r.authorization,
        vec![probe::ALLOW_CONFIG_COMMANDS.to_owned()]
    );
    assert_eq!(r.config_tree_changed, Some(true));
    assert!(r.effects_excluded.is_empty());
    assert!(
        r.executed_config_commands.is_empty(),
        "the inserted line was claimed"
    );
    assert!(
        r.config_tree_differences
            .iter()
            .any(|d| d.path_display.ends_with("inc.conf") && d.change == TreeChange::Modified),
        "{:?}",
        r.config_tree_differences
    );
}

#[test]
fn a21_new_glob_member_after_static_pass_is_reported_and_never_listed() {
    let fx = Fx::new();
    let dir = fx.path("conf.d");
    create_dir_owner_only(&dir).unwrap();
    write_owner_only(dir.join("10-first.conf"), "# inert member\n").unwrap();
    fx.config(&format!(
        "Include {}/*.conf\n{}",
        shown_path(&dir),
        alias_block(9, &fx.path("id.pub"))
    ));
    let touched = fx.path("new-member-ran");
    let line = format!(
        "{}\n",
        fx.exec_line(&HookMode::Touch {
            path: touched.clone()
        })
    );
    let member = dir.join("50-new.conf");
    // The static pass's own reads, for the control.
    let read_before: Vec<(PathBuf, Vec<u8>)> = vec![
        (
            fx.home.user_config.clone(),
            std::fs::read(&fx.home.user_config).unwrap(),
        ),
        (
            dir.join("10-first.conf"),
            std::fs::read(dir.join("10-first.conf")).unwrap(),
        ),
    ];
    let (r, _) = evaluate_with_hook(&fx, true, move || {
        write_owner_only(&member, line).unwrap();
    });
    assert!(touched.exists(), "the new member's Match exec did not run");
    assert_eq!(r.config_tree_changed, Some(true));
    assert!(r.executed_config_commands.is_empty());
    let added: Vec<_> = r
        .config_tree_differences
        .iter()
        .filter(|d| d.change == TreeChange::Added)
        .collect();
    assert_eq!(added.len(), 1, "{:?}", r.config_tree_differences);
    assert!(added[0].path_display.ends_with("50-new.conf"));
    // Control: comparing only the files the static pass read (revision 3's method)
    // finds no difference, so the re-walked glob is what detected the new file.
    for (p, bytes) in read_before {
        assert_eq!(
            std::fs::read(&p).unwrap(),
            bytes,
            "a file the static pass read changed"
        );
    }
}

#[test]
fn a21_change_then_revert_is_undetected_and_inventory_never_complete() {
    let fx = Fx::new();
    let inc = fx.path("conf.d/inc.conf");
    create_dir_owner_only(inc.parent().unwrap()).unwrap();
    let original_bytes = b"# included, inert\n".to_vec();
    write_owner_only(&inc, &original_bytes).unwrap();
    let original = fx.path("inc.original");
    write_owner_only(&original, &original_bytes).unwrap();
    fx.config(&format!(
        "Include {}\n{}",
        qp(&inc),
        alias_block(9, &fx.path("id.pub"))
    ));
    let marker = fx.path("reverted");
    #[cfg(unix)]
    let line = format!(
        "{}\n",
        fx.exec_line(&HookMode::Revert {
            path: inc.clone(),
            original: original.clone(),
            marker: marker.clone(),
        })
    );
    #[cfg(windows)]
    let command_marker = fx.path("transient-command-ran");
    #[cfg(windows)]
    let line = {
        // Native OpenSSH keeps the Include open without delete sharing. Its
        // wrapper restores the bytes after ssh closes the file, before the
        // probe takes its second snapshot. A separate marker proves the
        // inserted Match exec ran while the transient bytes were present.
        let restore = fx.hook.shell_command(&HookMode::Revert {
            path: inc.clone(),
            original: original.clone(),
            marker: marker.clone(),
        });
        let wrapper = std::fs::read_to_string(&fx.wrapper).unwrap().replace(
            "exit /b %errorlevel%",
            &format!("set \"ssh_exit=%errorlevel%\"\r\n{restore}\r\nif errorlevel 1 exit /b 1\r\nexit /b %ssh_exit%"));
        write_owner_only(&fx.wrapper, wrapper).unwrap();
        format!(
            "{}\n",
            fx.exec_line(&HookMode::Touch {
                path: command_marker.clone()
            })
        )
    };
    let target = inc.clone();
    let (r, _) = evaluate_with_hook(&fx, true, move || {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&target)
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();
    });
    assert!(marker.exists(), "the inserted command did not run");
    #[cfg(windows)]
    assert!(
        command_marker.exists(),
        "the transient Match exec did not run"
    );
    assert_eq!(std::fs::read(&inc).unwrap(), original_bytes);
    // Both snapshots are equal: the change is undetected, and the record says only
    // that the snapshots are equal.
    assert_eq!(r.config_tree_changed, Some(false));
    assert!(r.config_tree_differences.is_empty());
    assert!(
        r.executed_config_commands.is_empty(),
        "the inserted line was claimed"
    );
    assert!(r.effects_excluded.is_empty());
    // The inventory is never described as complete.
    assert!(INVENTORY_WORDING.contains("found before the run"));
    assert!(INVENTORY_WORDING.contains("may have executed others"));
    assert!(!INVENTORY_WORDING.contains("complete"));
}

#[test]
fn a21_unreadable_include_declines_even_with_authorization() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let fx = Fx::new();
    let locked = fx.path("locked.conf");
    write_owner_only(&locked, "Host x\n").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    #[cfg(windows)]
    let denied = heimdall_testkit::win::deny_read(&locked).unwrap();
    fx.config(&format!(
        "Include {}\n{}",
        qp(&locked),
        alias_block(9, &fx.path("id.pub"))
    ));
    for allow in [false, true] {
        let report = run(
            &fx.ctx(),
            &request(&[ProbeLevel::Evaluate], allow, &[ALIAS]),
        );
        let r = probe_of(&report, ProbeLevel::Evaluate);
        assert_eq!(r[0].outcome, ProbeOutcome::Declined);
        assert_eq!(
            r[0].decline_reason.as_deref(),
            Some(decline_reason::CONFIG_NOT_FULLY_READABLE),
            "allow={allow}"
        );
    }
    #[cfg(unix)]
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
    #[cfg(windows)]
    denied.restore().unwrap();
    // An Include chain beyond the depth bound (a root is depth 0; 17 is refused).
    let mut prev = fx.path("deep-17.conf");
    write_owner_only(&prev, "Host deep\n").unwrap();
    for i in (1..17).rev() {
        let p = fx.path(&format!("deep-{i}.conf"));
        write_owner_only(&p, format!("Include {}\n", qp(&prev))).unwrap();
        prev = p;
    }
    fx.config(&format!(
        "Include {}\n{}",
        qp(&prev),
        alias_block(9, &fx.path("id.pub"))
    ));
    for allow in [false, true] {
        let report = run(
            &fx.ctx(),
            &request(&[ProbeLevel::Evaluate], allow, &[ALIAS]),
        );
        let r = probe_of(&report, ProbeLevel::Evaluate);
        assert_eq!(
            r[0].decline_reason.as_deref(),
            Some(decline_reason::CONFIG_NOT_FULLY_READABLE),
            "depth, allow={allow}"
        );
    }
    assert!(!fx.ssh_started());
}

#[test]
fn a21_evaluate_authorized_runs_hooks_and_claims_no_exclusion() {
    let fx = Fx::new();
    let c = Canaries::new(&fx);
    let (text, exec_lines) = c.config(&alias_block(9, &fx.path("id.pub")));
    fx.config(&text);
    let ctx = fx.ctx();
    let pctx = ProbeContext::new(&ctx, true, false);
    let r = probe::evaluate::ssh_g(&pctx, ALIAS);
    std::thread::sleep(Duration::from_millis(200));
    let escaped_alive = c.kill_escaped();
    assert_eq!(r.outcome, ProbeOutcome::Ok, "{r:?}");
    assert_eq!(c.counter.count(), 1, "one accept on the loopback counter");
    assert!(
        c.agent
            .log()
            .iter()
            .any(|m| m.msg_type == msg::REQUEST_IDENTITIES),
        "one agent listing"
    );
    assert!(c.touched.exists());
    #[cfg(unix)]
    assert!(escaped_alive, "the setsid child did not outlive the probe");
    #[cfg(windows)]
    {
        assert!(c.pidfile.exists(), "the escape hook did not start a child");
        assert!(
            std::fs::read_to_string(&c.pidfile).unwrap().lines().nth(1) == Some("in_job"),
            "breakaway was not refused"
        );
        assert!(!escaped_alive, "the hook child survived job closure");
    }
    let lines: Vec<u32> = r.executed_config_commands.iter().map(|p| p.line).collect();
    assert_eq!(lines, exec_lines, "every hook's file:line");
    assert!(r.effects_excluded.is_empty());
    assert_eq!(
        r.containment,
        if cfg!(windows) {
            Containment::JobObject
        } else {
            Containment::ProcessGroup
        }
    );
    assert_eq!(r.config_tree_changed, Some(false));
}

#[test]
fn a21_hanging_match_exec_killed_with_group_at_timeout() {
    let fx = Fx::new();
    let late = fx.path("late-marker");
    #[cfg(unix)]
    let command = format!("sleep 3; touch '{}'", late.display());
    #[cfg(windows)]
    let command = format!(
        "ping -n 4 127.0.0.1 >nul & {}",
        fx.hook
            .shell_command(&HookMode::Touch { path: late.clone() })
    );
    fx.config(&format!(
        "{}Match exec {}\n",
        alias_block(9, &fx.path("id.pub")),
        ssh_config_quote(&command)
    ));
    let ctx = fx.ctx();
    let mut pctx = ProbeContext::new(&ctx, true, false);
    pctx.timeout = Duration::from_secs(1);
    let started = Instant::now();
    let r = probe::evaluate::ssh_g(&pctx, ALIAS);
    assert_eq!(r.outcome, ProbeOutcome::Timeout);
    #[cfg(windows)]
    assert_eq!(r.containment, Containment::JobObject);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    std::thread::sleep(Duration::from_millis(3500));
    assert!(
        !late.exists(),
        "the Match exec's shell survived the group kill"
    );
}

// --- agent and network levels ---------------------------------------------------------------

#[test]
fn a21_agent_level_sends_only_request_identities() {
    let fx = Fx::new();
    let agent = FakeAgent::start(
        Endpoint::in_scratch(fx.home.scratch(), "listed").unwrap(),
        FakeAgentConfig {
            keys: vec![FixtureKey::generate()],
            mode: AgentMode::Normal,
        },
    );
    let ctx = fx.ctx();
    let pctx = ProbeContext::new(&ctx, false, false);
    let locator = match agent.endpoint() {
        Endpoint::UnixSocket(p) => EndpointLocator::UnixSocket(p.clone()),
        Endpoint::NamedPipe(n) => EndpointLocator::NamedPipe(n.clone()),
    };
    let (r, listing) = probe::agent::list_identities_observed(&pctx, &locator);
    assert_eq!(r.outcome, ProbeOutcome::Ok, "{r:?}");
    assert_eq!(listing.unwrap().identities.len(), 1);
    let log = agent.log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].msg_type, msg::REQUEST_IDENTITIES);
    assert_eq!(
        r.effects_excluded,
        [
            ExcludedEffect::ConfigExecution,
            ExcludedEffect::Network,
            ExcludedEffect::Signing,
            ExcludedEffect::Mutation
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(r.containment, Containment::None);
    assert_eq!(fx.home.decoy_agent().contact_count(), 0);
}

#[test]
fn a21_agent_that_never_replies_times_out() {
    let fx = Fx::new();
    let agent = FakeAgent::start(
        Endpoint::in_scratch(fx.home.scratch(), "stall").unwrap(),
        FakeAgentConfig {
            keys: vec![FixtureKey::generate()],
            mode: AgentMode::Stall(StallPoint::BeforeReply),
        },
    );
    let ctx = fx.ctx();
    let pctx = ProbeContext::new(&ctx, false, false);
    let locator = match agent.endpoint() {
        Endpoint::UnixSocket(p) => EndpointLocator::UnixSocket(p.clone()),
        Endpoint::NamedPipe(n) => EndpointLocator::NamedPipe(n.clone()),
    };
    let started = Instant::now();
    let r = probe::agent::list_identities(&pctx, &locator);
    assert_eq!(r.outcome, ProbeOutcome::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a21_network_level_reads_banner_only() {
    let fx = Fx::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut accepts = 0;
        let (mut s, _) = listener.accept().unwrap();
        accepts += 1;
        s.write_all(b"SSH-2.0-HmFixture_1.0\r\n").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(700)))
            .unwrap();
        let mut got = Vec::new();
        let _ = s.read_to_end(&mut got);
        listener.set_nonblocking(true).unwrap();
        if listener.accept().is_ok() {
            accepts += 1;
        }
        (accepts, got)
    });
    let ctx = fx.ctx();
    let pctx = ProbeContext::new(&ctx, false, false);
    let (r, banner) = probe::network::banner_observed(&pctx, "127.0.0.1", port);
    let (accepts, client_bytes) = server.join().unwrap();
    assert_eq!(r.outcome, ProbeOutcome::Ok);
    assert_eq!(banner.as_deref(), Some("SSH-2.0-HmFixture_1.0"));
    assert_eq!(accepts, 1);
    assert!(
        client_bytes.is_empty(),
        "the client sent {} bytes",
        client_bytes.len()
    );
    assert!(!r.effects_excluded.contains(&ExcludedEffect::Network));
    assert!(
        r.effects_excluded
            .contains(&ExcludedEffect::ConfigExecution)
    );
}

// --- host verification and authentication ---------------------------------------------------

struct Login {
    fx: Fx,
    sshd: LoopbackSshd,
    agent: FakeAgent,
    key_pub: PathBuf,
}

impl Login {
    fn new() -> Login {
        let fx = Fx::new();
        let key = FixtureKey::generate();
        let sshd = LoopbackSshd::start(
            fx.home.scratch(),
            SshdConfig {
                authorized: vec![key.public().clone()],
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        fx.home.trust_host_key(&sshd.host_key_line).unwrap();
        let key_pub = fx.home.ssh_dir.join("adopted.pub");
        key.write_public(&key_pub).unwrap();
        let agent = FakeAgent::start(
            Endpoint::in_scratch(fx.home.scratch(), "provider").unwrap(),
            FakeAgentConfig {
                keys: vec![key],
                mode: AgentMode::Normal,
            },
        );
        Login {
            fx,
            sshd,
            agent,
            key_pub,
        }
    }

    fn alias(&self, extra: &str) -> String {
        format!(
            "{extra}Host {ALIAS}\n  HostName 127.0.0.1\n  Port {}\n  IdentityAgent {}\n  IdentityFile {}\n  IdentitiesOnly yes\n",
            self.sshd.port,
            qp(Path::new(&self.agent.endpoint().locator())),
            qp(&self.key_pub)
        )
    }

    fn catalog(&self, interaction: InteractionKind) -> CatalogAlias {
        CatalogAlias {
            alias: ALIAS.to_owned(),
            definition: AliasDefinition::Managed,
            identity: Some(CatalogIdentity {
                public_key_path: self.key_pub.clone(),
                // Recorded, as the catalog records it (ADR-0007 §12.29 item 1).
                fingerprint: Some(fingerprint_of(&self.key_pub)),
                interaction,
                endpoint: Some(endpoint_locator(self.agent.endpoint())),
            }),
        }
    }

    fn signs(&self) -> usize {
        self.agent
            .log()
            .iter()
            .filter(|m| m.msg_type == msg::SIGN_REQUEST)
            .count()
    }
}

#[test]
fn a21_host_verification_offers_nothing_to_sign() {
    let l = Login::new();
    l.fx.config(&l.alias(""));
    l.fx.home
        .check_alias(ALIAS)
        .expect("default-identity guard");
    let report = run(
        &l.fx.ctx(),
        &request(&[ProbeLevel::HostVerification], true, &[ALIAS]),
    );
    let r = probe_of(&report, ProbeLevel::HostVerification);
    assert_eq!(r[0].outcome, ProbeOutcome::Ok, "{:?}", r[0]);
    assert_eq!(l.signs(), 0, "something was offered to sign");
    assert_eq!(l.fx.home.decoy_agent().contact_count(), 0);
    assert!(l.sshd.accepted_log().is_empty());
    assert!(r[0].effects_excluded.is_empty());
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == finding::KNOWN_HOST_MISMATCH)
    );
}

#[test]
fn a21_host_verification_requires_authorization_with_or_without_constructs() {
    let fx = Fx::new();
    let counter = Counter::start();
    fx.config(&format!(
        "Host hm-proxied\n  {}\n  IdentityFile {}\n{}",
        fx.hook.proxy_command_line(counter.port),
        qp(&fx.path("id.pub")),
        alias_block(9, &fx.path("id.pub"))
    ));
    let report = run(
        &fx.ctx(),
        &request(
            &[ProbeLevel::HostVerification],
            false,
            &["hm-proxied", ALIAS],
        ),
    );
    let r = probe_of(&report, ProbeLevel::HostVerification);
    assert_eq!(r.len(), 2);
    for rec in r {
        assert_eq!(rec.outcome, ProbeOutcome::Declined, "{}", rec.target);
        assert_eq!(
            rec.decline_reason.as_deref(),
            Some(decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED)
        );
    }
    assert!(!fx.ssh_started());
    assert_eq!(counter.count(), 0);
}

/// Needs a session: `exit 0` runs through the account's login shell on the
/// non-root loopback sshd (ADR-0007 §12.15 item 6), as the level defines it.
#[test]
fn a21_authentication_level_single_identity_fixture_signs_exactly_once() {
    let l = Login::new();
    l.fx.config(&l.alias(""));
    l.fx.home
        .check_alias(ALIAS)
        .expect("default-identity guard");
    let mut ctx = l.fx.ctx();
    ctx.catalog = vec![l.catalog(InteractionKind::None)];
    let report = run(
        &ctx,
        &request(&[ProbeLevel::Authentication], true, &[ALIAS]),
    );
    let r = probe_of(&report, ProbeLevel::Authentication);
    assert_eq!(r[0].outcome, ProbeOutcome::Ok, "{:?}", r[0]);
    assert_eq!(
        l.signs(),
        1,
        "this single-identity fixture signs exactly once"
    );
    assert_eq!(l.sshd.accepted_log().len(), 1);
    assert_eq!(l.fx.home.decoy_agent().contact_count(), 0);
}

#[test]
fn a21_noninteractive_authentication_refused_for_unknown_or_interactive_identity() {
    let fx = Fx::new();
    let agent = FakeAgent::start(
        Endpoint::in_scratch(fx.home.scratch(), "provider").unwrap(),
        FakeAgentConfig {
            keys: vec![FixtureKey::generate()],
            mode: AgentMode::Normal,
        },
    );
    let key_pub = fx.home.ssh_dir.join("adopted.pub");
    FixtureKey::generate().write_public(&key_pub).unwrap();
    let alias = format!(
        "Host {ALIAS}\n  HostName 127.0.0.1\n  Port 9\n  IdentityAgent {}\n  IdentityFile {}\n  IdentitiesOnly yes\n",
        qp(Path::new(&agent.endpoint().locator())),
        qp(&key_pub)
    );
    fx.config(&alias);
    // The identity's declared endpoint is the alias's agent (ADR-0007 §12.25 item 3:
    // the probe compares them before either success path).
    let identity = |interaction| CatalogAlias {
        alias: ALIAS.to_owned(),
        definition: AliasDefinition::Managed,
        identity: Some(CatalogIdentity {
            public_key_path: key_pub.clone(),
            // Recorded, as the catalog records it (ADR-0007 §12.29 item 1).
            fingerprint: Some(fingerprint_of(&key_pub)),
            interaction,
            endpoint: Some(endpoint_locator(agent.endpoint())),
        }),
    };
    let refused = |ctx: &LocalContext, reason: &str| {
        let report = run(ctx, &request(&[ProbeLevel::Authentication], true, &[ALIAS]));
        let r = probe_of(&report, ProbeLevel::Authentication);
        assert_eq!(r[0].outcome, ProbeOutcome::Refused, "{reason}: {:?}", r[0]);
        assert_eq!(r[0].code, Some(Code::InteractionRequired));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == finding::INTERACTION_UNKNOWN
                    && f.reason.as_deref() == Some(reason)),
            "{reason}"
        );
    };
    // An identity the catalog does not know.
    refused(&fx.ctx(), "interaction_unknown");
    // An identity whose interaction is not `none`.
    let mut ctx = fx.ctx();
    ctx.catalog = vec![identity(InteractionKind::ProviderApproval)];
    refused(&ctx, "interaction_unknown");
    // A declared `none` identity with an uncleared inherited fallback (M2-R05).
    let inherited = fx.home.ssh_dir.join("inherited.pub");
    FixtureKey::generate().write_public(&inherited).unwrap();
    fx.config(&format!(
        "{alias}Host *\n  IdentityFile {}\n",
        qp(&inherited)
    ));
    let mut ctx = fx.ctx();
    ctx.catalog = vec![identity(InteractionKind::None)];
    refused(&ctx, "fallback_identity_interaction");
    assert!(!fx.ssh_started(), "an ssh child was started");
    assert_eq!(agent.contact_count(), 0);
    assert_eq!(fx.home.decoy_agent().contact_count(), 0);
}

/// ADR-0007 §12.25 item 2 (T02) for the doctor and the connect path that uses its
/// static level (`doctor::alias_profiles`): `Match localuser` reads the account
/// database, never the snapshot's `USER` or `USERNAME`. A fallback behind `Match
/// localuser <the OS account>` makes the adopted key's selection not exclusive with
/// `USER` unset and with `USER` naming another account, in the passive doctor and in
/// every profile; a rule for that other name never applies.
#[test]
fn doctor_reads_localuser_from_the_account_database() {
    let fx = Fx::new();
    let key_pub = fx.home.ssh_dir.join("adopted.pub");
    FixtureKey::generate().write_public(&key_pub).unwrap();
    let inherited = fx.home.ssh_dir.join("inherited.pub");
    FixtureKey::generate().write_public(&inherited).unwrap();
    let account = heimdall_localenv::doctor::local_account()
        .expect("the account database names this account");
    let other = "hm-fixture-other-account";
    let block = format!(
        "Host {ALIAS}\n  HostName 127.0.0.1\n  IdentityAgent none\n  IdentityFile {}\n  IdentitiesOnly yes\n",
        qp(&key_pub)
    );
    let rule = |name: &str| {
        format!(
            "{block}Match localuser {name}\n  IdentityFile {}\n",
            qp(&inherited)
        )
    };
    let ctx = |user: Option<&str>| {
        let mut c = fx.ctx();
        let mut vars: Vec<(String, OsString)> = vec![
            ("PATH".to_owned(), OsString::from("/usr/bin:/bin")),
            ("HOME".to_owned(), fx.home.git_home.clone().into_os_string()),
        ];
        if let Some(u) = user {
            vars.push(("USER".to_owned(), u.into()));
            vars.push(("USERNAME".to_owned(), u.into()));
        }
        c.env = Env::from_vars(vars);
        c.catalog = vec![CatalogAlias {
            alias: ALIAS.to_owned(),
            definition: AliasDefinition::Managed,
            identity: Some(CatalogIdentity {
                public_key_path: key_pub.clone(),
                // Recorded, as the catalog records it (ADR-0007 §12.29 item 1).
                fingerprint: Some(fingerprint_of(&key_pub)),
                interaction: InteractionKind::None,
                endpoint: None,
            }),
        }];
        c
    };
    let selections = |c: &LocalContext| -> Vec<IdentitySelection> {
        let mut request = DoctorRequest::passive();
        request.aliases = Some(vec![ALIAS.to_owned()]);
        request.local_queries = LocalQueries::Disabled;
        let mut out: Vec<IdentitySelection> = run(c, &request)
            .aliases
            .iter()
            .filter_map(|o| o.identity_selection.as_ref().map(|r| r.selection))
            .collect();
        out.extend(
            heimdall_localenv::doctor::alias_profiles(c, ALIAS)
                .iter()
                .filter_map(|(_, o)| o.identity_selection.as_ref().map(|r| r.selection)),
        );
        out
    };
    fx.config(&rule(&account));
    for user in [None, Some(other)] {
        assert_eq!(
            selections(&ctx(user)),
            vec![IdentitySelection::NotExclusive; 4],
            "USER {}",
            if user.is_some() {
                "names another account"
            } else {
                "unset"
            }
        );
    }
    fx.config(&rule(other));
    assert_eq!(
        selections(&ctx(Some(other))),
        vec![IdentitySelection::Exclusive; 4]
    );
    assert!(!fx.ssh_started());
}

/// ADR-0007 §12.28 item 6 for the doctor and the connect path that uses its static
/// level (`doctor::alias_profiles`): an identity entry read from a file outside the
/// account home is shown as the configuration names it, never in its canonical form.
/// The file is included through a symlinked directory: every entry shows the link's
/// path, in the passive doctor and in every profile.
#[test]
fn doctor_shows_a_file_outside_the_home_as_written() {
    let fx = Fx::new();
    let key_pub = fx.home.ssh_dir.join("adopted.pub");
    FixtureKey::generate().write_public(&key_pub).unwrap();
    let inherited = fx.home.ssh_dir.join("inherited.pub");
    FixtureKey::generate().write_public(&inherited).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let real = outside.path().join("hm-fixture-real-dir");
    create_dir_owner_only(&real).unwrap();
    let link = outside.path().join("hm-fixture-link-dir");
    link_dir(&real, &link);
    write_owner_only(
        real.join("extra.conf"),
        format!("Host {ALIAS}\n  IdentityFile {}\n", qp(&inherited)),
    )
    .unwrap();
    let written = link.join("extra.conf");
    fx.config(&format!(
        "Include {}\nHost {ALIAS}\n  HostName 127.0.0.1\n  IdentityAgent none\n  IdentityFile {}\n  IdentitiesOnly yes\n",
        qp(&written),
        qp(&key_pub)
    ));
    let mut c = fx.ctx();
    c.catalog = vec![CatalogAlias {
        alias: ALIAS.to_owned(),
        definition: AliasDefinition::Managed,
        identity: Some(CatalogIdentity {
            public_key_path: key_pub.clone(),
            // Recorded, as the catalog records it (ADR-0007 §12.29 item 1).
            fingerprint: Some(fingerprint_of(&key_pub)),
            interaction: InteractionKind::None,
            endpoint: None,
        }),
    }];
    let mut request = DoctorRequest::passive();
    request.aliases = Some(vec![ALIAS.to_owned()]);
    request.local_queries = LocalQueries::Disabled;
    let mut reports: Vec<_> = run(&c, &request)
        .aliases
        .into_iter()
        .filter_map(|o| o.identity_selection)
        .collect();
    reports.extend(
        heimdall_localenv::doctor::alias_profiles(&c, ALIAS)
            .into_iter()
            .filter_map(|(_, o)| o.identity_selection),
    );
    assert_eq!(reports.len(), 4);
    let shown = shown_path(&written);
    for report in &reports {
        let included: Vec<_> = report
            .entries
            .iter()
            .filter_map(|e| e.provenance.as_ref())
            .filter(|p| !p.path_display.starts_with('~'))
            .collect();
        assert_eq!(included.len(), 1, "{report:?}");
        assert_eq!(included[0].path_display, shown);
        assert_eq!(included[0].line, 2);
        let text = serde_json::to_string(report).unwrap();
        assert!(!text.contains("hm-fixture-real-dir"), "{text}");
    }
    assert!(!fx.ssh_started());
}

/// ADR-0007 §12.30 item 10 (the §12.28 item 6 residual): the passive doctor's
/// `config_files` listing and the provenance of an include failure show a file outside
/// the account home as the configuration names it (through
/// `ConfigSet::written_path_of`), never in its canonical form. The included file is
/// reached through a symlinked directory; inside it, one `Include` cannot be expanded
/// statically (an unset variable) and one names an unreadable file. The listing, both
/// findings' provenance and the unreadable file's own entry all show the link's path,
/// and the real directory's name appears nowhere in the report.
#[test]
fn doctor_lists_config_files_and_include_failures_as_written() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let fx = Fx::new();
    let outside = tempfile::tempdir().unwrap();
    let real = outside.path().join("hm-fixture-real-dir");
    create_dir_owner_only(&real).unwrap();
    let link = outside.path().join("hm-fixture-link-dir");
    link_dir(&real, &link);
    let unreadable = real.join("unreadable.conf");
    write_owner_only(&unreadable, "Host z\n").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    #[cfg(windows)]
    let denied = heimdall_testkit::win::deny_read(&unreadable).unwrap();
    let readable = std::fs::read(&unreadable).is_ok();
    #[cfg(windows)]
    assert!(!readable, "the deny-read DACL did not deny the read");
    write_owner_only(
        real.join("extra.conf"),
        format!(
            "Include ${{HM_FIXTURE_UNSET_VARIABLE}}/x.conf\nInclude {}\n",
            qp(&link.join("unreadable.conf"))
        ),
    )
    .unwrap();
    let written = link.join("extra.conf");
    fx.config(&format!(
        "Include {}\nHost {ALIAS}\n  HostName 127.0.0.1\n",
        qp(&written)
    ));
    let mut request = DoctorRequest::passive();
    request.aliases = Some(Vec::new());
    request.local_queries = LocalQueries::Disabled;
    let report = run(&fx.ctx(), &request);
    #[cfg(unix)]
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600)).unwrap();
    #[cfg(windows)]
    denied.restore().unwrap();
    let shown = shown_path(&written);
    let listed: Vec<&str> = report
        .config_files
        .iter()
        .map(|f| f.path_display.as_str())
        .collect();
    assert!(listed.contains(&shown.as_str()), "{listed:?}");
    assert!(
        listed.contains(&"~/.ssh/config"),
        "the user file under the home: {listed:?}"
    );
    let at = |line: u32| {
        report.findings.iter().any(|f| {
            f.provenance
                .as_ref()
                .is_some_and(|p| p.path_display == shown && p.line == line)
        })
    };
    assert!(
        at(1),
        "the unexpandable Include, as written: {:?}",
        report.findings
    );
    if !readable {
        assert!(
            at(2),
            "the unreadable Include, as written: {:?}",
            report.findings
        );
        let unreadable_shown = shown_path(&link.join("unreadable.conf"));
        assert!(
            report
                .config_files
                .iter()
                .any(|f| f.path_display == unreadable_shown && !f.readable),
            "{:?}",
            report.config_files
        );
    }
    let text = serde_json::to_string(&report).unwrap();
    assert!(!text.contains("hm-fixture-real-dir"), "{text}");
    assert!(!fx.ssh_started());
}

// --- reads that must not block, local queries ------------------------------------------------

// Unix-only: mkfifo creates a filesystem FIFO; Windows named pipes are not Include files.
#[cfg(unix)]
#[test]
fn a21_fifo_include_does_not_block() {
    let fx = Fx::new();
    let fifo = fx.path("fifo.conf");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    fx.config(&format!(
        "Include {}\n{}",
        qp(&fifo),
        alias_block(9, &fx.path("id.pub"))
    ));
    let ctx = fx.ctx();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let report = run(&ctx, &request(&[ProbeLevel::Evaluate], true, &[ALIAS]));
        let _ = tx.send(report);
    });
    let report = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the doctor blocked on a FIFO include");
    assert!(
        report
            .config_files
            .iter()
            .any(|f| f.path_display.ends_with("fifo.conf") && !f.readable)
    );
    let r = probe_of(&report, ProbeLevel::Evaluate);
    assert_eq!(
        r[0].decline_reason.as_deref(),
        Some(decline_reason::CONFIG_NOT_FULLY_READABLE)
    );
}

#[test]
fn a21_local_queries_listed_and_off_with_no_local_exec() {
    let fx = Fx::new();
    fx.config(&alias_block(9, &fx.path("id.pub")));
    // Wrappers that log every start, -V included.
    let log = fx.path("queries.log");
    let wrap = |name: &str, real: &Path| -> PathBuf {
        #[cfg(unix)]
        let p = fx.path(&format!("qbin/{name}"));
        #[cfg(windows)]
        let p = fx.path(&format!("qbin/{name}.cmd"));
        create_dir_owner_only(p.parent().unwrap()).unwrap();
        #[cfg(unix)]
        write_owner_only(
            &p,
            format!(
                "#!/bin/sh\necho {name} >> '{}'\nexec '{}' \"$@\"\n",
                log.display(),
                real.display()
            ),
        )
        .unwrap();
        #[cfg(windows)]
        write_owner_only(
            &p,
            format!(
                "@echo off\r\necho {name}>>\"{}\"\r\n\"{}\" %*\r\nexit /b %errorlevel%\r\n",
                log.display(),
                real.display()
            ),
        )
        .unwrap();
        make_executable(&p);
        p
    };
    let ssh = wrap("ssh", &fx.real_ssh);
    let git = wrap("git", &find_program("git").expect("git on PATH"));
    let ctx_with = |queries: LocalQueries| {
        let mut ctx = fx.ctx();
        ctx.clients = ClientsConfig {
            ssh: Some(ssh.clone()),
            git: Some(git.clone()),
            ..ClientsConfig::default()
        };
        let mut req = request(&[], false, &[ALIAS]);
        req.local_queries = queries;
        run(&ctx, &req)
    };
    let off = ctx_with(LocalQueries::Disabled);
    assert!(!log.exists(), "a local query ran with --no-local-exec");
    assert_eq!(static_record(&off).containment, Containment::None);
    assert!(off.clients.iter().all(|c| c.version.is_none()));
    let on = ctx_with(LocalQueries::Enabled);
    let ran = std::fs::read_to_string(&log).unwrap();
    assert!(ran.lines().any(|l| l == "ssh"), "ssh -V did not run");
    assert!(
        ran.lines().any(|l| l == "git"),
        "the git queries did not run"
    );
    assert_ne!(static_record(&on).containment, Containment::None);
    assert!(on.clients.iter().any(|c| c.selected && c.version.is_some()));
    // Both runs are static only: nothing configured ran.
    assert!(!fx.ssh_started());
    assert_eq!(on.levels_performed, BTreeSet::from([ProbeLevel::Static]));
}

// --- home, identity selection -------------------------------------------------------------

/// F19 and the `GLOB_TILDE` note (ADR-0007 §12.15): with a scratch `HOME`, `ssh -G`
/// expands `%d` from the account database, which must equal Heimdall's account home;
/// an `Include ~/…` is observed and recorded, and the doctor reports `home_mismatch`
/// whenever `HOME` differs from the account home. No path is printed.
#[test]
fn home_resolution_matches_ssh_g() {
    let fx = Fx::new();
    let probe_name = format!("hm-include-probe-{}.conf", std::process::id());
    write_owner_only(
        fx.home.git_home.join(&probe_name),
        "Host hm-home-inc\n  Port 2999\n",
    )
    .unwrap();
    fx.config(&format!(
        "Host hm-home\n  ControlPath %d/hm-home-probe-cp\n  IdentityFile {}\nHost hm-home-inc\n  Include ~/{probe_name}\n  IdentityFile {}\n",
        qp(&fx.path("id.pub")),
        qp(&fx.path("id.pub"))
    ));
    let account = SshPaths::resolve().unwrap().account_home;
    let ssh_g = |alias: &str| -> std::collections::BTreeMap<String, String> {
        let mut command = Command::new(&fx.real_ssh);
        command.env_clear();
        #[cfg(unix)]
        command.env("PATH", "/usr/bin:/bin");
        #[cfg(windows)]
        command.envs(fx.env().iter());
        let out = command
            .env("HOME", &fx.home.git_home)
            .arg("-G")
            .args(fx.home.isolation_args())
            .arg(alias)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    };
    let cp = ssh_g("hm-home")["controlpath"].clone();
    let expected = account.join("hm-home-probe-cp");
    #[cfg(unix)]
    let matches = cp == expected.to_string_lossy();
    #[cfg(windows)]
    let matches = Path::new(&cp) == expected;
    assert!(
        matches,
        "ssh's %d is not Heimdall's account home (paths withheld)"
    );
    let include_follows_home = ssh_g("hm-home-inc").get("port").map(String::as_str) == Some("2999");
    eprintln!(
        "observation test=home_resolution_matches_ssh_g percent_d_is_account_home=true include_tilde_follows_HOME={include_follows_home}"
    );
    // The doctor flags the case where an Include's ~ may resolve elsewhere: here the
    // (scratch) account home and HOME differ. With them equal it says nothing.
    let report = run(&fx.ctx(), &request(&[], false, &["hm-home"]));
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.code == finding::HOME_MISMATCH)
    );
    let mut ctx = fx.ctx();
    let other = fx.path("other-home");
    create_dir_owner_only(&other).unwrap();
    ctx.env = Env::from_vars(
        fx.env()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .filter(|(k, _)| k != "HOME")
            .chain([(OsString::from("HOME"), other.into_os_string())]),
    );
    let report = run(&ctx, &request(&[], false, &["hm-home"]));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == finding::HOME_MISMATCH)
    );
}

/// ADR-0007 §12.17 item 9, end to end: an `Include ~/…` (and a relative Include)
/// follows `$HOME`. Under a `HOME` that is not the account home, the doctor reports
/// `home_mismatch` and the include is undetermined (`environment_reference`), so the
/// tree is not fully readable and the explicit levels are declined even with
/// authorization: the static pass never claims the account home's file. With `HOME`
/// the account home, nothing is reported and the level is not declined for that.
#[test]
fn home_mismatch_makes_a_home_relative_include_not_fully_readable() {
    let fx = Fx::new();
    write_owner_only(
        fx.home.git_home.join("hm-inc-home.conf"),
        "Host hm-other\n  Port 2981\n",
    )
    .unwrap();
    fx.config(&format!(
        "Include ~/hm-inc-home.conf\n{}",
        alias_block(9, &fx.path("id.pub"))
    ));
    let other = fx.path("other-home");
    create_dir_owner_only(&other).unwrap();
    let with_home = |home: Option<OsString>| {
        let mut ctx = fx.ctx();
        ctx.env = Env::from_vars(
            fx.env()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .filter(|(k, _)| k != "HOME")
                .chain(home.map(|h| (OsString::from("HOME"), h))),
        );
        ctx
    };
    let mismatch = |r: &DoctorReport| r.findings.iter().any(|f| f.code == finding::HOME_MISMATCH);
    for home in [
        other.clone().into_os_string(),
        OsString::new(),
        OsString::from("relative-home"),
    ] {
        let report = run(
            &with_home(Some(home)),
            &request(&[ProbeLevel::Evaluate], true, &[ALIAS]),
        );
        assert!(mismatch(&report), "home_mismatch not reported");
        let r = probe_of(&report, ProbeLevel::Evaluate);
        assert_eq!(r[0].outcome, ProbeOutcome::Declined);
        assert_eq!(
            r[0].decline_reason.as_deref(),
            Some(decline_reason::CONFIG_NOT_FULLY_READABLE)
        );
    }
    assert!(!fx.ssh_started(), "a declined level started ssh");
    // HOME is the account home, or unset (glob(3) falls back to the account database).
    for home in [Some(fx.home.git_home.clone().into_os_string()), None] {
        let report = run(
            &with_home(home),
            &request(&[ProbeLevel::Evaluate], true, &[ALIAS]),
        );
        assert!(!mismatch(&report));
        let r = probe_of(&report, ProbeLevel::Evaluate);
        assert_ne!(
            r[0].decline_reason.as_deref(),
            Some(decline_reason::CONFIG_NOT_FULLY_READABLE)
        );
    }
}

#[test]
fn doctor_reports_identity_selection_not_exclusive_with_remedy() {
    let fx = Fx::new();
    let adopted = fx.home.ssh_dir.join("adopted.pub");
    let inherited = fx.home.ssh_dir.join("inherited.pub");
    FixtureKey::generate().write_public(&adopted).unwrap();
    FixtureKey::generate().write_public(&inherited).unwrap();
    fx.config(&format!(
        "Host hm-sel\n  HostName 127.0.0.1\n  IdentityFile {}\n  IdentitiesOnly yes\nHost *\n  IdentityFile {}\n",
        qp(&adopted),
        qp(&inherited)
    ));
    let mut ctx = fx.ctx();
    ctx.catalog = vec![CatalogAlias {
        alias: "hm-sel".to_owned(),
        definition: AliasDefinition::Managed,
        identity: Some(CatalogIdentity {
            public_key_path: adopted.clone(),
            fingerprint: None,
            interaction: InteractionKind::Unknown,
            endpoint: None,
        }),
    }];
    let report = run(&ctx, &request(&[], false, &["hm-sel"]));
    let alias = report.aliases.iter().find(|a| a.alias == "hm-sel").unwrap();
    assert_eq!(alias.definition, AliasDefinition::Managed);
    let sel = alias.identity_selection.as_ref().unwrap();
    assert_eq!(sel.selection, IdentitySelection::NotExclusive);
    assert_eq!(sel.entries.len(), 2);
    assert!(sel.entries.iter().all(|e| e.provenance.is_some()));
    let f = report
        .findings
        .iter()
        .find(|f| f.code == finding::IDENTITY_SELECTION_NOT_EXCLUSIVE)
        .expect("identity_selection_not_exclusive");
    assert_eq!(f.next.action, "review_config");
    assert!(
        f.message.contains("IdentitiesOnly yes"),
        "no remedy: {}",
        f.message
    );
    assert!(f.provenance.is_some());
}

/// The `SHA256:` fingerprint of the public key in the file at `path`, as the catalog
/// records an adopted identity's (ADR-0007 §12.29 item 1).
fn fingerprint_of(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    let encoded = text.split_ascii_whitespace().nth(1).unwrap();
    heimdall_localenv::known_hosts::fingerprint(
        &heimdall_localenv::known_hosts::base64_decode(encoded).unwrap(),
    )
}

/// G-P1: compare the token lookup with the in-box client's pw_name, without a
/// configured User and with %u, independently of USER/USERNAME in the child.
#[cfg(windows)]
#[test]
fn account_name_matches_inbox_ssh_g() {
    let fx = Fx::new();
    let account = heimdall_localenv::sys::account_name().unwrap();
    for user in ["", "  User %u\n"] {
        fx.config(&format!(
            "Host {ALIAS}\n  HostName 127.0.0.1\n  IdentityFile {}\n  IdentityAgent none\n{user}",
            qp(&fx.path("unused.pub"))
        ));
        let out = Command::new("C:/Windows/System32/OpenSSH/ssh.exe")
            .env_clear()
            .envs(fx.env().iter())
            .env("USER", "hm-fixture-wrong-account")
            .env("USERNAME", "hm-fixture-wrong-account")
            .arg("-G")
            .args(fx.home.isolation_args())
            .arg(ALIAS)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "in-box ssh -G failed");
        let text = String::from_utf8(out.stdout).unwrap();
        let observed = text.lines().find_map(|l| l.strip_prefix("user ")).unwrap();
        assert!(
            observed == account,
            "account lookup differs from in-box ssh (names withheld)"
        );
    }
}

/// F13 on Windows: every executable-bearing directive stays inert in the passive
/// doctor, including directives whose commands would use cmd /c on a real client.
#[cfg(windows)]
#[test]
fn a21_default_doctor_windows_execution_constructs_are_inert() {
    let fx = Fx::new();
    let counter = Counter::start();
    let marker = fx.path("execution-directive-ran");
    let touch = fx.hook.shell_command(&HookMode::Touch {
        path: marker.clone(),
    });
    fx.config(&format!(
        "{}  {}\n  KnownHostsCommand {touch}\n  LocalCommand {touch}\n  PermitLocalCommand yes\n  RemoteCommand {touch}\n{}\n",
        alias_block(counter.port, &fx.path("unused.pub")),
        fx.hook.proxy_command_line(counter.port),
        fx.exec_line(&HookMode::Touch { path: marker.clone() }),
    ));
    let before = tree_digest(&fx.root);
    let report = run(&fx.ctx(), &DoctorRequest::passive());
    assert!(static_record(&report).effects_excluded == all_effects());
    assert!(!fx.ssh_started(), "a passive doctor started ssh");
    assert!(!marker.exists(), "an execution directive ran");
    assert_eq!(counter.count(), 0);
    assert_eq!(fx.home.decoy_agent().contact_count(), 0);
    assert!(
        tree_digest(&fx.root) == before,
        "the passive doctor changed fixture files"
    );
}
