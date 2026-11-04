//! M02-U10 end-to-end suite: `heimdall tui` through the **real binary** on a pty
//! (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN`), against a real runtime started in
//! this test process (m02-plan U10 tests; ADR-0007 §8 TUI handoff, §12.24 item 9).
//!
//! **Isolation.** Every runtime lives in a `heimdall_testkit::home::ScratchHome`: its
//! directories, the scratch `~/.ssh/config` the TUI's static pass reads
//! (`HEIMDALL_TEST_SSH_HOME`), and the decoy counting agent at `SSH_AUTH_SOCK`. The TUI
//! gets a cleared environment with `PATH=<stub dir>:/usr/bin:/bin`: its verified client
//! `ssh` is a stub shell script that records how it ran and contacts nothing, so no
//! real `ssh` runs and no network is used. `GIT_CONFIG_NOSYSTEM=1` and a scratch
//! `GIT_CONFIG_GLOBAL` keep the doctor's Git queries in scratch. Only processes this
//! test started are stopped, through their own handles.
//!
//! **The screen.** Escape-sequence checks read the raw pty transcript; text checks read
//! the frame the TUI drew (`HEIMDALL_TEST_TUI_SCREEN`, debug builds), because ratatui
//! writes only changed cells and a word on the terminal stream may be split by cursor
//! moves.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::process::{Command, Stdio};

/// The binary under test.
fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

/// m02-plan U10: the TUI refuses, before it touches a terminal or the runtime, `--json`
/// (it has no machine output), `--non-interactive` (it is interactive) and a stdin that
/// is not a terminal: usage errors, exit 2, the Heimdall home never created.
#[test]
fn tui_refuses_json_non_interactive_and_a_non_terminal_before_touching_anything() {
    let scratch = tempfile::tempdir().unwrap();
    for (i, (args, needle)) in [
        (vec!["--json", "tui"], "machine output"),
        (vec!["--non-interactive", "tui"], "interactive"),
        (vec!["tui"], "terminal"),
    ]
    .into_iter()
    .enumerate()
    {
        let home = scratch.path().join(format!("h{i}"));
        let mut cmd = Command::new(bin());
        cmd.args(&args)
            .env_clear()
            .env("HEIMDALL_HOME", &home)
            .stdin(Stdio::null());
        if cfg!(windows) {
            for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
        } else {
            cmd.env("PATH", "/usr/bin:/bin");
        }
        let out = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        heimdall_testkit::assert_no_canary(&stdout);
        heimdall_testkit::assert_no_canary(&stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stdout} {stderr}");
        let text = format!("{stdout}{stderr}");
        assert!(text.contains(needle), "{args:?}: {text}");
        assert!(
            !text.contains("\u{1b}[?1049h"),
            "{args:?}: no terminal state touched"
        );
        if args.contains(&"--json") {
            let env: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
            assert_eq!(env["code"], "USAGE_ERROR");
        }
        assert!(!home.exists(), "{args:?}: the runtime was never reached");
    }
}

#[cfg(unix)]
mod pty {
    use std::ffi::{OsStr, OsString};
    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use heimdall_app::{Attendance, Caller, OpError, Operations};
    use heimdall_contract::catalog::{
        CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
        IdentitySourceSpec, IdentitySpec,
    };
    use heimdall_contract::ids::{DestinationId, IdentityId, RequestId};
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_contract::request::{InspectRequest, InspectSubject, InteractionMode};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::ProjectionConfig;
    use heimdall_runtime::config::{Config, Paths};
    use heimdall_runtime::service::{ProjectionWiring, Service, ServiceOptions};
    use heimdall_testkit::agent::FixtureKey;
    use heimdall_testkit::assert_no_canary;
    use heimdall_testkit::home::ScratchHome;
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{SpecialCodeIndex, Termios, Winsize, tcgetattr, tcsetwinsize};
    use serde_json::Value;
    use tokio_util::sync::CancellationToken;

    use super::bin;

    const SLAVE: &str = "HM_U10_PTY_SLAVE";
    const ARGV: &str = "HM_U10_PTY_ARGV";
    const LONG: Duration = Duration::from_secs(60);

    /// Child-mode entry of the pty cases: a new session on the pty as its controlling
    /// terminal, then `exec` of the program named in [`ARGV`]. Does nothing in a normal
    /// run.
    #[test]
    #[ignore = "child-mode entry of the pty tests, started by them"]
    fn pty_child() {
        let (Some(slave), Some(argv)) = (std::env::var_os(SLAVE), std::env::var(ARGV).ok()) else {
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
        let argv: Vec<String> = serde_json::from_str(&argv).unwrap();
        let err = Command::new(&argv[0]).args(&argv[1..]).exec();
        panic!("exec failed: {err}");
    }

    // ---- the pty ---------------------------------------------------------------------

    struct Pty {
        master: Option<OwnedFd>,
        slave: PathBuf,
        output: Arc<Mutex<Vec<u8>>>,
        stop: Arc<AtomicBool>,
        reader: Option<std::thread::JoinHandle<()>>,
    }

    impl Pty {
        fn open(rows: u16, cols: u16) -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            // Close-on-exec, so no child inherits the master and a hang-up is a real
            // one when this test closes it.
            rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let output = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            // Drain the terminal so the child never blocks on output. `poll` with a
            // short timeout lets the thread see `stop`, so `hang_up` can close every
            // descriptor of the master.
            let reader_fd = master.try_clone().unwrap();
            let sink = Arc::clone(&output);
            let done = Arc::clone(&stop);
            let reader = std::thread::spawn(move || {
                use rustix::event::{PollFd, PollFlags, Timespec, poll};
                let mut buf = [0u8; 8192];
                while !done.load(Ordering::SeqCst) {
                    let mut fds = [PollFd::new(&reader_fd, PollFlags::IN)];
                    let ts = Timespec {
                        tv_sec: 0,
                        tv_nsec: 20_000_000,
                    };
                    match poll(&mut fds, Some(&ts)) {
                        Ok(n) if n > 0 && fds[0].revents().contains(PollFlags::IN) => {
                            match rustix::io::read(&reader_fd, &mut buf) {
                                Ok(n) if n > 0 => {
                                    sink.lock().unwrap().extend_from_slice(&buf[..n]);
                                }
                                _ => std::thread::sleep(Duration::from_millis(10)),
                            }
                        }
                        Ok(n) if n > 0 => std::thread::sleep(Duration::from_millis(10)),
                        _ => {}
                    }
                }
            });
            let pty = Pty {
                master: Some(master),
                slave: PathBuf::from(OsStr::from_bytes(name.as_bytes())),
                output,
                stop,
                reader: Some(reader),
            };
            pty.resize(rows, cols);
            pty
        }

        fn open_slave(&self) -> OwnedFd {
            rustix::fs::open(
                &self.slave,
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
                rustix::fs::Mode::empty(),
            )
            .unwrap()
        }

        /// `TIOCSWINSZ` through the slave; the kernel signals the foreground group.
        fn resize(&self, rows: u16, cols: u16) {
            tcsetwinsize(
                self.open_slave(),
                Winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                },
            )
            .unwrap();
        }

        /// The terminal's current mode, read through the slave.
        fn termios(&self) -> Termios {
            tcgetattr(self.open_slave()).unwrap()
        }

        fn write(&self, bytes: &[u8]) {
            let fd = self.master.as_ref().unwrap().try_clone().unwrap();
            std::fs::File::from(fd).write_all(bytes).unwrap();
        }

        fn transcript(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        fn count(&self, needle: &str) -> usize {
            self.transcript().matches(needle).count()
        }

        /// Close every descriptor of the master: the terminal hangs up.
        fn hang_up(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(r) = self.reader.take() {
                r.join().unwrap();
            }
            self.master = None;
        }

        /// The test entry's arguments for `argv` on this terminal.
        fn start(&self, env: &[(OsString, OsString)], cwd: &Path, argv: &[OsString]) -> Proc {
            let argv: Vec<String> = argv
                .iter()
                .map(|a| a.to_str().unwrap().to_owned())
                .collect();
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "pty::pty_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .current_dir(cwd);
            for (k, v) in env {
                cmd.env(k, v);
            }
            let child = cmd
                .env(SLAVE, &self.slave)
                .env(ARGV, serde_json::to_string(&argv).unwrap())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Proc(Some(child))
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(r) = self.reader.take() {
                let _ = r.join();
            }
        }
    }

    /// A process this test started, killed through its own handle if the test fails.
    struct Proc(Option<Child>);

    impl Proc {
        fn pid(&self) -> u32 {
            self.0.as_ref().unwrap().id()
        }

        fn try_wait(&mut self) -> Option<ExitStatus> {
            self.0.as_mut().unwrap().try_wait().unwrap()
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
                    panic!("the process did not finish within {limit:?}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    fn wait_for(what: &str, limit: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + limit;
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    /// The terminal modes that matter for "restored": every flag word, and the special
    /// characters a cooked terminal relies on.
    fn modes(t: &Termios) -> String {
        format!(
            "{:?} {:?} {:?} {:?} {:?}",
            t.input_modes,
            t.output_modes,
            t.control_modes,
            t.local_modes,
            [
                SpecialCodeIndex::VMIN,
                SpecialCodeIndex::VTIME,
                SpecialCodeIndex::VINTR,
                SpecialCodeIndex::VSUSP,
                SpecialCodeIndex::VEOF,
            ]
            .map(|i| t.special_codes[i])
        )
    }

    // ---- the runtime -----------------------------------------------------------------

    struct World {
        home: ScratchHome,
        stubs: PathBuf,
        marks: PathBuf,
        ops: Operations,
        handle: tokio::runtime::Handle,
        token: CancellationToken,
        thread: Option<std::thread::JoinHandle<()>>,
        uid: u32,
        n: AtomicU32,
    }

    impl World {
        /// A scratch home, a stub directory and a runtime serving the scratch home.
        fn new() -> World {
            use std::os::unix::fs::MetadataExt as _;
            let home = ScratchHome::new();
            std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
            std::fs::create_dir_all(home.git_home.join("etc-ssh")).unwrap();
            let stubs = home.root.join("stubs");
            let marks = home.root.join("marks");
            std::fs::create_dir(&stubs).unwrap();
            std::fs::create_dir(&marks).unwrap();
            let uid = std::fs::metadata(&home.root).unwrap().uid();
            let paths =
                SshPaths::with_test_override(home.git_home.clone(), home.root.join("etc-ssh"));
            let mut projection =
                ProjectionConfig::new(paths, Platform::current(), home.config_dir.clone());
            projection.env = Env::from_vars([
                ("HOME", home.git_home.display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
            ]);
            let root = home.root.clone();
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
                    let _ = tx.send((handle, service.operations().clone()));
                    let _ = service.run().await;
                });
            });
            let (handle, ops) = rx.recv().expect("the runtime started");
            World {
                home,
                stubs,
                marks,
                ops,
                handle,
                token,
                thread: Some(thread),
                uid,
                n: AtomicU32::new(0),
            }
        }

        fn attended(&self) -> Caller {
            Caller {
                context: CallerContext {
                    principal: PrincipalRef::UnixUser { uid: self.uid },
                    role: ClientRole::Owner,
                },
                attendance: Attendance::Attended {
                    since: heimdall_contract::Timestamp::now(),
                },
                interaction: InteractionMode::Interactive,
            }
        }

        fn on<T: Send + 'static>(
            &self,
            f: impl std::future::Future<Output = T> + Send + 'static,
        ) -> T {
            let (tx, rx) = std::sync::mpsc::channel();
            self.handle.spawn(async move {
                let _ = tx.send(f.await);
            });
            rx.recv().expect("the runtime task finished")
        }

        fn next_id(&self, what: &str) -> RequestId {
            let n = self.n.fetch_add(1, Ordering::SeqCst);
            RequestId::parse(&format!("r-{what}-{n}")).unwrap()
        }

        fn catalog(&self, req: CatalogRequest) -> Result<Value, OpError> {
            let caller = self.attended();
            let ops = self.ops.clone();
            self.on(async move { ops.catalog(&caller, req).await.map(|c| c.data) })
        }

        fn inspect(&self, subject: InspectSubject) -> Value {
            let caller = self.attended();
            let ops = self.ops.clone();
            self.on(async move {
                ops.inspect(
                    &caller,
                    InspectRequest {
                        subject,
                        preview: None,
                    },
                )
                .await
                .map(|c| c.data)
            })
            .unwrap()
        }

        /// An observed catalog destination `alias`.
        fn observed(&self, alias: &str) {
            self.catalog(CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse(&format!("dst-{alias}")).unwrap(),
                    alias: alias.to_owned(),
                    definition: DestinationDefinitionSpec::Observed,
                    label: None,
                },
                request_id: self.next_id("dest"),
            })
            .unwrap();
        }

        /// A stub `ssh` in the stub directory: `-V` and `-G` answer at once; every
        /// invocation is logged to `marks/invocations`; any other run executes `body`.
        fn stub_ssh(&self, body: &str) {
            let marks = self.marks.display();
            let script = format!(
                "#!/bin/sh\n\
                 # hm-u10 stub ssh: contacts nothing.\n\
                 echo \"$*\" >> '{marks}/invocations'\n\
                 for a in \"$@\"; do\n\
                   case \"$a\" in\n\
                     -V) echo 'OpenSSH_9.9p1 hm-u10-stub' >&2; exit 0 ;;\n\
                     -G) echo 'user fixture'; echo 'hostname 127.0.0.1'; echo 'port 22'; exit 0 ;;\n\
                   esac\n\
                 done\n\
                 dir='{marks}'\n\
                 {body}\n"
            );
            let path = self.stubs.join("ssh");
            std::fs::write(&path, script).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn screen_file(&self) -> PathBuf {
            self.home.root.join("screen.txt")
        }

        fn screen(&self) -> String {
            std::fs::read_to_string(self.screen_file()).unwrap_or_default()
        }

        fn wait_screen(&self, what: &str, limit: Duration, cond: impl Fn(&str) -> bool) {
            let deadline = Instant::now() + limit;
            loop {
                let screen = self.screen();
                if cond(&screen) {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {what}; the last frame:\n{screen}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn env(&self) -> Vec<(OsString, OsString)> {
            let g = &self.home.git_home;
            let mut path = self.stubs.clone().into_os_string();
            path.push(":/usr/bin:/bin");
            vec![
                ("PATH".into(), path),
                ("HOME".into(), g.clone().into_os_string()),
                (
                    "HEIMDALL_HOME".into(),
                    self.home.root.clone().into_os_string(),
                ),
                ("HEIMDALL_TEST_SSH_HOME".into(), g.clone().into_os_string()),
                (
                    "HEIMDALL_TEST_TUI_SCREEN".into(),
                    self.screen_file().into_os_string(),
                ),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                (
                    "GIT_CONFIG_GLOBAL".into(),
                    g.join(".gitconfig").into_os_string(),
                ),
                (
                    "SSH_AUTH_SOCK".into(),
                    self.home.decoy_agent().endpoint().locator(),
                ),
                ("TERM".into(), "xterm-256color".into()),
            ]
        }

        /// `heimdall tui` on `pty`, with `extra` added to the environment.
        fn tui(&self, pty: &Pty, extra: &[(&str, &str)]) -> Proc {
            let mut env = self.env();
            env.extend(
                extra
                    .iter()
                    .map(|(k, v)| (OsString::from(k), OsString::from(v))),
            );
            let argv = vec![OsString::from(bin()), OsString::from("tui")];
            pty.start(&env, &self.home.root, &argv)
        }

        fn mark(&self, name: &str) -> PathBuf {
            self.marks.join(name)
        }

        fn read_mark(&self, name: &str) -> String {
            std::fs::read_to_string(self.mark(name)).unwrap_or_default()
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            self.token.cancel();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// Start the TUI and wait until the runtime's listing is on the screen (so the
    /// worker runs, its signal handlers are in place and the catalog is read).
    fn started(w: &World, pty: &Pty, extra: &[(&str, &str)]) -> Proc {
        let p = w.tui(pty, extra);
        w.wait_screen("the first frame", LONG, |s| s.contains("Overview"));
        w.wait_screen("the runtime's listing", LONG, |s| {
            s.contains("Runtime: connected")
        });
        w.wait_screen("the static pass", LONG, |s| {
            s.contains("Static pass:") && !s.contains("Static pass: running")
        });
        p
    }

    /// The screen's text with box borders removed and wrapped lines joined, so a
    /// sentence that wraps still reads as one.
    fn flat(screen: &str) -> String {
        screen
            .replace(['│', '┌', '┐', '└', '┘', '─'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The transcript's last 2000 bytes (for failure messages).
    fn tail(pty: &Pty) -> String {
        let t = pty.transcript();
        let start = t.len().saturating_sub(2000);
        let start = (start..t.len())
            .find(|i| t.is_char_boundary(*i))
            .unwrap_or(t.len());
        t[start..].to_owned()
    }

    fn ps(field: &str, pid: u32) -> String {
        let out = Command::new("/bin/ps")
            .args(["-o", &format!("{field}="), "-p", &pid.to_string()])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn stopped(pid: u32) -> bool {
        ps("stat", pid).starts_with('T')
    }

    // ---- the tests ---------------------------------------------------------------------

    /// m02-plan U10 `search_never_probes` (FakeAgent and listener counts 0): with the
    /// decoy counting agent at `SSH_AUTH_SOCK` and the aliases pointing at a counting
    /// loopback listener, the TUI's whole session (its passive static pass included)
    /// and every search keystroke contact neither.
    #[test]
    fn search_never_probes() {
        let w = World::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counter = {
            let accepted = Arc::clone(&accepted);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok(_) => {
                            accepted.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        };
        let agent = w.home.decoy_agent().endpoint().locator();
        w.home
            .write_user_config(&format!(
                "Host alpha beta\n  HostName 127.0.0.1\n  Port {port}\n  IdentityAgent {}\n",
                agent.to_string_lossy()
            ))
            .unwrap();
        w.observed("alpha");
        w.observed("beta");
        w.stub_ssh("exit 0");
        let pty = Pty::open(40, 120);
        let tui = started(&w, &pty, &[]);
        pty.write(b"2");
        w.wait_screen("the destinations", LONG, |s| {
            s.contains("alpha") && s.contains("beta")
        });
        pty.write(b"/");
        for (typed, shown) in [
            ("alp", "(1 of 2)"),
            ("\x7f\x7f\x7f", "(2 of 2)"),
            ("bet", "(1 of 2)"),
            ("zz", "(0 of 2)"),
        ] {
            pty.write(typed.as_bytes());
            w.wait_screen(shown, LONG, |s| s.contains(shown));
        }
        pty.write(b"\x1b");
        w.wait_screen("the search cleared", LONG, |s| s.contains("2 total"));
        std::thread::sleep(Duration::from_millis(500));
        pty.write(b"q");
        let status = tui.wait(LONG);
        stop.store(true, Ordering::SeqCst);
        counter.join().unwrap();
        assert_eq!(status.code(), Some(0), "{}", pty.transcript());
        assert_eq!(w.home.decoy_agent().contact_count(), 0, "agent contacted");
        assert_eq!(w.home.decoy_agent().connections(), 0, "agent connected to");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "the listener was contacted"
        );
        assert!(
            !w.read_mark("invocations")
                .lines()
                .any(|l| !l.trim().is_empty() && l.trim() != "-V"),
            "only the static pass's `ssh -V` ran: {}",
            w.read_mark("invocations")
        );
        assert_no_canary(&pty.transcript());
    }

    /// m02-plan U10 `connect_handoff_restores_terminal_after_exit_and_after_child_signal`
    /// (pty): connect leaves the alternate screen and gives the child a cooked terminal;
    /// after the child exits, and again after it dies by a signal, the TUI survives,
    /// re-enters and repaints; on quit the terminal's mode equals the one before.
    #[test]
    fn connect_handoff_restores_terminal_after_exit_and_after_child_signal() {
        let w = World::new();
        w.home
            .write_user_config("Host alpha\n  HostName 127.0.0.1\n")
            .unwrap();
        w.observed("alpha");
        w.stub_ssh(
            "n=$(cat \"$dir/count\" 2>/dev/null || echo 0); n=$((n+1)); echo $n > \"$dir/count\"\n\
             stty -a > \"$dir/stty.$n\" 2>&1\n\
             echo \"$$ $(ps -o pgid= -p $$) $(ps -o pgid= -p $PPID)\" > \"$dir/proc.$n\"\n\
             echo \"STUB-SSH-RUN-$n $*\"\n\
             case $n in 1) exit 7 ;; *) kill -TERM $$ ;; esac",
        );
        let pty = Pty::open(40, 120);
        let before = modes(&pty.termios());
        let tui = started(&w, &pty, &[]);
        let tui_pid = tui.pid();
        let raw = modes(&pty.termios());
        assert_ne!(raw, before, "the TUI runs in raw mode");
        pty.write(b"2");
        w.wait_screen("alpha", LONG, |s| s.contains("alpha"));
        // 1: the child exits 7.
        pty.write(b"c");
        w.wait_screen("the first handoff's end", LONG, |s| {
            s.contains("ssh alpha exited with status 7")
        });
        // 2: the child dies by SIGTERM; the TUI survives it.
        pty.write(b"c");
        w.wait_screen("the second handoff's end", LONG, |s| {
            s.contains("ssh alpha was ended by signal 15")
        });
        assert_eq!(
            modes(&pty.termios()),
            raw,
            "back in the TUI's mode after the handoffs"
        );
        for n in ["1", "2"] {
            // During the handoff the child had a cooked terminal.
            let stty = w.read_mark(&format!("stty.{n}"));
            for flag in ["icanon", "isig", "echo"] {
                assert!(
                    stty.split_whitespace().any(|t| t == flag),
                    "run {n}: {flag} set during the handoff: {stty}"
                );
            }
            // The child ran in the TUI's process group (system(3) model).
            let proc = w.read_mark(&format!("proc.{n}"));
            let fields: Vec<&str> = proc.split_whitespace().collect();
            assert_eq!(fields.len(), 3, "{proc}");
            assert_eq!(
                fields[1], fields[2],
                "the child shares the TUI's group: {proc}"
            );
            assert_eq!(fields[1], tui_pid.to_string(), "{proc}");
        }
        let transcript = pty.transcript();
        assert!(transcript.contains("STUB-SSH-RUN-1 alpha"), "{transcript}");
        assert!(transcript.contains("STUB-SSH-RUN-2 alpha"));
        // Entered once, left and re-entered around each handoff.
        assert_eq!(pty.count("\u{1b}[?1049h"), 3, "{transcript}");
        assert_eq!(pty.count("\u{1b}[?1049l"), 2);
        let left = transcript.find("STUB-SSH-RUN-1").unwrap();
        assert!(
            transcript[..left].contains("\u{1b}[?1049l"),
            "the alternate screen was left before the child ran"
        );
        pty.write(b"q");
        let status = tui.wait(LONG);
        assert_eq!(status.code(), Some(0), "{}", pty.transcript());
        assert_eq!(pty.count("\u{1b}[?1049l"), 3);
        let t = pty.transcript();
        assert!(
            t.rfind("\u{1b}[?25h") > t.rfind("\u{1b}[?1049h"),
            "the cursor is shown again after the last entry"
        );
        assert_eq!(
            modes(&pty.termios()),
            before,
            "the terminal's mode is restored"
        );
        assert_no_canary(&pty.transcript());
    }

    /// ADR-0007 §12.24 item 9 `tui_handoff_ctrl_z_stops_and_fg_resumes_as_one_job`: from
    /// an interactive shell with job control, Ctrl-Z during a connect handoff stops the
    /// TUI and its child together (one process group, SIGTSTP at its default), and `fg`
    /// continues both; the child then finishes and the TUI resumes.
    #[test]
    fn tui_handoff_ctrl_z_stops_and_fg_resumes_as_one_job() {
        let w = World::new();
        w.home
            .write_user_config("Host alpha\n  HostName 127.0.0.1\n")
            .unwrap();
        w.observed("alpha");
        w.stub_ssh(
            "echo \"$$ $PPID\" > \"$dir/pids.tmp\"; mv \"$dir/pids.tmp\" \"$dir/pids\"\n\
             while [ ! -f \"$dir/go\" ]; do echo tick >> \"$dir/beat\"; sleep 0.05; done\n\
             exit 0",
        );
        let pty = Pty::open(40, 120);
        let mut env = w.env();
        env.push(("PS1".into(), "HMSH$ ".into()));
        env.push(("ENV".into(), "/dev/null".into()));
        let shell = pty.start(&env, &w.home.root, &os(&["/bin/sh", "-i"]));
        wait_for("the shell prompt", LONG, || {
            pty.transcript().contains("HMSH$")
        });
        // One simple command: a stopped job in a list would let the shell run the rest.
        pty.write(format!("'{}' tui\n", bin()).as_bytes());
        w.wait_screen("the runtime's listing", LONG, |s| {
            s.contains("Runtime: connected")
        });
        pty.write(b"2");
        w.wait_screen("alpha", LONG, |s| s.contains("alpha"));
        pty.write(b"c");
        wait_for("the child", LONG, || w.mark("pids").exists());
        let pids = w.read_mark("pids");
        let (child, tui): (u32, u32) = {
            let mut it = pids.split_whitespace().map(|p| p.parse::<u32>().unwrap());
            (it.next().unwrap(), it.next().unwrap())
        };
        assert_eq!(ps("pgid", child), ps("pgid", tui), "one process group");
        assert_eq!(
            ps("pgid", tui),
            tui.to_string(),
            "the job's leader is the TUI"
        );
        // Ctrl-Z at the cooked terminal: both stop.
        pty.write(b"\x1a");
        wait_for("both stopped", LONG, || stopped(child) && stopped(tui));
        let beats = w.read_mark("beat").lines().count();
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(
            w.read_mark("beat").lines().count(),
            beats,
            "the child does not run while the job is stopped"
        );
        wait_for("the shell prompt again", LONG, || pty.count("HMSH$") >= 2);
        // fg: both continue.
        pty.write(b"fg\n");
        wait_for("both continued", LONG, || !stopped(child) && !stopped(tui));
        wait_for("the child's heartbeat", LONG, || {
            w.read_mark("beat").lines().count() > beats
        });
        std::fs::write(w.mark("go"), b"").unwrap();
        w.wait_screen("the handoff's end", LONG, |s| {
            s.contains("ssh alpha exited with status 0")
        });
        let prompts = pty.count("HMSH$");
        pty.write(b"q");
        wait_for("the shell prompt after the TUI", LONG, || {
            pty.count("HMSH$") > prompts
        });
        pty.write(b"echo TUI-EXIT=$?\n");
        let deadline = Instant::now() + LONG;
        while !pty.transcript().contains("TUI-EXIT=") {
            assert!(
                Instant::now() < deadline,
                "no exit status: {:?}",
                tail(&pty)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(pty.transcript().contains("TUI-EXIT=0"), "{:?}", tail(&pty));
        pty.write(b"exit\n");
        let status = shell.wait(LONG);
        assert_eq!(status.code(), Some(0), "{}", pty.transcript());
        assert_no_canary(&pty.transcript());
    }

    /// m02-plan U10 `panic_restores_terminal`: a panic of the TUI's thread restores the
    /// terminal (cooked mode, cursor shown, alternate screen left) before the panic
    /// message is printed, and the process exits 101.
    #[test]
    fn panic_restores_terminal() {
        let w = World::new();
        w.stub_ssh("exit 0");
        let pty = Pty::open(24, 80);
        let before = modes(&pty.termios());
        let tui = w.tui(&pty, &[("HEIMDALL_TEST_TUI_PANIC", "after_first_frame")]);
        let status = tui.wait(LONG);
        let transcript = pty.transcript();
        assert_eq!(status.code(), Some(101), "{transcript}");
        let entered = transcript.find("\u{1b}[?1049h").expect("the TUI entered");
        let left = transcript.rfind("\u{1b}[?1049l").expect("the TUI left");
        let message = transcript.find("panicked").expect("the panic message");
        assert!(
            entered < left && left < message,
            "restored before the message: {transcript}"
        );
        assert!(
            transcript[entered..message].contains("\u{1b}[?25h"),
            "cursor shown"
        );
        assert_eq!(
            modes(&pty.termios()),
            before,
            "the terminal's mode is restored"
        );
    }

    /// m02-plan U10 `hangup_watchdog_exits` (REPORT.md §5): when the terminal hangs up
    /// the TUI exits 129 promptly instead of spinning on a dead terminal.
    #[test]
    fn hangup_watchdog_exits() {
        let w = World::new();
        w.stub_ssh("exit 0");
        let mut pty = Pty::open(24, 80);
        let mut tui = started(&w, &pty, &[]);
        let t0 = Instant::now();
        pty.hang_up();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(s) = tui.try_wait() {
                break s;
            }
            assert!(
                Instant::now() < deadline,
                "the TUI is still running {:?} after the hang-up",
                t0.elapsed()
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(129), "{status:?}");
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }

    /// m02-plan U10 `no_cursor_position_query_emitted`: across a session that visits
    /// every view, opens a detail and a modal, resizes the terminal, connects once and
    /// quits, the TUI never writes `ESC[6n` (a cursor-position request a terminal may
    /// never answer).
    #[test]
    fn no_cursor_position_query_emitted() {
        let w = World::new();
        w.home
            .write_user_config("Host alpha\n  HostName 127.0.0.1\n")
            .unwrap();
        w.observed("alpha");
        w.stub_ssh("exit 0");
        let pty = Pty::open(24, 80);
        let tui = started(&w, &pty, &[]);
        for keys in ["2", "\r", "\x1b", "3", "4", "1", "?"] {
            pty.write(keys.as_bytes());
            std::thread::sleep(Duration::from_millis(150));
        }
        pty.write(b"\x1b");
        pty.resize(12, 40);
        w.wait_screen("the narrow layout", LONG, |s| s.lines().count() == 12);
        pty.resize(40, 120);
        w.wait_screen("the wide layout", LONG, |s| s.lines().count() == 40);
        pty.write(b"2c");
        // The re-entry after the handoff is where `Terminal::clear` would ask: stop
        // waiting as soon as a query shows up, so the failure names it.
        wait_for("the handoff's end or a cursor query", LONG, || {
            w.screen().contains("exited with status 0") || pty.transcript().contains("\u{1b}[6n")
        });
        assert!(
            !pty.transcript().contains("\u{1b}[6n"),
            "a cursor-position query was emitted"
        );
        pty.write(b"q");
        assert_eq!(tui.wait(LONG).code(), Some(0));
        let transcript = pty.transcript();
        assert!(
            transcript.contains("\u{1b}[?1049h"),
            "the stream was captured"
        );
        assert!(
            !transcript.contains("\u{1b}[6n"),
            "a cursor-position query was emitted"
        );
    }

    /// m02-plan U10 `decision_modal_requires_typed_yes_default_no`, end to end: a pending
    /// `DeclareInteraction` decision is shown with its decision text; Enter alone and a
    /// typed `no` send nothing (the record stays pending); a typed `yes` completes it
    /// through `Attend` and `Decide`, and the declaration is recorded.
    #[test]
    fn decision_modal_requires_typed_yes_default_no() {
        let w = World::new();
        w.stub_ssh("exit 0");
        let key = FixtureKey::generate();
        let identity = w
            .catalog(CatalogRequest::AdoptIdentity {
                identity: IdentitySpec {
                    source: IdentitySourceSpec::NativeAgent {
                        endpoint: EndpointRef {
                            kind: EndpointKind::UnixSocket,
                            locator: w
                                .home
                                .decoy_agent()
                                .endpoint()
                                .locator()
                                .to_string_lossy()
                                .into_owned(),
                        },
                    },
                    public_key: key.public_line_without_comment(),
                    label: None,
                },
                request_id: w.next_id("adopt"),
            })
            .unwrap();
        let identity = IdentityId::parse(identity["identity_id"].as_str().unwrap()).unwrap();
        let refused = w
            .catalog(CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
                request_id: w.next_id("declare"),
            })
            .unwrap_err();
        let decision = refused
            .next
            .decision_ref
            .clone()
            .expect("a decision record");
        let pending = |w: &World| {
            w.inspect(InspectSubject::Decisions)["decisions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["decision_id"] == decision.as_str())
        };
        assert!(pending(&w));
        let pty = Pty::open(40, 120);
        let tui = started(&w, &pty, &[]);
        pty.write(b"4");
        w.wait_screen("the decision", LONG, |s| s.contains(&decision));
        for typed in ["", "no", "yess"] {
            pty.write(b"\r");
            w.wait_screen("the modal", LONG, |s| {
                flat(s).contains("Heimdall will treat this key as needing no confirmation")
                    && s.contains("[y/N]")
            });
            pty.write(typed.as_bytes());
            pty.write(b"\r");
            w.wait_screen("not confirmed", LONG, |s| s.contains("not confirmed"));
            std::thread::sleep(Duration::from_millis(300));
            assert!(pending(&w), "{typed:?} must send nothing");
        }
        pty.write(b"\r");
        w.wait_screen("the modal", LONG, |s| s.contains("[y/N]"));
        pty.write(b"yes\r");
        wait_for("the decision completed", LONG, || !pending(&w));
        w.wait_screen("the result", LONG, |s| {
            s.contains(&format!("decision {decision}"))
        });
        let declared = w.inspect(InspectSubject::Identities)["identities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| {
                i["identity_id"] == identity.to_string() && i["interaction_basis"] == "declared"
            });
        assert!(declared, "the approved declaration is recorded");
        pty.write(b"q");
        assert_eq!(tui.wait(LONG).code(), Some(0));
        assert_no_canary(&pty.transcript());
    }

    /// m02-plan U10 ⟨r2⟩/⟨r3⟩ `config_commands_authorization_requires_typed_yes`, end to
    /// end: the `evaluate` level shows the authorization text with the line the static
    /// pass found; a typed `no` runs nothing (the stub client is never asked for
    /// `-G`); a typed `yes` runs it once, with isolation arguments only; the result
    /// labels the command list as found before the run.
    #[test]
    fn config_commands_authorization_requires_typed_yes() {
        let w = World::new();
        w.home
            .write_user_config("Host alpha\n  HostName 127.0.0.1\n  ProxyCommand /bin/false\n")
            .unwrap();
        w.observed("alpha");
        w.stub_ssh("exit 0");
        let pty = Pty::open(40, 120);
        let tui = started(&w, &pty, &[]);
        let ran_g = |w: &World| {
            w.read_mark("invocations")
                .lines()
                .filter(|l| l.split_whitespace().any(|a| a == "-G"))
                .count()
        };
        pty.write(b"2");
        w.wait_screen("alpha", LONG, |s| s.contains("alpha"));
        for refusal in ["no", ""] {
            pty.write(b"p");
            w.wait_screen("the probe menu", LONG, |s| s.contains("evaluate"));
            pty.write(b"\x1b[B\r");
            w.wait_screen("the authorization", LONG, |s| {
                flat(s)
                    .contains("runs your configuration's commands with whatever effects they have")
                    && s.contains("~/.ssh/config:3")
                    && s.contains("[y/N]")
            });
            pty.write(refusal.as_bytes());
            pty.write(b"\r");
            w.wait_screen("the decline", LONG, |s| {
                s.contains("config_commands_not_authorized")
            });
            std::thread::sleep(Duration::from_millis(500));
            assert_eq!(ran_g(&w), 0, "{refusal:?}: nothing ran");
        }
        pty.write(b"p");
        w.wait_screen("the probe menu", LONG, |s| s.contains("evaluate"));
        pty.write(b"\x1b[B\r");
        w.wait_screen("the authorization", LONG, |s| s.contains("[y/N]"));
        pty.write(b"yes\r");
        w.wait_screen("the probe result", LONG, |s| {
            flat(s).contains(
                "configuration commands found before the run; the run may have executed others",
            )
        });
        let screen = flat(&w.screen());
        assert!(screen.contains("allow_config_commands"), "{screen}");
        assert!(screen.contains("~/.ssh/config:3"), "{screen}");
        assert_eq!(ran_g(&w), 1, "{}", w.read_mark("invocations"));
        let line = w
            .read_mark("invocations")
            .lines()
            .find(|l| l.split_whitespace().any(|a| a == "-G"))
            .unwrap()
            .to_owned();
        assert!(line.starts_with("-F "), "isolation first: {line}");
        assert!(line.ends_with("-G alpha"), "{line}");
        for forbidden in [
            "IdentityAgent",
            "IdentityFile",
            "IdentitiesOnly",
            "HostName",
        ] {
            assert!(!line.contains(forbidden), "{line}");
        }
        // A lone Escape is decided by a pause (Escape then a key is Alt-key).
        pty.write(b"\x1b");
        w.wait_screen("the result closed", LONG, |s| !s.contains("probe: alpha"));
        pty.write(b"q");
        assert_eq!(tui.wait(LONG).code(), Some(0));
        assert_no_canary(&pty.transcript());
    }

    /// m02-plan U10: first-frame latency, measured and recorded, not gated in M02 (spec
    /// §15.1: P95 ≤ 750 ms from launch, measured in M08). Each sample is from the spawn
    /// of the process to the first frame written, and to the first frame showing the
    /// runtime's listing; the samples are printed for the evidence record.
    #[test]
    fn first_frame_latency_measured_and_recorded() {
        let w = World::new();
        w.observed("alpha");
        w.stub_ssh("exit 0");
        let mut first = Vec::new();
        let mut useful = Vec::new();
        for _ in 0..5 {
            let _ = std::fs::remove_file(w.screen_file());
            let pty = Pty::open(40, 120);
            let t0 = Instant::now();
            let tui = w.tui(&pty, &[]);
            w.wait_screen("the first frame", LONG, |s| s.contains("Overview"));
            first.push(t0.elapsed());
            w.wait_screen("the listing", LONG, |s| s.contains("Runtime: connected"));
            useful.push(t0.elapsed());
            pty.write(b"q");
            assert_eq!(tui.wait(LONG).code(), Some(0));
        }
        first.sort();
        useful.sort();
        let ms = |d: &Duration| d.as_millis();
        eprintln!(
            "M02-U10 tui first-frame latency (debug build, spawn to frame, 5 samples): first frame ms {:?} (p50 {}), with the runtime listing ms {:?} (p50 {}); spec §15.1 budget 750 ms P95, not gated in M02",
            first.iter().map(ms).collect::<Vec<_>>(),
            ms(&first[2]),
            useful.iter().map(ms).collect::<Vec<_>>(),
            ms(&useful[2]),
        );
        assert!(first.iter().all(|d| *d < LONG));
    }
}
