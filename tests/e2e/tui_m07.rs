//! M07-U1 end-to-end: the TUI's idle repaint and A20's completed-frame key latency,
//! through the **real binary** on a pty (`CARGO_BIN_EXE_heimdall`, or
//! `HEIMDALL_E2E_BIN`), against a real `heimdall service run` in a scratch home
//! (m07-plan U1 tests; §6 A20; probes P1 and P2). The test configuration's fixture
//! destinations (`h1`–`h3`) are listed beside the imported ones.
//!
//! **Isolation** (m07-plan rule 4; AGENTS.md). One `tempfile` root per test holds
//! separate `HOME`, `HEIMDALL_HOME` and `HEIMDALL_TEST_SSH_HOME` (with an empty
//! `etc-ssh`) directories, and every `heimdall` this test starts (the runtime, `import`,
//! `access ensure`, the TUI, `service stop`) gets a cleared environment naming only
//! those, the two fixture store paths, and the debug-build test variables the case
//! needs. The harness checks the homes and stores are inside its root. `SSH_AUTH_SOCK` is never
//! set; the verified client `ssh` on `PATH` is a stub script that answers `-V` and
//! contacts nothing. The imported destinations use reserved `.invalid` host names and
//! are never contacted. Only processes this test started are stopped: the runtime by
//! `heimdall service stop` (or its exact `Child` handle if that fails), the TUI by `q`
//! (or its exact handle).
//!
//! **The screen.** Text checks read the frame the TUI drew (`HEIMDALL_TEST_TUI_SCREEN`,
//! debug builds); the idle check reads the raw pty transcript, since any byte counts.
//!
//! **Latency isolation.** The cases of this binary run in parallel, and a latency
//! measurement taken beside them measures the machine's load, not the TUI (the W2 review
//! saw a P95 of 119.6 ms that way, against 8 to 9 ms alone). So every test takes one
//! process-wide guard first and holds it for its whole life, fixture cleanup included:
//! the latency tests exclusively ([`latency_test`]), every other test shared
//! ([`parallel_test`]). No other case of this binary runs during a measurement, and the
//! 100 ms bar stays as it is. A new test takes [`parallel_test`] as its first statement.
//! The PTY and ConPTY child-mode entries run in processes of their own, where the guard
//! is another one and blocks nothing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::sync::{PoisonError, RwLock, RwLockReadGuard};

/// The guard of the module docs' "Latency isolation".
static TEST_EXECUTION: RwLock<()> = RwLock::new(());

/// Held by a test that measures nothing: it may run beside the others, never beside a
/// latency measurement.
fn parallel_test() -> RwLockReadGuard<'static, ()> {
    // The lock carries no state. A panic in a measured case should not fail other tests.
    TEST_EXECUTION
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Held by a test that measures key latency: no other test of this binary runs with it.
#[cfg(any(unix, windows))]
fn latency_test() -> std::sync::RwLockWriteGuard<'static, ()> {
    TEST_EXECUTION
        .write()
        .unwrap_or_else(PoisonError::into_inner)
}

#[cfg(any(unix, windows))]
fn fixture_stores(root: &std::path::Path) -> [std::path::PathBuf; 2] {
    assert!(root.is_absolute() && root.is_dir());
    [root.join("mgmt-store"), root.join("iroh-key-store")]
}

#[cfg(any(unix, windows))]
fn checked_fixture_stores(root: &std::path::Path) -> [std::path::PathBuf; 2] {
    let paths = fixture_stores(root);
    for path in &paths {
        match path.symlink_metadata() {
            Ok(meta) => assert!(meta.is_file(), "redirected fixture store"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::NotFound),
        }
    }
    paths
}

#[cfg(any(unix, windows))]
fn assert_no_fixture_stores(root: &std::path::Path) {
    for store in fixture_stores(root) {
        assert!(
            store
                .symlink_metadata()
                .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound),
            "unexpected fixture store"
        );
    }
}

fn diagnostic_tail(bytes: &[u8], root: &std::path::Path) -> String {
    let mut names: Vec<_> = ["USER", "USERNAME", "LOGNAME", "HOSTNAME", "COMPUTERNAME"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .collect();
    names.sort_unstable_by_key(|name| std::cmp::Reverse(name.len()));
    redact_diagnostic(bytes, root, names.iter().map(String::as_str))
}

fn redact_diagnostic<'a>(
    bytes: &[u8],
    root: &std::path::Path,
    names: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    heimdall_testkit::assert_no_canary(&text);
    let root = root.to_string_lossy();
    for path in [
        root.to_string(),
        root.replace('\\', "/"),
        root.replace('\\', "\\\\"),
    ] {
        redact_value(&mut text, &path, "<scratch>");
    }
    // The shared excerpt sanitizer handles exact-case home paths. Also recognize
    // Windows home segments in mixed case and in JSON diagnostics.
    for marker in [r"\\users\\", r"\users\", "/users/"] {
        for (at, _) in text.to_ascii_lowercase().rmatch_indices(marker) {
            let start = at + marker.len();
            let account = &text[start..];
            let len = account
                .find(['/', '\\', '\'', '"', '\r', '\n'])
                .unwrap_or(account.len());
            if len != 0 {
                text.replace_range(start..start + len, "~");
            }
        }
    }
    for name in names {
        redact_value(&mut text, name, "<redacted>");
    }
    heimdall_enroll::remote::redact_excerpt(text.as_bytes(), 4096)
}

fn redact_value(text: &mut String, value: &str, replacement: &str) {
    if value.is_empty() {
        return;
    }
    let mut ranges = Vec::new();
    let mut end = 0;
    for (start, _) in text.char_indices() {
        if start < end {
            continue;
        }
        let mut rest = text[start..].chars();
        if value.chars().all(|expected| {
            rest.next()
                .is_some_and(|actual| actual.to_uppercase().eq(expected.to_uppercase()))
        }) {
            end = text.len() - rest.as_str().len();
            ranges.push(start..end);
        }
    }
    for range in ranges.into_iter().rev() {
        text.replace_range(range, replacement);
    }
}

#[test]
fn diagnostic_redacts_mixed_case_windows_identifiers() {
    let _guard = parallel_test();
    let stderr = br#"Failed: C:\uSeRs\ExampleUser\ScRaTcH\raw
{"path":"c:\\USerS\\EXAMPLEUSER\\sCrAtCh\\escaped"}
Path: c:/users/exampleuser/SCRATCH/forward
Other: c:\uSeRs\OtherFixture\file c:\\uSeRs\\OtherFixture\\file c:/uSeRs/OtherFixture/file
Account: eXaMpLeUsEr; Machine: example-pc
"#;
    let redacted = redact_diagnostic(
        stderr,
        std::path::Path::new(r"C:\Users\ExampleUser\scratch"),
        ["ExampleUser", "EXAMPLE-PC"],
    );
    assert_eq!(redacted.matches("<scratch>").count(), 3, "{redacted}");
    assert!(
        redacted.contains("Account: <redacted>; Machine: <redacted>"),
        "{redacted}"
    );
    for value in ["exampleuser", "example-pc", "otherfixture"] {
        assert!(!redacted.to_ascii_lowercase().contains(value), "{redacted}");
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
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use heimdall_testkit::assert_no_canary;
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{SpecialCodeIndex, Termios, Winsize, tcgetattr, tcsetwinsize};
    use serde_json::Value;

    const SLAVE: &str = "HM_M07_PTY_SLAVE";
    const ARGV: &str = "HM_M07_PTY_ARGV";
    const LONG: Duration = Duration::from_secs(120);
    /// A20: a sample that shows nothing within this counts as this long.
    const SAMPLE_LIMIT: Duration = Duration::from_secs(2);
    /// A20: samples per key.
    const SAMPLES: usize = 40;

    /// The binary under test.
    fn bin() -> String {
        std::env::var("HEIMDALL_E2E_BIN")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
    }

    /// Child-mode entry of the pty cases: a new session on the pty as its controlling
    /// terminal, then `exec` of the program named in [`ARGV`]. Does nothing in a normal
    /// run.
    #[test]
    #[ignore = "child-mode entry of the pty tests, started by them"]
    fn pty_child() {
        let _guard = super::parallel_test();
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
        heimdall_testkit::term::default_terminal_signals_for_exec().unwrap();
        let err = Command::new(&argv[0]).args(&argv[1..]).exec();
        panic!("exec failed: {err}");
    }

    // ---- the pty (as tests/e2e/tui_m02.rs) ---------------------------------------------

    /// A pseudo-terminal that holds a descriptor of its slave for its whole life (macOS
    /// forgets a pty's window size when the last descriptor of its slave closes;
    /// ADR-0007 §12.32 item 6), and drains the master into a transcript.
    struct Pty {
        master: Option<OwnedFd>,
        slave_fd: Mutex<Option<OwnedFd>>,
        size: Mutex<(u16, u16)>,
        slave: PathBuf,
        output: Arc<Mutex<Vec<u8>>>,
        stop: Arc<AtomicBool>,
        reader: Option<std::thread::JoinHandle<()>>,
    }

    impl Pty {
        fn open(rows: u16, cols: u16) -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
            // Non-blocking, so the drain thread can never sit in `read`: the terminal
            // may discard its output between `poll` saying "readable" and the read (the
            // session leader exiting flushes it), and a blocked reader would hang this
            // test's teardown without a bound.
            rustix::fs::fcntl_setfl(
                &master,
                rustix::fs::fcntl_getfl(&master).unwrap() | rustix::fs::OFlags::NONBLOCK,
            )
            .unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let slave = PathBuf::from(OsStr::from_bytes(name.as_bytes()));
            let slave_fd = rustix::fs::open(
                &slave,
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let output = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
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
                slave_fd: Mutex::new(Some(slave_fd)),
                size: Mutex::new((rows, cols)),
                slave,
                output,
                stop,
                reader: Some(reader),
            };
            let held = pty.held_slave();
            set_size(&held, rows, cols);
            pty
        }

        /// A live descriptor of the held slave (a revoked one is replaced, with the
        /// size the test asked for applied again).
        fn held_slave(&self) -> OwnedFd {
            let mut held = self.slave_fd.lock().unwrap();
            let alive = held
                .as_ref()
                .is_some_and(|fd| rustix::termios::tcgetwinsize(fd).is_ok());
            if !alive {
                let fd = rustix::fs::open(
                    &self.slave,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::NOCTTY
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .unwrap();
                let (rows, cols) = *self.size.lock().unwrap();
                set_size(&fd, rows, cols);
                *held = Some(fd);
            }
            held.as_ref().unwrap().try_clone().unwrap()
        }

        /// Type `bytes` at the terminal. The master is non-blocking, so a full input
        /// queue is waited out, for at most ten seconds.
        fn write(&self, bytes: &[u8]) {
            let fd = self.master.as_ref().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut rest = bytes;
            while !rest.is_empty() {
                match rustix::io::write(fd, rest) {
                    Ok(n) => rest = &rest[n..],
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                        assert!(
                            Instant::now() < deadline,
                            "the terminal took no input for ten seconds"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => panic!("writing to the terminal failed: {e}"),
                }
            }
        }

        /// Resize the terminal (the TUI gets SIGWINCH).
        fn resize(&self, rows: u16, cols: u16) {
            *self.size.lock().unwrap() = (rows, cols);
            set_size(&self.held_slave(), rows, cols);
        }

        /// The terminal's current mode, read through the slave.
        fn termios(&self) -> Termios {
            tcgetattr(self.held_slave()).unwrap()
        }

        /// How often `needle` occurs in the transcript.
        fn count(&self, needle: &str) -> usize {
            String::from_utf8_lossy(&self.bytes())
                .matches(needle)
                .count()
        }

        /// Every byte the terminal received so far.
        fn bytes(&self) -> Vec<u8> {
            self.output.lock().unwrap().clone()
        }

        /// The test entry's child mode running `argv` on this terminal.
        fn start(&self, env: &[(OsString, OsString)], cwd: &Path, argv: &[OsString]) -> Proc {
            drop(self.held_slave());
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
            Proc {
                child: Some(child),
                output: Arc::clone(&self.output),
                scratch: cwd.parent().unwrap_or(cwd).to_owned(),
            }
        }
    }

    fn set_size(fd: &OwnedFd, rows: u16, cols: u16) {
        tcsetwinsize(
            fd,
            Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .unwrap();
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

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(r) = self.reader.take() {
                let _ = r.join();
            }
        }
    }

    /// A process this test started, killed through its own handle if the test fails.
    struct Proc {
        child: Option<Child>,
        output: Arc<Mutex<Vec<u8>>>,
        scratch: PathBuf,
    }

    impl Proc {
        #[track_caller]
        fn wait(mut self, limit: Duration) {
            let mut child = self.child.take().unwrap();
            let logs = || super::diagnostic_tail(&self.output.lock().unwrap(), &self.scratch);
            let deadline = Instant::now() + limit;
            loop {
                if let Some(s) = child.try_wait().unwrap() {
                    assert!(
                        s.success(),
                        "the TUI exited with {s}; terminal tail: {:?}",
                        logs()
                    );
                    return;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "the TUI did not finish within {limit:?}; terminal tail: {:?}",
                        logs()
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    // ---- the runtime -------------------------------------------------------------------

    /// One scratch root with a runtime (`heimdall service run`) serving it.
    struct World {
        root: tempfile::TempDir,
        home: PathBuf,
        heimdall_home: PathBuf,
        ssh_home: PathBuf,
        stubs: PathBuf,
        service: Option<Child>,
    }

    impl World {
        /// A scratch root and a runtime; `service_env` adds debug-build test variables
        /// to the runtime only (the fixture adapter, its slowness).
        fn new(service_env: &[(&str, &str)]) -> World {
            World::start(service_env, None)
        }

        /// As [`World::new`], with `managed` managed destinations and `enrollments` held
        /// enrollment records put into the scratch state store before the runtime first
        /// starts ([`seed_store`]).
        fn seeded(managed: usize, enrollments: usize) -> World {
            World::start(&[], Some((managed, enrollments)))
        }

        fn start(service_env: &[(&str, &str)], seed: Option<(usize, usize)>) -> World {
            let root = tempfile::Builder::new()
                .prefix("hm-m07-")
                .tempdir()
                .unwrap();
            let home = root.path().join("home");
            let heimdall_home = root.path().join("hh");
            let ssh_home = root.path().join("sshhome");
            let stubs = root.path().join("stubs");
            for d in [&home, &heimdall_home, &stubs] {
                std::fs::create_dir(d).unwrap();
            }
            std::fs::create_dir_all(ssh_home.join("etc-ssh")).unwrap();
            // Rule 4: every scratch directory is inside this test's own root, and they
            // are separate, before anything is launched.
            let base = root.path().canonicalize().unwrap();
            for d in [&home, &heimdall_home, &ssh_home] {
                assert!(d.canonicalize().unwrap().starts_with(&base), "{d:?}");
            }
            assert!(home != heimdall_home && home != ssh_home && heimdall_home != ssh_home);
            // The verified client is a stub that contacts nothing.
            let stub = stubs.join("ssh");
            std::fs::write(
                &stub,
                "#!/bin/sh\n# hm-m07 stub ssh: contacts nothing.\nfor a in \"$@\"; do\n  case \"$a\" in\n    -V) echo 'OpenSSH_9.9p1 hm-m07-stub' >&2; exit 0 ;;\n  esac\ndone\nexit 0\n",
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            let mut w = World {
                root,
                home,
                heimdall_home,
                ssh_home,
                stubs,
                service: None,
            };
            if let Some((managed, enrollments)) = seed {
                seed_store(&w.heimdall_home, managed, enrollments);
            }
            let log = std::fs::File::create(w.root.path().join("service.log")).unwrap();
            let mut cmd = Command::new(bin());
            cmd.args(["service", "run"])
                .env_clear()
                .envs(w.env())
                .envs(service_env.iter().copied())
                .current_dir(&w.home)
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log);
            w.service = Some(cmd.spawn().unwrap());
            let deadline = Instant::now() + LONG;
            loop {
                let out = w.cli(&["--json", "service", "status"]);
                if out.status.success() {
                    break;
                }
                if let Some(s) = w.service.as_mut().unwrap().try_wait().unwrap() {
                    panic!("the runtime exited early ({s}): {}", w.service_log());
                }
                assert!(
                    Instant::now() < deadline,
                    "the runtime did not start; service tail: {:?}\n{}",
                    w.service_log(),
                    w.cli_diagnostics(&out)
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            w
        }

        /// The launch environment every `heimdall` of this test gets (rule 4).
        fn env(&self) -> Vec<(OsString, OsString)> {
            let [mgmt, iroh] = super::checked_fixture_stores(self.root.path());
            let mut path = self.stubs.clone().into_os_string();
            path.push(":/usr/bin:/bin:/usr/sbin:/sbin");
            vec![
                ("PATH".into(), path),
                ("LANG".into(), "en_US.UTF-8".into()),
                ("TERM".into(), "xterm-256color".into()),
                ("HOME".into(), self.home.clone().into_os_string()),
                (
                    "HEIMDALL_HOME".into(),
                    self.heimdall_home.clone().into_os_string(),
                ),
                (
                    "HEIMDALL_TEST_SSH_HOME".into(),
                    self.ssh_home.clone().into_os_string(),
                ),
                ("HEIMDALL_TEST_SECRET_STORE".into(), "scratch".into()),
                (
                    "HEIMDALL_TEST_MGMT_STORE".into(),
                    format!("fixture-file:{}", mgmt.to_str().unwrap()).into(),
                ),
                ("HEIMDALL_TEST_IROH_KEY_STORE".into(), iroh.into()),
                // A first start writes without an attended `time confirm`.
                ("HEIMDALL_TEST_TIME_SYNC".into(), "synchronized".into()),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                (
                    "GIT_CONFIG_GLOBAL".into(),
                    self.home.join(".gitconfig").into_os_string(),
                ),
            ]
        }

        fn service_log(&self) -> String {
            let bytes = std::fs::read(self.root.path().join("service.log")).unwrap_or_default();
            super::diagnostic_tail(&bytes, self.root.path())
        }

        /// `heimdall <args>` with stdin closed, both streams scanned for canaries.
        fn cli(&self, args: &[&str]) -> std::process::Output {
            let out = Command::new(bin())
                .args(args)
                .env_clear()
                .envs(self.env())
                .current_dir(&self.home)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_no_canary(&String::from_utf8_lossy(&out.stdout));
            assert_no_canary(&String::from_utf8_lossy(&out.stderr));
            out
        }

        fn cli_diagnostics(&self, out: &std::process::Output) -> String {
            format!(
                "exit {}; stdout tail: {:?}\nstderr tail: {:?}",
                out.status,
                super::diagnostic_tail(&out.stdout, self.root.path()),
                super::diagnostic_tail(&out.stderr, self.root.path())
            )
        }

        fn json(&self, args: &[&str]) -> Value {
            let out = self.cli(args);
            assert!(
                out.status.success(),
                "CLI failed: {}",
                self.cli_diagnostics(&out)
            );
            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
                panic!("CLI returned invalid JSON: {}", self.cli_diagnostics(&out))
            })
        }

        /// Import `n` observed destinations `host-<first>`… as one portable bundle,
        /// which must stay under the 1 MiB bundle cap.
        fn import(&self, first: usize, n: usize) {
            let destinations: Vec<Value> = (first..first + n)
                .map(|i| {
                    serde_json::json!({
                        "id": format!("d{i:06}"),
                        "alias": format!("host-{i:06}"),
                        "hostname": format!("h{i:06}.example.invalid"),
                        "account": "probe",
                        "port": 22,
                    })
                })
                .collect();
            let bundle = serde_json::json!({
                "schema": "heimdall-portable/1",
                "created_at": "2026-11-21T00:00:00Z",
                "destinations": destinations,
            });
            let path = self.root.path().join(format!("bundle-{first}.json"));
            let text = serde_json::to_vec(&bundle).unwrap();
            assert!(text.len() < 1024 * 1024, "bundle of {} bytes", text.len());
            std::fs::write(&path, text).unwrap();
            let v = self.json(&["--json", "import", path.to_str().unwrap(), "--yes"]);
            assert_eq!(v["code"], "OK", "{v}");
        }

        /// Replace the verified client on `PATH` with `script` (a `/bin/sh` script).
        fn write_ssh(&self, script: &str) {
            let stub = self.stubs.join("ssh");
            std::fs::write(&stub, script).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn screen_file(&self) -> PathBuf {
            self.root.path().join("screen.txt")
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
                    "timed out waiting for {what}; the last frame:\n{}",
                    super::diagnostic_tail(screen.as_bytes(), self.root.path())
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// `heimdall tui` on `pty`, with only the frame dump added to the environment.
        fn tui(&self, pty: &Pty) -> Proc {
            let mut env = self.env();
            env.push((
                "HEIMDALL_TEST_TUI_SCREEN".into(),
                self.screen_file().into_os_string(),
            ));
            pty.start(&env, &self.home, &[OsString::from(bin()), "tui".into()])
        }

        /// How many destinations the catalog lists (the imported ones and the test
        /// configuration's fixture destinations).
        fn destination_count(&self) -> usize {
            let v = self.json(&["--json", "inspect", "destinations"]);
            ["items", "destinations"]
                .iter()
                .find_map(|k| v["data"][k].as_array())
                .map_or(0, Vec::len)
        }

        /// Start the TUI and wait until the listing of `n` destinations and the
        /// static pass are on the screen.
        fn started(&self, pty: &Pty, n: usize) -> Proc {
            let p = self.tui(pty);
            self.wait_screen("the first frame", LONG, |s| s.contains("Overview"));
            self.wait_screen("the runtime's listing", LONG, |s| {
                s.contains("Runtime: connected")
            });
            let count = format!("; {n} destinations");
            self.wait_screen("the static pass and the listing", LONG, |s| {
                s.contains(&count) && !s.contains("Static pass: running")
            });
            p
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            let Some(mut child) = self.service.take() else {
                return;
            };
            // `service stop` validates the advertised PID of this home's own runtime.
            let _ = self.cli(&["--json", "service", "stop"]);
            let deadline = Instant::now() + Duration::from_secs(30);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if child.try_wait().ok().flatten().is_none() {
                // The exact child this test started.
                let _ = child.kill();
                let _ = child.wait();
            }
            if !std::thread::panicking() {
                let _ = self.service_log();
                super::assert_no_fixture_stores(self.root.path());
            }
        }
    }

    /// Put `managed` managed destinations (`m000000`…, `.invalid` host names) and
    /// `enrollments` held enrollment records (one per destination, from the first) into
    /// the state store of the scratch home `heimdall_home`, before any runtime has
    /// started there. This is the store's own test seeding, as tests/e2e/tui_m03.rs uses
    /// it: `import` creates observed destinations only, and each managed destination is a
    /// Settings connection row (M07-W0-R06). Nothing here names a real host, key or
    /// agent; a held record waits for the owner, so the runtime acts on none of it.
    fn seed_store(heimdall_home: &Path, managed: usize, enrollments: usize) {
        use heimdall_contract::Timestamp;
        use heimdall_contract::ids::{
            AccountName, CaFingerprint, DestinationId, EnrollmentId, IdentityId,
        };
        use heimdall_contract::issuer::{CaState, StoreKind};
        use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
        use heimdall_domain::enrollment::{
            ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentHold, EnrollmentRecord,
            EnrollmentState, ExistingAccessRecord, HoldReason, NoProxy, RegistryCanonical,
            RegistryRef, RegistryResolvedBy, marker_for,
        };
        use heimdall_store::{IssuerRecord, NoFaults, Store};
        use std::os::unix::fs::DirBuilderExt as _;
        assert!(enrollments <= managed);
        let state = heimdall_home.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        let at: Timestamp = "2026-11-01T00:00:00Z".parse().unwrap();
        let account = AccountName::parse("deploy").unwrap();
        let identity = IdentityId::from_random_bytes([0x41; 16]);
        let ca = CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap();
        let destination = |n: usize| DestinationId::parse(&format!("dm{n:06}")).unwrap();
        let store = Store::open(&state.join("state.db"), Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                for n in 0..managed {
                    tx.upsert_destination(&DestinationRecord {
                        id: destination(n),
                        alias: format!("m{n:06}"),
                        revision: 1,
                        definition: DestinationDefinition::Managed {
                            hostname: format!("m{n:06}.example.invalid"),
                            port: None,
                            account: account.clone(),
                            identity: identity.clone(),
                            jump: None,
                        },
                        label: None,
                        updated_at: at,
                    })?;
                }
                if enrollments > 0 {
                    tx.insert_issuer(&IssuerRecord {
                        ca_fingerprint: ca.clone(),
                        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture0".into(),
                        state: CaState::Active,
                        store_kind: StoreKind::LinuxSecretService,
                        backup_sha256: "00".repeat(32),
                        backup_created_at: at,
                        restored_without_log: false,
                        created_at: at,
                        retired_at: None,
                    })?;
                }
                for n in 0..enrollments {
                    let mut bytes = [0u8; 16];
                    bytes[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
                    let id = EnrollmentId::from_random_bytes(bytes);
                    tx.seed_enrollment(&EnrollmentRecord {
                        marker: marker_for(&id),
                        id,
                        destination: destination(n),
                        account: account.clone(),
                        ca_fingerprint: ca.clone(),
                        form: EnrollmentForm::Account,
                        registry: RegistryRef {
                            path_display: "~/.ssh/authorized_keys".into(),
                            resolved_by: RegistryResolvedBy::RemoteHome,
                        },
                        registry_canonical: RegistryCanonical {
                            path: None,
                            resolved_by: RegistryResolvedBy::RemoteHome,
                        },
                        line_sha256: "ab".repeat(32),
                        target: ApprovedTarget {
                            hostname: format!("m{n:06}.example.invalid"),
                            port: 22,
                            user: account.clone(),
                            proxy: NoProxy::None,
                            host_key: ApprovedHostKey {
                                algorithm: "ssh-ed25519".into(),
                                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                                fingerprint: "SHA256:hostfixture".into(),
                            },
                        },
                        existing_access: ExistingAccessRecord {
                            identity: identity.clone(),
                            endpoint: None,
                            public_key_file: None,
                        },
                        hold: Some(EnrollmentHold {
                            reason: HoldReason::HostKeyChanged,
                            evidence_based: false,
                        }),
                        removal_origin: None,
                        late_write: None,
                        state: EnrollmentState::Held,
                        verified_at: None,
                        evidence: None,
                        created_at: at,
                        updated_at: at,
                    })?;
                }
                Ok(())
            })
            .unwrap();
    }

    /// A loopback fixture for the `network` probe level (m07-plan U1c): a listener on
    /// `127.0.0.1` (an ephemeral port; never a public address) that counts the
    /// connections it accepts and answers each with an SSH identification line, then
    /// closes it. It reads nothing and speaks no SSH beyond that line.
    struct BannerFixture {
        port: u16,
        accepted: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl BannerFixture {
        fn start() -> BannerFixture {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let accepted = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let (count, done) = (accepted.clone(), stop.clone());
            let thread = std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            count.fetch_add(1, Ordering::SeqCst);
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.write_all(b"SSH-2.0-hm-m07-banner-fixture\r\n");
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            BannerFixture {
                port,
                accepted,
                stop,
                thread: Some(thread),
            }
        }

        /// How many connections the fixture has accepted so far.
        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
    }

    impl Drop for BannerFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// The selected tab's number, from the header (`[2 Destinations]`).
    fn selected_tab(screen: &str) -> Option<u8> {
        let header = screen.lines().next()?;
        (1..=8u8).find(|d| header.contains(&format!("[{d} ")))
    }

    /// The selected list row (`> ...`), trimmed.
    fn selected_row(screen: &str) -> Option<String> {
        screen
            .lines()
            .find(|l| l.starts_with("> "))
            .map(|l| l.trim().to_owned())
    }

    /// The nearest-rank percentile of sorted `xs`.
    fn pct(xs: &[Duration], p: usize) -> Duration {
        let rank = (p * xs.len()).div_ceil(100).max(1);
        xs[rank - 1]
    }

    fn uname() -> String {
        let out = Command::new("/usr/bin/uname").arg("-srm").output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// The seconds into the current UTC minute (the TUI's minute boundary).
    fn second_of_minute() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 60
    }

    // ---- the tests ---------------------------------------------------------------------

    /// m07-plan U1, probe P1: once the first frame and the runtime's listing have
    /// settled, an idle TUI writes nothing between minute ticks: the 3 s poll whose
    /// answers change nothing draws nothing, and relative times move only once a minute.
    #[test]
    fn idle_tui_writes_nothing_between_minute_ticks() {
        let _guard = super::parallel_test();
        let w = World::new(&[]);
        w.import(0, 100);
        let n = w.destination_count();
        assert!(n >= 100, "{n}");
        let pty = Pty::open(40, 120);
        let tui = w.started(&pty, n);
        // Two polls after the static pass, then a window inside one minute.
        std::thread::sleep(Duration::from_secs(7));
        const WINDOW: u64 = 12;
        let s = second_of_minute();
        if !(2..60 - WINDOW - 3).contains(&s) {
            std::thread::sleep(Duration::from_secs(60 - s + 2));
        }
        let before = pty.bytes().len();
        let screen_before = w.screen();
        std::thread::sleep(Duration::from_secs(WINDOW));
        let after = pty.bytes();
        let written = &after[before..];
        eprintln!(
            "M07-U1 idle: {} bytes written in {WINDOW} s between minute ticks (120x40, 100 destinations; host {})",
            written.len(),
            uname()
        );
        assert!(
            written.is_empty(),
            "an idle TUI wrote {} bytes in {WINDOW} s: {:?}",
            written.len(),
            String::from_utf8_lossy(written)
        );
        assert_eq!(w.screen(), screen_before, "no frame was drawn");
        // Still alive: a key draws at once.
        pty.write(b"\t");
        w.wait_screen("the Destinations tab", LONG, |s| selected_tab(s) == Some(2));
        pty.write(b"q");
        tui.wait(LONG);
        assert!(
            String::from_utf8_lossy(&pty.bytes()).contains("\u{1b}[?1049l"),
            "the alternate screen was left"
        );
    }

    /// One A20 sample: write `key`, then time until a frame satisfying `shown` is on
    /// screen; a sample that times out counts as [`SAMPLE_LIMIT`] and is reported.
    fn sample(w: &World, pty: &Pty, key: &[u8], shown: impl Fn(&str) -> bool) -> (Duration, bool) {
        let t0 = Instant::now();
        pty.write(key);
        loop {
            if shown(&w.screen()) {
                return (t0.elapsed(), false);
            }
            if t0.elapsed() >= SAMPLE_LIMIT {
                return (SAMPLE_LIMIT, true);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The catalog of [`a20_key_latency`], for [`report`].
    const OBSERVED_CATALOG: &str = "5000 destinations, a live slow operation";

    /// Report one key's samples over the catalog `what`; returns its P95.
    fn report(
        what: &str,
        key: &str,
        mut samples: Vec<Duration>,
        timeouts: usize,
        host: &str,
    ) -> Duration {
        samples.sort();
        let (p50, p95) = (pct(&samples, 50), pct(&samples, 95));
        eprintln!(
            "M07 A20 key latency (debug build, completed frame showing the key's effect, {what}): key {key}: samples {}, timeouts at 2 s {timeouts}, p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms; host {host}",
            samples.len(),
            p50.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0,
            samples.last().unwrap().as_secs_f64() * 1000.0,
        );
        eprintln!(
            "  {key} samples (ms, sorted): {:?}",
            samples
                .iter()
                .map(|d| (d.as_secs_f64() * 10_000.0).round() / 10.0)
                .collect::<Vec<_>>()
        );
        p95
    }

    /// m07-plan U1 / §6 A20: with 5000 observed destinations (two `import` bundles of
    /// 2500, each under 1 MiB) and a live slow operation, Tab, PageDown on Destinations
    /// and a search keystroke on Destinations each take at least 40 samples, timed from
    /// the key's write to the completed frame that shows its effect (the selected tab
    /// changes; the selection moves; the result count changes), read from the frame
    /// dump. P95 ≤ 100 ms is asserted on macOS only (the A20 bar); elsewhere recorded.
    #[test]
    fn a20_key_latency() {
        let _guard = super::latency_test();
        let w = World::new(&[
            ("HEIMDALL_TEST_ADAPTER", "prepare"),
            ("HEIMDALL_TEST_SLOW_PREPARE_MS", "600000"),
        ]);
        w.import(0, 2500);
        w.import(2500, 2500);
        // The live slow operation: an ensure whose prepare waits 10 minutes.
        let ensure = w.json(&[
            "--json",
            "access",
            "ensure",
            "--profile",
            "dev",
            "--work-id",
            "m07-a20",
            "--request-id",
            "m07-a20-1",
            "--pair",
            "h1:deploy",
            "--async",
        ]);
        let op = ensure["operation_id"].as_str().unwrap().to_owned();
        let n = w.destination_count();
        assert!(n >= 5000, "{n}");
        let pty = Pty::open(40, 120);
        let tui = w.started(&pty, n);
        w.wait_screen("the live operation", LONG, |s| s.contains("[..] working:"));
        let host = uname();
        let mut p95s = Vec::new();

        // Tab: the selected tab changes.
        let mut tab = Vec::new();
        let mut timeouts = 0;
        for _ in 0..SAMPLES {
            let now = selected_tab(&w.screen()).unwrap();
            let next = now % 8 + 1;
            let (d, timed_out) = sample(&w, &pty, b"\t", |s| selected_tab(s) == Some(next));
            tab.push(d);
            timeouts += usize::from(timed_out);
            if timed_out {
                w.wait_screen("the tab", LONG, |s| selected_tab(s) == Some(next));
            }
        }
        p95s.push(("Tab", report(OBSERVED_CATALOG, "Tab", tab, timeouts, &host)));

        // PageDown on Destinations: the selection moves.
        pty.write(b"2");
        w.wait_screen("the Destinations tab", LONG, |s| {
            selected_tab(s) == Some(2) && selected_row(s).is_some()
        });
        let mut page = Vec::new();
        let mut timeouts = 0;
        for _ in 0..SAMPLES {
            let before = selected_row(&w.screen()).unwrap();
            let moved = |s: &str| selected_row(s).is_some_and(|r| r != before);
            let (d, timed_out) = sample(&w, &pty, b"\x1b[6~", moved);
            page.push(d);
            timeouts += usize::from(timed_out);
            if timed_out {
                w.wait_screen("the selection", LONG, moved);
            }
        }
        p95s.push((
            "PageDown",
            report(OBSERVED_CATALOG, "PageDown", page, timeouts, &host),
        ));

        // A search keystroke on Destinations: the result count changes (100 ⇄ 10).
        pty.write(b"/host-0001");
        w.wait_screen("the search", LONG, |s| s.contains("(100 of "));
        let mut search = Vec::new();
        let mut timeouts = 0;
        for i in 0..SAMPLES {
            let (key, count): (&[u8], &str) = if i % 2 == 0 {
                (b"2", "(10 of ")
            } else {
                (b"\x7f", "(100 of ")
            };
            let (d, timed_out) = sample(&w, &pty, key, |s| s.contains(count));
            search.push(d);
            timeouts += usize::from(timed_out);
            if timed_out {
                w.wait_screen("the result count", LONG, |s| s.contains(count));
            }
        }
        p95s.push((
            "search",
            report(
                OBSERVED_CATALOG,
                "search keystroke",
                search,
                timeouts,
                &host,
            ),
        ));

        // The slow operation was live throughout.
        let shown = w.json(&["--json", "operation", "show", &op]);
        assert_eq!(shown["state"], "running", "{shown}");
        pty.write(b"\x1b");
        w.wait_screen("the search closed", LONG, |s| {
            s.contains(" total · / to search")
        });
        pty.write(b"q");
        tui.wait(LONG);
        let _ = w.cli(&["--json", "operation", "cancel", &op]);
        if cfg!(target_os = "macos") {
            for (key, p95) in p95s {
                assert!(
                    p95 <= Duration::from_millis(100),
                    "A20: {key} completed-frame P95 {p95:?} exceeds 100 ms on {host}"
                );
            }
        }
    }

    /// M07-W0-R06 (A20's sibling case): Settings and Activity do no catalog-sized work per
    /// key. With 4000 **managed** destinations (each a Settings connection row; seeded
    /// into the scratch store, since `import` creates observed ones) and 1000 enrollment
    /// records (the Activity list), PageDown on Settings and on Activity each take at
    /// least 40 samples, timed as in [`a20_key_latency`]: from the key's write to the
    /// completed frame in which the selection has moved. P95 ≤ 100 ms is asserted on macOS
    /// only; elsewhere recorded. (Before the fix a debug frame of Settings took about
    /// 79 ms for 5000 managed rows in the review's TestBackend probe.)
    ///
    /// **Why 4000 and not 5000.** A managed destination is about 254 bytes of `inspect
    /// destinations`, and one answer is one control frame of at most 1 MiB: at 5000 the
    /// runtime answers `INTERNAL_ERROR`, "response exceeds the frame limit" (observed
    /// here; U3's D19 and paged loading are later work), and the TUI then has no
    /// connection rows at all. 4000 is the largest round catalog the runtime can list.
    #[test]
    fn a20_key_latency_settings_and_activity() {
        const MANAGED: usize = 4000;
        const ENROLLMENTS: usize = 1000;
        const CATALOG: &str = "4000 managed destinations, 1000 enrollment records";
        let _guard = super::latency_test();
        let w = World::seeded(MANAGED, ENROLLMENTS);
        let n = w.destination_count();
        assert!(n >= MANAGED, "{n}");
        let listed = w.json(&["--json", "inspect", "enrollments"]);
        assert_eq!(
            listed["data"]["enrollments"].as_array().map(Vec::len),
            Some(ENROLLMENTS),
            "the runtime lists every seeded record"
        );
        let pty = Pty::open(40, 120);
        let tui = w.started(&pty, n);
        let host = uname();
        let mut p95s = Vec::new();
        for (tab, name, deep) in [
            (b"8", "Settings", "(read-only here)"),
            (b"4", "Activity", "held"),
        ] {
            pty.write(tab);
            let number = tab[0] - b'0';
            w.wait_screen(&format!("the {name} tab"), LONG, |s| {
                selected_tab(s) == Some(number) && selected_row(s).is_some()
            });
            let mut samples = Vec::new();
            let mut timeouts = 0;
            for _ in 0..SAMPLES {
                let before = selected_row(&w.screen()).unwrap();
                let moved = |s: &str| selected_row(s).is_some_and(|r| r != before);
                let (d, timed_out) = sample(&w, &pty, b"\x1b[6~", moved);
                samples.push(d);
                timeouts += usize::from(timed_out);
                if timed_out {
                    w.wait_screen("the selection", LONG, moved);
                }
            }
            // 40 pages down: a row deep in the catalog-sized part of the list.
            let row = selected_row(&w.screen()).unwrap();
            assert!(row.contains(deep), "{name}: {row}");
            let key = format!("PageDown on {name}");
            p95s.push((key.clone(), report(CATALOG, &key, samples, timeouts, &host)));
        }
        pty.write(b"q");
        tui.wait(LONG);
        if cfg!(target_os = "macos") {
            for (key, p95) in p95s {
                assert!(
                    p95 <= Duration::from_millis(100),
                    "A20: {key} completed-frame P95 {p95:?} exceeds 100 ms on {host}"
                );
            }
        }
    }

    /// M07-W0-R03 end to end: a runtime that stops while the TUI is open (the transport
    /// failure drops the session mid-refresh) is published, not lost. The list that was
    /// read stays on screen, scrolled as it was, and a row under the header says that
    /// what is shown was read earlier; the overview is not Ready and claims nothing about
    /// running work.
    #[test]
    fn a_stopped_runtime_is_shown_as_stale_not_ready() {
        let _guard = super::parallel_test();
        let w = World::new(&[]);
        w.import(0, 100);
        let n = w.destination_count();
        let pty = Pty::open(40, 120);
        let tui = w.started(&pty, n);
        assert!(
            !w.screen()
                .lines()
                .nth(1)
                .unwrap_or_default()
                .starts_with("[!!]"),
            "no indicator while the listings are current:\n{}",
            w.screen()
        );
        // The Destinations list, scrolled well past its first screen.
        pty.write(b"2");
        w.wait_screen("the Destinations tab", LONG, |s| {
            selected_tab(s) == Some(2) && selected_row(s).is_some()
        });
        for _ in 0..6 {
            let before = selected_row(&w.screen()).unwrap();
            pty.write(b"\x1b[6~");
            w.wait_screen("the selection", LONG, |s| {
                selected_row(s).is_some_and(|r| r != before)
            });
        }
        let row = selected_row(&w.screen()).unwrap();
        // The runtime stops (this test's own, by its own home's `service stop`).
        let stopped = w.cli(&["--json", "service", "stop"]);
        assert!(
            stopped.status.success(),
            "service stop: {}",
            w.cli_diagnostics(&stopped)
        );
        // Within the next polls: the indicator, outside the list, and no health claim.
        let indicator = |s: &str| {
            s.lines()
                .nth(1)
                .is_some_and(|l| l.starts_with("[!!] ") && l.contains("what is shown was read"))
        };
        w.wait_screen("the stale indicator", LONG, indicator);
        let screen = w.screen();
        assert!(screen.lines().next().unwrap().contains("[??]"), "{screen}");
        assert_eq!(
            selected_row(&screen).as_deref(),
            Some(row.as_str()),
            "the list read before is still shown, where it was:\n{screen}"
        );
        // The overview: not Ready, and nothing claimed about what runs.
        pty.write(b"1");
        w.wait_screen("the overview", LONG, |s| {
            selected_tab(s) == Some(1) && s.contains("[??] Not known")
        });
        let screen = w.screen();
        assert!(indicator(&screen), "{screen}");
        for claim in ["[OK] Ready", "no work running", "Nothing needs you"] {
            assert!(!screen.contains(claim), "{claim}:\n{screen}");
        }
        pty.write(b"q");
        tui.wait(LONG);
    }

    // ---- U1b: the keyboard walkthrough and the standalone journey ------------------------

    /// Each view's title and a line only it draws.
    const VIEWS: [(&str, &str); 8] = [
        ("Overview", "Pause or stop access: press s"),
        ("Destinations", " total · / to search"),
        ("Profiles", " total · / to search"),
        ("Activity", "Pending decisions"),
        ("Projects", "Standing access"),
        ("Environments", "environment(s) the runtime knows"),
        ("Identities", "adopted identit"),
        (
            "Settings",
            "Default profile (a preference, never authority)",
        ),
    ];

    /// The footer: the frame's last line.
    fn footer(screen: &str) -> String {
        screen.lines().last().unwrap_or_default().to_owned()
    }

    /// At the current size: the selected row is still `row` and on screen, the footer is
    /// the whole key-hint line for the width, and the search's results are shown.
    fn assert_walk_state(w: &World, rows: usize, cols: usize, row: &str) {
        let narrow = cols < 60;
        let hints = if narrow {
            "/ search · Enter open · ? help · q quit"
        } else {
            "/ search · Enter detail · c connect · p probes · ? help · q quit"
        };
        w.wait_screen(&format!("the {cols}x{rows} frame"), LONG, |s| {
            s.lines().count() == rows
                && selected_row(s).is_some_and(|r| r.contains(row))
                && footer(s) == hints
                && s.contains("Filter: host-00001  (10 of")
        });
        let screen = w.screen();
        assert!(
            screen.lines().all(|l| l.chars().count() <= cols),
            "{cols}x{rows}: a row wider than the terminal:\n{screen}"
        );
        let header = screen.lines().next().unwrap();
        if narrow {
            assert!(header.starts_with("[2 Destinations] 2/8"), "{header}");
        } else {
            assert!(
                header.contains("[2 Destinations]") && header.contains("8 Settings"),
                "{header}"
            );
        }
    }

    /// m07-plan U1 `a20_keyboard_walkthrough` (A20): with a live slow fixture operation
    /// (`HEIMDALL_TEST_ADAPTER=prepare`, `HEIMDALL_TEST_SLOW_PREPARE_MS`), keyboard only:
    /// every view by number and by Tab (and Shift-Tab); a search on Destinations, a detail
    /// and back; a resize 120x40 → 40x12 → 120x40 with, at each size, the selected row
    /// still selected and visible, the footer's key hints readable and the search results
    /// shown; the stop menu opened and escaped; a stop whose keys arrive in one batch, with
    /// no frame between them, refused (the M07-W0-R01 ruling for the stop menu); the
    /// operation's detail opened and `x` pressed in one batch, which cancels nothing, then
    /// the operation cancelled with `x` once its detail is on screen (m07-plan U1c); the
    /// `network` probe of an alias that names a loopback fixture, not run by a batch that
    /// opens the menu and presses Enter, then run once the menu is on screen (U1c); `?`;
    /// and `q`, with the terminal's modes byte-identical to before.
    #[test]
    fn a20_keyboard_walkthrough() {
        let _guard = super::parallel_test();
        let w = World::new(&[
            ("HEIMDALL_TEST_ADAPTER", "prepare"),
            ("HEIMDALL_TEST_SLOW_PREPARE_MS", "600000"),
        ]);
        w.import(0, 30);
        let ensure = w.json(&[
            "--json",
            "access",
            "ensure",
            "--profile",
            "dev",
            "--work-id",
            "m07-walk",
            "--request-id",
            "m07-walk-1",
            "--pair",
            "h1:deploy",
            "--async",
        ]);
        let op = ensure["operation_id"].as_str().unwrap().to_owned();
        // m07-plan U1c: an observed alias that the scratch configuration (the static
        // pass's too) points at a loopback fixture, the only thing a probe here contacts.
        const PROBED: &str = "hm-m07-probed";
        let banner = BannerFixture::start();
        let ssh_dir = w.ssh_home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(
            ssh_dir.join("config"),
            format!(
                "Host {PROBED}\n    HostName 127.0.0.1\n    Port {}\n",
                banner.port
            ),
        )
        .unwrap();
        let added = w.json(&["--json", "destination", "add", PROBED, "--observed"]);
        assert_eq!(added["code"], "OK", "{added}");
        let n = w.destination_count();
        let pty = Pty::open(40, 120);
        let before = modes(&pty.termios());
        let tui = w.started(&pty, n);
        w.wait_screen("the live operation", LONG, |s| s.contains("[..] working:"));

        // Every view by number, then by Tab from the last, then Shift-Tab.
        for (i, (title, line)) in VIEWS.iter().enumerate() {
            let d = u8::try_from(i + 1).unwrap();
            pty.write(&[b'0' + d]);
            w.wait_screen(&format!("view {d} {title}"), LONG, |s| {
                selected_tab(s) == Some(d)
                    && s.contains(&format!("[{d} {title}]"))
                    && s.contains(line)
            });
        }
        for (i, (title, line)) in VIEWS.iter().enumerate() {
            let d = u8::try_from(i + 1).unwrap();
            pty.write(b"\t");
            w.wait_screen(&format!("Tab to {title}"), LONG, |s| {
                selected_tab(s) == Some(d) && s.contains(line)
            });
        }
        pty.write(b"\x1b[Z");
        w.wait_screen("Shift-Tab to Identities", LONG, |s| {
            selected_tab(s) == Some(7)
        });

        // Search on Destinations (in memory), a detail, and back.
        pty.write(b"2/host-00001");
        w.wait_screen("the search results", LONG, |s| {
            s.contains("Search: host-00001_  (10 of")
        });
        pty.write(b"\r");
        w.wait_screen("the kept filter", LONG, |s| {
            s.contains("Filter: host-00001  (10 of")
        });
        for _ in 0..2 {
            let at = selected_row(&w.screen()).unwrap();
            pty.write(b"\x1b[B");
            w.wait_screen("the selection moving", LONG, |s| {
                selected_row(s).is_some_and(|r| r != at)
            });
        }
        let row = "host-000012";
        assert!(
            selected_row(&w.screen()).unwrap().contains(row),
            "{}",
            w.screen()
        );
        pty.write(b"\r");
        w.wait_screen("the detail", LONG, |s| {
            s.contains(&format!("{row}: ")) && s.contains("Esc back")
        });
        pty.write(b"\x1b");
        w.wait_screen("back on Destinations", LONG, |s| {
            selected_tab(s) == Some(2) && selected_row(s).is_some_and(|r| r.contains(row))
        });

        // The resize, with the state asserted at each size.
        assert_walk_state(&w, 40, 120, row);
        pty.resize(12, 40);
        assert_walk_state(&w, 12, 40, row);
        pty.resize(40, 120);
        assert_walk_state(&w, 40, 120, row);

        // The stop menu, opened and escaped: nothing is sent.
        pty.write(b"s");
        w.wait_screen("the stop menu", LONG, |s| {
            s.contains("Four different actions")
        });
        pty.write(b"\x1b");
        w.wait_screen("the stop menu closed", LONG, |s| {
            !s.contains("Four different actions") && s.contains("cancelled: nothing was sent")
        });

        // The M07-W0-R01 ruling for the stop menu, in the real input loop. One write is
        // one batch of keys with no frame between them: open the menu, pick "Stop this
        // work", type a work ID, then `yes`. None of it was on screen when the yes
        // arrived, so nothing is sent: the menu stays on the confirmation, which names
        // the action and its target, and says why.
        pty.write(b"s2\rjob-7\ryes\r");
        w.wait_screen("the batch's outcome", LONG, |s| {
            s.contains("yes refused") || s.contains("stop work job-7")
        });
        let refused = w.screen();
        for shown in [
            "Stop work job-7: access only it uses ends now",
            "yes refused: it was not on screen",
            "Type yes to confirm [y/N]: _",
            "screen changed: not sent; answer again",
        ] {
            assert!(refused.contains(shown), "{shown}:\n{refused}");
        }
        pty.write(b"\x1b");
        w.wait_screen("the refused stop cancelled", LONG, |s| {
            !s.contains("Type yes to confirm") && s.contains("cancelled: nothing was sent")
        });

        // The slow operation, cancelled with x from its detail.
        pty.write(b"1");
        w.wait_screen("the overview", LONG, |s| selected_tab(s) == Some(1));
        for _ in 0..20 {
            if selected_row(&w.screen()).is_some_and(|r| r.contains("working")) {
                break;
            }
            let at = selected_row(&w.screen());
            pty.write(b"\x1b[B");
            w.wait_screen("the selection moving", LONG, |s| selected_row(s) != at);
        }
        assert!(
            selected_row(&w.screen()).unwrap().contains(&op),
            "{}",
            w.screen()
        );
        // m07-plan U1c, in the real input loop. One write is one batch of keys with no
        // frame between them: Enter opens the operation's detail and `x` would cancel
        // it. No frame had drawn that operation when the `x` arrived, so nothing is
        // sent: the detail is on screen, the status line says why, and the operation
        // still runs.
        pty.write(b"\rx");
        w.wait_screen("the batch's outcome", LONG, |s| {
            footer(s).contains("screen changed") || footer(s).contains("cancel")
        });
        let refused = w.screen();
        for shown in [op.as_str(), "State: running", "x cancels it"] {
            assert!(refused.contains(shown), "{shown}:\n{refused}");
        }
        assert_eq!(
            footer(&refused),
            "screen changed: not sent; answer again",
            "{refused}"
        );
        let shown = w.json(&["--json", "operation", "show", &op]);
        assert!(
            shown["state"] == "running" || shown["state"] == "queued",
            "the batched x cancelled nothing: {shown}"
        );
        pty.write(b"\x1b");
        w.wait_screen("back on the overview", LONG, |s| {
            selected_tab(s) == Some(1) && !s.contains("State: running")
        });
        assert!(
            selected_row(&w.screen()).unwrap().contains(&op),
            "{}",
            w.screen()
        );
        // The same keys with a frame between them: the detail is drawn, then x.
        pty.write(b"\r");
        w.wait_screen("the operation detail", LONG, |s| {
            s.contains("State: running") && footer(s).contains("x cancel")
        });
        pty.write(b"x");
        w.wait_screen("the cancel's answer", LONG, |s| {
            s.contains(&format!("cancel {op}: "))
        });
        let deadline = Instant::now() + LONG;
        loop {
            let shown = w.json(&["--json", "operation", "show", &op]);
            if shown["state"] != "running" && shown["state"] != "queued" {
                eprintln!(
                    "M07 walkthrough: after x the operation is {}",
                    shown["state"]
                );
                break;
            }
            assert!(Instant::now() < deadline, "x did not cancel {op}: {shown}");
            std::thread::sleep(Duration::from_millis(100));
        }
        pty.write(b"\x1b");
        w.wait_screen("back on the overview", LONG, |s| {
            selected_tab(s) == Some(1) && s.contains("Static pass:")
        });

        // m07-plan U1c, the network probe, in the real input loop. The alias that names
        // the loopback fixture is selected on Destinations (the earlier search cleared).
        pty.write(b"2");
        w.wait_screen("Destinations again", LONG, |s| {
            selected_tab(s) == Some(2) && s.contains("Filter: host-00001")
        });
        pty.write(b"/");
        w.wait_screen("the search field", LONG, |s| {
            s.contains("Search: host-00001_")
        });
        pty.write(b"\x1b");
        w.wait_screen("the search cleared", LONG, |s| {
            s.contains("total · / to search")
        });
        pty.write(format!("/{PROBED}").as_bytes());
        w.wait_screen("the fixture alias found", LONG, |s| {
            s.contains(&format!("Search: {PROBED}_  (1 of"))
        });
        pty.write(b"\r");
        w.wait_screen("the fixture alias selected", LONG, |s| {
            s.contains(&format!("Filter: {PROBED}  (1 of"))
                && selected_row(s).is_some_and(|r| r.contains(PROBED))
        });
        // One write is one batch: open the probe menu, move to `network`, Enter. No
        // frame had drawn the menu when the Enter arrived, so no probe runs: the menu
        // stays open on that level, says why, and the fixture saw no connection.
        pty.write(b"p\x1b[B\x1b[B\x1b[B\r");
        w.wait_screen("the batch's outcome", LONG, |s| {
            s.contains("Enter refused") || s.contains("network probe: ")
        });
        let refused = w.screen();
        for shown in [
            format!("Explicit probes for {PROBED}; each names its level:"),
            "> network ".to_owned(),
            "Enter refused: it was not on screen".to_owned(),
            "screen changed: no probe; press again".to_owned(),
        ] {
            assert!(refused.contains(&shown), "{shown}:\n{refused}");
        }
        assert_eq!(banner.accepted(), 0, "the batched Enter probed nothing");
        pty.write(b"\x1b");
        w.wait_screen("the probe menu closed", LONG, |s| {
            !s.contains("Explicit probes")
        });
        // The same keys with a frame after each: the menu, the level, then Enter.
        pty.write(b"p");
        w.wait_screen("the probe menu", LONG, |s| {
            s.contains(&format!("Explicit probes for {PROBED};")) && s.contains("> static ")
        });
        for name in ["evaluate", "agent", "network"] {
            pty.write(b"\x1b[B");
            w.wait_screen(&format!("the {name} level selected"), LONG, |s| {
                s.contains(&format!("> {name} "))
            });
        }
        assert_eq!(banner.accepted(), 0, "nothing is probed before Enter");
        pty.write(b"\r");
        let target = format!("network 127.0.0.1:{}: ", banner.port);
        w.wait_screen("the network probe's result", LONG, |s| s.contains(&target));
        let result = w.screen();
        assert!(result.contains(&format!("{target}ok")), "{result}");
        assert_eq!(
            banner.accepted(),
            1,
            "one connection, to the loopback fixture"
        );
        pty.write(b"\x1b");
        w.wait_screen("the probe's result closed", LONG, |s| {
            !s.contains("network probe: ")
        });

        // The key help, and any key closes it.
        pty.write(b"?");
        w.wait_screen("the key help", LONG, |s| s.contains("this key help"));
        pty.write(b"\x1b");
        w.wait_screen("the help closed", LONG, |s| !s.contains("this key help"));

        // Quit: exit 0, the terminal as it was.
        pty.write(b"q");
        tui.wait(LONG);
        assert_eq!(
            modes(&pty.termios()),
            before,
            "the terminal's modes are restored"
        );
        assert_eq!(
            pty.count("\u{1b}[?1049h"),
            pty.count("\u{1b}[?1049l"),
            "the alternate screen is left as often as entered"
        );
        assert_no_canary(&String::from_utf8_lossy(&pty.bytes()));
    }

    /// A resize queued with Enter must invalidate a fully drawn confirmation.
    #[test]
    fn resize_then_yes_before_redraw_stops_nothing() {
        use rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};

        const WORK: &str = "m07-resize";
        const REFUSED: &str = "screen changed: not sent; answer again";
        const SHORT: Duration = Duration::from_secs(5);
        let _guard = super::parallel_test();
        let w = World::new(&[("HEIMDALL_TEST_ADAPTER", "prepare")]);
        let ensure = |attempt| {
            w.cli(&[
                "--json",
                "access",
                "ensure",
                "--profile",
                "dev",
                "--work-id",
                WORK,
                "--request-id",
                &format!("m07-resize-{attempt}"),
                "--pair",
                "h1:deploy",
                "--async",
            ])
        };
        let baseline = ensure(0);
        assert!(
            baseline.status.success(),
            "fixture work should be accepted: {}",
            w.cli_diagnostics(&baseline)
        );
        let pty = Pty::open(40, 120);
        let mut tui = w.started(&pty, w.destination_count());
        let resize_and_confirm = |tui: &mut Proc| {
            let child = tui.child.as_mut().unwrap();
            assert!(
                child.try_wait().unwrap().is_none(),
                "the TUI must be running"
            );
            let pid = Pid::from_child(child);
            kill_process(pid, Signal::STOP).unwrap();
            let (_, status) =
                rustix::io::retry_on_intr(|| waitpid(Some(pid), WaitOptions::UNTRACED))
                    .unwrap()
                    .unwrap();
            if !status.stopped() {
                tui.child.take(); // waitpid already reaped this child.
                panic!("the PTY child exited before suspension");
            }
            pty.resize(5, 40);
            pty.write(b"yes\r");
            kill_process(pid, Signal::CONT).unwrap();
        };
        let wide_confirm = |s: &str, action: &str| {
            s.lines().count() == 40
                && s.contains(action)
                && s.contains("Type yes to confirm [y/N]: _")
                && !s.contains("more rows below")
                && !s.contains("more row below")
        };
        for attempt in 1..=10 {
            pty.write(b"s2\rm07-resize\r");
            w.wait_screen("the full stop confirmation", SHORT, |s| {
                wide_confirm(s, "Stop work m07-resize: access only it uses ends now")
                    && s.contains("access stay.")
            });
            resize_and_confirm(&mut tui);
            w.wait_screen("the resize and stop answer", SHORT, |s| {
                s.lines().count() == 5
                    && (s.contains(REFUSED) || s.contains("stop work m07-resize:"))
            });
            // Wait for the stop's reply above before probing the durable record, so
            // an accepted stop cannot race a successful ensure.
            let out = ensure(attempt);
            assert!(
                out.status.success(),
                "work {WORK} was refused after resize attempt {attempt}: {}",
                w.cli_diagnostics(&out)
            );
            assert!(
                w.screen().contains(REFUSED),
                "stop confirmation did not explain its refusal"
            );
            assert!(
                tui.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "the TUI must stay open"
            );
            pty.resize(40, 120);
            w.wait_screen("the restored stop confirmation", SHORT, |s| {
                wide_confirm(s, "Stop work m07-resize:") && s.contains("yes refused")
            });
            pty.write(b"\x1b");
            w.wait_screen("the stop menu closed", SHORT, |s| {
                s.contains("cancelled: nothing was sent")
            });
        }

        pty.write(b"8");
        w.wait_screen("Settings and its standing access rows", SHORT, |s| {
            selected_tab(s) == Some(8) && s.contains("pol · profile dev")
        });
        pty.write(b"\x1b[B\r\r");
        w.wait_screen("the full Settings pause confirmation", SHORT, |s| {
            wide_confirm(s, "Same as: heimdall access pause pol")
                && s.contains("Standing access pol: profile dev")
        });
        resize_and_confirm(&mut tui);
        w.wait_screen("the Settings pause refusal", SHORT, |s| {
            s.lines().count() == 5 && s.contains(REFUSED)
        });
        let policies = w.json(&["--json", "inspect", "policies"]);
        assert!(
            policies["data"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| { p["policy_id"] == "pol" && p["paused_since"].is_null() }),
            "the fixture policy must stay active"
        );
        assert!(
            tui.child.as_mut().unwrap().try_wait().unwrap().is_none(),
            "the TUI must stay open"
        );
        pty.resize(40, 120);
        w.wait_screen("the restored Settings confirmation", SHORT, |s| {
            wide_confirm(s, "Same as: heimdall access pause pol") && s.contains("yes refused")
        });
        pty.write(b"\x1b");
        w.wait_screen("the Settings prompt closed", SHORT, |s| {
            s.contains("cancelled: nothing was sent")
        });
        pty.write(b"q");
        tui.wait(SHORT);
    }

    /// Review M07-W2-R01: a resize that goes away and comes back (`120x40 → 40x5 →
    /// 120x40`: a tmux zoom toggle, a tiling window manager) before the TUI draws again
    /// leaves the terminal at the size the last frame was drawn for, so the size
    /// comparison of M07-W1-R01 ([`resize_then_yes_before_redraw_stops_nothing`]) sees
    /// nothing; yet the frame on the screen was cut and has not been redrawn. Keys that
    /// arrive then must trigger nothing.
    ///
    /// One case for each guarded action the review probed, each with its own scratch
    /// runtime and TUI. Every case draws its target in full at 120x40, then [`ATTEMPTS`]
    /// times: stops the TUI, resizes there and back, writes the keys and lets the TUI
    /// continue ([`roundtrip_then_keys`]); nothing may have happened, the TUI is still
    /// running, has drawn again and says why. A miss names its action and attempt and is
    /// never retried. Then the same keys, written once the refusal's frame is on screen,
    /// must work once: the guard does not refuse everything, and the check that found
    /// nothing would have seen the action.
    mod roundtrip_resize_before_redraw_triggers_nothing {
        use super::*;

        /// Attempts per action. The fix waits a bounded time for the worker thread to
        /// count the resize, so one pass proves little: a rare miss needs many.
        const ATTEMPTS: usize = 20;
        const REFUSED: &str = "screen changed: not sent; answer again";
        const PROMPT: &str = "Type yes to confirm [y/N]: _";
        const SHORT: Duration = Duration::from_secs(5);

        /// The review's probe. Stop the TUI (SIGSTOP to the exact child this test
        /// started, waited for), take the terminal to 40x5 and 5 ms later back to 120x40,
        /// write `keys`, and let the TUI continue (SIGCONT, the same PID). It wakes up to
        /// a terminal of the size its last frame was drawn for, a resize it has not
        /// handled, and keys. Returns the length of the terminal's transcript when it
        /// continued.
        fn roundtrip_then_keys(pty: &Pty, tui: &mut Proc, keys: &[u8]) -> usize {
            use rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};
            let child = tui.child.as_mut().unwrap();
            assert!(
                child.try_wait().unwrap().is_none(),
                "the TUI must be running"
            );
            let pid = Pid::from_child(child);
            kill_process(pid, Signal::STOP).unwrap();
            let (_, status) =
                rustix::io::retry_on_intr(|| waitpid(Some(pid), WaitOptions::UNTRACED))
                    .unwrap()
                    .unwrap();
            if !status.stopped() {
                tui.child.take(); // waitpid already reaped this child.
                panic!("the PTY child exited before suspension");
            }
            pty.resize(5, 40);
            std::thread::sleep(Duration::from_millis(5));
            pty.resize(40, 120);
            pty.write(keys);
            let mark = pty.bytes().len();
            kill_process(pid, Signal::CONT).unwrap();
            mark
        }

        /// Type `keys` at a frame that is on the screen, until `done` holds. The guard may
        /// refuse them once more without any fault: on a loaded machine the count of the
        /// resizes above can reach the TUI after its repaint, and it then asks for one more
        /// frame. A refusal written after the keys (`refused`, in the terminal's bytes) is
        /// answered by typing them again at the frame that refusal drew; nothing else is.
        fn typed_at_a_drawn_frame(
            w: &World,
            pty: &Pty,
            keys: &[u8],
            refused: &str,
            what: &str,
            done: impl Fn(&str) -> bool,
        ) {
            let deadline = Instant::now() + LONG;
            let mut mark = pty.bytes().len();
            pty.write(keys);
            loop {
                let screen = w.screen();
                if done(&screen) {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {what}; the last frame:\n{screen}"
                );
                let bytes = pty.bytes();
                if String::from_utf8_lossy(&bytes[mark.min(bytes.len())..]).contains(refused) {
                    // The refusal's frame is complete before the keys go in again.
                    std::thread::sleep(Duration::from_millis(100));
                    mark = pty.bytes().len();
                    pty.write(keys);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// A frame of the whole 120x40 terminal.
        fn full_frame(screen: &str) -> bool {
            screen.lines().count() == 40
        }

        /// A confirmation drawn in full: `action` and the prompt, nothing cut off.
        fn full_confirmation(screen: &str, action: &str) -> bool {
            full_frame(screen)
                && screen.contains(action)
                && screen.contains(PROMPT)
                && !screen.contains("more rows below")
                && !screen.contains("more row below")
        }

        /// What a miss reports: the action, the attempt, what happened, and the first
        /// bytes the TUI wrote after it continued (whether it drew before the keys acted).
        fn miss(
            w: &World,
            pty: &Pty,
            mark: usize,
            action: &str,
            attempt: usize,
            what: &str,
        ) -> String {
            let bytes = pty.bytes();
            let written = bytes.get(mark..).unwrap_or_default();
            format!(
                "M07-W2-R01 MISS: {action}, attempt {attempt} of {ATTEMPTS}: {what}\n{} bytes written after the TUI continued, starting: {:?}\nthe last frame:\n{}",
                written.len(),
                super::super::diagnostic_tail(&written[..written.len().min(400)], w.root.path()),
                super::super::diagnostic_tail(w.screen().as_bytes(), w.root.path())
            )
        }

        /// After a refused attempt: the TUI is still running and wrote to the terminal
        /// after it continued. (The frame dump that shows the refusal is of that draw.)
        fn assert_running_and_repainted(pty: &Pty, tui: &mut Proc, mark: usize, action: &str) {
            assert!(
                tui.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "{action}: the TUI must stay open"
            );
            let deadline = Instant::now() + SHORT;
            while pty.bytes().len() <= mark {
                assert!(
                    Instant::now() < deadline,
                    "{action}: the TUI wrote nothing after it continued"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn passed(action: &str) {
            eprintln!(
                "M07-W2-R01 roundtrip resize (stopped; 120x40 -> 40x5 -> 5 ms -> 120x40; keys; continued): {action}: {ATTEMPTS} of {ATTEMPTS} attempts triggered nothing; the same keys to a drawn frame then worked once"
            );
        }

        /// The stop menu's confirmation: `yes` and Enter stop the work for good (a later
        /// `access ensure` for it is refused, `work_stopped`).
        #[test]
        fn stop_menu_yes() {
            const NAME: &str = "the stop menu's yes";
            const WORK: &str = "m07-roundtrip";
            const ACTION: &str = "Stop work m07-roundtrip: access only it uses ends now";
            const ANSWER: &str = "stop work m07-roundtrip: ";
            let _guard = super::super::parallel_test();
            let w = World::new(&[("HEIMDALL_TEST_ADAPTER", "prepare")]);
            let ensure = |attempt: usize| {
                w.cli(&[
                    "--json",
                    "access",
                    "ensure",
                    "--profile",
                    "dev",
                    "--work-id",
                    WORK,
                    "--request-id",
                    &format!("{WORK}-{attempt}"),
                    "--pair",
                    "h1:deploy",
                    "--async",
                ])
            };
            let baseline = ensure(0);
            assert!(
                baseline.status.success(),
                "fixture work should be accepted: {}",
                w.cli_diagnostics(&baseline)
            );
            let pty = Pty::open(40, 120);
            let mut tui = w.started(&pty, w.destination_count());
            let open = format!("s2\r{WORK}\r");
            pty.write(open.as_bytes());
            for attempt in 1..=ATTEMPTS {
                w.wait_screen("the stop confirmation in full", LONG, |s| {
                    full_confirmation(s, ACTION)
                        && s.contains("access stay.")
                        && !s.contains("yes refused")
                        && !s.contains(REFUSED)
                });
                let mark = roundtrip_then_keys(&pty, &mut tui, b"yes\r");
                // The stop's own answer, not only its sending, so that an accepted stop
                // cannot race the ensure below.
                w.wait_screen("the answer to yes", LONG, |s| {
                    s.contains(REFUSED) || s.contains(ANSWER)
                });
                let out = ensure(attempt);
                assert!(
                    out.status.success(),
                    "{}",
                    miss(
                        &w,
                        &pty,
                        mark,
                        NAME,
                        attempt,
                        &format!("work {WORK} is stopped: {}", w.cli_diagnostics(&out))
                    )
                );
                let screen = w.screen();
                for shown in [ACTION, PROMPT, "yes refused: it was not on screen", REFUSED] {
                    assert!(
                        full_frame(&screen) && screen.contains(shown),
                        "attempt {attempt}: {shown}:\n{screen}"
                    );
                }
                assert_running_and_repainted(&pty, &mut tui, mark, NAME);
                // The repaint after the refusal is a full one: the terminal may have
                // dropped cells of the frame while it was small, so the confirmation's own
                // rows are written again, not only the cells that differ (review
                // M07-W2-R01).
                let deadline = Instant::now() + SHORT;
                loop {
                    let bytes = pty.bytes();
                    let since = String::from_utf8_lossy(&bytes[mark.min(bytes.len())..]);
                    if since.contains("m07-roundtrip:") {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "attempt {attempt}: the refusal's frame did not write the action row again"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                if attempt < ATTEMPTS {
                    pty.write(b"\x1b");
                    w.wait_screen("the stop menu closed", LONG, |s| {
                        s.contains("cancelled: nothing was sent") && !s.contains(PROMPT)
                    });
                    pty.write(open.as_bytes());
                }
            }
            // The refusal's frame drew the confirmation again: a yes typed to it is sent.
            typed_at_a_drawn_frame(
                &w,
                &pty,
                b"yes\r",
                "yes refused",
                "the stop's answer",
                |s| s.contains(ANSWER),
            );
            let answer = w.screen();
            assert!(answer.contains("stop work m07-roundtrip: OK"), "{answer}");
            let out = ensure(ATTEMPTS + 1);
            assert!(
                !out.status.success()
                    && [&out.stdout, &out.stderr]
                        .iter()
                        .any(|b| String::from_utf8_lossy(b).contains("work_stopped")),
                "a stop that was sent refuses the work's next ensure: {}",
                w.cli_diagnostics(&out)
            );
            pty.write(b"q");
            tui.wait(LONG);
            passed(NAME);
        }

        /// A Settings confirmation: `yes` and Enter pause the standing access `pol`.
        #[test]
        fn settings_pause_yes() {
            const NAME: &str = "the Settings Pause yes";
            const ACTION: &str = "Same as: heimdall access pause pol";
            const ANSWER: &str = "pause pol: ";
            let _guard = super::super::parallel_test();
            let w = World::new(&[("HEIMDALL_TEST_ADAPTER", "prepare")]);
            let paused = || {
                let policies = w.json(&["--json", "inspect", "policies"]);
                let pol = policies["data"]["items"]
                    .as_array()
                    .and_then(|items| items.iter().find(|p| p["policy_id"] == "pol"))
                    .unwrap_or_else(|| panic!("the fixture policy is listed: {policies}"));
                !pol["paused_since"].is_null()
            };
            assert!(!paused(), "the fixture policy starts active");
            let pty = Pty::open(40, 120);
            let mut tui = w.started(&pty, w.destination_count());
            pty.write(b"8");
            w.wait_screen("Settings and its standing access rows", LONG, |s| {
                selected_tab(s) == Some(8) && s.contains("pol · profile dev")
            });
            // Down to the standing access row; Enter opens its changes, Enter picks Pause.
            pty.write(b"\x1b[B\r\r");
            for attempt in 1..=ATTEMPTS {
                w.wait_screen("the Settings pause confirmation in full", LONG, |s| {
                    full_confirmation(s, ACTION)
                        && s.contains("Standing access pol: profile dev")
                        && !s.contains("yes refused")
                        && !s.contains(REFUSED)
                });
                let mark = roundtrip_then_keys(&pty, &mut tui, b"yes\r");
                w.wait_screen("the answer to yes", LONG, |s| {
                    s.contains(REFUSED) || s.contains(ANSWER)
                });
                assert!(
                    !paused(),
                    "{}",
                    miss(&w, &pty, mark, NAME, attempt, "the policy pol is paused")
                );
                let screen = w.screen();
                for shown in [ACTION, PROMPT, "yes refused", REFUSED] {
                    assert!(
                        full_frame(&screen) && screen.contains(shown),
                        "attempt {attempt}: {shown}:\n{screen}"
                    );
                }
                assert_running_and_repainted(&pty, &mut tui, mark, NAME);
                if attempt < ATTEMPTS {
                    pty.write(b"\x1b");
                    w.wait_screen("the Settings prompt closed", LONG, |s| {
                        s.contains("cancelled: nothing was sent") && !s.contains(PROMPT)
                    });
                    pty.write(b"\r\r");
                }
            }
            // The refusal's frame drew the confirmation again: a yes typed to it is sent.
            typed_at_a_drawn_frame(
                &w,
                &pty,
                b"yes\r",
                "yes refused",
                "the pause's answer",
                |s| s.contains(ANSWER),
            );
            let answer = w.screen();
            assert!(answer.contains("pause pol: OK"), "{answer}");
            assert!(paused(), "a pause that was sent pauses the policy");
            pty.write(b"q");
            tui.wait(LONG);
            passed(NAME);
        }

        /// An operation's detail: `x` cancels the running operation.
        #[test]
        fn operation_cancel_x() {
            const NAME: &str = "the operation detail's x";
            let _guard = super::super::parallel_test();
            let w = World::new(&[
                ("HEIMDALL_TEST_ADAPTER", "prepare"),
                ("HEIMDALL_TEST_SLOW_PREPARE_MS", "600000"),
            ]);
            // The live slow operation: an ensure whose prepare waits 10 minutes.
            let ensure = w.json(&[
                "--json",
                "access",
                "ensure",
                "--profile",
                "dev",
                "--work-id",
                "m07-roundtrip-cancel",
                "--request-id",
                "m07-roundtrip-cancel-1",
                "--pair",
                "h1:deploy",
                "--async",
            ]);
            let op = ensure["operation_id"].as_str().unwrap().to_owned();
            let state = || {
                let shown = w.json(&["--json", "operation", "show", &op]);
                shown["state"].as_str().unwrap_or_default().to_owned()
            };
            let live = |state: &str| state == "running" || state == "queued";
            let pty = Pty::open(40, 120);
            let mut tui = w.started(&pty, w.destination_count());
            w.wait_screen("the live operation", LONG, |s| s.contains("[..] working:"));
            for _ in 0..20 {
                if selected_row(&w.screen()).is_some_and(|r| r.contains("working")) {
                    break;
                }
                let at = selected_row(&w.screen());
                pty.write(b"\x1b[B");
                w.wait_screen("the selection moving", LONG, |s| selected_row(s) != at);
            }
            let answer = format!("cancel {op}: ");
            for attempt in 1..=ATTEMPTS {
                assert!(
                    selected_row(&w.screen()).unwrap().contains(&op),
                    "{}",
                    w.screen()
                );
                pty.write(b"\r");
                w.wait_screen("the operation detail in full", LONG, |s| {
                    full_frame(s)
                        && s.contains(&op)
                        && s.contains("State: running")
                        && s.contains("x cancels it")
                        && footer(s).contains("x cancel")
                });
                let mark = roundtrip_then_keys(&pty, &mut tui, b"x");
                // The cancel's own answer, not only its sending.
                w.wait_screen("the answer to x", LONG, |s| {
                    footer(s) == REFUSED || s.contains(&answer)
                });
                let now = state();
                assert!(
                    live(&now),
                    "{}",
                    miss(
                        &w,
                        &pty,
                        mark,
                        NAME,
                        attempt,
                        &format!("the operation is {now}")
                    )
                );
                let screen = w.screen();
                for shown in [op.as_str(), "State: running", "x cancels it"] {
                    assert!(
                        full_frame(&screen) && screen.contains(shown),
                        "attempt {attempt}: {shown}:\n{screen}"
                    );
                }
                assert_eq!(footer(&screen), REFUSED, "attempt {attempt}:\n{screen}");
                assert_running_and_repainted(&pty, &mut tui, mark, NAME);
                if attempt < ATTEMPTS {
                    pty.write(b"\x1b");
                    w.wait_screen("back on the overview", LONG, |s| {
                        selected_tab(s) == Some(1) && !s.contains("State: running")
                    });
                }
            }
            // The refusal's frame drew the detail again: an x pressed on it is sent.
            typed_at_a_drawn_frame(&w, &pty, b"x", REFUSED, "the cancel's answer", |s| {
                s.contains(&answer)
            });
            let deadline = Instant::now() + LONG;
            loop {
                let now = state();
                if !live(&now) {
                    break;
                }
                assert!(Instant::now() < deadline, "x did not cancel {op}: {now}");
                std::thread::sleep(Duration::from_millis(100));
            }
            pty.write(b"\x1b");
            w.wait_screen("back on the overview", LONG, |s| {
                selected_tab(s) == Some(1) && s.contains("Static pass:")
            });
            pty.write(b"q");
            tui.wait(LONG);
            passed(NAME);
        }

        /// The probe menu: Enter on `network` connects to the alias's host, here a
        /// loopback listener that counts its connections ([`BannerFixture`]).
        #[test]
        fn network_probe_enter() {
            const NAME: &str = "the probe menu's Enter on network";
            const PROBED: &str = "hm-m07-roundtrip";
            const NOT_RUN: &str = "screen changed: no probe; press again";
            let _guard = super::super::parallel_test();
            let w = World::new(&[]);
            // An observed alias that the scratch configuration (the static pass's too)
            // points at the loopback fixture, the only thing a probe here contacts.
            let banner = BannerFixture::start();
            let ssh_dir = w.ssh_home.join(".ssh");
            std::fs::create_dir_all(&ssh_dir).unwrap();
            std::fs::write(
                ssh_dir.join("config"),
                format!(
                    "Host {PROBED}\n    HostName 127.0.0.1\n    Port {}\n",
                    banner.port
                ),
            )
            .unwrap();
            let added = w.json(&["--json", "destination", "add", PROBED, "--observed"]);
            assert_eq!(added["code"], "OK", "{added}");
            let pty = Pty::open(40, 120);
            let mut tui = w.started(&pty, w.destination_count());
            pty.write(b"2");
            w.wait_screen("the Destinations tab", LONG, |s| {
                selected_tab(s) == Some(2) && selected_row(s).is_some()
            });
            pty.write(format!("/{PROBED}").as_bytes());
            w.wait_screen("the fixture alias found", LONG, |s| {
                s.contains(&format!("Search: {PROBED}_  (1 of"))
            });
            pty.write(b"\r");
            w.wait_screen("the fixture alias selected", LONG, |s| {
                s.contains(&format!("Filter: {PROBED}  (1 of"))
                    && selected_row(s).is_some_and(|r| r.contains(PROBED))
            });
            let menu = format!("Explicit probes for {PROBED}; each names its level:");
            pty.write(b"p");
            w.wait_screen("the probe menu", LONG, |s| {
                s.contains(&menu) && s.contains("> static ")
            });
            for name in ["evaluate", "agent"] {
                pty.write(b"\x1b[B");
                w.wait_screen(&format!("the {name} level selected"), LONG, |s| {
                    s.contains(&format!("> {name} "))
                });
            }
            let target = format!("network 127.0.0.1:{}: ", banner.port);
            for attempt in 1..=ATTEMPTS {
                // From `agent` down to `network`, a frame after it; the key also ends the
                // note of the attempt before.
                pty.write(b"\x1b[B");
                w.wait_screen("the probe menu on network, in full", LONG, |s| {
                    full_frame(s)
                        && s.contains(&menu)
                        && s.contains("> network ")
                        && !s.contains("Enter refused")
                        && !s.contains(NOT_RUN)
                });
                assert_eq!(banner.accepted(), 0, "nothing is probed before Enter");
                let mark = roundtrip_then_keys(&pty, &mut tui, b"\r");
                // The probe's own result, not only its start.
                w.wait_screen("the answer to Enter", LONG, |s| {
                    s.contains("Enter refused") || s.contains(&target)
                });
                let connections = banner.accepted();
                assert_eq!(
                    connections,
                    0,
                    "{}",
                    miss(
                        &w,
                        &pty,
                        mark,
                        NAME,
                        attempt,
                        &format!("the loopback listener saw {connections} connection(s)")
                    )
                );
                let screen = w.screen();
                for shown in [
                    menu.as_str(),
                    "> network ",
                    "Enter refused: it was not on screen",
                    NOT_RUN,
                ] {
                    assert!(
                        full_frame(&screen) && screen.contains(shown),
                        "attempt {attempt}: {shown}:\n{screen}"
                    );
                }
                assert_running_and_repainted(&pty, &mut tui, mark, NAME);
                if attempt < ATTEMPTS {
                    pty.write(b"\x1b[A");
                    w.wait_screen("the agent level selected", LONG, |s| {
                        s.contains("> agent ") && !s.contains("Enter refused")
                    });
                }
            }
            assert_eq!(
                banner.accepted(),
                0,
                "no refused Enter reached the listener later either"
            );
            // The refusal's frame drew the menu on `network` again: Enter on it runs.
            typed_at_a_drawn_frame(
                &w,
                &pty,
                b"\r",
                "Enter refused",
                "the network probe's result",
                |s| s.contains(&target),
            );
            let result = w.screen();
            assert!(result.contains(&format!("{target}ok")), "{result}");
            assert_eq!(
                banner.accepted(),
                1,
                "one connection, to the loopback fixture"
            );
            pty.write(b"\x1b");
            w.wait_screen("the probe's result closed", LONG, |s| {
                !s.contains("network probe: ")
            });
            pty.write(b"q");
            tui.wait(LONG);
            passed(NAME);
        }
    }

    /// m07-plan U1 `tui_standalone_access_and_stop` (the TUI standalone row): an observed
    /// alias served by the loopback fixture sshd, reached with a per-run key.
    /// With no CLI command in between: the destination is opened,
    /// connected through the handoff (a trivial command on the fixture), and after the
    /// return the profile's access is stopped from the stop menu; the terminal is restored.
    ///
    /// The verified client is a scratch wrapper around the system `ssh` that adds only
    /// isolation and the fixture's own files: `-F` the scratch configuration, the fixture
    /// key with `IdentitiesOnly=yes` and `IdentityAgent=none`, no
    /// certificate, scratch known hosts, no global known hosts and no multiplexing, so the
    /// owner's `~/.ssh`, agent and keys are never read.
    #[test]
    fn tui_standalone_access_and_stop() {
        use heimdall_testkit::agent::FixtureKey;
        use heimdall_testkit::home::Scratch;
        use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

        const ALIAS: &str = "hm-m07-fixture";
        const LOGIN: &str = "HM-M07-FIXTURE-LOGIN";
        let _guard = super::parallel_test();
        let fixtures = Scratch::new().unwrap();
        let key = FixtureKey::generate().with_comment("hm-m07-fixture-key");
        let sshd = LoopbackSshd::start(
            &fixtures,
            SshdConfig {
                authorized: vec![key.public().clone()],
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("blocked: the loopback fixture sshd cannot start here: {e:?}"));

        let w = World::new(&[]);
        // The scratch configuration (also the static pass's) and known hosts.
        let ssh_dir = w.ssh_home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");
        std::fs::write(
            &config,
            format!(
                "Host {ALIAS}\n    HostName {}\n    Port {}\n",
                sshd.host, sshd.port
            ),
        )
        .unwrap();
        let known = w.root.path().join("fixture_known_hosts");
        std::fs::write(&known, format!("{}\n", sshd.host_key_line)).unwrap();
        let identity = w.root.path().join("fixture_key");
        key.write_private(&identity).unwrap();
        let marks = w.root.path().join("ssh-invocations");
        w.write_ssh(&format!(
            "#!/bin/sh\n\
             # hm-m07 fixture client: the system ssh, isolated, reaching only the loopback fixture.\n\
             for a in \"$@\"; do case \"$a\" in -V) exec /usr/bin/ssh -V ;; esac; done\n\
             echo \"$*\" >> '{marks}'\n\
             exec /usr/bin/ssh -F '{config}' -o IdentityFile=none -i '{identity}' -o IdentitiesOnly=yes \
             -o IdentityAgent=none -o CertificateFile=none -o UserKnownHostsFile='{known}' \
             -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes \
             -o ControlMaster=no -o ControlPath=none -o LogLevel=ERROR \"$@\" 'echo {LOGIN}'\n",
            marks = marks.display(),
            config = config.display(),
            identity = identity.display(),
            known = known.display(),
        ));
        let added = w.json(&["--json", "destination", "add", ALIAS, "--observed"]);
        assert_eq!(added["code"], "OK", "{added}");
        let n = w.destination_count();

        let pty = Pty::open(40, 120);
        let before = modes(&pty.termios());
        let tui = w.started(&pty, n);
        // Open the destination: Destinations, search, its detail.
        pty.write(format!("2/{ALIAS}\r").as_bytes());
        w.wait_screen("the fixture alias", LONG, |s| {
            selected_row(s).is_some_and(|r| r.contains(ALIAS))
        });
        pty.write(b"\r");
        w.wait_screen("its detail", LONG, |s| {
            s.contains(&format!("{ALIAS}: observed destination")) && footer(s).contains("c connect")
        });
        // Connect through the handoff; the TUI returns when ssh exits.
        let mark = sshd.log_mark();
        pty.write(b"c");
        w.wait_screen("the handoff's end", LONG, |s| {
            s.contains(&format!("ssh {ALIAS} exited with status"))
        });
        let screen = w.screen();
        assert!(
            screen.contains(&format!("ssh {ALIAS} exited with status 0")),
            "{}\n{}",
            super::diagnostic_tail(screen.as_bytes(), w.root.path()),
            super::diagnostic_tail(&pty.bytes(), w.root.path())
        );
        assert!(
            String::from_utf8_lossy(&pty.bytes()).contains(LOGIN),
            "the fixture command ran on the fixture sshd"
        );
        assert_eq!(
            std::fs::read_to_string(&marks).unwrap().trim(),
            ALIAS,
            "the TUI handed only the alias to the client"
        );
        let accepted = sshd.log_lines_since(mark, "Accepted publickey");
        assert!(
            !accepted.is_empty(),
            "the fixture sshd accepted the fixture key"
        );
        assert!(
            accepted.iter().all(|l| l.contains(&key.fingerprint())),
            "only the per-run key: {accepted:?}"
        );
        // Back in the TUI: stop the profile's access from the stop menu.
        pty.write(b"s");
        w.wait_screen("the stop menu", LONG, |s| {
            s.contains("Four different actions")
        });
        pty.write(b"3\r");
        w.wait_screen("the profile prompt", LONG, |s| s.contains("Profile ID: "));
        pty.write(b"dev\r");
        w.wait_screen("the confirmation", LONG, |s| {
            s.contains("Stop everything for profile dev") && s.contains("Type yes to confirm")
        });
        pty.write(b"yes\r");
        w.wait_screen("the stop's answer", LONG, |s| {
            s.contains("stop profile dev: ")
        });
        let answer = w.screen();
        assert!(answer.contains("stop profile dev: OK"), "{answer}");
        pty.write(b"q");
        // `q` on a detail goes back; on the view it quits.
        if tui_running_after(&pty, Duration::from_millis(500)) {
            pty.write(b"q");
        }
        tui.wait(LONG);
        assert_eq!(
            modes(&pty.termios()),
            before,
            "the terminal's modes are restored"
        );
        assert_eq!(
            pty.count("\u{1b}[?1049h"),
            pty.count("\u{1b}[?1049l"),
            "the alternate screen is left as often as entered"
        );
        assert_no_canary(&String::from_utf8_lossy(&pty.bytes()));
        // Afterwards (not in between): every policy of the profile is paused.
        let policies = w.json(&["--json", "inspect", "policies"]);
        let dev: Vec<&Value> = policies["data"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["profile"] == "dev")
            .collect();
        assert!(!dev.is_empty(), "{policies}");
        assert!(
            dev.iter().all(|p| p["paused_since"].is_string()),
            "{policies}"
        );
        drop(sshd);
    }

    /// Whether the TUI still draws after `wait` (its screen file changes or not is not
    /// enough: a quit leaves the alternate screen).
    fn tui_running_after(pty: &Pty, wait: Duration) -> bool {
        std::thread::sleep(wait);
        pty.count("\u{1b}[?1049h") > pty.count("\u{1b}[?1049l")
    }
}

/// m07-plan U1 the Windows walkthrough (A20's ConPTY row): `heimdall tui` on a Windows
/// pseudoconsole through `heimdall_testkit::console::TerminalCommand`, as tui_m03's Windows
/// case runs it: every view by number, a resize, a key after the resize answered within
/// 100 ms (timed from the key's write to the frame dump that shows it), and `q` with the
/// console's input mode cooked again.
///
/// **Isolation.** One `tempfile` root holds separate `HOME`, `HEIMDALL_HOME` and
/// `HEIMDALL_TEST_SSH_HOME` (with an empty `etc-ssh`) directories; `PATH` is only the
/// system directory, so no `ssh` is found and nothing is contacted; the runtime, if one
/// was started in the scratch home, is stopped with `service stop` there.
///
/// **The resize.** `TerminalCommand` has no resize, so the pseudoconsole's child (this
/// binary in child mode, [`console_child`]) resizes its own console with crossterm's
/// `SetSize` when the test asks (a request file), and reports it (a done file).
#[cfg(windows)]
mod windows_console {
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use heimdall_testkit::console::TerminalCommand;

    const ARGV: &str = "HM_M07_W_TUI_ARGV";
    const ENVS: &str = "HM_M07_W_TUI_ENV";
    const RESIZE: &str = "HM_M07_W_TUI_RESIZE";
    const LONG: Duration = Duration::from_secs(60);
    /// The A20 bar for a key after the resize.
    const BAR: Duration = Duration::from_millis(100);

    fn bin() -> String {
        std::env::var("HEIMDALL_E2E_BIN")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
    }

    /// Child-mode entry (module docs): starts the TUI on this console, samples the
    /// console's input mode, resizes the console when `<RESIZE>.request` appears (writing
    /// `<RESIZE>.done`), and prints what it saw.
    #[test]
    #[ignore = "child-mode entry of the Windows walkthrough, started by it"]
    fn console_child() {
        use ratatui::crossterm::terminal::{SetSize, is_raw_mode_enabled};
        let _guard = super::parallel_test();
        let (Ok(argv), Ok(envs), Ok(resize)) = (
            std::env::var(ARGV),
            std::env::var(ENVS),
            std::env::var(RESIZE),
        ) else {
            return;
        };
        let argv: Vec<String> = serde_json::from_str(&argv).unwrap();
        let envs: Vec<(String, String)> = serde_json::from_str(&envs).unwrap();
        let request = PathBuf::from(format!("{resize}.request"));
        let done = PathBuf::from(format!("{resize}.done"));
        let before = is_raw_mode_enabled().ok();
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .envs(envs)
            .spawn()
            .unwrap_or_else(|e| panic!("the TUI did not start: {e}"));
        let mut seen_raw = false;
        let mut resized = false;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            seen_raw |= is_raw_mode_enabled().unwrap_or(false);
            if !resized && request.exists() {
                resized = true;
                let result = ratatui::crossterm::execute!(std::io::stdout(), SetSize(40, 12));
                std::fs::write(&done, format!("{result:?}")).unwrap();
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let after = is_raw_mode_enabled().ok();
        let mut out = std::io::stdout();
        let _ = writeln!(
            out,
            "hm-console-modes before={before:?} raw_seen={seen_raw} after={after:?}"
        )
        .and_then(|()| out.flush());
        std::process::exit(status.code().unwrap_or(-1));
    }

    /// The scratch environment for the TUI and `service stop` (rule 4: separate homes in
    /// one root).
    fn env(root: &Path, screen: &Path) -> Vec<(String, String)> {
        let text = |p: &Path| p.to_string_lossy().into_owned();
        let base = root.canonicalize().unwrap();
        let mut homes = std::collections::BTreeSet::new();
        for name in ["hh", "home", "sshhome"] {
            let path = root.join(name).canonicalize().unwrap();
            assert!(path.is_dir() && path != base && path.starts_with(&base));
            assert!(homes.insert(path));
        }
        let [mgmt, iroh] = super::checked_fixture_stores(root);
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let mut env = vec![
            ("HEIMDALL_HOME".to_owned(), text(&root.join("hh"))),
            ("HOME".to_owned(), text(&root.join("home"))),
            ("USERPROFILE".to_owned(), text(&root.join("home"))),
            ("APPDATA".to_owned(), text(&root.join("home/appdata"))),
            (
                "LOCALAPPDATA".to_owned(),
                text(&root.join("home/localappdata")),
            ),
            ("ProgramData".to_owned(), text(&root.join("programdata"))),
            (
                "ALLUSERSPROFILE".to_owned(),
                text(&root.join("programdata")),
            ),
            ("TEMP".to_owned(), text(&root.join("temp"))),
            ("TMP".to_owned(), text(&root.join("temp"))),
            (
                "HEIMDALL_TEST_SSH_HOME".to_owned(),
                text(&root.join("sshhome")),
            ),
            (
                "HEIMDALL_TEST_SECRET_STORE".to_owned(),
                "scratch".to_owned(),
            ),
            (
                "HEIMDALL_TEST_MGMT_STORE".to_owned(),
                format!("fixture-file:{}", mgmt.to_str().unwrap()),
            ),
            ("HEIMDALL_TEST_IROH_KEY_STORE".to_owned(), text(&iroh)),
            ("HEIMDALL_TEST_TUI_SCREEN".to_owned(), text(screen)),
            (
                "HEIMDALL_TEST_TIME_SYNC".to_owned(),
                "synchronized".to_owned(),
            ),
            ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
            ("PATH".to_owned(), format!(r"{system}\System32")),
        ];
        for k in ["SystemRoot", "windir", "ComSpec", "PATHEXT"] {
            if let Ok(v) = std::env::var(k) {
                env.push((k.to_owned(), v));
            }
        }
        env
    }

    /// Runs `heimdall service stop` in the scratch home when dropped (a no-op when no
    /// runtime runs there).
    struct StopRuntime(Vec<(String, String)>, PathBuf);

    impl Drop for StopRuntime {
        fn drop(&mut self) {
            let _ = Command::new(bin())
                .args(["--json", "service", "stop"])
                .env_clear()
                .envs(self.0.iter().map(|(k, v)| (k, v)))
                .stdin(Stdio::null())
                .output();
            if !std::thread::panicking() {
                super::assert_no_fixture_stores(&self.1);
            }
        }
    }

    fn frame(screen: &Path) -> String {
        std::fs::read_to_string(screen).unwrap_or_default()
    }

    fn wait_frame(
        t: &mut heimdall_testkit::console::Terminal,
        screen: &Path,
        what: &str,
        cond: impl Fn(&str) -> bool,
    ) {
        let deadline = Instant::now() + LONG;
        loop {
            let f = frame(screen);
            if cond(&f) {
                return;
            }
            let exit = t.try_wait();
            let root = screen.parent().unwrap();
            let transcript = || super::diagnostic_tail(&t.output(), root);
            let frame_tail = || super::diagnostic_tail(f.as_bytes(), root);
            assert!(
                exit.is_none(),
                "the TUI exited with {exit:?} waiting for {what}; console tail: {:?}\nframe tail: {:?}",
                transcript(),
                frame_tail()
            );
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; console tail: {:?}\nframe tail: {:?}",
                transcript(),
                frame_tail()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn windows_tui_walkthrough() {
        let _guard = super::latency_test();
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        for d in [
            "home/appdata",
            "home/localappdata",
            "hh",
            "sshhome/etc-ssh",
            "programdata",
            "temp",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let screen = root.join("screen.txt");
        let resize = root.join("resize");
        let vars = env(root, &screen);
        let _stop = StopRuntime(vars.clone(), root.to_owned());
        let argv = vec![bin(), "tui".to_owned()];
        let mut command = TerminalCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_console::console_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .current_dir(root)
            .size(120, 40)
            .env(ARGV, serde_json::to_string(&argv).unwrap())
            .env(ENVS, serde_json::to_string(&vars).unwrap())
            .env(RESIZE, resize.to_string_lossy().into_owned());
        for (key, value) in &vars {
            command = command.env(key, value);
        }
        let mut t = command
            .spawn()
            .unwrap_or_else(|e| panic!("the pseudoconsole did not start: {e}"));
        wait_frame(&mut t, &screen, "the first frame", |f| {
            f.contains("Runtime:")
                && f.contains("Static pass:")
                && !f.contains("Static pass: running")
        });
        // Every view by number.
        let titles = [
            "Overview",
            "Destinations",
            "Profiles",
            "Activity",
            "Projects",
            "Environments",
            "Identities",
            "Settings",
        ];
        for (i, title) in titles.iter().enumerate() {
            let label = format!("[{} {title}]", i + 1);
            t.send(format!("{}", i + 1).as_bytes()).unwrap();
            wait_frame(&mut t, &screen, &label, |f| {
                f.lines().next().is_some_and(|h| h.contains(&label))
            });
        }
        // The resize (the console child resizes its console), then a key.
        std::fs::write(format!("{}.request", resize.display()), "40x12").unwrap();
        wait_frame(&mut t, &screen, "the resized frame", |f| {
            f.lines().count() == 12
        });
        let done =
            std::fs::read_to_string(format!("{}.done", resize.display())).unwrap_or_default();
        eprintln!("M07 Windows walkthrough: SetSize answered {done}");
        let t0 = Instant::now();
        t.send(b"2").unwrap();
        let mut answered = None;
        while t0.elapsed() < Duration::from_secs(2) {
            if frame(&screen)
                .lines()
                .next()
                .is_some_and(|h| h.starts_with("[2 Destinations] 2/8"))
            {
                answered = Some(t0.elapsed());
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        eprintln!("M07 Windows walkthrough: the key after the resize was drawn after {answered:?}");
        let answered = answered.unwrap_or_else(|| {
            panic!(
                "no frame showed the key; console tail: {:?}",
                super::diagnostic_tail(&t.output(), scratch.path())
            )
        });
        assert!(
            answered <= BAR,
            "the key after the resize took {answered:?} (bar {BAR:?})"
        );
        t.send(b"q").unwrap();
        let code = t.wait(LONG);
        let text = t.text();
        heimdall_testkit::assert_no_canary(&text);
        let console = || super::diagnostic_tail(text.as_bytes(), scratch.path());
        assert_eq!(code, Some(0), "q exits 0; console tail: {:?}", console());
        assert!(
            text.contains("hm-console-modes before=Some(false) raw_seen=true after=Some(false)"),
            "the console's input was raw while the TUI ran and cooked again after: {:?}",
            console()
        );
        let raw = String::from_utf8_lossy(&t.output()).into_owned();
        assert_eq!(
            raw.matches("\u{1b}[?1049h").count(),
            raw.matches("\u{1b}[?1049l").count(),
            "the alternate screen is left as often as entered: {:?}",
            console()
        );
    }

    /// The header: the frame's first line.
    fn header(f: &str) -> &str {
        f.lines().next().unwrap_or_default()
    }

    /// The footer: the frame's last line.
    fn footer(f: &str) -> &str {
        f.lines().last().unwrap_or_default()
    }

    /// The selected list row (`> ...`), trimmed.
    fn selected_row(f: &str) -> Option<&str> {
        f.lines().find(|l| l.starts_with("> ")).map(str::trim)
    }

    /// `heimdall service run` in the scratch home of the standalone row, started by this
    /// test. Dropped: `heimdall service stop` there (it checks the advertised PID of this
    /// home's own runtime), then, if the runtime is still running after 30 s, the exact
    /// child this test started is killed by its handle.
    struct Runtime {
        vars: Vec<(String, String)>,
        root: PathBuf,
        child: Option<std::process::Child>,
    }

    impl Runtime {
        fn start(vars: &[(String, String)], root: &Path) -> Runtime {
            let log = std::fs::File::create(root.join("service.log")).unwrap();
            let child = Command::new(bin())
                .args(["service", "run"])
                .env_clear()
                .envs(vars.iter().map(|(k, v)| (k, v)))
                .current_dir(root.join("home"))
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap_or_else(|e| panic!("the runtime did not start: {e}"));
            let mut rt = Runtime {
                vars: vars.to_vec(),
                root: root.to_owned(),
                child: Some(child),
            };
            let deadline = Instant::now() + LONG;
            loop {
                let out = rt.cli(&["--json", "service", "status"]);
                if out.status.success() {
                    break;
                }
                if let Some(s) = rt.child.as_mut().unwrap().try_wait().unwrap() {
                    panic!("the runtime exited early ({s}): {:?}", rt.log());
                }
                assert!(
                    Instant::now() < deadline,
                    "the runtime did not start; service tail: {:?}\n{}",
                    rt.log(),
                    rt.diagnostics(&out)
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            rt
        }

        fn log(&self) -> String {
            let bytes = std::fs::read(self.root.join("service.log")).unwrap_or_default();
            super::diagnostic_tail(&bytes, &self.root)
        }

        /// `heimdall <args>` with stdin closed, both streams scanned for canaries.
        fn cli(&self, args: &[&str]) -> std::process::Output {
            let out = Command::new(bin())
                .args(args)
                .env_clear()
                .envs(self.vars.iter().map(|(k, v)| (k, v)))
                .current_dir(self.root.join("home"))
                .stdin(Stdio::null())
                .output()
                .unwrap();
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
            out
        }

        fn diagnostics(&self, out: &std::process::Output) -> String {
            format!(
                "exit {}; stdout tail: {:?}\nstderr tail: {:?}",
                out.status,
                super::diagnostic_tail(&out.stdout, &self.root),
                super::diagnostic_tail(&out.stderr, &self.root)
            )
        }

        fn json(&self, args: &[&str]) -> serde_json::Value {
            let out = self.cli(args);
            assert!(
                out.status.success(),
                "CLI failed: {}",
                self.diagnostics(&out)
            );
            serde_json::from_slice(&out.stdout)
                .unwrap_or_else(|_| panic!("CLI returned invalid JSON: {}", self.diagnostics(&out)))
        }
    }

    impl Drop for Runtime {
        fn drop(&mut self) {
            let Some(mut child) = self.child.take() else {
                return;
            };
            let _ = self.cli(&["--json", "service", "stop"]);
            let deadline = Instant::now() + Duration::from_secs(30);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if child.try_wait().ok().flatten().is_none() {
                // The exact child this test started.
                let _ = child.kill();
                let _ = child.wait();
            }
            if !std::thread::panicking() {
                let _ = self.log();
                super::assert_no_fixture_stores(&self.root);
            }
        }
    }

    /// m07-plan U1 `tui_standalone_access_and_stop` on a Windows pseudoconsole (the TUI
    /// standalone row, "Windows (ConPTY variant)"; the Unix row is
    /// `pty::tui_standalone_access_and_stop`): with no CLI command in between, an observed
    /// alias served by the fixture sshd is opened in the TUI (Destinations, search, its
    /// detail, which offers `c connect`), ⟨M07 W9d⟩ connected through the handoff (a
    /// trivial command on the fixture), and after the return the profile's access is
    /// stopped from the stop menu (option 3, the profile `dev`, a typed `yes`), the TUI
    /// answers `stop profile dev: OK`, and `q` leaves it with exit 0, the console's input
    /// mode cooked again and the alternate screen left as often as entered. Afterwards (not
    /// in between) every policy of the profile is paused. Every key is typed only once the
    /// frame it acts on is drawn (the M07 reading guard).
    ///
    /// **The connect handoff.** ⟨M07 W9d; ADR-0007 §12.52⟩ The TUI's `c` launches the
    /// verified client with only the alias; on Windows that is the pinned in-box
    /// `%SystemRoot%\System32\OpenSSH\ssh.exe`, which finds the account's profile from its
    /// token, so here the debug pinned-client redirect (`HEIMDALL_TEST_PINNED_CLIENT`, which
    /// the TUI honours as `heimdall connect` does) names a scratch copy of testkit's
    /// `hm-pinned-ssh`. That wrapper adds `-F` the scratch configuration, the isolated
    /// known-hosts options (and `StrictHostKeyChecking=yes`, `BatchMode=yes`,
    /// `LogLevel=ERROR`), checks the effective identity configuration with `ssh -G`, records
    /// its arguments (its argument record), and starts the real in-box client with the
    /// remote `echo <LOGIN>`. The alias reaches the fixture sshd (on Windows the harness's,
    /// `HM_FIXTURE_SSHD_*`, as A01 and A11 do) with a per-run key that only a fixture agent
    /// on a `heimdall-hmtest-` pipe holds (`IdentityAgent` that pipe, `IdentityFile` its
    /// public half, `IdentitiesOnly yes`). Asserted: the handoff ended `ssh <alias> exited
    /// with status 0`; the argument record has one start whose caller words are only the
    /// alias; the wrapper printed `hm-pinned-ssh: checked: identity agent fixture pipe` and
    /// no `refused:` line; the session's output reached the console; and the fixture sshd
    /// accepted exactly one login, with the per-run key, and refused no other key (printed
    /// for the native run's report as `tui standalone console: other keys offered: <n>`).
    ///
    /// **Isolation.** As [`windows_tui_walkthrough`]'s ([`env`]): separate homes in one
    /// `tempfile` root, the fixture stores in it, `PATH` only the system directory,
    /// `ProgramData` scratch (the in-box client's system configuration). The alias's scratch
    /// configuration (`HEIMDALL_TEST_SSH_HOME`, also the wrapper's `-F`) names only the
    /// loopback fixture and files inside the root. The runtime is this test's own `service
    /// run` there ([`Runtime`]).
    #[test]
    fn windows_tui_standalone_access_and_stop() {
        use heimdall_testkit::agent::{
            AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey,
        };
        use heimdall_testkit::home::{Scratch, ssh_option_path};
        use heimdall_testkit::pinned_ssh::{ArgumentRecord, WrapperConfig};
        use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

        const ALIAS: &str = "hm-m07-fixture";
        const LOGIN: &str = "HM-M07-FIXTURE-LOGIN";
        let _guard = super::parallel_test();
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        for d in [
            "home/appdata",
            "home/localappdata",
            "hh",
            "sshhome/etc-ssh",
            "sshhome/.ssh",
            "programdata",
            "temp",
            "pinned",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        // The fixture sshd (the harness's on Windows) and a fixture agent holding the
        // per-run key; the key's comment is not a canary (the client may print it).
        let fixtures = Scratch::new().unwrap();
        let user_key = FixtureKey::generate().with_comment("hm-m07-fixture-key");
        let sshd = LoopbackSshd::start(
            &fixtures,
            SshdConfig {
                authorized: vec![user_key.public().clone()],
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("blocked: the fixture sshd is not available here: {e:?}"));
        let agent = FakeAgent::start(
            Endpoint::in_scratch(&fixtures, "agent").unwrap(),
            FakeAgentConfig {
                keys: vec![user_key.clone()],
                mode: AgentMode::Normal,
            },
        );
        let public = root.join("fixture_key.pub");
        user_key.write_public(&public).unwrap();
        let known = root.join("fixture_known_hosts");
        std::fs::write(&known, format!("{}\n", sshd.host_key_line)).unwrap();
        let global_known = root.join("empty_known_hosts");
        std::fs::write(&global_known, b"").unwrap();
        // The scratch configuration: the static pass's and the wrapper's `-F`.
        let config = root.join("sshhome/.ssh/config");
        let mut text = format!(
            "Host {ALIAS}\n    HostName {}\n    Port {}\n    IdentityFile {}\n    IdentitiesOnly yes\n    IdentityAgent {}\n",
            sshd.host,
            sshd.port,
            ssh_option_path(&public),
            ssh_option_path(Path::new(&agent.endpoint().locator()))
        );
        // The harness sshd's account (`HM_FIXTURE_SSHD_USER`), last, as
        // `ScratchHome::write_user_config` puts it; never on a command line.
        if let Some(account) = sshd.account() {
            text.push_str(&format!("Host *\n    User {account}\n"));
        }
        std::fs::write(&config, text).unwrap();
        // The scratch wrapper the redirect names, with its argument record.
        let record = root.join("pinned").join("args.ndjson");
        let wrapper = WrapperConfig {
            config: config.clone(),
            scratch_root: root.to_path_buf(),
            options: vec![
                format!("UserKnownHostsFile={}", ssh_option_path(&known)),
                format!("GlobalKnownHostsFile={}", ssh_option_path(&global_known)),
                "StrictHostKeyChecking=yes".to_owned(),
                "BatchMode=yes".to_owned(),
                "LogLevel=ERROR".to_owned(),
            ],
            trailing: vec!["echo".to_owned(), LOGIN.to_owned()],
            client: None,
        }
        .install_recording(&root.join("pinned"), &record)
        .unwrap_or_else(|e| panic!("the pinned-client wrapper: {e}"));
        let screen = root.join("screen.txt");
        let mut tui_vars = env(root, &screen);
        let vars: Vec<(String, String)> = tui_vars
            .iter()
            .filter(|(k, _)| k != "HEIMDALL_TEST_TUI_SCREEN")
            .cloned()
            .collect();
        // The redirect for the TUI only (the runtime launches no client).
        tui_vars.push((
            "HEIMDALL_TEST_PINNED_CLIENT".to_owned(),
            wrapper.to_string_lossy().into_owned(),
        ));
        let rt = Runtime::start(&vars, root);
        let added = rt.json(&["--json", "destination", "add", ALIAS, "--observed"]);
        assert_eq!(added["code"], "OK", "{added}");
        let listed = rt.json(&["--json", "inspect", "destinations"]);
        let n = ["items", "destinations"]
            .iter()
            .find_map(|k| listed["data"][k].as_array())
            .map_or(0, Vec::len);
        assert!(n > 0, "{listed}");

        let argv = vec![bin(), "tui".to_owned()];
        // The console child resizes only on a request file, which this test never writes.
        let mut command = TerminalCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_console::console_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .current_dir(root)
            .size(120, 40)
            .env(ARGV, serde_json::to_string(&argv).unwrap())
            .env(ENVS, serde_json::to_string(&tui_vars).unwrap())
            .env(RESIZE, root.join("resize").to_string_lossy().into_owned());
        for (key, value) in &tui_vars {
            command = command.env(key, value);
        }
        let mut t = command
            .spawn()
            .unwrap_or_else(|e| panic!("the pseudoconsole did not start: {e}"));
        wait_frame(&mut t, &screen, "the first frame", |f| {
            f.contains("Overview")
        });
        wait_frame(&mut t, &screen, "the runtime's listing", |f| {
            f.contains("Runtime: connected")
        });
        let count = format!("; {n} destinations");
        wait_frame(&mut t, &screen, "the static pass and the listing", |f| {
            f.contains(&count) && !f.contains("Static pass: running")
        });
        // Open the destination: Destinations, search, its detail.
        t.send(b"2").unwrap();
        wait_frame(&mut t, &screen, "the Destinations view", |f| {
            header(f).contains("[2 Destinations]")
        });
        t.send(b"/").unwrap();
        wait_frame(&mut t, &screen, "the search field", |f| {
            f.contains("Search: _")
        });
        t.send(ALIAS.as_bytes()).unwrap();
        let typed = format!("Search: {ALIAS}_");
        wait_frame(&mut t, &screen, "the typed search", |f| {
            f.contains(&typed) && selected_row(f).is_some_and(|r| r.contains(ALIAS))
        });
        t.send(b"\r").unwrap();
        let filter = format!("Filter: {ALIAS}");
        wait_frame(&mut t, &screen, "the search's filter", |f| {
            f.contains(&filter) && selected_row(f).is_some_and(|r| r.contains(ALIAS))
        });
        t.send(b"\r").unwrap();
        let detail = format!("{ALIAS}: observed destination");
        wait_frame(&mut t, &screen, "its detail", |f| {
            f.contains(&detail) && footer(f).contains("c connect")
        });
        // ⟨M07 W9d⟩ Connect through the handoff; the TUI returns when the client exits.
        let failed_before = sshd.failed_publickey_log().len();
        t.send(b"c").unwrap();
        let ended = format!("ssh {ALIAS} exited with status");
        wait_frame(&mut t, &screen, "the handoff's end", |f| f.contains(&ended));
        let after = frame(&screen);
        // The console's reader may trail the frame dump by a moment: wait (bounded) for
        // the wrapper's verdict and the session's output; the assertions below decide.
        let _ = t.expect("hm-pinned-ssh: ", Duration::from_secs(10));
        let _ = t.expect(LOGIN, Duration::from_secs(10));
        let console = t.text().replace('\n', "");
        assert!(
            after.contains(&format!("ssh {ALIAS} exited with status 0")),
            "frame tail: {:?}\nconsole tail: {:?}",
            super::diagnostic_tail(after.as_bytes(), root),
            super::diagnostic_tail(console.as_bytes(), root)
        );
        // The wrapper's argument record: one start, and the TUI passed only the alias.
        let lines = std::fs::read_to_string(&record).unwrap_or_default();
        let starts = ArgumentRecord::parse_all(&lines).unwrap_or_else(|e| panic!("{e}"));
        let [start] = starts.as_slice() else {
            panic!("one start of the wrapper: {} lines", starts.len());
        };
        assert_eq!(
            start.caller,
            [ALIAS],
            "the TUI handed only the alias to the client"
        );
        assert_eq!(start.trailing, ["echo", LOGIN]);
        assert_eq!(
            start.added[..2],
            ["-F".to_owned(), config.to_string_lossy().into_owned()],
            "the wrapper added the scratch configuration first"
        );
        // The guard's verdict (ADR-0007 §12.52): the effective identity agent is the
        // fixture's pipe, and nothing was refused.
        assert!(
            console.contains("hm-pinned-ssh: checked: identity agent fixture pipe")
                && !console.contains("hm-pinned-ssh: refused:"),
            "the wrapper's identity check passed on the fixture's agent: {:?}",
            super::diagnostic_tail(console.as_bytes(), root)
        );
        #[allow(clippy::print_stdout)] // a fact for the native run's report (M07-W9-R02)
        {
            println!(
                "tui standalone console: hm-pinned-ssh: checked: identity agent fixture pipe; refused: none"
            );
        }
        assert!(
            console.contains(LOGIN),
            "the fixture command ran on the fixture sshd: {:?}",
            super::diagnostic_tail(console.as_bytes(), root)
        );
        let offered = sshd.failed_publickey_log();
        let other = offered[failed_before.min(offered.len())..]
            .iter()
            .filter(|k| k.fingerprint != user_key.fingerprint())
            .count();
        #[allow(clippy::print_stdout)] // a fact for the native run's report
        {
            println!("tui standalone console: other keys offered: {other}");
        }
        assert_eq!(other, 0, "only the per-run key was offered: {offered:?}");
        let accepted = sshd.accepted_log();
        assert!(
            accepted.len() == 1 && accepted[0].fingerprint == user_key.fingerprint(),
            "exactly one login, with the per-run key: {accepted:?}"
        );
        // Back in the TUI, on the same detail (the status line shows the handoff's result
        // until the next key): stop the profile's access from the stop menu.
        assert!(
            after.contains(&detail),
            "frame tail: {:?}",
            super::diagnostic_tail(after.as_bytes(), root)
        );
        t.send(b"s").unwrap();
        wait_frame(&mut t, &screen, "the stop menu", |f| {
            f.contains("Four different actions")
        });
        t.send(b"3").unwrap();
        wait_frame(&mut t, &screen, "the profile action selected", |f| {
            f.contains("> 3. ")
        });
        t.send(b"\r").unwrap();
        wait_frame(&mut t, &screen, "the profile prompt", |f| {
            f.contains("Profile ID: _")
        });
        t.send(b"dev").unwrap();
        wait_frame(&mut t, &screen, "the typed profile", |f| {
            f.contains("Profile ID: dev_")
        });
        t.send(b"\r").unwrap();
        wait_frame(&mut t, &screen, "the confirmation", |f| {
            f.contains("Stop everything for profile dev") && f.contains("Type yes to confirm")
        });
        t.send(b"yes").unwrap();
        wait_frame(&mut t, &screen, "the typed yes", |f| {
            f.contains("Type yes to confirm [y/N]: yes_")
        });
        t.send(b"\r").unwrap();
        wait_frame(&mut t, &screen, "the stop's answer", |f| {
            f.contains("stop profile dev: ")
        });
        let answer = frame(&screen);
        assert!(
            answer.contains("stop profile dev: OK"),
            "{:?}",
            super::diagnostic_tail(answer.as_bytes(), root)
        );
        // `q` on a detail goes back; on the view it quits.
        t.send(b"q").unwrap();
        let deadline = Instant::now() + LONG;
        let left_detail = loop {
            if t.try_wait().is_some() {
                break false;
            }
            if !frame(&screen).contains(&detail) {
                break true;
            }
            assert!(
                Instant::now() < deadline,
                "q answered neither way; frame tail: {:?}",
                super::diagnostic_tail(frame(&screen).as_bytes(), root)
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        if left_detail {
            t.send(b"q").unwrap();
        }
        let code = t.wait(LONG);
        let text = t.text();
        heimdall_testkit::assert_no_canary(&text);
        let console = || super::diagnostic_tail(text.as_bytes(), root);
        assert_eq!(code, Some(0), "q exits 0; console tail: {:?}", console());
        assert!(
            text.contains("hm-console-modes before=Some(false) raw_seen=true after=Some(false)"),
            "the console's input was raw while the TUI ran and cooked again after: {:?}",
            console()
        );
        let raw = String::from_utf8_lossy(&t.output()).into_owned();
        assert_eq!(
            raw.matches("\u{1b}[?1049h").count(),
            raw.matches("\u{1b}[?1049l").count(),
            "the alternate screen is left as often as entered: {:?}",
            console()
        );
        // Afterwards (not in between): every policy of the profile is paused.
        let policies = rt.json(&["--json", "inspect", "policies"]);
        let dev: Vec<&serde_json::Value> = policies["data"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["profile"] == "dev")
            .collect();
        assert!(!dev.is_empty(), "{policies}");
        assert!(
            dev.iter().all(|p| p["paused_since"].is_string()),
            "{policies}"
        );
        drop(rt);
        drop(agent);
        drop(sshd);
    }
}
