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
//! those, plus the debug-build test variables the case needs. The harness checks all
//! three point inside its own root before it starts anything. `SSH_AUTH_SOCK` is never
//! set; the verified client `ssh` on `PATH` is a stub script that answers `-V` and
//! contacts nothing. The imported destinations use reserved `.invalid` host names and
//! are never contacted. Only processes this test started are stopped: the runtime by
//! `heimdall service stop` (or its exact `Child` handle if that fails), the TUI by `q`
//! (or its exact handle).
//!
//! **The screen.** Text checks read the frame the TUI drew (`HEIMDALL_TEST_TUI_SCREEN`,
//! debug builds); the idle check reads the raw pty transcript, since any byte counts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

#[cfg(unix)]
mod pty {
    use std::ffi::{OsStr, OsString};
    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
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

        fn write(&self, bytes: &[u8]) {
            let fd = self.master.as_ref().unwrap().try_clone().unwrap();
            std::fs::File::from(fd).write_all(bytes).unwrap();
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
            Proc(Some(child))
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
    struct Proc(Option<Child>);

    impl Proc {
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
                if w.cli(&["--json", "service", "status"]).status.success() {
                    break;
                }
                if let Some(s) = w.service.as_mut().unwrap().try_wait().unwrap() {
                    panic!("the runtime exited early ({s}): {}", w.service_log());
                }
                assert!(Instant::now() < deadline, "the runtime did not start");
                std::thread::sleep(Duration::from_millis(100));
            }
            w
        }

        /// The launch environment every `heimdall` of this test gets (rule 4).
        fn env(&self) -> Vec<(OsString, OsString)> {
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
            std::fs::read_to_string(self.root.path().join("service.log")).unwrap_or_default()
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

        fn json(&self, args: &[&str]) -> Value {
            let out = self.cli(args);
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "{args:?}: exit {:?}: {text} {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
            serde_json::from_str(text.trim()).unwrap()
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
                    "timed out waiting for {what}; the last frame:\n{screen}"
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
            assert_no_canary(&self.service_log());
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
        assert_eq!(tui.wait(LONG).code(), Some(0));
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

    /// Report one key's samples; returns its P95.
    fn report(key: &str, mut samples: Vec<Duration>, timeouts: usize, host: &str) -> Duration {
        samples.sort();
        let (p50, p95) = (pct(&samples, 50), pct(&samples, 95));
        eprintln!(
            "M07 A20 key latency (debug build, completed frame showing the key's effect, 5000 destinations, a live slow operation): key {key}: samples {}, timeouts at 2 s {timeouts}, p50 {:.1} ms, p95 {:.1} ms, max {:.1} ms; host {host}",
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
        p95s.push(("Tab", report("Tab", tab, timeouts, &host)));

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
        p95s.push(("PageDown", report("PageDown", page, timeouts, &host)));

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
            report("search keystroke", search, timeouts, &host),
        ));

        // The slow operation was live throughout.
        let shown = w.json(&["--json", "operation", "show", &op]);
        assert_eq!(shown["state"], "running", "{shown}");
        pty.write(b"\x1b");
        w.wait_screen("the search closed", LONG, |s| {
            s.contains(" total · / to search")
        });
        pty.write(b"q");
        assert_eq!(tui.wait(LONG).code(), Some(0));
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
    /// shown; the stop menu opened and escaped; the operation cancelled with `x`; `?`; and
    /// `q`, with the terminal's modes byte-identical to before.
    #[test]
    fn a20_keyboard_walkthrough() {
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

        // The key help, and any key closes it.
        pty.write(b"?");
        w.wait_screen("the key help", LONG, |s| s.contains("this key help"));
        pty.write(b"\x1b");
        w.wait_screen("the help closed", LONG, |s| !s.contains("this key help"));

        // Quit: exit 0, the terminal as it was.
        pty.write(b"q");
        assert_eq!(tui.wait(LONG).code(), Some(0));
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

    /// m07-plan U1 `tui_standalone_access_and_stop` (the TUI standalone row): an observed
    /// alias served by the loopback fixture sshd, reached with a per-run key held by a
    /// disposable `ssh-agent`. With no CLI command in between: the destination is opened,
    /// connected through the handoff (a trivial command on the fixture), and after the
    /// return the profile's access is stopped from the stop menu; the terminal is restored.
    ///
    /// The verified client is a scratch wrapper around the system `ssh` that adds only
    /// isolation and the fixture's own files: `-F` the scratch configuration, the fixture
    /// key through `IdentityAgent` = the disposable agent with `IdentitiesOnly=yes`, no
    /// certificate, scratch known hosts, no global known hosts and no multiplexing, so the
    /// owner's `~/.ssh`, agent and keys are never read.
    #[test]
    fn tui_standalone_access_and_stop() {
        use heimdall_testkit::agent::{
            AgentOptions, DisposableSshAgent, FixtureKey, KeyConstraints,
        };
        use heimdall_testkit::home::Scratch;
        use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

        const ALIAS: &str = "hm-m07-fixture";
        const LOGIN: &str = "HM-M07-FIXTURE-LOGIN";
        let fixtures = Scratch::new().unwrap();
        let key = FixtureKey::generate().with_comment("hm-m07-fixture-key");
        let agent = DisposableSshAgent::start(&fixtures, AgentOptions::default())
            .unwrap_or_else(|e| panic!("blocked: the disposable ssh-agent cannot start here: {e}"));
        agent.add_key(&key, KeyConstraints::default()).unwrap();
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
        let public = w.root.path().join("fixture_key.pub");
        key.write_public(&public).unwrap();
        let marks = w.root.path().join("ssh-invocations");
        let sock = agent.socket.display().to_string();
        w.write_ssh(&format!(
            "#!/bin/sh\n\
             # hm-m07 fixture client: the system ssh, isolated, reaching only the loopback fixture.\n\
             for a in \"$@\"; do case \"$a\" in -V) exec /usr/bin/ssh -V ;; esac; done\n\
             echo \"$*\" >> '{marks}'\n\
             exec /usr/bin/ssh -F '{config}' -o IdentityFile='{public}' -o IdentitiesOnly=yes \
             -o IdentityAgent='{sock}' -o CertificateFile=none -o UserKnownHostsFile='{known}' \
             -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes \
             -o ControlMaster=no -o ControlPath=none -o LogLevel=ERROR \"$@\" 'echo {LOGIN}'\n",
            marks = marks.display(),
            config = config.display(),
            public = public.display(),
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
            "{screen}\n{}",
            String::from_utf8_lossy(&pty.bytes())
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
        assert_eq!(tui.wait(LONG).code(), Some(0));
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
        drop(agent);
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
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let mut env = vec![
            ("HEIMDALL_HOME".to_owned(), text(&root.join("hh"))),
            ("HOME".to_owned(), text(&root.join("home"))),
            (
                "HEIMDALL_TEST_SSH_HOME".to_owned(),
                text(&root.join("sshhome")),
            ),
            ("HEIMDALL_TEST_TUI_SCREEN".to_owned(), text(screen)),
            (
                "HEIMDALL_TEST_TIME_SYNC".to_owned(),
                "synchronized".to_owned(),
            ),
            ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
            ("PATH".to_owned(), format!(r"{system}\System32")),
        ];
        for k in ["SystemRoot", "windir", "ComSpec", "PATHEXT", "TEMP", "TMP"] {
            if let Ok(v) = std::env::var(k) {
                env.push((k.to_owned(), v));
            }
        }
        env
    }

    /// Runs `heimdall service stop` in the scratch home when dropped (a no-op when no
    /// runtime runs there).
    struct StopRuntime(Vec<(String, String)>);

    impl Drop for StopRuntime {
        fn drop(&mut self) {
            let _ = Command::new(bin())
                .args(["--json", "service", "stop"])
                .env_clear()
                .envs(self.0.iter().map(|(k, v)| (k, v)))
                .stdin(Stdio::null())
                .output();
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
            assert!(
                t.try_wait().is_none(),
                "the TUI ended waiting for {what}; console: {}\nframe: {f}",
                t.text()
            );
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; console: {}\nframe: {f}",
                t.text()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn windows_tui_walkthrough() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        for d in ["home", "hh", "sshhome/etc-ssh"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let screen = root.join("screen.txt");
        let resize = root.join("resize");
        let vars = env(root, &screen);
        let _stop = StopRuntime(vars.clone());
        let argv = vec![bin(), "tui".to_owned()];
        let mut t = TerminalCommand::new(std::env::current_exe().unwrap())
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
            .env(RESIZE, resize.to_string_lossy().into_owned())
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
        let answered =
            answered.unwrap_or_else(|| panic!("no frame showed the key; console: {}", t.text()));
        assert!(
            answered <= BAR,
            "the key after the resize took {answered:?} (bar {BAR:?})"
        );
        t.send(b"q").unwrap();
        let code = t.wait(LONG);
        let text = t.text();
        heimdall_testkit::assert_no_canary(&text);
        assert_eq!(code, Some(0), "q exits 0; console: {text}");
        assert!(
            text.contains("hm-console-modes before=Some(false) raw_seen=true after=Some(false)"),
            "the console's input was raw while the TUI ran and cooked again after: {text}"
        );
        let raw = String::from_utf8_lossy(&t.output()).into_owned();
        assert_eq!(
            raw.matches("\u{1b}[?1049h").count(),
            raw.matches("\u{1b}[?1049l").count(),
            "the alternate screen is left as often as entered: {text}"
        );
    }
}
