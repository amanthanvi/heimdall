//! M03 wave 5 (U12): the TUI's M03 views through the real binary (m03-plan U12 "Tests",
//! TUI). Owner: worker T (`.m03-wave5-api.md` R1). At least one test stays ungated so the
//! target runs a test on every platform (check.sh fails a 0-test target).
//!
//! The pty cases (`#[cfg(unix)]`) run `heimdall tui` on a pseudo-terminal against a real
//! runtime started in this test process over a `heimdall_testkit::home::ScratchHome`,
//! as `tui_m02` does: a cleared environment, a stub `ssh` that contacts nothing, the
//! decoy counting agent at `SSH_AUTH_SOCK`, and the frame text read from
//! `HEIMDALL_TEST_TUI_SCREEN`. M03 records (a CA, enrollments, a pending enrollment
//! decision) are seeded into the scratch state store before the runtime starts, with
//! the store's own test seeding; nothing reaches a real host, key, agent or issuer.
//! The Windows rows of these cases need a native Windows pty harness (ConPTY), which
//! this suite does not have: they are `blocked` on Windows-native.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{AccountName, CaFingerprint, DestinationId, EnrollmentId, IdentityId};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentHold, EnrollmentRecord,
    EnrollmentState, ExistingAccessRecord, HoldReason, LateWrite, NoProxy, RegistryCanonical,
    RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_store::{IssuerRecord, NoFaults, Store};

/// The binary under test.
fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

fn t0() -> Timestamp {
    "2026-11-01T00:00:00Z".parse().unwrap()
}

fn ca() -> CaFingerprint {
    CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap()
}

/// A synthetic enrollment `n` of destination `dst-lab<n>` in `state`, its approved
/// target at `host:port` (a scratch loopback listener in the search case).
fn enrollment(n: u8, state: EnrollmentState, host: &str, port: u16) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    let account = AccountName::parse("deploy").unwrap();
    let at = t0().checked_add(Duration::from_secs(u64::from(n))).unwrap();
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: DestinationId::parse(&format!("dst-lab{n}")).unwrap(),
        account: account.clone(),
        ca_fingerprint: ca(),
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
            hostname: host.into(),
            port,
            user: account,
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                fingerprint: "SHA256:hostfixture".into(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes([n; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: (state == EnrollmentState::Held).then_some(EnrollmentHold {
            reason: HoldReason::HostKeyChanged,
            evidence_based: false,
        }),
        removal_origin: None,
        late_write: (state == EnrollmentState::Withdrawn).then(|| LateWrite {
            step_token: "st-fixture".into(),
            not_after_remote: 1_800_000_000,
        }),
        state,
        verified_at: None,
        evidence: None,
        created_at: at,
        updated_at: at,
    }
}

/// Into the state store at `db` (created at the current schema): one CA, then `with`.
fn seed(db: &Path, with: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()>) {
    let store = Store::open(db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            tx.insert_issuer(&IssuerRecord {
                ca_fingerprint: ca(),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture0".into(),
                state: CaState::Active,
                store_kind: StoreKind::LinuxSecretService,
                backup_sha256: "00".repeat(32),
                backup_created_at: t0(),
                restored_without_log: false,
                created_at: t0(),
                retired_at: None,
            })?;
            with(tx)
        })
        .unwrap();
}

/// Owner-only directories, whatever the umask (the devbox's is 002).
fn owner_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .unwrap();
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path).unwrap();
}

/// Ungated (every platform): with M03 state present (a CA and enrollments), the TUI
/// still refuses a stdin that is not a terminal before it touches anything: usage,
/// exit 2, the state store byte-identical and no runtime directory created.
#[test]
fn tui_refuses_a_non_terminal_with_m03_state_present() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("home");
    owner_dir(&home.join("state"));
    let db = home.join("state").join("state.db");
    seed(&db, |tx| {
        tx.seed_enrollment(&enrollment(1, EnrollmentState::Held, "example.invalid", 22))
    });
    let before = std::fs::read(&db).unwrap();
    let mut cmd = Command::new(bin());
    cmd.arg("tui")
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
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    heimdall_testkit::assert_no_canary(&text);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("terminal"), "{text}");
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
    assert!(!home.join("run").exists(), "no runtime was contacted");
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use heimdall_app::{Attendance, Caller, Operations};
    use heimdall_contract::request::{
        ConfirmTimeRequest, InspectRequest, InspectSubject, InteractionMode,
    };
    use heimdall_domain::enrollment::EnrollmentState;
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::time::{Clock, SyncStatus};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::ProjectionConfig;
    use heimdall_runtime::config::{Config, Paths};
    use heimdall_runtime::service::{ProjectionWiring, Service, ServiceOptions};
    use heimdall_testkit::home::ScratchHome;
    use heimdall_testkit::{ScriptedTimeSync, VirtualClock, assert_no_canary};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{SpecialCodeIndex, Termios, Winsize, tcgetattr, tcsetwinsize};
    use serde_json::Value;
    use tokio_util::sync::CancellationToken;

    use super::{bin, enrollment, seed};

    const SLAVE: &str = "HM_U12_PTY_SLAVE";
    const ARGV: &str = "HM_U12_PTY_ARGV";
    const LONG: Duration = Duration::from_secs(60);

    /// Child-mode entry of the pty cases (as `tui_m02`'s): a new session on the pty as
    /// its controlling terminal, then `exec` of the program named in [`ARGV`].
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

    // ---- the pty (tui_m02's, ADR-0007 §12.32 item 6) -----------------------------------

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
            set_size(&pty.held_slave(), rows, cols);
            pty
        }

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

        fn termios(&self) -> Termios {
            tcgetattr(self.held_slave()).unwrap()
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

    // ---- the runtime ---------------------------------------------------------------------

    /// One runtime instance serving the scratch home.
    struct Running {
        ops: Operations,
        handle: tokio::runtime::Handle,
        token: CancellationToken,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Running {
        fn stop(mut self) {
            self.token.cancel();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.token.cancel();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    struct World {
        home: ScratchHome,
        stubs: PathBuf,
        marks: PathBuf,
        clock: Arc<VirtualClock>,
        sync: Arc<ScriptedTimeSync>,
        runtime: Option<Running>,
        uid: u32,
    }

    impl World {
        /// A scratch home; `with` seeds the state store before the first runtime starts.
        fn new(
            with: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()>,
        ) -> World {
            use std::os::unix::fs::MetadataExt as _;
            let home = ScratchHome::new();
            std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
            std::fs::create_dir_all(home.git_home.join("etc-ssh")).unwrap();
            let stubs = home.root.join("stubs");
            let marks = home.root.join("marks");
            std::fs::create_dir(&stubs).unwrap();
            std::fs::create_dir(&marks).unwrap();
            let uid = std::fs::metadata(&home.root).unwrap().uid();
            seed(&home.state_dir.join("state.db"), with);
            let mut w = World {
                home,
                stubs,
                marks,
                clock: VirtualClock::at(heimdall_contract::Timestamp::now()),
                sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                runtime: None,
                uid,
            };
            w.start();
            w
        }

        /// Start a runtime over the home (with the world's clock and sync report).
        fn start(&mut self) {
            let paths = SshPaths::with_test_override(
                self.home.git_home.clone(),
                self.home.root.join("etc-ssh"),
            );
            let mut projection =
                ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone());
            projection.env = Env::from_vars([
                ("HOME", self.home.git_home.display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
            ]);
            let root = self.home.root.clone();
            let token = CancellationToken::new();
            let service_token = token.clone();
            let clock: Arc<dyn Clock> = self.clock.clone();
            let sync = self.sync.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let handle = rt.handle().clone();
                rt.block_on(async move {
                    let mut o = ServiceOptions::with_clock(clock, sync);
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
            self.runtime = Some(Running {
                ops,
                handle,
                token,
                thread: Some(thread),
            });
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
            self.runtime.as_ref().unwrap().handle.spawn(async move {
                let _ = tx.send(f.await);
            });
            rx.recv().expect("the runtime task finished")
        }

        fn ops(&self) -> Operations {
            self.runtime.as_ref().unwrap().ops.clone()
        }

        fn inspect(&self, subject: InspectSubject) -> Value {
            self.inspect_with_warnings(subject).0
        }

        /// The runtime's own `inspect` answer: its data and its warnings.
        fn inspect_with_warnings(
            &self,
            subject: InspectSubject,
        ) -> (Value, Vec<heimdall_contract::envelope::Warning>) {
            let caller = self.attended();
            let ops = self.ops();
            self.on(async move {
                ops.inspect(
                    &caller,
                    InspectRequest {
                        subject,
                        preview: None,
                    },
                )
                .await
                .map(|c| (c.data, c.warnings))
            })
            .unwrap()
        }

        fn stub_ssh(&self) {
            let marks = self.marks.display();
            let script = format!(
                "#!/bin/sh\n\
                 # hm-u12 stub ssh: contacts nothing.\n\
                 echo \"$*\" >> '{marks}/invocations'\n\
                 for a in \"$@\"; do\n\
                   case \"$a\" in\n\
                     -V) echo 'OpenSSH_9.9p1 hm-u12-stub' >&2; exit 0 ;;\n\
                     -G) echo 'user fixture'; echo 'hostname 127.0.0.1'; echo 'port 22'; exit 0 ;;\n\
                   esac\n\
                 done\n\
                 exit 0\n"
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

        fn wait_screen(&self, what: &str, cond: impl Fn(&str) -> bool) {
            let deadline = Instant::now() + LONG;
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

        /// `heimdall tui` on `pty`; waits until the runtime's listing and the static
        /// pass are on the screen.
        fn tui(&self, pty: &Pty) -> Proc {
            let argv = vec![OsString::from(bin()), OsString::from("tui")];
            let p = pty.start(&self.env(), &self.home.root, &argv);
            self.wait_screen("the runtime's listing", |s| {
                s.contains("Runtime: connected")
            });
            self.wait_screen("the static pass", |s| {
                s.contains("Static pass:") && !s.contains("Static pass: running")
            });
            p
        }

        fn read_mark(&self, name: &str) -> String {
            std::fs::read_to_string(self.marks.join(name)).unwrap_or_default()
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            if let Some(r) = self.runtime.take() {
                r.stop();
            }
        }
    }

    /// The screen's text with box borders removed and wrapped lines joined.
    fn flat(screen: &str) -> String {
        screen
            .replace(['│', '┌', '┐', '└', '┘', '─'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Quit with `q`; exit 0; the terminal's mode is what it was before, the alternate
    /// screen left as often as it was entered, and the cursor shown after the last entry.
    fn quit_restored(pty: &Pty, tui: Proc, before: &str) {
        pty.write(b"q");
        let status = tui.wait(LONG);
        assert_eq!(status.code(), Some(0), "{}", pty.transcript());
        assert_eq!(
            modes(&pty.termios()),
            before,
            "the terminal's mode is restored"
        );
        assert_eq!(
            pty.count("\u{1b}[?1049h"),
            pty.count("\u{1b}[?1049l"),
            "the alternate screen is left as often as entered"
        );
        let t = pty.transcript();
        assert!(
            t.rfind("\u{1b}[?25h") > t.rfind("\u{1b}[?1049h"),
            "the cursor is shown again after the last entry"
        );
        assert_no_canary(&t);
    }

    /// Every enrollment state the runtime lists, seeded one per destination.
    const SEEDED: [EnrollmentState; 20] = [
        EnrollmentState::Planned,
        EnrollmentState::Applying,
        EnrollmentState::OutcomeUnknown,
        EnrollmentState::Held,
        EnrollmentState::AppliedUnverified,
        EnrollmentState::ManualPending,
        EnrollmentState::Verifying,
        EnrollmentState::Verified,
        EnrollmentState::Reverifying,
        EnrollmentState::RollbackPending,
        EnrollmentState::RollbackUnknown,
        EnrollmentState::Removing,
        EnrollmentState::RemoveUnknown,
        EnrollmentState::ManualRemovalPending,
        EnrollmentState::RemovalVerifying,
        EnrollmentState::VerificationFailed,
        EnrollmentState::Removed,
        EnrollmentState::Withdrawn,
        EnrollmentState::FailedUnwritten,
        EnrollmentState::Abandoned,
    ];

    /// The runtime's own listing: (enrollment ID, state wire name).
    fn listed(w: &World) -> Vec<(String, String)> {
        w.inspect(InspectSubject::Enrollments)["enrollments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["enrollment_id"].as_str().unwrap().to_owned(),
                    e["state"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    /// m03-plan U12 `enrollment_states_rendered`: every enrollment state, seeded and as
    /// the runtime's `inspect enrollments` lists it, is on the Activity view with its
    /// state and a text marker; the held record needs attention on the overview, its
    /// detail shows the runtime's own `hold {reason, next}` (§17.25 item 4): the reason
    /// and every `next` command, exactly; and the withdrawn record's `late_write`
    /// residual is shown with its command.
    #[test]
    fn enrollment_states_rendered() {
        let w = World::new(|tx| {
            for (n, state) in (1u8..).zip(SEEDED) {
                tx.seed_enrollment(&enrollment(n, state, "example.invalid", 22))?;
            }
            Ok(())
        });
        w.stub_ssh();
        let runtime = listed(&w);
        assert_eq!(runtime.len(), SEEDED.len(), "{runtime:?}");
        // The runtime's hold of the held record (E2's fill, `EnrollmentView.hold`).
        let view = w.inspect(InspectSubject::Enrollments);
        let hold = view["enrollments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["state"] == "held")
            .and_then(|e| e.get("hold"))
            .cloned()
            .unwrap_or_else(|| panic!("the runtime reports no hold for the held record: {view}"));
        assert_eq!(hold["reason"], "host_key_changed", "{hold}");
        let next: Vec<String> = hold["next"]
            .as_array()
            .map(|n| n.iter().map(|c| c.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
        assert!(!next.is_empty(), "the runtime names the next steps: {hold}");
        let pty = Pty::open(50, 160);
        let before = modes(&pty.termios());
        let tui = w.tui(&pty);
        w.wait_screen("the held enrollment on the overview", |s| {
            s.contains("enrollment") && s.contains("is held")
        });
        pty.write(b"4");
        w.wait_screen("the enrollments", |s| s.contains("Enrollments"));
        let screen = w.screen();
        for (id, state) in &runtime {
            let row = screen
                .lines()
                .find(|l| l.contains(id.as_str()))
                .unwrap_or_else(|| panic!("{id} ({state}) not listed:\n{screen}"));
            assert!(
                row.split_whitespace().any(|w| w == state.as_str()),
                "{state}: {row}"
            );
            assert!(
                ["[OK]", "[!!]", "[..]", "[--]"]
                    .iter()
                    .any(|m| row.contains(m)),
                "{state}: no text marker: {row}"
            );
        }
        // The held record's detail (rows: decisions header, "none", operations header,
        // "none open", enrollments header; the held one is the 4th enrollment).
        let held = runtime.iter().position(|(_, s)| s == "held").unwrap();
        for _ in 0..held {
            pty.write(b"\x1b[B");
            std::thread::sleep(Duration::from_millis(30));
        }
        pty.write(b"\r");
        w.wait_screen("the held detail", |s| s.contains("State: held"));
        let detail = flat(&w.screen());
        assert!(detail.contains("[!!] Held: host_key_changed"), "{detail}");
        for n in &next {
            assert!(detail.contains(&format!("- `{n}`")), "{n}: {detail}");
        }
        assert!(!detail.contains("reason unknown"), "{detail}");
        pty.write(b"\x1b");
        if let Some(i) = runtime.iter().position(|(_, s)| s == "withdrawn") {
            w.wait_screen("the activity again", |s| s.contains("Enrollments"));
            let screen = w.screen();
            let row = screen
                .lines()
                .find(|l| l.contains(runtime[i].0.as_str()))
                .unwrap();
            assert!(row.contains("possible late write"), "{row}");
        }
        quit_restored(&pty, tui, &before);
    }

    /// m03-plan U12 ⟨r2⟩ `time_confirmation_chore_shown_after_reboot` (F14): with the
    /// time accepted, no chore; after a reboot (a new boot, the runtime restarted, sync
    /// not trusted) the overview shows `time_confirmation_after_reboot` first, Needs
    /// attention, with its one command `heimdall time confirm`; once the owner confirms
    /// time (attended) it is gone. The TUI keys on the runtime's warning reason
    /// `time_confirmation_after_reboot` (§17.25 item 15), which the runtime's own
    /// `inspect` answer carries here.
    #[test]
    fn time_confirmation_chore_shown_after_reboot() {
        let mut w = World::new(|_| Ok(()));
        w.stub_ssh();
        let pty = Pty::open(40, 160);
        let before = modes(&pty.termios());
        let tui = w.tui(&pty);
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !w.screen().contains("time_confirmation_after_reboot"),
            "{}",
            w.screen()
        );
        // The reboot: the runtime stops, the boot changes, it starts again.
        w.runtime.take().unwrap().stop();
        w.clock.reboot(heimdall_contract::Timestamp::now());
        w.sync.set(SyncStatus::Unknown);
        w.start();
        let (_, warnings) = w.inspect_with_warnings(InspectSubject::Capabilities);
        assert!(
            warnings.iter().any(|x| x.code == "TIME_UNCERTAIN"
                && x.reason.as_deref() == Some("time_confirmation_after_reboot")),
            "the runtime's warning carries the reason: {warnings:?}"
        );
        w.wait_screen("the chore", |s| {
            flat(s).contains("time_confirmation_after_reboot")
        });
        let screen = flat(&w.screen());
        assert!(screen.contains("[!!] Needs attention"), "{screen}");
        assert!(
            screen.contains(
                "[!!] time_confirmation_after_reboot: run `heimdall time confirm` (safe time cannot be established"
            ),
            "{screen}"
        );
        // The attended confirmation clears it.
        let caller = w.attended();
        let ops = w.ops();
        let observed_wall = Clock::wall(w.clock.as_ref());
        w.on(async move {
            ops.confirm_time(&caller, ConfirmTimeRequest { observed_wall })
                .await
                .map(|_| ())
        })
        .unwrap_or_else(|e| panic!("confirm: {} {}", e.code, e.message));
        w.wait_screen("the chore gone", |s| {
            !s.contains("time_confirmation_after_reboot")
        });
        quit_restored(&pty, tui, &before);
    }

    /// m03-plan U12 `tui_search_never_contacts_issuer_or_remote`: with enrollments whose
    /// approved targets and the aliases all point at a counting loopback listener, the
    /// decoy counting agent at `SSH_AUTH_SOCK`, and no issuer, the whole session (the
    /// listings, the enrollment views and every search keystroke) contacts neither the
    /// listener nor the agent, and runs no `ssh` but the static pass's `-V`. The issuer
    /// half: the TUI's refresh never names `issuer` and a search produces no request at
    /// all (`tui::view::tests::m03::m03_search_and_refresh_never_reach_the_issuer`).
    #[test]
    fn tui_search_never_contacts_issuer_or_remote() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let w = World::new(move |tx| {
            for (n, state) in (1u8..).zip([EnrollmentState::Verified, EnrollmentState::Held]) {
                tx.seed_enrollment(&enrollment(n, state, "127.0.0.1", port))?;
            }
            Ok(())
        });
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
        w.stub_ssh();
        let pty = Pty::open(40, 120);
        let before = modes(&pty.termios());
        let tui = w.tui(&pty);
        pty.write(b"4");
        w.wait_screen("the enrollments", |s| s.contains("Enrollments"));
        pty.write(b"2/");
        for (typed, shown) in [
            ("enr", "(0 of 0)"),
            ("\x7f\x7f\x7fissuer", "(0 of 0)"),
            ("\x7f\x7f\x7f\x7f\x7f\x7f127", "(0 of 0)"),
        ] {
            pty.write(typed.as_bytes());
            w.wait_screen(shown, |s| s.contains(shown));
        }
        pty.write(b"\x1b");
        std::thread::sleep(Duration::from_millis(500));
        quit_restored(&pty, tui, &before);
        stop.store(true, Ordering::SeqCst);
        counter.join().unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "the listener was contacted"
        );
        assert_eq!(w.home.decoy_agent().contact_count(), 0, "agent contacted");
        assert_eq!(w.home.decoy_agent().connections(), 0, "agent connected to");
        assert!(
            !w.read_mark("invocations")
                .lines()
                .any(|l| !l.trim().is_empty() && l.trim() != "-V"),
            "only the static pass's `ssh -V` ran: {}",
            w.read_mark("invocations")
        );
    }

    /// m03-plan U12 `tui_restores_terminal_after_enroll_decision`: a pending
    /// `enroll_account` decision opens readably (the plan line, the registry and its
    /// line digest, the disclosures, the runtime's own lock disclosure from `inspect
    /// capabilities` until the runtime reports it acknowledged, then not again) and
    /// read-only (§17.25 item 10, §17.26): its CLI command is shown for Approve, which is
    /// never offered here; Deny is its one verdict. Esc and anything but `yes` send
    /// nothing (the runtime still lists it pending); Tab does not toggle to Approve; the
    /// owner's typed `yes` sends `Attend` and Deny's `Decide`, the runtime answers, the
    /// TUI stays in its own terminal mode; and on quit the terminal is restored exactly.
    /// (A pending `approve_target_change` is seeded too, so the listing has a decidable
    /// decision beside the read-only one.)
    #[test]
    fn tui_restores_terminal_after_enroll_decision() {
        use heimdall_contract::enrollment::DisclosureKind;
        use heimdall_domain::decision::{
            DecisionKind, DecisionRecord, DecisionState, EnrollmentPlanSummary,
        };
        let did = heimdall_contract::ids::DecisionId::from_random_bytes([9; 16]);
        let did_text = did.to_string();
        let tid = heimdall_contract::ids::DecisionId::from_random_bytes([10; 16]);
        let tid_text = tid.to_string();
        let w = World::new(move |tx| {
            let r = enrollment(1, EnrollmentState::Planned, "example.invalid", 22);
            let now = heimdall_contract::Timestamp::now();
            let generation = tx.authority_generation()?;
            let mut proposed = r.target.clone();
            proposed.host_key.key = "AAAAC3NzaC1lZDI1NTE5AAAAIhostchanged".into();
            proposed.host_key.fingerprint = "SHA256:hostchanged".into();
            tx.insert_decision(&DecisionRecord {
                id: tid,
                kind: DecisionKind::ApproveTargetChange {
                    operation: heimdall_contract::ids::OperationId::from_random_bytes([7; 16]),
                    enrollment: r.id.clone(),
                    approved: r.target.clone(),
                    proposed,
                },
                generation,
                created_at: now,
                expires_at: now.checked_add(Duration::from_secs(900)).unwrap(),
                state: DecisionState::Pending,
                decided_at: None,
            })?;
            tx.insert_decision(&DecisionRecord {
                id: did,
                kind: DecisionKind::EnrollAccount {
                    operation: heimdall_contract::ids::OperationId::from_random_bytes([8; 16]),
                    plan_digest: heimdall_contract::setup::PlanDigest::parse(&"c".repeat(64))
                        .unwrap(),
                    summary: EnrollmentPlanSummary {
                        destination_id: r.destination.clone(),
                        alias: "lab1".to_owned(),
                        account: r.account.clone(),
                        form: r.form,
                        registry: r.registry.clone(),
                        line_sha256: r.line_sha256.clone(),
                        ca_fingerprint: r.ca_fingerprint.clone(),
                        approved_target: r.target.clone(),
                        invocation: vec!["ssh".to_owned(), "lab1".to_owned()],
                        host_trust: Vec::new(),
                        bootstrap: false,
                        disclosures: vec![
                            DisclosureKind::CaTrustBlastRadius,
                            DisclosureKind::LockContinuityOnce,
                        ],
                    },
                },
                generation,
                created_at: now,
                expires_at: now.checked_add(Duration::from_secs(900)).unwrap(),
                state: DecisionState::Pending,
                decided_at: None,
            })
        });
        w.stub_ssh();
        // The runtime's listing order is the Activity view's.
        let pending: Vec<String> = w.inspect(InspectSubject::Decisions)["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["decision_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(pending.len(), 2, "{pending:?}");
        let row = |id: &str| pending.iter().position(|p| p == id).unwrap();
        let pty = Pty::open(40, 140);
        let before = modes(&pty.termios());
        let tui = w.tui(&pty);
        let raw = modes(&pty.termios());
        assert_ne!(raw, before, "the TUI runs in raw mode");
        w.wait_screen("the decisions", |s| {
            s.contains(&did_text) && s.contains(&tid_text)
        });
        let open = |at: usize| {
            pty.write(b"4");
            std::thread::sleep(Duration::from_millis(100));
            pty.write(b"\x1b[H");
            std::thread::sleep(Duration::from_millis(50));
            for _ in 0..at {
                pty.write(b"\x1b[B");
                std::thread::sleep(Duration::from_millis(30));
            }
            pty.write(b"\r");
        };
        open(row(&did_text));
        w.wait_screen("the modal", |s| {
            flat(s).contains("Plan: enroll deploy at lab1")
        });
        let modal = flat(&w.screen());
        // The runtime's own lock report (`inspect capabilities` `lock`, §17.25 item 21):
        // not acknowledged yet, so its text is shown in the record that carries it.
        let lock = w.inspect(InspectSubject::Capabilities)["lock"].clone();
        let said = lock["disclosure"]
            .as_str()
            .unwrap_or_else(|| panic!("the runtime reports the lock disclosure: {lock}"))
            .to_owned();
        assert!(lock.get("acknowledged_at").is_none(), "{lock}");
        for want in [
            "Registry ~/.ssh/authorized_keys (resolved by remote_home)",
            "line SHA-256",
            "* ca_trust_blast_radius:",
            &format!(
                "Lock disclosure (shown once; recorded when the decision is approved): {}",
                flat(&said)
            ),
            "Approve in the CLI: run `heimdall enroll lab1`",
            "Deny? Type yes to confirm",
        ] {
            assert!(modal.contains(want), "{want}: {modal}");
        }
        assert!(!modal.contains("Approve? Type yes"), "{modal}");
        // Esc, and an answer other than yes, send nothing.
        for keys in [&b"yes\x1b"[..], &b"no\r"[..]] {
            pty.write(b"\x1b[F");
            std::thread::sleep(Duration::from_millis(200));
            pty.write(keys);
            w.wait_screen("nothing sent", |s| {
                let f = flat(s);
                f.contains("nothing was sent") && !f.contains("Plan: enroll deploy")
            });
            assert_eq!(
                w.inspect(InspectSubject::Decisions)["decisions"]
                    .as_array()
                    .unwrap()
                    .len(),
                2,
                "still pending"
            );
            open(row(&did_text));
            w.wait_screen("the modal again", |s| {
                flat(s).contains("Plan: enroll deploy")
            });
        }
        pty.write(b"\x1b");
        w.wait_screen("the modal closed", |s| {
            !flat(s).contains("Plan: enroll deploy")
        });
        // Shown once: once the runtime records the acknowledgement (as approving a
        // decision that showed it does, in the CLI), the modal no longer shows it.
        let ops = w.ops();
        let at = w
            .on(async move { ops.acknowledge_lock_disclosure().await })
            .unwrap_or_else(|e| panic!("acknowledge: {} {}", e.code, e.message));
        assert!(
            w.inspect(InspectSubject::Capabilities)["lock"]
                .get("acknowledged_at")
                .is_some(),
            "recorded"
        );
        open(row(&did_text));
        w.wait_screen("the acknowledged lock disclosure", |s| {
            flat(s).contains("Lock disclosure: acknowledged")
        });
        let modal = flat(&w.screen());
        assert!(
            modal.contains(&format!(
                "Lock disclosure: acknowledged {}; not shown again",
                at.strftime("%Y-%m-%dT%H:%M:%SZ")
            )),
            "{modal}"
        );
        assert!(!modal.contains(&flat(&said)), "{modal}");
        pty.write(b"\x1b");
        w.wait_screen("the modal closed", |s| {
            !flat(s).contains("Plan: enroll deploy")
        });
        // The enroll decision itself: Tab keeps Deny (never Approve); typed yes: Deny
        // is sent and answered.
        open(row(&did_text));
        w.wait_screen("the modal for the deny", |s| {
            flat(s).contains("Plan: enroll deploy")
        });
        pty.write(b"\t");
        std::thread::sleep(Duration::from_millis(100));
        let modal = flat(&w.screen());
        assert!(modal.contains("Deny? Type yes"), "{modal}");
        assert!(!modal.contains("Approve? Type yes"), "{modal}");
        pty.write(b"\x1b[F");
        std::thread::sleep(Duration::from_millis(200));
        pty.write(b"yes\r");
        w.wait_screen("the answer", |s| {
            s.contains(&format!("decision {did_text}:"))
        });
        let answer = w.screen();
        let answer = answer
            .lines()
            .find(|l| l.contains(&format!("decision {did_text}:")))
            .unwrap();
        // The seeded record waits on no real `enrollment.apply` operation, so the
        // driver's precheck may refuse the verdict; either way it was sent and answered.
        eprintln!("the runtime's answer: {}", answer.trim());
        assert!(
            !flat(&w.screen()).contains("Plan: enroll deploy"),
            "the modal closed"
        );
        assert_eq!(modes(&pty.termios()), raw, "still in the TUI's mode");
        quit_restored(&pty, tui, &before);
    }
}
