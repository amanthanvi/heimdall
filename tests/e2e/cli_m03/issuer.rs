//! M03 wave 5 (U12): `e2e_cli_m03` submodule `issuer` (owner: worker I, `.m03-wave5-api.md`
//! R1): `heimdall issuer …` through the **real binary** against this test's **in-process
//! runtime** (`Service::start_with`), whose issuer child is the real binary's
//! `internal issuer` on the scratch store (`HEIMDALL_TEST_SECRET_STORE=scratch`). A
//! runtime the CLI started would wire the account's real `~/.ssh`, so effectful commands
//! run only while the in-process runtime serves.
//!
//! **Terminal.** The ceremony and prompt cases re-execute this test binary as the leader
//! of a new session ([`issuer_cli_pty_child`]): with a pty slave it acquires the pty as
//! its controlling terminal, then execs `heimdall` with stdout and stderr on separate
//! files (stdin and stderr on the pty when a case says so), so the test can show what
//! reaches the terminal only. Without a slave the session has no controlling terminal.
//!
//! **Stores (ADR-0008 §17.25 item 7).** The scratch store is a test-configuration kind:
//! `issuer init|rotate begin|restore` stop at its registration (a test kind is never on
//! the wire), but `issuer retire` deletes its item by exact locator in a debug build (item
//! 7 (d)). On macOS the **product-file** test store
//! (`HEIMDALL_TEST_SECRET_STORE=product-file:<path>`, item 7 (b)) is a file keychain this
//! test creates in its scratch `HEIMDALL_HOME`, never added to the search list (checked
//! before and after, by digest, nothing printed) and removed at the end: there the whole
//! registration, passphrase and R2B chain runs on the keychain code path. Never the login
//! keychain. Windows DPAPI under the scratch home and Linux (no disposable Secret Service)
//! are named in each test.
//!
//! **Isolation.** Cleared environments (`PATH`, a scratch `HOME`, the scratch
//! `HEIMDALL_HOME`, the scratch store); fixture keys are generated per run; no owner key,
//! agent or keychain is touched; every output byte is scanned for canaries. Only
//! processes this test started are stopped, by their own handles.

#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_credential::cert::SecretCaKey;
use heimdall_issuer::store::{SecretStore, StoreItemRef};
use heimdall_store::{IssuerRecord, Store};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::scratch_store::ScratchSecretStore;
use serde_json::Value;

use super::{Out, bin, run};

const SLAVE: &str = "HM_I_PTY_SLAVE";
const ARGV: &str = "HM_I_ARGV";
const ENVS: &str = "HM_I_ENV";
const STDIN_TTY: &str = "HM_I_STDIN_TTY";
const STDERR_TTY: &str = "HM_I_STDERR_TTY";
const LIMIT: Duration = Duration::from_secs(120);

/// The scratch store's directory under the state directory (`m03_cmd::SCRATCH_STORE_DIR`).
const SCRATCH_STORE_DIR: &str = "scratch-secret-store";

// --- the in-process runtime ---------------------------------------------------------------

struct Running {
    store: Arc<Store>,
    /// The runtime's operations (its uninstall fence included).
    ops: heimdall_app::Operations,
    token: tokio_util::sync::CancellationToken,
    thread: std::thread::JoinHandle<()>,
    issuer: Option<heimdall_issuer::client::ChildIssuer>,
}

/// A scratch installation: its home, an account directory, the in-process runtime, and
/// (macOS) the product-file test store's keychain.
struct Rig {
    tmp: tempfile::TempDir,
    home: PathBuf,
    account: PathBuf,
    service: Option<Running>,
    /// The product-file test store this test created (`None`: the scratch store).
    product: Option<PathBuf>,
    /// The `heimdall` program every process of this rig runs (the CLI cases, the issuer
    /// child): this rig's **own snapshot** of the built binary, in its scratch directory.
    ///
    /// Why (round 3's `issuer_store_locked` flake, root-caused): a keychain item's access
    /// list trusts the code **at the program's path on disk** at the time of the write.
    /// `target/debug/heimdall` is shared, and a concurrent `cargo` build (another worker,
    /// another suite) replaces it while a ceremony runs; the item then trusted the new
    /// file, the running CLI's read-back failed (`errSecAuthFailed`) and the ceremony
    /// ended `issuer_store_locked`. The product now refuses that write
    /// (`issuer_init_refuses_when_its_executable_is_replaced_mid_ceremony`); the snapshot
    /// keeps every rig's program fixed for its whole life, so no rebuild elsewhere can
    /// change it mid-test.
    program: PathBuf,
}

/// A directory created owner-only (the devbox's umask is 002).
fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

impl Rig {
    /// A started runtime with no CA, on the scratch store.
    fn new() -> Rig {
        Rig::with_store(false)
    }

    /// A started runtime with no CA, on the product-file test store: a file keychain this
    /// test creates (marker first) in its scratch home (macOS).
    #[cfg(target_os = "macos")]
    fn product() -> Rig {
        Rig::with_store(true)
    }

    fn with_store(product: bool) -> Rig {
        let tmp = tempfile::Builder::new().prefix("hm-i-").tempdir().unwrap();
        private_dir(tmp.path());
        let home = tmp.path().join("hh");
        heimdall_runtime::Paths::under(&home).ensure().unwrap();
        let account = tmp.path().join("account");
        private_dir(&account);
        let program_dir = tmp.path().join("program");
        private_dir(&program_dir);
        let program = program_dir.join("heimdall");
        std::fs::copy(bin(), &program).unwrap();
        let product = product.then(|| {
            let path = home.join("test-ca.keychain-db");
            create_product_store(&path);
            path
        });
        let mut rig = Rig {
            tmp,
            home,
            account,
            service: None,
            product,
            program,
        };
        rig.start();
        // The native environment's record (a `setup` would make it), its managed
        // permissions off: the RegisterIssuer approval turns them on (D4 item 1 step 7).
        let env = rig
            .store()
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .unwrap();
        rig.store()
            .transaction(|tx| {
                if tx.environment(&env)?.is_none() {
                    tx.upsert_environment(&heimdall_domain::environment::EnvironmentRecord {
                        id: env.clone(),
                        device: heimdall_contract::ids::DeviceId::from_random_bytes([8; 16]),
                        kind: heimdall_domain::environment::EnvironmentKind::NativeSession,
                        label: None,
                        permissions: heimdall_domain::environment::EnvironmentPermissions {
                            automatic_activation: false,
                            managed_signing: false,
                            issuer_access: false,
                        },
                    })?;
                }
                Ok(())
            })
            .unwrap();
        rig
    }

    /// `HEIMDALL_TEST_SECRET_STORE`'s value for this rig.
    fn store_value(&self) -> String {
        match &self.product {
            Some(p) => format!("product-file:{}", p.display()),
            None => "scratch".to_owned(),
        }
    }

    /// The product-file test store, as this installation's environment sees it (macOS).
    #[cfg(target_os = "macos")]
    fn product_store(&self) -> Box<dyn SecretStore> {
        let env = self
            .store()
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .unwrap();
        heimdall_issuer::store::test_product::open(self.product.as_ref().unwrap(), &env).unwrap()
    }

    fn state_dir(&self) -> PathBuf {
        heimdall_runtime::Paths::under(&self.home).state_dir
    }

    /// The scratch store the CLI and the issuer child select (created owner-only).
    fn scratch_store(&self) -> ScratchSecretStore {
        let dir = self.state_dir().join(SCRATCH_STORE_DIR);
        private_dir(&dir);
        ScratchSecretStore::new(dir)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    /// The environment every CLI process of this rig gets.
    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), self.account.clone().into()),
            ("HEIMDALL_HOME".into(), self.home.clone().into()),
            (
                "HEIMDALL_TEST_SECRET_STORE".into(),
                self.store_value().into(),
            ),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("TERM".into(), "dumb".into()),
        ]
    }

    fn start(&mut self) {
        use heimdall_runtime::service::{ManagedOptions, ServiceOptions, SessionLockWiring};
        let paths = heimdall_runtime::Paths::under(&self.home);
        let child = heimdall_issuer::client::ChildCommand {
            program: self.program.clone(),
            args: vec!["internal".into(), "issuer".into()],
            env: vec![
                ("HEIMDALL_HOME".into(), self.home.clone().into()),
                (
                    "HEIMDALL_TEST_SECRET_STORE".into(),
                    self.store_value().into(),
                ),
            ],
        };
        let token = tokio_util::sync::CancellationToken::new();
        let service_token = token.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let clock = Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap());
                let mut o = ServiceOptions::with_clock(
                    clock,
                    heimdall_testkit::ScriptedTimeSync::new(
                        heimdall_domain::time::SyncStatus::Synchronized,
                    ),
                );
                o.endpoint_prefix = "hmi-".to_owned();
                o.managed = Some(ManagedOptions {
                    session_lock: SessionLockWiring::Source(Arc::new(
                        heimdall_testkit::session_lock::FakeSessionLockSource::default(),
                    )),
                    issuer_command: Some(child),
                    ..ManagedOptions::default()
                });
                let service = heimdall_runtime::Service::start_with(
                    paths,
                    heimdall_runtime::Config::default(),
                    o,
                    service_token,
                )
                .await
                .unwrap();
                let _ = tx.send((
                    Arc::clone(service.store()),
                    service.issuer(),
                    service.operations().clone(),
                ));
                let _ = service.run().await;
            });
        });
        let (store, issuer, ops) = rx.recv().expect("the service started");
        self.service = Some(Running {
            store,
            ops,
            token,
            thread,
            issuer,
        });
    }

    /// Stop the runtime and wait until its issuer child (by its own PID and start
    /// token) is gone.
    fn stop(&mut self) {
        let Some(s) = self.service.take() else {
            return;
        };
        let child = s.issuer.as_ref().and_then(|i| i.identity());
        s.token.cancel();
        let _ = s.thread.join();
        if let Some(id) = child {
            let deadline = Instant::now() + Duration::from_secs(20);
            while heimdall_runtime::platform::process_start_time(id.pid) == id.start_token
                && id.start_token.is_some()
            {
                assert!(Instant::now() < deadline, "the issuer child survived");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn store(&self) -> Arc<Store> {
        Arc::clone(&self.service.as_ref().unwrap().store)
    }

    /// Register a CA directly (state `active`), its K_ca in the scratch store and its
    /// locator recorded, then restart so the issuer child loads it.
    fn seed_ca(&mut self) -> (CaFingerprint, StoreItemRef) {
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        let public = key.public_openssh().unwrap();
        let item = self.scratch_store().put(&fp, &key).unwrap();
        drop(key);
        let now = Timestamp::now();
        let locator = item.locator.clone();
        self.store()
            .transaction(|tx| {
                tx.insert_issuer(&IssuerRecord {
                    ca_fingerprint: fp.clone(),
                    public_key: public.clone(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: now,
                    restored_without_log: false,
                    created_at: now,
                    retired_at: None,
                })?;
                tx.set_issuer_store_locator(&fp, &locator)
            })
            .unwrap();
        self.stop();
        self.start();
        (fp, item)
    }

    /// A K_ca in the scratch store that no registration names (an orphan).
    fn seed_orphan(&self) -> StoreItemRef {
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        self.scratch_store().put(&fp, &key).unwrap()
    }

    fn ca_state(&self, fp: &CaFingerprint) -> Option<CaState> {
        self.store()
            .transaction(|tx| tx.issuer(fp))
            .unwrap()
            .map(|r| r.state)
    }

    /// The newest event's sequence in this installation's environment (a request that
    /// changed anything leaves an event).
    #[cfg(unix)]
    fn event_head(&self) -> u64 {
        let env = self
            .store()
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .unwrap();
        self.store()
            .transaction(move |tx| {
                tx.events_after(
                    &env,
                    0,
                    &heimdall_contract::event::EventFilter::default(),
                    1,
                )
            })
            .unwrap()
            .head_seq
    }

    /// ⟨ADR-0008 D9 item 1⟩ A saved standing policy `id` applicable here (its profile, this
    /// installation's environment), with its own maximum window, cutoff and lock behaviour:
    /// the "saved limits" the runtime's lock disclosure states.
    #[cfg(target_os = "macos")]
    fn seed_policy(
        &self,
        id: &str,
        lock_behavior: heimdall_contract::managed::LockBehavior,
        max_window: Duration,
        cutoff_at: Option<Timestamp>,
    ) {
        use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
        use heimdall_domain::profile::ProfileDefinition;
        let env = self
            .store()
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .unwrap();
        let profile = heimdall_contract::ids::ProfileId::parse(&format!("{id}-profile")).unwrap();
        let policy = heimdall_contract::ids::PolicyId::parse(id).unwrap();
        self.store()
            .transaction(move |tx| {
                tx.upsert_profile(&ProfileDefinition {
                    id: profile.clone(),
                    revision: 1,
                    scope: heimdall_domain::scope::Scope::empty(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: policy.clone(),
                        revision: PolicyRevision(1),
                        profile: profile.clone(),
                        workspace: None,
                        scope: heimdall_domain::scope::Scope::empty(),
                        environments: [env.clone()].into_iter().collect(),
                        max_window,
                        pause: PauseState::Active,
                        cutoff_at,
                        source: PolicySource::SetupDefault,
                        lock_behavior,
                        connection: Default::default(),
                    },
                    false,
                )
                .map(|_| ())
            })
            .unwrap();
    }

    fn pending(&self) -> Vec<heimdall_domain::decision::DecisionRecord> {
        self.store()
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
    }

    /// The CLI ([`Rig::program`]) with stdin closed, no terminal involved (as the parent's
    /// `run`, with this rig's program).
    fn cli(&self, args: &[&str]) -> Out {
        let out = Command::new(&self.program)
            .args(args)
            .env_clear()
            .env("HEIMDALL_HOME", &self.home)
            .env("HOME", &self.account)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("PATH", "/usr/bin:/bin")
            .env("HEIMDALL_TEST_SECRET_STORE", self.store_value())
            .stdin(Stdio::null())
            .output()
            .expect("spawn heimdall");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        assert_no_canary(&out.stdout);
        assert_no_canary(&out.stderr);
        out
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.stop();
        if let Some(path) = self.product.take() {
            remove_product_store(&path, &self.home);
        }
    }
}

// --- the product-file test store (macOS) ----------------------------------------------------

/// SHA-256 of `security <args>`'s output (the user search list, the default keychain):
/// compared before and after, never printed.
#[cfg(target_os = "macos")]
fn security_digest(args: &[&str]) -> String {
    let out = Command::new("/usr/bin/security")
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    heimdall_issuer::backup::sha256_hex(&out.stdout)
}

/// The owner's keychain search list and default keychain, as digests.
#[cfg(target_os = "macos")]
fn owner_keychains() -> (String, String) {
    (
        security_digest(&["list-keychains", "-d", "user"]),
        security_digest(&["default-keychain", "-d", "user"]),
    )
}

/// Create the product-file test store at `path` (marker first, then a file keychain with a
/// per-run password held in memory only); the search list and default keychain must not
/// change.
#[cfg(target_os = "macos")]
fn create_product_store(path: &Path) {
    let before = owner_keychains();
    let password = heimdall_issuer::backup::Passphrase::generate().unwrap();
    heimdall_issuer::store::test_product::create(path, password.expose()).unwrap();
    assert_eq!(
        owner_keychains(),
        before,
        "the test keychain joined the search list"
    );
    let listed = Command::new("/usr/bin/security")
        .args(["list-keychains", "-d", "user"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&listed.stdout).contains(&*path.to_string_lossy()),
        "the test keychain is not in the search list"
    );
}

#[cfg(not(target_os = "macos"))]
fn create_product_store(_: &Path) {
    unreachable!("the product-file test store is macOS-only in this suite");
}

/// Remove the product-file test store (keychain and marker), by path.
#[cfg(target_os = "macos")]
fn remove_product_store(path: &Path, home: &Path) {
    let before = owner_keychains();
    let removed = heimdall_issuer::store::test_product::remove(path, home);
    if !std::thread::panicking() {
        removed.unwrap();
        assert!(!path.exists(), "the test keychain was removed");
        assert_eq!(owner_keychains(), before);
    }
}

#[cfg(not(target_os = "macos"))]
fn remove_product_store(_: &Path, _: &Path) {}

// --- the terminal -------------------------------------------------------------------------

/// Child-mode entry: a new session (with the pty as its controlling terminal when a slave
/// is given), then `exec` of the argv from the parent (never holding a passphrase).
#[cfg(unix)]
#[test]
#[ignore = "child-mode entry of the issuer pty cases, started by them"]
fn issuer_cli_pty_child() {
    use std::os::unix::process::CommandExt as _;
    let (Some(argv), Some(envs)) = (std::env::var(ARGV).ok(), std::env::var(ENVS).ok()) else {
        return;
    };
    rustix::process::setsid().unwrap();
    if let Some(slave) = std::env::var_os(SLAVE) {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave)
            .unwrap();
        rustix::process::ioctl_tiocsctty(&tty).unwrap();
        if std::env::var_os(STDIN_TTY).is_some() {
            rustix::stdio::dup2_stdin(&tty).unwrap();
        }
        if std::env::var_os(STDERR_TTY).is_some() {
            rustix::stdio::dup2_stderr(&tty).unwrap();
        }
    }
    let argv: Vec<String> = serde_json::from_str(&argv).unwrap();
    let envs: Vec<(String, String)> = serde_json::from_str(&envs).unwrap();
    heimdall_testkit::term::default_terminal_signals_for_exec().unwrap();
    let err = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(envs)
        .stdin(if std::env::var_os(STDIN_TTY).is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .exec();
    panic!("exec failed: {err}");
}

#[cfg(unix)]
mod term {
    use std::io::{Read as _, Write as _};
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::*;

    /// A pseudo-terminal whose output is drained into an in-memory transcript.
    pub(super) struct Pty {
        master: OwnedFd,
        pub(super) slave: PathBuf,
        _slave_fd: OwnedFd,
        output: Arc<Mutex<Vec<u8>>>,
        stop: Arc<AtomicBool>,
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    impl Pty {
        pub(super) fn open() -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let slave = PathBuf::from(std::ffi::OsStr::from_bytes(name.as_bytes()));
            let slave_fd = rustix::fs::open(
                &slave,
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let output = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let reader = master.try_clone().unwrap();
            let sink = Arc::clone(&output);
            let done = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut f = std::fs::File::from(reader);
                let mut buf = [0u8; 4096];
                while !done.load(Ordering::SeqCst) {
                    match f.read(&mut buf) {
                        Ok(n) if n > 0 => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            Pty {
                master,
                slave,
                _slave_fd: slave_fd,
                output,
                stop,
            }
        }

        pub(super) fn transcript(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        /// Wait until the transcript contains `needle`; `false` when `child` exited first.
        pub(super) fn wait_for(&self, needle: &str, child: &mut Child) -> bool {
            let deadline = Instant::now() + LIMIT;
            loop {
                if self.transcript().contains(needle) {
                    return true;
                }
                if child.try_wait().unwrap().is_some() {
                    std::thread::sleep(Duration::from_millis(100));
                    return self.transcript().contains(needle);
                }
                assert!(Instant::now() < deadline, "no {needle:?} on the terminal");
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// Type raw bytes at the terminal.
        pub(super) fn type_bytes(&self, bytes: &[u8]) {
            let mut f = std::fs::File::from(self.master.try_clone().unwrap());
            let _ = f.write_all(bytes);
        }

        /// Type `text` and a newline.
        pub(super) fn type_line(&self, text: &str) {
            self.type_bytes(format!("{text}\n").as_bytes());
        }
    }
}

#[cfg(unix)]
use term::Pty;

/// One started CLI case: its process, what the test gave it, its output files.
struct Started {
    child: Child,
    given: Vec<OsString>,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl Drop for Started {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Where a case's stdin and stderr go (stdout is always its own file).
#[derive(Clone, Copy)]
struct Wiring {
    /// The pty is the controlling terminal.
    tty: bool,
    stdin_tty: bool,
    stderr_tty: bool,
}

/// ⟨ADR-0008 §17.27 item 5⟩ A ceremony's invocation: the pty is the controlling terminal
/// and stdin (an interactive invocation); stdout and stderr stay their own files, so the
/// test shows what reaches the terminal only.
const CEREMONY: Wiring = Wiring {
    tty: true,
    stdin_tty: true,
    stderr_tty: false,
};
/// ⟨§17.27 item 5⟩ stdin redirected (`/dev/null`) while the pty stays the controlling
/// terminal: not an interactive invocation.
#[cfg(unix)]
const REDIRECTED_STDIN: Wiring = Wiring {
    tty: true,
    stdin_tty: false,
    stderr_tty: false,
};
const PROMPT: Wiring = Wiring {
    tty: true,
    stdin_tty: true,
    stderr_tty: true,
};
const NO_TTY: Wiring = Wiring {
    tty: false,
    stdin_tty: false,
    stderr_tty: false,
};

#[cfg(unix)]
fn start_cli(rig: &Rig, case: &str, args: &[&str], pty: Option<&Pty>, wiring: Wiring) -> Started {
    let mut argv = vec![rig.program.to_string_lossy().into_owned()];
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    start_argv(rig, case, argv, pty, wiring)
}

/// [`start_cli`] for any program (`argv[0]`), with the rig's environment.
#[cfg(unix)]
fn start_argv(
    rig: &Rig,
    case: &str,
    argv: Vec<String>,
    pty: Option<&Pty>,
    wiring: Wiring,
) -> Started {
    let exe = std::env::current_exe().unwrap();
    let envs: Vec<(String, String)> = rig
        .env()
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    let stdout = rig.file(&format!("{case}.stdout"));
    let stderr = rig.file(&format!("{case}.stderr"));
    let mut cmd = Command::new(&exe);
    let entry = [
        "--exact",
        "issuer::issuer_cli_pty_child",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ];
    cmd.args(entry)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(ARGV, serde_json::to_string(&argv).unwrap())
        .env(ENVS, serde_json::to_string(&envs).unwrap())
        .current_dir(rig.tmp.path());
    if let (Some(p), true) = (pty, wiring.tty) {
        cmd.env(SLAVE, &p.slave);
        if wiring.stdin_tty {
            cmd.env(STDIN_TTY, "1");
        }
        if wiring.stderr_tty {
            cmd.env(STDERR_TTY, "1");
        }
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let mut given: Vec<OsString> = vec![exe.into_os_string()];
    given.extend(entry.iter().map(OsString::from));
    given.extend(argv.into_iter().map(OsString::from));
    given.extend(envs.into_iter().flat_map(|(k, v)| [k.into(), v.into()]));
    Started {
        child,
        given,
        stdout,
        stderr,
    }
}

/// Wait for the case to exit; its exit code and its stdout/stderr (scanned).
fn finish(started: &mut Started) -> Out {
    finish_within(started, LIMIT).expect("the CLI case did not finish")
}

/// [`finish`] bounded by `limit`: `None` while the case still runs then (the case is
/// stopped by its own handle when `started` drops).
fn finish_within(started: &mut Started, limit: Duration) -> Option<Out> {
    let deadline = Instant::now() + limit;
    let code = loop {
        if let Some(s) = started.child.try_wait().unwrap() {
            break s.code().unwrap_or(-1);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = std::fs::read_to_string(&started.stdout).unwrap_or_default();
    let stderr = std::fs::read_to_string(&started.stderr).unwrap_or_default();
    assert_no_canary(&stdout);
    assert_no_canary(&stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    Some(Out {
        code,
        stdout,
        stderr,
    })
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// A run of 26 base32 symbols in groups of five (a shown passphrase) in `text`.
fn has_passphrase_shape(text: &str) -> bool {
    heimdall_testkit::ca::ceremony::find_passphrase(text.as_bytes()).is_some()
}

fn reason(env: &Value) -> &str {
    env["data"]["error"]["reason"].as_str().unwrap_or_default()
}

// --- the tests ----------------------------------------------------------------------------

/// The JSON envelope of every issuer command where no terminal or runtime is involved
/// (all platforms): the ceremonies refuse `--non-interactive` first (exit 3, effect
/// `none`); `restore` without `--not-stolen` and a malformed fingerprint are usage
/// errors (exit 2); the read-only `status` and `bundle` never start a runtime (exit 5).
/// Nothing creates the Heimdall home, and none answers "not available".
#[test]
fn issuer_commands_json_envelopes_without_a_runtime_or_terminal() {
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    private_dir(&account);
    let cases: &[(&[&str], i32, &str)] = &[
        (
            &["issuer", "init", "--backup-out", "b.enc"],
            3,
            "INTERACTION_REQUIRED",
        ),
        (
            &[
                "issuer",
                "init",
                "--backup-out",
                "b",
                "--replace-orphan",
                "fp",
                "--no-bundle-available",
            ],
            3,
            "INTERACTION_REQUIRED",
        ),
        (
            &["issuer", "rotate", "begin", "--backup-out", "b.enc"],
            3,
            "INTERACTION_REQUIRED",
        ),
        (
            &["issuer", "restore", "--backup", "b.enc", "--not-stolen"],
            3,
            "INTERACTION_REQUIRED",
        ),
        (&["issuer", "unlock"], 3, "INTERACTION_REQUIRED"),
        (&["issuer", "status"], 5, "SERVICE_UNAVAILABLE"),
        (
            &["issuer", "bundle", "--out", "o.json"],
            5,
            "SERVICE_UNAVAILABLE",
        ),
        (&["issuer", "retire", "SHA256:abc"], 2, "USAGE_ERROR"),
    ];
    for (i, (line, exit, code)) in cases.iter().enumerate() {
        let home = scratch.path().join(format!("home-{i}"));
        let mut argv = vec!["--json", "--non-interactive"];
        argv.extend_from_slice(line);
        let out = run(&home, &account, &argv, &[]);
        assert_eq!(out.code, *exit, "{line:?}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], *code, "{line:?}: {out:?}");
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{line:?}");
        assert!(
            !out.message().contains("not available in this build"),
            "{line:?}"
        );
        assert!(!home.exists(), "{line:?} created the Heimdall home");
    }
    // Without --non-interactive and without --not-stolen: the ADR-0005 §5.3 guidance,
    // a usage error before any runtime contact.
    let home = scratch.path().join("home-restore");
    let out = run(
        &home,
        &account,
        &["--json", "issuer", "restore", "--backup", "b.enc"],
        &[],
    );
    assert_eq!(out.code, 2, "{out:?}");
    assert!(out.message().contains("--not-stolen"), "{out:?}");
    assert!(out.message().contains("rotate"), "{out:?}");
    assert!(!home.exists());
}

/// `issuer_init_prints_passphrase_only_to_tty` (m03-plan U12): `issuer init` on a real
/// pty (the controlling terminal; stdin, stdout and stderr are not the terminal), with
/// `--json`. Without a controlling terminal it is refused (exit 3) before the runtime is
/// contacted.
///
/// * **macOS, the product-file test store** (ADR-0008 §17.25 item 7 (b)): the decision
///   with its disclosures (the shared texts), the typed `yes`, the backup written, then
///   the passphrase **on the terminal only**: not before the `yes`, not in stdout or
///   stderr, not in any argument or variable a process of this test was given or the
///   running CLI's arguments, not in any file of the installation (the state database,
///   its logs, the keychain, the backup); `written` clears its screen region; the CA is
///   registered (exit 0) with its keychain item; and stock `ssh-keygen` decrypts the
///   backup with it, typed at its terminal prompt.
/// * **Linux** (no disposable Secret Service; the scratch store is a test kind, never on
///   the wire): the ceremony stops at the registration, exit 4, nothing written, no
///   passphrase anywhere. The passphrase half is **not** proven there.
#[cfg(unix)]
#[test]
fn issuer_init_prints_passphrase_only_to_tty() {
    #[cfg(target_os = "macos")]
    let rig = Rig::product();
    #[cfg(not(target_os = "macos"))]
    let rig = Rig::new();
    let _ = rig.scratch_store();
    let backup = rig.file("ca-backup.key");
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];

    // No controlling terminal: refused first.
    let mut started = start_cli(&rig, "no-tty", &args, None, NO_TTY);
    let out = finish(&mut started);
    assert_eq!(out.code, 3, "{out:?}");
    assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{out:?}");
    assert!(out.message().contains("terminal"), "{out:?}");

    #[cfg(target_os = "macos")]
    {
        let (fp, passphrase, started) = init_on_pty(&rig, &backup);
        // ssh-keygen decrypts the backup with the passphrase typed at its prompt.
        let public = keygen_public_key(&rig, &backup, &passphrase);
        assert_eq!(
            heimdall_issuer::ceremony::public_key_fingerprint(public.trim()),
            Some(fp.clone())
        );
        for g in &started.given {
            assert!(!g.to_string_lossy().contains(passphrase.as_str()));
        }
        let items = rig.product_store().list().unwrap();
        assert_eq!(items.len(), 1, "one keychain item");
        assert_eq!(items[0].fingerprint, fp);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let pty = Pty::open();
        let mut started = start_cli(&rig, "init", &args, Some(&pty), CEREMONY);
        let out = finish(&mut started);
        let transcript = pty.transcript();
        assert_eq!(out.code, 4, "{out:?}\n{transcript}");
        let env = out.json();
        assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{out:?}");
        assert_eq!(reason(&env), "issuer_store_unavailable", "{out:?}");
        assert!(
            out.message().contains("test-configuration store"),
            "{out:?}"
        );
        assert_eq!(env["data"]["error"]["effect_status"], "none");
        assert!(rig.pending().is_empty(), "no RegisterIssuer decision");
        assert!(!backup.exists(), "no backup file");
        assert!(files_under(&rig.state_dir().join(SCRATCH_STORE_DIR)).is_empty());
        assert!(!transcript.contains("Backup passphrase"), "{transcript}");
        assert!(!has_passphrase_shape(&transcript));
        assert!(!has_passphrase_shape(&out.stdout) && !has_passphrase_shape(&out.stderr));
        for f in files_under(rig.tmp.path()) {
            let text = String::from_utf8_lossy(&std::fs::read(&f).unwrap_or_default()).into_owned();
            assert!(!text.contains("Backup passphrase"), "{}", f.display());
        }
        for g in &started.given {
            assert!(!has_passphrase_shape(&g.to_string_lossy()));
        }
        assert_no_canary(&transcript);
    }
}

/// The running process `pid`'s arguments as the kernel reports them (`ps`), for the
/// argv check only; never printed.
#[cfg(target_os = "macos")]
fn process_args(pid: u32) -> String {
    let out = Command::new("/bin/ps")
        .args(["-o", "args=", "-p", &pid.to_string()])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every form a shown passphrase may take: joined, grouped by spaces, grouped by `-`.
#[cfg(target_os = "macos")]
fn passphrase_forms(joined: &str) -> Vec<String> {
    let groups: Vec<String> = joined
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    vec![joined.to_owned(), groups.join(" "), groups.join("-")]
}

/// `issuer init` on a pty against the rig's product-file store, through to `registered`:
/// the passphrase checks of `issuer_init_prints_passphrase_only_to_tty`. Returns the CA,
/// the passphrase (for scanning and the decryption; never printed) and the finished case.
#[cfg(target_os = "macos")]
fn init_on_pty(rig: &Rig, backup: &Path) -> (CaFingerprint, String, Started) {
    use heimdall_contract::enrollment::DisclosureKind;
    use heimdall_issuer::ceremony::{DisclosureContext, disclosure_text};
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];
    let pty = Pty::open();
    let mut started = start_cli(rig, "init", &args, Some(&pty), CEREMONY);
    assert!(
        pty.wait_for("Type 'yes' to register this CA: ", &mut started.child),
        "{}",
        pty.transcript()
    );
    let shown = pty.transcript();
    assert!(shown.contains("Register CA SHA256:"), "{shown}");
    for kind in [
        DisclosureKind::SameUserIssuerBoundary,
        DisclosureKind::BackupInstructions,
    ] {
        let text = disclosure_text(kind, &DisclosureContext::default());
        assert!(shown.contains(&text), "{kind:?} shown: {shown}");
    }
    assert!(
        !has_passphrase_shape(&shown),
        "no passphrase before the yes"
    );
    assert!(!backup.exists(), "nothing written before the yes");
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    assert!(
        pty.wait_for("Type 'written'", &mut started.child),
        "{}",
        pty.transcript()
    );
    let shown = pty.transcript();
    let joined = String::from_utf8(
        heimdall_testkit::ca::ceremony::find_passphrase(shown.as_bytes()).expect("shown"),
    )
    .unwrap();
    assert!(
        backup.exists(),
        "the backup is written before the passphrase is shown"
    );
    // While it is shown: not in the running CLI's arguments.
    let running = process_args(started.child.id());
    assert!(running.contains("issuer"), "the CLI is the running program");
    for form in passphrase_forms(&joined) {
        assert!(!running.contains(&form));
    }
    let before_written = shown.len();
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("written");
    let out = finish(&mut started);
    let transcript = pty.transcript();
    assert_eq!(out.code, 0, "{out:?}\n{transcript}");
    let env = out.json();
    assert_eq!(env["code"], "OK", "{out:?}");
    let ca = &env["data"]["cas"][0];
    assert_eq!(ca["state"], "active", "{env}");
    assert_eq!(ca["store"], "macos_login_keychain", "{env}");
    let fp = CaFingerprint::parse(ca["fingerprint"].as_str().unwrap()).unwrap();
    // `written` cleared the passphrase's region (cursor up, column 1, clear to the end).
    let after = &transcript[before_written..];
    assert!(after.contains("A\r\x1b[J"), "cleared after written");
    assert!(transcript.contains(&format!("CA {fp} registered")));
    // The passphrase reached the terminal only.
    for form in passphrase_forms(&joined) {
        assert!(!out.stdout.contains(&form) && !out.stderr.contains(&form));
        for g in &started.given {
            assert!(!g.to_string_lossy().contains(&form));
        }
        for f in files_under(rig.tmp.path()) {
            let bytes = std::fs::read(&f).unwrap_or_default();
            assert!(
                !bytes.windows(form.len()).any(|w| w == form.as_bytes()),
                "the passphrase is in {}",
                f.display()
            );
        }
    }
    assert_no_canary(&transcript);
    (fp, joined, started)
}

/// Stock `ssh-keygen -y -f <backup>` on a pty, the passphrase typed at its prompt (never
/// an argument): the public key it prints.
#[cfg(target_os = "macos")]
fn keygen_public_key(rig: &Rig, backup: &Path, passphrase: &str) -> String {
    let keygen = "/usr/bin/ssh-keygen";
    assert!(Path::new(keygen).is_file(), "stock ssh-keygen");
    let pty = Pty::open();
    let argv = vec![
        keygen.to_owned(),
        "-y".to_owned(),
        "-f".to_owned(),
        backup.to_string_lossy().into_owned(),
    ];
    let mut s = start_argv(rig, "keygen", argv, Some(&pty), PROMPT);
    assert!(
        pty.wait_for("passphrase", &mut s.child),
        "{}",
        pty.transcript()
    );
    let running = process_args(s.child.id());
    assert!(running.contains("ssh-keygen"));
    assert!(!running.contains(passphrase));
    for g in &s.given {
        assert!(!g.to_string_lossy().contains(passphrase));
    }
    pty.type_line(passphrase);
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "ssh-keygen exit {}", out.code);
    // The child-mode entry's own libtest line precedes the program's output.
    out.stdout
        .lines()
        .find(|l| l.starts_with("ssh-ed25519 "))
        .unwrap_or_default()
        .to_owned()
}

/// `register_issuer`'s typed confirmation (m03-plan U12 "the typed `yes` confirmation for
/// every decision kind"), macOS on the product-file test store: at `issuer init`'s
/// prompt, end of input, `no` and Ctrl-C send nothing more (exit 3
/// `INTERACTION_REQUIRED`: nothing written, stored or registered, no `Decide`); a process
/// without a terminal and `--non-interactive` are refused before any runtime contact (exit
/// 3); `yes` registers. Windows (DPAPI under the scratch home) needs a native console
/// harness; Linux has no product store.
#[cfg(target_os = "macos")]
#[test]
fn issuer_init_register_issuer_typed_yes_sends_nothing_without_yes() {
    let rig = Rig::product();
    let backup = rig.file("typed.key");
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];
    let registered = |rig: &Rig| rig.store().transaction(|tx| tx.issuers()).unwrap().len();
    for (label, answer) in [
        ("EOF", &b"\x04"[..]),
        ("no", &b"no\n"[..]),
        ("Ctrl-C", &b"\x03"[..]),
    ] {
        let pty = Pty::open();
        let mut s = start_cli(&rig, &format!("reg-{label}"), &args, Some(&pty), CEREMONY);
        assert!(
            pty.wait_for("Type 'yes' to register this CA: ", &mut s.child),
            "{label}"
        );
        std::thread::sleep(Duration::from_millis(300));
        pty.type_bytes(answer);
        let out = finish(&mut s);
        assert_eq!(out.code, 3, "{label}: {out:?}\n{}", pty.transcript());
        assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{label}");
        assert!(!backup.exists(), "{label}: no backup");
        assert!(
            rig.product_store().list().unwrap().is_empty(),
            "{label}: no item"
        );
        assert_eq!(registered(&rig), 0, "{label}: nothing registered");
        assert!(!has_passphrase_shape(&pty.transcript()), "{label}");
    }
    for (label, argv, wiring) in [
        ("non-TTY", args.to_vec(), NO_TTY),
        (
            "--non-interactive",
            [&["--non-interactive"][..], &args[..]].concat(),
            CEREMONY,
        ),
    ] {
        let pty = Pty::open();
        let mut s = start_cli(&rig, label, &argv, Some(&pty), wiring);
        let out = finish(&mut s);
        assert_eq!(out.code, 3, "{label}: {out:?}");
        assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{label}");
        assert!(
            !pty.transcript().contains("Register CA"),
            "{label}: nothing sent"
        );
    }
    assert_eq!(registered(&rig), 0);
    // `yes` registers.
    let (fp, _passphrase, _s) = init_on_pty(&rig, &backup);
    assert_eq!(rig.ca_state(&fp), Some(CaState::Active));
}

/// `issuer rotate begin` past the registration (D4 item 1 steps for the successor CA),
/// macOS on the product-file test store: after an `init`, the successor's decision names
/// the CA it rotates, `yes`, the backup, the passphrase on the terminal, `written`, and the
/// successor is registered with its own keychain item (exit 0).
#[cfg(target_os = "macos")]
#[test]
fn issuer_rotate_begin_registers_the_successor_on_the_product_store() {
    let rig = Rig::product();
    let (old, _p, _s) = init_on_pty(&rig, &rig.file("first.key"));
    let backup = rig.file("successor.key");
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "rotate",
        "begin",
        "--backup-out",
        backup_arg.as_str(),
    ];
    let pty = Pty::open();
    let mut s = start_cli(&rig, "rotate", &args, Some(&pty), CEREMONY);
    assert!(
        pty.wait_for("Type 'yes' to register this CA: ", &mut s.child),
        "{}",
        pty.transcript()
    );
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    assert!(pty.wait_for("Type 'written'", &mut s.child));
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("written");
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    let env = out.json();
    let cas = env["data"]["cas"].as_array().unwrap();
    assert_eq!(cas.len(), 2, "{env}");
    let new = cas
        .iter()
        .find(|c| c["fingerprint"] != old.as_str())
        .unwrap();
    let new_fp = CaFingerprint::parse(new["fingerprint"].as_str().unwrap()).unwrap();
    assert!(backup.exists());
    let items = rig.product_store().list().unwrap();
    assert!(
        items.iter().any(|i| i.fingerprint == new_fp),
        "the successor's item"
    );
    assert!(
        items.iter().any(|i| i.fingerprint == old),
        "the old item stays"
    );
    assert_eq!(
        new["store_locator"],
        items
            .iter()
            .find(|i| i.fingerprint == new_fp)
            .unwrap()
            .locator
            .as_str()
    );
}

/// `issuer restore` past the registration (D4 item 4; ADR-0008 §17.22 item 12), macOS on
/// the product-file test store, the passphrase typed with echo off:
///
/// * **log lost** (a fresh installation, no record of the CA): the key-only restore's
///   decision with its residuals-unknown disclosure, `yes`, registered with
///   `restored_without_log` and its keychain item (exit 0);
/// * **log intact, same locator** (the CA recorded, its item present): adopted and
///   reloaded, no new decision (exit 0);
/// * **log intact, a new locator** (the record names another locator than the restore
///   writes): the registration again with the expected locator, `yes`, approved: the CA's
///   recorded locator is now the new item's (compare and swap) and the old one is listed as
///   displaced. A keychain locator names this installation only, so the displaced item
///   (another installation's locator) is **not** deleted by this store (exit 4,
///   `issuer_store_unavailable`): the genuinely-new-locator deletion is the Linux Secret
///   Service's (native row).
#[cfg(target_os = "macos")]
#[test]
fn issuer_restore_paths_past_registration_on_the_product_store() {
    use heimdall_issuer::backup::{self, Passphrase};
    // Log lost: A's backup restored on a fresh installation B.
    let a = Rig::product();
    let backup_a = a.file("a.key");
    let (fp, passphrase, _s) = init_on_pty(&a, &backup_a);
    let b = Rig::product();
    let backup_arg = backup_a.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "restore",
        "--backup",
        backup_arg.as_str(),
        "--not-stolen",
    ];
    let restore = |rig: &Rig, case: &str, passphrase: &str, decision: Option<&str>| {
        let pty = Pty::open();
        let mut s = start_cli(rig, case, &args, Some(&pty), CEREMONY);
        assert!(pty.wait_for("Backup passphrase: ", &mut s.child), "{case}");
        std::thread::sleep(Duration::from_millis(300));
        pty.type_line(passphrase);
        if let Some(prompt) = decision {
            assert!(
                pty.wait_for(prompt, &mut s.child),
                "{case}: {}",
                pty.transcript()
            );
            std::thread::sleep(Duration::from_millis(300));
            pty.type_line("yes");
        }
        let out = finish(&mut s);
        let t = pty.transcript();
        for form in passphrase_forms(passphrase) {
            assert!(!t.contains(&form), "{case}: echo was off");
            assert!(!out.stdout.contains(&form) && !out.stderr.contains(&form));
        }
        (out, t)
    };
    let (out, t) = restore(
        &b,
        "log-lost",
        &passphrase,
        Some("Type 'yes' to register this restored CA: "),
    );
    assert_eq!(out.code, 0, "{out:?}\n{t}");
    assert!(t.contains("Key-only restore"), "{t}");
    let ca = &out.json()["data"]["cas"][0];
    assert_eq!(ca["fingerprint"], fp.as_str());
    assert_eq!(ca["restored_without_log"], true);
    assert_eq!(ca["state"], "active");
    assert_eq!(b.product_store().list().unwrap()[0].fingerprint, fp);

    // Log intact, same locator: adopted and reloaded, no new decision.
    let (out, t) = restore(&a, "log-intact", &passphrase, None);
    assert_eq!(out.code, 0, "{out:?}\n{t}");
    assert!(t.contains("restored to the store and reloaded"), "{t}");
    assert!(!t.contains("Type 'yes'"), "{t}");
    assert_eq!(a.product_store().list().unwrap().len(), 1);

    // Log intact, a new locator: a CA recorded with another installation's locator, its
    // backup made here with a per-run passphrase, no item in this store.
    let mut c = Rig::product();
    let key = heimdall_credential::cert::SecretCaKey::generate().unwrap();
    let c_fp = key.fingerprint().unwrap();
    let pass = Passphrase::generate().unwrap();
    let prepared = backup::prepare(&key, &pass).unwrap();
    let c_backup = c.file("c.key");
    backup::write_exact(&c_backup, &prepared).unwrap();
    let other = format!(
        "service=heimdall-issuer/{};account=env_other_installation",
        c_fp.as_str()
    );
    let now = Timestamp::now();
    let public = key.public_openssh().unwrap();
    drop(key);
    let (other_c, sha) = (other.clone(), prepared.sha256.clone());
    c.store()
        .transaction(move |tx| {
            tx.insert_issuer(&IssuerRecord {
                ca_fingerprint: c_fp.clone(),
                public_key: public.clone(),
                state: CaState::Active,
                store_kind: StoreKind::MacosLoginKeychain,
                backup_sha256: sha.clone(),
                backup_created_at: now,
                restored_without_log: false,
                created_at: now,
                retired_at: None,
            })?;
            tx.set_issuer_store_locator(&c_fp, &other_c)
        })
        .unwrap();
    let c_fp = prepared_fp(&c_backup, &pass);
    c.stop();
    c.start();
    let c_arg = c_backup.to_string_lossy().into_owned();
    let c_args = [
        "--json",
        "issuer",
        "restore",
        "--backup",
        c_arg.as_str(),
        "--not-stolen",
    ];
    let pty = Pty::open();
    let mut s = start_cli(&c, "new-locator", &c_args, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Backup passphrase: ", &mut s.child));
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line(pass.expose());
    assert!(
        pty.wait_for(
            "Type 'yes' to record the restored store item: ",
            &mut s.child
        ),
        "{}",
        pty.transcript()
    );
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert!(t.contains("restored to the store and reloaded"), "{t}");
    let items = c.product_store().list().unwrap();
    assert_eq!(items.len(), 1, "the new item");
    let st = c.cli(&["--json", "issuer", "status"]);
    let st = st.json();
    let row = &st["data"]["cas"][0];
    assert_eq!(
        row["store_locator"],
        items[0].locator.as_str(),
        "swapped: {st}"
    );
    assert!(
        st["data"]["orphan_store_items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["locator"] == other.as_str()),
        "the old locator is listed as displaced: {st}"
    );
    assert_eq!(out.code, 4, "{out:?}\n{t}");
    assert_eq!(reason(&out.json()), "issuer_store_unavailable");
    assert_eq!(c.ca_state(&c_fp), Some(CaState::Active));
}

/// The CA fingerprint of the backup at `path` under `pass` (the test's own key).
#[cfg(target_os = "macos")]
fn prepared_fp(path: &Path, pass: &heimdall_issuer::backup::Passphrase) -> CaFingerprint {
    heimdall_issuer::backup::restore(path, pass)
        .unwrap()
        .fingerprint()
        .unwrap()
}

/// R2B on the product-file test store (macOS; ADR-0008 §17.22 item 12, §17.25 items 7 (b),
/// 9): after an `init`, `issuer retire` → `yes` → `unloaded` → this process deletes exactly
/// the recorded keychain item → `deleted_locator` → `retired` (exit 0), the item gone.
#[cfg(target_os = "macos")]
#[test]
fn issuer_retire_deletes_the_exact_keychain_item_on_the_product_store() {
    let rig = Rig::product();
    let (fp, _p, _s) = init_on_pty(&rig, &rig.file("r.key"));
    let fp_arg = fp.to_string();
    let args = ["--json", "issuer", "retire", fp_arg.as_str()];
    let pty = Pty::open();
    let mut s = start_cli(&rig, "retire-product", &args, Some(&pty), PROMPT);
    assert!(
        pty.wait_for("[y/N]: ", &mut s.child),
        "{}",
        pty.transcript()
    );
    std::thread::sleep(Duration::from_millis(200));
    pty.type_line("yes");
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    assert_eq!(out.json()["data"]["cas"][0]["state"], "retired");
    assert_eq!(rig.ca_state(&fp), Some(CaState::Retired));
    assert!(
        rig.product_store().list().unwrap().is_empty(),
        "exactly L was deleted"
    );
}

/// `test_ca_ceremony_captures_passphrase_only_from_pty` (m03-plan U11 `ca::TestCa`, the
/// ceremony form; ADR-0008 D13 item 1, A33): testkit's `ca::ceremony::run` drives the real
/// `heimdall issuer init` through the host's `script` pty against this installation (macOS,
/// the product-file test store) and returns the CA and the passphrase captured from the
/// transcript; the passphrase is in the transcript and nowhere else (stdout of the run is
/// the transcript itself; no file, no argument), and it decrypts the backup.
#[cfg(target_os = "macos")]
#[test]
fn test_ca_ceremony_captures_passphrase_only_from_pty() {
    use heimdall_testkit::ca::ceremony::{CeremonyRun, run as ceremony_run};
    let rig = Rig::product();
    let backup = rig.file("testca.key");
    let bin = rig.program.clone();
    let env: Vec<(OsString, OsString)> = rig
        .env()
        .into_iter()
        .filter(|(k, _)| k != "PATH" && k != "TERM")
        .collect();
    let ca = ceremony_run(&CeremonyRun {
        binary: &bin,
        env: &env,
        cwd: rig.tmp.path(),
        backup_out: &backup,
        timeout: LIMIT,
    })
    .unwrap();
    assert_eq!(ca.status, Some(0), "{ca:?}");
    let joined = String::from_utf8(ca.passphrase.expose().to_vec()).unwrap();
    assert_eq!(joined.len(), 26);
    assert_eq!(rig.ca_state(&ca.fingerprint), Some(CaState::Active));
    let pass = heimdall_issuer::backup::Passphrase::from_utf8(joined.clone().into_bytes()).unwrap();
    assert_eq!(prepared_fp(&backup, &pass), ca.fingerprint);
    for form in passphrase_forms(&joined) {
        for f in files_under(rig.tmp.path()) {
            let bytes = std::fs::read(&f).unwrap_or_default();
            assert!(!bytes.windows(form.len()).any(|w| w == form.as_bytes()));
        }
        for (k, v) in &env {
            assert!(!k.to_string_lossy().contains(&form) && !v.to_string_lossy().contains(&form));
        }
    }
}

/// `replace_orphan_cli_warns_and_cross_checks_bundle` (m03-plan U12; ADR-0008 D4 item 1,
/// F08), on a pty against the in-process runtime with an orphan K_ca in the scratch
/// store (no registration names it):
///
/// * plain `init` refuses (`CONFIG_CONFLICT`), naming restore and `--replace-orphan`;
/// * with a bundle listing a live enrollment trusting the orphan: the irreversibility
///   warning, the refusal, and the restore offer; the item stays (exit 6);
/// * with a bundle that does not list the CA: a note, then the typed confirmation;
/// * with `--no-bundle-available`: the "remote lines may still trust" warning; anything
///   but `delete` keeps the item (exit 3); `delete` deletes exactly that item, then the
///   init ceremony goes on to the registration, which the scratch store stops (S3).
#[cfg(unix)]
#[test]
fn replace_orphan_cli_warns_and_cross_checks_bundle() {
    let rig = Rig::new();
    let orphan = rig.seed_orphan();
    let fp = orphan.fingerprint.to_string();
    let backup = rig.file("new-backup.key");
    let backup_arg = backup.to_string_lossy().into_owned();
    let store = rig.scratch_store();

    // Plain init: the orphan is reported first.
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];
    let mut s = start_cli(&rig, "plain", &args, Some(&pty), CEREMONY);
    let out = finish(&mut s);
    assert_eq!(out.code, 6, "{out:?}");
    assert_eq!(out.json()["code"], "CONFIG_CONFLICT");
    let t = pty.transcript();
    assert!(t.contains("heimdall issuer restore"), "{t}");
    assert!(t.contains("--replace-orphan"), "{t}");

    // A bundle listing a live enrollment under the orphan's CA.
    let bundle = |name: &str, live: bool, list_ca: bool| -> PathBuf {
        let path = rig.file(name);
        let ca_line = format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture {fp}");
        let mut b = serde_json::json!({
            "schema": "heimdall-recovery-bundle/1",
            "created_at": "2026-11-01T00:00:00Z",
            "redacted": false,
            "cas": [],
            "enrollments": [{
                "marker": "heimdall:enr_fixture",
                "destination_id": "dst-lab",
                "alias": "lab",
                "hostname": "lab.example.invalid",
                "port": 22,
                "account": "deploy",
                "registry": {"path": null, "resolved_by": "remote_home"},
                "registry_path_display": "~/.ssh/authorized_keys",
                "form": "account",
                "state": if live { "verified" } else { "removed" },
                "ca_fingerprint": fp,
                "ca_public_key": ca_line,
                "line_sha256": "ab".repeat(32),
            }],
            "instructions": [],
        });
        if list_ca {
            b["cas"] = serde_json::json!([{
                "fingerprint": fp,
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture",
                "backup_sha256": "ab".repeat(32),
                "backup_created_at": "2026-11-01T00:00:00Z",
                "state": "active",
            }]);
        }
        std::fs::write(&path, serde_json::to_vec(&b).unwrap()).unwrap();
        path
    };
    let live = bundle("live.json", true, true);
    let live_arg = live.to_string_lossy().into_owned();
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
        "--replace-orphan",
        fp.as_str(),
        "--bundle",
        live_arg.as_str(),
    ];
    let mut s = start_cli(&rig, "live", &args, Some(&pty), CEREMONY);
    let out = finish(&mut s);
    let t = pty.transcript();
    assert_eq!(out.code, 6, "{out:?}\n{t}");
    assert_eq!(out.json()["code"], "CONFIG_CONFLICT");
    assert!(t.contains("irreversible"), "{t}");
    assert!(
        t.contains("1 enrollment(s) that still trust this CA"),
        "{t}"
    );
    assert!(t.contains("Restore it instead"), "{t}");
    assert!(t.contains("heimdall issuer restore --backup"), "{t}");
    assert!(!t.contains("Type 'delete'"), "no deletion offered: {t}");
    assert_eq!(
        store.list().unwrap(),
        vec![orphan.clone()],
        "the item stays"
    );

    // A bundle that does not list this CA and only a final enrollment: a note, then the
    // typed confirmation; `no` keeps the item.
    let other = bundle("other.json", false, false);
    let other_arg = other.to_string_lossy().into_owned();
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
        "--replace-orphan",
        fp.as_str(),
        "--bundle",
        other_arg.as_str(),
    ];
    let mut s = start_cli(&rig, "other", &args, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Type 'delete'", &mut s.child));
    pty.type_line("no");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert_eq!(out.code, 3, "{out:?}\n{t}");
    assert_eq!(out.json()["code"], "INTERACTION_REQUIRED");
    assert!(t.contains("does not list this CA"), "{t}");
    assert!(t.contains("irreversible"), "{t}");
    assert_eq!(store.list().unwrap(), vec![orphan.clone()]);

    // No bundle: the warning, then `delete` deletes exactly the orphan; the ceremony
    // then reaches the registration, which the scratch store stops (S3).
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
        "--replace-orphan",
        fp.as_str(),
        "--no-bundle-available",
    ];
    let mut s = start_cli(&rig, "none", &args, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Type 'delete'", &mut s.child));
    let t = pty.transcript();
    assert!(t.contains("remote lines may still trust this CA"), "{t}");
    pty.type_line("delete");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert!(t.contains("Deleted."), "{t}");
    assert!(
        store.list().unwrap().is_empty(),
        "exactly the orphan was deleted"
    );
    assert_eq!(out.code, 4, "{out:?}\n{t}");
    assert_eq!(reason(&out.json()), "issuer_store_unavailable");
    assert!(!backup.exists());
    assert!(rig.pending().is_empty());
    assert_no_canary(&t);
}

/// The `retire_issuer` typed confirmation and the R2B deletion end to end (m03-plan
/// U12; ADR-0008 §17.22 item 12), against the in-process runtime with a registered CA
/// whose K_ca is in the scratch store and whose locator is recorded:
///
/// * `--non-interactive` and a non-TTY stdin send `issuer.retire` only: exit 3
///   `INTERACTION_REQUIRED` with `next.decision_ref`, the CA still `active`;
/// * on a pty, EOF, `no` and Ctrl-C at the prompt send nothing more (exit 3), and the
///   decision stays pending;
/// * `yes`: `Decide approve`, the issuer unloads the CA (`unloaded`), then this process
///   deletes exactly the recorded locator and confirms it (`deleted_locator`): in a debug
///   build the scratch store's item is deleted by its exact locator (ADR-0008 §17.25 item
///   7 (d)), and the CA is `retired` (exit 0), the other item kept. This is the R2B order
///   proven on every Unix host, Linux included (no disposable Secret Service there).
#[cfg(unix)]
#[test]
fn issuer_retire_typed_yes_and_r2b_deletion_on_scratch_store() {
    let mut rig = Rig::new();
    let (fp, item) = rig.seed_ca();
    let store = rig.scratch_store();
    // Another CA's item in the same store: never touched by this retirement.
    let other = rig.seed_orphan();
    let fp_arg = fp.to_string();

    for (label, args) in [
        (
            "--non-interactive",
            vec![
                "--json",
                "--non-interactive",
                "issuer",
                "retire",
                fp_arg.as_str(),
            ],
        ),
        (
            "non-TTY stdin",
            vec!["--json", "issuer", "retire", fp_arg.as_str()],
        ),
    ] {
        let out = rig.cli(&args);
        assert_eq!(out.code, 3, "{label}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], "INTERACTION_REQUIRED", "{label}");
        assert!(env["next"]["decision_ref"].is_string(), "{label}: {out:?}");
        assert_eq!(rig.ca_state(&fp), Some(CaState::Active), "{label}");
    }
    let pending = rig.pending();
    assert_eq!(pending.len(), 1, "one RetireIssuer decision, joined");

    let args = ["--json", "issuer", "retire", fp_arg.as_str()];
    for (label, answer) in [
        ("EOF", &b"\x04"[..]),
        ("no", &b"no\n"[..]),
        ("Ctrl-C", &b"\x03"[..]),
    ] {
        let pty = Pty::open();
        let mut s = start_cli(&rig, &format!("retire-{label}"), &args, Some(&pty), PROMPT);
        assert!(pty.wait_for("[y/N]: ", &mut s.child), "{label}");
        std::thread::sleep(Duration::from_millis(200));
        pty.type_bytes(answer);
        let out = finish(&mut s);
        assert_eq!(out.code, 3, "{label}: {out:?}\n{}", pty.transcript());
        assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{label}");
        assert_eq!(rig.ca_state(&fp), Some(CaState::Active), "{label}");
        assert_eq!(rig.pending().len(), 1, "{label}: still pending");
    }

    // `yes`: approve, unload, then the owner-present deletion.
    let pty = Pty::open();
    let mut s = start_cli(&rig, "retire-yes", &args, Some(&pty), PROMPT);
    assert!(pty.wait_for("[y/N]: ", &mut s.child));
    let shown = pty.transcript();
    assert!(shown.contains("retire_issuer"), "{shown}");
    assert!(shown.contains(fp.as_str()), "{shown}");
    pty.type_line("yes");
    let out = finish(&mut s);
    let env = out.json();
    assert!(rig.pending().is_empty(), "the decision was used");
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    assert_eq!(env["code"], "OK");
    assert_eq!(rig.ca_state(&fp), Some(CaState::Retired));
    assert_eq!(store.list().unwrap(), vec![other], "exactly L was deleted");
    assert!(!store.list().unwrap().contains(&item));
    let ca = &env["data"]["cas"][0];
    assert_eq!(ca["state"], "retired", "{env}");
}

/// `issuer status`, `issuer bundle` and `issuer unlock` JSON envelopes against the
/// in-process runtime (m03-plan U12 "the JSON envelope for each command"):
///
/// * `status`: `OK`, the `issuer.status` data (the CA, its recorded store item); the
///   human form names the store item the CLI found that no registration names;
/// * `bundle --out`: `OK`, the bundle data; the file is written owner-only (0600 on
///   Unix, also under umask 002), equals the data, and is never overwritten (exit 2);
///   `--redact hostnames` writes a redacted bundle;
/// * `unlock` (pty): `OK` with the status while the store is available; a missing store
///   reports what to do (exit 4) and sends no `issuer.unlock`.
#[cfg(unix)]
#[test]
fn issuer_status_bundle_unlock_json_envelopes() {
    let mut rig = Rig::new();
    let (fp, item) = rig.seed_ca();
    let _orphan = rig.seed_orphan();

    let out = rig.cli(&["--json", "issuer", "status"]);
    assert_eq!(out.code, 0, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "OK");
    assert_eq!(env["data"]["cas"][0]["fingerprint"], fp.as_str());
    assert_eq!(env["data"]["cas"][0]["state"], "active");
    assert_eq!(
        env["data"]["cas"][0]["store_locator"],
        item.locator.as_str()
    );
    assert_eq!(env["data"]["issuer_isolation"], "same_user_process");
    let human = rig.cli(&["issuer", "status"]);
    assert_eq!(human.code, 0, "{human:?}");
    assert!(human.stdout.contains(fp.as_str()), "{human:?}");
    assert!(
        human.stdout.contains("test-configuration store"),
        "{human:?}"
    );

    // bundle
    let out_path = rig.file("bundle.json");
    let out_arg = out_path.to_string_lossy().into_owned();
    let out = rig.cli(&["--json", "issuer", "bundle", "--out", out_arg.as_str()]);
    assert_eq!(out.code, 0, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "OK");
    assert_eq!(env["data"]["schema"], "heimdall-recovery-bundle/1");
    assert_eq!(env["data"]["cas"][0]["fingerprint"], fp.as_str());
    let written: Value = serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
    assert_eq!(written, env["data"]);
    // ⟨ADR-0008 §17.25 item 8⟩ After the write, the CLI confirmed it: the runtime recorded
    // the file's exact SHA-256 with its `created_at`, and `last_bundle_at` (never the path).
    let created_at: Timestamp = env["data"]["created_at"].as_str().unwrap().parse().unwrap();
    let digest = heimdall_issuer::backup::sha256_hex(&std::fs::read(&out_path).unwrap());
    let d = digest.clone();
    let (recorded, last) = rig
        .store()
        .transaction(move |tx| Ok((tx.bundle_digest_recorded_at(&d)?, tx.last_bundle_at()?)))
        .unwrap();
    assert_eq!(recorded, Some(created_at), "the digest is recorded");
    assert_eq!(
        last,
        Some(created_at),
        "last_bundle_at is the bundle's created_at"
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "owner-only");
    }
    let before = std::fs::read(&out_path).unwrap();
    let again = rig.cli(&["--json", "issuer", "bundle", "--out", out_arg.as_str()]);
    assert_eq!(again.code, 2, "{again:?}");
    assert!(again.message().contains("never overwrites"), "{again:?}");
    assert_eq!(std::fs::read(&out_path).unwrap(), before);
    let redacted = rig.file("redacted.json");
    let redacted_arg = redacted.to_string_lossy().into_owned();
    let out = rig.cli(&[
        "issuer",
        "bundle",
        "--out",
        redacted_arg.as_str(),
        "--redact",
        "hostnames",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stdout.contains("bundle_redacted"), "{out:?}");
    let r: Value = serde_json::from_slice(&std::fs::read(&redacted).unwrap()).unwrap();
    assert_eq!(r["redacted"], true);
    // A redacted bundle is never confirmed: its digest is not recorded, and
    // `last_bundle_at` stays the unredacted one's.
    let rd = heimdall_issuer::backup::sha256_hex(&std::fs::read(&redacted).unwrap());
    let (recorded, last) = rig
        .store()
        .transaction(move |tx| Ok((tx.bundle_digest_recorded_at(&rd)?, tx.last_bundle_at()?)))
        .unwrap();
    assert_eq!(recorded, None, "a redacted bundle is not recorded");
    assert_eq!(last, Some(created_at));
    // No path is recorded anywhere in the state database.
    let db = std::fs::read(rig.state_dir().join("state.db")).unwrap_or_default();
    let shown = out_path.to_string_lossy().into_owned();
    assert!(!db.windows(shown.len()).any(|w| w == shown.as_bytes()));

    // unlock on the pty: the store is available, the issuer reloads.
    let pty = Pty::open();
    let mut s = start_cli(
        &rig,
        "unlock",
        &["--json", "issuer", "unlock"],
        Some(&pty),
        CEREMONY,
    );
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    assert_eq!(out.json()["code"], "OK");
    assert!(
        pty.transcript().contains("reloaded"),
        "{}",
        pty.transcript()
    );

    // The store is missing: reported with what to do; nothing is sent.
    let dir = rig.state_dir().join(SCRATCH_STORE_DIR);
    let aside = rig.state_dir().join("scratch-aside");
    std::fs::rename(&dir, &aside).unwrap();
    let pty = Pty::open();
    let mut s = start_cli(
        &rig,
        "unlock-missing",
        &["--json", "issuer", "unlock"],
        Some(&pty),
        CEREMONY,
    );
    let out = finish(&mut s);
    std::fs::rename(&aside, &dir).unwrap();
    assert_eq!(out.code, 4, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(reason(&env), "issuer_store_unavailable");
    assert!(
        pty.transcript().contains("heimdall issuer unlock"),
        "{}",
        pty.transcript()
    );
    rig.stop();
}

// --- M03 wave 5, round 3 (ADR-0008 §17.27 items 3–8) ------------------------------------------

/// ⟨ADR-0008 §17.27 item 5; W5-R03⟩ `issuer_ceremonies_refuse_redirected_stdin_with_a_terminal_attached`:
/// every ceremony (`init`, `init --replace-orphan`, `rotate begin`, `restore`, `unlock`)
/// with stdin redirected (`/dev/null`) while the pty stays the controlling terminal is not an
/// interactive invocation: exit 3 `INTERACTION_REQUIRED`, effect `none`, before anything is
/// connected, attended or opened. Nothing reaches the terminal; no request changed the
/// runtime (no event, no decision, no CA); no backup is written and the store keeps its one
/// item. Runs on every Unix host (the refusal precedes the store).
#[cfg(unix)]
#[test]
fn issuer_ceremonies_refuse_redirected_stdin_with_a_terminal_attached() {
    let rig = Rig::new();
    let orphan = rig.seed_orphan();
    let fp = orphan.fingerprint.to_string();
    let backup = rig.file("redirected.key");
    let b = backup.to_string_lossy().into_owned();
    let restore_from = rig.file("absent-backup.key");
    let r = restore_from.to_string_lossy().into_owned();
    let head = rig.event_head();
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("init", vec!["--json", "issuer", "init", "--backup-out", &b]),
        (
            "replace-orphan",
            vec![
                "--json",
                "issuer",
                "init",
                "--backup-out",
                &b,
                "--replace-orphan",
                &fp,
                "--no-bundle-available",
            ],
        ),
        (
            "rotate",
            vec!["--json", "issuer", "rotate", "begin", "--backup-out", &b],
        ),
        (
            "restore",
            vec![
                "--json",
                "issuer",
                "restore",
                "--backup",
                &r,
                "--not-stolen",
            ],
        ),
        ("unlock", vec!["--json", "issuer", "unlock"]),
        ("human-init", vec!["issuer", "init", "--backup-out", &b]),
    ];
    for (label, args) in cases {
        let pty = Pty::open();
        let mut s = start_cli(
            &rig,
            &format!("redirected-{label}"),
            &args,
            Some(&pty),
            REDIRECTED_STDIN,
        );
        let out = finish_within(&mut s, Duration::from_secs(30)).unwrap_or_else(|| {
            panic!(
                "{label}: still running (it reached a prompt): {:?}",
                pty.transcript()
            )
        });
        assert_eq!(out.code, 3, "{label}: {out:?}\n{:?}", pty.transcript());
        if args[0] == "--json" {
            let env = out.json();
            assert_eq!(env["code"], "INTERACTION_REQUIRED", "{label}: {out:?}");
            assert_eq!(env["data"]["error"]["effect_status"], "none", "{label}");
            assert!(out.message().contains("stdin"), "{label}: {out:?}");
        } else {
            assert!(out.stderr.contains("stdin"), "{label}: {out:?}");
        }
        assert!(
            pty.transcript().is_empty(),
            "{label}: nothing on the terminal: {:?}",
            pty.transcript()
        );
    }
    assert_eq!(rig.event_head(), head, "no request changed the runtime");
    assert!(rig.pending().is_empty(), "no decision");
    assert!(
        rig.store()
            .transaction(|tx| tx.issuers())
            .unwrap()
            .is_empty()
    );
    assert_eq!(rig.scratch_store().list().unwrap(), vec![orphan]);
    assert!(!backup.exists(), "no backup");
}

/// ⟨ADR-0008 §17.27 item 7; W5-S05, the security reviewer's probe⟩
/// `issuer_init_ctrl_c_or_eof_at_written_sends_nothing_more`, macOS on the product-file test
/// store: after the `yes`, Ctrl-C (ETX) or end of input (Ctrl-D) at the passphrase's
/// `written` acknowledgement ends the ceremony at once (no retry; well within the 120 s
/// prompt timeout): exit 3 `INTERACTION_REQUIRED`, the passphrase's region cleared, no
/// keychain item, nothing registered, the lock acknowledgement not recorded. (The backup
/// written at step 4 stays, D4 item 1's crash point between steps 4 and 6.)
#[cfg(target_os = "macos")]
#[test]
fn issuer_init_ctrl_c_or_eof_at_written_sends_nothing_more() {
    let rig = Rig::product();
    for (label, bytes) in [("Ctrl-C", &b"\x03"[..]), ("EOF", &b"\x04"[..])] {
        let backup = rig.file(&format!("written-{label}.key"));
        let backup_arg = backup.to_string_lossy().into_owned();
        let args = [
            "--json",
            "issuer",
            "init",
            "--backup-out",
            backup_arg.as_str(),
        ];
        let pty = Pty::open();
        let mut s = start_cli(
            &rig,
            &format!("written-{label}"),
            &args,
            Some(&pty),
            CEREMONY,
        );
        assert!(
            pty.wait_for("Type 'yes' to register this CA: ", &mut s.child),
            "{label}: {}",
            pty.transcript()
        );
        std::thread::sleep(Duration::from_millis(300));
        pty.type_line("yes");
        assert!(pty.wait_for("Type 'written'", &mut s.child), "{label}");
        let at = pty.transcript().len();
        std::thread::sleep(Duration::from_millis(300));
        pty.type_bytes(bytes);
        let out = finish_within(&mut s, Duration::from_secs(15))
            .unwrap_or_else(|| panic!("{label} at `written` did not end the ceremony"));
        let t = pty.transcript();
        assert_eq!(out.code, 3, "{label}: {out:?}");
        assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{label}");
        assert!(
            t[at..].contains("A\r\x1b[J"),
            "{label}: the passphrase was cleared"
        );
        assert_eq!(t.matches("Type 'written'").count(), 1, "{label}: no retry");
        assert!(
            rig.product_store().list().unwrap().is_empty(),
            "{label}: no keychain item"
        );
        assert!(
            rig.store()
                .transaction(|tx| tx.issuers())
                .unwrap()
                .is_empty(),
            "{label}: nothing registered"
        );
        assert!(
            rig.store()
                .transaction(|tx| tx.lock_disclosure_ack())
                .unwrap()
                .is_none(),
            "{label}: the lock disclosure was not acknowledged"
        );
        assert!(!has_passphrase_shape(&out.stdout) && !has_passphrase_shape(&out.stderr));
    }
}

/// The lock-text case of `issuer init --json` on a pty (macOS, the product-file test store):
/// the runtime's conditional `inspect capabilities` `lock.disclosure` names `expect` (the
/// saved limits) and is not the general sentence; before the prompt the terminal shows the
/// whole preview and every disclosure's prose, the lock disclosure as that exact text
/// (§17.27 items 3, 4); the approval then records the once-only acknowledgement, and stdout
/// carries exactly one envelope.
#[cfg(target_os = "macos")]
fn init_shows_runtime_lock_text(rig: &Rig, case: &str, expect: &[&str]) {
    use heimdall_contract::enrollment::DisclosureKind;
    use heimdall_issuer::ceremony::{DisclosureContext, disclosure_text};
    let caps = rig.cli(&["--json", "inspect", "capabilities"]);
    assert_eq!(caps.code, 0, "{caps:?}");
    let text = caps.json()["data"]["lock"]["disclosure"]
        .as_str()
        .unwrap_or_else(|| panic!("the runtime reports its lock disclosure: {caps:?}"))
        .to_owned();
    for e in expect {
        assert!(text.contains(e), "{e:?} in the runtime's text: {text}");
    }
    let general = disclosure_text(
        DisclosureKind::LockContinuityOnce,
        &DisclosureContext::default(),
    );
    assert_ne!(text, general);
    let backup = rig.file(&format!("{case}.key"));
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];
    let pty = Pty::open();
    let mut s = start_cli(rig, case, &args, Some(&pty), CEREMONY);
    assert!(
        pty.wait_for("Type 'yes' to register this CA: ", &mut s.child),
        "{}",
        pty.transcript()
    );
    let shown = pty.transcript();
    let before = &shown[..shown.find("Type 'yes'").unwrap()];
    for needle in ["Register CA SHA256:", "backup SHA-256 ", "backup file "] {
        assert!(before.contains(needle), "{needle:?}: {before}");
    }
    for kind in [
        DisclosureKind::SameUserIssuerBoundary,
        DisclosureKind::CaTrustBlastRadius,
        DisclosureKind::BackupInstructions,
    ] {
        let prose = disclosure_text(kind, &DisclosureContext::default());
        assert!(before.contains(&prose), "{kind:?}: {before}");
    }
    assert!(before.contains(&text), "the runtime's lock text: {before}");
    assert!(!before.contains(&general), "not the general sentence");
    assert!(
        rig.store()
            .transaction(|tx| tx.lock_disclosure_ack())
            .unwrap()
            .is_none()
    );
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    assert!(pty.wait_for("Type 'written'", &mut s.child));
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("written");
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    // Stdout: exactly one envelope (the child-mode entry's own libtest lines aside); stderr
    // none.
    let envelopes = |text: &str| {
        text.lines()
            .filter(|l| serde_json::from_str::<Value>(l.trim()).is_ok_and(|v| v.is_object()))
            .count()
    };
    assert_eq!(envelopes(&out.stdout), 1, "{out:?}");
    assert_eq!(envelopes(&out.stderr), 0, "{out:?}");
    assert_eq!(out.json()["code"], "OK");
    assert!(
        rig.store()
            .transaction(|tx| tx.lock_disclosure_ack())
            .unwrap()
            .is_some(),
        "the acknowledgement is recorded for the decision that showed the text"
    );
}

/// ⟨ADR-0008 §17.26 item 6, §17.27 items 3, 4; W5-R05, W5-S03⟩
/// `issuer_init_shows_the_continuing_lock_text_with_saved_limits`: a saved continuing policy
/// with a maximum window and a cutoff.
#[cfg(target_os = "macos")]
#[test]
fn issuer_init_shows_the_continuing_lock_text_with_saved_limits() {
    let rig = Rig::product();
    let cutoff: Timestamp = "2031-01-01T00:00:00Z".parse().unwrap();
    rig.seed_policy(
        "daily",
        heimdall_contract::managed::LockBehavior::Continue,
        Duration::from_secs(2 * 3600),
        Some(cutoff),
    );
    init_shows_runtime_lock_text(
        &rig,
        "lock-continue",
        &["\"daily\"", "after approval", "no new work after"],
    );
}

/// ⟨ADR-0008 §17.26 item 6, §17.27 items 3, 4; W5-R05, W5-S03⟩
/// `issuer_init_shows_the_revoke_on_lock_text_with_saved_limits`: a saved revoke-on-lock
/// policy with its maximum window, beside a continuing one.
#[cfg(target_os = "macos")]
#[test]
fn issuer_init_shows_the_revoke_on_lock_text_with_saved_limits() {
    let rig = Rig::product();
    rig.seed_policy(
        "strict",
        heimdall_contract::managed::LockBehavior::RevokeOnLock,
        Duration::from_secs(3600),
        None,
    );
    rig.seed_policy(
        "relaxed",
        heimdall_contract::managed::LockBehavior::Continue,
        Duration::from_secs(4 * 3600),
        None,
    );
    init_shows_runtime_lock_text(
        &rig,
        "lock-revoke",
        &["\"strict\" ends when you lock the screen", "\"relaxed\""],
    );
}

/// `transcript` without the ceremony's own control sequences (the passphrase region's
/// clearing: cursor up `ESC [ n A`, carriage return, `ESC [ J`).
#[cfg(target_os = "macos")]
fn without_own_clearing(transcript: &str) -> String {
    let mut out = String::new();
    let mut rest = transcript;
    while let Some(at) = rest.find("\x1b[") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 2..];
        let digits = tail.chars().take_while(char::is_ascii_digit).count();
        match tail[digits..].chars().next() {
            Some('A') if digits > 0 => rest = &tail[digits + 1..],
            Some('J') if digits == 0 => rest = &tail[1..],
            _ => {
                out.push_str("\x1b[");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// ⟨ADR-0008 §17.27 item 8; W5-S06⟩ `issuer_init_backup_path_controls_never_reach_the_terminal`,
/// macOS on the product-file test store: a `--backup-out` file name carrying clear-screen and
/// cursor-home controls is shown sanitized (by `output::sanitize_for_terminal`, the ordinary
/// renderers' sanitizer) in the decision and after the backup is written; the only control
/// sequences on the terminal are the ceremony's own clearing of the passphrase.
#[cfg(target_os = "macos")]
#[test]
fn issuer_init_backup_path_controls_never_reach_the_terminal() {
    let rig = Rig::product();
    let backup = rig.file("ctl\x1b[2J\x1b[Hname.key");
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];
    let pty = Pty::open();
    let mut s = start_cli(&rig, "ctl-path", &args, Some(&pty), CEREMONY);
    assert!(
        pty.wait_for("Type 'yes' to register this CA: ", &mut s.child),
        "{:?}",
        pty.transcript()
    );
    let shown = pty.transcript();
    assert!(
        !shown.contains('\x1b'),
        "no control sequence before the yes: {shown:?}"
    );
    assert!(
        shown.contains("ctlname.key"),
        "the path, sanitized: {shown:?}"
    );
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    assert!(pty.wait_for("Type 'written'", &mut s.child));
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("written");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert_eq!(out.code, 0, "{out:?}\n{t:?}");
    assert!(backup.exists(), "the backup at the given name");
    assert!(t.contains("Backup written: "), "{t:?}");
    for raw in ["\x1b[2J", "\x1b[H"] {
        assert!(!t.contains(raw), "{raw:?} reached the terminal");
    }
    let rest = without_own_clearing(&t);
    assert!(
        !rest.contains('\x1b'),
        "only the ceremony's own clearing: {rest:?}"
    );
    assert_ne!(rest.len(), t.len(), "the passphrase's region was cleared");
}

/// Replace `rig`'s program (stopped runtime) by a re-signed copy of itself at the same path:
/// another code identity, what an update of an ad-hoc-signed build does.
#[cfg(target_os = "macos")]
fn update_program_in_place(rig: &Rig, identifier: &str) {
    let variant = rig.program.with_file_name("updated");
    std::fs::copy(&rig.program, &variant).unwrap();
    let signed = Command::new("/usr/bin/codesign")
        .args(["-f", "-s", "-", "-i", identifier])
        .arg(&variant)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(signed.success(), "codesign re-signed the copy");
    std::fs::rename(&variant, &rig.program).unwrap();
}

/// A product-store rig whose CA item the current program can no longer read: `issuer init`
/// writes K_ca with this rig's program (copy A); the program is then replaced by a re-signed
/// copy at the same path (copy B: an update of an ad-hoc-signed build, another code
/// identity) and the runtime restarted, so its issuer child (B) is denied the item
/// (`errSecAuthFailed` from an unlocked keychain). Returns the rig, the CA, the backup's
/// passphrase and path, and the init's terminal (kept open).
#[cfg(target_os = "macos")]
fn access_denied_rig() -> (Rig, CaFingerprint, String, PathBuf, Started) {
    let mut rig = Rig::product();
    let backup = rig.file("denied.key");
    let (fp, passphrase, started) = init_on_pty(&rig, &backup);
    let st = rig.cli(&["--json", "issuer", "status"]).json();
    assert_eq!(st["data"]["state"], "ready", "{st}");
    rig.stop();
    update_program_in_place(&rig, "heimdall-updated");
    rig.start();
    // The keychain is unlocked: this is the access list, not the lock.
    assert_eq!(
        rig.product_store().availability(),
        heimdall_issuer::store::StoreAvailability::Available
    );
    (rig, fp, passphrase, backup, started)
}

/// ⟨ADR-0008 §17.28 item 6⟩ `issuer_store_access_denied_when_another_binary_reads_the_item`,
/// macOS on the product-file test store (a disposable file keychain, unlocked throughout;
/// [`access_denied_rig`]). Reported through the real paths as `issuer_store_access_denied`,
/// never `issuer_store_locked`: `issuer status` (the child's load), `issuer unlock` (the
/// runtime's reload) with `next_command` the restore, and the doctor's finding.
#[cfg(target_os = "macos")]
#[test]
fn issuer_store_access_denied_when_another_binary_reads_the_item() {
    let owner = owner_keychains();
    let (rig, fp, _passphrase, _backup, _s) = access_denied_rig();
    let out = rig.cli(&["--json", "issuer", "status"]);
    let st = out.json();
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(st["data"]["state"], "store_unavailable", "{st}");
    assert_eq!(st["data"]["reason"], "issuer_store_access_denied", "{st}");
    let human = rig.cli(&["issuer", "status"]);
    assert!(
        human.stdout.contains(
            "Run `heimdall issuer restore --backup <file>`: it restores the CA to a new store item"
        ),
        "{human:?}"
    );
    // `issuer unlock`: the runtime's reload reads the item again and is denied again.
    let pty = Pty::open();
    let mut s = start_cli(
        &rig,
        "unlock",
        &["--json", "issuer", "unlock"],
        Some(&pty),
        CEREMONY,
    );
    let out = finish(&mut s);
    let env = out.json();
    assert_eq!(out.code, 4, "{out:?}\n{}", pty.transcript());
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{out:?}");
    assert_eq!(reason(&env), "issuer_store_access_denied", "{out:?}");
    assert_eq!(
        env["data"]["next_command"], "heimdall issuer restore --backup <file>",
        "{out:?}"
    );
    assert!(out.message().contains("unlocking cannot help"), "{out:?}");
    // The doctor reports it (from the running runtime's status; it never reads K_ca).
    let doc = rig.cli(&["--json", "doctor"]);
    assert_eq!(doc.code, 0, "{doc:?}");
    let doc = doc.json();
    let found: Vec<&Value> = doc["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "issuer_store_access_denied")
        .collect();
    assert_eq!(found.len(), 1, "{doc}");
    assert_eq!(found[0]["reason"], "issuer_store_access_denied");
    let message = found[0]["message"].as_str().unwrap();
    assert!(
        message.contains("heimdall issuer restore --backup <file>")
            && message.contains("new store item")
            && message.contains("Keychain Access"),
        "{message}"
    );
    assert!(
        !doc.to_string().contains("issuer_store_locked"),
        "never the lock: {doc}"
    );
    assert_eq!(rig.ca_state(&fp), Some(CaState::Active));
    drop(rig);
    assert_eq!(
        owner_keychains(),
        owner,
        "the owner's keychains are unchanged"
    );
}

/// ⟨ADR-0008 §17.28 item 7⟩ `issuer_restore_after_access_denial_writes_a_new_item_and_lists_the_orphan`,
/// macOS on the product-file test store ([`access_denied_rig`]: copy A wrote the item, copy
/// B is denied it). B runs `issuer restore --backup <file>` on a pty with no deletion first:
/// the key goes to a new item (same service, account `<environment>#r1`), the attended
/// `RegisterIssuer` decision carries that locator with a compare-and-swap against the old
/// one and is approved by a typed `yes`; the issuer (B) reads the new item (`ready`);
/// `issuer status` lists the old item under `orphan_store_items` with its service and
/// account and the Keychain Access instruction; nothing is deleted (the old item is still in
/// the keychain).
#[cfg(target_os = "macos")]
#[test]
fn issuer_restore_after_access_denial_writes_a_new_item_and_lists_the_orphan() {
    use heimdall_domain::decision::{DecisionKind, DecisionState};
    let owner = owner_keychains();
    let (rig, fp, passphrase, backup, _s) = access_denied_rig();
    let env_id = rig
        .store()
        .transaction(|tx| tx.self_environment())
        .unwrap()
        .unwrap();
    let service = format!("heimdall-issuer/{}", fp.as_str());
    let old = format!("service={service};account={}", env_id.as_str());
    let new = format!("service={service};account={}#r1", env_id.as_str());
    let recorded = |rig: &Rig| {
        rig.store()
            .transaction(|tx| tx.issuer_store_locator(&fp))
            .unwrap()
    };
    assert_eq!(recorded(&rig).as_deref(), Some(old.as_str()));
    let listed = |rig: &Rig| -> Vec<String> {
        rig.product_store()
            .list()
            .unwrap()
            .into_iter()
            .map(|i| i.locator)
            .collect()
    };
    assert_eq!(listed(&rig), vec![old.clone()]);
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "restore",
        "--backup",
        backup_arg.as_str(),
        "--not-stolen",
    ];
    let pty = Pty::open();
    let mut s = start_cli(&rig, "restore-new-item", &args, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Backup passphrase: ", &mut s.child));
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line(&passphrase);
    assert!(
        pty.wait_for(
            "Type 'yes' to record the restored store item: ",
            &mut s.child
        ),
        "{}",
        pty.transcript()
    );
    // The pending RegisterIssuer decision: the new locator, CAS against the old one.
    let pending: Vec<_> = rig
        .pending()
        .into_iter()
        .filter_map(|d| match d.kind {
            DecisionKind::RegisterIssuer {
                ca_fingerprint,
                store_locator,
                expected_store_locator,
                ..
            } if ca_fingerprint == fp => Some((d.id, store_locator, expected_store_locator)),
            _ => None,
        })
        .collect();
    assert_eq!(pending.len(), 1, "one RegisterIssuer decision");
    let (decision, locator, expected) = pending.into_iter().next().unwrap();
    assert_eq!(locator.as_deref(), Some(new.as_str()), "the new locator");
    assert_eq!(
        expected.as_deref(),
        Some(old.as_str()),
        "CAS against the old"
    );
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert_eq!(out.code, 0, "{out:?}\n{t}");
    assert!(t.contains("restored to the store and reloaded"), "{t}");
    assert!(t.contains("Heimdall never deletes"), "{t}");
    assert!(
        t.contains(&format!(
            "Keychain Access (service {service}, account {})",
            env_id.as_str()
        )),
        "{t}"
    );
    for form in passphrase_forms(&passphrase) {
        assert!(!t.contains(&form) && !out.stdout.contains(&form));
    }
    let d = rig
        .store()
        .transaction(|tx| tx.decision(&decision))
        .unwrap()
        .unwrap();
    assert_eq!(d.state, DecisionState::Approved);
    assert_eq!(recorded(&rig).as_deref(), Some(new.as_str()), "swapped");
    // Nothing deleted: both items are in the keychain.
    assert_eq!(listed(&rig), vec![old.clone(), new.clone()]);
    // B reads its new item: the issuer is ready (after a fresh reload too).
    let st = rig.cli(&["--json", "issuer", "status"]).json();
    assert_eq!(st["data"]["state"], "ready", "{st}");
    assert_eq!(st["data"]["cas"][0]["store_locator"], new.as_str(), "{st}");
    let orphans = st["data"]["orphan_store_items"].as_array().unwrap();
    assert!(
        orphans
            .iter()
            .any(|o| o["locator"] == old.as_str() && o["fingerprint"] == fp.as_str()),
        "the old item is listed with its service and account: {st}"
    );
    let human = rig.cli(&["issuer", "status"]).stdout;
    assert!(
        human.contains(&format!(
            "delete it in Keychain Access (service {service}, account {})",
            env_id.as_str()
        )),
        "{human}"
    );
    let pty = Pty::open();
    let mut s = start_cli(
        &rig,
        "unlock-after",
        &["--json", "issuer", "unlock"],
        Some(&pty),
        CEREMONY,
    );
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    assert_eq!(out.json()["data"]["state"], "ready", "{out:?}");
    assert_eq!(listed(&rig), vec![old, new], "still nothing deleted");
    assert_eq!(rig.ca_state(&fp), Some(CaState::Active));
    drop(rig);
    assert_eq!(
        owner_keychains(),
        owner,
        "the owner's keychains are unchanged"
    );
}

/// ⟨ADR-0008 §17.31 item 5; wave-5 re-check W5-C05⟩
/// `recheck_retire_after_new_item_restore_deletes_only_current_generation`, macOS on the
/// product-file test store ([`access_denied_rig`]): copy B restores to the new item
/// `<environment>#r1` (typed `yes`), then retires the CA (typed `yes`, human output). The
/// current item is deleted and its deletion confirmed (`deleted_locator`), the CA is
/// `retired`; the old, access-denied item is never deleted and stays in
/// `orphan_store_items` with its service and account; the command exits 0 (effect applied),
/// names the Keychain Access step for the orphan, and advises no restore (`issuer status`
/// neither). Before the fix the
/// displaced item's refused deletion answered exit 4 / effect `none` / "restore".
#[cfg(target_os = "macos")]
#[test]
fn recheck_retire_after_new_item_restore_deletes_only_current_generation() {
    let owner = owner_keychains();
    let (rig, fp, passphrase, backup, _s) = access_denied_rig();
    let env_id = rig
        .store()
        .transaction(|tx| tx.self_environment())
        .unwrap()
        .unwrap();
    let service = format!("heimdall-issuer/{}", fp.as_str());
    let old = format!("service={service};account={}", env_id.as_str());
    let new = format!("service={service};account={}#r1", env_id.as_str());
    let listed = |rig: &Rig| -> Vec<String> {
        rig.product_store()
            .list()
            .unwrap()
            .into_iter()
            .map(|i| i.locator)
            .collect()
    };
    // The new-item restore (§17.28 item 7).
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "restore",
        "--backup",
        backup_arg.as_str(),
        "--not-stolen",
    ];
    let pty = Pty::open();
    let mut s = start_cli(&rig, "restore-new-item", &args, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Backup passphrase: ", &mut s.child));
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line(&passphrase);
    assert!(
        pty.wait_for(
            "Type 'yes' to record the restored store item: ",
            &mut s.child
        ),
        "{}",
        pty.transcript()
    );
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    assert_eq!(listed(&rig), vec![old.clone(), new.clone()]);
    // The retirement, human output.
    let fp_arg = fp.to_string();
    let pty = Pty::open();
    let mut s = start_cli(
        &rig,
        "retire-after-restore",
        &["issuer", "retire", fp_arg.as_str()],
        Some(&pty),
        PROMPT,
    );
    assert!(
        pty.wait_for("[y/N]: ", &mut s.child),
        "{}",
        pty.transcript()
    );
    std::thread::sleep(Duration::from_millis(200));
    pty.type_line("yes");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert_eq!(out.code, 0, "exit 0, the retirement applied: {out:?}\n{t}");
    let text = format!("{}{}{t}", out.stdout, out.stderr);
    assert!(text.contains("retired"), "{text}");
    assert!(
        text.contains(&format!(
            "delete it yourself in Keychain Access (service {service}, account {})",
            env_id.as_str()
        )),
        "the orphan's step: {text}"
    );
    assert!(
        !text.contains("issuer restore") && !text.contains("rerun the restore"),
        "no restore advice after a completed retirement: {text}"
    );
    assert!(!text.contains("effect_status"), "{text}");
    // The current item deleted and confirmed; the CA retired.
    assert_eq!(rig.ca_state(&fp), Some(CaState::Retired));
    // The old item is still in the keychain, and listed with its service and account.
    assert_eq!(
        listed(&rig),
        vec![old.clone()],
        "only the current item went"
    );
    let st = rig.cli(&["--json", "issuer", "status"]);
    assert_eq!(st.code, 0, "{st:?}");
    let st = st.json();
    assert_eq!(st["code"], "OK", "{st}");
    assert_eq!(st["state"], "succeeded", "{st}");
    let row = st["data"]["cas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["fingerprint"] == fp.as_str())
        .cloned()
        .unwrap();
    assert_eq!(row["state"], "retired", "{st}");
    assert!(
        st["data"]["orphan_store_items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["locator"] == old.as_str() && o["fingerprint"] == fp.as_str()),
        "the old item is listed: {st}"
    );
    assert!(
        !st["data"]["orphan_store_items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["locator"] == new.as_str()),
        "the current item's deletion was confirmed: {st}"
    );
    let human = rig.cli(&["issuer", "status"]).stdout;
    assert!(
        !human.contains("rerun the restore"),
        "no restore advice for a retired CA: {human}"
    );
    assert!(human.contains("now retired"), "{human}");
    assert_eq!(listed(&rig), vec![old], "still never deleted");
    drop(rig);
    assert_eq!(
        owner_keychains(),
        owner,
        "the owner's keychains are unchanged"
    );
}

/// ⟨ADR-0008 §17.33 item 2 (W5-E02)⟩ The real `internal issuer` child of `rig`'s program,
/// on a client wired exactly as the runtime wires its own
/// (`heimdall_runtime::service::issuer_client_config`: the rig runtime's load gate, request
/// hold and exact-child check), started (`ready`, the seeded CA loaded).
#[cfg(unix)]
async fn real_issuer(rig: &Rig) -> heimdall_issuer::client::ChildIssuer {
    real_issuer_with(rig, |_| {}).await
}

/// [`real_issuer`] with the runtime's configuration adjusted by `adjust` first.
#[cfg(unix)]
async fn real_issuer_with(
    rig: &Rig,
    adjust: impl FnOnce(&mut heimdall_issuer::client::ClientConfig),
) -> heimdall_issuer::client::ChildIssuer {
    let ops = rig.service.as_ref().unwrap().ops.clone();
    let command = heimdall_issuer::client::ChildCommand {
        program: rig.program.clone(),
        args: vec!["internal".into(), "issuer".into()],
        env: vec![
            ("HEIMDALL_HOME".into(), rig.home.clone().into()),
            (
                "HEIMDALL_TEST_SECRET_STORE".into(),
                rig.store_value().into(),
            ),
        ],
    };
    let mut config = heimdall_runtime::service::issuer_client_config(
        command,
        Arc::new(heimdall_runtime::platform::process_start_time),
        &ops,
    );
    adjust(&mut config);
    let issuer = heimdall_issuer::client::ChildIssuer::new(config);
    issuer.start().await.unwrap();
    assert_eq!(
        issuer.state(),
        heimdall_contract::issuer::IssuerState::Ready
    );
    assert_eq!(issuer.loaded_cas().len(), 1, "the seeded CA is loaded");
    issuer
}

/// Whether `pid` is a live process (`ps`; a zombie or a gone process reads as not).
#[cfg(unix)]
fn running(pid: u32) -> bool {
    let out = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stat = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    !stat.is_empty() && !stat.starts_with('Z')
}

/// `kill -<signal> <pid>` for the exact child this test started (its PID from the client).
#[cfg(unix)]
fn signal_pid(signal: &str, pid: u32) {
    let ok = Command::new("/bin/kill")
        .args([signal, &pid.to_string()])
        .stdin(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "kill {signal} {pid}");
}

/// The fence holder in these tests (no dispatcher hands this out).
#[cfg(unix)]
const FENCE_HOLDER: u64 = u64::MAX - 11;

/// ⟨ADR-0008 §17.33 item 2 (W5-E02)⟩ `recheck3_real_issuer_late_sign_cannot_cross_fence`:
/// with the real child stopped (`SIGSTOP`, the exact PID), a `sign` under an admission
/// (the managed pipeline's, held by this task) is delivered and its waiter times out.
/// The child must be ended and its exit confirmed **before** the admission is released:
/// a fence acquisition that follows completes only once the child is gone, so no late
/// signature can cross it. Afterwards the client is `crashed`, and under the held fence a
/// demand restarts nothing.
#[cfg(unix)]
#[test]
fn recheck3_real_issuer_late_sign_cannot_cross_fence() {
    use heimdall_app::ports::IssuerPort as _;
    let mut rig = Rig::new();
    rig.seed_ca();
    let ops = rig.service.as_ref().unwrap().ops.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let issuer = real_issuer(&rig).await;
        let pid = issuer.identity().unwrap().pid;
        signal_pid("-STOP", pid);
        // The managed pipeline's shape: a task holding its fence admission signs under
        // an outer bound (`managed::driver::sign`), then drops the admission.
        let (o, i) = (ops.clone(), issuer.clone());
        tokio::spawn(async move {
            let _pipeline = o.uninstall_fence_admit().unwrap();
            let sign = i.sign(
                heimdall_issuer::protocol::IssuanceRef {
                    table: heimdall_issuer::protocol::IssuanceTable::Grant,
                    id: heimdall_contract::ids::IssuanceId::from_random_bytes([5; 16]),
                },
                "ssh-ed25519 AAAA",
            );
            let r = tokio::time::timeout(Duration::from_millis(300), sign).await;
            assert!(r.is_err(), "the waiter timed out: {r:?}");
        })
        .await
        .unwrap();
        let acquired = ops.uninstall_fence_acquire(FENCE_HOLDER).await;
        let alive_at_acquire = running(pid);
        if alive_at_acquire {
            // Before the fix: the stopped child still owns the delivered request.
            signal_pid("-CONT", pid);
            issuer.stop().await;
        }
        assert!(acquired.is_ok(), "{acquired:?}");
        assert!(
            !alive_at_acquire,
            "the fence was taken while the child that owns the delivered sign was alive"
        );
        assert_eq!(
            issuer.state(),
            heimdall_contract::issuer::IssuerState::Crashed
        );
        // Under the held fence a demand restarts nothing (no load, no new child).
        let _ = issuer
            .sign(
                heimdall_issuer::protocol::IssuanceRef {
                    table: heimdall_issuer::protocol::IssuanceTable::Grant,
                    id: heimdall_contract::ids::IssuanceId::from_random_bytes([6; 16]),
                },
                "ssh-ed25519 AAAA",
            )
            .await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            issuer.identity().is_none(),
            "no child started under the fence"
        );
        assert!(issuer.loaded_cas().is_empty());
        assert!(!ops.uninstall_fence_release(FENCE_HOLDER));
        issuer.stop().await;
    });
}

/// ⟨ADR-0008 §17.33 item 2 (W5-E02), the bounded stop⟩ When the exact-child check cannot
/// verify the child (here its image is unreadable), it is never signalled: it gets only EOF,
/// and the delivered `sign`'s admission stays held until its exit is observed. A fence
/// acquisition meanwhile waits out its bound and reports it (`SERVICE_UNAVAILABLE`,
/// `uninstall_in_progress`, "work being admitted did not settle in time"), nothing taken;
/// once the child is resumed, finishes and exits at EOF, the hold is released and the next
/// acquisition succeeds with the child gone.
#[cfg(unix)]
#[test]
fn recheck3_real_issuer_unconfirmed_stop_keeps_the_admission_held() {
    use heimdall_app::ports::IssuerPort as _;
    let mut rig = Rig::new();
    rig.seed_ca();
    let ops = rig.service.as_ref().unwrap().ops.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let issuer = real_issuer_with(&rig, |c| c.child_image = Some(Arc::new(|_| None))).await;
        let pid = issuer.identity().unwrap().pid;
        signal_pid("-STOP", pid);
        let (o, i) = (ops.clone(), issuer.clone());
        tokio::spawn(async move {
            let _pipeline = o.uninstall_fence_admit().unwrap();
            let sign = i.sign(
                heimdall_issuer::protocol::IssuanceRef {
                    table: heimdall_issuer::protocol::IssuanceTable::Grant,
                    id: heimdall_contract::ids::IssuanceId::from_random_bytes([8; 16]),
                },
                "ssh-ed25519 AAAA",
            );
            let r = tokio::time::timeout(Duration::from_millis(300), sign).await;
            assert!(r.is_err(), "the waiter timed out: {r:?}");
        })
        .await
        .unwrap();
        let refused = ops.uninstall_fence_acquire(FENCE_HOLDER).await;
        let alive = running(pid);
        signal_pid("-CONT", pid);
        let e = refused.expect_err("the held admission keeps the fence from being taken");
        assert!(alive, "the unverified child was never signalled");
        assert_eq!(e.reason.as_deref(), Some("uninstall_in_progress"), "{e:?}");
        assert!(e.message.contains("did not settle"), "{e:?}");
        // Resumed, the child finishes and exits at EOF: the hold is released.
        let deadline = Instant::now() + Duration::from_secs(10);
        while running(pid) {
            assert!(Instant::now() < deadline, "the child exited at EOF");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ops.uninstall_fence_acquire(FENCE_HOLDER).await.unwrap();
        assert!(!ops.uninstall_fence_release(FENCE_HOLDER));
        issuer.stop().await;
    });
}

/// ⟨ADR-0008 §17.33 item 2 (W5-E02)⟩ `recheck3_real_issuer_cancelled_load_cannot_cross_fence`:
/// with the real child stopped, an `issuer unlock`-style reload (the load gate's admission)
/// delivers `load` and its waiter is cancelled. The child is ended and its exit confirmed
/// before that admission is released, so a fence acquisition completes only once the child
/// is gone: no late K_ca load crosses it; the client is `crashed` and loads nothing under
/// the fence.
#[cfg(unix)]
#[test]
fn recheck3_real_issuer_cancelled_load_cannot_cross_fence() {
    let mut rig = Rig::new();
    rig.seed_ca();
    let ops = rig.service.as_ref().unwrap().ops.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let issuer = real_issuer(&rig).await;
        let pid = issuer.identity().unwrap().pid;
        signal_pid("-STOP", pid);
        let r = tokio::time::timeout(Duration::from_millis(300), issuer.reload()).await;
        assert!(r.is_err(), "the waiter was cancelled: {r:?}");
        let acquired = ops.uninstall_fence_acquire(FENCE_HOLDER).await;
        let alive_at_acquire = running(pid);
        if alive_at_acquire {
            signal_pid("-CONT", pid);
            issuer.stop().await;
        }
        assert!(acquired.is_ok(), "{acquired:?}");
        assert!(
            !alive_at_acquire,
            "the fence was taken while the child that owns the delivered load was alive"
        );
        assert_eq!(
            issuer.state(),
            heimdall_contract::issuer::IssuerState::Crashed
        );
        assert!(issuer.loaded_cas().is_empty(), "no CA loaded");
        let _ = heimdall_app::ports::IssuerPort::sign(
            &issuer,
            heimdall_issuer::protocol::IssuanceRef {
                table: heimdall_issuer::protocol::IssuanceTable::Grant,
                id: heimdall_contract::ids::IssuanceId::from_random_bytes([7; 16]),
            },
            "ssh-ed25519 AAAA",
        )
        .await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            issuer.identity().is_none(),
            "no child started under the fence"
        );
        assert!(!ops.uninstall_fence_release(FENCE_HOLDER));
        issuer.stop().await;
    });
}

/// ⟨M03 wave 5, round 3; the round's `issuer_store_locked` flake⟩
/// `issuer_init_refuses_when_its_executable_is_replaced_mid_ceremony`, macOS on the
/// product-file test store: the CLI runs from its own copy of the binary; while it waits at
/// the passphrase's `written` prompt, that file is replaced by a re-signed copy (another
/// code identity: what an update, or a concurrent rebuild of a shared `target/`, does).
/// The keychain item's access list would then trust the new file and the running CLI could
/// never read it back (`errSecAuthFailed`, reported before the fix as `issuer_store_locked`
/// with an orphan item). Now nothing is written: `SERVICE_UNAVAILABLE` (exit 5) naming the
/// replaced executable, no keychain item, nothing registered or acknowledged.
#[cfg(target_os = "macos")]
#[test]
fn issuer_init_refuses_when_its_executable_is_replaced_mid_ceremony() {
    let rig = Rig::product();
    let dir = rig.file("own-bin");
    private_dir(&dir);
    let copy = dir.join("heimdall");
    std::fs::copy(&rig.program, &copy).unwrap();
    let variant = dir.join("variant");
    std::fs::copy(&rig.program, &variant).unwrap();
    let signed = Command::new("/usr/bin/codesign")
        .args(["-f", "-s", "-", "-i", "heimdall-replaced"])
        .arg(&variant)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(signed.success(), "codesign re-signed the variant");
    let backup = rig.file("replaced.key");
    let argv = vec![
        copy.to_string_lossy().into_owned(),
        "--json".into(),
        "issuer".into(),
        "init".into(),
        "--backup-out".into(),
        backup.to_string_lossy().into_owned(),
    ];
    let pty = Pty::open();
    let mut s = start_argv(&rig, "replaced", argv, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Type 'yes' to register this CA: ", &mut s.child));
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("yes");
    assert!(pty.wait_for("Type 'written'", &mut s.child));
    std::fs::rename(&variant, &copy).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    pty.type_line("written");
    let out = finish(&mut s);
    assert_eq!(out.code, 5, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "SERVICE_UNAVAILABLE", "{out:?}");
    assert_ne!(reason(&env), "issuer_store_locked", "{out:?}");
    // ⟨ADR-0008 §17.28 item 5⟩ Its own reason, and the next step.
    assert_eq!(reason(&env), "issuer_executable_changed", "{out:?}");
    assert!(out.message().contains("executable was replaced"), "{out:?}");
    assert!(
        out.message()
            .contains("finish installing or updating Heimdall, then run the command again"),
        "{out:?}"
    );
    assert!(
        rig.product_store().list().unwrap().is_empty(),
        "no keychain item was written"
    );
    assert!(
        rig.store()
            .transaction(|tx| tx.issuers())
            .unwrap()
            .is_empty()
    );
    assert!(
        rig.store()
            .transaction(|tx| tx.lock_disclosure_ack())
            .unwrap()
            .is_none()
    );
}

/// ⟨ADR-0008 §17.34 item 3 (W5-F04); `RESIDUALS`
/// `issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child`⟩
/// `recheck4_cancelling_stop_must_not_signal_unverified_child` **documents** the residual
/// (it passes while the residual holds). The real child is stopped and the exact-child check
/// cannot verify it (its image is unreadable), so the indeterminate `load`'s cleanup does not
/// signal it and waits (≤ 5 s) for its exit. Cancelling that wait drops the cleanup, and the
/// child handle's `kill_on_drop` signals the child. What the test shows:
/// * the signal reaches only that child: while the PID is present it is the same process
///   (its start token unchanged), unreaped, so the handle cannot reach a reused PID, and the
///   child then ends;
/// * no lasting effect: no store write (no event, the CA record unchanged), no CA loaded and
///   no certificate produced; the fence can then be taken.
#[cfg(unix)]
#[test]
fn recheck4_cancelling_stop_must_not_signal_unverified_child() {
    let mut rig = Rig::new();
    let (fp, _) = rig.seed_ca();
    let ops = rig.service.as_ref().unwrap().ops.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let issuer = real_issuer_with(&rig, |c| {
            c.child_image = Some(Arc::new(|_| None));
            c.request_timeout = Duration::from_secs(2);
        })
        .await;
        let identity = issuer.identity().unwrap();
        let pid = identity.pid;
        let head = rig.event_head();
        let record = rig.store().transaction(|tx| tx.issuer(&fp)).unwrap();
        signal_pid("-STOP", pid);
        // The load times out at 2 s; the cleanup's wait (≤ 5 s) is cancelled at 2.5 s.
        let cancelled = tokio::time::timeout(Duration::from_millis(2500), issuer.reload()).await;
        assert!(cancelled.is_err(), "cancelled during the cleanup's wait");
        // Only that child is signalled: whatever holds the PID is still the same process
        // (unreaped, its start token unchanged) until it has ended and been reaped.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let now = heimdall_runtime::platform::process_start_time(pid);
            assert!(
                now.is_none() || now == identity.start_token,
                "the PID is held by another process"
            );
            if !running(pid) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the dropped handle signalled the child"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // No lasting effect: nothing written, nothing loaded, nothing signed.
        assert_eq!(rig.event_head(), head, "no store write");
        assert_eq!(
            rig.store().transaction(|tx| tx.issuer(&fp)).unwrap(),
            record,
            "the CA record is unchanged"
        );
        assert!(issuer.loaded_cas().is_empty(), "no CA loaded");
        assert_ne!(
            issuer.state(),
            heimdall_contract::issuer::IssuerState::Ready
        );
        ops.uninstall_fence_acquire(FENCE_HOLDER).await.unwrap();
        assert!(!ops.uninstall_fence_release(FENCE_HOLDER));
        issuer.stop().await;
        assert!(!running(pid), "no survivor");
    });
}

/// ⟨ADR-0008 §17.33 item 11 (audit B2), recorded residual
/// `issuer_request_hold_absent_for_leader_and_lease_work`⟩
/// `residual_leader_shaped_sign_unconfirmed_stop_keeps_no_admission` (after the audit's
/// `rvprobe_leader_shaped_sign_unconfirmed_stop_keeps_admission`): a `sign` sent from a
/// task that holds no admission of its own (the verification leader's shape: the
/// admission is another task's) to a child that cannot be verified (never signalled)
/// and stopped. When its waiter times out, nothing extends the admission, so once the
/// other task drops it a fence acquisition is taken **while the stuck child is still
/// alive**: the residual. It has no lasting effect: the child never writes the state
/// database, and the late signature reaches no reader, so no certificate is published
/// (the database is byte-identical afterwards).
#[cfg(unix)]
#[test]
fn residual_leader_shaped_sign_unconfirmed_stop_keeps_no_admission() {
    use heimdall_app::ports::IssuerPort as _;
    let mut rig = Rig::new();
    rig.seed_ca();
    let ops = rig.service.as_ref().unwrap().ops.clone();
    let db = rig.state_dir().join("state.db");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let issuer = real_issuer_with(&rig, |c| c.child_image = Some(Arc::new(|_| None))).await;
        let pid = issuer.identity().unwrap().pid;
        signal_pid("-STOP", pid);
        let before = std::fs::read(&db).unwrap();
        // The admission is this task's; the sign runs in a task of its own.
        let admission = ops.uninstall_fence_admit().unwrap();
        let i = issuer.clone();
        tokio::spawn(async move {
            let sign = i.sign(
                heimdall_issuer::protocol::IssuanceRef {
                    table: heimdall_issuer::protocol::IssuanceTable::Grant,
                    id: heimdall_contract::ids::IssuanceId::from_random_bytes([9; 16]),
                },
                "ssh-ed25519 AAAA",
            );
            let r = tokio::time::timeout(Duration::from_millis(300), sign).await;
            assert!(r.is_err(), "the waiter timed out: {r:?}");
        })
        .await
        .unwrap();
        drop(admission);
        let acquired = ops.uninstall_fence_acquire(FENCE_HOLDER).await;
        let alive = running(pid);
        signal_pid("-CONT", pid);
        assert!(acquired.is_ok(), "{acquired:?}");
        assert!(
            alive,
            "the residual: the stuck child outlived the admission"
        );
        // Resumed, it finishes and exits at EOF; nothing lasting follows.
        let deadline = Instant::now() + Duration::from_secs(10);
        while running(pid) {
            assert!(Instant::now() < deadline, "the child exited at EOF");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            std::fs::read(&db).unwrap(),
            before,
            "no store write and no published certificate followed"
        );
        assert!(!ops.uninstall_fence_release(FENCE_HOLDER));
        issuer.stop().await;
    });
}
