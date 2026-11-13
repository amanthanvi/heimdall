//! m03-plan U4 pty ceremony tests (hosted by heimdall; ADR-0008 D4 item 1, D13 item 1,
//! A33): the issuer ceremonies on a **real pseudo-terminal**, and the D5 backup read
//! by stock `ssh-keygen` through a pty.
//!
//! A case re-executes this test binary as the leader of a new session whose
//! controlling terminal is the pty (`setsid`, `TIOCSCTTY`), and runs the ceremony
//! there with `ControllingTerminal` (`/dev/tty`); its stdout and stderr are separate
//! files, so the test can show the passphrase reaches the terminal only. The owner
//! session is a fake standing in for U12's CLI and U10's runtime (the real CLI →
//! `issuer.register` → `Decide` path needs U10/U12); the store is a file store of
//! this suite holding K_ca only in the D5 encrypted form. The passphrase is typed at
//! prompts, never put in an argument or a variable; the transcript stays in memory.
//!
//! The pty rows are Unix-only (`cfg(unix)`); `init_refuses_non_tty_and_non_interactive`
//! also runs on Windows (a detached child has no console, so `CONIN$` cannot open).

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(unix)]
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{CaFingerprint, DecisionId};
use heimdall_contract::issuer::{
    CaState, CaStatus, EnrollmentCounts, IssuerState, IssuerStatus, StoreKind,
};
use heimdall_contract::managed::IssuerIsolation;
#[cfg(unix)]
use heimdall_issuer::backup::sha256_hex;
use heimdall_issuer::backup::{Passphrase, fingerprint_file_stem};
use heimdall_issuer::bundle::{Redaction, StoreView};
use heimdall_issuer::ceremony::{
    self, ControllingTerminal, InitOptions, OwnerSession, RegisterDecision, RegisterRequest,
    SessionError,
};
use heimdall_issuer::store::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef, StoredCaKey,
};
#[cfg(unix)]
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

const SLAVE: &str = "HM_U4_PTY_SLAVE";
const CASE: &str = "HM_U4_CASE";
const DIR: &str = "HM_U4_DIR";
#[cfg(unix)]
const ARGV: &str = "HM_U4_ARGV";
const LIMIT: Duration = Duration::from_secs(120);

// -----------------------------------------------------------------------------
// The child side: a ceremony on the controlling terminal
// -----------------------------------------------------------------------------

/// A file store of this suite: one file per CA holding the D5 form under a passphrase
/// that lives only in this process's memory (test configuration; kind
/// `e2e_file_test`).
struct FileStore {
    dir: PathBuf,
    passphrase: Passphrase,
}

impl FileStore {
    fn path(&self, fp: &CaFingerprint) -> PathBuf {
        self.dir.join(format!("{}.key", fingerprint_file_stem(fp)))
    }

    fn reference(&self, fp: &CaFingerprint) -> StoreItemRef {
        StoreItemRef {
            kind: self.kind(),
            fingerprint: fp.clone(),
            locator: self.path(fp).to_string_lossy().into_owned(),
        }
    }
}

impl SecretStore for FileStore {
    fn kind(&self) -> SecretStoreKind {
        SecretStoreKind::Test("e2e_file_test")
    }

    fn availability(&self) -> StoreAvailability {
        if self.dir.is_dir() {
            StoreAvailability::Available
        } else {
            StoreAvailability::Missing
        }
    }

    fn put(&self, fp: &CaFingerprint, key: &StoredCaKey) -> Result<StoreItemRef, StoreError> {
        let sealed = key
            .encrypt_openssh(self.passphrase.expose().as_bytes())
            .map_err(|_| StoreError::Failed)?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path(fp))
            .map_err(|_| StoreError::AlreadyExists)?;
        f.write_all(&sealed).map_err(|_| StoreError::Failed)?;
        Ok(self.reference(fp))
    }

    fn get(&self, fp: &CaFingerprint) -> Result<StoredCaKey, StoreError> {
        let bytes = std::fs::read(self.path(fp)).map_err(|_| StoreError::NotFound)?;
        StoredCaKey::decrypt_openssh(&bytes, self.passphrase.expose().as_bytes())
            .map_err(|_| StoreError::Corrupt)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        std::fs::remove_file(self.path(&item.fingerprint)).map_err(|_| StoreError::NotFound)
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.dir).map_err(|_| StoreError::Failed)? {
            let name = e.map_err(|_| StoreError::Failed)?.file_name();
            let name = name.to_string_lossy();
            if let Some(fp) = name
                .strip_suffix(".key")
                .and_then(heimdall_issuer::backup::fingerprint_from_file_stem)
            {
                out.push(self.reference(&fp));
            }
        }
        Ok(out)
    }
}

/// The fake runtime of the child: it answers `register` with a decision naming the
/// request's CA and digest, and on `approve` records the CA and the native
/// environment's `managed_signing` and `issuer_access` permissions as the runtime's
/// one transaction would (U10 implements the real one).
#[derive(Default)]
struct FakeRuntime {
    events: Vec<String>,
    registered: Vec<RegisterRequest>,
    approved: Vec<DecisionId>,
    cas: Vec<CaStatus>,
    permissions: Vec<String>,
}

impl OwnerSession for FakeRuntime {
    fn attend(&mut self) -> Result<(), SessionError> {
        self.events.push("attend".into());
        Ok(())
    }

    fn status(&mut self) -> Result<IssuerStatus, SessionError> {
        self.events.push("status".into());
        Ok(IssuerStatus {
            state: IssuerState::NotInitialized,
            reason: None,
            cas: self.cas.clone(),
            orphan_store_items: Vec::new(),
            issuer_isolation: IssuerIsolation::SameUserProcess,
            bundle_stale: false,
        })
    }

    fn register(&mut self, request: &RegisterRequest) -> Result<RegisterDecision, SessionError> {
        self.events.push("register".into());
        self.registered.push(request.clone());
        let fp = ceremony::public_key_fingerprint(&request.ca_public_key).unwrap();
        Ok(RegisterDecision {
            decision_id: DecisionId::from_random_bytes([1; 16]),
            ca_fingerprint: fp,
            backup_sha256: request.backup_sha256.clone(),
            disclosures: vec![
                heimdall_contract::enrollment::DisclosureKind::SameUserIssuerBoundary,
                heimdall_contract::enrollment::DisclosureKind::CaTrustBlastRadius,
                heimdall_contract::enrollment::DisclosureKind::BackupInstructions,
            ],
        })
    }

    fn approve(&mut self, decision: &DecisionId) -> Result<(), SessionError> {
        self.events.push("approve".into());
        self.approved.push(decision.clone());
        let request = self.registered.last().unwrap();
        let fp = ceremony::public_key_fingerprint(&request.ca_public_key).unwrap();
        self.cas.push(CaStatus {
            fingerprint: fp,
            state: CaState::Active,
            store: StoreKind::LinuxSecretService,
            backup_sha256: request.backup_sha256.clone(),
            backup_created_at: request.backup_created_at,
            restored_without_log: false,
            enrollments: EnrollmentCounts::default(),
            store_locator: request.store_locator.clone(),
        });
        self.permissions = vec!["managed_signing".into(), "issuer_access".into()];
        Ok(())
    }

    fn unlock(&mut self) -> Result<IssuerStatus, SessionError> {
        self.status()
    }
}

/// Run one ceremony case in this (child) process and write `result.json`.
fn run_case(case: &str, dir: &Path) {
    let store_dir = dir.join("store");
    let store = FileStore {
        dir: store_dir.clone(),
        passphrase: Passphrase::generate().unwrap(),
    };
    let backup_out = dir.join("ca-backup.key");
    let mut runtime = FakeRuntime::default();
    let options = InitOptions {
        backup_out: &backup_out,
        non_interactive: case == "non_interactive",
    };
    // `no_tty`: the session has no controlling terminal; `non_interactive`: it has
    // one, and the flag is refused first.
    let outcome = match ControllingTerminal::open() {
        Ok(mut tty) => ceremony::init(&mut tty, &mut runtime, &store, &options),
        Err(e) => Err(e),
    };
    let mut result = BTreeMap::new();
    match &outcome {
        Ok(done) => {
            result.insert("outcome", serde_json::json!("registered"));
            result.insert("fingerprint", serde_json::json!(done.fingerprint.as_str()));
            result.insert("item", serde_json::json!(done.item.locator));
            result.insert(
                "backup_sha256",
                serde_json::json!(done.backup.as_ref().unwrap().sha256),
            );
        }
        Err(e) => {
            result.insert("outcome", serde_json::json!("refused"));
            result.insert("code", serde_json::to_value(e.code()).unwrap());
            result.insert("error", serde_json::json!(e.to_string()));
        }
    }
    result.insert("events", serde_json::json!(runtime.events));
    result.insert("permissions", serde_json::json!(runtime.permissions));
    result.insert(
        "registered",
        serde_json::json!(
            runtime
                .registered
                .iter()
                .map(|r| serde_json::json!({
                    "ca_public_key": r.ca_public_key,
                    "store": format!("{:?}", r.store),
                    "backup_sha256": r.backup_sha256,
                    "rotation_of": r.rotation_of.as_ref().map(CaFingerprint::as_str),
                    "restored_without_log": r.restored_without_log,
                    "store_locator": r.store_locator,
                }))
                .collect::<Vec<_>>()
        ),
    );
    result.insert("approved", serde_json::json!(runtime.approved.len()));
    if let Ok(done) = &outcome {
        let key = store.get(&done.fingerprint).unwrap();
        result.insert(
            "public_key",
            serde_json::json!(key.public_openssh().unwrap()),
        );
        // A bundle of this CA (public metadata only), for the passphrase scan.
        let record = heimdall_store::IssuerRecord {
            ca_fingerprint: done.fingerprint.clone(),
            public_key: key.public_openssh().unwrap(),
            state: CaState::Active,
            store_kind: StoreKind::LinuxSecretService,
            backup_sha256: done.backup.as_ref().unwrap().sha256.clone(),
            backup_created_at: Timestamp::now(),
            restored_without_log: false,
            created_at: Timestamp::now(),
            retired_at: None,
        };
        let bundle = heimdall_issuer::bundle::export(
            &StoreView {
                created_at: Timestamp::now(),
                cas: std::slice::from_ref(&record),
                enrollments: &[],
            },
            Redaction::None,
        )
        .unwrap();
        std::fs::write(
            dir.join("bundle.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

/// Child-mode entry of the ceremony cases: a new session on the pty (or, for
/// `no_tty`, a new session with no controlling terminal). stdout and stderr stay the
/// files the parent gave.
#[test]
#[ignore = "child-mode entry of the pty ceremony tests, started by them"]
fn pty_ceremony_child() {
    let (Some(case), Some(dir)) = (std::env::var(CASE).ok(), std::env::var_os(DIR)) else {
        return;
    };
    // Unix: a new session, which acquires the pty as its controlling terminal unless
    // the case is `no_tty`. Windows: the parent started this process detached (no
    // console) for `no_tty`.
    #[cfg(unix)]
    {
        rustix::process::setsid().unwrap();
        if case != "no_tty" {
            let slave = std::env::var_os(SLAVE).unwrap();
            let tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(slave)
                .unwrap();
            rustix::process::ioctl_tiocsctty(&tty).unwrap();
            drop(tty);
        }
    }
    run_case(&case, Path::new(&dir));
}

/// Child-mode entry that execs a program on the pty (stdio on the terminal too), the
/// argv from the parent (never holding a passphrase).
#[cfg(unix)]
#[test]
#[ignore = "child-mode entry of d5_backup_restores_with_stock_ssh_keygen, started by it"]
fn pty_exec_child() {
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
    let err = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .exec();
    panic!("exec failed: {err}");
}

// -----------------------------------------------------------------------------
// The parent side: the pty and its transcript
// -----------------------------------------------------------------------------

#[cfg(unix)]
/// A pseudo-terminal whose output is drained into an in-memory transcript. It holds
/// its slave descriptor for its life (macOS forgets the size otherwise).
struct Pty {
    master: OwnedFd,
    slave: PathBuf,
    _slave_fd: OwnedFd,
    output: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
}

#[cfg(unix)]
impl Drop for Pty {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(unix)]
impl Pty {
    fn open() -> Pty {
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

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    /// Wait until the transcript contains `needle` (or `child` exits).
    fn wait_for(&self, needle: &str, child: &mut Child) {
        let deadline = Instant::now() + LIMIT;
        while !self.transcript().contains(needle) {
            assert!(
                child.try_wait().unwrap().is_none() || self.transcript().contains(needle),
                "the child exited before {needle:?}"
            );
            assert!(Instant::now() < deadline, "no {needle:?} on the terminal");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Type `text` at the terminal.
    fn type_line(&self, text: &str) {
        self.try_type_line(text).unwrap();
    }

    /// Type `text`; the terminal may already be gone (its session ended).
    fn try_type_line(&self, text: &str) -> std::io::Result<()> {
        let mut f = std::fs::File::from(self.master.try_clone()?);
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")
    }
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the child did not finish");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The libtest arguments that run one child-mode entry.
fn entry(name: &str) -> Vec<OsString> {
    [
        "--exact",
        name,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// A started child: its process, every argument and variable value the test gave it
/// (checked for the passphrase), and its stdout and stderr files.
// The Windows row reads only the exit status; the fields are read by the Unix rows.
#[cfg_attr(not(unix), allow(dead_code))]
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

fn start_case(dir: &Path, case: &str, slave: Option<&Path>) -> Started {
    let exe = std::env::current_exe().unwrap();
    let args = entry("pty_ceremony_child");
    let stdout = dir.join(format!("{case}.stdout"));
    let stderr = dir.join(format!("{case}.stderr"));
    let mut env: Vec<(OsString, OsString)> = vec![
        (CASE.into(), case.into()),
        (DIR.into(), dir.as_os_str().to_owned()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("HOME".into(), dir.as_os_str().to_owned()),
    ];
    if let Some(slave) = slave {
        env.push((SLAVE.into(), slave.as_os_str().to_owned()));
    }
    #[cfg(windows)]
    for k in ["SystemRoot", "TEMP", "TMP"] {
        if let Some(v) = std::env::var_os(k) {
            env.push((k.into(), v));
        }
    }
    let mut cmd = Command::new(&exe);
    cmd.args(&args).env_clear().current_dir(dir);
    for (k, v) in &env {
        cmd.env(k, v);
    }
    // Windows: no slave means no terminal; `DETACHED_PROCESS` starts the child with no
    // console at all, so `CONIN$` cannot be opened.
    #[cfg(windows)]
    if slave.is_none() {
        use std::os::windows::process::CommandExt as _;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let mut given = vec![exe.into_os_string()];
    given.extend(args);
    given.extend(env.into_iter().flat_map(|(k, v)| [k, v]));
    Started {
        child,
        given,
        stdout,
        stderr,
    }
}

#[cfg(unix)]
/// The running process `pid`'s arguments as the kernel reports them (`ps`), for the
/// argv check only; never printed.
fn process_args(pid: u32) -> String {
    let out = Command::new("/bin/ps")
        .args(["-o", "args=", "-p", &pid.to_string()])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn read_result(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir.join("result.json")).unwrap()).unwrap()
}

#[cfg(unix)]
/// The passphrase as the ceremony displayed it (groups of five), joined.
fn shown_passphrase(transcript: &str) -> String {
    let marker = "without the spaces):";
    let at = transcript.find(marker).expect("passphrase shown") + marker.len();
    let line = transcript[at..]
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap();
    let joined: String = line.split(' ').collect();
    assert_eq!(joined.len(), 26, "26 base32 symbols");
    joined
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("hm-u4-pty-")
        .tempdir()
        .unwrap()
}

#[cfg(unix)]
/// Run the init ceremony on a pty, typing `yes` and `written`; returns the scratch,
/// the transcript, the started child (exited) and the passphrase.
fn run_init(argv_check: bool) -> (tempfile::TempDir, String, Started, String) {
    let dir = scratch();
    std::fs::create_dir(dir.path().join("store")).unwrap();
    let pty = Pty::open();
    let mut started = start_case(dir.path(), "init", Some(&pty.slave));
    pty.wait_for("Type 'yes' to register this CA: ", &mut started.child);
    pty.type_line("yes");
    pty.wait_for("Type 'written'", &mut started.child);
    let passphrase = shown_passphrase(&pty.transcript());
    if argv_check {
        // While the passphrase is on the terminal, the child's own argv (as the
        // kernel holds it) does not carry it.
        let args = process_args(started.child.id());
        assert!(!args.is_empty());
        assert!(!args.contains(&passphrase));
    }
    pty.type_line("written");
    let status = wait(&mut started.child);
    assert!(status.success(), "child exit {:?}", status.code());
    let transcript = pty.transcript();
    (dir, transcript, started, passphrase)
}

// -----------------------------------------------------------------------------
// The tests
// -----------------------------------------------------------------------------

#[cfg(unix)]
/// The ceremony part of this row: register (public key, store kind, digest of the
/// exact backup), the owner's `yes`, the exact backup, the passphrase on the terminal
/// with `written`, the store, then `Decide approve` (the fake runtime records the CA
/// and sets `managed_signing` and `issuer_access`; the real transaction that moves
/// the generation is U10's, not done here).
#[test]
fn init_ceremony_registers_ca_and_environment_permissions() {
    let (dir, transcript, _started, _passphrase) = run_init(false);
    let result = read_result(dir.path());
    assert_eq!(result["outcome"], "registered", "{result}");
    assert_eq!(
        result["events"],
        serde_json::json!(["status", "attend", "register", "register", "approve"])
    );
    let registered = &result["registered"][0];
    // ⟨ADR-0008 §17.22 item 12⟩ Step 3 carries no store item; after the put the same
    // registration reports the put's exact locator (the fake joins the same decision).
    assert_eq!(registered["store_locator"], serde_json::Value::Null);
    let report = &result["registered"][1];
    assert_eq!(report["store_locator"], result["item"]);
    for k in ["ca_public_key", "store", "backup_sha256", "rotation_of"] {
        assert_eq!(report[k], registered[k], "{k}");
    }
    assert_eq!(registered["ca_public_key"], result["public_key"]);
    assert!(
        registered["ca_public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 AAAA")
    );
    assert_eq!(registered["store"], "Test(\"e2e_file_test\")");
    assert_eq!(registered["rotation_of"], serde_json::Value::Null);
    let backup = std::fs::read(dir.path().join("ca-backup.key")).unwrap();
    assert_eq!(registered["backup_sha256"], sha256_hex(&backup));
    assert_eq!(result["backup_sha256"], sha256_hex(&backup));
    assert_eq!(result["approved"], 1);
    assert_eq!(
        result["permissions"],
        serde_json::json!(["managed_signing", "issuer_access"])
    );
    // The disclosure was shown before the confirmation; the passphrase region was
    // cleared after `written`.
    let disclose = transcript
        .find("same-user")
        .or_else(|| transcript.find("your own OS user"));
    let confirm = transcript.find("Type 'yes'").unwrap();
    assert!(disclose.unwrap() < confirm);
    assert!(transcript.contains(&format!(
        "Register CA {}",
        result["fingerprint"].as_str().unwrap()
    )));
    let written = transcript.find("Type 'written'").unwrap();
    assert!(
        transcript[written..].contains("\x1b[J"),
        "screen region cleared"
    );
    assert!(transcript.contains("registered."));
    // The store holds exactly the one item.
    assert_eq!(files_under(&dir.path().join("store")).len(), 1);
}

#[cfg(unix)]
#[test]
fn passphrase_only_on_tty_transcript() {
    let (dir, transcript, started, passphrase) = run_init(true);
    assert!(
        transcript.contains(&passphrase[..5]),
        "shown on the terminal"
    );
    let grouped: String = passphrase
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(transcript.contains(&grouped));
    // Not on stdout or stderr (separate from the terminal), in no file the run wrote
    // (the result JSON, the backup, the store, the bundle), in no argument or variable
    // the test gave a process.
    let needles = [passphrase.clone(), grouped.clone()];
    for file in files_under(dir.path()) {
        let bytes = std::fs::read(&file).unwrap();
        for n in &needles {
            assert!(
                !bytes.windows(n.len()).any(|w| w == n.as_bytes()),
                "the passphrase is in {}",
                file.file_name().unwrap().to_string_lossy()
            );
        }
    }
    for path in [&started.stdout, &started.stderr] {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(!text.contains(&passphrase));
    }
    for v in &started.given {
        assert!(!v.to_string_lossy().contains(&passphrase));
    }
    let bundle = std::fs::read_to_string(dir.path().join("bundle.json")).unwrap();
    assert!(!bundle.contains(&passphrase));
    heimdall_testkit::assert_no_canary(&bundle);
    let result = std::fs::read_to_string(dir.path().join("result.json")).unwrap();
    assert!(!result.contains(&passphrase));
    // The passphrase decrypts the backup (it is the real one).
    let restored = heimdall_issuer::backup::restore(
        &dir.path().join("ca-backup.key"),
        &Passphrase::from_utf8(passphrase.into_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        restored.public_openssh().unwrap(),
        read_result(dir.path())["public_key"].as_str().unwrap()
    );
}

/// A terminal any use of which fails the test: the refusal must come first.
struct UntouchedTty;

impl ceremony::Tty for UntouchedTty {
    fn write_text(&mut self, _: &str) -> std::io::Result<()> {
        panic!("the terminal was written before the refusal")
    }
    fn read_line(&mut self) -> std::io::Result<Option<ceremony::Zeroizing<String>>> {
        panic!("the terminal was read before the refusal")
    }
    fn read_hidden(&mut self) -> std::io::Result<Option<ceremony::Zeroizing<String>>> {
        panic!("the terminal was read before the refusal")
    }
    fn clear_lines(&mut self, _: usize) -> std::io::Result<()> {
        panic!("the terminal was cleared before the refusal")
    }
}

fn assert_refused_and_untouched(dir: &Path, needle: &str) {
    let result = read_result(dir);
    assert_eq!(result["outcome"], "refused", "{result}");
    assert_eq!(result["code"], "INTERACTION_REQUIRED");
    assert!(
        result["error"].as_str().unwrap().contains(needle),
        "{result}"
    );
    assert_eq!(result["events"], serde_json::json!([]));
    assert!(!dir.join("ca-backup.key").exists());
    assert!(files_under(&dir.join("store")).is_empty());
}

#[test]
fn init_refuses_non_tty_and_non_interactive() {
    // No controlling terminal: Unix, a new session that never acquires one; Windows, a
    // detached process with no console.
    let dir = scratch();
    std::fs::create_dir(dir.path().join("store")).unwrap();
    let mut started = start_case(dir.path(), "no_tty", None);
    assert!(wait(&mut started.child).success());
    assert_refused_and_untouched(dir.path(), "terminal");
    // --non-interactive is refused before the terminal, the store or the runtime is
    // used (in process: any terminal use would panic).
    let dir = scratch();
    std::fs::create_dir(dir.path().join("store")).unwrap();
    let store = FileStore {
        dir: dir.path().join("store"),
        passphrase: Passphrase::generate().unwrap(),
    };
    let mut runtime = FakeRuntime::default();
    let out = dir.path().join("ca-backup.key");
    let err = ceremony::init(
        &mut UntouchedTty,
        &mut runtime,
        &store,
        &InitOptions {
            backup_out: &out,
            non_interactive: true,
        },
    )
    .err()
    .unwrap();
    assert_eq!(err, ceremony::CeremonyError::NonInteractive);
    assert_eq!(
        serde_json::to_value(err.code()).unwrap(),
        "INTERACTION_REQUIRED"
    );
    assert!(runtime.events.is_empty());
    assert!(!out.exists());
    assert!(files_under(&dir.path().join("store")).is_empty());
    // And with a real terminal present (Unix pty).
    #[cfg(unix)]
    {
        let dir = scratch();
        std::fs::create_dir(dir.path().join("store")).unwrap();
        let pty = Pty::open();
        let mut started = start_case(dir.path(), "non_interactive", Some(&pty.slave));
        assert!(wait(&mut started.child).success());
        assert_refused_and_untouched(dir.path(), "non-interactive");
        assert!(!pty.transcript().contains("passphrase"));
    }
}

#[cfg(unix)]
#[test]
fn d5_backup_restores_with_stock_ssh_keygen() {
    let keygen = Path::new("/usr/bin/ssh-keygen");
    assert!(keygen.is_file(), "stock ssh-keygen");
    // The backup the ceremony wrote, and its passphrase from the ceremony's terminal.
    let (dir, _transcript, started, passphrase) = run_init(false);
    let result = read_result(dir.path());
    let public = result["public_key"].as_str().unwrap().to_owned();
    let backup = dir.path().join("ca-backup.key");
    // `ssh-keygen -y -f <backup>` on a pty: the passphrase is typed at its prompt.
    let pty = Pty::open();
    let argv = vec![
        keygen.to_string_lossy().into_owned(),
        "-y".to_owned(),
        "-f".to_owned(),
        backup.to_string_lossy().into_owned(),
    ];
    let argv_json = serde_json::to_string(&argv).unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(&exe)
        .args(entry("pty_exec_child"))
        .env_clear()
        .env(SLAVE, &pty.slave)
        .env(ARGV, &argv_json)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    pty.wait_for("passphrase", &mut child);
    // At its prompt, the running ssh-keygen's argv holds no passphrase.
    let args = process_args(child.id());
    assert!(
        args.contains("ssh-keygen"),
        "ssh-keygen is the running program"
    );
    assert!(!args.contains(&passphrase));
    pty.type_line(&passphrase);
    let status = wait(&mut child);
    assert!(status.success(), "ssh-keygen exit {:?}", status.code());
    let transcript = pty.transcript();
    assert!(
        transcript.lines().any(|l| l.trim() == public),
        "ssh-keygen printed the CA public key"
    );
    // No argument or variable any process of this test was given held it.
    for v in started
        .given
        .iter()
        .chain([exe.as_os_str().to_owned(), OsString::from(&argv_json)].iter())
    {
        assert!(!v.to_string_lossy().contains(&passphrase));
    }
    for a in &argv {
        assert!(!a.contains(&passphrase));
    }
    // A wrong passphrase is refused by ssh-keygen too.
    let pty = Pty::open();
    let mut child = Command::new(&exe)
        .args(entry("pty_exec_child"))
        .env_clear()
        .env(SLAVE, &pty.slave)
        .env(ARGV, &argv_json)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    pty.wait_for("passphrase", &mut child);
    let wrong = Passphrase::generate().unwrap();
    pty.type_line(wrong.expose());
    // Should it ask again, answer wrong again until it gives up.
    let deadline = Instant::now() + LIMIT;
    let mut prompts = 1;
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "ssh-keygen did not give up");
        let now = pty.transcript().matches("passphrase").count();
        if now > prompts {
            prompts = now;
            // It may have printed its refusal and exited meanwhile.
            let _ = pty.try_type_line(wrong.expose());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = wait(&mut child);
    assert!(!status.success());
    assert!(!pty.transcript().lines().any(|l| l.trim() == public));
}
