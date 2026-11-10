//! The loopback sshd fixture (m02-plan §0, U7 `sshd::LoopbackSshd`; tests/fixtures
//! MANIFEST row 1).
//!
//! On Unix it runs the host's `sshd` as the current, non-root user: `sshd -D -f
//! <scratch config> -E <scratch log>`, `ListenAddress 127.0.0.1` only, an ephemeral port,
//! a per-run Ed25519 host key, `AuthorizedKeysFile` in scratch with `restrict` (plus
//! `pty` when asked), public-key authentication only, `PermitUserRC no` and, where the
//! server knows the option, `PerSourcePenalties no` (MANIFEST row 1). A non-root sshd
//! authenticates only its own account, so clients log in as the current user and no
//! user name appears in any fixture text (a harness sshd that names its account is the
//! one exception; see below). Limitation: the session runs the account's
//! login shell in the account's home, as any login to this account would.
//!
//! When the harness supplies `HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY}` (Windows, which
//! runs the fixture sshd in WSL scratch, or the Docker fallback of m02-plan §4), that
//! server is used instead. Per-run authorized keys then go to the file named by
//! `HM_FIXTURE_SSHD_AUTHORIZED_KEYS`; without it a fixture that needs keys is
//! [`SshdUnavailable`]. When no sshd can start, the fixture reports
//! [`SshdUnavailable`] and the harness falls back to the M00-T03 Docker fixtures.
//!
//! A harness server is shared by every test of the process, so (ADR-0007 §12.47 item 8,
//! WU-0; audit G-T1):
//! * **It never silently ignores a setting.** The harness sshd runs `MaxAuthTries 6` and
//!   `LogLevel VERBOSE` (tests/native/m02/remote-lib.sh). A config with
//!   `max_auth_tries` 3 uses the strict harness sshd,
//!   `HM_FIXTURE_SSHD_STRICT_{PORT,HOST_KEY,AUTHORIZED_KEYS,LOG}`, which the Windows local
//!   runner starts with `MaxAuthTries 3`. Any other value, or `log_level_verbose: false`,
//!   is [`SshdUnavailable`].
//! * **Its authorized-keys file has one owner at a time.** Each harness server has a
//!   process-wide lease, taken before the file is written and held for the fixture's
//!   lifetime, so parallel test threads never replace each other's keys mid-login. The
//!   file is rewritten at the start (emptied when the config has no keys) and emptied
//!   again on drop. A second fixture for the same harness server on the same thread is
//!   refused rather than left waiting on itself.
//! * **Its log is read from where this fixture started.** [`LoopbackSshd::accepted_log`]
//!   reads the shared `HM_FIXTURE_SSHD_LOG` from its length when the lease was taken.
//! * **Its account.** A non-root sshd authenticates only its own account; the WSL sshd's
//!   account is not the Windows user. `HM_FIXTURE_SSHD_USER` names it.
//!   [`LoopbackSshd::account`] exposes it (for example as a catalog destination
//!   account), and [`crate::home::ScratchHome::write_user_config`] of the same scratch
//!   then ends the scratch user configuration with `Host *` / `User <account>`, so it
//!   applies only where nothing earlier sets `User`. It never goes on a client's command
//!   line (ADR-0007 §9 item 1). Unset, nothing changes.
//!
//! **M03 extensions** (m03-plan U11; ADR-0008 D13 item 2), all local servers only. A
//! harness server cannot honour them, so a config that sets any of them is
//! [`SshdUnavailable`] there (never silently ignored), except
//! [`SshdConfig::registry_seed`], which a harness server's authorized-keys file can
//! carry:
//! * the **account form**: the scratch `AuthorizedKeysFile` is the explicit registry
//!   ([`LoopbackSshd::registry_path`]), seeded with [`SshdConfig::registry_seed`]
//!   (for example [`enrollable_like_seed`]);
//! * the **system form**: `TrustedUserCAKeys` ([`SshdConfig::trusted_user_ca_keys`]),
//!   `AuthorizedPrincipalsFile <scratch>/principals/%u`
//!   ([`SshdConfig::authorized_principals`]) and, for the `principals_not_enforced`
//!   fixture, an `AuthorizedPrincipalsCommand` ([`PrincipalsNotEnforced`]);
//! * [`TwoHosts`] and [`ThreeHosts`]: servers with distinct destination IDs, whose
//!   accepted certificate key IDs are read from each log
//!   ([`LoopbackSshd::accepted_certificates`]);
//! * [`Faults`]: a loopback fault proxy in front of a fixture sshd, for the negative
//!   verification's inconclusive cases; [`LaggingClock`]: sessions whose `awk` reports
//!   the time minus a lag (no clock is changed); [`WrongKey`]: a server whose host key
//!   is not the approved one, with the inheritance variants.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use heimdall_contract::enrollment::EnrollmentForm;
use ssh_key::PublicKey;

use crate::agent::{FixtureKey, random_hex, stop_child};
use crate::home::{Scratch, ScratchHome, find_program, ssh_config_quote};

/// The loopback address every fixture server binds.
pub const LOOPBACK: &str = "127.0.0.1";

/// How the fixture sshd is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshdConfig {
    /// Authorized user keys (written with `restrict`).
    pub authorized: Vec<PublicKey>,
    /// `MaxAuthTries`.
    pub max_auth_tries: u32,
    /// Add `pty` to the authorized keys' options.
    pub allow_pty: bool,
    /// `LogLevel VERBOSE` (else `INFO`).
    pub log_level_verbose: bool,
    /// ⟨M03⟩ `TrustedUserCAKeys <path>` (the system form; the file is read at each
    /// authentication, so a test may write the CA after the start).
    pub trusted_user_ca_keys: Option<PathBuf>,
    /// ⟨M03⟩ `AuthorizedPrincipalsFile <scratch>/principals/%u`, one file per account
    /// (the key) listing its principals. A non-root sshd authenticates only its own
    /// account ([`current_account`]).
    pub authorized_principals: Option<BTreeMap<String, Vec<String>>>,
    /// ⟨M03⟩ The account form's explicit registry: these bytes start the scratch
    /// `AuthorizedKeysFile`, before the [`authorized`](Self::authorized) lines.
    pub registry_seed: Option<Vec<u8>>,
    /// ⟨M03⟩ `AuthorizedPrincipalsCommand /bin/sh <script> %t %k` with
    /// `AuthorizedPrincipalsCommandUser` = the current account
    /// ([`PrincipalsNotEnforced::echo_principals_command`]). `/bin/sh` is the command
    /// (root-owned, as sshd's path check requires); the scratch script is its argument.
    pub authorized_principals_command: Option<PathBuf>,
    /// ⟨M03⟩ `MaxStartups <value>` (for example `1:100:1`, [`Faults`]).
    pub max_startups: Option<String>,
    /// ⟨M03⟩ `SetEnv PATH=<dir>:/usr/bin:/bin:/usr/sbin:/sbin` for sessions
    /// ([`LaggingClock`]).
    pub session_path: Option<PathBuf>,
}

impl Default for SshdConfig {
    fn default() -> Self {
        SshdConfig {
            authorized: Vec::new(),
            max_auth_tries: 6,
            allow_pty: false,
            log_level_verbose: true,
            trusted_user_ca_keys: None,
            authorized_principals: None,
            registry_seed: None,
            authorized_principals_command: None,
            max_startups: None,
            session_path: None,
        }
    }
}

impl SshdConfig {
    /// The first M03 setting a harness server cannot honour, by name.
    fn local_only_setting(&self) -> Option<&'static str> {
        if self.trusted_user_ca_keys.is_some() {
            Some("TrustedUserCAKeys")
        } else if self.authorized_principals.is_some() {
            Some("AuthorizedPrincipalsFile")
        } else if self.authorized_principals_command.is_some() {
            Some("AuthorizedPrincipalsCommand")
        } else if self.max_startups.is_some() {
            Some("MaxStartups")
        } else if self.session_path.is_some() {
            Some("SetEnv PATH")
        } else {
            None
        }
    }
}

/// The account a local, non-root fixture sshd authenticates: the current user
/// (`id -un`, read once). `None` when it cannot be read. The name goes only into scratch
/// files (principals files, `AuthorizedPrincipalsCommandUser`), never into a client's
/// command line.
#[must_use]
pub fn current_account() -> Option<String> {
    static ACCOUNT: OnceLock<Option<String>> = OnceLock::new();
    ACCOUNT
        .get_or_init(|| {
            let id = find_program("id")?;
            let out = Command::new(id)
                .arg("-un")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .ok()?;
            let name = String::from_utf8(out.stdout).ok()?.trim().to_owned();
            (out.status.success() && is_plain_account(&name)).then_some(name)
        })
        .clone()
}

/// No fixture sshd can run on this host (m02-plan U7): the harness falls back to the
/// Docker fixtures. The reason names no path or user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshdUnavailable {
    /// Why.
    pub reason: String,
}

impl fmt::Display for SshdUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture sshd unavailable: {}", self.reason)
    }
}

impl std::error::Error for SshdUnavailable {}

fn unavailable(reason: impl Into<String>) -> SshdUnavailable {
    SshdUnavailable {
        reason: reason.into(),
    }
}

/// One `Accepted publickey` line from the server log, without the user name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AcceptedKey {
    /// `ED25519`, `RSA`, …
    pub key_type: String,
    /// `SHA256:…`.
    pub fingerprint: String,
}

/// ⟨M03⟩ One `Accepted publickey … ssh2: <TYPE>-CERT <FP> ID <key id> (serial <n>) CA
/// <TYPE> <CA FP>` line: the oracle of which certificate (and so which grant)
/// authenticated (ADR-0008 D13 item 6; m03-plan §4.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AcceptedCert {
    /// `ED25519-CERT`, …
    pub key_type: String,
    /// The certified key's `SHA256:…`.
    pub fingerprint: String,
    /// The certificate key ID.
    pub key_id: String,
    /// The certificate serial.
    pub serial: u64,
    /// The signing CA's `SHA256:…`.
    pub ca_fingerprint: String,
}

/// Parse the tail of an `Accepted publickey` line after `ssh2: ` as a certificate.
fn parse_accepted_cert(tail: &str) -> Option<AcceptedCert> {
    let mut f = tail.split_whitespace();
    let key_type = f.next()?.to_owned();
    if !key_type.ends_with("-CERT") {
        return None;
    }
    let fingerprint = f.next()?.to_owned();
    // `ID <key id> (serial <n>) CA <type> <fp>`; the key ID is quoted-free text up to
    // ` (serial `.
    let rest = tail.split_once(" ID ")?.1;
    let (key_id, rest) = rest.split_once(" (serial ")?;
    let (serial, rest) = rest.split_once(')')?;
    let mut ca = rest.split_whitespace();
    if ca.next()? != "CA" {
        return None;
    }
    let _ca_type = ca.next()?;
    Some(AcceptedCert {
        key_type,
        fingerprint,
        key_id: key_id.to_owned(),
        serial: serial.trim().parse().ok()?,
        ca_fingerprint: ca.next()?.to_owned(),
    })
}

/// A running fixture sshd. Stopped by exact PID on [`stop`](Self::stop) or drop (a
/// harness-supplied server is left alone).
#[derive(Debug)]
pub struct LoopbackSshd {
    /// The loopback address.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The known-hosts line: `[127.0.0.1]:<port> ssh-ed25519 <base64>`.
    pub host_key_line: String,
    account: Option<String>,
    log: Option<PathBuf>,
    /// Where this fixture's part of a shared harness log starts (0 for its own log).
    log_start: u64,
    child: Option<Child>,
    /// The shared harness authorized-keys file this fixture wrote (emptied on drop).
    harness_keys: Option<PathBuf>,
    /// ⟨M03⟩ The destination ID a [`TwoHosts`]/[`ThreeHosts`] fixture gave this server.
    destination_id: Option<String>,
    /// ⟨M03⟩ The `AuthorizedKeysFile` (the account form's explicit registry).
    registry: Option<PathBuf>,
    /// ⟨M03⟩ The `TrustedUserCAKeys` file.
    ca_keys: Option<PathBuf>,
    /// ⟨M03⟩ The `AuthorizedPrincipalsFile` directory (`<dir>/%u`).
    principals_dir: Option<PathBuf>,
    /// The harness server's lease (none for a local server). Declared last, so it is
    /// released after the keys file is emptied in `drop`.
    _lease: Option<HarnessLease>,
}

/// `MaxAuthTries` of the harness sshd (tests/native/m02/remote-lib.sh default).
pub const HARNESS_MAX_AUTH_TRIES: u32 = 6;
/// `MaxAuthTries` of the strict harness sshd (`HM_FIXTURE_SSHD_STRICT_*`).
pub const STRICT_MAX_AUTH_TRIES: u32 = 3;
/// How long a fixture waits for another test thread to release a harness server.
const LEASE_WAIT: Duration = Duration::from_secs(600);

/// One harness server's owner: the thread that holds it, if any.
struct HarnessSlot {
    holder: Mutex<Option<ThreadId>>,
    released: Condvar,
}

impl HarnessSlot {
    const fn new() -> HarnessSlot {
        HarnessSlot {
            holder: Mutex::new(None),
            released: Condvar::new(),
        }
    }
}

/// The default and the strict harness server.
static HARNESS_SLOTS: [HarnessSlot; 2] = [HarnessSlot::new(), HarnessSlot::new()];

/// A held harness server; released (and a waiter woken) on drop.
struct HarnessLease {
    slot: &'static HarnessSlot,
}

impl fmt::Debug for HarnessLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HarnessLease")
    }
}

impl HarnessLease {
    fn acquire(
        slot: &'static HarnessSlot,
        wait: Duration,
    ) -> Result<HarnessLease, SshdUnavailable> {
        let me = thread::current().id();
        let deadline = Instant::now() + wait;
        let mut holder = slot.holder.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match *holder {
                None => {
                    *holder = Some(me);
                    return Ok(HarnessLease { slot });
                }
                Some(t) if t == me => {
                    return Err(unavailable(
                        "this thread already holds this harness sshd; a second fixture would \
                         replace its authorized keys",
                    ));
                }
                Some(_) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(unavailable(format!(
                            "the harness sshd is still held by another test after {} s",
                            wait.as_secs()
                        )));
                    }
                    holder = slot
                        .released
                        .wait_timeout(holder, deadline - now)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
    }
}

impl Drop for HarnessLease {
    fn drop(&mut self) {
        *self
            .slot
            .holder
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        self.slot.released.notify_all();
    }
}

/// Which harness server a config needs: the environment-variable prefix of its port,
/// host key, authorized keys and log, and its slot.
fn harness_for(config: &SshdConfig) -> Result<(&'static str, usize), SshdUnavailable> {
    if let Some(setting) = config.local_only_setting() {
        return Err(unavailable(format!(
            "the harness sshd cannot honour {setting} (M03 fixtures need a local sshd)"
        )));
    }
    if !config.log_level_verbose {
        return Err(unavailable(
            "the harness sshd logs at VERBOSE only, so LogLevel INFO cannot be honoured",
        ));
    }
    match config.max_auth_tries {
        HARNESS_MAX_AUTH_TRIES => Ok(("HM_FIXTURE_SSHD_", 0)),
        STRICT_MAX_AUTH_TRIES => Ok(("HM_FIXTURE_SSHD_STRICT_", 1)),
        n => Err(unavailable(format!(
            "the harness sshds serve MaxAuthTries {HARNESS_MAX_AUTH_TRIES} and \
             {STRICT_MAX_AUTH_TRIES} only, not {n}"
        ))),
    }
}

/// A user name `User` can carry unquoted: ASCII letters, digits, `.`, `_` and `-`, not
/// starting with `-`, at most 64 bytes.
fn is_plain_account(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl LoopbackSshd {
    /// Start a fixture sshd in `scratch` (or adopt the harness's; see the module
    /// documentation).
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn start(scratch: &Scratch, config: SshdConfig) -> Result<LoopbackSshd, SshdUnavailable> {
        if std::env::var_os("HM_FIXTURE_SSHD_PORT").is_some() {
            return LoopbackSshd::from_harness(scratch, &config);
        }
        if cfg!(unix) {
            LoopbackSshd::start_local(scratch, &config)
        } else {
            Err(unavailable(
                "no harness sshd (HM_FIXTURE_SSHD_HOST, _PORT, _HOST_KEY) on this platform",
            ))
        }
    }

    fn from_harness(
        scratch: &Scratch,
        config: &SshdConfig,
    ) -> Result<LoopbackSshd, SshdUnavailable> {
        let (prefix, slot) = harness_for(config)?;
        let var = |k: &str| std::env::var(k).map_err(|_| unavailable(format!("{k} is not set")));
        let host = var("HM_FIXTURE_SSHD_HOST")?;
        if !matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost") {
            return Err(unavailable(
                "HM_FIXTURE_SSHD_HOST is not a loopback address",
            ));
        }
        let port_var = format!("{prefix}PORT");
        let port: u16 = var(&port_var)?
            .parse()
            .map_err(|_| unavailable(format!("{port_var} is not a port")))?;
        let key_var = format!("{prefix}HOST_KEY");
        let key = var(&key_var)?;
        let mut fields = key.split_whitespace();
        let (Some(kind), Some(b64)) = (fields.next(), fields.next()) else {
            return Err(unavailable(format!("{key_var} is not a public key line")));
        };
        let account = match std::env::var("HM_FIXTURE_SSHD_USER") {
            Ok(name) if is_plain_account(&name) => Some(name),
            Ok(_) => {
                return Err(unavailable(
                    "HM_FIXTURE_SSHD_USER is not a plain account name",
                ));
            }
            Err(_) => None,
        };
        let keys_var = format!("{prefix}AUTHORIZED_KEYS");
        let keys_file = std::env::var_os(&keys_var).map(PathBuf::from);
        if keys_file.is_none() && (!config.authorized.is_empty() || config.registry_seed.is_some())
        {
            return Err(unavailable(format!("{keys_var} is not set")));
        }
        let lease = HarnessLease::acquire(&HARNESS_SLOTS[slot], LEASE_WAIT)?;
        if let Some(path) = &keys_file {
            fs::write(path, authorized_keys_text(config))
                .map_err(|_| unavailable("cannot write the harness authorized-keys file"))?;
        }
        let log = std::env::var_os(format!("{prefix}LOG")).map(PathBuf::from);
        let log_start = log
            .as_ref()
            .and_then(|p| fs::metadata(p).ok())
            .map_or(0, |m| m.len());
        if let Some(name) = &account {
            scratch.set_fixture_account(name);
        }
        Ok(LoopbackSshd {
            host_key_line: format!("[{host}]:{port} {kind} {b64}"),
            host,
            port,
            account,
            log,
            log_start,
            child: None,
            registry: keys_file.clone(),
            harness_keys: keys_file,
            destination_id: None,
            ca_keys: None,
            principals_dir: None,
            _lease: Some(lease),
        })
    }

    fn start_local(
        scratch: &Scratch,
        config: &SshdConfig,
    ) -> Result<LoopbackSshd, SshdUnavailable> {
        let program = find_program("sshd").ok_or_else(|| unavailable("sshd is not installed"))?;
        let io_err = |what: &str| {
            let what = what.to_owned();
            move |e: io::Error| unavailable(format!("{what}: {:?}", e.kind()))
        };
        let dir = scratch
            .subdir("sshd")
            .map_err(io_err("scratch directory"))?;
        let host_key = FixtureKey::generate();
        let host_key_file = dir.join("host_ed25519");
        host_key
            .write_private(&host_key_file)
            .map_err(io_err("host key"))?;
        let authorized = dir.join("authorized_keys");
        fs::write(&authorized, authorized_keys_text(config)).map_err(io_err("authorized keys"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&authorized, fs::Permissions::from_mode(0o600))
                .map_err(io_err("authorized keys"))?;
        }
        let principals_dir = match &config.authorized_principals {
            Some(map) => {
                let pdir = dir.join("principals");
                fs::create_dir(&pdir).map_err(io_err("principals directory"))?;
                for (account, principals) in map {
                    if !is_plain_account(account) {
                        return Err(unavailable("a principals account is not a plain name"));
                    }
                    let text: String = principals.iter().map(|p| format!("{p}\n")).collect();
                    fs::write(pdir.join(account), text).map_err(io_err("principals file"))?;
                }
                Some(pdir)
            }
            None => None,
        };
        let command_user = match config.authorized_principals_command {
            Some(_) => Some(current_account().ok_or_else(|| {
                unavailable("AuthorizedPrincipalsCommandUser: the current account is unknown")
            })?),
            None => None,
        };
        let extras = Extras {
            principals_dir: principals_dir.as_deref(),
            command_user: command_user.as_deref(),
        };
        let config_file = dir.join("sshd_config");
        let log = dir.join("sshd.log");

        let mut last = String::from("not started");
        for _attempt in 0..5 {
            let port = pick_loopback_port().map_err(io_err("port"))?;
            let mut penalties = true;
            let mut accepted = false;
            for _ in 0..2 {
                let text = sshd_config_text(
                    port,
                    &host_key_file,
                    &authorized,
                    config,
                    penalties,
                    &extras,
                );
                fs::write(&config_file, text).map_err(io_err("sshd_config"))?;
                let status = Command::new(&program)
                    .arg("-t")
                    .arg("-f")
                    .arg(&config_file)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(io_err("sshd -t"))?;
                if status.success() {
                    accepted = true;
                    break;
                }
                // Servers before OpenSSH 9.8 do not know PerSourcePenalties.
                penalties = false;
            }
            if !accepted {
                return Err(unavailable("sshd -t rejected the fixture configuration"));
            }
            let _ = fs::remove_file(&log);
            let mut child = Command::new(&program)
                .arg("-D")
                .arg("-f")
                .arg(&config_file)
                .arg("-E")
                .arg(&log)
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(io_err("spawn sshd"))?;
            let ready = format!("Server listening on {LOOPBACK} port {port}.");
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                if fs::read_to_string(&log).is_ok_and(|t| t.contains(&ready)) {
                    return Ok(LoopbackSshd {
                        host: LOOPBACK.to_owned(),
                        port,
                        host_key_line: format!(
                            "[{LOOPBACK}]:{port} {}",
                            host_key.public_line_without_comment()
                        ),
                        account: None,
                        log: Some(log),
                        log_start: 0,
                        child: Some(child),
                        harness_keys: None,
                        destination_id: None,
                        registry: Some(authorized),
                        ca_keys: config.trusted_user_ca_keys.clone(),
                        principals_dir,
                        _lease: None,
                    });
                }
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let text = fs::read_to_string(&log).unwrap_or_default();
                        last = if text.contains("Address already in use") {
                            "port taken".to_owned()
                        } else {
                            format!("sshd exited before listening: {status}")
                        };
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => return Err(unavailable(format!("wait: {:?}", e.kind()))),
                }
                if Instant::now() >= end {
                    stop_child(&mut child);
                    return Err(unavailable("sshd did not report listening within 10 s"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if last != "port taken" {
                break;
            }
        }
        Err(unavailable(last))
    }

    /// The server log from byte `from` on (empty when there is no log). Bytes are read
    /// raw, so an offset inside a character never fails the read.
    fn log_text_from(&self, from: u64) -> String {
        let Some(path) = &self.log else {
            return String::new();
        };
        let mut bytes = Vec::new();
        let read = fs::File::open(path).and_then(|mut f| {
            f.seek(SeekFrom::Start(from))?;
            f.read_to_end(&mut bytes)
        });
        if read.is_err() {
            return String::new();
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// The account a client logs in as: `HM_FIXTURE_SSHD_USER` for a harness server that
    /// names one, `None` when the server authenticates the current account (a local
    /// server, or a harness that names none), so a client sets no `User`.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Every `Accepted publickey … ssh2: <TYPE> <FP>` in the server log, in order (empty
    /// when the harness supplies no log). For a shared harness log, only what was
    /// logged after this fixture started.
    #[must_use]
    pub fn accepted_log(&self) -> Vec<AcceptedKey> {
        self.publickey_log("Accepted publickey for ")
    }

    /// Every `Failed publickey … ssh2: <TYPE> <FP>` in the server log, in order: each key
    /// the server refused, so its count shows how many attempts `MaxAuthTries` allowed.
    /// Read like [`accepted_log`](Self::accepted_log).
    #[must_use]
    pub fn failed_publickey_log(&self) -> Vec<AcceptedKey> {
        self.publickey_log("Failed publickey for ")
    }

    /// ⟨M03⟩ Every accepted **certificate** in the server log, in order (read like
    /// [`accepted_log`](Self::accepted_log)): its key ID, serial and CA. The key ID says
    /// which grant authenticated (m03-plan §4.4).
    #[must_use]
    pub fn accepted_certificates(&self) -> Vec<AcceptedCert> {
        self.log_text_from(self.log_start)
            .lines()
            .filter(|l| l.contains("Accepted publickey for "))
            .filter_map(|l| parse_accepted_cert(&l[l.find("ssh2: ")? + "ssh2: ".len()..]))
            .collect()
    }

    /// ⟨M03⟩ The key IDs of [`accepted_certificates`](Self::accepted_certificates).
    #[must_use]
    pub fn accepted_key_ids(&self) -> Vec<String> {
        self.accepted_certificates()
            .into_iter()
            .map(|c| c.key_id)
            .collect()
    }

    /// ⟨M03⟩ Every log line (from where this fixture started) containing `needle`, for
    /// the transport-failure oracles of [`Faults`] (`drop connection`, …).
    #[must_use]
    pub fn log_lines_containing(&self, needle: &str) -> Vec<String> {
        self.log_text_from(self.log_start)
            .lines()
            .filter(|l| l.contains(needle))
            .map(str::to_owned)
            .collect()
    }

    /// ⟨M03⟩ The destination ID a [`TwoHosts`]/[`ThreeHosts`] fixture assigned (or
    /// [`set_destination_id`](Self::set_destination_id) set).
    #[must_use]
    pub fn destination_id(&self) -> Option<&str> {
        self.destination_id.as_deref()
    }

    /// ⟨M03⟩ Give this server a destination ID (a plain token).
    pub fn set_destination_id(&mut self, id: &str) {
        self.destination_id = Some(id.to_owned());
    }

    /// ⟨M03⟩ The account a client authenticates as: the harness account, or the
    /// current account for a local server ([`current_account`]).
    #[must_use]
    pub fn login_account(&self) -> Option<String> {
        self.account.clone().or_else(current_account)
    }

    /// ⟨M03⟩ `hm:<destination-id>:<account>`, this server's managed principal (ADR-0008
    /// D5 §6.5 item 2), when it has a destination ID and the account is known.
    #[must_use]
    pub fn managed_principal(&self) -> Option<String> {
        Some(format!(
            "hm:{}:{}",
            self.destination_id.as_deref()?,
            self.login_account()?
        ))
    }

    /// ⟨M03⟩ The `AuthorizedKeysFile`: the account form's explicit registry (a scratch
    /// path for a local server; the harness's keys file for a harness server).
    #[must_use]
    pub fn registry_path(&self) -> Option<&Path> {
        self.registry.as_deref()
    }

    /// ⟨M03⟩ The `TrustedUserCAKeys` file, when configured.
    #[must_use]
    pub fn trusted_ca_keys_path(&self) -> Option<&Path> {
        self.ca_keys.as_deref()
    }

    /// ⟨M03⟩ The principals file of `account` (`AuthorizedPrincipalsFile <dir>/%u`),
    /// when configured.
    #[must_use]
    pub fn principals_path(&self, account: &str) -> Option<PathBuf> {
        if !is_plain_account(account) {
            return None;
        }
        self.principals_dir.as_ref().map(|d| d.join(account))
    }

    /// ⟨M03⟩ As the owner-administrator would: append a CA public line to this server's
    /// `TrustedUserCAKeys` file (system form; scratch only).
    ///
    /// # Errors
    /// The server has no `TrustedUserCAKeys` file, or the write fails.
    pub fn trust_user_ca(&self, ca_public_line: &str) -> io::Result<()> {
        let path = self
            .ca_keys
            .as_ref()
            .ok_or_else(|| io::Error::other("this fixture sshd has no TrustedUserCAKeys"))?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{}", ca_public_line.trim_end())
    }

    /// ⟨M03⟩ As the owner-administrator would: replace `account`'s principals file
    /// (system form; scratch only).
    ///
    /// # Errors
    /// No principals directory, a non-plain account name, or the write fails.
    pub fn set_principals(&self, account: &str, principals: &[&str]) -> io::Result<()> {
        let path = self
            .principals_path(account)
            .ok_or_else(|| io::Error::other("no AuthorizedPrincipalsFile for this account"))?;
        let text: String = principals.iter().map(|p| format!("{p}\n")).collect();
        fs::write(path, text)
    }

    /// ⟨M03⟩ Append one line to the account-form registry (as an administrator or the
    /// enrollment would; scratch only). A missing final newline is added first.
    ///
    /// # Errors
    /// No registry, or the write fails.
    pub fn append_registry_line(&self, line: &str) -> io::Result<()> {
        let path = self
            .registry
            .as_ref()
            .ok_or_else(|| io::Error::other("this fixture sshd has no registry"))?;
        append_line(path, line)
    }

    fn publickey_log(&self, marker: &str) -> Vec<AcceptedKey> {
        self.log_text_from(self.log_start)
            .lines()
            .filter(|l| l.contains(marker))
            .filter_map(|l| {
                let tail = &l[l.find("ssh2: ")? + "ssh2: ".len()..];
                let mut f = tail.split_whitespace();
                Some(AcceptedKey {
                    key_type: f.next()?.to_owned(),
                    fingerprint: f.next()?.to_owned(),
                })
            })
            .collect()
    }

    /// Every address the server reported binding (`Server listening on <addr> port
    /// <port>.`), as `<addr>:<port>`. The whole log: a harness server reported it before
    /// any fixture started.
    #[must_use]
    pub fn listening(&self) -> Vec<String> {
        self.log_text_from(0)
            .lines()
            .filter_map(|l| {
                let rest = &l[l.find("Server listening on ")? + "Server listening on ".len()..];
                let (addr, port) = rest.split_once(" port ")?;
                Some(format!("{addr}:{}", port.trim_end_matches('.')))
            })
            .collect()
    }

    /// The server's PID (none for a harness-supplied server).
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Stop by exact PID (SIGTERM, then kill through the handle).
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            stop_child(&mut child);
        }
    }
}

impl Drop for LoopbackSshd {
    fn drop(&mut self) {
        self.stop();
        // A harness server's keys do not outlive the fixture; the lease (a later
        // field) is released after this.
        if let Some(path) = self.harness_keys.take() {
            let _ = fs::write(path, b"");
        }
    }
}

/// Bind `127.0.0.1:0`, read the port, release it.
///
/// # Errors
/// The bind fails.
pub fn pick_loopback_port() -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    debug_assert!(addr.ip().is_loopback());
    Ok(addr.port())
}

/// Append `line` and a newline to `path`, writing a newline first when the file is
/// non-empty and does not end with one.
fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let existing = fs::read(path).unwrap_or_default();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if existing.last().is_some_and(|&b| b != b'\n') {
        f.write_all(b"\n")?;
    }
    writeln!(f, "{line}")
}

fn authorized_keys_text(config: &SshdConfig) -> Vec<u8> {
    let options = if config.allow_pty {
        "restrict,pty"
    } else {
        "restrict"
    };
    let mut out = config.registry_seed.clone().unwrap_or_default();
    if out.last().is_some_and(|&b| b != b'\n') {
        out.push(b'\n');
    }
    for k in &config.authorized {
        let mut k = k.clone();
        k.set_comment("");
        if let Ok(line) = k.to_openssh() {
            out.extend_from_slice(format!("{options} {}\n", line.trim_end()).as_bytes());
        }
    }
    out
}

/// ⟨M03⟩ An account registry seeded like the M00-T03 `enrollable` fixture
/// (`tests/fixtures/ssh/up.sh`): a comment with UTF-8, a `command=…,no-pty` entry, a
/// blank line, a `from=…` entry, a **foreign** `cert-authority,principals="ops"` entry,
/// a comment, and a trailer comment. Its three keys are generated per call; their
/// private halves are dropped at once, and their comments are plain (`unrelated-<n>`),
/// so the seed never carries a canary.
#[must_use]
pub fn enrollable_like_seed() -> Vec<u8> {
    let unrelated: Vec<String> = (1..=3)
        .map(|n| {
            let key = FixtureKey::generate();
            format!("{} unrelated-{n}", key.public_line_without_comment())
        })
        .collect();
    let mut seed = String::new();
    seed.push_str(
        "# Hand-maintained by the account owner. Do not reorder. (caf\u{e9} \u{fc}\u{f1}\u{ef})\n",
    );
    seed.push_str(&format!(
        "command=\"/bin/echo restricted\",no-pty,no-port-forwarding {}\n",
        unrelated[0]
    ));
    seed.push('\n');
    seed.push_str("# options and CA entry below belong to someone else\n");
    seed.push_str(&format!(
        "from=\"192.0.2.0/24\",no-agent-forwarding {}\n",
        unrelated[1]
    ));
    seed.push_str(&format!(
        "cert-authority,principals=\"ops\" {}\n",
        unrelated[2]
    ));
    seed.push_str("# end of file\n");
    seed.into_bytes()
}

fn config_path(p: &Path) -> String {
    let text = p.to_string_lossy();
    if text
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        ssh_config_quote(&text)
    } else {
        text.into_owned()
    }
}

/// The derived values the M03 settings need in `sshd_config`.
#[derive(Debug, Default)]
struct Extras<'a> {
    principals_dir: Option<&'a Path>,
    command_user: Option<&'a str>,
}

/// A path as an `sshd_config` token that sshd expands (`%` doubled), quoted when needed.
fn token_path(p: &Path) -> String {
    let text = p.to_string_lossy().replace('%', "%%");
    config_path(Path::new(&text))
}

fn sshd_config_text(
    port: u16,
    host_key: &Path,
    authorized: &Path,
    config: &SshdConfig,
    penalties: bool,
    extras: &Extras<'_>,
) -> String {
    let mut text = format!(
        "ListenAddress {LOOPBACK}\n\
         Port {port}\n\
         AddressFamily inet\n\
         HostKey {}\n\
         AuthorizedKeysFile {}\n\
         PidFile none\n\
         StrictModes no\n\
         UsePAM no\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         PubkeyAuthentication yes\n\
         AuthenticationMethods publickey\n\
         PermitRootLogin no\n\
         PermitUserRC no\n\
         PermitUserEnvironment no\n\
         AllowAgentForwarding no\n\
         AllowTcpForwarding no\n\
         X11Forwarding no\n\
         UseDNS no\n\
         MaxAuthTries {}\n\
         LogLevel {}\n\
         Subsystem sftp internal-sftp\n",
        config_path(host_key),
        config_path(authorized),
        config.max_auth_tries,
        if config.log_level_verbose {
            "VERBOSE"
        } else {
            "INFO"
        },
    );
    if penalties {
        text.push_str("PerSourcePenalties no\n");
    }
    if let Some(ca) = &config.trusted_user_ca_keys {
        text.push_str(&format!("TrustedUserCAKeys {}\n", config_path(ca)));
    }
    if let Some(dir) = extras.principals_dir {
        text.push_str(&format!(
            "AuthorizedPrincipalsFile {}/%u\n",
            token_path(dir)
        ));
    }
    if let (Some(script), Some(user)) = (&config.authorized_principals_command, extras.command_user)
    {
        text.push_str(&format!(
            "AuthorizedPrincipalsCommand /bin/sh {} %t %k\nAuthorizedPrincipalsCommandUser {user}\n",
            token_path(script)
        ));
    }
    if let Some(value) = &config.max_startups {
        text.push_str(&format!("MaxStartups {value}\n"));
    }
    if let Some(dir) = &config.session_path {
        text.push_str(&format!(
            "SetEnv {}\n",
            config_path(Path::new(&format!(
                "PATH={}:{STANDARD_PATH}",
                dir.to_string_lossy()
            )))
        ));
    }
    text
}

/// The standard directories after a [`LaggingClock`]'s scratch directory.
const STANDARD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

// --- ⟨M03⟩ multi-host fixtures ------------------------------------------------------------

/// A fresh destination ID for a fixture host: `hm-fx-<8 hex>-<n>` (a plain token).
fn fixture_destination_id(n: usize) -> String {
    format!("hm-fx-{}-{n}", random_hex(4))
}

/// The config of host `n` of a multi-host fixture in `form`: the account form seeds the
/// explicit registry like `enrollable` ([`enrollable_like_seed`]); the system form has
/// an (initially empty) `TrustedUserCAKeys` file and a principals file listing the
/// host's own managed principal, as the owner-administrator would write them.
fn multi_host_config(
    scratch: &Scratch,
    form: EnrollmentForm,
    destination: &str,
) -> Result<SshdConfig, SshdUnavailable> {
    match form {
        EnrollmentForm::Account => Ok(SshdConfig {
            registry_seed: Some(enrollable_like_seed()),
            ..SshdConfig::default()
        }),
        EnrollmentForm::System => {
            let account =
                current_account().ok_or_else(|| unavailable("the current account is unknown"))?;
            let dir = scratch
                .subdir("ca-keys")
                .map_err(|e| unavailable(format!("scratch: {:?}", e.kind())))?;
            let ca_keys = dir.join("trusted_user_ca_keys");
            fs::write(&ca_keys, b"").map_err(|e| unavailable(format!("{:?}", e.kind())))?;
            let mut principals = BTreeMap::new();
            principals.insert(account.clone(), vec![format!("hm:{destination}:{account}")]);
            Ok(SshdConfig {
                trusted_user_ca_keys: Some(ca_keys),
                authorized_principals: Some(principals),
                ..SshdConfig::default()
            })
        }
        _ => Err(unavailable("an enrollment form this fixture does not know")),
    }
}

fn start_host(
    scratch: &Scratch,
    form: EnrollmentForm,
    n: usize,
) -> Result<LoopbackSshd, SshdUnavailable> {
    let destination = fixture_destination_id(n);
    let config = multi_host_config(scratch, form, &destination)?;
    let mut sshd = LoopbackSshd::start(scratch, config)?;
    sshd.set_destination_id(&destination);
    Ok(sshd)
}

/// Two loopback hosts with distinct destination IDs (ADR-0008 D13 item 2; A10 on two
/// hosts). See [`multi_host_config`] for what each form sets up.
#[derive(Debug)]
pub struct TwoHosts;

impl TwoHosts {
    /// Start two hosts in `form`, each with its own destination ID
    /// ([`LoopbackSshd::destination_id`]) and so its own managed principal
    /// ([`LoopbackSshd::managed_principal`]).
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn start(
        scratch: &Scratch,
        form: EnrollmentForm,
    ) -> Result<(LoopbackSshd, LoopbackSshd), SshdUnavailable> {
        let a = start_host(scratch, form, 1)?;
        let b = start_host(scratch, form, 2)?;
        Ok((a, b))
    }
}

/// Three loopback hosts with disjoint pairs, for the lock procedure (m03-plan §4.4;
/// ADR-0008 §17.1 item 17): each grant gets its own host, and the key ID in each host's
/// log says which grant authenticated.
#[derive(Debug)]
pub struct ThreeHosts {
    /// The hosts, in order (host 1 for grant C, 2 for R, 3 for N in §4.4).
    pub hosts: [LoopbackSshd; 3],
}

impl ThreeHosts {
    /// Start three hosts in `form` with distinct destination IDs.
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn start(scratch: &Scratch, form: EnrollmentForm) -> Result<ThreeHosts, SshdUnavailable> {
        Ok(ThreeHosts {
            hosts: [
                start_host(scratch, form, 1)?,
                start_host(scratch, form, 2)?,
                start_host(scratch, form, 3)?,
            ],
        })
    }

    /// The accepted certificate key IDs of each host's log, in host order.
    #[must_use]
    pub fn accepted_key_ids(&self) -> [Vec<String>; 3] {
        [
            self.hosts[0].accepted_key_ids(),
            self.hosts[1].accepted_key_ids(),
            self.hosts[2].accepted_key_ids(),
        ]
    }
}

// --- ⟨M03⟩ faults ---------------------------------------------------------------------------

/// Which transport failure a [`Faults`] proxy produces for every connection after the
/// first (ADR-0008 §17.1 item 3; the negative verification's inconclusive cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultKind {
    /// When connection 1 ends, the sshd is stopped by its exact PID; later connections
    /// reach the proxy, whose upstream connect is refused, so they close before the
    /// version exchange.
    StopBetweenAttempts,
    /// When connection 1 ends, the proxy's listening socket is closed: later connects
    /// are refused (the sshd keeps running).
    ClosePortBetweenAttempts,
    /// `MaxStartups 1:100:1`; when connection 1 ends, an unauthenticated connection is
    /// opened to the sshd and held, so sshd drops later connections.
    MaxStartupsBetweenAttempts,
    /// `MaxStartups 1:100:1`; when connection 2 arrives (during the negative), the held
    /// unauthenticated connection is opened first, so sshd drops it.
    MaxStartupsDuringNegative,
    /// Later connections get the server's version line and then a TCP reset (the proxy
    /// closes the client socket with unread data).
    ResetAfterVersionExchange,
}

impl FaultKind {
    /// Every kind.
    pub const ALL: [FaultKind; 5] = [
        FaultKind::StopBetweenAttempts,
        FaultKind::ClosePortBetweenAttempts,
        FaultKind::MaxStartupsBetweenAttempts,
        FaultKind::MaxStartupsDuringNegative,
        FaultKind::ResetAfterVersionExchange,
    ];

    fn max_startups(self) -> bool {
        matches!(
            self,
            FaultKind::MaxStartupsBetweenAttempts | FaultKind::MaxStartupsDuringNegative
        )
    }
}

#[derive(Debug, Default)]
struct FaultState {
    connections: AtomicUsize,
    applied: AtomicBool,
    stop: AtomicBool,
    held: Mutex<Vec<TcpStream>>,
}

/// A loopback fault proxy in front of a fixture sshd: connection 1 (the positive
/// attempt) is forwarded unchanged; the fault is applied deterministically, before
/// connection 1's close reaches the client (or, for
/// [`FaultKind::MaxStartupsDuringNegative`], before connection 2 is forwarded). The
/// client's destination is the **proxy's** port ([`Faults::port`],
/// [`Faults::host_key_line`]). Stopped (threads, held connections, sshd) on drop.
pub struct Faults {
    kind: FaultKind,
    port: u16,
    host_key_line: String,
    sshd: Arc<Mutex<LoopbackSshd>>,
    state: Arc<FaultState>,
    listener: Arc<Mutex<Option<TcpListener>>>,
    accept: Option<JoinHandle<()>>,
}

impl fmt::Debug for Faults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Faults")
            .field("kind", &self.kind)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Faults {
    /// [`FaultKind::StopBetweenAttempts`].
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn stop_between_attempts(
        scratch: &Scratch,
        config: SshdConfig,
    ) -> Result<Faults, SshdUnavailable> {
        Faults::start(scratch, config, FaultKind::StopBetweenAttempts)
    }

    /// [`FaultKind::ClosePortBetweenAttempts`].
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn close_port_between_attempts(
        scratch: &Scratch,
        config: SshdConfig,
    ) -> Result<Faults, SshdUnavailable> {
        Faults::start(scratch, config, FaultKind::ClosePortBetweenAttempts)
    }

    /// `MaxStartups 1:100:1` with a held unauthenticated connection, opened between the
    /// attempts (`during_negative: false`) or as the negative connects (`true`).
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn max_startups(
        scratch: &Scratch,
        config: SshdConfig,
        during_negative: bool,
    ) -> Result<Faults, SshdUnavailable> {
        let kind = if during_negative {
            FaultKind::MaxStartupsDuringNegative
        } else {
            FaultKind::MaxStartupsBetweenAttempts
        };
        Faults::start(scratch, config, kind)
    }

    /// [`FaultKind::ResetAfterVersionExchange`].
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn reset_after_version_exchange(
        scratch: &Scratch,
        config: SshdConfig,
    ) -> Result<Faults, SshdUnavailable> {
        Faults::start(scratch, config, FaultKind::ResetAfterVersionExchange)
    }

    /// Start a local fixture sshd (`MaxStartups 1:100:1` for the MaxStartups kinds) and
    /// the proxy on `127.0.0.1:<ephemeral>`.
    ///
    /// # Errors
    /// [`SshdUnavailable`] (a harness server cannot sit behind the proxy's stop and
    /// MaxStartups faults, so they need a local sshd).
    pub fn start(
        scratch: &Scratch,
        mut config: SshdConfig,
        kind: FaultKind,
    ) -> Result<Faults, SshdUnavailable> {
        if kind.max_startups() {
            config.max_startups = Some("1:100:1".to_owned());
        }
        if std::env::var_os("HM_FIXTURE_SSHD_PORT").is_some() {
            return Err(unavailable(
                "the fault proxy needs a local fixture sshd (it stops it or sets MaxStartups)",
            ));
        }
        let sshd = LoopbackSshd::start(scratch, config)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| unavailable(format!("proxy bind: {:?}", e.kind())))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| unavailable(format!("proxy: {:?}", e.kind())))?;
        let port = listener
            .local_addr()
            .map_err(|e| unavailable(format!("proxy: {:?}", e.kind())))?
            .port();
        let key = sshd
            .host_key_line
            .split_once(' ')
            .map(|(_, k)| k.to_owned())
            .unwrap_or_default();
        let upstream = sshd.port;
        let sshd = Arc::new(Mutex::new(sshd));
        let state = Arc::new(FaultState::default());
        let listener = Arc::new(Mutex::new(Some(listener)));
        let accept = {
            let (sshd, state, listener) =
                (Arc::clone(&sshd), Arc::clone(&state), Arc::clone(&listener));
            thread::spawn(move || accept_loop(kind, upstream, &sshd, &state, &listener))
        };
        Ok(Faults {
            kind,
            port,
            host_key_line: format!("[{LOOPBACK}]:{port} {key}"),
            sshd,
            state,
            listener,
            accept: Some(accept),
        })
    }

    /// The fault.
    #[must_use]
    pub fn kind(&self) -> FaultKind {
        self.kind
    }

    /// The destination port clients use (the proxy's).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The known-hosts line for the proxy's address: `[127.0.0.1]:<proxy port> <key>`.
    #[must_use]
    pub fn host_key_line(&self) -> &str {
        &self.host_key_line
    }

    /// The sshd behind the proxy (for its log oracles).
    pub fn sshd(&self) -> MutexGuard<'_, LoopbackSshd> {
        self.sshd.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Connections the proxy accepted so far.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// Whether the fault has been applied.
    #[must_use]
    pub fn applied(&self) -> bool {
        self.state.applied.load(Ordering::SeqCst)
    }
}

impl Drop for Faults {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
        self.listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.state
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.sshd().stop();
    }
}

/// Apply `kind`'s between-attempts fault (once).
fn apply_fault(
    kind: FaultKind,
    upstream: u16,
    sshd: &Mutex<LoopbackSshd>,
    state: &FaultState,
    listener: &Mutex<Option<TcpListener>>,
) {
    if state.applied.swap(true, Ordering::SeqCst) {
        return;
    }
    match kind {
        FaultKind::StopBetweenAttempts => {
            sshd.lock().unwrap_or_else(PoisonError::into_inner).stop();
        }
        FaultKind::ClosePortBetweenAttempts => {
            listener
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
        }
        FaultKind::MaxStartupsBetweenAttempts | FaultKind::MaxStartupsDuringNegative => {
            hold_unauthenticated(upstream, state);
        }
        FaultKind::ResetAfterVersionExchange => {}
    }
}

/// Open a connection to the sshd and read its version line, so sshd counts it as an
/// unauthenticated startup; keep it open.
fn hold_unauthenticated(upstream: u16, state: &FaultState) {
    if let Ok(mut s) = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream)) {
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while let Ok(1) = s.read(&mut b) {
            line.push(b[0]);
            if b[0] == b'\n' || line.len() > 255 {
                break;
            }
        }
        state
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(s);
    }
}

fn accept_loop(
    kind: FaultKind,
    upstream: u16,
    sshd: &Arc<Mutex<LoopbackSshd>>,
    state: &Arc<FaultState>,
    listener: &Arc<Mutex<Option<TcpListener>>>,
) {
    let mut workers = Vec::new();
    while !state.stop.load(Ordering::SeqCst) {
        let accepted = {
            let guard = listener.lock().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(l) => l.accept().ok(),
                None => None,
            }
        };
        let Some((client, _)) = accepted else {
            thread::sleep(Duration::from_millis(2));
            continue;
        };
        let _ = client.set_nonblocking(false);
        let n = state.connections.fetch_add(1, Ordering::SeqCst) + 1;
        let (sshd, state, listener) = (Arc::clone(sshd), Arc::clone(state), Arc::clone(listener));
        workers.push(thread::spawn(move || {
            serve(kind, n, client, upstream, &sshd, &state, &listener);
        }));
    }
    for w in workers {
        let _ = w.join();
    }
}

fn serve(
    kind: FaultKind,
    n: usize,
    client: TcpStream,
    upstream: u16,
    sshd: &Mutex<LoopbackSshd>,
    state: &FaultState,
    listener: &Mutex<Option<TcpListener>>,
) {
    if n >= 2 {
        if kind == FaultKind::MaxStartupsDuringNegative {
            apply_fault(kind, upstream, sshd, state, listener);
        }
        if kind == FaultKind::ResetAfterVersionExchange {
            reset_after_version(client, upstream, state);
            return;
        }
    }
    let Ok(server) = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream)) else {
        // Upstream refused (the sshd was stopped): close the client at once.
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let first = n == 1 && kind != FaultKind::MaxStartupsDuringNegative;
    let (Ok(c2), Ok(s2)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    // Each direction copies until EOF; the first EOF of connection 1 applies the fault
    // before the close is passed on, so the client cannot start the next attempt first.
    let fault = |state: &FaultState| {
        if first {
            apply_fault(kind, upstream, sshd, state, listener);
        }
    };
    thread::scope(|s| {
        s.spawn(|| {
            pump(&client, &s2, state);
            fault(state);
            let _ = s2.shutdown(Shutdown::Write);
        });
        s.spawn(|| {
            pump(&server, &c2, state);
            fault(state);
            let _ = c2.shutdown(Shutdown::Write);
        });
    });
}

fn pump(mut from: &TcpStream, mut to: &TcpStream, state: &FaultState) {
    let _ = from.set_read_timeout(Some(Duration::from_millis(200)));
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return,
            Ok(k) => {
                if to.write_all(&buf[..k]).is_err() {
                    return;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if state.stop.load(Ordering::SeqCst) {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Pass the server's version line to the client, wait for the client's version line
/// and further data (its key exchange), then drop the client socket with that data
/// unread: the kernel answers with a reset.
fn reset_after_version(mut client: TcpStream, upstream: u16, state: &FaultState) {
    state.applied.store(true, Ordering::SeqCst);
    let Ok(mut server) = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream)) else {
        return;
    };
    let _ = server.set_read_timeout(Some(Duration::from_secs(5)));
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while let Ok(1) = server.read(&mut b) {
        line.push(b[0]);
        if b[0] == b'\n' || line.len() > 255 {
            break;
        }
    }
    if client.write_all(&line).is_err() {
        return;
    }
    // Wait until the client has sent more than its version line, without reading it.
    let _ = client.set_read_timeout(Some(Duration::from_millis(50)));
    let end = Instant::now() + Duration::from_secs(5);
    let mut peek = [0u8; 2048];
    while Instant::now() < end {
        match client.peek(&mut peek) {
            Ok(k)
                if k > 0
                    && peek[..k].contains(&b'\n')
                    && k > peek.iter().position(|&c| c == b'\n').unwrap_or(k) + 1 =>
            {
                break;
            }
            Ok(0) => return,
            _ => {}
        }
    }
    drop(server);
    drop(client);
}

// --- ⟨M03⟩ the lagging clock --------------------------------------------------------------------

/// A destination whose sessions see an `awk` that reports the time minus `lag`
/// (ADR-0008 §17.1 item 10, D13 item 2): the fixture sshd's own `sshd_config` sets
/// `SetEnv PATH=<scratch dir>:/usr/bin:/bin:/usr/sbin:/sbin`, and the scratch directory's
/// `awk` runs the real `awk` and rewrites each `HM1 now=<T>` line to `HM1 now=<T - lag>`
/// (the verifier's reading, D5 §6.5 item 4). The directory's `date` reports the lagged
/// time for `date -u +<format>` (the enrollment scripts' `remote_now` reading,
/// `heimdall_registry::script::REMOTE_CLOCK_COMMAND`) and passes every other use to the
/// real `date`. **No clock is changed**: sshd validates certificates with the real
/// clock. Limitation: a login shell whose startup files reset `PATH` defeats it (the
/// test checks it took effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaggingClock {
    /// The lag.
    pub lag: Duration,
    dir: PathBuf,
}

impl LaggingClock {
    /// Write the wrapper into a fresh scratch directory.
    ///
    /// # Errors
    /// `awk` is not found, or a write failed.
    pub fn new(scratch: &Scratch, lag: Duration) -> io::Result<LaggingClock> {
        let real = find_program("awk").ok_or_else(|| io::Error::other("awk not found"))?;
        let dir = scratch.subdir("lag")?;
        let real = real.to_string_lossy().replace('\'', "");
        let text = format!(
            "#!/bin/sh\n\
             # Heimdall fixture LaggingClock (m03-plan U11): the real awk, with every\n\
             # `HM1 now=<T>` line reported as T minus {lag} s. No clock is changed.\n\
             '{real}' \"$@\" | '{real}' -v lag={lag} '{{ if (index($0, \"HM1 now=\") == 1) print \"HM1 now=\" (substr($0, 9) - lag); else print }}'\n",
            lag = lag.as_secs()
        );
        write_script(&dir.join("awk"), &text)?;
        let date = find_program("date").ok_or_else(|| io::Error::other("date not found"))?;
        let date = date.to_string_lossy().replace('\'', "");
        // BSD `date -r <secs>` or GNU `date -d @<secs>`, whichever this host's has.
        let bsd = Command::new(&date)
            .args(["-u", "-r", "0", "+%Y"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|o| o.status.success() && o.stdout.starts_with(b"1970"));
        let at = if bsd { "-r \"$hm_t\"" } else { "-d \"@$hm_t\"" };
        let date_text = format!(
            "#!/bin/sh\n\
             # Heimdall fixture LaggingClock (m03-plan U11): `date -u +<format>` reports the\n\
             # time minus {lag} s; every other use is the real date. No clock is changed.\n\
             if [ \"$#\" -eq 2 ] && [ \"$1\" = -u ]; then\n\
             \x20 case \"$2\" in\n\
             \x20   +*) hm_t=$(( $('{date}' -u +%s) - {lag} )); exec '{date}' -u {at} \"$2\" ;;\n\
             \x20 esac\n\
             fi\n\
             exec '{date}' \"$@\"\n",
            lag = lag.as_secs()
        );
        write_script(&dir.join("date"), &date_text)?;
        Ok(LaggingClock { lag, dir })
    }

    /// The scratch directory placed first on the sessions' `PATH`.
    #[must_use]
    pub fn path_dir(&self) -> &Path {
        &self.dir
    }

    /// Start a fixture sshd whose sessions use this clock (`config.session_path` set).
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn start_sshd(
        &self,
        scratch: &Scratch,
        config: SshdConfig,
    ) -> Result<LoopbackSshd, SshdUnavailable> {
        LoopbackSshd::start(
            scratch,
            SshdConfig {
                session_path: Some(self.dir.clone()),
                ..config
            },
        )
    }
}

/// The remote clock reading command of ADR-0008 D5 §6.5 item 4 (a fixed literal).
pub const REMOTE_CLOCK_COMMAND: &str = "awk 'BEGIN { srand(); print \"HM1 now=\" srand() }'";

// --- ⟨M03⟩ wrong-key destinations ------------------------------------------------------------------

/// How a client inherits trust in the wrong host key (ADR-0008 D13 item 2 ⟨r3⟩).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WrongKeyVariant {
    /// A `KnownHostsCommand` in the scratch user configuration prints the served key.
    KnownHostsCommand,
    /// The scratch user known-hosts file (the isolation `UserKnownHostsFile`) lists it.
    UserKnownHostsFile,
    /// The scratch global known-hosts file (the isolation `GlobalKnownHostsFile`)
    /// lists it.
    GlobalKnownHostsFile,
    /// `NoHostAuthenticationForLocalhost yes` in the scratch user configuration.
    NoHostAuthenticationForLocalhost,
}

impl WrongKeyVariant {
    /// Every variant.
    pub const ALL: [WrongKeyVariant; 4] = [
        WrongKeyVariant::KnownHostsCommand,
        WrongKeyVariant::UserKnownHostsFile,
        WrongKeyVariant::GlobalKnownHostsFile,
        WrongKeyVariant::NoHostAuthenticationForLocalhost,
    ];
}

/// A loopback sshd whose host key is **not** the approved one, with the inheritance
/// variants, and a `PATH` fixture program named `none` that records every invocation
/// (Q22: `KnownHostsCommand none` must be a keyword, never a program).
#[derive(Debug)]
pub struct WrongKey {
    /// The server (serving its own per-run host key: the wrong one).
    pub sshd: LoopbackSshd,
    approved: FixtureKey,
    dir: PathBuf,
    none_dir: PathBuf,
    none_log: PathBuf,
}

impl WrongKey {
    /// Start the server and write the fixture programs in scratch.
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn start(scratch: &Scratch, config: SshdConfig) -> Result<WrongKey, SshdUnavailable> {
        let sshd = LoopbackSshd::start(scratch, config)?;
        let io_err = |e: io::Error| unavailable(format!("wrong-key fixture: {:?}", e.kind()));
        let dir = scratch.subdir("wrongkey").map_err(io_err)?;
        let none_dir = dir.join("path");
        fs::create_dir(&none_dir).map_err(io_err)?;
        let none_log = dir.join("none-invocations.log");
        let served = sshd.host_key_line.clone();
        write_script(
            &none_dir.join("none"),
            &format!(
                "#!/bin/sh\n\
                 # Heimdall fixture (Q22): a program named none; it must never run.\n\
                 printf 'none %s\\n' \"$*\" >> '{}'\n\
                 printf '%s\\n' '{served}'\n",
                sh_single(&none_log)
            ),
        )
        .map_err(io_err)?;
        write_script(
            &dir.join("khc"),
            &format!(
                "#!/bin/sh\n\
                 # Heimdall fixture: an inherited KnownHostsCommand printing the wrong key.\n\
                 printf '%s\\n' '{served}'\n"
            ),
        )
        .map_err(io_err)?;
        Ok(WrongKey {
            sshd,
            approved: FixtureKey::generate(),
            dir,
            none_dir,
            none_log,
        })
    }

    /// The **approved** host key (never served): `[127.0.0.1]:<port> ssh-ed25519 …`.
    #[must_use]
    pub fn approved_host_key_line(&self) -> String {
        format!(
            "[{}]:{} {}",
            self.sshd.host,
            self.sshd.port,
            self.approved.public_line_without_comment()
        )
    }

    /// The approved host key.
    #[must_use]
    pub fn approved_public_key(&self) -> &PublicKey {
        self.approved.public()
    }

    /// The served (wrong) host key line.
    #[must_use]
    pub fn served_host_key_line(&self) -> &str {
        &self.sshd.host_key_line
    }

    /// Set up `variant` for `home`: write the served key into the scratch known-hosts
    /// file the variant names, and return the `ssh_config` lines (possibly none) the
    /// alias's block must carry. The caller writes the scratch user configuration.
    ///
    /// # Errors
    /// A write failed.
    pub fn inherit(&self, variant: WrongKeyVariant, home: &ScratchHome) -> io::Result<Vec<String>> {
        match variant {
            WrongKeyVariant::KnownHostsCommand => Ok(vec![format!(
                "KnownHostsCommand {} %H",
                config_path(&self.dir.join("khc"))
            )]),
            WrongKeyVariant::UserKnownHostsFile => {
                append_line(&home.known_hosts, &self.sshd.host_key_line)?;
                Ok(Vec::new())
            }
            WrongKeyVariant::GlobalKnownHostsFile => {
                append_line(&home.global_known_hosts, &self.sshd.host_key_line)?;
                Ok(Vec::new())
            }
            WrongKeyVariant::NoHostAuthenticationForLocalhost => {
                Ok(vec!["NoHostAuthenticationForLocalhost yes".to_owned()])
            }
        }
    }

    /// The directory holding the `none` program (put it first on the client's `PATH`).
    #[must_use]
    pub fn none_program_dir(&self) -> &Path {
        &self.none_dir
    }

    /// How many times the `none` program ran.
    #[must_use]
    pub fn none_invocations(&self) -> usize {
        fs::read_to_string(&self.none_log)
            .map(|t| t.lines().count())
            .unwrap_or(0)
    }
}

/// A path for a single-quoted `sh` word (quotes dropped: scratch paths hold none).
fn sh_single(p: &Path) -> String {
    p.to_string_lossy().replace('\'', "")
}

fn write_script(path: &Path, text: &str) -> io::Result<()> {
    fs::write(path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

// --- ⟨M03⟩ principals_not_enforced ------------------------------------------------------------------

/// The `principals_not_enforced` fixtures (ADR-0008 §17.4 item 11; M-F27).
#[derive(Debug, Clone, Copy)]
pub struct PrincipalsNotEnforced;

/// The verification's negative principal: `hm:verify-negative:<nonce>`.
#[must_use]
pub fn negative_principal(nonce: &str) -> String {
    format!("hm:verify-negative:{nonce}")
}

impl PrincipalsNotEnforced {
    /// The account-form line listing **both** principals: `cert-authority,principals="
    /// <positive>,hm:verify-negative:<nonce>" <ca>`.
    #[must_use]
    pub fn account_line(ca_public_line: &str, positive: &str, nonce: &str) -> String {
        format!(
            "cert-authority,principals=\"{positive},{}\" {}",
            negative_principal(nonce),
            ca_public_line.trim_end()
        )
    }

    /// Wait at `nonce_known` in `hooks` (the verifier reports `nonce=<32 hex>`), append
    /// [`Self::account_line`] to `registry`, then release the verifier. Returns the
    /// nonce. `hooks` must have `nonce_known` armed.
    ///
    /// # Errors
    /// The wait timed out, the arrival carried no valid nonce (the verifier is released
    /// unchanged), or the write failed.
    pub fn write_at_nonce_known(
        hooks: &crate::registry::PauseHooks,
        registry: &Path,
        ca_public_line: &str,
        positive: &str,
    ) -> io::Result<String> {
        let reached = hooks.wait_at(crate::registry::hook::NONCE_KNOWN)?;
        let nonce = reached
            .fields
            .get("nonce")
            .filter(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit()))
            .cloned();
        let written = match &nonce {
            Some(n) => append_line(registry, &Self::account_line(ca_public_line, positive, n)),
            None => Err(io::Error::other("nonce_known carried no 32-hex nonce")),
        };
        hooks.release(crate::registry::hook::NONCE_KNOWN)?;
        written.map(|()| nonce.unwrap_or_default())
    }

    /// The system form's `AuthorizedPrincipalsCommand` script (for
    /// [`SshdConfig::authorized_principals_command`]): run as `/bin/sh <script> %t %k`,
    /// it prints every principal of the presented certificate (read with `ssh-keygen
    /// -L`), so the server accepts whatever principal a certificate names.
    ///
    /// # Errors
    /// `ssh-keygen` is not found, or the write failed.
    pub fn echo_principals_command(scratch: &Scratch) -> io::Result<PathBuf> {
        let keygen =
            find_program("ssh-keygen").ok_or_else(|| io::Error::other("ssh-keygen not found"))?;
        let dir = scratch.subdir("principals-cmd")?;
        let path = dir.join("echo-principals.sh");
        write_script(
            &path,
            &format!(
                "# Heimdall fixture (M-F27): print the presented certificate's principals.\n\
                 printf '%s %s\\n' \"$1\" \"$2\" | '{}' -L -f /dev/stdin | \
                 awk '/^[[:space:]]*Principals:/ {{ p = 1; next }} \
                 /^[[:space:]]*(Critical Options|Extensions):/ {{ p = 0 }} \
                 p && NF {{ print $1 }}'\n",
                sh_single(&keygen)
            ),
        )?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_binds_loopback_only_and_restricts_keys() {
        let key = FixtureKey::generate();
        let cfg = SshdConfig {
            authorized: vec![key.public().clone()],
            allow_pty: true,
            ..SshdConfig::default()
        };
        let text = sshd_config_text(
            2222,
            Path::new("/s/h"),
            Path::new("/s/a"),
            &cfg,
            true,
            &Extras::default(),
        );
        let listen: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("ListenAddress"))
            .collect();
        assert_eq!(listen, ["ListenAddress 127.0.0.1"]);
        assert!(text.contains("PerSourcePenalties no\n"));
        assert!(text.contains("AuthorizedKeysFile /s/a\n"));
        let ak = String::from_utf8(authorized_keys_text(&cfg)).unwrap();
        assert!(ak.starts_with("restrict,pty ssh-ed25519 "));
        assert!(!ak.contains(crate::CANARY_PREFIX));
        assert!(pick_loopback_port().unwrap() > 0);
    }

    #[test]
    fn harness_selection_never_ignores_a_setting() {
        let cfg = |max_auth_tries, log_level_verbose| SshdConfig {
            max_auth_tries,
            log_level_verbose,
            ..SshdConfig::default()
        };
        assert_eq!(
            harness_for(&SshdConfig::default()),
            Ok(("HM_FIXTURE_SSHD_", 0))
        );
        assert_eq!(
            harness_for(&cfg(STRICT_MAX_AUTH_TRIES, true)),
            Ok(("HM_FIXTURE_SSHD_STRICT_", 1))
        );
        for refused in [
            cfg(4, true),
            cfg(1, true),
            cfg(HARNESS_MAX_AUTH_TRIES, false),
        ] {
            assert!(harness_for(&refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn account_names_are_plain_or_refused() {
        for ok in ["wsluser", "a.b_c-d", "U1"] {
            assert!(is_plain_account(ok), "{ok}");
        }
        for bad in [
            "",
            "-oProxyCommand=x",
            "a b",
            "a\nHost *",
            "a\"b",
            "dom\\u",
            "é",
        ] {
            assert!(!is_plain_account(bad), "{bad:?}");
        }
        assert!(!is_plain_account(&"a".repeat(65)));
    }

    #[test]
    fn a_harness_lease_has_one_holder_and_refuses_its_own_thread() {
        static SLOT: HarnessSlot = HarnessSlot::new();
        let lease = HarnessLease::acquire(&SLOT, Duration::from_secs(5)).unwrap();
        // The same thread again: refused at once, never a wait on itself.
        let started = Instant::now();
        assert!(HarnessLease::acquire(&SLOT, Duration::from_secs(30)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        // Another thread waits for the release.
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let got = HarnessLease::acquire(&SLOT, Duration::from_secs(30));
            tx.send(got.is_ok()).unwrap();
            drop(got);
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "held: the other thread waits"
        );
        drop(lease);
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(true));
        waiter.join().unwrap();
        // A bounded wait reports instead of hanging.
        let _held = HarnessLease::acquire(&SLOT, Duration::from_secs(5)).unwrap();
        let other =
            thread::spawn(|| HarnessLease::acquire(&SLOT, Duration::from_millis(200)).is_err());
        assert!(other.join().unwrap());
    }

    #[test]
    fn accepted_log_reads_from_where_the_fixture_started() {
        let scratch = Scratch::new().unwrap();
        let log = scratch.path().join("shared.log");
        let line = |fp: &str| {
            format!("x: Accepted publickey for u from 127.0.0.1 port 1 ssh2: ED25519 {fp}\n")
        };
        fs::write(
            &log,
            format!(
                "Server listening on 127.0.0.1 port 22.\n{}",
                line("SHA256:old")
            ),
        )
        .unwrap();
        let start = fs::metadata(&log).unwrap().len();
        let mut f = fs::OpenOptions::new().append(true).open(&log).unwrap();
        use std::io::Write;
        f.write_all(line("SHA256:new").as_bytes()).unwrap();
        drop(f);
        let sshd = LoopbackSshd {
            host: LOOPBACK.to_owned(),
            port: 22,
            host_key_line: String::new(),
            account: None,
            log: Some(log),
            log_start: start,
            child: None,
            harness_keys: None,
            destination_id: None,
            registry: None,
            ca_keys: None,
            principals_dir: None,
            _lease: None,
        };
        assert_eq!(
            sshd.accepted_log(),
            [AcceptedKey {
                key_type: "ED25519".to_owned(),
                fingerprint: "SHA256:new".to_owned()
            }]
        );
        assert_eq!(sshd.listening(), ["127.0.0.1:22"]);
        assert_eq!(sshd.account(), None);
    }
}
