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

use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use ssh_key::PublicKey;

use crate::agent::{FixtureKey, stop_child};
use crate::home::{Scratch, find_program, ssh_config_quote};

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
}

impl Default for SshdConfig {
    fn default() -> Self {
        SshdConfig {
            authorized: Vec::new(),
            max_auth_tries: 6,
            allow_pty: false,
            log_level_verbose: true,
        }
    }
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
        if keys_file.is_none() && !config.authorized.is_empty() {
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
            harness_keys: keys_file,
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
        let config_file = dir.join("sshd_config");
        let log = dir.join("sshd.log");

        let mut last = String::from("not started");
        for _attempt in 0..5 {
            let port = pick_loopback_port().map_err(io_err("port"))?;
            let mut penalties = true;
            let mut accepted = false;
            for _ in 0..2 {
                let text = sshd_config_text(port, &host_key_file, &authorized, config, penalties);
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

fn authorized_keys_text(config: &SshdConfig) -> String {
    let options = if config.allow_pty {
        "restrict,pty"
    } else {
        "restrict"
    };
    config
        .authorized
        .iter()
        .filter_map(|k| {
            let mut k = k.clone();
            k.set_comment("");
            k.to_openssh()
                .ok()
                .map(|line| format!("{options} {}\n", line.trim_end()))
        })
        .collect()
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

fn sshd_config_text(
    port: u16,
    host_key: &Path,
    authorized: &Path,
    config: &SshdConfig,
    penalties: bool,
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
    text
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
        let text = sshd_config_text(2222, Path::new("/s/h"), Path::new("/s/a"), &cfg, true);
        let listen: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("ListenAddress"))
            .collect();
        assert_eq!(listen, ["ListenAddress 127.0.0.1"]);
        assert!(text.contains("PerSourcePenalties no\n"));
        assert!(text.contains("AuthorizedKeysFile /s/a\n"));
        let ak = authorized_keys_text(&cfg);
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
