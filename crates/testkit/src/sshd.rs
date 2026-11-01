//! The loopback sshd fixture (m02-plan §0, U7 `sshd::LoopbackSshd`; tests/fixtures
//! MANIFEST row 1).
//!
//! On Unix it runs the host's `sshd` as the current, non-root user: `sshd -D -f
//! <scratch config> -E <scratch log>`, `ListenAddress 127.0.0.1` only, an ephemeral port,
//! a per-run Ed25519 host key, `AuthorizedKeysFile` in scratch with `restrict` (plus
//! `pty` when asked), public-key authentication only, `PermitUserRC no` and, where the
//! server knows the option, `PerSourcePenalties no` (MANIFEST row 1). A non-root sshd
//! authenticates only its own account, so clients log in as the current user and no
//! user name appears in any fixture text. Limitation: the session runs the account's
//! login shell in the account's home, as any login to this account would.
//!
//! When the harness supplies `HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY}` (Windows, which
//! runs the fixture sshd in WSL scratch, or the Docker fallback of m02-plan §4), that
//! server is used instead. Per-run authorized keys then go to the file named by
//! `HM_FIXTURE_SSHD_AUTHORIZED_KEYS`; without it a fixture that needs keys is
//! [`SshdUnavailable`]. When no sshd can start, the fixture reports
//! [`SshdUnavailable`] and the harness falls back to the M00-T03 Docker fixtures.

use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
    log: Option<PathBuf>,
    child: Option<Child>,
}

impl LoopbackSshd {
    /// Start a fixture sshd in `scratch` (or adopt the harness's; see the module
    /// documentation).
    ///
    /// # Errors
    /// [`SshdUnavailable`].
    pub fn start(scratch: &Scratch, config: SshdConfig) -> Result<LoopbackSshd, SshdUnavailable> {
        if std::env::var_os("HM_FIXTURE_SSHD_PORT").is_some() {
            return LoopbackSshd::from_harness(&config);
        }
        if cfg!(unix) {
            LoopbackSshd::start_local(scratch, &config)
        } else {
            Err(unavailable(
                "no harness sshd (HM_FIXTURE_SSHD_HOST, _PORT, _HOST_KEY) on this platform",
            ))
        }
    }

    fn from_harness(config: &SshdConfig) -> Result<LoopbackSshd, SshdUnavailable> {
        let var = |k: &str| std::env::var(k).map_err(|_| unavailable(format!("{k} is not set")));
        let host = var("HM_FIXTURE_SSHD_HOST")?;
        if !matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost") {
            return Err(unavailable(
                "HM_FIXTURE_SSHD_HOST is not a loopback address",
            ));
        }
        let port: u16 = var("HM_FIXTURE_SSHD_PORT")?
            .parse()
            .map_err(|_| unavailable("HM_FIXTURE_SSHD_PORT is not a port"))?;
        let key = var("HM_FIXTURE_SSHD_HOST_KEY")?;
        let mut fields = key.split_whitespace();
        let (Some(kind), Some(b64)) = (fields.next(), fields.next()) else {
            return Err(unavailable(
                "HM_FIXTURE_SSHD_HOST_KEY is not a public key line",
            ));
        };
        if !config.authorized.is_empty() {
            let path = var("HM_FIXTURE_SSHD_AUTHORIZED_KEYS")?;
            fs::write(&path, authorized_keys_text(config))
                .map_err(|_| unavailable("cannot write the harness authorized-keys file"))?;
        }
        Ok(LoopbackSshd {
            host_key_line: format!("[{host}]:{port} {kind} {b64}"),
            host,
            port,
            log: std::env::var_os("HM_FIXTURE_SSHD_LOG").map(PathBuf::from),
            child: None,
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
                        log: Some(log),
                        child: Some(child),
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

    fn log_text(&self) -> String {
        self.log
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())
            .unwrap_or_default()
    }

    /// Every `Accepted publickey … ssh2: <TYPE> <FP>` in the server log, in order (empty
    /// when the harness supplies no log).
    #[must_use]
    pub fn accepted_log(&self) -> Vec<AcceptedKey> {
        self.log_text()
            .lines()
            .filter(|l| l.contains("Accepted publickey for "))
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
    /// <port>.`), as `<addr>:<port>`.
    #[must_use]
    pub fn listening(&self) -> Vec<String> {
        self.log_text()
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
}
