//! Local queries: bounded runs of a local tool for a version or a lookup (m02-plan U3,
//! Q4). Each is bounded by [`LOCAL_QUERY_TIMEOUT`] (10 s), runs with stdin null and no
//! shell, and never modifies the environment. `--no-local-exec` turns them off (`LocalQueries::Disabled`).
//!
//! The runner behind them, [`run_contained`], is also the probes' (ADR-0007 §6
//! "Containment"): the child runs in its own process group (Unix, `process_group(0)`)
//! or a kill-on-close job object without breakaway (Windows). When the child exits,
//! or at the timeout, the group is killed with `killpg` while the leader is still an
//! unreaped zombie (`sys::exited_unreaped`), so the group ID cannot have been reused;
//! on Windows the job is closed. A descendant that left the group (`setsid`, a
//! daemonizing double fork) or the job is not contained. Output is read on two
//! threads, each bounded; a reader still blocked after the child is gone (a
//! descendant holding the pipe) is abandoned, not waited for.
//!
//! A child's environment is exactly the [`Env`] snapshot given (nothing from this
//! process is added), or this process's environment when none is given.

use std::ffi::OsString;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use heimdall_contract::doctor::Containment;
use heimdall_sshconf::eval::OpenSshVersion;

use crate::env::Env;

/// The bound on one local query: 10 s. It bounds a hung program, not normal latency.
/// M03 wave 5 r4 (F1): at the earlier 2 s, a `git.exe` start-up under a native Windows
/// test harness's process-spawn load (and antivirus scanning) overran it, so one of two
/// back-to-back previews saw an incomplete Git observation (`git_config_unreadable`) and
/// planned a different digest. A preview and the doctor are not latency-critical.
pub const LOCAL_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes kept from each output stream of a local query.
pub const LOCAL_QUERY_OUTPUT_BYTES: usize = 64 * 1024;

/// How long readers are waited for after the child is gone.
const READER_GRACE: Duration = Duration::from_millis(500);

/// Whether local queries may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalQueries {
    /// Allowed (the default; listed in the report).
    Enabled,
    /// Off (`--no-local-exec`).
    Disabled,
}

/// A local query that did not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LocalQueryError {
    /// Local queries are disabled.
    #[error("local queries disabled")]
    Disabled,
    /// The tool did not answer within the bound.
    #[error("local query timed out")]
    Timeout,
    /// The tool could not be started.
    #[error("local query could not start")]
    Spawn,
    /// The output was not understood.
    #[error("local query output not understood")]
    Unparsed,
}

/// Run `<client> -V` and parse its version (`OpenSSH_10.3p1, …` or
/// `OpenSSH_for_Windows_9.5p2, …`, on stderr or stdout). The process environment is
/// inherited: `-V` reads no configuration.
///
/// # Errors
/// [`LocalQueryError`].
pub fn run_version(client: &Path) -> Result<OpenSshVersion, LocalQueryError> {
    let out = run_contained(&Spec {
        program: client,
        args: vec!["-V".into()],
        env: None,
        cwd: None,
        timeout: LOCAL_QUERY_TIMEOUT,
        max_output: LOCAL_QUERY_OUTPUT_BYTES,
    })
    .map_err(|_| LocalQueryError::Spawn)?;
    if out.timed_out {
        return Err(LocalQueryError::Timeout);
    }
    let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&out.stdout));
    parse_openssh_version(&text).ok_or(LocalQueryError::Unparsed)
}

/// Parse the first `OpenSSH_<major>.<minor>[p<portable>]` (or
/// `OpenSSH_for_Windows_…`) in `text`.
#[must_use]
pub fn parse_openssh_version(text: &str) -> Option<OpenSshVersion> {
    let start = text.find("OpenSSH_")? + "OpenSSH_".len();
    let rest = &text[start..];
    let rest = rest.strip_prefix("for_Windows_").unwrap_or(rest);
    let digits = |s: &str| -> (Option<u16>, usize) {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        (s[..n].parse().ok(), n)
    };
    let (major, n) = digits(rest);
    let rest = rest[n..].strip_prefix('.')?;
    let (minor, n) = digits(rest);
    let rest = &rest[n..];
    let portable = rest.strip_prefix('p').and_then(|r| digits(r).0);
    Some(OpenSshVersion {
        major: major?,
        minor: minor?,
        portable,
    })
}

/// `10.3p1`-style text for a version.
#[must_use]
pub fn version_text(v: &OpenSshVersion) -> String {
    match v.portable {
        Some(p) => format!("{}.{}p{p}", v.major, v.minor),
        None => format!("{}.{}", v.major, v.minor),
    }
}

/// One contained run.
#[derive(Debug, Clone)]
pub(crate) struct Spec<'a> {
    /// The program (never a shell unless the caller names one).
    pub program: &'a Path,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// The child's whole environment; `None` inherits this process's.
    pub env: Option<&'a Env>,
    /// The working directory; `None` inherits.
    pub cwd: Option<&'a Path>,
    /// The bound.
    pub timeout: Duration,
    /// Bytes kept per stream (the rest is drained and dropped).
    pub max_output: usize,
}

/// What one contained run did.
#[derive(Debug, Clone)]
pub(crate) struct Finished {
    /// The exit status (after a kill at the timeout, the killed status).
    pub status: Option<ExitStatus>,
    /// Whether the timeout fired and the group or job was killed.
    pub timed_out: bool,
    /// Bounded stdout.
    pub stdout: Vec<u8>,
    /// Bounded stderr.
    pub stderr: Vec<u8>,
    /// How the child was contained.
    pub containment: Containment,
}

/// The run could not be started or contained.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("contained run failed: {0}")]
pub(crate) struct RunError(pub &'static str);

fn spawn_reader<R: Read + Send + 'static>(mut r: R, max: usize) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = max.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        let _ = tx.send(kept);
    });
    rx
}

fn collect(rx: &mpsc::Receiver<Vec<u8>>, until: Instant) -> Vec<u8> {
    rx.recv_timeout(until.saturating_duration_since(Instant::now()))
        .unwrap_or_default()
}

/// Run `spec` contained and bounded (module documentation).
pub(crate) fn run_contained(spec: &Spec<'_>) -> Result<Finished, RunError> {
    let mut cmd = Command::new(spec.program);
    cmd.args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(env) = spec.env {
        cmd.env_clear();
        for (k, v) in env.iter() {
            cmd.env(k, v);
        }
    }
    if let Some(cwd) = spec.cwd {
        cmd.current_dir(cwd);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|_| RunError("spawn"))?;
    #[cfg(windows)]
    let job = {
        let job = crate::sys::JobObject::kill_on_close().and_then(|job| {
            job.assign_child(&child)?;
            Ok(job)
        });
        match job {
            Ok(job) => job,
            Err(_) => {
                // Not contained: stop it at once and report the failure.
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError("job object"));
            }
        }
    };
    let out_rx = child
        .stdout
        .take()
        .map(|s| spawn_reader(s, spec.max_output));
    let err_rx = child
        .stderr
        .take()
        .map(|s| spawn_reader(s, spec.max_output));
    let deadline = started + spec.timeout;
    let mut timed_out = false;
    let mut pause = Duration::from_millis(2);
    loop {
        if exited(&mut child)? {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(25));
    }
    #[cfg(unix)]
    let containment = {
        // The leader is alive (timeout) or an unreaped zombie: the group ID is ours.
        let _ = crate::sys::killpg(child.id());
        Containment::ProcessGroup
    };
    #[cfg(windows)]
    let containment = {
        if timed_out {
            let _ = child.kill();
        }
        drop(job);
        Containment::JobObject
    };
    #[cfg(not(any(unix, windows)))]
    let containment = {
        if timed_out {
            let _ = child.kill();
        }
        Containment::None
    };
    let status = child.wait().ok();
    let grace = Instant::now() + READER_GRACE;
    let stdout = out_rx.map(|rx| collect(&rx, grace)).unwrap_or_default();
    let stderr = err_rx.map(|rx| collect(&rx, grace)).unwrap_or_default();
    Ok(Finished {
        status,
        timed_out,
        stdout,
        stderr,
        containment,
    })
}

#[cfg(unix)]
fn exited(child: &mut std::process::Child) -> Result<bool, RunError> {
    crate::sys::exited_unreaped(child.id()).map_err(|_| RunError("waitid"))
}

#[cfg(not(unix))]
fn exited(child: &mut std::process::Child) -> Result<bool, RunError> {
    // Windows keeps the process object while our handle is open, so polling with
    // `try_wait` cannot let the ID be reused under the job.
    child
        .try_wait()
        .map(|s| s.is_some())
        .map_err(|_| RunError("try_wait"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_in_both_forms() {
        let v = parse_openssh_version("OpenSSH_10.3p1, LibreSSL 3.3.6").unwrap();
        assert_eq!((v.major, v.minor, v.portable), (10, 3, Some(1)));
        let w = parse_openssh_version("OpenSSH_for_Windows_9.5p2, LibreSSL 3.4.3").unwrap();
        assert_eq!((w.major, w.minor, w.portable), (9, 5, Some(2)));
        let n = parse_openssh_version("OpenSSH_9.6, OpenSSL").unwrap();
        assert_eq!(n.portable, None);
        assert_eq!(version_text(&w), "9.5p2");
        assert!(parse_openssh_version("ssh: unknown").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn contained_run_is_bounded_and_its_group_killed_at_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("late");
        // A background member of the group would create the marker after 1 s.
        let script = format!("(sleep 1; touch '{}') & sleep 30", marker.display());
        let env = Env::from_vars([("PATH", "/usr/bin:/bin")]);
        let started = Instant::now();
        let out = run_contained(&Spec {
            program: Path::new("/bin/sh"),
            args: vec!["-c".into(), script.into()],
            env: Some(&env),
            cwd: None,
            timeout: Duration::from_millis(300),
            max_output: 16,
        })
        .unwrap();
        assert!(out.timed_out);
        assert_eq!(out.containment, Containment::ProcessGroup);
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!marker.exists(), "a group member survived the kill");
    }

    #[cfg(unix)]
    #[test]
    fn contained_run_gets_only_the_given_environment_and_bounded_output() {
        let env = Env::from_vars([("PATH", "/usr/bin:/bin"), ("HM_U3_ONLY", "yes")]);
        let out = run_contained(&Spec {
            program: Path::new("/bin/sh"),
            args: vec!["-c".into(), "env | sort; printf '%0100d' 0 >&2".into()],
            env: Some(&env),
            cwd: None,
            timeout: LOCAL_QUERY_TIMEOUT,
            max_output: 64,
        })
        .unwrap();
        assert!(!out.timed_out);
        assert!(out.status.unwrap().success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("HM_U3_ONLY=yes"), "{text}");
        assert!(!text.contains("HOME="), "{text}");
        assert_eq!(out.stderr.len(), 64);
    }
}
