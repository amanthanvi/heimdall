//! The `wsl.exe` side of a session (ADR-0010 §3 items 3, 9–10; design U3 §4): the commands,
//! their environment, and bounded runs. Only the command text, the environment filter and the
//! output parsing are pure; running needs a Windows host (a missing `wsl.exe` is an error,
//! never a guess).
//!
//! Every process here starts through
//! [`heimdall_localenv::sys::spawn`] (the explicit handle list), with a cleared environment
//! except `SystemRoot`, `PATH`, `TEMP`/`TMP` and `WSL_UTF8=0`.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use heimdall_localenv::sys::spawn::{ListedChild, ListedSpawn, ListedStdio, spawn_listed};

use crate::discover::{RunningSet, parse_running_list};

/// `CREATE_NO_WINDOW`: no console window for a `wsl.exe` child.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The bound on `wsl.exe --list --running --quiet`.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(5);
/// The bound on `wslpath` through `wsl.exe` (it may cold-start the distribution; ADR-0010
/// §9 item 8 keeps a hello that never comes the same failure).
pub const WSLPATH_TIMEOUT: Duration = Duration::from_secs(10);
/// The most output of a bounded run that is kept.
const OUTPUT_MAX: usize = 1 << 20;

/// The directory beneath the Windows executable that holds the Linux helper build
/// (`<directory of heimdall.exe>\linux-x86_64\heimdall`).
pub const HELPER_DIR: &str = "linux-x86_64";
/// The helper's file name.
pub const HELPER_FILE: &str = "heimdall";

/// The in-box OpenSSH client, as Windows names it (used when `SystemRoot` is unset).
pub const SSH_EXE_DEFAULT: &str = "C:\\Windows\\System32\\OpenSSH\\ssh.exe";

/// The environment variables a `wsl.exe` child keeps.
const KEPT_ENV: [&str; 4] = ["SystemRoot", "PATH", "TEMP", "TMP"];

/// A name or account the commands can pass to `wsl.exe` without it being read as an option or
/// carrying control characters: non-empty, not beginning with `-`, no control character.
#[must_use]
pub fn is_plain_argument(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && !s.chars().any(char::is_control)
}

/// `%SystemRoot%\System32\OpenSSH\ssh.exe`, from the given `SystemRoot`.
#[must_use]
pub fn ssh_exe_windows(system_root: Option<&str>) -> String {
    match system_root.filter(|r| !r.is_empty()) {
        Some(root) => format!(
            "{}\\System32\\OpenSSH\\ssh.exe",
            root.trim_end_matches('\\')
        ),
        None => SSH_EXE_DEFAULT.to_owned(),
    }
}

/// The Windows path of the Linux helper: `<exe_dir>\linux-x86_64\heimdall`.
#[must_use]
pub fn helper_windows_path(exe_dir: &Path) -> PathBuf {
    exe_dir.join(HELPER_DIR).join(HELPER_FILE)
}

/// A `wsl.exe` command with the filtered environment applied. `kept` is the lookup of the
/// parent's variables (injected so the filter is testable).
#[must_use]
pub fn wsl_command(
    wsl_exe: &Path,
    args: &[&str],
    kept: &dyn Fn(&str) -> Option<OsString>,
) -> Command {
    let mut cmd = Command::new(wsl_exe);
    cmd.args(args);
    for name in KEPT_ENV {
        if let Some(v) = kept(name) {
            cmd.env(name, v);
        }
    }
    cmd.env("WSL_UTF8", "0");
    cmd
}

/// `wsl.exe` under `SystemRoot\System32`, or the bare name when `SystemRoot` is unset (the
/// search is then the process's own `PATH`).
#[must_use]
pub fn wsl_exe_path(system_root: Option<&str>) -> PathBuf {
    match system_root.filter(|r| !r.is_empty()) {
        Some(root) => Path::new(root).join("System32").join("wsl.exe"),
        None => PathBuf::from("wsl.exe"),
    }
}

/// `wsl.exe -d <name> -u <account> --exec /usr/bin/wslpath -u <windows path>`.
///
/// # Errors
/// `None` when `name` or `account` is not a plain argument.
#[must_use]
pub fn wslpath_args<'a>(
    name: &'a str,
    account: &'a str,
    windows_path: &'a str,
) -> Option<Vec<&'a str>> {
    (is_plain_argument(name) && is_plain_argument(account) && !windows_path.is_empty()).then(|| {
        vec![
            "-d",
            name,
            "-u",
            account,
            "--exec",
            "/usr/bin/wslpath",
            "-u",
            windows_path,
        ]
    })
}

/// `wsl.exe -d <name> -u <account> --exec <helper> internal wsl-helper`.
#[must_use]
pub fn helper_args<'a>(
    name: &'a str,
    account: &'a str,
    linux_helper: &'a str,
) -> Option<Vec<&'a str>> {
    (is_plain_argument(name) && is_plain_argument(account) && linux_helper.starts_with('/')).then(
        || {
            vec![
                "-d",
                name,
                "-u",
                account,
                "--exec",
                linux_helper,
                "internal",
                "wsl-helper",
            ]
        },
    )
}

/// The Linux-visible path `wslpath -u` printed: one absolute path, trailing newline removed.
/// Empty, relative, multi-line or NUL-bearing output is `None` (never passed on).
#[must_use]
pub fn parse_wslpath_output(out: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(out).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    (line.starts_with('/') && !line.contains(['\n', '\r', '\0'])).then(|| line.to_owned())
}

/// A bounded run failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// The process could not be started.
    #[error("the process could not be started")]
    Spawn,
    /// It did not finish in time and was killed.
    #[error("the process did not finish in time")]
    Timeout,
    /// Its status could not be read.
    #[error("the process status could not be read")]
    Wait,
}

/// A finished bounded run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// The exit code (negative: a signal).
    pub status: i32,
    /// Up to 1 MiB of stdout.
    pub stdout: Vec<u8>,
}

/// Run `cmd` with stdin and stderr null and stdout captured, killing it after `timeout`.
///
/// # Errors
/// [`RunError`].
pub fn run_bounded(cmd: &Command, timeout: Duration) -> Result<Finished, RunError> {
    let mut child: ListedChild = spawn_listed(
        cmd,
        &ListedSpawn {
            stdin: ListedStdio::Null,
            stdout: ListedStdio::Piped,
            stderr: ListedStdio::Null,
            env_clear: true,
            creation_flags: CREATE_NO_WINDOW,
        },
    )
    .map_err(|_| RunError::Spawn)?;
    let reader = child.stdout.take().map(|mut f| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buf = [0u8; 8192];
            while let Ok(n) = f.read(&mut buf) {
                if n == 0 {
                    break;
                }
                // Keep reading past the cap so the child never blocks on a full pipe.
                let room = OUTPUT_MAX.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            kept
        })
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(code)) => break Ok(code),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(RunError::Timeout);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(RunError::Wait);
            }
        }
    };
    let stdout = reader
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    status.map(|status| Finished { status, stdout })
}

/// The running set from `wsl.exe --list --running --quiet` (starts nothing). A failed start,
/// a timeout, a non-zero exit or undecodable output is [`RunningSet::Unknown`].
#[must_use]
pub fn list_running(wsl_exe: &Path, kept: &dyn Fn(&str) -> Option<OsString>) -> RunningSet {
    let cmd = wsl_command(wsl_exe, &["--list", "--running", "--quiet"], kept);
    match run_bounded(&cmd, LIST_TIMEOUT) {
        Ok(f) if f.status == 0 => parse_running_list(&f.stdout),
        _ => RunningSet::Unknown,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_exact_and_refuse_option_like_names() {
        let args = helper_args("Ubuntu", "alice", "/mnt/c/h/linux-x86_64/heimdall").unwrap();
        assert_eq!(
            args,
            [
                "-d",
                "Ubuntu",
                "-u",
                "alice",
                "--exec",
                "/mnt/c/h/linux-x86_64/heimdall",
                "internal",
                "wsl-helper"
            ]
        );
        assert!(helper_args("-d", "a", "/x").is_none());
        assert!(helper_args("Ubuntu", "", "/x").is_none());
        assert!(helper_args("Ubuntu", "a", "relative").is_none());
        assert!(wslpath_args("Ubu\nntu", "a", "C:\\x").is_none());
        let w = wslpath_args("Ubuntu", "a", "C:\\h\\heimdall").unwrap();
        assert_eq!(
            &w[4..],
            ["--exec", "/usr/bin/wslpath", "-u", "C:\\h\\heimdall"]
        );
    }

    #[test]
    fn wslpath_output_must_be_one_absolute_path() {
        assert_eq!(
            parse_wslpath_output(b"/mnt/c/Users/a/heimdall\n").as_deref(),
            Some("/mnt/c/Users/a/heimdall")
        );
        for bad in [
            &b""[..],
            b"\n",
            b"C:\\x\n",
            b"rel/x\n",
            b"/a\n/b\n",
            b"/a\0b\n",
        ] {
            assert_eq!(parse_wslpath_output(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn child_environment_keeps_only_the_listed_variables() {
        let parent = |n: &str| match n {
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            "PATH" => Some(OsString::from("C:\\p")),
            "TEMP" => Some(OsString::from("C:\\t")),
            "SECRET_TOKEN" => Some(OsString::from("x")),
            _ => None,
        };
        let cmd = wsl_command(Path::new("wsl.exe"), &["--list"], &parent);
        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect();
        let mut names: Vec<&str> = envs.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["PATH", "SystemRoot", "TEMP", "WSL_UTF8"]);
        assert!(envs.iter().any(|(k, v)| k == "WSL_UTF8" && v == "0"));
        assert_eq!(
            ssh_exe_windows(Some("C:\\Windows\\")),
            "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
        );
        assert_eq!(ssh_exe_windows(None), SSH_EXE_DEFAULT);
    }
}
