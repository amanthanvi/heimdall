//! The fixture hook program `hm-fixture-hook` (m02-plan U7 `hook::HookBinary`), for
//! `Match exec`, ProxyCommand and askpass fixtures. The program body is
//! [`main_with_args`]; `src/bin/hm-fixture-hook.rs` only calls it.
//!
//! Modes and exit statuses (0 = done, 1 = the action failed or was denied, 2 = usage):
//!
//! | Mode | Action | Exit |
//! |---|---|---|
//! | `connect <port>` | Connects to `127.0.0.1:<port>` and relays stdin to the socket and the socket to stdout (a ProxyCommand). After stdin ends it half-closes and waits at most 2 s for the server. | 0 when the relay ends; 1 when the connection fails |
//! | `agent-list <socket\|pipe>` | Sends one `SSH_AGENTC_REQUEST_IDENTITIES` and prints the number of identities (never their comments). | 0 on an identities answer; 1 otherwise |
//! | `touch <path>` | Appends one line `ran` to `<path>` (created if absent), so the line count is the number of runs. | 0; 1 on an I/O error |
//! | `escape <pidfile>` | Starts a child that leaves the caller's containment and sleeps 120 s: on Unix it calls `setsid`; on Windows it is created with `CREATE_BREAKAWAY_FROM_JOB`, and when the job refuses that, it is created inside the job instead. The child writes `<pid>\n<setsid\|breakaway\|in_job>\n` to `<pidfile>` (temporary file and rename). The caller returns once the pidfile exists; the test kills the child by that exact PID. | 0 once the pidfile exists; 1 otherwise |
//! | `askpass <log> <approve\|deny> [prompt…]` | Appends one line `askpass` to `<log>` (never the prompt, which names the key). `approve` prints nothing (an empty answer is consent to `ssh-agent`); `deny` refuses. | 0 for approve; 1 for deny; 2 for any other answer (logged too) |
//! | `revert <path> <original> <marker>` | Copies `<original>` over `<path>` through a temporary file in the same directory and a rename, then creates `<marker>` (the change-then-revert control of m02-plan U3, M2-S04). | 0; 1 on an I/O error |
//!
//! Anything else exits 2. The hook never prints a canary, a key, a path or a user
//! name.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::agent::{AgentConnection, AskpassAnswer, Endpoint};
use crate::home::{sh_join, ssh_config_quote};

/// Exit statuses of `hm-fixture-hook`.
pub mod exit {
    /// The mode's action happened (askpass: approved).
    pub const OK: i32 = 0;
    /// The action failed (askpass: denied).
    pub const FAILED: i32 = 1;
    /// Unknown mode or bad arguments.
    pub const USAGE: i32 = 2;
}

/// How long an escaped child sleeps before it exits on its own.
pub const ESCAPE_SLEEP: Duration = Duration::from_secs(120);
/// How long `escape` waits for the child's pidfile.
const ESCAPE_PIDFILE_WAIT: Duration = Duration::from_secs(5);
/// How long `connect` waits for the server after stdin ends.
const CONNECT_DRAIN: Duration = Duration::from_secs(2);
/// Windows `CREATE_BREAKAWAY_FROM_JOB`.
#[cfg(windows)]
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

/// One invocation of the hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookMode {
    /// `connect <port>`.
    Connect {
        /// Loopback port.
        port: u16,
    },
    /// `agent-list <socket|pipe>`.
    AgentList {
        /// The agent.
        endpoint: Endpoint,
    },
    /// `touch <path>`.
    Touch {
        /// The marker file.
        path: PathBuf,
    },
    /// `escape <pidfile>`.
    Escape {
        /// Where the escaped child writes its PID.
        pidfile: PathBuf,
    },
    /// `askpass <log> <approve|deny>`.
    Askpass {
        /// The invocation log.
        log: PathBuf,
        /// The answer.
        answer: AskpassAnswer,
    },
    /// `revert <path> <original> <marker>`.
    Revert {
        /// The file to put back.
        path: PathBuf,
        /// The bytes to put back.
        original: PathBuf,
        /// Created after the rename.
        marker: PathBuf,
    },
}

impl HookMode {
    /// The program arguments for this mode.
    #[must_use]
    pub fn args(&self) -> Vec<OsString> {
        match self {
            HookMode::Connect { port } => vec!["connect".into(), port.to_string().into()],
            HookMode::AgentList { endpoint } => vec!["agent-list".into(), endpoint.locator()],
            HookMode::Touch { path } => vec!["touch".into(), path.clone().into()],
            HookMode::Escape { pidfile } => vec!["escape".into(), pidfile.clone().into()],
            HookMode::Askpass { log, answer } => {
                vec!["askpass".into(), log.clone().into(), answer.as_str().into()]
            }
            HookMode::Revert {
                path,
                original,
                marker,
            } => vec![
                "revert".into(),
                path.clone().into(),
                original.clone().into(),
                marker.clone().into(),
            ],
        }
    }
}

/// The built `hm-fixture-hook` program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBinary {
    path: PathBuf,
}

impl HookBinary {
    /// The program name.
    pub const NAME: &'static str = "hm-fixture-hook";
    /// An environment variable naming the program explicitly (native harnesses).
    pub const ENV_OVERRIDE: &'static str = "HM_FIXTURE_HOOK";

    /// The program at `path`.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> HookBinary {
        HookBinary { path: path.into() }
    }

    /// [`ENV_OVERRIDE`](Self::ENV_OVERRIDE) when set (native harnesses name the copied
    /// program; ADR-0007 §12.32 item 3), else `compiled`, the build's own path (tests of
    /// this package pass `env!("CARGO_BIN_EXE_hm-fixture-hook")`).
    ///
    /// # Errors
    /// `NotFound` when the variable is set but does not name a file.
    pub fn locate_or(compiled: impl Into<PathBuf>) -> io::Result<HookBinary> {
        match std::env::var_os(Self::ENV_OVERRIDE) {
            Some(p) if !p.is_empty() => {
                let p = PathBuf::from(p);
                if p.is_file() {
                    Ok(HookBinary::at(p))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "HM_FIXTURE_HOOK does not name a file",
                    ))
                }
            }
            _ => Ok(HookBinary::at(compiled)),
        }
    }

    /// Find the program: [`ENV_OVERRIDE`](Self::ENV_OVERRIDE), else next to the
    /// running test executable (`target/<profile>/`, the parent of `deps/`).
    ///
    /// # Errors
    /// `NotFound`, naming the build command, when it was not built.
    pub fn locate() -> io::Result<HookBinary> {
        if let Some(p) = std::env::var_os(Self::ENV_OVERRIDE) {
            let p = PathBuf::from(p);
            return if p.is_file() {
                Ok(HookBinary::at(p))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "HM_FIXTURE_HOOK does not name a file",
                ))
            };
        }
        let file = format!("{}{}", Self::NAME, std::env::consts::EXE_SUFFIX);
        let exe = std::env::current_exe()?;
        exe.ancestors()
            .skip(1)
            .take(3)
            .map(|d| d.join(&file))
            .find(|c| c.is_file())
            .map(HookBinary::at)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "hm-fixture-hook is not built: run `cargo build -p heimdall-testkit --bin hm-fixture-hook`",
                )
            })
    }

    /// The program path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A command running `mode` directly (no shell).
    #[must_use]
    pub fn command(&self, mode: &HookMode) -> Command {
        let mut cmd = Command::new(&self.path);
        cmd.args(mode.args());
        cmd
    }

    /// The command line a shell runs for `mode`: `sh` single-quoting on Unix; on
    /// Windows words for `cmd.exe /c`, double-quoted where needed and, then, wrapped in
    /// one more pair of quotes (cmd strips the outer pair). The Windows form is not yet
    /// observed natively (m02-plan §4 Windows harness).
    #[must_use]
    pub fn shell_command(&self, mode: &HookMode) -> String {
        let mut words: Vec<OsString> = vec![self.path.clone().into_os_string()];
        words.extend(mode.args());
        if cfg!(windows) {
            cmd_join(&words)
        } else {
            sh_join(&words)
        }
    }

    /// An `ssh_config` line `Match exec "<shell command>"` (`%` doubled, quoted as one
    /// token).
    #[must_use]
    pub fn match_exec_line(&self, mode: &HookMode) -> String {
        format!(
            "Match exec {}",
            ssh_config_quote(&self.shell_command(mode).replace('%', "%%"))
        )
    }

    /// An `ssh_config` line `ProxyCommand <shell command>` for `connect <port>`
    /// (ProxyCommand takes the rest of the line verbatim; `%` doubled).
    #[must_use]
    pub fn proxy_command_line(&self, port: u16) -> String {
        format!(
            "ProxyCommand {}",
            self.shell_command(&HookMode::Connect { port })
                .replace('%', "%%")
        )
    }
}

fn cmd_join(words: &[OsString]) -> String {
    let mut quoted = false;
    let parts: Vec<String> = words
        .iter()
        .map(|w| {
            let t = w.to_string_lossy().into_owned();
            if t.is_empty()
                || t.chars()
                    .any(|c| c.is_whitespace() || "&|<>^()".contains(c))
            {
                quoted = true;
                format!("\"{t}\"")
            } else {
                t
            }
        })
        .collect();
    let line = parts.join(" ");
    if quoted { format!("\"{line}\"") } else { line }
}

/// The `hm-fixture-hook` program: `args` excludes the program name. Returns the exit
/// status.
#[must_use]
pub fn main_with_args(args: Vec<OsString>) -> i32 {
    let mode = args.first().and_then(|m| m.to_str()).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    match (mode, rest) {
        ("connect", [port]) => connect(port),
        ("agent-list", [endpoint]) => agent_list(endpoint),
        ("touch", [path]) => touch(Path::new(path)),
        ("escape", [pidfile]) => escape(Path::new(pidfile)),
        ("escape-child", [pidfile, how]) => escape_child(Path::new(pidfile), how),
        ("askpass", [log, answer, ..]) => askpass(Path::new(log), answer),
        ("revert", [path, original, marker]) => {
            revert(Path::new(path), Path::new(original), Path::new(marker))
        }
        _ => exit::USAGE,
    }
}

fn copy_flushing(mut from: impl Read, mut to: impl Write) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() || to.flush().is_err() {
                    return;
                }
            }
        }
    }
}

enum RelayEvent {
    SocketClosed,
    StdinClosed,
}

fn connect(port: &OsStr) -> i32 {
    let Some(port) = port.to_str().and_then(|p| p.parse::<u16>().ok()) else {
        return exit::USAGE;
    };
    let Ok(stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) else {
        return exit::FAILED;
    };
    let (Ok(reader), Ok(writer)) = (stream.try_clone(), stream.try_clone()) else {
        return exit::FAILED;
    };
    let (tx, rx) = mpsc::channel();
    let socket_tx = tx.clone();
    std::thread::spawn(move || {
        copy_flushing(reader, io::stdout());
        let _ = socket_tx.send(RelayEvent::SocketClosed);
    });
    std::thread::spawn(move || {
        let mut writer = writer;
        copy_flushing(io::stdin(), &mut writer);
        let _ = writer.shutdown(Shutdown::Write);
        let _ = tx.send(RelayEvent::StdinClosed);
    });
    match rx.recv() {
        Ok(RelayEvent::StdinClosed) => {
            let _ = rx.recv_timeout(CONNECT_DRAIN);
        }
        Ok(RelayEvent::SocketClosed) | Err(_) => {}
    }
    drop(stream);
    exit::OK
}

fn endpoint_from_arg(arg: &OsStr) -> Endpoint {
    let text = arg.to_string_lossy();
    if text.starts_with(r"\\.\pipe\") || text.starts_with("//./pipe/") {
        Endpoint::NamedPipe(text.into_owned())
    } else {
        Endpoint::UnixSocket(PathBuf::from(arg))
    }
}

fn agent_list(endpoint: &OsStr) -> i32 {
    let endpoint = endpoint_from_arg(endpoint);
    let listed =
        AgentConnection::connect(&endpoint, Duration::from_secs(5)).and_then(|mut c| c.list());
    match listed {
        Ok(keys) => {
            let mut out = io::stdout();
            let _ = writeln!(out, "{}", keys.len());
            let _ = out.flush();
            exit::OK
        }
        Err(_) => exit::FAILED,
    }
}

fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()
}

fn touch(path: &Path) -> i32 {
    match append_line(path, "ran") {
        Ok(()) => exit::OK,
        Err(_) => exit::FAILED,
    }
}

fn askpass(log: &Path, answer: &OsStr) -> i32 {
    if append_line(log, "askpass").is_err() {
        return exit::FAILED;
    }
    match answer.to_str() {
        Some("approve") => exit::OK,
        Some("deny") => exit::FAILED,
        _ => exit::USAGE,
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map_or_else(|| "hook".into(), |n| n.to_string_lossy().into_owned());
    let tmp = dir.join(format!(".{name}.hm-hook-{}", std::process::id()));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn revert(path: &Path, original: &Path, marker: &Path) -> i32 {
    let done = fs::read(original)
        .and_then(|bytes| write_atomically(path, &bytes))
        .and_then(|()| append_line(marker, "reverted"));
    match done {
        Ok(()) => exit::OK,
        Err(_) => exit::FAILED,
    }
}

/// The one Windows system call the hook makes (same shape as
/// `heimdall_runtime::platform::disinherit_standard_handles`).
#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

    /// Clear `HANDLE_FLAG_INHERIT` on this process's standard input, output and error
    /// handles. They stay open and usable here; a child created afterwards no longer
    /// receives them through handle inheritance.
    pub(super) fn disinherit_standard_handles() {
        use std::os::windows::io::AsRawHandle as _;
        for handle in [
            std::io::stdin().as_raw_handle(),
            std::io::stdout().as_raw_handle(),
            std::io::stderr().as_raw_handle(),
        ] {
            if handle.is_null() {
                continue;
            }
            // SAFETY: `handle` is this process's own standard handle as the standard
            // library holds it (null skipped above); changing its inherit flag neither
            // closes nor invalidates it. An invalid or console pseudo handle makes the
            // call fail, which is ignored.
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
}

fn escape(pidfile: &Path) -> i32 {
    let Ok(me) = std::env::current_exe() else {
        return exit::FAILED;
    };
    let spawn = |how: &str| {
        let mut cmd = Command::new(&me);
        cmd.arg("escape-child")
            .arg(pidfile)
            .arg(how)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    };
    #[cfg(windows)]
    let started = {
        use std::os::windows::process::CommandExt;
        // `CreateProcess` hands the child every inheritable handle of this process, so
        // the caller's stdout pipe would stay open (and `wait_with_output` or `ssh`
        // would wait for its end of file) until the 120 s child exits.
        win::disinherit_standard_handles();
        spawn("breakaway")
            .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
            .spawn()
            .or_else(|_| spawn("in_job").spawn())
    };
    #[cfg(not(windows))]
    let started = spawn("setsid").spawn();
    if started.is_err() {
        return exit::FAILED;
    }
    let end = Instant::now() + ESCAPE_PIDFILE_WAIT;
    while Instant::now() < end {
        if pidfile.is_file() {
            return exit::OK;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    exit::FAILED
}

fn escape_child(pidfile: &Path, how: &OsStr) -> i32 {
    let how = how.to_string_lossy().into_owned();
    #[cfg(unix)]
    let how = if how == "setsid" && rustix::process::setsid().is_err() {
        "setsid_failed".to_owned()
    } else {
        how
    };
    let record = format!("{}\n{how}\n", std::process::id());
    if write_atomically(pidfile, record.as_bytes()).is_err() {
        return exit::FAILED;
    }
    std::thread::sleep(ESCAPE_SLEEP);
    exit::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> i32 {
        main_with_args(args.iter().map(OsString::from).collect())
    }

    #[test]
    fn usage_errors_exit_2() {
        assert_eq!(run(&[]), exit::USAGE);
        assert_eq!(run(&["nope"]), exit::USAGE);
        assert_eq!(run(&["touch"]), exit::USAGE);
        assert_eq!(run(&["connect", "not-a-port"]), exit::USAGE);
        assert_eq!(run(&["revert", "a", "b"]), exit::USAGE);
    }

    #[test]
    fn touch_askpass_and_revert_in_process() {
        let d = tempfile::tempdir().unwrap();
        let p = |n: &str| d.path().join(n).to_str().unwrap().to_owned();
        assert_eq!(run(&["touch", &p("t")]), exit::OK);
        assert_eq!(run(&["touch", &p("t")]), exit::OK);
        assert_eq!(fs::read_to_string(p("t")).unwrap(), "ran\nran\n");
        assert_eq!(
            run(&["askpass", &p("log"), "approve", "Allow use of key?"]),
            exit::OK
        );
        assert_eq!(run(&["askpass", &p("log"), "deny"]), exit::FAILED);
        assert_eq!(run(&["askpass", &p("log"), "maybe"]), exit::USAGE);
        assert_eq!(
            fs::read_to_string(p("log")).unwrap(),
            "askpass\naskpass\naskpass\n"
        );
        fs::write(p("orig"), b"original\r\n\x00bytes").unwrap();
        fs::write(p("file"), b"changed").unwrap();
        assert_eq!(
            run(&["revert", &p("file"), &p("orig"), &p("marker")]),
            exit::OK
        );
        assert_eq!(fs::read(p("file")).unwrap(), b"original\r\n\x00bytes");
        assert!(Path::new(&p("marker")).is_file());
        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            5,
            "no temporary file left"
        );
        assert_eq!(
            run(&["revert", &p("file"), &p("absent"), &p("m2")]),
            exit::FAILED
        );
        assert!(!Path::new(&p("m2")).exists());
    }

    #[test]
    fn config_lines_quote_and_double_percent() {
        let h = HookBinary::at("/opt/hm hook/hm-fixture-hook");
        let line = h.match_exec_line(&HookMode::Touch {
            path: PathBuf::from("/tmp/a%b"),
        });
        if cfg!(unix) {
            assert_eq!(
                line,
                r#"Match exec "'/opt/hm hook/hm-fixture-hook' 'touch' '/tmp/a%%b'""#
            );
            assert_eq!(
                h.proxy_command_line(2222),
                "ProxyCommand '/opt/hm hook/hm-fixture-hook' 'connect' '2222'"
            );
        }
        assert_eq!(
            cmd_join(&["C:\\a b\\h.exe".into(), "touch".into(), "C:\\x".into()]),
            "\"\"C:\\a b\\h.exe\" touch C:\\x\""
        );
        assert_eq!(
            cmd_join(&["C:\\h.exe".into(), "touch".into()]),
            "C:\\h.exe touch"
        );
    }
}
