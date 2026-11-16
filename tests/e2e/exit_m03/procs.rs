//! Process, descriptor and endpoint readings for the exit checks (`e2e_exit_m03`
//! submodule). Everything here reads; nothing signals or changes a process.
//!
//! **Descriptor identity** (A10's "no issuer pipe descriptor in a runtime-spawned
//! process", checked on exact PIDs):
//! * **Linux:** `readlink /proc/<pid>/fd/<n>`: `pipe:[<inode>]` (both ends of a pipe
//!   share the inode), `socket:[<inode>]`, a path, or another anonymous kind;
//! * **macOS:** `lsof -n -P -a -p <pid> -F ftdn`: a pipe end's `d` field is its kernel
//!   address (what `fstat` reports as `st_ino` for that end) and its `n` field `->0x…`
//!   the peer end's, so a pipe is identified by the pair of addresses.
//!
//! A worker reads its own descriptors the same way (`/proc/<own pid>` on Linux, `lsof
//! -p <own pid>` on macOS).
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

/// What kind of object a descriptor refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    Pipe,
    Socket,
    File,
    Other,
}

impl FdKind {
    fn name(self) -> &'static str {
        match self {
            FdKind::Pipe => "pipe",
            FdKind::Socket => "socket",
            FdKind::File => "file",
            FdKind::Other => "other",
        }
    }

    fn of(name: &str) -> FdKind {
        match name {
            "pipe" => FdKind::Pipe,
            "socket" => FdKind::Socket,
            "file" => FdKind::File,
            _ => FdKind::Other,
        }
    }
}

/// One open descriptor: its number, kind and pipe identities (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fd {
    pub fd: i64,
    pub kind: FdKind,
    /// Linux: the pipe inode; macOS: the end's address and its peer's.
    pub ids: Vec<u64>,
}

impl Fd {
    /// As JSON (a worker's result).
    pub fn to_json(&self) -> Value {
        json!({ "fd": self.fd, "kind": self.kind.name(), "ids": self.ids })
    }

    /// From [`Fd::to_json`].
    pub fn from_json(v: &Value) -> Fd {
        Fd {
            fd: v["fd"].as_i64().unwrap_or(-1),
            kind: FdKind::of(v["kind"].as_str().unwrap_or("")),
            ids: v["ids"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default(),
        }
    }
}

/// The open descriptors of `pid` (module docs). `Err` with the reason when they
/// cannot be read.
pub fn fds_of(pid: u32) -> Result<Vec<Fd>, String> {
    #[cfg(target_os = "linux")]
    {
        let dir = format!("/proc/{pid}/fd");
        let entries = std::fs::read_dir(&dir).map_err(|e| unreadable("fd", &e))?;
        let mut out = Vec::new();
        for e in entries.flatten() {
            let Ok(fd) = e.file_name().to_string_lossy().parse::<i64>() else {
                continue;
            };
            let Ok(target) = std::fs::read_link(e.path()) else {
                continue;
            };
            let t = target.to_string_lossy().into_owned();
            let bracket = |prefix: &str| {
                t.strip_prefix(prefix)
                    .and_then(|r| r.strip_suffix(']'))
                    .and_then(|n| n.parse::<u64>().ok())
            };
            let (kind, ids) = if let Some(n) = bracket("pipe:[") {
                (FdKind::Pipe, vec![n])
            } else if bracket("socket:[").is_some() {
                (FdKind::Socket, Vec::new())
            } else if t.starts_with('/') {
                (FdKind::File, Vec::new())
            } else {
                (FdKind::Other, Vec::new())
            };
            out.push(Fd { fd, kind, ids });
        }
        Ok(out)
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/sbin/lsof")
            .args(["-n", "-P", "-a", "-p", &pid.to_string(), "-F", "ftdn"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| format!("lsof: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut fds = Vec::new();
        let mut cur: Option<(i64, String, Option<u64>, Option<u64>)> = None;
        let flush = |cur: &mut Option<(i64, String, Option<u64>, Option<u64>)>,
                     fds: &mut Vec<Fd>| {
            if let Some((fd, t, d, peer)) = cur.take() {
                let kind = match t.as_str() {
                    "PIPE" | "FIFO" => FdKind::Pipe,
                    "unix" | "IPv4" | "IPv6" | "sock" => FdKind::Socket,
                    "REG" | "DIR" | "CHR" => FdKind::File,
                    _ => FdKind::Other,
                };
                let ids = if kind == FdKind::Pipe {
                    d.into_iter().chain(peer).collect()
                } else {
                    Vec::new()
                };
                fds.push(Fd { fd, kind, ids });
            }
        };
        let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok();
        for line in text.lines() {
            let (tag, rest) = line.split_at(line.len().min(1));
            match tag {
                "f" => {
                    flush(&mut cur, &mut fds);
                    cur = rest
                        .parse::<i64>()
                        .ok()
                        .map(|fd| (fd, String::new(), None, None));
                }
                "t" => {
                    if let Some(c) = cur.as_mut() {
                        c.1 = rest.to_owned();
                    }
                }
                "d" => {
                    if let Some(c) = cur.as_mut() {
                        c.2 = hex(rest);
                    }
                }
                "n" => {
                    if let Some(c) = cur.as_mut()
                        && let Some(p) = rest.strip_prefix("->")
                    {
                        c.3 = hex(p);
                    }
                }
                _ => {}
            }
        }
        flush(&mut cur, &mut fds);
        if fds.is_empty() {
            return Err("lsof listed no descriptor".to_owned());
        }
        Ok(fds)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err("descriptor listing is Unix-only here".to_owned())
    }
}

/// Every pipe identity among `fds`.
pub fn pipe_ids(fds: &[Fd]) -> BTreeSet<u64> {
    fds.iter()
        .filter(|f| f.kind == FdKind::Pipe)
        .flat_map(|f| f.ids.iter().copied())
        .collect()
}

/// One process: PID, parent PID and executable base name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

/// Every process of this host the account can see, with the executable's base name
/// only: Unix `ps -A -o pid= -o ppid= -o comm=`; Windows the CIM `Win32_Process` class.
pub fn processes() -> Vec<Proc> {
    #[cfg(unix)]
    let out = Command::new("ps")
        .args(["-A", "-o", "pid=", "-o", "ppid=", "-o", "comm="])
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    #[cfg(windows)]
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId) $($_.ParentProcessId) $($_.Name)\" }",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(out) = out else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let pid = w.next()?.parse().ok()?;
            let ppid = w.next()?.parse().ok()?;
            let comm = w.collect::<Vec<_>>().join(" ");
            let name = Path::new(&comm)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or(comm);
            let name = name.strip_suffix(".exe").map(str::to_owned).unwrap_or(name);
            Some(Proc { pid, ppid, name })
        })
        .collect()
}

/// The runtime's issuer child: its one child process running the same executable as
/// the runtime (`internal issuer`; the file name is not assumed, `HEIMDALL_E2E_BIN` may
/// name another one).
pub fn issuer_child(runtime: u32) -> Option<u32> {
    let all = processes();
    let name = all.iter().find(|p| p.pid == runtime)?.name.clone();
    let kids: Vec<&Proc> = all
        .iter()
        .filter(|p| p.ppid == runtime && p.name == name)
        .collect();
    (kids.len() == 1).then(|| kids[0].pid)
}

/// Whether `pid` is a live process of this account (Unix: `kill -0` semantics through
/// `ps -p`; Windows: `tasklist`).
pub fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!("\"{pid}\"")))
            .unwrap_or(false)
    }
}

/// A process's argument vector and environment as this account can read them, for
/// A33's scan: `(argv, environ)`, each `Err(why)` when unobservable here.
///
/// * Linux: `/proc/<pid>/cmdline` and `/proc/<pid>/environ` (NUL-separated);
/// * macOS: the argument vector from `ps -ww -o command=`; the environment of another
///   process is not shown without privilege;
/// * Windows: the command line from the CIM `Win32_Process` class (PowerShell, this
///   user's own processes); the environment of another process is not readable through
///   a documented unprivileged interface.
pub fn argv_environ(pid: u32) -> (Result<Vec<u8>, String>, Result<Vec<u8>, String>) {
    #[cfg(target_os = "linux")]
    {
        let read =
            |f: &str| std::fs::read(format!("/proc/{pid}/{f}")).map_err(|e| unreadable(f, &e));
        (read("cmdline"), read("environ"))
    }
    #[cfg(target_os = "macos")]
    {
        let argv = Command::new("/bin/ps")
            .args(["-ww", "-o", "command=", "-p", &pid.to_string()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| o.stdout)
            .map_err(|e| format!("ps: {e}"));
        (
            argv,
            Err("macOS shows another process's environment only with privilege".to_owned()),
        )
    }
    #[cfg(windows)]
    {
        let script =
            format!("(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine");
        let argv = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| o.stdout)
            .map_err(|e| format!("powershell: {e}"));
        (
            argv,
            Err(
                "Windows has no documented unprivileged reading of another process's environment"
                    .to_owned(),
            ),
        )
    }
}

/// Why `/proc/<pid>/<what>` could not be read (no path or PID in the text). A
/// permission refusal is the hardened processes' case: the runtime and its issuer child
/// make themselves non-dumpable (`heimdall_credential::sys::harden_process`), so their
/// `/proc/<pid>` entries are root's.
#[cfg(target_os = "linux")]
fn unreadable(what: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!("/proc/<pid>/{what} is root's for a non-dumpable process (harden_process)")
    } else {
        format!("/proc/<pid>/{what}: {}", e.kind())
    }
}

/// Linux: every Unix socket of this network namespace with its bound name
/// (`/proc/net/unix`'s last column: a path, or `@name` for an abstract socket). Any
/// user can read it; it does not name the holding process.
#[cfg(target_os = "linux")]
pub fn unix_socket_names() -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string("/proc/net/unix")
        .map_err(|e| format!("/proc/net/unix: {}", e.kind()))?;
    Ok(text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            (cols.len() >= 8).then(|| cols[7..].join(" "))
        })
        .collect())
}
