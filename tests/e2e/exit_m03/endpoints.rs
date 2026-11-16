//! Heimdall's endpoints as a same-user process finds them, and what each one lists
//! (`e2e_exit_m03` submodule; A10, ADR-0008 D12 item 6).
//!
//! * **Unix:** every socket and FIFO under the Heimdall home, each classified against
//!   the runtime's advertisement (`instance.json`: `control_endpoint`,
//!   `signing_endpoint`, the environment endpoint), the binding layout
//!   (`<run>/b/<16 hex>/agent.sock`) and the issuer path the IPC layer reserves and must
//!   never create (`<run>/issuer.sock`, ADR-0008 Q1).
//! * **Windows:** every pipe of the pipe namespace named `heimdall-<instance token>-…`
//!   (the tokens of the advertised control and signing pipes), classified by suffix:
//!   `control`, `signing`, `issuer` (reserved, never created), `b<tag>` (a binding).
//!
//! An agent endpoint is listed with the system `ssh-add -L` (bounded; nothing is
//! signed). A listed line is `(key type, base64 blob)`; a certificate's key ID and
//! serial are decoded from its blob.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::process::Command;
use std::time::Duration;

use crate::world::{World, openssh, run_bounded};

/// What an endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Control,
    Environment,
    Binding,
    Issuer,
    Other,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::Control => "control",
            Class::Environment => "environment",
            Class::Binding => "binding",
            Class::Issuer => "issuer",
            Class::Other => "other",
        }
    }
}

/// One endpoint: its class and locator (a socket path or `\\.\pipe\<name>`; never
/// printed).
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub class: Class,
    pub locator: String,
}

/// Every endpoint of `w`'s runtime (module docs).
pub fn of(w: &World) -> Vec<Endpoint> {
    let instance = w.instance();
    let control = instance["control_endpoint"].as_str().unwrap().to_owned();
    let signing = instance["signing_endpoint"].as_str().unwrap().to_owned();
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;
        let run = w.hh.join("run");
        let issuer = run.join("issuer.sock");
        let mut found = Vec::new();
        let mut stack = vec![w.hh.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let Ok(t) = e.file_type() else { continue };
                let path = e.path();
                if t.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !(t.is_socket() || t.is_fifo()) {
                    continue;
                }
                let s = path.to_string_lossy().into_owned();
                let class = if s == control {
                    Class::Control
                } else if s == signing {
                    Class::Environment
                } else if path == issuer || e.file_name().to_string_lossy().contains("issuer") {
                    Class::Issuer
                } else if path.parent().and_then(std::path::Path::parent)
                    == Some(run.join("b").as_path())
                    && e.file_name() == "agent.sock"
                {
                    Class::Binding
                } else {
                    Class::Other
                };
                found.push(Endpoint { class, locator: s });
            }
        }
        found.sort_by(|a, b| a.class.cmp(&b.class).then(a.locator.cmp(&b.locator)));
        found
    }
    #[cfg(windows)]
    {
        let name = |locator: &str| {
            locator
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        // The tokens of the advertised control and signing pipes (one token in
        // practice; both are read so neither endpoint's pipes are missed).
        let token_of = |locator: &str, suffix: &str| {
            name(locator)
                .strip_prefix("heimdall-")
                .and_then(|r| r.strip_suffix(suffix))
                .map(str::to_owned)
        };
        let prefixes: std::collections::BTreeSet<String> = [
            token_of(&control, "-control").expect("the control pipe is heimdall-<token>-control"),
            token_of(&signing, "-signing").expect("the signing pipe is heimdall-<token>-signing"),
        ]
        .into_iter()
        .map(|t| format!("heimdall-{t}-"))
        .collect();
        let mut found = Vec::new();
        if let Ok(entries) = std::fs::read_dir(r"\\.\pipe\") {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                let Some(suffix) = prefixes.iter().find_map(|p| n.strip_prefix(p.as_str())) else {
                    continue;
                };
                let class = match suffix {
                    "control" => Class::Control,
                    "signing" => Class::Environment,
                    s if s.contains("issuer") => Class::Issuer,
                    s if s.starts_with('b') => Class::Binding,
                    _ => Class::Other,
                };
                found.push(Endpoint {
                    class,
                    locator: format!(r"\\.\pipe\{n}"),
                });
            }
        }
        found.sort_by(|a, b| a.class.cmp(&b.class).then(a.locator.cmp(&b.locator)));
        found
    }
}

/// `class=count` for each class present, in class order.
pub fn summary(eps: &[Endpoint]) -> String {
    let mut out = Vec::new();
    for c in [
        Class::Control,
        Class::Environment,
        Class::Binding,
        Class::Issuer,
        Class::Other,
    ] {
        out.push(format!(
            "{}={}",
            c.name(),
            eps.iter().filter(|e| e.class == c).count()
        ));
    }
    out.join(" ")
}

/// One listed identity: its key type and blob (base64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub key_type: String,
    pub blob: String,
}

/// `ssh-add -L` against `locator`: `Ok(identities)` (an agent with none answers exit
/// 1, "no identities"), or `Err(exit)` when it does not answer as an agent.
pub fn list(locator: &str) -> Result<Vec<Listed>, i32> {
    let mut cmd = Command::new(openssh("ssh-add"));
    cmd.arg("-L").env_clear().env("SSH_AUTH_SOCK", locator);
    for k in ["SystemRoot", "PATH"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    let out = run_bounded(&mut cmd, Duration::from_secs(20));
    parse_listing(out.code, &out.stdout)
}

/// [`list`]'s reading of an `ssh-add -L` run (also for a worker's result).
pub fn parse_listing(code: i32, stdout: &str) -> Result<Vec<Listed>, i32> {
    match code {
        0 => Ok(stdout
            .lines()
            .filter_map(|l| {
                let mut w = l.split_whitespace();
                Some(Listed {
                    key_type: w.next()?.to_owned(),
                    blob: w.next()?.to_owned(),
                })
            })
            .collect()),
        1 => Ok(Vec::new()),
        other => Err(other),
    }
}

/// Whether `l` is the CA key itself (`ca_public` is `ssh-ed25519 <blob>`).
pub fn is_ca(l: &Listed, ca_public: &str) -> bool {
    let mut w = ca_public.split_whitespace();
    w.next() == Some(l.key_type.as_str()) && w.next() == Some(l.blob.as_str())
}

/// A listed certificate's key ID and serial (an OpenSSH Ed25519 certificate: type,
/// nonce, public key, serial, type, key ID).
pub fn cert_key_id(l: &Listed) -> Option<(String, u64)> {
    if !l.key_type.ends_with("-cert-v01@openssh.com") {
        return None;
    }
    let blob = crate::scan::base64_decode(&l.blob)?;
    let mut r = Reader(&blob);
    let _type = r.string()?;
    let _nonce = r.string()?;
    if l.key_type.starts_with("ssh-ed25519") {
        let _pk = r.string()?;
    } else {
        return None;
    }
    let serial = r.u64()?;
    let _cert_type = r.u32()?;
    let key_id = String::from_utf8(r.string()?.to_vec()).ok()?;
    Some((key_id, serial))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u32()?).ok()?;
        self.take(n)
    }
}
