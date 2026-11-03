//! Client discovery (m02-plan U3; ADR-0007 §8 "The verified client"; ADR-0004 E6).
//!
//! Windows selects the in-box System32 client unless `config.toml` `[clients]` names
//! another; the PATH-first MSI client is recorded as a candidate, not chosen.
//!
//! Discovery is passive: it searches `PATH` from the [`Env`] snapshot (never the live
//! process environment), stats candidates, hashes the executables it found (a read),
//! and, only with [`LocalQueries::Enabled`], runs `<ssh> -V` (a local query, Q4). It
//! never runs a client with a configuration.
//!
//! **Encodings (ADR-0007 §4).** [`ClientInventory::accepts_bom_crlf`] answers from
//! [`ENCODING_OBSERVATIONS`], the table `integration_sshconf_vs_ssh_g::bom_and_crlf_acceptance`
//! fills per client: whether a user file with a BOM, and one with CRLF line endings,
//! loads with the include block B effective. A client without a row is "unknown",
//! which means `false` (manual mode, `unsupported_encoding`).

use std::io::Read;
use std::path::{Path, PathBuf};

use heimdall_sshconf::eval::OpenSshVersion;
use sha2::{Digest, Sha256};

use crate::env::{Env, Platform};
use crate::local_query::{LocalQueries, run_version};
use crate::paths::SshPaths;

/// Which client program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClientKind {
    /// `ssh`.
    Ssh,
    /// `scp`.
    Scp,
    /// `sftp`.
    Sftp,
    /// `git`.
    Git,
    /// `ssh-keygen`.
    SshKeygen,
}

impl ClientKind {
    /// Every kind, in report order.
    pub const ALL: [ClientKind; 5] = [
        ClientKind::Ssh,
        ClientKind::Scp,
        ClientKind::Sftp,
        ClientKind::Git,
        ClientKind::SshKeygen,
    ];

    /// The program's base name (without `.exe`).
    #[must_use]
    pub fn program(self) -> &'static str {
        match self {
            ClientKind::Ssh => "ssh",
            ClientKind::Scp => "scp",
            ClientKind::Sftp => "sftp",
            ClientKind::Git => "git",
            ClientKind::SshKeygen => "ssh-keygen",
        }
    }

    /// Whether the program is part of an OpenSSH installation.
    #[must_use]
    pub fn is_openssh(self) -> bool {
        !matches!(self, ClientKind::Git)
    }
}

/// Where a candidate was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientSource {
    /// `PATH`.
    Path,
    /// `%WINDIR%\System32\OpenSSH`.
    System32,
    /// Git for Windows' bundled MSYS client.
    GitBundled,
    /// `config.toml` `[clients]`.
    Configured,
}

/// One candidate executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCandidate {
    /// Which program.
    pub kind: ClientKind,
    /// Its path.
    pub path: PathBuf,
    /// Where it was found.
    pub source: ClientSource,
    /// Its version, when a local query ran.
    pub version: Option<OpenSshVersion>,
    /// SHA-256 of the executable, lowercase hex.
    pub sha256: Option<String>,
    /// Whether it is the client Heimdall selects.
    pub selected: bool,
}

/// `config.toml` `[clients]` (m02-plan §5 item 19): absolute paths to existing regular
/// files.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientsConfig {
    /// `ssh`.
    pub ssh: Option<PathBuf>,
    /// `scp`.
    pub scp: Option<PathBuf>,
    /// `sftp`.
    pub sftp: Option<PathBuf>,
    /// `git`.
    pub git: Option<PathBuf>,
    /// `ssh_keygen`.
    pub ssh_keygen: Option<PathBuf>,
}

impl ClientsConfig {
    /// The configured path for `kind`.
    #[must_use]
    pub fn get(&self, kind: ClientKind) -> Option<&Path> {
        match kind {
            ClientKind::Ssh => self.ssh.as_deref(),
            ClientKind::Scp => self.scp.as_deref(),
            ClientKind::Sftp => self.sftp.as_deref(),
            ClientKind::Git => self.git.as_deref(),
            ClientKind::SshKeygen => self.ssh_keygen.as_deref(),
        }
    }
}

/// Every candidate found, with the selection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientInventory {
    /// Candidates, selected ones marked.
    pub candidates: Vec<ClientCandidate>,
}

/// One row of the corpus observation table (ADR-0007 §4): whether this exact client
/// loads a user file whose block B sits after a UTF-8 BOM, and one with CRLF line
/// endings, with B effective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingObservation {
    /// The platform the client runs on.
    pub platform: Platform,
    /// Its exact version.
    pub version: OpenSshVersion,
    /// A file starting with a UTF-8 BOM loads with B effective.
    pub bom: bool,
    /// A file with CRLF line endings loads with B effective.
    pub crlf: bool,
}

/// The observations recorded by `integration_sshconf_vs_ssh_g::bom_and_crlf_acceptance`
/// (which fails when a listed client's behaviour differs from its row). Only rows
/// observed on a native run are listed; other clients answer `false`.
///
/// * macOS 27, system `OpenSSH_10.3p1` (M02-W2-U3, 2026-11-03): a BOM makes the first
///   line an unknown keyword and ssh refuses the file (exit 255); CRLF loads, B
///   effective.
pub const ENCODING_OBSERVATIONS: &[EncodingObservation] = &[EncodingObservation {
    platform: Platform::MacOs,
    version: OpenSshVersion {
        major: 10,
        minor: 3,
        portable: Some(1),
    },
    bom: false,
    crlf: true,
}];

impl ClientInventory {
    /// The selected client of `kind`.
    #[must_use]
    pub fn selected(&self, kind: ClientKind) -> Option<&ClientCandidate> {
        self.candidates
            .iter()
            .find(|c| c.kind == kind && c.selected)
    }

    /// Whether `client` loads a user file with a BOM or CRLF with B effective, from
    /// the U3 corpus observation table (ADR-0007 §4). Unknown means `false`.
    ///
    /// Both encodings must be accepted: a client with a row accepting only one of them
    /// answers `false` here (see [`ClientInventory::accepts_encoding`] for the finer
    /// question).
    #[must_use]
    pub fn accepts_bom_crlf(&self, client: &ClientCandidate) -> bool {
        self.accepts_encoding(client, true, true)
    }

    /// Whether `client` loads a user file with B effective when the file has a BOM
    /// (`bom`) and/or CRLF line endings (`crlf`), from [`ENCODING_OBSERVATIONS`] for
    /// this platform. A file with neither is always accepted; an unobserved client or
    /// a client without a known version answers `false` otherwise.
    #[must_use]
    pub fn accepts_encoding(&self, client: &ClientCandidate, bom: bool, crlf: bool) -> bool {
        if !bom && !crlf {
            return true;
        }
        if client.kind != ClientKind::Ssh {
            return false;
        }
        let Some(version) = client.version else {
            return false;
        };
        let platform = Platform::current();
        ENCODING_OBSERVATIONS
            .iter()
            .find(|row| row.platform == platform && row.version == version)
            .is_some_and(|row| (!bom || row.bom) && (!crlf || row.crlf))
    }
}

/// Discover the clients.
#[must_use]
pub fn resolve_clients(
    env: &Env,
    paths: &SshPaths,
    config: &ClientsConfig,
    queries: LocalQueries,
) -> ClientInventory {
    resolve_clients_on(env, paths, config, queries, Platform::current())
}

/// [`resolve_clients`] under `platform`'s rules (tests check the Windows selection
/// rules on any host with scratch files).
#[must_use]
pub fn resolve_clients_on(
    env: &Env,
    paths: &SshPaths,
    config: &ClientsConfig,
    queries: LocalQueries,
    platform: Platform,
) -> ClientInventory {
    let _ = paths;
    let mut candidates = Vec::new();
    for kind in ClientKind::ALL {
        let found = candidates_for(env, config, kind, platform);
        let chosen = chosen_index(&found, kind, platform);
        for (i, (path, source)) in found.into_iter().enumerate() {
            let version = if kind == ClientKind::Ssh && queries == LocalQueries::Enabled {
                run_version(&path).ok()
            } else {
                None
            };
            let sha256 = sha256_file(&path);
            candidates.push(ClientCandidate {
                kind,
                path,
                source,
                version,
                sha256,
                selected: chosen == Some(i),
            });
        }
    }
    // Versions of the other OpenSSH programs are the `ssh` beside them, when one is.
    let ssh_versions: Vec<(PathBuf, Option<OpenSshVersion>)> = candidates
        .iter()
        .filter(|c| c.kind == ClientKind::Ssh)
        .map(|c| (c.path.clone(), c.version))
        .collect();
    for c in candidates.iter_mut().filter(|c| {
        matches!(
            c.kind,
            ClientKind::Scp | ClientKind::Sftp | ClientKind::SshKeygen
        )
    }) {
        c.version = ssh_versions
            .iter()
            .find(|(p, _)| p.parent() == c.path.parent())
            .and_then(|(_, v)| *v);
    }
    ClientInventory { candidates }
}

/// The candidates for `kind`, in discovery order, without hashing or querying.
#[must_use]
pub fn candidates_for(
    env: &Env,
    config: &ClientsConfig,
    kind: ClientKind,
    platform: Platform,
) -> Vec<(PathBuf, ClientSource)> {
    let dirs = path_dirs(env);
    let mut found: Vec<(PathBuf, ClientSource)> = Vec::new();
    let mut push = |p: PathBuf, s: ClientSource| {
        if !found.iter().any(|(q, _)| *q == p) {
            found.push((p, s));
        }
    };
    if let Some(p) = config.get(kind)
        && p.is_absolute()
        && is_regular_file(p)
    {
        push(p.to_path_buf(), ClientSource::Configured);
    }
    if platform.is_windows()
        && kind.is_openssh()
        && let Some(p) = system32_client(env, kind)
    {
        push(p, ClientSource::System32);
    }
    if let Some(p) = search_path(&dirs, kind.program(), platform) {
        push(p, ClientSource::Path);
    }
    if platform.is_windows()
        && kind == ClientKind::Ssh
        && let Some(p) = git_bundled_ssh(&dirs, platform)
    {
        push(p, ClientSource::GitBundled);
    }
    found
}

/// Which candidate is selected: `[clients]` first; otherwise on Windows the System32
/// client for OpenSSH programs (ADR-0004 E6), and `PATH` for Git and on Unix.
fn chosen_index(
    found: &[(PathBuf, ClientSource)],
    kind: ClientKind,
    platform: Platform,
) -> Option<usize> {
    found
        .iter()
        .position(|(_, s)| *s == ClientSource::Configured)
        .or_else(|| {
            if platform.is_windows() && kind.is_openssh() {
                found.iter().position(|(_, s)| *s == ClientSource::System32)
            } else {
                found.iter().position(|(_, s)| *s == ClientSource::Path)
            }
        })
}

/// The selected client's path for `kind`, without hashing or querying.
#[must_use]
pub fn selected_path(env: &Env, config: &ClientsConfig, kind: ClientKind) -> Option<PathBuf> {
    let platform = Platform::current();
    let found = candidates_for(env, config, kind, platform);
    chosen_index(&found, kind, platform).map(|i| found[i].0.clone())
}

/// Whether `path` names an existing regular file (the `[clients]` rule).
#[must_use]
pub fn is_regular_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
}

/// `PATH` from the snapshot, absolute entries only (a relative entry would resolve
/// against the working directory).
fn path_dirs(env: &Env) -> Vec<PathBuf> {
    env.get("PATH")
        .map(|p| {
            std::env::split_paths(p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

fn exe_name(program: &str, platform: Platform) -> String {
    if platform.is_windows() {
        format!("{program}.exe")
    } else {
        program.to_owned()
    }
}

/// The first `PATH` entry holding `program` as a regular file.
#[must_use]
pub fn search_path(dirs: &[PathBuf], program: &str, platform: Platform) -> Option<PathBuf> {
    let name = exe_name(program, platform);
    dirs.iter()
        .map(|d| d.join(&name))
        .find(|p| is_regular_file(p))
}

fn system32_client(env: &Env, kind: ClientKind) -> Option<PathBuf> {
    let root = env
        .get("SystemRoot")
        .or_else(|| env.get("WINDIR"))
        .or_else(|| env.get("windir"))?;
    let p = PathBuf::from(root)
        .join("System32")
        .join("OpenSSH")
        .join(exe_name(kind.program(), Platform::Windows));
    is_regular_file(&p).then_some(p)
}

/// Git for Windows' own `ssh.exe`: `<git root>\usr\bin\ssh.exe`, where `git.exe` is
/// found in `<git root>\cmd`, `<git root>\bin` or `<git root>\mingw64\bin`.
#[must_use]
pub fn git_bundled_ssh(dirs: &[PathBuf], platform: Platform) -> Option<PathBuf> {
    let git = search_path(dirs, "git", platform)?;
    let bin = git.parent()?;
    let root = match bin
        .file_name()?
        .to_string_lossy()
        .to_ascii_lowercase()
        .as_str()
    {
        "cmd" | "bin" => {
            let up = bin.parent()?;
            if up
                .file_name()
                .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("mingw64"))
            {
                up.parent()?.to_path_buf()
            } else {
                up.to_path_buf()
            }
        }
        _ => return None,
    };
    let p = root.join("usr").join("bin").join(exe_name("ssh", platform));
    is_regular_file(&p).then_some(p)
}

/// Bytes hashed from one executable at most (a larger file gets no digest).
const MAX_HASH_BYTES: u64 = 512 << 20;

/// SHA-256 of a regular file, lowercase hex; `None` when unreadable or too large.
#[must_use]
pub fn sha256_file(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut reader = file.take(MAX_HASH_BYTES);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(hex(&hasher.finalize()))
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
    }

    fn scratch_paths(root: &Path) -> SshPaths {
        SshPaths::with_test_override(root.join("home"), root.join("etc-ssh"))
    }

    #[test]
    fn unix_rules_select_the_path_first_client_and_configured_wins() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        touch(&a.join("ssh"));
        touch(&b.join("ssh"));
        touch(&b.join("git"));
        let path = std::env::join_paths([&a, &b, &PathBuf::from("relative")]).unwrap();
        let env = Env::from_vars([("PATH", path)]);
        let none = ClientsConfig::default();
        let inv = resolve_clients_on(
            &env,
            &scratch_paths(dir.path()),
            &none,
            LocalQueries::Disabled,
            Platform::Linux,
        );
        let ssh = inv.selected(ClientKind::Ssh).unwrap();
        assert_eq!(ssh.path, a.join("ssh"));
        assert_eq!(ssh.source, ClientSource::Path);
        assert!(ssh.version.is_none(), "no local query when disabled");
        assert_eq!(ssh.sha256.as_deref().map(str::len), Some(64));
        assert_eq!(inv.selected(ClientKind::Git).unwrap().path, b.join("git"));
        assert!(inv.selected(ClientKind::Scp).is_none());

        let configured = ClientsConfig {
            ssh: Some(b.join("ssh")),
            ..ClientsConfig::default()
        };
        let inv = resolve_clients_on(
            &env,
            &scratch_paths(dir.path()),
            &configured,
            LocalQueries::Disabled,
            Platform::Linux,
        );
        let ssh = inv.selected(ClientKind::Ssh).unwrap();
        assert_eq!(ssh.path, b.join("ssh"));
        assert_eq!(ssh.source, ClientSource::Configured);
        // The PATH-first client stays a candidate, not selected.
        assert!(
            inv.candidates
                .iter()
                .any(|c| c.path == a.join("ssh") && !c.selected)
        );
    }

    #[test]
    fn windows_rules_select_system32_and_record_path_first_and_bundled_clients() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Windows");
        let system32 = root.join("System32").join("OpenSSH").join("ssh.exe");
        touch(&system32);
        let msi = dir.path().join("msi");
        touch(&msi.join("ssh.exe"));
        let git_root = dir.path().join("Git");
        touch(&git_root.join("cmd").join("git.exe"));
        touch(&git_root.join("usr").join("bin").join("ssh.exe"));
        let path = std::env::join_paths([&msi, &git_root.join("cmd")]).unwrap();
        let env = Env::from_vars([
            ("PATH", path),
            ("SystemRoot", root.clone().into_os_string()),
        ]);
        let inv = resolve_clients_on(
            &env,
            &scratch_paths(dir.path()),
            &ClientsConfig::default(),
            LocalQueries::Disabled,
            Platform::Windows,
        );
        let ssh: Vec<_> = inv
            .candidates
            .iter()
            .filter(|c| c.kind == ClientKind::Ssh)
            .collect();
        assert_eq!(ssh.len(), 3);
        let selected = inv.selected(ClientKind::Ssh).unwrap();
        assert_eq!(selected.source, ClientSource::System32);
        assert_eq!(selected.path, system32);
        assert!(
            ssh.iter()
                .any(|c| c.source == ClientSource::Path && !c.selected)
        );
        assert!(
            ssh.iter()
                .any(|c| c.source == ClientSource::GitBundled && !c.selected)
        );
        assert_eq!(
            inv.selected(ClientKind::Git).unwrap().source,
            ClientSource::Path
        );
    }

    #[test]
    fn encoding_acceptance_comes_only_from_observed_rows() {
        let inv = ClientInventory::default();
        let observed = ENCODING_OBSERVATIONS[0];
        let client = ClientCandidate {
            kind: ClientKind::Ssh,
            path: PathBuf::from("/usr/bin/ssh"),
            source: ClientSource::Path,
            version: Some(observed.version),
            sha256: None,
            selected: true,
        };
        // A file with neither encoding needs no row.
        assert!(inv.accepts_encoding(&client, false, false));
        let here = Platform::current() == observed.platform;
        assert_eq!(
            inv.accepts_encoding(&client, false, true),
            here && observed.crlf
        );
        assert_eq!(
            inv.accepts_encoding(&client, true, false),
            here && observed.bom
        );
        assert_eq!(
            inv.accepts_bom_crlf(&client),
            here && observed.bom && observed.crlf
        );
        let unknown = ClientCandidate {
            version: None,
            ..client.clone()
        };
        assert!(!inv.accepts_bom_crlf(&unknown));
        assert!(!inv.accepts_encoding(&unknown, false, true));
        let other = ClientCandidate {
            version: Some(OpenSshVersion {
                major: 1,
                minor: 0,
                portable: None,
            }),
            ..client
        };
        assert!(!inv.accepts_encoding(&other, false, true));
    }
}
