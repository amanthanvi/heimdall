//! Client discovery (m02-plan U3; ADR-0007 §8 "The verified client"; ADR-0004 E6).
//!
//! Windows selects the in-box System32 client unless `config.toml` `[clients]` names
//! another; the PATH-first MSI client is recorded as a candidate, not chosen.

use std::path::{Path, PathBuf};

use heimdall_sshconf::eval::OpenSshVersion;

use crate::env::Env;
use crate::local_query::LocalQueries;
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

/// Every candidate found, with the selection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientInventory {
    /// Candidates, selected ones marked.
    pub candidates: Vec<ClientCandidate>,
}

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
    #[must_use]
    pub fn accepts_bom_crlf(&self, client: &ClientCandidate) -> bool {
        let _ = client;
        todo!("M02-U3 clients::ClientInventory::accepts_bom_crlf")
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
    let _ = (env, paths, config, queries);
    todo!("M02-U3 clients::resolve_clients")
}

/// Whether `path` names an existing regular file (the `[clients]` rule).
#[must_use]
pub fn is_regular_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file())
}
