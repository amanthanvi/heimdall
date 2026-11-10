//! The owner-material digest (m03-plan U11 `owner_digest::OwnerDigest`, §0.2; ADR-0008
//! D13 item 4). Feature `fixtures`.
//!
//! Each harness records a SHA-256 digest of the owner's `~/.ssh` tree, the Git global
//! files and, on macOS, the **names** of `security list-keychains -d user`, before and
//! after the run, and fails on any change. This module is **read-only**: it never
//! writes, never follows a symlink, never opens a socket or a FIFO, and its `Debug`,
//! `Display` and panic messages carry **digests and component names only**, never a
//! path, a file name or content. Buffers read for hashing are overwritten afterwards.
//!
//! [`OwnerDigest::capture_tree`] digests the same components under any root (a scratch
//! tree for the fixture's own self-test).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ssh_key::HashAlg;

/// One digested component.
#[derive(Clone, PartialEq, Eq)]
pub struct Component {
    /// `ssh_tree`, `git_global` or `keychain_list`.
    pub name: &'static str,
    /// The lowercase hex SHA-256.
    pub sha256: String,
}

impl fmt::Debug for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.sha256)
    }
}

/// The digests of the owner's material at one moment.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerDigest {
    root: PathBuf,
    xdg: Option<PathBuf>,
    keychains: bool,
    components: Vec<Component>,
}

impl fmt::Debug for OwnerDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.components).finish()
    }
}

/// A changed component (names and digests only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChanged {
    /// The component.
    pub name: &'static str,
    /// Its digest before.
    pub before: String,
    /// Its digest after.
    pub after: String,
}

impl fmt::Display for DigestChanged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "owner material changed: {} {} -> {}",
            self.name, self.before, self.after
        )
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    HashAlg::Sha256
        .digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Append one length-prefixed field to a serialization.
fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The digest record of one path: kind, mode, length and a content digest (regular
/// files only; never following a symlink, whose target text is digested instead).
fn entry_record(path: &Path, rel: &[u8], out: &mut Vec<u8>) {
    field(out, rel);
    let Ok(meta) = fs::symlink_metadata(path) else {
        field(out, b"absent");
        return;
    };
    let kind: &[u8] = if meta.file_type().is_symlink() {
        b"symlink"
    } else if meta.is_dir() {
        b"dir"
    } else if meta.is_file() {
        b"file"
    } else {
        b"other"
    };
    field(out, kind);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        field(out, &meta.mode().to_be_bytes());
        field(out, &meta.uid().to_be_bytes());
    }
    if meta.is_file() {
        field(out, &meta.len().to_be_bytes());
        match fs::read(path) {
            Ok(mut bytes) => {
                field(out, sha256_hex(&bytes).as_bytes());
                bytes.fill(0);
            }
            Err(_) => field(out, b"unreadable"),
        }
    } else if meta.file_type().is_symlink() {
        match fs::read_link(path) {
            Ok(target) => field(
                out,
                sha256_hex(target.as_os_str().as_encoded_bytes()).as_bytes(),
            ),
            Err(_) => field(out, b"unreadable"),
        }
    }
}

/// Every entry under `dir` (recursively, symlinks not followed), sorted by relative
/// path bytes, recorded into one serialization.
fn tree_digest(dir: &Path) -> String {
    let mut paths = Vec::new();
    collect(dir, dir, &mut paths);
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    entry_record(dir, b".", &mut out);
    for (rel, path) in &paths {
        entry_record(path, rel, &mut out);
    }
    sha256_hex(&out)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(Vec<u8>, PathBuf)>) {
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        out.push((b"<unreadable-dir>".to_vec(), dir.to_path_buf()));
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .map(|p| p.as_os_str().as_encoded_bytes().to_vec())
            .unwrap_or_default();
        let is_dir = fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir());
        out.push((rel, path.clone()));
        if is_dir {
            collect(root, &path, out);
        }
    }
}

/// The Git global files under `home`: `.gitconfig`, `.config/git/config`,
/// `.config/git/ignore` and `.config/git/attributes` (`XDG_CONFIG_HOME` is honoured
/// only for the owner's real home).
fn git_digest(home: &Path, xdg: Option<&Path>) -> String {
    let config = xdg.map_or_else(|| home.join(".config"), Path::to_path_buf);
    let mut out = Vec::new();
    for (rel, path) in [
        (&b".gitconfig"[..], home.join(".gitconfig")),
        (b"git/config", config.join("git/config")),
        (b"git/ignore", config.join("git/ignore")),
        (b"git/attributes", config.join("git/attributes")),
    ] {
        entry_record(&path, rel, &mut out);
    }
    sha256_hex(&out)
}

/// The digest of `security list-keychains -d user`'s output (names only; read-only).
/// `unavailable` (digested) when the command cannot run.
fn keychain_digest() -> String {
    let out = Command::new("/usr/bin/security")
        .args(["list-keychains", "-d", "user"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => sha256_hex(&o.stdout),
        _ => sha256_hex(b"unavailable"),
    }
}

impl OwnerDigest {
    /// Digest the owner's material: `$HOME/.ssh`, the Git global files and, on macOS,
    /// the user keychain search list's names.
    ///
    /// # Errors
    /// `HOME` is unset or relative.
    pub fn capture() -> io::Result<OwnerDigest> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| io::Error::other("HOME is unset or relative"))?;
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());
        Ok(OwnerDigest::capture_with(
            &home,
            xdg.as_deref(),
            cfg!(target_os = "macos"),
        ))
    }

    /// Digest the same components under `root` (a scratch tree), without the keychain
    /// list.
    #[must_use]
    pub fn capture_tree(root: &Path) -> OwnerDigest {
        OwnerDigest::capture_with(root, None, false)
    }

    fn capture_with(home: &Path, xdg: Option<&Path>, keychains: bool) -> OwnerDigest {
        let mut components = vec![
            Component {
                name: "ssh_tree",
                sha256: tree_digest(&home.join(".ssh")),
            },
            Component {
                name: "git_global",
                sha256: git_digest(home, xdg),
            },
        ];
        if keychains {
            components.push(Component {
                name: "keychain_list",
                sha256: keychain_digest(),
            });
        }
        OwnerDigest {
            root: home.to_path_buf(),
            xdg: xdg.map(Path::to_path_buf),
            keychains,
            components,
        }
    }

    /// The components.
    #[must_use]
    pub fn components(&self) -> &[Component] {
        &self.components
    }

    /// Capture again (the same root and components) and list what changed.
    #[must_use]
    pub fn changes(&self) -> Vec<DigestChanged> {
        let now = OwnerDigest::capture_with(&self.root, self.xdg.as_deref(), self.keychains);
        self.components
            .iter()
            .zip(&now.components)
            .filter(|(a, b)| a.sha256 != b.sha256)
            .map(|(a, b)| DigestChanged {
                name: a.name,
                before: a.sha256.clone(),
                after: b.sha256.clone(),
            })
            .collect()
    }

    /// Panic (names and digests only) when anything changed since the capture.
    ///
    /// # Panics
    /// The owner's material changed.
    pub fn assert_unchanged(&self) {
        let changes = self.changes();
        assert!(
            changes.is_empty(),
            "{}",
            changes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
}
