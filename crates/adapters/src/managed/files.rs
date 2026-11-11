//! ⟨M03⟩ The managed credential files (ADR-0008 D6 item 1 step 6, D10 items 1–2;
//! readings R1–R3): the per-binding files beside a binding endpoint and the
//! environment's pair slots.
//!
//! **Paths.** Every slot path comes from
//! `heimdall_localenv::projection::content::managed_slot_paths(data_dir, dest)` and
//! every path component from a destination from `content::slot_component` (an unsafe
//! ID refuses); `data_dir` is `Paths.state_dir` (R1). The binding directory is
//! `heimdall_credential::endpoints::binding_dir(runtime_dir, tag)` =
//! `<runtime_dir>/b/<16 hex>/` (R2), holding [`BINDING_KEY_FILE`] and one
//! `cert-<destination component>.pub` per destination ([`binding_cert_name`]).
//! [`binding_files_for_endpoint`] derives the same paths from the endpoint, byte for
//! byte as `heimdall::connect_cmd::binding_files` does (U8; reading R2).
//!
//! **Contents (R3).** Each certificate file holds exactly one OpenSSH certificate line
//! and `\n`: it is what `heimdall_sshconf::render::managed_identity_options` names as
//! the identity file (`CertificateAsIdentityFile`). `key.pub` holds K_env's public
//! line and `\n`; it is written (D6 step 6, the slot table) but nothing names it as an
//! identity.
//!
//! **Atomic and generation-bound.** Every file is written to a fresh temporary name in
//! its own directory and renamed over its target (Windows: the M02 replace primitive
//! `heimdall_localenv::sys::replace_file` when the target exists, `rename` when it does
//! not). Each directory carries a marker, [`GENERATION_FILE`], `<generation>
//! <binding-id>\n`, written **first** (a write claims the directory for its
//! generation) and removed **last** (a clear that stops half way is completed by the
//! next clear of the same generation). A clear of generation `g` removes nothing when
//! the marker names another generation, so a clear of `g` never touches `g + 1`.
//! Every write and clear in this process is serialized by one lock, so a clear cannot
//! interleave with the write of the next generation.
//!
//! Synchronous file work only: callers run it on the blocking pool
//! (`ManagedEffects::materialize`/`clear`).

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use heimdall_contract::ids::{BindingId, DestinationId, EnvironmentId};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_credential::endpoints::{self, EndpointTag};
use heimdall_domain::scope::AccessPair;
pub use heimdall_localenv::projection::content::SlotPathRefused;
use heimdall_localenv::projection::content::{SlotPaths, managed_slot_paths, slot_component};

/// The binding's K_env public-key file name (D6 item 1 step 6).
pub const BINDING_KEY_FILE: &str = "key.pub";

/// The generation marker in a binding directory or a slot directory:
/// `<generation> <binding-id>\n`.
pub const GENERATION_FILE: &str = ".generation";

/// The longest file this module reads back (a marker): anything larger is not ours.
const MARKER_MAX: u64 = 256;

/// `cert-<slot_component(dest)>.pub`: one binding certificate file's name.
///
/// # Errors
/// [`SlotPathRefused`]: the destination ID is not a safe path component.
pub fn binding_cert_name(dest: &DestinationId) -> Result<String, SlotPathRefused> {
    Ok(format!("cert-{}.pub", slot_component(dest)?))
}

/// A binding's files (what is, or is to be, on disk): pure paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindingFiles {
    /// `<runtime_dir>/b/<16 hex>`.
    pub directory: PathBuf,
    /// `<directory>/key.pub`.
    pub key_pub: PathBuf,
    /// One `<directory>/cert-<component>.pub` per destination, in the order given.
    pub certificates: Vec<(DestinationId, PathBuf)>,
}

impl BindingFiles {
    /// The certificate file of `dest`, if it is one of these files.
    #[must_use]
    pub fn certificate(&self, dest: &DestinationId) -> Option<&Path> {
        self.certificates
            .iter()
            .find(|(d, _)| d == dest)
            .map(|(_, p)| p.as_path())
    }

    fn in_directory(directory: PathBuf, dests: &[DestinationId]) -> Result<Self, SlotPathRefused> {
        let certificates = dests
            .iter()
            .map(|d| Ok((d.clone(), directory.join(binding_cert_name(d)?))))
            .collect::<Result<Vec<_>, SlotPathRefused>>()?;
        Ok(Self {
            key_pub: directory.join(BINDING_KEY_FILE),
            certificates,
            directory,
        })
    }
}

/// The files of the binding endpoint `tag` under `runtime_dir`, for `dests` (R2):
/// `endpoints::binding_dir(runtime_dir, tag)` / `key.pub` and `cert-<dest>.pub`.
///
/// # Errors
/// [`SlotPathRefused`] for an unsafe destination ID.
pub fn binding_files(
    runtime_dir: &Path,
    tag: &EndpointTag,
    dests: &[DestinationId],
) -> Result<BindingFiles, SlotPathRefused> {
    BindingFiles::in_directory(endpoints::binding_dir(runtime_dir, tag), dests)
}

/// 16 lowercase hex characters (an [`EndpointTag`]).
fn tag_of(text: &str) -> Option<EndpointTag> {
    EndpointTag::parse(text)
}

/// The binding files beside `endpoint` (R2), the same derivation as
/// `heimdall::connect_cmd::binding_files`:
/// * a Unix socket `<runtime_dir>/b/<16 hex>/agent.sock` → that directory;
/// * a Windows pipe `\\.\pipe\heimdall-<token>-b<16 hex>` →
///   `<runtime_dir>/b/<16 hex>`.
///
/// `None` when the endpoint is not a binding endpoint of this runtime (the
/// environment or a verification endpoint, another directory, a tag that is not 16
/// lowercase hex), or a destination ID is unsafe: fail closed.
#[must_use]
pub fn binding_files_for_endpoint(
    runtime_dir: &Path,
    endpoint: &EndpointRef,
    dests: &[DestinationId],
) -> Option<BindingFiles> {
    let directory = match endpoint.kind {
        EndpointKind::NamedPipe => {
            let name = endpoint.locator.strip_prefix(r"\\.\pipe\")?;
            let (_, hex) = name.strip_prefix("heimdall-")?.rsplit_once("-b")?;
            let tag = tag_of(hex)?;
            runtime_dir.join(endpoints::BINDING_DIR).join(tag.as_str())
        }
        EndpointKind::UnixSocket => {
            let socket = Path::new(&endpoint.locator);
            if socket.file_name()? != endpoints::AGENT_SOCKET {
                return None;
            }
            let dir = socket.parent()?;
            tag_of(dir.file_name()?.to_str()?)?;
            if dir.parent()? != runtime_dir.join(endpoints::BINDING_DIR) {
                return None;
            }
            dir.to_path_buf()
        }
        _ => return None,
    };
    BindingFiles::in_directory(directory, dests).ok()
}

// --- errors -----------------------------------------------------------------------

/// Why a managed file operation did not complete. Nonsecret: file names and OS error
/// kinds only, never content.
#[derive(Debug)]
#[non_exhaustive]
pub enum FilesError {
    /// The destination ID cannot name a path (U8-Q3).
    Path(SlotPathRefused),
    /// The content is not one public-key or certificate line.
    Content(&'static str),
    /// The directory is not a plain directory Heimdall can own (a symlink, a file).
    Directory(PathBuf),
    /// The pair is not in the binding's environment (`write_slot` for another
    /// environment's slot).
    Environment,
    /// An I/O failure.
    Io(io::Error),
}

impl std::fmt::Display for FilesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilesError::Path(e) => write!(f, "{e}"),
            FilesError::Content(what) => write!(f, "managed file content refused: {what}"),
            // The last component only: never a home path in an error.
            FilesError::Directory(p) => write!(
                f,
                "managed file directory is not a plain directory: {}",
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            FilesError::Environment => f.write_str("the slot belongs to another environment"),
            FilesError::Io(e) => write!(f, "managed file I/O: {:?}", e.kind()),
        }
    }
}

impl std::error::Error for FilesError {}

impl From<io::Error> for FilesError {
    fn from(e: io::Error) -> Self {
        FilesError::Io(e)
    }
}

impl From<SlotPathRefused> for FilesError {
    fn from(e: SlotPathRefused) -> Self {
        FilesError::Path(e)
    }
}

/// What a clear found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    /// The files of the generation were removed (or were already partly removed and
    /// the marker named it).
    Removed,
    /// Nothing was there: no marker and none of the files.
    Absent,
    /// The directory belongs to another generation (or holder): untouched.
    OtherGeneration(u64),
    /// Files exist without a readable marker: not provably this generation, so they
    /// are left untouched (fail closed).
    Unmarked,
}

// --- content checks -----------------------------------------------------------------

fn one_line(text: &str) -> Result<&str, FilesError> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() {
        return Err(FilesError::Content("empty"));
    }
    if line.len() > 16 * 1024 {
        return Err(FilesError::Content("too long"));
    }
    if line.bytes().any(|b| b == b'\n' || b == b'\r' || b == 0) {
        return Err(FilesError::Content("not one line"));
    }
    Ok(line)
}

fn key_type(line: &str) -> &str {
    line.split(' ').next().unwrap_or_default()
}

/// One OpenSSH public-key line that is not a certificate.
fn public_key_line(text: &str) -> Result<&str, FilesError> {
    let line = one_line(text)?;
    let kt = key_type(line);
    if kt.is_empty() || kt.contains("-cert-") || line.split(' ').nth(1).is_none() {
        return Err(FilesError::Content("not a public key line"));
    }
    Ok(line)
}

/// One OpenSSH certificate line.
fn certificate_line(text: &str) -> Result<&str, FilesError> {
    let line = one_line(text)?;
    if !key_type(line).ends_with("-cert-v01@openssh.com") || line.split(' ').nth(1).is_none() {
        return Err(FilesError::Content("not a certificate line"));
    }
    Ok(line)
}

// --- the primitives -----------------------------------------------------------------

/// Serializes every write and clear of this module in this process.
static FILES_LOCK: Mutex<()> = Mutex::new(());

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn marker_text(generation: u64, binding: &BindingId) -> String {
    format!("{generation} {}\n", binding.as_str())
}

/// The marker of `dir`: `Some((generation, binding text))`, `None` when absent.
fn read_marker(dir: &Path) -> Result<Option<(u64, String)>, FilesError> {
    let path = dir.join(GENERATION_FILE);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !meta.file_type().is_file() || meta.len() > MARKER_MAX {
        return Err(FilesError::Content("marker"));
    }
    let text = fs::read_to_string(&path)?;
    let line = text.strip_suffix('\n').unwrap_or(&text);
    let (generation, binding) = line.split_once(' ').ok_or(FilesError::Content("marker"))?;
    let generation = generation
        .parse::<u64>()
        .map_err(|_| FilesError::Content("marker"))?;
    Ok(Some((generation, binding.to_owned())))
}

/// Create `dir` (and parents) when absent; refuse anything but a plain directory.
fn ensure_dir(dir: &Path) -> Result<(), FilesError> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_dir() => return Ok(()),
        Ok(_) => return Err(FilesError::Directory(dir.to_path_buf())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        _ => Err(FilesError::Directory(dir.to_path_buf())),
    }
}

fn temp_name(target: &str) -> String {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{target}.tmp-{}-{n}", std::process::id())
}

/// Write `content` to `dir/name` atomically: a fresh temporary name in `dir`, synced,
/// then renamed over the target (Windows: `ReplaceFileW` when the target exists).
fn write_atomic(dir: &Path, name: &str, content: &[u8]) -> Result<PathBuf, FilesError> {
    let target = dir.join(name);
    let temp = temp_name(name);
    let temp_path = dir.join(&temp);
    let written = (|| -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut f = options.open(&temp_path)?;
        f.write_all(content)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&temp_path);
        return Err(e.into());
    }
    if let Err(e) = replace(dir, name, &temp) {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }
    Ok(target)
}

#[cfg(not(windows))]
fn replace(dir: &Path, name: &str, temp: &str) -> Result<(), FilesError> {
    fs::rename(dir.join(temp), dir.join(name))?;
    Ok(())
}

#[cfg(windows)]
fn replace(dir: &Path, name: &str, temp: &str) -> Result<(), FilesError> {
    match fs::symlink_metadata(dir.join(name)) {
        Ok(_) => {
            // The M02 replace primitive (ReplaceFileW with a backup name), as the
            // projection uses it (m03-plan §0.4 M4); the backup is removed after.
            let backup = temp_name(&format!("{name}.old"));
            heimdall_localenv::sys::replace_file(dir, name, temp, &backup)
                .map_err(|e| FilesError::Io(io::Error::other(e.to_string())))?;
            let _ = fs::remove_file(dir.join(backup));
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::rename(dir.join(temp), dir.join(name))?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn remove_if_present(path: &Path) -> Result<(), FilesError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Write the marker, then each `(name, content)`: the generation-bound write of one
/// directory. Returns the files written (marker excluded).
fn write_generation(
    dir: &Path,
    generation: u64,
    binding: &BindingId,
    files: &[(String, String)],
) -> Result<Vec<PathBuf>, FilesError> {
    ensure_dir(dir)?;
    write_atomic(
        dir,
        GENERATION_FILE,
        marker_text(generation, binding).as_bytes(),
    )?;
    files
        .iter()
        .map(|(name, content)| write_atomic(dir, name, content.as_bytes()))
        .collect()
}

/// Remove `names` and then the marker of `dir`, only if the marker names
/// `generation` (and `binding`, when given).
fn clear_generation(
    dir: &Path,
    generation: u64,
    binding: Option<&BindingId>,
    names: &[String],
) -> Result<ClearOutcome, FilesError> {
    if !exists(dir) {
        return Ok(ClearOutcome::Absent);
    }
    let marker = match read_marker(dir) {
        Ok(m) => m,
        Err(FilesError::Content(_)) => return Ok(ClearOutcome::Unmarked),
        Err(e) => return Err(e),
    };
    match marker {
        None => {
            if names.iter().any(|n| exists(&dir.join(n))) {
                Ok(ClearOutcome::Unmarked)
            } else {
                Ok(ClearOutcome::Absent)
            }
        }
        Some((g, b)) if g == generation && binding.is_none_or(|x| x.as_str() == b) => {
            for n in names {
                remove_if_present(&dir.join(n))?;
            }
            remove_if_present(&dir.join(GENERATION_FILE))?;
            Ok(ClearOutcome::Removed)
        }
        Some((g, _)) => Ok(ClearOutcome::OtherGeneration(g)),
    }
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    FILES_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

// --- binding files ------------------------------------------------------------------

/// Write a binding's files at `generation` (D6 item 1 step 6): the marker, `key.pub`
/// (K_env's public line) and one certificate file per `(destination, certificate
/// line)`. Every certificate's destination must be one of `files.certificates`.
///
/// # Errors
/// [`FilesError`]; a partial write is completed or cleared by the same generation.
pub fn write_binding_files(
    files: &BindingFiles,
    binding: &BindingId,
    generation: u64,
    key_pub: &str,
    certs: &[(DestinationId, String)],
) -> Result<Vec<PathBuf>, FilesError> {
    let key = public_key_line(key_pub)?;
    let mut contents = vec![(BINDING_KEY_FILE.to_owned(), format!("{key}\n"))];
    for (dest, cert) in certs {
        let line = certificate_line(cert)?;
        if files.certificate(dest).is_none() {
            return Err(FilesError::Content(
                "certificate for a destination not listed",
            ));
        }
        contents.push((binding_cert_name(dest)?, format!("{line}\n")));
    }
    let _guard = lock();
    write_generation(&files.directory, generation, binding, &contents)
}

/// Remove a binding's files of `generation` only (a newer generation's are left).
///
/// # Errors
/// [`FilesError`].
pub fn clear_binding_files(
    files: &BindingFiles,
    binding: &BindingId,
    generation: u64,
) -> Result<ClearOutcome, FilesError> {
    let mut names = vec![BINDING_KEY_FILE.to_owned()];
    names.extend(
        files
            .certificates
            .iter()
            .filter_map(|(d, _)| binding_cert_name(d).ok()),
    );
    // Certificate files of destinations the caller no longer lists are ours too
    // when the marker names this generation.
    if let Ok(entries) = fs::read_dir(&files.directory) {
        for e in entries.flatten() {
            if let Some(n) = e.file_name().to_str()
                && n.starts_with("cert-")
                && n.ends_with(".pub")
                && !names.iter().any(|x| x == n)
            {
                names.push(n.to_owned());
            }
        }
    }
    let _guard = lock();
    clear_generation(&files.directory, generation, Some(binding), &names)
}

/// Every binding directory under `<runtime_dir>/b/` whose marker names `(generation,
/// binding)`: how a clear finds a binding's files after its endpoint is gone.
#[must_use]
pub fn binding_directories_of(runtime_dir: &Path, binding: &BindingId) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(runtime_dir.join(endpoints::BINDING_DIR)) else {
        return out;
    };
    for e in entries.flatten() {
        let dir = e.path();
        let is_tag = e.file_name().to_str().and_then(tag_of).is_some();
        if !is_tag {
            continue;
        }
        if let Ok(Some((g, b))) = read_marker(&dir)
            && b == binding.as_str()
        {
            out.push((dir, g));
        }
    }
    out.sort();
    out
}

// --- slots ----------------------------------------------------------------------------

/// The slot paths of `pair` under `data_dir` (R1: `managed_slot_paths` only).
///
/// # Errors
/// [`SlotPathRefused`].
pub fn slot_paths(data_dir: &Path, pair: &AccessPair) -> Result<SlotPaths, SlotPathRefused> {
    managed_slot_paths(data_dir, &pair.destination)
}

/// The slot file names (marker excluded).
fn slot_names(paths: &SlotPaths) -> Vec<String> {
    [&paths.key_pub, &paths.cert_pub]
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
        .collect()
}

/// Where slots of one environment live: `data_dir` is `Paths.state_dir` (R1), one
/// environment per state directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRoot {
    /// `Paths.state_dir`.
    pub data_dir: PathBuf,
    /// The environment the state directory serves.
    pub environment: EnvironmentId,
}

/// Write `pair`'s slot at `generation` for `binding` (D10 item 2: `free(g) → held(b,
/// g + 1)`: the files are written, **then** the endpoint lists the key): the marker,
/// `key.pub` and `cert.pub` (the certificate the alias names as its identity, R3).
///
/// # Errors
/// [`FilesError`]; [`FilesError::Environment`] for another environment's slot.
pub fn write_slot(
    root: &SlotRoot,
    environment: &EnvironmentId,
    pair: &AccessPair,
    binding: &BindingId,
    generation: u64,
    key_pub: &str,
    cert: &str,
) -> Result<Vec<PathBuf>, FilesError> {
    if environment != &root.environment {
        return Err(FilesError::Environment);
    }
    let paths = slot_paths(&root.data_dir, pair)?;
    let key = public_key_line(key_pub)?;
    let cert = certificate_line(cert)?;
    let names = slot_names(&paths);
    let [key_name, cert_name] = names.as_slice() else {
        return Err(FilesError::Content("slot file names"));
    };
    let contents = vec![
        (key_name.clone(), format!("{key}\n")),
        (cert_name.clone(), format!("{cert}\n")),
    ];
    let _guard = lock();
    write_generation(&paths.dir, generation, binding, &contents)
}

/// Remove `pair`'s slot files of `generation` only (`clearing(g) → free(g)`); a slot
/// already written for another generation is untouched.
///
/// # Errors
/// [`FilesError`].
pub fn clear_slot(
    root: &SlotRoot,
    environment: &EnvironmentId,
    pair: &AccessPair,
    generation: u64,
) -> Result<ClearOutcome, FilesError> {
    if environment != &root.environment {
        return Err(FilesError::Environment);
    }
    let paths = slot_paths(&root.data_dir, pair)?;
    let names = slot_names(&paths);
    let _guard = lock();
    clear_generation(&paths.dir, generation, None, &names)
}

/// The slot directories under `<data_dir>/managed/` whose marker names `binding`,
/// with their generation: how `clear(binding, g)` finds the slots a binding wrote.
#[must_use]
pub fn slots_written_by(data_dir: &Path, binding: &BindingId) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(data_dir.join("managed")) else {
        return out;
    };
    for e in entries.flatten() {
        let dir = e.path();
        if let Ok(Some((g, b))) = read_marker(&dir)
            && b == binding.as_str()
        {
            out.push((dir, g));
        }
    }
    out.sort();
    out
}

/// Remove the slot files in `dir` of `(generation, binding)` (a directory
/// [`slots_written_by`] returned).
///
/// # Errors
/// [`FilesError`].
pub fn clear_slot_dir(
    dir: &Path,
    binding: &BindingId,
    generation: u64,
) -> Result<ClearOutcome, FilesError> {
    let names = vec!["key.pub".to_owned(), "cert.pub".to_owned()];
    let _guard = lock();
    clear_generation(dir, generation, Some(binding), &names)
}

/// The generation the slot files of `pair` carry, `None` when the slot has no marker
/// (free, or never written).
///
/// # Errors
/// [`FilesError`].
pub fn slot_generation(root: &SlotRoot, pair: &AccessPair) -> Result<Option<u64>, FilesError> {
    let paths = slot_paths(&root.data_dir, pair)?;
    if !exists(&paths.dir) {
        return Ok(None);
    }
    Ok(read_marker(&paths.dir)?.map(|(g, _)| g))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn dest(s: &str) -> DestinationId {
        DestinationId::parse(s).unwrap()
    }

    #[test]
    fn binding_cert_names_follow_the_slot_component() {
        assert_eq!(binding_cert_name(&dest("dst-w")).unwrap(), "cert-dst-w.pub");
        assert!(binding_cert_name(&dest("a:b")).is_err());
        assert!(binding_cert_name(&dest("Upper")).is_err());
    }

    #[test]
    fn content_checks() {
        assert!(public_key_line("ssh-ed25519 AAAA c\n").is_ok());
        assert!(public_key_line("ssh-ed25519-cert-v01@openssh.com AAAA").is_err());
        assert!(certificate_line("ssh-ed25519-cert-v01@openssh.com AAAA\n").is_ok());
        assert!(certificate_line("ssh-ed25519 AAAA").is_err());
        assert!(certificate_line("ssh-ed25519-cert-v01@openssh.com AAAA\nx").is_err());
        assert!(certificate_line("").is_err());
    }
}
