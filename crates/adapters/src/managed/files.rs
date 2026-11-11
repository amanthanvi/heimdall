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
//! **Anchored (ADR-0008 §17.20 item 7; W3-S04).** Every write, clear and enumeration
//! goes through `heimdall_localenv::sys::ManagedDir` handles: the anchor (`data_dir`
//! or `runtime_dir`) is opened without following its last component, and each level
//! below it (`managed/<component>`, `b/<tag>`) relative to its verified parent. A
//! symlink or reparse point at any level is refused, never followed; an existing
//! directory that is not owner-only is refused with [`FilesError::Unsafe`]
//! (`managed_dir_unsafe`) and never repaired; nothing is removed through a directory
//! that was not verified. A missing level is created owner-only. The files stay public
//! (mode 0644, D10 item 2).
//!
//! **Atomic and generation-bound (§17.20 item 1; W3-R01, W3-S05).** Every file is
//! written to a fresh exclusive temporary name in its own directory and renamed over
//! its target (Windows: the M02 replace primitive when the target exists, a no-replace
//! move when it does not). Each directory carries a marker, [`GENERATION_FILE`],
//! `<generation> <binding-id>\n`, written **first** (a write claims the directory for
//! its generation) and removed **last** (a clear that stops half way is completed by
//! the next clear of the same generation). **A write is fenced by the marker**: a
//! generation older than the marker, or another holder at the same generation, is
//! refused before anything is written ([`FilesError::StaleGeneration`],
//! [`FilesError::OtherHolder`]). A clear of generation `g` removes nothing when the
//! marker names another generation, so a clear of `g` never touches `g + 1`. Every
//! marker read and the write or clear it decides are serialized by one lock in this
//! process. The renames are atomic one by one; the protocol is the marker fence plus
//! the slot's serialization and store re-validation in
//! [`super::effects::ManagedEffectsImpl`].
//!
//! Synchronous file work only: callers run it on the blocking pool
//! (`ManagedEffects::materialize`/`clear`).

use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use heimdall_contract::ids::{BindingId, DestinationId, EnvironmentId};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_credential::endpoints::{self, EndpointTag};
use heimdall_domain::scope::AccessPair;
pub use heimdall_localenv::projection::content::SlotPathRefused;
use heimdall_localenv::projection::content::{SlotPaths, managed_slot_paths, slot_component};
pub use heimdall_localenv::sys::MANAGED_DIR_UNSAFE;
use heimdall_localenv::sys::{ManagedDir, ManagedDirError, SysError};

/// The binding's K_env public-key file name (D6 item 1 step 6).
pub const BINDING_KEY_FILE: &str = "key.pub";

/// The generation marker in a binding directory or a slot directory:
/// `<generation> <binding-id>\n`.
pub const GENERATION_FILE: &str = ".generation";

/// The longest file this module reads back (a marker): anything larger is not ours.
const MARKER_MAX: usize = 256;

/// The slot directories' level under `data_dir`, as
/// `heimdall_localenv::projection::content::managed_slot_paths` names it (R1).
const SLOT_DIR: &str = "managed";

/// The `AdapterError::Protocol` text of a write refused by the marker fence: a newer
/// generation holds the directory (§17.20 item 1).
pub const STALE_GENERATION: &str = "stale_generation";
/// The `AdapterError::Protocol` text of a write refused by the marker fence: another
/// holder holds the same generation (§17.20 item 1).
pub const GENERATION_HOLDER_MISMATCH: &str = "generation_holder_mismatch";

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
    /// ⟨§17.20 item 7⟩ A directory (or a file name) is not safe to use: a symlink or
    /// reparse point, not a directory, or an existing directory that is not owner-only
    /// (`managed_dir_unsafe`). Nothing was followed or repaired.
    Unsafe(&'static str),
    /// ⟨§17.20 item 7⟩ A platform call on a verified directory failed.
    Sys(SysError),
    /// ⟨§17.20 item 1⟩ The directory's marker names this newer generation: an older
    /// write never replaces it.
    StaleGeneration(u64),
    /// ⟨§17.20 item 1⟩ Another holder's marker names the same generation.
    OtherHolder,
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
            FilesError::Unsafe(why) => write!(f, "{MANAGED_DIR_UNSAFE}: {why}"),
            FilesError::Sys(e) => write!(f, "managed file I/O: {e}"),
            FilesError::StaleGeneration(g) => {
                write!(f, "{STALE_GENERATION}: generation {g} holds the directory")
            }
            FilesError::OtherHolder => f.write_str(GENERATION_HOLDER_MISMATCH),
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

/// Serializes every write and clear of this module in this process (a marker read
/// and the write it fences are one step).
static FILES_LOCK: Mutex<()> = Mutex::new(());

fn marker_text(generation: u64, binding: &BindingId) -> String {
    format!("{generation} {}\n", binding.as_str())
}

fn from_dir(e: ManagedDirError) -> FilesError {
    match e {
        ManagedDirError::Unsafe(why) => FilesError::Unsafe(why),
        ManagedDirError::Sys(s) => FilesError::Sys(s),
    }
}

/// The levels of `dir` below `root` (each one plain name), or a refusal.
fn levels_below(root: &Path, dir: &Path) -> Result<Vec<String>, FilesError> {
    let refused = || FilesError::Directory(dir.to_path_buf());
    let rel = dir.strip_prefix(root).map_err(|_| refused())?;
    let levels = rel
        .components()
        .map(|c| match c {
            Component::Normal(n) => n.to_str().map(str::to_owned).ok_or_else(refused),
            _ => Err(refused()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if levels.is_empty() {
        return Err(refused());
    }
    Ok(levels)
}

/// Open the anchor `root` and then each of `levels`, each verified relative to its
/// parent (`heimdall_localenv::sys::ManagedDir`; ADR-0008 §17.20 item 7). With
/// `create`, missing levels are created owner-only and the anchor must exist;
/// without, `Ok(None)` when the anchor or a level is absent.
fn open_levels(
    root: &Path,
    levels: &[String],
    create: bool,
) -> Result<Option<ManagedDir>, FilesError> {
    let Some(mut dir) = ManagedDir::open_root(root).map_err(from_dir)? else {
        return if create {
            Err(FilesError::Directory(root.to_path_buf()))
        } else {
            Ok(None)
        };
    };
    for level in levels {
        match dir.child(level, create).map_err(from_dir)? {
            Some(d) => dir = d,
            None => return Ok(None),
        }
    }
    Ok(Some(dir))
}

/// The anchor and levels of a binding directory `<runtime_dir>/b/<16 hex>`.
fn binding_anchor(directory: &Path) -> Result<(PathBuf, Vec<String>), FilesError> {
    let refused = || FilesError::Directory(directory.to_path_buf());
    let tag = directory
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|t| tag_of(t).is_some())
        .ok_or_else(refused)?;
    let b = directory.parent().ok_or_else(refused)?;
    if b.file_name().and_then(|n| n.to_str()) != Some(endpoints::BINDING_DIR) {
        return Err(refused());
    }
    let root = b.parent().ok_or_else(refused)?;
    Ok((
        root.to_path_buf(),
        vec![endpoints::BINDING_DIR.to_owned(), tag.to_owned()],
    ))
}

/// The anchor and levels of a slot directory `<data_dir>/managed/<component>`.
fn slot_anchor(directory: &Path) -> Result<(PathBuf, Vec<String>), FilesError> {
    let refused = || FilesError::Directory(directory.to_path_buf());
    let component = directory
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(refused)?;
    let managed = directory.parent().ok_or_else(refused)?;
    if managed.file_name().and_then(|n| n.to_str()) != Some(SLOT_DIR) {
        return Err(refused());
    }
    let root = managed.parent().ok_or_else(refused)?;
    Ok((
        root.to_path_buf(),
        vec![SLOT_DIR.to_owned(), component.to_owned()],
    ))
}

/// The marker of `dir`: `Some((generation, binding text))`, `None` when absent;
/// `FilesError::Content` when it is not a marker (a symlink, another file, garbage).
fn read_marker(dir: &ManagedDir) -> Result<Option<(u64, String)>, FilesError> {
    let bytes = match dir.read(GENERATION_FILE, MARKER_MAX) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(ManagedDirError::Unsafe(_)) => return Err(FilesError::Content("marker")),
        Err(e) => return Err(from_dir(e)),
    };
    let text = String::from_utf8(bytes).map_err(|_| FilesError::Content("marker"))?;
    let line = text.strip_suffix('\n').unwrap_or(&text);
    let (generation, binding) = line.split_once(' ').ok_or(FilesError::Content("marker"))?;
    let generation = generation
        .parse::<u64>()
        .map_err(|_| FilesError::Content("marker"))?;
    Ok(Some((generation, binding.to_owned())))
}

/// Write the marker, then each `(name, content)`: the generation-bound write of one
/// directory (`path` is its path, for the returned names). **Fenced** (ADR-0008
/// §17.20 item 1): a generation older than the directory's marker, or another holder
/// at the same generation, is refused and nothing is written; so is a marker that is
/// not one. Returns the files written (marker excluded).
fn write_generation(
    dir: &ManagedDir,
    path: &Path,
    generation: u64,
    binding: &BindingId,
    files: &[(String, String)],
) -> Result<Vec<PathBuf>, FilesError> {
    match read_marker(dir)? {
        Some((g, _)) if g > generation => return Err(FilesError::StaleGeneration(g)),
        Some((g, b)) if g == generation && b != binding.as_str() => {
            return Err(FilesError::OtherHolder);
        }
        _ => {}
    }
    dir.write_replace(GENERATION_FILE, marker_text(generation, binding).as_bytes())
        .map_err(from_dir)?;
    files
        .iter()
        .map(|(name, content)| {
            dir.write_replace(name, content.as_bytes())
                .map_err(from_dir)
                .map(|()| path.join(name))
        })
        .collect()
}

/// Remove `names` and then the marker of `dir`, only if the marker names
/// `generation` (and `binding`, when given). Only through the verified handle.
fn clear_generation(
    dir: Option<&ManagedDir>,
    generation: u64,
    binding: Option<&BindingId>,
    names: &[String],
) -> Result<ClearOutcome, FilesError> {
    let Some(dir) = dir else {
        return Ok(ClearOutcome::Absent);
    };
    let marker = match read_marker(dir) {
        Ok(m) => m,
        Err(FilesError::Content(_)) => return Ok(ClearOutcome::Unmarked),
        Err(e) => return Err(e),
    };
    match marker {
        None => {
            for n in names {
                if dir.contains(n).map_err(from_dir)? {
                    return Ok(ClearOutcome::Unmarked);
                }
            }
            Ok(ClearOutcome::Absent)
        }
        Some((g, b)) if g == generation && binding.is_none_or(|x| x.as_str() == b) => {
            for n in names {
                dir.remove(n).map_err(from_dir)?;
            }
            dir.remove(GENERATION_FILE).map_err(from_dir)?;
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
    let (root, levels) = binding_anchor(&files.directory)?;
    let _guard = lock();
    let dir = open_levels(&root, &levels, true)?
        .ok_or_else(|| FilesError::Directory(files.directory.clone()))?;
    write_generation(&dir, &files.directory, generation, binding, &contents)
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
    let (root, levels) = binding_anchor(&files.directory)?;
    let _guard = lock();
    let Some(dir) = open_levels(&root, &levels, false)? else {
        return Ok(ClearOutcome::Absent);
    };
    let mut names = vec![BINDING_KEY_FILE.to_owned()];
    names.extend(
        files
            .certificates
            .iter()
            .filter_map(|(d, _)| binding_cert_name(d).ok()),
    );
    // Certificate files of destinations the caller no longer lists are ours too
    // when the marker names this generation.
    for n in dir.names().map_err(from_dir)? {
        if n.starts_with("cert-") && n.ends_with(".pub") && !names.contains(&n) {
            names.push(n);
        }
    }
    clear_generation(Some(&dir), generation, Some(binding), &names)
}

/// Every binding directory under `<runtime_dir>/b/` whose marker names `(generation,
/// binding)`: how a clear finds a binding's files after its endpoint is gone. The
/// enumeration is anchored (§17.20 item 7): an entry that is not a directory (a
/// symlink planted at a tag's name, a file) is never followed and never listed.
///
/// # Errors
/// [`FilesError::Unsafe`] (`managed_dir_unsafe`) when `<runtime_dir>/b` or one of its
/// directories is a symlink or not owner-only; [`FilesError`] for I/O.
pub fn binding_directories_of(
    runtime_dir: &Path,
    binding: &BindingId,
) -> Result<Vec<(PathBuf, u64)>, FilesError> {
    let mut out = Vec::new();
    let _guard = lock();
    let Some(b) = open_levels(runtime_dir, &[endpoints::BINDING_DIR.to_owned()], false)? else {
        return Ok(out);
    };
    for name in b.names().map_err(from_dir)? {
        if tag_of(&name).is_none() || !b.is_directory(&name).map_err(from_dir)? {
            continue;
        }
        let Some(dir) = b.child(&name, false).map_err(from_dir)? else {
            continue;
        };
        if let Ok(Some((g, holder))) = read_marker(&dir)
            && holder == binding.as_str()
        {
            out.push((runtime_dir.join(endpoints::BINDING_DIR).join(&name), g));
        }
    }
    out.sort();
    Ok(out)
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
/// Fenced by the marker (§17.20 item 1): an older generation, or another holder at
/// the same generation, is refused ([`FilesError::StaleGeneration`],
/// [`FilesError::OtherHolder`]).
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
    let levels = levels_below(&root.data_dir, &paths.dir)?;
    let _guard = lock();
    let dir = open_levels(&root.data_dir, &levels, true)?
        .ok_or_else(|| FilesError::Directory(paths.dir.clone()))?;
    write_generation(&dir, &paths.dir, generation, binding, &contents)
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
    let levels = levels_below(&root.data_dir, &paths.dir)?;
    let _guard = lock();
    let dir = open_levels(&root.data_dir, &levels, false)?;
    clear_generation(dir.as_ref(), generation, None, &names)
}

/// The slot directories under `<data_dir>/managed/` whose marker names `binding`,
/// with their generation (restart enumeration). Anchored as
/// [`binding_directories_of`]: an entry that is not a directory is never followed.
///
/// # Errors
/// As [`binding_directories_of`].
pub fn slots_written_by(
    data_dir: &Path,
    binding: &BindingId,
) -> Result<Vec<(PathBuf, u64)>, FilesError> {
    let mut out = Vec::new();
    let _guard = lock();
    let Some(managed) = open_levels(data_dir, &[SLOT_DIR.to_owned()], false)? else {
        return Ok(out);
    };
    for name in managed.names().map_err(from_dir)? {
        if !managed.is_directory(&name).map_err(from_dir)? {
            continue;
        }
        let Some(dir) = managed.child(&name, false).map_err(from_dir)? else {
            continue;
        };
        if let Ok(Some((g, holder))) = read_marker(&dir)
            && holder == binding.as_str()
        {
            out.push((data_dir.join(SLOT_DIR).join(&name), g));
        }
    }
    out.sort();
    Ok(out)
}

/// Remove the slot files in `dir` of `(generation, binding)` (a directory
/// [`slots_written_by`] returned), through its verified handle.
///
/// # Errors
/// [`FilesError`].
pub fn clear_slot_dir(
    dir: &Path,
    binding: &BindingId,
    generation: u64,
) -> Result<ClearOutcome, FilesError> {
    let (root, levels) = slot_anchor(dir)?;
    let names = vec!["key.pub".to_owned(), "cert.pub".to_owned()];
    let _guard = lock();
    let handle = open_levels(&root, &levels, false)?;
    clear_generation(handle.as_ref(), generation, Some(binding), &names)
}

/// The generation the slot files of `pair` carry, `None` when the slot has no marker
/// (free, or never written).
///
/// # Errors
/// [`FilesError`].
pub fn slot_generation(root: &SlotRoot, pair: &AccessPair) -> Result<Option<u64>, FilesError> {
    let paths = slot_paths(&root.data_dir, pair)?;
    let levels = levels_below(&root.data_dir, &paths.dir)?;
    let _guard = lock();
    match open_levels(&root.data_dir, &levels, false)? {
        Some(dir) => Ok(read_marker(&dir)?.map(|(g, _)| g)),
        None => Ok(None),
    }
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
    fn slot_dir_level_is_the_projections() {
        let p = managed_slot_paths(Path::new("/d"), &dest("dst-w")).unwrap();
        assert_eq!(p.dir, Path::new("/d").join(SLOT_DIR).join("dst-w"));
        assert_eq!(
            levels_below(Path::new("/d"), &p.dir).unwrap(),
            vec![SLOT_DIR.to_owned(), "dst-w".to_owned()]
        );
        assert_eq!(
            slot_anchor(&p.dir).unwrap(),
            (
                PathBuf::from("/d"),
                vec![SLOT_DIR.to_owned(), "dst-w".to_owned()]
            )
        );
        assert!(slot_anchor(Path::new("/d/other/dst-w")).is_err());
        let b = endpoints::binding_dir(
            Path::new("/r"),
            &EndpointTag::parse("0123456789abcdef").unwrap(),
        );
        assert_eq!(
            binding_anchor(&b).unwrap(),
            (
                PathBuf::from("/r"),
                vec![
                    endpoints::BINDING_DIR.to_owned(),
                    "0123456789abcdef".to_owned()
                ]
            )
        );
        assert!(binding_anchor(Path::new("/r/v/0123456789abcdef")).is_err());
        assert!(binding_anchor(Path::new("/r/b/xyz")).is_err());
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
