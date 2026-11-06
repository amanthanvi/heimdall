//! The include loader and the read-only source port (m02-plan U1; ADR-0007 F3, F6,
//! F19).
//!
//! [`ConfigSource`] is the only way this crate reads anything. It has no method that
//! runs a command, and none is ever added: the `Match exec` tests use a fake that would
//! panic if asked (m02-plan U2). The real implementation is
//! `heimdall_localenv::fs::BoundedSource` (U3).
//!
//! # Include semantics (U1)
//!
//! From S01's `Include` entry (F3) and its TOKENS and ENVIRONMENT VARIABLES sections
//! (F7); the points S01 does not state are OpenSSH's `readconf.c` behaviour and are
//! marked `[I]` (the U3 corpus comparison against `ssh -G` settles them):
//!
//! * every argument is one pathname; each is expanded in order ([`expand_include_arg`]):
//!   `${VAR}` and the `%` tokens of S01's common set, in one left-to-right pass
//!   ([`expand`]). An unset variable is [`ArgError::EnvUnset`]; a token whose value
//!   the caller cannot supply is [`ArgError::TokenUnavailable`]; an unknown token, a
//!   trailing `%`, an unterminated or empty `${}` and an empty argument are
//!   [`ArgError::Invalid`] (ssh refuses the line `[I]`);
//! * a path that is not absolute resolves under the user directory (`~/.ssh`) when the
//!   including file belongs to the user tree, or under the system directory
//!   (`/etc/ssh`) when it belongs to the system tree ([`Origin`]). The tree is that of
//!   the root the walk started from: a `-F` file is a user file, so its relative
//!   includes resolve under `~/.ssh` too, not beside it `[I]`;
//! * `~` and `~/…` are the home [`ConfigSource::include_home`] reports, in user files
//!   only; `~` in a system file is refused `[I]`; `~user` needs the account database
//!   and is [`ArgError::TokenUnavailable`] with `'~'`. OpenSSH leaves an Include's `~`,
//!   and the implicit `~/.ssh/` it puts in front of a relative user Include, to
//!   `glob(3)` with `GLOB_TILDE`, which reads `$HOME` before the account database
//!   (observed on 10.3p1, ADR-0007 §12.17 item 9). F19 still holds for `%d`,
//!   `IdentityFile` and the other paths. So such an Include is resolved under the
//!   account home only when the runtime's `HOME` is that home (or unset, so `glob(3)`
//!   falls back to the account database); otherwise it is
//!   [`ArgError::EnvironmentReference`]: its resolution is undetermined, because the
//!   `HOME` of a later `ssh` is not known;
//! * the anchored pattern is expanded by [`ConfigSource::glob`]; the matches are
//!   sorted bytewise here whatever the source returned (F3 "lexical order", ADR-0007
//!   §6) and bounded by `Limits::glob_results`; no match is not an error (OpenSSH skips
//!   such an argument silently), so a missing literal file includes nothing;
//! * every match is read and walked in place, **even inside a `Host`/`Match` section
//!   that does not apply** (OpenSSH parses it with matching disabled `[I]`). After each
//!   included file the containing file's section state is restored (ADR-0007 §3 `[I]`);
//!   the evaluator does that in [`IncludeVisitor::leave`];
//! * bounds ([`Limits`]): an included file deeper than `depth` (a root is depth 0, so
//!   depth 17 is refused), more than `files` file reads in one walk (every inclusion
//!   counts, as OpenSSH re-reads a file each time it is included), more than
//!   `total_bytes` over those reads, a file over `file_bytes`, a line over
//!   `line_bytes`, and more than `glob_results` matches are each recorded as
//!   [`IncludeError::BoundExceeded`] (or the parse error), never truncated;
//! * a file that includes itself, directly or not (by canonical path), is
//!   [`IncludeError::Cycle`]; OpenSSH would recurse to its depth limit and fail.
//!
//! [`ConfigSet::load`] is the cache; [`walk`] is the whole-tree reader built on it,
//! driving an [`IncludeVisitor`]; [`record`] is a walk that records everything.
//! [`MemSource`] is an in-memory source for tests.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::directive::{self, Keyword, KnownKeyword};
use crate::limits::Limits;
use crate::parse::{ConfigFile, Line, SourceId, Span, parse_file};

/// Bytes read from one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBytes {
    /// The canonical path the bytes came from (the cache key).
    pub canonical: PathBuf,
    /// The file's bytes, at most `Limits::file_bytes`.
    pub bytes: Vec<u8>,
}

/// Why a source could not be read. Recorded as `IncludeUnreadable` or
/// `BoundExceeded`; never treated as an empty file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// No such file.
    #[error("not found")]
    NotFound,
    /// Not a regular file (a FIFO, a device, a directory).
    #[error("not a regular file")]
    NotRegular,
    /// Permission denied.
    #[error("permission denied")]
    PermissionDenied,
    /// Larger than the bound, or a glob with more results than the bound.
    #[error("bound exceeded")]
    BoundExceeded,
    /// Another I/O failure (redacted kind only).
    #[error("read failed: {0}")]
    Io(String),
}

/// Read-only access to configuration files and the facts OpenSSH expands.
pub trait ConfigSource {
    /// Read one file, following symlinks as OpenSSH does, regular files only.
    ///
    /// # Errors
    /// [`SourceError`].
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError>;
    /// Expand one `Include` pattern; results in bytewise order.
    ///
    /// # Errors
    /// [`SourceError`].
    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError>;
    /// The account's home directory (from the account database, never `$HOME`;
    /// ADR-0007 F19).
    fn account_home(&self) -> &Path;
    /// The user configuration directory (`~/.ssh`).
    fn user_dir(&self) -> &Path;
    /// The system configuration directory (`/etc/ssh`, `%PROGRAMDATA%\ssh`).
    fn system_dir(&self) -> &Path;
    /// An environment variable, for `${VAR}` expansion (F7). `None` when unset.
    fn env(&self, name: &str) -> Option<String>;

    /// The home an `Include`'s `~` and a relative user `Include`'s implicit `~/.ssh/`
    /// resolve under (ADR-0007 §12.17 item 9): OpenSSH expands both with `glob(3)`
    /// `GLOB_TILDE`, which reads `$HOME` first. `None` makes such an `Include`
    /// undetermined ([`ArgError::EnvironmentReference`]).
    ///
    /// The default is the account home when the runtime's `HOME` is unset (`glob(3)`
    /// then falls back to the account database) or names the account home exactly
    /// (component-wise; ASCII case aside on Windows), and `None` when `HOME` is set to
    /// anything else, the empty string and a relative path included. A source whose
    /// `env` cannot show every value (one that is not UTF-8) overrides this to compare
    /// the raw value, so such a `HOME` is never taken for an unset one
    /// (`heimdall_localenv::fs::BoundedSource` does).
    fn include_home(&self) -> Option<&Path> {
        let home = self.account_home();
        match self.env("HOME") {
            None => Some(home),
            Some(value) => home_matches(Path::new(&value), home).then_some(home),
        }
    }
}

/// Whether a `HOME` value names the account home: non-empty and equal component-wise
/// (ASCII-case-insensitively on Windows), so a relative value never matches an absolute
/// home. A trailing separator does not matter; anything else does (ADR-0007 §12.17
/// item 9, fail closed).
#[must_use]
pub fn home_matches(value: &Path, account_home: &Path) -> bool {
    !value.as_os_str().is_empty()
        && !account_home.as_os_str().is_empty()
        && same_path(value, account_home)
}

/// The user and system configuration files an evaluation starts from, and the file the
/// source role of Heimdall's own values is read from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Roots {
    /// The user file (`~/.ssh/config`, or `-F`), when present.
    pub user: Option<PathBuf>,
    /// The system file, when read (a `-F` file drops it, F6).
    pub system: Option<PathBuf>,
    /// P, the Heimdall-owned include file (ADR-0007 §12.15 item 3a). It is not a
    /// starting point: the user file's block B includes it. A file the walk reads whose
    /// path (as requested, or canonical) is this one has the role
    /// [`SourceRole::Managed`]; every other file has the role of its tree. `None`: no
    /// file is managed.
    pub managed: Option<PathBuf>,
}

impl Roots {
    /// Roots with the user and system files and no managed include file. Use this (or
    /// `..Roots::default()`) rather than a struct literal, so a field added later does
    /// not break the caller.
    #[must_use]
    pub fn new(user: Option<PathBuf>, system: Option<PathBuf>) -> Self {
        Self {
            user,
            system,
            managed: None,
        }
    }

    /// These roots with P's path set (see [`Roots::managed`]).
    #[must_use]
    pub fn with_managed(mut self, managed: impl Into<PathBuf>) -> Self {
        self.managed = Some(managed.into());
        self
    }
}

/// Why an include could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IncludeError {
    /// The source refused the read.
    #[error("include unreadable: {0}")]
    Unreadable(SourceError),
    /// A bound of [`Limits`] was exceeded.
    #[error("include bound exceeded")]
    BoundExceeded,
    /// The file includes itself, directly or not.
    #[error("include cycle")]
    Cycle,
    /// The file parsed with an error.
    #[error("include did not parse: {0}")]
    Parse(crate::parse::ParseError),
}

impl IncludeError {
    /// Whether this is a bound of [`Limits`] (`BoundExceeded`, and the parse errors for
    /// the per-file and per-line bounds), as opposed to an unreadable file, a cycle or a
    /// NUL byte. An evaluator records the former as `UnresolvedReason::BoundExceeded`.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        matches!(
            self,
            IncludeError::BoundExceeded
                | IncludeError::Unreadable(SourceError::BoundExceeded)
                | IncludeError::Parse(
                    crate::parse::ParseError::FileTooLarge
                        | crate::parse::ParseError::LineTooLong { .. }
                )
        )
    }
}

fn from_source(error: SourceError) -> IncludeError {
    match error {
        SourceError::BoundExceeded => IncludeError::BoundExceeded,
        other => IncludeError::Unreadable(other),
    }
}

#[derive(Debug, Clone)]
struct Cached {
    file: Arc<ConfigFile>,
    len: usize,
}

/// A cache of parsed files keyed by canonical path, shared by every evaluation of one
/// configuration tree.
///
/// The cache itself is bounded: at most `Limits::files` distinct files and
/// `Limits::total_bytes` bytes. A path is read once; a second path with the same
/// canonical path (a symlink) shares the parsed file. A failed load is not cached.
#[derive(Debug, Clone, Default)]
pub struct ConfigSet {
    files: BTreeMap<PathBuf, Cached>,
    next: u32,
    /// Every path a load succeeded for, to its canonical path.
    requested: BTreeMap<PathBuf, PathBuf>,
    /// The canonical path of each loaded file's id.
    paths: BTreeMap<SourceId, PathBuf>,
    /// ⟨M02⟩ The path each loaded file's id was first requested as (ADR-0007 §12.30
    /// item 10).
    written: BTreeMap<SourceId, PathBuf>,
    /// Bytes of every cached file.
    bytes: usize,
}

impl ConfigSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of files loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether nothing is loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// A loaded file by canonical path.
    #[must_use]
    pub fn get(&self, canonical: &Path) -> Option<&ConfigFile> {
        self.files.get(canonical).map(|c| &*c.file)
    }

    /// A loaded file by id.
    #[must_use]
    pub fn file(&self, id: SourceId) -> Option<&ConfigFile> {
        self.paths.get(&id).and_then(|p| self.get(p))
    }

    /// The canonical path of a loaded file (for `file:line` display).
    #[must_use]
    pub fn path_of(&self, id: SourceId) -> Option<&Path> {
        self.paths.get(&id).map(PathBuf::as_path)
    }

    /// ⟨M02⟩ ADR-0007 §12.30 item 10 (the §12.28 item 6 residual): the path a loaded
    /// file was first requested as, which is how the configuration names it (an
    /// `Include` match or a root, after expansion), never its canonical form. A file
    /// outside the account home is shown this way, so a link in its path (a symlinked
    /// directory, macOS `/var` against `/private/var`) is shown as written. The first
    /// request wins when two paths reach one file. `None` for an id this set did not
    /// load.
    #[must_use]
    pub fn written_path_of(&self, id: SourceId) -> Option<&Path> {
        self.written.get(&id).map(PathBuf::as_path)
    }

    /// The canonical path a successful load of `requested` resolved to.
    #[must_use]
    pub fn canonical(&self, requested: &Path) -> Option<&Path> {
        self.requested.get(requested).map(PathBuf::as_path)
    }

    /// Bytes of every cached file.
    #[must_use]
    pub fn loaded_bytes(&self) -> usize {
        self.bytes
    }

    /// The next unused [`SourceId`] (each loaded file gets one).
    pub fn next_source_id(&mut self) -> SourceId {
        let id = SourceId(self.next);
        self.next = self.next.saturating_add(1);
        id
    }

    /// Load and parse `path` through `source`, or return the cached copy.
    ///
    /// # Errors
    /// [`IncludeError`]: `Unreadable` with the source's reason (`NotFound` included:
    /// a missing file is never an empty one), `BoundExceeded` for a file over
    /// `Limits::file_bytes` or a full cache, `Parse` when the parser refuses the file.
    /// `Cycle` comes only from [`walk`], which knows the include chain.
    pub fn load(
        &mut self,
        source: &dyn ConfigSource,
        path: &Path,
        limits: &Limits,
    ) -> Result<&ConfigFile, IncludeError> {
        let (_, canonical, _) = self.load_shared(source, path, limits)?;
        self.get(&canonical)
            .ok_or_else(|| IncludeError::Unreadable(SourceError::Io("cache entry missing".into())))
    }

    /// [`ConfigSet::load`], returning a shared handle, the canonical path and the byte
    /// length (so a walk can recurse without borrowing the set).
    fn load_shared(
        &mut self,
        source: &dyn ConfigSource,
        path: &Path,
        limits: &Limits,
    ) -> Result<(Arc<ConfigFile>, PathBuf, usize), IncludeError> {
        if let Some(canonical) = self.requested.get(path)
            && let Some(cached) = self.files.get(canonical)
        {
            return Ok((Arc::clone(&cached.file), canonical.clone(), cached.len));
        }
        if self.files.len() >= limits.files {
            return Err(IncludeError::BoundExceeded);
        }
        let read = source.read(path).map_err(from_source)?;
        if let Some(cached) = self.files.get(&read.canonical) {
            let shared = (Arc::clone(&cached.file), read.canonical.clone(), cached.len);
            self.requested.insert(path.to_path_buf(), read.canonical);
            return Ok(shared);
        }
        let len = read.bytes.len();
        if len > limits.file_bytes || self.bytes.saturating_add(len) > limits.total_bytes {
            return Err(IncludeError::BoundExceeded);
        }
        let id = self.next_source_id();
        let file = Arc::new(parse_file(id, &read.bytes, limits).map_err(IncludeError::Parse)?);
        self.bytes += len;
        self.paths.insert(id, read.canonical.clone());
        self.written.insert(id, path.to_path_buf());
        self.requested
            .insert(path.to_path_buf(), read.canonical.clone());
        self.files.insert(
            read.canonical.clone(),
            Cached {
                file: Arc::clone(&file),
                len,
            },
        );
        Ok((file, read.canonical, len))
    }
}

// --- expansion ----------------------------------------------------------------------

/// Which configuration tree a file belongs to (F3): it decides where a relative
/// `Include` resolves and whether `~` is allowed. A file has the origin of the root its
/// walk started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// The user file (`~/.ssh/config` or a `-F` file) and what it includes.
    User,
    /// The system file and what it includes.
    System,
}

/// Where a value comes from, reduced to the four roles of ADR-0007 §5.2 (the digest
/// binds the role, never the file or the line).
///
/// A value read from a file has [`SourceRole::Managed`] (P, [`Roots::managed`]),
/// [`SourceRole::User`] (the user file and what it includes) or
/// [`SourceRole::System`] (the system file and what it includes). [`SourceRole::Default`]
/// is ssh's own default, which no file states: an identity-list entry for a default
/// identity file carries it; the evaluator gives no file value this role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceRole {
    /// Read from the Heimdall-owned include file P.
    Managed,
    /// Read from the user's file or a file it includes.
    User,
    /// Read from the system file or a file it includes.
    System,
    /// ssh's built-in default.
    Default,
}

impl SourceRole {
    /// The stable `snake_case` name (§5.2), which the digest binds.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SourceRole::Managed => "managed",
            SourceRole::User => "user",
            SourceRole::System => "system",
            SourceRole::Default => "default",
        }
    }

    /// The role of an ordinary file of this tree (P is told apart by its path).
    #[must_use]
    pub fn of_origin(origin: Origin) -> Self {
        match origin {
            Origin::User => SourceRole::User,
            Origin::System => SourceRole::System,
        }
    }
}

/// Whether two paths name the same file lexically: component-wise (so a doubled or
/// trailing separator does not matter), ASCII-case-insensitively on Windows.
fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        let lower = |p: &Path| {
            p.components()
                .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
                .collect::<Vec<_>>()
        };
        lower(a) == lower(b)
    } else {
        a == b
    }
}

/// Why OpenSSH refuses an argument outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidArg {
    /// An empty argument.
    EmptyArgument,
    /// `${` without a closing `}`.
    UnterminatedVariable,
    /// `${}`.
    EmptyVariable,
    /// A `%` token the keyword does not accept.
    UnknownToken(char),
    /// A `%` at the end.
    TrailingPercent,
    /// `~` in an `Include` of a system file.
    TildeInSystemFile,
}

impl InvalidArg {
    /// A stable `snake_case` reason (for `eval::Invalid::reason`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            InvalidArg::EmptyArgument => "empty_argument",
            InvalidArg::UnterminatedVariable => "unterminated_variable",
            InvalidArg::EmptyVariable => "empty_variable",
            InvalidArg::UnknownToken(_) => "unknown_token",
            InvalidArg::TrailingPercent => "trailing_percent",
            InvalidArg::TildeInSystemFile => "tilde_in_system_file",
        }
    }
}

impl std::fmt::Display for InvalidArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why one `Include` argument (or another expanded argument) reached no file list.
/// The messages never carry the argument's text or a variable's value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArgError {
    /// `${VAR}` names an unset variable (F7: the setting is ignored).
    #[error("environment variable unset")]
    EnvUnset(String),
    /// A `%` token (or `~user`, as `'~'`) whose value is not known statically.
    #[error("token unavailable")]
    TokenUnavailable(char),
    /// OpenSSH refuses the argument.
    #[error("invalid argument: {0}")]
    Invalid(InvalidArg),
    /// The pattern's glob failed or exceeded `Limits::glob_results`.
    #[error("include glob failed: {0}")]
    Glob(IncludeError),
    /// The argument's `~`, or the implicit `~/.ssh/` of a relative user `Include`,
    /// follows `$HOME`, and [`ConfigSource::include_home`] is `None` (the runtime's
    /// `HOME` is not the account home): the resolution is undetermined (ADR-0007
    /// §12.17 item 9; reason `environment_reference`).
    #[error("include depends on HOME")]
    EnvironmentReference,
}

/// Expand `${VAR}` (when [`directive::expands_env`]) and the `%` tokens of
/// [`directive::tokens`] in `text`, in OpenSSH's single left-to-right pass: a
/// variable's value is inserted verbatim and not expanded again, `%%` is `%`, and a
/// `$` not followed by `{` is literal.
///
/// `tokens` supplies the value of each accepted token letter at this point of the
/// evaluation, `None` when it is not known statically. `%d` falls back to
/// [`ConfigSource::account_home`] (F19).
///
/// # Errors
/// [`ArgError::Invalid`] first, for anything OpenSSH refuses anywhere in the text;
/// otherwise the first [`ArgError::EnvUnset`] or [`ArgError::TokenUnavailable`].
pub fn expand(
    text: &str,
    keyword: KnownKeyword,
    source: &dyn ConfigSource,
    tokens: &dyn Fn(char) -> Option<String>,
) -> Result<String, ArgError> {
    expand_with(text, keyword, source, tokens, Expansion::FULL)
}

/// Which expansions a client applies to an argument (ADR-0007 §12.32 item 11 (b)): the
/// pinned manual's (`FULL`), or none of `${VAR}` and the `%` tokens for a client
/// observed to take them literally (OpenSSH 9.6p1 for `User`, `SetEnv` and
/// `Include`; [`crate::client`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Expansion {
    /// `${VAR}` is expanded (when [`directive::expands_env`]); otherwise `$`, `{` and
    /// `}` are ordinary characters.
    pub env: bool,
    /// The `%` tokens of [`directive::tokens`] and `%%` are expanded; otherwise `%` is
    /// an ordinary character.
    pub tokens: bool,
}

impl Expansion {
    /// What the pinned manual describes.
    pub const FULL: Expansion = Expansion {
        env: true,
        tokens: true,
    };
    /// Neither `${VAR}` nor `%` is expanded.
    pub const LITERAL: Expansion = Expansion {
        env: false,
        tokens: false,
    };
}

/// [`expand`] for a client that applies only the expansions `expansion` allows (ADR-0007
/// §12.32 item 11 (b)).
///
/// # Errors
/// As [`expand`]; an expansion that is off cannot fail.
pub fn expand_with(
    text: &str,
    keyword: KnownKeyword,
    source: &dyn ConfigSource,
    tokens: &dyn Fn(char) -> Option<String>,
    expansion: Expansion,
) -> Result<String, ArgError> {
    let accepted = if expansion.tokens {
        directive::tokens(keyword)
    } else {
        &[]
    };
    let env = expansion.env && directive::expands_env(keyword);
    let mut out = String::with_capacity(text.len());
    let mut unresolved: Option<ArgError> = None;
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if env && let Some(after) = rest.strip_prefix("${") {
            let Some((name, tail)) = after.split_once('}') else {
                return Err(ArgError::Invalid(InvalidArg::UnterminatedVariable));
            };
            if name.is_empty() {
                return Err(ArgError::Invalid(InvalidArg::EmptyVariable));
            }
            match source.env(name) {
                Some(value) => out.push_str(&value),
                None => {
                    unresolved.get_or_insert_with(|| ArgError::EnvUnset(name.to_owned()));
                }
            }
            rest = tail;
            continue;
        }
        if !accepted.is_empty()
            && let Some(after) = rest.strip_prefix('%')
        {
            let mut chars = after.chars();
            match chars.next() {
                None => return Err(ArgError::Invalid(InvalidArg::TrailingPercent)),
                Some('%') => out.push('%'),
                Some(t) if accepted.contains(&t) => {
                    let value = tokens(t).or_else(|| {
                        if t == 'd' {
                            source.account_home().to_str().map(str::to_owned)
                        } else {
                            None
                        }
                    });
                    match value {
                        Some(value) => out.push_str(&value),
                        None => {
                            unresolved.get_or_insert(ArgError::TokenUnavailable(t));
                        }
                    }
                }
                Some(t) => return Err(ArgError::Invalid(InvalidArg::UnknownToken(t))),
            }
            rest = chars.as_str();
            continue;
        }
        out.push(c);
        rest = rest.get(c.len_utf8()..).unwrap_or_default();
    }
    match unresolved {
        Some(error) => Err(error),
        None => Ok(out),
    }
}

#[cfg(not(windows))]
fn is_separator(c: char) -> bool {
    c == '/'
}

#[cfg(windows)]
fn is_separator(c: char) -> bool {
    c == '/' || c == '\\'
}

/// OpenSSH's `path_absolute`: a leading `/` on Unix; on Windows also `\` or a drive
/// letter (`[I]` for the Win32 port).
#[cfg(not(windows))]
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

#[cfg(windows)]
fn is_absolute(path: &str) -> bool {
    path.starts_with(['/', '\\']) || path.as_bytes().get(1) == Some(&b':')
}

/// Expand one `Include` argument into the absolute pattern to glob (module
/// documentation: tokens and `${VAR}` first, then `~`, then the relative anchor).
///
/// `~` and the relative anchor of a user file (OpenSSH writes it `~/.ssh/<arg>`) need
/// [`ConfigSource::include_home`]; when it is `None` the argument is
/// [`ArgError::EnvironmentReference`] (ADR-0007 §12.17 item 9). With it, a relative
/// user argument resolves under [`ConfigSource::user_dir`] as before.
///
/// # Errors
/// [`ArgError`] (never [`ArgError::Glob`]).
pub fn expand_include_arg(
    arg: &str,
    origin: Origin,
    source: &dyn ConfigSource,
    tokens: &dyn Fn(char) -> Option<String>,
) -> Result<PathBuf, ArgError> {
    expand_include_arg_with(arg, origin, source, tokens, Expansion::FULL)
}

/// [`expand_include_arg`] for a client that applies only `expansion` to the argument
/// before `~`, the relative anchor and the glob (ADR-0007 §12.32 item 11 (b)).
///
/// # Errors
/// As [`expand_include_arg`].
pub fn expand_include_arg_with(
    arg: &str,
    origin: Origin,
    source: &dyn ConfigSource,
    tokens: &dyn Fn(char) -> Option<String>,
    expansion: Expansion,
) -> Result<PathBuf, ArgError> {
    if arg.is_empty() {
        return Err(ArgError::Invalid(InvalidArg::EmptyArgument));
    }
    let expanded = expand_with(arg, KnownKeyword::Include, source, tokens, expansion)?;
    if let Some(after) = expanded.strip_prefix('~') {
        if origin == Origin::System {
            return Err(ArgError::Invalid(InvalidArg::TildeInSystemFile));
        }
        if !(after.is_empty() || after.starts_with(is_separator)) {
            return Err(ArgError::TokenUnavailable('~'));
        }
        let tail = after.trim_start_matches(is_separator);
        let home = source
            .include_home()
            .ok_or(ArgError::EnvironmentReference)?;
        return Ok(if tail.is_empty() {
            home.to_path_buf()
        } else {
            home.join(tail)
        });
    }
    if is_absolute(&expanded) {
        return Ok(PathBuf::from(expanded));
    }
    let base = match origin {
        Origin::User => {
            source
                .include_home()
                .ok_or(ArgError::EnvironmentReference)?;
            source.user_dir()
        }
        Origin::System => source.system_dir(),
    };
    Ok(base.join(expanded))
}

/// Glob `pattern` through `source`, then sort the matches bytewise, drop duplicates,
/// and refuse more than `Limits::glob_results`. A source's `NotFound` is no match.
///
/// # Errors
/// [`IncludeError::BoundExceeded`], or [`IncludeError::Unreadable`] with the source's
/// reason.
pub fn glob_sorted(
    source: &dyn ConfigSource,
    pattern: &Path,
    limits: &Limits,
) -> Result<Vec<PathBuf>, IncludeError> {
    let mut found = match source.glob(pattern) {
        Ok(found) => found,
        Err(SourceError::NotFound) => Vec::new(),
        Err(error) => return Err(from_source(error)),
    };
    if found.len() > limits.glob_results {
        return Err(IncludeError::BoundExceeded);
    }
    found.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    found.dedup();
    Ok(found)
}

/// One argument of an `Include` directive, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeArg {
    /// The argument as written (after quote removal).
    pub written: String,
    /// The absolute pattern it expanded to; `None` when expansion failed.
    pub pattern: Option<PathBuf>,
    /// The matches in bytewise order (empty: nothing matched, which OpenSSH skips), or
    /// why there is no list.
    pub matches: Result<Vec<PathBuf>, ArgError>,
}

/// Expand and glob one `Include` argument ([`expand_include_arg`], [`glob_sorted`]).
#[must_use]
pub fn resolve_include_arg(
    arg: &str,
    origin: Origin,
    source: &dyn ConfigSource,
    tokens: &dyn Fn(char) -> Option<String>,
    limits: &Limits,
) -> IncludeArg {
    resolve_include_arg_with(arg, origin, source, tokens, limits, Expansion::FULL)
}

/// [`resolve_include_arg`] under `expansion` ([`expand_include_arg_with`]).
#[must_use]
pub fn resolve_include_arg_with(
    arg: &str,
    origin: Origin,
    source: &dyn ConfigSource,
    tokens: &dyn Fn(char) -> Option<String>,
    limits: &Limits,
    expansion: Expansion,
) -> IncludeArg {
    match expand_include_arg_with(arg, origin, source, tokens, expansion) {
        Ok(pattern) => {
            let matches = glob_sorted(source, &pattern, limits).map_err(ArgError::Glob);
            IncludeArg {
                written: arg.to_owned(),
                pattern: Some(pattern),
                matches,
            }
        }
        Err(error) => IncludeArg {
            written: arg.to_owned(),
            pattern: None,
            matches: Err(error),
        },
    }
}

// --- the walk ------------------------------------------------------------------------

/// One file being read by [`walk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visit {
    /// The file's id in the [`ConfigSet`].
    pub source: SourceId,
    /// Its canonical path.
    pub canonical: PathBuf,
    /// The tree it belongs to.
    pub origin: Origin,
    /// Its source role: [`SourceRole::Managed`] for P ([`Roots::managed`]), otherwise
    /// the role of its tree.
    pub role: SourceRole,
    /// 0 for a root, `n` for a file `n` includes deep.
    pub depth: usize,
}

/// What a [`walk`] reports, in OpenSSH's reading order. Every method has an empty
/// default.
///
/// For one `Include` line the order is: [`IncludeVisitor::line`] with the directive;
/// then per argument [`IncludeVisitor::include`]; then per match either
/// [`IncludeVisitor::enter`], the included file's lines, [`IncludeVisitor::leave`],
/// or [`IncludeVisitor::include_failed`]. An evaluator restores its section state in
/// `leave` (ADR-0007 §3).
pub trait IncludeVisitor {
    /// The value of `%token` at this point of the walk, `None` when it is not known
    /// statically (`%d` falls back to the account home).
    fn token(&self, token: char) -> Option<String> {
        let _ = token;
        None
    }
    /// The expansions the client applies to an `Include` argument ([`Expansion`];
    /// ADR-0007 §12.32 item 11 (b)). The default is the pinned manual's.
    fn include_expansion(&self) -> Expansion {
        Expansion::FULL
    }
    /// A file starts (a root, or an include).
    fn enter(&mut self, visit: &Visit) {
        let _ = visit;
    }
    /// One line of the current file.
    fn line(&mut self, visit: &Visit, line: &Line) {
        let _ = (visit, line);
    }
    /// One argument of the `Include` at `span` was resolved.
    fn include(&mut self, visit: &Visit, span: Span, arg: &IncludeArg) {
        let _ = (visit, span, arg);
    }
    /// A match of the `Include` at `span` could not be walked.
    fn include_failed(&mut self, visit: &Visit, span: Span, path: &Path, error: &IncludeError) {
        let _ = (visit, span, path, error);
    }
    /// The current file ended.
    fn leave(&mut self, visit: &Visit) {
        let _ = visit;
    }
    /// A root file could not be walked.
    fn root_failed(&mut self, origin: Origin, path: &Path, error: &IncludeError) {
        let _ = (origin, path, error);
    }
}

/// What one [`walk`] read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WalkSummary {
    /// File reads (every visit counts, cached or not).
    pub visits: usize,
    /// Bytes over those reads.
    pub bytes: usize,
}

struct Walker<'a> {
    set: &'a mut ConfigSet,
    source: &'a dyn ConfigSource,
    limits: &'a Limits,
    /// P's path ([`Roots::managed`]).
    managed: Option<&'a Path>,
    summary: WalkSummary,
    /// Canonical paths of the files being read, root first.
    chain: Vec<PathBuf>,
}

impl Walker<'_> {
    /// P is told apart by its path, as requested or canonical (a symlinked directory
    /// gives a different canonical spelling), or by the canonical path an earlier load
    /// of P's configured path resolved to.
    fn role_of(&self, requested: &Path, canonical: &Path, origin: Origin) -> SourceRole {
        let is_managed = self.managed.is_some_and(|m| {
            same_path(requested, m)
                || same_path(canonical, m)
                || self
                    .set
                    .canonical(m)
                    .is_some_and(|resolved| same_path(canonical, resolved))
        });
        if is_managed {
            SourceRole::Managed
        } else {
            SourceRole::of_origin(origin)
        }
    }

    fn visit(
        &mut self,
        visitor: &mut dyn IncludeVisitor,
        path: &Path,
        origin: Origin,
        depth: usize,
    ) -> Result<(), IncludeError> {
        if depth > self.limits.depth || self.summary.visits >= self.limits.files {
            return Err(IncludeError::BoundExceeded);
        }
        let (file, canonical, len) = self.set.load_shared(self.source, path, self.limits)?;
        if self.chain.contains(&canonical) {
            return Err(IncludeError::Cycle);
        }
        if self.summary.bytes.saturating_add(len) > self.limits.total_bytes {
            return Err(IncludeError::BoundExceeded);
        }
        self.summary.visits += 1;
        self.summary.bytes += len;
        let role = self.role_of(path, &canonical, origin);
        let visit = Visit {
            source: file.source,
            canonical: canonical.clone(),
            origin,
            role,
            depth,
        };
        self.chain.push(canonical);
        visitor.enter(&visit);
        for line in &file.lines {
            visitor.line(&visit, line);
            let Line::Directive(d) = line else { continue };
            if d.keyword != Keyword::Known(KnownKeyword::Include) {
                continue;
            }
            for written in &d.args {
                let arg = resolve_include_arg_with(
                    written,
                    origin,
                    self.source,
                    &|t| visitor.token(t),
                    self.limits,
                    visitor.include_expansion(),
                );
                visitor.include(&visit, d.span, &arg);
                let Ok(matches) = &arg.matches else { continue };
                for m in matches {
                    if let Err(error) = self.visit(visitor, m, origin, depth + 1) {
                        visitor.include_failed(&visit, d.span, m, &error);
                    }
                }
            }
        }
        visitor.leave(&visit);
        self.chain.pop();
        Ok(())
    }
}

/// Read the whole tree from `roots`, user file first then system file (F1), expanding
/// every `Include` in place under the bounds of `limits` (module documentation), and
/// report it to `visitor`. Reads only through `source`; executes nothing.
pub fn walk(
    set: &mut ConfigSet,
    source: &dyn ConfigSource,
    roots: &Roots,
    limits: &Limits,
    visitor: &mut dyn IncludeVisitor,
) -> WalkSummary {
    let mut walker = Walker {
        set,
        source,
        limits,
        managed: roots.managed.as_deref(),
        summary: WalkSummary::default(),
        chain: Vec::new(),
    };
    for (origin, root) in [(Origin::User, &roots.user), (Origin::System, &roots.system)] {
        let Some(path) = root else { continue };
        if let Err(error) = walker.visit(visitor, path, origin, 0) {
            visitor.root_failed(origin, path, &error);
        }
    }
    walker.summary
}

/// One `Include` argument met by [`record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeRecord {
    /// The `Include` line.
    pub span: Span,
    /// The including file's tree.
    pub origin: Origin,
    /// The argument and its resolution.
    pub arg: IncludeArg,
}

/// A file [`record`] could not walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkFailure {
    /// The `Include` line, `None` for a root.
    pub at: Option<Span>,
    /// The tree.
    pub origin: Origin,
    /// The path as matched or given.
    pub path: PathBuf,
    /// Why.
    pub error: IncludeError,
}

/// Everything one walk met, in reading order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalkRecord {
    /// Every file read, in order (a file included twice appears twice).
    pub visits: Vec<Visit>,
    /// Every `Include` argument, in order.
    pub includes: Vec<IncludeRecord>,
    /// Every file that could not be walked, in order.
    pub failures: Vec<WalkFailure>,
    /// The totals.
    pub summary: WalkSummary,
}

struct Recorder<'a> {
    tokens: &'a dyn Fn(char) -> Option<String>,
    expansion: Expansion,
    record: WalkRecord,
}

impl IncludeVisitor for Recorder<'_> {
    fn token(&self, token: char) -> Option<String> {
        (self.tokens)(token)
    }
    fn include_expansion(&self) -> Expansion {
        self.expansion
    }
    fn enter(&mut self, visit: &Visit) {
        self.record.visits.push(visit.clone());
    }
    fn include(&mut self, visit: &Visit, span: Span, arg: &IncludeArg) {
        self.record.includes.push(IncludeRecord {
            span,
            origin: visit.origin,
            arg: arg.clone(),
        });
    }
    fn include_failed(&mut self, visit: &Visit, span: Span, path: &Path, error: &IncludeError) {
        self.record.failures.push(WalkFailure {
            at: Some(span),
            origin: visit.origin,
            path: path.to_path_buf(),
            error: error.clone(),
        });
    }
    fn root_failed(&mut self, origin: Origin, path: &Path, error: &IncludeError) {
        self.record.failures.push(WalkFailure {
            at: None,
            origin,
            path: path.to_path_buf(),
            error: error.clone(),
        });
    }
}

/// [`walk`] with a visitor that records every visit, `Include` argument and failure,
/// taking token values from `tokens` (U3's snapshot; tests).
#[must_use]
pub fn record(
    set: &mut ConfigSet,
    source: &dyn ConfigSource,
    roots: &Roots,
    limits: &Limits,
    tokens: &dyn Fn(char) -> Option<String>,
) -> WalkRecord {
    record_with(set, source, roots, limits, tokens, Expansion::FULL)
}

/// [`record`] for a client that applies only `expansion` to `Include` arguments, so a
/// snapshot reads the files the evaluation of that client reads (ADR-0007 §12.32 item
/// 11 (b); [`crate::client::include_expansion`]).
#[must_use]
pub fn record_with(
    set: &mut ConfigSet,
    source: &dyn ConfigSource,
    roots: &Roots,
    limits: &Limits,
    tokens: &dyn Fn(char) -> Option<String>,
    expansion: Expansion,
) -> WalkRecord {
    let mut recorder = Recorder {
        tokens,
        expansion,
        record: WalkRecord::default(),
    };
    let summary = walk(set, source, roots, limits, &mut recorder);
    recorder.record.summary = summary;
    recorder.record
}

// --- the in-memory source ---------------------------------------------------------------

/// One entry of a [`MemSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemEntry {
    /// A regular file.
    File(Vec<u8>),
    /// A symbolic link to another path (relative targets resolve beside the link).
    Symlink(PathBuf),
    /// A FIFO: matched by globs, refused by reads as [`SourceError::NotRegular`].
    Fifo,
    /// A directory: likewise [`SourceError::NotRegular`].
    Directory,
    /// A file the account cannot read: [`SourceError::PermissionDenied`].
    Denied,
}

/// An in-memory [`ConfigSource`], for tests: no I/O, nothing run. Reads and globs are
/// counted.
///
/// Globbing follows `glob(3)` as OpenSSH calls it, over the stored paths: `*`, `?`,
/// `[…]`/`[!…]` with ranges, and (on Unix) `\` escapes, matched per `/`-separated
/// component, wildcards never matching `/` or a leading `.`; every entry kind is a
/// candidate (a FIFO or directory is returned and then refused by `read`). Paths are
/// compared as UTF-8, with `\` read as `/` on Windows.
#[derive(Debug, Clone, Default)]
pub struct MemSource {
    entries: BTreeMap<String, MemEntry>,
    account_home: PathBuf,
    user_dir: PathBuf,
    system_dir: PathBuf,
    env: BTreeMap<String, String>,
    reads: Cell<usize>,
    globs: Cell<usize>,
}

impl MemSource {
    /// An empty source with these directories and no environment.
    #[must_use]
    pub fn new(
        account_home: impl Into<PathBuf>,
        user_dir: impl Into<PathBuf>,
        system_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            account_home: account_home.into(),
            user_dir: user_dir.into(),
            system_dir: system_dir.into(),
            ..Self::default()
        }
    }

    /// Add or replace an entry.
    pub fn insert(&mut self, path: impl AsRef<Path>, entry: MemEntry) {
        self.entries.insert(mem_key(path.as_ref()), entry);
    }

    /// Remove an entry.
    pub fn remove(&mut self, path: impl AsRef<Path>) {
        self.entries.remove(&mem_key(path.as_ref()));
    }

    /// Builder form of [`MemSource::insert`] for a regular file.
    #[must_use]
    pub fn with_file(mut self, path: impl AsRef<Path>, bytes: impl Into<Vec<u8>>) -> Self {
        self.insert(path, MemEntry::File(bytes.into()));
        self
    }

    /// Builder form of [`MemSource::insert`].
    #[must_use]
    pub fn with_entry(mut self, path: impl AsRef<Path>, entry: MemEntry) -> Self {
        self.insert(path, entry);
        self
    }

    /// Builder: set an environment variable.
    #[must_use]
    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_owned(), value.to_owned());
        self
    }

    /// Calls to [`ConfigSource::read`] so far.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.reads.get()
    }

    /// Calls to [`ConfigSource::glob`] so far.
    #[must_use]
    pub fn globs(&self) -> usize {
        self.globs.get()
    }
}

/// A path as a [`MemSource`] key: lossy UTF-8, `\` read as `/` on Windows.
fn mem_key(path: &Path) -> String {
    let s = path.to_string_lossy();
    if cfg!(windows) {
        s.replace('\\', "/")
    } else {
        s.into_owned()
    }
}

impl ConfigSource for MemSource {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        self.reads.set(self.reads.get().saturating_add(1));
        let mut key = mem_key(path);
        // Follow at most 40 links, like the kernel's ELOOP bound.
        for _ in 0..=40 {
            match self.entries.get(&key) {
                None => return Err(SourceError::NotFound),
                Some(MemEntry::File(bytes)) => {
                    return Ok(SourceBytes {
                        canonical: PathBuf::from(key),
                        bytes: bytes.clone(),
                    });
                }
                Some(MemEntry::Fifo | MemEntry::Directory) => return Err(SourceError::NotRegular),
                Some(MemEntry::Denied) => return Err(SourceError::PermissionDenied),
                Some(MemEntry::Symlink(target)) => {
                    let target = mem_key(target);
                    key = if target.starts_with('/') || is_absolute(&target) {
                        target
                    } else {
                        let parent = key.rsplit_once('/').map_or("", |(p, _)| p);
                        format!("{parent}/{target}")
                    };
                }
            }
        }
        Err(SourceError::Io("too many levels of symbolic links".into()))
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        self.globs.set(self.globs.get().saturating_add(1));
        let pattern = mem_key(pattern);
        Ok(self
            .entries
            .keys()
            .filter(|name| glob_match(&pattern, name))
            .map(PathBuf::from)
            .collect())
    }

    fn account_home(&self) -> &Path {
        &self.account_home
    }

    fn user_dir(&self) -> &Path {
        &self.user_dir
    }

    fn system_dir(&self) -> &Path {
        &self.system_dir
    }

    fn env(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }
}

/// `fnmatch(pattern, name, FNM_PATHNAME | FNM_PERIOD)` over `/`-separated paths, as
/// `glob(3)` applies it component by component (the [`MemSource`] matcher).
#[doc(hidden)]
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let mut p = pattern.split('/');
    let mut n = name.split('/');
    loop {
        match (p.next(), n.next()) {
            (None, None) => return true,
            (Some(pc), Some(nc)) if component_match(pc, nc) => {}
            _ => return false,
        }
    }
}

fn component_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    if n.first() == Some(&'.') {
        let literal_dot = p.first() == Some(&'.')
            || (cfg!(not(windows)) && p.first() == Some(&'\\') && p.get(1) == Some(&'.'));
        if !literal_dot {
            return false;
        }
    }
    let (mut pi, mut ni) = (0, 0);
    // The pattern index after the last `*` and the name index it is matched up to.
    let mut star: Option<(usize, usize)> = None;
    while let Some(&c) = n.get(ni) {
        if p.get(pi) == Some(&'*') {
            star = Some((pi + 1, ni));
            pi += 1;
            continue;
        }
        if let Some(width) = single(&p, pi, c) {
            pi += width;
            ni += 1;
            continue;
        }
        match star {
            Some((after, upto)) => {
                pi = after;
                ni = upto + 1;
                star = Some((after, upto + 1));
            }
            None => return false,
        }
    }
    while p.get(pi) == Some(&'*') {
        pi += 1;
    }
    pi == p.len()
}

/// Whether the pattern element at `pi` (not `*`) matches `c`, and its width.
fn single(p: &[char], pi: usize, c: char) -> Option<usize> {
    let &head = p.get(pi)?;
    match head {
        '?' => Some(1),
        '[' => match class(p, pi, c) {
            Some((matched, width)) => matched.then_some(width),
            // An unclosed `[` is a literal.
            None => (c == '[').then_some(1),
        },
        '\\' if cfg!(not(windows)) => match p.get(pi + 1) {
            Some(&escaped) => (escaped == c).then_some(2),
            None => (c == '\\').then_some(1),
        },
        literal => (literal == c).then_some(1),
    }
}

/// A bracket expression at `start`: whether it matches `c` and its width, or `None`
/// when it is not closed.
fn class(p: &[char], start: usize, c: char) -> Option<(bool, usize)> {
    let mut j = start + 1;
    let negate = p.get(j) == Some(&'!');
    if negate {
        j += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let &lo = p.get(j)?;
        if lo == ']' && !first {
            break;
        }
        first = false;
        match (p.get(j + 1), p.get(j + 2)) {
            (Some('-'), Some(&hi)) if hi != ']' => {
                if lo <= c && c <= hi {
                    matched = true;
                }
                j += 3;
            }
            _ => {
                if lo == c {
                    matched = true;
                }
                j += 1;
            }
        }
    }
    Some((matched != negate, j + 1 - start))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("/a/*.conf", "/a/x.conf"));
        assert!(!glob_match("/a/*.conf", "/a/.x.conf"));
        assert!(glob_match("/a/.*", "/a/.x"));
        assert!(!glob_match("/a/*", "/a/b/c"));
        assert!(glob_match("/a/?/c", "/a/b/c"));
        assert!(glob_match("/a/[a-c]", "/a/b"));
        assert!(!glob_match("/a/[!a-c]", "/a/b"));
        assert!(glob_match("/a/[]]", "/a/]"));
        assert!(glob_match("/a/[", "/a/["));
        assert!(glob_match("/a/x*y*z", "/a/xaybz"));
        assert!(!glob_match("/a/x*y*z", "/a/xaybza"));
    }

    #[test]
    fn mem_source_symlink_and_kinds() {
        let src = MemSource::new("/h", "/h/.ssh", "/etc/ssh")
            .with_file("/h/real", b"Host a\n".to_vec())
            .with_entry("/h/link", MemEntry::Symlink("real".into()))
            .with_entry("/h/fifo", MemEntry::Fifo)
            .with_entry("/h/loop", MemEntry::Symlink("/h/loop".into()));
        let got = src.read(Path::new("/h/link")).unwrap();
        assert_eq!(got.canonical, PathBuf::from("/h/real"));
        assert_eq!(src.read(Path::new("/h/fifo")), Err(SourceError::NotRegular));
        assert_eq!(src.read(Path::new("/h/none")), Err(SourceError::NotFound));
        assert!(matches!(
            src.read(Path::new("/h/loop")),
            Err(SourceError::Io(_))
        ));
        assert_eq!(src.reads(), 4);
    }

    /// ADR-0007 §12.30 item 10: a file loaded through a link keeps the path it was
    /// requested as (`written_path_of`), beside its canonical path (`path_of`); a second
    /// path to the same file shares it and keeps the first written path; an id the set
    /// did not load has none.
    #[test]
    fn written_path_is_the_path_as_requested_never_the_canonical_one() {
        let src = MemSource::new("/h", "/h/.ssh", "/etc/ssh")
            .with_file("/outside/real.conf", b"Host a\n".to_vec())
            .with_entry("/outside/link.conf", MemEntry::Symlink("real.conf".into()))
            .with_entry("/outside/again", MemEntry::Symlink("real.conf".into()));
        let mut set = ConfigSet::new();
        let limits = Limits::default();
        let id = set
            .load(&src, Path::new("/outside/link.conf"), &limits)
            .unwrap()
            .source;
        assert_eq!(
            set.path_of(id),
            Some(Path::new("/outside/real.conf")),
            "canonical"
        );
        assert_eq!(
            set.written_path_of(id),
            Some(Path::new("/outside/link.conf")),
            "as written"
        );
        let again = set
            .load(&src, Path::new("/outside/again"), &limits)
            .unwrap()
            .source;
        assert_eq!(again, id, "one file, one id");
        assert_eq!(
            set.written_path_of(id),
            Some(Path::new("/outside/link.conf")),
            "the first request wins"
        );
        assert_eq!(set.written_path_of(SourceId(u32::MAX)), None);
    }
}
