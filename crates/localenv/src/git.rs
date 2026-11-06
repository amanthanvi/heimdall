//! Git observation (m02-plan U3; ADR-0007 §5.6, §8, F22).
//!
//! A configuration value never leaves these functions: they return scope, origin, a
//! value digest and a classification. Queries run with `--includes`, and the include
//! graph of the system file and both global files is walked with
//! `heimdall_sshconf::gitedit::scan` (bounded: 1 MiB per file, 64 files, depth 10).
//!
//! **Observation** ([`observe_global`]) unions two sources:
//!
//! * the local queries of §5.6, `git config --system|--global --includes --show-origin
//!   -z --get-all core.sshCommand`, run with the caller's environment snapshot, stdin
//!   null, no shell, 2 s, and the filesystem root as the working directory, so no
//!   repository's local scope or `includeIf` condition can apply;
//! * the static scan of the system file, both global files and every file they
//!   include, conditionally or not (§5.6, M2-R08). Each `core.sshCommand` key is
//!   counted; its value is read from the key's line only to digest it, then dropped.
//!   An include that cannot be read, resolved or bounded makes the observation list
//!   it in `unreadable` (the item is then `not_applicable`, `git_config_unreadable`).
//!   A missing include file is skipped, as Git skips it.
//!
//! Per origin, the count is the larger of the two sources' counts; an entry reached
//! through `includeIf` is `conditional`.
//!
//! **Heimdall's own value** (ADR-0007 §12.34 item 8): once the Git item is applied, the
//! global file's B_git includes P_git, which holds one `core.sshCommand`.
//! [`observe_global`] counts it like any other value.
//! [`observe_global_for`] takes P_git's path and splits that one occurrence out as
//! [`GitGlobalObservation::own_values`], so neither a setup preview nor the doctor takes
//! Heimdall's own value for a user's. Both then judge it from the global files' bytes:
//! it is Heimdall's own only when an intact B_git links it in ([`holds_include`]; the
//! doctor's whole-file form is [`managed_include_present`]). When Heimdall's value is the
//! effective one ([`winning_origin`]) and a user's is in another global file, the doctor
//! reports `git_user_value_shadowed` (ADR-0007 §12.37).
//!
//! **`[I]` observed on Apple Git 2.54 (M02-W2-U3) and on git 2.43.0 (M02 wave 5c, the
//! same plain-Git script on both: `tests/evidence/artifacts/m02/git-2.43/`, identical
//! output apart from the version line):** `git config --global` reads only
//! `~/.gitconfig` when that file is readable and the XDG file only otherwise, so the
//! `--global` query misses a value in the XDG file whenever both exist (ADR-0007 F22
//! assumed both are read). The static scan reads both files, so the observation still
//! counts it. The system file's path comes from `git var GIT_CONFIG_SYSTEM` (Git
//! ≥ 2.42) or `GIT_CONFIG_SYSTEM`; when neither can say, the system scope counts as
//! unreadable (fail closed).
//!
//! **Run-time selection** ([`resolve_run_selection`], §8): `GIT_SSH_COMMAND`, then
//! `core.sshCommand` at its winning scope (`git -C <cwd> config --show-scope -z --get
//! core.sshCommand` with the child's environment), then `GIT_SSH`, then Git's default.

use std::path::{Path, PathBuf};

use heimdall_contract::doctor::{
    GitScope, GitSshClassification, GitSshSelection, GitSshSource, GitValueObservation,
};
use heimdall_contract::setup::{GitFileResolution, GitGlobalFileKind};
use heimdall_sshconf::edit;
use heimdall_sshconf::gitedit;
use heimdall_sshconf::render::{self, Newline, RenderError, RenderPath};
use sha2::{Digest, Sha256};

use crate::clients::{ClientInventory, ClientKind, git_bundled_ssh, hex, search_path};
use crate::env::{Env, Platform};
use crate::local_query::{
    LOCAL_QUERY_OUTPUT_BYTES, LOCAL_QUERY_TIMEOUT, LocalQueries, Spec, run_contained,
};
use crate::paths::display_path;

/// Bytes read per Git configuration file during the include walk.
pub const GIT_WALK_FILE_BYTES: usize = 1 << 20;
/// Files read by one include walk.
pub const GIT_WALK_FILES: usize = 64;
/// Include depth of one walk.
pub const GIT_WALK_DEPTH: usize = 10;

/// The environment variables that override Git's SSH selection or its configuration
/// files, reported by name only.
pub const GIT_ENV_OVERRIDES: &[&str] = &[
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_SSH_VARIANT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG",
];

/// The global file B_git goes into, under the first-read rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalFileResolution {
    /// The file.
    pub path: PathBuf,
    /// Which of the two global files.
    pub file: GitGlobalFileKind,
    /// How it was chosen.
    pub rule: GitFileResolution,
}

/// Git's default SSH program on this platform, when nothing overrides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultGitSsh {
    /// `ssh` from `PATH`.
    PathSsh,
    /// Git for Windows' bundled MSYS ssh.
    BundledMsys(PathBuf),
    /// Not established (no Git, or local queries off).
    Undetermined,
}

/// What the global Git configuration says about `core.sshCommand`, by digest only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitGlobalObservation {
    /// The global file B_git would go into (`None` when `GIT_CONFIG_GLOBAL`
    /// redirects it: manual mode, `git_global_redirected`).
    pub file: Option<GlobalFileResolution>,
    /// Every `core.sshCommand` occurrence in the system and global scopes, includes
    /// and conditional includes counted. From [`observe_global_for`], without the
    /// occurrences that are [`Self::own_values`].
    pub values: Vec<GitValueObservation>,
    /// ADR-0007 §12.34 item 8, additive: the occurrences that are Heimdall's own P_git
    /// as B_git includes it, split out of [`Self::values`] by [`observe_global_for`].
    /// An occurrence is Heimdall's own only when the managed file was counted exactly
    /// once in all (no second key, no second path to it, not from the system file) and
    /// that one is global and was not reached through an `includeIf`. Always empty from
    /// [`observe_global`], which counts every occurrence in `values`. Whether the
    /// include that reaches the file is B_git, intact and naming that file, is the
    /// caller's to establish from the global file's bytes: until it has, these
    /// occurrences are present values like any other.
    pub own_values: Vec<GitValueObservation>,
    /// The overriding variables that are set (`GIT_SSH_COMMAND`, `GIT_SSH`,
    /// `GIT_CONFIG_GLOBAL` …); names only.
    pub env_overrides: Vec<&'static str>,
    /// Git's default SSH program.
    pub default_ssh: DefaultGitSsh,
    /// Files the walk could not read (display form); the item is then
    /// `not_applicable` (`git_config_unreadable`).
    pub unreadable: Vec<String>,
}

impl GitGlobalObservation {
    /// The reason this observation makes the Git item `not_applicable` (ADR-0007 §5.6),
    /// or `None` when nothing observed blocks it. In order: a file the walk could not
    /// read or a home it could not establish (`git_config_unreadable`, fail closed),
    /// `GIT_CONFIG_GLOBAL` (`git_global_redirected`), any `core.sshCommand` in the system
    /// or global scopes, conditional or not (`git_ssh_command_present`). Whether Git's
    /// default is the bundled MSYS client is the caller's last check. Only
    /// [`Self::values`] counts: [`Self::own_values`] is the caller's to judge.
    #[must_use]
    pub fn not_applicable_reason(&self) -> Option<&'static str> {
        if !self.unreadable.is_empty() {
            return Some("git_config_unreadable");
        }
        if self.file.is_none() {
            return Some(if self.env_overrides.contains(&"GIT_CONFIG_GLOBAL") {
                "git_global_redirected"
            } else {
                "git_config_unreadable"
            });
        }
        if !self.values.is_empty() {
            return Some("git_ssh_command_present");
        }
        None
    }
}

/// Git's home: `$HOME`, else `%USERPROFILE%` on Windows (ADR-0007 §5.6).
#[must_use]
pub fn git_home(env: &Env) -> Option<PathBuf> {
    let pick = |name: &str| env.get(name).map(PathBuf::from).filter(|p| p.is_absolute());
    pick("HOME").or_else(|| {
        if Platform::current().is_windows() {
            pick("USERPROFILE")
        } else {
            None
        }
    })
}

/// The two global files in Git's read order (XDG first), or the redirected file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalFiles {
    /// `$XDG_CONFIG_HOME/git/config` (default `~/.config/git/config`).
    pub xdg: Option<PathBuf>,
    /// `~/.gitconfig`.
    pub home: Option<PathBuf>,
    /// `GIT_CONFIG_GLOBAL`, when set: Git reads that file instead of both.
    pub redirected: Option<PathBuf>,
}

impl GlobalFiles {
    /// The files Git reads for the global scope, in read order: the redirected file
    /// alone, else the XDG file and then `~/.gitconfig`. Not every one exists.
    #[must_use]
    pub fn roots(&self) -> Vec<PathBuf> {
        match &self.redirected {
            Some(p) => vec![p.clone()],
            None => self.xdg.iter().chain(self.home.iter()).cloned().collect(),
        }
    }
}

/// Git's global files for `env`.
#[must_use]
pub fn global_files(env: &Env) -> GlobalFiles {
    let redirected = env
        .get("GIT_CONFIG_GLOBAL")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let home = git_home(env);
    let xdg = env
        .get("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.as_ref().map(|h| h.join(".config")))
        .map(|d| d.join("git").join("config"));
    GlobalFiles {
        xdg,
        home: home.map(|h| h.join(".gitconfig")),
        redirected,
    }
}

/// The global file B_git goes into (ADR-0007 §5.6 first-read rule): the XDG file when
/// it exists, else `~/.gitconfig` when it exists, else `~/.gitconfig` to be created.
/// `None` when `GIT_CONFIG_GLOBAL` redirects the global file, or Git's home is unknown.
#[must_use]
pub fn resolve_global_file(env: &Env) -> Option<GlobalFileResolution> {
    let files = global_files(env);
    if files.redirected.is_some() {
        return None;
    }
    let exists = |p: &Path| std::fs::symlink_metadata(p).is_ok();
    if let Some(xdg) = files.xdg.filter(|p| exists(p)) {
        return Some(GlobalFileResolution {
            path: xdg,
            file: GitGlobalFileKind::XdgConfig,
            rule: GitFileResolution::FirstReadExisting,
        });
    }
    let home = files.home?;
    let rule = if exists(&home) {
        GitFileResolution::FirstReadExisting
    } else {
        GitFileResolution::Created
    };
    Some(GlobalFileResolution {
        path: home,
        file: GitGlobalFileKind::HomeGitconfig,
        rule,
    })
}

/// SHA-256 of a value, lowercase hex.
#[must_use]
pub fn value_digest(value: &str) -> String {
    hex(&Sha256::digest(value.as_bytes()))
}

fn query_cwd() -> PathBuf {
    if Platform::current().is_windows() {
        std::env::var_os("SystemDrive")
            .map(|d| PathBuf::from(format!("{}\\", d.to_string_lossy())))
            .unwrap_or_else(|| PathBuf::from(r"C:\"))
    } else {
        PathBuf::from("/")
    }
}

/// One `git` local query's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QueryAnswer {
    /// Exit 0 with this output.
    Found(Vec<u8>),
    /// Exit 1: nothing set.
    Absent,
    /// Anything else (error, timeout, unparsed).
    Failed,
}

fn git_query(git: &Path, args: &[&str], env: &Env, cwd: &Path) -> QueryAnswer {
    let Ok(out) = run_contained(&Spec {
        program: git,
        args: args.iter().map(Into::into).collect(),
        env: Some(env),
        cwd: Some(cwd),
        timeout: LOCAL_QUERY_TIMEOUT,
        max_output: LOCAL_QUERY_OUTPUT_BYTES,
    }) else {
        return QueryAnswer::Failed;
    };
    if out.timed_out || out.stdout.len() >= LOCAL_QUERY_OUTPUT_BYTES {
        return QueryAnswer::Failed;
    }
    match out.status.and_then(|s| s.code()) {
        Some(0) => QueryAnswer::Found(out.stdout),
        Some(1) => QueryAnswer::Absent,
        _ => QueryAnswer::Failed,
    }
}

/// Parse `--show-origin -z --get-all` output: `origin NUL value NUL` pairs. The
/// origin keeps its `file:` prefix stripped; any other origin kind is kept as written.
#[must_use]
pub fn parse_origin_values(out: &[u8]) -> Option<Vec<(String, String)>> {
    let mut fields: Vec<&[u8]> = out.split(|&b| b == 0).collect();
    if fields.last().is_some_and(|f| f.is_empty()) {
        fields.pop();
    }
    if !fields.len().is_multiple_of(2) {
        return None;
    }
    fields
        .chunks(2)
        .map(|pair| {
            let origin = std::str::from_utf8(pair[0]).ok()?;
            let value = std::str::from_utf8(pair[1]).ok()?;
            Some((origin.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Parse `--show-scope --show-origin -z --get-all` output: `scope NUL origin NUL value
/// NUL` triples, in read order. `None` when the output is not whole triples, a field is
/// not UTF-8 or a scope is not one Git names.
#[must_use]
pub fn parse_scope_origin_values(out: &[u8]) -> Option<Vec<(GitScope, String, String)>> {
    let mut fields: Vec<&[u8]> = out.split(|&b| b == 0).collect();
    if fields.last().is_some_and(|f| f.is_empty()) {
        fields.pop();
    }
    if !fields.len().is_multiple_of(3) {
        return None;
    }
    fields
        .chunks(3)
        .map(|t| {
            let scope = parse_scope(std::str::from_utf8(t[0]).ok()?)?;
            let origin = std::str::from_utf8(t[1]).ok()?;
            let value = std::str::from_utf8(t[2]).ok()?;
            Some((scope, origin.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Parse `--show-scope -z --get` output: `scope NUL value NUL`.
#[must_use]
pub fn parse_scope_value(out: &[u8]) -> Option<(GitScope, String)> {
    let mut fields = out.split(|&b| b == 0);
    let scope = parse_scope(std::str::from_utf8(fields.next()?).ok()?)?;
    let value = std::str::from_utf8(fields.next()?).ok()?.to_owned();
    Some((scope, value))
}

/// A `--show-scope` word.
#[must_use]
pub fn parse_scope(word: &str) -> Option<GitScope> {
    match word {
        "system" => Some(GitScope::System),
        "global" => Some(GitScope::Global),
        "local" => Some(GitScope::Local),
        "worktree" => Some(GitScope::Worktree),
        "command" => Some(GitScope::Command),
        _ => None,
    }
}

/// One `core.sshCommand` occurrence, before grouping.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Occurrence {
    scope: GitScope,
    origin: String,
    digest: String,
    conditional: bool,
}

struct Walk<'a> {
    home: Option<&'a Path>,
    files: usize,
    found: Vec<Occurrence>,
    unreadable: Vec<String>,
}

impl Walk<'_> {
    fn display(&self, p: &Path) -> String {
        match self.home {
            Some(h) => display_path(h, p),
            None => p.to_string_lossy().into_owned(),
        }
    }

    fn file(
        &mut self,
        path: &Path,
        scope: GitScope,
        depth: usize,
        conditional: bool,
        chain: &mut Vec<PathBuf>,
    ) {
        if depth > GIT_WALK_DEPTH || self.files >= GIT_WALK_FILES {
            let d = self.display(path);
            self.unreadable.push(d);
            return;
        }
        let read = match crate::fs::read_bounded(path, GIT_WALK_FILE_BYTES) {
            Ok(r) => r,
            // Git skips a missing global file and a missing include target.
            Err(heimdall_sshconf::include::SourceError::NotFound) => return,
            Err(_) => {
                let d = self.display(path);
                self.unreadable.push(d);
                return;
            }
        };
        self.files += 1;
        if chain.contains(&read.canonical) {
            // Git refuses an include cycle (its depth limit): not fully readable.
            let d = self.display(path);
            self.unreadable.push(d);
            return;
        }
        let scan = gitedit::scan(&read.bytes);
        let origin = format!("file:{}", self.display(&read.canonical));
        for key in &scan.keys {
            if key.section == "core" && key.subsection.is_none() && key.key == "sshcommand" {
                let digest = value_at_line(&read.bytes, key.span.range.start).map_or_else(
                    || {
                        value_digest(&String::from_utf8_lossy(
                            &read.bytes[key.span.range.clone()],
                        ))
                    },
                    |v| value_digest(&v),
                );
                self.found.push(Occurrence {
                    scope,
                    origin: origin.clone(),
                    digest,
                    conditional,
                });
            }
        }
        chain.push(read.canonical.clone());
        for inc in &scan.includes {
            let Some(target) = resolve_include(&inc.path, path, self.home) else {
                let d = format!("{}:{}", self.display(path), inc.span.line);
                self.unreadable.push(d);
                continue;
            };
            self.file(
                &target,
                scope,
                depth + 1,
                conditional || inc.conditional,
                chain,
            );
        }
        chain.pop();
    }
}

/// Resolve an include path: `~/` against Git's home, a relative path against the
/// including file's directory. `None` when it cannot be resolved (empty, `~user`, `~/`
/// without a home, a relative path from a file without a directory).
fn resolve_include(written: &str, including: &Path, home: Option<&Path>) -> Option<PathBuf> {
    if written.is_empty() {
        return None;
    }
    if let Some(rest) = written.strip_prefix('~') {
        let rest = rest.strip_prefix(['/', '\\'])?;
        return Some(home?.join(rest));
    }
    let p = Path::new(written);
    if p.is_absolute() {
        return Some(p.to_path_buf());
    }
    Some(including.parent()?.join(p))
}

/// The value of the key that starts on the line beginning at `start` (after an
/// optional `[section]` header on the same line): Git's value syntax (quotes, `\`
/// escapes, `#`/`;` comments, `\` line continuations, trailing blanks trimmed). A key
/// without `=` is `true`. `None` when the line is not understood.
#[must_use]
pub fn value_at_line(bytes: &[u8], start: usize) -> Option<String> {
    let mut i = start;
    let at = |i: usize| bytes.get(i).copied();
    while matches!(at(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    if at(i) == Some(b'[') {
        let mut quoted = false;
        loop {
            match at(i)? {
                b'"' => quoted = !quoted,
                b'\\' if quoted => i += 1,
                b']' if !quoted => {
                    i += 1;
                    break;
                }
                b'\n' => return None,
                _ => {}
            }
            i += 1;
        }
        while matches!(at(i), Some(b' ' | b'\t')) {
            i += 1;
        }
    }
    let key_start = i;
    while matches!(at(i), Some(c) if c.is_ascii_alphanumeric() || c == b'-') {
        i += 1;
    }
    if i == key_start {
        return None;
    }
    while matches!(at(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    match at(i) {
        None | Some(b'\n' | b'\r' | b'#' | b';') => return Some("true".to_owned()),
        Some(b'=') => i += 1,
        Some(_) => return None,
    }
    let mut out: Vec<u8> = Vec::new();
    let mut quoted = false;
    let mut pending_space = 0usize;
    while let Some(c) = at(i) {
        match c {
            b'\n' if !quoted => break,
            b'\n' => return None,
            b'\r' if at(i + 1) == Some(b'\n') && !quoted => break,
            b' ' | b'\t' if !quoted => {
                if !out.is_empty() {
                    pending_space += 1;
                }
            }
            b'#' | b';' if !quoted => break,
            b'"' => {
                out.extend(std::iter::repeat_n(b' ', pending_space));
                pending_space = 0;
                quoted = !quoted;
            }
            b'\\' => {
                let next = at(i + 1)?;
                i += 1;
                match next {
                    b'\n' => {}
                    b'\r' if at(i + 1) == Some(b'\n') => i += 1,
                    _ => {
                        out.extend(std::iter::repeat_n(b' ', pending_space));
                        pending_space = 0;
                        out.push(match next {
                            b'n' => b'\n',
                            b't' => b'\t',
                            b'b' => 0x08,
                            b'"' | b'\\' => next,
                            _ => return None,
                        });
                    }
                }
            }
            _ => {
                out.extend(std::iter::repeat_n(b' ', pending_space));
                pending_space = 0;
                out.push(c);
            }
        }
        i += 1;
    }
    if quoted {
        return None;
    }
    String::from_utf8(out).ok()
}

/// The system file Git reads, when it reads one: `Ok(None)` when Git reads none
/// (`GIT_CONFIG_NOSYSTEM`), `Err(())` when it cannot be established.
fn system_file(
    env: &Env,
    git: Option<&Path>,
    queries: LocalQueries,
) -> Result<Option<PathBuf>, ()> {
    if let (Some(git), LocalQueries::Enabled) = (git, queries) {
        return match git_query(git, &["var", "GIT_CONFIG_SYSTEM"], env, &query_cwd()) {
            QueryAnswer::Found(out) => {
                let text = String::from_utf8_lossy(&out);
                let line = text.lines().next().unwrap_or_default().trim();
                if line.is_empty() {
                    Err(())
                } else {
                    Ok(Some(PathBuf::from(line)))
                }
            }
            QueryAnswer::Absent => Ok(None),
            QueryAnswer::Failed => Err(()),
        };
    }
    let nosystem = env
        .get("GIT_CONFIG_NOSYSTEM")
        .and_then(|v| v.to_str())
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"));
    if nosystem {
        return Ok(None);
    }
    match env.get("GIT_CONFIG_SYSTEM").filter(|v| !v.is_empty()) {
        Some(p) => Ok(Some(PathBuf::from(p))),
        None => Err(()),
    }
}

/// Observe the system and global Git configuration. Every `core.sshCommand` occurrence
/// is in [`GitGlobalObservation::values`], Heimdall's own P_git included. The setup
/// preview and the doctor use [`observe_global_for`], which knows P_git.
#[must_use]
pub fn observe_global(
    env: &Env,
    clients: &ClientInventory,
    queries: LocalQueries,
) -> GitGlobalObservation {
    observe(env, clients, queries, None)
}

/// ADR-0007 §12.34 item 8, additive: [`observe_global`], with the occurrences that are
/// Heimdall's own `managed` file (P_git) split out into
/// [`GitGlobalObservation::own_values`]. Once the Git item is applied, B_git includes
/// P_git, and P_git holds a `core.sshCommand`: counted as a user value, Heimdall's own
/// value made every later preview `git_ssh_command_present`, so an update or a
/// re-render could never be planned. Only a `managed` file counted exactly once in all,
/// globally and outside any `includeIf`, is split out: a second path to the same file
/// (a user's own include, a conditional include, the system file) or a second key in it
/// is not B_git's value and stays in `values`, as does every value in any other file. A
/// `managed` file that does not exist splits nothing.
#[must_use]
pub fn observe_global_for(
    env: &Env,
    clients: &ClientInventory,
    queries: LocalQueries,
    managed: &Path,
) -> GitGlobalObservation {
    observe(env, clients, queries, Some(managed))
}

/// The origin string an observation reports for the file at `path` (`file:` and the
/// canonical path, `~` for Git's home), as [`GitValueObservation::origin_display`] shows
/// it. `None` when the path cannot be resolved (it does not exist).
#[must_use]
pub fn origin_of(env: &Env, path: &Path) -> Option<String> {
    let canonical = crate::fs::canonical_path(path).ok()?;
    Some(format!(
        "file:{}",
        display_origin(git_home(env).as_deref(), &canonical)
    ))
}

fn display_origin(home: Option<&Path>, path: &Path) -> String {
    home.map_or_else(
        || path.to_string_lossy().into_owned(),
        |h| display_path(h, path),
    )
}

/// An origin as `git config --show-origin` prints it, in the form an observation reports
/// (the canonical path, `~` for Git's home); an origin that is not a file is kept as
/// written.
fn queried_origin(origin: String, home: Option<&Path>) -> String {
    match origin.strip_prefix("file:") {
        Some(p) => {
            let p = crate::fs::canonical_path(Path::new(p)).unwrap_or_else(|_| PathBuf::from(p));
            format!("file:{}", display_origin(home, &p))
        }
        None => origin,
    }
}

/// The name of P_git in Heimdall's configuration directory (ADR-0007 §5.6).
pub const MANAGED_GIT_FILE: &str = "gitconfig";

/// ADR-0007 §12.34 item 8, §12.37 item 1: whether the global Git file `bytes` holds B_git
/// as Heimdall renders it for `target` (P_git's absolute path): exactly one marked block,
/// intact, whose bytes are what [`render::render_git_include_block`] gives for its own
/// marker, `target` and its own line ending. A block that is edited, duplicated, absent
/// or names another file is not B_git.
///
/// # Errors
/// [`RenderError`] when no B_git can be rendered for `target`.
pub fn holds_include(bytes: &[u8], target: &RenderPath) -> Result<bool, RenderError> {
    let blocks = gitedit::find_blocks(bytes);
    let [only] = blocks.as_slice() else {
        return Ok(false);
    };
    if !only.intact {
        return Ok(false);
    }
    let newline = bytes
        .get(only.range.clone())
        .and_then(edit::detect_newline)
        .unwrap_or(Newline::Lf);
    let expected = render::render_git_include_block(&only.marker, target, newline)?;
    Ok(bytes.get(only.range.clone()) == Some(expected.as_slice()))
}

/// ADR-0007 §12.37 item 1: whether Heimdall's B_git for `managed` (P_git) is in the
/// global Git files: exactly one Heimdall block in all of them, intact, naming `managed`.
/// The doctor takes a `core.sshCommand` reached once through P_git for Heimdall's own
/// only when this holds. Every file that cannot be read within the bounds, a second block
/// anywhere and a path no B_git can name make it `false` (fail closed: the value is then
/// reported like a user's).
#[must_use]
pub fn managed_include_present(env: &Env, managed: &Path, windows: bool) -> bool {
    let target = if windows {
        RenderPath::windows(managed)
    } else {
        RenderPath::unix(managed)
    };
    let Ok(target) = target else {
        return false;
    };
    let mut holding: Option<Vec<u8>> = None;
    for root in global_files(env).roots() {
        match crate::fs::read_bounded(&root, GIT_WALK_FILE_BYTES) {
            Ok(read) => {
                if !gitedit::find_blocks(&read.bytes).is_empty()
                    && holding.replace(read.bytes).is_some()
                {
                    // Blocks in two global files: which one Git reads first is not the
                    // question here, and neither can be taken for the only B_git.
                    return false;
                }
            }
            Err(heimdall_sshconf::include::SourceError::NotFound) => {}
            Err(_) => return false,
        }
    }
    holding.is_some_and(|bytes| holds_include(&bytes, &target).unwrap_or(false))
}

/// ADR-0007 §12.37 item 2: the origin of the `core.sshCommand` value that the
/// **persistent** configuration selects, as an observation shows origins ([`origin_of`]'s
/// form): the **last** occurrence in the system and global scopes, which is how Git
/// resolves a repeated key. `git config --show-scope --show-origin -z --get-all` lists the
/// occurrences in read order, with each include expanded where it stands, so the last
/// system or global one is the winner (system, then the XDG file, then `~/.gitconfig`).
/// ADR-0007 §12.42 item 1 (R01): the command scope (`-c`, `GIT_CONFIG_COUNT`,
/// `GIT_CONFIG_PARAMETERS`) and a repository's own scopes belong to one process or one
/// repository, not to the selection that setup changes (§5.6 covers the system and
/// global files), so an occurrence there never decides who wins. `None` when no
/// system or global value is set, the query failed or local queries are off: nothing
/// is then said about who wins.
#[must_use]
pub fn winning_origin(
    env: &Env,
    clients: &ClientInventory,
    queries: LocalQueries,
) -> Option<String> {
    let git = clients.selected(ClientKind::Git).map(|c| c.path.clone())?;
    if queries != LocalQueries::Enabled {
        return None;
    }
    let args = [
        "config",
        "--show-scope",
        "--show-origin",
        "-z",
        "--get-all",
        "core.sshCommand",
    ];
    let QueryAnswer::Found(out) = git_query(&git, &args, env, &query_cwd()) else {
        return None;
    };
    let (_scope, origin, _value) = parse_scope_origin_values(&out)?
        .into_iter()
        .rfind(|(scope, _, _)| matches!(scope, GitScope::System | GitScope::Global))?;
    Some(queried_origin(origin, git_home(env).as_deref()))
}

/// Split Heimdall's own occurrence out of `values`: `(own, rest)`. `own` is the file's
/// origin as [`origin_of`] gives it. The file's occurrences are Heimdall's own only when
/// the file was counted exactly once, over every scope, include path and key, and that
/// one is global and unconditional. A second key (another value, so another group), a
/// second path to the file, an `includeIf` or the system file is not B_git's value:
/// nothing is split out and every occurrence stays in `rest`.
fn split_own(
    mut values: Vec<GitValueObservation>,
    own: &str,
) -> (Vec<GitValueObservation>, Vec<GitValueObservation>) {
    let of_file = |v: &GitValueObservation| v.origin_display.as_deref() == Some(own);
    let reached: u32 = values
        .iter()
        .filter(|v| of_file(v))
        .fold(0, |n, v| n.saturating_add(v.count));
    // `reached == 1` makes the one group's count 1.
    let one = values
        .iter()
        .position(|v| of_file(v) && v.scope == GitScope::Global && !v.conditional);
    match one {
        Some(i) if reached == 1 => (vec![values.remove(i)], values),
        _ => (Vec::new(), values),
    }
}

fn observe(
    env: &Env,
    clients: &ClientInventory,
    queries: LocalQueries,
    managed: Option<&Path>,
) -> GitGlobalObservation {
    let git = clients.selected(ClientKind::Git).map(|c| c.path.clone());
    let home = git_home(env);
    let env_overrides: Vec<&'static str> = GIT_ENV_OVERRIDES
        .iter()
        .copied()
        .filter(|n| env.get(n).is_some())
        .collect();
    let mut walk = Walk {
        home: home.as_deref(),
        files: 0,
        found: Vec::new(),
        unreadable: Vec::new(),
    };
    if home.is_none() {
        walk.unreadable.push("Git home (HOME unset)".to_owned());
    }
    // Static scan: the system file, then the global files in read order.
    match system_file(env, git.as_deref(), queries) {
        Ok(Some(path)) => walk.file(&path, GitScope::System, 0, false, &mut Vec::new()),
        Ok(None) => {}
        Err(()) => walk
            .unreadable
            .push("git system configuration (path not established)".to_owned()),
    }
    for root in &global_files(env).roots() {
        walk.file(root, GitScope::Global, 0, false, &mut Vec::new());
    }
    let mut occurrences = walk.found;
    let mut unreadable = walk.unreadable;
    // The local queries of §5.6.
    let mut queried: Vec<Occurrence> = Vec::new();
    if let (Some(git), LocalQueries::Enabled) = (git.as_deref(), queries) {
        for (flag, scope) in [
            ("--system", GitScope::System),
            ("--global", GitScope::Global),
        ] {
            let args = [
                "config",
                flag,
                "--includes",
                "--show-origin",
                "-z",
                "--get-all",
                "core.sshCommand",
            ];
            match git_query(git, &args, env, &query_cwd()) {
                QueryAnswer::Found(out) => match parse_origin_values(&out) {
                    Some(pairs) => {
                        for (origin, value) in pairs {
                            queried.push(Occurrence {
                                scope,
                                origin: queried_origin(origin, home.as_deref()),
                                digest: value_digest(&value),
                                conditional: false,
                            });
                        }
                    }
                    None => unreadable.push(format!("git config {flag} (output not understood)")),
                },
                QueryAnswer::Absent => {}
                QueryAnswer::Failed => unreadable.push(format!("git config {flag}")),
            }
        }
    }
    occurrences.extend(merge_extra(&occurrences, queried));
    let values = group(&occurrences);
    let (own_values, values) = match managed.and_then(|m| origin_of(env, m)) {
        Some(own) => split_own(values, &own),
        None => (Vec::new(), values),
    };
    unreadable.sort();
    unreadable.dedup();
    let default_ssh = match (git.as_deref(), queries) {
        (None, _) | (_, LocalQueries::Disabled) => DefaultGitSsh::Undetermined,
        (Some(_), LocalQueries::Enabled) => default_git_ssh(env),
    };
    GitGlobalObservation {
        file: resolve_global_file(env),
        values,
        own_values,
        env_overrides,
        default_ssh,
        unreadable,
    }
}

/// The queried occurrences beyond what the static scan already counted, per
/// (scope, origin, digest): a query that reports more occurrences than the scan adds
/// the difference.
fn merge_extra(scanned: &[Occurrence], queried: Vec<Occurrence>) -> Vec<Occurrence> {
    let mut extra = Vec::new();
    let mut used = vec![false; scanned.len()];
    for q in queried {
        let hit = scanned.iter().enumerate().position(|(i, s)| {
            !used[i] && s.scope == q.scope && s.origin == q.origin && s.digest == q.digest
        });
        match hit {
            Some(i) => used[i] = true,
            None => extra.push(q),
        }
    }
    extra
}

fn group(occurrences: &[Occurrence]) -> Vec<GitValueObservation> {
    let mut out: Vec<GitValueObservation> = Vec::new();
    for o in occurrences {
        match out.iter_mut().find(|v| {
            v.scope == o.scope
                && v.origin_display.as_deref() == Some(o.origin.as_str())
                && v.value_sha256 == o.digest
                && v.conditional == o.conditional
        }) {
            Some(v) => v.count = v.count.saturating_add(1),
            None => out.push(GitValueObservation {
                scope: o.scope,
                origin_display: Some(o.origin.clone()),
                value_sha256: o.digest.clone(),
                count: 1,
                conditional: o.conditional,
            }),
        }
    }
    out
}

fn default_git_ssh(env: &Env) -> DefaultGitSsh {
    let platform = Platform::current();
    if platform.is_windows()
        && let Some(p) = git_bundled_ssh(&path_dirs(env), platform)
    {
        return DefaultGitSsh::BundledMsys(p);
    }
    DefaultGitSsh::PathSsh
}

fn path_dirs(env: &Env) -> Vec<PathBuf> {
    env.get("PATH")
        .map(|p| {
            std::env::split_paths(p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve Git's effective SSH selection in the child's working directory with the
/// child's environment (ADR-0007 §8). The value is classified in memory and dropped.
#[must_use]
pub fn resolve_run_selection(
    cwd: &Path,
    child_env: &Env,
    clients: &ClientInventory,
    queries: LocalQueries,
) -> GitSshSelection {
    let selection = |source, scope, classification| GitSshSelection {
        source,
        scope,
        classification,
    };
    if let Some(cmd) = child_env
        .get("GIT_SSH_COMMAND")
        .and_then(|v| v.to_str())
        .filter(|v| !v.is_empty())
    {
        return selection(
            GitSshSource::EnvGitSshCommand,
            None,
            classify_command(cmd, child_env, clients),
        );
    }
    let Some(git) = clients.selected(ClientKind::Git).map(|c| c.path.clone()) else {
        return selection(
            GitSshSource::Default,
            None,
            GitSshClassification::Undetermined,
        );
    };
    if queries == LocalQueries::Disabled {
        // A configured value cannot be ruled out without the query.
        return selection(
            GitSshSource::Config,
            None,
            GitSshClassification::Undetermined,
        );
    }
    let cwd_arg = cwd.to_string_lossy().into_owned();
    let args = [
        "-C",
        cwd_arg.as_str(),
        "config",
        "--show-scope",
        "-z",
        "--get",
        "core.sshCommand",
    ];
    match git_query(&git, &args, child_env, cwd) {
        QueryAnswer::Found(out) => {
            return match parse_scope_value(&out) {
                Some((scope, value)) => selection(
                    GitSshSource::Config,
                    Some(scope),
                    classify_command(&value, child_env, clients),
                ),
                None => selection(
                    GitSshSource::Config,
                    None,
                    GitSshClassification::Undetermined,
                ),
            };
        }
        QueryAnswer::Absent => {}
        QueryAnswer::Failed => {
            return selection(
                GitSshSource::Config,
                None,
                GitSshClassification::Undetermined,
            );
        }
    }
    if let Some(prog) = child_env
        .get("GIT_SSH")
        .and_then(|v| v.to_str())
        .filter(|v| !v.is_empty())
    {
        return selection(
            GitSshSource::EnvGitSsh,
            None,
            classify_program(prog, child_env, clients),
        );
    }
    let platform = Platform::current();
    let dirs = path_dirs(child_env);
    if platform.is_windows() && git_bundled_ssh(&dirs, platform).is_some() {
        return selection(
            GitSshSource::Default,
            None,
            GitSshClassification::BundledMsys,
        );
    }
    let default = if search_path(&dirs, "ssh", platform).is_some() {
        classify_program("ssh", child_env, clients)
    } else {
        GitSshClassification::Undetermined
    };
    selection(GitSshSource::Default, None, default)
}

/// The first word of a shell command (`'…'` and `"…"` quoting, `\` escapes).
#[must_use]
pub fn first_shell_word(cmd: &str) -> Option<String> {
    let mut chars = cmd.trim_start().chars().peekable();
    let mut word = String::new();
    let mut any = false;
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' => break,
            '\'' => {
                chars.next();
                any = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        ch => word.push(ch),
                    }
                }
            }
            '"' => {
                chars.next();
                any = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => word.push(chars.next()?),
                        ch => word.push(ch),
                    }
                }
            }
            '\\' => {
                chars.next();
                word.push(chars.next()?);
                any = true;
            }
            _ => {
                chars.next();
                word.push(c);
                any = true;
            }
        }
    }
    any.then_some(word)
}

fn classify_command(cmd: &str, env: &Env, clients: &ClientInventory) -> GitSshClassification {
    match first_shell_word(cmd) {
        Some(word) => classify_program(&word, env, clients),
        None => GitSshClassification::Undetermined,
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    if Platform::current().is_windows() {
        let norm = |p: &Path| p.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
        norm(a) == norm(b)
    } else {
        a == b
    }
}

fn classify_program(prog: &str, env: &Env, clients: &ClientInventory) -> GitSshClassification {
    let platform = Platform::current();
    let dirs = path_dirs(env);
    let path = if prog.contains(['/', '\\']) {
        PathBuf::from(prog)
    } else {
        let bare = prog.strip_suffix(".exe").unwrap_or(prog);
        match search_path(&dirs, bare, platform) {
            Some(p) => p,
            // A named program that is not on PATH is neither client.
            None => return GitSshClassification::Other,
        }
    };
    if clients
        .selected(ClientKind::Ssh)
        .is_some_and(|c| same_path(&c.path, &path))
    {
        return GitSshClassification::VerifiedClient;
    }
    if platform.is_windows()
        && git_bundled_ssh(&dirs, platform).is_some_and(|b| same_path(&b, &path))
    {
        return GitSshClassification::BundledMsys;
    }
    GitSshClassification::Other
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn values_parse_with_quotes_escapes_comments_and_headers() {
        let cases: &[(&str, &str)] = &[
            ("\tsshCommand = ssh -v\n", "ssh -v"),
            ("sshCommand=\"a  b\" # c\n", "a  b"),
            ("sshCommand = a \\\"q\\\" ; c\n", "a \"q\""),
            ("sshCommand = 'x'  y  \n", "'x'  y"),
            ("[core] sshCommand = inline\n", "inline"),
            ("sshCommand = one \\\n two\n", "one  two"),
            ("sshCommand\n", "true"),
            ("sshCommand = tab\\tend\r\n", "tab\tend"),
        ];
        for (line, want) in cases {
            assert_eq!(
                value_at_line(line.as_bytes(), 0).as_deref(),
                Some(*want),
                "{line:?}"
            );
        }
        assert_eq!(value_at_line(b"sshCommand = \"open\n", 0), None);
    }

    #[test]
    fn query_outputs_parse() {
        let out = b"file:/s/home/.gitconfig\0ssh -v\0file:/s/home/inc.conf\0included\0";
        let pairs = parse_origin_values(out).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("file:/s/home/.gitconfig".to_owned(), "ssh -v".to_owned()),
                ("file:/s/home/inc.conf".to_owned(), "included".to_owned()),
            ]
        );
        assert!(parse_origin_values(b"file:/x\0").is_none());
        assert_eq!(
            parse_scope_value(b"global\0included-ssh\0"),
            Some((GitScope::Global, "included-ssh".to_owned()))
        );
        assert_eq!(parse_scope_value(b"unknown\0x\0"), None);
        assert_eq!(
            parse_scope_origin_values(
                b"global\0file:/h/.gitconfig\0a\0command\0command line:\0b\0"
            ),
            Some(vec![
                (
                    GitScope::Global,
                    "file:/h/.gitconfig".to_owned(),
                    "a".to_owned()
                ),
                (
                    GitScope::Command,
                    "command line:".to_owned(),
                    "b".to_owned()
                ),
            ])
        );
        assert_eq!(parse_scope_origin_values(b"global\0file:/x\0"), None);
        assert_eq!(parse_scope_origin_values(b"nonsense\0file:/x\0v\0"), None);
    }

    #[test]
    fn first_shell_word_handles_quotes() {
        assert_eq!(first_shell_word("ssh -v").as_deref(), Some("ssh"));
        assert_eq!(
            first_shell_word("'/a b/ssh' -o X").as_deref(),
            Some("/a b/ssh")
        );
        assert_eq!(first_shell_word("\"/c/ssh\"").as_deref(), Some("/c/ssh"));
        assert_eq!(
            first_shell_word("  /x\\ y/ssh").as_deref(),
            Some("/x y/ssh")
        );
        assert_eq!(first_shell_word("   "), None);
        assert_eq!(first_shell_word("'open"), None);
    }

    #[test]
    fn global_file_follows_the_first_read_rule() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".config").join("git")).unwrap();
        let env = Env::from_vars([("HOME", home.clone().into_os_string())]);
        let r = resolve_global_file(&env).unwrap();
        assert_eq!(r.file, GitGlobalFileKind::HomeGitconfig);
        assert_eq!(r.rule, GitFileResolution::Created);
        std::fs::write(home.join(".gitconfig"), b"").unwrap();
        let r = resolve_global_file(&env).unwrap();
        assert_eq!(
            (r.file, r.rule),
            (
                GitGlobalFileKind::HomeGitconfig,
                GitFileResolution::FirstReadExisting
            )
        );
        std::fs::write(home.join(".config").join("git").join("config"), b"").unwrap();
        let r = resolve_global_file(&env).unwrap();
        assert_eq!(
            (r.file, r.rule),
            (
                GitGlobalFileKind::XdgConfig,
                GitFileResolution::FirstReadExisting
            )
        );
        let redirected = Env::from_vars([
            ("HOME", home.clone().into_os_string()),
            ("GIT_CONFIG_GLOBAL", home.join("other").into_os_string()),
        ]);
        assert!(resolve_global_file(&redirected).is_none());
    }
}
